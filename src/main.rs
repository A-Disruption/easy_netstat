#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use iced::event;
use iced::keyboard;
use iced::time::Instant;
use iced::widget;
use iced::{
    Alignment, Element, Font, Length, Subscription, Task, Theme, Widget, alignment, font, time,
    widget::{button, column, container, pick_list, row, space, stack, text, text_input, toggler},
};

use advanced_table::{Direction, Policy, Sort, data_table, leaf};
use easy_netstat::{
    collectors::{Cancellation, DiagnosticCollector},
    diagnostics::{self, Analysis},
    inventory::InventoryCollector,
    model::*,
    state::{History, JobGate},
    storage::{self, Preferences, SavedView, Snapshot},
};
use filter::{FilterExpr, optimize_filter, parse_filter, parse_single_criterion};
use iced_native_frame::{FrameAction, NativeFrame, NativeFrameConfig};
use std::{
    collections::BTreeSet,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use widgets::anchor::{Align, Side};
use widgets::layer::modal;
use widgets::popover::{self, popover};

mod diagnostic_style;
mod filter;
mod icon;
mod reach_ui;
mod workbench_ui;

/// How often an automatic refresh runs, before the user changes it.
const DEFAULT_REFRESH_SECS: u64 = 5;

/// The application icon: one source for the taskbar, the window and the title
/// bar. Nine resolutions, 16x16 up to 256x256.
const ICON: &[u8] = include_bytes!("../assets/netstat-rust.ico");

/// The width the title-bar icon is drawn at, in logical pixels. Matches
/// `NativeFrameConfig::window_icon_size`, whose container clips rather than
/// scales -- so the element has to arrive already the right size.
const TITLE_BAR_ICON_SIZE: f32 = 16.0;

/// Decodes [`ICON`] for the window, and so for the taskbar and Alt-Tab.
///
/// iced only builds an `Icon` out of raw RGBA, so the `.ico` is decoded here
/// rather than handed over as a file. The `image` crate's ICO decoder yields
/// the largest entry, 256x256, which leaves Windows the most to work with
/// wherever it needs a smaller one.
fn window_icon() -> Option<iced::window::Icon> {
    let icon = image::load_from_memory_with_format(ICON, image::ImageFormat::Ico)
        .ok()?
        .into_rgba8();

    let (width, height) = icon.dimensions();

    iced::window::icon::from_rgba(icon.into_raw(), width, height).ok()
}

/// Decodes [`ICON`] for the title bar.
///
/// Resampled on the CPU rather than left to the GPU at draw time: the source is
/// 256 square and the title bar draws it at 16, and a sampler asked for a 16x
/// reduction in one step aliases badly. 32 is the physical size at 200% display
/// scaling, so there is headroom on a HiDPI screen without carrying a texture
/// nothing needs.
fn title_bar_icon() -> Option<iced::widget::image::Handle> {
    const SIZE: u32 = 32;

    let icon = image::load_from_memory_with_format(ICON, image::ImageFormat::Ico)
        .ok()?
        .resize_exact(SIZE, SIZE, image::imageops::FilterType::Lanczos3)
        .into_rgba8();

    Some(iced::widget::image::Handle::from_rgba(
        SIZE,
        SIZE,
        icon.into_raw(),
    ))
}

#[derive(Debug, Clone)]
enum Message {
    Settings,
    RestartAsAdministrator,
    AdministratorRestartReady(Result<(), String>),
    RefreshData,
    InventoryReady(u64, Result<Arc<Inventory>, String>),
    SelectConnection(Option<ConnectionKey>),
    DiagnosticTabChanged(workbench_ui::DiagnosticTab),
    RuleSearchChanged(String),
    RulePageChanged(usize),
    RuleScopeChanged(bool),
    RuleSelected(String),
    InspectFirewallRule(String),
    CloseDetails,
    TogglePanel,
    OpenFullReport,
    ShowRuleDetail(Option<String>),
    OpenRuleInBrowser(String),
    CopyText(String),
    Diagnose(bool),
    EvaluateCached,
    AnalysisReady(u64, ConnectionKey, Result<Arc<Analysis>, String>),
    CancelDiagnosis,
    DiagnosisReady(u64, ConnectionKey, Result<Arc<DiagnosticData>, String>),
    ScenarioChanged(String, String),
    ToggleSection(String),
    CaptureSnapshot,
    CompareSnapshot,
    SaveSnapshot,
    LoadSnapshot,
    SnapshotLoaded(Result<Arc<Snapshot>, String>),
    ExportReport,
    IoFinished(Result<String, String>),
    ViewNameChanged(String),
    SaveView,
    LoadView(String),
    PreferencesLoaded(Result<Preferences, String>),
    DnsChanged(String),
    ResolveDns,
    DnsReady(Result<Vec<String>, String>),
    FilterChanged(String),
    FilterChangedImmediate(String),
    CheckDebounce,
    SelectAutocomplete(String),
    AutocompleteNavigate(AutocompleteNav),
    SortChanged(Option<Sort>),
    SettingsDismissed,
    AutoRefreshToggled(bool),
    RefreshIntervalChanged(String),
    ThemeChanged(Theme),
    Frame(FrameAction),
}
struct App {
    process_info: DataState<Vec<SocketDisplay>, String>,
    collector: Arc<Mutex<InventoryCollector>>,
    diagnostic_collector: Arc<Mutex<DiagnosticCollector>>,
    inventory_gate: JobGate,
    diagnostic_gate: JobGate,
    diagnostic_cancel: Option<Cancellation>,
    history: History,
    selected: Option<Connection>,
    diagnostic_data: Option<Arc<DiagnosticData>>,
    analysis: Analysis,
    analysis_request: u64,
    analysis_busy: bool,
    show_workbench: bool,
    /// Docked reachability panel beside the table.
    show_panel: bool,
    /// Rule shown in the rule-vs-traffic drill-down.
    rule_detail: Option<String>,
    /// Latest verdict per connection checked this session: (outcome, confirmed).
    reach: std::collections::HashMap<ConnectionKey, (diagnostics::Outcome, bool)>,
    elevation_status: Result<bool, String>,
    elevation_busy: bool,
    diagnostic_tab: workbench_ui::DiagnosticTab,
    diagnostic_scroll_id: widget::Id,
    rule_search: String,
    rule_page: usize,
    rule_candidates_only: bool,
    selected_rule: Option<String>,
    sections: BTreeSet<String>,
    local_input: String,
    peer_input: String,
    direction: easy_netstat::model::Direction,
    direction_confirmed: bool,
    /// The direction came from the socket state, not the user.
    direction_guessed: bool,
    interface_input: String,
    expected_service: String,
    expected_port: String,
    status: String,
    filter_error: Option<String>,
    parsed_filter: Option<FilterExpr>,
    preferences: Preferences,
    preferences_ready: bool,
    view_name: String,
    loaded_view: Option<String>,
    snapshot: Option<Snapshot>,
    session_id: String,
    file_path: String,
    dns_name: String,
    dns_busy: bool,
    dns_cancel: Option<Cancellation>,
    dns_result: String,
    filter_text: String,
    filter_text_staged: String,
    last_keystroke: Option<Instant>,
    debounce_duration: std::time::Duration,
    autocomplete_suggestions: Vec<AutocompleteOption>,
    autocomplete_selected_index: Option<usize>,
    text_input_id: widget::Id,
    sort: Option<Sort>,
    show_settings: bool,
    auto_refresh: bool,
    refresh_secs: u64,
    /// Kept as text, not just as the parsed `refresh_secs`, so the field can be
    /// emptied and retyped without the interval snapping to something in the
    /// middle of the edit.
    refresh_secs_input: String,
    theme: Theme,
    /// Draws the title bar and owns the caption state (maximized, focused)
    /// behind it. Cloned from the one `main` built the window settings with,
    /// so both sides agree on the frame's geometry.
    frame: NativeFrame,
    /// Decoded once at startup. `view` runs every frame and an ICO decode plus
    /// a Lanczos resample is not something to repeat at that rate.
    icon: Option<iced::widget::image::Handle>,
}

enum DataState<T, E> {
    NotLoaded,
    Loaded(Result<T, E>),
}

#[derive(Clone)]
struct SocketDisplay {
    key: Option<ConnectionKey>,
    protocol: String,
    state: String,
    local_addr: String,
    remote_addr: String,
    pid: String,
    process_name: String,
}

impl SocketDisplay {
    fn from_connection(c: &Connection) -> Self {
        Self {
            key: Some(c.key.clone()),
            protocol: c.key.protocol.to_string(),
            state: c.state.clone(),
            local_addr: c.key.local.to_string(),
            remote_addr: c
                .key
                .remote
                .map(|a| a.to_string())
                .unwrap_or_else(|| "*:*".into()),
            pid: c.key.process.pid.to_string(),
            process_name: c.process.name.clone(),
        }
    }
}

impl App {
    pub fn new(frame: NativeFrame) -> (Self, Task<Message>) {
        (
            Self {
                process_info: DataState::NotLoaded,
                collector: Arc::new(Mutex::new(InventoryCollector::default())),
                diagnostic_collector: Arc::new(Mutex::new(DiagnosticCollector::default())),
                inventory_gate: JobGate::default(),
                diagnostic_gate: JobGate::default(),
                diagnostic_cancel: None,
                history: History::default(),
                selected: None,
                diagnostic_data: None,
                analysis: Analysis::default(),
                analysis_request: 0,
                analysis_busy: false,
                show_workbench: false,
                show_panel: true,
                rule_detail: None,
                reach: std::collections::HashMap::new(),
                elevation_status: easy_netstat::elevation::is_elevated(),
                elevation_busy: false,
                diagnostic_tab: workbench_ui::DiagnosticTab::Overview,
                diagnostic_scroll_id: widget::Id::unique(),
                rule_search: String::new(),
                rule_page: 0,
                rule_candidates_only: true,
                selected_rule: None,
                sections: BTreeSet::new(),
                local_input: String::new(),
                peer_input: String::new(),
                direction: easy_netstat::model::Direction::Inbound,
                direction_confirmed: false,
                direction_guessed: false,
                interface_input: String::new(),
                expected_service: String::new(),
                expected_port: String::new(),
                status: String::new(),
                filter_error: None,
                parsed_filter: None,
                preferences: Preferences::default(),
                preferences_ready: false,
                view_name: String::new(),
                loaded_view: None,
                snapshot: None,
                session_id: format!("{}:{}", std::process::id(), now_ms()),
                file_path: storage::default_directory()
                    .join(format!("diagnostic-{}.md", now_ms()))
                    .to_string_lossy()
                    .into_owned(),
                dns_name: String::new(),
                dns_busy: false,
                dns_cancel: None,
                dns_result: String::new(),
                filter_text: String::new(),
                filter_text_staged: String::new(),
                last_keystroke: None,
                debounce_duration: std::time::Duration::from_millis(250),
                autocomplete_suggestions: Vec::new(),
                autocomplete_selected_index: None,
                text_input_id: widget::Id::unique(),
                sort: None,
                show_settings: false,
                auto_refresh: false,
                refresh_secs: DEFAULT_REFRESH_SECS,
                refresh_secs_input: DEFAULT_REFRESH_SECS.to_string(),
                theme: Theme::Nord,
                frame,
                icon: title_bar_icon(),
            },
            Task::batch([
                Task::done(Message::RefreshData),
                Task::perform(
                    async {
                        tokio::task::spawn_blocking(|| {
                            let path = storage::preferences_path();
                            if !path.exists() {
                                Ok(Preferences::default())
                            } else {
                                storage::load_preferences(&path)
                            }
                        })
                        .await
                        .unwrap_or_else(|e| Err(e.to_string()))
                    },
                    Message::PreferencesLoaded,
                ),
            ]),
        )
    }

    fn title(&self) -> String {
        String::from("Easy Net Stat")
    }

    fn theme(&self) -> Theme {
        self.theme.clone()
    }

    pub fn window_settings() -> iced::window::Settings {
        iced::window::Settings {
            size: iced::Size::new(1275.0, 768.0),
            min_size: Some(iced::Size::new(1275.0, 768.0)),
            icon: window_icon(),
            ..iced::window::Settings::default()
        }
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Settings => {
                self.show_settings = !self.show_settings;
                self.show_workbench = false;
                self.autocomplete_suggestions.clear();
                self.autocomplete_selected_index = None;
            }
            Message::SettingsDismissed => {
                self.show_settings = false;
            }
            Message::AutoRefreshToggled(enabled) => {
                self.auto_refresh = enabled;
                if !enabled {
                    self.inventory_gate.clear_pending();
                }
            }
            Message::RefreshIntervalChanged(value) => {
                // Digits only. The interval itself only moves when the field
                // holds something usable, so clearing it leaves the last good
                // value running rather than dropping to zero.
                let digits: String = value.chars().filter(char::is_ascii_digit).collect();

                if let Some(secs) = easy_netstat::state::valid_interval(&digits) {
                    self.refresh_secs = secs;
                }

                self.refresh_secs_input = digits;
            }
            Message::ThemeChanged(theme) => {
                self.theme = theme;
            }
            Message::Frame(action) => {
                // Dragging, resizing, snapping and the caption buttons all come
                // back through here as window `Task`s.
                return self.frame.update(action, Message::Frame);
            }
            Message::SortChanged(sort) => {
                // The table renders the sort and reports what it should become;
                // reordering the rows is ours to do, in `view`.
                self.sort = sort;
            }
            Message::FilterChangedImmediate(value) => {
                self.filter_text_staged = value;
                self.apply_filter();
                self.last_keystroke = None;
            }
            Message::RefreshData => {
                return self.start_inventory();
            }
            Message::InventoryReady(id, result) => {
                let Some(pending) = self.inventory_gate.finish(id) else {
                    return Task::none();
                };
                match result {
                    Ok(sample) => {
                        self.history.apply(Arc::unwrap_or_clone(sample));
                        self.process_info = DataState::Loaded(Ok(self
                            .history
                            .current
                            .iter()
                            .map(SocketDisplay::from_connection)
                            .collect()));
                        if let Some(selected) = &mut self.selected
                            && selected.key.process.created.is_some()
                            && let Some(current) =
                                self.history.current.iter().find(|c| c.key == selected.key)
                        {
                            *selected = current.clone();
                        }
                    }
                    Err(error) => {
                        self.history.errors = vec![error];
                    }
                }
                if pending {
                    return self.start_inventory();
                }
            }
            other @ (Message::RestartAsAdministrator
            | Message::AdministratorRestartReady(_)
            | Message::SelectConnection(_)
            | Message::DiagnosticTabChanged(_)
            | Message::RuleSearchChanged(_)
            | Message::RulePageChanged(_)
            | Message::RuleScopeChanged(_)
            | Message::RuleSelected(_)
            | Message::InspectFirewallRule(_)
            | Message::CloseDetails
            | Message::TogglePanel
            | Message::OpenFullReport
            | Message::ShowRuleDetail(_)
            | Message::OpenRuleInBrowser(_)
            | Message::CopyText(_)
            | Message::Diagnose(_)
            | Message::EvaluateCached
            | Message::AnalysisReady(..)
            | Message::CancelDiagnosis
            | Message::DiagnosisReady(..)
            | Message::ScenarioChanged(..)
            | Message::ToggleSection(_)
            | Message::CaptureSnapshot
            | Message::CompareSnapshot
            | Message::SaveSnapshot
            | Message::LoadSnapshot
            | Message::SnapshotLoaded(_)
            | Message::ExportReport
            | Message::IoFinished(_)
            | Message::ViewNameChanged(_)
            | Message::SaveView
            | Message::LoadView(_)
            | Message::PreferencesLoaded(_)
            | Message::DnsChanged(_)
            | Message::ResolveDns
            | Message::DnsReady(_)) => return self.update_workbench(other),
            Message::FilterChanged(value) => {
                self.filter_text_staged = value;
                self.last_keystroke = Some(Instant::now());
                self.autocomplete_suggestions = self.generate_autocomplete();

                // Reset selected index when typing
                self.autocomplete_selected_index = if self.autocomplete_suggestions.is_empty() {
                    None
                } else {
                    Some(0)
                };
            }
            Message::CheckDebounce => {
                if let Some(last) = self.last_keystroke
                    && last.elapsed() >= self.debounce_duration
                {
                    self.apply_filter();
                    self.last_keystroke = None;
                }
            }
            Message::SelectAutocomplete(value) => {
                let start = filter::last_token_start(&self.filter_text_staged);

                // Only add trailing space if the value doesn't end with ':'
                let trailing_space = if value.ends_with(':') { "" } else { " " };

                self.filter_text_staged = format!(
                    "{}{}{}",
                    &self.filter_text_staged[..start],
                    value,
                    trailing_space
                );

                // Clear autocomplete
                self.autocomplete_suggestions.clear();
                self.autocomplete_selected_index = None;

                if value.ends_with(':') {
                    self.autocomplete_suggestions = self.generate_autocomplete();
                }

                self.last_keystroke = Some(Instant::now());

                // Focus alone leaves the caret where it was, which lands it in
                // the middle of the text just inserted. Park it at the end so
                // typing continues from the completion.
                return Task::batch([
                    iced::widget::operation::focus(self.text_input_id.clone()),
                    iced::widget::operation::text_input::move_cursor_to_end(
                        self.text_input_id.clone(),
                    ),
                ]);
            }
            Message::AutocompleteNavigate(nav) => match nav {
                AutocompleteNav::Down => {
                    if let Some(current) = self.autocomplete_selected_index {
                        self.autocomplete_selected_index = Some(
                            (current + 1)
                                .min(self.autocomplete_suggestions.len().saturating_sub(1)),
                        );
                    } else if !self.autocomplete_suggestions.is_empty() {
                        self.autocomplete_selected_index = Some(0);
                    }
                }
                AutocompleteNav::Up => {
                    if let Some(current) = self.autocomplete_selected_index {
                        self.autocomplete_selected_index = Some(current.saturating_sub(1));
                    }
                }
                AutocompleteNav::Select => {
                    if let Some(index) = self.autocomplete_selected_index
                        && let Some(option) = self.autocomplete_suggestions.get(index)
                    {
                        return self.update(Message::SelectAutocomplete(option.insert.clone()));
                    }
                }
                AutocompleteNav::Escape => {
                    self.autocomplete_suggestions.clear();
                    self.autocomplete_selected_index = None;
                }
            },
        }
        Task::none()
    }

    pub fn view<'a>(&'a self) -> Element<'a, Message> {
        let process: Element<Message> = match &self.process_info {
            DataState::Loaded(Ok(sockets)) => {
                // Parsed once for the whole sweep. It used to be rebuilt inside
                // the closure, so every socket re-tokenized the filter string.
                let filter = &self.parsed_filter;

                let mut rows: Vec<&SocketDisplay> = sockets
                    .iter()
                    .filter(|socket| filter.as_ref().is_none_or(|expr| expr.matches(socket)))
                    .collect();

                if let Some(sort) = self.sort {
                    sort_rows(&mut rows, sort);
                }

                let keys: Vec<_> = rows.iter().map(|r| r.key.clone()).collect();
                let selected_rows: BTreeSet<usize> = rows
                    .iter()
                    .enumerate()
                    .filter(|(_, r)| {
                        self.selected
                            .as_ref()
                            .is_some_and(|c| r.key.as_ref() == Some(&c.key))
                    })
                    .map(|(i, _)| i)
                    .collect();
                let bold = |header| {
                    text(header).font(Font {
                        weight: font::Weight::Bold,
                        ..Font::DEFAULT
                    })
                };

                // Column order follows the question people ask: which program,
                // then where it talks, then what the firewall makes of it.
                let mono = |value: &'a str| text(value).font(Font::MONOSPACE).size(13);
                data_table(vec![
                    leaf(bold("Process")).fill(2).sortable(),
                    leaf(bold("PID"))
                        .fixed(80.0)
                        .align(alignment::Horizontal::Right)
                        .sortable(),
                    leaf(bold("Proto")).fixed(70.0).sortable(),
                    leaf(bold("Local")).fill(3).sortable(),
                    leaf(bold("Remote")).fill(3).sortable(),
                    leaf(bold("State")).fixed(120.0).sortable(),
                    leaf(bold("Reach")).fixed(130.0),
                ])
                .rows(rows, move |socket, column| match column {
                    0 => text(&socket.process_name).boxed(),
                    1 => mono(&socket.pid).boxed(),
                    2 => text(&socket.protocol).boxed(),
                    3 => mono(&socket.local_addr).boxed(),
                    4 => mono(&socket.remote_addr).boxed(),
                    5 => text(&socket.state).boxed(),
                    _ => self.reach_cell(socket.key.as_ref()),
                })
                .selection(
                    advanced_table::SelectionMode::Single,
                    &selected_rows,
                    move |set| {
                        Message::SelectConnection(
                            set.iter()
                                .next()
                                .and_then(|i| keys.get(*i))
                                .cloned()
                                .flatten(),
                        )
                    },
                )
                .sorting(self.sort, Message::SortChanged)
                .vertical_scroll(Policy::Auto)
                .horizontal_scroll(Policy::Auto)
                .padding([5.0, 10.0])
                .spacing(1.0_f32)
                .resizable(true)
                .height(Length::Fill)
                .boxed()
            }

            DataState::NotLoaded => text("Loading network information…").boxed(),
            DataState::Loaded(Err(e)) => text(format!("Error: {}", e)).boxed(),
        };

        let page = container(
            column![
                row![
                    text("Filter : "),
                    popover(
                        text_input("Filter text i.e. port:5013", &self.filter_text_staged)
                            .on_input(Message::FilterChanged)
                            .on_submit(Message::FilterChangedImmediate(
                                self.filter_text_staged.clone()
                            ))
                            .id(self.text_input_id.clone())
                            .size(16)
                            .padding(5.0),
                        column(self.autocomplete_suggestions.iter().enumerate().map(
                            |(idx, suggestion)| {
                                let is_selected = self.autocomplete_selected_index == Some(idx);

                                button(text(&suggestion.display))
                                    .on_press(Message::SelectAutocomplete(
                                        suggestion.insert.clone(),
                                    ))
                                    .width(Length::Fill)
                                    .style(if is_selected {
                                        button::primary
                                    } else {
                                        button::secondary
                                    })
                            }
                        ))
                        .spacing(2)
                    )
                    .open(!self.autocomplete_suggestions.is_empty())
                    .side(Side::Bottom)
                    .align(Align::Start)
                    .gap(0.0)
                    .padding(0.0)
                    .min_width(260.0)
                    .style(blank_popover),
                    button(icon::refresh())
                        .on_press(Message::RefreshData)
                        .style(button::text),
                    button(if self.show_panel {
                        "Hide reachability"
                    } else {
                        "Reachability"
                    })
                    .style(button::secondary)
                    .on_press(Message::TogglePanel)
                ]
                .spacing(10)
                .align_y(Alignment::Center)
                .padding(10.0),
                match &self.filter_error {
                    Some(error) => text(error).size(12).style(text::danger).boxed(),
                    None => space::horizontal().height(0).boxed(),
                },
                if self.show_panel {
                    row![
                        container(process).width(Length::Fill).height(Length::Fill),
                        self.reach_panel()
                    ]
                    .spacing(10)
                    .boxed()
                } else {
                    container(process)
                        .width(Length::Fill)
                        .height(Length::Fill)
                        .boxed()
                },
                text(self.inventory_status())
                    .size(12)
                    .style(diagnostic_style::muted),
            ]
            .width(Length::Fill)
            .height(Length::Fill)
            .padding(10.0),
        );

        // A `Stack`, not a `Column`: the layer reports a zero size, and a column
        // with spacing would still budget a gap for it.
        let content = stack![
            page,
            self.settings(),
            self.workbench_modal(),
            self.rule_detail_modal()
        ];

        // Until `install_latest` resolves there is no window to decorate. In
        // practice that is the first frame only.
        let Some(window_id) = self.frame.primary_window() else {
            return content.boxed();
        };

        // The title bar's application-owned row. The leading space captures
        // nothing, so it falls through to the draggable region behind it and
        // the gear ends up beside the caption controls.
        let title_content = row![
            space::horizontal(),
            button(icon::settings())
                .style(button::text)
                .padding([0.0, 10.0])
                .on_press(Message::Settings),
        ]
        .align_y(Alignment::Center);

        // The frame draws its title bar from the same palette the rest of the
        // app uses, so it follows the theme picker with nothing else wired.
        // The frame's icon slot clips to `window_icon_size` instead of scaling,
        // so the image is sized here to land inside it.
        let window_icon: Option<Element<'a, Message>> = self.icon.clone().map(|handle| {
            iced::widget::image(handle)
                .width(TITLE_BAR_ICON_SIZE)
                .height(TITLE_BAR_ICON_SIZE)
                .boxed()
        });

        self.frame.view(
            window_id,
            "Easy Net Stat",
            window_icon,
            Some(title_content.boxed()),
            content,
            Message::Frame,
        )
    }

    /// The settings surface: a modal window over a dimmed page.
    fn settings(&self) -> Element<'_, Message> {
        let interval = row![
            text("Every"),
            text_input("5", &self.refresh_secs_input)
                .on_input(Message::RefreshIntervalChanged)
                .width(Length::Fixed(70.0))
                .padding(5.0),
            text("seconds (1–3600)"),
            text(
                if easy_netstat::state::valid_interval(&self.refresh_secs_input).is_some() {
                    ""
                } else {
                    "Invalid interval; previous value remains active"
                }
            )
            .size(12),
        ]
        .spacing(8)
        .align_y(Alignment::Center);

        modal(
            column![
                toggler(self.auto_refresh)
                    .label("Refresh automatically")
                    .on_toggle(Message::AutoRefreshToggled),
                interval,
                row![
                    text("Theme"),
                    space::horizontal(),
                    pick_list(Some(&self.theme), Theme::ALL, Theme::to_string)
                        .menu_height(Length::Fixed(300.0))
                        .on_select(Message::ThemeChanged),
                ]
                .spacing(8)
                .align_y(Alignment::Center),
            ]
            .spacing(16),
            "Settings",
        )
        .open(self.show_settings)
        .min_width(340.0)
        .on_dismiss(Message::SettingsDismissed)
        .boxed()
    }

    fn subscription(&self) -> Subscription<Message> {
        use iced::keyboard::{Key, key};

        let tick = if self.last_keystroke.is_some() {
            time::every(std::time::Duration::from_millis(50)).map(|_| Message::CheckDebounce)
        } else {
            Subscription::none()
        };

        let auto_refresh = if self.auto_refresh {
            time::every(std::time::Duration::from_secs(self.refresh_secs.max(1)))
                .map(|_| Message::RefreshData)
        } else {
            Subscription::none()
        };

        let keyboard = if self.autocomplete_suggestions.is_empty() {
            Subscription::none()
        } else {
            event::listen_with(|event, _, _| match event {
                event::Event::Keyboard(keyboard::Event::KeyPressed { key, .. }) => match key {
                    Key::Named(key::Named::ArrowDown) => {
                        Some(Message::AutocompleteNavigate(AutocompleteNav::Down))
                    }
                    Key::Named(key::Named::ArrowUp) => {
                        Some(Message::AutocompleteNavigate(AutocompleteNav::Up))
                    }
                    Key::Named(key::Named::Enter) | Key::Named(key::Named::Tab) => {
                        Some(Message::AutocompleteNavigate(AutocompleteNav::Select))
                    }
                    Key::Named(key::Named::Escape) => {
                        Some(Message::AutocompleteNavigate(AutocompleteNav::Escape))
                    }
                    _ => None,
                },
                _ => None,
            })
        };

        // The frame needs the window events to track maximization and focus.
        let frame = self.frame.subscription().map(Message::Frame);

        Subscription::batch(vec![tick, auto_refresh, keyboard, frame])
    }

    fn generate_autocomplete(&self) -> Vec<AutocompleteOption> {
        if self.filter_text_staged.is_empty() {
            return vec![];
        }

        let mut suggestions = Vec::new();

        // Get unique values from current data
        if let DataState::Loaded(Ok(sockets)) = &self.process_info {
            let token_start = filter::last_token_start(&self.filter_text_staged);
            let last_token = &self.filter_text_staged[token_start..];

            // Check if typing a field name
            if last_token.contains(':') {
                let (field, partial) = last_token.split_once(':').unwrap();
                let partial_lower = partial.trim_matches('"').to_lowercase();

                // Everything already typed except the token being completed, so
                // the values offered are the ones actually reachable: with
                // `local:5013 proc:` in the box, only the processes on that port.
                //
                // Criteria on the same field are dropped, because
                // `optimize_filter` OR-s those together -- narrowing by
                // `proc:chrome` would hide every process that could be added
                // next to it.
                let field_name = parse_single_criterion(last_token).field_name();

                let context = filter::completion_context(
                    &self.filter_text_staged[..token_start],
                    &field_name,
                );

                let in_context = |socket: &SocketDisplay| {
                    context.as_ref().is_none_or(|expr| expr.matches(socket))
                };

                // Ordered, not hashed: the highlighted row is tracked by index,
                // so a set that reshuffles each keystroke moves the selection
                // out from under the arrow keys.
                let mut values = std::collections::BTreeSet::new();

                for socket in sockets.iter().filter(|socket| in_context(socket)) {
                    if field.eq_ignore_ascii_case("port") {
                        for endpoint in [&socket.local_addr, &socket.remote_addr] {
                            if let Ok(address) = endpoint.parse::<std::net::SocketAddr>() {
                                let value = address.port().to_string();
                                if value.contains(&partial_lower) {
                                    values.insert(value);
                                }
                            }
                        }
                        continue;
                    }
                    // Every field the filter parser understands, under the same
                    // names and aliases `parse_single_criterion` accepts.
                    let value = match field.to_lowercase().as_str() {
                        "protocol" | "proto" => &socket.protocol,
                        "process" | "proc" => &socket.process_name,
                        "state" => &socket.state,
                        "local" | "localaddr" => &socket.local_addr,
                        "remote" | "remoteaddr" => &socket.remote_addr,
                        "pid" => &socket.pid,
                        _ => continue,
                    };

                    if value.to_lowercase().contains(&partial_lower) {
                        values.insert(value.clone());
                    }
                }

                for value in values {
                    suggestions.push(AutocompleteOption {
                        display: format!("{}:{}", field, value),
                        insert: format!("{}:{}", field, filter::quote_value(&value)),
                    });
                }
            } else {
                // Suggest field names
                let field_names = vec![
                    "protocol:",
                    "process:",
                    "state:",
                    "local:",
                    "remote:",
                    "pid:",
                    "port:",
                ];

                for field in field_names {
                    if field.starts_with(&last_token.to_lowercase()) {
                        suggestions.push(AutocompleteOption {
                            display: field.to_string(),
                            insert: field.to_string(),
                        });
                    }
                }
            }
        }

        suggestions.truncate(10); // Limit to 10 suggestions
        suggestions
    }
}

pub fn main() -> iced::Result {
    let frame = NativeFrame::new(NativeFrameConfig::platform_default());

    // The frame has requirements of its own for the window -- undecorated, and
    // whatever the platform needs for rounded corners and the drop shadow -- so
    // it gets to amend the settings before they are handed to iced.
    let settings = frame.window_settings(App::window_settings());

    iced::application(
        {
            let frame = frame.clone();

            move || {
                let (app, task) = App::new(frame.clone());

                // `install_latest` subclasses the window iced just opened, which
                // is what gives the title bar its Windows 11 caption semantics.
                (app, Task::batch([task, frame.install_latest().discard()]))
            }
        },
        App::update,
        App::view,
    )
    .theme(App::theme)
    .title(App::title)
    .subscription(App::subscription)
    .window(settings)
    .fonts([icon::FONT])
    .run()
}

/// A popover surface with no chrome of its own.
///
/// The suggestion buttons draw the whole dropdown, so the surface behind them
/// stays out of the way - the same thing `generic_overlay::blank` used to do.
fn blank_popover(theme: &Theme) -> popover::Style {
    popover::Style {
        background: iced::Background::Color(iced::Color::TRANSPARENT),
        border: iced::Border::default(),
        shadow: iced::Shadow::default(),
        text_color: theme.palette().background.base.text,
    }
}

/// Order the visible rows by the column the table reports as sorted.
///
/// The table draws the sort indicator and hands back what the sort should
/// become, but never reorders anything itself -- it only ever sees the
/// `Element` built from each field, not the value behind it.
fn sort_rows(rows: &mut [&SocketDisplay], sort: Sort) {
    rows.sort_by(|a, b| {
        let ordering = match sort.column {
            2 => a.protocol.cmp(&b.protocol),
            5 => a.state.cmp(&b.state),
            3 => a
                .local_addr
                .parse::<std::net::SocketAddr>()
                .ok()
                .cmp(&b.local_addr.parse::<std::net::SocketAddr>().ok()),
            4 => a
                .remote_addr
                .parse::<std::net::SocketAddr>()
                .ok()
                .cmp(&b.remote_addr.parse::<std::net::SocketAddr>().ok()),
            // Numerically, so 9 comes before 10. Sockets with no owning process
            // carry "-" rather than a number, and sort to the end ascending.
            1 => a
                .pid
                .parse::<u32>()
                .unwrap_or(u32::MAX)
                .cmp(&b.pid.parse::<u32>().unwrap_or(u32::MAX)),
            _ => a
                .process_name
                .to_lowercase()
                .cmp(&b.process_name.to_lowercase()),
        };

        match sort.direction {
            Direction::Ascending => ordering,
            Direction::Descending => ordering.reverse(),
        }
    });
}

#[derive(Debug, Clone)]
struct AutocompleteOption {
    display: String,
    insert: String,
}

#[derive(Debug, Clone)]
enum AutocompleteNav {
    Up,
    Down,
    Select,
    Escape,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn immediate_filter_paste_updates_staged_and_applied_text() {
        let mut app = App::new(NativeFrame::default()).0;
        let _ = app.update(Message::FilterChangedImmediate("port:5001".into()));
        assert_eq!(app.filter_text_staged, "port:5001");
        assert_eq!(app.filter_text, "port:5001");
        assert!(app.last_keystroke.is_none());
        let _ = app.update(Message::FilterChangedImmediate("(".into()));
        assert_eq!(app.filter_text, "port:5001");
        assert!(app.filter_error.is_some());
    }
    #[test]
    fn completion_preserves_quoted_context_and_exact_port_suggestions() {
        let mut app = typing(
            vec![socket("0.0.0.0:5001", "Acme Agent.exe", "42")],
            "proc:\"Acme Agent.exe\" port:50",
        );
        assert_eq!(suggestions(&app), vec!["port:5001"]);
        let _ = app.update(Message::SelectAutocomplete("port:5001".into()));
        assert_eq!(app.filter_text_staged, "proc:\"Acme Agent.exe\" port:5001 ");
        app.filter_text_staged = "proc:Acme".into();
        assert_eq!(suggestions(&app), vec!["proc:\"Acme Agent.exe\""]);
    }
    #[test]
    fn leaving_filter_for_settings_or_details_dismisses_completion() {
        let mut app = typing(vec![socket("0.0.0.0:5001", "IFC8.exe", "42")], "proc:");
        app.autocomplete_suggestions = app.generate_autocomplete();
        assert!(!app.autocomplete_suggestions.is_empty());
        let _ = app.update(Message::Settings);
        assert!(app.autocomplete_suggestions.is_empty());
        app.autocomplete_suggestions = app.generate_autocomplete();
        let _ = app.update(Message::SelectConnection(None));
        assert!(app.autocomplete_suggestions.is_empty());
    }
    #[test]
    fn invalid_refresh_input_keeps_last_valid_interval_and_pause_clears_pending() {
        let mut app = App::new(NativeFrame::default()).0;
        for input in ["0", "", "3601", "999999999999999999999"] {
            let _ = app.update(Message::RefreshIntervalChanged(input.into()));
            assert_eq!(app.refresh_secs, 5);
        }
        let _ = app.update(Message::RefreshIntervalChanged("10".into()));
        assert_eq!(app.refresh_secs, 10);
        let id = app.inventory_gate.request().unwrap();
        app.inventory_gate.request();
        let _ = app.update(Message::AutoRefreshToggled(false));
        assert_eq!(app.inventory_gate.finish(id), Some(false));
    }
    #[test]
    fn sort_uses_numeric_pid_and_endpoint_port() {
        let a = socket("127.0.0.1:9", "a", "9");
        let b = socket("127.0.0.1:10", "B", "10");
        let mut rows = vec![&b, &a];
        for column in [3, 1] {
            sort_rows(
                &mut rows,
                Sort {
                    column,
                    direction: Direction::Ascending,
                },
            );
            assert_eq!(rows[0].pid, "9");
            sort_rows(
                &mut rows,
                Sort {
                    column,
                    direction: Direction::Descending,
                },
            );
            assert_eq!(rows[0].pid, "10");
        }
    }
    #[test]
    fn stale_inventory_and_analysis_results_cannot_replace_state() {
        let mut app = App::new(NativeFrame::default()).0;
        let id = app.inventory_gate.request().unwrap();
        let _ = app.update(Message::InventoryReady(
            id + 1,
            Ok(Arc::new(Inventory::default())),
        ));
        assert!(app.inventory_gate.busy());
        app.analysis_request = 2;
        app.analysis_busy = true;
        let key = ConnectionKey {
            protocol: Protocol::Tcp,
            local: "127.0.0.1:1".parse().unwrap(),
            remote: None,
            process: ProcessKey {
                pid: 1,
                created: Some(1),
            },
            ordinal: 0,
        };
        let _ = app.update(Message::AnalysisReady(
            1,
            key,
            Ok(Arc::new(Analysis {
                evaluator_version: 99,
                ..Analysis::default()
            })),
        ));
        assert!(!app.analysis_busy);
        assert_eq!(app.analysis.evaluator_version, 0);
    }
    #[test]
    fn large_connection_table_constructs_without_collecting() {
        let mut app = App::new(NativeFrame::default()).0;
        app.process_info = DataState::Loaded(Ok((0..10_000)
            .map(|i| {
                socket(
                    &format!("127.0.0.1:{}", i + 1),
                    "fixture.exe",
                    &i.to_string(),
                )
            })
            .collect()));
        let _ = app.view();
        assert!(!app.inventory_gate.busy());
    }

    fn socket(local: &str, process: &str, pid: &str) -> SocketDisplay {
        SocketDisplay {
            key: None,
            protocol: String::from("TCP"),
            state: String::from("Listen"),
            local_addr: String::from(local),
            remote_addr: String::from("*:*"),
            pid: String::from(pid),
            process_name: String::from(process),
        }
    }

    /// An app holding `sockets`, with `typed` sitting in the filter box.
    fn typing(sockets: Vec<SocketDisplay>, typed: &str) -> App {
        let mut app = App::new(NativeFrame::default()).0;

        app.process_info = DataState::Loaded(Ok(sockets));
        app.filter_text_staged = String::from(typed);

        app
    }

    fn suggestions(app: &App) -> Vec<String> {
        app.generate_autocomplete()
            .into_iter()
            .map(|option| option.insert)
            .collect()
    }

    #[test]
    fn every_field_offers_values_not_just_the_three_that_used_to() {
        let sockets = vec![socket("0.0.0.0:5013", "server.exe", "42")];

        for (typed, expected) in [
            ("local:50", "local:0.0.0.0:5013"),
            ("remote:*", "remote:*:*"),
            ("pid:4", "pid:42"),
        ] {
            assert_eq!(suggestions(&typing(sockets.clone(), typed)), vec![expected]);
        }
    }

    #[test]
    fn suggestions_are_narrowed_by_the_rest_of_the_filter() {
        let sockets = vec![
            socket("0.0.0.0:5013", "server.exe", "1"),
            socket("0.0.0.0:5013", "agent.exe", "2"),
            socket("0.0.0.0:9999", "unrelated.exe", "3"),
        ];

        // Only the two processes actually on 5013, rather than every process
        // the machine happens to be running.
        assert_eq!(
            suggestions(&typing(sockets, "local:5013 proc:")),
            vec!["proc:agent.exe", "proc:server.exe"],
        );
    }

    #[test]
    fn a_second_value_for_one_field_still_sees_its_alternatives() {
        let sockets = vec![
            socket("0.0.0.0:5013", "server.exe", "1"),
            socket("0.0.0.0:9999", "agent.exe", "2"),
        ];

        // `optimize_filter` OR-s criteria on the same field, so narrowing by
        // the first `proc:` would leave nothing left to add beside it.
        assert_eq!(
            suggestions(&typing(sockets, "proc:server.exe proc:")),
            vec!["proc:agent.exe", "proc:server.exe"],
        );
    }

    #[test]
    fn the_icon_decodes_for_both_the_window_and_the_title_bar() {
        // Guards the `image` crate's `ico` feature as much as the file itself:
        // without it the decode returns `Err` and both callers silently fall
        // back to no icon at all.
        let icon = window_icon().expect("the .ico decodes for the window");
        let (pixels, size) = icon.into_raw();

        assert_eq!(
            size,
            iced::Size::new(256, 256),
            "expected the largest entry"
        );
        assert_eq!(pixels.len(), 256 * 256 * 4, "expected RGBA");

        assert!(
            title_bar_icon().is_some(),
            "the .ico decodes for the title bar",
        );
    }

    #[test]
    fn completing_a_value_leaves_a_trailing_space_but_a_field_name_does_not() {
        let mut app = typing(vec![socket("0.0.0.0:5013", "server.exe", "42")], "local:");

        // A bare field name is only half a criterion -- the caret has to stay
        // put so the value can be typed straight after the colon.
        let _ = app.update(Message::SelectAutocomplete(String::from("local:")));
        assert_eq!(app.filter_text_staged, "local:");

        let _ = app.update(Message::SelectAutocomplete(String::from(
            "local:0.0.0.0:5013",
        )));
        assert_eq!(app.filter_text_staged, "local:0.0.0.0:5013 ");
    }
}
