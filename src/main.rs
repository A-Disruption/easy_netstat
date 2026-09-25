use iced::{
    Length, Alignment, Element, Subscription, Theme, Task, Font, font, alignment, time,
    widget::{button, column, container, pick_list, row, space, stack, text, text_input,
             toggler},
};
use iced::widget;
use iced::keyboard;
use iced::event;
use iced::time::Instant;

use advanced_table::{data_table, leaf, Direction, Policy, Sort};
use iced_native_frame::{FrameAction, NativeFrame, NativeFrameConfig};
use widgets::anchor::{Align, Side};
use widgets::layer::modal;
use widgets::popover::{self, popover};
use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, SocketInfo, error::Error};
use sysinfo::{ProcessesToUpdate, RefreshKind, System};

mod icon;

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
pub enum Message {
    Settings,
    RefreshData,
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
    process_info: DataState<Vec<SocketDisplay>, Error>,
    system_info: System,
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
    Loading,
    Loaded(Result<T, E>),
}

#[derive(Clone)]
struct SocketDisplay {
    protocol: String,
    state: String,
    local_addr: String,
    remote_addr: String,
    pid: String,
    process_name: String,
}

impl SocketDisplay {
    fn from_socket(socket: &SocketInfo, sys: &System) -> Self {
        let protocol = match socket.protocol_socket_info {
            ProtocolSocketInfo::Tcp(_) => "TCP".to_string(),
            ProtocolSocketInfo::Udp(_) => "UDP".to_string(),
        };

        let (local_addr, remote_addr, state) = match &socket.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp_info) => (
                format!("{}:{}", tcp_info.local_addr, tcp_info.local_port),
                format!("{}:{}", tcp_info.remote_addr, tcp_info.remote_port),
                format!("{:?}", tcp_info.state),
            ),
            ProtocolSocketInfo::Udp(udp_info) => (
                format!("{}:{}", udp_info.local_addr, udp_info.local_port),
                String::from("*:*"),
                String::from("-"),
            ),
        };

        let process_name = socket
            .associated_pids
            .first()
            .and_then(|&pid| sys.process(sysinfo::Pid::from_u32(pid)))
            .map(|process| process.name().to_string_lossy().to_string())
            .unwrap_or_else(|| String::from("Unknown"));

        let pid = socket
            .associated_pids
            .first()
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| String::from("-"));

        Self {
            protocol,
            state,
            local_addr,
            remote_addr,
            pid,
            process_name,
        }
    }
}

impl App {
    pub fn new(frame: NativeFrame) -> (Self, Task<Message>) {
        let sys = System::new_with_specifics(
            RefreshKind::everything(),
        );        
        (
            Self {
                process_info: DataState::NotLoaded,
                system_info: sys,
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
            Task::done(Message::RefreshData)
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
            min_size: Some( iced::Size::new(1275.0, 768.0) ),
            icon: window_icon(),
            ..iced::window::Settings::default()
        }
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Settings => {
                self.show_settings = !self.show_settings;
            }
            Message::SettingsDismissed => {
                self.show_settings = false;
            }
            Message::AutoRefreshToggled(enabled) => {
                self.auto_refresh = enabled;
            }
            Message::RefreshIntervalChanged(value) => {
                // Digits only. The interval itself only moves when the field
                // holds something usable, so clearing it leaves the last good
                // value running rather than dropping to zero.
                let digits: String = value.chars().filter(char::is_ascii_digit).collect();

                if let Ok(secs) = digits.parse::<u64>()
                    && secs > 0
                {
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
                self.filter_text = self.filter_text_staged.clone();
            }
            Message::RefreshData => {
                let socket_info = get_netstat(&mut self.system_info);
                
                self.process_info = DataState::Loaded(
                    socket_info.map(|sockets| {
                        sockets
                            .iter()
                            .map(|socket| SocketDisplay::from_socket(socket, &self.system_info))
                            .collect()
                    })
                );
            }
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
                if let Some(last) = self.last_keystroke {
                    if last.elapsed() >= self.debounce_duration {
                        self.filter_text = self.filter_text_staged.clone();
                    }
                }
            }
            Message::SelectAutocomplete(value) => {
                // Replace last token with selected value
                let mut tokens: Vec<&str> = self.filter_text_staged.split_whitespace().collect();
                if !tokens.is_empty() {
                    tokens.pop();
                }
                tokens.push(&value);

                // Only add trailing space if the value doesn't end with ':'
                let trailing_space = if value.ends_with(':') {
                    ""
                } else {
                    " "
                };

                self.filter_text_staged = tokens.join(" ") + trailing_space;

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
                    iced::widget::operation::move_cursor_to_end(self.text_input_id.clone()),
                ]);
            }
            Message::AutocompleteNavigate(nav) => {
                match nav {
                    AutocompleteNav::Down => {
                        if let Some(current) = self.autocomplete_selected_index {
                            self.autocomplete_selected_index = Some(
                                (current + 1).min(self.autocomplete_suggestions.len().saturating_sub(1))
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
                        if let Some(index) = self.autocomplete_selected_index {
                            if let Some(option) = self.autocomplete_suggestions.get(index) {
                                return self.update(Message::SelectAutocomplete(option.insert.clone()));
                            }
                        }
                    }
                    AutocompleteNav::Escape => {
                        self.autocomplete_suggestions.clear();
                        self.autocomplete_selected_index = None;
                    }
                }
            }
        }
        Task::none()
    }

    pub fn view<'a>(&'a self) -> Element<'a, Message> {
        let process: Element<Message> = match &self.process_info {
            DataState::Loaded(Ok(sockets)) => {
                // Parsed once for the whole sweep. It used to be rebuilt inside
                // the closure, so every socket re-tokenized the filter string.
                let filter = (!self.filter_text.is_empty())
                    .then(|| optimize_filter(parse_filter(&self.filter_text)));

                let mut rows: Vec<&SocketDisplay> = sockets
                    .iter()
                    .filter(|socket| filter.as_ref().is_none_or(|expr| expr.matches(socket)))
                    .collect();

                if let Some(sort) = self.sort {
                    sort_rows(&mut rows, sort);
                }

                let bold = |header| {
                    text(header).font(Font {
                        weight: font::Weight::Bold,
                        ..Font::DEFAULT
                    })
                };

                data_table(vec![
                    leaf(bold("Protocol")).fixed(90.0).sortable(),
                    leaf(bold("State")).fixed(130.0).sortable(),
                    leaf(bold("Local Address")).fill(2).sortable(),
                    leaf(bold("Remote Address")).fill(2).sortable(),
                    leaf(bold("PID"))
                        .fixed(80.0)
                        .align(alignment::Horizontal::Right)
                        .sortable(),
                    leaf(bold("Process")).fill(2).sortable(),
                ])
                .rows(rows, |socket, column| match column {
                    0 => text(&socket.protocol).into(),
                    1 => text(&socket.state).into(),
                    2 => text(&socket.local_addr).into(),
                    3 => text(&socket.remote_addr).into(),
                    4 => text(&socket.pid).into(),
                    _ => text(&socket.process_name).into(),
                })
                .sorting(self.sort, Message::SortChanged)
                .vertical_scroll(Policy::Auto)
                .horizontal_scroll(Policy::Auto)
                .padding([5.0, 10.0])
                .spacing(1.0)
                .resizable(true)
                .height(Length::Fill)
                .into()
            }
            DataState::Loading => text("Loading...").into(),
            DataState::NotLoaded => button("Load Network Info").into(),
            DataState::Loaded(Err(e)) => text(format!("Error: {}", e)).into(),
        };

        let page = container(
            column![
                row![
                    text("Filter : "),
                    popover(
                        text_input("Filter text i.e. port:5013", &self.filter_text_staged)
                            .on_input(Message::FilterChanged)
                            .on_submit(Message::FilterChangedImmediate(self.filter_text_staged.clone()))
                            .on_paste(Message::FilterChangedImmediate)
                            .id(self.text_input_id.clone())
                            .size(16)
                            .padding(5.0),
                        column(
                            self.autocomplete_suggestions.iter().enumerate().map(|(idx, suggestion)| {
                                let is_selected = self.autocomplete_selected_index == Some(idx);
                                
                                button(text(&suggestion.display))
                                    .on_press(Message::SelectAutocomplete(suggestion.insert.clone()))
                                    .width(Length::Fill)
                                    .style(if is_selected {
                                        button::primary
                                    } else {
                                        button::secondary
                                    })
                                    .into()
                            })
                        )
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
                        .style(button::text)
                ]
                .spacing(10)
                .align_y(Alignment::Center)
                .padding(10.0),
                container(process).height(Length::Fill)
            ]
            .width(Length::Fill)
            .height(Length::Fill)
            .padding(10.0)
        );

        // A `Stack`, not a `Column`: the layer reports a zero size, and a column
        // with spacing would still budget a gap for it.
        let content = stack![page, self.settings()];

        // Until `install_latest` resolves there is no window to decorate. In
        // practice that is the first frame only.
        let Some(window_id) = self.frame.primary_window() else {
            return content.into();
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
                .into()
        });

        self.frame.view(
            window_id,
            "Easy Net Stat",
            window_icon,
            Some(title_content.into()),
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
            text("seconds"),
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
        .into()
    }

    fn subscription(&self) -> Subscription<Message> {
        use iced::keyboard::{key, Key};

        let tick = time::every(std::time::Duration::from_millis(100)).map(|_| Message::CheckDebounce);

        let auto_refresh = if self.auto_refresh {
            time::every(std::time::Duration::from_secs(self.refresh_secs.max(1)))
                .map(|_| Message::RefreshData)
        } else {
            Subscription::none()
        };

        let keyboard = event::listen_with(|event, _, _| 
            match event {
                event::Event::Keyboard(keyboard::Event::KeyPressed { key, .. }) => {
                    match key {
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
                    }                    
                }
                _ => { None }
            }
        );

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
            let last_token = self.filter_text_staged
                .split_whitespace()
                .last()
                .unwrap_or("");

            // Check if typing a field name
            if last_token.contains(':') {
                let (field, partial) = last_token.split_once(':').unwrap();
                let partial_lower = partial.to_lowercase();

                // Everything already typed except the token being completed, so
                // the values offered are the ones actually reachable: with
                // `local:5013 proc:` in the box, only the processes on that port.
                //
                // Criteria on the same field are dropped, because
                // `optimize_filter` OR-s those together -- narrowing by
                // `proc:chrome` would hide every process that could be added
                // next to it.
                let field_name = parse_single_criterion(last_token).field_name();

                let context = {
                    let mut tokens: Vec<&str> =
                        self.filter_text_staged.split_whitespace().collect();
                    tokens.pop();

                    let rest = tokens
                        .into_iter()
                        .filter(|token| {
                            parse_single_criterion(token).field_name() != field_name
                        })
                        .collect::<Vec<_>>()
                        .join(" ");

                    (!rest.is_empty()).then(|| optimize_filter(parse_filter(&rest)))
                };

                let in_context = |socket: &SocketDisplay| {
                    context.as_ref().is_none_or(|expr| expr.matches(socket))
                };
                
                // Ordered, not hashed: the highlighted row is tracked by index,
                // so a set that reshuffles each keystroke moves the selection
                // out from under the arrow keys.
                let mut values = std::collections::BTreeSet::new();
                
                for socket in sockets.iter().filter(|socket| in_context(socket)) {
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
                        insert: format!("{}:{}", field, value),
                    });
                }
            } else {
                // Suggest field names
                let field_names = vec![
                    "protocol:", "process:", "state:", 
                    "local:", "remote:", "pid:"
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
            0 => a.protocol.cmp(&b.protocol),
            1 => a.state.cmp(&b.state),
            2 => a.local_addr.cmp(&b.local_addr),
            3 => a.remote_addr.cmp(&b.remote_addr),
            // Numerically, so 9 comes before 10. Sockets with no owning process
            // carry "-" rather than a number, and sort to the end ascending.
            4 => a
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

fn get_netstat(system: &mut System) -> Result<Vec<SocketInfo>, Error> {
    system.refresh_processes(ProcessesToUpdate::All, true);

    // Get all TCP and UDP sockets for IPv4 and IPv6
    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
    get_sockets_info(af_flags, proto_flags)
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

#[derive(Debug, Clone)]
enum Token {
    OpenParen,
    CloseParen,
    Or,
    Not,
    Criterion(FilterCriterion),
}

#[derive(Debug, Clone)]
enum FilterExpr {
    And(Vec<FilterExpr>),
    Or(Vec<FilterExpr>),
    Not(Box<FilterExpr>),
    Criterion(FilterCriterion),
}

impl FilterExpr {
    fn matches(&self, socket: &SocketDisplay) -> bool {
        match self {
            FilterExpr::And(exprs) => exprs.iter().all(|e| e.matches(socket)),
            FilterExpr::Or(exprs) => exprs.iter().any(|e| e.matches(socket)),
            FilterExpr::Not(expr) => !expr.matches(socket),
            FilterExpr::Criterion(criterion) => criterion.matches(socket),
        }
    }
}

#[derive(Debug, Clone)]
enum FilterCriterion {
    Protocol(FilterMatch),
    Process(FilterMatch),
    State(FilterMatch),
    LocalAddr(FilterMatch),
    RemoteAddr(FilterMatch),
    Pid(FilterMatch),
    Any(FilterMatch),
}

impl FilterCriterion {
    fn field_name(&self) -> String {
        match self {
            FilterCriterion::Protocol(_) => "protocol".to_string(),
            FilterCriterion::Process(_) => "process".to_string(),
            FilterCriterion::State(_) => "state".to_string(),
            FilterCriterion::LocalAddr(_) => "local".to_string(),
            FilterCriterion::RemoteAddr(_) => "remote".to_string(),
            FilterCriterion::Pid(_) => "pid".to_string(),
            FilterCriterion::Any(_) => "any".to_string(),
        }
    }

    fn matches(&self, socket: &SocketDisplay) -> bool {
        match self {
            FilterCriterion::Protocol(m) => m.matches(&socket.protocol),
            FilterCriterion::Process(m) => m.matches(&socket.process_name),
            FilterCriterion::State(m) => m.matches(&socket.state),
            FilterCriterion::LocalAddr(m) => m.matches(&socket.local_addr),
            FilterCriterion::RemoteAddr(m) => m.matches(&socket.remote_addr),
            FilterCriterion::Pid(m) => m.matches(&socket.pid),
            FilterCriterion::Any(m) => {
                m.matches(&socket.protocol)
                    || m.matches(&socket.process_name)
                    || m.matches(&socket.state)
                    || m.matches(&socket.local_addr)
                    || m.matches(&socket.remote_addr)
                    || m.matches(&socket.pid)
            }
        }
    }
}

#[derive(Debug, Clone)]
enum FilterMatch {
    Exact(String),      // "System" - exact match
    Contains(String),   // *System* - contains
    StartsWith(String), // System* - starts with
    EndsWith(String),   // *System - ends with
}

impl FilterMatch {
    fn matches(&self, value: &str) -> bool {
        let value_lower = value.to_lowercase();
        match self {
            FilterMatch::Exact(s) => value_lower == s.to_lowercase(),
            FilterMatch::Contains(s) => value_lower.contains(&s.to_lowercase()),
            FilterMatch::StartsWith(s) => value_lower.starts_with(&s.to_lowercase()),
            FilterMatch::EndsWith(s) => value_lower.ends_with(&s.to_lowercase()),
        }
    }
    
    fn from_pattern(pattern: &str) -> Self {
        // Check if pattern is quoted
        let is_quoted = pattern.starts_with('"') && pattern.ends_with('"');
        
        let clean_pattern = if is_quoted {
            // Remove quotes for exact match
            pattern.trim_matches('"').to_string()
        } else {
            pattern.to_string()
        };
        
        let starts_with_wildcard = clean_pattern.starts_with('*');
        let ends_with_wildcard = clean_pattern.ends_with('*');
        
        // If quoted and no wildcards, treat as exact match
        if is_quoted && !starts_with_wildcard && !ends_with_wildcard {
            return FilterMatch::Exact(clean_pattern);
        }
        
        // If not quoted and no explicit wildcards, add them automatically
        if !is_quoted && !starts_with_wildcard && !ends_with_wildcard {
            return FilterMatch::Contains(clean_pattern);
        }
        
        // Otherwise handle explicit wildcards
        match (starts_with_wildcard, ends_with_wildcard) {
            (true, true) => {
                FilterMatch::Contains(clean_pattern.trim_matches('*').to_string())
            }
            (true, false) => {
                FilterMatch::EndsWith(clean_pattern.trim_start_matches('*').to_string())
            }
            (false, true) => {
                FilterMatch::StartsWith(clean_pattern.trim_end_matches('*').to_string())
            }
            (false, false) => {
                FilterMatch::Exact(clean_pattern)
            }
        }
    }
}

fn parse_filter(input: &str) -> FilterExpr {
    let tokens = tokenize(input);
    parse_expression(&tokens, 0).0
}

fn tokenize(input: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                current.push(ch); // Keep the quote in the string
            }
            '(' if !in_quotes => {
                if !current.is_empty() {
                    tokens.push(Token::Criterion(parse_single_criterion(&current)));
                    current.clear();
                }
                tokens.push(Token::OpenParen);
            }
            ')' if !in_quotes => {
                if !current.is_empty() {
                    tokens.push(Token::Criterion(parse_single_criterion(&current)));
                    current.clear();
                }
                tokens.push(Token::CloseParen);
            }
            '|' if !in_quotes => {
                if !current.is_empty() {
                    tokens.push(Token::Criterion(parse_single_criterion(&current)));
                    current.clear();
                }
                tokens.push(Token::Or);
            }
            '!' if !in_quotes => {
                if !current.is_empty() {
                    tokens.push(Token::Criterion(parse_single_criterion(&current)));
                    current.clear();
                }
                tokens.push(Token::Not);
            }
            ' ' if !in_quotes => {
                if !current.is_empty() {
                    tokens.push(Token::Criterion(parse_single_criterion(&current)));
                    current.clear();
                }
            }
            _ => {
                current.push(ch);
            }
        }
    }

    if !current.is_empty() {
        tokens.push(Token::Criterion(parse_single_criterion(&current)));
    }

    tokens
}

fn parse_expression(tokens: &[Token], pos: usize) -> (FilterExpr, usize) {
    if pos >= tokens.len() {
        return (FilterExpr::And(vec![]), pos);
    }

    let mut current_pos = pos;
    let mut or_groups: Vec<Vec<FilterExpr>> = vec![vec![]];
    let mut current_or_index = 0;

    while current_pos < tokens.len() {
        match &tokens[current_pos] {
            Token::Not => {
                current_pos += 1;
                if current_pos >= tokens.len() {
                    break;
                }
                
                // Parse the next expression to negate
                let (expr, new_pos) = match &tokens[current_pos] {
                    Token::OpenParen => {
                        parse_expression(tokens, current_pos + 1)
                    }
                    Token::Criterion(criterion) => {
                        (FilterExpr::Criterion(criterion.clone()), current_pos + 1)
                    }
                    _ => break,
                };
                
                or_groups[current_or_index].push(FilterExpr::Not(Box::new(expr)));
                current_pos = new_pos;
            }
            Token::OpenParen => {
                let (sub_expr, new_pos) = parse_expression(tokens, current_pos + 1);
                or_groups[current_or_index].push(sub_expr);
                current_pos = new_pos;
            }
            Token::CloseParen => {
                current_pos += 1;
                break;
            }
            Token::Or => {
                or_groups.push(vec![]);
                current_or_index += 1;
                current_pos += 1;
            }
            Token::Criterion(criterion) => {
                or_groups[current_or_index].push(FilterExpr::Criterion(criterion.clone()));
                current_pos += 1;
            }
        }
    }

    // Build the expression tree
    let result = if or_groups.len() > 1 {
        let or_exprs: Vec<FilterExpr> = or_groups
            .into_iter()
            .map(|group| {
                if group.len() == 1 {
                    group.into_iter().next().unwrap()
                } else {
                    FilterExpr::And(group)
                }
            })
            .collect();
        FilterExpr::Or(or_exprs)
    } else {
        let group = or_groups.into_iter().next().unwrap();
        if group.len() == 1 {
            group.into_iter().next().unwrap()
        } else {
            FilterExpr::And(group)
        }
    };

    (result, current_pos)
}

fn parse_single_criterion(input: &str) -> FilterCriterion {
    if let Some((prefix, value)) = input.split_once(':') {
        let filter_match = FilterMatch::from_pattern(value);
        match prefix.to_lowercase().as_str() {
            "protocol" | "proto" => FilterCriterion::Protocol(filter_match),
            "process" | "proc" => FilterCriterion::Process(filter_match),
            "state" => FilterCriterion::State(filter_match),
            "local" | "localaddr" => FilterCriterion::LocalAddr(filter_match),
            "remote" | "remoteaddr" => FilterCriterion::RemoteAddr(filter_match),
            "pid" => FilterCriterion::Pid(filter_match),
            _ => FilterCriterion::Any(FilterMatch::from_pattern(input)),
        }
    } else {
        FilterCriterion::Any(FilterMatch::from_pattern(input))
    }
}

fn optimize_filter(expr: FilterExpr) -> FilterExpr {
    match expr {
        FilterExpr::And(exprs) => {
            // Group criteria by field type
            let mut by_field: std::collections::HashMap<String, Vec<FilterCriterion>> = 
                std::collections::HashMap::new();
            let mut other_exprs = Vec::new();

            for e in exprs {
                match e {
                    FilterExpr::Criterion(criterion) => {
                        let field_name = criterion.field_name();
                        by_field.entry(field_name).or_insert_with(Vec::new).push(criterion);
                    }
                    other => other_exprs.push(optimize_filter(other)),
                }
            }

            // Convert fields with multiple criteria to OR
            let mut result = Vec::new();
            for (_, criteria) in by_field {
                if criteria.len() > 1 {
                    result.push(FilterExpr::Or(
                        criteria.into_iter().map(FilterExpr::Criterion).collect()
                    ));
                } else {
                    result.push(FilterExpr::Criterion(criteria.into_iter().next().unwrap()));
                }
            }
            result.extend(other_exprs);

            if result.len() == 1 {
                result.into_iter().next().unwrap()
            } else {
                FilterExpr::And(result)
            }
        }
        FilterExpr::Or(exprs) => {
            FilterExpr::Or(exprs.into_iter().map(optimize_filter).collect())
        }
        other => other,
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn socket(local: &str, process: &str, pid: &str) -> SocketDisplay {
        SocketDisplay {
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

        assert_eq!(size, iced::Size::new(256, 256), "expected the largest entry");
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
