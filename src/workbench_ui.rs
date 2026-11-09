use super::*;
use easy_netstat::model::Direction as TrafficDirection;
use iced::widget::scrollable;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DiagnosticTab {
    Overview,
    Firewall,
    Process,
    Network,
    Events,
    History,
    Tools,
}
impl DiagnosticTab {
    const ALL: [Self; 7] = [
        Self::Overview,
        Self::Firewall,
        Self::Process,
        Self::Network,
        Self::Events,
        Self::History,
        Self::Tools,
    ];
    fn label(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Firewall => "Firewall rules",
            Self::Process => "Process / services",
            Self::Network => "Network",
            Self::Events => "Events",
            Self::History => "History",
            Self::Tools => "Tools / reports",
        }
    }
}
const RULES_PER_PAGE: usize = 10;

impl App {
    pub(super) fn apply_filter(&mut self) {
        match filter::validate(&self.filter_text_staged) {
            Ok(()) => {
                self.filter_text = self.filter_text_staged.clone();
                self.parsed_filter = (!self.filter_text.is_empty())
                    .then(|| optimize_filter(parse_filter(&self.filter_text)));
                self.filter_error = None;
            }
            Err(e) => {
                self.filter_error = Some(format!("{e}. Previous valid filter remains applied."))
            }
        }
    }
    pub(super) fn start_inventory(&mut self) -> Task<Message> {
        let Some(id) = self.inventory_gate.request() else {
            return Task::none();
        };
        let collector = self.collector.clone();
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    collector
                        .lock()
                        .map_err(|_| "Inventory worker unavailable".to_string())
                        .map(|mut c| Arc::new(c.collect()))
                })
                .await
                .unwrap_or_else(|e| Err(e.to_string()))
            },
            move |result| Message::InventoryReady(id, result),
        )
    }
    pub(super) fn inventory_status(&self) -> String {
        format!(
            "{} | {} endpoints | last success: {} | changes: {} ({} evicted){}",
            if self.inventory_gate.busy() {
                "Refreshing…"
            } else if self.auto_refresh {
                "Automatic refresh enabled"
            } else {
                "Automatic refresh paused"
            },
            self.history.current.len(),
            self.history
                .last_success_ms
                .map(|t| format!("{t} ms UTC"))
                .unwrap_or_else(|| "not yet available".into()),
            self.history.changes.len(),
            self.history.evicted,
            if self.history.errors.is_empty() {
                String::new()
            } else {
                format!(" | PARTIAL/STALE: {}", self.history.errors.join("; "))
            }
        )
    }
    fn scenario(&self) -> Result<Scenario, String> {
        let c = self.selected.as_ref().ok_or("Select a connection")?;
        let local = self
            .local_input
            .parse()
            .map_err(|_| "Enter local IP:port; IPv6 needs brackets")?;
        let remote = if self.peer_input.trim().is_empty() {
            None
        } else {
            Some(
                self.peer_input
                    .trim()
                    .parse()
                    .map_err(|_| "Enter peer IP:port; IPv6 needs brackets")?,
            )
        };
        let mut s = Scenario::for_connection(c);
        s.local = local;
        s.remote = remote;
        s.direction = self.direction;
        s.service =
            (!self.expected_service.trim().is_empty()).then(|| self.expected_service.trim().into());
        if let Some(data) = &self.diagnostic_data {
            let interfaces: Vec<_> = data
                .interfaces
                .iter()
                .filter(|i| {
                    if self.interface_input.is_empty() {
                        i.has_ip(s.local.ip())
                    } else {
                        i.alias.eq_ignore_ascii_case(&self.interface_input)
                    }
                })
                .collect();
            if interfaces.len() == 1 {
                let i = interfaces[0];
                s.interface = Some(i.alias.clone());
                s.profile = (!i.profile.is_empty()).then(|| i.profile.clone());
                s.interface_type = (!i.kind.is_empty()).then(|| i.kind.clone());
            }
        }
        Ok(s)
    }
    fn evaluate(&mut self) -> Task<Message> {
        if self.analysis_busy {
            self.status = "Analysis is still running; evaluate again when it finishes.".into();
            return Task::none();
        }
        let scenario = match self.scenario() {
            Ok(s) => s,
            Err(e) => {
                self.status = e;
                return Task::none();
            }
        };
        let (Some(c), Some(data)) = (self.selected.clone(), self.diagnostic_data.clone()) else {
            return Task::none();
        };
        if !self.expected_port.is_empty() && self.expected_port.parse::<u16>().is_err() {
            self.status = "Expected port must be 0–65535 or empty".into();
            return Task::none();
        }
        self.analysis_request += 1;
        let id = self.analysis_request;
        let key = c.key.clone();
        self.analysis_busy = true;
        let service = self.expected_service.clone();
        let port = self.expected_port.parse().ok();
        self.status = "Evaluating evidence in background…".into();
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    Arc::new(diagnostics::analyze(&c, &scenario, &data, &service, port))
                })
                .await
                .map_err(|e| e.to_string())
            },
            move |result| Message::AnalysisReady(id, key.clone(), result),
        )
    }
    pub(super) fn update_workbench(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::SelectConnection(key) => {
                self.autocomplete_suggestions.clear();
                self.autocomplete_selected_index = None;
                if self.selected.as_ref().map(|c| &c.key) == key.as_ref() {
                    return Task::none();
                }
                if let Some(cancel) = &self.diagnostic_cancel {
                    cancel.store(true, Ordering::Relaxed);
                }
                self.selected =
                    key.and_then(|k| self.history.current.iter().find(|c| c.key == k).cloned());
                self.diagnostic_data = None;
                self.analysis = Analysis::default();
                self.analysis_request += 1;
                self.selected_rule = None;
                self.rule_page = 0;
                if let Some(c) = &self.selected {
                    self.local_input = c.key.local.to_string();
                    self.peer_input = if c.is_listener() {
                        String::new()
                    } else {
                        c.key.remote.map(|a| a.to_string()).unwrap_or_default()
                    };
                }
                self.status="Endpoint selected. Open Diagnostics to inspect its process, firewall policy, network context and recorded events.".into();
            }
            Message::ToggleWorkbench => {
                if self.show_workbench {
                    return self.update_workbench(Message::CloseDetails);
                }
                self.show_workbench = true;
                self.show_settings = false;
                self.autocomplete_suggestions.clear();
                self.autocomplete_selected_index = None;
            }
            Message::DiagnosticTabChanged(tab) => {
                self.diagnostic_tab = tab;
                return widget::operation::scrollable::snap_to(
                    self.diagnostic_scroll_id.clone(),
                    widget::scrollable::RelativeOffset::START,
                    widget::operation::Animation::Instant,
                );
            }
            Message::RuleSearchChanged(value) => {
                self.rule_search = value;
                self.rule_page = 0;
                self.selected_rule = None;
            }
            Message::RulePageChanged(page) => {
                self.rule_page = page;
                self.selected_rule = None;
            }
            Message::RuleScopeChanged(only) => {
                self.rule_candidates_only = only;
                self.rule_page = 0;
                self.selected_rule = None;
            }
            Message::RuleSelected(id) => self.selected_rule = Some(id),
            Message::CloseDetails => {
                self.show_workbench = false;
                if let Some(c) = &self.diagnostic_cancel {
                    c.store(true, Ordering::Relaxed);
                }
            }
            Message::Diagnose(force) => {
                let Some(c) = self.selected.clone() else {
                    return Task::none();
                };
                if self.diagnostic_gate.busy() {
                    return Task::none();
                }
                let id = self.diagnostic_gate.request().unwrap();
                let key = c.key.clone();
                let worker = self.diagnostic_collector.clone();
                let cancel = Arc::new(AtomicBool::new(false));
                self.diagnostic_cancel = Some(cancel.clone());
                let expected = self.expected_service.clone();
                self.status="Reading process/services, policy, network and existing events (90-second PowerShell deadline; native queries may finish later)…".into();
                return Task::perform(
                    async move {
                        tokio::task::spawn_blocking(move || {
                            worker
                                .lock()
                                .map_err(|_| "Diagnostic worker unavailable".to_string())?
                                .collect(&c, &expected, force, &cancel)
                                .map(Arc::new)
                        })
                        .await
                        .unwrap_or_else(|e| Err(e.to_string()))
                    },
                    move |result| Message::DiagnosisReady(id, key.clone(), result),
                );
            }
            Message::CancelDiagnosis => {
                if let Some(c) = &self.diagnostic_cancel {
                    c.store(true, Ordering::Relaxed);
                }
                self.status = "Cancellation requested; stopping the owned collector.".into();
            }
            Message::DiagnosisReady(id, key, result) => {
                if self.diagnostic_gate.finish(id).is_none() {
                    return Task::none();
                }
                let cancelled = self
                    .diagnostic_cancel
                    .take()
                    .is_some_and(|c| c.load(Ordering::Relaxed));
                if cancelled || self.selected.as_ref().map(|c| &c.key) != Some(&key) {
                    self.status = "Result discarded after cancellation or selection change.".into();
                    return Task::none();
                }
                match result {
                    Ok(data) => {
                        self.diagnostic_data = Some(data);
                        return self.evaluate();
                    }
                    Err(e) => self.status = e,
                }
            }
            Message::EvaluateCached => return self.evaluate(),
            Message::AnalysisReady(id, key, result) => {
                self.analysis_busy = false;
                if id == self.analysis_request
                    && self.selected.as_ref().map(|c| &c.key) == Some(&key)
                {
                    match result {
                        Ok(a) => {
                            self.analysis = Arc::unwrap_or_clone(a);
                            self.status="Analysis complete. Scenario/service inputs are assumptions; configuration does not confirm traffic failure.".into();
                        }
                        Err(e) => self.status = e,
                    }
                }
            }
            Message::ScenarioChanged(field, value) => {
                match field.as_str() {
                    "local" => self.local_input = value,
                    "peer" => self.peer_input = value,
                    "interface" => self.interface_input = value,
                    "service" => self.expected_service = value,
                    "port" => self.expected_port = value,
                    "file" => {
                        self.file_path = value;
                        return Task::none();
                    }
                    "direction" => {
                        self.direction = if value == "Outbound" {
                            TrafficDirection::Outbound
                        } else {
                            TrafficDirection::Inbound
                        }
                    }
                    _ => {}
                }
                self.analysis = Analysis::default();
                self.analysis_request += 1;
                self.status = "Inputs changed. Evaluate cached evidence or run Diagnose.".into();
            }
            Message::ToggleSection(section) => {
                if !self.sections.remove(&section) {
                    self.sections.insert(section);
                }
            }
            Message::CaptureSnapshot => {
                self.snapshot = Some(self.current_snapshot());
                self.status = format!(
                    "Baseline captured: {} endpoints (includes addresses/process paths).",
                    self.history.current.len()
                );
            }
            Message::CompareSnapshot => {
                if let Some(snapshot) = &self.snapshot {
                    let d = storage::diff(snapshot, &self.current_snapshot());
                    self.status = format!(
                        "{} added, {} removed, {} sampled state changes. Policy changed: {:?}; network changed: {:?}. {}",
                        d.added,
                        d.removed,
                        d.changed,
                        d.policy_changed,
                        d.network_changed,
                        if d.comparable {
                            "Same app session; tuple continuity remains inferred."
                        } else {
                            "Different session/partial samples: not confirmed connection changes."
                        }
                    );
                } else {
                    self.status = "Capture or load a baseline first.".into();
                }
            }
            Message::SaveSnapshot => {
                let snapshot = self
                    .snapshot
                    .clone()
                    .unwrap_or_else(|| self.current_snapshot());
                let path = PathBuf::from(&self.file_path);
                return Self::io_task(move || {
                    let text =
                        serde_json::to_string_pretty(&snapshot).map_err(|e| e.to_string())?;
                    if let Some(parent) = path.parent() {
                        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                    }
                    storage::write_new(&path, &text)?;
                    Ok(format!(
                        "Full snapshot saved to {} (contains addresses/process paths).",
                        path.display()
                    ))
                });
            }
            Message::LoadSnapshot => {
                let path = PathBuf::from(&self.file_path);
                return Task::perform(
                    async move {
                        tokio::task::spawn_blocking(move || {
                            let s: Snapshot = storage::read_json(&path)?;
                            s.validate()?;
                            Ok(Arc::new(s))
                        })
                        .await
                        .unwrap_or_else(|e| Err(e.to_string()))
                    },
                    Message::SnapshotLoaded,
                );
            }
            Message::SnapshotLoaded(result) => {
                match result {
                    Ok(s) => {
                        self.snapshot = Some(Arc::unwrap_or_clone(s));
                        self.status="Baseline loaded for comparison only; imports never control collectors.".into();
                    }
                    Err(e) => self.status = e,
                }
            }
            Message::ExportReport => {
                let Some(data) = &self.diagnostic_data else {
                    self.status = "Run Diagnose before exporting.".into();
                    return Task::none();
                };
                let text = storage::report(&self.analysis, data);
                let path = PathBuf::from(&self.file_path);
                return Self::io_task(move || {
                    if let Some(parent) = path.parent() {
                        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                    }
                    storage::write_new(&path, &text)?;
                    Ok(format!("Redacted report saved to {}", path.display()))
                });
            }
            Message::IoFinished(result) => self.status = result.unwrap_or_else(|e| e),
            Message::ViewNameChanged(value) => self.view_name = value,
            Message::SaveView => {
                if !self.preferences_ready {
                    return Task::none();
                }
                let view = SavedView {
                    name: self.view_name.trim().into(),
                    filter: self.filter_text_staged.clone(),
                    sort_column: self.sort.map(|s| s.column),
                    descending: self
                        .sort
                        .is_some_and(|s| s.direction == Direction::Descending),
                    expected_service: self.expected_service.clone(),
                    expected_port: self.expected_port.clone(),
                    peer: self.peer_input.clone(),
                    local: self.local_input.clone(),
                    direction: self.direction.to_string(),
                    interface: self.interface_input.clone(),
                };
                match self.preferences.save_view(view) {
                    Ok(()) => {
                        let p = self.preferences.clone();
                        return Self::io_task(move || {
                            storage::save_preferences(&storage::preferences_path(), &p)?;
                            Ok("View saved locally; saved scenarios can contain endpoint/customer context.".into())
                        });
                    }
                    Err(e) => self.status = e,
                }
            }
            Message::LoadView(name) => {
                if let Some(v) = self
                    .preferences
                    .views
                    .iter()
                    .find(|v| v.name == name)
                    .cloned()
                {
                    self.loaded_view = Some(name);
                    self.filter_text_staged = v.filter;
                    self.apply_filter();
                    self.sort = v.sort_column.map(|column| Sort {
                        column,
                        direction: if v.descending {
                            Direction::Descending
                        } else {
                            Direction::Ascending
                        },
                    });
                    self.expected_service = v.expected_service;
                    self.expected_port = v.expected_port;
                    self.peer_input = v.peer;
                    self.local_input = v.local;
                    self.interface_input = v.interface;
                    self.direction = if v.direction == "Outbound" {
                        TrafficDirection::Outbound
                    } else {
                        TrafficDirection::Inbound
                    };
                    self.analysis = Analysis::default();
                    self.analysis_request += 1;
                }
            }
            Message::PreferencesLoaded(result) => {
                self.preferences_ready = true;
                match result {
                    Ok(p) => self.preferences = p,
                    Err(e) => self.status = format!("Saved views not loaded: {e}"),
                }
            }
            Message::DnsChanged(value) => self.dns_name = value,
            Message::ResolveDns => {
                if self.dns_busy {
                    return Task::none();
                }
                let name = self.dns_name.clone();
                let cancel = Arc::new(AtomicBool::new(false));
                self.dns_cancel = Some(cancel.clone());
                self.dns_busy = true;
                self.dns_result = "Resolving (network lookup, 10-second deadline)…".into();
                return Task::perform(
                    async move {
                        tokio::task::spawn_blocking(move || {
                            easy_netstat::collectors::resolve_dns(&name, &cancel)
                        })
                        .await
                        .unwrap_or_else(|e| Err(e.to_string()))
                    },
                    Message::DnsReady,
                );
            }
            Message::DnsReady(result) => {
                self.dns_busy = false;
                self.dns_cancel = None;
                self.dns_result=result.map(|v|format!("Answers: {}. These do not establish the application's DNS cache or endpoint ownership.",v.join(", "))).unwrap_or_else(|e|e);
            }
            _ => {}
        }
        Task::none()
    }
    fn io_task(work: impl FnOnce() -> Result<String, String> + Send + 'static) -> Task<Message> {
        Task::perform(
            async move {
                tokio::task::spawn_blocking(work)
                    .await
                    .unwrap_or_else(|e| Err(e.to_string()))
            },
            Message::IoFinished,
        )
    }
    fn current_snapshot(&self) -> Snapshot {
        Snapshot {
            schema: 1,
            session: self.session_id.clone(),
            captured_ms: now_ms(),
            connections: self.history.current.clone(),
            errors: self.history.errors.clone(),
            policy: self.diagnostic_data.as_ref().map(|d| d.policy.clone()),
            interfaces: self
                .diagnostic_data
                .as_ref()
                .map(|d| d.interfaces.clone())
                .unwrap_or_default(),
            routes: self
                .diagnostic_data
                .as_ref()
                .map(|d| d.routes.clone())
                .unwrap_or_default(),
        }
    }
    pub(super) fn toolbar(&self) -> Element<'_, Message> {
        row![
            button("Diagnostics").on_press(Message::ToggleWorkbench),
            text(
                self.selected
                    .as_ref()
                    .map(|c| format!(
                        "Selected: {} · PID {} · {}",
                        c.process.name, c.key.process.pid, c.key.local
                    ))
                    .unwrap_or_else(|| "Select a connection to inspect it".into())
            )
            .size(13),
            space::horizontal()
        ]
        .spacing(12)
        .align_y(Alignment::Center)
        .boxed()
    }
    fn section_button(&self, name: &str) -> Element<'_, Message> {
        button(text(format!(
            "{} {}",
            if self.sections.contains(name) {
                "▾"
            } else {
                "▸"
            },
            name
        )))
        .style(button::text)
        .on_press(Message::ToggleSection(name.into()))
        .boxed()
    }
    pub(super) fn workbench_modal(&self) -> Element<'_, Message> {
        let content: Element<'_, Message> =
            if self.show_workbench {
                let mut tabs = iced::widget::row![].spacing(4);
                for tab in DiagnosticTab::ALL {
                    tabs = tabs.push(
                        button(tab.label())
                            .padding([7, 10])
                            .style(if self.diagnostic_tab == tab {
                                button::primary
                            } else {
                                button::text
                            })
                            .on_press(Message::DiagnosticTabChanged(tab))
                            .boxed(),
                    );
                }
                let body = match self.diagnostic_tab {
                    DiagnosticTab::Overview => self.overview_tab(),
                    DiagnosticTab::Firewall => self.firewall_tab(),
                    DiagnosticTab::Process => self.process_tab(),
                    DiagnosticTab::Network => self.network_tab(),
                    DiagnosticTab::Events => self.events_tab(),
                    DiagnosticTab::History => self.history_tab(),
                    DiagnosticTab::Tools => self.tools_tab(),
                };
                iced::widget::column![
                row![
                    text(
                        self.selected
                            .as_ref()
                            .map(|c| format!(
                                "{} · PID {} · {} {}",
                                c.process.name, c.key.process.pid, c.key.protocol, c.key.local
                            ))
                            .unwrap_or_else(|| "Diagnostic tools".into())
                    )
                    .size(16),
                    space::horizontal(),
                    button(if self.diagnostic_gate.busy() {
                        "Collecting…"
                    } else {
                        "Collect diagnostics"
                    })
                    .on_press_maybe(
                        (self.selected.is_some() && !self.diagnostic_gate.busy())
                            .then_some(Message::Diagnose(false))
                    ),
                    button("Cancel").style(button::text).on_press_maybe(
                        self.diagnostic_gate
                            .busy()
                            .then_some(Message::CancelDiagnosis)
                    )
                ]
                .spacing(8)
                .align_y(Alignment::Center),
                tabs,
                text(&self.status).size(12),
                scrollable(body).id(self.diagnostic_scroll_id.clone()).height(Length::Fill),
                text(
                    "Read-only · collection uses existing Windows configuration and recorded events"
                )
                .size(12)
            ]
                .spacing(12)
                .width(960)
                .height(590)
                .boxed()
            } else {
                space::horizontal().boxed()
            };
        modal(content, "Diagnostics")
            .open(self.show_workbench)
            .min_width(760.0)
            .max_width(1040.0)
            .min_height(400.0)
            .on_dismiss(Message::CloseDetails)
            .boxed()
    }
    fn no_collection(&self) -> Element<'_, Message> {
        let message = if self.selected.is_none() {
            "Select a connection in the table, then open Diagnostics. Saved views, snapshots, reports and DNS lookup are in Tools / reports."
        } else {
            "Click Collect diagnostics to load effective firewall rules, process/services, network configuration and existing Windows events. No settings are changed."
        };
        container(text(message).size(15))
            .padding(16)
            .style(container::bordered_box)
            .width(Length::Fill)
            .boxed()
    }
    fn overview_tab(&self) -> Element<'_, Message> {
        let mut content =
            iced::widget::column![text("Connection and examined traffic").size(18)].spacing(12);
        if let Some(c) = &self.selected {
            content = content.push(
                text(format!(
                    "{} · {} → {} · {}",
                    c.key.protocol,
                    c.key.local,
                    c.key
                        .remote
                        .map(|a| a.to_string())
                        .unwrap_or_else(|| "peer unspecified".into()),
                    c.state
                ))
                .boxed(),
            );
            content=content.push(text(format!("Observed {} seconds ago. Direction and values entered below are scenario assumptions.",now_ms().saturating_sub(c.observed_ms)/1000)).size(12).boxed());
            content = content.push(
                row![
                    input(
                        "Local endpoint",
                        "Actual local IP:port",
                        &self.local_input,
                        "local"
                    ),
                    input(
                        "Remote endpoint",
                        "Peer IP:port (optional)",
                        &self.peer_input,
                        "peer"
                    )
                ]
                .spacing(16)
                .boxed(),
            );
            content = content.push(
                row![
                    input(
                        "Interface",
                        "Interface alias (optional)",
                        &self.interface_input,
                        "interface"
                    ),
                    input(
                        "Expected service",
                        "Assumed socket service (optional)",
                        &self.expected_service,
                        "service"
                    ),
                    input(
                        "Expected port",
                        "Local port (optional)",
                        &self.expected_port,
                        "port"
                    )
                ]
                .spacing(16)
                .boxed(),
            );
            content = content.push(
                row![
                    text("Direction"),
                    button("Inbound")
                        .style(if self.direction == TrafficDirection::Inbound {
                            button::primary
                        } else {
                            button::secondary
                        })
                        .on_press(Message::ScenarioChanged(
                            "direction".into(),
                            "Inbound".into()
                        )),
                    button("Outbound")
                        .style(if self.direction == TrafficDirection::Outbound {
                            button::primary
                        } else {
                            button::secondary
                        })
                        .on_press(Message::ScenarioChanged(
                            "direction".into(),
                            "Outbound".into()
                        )),
                    space::horizontal(),
                    button("Evaluate collected evidence").on_press_maybe(
                        (self.diagnostic_data.is_some() && !self.analysis_busy)
                            .then_some(Message::EvaluateCached)
                    )
                ]
                .spacing(8)
                .align_y(Alignment::Center)
                .boxed(),
            );
        }
        if let Some(data) = &self.diagnostic_data {
            content = content.push(
                row![
                    button(text(format!(
                        "Firewall rules: {} collected",
                        data.policy.rules.len()
                    )))
                    .on_press(Message::DiagnosticTabChanged(DiagnosticTab::Firewall)),
                    button(text(format!("Services: {}", data.services.len())))
                        .on_press(Message::DiagnosticTabChanged(DiagnosticTab::Process)),
                    button(text(format!("Interfaces: {}", data.interfaces.len())))
                        .on_press(Message::DiagnosticTabChanged(DiagnosticTab::Network)),
                    button(text(format!("Events: {}", data.events.len())))
                        .on_press(Message::DiagnosticTabChanged(DiagnosticTab::Events))
                ]
                .spacing(8)
                .boxed(),
            );
            content=content.push(text(format!("Evidence collected {} seconds ago. Explore the tabs even when no rule can be fully evaluated.",now_ms().saturating_sub(data.finished_ms)/1000)).size(12).boxed());
            for cap in data
                .capabilities
                .iter()
                .filter(|c| c.status != "Available")
                .take(6)
            {
                content = content.push(
                    text(format!("{}: {} — {}", cap.source, cap.status, cap.detail))
                        .size(12)
                        .boxed(),
                );
            }
        } else {
            content = content.push(self.no_collection());
        }
        content = content.push(text("Findings and next checks").size(18).boxed());
        if self.analysis.findings.is_empty() {
            content=content.push(text(if self.analysis_busy{"Evaluating evidence…"}else{"Collect diagnostics, then evaluate a concrete traffic scenario to generate findings."}).boxed());
        }
        for f in &self.analysis.findings {
            let mut card = iced::widget::column![
                text(format!("{} · {}", f.certainty, f.title)).font(Font {
                    weight: font::Weight::Bold,
                    ..Font::DEFAULT
                }),
                text(&f.explanation).size(13),
                text(format!("Next check: {}", f.follow_up)).size(13)
            ]
            .spacing(6);
            if self.sections.contains("Evidence references") {
                card = card.push(
                    text(format!(
                        "Evidence: {}\nAssumptions: {}\nEvaluator {} · {} ms UTC",
                        f.evidence.join(", "),
                        f.assumptions.join("; "),
                        self.analysis.evaluator_version,
                        f.time_ms
                    ))
                    .size(12)
                    .boxed(),
                );
            }
            content = content.push(
                container(card)
                    .padding(12)
                    .width(Length::Fill)
                    .style(container::bordered_box)
                    .boxed(),
            );
        }
        content
            .push(self.section_button("Evidence references"))
            .boxed()
    }
    fn visible_rules(&self) -> Vec<&FirewallRule> {
        let Some(data) = &self.diagnostic_data else {
            return Vec::new();
        };
        let query = self.rule_search.to_lowercase();
        let candidates: std::collections::HashSet<_> = self
            .analysis
            .rules
            .iter()
            .map(|e| e.rule_id.as_str())
            .collect();
        data.policy
            .rules
            .iter()
            .filter(|r| !self.rule_candidates_only || candidates.contains(r.id.as_str()))
            .filter(|r| rule_matches_query(r, &query))
            .collect()
    }
    fn firewall_tab(&self) -> Element<'_, Message> {
        let Some(data) = &self.diagnostic_data else {
            return self.no_collection();
        };
        let mut content = iced::widget::column![
            row![
                text("Effective firewall policy").size(18),
                space::horizontal(),
                button("Refresh policy").on_press_maybe(
                    (self.selected.is_some() && !self.diagnostic_gate.busy())
                        .then_some(Message::Diagnose(true))
                )
            ]
            .align_y(Alignment::Center),
            text(format!(
                "{} collected rules · {} analyzed candidates · {} · snapshot {}",
                data.policy.rules.len(),
                self.analysis.rules.len(),
                if data.policy.complete {
                    "collected supported data"
                } else {
                    "partial / unavailable data"
                },
                data.policy.version
            ))
            .size(13)
        ]
        .spacing(12);
        for cap in data
            .capabilities
            .iter()
            .filter(|c| c.source == "Firewall" || c.source.starts_with("Get-NetFirewall"))
        {
            if cap.status != "Available" {
                content = content.push(
                    text(format!("{}: {} — {}", cap.source, cap.status, cap.detail))
                        .size(12)
                        .boxed(),
                );
            }
        }
        if data.policy.profiles.is_empty() {
            content = content.push(
                text("Firewall profile settings were not collected or could not be read.").boxed(),
            );
        }
        for p in &data.policy.profiles {
            content=content.push(container(iced::widget::column![text(format!("{} profile · enabled {}",p.name,p.enabled)).font(Font{weight:font::Weight::Bold,..Font::DEFAULT}),text(format!("Default inbound: {}    Default outbound: {}\nInbound rules: {}    Local rule merging: {}",p.inbound,p.outbound,p.allow_inbound_rules,p.allow_local_rules)).size(13)].spacing(5)).padding(10).width(Length::Fill).style(container::bordered_box).boxed());
        }
        content = content.push(
            row![
                text_input(
                    "Search name, program, service, port, scope or policy source",
                    &self.rule_search
                )
                .on_input(Message::RuleSearchChanged),
                button("All collected")
                    .style(if !self.rule_candidates_only {
                        button::primary
                    } else {
                        button::secondary
                    })
                    .on_press(Message::RuleScopeChanged(false)),
                button("Examined candidates")
                    .style(if self.rule_candidates_only {
                        button::primary
                    } else {
                        button::secondary
                    })
                    .on_press(Message::RuleScopeChanged(true))
            ]
            .spacing(8)
            .boxed(),
        );
        let rules = self.visible_rules();
        let pages = rules.len().div_ceil(RULES_PER_PAGE).max(1);
        let page = self.rule_page.min(pages - 1);
        content = content.push(
            row![
                text(format!(
                    "{} rules in this view · page {} / {}",
                    rules.len(),
                    page + 1,
                    pages
                )),
                space::horizontal(),
                button("Previous")
                    .on_press_maybe((page > 0).then(|| Message::RulePageChanged(page - 1))),
                button("Next")
                    .on_press_maybe((page + 1 < pages).then(|| Message::RulePageChanged(page + 1)))
            ]
            .spacing(8)
            .align_y(Alignment::Center)
            .boxed(),
        );
        if rules.is_empty() {
            return content.push(text(if data.policy.rules.is_empty(){"No rules are available in this collection. See the source status above; this is not proof that no firewall rules exist."}else if self.rule_candidates_only&&self.analysis.rules.is_empty(){"No analyzed candidates yet. Evaluate the traffic scenario in Overview, or choose All collected to browse the raw policy."}else{"No rules match this search/scope. Try All collected or clear the search."}).boxed()).boxed();
        }
        let selected = self
            .selected_rule
            .as_ref()
            .and_then(|id| rules.iter().find(|r| r.id == *id).copied())
            .unwrap_or(rules[page * RULES_PER_PAGE]);
        let mut list = iced::widget::column![].spacing(6);
        for rule in rules
            .iter()
            .skip(page * RULES_PER_PAGE)
            .take(RULES_PER_PAGE)
        {
            list = list.push(
                button(
                    text(format!(
                        "{}\n{} · {} · {}",
                        rule.name,
                        rule.action,
                        rule.direction,
                        if rule.enabled { "enabled" } else { "disabled" }
                    ))
                    .size(13),
                )
                .style(if rule.id == selected.id {
                    button::primary
                } else {
                    button::secondary
                })
                .padding(10)
                .width(Length::Fill)
                .on_press(Message::RuleSelected(rule.id.clone()))
                .boxed(),
            );
        }
        content = content.push(
            row![
                container(list).width(280),
                container(self.rule_details(selected))
                    .padding(12)
                    .width(Length::Fill)
                    .style(container::bordered_box)
            ]
            .spacing(12)
            .boxed(),
        );
        content.push(text("Collected policy is configuration evidence. A matching allow or block candidate is not an observed traffic verdict; unsupported or unreadable predicates remain unknown.").size(12).boxed()).boxed()
    }
    fn rule_details<'a>(&'a self, r: &'a FirewallRule) -> Element<'a, Message> {
        let mut details = iced::widget::column![
            text(&r.name).size(18),
            text(format!(
                "{} · {} · {}",
                r.action,
                r.direction,
                if r.enabled { "Enabled" } else { "Disabled" }
            ))
            .size(14),
            text(format!("Rule ID: {}", r.id)).size(12)
        ]
        .spacing(8);
        for (name, value) in [
            ("Program", values(&r.program)),
            ("Service restriction", values(&r.service)),
            ("Protocol", values(&r.protocol)),
            ("Local ports", values(&r.local_ports)),
            ("Remote ports", values(&r.remote_ports)),
            ("Local addresses", values(&r.local_addresses)),
            ("Remote addresses", values(&r.remote_addresses)),
            ("Profiles", values(&r.profiles)),
            ("Interfaces", values(&r.interfaces)),
            ("Interface types", values(&r.interface_types)),
            ("Policy source", format!("{} / {}", r.source, r.source_type)),
            ("Enforcement", r.enforcement.clone()),
        ] {
            details = details.push(
                iced::widget::column![
                    text(name)
                        .font(Font {
                            weight: font::Weight::Bold,
                            ..Font::DEFAULT
                        })
                        .size(12),
                    text(if value.is_empty() {
                        "Unavailable".into()
                    } else {
                        value
                    })
                    .size(13)
                ]
                .spacing(3)
                .boxed(),
            );
        }
        if !r.unsupported.is_empty() {
            details = details.push(
                text(format!(
                    "Unsupported conditions: {}",
                    r.unsupported.join("; ")
                ))
                .size(12)
                .boxed(),
            );
        }
        if !r.complete {
            details=details.push(text("Some associated filters could not be read. Missing values are unknown, not Any.").size(12).boxed());
        }
        if let Some(evaluation) = self
            .scenario()
            .ok()
            .map(|s| easy_netstat::firewall::evaluate(r, &s))
        {
            details = details.push(
                text(format!("Examined scenario: {}", evaluation.result))
                    .size(16)
                    .boxed(),
            );
            for c in evaluation.conditions {
                details = details.push(
                    text(format!("{}: {} — {}", c.name, c.result, c.detail))
                        .size(12)
                        .boxed(),
                );
            }
        }
        details.boxed()
    }
    fn process_tab(&self) -> Element<'_, Message> {
        let mut content =
            iced::widget::column![text("Owning process and associated services").size(18)]
                .spacing(12);
        if let Some(c) = &self.selected {
            content = content.push(
                text(format!(
                    "{} · PID {}\nExecutable: {}\nCreation identity: {:?}\n{}",
                    c.process.name,
                    c.key.process.pid,
                    c.process.path.as_deref().unwrap_or("Unavailable"),
                    c.key.process.created,
                    c.process.unavailable.join("; ")
                ))
                .boxed(),
            );
        }
        let Some(data) = &self.diagnostic_data else {
            return content.push(self.no_collection()).boxed();
        };
        if let Some(p) = &data.process {
            content = content
                .push(
                    text(format!(
                        "Process owner: {}",
                        p.owner.as_deref().unwrap_or("Unavailable")
                    ))
                    .boxed(),
                )
                .push(self.section_button("Command line (sensitive)"));
            if self.sections.contains("Command line (sensitive)") {
                content = content.push(
                    text(p.command_line.as_deref().unwrap_or("Unavailable"))
                        .size(13)
                        .boxed(),
                );
            }
        }
        if data.services.is_empty() {
            content=content.push(text("No visible associated/expected services were returned. Check collection access below.").boxed());
        }
        for s in &data.services {
            content=content.push(container(iced::widget::column![text(format!("{} ({})",s.display_name,s.name)).size(16),text(format!("State: {} · start type: {} · PID {}\nConfigured account: {}\nConfigured binary: {}",s.state,s.start_mode,s.pid,s.account,s.binary)).size(13)].spacing(6)).padding(12).style(container::bordered_box).width(Length::Fill).boxed());
        }
        content=content.push(text("A shared PID can host several services. Membership does not establish which service owns a socket; executable and service firewall restrictions are separate conditions.").size(12).boxed());
        for cap in data
            .capabilities
            .iter()
            .filter(|c| c.source.starts_with("Process") || c.source == "Services")
        {
            content = content.push(
                text(format!("{}: {} — {}", cap.source, cap.status, cap.detail))
                    .size(12)
                    .boxed(),
            );
        }
        content.boxed()
    }
    fn network_tab(&self) -> Element<'_, Message> {
        let Some(data) = &self.diagnostic_data else {
            return self.no_collection();
        };
        let mut content =
            iced::widget::column![text("Interfaces, profiles and DNS configuration").size(18)]
                .spacing(12);
        for cap in data
            .capabilities
            .iter()
            .filter(|c| c.source == "Network" || c.source == "Routes")
        {
            content = content.push(
                text(format!("{}: {} — {}", cap.source, cap.status, cap.detail))
                    .size(12)
                    .boxed(),
            );
        }
        for i in &data.interfaces {
            content=content.push(container(iced::widget::column![text(format!("{} · #{} · {} · {} profile",i.alias,i.index,i.status,i.profile)).size(16),text(format!("Type: {}\nAddresses: {}\nDNS servers: {}\nGateways: {}\nAbsolute error counter: {:?}",i.kind,values(&i.addresses),values(&i.dns),values(&i.gateways),i.errors)).size(13)].spacing(6)).padding(12).width(Length::Fill).style(container::bordered_box).boxed());
        }
        content = content.push(
            text(format!(
                "Routing information · {} collected routes",
                data.routes.len()
            ))
            .size(18)
            .boxed(),
        );
        for r in data.routes.iter().take(80) {
            content = content.push(
                text(format!(
                    "{} via {} · interface {} · metric {}",
                    r.destination, r.next_hop, r.interface, r.metric
                ))
                .size(13)
                .boxed(),
            );
        }
        if data.routes.len() > 80 {
            content = content.push(text("First 80 routes displayed.").size(12).boxed());
        }
        content.push(text("Current routes and counters are context, not proof of a historical packet path. Explicit hostname resolution is in Tools / reports.").size(12).boxed()).boxed()
    }
    fn events_tab(&self) -> Element<'_, Message> {
        let Some(data) = &self.diagnostic_data else {
            return self.no_collection();
        };
        let mut content=iced::widget::column![text("Recorded traffic and system evidence").size(18),text("No recorded event is different from denied access or disabled auditing. No new auditing is enabled by this tool.").size(13)].spacing(12);
        for cap in data
            .capabilities
            .iter()
            .filter(|c| c.source.contains("events") || c.source == "Audit policy")
        {
            content = content.push(
                text(format!("{}: {} — {}", cap.source, cap.status, cap.detail))
                    .size(12)
                    .boxed(),
            );
        }
        let mut count = 0;
        for event in data
            .events
            .iter()
            .filter_map(|r| easy_netstat::evidence::network_event(r).ok())
            .filter(|e| {
                self.selected
                    .as_ref()
                    .is_some_and(|c| e.pid == Some(c.key.process.pid))
            })
            .take(50)
        {
            count += 1;
            content=content.push(container(text(format!("Event {} · {} ms UTC · PID {:?}\n{} → {} · {:?} · {:?}\nFilter {:?} · {}\nPID-only event context; confirmed attribution requires the full tuple and process lifetime.",event.event_id,event.time_ms,event.pid,event.source.map(|a|a.to_string()).unwrap_or_else(||"Unknown".into()),event.destination.map(|a|a.to_string()).unwrap_or_else(||"Unknown".into()),event.direction,event.protocol,event.filter_id,event.layer)).size(13)).padding(12).width(Length::Fill).style(container::bordered_box).boxed());
        }
        if count == 0 {
            content=content.push(text("No recorded WFP events for this PID in the collected window. This does not prove traffic was allowed.").boxed());
        }
        for f in self
            .analysis
            .findings
            .iter()
            .filter(|f| f.id.starts_with("wfp.") || f.id == "system.context")
        {
            content = content.push(
                text(format!(
                    "{} · {}\n{}\nEvidence: {}",
                    f.certainty,
                    f.title,
                    f.explanation,
                    f.evidence.join(", ")
                ))
                .size(13)
                .boxed(),
            );
        }
        content = content.push(text("Current WFP filter metadata").size(18).boxed());
        for f in &data.filters {
            content = content.push(
                text(format!(
                    "Filter {} · {}\n{}\nProvider {} · layer {}",
                    f.runtime_id, f.name, f.status, f.provider, f.layer
                ))
                .size(13)
                .boxed(),
            );
        }
        if data.filters.is_empty() {
            content=content.push(text("No current filter metadata was available. Runtime IDs may expire after policy/engine changes.").size(12).boxed());
        }
        content.boxed()
    }
    fn history_tab(&self) -> Element<'_, Message> {
        let mut content=iced::widget::column![text("Recent connection history").size(18),text("Sampled changes may miss short-lived connections; disappearance is not proof of graceful closure or a crash.").size(13)].spacing(12);
        if let Some(c) = &self.selected {
            for change in self
                .history
                .changes
                .iter()
                .rev()
                .filter(|v| v.key == c.key)
                .take(50)
            {
                content = content.push(
                    text(format!(
                        "{} ms UTC · {}\n{} → {}",
                        change.time_ms, change.kind, change.before, change.after
                    ))
                    .size(13)
                    .boxed(),
                );
            }
        }
        content.push(row![button("Capture baseline").on_press(Message::CaptureSnapshot),button("Compare current").on_press_maybe(self.snapshot.as_ref().map(|_|Message::CompareSnapshot))].spacing(8).boxed()).push(text(format!("{} retained changes · {} evicted. Save/load full baseline JSON in Tools / reports.",self.history.changes.len(),self.history.evicted)).size(12).boxed()).boxed()
    }
    fn tools_tab(&self) -> Element<'_, Message> {
        let names: Vec<String> = self
            .preferences
            .views
            .iter()
            .map(|v| v.name.clone())
            .collect();
        let mut content=iced::widget::column![text("Saved diagnostic views").size(18),row![text_input("Diagnostic view name",&self.view_name).on_input(Message::ViewNameChanged),button("Save view").on_press_maybe(self.preferences_ready.then_some(Message::SaveView)),pick_list(self.loaded_view.as_ref(),names,|s:&String|s.clone()).placeholder("Load saved view").on_select(Message::LoadView)].spacing(8),
            text("Baselines and reports").size(18),text_input("Full file path",&self.file_path).on_input(|v|Message::ScenarioChanged("file".into(),v)),
            row![button("Capture baseline").on_press(Message::CaptureSnapshot),button("Save full snapshot").on_press(Message::SaveSnapshot),button("Load baseline JSON").on_press(Message::LoadSnapshot),button("Compare current").on_press_maybe(self.snapshot.as_ref().map(|_|Message::CompareSnapshot))].spacing(8),
            text("Full snapshots contain addresses, paths and collected policy/network details. Existing files are preserved.").size(12),
            button("Export redacted report").on_press_maybe((self.diagnostic_data.is_some()&&!self.analysis.findings.is_empty()).then_some(Message::ExportReport)),
            self.section_button("Redacted report preview")].spacing(12);
        if self.sections.contains("Redacted report preview")
            && let Some(data) = &self.diagnostic_data
        {
            content = content.push(text(storage::report(&self.analysis, data)).size(12).boxed());
        }
        content = content
            .push(
                text("Optional DNS lookup (network activity)")
                    .size(18)
                    .boxed(),
            )
            .push(
                row![
                    text_input("Hostname", &self.dns_name).on_input(Message::DnsChanged),
                    button("Resolve hostname")
                        .on_press_maybe((!self.dns_busy).then_some(Message::ResolveDns))
                ]
                .spacing(8)
                .boxed(),
            )
            .push(text(&self.dns_result).size(13).boxed());
        content.boxed()
    }
}
fn input<'a>(
    label: &'static str,
    placeholder: &'static str,
    value: &'a str,
    key: &'static str,
) -> Element<'a, Message> {
    iced::widget::column![
        text(label).size(12),
        text_input(placeholder, value)
            .on_input(move |v| Message::ScenarioChanged(key.into(), v))
            .padding(7)
    ]
    .spacing(5)
    .width(Length::Fill)
    .boxed()
}
fn values(values: &[String]) -> String {
    if values.is_empty() {
        "Unavailable / not collected".into()
    } else {
        values.join(", ")
    }
}
fn rule_matches_query(rule: &FirewallRule, query: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    [
        &rule.id,
        &rule.name,
        &rule.source,
        &rule.source_type,
        &rule.action,
        &rule.direction,
    ]
    .into_iter()
    .chain(rule.program.iter())
    .chain(rule.service.iter())
    .chain(rule.protocol.iter())
    .chain(rule.local_ports.iter())
    .chain(rule.remote_ports.iter())
    .chain(rule.local_addresses.iter())
    .chain(rule.remote_addresses.iter())
    .chain(rule.profiles.iter())
    .chain(rule.interfaces.iter())
    .any(|v| v.to_lowercase().contains(query))
}

impl Drop for App {
    fn drop(&mut self) {
        if let Some(c) = &self.diagnostic_cancel {
            c.store(true, Ordering::Relaxed);
        }
        if let Some(c) = &self.dns_cancel {
            c.store(true, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> App {
        let mut app = App::new(NativeFrame::default()).0;
        let c = Connection {
            key: ConnectionKey {
                protocol: Protocol::Tcp,
                local: "0.0.0.0:5001".parse().unwrap(),
                remote: None,
                process: ProcessKey {
                    pid: 42,
                    created: Some(1),
                },
                ordinal: 0,
            },
            state: "Listen".into(),
            process: ProcessDetails {
                name: "IFC8.exe".into(),
                path: Some("C:\\Opera\\IFC8.exe".into()),
                unavailable: vec![],
            },
            observed_ms: now_ms(),
            partition: "TCP/IPv4".into(),
        };
        app.history.current.push(c.clone());
        app.selected = Some(c);
        app.local_input = "10.20.0.10:5001".into();
        let rules = (0..25)
            .map(|i| FirewallRule {
                id: format!("id-{i}"),
                name: format!("Rule {i}"),
                action: if i % 2 == 0 {
                    "Allow".into()
                } else {
                    "Block".into()
                },
                direction: "Inbound".into(),
                enabled: i != 1,
                program: vec!["C:\\Opera\\IFC8.exe".into()],
                service: vec!["OperaService".into()],
                local_ports: vec!["5001".into()],
                remote_addresses: vec!["10.20.0.0/24".into()],
                source: "Domain GPO".into(),
                ..FirewallRule::default()
            })
            .collect();
        app.diagnostic_data = Some(Arc::new(DiagnosticData {
            schema: 1,
            policy: easy_netstat::model::Policy {
                rules,
                collected_ms: 1,
                ..easy_netstat::model::Policy::default()
            },
            capabilities: vec![Capability {
                source: "Get-NetFirewallPortFilter".into(),
                status: "Unavailable".into(),
                detail: "Access denied".into(),
            }],
            ..DiagnosticData::default()
        }));
        app
    }
    #[test]
    fn popup_and_settings_are_exclusive_and_dismissible() {
        let mut app = fixture();
        app.show_settings = true;
        let _ = app.update(Message::ToggleWorkbench);
        assert!(app.show_workbench);
        assert!(!app.show_settings);
        let _ = app.update(Message::Settings);
        assert!(app.show_settings);
        assert!(!app.show_workbench);
        let _ = app.update(Message::ToggleWorkbench);
        let cancel = Arc::new(AtomicBool::new(false));
        app.diagnostic_cancel = Some(cancel.clone());
        let _ = app.update(Message::CloseDetails);
        assert!(!app.show_workbench);
        assert!(cancel.load(Ordering::Relaxed));
        assert!(app.selected.is_some());
    }
    #[test]
    fn selecting_a_row_does_not_force_open_a_popup() {
        let mut app = fixture();
        let key = app.selected.as_ref().unwrap().key.clone();
        app.selected = None;
        let _ = app.update(Message::SelectConnection(Some(key.clone())));
        assert!(app.selected.is_some());
        assert!(!app.show_workbench);
        let _ = app.update(Message::SelectConnection(Some(key)));
        assert!(!app.show_workbench);
    }
    #[test]
    fn collected_rules_are_visible_before_scenario_evaluation() {
        let mut app = fixture();
        assert!(app.analysis.rules.is_empty());
        assert_eq!(app.visible_rules().len(), 25);
        let _ = app.update(Message::RuleScopeChanged(true));
        assert!(app.visible_rules().is_empty());
        let _ = app.update(Message::RuleScopeChanged(false));
        assert_eq!(app.visible_rules().len(), 25);
        assert!(app.visible_rules().iter().any(|r| !r.enabled));
    }
    #[test]
    fn rule_search_covers_program_service_ports_scope_and_source() {
        let mut app = fixture();
        for query in [
            "IFC8.EXE",
            "operaservice",
            "5001",
            "10.20.0.0/24",
            "DOMAIN GPO",
        ] {
            let _ = app.update(Message::RuleSearchChanged(query.into()));
            assert_eq!(app.visible_rules().len(), 25, "{query}");
        }
        let _ = app.update(Message::RuleSearchChanged("rule 24".into()));
        assert_eq!(app.visible_rules().len(), 1);
        let _ = app.update(Message::RuleSearchChanged("missing".into()));
        assert!(app.visible_rules().is_empty());
    }
    #[test]
    fn pages_selection_and_all_tabs_build_for_partial_data() {
        let mut app = fixture();
        app.show_workbench = true;
        for tab in DiagnosticTab::ALL {
            let _ = app.update(Message::DiagnosticTabChanged(tab));
            let _ = app.workbench_modal();
            assert!(!app.diagnostic_gate.busy());
        }
        let _ = app.update(Message::RulePageChanged(usize::MAX));
        let _ = app.firewall_tab();
        let _ = app.update(Message::RuleSelected("not-collected".into()));
        let _ = app.firewall_tab();
        let _ = app.update(Message::RuleSearchChanged("IFC8".into()));
        assert_eq!(app.rule_page, 0);
        assert!(app.selected_rule.is_none());
        app.diagnostic_data = None;
        for tab in DiagnosticTab::ALL {
            app.diagnostic_tab = tab;
            let _ = app.workbench_modal();
        }
    }
    #[test]
    fn missing_rule_filters_are_not_presented_as_any() {
        assert_eq!(values(&[]), "Unavailable / not collected");
        assert_eq!(values(&["Any".into()]), "Any");
    }
}
