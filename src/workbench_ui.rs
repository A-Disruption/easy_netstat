use super::*;
use easy_netstat::model::Direction as TrafficDirection;
use iced::widget::scrollable;
use std::path::PathBuf;

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
                    self.show_workbench = true;
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
                self.show_workbench = true;
                if let Some(c) = &self.selected {
                    self.local_input = c.key.local.to_string();
                    self.peer_input = if c.is_listener() {
                        String::new()
                    } else {
                        c.key.remote.map(|a| a.to_string()).unwrap_or_default()
                    };
                }
                self.status="Endpoint selected. Direction and service inputs are assumptions until supported by evidence.".into();
            }
            Message::ToggleWorkbench => self.show_workbench = !self.show_workbench,
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
        let names: Vec<String> = self
            .preferences
            .views
            .iter()
            .map(|v| v.name.clone())
            .collect();
        row![
            button(if self.show_workbench {
                "Hide diagnostics/tools"
            } else {
                "Diagnostics/tools"
            })
            .on_press(Message::ToggleWorkbench),
            text_input("Diagnostic view name", &self.view_name)
                .on_input(Message::ViewNameChanged)
                .width(180),
            button("Save view").on_press_maybe(self.preferences_ready.then_some(Message::SaveView)),
            pick_list(self.loaded_view.as_ref(), names, |s: &String| s.clone())
                .placeholder("Saved views")
                .on_select(Message::LoadView),
            button("Capture baseline").on_press(Message::CaptureSnapshot),
            button("Compare")
                .on_press_maybe(self.snapshot.as_ref().map(|_| Message::CompareSnapshot))
        ]
        .spacing(6)
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
        .on_press(Message::ToggleSection(name.into()))
        .width(Length::Fill)
        .boxed()
    }
    pub(super) fn workbench_pane(&self) -> Element<'_, Message> {
        if !self.show_workbench {
            return space::horizontal().width(0).boxed();
        }
        let mut content = iced::widget::column![
            row![
                text("Connection diagnostics").size(20),
                space::horizontal(),
                button("Close").on_press(Message::CloseDetails)
            ],
            text(&self.status).size(13)
        ]
        .spacing(9);
        if let Some(c) = &self.selected {
            let live = c.key.process.created.is_some()
                && self
                    .history
                    .current
                    .iter()
                    .any(|v| v.key == c.key && v.observed_ms == c.observed_ms);
            content = content
                .push(
                    (text(format!(
                        "{} {} → {} | {}\nPID {} | {}\nObserved {} ms UTC | {}",
                        c.key.protocol,
                        c.key.local,
                        c.key
                            .remote
                            .map(|r| r.to_string())
                            .unwrap_or_else(|| "peer unspecified".into()),
                        c.state,
                        c.key.process.pid,
                        c.process.name,
                        c.observed_ms,
                        if live {
                            "sample retained; check freshness"
                        } else {
                            "historical/ambiguous"
                        }
                    )))
                    .boxed(),
                )
                .push(
                    (text(
                        c.process
                            .path
                            .as_deref()
                            .unwrap_or("Executable path unavailable"),
                    ))
                    .boxed(),
                )
                .push(
                    (text(format!(
                        "Creation identity: {:?}\n{}",
                        c.key.process.created,
                        c.process.unavailable.join("; ")
                    ))
                    .size(12))
                    .boxed(),
                );
            content = content.push(
                (row![
                    button("Diagnose").on_press_maybe(
                        (!self.diagnostic_gate.busy()).then_some(Message::Diagnose(false))
                    ),
                    button("Refresh policy").on_press_maybe(
                        (!self.diagnostic_gate.busy()).then_some(Message::Diagnose(true))
                    ),
                    button("Cancel").on_press_maybe(
                        self.diagnostic_gate
                            .busy()
                            .then_some(Message::CancelDiagnosis)
                    )
                ]
                .spacing(6))
                .boxed(),
            );
            content = content
                .push((text("Examined traffic (inputs are assumptions)").size(16)).boxed())
                .push(
                    (text_input("Concrete local IP:port", &self.local_input)
                        .on_input(|v| Message::ScenarioChanged("local".into(), v)))
                    .boxed(),
                )
                .push(
                    (text_input("Peer IP:port (optional)", &self.peer_input)
                        .on_input(|v| Message::ScenarioChanged("peer".into(), v)))
                    .boxed(),
                )
                .push(
                    (row![
                        button(if self.direction == TrafficDirection::Inbound {
                            "● Inbound"
                        } else {
                            "Inbound"
                        })
                        .on_press(Message::ScenarioChanged(
                            "direction".into(),
                            "Inbound".into()
                        )),
                        button(if self.direction == TrafficDirection::Outbound {
                            "● Outbound"
                        } else {
                            "Outbound"
                        })
                        .on_press(Message::ScenarioChanged(
                            "direction".into(),
                            "Outbound".into()
                        ))
                    ]
                    .spacing(6))
                    .boxed(),
                )
                .push(
                    (text_input(
                        "Interface alias (optional; no wildcard guess)",
                        &self.interface_input,
                    )
                    .on_input(|v| Message::ScenarioChanged("interface".into(), v)))
                    .boxed(),
                )
                .push(
                    (text_input(
                        "Expected/assumed socket service (optional)",
                        &self.expected_service,
                    )
                    .on_input(|v| Message::ScenarioChanged("service".into(), v)))
                    .boxed(),
                )
                .push(
                    (text_input("Expected local port (optional)", &self.expected_port)
                        .on_input(|v| Message::ScenarioChanged("port".into(), v)))
                    .boxed(),
                )
                .push(
                    (button("Evaluate cached evidence").on_press_maybe(
                        (self.diagnostic_data.is_some() && !self.analysis_busy)
                            .then_some(Message::EvaluateCached),
                    ))
                    .boxed(),
                );
            for f in &self.analysis.findings {
                let color = match f.certainty {
                    diagnostics::Certainty::ConfirmedFailure => {
                        iced::Color::from_rgb(0.95, 0.4, 0.4)
                    }
                    diagnostics::Certainty::Inferred => iced::Color::from_rgb(0.95, 0.75, 0.3),
                    diagnostics::Certainty::Observed => iced::Color::from_rgb(0.5, 0.8, 0.95),
                };
                content = content
                    .push((iced::widget::rule::horizontal(1)).boxed())
                    .push((text(format!("{} — {}", f.certainty, f.title)).color(color)).boxed())
                    .push((text(&f.explanation).size(13)).boxed())
                    .push((text(format!("Next: {}", f.follow_up)).size(12)).boxed());
                if self.sections.contains("Evidence references") {
                    content = content.push(
                        (text(format!(
                            "{} v{} | {} ms UTC\nEvidence: {}\nAssumptions: {}",
                            f.id,
                            self.analysis.evaluator_version,
                            f.time_ms,
                            f.evidence.join(", "),
                            f.assumptions.join("; ")
                        ))
                        .size(11))
                        .boxed(),
                    );
                }
            }
            content = content.push((self.section_button("Evidence references")).boxed());
            if let Some(data) = &self.diagnostic_data {
                content=content.push(text(format!("Diagnostic evidence collected {} seconds ago ({} ms UTC). Refresh to investigate newer attempts.",now_ms().saturating_sub(data.finished_ms)/1000,data.finished_ms)).size(12).boxed());
                content = content.push((self.section_button("Process and services")).boxed());
                if self.sections.contains("Process and services") {
                    if let Some(p) = &data.process {
                        content = content.push(
                            (text(format!(
                                "Owner: {}\nCommand line (sensitive): {}",
                                p.owner.as_deref().unwrap_or("unavailable"),
                                p.command_line.as_deref().unwrap_or("unavailable")
                            ))
                            .size(12))
                            .boxed(),
                        );
                    }
                    for s in &data.services {
                        content=content.push((text(format!("{} ({}) — {} / {}\nPID {} | configured account {}\nConfigured binary: {}",s.name,s.display_name,s.state,s.start_mode,s.pid,s.account,s.binary)).size(12)).boxed());
                    }
                    content = content.push(
                        (text("PID membership does not establish socket-level service ownership.")
                            .size(12))
                        .boxed(),
                    );
                }
                content = content.push((self.section_button("Firewall condition details")).boxed());
                if self.sections.contains("Firewall condition details") {
                    content = content.push(
                        (text(format!(
                            "ActiveStore {} ms UTC | version {} | {}",
                            data.policy.collected_ms,
                            data.policy.version,
                            if data.policy.complete {
                                "collected; supported subset"
                            } else {
                                "partial/unavailable"
                            }
                        ))
                        .size(12))
                        .boxed(),
                    );
                    for p in &data.policy.profiles {
                        content=content.push((text(format!("{} enabled={} inbound={} outbound={} inbound rules={} local merge={}",p.name,p.enabled,p.inbound,p.outbound,p.allow_inbound_rules,p.allow_local_rules)).size(12)).boxed());
                    }
                    for e in self.analysis.rules.iter().take(50) {
                        content = content.push(
                            (text(format!(
                                "{} | {} | {} ({})",
                                e.result, e.action, e.rule_name, e.rule_id
                            ))
                            .size(14))
                            .boxed(),
                        );
                        for cond in &e.conditions {
                            content = content.push(
                                (text(format!("{}: {} — {}", cond.name, cond.result, cond.detail))
                                    .size(11))
                                .boxed(),
                            );
                        }
                        if let Some(rule) = data.policy.rules.iter().find(|r| r.id == e.rule_id) {
                            content = content.push(
                                (text(format!(
                                    "Source {} / {} | enforcement {}",
                                    rule.source, rule.source_type, rule.enforcement
                                ))
                                .size(11))
                                .boxed(),
                            );
                        }
                    }
                    if self.analysis.rules.len() > 50 {
                        content = content.push(
                            (text(
                                "First 50 candidates displayed; evaluator considers up to 2000.",
                            )
                            .size(12))
                            .boxed(),
                        );
                    }
                }
                content = content.push((self.section_button("Network context")).boxed());
                if self.sections.contains("Network context") {
                    for i in &data.interfaces {
                        content=content.push((text(format!("{} (#{}), {} / {} / {}\nIPs {}\nDNS {} | gateways {} | absolute errors {:?}",i.alias,i.index,i.status,i.profile,i.kind,i.addresses.join(", "),i.dns.join(", "),i.gateways.join(", "),i.errors)).size(12)).boxed());
                    }
                    for r in data.routes.iter().take(80) {
                        content = content.push(
                            (text(format!(
                                "{} via {} interface {} metric {}",
                                r.destination, r.next_hop, r.interface, r.metric
                            ))
                            .size(11))
                            .boxed(),
                        );
                    }
                    if data.routes.len() > 80 {
                        content =
                            content.push((text("First 80 routes displayed.").size(11)).boxed());
                    }
                }
                content = content.push((self.section_button("WFP filter evidence")).boxed());
                if self.sections.contains("WFP filter evidence") {
                    for f in &data.filters {
                        content = content.push(
                            text(format!(
                                "Filter {} | queried {} ms UTC\n{}\n{} | provider {} | layer {}",
                                f.runtime_id, f.queried_ms, f.status, f.name, f.provider, f.layer
                            ))
                            .size(12)
                            .boxed(),
                        );
                    }
                    if data.filters.is_empty() {
                        content=content.push(text("No runtime filter IDs available for lookup; direct event and filter access can require elevation.").size(12).boxed());
                    }
                }
                content = content.push((self.section_button("Collection capabilities")).boxed());
                if self.sections.contains("Collection capabilities") {
                    for cap in &data.capabilities {
                        content = content.push(
                            (text(format!("{} — {}\n{}", cap.source, cap.status, cap.detail))
                                .size(12))
                            .boxed(),
                        );
                    }
                }
                content = content.push((self.section_button("Redacted report preview")).boxed());
                if self.sections.contains("Redacted report preview") {
                    content = content
                        .push((text(storage::report(&self.analysis, data)).size(12)).boxed());
                }
            }
            content = content.push((self.section_button("Recent connection history")).boxed());
            if self.sections.contains("Recent connection history") {
                for change in self
                    .history
                    .changes
                    .iter()
                    .rev()
                    .filter(|v| v.key == c.key)
                    .take(50)
                {
                    content = content.push(
                        (text(format!(
                            "{} ms UTC | {} | {} → {}",
                            change.time_ms, change.kind, change.before, change.after
                        ))
                        .size(12))
                        .boxed(),
                    );
                }
                content=content.push((text("Sampling may miss short-lived connections; opening/closing times are not exact.").size(12)).boxed());
            }
        } else {
            content=content.push((text("Select a connection row to inspect it. Individual diagnostic capabilities may need additional access.")).boxed());
        }
        content=content.push((iced::widget::rule::horizontal(1)).boxed()).push((text("Local files and reports").size(16)).boxed())
            .push((text_input("Full file path",&self.file_path).on_input(|v|Message::ScenarioChanged("file".into(),v))).boxed())
            .push((text("Reports are redacted. Full snapshots contain addresses/process paths. Existing files are preserved.").size(12)).boxed())
            .push((row![button("Export redacted report").on_press_maybe((self.diagnostic_data.is_some()&&!self.analysis.findings.is_empty()).then_some(Message::ExportReport)),button("Save full snapshot").on_press(Message::SaveSnapshot)].spacing(5)).boxed())
            .push((row![button("Load baseline JSON").on_press(Message::LoadSnapshot),button("Compare current").on_press_maybe(self.snapshot.as_ref().map(|_|Message::CompareSnapshot))].spacing(5)).boxed())
            .push((iced::widget::rule::horizontal(1)).boxed()).push((text("Optional DNS lookup (network activity)").size(16)).boxed())
            .push((text_input("Hostname",&self.dns_name).on_input(Message::DnsChanged)).boxed()).push((button("Resolve hostname").on_press_maybe((!self.dns_busy).then_some(Message::ResolveDns))).boxed()).push((text(&self.dns_result).size(12)).boxed())
            .push((text("Read-only diagnosis: firewall rules, audit settings and services are never changed. Events depend on existing audit policy/access.").size(12)).boxed());
        container(scrollable(content.padding(10)))
            .width(480)
            .height(Length::Fill)
            .style(container::bordered_box)
            .boxed()
    }
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
