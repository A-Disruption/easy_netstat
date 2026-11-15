//! Docked reachability panel beside the connection table, and the rule-vs-traffic
//! drill-down it opens. The full multi-tab report stays available as a modal.
use super::*;
use crate::diagnostic_style::{Tone, badge, diagnostic_scroll, muted, notice};
use easy_netstat::diagnostics::{Outcome, ProfileVerdict, StepStatus, Verdict};
use easy_netstat::firewall::{self, Evaluation, Match, Relevance};
use easy_netstat::model::Direction as TrafficDirection;

pub(super) const PANEL_WIDTH: f32 = 400.0;

fn bold<'a>(value: impl text::IntoFragment<'a>) -> iced::widget::Text<'a, Theme> {
    text(value).font(Font {
        weight: font::Weight::Bold,
        ..Font::DEFAULT
    })
}

pub(super) fn outcome_tone(outcome: Outcome, confirmed: bool) -> Tone {
    match outcome.permits() {
        Some(true) => Tone::Success,
        Some(false) if confirmed => Tone::Danger,
        Some(false) => Tone::Warning,
        None => Tone::Neutral,
    }
}
/// One compact decision row: colored square, step name, status word. Detail
/// shows underneath only when the step stopped or couldn't decide the traffic.
fn step_row(status: StepStatus, name: String, detail: String) -> Element<'static, Message> {
    let color = move |t: &Theme| {
        let p = t.palette();
        match status {
            StepStatus::Pass => p.success.base.color,
            StepStatus::Fail => p.warning.base.color,
            StepStatus::Unknown | StepStatus::Skipped => p.background.strong.color,
        }
    };
    let word = match status {
        StepStatus::Pass => "Pass",
        StepStatus::Fail => "Fail",
        StepStatus::Unknown => "Unknown",
        StepStatus::Skipped => "Skipped",
    };
    let square = container(space::horizontal())
        .width(10)
        .height(10)
        .style(move |t: &Theme| container::Style {
            background: Some(color(t).into()),
            border: iced::Border {
                radius: 2.0.into(),
                ..iced::Border::default()
            },
            ..container::Style::default()
        });
    let label = text(word).size(12).style(move |t: &Theme| match status {
        StepStatus::Pass | StepStatus::Fail => text::Style {
            color: Some(color(t)),
            ..text::Style::default()
        },
        _ => muted(t),
    });
    let line = row![square, text(name).size(13), space::horizontal(), label]
        .spacing(10)
        .align_y(Alignment::Center)
        .padding([4, 0]);
    if matches!(status, StepStatus::Fail | StepStatus::Unknown) {
        iced::widget::column![
            line,
            container(text(detail).size(12).style(muted)).padding(iced::Padding {
                left: 20.0,
                ..iced::Padding::ZERO
            })
        ]
        .boxed()
    } else {
        line.boxed()
    }
}
/// Text-only button in the theme's accent color, used like a hyperlink.
fn link(theme: &Theme, status: button::Status) -> button::Style {
    let mut style = button::text(theme, status);
    style.text_color = theme.palette().primary.strong.color;
    style
}
fn match_badge(m: Match) -> Element<'static, Message> {
    match m {
        Match::Match => badge("✓ Match", Tone::Success),
        Match::Mismatch => badge("✕ Excludes", Tone::Warning),
        Match::Unknown => badge("? Can't evaluate", Tone::Neutral),
    }
}
fn differences(e: &Evaluation) -> String {
    let names: Vec<_> = e
        .conditions
        .iter()
        .filter(|c| c.result == Match::Mismatch)
        .map(|c| c.name.to_lowercase())
        .collect();
    match names.len() {
        0 if e.result == Match::Match => "matches".into(),
        0 => "can't be fully evaluated".into(),
        1 => format!("1 difference: {}", names[0]),
        n => format!("{n} differences: {}", names.join(", ")),
    }
}
fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

impl App {
    /// A listener, or a socket sharing a listener's PID and port, receives
    /// traffic; anything else most likely initiated it. Shown as a guess.
    pub(super) fn guess_direction(&self, c: &Connection) -> TrafficDirection {
        let receives = c.is_listener()
            || (c.key.protocol == Protocol::Udp && c.key.remote.is_none())
            || self.history.current.iter().any(|o| {
                o.is_listener()
                    && o.key.process.pid == c.key.process.pid
                    && o.key.local.port() == c.key.local.port()
            });
        if receives {
            TrafficDirection::Inbound
        } else {
            TrafficDirection::Outbound
        }
    }

    pub(super) fn reach_cell(&self, key: Option<&ConnectionKey>) -> Element<'_, Message> {
        match key.and_then(|k| self.reach.get(k)) {
            Some(&(outcome, confirmed)) => badge(
                if confirmed && outcome.permits() == Some(false) {
                    "Blocked"
                } else {
                    outcome.label()
                },
                outcome_tone(outcome, confirmed),
            ),
            None => text("Not checked").size(13).style(muted).boxed(),
        }
    }

    fn rule_name(&self, id: &str) -> String {
        self.diagnostic_data
            .as_ref()
            .and_then(|d| d.policy.rules.iter().find(|r| r.id == id))
            .map(|r| r.name.clone())
            .unwrap_or_else(|| id.to_string())
    }

    fn events_step(&self, v: &Verdict) -> (StepStatus, String) {
        if v.confirmed {
            return (
                if v.outcome.permits() == Some(false) {
                    StepStatus::Fail
                } else {
                    StepStatus::Pass
                },
                "A Security event for this process and endpoint decided the result.".into(),
            );
        }
        let cap = self.diagnostic_data.as_ref().and_then(|d| {
            d.capabilities
                .iter()
                .find(|c| c.source == "WFP Security events")
        });
        let detail = match cap.map(|c| c.status.as_str()) {
            Some("Available" | "Partial") => {
                "No matching events in the last 15 minutes. Auditing may be off.".into()
            }
            Some("No records") => {
                "No connection events recorded in the last 15 minutes; connection auditing is probably off."
                    .into()
            }
            Some(_) if !matches!(self.elevation_status, Ok(true)) => {
                "The Security log can't be read without administrator rights.".into()
            }
            Some(_) => "The Security log couldn't be read.".into(),
            None => "Recorded events were not collected.".into(),
        };
        (StepStatus::Unknown, detail)
    }

    pub(super) fn verdict_view<'a>(&'a self, v: &'a Verdict) -> Element<'a, Message> {
        let tone = outcome_tone(v.outcome, v.confirmed);
        let card = container(
            iced::widget::column![
                bold(v.outcome.label()).size(17),
                text(&v.reason).size(13),
                text(if v.confirmed {
                    "Confirmed by a recorded Windows Filtering Platform event."
                } else {
                    "Based on firewall configuration, not a recorded packet."
                })
                .size(12)
                .style(muted),
            ]
            .spacing(6),
        )
        .padding(14)
        .width(Length::Fill)
        .style(move |t: &Theme| tone.surface(t));

        // Profiles that took identical steps are shown once, named together.
        let key = |p: &ProfileVerdict| {
            p.steps
                .iter()
                .map(|s| (s.status, s.name.clone(), s.detail.replace(&p.profile, "")))
                .collect::<Vec<_>>()
        };
        let mut groups: Vec<(Vec<&ProfileVerdict>, _)> = Vec::new();
        for p in &v.profiles {
            let k = key(p);
            match groups
                .iter_mut()
                .find(|(g, gk)| g[0].outcome == p.outcome && *gk == k)
            {
                Some((g, _)) => g.push(p),
                None => groups.push((vec![p], k)),
            }
        }
        let mut steps = iced::widget::column![].spacing(4);
        for (group, _) in &groups {
            if v.profiles.len() > 1 {
                let names =
                    easy_netstat::verdict::join_names(group.iter().map(|p| p.profile.as_str()));
                steps = steps.push(
                    text(format!(
                        "{names} {} · {}",
                        if group.len() > 1 {
                            "profiles"
                        } else {
                            "profile"
                        },
                        group[0].outcome.label()
                    ))
                    .size(12)
                    .style(muted)
                    .boxed(),
                );
            }
            for s in group[0]
                .steps
                .iter()
                .filter(|s| s.status != StepStatus::Skipped)
            {
                steps = steps.push(step_row(s.status, s.name.clone(), s.detail.clone()));
            }
        }
        let (status, detail) = self.events_step(v);
        steps = steps.push(step_row(status, "Recorded events".into(), detail));

        let mut rules = iced::widget::column![].spacing(4);
        let deciding = v.profiles.iter().find_map(|p| p.deciding_rule.clone());
        for (label, id) in [
            ("Deciding rule:", deciding),
            ("Closest rule:", v.closest_rule.clone()),
        ]
        .into_iter()
        .filter_map(|(l, id)| id.map(|id| (l, id)))
        {
            let scope = self
                .analysis
                .rules
                .iter()
                .find(|e| e.rule_id == id)
                .and_then(|e| e.conditions.iter().find(|c| c.result == Match::Mismatch))
                .map(|c| format!("· {} {}", c.name.to_lowercase(), c.rule_value))
                .unwrap_or_default();
            rules = rules.push(
                row![
                    text(label).size(13),
                    button(text(self.rule_name(&id)).size(13))
                        .padding(0)
                        .style(link)
                        .on_press(Message::ShowRuleDetail(Some(id))),
                    text(scope).size(13).style(muted),
                ]
                .spacing(6)
                .wrap()
                .boxed(),
            );
        }
        iced::widget::column![card, steps, rules, text(&v.next).size(12).style(muted)]
            .spacing(14)
            .boxed()
    }

    pub(super) fn reach_panel(&self) -> Element<'_, Message> {
        let header = row![
            bold("Reachability").size(16),
            space::horizontal(),
            button(text("✕"))
                .style(button::text)
                .on_press(Message::TogglePanel)
        ]
        .align_y(Alignment::Center);
        let mut body = iced::widget::column![header]
            .spacing(14)
            .padding(iced::Padding {
                right: 16.0,
                ..iced::Padding::ZERO
            });
        let Some(c) = &self.selected else {
            body = body.push(
                text("Select a row in the table to check whether its traffic would get through the firewall.")
                    .size(13)
                    .style(muted)
                    .boxed(),
            );
            return self.panel_frame(body);
        };
        let endpoint = if c.key.local.ip().is_unspecified() {
            format!("listening on all addresses, port {}", c.key.local.port())
        } else {
            c.key.local.to_string()
        };
        body = body.push(
            iced::widget::column![
                bold(&c.process.name).size(16),
                text(format!(
                    "PID {} · {} · {}",
                    c.key.process.pid, c.key.protocol, c.state
                ))
                .size(13)
                .style(muted),
                text(endpoint).size(12).font(Font::MONOSPACE).style(muted),
            ]
            .spacing(3)
            .boxed(),
        );
        let inbound = self.direction == TrafficDirection::Inbound;
        let dir_button = |label: &'static str, dir: TrafficDirection| {
            button(text(label).align_x(alignment::Horizontal::Center))
                .width(Length::Fill)
                .style(if self.direction_confirmed && self.direction == dir {
                    button::primary
                } else {
                    button::secondary
                })
                .on_press(Message::ScenarioChanged("direction".into(), label.into()))
        };
        let busy = self.diagnostic_gate.busy();
        body = body.push(
            iced::widget::column![
                text(if inbound { "From client" } else { "To server" })
                    .size(12)
                    .style(muted),
                text_input("IP:port (optional)", &self.peer_input)
                    .on_input(|v| Message::ScenarioChanged("peer".into(), v))
                    .font(Font::MONOSPACE)
                    .size(13)
                    .padding(8),
                row![
                    dir_button("Inbound", TrafficDirection::Inbound),
                    dir_button("Outbound", TrafficDirection::Outbound)
                ]
                .spacing(6),
                text(if self.direction_guessed {
                    "Direction guessed from the socket state."
                } else if inbound {
                    "Traffic arriving at this endpoint."
                } else {
                    "Traffic this endpoint sends."
                })
                .size(12)
                .style(muted),
                row![
                    button(if busy {
                        "Checking…"
                    } else if self.diagnostic_data.is_some() {
                        "Check again"
                    } else {
                        "Check"
                    })
                    .style(button::primary)
                    .on_press_maybe((!busy).then_some(Message::Diagnose(false))),
                    button("Cancel")
                        .style(button::text)
                        .on_press_maybe(busy.then_some(Message::CancelDiagnosis)),
                ]
                .spacing(8)
                .align_y(Alignment::Center),
            ]
            .spacing(6)
            .boxed(),
        );

        if let Some(v) = &self.analysis.verdict {
            body = body.push(self.verdict_view(v));
        } else if self.analysis_busy {
            body = body.push(text("Evaluating…").size(13).style(muted).boxed());
        } else if self.diagnostic_data.is_some() {
            body = body.push(notice("Not evaluated", self.status.clone(), Tone::Info));
        } else {
            body = body.push(
                text("Check reads firewall policy, process, network and recorded events for this endpoint. Nothing is changed.")
                    .size(13)
                    .style(muted)
                    .boxed(),
            );
        }
        if let Some(data) = &self.diagnostic_data {
            let missing: Vec<_> = data
                .capabilities
                .iter()
                .filter(|c| matches!(c.status.as_str(), "Unavailable" | "Partial" | "Ambiguous"))
                .map(|c| c.source.as_str())
                .collect();
            if !missing.is_empty() {
                body = body.push(
                    text(format!("Limited data: {}.", missing.join(", ")))
                        .size(12)
                        .style(muted)
                        .boxed(),
                );
            }
        }
        body = body.push(
            button(text("Open full report").align_x(alignment::Horizontal::Center))
                .width(Length::Fill)
                .style(button::secondary)
                .on_press(Message::OpenFullReport)
                .boxed(),
        );
        if !matches!(self.elevation_status, Ok(true)) {
            body = body.push(
                row![
                    text("Standard user · Security events need admin.")
                        .size(12)
                        .style(muted),
                    button(
                        text(if self.elevation_busy {
                            "Waiting…"
                        } else {
                            "Restart as admin"
                        })
                        .size(12)
                    )
                    .padding(0)
                    .style(link)
                    .on_press_maybe(
                        (!self.elevation_busy).then_some(Message::RestartAsAdministrator)
                    )
                ]
                .spacing(6)
                .wrap()
                .boxed(),
            );
        }
        body = body.push(
            text("Changing the peer or direction re-checks the collected data instantly; Check again re-reads Windows.")
                .size(12)
                .style(muted)
                .boxed(),
        );
        self.panel_frame(body)
    }

    /// A plain side column divided from the table by a single line, not a card.
    fn panel_frame<'a>(
        &'a self,
        body: iced::widget::Column<Element<'a, Message>>,
    ) -> Element<'a, Message> {
        row![
            iced::widget::rule::vertical(1),
            container(diagnostic_scroll(body))
                .width(Length::Fill)
                .height(Length::Fill)
                .padding(iced::Padding {
                    top: 16.0,
                    bottom: 16.0,
                    left: 18.0,
                    right: 2.0,
                })
                .style(|t: &Theme| container::Style {
                    background: Some(t.palette().background.weak.color.into()),
                    ..container::Style::default()
                })
        ]
        .width(PANEL_WIDTH)
        .height(Length::Fill)
        .boxed()
    }

    /// The analysis's own evaluation when the rule is on its shortlist; else a
    /// fresh evaluation against the current scenario and verdict profile.
    fn detail_evaluation(&self, rule: &FirewallRule) -> Option<Evaluation> {
        if let Some(e) = self.analysis.rules.iter().find(|e| e.rule_id == rule.id) {
            return Some(e.clone());
        }
        let mut s = easy_netstat::diagnostics::enrich(
            &self.scenario().ok()?,
            self.diagnostic_data.as_ref()?,
        );
        if s.profile.is_none()
            && let Some(v) = &self.analysis.verdict
            && let [only] = v.profiles.as_slice()
        {
            s.profile = Some(only.profile.clone());
        }
        Some(firewall::evaluate(rule, &s))
    }

    /// A copyable command that adds the examined value to the one condition
    /// that excludes it. Offered only for conditions with a direct parameter.
    pub(super) fn widen_command(&self, rule: &FirewallRule, e: &Evaluation) -> Option<String> {
        let [only] = e
            .conditions
            .iter()
            .filter(|c| c.result == Match::Mismatch)
            .collect::<Vec<_>>()[..]
        else {
            return None;
        };
        let (param, existing, add) = match only.name.as_str() {
            "Remote address" => (
                "-RemoteAddress",
                &rule.remote_addresses,
                self.scenario().ok()?.remote?.ip().to_string(),
            ),
            "Local port" => ("-LocalPort", &rule.local_ports, only.traffic.clone()),
            "Profile" => ("-Profile", &rule.profiles, only.traffic.clone()),
            _ => return None,
        };
        if add.is_empty() || add == "unknown" {
            return None;
        }
        let values = existing
            .iter()
            .chain(std::iter::once(&add))
            .cloned()
            .collect::<Vec<_>>()
            .join(",");
        Some(format!(
            "Set-NetFirewallRule -Name {} {param} {values}",
            quote(&rule.id)
        ))
    }

    fn rule_detail_body(&self, id: &str) -> Element<'_, Message> {
        let Some(rule) = self
            .diagnostic_data
            .as_ref()
            .and_then(|d| d.policy.rules.iter().find(|r| r.id == id))
        else {
            return notice(
                "Rule unavailable",
                "This rule is not in the current collection. Check again to reload policy.",
                Tone::Warning,
            );
        };
        let Some(e) = self.detail_evaluation(rule) else {
            return notice(
                "Scenario incomplete",
                "Set a direction and a valid peer to compare this rule with the traffic.",
                Tone::Info,
            );
        };
        let excluded = e
            .conditions
            .iter()
            .filter(|c| c.result == Match::Mismatch)
            .count();
        let unknown = e
            .conditions
            .iter()
            .filter(|c| c.result == Match::Unknown)
            .count();
        let summary = match (excluded, unknown) {
            (0, 0) => "All conditions match this traffic".to_string(),
            (0, n) => format!("{n} condition(s) can't be evaluated"),
            (1, _) => "1 condition excludes this traffic".into(),
            (n, _) => format!("{n} conditions exclude this traffic"),
        };
        let action_tone = if rule.action.eq_ignore_ascii_case("Block") {
            Tone::Danger
        } else {
            Tone::Success
        };
        let source = if rule.source_type.is_empty() {
            "Source unknown".to_string()
        } else if rule.source.is_empty() {
            rule.source_type.clone()
        } else {
            format!("{} · {}", rule.source_type, rule.source)
        };
        let header = row![
            bold(rule.name.clone()).size(18),
            badge(rule.action.clone(), action_tone),
            badge(source, Tone::Neutral),
            space::horizontal(),
            text(summary).size(13),
        ]
        .spacing(10)
        .align_y(Alignment::Center);

        let cell = |s: &str| {
            text(if s.is_empty() {
                "—".to_string()
            } else {
                s.to_string()
            })
            .size(13)
            .font(Font::MONOSPACE)
            // SIDs, paths and IPv6 addresses have no spaces; break inside them
            // rather than running over the next column.
            .wrapping(text::Wrapping::WordOrGlyph)
            .width(Length::FillPortion(2))
        };
        let mut table = iced::widget::column![
            row![
                text("Condition").size(12).style(muted).width(130),
                text("Rule requires")
                    .size(12)
                    .style(muted)
                    .width(Length::FillPortion(2)),
                text("This traffic")
                    .size(12)
                    .style(muted)
                    .width(Length::FillPortion(2)),
                text("Result").size(12).style(muted).width(130),
            ]
            .spacing(10)
            .padding([4, 10])
        ]
        .spacing(2);
        for c in &e.conditions {
            let line = row![
                text(c.name.clone())
                    .size(13)
                    .width(130)
                    .wrapping(text::Wrapping::WordOrGlyph),
                cell(if c.rule_value.is_empty() && c.traffic.is_empty() {
                    &c.detail
                } else {
                    &c.rule_value
                }),
                cell(&c.traffic),
                container(match_badge(c.result)).width(130),
            ]
            .spacing(10)
            .align_y(Alignment::Center);
            let tone = if c.result == Match::Mismatch {
                Some(Tone::Warning)
            } else {
                None
            };
            table = table.push(
                container(line)
                    .padding([6, 10])
                    .width(Length::Fill)
                    .style(move |t: &Theme| match tone {
                        Some(tone) => tone.surface(t),
                        None => container::Style::default(),
                    })
                    .boxed(),
            );
        }

        let mut left = iced::widget::column![
            header,
            container(table).style(|t: &Theme| Tone::Neutral.surface(t))
        ]
        .spacing(14)
        .width(Length::Fill);
        if let Some(cmd) = self.widen_command(rule, &e) {
            left = left.push(
                container(
                    iced::widget::column![
                        text("To let this traffic through, an administrator could run")
                            .size(12)
                            .style(muted),
                        row![
                            text(cmd.clone())
                                .size(12)
                                .font(Font::MONOSPACE)
                                .width(Length::Fill),
                            button(text("Copy").size(12))
                                .style(button::secondary)
                                .on_press(Message::CopyText(cmd))
                        ]
                        .spacing(10)
                        .align_y(Alignment::Center),
                        text("easy_netstat stays read-only; this is only a suggestion to copy.")
                            .size(12)
                            .style(muted),
                    ]
                    .spacing(8),
                )
                .padding(12)
                .width(Length::Fill)
                .style(|t: &Theme| Tone::Neutral.surface(t))
                .boxed(),
            );
        }
        left = left.push(
            row![
                button("Open in rule browser")
                    .style(button::secondary)
                    .on_press(Message::OpenRuleInBrowser(rule.id.clone())),
                button("Close")
                    .style(button::text)
                    .on_press(Message::ShowRuleDetail(None)),
            ]
            .spacing(8)
            .boxed(),
        );

        let candidate = |e: &Evaluation| {
            let current = e.rule_id == id;
            button(
                iced::widget::column![
                    bold(e.rule_name.clone()).size(13),
                    text(format!("{} · {}", e.action, differences(e))).size(12)
                ]
                .spacing(2),
            )
            .width(Length::Fill)
            .style(if current {
                button::primary
            } else {
                button::secondary
            })
            .on_press(Message::ShowRuleDetail(Some(e.rule_id.clone())))
        };
        let mut right =
            iced::widget::column![text("RULES THAT NAME THIS PROGRAM").size(11).style(muted)]
                .spacing(8)
                .width(270);
        let named: Vec<_> = self
            .analysis
            .rules
            .iter()
            .filter(|e| {
                matches!(
                    e.relevance,
                    Some(Relevance::Application | Relevance::Service)
                )
            })
            .take(8)
            .collect();
        if named.is_empty() {
            right = right.push(text("None").size(13).style(muted).boxed());
        }
        for e in named {
            right = right.push(candidate(e).boxed());
        }
        right = right.push(text("BROAD RULES THAT MATCH").size(11).style(muted).boxed());
        let broad: Vec<_> = self
            .analysis
            .rules
            .iter()
            .filter(|e| e.result == Match::Match && e.relevance == Some(Relevance::Traffic))
            .take(5)
            .collect();
        if broad.is_empty() {
            right = right.push(text("None").size(13).style(muted).boxed());
        }
        for e in broad {
            right = right.push(candidate(e).boxed());
        }
        right = right.push(
            text("Sorted by fewest differences. A rule with one difference is usually the one someone meant to apply.")
                .size(12)
                .style(muted).boxed()
        );
        diagnostic_scroll(row![left, right].spacing(20)).boxed()
    }

    pub(super) fn rule_detail_modal(&self) -> Element<'_, Message> {
        let content = match &self.rule_detail {
            Some(id) => self.rule_detail_body(id),
            None => space::horizontal().boxed(),
        };
        modal(content, "Rule vs traffic")
            .open(self.rule_detail.is_some())
            .min_width(1120.0)
            .max_width(1500.0)
            .min_height(420.0)
            .on_dismiss(Message::ShowRuleDetail(None))
            .boxed()
    }
}
