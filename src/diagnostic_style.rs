//! Shared diagnostic presentation: colors describe evidence/condition states,
//! never upgrade a configuration inference into a confirmed traffic failure.
use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Tone {
    Neutral,
    Info,
    Success,
    Warning,
    Danger,
}
impl Tone {
    fn pair(self, theme: &Theme) -> iced::theme::palette::Pair {
        let p = theme.palette();
        match self {
            Self::Neutral => p.background.weak,
            Self::Info => p.primary.weak,
            Self::Success => p.success.weak,
            Self::Warning => p.warning.weak,
            Self::Danger => p.danger.weak,
        }
    }
    fn accent(self, theme: &Theme) -> iced::Color {
        let p = theme.palette();
        match self {
            Self::Neutral => p.background.strong.color,
            Self::Info => p.primary.base.color,
            Self::Success => p.success.base.color,
            Self::Warning => p.warning.base.color,
            Self::Danger => p.danger.base.color,
        }
    }
    /// A card: the darkest background, barely tinted toward the tone, with a
    /// thin tone-colored border. Large areas stay calm; color marks state.
    pub(super) fn surface(self, theme: &Theme) -> container::Style {
        let p = theme.palette();
        let accent = self.accent(theme);
        let tint = if self == Self::Neutral { 0.0 } else { 0.10 };
        container::Style {
            background: Some(p.background.base.color.mix(accent, tint).into()),
            text_color: Some(p.background.base.text),
            border: iced::Border {
                radius: 8.0.into(),
                width: 1.0,
                color: if self == Self::Neutral {
                    p.background.strong.color
                } else {
                    accent.scale_alpha(0.7)
                },
            },
            ..container::Style::default()
        }
    }
    /// A small solid label. The only place a tone fills its whole box.
    pub(super) fn pill(self, theme: &Theme) -> container::Style {
        let pair = self.pair(theme);
        container::Style {
            background: Some(pair.color.into()),
            text_color: Some(pair.text),
            border: iced::Border {
                radius: 999.0.into(),
                ..iced::Border::default()
            },
            ..container::Style::default()
        }
    }
}
pub(super) fn certainty_tone(c: diagnostics::Certainty) -> Tone {
    match c {
        diagnostics::Certainty::Observed => Tone::Info,
        diagnostics::Certainty::Inferred => Tone::Warning,
        diagnostics::Certainty::ConfirmedFailure => Tone::Danger,
    }
}
pub(super) fn match_tone(m: easy_netstat::firewall::Match) -> Tone {
    match m {
        easy_netstat::firewall::Match::Match => Tone::Success,
        easy_netstat::firewall::Match::Mismatch => Tone::Warning,
        easy_netstat::firewall::Match::Unknown => Tone::Neutral,
    }
}
pub(super) fn capability_tone(status: &str) -> Tone {
    match status {
        "Available" => Tone::Success,
        "Partial" | "Unavailable" | "Ambiguous" => Tone::Warning,
        _ => Tone::Neutral,
    }
}
pub(super) fn firewall_enabled_status(enabled: &str) -> (&'static str, Tone) {
    if enabled.trim().eq_ignore_ascii_case("True") {
        ("Enabled", Tone::Success)
    } else if enabled.trim().eq_ignore_ascii_case("False") {
        ("Disabled", Tone::Danger)
    } else {
        ("Enabled state unavailable", Tone::Warning)
    }
}
/// "just now", "12 s ago", "5 min ago", "2 h ago", "3 d ago".
pub(super) fn ago(ms: u64) -> String {
    let s = now_ms().saturating_sub(ms) / 1000;
    match s {
        0..=4 => "just now".into(),
        5..=59 => format!("{s} s ago"),
        60..=3599 => format!("{} min ago", s / 60),
        3600..=86399 => format!("{} h ago", s / 3600),
        _ => format!("{} d ago", s / 86400),
    }
}
pub(super) fn muted(theme: &Theme) -> text::Style {
    let p = theme.palette().background.base;
    text::Style {
        color: Some(p.text.mix(p.color, 0.28)),
        ..text::Style::default()
    }
}
pub(super) fn badge(label: impl Into<String>, tone: Tone) -> Element<'static, Message> {
    container(text(label.into()).size(12).font(Font {
        weight: font::Weight::Bold,
        ..Font::DEFAULT
    }))
    .padding([3, 10])
    .style(move |theme: &Theme| tone.pill(theme))
    .boxed()
}
pub(super) fn section(
    title: impl Into<String>,
    subtitle: impl Into<String>,
) -> Element<'static, Message> {
    iced::widget::column![
        text(title.into())
            .size(19)
            .font(Font {
                weight: font::Weight::Bold,
                ..Font::DEFAULT
            })
            .style(text::primary),
        text(subtitle.into()).size(12).style(muted),
        iced::widget::rule::horizontal(1)
    ]
    .spacing(5)
    .boxed()
}
pub(super) fn key_value(
    label: impl Into<String>,
    value: impl Into<String>,
) -> Element<'static, Message> {
    row![
        text(label.into()).size(12).style(muted).width(130),
        text(value.into()).size(14).width(Length::Fill)
    ]
    .spacing(12)
    .align_y(Alignment::Start)
    .boxed()
}
pub(super) fn notice(
    title: impl Into<String>,
    detail: impl Into<String>,
    tone: Tone,
) -> Element<'static, Message> {
    container(iced::widget::column![badge(title, tone), text(detail.into()).size(13)].spacing(8))
        .padding(12)
        .width(Length::Fill)
        .style(move |theme: &Theme| tone.surface(theme))
        .boxed()
}
/// `auditpol /r` CSV rows -> "Subcategory: setting" lines.
fn readable_audit(detail: &str) -> String {
    let lines: Vec<_> = detail
        .lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<_> = l.split(',').collect();
            (f.len() > 4 && !f[2].is_empty()).then(|| format!("{}: {}", f[2], f[4]))
        })
        .collect();
    if lines.is_empty() {
        detail.to_string()
    } else {
        lines.join(
            "
",
        )
    }
}
pub(super) fn capability(cap: &Capability) -> Element<'static, Message> {
    let tone = capability_tone(&cap.status);
    let detail = if cap.source == "Audit policy" {
        readable_audit(&cap.detail)
    } else {
        cap.detail.clone()
    };
    container(
        iced::widget::column![
            row![
                text(cap.source.clone())
                    .font(Font {
                        weight: font::Weight::Bold,
                        ..Font::DEFAULT
                    })
                    .size(13),
                space::horizontal(),
                badge(cap.status.clone(), tone)
            ]
            .spacing(10),
            text(detail).size(12).style(muted)
        ]
        .spacing(6),
    )
    .padding(10)
    .width(Length::Fill)
    .style(|theme: &Theme| Tone::Neutral.surface(theme))
    .boxed()
}
pub(super) fn detail_group(
    title: &'static str,
    fields: Vec<(&'static str, String)>,
) -> Element<'static, Message> {
    let mut body = iced::widget::column![
        text(title)
            .size(15)
            .font(Font {
                weight: font::Weight::Bold,
                ..Font::DEFAULT
            })
            .style(text::primary)
    ]
    .spacing(10);
    for (label, value) in fields {
        body = body.push(key_value(
            label,
            if value.is_empty() {
                "Unavailable / not collected".into()
            } else {
                value
            },
        ));
    }
    container(body)
        .padding(14)
        .width(Length::Fill)
        .style(|t: &Theme| Tone::Neutral.surface(t))
        .boxed()
}
/// Reserve a scrollbar lane instead of drawing the rail over rightmost controls.
/// Iced's spacing includes the rail width and relayouts content when it appears.
pub(super) fn diagnostic_scroll<'a, M, W>(body: W) -> iced::widget::Scrollable<'a, M, W, Theme> {
    iced::widget::scrollable(body)
        .spacing(8)
        .width(Length::Fill)
        .height(Length::Fill)
}

/// Fill the content area settled by the modal, rather than keeping a fixed
/// height after the user resizes the surface.
pub(super) fn expanding_body<W>(body: iced::widget::Column<W>) -> iced::widget::Column<W> {
    body.spacing(12).width(Length::Fill).height(Length::Fill)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced::advanced::Widget;
    #[test]
    fn resized_body_and_remaining_content_grow_vertically() {
        let body = expanding_body(iced::widget::column![
            space::horizontal().height(40),
            diagnostic_scroll(space::horizontal().height(2000)),
            space::horizontal().height(20)
        ]);
        let mut element: iced::Element<'_, (), Theme, ()> = iced::Widget::boxed(body);
        let mut tree = iced::advanced::widget::Tree::new(&element);
        element.diff(&mut tree);
        element.layout(
            &mut tree,
            &(),
            &iced::advanced::layout::Limits::new(iced::Size::ZERO, iced::Size::new(900.0, 400.0)),
        );
        assert_eq!(tree.size, iced::Size::new(900.0, 400.0));
        let initial = tree.children[1].size.height;
        element.layout(
            &mut tree,
            &(),
            &iced::advanced::layout::Limits::new(iced::Size::ZERO, iced::Size::new(1100.0, 650.0)),
        );
        assert_eq!(tree.size, iced::Size::new(1100.0, 650.0));
        assert_eq!(tree.children[1].size.height - initial, 250.0);
        assert_eq!(tree.children[0].size.height, 40.0);
        assert_eq!(tree.children[2].size.height, 20.0);
        element.layout(
            &mut tree,
            &(),
            &iced::advanced::layout::Limits::new(iced::Size::ZERO, iced::Size::new(760.0, 300.0)),
        );
        assert_eq!(tree.size, iced::Size::new(760.0, 300.0));
        assert_eq!(tree.children[1].size.height, initial - 100.0);
    }
    #[test]
    fn scrollbar_reserves_space_and_releases_it_when_content_fits() {
        let mut element: iced::Element<'_, (), Theme, ()> =
            iced::Widget::boxed(diagnostic_scroll(space::horizontal().height(600)));
        let mut tree = iced::advanced::widget::Tree::new(&element);
        element.diff(&mut tree);
        // Reuse state through narrow/wide sizes and scrollbar visibility changes.
        for (width, height, gutter) in [
            (760.0, 300.0, 18.0),
            (1040.0, 450.0, 18.0),
            (760.0, 700.0, 0.0),
            (760.0, 300.0, 18.0),
        ] {
            element.layout(
                &mut tree,
                &(),
                &iced::advanced::layout::Limits::new(
                    iced::Size::ZERO,
                    iced::Size::new(width, height),
                ),
            );
            assert_eq!(tree.size, iced::Size::new(width, height));
            let content = &tree.children[0];
            // 10px default rail + 8px spacing. Fill-width cards/controls must end
            // before this lane; with no scrollbar they get the full width back.
            assert_eq!(content.translation.x + content.size.width, width - gutter);
        }
    }

    #[test]
    fn certainty_and_conditions_have_different_semantics() {
        assert_eq!(
            certainty_tone(diagnostics::Certainty::ConfirmedFailure),
            Tone::Danger
        );
        assert_eq!(
            certainty_tone(diagnostics::Certainty::Inferred),
            Tone::Warning
        );
        assert_eq!(certainty_tone(diagnostics::Certainty::Observed), Tone::Info);
        assert_ne!(
            match_tone(easy_netstat::firewall::Match::Mismatch),
            Tone::Danger
        );
        assert_ne!(
            match_tone(easy_netstat::firewall::Match::Unknown),
            Tone::Success
        );
        assert_eq!(capability_tone("Unavailable"), Tone::Warning);
    }
    #[test]
    fn firewall_enabled_state_distinguishes_disabled_and_unknown() {
        assert_eq!(firewall_enabled_status("True"), ("Enabled", Tone::Success));
        assert_eq!(
            firewall_enabled_status(" false "),
            ("Disabled", Tone::Danger)
        );
        for value in ["", "NotConfigured", "Unknown"] {
            assert_eq!(
                firewall_enabled_status(value),
                ("Enabled state unavailable", Tone::Warning)
            );
        }
    }
    #[test]
    fn semantic_surfaces_adapt_to_light_and_dark_themes() {
        for theme in [Theme::Light, Theme::Dark, Theme::Nord] {
            let info = Tone::Info.surface(&theme);
            let danger = Tone::Danger.surface(&theme);
            assert_ne!(info.background, danger.background);
            assert_ne!(info.border.color, danger.border.color);
            for tone in [
                Tone::Neutral,
                Tone::Info,
                Tone::Success,
                Tone::Warning,
                Tone::Danger,
            ] {
                let pair = tone.pair(&theme);
                assert_ne!(pair.color, pair.text);
            }
        }
        assert_ne!(
            Tone::Warning.surface(&Theme::Light).background,
            Tone::Warning.surface(&Theme::Dark).background
        );
    }
}

#[cfg(test)]
mod audit_tests {
    #[test]
    fn audit_csv_becomes_readable_lines() {
        let csv = "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting
PC,System,Filtering Platform Packet Drop,{0CCE9225},No Auditing,
";
        assert_eq!(
            super::readable_audit(csv),
            "Filtering Platform Packet Drop: No Auditing"
        );
        assert_eq!(super::readable_audit("Access denied"), "Access denied");
    }
}
