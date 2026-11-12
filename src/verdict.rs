//! Combines firewall profile settings with rule evaluation into one answer:
//! what Windows Firewall would most likely do with the examined traffic.
//!
//! Order follows Windows Firewall: profile off → nothing is filtered; matching
//! block rules win; "block all incoming" ignores inbound allow rules; a
//! matching allow rule permits; otherwise the profile default action applies.
use crate::{
    firewall::{self, Evaluation, Match, Relevance},
    model::*,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    Allowed,
    AllowedByDefault,
    Blocked,
    BlockedByDefault,
    NotFiltered,
    Uncertain,
    Unavailable,
}
impl Outcome {
    pub fn label(self) -> &'static str {
        match self {
            Self::Allowed | Self::AllowedByDefault => "Likely allowed",
            Self::Blocked | Self::BlockedByDefault => "Likely blocked",
            Self::NotFiltered => "Not filtered",
            Self::Uncertain => "Can't tell",
            Self::Unavailable => "Unavailable",
        }
    }
    /// Some(true) lets traffic through, Some(false) stops it, None unknown.
    pub fn permits(self) -> Option<bool> {
        match self {
            Self::Allowed | Self::AllowedByDefault | Self::NotFiltered => Some(true),
            Self::Blocked | Self::BlockedByDefault => Some(false),
            Self::Uncertain | Self::Unavailable => None,
        }
    }
}

/// Pass: this stage lets the traffic through. Fail: this stage stops it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepStatus {
    Pass,
    Fail,
    Unknown,
    Skipped,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    pub name: String,
    pub status: StepStatus,
    pub detail: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileVerdict {
    pub profile: String,
    pub outcome: Outcome,
    pub reason: String,
    pub deciding_rule: Option<String>,
    pub steps: Vec<Step>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub outcome: Outcome,
    pub headline: String,
    pub reason: String,
    pub next: String,
    pub assumptions: Vec<String>,
    /// True only when a revalidated WFP event, not configuration, decided it.
    pub confirmed: bool,
    /// Identity-linked allow rule with the fewest excluding conditions.
    pub closest_rule: Option<String>,
    pub profiles: Vec<ProfileVerdict>,
}

fn flag(v: &str) -> Option<bool> {
    let v = v.trim();
    if v.eq_ignore_ascii_case("True") || v.eq_ignore_ascii_case("NotConfigured") {
        // NotConfigured falls back to the Windows default, which is on/permitted
        // for Enabled, AllowInboundRules and AllowLocalFirewallRules.
        Some(true)
    } else if v.eq_ignore_ascii_case("False") {
        Some(false)
    } else {
        None
    }
}
/// Some(true) = Allow. NotConfigured is the Windows default: inbound Block,
/// outbound Allow.
fn default_allows(v: &str, direction: Direction) -> Option<bool> {
    let v = v.trim();
    if v.eq_ignore_ascii_case("Allow") {
        Some(true)
    } else if v.eq_ignore_ascii_case("Block") {
        Some(false)
    } else if v.eq_ignore_ascii_case("NotConfigured") {
        Some(direction == Direction::Outbound)
    } else {
        None
    }
}
pub fn normalize_profile(p: &str) -> Option<String> {
    let p = p.trim();
    if p.eq_ignore_ascii_case("DomainAuthenticated") {
        return Some("Domain".into());
    }
    ["Domain", "Private", "Public"]
        .into_iter()
        .find(|n| p.eq_ignore_ascii_case(n))
        .map(String::from)
}

/// Profiles that can apply: the scenario's, else those on Up interfaces.
pub fn candidate_profiles(s: &Scenario, data: &DiagnosticData) -> Vec<String> {
    if let Some(p) = s.profile.as_deref().and_then(normalize_profile) {
        return vec![p];
    }
    let mut v: Vec<_> = data
        .interfaces
        .iter()
        .filter(|i| i.status.eq_ignore_ascii_case("Up"))
        .filter_map(|i| normalize_profile(&i.profile))
        .collect();
    v.sort();
    v.dedup();
    v
}

struct Steps(Vec<Step>);
impl Steps {
    fn push(&mut self, name: &str, status: StepStatus, detail: impl Into<String>) {
        self.0.push(Step {
            name: name.into(),
            status,
            detail: detail.into(),
        });
    }
}

fn names(v: &[&Evaluation]) -> String {
    let mut s = v
        .iter()
        .take(3)
        .map(|e| format!("'{}'", e.rule_name))
        .collect::<Vec<_>>()
        .join(", ");
    if v.len() > 3 {
        s.push_str(&format!(" and {} more", v.len() - 3));
    }
    s
}

pub fn profile_verdict(profile: &str, s: &Scenario, data: &DiagnosticData) -> ProfileVerdict {
    let dir = s.direction.to_string().to_lowercase();
    let mut steps = Steps(Vec::new());
    let finish = |outcome, reason: String, rule: Option<String>, steps: Steps| ProfileVerdict {
        profile: profile.into(),
        outcome,
        reason,
        deciding_rule: rule,
        steps: steps.0,
    };
    let Some(record) = data
        .policy
        .profiles
        .iter()
        .find(|p| normalize_profile(&p.name).as_deref() == Some(profile))
    else {
        let reason = format!("{profile} profile settings were not collected.");
        steps.push("Firewall profile", StepStatus::Unknown, reason.clone());
        return finish(Outcome::Unavailable, reason, None, steps);
    };
    let enabled = flag(&record.enabled);
    if enabled == Some(false) {
        steps.push(
            "Firewall profile",
            StepStatus::Pass,
            format!("The firewall is off for the {profile} profile; rules are not enforced."),
        );
        return finish(
            Outcome::NotFiltered,
            format!("The firewall is off for the {profile} profile."),
            None,
            steps,
        );
    }
    let default = default_allows(
        if s.direction == Direction::Inbound {
            &record.inbound
        } else {
            &record.outbound
        },
        s.direction,
    );
    let allow_inbound =
        s.direction == Direction::Outbound || flag(&record.allow_inbound_rules) != Some(false);
    let local_rules_ignored = flag(&record.allow_local_rules) == Some(false);
    steps.push(
        "Firewall profile",
        if enabled.is_none() {
            StepStatus::Unknown
        } else {
            StepStatus::Pass
        },
        format!(
            "{profile}: {}, default {dir} {}{}",
            if enabled.is_none() {
                "enabled state unknown"
            } else {
                "on"
            },
            match default {
                Some(true) => "Allow",
                Some(false) => "Block",
                None => "unknown",
            },
            if local_rules_ignored {
                "; locally created rules are ignored"
            } else {
                ""
            }
        ),
    );

    let mut scenario = s.clone();
    scenario.profile = Some(profile.into());
    let evals: Vec<_> = data
        .policy
        .rules
        .iter()
        .filter(|r| !(local_rules_ignored && r.source_type.eq_ignore_ascii_case("Local")))
        .map(|r| firewall::evaluate(r, &scenario))
        .collect();
    let pick = |result: Match, action: &str| {
        evals
            .iter()
            .filter(|e| e.result == result && e.action.eq_ignore_ascii_case(action))
            .collect::<Vec<_>>()
    };
    let blocks = pick(Match::Match, "Block");
    let maybe_blocks = pick(Match::Unknown, "Block");
    let allows = pick(Match::Match, "Allow");
    let maybe_allows = pick(Match::Unknown, "Allow");

    if let Some(first) = blocks.first() {
        steps.push(
            "Block rules",
            StepStatus::Fail,
            format!("{} matching block rule(s): {}", blocks.len(), names(&blocks)),
        );
        steps.push(
            "Allow rules",
            StepStatus::Skipped,
            "Block rules take precedence over allow rules.",
        );
        steps.push("Default action", StepStatus::Skipped, "A rule decided this traffic.");
        return finish(
            Outcome::Blocked,
            format!(
                "Block rule '{}' matches this traffic ({profile} profile).",
                first.rule_name
            ),
            Some(first.rule_id.clone()),
            steps,
        );
    }
    if maybe_blocks.is_empty() {
        steps.push("Block rules", StepStatus::Pass, "No block rule matches.");
    } else {
        steps.push(
            "Block rules",
            StepStatus::Unknown,
            format!(
                "{} block rule(s) could match but have conditions that can't be evaluated: {}",
                maybe_blocks.len(),
                names(&maybe_blocks)
            ),
        );
    }
    if !allow_inbound {
        steps.push(
            "Allow rules",
            StepStatus::Fail,
            format!("The {profile} profile blocks all incoming connections, including allowed apps."),
        );
        steps.push("Default action", StepStatus::Skipped, "Allow rules are not applied.");
        return finish(
            Outcome::Blocked,
            format!(
                "The {profile} profile is set to block all incoming connections, so allow rules don't apply."
            ),
            None,
            steps,
        );
    }
    if let Some(first) = allows.first() {
        steps.push(
            "Allow rules",
            StepStatus::Pass,
            format!("{} matching allow rule(s): {}", allows.len(), names(&allows)),
        );
        steps.push("Default action", StepStatus::Skipped, "A rule decided this traffic.");
        return if maybe_blocks.is_empty() {
            finish(
                Outcome::Allowed,
                format!(
                    "Allow rule '{}' matches this traffic ({profile} profile).",
                    first.rule_name
                ),
                Some(first.rule_id.clone()),
                steps,
            )
        } else {
            finish(
                Outcome::Uncertain,
                format!(
                    "Allow rule '{}' matches, but {} might override it.",
                    first.rule_name,
                    names(&maybe_blocks)
                ),
                Some(first.rule_id.clone()),
                steps,
            )
        };
    }
    match default {
        Some(false) => {
            if maybe_allows.is_empty() {
                steps.push("Allow rules", StepStatus::Fail, "No allow rule matches.");
            } else {
                steps.push(
                    "Allow rules",
                    StepStatus::Unknown,
                    format!(
                        "No complete match; {} allow rule(s) have conditions that can't be evaluated: {}",
                        maybe_allows.len(),
                        names(&maybe_allows)
                    ),
                );
            }
            steps.push(
                "Default action",
                StepStatus::Fail,
                format!("{profile} blocks {dir} traffic by default."),
            );
            if maybe_allows.is_empty() {
                finish(
                    Outcome::BlockedByDefault,
                    format!(
                        "No allow rule matches, and the {profile} profile blocks {dir} traffic by default."
                    ),
                    None,
                    steps,
                )
            } else {
                finish(
                    Outcome::Uncertain,
                    format!(
                        "No allow rule fully matches; {} could, depending on conditions that can't be evaluated. The {profile} default is Block.",
                        names(&maybe_allows)
                    ),
                    None,
                    steps,
                )
            }
        }
        Some(true) => {
            steps.push(
                "Allow rules",
                StepStatus::Skipped,
                "Not needed: the default action allows.",
            );
            steps.push(
                "Default action",
                StepStatus::Pass,
                format!("{profile} allows {dir} traffic by default."),
            );
            if maybe_blocks.is_empty() {
                finish(
                    Outcome::AllowedByDefault,
                    format!(
                        "No block rule matches, and the {profile} profile allows {dir} traffic by default."
                    ),
                    None,
                    steps,
                )
            } else {
                finish(
                    Outcome::Uncertain,
                    format!(
                        "The {profile} default allows this, but {} might block it.",
                        names(&maybe_blocks)
                    ),
                    None,
                    steps,
                )
            }
        }
        None => {
            steps.push("Allow rules", StepStatus::Unknown, "No allow rule matches.");
            steps.push(
                "Default action",
                StepStatus::Unknown,
                format!("The {profile} default {dir} action couldn't be read."),
            );
            finish(
                Outcome::Uncertain,
                format!(
                    "No rule decides this and the {profile} default action couldn't be read."
                ),
                None,
                steps,
            )
        }
    }
}

fn headline_for(p: &ProfileVerdict, s: &Scenario) -> String {
    let dir = s.direction.to_string().to_lowercase();
    match p.outcome {
        Outcome::Allowed => "Likely allowed by a matching rule".into(),
        Outcome::AllowedByDefault => format!(
            "Likely allowed: {} allows {dir} traffic by default",
            p.profile
        ),
        Outcome::Blocked if p.deciding_rule.is_some() => {
            "Likely blocked by a matching block rule".into()
        }
        Outcome::Blocked => format!(
            "Likely blocked: {} blocks all incoming connections",
            p.profile
        ),
        Outcome::BlockedByDefault => format!(
            "Likely blocked: no allow rule matches and {} blocks {dir} by default",
            p.profile
        ),
        Outcome::NotFiltered => format!(
            "Not filtered: the firewall is off for the {} profile",
            p.profile
        ),
        Outcome::Uncertain => "Can't tell from configuration alone".into(),
        Outcome::Unavailable => "Firewall profile settings unavailable".into(),
    }
}

/// `rules` is the analysis shortlist (sorted by priority) used to name the
/// closest identity-linked allow rule.
pub fn verdict(
    s: &Scenario,
    data: &DiagnosticData,
    candidates: &[String],
    rules: &[Evaluation],
    confirmed_block: bool,
    confirmed_permit: bool,
) -> Verdict {
    let mut assumptions = vec![format!(
        "Direction is {}; the scenario {}.",
        s.direction,
        if s.hypothetical {
            "contains supplied or assumed values"
        } else {
            "is observed"
        }
    )];
    let names: Vec<String> = if candidates.is_empty() {
        assumptions.push(
            "The active firewall profile couldn't be determined, so every collected profile was checked."
                .into(),
        );
        let mut all: Vec<_> = data
            .policy
            .profiles
            .iter()
            .filter_map(|p| normalize_profile(&p.name))
            .collect();
        all.sort();
        all.dedup();
        all
    } else {
        if s.profile.is_none() {
            assumptions.push(format!(
                "Profile taken from the active interface(s): {}.",
                candidates.join(", ")
            ));
        }
        candidates.to_vec()
    };
    if !data.policy.complete {
        assumptions
            .push("Collected policy is partial; some rules could not be read completely.".into());
    }
    if s.remote.is_none() {
        assumptions.push(
            "No peer was given, so rules limited to certain remote addresses can't be decided."
                .into(),
        );
    }
    let profiles: Vec<_> = names.iter().map(|p| profile_verdict(p, s, data)).collect();
    let closest_rule = rules
        .iter()
        .find(|e| {
            e.result == Match::Mismatch
                && e.action.eq_ignore_ascii_case("Allow")
                && matches!(
                    e.relevance,
                    Some(Relevance::Application | Relevance::Service)
                )
        })
        .map(|e| e.rule_id.clone());

    let (mut outcome, mut headline, mut reason) = match profiles.first() {
        None => (
            Outcome::Unavailable,
            "Firewall profile settings unavailable".to_string(),
            "No firewall profile settings were collected.".to_string(),
        ),
        Some(first) if profiles.iter().all(|p| p.outcome == first.outcome) => (
            first.outcome,
            headline_for(first, s),
            profiles
                .iter()
                .map(|p| p.reason.as_str())
                .collect::<Vec<_>>()
                .join(" "),
        ),
        Some(_) => (
            Outcome::Uncertain,
            "Can't tell: the result depends on which firewall profile applies".to_string(),
            profiles
                .iter()
                .map(|p| format!("{}: {}.", p.profile, p.outcome.label()))
                .collect::<Vec<_>>()
                .join(" ")
                + " Choose the interface the traffic uses to narrow it down.",
        ),
    };
    let mut confirmed = false;
    if confirmed_block && confirmed_permit {
        outcome = Outcome::Uncertain;
        headline = "Windows recorded both a permit and a block for this traffic".into();
        reason = format!(
            "{reason} Recorded events disagree, so some attempts are being stopped; compare their peers and times."
        );
    } else if confirmed_block {
        confirmed = true;
        outcome = Outcome::Blocked;
        headline = "Blocked: Windows recorded a dropped connection".into();
        reason = format!(
            "A Security event for this process and tuple shows the Windows Filtering Platform blocked it. Configuration: {reason}"
        );
    } else if confirmed_permit {
        confirmed = true;
        outcome = Outcome::Allowed;
        headline = "Allowed: Windows recorded a permitted connection".into();
        reason = format!(
            "A Security event for this process and tuple shows the Windows Filtering Platform permitted it. Configuration: {reason}"
        );
    }
    let next = match outcome {
        Outcome::Blocked | Outcome::BlockedByDefault if closest_rule.is_some() => {
            "Open the closest rule to see which condition excludes this traffic."
        }
        Outcome::Blocked | Outcome::BlockedByDefault => {
            "Add or adjust an allow rule for this program and port, or check whether a block rule is intended."
        }
        Outcome::Allowed | Outcome::AllowedByDefault | Outcome::NotFiltered => {
            "The firewall is unlikely to be the cause; check the peer, routing and the application itself."
        }
        Outcome::Uncertain => {
            "Fill in the peer address and interface, or enable connection auditing and reproduce to get a recorded result."
        }
        Outcome::Unavailable => {
            "Collect diagnostics again, as administrator if profile settings can't be read."
        }
    }
    .into();
    Verdict {
        outcome,
        headline,
        reason,
        next,
        assumptions,
        confirmed,
        closest_rule,
        profiles,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::{rule, scenario};

    fn profile(name: &str, enabled: &str, inbound: &str, allow_inbound: &str) -> FirewallProfile {
        FirewallProfile {
            name: name.into(),
            enabled: enabled.into(),
            inbound: inbound.into(),
            outbound: "Allow".into(),
            allow_inbound_rules: allow_inbound.into(),
            allow_local_rules: "True".into(),
        }
    }
    fn data(rules: Vec<FirewallRule>, profiles: Vec<FirewallProfile>) -> DiagnosticData {
        DiagnosticData {
            policy: Policy {
                collected_ms: 1,
                rules,
                profiles,
                complete: true,
                ..Policy::default()
            },
            ..DiagnosticData::default()
        }
    }
    fn outcome(d: &DiagnosticData, s: &Scenario) -> Outcome {
        verdict(s, d, &candidate_profiles(s, d), &[], false, false).outcome
    }
    fn outside_peer() -> Scenario {
        let mut s = scenario();
        s.remote = Some("10.30.0.25:53000".parse().unwrap());
        s
    }

    #[test]
    fn no_allow_and_default_block_is_blocked_by_default() {
        let d = data(vec![rule()], vec![profile("Domain", "True", "Block", "True")]);
        let v = verdict(&outside_peer(), &d, &["Domain".into()], &[], false, false);
        assert_eq!(v.outcome, Outcome::BlockedByDefault);
        assert!(!v.confirmed);
        assert_eq!(
            v.profiles[0].steps.last().unwrap().status,
            StepStatus::Fail
        );
    }
    #[test]
    fn matching_allow_is_allowed() {
        let d = data(vec![rule()], vec![profile("Domain", "True", "Block", "True")]);
        assert_eq!(outcome(&d, &scenario()), Outcome::Allowed);
    }
    #[test]
    fn firewall_off_is_not_filtered_even_with_a_block_rule() {
        let mut r = rule();
        r.action = "Block".into();
        let d = data(vec![r], vec![profile("Domain", "False", "Block", "True")]);
        assert_eq!(outcome(&d, &scenario()), Outcome::NotFiltered);
    }
    #[test]
    fn block_all_incoming_overrides_matching_allow() {
        let d = data(vec![rule()], vec![profile("Domain", "True", "Block", "False")]);
        assert_eq!(outcome(&d, &scenario()), Outcome::Blocked);
        let mut s = scenario();
        s.direction = Direction::Outbound;
        // Outbound is unaffected by AllowInboundRules; default outbound Allow.
        assert_eq!(outcome(&d, &s), Outcome::AllowedByDefault);
    }
    #[test]
    fn block_rule_wins_over_allow() {
        let mut b = rule();
        b.id = "block".into();
        b.action = "Block".into();
        let d = data(vec![rule(), b], vec![profile("Domain", "True", "Block", "True")]);
        let v = verdict(&scenario(), &d, &["Domain".into()], &[], false, false);
        assert_eq!(v.outcome, Outcome::Blocked);
        assert_eq!(v.profiles[0].deciding_rule.as_deref(), Some("block"));
    }
    #[test]
    fn local_rules_ignored_when_merge_is_disabled() {
        let mut r = rule();
        r.source_type = "Local".into();
        let mut p = profile("Domain", "True", "Block", "True");
        p.allow_local_rules = "False".into();
        let d = data(vec![r], vec![p]);
        assert_eq!(outcome(&d, &scenario()), Outcome::BlockedByDefault);
    }
    #[test]
    fn unknown_allow_with_default_block_is_uncertain() {
        let mut r = rule();
        r.remote_addresses = vec!["LocalSubnet".into()];
        let d = data(vec![r], vec![profile("Domain", "True", "Block", "True")]);
        assert_eq!(outcome(&d, &scenario()), Outcome::Uncertain);
    }
    #[test]
    fn profile_comes_from_up_interfaces_and_disagreement_is_uncertain() {
        let mut d = data(
            vec![rule()],
            vec![
                profile("Domain", "True", "Block", "True"),
                profile("Public", "True", "Block", "True"),
            ],
        );
        let mut s = scenario();
        s.profile = None;
        d.interfaces = vec![Interface {
            profile: "DomainAuthenticated".into(),
            status: "Up".into(),
            ..Interface::default()
        }];
        assert_eq!(candidate_profiles(&s, &d), vec!["Domain".to_string()]);
        assert_eq!(outcome(&d, &s), Outcome::Allowed);
        d.interfaces.push(Interface {
            profile: "Public".into(),
            status: "Up".into(),
            ..Interface::default()
        });
        // The rule is Domain-only, so Public blocks by default.
        assert_eq!(outcome(&d, &s), Outcome::Uncertain);
    }
    #[test]
    fn recorded_events_override_configuration() {
        let d = data(vec![rule()], vec![profile("Domain", "True", "Block", "True")]);
        let v = verdict(&scenario(), &d, &["Domain".into()], &[], true, false);
        assert_eq!((v.outcome, v.confirmed), (Outcome::Blocked, true));
        let v = verdict(&scenario(), &d, &["Domain".into()], &[], true, true);
        assert_eq!((v.outcome, v.confirmed), (Outcome::Uncertain, false));
    }
    #[test]
    fn not_configured_uses_windows_defaults() {
        let d = data(
            vec![],
            vec![profile("Domain", "NotConfigured", "NotConfigured", "NotConfigured")],
        );
        assert_eq!(outcome(&d, &scenario()), Outcome::BlockedByDefault);
    }
}
