//! Conservative static-condition matching, not a Windows Filtering Platform simulator.
use crate::model::*;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Match {
    Match,
    Mismatch,
    Unknown,
}
impl std::fmt::Display for Match {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    pub name: String,
    pub result: Match,
    pub detail: String,
    /// What the rule requires, as collected (empty for older saved analyses).
    #[serde(default)]
    pub rule_value: String,
    /// The examined traffic's value for this condition; empty when not applicable.
    #[serde(default)]
    pub traffic: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Relevance {
    Application,
    Service,
    Traffic,
    Uncertain,
}
impl Relevance {
    pub fn reason(self) -> &'static str {
        match self {
            Self::Application => {
                "The rule explicitly names this executable; its direction and protocol do not exclude the examined traffic."
            }
            Self::Service => {
                "The rule explicitly names the scenario service; that service identity is an assumption unless independently verified."
            }
            Self::Traffic => {
                "All evaluated conditions match this traffic, including rules that apply to any executable."
            }
            Self::Uncertain => {
                "No known condition excludes this traffic, but missing or unsupported conditions prevent a complete match. This is not a verified application-specific rule."
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evaluation {
    pub rule_id: String,
    pub rule_name: String,
    pub action: String,
    pub result: Match,
    pub conditions: Vec<Condition>,
    #[serde(default)]
    pub relevance: Option<Relevance>,
}

fn all(values: impl Iterator<Item = Match>) -> Match {
    let mut unknown = false;
    for v in values {
        match v {
            Match::Mismatch => return Match::Mismatch,
            Match::Unknown => unknown = true,
            _ => {}
        }
    }
    if unknown {
        Match::Unknown
    } else {
        Match::Match
    }
}
fn any(values: impl Iterator<Item = Match>) -> Match {
    let mut unknown = false;
    let mut count = 0;
    for v in values {
        count += 1;
        match v {
            Match::Match => return Match::Match,
            Match::Unknown => unknown = true,
            _ => {}
        }
    }
    if unknown || count == 0 {
        Match::Unknown
    } else {
        Match::Mismatch
    }
}
fn unrestricted(s: &str) -> bool {
    s.eq_ignore_ascii_case("Any") || s == "*"
}
fn eq(a: &str, b: &str) -> Match {
    if a.eq_ignore_ascii_case(b) {
        Match::Match
    } else {
        Match::Mismatch
    }
}
fn list(values: &[String], actual: Option<&str>) -> Match {
    any(values.iter().map(|v| {
        if unrestricted(v) {
            Match::Match
        } else {
            actual.map_or(Match::Unknown, |a| eq(v, a))
        }
    }))
}
pub fn normalize_path(path: &str) -> Option<String> {
    let path = path.trim().trim_matches('"').replace('/', "\\");
    if path.contains('%')
        || path.contains('*')
        || path.to_lowercase().starts_with("\\device\\")
        || path.is_empty()
        || path.contains('~')
        || path.split('\\').any(|part| part == "." || part == "..")
    {
        None
    } else {
        Some(path.strip_prefix("\\\\?\\").unwrap_or(&path).to_lowercase())
    }
}
fn program(values: &[String], actual: Option<&str>) -> Match {
    any(values.iter().map(|v| {
        if unrestricted(v) {
            Match::Match
        } else {
            match (normalize_path(v), actual.and_then(normalize_path)) {
                (Some(v), Some(a)) => eq(&v, &a),
                _ => Match::Unknown,
            }
        }
    }))
}
pub fn port_match(pattern: &str, port: Option<u16>) -> Match {
    if unrestricted(pattern) {
        return Match::Match;
    }
    let Some(port) = port else {
        return Match::Unknown;
    };
    if let Ok(p) = pattern.parse::<u16>() {
        return if port == p {
            Match::Match
        } else {
            Match::Mismatch
        };
    }
    if let Some((a, b)) = pattern.split_once('-')
        && let (Ok(a), Ok(b)) = (a.parse::<u16>(), b.parse::<u16>())
        && a <= b
    {
        return if (a..=b).contains(&port) {
            Match::Match
        } else {
            Match::Mismatch
        };
    }
    Match::Unknown
}
fn ip_value(ip: IpAddr) -> (u128, u32) {
    match ip {
        IpAddr::V4(a) => (u32::from(a) as u128, 32),
        IpAddr::V6(a) => (u128::from(a), 128),
    }
}
pub fn address_match(pattern: &str, address: Option<IpAddr>) -> Match {
    if unrestricted(pattern) {
        return Match::Match;
    }
    let Some(address) = address.filter(|ip| !ip.is_unspecified()) else {
        return Match::Unknown;
    };
    let (value, bits) = ip_value(address);
    if let Ok(ip) = pattern.parse::<IpAddr>() {
        return if ip == address {
            Match::Match
        } else {
            Match::Mismatch
        };
    }
    if let Some((network, prefix)) = pattern.split_once('/')
        && let (Ok(network), Ok(prefix)) = (network.parse::<IpAddr>(), prefix.parse::<u32>())
    {
        let (network, nbits) = ip_value(network);
        if nbits != bits {
            return Match::Mismatch;
        }
        if prefix > bits {
            return Match::Unknown;
        }
        let mask = if prefix == 0 {
            0
        } else {
            u128::MAX << (bits - prefix)
        };
        return if value & mask == network & mask {
            Match::Match
        } else {
            Match::Mismatch
        };
    }
    if let Some((a, b)) = pattern.split_once('-')
        && let (Ok(a), Ok(b)) = (a.parse::<IpAddr>(), b.parse::<IpAddr>())
    {
        let (a, abits) = ip_value(a);
        let (b, bbits) = ip_value(b);
        if abits != bbits || a > b {
            return Match::Unknown;
        }
        return if bits == abits && (a..=b).contains(&value) {
            Match::Match
        } else {
            Match::Mismatch
        };
    }
    Match::Unknown
}

pub fn evaluate(rule: &FirewallRule, scenario: &Scenario) -> Evaluation {
    let mut conditions = Vec::new();
    let mut add = |name: &str, result: Match, rule_value: String, traffic: String| {
        conditions.push(Condition {
            name: name.into(),
            result,
            detail: if traffic.is_empty() {
                rule_value.clone()
            } else {
                format!("{rule_value}; examined {traffic}")
            },
            rule_value,
            traffic,
        })
    };
    let or_unknown = |v: Option<&str>, unknown: &str| v.unwrap_or(unknown).to_string();
    add(
        "Enabled",
        if rule.enabled {
            Match::Match
        } else {
            Match::Mismatch
        },
        if rule.enabled { "Yes" } else { "No" }.into(),
        String::new(),
    );
    add(
        "Direction",
        if rule.direction.is_empty() {
            Match::Unknown
        } else {
            eq(&rule.direction, &scenario.direction.to_string())
        },
        rule.direction.clone(),
        scenario.direction.to_string(),
    );
    add(
        "Program",
        program(&rule.program, scenario.program.as_deref()),
        rule.program.join(", "),
        or_unknown(scenario.program.as_deref(), "unavailable"),
    );
    add(
        "Service",
        list(&rule.service, scenario.service.as_deref()),
        rule.service.join(", "),
        or_unknown(scenario.service.as_deref(), "unverified"),
    );
    add(
        "Protocol",
        any(rule.protocol.iter().map(|p| {
            if unrestricted(p) || p == "256" {
                Match::Match
            } else if let Ok(n) = p.parse::<u32>() {
                eq(
                    &n.to_string(),
                    match scenario.protocol {
                        Protocol::Tcp => "6",
                        Protocol::Udp => "17",
                    },
                )
            } else {
                eq(p, &scenario.protocol.to_string())
            }
        })),
        rule.protocol.join(", "),
        scenario.protocol.to_string(),
    );
    add(
        "Local port",
        any(rule
            .local_ports
            .iter()
            .map(|p| port_match(p, Some(scenario.local.port())))),
        rule.local_ports.join(", "),
        scenario.local.port().to_string(),
    );
    add(
        "Remote port",
        any(rule
            .remote_ports
            .iter()
            .map(|p| port_match(p, scenario.remote.map(|a| a.port())))),
        rule.remote_ports.join(", "),
        scenario
            .remote
            .map(|a| a.port().to_string())
            .unwrap_or_else(|| "unknown peer".into()),
    );
    add(
        "Local address",
        any(rule
            .local_addresses
            .iter()
            .map(|a| address_match(a, Some(scenario.local.ip())))),
        rule.local_addresses.join(", "),
        scenario.local.ip().to_string(),
    );
    add(
        "Remote address",
        any(rule
            .remote_addresses
            .iter()
            .map(|a| address_match(a, scenario.remote.map(|r| r.ip())))),
        rule.remote_addresses.join(", "),
        scenario
            .remote
            .map(|r| r.to_string())
            .unwrap_or_else(|| "unknown peer".into()),
    );
    add(
        "Profile",
        list(&rule.profiles, scenario.profile.as_deref()),
        rule.profiles.join(", "),
        or_unknown(scenario.profile.as_deref(), "unknown"),
    );
    add(
        "Interface",
        list(&rule.interfaces, scenario.interface.as_deref()),
        rule.interfaces.join(", "),
        or_unknown(scenario.interface.as_deref(), "unknown"),
    );
    add(
        "Interface type",
        list(&rule.interface_types, scenario.interface_type.as_deref()),
        rule.interface_types.join(", "),
        or_unknown(scenario.interface_type.as_deref(), "unknown"),
    );
    add(
        "Coverage",
        if rule.complete
            && rule.unsupported.is_empty()
            && (rule.enforcement.is_empty()
                || rule.enforcement == "Full"
                || rule.enforcement == "NotApplicable")
        {
            Match::Match
        } else {
            Match::Unknown
        },
        if !rule.complete {
            "Associated filters incomplete".into()
        } else if rule.unsupported.is_empty() {
            format!(
                "No advanced conditions; enforcement {}",
                if rule.enforcement.is_empty() {
                    "not reported"
                } else {
                    &rule.enforcement
                }
            )
        } else {
            format!(
                "{}; enforcement status {}",
                rule.unsupported.join("; "),
                rule.enforcement
            )
        },
        String::new(),
    );
    let result = all(conditions.iter().map(|c| c.result));
    let condition = |name: &str| conditions.iter().find(|c| c.name == name).unwrap().result;
    let explicit_program = !rule.program.is_empty()
        && rule.program.iter().all(|p| !unrestricted(p))
        && condition("Program") == Match::Match;
    let explicit_service = !rule.service.is_empty()
        && rule.service.iter().all(|p| !unrestricted(p))
        && condition("Service") == Match::Match;
    let relevance = if !rule.enabled
        || ["Program", "Direction", "Protocol"]
            .iter()
            .any(|n| condition(n) == Match::Mismatch)
    {
        None
    } else if explicit_program {
        Some(Relevance::Application)
    } else if explicit_service {
        Some(Relevance::Service)
    } else if result == Match::Match {
        Some(Relevance::Traffic)
    } else if result == Match::Unknown {
        Some(Relevance::Uncertain)
    } else {
        None
    };

    Evaluation {
        rule_id: rule.id.clone(),
        rule_name: rule.name.clone(),
        action: rule.action.clone(),
        result,
        conditions,
        relevance,
    }
}

/// Shortlist traffic candidates and identity-backed near matches, never the
/// unrelated direction/protocol/program rules in the full policy browser.
pub fn relevant(rule: &FirewallRule, s: &Scenario) -> bool {
    evaluate(rule, s).relevance.is_some()
}

/// Stable ordering puts supported matching blocks/allows first, useful identity
/// near matches next, and unreadable/unsupported candidates last.
pub fn priority(e: &Evaluation) -> (u8, usize, &str) {
    let rank = match (e.result, e.relevance) {
        (Match::Match, _) if e.action.eq_ignore_ascii_case("Block") => 0,
        (Match::Match, _) => 1,
        (_, Some(Relevance::Application | Relevance::Service)) => 2,
        _ => 3,
    };
    (
        rank,
        e.conditions
            .iter()
            .filter(|c| c.result == Match::Mismatch)
            .count(),
        &e.rule_id,
    )
}

#[cfg(test)]
pub fn rule() -> FirewallRule {
    FirewallRule {
        id: "rule-1".into(),
        name: "IFC8 inbound".into(),
        enabled: true,
        action: "Allow".into(),
        direction: "Inbound".into(),
        profiles: vec!["Domain".into()],
        program: vec!["C:\\Opera\\IFC8.exe".into()],
        service: vec!["Any".into()],
        protocol: vec!["TCP".into()],
        local_ports: vec!["5001".into()],
        remote_ports: vec!["Any".into()],
        local_addresses: vec!["Any".into()],
        remote_addresses: vec!["10.20.0.0/24".into()],
        interfaces: vec!["Any".into()],
        interface_types: vec!["Any".into()],
        complete: true,
        ..FirewallRule::default()
    }
}
#[cfg(test)]
pub fn scenario() -> Scenario {
    Scenario {
        direction: Direction::Inbound,
        protocol: Protocol::Tcp,
        local: "10.20.0.10:5001".parse().unwrap(),
        remote: Some("10.20.0.25:53000".parse().unwrap()),
        program: Some("c:/opera/ifc8.EXE".into()),
        service: None,
        profile: Some("Domain".into()),
        interface: None,
        interface_type: None,
        hypothetical: true,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ifc8_scope_mismatch_is_explainable() {
        let r = rule();
        let mut s = scenario();
        assert_eq!(evaluate(&r, &s).result, Match::Match);
        s.remote = Some("10.30.0.25:53000".parse().unwrap());
        let e = evaluate(&r, &s);
        assert_eq!(e.result, Match::Mismatch);
        assert_eq!(
            e.conditions
                .iter()
                .filter(|c| c.result == Match::Mismatch)
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>(),
            vec!["Remote address"]
        );
    }
    #[test]
    fn service_hosting_does_not_invalidate_program_rule() {
        let mut s = scenario();
        s.service = Some("OperaInterface".into());
        assert_eq!(evaluate(&rule(), &s).result, Match::Match);
        let mut r = rule();
        r.service = vec!["OtherService".into()];
        assert_eq!(evaluate(&r, &s).result, Match::Mismatch);
        s.service = None;
        assert_eq!(evaluate(&r, &s).result, Match::Unknown);
    }
    #[test]
    fn unknown_conditions_prevent_complete_match() {
        for field in 0..4 {
            let mut r = rule();
            match field {
                0 => r.complete = false,
                1 => r.unsupported.push("IPsec".into()),
                2 => r.local_ports = vec!["RPC".into()],
                _ => r.program.clear(),
            };
            assert_eq!(evaluate(&r, &scenario()).result, Match::Unknown);
        }
    }
    #[test]
    fn dimension_mismatches() {
        for i in 0..7 {
            let mut s = scenario();
            let mut r = rule();
            match i {
                0 => s.direction = Direction::Outbound,
                1 => s.protocol = Protocol::Udp,
                2 => s.profile = Some("Public".into()),
                3 => s.program = Some("C:\\Other.exe".into()),
                4 => r.enabled = false,
                5 => r.interfaces = vec!["Wi-Fi".into()],
                _ => r.remote_ports = vec!["80".into()],
            };
            let e = evaluate(&r, &s);
            assert_eq!(
                e.result,
                if i == 5 {
                    Match::Unknown
                } else {
                    Match::Mismatch
                }
            );
        }
    }
    #[test]
    fn port_ranges_and_dynamic_tokens() {
        for (s, p, m) in [
            ("Any", None, Match::Match),
            ("50-60", Some(50), Match::Match),
            ("50-60", Some(61), Match::Mismatch),
            ("60-50", Some(55), Match::Unknown),
            ("RPC", Some(135), Match::Unknown),
            ("65536", Some(0), Match::Unknown),
            ("5001", None, Match::Unknown),
        ] {
            assert_eq!(port_match(s, p), m);
        }
    }
    #[test]
    fn addresses_cover_v4_v6_ranges_and_unknowns() {
        for (s, ip, m) in [
            ("10.0.0.0/8", "10.1.2.3", Match::Match),
            ("0.0.0.0/0", "192.0.2.1", Match::Match),
            ("10.0.0.1-10.0.0.3", "10.0.0.4", Match::Mismatch),
            ("::/0", "2001:db8::1", Match::Match),
            ("2001:db8::/32", "2001:db9::1", Match::Mismatch),
            ("::1/129", "::1", Match::Unknown),
            ("LocalSubnet", "10.1.2.3", Match::Unknown),
            ("::/0", "10.1.2.3", Match::Mismatch),
            ("10.0.0.0/8", "0.0.0.0", Match::Unknown),
        ] {
            assert_eq!(address_match(s, Some(ip.parse().unwrap())), m, "{s} {ip}");
        }
    }
    #[test]
    fn unknown_program_or_profile_not_false_mismatch() {
        let mut s = scenario();
        s.program = None;
        s.profile = None;
        assert_eq!(evaluate(&rule(), &s).result, Match::Unknown);
    }
    #[test]
    fn paths_are_not_basename_matches() {
        assert_eq!(normalize_path("%x%\\a.exe"), None);
        assert_eq!(normalize_path("\\Device\\HarddiskVolume1\\a.exe"), None);
        let mut s = scenario();
        s.program = Some("D:\\Opera\\IFC8.exe".into());
        assert_eq!(evaluate(&rule(), &s).result, Match::Mismatch);
    }
    #[test]
    fn candidate_filter_keeps_broad_block_and_program_near_matches() {
        let mut r = rule();
        r.local_ports = vec!["9999".into()];
        assert!(relevant(&r, &scenario()));
        r.program = vec!["Any".into()];
        assert!(!relevant(&r, &scenario()));
        r.local_ports = vec!["Any".into()];
        r.action = "Block".into();
        assert!(relevant(&r, &scenario()));
    }
    #[test]
    fn unrelated_direction_protocol_program_and_broad_scope_are_not_shortlisted() {
        let s = scenario();
        for dimension in 0..4 {
            let mut r = rule();
            r.program = vec!["Any".into()];
            match dimension {
                0 => r.direction = "Outbound".into(),
                1 => r.protocol = vec!["UDP".into()],
                2 => r.program = vec!["C:\\Other.exe".into()],
                _ => r.remote_addresses = vec!["192.0.2.0/24".into()],
            }
            assert_eq!(evaluate(&r, &s).relevance, None, "dimension {dimension}");
        }
    }
    #[test]
    fn identity_link_is_positive_not_guessed_from_unknown_paths() {
        let mut r = rule();
        r.local_ports = vec!["9999".into()];
        assert_eq!(
            evaluate(&r, &scenario()).relevance,
            Some(Relevance::Application)
        );
        r.program = vec!["%UNKNOWN%\\IFC8.exe".into()];
        assert_eq!(evaluate(&r, &scenario()).relevance, None);
        r.local_ports = vec!["5001".into()];
        assert_eq!(
            evaluate(&r, &scenario()).relevance,
            Some(Relevance::Uncertain)
        );
        let mut s = scenario();
        s.program = None;
        r = rule();
        assert_eq!(evaluate(&r, &s).relevance, Some(Relevance::Uncertain));
    }
    #[test]
    fn specific_service_requires_a_known_scenario_identity() {
        let mut r = rule();
        r.program = vec!["Any".into()];
        r.service = vec!["OperaService".into()];
        r.local_ports = vec!["9999".into()];
        let mut s = scenario();
        assert_eq!(evaluate(&r, &s).relevance, None);
        s.service = Some("OperaService".into());
        assert_eq!(evaluate(&r, &s).relevance, Some(Relevance::Service));
    }
    #[test]
    fn broad_matching_blocks_survive_and_disabled_rules_do_not() {
        let mut r = rule();
        r.program = vec!["Any".into()];
        r.action = "Block".into();
        let block = evaluate(&r, &scenario());
        assert_eq!(block.relevance, Some(Relevance::Traffic));
        r.action = "Allow".into();
        assert!(priority(&block) < priority(&evaluate(&r, &scenario())));
        r.enabled = false;
        assert_eq!(evaluate(&r, &scenario()).relevance, None);
    }
}
