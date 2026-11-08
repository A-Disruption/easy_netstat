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
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evaluation {
    pub rule_id: String,
    pub rule_name: String,
    pub action: String,
    pub result: Match,
    pub conditions: Vec<Condition>,
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
    let mut add = |name: &str, result: Match, detail: String| {
        conditions.push(Condition {
            name: name.into(),
            result,
            detail,
        })
    };
    add(
        "Enabled",
        if rule.enabled {
            Match::Match
        } else {
            Match::Mismatch
        },
        rule.enabled.to_string(),
    );
    add(
        "Direction",
        if rule.direction.is_empty() {
            Match::Unknown
        } else {
            eq(&rule.direction, &scenario.direction.to_string())
        },
        format!("{}; examined {}", rule.direction, scenario.direction),
    );
    add(
        "Program",
        program(&rule.program, scenario.program.as_deref()),
        format!(
            "{}; examined {}",
            rule.program.join(", "),
            scenario.program.as_deref().unwrap_or("unavailable")
        ),
    );
    add(
        "Service",
        list(&rule.service, scenario.service.as_deref()),
        format!(
            "{}; socket service {}",
            rule.service.join(", "),
            scenario.service.as_deref().unwrap_or("unverified")
        ),
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
    );
    add(
        "Local port",
        any(rule
            .local_ports
            .iter()
            .map(|p| port_match(p, Some(scenario.local.port())))),
        format!(
            "{}; examined {}",
            rule.local_ports.join(", "),
            scenario.local.port()
        ),
    );
    add(
        "Remote port",
        any(rule
            .remote_ports
            .iter()
            .map(|p| port_match(p, scenario.remote.map(|a| a.port())))),
        rule.remote_ports.join(", "),
    );
    add(
        "Local address",
        any(rule
            .local_addresses
            .iter()
            .map(|a| address_match(a, Some(scenario.local.ip())))),
        format!(
            "{}; examined {}",
            rule.local_addresses.join(", "),
            scenario.local.ip()
        ),
    );
    add(
        "Remote address",
        any(rule
            .remote_addresses
            .iter()
            .map(|a| address_match(a, scenario.remote.map(|r| r.ip())))),
        format!(
            "{}; examined {}",
            rule.remote_addresses.join(", "),
            scenario
                .remote
                .map(|r| r.to_string())
                .unwrap_or_else(|| "unknown peer".into())
        ),
    );
    add(
        "Profile",
        list(&rule.profiles, scenario.profile.as_deref()),
        format!(
            "{}; examined {}",
            rule.profiles.join(", "),
            scenario.profile.as_deref().unwrap_or("unknown")
        ),
    );
    add(
        "Interface",
        list(&rule.interfaces, scenario.interface.as_deref()),
        rule.interfaces.join(", "),
    );
    add(
        "Interface type",
        list(&rule.interface_types, scenario.interface_type.as_deref()),
        rule.interface_types.join(", "),
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
        } else {
            format!(
                "{}; enforcement status {}",
                rule.unsupported.join("; "),
                rule.enforcement
            )
        },
    );
    let result = all(conditions.iter().map(|c| c.result));
    Evaluation {
        rule_id: rule.id.clone(),
        rule_name: rule.name.clone(),
        action: rule.action.clone(),
        result,
        conditions,
    }
}

/// Broad candidates (including unknown predicates) are always retained. A
/// program-specific near match is retained to explain other mismatching fields.
pub fn relevant(rule: &FirewallRule, s: &Scenario) -> bool {
    if !rule.enabled {
        return false;
    }
    let p = program(&rule.program, s.program.as_deref());
    if p == Match::Mismatch {
        return false;
    }
    let ports = any(rule
        .local_ports
        .iter()
        .map(|p| port_match(p, Some(s.local.port()))));
    ports != Match::Mismatch || rule.program.iter().any(|p| !unrestricted(p))
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
}
