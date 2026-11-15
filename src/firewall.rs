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
fn program(values: &[String], actual: Option<&str>, pid: Option<u32>) -> Match {
    any(values.iter().map(|v| {
        if unrestricted(v) {
            Match::Match
        } else if v.trim().eq_ignore_ascii_case("System") {
            match pid {
                Some(4) => Match::Match,
                Some(_) => Match::Mismatch,
                None => Match::Unknown,
            }
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
    let address = address.map(|ip| match ip {
        IpAddr::V6(v6) => v6.to_canonical(),
        v4 => v4,
    });
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

/// Resolves Windows Firewall address keywords against collected network
/// context before falling back to literal addresses, ranges and prefixes.
pub fn address_keyword_match(
    pattern: &str,
    address: Option<IpAddr>,
    net: &NetworkContext,
) -> Match {
    if unrestricted(pattern) {
        return Match::Match;
    }
    let key = pattern.trim().to_ascii_lowercase();
    let family = |name: &str| match key.strip_prefix(name) {
        Some("") => Some(None),
        Some("4") => Some(Some(true)),
        Some("6") => Some(Some(false)),
        _ => None,
    };
    let list: Option<(&[IpAddr], Option<bool>)> = if let Some(f) = family("dns") {
        Some((&net.dns, f))
    } else if let Some(f) = family("dhcp") {
        Some((&net.dhcp, f))
    } else if let Some(f) = family("wins") {
        Some((&net.wins, f))
    } else if let Some(f) = family("defaultgateway") {
        Some((&net.gateways, f))
    } else {
        None
    };
    let address = address.map(|ip| match ip {
        IpAddr::V6(v6) => v6.to_canonical(),
        v4 => v4,
    });
    let family_ok = |ip: IpAddr, f: Option<bool>| f.is_none_or(|v4| ip.is_ipv4() == v4);
    if let Some((values, f)) = list {
        let Some(ip) = address.filter(|_| net.known) else {
            return Match::Unknown;
        };
        return if family_ok(ip, f) && values.contains(&ip) {
            Match::Match
        } else {
            Match::Mismatch
        };
    }
    if let Some(f) = family("localsubnet") {
        let Some(ip) = address.filter(|_| net.known) else {
            return Match::Unknown;
        };
        if !family_ok(ip, f) {
            return Match::Mismatch;
        }
        return if net
            .subnets
            .iter()
            .any(|prefix| address_match(prefix, Some(ip)) == Match::Match)
        {
            Match::Match
        } else {
            Match::Mismatch
        };
    }
    // Internet, Intranet, IntranetRemoteAccess, PlayToDevice, CaptivePortal...
    // depend on network isolation or device state that isn't collected.
    if key.chars().all(|c| c.is_ascii_alphabetic()) {
        return Match::Unknown;
    }
    address_match(pattern, address)
}

/// Resolves port keywords; RPC endpoints are always dynamic ports.
pub fn port_keyword_match(pattern: &str, port: Option<u16>, net: &NetworkContext) -> Match {
    let key = pattern.trim().to_ascii_lowercase();
    let fixed = |wanted: u16| match port {
        Some(p) if p == wanted => Match::Match,
        Some(_) => Match::Mismatch,
        None => Match::Unknown,
    };
    match key.as_str() {
        "rpcepmap" => fixed(135),
        "mdns" => fixed(5353),
        // IP-HTTPS tunnels run over TCP 443; anything else can't be one.
        "iphttpsin" | "iphttpsout" => match fixed(443) {
            Match::Match => Match::Unknown,
            other => other,
        },
        // Dynamic RPC endpoints come from the ephemeral range; Windows' default
        // is 49152-65535 when the configured range wasn't collected.
        "rpc" => match port {
            None => Match::Unknown,
            Some(p) => {
                let (lo, hi) = net.dynamic_ports.unwrap_or((49152, 65535));
                if (lo..=hi).contains(&p) {
                    Match::Unknown
                } else {
                    Match::Mismatch
                }
            }
        },
        _ => port_match(pattern, port),
    }
}

/// Specific-service rules apply only to processes hosting that service.
fn service_match(values: &[String], s: &Scenario) -> Match {
    if values.is_empty() {
        return Match::Unknown;
    }
    // "*" means "services only", so only a literal Any is unrestricted here.
    if values.iter().any(|v| v.trim().eq_ignore_ascii_case("Any")) {
        return Match::Match;
    }
    if let Some(service) = s.service.as_deref() {
        return list(values, Some(service));
    }
    let Some(hosted) = &s.hosted_services else {
        return Match::Unknown;
    };
    if hosted.is_empty() {
        return Match::Mismatch;
    }
    // "*" means "any service": every hosted service qualifies.
    let wanted = |h: &String| values.iter().any(|v| v == "*" || v.eq_ignore_ascii_case(h));
    match hosted.iter().filter(|h| wanted(h)).count() {
        0 => Match::Mismatch,
        n if n == hosted.len() => Match::Match,
        // A shared host; which service owns the socket isn't known.
        _ => Match::Unknown,
    }
}

fn sid_eq(a: &str, b: &str) -> bool {
    a.trim().eq_ignore_ascii_case(b.trim())
}

/// SDDL two-letter aliases that appear in firewall LocalUser lists.
fn sddl_alias(alias: &str) -> Option<&'static str> {
    Some(match alias.to_ascii_uppercase().as_str() {
        "WD" => "S-1-1-0",
        "AU" => "S-1-5-11",
        "IU" => "S-1-5-4",
        "SU" => "S-1-5-6",
        "NU" => "S-1-5-2",
        "SY" => "S-1-5-18",
        "LS" => "S-1-5-19",
        "NS" => "S-1-5-20",
        "BA" => "S-1-5-32-544",
        "BU" => "S-1-5-32-545",
        "BG" => "S-1-5-32-546",
        "PU" => "S-1-5-32-547",
        "RD" => "S-1-5-32-555",
        "NO" => "S-1-5-32-556",
        "AC" => "S-1-15-2-1",
        _ => return None,
    })
}

/// Evaluates a LocalUser SDDL (for example `O:LSD:(A;;CC;;;S-1-5-21-...)`)
/// against the process token: a matching deny entry excludes, a matching
/// allow entry includes, and no match excludes.
pub fn local_user_match(sddl: &str, token: Option<&TokenIdentity>) -> Match {
    let sddl = sddl.trim();
    if sddl.is_empty() || unrestricted(sddl) {
        return Match::Match;
    }
    let Some(token) = token else {
        return Match::Unknown;
    };
    let Some(dacl) = sddl.find("D:").map(|i| &sddl[i + 2..]) else {
        return Match::Unknown;
    };
    let mut principals: Vec<&str> = std::iter::once(token.user_sid.as_str())
        .chain(token.groups.iter().map(String::as_str))
        .collect();
    if token.app_container_sid.is_some() {
        principals.push("S-1-15-2-1");
    }
    let (mut allowed, mut unresolved) = (false, false);
    for ace in dacl.split('(').skip(1) {
        let Some(ace) = ace.split(')').next() else {
            continue;
        };
        let fields: Vec<_> = ace.split(';').collect();
        if fields.len() < 6 {
            unresolved = true;
            continue;
        }
        let sid = if fields[5].starts_with("S-") {
            Some(fields[5])
        } else {
            sddl_alias(fields[5])
        };
        let Some(sid) = sid else {
            unresolved = true;
            continue;
        };
        match fields[0] {
            "D" => {
                let deny_set = principals
                    .iter()
                    .copied()
                    .chain(token.deny_only.iter().map(String::as_str));
                if deny_set.into_iter().any(|p| sid_eq(p, sid)) {
                    return Match::Mismatch;
                }
            }
            "A" => allowed |= principals.iter().any(|p| sid_eq(p, sid)),
            _ => unresolved = true,
        }
    }
    if allowed {
        Match::Match
    } else if unresolved {
        Match::Unknown
    } else {
        Match::Mismatch
    }
}

/// Owner SID (per-user and AppContainer rules) against the token user.
fn owner_match(owner: &str, token: Option<&TokenIdentity>) -> Match {
    if owner.trim().is_empty() || unrestricted(owner) {
        return Match::Match;
    }
    match token {
        Some(t) if sid_eq(&t.user_sid, owner) => Match::Match,
        Some(_) => Match::Mismatch,
        None => Match::Unknown,
    }
}

/// AppContainer package SID against the token's AppContainer, if any.
fn package_match(package: &str, token: Option<&TokenIdentity>) -> Match {
    if package.trim().is_empty() || unrestricted(package) {
        return Match::Match;
    }
    match token {
        None => Match::Unknown,
        Some(t) => match &t.app_container_sid {
            Some(sid) if package == "*" || sid_eq(sid, package) => Match::Match,
            _ => Match::Mismatch,
        },
    }
}

/// `EnforcementStatus` lists one state per filter/profile, e.g.
/// "ProfileInactive Enforced Enforced". Windows installs no filter for a rule
/// that is OptimizedOut or whose keyword resolved to nothing (NoRemoteAddress,
/// NoLocalPort, ...), so such a rule has no effect on traffic.
pub fn enforcement_match(status: &str) -> (Match, String) {
    let states: Vec<&str> = status.split_whitespace().collect();
    if states.is_empty() {
        return (Match::Match, "Not reported".into());
    }
    let enforced = |s: &str| matches!(s, "Enforced" | "Full" | "NotApplicable");
    let neutral = |s: &str| {
        matches!(
            s,
            "ProfileInactive" | "InactiveProfile" | "Disabled" | "DisabledObject"
        )
    };
    let absent = |s: &str| {
        s.starts_with("No") && s != "NotApplicable"
            || matches!(
                s,
                "OptimizedOut" | "Invalid" | "FirewallOffInProfile" | "CategoryOff"
            )
            || s.ends_with("ResolutionEmpty")
            || s.ends_with("Empty")
            || s.ends_with("Disallowed")
    };
    if states.iter().any(|s| enforced(s)) {
        (Match::Match, format!("Enforced ({status})"))
    } else if states.iter().all(|s| neutral(s)) {
        (
            Match::Match,
            format!("Not enforced in inactive profiles only ({status})"),
        )
    } else if states.iter().all(|s| neutral(s) || absent(s)) {
        let why = states.iter().find(|s| absent(s)).copied().unwrap_or("");
        (
            Match::Mismatch,
            match why {
                "OptimizedOut" => "Optimized out by Windows; the rule has no effect".into(),
                w if w.starts_with("No") => format!(
                    "Not enforced: {} resolved to nothing ({status})",
                    w.trim_start_matches("No").to_lowercase()
                ),
                _ => format!("Not enforced ({status})"),
            },
        )
    } else {
        (
            Match::Unknown,
            format!("Unrecognized enforcement status: {status}"),
        )
    }
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
        program(&rule.program, scenario.program.as_deref(), scenario.pid),
        rule.program.join(", "),
        or_unknown(scenario.program.as_deref(), "unavailable"),
    );
    add(
        "Service",
        service_match(&rule.service, scenario),
        rule.service.join(", "),
        match (&scenario.service, &scenario.hosted_services) {
            (Some(s), _) => s.clone(),
            (None, Some(h)) if h.is_empty() => "no services hosted".into(),
            (None, Some(h)) => format!("hosts {}", h.join(", ")),
            (None, None) => "unverified".into(),
        },
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
            .map(|p| port_keyword_match(p, Some(scenario.local.port()), &scenario.network))),
        rule.local_ports.join(", "),
        scenario.local.port().to_string(),
    );
    add(
        "Remote port",
        any(rule
            .remote_ports
            .iter()
            .map(|p| port_keyword_match(p, scenario.remote.map(|a| a.port()), &scenario.network))),
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
            .map(|a| address_keyword_match(a, Some(scenario.local.ip()), &scenario.network))),
        rule.local_addresses.join(", "),
        scenario.local.ip().to_string(),
    );
    add(
        "Remote address",
        any(rule
            .remote_addresses
            .iter()
            .map(|a| address_keyword_match(a, scenario.remote.map(|r| r.ip()), &scenario.network))),
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
    let user = scenario
        .token
        .as_ref()
        .map(|t| t.user_sid.clone())
        .unwrap_or_else(|| "unknown".into());
    add(
        "Owner",
        owner_match(&rule.owner, scenario.token.as_ref()),
        if rule.owner.is_empty() {
            "Any".into()
        } else {
            rule.owner.clone()
        },
        user.clone(),
    );
    add(
        "Package",
        package_match(&rule.package, scenario.token.as_ref()),
        if rule.package.is_empty() {
            "Any".into()
        } else {
            rule.package.clone()
        },
        match scenario.token.as_ref() {
            Some(t) => t
                .app_container_sid
                .clone()
                .unwrap_or_else(|| "not an app container".into()),
            None => "unknown".into(),
        },
    );
    add(
        "Local user",
        local_user_match(&rule.local_user, scenario.token.as_ref()),
        if rule.local_user.is_empty() {
            "Any".into()
        } else {
            rule.local_user.clone()
        },
        user,
    );
    let (enforced, enforcement_detail) = enforcement_match(&rule.enforcement);
    add("Enforcement", enforced, enforcement_detail, String::new());
    add(
        "Advanced",
        if rule.complete && rule.unsupported.is_empty() {
            Match::Match
        } else {
            Match::Unknown
        },
        if !rule.complete {
            "Associated filters incomplete".into()
        } else if rule.unsupported.is_empty() {
            "None".into()
        } else {
            rule.unsupported.join("; ")
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
        pid: Some(42),
        token: None,
        hosted_services: None,
        network: NetworkContext::default(),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn token(user: &str) -> TokenIdentity {
        TokenIdentity {
            user_sid: user.into(),
            groups: vec!["S-1-1-0".into(), "S-1-5-11".into(), "S-1-5-32-545".into()],
            deny_only: vec!["S-1-5-32-544".into()],
            app_container_sid: None,
        }
    }
    const ME: &str = "S-1-5-21-1-2-3-1001";
    const SANDBOX: &str = "S-1-5-21-1-2-3-1011";

    #[test]
    fn enforcement_status_lists_are_understood() {
        for (status, m) in [
            ("", Match::Match),
            ("Enforced Enforced Enforced", Match::Match),
            ("ProfileInactive Enforced", Match::Match),
            ("ProfileInactive", Match::Match),
            ("Disabled", Match::Match),
            ("OptimizedOut", Match::Mismatch),
            ("NoRemoteAddress NoRemoteAddress", Match::Mismatch),
            (
                "ProfileInactive NoDynamicTransport NoDynamicTransport",
                Match::Mismatch,
            ),
            (
                "ProfileInactive NoRemoteAddress Enforced Enforced",
                Match::Match,
            ),
            ("SomethingNew", Match::Unknown),
        ] {
            assert_eq!(enforcement_match(status).0, m, "{status}");
        }
        assert!(enforcement_match("OptimizedOut").1.contains("no effect"));
    }
    #[test]
    fn local_user_sddl_allows_denies_and_resolves_aliases() {
        let me = token(ME);
        let sddl = |aces: &str| format!("O:LSD:{aces}");
        assert_eq!(local_user_match("", Some(&me)), Match::Match);
        assert_eq!(
            local_user_match(&sddl(&format!("(A;;CC;;;{SANDBOX})")), Some(&me)),
            Match::Mismatch
        );
        assert_eq!(
            local_user_match(&sddl(&format!("(A;;CC;;;{ME})")), Some(&me)),
            Match::Match
        );
        assert_eq!(
            local_user_match(&sddl("(A;;CC;;;AU)"), Some(&me)),
            Match::Match
        );
        assert_eq!(
            local_user_match(&sddl("(A;;CC;;;BA)"), Some(&me)),
            Match::Mismatch
        );
        // A deny-only Administrators group still matches a deny entry.
        assert_eq!(
            local_user_match(&sddl("(A;;CC;;;WD)(D;;CC;;;BA)"), Some(&me)),
            Match::Mismatch
        );
        assert_eq!(
            local_user_match(&sddl("(A;;CC;;;ZZ)"), Some(&me)),
            Match::Unknown
        );
        assert_eq!(
            local_user_match(&sddl(&format!("(A;;CC;;;{ME})")), None),
            Match::Unknown
        );
    }
    #[test]
    fn sandbox_user_block_rule_does_not_apply_to_other_users() {
        let mut r = rule();
        r.action = "Block".into();
        r.direction = "Outbound".into();
        r.program = vec!["Any".into()];
        r.protocol = vec!["Any".into()];
        r.local_ports = vec!["Any".into()];
        r.remote_addresses = vec!["Any".into()];
        r.profiles = vec!["Any".into()];
        r.local_user = format!("O:LSD:(A;;CC;;;{SANDBOX})");
        r.enforcement = "ProfileInactive Enforced Enforced Enforced".into();
        let mut s = scenario();
        s.direction = Direction::Outbound;
        s.token = Some(token(ME));
        let e = evaluate(&r, &s);
        assert_eq!(e.result, Match::Mismatch);
        assert_eq!(e.relevance, None);
        s.token = Some(token(SANDBOX));
        assert_eq!(evaluate(&r, &s).result, Match::Match);
        s.token = None;
        assert_eq!(evaluate(&r, &s).result, Match::Unknown);
    }
    #[test]
    fn owner_and_package_rules_need_that_user_and_app_container() {
        let mut r = rule();
        r.owner = ME.into();
        r.package = "S-1-15-2-99".into();
        let mut s = scenario();
        s.token = Some(token(ME));
        // A desktop process is not that app container.
        assert_eq!(evaluate(&r, &s).result, Match::Mismatch);
        s.token.as_mut().unwrap().app_container_sid = Some("s-1-15-2-99".into());
        assert_eq!(evaluate(&r, &s).result, Match::Match);
        s.token.as_mut().unwrap().user_sid = SANDBOX.into();
        assert_eq!(evaluate(&r, &s).result, Match::Mismatch);
    }
    #[test]
    fn system_program_is_the_kernel_process() {
        let mut r = rule();
        r.program = vec!["System".into()];
        let mut s = scenario();
        assert_eq!(evaluate(&r, &s).result, Match::Mismatch);
        s.pid = Some(4);
        s.program = None;
        assert_eq!(evaluate(&r, &s).result, Match::Match);
        s.pid = None;
        assert_eq!(evaluate(&r, &s).result, Match::Unknown);
    }
    #[test]
    fn service_rules_follow_hosted_services() {
        let s = |hosted: Option<Vec<&str>>| Scenario {
            hosted_services: hosted.map(|h| h.into_iter().map(String::from).collect()),
            ..scenario()
        };
        let one = vec!["Dnscache".to_string()];
        assert_eq!(service_match(&one, &s(None)), Match::Unknown);
        assert_eq!(service_match(&one, &s(Some(vec![]))), Match::Mismatch);
        assert_eq!(
            service_match(&one, &s(Some(vec!["dnscache"]))),
            Match::Match
        );
        assert_eq!(service_match(&one, &s(Some(vec!["Dhcp"]))), Match::Mismatch);
        // Shared svchost: which service owns the socket is unknown.
        assert_eq!(
            service_match(&one, &s(Some(vec!["Dnscache", "Dhcp"]))),
            Match::Unknown
        );
        assert_eq!(
            service_match(&["*".into()], &s(Some(vec!["Dhcp"]))),
            Match::Match
        );
        assert_eq!(
            service_match(&["*".into()], &s(Some(vec![]))),
            Match::Mismatch
        );
    }
    #[test]
    fn address_and_port_keywords_resolve_from_network_context() {
        let net = NetworkContext {
            known: true,
            subnets: vec!["10.0.0.0/24".into(), "2601:281::/64".into()],
            dns: vec!["10.0.0.1".parse().unwrap()],
            gateways: vec!["10.0.0.1".parse().unwrap()],
            dhcp: vec!["10.0.0.1".parse().unwrap()],
            wins: vec![],
            dynamic_ports: Some((49152, 65535)),
        };
        let ip = |s: &str| Some(s.parse::<IpAddr>().unwrap());
        for (pattern, addr, m) in [
            ("Any", "8.8.8.8", Match::Match),
            ("LocalSubnet", "10.0.0.77", Match::Match),
            ("LocalSubnet", "::ffff:10.0.0.77", Match::Match),
            ("LocalSubnet", "8.8.8.8", Match::Mismatch),
            ("LocalSubnet4", "2601:281::5", Match::Mismatch),
            ("LocalSubnet6", "2601:281::5", Match::Match),
            ("DNS", "10.0.0.1", Match::Match),
            ("DNS4", "1.1.1.1", Match::Mismatch),
            ("DefaultGateway", "10.0.0.1", Match::Match),
            ("DHCP", "10.0.0.2", Match::Mismatch),
            ("WINS", "10.0.0.1", Match::Mismatch),
            ("Intranet", "10.0.0.1", Match::Unknown),
            ("10.0.0.0/8", "10.9.9.9", Match::Match),
        ] {
            assert_eq!(
                address_keyword_match(pattern, ip(addr), &net),
                m,
                "{pattern} {addr}"
            );
        }
        let unknown = NetworkContext::default();
        assert_eq!(
            address_keyword_match("LocalSubnet", ip("10.0.0.7"), &unknown),
            Match::Unknown
        );
        for (pattern, port, m) in [
            ("RPCEPMap", 135, Match::Match),
            ("RPCEPMap", 5001, Match::Mismatch),
            ("RPC", 5001, Match::Mismatch),
            ("RPC", 50000, Match::Unknown),
            ("IPHTTPSIn", 5001, Match::Mismatch),
            ("IPHTTPSIn", 443, Match::Unknown),
            ("mDNS", 5353, Match::Match),
            ("Teredo", 3544, Match::Unknown),
            ("5000-5010", 5001, Match::Match),
        ] {
            assert_eq!(
                port_keyword_match(pattern, Some(port), &net),
                m,
                "{pattern} {port}"
            );
        }
    }
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
                2 => r.local_ports = vec!["Teredo".into()],
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
