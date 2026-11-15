pub use crate::verdict::{Outcome, ProfileVerdict, Step, StepStatus, Verdict};
use crate::verdict::{candidate_profiles, verdict};
use crate::{
    evidence,
    firewall::{self, Evaluation, Match},
    inventory::filetime_ms,
    model::*,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Certainty {
    Observed,
    Inferred,
    ConfirmedFailure,
}
impl std::fmt::Display for Certainty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Observed => "Observed",
            Self::Inferred => "Inferred",
            Self::ConfirmedFailure => "Confirmed Failure",
        })
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub certainty: Certainty,
    pub title: String,
    pub explanation: String,
    pub evidence: Vec<String>,
    pub assumptions: Vec<String>,
    pub follow_up: String,
    pub time_ms: u64,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Analysis {
    pub evaluator_version: u32,
    pub findings: Vec<Finding>,
    pub rules: Vec<Evaluation>,
    #[serde(default)]
    pub verdict: Option<Verdict>,
}

/// "10.0.0.42/24" or "fe80::1%5/64" -> (address, prefix length).
fn prefix(value: &str) -> Option<(std::net::IpAddr, u32)> {
    let (address, length) = value.split_once('/')?;
    let address = address.split('%').next()?.parse().ok()?;
    Some((address, length.trim().parse().ok()?))
}

/// Fills in what rule conditions need beyond the endpoint itself, from this
/// collection: the process token, the services it hosts, and what address
/// and port keywords (LocalSubnet, DNS, RPC, ...) resolve to. Values the user
/// already supplied are kept.
pub fn enrich(s: &Scenario, data: &DiagnosticData) -> Scenario {
    let mut e = s.clone();
    let status = |source: &str| {
        data.capabilities
            .iter()
            .find(|c| c.source == source)
            .map(|c| c.status.as_str())
    };
    // `process` is only kept when its identity was revalidated (collectors).
    let process = data.process.as_ref().filter(|p| Some(p.pid) == s.pid);
    if e.token.is_none() {
        e.token = process.and_then(|p| p.token.clone());
    }
    if e.hosted_services.is_none() && process.is_some() && status("Services") == Some("Available") {
        e.hosted_services = Some(
            data.services
                .iter()
                .filter(|v| Some(v.pid) == s.pid && v.state.eq_ignore_ascii_case("Running"))
                .map(|v| v.name.clone())
                .collect(),
        );
    }
    if e.network.dynamic_ports.is_none() {
        e.network.dynamic_ports = match s.protocol {
            Protocol::Tcp => data.tcp_dynamic_ports,
            Protocol::Udp => data.udp_dynamic_ports,
        }
        .filter(|[start, count]| *count > 0 && *start <= 65535)
        .map(|[start, count]| (start as u16, (start + count - 1).min(65535) as u16));
    }
    if !e.network.known && status("Network") == Some("Available") {
        let interfaces: Vec<_> = data
            .interfaces
            .iter()
            .filter(|i| match &s.interface {
                Some(alias) => i.alias.eq_ignore_ascii_case(alias),
                None => i.status.eq_ignore_ascii_case("Up"),
            })
            .collect();
        let ips = |values: &[String]| -> Vec<std::net::IpAddr> {
            values
                .iter()
                .filter_map(|v| v.split(['/', '%']).next()?.trim().parse().ok())
                .collect()
        };
        let net = &mut e.network;
        net.known = true;
        let mut push_subnet = |ip: std::net::IpAddr, len: u32| {
            let full = if ip.is_ipv4() { 32 } else { 128 };
            // Host routes and default routes are not subnets.
            if len > 0 && len < full && !ip.is_multicast() {
                let entry = format!("{ip}/{len}");
                if !net.subnets.contains(&entry) {
                    net.subnets.push(entry);
                }
            }
        };
        for i in &interfaces {
            for (ip, len) in i.addresses.iter().filter_map(|a| prefix(a)) {
                push_subnet(ip, len);
            }
        }
        // Temporary IPv6 addresses are /128; their subnet is the on-link route.
        if matches!(status("Routes"), Some("Available" | "Partial")) {
            let indexes: Vec<_> = interfaces.iter().map(|i| i.index).collect();
            for r in data
                .routes
                .iter()
                .filter(|r| indexes.contains(&r.interface))
            {
                if matches!(r.next_hop.trim(), "0.0.0.0" | "::")
                    && let Some((ip, len)) = prefix(&r.destination)
                {
                    push_subnet(ip, len);
                }
            }
        }
        for i in &interfaces {
            net.dns.extend(ips(&i.dns));
            net.gateways.extend(ips(&i.gateways));
            net.dhcp.extend(ips(&i.dhcp));
            net.wins.extend(ips(&i.wins));
        }
    }
    e
}

pub fn analyze(
    c: &Connection,
    s: &Scenario,
    data: &DiagnosticData,
    expected_service: &str,
    expected_port: Option<u16>,
) -> Analysis {
    let mut result = Analysis {
        evaluator_version: 3,
        ..Analysis::default()
    };
    let mut add = |id: &str,
                   certainty,
                   title: String,
                   explanation: String,
                   refs: Vec<String>,
                   assumptions: Vec<String>,
                   follow_up: &str| {
        result.findings.push(Finding {
            id: id.into(),
            certainty,
            title,
            explanation,
            evidence: refs,
            assumptions,
            follow_up: follow_up.into(),
            time_ms: data.finished_ms,
        })
    };
    let conn_ref = format!(
        "inventory:{}:pid:{}:created:{:?}",
        c.observed_ms, c.key.process.pid, c.key.process.created
    );
    add("connection.observed",Certainty::Observed,format!("{} {} at {}",c.key.protocol,c.state,c.key.local),
        "A sampled endpoint/state does not prove reachability, traffic direction or application readiness.".into(),vec![conn_ref.clone()],vec![],"Compare the expected address/port and use a concrete peer scenario.");
    if expected_port.is_some_and(|p| p != c.key.local.port()) {
        add(
            "binding.port",
            Certainty::Inferred,
            "Observed port differs from your expectation".into(),
            format!(
                "Observed {}; expected {}.",
                c.key.local.port(),
                expected_port.unwrap()
            ),
            vec![conn_ref.clone()],
            vec!["The supplied expected port is correct.".into()],
            "Verify the application's configured listening port.",
        );
    }
    if c.key.local.ip().is_loopback() {
        add(
            "binding.loopback",
            Certainty::Inferred,
            "Endpoint is bound to loopback".into(),
            "This binding is local-only; other independent listeners may exist.".into(),
            vec![conn_ref.clone()],
            vec!["You intend to receive traffic from another machine.".into()],
            "Check the application bind configuration and other listeners.",
        );
    }
    let identity_matches = data.process.as_ref().is_some_and(|p| {
        p.pid == c.key.process.pid && p.created.is_some() && p.created == c.key.process.created
    });
    let associated: Vec<_> = data
        .services
        .iter()
        .filter(|v| v.pid == c.key.process.pid && v.state != "Stopped")
        .collect();
    if associated.len() > 1 {
        add(
            "service.shared",
            Certainty::Observed,
            "Multiple visible services share this process".into(),
            format!(
                "{} associated services; this does not identify which owns the socket.",
                associated.len()
            ),
            vec![format!("services:{}", data.finished_ms)],
            vec![],
            "Inspect service restrictions independently; leave socket service unknown without additional evidence.",
        );
    }
    if !expected_service.is_empty()
        && let Some(service) = data
            .services
            .iter()
            .find(|v| v.name.eq_ignore_ascii_case(expected_service))
    {
        add(
            "service.expected",
            Certainty::Observed,
            format!("Expected service is {}", service.state),
            format!(
                "Start mode: {}. The configured service binary may differ from the running process.",
                service.start_mode
            ),
            vec![format!("service:{}:{}", service.name, data.finished_ms)],
            vec![],
            "Compare service state and configured endpoint with the application's logs.",
        );
        if service.state == "Stopped" {
            add("service.stopped",Certainty::Inferred,"Stopped expected service may explain missing communication".into(),"A stopped service does not prove the selected process or every endpoint is unavailable.".into(),vec![format!("service:{}:{}",service.name,data.finished_ms)],vec!["The supplied service is required for this communication.".into()],"Review the service's recent events and application configuration; no service changes are performed.");
        }
    }

    let (mut blocks_seen, mut permits_seen) = (0usize, 0usize);
    let mut confirmed_block = false;
    let mut confirmed_permit = false;
    for raw in &data.events {
        let Ok(event) = evidence::network_event(raw) else {
            continue;
        };
        let Some(peer) = evidence::scenario_peer(&event, s) else {
            continue;
        };
        let lifetime = c.key.process.created.is_some_and(|created| {
            event.time_ms >= filetime_ms(created) + u64::from(created % 10_000 != 0)
                && event.time_ms <= data.finished_ms
        });
        let path_conflict = event
            .program
            .as_deref()
            .and_then(firewall::normalize_path)
            .zip(c.process.path.as_deref().and_then(firewall::normalize_path))
            .is_some_and(|(a, b)| a != b);
        let strong =
            identity_matches && lifetime && event.pid == Some(c.key.process.pid) && !path_conflict;
        if [5152, 5157].contains(&event.event_id) {
            blocks_seen += 1;
            if blocks_seen > 20 {
                continue;
            }
            if strong {
                confirmed_block = true;
                add("wfp.block",Certainty::ConfirmedFailure,if event.event_id==5152{format!("WFP dropped a matching packet from {peer}")}else{format!("WFP blocked a matching connection attempt with {peer}")},format!("Event {}, time {} ms UTC, peer {peer}, filter {:?}, layer {}. This confirms this recorded attempt only; friendly-rule causation and business-transaction failure are not established.",event.event_id,event.time_ms,event.filter_id,event.layer),vec![event.reference],vec!["Event tuple/direction and revalidated process lifetime match; historical policy may differ.".into()],"Inspect the filter/provider and contemporaneous application evidence before attributing a root cause.");
            } else {
                add("wfp.unattributed",Certainty::Observed,format!("A recorded block matches the examined tuple (peer {peer})"),"Process identity/lifetime could not be confirmed for the selected observation. This is not a confirmed failure of the selected process.".into(),vec![event.reference],vec![],"Reproduce with process identity available or inspect historical process evidence.");
            }
        } else if event.event_id == 5156 && strong {
            confirmed_permit = true;
            permits_seen += 1;
            if permits_seen > 5 {
                continue;
            }
            add(
                "wfp.permit",
                Certainty::Observed,
                format!("WFP recorded a permit for an attempt with {peer}"),
                "A permit at this event point does not prove delivery or application success."
                    .into(),
                vec![event.reference],
                vec![],
                "Check the remote endpoint and application-level response.",
            );
        }
    }
    // Relevant SCM/WER facts remain observed context; no causal restart/crash
    // conclusion is manufactured from a translated message or a PID alone.
    for raw in data.events.iter().filter(|r| r.channel != "Security") {
        let Ok(fields) = evidence::fields(&raw.xml) else {
            continue;
        };
        let service_match = data.services.iter().any(|svc| {
            fields
                .values()
                .any(|v| v == &svc.name || v == &svc.display_name)
        });
        let process_match = identity_matches
            && c.key
                .process
                .created
                .is_some_and(|t| raw.time_ms >= filetime_ms(t))
            && fields
                .get("ProcessId")
                .and_then(|v| evidence::parse_number(v))
                == Some(c.key.process.pid as u64);
        if service_match || process_match {
            add("system.context",Certainty::Observed,format!("Relevant {} event {}",raw.provider,raw.event_id),"Structured identity fields match an associated service or revalidated process lifetime; causation is not established.".into(),vec![format!("{}:{}:{}:{}",raw.channel,raw.provider,raw.record_id,raw.time_ms)],vec![],"Review the event with application logs at the same timestamp.");
        }
    }
    if data
        .capabilities
        .iter()
        .any(|cap| cap.source == "Network" && cap.status == "Available")
        && !s.local.ip().is_unspecified()
        && !s.local.ip().is_loopback()
        && !data.interfaces.iter().any(|i| i.has_ip(s.local.ip()))
    {
        add("network.local-address",Certainty::Inferred,"Scenario local address was not found on collected interfaces".into(),"The supplied local endpoint may be incorrect, stale, virtual, or in another network compartment. This does not prove the listener failed to bind.".into(),vec![format!("network:{}",data.finished_ms)],vec!["The collected interface context covers the examined traffic.".into()],"Verify the concrete local endpoint and interface, including VPN/virtual adapters.");
    }
    if let Some(peer) = s.remote
        && !peer.ip().is_loopback()
        && data
            .capabilities
            .iter()
            .any(|cap| cap.source == "Routes" && cap.status == "Available")
        && !data.routes.iter().any(|route| {
            firewall::address_match(&route.destination, Some(peer.ip())) != Match::Mismatch
        })
    {
        add("network.route",Certainty::Inferred,"No candidate route to the examined peer in collected routing context".into(),"No collected destination prefix covered the peer. This is a current configuration inference, not a recorded packet failure or a complete multi-compartment route decision.".into(),vec![format!("routes:{}",data.finished_ms)],vec!["The examined peer and queried routing compartment are correct.".into()],"Check destination, current routes, VPN/compartment context and the intended interface.");
    }
    drop(add);
    let policy_ref = format!(
        "ActiveStore:{}:{}",
        data.policy.version, data.policy.collected_ms
    );
    let profiles = candidate_profiles(s, data);
    let mut effective = enrich(s, data);
    if effective.profile.is_none()
        && let [only] = profiles.as_slice()
    {
        effective.profile = Some(only.clone());
    }
    let s = &effective;
    result.rules = data
        .policy
        .rules
        .iter()
        .map(|r| firewall::evaluate(r, s))
        .filter(|e| e.relevance.is_some())
        .collect();
    result
        .rules
        .sort_by(|a, b| firewall::priority(a).cmp(&firewall::priority(b)));
    let candidates_capped = result.rules.len() > 2000;
    result.rules.truncate(2000);
    for e in result
        .rules
        .iter()
        .filter(|e| {
            e.result == Match::Mismatch
                && e.action.eq_ignore_ascii_case("Allow")
                && matches!(
                    e.relevance,
                    Some(firewall::Relevance::Application | firewall::Relevance::Service)
                )
        })
        .take(10)
    {
        let mismatches = e
            .conditions
            .iter()
            .filter(|c| c.result == Match::Mismatch)
            .map(|c| format!("{}: {}", c.name, c.detail))
            .collect::<Vec<_>>();
        let fields = e
            .conditions
            .iter()
            .filter(|c| c.result == Match::Mismatch)
            .map(|c| c.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        result.findings.push(Finding {
            id: format!("policy.mismatch:{}", e.rule_id), certainty: Certainty::Inferred,
            title: format!("Allow rule '{}' excludes this traffic: {}", e.rule_name, fields),
            explanation: format!("Why shown: {} Conditions excluding this traffic: {}", e.relevance.unwrap().reason(), mismatches.join("; ")),
            evidence: vec![policy_ref.clone(), format!("rule:{}", e.rule_id)],
            assumptions: vec!["This rule is only a potential intended exception. Other rules may allow the traffic; scenario inputs and collected policy must describe the examined attempt.".into()],
            follow_up: "If this rule is intended to allow the communication, compare the listed restrictions with the actual peer/interface. Check matching allow candidates before treating this as a problem. A nonmatching rule does not prove a block.".into(),
            time_ms: data.finished_ms,
        });
    }
    let matched_allow = result
        .rules
        .iter()
        .any(|e| e.result == Match::Match && e.action.eq_ignore_ascii_case("Allow"));
    let matching_blocks = result
        .rules
        .iter()
        .filter(|e| e.result == Match::Match && e.action.eq_ignore_ascii_case("Block"))
        .count();
    let policy_coverage = data.policy.complete && !candidates_capped;
    let title = if data.policy.collected_ms == 0 {
        "Effective firewall policy is unavailable"
    } else if matching_blocks > 0 {
        "Matching configured block candidates found"
    } else if matched_allow {
        "Allow candidate matches the evaluated conditions"
    } else {
        "No complete allow candidate found in collected policy"
    };
    let unknown = result
        .rules
        .iter()
        .filter(|e| e.result == Match::Unknown)
        .count();
    let near = result
        .rules
        .iter()
        .filter(|e| e.result == Match::Mismatch)
        .count();
    let allows = result
        .rules
        .iter()
        .filter(|e| e.result == Match::Match && e.action.eq_ignore_ascii_case("Allow"))
        .count();
    let names = result
        .rules
        .iter()
        .filter(|e| e.result == Match::Match)
        .take(5)
        .map(|e| format!("{}: {}", e.action, e.rule_name))
        .collect::<Vec<_>>()
        .join("; ");
    result.findings.push(Finding {
        id: "policy.summary".into(), certainty: if data.policy.collected_ms == 0 { Certainty::Observed } else { Certainty::Inferred }, title: title.into(),
        explanation: format!("{} matching allow candidate(s), {} matching block candidate(s), {} incomplete candidate(s), {} identity-linked near match(es). {} Policy coverage {}. Unrelated rules are excluded from the shortlist. Configuration cannot confirm a block or guarantee passage.", allows, matching_blocks, unknown, near, if names.is_empty() { String::new() } else { format!("Matching rules: {}. ", names) }, if policy_coverage { "collected supported subset" } else { "partial/unavailable/capped" }),
        evidence: vec![policy_ref.clone()], assumptions: vec![format!("Scenario {}. Unknown conditions, service hardening, IPsec and other providers may affect the outcome.", if s.hypothetical { "contains supplied or assumed values" } else { "is observed" })],
        follow_up: "Review the Relevant rules shortlist and each inclusion reason. Supply a concrete peer/local interface and inspect corresponding WFP events for an observed traffic verdict.".into(), time_ms: data.finished_ms,
    });

    if data.policy.collected_ms > 0 {
        let verdict = verdict(
            s,
            data,
            &profiles,
            &result.rules,
            confirmed_block,
            confirmed_permit,
        );
        result.findings.push(Finding {
            id: "policy.verdict".into(),
            certainty: if verdict.confirmed {
                Certainty::Observed
            } else {
                Certainty::Inferred
            },
            title: verdict.headline.clone(),
            explanation: verdict.reason.clone(),
            evidence: vec![policy_ref.clone()],
            assumptions: verdict.assumptions.clone(),
            follow_up: verdict.next.clone(),
            time_ms: data.finished_ms,
        });
        result.verdict = Some(verdict);
    }
    result.findings.sort_by_key(|f| {
        (
            match f.certainty {
                Certainty::ConfirmedFailure => 0,
                Certainty::Inferred => 1,
                Certainty::Observed => 2,
            },
            match f.id.as_str() {
                "policy.verdict" => 0,
                "policy.summary" => 1,
                _ => 2,
            },
        )
    });
    result.findings.truncate(100);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn data() -> DiagnosticData {
        DiagnosticData {
            schema: 1,
            finished_ms: 10000,
            policy: Policy {
                collected_ms: 1,
                rules: vec![crate::firewall::rule()],
                complete: true,
                ..Policy::default()
            },
            ..DiagnosticData::default()
        }
    }
    #[test]
    fn configuration_never_confirms_failure() {
        let c = crate::state::connection(42, Some(1), "Listen");
        let mut s = crate::firewall::scenario();
        s.remote = Some("10.30.0.25:53000".parse().unwrap());
        let a = analyze(&c, &s, &data(), "", None);
        assert!(
            a.findings
                .iter()
                .all(|f| f.certainty != Certainty::ConfirmedFailure)
        );
        assert!(
            a.findings
                .iter()
                .any(|f| f.id.starts_with("policy.mismatch"))
        );
    }
    #[test]
    fn absent_policy_has_honest_summary() {
        let c = crate::state::connection(1, None, "Listen");
        let a = analyze(
            &c,
            &Scenario::for_connection(&c),
            &DiagnosticData::default(),
            "",
            None,
        );
        assert!(a.findings.iter().any(|f| f.title.contains("unavailable")));
        assert!(
            a.findings
                .iter()
                .all(|f| f.certainty != Certainty::ConfirmedFailure)
        );
    }
    #[test]
    fn stopped_service_is_fact_and_cause_remains_inferred() {
        let c = crate::state::connection(42, Some(1), "Listen");
        let mut d = data();
        d.services.push(Service {
            name: "Opera".into(),
            state: "Stopped".into(),
            ..Service::default()
        });
        let a = analyze(&c, &crate::firewall::scenario(), &d, "Opera", Some(5002));
        assert!(
            a.findings
                .iter()
                .any(|f| f.id == "service.expected" && f.certainty == Certainty::Observed)
        );
        assert!(
            a.findings
                .iter()
                .any(|f| f.id == "service.stopped" && f.certainty == Certainty::Inferred)
        );
        assert!(a.findings.iter().any(|f| f.id == "binding.port"));
    }
    #[test]
    fn block_requires_tuple_lifetime_and_revalidated_identity() {
        let created = 116_444_736_000_000_000;
        let c = crate::state::connection(42, Some(created), "Listen");
        let s = crate::firewall::scenario();
        let mut d = data();
        d.events.push(RawEvent{channel:"Security".into(),provider:"Microsoft-Windows-Security-Auditing".into(),record_id:1,event_id:5157,time_ms:5000,xml:r#"<E><Data Name="ProcessID">42</Data><Data Name="Direction">%%14592</Data><Data Name="Protocol">6</Data><Data Name="SourceAddress">10.20.0.25</Data><Data Name="SourcePort">53000</Data><Data Name="DestAddress">10.20.0.10</Data><Data Name="DestPort">5001</Data></E>"#.into()});
        assert!(
            !analyze(&c, &s, &d, "", None)
                .findings
                .iter()
                .any(|f| f.certainty == Certainty::ConfirmedFailure)
        );
        d.process = Some(ProcessContext {
            pid: 42,
            created: Some(created),
            ..ProcessContext::default()
        });
        assert!(
            analyze(&c, &s, &d, "", None)
                .findings
                .iter()
                .any(|f| f.certainty == Certainty::ConfirmedFailure)
        );
        d.process.as_mut().unwrap().created = Some(created + 1);
        assert!(
            !analyze(&c, &s, &d, "", None)
                .findings
                .iter()
                .any(|f| f.certainty == Certainty::ConfirmedFailure)
        );
    }
    #[test]
    fn listener_without_peer_is_confirmed_by_documented_event_layout() {
        let created = 116_444_736_000_000_000;
        let c = crate::state::connection(42, Some(created), "Listen");
        let mut s = crate::firewall::scenario();
        s.local = "0.0.0.0:5001".parse().unwrap();
        s.remote = None;
        let mut d = data();
        d.process = Some(ProcessContext {
            pid: 42,
            created: Some(created),
            ..ProcessContext::default()
        });
        // 5157 as documented: inbound Source is the local endpoint.
        d.events.push(RawEvent{channel:"Security".into(),provider:"Microsoft-Windows-Security-Auditing".into(),record_id:1,event_id:5157,time_ms:5000,xml:r#"<E><Data Name="ProcessID">42</Data><Data Name="Direction">%%14592</Data><Data Name="Protocol">6</Data><Data Name="SourceAddress">10.20.0.10</Data><Data Name="SourcePort">5001</Data><Data Name="DestAddress">10.30.0.25</Data><Data Name="DestPort">53000</Data></E>"#.into()});
        let a = analyze(&c, &s, &d, "", None);
        let block = a
            .findings
            .iter()
            .find(|f| f.certainty == Certainty::ConfirmedFailure)
            .expect("confirmed block");
        assert!(block.title.contains("10.30.0.25:53000"));
        let v = a.verdict.expect("verdict");
        assert_eq!((v.outcome, v.confirmed), (Outcome::Blocked, true));
    }
    #[test]
    fn verdict_uses_profile_default_and_single_active_profile() {
        let c = crate::state::connection(42, Some(1), "Listen");
        let mut s = crate::firewall::scenario();
        s.profile = None;
        s.remote = Some("10.30.0.25:53000".parse().unwrap());
        let mut d = data();
        d.policy.profiles = vec![FirewallProfile {
            name: "Domain".into(),
            enabled: "True".into(),
            inbound: "Block".into(),
            outbound: "Allow".into(),
            allow_inbound_rules: "True".into(),
            allow_local_rules: "True".into(),
        }];
        d.interfaces = vec![Interface {
            profile: "Domain".into(),
            status: "Up".into(),
            ..Interface::default()
        }];
        let a = analyze(&c, &s, &d, "", None);
        let v = a.verdict.as_ref().unwrap();
        assert_eq!(v.outcome, Outcome::BlockedByDefault);
        assert_eq!(v.closest_rule.as_deref(), Some("rule-1"));
        assert_eq!(a.findings[0].id, "policy.verdict");
    }
    #[test]
    fn enrich_resolves_subnets_services_token_and_dynamic_ports() {
        let c = crate::state::connection(42, Some(1), "Listen");
        let mut d = data();
        d.capabilities = ["Network", "Routes", "Services"]
            .map(|source| Capability {
                source: source.into(),
                status: "Available".into(),
                detail: String::new(),
            })
            .to_vec();
        d.process = Some(ProcessContext {
            pid: 42,
            token: Some(TokenIdentity {
                user_sid: "S-1-5-21-1-2-3-1001".into(),
                ..TokenIdentity::default()
            }),
            ..ProcessContext::default()
        });
        d.services = vec![
            Service {
                name: "Dnscache".into(),
                pid: 42,
                state: "Running".into(),
                ..Service::default()
            },
            Service {
                name: "Other".into(),
                pid: 7,
                state: "Running".into(),
                ..Service::default()
            },
        ];
        d.interfaces = vec![
            Interface {
                index: 5,
                status: "Up".into(),
                addresses: vec![
                    "10.0.0.42/24".into(),
                    "2601:281::1094/128".into(),
                    "fe80::1%5/64".into(),
                ],
                dns: vec!["10.0.0.1".into()],
                ..Interface::default()
            },
            Interface {
                index: 9,
                status: "Disconnected".into(),
                addresses: vec!["192.168.9.2/24".into()],
                ..Interface::default()
            },
        ];
        d.routes = vec![
            Route {
                destination: "2601:281::/64".into(),
                next_hop: "::".into(),
                interface: 5,
                ..Route::default()
            },
            Route {
                destination: "0.0.0.0/0".into(),
                next_hop: "10.0.0.1".into(),
                interface: 5,
                ..Route::default()
            },
            Route {
                destination: "10.0.0.42/32".into(),
                next_hop: "0.0.0.0".into(),
                interface: 5,
                ..Route::default()
            },
        ];
        d.tcp_dynamic_ports = Some([49152, 16384]);
        let e = enrich(&Scenario::for_connection(&c), &d);
        assert_eq!(e.token.unwrap().user_sid, "S-1-5-21-1-2-3-1001");
        assert_eq!(e.hosted_services, Some(vec!["Dnscache".to_string()]));
        assert_eq!(e.network.dynamic_ports, Some((49152, 65535)));
        assert!(e.network.known);
        assert_eq!(
            e.network.subnets,
            vec!["10.0.0.42/24", "fe80::1/64", "2601:281::/64"]
        );
        assert_eq!(
            e.network.dns,
            vec!["10.0.0.1".parse::<std::net::IpAddr>().unwrap()]
        );
        // Another PID's collection lends nothing.
        let mut other = Scenario::for_connection(&c);
        other.pid = Some(7);
        let e = enrich(&other, &d);
        assert!(e.token.is_none() && e.hosted_services.is_none());
    }
    #[test]
    fn deterministic_replay() {
        let c = crate::state::connection(42, Some(1), "Listen");
        let s = crate::firewall::scenario();
        assert_eq!(
            serde_json::to_string(&analyze(&c, &s, &data(), "", None)).unwrap(),
            serde_json::to_string(&analyze(&c, &s, &data(), "", None)).unwrap()
        );
    }
    #[test]
    fn routing_and_bind_anomalies_require_complete_context_and_remain_inferred() {
        let c = crate::state::connection(42, Some(1), "Listen");
        let s = crate::firewall::scenario();
        let mut d = data();
        d.capabilities = vec![
            Capability {
                source: "Routes".into(),
                status: "Partial".into(),
                detail: String::new(),
            },
            Capability {
                source: "Network".into(),
                status: "Unavailable".into(),
                detail: String::new(),
            },
        ];
        assert!(
            !analyze(&c, &s, &d, "", None)
                .findings
                .iter()
                .any(|f| f.id.starts_with("network."))
        );
        for cap in &mut d.capabilities {
            cap.status = "Available".into();
        }
        let a = analyze(&c, &s, &d, "", None);
        assert_eq!(
            a.findings
                .iter()
                .filter(|f| f.id.starts_with("network.") && f.certainty == Certainty::Inferred)
                .count(),
            2
        );
        d.routes.push(Route {
            destination: "0.0.0.0/0".into(),
            ..Route::default()
        });
        d.interfaces.push(Interface {
            addresses: vec![s.local.ip().to_string()],
            ..Interface::default()
        });
        assert!(
            !analyze(&c, &s, &d, "", None)
                .findings
                .iter()
                .any(|f| f.id.starts_with("network."))
        );
    }
    #[test]
    fn findings_explain_identity_link_and_only_meaningful_allow_exclusions() {
        let c = crate::state::connection(42, Some(1), "Listen");
        let s = crate::firewall::scenario();
        let mut d = data();
        let mut intended = crate::firewall::rule();
        intended.id = "intended".into();
        intended.remote_addresses = vec!["192.0.2.0/24".into()];
        let mut unrelated = intended.clone();
        unrelated.id = "unrelated".into();
        unrelated.program = vec!["Any".into()];
        let mut nonmatching_block = intended.clone();
        nonmatching_block.id = "nonmatching-block".into();
        nonmatching_block.action = "Block".into();
        d.policy.rules = vec![unrelated, nonmatching_block, intended];
        let a = analyze(&c, &s, &d, "", None);
        let findings: Vec<_> = a
            .findings
            .iter()
            .filter(|f| f.id.starts_with("policy.mismatch"))
            .collect();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "policy.mismatch:intended");
        assert!(findings[0].title.contains("Remote address"));
        assert!(
            findings[0]
                .explanation
                .contains("explicitly names this executable")
        );
        assert!(findings[0].explanation.contains("192.0.2.0/24"));
        assert!(findings[0].explanation.contains("10.20.0.25"));
        assert!(a.rules.iter().all(|e| e.rule_id != "unrelated"));
        let summary = a
            .findings
            .iter()
            .position(|f| f.id == "policy.summary")
            .unwrap();
        let mismatch = a
            .findings
            .iter()
            .position(|f| f.id.starts_with("policy.mismatch"))
            .unwrap();
        assert!(summary < mismatch);
        assert!(
            a.findings
                .iter()
                .all(|f| f.certainty != Certainty::ConfirmedFailure)
        );
    }
    #[test]
    fn high_value_candidates_are_ranked_before_the_analysis_cap() {
        let c = crate::state::connection(42, Some(1), "Listen");
        let mut d = data();
        d.policy.rules = (0..2001)
            .map(|i| {
                let mut r = crate::firewall::rule();
                r.id = format!("uncertain-{i}");
                r.program = vec!["Any".into()];
                r.protocol.clear();
                r
            })
            .collect();
        let mut block = crate::firewall::rule();
        block.id = "late-block".into();
        block.action = "Block".into();
        d.policy.rules.push(block);
        let a = analyze(&c, &crate::firewall::scenario(), &d, "", None);
        assert_eq!(a.rules.len(), 2000);
        assert_eq!(a.rules[0].rule_id, "late-block");
        let summary = a
            .findings
            .iter()
            .find(|f| f.id == "policy.summary")
            .unwrap();
        assert!(summary.title.contains("block candidates"));
        assert!(summary.explanation.contains("partial/unavailable/capped"));
    }
}
