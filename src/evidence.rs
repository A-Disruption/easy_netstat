use crate::model::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    pub reference: String,
    pub event_id: u32,
    pub time_ms: u64,
    pub pid: Option<u32>,
    pub program: Option<String>,
    pub direction: Option<Direction>,
    pub protocol: Option<Protocol>,
    pub source: Option<SocketAddr>,
    pub destination: Option<SocketAddr>,
    pub filter_id: Option<u64>,
    pub layer: String,
}

pub fn parse_number(s: &str) -> Option<u64> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}
/// Parse named EventData values, never translated display messages. Entity
/// expansion is disabled; an input byte/event budget is enforced by collectors.
pub fn fields(xml: &str) -> Result<HashMap<String, String>, String> {
    if xml.len() > 256 * 1024 {
        return Err("Event exceeds size limit".into());
    }
    let mut reader = quick_xml::Reader::from_str(xml);
    let mut result = HashMap::new();
    let mut depth = 0usize;
    let mut name: Option<String> = None;
    let mut value = String::new();
    loop {
        use quick_xml::events::Event;
        let event = reader.read_event().map_err(|e| e.to_string())?;
        match &event {
            quick_xml::events::Event::Start(_) => {
                depth += 1;
                if depth > 64 {
                    return Err("Event nesting exceeds limit".into());
                }
            }
            quick_xml::events::Event::End(_) => {
                depth = depth.checked_sub(1).ok_or("Unexpected event closing tag")?;
            }
            quick_xml::events::Event::Eof if depth != 0 => {
                return Err("Incomplete event XML".into());
            }
            _ => {}
        }
        match event {
            Event::DocType(_) => return Err("DOCTYPE is not allowed".into()),
            Event::Start(e) if e.local_name().as_ref() == b"Data" => {
                name = None;
                value.clear();
                for a in e.attributes() {
                    let a = a.map_err(|e| e.to_string())?;
                    if a.key.as_ref() == b"Name" {
                        name = Some(
                            a.normalized_value(quick_xml::XmlVersion::Implicit1_0)
                                .map_err(|e| e.to_string())?
                                .into_owned(),
                        );
                    }
                }
            }
            Event::Text(t) if name.is_some() => {
                value.push_str(&t.decode().map_err(|e| e.to_string())?)
            }
            Event::GeneralRef(r) if name.is_some() => {
                if let Some(c) = r.resolve_char_ref().map_err(|e| e.to_string())? {
                    value.push(c);
                    continue;
                }
                let r = r.decode().map_err(|e| e.to_string())?;
                let decoded: String = match r.as_ref() {
                    "amp" => "&".into(),
                    "lt" => "<".into(),
                    "gt" => ">".into(),
                    "quot" => "\"".into(),
                    "apos" => "'".into(),
                    _ => return Err("Unsupported XML reference".into()),
                };
                value.push_str(&decoded);
            }
            Event::End(e) if e.local_name().as_ref() == b"Data" => {
                if let Some(n) = name.take()
                    && result.insert(n, value.clone()).is_some()
                {
                    return Err("Duplicate event field".into());
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(result)
}
pub fn network_event(raw: &RawEvent) -> Result<NetworkEvent, String> {
    if raw.provider != "Microsoft-Windows-Security-Auditing"
        || ![5152, 5154, 5155, 5156, 5157, 5158, 5159].contains(&raw.event_id)
    {
        return Err("Not a supported Security WFP event".into());
    }
    let f = fields(&raw.xml)?;
    let get = |n: &str| f.get(n).map(String::as_str).unwrap_or("");
    let endpoint = |a: &str, p: &str| {
        get(a)
            .parse()
            .ok()
            .zip(get(p).parse::<u16>().ok())
            .map(|(ip, port)| SocketAddr::new(ip, port))
    };
    Ok(NetworkEvent {
        reference: format!(
            "{}:{}:{}:{}",
            raw.channel, raw.provider, raw.record_id, raw.time_ms
        ),
        event_id: raw.event_id,
        time_ms: raw.time_ms,
        pid: parse_number(get("ProcessID")).and_then(|n| n.try_into().ok()),
        program: f.get("Application").cloned(),
        direction: match get("Direction") {
            "%%14592" | "Inbound" => Some(Direction::Inbound),
            "%%14593" | "Outbound" => Some(Direction::Outbound),
            _ => None,
        },
        protocol: match get("Protocol") {
            "6" => Some(Protocol::Tcp),
            "17" => Some(Protocol::Udp),
            _ => None,
        },
        source: endpoint("SourceAddress", "SourcePort"),
        destination: endpoint("DestAddress", "DestPort"),
        filter_id: parse_number(get("FilterRTID")),
        layer: get("LayerName").into(),
    })
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_canonical(),
        v4 => v4,
    }
}

/// The scenario's local endpoint may be a listener wildcard (`0.0.0.0` / `::`),
/// which accepts any concrete local address of a compatible family. A `::`
/// listener can be dual-stack, so it also accepts IPv4 (and mapped) addresses.
fn local_matches(spec: SocketAddr, actual: SocketAddr) -> bool {
    if spec.port() != actual.port() {
        return false;
    }
    match spec.ip() {
        IpAddr::V4(a) if a.is_unspecified() => canonical(actual.ip()).is_ipv4(),
        IpAddr::V6(a) if a.is_unspecified() => true,
        ip => canonical(ip) == canonical(actual.ip()),
    }
}

/// With no peer supplied, any remote endpoint qualifies; the event's own
/// remote address is then reported, not assumed.
fn remote_matches(spec: Option<SocketAddr>, actual: SocketAddr) -> bool {
    spec.is_none_or(|r| r.port() == actual.port() && canonical(r.ip()) == canonical(actual.ip()))
}

/// The remote endpoint of `e` when its tuple matches the scenario, else None.
///
/// Direction and protocol must match exactly. Source/destination orientation is
/// NOT trusted: Microsoft documents inbound 5157/5152 Source as the local side,
/// words 5156 the other way, and its own samples disagree with both. The local
/// side is therefore identified by the scenario's local endpoint, in either slot.
pub fn scenario_peer(e: &NetworkEvent, s: &Scenario) -> Option<SocketAddr> {
    if e.direction != Some(s.direction) || e.protocol != Some(s.protocol) {
        return None;
    }
    let (a, b) = (e.source?, e.destination?);
    [(a, b), (b, a)]
        .into_iter()
        .find(|&(local, remote)| local_matches(s.local, local) && remote_matches(s.remote, remote))
        .map(|(_, remote)| remote)
}

/// Exact tuple/direction matching is necessary even when an application path
/// looks familiar. A wildcard listener matches its port on any local address.
pub fn matches_scenario(e: &NetworkEvent, s: &Scenario) -> bool {
    scenario_peer(e, s).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event() -> RawEvent {
        RawEvent{channel:"Security".into(),provider:"Microsoft-Windows-Security-Auditing".into(),record_id:1,event_id:5157,time_ms:2,
        xml:r#"<Event><EventData><Data Name="ProcessID">0x2a</Data><Data Name="Application">C:\Opera\IFC8.exe</Data><Data Name="Direction">%%14592</Data><Data Name="SourceAddress">10.20.0.25</Data><Data Name="SourcePort">53000</Data><Data Name="DestAddress">10.20.0.10</Data><Data Name="DestPort">5001</Data><Data Name="Protocol">6</Data><Data Name="FilterRTID">88</Data></EventData></Event>"#.into()}
    }
    #[test]
    fn structured_event_normalizes_inbound_and_hex_pid() {
        let e = network_event(&event()).unwrap();
        assert_eq!(e.pid, Some(42));
        assert_eq!(e.filter_id, Some(88));
        assert!(matches_scenario(&e, &crate::firewall::scenario()));
    }
    #[test]
    fn tuple_direction_and_protocol_must_match() {
        let e = network_event(&event()).unwrap();
        let mut s = crate::firewall::scenario();
        s.direction = Direction::Outbound;
        assert!(!matches_scenario(&e, &s));
        s.direction = Direction::Inbound;
        s.protocol = Protocol::Udp;
        assert!(!matches_scenario(&e, &s));
        s.protocol = Protocol::Tcp;
        s.remote = Some("10.20.0.26:53000".parse().unwrap());
        assert!(!matches_scenario(&e, &s));
        s.local = "10.20.0.10:5002".parse().unwrap();
        s.remote = None;
        assert!(!matches_scenario(&e, &s));
    }
    #[test]
    fn listener_without_peer_matches_and_reports_event_peer() {
        let e = network_event(&event()).unwrap();
        let mut s = crate::firewall::scenario();
        s.remote = None;
        s.local = "0.0.0.0:5001".parse().unwrap();
        assert_eq!(scenario_peer(&e, &s), Some("10.20.0.25:53000".parse().unwrap()));
        s.local = "[::]:5001".parse().unwrap();
        assert!(matches_scenario(&e, &s));
        s.local = "[::1]:5001".parse().unwrap();
        assert!(!matches_scenario(&e, &s));
    }
    #[test]
    fn either_source_destination_orientation_matches() {
        // Documented 5157 layout: inbound Source is the local endpoint.
        let mut raw = event();
        raw.xml = raw
            .xml
            .replace("10.20.0.25</Data><Data Name=\"SourcePort\">53000", "10.20.0.10</Data><Data Name=\"SourcePort\">5001")
            .replace("10.20.0.10</Data><Data Name=\"DestPort\">5001", "10.20.0.25</Data><Data Name=\"DestPort\">53000");
        let e = network_event(&raw).unwrap();
        assert_eq!(e.source, Some("10.20.0.10:5001".parse().unwrap()));
        let s = crate::firewall::scenario();
        assert_eq!(scenario_peer(&e, &s), s.remote);
    }
    #[test]
    fn mapped_ipv6_peer_matches_ipv4_scenario() {
        let mut raw = event();
        raw.xml = raw.xml.replace(">10.20.0.25<", ">::ffff:10.20.0.25<");
        let e = network_event(&raw).unwrap();
        assert!(matches_scenario(&e, &crate::firewall::scenario()));
    }
    #[test]
    fn unknown_fields_do_not_invent_endpoints() {
        let mut raw = event();
        raw.xml = "<Event/>".into();
        let e = network_event(&raw).unwrap();
        assert!(e.pid.is_none());
        assert!(!matches_scenario(&e, &crate::firewall::scenario()));
    }
    #[test]
    fn malformed_duplicate_doctype_and_oversize_are_rejected() {
        for xml in [
            "<Data Name=\"x\"><",
            "<Event><Data Name=\"x\">1</Data>",
            "<E><Data Name=\"x\">1</Data><Data Name=\"x\">2</Data></E>",
            "<!DOCTYPE Event><Event/>",
        ] {
            assert!(fields(xml).is_err(), "{xml}");
        }
        assert!(fields(&"x".repeat(256 * 1024 + 1)).is_err());
    }
    #[test]
    fn named_xml_entities_are_decoded() {
        assert_eq!(
            fields("<E><Data Name=\"x\">a&amp;b</Data></E>").unwrap()["x"],
            "a&b"
        );
    }
    #[test]
    fn numeric_xml_references_and_outbound_ipv6_are_supported() {
        assert_eq!(
            fields("<E><Data Name=\"x\">A&#38;&#x42;</Data></E>").unwrap()["x"],
            "A&B"
        );
        let raw=RawEvent{provider:"Microsoft-Windows-Security-Auditing".into(),event_id:5157,xml:r#"<E><Data Name="Direction">%%14593</Data><Data Name="Protocol">6</Data><Data Name="SourceAddress">::1</Data><Data Name="SourcePort">5001</Data><Data Name="DestAddress">2001:db8::1</Data><Data Name="DestPort">80</Data></E>"#.into(),..RawEvent::default()};
        let event = network_event(&raw).unwrap();
        let mut s = crate::firewall::scenario();
        s.direction = Direction::Outbound;
        s.local = "[::1]:5001".parse().unwrap();
        s.remote = Some("[2001:db8::1]:80".parse().unwrap());
        assert!(matches_scenario(&event, &s));
    }
    #[test]
    fn provider_and_event_id_are_required() {
        let mut raw = event();
        raw.provider = "Other".into();
        assert!(network_event(&raw).is_err());
        raw.provider = "Microsoft-Windows-Security-Auditing".into();
        raw.event_id = 7036;
        assert!(network_event(&raw).is_err());
    }
}
