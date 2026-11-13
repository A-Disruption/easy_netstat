use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, SocketAddr},
    time::{SystemTime, UNIX_EPOCH},
};

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
}
impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ProcessKey {
    pub pid: u32,
    /// Windows FILETIME creation timestamp (100ns); None never establishes continuity.
    pub created: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcessDetails {
    pub name: String,
    pub path: Option<String>,
    pub unavailable: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConnectionKey {
    pub protocol: Protocol,
    pub local: SocketAddr,
    pub remote: Option<SocketAddr>,
    pub process: ProcessKey,
    /// Disambiguates duplicate table rows within a sample.
    pub ordinal: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub key: ConnectionKey,
    pub state: String,
    pub process: ProcessDetails,
    pub observed_ms: u64,
    pub partition: String,
}
impl Connection {
    pub fn is_listener(&self) -> bool {
        self.key.protocol == Protocol::Tcp && self.state == "Listen"
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Inventory {
    pub started_ms: u64,
    pub finished_ms: u64,
    pub connections: Vec<Connection>,
    pub successful_partitions: Vec<String>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    Inbound,
    Outbound,
}
impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Inbound => "Inbound",
            Self::Outbound => "Outbound",
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scenario {
    pub direction: Direction,
    pub protocol: Protocol,
    pub local: SocketAddr,
    pub remote: Option<SocketAddr>,
    pub program: Option<String>,
    pub service: Option<String>,
    pub profile: Option<String>,
    pub interface: Option<String>,
    pub interface_type: Option<String>,
    pub hypothetical: bool,
    /// Owning process; identifies the kernel ("System", PID 4).
    #[serde(default)]
    pub pid: Option<u32>,
    /// Revalidated process token; None when it couldn't be read.
    #[serde(default)]
    pub token: Option<TokenIdentity>,
    /// Running services hosted by the process; None when not collected.
    #[serde(default)]
    pub hosted_services: Option<Vec<String>>,
    /// Facts that resolve address and port keywords in rules.
    #[serde(default)]
    pub network: NetworkContext,
}

/// Security identity of a process token, as SID strings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TokenIdentity {
    pub user_sid: String,
    /// Enabled groups, excluding deny-only ones.
    pub groups: Vec<String>,
    /// Groups that only ever match deny entries.
    pub deny_only: Vec<String>,
    /// AppContainer (package) SID; None for ordinary desktop processes.
    pub app_container_sid: Option<String>,
}

/// What a rule's keywords (LocalSubnet, DNS, RPC, ...) resolve to here.
/// `known` is false when network context wasn't collected.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkContext {
    pub known: bool,
    /// On-link prefixes, "address/length".
    pub subnets: Vec<String>,
    pub dns: Vec<IpAddr>,
    pub gateways: Vec<IpAddr>,
    pub dhcp: Vec<IpAddr>,
    pub wins: Vec<IpAddr>,
    /// Inclusive dynamic (ephemeral) port range for this protocol.
    pub dynamic_ports: Option<(u16, u16)>,
}
impl Scenario {
    pub fn for_connection(c: &Connection) -> Self {
        Self {
            direction: Direction::Inbound,
            protocol: c.key.protocol,
            local: c.key.local,
            remote: if c.is_listener() { None } else { c.key.remote },
            program: c.process.path.clone(),
            service: None,
            profile: None,
            interface: None,
            interface_type: None,
            hypothetical: true,
            pid: Some(c.key.process.pid),
            token: None,
            hosted_services: None,
            network: NetworkContext::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Service {
    pub name: String,
    pub display_name: String,
    pub pid: u32,
    pub state: String,
    pub start_mode: String,
    pub account: String,
    pub binary: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Interface {
    pub index: u32,
    pub alias: String,
    pub profile: String,
    pub kind: String,
    pub addresses: Vec<String>,
    pub dns: Vec<String>,
    pub gateways: Vec<String>,
    pub dhcp: Vec<String>,
    pub wins: Vec<String>,
    pub status: String,
    pub errors: Option<u64>,
}
impl Interface {
    pub fn has_ip(&self, ip: IpAddr) -> bool {
        self.addresses.iter().any(|a| {
            a.split(['/', '%'])
                .next()
                .and_then(|a| a.parse::<IpAddr>().ok())
                == Some(ip)
        })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Route {
    pub destination: String,
    pub next_hop: String,
    pub interface: u32,
    pub metric: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Capability {
    pub source: String,
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FirewallProfile {
    pub name: String,
    pub enabled: String,
    pub inbound: String,
    pub outbound: String,
    pub allow_inbound_rules: String,
    pub allow_local_rules: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FirewallRule {
    pub id: String,
    pub name: String,
    pub source: String,
    pub source_type: String,
    pub enabled: bool,
    pub action: String,
    pub direction: String,
    pub profiles: Vec<String>,
    pub program: Vec<String>,
    pub service: Vec<String>,
    pub protocol: Vec<String>,
    pub local_ports: Vec<String>,
    pub remote_ports: Vec<String>,
    pub local_addresses: Vec<String>,
    pub remote_addresses: Vec<String>,
    pub interfaces: Vec<String>,
    pub interface_types: Vec<String>,
    pub unsupported: Vec<String>,
    pub complete: bool,
    pub enforcement: String,
    /// Owning user SID (per-user and AppContainer rules).
    pub owner: String,
    /// AppContainer package SID the rule is limited to.
    pub package: String,
    /// SDDL of local users/groups allowed by the rule.
    pub local_user: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Policy {
    pub collected_ms: u64,
    pub version: String,
    pub profiles: Vec<FirewallProfile>,
    pub rules: Vec<FirewallRule>,
    pub complete: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RawEvent {
    pub channel: String,
    pub provider: String,
    pub record_id: u64,
    pub event_id: u32,
    pub time_ms: u64,
    pub xml: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ProcessContext {
    pub pid: u32,
    pub created: Option<u64>,
    pub command_line: Option<String>,
    pub owner: Option<String>,
    pub path: Option<String>,
    /// Read natively inside the same identity check as `created`.
    pub token: Option<TokenIdentity>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct FilterEvidence {
    pub runtime_id: u64,
    pub queried_ms: u64,
    pub status: String,
    pub name: String,
    pub provider: String,
    pub layer: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DiagnosticData {
    pub schema: u32,
    pub started_ms: u64,
    pub finished_ms: u64,
    pub process: Option<ProcessContext>,
    pub services: Vec<Service>,
    pub interfaces: Vec<Interface>,
    pub routes: Vec<Route>,
    pub policy: Policy,
    pub events: Vec<RawEvent>,
    pub capabilities: Vec<Capability>,
    pub filters: Vec<FilterEvidence>,
    /// [start, count] of the TCP/UDP dynamic port ranges.
    pub tcp_dynamic_ports: Option<[u32; 2]>,
    pub udp_dynamic_ports: Option<[u32; 2]>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ipv6_scope_round_trip() {
        let a: SocketAddr = "[fe80::1%12]:5001".parse().unwrap();
        assert_eq!(
            serde_json::from_str::<SocketAddr>(&serde_json::to_string(&a).unwrap()).unwrap(),
            a
        );
        assert_ne!(a, "[fe80::1%13]:5001".parse::<SocketAddr>().unwrap());
    }
    #[test]
    fn malformed_endpoint_is_not_accepted() {
        for s in ["0.0.0.0:65536", "fe80::1:5001", "x:5001"] {
            assert!(s.parse::<SocketAddr>().is_err());
        }
    }
}
