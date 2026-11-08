#![cfg(windows)]
//! Read-only endpoint integration tests. No firewall/audit/service settings are
//! changed. Temporary loopback sockets and owned PowerShell processes are closed.
use easy_netstat::{collectors::DiagnosticCollector, inventory::InventoryCollector};
use std::sync::atomic::AtomicBool;

#[test]
fn on_demand_windows_collector_returns_versioned_capabilities() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let sample = InventoryCollector::default().collect();
    let selected = sample
        .connections
        .iter()
        .find(|c| {
            c.key.local == listener.local_addr().unwrap() && c.key.process.pid == std::process::id()
        })
        .expect("Owned TCP endpoint must be enumerated");
    let data = DiagnosticCollector::default()
        .collect(selected, "", true, &AtomicBool::new(false))
        .expect(
            "Read-only collector must emit structured data, including unavailable capabilities",
        );
    assert_eq!(data.schema, 1);
    assert!(data.finished_ms >= data.started_ms);
    for source in [
        "Process",
        "Services",
        "Network",
        "Routes",
        "Firewall",
        "Audit policy",
        "WFP Security events",
    ] {
        assert!(
            data.capabilities.iter().any(|c| c.source == source),
            "Missing capability {source}"
        );
    }
    for cap in &data.capabilities {
        eprintln!("{}: {}", cap.source, cap.status);
    }
    if data
        .capabilities
        .iter()
        .any(|c| c.source == "Process" && c.status == "Available")
    {
        assert!(
            data.process.is_some(),
            "Own-process native/CIM identity must revalidate without false PID-reuse rejection"
        );
    }
    if data.policy.collected_ms > 0 {
        assert!(!data.policy.profiles.is_empty());
        if data
            .capabilities
            .iter()
            .any(|c| c.source == "Get-NetFirewallApplicationFilter" && c.status == "Available")
            && !data.policy.rules.is_empty()
        {
            assert!(
                data.policy.rules.iter().any(|r| !r.program.is_empty()),
                "Filter InstanceID association must retain application data"
            );
        }
    }
    if let Some(p) = data.process {
        assert_eq!(p.pid, std::process::id());
        assert_eq!(p.created, selected.key.process.created);
    }
}

#[test]
fn ipv6_loopback_retains_family_and_ports() {
    let tcp = std::net::TcpListener::bind("[::1]:0")
        .expect("IPv6 loopback required for this endpoint test");
    let udp = std::net::UdpSocket::bind("[::1]:0").unwrap();
    let sample = InventoryCollector::default().collect();
    for address in [tcp.local_addr().unwrap(), udp.local_addr().unwrap()] {
        assert!(
            sample
                .connections
                .iter()
                .any(|c| c.key.local == address && c.key.process.pid == std::process::id()),
            "Missing {address}"
        );
    }
}
