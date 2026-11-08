//! IP Helper owner-PID tables. Buffers are initialized, capped, length checked,
//! and read unaligned by value; no references into Win32 variable-length arrays.
use crate::model::*;
use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};

#[derive(Default)]
pub struct InventoryCollector {
    system: Option<System>,
}
impl InventoryCollector {
    pub fn collect(&mut self) -> Inventory {
        let started_ms = now_ms();
        let mut result = Inventory {
            started_ms,
            ..Inventory::default()
        };
        if self.system.is_none() {
            self.system = System::new().ok();
        }
        if let Some(system) = &mut self.system {
            system.refresh_processes_specifics(
                ProcessesToUpdate::All,
                true,
                ProcessRefreshKind::nothing(),
            );
        } else {
            result
                .errors
                .push("Process names unavailable: system enumeration failed".into());
        }
        let mut owners = HashMap::new();
        for (protocol, ipv6, partition) in [
            (Protocol::Tcp, false, "TCP/IPv4"),
            (Protocol::Tcp, true, "TCP/IPv6"),
            (Protocol::Udp, false, "UDP/IPv4"),
            (Protocol::Udp, true, "UDP/IPv6"),
        ] {
            match native::table(protocol, ipv6) {
                Ok(rows) => {
                    result.successful_partitions.push(partition.into());
                    for (local, remote, state, pid) in rows {
                        let (key, details) = owners.entry(pid).or_insert_with(|| {
                            let (mut key, mut details) = native::process(pid);
                            // A process created after enumeration began cannot safely
                            // be attributed to rows from earlier in this sample.
                            if key.created.is_some_and(|t| filetime_ms(t) > started_ms) {
                                key.created = None;
                                details.path = None;
                                details.unavailable.push(
                                    "Process started during enumeration; ownership ambiguous"
                                        .into(),
                                );
                            }
                            if let Some(path) = &details.path {
                                details.name =
                                    path.rsplit(['\\', '/']).next().unwrap_or(path).into();
                            } else if key.created.is_some() {
                                details.name = self
                                    .system
                                    .as_ref()
                                    .and_then(|s| s.process(sysinfo::Pid::from_u32(pid)))
                                    .map(|p| p.name().to_string_lossy().into_owned())
                                    .unwrap_or_else(|| "Unknown".into());
                            }
                            (key, details)
                        });
                        result.connections.push(Connection {
                            key: ConnectionKey {
                                protocol,
                                local,
                                remote,
                                process: key.clone(),
                                ordinal: 0,
                            },
                            state,
                            process: details.clone(),
                            observed_ms: started_ms,
                            partition: partition.into(),
                        });
                    }
                }
                Err(e) => result.errors.push(format!("{partition}: {e}")),
            }
        }
        let mut duplicates = HashMap::<ConnectionKey, u32>::new();
        for c in &mut result.connections {
            let count = duplicates.entry(c.key.clone()).or_default();
            c.key.ordinal = *count;
            *count += 1;
        }
        result.finished_ms = now_ms();
        result
    }
}

pub fn filetime_ms(t: u64) -> u64 {
    t.saturating_sub(116_444_736_000_000_000) / 10_000
}

/// Exact native identity for revalidating slower CIM enrichment. CIM timestamps
/// can round sub-millisecond FILETIME digits and must not replace this key.
pub fn process_identity(pid: u32) -> ProcessKey {
    native::process(pid).0
}
type Row = (SocketAddr, Option<SocketAddr>, String, u32);

pub fn tcp_state(value: u32) -> String {
    match value {
        1 => "Closed",
        2 => "Listen",
        3 => "SynSent",
        4 => "SynReceived",
        5 => "Established",
        6 => "FinWait1",
        7 => "FinWait2",
        8 => "CloseWait",
        9 => "Closing",
        10 => "LastAck",
        11 => "TimeWait",
        12 => "DeleteTcb",
        _ => "Unknown",
    }
    .into()
}

/// Bounds validation is independent of Win32 and tested with malformed fixtures.
fn checked_rows(bytes: usize, count: usize, offset: usize, stride: usize) -> Result<(), String> {
    if count > 250_000
        || stride == 0
        || count
            .checked_mul(stride)
            .and_then(|n| offset.checked_add(n))
            .is_none_or(|end| end > bytes)
    {
        Err("Malformed/truncated IP Helper table".into())
    } else {
        Ok(())
    }
}

#[cfg(windows)]
mod native {
    use super::*;
    use std::{
        mem::{offset_of, size_of},
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::{CloseHandle, FILETIME, GetLastError},
        NetworkManagement::IpHelper::*,
        System::Threading::*,
    };

    pub(super) fn process(pid: u32) -> (ProcessKey, ProcessDetails) {
        let mut key = ProcessKey { pid, created: None };
        let mut details = ProcessDetails {
            name: "Unknown".into(),
            ..ProcessDetails::default()
        };
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if handle.is_null() {
                details.unavailable.push(format!(
                    "Process query unavailable (Windows {})",
                    GetLastError()
                ));
                return (key, details);
            }
            let mut created: FILETIME = std::mem::zeroed();
            let mut exit: FILETIME = std::mem::zeroed();
            let mut kernel: FILETIME = std::mem::zeroed();
            let mut user: FILETIME = std::mem::zeroed();
            if GetProcessTimes(handle, &mut created, &mut exit, &mut kernel, &mut user) != 0 {
                key.created = Some(
                    (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime),
                );
            } else {
                details.unavailable.push(format!(
                    "Creation time unavailable (Windows {})",
                    GetLastError()
                ));
            }
            let mut path = vec![0u16; 32_768];
            let mut len = path.len() as u32;
            if QueryFullProcessImageNameW(handle, 0, path.as_mut_ptr(), &mut len) != 0 {
                details.path = Some(String::from_utf16_lossy(&path[..len as usize]));
            } else {
                details.unavailable.push(format!(
                    "Executable path unavailable (Windows {})",
                    GetLastError()
                ));
            }
            CloseHandle(handle);
        }
        (key, details)
    }

    pub(super) fn table(protocol: Protocol, ipv6: bool) -> Result<Vec<Row>, String> {
        let family = if ipv6 { 23 } else { 2 };
        let query = |buffer: *mut std::ffi::c_void, size: &mut u32| unsafe {
            match protocol {
                Protocol::Tcp => {
                    GetExtendedTcpTable(buffer, size, 0, family, TCP_TABLE_OWNER_PID_ALL, 0)
                }
                Protocol::Udp => {
                    GetExtendedUdpTable(buffer, size, 0, family, UDP_TABLE_OWNER_PID, 0)
                }
            }
        };
        let mut size = 0;
        let status = query(ptr::null_mut(), &mut size);
        if status != 122 && status != 0 {
            return Err(format!("Windows {status}"));
        }
        for _ in 0..5 {
            if !(4..=32 * 1024 * 1024).contains(&size) {
                return Err("Invalid or excessive table buffer size".into());
            }
            let mut buffer = vec![0u64; (size as usize).div_ceil(8)];
            let mut written = (buffer.len() * 8) as u32;
            let status = query(buffer.as_mut_ptr().cast(), &mut written);
            if status == 122 {
                size = written;
                continue;
            }
            if status != 0 {
                return Err(format!("Windows {status}"));
            }
            if written < 4 || written as usize > buffer.len() * 8 {
                return Err("Invalid returned table size".into());
            }
            let pointer = buffer.as_ptr().cast::<u8>();
            // SAFETY: initialized buffer has at least four bytes; read by value.
            let count = unsafe { ptr::read_unaligned(pointer.cast::<u32>()) } as usize;
            let mut rows = Vec::with_capacity(count.min(100_000));
            macro_rules! read_rows {
                ($table:ty, $row:ty, $convert:expr) => {{
                    let offset = offset_of!($table, table);
                    checked_rows(written as usize, count, offset, size_of::<$row>())?;
                    for i in 0..count {
                        // SAFETY: checked complete row extent, no borrowed/aligned
                        // references are formed; OS owns no pointers in these rows.
                        let row = unsafe {
                            ptr::read_unaligned(
                                pointer.add(offset + i * size_of::<$row>()).cast::<$row>(),
                            )
                        };
                        rows.push(($convert)(row));
                    }
                }};
            }
            match (protocol, ipv6) {
                (Protocol::Tcp, false) => read_rows!(
                    MIB_TCPTABLE_OWNER_PID,
                    MIB_TCPROW_OWNER_PID,
                    |r: MIB_TCPROW_OWNER_PID| (
                        SocketAddr::new(
                            Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes()).into(),
                            u16::from_be(r.dwLocalPort as u16)
                        ),
                        Some(SocketAddr::new(
                            Ipv4Addr::from(r.dwRemoteAddr.to_ne_bytes()).into(),
                            u16::from_be(r.dwRemotePort as u16)
                        )),
                        tcp_state(r.dwState),
                        r.dwOwningPid
                    )
                ),
                (Protocol::Tcp, true) => read_rows!(
                    MIB_TCP6TABLE_OWNER_PID,
                    MIB_TCP6ROW_OWNER_PID,
                    |r: MIB_TCP6ROW_OWNER_PID| (
                        SocketAddr::V6(SocketAddrV6::new(
                            Ipv6Addr::from(r.ucLocalAddr),
                            u16::from_be(r.dwLocalPort as u16),
                            0,
                            r.dwLocalScopeId
                        )),
                        Some(SocketAddr::V6(SocketAddrV6::new(
                            Ipv6Addr::from(r.ucRemoteAddr),
                            u16::from_be(r.dwRemotePort as u16),
                            0,
                            r.dwRemoteScopeId
                        ))),
                        tcp_state(r.dwState),
                        r.dwOwningPid
                    )
                ),
                (Protocol::Udp, false) => read_rows!(
                    MIB_UDPTABLE_OWNER_PID,
                    MIB_UDPROW_OWNER_PID,
                    |r: MIB_UDPROW_OWNER_PID| (
                        SocketAddr::new(
                            Ipv4Addr::from(r.dwLocalAddr.to_ne_bytes()).into(),
                            u16::from_be(r.dwLocalPort as u16)
                        ),
                        None,
                        "Bound".into(),
                        r.dwOwningPid
                    )
                ),
                (Protocol::Udp, true) => read_rows!(
                    MIB_UDP6TABLE_OWNER_PID,
                    MIB_UDP6ROW_OWNER_PID,
                    |r: MIB_UDP6ROW_OWNER_PID| (
                        SocketAddr::V6(SocketAddrV6::new(
                            Ipv6Addr::from(r.ucLocalAddr),
                            u16::from_be(r.dwLocalPort as u16),
                            0,
                            r.dwLocalScopeId
                        )),
                        None,
                        "Bound".into(),
                        r.dwOwningPid
                    )
                ),
            }
            return Ok(rows);
        }
        Err("Table changed repeatedly; retry on next refresh".into())
    }
}

#[cfg(not(windows))]
mod native {
    use super::*;
    pub(super) fn table(_: Protocol, _: bool) -> Result<Vec<Row>, String> {
        Err("Windows required".into())
    }
    pub(super) fn process(pid: u32) -> (ProcessKey, ProcessDetails) {
        (ProcessKey { pid, created: None }, ProcessDetails::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounds_reject_truncation_overflow_and_zero_stride() {
        assert!(checked_rows(8, 1, 4, 4).is_ok());
        for (bytes, count, offset, stride) in [
            (7, 1, 4, 4),
            (8, usize::MAX, 4, 4),
            (8, 1, usize::MAX, 4),
            (8, 1, 4, 0),
        ] {
            assert!(checked_rows(bytes, count, offset, stride).is_err());
        }
    }
    #[test]
    fn timestamps_and_state_codes() {
        assert_eq!(filetime_ms(116_444_736_000_010_000), 1);
        assert_eq!(filetime_ms(0), 0);
        assert_eq!(tcp_state(2), "Listen");
        assert_eq!(tcp_state(5), "Established");
        assert_eq!(tcp_state(999), "Unknown");
    }
    #[cfg(windows)]
    #[test]
    fn owned_loopback_tcp_and_udp_are_enumerated_without_elevation() {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let inventory = InventoryCollector::default().collect();
        for (protocol, addr) in [
            (Protocol::Tcp, tcp.local_addr().unwrap()),
            (Protocol::Udp, udp.local_addr().unwrap()),
        ] {
            assert!(
                inventory.connections.iter().any(|c| c.key.local == addr
                    && c.key.protocol == protocol
                    && c.key.process.pid == std::process::id()),
                "{protocol} {addr}; {:?}",
                inventory.errors
            );
        }
    }
}
