//! Bounded on-demand collectors. No operating-system configuration mutations.
use crate::model::*;
use serde::Serialize;
use std::{
    io::{Read, Write},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

const SCRIPT: &str = include_str!("collectors/diagnose.ps1");
const MAX_OUTPUT: usize = 16 * 1024 * 1024;
pub type Cancellation = Arc<AtomicBool>;

/// Kill/reap this owned process tree, including early returns and unwind. Reader threads
/// bound retained bytes and drain pipes to avoid subprocess pipe deadlocks.
struct ChildGuard {
    process: std::process::Child,
    #[cfg(windows)]
    job: Option<OwnedJob>,
}
#[cfg(windows)]
struct OwnedJob(windows_sys::Win32::Foundation::HANDLE);
#[cfg(windows)]
impl OwnedJob {
    fn attach(child: &std::process::Child) -> Result<Self, String> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::{Foundation::*, System::JobObjects::*};
        // A fresh unnamed job contains only our just-created hidden collector.
        // Kill-on-close also closes inherited pipe handles in descendants.
        unsafe {
            let handle = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if handle.is_null() {
                return Err(format!(
                    "Collector containment unavailable: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let job = Self(handle);
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
            ) == 0
                || AssignProcessToJobObject(handle, child.as_raw_handle().cast()) == 0
            {
                let error = GetLastError();
                drop(job);
                return Err(format!(
                    "Cannot contain diagnostic process tree (Windows {error}); collector stopped"
                ));
            }
            Ok(job)
        }
    }
}
#[cfg(windows)]
impl Drop for OwnedJob {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}
impl ChildGuard {
    fn stop(&mut self) {
        #[cfg(windows)]
        self.job.take();
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

fn read_bounded(mut stream: impl Read, limit: usize) -> Result<Vec<u8>, String> {
    let mut kept = Vec::new();
    let mut buffer = [0u8; 8192];
    let mut overflow = false;
    loop {
        let n = stream.read(&mut buffer).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        if kept.len().saturating_add(n) > limit {
            overflow = true;
        } else if !overflow {
            kept.extend_from_slice(&buffer[..n]);
        }
    }
    if overflow {
        Err(format!("Collector output exceeded {limit} bytes"))
    } else {
        Ok(kept)
    }
}
fn command(script: &str) -> Command {
    let mut command = Command::new("powershell.exe");
    command.args([
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        script,
    ]);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    command
}
fn run(
    script: &str,
    input: &[u8],
    cancel: &AtomicBool,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    if cancel.load(Ordering::Relaxed) {
        return Err("Cancelled".into());
    }
    let mut child = ChildGuard {
        process: command(script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("PowerShell unavailable: {e}"))?,
        #[cfg(windows)]
        job: None,
    };
    #[cfg(windows)]
    {
        child.job = Some(OwnedJob::attach(&child.process)?);
    }
    let stdout = child.process.stdout.take().ok_or("Missing stdout")?;
    let stderr = child.process.stderr.take().ok_or("Missing stderr")?;
    let out = std::thread::spawn(move || read_bounded(stdout, MAX_OUTPUT));
    let err = std::thread::spawn(move || read_bounded(stderr, 64 * 1024));
    {
        let mut stdin = child.process.stdin.take().ok_or("Missing stdin")?;
        stdin.write_all(input).map_err(|e| e.to_string())?;
    }
    let start = Instant::now();
    let status = loop {
        if cancel.load(Ordering::Relaxed) || start.elapsed() > timeout {
            child.stop();
            let _ = out.join();
            let _ = err.join();
            return Err(if cancel.load(Ordering::Relaxed) {
                "Cancelled"
            } else {
                "Diagnostic deadline exceeded; owned collector stopped"
            }
            .into());
        }
        if let Some(status) = child.process.try_wait().map_err(|e| e.to_string())? {
            break status;
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    child.stop();
    let output = out.join().map_err(|_| "Output reader failed")??;
    let errors = err.join().map_err(|_| "Error reader failed")??;
    if !status.success() {
        return Err(format!(
            "Collector exited {status}: {}",
            String::from_utf8_lossy(&errors)
        ));
    }
    Ok(output)
}

#[derive(Default)]
pub struct DiagnosticCollector {
    cached_policy: Option<Policy>,
    cached_capabilities: Vec<Capability>,
}
impl DiagnosticCollector {
    pub fn collect(
        &mut self,
        selected: &Connection,
        expected_service: &str,
        force_policy: bool,
        cancel: &AtomicBool,
    ) -> Result<DiagnosticData, String> {
        if expected_service.len() > 256 {
            return Err("Service name exceeds 256 bytes".into());
        }
        let before = crate::inventory::process_identity(selected.key.process.pid);
        let cached = self
            .cached_policy
            .as_ref()
            .filter(|p| !force_policy && now_ms().saturating_sub(p.collected_ms) < 60_000);
        #[derive(Serialize)]
        struct Request<'a> {
            pid: u32,
            expected_service: &'a str,
            include_policy: bool,
        }
        let request = serde_json::to_vec(&Request {
            pid: selected.key.process.pid,
            expected_service,
            include_policy: cached.is_none(),
        })
        .map_err(|e| e.to_string())?;
        let bytes = run(SCRIPT, &request, cancel, Duration::from_secs(90))?;
        let mut data = decode(&bytes)?;
        if data.policy.collected_ms > 0 {
            data.policy.rules.sort_by(|a, b| a.id.cmp(&b.id));
            data.policy.profiles.sort_by(|a, b| a.name.cmp(&b.name));
            let content = serde_json::to_vec(&(&data.policy.profiles, &data.policy.rules))
                .map_err(|e| e.to_string())?;
            // Stable content identity, not a cryptographic integrity claim.
            let hash = content.iter().fold(0xcbf29ce484222325u64, |h, b| {
                (h ^ u64::from(*b)).wrapping_mul(0x100000001b3)
            });
            data.policy.version = format!("{hash:016x}");
        }
        if let Some(policy) = cached {
            data.policy = policy.clone();
            for mut cap in self.cached_capabilities.clone() {
                cap.detail = format!("Cached at {} ms UTC. {}", policy.collected_ms, cap.detail);
                data.capabilities.push(cap);
            }
        } else if data.policy.collected_ms > 0 {
            self.cached_policy = Some(data.policy.clone());
            self.cached_capabilities = data
                .capabilities
                .iter()
                .filter(|c| c.source == "Firewall" || c.source.starts_with("Get-NetFirewall"))
                .cloned()
                .collect();
        }
        // Never attach a reused PID's command line/account/service membership.
        let after = crate::inventory::process_identity(selected.key.process.pid);
        let identity_matches = data.process.as_ref().is_some_and(|p| {
            enrichment_identity_matches(&selected.key.process, &before, &after, p)
        });
        if identity_matches && let Some(p) = &mut data.process {
            p.created = selected.key.process.created;
        }
        if !identity_matches {
            data.process = None;
            data.services
                .retain(|s| s.name.eq_ignore_ascii_case(expected_service) && s.state == "Stopped");
            data.capabilities.push(Capability{source:"Process identity".into(),status:"Ambiguous".into(),detail:"Selected process exited, access is restricted, or creation identity changed; details were discarded.".into()});
        }
        let ids: std::collections::BTreeSet<_> = data
            .events
            .iter()
            .filter_map(|r| crate::evidence::network_event(r).ok())
            .filter(|e| e.pid == Some(selected.key.process.pid))
            .filter_map(|e| e.filter_id)
            .collect();
        for id in ids.into_iter().take(16) {
            if cancel.load(Ordering::Relaxed) {
                return Err("Cancelled".into());
            }
            data.filters.push(crate::wfp::filter(id));
        }
        Ok(data)
    }
}

fn enrichment_identity_matches(
    selected: &ProcessKey,
    before: &ProcessKey,
    after: &ProcessKey,
    context: &ProcessContext,
) -> bool {
    selected.created.is_some()
        && selected == before
        && selected == after
        && context.pid == selected.pid
        && selected
            .created
            .zip(context.created)
            .is_some_and(|(native, cim)| native.abs_diff(cim) <= 10_000)
}
pub fn decode(bytes: &[u8]) -> Result<DiagnosticData, String> {
    if bytes.len() > MAX_OUTPUT {
        return Err("Diagnostic output exceeds limit".into());
    }
    let data: DiagnosticData =
        serde_json::from_slice(bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes))
            .map_err(|e| format!("Invalid diagnostic response: {e}"))?;
    if data.schema != 1 {
        return Err("Unsupported diagnostic schema".into());
    }
    if data.policy.rules.len() > 20000
        || data.events.len() > 1200
        || data.interfaces.len() > 256
        || data.routes.len() > 4096
    {
        return Err("Diagnostic record limit exceeded".into());
    }
    Ok(data)
}

pub fn resolve_dns(name: &str, cancel: &AtomicBool) -> Result<Vec<String>, String> {
    if name.len() > 253
        || name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return Err("Enter a DNS hostname (letters, digits, dot, hyphen)".into());
    }
    // Fixed script; hostname remains JSON input. This is explicit network activity.
    let script = r#"$ErrorActionPreference='Stop';[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false);$name=[Console]::In.ReadToEnd()|ConvertFrom-Json;@([System.Net.Dns]::GetHostAddresses([string]$name)|ForEach-Object{$_.IPAddressToString})|ConvertTo-Json -Compress"#;
    let bytes = run(
        script,
        &serde_json::to_vec(name).map_err(|e| e.to_string())?,
        cancel,
        Duration::from_secs(10),
    )?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    match v {
        serde_json::Value::String(s) => Ok(vec![s]),
        serde_json::Value::Array(a) => Ok(a
            .into_iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect()),
        _ => Err("DNS returned no addresses".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn enrichment_accepts_cim_rounding_but_not_pid_reuse() {
        let key = ProcessKey {
            pid: 42,
            created: Some(116_444_736_000_123_456),
        };
        let mut context = ProcessContext {
            pid: 42,
            created: Some(116_444_736_000_120_000),
            ..ProcessContext::default()
        };
        assert!(enrichment_identity_matches(&key, &key, &key, &context));
        let reused = ProcessKey {
            pid: 42,
            created: Some(116_444_736_100_000_000),
        };
        assert!(!enrichment_identity_matches(&key, &key, &reused, &context));
        context.created = None;
        assert!(!enrichment_identity_matches(&key, &key, &key, &context));
    }
    #[test]
    fn output_limits_and_schema() {
        assert!(read_bounded(&b"12345"[..], 4).is_err());
        assert_eq!(read_bounded(&b"1234"[..], 4).unwrap(), b"1234");
        assert!(decode(b"{}").is_err());
        assert!(decode(b"not json").is_err());
        assert!(decode(b"{\"schema\":99}").is_err());
        assert!(decode(b"{\"schema\":1}").is_ok());
    }
    #[test]
    fn script_has_no_mutating_commands() {
        let lower = SCRIPT.to_lowercase();
        for banned in [
            "set-netfirewall",
            "new-netfirewall",
            "remove-netfirewall",
            "set-netconnection",
            "set-audit",
            "start-service",
            "stop-service",
            "restart-service",
            "/set ",
            "fwpmenginesetoption",
        ] {
            assert!(!lower.contains(banned), "{banned}");
        }
    }
    #[test]
    fn dns_rejects_command_injection_before_spawning() {
        for value in ["x;whoami", "$(whoami)", "a\nb", "", "a/b"] {
            assert!(resolve_dns(value, &AtomicBool::new(false)).is_err());
        }
    }
    #[test]
    fn cancelled_request_does_not_spawn() {
        assert_eq!(
            run(
                "throw 'must not run'",
                b"",
                &AtomicBool::new(true),
                Duration::from_secs(1)
            )
            .unwrap_err(),
            "Cancelled"
        );
    }
    #[cfg(windows)]
    #[test]
    fn subprocess_deadline_and_output_errors() {
        assert!(
            run(
                "Start-Sleep -Seconds 10",
                b"",
                &AtomicBool::new(false),
                Duration::from_millis(200)
            )
            .unwrap_err()
            .contains("deadline")
        );
        assert!(
            run(
                "exit 7",
                b"",
                &AtomicBool::new(false),
                Duration::from_secs(10)
            )
            .is_err()
        );
    }
    #[cfg(windows)]
    #[test]
    fn cancellation_stops_an_active_owned_collector() {
        let cancel = Arc::new(AtomicBool::new(false));
        let flag = cancel.clone();
        let trigger = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(250));
            flag.store(true, Ordering::Relaxed);
        });
        let result = run(
            "Start-Sleep -Seconds 10",
            b"",
            &cancel,
            Duration::from_secs(15),
        );
        trigger.join().unwrap();
        assert_eq!(result.unwrap_err(), "Cancelled");
    }
    #[cfg(windows)]
    #[test]
    fn collector_job_closes_descendants_on_normal_exit() {
        let script = "$p=Start-Process -FilePath powershell.exe -ArgumentList @('-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30') -WindowStyle Hidden -PassThru; [Console]::Write($p.Id)";
        let bytes = run(
            script,
            b"",
            &AtomicBool::new(false),
            Duration::from_secs(10),
        )
        .unwrap();
        let pid = String::from_utf8(bytes)
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap();
        use windows_sys::Win32::{Foundation::*, System::Threading::*};
        unsafe {
            let handle = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                pid,
            );
            if !handle.is_null() {
                let wait = WaitForSingleObject(handle, 5000);
                let mut code = 0;
                assert_ne!(GetExitCodeProcess(handle, &mut code), 0);
                CloseHandle(handle);
                assert_eq!(
                    wait, WAIT_OBJECT_0,
                    "Owned descendant did not terminate within the cleanup deadline"
                );
                assert_ne!(
                    code, 259,
                    "Owned descendant must not survive collector completion"
                );
            }
        }
    }
}
