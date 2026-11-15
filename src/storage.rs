//! Versioned local workflows. Export uses an allowlist, not string replacement
//! over arbitrary event/command text. Sensitive raw fields are never serialized
//! into the default shareable report.
use crate::{
    diagnostics::{Analysis, Certainty},
    model::*,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const MAX_FILE: u64 = 16 * 1024 * 1024;
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SavedView {
    pub name: String,
    pub filter: String,
    pub sort_column: Option<usize>,
    pub descending: bool,
    pub expected_service: String,
    pub expected_port: String,
    pub peer: String,
    pub local: String,
    pub direction: String,
    pub interface: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Preferences {
    pub schema: u32,
    pub views: Vec<SavedView>,
}
impl Default for Preferences {
    fn default() -> Self {
        Self {
            schema: 1,
            views: Vec::new(),
        }
    }
}
impl Preferences {
    pub fn save_view(&mut self, view: SavedView) -> Result<(), String> {
        if view.name.trim().is_empty() || view.name.len() > 128 || view.filter.len() > 4096 {
            return Err("View needs a name (up to 128 characters) and a bounded filter".into());
        }
        if let Some(existing) = self.views.iter_mut().find(|v| v.name == view.name) {
            *existing = view;
        } else {
            if self.views.len() >= 100 {
                return Err("Saved view limit (100) reached".into());
            }
            self.views.push(view);
        }
        Ok(())
    }
}
pub fn default_directory() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("EasyNetstat")
}
pub fn preferences_path() -> PathBuf {
    default_directory().join("views.json")
}
pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let f = std::fs::File::open(path).map_err(|e| e.to_string())?;
    if f.metadata().map_err(|e| e.to_string())?.len() > MAX_FILE {
        return Err("File exceeds 16 MiB limit".into());
    }
    let mut bytes = Vec::new();
    f.take(MAX_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_FILE {
        return Err("File exceeds limit".into());
    }
    serde_json::from_slice(&bytes).map_err(|e| format!("Invalid file: {e}"))
}
pub fn load_preferences(path: &Path) -> Result<Preferences, String> {
    let p: Preferences = read_json(path)?;
    if p.schema != 1 || p.views.len() > 100 {
        return Err("Unsupported or excessive saved views".into());
    }
    for v in &p.views {
        if v.name.len() > 128 || v.filter.len() > 4096 || v.sort_column.is_some_and(|c| c > 5) {
            return Err("Invalid saved view".into());
        }
    }
    Ok(p)
}
/// Atomically replace only app-owned preferences. Other exports use create-new.
pub fn save_preferences(path: &Path, p: &Preferences) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
    let bytes = serde_json::to_vec_pretty(p).map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_FILE {
        return Err("Preferences exceed limit".into());
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(|e| e.to_string())?;
    let outcome = (|| {
        f.write_all(&bytes).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
        drop(f);
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            use windows_sys::Win32::Storage::FileSystem::{
                MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
            };
            let a: Vec<_> = tmp.as_os_str().encode_wide().chain(Some(0)).collect();
            let b: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            if unsafe {
                MoveFileExW(
                    a.as_ptr(),
                    b.as_ptr(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error().to_string());
            }
        }
        #[cfg(not(windows))]
        std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
        Ok(())
    })();
    if outcome.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    outcome
}
pub fn write_new(path: &Path, text: &str) -> Result<(), String> {
    if text.len() as u64 > MAX_FILE {
        return Err("Export exceeds 16 MiB limit".into());
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("Cannot create export (existing files are preserved): {e}"))?;
    if let Err(e) = f.write_all(text.as_bytes()).and_then(|_| f.sync_all()) {
        drop(f);
        let _ = std::fs::remove_file(path);
        return Err(e.to_string());
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub schema: u32,
    pub session: String,
    pub captured_ms: u64,
    pub connections: Vec<Connection>,
    pub errors: Vec<String>,
    #[serde(default)]
    pub policy: Option<Policy>,
    #[serde(default)]
    pub interfaces: Vec<Interface>,
    #[serde(default)]
    pub routes: Vec<Route>,
}
impl Snapshot {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != 1
            || self.connections.len() > 100_000
            || self.session.len() > 256
            || self.policy.as_ref().is_some_and(|p| p.rules.len() > 20000)
            || self.interfaces.len() > 256
            || self.routes.len() > 4096
        {
            return Err("Unsupported or excessive snapshot".into());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotDiff {
    pub added: usize,
    pub removed: usize,
    pub changed: usize,
    pub comparable: bool,
    pub policy_changed: Option<bool>,
    pub network_changed: Option<bool>,
}
pub fn diff(before: &Snapshot, after: &Snapshot) -> SnapshotDiff {
    let comparable =
        before.session == after.session && before.errors.is_empty() && after.errors.is_empty();
    let old: HashSet<_> = before.connections.iter().map(|c| &c.key).collect();
    let new: HashSet<_> = after.connections.iter().map(|c| &c.key).collect();
    let states: HashMap<_, _> = before
        .connections
        .iter()
        .map(|c| (&c.key, &c.state))
        .collect();
    let known = |k: &&ConnectionKey| k.process.created.is_some() && comparable;
    SnapshotDiff {
        added: after
            .connections
            .iter()
            .filter(|c| !known(&&c.key) || !old.contains(&c.key))
            .count(),
        removed: before
            .connections
            .iter()
            .filter(|c| !known(&&c.key) || !new.contains(&c.key))
            .count(),
        changed: after
            .connections
            .iter()
            .filter(|c| {
                comparable
                    && c.key.process.created.is_some()
                    && states.get(&c.key).is_some_and(|state| **state != c.state)
            })
            .count(),
        comparable,
        policy_changed: before
            .policy
            .as_ref()
            .zip(after.policy.as_ref())
            .map(|(a, b)| a.version != b.version),
        network_changed: if before.interfaces.is_empty() || after.interfaces.is_empty() {
            None
        } else {
            let normalize = |items: &[Interface]| {
                let mut items: Vec<_> = items
                    .iter()
                    .map(|i| {
                        let mut a = i.addresses.clone();
                        a.sort();
                        let mut dns = i.dns.clone();
                        dns.sort();
                        format!("{}:{:?}:{:?}:{}", i.index, a, dns, i.profile)
                    })
                    .collect();
                items.sort();
                items
            };
            Some(normalize(&before.interfaces) != normalize(&after.interfaces))
        },
    }
}

pub fn report(analysis: &Analysis, data: &DiagnosticData) -> String {
    // Default export intentionally excludes arbitrary titles/explanations, rule
    // names/IDs, paths, addresses, account/command fields and raw event XML.
    let mut out = format!(
        "# Network diagnostic report (redacted)\n\nEvaluator: {}\nCollected: {}–{} ms UTC\n\n",
        analysis.evaluator_version, data.started_ms, data.finished_ms
    );
    for class in [
        Certainty::ConfirmedFailure,
        Certainty::Inferred,
        Certainty::Observed,
    ] {
        let n = analysis
            .findings
            .iter()
            .filter(|f| f.certainty == class)
            .count();
        out.push_str(&format!("- {class}: {n} finding(s)\n"));
    }
    out.push_str("\n## Findings\n\n");
    let mut evidence_ids = HashMap::<String, usize>::new();
    for (i, f) in analysis.findings.iter().enumerate() {
        // IDs are reduced to internal rule family; suffixes can contain rule IDs.
        let family = f.id.split(':').next().unwrap_or("finding");
        let description = match family {
            "connection.observed" => "Endpoint observed; reachability unconfirmed.",
            "binding.port" => "Observed local port differs from supplied expectation.",
            "binding.loopback" => "Local-only loopback binding observed.",
            "service.shared" => "Multiple services share the observed process.",
            "service.expected" => "Expected service status was inspected.",
            "service.stopped" => "Stopped expected service may affect communication.",
            "wfp.block" => {
                "A recorded WFP block matched the examined tuple and revalidated process lifetime."
            }
            "wfp.unattributed" => "Block tuple matched; process attribution is unverified.",
            "wfp.permit" => "A permit event was recorded; delivery is unconfirmed.",
            "system.context" => {
                "A relevant service/process event was found; causation is unconfirmed."
            }
            "network.local-address" => {
                "The scenario local address was absent from collected interface context; verify inputs/virtual adapters."
            }
            "network.route" => {
                "No candidate route covered the examined peer in the queried context; packet failure is unconfirmed."
            }
            "policy.mismatch" => {
                "A candidate rule has a condition mismatch; this alone does not confirm a block."
            }
            "policy.summary" => {
                "Firewall analysis covers a supported subset and cannot guarantee packet passage."
            }
            _ => "Diagnostic finding; details omitted by redaction.",
        };
        let refs = f
            .evidence
            .iter()
            .map(|source| {
                let next = evidence_ids.len() + 1;
                format!("E{}", evidence_ids.entry(source.clone()).or_insert(next))
            })
            .collect::<Vec<_>>();
        out.push_str(&format!(
            "{}. **{}** — {} Evidence: {}. Observed/collected {} ms UTC.\n",
            i + 1,
            f.certainty,
            description,
            refs.join(", "),
            f.time_ms,
        ));
    }
    out.push_str("\n## Policy condition results (anonymous candidates)\n\n");
    for (index, rule) in analysis.rules.iter().take(50).enumerate() {
        let action = match rule.action.as_str() {
            "Allow" => "Allow",
            "Block" => "Block",
            _ => "Other/unknown",
        };
        out.push_str(&format!(
            "- Candidate {}: {} / {}",
            index + 1,
            action,
            rule.result
        ));
        for condition in &rule.conditions {
            let safe_name = match condition.name.as_str() {
                "Enabled" => "Enabled",
                "Direction" => "Direction",
                "Program" => "Program",
                "Service" => "Service",
                "Protocol" => "Protocol",
                "Local port" => "Local port",
                "Remote port" => "Remote port",
                "Local address" => "Local address",
                "Remote address" => "Remote address",
                "Profile" => "Profile",
                "Interface" => "Interface",
                "Interface type" => "Interface type",
                "Coverage" => "Coverage",
                _ => "Other condition",
            };
            if condition.result != crate::firewall::Match::Match {
                out.push_str(&format!("; {safe_name}: {}", condition.result));
            }
        }
        out.push('\n');
    }
    out.push_str("\nProcess arguments, environment, paths, accounts, hostnames, endpoint addresses, rule names and raw events are excluded. No OS settings were changed. Missing events do not prove absence of a block. Review full evidence locally.\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn redaction_does_not_leak_embedded_sensitive_strings() {
        let secret = "customer-secret 10.1.2.3 C:\\Secret\\IFC8.exe password=abc";
        let a = Analysis {
            evaluator_version: 1,
            findings: vec![crate::diagnostics::Finding {
                id: format!("policy.mismatch:{secret}"),
                certainty: Certainty::Inferred,
                title: secret.into(),
                explanation: secret.into(),
                evidence: vec![secret.into()],
                assumptions: vec![secret.into()],
                follow_up: secret.into(),
                time_ms: 1,
            }],
            rules: vec![],
            verdict: None,
        };
        let mut d = DiagnosticData::default();
        d.events.push(RawEvent {
            xml: secret.into(),
            ..RawEvent::default()
        });
        let r = report(&a, &d);
        for s in ["customer-secret", "10.1.2.3", "password=abc", "Secret"] {
            assert!(!r.contains(s));
        }
        assert!(r.contains("condition mismatch"));
    }
    #[test]
    fn profile_limits_and_versions() {
        let mut p = Preferences::default();
        assert!(p.save_view(SavedView::default()).is_err());
        p.save_view(SavedView {
            name: "IFC8".into(),
            filter: "local:5001".into(),
            ..SavedView::default()
        })
        .unwrap();
        p.save_view(SavedView {
            name: "IFC8".into(),
            filter: "proc:ifc8".into(),
            ..SavedView::default()
        })
        .unwrap();
        assert_eq!(p.views.len(), 1);
        let json = serde_json::to_vec(&p).unwrap();
        let q: Preferences = serde_json::from_slice(&json).unwrap();
        assert_eq!(q.views[0].filter, "proc:ifc8");
    }
    #[test]
    fn snapshots_do_not_merge_pid_reuse() {
        let mut a = Snapshot {
            schema: 1,
            session: "same session".into(),
            captured_ms: 1,
            connections: vec![crate::state::connection(42, Some(1), "Listen")],
            errors: vec![],
            policy: None,
            interfaces: vec![],
            routes: vec![],
        };
        let mut b = a.clone();
        b.connections[0].key.process.created = Some(2);
        assert_eq!(
            diff(&a, &b),
            SnapshotDiff {
                added: 1,
                removed: 1,
                changed: 0,
                comparable: true,
                policy_changed: None,
                network_changed: None,
            }
        );
        a.session = "other".into();
        assert!(!diff(&a, &b).comparable);
    }
    #[test]
    fn export_does_not_overwrite_and_atomic_preferences_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "easy-netstat-test-{}-{}",
            std::process::id(),
            now_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("report.md");
        write_new(&path, "one").unwrap();
        assert!(write_new(&path, "two").is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "one");
        let pref = dir.join("views.json");
        save_preferences(&pref, &Preferences::default()).unwrap();
        save_preferences(&pref, &Preferences::default()).unwrap();
        assert_eq!(load_preferences(&pref).unwrap().schema, 1);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(pref).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }
    #[test]
    fn snapshot_schema_and_network_policy_differences_are_explicit() {
        let mut a = Snapshot {
            schema: 1,
            session: "session".into(),
            captured_ms: 1,
            connections: vec![],
            errors: vec![],
            policy: Some(Policy {
                version: "one".into(),
                ..Policy::default()
            }),
            interfaces: vec![Interface {
                index: 1,
                profile: "Domain".into(),
                ..Interface::default()
            }],
            routes: vec![],
        };
        let mut b = a.clone();
        b.policy.as_mut().unwrap().version = "two".into();
        b.interfaces[0].profile = "Public".into();
        let d = diff(&a, &b);
        assert_eq!(d.policy_changed, Some(true));
        assert_eq!(d.network_changed, Some(true));
        a.schema = 99;
        assert!(a.validate().is_err());
        assert!(serde_json::from_str::<Snapshot>("{\"schema\":1,\"session\":\"s\",\"captured_ms\":0,\"connections\":[],\"errors\":[]}").unwrap().validate().is_ok());
    }
}
