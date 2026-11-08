use crate::model::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

/// Completion IDs prevent late/cancelled requests from replacing current data.
#[derive(Debug, Default)]
pub struct JobGate {
    next: u64,
    active: Option<u64>,
    pending: bool,
}
impl JobGate {
    pub fn request(&mut self) -> Option<u64> {
        if self.active.is_some() {
            self.pending = true;
            return None;
        }
        self.next += 1;
        self.active = Some(self.next);
        Some(self.next)
    }
    pub fn finish(&mut self, id: u64) -> Option<bool> {
        if self.active != Some(id) {
            return None;
        }
        self.active = None;
        Some(std::mem::take(&mut self.pending))
    }
    pub fn busy(&self) -> bool {
        self.active.is_some()
    }
    pub fn clear_pending(&mut self) {
        self.pending = false;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Change {
    pub time_ms: u64,
    pub key: ConnectionKey,
    pub kind: String,
    pub before: String,
    pub after: String,
}

#[derive(Debug)]
pub struct History {
    pub current: Vec<Connection>,
    pub changes: VecDeque<Change>,
    pub last_success_ms: Option<u64>,
    pub errors: Vec<String>,
    pub evicted: u64,
    max_records: usize,
    max_bytes: usize,
    ttl_ms: u64,
    bytes: usize,
}
impl Default for History {
    fn default() -> Self {
        Self::new(50_000, 32 * 1024 * 1024, 15 * 60 * 1000)
    }
}
impl History {
    pub fn new(max_records: usize, max_bytes: usize, ttl_ms: u64) -> Self {
        Self {
            current: Vec::new(),
            changes: VecDeque::new(),
            last_success_ms: None,
            errors: Vec::new(),
            evicted: 0,
            max_records,
            max_bytes,
            ttl_ms,
            bytes: 0,
        }
    }
    pub fn apply(&mut self, sample: Inventory) {
        self.errors = sample.errors;
        let partitions: HashSet<_> = sample
            .successful_partitions
            .iter()
            .map(String::as_str)
            .collect();
        if partitions.is_empty() {
            return;
        }
        let old: HashMap<_, _> = self
            .current
            .iter()
            .map(|c| (c.key.clone(), c.clone()))
            .collect();
        let mut next: HashMap<_, _> = self
            .current
            .iter()
            .filter(|c| !partitions.contains(c.partition.as_str()))
            .map(|c| (c.key.clone(), c.clone()))
            .collect();
        for c in sample.connections {
            if !partitions.contains(c.partition.as_str()) {
                continue;
            }
            let previous = old.get(&c.key).filter(|_| c.key.process.created.is_some());
            match previous {
                None => self.push(Change {
                    time_ms: sample.finished_ms,
                    key: c.key.clone(),
                    kind: "First observed (continuity unverified)".into(),
                    before: String::new(),
                    after: c.state.clone(),
                }),
                Some(p) if p.state != c.state => self.push(Change {
                    time_ms: sample.finished_ms,
                    key: c.key.clone(),
                    kind: "Sampled state change".into(),
                    before: p.state.clone(),
                    after: c.state.clone(),
                }),
                _ => {}
            }
            next.insert(c.key.clone(), c);
        }
        for (key, c) in &old {
            if partitions.contains(c.partition.as_str()) && !next.contains_key(key) {
                self.push(Change {
                    time_ms: sample.finished_ms,
                    key: key.clone(),
                    kind: "Not present in successful sample (not proof of closure)".into(),
                    before: c.state.clone(),
                    after: String::new(),
                });
            }
        }
        self.current = next.into_values().collect();
        self.current.sort_by(|a, b| {
            a.key
                .local
                .cmp(&b.key.local)
                .then(a.key.process.pid.cmp(&b.key.process.pid))
                .then(a.key.ordinal.cmp(&b.key.ordinal))
        });
        self.last_success_ms = Some(sample.finished_ms);
        self.prune(sample.finished_ms);
    }
    fn cost(c: &Change) -> usize {
        std::mem::size_of::<Change>() + c.kind.len() + c.before.len() + c.after.len()
    }
    fn push(&mut self, change: Change) {
        self.bytes += Self::cost(&change);
        self.changes.push_back(change);
    }
    pub fn prune(&mut self, time: u64) {
        while self
            .changes
            .front()
            .is_some_and(|c| time.saturating_sub(c.time_ms) > self.ttl_ms)
            || self.changes.len() > self.max_records
            || self.bytes > self.max_bytes
        {
            if let Some(c) = self.changes.pop_front() {
                self.bytes = self.bytes.saturating_sub(Self::cost(&c));
                self.evicted += 1;
            } else {
                break;
            }
        }
    }
}

pub fn valid_interval(text: &str) -> Option<u64> {
    text.parse::<u64>().ok().filter(|n| (1..=3600).contains(n))
}

#[cfg(test)]
pub fn connection(pid: u32, created: Option<u64>, state: &str) -> Connection {
    Connection {
        key: ConnectionKey {
            protocol: Protocol::Tcp,
            local: "0.0.0.0:5001".parse().unwrap(),
            remote: None,
            process: ProcessKey { pid, created },
            ordinal: 0,
        },
        state: state.into(),
        process: ProcessDetails::default(),
        observed_ms: 1,
        partition: "TCP/IPv4".into(),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn sample(c: Vec<Connection>, ok: bool, time: u64) -> Inventory {
        Inventory {
            connections: c,
            finished_ms: time,
            successful_partitions: if ok { vec!["TCP/IPv4".into()] } else { vec![] },
            errors: if ok { vec![] } else { vec!["Denied".into()] },
            ..Inventory::default()
        }
    }
    #[test]
    fn gate_coalesces_and_rejects_stale() {
        let mut g = JobGate::default();
        let a = g.request().unwrap();
        assert!(g.request().is_none());
        assert_eq!(g.finish(a + 1), None);
        assert!(g.busy());
        assert_eq!(g.finish(a), Some(true));
        let b = g.request().unwrap();
        assert_ne!(a, b);
        assert_eq!(g.finish(a), None);
        assert_eq!(g.finish(b), Some(false));
    }
    #[test]
    fn pause_clears_queued_refresh() {
        let mut g = JobGate::default();
        let id = g.request().unwrap();
        g.request();
        g.clear_pending();
        assert_eq!(g.finish(id), Some(false));
    }
    #[test]
    fn failure_preserves_data_and_does_not_invent_disappearance() {
        let mut h = History::default();
        h.apply(sample(vec![connection(1, Some(1), "Listen")], true, 1));
        h.apply(sample(vec![], false, 2));
        assert_eq!(h.current.len(), 1);
        assert_eq!(h.changes.len(), 1);
        h.apply(sample(vec![], true, 3));
        assert!(h.current.is_empty());
        assert_eq!(h.changes.len(), 2);
    }
    #[test]
    fn pid_reuse_is_new_identity_and_transition_is_sampled() {
        let mut h = History::default();
        h.apply(sample(vec![connection(1, Some(1), "SynSent")], true, 1));
        h.apply(sample(vec![connection(1, Some(1), "Established")], true, 2));
        assert_eq!(h.changes.back().unwrap().before, "SynSent");
        h.apply(sample(vec![connection(1, Some(2), "Listen")], true, 3));
        assert_eq!(h.changes.len(), 4);
    }
    #[test]
    fn retention_is_bounded_by_count_bytes_and_age() {
        for (count, bytes, ttl) in [
            (2, usize::MAX, 100),
            (usize::MAX, 1, 100),
            (usize::MAX, usize::MAX, 1),
        ] {
            let mut h = History::new(count, bytes, ttl);
            for i in 0..10 {
                h.apply(sample(vec![connection(1, Some(i), "Listen")], true, i));
            }
            assert!(h.changes.len() <= count);
            assert!(h.bytes <= bytes);
            h.prune(1000);
            assert!(h.changes.is_empty());
            assert!(h.evicted > 0);
        }
    }
    #[test]
    fn unknown_creation_never_claims_continuity() {
        let mut h = History::default();
        for i in 1..3 {
            h.apply(sample(vec![connection(1, None, "Listen")], true, i));
        }
        assert_eq!(h.changes.len(), 2);
    }
    #[test]
    fn interval_limits() {
        for v in ["", "0", "3601", "-1", "18446744073709551616"] {
            assert_eq!(valid_interval(v), None);
        }
        assert_eq!(valid_interval("5"), Some(5));
    }
    #[test]
    fn partial_samples_preserve_only_failed_partitions() {
        let mut h = History::default();
        let tcp = connection(1, Some(1), "Listen");
        let mut udp = connection(2, Some(2), "Bound");
        udp.partition = "UDP/IPv4".into();
        udp.key.protocol = Protocol::Udp;
        h.apply(Inventory {
            connections: vec![tcp, udp],
            successful_partitions: vec!["TCP/IPv4".into(), "UDP/IPv4".into()],
            finished_ms: 1,
            ..Inventory::default()
        });
        h.apply(Inventory {
            successful_partitions: vec!["TCP/IPv4".into()],
            errors: vec!["UDP denied".into()],
            finished_ms: 2,
            ..Inventory::default()
        });
        assert_eq!(h.current.len(), 1);
        assert_eq!(h.current[0].key.protocol, Protocol::Udp);
        assert_eq!(h.current[0].observed_ms, 1);
    }
    #[test]
    fn repeated_identical_samples_do_not_duplicate_known_history() {
        let mut h = History::new(100, 100000, 60_000);
        for time in 1..1000 {
            h.apply(Inventory {
                connections: vec![connection(1, Some(1), "Listen")],
                successful_partitions: vec!["TCP/IPv4".into()],
                finished_ms: time,
                ..Inventory::default()
            });
        }
        assert_eq!(h.changes.len(), 1);
        assert_eq!(h.current.len(), 1);
    }
}
