//! `ProcessIntelligence` — the single shared API both the CLI and any
//! future GUI call. No telemetry-format knowledge leaks past this layer:
//! callers see `ProcessTree`/`FamilyRollup`/history/`TimelineEvent`, never
//! a raw `/proc` field.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sher_pe_model::{
    CgroupInfo, DiskIoStats, FamilyRollup, HotFunction, NamespaceInfo, NetworkConnection, OpenFile,
    Pid, ProcessSnapshot, ProcessTree, SchedulerStats, SecurityContext, SyscallStat,
    ThreadSnapshot, TimelineEvent, TimelineEventKind,
};
use sher_pe_telemetry::{TelemetryAdapter, TelemetryError};

pub type Result<T> = std::result::Result<T, TelemetryError>;

/// Clock ticks per second (`sysconf(_SC_CLK_TCK)`). Standardized at 100 on
/// every mainstream Linux architecture (x86_64, aarch64) since the kernel
/// fixed `HZ`'s user-visible value there; a from-scratch embedded kernel
/// could differ, but that's out of scope for Phase 0.
const CLK_TCK: f64 = 100.0;

/// How far back a process's history must reach before "growth over the
/// window" is a meaningful claim (see `why_memory`-style thresholds).
pub const DEFAULT_GROWTH_WINDOW_SECS: i64 = 3600;
/// RSS growth (%) within `DEFAULT_GROWTH_WINDOW_SECS` that crosses from
/// "normal" to "flag it" — a documented heuristic, not a hard fact, which
/// is why the resulting `TimelineEvent` is advisory and any `Finding` built
/// from it (see `sher-pe-investigation`) uses `Confidence::Likely`, not
/// `Observed`.
pub const DEFAULT_GROWTH_THRESHOLD_PERCENT: f64 = 50.0;

/// How many history entries (one per `refresh_at` tick) are kept per
/// `(pid, start_time)` before the oldest are dropped.
const DEFAULT_HISTORY_CAPACITY: usize = 120;
/// How many timeline events are kept in total before the oldest are
/// dropped.
const DEFAULT_TIMELINE_CAPACITY: usize = 1000;

/// A `(pid, start_time)` pair — the history key that survives PID reuse.
/// The kernel recycles PIDs; it never recycles `(pid, start_time)`.
type HistoryKey = (Pid, u64);

fn cpu_percent(prev_ticks: u64, curr_ticks: u64, elapsed_secs: f64) -> f64 {
    if elapsed_secs <= 0.0 {
        return 0.0;
    }
    let delta_ticks = curr_ticks.saturating_sub(prev_ticks) as f64;
    (delta_ticks / CLK_TCK) / elapsed_secs * 100.0
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Owns a `Box<dyn TelemetryAdapter>` plus everything derived from
/// repeated `refresh()` calls: the current process map, per-process
/// history, and a running timeline.
pub struct ProcessIntelligence {
    adapter: Box<dyn TelemetryAdapter>,
    current: HashMap<Pid, ProcessSnapshot>,
    history: HashMap<HistoryKey, VecDeque<(i64, ProcessSnapshot)>>,
    connections_seen: HashMap<HistoryKey, HashSet<String>>,
    timeline: VecDeque<TimelineEvent>,
    /// Keys that exited on the *previous* tick. Kept for exactly one more
    /// `refresh_at` call before being pruned, so a `sher investigate <pid>`
    /// / `crash_analysis` run immediately after noticing an exit can still
    /// see the history and timeline that led up to it, without the map
    /// growing unboundedly over a long-running session (each dead key is
    /// retained for one grace tick, never indefinitely).
    stale_keys: Vec<HistoryKey>,
    history_capacity: usize,
    timeline_capacity: usize,
}

impl ProcessIntelligence {
    pub fn new(adapter: Box<dyn TelemetryAdapter>) -> Self {
        Self {
            adapter,
            current: HashMap::new(),
            history: HashMap::new(),
            connections_seen: HashMap::new(),
            timeline: VecDeque::new(),
            stale_keys: Vec::new(),
            history_capacity: DEFAULT_HISTORY_CAPACITY,
            timeline_capacity: DEFAULT_TIMELINE_CAPACITY,
        }
    }

    /// A full snapshot pass at the current wall-clock time. See
    /// `refresh_at` for the actual logic — this just supplies `now`.
    pub fn refresh(&mut self) -> Result<()> {
        self.refresh_at(now_unix())
    }

    /// Testable core of `refresh()`: takes `now` explicitly so tests can
    /// drive multiple ticks at controlled timestamps instead of racing
    /// real wall-clock time.
    pub fn refresh_at(&mut self, now: i64) -> Result<()> {
        for key in self.stale_keys.drain(..) {
            self.history.remove(&key);
            self.connections_seen.remove(&key);
        }

        let pids = self.adapter.list_pids()?;
        let old_keys: HashSet<HistoryKey> = self
            .current
            .iter()
            .map(|(pid, snap)| (*pid, snap.start_time))
            .collect();

        let mut new_current = HashMap::with_capacity(pids.len());
        let mut new_keys = HashSet::with_capacity(pids.len());
        let mut pending_events = Vec::new();

        for pid in pids {
            // A process can exit between `list_pids` and `process` — a
            // routine race under `/proc`, not a failure worth aborting the
            // whole refresh over.
            let Ok(mut snap) = self.adapter.process(pid) else {
                tracing::debug!(
                    pid,
                    "process exited between list_pids and process, skipping this tick"
                );
                continue;
            };
            let key = (pid, snap.start_time);
            new_keys.insert(key);

            let previously_live =
                self.current.get(&pid).map(|s| s.start_time) == Some(snap.start_time);
            if !previously_live {
                pending_events.push(TimelineEvent {
                    pid,
                    at: now,
                    kind: TimelineEventKind::Started,
                    description: format!("{} ({pid}) started", snap.name),
                });
                if self.current.contains_key(&snap.ppid) || new_current.contains_key(&snap.ppid) {
                    pending_events.push(TimelineEvent {
                        pid: snap.ppid,
                        at: now,
                        kind: TimelineEventKind::NewChild { child_pid: pid },
                        description: format!("new child process {pid} ({})", snap.name),
                    });
                }
            }

            if let Some(hist) = self.history.get(&key) {
                if let Some((prev_at, prev_snap)) = hist.back() {
                    let elapsed = (now - prev_at) as f64;
                    snap.cpu.percent =
                        cpu_percent(prev_snap.cpu.total_ticks(), snap.cpu.total_ticks(), elapsed);
                }
                if let Some((_, baseline)) = hist
                    .iter()
                    .rev()
                    .find(|(at, _)| now - at >= DEFAULT_GROWTH_WINDOW_SECS)
                {
                    if baseline.memory.rss > 0 {
                        let growth = (snap.memory.rss as f64 - baseline.memory.rss as f64)
                            / baseline.memory.rss as f64
                            * 100.0;
                        if growth >= DEFAULT_GROWTH_THRESHOLD_PERCENT {
                            pending_events.push(TimelineEvent {
                                pid,
                                at: now,
                                kind: TimelineEventKind::MemoryGrowthThresholdCrossed {
                                    percent_growth: growth,
                                    window_secs: DEFAULT_GROWTH_WINDOW_SECS as u64,
                                },
                                description: format!(
                                    "{} ({pid}) RSS grew {growth:.1}% over the last {}m",
                                    snap.name,
                                    DEFAULT_GROWTH_WINDOW_SECS / 60
                                ),
                            });
                        }
                    }
                }
            }

            if let Ok(conns) = self.adapter.connections(pid) {
                let addrs: HashSet<String> = conns
                    .into_iter()
                    .map(|c| c.remote_addr)
                    .filter(|addr| !addr.is_empty())
                    .collect();
                let seen = self.connections_seen.entry(key).or_default();
                for addr in addrs.difference(seen) {
                    pending_events.push(TimelineEvent {
                        pid,
                        at: now,
                        kind: TimelineEventKind::NewConnection {
                            remote_addr: addr.clone(),
                        },
                        description: format!("{} ({pid}) connected to {addr}", snap.name),
                    });
                }
                *seen = addrs;
            }

            let deque = self.history.entry(key).or_default();
            deque.push_back((now, snap.clone()));
            while deque.len() > self.history_capacity {
                deque.pop_front();
            }

            new_current.insert(pid, snap);
        }

        for key in old_keys.difference(&new_keys) {
            pending_events.push(TimelineEvent {
                pid: key.0,
                at: now,
                kind: TimelineEventKind::Exited { exit_reason: None },
                description: format!("process {} exited", key.0),
            });
        }
        // Deferred one tick (see `stale_keys`'s doc comment) rather than
        // removed here, so history/connections from just before the exit
        // are still visible to an investigation run this tick.
        self.stale_keys = old_keys.difference(&new_keys).copied().collect();

        for event in pending_events {
            self.timeline.push_back(event);
        }
        while self.timeline.len() > self.timeline_capacity {
            self.timeline.pop_front();
        }

        self.current = new_current;
        Ok(())
    }

    /// The full process hierarchy as of the last `refresh()`.
    pub fn tree(&self) -> ProcessTree {
        ProcessTree::build(self.current.values().cloned())
    }

    /// Aggregated CPU/memory/thread/file usage across `pid` and every
    /// descendant, as of the last `refresh()`.
    pub fn family_rollup(&self, pid: Pid) -> Option<FamilyRollup> {
        self.tree().aggregate(pid)
    }

    /// The most recent snapshot of `pid`, if it was alive at the last
    /// `refresh()`.
    pub fn process(&self, pid: Pid) -> Option<&ProcessSnapshot> {
        self.current.get(&pid)
    }

    /// Every recorded snapshot of `pid`'s current run, oldest first. If
    /// `pid` has exited, this returns whatever history hadn't yet been
    /// pruned from a previous `refresh()`.
    pub fn history(&self, pid: Pid) -> Vec<(i64, ProcessSnapshot)> {
        let key = self
            .current
            .get(&pid)
            .map(|snap| (pid, snap.start_time))
            .or_else(|| self.history.keys().find(|(p, _)| *p == pid).copied());
        key.and_then(|k| self.history.get(&k))
            .map(|deque| deque.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Every recorded timeline event for `pid`, oldest first.
    pub fn timeline(&self, pid: Pid) -> Vec<TimelineEvent> {
        self.timeline
            .iter()
            .filter(|event| event.pid == pid)
            .cloned()
            .collect()
    }

    /// Live per-thread detail for `pid`, read fresh from the adapter. This
    /// is *not* part of the tracked history — thread-level detail is
    /// comparatively expensive and is only needed on demand (by
    /// `sher-pe-investigation`'s `why_cpu`), not on every `refresh()`.
    pub fn threads(&self, pid: Pid) -> Result<Vec<ThreadSnapshot>> {
        self.adapter.threads(pid)
    }

    /// Live network connections for `pid`, read fresh from the adapter.
    pub fn connections(&self, pid: Pid) -> Result<Vec<NetworkConnection>> {
        self.adapter.connections(pid)
    }

    /// Live cumulative disk I/O counters for `pid`, read fresh from the
    /// adapter — used by `why_disk`'s byte-delta calculation.
    pub fn disk_io(&self, pid: Pid) -> Result<DiskIoStats> {
        self.adapter.disk_io(pid)
    }

    /// Live open-file-descriptor listing for `pid`.
    pub fn open_files(&self, pid: Pid) -> Result<Vec<OpenFile>> {
        self.adapter.open_files(pid)
    }

    /// Live cgroup membership for `pid`.
    pub fn cgroup(&self, pid: Pid) -> Result<Option<CgroupInfo>> {
        self.adapter.cgroup(pid)
    }

    /// Live namespace membership for `pid`.
    pub fn namespaces(&self, pid: Pid) -> Result<NamespaceInfo> {
        self.adapter.namespaces(pid)
    }

    /// Live security context (uid/gid, capabilities, LSM label, seccomp)
    /// for `pid`.
    pub fn security(&self, pid: Pid) -> Result<SecurityContext> {
        self.adapter.security(pid)
    }

    /// The systemd unit (if any) that owns `pid`, derived from its cgroup.
    pub fn systemd_unit(&self, pid: Pid) -> Result<Option<String>> {
        self.adapter.systemd_unit(pid)
    }

    /// Live scheduler accounting (time running vs. time waiting for a
    /// CPU) for `pid`.
    pub fn scheduler_stats(&self, pid: Pid) -> Result<SchedulerStats> {
        self.adapter.scheduler_stats(pid)
    }

    /// A short, opt-in stack-sampling profile of `pid` via `perf`
    /// (`Tier::Profile`). Blocks for roughly `duration` while the sample
    /// runs — not something to call from a UI's continuous refresh loop.
    pub fn sample_hot_functions(&self, pid: Pid, duration: Duration) -> Result<Vec<HotFunction>> {
        self.adapter.sample_hot_functions(pid, duration)
    }

    /// A short, opt-in syscall-count sample of `pid` via `strace -c`
    /// (`Tier::ShortSample`). Same blocking caveat as
    /// `sample_hot_functions`.
    pub fn sample_syscalls(&self, pid: Pid, duration: Duration) -> Result<Vec<SyscallStat>> {
        self.adapter.sample_syscalls(pid, duration)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sher_pe_model::{
        ConnectionState, CpuStats, MemoryBreakdown, NetworkConnection, ProcessState, Protocol,
    };
    use sher_pe_telemetry::testing::MockTelemetryAdapter;
    use std::sync::Arc;

    fn snap(pid: Pid, ppid: Pid, start_time: u64, utime: u64, rss: u64) -> ProcessSnapshot {
        ProcessSnapshot {
            pid,
            ppid,
            name: format!("proc-{pid}"),
            cmdline: vec![],
            exe: None,
            state: ProcessState::Running,
            uid: 1000,
            gid: 1000,
            start_time,
            cpu: CpuStats {
                utime_ticks: utime,
                stime_ticks: 0,
                ..Default::default()
            },
            memory: MemoryBreakdown {
                rss,
                ..Default::default()
            },
            thread_count: 1,
            open_file_count: 0,
            cgroup: None,
        }
    }

    fn new_intelligence() -> (Arc<MockTelemetryAdapter>, ProcessIntelligence) {
        let mock = Arc::new(MockTelemetryAdapter::new());
        let intel = ProcessIntelligence::new(Box::new(SharedAdapter(mock.clone())));
        (mock, intel)
    }

    /// `TelemetryAdapter` requires `Box<dyn TelemetryAdapter>` ownership,
    /// but tests need to keep mutating the mock after handing it to
    /// `ProcessIntelligence` — this thin wrapper lets the test hold an
    /// `Arc` to the same underlying mock the box delegates to.
    struct SharedAdapter(Arc<MockTelemetryAdapter>);
    impl TelemetryAdapter for SharedAdapter {
        fn list_pids(&self) -> sher_pe_telemetry::Result<Vec<Pid>> {
            self.0.list_pids()
        }
        fn process(&self, pid: Pid) -> sher_pe_telemetry::Result<ProcessSnapshot> {
            self.0.process(pid)
        }
        fn threads(
            &self,
            pid: Pid,
        ) -> sher_pe_telemetry::Result<Vec<sher_pe_model::ThreadSnapshot>> {
            self.0.threads(pid)
        }
        fn open_files(&self, pid: Pid) -> sher_pe_telemetry::Result<Vec<sher_pe_model::OpenFile>> {
            self.0.open_files(pid)
        }
        fn connections(&self, pid: Pid) -> sher_pe_telemetry::Result<Vec<NetworkConnection>> {
            self.0.connections(pid)
        }
        fn cgroup(&self, pid: Pid) -> sher_pe_telemetry::Result<Option<sher_pe_model::CgroupInfo>> {
            self.0.cgroup(pid)
        }
        fn namespaces(&self, pid: Pid) -> sher_pe_telemetry::Result<sher_pe_model::NamespaceInfo> {
            self.0.namespaces(pid)
        }
        fn security(&self, pid: Pid) -> sher_pe_telemetry::Result<sher_pe_model::SecurityContext> {
            self.0.security(pid)
        }
        fn systemd_unit(&self, pid: Pid) -> sher_pe_telemetry::Result<Option<String>> {
            self.0.systemd_unit(pid)
        }
        fn disk_io(&self, pid: Pid) -> sher_pe_telemetry::Result<sher_pe_model::DiskIoStats> {
            self.0.disk_io(pid)
        }
        fn scheduler_stats(&self, pid: Pid) -> sher_pe_telemetry::Result<SchedulerStats> {
            self.0.scheduler_stats(pid)
        }
    }

    #[test]
    fn history_survives_one_grace_tick_after_exit_then_is_pruned() {
        let (mock, mut intel) = new_intelligence();
        mock.set_process(snap(1, 0, 100, 0, 1000));
        intel.refresh_at(1000).unwrap();
        assert_eq!(intel.history(1).len(), 1);

        mock.remove_process(1);
        intel.refresh_at(1001).unwrap();
        // Exited this tick — history from before the exit must still be
        // visible so a `sher investigate 1` run right after noticing the
        // exit (the realistic usage pattern) can still see it.
        assert_eq!(intel.history(1).len(), 1);

        intel.refresh_at(1002).unwrap();
        // One more tick later, the grace period is over.
        assert_eq!(intel.history(1).len(), 0);
    }

    #[test]
    fn scheduler_stats_passes_through_to_the_adapter() {
        let (mock, mut intel) = new_intelligence();
        mock.set_process(snap(1, 0, 100, 0, 1000));
        mock.set_scheduler_stats(
            1,
            sher_pe_model::SchedulerStats {
                on_cpu_ns: 900,
                wait_ns: 100,
                timeslices: 5,
            },
        );
        intel.refresh_at(1000).unwrap();

        let stats = intel.scheduler_stats(1).unwrap();
        assert_eq!(stats.on_cpu_ns, 900);
        assert_eq!(stats.wait_ratio_percent(), Some(10.0));
    }

    #[test]
    fn refresh_populates_current_and_emits_started_event() {
        let (mock, mut intel) = new_intelligence();
        mock.set_process(snap(1, 0, 100, 0, 1000));

        intel.refresh_at(1000).unwrap();

        assert!(intel.process(1).is_some());
        let events = intel.timeline(1);
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0].kind, TimelineEventKind::Started));
    }

    #[test]
    fn refresh_computes_cpu_percent_from_tick_delta() {
        let (mock, mut intel) = new_intelligence();
        mock.set_process(snap(1, 0, 100, 0, 1000));
        intel.refresh_at(1000).unwrap();

        // 100 ticks over 1 second at CLK_TCK=100 => 1 full core-second in
        // 1 wall-second => 100%.
        mock.set_process(snap(1, 0, 100, 100, 1000));
        intel.refresh_at(1001).unwrap();

        let cpu_percent = intel.process(1).unwrap().cpu.percent;
        assert!(
            (cpu_percent - 100.0).abs() < 0.01,
            "expected ~100%, got {cpu_percent}"
        );
    }

    #[test]
    fn refresh_detects_exit_and_new_child() {
        let (mock, mut intel) = new_intelligence();
        mock.set_process(snap(1, 0, 100, 0, 1000));
        intel.refresh_at(1000).unwrap();

        mock.set_process(snap(2, 1, 200, 0, 500));
        intel.refresh_at(1001).unwrap();
        let child_events = intel.timeline(1);
        assert!(child_events
            .iter()
            .any(|e| matches!(e.kind, TimelineEventKind::NewChild { child_pid: 2 })));

        mock.remove_process(2);
        intel.refresh_at(1002).unwrap();
        let exit_events = intel.timeline(2);
        assert!(exit_events
            .iter()
            .any(|e| matches!(e.kind, TimelineEventKind::Exited { .. })));
        assert!(intel.process(2).is_none());
    }

    #[test]
    fn refresh_flags_sustained_memory_growth_over_window() {
        let (mock, mut intel) = new_intelligence();
        mock.set_process(snap(1, 0, 100, 0, 1_000_000));
        intel.refresh_at(0).unwrap();

        // 70% growth after exactly the growth window has elapsed.
        mock.set_process(snap(1, 0, 100, 0, 1_700_000));
        intel.refresh_at(DEFAULT_GROWTH_WINDOW_SECS).unwrap();

        let events = intel.timeline(1);
        assert!(events.iter().any(|e| matches!(
            e.kind,
            TimelineEventKind::MemoryGrowthThresholdCrossed { .. }
        )));
    }

    #[test]
    fn refresh_detects_new_connection() {
        let (mock, mut intel) = new_intelligence();
        mock.set_process(snap(1, 0, 100, 0, 1000));
        intel.refresh_at(1000).unwrap();

        mock.set_connections(
            1,
            vec![NetworkConnection {
                protocol: Protocol::Tcp,
                local_addr: "127.0.0.1:9000".into(),
                remote_addr: "10.0.0.5:443".into(),
                state: ConnectionState::Established,
                inode: 42,
            }],
        );
        intel.refresh_at(1001).unwrap();

        let events = intel.timeline(1);
        assert!(events.iter().any(|e| matches!(
            &e.kind,
            TimelineEventKind::NewConnection { remote_addr } if remote_addr == "10.0.0.5:443"
        )));

        // A second refresh with the same connection must not re-fire the
        // event — only genuinely new remote addresses should.
        intel.refresh_at(1002).unwrap();
        let new_connection_count = intel
            .timeline(1)
            .iter()
            .filter(|e| matches!(e.kind, TimelineEventKind::NewConnection { .. }))
            .count();
        assert_eq!(new_connection_count, 1);
    }

    #[test]
    fn tree_and_family_rollup_reflect_current_snapshot() {
        let (mock, mut intel) = new_intelligence();
        mock.set_process(snap(1, 0, 100, 0, 1000));
        mock.set_process(snap(2, 1, 200, 0, 2000));
        intel.refresh_at(1000).unwrap();

        let rollup = intel.family_rollup(1).expect("pid 1 exists");
        assert_eq!(rollup.process_count, 2);
        assert_eq!(rollup.rss, 3000);
    }

    #[test]
    fn history_survives_pid_reuse_as_distinct_keys() {
        let (mock, mut intel) = new_intelligence();
        mock.set_process(snap(1, 0, 100, 0, 1000));
        intel.refresh_at(1000).unwrap();
        mock.remove_process(1);
        intel.refresh_at(1001).unwrap();

        // Same bare pid, different start_time => a different process, a
        // fresh history, and a second Started event rather than being
        // treated as a continuation of the exited one.
        mock.set_process(snap(1, 0, 999, 0, 5000));
        intel.refresh_at(1002).unwrap();

        let started_events: Vec<_> = intel
            .timeline(1)
            .into_iter()
            .filter(|e| matches!(e.kind, TimelineEventKind::Started))
            .collect();
        assert_eq!(started_events.len(), 2);
        assert_eq!(intel.history(1).len(), 1);
    }
}
