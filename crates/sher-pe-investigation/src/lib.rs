//! Deterministic, rule-based "why" investigation engine. Explicitly not an
//! LLM call this pass (see `ROADMAP.md`'s Phase 7) — every `Finding` here
//! is produced by a fixed rule against real `ProcessIntelligence` data, and
//! carries the `Evidence` that justifies it.

use sher_pe_intelligence::{
    ProcessIntelligence, DEFAULT_GROWTH_THRESHOLD_PERCENT, DEFAULT_GROWTH_WINDOW_SECS,
};
use sher_pe_model::{Confidence, Evidence, Finding, Pid, Severity, TimelineEventKind};

fn not_found(pid: Pid) -> Finding {
    Finding::new(
        Severity::Info,
        "Process not found",
        format!("pid {pid} is not in the currently tracked process set"),
        Confidence::Unknown,
        Vec::new(),
    )
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Top threads by cumulative CPU ticks, and whether one thread dominates.
///
/// Thread-level *rate* (`%`) isn't tracked anywhere in Phase 0 — only the
/// process-level history in `ProcessIntelligence` computes a rate from
/// tick deltas across ticks. This instead compares each thread's share of
/// the process's total accumulated ticks in a single live read — a ratio
/// of directly observed counters, not a rate, so it's reported at
/// `Confidence::Correlated` rather than `Observed`.
pub fn why_cpu(intel: &ProcessIntelligence, pid: Pid) -> Finding {
    let Some(process) = intel.process(pid) else {
        return not_found(pid);
    };

    let threads = intel.threads(pid).unwrap_or_default();
    let total_ticks: u64 = threads.iter().map(|t| t.cpu.total_ticks()).sum();

    let mut evidence = vec![Evidence {
        source: format!("process {pid} snapshot"),
        collected_at: now_unix(),
        description: "process-level CPU utilization".into(),
        raw: format!("{:.1}%", process.cpu.percent),
    }];

    if threads.is_empty() || total_ticks == 0 {
        return Finding::new(
            Severity::Info,
            "CPU usage",
            format!(
                "{} (pid {pid}) is at {:.1}% CPU; no per-thread breakdown available",
                process.name, process.cpu.percent
            ),
            Confidence::Observed,
            evidence,
        );
    }

    let mut by_ticks = threads.clone();
    by_ticks.sort_by_key(|t| std::cmp::Reverse(t.cpu.total_ticks()));
    let top = &by_ticks[0];
    let top_share = top.cpu.total_ticks() as f64 / total_ticks as f64 * 100.0;

    evidence.push(Evidence {
        source: format!("threads of process {pid}"),
        collected_at: now_unix(),
        description: format!("top thread '{}' (tid {})", top.name, top.tid),
        raw: format!(
            "{} / {} total ticks ({top_share:.1}%)",
            top.cpu.total_ticks(),
            total_ticks
        ),
    });

    const DOMINANCE_THRESHOLD_PERCENT: f64 = 80.0;
    if threads.len() > 1 && top_share >= DOMINANCE_THRESHOLD_PERCENT {
        Finding::new(
            Severity::Notice,
            "Single-thread CPU dominance",
            format!(
                "thread '{}' (tid {}) accounts for {top_share:.1}% of {}'s accumulated CPU ticks across {} threads",
                top.name, top.tid, process.name, threads.len()
            ),
            Confidence::Correlated,
            evidence,
        )
    } else {
        Finding::new(
            Severity::Info,
            "CPU usage spread across threads",
            format!(
                "{} (pid {pid}) is at {:.1}% CPU, spread across {} threads with no single dominant thread",
                process.name,
                process.cpu.percent,
                threads.len()
            ),
            Confidence::Observed,
            evidence,
        )
    }
}

/// Memory breakdown plus, when enough history exists, an RSS growth-rate
/// claim over `DEFAULT_GROWTH_WINDOW_SECS`.
pub fn why_memory(intel: &ProcessIntelligence, pid: Pid) -> Finding {
    let Some(process) = intel.process(pid) else {
        return not_found(pid);
    };
    let history = intel.history(pid);

    let mut evidence = vec![Evidence {
        source: format!("process {pid} snapshot"),
        collected_at: now_unix(),
        description: "memory breakdown".into(),
        raw: format!(
            "rss={} anon={} file={} shared={} private={} swap={} (bytes)",
            process.memory.rss,
            process.memory.anonymous,
            process.memory.file_backed,
            process.memory.shared,
            process.memory.private,
            process.memory.swap
        ),
    }];

    // `history` includes this tick's own just-appended reading, so at
    // least *two* entries are needed before "baseline" (the oldest) and
    // "latest" (the newest) are actually two distinct points in time —
    // with only one entry, both would resolve to the same reading and a
    // 0%-over-0-seconds "growth" claim would be a meaningless artifact,
    // not real data.
    if history.len() < 2 {
        return Finding::new(
            Severity::Info,
            "Memory usage",
            format!(
                "{} (pid {pid}) is using {} bytes RSS; no history yet to assess growth",
                process.name, process.memory.rss
            ),
            Confidence::Observed,
            evidence,
        );
    }
    let (baseline_at, baseline) = history.first().cloned().expect("len >= 2 checked above");
    let (latest_at, _) = history.last().cloned().expect("len >= 2 checked above");

    if baseline.memory.rss == 0 {
        return Finding::new(
            Severity::Info,
            "Memory usage",
            format!(
                "{} (pid {pid}) is using {} bytes RSS",
                process.name, process.memory.rss
            ),
            Confidence::Observed,
            evidence,
        );
    }

    let growth_percent = (process.memory.rss as f64 - baseline.memory.rss as f64)
        / baseline.memory.rss as f64
        * 100.0;
    let window_secs = latest_at - baseline_at;

    evidence.push(Evidence {
        source: format!("history of process {pid}"),
        collected_at: latest_at,
        description: format!("RSS at start of the observed window ({window_secs}s ago)"),
        raw: format!("{} bytes", baseline.memory.rss),
    });

    let window_covers_default = window_secs >= DEFAULT_GROWTH_WINDOW_SECS;
    if window_covers_default && growth_percent >= DEFAULT_GROWTH_THRESHOLD_PERCENT {
        Finding::new(
            Severity::Warning,
            "Sustained memory growth",
            format!(
                "{} (pid {pid})'s RSS grew {growth_percent:.1}% over the last {}m — worth checking for a leak",
                process.name,
                window_secs / 60
            ),
            Confidence::Likely,
            evidence,
        )
    } else {
        Finding::new(
            Severity::Info,
            "Memory usage",
            format!(
                "{} (pid {pid})'s RSS changed {growth_percent:.1}% over the last {window_secs}s (below the {}%/{}m threshold, or too little history yet)",
                process.name,
                DEFAULT_GROWTH_THRESHOLD_PERCENT,
                DEFAULT_GROWTH_WINDOW_SECS / 60
            ),
            Confidence::Correlated,
            evidence,
        )
    }
}

/// Connection count/persistence summary — a live read, not historical.
pub fn why_network(intel: &ProcessIntelligence, pid: Pid) -> Finding {
    let Some(process) = intel.process(pid) else {
        return not_found(pid);
    };
    let connections = intel.connections(pid).unwrap_or_default();
    let established = connections
        .iter()
        .filter(|c| c.state == sher_pe_model::ConnectionState::Established)
        .count();

    let evidence = vec![Evidence {
        source: format!("connections of process {pid}"),
        collected_at: now_unix(),
        description: "open connections/sockets".into(),
        raw: format!("{} total, {established} established", connections.len()),
    }];

    if connections.is_empty() {
        Finding::new(
            Severity::Info,
            "Network activity",
            format!(
                "{} (pid {pid}) has no open network connections",
                process.name
            ),
            Confidence::Observed,
            evidence,
        )
    } else {
        Finding::new(
            Severity::Info,
            "Network activity",
            format!(
                "{} (pid {pid}) holds {} connections/sockets ({established} established)",
                process.name,
                connections.len()
            ),
            Confidence::Observed,
            evidence,
        )
    }
}

/// Cumulative disk I/O bytes since process start (a live read). A true
/// rate/delta needs two temporally-separated readings, which Phase 0
/// doesn't track historically for I/O — so this reports the observed
/// cumulative totals only, not a fabricated rate.
pub fn why_disk(intel: &ProcessIntelligence, pid: Pid) -> Finding {
    let Some(process) = intel.process(pid) else {
        return not_found(pid);
    };
    let io = match intel.disk_io(pid) {
        Ok(io) => io,
        Err(_) => {
            return Finding::new(
                Severity::Info,
                "Disk I/O",
                format!("{} (pid {pid})'s /proc/[pid]/io could not be read (permission denied or unsupported)", process.name),
                Confidence::Unknown,
                Vec::new(),
            )
        }
    };

    let evidence = vec![Evidence {
        source: format!("/proc/{pid}/io"),
        collected_at: now_unix(),
        description: "cumulative disk I/O since process start".into(),
        raw: format!(
            "read_bytes={} write_bytes={}",
            io.read_bytes, io.write_bytes
        ),
    }];

    Finding::new(
        Severity::Info,
        "Disk I/O",
        format!(
            "{} (pid {pid}) has read {} and written {} bytes from/to disk since it started",
            process.name, io.read_bytes, io.write_bytes
        ),
        Confidence::Observed,
        evidence,
    )
}

/// Runs every `why_*` rule and collects the results.
pub fn investigate(intel: &ProcessIntelligence, pid: Pid) -> Vec<Finding> {
    if intel.process(pid).is_none() {
        return vec![not_found(pid)];
    }
    vec![
        why_cpu(intel, pid),
        why_memory(intel, pid),
        why_network(intel, pid),
        why_disk(intel, pid),
    ]
}

/// Correlates a process's `Exited` timeline event against its memory-growth
/// history and any OOM-kill lines already extracted from the kernel log
/// (see `sher_pe_telemetry::linux::kernel_log::oom_kill_lines`; this
/// function takes the already-filtered lines rather than reading the log
/// itself, keeping this crate free of any telemetry/process dependency).
pub fn crash_analysis(intel: &ProcessIntelligence, pid: Pid, oom_kill_lines: &[String]) -> Finding {
    let timeline = intel.timeline(pid);
    let Some(exit_event) = timeline
        .iter()
        .find(|e| matches!(e.kind, TimelineEventKind::Exited { .. }))
    else {
        return Finding::new(
            Severity::Info,
            "Crash analysis",
            format!("pid {pid} has no recorded exit yet"),
            Confidence::Unknown,
            Vec::new(),
        );
    };

    let mut evidence = vec![Evidence {
        source: format!("timeline of process {pid}"),
        collected_at: exit_event.at,
        description: "exit event".into(),
        raw: exit_event.description.clone(),
    }];

    let growth_before_exit = timeline.iter().rfind(|e| {
        matches!(
            e.kind,
            TimelineEventKind::MemoryGrowthThresholdCrossed { .. }
        ) && e.at <= exit_event.at
    });

    let matching_oom_line = oom_kill_lines
        .iter()
        .find(|line| line.contains(&pid.to_string()));

    match (growth_before_exit, matching_oom_line) {
        (Some(growth), Some(oom_line)) => {
            evidence.push(Evidence {
                source: format!("timeline of process {pid}"),
                collected_at: growth.at,
                description: "memory-growth event preceding exit".into(),
                raw: growth.description.clone(),
            });
            evidence.push(Evidence {
                source: "kernel log".into(),
                collected_at: exit_event.at,
                description: "matching OOM-kill line".into(),
                raw: oom_line.clone(),
            });
            Finding::new(
                Severity::Critical,
                "Likely OOM kill",
                format!("pid {pid} exited after sustained memory growth, and the kernel log records an OOM kill mentioning this pid"),
                Confidence::Likely,
                evidence,
            )
        }
        (None, Some(oom_line)) => {
            evidence.push(Evidence {
                source: "kernel log".into(),
                collected_at: exit_event.at,
                description: "matching OOM-kill line".into(),
                raw: oom_line.clone(),
            });
            Finding::new(
                Severity::Warning,
                "Possible OOM kill",
                format!("pid {pid} exited and the kernel log records an OOM kill mentioning this pid, but no sustained memory growth was recorded beforehand"),
                Confidence::Correlated,
                evidence,
            )
        }
        (Some(growth), None) => {
            evidence.push(Evidence {
                source: format!("timeline of process {pid}"),
                collected_at: growth.at,
                description: "memory-growth event preceding exit".into(),
                raw: growth.description.clone(),
            });
            Finding::new(
                Severity::Notice,
                "Exit preceded by memory growth",
                format!("pid {pid} exited after sustained memory growth was recorded, but no matching kernel OOM-kill line was found"),
                Confidence::Correlated,
                evidence,
            )
        }
        (None, None) => Finding::new(
            Severity::Info,
            "Exit, cause unclear",
            format!("pid {pid} exited; no sustained memory growth or OOM-kill line was found to explain why"),
            Confidence::Unknown,
            Vec::new(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sher_pe_model::{
        ConnectionState, CpuStats, MemoryBreakdown, NetworkConnection, Pid as PidType,
        ProcessSnapshot, ProcessState, Protocol, ThreadSnapshot,
    };
    use sher_pe_telemetry::testing::MockTelemetryAdapter;
    use sher_pe_telemetry::TelemetryAdapter;
    use std::sync::Arc;

    fn snap(pid: PidType, ppid: PidType, start_time: u64, rss: u64) -> ProcessSnapshot {
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
            cpu: CpuStats::default(),
            memory: MemoryBreakdown {
                rss,
                ..Default::default()
            },
            thread_count: 1,
            open_file_count: 0,
            cgroup: None,
        }
    }

    struct SharedAdapter(Arc<MockTelemetryAdapter>);
    impl TelemetryAdapter for SharedAdapter {
        fn list_pids(&self) -> sher_pe_telemetry::Result<Vec<PidType>> {
            self.0.list_pids()
        }
        fn process(&self, pid: PidType) -> sher_pe_telemetry::Result<ProcessSnapshot> {
            self.0.process(pid)
        }
        fn threads(&self, pid: PidType) -> sher_pe_telemetry::Result<Vec<ThreadSnapshot>> {
            self.0.threads(pid)
        }
        fn open_files(
            &self,
            pid: PidType,
        ) -> sher_pe_telemetry::Result<Vec<sher_pe_model::OpenFile>> {
            self.0.open_files(pid)
        }
        fn connections(&self, pid: PidType) -> sher_pe_telemetry::Result<Vec<NetworkConnection>> {
            self.0.connections(pid)
        }
        fn cgroup(
            &self,
            pid: PidType,
        ) -> sher_pe_telemetry::Result<Option<sher_pe_model::CgroupInfo>> {
            self.0.cgroup(pid)
        }
        fn namespaces(
            &self,
            pid: PidType,
        ) -> sher_pe_telemetry::Result<sher_pe_model::NamespaceInfo> {
            self.0.namespaces(pid)
        }
        fn security(
            &self,
            pid: PidType,
        ) -> sher_pe_telemetry::Result<sher_pe_model::SecurityContext> {
            self.0.security(pid)
        }
        fn systemd_unit(&self, pid: PidType) -> sher_pe_telemetry::Result<Option<String>> {
            self.0.systemd_unit(pid)
        }
        fn disk_io(&self, pid: PidType) -> sher_pe_telemetry::Result<sher_pe_model::DiskIoStats> {
            self.0.disk_io(pid)
        }
    }

    fn new_intelligence() -> (Arc<MockTelemetryAdapter>, ProcessIntelligence) {
        let mock = Arc::new(MockTelemetryAdapter::new());
        let intel = ProcessIntelligence::new(Box::new(SharedAdapter(mock.clone())));
        (mock, intel)
    }

    #[test]
    fn why_cpu_reports_unknown_for_missing_process() {
        let (_mock, intel) = new_intelligence();
        let finding = why_cpu(&intel, 999);
        assert_eq!(finding.confidence, Confidence::Unknown);
    }

    #[test]
    fn why_cpu_flags_single_thread_dominance() {
        let (mock, mut intel) = new_intelligence();
        mock.set_process(snap(1, 0, 100, 1000));
        mock.set_threads(
            1,
            vec![
                ThreadSnapshot {
                    tid: 1,
                    name: "main".into(),
                    state: ProcessState::Running,
                    cpu: CpuStats {
                        utime_ticks: 950,
                        ..Default::default()
                    },
                    priority: 20,
                    nice: 0,
                    affinity: vec![],
                },
                ThreadSnapshot {
                    tid: 2,
                    name: "helper".into(),
                    state: ProcessState::Sleeping,
                    cpu: CpuStats {
                        utime_ticks: 50,
                        ..Default::default()
                    },
                    priority: 20,
                    nice: 0,
                    affinity: vec![],
                },
            ],
        );
        intel.refresh_at(1000).unwrap();

        let finding = why_cpu(&intel, 1);
        assert_eq!(finding.title, "Single-thread CPU dominance");
        assert_eq!(finding.confidence, Confidence::Correlated);
    }

    #[test]
    fn why_cpu_reports_spread_when_no_thread_dominates() {
        let (mock, mut intel) = new_intelligence();
        mock.set_process(snap(1, 0, 100, 1000));
        mock.set_threads(
            1,
            vec![
                ThreadSnapshot {
                    tid: 1,
                    name: "a".into(),
                    state: ProcessState::Running,
                    cpu: CpuStats {
                        utime_ticks: 500,
                        ..Default::default()
                    },
                    priority: 20,
                    nice: 0,
                    affinity: vec![],
                },
                ThreadSnapshot {
                    tid: 2,
                    name: "b".into(),
                    state: ProcessState::Running,
                    cpu: CpuStats {
                        utime_ticks: 500,
                        ..Default::default()
                    },
                    priority: 20,
                    nice: 0,
                    affinity: vec![],
                },
            ],
        );
        intel.refresh_at(1000).unwrap();

        let finding = why_cpu(&intel, 1);
        assert_eq!(finding.title, "CPU usage spread across threads");
    }

    #[test]
    fn why_memory_reports_observed_with_no_history() {
        let (mock, mut intel) = new_intelligence();
        mock.set_process(snap(1, 0, 100, 1000));
        intel.refresh_at(1000).unwrap();

        let finding = why_memory(&intel, 1);
        assert_eq!(finding.confidence, Confidence::Observed);
    }

    #[test]
    fn why_memory_flags_sustained_growth_over_full_window() {
        let (mock, mut intel) = new_intelligence();
        mock.set_process(snap(1, 0, 100, 1_000_000));
        intel.refresh_at(0).unwrap();

        mock.set_process(snap(1, 0, 100, 1_700_000));
        intel.refresh_at(DEFAULT_GROWTH_WINDOW_SECS).unwrap();

        let finding = why_memory(&intel, 1);
        assert_eq!(finding.title, "Sustained memory growth");
        assert_eq!(finding.confidence, Confidence::Likely);
        assert_eq!(finding.severity, Severity::Warning);
    }

    #[test]
    fn why_network_reports_no_connections() {
        let (mock, mut intel) = new_intelligence();
        mock.set_process(snap(1, 0, 100, 1000));
        intel.refresh_at(1000).unwrap();

        let finding = why_network(&intel, 1);
        assert_eq!(finding.title, "Network activity");
        assert_eq!(finding.confidence, Confidence::Observed);
    }

    #[test]
    fn why_network_counts_established_connections() {
        let (mock, mut intel) = new_intelligence();
        mock.set_process(snap(1, 0, 100, 1000));
        mock.set_connections(
            1,
            vec![NetworkConnection {
                protocol: Protocol::Tcp,
                local_addr: "127.0.0.1:1".into(),
                remote_addr: "10.0.0.1:443".into(),
                state: ConnectionState::Established,
                inode: 1,
            }],
        );
        intel.refresh_at(1000).unwrap();

        let finding = why_network(&intel, 1);
        assert!(finding.narrative.contains("1 established"));
    }

    #[test]
    fn why_disk_reports_cumulative_bytes() {
        let (mock, mut intel) = new_intelligence();
        mock.set_process(snap(1, 0, 100, 1000));
        mock.set_disk_io(
            1,
            sher_pe_model::DiskIoStats {
                read_bytes: 4096,
                write_bytes: 1024,
            },
        );
        intel.refresh_at(1000).unwrap();

        let finding = why_disk(&intel, 1);
        assert_eq!(finding.confidence, Confidence::Observed);
        assert!(finding.narrative.contains("4096"));
        assert!(finding.narrative.contains("1024"));
    }

    #[test]
    fn investigate_runs_all_rules_for_a_live_process() {
        let (mock, mut intel) = new_intelligence();
        mock.set_process(snap(1, 0, 100, 1000));
        intel.refresh_at(1000).unwrap();

        let findings = investigate(&intel, 1);
        assert_eq!(findings.len(), 4);
    }

    #[test]
    fn investigate_returns_single_unknown_finding_for_missing_pid() {
        let (_mock, intel) = new_intelligence();
        let findings = investigate(&intel, 999);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].confidence, Confidence::Unknown);
    }

    #[test]
    fn crash_analysis_correlates_growth_and_oom_line() {
        let (mock, mut intel) = new_intelligence();
        mock.set_process(snap(7, 0, 100, 1_000_000));
        intel.refresh_at(0).unwrap();
        mock.set_process(snap(7, 0, 100, 1_700_000));
        intel.refresh_at(DEFAULT_GROWTH_WINDOW_SECS).unwrap();
        mock.remove_process(7);
        intel.refresh_at(DEFAULT_GROWTH_WINDOW_SECS + 10).unwrap();

        let oom_lines =
            vec!["Out of memory: Killed process 7 (proc-7) total-vm:2048000kB".to_string()];
        let finding = crash_analysis(&intel, 7, &oom_lines);

        assert_eq!(finding.title, "Likely OOM kill");
        assert_eq!(finding.confidence, Confidence::Likely);
        assert_eq!(finding.severity, Severity::Critical);
    }

    #[test]
    fn crash_analysis_reports_unclear_without_evidence() {
        let (mock, mut intel) = new_intelligence();
        mock.set_process(snap(8, 0, 100, 1000));
        intel.refresh_at(1000).unwrap();
        mock.remove_process(8);
        intel.refresh_at(1001).unwrap();

        let finding = crash_analysis(&intel, 8, &[]);
        assert_eq!(finding.title, "Exit, cause unclear");
        assert_eq!(finding.confidence, Confidence::Unknown);
    }

    #[test]
    fn crash_analysis_unknown_when_no_exit_recorded() {
        let (mock, mut intel) = new_intelligence();
        mock.set_process(snap(9, 0, 100, 1000));
        intel.refresh_at(1000).unwrap();

        let finding = crash_analysis(&intel, 9, &[]);
        assert_eq!(finding.title, "Crash analysis");
        assert_eq!(finding.confidence, Confidence::Unknown);
    }
}
