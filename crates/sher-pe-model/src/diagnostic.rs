use serde::{Deserialize, Serialize};

use crate::{
    CgroupInfo, ContainerInfo, DiskIoStats, EnvVar, FamilyRollup, FdLimits, Finding, LogEntry,
    MappedFile, NamespaceInfo, NetworkConnection, OpenFile, Pid, ProcessSnapshot, SchedulerStats,
    SecurityContext, SystemOverview, ThreadSnapshot, TimelineEvent,
};

/// A single-file bundle of everything SHER Process Explorer knows about
/// one process at one point in time: the same data already visible across
/// the CLI's `inspect`/`why`/`timeline` commands and the GUI's detail
/// tabs, just assembled into one exportable JSON document for sharing
/// (e.g. attaching to a bug report) rather than read live.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticReport {
    /// Unix timestamp (seconds) this report was assembled.
    pub generated_at: i64,
    pub pid: Pid,
    pub process: ProcessSnapshot,
    pub family_rollup: Option<FamilyRollup>,
    pub threads: Vec<ThreadSnapshot>,
    pub open_files: Vec<OpenFile>,
    pub connections: Vec<NetworkConnection>,
    pub cgroup: Option<CgroupInfo>,
    pub namespaces: Option<NamespaceInfo>,
    pub security: Option<SecurityContext>,
    pub systemd_unit: Option<String>,
    pub container: Option<ContainerInfo>,
    pub scheduler_stats: Option<SchedulerStats>,
    pub disk_io: Option<DiskIoStats>,
    pub fd_limits: Option<FdLimits>,
    pub environment: Vec<EnvVar>,
    pub mapped_files: Vec<MappedFile>,
    pub timeline: Vec<TimelineEvent>,
    pub journal_entries: Vec<LogEntry>,
    pub kernel_log: Vec<String>,
    /// `why_cpu`/`why_memory`/`why_network`/`why_disk`, in that order —
    /// the same findings `sher investigate <pid>` produces.
    pub findings: Vec<Finding>,
    pub system: SystemOverview,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Confidence, CpuStats, MemoryBreakdown, ProcessState, Severity};

    #[test]
    fn diagnostic_report_json_round_trip() {
        let report = DiagnosticReport {
            generated_at: 1_700_000_000,
            pid: 42,
            process: ProcessSnapshot {
                pid: 42,
                ppid: 1,
                pgid: 42,
                sid: 1,
                name: "sherd".into(),
                cmdline: vec!["sherd".into()],
                exe: None,
                state: ProcessState::Running,
                uid: 1000,
                gid: 1000,
                start_time: 100,
                cpu: CpuStats::default(),
                memory: MemoryBreakdown::default(),
                thread_count: 1,
                open_file_count: 0,
                cgroup: None,
            },
            family_rollup: None,
            threads: vec![],
            open_files: vec![],
            connections: vec![],
            cgroup: None,
            namespaces: None,
            security: None,
            systemd_unit: None,
            container: None,
            scheduler_stats: None,
            disk_io: None,
            fd_limits: None,
            environment: vec![],
            mapped_files: vec![],
            timeline: vec![],
            journal_entries: vec![],
            kernel_log: vec![],
            findings: vec![Finding::new(
                Severity::Info,
                "title",
                "narrative",
                Confidence::Unknown,
                vec![],
            )],
            system: SystemOverview::default(),
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: DiagnosticReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report.pid, back.pid);
        assert_eq!(report.findings.len(), back.findings.len());
    }
}
