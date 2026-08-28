//! The `TelemetryAdapter` trait and its Linux implementation.
//!
//! `sher-pe-model` types describe *what* a snapshot looks like;
//! `TelemetryAdapter` is *how* one gets collected. This crate hand-rolls
//! `/proc`/`/sys` parsing rather than depending on a procfs-wrapper crate,
//! so callers get exact control over which fields are read and how
//! degradation (missing `smaps_rollup`, cgroup v1 vs v2, permission
//! errors) is handled.

pub mod linux;
pub mod testing;

use std::time::Duration;

use sher_pe_model::{
    CgroupInfo, ContainerInfo, DiskIoStats, HotFunction, LogEntry, NamespaceInfo,
    NetworkConnection, OpenFile, Pid, ProcessSnapshot, SchedulerStats, SecurityContext,
    SyscallStat, SystemOverview, ThreadSnapshot, TraceEvent,
};

pub type Result<T> = std::result::Result<T, TelemetryError>;

/// Collection depth, from cheap-and-continuous to expensive-and-opt-in.
/// All four tiers are implemented for `LinuxAdapter` (Phases 0–3) — see
/// `CLAUDE.md`'s "no fake stubs" rule: an adapter that doesn't override a
/// tier's method (e.g. a future `SherKernelAdapter` that can't support
/// `bpftrace`) returns a typed `TelemetryError::Unsupported` for it, never
/// a silent empty result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Level 1 — cheap enough to sample continuously (reading `/proc`
    /// fields already resident in the kernel).
    Continuous,
    /// Level 2 — a short, targeted sample (`strace -c`'s syscall-count
    /// summary).
    ShortSample,
    /// Level 3 — explicit stack-sampling profile (`perf record`/`perf
    /// report`).
    Profile,
    /// Level 4 — deep, per-event tracing (`bpftrace` attached to real
    /// eBPF tracepoints). Opt-in and overhead-warned at the CLI/GUI layer,
    /// not silently run.
    DeepTrace,
}

#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    #[error("process {0} not found")]
    NotFound(Pid),
    #[error("permission denied reading {0}")]
    PermissionDenied(String),
    #[error("failed to parse {path}: {message}")]
    Parse { path: String, message: String },
    #[error("I/O error reading {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{0:?} collection is not implemented yet")]
    Unsupported(Tier),
    #[error("unsupported platform: {0}")]
    UnsupportedPlatform(String),
}

/// The seam between the process-intelligence layer and however telemetry
/// is actually collected. `linux::LinuxAdapter` is the only implementation
/// this pass; a future `SherKernelAdapter` (Phase 6, see `ROADMAP.md`)
/// drops in alongside it without any change to this trait or to anything
/// above it.
pub trait TelemetryAdapter: Send + Sync {
    fn list_pids(&self) -> Result<Vec<Pid>>;
    fn process(&self, pid: Pid) -> Result<ProcessSnapshot>;
    fn threads(&self, pid: Pid) -> Result<Vec<ThreadSnapshot>>;
    fn open_files(&self, pid: Pid) -> Result<Vec<OpenFile>>;
    fn connections(&self, pid: Pid) -> Result<Vec<NetworkConnection>>;
    fn cgroup(&self, pid: Pid) -> Result<Option<CgroupInfo>>;
    fn namespaces(&self, pid: Pid) -> Result<NamespaceInfo>;
    fn security(&self, pid: Pid) -> Result<SecurityContext>;
    fn systemd_unit(&self, pid: Pid) -> Result<Option<String>>;
    /// Cumulative disk I/O bytes, from `/proc/[pid]/io`. Used only by
    /// `why_disk`'s byte-delta calculation, not the continuous refresh
    /// loop, since it requires an extra privileged read per call.
    fn disk_io(&self, pid: Pid) -> Result<DiskIoStats>;
    /// Scheduler accounting (`Tier::Continuous` — cheap, no sampling
    /// needed): time actually running vs. time waiting for a CPU.
    fn scheduler_stats(&self, pid: Pid) -> Result<SchedulerStats>;
    /// Container that owns `pid`, if any — detected from its cgroup path,
    /// enriched via `docker`/`podman inspect` when possible. `Ok(None)`
    /// for a process that isn't containerized (the common case).
    fn container_info(&self, pid: Pid) -> Result<Option<ContainerInfo>>;
    /// Journal entries for the systemd unit that owns `pid`, most recent
    /// `max_lines`. `Ok(vec![])` when `pid` has no systemd unit — there's
    /// nothing to correlate, not a failure.
    fn journal_entries(&self, pid: Pid, max_lines: usize) -> Result<Vec<LogEntry>>;
    /// Kernel-log lines that mention `pid` or its process name —
    /// best-effort correlation (see
    /// `linux::kernel_log::correlate_kernel_lines`), not a certainty.
    fn kernel_log_for(&self, pid: Pid) -> Result<Vec<String>>;
    /// System-wide (not per-process) totals: memory, swap, load average,
    /// uptime, kernel version, process count.
    fn system_overview(&self) -> Result<SystemOverview>;

    /// `Tier::Profile` — a short stack-sampling profile via `perf`. `Ok`
    /// with an empty `Vec` is a valid "no samples landed anywhere
    /// interesting" result; anything that couldn't be sampled at all
    /// (`perf` missing, insufficient privilege, unsupported adapter) is a
    /// typed error, never a silently-empty list standing in for both.
    fn sample_hot_functions(&self, _pid: Pid, _duration: Duration) -> Result<Vec<HotFunction>> {
        Err(TelemetryError::Unsupported(Tier::Profile))
    }

    /// `Tier::ShortSample` — a short syscall-count sample via `strace -c`.
    fn sample_syscalls(&self, _pid: Pid, _duration: Duration) -> Result<Vec<SyscallStat>> {
        Err(TelemetryError::Unsupported(Tier::ShortSample))
    }

    /// `Tier::DeepTrace` — a live, per-event syscall trace via real eBPF
    /// (`bpftrace`). Opt-in and overhead-warned at the CLI/GUI layer,
    /// since a busy process can generate hundreds of thousands of events
    /// per second (confirmed against a real workload, not assumed).
    fn deep_trace(&self, _pid: Pid, _duration: Duration) -> Result<Vec<TraceEvent>> {
        Err(TelemetryError::Unsupported(Tier::DeepTrace))
    }
}
