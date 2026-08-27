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

use sher_pe_model::{
    CgroupInfo, DiskIoStats, NamespaceInfo, NetworkConnection, OpenFile, Pid, ProcessSnapshot,
    SecurityContext, ThreadSnapshot,
};

pub type Result<T> = std::result::Result<T, TelemetryError>;

/// Collection depth, from cheap-and-continuous to expensive-and-opt-in.
/// Only `Continuous` is implemented this pass — see `CLAUDE.md`'s "no fake
/// stubs" rule: the others are honest `TelemetryError::Unsupported`, not a
/// silent empty result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Level 1 — cheap enough to sample continuously (reading `/proc`
    /// fields already resident in the kernel).
    Continuous,
    /// Level 2 — a short, targeted sample (e.g. a brief `perf` stat run).
    ShortSample,
    /// Level 3 — explicit stack-sampling profile.
    Profile,
    /// Level 4 — deep tracing (eBPF/`perf` syscall/I/O/network tracing).
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

    /// Attempts collection at `tier`. Only `Tier::Continuous` — already
    /// covered by the methods above — is available this pass; every other
    /// tier is a typed `Unsupported`, never a silent empty success.
    fn collect(&self, _pid: Pid, tier: Tier) -> Result<()> {
        match tier {
            Tier::Continuous => Ok(()),
            other => Err(TelemetryError::Unsupported(other)),
        }
    }
}
