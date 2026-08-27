//! `LinuxAdapter` — the only `TelemetryAdapter` implementation this pass,
//! built entirely on the hand-rolled parsers in `procfs`.

pub mod affinity;
pub mod bpftrace;
pub mod kernel_log;
pub mod perf;
pub mod procfs;
pub mod strace;
pub mod systemd;

use std::path::{Path, PathBuf};

use sher_pe_model::{
    CgroupInfo, CpuStats, DiskIoStats, HotFunction, NamespaceInfo, NetworkConnection, OpenFile,
    Pid, ProcessSnapshot, ProcessState, SchedulerStats, SecurityContext, SyscallStat,
    ThreadSnapshot, TraceEvent,
};

use crate::{Result, TelemetryAdapter};

/// Reads `/proc`/`/sys` directly. `root` defaults to `/proc` and `sys_root`
/// to `/sys/fs/cgroup`; both are overridable (`with_roots`) so tests can
/// point at fixture directories instead.
pub struct LinuxAdapter {
    root: PathBuf,
    sys_root: PathBuf,
    page_size: u64,
}

impl Default for LinuxAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxAdapter {
    pub fn new() -> Self {
        Self::with_roots("/proc", "/sys/fs/cgroup")
    }

    pub fn with_roots(root: impl Into<PathBuf>, sys_root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            sys_root: sys_root.into(),
            page_size: system_page_size(),
        }
    }

    fn stat_path_root(&self) -> &Path {
        &self.root
    }
}

#[cfg(target_os = "linux")]
fn system_page_size() -> u64 {
    nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE)
        .ok()
        .flatten()
        .unwrap_or(4096) as u64
}

#[cfg(not(target_os = "linux"))]
fn system_page_size() -> u64 {
    4096
}

impl TelemetryAdapter for LinuxAdapter {
    fn list_pids(&self) -> Result<Vec<Pid>> {
        procfs::process::list_pids(self.stat_path_root())
    }

    fn process(&self, pid: Pid) -> Result<ProcessSnapshot> {
        let stat = procfs::process::read_stat(&self.root, pid)?;
        let (uid, gid) = procfs::process::read_ids(&self.root, pid)?;
        let cmdline = procfs::process::read_cmdline(&self.root, pid).unwrap_or_default();
        let exe = procfs::process::read_exe(&self.root, pid);
        let memory = procfs::memory::read_memory_breakdown(&self.root, pid, self.page_size)?;
        let cgroup = procfs::cgroup::read_cgroup(&self.root, &self.sys_root, pid)?;
        let open_file_count = procfs::files::list_open_files(&self.root, pid)
            .map(|files| files.len() as u32)
            .unwrap_or(0);

        Ok(ProcessSnapshot {
            pid: stat.id,
            ppid: stat.ppid,
            name: stat.comm,
            cmdline,
            exe,
            state: ProcessState::from_proc_char(stat.state_char),
            uid,
            gid,
            start_time: stat.starttime,
            cpu: CpuStats {
                utime_ticks: stat.utime,
                stime_ticks: stat.stime,
                percent: 0.0,
                voluntary_ctxt_switches: 0,
                nonvoluntary_ctxt_switches: 0,
            },
            memory,
            thread_count: stat.num_threads,
            open_file_count,
            cgroup,
        })
    }

    fn threads(&self, pid: Pid) -> Result<Vec<ThreadSnapshot>> {
        let tids = procfs::threads::list_tids(&self.root, pid)?;
        tids.into_iter()
            .map(|tid| procfs::threads::read_thread(&self.root, pid, tid))
            .collect()
    }

    fn open_files(&self, pid: Pid) -> Result<Vec<OpenFile>> {
        procfs::files::list_open_files(&self.root, pid)
    }

    fn connections(&self, pid: Pid) -> Result<Vec<NetworkConnection>> {
        procfs::net::read_connections(&self.root, pid)
    }

    fn cgroup(&self, pid: Pid) -> Result<Option<CgroupInfo>> {
        procfs::cgroup::read_cgroup(&self.root, &self.sys_root, pid)
    }

    fn namespaces(&self, pid: Pid) -> Result<NamespaceInfo> {
        procfs::namespace::read_namespaces(&self.root, pid)
    }

    fn security(&self, pid: Pid) -> Result<SecurityContext> {
        procfs::security::read_security(&self.root, pid)
    }

    fn systemd_unit(&self, pid: Pid) -> Result<Option<String>> {
        let Some(cgroup) = procfs::cgroup::read_cgroup(&self.root, &self.sys_root, pid)? else {
            return Ok(None);
        };
        Ok(systemd::unit_from_cgroup_path(&cgroup.path))
    }

    fn disk_io(&self, pid: Pid) -> Result<DiskIoStats> {
        procfs::io::read_io(&self.root, pid)
    }

    fn scheduler_stats(&self, pid: Pid) -> Result<SchedulerStats> {
        procfs::scheduler::read_schedstat(&self.root, pid)
    }

    fn sample_hot_functions(
        &self,
        pid: Pid,
        duration: std::time::Duration,
    ) -> Result<Vec<HotFunction>> {
        perf::sample_hot_functions(pid, duration)
    }

    fn sample_syscalls(&self, pid: Pid, duration: std::time::Duration) -> Result<Vec<SyscallStat>> {
        strace::sample_syscalls(pid, duration)
    }

    fn deep_trace(&self, pid: Pid, duration: std::time::Duration) -> Result<Vec<TraceEvent>> {
        bpftrace::deep_trace(pid, duration)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc")
    }

    fn fixture_sys_root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sys/fs/cgroup")
    }

    fn adapter() -> LinuxAdapter {
        LinuxAdapter::with_roots(fixture_root(), fixture_sys_root())
    }

    #[test]
    fn list_pids_returns_fixture_pids() {
        let mut pids = adapter().list_pids().unwrap();
        pids.sort();
        assert_eq!(pids, vec![100, 101]);
    }

    #[test]
    fn process_assembles_full_snapshot_from_all_sources() {
        let snap = adapter().process(100).unwrap();
        assert_eq!(snap.pid, 100);
        assert_eq!(snap.ppid, 1);
        assert_eq!(snap.name, "sherd");
        assert_eq!(
            snap.cmdline,
            vec!["sherd".to_string(), "--foreground".to_string()]
        );
        assert_eq!(snap.uid, 1000);
        assert!(snap.memory.is_detailed());
        assert!(snap.cgroup.is_some());
        assert_eq!(snap.thread_count, 2);
    }

    #[test]
    fn threads_lists_both_fixture_threads() {
        let mut threads = adapter().threads(100).unwrap();
        threads.sort_by_key(|t| t.tid);
        assert_eq!(threads.len(), 2);
        assert_eq!(threads[0].tid, 100);
        assert_eq!(threads[1].tid, 102);
    }

    #[test]
    fn systemd_unit_derives_from_cgroup_path() {
        // Fixture cgroup path is a session scope with no .service/.scope
        // segment ("session.scope" itself does end in ".scope" though).
        let unit = adapter().systemd_unit(100).unwrap();
        assert_eq!(unit, Some("session.scope".to_string()));
    }

    #[test]
    fn process_not_found_is_a_typed_error_not_a_panic() {
        let err = adapter().process(999_999).unwrap_err();
        assert!(matches!(err, crate::TelemetryError::Io { .. }));
    }
}
