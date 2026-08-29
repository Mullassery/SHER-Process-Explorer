//! `MockTelemetryAdapter` — an in-memory `TelemetryAdapter` for
//! deterministic multi-tick tests in `sher-pe-intelligence` and
//! `sher-pe-investigation`, without touching real `/proc`.

use std::collections::HashMap;
use std::sync::Mutex;

use sher_pe_model::{
    CgroupInfo, ContainerInfo, DiskIoStats, EnvVar, FdLimits, LogEntry, NamespaceInfo,
    NetworkConnection, OpenFile, Pid, ProcessSnapshot, SchedulerStats, SecurityContext, Signal,
    SystemOverview, ThreadSnapshot,
};

use crate::{Result, TelemetryAdapter, TelemetryError};

/// Configurable in-memory adapter. `set_process`/`remove_process` take
/// `&self` (interior mutability) so a test can mutate the fake process
/// table between successive `ProcessIntelligence::refresh_at` calls while
/// the adapter is already held behind a `Box<dyn TelemetryAdapter>`.
#[derive(Default)]
pub struct MockTelemetryAdapter {
    processes: Mutex<HashMap<Pid, ProcessSnapshot>>,
    threads: Mutex<HashMap<Pid, Vec<ThreadSnapshot>>>,
    connections: Mutex<HashMap<Pid, Vec<NetworkConnection>>>,
    disk_io: Mutex<HashMap<Pid, DiskIoStats>>,
    scheduler_stats: Mutex<HashMap<Pid, SchedulerStats>>,
    container_info: Mutex<HashMap<Pid, ContainerInfo>>,
    journal_entries: Mutex<HashMap<Pid, Vec<LogEntry>>>,
    kernel_log: Mutex<HashMap<Pid, Vec<String>>>,
    system_overview: Mutex<Option<SystemOverview>>,
    /// Every `send_signal` call this mock has received, in order — lets a
    /// test assert exactly what a `ProcessIntelligence::send_signal` call
    /// forwarded, without a real `kill(2)` ever happening.
    sent_signals: Mutex<Vec<(Pid, Signal)>>,
    fd_limits: Mutex<HashMap<Pid, FdLimits>>,
    environment: Mutex<HashMap<Pid, Vec<EnvVar>>>,
}

impl MockTelemetryAdapter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_process(&self, snapshot: ProcessSnapshot) {
        self.processes
            .lock()
            .unwrap()
            .insert(snapshot.pid, snapshot);
    }

    pub fn remove_process(&self, pid: Pid) {
        self.processes.lock().unwrap().remove(&pid);
        self.threads.lock().unwrap().remove(&pid);
        self.connections.lock().unwrap().remove(&pid);
        self.disk_io.lock().unwrap().remove(&pid);
        self.scheduler_stats.lock().unwrap().remove(&pid);
        self.container_info.lock().unwrap().remove(&pid);
        self.journal_entries.lock().unwrap().remove(&pid);
        self.kernel_log.lock().unwrap().remove(&pid);
    }

    pub fn set_threads(&self, pid: Pid, threads: Vec<ThreadSnapshot>) {
        self.threads.lock().unwrap().insert(pid, threads);
    }

    pub fn set_connections(&self, pid: Pid, connections: Vec<NetworkConnection>) {
        self.connections.lock().unwrap().insert(pid, connections);
    }

    pub fn set_disk_io(&self, pid: Pid, io: DiskIoStats) {
        self.disk_io.lock().unwrap().insert(pid, io);
    }

    pub fn set_scheduler_stats(&self, pid: Pid, stats: SchedulerStats) {
        self.scheduler_stats.lock().unwrap().insert(pid, stats);
    }

    pub fn set_container_info(&self, pid: Pid, info: ContainerInfo) {
        self.container_info.lock().unwrap().insert(pid, info);
    }

    pub fn set_journal_entries(&self, pid: Pid, entries: Vec<LogEntry>) {
        self.journal_entries.lock().unwrap().insert(pid, entries);
    }

    pub fn set_kernel_log(&self, pid: Pid, lines: Vec<String>) {
        self.kernel_log.lock().unwrap().insert(pid, lines);
    }

    pub fn set_system_overview(&self, overview: SystemOverview) {
        *self.system_overview.lock().unwrap() = Some(overview);
    }

    /// Every `send_signal` call received so far, in order.
    pub fn sent_signals(&self) -> Vec<(Pid, Signal)> {
        self.sent_signals.lock().unwrap().clone()
    }

    pub fn set_fd_limits(&self, pid: Pid, limits: FdLimits) {
        self.fd_limits.lock().unwrap().insert(pid, limits);
    }

    pub fn set_environment(&self, pid: Pid, vars: Vec<EnvVar>) {
        self.environment.lock().unwrap().insert(pid, vars);
    }
}

impl TelemetryAdapter for MockTelemetryAdapter {
    fn list_pids(&self) -> Result<Vec<Pid>> {
        Ok(self.processes.lock().unwrap().keys().copied().collect())
    }

    fn process(&self, pid: Pid) -> Result<ProcessSnapshot> {
        self.processes
            .lock()
            .unwrap()
            .get(&pid)
            .cloned()
            .ok_or(TelemetryError::NotFound(pid))
    }

    fn threads(&self, pid: Pid) -> Result<Vec<ThreadSnapshot>> {
        Ok(self
            .threads
            .lock()
            .unwrap()
            .get(&pid)
            .cloned()
            .unwrap_or_default())
    }

    fn open_files(&self, _pid: Pid) -> Result<Vec<OpenFile>> {
        Ok(Vec::new())
    }

    fn connections(&self, pid: Pid) -> Result<Vec<NetworkConnection>> {
        Ok(self
            .connections
            .lock()
            .unwrap()
            .get(&pid)
            .cloned()
            .unwrap_or_default())
    }

    fn cgroup(&self, _pid: Pid) -> Result<Option<CgroupInfo>> {
        Ok(None)
    }

    fn namespaces(&self, pid: Pid) -> Result<NamespaceInfo> {
        Ok(NamespaceInfo {
            pid,
            mnt: 0,
            net: 0,
            user: 0,
            uts: 0,
            ipc: 0,
            cgroup: None,
        })
    }

    fn security(&self, pid: Pid) -> Result<SecurityContext> {
        let snap = self.process(pid)?;
        Ok(SecurityContext {
            uid: snap.uid,
            gid: snap.gid,
            euid: snap.uid,
            egid: snap.gid,
            capabilities_effective: Vec::new(),
            capabilities_bounding: Vec::new(),
            lsm_label: None,
            seccomp_mode: 0,
        })
    }

    fn systemd_unit(&self, _pid: Pid) -> Result<Option<String>> {
        Ok(None)
    }

    fn disk_io(&self, pid: Pid) -> Result<DiskIoStats> {
        Ok(self
            .disk_io
            .lock()
            .unwrap()
            .get(&pid)
            .copied()
            .unwrap_or_default())
    }

    fn scheduler_stats(&self, pid: Pid) -> Result<SchedulerStats> {
        Ok(self
            .scheduler_stats
            .lock()
            .unwrap()
            .get(&pid)
            .copied()
            .unwrap_or_default())
    }

    fn container_info(&self, pid: Pid) -> Result<Option<ContainerInfo>> {
        Ok(self.container_info.lock().unwrap().get(&pid).cloned())
    }

    fn journal_entries(&self, pid: Pid, _max_lines: usize) -> Result<Vec<LogEntry>> {
        Ok(self
            .journal_entries
            .lock()
            .unwrap()
            .get(&pid)
            .cloned()
            .unwrap_or_default())
    }

    fn kernel_log_for(&self, pid: Pid) -> Result<Vec<String>> {
        Ok(self
            .kernel_log
            .lock()
            .unwrap()
            .get(&pid)
            .cloned()
            .unwrap_or_default())
    }

    fn system_overview(&self) -> Result<SystemOverview> {
        Ok(self
            .system_overview
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_default())
    }

    fn send_signal(&self, pid: Pid, signal: Signal) -> Result<()> {
        if !self.processes.lock().unwrap().contains_key(&pid) {
            return Err(TelemetryError::NotFound(pid));
        }
        self.sent_signals.lock().unwrap().push((pid, signal));
        Ok(())
    }

    fn fd_limits(&self, pid: Pid) -> Result<FdLimits> {
        Ok(self
            .fd_limits
            .lock()
            .unwrap()
            .get(&pid)
            .copied()
            .unwrap_or_default())
    }

    fn environment(&self, pid: Pid) -> Result<Vec<EnvVar>> {
        Ok(self
            .environment
            .lock()
            .unwrap()
            .get(&pid)
            .cloned()
            .unwrap_or_default())
    }
}
