//! `MockTelemetryAdapter` — an in-memory `TelemetryAdapter` for
//! deterministic multi-tick tests in `sher-pe-intelligence` and
//! `sher-pe-investigation`, without touching real `/proc`.

use std::collections::HashMap;
use std::sync::Mutex;

use sher_pe_model::{
    CgroupInfo, DiskIoStats, NamespaceInfo, NetworkConnection, OpenFile, Pid, ProcessSnapshot,
    SecurityContext, ThreadSnapshot,
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
}
