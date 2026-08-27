use serde::{Deserialize, Serialize};

use crate::cpu::CpuStats;
use crate::process::ProcessState;
use crate::Pid;

/// A single thread (task) within a process.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreadSnapshot {
    pub tid: Pid,
    pub name: String,
    pub state: ProcessState,
    pub cpu: CpuStats,
    pub priority: i32,
    pub nice: i32,
    /// CPU indices this thread is allowed to run on
    /// (`sched_getaffinity`), empty if not queried.
    pub affinity: Vec<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thread_snapshot_json_round_trip() {
        let thread = ThreadSnapshot {
            tid: 43,
            name: "worker-0".into(),
            state: ProcessState::Running,
            cpu: CpuStats::default(),
            priority: 20,
            nice: 0,
            affinity: vec![0, 1, 2, 3],
        };
        let json = serde_json::to_string(&thread).unwrap();
        let back: ThreadSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(thread, back);
    }
}
