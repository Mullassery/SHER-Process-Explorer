use serde::{Deserialize, Serialize};

use crate::cgroup::CgroupInfo;
use crate::cpu::CpuStats;
use crate::memory::MemoryBreakdown;
use crate::Pid;

/// Coarse process run-state, mirroring the single-letter codes in
/// `/proc/[pid]/stat` field 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessState {
    Running,
    Sleeping,
    DiskSleep,
    Zombie,
    Stopped,
    TracingStop,
    Dead,
    Idle,
    /// A state code the parser didn't recognize — kept instead of erroring
    /// so a kernel version skew never crashes a snapshot.
    Unknown(char),
}

impl ProcessState {
    /// Parses a `/proc/[pid]/stat` state character.
    pub fn from_proc_char(c: char) -> Self {
        match c {
            'R' => Self::Running,
            'S' => Self::Sleeping,
            'D' => Self::DiskSleep,
            'Z' => Self::Zombie,
            'T' | 't' => Self::Stopped,
            'X' | 'x' => Self::Dead,
            'I' => Self::Idle,
            other => Self::Unknown(other),
        }
    }
}

/// A single point-in-time view of one process, as reported by a
/// `TelemetryAdapter`. Everything nested in here is what one `refresh()`
/// pass is able to read cheaply (Tier::Continuous) — thread/file/network
/// detail lives behind separate `TelemetryAdapter` calls, not inline here,
/// so a full-tree scan doesn't pay for detail nobody asked to see yet.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProcessSnapshot {
    pub pid: Pid,
    pub ppid: Pid,
    pub name: String,
    pub cmdline: Vec<String>,
    pub exe: Option<String>,
    pub state: ProcessState,
    pub uid: u32,
    pub gid: u32,
    /// Process start time, in clock ticks since boot (`/proc/[pid]/stat`
    /// field 22) — paired with `pid` as the history key, since the kernel
    /// reuses PIDs but never reuses `(pid, start_time)`.
    pub start_time: u64,
    pub cpu: CpuStats,
    pub memory: MemoryBreakdown,
    pub thread_count: u32,
    pub open_file_count: u32,
    pub cgroup: Option<CgroupInfo>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_from_proc_char_covers_common_codes() {
        assert_eq!(ProcessState::from_proc_char('R'), ProcessState::Running);
        assert_eq!(ProcessState::from_proc_char('S'), ProcessState::Sleeping);
        assert_eq!(ProcessState::from_proc_char('Z'), ProcessState::Zombie);
        assert_eq!(
            ProcessState::from_proc_char('?'),
            ProcessState::Unknown('?')
        );
    }

    #[test]
    fn process_snapshot_json_round_trip() {
        let snap = ProcessSnapshot {
            pid: 42,
            ppid: 1,
            name: "sherd".into(),
            cmdline: vec!["sherd".into(), "--foreground".into()],
            exe: Some("/usr/bin/sherd".into()),
            state: ProcessState::Sleeping,
            uid: 1000,
            gid: 1000,
            start_time: 123_456,
            cpu: CpuStats::default(),
            memory: MemoryBreakdown::default(),
            thread_count: 4,
            open_file_count: 12,
            cgroup: None,
        };
        let json = serde_json::to_string(&snap).expect("serialize");
        let back: ProcessSnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(snap, back);
    }
}
