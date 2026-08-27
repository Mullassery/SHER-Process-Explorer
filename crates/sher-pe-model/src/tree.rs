use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::process::ProcessSnapshot;
use crate::Pid;

/// The full process hierarchy at one point in time.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProcessTree {
    pub nodes: HashMap<Pid, ProcessSnapshot>,
    pub children: HashMap<Pid, Vec<Pid>>,
}

/// Aggregated resource usage across a process and all of its descendants.
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
pub struct FamilyRollup {
    pub process_count: u32,
    pub cpu_percent: f64,
    pub rss: u64,
    pub thread_count: u32,
    pub open_file_count: u32,
}

impl ProcessTree {
    /// Builds a tree from a flat list of snapshots (as returned by one
    /// `TelemetryAdapter::list_pids` + `process` pass). A snapshot whose
    /// `ppid` isn't itself present in `snapshots` (i.e. its parent already
    /// exited, or it's `init`/a kernel thread's parent) is treated as a
    /// root — it simply has no entry pointing to it in `children`.
    pub fn build(snapshots: impl IntoIterator<Item = ProcessSnapshot>) -> Self {
        let nodes: HashMap<Pid, ProcessSnapshot> =
            snapshots.into_iter().map(|s| (s.pid, s)).collect();

        let mut children: HashMap<Pid, Vec<Pid>> = HashMap::new();
        for snap in nodes.values() {
            if nodes.contains_key(&snap.ppid) && snap.ppid != snap.pid {
                children.entry(snap.ppid).or_default().push(snap.pid);
            }
        }

        Self { nodes, children }
    }

    /// The roots of the forest: processes whose parent is absent from this
    /// tree (already exited, or PID 0/1's own parent).
    pub fn roots(&self) -> Vec<Pid> {
        self.nodes
            .keys()
            .copied()
            .filter(|pid| {
                let Some(snap) = self.nodes.get(pid) else {
                    return false;
                };
                snap.ppid == *pid || !self.nodes.contains_key(&snap.ppid)
            })
            .collect()
    }

    /// `pid` plus every descendant, in breadth-first order. Returns an
    /// empty vec if `pid` isn't in the tree.
    pub fn family(&self, pid: Pid) -> Vec<Pid> {
        if !self.nodes.contains_key(&pid) {
            return Vec::new();
        }
        let mut family = Vec::new();
        let mut queue = std::collections::VecDeque::from([pid]);
        while let Some(current) = queue.pop_front() {
            family.push(current);
            if let Some(kids) = self.children.get(&current) {
                queue.extend(kids.iter().copied());
            }
        }
        family
    }

    /// Sums CPU%, RSS, thread count, and open-file count across `pid` and
    /// every descendant. Returns `None` if `pid` isn't in the tree, rather
    /// than a silent zeroed rollup — an absent process is a different fact
    /// than a process using zero resources.
    pub fn aggregate(&self, pid: Pid) -> Option<FamilyRollup> {
        if !self.nodes.contains_key(&pid) {
            return None;
        }
        let mut rollup = FamilyRollup::default();
        for member_pid in self.family(pid) {
            let Some(snap) = self.nodes.get(&member_pid) else {
                continue;
            };
            rollup.process_count += 1;
            rollup.cpu_percent += snap.cpu.percent;
            rollup.rss += snap.memory.rss;
            rollup.thread_count += snap.thread_count;
            rollup.open_file_count += snap.open_file_count;
        }
        Some(rollup)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cpu::CpuStats;
    use crate::memory::MemoryBreakdown;
    use crate::process::ProcessState;

    fn snap(pid: Pid, ppid: Pid, rss: u64, cpu_percent: f64) -> ProcessSnapshot {
        ProcessSnapshot {
            pid,
            ppid,
            name: format!("proc-{pid}"),
            cmdline: vec![],
            exe: None,
            state: ProcessState::Running,
            uid: 1000,
            gid: 1000,
            start_time: 0,
            cpu: CpuStats {
                percent: cpu_percent,
                ..Default::default()
            },
            memory: MemoryBreakdown {
                rss,
                ..Default::default()
            },
            thread_count: 1,
            open_file_count: 2,
            cgroup: None,
        }
    }

    #[test]
    fn build_links_children_and_skips_absent_parents() {
        // 1 is root (its ppid 0 isn't in the set), 2 and 3 are children of 1,
        // 4 is a child of 2 (grandchild of 1).
        let tree = ProcessTree::build([
            snap(1, 0, 1000, 1.0),
            snap(2, 1, 2000, 2.0),
            snap(3, 1, 3000, 3.0),
            snap(4, 2, 4000, 4.0),
        ]);

        assert_eq!(tree.roots(), vec![1]);
        let mut kids_of_1 = tree.children.get(&1).cloned().unwrap_or_default();
        kids_of_1.sort();
        assert_eq!(kids_of_1, vec![2, 3]);
        assert_eq!(tree.children.get(&2), Some(&vec![4]));
    }

    #[test]
    fn family_includes_self_and_all_descendants() {
        let tree = ProcessTree::build([
            snap(1, 0, 1000, 1.0),
            snap(2, 1, 2000, 2.0),
            snap(3, 1, 3000, 3.0),
            snap(4, 2, 4000, 4.0),
        ]);

        let mut family = tree.family(1);
        family.sort();
        assert_eq!(family, vec![1, 2, 3, 4]);
        assert_eq!(tree.family(4), vec![4]);
        assert_eq!(tree.family(999), Vec::<Pid>::new());
    }

    #[test]
    fn aggregate_sums_family_resources() {
        let tree = ProcessTree::build([
            snap(1, 0, 1000, 1.0),
            snap(2, 1, 2000, 2.0),
            snap(4, 2, 4000, 4.0),
        ]);

        let rollup = tree.aggregate(1).expect("pid 1 exists");
        assert_eq!(rollup.process_count, 3);
        assert_eq!(rollup.rss, 7000);
        assert!((rollup.cpu_percent - 7.0).abs() < f64::EPSILON);
        assert_eq!(rollup.thread_count, 3);
        assert_eq!(rollup.open_file_count, 6);
    }

    #[test]
    fn aggregate_returns_none_for_absent_pid() {
        let tree = ProcessTree::build([snap(1, 0, 1000, 1.0)]);
        assert_eq!(tree.aggregate(999), None);
    }
}
