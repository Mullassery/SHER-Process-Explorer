use std::path::Path;

use sher_pe_model::{CpuStats, Pid, ThreadSnapshot};

use super::common::{list_numeric_entries, parse_stat_line, read_to_string};
use crate::linux::affinity;
use crate::Result;

/// Lists every tid under `/proc/[pid]/task/`.
pub fn list_tids(root: &Path, pid: Pid) -> Result<Vec<Pid>> {
    list_numeric_entries(&root.join(pid.to_string()).join("task"))
}

/// Builds a full `ThreadSnapshot` for one `(pid, tid)` pair. CPU `percent`
/// is left at `0.0` here — only the intelligence layer, which sees two
/// snapshots over time, can turn tick counts into a rate.
pub fn read_thread(root: &Path, pid: Pid, tid: Pid) -> Result<ThreadSnapshot> {
    let path = root
        .join(pid.to_string())
        .join("task")
        .join(tid.to_string())
        .join("stat");
    let content = read_to_string(&path)?;
    let stat = parse_stat_line(&content, &path)?;

    // Affinity is Linux-only (real `sched_getaffinity`) and best-effort:
    // a transient failure (thread exited between listing and reading)
    // degrades to an empty affinity list rather than failing the whole
    // thread snapshot.
    let affinity = affinity::read_affinity(tid).unwrap_or_default();

    Ok(ThreadSnapshot {
        tid: stat.id,
        name: stat.comm,
        state: sher_pe_model::ProcessState::from_proc_char(stat.state_char),
        cpu: CpuStats {
            utime_ticks: stat.utime,
            stime_ticks: stat.stime,
            percent: 0.0,
            voluntary_ctxt_switches: 0,
            nonvoluntary_ctxt_switches: 0,
        },
        priority: stat.priority,
        nice: stat.nice,
        affinity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc")
    }

    #[test]
    fn list_tids_finds_both_fixture_threads() {
        let mut tids = list_tids(&fixture_root(), 100).unwrap();
        tids.sort();
        assert_eq!(tids, vec![100, 102]);
    }

    #[test]
    fn read_thread_parses_name_and_cpu_ticks() {
        let thread = read_thread(&fixture_root(), 100, 102).unwrap();
        assert_eq!(thread.tid, 102);
        assert_eq!(thread.name, "sherd:worker");
        assert_eq!(thread.cpu.utime_ticks, 200);
        assert_eq!(thread.cpu.stime_ticks, 100);
        assert_eq!(thread.cpu.percent, 0.0);
    }
}
