use std::path::Path;

use sher_pe_model::{Pid, SchedulerStats};

use super::common::{parse_err, read_to_string};
use crate::Result;

/// `/proc/[pid]/schedstat`: three whitespace-separated integers, in the
/// kernel's documented order — time running, time waiting on a runqueue,
/// number of timeslices (see `Documentation/scheduler/sched-stats.rst`).
pub fn read_schedstat(root: &Path, pid: Pid) -> Result<SchedulerStats> {
    let path = root.join(pid.to_string()).join("schedstat");
    let content = read_to_string(&path)?;
    let mut fields = content.split_whitespace();
    let mut next_u64 = || -> Result<u64> {
        fields
            .next()
            .ok_or_else(|| parse_err(&path, "schedstat has fewer than 3 fields"))?
            .parse::<u64>()
            .map_err(|_| parse_err(&path, "schedstat field is not an integer"))
    };
    Ok(SchedulerStats {
        on_cpu_ns: next_u64()?,
        wait_ns: next_u64()?,
        timeslices: next_u64()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc")
    }

    #[test]
    fn read_schedstat_parses_fixture() {
        let stats = read_schedstat(&fixture_root(), 100).unwrap();
        assert_eq!(stats.on_cpu_ns, 500_000_000);
        assert_eq!(stats.wait_ns, 50_000_000);
        assert_eq!(stats.timeslices, 42);
    }

    #[test]
    fn read_schedstat_errors_on_missing_file() {
        let err = read_schedstat(&fixture_root(), 999_999).unwrap_err();
        assert!(matches!(err, crate::TelemetryError::Io { .. }));
    }
}
