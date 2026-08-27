use serde::{Deserialize, Serialize};

/// Scheduler accounting for one process/thread, from `/proc/[pid]/schedstat`
/// (three fields, in the kernel's documented order): time actually running
/// on a CPU, time spent runnable but waiting for one, and how many
/// timeslices it has been given. Cheap enough to read on every refresh —
/// no sampling or privilege beyond normal `/proc` access required.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SchedulerStats {
    pub on_cpu_ns: u64,
    pub wait_ns: u64,
    pub timeslices: u64,
}

impl SchedulerStats {
    /// The fraction of (running + waiting) time that was spent waiting for
    /// a CPU rather than actually running on one — a direct signal of
    /// scheduler contention. `None` when there's no accounted time yet
    /// (a fresh process), rather than a misleading `0.0`.
    pub fn wait_ratio_percent(&self) -> Option<f64> {
        let total = self.on_cpu_ns + self.wait_ns;
        if total == 0 {
            None
        } else {
            Some(self.wait_ns as f64 / total as f64 * 100.0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait_ratio_percent_none_when_no_time_accounted() {
        assert_eq!(SchedulerStats::default().wait_ratio_percent(), None);
    }

    #[test]
    fn wait_ratio_percent_computes_fraction_waiting() {
        let stats = SchedulerStats {
            on_cpu_ns: 900,
            wait_ns: 100,
            timeslices: 5,
        };
        let ratio = stats.wait_ratio_percent().unwrap();
        assert!((ratio - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn scheduler_stats_json_round_trip() {
        let stats = SchedulerStats {
            on_cpu_ns: 1,
            wait_ns: 2,
            timeslices: 3,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let back: SchedulerStats = serde_json::from_str(&json).unwrap();
        assert_eq!(stats, back);
    }
}
