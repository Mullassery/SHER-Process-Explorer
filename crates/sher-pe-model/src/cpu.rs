use serde::{Deserialize, Serialize};

/// CPU accounting for a process or thread.
///
/// `percent` is deliberately not computed here: a single `/proc` read only
/// gives cumulative ticks since start, not a rate. `sher-pe-intelligence`
/// computes `percent` from the delta between two snapshots' `utime_ticks` +
/// `stime_ticks` divided by the elapsed wall time between them — telemetry
/// never fabricates a rate from one reading.
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
pub struct CpuStats {
    pub utime_ticks: u64,
    pub stime_ticks: u64,
    pub percent: f64,
    pub voluntary_ctxt_switches: u64,
    pub nonvoluntary_ctxt_switches: u64,
}

impl CpuStats {
    /// Total ticks (user + system) this snapshot has accumulated since
    /// process start. Used by the intelligence layer to compute `percent`
    /// from deltas across two snapshots.
    pub fn total_ticks(&self) -> u64 {
        self.utime_ticks + self.stime_ticks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn total_ticks_sums_user_and_system() {
        let stats = CpuStats {
            utime_ticks: 100,
            stime_ticks: 50,
            ..Default::default()
        };
        assert_eq!(stats.total_ticks(), 150);
    }

    #[test]
    fn cpu_stats_json_round_trip() {
        let stats = CpuStats {
            utime_ticks: 10,
            stime_ticks: 5,
            percent: 12.5,
            voluntary_ctxt_switches: 3,
            nonvoluntary_ctxt_switches: 1,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let back: CpuStats = serde_json::from_str(&json).unwrap();
        assert_eq!(stats, back);
    }
}
