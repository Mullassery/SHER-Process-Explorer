use serde::{Deserialize, Serialize};

/// System-wide snapshot: total/used/available memory and swap, load
/// average, uptime, and kernel version. Previously nothing in SHER
/// Process Explorer reported system-level totals — every view was
/// per-process only.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SystemOverview {
    pub memory: SystemMemory,
    pub load_average: LoadAverage,
    /// Seconds since boot (`/proc/uptime`'s first field).
    pub uptime_secs: f64,
    /// Raw `/proc/version` string, e.g. `"Linux version 6.12.76-linuxkit
    /// (...) ..."`.
    pub kernel_version: String,
    pub process_count: usize,
}

/// All fields in bytes (converted from `/proc/meminfo`'s kB).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemMemory {
    pub total: u64,
    pub free: u64,
    /// The kernel's own estimate of memory available for new
    /// applications without swapping — not simply `free + cached`, which
    /// historically overstated real availability.
    pub available: u64,
    pub buffers: u64,
    pub cached: u64,
    pub swap_total: u64,
    pub swap_free: u64,
}

impl SystemMemory {
    pub fn used(&self) -> u64 {
        self.total.saturating_sub(self.free)
    }

    pub fn swap_used(&self) -> u64 {
        self.swap_total.saturating_sub(self.swap_free)
    }
}

/// `/proc/loadavg`'s three averages (1, 5, 15 minutes) — the classic
/// "number of runnable-or-uninterruptible-sleep processes, exponentially
/// averaged" metric.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct LoadAverage {
    pub one_min: f64,
    pub five_min: f64,
    pub fifteen_min: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_memory_used_and_swap_used() {
        let mem = SystemMemory {
            total: 1000,
            free: 300,
            available: 600,
            buffers: 50,
            cached: 200,
            swap_total: 500,
            swap_free: 500,
        };
        assert_eq!(mem.used(), 700);
        assert_eq!(mem.swap_used(), 0);
    }

    #[test]
    fn system_overview_json_round_trip() {
        let overview = SystemOverview {
            memory: SystemMemory {
                total: 1000,
                free: 300,
                available: 600,
                buffers: 50,
                cached: 200,
                swap_total: 500,
                swap_free: 500,
            },
            load_average: LoadAverage {
                one_min: 0.28,
                five_min: 0.18,
                fifteen_min: 0.09,
            },
            uptime_secs: 289.27,
            kernel_version: "Linux version 6.12.76-linuxkit".to_string(),
            process_count: 42,
        };
        let json = serde_json::to_string(&overview).unwrap();
        let back: SystemOverview = serde_json::from_str(&json).unwrap();
        assert_eq!(overview, back);
    }
}
