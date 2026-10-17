use serde::{Deserialize, Serialize};

use crate::Pid;

/// The kind of process-lifecycle event a `refresh()` can detect between
/// two ticks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TimelineEventKind {
    Started,
    Exited {
        exit_reason: Option<String>,
    },
    MemoryGrowthThresholdCrossed {
        percent_growth: f64,
        window_secs: u64,
    },
    NewChild {
        child_pid: Pid,
    },
    NewConnection {
        remote_addr: String,
    },
}

/// One entry in a process's history timeline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub pid: Pid,
    /// Start time of the process *generation* this event belongs to.
    ///
    /// Together with `pid` this forms the PID-reuse-safe key
    /// `(Pid, start_time)` the rest of the system uses: the kernel reuses
    /// PIDs, so an event must be attributable to the exact run it was
    /// observed in, not just the bare pid (which a later, unrelated process
    /// could reuse).
    pub start_time: u64,
    /// Unix timestamp (seconds) this event was observed.
    pub at: i64,
    pub kind: TimelineEventKind,
    pub description: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeline_event_json_round_trip() {
        let event = TimelineEvent {
            pid: 42,
            start_time: 1_699_999_000,
            at: 1_700_000_000,
            kind: TimelineEventKind::MemoryGrowthThresholdCrossed {
                percent_growth: 62.5,
                window_secs: 3600,
            },
            description: "RSS grew 62.5% in the last hour".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: TimelineEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }
}
