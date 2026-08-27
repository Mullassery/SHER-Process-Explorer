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
