use serde::{Deserialize, Serialize};

use crate::Pid;

/// One structured journald entry, from `journalctl -o json` (real
/// structured fields, not scraped human-readable text — see
/// `sher_pe_telemetry::linux::journald`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    /// Microseconds since the Unix epoch (`__REALTIME_TIMESTAMP`) — real
    /// wall-clock time, unlike `bpftrace`'s `nsecs` or `dmesg`'s
    /// boot-relative offsets, so this is directly comparable to
    /// `TimelineEvent::at` (its seconds, times 1,000,000).
    pub at_us: i64,
    pub message: String,
    /// Syslog priority (0 = emergency, 7 = debug), when present.
    pub priority: Option<u8>,
    pub pid: Option<Pid>,
    /// `SYSLOG_IDENTIFIER`, e.g. `"systemd"` or the unit's own binary name.
    pub identifier: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_entry_json_round_trip() {
        let entry = LogEntry {
            at_us: 1_700_000_000_000_000,
            message: "Started sherd.service".into(),
            priority: Some(6),
            pid: Some(1234),
            identifier: Some("systemd".into()),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: LogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }
}
