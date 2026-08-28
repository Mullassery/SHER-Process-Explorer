//! Real journald ingestion for timeline correlation: `journalctl -u <unit>
//! -o json` gives one real, structured JSON object per line (confirmed
//! directly against a real systemd container) — parsed via `serde_json`,
//! not scraped from journalctl's human-readable text the way
//! `systemd.rs`'s `systemctl_show`/`journalctl_unit_logs` do (those exist
//! for showing a human raw log; this exists for machine-correlatable
//! timestamps).

use std::process::Command;

use serde::Deserialize;
use sher_pe_model::{LogEntry, Pid};

use crate::{Result, TelemetryError};

/// The subset of journald's export fields this needs. Field names are
/// journald's own real, stable export-format keys (see
/// `systemd.journal-fields(7)`) — `#[serde(rename)]` matches them
/// verbatim rather than guessing.
#[derive(Debug, Deserialize)]
struct RawEntry {
    #[serde(rename = "__REALTIME_TIMESTAMP")]
    realtime_timestamp: Option<String>,
    #[serde(rename = "MESSAGE")]
    message: Option<serde_json::Value>,
    #[serde(rename = "PRIORITY")]
    priority: Option<String>,
    #[serde(rename = "_PID")]
    pid: Option<String>,
    #[serde(rename = "SYSLOG_IDENTIFIER")]
    syslog_identifier: Option<String>,
}

/// Reads the most recent `max_lines` journal entries for `unit`. `Ok(vec
/// ![])` for a unit with no journal entries; a real error only for
/// `journalctl` itself failing to run (missing, no journald, permission
/// denied).
pub fn unit_log_entries(unit: &str, max_lines: usize) -> Result<Vec<LogEntry>> {
    let output = Command::new("journalctl")
        .args([
            "-u",
            unit,
            "-o",
            "json",
            "-n",
            &max_lines.to_string(),
            "--no-pager",
        ])
        .output()
        .map_err(|source| TelemetryError::Io {
            path: "journalctl".to_string(),
            source,
        })?;

    if !output.status.success() {
        return Err(TelemetryError::Io {
            path: "journalctl".to_string(),
            source: std::io::Error::other(format!(
                "journalctl exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )),
        });
    }

    Ok(parse_journal_json(&String::from_utf8_lossy(&output.stdout)))
}

/// Parses `journalctl -o json`'s one-JSON-object-per-line output. A line
/// that fails to parse (unexpected shape, or `MESSAGE` as a byte array
/// when the real message wasn't valid UTF-8 — a documented journald
/// quirk) is skipped rather than aborting the whole read; a partial real
/// timeline is more useful than none.
fn parse_journal_json(stdout: &str) -> Vec<LogEntry> {
    stdout
        .lines()
        .filter_map(|line| {
            let raw: RawEntry = serde_json::from_str(line).ok()?;
            let at_us: i64 = raw.realtime_timestamp?.parse().ok()?;
            let message = match raw.message {
                Some(serde_json::Value::String(s)) => s,
                Some(_) => "(non-UTF8 message)".to_string(),
                None => return None,
            };
            Some(LogEntry {
                at_us,
                message,
                priority: raw.priority.and_then(|p| p.parse().ok()),
                pid: raw.pid.and_then(|p| p.parse::<Pid>().ok()),
                identifier: raw.syslog_identifier,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_journal_json_reads_real_shaped_entry() {
        // Field ordering and presence match a real journalctl -o json
        // line captured from a genuine systemd container.
        let line = r#"{"_SYSTEMD_SLICE":"-.slice","_HOSTNAME":"host","__REALTIME_TIMESTAMP":"1787884007959954","_PID":"1","SYSLOG_IDENTIFIER":"systemd","PRIORITY":"6","MESSAGE":"Reached target Timer Units."}"#;
        let entries = parse_journal_json(line);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].at_us, 1_787_884_007_959_954);
        assert_eq!(entries[0].message, "Reached target Timer Units.");
        assert_eq!(entries[0].priority, Some(6));
        assert_eq!(entries[0].pid, Some(1));
        assert_eq!(entries[0].identifier, Some("systemd".to_string()));
    }

    #[test]
    fn parse_journal_json_skips_lines_without_timestamp_or_message() {
        let stdout = "not json at all\n{\"MESSAGE\":\"no timestamp\"}\n{}\n";
        assert!(parse_journal_json(stdout).is_empty());
    }

    #[test]
    fn parse_journal_json_handles_non_utf8_message_array() {
        // journald represents a non-UTF8 MESSAGE as a byte array instead
        // of a string.
        let line = r#"{"__REALTIME_TIMESTAMP":"100","MESSAGE":[104,105,255]}"#;
        let entries = parse_journal_json(line);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].message, "(non-UTF8 message)");
    }

    #[test]
    fn parse_journal_json_reads_multiple_lines() {
        let stdout = "{\"__REALTIME_TIMESTAMP\":\"100\",\"MESSAGE\":\"first\"}\n{\"__REALTIME_TIMESTAMP\":\"200\",\"MESSAGE\":\"second\"}\n";
        let entries = parse_journal_json(stdout);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].message, "first");
        assert_eq!(entries[1].message, "second");
    }
}
