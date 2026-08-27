//! Live, opt-in deep syscall tracing (`Tier::DeepTrace`) via real eBPF —
//! `bpftrace` attached to every `syscalls:sys_enter_*` tracepoint, filtered
//! to one pid. Genuinely different from `strace.rs`'s aggregate counts:
//! this is a per-event timeline. Requires `bpftrace` installed, `tracefs`
//! mounted (standard on real Linux desktops, not always true inside a
//! container), and enough privilege (`CAP_BPF`/`CAP_SYS_ADMIN`).
//!
//! A tight syscall-bound process can generate hundreds of thousands of
//! events per second — confirmed against a real busy-loop process, not
//! assumed — so `MAX_EVENTS` caps what's returned regardless of how much
//! more `bpftrace` actually captured.

use std::process::Command;
use std::time::Duration;

use sher_pe_model::{Pid, TraceEvent};

use crate::{Result, TelemetryError};

const MAX_EVENTS: usize = 2000;

/// How long `timeout` waits after sending `SIGTERM` before escalating to
/// `SIGKILL`. Required, not optional: measured directly that under a
/// high-syscall-rate process, `bpftrace`'s userspace polling loop can take
/// several seconds to notice `SIGTERM` and exit — `timeout <secs>` alone
/// (the pattern `strace.rs` uses) left a real test run running for ~13s
/// after a requested 3s duration. `-k` gives a hard wall-clock bound.
const KILL_GRACE_SECS: u64 = 2;

pub fn deep_trace(pid: Pid, duration: Duration) -> Result<Vec<TraceEvent>> {
    let script_path =
        std::env::temp_dir().join(format!("sher-pe-bpftrace-{pid}-{}.bt", std::process::id()));
    let script =
        format!("tracepoint:syscalls:sys_enter_* /pid == {pid}/ {{\n    printf(\"%llu|%s\\n\", nsecs, probe);\n}}\n");
    std::fs::write(&script_path, &script).map_err(|source| TelemetryError::Io {
        path: script_path.display().to_string(),
        source,
    })?;

    let duration_secs = duration.as_secs().max(1);
    let output = Command::new("timeout")
        .args([
            "-k",
            &KILL_GRACE_SECS.to_string(),
            &duration_secs.to_string(),
            "bpftrace",
        ])
        .arg(&script_path)
        .output();
    let _ = std::fs::remove_file(&script_path);
    let output = output.map_err(|source| TelemetryError::Io {
        path: "bpftrace".to_string(),
        source,
    })?;

    // 124 = `timeout`'s SIGTERM fired; 137 = its follow-up SIGKILL fired.
    // Both mean "the sample ran for its requested duration," not a
    // failure — the same acceptance `strace.rs` gives 124, extended here
    // to also accept the forced-kill case this module specifically needs.
    let code = output.status.code();
    let sample_completed_as_expected = code == Some(124) || code == Some(137);
    if !output.status.success() && !sample_completed_as_expected {
        return Err(TelemetryError::Io {
            path: "bpftrace".to_string(),
            source: std::io::Error::other(format!(
                "bpftrace exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )),
        });
    }

    Ok(parse_bpftrace_output(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

/// Parses lines of the form `"<nsecs>|tracepoint:syscalls:sys_enter_<name>"`
/// (bpftrace's own `Attaching N probes...` banner and any blank lines have
/// no `|` and are skipped naturally). Timestamps are normalized relative
/// to the first captured event, since `nsecs` is an arbitrary monotonic
/// reference, not wall-clock time.
fn parse_bpftrace_output(stdout: &str) -> Vec<TraceEvent> {
    let mut first_ns: Option<u64> = None;
    let mut events = Vec::new();
    for line in stdout.lines() {
        let Some((ns_str, probe)) = line.split_once('|') else {
            continue;
        };
        let Ok(ns) = ns_str.trim().parse::<u64>() else {
            continue;
        };
        let probe = probe.trim();
        let syscall = probe
            .strip_prefix("tracepoint:syscalls:sys_enter_")
            .unwrap_or(probe);
        if syscall.is_empty() {
            continue;
        }
        let base = *first_ns.get_or_insert(ns);
        events.push(TraceEvent {
            at_ns: ns.saturating_sub(base),
            syscall: syscall.to_string(),
        });
        if events.len() >= MAX_EVENTS {
            break;
        }
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bpftrace_output_skips_banner_and_normalizes_timestamps() {
        let stdout = "\
Attaching 305 probes...
1000000100|tracepoint:syscalls:sys_enter_openat
1000000200|tracepoint:syscalls:sys_enter_write
1000000350|tracepoint:syscalls:sys_enter_close
";
        let events = parse_bpftrace_output(stdout);
        assert_eq!(events.len(), 3);
        assert_eq!(
            events[0],
            TraceEvent {
                at_ns: 0,
                syscall: "openat".to_string()
            }
        );
        assert_eq!(
            events[1],
            TraceEvent {
                at_ns: 100,
                syscall: "write".to_string()
            }
        );
        assert_eq!(
            events[2],
            TraceEvent {
                at_ns: 250,
                syscall: "close".to_string()
            }
        );
    }

    #[test]
    fn parse_bpftrace_output_caps_at_max_events() {
        let mut stdout = String::new();
        for i in 0..(MAX_EVENTS + 500) {
            stdout.push_str(&format!("{i}|tracepoint:syscalls:sys_enter_read\n"));
        }
        let events = parse_bpftrace_output(&stdout);
        assert_eq!(events.len(), MAX_EVENTS);
    }

    #[test]
    fn parse_bpftrace_output_empty_is_empty() {
        assert!(parse_bpftrace_output("").is_empty());
    }

    #[test]
    fn parse_bpftrace_output_ignores_malformed_lines() {
        let stdout =
            "not a real line\n|missing timestamp\nabc|tracepoint:syscalls:sys_enter_read\n";
        assert!(parse_bpftrace_output(stdout).is_empty());
    }
}
