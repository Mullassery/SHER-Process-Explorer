//! Kernel-log reading, used only for OOM-kill correlation in the
//! investigation engine's `crash_analysis`. Best-effort by nature — kernel
//! log access is frequently permission-gated — so callers get a `Result`
//! and decide how to degrade, rather than this module silently returning
//! nothing on failure.

use std::process::Command;

use crate::{Result, TelemetryError};

/// Shells out to `dmesg -T` (human-readable timestamps) for the raw
/// kernel ring buffer.
pub fn read_dmesg() -> Result<String> {
    let output = Command::new("dmesg")
        .arg("-T")
        .output()
        .map_err(|source| TelemetryError::Io {
            path: "dmesg".to_string(),
            source,
        })?;
    if !output.status.success() {
        return Err(TelemetryError::Io {
            path: "dmesg".to_string(),
            source: std::io::Error::other(format!(
                "dmesg exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Filters raw kernel-log text down to lines relevant to an OOM kill —
/// pure string matching, testable without a real kernel log.
pub fn oom_kill_lines(kernel_log: &str) -> Vec<String> {
    kernel_log
        .lines()
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            lower.contains("out of memory")
                || lower.contains("oom-killer")
                || lower.contains("killed process")
        })
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oom_kill_lines_filters_relevant_entries() {
        let log = "\
[Mon Aug 25 10:00:00 2026] sherd[1234]: normal startup message
[Mon Aug 25 10:05:00 2026] Out of memory: Killed process 1234 (sherd) total-vm:2048000kB
[Mon Aug 25 10:05:00 2026] some-worker invoked oom-killer: gfp_mask=0x140cca
[Mon Aug 25 10:06:00 2026] unrelated message
";
        let lines = oom_kill_lines(log);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("Killed process 1234"));
        assert!(lines[1].contains("invoked oom-killer"));
    }

    #[test]
    fn oom_kill_lines_empty_for_clean_log() {
        let log = "[Mon Aug 25 10:00:00 2026] nothing to see here\n";
        assert!(oom_kill_lines(log).is_empty());
    }
}
