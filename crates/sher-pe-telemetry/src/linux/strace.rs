//! Per-thread syscall breakdown (`Tier::ShortSample`) via the real
//! `strace -c` summary, following the same "shell out to the real thing"
//! choice as `perf.rs`. `strace -p <pid>` runs until interrupted, so this
//! bounds it with `timeout` and treats exit code 124 (timeout fired,
//! meaning the sample completed as intended) the same as a clean exit —
//! `strace -c`'s summary table is written to stderr regardless of how the
//! traced process's own run ends.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use sher_pe_model::{Pid, SyscallStat};

use crate::{Result, TelemetryError};

const TIMEOUT_EXIT_CODE: i32 = 124;

pub fn sample_syscalls(pid: Pid, duration: Duration) -> Result<Vec<SyscallStat>> {
    let output = Command::new("timeout")
        .arg(duration.as_secs().max(1).to_string())
        .args(["strace", "-c", "-f", "-p", &pid.to_string()])
        .output()
        .map_err(|source| TelemetryError::Io {
            path: "strace".to_string(),
            source,
        })?;

    let timed_out_as_expected = output.status.code() == Some(TIMEOUT_EXIT_CODE);
    if !output.status.success() && !timed_out_as_expected {
        return Err(TelemetryError::Io {
            path: "strace".to_string(),
            source: std::io::Error::other(format!(
                "strace exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )),
        });
    }

    parse_strace_summary(
        &String::from_utf8_lossy(&output.stderr),
        Path::new("strace -c"),
    )
}

/// Parses `strace -c`'s summary table (written to stderr):
/// ```text
/// % time     seconds  usecs/call     calls    errors syscall
/// ------ ----------- ----------- --------- --------- ----------------
///  45.23    0.001234          12       102           read
///  30.11    0.000821           8       102         2 write
/// ------ ----------- ----------- --------- --------- ----------------
/// 100.00    0.002730                     204         2 total
/// ```
/// The `errors` column is absent for syscalls with zero errors (not a `0`
/// — genuinely missing), and the final `total` row is dropped since it's
/// a summary of the rows already parsed, not a syscall itself.
fn parse_strace_summary(stderr: &str, path: &Path) -> Result<Vec<SyscallStat>> {
    let mut stats = Vec::new();
    let mut saw_header = false;
    for line in stderr.lines() {
        let line = line.trim();
        if line.starts_with("% time") {
            saw_header = true;
            continue;
        }
        if !saw_header || line.is_empty() || line.starts_with('-') {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        // With errors:    % time  seconds  usecs/call  calls  errors  syscall (6 fields)
        // Without errors: % time  seconds  usecs/call  calls  syscall        (5 fields)
        if fields.len() < 5 {
            continue;
        }
        if fields.last() == Some(&"total") {
            continue;
        }
        let time_percent = fields[0].parse::<f64>().map_err(|_| {
            crate::linux::procfs::common::parse_err(path, format!("bad %time '{}'", fields[0]))
        })?;
        let seconds = fields[1].parse::<f64>().map_err(|_| {
            crate::linux::procfs::common::parse_err(path, format!("bad seconds '{}'", fields[1]))
        })?;
        let calls = fields[3].parse::<u64>().map_err(|_| {
            crate::linux::procfs::common::parse_err(path, format!("bad calls '{}'", fields[3]))
        })?;
        let (errors, name) = if fields.len() >= 6 {
            let errors = fields[4].parse::<u64>().unwrap_or(0);
            (errors, fields[5])
        } else {
            (0, fields[4])
        };
        stats.push(SyscallStat {
            name: name.to_string(),
            calls,
            errors,
            time_percent,
            seconds,
        });
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_strace_summary_handles_mixed_error_columns() {
        let stderr = "\
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 45.23    0.001234          12       102           read
 30.11    0.000821           8       102         2 write
------ ----------- ----------- --------- --------- ----------------
100.00    0.002730                     204         2 total
";
        let stats = parse_strace_summary(stderr, Path::new("test")).unwrap();
        assert_eq!(stats.len(), 2);
        assert_eq!(stats[0].name, "read");
        assert_eq!(stats[0].calls, 102);
        assert_eq!(stats[0].errors, 0);
        assert_eq!(stats[1].name, "write");
        assert_eq!(stats[1].errors, 2);
    }

    #[test]
    fn parse_strace_summary_drops_total_row() {
        let stderr = "\
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
100.00    0.001234          12       102           read
------ ----------- ----------- --------- --------- ----------------
100.00    0.001234                     102           total
";
        let stats = parse_strace_summary(stderr, Path::new("test")).unwrap();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].name, "read");
    }

    #[test]
    fn parse_strace_summary_empty_without_header_is_empty() {
        let stats =
            parse_strace_summary("strace: attach: no such process\n", Path::new("test")).unwrap();
        assert!(stats.is_empty());
    }
}
