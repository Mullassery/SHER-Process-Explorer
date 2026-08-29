use std::path::Path;

use sher_pe_model::{FdLimits, Pid};

use super::common::{parse_err, read_to_string};
use crate::Result;

/// `/proc/[pid]/limits`, specifically the "Max open files" row
/// (`RLIMIT_NOFILE` soft/hard) — the concrete, named gap this exists to
/// close: diagnosing "too many open files" against the process's actual
/// configured ceiling, not just its current `open_file_count`. The rest
/// of the file's rows (cpu time, stack size, ...) aren't parsed, since
/// nothing in this project needs them yet.
pub fn read_fd_limits(root: &Path, pid: Pid) -> Result<FdLimits> {
    let path = root.join(pid.to_string()).join("limits");
    let content = read_to_string(&path)?;
    let line = content
        .lines()
        .find(|line| line.starts_with("Max open files"))
        .ok_or_else(|| parse_err(&path, "missing 'Max open files' line"))?;

    // "Max open files             1024                 4096                 files"
    // — the limit name itself is three whitespace-separated words.
    let mut fields = line.split_whitespace().skip(3);
    let soft = fields
        .next()
        .ok_or_else(|| parse_err(&path, "'Max open files' line has no soft limit"))?;
    let hard = fields
        .next()
        .ok_or_else(|| parse_err(&path, "'Max open files' line has no hard limit"))?;

    Ok(FdLimits {
        soft: parse_limit_value(&path, soft)?,
        hard: parse_limit_value(&path, hard)?,
    })
}

/// The kernel prints `RLIM_INFINITY` as the literal string `"unlimited"`;
/// anything else must be a real integer, never silently treated as
/// unlimited just because it failed to parse.
fn parse_limit_value(path: &Path, s: &str) -> Result<Option<u64>> {
    if s == "unlimited" {
        Ok(None)
    } else {
        s.parse::<u64>().map(Some).map_err(|_| {
            parse_err(
                path,
                format!("limit value is not an integer or 'unlimited': '{s}'"),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc")
    }

    #[test]
    fn read_fd_limits_parses_fixture() {
        let limits = read_fd_limits(&fixture_root(), 100).unwrap();
        assert_eq!(limits.soft, Some(1024));
        assert_eq!(limits.hard, Some(4096));
    }

    #[test]
    fn read_fd_limits_errors_on_missing_file() {
        let err = read_fd_limits(&fixture_root(), 999_999).unwrap_err();
        assert!(matches!(err, crate::TelemetryError::Io { .. }));
    }

    #[test]
    fn parse_limit_value_treats_unlimited_as_none() {
        let path = Path::new("/proc/1/limits");
        assert_eq!(parse_limit_value(path, "unlimited").unwrap(), None);
        assert_eq!(parse_limit_value(path, "1024").unwrap(), Some(1024));
    }

    #[test]
    fn parse_limit_value_errors_on_garbage_rather_than_guessing_unlimited() {
        let path = Path::new("/proc/1/limits");
        let err = parse_limit_value(path, "not-a-number").unwrap_err();
        assert!(matches!(err, crate::TelemetryError::Parse { .. }));
    }
}
