//! Shared helpers used by every `/proc` parser: typed I/O error mapping and
//! the `/proc/[pid]/stat` (and `/proc/[pid]/task/[tid]/stat`) line format,
//! which `process.rs` and `threads.rs` both need.

use std::io::ErrorKind;
use std::path::Path;

use sher_pe_model::Pid;

use crate::{Result, TelemetryError};

/// Reads a file to a `String`, mapping `NotFound`/`PermissionDenied` to
/// their typed equivalents so a caller can decide whether to degrade
/// gracefully or propagate.
pub fn read_to_string(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(|source| map_io_error(path, source))
}

/// Like `read_to_string`, but a missing file becomes `Ok(None)` instead of
/// an error — for fields that are legitimately absent on some kernels
/// (e.g. `smaps_rollup`) rather than a hard failure.
pub fn read_to_string_optional(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(content) => Ok(Some(content)),
        Err(source) if source.kind() == ErrorKind::NotFound => Ok(None),
        Err(source) => Err(map_io_error(path, source)),
    }
}

pub fn map_io_error(path: &Path, source: std::io::Error) -> TelemetryError {
    if source.kind() == ErrorKind::PermissionDenied {
        TelemetryError::PermissionDenied(path.display().to_string())
    } else {
        TelemetryError::Io {
            path: path.display().to_string(),
            source,
        }
    }
}

pub fn parse_err(path: &Path, message: impl Into<String>) -> TelemetryError {
    TelemetryError::Parse {
        path: path.display().to_string(),
        message: message.into(),
    }
}

/// The subset of `/proc/[pid]/stat` (or `/proc/[pid]/task/[tid]/stat`)
/// fields this project needs, already parsed to native types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatFields {
    /// Field 1 — the pid (for a process) or tid (for a thread) itself.
    pub id: Pid,
    /// Field 2, `comm`, with the wrapping parens stripped.
    pub comm: String,
    /// Field 3, the single-character run state.
    pub state_char: char,
    /// Field 4.
    pub ppid: Pid,
    /// Field 5 — the process group ID (`setpgid(2)`/job control).
    pub pgrp: Pid,
    /// Field 6 — the session ID (`setsid(2)`).
    pub session: Pid,
    /// Field 14.
    pub utime: u64,
    /// Field 15.
    pub stime: u64,
    /// Field 18.
    pub priority: i32,
    /// Field 19.
    pub nice: i32,
    /// Field 20.
    pub num_threads: u32,
    /// Field 22, in clock ticks since boot.
    pub starttime: u64,
}

/// Parses a `/proc/[pid]/stat`-format line. `comm` (field 2) is
/// parenthesized and may itself contain spaces or parens, so this splits
/// on the *outermost* `(`/`)` pair rather than whitespace.
pub fn parse_stat_line(content: &str, path: &Path) -> Result<StatFields> {
    let content = content.trim_end();
    let open = content
        .find('(')
        .ok_or_else(|| parse_err(path, "missing '(' before comm"))?;
    let close = content
        .rfind(')')
        .ok_or_else(|| parse_err(path, "missing ')' after comm"))?;
    if close <= open {
        return Err(parse_err(path, "malformed comm delimiters"));
    }

    let id_str = content[..open].trim();
    let comm = content[open + 1..close].to_string();
    let rest = content[close + 1..].trim_start();
    let fields: Vec<&str> = rest.split_whitespace().collect();

    // `rest` starts at field 3 (state); field N is at index N - 3.
    const MIN_FIELDS: usize = 20; // through field 22 (starttime), index 19
    if fields.len() < MIN_FIELDS {
        return Err(parse_err(
            path,
            format!(
                "expected at least {MIN_FIELDS} fields after comm, found {}",
                fields.len()
            ),
        ));
    }

    let field = |n: usize| -> Result<&str> {
        fields
            .get(n - 3)
            .copied()
            .ok_or_else(|| parse_err(path, format!("missing field {n}")))
    };
    let parse_num = |s: &str| -> Result<i64> {
        s.parse::<i64>()
            .map_err(|_| parse_err(path, format!("expected an integer, got '{s}'")))
    };

    let id = id_str
        .parse::<Pid>()
        .map_err(|_| parse_err(path, format!("expected an integer pid, got '{id_str}'")))?;
    let state_char = field(3)?.chars().next().unwrap_or('?');
    let ppid = parse_num(field(4)?)? as Pid;
    let pgrp = parse_num(field(5)?)? as Pid;
    let session = parse_num(field(6)?)? as Pid;
    let utime = parse_num(field(14)?)? as u64;
    let stime = parse_num(field(15)?)? as u64;
    let priority = parse_num(field(18)?)? as i32;
    let nice = parse_num(field(19)?)? as i32;
    let num_threads = parse_num(field(20)?)? as u32;
    let starttime = parse_num(field(22)?)? as u64;

    Ok(StatFields {
        id,
        comm,
        state_char,
        ppid,
        pgrp,
        session,
        utime,
        stime,
        priority,
        nice,
        num_threads,
        starttime,
    })
}

/// Lists the numeric subdirectory names of `dir` (used for `/proc/*` pids
/// and `/proc/[pid]/task/*` tids) as parsed integers, skipping anything
/// non-numeric (e.g. `/proc/self`, `/proc/net`).
pub fn list_numeric_entries(dir: &Path) -> Result<Vec<Pid>> {
    let entries = std::fs::read_dir(dir).map_err(|source| map_io_error(dir, source))?;
    let mut ids = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| map_io_error(dir, source))?;
        if let Some(id) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<Pid>().ok())
        {
            ids.push(id);
        }
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_stat_line_handles_simple_comm() {
        let line = "42 (sherd) S 1 42 42 0 -1 4194304 100 0 0 0 10 5 0 0 20 0 4 0 999 0 0 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 1 0 0 0 0 0";
        let fields = parse_stat_line(line, Path::new("/proc/42/stat")).unwrap();
        assert_eq!(fields.id, 42);
        assert_eq!(fields.comm, "sherd");
        assert_eq!(fields.state_char, 'S');
        assert_eq!(fields.ppid, 1);
        assert_eq!(fields.pgrp, 42);
        assert_eq!(fields.session, 42);
        assert_eq!(fields.utime, 10);
        assert_eq!(fields.stime, 5);
        assert_eq!(fields.priority, 20);
        assert_eq!(fields.nice, 0);
        assert_eq!(fields.num_threads, 4);
        assert_eq!(fields.starttime, 999);
    }

    #[test]
    fn parse_stat_line_handles_comm_with_spaces_and_parens() {
        // A comm like "(sh) worker" is realistic (renamed threads can
        // contain almost anything) and must not be split on the inner
        // parens.
        let line = "7 ((sh) worker) R 1 7 7 0 -1 0 0 0 0 0 1 1 0 0 20 0 1 0 5 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0";
        let fields = parse_stat_line(line, Path::new("/proc/7/stat")).unwrap();
        assert_eq!(fields.comm, "(sh) worker");
        assert_eq!(fields.state_char, 'R');
    }

    #[test]
    fn parse_stat_line_errors_on_too_few_fields() {
        let err = parse_stat_line("1 (init) S 0", Path::new("/proc/1/stat")).unwrap_err();
        assert!(matches!(err, TelemetryError::Parse { .. }));
    }
}
