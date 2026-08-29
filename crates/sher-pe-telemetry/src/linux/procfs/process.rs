use std::path::Path;

use sher_pe_model::{Pid, ProcessState};

use super::common::{list_numeric_entries, parse_err, parse_stat_line, read_to_string, StatFields};
use crate::Result;

/// `/proc/[pid]/stat`, parsed.
pub fn read_stat(root: &Path, pid: Pid) -> Result<StatFields> {
    let path = root.join(pid.to_string()).join("stat");
    let content = read_to_string(&path)?;
    parse_stat_line(&content, &path)
}

/// The real (not effective) uid/gid, from `/proc/[pid]/status`'s `Uid:`/
/// `Gid:` lines (each: real, effective, saved-set, filesystem).
pub fn read_ids(root: &Path, pid: Pid) -> Result<(u32, u32)> {
    let path = root.join(pid.to_string()).join("status");
    let content = read_to_string(&path)?;
    let uid = first_status_value(&content, "Uid:", &path)?;
    let gid = first_status_value(&content, "Gid:", &path)?;
    Ok((uid, gid))
}

/// Extracts the first whitespace-separated value after a `Key:` prefix,
/// e.g. `"Uid:\t1000\t1000\t1000\t1000"` -> `1000`.
pub(super) fn first_status_value(content: &str, key: &str, path: &Path) -> Result<u32> {
    let line = content
        .lines()
        .find(|line| line.starts_with(key))
        .ok_or_else(|| parse_err(path, format!("missing '{key}' line")))?;
    line.trim_start_matches(key)
        .split_whitespace()
        .next()
        .ok_or_else(|| parse_err(path, format!("'{key}' line has no value")))?
        .parse::<u32>()
        .map_err(|_| parse_err(path, format!("'{key}' value is not an integer")))
}

/// `/proc/[pid]/cmdline` is NUL-separated (and NUL-terminated); a kernel
/// thread or a zombie may report it empty.
pub fn read_cmdline(root: &Path, pid: Pid) -> Result<Vec<String>> {
    let path = root.join(pid.to_string()).join("cmdline");
    let content = read_to_string(&path)?;
    Ok(content
        .split('\0')
        .filter(|arg| !arg.is_empty())
        .map(str::to_string)
        .collect())
}

/// `/proc/[pid]/exe`'s symlink target. `None` if the process has exited,
/// is a kernel thread (no `exe`), or the link isn't readable — this is
/// treated as absent information, not a hard error, since it's routine.
pub fn read_exe(root: &Path, pid: Pid) -> Option<String> {
    let path = root.join(pid.to_string()).join("exe");
    std::fs::read_link(&path)
        .ok()
        .map(|target| target.to_string_lossy().into_owned())
}

/// Lists every pid currently present under `root` (i.e. `/proc/*`).
pub fn list_pids(root: &Path) -> Result<Vec<Pid>> {
    list_numeric_entries(root)
}

pub fn process_state(stat: &StatFields) -> ProcessState {
    ProcessState::from_proc_char(stat.state_char)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fixture_root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc")
    }

    #[test]
    fn read_stat_parses_fixture_process() {
        let stat = read_stat(&fixture_root(), 100).expect("read fixture stat");
        assert_eq!(stat.id, 100);
        assert_eq!(stat.comm, "sherd");
        assert_eq!(stat.ppid, 1);
        assert_eq!(stat.pgrp, 100);
        assert_eq!(stat.session, 100);
    }

    #[test]
    fn read_ids_parses_fixture_status() {
        let (uid, gid) = read_ids(&fixture_root(), 100).expect("read fixture status");
        assert_eq!(uid, 1000);
        assert_eq!(gid, 1000);
    }

    #[test]
    fn read_cmdline_splits_on_nul_and_drops_trailing_empty() {
        let cmdline = read_cmdline(&fixture_root(), 100).expect("read fixture cmdline");
        assert_eq!(
            cmdline,
            vec!["sherd".to_string(), "--foreground".to_string()]
        );
    }

    #[test]
    fn read_exe_resolves_symlink() {
        let exe = read_exe(&fixture_root(), 100);
        assert!(exe.is_some());
    }

    #[test]
    fn read_exe_is_none_for_missing_link() {
        let exe = read_exe(&fixture_root(), 999_999);
        assert_eq!(exe, None);
    }

    #[test]
    fn list_pids_finds_only_numeric_dirs() {
        let mut pids = list_pids(&fixture_root()).expect("list fixture pids");
        pids.sort();
        assert!(pids.contains(&100));
        assert!(pids.contains(&101));
    }

    #[test]
    fn read_stat_errors_are_typed_not_panics() {
        let err = read_stat(&fixture_root(), 424_242).unwrap_err();
        assert!(matches!(err, crate::TelemetryError::Io { .. }));
    }

    #[test]
    fn missing_status_line_is_a_typed_parse_error() {
        let dir = std::env::temp_dir().join(format!("sher-pe-test-{}", std::process::id()));
        fs::create_dir_all(dir.join("500")).unwrap();
        fs::write(dir.join("500/status"), "Name:\tweird\n").unwrap();
        let err = read_ids(&dir, 500).unwrap_err();
        assert!(matches!(err, crate::TelemetryError::Parse { .. }));
        fs::remove_dir_all(&dir).ok();
    }
}
