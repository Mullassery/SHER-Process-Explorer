//! System-wide (not per-process) telemetry: `/proc/meminfo`,
//! `/proc/loadavg`, `/proc/uptime`, `/proc/version`. All confirmed
//! against a real running kernel — these are among the oldest, most
//! stable `/proc` formats and haven't changed across kernel versions.

use std::path::Path;

use sher_pe_model::{LoadAverage, SystemMemory};

use super::procfs::common::{parse_err, read_to_string};
use crate::Result;

/// `/proc/meminfo`: one `"Key:   NNNN kB"` line per field (a handful of
/// lines, like `HugePages_Total`, have no unit suffix — irrelevant to the
/// fields read here, all of which are always in kB).
pub fn read_meminfo(root: &Path) -> Result<SystemMemory> {
    let path = root.join("meminfo");
    let content = read_to_string(&path)?;
    let field = |key: &str| -> Result<u64> {
        let line = content
            .lines()
            .find(|line| line.starts_with(key))
            .ok_or_else(|| parse_err(&path, format!("missing '{key}' line")))?;
        line.trim_start_matches(key)
            .split_whitespace()
            .next()
            .ok_or_else(|| parse_err(&path, format!("'{key}' line has no value")))?
            .parse::<u64>()
            .map(|kb| kb * 1024)
            .map_err(|_| parse_err(&path, format!("'{key}' value is not an integer")))
    };
    Ok(SystemMemory {
        total: field("MemTotal:")?,
        free: field("MemFree:")?,
        available: field("MemAvailable:")?,
        buffers: field("Buffers:")?,
        cached: field("Cached:")?,
        swap_total: field("SwapTotal:")?,
        swap_free: field("SwapFree:")?,
    })
}

/// `/proc/loadavg`: `"<1min> <5min> <15min> <running>/<total> <last_pid>"`.
/// Only the three averages are needed here.
pub fn read_loadavg(root: &Path) -> Result<LoadAverage> {
    let path = root.join("loadavg");
    let content = read_to_string(&path)?;
    let mut fields = content.split_whitespace();
    let mut next_f64 = || -> Result<f64> {
        fields
            .next()
            .ok_or_else(|| parse_err(&path, "loadavg has fewer than 3 fields"))?
            .parse::<f64>()
            .map_err(|_| parse_err(&path, "loadavg field is not a number"))
    };
    Ok(LoadAverage {
        one_min: next_f64()?,
        five_min: next_f64()?,
        fifteen_min: next_f64()?,
    })
}

/// `/proc/uptime`: `"<uptime_secs> <idle_secs>"`. Only the first field is
/// needed.
pub fn read_uptime_secs(root: &Path) -> Result<f64> {
    let path = root.join("uptime");
    let content = read_to_string(&path)?;
    content
        .split_whitespace()
        .next()
        .ok_or_else(|| parse_err(&path, "uptime file is empty"))?
        .parse::<f64>()
        .map_err(|_| parse_err(&path, "uptime field is not a number"))
}

/// `/proc/version`'s raw content, trimmed. A single free-form line — no
/// further parsing attempted, since its exact wording varies by
/// distro/build and any structured extraction would be guessing at a
/// format that isn't actually stable.
pub fn read_kernel_version(root: &Path) -> Result<String> {
    let path = root.join("version");
    Ok(read_to_string(&path)?.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_fixture(dir: &Path, name: &str, content: &str) {
        std::fs::write(dir.join(name), content).unwrap();
    }

    fn fixture_dir() -> std::path::PathBuf {
        // Tests in this module run in parallel within the same process, so
        // a directory keyed only by process id was shared across all of
        // them — one test's `remove_dir_all` cleanup could delete a file
        // another concurrently-running test had just written. A per-call
        // atomic counter keeps each test's fixture directory unique.
        static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("sher-pe-system-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn read_meminfo_parses_real_shaped_fixture() {
        let dir = fixture_dir();
        write_fixture(
            &dir,
            "meminfo",
            "MemTotal:        8126672 kB\n\
             MemFree:         7098928 kB\n\
             MemAvailable:    7558868 kB\n\
             Buffers:           45032 kB\n\
             Cached:            552932 kB\n\
             SwapTotal:       1048572 kB\n\
             SwapFree:        1048572 kB\n",
        );
        let mem = read_meminfo(&dir).unwrap();
        assert_eq!(mem.total, 8_126_672 * 1024);
        assert_eq!(mem.free, 7_098_928 * 1024);
        assert_eq!(mem.swap_total, 1_048_572 * 1024);
        assert_eq!(mem.used(), (8_126_672 - 7_098_928) * 1024);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_loadavg_parses_real_shaped_fixture() {
        let dir = fixture_dir();
        write_fixture(&dir, "loadavg", "0.28 0.18 0.09 4/278 7\n");
        let load = read_loadavg(&dir).unwrap();
        assert!((load.one_min - 0.28).abs() < f64::EPSILON);
        assert!((load.five_min - 0.18).abs() < f64::EPSILON);
        assert!((load.fifteen_min - 0.09).abs() < f64::EPSILON);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_uptime_secs_parses_real_shaped_fixture() {
        let dir = fixture_dir();
        write_fixture(&dir, "uptime", "289.27 2826.43\n");
        let uptime = read_uptime_secs(&dir).unwrap();
        assert!((uptime - 289.27).abs() < f64::EPSILON);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_kernel_version_trims_real_shaped_fixture() {
        let dir = fixture_dir();
        write_fixture(
            &dir,
            "version",
            "Linux version 6.12.76-linuxkit (root@buildkitsandbox)\n",
        );
        let version = read_kernel_version(&dir).unwrap();
        assert_eq!(
            version,
            "Linux version 6.12.76-linuxkit (root@buildkitsandbox)"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_meminfo_errors_on_missing_file() {
        let dir = fixture_dir();
        let err = read_meminfo(&dir).unwrap_err();
        assert!(matches!(err, crate::TelemetryError::Io { .. }));
        std::fs::remove_dir_all(&dir).ok();
    }
}
