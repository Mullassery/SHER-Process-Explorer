use std::path::Path;

use sher_pe_model::{MemoryBreakdown, Pid};

use super::common::{parse_err, read_to_string, read_to_string_optional};
use crate::Result;

/// `/proc/[pid]/statm`, in pages: `size resident shared text lib data dt`.
/// Returns `(vsz_bytes, rss_bytes)` — the coarse fallback used when
/// `smaps_rollup` isn't available.
pub fn read_statm(root: &Path, pid: Pid, page_size: u64) -> Result<(u64, u64)> {
    let path = root.join(pid.to_string()).join("statm");
    let content = read_to_string(&path)?;
    let mut fields = content.split_whitespace();
    let size = next_u64(&mut fields, &path)?;
    let resident = next_u64(&mut fields, &path)?;
    Ok((size * page_size, resident * page_size))
}

fn next_u64<'a>(fields: &mut impl Iterator<Item = &'a str>, path: &Path) -> Result<u64> {
    fields
        .next()
        .ok_or_else(|| parse_err(path, "statm has fewer fields than expected"))?
        .parse::<u64>()
        .map_err(|_| parse_err(path, "statm field is not an integer"))
}

/// `/proc/[pid]/status`'s `VmSwap:` line, in bytes. Used as the swap
/// fallback when `smaps_rollup` is unavailable.
pub fn read_vmswap(root: &Path, pid: Pid) -> Result<u64> {
    let path = root.join(pid.to_string()).join("status");
    let content = read_to_string(&path)?;
    read_kb_field(&content, "VmSwap:", &path).map(|kb| kb.unwrap_or(0) * 1024)
}

/// A parsed `/proc/[pid]/smaps_rollup`, values in bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SmapsRollup {
    pub rss: u64,
    pub anonymous: u64,
    pub shared_clean: u64,
    pub shared_dirty: u64,
    pub private_clean: u64,
    pub private_dirty: u64,
    pub swap: u64,
}

/// `None` on kernels without `smaps_rollup` (introduced in Linux 4.14) —
/// an expected, gracefully-handled absence, not an error.
pub fn read_smaps_rollup(root: &Path, pid: Pid) -> Result<Option<SmapsRollup>> {
    let path = root.join(pid.to_string()).join("smaps_rollup");
    let Some(content) = read_to_string_optional(&path)? else {
        return Ok(None);
    };
    let field =
        |key: &str| -> Result<u64> { Ok(read_kb_field(&content, key, &path)?.unwrap_or(0) * 1024) };
    Ok(Some(SmapsRollup {
        rss: field("Rss:")?,
        anonymous: field("Anonymous:")?,
        shared_clean: field("Shared_Clean:")?,
        shared_dirty: field("Shared_Dirty:")?,
        private_clean: field("Private_Clean:")?,
        private_dirty: field("Private_Dirty:")?,
        swap: field("Swap:")?,
    }))
}

/// Finds a `"Key:   NNNN kB"`-style line and returns `NNNN`, or `None` if
/// the key isn't present at all (some keys are legitimately optional).
fn read_kb_field(content: &str, key: &str, path: &Path) -> Result<Option<u64>> {
    let Some(line) = content
        .lines()
        .find(|line| line.trim_start().starts_with(key))
    else {
        return Ok(None);
    };
    let value = line
        .trim_start()
        .trim_start_matches(key)
        .split_whitespace()
        .next()
        .ok_or_else(|| parse_err(path, format!("'{key}' line has no value")))?;
    value
        .parse::<u64>()
        .map(Some)
        .map_err(|_| parse_err(path, format!("'{key}' value is not an integer")))
}

/// Composes the full `MemoryBreakdown` for one process: `smaps_rollup`
/// where the kernel provides it, falling back to `statm`/`VmSwap`
/// otherwise. A fallback result has every detailed field at `0`, which is
/// exactly what `MemoryBreakdown::is_detailed()` checks for.
pub fn read_memory_breakdown(root: &Path, pid: Pid, page_size: u64) -> Result<MemoryBreakdown> {
    let (vsz, statm_rss) = read_statm(root, pid, page_size)?;
    match read_smaps_rollup(root, pid)? {
        Some(rollup) => Ok(MemoryBreakdown {
            rss: rollup.rss,
            vsz,
            anonymous: rollup.anonymous,
            file_backed: rollup.rss.saturating_sub(rollup.anonymous),
            shared: rollup.shared_clean + rollup.shared_dirty,
            private: rollup.private_clean + rollup.private_dirty,
            swap: rollup.swap,
        }),
        None => {
            tracing::debug!(
                pid,
                "smaps_rollup unavailable, falling back to statm/VmSwap"
            );
            Ok(MemoryBreakdown {
                rss: statm_rss,
                vsz,
                anonymous: 0,
                file_backed: 0,
                shared: 0,
                private: 0,
                swap: read_vmswap(root, pid)?,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc")
    }

    #[test]
    fn read_statm_converts_pages_to_bytes() {
        let (vsz, rss) = read_statm(&fixture_root(), 100, 4096).unwrap();
        assert_eq!(vsz, 51200 * 4096);
        assert_eq!(rss, 12800 * 4096);
    }

    #[test]
    fn read_smaps_rollup_parses_kb_fields() {
        let rollup = read_smaps_rollup(&fixture_root(), 100)
            .unwrap()
            .expect("present");
        assert_eq!(rollup.rss, 51200 * 1024);
        assert_eq!(rollup.anonymous, 40000 * 1024);
        assert_eq!(rollup.shared_clean, 2000 * 1024);
        assert_eq!(rollup.private_dirty, 45700 * 1024);
    }

    #[test]
    fn read_smaps_rollup_is_none_when_file_absent() {
        // pid 101 has no smaps_rollup fixture, simulating an older kernel.
        let rollup = read_smaps_rollup(&fixture_root(), 101).unwrap();
        assert_eq!(rollup, None);
    }

    #[test]
    fn read_memory_breakdown_prefers_smaps_rollup_when_present() {
        let mem = read_memory_breakdown(&fixture_root(), 100, 4096).unwrap();
        assert!(mem.is_detailed());
        assert_eq!(mem.rss, 51200 * 1024);
        assert_eq!(mem.anonymous, 40000 * 1024);
    }

    #[test]
    fn read_memory_breakdown_falls_back_to_statm_when_rollup_absent() {
        let mem = read_memory_breakdown(&fixture_root(), 101, 4096).unwrap();
        assert!(!mem.is_detailed());
        assert_eq!(mem.rss, 5120 * 4096);
        assert_eq!(mem.swap, 0);
    }
}
