use std::path::Path;

use sher_pe_model::{DiskIoStats, Pid};

use super::common::{parse_err, read_to_string};
use crate::Result;

/// `/proc/[pid]/io`'s `read_bytes`/`write_bytes` fields: actual bytes
/// fetched from or sent to the underlying block layer, not `rchar`/
/// `wchar` (which also count cache-served I/O). Requires
/// `CAP_SYS_PTRACE` to read another user's — a `PermissionDenied` here is
/// routine, not a bug.
pub fn read_io(root: &Path, pid: Pid) -> Result<DiskIoStats> {
    let path = root.join(pid.to_string()).join("io");
    let content = read_to_string(&path)?;
    Ok(DiskIoStats {
        read_bytes: field(&content, "read_bytes:", &path)?,
        write_bytes: field(&content, "write_bytes:", &path)?,
    })
}

fn field(content: &str, key: &str, path: &Path) -> Result<u64> {
    let line = content
        .lines()
        .find(|line| line.starts_with(key))
        .ok_or_else(|| parse_err(path, format!("missing '{key}' line")))?;
    line.trim_start_matches(key)
        .trim()
        .parse::<u64>()
        .map_err(|_| parse_err(path, format!("'{key}' value is not an integer")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc")
    }

    #[test]
    fn read_io_parses_fixture() {
        let io = read_io(&fixture_root(), 100).unwrap();
        assert_eq!(io.read_bytes, 4_096_000);
        assert_eq!(io.write_bytes, 819_200);
    }
}
