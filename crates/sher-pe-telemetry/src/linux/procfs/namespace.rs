use std::path::Path;

use sher_pe_model::{NamespaceInfo, Pid};

use super::common::{map_io_error, parse_err};
use crate::Result;

/// Reads one `/proc/[pid]/ns/<kind>` symlink and extracts the inode number
/// from its `"kind:[INODE]"`-format target.
fn read_ns_inode(root: &Path, pid: Pid, kind: &str) -> Result<u64> {
    let path = root.join(pid.to_string()).join("ns").join(kind);
    let target = std::fs::read_link(&path).map_err(|source| map_io_error(&path, source))?;
    let target = target.to_string_lossy();
    let open = target
        .find('[')
        .ok_or_else(|| parse_err(&path, "missing '[' in ns target"))?;
    let close = target
        .find(']')
        .ok_or_else(|| parse_err(&path, "missing ']' in ns target"))?;
    target[open + 1..close]
        .parse()
        .map_err(|_| parse_err(&path, "ns inode is not an integer"))
}

/// Reads every namespace `pid` belongs to. `cgroup` is `None` on kernels
/// built without cgroup-namespace support (Linux < 4.6) rather than an
/// error, since the other five namespaces are unaffected by its absence.
pub fn read_namespaces(root: &Path, pid: Pid) -> Result<NamespaceInfo> {
    Ok(NamespaceInfo {
        pid,
        mnt: read_ns_inode(root, pid, "mnt")?,
        net: read_ns_inode(root, pid, "net")?,
        user: read_ns_inode(root, pid, "user")?,
        uts: read_ns_inode(root, pid, "uts")?,
        ipc: read_ns_inode(root, pid, "ipc")?,
        cgroup: read_ns_inode(root, pid, "cgroup").ok(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc")
    }

    #[test]
    fn read_namespaces_parses_all_present_symlinks() {
        let ns = read_namespaces(&fixture_root(), 100).unwrap();
        assert_eq!(ns.pid, 100);
        assert_eq!(ns.mnt, 4_026_531_840);
        assert_eq!(ns.net, 4_026_531_992);
        assert_eq!(ns.cgroup, Some(4_026_531_835));
    }

    #[test]
    fn read_namespaces_treats_missing_cgroup_ns_as_none() {
        // pid 101's fixture has no ns/cgroup symlink, simulating an older
        // kernel without cgroup-namespace support.
        let ns = read_namespaces(&fixture_root(), 101).unwrap();
        assert_eq!(ns.cgroup, None);
        assert_eq!(ns.mnt, 4_026_531_840);
    }
}
