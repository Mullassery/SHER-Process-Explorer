use serde::{Deserialize, Serialize};

use crate::Pid;

/// Linux namespace membership for a process, as inode numbers read from
/// `/proc/[pid]/ns/*`. Two processes share a namespace iff their inode
/// numbers for that namespace kind match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceInfo {
    pub pid: Pid,
    pub mnt: u64,
    pub net: u64,
    pub user: u64,
    pub uts: u64,
    pub ipc: u64,
    /// `None` on kernels built without `CONFIG_CGROUPS` namespace support.
    pub cgroup: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespace_info_json_round_trip() {
        let ns = NamespaceInfo {
            pid: 42,
            mnt: 1,
            net: 2,
            user: 3,
            uts: 4,
            ipc: 5,
            cgroup: Some(6),
        };
        let json = serde_json::to_string(&ns).unwrap();
        let back: NamespaceInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(ns, back);
    }
}
