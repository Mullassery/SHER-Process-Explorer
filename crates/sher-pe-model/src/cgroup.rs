use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CgroupVersion {
    V1,
    V2,
}

/// A process's cgroup membership.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CgroupInfo {
    pub version: CgroupVersion,
    pub path: String,
    /// Controllers attached to this cgroup (cpu, memory, io, ...). Always
    /// a single implicit "unified" hierarchy under v2; can be several
    /// independent hierarchies under v1, but the parser flattens them into
    /// one path/list pair — the exact per-controller path is a v1 detail
    /// the model doesn't need to expose to be useful.
    pub controllers: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_info_json_round_trip() {
        let cgroup = CgroupInfo {
            version: CgroupVersion::V2,
            path: "/user.slice/user-1000.slice".into(),
            controllers: vec!["cpu".into(), "memory".into(), "io".into()],
        };
        let json = serde_json::to_string(&cgroup).unwrap();
        let back: CgroupInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(cgroup, back);
    }
}
