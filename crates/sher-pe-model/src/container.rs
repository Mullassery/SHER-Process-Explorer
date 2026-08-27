use serde::{Deserialize, Serialize};

/// Which container runtime owns a process, detected from its cgroup path
/// (see `sher_pe_telemetry::linux::container`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContainerRuntime {
    Docker,
    Podman,
    Containerd,
}

/// Container metadata for a process that belongs to one, mapping
/// container ↔ host process ↔ cgroup without requiring the user to
/// understand Linux internals themselves.
///
/// `name`/`image`/`status` are `None` when the id was recognized from the
/// cgroup path but the runtime's own inspect command couldn't be run
/// (not installed, or the container already exited) — the id itself is
/// still real, useful information even without the richer metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerInfo {
    pub runtime: ContainerRuntime,
    pub id: String,
    pub name: Option<String>,
    pub image: Option<String>,
    pub status: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_info_json_round_trip() {
        let info = ContainerInfo {
            runtime: ContainerRuntime::Docker,
            id: "abc123".into(),
            name: Some("my-container".into()),
            image: Some("ubuntu:22.04".into()),
            status: Some("running".into()),
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: ContainerInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info, back);
    }
}
