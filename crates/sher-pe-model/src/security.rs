use serde::{Deserialize, Serialize};

/// Security-relevant identity and privilege state for a process, from
/// `/proc/[pid]/status`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityContext {
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    /// Effective capability set (`CapEff`), as the individual capability
    /// names it decodes to (e.g. `CAP_NET_ADMIN`) rather than the raw
    /// bitmask — the raw hex is kept in `Evidence::raw` when this feeds an
    /// investigation `Finding`, not duplicated here.
    pub capabilities_effective: Vec<String>,
    /// Bounding capability set (`CapBnd`), decoded the same way.
    pub capabilities_bounding: Vec<String>,
    /// Best-effort LSM label (AppArmor/SELinux), `None` if no LSM is
    /// active or the label couldn't be read.
    pub lsm_label: Option<String>,
    /// `/proc/[pid]/status`'s `Seccomp` field: 0 = disabled, 1 = strict,
    /// 2 = filter. Kept as the raw mode rather than a bool so "filter vs.
    /// strict" isn't lost.
    pub seccomp_mode: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_context_json_round_trip() {
        let ctx = SecurityContext {
            uid: 1000,
            gid: 1000,
            euid: 1000,
            egid: 1000,
            capabilities_effective: vec!["CAP_NET_BIND_SERVICE".into()],
            capabilities_bounding: vec!["CAP_NET_BIND_SERVICE".into(), "CAP_SYS_ADMIN".into()],
            lsm_label: Some("unconfined".into()),
            seccomp_mode: 2,
        };
        let json = serde_json::to_string(&ctx).unwrap();
        let back: SecurityContext = serde_json::from_str(&json).unwrap();
        assert_eq!(ctx, back);
    }
}
