use serde::{Deserialize, Serialize};

/// File-descriptor limits for a process (`/proc/[pid]/limits`'s "Max open
/// files" row, i.e. `RLIMIT_NOFILE`). `None` means unlimited (the
/// kernel's own `RLIM_INFINITY`, printed literally as `"unlimited"` in
/// that file) — not a missing or unread value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FdLimits {
    pub soft: Option<u64>,
    pub hard: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fd_limits_json_round_trip() {
        let limits = FdLimits {
            soft: Some(1024),
            hard: None,
        };
        let json = serde_json::to_string(&limits).unwrap();
        let back: FdLimits = serde_json::from_str(&json).unwrap();
        assert_eq!(limits, back);
    }
}
