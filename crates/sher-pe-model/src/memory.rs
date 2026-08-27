use serde::{Deserialize, Serialize};

/// Memory breakdown for a process, in bytes.
///
/// Sourced from `/proc/[pid]/smaps_rollup` where the kernel provides it
/// (accurate `Pss`-based anon/file/shared/private split); falls back to
/// `/proc/[pid]/statm` + `/proc/[pid]/status` (VmRSS/VmSwap) on kernels
/// without `smaps_rollup`, in which case `anonymous`/`file_backed`/`shared`/
/// `private` are `0` rather than a guess — see `is_detailed()`.
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize, Deserialize)]
pub struct MemoryBreakdown {
    pub rss: u64,
    pub vsz: u64,
    pub anonymous: u64,
    pub file_backed: u64,
    pub shared: u64,
    pub private: u64,
    pub swap: u64,
}

impl MemoryBreakdown {
    /// True when this breakdown came from `smaps_rollup` rather than the
    /// `statm` fallback. The investigation engine uses this to decide
    /// whether it can make a Pss-backed claim vs. only a coarse RSS one.
    pub fn is_detailed(&self) -> bool {
        self.anonymous != 0 || self.file_backed != 0 || self.shared != 0 || self.private != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_detailed_false_for_statm_fallback() {
        let mem = MemoryBreakdown {
            rss: 1_000_000,
            vsz: 2_000_000,
            swap: 0,
            ..Default::default()
        };
        assert!(!mem.is_detailed());
    }

    #[test]
    fn is_detailed_true_when_smaps_rollup_present() {
        let mem = MemoryBreakdown {
            rss: 1_000_000,
            anonymous: 800_000,
            file_backed: 200_000,
            ..Default::default()
        };
        assert!(mem.is_detailed());
    }

    #[test]
    fn memory_breakdown_json_round_trip() {
        let mem = MemoryBreakdown {
            rss: 1,
            vsz: 2,
            anonymous: 3,
            file_backed: 4,
            shared: 5,
            private: 6,
            swap: 7,
        };
        let json = serde_json::to_string(&mem).unwrap();
        let back: MemoryBreakdown = serde_json::from_str(&json).unwrap();
        assert_eq!(mem, back);
    }
}
