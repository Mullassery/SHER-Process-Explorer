use serde::{Deserialize, Serialize};

/// One entry from a stack-sampling profile: a symbol and the fraction of
/// samples that landed in it, as reported by `perf report`. Level 2/3
/// (opt-in, short-duration) data — see `sher-pe-telemetry::linux::perf`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HotFunction {
    pub symbol: String,
    /// The binary or shared object the symbol resolved in (e.g. the main
    /// executable, or `libc.so.6`), as `perf report` prints it — kept
    /// separate from `symbol` since the same symbol name can appear in
    /// more than one module.
    pub module: String,
    pub overhead_percent: f64,
}

/// One row of a syscall-count summary, as reported by `strace -c`. Level 2
/// (opt-in, short-duration) data — see `sher-pe-telemetry::linux::strace`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyscallStat {
    pub name: String,
    pub calls: u64,
    pub errors: u64,
    pub time_percent: f64,
    pub seconds: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hot_function_json_round_trip() {
        let hot = HotFunction {
            symbol: "malloc".into(),
            module: "libc.so.6".into(),
            overhead_percent: 12.5,
        };
        let json = serde_json::to_string(&hot).unwrap();
        let back: HotFunction = serde_json::from_str(&json).unwrap();
        assert_eq!(hot, back);
    }

    #[test]
    fn syscall_stat_json_round_trip() {
        let stat = SyscallStat {
            name: "read".into(),
            calls: 100,
            errors: 2,
            time_percent: 15.3,
            seconds: 0.002,
        };
        let json = serde_json::to_string(&stat).unwrap();
        let back: SyscallStat = serde_json::from_str(&json).unwrap();
        assert_eq!(stat, back);
    }
}
