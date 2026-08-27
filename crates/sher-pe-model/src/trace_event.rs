use serde::{Deserialize, Serialize};

/// One syscall entry from a live, opt-in deep trace (`Tier::DeepTrace` —
/// eBPF via `bpftrace`, see `sher_pe_telemetry::linux::bpftrace`). This is
/// the per-event counterpart to `sher-pe-model::SyscallStat`'s aggregate
/// counts: a real timeline of individual syscalls, not just a summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceEvent {
    /// Nanoseconds since the first captured event in this trace (not
    /// wall-clock/epoch time — `bpftrace`'s `nsecs` is an arbitrary
    /// monotonic reference, so only deltas within one trace are
    /// meaningful).
    pub at_ns: u64,
    pub syscall: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_event_json_round_trip() {
        let event = TraceEvent {
            at_ns: 12345,
            syscall: "openat".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: TraceEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }
}
