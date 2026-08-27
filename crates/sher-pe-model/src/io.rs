use serde::{Deserialize, Serialize};

/// Cumulative disk I/O accounting for a process, from `/proc/[pid]/io`'s
/// `read_bytes`/`write_bytes` fields — actual bytes the process caused to
/// be fetched from or sent to the underlying block layer (as opposed to
/// `rchar`/`wchar`, which count all read()/write() syscalls including ones
/// served entirely from cache).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DiskIoStats {
    pub read_bytes: u64,
    pub write_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disk_io_stats_json_round_trip() {
        let io = DiskIoStats {
            read_bytes: 1024,
            write_bytes: 2048,
        };
        let json = serde_json::to_string(&io).unwrap();
        let back: DiskIoStats = serde_json::from_str(&json).unwrap();
        assert_eq!(io, back);
    }
}
