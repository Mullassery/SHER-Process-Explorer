use serde::{Deserialize, Serialize};

/// Classification of a `/proc/[pid]/fd/*` entry, derived from what its
/// symlink target looks like.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileKind {
    Regular,
    Directory,
    Socket,
    Pipe,
    CharDevice,
    BlockDevice,
    Unknown,
}

/// One open file descriptor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OpenFile {
    pub fd: i32,
    /// The resolved symlink target, e.g. `/var/log/sherd.log`,
    /// `socket:[12345]`, or `pipe:[6789]`.
    pub path: String,
    pub kind: FileKind,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_file_json_round_trip() {
        let file = OpenFile {
            fd: 3,
            path: "/var/log/sherd.log".into(),
            kind: FileKind::Regular,
        };
        let json = serde_json::to_string(&file).unwrap();
        let back: OpenFile = serde_json::from_str(&json).unwrap();
        assert_eq!(file, back);
    }
}
