use std::path::Path;

use sher_pe_model::{FileKind, OpenFile, Pid};

use super::common::list_numeric_entries;
use crate::Result;

/// Lists and classifies every entry in `/proc/[pid]/fd/`.
///
/// A single unreadable descriptor (raced-with-close between listing and
/// reading, which is routine under `/proc`) is skipped rather than failing
/// the whole listing — a transient miss on one fd shouldn't hide every
/// other fd this process has open.
pub fn list_open_files(root: &Path, pid: Pid) -> Result<Vec<OpenFile>> {
    let fd_dir = root.join(pid.to_string()).join("fd");
    let fds = list_numeric_entries(&fd_dir)?;
    let mut files = Vec::with_capacity(fds.len());
    for fd in fds {
        let path = fd_dir.join(fd.to_string());
        let Ok(target) = std::fs::read_link(&path) else {
            tracing::debug!(pid, fd, "fd closed between listing and read, skipping");
            continue;
        };
        let target = target.to_string_lossy().into_owned();
        let kind = classify(&path, &target);
        files.push(OpenFile {
            fd,
            path: target,
            kind,
        });
    }
    Ok(files)
}

fn classify(fd_path: &Path, target: &str) -> FileKind {
    if target.starts_with("socket:[") {
        return FileKind::Socket;
    }
    if target.starts_with("pipe:[") {
        return FileKind::Pipe;
    }
    // Anything else is classified by resolving the symlink through
    // `/proc/[pid]/fd/N` itself (not `target`, which may be a bare
    // `anon_inode:[...]` string with no real path on disk).
    match std::fs::metadata(fd_path) {
        Ok(meta) => {
            use std::os::unix::fs::FileTypeExt;
            let file_type = meta.file_type();
            if file_type.is_dir() {
                FileKind::Directory
            } else if file_type.is_char_device() {
                FileKind::CharDevice
            } else if file_type.is_block_device() {
                FileKind::BlockDevice
            } else if file_type.is_file() {
                FileKind::Regular
            } else {
                FileKind::Unknown
            }
        }
        Err(_) => FileKind::Unknown,
    }
}

/// Extracts the inode from a `"socket:[12345]"`-style fd target, for
/// cross-referencing against `/proc/[pid]/net/*`'s inode column.
pub fn socket_inode(target: &str) -> Option<u64> {
    let inner = target.strip_prefix("socket:[")?.strip_suffix(']')?;
    inner.parse().ok()
}

/// Every socket inode this process currently holds open, resolved from its
/// `fd/*` entries.
pub fn socket_inodes(root: &Path, pid: Pid) -> Result<std::collections::HashSet<u64>> {
    let fd_dir = root.join(pid.to_string()).join("fd");
    let fds = list_numeric_entries(&fd_dir)?;
    let mut inodes = std::collections::HashSet::new();
    for fd in fds {
        let path = fd_dir.join(fd.to_string());
        let Ok(target) = std::fs::read_link(&path) else {
            continue;
        };
        if let Some(inode) = socket_inode(&target.to_string_lossy()) {
            inodes.insert(inode);
        }
    }
    Ok(inodes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc")
    }

    #[test]
    fn list_open_files_classifies_socket_and_pipe() {
        let files = list_open_files(&fixture_root(), 100).unwrap();
        let by_fd = |fd: i32| files.iter().find(|f| f.fd == fd).unwrap();

        assert_eq!(by_fd(3).kind, FileKind::Socket);
        assert_eq!(by_fd(3).path, "socket:[999]");
        assert_eq!(by_fd(4).kind, FileKind::Pipe);
        assert_eq!(by_fd(4).path, "pipe:[888]");
    }

    #[test]
    fn list_open_files_classifies_char_device() {
        // fd 0/1 point at /dev/null, a real char device on macOS and Linux.
        let files = list_open_files(&fixture_root(), 100).unwrap();
        let stdin = files.iter().find(|f| f.fd == 0).unwrap();
        assert_eq!(stdin.kind, FileKind::CharDevice);
    }

    #[test]
    fn socket_inode_parses_bracketed_inode() {
        assert_eq!(socket_inode("socket:[999]"), Some(999));
        assert_eq!(socket_inode("pipe:[888]"), None);
        assert_eq!(socket_inode("/var/log/sherd.log"), None);
    }

    #[test]
    fn socket_inodes_collects_all_sockets_for_pid() {
        let inodes = socket_inodes(&fixture_root(), 100).unwrap();
        assert!(inodes.contains(&999));
        assert!(inodes.contains(&1500));
        assert!(inodes.contains(&3000));
        assert_eq!(inodes.len(), 3);
    }
}
