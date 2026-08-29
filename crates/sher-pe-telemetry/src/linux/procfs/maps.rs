use std::collections::HashMap;
use std::path::Path;

use sher_pe_model::{MappedFile, Pid};

use super::common::{parse_err, read_to_string};
use crate::Result;

/// `/proc/[pid]/maps` — real mapped files only (shared libraries, the
/// executable itself, mapped data files), collapsed to one entry per
/// path with sizes summed across every segment. Anonymous mappings
/// (`[heap]`, `[stack]`, `[vdso]`, `[vvar]`, and unnamed segments) are
/// excluded, since this answers "what does this process depend on," not
/// "show me the whole address space" — see `MappedFile`'s doc comment.
///
/// Order is by first appearance in the file (which the kernel emits in
/// address order), not alphabetical, so the executable itself typically
/// sorts first, matching how a reader would expect to scan it.
pub fn read_mapped_files(root: &Path, pid: Pid) -> Result<Vec<MappedFile>> {
    let path = root.join(pid.to_string()).join("maps");
    let content = read_to_string(&path)?;

    let mut order: Vec<String> = Vec::new();
    let mut sizes: HashMap<String, u64> = HashMap::new();

    for line in content.lines() {
        // Skip perms/offset/dev/inode - only the range (field 1) and the
        // trailing pathname (field 6, if present) matter here.
        let rest: Vec<&str> = line.split_whitespace().collect();
        let Some(range) = rest.first() else {
            continue; // blank line
        };
        let Some(candidate) = rest.get(5) else {
            continue; // no pathname field at all - anonymous mapping
        };
        if !candidate.starts_with('/') {
            continue; // "[heap]", "[stack]", "[vdso]", "[vvar]", ...
        }
        // A path containing spaces would break the simple split above,
        // but /proc/[pid]/maps doesn't quote them - rejoin anything past
        // field 5 to be safe rather than silently truncating such a path.
        let path_field = rest[5..].join(" ");

        let (start, end) = range
            .split_once('-')
            .ok_or_else(|| parse_err(&path, format!("malformed address range '{range}'")))?;
        let start = u64::from_str_radix(start, 16)
            .map_err(|_| parse_err(&path, format!("bad range start '{start}'")))?;
        let end = u64::from_str_radix(end, 16)
            .map_err(|_| parse_err(&path, format!("bad range end '{end}'")))?;
        let size = end.saturating_sub(start);

        if !sizes.contains_key(&path_field) {
            order.push(path_field.clone());
        }
        *sizes.entry(path_field).or_insert(0) += size;
    }

    Ok(order
        .into_iter()
        .map(|path_field| {
            let size_bytes = sizes[&path_field];
            MappedFile {
                path: path_field,
                size_bytes,
            }
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc")
    }

    #[test]
    fn read_mapped_files_collapses_segments_and_excludes_anonymous() {
        let files = read_mapped_files(&fixture_root(), 100).unwrap();
        assert_eq!(files.len(), 2);

        assert_eq!(files[0].path, "/usr/bin/sherd");
        assert_eq!(files[0].size_bytes, 65_536);

        assert_eq!(files[1].path, "/usr/lib/x86_64-linux-gnu/libc.so.6");
        assert_eq!(files[1].size_bytes, 1_736_704);

        assert!(!files.iter().any(|f| f.path.contains('[')));
    }

    #[test]
    fn read_mapped_files_errors_on_missing_file() {
        let err = read_mapped_files(&fixture_root(), 999_999).unwrap_err();
        assert!(matches!(err, crate::TelemetryError::Io { .. }));
    }
}
