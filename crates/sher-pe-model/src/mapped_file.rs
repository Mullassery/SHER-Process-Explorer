use serde::{Deserialize, Serialize};

/// One real file (a shared library, the executable itself, a
/// memory-mapped data file) `/proc/[pid]/maps` shows loaded into a
/// process's address space. Anonymous mappings (`[heap]`, `[stack]`,
/// `[vdso]`, and unnamed segments) are deliberately excluded — this
/// answers "what libraries/files does this process depend on," not
/// "show me the whole address space."
///
/// A real file is typically mapped across several segments (one per
/// permission combination: read-only data, executable code, ...); those
/// are collapsed into one entry with `size_bytes` summed across all of
/// them, since "how much of this library is mapped" is the useful
/// question, not the individual segment boundaries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MappedFile {
    pub path: String,
    pub size_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapped_file_json_round_trip() {
        let file = MappedFile {
            path: "/usr/lib/x86_64-linux-gnu/libc.so.6".into(),
            size_bytes: 2_000_000,
        };
        let json = serde_json::to_string(&file).unwrap();
        let back: MappedFile = serde_json::from_str(&json).unwrap();
        assert_eq!(file, back);
    }
}
