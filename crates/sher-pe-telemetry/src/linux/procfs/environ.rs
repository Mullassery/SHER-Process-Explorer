use std::path::Path;

use sher_pe_model::{EnvVar, Pid};

use super::common::read_to_string;
use crate::Result;

/// `/proc/[pid]/environ` — NUL-separated (and NUL-terminated)
/// `KEY=VALUE` entries, the same format `cmdline` uses. Requires
/// same-uid or `CAP_SYS_PTRACE`, same as reading another user's
/// `/proc/[pid]/status`; a permission-denied read surfaces as the usual
/// typed error rather than a silently empty list, since "no environment"
/// and "not allowed to see it" are different facts.
///
/// A malformed entry with no `=` (not expected in practice, but the
/// kernel doesn't guarantee one) is kept as `(entry, "")` rather than
/// silently dropped — an unusual real value, not an error worth failing
/// the whole read over.
pub fn read_environ(root: &Path, pid: Pid) -> Result<Vec<EnvVar>> {
    let path = root.join(pid.to_string()).join("environ");
    let content = read_to_string(&path)?;
    Ok(content
        .split('\0')
        .filter(|entry| !entry.is_empty())
        .map(|entry| match entry.split_once('=') {
            Some((key, value)) => EnvVar {
                key: key.to_string(),
                value: value.to_string(),
            },
            None => EnvVar {
                key: entry.to_string(),
                value: String::new(),
            },
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
    fn read_environ_splits_nul_separated_key_value_pairs() {
        let vars = read_environ(&fixture_root(), 100).unwrap();
        assert_eq!(
            vars,
            vec![
                EnvVar {
                    key: "PATH".into(),
                    value: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin".into(),
                },
                EnvVar {
                    key: "HOME".into(),
                    value: "/root".into(),
                },
                EnvVar {
                    key: "LANG".into(),
                    value: "C.UTF-8".into(),
                },
                EnvVar {
                    key: "MALFORMED_NO_EQUALS_SIGN".into(),
                    value: "".into(),
                },
            ]
        );
    }

    #[test]
    fn read_environ_errors_on_missing_file() {
        let err = read_environ(&fixture_root(), 999_999).unwrap_err();
        assert!(matches!(err, crate::TelemetryError::Io { .. }));
    }
}
