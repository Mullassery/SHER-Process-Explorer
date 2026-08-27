use std::path::Path;

use sher_pe_model::{Pid, SecurityContext};

use super::common::{parse_err, read_to_string, read_to_string_optional};
use super::process::first_status_value;
use crate::Result;

/// Standard Linux capability names indexed by bit number
/// (`include/uapi/linux/capability.h`). Anything beyond this table (future
/// kernel additions, or bits set by a newer kernel than this list knows
/// about) is decoded as `CAP_UNKNOWN_<bit>` rather than silently dropped —
/// losing a set bit would be exactly the kind of "hides real data" bug
/// `CLAUDE.md`'s no-fake-stubs rule exists to prevent.
const CAPABILITY_NAMES: &[&str] = &[
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_MKNOD",
    "CAP_LEASE",
    "CAP_AUDIT_WRITE",
    "CAP_AUDIT_CONTROL",
    "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND",
    "CAP_AUDIT_READ",
    "CAP_PERFMON",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
];

fn decode_capabilities(mask: u64) -> Vec<String> {
    let mut names = Vec::new();
    for bit in 0..64u32 {
        if mask & (1u64 << bit) == 0 {
            continue;
        }
        match CAPABILITY_NAMES.get(bit as usize) {
            Some(name) => names.push((*name).to_string()),
            None => names.push(format!("CAP_UNKNOWN_{bit}")),
        }
    }
    names
}

fn hex_status_value(content: &str, key: &str, path: &Path) -> Result<u64> {
    let line = content
        .lines()
        .find(|line| line.starts_with(key))
        .ok_or_else(|| parse_err(path, format!("missing '{key}' line")))?;
    let value = line
        .trim_start_matches(key)
        .split_whitespace()
        .next()
        .ok_or_else(|| parse_err(path, format!("'{key}' line has no value")))?;
    u64::from_str_radix(value, 16).map_err(|_| parse_err(path, format!("'{key}' value is not hex")))
}

/// Best-effort LSM label from `/proc/[pid]/attr/current` (AppArmor/
/// SELinux). `None` if no LSM is active, the process has exited, or the
/// read is denied — all routine, not error conditions.
fn read_lsm_label(root: &Path, pid: Pid) -> Option<String> {
    let path = root.join(pid.to_string()).join("attr").join("current");
    let content = read_to_string_optional(&path).ok().flatten()?;
    let trimmed = content.trim().trim_end_matches('\0').trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

pub fn read_security(root: &Path, pid: Pid) -> Result<SecurityContext> {
    let path = root.join(pid.to_string()).join("status");
    let content = read_to_string(&path)?;

    let uid = first_status_value(&content, "Uid:", &path)?;
    let gid = first_status_value(&content, "Gid:", &path)?;
    let euid = nth_status_value(&content, "Uid:", 1, &path)?;
    let egid = nth_status_value(&content, "Gid:", 1, &path)?;
    let cap_eff = hex_status_value(&content, "CapEff:", &path)?;
    let cap_bnd = hex_status_value(&content, "CapBnd:", &path)?;
    let seccomp_mode = first_status_value(&content, "Seccomp:", &path)? as u8;

    Ok(SecurityContext {
        uid,
        gid,
        euid,
        egid,
        capabilities_effective: decode_capabilities(cap_eff),
        capabilities_bounding: decode_capabilities(cap_bnd),
        lsm_label: read_lsm_label(root, pid),
        seccomp_mode,
    })
}

/// Like `first_status_value`, but for the Nth (0-indexed) whitespace-
/// separated value after the key — `Uid:`/`Gid:` carry four values (real,
/// effective, saved-set, filesystem) on one line.
fn nth_status_value(content: &str, key: &str, index: usize, path: &Path) -> Result<u32> {
    let line = content
        .lines()
        .find(|line| line.starts_with(key))
        .ok_or_else(|| parse_err(path, format!("missing '{key}' line")))?;
    line.trim_start_matches(key)
        .split_whitespace()
        .nth(index)
        .ok_or_else(|| parse_err(path, format!("'{key}' line missing value at index {index}")))?
        .parse::<u32>()
        .map_err(|_| parse_err(path, format!("'{key}' value is not an integer")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/proc")
    }

    #[test]
    fn decode_capabilities_maps_known_bits() {
        // 0x400 = bit 10 = CAP_NET_BIND_SERVICE only.
        assert_eq!(
            decode_capabilities(0x400),
            vec!["CAP_NET_BIND_SERVICE".to_string()]
        );
    }

    #[test]
    fn decode_capabilities_labels_unknown_high_bits() {
        let caps = decode_capabilities(1u64 << 50);
        assert_eq!(caps, vec!["CAP_UNKNOWN_50".to_string()]);
    }

    #[test]
    fn read_security_parses_fixture_process() {
        let ctx = read_security(&fixture_root(), 100).unwrap();
        assert_eq!(ctx.uid, 1000);
        assert_eq!(ctx.gid, 1000);
        assert_eq!(
            ctx.capabilities_effective,
            vec!["CAP_NET_BIND_SERVICE".to_string()]
        );
        assert_eq!(ctx.seccomp_mode, 2);
        assert_eq!(ctx.lsm_label, Some("unconfined".to_string()));
    }

    #[test]
    fn read_security_lsm_label_none_when_attr_missing() {
        // pid 101 has no fixture attr/current file.
        let ctx = read_security(&fixture_root(), 101).unwrap();
        assert_eq!(ctx.lsm_label, None);
        assert_eq!(ctx.seccomp_mode, 0);
    }
}
