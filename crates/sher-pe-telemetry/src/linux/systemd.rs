//! systemd unit mapping. Deliberately shells out to `systemctl`/
//! `journalctl` rather than talking to dbus directly — `zbus` is a
//! reasonable future upgrade, but shelling out is the right MVP-sized
//! choice for how rarely these are called (once per `investigate`/`why`
//! call, not in the hot `refresh()` loop).

use std::process::Command;

use crate::{Result, TelemetryError};

/// Maps a cgroup path (as read from `/proc/[pid]/cgroup`) to the systemd
/// unit that owns it, e.g. `/system.slice/sshd.service` -> `sshd.service`.
/// Pure string logic — no filesystem or process access — so it's testable
/// without a real systemd.
pub fn unit_from_cgroup_path(cgroup_path: &str) -> Option<String> {
    cgroup_path
        .split('/')
        .rev()
        .find(|segment| segment.ends_with(".service") || segment.ends_with(".scope"))
        .map(str::to_string)
}

/// Shells out to `systemctl show <unit>`, returning its raw stdout. A
/// non-systemd host, or a unit that doesn't exist, surfaces as a typed
/// `Io` error from the command's own failure — not a fabricated empty
/// summary.
pub fn systemctl_show(unit: &str) -> Result<String> {
    run_command("systemctl", &["show", unit])
}

/// Shells out to `journalctl -u <unit> -n <lines> --no-pager`.
pub fn journalctl_unit_logs(unit: &str, lines: usize) -> Result<String> {
    run_command(
        "journalctl",
        &["-u", unit, "-n", &lines.to_string(), "--no-pager"],
    )
}

fn run_command(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|source| TelemetryError::Io {
            path: program.to_string(),
            source,
        })?;
    if !output.status.success() {
        return Err(TelemetryError::Io {
            path: program.to_string(),
            source: std::io::Error::other(format!(
                "{program} exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_from_cgroup_path_finds_trailing_service() {
        assert_eq!(
            unit_from_cgroup_path("/system.slice/sshd.service"),
            Some("sshd.service".to_string())
        );
    }

    #[test]
    fn unit_from_cgroup_path_finds_deeply_nested_scope() {
        assert_eq!(
            unit_from_cgroup_path(
                "/user.slice/user-1000.slice/user@1000.service/app.slice/app-foo.slice/foo.scope"
            ),
            Some("foo.scope".to_string())
        );
    }

    #[test]
    fn unit_from_cgroup_path_none_when_no_unit_segment() {
        assert_eq!(unit_from_cgroup_path("/user.slice/user-1000.slice"), None);
    }
}
