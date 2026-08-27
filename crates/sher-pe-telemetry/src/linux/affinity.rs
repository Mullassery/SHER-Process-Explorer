//! `sched_getaffinity` — the one piece of telemetry that is a real syscall
//! rather than a `/proc` read, so it can't be fixture-tested on macOS. Gated
//! to compile only on Linux; every other OS gets a typed `Unsupported`.

use sher_pe_model::Pid;

use crate::{Result, TelemetryError};

#[cfg(target_os = "linux")]
pub fn read_affinity(pid: Pid) -> Result<Vec<u32>> {
    use nix::sched::{sched_getaffinity, CpuSet};
    use nix::unistd::Pid as NixPid;

    let set = sched_getaffinity(NixPid::from_raw(pid)).map_err(|errno| TelemetryError::Io {
        path: format!("sched_getaffinity({pid})"),
        source: std::io::Error::from_raw_os_error(errno as i32),
    })?;

    let mut cpus = Vec::new();
    for cpu in 0..CpuSet::count() {
        if set.is_set(cpu).unwrap_or(false) {
            cpus.push(cpu as u32);
        }
    }
    Ok(cpus)
}

#[cfg(not(target_os = "linux"))]
pub fn read_affinity(_pid: Pid) -> Result<Vec<u32>> {
    Err(TelemetryError::UnsupportedPlatform(
        "sched_getaffinity is only available on Linux".into(),
    ))
}
