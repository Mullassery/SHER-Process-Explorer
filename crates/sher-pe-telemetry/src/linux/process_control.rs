//! `kill(2)` — the one write/control operation this crate performs, as
//! opposed to everything else here which only reads telemetry. Kept in its
//! own module rather than folded into `procfs` since it isn't a `/proc`
//! parser and can't be fixture-tested the way those are; gated to Linux
//! like `affinity.rs`, with a typed `UnsupportedPlatform` elsewhere.

use sher_pe_model::{Pid, Signal};

use crate::{Result, TelemetryError};

#[cfg(target_os = "linux")]
fn to_nix_signal(signal: Signal) -> nix::sys::signal::Signal {
    use nix::sys::signal::Signal as NixSignal;
    match signal {
        Signal::Term => NixSignal::SIGTERM,
        Signal::Kill => NixSignal::SIGKILL,
        Signal::Hup => NixSignal::SIGHUP,
        Signal::Int => NixSignal::SIGINT,
        Signal::Quit => NixSignal::SIGQUIT,
        Signal::Usr1 => NixSignal::SIGUSR1,
        Signal::Usr2 => NixSignal::SIGUSR2,
        Signal::Stop => NixSignal::SIGSTOP,
        Signal::Cont => NixSignal::SIGCONT,
    }
}

#[cfg(target_os = "linux")]
pub fn send_signal(pid: Pid, signal: Signal) -> Result<()> {
    use nix::errno::Errno;
    use nix::sys::signal::kill;
    use nix::unistd::Pid as NixPid;

    kill(NixPid::from_raw(pid), to_nix_signal(signal)).map_err(|errno| match errno {
        Errno::ESRCH => TelemetryError::NotFound(pid),
        Errno::EPERM => {
            TelemetryError::PermissionDenied(format!("not permitted to signal pid {pid}"))
        }
        other => TelemetryError::Io {
            path: format!("kill({pid}, {signal})"),
            source: std::io::Error::from_raw_os_error(other as i32),
        },
    })
}

#[cfg(not(target_os = "linux"))]
pub fn send_signal(_pid: Pid, _signal: Signal) -> Result<()> {
    Err(TelemetryError::UnsupportedPlatform(
        "sending signals is only available on Linux".into(),
    ))
}
