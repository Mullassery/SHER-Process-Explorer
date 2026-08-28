use serde::{Deserialize, Serialize};

/// POSIX signals `sher` can send to a process. Deliberately a small,
/// closed set — the common process-control signals, not every signal
/// number the kernel defines — since anything wider than this would need
/// per-signal justification in the UI/CLI anyway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Signal {
    /// Polite request to terminate; the process can catch/ignore it.
    Term,
    /// Immediate, unblockable termination by the kernel.
    Kill,
    /// Hangup — traditionally "reload config" for daemons.
    Hup,
    /// Interrupt (what Ctrl-C sends).
    Int,
    /// Quit with a core dump.
    Quit,
    Usr1,
    Usr2,
    /// Suspend the process (can be resumed with `Cont`).
    Stop,
    /// Resume a `Stop`-ped process.
    Cont,
}

impl Signal {
    /// Whether this signal can be caught, blocked, or ignored by the
    /// target process. Only `Kill` and `Stop` cannot — used to decide
    /// whether a confirmation prompt should call out "this cannot be
    /// undone or refused by the process."
    pub fn is_uncatchable(self) -> bool {
        matches!(self, Signal::Kill | Signal::Stop)
    }

    pub fn name(self) -> &'static str {
        match self {
            Signal::Term => "SIGTERM",
            Signal::Kill => "SIGKILL",
            Signal::Hup => "SIGHUP",
            Signal::Int => "SIGINT",
            Signal::Quit => "SIGQUIT",
            Signal::Usr1 => "SIGUSR1",
            Signal::Usr2 => "SIGUSR2",
            Signal::Stop => "SIGSTOP",
            Signal::Cont => "SIGCONT",
        }
    }
}

impl std::fmt::Display for Signal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kill_and_stop_are_uncatchable_others_are_not() {
        assert!(Signal::Kill.is_uncatchable());
        assert!(Signal::Stop.is_uncatchable());
        assert!(!Signal::Term.is_uncatchable());
        assert!(!Signal::Hup.is_uncatchable());
    }

    #[test]
    fn name_matches_posix_signal_names() {
        assert_eq!(Signal::Term.name(), "SIGTERM");
        assert_eq!(Signal::Kill.name(), "SIGKILL");
        assert_eq!(Signal::Cont.name(), "SIGCONT");
    }
}
