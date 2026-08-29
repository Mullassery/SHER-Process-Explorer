//! `sher` — the CLI for SHER Process Explorer. The only consumer of
//! `sher-pe-intelligence`/`sher-pe-investigation` this pass; a future GUI
//! calls the exact same APIs, never a separate code path.

mod render;

use clap::{Parser, Subcommand, ValueEnum};
use sher_pe_intelligence::ProcessIntelligence;
use sher_pe_model::{Pid, Signal};
use sher_pe_telemetry::linux::LinuxAdapter;

#[derive(Parser)]
#[command(
    name = "sher",
    version,
    about = "Understand what a Linux process is doing, and why."
)]
struct Cli {
    /// Emit machine-readable JSON instead of formatted text.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// System-wide totals: memory, swap, load average, uptime, kernel
    /// version, process count.
    System,
    /// List every process, flat.
    Ps,
    /// Show the process hierarchy, optionally rooted at one pid.
    Tree { pid: Option<Pid> },
    /// Show full detail for one process: overview, memory, CPU, threads,
    /// files, network, security.
    Inspect { pid: Pid },
    /// Ask "why" about one aspect of a process.
    Why {
        pid: Pid,
        #[arg(value_enum)]
        aspect: WhyAspect,
    },
    /// Run every "why" rule against one process.
    Investigate { pid: Pid },
    /// Chronological view of a process's life: recorded lifecycle events
    /// (started/exited/memory-growth/etc.) merged with real journald
    /// entries for its systemd unit, plus a best-effort kernel-log
    /// correlation section.
    Timeline {
        pid: Pid,
        /// Max journal entries to fetch (most recent).
        #[arg(long, default_value_t = 200)]
        journal_lines: usize,
    },
    /// Syscall-count breakdown via `strace -c` (`Tier::ShortSample`).
    /// Requires `strace` and `timeout` installed, and ptrace permission
    /// for this pid (same-uid or `CAP_SYS_PTRACE`).
    Trace {
        pid: Pid,
        /// How long to sample for.
        #[arg(long, default_value_t = 3)]
        duration_secs: u64,
    },
    /// Stack-sampling hot-function profile via `perf` (`Tier::Profile`).
    /// Requires `perf` installed and enough privilege
    /// (`CAP_PERFMON`/`perf_event_paranoid`).
    Profile {
        pid: Pid,
        /// How long to sample for.
        #[arg(long, default_value_t = 3)]
        duration_secs: u64,
    },
    /// Live, per-event syscall trace via real eBPF (`bpftrace`,
    /// `Tier::DeepTrace`). Requires `bpftrace`, `timeout`, and `tracefs`
    /// mounted (standard on real Linux desktops) plus enough privilege
    /// (`CAP_BPF`/`CAP_SYS_ADMIN`).
    ///
    /// This is meaningfully more invasive than `trace`: it captures every
    /// individual syscall, not a count summary, and a busy process can
    /// generate hundreds of thousands of events per second. It can also
    /// run noticeably longer than --duration-secs before returning —
    /// tearing down ~300 eBPF probes takes real kernel-side time that no
    /// signal can shorten. Requires explicit opt-in.
    DeepTrace {
        pid: Pid,
        /// How long to sample for.
        #[arg(long, default_value_t = 3)]
        duration_secs: u64,
        /// Required: confirms you understand this can be highly invasive
        /// under a busy process (potentially hundreds of thousands of
        /// events per second) and needs elevated privilege.
        #[arg(long)]
        i_accept_the_overhead: bool,
    },
    /// Export a full diagnostic report for one process (process detail,
    /// threads, files, network, security, container, timeline, journal,
    /// kernel-log correlation, and every "why" finding) as one JSON
    /// document. Writes to stdout unless `--output` is given.
    Export {
        pid: Pid,
        #[arg(long)]
        output: Option<std::path::PathBuf>,
    },
    /// Send a POSIX signal to a process (default: SIGTERM). Prompts for
    /// interactive confirmation unless `--yes` is passed — this sends a
    /// real signal to a real process, not a simulation.
    Kill {
        pid: Pid,
        #[arg(value_enum, long, default_value = "term")]
        signal: SignalArg,
        /// Skip the interactive confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
    /// Long-term history for a process, persisted by `sherd` (the
    /// background daemon) — unlike `timeline`, this works for a process
    /// that has since exited, and reaches back further than
    /// `ProcessIntelligence`'s in-memory, capacity-bounded history.
    /// Requires `sherd` to have been running and sampling.
    History {
        pid: Pid,
        /// Only show snapshots/events from the last N seconds.
        #[arg(long, default_value_t = 86_400)]
        since_secs: i64,
        /// SQLite database path. Defaults to the same path `sherd` uses:
        /// /var/lib/sher/history.db when run as root,
        /// ~/.local/share/sher/history.db otherwise.
        #[arg(long)]
        db: Option<std::path::PathBuf>,
    },
    /// Reverse lookup: which process has a given file open, or a given
    /// port bound — investigation often starts from a symptom (a stuck
    /// port, a locked file), not a pid.
    WhoHas {
        /// A substring to match against every live process's open file
        /// paths (e.g. a filename or directory) — mutually exclusive
        /// with `--port`.
        path: Option<String>,
        /// A port number to match against every live process's local
        /// connection addresses — mutually exclusive with `path`.
        #[arg(long)]
        port: Option<u16>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum WhyAspect {
    Cpu,
    Memory,
    Network,
    Disk,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum SignalArg {
    Term,
    Kill,
    Hup,
    Int,
    Quit,
    Usr1,
    Usr2,
    Stop,
    Cont,
}

impl From<SignalArg> for Signal {
    fn from(arg: SignalArg) -> Signal {
        match arg {
            SignalArg::Term => Signal::Term,
            SignalArg::Kill => Signal::Kill,
            SignalArg::Hup => Signal::Hup,
            SignalArg::Int => Signal::Int,
            SignalArg::Quit => Signal::Quit,
            SignalArg::Usr1 => Signal::Usr1,
            SignalArg::Usr2 => Signal::Usr2,
            SignalArg::Stop => Signal::Stop,
            SignalArg::Cont => Signal::Cont,
        }
    }
}

/// Rust's runtime ignores `SIGPIPE` by default, which turns a closed
/// downstream pipe (e.g. `sher ps | head`) into a normal `io::Error` that
/// `println!` then panics on instead of the process just quietly exiting
/// the way `grep`/`cat`/every other Unix tool does. Restoring the default
/// disposition is the standard fix (the same one ripgrep uses).
#[cfg(unix)]
fn reset_sigpipe() {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}

#[cfg(not(unix))]
fn reset_sigpipe() {}

/// Same default as `sherd` (see `sher-pe-daemon/src/main.rs`) — `sher
/// history` with no `--db` needs to find the same database `sherd` writes
/// to by default.
fn default_history_db_path() -> std::path::PathBuf {
    #[cfg(unix)]
    {
        // SAFETY: geteuid() takes no arguments and cannot fail.
        let is_root = unsafe { libc::geteuid() == 0 };
        if is_root {
            return std::path::PathBuf::from("/var/lib/sher/history.db");
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    std::path::PathBuf::from(home).join(".local/share/sher/history.db")
}

fn main() {
    reset_sigpipe();

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Parsed first so `--help`/`--version` work on every OS — clap exits
    // the process itself for those before returning here.
    let cli = Cli::parse();

    if !cfg!(target_os = "linux") {
        eprintln!(
            "sher reads /proc and only runs on Linux (this binary was built for {}). \
             See README.md — the parser layer is unit-tested on macOS, but there is no \
             real /proc to read outside Linux.",
            std::env::consts::OS
        );
        std::process::exit(1);
    }

    if let Command::DeepTrace {
        pid,
        i_accept_the_overhead: false,
        ..
    } = cli.command
    {
        eprintln!(
            "sher deep-trace {pid}: refusing to run without --i-accept-the-overhead.\n\n\
             This attaches real eBPF probes to every syscall the process makes. Under a busy \
             process this can generate hundreds of thousands of events per second and needs \
             CAP_BPF/CAP_SYS_ADMIN plus tracefs mounted. It can also take noticeably longer than \
             --duration-secs to return — tearing down ~300 probes takes real kernel-side time \
             no signal can shorten (observed ~10-15s beyond the requested duration). Pass \
             --i-accept-the-overhead to confirm you understand this before it runs."
        );
        std::process::exit(2);
    }

    let adapter = LinuxAdapter::new();
    let mut intel = ProcessIntelligence::new(Box::new(adapter));
    if let Err(err) = intel.refresh() {
        eprintln!("sher: failed to read process table: {err}");
        std::process::exit(1);
    }

    let exit_code = match cli.command {
        Command::System => render::system(&intel, cli.json),
        Command::Ps => render::ps(&intel, cli.json),
        Command::Tree { pid } => render::tree(&intel, pid, cli.json),
        Command::Inspect { pid } => render::inspect(&intel, pid, cli.json),
        Command::Why { pid, aspect } => render::why(&intel, pid, aspect, cli.json),
        Command::Investigate { pid } => render::investigate(&intel, pid, cli.json),
        Command::Timeline { pid, journal_lines } => {
            render::timeline(&intel, pid, journal_lines, cli.json)
        }
        Command::Trace { pid, duration_secs } => {
            render::trace(&intel, pid, duration_secs, cli.json)
        }
        Command::Profile { pid, duration_secs } => {
            render::profile(&intel, pid, duration_secs, cli.json)
        }
        Command::DeepTrace {
            pid, duration_secs, ..
        } => render::deep_trace(&intel, pid, duration_secs, cli.json),
        Command::Kill { pid, signal, yes } => {
            render::kill(&intel, pid, signal.into(), yes, cli.json)
        }
        Command::Export { pid, output } => render::export(&intel, pid, output.as_deref()),
        Command::History {
            pid,
            since_secs,
            db,
        } => {
            let db_path = db.unwrap_or_else(default_history_db_path);
            render::history(pid, since_secs, &db_path, cli.json)
        }
        Command::WhoHas { path, port } => render::who_has(&intel, path, port, cli.json),
    };
    std::process::exit(exit_code);
}
