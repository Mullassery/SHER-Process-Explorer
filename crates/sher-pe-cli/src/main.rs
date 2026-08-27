//! `sher` — the CLI for SHER Process Explorer. The only consumer of
//! `sher-pe-intelligence`/`sher-pe-investigation` this pass; a future GUI
//! calls the exact same APIs, never a separate code path.

mod render;

use clap::{Parser, Subcommand, ValueEnum};
use sher_pe_intelligence::ProcessIntelligence;
use sher_pe_model::Pid;
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
    /// generate hundreds of thousands of events per second. Requires
    /// explicit opt-in.
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
}

#[derive(Clone, Copy, ValueEnum)]
enum WhyAspect {
    Cpu,
    Memory,
    Network,
    Disk,
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
             CAP_BPF/CAP_SYS_ADMIN plus tracefs mounted. Pass --i-accept-the-overhead to confirm \
             you understand this before it runs."
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
        Command::Ps => render::ps(&intel, cli.json),
        Command::Tree { pid } => render::tree(&intel, pid, cli.json),
        Command::Inspect { pid } => render::inspect(&intel, pid, cli.json),
        Command::Why { pid, aspect } => render::why(&intel, pid, aspect, cli.json),
        Command::Investigate { pid } => render::investigate(&intel, pid, cli.json),
        Command::Trace { pid, duration_secs } => {
            render::trace(&intel, pid, duration_secs, cli.json)
        }
        Command::Profile { pid, duration_secs } => {
            render::profile(&intel, pid, duration_secs, cli.json)
        }
        Command::DeepTrace {
            pid, duration_secs, ..
        } => render::deep_trace(&intel, pid, duration_secs, cli.json),
    };
    std::process::exit(exit_code);
}
