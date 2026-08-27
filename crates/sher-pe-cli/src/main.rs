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
    /// Level 3 stack-sampling profile — not built yet (see `ROADMAP.md`
    /// Phase 2).
    Trace { pid: Pid },
    /// Level 4 deep tracing (eBPF/perf) — not built yet (see
    /// `ROADMAP.md` Phase 3).
    Profile { pid: Pid },
}

#[derive(Clone, Copy, ValueEnum)]
enum WhyAspect {
    Cpu,
    Memory,
    Network,
    Disk,
}

fn main() {
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

    match cli.command {
        Command::Trace { pid } => {
            eprintln!(
                "sher trace {pid}: requires Level 3 (stack-sampling profile) tracing, not yet built. See ROADMAP.md Phase 2."
            );
            std::process::exit(2);
        }
        Command::Profile { pid } => {
            eprintln!(
                "sher profile {pid}: requires Level 4 (eBPF/perf) deep tracing, not yet built. See ROADMAP.md Phase 3."
            );
            std::process::exit(2);
        }
        _ => {}
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
        Command::Trace { .. } | Command::Profile { .. } => unreachable!("handled above"),
    };
    std::process::exit(exit_code);
}
