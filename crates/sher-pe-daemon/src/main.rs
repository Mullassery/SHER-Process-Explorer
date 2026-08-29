//! `sherd` — background daemon that samples the process table on a fixed
//! interval and persists it to a SQLite database (`sher-pe-history`), so
//! `sher history <pid>` can answer "what was this process doing an hour
//! ago" or "why did this process that exited last night crash" — questions
//! `sher-pe-intelligence`'s in-memory, capacity-bounded history can't
//! answer once the process asking has itself exited.
//!
//! Meant to run under systemd (see `packaging/systemd/sherd.service`), not
//! self-daemonizing (no fork/setsid) — systemd already supervises
//! long-running foreground processes, and a manual double-fork would just
//! fight it.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use clap::Parser;
use sher_pe_history::HistoryStore;
use sher_pe_intelligence::ProcessIntelligence;
use sher_pe_telemetry::linux::LinuxAdapter;

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn handle_shutdown_signal(_sig: libc::c_int) {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

#[derive(Parser)]
#[command(
    name = "sherd",
    version,
    about = "Background daemon: samples processes into persistent long-term history."
)]
struct Cli {
    /// SQLite database path. Defaults to /var/lib/sher/history.db when
    /// running as root, ~/.local/share/sher/history.db otherwise.
    #[arg(long)]
    db: Option<PathBuf>,
    /// Seconds between sampling ticks.
    #[arg(long, default_value_t = 5)]
    interval_secs: u64,
    /// Snapshots/events older than this many days are pruned periodically.
    #[arg(long, default_value_t = 7)]
    retention_days: u64,
}

fn default_db_path() -> PathBuf {
    #[cfg(unix)]
    {
        // SAFETY: geteuid() takes no arguments and cannot fail.
        let is_root = unsafe { libc::geteuid() == 0 };
        if is_root {
            return PathBuf::from("/var/lib/sher/history.db");
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".local/share/sher/history.db")
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Sleeps for up to `total`, but wakes early (in <=200ms increments) once
/// `SHUTDOWN` is set, so a systemd `stop` doesn't have to wait out a full
/// tick interval before the process actually exits.
fn sleep_interruptible(total: Duration) {
    let step = Duration::from_millis(200);
    let mut remaining = total;
    while remaining > Duration::ZERO && !SHUTDOWN.load(Ordering::SeqCst) {
        let this_step = step.min(remaining);
        std::thread::sleep(this_step);
        remaining = remaining.saturating_sub(this_step);
    }
}

fn persist_tick(
    intel: &ProcessIntelligence,
    history: &HistoryStore,
    now: i64,
) -> sher_pe_history::Result<()> {
    let tree = intel.tree();
    for snapshot in tree.nodes.values() {
        history.record_snapshot(snapshot, now)?;
    }
    for event in intel.recent_timeline_events(now) {
        history.record_event(&event)?;
    }
    Ok(())
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    if !cfg!(target_os = "linux") {
        eprintln!(
            "sherd reads /proc and only runs on Linux (this binary was built for {}).",
            std::env::consts::OS
        );
        std::process::exit(1);
    }

    let cli = Cli::parse();
    let db_path = cli.db.unwrap_or_else(default_db_path);

    #[cfg(unix)]
    unsafe {
        let handler = handle_shutdown_signal as *const () as libc::sighandler_t;
        libc::signal(libc::SIGTERM, handler);
        libc::signal(libc::SIGINT, handler);
    }

    let history = match HistoryStore::open(&db_path) {
        Ok(store) => store,
        Err(err) => {
            eprintln!(
                "sherd: failed to open history database at {}: {err}",
                db_path.display()
            );
            std::process::exit(1);
        }
    };

    let existing_rows = history.snapshot_count().unwrap_or(0);
    let oldest = history.oldest_sampled_at().ok().flatten();
    tracing::info!(
        db = %db_path.display(),
        existing_rows,
        oldest_sample = ?oldest,
        interval_secs = cli.interval_secs,
        retention_days = cli.retention_days,
        "sherd started"
    );

    let adapter = LinuxAdapter::new();
    let mut intel = ProcessIntelligence::new(Box::new(adapter));

    let interval = Duration::from_secs(cli.interval_secs.max(1));
    let retention_secs = (cli.retention_days.max(1) * 86_400) as i64;
    let prune_every_secs: i64 = 3600;
    let mut last_prune = now_unix();

    while !SHUTDOWN.load(Ordering::SeqCst) {
        let now = now_unix();
        if let Err(err) = intel.refresh_at(now) {
            tracing::warn!(%err, "refresh failed, skipping this tick");
        } else if let Err(err) = persist_tick(&intel, &history, now) {
            tracing::warn!(%err, "failed to persist this tick");
        }

        if now - last_prune >= prune_every_secs {
            match history.prune_older_than(now - retention_secs) {
                Ok(removed) if removed > 0 => {
                    tracing::info!(removed, "pruned old history rows")
                }
                Ok(_) => {}
                Err(err) => tracing::warn!(%err, "prune failed"),
            }
            last_prune = now;
        }

        sleep_interruptible(interval);
    }

    tracing::info!("sherd shutting down");
}
