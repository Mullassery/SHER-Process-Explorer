//! Human-readable + `--json` rendering for every `sher` subcommand. Each
//! function returns the process exit code the caller should use.

use std::time::Duration;

use sher_pe_intelligence::ProcessIntelligence;
use sher_pe_model::{Finding, Pid, ProcessSnapshot};

use crate::WhyAspect;

fn print_json_or<T: serde::Serialize>(json: bool, value: &T, human: impl FnOnce()) {
    if json {
        match serde_json::to_string_pretty(value) {
            Ok(text) => println!("{text}"),
            Err(err) => eprintln!("sher: failed to serialize output: {err}"),
        }
    } else {
        human();
    }
}

fn not_found_error(pid: Pid) -> i32 {
    eprintln!("sher: no process with pid {pid} (it may have exited)");
    1
}

pub fn system(intel: &ProcessIntelligence, json: bool) -> i32 {
    let overview = match intel.system_overview() {
        Ok(overview) => overview,
        Err(err) => {
            eprintln!("sher: failed to read system overview: {err}");
            return 1;
        }
    };

    print_json_or(json, &overview, || {
        let mem = &overview.memory;
        let uptime_secs = overview.uptime_secs as u64;
        println!(
            "uptime:   {}d {}h {}m",
            uptime_secs / 86400,
            (uptime_secs % 86400) / 3600,
            (uptime_secs % 3600) / 60
        );
        println!("kernel:   {}", overview.kernel_version);
        println!("processes: {}", overview.process_count);
        println!(
            "load avg: {:.2} {:.2} {:.2} (1m 5m 15m)",
            overview.load_average.one_min,
            overview.load_average.five_min,
            overview.load_average.fifteen_min
        );
        println!(
            "memory:   {} / {} KB used ({:.1}%), {} KB available, {} KB buffers, {} KB cached",
            mem.used() / 1024,
            mem.total / 1024,
            if mem.total > 0 {
                mem.used() as f64 / mem.total as f64 * 100.0
            } else {
                0.0
            },
            mem.available / 1024,
            mem.buffers / 1024,
            mem.cached / 1024
        );
        if mem.swap_total > 0 {
            println!(
                "swap:     {} / {} KB used",
                mem.swap_used() / 1024,
                mem.swap_total / 1024
            );
        } else {
            println!("swap:     (none configured)");
        }
    });
    0
}

pub fn ps(intel: &ProcessIntelligence, json: bool) -> i32 {
    let tree = intel.tree();
    let mut processes: Vec<&ProcessSnapshot> = tree.nodes.values().collect();
    processes.sort_by_key(|p| p.pid);

    print_json_or(json, &processes, || {
        println!(
            "{:>8} {:>8} {:>6} {:>10} {:<8} NAME",
            "PID", "PPID", "CPU%", "RSS(KB)", "STATE"
        );
        for p in &processes {
            println!(
                "{:>8} {:>8} {:>6.1} {:>10} {:<8} {}",
                p.pid,
                p.ppid,
                p.cpu.percent,
                p.memory.rss / 1024,
                format!("{:?}", p.state),
                p.name
            );
        }
    });
    0
}

pub fn tree(intel: &ProcessIntelligence, pid: Option<Pid>, json: bool) -> i32 {
    let process_tree = intel.tree();

    if json {
        print_json_or(json, &process_tree, || {});
        return 0;
    }

    let roots = match pid {
        Some(pid) if !process_tree.nodes.contains_key(&pid) => return not_found_error(pid),
        Some(pid) => vec![pid],
        None => {
            let mut roots = process_tree.roots();
            roots.sort();
            roots
        }
    };

    for root in roots {
        print_subtree(&process_tree, root, 0);
    }
    if let Some(pid) = pid {
        if let Some(rollup) = process_tree.aggregate(pid) {
            println!(
                "\nfamily rollup for {pid}: {} processes, {:.1}% CPU, {} KB RSS, {} threads, {} open files",
                rollup.process_count,
                rollup.cpu_percent,
                rollup.rss / 1024,
                rollup.thread_count,
                rollup.open_file_count
            );
        }
    }
    0
}

fn print_subtree(tree: &sher_pe_model::ProcessTree, pid: Pid, depth: usize) {
    let Some(process) = tree.nodes.get(&pid) else {
        return;
    };
    println!(
        "{}{} (pid {pid}, {:.1}% CPU, {} KB RSS)",
        "  ".repeat(depth),
        process.name,
        process.cpu.percent,
        process.memory.rss / 1024
    );
    if let Some(children) = tree.children.get(&pid) {
        let mut children = children.clone();
        children.sort();
        for child in children {
            print_subtree(tree, child, depth + 1);
        }
    }
}

pub fn inspect(intel: &ProcessIntelligence, pid: Pid, json: bool) -> i32 {
    let Some(process) = intel.process(pid) else {
        return not_found_error(pid);
    };

    if json {
        #[derive(serde::Serialize)]
        struct Inspection {
            process: ProcessSnapshot,
            threads: Vec<sher_pe_model::ThreadSnapshot>,
            open_files: Vec<sher_pe_model::OpenFile>,
            connections: Vec<sher_pe_model::NetworkConnection>,
            security: Option<sher_pe_model::SecurityContext>,
            systemd_unit: Option<String>,
            scheduler_stats: Option<sher_pe_model::SchedulerStats>,
            container: Option<sher_pe_model::ContainerInfo>,
            fd_limits: Option<sher_pe_model::FdLimits>,
            environment: Vec<sher_pe_model::EnvVar>,
        }
        let inspection = Inspection {
            process: process.clone(),
            threads: intel.threads(pid).unwrap_or_default(),
            open_files: intel.open_files(pid).unwrap_or_default(),
            connections: intel.connections(pid).unwrap_or_default(),
            security: intel.security(pid).ok(),
            systemd_unit: intel.systemd_unit(pid).ok().flatten(),
            scheduler_stats: intel.scheduler_stats(pid).ok(),
            container: intel.container_info(pid).ok().flatten(),
            fd_limits: intel.fd_limits(pid).ok(),
            environment: intel.environment(pid).unwrap_or_default(),
        };
        print_json_or(json, &inspection, || {});
        return 0;
    }

    println!("=== Overview ===");
    println!("pid:      {}", process.pid);
    println!("ppid:     {}", process.ppid);
    println!("pgid:     {}", process.pgid);
    println!("sid:      {}", process.sid);
    println!("name:     {}", process.name);
    println!("state:    {:?}", process.state);
    println!("uid/gid:  {}/{}", process.uid, process.gid);
    println!("cmdline:  {}", process.cmdline.join(" "));
    println!(
        "exe:      {}",
        process.exe.as_deref().unwrap_or("(unknown)")
    );
    if let Ok(Some(unit)) = intel.systemd_unit(pid) {
        println!("systemd:  {unit}");
    }
    if let Ok(Some(container)) = intel.container_info(pid) {
        println!(
            "container: {:?} {} (image: {}, status: {})",
            container.runtime,
            container.name.as_deref().unwrap_or(&container.id[..12]),
            container.image.as_deref().unwrap_or("unknown"),
            container.status.as_deref().unwrap_or("unknown")
        );
    }

    println!("\n=== Memory ===");
    println!("rss:      {} KB", process.memory.rss / 1024);
    println!("vsz:      {} KB", process.memory.vsz / 1024);
    if process.memory.is_detailed() {
        println!("anon:     {} KB", process.memory.anonymous / 1024);
        println!("file:     {} KB", process.memory.file_backed / 1024);
        println!("shared:   {} KB", process.memory.shared / 1024);
        println!("private:  {} KB", process.memory.private / 1024);
    } else {
        println!("(detailed anon/file/shared/private breakdown unavailable on this kernel)");
    }
    println!("swap:     {} KB", process.memory.swap / 1024);

    println!("\n=== CPU ===");
    println!("percent:  {:.1}%", process.cpu.percent);
    println!("utime:    {} ticks", process.cpu.utime_ticks);
    println!("stime:    {} ticks", process.cpu.stime_ticks);
    if let Ok(sched) = intel.scheduler_stats(pid) {
        print!(
            "sched:    on-cpu={}ns wait={}ns",
            sched.on_cpu_ns, sched.wait_ns
        );
        match sched.wait_ratio_percent() {
            Some(ratio) => println!(" ({ratio:.1}% waiting)"),
            None => println!(),
        }
    }

    println!("\n=== Threads ({}) ===", process.thread_count);
    match intel.threads(pid) {
        Ok(threads) => {
            for t in threads {
                println!(
                    "  tid {:>7}  {:<20} {:?}  prio={} nice={}",
                    t.tid, t.name, t.state, t.priority, t.nice
                );
            }
        }
        Err(err) => println!("  (unavailable: {err})"),
    }

    println!("\n=== Files ({}) ===", process.open_file_count);
    if let Ok(limits) = intel.fd_limits(pid) {
        println!(
            "limits:   soft={} hard={}",
            limits
                .soft
                .map_or("unlimited".to_string(), |v| v.to_string()),
            limits
                .hard
                .map_or("unlimited".to_string(), |v| v.to_string())
        );
    }
    match intel.open_files(pid) {
        Ok(files) => {
            for f in files.iter().take(20) {
                println!("  fd {:>4}  {:?}  {}", f.fd, f.kind, f.path);
            }
            if files.len() > 20 {
                println!("  ... and {} more", files.len() - 20);
            }
        }
        Err(err) => println!("  (unavailable: {err})"),
    }

    println!("\n=== Network ===");
    match intel.connections(pid) {
        Ok(conns) if conns.is_empty() => println!("  (no open connections)"),
        Ok(conns) => {
            for c in conns {
                println!(
                    "  {:?} {} -> {} [{:?}]",
                    c.protocol, c.local_addr, c.remote_addr, c.state
                );
            }
        }
        Err(err) => println!("  (unavailable: {err})"),
    }

    println!("\n=== Security ===");
    match intel.security(pid) {
        Ok(sec) => {
            println!("  uid/gid (real):      {}/{}", sec.uid, sec.gid);
            println!("  uid/gid (effective): {}/{}", sec.euid, sec.egid);
            println!(
                "  effective caps:      {}",
                sec.capabilities_effective.join(", ")
            );
            println!("  seccomp mode:        {}", sec.seccomp_mode);
            println!(
                "  LSM label:           {}",
                sec.lsm_label.as_deref().unwrap_or("(none)")
            );
        }
        Err(err) => println!("  (unavailable: {err})"),
    }

    println!("\n=== Environment ===");
    match intel.environment(pid) {
        Ok(vars) if vars.is_empty() => println!("  (no environment variables)"),
        Ok(vars) => {
            for var in vars {
                println!("  {}={}", var.key, var.value);
            }
        }
        Err(err) => println!("  (unavailable: {err})"),
    }

    0
}

pub fn why(intel: &ProcessIntelligence, pid: Pid, aspect: WhyAspect, json: bool) -> i32 {
    if intel.process(pid).is_none() {
        return not_found_error(pid);
    }
    let finding = match aspect {
        WhyAspect::Cpu => sher_pe_investigation::why_cpu(intel, pid),
        WhyAspect::Memory => sher_pe_investigation::why_memory(intel, pid),
        WhyAspect::Network => sher_pe_investigation::why_network(intel, pid),
        WhyAspect::Disk => sher_pe_investigation::why_disk(intel, pid),
    };
    print_json_or(json, &finding, || print_finding(&finding));
    0
}

pub fn investigate(intel: &ProcessIntelligence, pid: Pid, json: bool) -> i32 {
    if intel.process(pid).is_none() {
        return not_found_error(pid);
    }
    let findings = sher_pe_investigation::investigate(intel, pid);
    print_json_or(json, &findings, || {
        for finding in &findings {
            print_finding(finding);
            println!();
        }
    });
    0
}

/// `sher timeline <pid>` — recorded lifecycle events merged
/// chronologically with real journald entries for the process's systemd
/// unit, plus a separately-labeled best-effort kernel-log correlation
/// section (kept separate rather than merged in, since `dmesg`'s
/// timestamps aren't reliably comparable to journald's real epoch time).
pub fn timeline(intel: &ProcessIntelligence, pid: Pid, journal_lines: usize, json: bool) -> i32 {
    if intel.process(pid).is_none() {
        return not_found_error(pid);
    }

    let events = intel.timeline(pid);
    let journal = intel
        .journal_entries(pid, journal_lines)
        .unwrap_or_default();
    let kernel_log = intel.kernel_log_for(pid).unwrap_or_default();

    if json {
        #[derive(serde::Serialize)]
        struct Timeline {
            events: Vec<sher_pe_model::TimelineEvent>,
            journal: Vec<sher_pe_model::LogEntry>,
            kernel_log: Vec<String>,
        }
        print_json_or(
            json,
            &Timeline {
                events,
                journal,
                kernel_log,
            },
            || {},
        );
        return 0;
    }

    enum Item<'a> {
        Event(&'a sher_pe_model::TimelineEvent),
        Log(&'a sher_pe_model::LogEntry),
    }
    let mut items: Vec<(i64, Item)> = Vec::with_capacity(events.len() + journal.len());
    items.extend(events.iter().map(|e| (e.at * 1_000_000, Item::Event(e))));
    items.extend(journal.iter().map(|l| (l.at_us, Item::Log(l))));
    items.sort_by_key(|(at_us, _)| *at_us);

    if items.is_empty() {
        println!("(no recorded lifecycle events or journal entries for pid {pid} yet)");
    }
    for (at_us, item) in &items {
        let secs = at_us / 1_000_000;
        match item {
            Item::Event(e) => println!("[{secs}] EVENT  {}", e.description),
            Item::Log(l) => println!("[{secs}] LOG    {}", l.message),
        }
    }

    if !kernel_log.is_empty() {
        println!("\n=== Kernel log (best-effort correlation by pid/name, not merged into the timeline above) ===");
        for line in &kernel_log {
            println!("{line}");
        }
    }

    0
}

/// `sher trace <pid>` — a short syscall-count sample via `strace -c`
/// (`Tier::ShortSample`). Blocks for roughly `duration_secs`.
pub fn trace(intel: &ProcessIntelligence, pid: Pid, duration_secs: u64, json: bool) -> i32 {
    if intel.process(pid).is_none() {
        return not_found_error(pid);
    }
    match intel.sample_syscalls(pid, Duration::from_secs(duration_secs)) {
        Ok(mut stats) => {
            stats.sort_by_key(|s| std::cmp::Reverse(s.calls));
            print_json_or(json, &stats, || {
                if stats.is_empty() {
                    println!("(no syscalls observed in {duration_secs}s — process may be idle)");
                    return;
                }
                println!(
                    "{:>8} {:>8} {:>8} {:>10}  SYSCALL",
                    "CALLS", "ERRORS", "TIME%", "SECONDS"
                );
                for stat in &stats {
                    println!(
                        "{:>8} {:>8} {:>8.2} {:>10.6}  {}",
                        stat.calls, stat.errors, stat.time_percent, stat.seconds, stat.name
                    );
                }
            });
            0
        }
        Err(err) => {
            eprintln!("sher: syscall trace failed: {err}");
            eprintln!(
                "(requires `strace` and `timeout` installed, and ptrace permission for this pid)"
            );
            1
        }
    }
}

/// `sher profile <pid>` — a short stack-sampling profile via `perf`
/// (`Tier::Profile`). Blocks for roughly `duration_secs`.
pub fn profile(intel: &ProcessIntelligence, pid: Pid, duration_secs: u64, json: bool) -> i32 {
    if intel.process(pid).is_none() {
        return not_found_error(pid);
    }
    match intel.sample_hot_functions(pid, Duration::from_secs(duration_secs)) {
        Ok(hot_functions) => {
            print_json_or(json, &hot_functions, || {
                if hot_functions.is_empty() {
                    println!(
                        "(no samples landed anywhere in {duration_secs}s — process may be idle)"
                    );
                    return;
                }
                println!("{:>8}  MODULE  SYMBOL", "OVERHEAD");
                for hot in &hot_functions {
                    println!(
                        "{:>7.2}%  {:<8}  {}",
                        hot.overhead_percent, hot.module, hot.symbol
                    );
                }
            });
            0
        }
        Err(err) => {
            eprintln!("sher: profile failed: {err}");
            eprintln!("(requires `perf` installed and sufficient privilege — CAP_PERFMON/perf_event_paranoid)");
            1
        }
    }
}

/// `sher deep-trace <pid>` — a live, per-event syscall trace via real
/// eBPF (`bpftrace`, `Tier::DeepTrace`). Blocks for roughly
/// `duration_secs` (plus a short kill-grace period — see
/// `sher_pe_telemetry::linux::bpftrace`). Gated behind
/// `--i-accept-the-overhead` in `main()`, not here.
pub fn deep_trace(intel: &ProcessIntelligence, pid: Pid, duration_secs: u64, json: bool) -> i32 {
    if intel.process(pid).is_none() {
        return not_found_error(pid);
    }
    match intel.deep_trace(pid, Duration::from_secs(duration_secs)) {
        Ok(events) => {
            print_json_or(json, &events, || {
                if events.is_empty() {
                    println!("(no syscalls observed in {duration_secs}s — process may be idle)");
                    return;
                }
                println!("{:>14}  SYSCALL", "+ns");
                for event in &events {
                    println!("{:>14}  {}", event.at_ns, event.syscall);
                }
                println!(
                    "({} events shown — a busy process may generate far more than this per second)",
                    events.len()
                );
            });
            0
        }
        Err(err) => {
            eprintln!("sher: deep trace failed: {err}");
            eprintln!(
                "(requires `bpftrace` and `timeout` installed, tracefs mounted, and CAP_BPF/CAP_SYS_ADMIN)"
            );
            1
        }
    }
}

/// `sher history <pid>` — long-term history from `sherd`'s persistent
/// SQLite database, independent of whether `pid` is still alive or how
/// long ago it was sampled (unlike `timeline`, which only sees this
/// process's own short-lived, in-memory `ProcessIntelligence` history).
pub fn history(pid: Pid, since_secs: i64, db_path: &std::path::Path, json: bool) -> i32 {
    let store = match sher_pe_history::HistoryStore::open(db_path) {
        Ok(store) => store,
        Err(err) => {
            eprintln!(
                "sher: failed to open history database at {}: {err}",
                db_path.display()
            );
            eprintln!("(is sherd running? see `sherd --help`)");
            return 1;
        }
    };

    let since = now_unix() - since_secs;
    let snapshots = match store.snapshots_for(pid, since) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("sher: failed to read snapshot history: {err}");
            return 1;
        }
    };
    let events = match store.events_for(pid, since) {
        Ok(e) => e,
        Err(err) => {
            eprintln!("sher: failed to read timeline history: {err}");
            return 1;
        }
    };

    if json {
        #[derive(serde::Serialize)]
        struct History {
            snapshots: Vec<(i64, sher_pe_model::ProcessSnapshot)>,
            events: Vec<sher_pe_model::TimelineEvent>,
        }
        print_json_or(true, &History { snapshots, events }, || {});
        return 0;
    }

    if snapshots.is_empty() && events.is_empty() {
        println!(
            "(no persisted history for pid {pid} in the last {since_secs}s — either sherd \
             isn't running, or this pid has no recorded activity in that window)"
        );
        return 0;
    }

    println!("=== Snapshots ({}) ===", snapshots.len());
    for (sampled_at, snap) in &snapshots {
        println!(
            "[{sampled_at}] {} rss={} KB cpu={:.1}% state={:?}",
            snap.name,
            snap.memory.rss / 1024,
            snap.cpu.percent,
            snap.state
        );
    }

    println!("\n=== Timeline events ({}) ===", events.len());
    for event in &events {
        println!("[{}] {}", event.at, event.description);
    }

    0
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `sher export <pid>` — a full diagnostic report as one JSON document.
/// Writes to `output` if given, otherwise stdout (so it composes with
/// shell redirection/piping the same way every other `sher` command does).
pub fn export(intel: &ProcessIntelligence, pid: Pid, output: Option<&std::path::Path>) -> i32 {
    let Some(report) = sher_pe_investigation::diagnostic_report(intel, pid) else {
        return not_found_error(pid);
    };
    let json = match serde_json::to_string_pretty(&report) {
        Ok(json) => json,
        Err(err) => {
            eprintln!("sher: failed to serialize diagnostic report: {err}");
            return 1;
        }
    };
    match output {
        Some(path) => match std::fs::write(path, &json) {
            Ok(()) => {
                println!(
                    "Wrote diagnostic report for pid {pid} to {}",
                    path.display()
                );
                0
            }
            Err(err) => {
                eprintln!("sher: failed to write {}: {err}", path.display());
                1
            }
        },
        None => {
            println!("{json}");
            0
        }
    }
}

/// `sher kill <pid>` — sends a real POSIX signal to a real process.
/// Prompts for interactive confirmation unless `yes` is set, since this is
/// the one CLI command that changes system state rather than just reading
/// it.
pub fn kill(
    intel: &ProcessIntelligence,
    pid: Pid,
    signal: sher_pe_model::Signal,
    yes: bool,
    json: bool,
) -> i32 {
    let Some(process) = intel.process(pid) else {
        return not_found_error(pid);
    };
    let process_name = process.name.clone();

    if !yes {
        use std::io::Write;
        print!(
            "Send {signal} to {} (pid {pid})?{} [y/N] ",
            process.name,
            if signal.is_uncatchable() {
                " This cannot be caught or ignored by the process."
            } else {
                ""
            }
        );
        if std::io::stdout().flush().is_err() {
            eprintln!("sher: failed to write confirmation prompt");
            return 1;
        }
        let mut answer = String::new();
        if std::io::stdin().read_line(&mut answer).is_err() {
            eprintln!("sher: failed to read confirmation, aborting");
            return 1;
        }
        let answer = answer.trim().to_lowercase();
        if answer != "y" && answer != "yes" {
            println!("Aborted.");
            return 1;
        }
    }

    let result = intel.send_signal(pid, signal);
    if json {
        #[derive(serde::Serialize)]
        struct KillResult {
            pid: Pid,
            process_name: String,
            signal: String,
            ok: bool,
            error: Option<String>,
        }
        let kill_result = KillResult {
            pid,
            process_name,
            signal: signal.to_string(),
            ok: result.is_ok(),
            error: result.as_ref().err().map(|e| e.to_string()),
        };
        print_json_or(true, &kill_result, || {});
        return if kill_result.ok { 0 } else { 1 };
    }
    match result {
        Ok(()) => {
            println!("Sent {signal} to pid {pid} ({process_name}).");
            0
        }
        Err(err) => {
            eprintln!("sher: failed to send {signal} to pid {pid}: {err}");
            1
        }
    }
}

fn print_finding(finding: &Finding) {
    println!(
        "[{:?}/{:?}] {}",
        finding.severity, finding.confidence, finding.title
    );
    println!("  {}", finding.narrative);
    for evidence in &finding.evidence {
        println!(
            "  - evidence ({}): {} — {}",
            evidence.source, evidence.description, evidence.raw
        );
    }
}
