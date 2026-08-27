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
        }
        let inspection = Inspection {
            process: process.clone(),
            threads: intel.threads(pid).unwrap_or_default(),
            open_files: intel.open_files(pid).unwrap_or_default(),
            connections: intel.connections(pid).unwrap_or_default(),
            security: intel.security(pid).ok(),
            systemd_unit: intel.systemd_unit(pid).ok().flatten(),
            scheduler_stats: intel.scheduler_stats(pid).ok(),
        };
        print_json_or(json, &inspection, || {});
        return 0;
    }

    println!("=== Overview ===");
    println!("pid:      {}", process.pid);
    println!("ppid:     {}", process.ppid);
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
