//! Curated bpftrace scripts for off-CPU/IO/scheduler investigation.
//!
//! These complement procfs/syscall sampling: blocking, IO latency and run-queue
//! delay are the usual root causes that CPU sampling alone cannot see.

pub const SCRIPTS: &[(&str, &str)] = &[
    (
        "offcpu",
        r#"tracepoint:sched:sched_switch /args->prev_pid == $PID/
{
  @start[args->prev_pid] = nsecs;
}
tracepoint:sched:sched_switch /args->next_pid == $PID && @start[args->next_pid]/
{
  @offcpu[args->next_comm] = hist(nsecs - @start[args->next_pid]);
  delete(@start[args->next_pid]);
}
"#,
    ),
    (
        "iolatency",
        r#"kprobe:blk_account_io_start { @start[arg0] = nsecs; }
kretprobe:blk_account_io_done /@start[arg0]/
{
  @io_latency_us = hist((nsecs - @start[arg0]) / 1000);
  delete(@start[arg0]);
}
"#,
    ),
    (
        "runqlat",
        r#"tracepoint:sched:sched_wakeup /args->pid == $PID/ { @wake[args->pid] = nsecs; }
tracepoint:sched:sched_switch /args->next_pid == $PID && @wake[args->next_pid]/
{
  @runqueue_us = hist((nsecs - @wake[args->next_pid]) / 1000);
  delete(@wake[args->next_pid]);
}
"#,
    ),
];

pub fn available_scripts() -> Vec<&'static str> {
    SCRIPTS.iter().map(|(name, _)| *name).collect()
}

pub fn script(name: &str) -> Option<&'static str> {
    SCRIPTS
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, body)| *body)
}

pub fn command(name: &str, pid: i32, duration_secs: u64) -> Result<(String, Vec<String>), String> {
    let body = script(name).ok_or_else(|| {
        format!(
            "unknown ebpf script '{name}' (available: {})",
            available_scripts().join(", ")
        )
    })?;
    let bpftrace = format!("{body}\ninterval:s:{duration_secs} {{ exit(); }}\n")
        .replace("$PID", &pid.to_string());
    Ok((
        "bpftrace".to_string(),
        vec![
            "-p".to_string(),
            pid.to_string(),
            "-e".to_string(),
            bpftrace,
        ],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_and_looks_up_scripts() {
        assert!(available_scripts().contains(&"offcpu"));
        assert!(script("iolatency").is_some());
        assert!(script("nope").is_none());
    }

    #[test]
    fn command_includes_pid_and_exit_interval() {
        let (program, args) = command("runqlat", 42, 5).unwrap();
        assert_eq!(program, "bpftrace");
        assert!(args.contains(&"42".to_string()));
        assert!(args.iter().any(|arg| arg.contains("interval:s:5")));
        let script = args
            .iter()
            .find(|arg| arg.contains("tracepoint:sched:sched_wakeup"))
            .unwrap();
        assert!(script.contains("== 42"));
        assert!(!script.contains("$PID"));
    }
}
