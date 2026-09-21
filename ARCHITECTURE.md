# ARCHITECTURE.md — SHER Process Explorer

## Layering

```mermaid
flowchart TB
    CLI["sher-pe-cli\n(sher binary)"]
    GUI["sher-pe-gui\n(sher-gui binary)"]
    DAEMON["sher-pe-daemon\n(sherd binary)"]
    INVEST["sher-pe-investigation\n(deterministic \"why\" engine)"]
    INTEL["sher-pe-intelligence\n(tree / rollups / history / timeline)"]
    HISTORY["sher-pe-history\n(SQLite persistence)"]
    TELEM["sher-pe-telemetry\nTelemetryAdapter trait"]
    LINUX["linux::LinuxAdapter\n(hand-rolled /proc parsing)"]
    KERNEL["SherKernelAdapter\n(Phase 6 — reserved seam, NOT BUILT)"]
    MODEL["sher-pe-model\n(pure data types, no I/O)"]

    CLI --> INVEST
    CLI --> INTEL
    GUI --> INVEST
    GUI --> INTEL
    DAEMON --> INTEL
    DAEMON --> HISTORY
    INVEST --> INTEL
    INTEL --> TELEM
    HISTORY --> MODEL
    TELEM --> MODEL
    TELEM -.implements.-> LINUX
    TELEM -.would implement.-> KERNEL
    LINUX --> MODEL

    classDef notbuilt fill:none,stroke:#999,stroke-dasharray: 4 3,color:#999;
    class KERNEL notbuilt;
```

`sher-pe-model` has no I/O and no dependency on anything else in this
workspace — it is pure data. Everything else depends on it.
`sher-pe-investigation`'s production code depends only on
`sher-pe-intelligence` (it never talks to `TelemetryAdapter` directly —
`ProcessIntelligence` exposes live `threads`/`connections`/`disk_io`
pass-throughs for exactly the on-demand reads `why_cpu`/`why_network`/
`why_disk` need, alongside the tracked history `why_memory` uses); it only
takes `sher-pe-telemetry` as a dev-dependency, to build a
`MockTelemetryAdapter`-backed `ProcessIntelligence` in its own tests.
`sher-pe-cli`, `sher-pe-gui`, and `sher-pe-daemon` are the only crates
allowed to depend on `sher-pe-intelligence` directly from the binary layer;
`sher-pe-cli`/`sher-pe-gui` additionally depend on `sher-pe-investigation`
directly — siblings at the same level, calling the exact same API, never
one depending on the other. `sher-pe-daemon` depends on `sher-pe-history`
instead, since its job is persistence, not investigation.

**`SherKernelAdapter` (dashed box above) does not exist yet.** It is
Phase 6 in `ROADMAP.md`: a second `TelemetryAdapter` implementation,
consuming native SHER Kernel process telemetry once SHER Kernel ships it,
dropped in alongside `linux::LinuxAdapter` without changing
`sher-pe-intelligence`, `sher-pe-investigation`, the CLI, the GUI, or the
daemon. It is shown here only to make the reserved seam concrete, not
because any code backs it.

## `sher-pe-model`

Pure structs/enums, `serde::{Serialize, Deserialize}` derived on everything
so any consumer gets `--json` output for free. One module per domain:
`process`, `cpu`, `memory`, `thread`, `files`, `network`, `cgroup`,
`namespace`, `security`, `tree`, `evidence`, `timeline`.

Key types:

- `ProcessSnapshot { pid, ppid, name, cmdline, exe, state, uid, gid,
  start_time, cpu, memory, thread_count, open_file_count, cgroup }`
- `MemoryBreakdown { rss, vsz, anonymous, file_backed, shared, private,
  swap }` — sourced from `smaps_rollup` where available, falling back to
  `statm`/`status` on kernels without it.
- `CpuStats { utime_ticks, stime_ticks, percent, voluntary_ctxt_switches,
  nonvoluntary_ctxt_switches }` — `percent` is computed by the intelligence
  layer from two tick-deltas across a `refresh()`, never by telemetry
  (telemetry only ever reports a single point-in-time reading).
- `ThreadSnapshot { tid, name, state, cpu, priority, nice, affinity }`
- `OpenFile { fd, path, kind }`, `NetworkConnection { protocol, local_addr,
  remote_addr, state, inode }`, `CgroupInfo { version, path, controllers }`,
  `NamespaceInfo { pid, mnt, net, user, uts, ipc, cgroup }`,
  `SecurityContext { uid, gid, euid, capabilities, seccomp }`
- `ProcessTree { nodes: HashMap<Pid, ProcessSnapshot>, children:
  HashMap<Pid, Vec<Pid>> }` with `family(pid)` / `aggregate(pid) ->
  FamilyRollup`
- `Evidence { source, collected_at, description, raw }`, `Confidence
  { Observed, Correlated, Likely, Unknown }`, `Finding { severity, title,
  narrative, confidence, evidence }` — the type that structurally enforces
  "never claim more certainty than the data supports."
- `TimelineEvent { at, kind, description }`

## `sher-pe-telemetry`

One trait, mirroring the `HardwareDriver` HAL pattern from SHER-Kernel:

```rust
pub trait TelemetryAdapter: Send + Sync {
    fn list_pids(&self) -> Result<Vec<Pid>>;
    fn process(&self, pid: Pid) -> Result<ProcessSnapshot>;
    fn threads(&self, pid: Pid) -> Result<Vec<ThreadSnapshot>>;
    fn open_files(&self, pid: Pid) -> Result<Vec<OpenFile>>;
    fn connections(&self, pid: Pid) -> Result<Vec<NetworkConnection>>;
    fn cgroup(&self, pid: Pid) -> Result<Option<CgroupInfo>>;
    fn namespaces(&self, pid: Pid) -> Result<NamespaceInfo>;
    fn security(&self, pid: Pid) -> Result<SecurityContext>;
    fn systemd_unit(&self, pid: Pid) -> Result<Option<String>>;
}
```

`linux::LinuxAdapter` is the only implementation this pass, built entirely
from hand-rolled parsers reading `/proc` and `/sys` directly — no
`procfs`/`sysinfo` crate. Parsers take a `root: &Path` (defaults to `/proc`)
so they're swappable onto fixture directories in tests.

Submodules:

- `linux::procfs::process` — `stat`, `status`, `cmdline`, `exe` (readlink),
  `comm`
- `linux::procfs::memory` — `statm`, `status` (VmRSS/VmSwap),
  `smaps_rollup` (Pss, Shared/Private Clean/Dirty, Anonymous)
- `linux::procfs::threads` — `task/*/stat`, affinity via
  `nix::sched::sched_getaffinity`
- `linux::procfs::files` — `fd/*` readlink + classification
  (regular/dir/socket/pipe/device)
- `linux::procfs::net` — `/proc/net/{tcp,tcp6,udp,udp6,unix}` parsing, hex
  addr:port decode, socket-inode → pid resolution via the `fd/*` scan
- `linux::procfs::cgroup` — `/proc/[pid]/cgroup` + v1-vs-v2 detection via
  `/sys/fs/cgroup`
- `linux::procfs::namespace` — `/proc/[pid]/ns/*` inode readlink
- `linux::procfs::security` — `status` (Uid/Gid/CapEff/CapBnd), best-effort
  LSM label
- `linux::procfs::scheduler` — `/proc/[pid]/schedstat` (time running vs.
  time waiting for a CPU)
- `linux::systemd` — unit-from-cgroup-path mapping + `systemctl show`/
  `journalctl -u` shell-outs (dbus/`zbus` explicitly deferred)
- `linux::kernel_log` — `dmesg -T` / `/dev/kmsg` best-effort read, used only
  for OOM-kill correlation in the investigation engine
- `linux::perf` — `perf record`/`perf report` shell-outs for a short
  stack-sampling profile, parsed into `HotFunction` rows
- `linux::strace` — `strace -c` (bounded by `timeout`) for a syscall-count
  summary, parsed into `SyscallStat` rows
- `linux::bpftrace` — real eBPF: `bpftrace` attached to every
  `syscalls:sys_enter_*` tracepoint (filtered by pid) for a live per-event
  syscall timeline, parsed into `TraceEvent` rows. Bounded with
  `timeout -k <grace> <duration>`, not plain `timeout` — `bpftrace`'s
  userspace loop can defer noticing `SIGTERM` for many seconds under a
  busy process. Detaching the ~300 attached probes still takes real,
  non-interruptible kernel-side time regardless (observed 10–15s beyond
  the requested duration, independent of target activity) — documented in
  the module rather than papered over.
- `linux::container` — maps a cgroup path to `(runtime, id)` via pure
  string matching (`/docker/<id>`, `docker-<id>.scope`,
  `libpod-<id>.scope`, `cri-containerd-<id>.scope`), then enriches with
  `docker`/`podman inspect --format` when possible. containerd is
  detected but not enriched (no single universal inspect CLI). Confirmed
  end-to-end against a real running Docker container.
- `linux::journald` — real journald ingestion for timeline correlation:
  `journalctl -u <unit> -o json`, parsed via `serde_json` against
  journald's real, stable export-format field names (confirmed against a
  genuine systemd+journald container), not scraped text.

Tiered collection (`Tier::{Continuous, ShortSample, Profile, DeepTrace}`)
exists as an enum so the seam is real, and all four tiers are implemented
for `LinuxAdapter`: `Continuous` (Level 1, cheap — includes
`scheduler_stats`), `ShortSample` (Level 2, `sample_syscalls`), `Profile`
(Level 3, `sample_hot_functions`), and `DeepTrace` (Level 4,
`deep_trace`). An adapter that doesn't override a tier's method (e.g. a
future `SherKernelAdapter`) returns a typed `TelemetryError::Unsupported`
for it, by default.

## `sher-pe-intelligence`

`ProcessIntelligence` owns a `Box<dyn TelemetryAdapter>` plus a bounded
in-memory history buffer keyed by `(Pid, start_time)` — never bare `Pid`, to
avoid misattributing history across PID reuse.

- `refresh(&mut self) -> Result<()>` — full snapshot pass: computes CPU%
  from tick deltas, appends to history, prunes exited processes, emits
  `TimelineEvent`s (started/exited, memory-growth threshold crossed, new
  child, new connection).
- `tree(&self) -> ProcessTree`, `family_rollup(&self, pid) -> FamilyRollup`
- `process(&self, pid)`, `history(&self, pid)`, `timeline(&self, pid)`

This is the single shared API both `sher-pe-cli` and `sher-pe-gui` call —
no telemetry-format knowledge leaks past this layer.

## `sher-pe-investigation`

Deterministic, rule-based — explicitly **not** an LLM call this pass (see
Phase 7 in `ROADMAP.md`).

- `why_cpu(pid) -> Finding` — top threads by CPU%, flags single-thread
  dominance; also folds in `/proc/[pid]/schedstat`-based scheduling
  contention (≥20% of scheduled time spent waiting for a CPU escalates
  severity and caps confidence at `Likely`)
- `why_memory(pid) -> Finding` — anon/file/shared breakdown, RSS
  growth-rate over the history window (e.g. >50% growth within 60 min →
  `Confidence::Likely` "sustained growth")
- `why_network(pid) -> Finding` — connection count/persistence summary
- `why_disk(pid) -> Finding` — best-effort via `/proc/[pid]/io` byte deltas
- `investigate(pid) -> Vec<Finding>` — runs all of the above
- `crash_analysis(pid_history) -> Finding` — correlates a process-exit
  timeline event against memory-growth history and `dmesg` OOM-kill lines

Every `Finding` carries `Vec<Evidence>` pointing at the exact raw source
(file path + raw value), so a caller can always show "why do you say that."

## `sher-pe-cli`

`clap`-derive based, binary name `sher`, global `--json` on every
subcommand (headless/SSH-friendly):

```
sher ps                                 # flat or tree-collapsed listing
sher tree [pid]                          # hierarchical view + family rollups
sher inspect <pid>                       # Overview/Memory/CPU/Threads/Files/Network/Security
sher why <pid> <cpu|memory|network|disk>
sher investigate <pid>
sher timeline <pid>                      # lifecycle events + journald merged chronologically
sher trace <pid>                         # strace -c syscall breakdown (Tier::ShortSample)
sher profile <pid>                       # perf hot-function sample (Tier::Profile)
sher deep-trace <pid> --i-accept-the-overhead   # bpftrace live syscall timeline (Tier::DeepTrace)
```

`main()` checks `cfg!(target_os = "linux")` and exits with a clear error
message on any other OS — no silent no-op. `SIGPIPE` is reset to its
default disposition at startup (`reset_sigpipe`, Unix only) so piping into
something that closes early (`sher ps | head`) exits quietly instead of
panicking on a broken-pipe write — the standard fix every Unix CLI tool
needs and Rust's runtime doesn't apply for you.

## `sher-pe-gui`

`egui`/`eframe`-based, binary name `sher-gui`. Same data, same calls as the
CLI — `treeview::flatten_tree` (pure, unit-tested) turns `ProcessTree` plus
expand/collapse + search-filter state into display rows; `SherApp::ui`
renders a process tree on the left and, for the selected pid, tabbed detail
(Overview/Memory/CPU/Threads/Files/Network/Disk I/O/Security) on the right,
with `Why?` buttons on Memory/CPU/Network/Disk calling straight into
`sher-pe-investigation`.

Unlike the CLI, `main()` does **not** refuse to run off Linux — it still
opens the window (there's real value in tweaking the UI without a Linux
machine on hand) and surfaces a failed `refresh()` as an in-window banner
instead. `SherApp` re-runs `intel.refresh()` every 2 seconds
(`REFRESH_INTERVAL`) so CPU% — computed from tick deltas across two ticks —
becomes meaningful shortly after the window opens, rather than staying at
0% forever the way a one-shot CLI invocation would.

## `sher-pe-history`

Persistent, long-term process history — the piece `sher-pe-intelligence`
deliberately doesn't provide, since its in-memory history/timeline are
capacity-bounded (120 ticks, 1000 events) and gone the moment a process is
dropped and the CLI/GUI invocation exits. Depends only on `sher-pe-model`
(pure persistence over its types) — no telemetry dependency, so it can't
accidentally grow logic that belongs in `sher-pe-intelligence`.

`HistoryStore` wraps a real SQLite connection (`rusqlite`, `bundled`
feature — no system `libsqlite3` needed) with two tables, `snapshots` and
`timeline_events`, both indexed by pid and time and keyed by `(pid,
start_time)` (same PID-reuse-safe key `sher-pe-intelligence` uses in
memory, not bare `Pid`). `HistoryStore::open(path)` creates parent
directories and migrates the schema if needed; `open_in_memory()` gives
tests a real SQLite connection that never touches disk. `prune_older_than`
bounds retention. `HistoryError` wraps both `rusqlite::Error` and
`serde_json::Error` (snapshots/events are stored as JSON blobs alongside
indexed pid/time columns for fast range queries without a wide relational
schema).

## `sher-pe-daemon`

`sherd`, meant to run under systemd (`packaging/systemd/sherd.service`),
not self-daemonizing (no fork/setsid — systemd already supervises
long-running foreground processes). `main()` builds a
`ProcessIntelligence` over the real `linux::LinuxAdapter` and a
`HistoryStore` at `--db` (default: `/var/lib/sher/history.db` when
`geteuid() == 0`, else `~/.local/share/sher/history.db`), then loops on a
fixed `--interval-secs` (default 5): `refresh_at`, persist every current
snapshot, persist each tick's *new* timeline events only (via
`ProcessIntelligence::recent_timeline_events(since)`, so the same event
isn't re-written every tick), and periodically prune anything older than
`--retention-days` (default 7). A `SIGTERM`/`SIGINT` handler
(`handle_shutdown_signal`) flips an `AtomicBool` that `sleep_interruptible`
polls in 200ms steps, so a systemd `stop` doesn't have to wait out a full
tick interval before the process actually exits. No unit tests of its own
(it is thin wiring over already-tested `sher-pe-intelligence`/
`sher-pe-history` APIs); validated end-to-end on real Linux instead
(ROADMAP.md Phase 8).

## Risk notes

- **cgroup v1 vs v2 / missing `smaps_rollup`** → detect and degrade
  gracefully, never panic on a missing file.
- **Permission errors** on another user's `/proc/[pid]/*` → typed
  `PermissionDenied` surfaced per-field, not a crash of the whole snapshot.
- **PID reuse** between refresh ticks → history keyed by `(pid,
  start_time)`.
- **Dev machine is macOS** → parser unit tests run against fixtures on
  macOS; anything needing real Linux syscalls is
  `#[cfg(target_os = "linux")]`-gated and validated separately.
