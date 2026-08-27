# ARCHITECTURE.md — SHER Process Explorer

## Layering

```
sher-pe-cli   sher-pe-gui
    │              │  depend on
    └──────┬───────┘
           ▼
sher-pe-investigation
    │  depends on
    ▼
sher-pe-intelligence
    │  depends on
    ▼
sher-pe-telemetry
    │  depends on
    ▼
sher-pe-model
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
`sher-pe-cli` and `sher-pe-gui` are the only crates allowed to depend on
both `sher-pe-intelligence` and `sher-pe-investigation` directly — siblings
at the same level, calling the exact same API, never one depending on the
other.

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
- `linux::systemd` — unit-from-cgroup-path mapping + `systemctl show`/
  `journalctl -u` shell-outs (dbus/`zbus` explicitly deferred)
- `linux::kernel_log` — `dmesg -T` / `/dev/kmsg` best-effort read, used only
  for OOM-kill correlation in the investigation engine

Tiered collection (`Tier::{Continuous, ShortSample, Profile, DeepTrace}`)
exists as an enum so the seam is real, but only `Continuous` (Level 1,
cheap) is implemented this pass — the rest return a typed
`TelemetryError::Unsupported`.

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
  dominance
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
sher trace <pid> / sher profile <pid>    # honest errors: Level 3/4 tracing not built
```

`main()` checks `cfg!(target_os = "linux")` and exits with a clear error
message on any other OS — no silent no-op.

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
