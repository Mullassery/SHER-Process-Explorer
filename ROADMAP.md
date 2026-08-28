# ROADMAP.md — SHER Process Explorer

Phased plan. Each phase is additive on top of the trait/API seams laid down
in Phase 0 — later phases should not require rewriting earlier ones.

## Phase 0 — Engine + CLI ✅ (this pass)

Process discovery, hierarchical tree + family rollups, CPU/memory/thread/
file/network/cgroup/namespace/security telemetry (Level 1 only), timeline,
rule-based "Why?" investigation engine, `sher` CLI, systemd unit mapping,
evidence-based findings. Runs on any standard Linux distro, no SHER Kernel
dependency.

*Success bar: everything answerable from the CLI alone.*

## Phase 1 — Desktop UI ✅

A GUI (`sher-pe-gui`, binary `sher-gui`) consuming the *same*
`sher-pe-intelligence` / `sher-pe-investigation` APIs the CLI uses — no new
logic, just presentation: hierarchical process explorer with a
collapse/expand + search-filterable tree (`treeview.rs`, unit-tested
independently of any rendering), drill-down detail tabs (Overview, Memory,
CPU, Threads, Files, Network, Disk I/O, Security), and `Why?` buttons on
Memory/CPU/Network/Disk wired directly to the existing investigation
engine. Toolkit: **egui/eframe** (pure Rust, immediate-mode) — chosen over
GTK4/libadwaita and Tauri for a fast native dev loop on any OS with no
system library bindings; the tradeoff is not plugging directly into
Aurora's GTK4/libadwaita design system, which stays open for a future
reskin if the ecosystem needs it. Auto-refreshes every 2s so CPU% (which
needs two ticks to compute) becomes meaningful shortly after opening.

Verified with a real screenshot (via Xvfb + `import` in a Linux container)
showing live real `/proc` data end-to-end: the process tree, a family
rollup, and a `why_memory` `Finding` with real evidence, not a mock.

## Phase 2 — Deeper CPU/thread intelligence (Level 2–3 tracing) ✅

Scheduler latency (`/proc/[pid]/schedstat`, real parser, `Tier::Continuous`
since it's cheap — no sampling needed), stack-sampling "hot function" views
(`sample_hot_functions`, `Tier::Profile`), and syscall-count breakdown
(`sample_syscalls`, `Tier::ShortSample`). The latter two shell out to the
real `perf` and `strace` tools — the same "shell out to the real thing"
MVP-sized choice `systemd.rs`/`kernel_log.rs` already made in Phase 0,
rather than reimplementing `perf_event_open` + stack unwinding +
symbolization or ptrace-based syscall tracing from scratch. Both require
the tool installed and adequate privilege (`CAP_PERFMON`/
`perf_event_paranoid` for `perf`; ptrace permission for `strace`) — a
missing tool or insufficient privilege surfaces as a normal error, not a
crash or a fake empty result.

`why_cpu` folds in scheduling-contention evidence: ≥20% of scheduled time
spent waiting for a CPU escalates severity to at least Notice and caps
confidence at `Likely` (a threshold heuristic, not an observed fact).

Exposed in both the CLI (`sher trace`/`sher profile`, previously honest
stubs, now real) and the GUI (CPU tab: scheduler stats plus "Profile"/
"Trace syscalls" buttons — both block the window for the sample duration,
documented in the UI rather than silently freezing).

Verified end-to-end on real Linux against a genuine CPU-busy process
(`perf`/`strace` actually invoked, not mocked) in a privileged container,
including a GUI screenshot of the CPU tab mid-round-trip. That testing
caught two real bugs before they shipped: `perf report`'s output for an
unresolved symbol (stripped/static binary) appends placeholder columns
that were being swept into the symbol string, and `println!`-based output
piped into something that closes early (e.g. `| head`) panicked on
`SIGPIPE` instead of exiting quietly like other Unix tools — both fixed,
with a regression test for the first.

## Phase 3 — eBPF / perf (Level 4 deep tracing) ✅ (syscall tracing)

`deep_trace` (`Tier::DeepTrace`) attaches real `bpftrace` to every
`syscalls:sys_enter_*` tracepoint filtered by pid — a genuine per-event
syscall timeline (real syscall names, not numeric IDs), not the aggregate
counts Phase 2's `sample_syscalls` already provides. Deliberately uses the
wildcard tracepoint match rather than a single `raw_syscalls:sys_enter`
probe plus a hand-maintained syscall-number-to-name table: the latter
would be faster to tear down but risks a silent, unverifiable mislabeling
on some architecture, which is a worse failure mode than being slower.
Gated behind a required `--i-accept-the-overhead` CLI flag (ROADMAP's
"clear user-facing warnings before enabling") that explains the real cost
before running, not just on failure.

Exposed only in the CLI (`sher deep-trace`) this pass — GUI wiring is
deferred, not a fake stub: the underlying capability is fully real and
already usable from the CLI; the GUI would additionally need
volume-bounded table rendering for up to 2000 rows and the same explicit
opt-in gating, which is real but separable UI work.

I/O and network tracing (this phase's other two ROADMAP items) remain
future work — this pass covers syscall tracing only.

**Verified end-to-end on real Linux** in a privileged container against
both a saturating syscall-bound process and an idle one. That testing
caught two real, non-obvious bugs:
- `timeout <secs>` alone (Phase 2's `strace.rs` pattern) isn't sufficient
  here — `bpftrace`'s userspace loop can defer noticing `SIGTERM` for many
  seconds under load. Fixed with `timeout -k <grace> <duration>` to force
  `SIGKILL` after a grace period.
- `std::process::ExitStatus::code()` returns `None` for a signal-killed
  process (unlike a shell's `$?`, which reports `128+signal`) — the
  original `code() == Some(137)` check for the forced-`SIGKILL` case
  silently never matched, so every forced-kill sample was wrongly treated
  as a hard failure. Fixed by checking
  `ExitStatusExt::signal() == Some(9)` instead.

Also discovered, and documented rather than silently absorbed: tearing
down ~300 attached eBPF probes takes real kernel-side time — observed
10–15 seconds beyond the requested duration, independent of how busy the
traced process is, and not shortened by any signal (not even `SIGKILL`)
once the kernel-side teardown has started. `deep_trace` always returns
correct data; it just doesn't return within `duration + a small grace`,
unlike `sample_hot_functions`/`sample_syscalls`. The CLI's pre-run warning
says so explicitly.

## Phase 4 — Containers & namespaces as first-class objects ✅

`container_info` maps a process's cgroup path (already collected since
Phase 0) to the container that owns it: Docker and Podman get full
metadata (name, image, status) via `docker`/`podman inspect --format`;
containerd (CRI) containers are detected (runtime + id) but not enriched
— no single universal inspect CLI exists for it the way Docker/Podman
each have one, an honest scope limit rather than a stub. Shown in `sher
inspect`'s Overview section, its `--json` output, and the GUI's Overview
tab — the same `ProcessIntelligence::container_info` call, no separate
logic.

Detection is pure cgroup-path pattern matching against the real
`cgroupfs`- and `systemd`-driver conventions each runtime's own source
code emits (`/docker/<id>`, `docker-<id>.scope`, `libpod-<id>.scope`,
`cri-containerd-<id>.scope`). The `cgroupfs` pattern was confirmed
directly against a real running container; the others are stable string
constants (not numeric values at risk of a transcription error — a
lesson carried over from Phase 3's syscall-table decision). A path
matching none of these is `None`, never a wrong or fabricated answer.

**Verified end-to-end on real Linux**: built a real Docker daemon +
container inside a privileged test container, ran `sher inspect` against
its actual init process, and confirmed the CLI, `--json`, and a GUI
screenshot all correctly show `Container: Docker testctr (image:
ubuntu:22.04, status: running)`. That testing caught a real bug in the
test data itself, not the shipped code: a hand-copied 64-hex-character
container id was transcribed one character short in a unit test,
silently failing every pattern-match test until length validation caught
it — exactly the transcription risk that motivated avoiding a hand-built
syscall-number table in Phase 3, now validated as a real, recurring risk
worth designing around.

## Phase 5 — Log correlation & crash timeline UI ✅

`journal_entries` shells `journalctl -u <unit> -o json` and parses the
real structured per-line JSON (not scraped text) into `LogEntry`, with a
real epoch-microsecond timestamp directly comparable to `TimelineEvent`.
`sher timeline <pid>` (CLI) and the GUI's new Timeline tab both merge
recorded lifecycle events with journal entries chronologically by their
actual timestamps — the same merge logic, no separate CLI/GUI code path
— plus a separately-labeled best-effort kernel-log correlation section
(`kernel_log_for`, generalizing Phase 0's OOM-only check to match by pid
or process name). Kept separate rather than merged into the same sorted
list: `dmesg`'s timestamps aren't reliably comparable to journald's real
epoch time, so pretending otherwise would be a fabricated precision.

**Verified end-to-end on real Linux** against a genuine systemd +
journald container (`jrei/systemd-ubuntu`, real `systemd-journald.service`
unit): `sher timeline` correctly merged real journal messages ("Journal
started", "Runtime Journal is 8.0M...") with the process's own recorded
`Started` event in the right chronological order, in both human and
`--json` output. The kernel-log section's output was itself a live
demonstration of the documented "coincidental substring match" caveat —
docker networking lines matched via the pid number appearing
incidentally, exactly the false-positive risk the doc comment warns
about, confirming the caveat is accurate rather than theoretical.

## Phase 6 — SHER Kernel adapter

A second `TelemetryAdapter` implementation (`SherKernelAdapter`) consuming
native SHER Kernel process telemetry once it exists, dropped in alongside
`LinuxAdapter` without changing `sher-pe-intelligence`,
`sher-pe-investigation`, the CLI, or the Phase-1 GUI.

## Phase 7 — AI interpretation layer (optional, opt-in)

An LLM-backed layer that turns `Finding`/`Evidence` into richer
natural-language narrative — explicitly *on top of* the deterministic
evidence engine, never replacing it, preserving the
Observed/Correlated/Likely/Unknown distinctions. Only viable once Phase 0's
evidence model has been validated against real-world findings.

## Phase 8 — Packaging & multi-distro hardening

`.deb`/`.rpm`/AUR packaging, a background daemon mode with persistent
(SQLite or similar) history for longer look-back windows and crash
post-mortems, and validated testing across Ubuntu, Fedora, Debian, and Arch.

## Phase 9 — Quick wins from a PyQt6 rebuild spec review

A separate, much narrower PyQt6-based "SHER-Process-Explorer" spec was
reviewed against this project for ideas worth folding in — this project's
scope remains the larger of the two, so good ideas from that spec land here
as additions, not a rewrite. Gaps identified: system-wide overview
(memory/swap/load/uptime/kernel — this project previously reported
per-process data only), process control (kill/signal with confirmation),
export/diagnostic reports, process groups/sessions, GUI table/graph views,
config persistence, keyboard shortcuts/context menus, FD limits, and env
vars. Places this project already exceeds that spec (e.g. the
evidence-typed `Confidence` system) are left as-is.

- System-wide overview (`SystemOverview`: `/proc/meminfo`, `/proc/loadavg`,
  `/proc/uptime`, `/proc/version`, process count) ✅ — `sher system` (CLI),
  a persistent status line in the GUI's top bar, and
  `ProcessIntelligence::system_overview()` for both to share.
- Process control (kill/signal with confirmation) ✅ — real `kill(2)` via
  `nix::sys::signal` (`TelemetryAdapter::send_signal`), `sher kill <pid>
  [--signal term|kill|hup|int|quit|usr1|usr2|stop|cont] [--yes] [--json]`
  (CLI), and Terminate/Kill buttons with an inline confirm/cancel step in
  the GUI's Overview tab. Confirmation is required by default in both —
  the CLI prompts interactively unless `--yes` is passed, and the GUI
  never calls `send_signal` until the user clicks "Confirm." Verified
  end-to-end on real Linux: `SIGTERM` and `SIGKILL` both actually
  terminate a real process, a nonexistent pid returns a typed
  `NotFound` error (not a crash), and declining the CLI's confirmation
  prompt leaves the process running. That validation caught a real,
  pre-existing bug unrelated to this feature: the workspace `Cargo.toml`'s
  `nix` feature list (`["sched", "feature"]`) had never actually enabled
  `nix::unistd::sysconf` correctly — it happened to build on macOS only
  because that call site is Linux-`cfg`-gated and had never been compiled
  for real until this Linux container run. Fixed to `["sched", "signal",
  "user"]`.
- Export snapshots + diagnostic reports ✅ — `DiagnosticReport`
  (`sher-pe-model`) bundles a process's full detail (snapshot, family
  rollup, threads, files, connections, cgroup, namespaces, security,
  systemd unit, container, scheduler stats, disk I/O, timeline, journal
  entries, kernel-log correlation), every "why" finding, and the
  system-wide overview into one JSON document. Assembled by
  `sher_pe_investigation::diagnostic_report` (lives there, not on
  `ProcessIntelligence`, since it needs `why_*`'s `Finding`s and
  `sher-pe-intelligence` can't depend on `sher-pe-investigation` without a
  cycle). Exposed as `sher export <pid> [--output <path>]` (stdout by
  default) and an "Export diagnostic report" button in the GUI's Overview
  tab (writes `sher-report-<pid>.json` to the working directory — no
  native file-dialog dependency this pass). Verified end-to-end on real
  Linux: exported JSON for a real process correctly contains its process
  detail, 4 findings, and the live system process count; a nonexistent
  pid returns a typed not-found error, not an empty or partial report.

### Note on validation environment

All real-Linux validation this project relies on (privileged Docker
containers) remains the practical path for now. `~/tinybridge` (a sibling
project — a macOS-native Linux VM runtime via Apple's
Virtualization.framework) was tried as a lighter-weight alternative on
2026-08-28: it built and its hypervisor lifecycle worked (`Running` state,
real DHCP-assigned guest IP), but the guest kernel never produced any
serial console output over a 60s window, so no shell was ever reachable
inside it — a real, currently-unresolved TinyBridge-side blocker (see its
own README for the concrete AMFI-signature finding from that session), not
something fixable from this project's side. Revisit once TinyBridge's
guest boot is confirmed working.
