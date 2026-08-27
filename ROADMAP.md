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

## Phase 4 — Containers & namespaces as first-class objects

Docker/Podman/containerd awareness layered on top of the cgroup/namespace
data Phase 0 already collects — mapping container ↔ host process ↔ cgroup ↔
namespace without requiring the user to understand Linux internals.

## Phase 5 — Log correlation & crash timeline UI

Full journald + kernel-log + resource-metric timeline correlation with a
visual timeline, built on the `TimelineEvent` history Phase 0 already
accumulates plus richer `dmesg`/journald ingestion.

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
