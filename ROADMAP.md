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

## Phase 1 — Desktop UI

A GUI consuming the *same* `sher-pe-intelligence` / `sher-pe-investigation`
APIs the CLI uses — no new logic, just presentation: hierarchical process
explorer, drill-down detail tabs, memory/CPU breakdown visuals, `[Why?]`
buttons wired to the existing investigation engine. Toolkit choice (GTK4/
libadwaita to plug into Aurora's design system vs. Tauri/egui) deferred to
when this phase starts.

## Phase 2 — Deeper CPU/thread intelligence (Level 2–3 tracing)

Short targeted sampling and explicit profiling: stack sampling for "hot
function" views, per-thread syscall breakdown, scheduler latency.
Implemented as new `TelemetryAdapter` methods behind the existing `Tier`
enum — additive, not a rewrite.

## Phase 3 — eBPF / perf (Level 4 deep tracing)

Opt-in, explicitly overhead-warned deep tracing: syscall tracing, I/O
tracing, network tracing via eBPF and `perf`. Gated behind capability checks
(`CAP_SYS_ADMIN`/`perf_event_paranoid`) with clear user-facing warnings
before enabling.

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
