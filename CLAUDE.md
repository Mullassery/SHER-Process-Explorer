# CLAUDE.md — SHER Process Explorer

## Philosophy

A process manager should answer *why*, not just *what*. `ps aux` tells you a
process exists and its RSS; it does not tell you whether that RSS is a memory
leak, why a process is pinned at 100% CPU, or what killed it three minutes
ago. SHER Process Explorer's job is to close that gap with **evidence**, not
guesses: every `Finding` the investigation engine produces carries a
`Vec<Evidence>` pointing at the exact raw source (file path + raw value) that
justified it, and a `Confidence` that is never rounded up past what the data
actually supports.

This is also a deliberate architectural exercise in **one API, many
consumers**: `sher-pe-cli` today, a future desktop GUI in Phase 1, never
touch telemetry internals directly. They both call `sher-pe-intelligence` /
`sher-pe-investigation`. If a feature can only be reached from the CLI, that
is a bug in the layering, not a CLI feature.

## No fake stubs

Anything not implemented this pass says so honestly. `Tier::ShortSample` /
`Profile` / `DeepTrace` return `TelemetryError::Unsupported`. `sher trace` /
`sher profile` print "requires Level 3/4 tracing, not yet built" and exit
non-zero. Nothing pretends to work by returning empty/zero data where real
data was expected — a missing capability is a typed error, not a silent
default.

## Cross-repo boundary

SHER Process Explorer must **not** require SHER Kernel to build or run this
pass — it works standalone against any Linux's real `/proc`. The
`TelemetryAdapter` trait is the seam for a future `SherKernelAdapter`
(Phase 6): a second implementation dropped in alongside `LinuxAdapter`
without touching `sher-pe-intelligence`, `sher-pe-investigation`, the CLI, or
the Phase-1 GUI. Mirrors the `HardwareDriver` trait + `Box<dyn Trait>`
registry pattern already used in `SHER-Kernel/crates/hal/src/lib.rs` — same
discipline as SHER-Display's rule of never instantiating a second owner of
state another subsystem already owns, applied here as "never build a second
adapter trait when this one already has the seam."

## Workspace layout

```
crates/
├── sher-pe-model/           # pure data types, no I/O
├── sher-pe-telemetry/       # TelemetryAdapter trait + Linux implementation
├── sher-pe-intelligence/    # tree, rollups, history, timeline
├── sher-pe-investigation/   # rule-based "why" evidence engine
├── sher-pe-cli/             # `sher` binary
└── sher-pe-gui/             # `sher-gui` binary (egui/eframe) — same APIs, different presentation
```

Dependency direction is strictly top-to-bottom: `sher-pe-cli` and
`sher-pe-gui` each depend on `sher-pe-intelligence` + `sher-pe-investigation`,
which depend on `sher-pe-telemetry`, which depends on `sher-pe-model`.
Nothing depends upward, and the CLI and GUI never depend on each other.

## Testing discipline

- `sher-pe-model`: plain unit tests (serde round-trips, tree/rollup math).
- `sher-pe-telemetry` parsers: fixture-based against synthetic
  `/proc`-shaped directories under `tests/fixtures/proc/`. Parsers take a
  `root: &Path` specifically so tests never need real `/proc` or root — this
  is also what makes the parser layer testable on macOS despite the adapter
  being Linux-only.
- Real-syscall paths (`sched_getaffinity`, live `/proc` reads) are
  `#[cfg(target_os = "linux")]`-gated and validated separately (OrbStack
  Ubuntu VM, not this dev machine).
- `sher-pe-intelligence` / `sher-pe-investigation`: tested against a
  hand-built `MockTelemetryAdapter` feeding multi-tick synthetic snapshots,
  so growth-detection thresholds are deterministic and don't touch real
  `/proc`.
- `sher-pe-gui`: the one piece of real logic (`treeview::flatten_tree` —
  expand/collapse + search-filter behavior) is kept free of any `egui`
  dependency and unit-tested directly, the same way `sher-pe-model::tree`
  is. Actual rendering isn't unit-testable, so it's verified by running the
  compiled binary against a real X server (Xvfb) with real `/proc` data and
  visually inspecting a screenshot — not just "it compiles."

## Degrade, never panic

Missing `smaps_rollup` (older kernels), cgroup v1 vs v2, permission errors on
another user's `/proc/[pid]/*` — all of these are expected, not exceptional.
Fall back (e.g. to `statm`/`status`) or surface a typed `PermissionDenied`
per-field. A single unreadable field must never crash a whole snapshot.

## PID reuse

History is keyed by `(Pid, start_time)`, never bare `Pid` — the kernel reuses
PIDs, and misattributing a new process's history to a dead one with the same
PID would silently corrupt every growth-rate and timeline calculation built
on top.
