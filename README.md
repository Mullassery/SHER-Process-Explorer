# SHER Process Explorer

[![CI](https://github.com/Mullassery/SHER-Process-Explorer/actions/workflows/ci.yml/badge.svg)](https://github.com/Mullassery/SHER-Process-Explorer/actions/workflows/ci.yml)

Makes Linux's process-level reality *understandable*. Instead of forcing a
user to manually combine `top`/`ps`/`lsof`/`ss`/`strace`/`perf`/`journalctl`
and stitch the story together by hand, SHER Process Explorer answers "what is
this process doing, why, and what should I look at next" — with evidence
pointing at the exact raw source for every claim it makes.

Part of the same personal ecosystem as [Aurora](https://github.com/Mullassery/aurora)
(look), Himalayas (feel), [SHER Kernel](https://github.com/Mullassery/SHER-KERNEL)
(work differently), and TinyBridge (run safer).

## Use cases

- **Figuring out why a process is behaving badly** without manually
  combining `top`/`ps`/`lsof`/`ss`/`strace`/`perf`/`journalctl` — `sher why
  <pid>` produces evidence-backed findings, not a raw dump.
- **Real syscall/stack tracing** — `sher trace <pid>` (via `strace`) and
  `sher profile <pid>` (via `perf`) for a live process, not a mocked or
  `Unsupported`-stub command.
- **Reverse lookup from a symptom** — "who has this file/port open" via
  `sher-pe-intelligence`'s `who_has_file`/`who_has_port`, instead of
  starting from a pid you don't have yet.
- **Long-term history** — `sherd` (the background daemon) samples on an
  interval into a persistent SQLite store, so `sher history <pid>` can
  answer "what was this process doing an hour ago."
- **Not yet a good fit for:** SHER Kernel telemetry integration or an
  AI-narrative layer over findings — both explicitly not started (Phase 6/7
  in `ROADMAP.md`).

## What's here

172 Rust tests (`cargo test --workspace`), CI green. Phases 0 through 5 and
Phase 8 are shipped (✅ in `ROADMAP.md`); Phase 6 (SHER Kernel adapter) and
Phase 7 (optional AI narrative layer) haven't been started; Phases 9/10 are
living "ideas adopted incrementally" phases, not one-shot deliverables — see
`ROADMAP.md` for the exact per-item status.

- **Hand-rolled `/proc` parsing** (`sher-pe-telemetry`) — no external
  procfs-wrapper dependency, fixture-tested so the parser logic runs on
  macOS too even though the adapter itself is Linux-only. Includes real
  `strace`/`perf`/`bpftrace`-backed syscall tracing and stack profiling
  (Phase 3) — `sher trace`/`sher profile` are real commands, not stubs.
- **Process intelligence** (`sher-pe-intelligence`) — process tree, family
  rollups, CPU%-over-time, a timeline of started/exited/grew/connected
  events, containers/namespaces as first-class objects (Phase 4), and
  reverse lookup (who-has-file/who-has-port, Phase 10).
- **A deterministic, rule-based "why" investigation engine**
  (`sher-pe-investigation`) producing `Finding`s backed by `Evidence` —
  structurally unable to claim more certainty than the data supports (see
  `Confidence::{Observed,Correlated,Likely,Unknown}`).
- **Log correlation & crash timeline** (Phase 5).
- **`sherd`** (`sher-pe-daemon`) — a background daemon sampling the process
  table on an interval, persisting to SQLite via **`sher-pe-history`**, so
  `sher history <pid>` isn't bounded by `sher-pe-intelligence`'s in-memory,
  capacity-bounded history (120 ticks / 1000 events, gone once the process
  exits).
- **Packaging** (Phase 8) — real `.deb` (`cargo-deb`) and `.rpm`
  (`cargo-generate-rpm`) packages, plus an AUR `PKGBUILD`
  (`packaging/aur/`), each verified end-to-end against real Ubuntu/Fedora/
  Arch containers — see [Install](#install) below.
- A `sher` CLI (`sher-pe-cli`).
- `sher-gui` (`sher-pe-gui`), an `egui`/`eframe` desktop app calling the
  *exact same* `sher-pe-intelligence`/`sher-pe-investigation` APIs the CLI
  uses — a process tree with search/collapse, tabbed detail per process,
  and `Why?` buttons wired straight into the investigation engine. No
  separate logic lives here, only presentation.

See `ARCHITECTURE.md` for the full crate-by-crate design and `ROADMAP.md` for
the phased plan and exact per-item status beyond this.

## Not yet started

Phase 6 (a `SherKernelAdapter` consuming native SHER Kernel telemetry once
it exists — blocked on SHER Kernel itself shipping that) and Phase 7 (an
optional, opt-in LLM narrative layer over `Finding`/`Evidence`, explicitly
never replacing the deterministic evidence engine). Neither has any code
yet — see `ROADMAP.md` for the full description of each.

## Install

Packages are built and verified (Phase 8: `.deb`, `.rpm`, an AUR
`PKGBUILD`) but not yet published anywhere (no tagged GitHub release, no
distro repo) — build from source for now.

## Building

The CLI runs on Linux only (`main()` checks `cfg!(target_os = "linux")` and
exits with a clear error elsewhere); the GUI still opens on any OS and
surfaces the same failure as an in-window banner instead. Parser and model
unit tests are fixture-based and run on any OS:

```sh
cargo build --workspace
cargo test --workspace
```

## Docs

- `ARCHITECTURE.md` — full crate-by-crate design, dependency diagram
  (including the reserved, unbuilt `SherKernelAdapter` seam).
- `ROADMAP.md` — the detailed, phase-by-phase build record and how each
  phase was validated.
- `ROADMAP_HONEST.md` — a blunt status/technical-debt audit supplement to
  `ROADMAP.md`: what's been independently re-verified, what hasn't, and
  concrete debt findings by file/line.
- `CLAUDE.md` — the architectural philosophy and non-negotiables (no fake
  stubs, evidence not guesses, degrade never panic) for anyone (human or
  AI) extending this codebase.
- `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md`.

## Contributing

See `CONTRIBUTING.md` for the development workflow, required checks
(`cargo build`/`test`/`clippy`/`fmt`), and this project's architectural
rules. This is a single-maintainer project (see `SECURITY.md`) — review
happens on a best-effort basis, not a fixed schedule.

## License

Apache License 2.0 — see `LICENSE`. Copyright © 2026 SHER.
