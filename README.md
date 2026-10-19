# SHER Process Explorer

`ps aux` tells you a process exists. SHER Process Explorer tells you why it is misbehaving — with evidence pointing at the exact raw source for every claim.

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/Mullassery/SHER-Process-Explorer/actions/workflows/ci.yml/badge.svg)](https://github.com/Mullassery/SHER-Process-Explorer/actions/workflows/ci.yml)

## What it is

SHER Process Explorer is an evidence-based Linux process investigation tool. Instead of forcing you to manually combine `top`/`ps`/`lsof`/`ss`/`strace`/`perf`/`journalctl` and stitch the story together by hand, it answers "what is this process doing, why, and what should I look at next" — with every finding backed by evidence that points at the exact raw source it came from.

It is a Rust workspace of eight crates (about 172 tests, CI green) with a CLI (`sher`), a desktop GUI (`sher-gui`, using egui/eframe), and a background sampling daemon (`sherd`) that all call the same `sher-pe-intelligence`/`sher-pe-investigation` APIs. It runs standalone against any Linux's real `/proc` and has no Cargo dependency on the rest of the SHER family.

## Features / Highlights

- **Hand-rolled `/proc` parsing** (`sher-pe-telemetry`) — no external procfs-wrapper dependency, fixture-tested so the parser logic runs on macOS too even though the adapter itself is Linux-only.
- **Real syscall/stack tracing** — `sher trace <pid>` (via `strace`) and `sher profile <pid>` (via `perf`/`bpftrace`), not mocked or `Unsupported`-stub commands.
- **Process intelligence** (`sher-pe-intelligence`) — process tree, family rollups, CPU%-over-time, a started/exited/grew/connected timeline, containers/namespaces as first-class objects, and reverse lookup (`who_has_file`/`who_has_port`).
- **A deterministic, rule-based "why" engine** (`sher-pe-investigation`) producing `Finding`s backed by `Evidence`, structurally unable to claim more certainty than the data supports (`Confidence::{Observed,Correlated,Likely,Unknown}`).
- **Log correlation and crash timeline.**
- **Long-term history** — `sherd` samples the process table on an interval and persists to SQLite via `sher-pe-history`, so `sher history <pid>` can answer "what was this process doing an hour ago" instead of being bounded by in-memory history.
- **One API, many consumers** — `sher` and `sher-gui` never touch telemetry internals; both call `sher-pe-intelligence`/`sher-pe-investigation`, so any feature reachable only from the CLI is treated as a layering bug.
- **Packaging** — real `.deb` (`cargo-deb`), `.rpm` (`cargo-generate-rpm`), and AUR `PKGBUILD`, each verified against real Ubuntu/Fedora/Arch containers.

## Who it's for / Use cases

- **Figuring out why a process is behaving badly** without manually combining `top`/`ps`/`lsof`/`ss`/`strace`/`perf`/`journalctl` — `sher why <pid>` produces evidence-backed findings, not a raw dump.
- **Real syscall/stack tracing** of a live process via `sher trace <pid>` and `sher profile <pid>`.
- **Reverse lookup from a symptom** — "who has this file/port open" via `who_has_file`/`who_has_port`, instead of starting from a pid you do not have yet.
- **Long-term history** — a persistent SQLite store answers "what was this process doing an hour ago."

## What it is not

- **Not a cross-platform tool.** The CLI runs on Linux only (`main()` checks `cfg!(target_os = "linux")` and exits with a clear error elsewhere); the GUI opens on any OS but surfaces the same failure as an in-window banner. Parser and model unit tests are fixture-based and run anywhere.
- **Not a SHER Kernel integration yet.** Phase 6 (`SherKernelAdapter`, consuming native SHER Kernel telemetry once it exists) is not started — blocked on SHER Kernel shipping that.
- **No AI narrative layer yet.** Phase 7 (an optional, opt-in LLM layer over `Finding`/`Evidence`) is not started; it is explicitly intended never to replace the deterministic evidence engine.
- **Not a real-time kernel observability platform.** Some instrumented paths (live `/proc`, `perf`/`strace`/`bpftrace`/`journalctl`, signal delivery) are Linux-gated and validated in privileged containers, not on macOS.
- **Not published anywhere.** The `.deb`/`.rpm`/AUR packages are built and verified but there is no tagged GitHub release or distro repo yet — build from source for now.
- **Known tooling limitations:** `cargo audit`/`cargo deny` are wired into CI but have not been observed to execute (no network route to the advisory DB in sandboxes tested so far), and one transitive dependency (`ttf-parser`, RUSTSEC-2026-0192) is unmaintained with no live vulnerability and no upstream fix yet.

## Project status

- **Shipped (Phases 0–5, 8):** `/proc` telemetry, process intelligence, the evidence-based "why" engine, log correlation/crash timeline, persistence daemon, and packaging.
- **Not started:** Phase 6 (SHER Kernel adapter) and Phase 7 (optional AI narrative layer).
- **Ongoing:** Phases 9/10 are living "ideas adopted incrementally" phases rather than one-shot deliverables — see [`ROADMAP.md`](ROADMAP.md) for the exact per-item status.
- **Tests:** about 172 Rust tests (`cargo test --workspace`); CI green.

## Installation

Packages (`.deb`, `.rpm`, AUR `PKGBUILD`) are built and verified but not yet published anywhere, so build from source for now:

```bash
git clone https://github.com/Mullassery/SHER-Process-Explorer.git
cd SHER-Process-Explorer
cargo build --workspace
```

## Quick start

```bash
# Explain why a process is misbehaving, with evidence
cargo run -p sher-pe-cli -- why <pid>

# Trace syscalls / profile stacks for a live process
cargo run -p sher-pe-cli -- trace <pid>
cargo run -p sher-pe-cli -- profile <pid>

# Ask what a process was doing earlier (requires the daemon to have sampled)
cargo run -p sher-pe-cli -- history <pid>

# Launch the desktop GUI
cargo run -p sher-pe-gui
```

## Usage

The CLI (`sher`) and GUI (`sher-gui`) present the same underlying APIs; `sherd` (`sher-pe-daemon`) samples on an interval and persists history. Build and test:

```bash
cargo build --workspace
cargo test --workspace
```

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the crate-by-crate design and dependency diagram (including the reserved, unbuilt `SherKernelAdapter` seam).

## Documentation

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — full crate-by-crate design and dependency diagram
- [`ROADMAP.md`](ROADMAP.md) — the phase-by-phase build record and how each phase was validated
- [`ROADMAP_HONEST.md`](ROADMAP_HONEST.md) — blunt status/technical-debt audit by file/line
- [`CLAUDE.md`](CLAUDE.md) — architectural philosophy and non-negotiables
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — development workflow and required checks
- [`SECURITY.md`](SECURITY.md) — how to report a vulnerability
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)
- [`CHANGELOG.md`](CHANGELOG.md)

## Known issues and deferred work

**Blocked / failed:**
- Publish .deb/.rpm/AUR; non-root mode; JSON/OTEL/TUI.

**Rejected / deferred:**
- AI narrative layer now; deterministic evidence is the product.

Full shipped/blocked/rejected detail: [`QUEUE_STATUS.md`](QUEUE_STATUS.md).

## Queue status

Shipped, blocked/failed, and rejected work for this repository is documented in
[`QUEUE_STATUS.md`](QUEUE_STATUS.md).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the development workflow, required checks (`cargo build`/`test`/`clippy`/`fmt`), and this project's architectural rules. This is a single-maintainer project (see [`SECURITY.md`](SECURITY.md)) — review happens on a best-effort basis, not a fixed schedule.

## Part of the SHER OS family

SHER-Process-Explorer is part of the SHER OS family — an AI-native operating system built from scratch in Rust. The subsystems are designed to work together as a coherent OS stack.

| Tool | Role | What it does |
|---|---|---|
| [SHER-KERNEL](https://github.com/Mullassery/SHER-KERNEL) | Kernel core | Core kernel scaffolding: object model, scheduling, memory, driver-lifecycle concepts, and a Linux Kernel Interface (LKI) compatibility layer. |
| [SHER-Graphics](https://github.com/Mullassery/SHER-Graphics) | Graphics/GPU | GPU abstraction and rendering — software simulation plus a real, working Vulkan/MoltenVK backend. |
| [SHER-Display](https://github.com/Mullassery/SHER-Display) | Display/compositor | Display server, compositor, and window management. |
| [SHER-INPUT](https://github.com/Mullassery/SHER-INPUT) | Input | Canonical, backend-independent input event stream — real evdev on Linux, simulated backend for hardware-free testing. |
| [SHER-Aurora](https://github.com/Mullassery/SHER-Aurora) | Design system | GNOME-style design system — tokens, typography, motion, and an automated WCAG contrast audit. |
| [SHER-Process-Explorer](https://github.com/Mullassery/SHER-Process-Explorer) | Observability | **This project** — evidence-based Linux process investigation tool: /proc telemetry, bpftrace integration, daemon + CLI + desktop UI. |

Each works standalone; they're complementary by design. [Browse all projects →](https://github.com/Mullassery?tab=repositories)

## License

Apache License 2.0 — see [`LICENSE`](LICENSE). Copyright © 2026 SHER.
