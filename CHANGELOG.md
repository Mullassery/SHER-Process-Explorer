# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

**There has been no tagged release yet** — no git tag, no published crate,
no published `.deb`/`.rpm`/AUR package (see README.md "Install"). Everything
below is `[Unreleased]`, tracked against `main`. `Cargo.toml`'s workspace
version has stayed at `0.1.0` throughout.

For the detailed, phase-by-phase account of what was built, in what order,
and how each phase was validated end-to-end on real Linux, see
`ROADMAP.md` — that document is the source of truth; this file is a flat
summary for people who just want the shape of what's shipped.

## [Unreleased]

### Added

- Core engine: `sher-pe-model` (data types), `sher-pe-telemetry`
  (hand-rolled `/proc` parsing behind a `TelemetryAdapter` trait,
  `LinuxAdapter` implementation), `sher-pe-intelligence` (process tree,
  family rollups, history, timeline), `sher-pe-investigation` (deterministic
  evidence-based "why" engine), and the `sher` CLI (`sher-pe-cli`).
- `sher-gui` (`sher-pe-gui`), an `egui`/`eframe` desktop app on the same
  intelligence/investigation APIs as the CLI.
- Deeper CPU/thread tracing: `sher trace` (strace), `sher profile` (perf),
  `sher deep-trace` (bpftrace, gated behind `--i-accept-the-overhead`).
- Containers/namespaces as first-class objects (Docker/Podman enrichment,
  containerd detection).
- Log correlation and crash timeline (`sher timeline`, real journald + best-
  effort kernel-log correlation).
- Packaging: `.deb` (cargo-deb), `.rpm` (cargo-generate-rpm), an AUR
  `PKGBUILD`, and a background daemon (`sherd`, `sher-pe-daemon`) with
  persistent SQLite history (`sher-pe-history`) for long-look-back and
  crash post-mortems. Validated end-to-end on Ubuntu, Fedora, Debian, and
  Arch containers.
- System-wide overview (`sher system`), process control (`sher kill` with
  confirmation), diagnostic export (`sher export`), process groups/
  sessions, FD limits, and environment variables — a batch of gaps
  identified against a separate PyQt6 rebuild spec review.
- Reverse lookup (`sher who-has`) and mapped-library listing, from a
  structured comparison against MacTop/Process Explorer/htop/lsof/dtrace/
  Instruments/Procmon.

### Known gaps (not started)

- Phase 6: a `SherKernelAdapter` (second `TelemetryAdapter` implementation
  for native SHER Kernel telemetry) — blocked on SHER Kernel shipping that
  telemetry; no code exists for this yet.
- Phase 7: an optional, opt-in LLM narrative layer over `Finding`/
  `Evidence` — no code exists for this yet.
- See `ROADMAP_HONEST.md` for the full honest-status and technical-debt
  breakdown, including items from Phase 9/10 still marked "pending."
