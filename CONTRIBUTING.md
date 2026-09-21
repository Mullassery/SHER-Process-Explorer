# Contributing to SHER Process Explorer

This is a personal project, developed by one person, without a maintainer
team or SLA (see `SECURITY.md`). External contributions are welcome, but
review and merge happen on a best-effort basis, not a fixed schedule.

## Before you start

For anything beyond a small fix (a new feature, a change to the
`TelemetryAdapter` trait, a new "why" rule), open an issue first describing
what you want to do and why. This project has a deliberate architecture
(see `ARCHITECTURE.md` and `CLAUDE.md`) and a phased roadmap (`ROADMAP.md`,
`ROADMAP_HONEST.md`) — an issue first avoids wasted work on something that
doesn't fit either.

## Development environment

- Rust stable (`rustup default stable`), `clippy` and `rustfmt` components.
- **The CLI and daemon binaries are Linux-only.** `sher` and `sherd` check
  `cfg!(target_os = "linux")` at startup and refuse to run elsewhere with a
  clear error — this is intentional, not a bug to fix. `sher-pe-telemetry`'s
  parser logic is fixture-tested and runs fine on macOS; anything that
  touches real `/proc`, real signals, or shells out to `perf`/`strace`/
  `bpftrace`/`journalctl`/`docker`/`podman` is `#[cfg(target_os = "linux")]`
  and can only be exercised on real Linux (a container or VM works fine —
  see `ROADMAP.md` Phase 8 for exactly what was validated where).
- `sher-pe-gui` (`sher-gui` binary) opens on any OS and shows a banner
  instead of refusing to run, so UI work doesn't require a Linux machine.

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

All four are required by CI (`.github/workflows/ci.yml`) and must pass
before a PR can merge.

## Code conventions

- **Dependency direction is one-way**: `sher-pe-model` → `sher-pe-telemetry`
  → `sher-pe-intelligence` → `sher-pe-investigation`; `sher-pe-cli`/
  `sher-pe-gui`/`sher-pe-daemon` sit on top and never depend on each other.
  See `ARCHITECTURE.md` before adding a new cross-crate dependency.
- **No fake stubs.** If something isn't implemented, it returns a typed
  error (e.g. `TelemetryError::Unsupported`) or is documented as not done —
  never a silently empty/zero result presented as real data. See `CLAUDE.md`
  ("No fake stubs").
- **Evidence, not guesses.** Anything added to the investigation engine
  (`sher-pe-investigation`) must produce a `Finding` backed by `Evidence`
  pointing at the exact raw source, with a `Confidence` that never claims
  more certainty than the data supports.
- **Degrade, never panic**, on missing files, permission errors, or
  cgroup v1-vs-v2 differences — fall back or surface a typed error per
  field, don't crash the whole snapshot.
- Parsers in `sher-pe-telemetry` take a `root: &Path` (defaulting to
  `/proc`) specifically so they can be pointed at a fixture directory under
  `tests/fixtures/proc/` in tests — new parsers should follow this pattern
  so they stay testable on any OS.

## Tests

- New parser logic in `sher-pe-telemetry`: add a fixture under
  `tests/fixtures/proc/` and a unit test reading from it — don't require
  real Linux for logic that doesn't need it.
- New `sher-pe-intelligence`/`sher-pe-investigation` behavior: use
  `sher_pe_telemetry::testing::MockTelemetryAdapter` (already used
  throughout both crates' test suites) rather than touching real `/proc`.
- Anything that genuinely can only be verified against real Linux (a new
  shell-out, a new signal, a new privileged operation) should say so in the
  PR description — end-to-end validation against real Linux is expected for
  that kind of change (see `ROADMAP.md`'s per-phase "Verified end-to-end on
  real Linux" sections for the bar this project holds itself to), and the
  maintainer may ask for it if it's missing.

## Commit / PR style

- Keep commits focused; a large PR mixing an unrelated refactor with a
  feature is harder to review and more likely to be asked to split.
- Update `CHANGELOG.md` under `[Unreleased]` for any user-visible change.
- If your change affects a claim made in `README.md`, `ARCHITECTURE.md`, or
  `ROADMAP.md`, update those in the same PR — this project treats doc/code
  drift as a bug (see `ROADMAP_HONEST.md`'s technical debt section for
  where that has already happened once).

## Reporting bugs / requesting features

Use the GitHub issue templates (`.github/ISSUE_TEMPLATE/`). For security
issues, see `SECURITY.md` instead of opening a public issue.
