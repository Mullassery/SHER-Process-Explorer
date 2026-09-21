## What does this change?

<!-- One or two sentences. Link an issue if there is one. -->

## Why?

<!-- What couldn't you do before this change? -->

## Checklist

- [ ] `cargo build --workspace` passes
- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo fmt --all -- --check` passes
- [ ] New behavior has a test (fixture-based for `sher-pe-telemetry` parsers,
      `MockTelemetryAdapter`-based for `sher-pe-intelligence`/
      `sher-pe-investigation`) — or this PR explains why one isn't practical
- [ ] If this touches a real shell-out, real signal, or anything else that
      genuinely can't be exercised on macOS: validated on real Linux, and
      that validation is described below
- [ ] `README.md` / `ARCHITECTURE.md` / `ROADMAP.md` updated if this PR
      changes a claim any of them currently make
- [ ] `CHANGELOG.md`'s `[Unreleased]` section updated for any user-visible
      change

## Real-Linux validation (if applicable)

<!--
If this PR touches /proc parsing, signals, perf/strace/bpftrace,
docker/podman/journalctl shell-outs, or anything else Linux-only:
describe what you actually ran and against what (a container, a VM, bare
metal) and what you observed. "Should work" is not validation — see this
project's own ROADMAP.md for the bar ("Verified end-to-end on real Linux")
it holds itself to.
-->
