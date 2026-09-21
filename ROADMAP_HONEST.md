# ROADMAP_HONEST.md — status audit supplement

This is not a replacement for `ROADMAP.md` — that document is the detailed,
phase-by-phase record and remains the source of truth for what each phase
actually did and how it was validated. This file is a blunt, dated audit
supplement: what was independently re-verified during this pass (2026-09),
what technical debt exists, and what remains genuinely incomplete, stated
without hedge language.

## Independently re-verified this pass

All of the following were actually run, not assumed from prior commit
messages or `ROADMAP.md`'s own claims.

- **`cargo fmt --all -- --check`** — clean, no diff.
- **`cargo clippy --workspace --all-targets -- -D warnings`** — zero
  warnings across all 8 crates.
- **`cargo test --workspace` on macOS (this dev machine)** — **172 tests
  passed, 0 failed.** Breakdown: `sher-pe-model` 40, `sher-pe-telemetry` 86,
  `sher-pe-intelligence` 14, `sher-pe-investigation` 17, `sher-pe-history` 6,
  `sher-pe-gui` 9, `sher-pe-cli` 0, `sher-pe-daemon` 0 (the last two have no
  unit tests of their own — thin binaries over already-tested library
  crates). This matches the README's "172 Rust tests" claim exactly. Zero
  doc-tests exist in any crate (not a failure, just zero coverage from that
  mechanism).
- **`cargo test --workspace --exclude sher-pe-gui` on real Linux** — a
  Docker container (`rust:1-slim`, real kernel `6.12.76-linuxkit`, not a
  mock) was available in this sandbox with real network egress, so this
  pass went further than expected: **163 of the 172 tests (everything
  except the GUI's 9) were re-run and passed on genuine Linux**, not just
  fixture-emulated on macOS.
- **`sher` CLI, for real, against real `/proc`, on real Linux** (same
  container): `sher --help`, `sher ps` (listed real live pids/RSS/state),
  `sher system` (real uptime/kernel version/load average/memory), `sher
  inspect 1` (real pgid/sid/uid/cmdline), and `sher why 1 memory` (produced
  a real `Finding` with real evidence: `rss=3063808 anon=274432
  file=2789376...`) all worked correctly against the container's actual
  process table.
- **`sher`/`sherd` refuse to run on non-Linux with a clear message, not a
  crash or silent no-op** — verified on macOS: `sher ps` and `sherd --help`
  both printed `"sher[d] reads /proc and only runs on Linux (this binary
  was built for macos)"` and exited, exactly as README/ARCHITECTURE claim.
- **`actionlint` on `.github/workflows/ci.yml`** — zero findings, both
  before and after this pass's edits.
- **No shell-injection surface**: every `std::process::Command` call site
  in `sher-pe-telemetry` (`strace.rs`, `perf.rs`, `bpftrace.rs`,
  `container.rs`, `journald.rs`, `kernel_log.rs`, `systemd.rs`) uses an
  argument array, never `sh -c "<interpolated string>"` — confirmed by
  grepping the full source tree for `"-c"`/`sh -c` patterns.
- **No secrets/credentials found** in a pattern scan (`api[_-]?key`,
  `secret`, `password`, `token\s*=`) across `.rs`/`.toml`/`.yml` files.
- **`Cargo.lock` is committed** (`git ls-files | grep Cargo.lock` — one
  match), not gitignored, correct for a repo that ships binaries.
- **Two stale license references found and fixed** (pre-existing bug, not
  introduced by this pass): `crates/sher-pe-cli/Cargo.toml`'s
  `[package.metadata.generate-rpm]` block and `packaging/aur/PKGBUILD`'s
  `license=` field both still said `"SHER Free Use & Proprietary Software
  License"` — the pre-Apache-2.0 license name — even though the repo was
  relicensed to Apache-2.0 in commit `d96db58` (2026-09-11). Both fixed to
  `Apache-2.0` in this pass. Nothing else in the repo referenced the old
  license name (checked via full-tree grep).
- **`CLAUDE.md` was stale and has been corrected**: it described the
  workspace as 6 crates (missing `sher-pe-history` and `sher-pe-daemon`,
  both real, shipped in Phase 8), described the GUI as "a future desktop
  GUI in Phase 1" (shipped), and described `sher trace`/`sher profile` as
  unimplemented stubs (both real since Phase 2). Fixed to reflect current
  state; this is exactly the "internal doc self-contradiction" failure
  mode this org's other repos have had.
- **`ARCHITECTURE.md` was incomplete**: it had no section for
  `sher-pe-history` or `sher-pe-daemon` despite both being real, shipped,
  Phase-8 crates with real code and tests. Added sections for both, plus a
  Mermaid dependency diagram (GitHub-renderable) replacing the old ASCII
  arrow diagram, with the reserved-but-not-built `SherKernelAdapter` seam
  shown as an explicitly dashed/unbuilt node so it can't be mistaken for
  shipped code.
- **systemd unit is genuinely hardened**, not just claimed to be:
  `packaging/systemd/sherd.service` was checked directly and has
  `NoNewPrivileges=true`, `ProtectSystem=strict`, a scoped
  `ReadWritePaths=/var/lib/sher`, and a minimal `AmbientCapabilities=
  CAP_SYS_PTRACE` instead of running the whole daemon as root. (An earlier
  draft of `SECURITY.md` in this pass incorrectly claimed this hardening
  was missing — that was wrong and has been corrected before being
  committed.)

## Not re-verified this pass (and why)

- **`perf`/`strace`/`bpftrace`/`docker`/`podman`/`journalctl`-dependent
  behavior** (Phases 2–5, 9's container detection) — re-running these
  needs a *privileged* container with those specific tools installed and,
  for `bpftrace`, a kernel with tracefs/eBPF exposed to the container,
  which is real setup work beyond what a documentation-focused pass
  warrants. Not re-verified; taken on `ROADMAP.md`'s word that Phases 2–5
  did this properly against real tools at the time.
- **`.deb`/`.rpm`/AUR packaging builds** (Phase 8) — not re-run
  (`cargo-deb`/`cargo-generate-rpm`/`makepkg` aren't installed in this
  environment and installing a full multi-distro packaging toolchain
  wasn't warranted for this pass, especially right after finding and
  fixing the stale-license bug in exactly these files — a follow-up pass
  should re-run all three after this pass's Apache-2.0 fix to confirm the
  generated packages now carry the corrected license).
- **`sher-gui` visual/rendering behavior** — not launched (headless
  sandbox); only its 9 unit tests (`treeview::flatten_tree` logic) were
  re-run, on macOS and not separately on Linux. The Xvfb-screenshot-based
  visual verification `ROADMAP.md` describes for Phases 1–4 was not
  repeated.
- **`cargo audit`** — attempted, failed: this sandbox has no network route
  to `github.com` for most operations (confirmed separately via a timed-out
  `gh` call), so the RustSec advisory database couldn't be fetched. A
  dependency-audit CI job (`rustsec/audit-check`) has been added to
  `.github/workflows/ci.yml` in this pass, but its actual pass/fail result
  has never been observed — GitHub's own runners have the network access
  this sandbox doesn't, so the very first real signal from that job will
  come from its first real run on `main` or a PR, not from anything in this
  audit.
- **GitHub-side CI status** (`gh run list`) — attempted, timed out (no
  network). The README's "CI green" claim could not be independently
  confirmed against a live GitHub Actions run in this pass; it was taken on
  faith from the local re-run of the same commands CI runs.

## Technical debt (concrete, file:line)

- **`crates/sher-pe-cli/Cargo.toml:29`** (`[package.metadata.deb]`
  `copyright = "2026, SHER"`) vs. **`LICENSE:189`** (`Copyright 2026 Georgi
  Mullassery`) — the `.deb` copyright holder string and the actual LICENSE
  file's copyright line name different entities ("SHER" the project vs.
  "Georgi Mullassery" the person). Not a legal problem (Apache-2.0 doesn't
  mandate a specific format), just an inconsistency worth aligning. Low
  priority, cosmetic.
- **`crates/sher-pe-telemetry/src/testing.rs`** — `pub mod testing`
  (not `#[cfg(test)]`-gated) exposing `MockTelemetryAdapter` with ~36
  `.unwrap()` calls, compiled into every consumer of `sher-pe-telemetry`
  including the release `sher`/`sherd`/`sher-gui` binaries. This is not a
  bug — it has to be a real (non-cfg-test) public item because
  `sher-pe-intelligence`/`sher-pe-investigation` use it as a
  dev-dependency, and Cargo dev-dependencies don't get the depended
  crate's `#[cfg(test)]` items — but it does mean unwrap-heavy mock code
  ships, unreachable, in the production binary. No exploitability (nothing
  in the CLI/GUI/daemon code paths constructs a `MockTelemetryAdapter`),
  but worth knowing it's there if a future audit tool flags unwrap density
  in `sher-pe-telemetry` without this context.
- **Zero doc-tests** across all 5 library crates (`sher-pe-model`,
  `sher-pe-telemetry`, `sher-pe-intelligence`, `sher-pe-investigation`,
  `sher-pe-history`), despite public APIs like `TelemetryAdapter`,
  `ProcessIntelligence`, and the `why_*` functions being exactly the kind
  of API that benefits from a runnable usage example in its doc comment.
  Not a defect, just uncaptured documentation value.
- **`cargo audit`/`cargo deny` were absent from CI before this pass** (now
  added, unverified — see above). Before this pass, there had never been
  any automated dependency-vulnerability check on this repo, local or CI.
- **No `#![deny(unsafe_code)]` or documented unsafe-code inventory.** A
  quick grep shows `unsafe` blocks exist (e.g. `sher-pe-daemon`'s
  `geteuid()` FFI call, `nix::sched::sched_getaffinity` call sites) — all
  narrowly scoped and commented with `// SAFETY:` where checked in this
  pass, but there's no single doc enumerating every `unsafe` block in the
  workspace for a reviewer to audit at a glance. Not urgent for a project
  this size, but worth a `grep -rn unsafe crates/*/src` pass before any
  future security-focused review.
- **ROADMAP.md's own Phase 10 "pending" items remain pending** (confirmed
  still true, not newly discovered): trend-over-time narrative/sparkline
  query layer, syscall aggregation over `deep_trace` (dtrace-style
  `count()` by syscall), new `TimelineEventKind` variants for CPU
  spikes/syscall bursts, and **GUI signal-picker parity** — the CLI's
  `sher kill` supports 9 named signals, the GUI's Terminate/Kill buttons
  only expose 2, which `ROADMAP.md` itself already correctly flags as
  breaking this project's own "one API, many consumers" architectural
  rule.
- **Phase 6 (`SherKernelAdapter`) and Phase 7 (AI narrative layer): zero
  code exists.** Confirmed via full-tree grep — `SherKernelAdapter` appears
  only in doc comments (`sher-pe-telemetry/src/lib.rs`) describing the
  reserved seam, never as an actual type or module. This is not a gap in
  disguise — both phases are honestly marked not-started in `ROADMAP.md`
  and the README — but stated here plainly per this audit's own rule: no
  code means no code, not "in progress."

## Security-relevant gaps (see `SECURITY.md` for the full writeup)

- No automated dependency vulnerability scanning existed before this pass
  (see above) — now added but unverified.
- `sherd`'s SQLite database aggregates every user's process history
  (command lines, resource usage over time) into one file readable by
  whoever can read `/var/lib/sher/history.db` or
  `~/.local/share/sher/history.db` — inherent to what the daemon is for,
  not a bug, but worth knowing before deploying it on a shared machine.
- No security team, no SLA, no bug bounty — single-maintainer project,
  now stated explicitly in `SECURITY.md` rather than left unstated.

## What's genuinely done vs. not, restated bluntly

- **Done and re-verified this pass**: Phases 0, 1 (GUI, minus fresh visual
  verification), 8 (packaging code exists and was previously validated per
  `ROADMAP.md`, not re-run this pass), plus Phase 9/10's shipped items
  (system overview, kill, export, groups/sessions, FD limits, env vars,
  who-has, mapped files) — all present in source, all covered by the 172
  passing tests, core CLI paths re-run against real `/proc` on real Linux
  in this pass.
- **Done per `ROADMAP.md` but not independently re-verified this pass**:
  Phases 2–5's `perf`/`strace`/`bpftrace`/container/journald integration,
  and the actual `.deb`/`.rpm`/AUR package builds.
- **Not started, zero code, not close to done**: Phase 6
  (`SherKernelAdapter`), Phase 7 (AI narrative layer), and Phase 10's four
  explicitly-pending items listed above.
