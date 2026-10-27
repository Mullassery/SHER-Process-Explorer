# SHER Process Explorer — Systems Design Audit

Audit date: 2026-10-27
Repository: `SHER-Process-Explorer`
Revision observed: commit dated 2026-10-25, working tree clean
License: Apache-2.0

## Overview

SHER Process Explorer is a Linux process-inspection tool that answers not only
what a process is doing, but why. It is a Rust workspace of eight crates with
three binaries: `sher` (CLI), `sher-gui` (egui/eframe desktop UI), and `sherd`
(background sampling daemon). All three consume the same intelligence and
investigation APIs. A separate history crate persists process snapshots and
timeline events to SQLite so `sher history <pid>` can answer questions after a
process has exited.

The project deliberately has no dependency on the rest of the SHER family and
runs directly against Linux `/proc`. It is Linux-only for real telemetry; the
GUI opens elsewhere but surfaces the same platform error, while parser/model
tests use fixtures and run on any platform.

## Architecture

```text
sher / sher-gui / sherd
        |
        +--> sher-pe-investigation ("why" engine)
        |          |
        |          v
        +--> sher-pe-intelligence (tree, rollups, history, timeline)
                   |
                   v
             sher-pe-telemetry (TelemetryAdapter)
                   |
                   v
             linux::LinuxAdapter (hand-rolled /proc parsing)

sherd --> sher-pe-history (SQLite)
all crates --> sher-pe-model (pure data types, no I/O)
```

Layering is explicit in `ARCHITECTURE.md`:

- `sher-pe-model`: pure serializable data types, no I/O, no workspace
  dependencies.
- `sher-pe-telemetry`: `TelemetryAdapter` trait plus a Linux `/proc`
  implementation. `SherKernelAdapter` is a reserved Phase 6 seam, not built.
- `sher-pe-intelligence`: in-memory process tree, CPU/memory rollups,
  capacity-bounded history, timeline, and live pass-through reads for threads,
  connections, and disk I/O.
- `sher-pe-investigation`: deterministic evidence-based "why" queries
  (`why_cpu`, `why_memory`, `why_network`, `why_disk`) that cite evidence.
- `sher-pe-history`: SQLite persistence for daemon-collected snapshots/events.
- `sher-pe-cli`, `sher-pe-gui`, `sher-pe-daemon`: binary layers. The CLI and
  GUI call intelligence and investigation directly; the daemon calls
  intelligence and history.

The daemon samples the process tree every 5 seconds by default. For every
process in the snapshot it writes a JSON row to `snapshots`, then writes recent
timeline events to `timeline_events`. It prunes rows older than 7 days by
default once per hour. It is designed for systemd and does not double-fork or
detach itself.

## Entry Points

- `sher` — `crates/sher-pe-cli` binary. `main()` exits with a clear message on
  non-Linux targets.
- `sher-gui` — `crates/sher-pe-gui` binary. egui/eframe UI; opens on other
  platforms but shows the Linux telemetry failure.
- `sherd` — `crates/sher-pe-daemon` binary. CLI options:
  `--db <path>`, `--interval-secs` (default 5), `--retention-days` (default 7).
  Default database is `/var/lib/sher/history.db` when effective UID is 0,
  otherwise `$HOME/.local/share/sher/history.db`.
- `sher history <pid>` and related subcommands read the SQLite database.

## Dependencies

Workspace version 0.1.0, edition 2021, Apache-2.0.

- `serde` / `serde_json` — model serialization and `--json` output.
- `thiserror` — crate error types.
- `tracing` / `tracing-subscriber` — structured logging.
- `clap` — CLI parsing.
- `nix` — signals, scheduling, user lookup.
- `egui` / `eframe` 0.36 — GUI.
- `rusqlite` 0.32 with bundled SQLite — persistence.
- `libc` — UID and low-level Unix behavior.

No HTTP client/server dependency is present; the binaries do not open network
listeners.

## Module Structure

- `crates/sher-pe-model/src/{process,cpu,memory,thread,files,network,cgroup,namespace,security,tree,evidence,timeline}.rs`
- `crates/sher-pe-telemetry/src/linux/{procfs,strace,perf,bpftrace,container,journald,kernel_log,systemd}.rs`
- `crates/sher-pe-intelligence/src/` — tree/rollup/history/timeline logic.
- `crates/sher-pe-investigation/src/` — deterministic investigation queries.
- `crates/sher-pe-history/src/lib.rs` — `HistoryStore`, schema migration,
  snapshot/event insertion, queries, retention pruning.
- `crates/sher-pe-cli/src/` — argument parsing, command dispatch, output.
- `crates/sher-pe-gui/src/` — eframe app and panels.
- `crates/sher-pe-daemon/src/main.rs` — sampling loop, signal handling, DB path,
  pruning.

## Data, State, APIs, and Contracts

### SQLite schema

`snapshots`:

- `id INTEGER PRIMARY KEY AUTOINCREMENT`
- `pid`, `start_time`, `sampled_at`, `name`
- `snapshot_json` (serialized `ProcessSnapshot`)

Indexes: `(pid, start_time)` and `(sampled_at)`.

`timeline_events`:

- `id INTEGER PRIMARY KEY AUTOINCREMENT`
- `pid`, `start_time`, `at`
- `event_json` (serialized `TimelineEvent`)

Indexes: `(pid, start_time)` and `(at)`. Migration adds `start_time` to old
databases and defaults it to 0 for historical rows.

Identity of a process generation is `(pid, start_time)`, which avoids
misattributing events after PID reuse. JSON is used for forward-compatible
payloads while indexed scalar columns support the common queries.

### Daemon lifecycle

- Installs `SIGTERM`/`SIGINT` handlers with `sigaction` and `SA_RESTART`.
- Handler only stores an atomic boolean.
- Sleeps in 200 ms increments so shutdown does not wait a full interval.
- On each tick: sample, persist snapshots, persist recent events.
- Once per hour: `prune_older_than(now - retention_secs)`.
- Does not daemonize; systemd owns supervision.

### Telemetry contract

`TelemetryAdapter` returns point-in-time readings; CPU percentages are derived
by the intelligence layer from tick deltas across refreshes, not by telemetry.
Live pass-through methods let investigation read threads/connections/disk I/O
without bypassing the intelligence facade.

## Security Observations

### Positive controls

- Shell-outs to `strace`, `perf`, `bpftrace`, `docker`, `podman`,
  `journalctl`, and `dmesg` use `std::process::Command` argument arrays, never
  `sh -c`; PID input is a parsed integer. No shell injection path was found.
- No network listener and no network client in the core binaries.
- The systemd unit uses `NoNewPrivileges=true`, `ProtectSystem=strict`,
  `ReadWritePaths=/var/lib/sher`, and scoped `AmbientCapabilities=CAP_SYS_PTRACE`
  rather than full root privileges.
- Kill/trace paths perform verification before acting; no production
  `unwrap`/`expect` panic path was found outside tests.
- The daemon does not attempt `setuid`/`setgid`/`setcap` or self-escalation.
- SQLite is bundled, avoiding a runtime dependency on a system SQLite version.

### Risk areas

1. **History database permissions are not explicitly restricted.** The systemd
   unit sets `StateDirectory=sher` but not `StateDirectoryMode=0700`; systemd
   creates state directories with mode 0755 by default. `HistoryStore::open`
   calls `create_dir_all` and lets SQLite create the database subject to the
   process umask, with no `chmod`/`set_permissions`. On a default umask the
   database and WAL/SHM files can be world-readable. Because `sherd` collects
   every user's process command lines and `/proc` details (with
   `CAP_SYS_PTRACE`), this is a local privacy exposure. `SECURITY.md` calls the
   database a single aggregation point whose permissions matter, but the code
   and unit do not enforce restrictive permissions.
2. **Time-based retention only; no size cap or compaction.** At a 5-second
   interval, every process is written on every tick. Seven days of process
   churn can produce a large database. Pruning deletes rows hourly but SQLite
   does not return file space without `VACUUM`/auto-vacuum. `ReadWritePaths` and
   host disk quotas are the only backstops. This is an availability/disk
   exhaustion concern rather than a memory-safety bug.
3. **Dependency-audit documentation contradiction.** `SECURITY.md:83-88` says
   `cargo audit`/`cargo deny` are not wired into CI, but
   `.github/workflows/ci.yml:56-69` contains an `audit` job using
   `rustsec/audit-check@v2`. `README.md:39` says audit is wired but not observed
   to execute. The project therefore has an audit job, but its operational
   status is ambiguous and the security policy is stale.
4. **Linux-only CI for a GUI that builds on other platforms.** CI runs
   `cargo build/test/clippy/fmt` on Ubuntu x86_64 and arm64 only. Parser/model
   tests are platform-independent, and the GUI is expected to open on non-Linux
   platforms with an error banner, but no macOS/Windows build or UI smoke test
   covers that path.
5. **Daemon hardening could be tighter.** The unit has good baseline
   hardening but omits `StateDirectoryMode=0700`, `UMask=0077`,
   `ProtectHome`, `PrivateTmp`, `RestrictAddressFamilies`, and a system-call
   filter. These are defense-in-depth improvements for a process with
   `CAP_SYS_PTRACE`.

## Tests and CI

- CI: `.github/workflows/ci.yml` runs on push/PR to `main` for Ubuntu x86_64
  (`ubuntu-latest`) and arm64 (`ubuntu-24.04-arm`).
- Steps: `cargo fmt --all -- --check`, `cargo build --workspace --all-targets`,
  `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`.
- Separate `audit` job uses `rustsec/audit-check@v2` with `GITHUB_TOKEN`.
- 184 `#[test]`/`#[tokio::test]` attributes observed; `README.md` says about
  172. Tests include parser fixtures that run on macOS, model serialization,
  intelligence/history/investigation behavior, and kill-verification logic.
- No macOS or Windows CI. No end-to-end test starts `sherd` under systemd or
  checks file permissions.
- No formula/packaging test beyond AUR/deb metadata; AUR builds CLI from git,
  while deb/rpm metadata builds `sher` only.

## Findings

| Severity | Finding | Evidence | Impact | Root Cause Hypothesis | Recommendation |
|---|---|---|---|---|---|
| Medium | Daemon history DB and state directory are not explicitly mode-restricted | `packaging/systemd/sherd.service` has `StateDirectory=sher` but no `StateDirectoryMode`/`UMask`; `crates/sher-pe-history/src/lib.rs:38-49` uses `create_dir_all` + `Connection::open` with no `chmod`/`set_permissions`; `SECURITY.md:44-60` acknowledges the DB is a single aggregation point | On default umask, `/var/lib/sher` (0755) and `history.db`/`-wal`/`-shm` (0644) can be readable by local users. The DB contains every user's command lines, process metadata, and timeline events collected with `CAP_SYS_PTRACE` | The service relies on systemd defaults and process umask instead of explicitly setting private permissions; security documentation describes the risk but no control enforces it | Set `StateDirectoryMode=0700` and `UMask=0077` in the unit; create the DB with mode 0600 (or `chmod` after open) and ensure WAL/SHM inherit; add a startup check that refuses a group/world-readable DB or fixes it; document `/var/lib/sher` access |
| Low | No database size cap or space reclamation after pruning | `crates/sher-pe-daemon/src/main.rs:168-192` prunes by age hourly; `crates/sher-pe-history/src/lib.rs:251` deletes rows; no `VACUUM`, auto-vacuum, max-size check, or disk-full handling | Long-running hosts with high process churn can grow the SQLite file or fill `/var/lib/sher`, affecting the daemon and host; deleted rows do not shrink the file | Retention was designed as a time bound, not a storage bound; SQLite file reclamation was not included | Add `PRAGMA auto_vacuum=INCREMENTAL` or periodic `VACUUM`, expose a max-size/row cap, and log/handle `SQLITE_FULL`; consider sampling only changed snapshots |
| Low | Dependency-audit documentation contradicts CI | `SECURITY.md:83-88` says audit/deny are not wired; `.github/workflows/ci.yml:56-69` runs `rustsec/audit-check@v2`; `README.md:39` says wired but not observed | Users and maintainers cannot tell whether advisories block merges; a real advisory may be ignored if the job is advisory-only or failing silently | Security policy and CI evolved independently; no single source of truth for audit status | Make `SECURITY.md` match CI, decide whether the audit job is required, and document how advisory failures are triaged; consider `cargo deny` for licenses/sources as well |
| Low | CI does not build or smoke-test non-Linux GUI behavior | `.github/workflows/ci.yml` matrix contains only Ubuntu runners; `README.md:34` says the GUI opens on any OS with a failure banner | A macOS/Windows GUI build regression can merge unnoticed; the documented non-Linux behavior is untested | Linux telemetry is the primary target and CI cost was minimized | Add a macOS build job for `sher-gui` (and optionally Windows), at minimum `cargo check -p sher-pe-gui`, plus a headless smoke test of the failure banner if feasible |
| Low | systemd hardening omits several low-cost isolation controls | `packaging/systemd/sherd.service` has `ProtectSystem=strict`, `NoNewPrivileges`, `ReadWritePaths`, `AmbientCapabilities`, but no `StateDirectoryMode`, `UMask`, `ProtectHome`, `PrivateTmp`, `RestrictAddressFamilies`, or `SystemCallFilter` | A compromised daemon has more host visibility than necessary for a process that only needs `/proc`, `/var/lib/sher`, and basic syscalls | Baseline hardening was implemented, but the unit was not taken through a full `systemd-analyze security` review | Run `systemd-analyze security sherd.service`, add `StateDirectoryMode=0700`, `UMask=0077`, `ProtectHome=read-only` or `tmpfs` as appropriate, `PrivateTmp=true`, `RestrictAddressFamilies=AF_UNIX`, and a conservative `SystemCallFilter` |

## Strengths

- Clear crate layering with a pure model crate and a documented telemetry seam.
- Deterministic investigation engine with explicit evidence citations.
- Hand-rolled `/proc` parsing with fixture tests that run off-Linux.
- No shell invocation for external tools; argument-array use is consistent.
- No network listener; the attack surface is local.
- Good baseline systemd hardening and graceful signal handling.
- Solid test volume and strict CI (fmt, build, test, clippy `-D warnings`).

## Open Questions / Not Verified

- Whether the `rustsec/audit-check` job currently succeeds in the maintainer's
  environment; README says it has not been observed to execute.
- Whether any deployment sets a restrictive `UMask` outside the unit (e.g.,
  systemd `UMask=` drop-in), which would mitigate the DB permission finding.
- Whether `sherd` is ever run as a non-root user with a pre-existing
  world-readable database; the code does not correct existing modes.

## References

- `ARCHITECTURE.md`
- `SECURITY.md` (lines 44-60, 83-88)
- `README.md` (lines 12, 34, 39, 46, 105-109)
- `packaging/systemd/sherd.service`
- `packaging/aur/PKGBUILD`
- `.github/workflows/ci.yml`
- `crates/sher-pe-history/src/lib.rs`
- `crates/sher-pe-daemon/src/main.rs`
- `crates/sher-pe-cli/Cargo.toml`
- `crates/sher-pe-telemetry/src/linux/`
