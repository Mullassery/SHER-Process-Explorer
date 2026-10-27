# SHER Process Explorer — Audit Findings

Audit date: 2026-10-27
Scope: full repository source, packaging, CI, and security documentation
Method: read-only source/docs/CI inspection; tests were not run to avoid
generated artifacts

## Summary

The core design is sound: a pure model crate, a telemetry trait with a
hand-rolled Linux `/proc` adapter, a bounded in-memory intelligence layer, a
deterministic investigation engine, and a separate SQLite history store. No
network listener, no shell-string execution, and no production panic path were
found.

The main risks are local privacy and operational rather than memory-safety:
the daemon aggregates all users' process history but does not explicitly
restrict the database/state-directory permissions, and retention is time-based
without a size cap or space reclamation. CI/documentation also disagree about
whether dependency auditing is wired in.

| Severity | Count |
|---|---:|
| Critical | 0 |
| High | 0 |
| Medium | 1 |
| Low | 4 |

## Findings

### 1. Medium — History DB and state directory are not explicitly mode-restricted

**Evidence**

- `packaging/systemd/sherd.service` sets `StateDirectory=sher` but no
  `StateDirectoryMode=` or `UMask=`.
- `crates/sher-pe-history/src/lib.rs:38-49` creates parent directories with
  `create_dir_all` and opens SQLite without `chmod`/`set_permissions`.
- `SECURITY.md:44-60` explicitly calls the database a single point that
  aggregates every user's process history and says its file permissions matter.

**Impact**

With systemd's default state-directory mode (0755) and a typical umask, the
database and its WAL/SHM companions can be readable by local users. Because
`sherd` runs with `CAP_SYS_PTRACE` and records command lines and `/proc`
details for every process, this can disclose other users' activity.

**Root cause hypothesis**

The service relies on platform defaults and process umask; the security policy
documents the risk but no code or unit setting enforces restrictive access.

**Recommendation**

- Add `StateDirectoryMode=0700` and `UMask=0077` to the unit.
- Create/open the DB with mode 0600, and ensure `-wal`/`-shm` inherit it.
- On startup, detect group/world-readable files and either fix or refuse to
  start with a clear error.
- Consider encrypting or redacting command lines at rest if the DB must be
  readable by a broader group.

### 2. Low — No database size cap or space reclamation

**Evidence**

- `crates/sher-pe-daemon/src/main.rs:168-192` prunes by age once per hour.
- `crates/sher-pe-history/src/lib.rs:251` deletes old rows.
- No `VACUUM`, `auto_vacuum`, max-size check, or `SQLITE_FULL` handling.

**Impact**

High-churn hosts can accumulate a large file or fill `/var/lib/sher`; deleted
rows do not shrink the SQLite file. This is an availability/disk-exhaustion
risk, not a confidentiality/integrity bug.

**Root cause hypothesis**

Retention was specified as a time bound only; storage reclamation was not part
of the initial design.

**Recommendation**

Add incremental auto-vacuum or periodic `VACUUM`, a configurable max-size/row
cap, and explicit disk-full handling. Consider skipping unchanged snapshots or
sampling less frequently for stable processes.

### 3. Low — Audit documentation and CI contradict each other

**Evidence**

- `SECURITY.md:83-88`: "`cargo audit` / `cargo deny` are not yet wired into CI".
- `.github/workflows/ci.yml:56-69`: `audit` job using
  `rustsec/audit-check@v2`.
- `README.md:39`: audit is "wired into CI" but "not observed to execute".

**Impact**

Maintainers and users cannot tell whether a known advisory blocks a merge. If
the job is advisory-only or silently failing, the project may ship vulnerable
dependencies while the README claims coverage.

**Root cause hypothesis**

Security policy and CI evolved independently; there is no single source of
truth for audit status.

**Recommendation**

Align `SECURITY.md` with the actual CI, make the audit job required (or
explicitly document it as advisory), and record how failures are triaged.
Consider `cargo deny` for licenses, duplicate versions, and sources.

### 4. Low — Non-Linux GUI path is not built in CI

**Evidence**

- `.github/workflows/ci.yml` only uses Ubuntu runners.
- `README.md:34` says the GUI opens on any OS but shows the same Linux
  telemetry failure.

**Impact**

A macOS/Windows-only compile or UI regression can merge unnoticed, even though
the GUI is advertised as openable there.

**Root cause hypothesis**

CI cost and Linux-first targeting; parser/model tests already run off-Linux, so
the remaining gap is the GUI binary.

**Recommendation**

Add at least `cargo check -p sher-pe-gui` on macOS, and optionally Windows. A
headless smoke test of the failure banner would cover the documented behavior.

### 5. Low — systemd unit hardening can be tightened

**Evidence**

`packaging/systemd/sherd.service` includes `NoNewPrivileges=true`,
`ProtectSystem=strict`, `ReadWritePaths=/var/lib/sher`, and
`AmbientCapabilities=CAP_SYS_PTRACE`, but omits `StateDirectoryMode`,
`UMask`, `ProtectHome`, `PrivateTmp`, `RestrictAddressFamilies`, and a
system-call filter.

**Impact**

A compromised daemon retains more host visibility than required. This is
defense-in-depth, not an observed vulnerability.

**Root cause hypothesis**

Baseline hardening was added without a full `systemd-analyze security` pass.

**Recommendation**

Run `systemd-analyze security sherd.service`; add `StateDirectoryMode=0700`,
`UMask=0077`, `PrivateTmp=true`, `ProtectHome` as appropriate (the daemon needs
`/proc` but not user homes), `RestrictAddressFamilies=AF_UNIX`, and a
conservative `SystemCallFilter`.

## Positive Observations

- No network listener or client in `sher`/`sherd`/`sher-gui`.
- External tools are invoked with argument arrays, never `sh -c`.
- Kill/trace paths verify the target before acting.
- Pure model crate and a clear telemetry abstraction.
- Deterministic investigation results with explicit evidence citations.
- Strict CI: fmt, build, test, and clippy with `-D warnings`.
- 184 tests, including fixtures that run on non-Linux hosts.

## Verification Notes

- Working tree was clean at audit time; no source/config changes were made.
- Tests were not executed to avoid build/cache artifacts.
- The audit job's live status was not verified; the contradiction is between
  repository files.
- File-mode exposure depends on deployment umask/systemd defaults; a custom
  `UMask=` drop-in would mitigate it.
