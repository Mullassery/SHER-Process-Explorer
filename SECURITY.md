# Security Policy

## Project status

SHER Process Explorer is a personal, single-maintainer project. There is no
security team, no paid support contract, and no guaranteed response time
(SLA). Reports are handled on a best-effort basis by the one person who
maintains this repository. If that's not an acceptable level of support for
your use case, please factor that in before deploying this tool anywhere
that matters.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository
(Security tab → "Report a vulnerability") if it's enabled, or open a normal
GitHub issue with minimal detail asking for a private channel if it's not.
Do not include exploit details in a public issue.

There is no dedicated security email address and no bug bounty program.

## What this tool actually touches (read before relying on it)

- **`sher` reads `/proc` and `/sys`** for the current user's own processes,
  and for other users' processes to the extent normal Linux permissions
  allow (i.e. root or matching UID). It does not attempt to bypass
  permission checks; a `PermissionDenied` on another user's `/proc/[pid]/*`
  is surfaced as a typed error per field, not worked around.
- **`sher kill <pid>`** sends a real POSIX signal via `nix::sys::signal` (a
  thin wrapper over `kill(2)`) to a real process. It prompts for interactive
  confirmation by default; `--yes` skips that prompt. There is no dry-run
  mode and no undo — a `SIGKILL` sent to the wrong pid kills the wrong
  process, same as running `kill` directly. Treat `--yes` accordingly in
  scripts.
- **`sherd` (the daemon)** is meant to run under systemd
  (`packaging/systemd/sherd.service`) and writes a SQLite database
  (`/var/lib/sher/history.db` when run as root, `~/.local/share/sher/history.db`
  otherwise). That database accumulates process snapshots — including
  command lines and, historically, whatever was visible in `/proc` at
  sample time — over the daemon's entire uptime. Anyone who can read that
  file can read that history. The provided `sherd.service` unit *is*
  hardened: `NoNewPrivileges=true`, `ProtectSystem=strict`,
  `ReadWritePaths=/var/lib/sher` only, and a scoped
  `AmbientCapabilities=CAP_SYS_PTRACE` instead of running as root outright
  (checked directly against `packaging/systemd/sherd.service` as part of
  this audit). `CAP_SYS_PTRACE` still lets the daemon see every other
  user's `/proc/[pid]/*` fields, which is inherent to what the daemon is
  for (system-wide history), not an oversight — but it does mean the
  daemon's own SQLite database is a single point that aggregates data
  about every user's processes on the machine, so its file permissions and
  the host's access to `/var/lib/sher` matter.
- **Shell-outs**: `sher trace`/`profile`/`deep-trace` invoke `strace`/
  `perf`/`bpftrace` (via `timeout`); container detection invokes `docker`/
  `podman inspect`; log correlation invokes `journalctl`/`dmesg`. All of
  these use `std::process::Command` with argument arrays (`.args([...])`),
  never a shell string (`sh -c "..."`), so untrusted input reaching these
  call sites (a pid, in practice always a parsed integer) cannot inject
  shell metacharacters. This was checked directly against the source at
  `crates/sher-pe-telemetry/src/linux/{strace,perf,bpftrace,container,journald,kernel_log,systemd}.rs`
  as part of this audit — no `sh -c` pattern exists anywhere in the
  codebase.
- **Privilege**: nothing in this codebase calls `setuid`/`setgid`/`setcap`
  or otherwise attempts to escalate its own privilege. Tracing features
  (`perf`, `bpftrace`) require the invoking user to already have the
  relevant capability (`CAP_PERFMON`/`CAP_BPF`/`perf_event_paranoid`) or be
  root — the tool does not request or manage that for you.
- **No network listener.** `sher`/`sherd`/`sher-gui` do not open any
  network socket of their own; all network-related output (`sher inspect`'s
  connection list) is read-only reporting of *other* processes' sockets via
  `/proc/net/*`.

## Dependency security

`cargo audit` / `cargo deny` are not yet wired into CI (tracked in
`ROADMAP_HONEST.md`). Dependencies were last spot-checked manually during
this audit pass; this repo currently has no automated, recurring dependency
vulnerability scan. Dependabot (`.github/dependabot.yml`) is configured to
open PRs for outdated/vulnerable `cargo` and GitHub Actions dependencies,
but nothing currently fails CI on a known advisory.

## Scope

This policy covers the code in this repository only. It does not cover
third-party tools this project shells out to (`strace`, `perf`, `bpftrace`,
`docker`, `podman`, `journalctl`) — vulnerabilities in those belong to their
own projects.
