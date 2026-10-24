# Competitive intelligence in roadmap and upgrade work

**Policy date:** 2026-10-19

Competitive findings are an input to product decisions, not a one-off report.
Every pending roadmap item, new feature, and routine dependency upgrade should
check the repository's [`AUDIT_FINDINGS.md`](AUDIT_FINDINGS.md) before work
starts, and record the decision in the PR or changelog.

## Required check before building

1. **Read `AUDIT_FINDINGS.md`.** Find the relevant competitor row and the
   ranked next actions. If the finding is stale, update it with a dated source.
2. **Name the competitor and the user problem.** A feature is not justified by
   "competitor has it". State the workflow it unlocks, who needs it, and how
   often. Mark unverified demand as a hypothesis.
3. **Prefer reuse over new code.** Check whether an existing Mullassery repo
   already provides the capability (see `BUNDLES.md` in the profile repo and
   the bundle role file in this repo, when present). Typical reuse:
   - crawling/fetching/robots/SSRF → **MudFish**
   - architecture maps / PR diffs → **CodeAtlas**
   - data-quality contracts / validation → **StatGuardian**
   - token counting / cost tables → **PyTokenCalc**
   - dependency graph / advisories / SBOM → **PyDeepMesh**
   - segmentation / CLV / churn → **ClusterAudienceKit**
   - activation / lineage / PII → **PyReverseETL**
   - fleet state sync → **SyncFleet** (only after conflict resolution)
4. **Choose one disposition:** build, integrate, defer, or reject. Write it
   down. A rejection with a reason is a successful outcome.
5. **For routine upgrades**, check whether the upgrade closes a known
   competitor gap or breaks a differentiated capability. Run the tests that
   cover the affected path; do not merge a green build that silently changes a
   user-visible contract.

## PR / changelog checklist

- [ ] Competitor and source URL/date recorded (or "no direct competitor").
- [ ] User impact and frequency stated; unverified demand labelled.
- [ ] Reuse check done against sibling repos/bundles.
- [ ] Failure mode and rollback considered (especially auth, PII, cost).
- [ ] Docs/roadmap status updated honestly.
- [ ] Tests or a manual verification command included.

## Review cadence

- Refresh the competitor row when a release changes the capability.
- Re-check the full `AUDIT_FINDINGS.md` at least quarterly and before a major
  release.
- If a finding is wrong or stale, correct it in the same PR that relies on it.

## Non-goals

- Copying features for parity.
- Adding a dependency just because a competitor uses it.
- Treating star counts or download counts as proof of user need.

## OSS gap analysis — 2026-10-24

**What matters most here:** publish it and add a TUI. Nothing is released despite packaging recipes, and a one-shot CLI plus GUI misses terminal-first investigation; ship packages and a TUI before deeper tracing.

Scope: workspace v0.1.0 — `sher-pe-model/telemetry/intelligence/investigation/
history`, plus `sher` (CLI), `sher-gui` (egui/eframe), and `sherd` (SQLite sampler).
Real `/proc`, strace, perf, bpftrace, journald, container detection, and OTLP/JSON
export exist; 172 tests. Linux-only, no TUI, packages built but unpublished.
`AUDIT_FINDINGS.md` predates the OTLP export.

### Comparable OSS projects

| Project | GitHub | License | Last activity | Why it is the comparison |
|---|---|---|---|---|
| htop | https://github.com/htop-dev/htop | GPL-2.0 | 3.5.3 tagged 2026-08-16; commits 2026-10-19 | The default interactive process viewer users compare any process tool against |
| btop | https://github.com/aristocratos/btop | Apache-2.0 | v1.4.7 tagged 2026-05-01; commits 2026-10-23 | Widely used TUI monitor with process tree, resource meters, and a large user base |
| sysdig | https://github.com/draios/sysdig | Apache-2.0 (driver separately licensed) | 0.41.4 released 2026-01-29; commits 2026-04-13 | Deep syscall/system visibility with containers and a built-in eBPF/kernel capture path |

bpftrace (https://github.com/bpftrace/bpftrace, Apache-2.0, commits 2026-10-22)
is the external tracer our `sher ebpf` shells out to, not a direct UI competitor.

### Capability comparison

| Capability | Ours | htop | btop | sysdig | Gap |
|---|---|---|---|---|---|
| Desktop GUI | Yes | No | No | No | Ahead: egui/eframe UI sharing the same APIs as the CLI |
| Terminal TUI | No | Yes | Yes | Partial | Absent: `csysdig` is the only comparable TUI here |
| Evidence-backed findings | Yes | No | No | Partial | Differentiated: `Finding` + `Evidence` + `Confidence`, not raw rows |
| Syscall tracing | Yes | No | No | Yes | Parity via `strace -c`; sysdig is deeper and self-contained |
| eBPF scripting | Partial | No | No | Yes | Weaker: 3 fixed scripts shelling out to `bpftrace`, no custom scripts |
| Long-term history | Yes | No | No | Partial | Ahead: SQLite daemon keyed by `(Pid, start_time)`; sysdig has captures, not per-process history |
| Container/namespace awareness | Yes | Partial | Partial | Yes | Parity: containers and namespaces are first-class objects |
| Journald/log correlation | Yes | No | No | No | Differentiated: `journalctl` correlation plus crash timeline |
| OTLP/JSON export | Yes | No | No | Partial | Ahead: spec-shaped OTLP file; sysdig emits JSON/capture files |
| Non-root operation | No | Yes | Yes | Partial | Weaker: live tracing needs root/CAP_SYS_PTRACE and external tools |

### Gaps that matter (ranked)

1. **Nothing is published (weaker, S).** `.deb`/`.rpm`/AUR recipes exist and
   were validated, but there is no release, distro repo, or install path except
   `cargo build`; htop/btop/sysdig are one package-manager command away.
2. **No TUI (absent, M).** `sher` is one-shot and `sher-gui` needs a display;
   there is no htop/btop-class terminal view, where most server investigation
   happens, and the roadmap lists a TUI as pending.
3. **Privileged-only deep paths (weaker, M).** Live `/proc`, `perf`, `strace`,
   `bpftrace`, and journald need root or `CAP_SYS_PTRACE` (the daemon grants it);
   no non-root mode is documented, while htop/btop work unprivileged.
4. **eBPF is three hardcoded scripts (weaker, M).** `sher ebpf` offers only
   `offcpu`, `iolatency`, and `runqlat` via an external `bpftrace`; users cannot add
   probes or aggregate results. sysdig embeds its own driver and chisels.
5. **Evidence quality is unvalidated (weaker, S/M).** The rule-based
   `Finding`/`Confidence` model is structurally honest, but no external users or
   incident benchmark mean precision and false-positive rates are unknown.
6. **History is an unmanaged sensitive store (weaker, S/M).** `sherd` aggregates
   every user's command lines and resource history into one readable SQLite file
   with no retention, redaction, or encryption; htop/btop keep none.

### Where we are differentiated

- The `Finding`/`Evidence`/`Confidence` model is the real differentiator: every
  claim points at a raw source value, and confidence cannot exceed the data.
  htop/btop show metrics; sysdig shows events; neither produces a cited "why".
- One API serves CLI, GUI, and daemon, and history is keyed by
  `(Pid, start_time)` so PID reuse cannot merge two processes.
- Correlation across `/proc`, containers, journald, crash timeline, and
  syscall/perf/eBPF output is broader than sysdig's event-centric view, and no
  comparable ships a desktop GUI — but that advantage needs a published install.

### Disposition

- **Build:** publish `.deb`/`.rpm`/AUR and a GitHub release first; add a TUI and a
  documented non-root mode; make the eBPF script set extensible.
- **Integrate/reuse:** keep `bpftrace`/`perf`/`strace` as the tracing backends
  rather than embedding eBPF; consider sysdig/libscap for capture if richer
  syscall depth is needed; reuse the existing packaging recipes.
- **Defer/reject:** cross-platform support, the AI narrative layer, Phase 6
  (`SherKernelAdapter`) until SHER Kernel exposes telemetry, and a network
  exporter while the OTLP file artifact works.

### Sources

- https://github.com/htop-dev/htop and /tags (accessed 2026-10-24)
- https://github.com/aristocratos/btop and /tags (accessed 2026-10-24)
- https://github.com/draios/sysdig and /releases/tag/0.41.4 (accessed 2026-10-24)
- https://github.com/bpftrace/bpftrace (accessed 2026-10-24)
- Repo files inspected: README.md, AUDIT_FINDINGS.md, ROADMAP_HONEST.md,
  ROADMAP.md, ARCHITECTURE.md, Cargo.toml, all manifests, `sher-pe-cli/src/*.rs`,
  `sher-pe-history/src/lib.rs`
