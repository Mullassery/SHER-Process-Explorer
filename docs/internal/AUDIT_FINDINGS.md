# Audit findings — 2026-10-19

This file records the repository-specific findings from the portfolio audit
conducted on 2026-10-19. It is documentation only; no code or release artifacts
were changed in this pass unless explicitly noted under "Implementation status".

Sources: the repository's own README/source/workflows, GitHub metadata and
Actions runs, PyPI metadata, and official competitor documentation. Claims are
marked as verified, inferred, or open questions. "Absent" means not found in the
inspected repository/docs, not proof that it cannot exist.

## What it is

Evidence-based Linux process investigation: `/proc` telemetry, perf/strace/bpftrace sampling, container detection, journald correlation, history daemon, CLI, and egui UI.

## Verified strengths

- Real `/proc` parsing; real strace/perf/bpftrace; process intelligence; deterministic 'why' engine with evidence/confidence; log/crash timeline; SQLite history daemon; .deb/.rpm/AUR packaging built; 172 tests; CI green.
- The only SHER repo with a clear standalone user and a real differentiator.

## Verified gaps and user-facing risks

- Packages are built but not published; no tagged GitHub release or distro repo.
- Linux-only; no non-root mode for privileged paths; no JSON/OTEL export; no TUI; Phase 6/7 not started.
- AI narrative is intentionally not built.

## Direct competitors

- perf, bpftrace, strace, sysdig, btop/htop, px.

## Ranked next actions

- P1: publish .deb/.rpm/AUR + GitHub releases + install docs (S).
- P2: non-root/user mode + safer defaults (M).
- P2: JSON/OTEL export + TUI (M).

## Do not build

- The AI narrative layer now; deterministic evidence is the product.

## Evidence gaps / validation needed

- No external users; no validation on real incidents; privileged paths tested only in containers.

## Recommended disposition

Invest; this is the portfolio's clearest standalone Linux tool.

## Implementation status

No code changes in this pass.
