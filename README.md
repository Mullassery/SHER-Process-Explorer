# SHER Process Explorer

Makes Linux's process-level reality *understandable*. Instead of forcing a
user to manually combine `top`/`ps`/`lsof`/`ss`/`strace`/`perf`/`journalctl`
and stitch the story together by hand, SHER Process Explorer answers "what is
this process doing, why, and what should I look at next" — with evidence
pointing at the exact raw source for every claim it makes.

Part of the same personal ecosystem as [Aurora](https://github.com/Mullassery/aurora)
(look), Himalayas (feel), [SHER Kernel](https://github.com/Mullassery/SHER-KERNEL)
(work differently), and TinyBridge (run safer).

## What's here (Phase 0 — engine + CLI)

- Hand-rolled `/proc` parsing (`sher-pe-telemetry`) — no external procfs-wrapper
  dependency, full control over exact fields, fixture-tested so the parser
  logic runs on macOS too even though the adapter itself is Linux-only.
- A process intelligence layer (`sher-pe-intelligence`) that turns raw
  snapshots into a process tree, family rollups, CPU%-over-time, and a
  timeline of started/exited/grew/connected events.
- A deterministic, rule-based "why" investigation engine
  (`sher-pe-investigation`) that produces `Finding`s backed by `Evidence` —
  structurally unable to claim more certainty than the data supports (see
  `Confidence::{Observed,Correlated,Likely,Unknown}`).
- A `sher` CLI (`sher-pe-cli`) that is the *only* consumer of the above this
  pass — the same API surface a future GUI will call, so there is never
  separate logic for CLI vs. GUI.

See `ARCHITECTURE.md` for the full crate-by-crate design and `ROADMAP.md` for
the phased plan beyond this MVP (desktop UI, deep tracing, containers, log
correlation, an optional AI narrative layer, packaging).

## Non-goals this pass

No desktop UI yet, no eBPF/perf/strace integration, no persistent history
storage (in-memory only), no LLM-backed narrative generation. `sher trace`
and `sher profile` are honest `Unsupported` errors, not silent no-ops — see
the "no fake stubs" note in `CLAUDE.md`.

## Building

Runs on Linux only (`main()` checks `cfg!(target_os = "linux")` and exits
with a clear error elsewhere). Parser and model unit tests are fixture-based
and run on any OS:

```sh
cargo build --workspace
cargo test --workspace
```

## License

Proprietary — see `LICENSE`. Free to use with explicit attribution to
Georgi Mammen Mullassery.
