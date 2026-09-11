# SHER Process Explorer

Makes Linux's process-level reality *understandable*. Instead of forcing a
user to manually combine `top`/`ps`/`lsof`/`ss`/`strace`/`perf`/`journalctl`
and stitch the story together by hand, SHER Process Explorer answers "what is
this process doing, why, and what should I look at next" — with evidence
pointing at the exact raw source for every claim it makes.

Part of the same personal ecosystem as [Aurora](https://github.com/Mullassery/aurora)
(look), Himalayas (feel), [SHER Kernel](https://github.com/Mullassery/SHER-KERNEL)
(work differently), and TinyBridge (run safer).

## What's here

**Phase 0 — engine + CLI:**

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
- A `sher` CLI (`sher-pe-cli`).

**Phase 1 — desktop UI:**

- `sher-gui` (`sher-pe-gui`), an `egui`/`eframe` desktop app calling the
  *exact same* `sher-pe-intelligence`/`sher-pe-investigation` APIs the CLI
  uses — a process tree with search/collapse, tabbed detail per process,
  and `Why?` buttons wired straight into the investigation engine. No
  separate logic lives here, only presentation.

See `ARCHITECTURE.md` for the full crate-by-crate design and `ROADMAP.md` for
the phased plan beyond this (deep tracing, containers, log correlation, an
optional AI narrative layer, packaging).

## Non-goals this pass

No eBPF/perf/strace integration, no persistent history storage (in-memory
only), no LLM-backed narrative generation. `sher trace` and `sher profile`
are honest `Unsupported` errors, not silent no-ops — see the "no fake
stubs" note in `CLAUDE.md`.

## Building

The CLI runs on Linux only (`main()` checks `cfg!(target_os = "linux")` and
exits with a clear error elsewhere); the GUI still opens on any OS and
surfaces the same failure as an in-window banner instead. Parser and model
unit tests are fixture-based and run on any OS:

```sh
cargo build --workspace
cargo test --workspace
```

## License

Apache License 2.0 — see `LICENSE`. Copyright © 2026 SHER.
