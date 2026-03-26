# SentinelEdge Documentation

This folder keeps the runtime, research blueprint, and public documentation in sync.

Read it in this order:

1. [`GETTING_STARTED.md`](/Users/michelpicker/Library/Mobile Documents/com~apple~CloudDocs/Projekte/SentinelEdge/docs/GETTING_STARTED.md) for build, run, and sample telemetry input.
2. [`ARCHITECTURE.md`](/Users/michelpicker/Library/Mobile Documents/com~apple~CloudDocs/Projekte/SentinelEdge/docs/ARCHITECTURE.md) for the runtime pipeline and design decisions.
3. [`STATUS.md`](/Users/michelpicker/Library/Mobile Documents/com~apple~CloudDocs/Projekte/SentinelEdge/docs/STATUS.md) for what is implemented, partially wired, and still unbuilt.
4. [`PROJECT_BACKLOG.md`](/Users/michelpicker/Library/Mobile Documents/com~apple~CloudDocs/Projekte/SentinelEdge/docs/PROJECT_BACKLOG.md) for small, buildable tasks.
5. [`RESEARCH_TRACKS.md`](/Users/michelpicker/Library/Mobile Documents/com~apple~CloudDocs/Projekte/SentinelEdge/docs/RESEARCH_TRACKS.md) for the full 40-track blueprint translated into an implementation status map.
6. [`../site/admin.html`](/Users/michelpicker/Library/Mobile Documents/com~apple~CloudDocs/Projekte/SentinelEdge/site/admin.html) for the read-only browser console backed by exported JSON artifacts.

## Design documents (Phase 5)

- [`PAPER_TARGETS.md`](/Users/michelpicker/Library/Mobile Documents/com~apple~CloudDocs/Projekte/SentinelEdge/docs/PAPER_TARGETS.md) — research paper targeting and evaluation plan.
- [`DESIGN_SWARM_PROTOCOL.md`](/Users/michelpicker/Library/Mobile Documents/com~apple~CloudDocs/Projekte/SentinelEdge/docs/DESIGN_SWARM_PROTOCOL.md) — swarm coordination protocol sketch (R03/R08/R15/R23).
- [`DESIGN_WASM_EXTENSIONS.md`](/Users/michelpicker/Library/Mobile Documents/com~apple~CloudDocs/Projekte/SentinelEdge/docs/DESIGN_WASM_EXTENSIONS.md) — Wasm extension surface specification (R17).
- [`DESIGN_SUPPLY_CHAIN.md`](/Users/michelpicker/Library/Mobile Documents/com~apple~CloudDocs/Projekte/SentinelEdge/docs/DESIGN_SUPPLY_CHAIN.md) — supply-chain attestation inputs (R20).
- [`DESIGN_POST_QUANTUM.md`](/Users/michelpicker/Library/Mobile Documents/com~apple~CloudDocs/Projekte/SentinelEdge/docs/DESIGN_POST_QUANTUM.md) — post-quantum logging upgrade path (R11/R21).

## Research questions & design documents (Phase 7)

- [`RESEARCH_QUESTIONS_R26_R30.md`](/Users/michelpicker/Library/Mobile Documents/com~apple~CloudDocs/Projekte/SentinelEdge/docs/RESEARCH_QUESTIONS_R26_R30.md) — edge intelligence & explainability (R26–R30).
- [`RESEARCH_QUESTIONS_R31_R35.md`](/Users/michelpicker/Library/Mobile Documents/com~apple~CloudDocs/Projekte/SentinelEdge/docs/RESEARCH_QUESTIONS_R31_R35.md) — edge infrastructure & hardening (R31–R35).
- [`RESEARCH_QUESTIONS_R36_R40.md`](/Users/michelpicker/Library/Mobile Documents/com~apple~CloudDocs/Projekte/SentinelEdge/docs/RESEARCH_QUESTIONS_R36_R40.md) — resilience & long-horizon (R36–R40).
- [`DESIGN_ADVERSARIAL_HARNESS.md`](/Users/michelpicker/Library/Mobile Documents/com~apple~CloudDocs/Projekte/SentinelEdge/docs/DESIGN_ADVERSARIAL_HARNESS.md) — adversarial robustness testing harness (R28).
- [`DESIGN_TEMPORAL_LOGIC.md`](/Users/michelpicker/Library/Mobile Documents/com~apple~CloudDocs/Projekte/SentinelEdge/docs/DESIGN_TEMPORAL_LOGIC.md) — temporal-logic property specification format (R29).
- [`DESIGN_DIGITAL_TWIN.md`](/Users/michelpicker/Library/Mobile Documents/com~apple~CloudDocs/Projekte/SentinelEdge/docs/DESIGN_DIGITAL_TWIN.md) — digital-twin fleet simulation architecture (R31).
- [`DESIGN_POLICY_COMPOSITION.md`](/Users/michelpicker/Library/Mobile Documents/com~apple~CloudDocs/Projekte/SentinelEdge/docs/DESIGN_POLICY_COMPOSITION.md) — formal policy composition algebra (R39).

## Current philosophy

- Build a useful runtime slice first.
- Keep the research agenda visible, but separate implemented code from planned work.
- Update the docs whenever behavior changes so the repository stays accurate.

## Working rule

When a new feature lands, update:

- the code in `src/`
- the implementation snapshot in [`STATUS.md`](/Users/michelpicker/Library/Mobile Documents/com~apple~CloudDocs/Projekte/SentinelEdge/docs/STATUS.md)
- the task state in [`PROJECT_BACKLOG.md`](/Users/michelpicker/Library/Mobile Documents/com~apple~CloudDocs/Projekte/SentinelEdge/docs/PROJECT_BACKLOG.md)
