# SentinelEdge Project Backlog

This backlog lists the next concrete tasks in build order.

## Phase 0 - Foundation (completed)

- [x] T001: Bootstrap the Rust package and module layout.
- [x] T002: Implement CSV telemetry ingestion and validation.
- [x] T003: Implement an adaptive multi-signal anomaly detector.
- [x] T004: Implement a policy engine with battery-aware mitigation scaling.
- [x] T005: Implement a chained audit log for run forensics.
- [x] T006: Add baseline documentation and a GitHub Pages landing site.

## Phase 1 - Runtime hardening (completed)

- [x] T010: Add TOML/JSON configuration loading for thresholds, battery policies, and output paths.
- [x] T011: Support JSONL telemetry ingestion in addition to CSV.
- [x] T012: Emit structured JSON reports for SIEM ingestion.
- [x] T013: Persist and reload learned baselines between runs.
- [x] T014: Add richer anomaly features (process count, disk pressure, sensor drift windows).
- [x] T015: Add replayable deterministic test fixtures for benign and adversarial traces.

## Phase 2 - Device actions (completed)

- [x] T020: Replace abstract response actions with pluggable device action adapters.
- [x] T021: Add soft-throttle, service quarantine, and network isolate implementations behind traits.
- [x] T022: Add rollback checkpoints for configuration and model state.
- [x] T023: Add a forensic bundle exporter (audit log + summarized evidence).

## Phase 3 - Verifiability (completed)

- [x] T030: Replace the prototype hash chain with a cryptographic digest chain.
- [x] T031: Add signed audit checkpoints.
- [x] T032: Define proof-carrying update metadata for future ZK integration.
- [x] T033: Model the response policy as a formally checkable state machine.

## Phase 4 - Edge learning (completed)

- [x] T040: Add a bounded replay buffer for telemetry windows.
- [x] T041: Add baseline adaptation controls (freeze, decay, reset).
- [x] T042: Add poisoning heuristics beyond `integrity_drift`.
- [x] T043: Add benchmark harnesses for false-positive / false-negative tradeoffs.

## Phase 5 - Research blueprint expansion (completed)

- [x] T050: Formalize the subset of blueprint tracks targeted for the first research paper draft.
- [x] T051: Design a swarm-coordination protocol sketch for R03/R08/R15/R23.
- [x] T052: Specify a Wasm extension surface for R17.
- [x] T053: Specify supply-chain attestation inputs for R20.
- [x] T054: Define a post-quantum logging upgrade path for R11/R21.

## Phase 6 - Browser admin console (completed)

- [x] T060: Define the browser admin console scope and data contracts.
- [x] T061: Build a read-only browser status dashboard backed by exported JSON.
- [x] T062: Add JSON report upload and per-sample drilldown views.
- [x] T063: Add a local runtime-backed status/report refresh path.
- [x] T064: Add authenticated browser-side control actions.

## Phase 7 - Expanded research agenda (completed)

- [x] T070: Write detailed research-question statements for R26-R30 (explainability and edge intelligence).
- [x] T071: Write detailed research-question statements for R31-R35 (infrastructure and hardening).
- [x] T072: Write detailed research-question statements for R36-R40 (resilience and long-horizon).
- [x] T073: Design an adversarial robustness testing harness for R28.
- [x] T074: Design a temporal-logic property specification format for R29.
- [x] T075: Sketch a digital-twin simulation architecture for R31.
- [x] T076: Sketch a formal policy composition algebra for R39.

## Recommended next build order

1. ~~T050-T054~~ (completed) — research blueprint expansion with design documents.
2. ~~T070-T076~~ (completed) — expanded research questions and design documents.
3. ~~T063-T064~~ (completed) — live browser admin console with authenticated control plane.

All 41 backlog items are now complete.
