# Implementation Status

Updated: 2026-03-29

## Implemented now

- Rust project scaffold and runnable CLI (`demo`, `analyze`, `status`, `status-json`, `report`, `init-config`, `harness`, `export-model`, `attest`, `bench`, `serve`, `help`)
- Typed telemetry ingestion from CSV and JSONL (auto-detected by file extension)
- TOML/JSON configuration loading for thresholds, battery policies, and output paths
- Adaptive EWMA-based anomaly scoring across eight signal dimensions (CPU, memory, temperature, network, auth failures, integrity drift, process count, disk pressure)
- Human-readable anomaly reasons for operator inspection
- Threat-level and response decision engine
- Battery-aware graceful degradation of mitigation actions
- Pluggable device action adapters with trait-based implementations (throttle, quarantine, isolate, logging)
- Composite adapter chaining for multi-stage response execution
- Rollback checkpoints with bounded ring buffer for model/config state
- Forensic evidence bundle exporter (audit log + summary + checkpoints)
- SHA-256 cryptographic digest chain for tamper-evident audit logging (replaces FNV-1a)
- Signed audit checkpoints at configurable intervals with chain verification
- Structured JSON reports for SIEM ingestion (full and JSONL streaming)
- Baseline persistence and reload between runs
- Deterministic test fixtures: benign baseline, credential storm, slow escalation, low-battery attack
- Proof-carrying update metadata with SHA-256 binding digests (T032)
- Formally checkable policy state machine with transition validation and trace export (T033)
- Bounded replay buffer for telemetry windows with descriptive statistics (T040)
- Baseline adaptation controls: normal, frozen, and decay modes (T041)
- Poisoning heuristics: mean-shift detection, variance spike, drift accumulation, auth-burst patterns (T042)
- FP/FN benchmark harness with precision, recall, F1, and accuracy metrics (T043)
- Structured status JSON export for browser consumption (`status-json`)
- Read-only browser admin console for status snapshots and JSON report inspection
- Live admin console with auto-refresh (5 s polling), connection status indicator, file upload analysis (JSONL and CSV), decay rate slider, and drag-and-drop upload zone
- Dark mode support via CSS `prefers-color-scheme: dark` across the entire site
- CORS hardened to same-origin (`http://localhost`) with `Vary: Origin` header
- CSV parsing support in the `/api/analyze` endpoint alongside existing JSONL support
- Checkpoint save and restore via API (`/api/control/checkpoint`, `/api/control/restore-checkpoint`, `/api/checkpoints`)
- Adapter-backed checkpoint restore for abstract device state (isolation/quarantine rollback)
- TLA+ and Alloy model export of the policy state machine for offline formal verification (T101)
- `/api/export/tla` and `/api/export/alloy` endpoints for browser-accessible model download
- `export-model` CLI command for TLA+ and Alloy artifact generation
- Proof backend interface with pluggable backends (`DigestBackend`, `ZkStubBackend`) for future Halo2/SNARK integration (T102)
- Witness export path producing serializable JSON bundles for offline prover consumption (T102)
- `/api/export/witnesses` endpoint for browser-accessible witness bundle download
- Live proof recording in server-side analysis and demo execution
- Single-source research-track data: canonical JSON consumed by runtime, API (`/api/research-tracks`), and admin console with static-file fallback (T103)
- Supply-chain attestation foundations: build manifest generation with SHA-256 artifact hashing, trust-store loading/serialization, manifest and artifact verification hooks, and `/api/attestation/status` endpoint (T104)
- `attest` CLI command for build manifest generation
- Extended test fixtures (120 samples each) for paper evaluation: benign steady-state, credential storm, slow escalation, and low-battery attack scenarios (T110)
- Fixed-threshold baseline comparison detector with static per-signal thresholds for paper evaluation against adaptive EWMA (T111)
- `bench` CLI command for head-to-head detector comparison with precision/recall/F1/accuracy and throughput (T112)
- Per-signal contribution aggregation in `BenchmarkResult` with averaged attribution breakdown printed by `bench` command (T113)
- CSV report export from admin console
- Report filtering by threat level in admin console
- Improved connection error messages (distinguishes auth failure, server offline, HTTP errors)
- Auto-detecting CSV column count (8 or 10 columns) in CSV parsing
- Research paper targeting document with evaluation plan (T050)
- Swarm coordination protocol design with digest gossip, voting, and provenance (T051)
- Wasm extension surface specification with sandboxed detector/response plugins (T052)
- Supply-chain attestation design with build manifests and trust stores (T053)
- Post-quantum logging upgrade path with hybrid signature strategy (T054)
- Research questions formalised for R26-R30 with hypotheses, evaluation criteria, and implementation sketches (T070)
- Research questions formalised for R31-R35 with hypotheses, evaluation criteria, and implementation sketches (T071)
- Research questions formalised for R36-R40 with hypotheses, evaluation criteria, and implementation sketches (T072)
- Adversarial robustness testing harness design with evasion grammar and coverage metric (T073)
- Temporal-logic property specification format (SentinelTL) with runtime monitor architecture (T074)
- Digital-twin fleet simulation architecture with deterministic discrete-event model (T075)
- Formal policy composition algebra with conflict resolution and verification (T076)
- Static GitHub Pages site and deployment workflow
- Documentation index, architecture notes, backlog, and research-track mapping
- 147 automated tests (126 unit + 21 integration) covering all modules
- 10,000-sample benchmark test for detector performance at scale
- End-to-end HTTP API integration test suite (19 tests)
- Auto-refresh exponential backoff with resume button in admin console
- Research-track status table (40 tracks with badges) in admin console
- Collapsible partially-wired and not-implemented detail lists in status panel
- Cross-platform CI (Linux, macOS, Windows) with clippy and fmt checks
- FEATURES.md one-page marketing summary and CHANGELOG.md
- Five rounds of code-quality review with 20 hardening fixes (CQ-01 through CQ-20)
- NaN/Infinity rejection in telemetry validation for `network_kbps` and `temperature_c`
- Decay-rate API parameter validation (finite, 0.0–1.0)
- Client-side 10 MB file upload limit in admin console
- Explainable anomaly attribution with per-signal contribution breakdown in reports (T080)
- Config validation: threshold ordering, range checks, and warmup/smoothing/interval constraints (T081)
- Multi-signal anomaly correlation engine with Pearson co-movement detection (T082)
- Temporal-logic runtime monitor with safety and bounded-liveness property checking (T083)
- Adversarial test harness with grammar-based evasion strategies (SlowDrip, BurstMask, DriftInject) and coverage metrics (T084)
- Correlation engine wired into runtime pipeline with audit logging and console output (T090)
- Temporal-logic monitor wired into runtime pipeline with transition events and violation reporting (T091)
- Server-side `/api/correlation` endpoint for live multi-signal correlation analysis (T092)
- Adversarial harness CLI command for regression testing from the command line (T093)
- Behavioural device fingerprinting with statistical profiling and impersonation detection (T094)

## Partially wired

- Integrity-drift handling as a precursor to full spectral poisoning recovery
- ZK proof backend integration (witness export exists with digest backend; Halo2/SNARK circuit implementation deferred)
- TLA+/Alloy model-checking integration (export exists as TLA+ and Alloy modules; automated model-checking backend not wired)
- Research-track status accounting for all 40 blueprint items (now live in admin console; data served from canonical JSON via API with static-file fallback)

## Not implemented yet

- Continual learning or any on-device model training
- Differential privacy guarantees
- Zero-knowledge proofs, Halo2 circuits, or zk-SNARKs
- Automated model-checking backend for TLA+/Alloy (export is available; solver integration deferred)
- Swarm or cross-device coordination
- Quantum-walk anomaly propagation modeling
- Secure MPC / private set intersection
- Post-quantum signatures and hardware roots of trust
- Wasm-based extensible policies
- Supply-chain attestation (full Ed25519 signing and on-boot verification deferred)
- Long-term archival and energy-harvesting orchestration

## Practical milestone summary

The repository has completed Phases 0–10, providing a working edge security runtime with configurable detection, pluggable response actions, cryptographic audit trails, proof-carrying update metadata, a checkable policy state machine, poisoning heuristics, replay buffering, benchmark tooling, a live browser admin console backed by an authenticated HTTP API, and browser-based inspection of exported status/report artifacts. The admin console features auto-refresh polling, connection status indicator, drag-and-drop JSONL/CSV file upload for custom analysis, decay rate slider, checkpoint save/restore, adapter-backed device-state restore, CSV report export, threat-level filtering, improved error diagnostics, and dark mode support across the entire site. CORS is hardened to same-origin, and the analyze endpoint accepts both JSONL and CSV formats with auto-detecting column count. Twelve CLI commands are available. The policy state machine can be exported as TLA+ or Alloy modules for offline formal verification. Phase 5 produced design documents for research publication targeting, swarm coordination, Wasm extensibility, supply-chain attestation, and post-quantum cryptography upgrade. Phase 6 delivers a live control plane with token-authenticated endpoints for analysis, mode switching, baseline reset, checkpoint management, and demo execution. Phase 7 formalised research questions for all 15 expanded tracks (R26–R40) with hypotheses, evaluation criteria, and implementation sketches, plus design documents for adversarial robustness testing, temporal-logic monitoring, digital-twin simulation, and formal policy composition. Phase 8 adds runtime intelligence: explainable anomaly attribution with per-signal contribution breakdown, config validation with threshold ordering and range checks, Pearson-based multi-signal correlation detection, a temporal-logic runtime monitor supporting safety and bounded-liveness properties, and a grammar-based adversarial test harness with evasion strategies and decision-surface coverage metrics. Phase 9 integrates the Phase 8 modules into the runtime pipeline: the correlation engine and temporal-logic monitor are now wired into `execute()` with audit logging and console output, a `/api/correlation` endpoint exposes live analysis, the adversarial harness is accessible via CLI, and behavioural device fingerprinting enables impersonation detection from telemetry profiles. Phase 10 adds adapter-backed checkpoint restore so rollback reapplies abstract device isolation/quarantine state as well as detector baseline state, exports the policy state machine as TLA+ and Alloy modules for offline formal verification, introduces a proof backend interface with serializable witness export for future Halo2/SNARK integration, consolidates research-track data into a single canonical JSON source with API and static-file fallback, and delivers supply-chain attestation foundations with build manifest generation, trust-store loading, and artifact verification hooks. Phase 11 begins paper readiness with extended 120-sample test fixtures for four attack scenarios. The research agenda spans 40 tracks across seven thematic categories. 57 of 61 backlog items are complete. 147 automated tests (126 unit + 21 integration) cover all modules. Five rounds of code-quality review identified and fixed 20 hardening issues spanning data-loss bugs, panic risks, input validation gaps, API safety, statistical correctness, and client-side protections. Differential privacy, ZK proofs, swarm coordination, and full model-checking integration are not implemented yet.
