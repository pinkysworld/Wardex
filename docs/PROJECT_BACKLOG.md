# Wardex Project Backlog

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

## Phase 8 - Runtime intelligence (completed)

- [x] T080: Add explainable anomaly attribution — per-signal contribution breakdown in `AnomalySignal` (R26).
- [x] T081: Add `Config::validate()` with threshold ordering and range checks.
- [x] T082: Add anomaly correlation engine — multi-signal co-movement detection via replay buffer analysis (R30).
- [x] T083: Add temporal-logic runtime monitor — lightweight LTL property checking on live telemetry (R29 / T074).
- [x] T084: Add adversarial test harness — grammar-based evasion fuzzer for detector regression testing (R28 / T073).

## Phase 9 - Pipeline integration and fingerprinting (completed)

- [x] T090: Wire correlation engine into the runtime `execute()` pipeline with audit logging and console output (R30).
- [x] T091: Wire temporal-logic monitor into the runtime pipeline with transition events and violation reporting (R29).
- [x] T092: Add `/api/correlation` GET endpoint and server-side replay buffer for live correlation analysis.
- [x] T093: Add `harness` CLI command for adversarial regression testing from the command line (R28).
- [x] T094: Add behavioural device fingerprinting module with statistical profiling and impersonation detection (R38).

## Phase 10 - Integration closure (completed)

- [x] T100: Add a device-state restore abstraction so checkpoint restore can drive adapter-backed rollback beyond detector baseline state.
- [x] T101: Export the policy state machine to TLA+/Alloy-friendly artifacts for offline verification workflows.
- [x] T102: Introduce a proof backend interface and witness export path for future Halo2 / SNARK integration.
- [x] T103: Replace static research-track status duplication with a single generated source consumed by docs, runtime status, and the admin console.
- [x] T104: Implement supply-chain attestation foundations: build manifest generation, trust-store loading, and verification hooks.

## Phase 11 - Paper readiness (completed)

- [x] T110: Generate extended test fixtures (100+ samples each) for four attack scenarios: benign steady-state, credential storm, slow escalation, and low-battery attack.
- [x] T111: Add a fixed-threshold baseline comparison detector for paper evaluation against the adaptive EWMA detector.
- [x] T112: Add a `bench` CLI command that runs the benchmark harness and prints precision/recall/F1/accuracy plus per-sample throughput.
- [x] T113: Add per-signal contribution percentage to `BenchmarkResult` for paper-ready attribution breakdowns.
- [x] T114: Clean up stale documentation references (supply-chain now partially implemented, Phase 10 complete, update counts and recommended-next section).

## Phase 12 - Complete research blueprint (completed)

- [x] T120: Deep OS enforcement engine — process control, network isolation, filesystem quarantine (R07, R09, R16).
- [x] T121: Hardware root-of-trust abstraction — software TPM with PCR extend/read/quote/seal/unseal (R16).
- [x] T122: Post-quantum Lamport one-time signatures with epoch-based key rotation and quantum-walk threat propagation (R04, R11, R21).
- [x] T123: Sigma-protocol ZK proof backend with commitment-challenge-response (R12).
- [x] T124: Gossip-based swarm coordination with fleet orchestration, weighted voting, mesh self-organisation, and negotiated security posture (R03, R23, R24, R37).
- [x] T125: Privacy-preserving coordination — differential privacy, federated averaging, secure aggregation, and forensic redaction (R08, R27, R40).
- [x] T126: Sandboxed bytecode VM for extensible policy rules with step/stack limits and rule compiler (R17).
- [x] T127: Threat intelligence store with IoC management, feed ingestion, deception engine, and attacker profiling (R15, R33).
- [x] T128: Side-channel detection — timing analysis, cache monitoring, frequency analysis, covert channel identification (R35).
- [x] T129: Digital twin simulation engine with device state modeling, what-if analysis, and fleet attack simulation (R31).
- [x] T130: Formal verification — explicit-state model checker with safety, reachability, and invariant checking (R02, R13).
- [x] T131: Regulatory compliance manager, causal analysis graph, multi-tenancy engine, edge-cloud hybrid workload offload, patch management, energy-aware scheduling, and model quantization (R10, R13, R14, R18, R19, R22, R25, R32, R34, R36).

## Phase 13 - Research agenda advancement (completed)

- [x] T132: Wire all Phase 12 modules into the runtime pipeline — threat intel, enforcement, digital twin, energy, side-channel, and compliance integrated into `execute()`.
- [x] T133: Add criterion micro-benchmarks for pipeline latency measurement — per-sample throughput, per-stage latency, and scaling benchmarks (Paper 1 enabler).
- [x] T134: Implement continual learning loop — Page-Hinkley drift detector with automatic baseline re-learning via `ContinualLearner` (R01).
- [x] T135: Implement policy composition algebra — `CompositePolicy` with `MaxSeverity`/`MinSeverity`/`LeftPriority`/`RightPriority` operators and conflict detection (R39, Paper 2 enabler).
- [x] T136: Update documentation — CHANGELOG, FEATURES, STATUS, README, and PROJECT_BACKLOG for Phase 13.

## Phase 14 — Full admin console integration (completed)

- [x] T137: Add 18 new API endpoints for all un-exposed feature modules — side-channel, quantum key rotation, privacy budget, WASM policy VM, fingerprint, adversarial harness, temporal monitor, deception engine, policy composition, drift detection, causal graph, patch management, workload offload, swarm posture, energy harvest.
- [x] T138: Wire Security Operations admin panel — enforcement quarantine, threat intel IOC management, side-channel risk display, deception engine deploy UI.
- [x] T139: Wire Fleet, Digital Twin & Testing admin panels — fleet device registration, swarm posture, digital twin simulation, adversarial harness execution.
- [x] T140: Wire Monitoring & Analysis admin panel — temporal monitor status/violations, correlation analysis, drift detection reset, fingerprint status, causal graph display.
- [x] T141: Wire Compliance, Quantum, Policy, Infrastructure & Formal Exports admin panels — compliance scoring, attestation, privacy budget, quantum key rotate, policy composition, WASM VM execute, energy harvest/consume, patch status, workload offload, TLA+/Alloy/witness download.

## Phase 15 — Integration test coverage & paper evaluation harnesses (completed)

- [x] T142: Add 49 new HTTP integration tests covering all API endpoints — auth, fleet, enforcement, threat-intel, digital-twin, compliance, energy, tenants, platform, correlation, side-channel, quantum, privacy, policy-vm, fingerprint, harness, monitor, deception, policy compose, drift, causal, patches, offload, swarm, energy harvest — with 401 auth rejection tests for every POST endpoint.
- [x] T143: Paper evaluation harnesses — per-sample latency benchmark (`run_latency_benchmark` with LatencyStats struct), audit chain scaling benchmark (`run_audit_scaling_benchmark` at 10–100K record sizes), with 4 new unit tests.
- [x] T144: Rewrite RESEARCH_TRACKS.md — update all 40 tracks from stale "Future"/"Planned"/"Scaffolded" to accurate "Implemented foundation" status with current repo-state descriptions.
- [x] T145: Update PAPER_TARGETS.md — close 5 Paper 1 gaps (latency benchmark, audit scaling, contribution aggregation, fixed-threshold comparator, criterion benchmarks), update Papers 2 and 3 prerequisites from "not started" to "met".
- [x] T146: Documentation and version updates — bump version 0.13.0, update all counts (77/77 tasks, 329 tests, 16 phases), update STATUS.md, CHANGELOG.md, README.md, site pages.

## Phase 16 — Production hardening & self-healing (completed)

- [x] T147: ML-DSA-65 post-quantum hybrid signatures — `MlDsaKeyPair` with deterministic signing, `HybridSignature` dual-verification (classical Lamport + PQ ML-DSA), `PqHybridCheckpoint` with sign/verify helpers. 8 new tests.
- [x] T148: TLS server configuration module — `TlsConfig` with cert/key paths, mTLS client CA, TLS version enforcement, cipher suite selection, Unix key-permission checks, `ListenerMode` abstraction. `GET /api/tls/status` endpoint. 10 unit + 1 integration test.
- [x] T149: Zero-downtime config hot-reload — `ConfigPatch` partial-update struct with validation and automatic rollback, `HotReloadResult`. `GET /api/config/current` and `POST /api/config/reload` endpoints. 3 unit + 4 integration tests.
- [x] T150: Mesh self-healing topology — BFS spanning-tree computation, connected-component partition detection, repair proposal algorithm (AddEdge, PromoteRelay, Reroute), `SwarmNode::self_heal()` and `apply_repair()`. `GET /api/mesh/health` and `POST /api/mesh/heal` endpoints. 12 unit + 2 integration tests.

## Phase 17 — Cross-platform XDR agent with live monitoring (completed)

- [x] T151: Cross-platform host telemetry collector — `collector.rs` (~680 lines) with `HostPlatform` enum, `detect_platform()`, `collect_sample()` dispatching per-OS metric collection (CPU, memory, temperature, network, auth, battery, processes, disk), `FileIntegrityMonitor` with SHA-256, `AlertRecord` with syslog/CEF, `run_monitor()` loop, `send_webhook()`, `parse_monitor_args()`. 12 unit tests.
- [x] T152: Simplified startup — `cargo run` (no args) defaults to combined serve+monitor, `cargo run -- start` for explicit combined mode, `cargo run -- monitor` for CLI-only headless monitor. Auto-creates `var/wardex.toml` on first run. Ctrl+C graceful shutdown via `register_ctrlc()`.
- [x] T153: Webhook & alert output — `send_webhook()` via ureq, `--syslog` and `--cef` CLI flags, `AlertRecord::to_syslog()` and `to_cef()` formatters.
- [x] T154: Server alert API & health — `GET /api/health`, `GET /api/alerts`, `GET /api/alerts/count`, `DELETE /api/alerts`, `GET /api/endpoints`, `POST /api/config/save`. Configurable CORS via `SENTINEL_CORS_ORIGIN`. 7 new integration tests.
- [x] T155: Admin console panels — Live Monitoring panel (auto-polling alert table at 3s, metric summary strip, health bar, CSV export), Settings panel (6 config sections), toast notification system, token show/hide toggle, `MonitorSettings` struct with nested `ConfigPatch` support.
- [x] T156: Documentation and version update — bump to v0.15.0, CHANGELOG, STATUS, README, FEATURES, PROJECT_BACKLOG, site, and runtime manifest updated. 387 tests (303 unit + 84 integration), 85/85 tasks, 17 phases.

## Recommended next build order

85 of 85 backlog items are complete. Phases 0–17 are complete.

All tasks are done.

## Code-quality sweep (post-Phase 7)

The following hardening fixes were applied across three code-review rounds:

- [x] CQ-01: Add `process_count` and `disk_pressure_pct` to `PersistedBaseline` — fixes data loss on checkpoint restore.
- [x] CQ-02: Replace CSV header heuristic with exact match against `CSV_HEADER` / `CSV_HEADER_LEGACY`.
- [x] CQ-03: Remove panicking `unwrap()` on `serde_json::from_str` round-trips in run-demo and analyze handlers — store `JsonReport` directly.
- [x] CQ-04: Replace `unwrap_or_default()` serialization with proper 500 error responses in three endpoints.
- [x] CQ-05: Fix CSV parse error line numbers — move `enumerate()` before `filter()`.
- [x] CQ-06: Fix `u32` overflow risk in `auth_burst_detected()` — use `u64` accumulator.
- [x] CQ-07: Guard ring buffers (`ReplayBuffer`, `CheckpointStore`) against capacity=0.
- [x] CQ-08: Rename misleading `ProofRegistry::verify()` to `contains()`.
- [x] CQ-09: Validate NaN/Infinity in `network_kbps` and `temperature_c` fields.
- [x] CQ-10: Validate `decay_rate` parameter in `/api/control/mode` (must be finite, 0.0–1.0).
- [x] CQ-11: Add client-side file size limit (10 MB) on admin console uploads.

## Code-quality sweep (post-Phase 8)

- [x] CQ-12: Fix JSONL line numbers in `/api/analyze` — enumerate before filter so errors report original line positions.
- [x] CQ-13: Use `saturating_add` for `observed_samples` in detector to prevent overflow.
- [x] CQ-14: Validate state machine transitions in `step()` via `is_legal()` before accepting.
- [x] CQ-15: Add test for illegal transition rejection in state machine.

## Code-quality sweep (post-Phase 9)

- [x] CQ-16: Use Bessel's correction (n−1) for fingerprint standard deviation to avoid inflated z-scores.
- [x] CQ-17: Guard against NaN/Inf propagation in `DeviceFingerprint::train()`.
- [x] CQ-18: Add test for zero-variance dimension sentinel z-score in fingerprinting.
- [x] CQ-19: Update R38 research track status from "future" to "foundation".
- [x] CQ-20: Feed state machine transitions to the temporal-logic monitor so `no_skip_escalation` is exercised.
