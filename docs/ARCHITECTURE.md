# Architecture

## Runtime pipeline

SentinelEdge follows an edge-first control loop:

1. **Telemetry ingestion**
   - CSV or JSONL samples are parsed into typed `TelemetrySample` records.
   - Format auto-detected by file extension. Both legacy 8-column and extended 10-column CSV are supported.
2. **Adaptive baseline + anomaly scoring**
   - An `AnomalyDetector` maintains an EWMA-like baseline for "normal" behavior.
   - Deviations across CPU, memory, temperature, bandwidth, auth failures, integrity drift, process count, and disk pressure are weighted into a single anomaly score.
   - Baselines can be persisted between runs and reloaded on startup.
3. **Policy evaluation**
   - A `PolicyEngine` converts the anomaly signal into a threat level and response action.
   - Battery level can soften heavy-handed actions to support graceful degradation on constrained devices.
4. **Response execution**
   - Pluggable `ActionAdapter` trait implementations (throttle, quarantine, isolate, logging) execute the decided response.
   - A `CompositeAdapter` chains multiple adapters for multi-stage enforcement.
5. **Audit trail**
   - Every detection and response step is chained into an append-only audit log with SHA-256 cryptographic hash links.
   - Signed checkpoints are inserted at configurable intervals.
   - Chain integrity can be verified programmatically.
6. **Rollback checkpoints**
   - A bounded `CheckpointStore` captures detector state snapshots when severe/critical thresholds are crossed.
   - Enables future rollback to a known-good state after suspected compromise.
7. **Proof-carrying updates**
   - Every baseline state change is bound to a SHA-256 proof linking prior state, transform, and post state.
   - A `ProofRegistry` accumulates and verifies all proofs in a session.
8. **Policy state machine**
   - An explicit `PolicyStateMachine` records and validates all threat-level transitions.
   - Legal transitions (escalation, de-escalation, battery downgrades) are formally defined.
   - Full transition trace is exportable for future TLA+/Alloy verification.
9. **Replay buffer & poisoning analysis**
   - A bounded `ReplayBuffer` retains recent telemetry for windowed statistical analysis.
   - Four poisoning heuristics (mean shift, variance spike, drift accumulation, auth burst) detect data manipulation attempts.
10. **Output**
   - Console reports with per-sample detail.
   - Structured JSON reports for SIEM ingestion.
  - Structured status JSON snapshots for the browser admin console.
   - JSONL streaming output for alert-only events.
   - Forensic evidence bundles combining audit log, summary, and checkpoints.

## Implemented modules

- `src/config.rs`
  - TOML/JSON configuration loading and serialization
- `src/telemetry.rs`
  - CSV and JSONL input parsing with field validation
- `src/detector.rs`
  - adaptive scoring logic, anomaly explanations, baseline persistence
- `src/policy.rs`
  - response mapping for nominal/elevated/severe/critical states
- `src/actions.rs`
  - pluggable device action adapters (throttle, quarantine, isolate, logging)
- `src/audit.rs`
  - SHA-256 cryptographic digest chain with signed checkpoints and chain verification
- `src/baseline.rs`
  - serializable baseline state for persistence between runs
- `src/checkpoint.rs`
  - bounded rollback checkpoint ring buffer
- `src/report.rs`
  - structured JSON and JSONL report generation for SIEM
- `src/forensics.rs`
  - forensic evidence bundle exporter
- `src/proof.rs`
  - proof-carrying update metadata with SHA-256 binding digests and verification
- `src/state_machine.rs`
  - formally checkable policy state machine with legal transition validation
- `src/replay.rs`
  - bounded ring-buffer replay buffer with windowed statistics
- `src/poisoning.rs`
  - four poisoning heuristics: mean shift, variance spike, drift accumulation, auth burst
- `src/benchmark.rs`
  - FP/FN benchmark harness with precision, recall, F1, and accuracy metrics
- `src/server.rs`
  - HTTP server with token-authenticated API for browser admin console
- `src/runtime.rs`
  - orchestration, proof registry, state machine, replay buffer, summaries, and CLI

## Mapping to the research blueprint

The codebase has completed all 8 phases (0–7) of the backlog. Here is how the implementation maps to the research tracks:

- **R01 Learned Multi-Modal Anomaly Detection**
  - Implemented as a practical adaptive detector foundation with 8 signal dimensions.
  - Replay buffer provides windowed statistics for continual learning foundation.
  - Missing: on-device continual learning, differential privacy, and proof generation.
- **R02 Formally Verifiable Policy Engine**
  - Policy state machine records and validates all transitions against formally defined legal rules.
  - Transition trace exportable for TLA+/Alloy verification.
  - Missing: actual TLA+/Alloy model checking integration.
- **R05 Model Poisoning Detection and Self-Recovery**
  - Four poisoning heuristics analyze replay buffer for data manipulation attempts.
  - Baseline adaptation controls (freeze, decay) support containment during suspected poisoning.
  - Missing: verified checkpoint rollback and recovery proofs.
- **R06 Energy-Aware Verifiable Isolation**
  - Battery-aware policy downgrades and pluggable action adapters are implemented.
  - Missing: formal proof machinery and hardware-level isolation enforcement.
- **R09 Adaptive Response Strength**
  - Implemented through response selection based on score and battery, with pluggable adapter chain.
  - Adaptation mode controls (Normal, Frozen, Decay) refine detector sensitivity.
- **R10 Verifiable Rollback and Forensic Recovery**
  - Checkpoints captured on severe/critical events. Forensic bundle export available.
  - Proof-carrying updates bind every baseline change with cryptographic evidence.
  - Missing: real device state restore and cryptographic proof of restoration.
- **R11 Post-Quantum Secure Audit Logs**
  - SHA-256 cryptographic digest chain with signed checkpoints and chain verification.
  - Missing: post-quantum signature algorithms.
- **R13 Regulatory-Compliant Verifiable Export**
  - Forensic bundle export and structured JSON reports provide a foundation.
  - Benchmark harness enables FP/FN measurement for regulatory compliance evidence.
  - Missing: selective disclosure and ZK-based redaction.

## Design principle

The code stays explicit about scope:

- implemented features run now
- partially wired features expose structure without overstating capability
- advanced tracks stay as backlog items rather than implied promises
