# Architecture

For the current API contract and server-state decomposition decisions, see
[`ARCHITECTURE_CONTRACT_STATE_SPINE.md`](ARCHITECTURE_CONTRACT_STATE_SPINE.md).

For the current product workflow and KPI decisions that bind operator journeys
to proof-bearing value, see
[`PRODUCT_WORKFLOW_METRICS_SPINE.md`](PRODUCT_WORKFLOW_METRICS_SPINE.md).

## Runtime pipeline

Wardex follows an edge-first control loop:

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
11. **Threat intelligence**
   - IOC matching against a local threat-intelligence store.
   - Enriches anomaly signals with known-bad indicator metadata.
12. **Enforcement**
   - Automated network blocking and process suspension driven by threat level.
   - NetworkEnforcer and ProcessEnforcer fire on severe/critical events.
13. **Digital twin simulation**
   - Deterministic discrete-event fleet simulation.
   - Predicts cascading failures and validates response strategies.
14. **Energy budget tracking**
   - Per-iteration energy accounting and proportional processing.
   - EnergyBudget.tick() enforces consumption limits.
15. **Side-channel detection**
   - Timing-based side-channel observation.
   - Statistical deviation detection across execution windows.
16. **Compliance scoring**
   - Evidence collection from audit, detection, and enforcement.
   - Quantitative compliance score per framework.

## Enterprise control plane overlays

The operator-facing control plane layers additional enterprise state on top of the core runtime loop:

1. **Identity-aware sessions and routing**
  - Requests can resolve as admin tokens, RBAC tokens, or persisted SSO sessions.
  - Session-backed identities carry role, `user_id`, group membership, and auth `source` metadata.
  - Hunt and content-pack mutations can declare a `target_group`; session-backed operators must belong to that group before the mutation or saved-hunt execution is accepted.
2. **Content lifecycle and bundle management**
  - Saved hunts and content packs are persisted in the enterprise snapshot alongside lifecycle state, canary percentage, recommended workflows, target groups, and rollout notes.
  - Detection engineers can move between rule tuning, hunt creation, and content-pack editing without leaving the detection workspace.
3. **Persisted automation and rollout history**
  - Playbook execution analytics and release rollout events are recorded into the enterprise snapshot as historical records.
  - Historical records survive restarts and are merged with live engine state so dashboards stay fresh without losing continuity.
4. **Program-level workbench aggregation**
  - The SOC workbench overview aggregates queue, cases, incidents, response posture, identity routing readiness, rollout history, content bundle adoption, automation history, and API analytics into one program surface.
  - Recommendation items are attached to that overview so the UI can pivot directly into settings, detection, infrastructure, or playbook review flows.

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
- `src/correlation.rs`
  - multi-signal Pearson correlation analysis and co-rising detection
- `src/monitor.rs`
  - temporal-logic runtime monitor with safety and bounded liveness properties
- `src/harness.rs`
  - adversarial testing harness with grammar-based evasion strategies
- `src/fingerprint.rs`
  - behavioural device fingerprinting with Mahalanobis-inspired distance
- `src/attestation.rs`
  - supply-chain attestation with SBOM generation and build manifests
- `src/fixed_threshold.rs`
  - static per-signal threshold detector for paper comparison
- `src/compliance.rs`
  - compliance evidence collection and framework scoring
- `src/digital_twin.rs`
  - deterministic discrete-event fleet simulation engine
- `src/edge_cloud.rs`
  - edge-cloud hybrid offload decision engine
- `src/energy.rs`
  - energy budget tracking and proportional processing control
- `src/enforcement.rs`
  - automated network blocking and process suspension
- `src/multi_tenant.rs`
  - tenant-isolated security contexts for multi-tenancy
- `src/privacy.rs`
  - privacy-preserving forensic evidence handling
- `src/quantum.rs`
  - post-quantum Lamport one-time signatures
- `src/side_channel.rs`
  - timing-based side-channel attack detection
- `src/swarm.rs`
  - swarm coordination protocol with peer discovery and digest gossip
- `src/threat_intel.rs`
  - local threat-intelligence store with IOC matching
- `src/wasm_engine.rs`
  - Wasm extension sandbox for user-defined detection policies

## Mapping to the research blueprint

The codebase has completed all 14 phases (0–13) of the backlog. Here is how the implementation maps to the research tracks:

- **R01 Learned Multi-Modal Anomaly Detection**
  - Implemented as a practical adaptive detector foundation with 8 signal dimensions.
  - Replay buffer provides windowed statistics for continual learning foundation.
  - Page-Hinkley drift detection triggers automatic baseline re-learning (Phase 13).
  - Missing: differential privacy and proof generation.
- **R02 Formally Verifiable Policy Engine**
  - Policy state machine records and validates all transitions against formally defined legal rules.
  - Transition trace exportable for TLA+/Alloy verification.
  - Policy composition algebra with conflict resolution operators (Phase 13).
  - Missing: actual TLA+/Alloy model checking integration.
- **R05 Model Poisoning Detection and Self-Recovery**
  - Four poisoning heuristics analyze replay buffer for data manipulation attempts.
  - Baseline adaptation controls (freeze, decay) support containment during suspected poisoning.
  - Missing: verified checkpoint rollback and recovery proofs.
- **R06 Energy-Aware Verifiable Isolation**
  - Battery-aware policy downgrades and pluggable action adapters are implemented.
  - Energy budget tracking with per-iteration tick consumption (Phase 12/13).
  - Missing: formal proof machinery and hardware-level isolation enforcement.
- **R09 Adaptive Response Strength**
  - Implemented through response selection based on score and battery, with pluggable adapter chain.
  - Automated enforcement module with network blocking and process suspension (Phase 12/13).
  - Adaptation mode controls (Normal, Frozen, Decay) refine detector sensitivity.
- **R10 Verifiable Rollback and Forensic Recovery**
  - Checkpoints captured on severe/critical events. Forensic bundle export available.
  - Proof-carrying updates bind every baseline change with cryptographic evidence.
  - Missing: real device state restore and cryptographic proof of restoration.
- **R11 Post-Quantum Secure Audit Logs**
  - SHA-256 cryptographic digest chain with signed checkpoints and chain verification.
  - Lamport one-time signatures for quantum-resistant signing (Phase 12).
- **R13 Regulatory-Compliant Verifiable Export**
  - Forensic bundle export and structured JSON reports provide a foundation.
  - Benchmark harness enables FP/FN measurement for regulatory compliance evidence.
  - Missing: selective disclosure and ZK-based redaction.

- **R15 Cross-Device Threat Intelligence Sharing**
  - Local threat-intelligence store with IOC matching and severity ratings (Phase 12).
  - Wired into runtime pipeline for per-sample enrichment (Phase 13).
- **R17 Wasm-Based Extensible Policies**
  - Wasm extension sandbox for user-defined detection policies (Phase 12).
- **R23 Verifiable Swarm Defence Coordination**
  - Swarm coordination protocol with peer discovery and digest gossip (Phase 12).
- **R31 Digital Twin Fleet Simulation**
  - Deterministic discrete-event fleet simulation engine (Phase 12).
  - Wired into runtime pipeline for per-sample predictive analysis (Phase 13).
- **R34 Secure Multi-Tenancy Isolation**
  - Tenant-isolated security contexts for multi-tenancy (Phase 12).
- **R35 Side-Channel Attack Detection**
  - Timing-based statistical side-channel detection (Phase 12).
  - Wired into runtime pipeline for per-sample observation (Phase 13).
- **R36 Edge-Cloud Hybrid Offload**
  - Edge-cloud offload decision engine (Phase 12).
- **R39 Formal Policy Composition**
  - Policy composition algebra with MaxSeverity, MinSeverity, LeftPriority, RightPriority operators (Phase 13).
- **R40 Privacy-Preserving Incident Forensics**
  - Privacy-preserving forensic evidence handling with field redaction and k-anonymity (Phase 12).

## Frontend architecture (admin-console)

The admin console is a single-page React application served from the `/admin/` path.

### Stack

- **React 19** with React Router for client-side routing
- **Vite** for dev server, HMR, and production builds
- **Vitest** + Testing Library for unit tests; **Playwright** for E2E
- **Recharts** for dashboard visualisations

### Component tree

```
App
├─ AuthProvider          (token auth, auto-reconnect from localStorage)
│  └─ RoleProvider       (admin/analyst/viewer derived from /api/auth/session)
│     └─ ThemeProvider   (dark/light mode, persisted to localStorage)
│        └─ ToastProvider (notification system with timed dismissal)
│           ├─ Sidebar   (role-filtered nav, collapsible, keyboard shortcuts)
│           ├─ TopBar    (version badge, search trigger, auth form / badge)
│           └─ Routes    (each wrapped in ErrorBoundary + Suspense)
│              ├─ Dashboard         (lazy, 15+ widget API calls via useApi)
│              ├─ LiveMonitor       (lazy, alert stream/grouped/processes tabs)
│              ├─ ThreatDetection   (lazy, analyst+ role)
│              ├─ FleetAgents       (lazy)
│              ├─ SecurityPolicy    (lazy, analyst+ role)
│              ├─ SOCWorkbench      (lazy, analyst+ role)
│              ├─ Infrastructure    (lazy, analyst+ role)
│              ├─ ReportsExports    (lazy)
│              ├─ Settings          (lazy, admin role)
│              └─ HelpDocs          (lazy)
├─ SearchPalette         (⌘K global search across alerts, agents, rules)
├─ NotificationToast     (WebSocket-driven alert toasts)
└─ OnboardingWizard      (first-visit guided tour)
```

### State management

All state management uses React Context + `useReducer`/`useState`:

| Context | Purpose | Persistence |
|---------|---------|-------------|
| `AuthContext` | Token, `authenticated` flag, `connect()`/`disconnect()` | `localStorage` |
| `RoleContext` | Current role plus session `groups`, `userId`, and auth `source` | None (fetched on auth) |
| `ThemeContext` | Dark mode toggle | `localStorage` |
| `ToastContext` | Notification queue with auto-dismiss | In-memory |

### API client (`api.js`)

A unified `request()` helper sends all HTTP calls with:
- Bearer token in `Authorization` header (auto-set via `setToken()`)
- Error objects carrying `status` and `body` for catch-block dispatch
- `withSignal()` wrapper for AbortController integration

~160 endpoint functions organised by domain (auth, health, alerts, agents, cases, playbooks, compliance, export, hunting, etc.).

### `useApi` hook

The primary data-fetching hook provides `{ data, loading, error, reload }`:
- Automatically cancels in-flight requests on unmount or re-fetch
- Supports `skip` option for conditional fetching
- Error state enables per-widget error display

### Code splitting

Vite `manualChunks` splits the bundle into:
- `vendor` — React, React DOM, React Router
- `charts` — Recharts

All route components are `React.lazy()` loaded. The dev server proxies `/api` to the backend at `http://127.0.0.1:8080`.

## Design principle

The code stays explicit about scope:

- implemented features run now
- partially wired features expose structure without overstating capability
- advanced tracks stay as backlog items rather than implied promises
