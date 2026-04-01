# Implementation Status

Updated: current

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
- Deep OS enforcement engine: process control (kill/suspend/resume/CPU-limit via signals), network enforcement (firewall rules, block/rate-limit/port-block), filesystem quarantine with integrity hashing (R07, R09, R16)
- Software TPM with PCR extend/read/quote, seal/unseal operations, and boot-time attestation (R16)
- Self-healing network topology with BFS-based path recovery and auto-remediation (R07)
- Post-quantum Lamport one-time signature scheme (256-pair SHA-256) with full sign/verify cycle (R04, R11)
- Epoch-based post-quantum key rotation manager with active/retiring/expired lifecycle (R21)
- Quantum-walk anomaly propagation engine with Grover-like coin operator (R04)
- Swarm coordination protocol: device registry, gossip with anti-amplification, weighted voting with quorum, negotiated security posture, mesh topology self-organisation (R03, R23, R24, R37)
- Fleet orchestration with health reporting, policy distribution, and device status management (R03)
- Differential privacy with Laplace noise injection, privacy accountant, and budget tracking (R08)
- Federated learning coordinator with weighted averaging, DP noise, and convergence tracking (R27)
- Secure aggregation with masking-based contributions and commitment verification (R27)
- Privacy-preserving forensic bundle export with configurable redaction levels (R40)
- Safe bytecode VM for extensible policy rules: 19-opcode interpreter with step/stack limits, rule compiler, and extension registry (R17)
- Threat intelligence store with IoC management (8 types), exact and fuzzy matching, feed ingestion, and signal correlation (R15, R33)
- Deception engine with 5 decoy types (honeypot, honeyfile, honey-credential, honey-service, canary) and cross-decoy attacker profiling (R33)
- Side-channel detection: timing analysis (Welford's algorithm), cache-line probing detection, frequency analysis (DFT), and covert channel identification (R35)
- Digital twin simulation engine with device state modeling, 8 event types, what-if analysis, and fleet attack simulation with probabilistic lateral movement (R31)
- Explicit-state model checker with BFS: safety, reachability, and invariant checking with counterexample generation (R02, R13)
- Regulatory compliance manager supporting 5 frameworks (GDPR, NIST 800-53, IEC 62443, CIS Controls, ISO 27001) with evidence tracking (R19)
- Causal analysis graph with root-cause BFS, path-strength computation, and false-positive probability estimation (R13)
- Multi-tenancy engine with 4 tiers (Free/Standard/Enterprise/Government), per-tenant quotas, SHA-256 API-key authentication, and device allocation limits (R34)
- Edge-cloud hybrid workload offload with capacity-aware tier selection (R22, R36)
- Cross-platform capability detection for 8 platforms (Linux/macOS/Windows x86/ARM + Android/iOS/RTOS/Wasm) (R25, R32)
- Patch lifecycle manager with severity-ordered planning and CVE tracking (Available→Staged→Installed→RolledBack) (R32)
- Sequence-based edge-cloud sync tracker with acknowledgement and loss detection (R36)
- Energy budget tracking with 6 power states, power-aware task scheduling, and energy harvesting manager (solar/vibration/thermal/RF) (R14)
- Model quantization engine (int8/int4) with symmetric quantization, compression ratios, and SHA-256 bound quantization proofs (R18)
- Sigma-protocol ZK proof backend with hash-based commitment-challenge-response (R12)
- Fleet, enforcement, threat-intel, digital-twin, compliance, energy, multi-tenancy, and platform API endpoints in the admin server
- 276 automated tests (255 unit + 21 integration) covering all 35 modules
- All 40 research tracks at foundation implementation status
- Runtime pipeline wiring: threat intel, enforcement, digital twin, energy, side-channel, and compliance modules integrated into `execute()` with enrichment data flowing through all stages (T132)
- Criterion micro-benchmarks: per-sample pipeline throughput (~55K samples/sec), per-stage latency, and scaling benchmarks for paper evaluation (T133)
- Continual learning loop: Page-Hinkley drift detection with automatic baseline re-learning via `ContinualLearner` for concept drift and adversarial adaptation (T134, R01)
- Policy composition algebra: `CompositePolicy` with `MaxSeverity`/`MinSeverity`/`LeftPriority`/`RightPriority` operators and conflict detection for multi-rule evaluation (T135, R39)
- `RunResult` enriched with enforcement actions, threat intel matches, energy state, side-channel report, and compliance score
- 329 automated tests (259 unit + 70 integration) covering all 35 modules
- **Phase 14 — Full admin console integration** (T137–T141): 18 new API endpoints exposing all modules, 8 new interactive admin UI panels:
  - Security Operations: enforcement quarantine, threat intel IOC management, side-channel risk, deception deploy
  - Fleet & Swarm: device registration, swarm posture, platform capabilities
  - Digital Twin & Testing: twin simulation, adversarial harness execution
  - Monitoring & Analysis: temporal monitor status/violations, correlation, drift reset, fingerprint, causal graph
  - Compliance & Privacy: compliance scoring, attestation status, privacy budget
  - Quantum & Policy: key rotation, policy composition, WASM VM execution
  - Infrastructure: energy harvest/consume, tenant count, patch management, workload offload
  - Formal Exports: TLA+ module, Alloy spec, witness bundle download
- **Phase 15 — Integration test coverage & paper evaluation harnesses** (T142–T146): 49 new HTTP integration tests for all API endpoints with auth rejection coverage, per-sample latency benchmark, audit chain scaling benchmark, RESEARCH_TRACKS.md and PAPER_TARGETS.md fully synchronised with implementation status.
- **Phase 16 — Production hardening & self-healing** (T147–T150): ML-DSA-65 post-quantum hybrid signatures with classical+PQ dual verification, TLS server configuration module with mTLS and certificate validation, zero-downtime config hot-reload with validation and automatic rollback, mesh self-healing topology with BFS spanning tree, partition detection, and repair proposal/application.
- **Phase 17 — Cross-platform XDR agent with live monitoring** (T151–T156): Cross-platform host telemetry collector (`collector.rs`) with OS-specific metric collection (CPU, memory, temperature, network, auth, battery, processes, disk), file-integrity monitoring with SHA-256 baselines, webhook/syslog/CEF alert output, simplified `cargo run` startup defaulting to combined serve+monitor mode, server alert API with health/alerts/endpoints, admin console Live Monitoring panel with auto-polling alert table and Settings editor with MonitorSettings, toast notifications, token show/hide toggle.
- **Phase 18 — XDR fleet management with SIEM integration** (T157–T163): Central server + lightweight agent architecture with single-binary mode selection (`wardex server` / `wardex agent`), agent enrollment with token-based authentication and heartbeat staleness detection (`enrollment.rs`), agent client for endpoint telemetry forwarding and policy reception (`agent_client.rs`), cross-agent event forwarding with correlation (`event_forward.rs`), versioned policy distribution (`policy_dist.rs`), cross-platform service installation via systemd/launchd/sc.exe (`service.rs`), SIEM integration with Splunk HEC, Elasticsearch bulk, and generic JSON backends plus pull-based threat intel (`siem.rs`), agent auto-update with SHA-256 binary verification (`auto_update.rs`), XDR Fleet Dashboard in admin console, 15+ new API endpoints.
- **Phase 19 — Professional admin console & local auto-monitoring** (T164–T167): Complete rewrite of the admin console (`site/admin.html`) as a dark-themed, single-file HTML+CSS+JS application with 10 interactive sections (Dashboard, Live Monitor, Threat Detection, Fleet & Agents, Security Policy, Incident Response, Infrastructure, Reports & Exports, Settings, Help & Docs), demo mode for browser-side XDR simulation, sparkline charts, host telemetry gauges, `/api/threads/status` endpoint for background thread introspection, background auto-monitoring thread in the server process, BSL 1.1 license, collapsible global activity log panel on all views, icon-only sidebar at ≤1024 px with hover tooltips, and Ctrl+K/⌘+K quick-focus shortcut.
- **Phase 20 — UX hardening & licensing** (T168–T171): Global collapsible activity log panel docked to every view, icon-only responsive sidebar collapsing to 52 px at ≤1024 px with CSS tooltip fallback, Ctrl+K/⌘+K keyboard shortcut, Business Source License 1.1 replacing MIT placeholder, license references in README, Cargo.toml, admin console footer, and website footer.
- **Phase 21 — Detection engine expansion & server security hardening** (T172–T180): Velocity rate-of-change detector (first/second derivative analysis with σ-outlier flagging), Shannon entropy detector (per-axis sliding-window analysis for constant-traffic and randomised-evasion detection), compound multi-axis threat detector (coordinated attack scoring multiplier), monitor thread enrichment with all three new detectors, `/api/detection/summary` endpoint, detection analysis panel in admin console, server security hardening (canonicalize path traversal, 10 MB body limit, security headers, CORS on static files), Help & Docs updated with new detection method documentation.
- 635 automated tests covering all 58 modules
- **Phase 22 — Graceful shutdown, alert detail views, help redesign & code review hardening** (T181–T187): Real Ctrl+C / SIGTERM graceful shutdown via `ctrlc` crate, `POST /api/shutdown` endpoint with server unblock, shutdown button in admin Settings with double-confirmation, expandable alert detail rows with full telemetry snapshot and detection analysis, `GET /api/alerts/{index}` API endpoint, help section redesign with three categorised sections, code review hardening (JSON injection fixes via `serde_json::json!()`, bounded body reads for chunked encoding via `read_body_limited()`, auth on sensitive GET endpoints, consistent security headers).
- **Phase 23 — OCSF normalization, Sigma detection, automated response, feature flags, process tree, encrypted spool, and RBAC** (T188–T194): OCSF event normalization with dead-letter queue for parse-rejected events, 25 Sigma detection rules (SE-001 through SE-025) spanning credential attacks, lateral movement, data exfiltration, cryptomining, and privilege escalation, automated response engine with approval workflow and configurable playbooks, feature flag system with user/group/percentage targeting and A/B testing, process tree analysis with deep-chain detection and orphan tracking, encrypted local event spool with retry/dead-letter semantics, role-based access control with user/role management.
- **Phase 24 — Platform collectors, analyst console, SIEM formats, and DLQ wiring** (T195–T203): Windows collector with WMI/registry/event-log parsing (13 tests), Linux collector with /proc and journalctl parsing (19 tests), macOS collector with sysctl/IOKit/unified-log parsing (15 tests), Elastic ECS and QRadar LEEF SIEM output formats, analyst console with case management (CRUD, status workflow, priority, assignee, timeline), alert queue with acknowledgement and assignment, full-text event search with faceted filtering, investigation timeline and graph builder, remediation approval workflow, dead-letter queue wired into server API endpoints (`/api/dlq`, `/api/dlq/stats`, `DELETE /api/dlq`), OCSF schema registry endpoint (`/api/ocsf/schema/version`), 5 operational runbooks (incident response, deployment, monitoring, troubleshooting, disaster recovery).
- **Phase 25 — Code review hardening and security improvements** (T204–T207): Replaced insecure XOR spool cipher with SHA-256 CTR mode for encrypted event buffering, wired AuditLog into HTTP request handling for comprehensive API audit trail, activated RBAC enforcement on sensitive API endpoints, eliminated all dead-code suppressions.

## Partially wired

(all research tracks now have foundation implementations)

## Not implemented yet

(all research tracks now have foundation implementations — production hardening and external integrations remain for future work)

## Practical milestone summary

The repository has completed Phases 0–25, providing a comprehensive edge security runtime that spans detection, enforcement, fleet orchestration, formal verification, privacy, post-quantum cryptography, and a professional browser-based admin console. **Phase 25** hardens the codebase with a SHA-256 CTR mode spool cipher replacing the insecure XOR cipher, comprehensive API audit logging via `AuditLog::record()` wired into every HTTP request, RBAC enforcement on sensitive endpoints, and elimination of all `#[allow(dead_code)]` suppressions. **Phase 24** adds three platform-specific collectors (Windows WMI/registry/event-log, Linux /proc/journalctl, macOS sysctl/IOKit/unified-log), a full analyst console with case management, alert queue, event search, investigation graph, and remediation approval, Elastic ECS and QRadar LEEF SIEM output formats, dead-letter queue API endpoints, and 5 operational runbooks. **Phase 23** introduces OCSF event normalization, 25 Sigma detection rules, automated response with approval workflow, feature flags, process tree analysis, encrypted event spool, and role-based access control. **Phase 22** adds graceful shutdown via CLI (Ctrl+C / SIGTERM) and web console (`POST /api/shutdown`), expandable alert detail rows with full telemetry snapshots and detection analysis, a redesigned Help section with categorised layout, and code review hardening including JSON injection fixes, bounded body reads for chunked encoding, authentication on sensitive GET endpoints, and consistent security headers.
