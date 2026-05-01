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

## Phase 18 — XDR fleet management with SIEM integration (completed)

- [x] T157: Add token-based agent enrollment with heartbeat staleness tracking and persistent registry storage.
- [x] T158: Add lightweight agent client mode for enrollment, heartbeat, event forwarding, policy fetch, and update checks.
- [x] T159: Add cross-agent event forwarding with correlation-aware fleet event storage.
- [x] T160: Add versioned policy distribution bundles with rollback history.
- [x] T161: Add cross-platform service installation support for systemd, launchd, and Windows service control.
- [x] T162: Add SIEM integrations for Splunk HEC, Elasticsearch bulk, and generic JSON export with feed ingestion hooks.
- [x] T163: Add agent auto-update foundations with SHA-256 verification and path traversal protection.

## Phase 19 — Professional admin console & local auto-monitoring (completed)

- [x] T164: Add background local-host monitoring with telemetry history and thread-status introspection endpoints.
- [x] T165: Rewrite the admin console as a professional single-file application with dashboard, live monitor, and fleet views.
- [x] T166: Add browser-side demo mode for synthetic attack simulation without mutating server state.
- [x] T167: Expand Help & Docs with architecture, detection, API reference, and getting-started guidance.

## Phase 20 — UX hardening & licensing (completed)

- [x] T168: Add a global collapsible activity log panel across all admin views.
- [x] T169: Add responsive icon-only sidebar behavior for narrow viewports.
- [x] T170: Add Ctrl+K / Cmd+K keyboard shortcut support for rapid navigation.
- [x] T171: Replace placeholder licensing with BSL 1.1 and propagate references through docs and site assets.

## Phase 21 — Detection expansion & server security hardening (completed)

- [x] T172: Add a velocity rate-of-change detector for first/second-derivative anomaly analysis.
- [x] T173: Add a Shannon entropy detector for behavioural randomness and constant-traffic anomalies.
- [x] T174: Add a compound multi-axis threat detector for coordinated attack scoring.
- [x] T175: Wire advanced detectors into the local monitoring thread and runtime pipeline.
- [x] T176: Add `/api/detection/summary` and detection-analysis UI coverage.
- [x] T177: Harden static-file serving with canonical path traversal protection.
- [x] T178: Enforce bounded request body sizes for server endpoints.
- [x] T179: Add consistent security headers and CORS handling on server responses.
- [x] T180: Update Help & Docs with the expanded detection pipeline and server security behavior.

## Phase 22 — Graceful shutdown, alert details & code review hardening (completed)

- [x] T181: Add real Ctrl+C / SIGTERM graceful shutdown using the `ctrlc` crate.
- [x] T182: Add `POST /api/shutdown` and admin console shutdown controls with safety confirmation.
- [x] T183: Add expandable alert detail rows with telemetry snapshots and detection analysis.
- [x] T184: Add `GET /api/alerts/{index}` for detailed alert inspection.
- [x] T185: Redesign Help & Docs into categorised sections for operators.
- [x] T186: Harden JSON construction and bounded body reads in reviewed HTTP paths.
- [x] T187: Require authentication on sensitive GET endpoints and standardize security headers.

## Phase 23 — OCSF, Sigma, response, feature flags, process tree, spool & RBAC (completed)

- [x] T188: Add OCSF event normalization with schema registry and dead-letter queue support.
- [x] T189: Add Sigma rule engine coverage with built-in detection content and statistics endpoints.
- [x] T190: Add automated response orchestration with approval workflow and playbooks.
- [x] T191: Add feature flags with user/group/percentage targeting.
- [x] T192: Add process-tree analysis with deep-chain and orphan detection.
- [x] T193: Add encrypted local event spool with retry and dead-letter semantics.
- [x] T194: Add role-based access control with user management and endpoint permission mapping.

## Phase 24 — Platform collectors, analyst console, SIEM formats & DLQ wiring (completed)

- [x] T195: Add Windows collector support with WMI, registry, and Event Log parsing.
- [x] T196: Add Linux collector support with `/proc`, journalctl, and service enumeration.
- [x] T197: Add macOS collector support with sysctl, IOKit, and unified-log parsing.
- [x] T198: Add Elastic ECS SIEM output formatting.
- [x] T199: Add QRadar LEEF SIEM output formatting.
- [x] T200: Add analyst case management workflows and APIs.
- [x] T201: Add analyst alert queue acknowledgement and assignment workflows.
- [x] T202: Add full-text event search, investigation timeline, and graph builder support.
- [x] T203: Wire dead-letter queue APIs and operational runbooks into the platform and admin console.

## Phase 25 — Code review hardening & security improvements (completed)

- [x] T204: Replace the insecure XOR spool cipher with SHA-256 CTR-style keystream generation.
- [x] T205: Wire API audit logging into the HTTP request lifecycle.
- [x] T206: Activate RBAC enforcement on sensitive write endpoints.
- [x] T207: Remove dead-code suppressions from reviewed server audit/RBAC paths and document the remaining platform-specific exceptions accurately.

## Phase 26 — Security audit fixes (completed)

- [x] T208: Fix endpoint-aware rate limiting so authenticated admin read traffic no longer self-triggers 429 responses under normal polling.
- [x] T209: Reduce admin console polling pressure by slowing live-monitor cadence and refreshing telemetry history less aggressively.
- [x] T210: Harden the default CORS origin to `http://localhost` and align runtime behavior with the documented security posture.
- [x] T211: Correct Phase 25/26 status and changelog claims around dead-code suppressions, audit behavior, and backlog state.

## Phase 28 — Production hardening (completed)

- [x] T219: Add token TTL with configurable session expiry (`security.token_ttl_secs`) and automatic expired-token rejection.
- [x] T220: Add token rotation endpoint (`POST /api/auth/rotate`) with immediate invalidation and TTL reset.
- [x] T221: Add session info endpoint (`GET /api/session/info`) with uptime, token age, TTL, and expiry status.
- [x] T222: Add configurable retention policies (`[retention]` config) for audit, alert, and event record limits.
- [x] T223: Add retention status and apply endpoints (`GET /api/retention/status`, `POST /api/retention/apply`).
- [x] T224: Add audit chain verification endpoint (`GET /api/audit/verify`) with `verify_and_report()` and `apply_retention()`.
- [x] T225: Add spool per-tenant partitioning with `tenant_id`, `enqueue_with_tenant()`, `entries_for_tenant()`, and `tenant_counts()`.
- [x] T226: Add mTLS configuration (`[security]` config section with `require_mtls_agents` and `agent_ca_cert_path`).
- [x] T227: Add Dockerfile with multi-stage build, non-root user, health check, and `docker-compose.yml`.
- [x] T228: Add systemd service unit (`deploy/wardex.service`) with security hardening and launchd plist (`deploy/com.wardex.agent.plist`).
- [x] T229: Add 5 chaos/fault injection integration tests and 6 API integration tests + 8 unit tests.

## Phase 27 — Operational contract & production hardening backlog

- [x] T212: Publish OpenAPI coverage for all public HTTP APIs and verify it in CI.
- [x] T213: Define schema lifecycle policy covering compatibility, migration, and fixture validation.
- [x] T214: Add backup and restore validation with explicit disaster-recovery verification steps.
- [x] T215: Define service-level objectives, error budgets, and operator-facing observability acceptance criteria.
- [x] T216: Document and scaffold regional, single-tenant, and relay deployment models.
- [x] T217: Promote the threat model into the primary documentation set and release/phase acceptance criteria.

## Phase 29 — Console parity & operator usability

- [x] T230: Create and maintain a feature-to-UI coverage matrix so every capability in `FEATURES.md` maps to a reachable admin-console surface or an explicit backlog gap.
- [x] T231: Replace broken or raw-json Security Policy workflows with working forms and structured result views for policy composition, digital twin simulation, adversarial harness runs, deception deployment, and enforcement quarantine.
- [x] T232: Complete operator-first threat-intel, enrichment, and deception management surfaces with browse/filter/action workflows instead of status-only summaries.
- [x] T233: Finish structured compliance, GDPR, PII, and evidence-export workflows in the browser console so governance features are usable without manual API calls.
- [x] T234: Add deep links, guided pivots, and workflow recommendations between Dashboard, Threat Detection, SOC Workbench, UEBA, NDR, Attack Graph, Infrastructure, and Reports.

## Phase 30 — Analyst workflow depth & realtime

- [x] T235: Harden authenticated realtime analyst transport UX with connection-state visibility, session recovery, and filtered live-event controls.
- [x] T236: Expand investigation planner and active-investigation tracking with step progress, notes, auto-query pivots, and case handoff support.
- [x] T237: Promote detection efficacy, ATT&CK gap, suppression noise, and content-pack rollout signals into first-class operator drill-down surfaces.
- [x] T238: Add customizable dashboards with persisted analyst/admin presets and shared layout support.
- [x] T239: Close queue-to-hunt, hunt-to-case, and workflow-to-response usability gaps across the SOC workflow.

## Phase 31 — Platform scale, configuration, and docs completion

- [x] T240: Finish ClickHouse-backed long-retention history UX, retention controls, and validation against real deployments.
- [x] T241: Add structured cloud-collector and secrets-manager setup flows with validation, health, and ingestion visibility.
- [x] T242: Add API, SDK, and GraphQL parity diagnostics plus an operator-facing API explorer for supportability and contract verification.
- [x] T243: Deliver searchable, versioned documentation with console-linked runbooks and deployment guidance.
- [x] T244: Keep `STATUS.md`, roadmap, release, packaging, and support docs aligned with the shipped product surface.

## Phase 32 — Acceptance and regression closure

- [x] T245: Expand Playwright and browser regression coverage across Security Policy, enterprise SSO, investigations, dashboards, and advanced operator workflows.
- [x] T246: Add a release acceptance checklist that enforces routed UI coverage, structured presentation, and no broken JSON-only dead ends for shipped features.
- [x] T247: Audit and fix remaining admin-console request/response mismatches against the server API contract.
- [x] T218: Add a production-hardening review checklist derived from `xdr_ai_handoff_pack` guidance.

## Phase 33 — Detection trust and workflow-depth release

- [x] T248: Replace stub-like explainability edges with richer entity-centric detection scores for host, agent, action, identity, and network destinations.
- [x] T249: Wire stored-event campaign clustering into `/api/correlation/campaigns` and the Attack Graph campaign-intelligence workspace.
- [x] T250: Add a deterministic replay-corpus acceptance gate for benign admin, developer tooling, identity abuse, ransomware, beaconing, and lateral movement scenarios.
- [x] T253: Add custom labeled replay-corpus pack evaluation through `POST /api/detection/replay-corpus`.
- [x] T254: Add retained-event sampling mode for `POST /api/detection/replay-corpus` with limit and threshold controls.
- [x] T255: Add a Threat Detection replay validation runner for retained-event checks and pasted custom JSON packs.
- [x] T251: Close route-aware operator workflows for detection drilldowns, fleet rollout history, UEBA/NDR response playbooks, infrastructure remediation, malware verdicts, SSO readiness, SaaS collectors, and dashboard reporting pivots.
- [x] T252: Refresh release docs, OpenAPI metadata, status, roadmap, SDK notes, reproducibility references, and version metadata for `v0.53.4`.

## Phase 34 — Replay-corpus drift analysis

- [x] T256: Add platform and signal-type delta breakdowns on top of the built-in, custom, and retained-event replay-corpus APIs and surface them in the Threat Detection workspace.

## Phase 35 — Collector ingestion timelines

- [x] T257: Add deeper ingestion-health timelines for cloud, SaaS, and identity collectors in the shared collector status contract and routed Settings workspace.

## Phase 36 — Release-gate workflow coverage

- [x] T258: Broaden the routed release-gate browser smoke coverage across detection, response, collector health, fleet rollout, and infrastructure malware/remediation workflows.

## Phase 37 — Admin-console quality sweep & panic-policy guard

- [x] T259: Centralize admin-console API error formatting in `utils/errors.js` and replace duplicated implementations across Settings, Email Security, and other workspaces.
- [x] T260: Capture and surface the backend `X-Request-Id` header on thrown API errors so operator-facing failure messages can be matched to server logs.
- [x] T261: Add reusable `WorkspaceEmptyState` and `WorkspaceErrorState` primitives with proper ARIA semantics and migrate Email Security as the first adopter.
- [x] T262: Add `role="tablist"` / `role="tab"` / `aria-selected` semantics to Settings, Infrastructure, Reports & Exports, Email Security, and NDR Dashboard tab strips.
- [x] T263: Split `Settings.jsx` by extracting 35 pure helpers into `components/settings/helpers.js` and 8 reusable widgets into `components/settings/components.jsx`.
- [x] T264: Add a panic-policy CI guard (`scripts/check_panic_policy.py` plus baseline file) that blocks regressions in non-test `unwrap`/`expect` density.
- [x] T265: Run a `knip` dead-code audit and remove three unused admin-console files and two over-exported helpers.
- [x] T266: Refresh README, STATUS, ROADMAP, REPRODUCIBILITY, installation runbook, OpenAPI metadata, helm and otlp manifests, SDK notes, website footers, and version metadata for `v0.53.6`.

## Phase 38 — Lint, coverage, knip & panic-policy tightening

- [x] T267: Resolve the 11 long-standing `react-hooks/exhaustive-deps` and `react-hooks/set-state-in-effect` warnings in NDR Dashboard, Onboarding wizard, App.jsx, and AlertDrawer.
- [x] T268: Tighten the admin-console lint script to `--max-warnings=0` so new warnings cannot land.
- [x] T269: Add a vitest v8 coverage gate with global thresholds (statements ≥ 60, branches ≥ 55, functions ≥ 55, lines ≥ 60) and wire it into CI.
- [x] T270: Install `knip`, add `admin-console/knip.json`, expose `npm run knip`, wire it into CI, and remove the dead `useDraftAutosave` hook plus the over-exported `LOCAL_AGENT` test fixture.
- [x] T271: Lower the panic-policy baseline from 19 to 6 by replacing `unwrap`/`expect` calls in `event_forward.rs`, `incident.rs`, `lateral.rs`, `feed_ingestion.rs`, `oidc.rs`, and `benchmark.rs` with `let-else` / `match` / `ok_or_else?` patterns.
- [x] T272: Continue the `WorkspaceEmptyState` migration into Assistant Workspace (5 sites), Fleet Agents, and Threat Detection rule list / detail.
- [x] T273: Refresh release docs, OpenAPI metadata, helm/otlp values, status, roadmap, SDK notes, and website surfaces for `v0.53.7`.

## Phase 39 — Session hardening, lifecycle analytics, and release readiness

- [x] T274: Exchange pasted admin-console tokens for HttpOnly `wardex_session` cookies and remove legacy localStorage token persistence while preserving bearer-token automation compatibility.
- [x] T275: Add persisted collector lifecycle analytics with validation run history, last-success/error checkpoints, retry/backoff state, freshness, failure streaks, and 24h ingestion counts.
- [x] T276: Add remediation change-review and recovery-history APIs plus Infrastructure workflow cards for malware verdicts and remediation candidates.
- [x] T277: Add a production demo lab entry point in Help & Docs backed by the first-run proof scenario.
- [x] T278: Update SDK/session helpers, release-doc drift validation, website, OpenAPI, Helm/OTLP, reproducibility, status, roadmap, and release metadata for `v0.53.8`.

## Phase 40 — Roadmap closure: approval proofs, collector pivots, and IdP validation

- [x] T279: Add signed remediation approval records with risk-aware multi-approver quorum, approval-chain digests, and generated rollback proof.
- [x] T280: Add collector ingestion evidence and SOC/Infrastructure pivots to cloud, identity, and SaaS collector status.
- [x] T281: Expand production demo lab proof across cloud, identity, SaaS, UEBA, NDR, and attack-graph evidence surfaces.
- [x] T282: Surface IdP launch-validation checks for metadata, callback route alignment, credentials, mappings, and test-login paths.
- [x] T283: Extend Python and TypeScript SDK helpers for collector status, remediation reviews, and signed remediation approvals.
- [x] T284: Add deterministic browser regression coverage for signed remediation approvals, rollback verification, collector pivots, and IdP launch validation.
- [x] T285: Add adapter-backed rollback verification for approved remediation change reviews with dry-run-first execution records.

## Recommended next build order

Phases 0–40 are complete. Routed browser regression coverage, the repeatable release-acceptance gate, admin-console API contract audit, entity-centric explainability, campaign clustering, replay-corpus promotion gates, replay delta analysis, collector lifecycle analytics, remediation change-review history, signed approval-chain proof, rollback verification, collector ingestion pivots, IdP launch validation, expanded live workflow smoke coverage, and the first Product Command Center slice are all in place.

## Phase 41 — Product Command Center and workflow federation

- [x] T286: Add an analyst-facing `/command` workspace that federates incidents, cases, connectors, detection quality, release metadata, remediation approvals, assistant guardrails, attack storytelling, RBAC posture, rule tuning debt, and compliance evidence packs.
- [x] T287: Add direct Command Center action drawers for connector validation, remediation approval review, rule replay, release rollout readiness, and evidence-pack export.
- [x] T288: Add routed Playwright smoke coverage for Command Center deep links, mobile layout, lane refresh behavior, and high-risk remediation/release handoffs.
- [x] T289: Add backend summary endpoints for Command Center lane health so the UI can reduce client-side fan-out as the workspace becomes the default operator entry point.
- [x] T290: Mirror detection tuning/scoring, remote fleet install, process-thread, and backup endpoints across the live OpenAPI builder plus Python and TypeScript SDK surfaces.

## Phase 42 — Remediation module extraction and rollback execution depth

- [x] T291: Move remediation change-review JSON response envelopes and HTTP error mapping into `remediation.rs` so `server.rs` only owns route dispatch and response wiring.
- [x] T292: Extract remaining remediation route parsing and policy assembly from `server.rs` into a focused remediation API adapter.
- [x] T293: Broaden live rollback execution coverage for additional safe, platform-matched remediation actions and document operator safeguards.

## Phase 43 — Command Center parity and workflow depth (completed)

- [x] T294: Add Python and TypeScript SDK helpers for `/api/command/summary` so Command Center summary contracts are available outside admin-console fetch helpers.
- [x] T295: Broaden Command Center lane annotations and release-gate coverage as new workflows land.
- [x] T296: Keep remediation operator safeguards and matching-platform rollback regressions aligned as additional adapters are introduced.

## Phase 44 — Command Center contract hardening and release-doc alignment (completed)

- [x] T297: Replace the generic OpenAPI documentation for `/api/command/summary` and `/api/command/lanes/{lane}` with explicit Command Center response schemas, including lane annotations and next-step guidance.
- [x] T298: Add Python and TypeScript SDK helpers for `/api/command/lanes/{lane}` so focused lane-refresh contracts are available outside admin-console fetch helpers.
- [x] T299: Refresh feature-coverage, SDK guide, and release-doc tracking text so the shipped Command Center and remediation workflow state no longer reads as pre-action-drawer or pre-live-adapter work.

## Phase 45 — Command Center typed SDK contracts (completed)

- [x] T300: Replace the generic TypeScript SDK record responses for `/api/command/summary` and `/api/command/lanes/{lane}` with explicit Command Center interfaces so consumers can rely on typed lane metrics and payload fields.

## Phase 46 — Python Command Center typed exports (completed)

- [x] T301: Add exported Python `TypedDict` contracts for `/api/command/summary` and `/api/command/lanes/{lane}` so SDK consumers can rely on the same stable Command Center fields without dropping to untyped dictionaries.

## Phase 47 — Live Command Center drawer handoff smoke (completed)

- [x] T302: Extend the live enterprise Playwright smoke to open shipped Command Center drawers and verify stable handoffs into Settings and Infrastructure before the broader route sweep continues.

## Phase 48 — Live Command Center release and evidence handoffs (completed)

- [x] T303: Extend the live enterprise Playwright smoke to open the shipped Command Center release and evidence drawers and verify stable handoffs into Infrastructure rollouts and Reports & Exports.

## Phase 49 — Federated SSO regression depth (completed)

- [x] T304: Add routed browser coverage for launching ready SSO providers from Settings and verify the computed backend login path and callback destination remain aligned with the console route.
- [x] T305: Add regression coverage for post-callback session recovery and unauthenticated-shell error handling so `/api/auth/check`, `/api/auth/session`, and login-shell SSO affordances stay coherent after provider changes.
- [x] T306: Refresh status, feature-coverage, and release-doc tracking once the expanded federated SSO launch/callback regression slice lands.

## Phase 50 — Collector lifecycle regression depth

- [ ] T307: Add routed browser coverage for collector-specific analytics and readiness pivots from Settings and Infrastructure so shipped cloud, identity, SaaS, and syslog lanes keep stable deep links as provider workflows evolve.
- [ ] T308: Add regression coverage for staged ingestion evidence, freshness, failure-streak analytics, and retry/backoff context so collector health details remain operator-usable across the shipped lanes.
- [ ] T309: Refresh roadmap, status, and feature-coverage tracking once the broader collector lifecycle regression tranche lands.

See `docs/ROADMAP_XDR_PROFESSIONAL.md` for the broader professional roadmap beyond the current implementation order.

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
