/* ═══════════════════════════════════════════════════════════════════════════
   Wardex — Site Logic v5
   Data-driven rendering. Researcher tone. No marketing fluff.
   ═══════════════════════════════════════════════════════════════════════════ */

// ── Project Data ──────────────────────────────────────────────────────────────

const stats = [
  { value: "37", label: "core runtime modules" },
  { value: "8",  label: "telemetry dimensions" },
  { value: "40", label: "research tracks mapped" },
  { value: "387", label: "automated tests" },
];

const pipelineDetails = [
  {
    num: "01",
    title: "Telemetry Ingestion",
    body: "CSV and JSONL inputs are parsed into typed TelemetrySample records. Eight signal dimensions (CPU, memory, temperature, bandwidth, auth failures, integrity drift, process count, disk pressure) are validated against expected ranges. The parser auto-detects format by file extension, and deterministic replay semantics ensure the same input always produces the same internal state — useful for regression testing and scenario comparison.",
    note: "CSV supports both 8-column legacy and 10-column extended formats. JSONL ingestion is fully implemented (T011)."
  },
  {
    num: "02",
    title: "Adaptive Anomaly Detection",
    body: "An EWMA-style rolling baseline tracks normal behaviour for each signal dimension. Incoming samples are compared against this baseline; deviations are weighted by dimension and combined into a single anomaly score. The detector also emits human-readable explanations identifying which signals contributed most. Baselines can be persisted to disk and restored across sessions for long-running deployments. Adaptation controls allow freezing, decaying, or resetting baselines during suspected poisoning.",
    note: "Adaptation modes (Normal, Frozen, Decay) are implemented (T041). Page-Hinkley drift detection triggers automatic baseline re-learning (Phase 13)."
  },
  {
    num: "03",
    title: "Policy-Driven Response",
    body: "The anomaly score is mapped to one of four threat levels: nominal, elevated, severe, critical. Each level triggers a corresponding response action (observe, rate-limit, quarantine, rollback-and-escalate). When the device battery is low, the policy engine automatically downgrades expensive actions to preserve device availability — the assumption being that a dead device is worse than a slightly softer response.",
    note: "Pluggable action adapters (T020–T021) provide trait-based implementations for logging, throttle, quarantine, and isolate actions."
  },
  {
    num: "04",
    title: "Response Execution",
    body: "Actions are dispatched through a composable adapter chain. Each adapter implements a trait with execute/name methods. The default chain includes logging, throttle, quarantine, and isolate adapters that fire in sequence based on threat level.",
    note: "Adapters are currently simulated (log-based). Real device enforcement is a future integration point."
  },
  {
    num: "05",
    title: "Rollback & Checkpoints",
    body: "Rollback checkpoints capture detector state snapshots on severe/critical events. A bounded ring buffer retains recent checkpoints, enabling post-incident analysis and future state restoration. The forensic bundle exporter combines audit logs, checkpoint history, and evidence summaries into a single human-readable report.",
    note: "State restoration from checkpoints is not yet implemented — the snapshot infrastructure is in place."
  },
  {
    num: "06",
    title: "Proof-Carrying Updates",
    body: "Every baseline state change is bound to a SHA-256 proof linking prior state, transform description, and post state. A ProofRegistry accumulates and batch-verifies all proofs in a session, providing cryptographic evidence that no update was silently tampered with.",
    note: "ZK proof placeholder exists for future Halo2/SNARK integration (T032)."
  },
  {
    num: "07",
    title: "Policy State Machine",
    body: "An explicit state machine records and validates all threat-level transitions against formally defined legal rules. Escalation, de-escalation, and battery downgrade transitions are each constrained to legal paths. The full transition trace is exportable for future TLA+/Alloy verification.",
    note: "Legal transition rules are defined and enforced at runtime. Formal model checker integration remains future work (T033)."
  },
  {
    num: "08",
    title: "Replay Buffer & Poisoning Analysis",
    body: "A bounded replay buffer retains recent telemetry in a ring buffer for windowed statistical analysis. Four poisoning heuristics — mean shift detection, variance spike, drift accumulation, and auth burst pattern analysis — scan the buffer for signs of data manipulation.",
    note: "Poisoning analysis is implemented (T042). Automated recovery from detected poisoning is future scope."
  },
  {
    num: "09",
    title: "Audit Trail",
    body: "Every detection-and-response decision is appended to a SHA-256-chained audit log. Each entry includes a cryptographic hash of the previous entry, forming a linked sequence that makes retroactive tampering detectable. Signed audit checkpoints are inserted at configurable intervals. The entire chain can be verified end-to-end.",
    note: "SHA-256 digest chain and signed checkpoints are implemented (T030–T031). Post-quantum signatures remain deferred."
  },
  {
    num: "10",
    title: "Output & Reporting",
    body: "Structured JSON reports can be generated for SIEM integration. JSONL alert streams provide real-time event output. The init-config command generates a TOML configuration template, and the status command provides a live implementation snapshot.",
    note: "Twelve CLI commands: demo, analyze, report, init-config, status, status-json, serve, harness, attest, bench, export-model, and help."
  },
  {
    num: "11",
    title: "Threat Intelligence",
    body: "Observed indicators are matched against a local threat-intelligence store. Matches enrich anomaly signals with known-bad indicator metadata such as severity ratings and indicator types (IP, hash, domain).",
    note: "IOC matching is wired into the runtime pipeline (Phase 13). Feed ingestion from external STIX/TAXII sources is future scope."
  },
  {
    num: "12",
    title: "Enforcement",
    body: "Automated network blocking and process suspension driven by threat level. Pluggable enforcer traits abstract OS-specific primitives so enforcement logic is testable without real kernel calls.",
    note: "NetworkEnforcer and ProcessEnforcer are wired into the pipeline on severe/critical events (Phase 13)."
  },
  {
    num: "13",
    title: "Digital Twin Simulation",
    body: "Simulate fleet behaviour under observed conditions. A deterministic discrete-event engine predicts cascading failures and validates response strategies before real deployment.",
    note: "DigitalTwinEngine.simulate() runs per-sample in the pipeline (Phase 13). Fleet-scale simulation is future work."
  },
  {
    num: "14",
    title: "Energy Budget Tracking",
    body: "Track energy budgets and tick consumption per pipeline iteration. Enforce energy-proportional processing on battery-constrained devices by scaling pipeline depth to available energy.",
    note: "EnergyBudget.tick() is invoked per sample in the pipeline (Phase 13)."
  },
  {
    num: "15",
    title: "Side-Channel Detection",
    body: "Detect timing anomalies indicative of side-channel attacks. A statistical observer tracks execution-timing distributions and flags deviations beyond configurable thresholds.",
    note: "SideChannelDetector.observe_timing() runs per sample in the pipeline (Phase 13)."
  },
  {
    num: "16",
    title: "Compliance Scoring",
    body: "Collect evidence toward compliance frameworks. Audit, detection, and enforcement records accumulate into a compliance score that quantifies adherence to security policies.",
    note: "ComplianceManager.add_evidence() and .score() are wired into the pipeline (Phase 13)."
  },
];

const statusData = {
  implemented: [
    "Rust project scaffold with runnable CLI (demo, analyze, report, init-config, status)",
    "Typed telemetry ingestion from CSV and JSONL with auto-detection",
    "Adaptive EWMA-based anomaly scoring across eight signal dimensions",
    "Human-readable anomaly explanations per scoring decision",
    "Threat-level classification and response-action selection",
    "Battery-aware graceful degradation of mitigation actions",
    "TOML/JSON configuration loading with write-default support",
    "Baseline persistence and cross-session restoration",
    "Pluggable action adapters (logging, throttle, quarantine, isolate)",
    "Rollback checkpoints with bounded ring buffer",
    "Forensic evidence bundle exporter",
    "SHA-256 cryptographic digest chain in audit log",
    "Signed audit checkpoints at configurable intervals",
    "Structured JSON reports for SIEM integration",
    "Proof-carrying update metadata with SHA-256 binding and verification",
    "Formally checkable policy state machine with legal transition validation",
    "Bounded replay buffer with windowed statistics",
    "Baseline adaptation controls (freeze, decay, reset)",
    "Four poisoning heuristics (mean shift, variance spike, drift accumulation, auth burst)",
    "FP/FN benchmark harness with precision, recall, F1, and accuracy",
    "Live browser admin console with authenticated control plane (T063/T064)",
    "HTTP server with token-authenticated API for status, analysis, and mode control",
    "Deterministic test fixtures (benign, escalation, low-battery, credential-storm)",
    "GitHub Pages deployment with CI workflow",
    "Documentation: architecture, getting started, backlog, research tracks",
    "Research paper targeting document with evaluation plan",
    "Swarm coordination protocol design (digest gossip, voting, provenance)",
    "Wasm extension surface specification (sandboxed detector/response plugins)",
    "Supply-chain attestation design (build manifests, trust stores)",
    "Post-quantum logging upgrade path (hybrid signature strategy)",
    "Research questions for R26-R30 (explainability and edge intelligence)",
    "Research questions for R31-R35 (infrastructure and hardening)",
    "Research questions for R36-R40 (resilience and long-horizon)",
    "Adversarial robustness testing harness design (evasion grammar, coverage metric)",
    "Temporal-logic property specification format (SentinelTL, runtime monitor)",
    "Digital-twin fleet simulation architecture (deterministic discrete-event model)",
    "Formal policy composition algebra (conflict resolution, verification)",
    "Explainable anomaly attribution with per-signal contribution breakdown (T080)",
    "Multi-signal correlation analysis with Pearson coefficients and co-rising detection (T081)",
    "Runtime temporal-logic monitor with safety and liveness property checking (T083)",
    "Adversarial testing harness with grammar-based evasion strategies (T084)",
    "Behavioural device fingerprinting with Mahalanobis-inspired distance scoring (T094)",
    "Single-source research-track data pipeline for website and API (T103)",
    "Supply-chain attestation module with SBOM generation and build-manifest signing (T104)",
    "Extended 120-sample test fixtures for all four attack scenarios (T110)",
    "Fixed-threshold baseline detector for paper comparison (T111)",
    "Side-by-side bench CLI comparing EWMA vs fixed-threshold detectors (T112)",
    "Per-signal contribution aggregation in benchmark harness (T113)",
    "Enforcement module with network blocking and process suspension (T120)",
    "Post-quantum Lamport one-time signatures (T121)",
    "Swarm coordination protocol with peer discovery and digest gossip (T122)",
    "Privacy-preserving forensic evidence handling (T123)",
    "Wasm extension sandbox for user-defined detection policies (T124)",
    "Local threat-intelligence store with IOC matching (T125)",
    "Timing-based side-channel attack detection (T126)",
    "Digital-twin fleet simulation engine (T127)",
    "Compliance evidence collection and framework scoring (T128)",
    "Tenant-isolated security contexts for multi-tenancy (T129)",
    "Edge-cloud hybrid offload decision engine (T130)",
    "Energy budget tracking and proportional processing (T131)",
    "All 40 research tracks at foundation status",
    "Pipeline wiring: threat-intel, enforcement, digital-twin, energy, side-channel, compliance (Phase 13)",
    "Criterion micro-benchmarks for paper evaluation (~55K samples/sec throughput) (T132)",
    "Continual learning with Page-Hinkley drift detection and automatic re-learning (T133)",
    "Policy composition algebra with conflict resolution operators (T134)",
  ],
  scaffolded: [
    "ZK proof placeholder in proof-carrying metadata — Halo2/SNARK deferred (R12)",
    "TLA+/Alloy export stubs in state machine — formal checker integration deferred (R02)",
  ],
  deferred: [
    "Differential privacy guarantees",
    "Zero-knowledge proofs (Halo2, zk-SNARKs)",
    "Formal rule verification / TLA+ model checking",
    "Quantum-walk anomaly propagation modeling",
    "Secure MPC / private set intersection",
    "Hardware roots of trust integration",
  ],
};

const backlogPhases = [
  {
    id: "phase-0",
    tag: "Phase 0",
    tagClass: "done",
    title: "Foundation (complete)",
    tasks: [
      { id: "T001", title: "Bootstrap Rust package and module layout", done: true },
      { id: "T002", title: "CSV telemetry ingestion and validation", done: true },
      { id: "T003", title: "Adaptive multi-signal anomaly detector", done: true },
      { id: "T004", title: "Policy engine with battery-aware mitigation", done: true },
      { id: "T005", title: "Chained audit log for run forensics", done: true },
      { id: "T006", title: "Baseline documentation and GitHub Pages site", done: true },
    ],
  },
  {
    id: "phase-1",
    tag: "Phase 1",
    tagClass: "done",
    title: "Runtime Hardening (complete)",
    tasks: [
      { id: "T010", title: "TOML/JSON configuration loading", done: true },
      { id: "T011", title: "JSONL telemetry ingestion", done: true },
      { id: "T012", title: "Structured JSON reports for SIEM ingestion", done: true },
      { id: "T013", title: "Persist and reload learned baselines", done: true },
      { id: "T014", title: "Richer anomaly features (process count, disk pressure)", done: true },
      { id: "T015", title: "Deterministic test fixtures", done: true },
    ],
  },
  {
    id: "phase-2",
    tag: "Phase 2",
    tagClass: "done",
    title: "Device Actions (complete)",
    tasks: [
      { id: "T020", title: "Pluggable device action adapters", done: true },
      { id: "T021", title: "Throttle, quarantine, and isolate implementations", done: true },
      { id: "T022", title: "Rollback checkpoints", done: true },
      { id: "T023", title: "Forensic bundle exporter", done: true },
    ],
  },
  {
    id: "phase-3",
    tag: "Phase 3",
    tagClass: "done",
    title: "Verifiability (complete)",
    tasks: [
      { id: "T030", title: "Cryptographic digest chain (SHA-256)", done: true },
      { id: "T031", title: "Signed audit checkpoints", done: true },
      { id: "T032", title: "Proof-carrying update metadata", done: true },
      { id: "T033", title: "Formally checkable response policy", done: true },
    ],
  },
  {
    id: "phase-4",
    tag: "Phase 4",
    tagClass: "done",
    title: "Edge Learning (complete)",
    tasks: [
      { id: "T040", title: "Bounded replay buffer", done: true },
      { id: "T041", title: "Baseline adaptation controls", done: true },
      { id: "T042", title: "Broader poisoning heuristics", done: true },
      { id: "T043", title: "FP/FN benchmark harnesses", done: true },
    ],
  },
  {
    id: "phase-5",
    tag: "Phase 5",
    tagClass: "done",
    title: "Research Expansion (complete)",
    tasks: [
      { id: "T050", title: "Select first research paper subset", done: true },
      { id: "T051", title: "Swarm coordination protocol sketch", done: true },
      { id: "T052", title: "Wasm extension surface specification", done: true },
      { id: "T053", title: "Supply-chain attestation inputs", done: true },
      { id: "T054", title: "Post-quantum logging upgrade path", done: true },
    ],
  },
  {
    id: "phase-6",
    tag: "Phase 6",
    tagClass: "done",
    title: "Browser Admin Console (complete)",
    tasks: [
      { id: "T060", title: "Define browser admin console scope and data contracts", done: true },
      { id: "T061", title: "Build read-only browser status dashboard", done: true },
      { id: "T062", title: "Add JSON report upload and sample drilldown", done: true },
      { id: "T063", title: "Add local runtime-backed refresh path", done: true },
      { id: "T064", title: "Add authenticated browser control actions", done: true },
    ],
  },
  {
    id: "phase-7",
    tag: "Phase 7",
    tagClass: "done",
    title: "Expanded Research Agenda",
    tasks: [
      { id: "T070", title: "Research-question statements for R26-R30", desc: "Formalize explainability and edge intelligence research questions.", done: true },
      { id: "T071", title: "Research-question statements for R31-R35", desc: "Formalize infrastructure and hardening research questions.", done: true },
      { id: "T072", title: "Research-question statements for R36-R40", desc: "Formalize resilience and long-horizon research questions.", done: true },
      { id: "T073", title: "Adversarial robustness harness design", desc: "Design an automated red-team testing harness for R28.", done: true },
      { id: "T074", title: "Temporal-logic property spec format", desc: "Design a property specification format for R29.", done: true },
      { id: "T075", title: "Digital-twin simulation architecture", desc: "Sketch a fleet simulation architecture for R31.", done: true },
      { id: "T076", title: "Formal policy composition algebra", desc: "Sketch a policy algebra for R39.", done: true },
    ],
  },
  {
    id: "phase-8",
    tag: "Phase 8",
    tagClass: "done",
    title: "Runtime Intelligence (complete)",
    tasks: [
      { id: "T080", title: "Explainable anomaly attribution", desc: "Per-signal contribution breakdown in AnomalySignal.", done: true },
      { id: "T081", title: "Multi-signal correlation engine", desc: "Pearson coefficients and co-rising detection.", done: true },
      { id: "T082", title: "Attribution + correlation wired into pipeline", desc: "Full pipeline integration with audit logging.", done: true },
      { id: "T083", title: "Temporal-logic runtime monitor", desc: "SentinelTL property checking (safety + liveness).", done: true },
      { id: "T084", title: "Adversarial testing harness", desc: "Grammar-based evasion strategies and coverage metric.", done: true },
    ],
  },
  {
    id: "phase-9",
    tag: "Phase 9",
    tagClass: "done",
    title: "Extended Intelligence (complete)",
    tasks: [
      { id: "T090", title: "Correlation analysis wired into API", desc: "Correlation endpoint and pipeline integration.", done: true },
      { id: "T091", title: "Monitor violations in pipeline output", desc: "Temporal-logic violations in run results.", done: true },
      { id: "T092", title: "Adversarial harness wired into pipeline", desc: "Evasion testing callable from CLI and API.", done: true },
      { id: "T093", title: "Export endpoints (TLA+, Alloy, witnesses)", desc: "Formal model export endpoints.", done: true },
      { id: "T094", title: "Behavioural device fingerprinting", desc: "Statistical profile for device impersonation detection.", done: true },
    ],
  },
  {
    id: "phase-10",
    tag: "Phase 10",
    tagClass: "done",
    title: "Data Pipeline & Attestation (complete)",
    tasks: [
      { id: "T103", title: "Single-source research-track data", desc: "Canonical JSON drives website and API.", done: true },
      { id: "T104", title: "Supply-chain attestation module", desc: "SBOM generation and build-manifest signing.", done: true },
    ],
  },
  {
    id: "phase-11",
    tag: "Phase 11",
    tagClass: "done",
    title: "Extended Fixtures & Benchmarking (complete)",
    tasks: [
      { id: "T110", title: "Extended 120-sample test fixtures", desc: "Benign, credential-storm, slow-escalation, and low-battery extended CSVs.", done: true },
      { id: "T111", title: "Fixed-threshold baseline detector", desc: "Static per-signal threshold detector for paper comparison.", done: true },
      { id: "T112", title: "Bench CLI command", desc: "Side-by-side EWMA vs fixed-threshold comparison.", done: true },
      { id: "T113", title: "Per-signal contribution in benchmarks", desc: "Signal attribution aggregation in benchmark harness.", done: true },
      { id: "T114", title: "Documentation cleanup", desc: "Fix all stale references across docs.", done: true },
    ],
  },
  {
    id: "phase-12",
    tag: "Phase 12",
    tagClass: "done",
    title: "Research Frontier Modules (complete)",
    tasks: [
      { id: "T120", title: "Enforcement module", desc: "Network blocking and process suspension driven by threat level.", done: true },
      { id: "T121", title: "Post-quantum Lamport signatures", desc: "One-time hash-based signatures for quantum-resistant signing.", done: true },
      { id: "T122", title: "Swarm coordination protocol", desc: "Peer discovery, digest gossip, and voting protocol.", done: true },
      { id: "T123", title: "Privacy-preserving forensics", desc: "PrivacyFilter for field redaction and k-anonymity.", done: true },
      { id: "T124", title: "Wasm extension engine", desc: "Sandboxed Wasm VM for user-defined detection policies.", done: true },
      { id: "T125", title: "Threat intelligence store", desc: "Local IOC matching with severity-rated indicators.", done: true },
      { id: "T126", title: "Side-channel detection", desc: "Timing-based side-channel attack detection.", done: true },
      { id: "T127", title: "Digital-twin simulation", desc: "Deterministic discrete-event fleet simulation engine.", done: true },
      { id: "T128", title: "Compliance scoring", desc: "Evidence collection and framework compliance score.", done: true },
      { id: "T129", title: "Multi-tenancy isolation", desc: "Tenant-isolated security contexts.", done: true },
      { id: "T130", title: "Edge-cloud offload", desc: "Hybrid offload decision engine.", done: true },
      { id: "T131", title: "Energy budget tracking", desc: "Per-iteration energy accounting and proportional processing.", done: true },
    ],
  },
  {
    id: "phase-13",
    tag: "Phase 13",
    tagClass: "done",
    title: "Research Agenda Advancement (complete)",
    tasks: [
      { id: "T132", title: "Pipeline wiring", desc: "Threat-intel, enforcement, digital-twin, energy, side-channel, and compliance wired into runtime.", done: true },
      { id: "T133", title: "Criterion micro-benchmarks", desc: "Benchmark suite for paper evaluation (~55K samples/sec, ~98ns detector, ~404ns policy).", done: true },
      { id: "T134", title: "Continual learning", desc: "Page-Hinkley drift detection with automatic baseline re-learning.", done: true },
      { id: "T135", title: "Policy composition algebra", desc: "MaxSeverity, MinSeverity, LeftPriority, RightPriority operators with conflict resolution.", done: true },
      { id: "T136", title: "Documentation update", desc: "Backlog, changelog, features, status, and README updated for Phase 13.", done: true },
    ],
  },
  {
    id: "phase-14",
    tag: "Phase 14",
    tagClass: "done",
    title: "Full Admin Console Integration (complete)",
    tasks: [
      { id: "T137", title: "API endpoints", desc: "18 new endpoints for side-channel, quantum, privacy, WASM VM, fingerprint, harness, monitor, deception, policy compose, drift, causal, patches, offload, swarm, energy harvest.", done: true },
      { id: "T138", title: "Security Operations panel", desc: "Enforcement quarantine, threat intel IOC, side-channel risk, deception deploy.", done: true },
      { id: "T139", title: "Fleet, Twin & Testing panels", desc: "Device registration, swarm posture, twin simulation, adversarial harness.", done: true },
      { id: "T140", title: "Monitoring & Analysis panel", desc: "Monitor status/violations, correlation, drift reset, fingerprint, causal graph.", done: true },
      { id: "T141", title: "Compliance, Quantum, Policy, Infra & Exports", desc: "Compliance, attestation, privacy, quantum key rotate, policy compose, WASM VM, energy, patches, offload, TLA+/Alloy/witness export.", done: true },
    ],
  },
  {
    id: "phase-15",
    tag: "Phase 15",
    tagClass: "done",
    title: "Integration Test Coverage & Paper Evaluation (complete)",
    tasks: [
      { id: "T142", title: "API integration tests", desc: "49 new HTTP integration tests covering all 40+ API endpoints with auth rejection tests for every POST endpoint.", done: true },
      { id: "T143", title: "Paper evaluation harnesses", desc: "Per-sample latency benchmark (LatencyStats) and audit chain scaling benchmark (10–100K records) with 4 new unit tests.", done: true },
      { id: "T144", title: "RESEARCH_TRACKS.md rewrite", desc: "All 40 tracks updated to accurate 'Implemented foundation' status with current repo-state descriptions.", done: true },
      { id: "T145", title: "PAPER_TARGETS.md update", desc: "Paper 1 gaps closed (latency, audit scaling). Papers 2 and 3 prerequisites marked as met.", done: true },
      { id: "T146", title: "Documentation & version update", desc: "Version 0.13.0, updated counts (77/77 tasks, 329 tests, 16 phases), backlog, changelog, status, README.", done: true },
    ],
  },
  {
    id: "phase-16",
    tag: "Phase 16",
    tagClass: "done",
    title: "Production Hardening & Self-Healing (complete)",
    tasks: [
      { id: "T147", title: "ML-DSA-65 hybrid signatures", desc: "Post-quantum hybrid signing with classical Lamport + ML-DSA-65 dual verification, PqHybridCheckpoint.", done: true },
      { id: "T148", title: "TLS server configuration", desc: "TlsConfig with mTLS, version enforcement, cipher suite selection, ListenerMode abstraction, /api/tls/status.", done: true },
      { id: "T149", title: "Config hot-reload", desc: "ConfigPatch partial update with validation and automatic rollback, /api/config/current and /api/config/reload.", done: true },
      { id: "T150", title: "Mesh self-healing topology", desc: "BFS spanning tree, partition detection, repair proposals (AddEdge/PromoteRelay/Reroute), /api/mesh/health and /api/mesh/heal.", done: true },
    ],
  },
  {
    id: "phase-17",
    tag: "Phase 17",
    tagClass: "done",
    title: "Cross-platform XDR Agent with Live Monitoring (complete)",
    tasks: [
      { id: "T151", title: "Host telemetry collector", desc: "collector.rs (~680 lines): cross-platform OS detection, live metric collection (CPU/mem/temp/net/auth/battery/proc/disk), FileIntegrityMonitor, AlertRecord with syslog/CEF.", done: true },
      { id: "T152", title: "Simplified startup", desc: "cargo run defaults to combined serve+monitor. Auto-creates var/wardex.toml. Ctrl+C graceful shutdown.", done: true },
      { id: "T153", title: "Webhook & alert output", desc: "send_webhook() via ureq, --syslog and --cef CLI flags for standard alert formats.", done: true },
      { id: "T154", title: "Server alert API & health", desc: "GET /api/health, GET /api/alerts, GET /api/alerts/count, DELETE /api/alerts, GET /api/endpoints, POST /api/config/save. Configurable CORS. 7 integration tests.", done: true },
      { id: "T155", title: "Admin console panels", desc: "Live Monitoring panel with auto-polling alert table (3s), Settings panel with 6 config sections, toast notifications, token toggle, MonitorSettings.", done: true },
      { id: "T156", title: "Docs & version bump", desc: "Version 0.15.0, CHANGELOG, STATUS, README, FEATURES, PROJECT_BACKLOG, site, and runtime manifest updated. 387 tests, 85/85 tasks.", done: true },
    ],
  },
];

// Research track data is loaded from the canonical source at
// /api/research-tracks (when the server is running) or from the
// static JSON file at data/research_tracks.json (offline / GitHub Pages).
// See site/data/research_tracks.json for the single source of truth.

let _trackGroupsCache = null;

async function loadTrackGroups() {
  if (_trackGroupsCache) return _trackGroupsCache;
  try {
    const resp = await fetch("/api/research-tracks");
    if (resp.ok) {
      _trackGroupsCache = await resp.json();
      return _trackGroupsCache;
    }
  } catch (_) { /* server not running, fall through */ }
  try {
    const resp = await fetch("data/research_tracks.json");
    if (resp.ok) {
      _trackGroupsCache = await resp.json();
      return _trackGroupsCache;
    }
  } catch (_) { /* static file not available */ }
  return [];
}

const csvFields = [
  { name: "timestamp_ms", desc: "Monotonically increasing sample time" },
  { name: "cpu_load_pct", desc: "CPU load, 0–100" },
  { name: "memory_load_pct", desc: "Memory usage, 0–100" },
  { name: "temperature_c", desc: "Operating temperature, °C" },
  { name: "network_kbps", desc: "Observed throughput (kbps)" },
  { name: "auth_failures", desc: "Failed auth attempts per window" },
  { name: "battery_pct", desc: "Battery level, 0–100" },
  { name: "integrity_drift", desc: "Model/config drift, 0–1" },
  { name: "process_count", desc: "Running process count (optional, extended format)" },
  { name: "disk_pressure_pct", desc: "Disk pressure, 0–100 (optional, extended format)" },
];

// ── Rendering ─────────────────────────────────────────────────────────────────

function renderStats() {
  const el = document.getElementById("stats-grid");
  if (!el) return;
  stats.forEach(s => {
    const div = document.createElement("div");
    div.className = "stat-item";
    div.innerHTML = `<span class="stat-value">${s.value}</span><span class="stat-label">${s.label}</span>`;
    el.appendChild(div);
  });
}

function renderPipelineDetails() {
  const el = document.getElementById("pipeline-details");
  if (!el) return;
  pipelineDetails.forEach((d, i) => {
    const card = document.createElement("div");
    card.className = "detail-card";
    card.style.setProperty("--stagger", `${i * 80}ms`);
    card.setAttribute("data-delay", "");
    card.innerHTML = `
      <h3><span class="detail-num">${d.num}</span>${d.title}</h3>
      <p>${d.body}</p>
      ${d.note ? `<p class="detail-note">${d.note}</p>` : ""}
    `;
    el.appendChild(card);
  });
}

function renderStatus() {
  const lists = {
    implemented: document.getElementById("status-implemented"),
    scaffolded: document.getElementById("status-scaffolded"),
    deferred: document.getElementById("status-deferred"),
  };
  Object.entries(statusData).forEach(([key, items]) => {
    const ul = lists[key];
    if (!ul) return;
    items.forEach(text => {
      const li = document.createElement("li");
      li.textContent = text;
      ul.appendChild(li);
    });
  });
}

function renderBacklog() {
  const el = document.getElementById("backlog-phases");
  if (!el) return;
  backlogPhases.forEach((phase, i) => {
    const block = document.createElement("div");
    block.className = "phase-block";
    block.style.setProperty("--stagger", `${i * 80}ms`);
    block.setAttribute("data-delay", "");

    const taskHTML = phase.tasks.map(t => {
      const completed = t.done ? " completed" : "";
      const descHTML = t.desc ? `<p>${t.desc}</p>` : "";
      return `
        <div class="task-item${completed}">
          <span class="task-id">${t.id}</span>
          <div class="task-content">
            <strong>${t.title}</strong>
            ${descHTML}
          </div>
        </div>`;
    }).join("");

    block.innerHTML = `
      <div class="phase-header">
        <span class="phase-tag ${phase.tagClass}">${phase.tag}</span>
        <span class="phase-title">${phase.title}</span>
      </div>
      <div class="task-list">${taskHTML}</div>
    `;
    el.appendChild(block);
  });
}

function chevronSVG() {
  return `<svg width="10" height="6" viewBox="0 0 10 6" fill="none"><path d="M1 1l4 4 4-4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
}

async function renderTracks() {
  const container = document.getElementById("tracks-container");
  if (!container) return;

  const trackGroups = await loadTrackGroups();

  trackGroups.forEach(group => {
    const groupEl = document.createElement("div");
    groupEl.className = "track-group";

    const count = group.tracks.length;
    groupEl.innerHTML = `
      <div class="track-group-header">
        <span class="track-group-label">${group.label}</span>
        <span class="track-group-count">${count} track${count !== 1 ? "s" : ""}</span>
      </div>
      <div class="track-group-grid" id="tg-${group.id}"></div>
    `;
    container.appendChild(groupEl);

    const grid = groupEl.querySelector(`#tg-${group.id}`);
    group.tracks.forEach((track, i) => {
      const card = document.createElement("article");
      card.className = "track-card";
      card.dataset.status = track.status;
      card.style.setProperty("--stagger", `${i * 60}ms`);
      card.setAttribute("data-delay", "");

      card.innerHTML = `
        <span class="track-badge ${track.status}">${track.code} · ${track.status}</span>
        <h3>${track.title}</h3>
        <p class="track-summary">${track.summary}</p>
        <button class="track-expand-btn" aria-expanded="false">
          <span>Details</span>${chevronSVG()}
        </button>
        <div class="track-detail">
          <div class="track-detail-inner">
            <dl class="track-dl">
              <div><dt>Research idea</dt><dd>${track.idea}</dd></div>
              <div><dt>Why it matters</dt><dd>${track.matters}</dd></div>
              <div><dt>Current prototype</dt><dd>${track.state}</dd></div>
            </dl>
          </div>
        </div>
      `;

      grid.appendChild(card);

      // Expand / collapse
      const btn = card.querySelector(".track-expand-btn");
      btn.addEventListener("click", () => {
        const isOpen = card.classList.toggle("open");
        btn.setAttribute("aria-expanded", String(isOpen));
        btn.querySelector("span").textContent = isOpen ? "Close" : "Details";
      });
    });
  });
}

function renderFields() {
  const el = document.getElementById("field-grid");
  if (!el) return;
  csvFields.forEach(f => {
    const div = document.createElement("div");
    div.className = "field-item";
    div.innerHTML = `<code>${f.name}</code><span>${f.desc}</span>`;
    el.appendChild(div);
  });
}

// ── Track Filtering ───────────────────────────────────────────────────────────

function initFilters() {
  const buttons = document.querySelectorAll(".filter-btn");
  const cards = document.querySelectorAll(".track-card");

  buttons.forEach(btn => {
    btn.addEventListener("click", () => {
      const filter = btn.dataset.filter;
      buttons.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");

      cards.forEach(card => {
        if (filter === "all" || card.dataset.status === filter) {
          card.classList.remove("hidden");
        } else {
          card.classList.add("hidden");
        }
      });
    });
  });
}

// ── Navigation ────────────────────────────────────────────────────────────────

function initNav() {
  const nav = document.getElementById("site-nav");
  const toggle = document.getElementById("nav-toggle");
  const links = document.getElementById("nav-links");

  // Mobile toggle
  if (toggle && links) {
    toggle.addEventListener("click", () => {
      const open = links.classList.toggle("open");
      toggle.setAttribute("aria-expanded", String(open));
    });
  }

  // Dropdown triggers (mobile)
  document.querySelectorAll(".nav-dropdown-trigger").forEach(trigger => {
    trigger.addEventListener("click", (e) => {
      // On mobile, toggle the dropdown
      if (window.innerWidth <= 768) {
        e.preventDefault();
        const dropdown = trigger.closest(".nav-dropdown");
        dropdown.classList.toggle("open");
      }
    });
  });

  // Close mobile menu when a link is clicked
  document.querySelectorAll(".nav-dropdown-menu a, .nav-links > .nav-link").forEach(link => {
    link.addEventListener("click", () => {
      if (links) links.classList.remove("open");
      if (toggle) toggle.setAttribute("aria-expanded", "false");
    });
  });

  // Active section tracking on scroll
  const sections = document.querySelectorAll("section[id]");
  const allNavLinks = document.querySelectorAll("[data-section]");

  const observer = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const id = entry.target.id;
        allNavLinks.forEach(l => l.classList.remove("active"));
        const match = document.querySelector(`[data-section="${id}"]`);
        if (match) match.classList.add("active");
      }
    });
  }, { rootMargin: "-30% 0px -60% 0px" });

  sections.forEach(s => observer.observe(s));

  // Shrink nav on scroll
  let lastScroll = 0;
  window.addEventListener("scroll", () => {
    const scrollY = window.scrollY;
    if (scrollY > 80) {
      nav.classList.add("scrolled");
    } else {
      nav.classList.remove("scrolled");
    }
    lastScroll = scrollY;
  }, { passive: true });
}

// ── Scroll Reveal ─────────────────────────────────────────────────────────────

function initScrollReveal() {
  const targets = document.querySelectorAll(
    ".section-header, .arch-stage, .detail-card, .status-col, .phase-block, " +
    ".track-group, .start-card, .csv-format, .stat-card, .console-preview, " +
    ".module-table"
  );

  const observer = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add("visible");
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.08, rootMargin: "0px 0px -40px 0px" });

  let groupIndex = 0;
  targets.forEach(t => {
    t.classList.add("reveal");
    // Stagger siblings within the same parent
    const siblings = t.parentElement.querySelectorAll(":scope > .reveal");
    if (siblings.length > 1) {
      const idx = Array.from(siblings).indexOf(t);
      t.style.transitionDelay = `${idx * 80}ms`;
    }
    observer.observe(t);
    groupIndex++;
  });
}

// ── Revealed class ────────────────────────────────────────────────────────────

// (reveal/visible classes handled via styles.css)

// ── Init ──────────────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", async () => {
  renderStats();
  renderPipelineDetails();
  renderStatus();
  renderBacklog();
  await renderTracks();
  renderFields();
  initFilters();
  initNav();
  // Small delay to let elements render before observing
  requestAnimationFrame(() => initScrollReveal());
});
