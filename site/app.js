/* ═══════════════════════════════════════════════════════════════════════════
   SentinelEdge — Site Logic v4
   Data-driven rendering. Researcher tone. No marketing fluff.
   ═══════════════════════════════════════════════════════════════════════════ */

// ── Project Data ──────────────────────────────────────────────────────────────

const stats = [
  { value: "17", label: "core runtime modules" },
  { value: "8",  label: "telemetry dimensions" },
  { value: "40", label: "research tracks mapped" },
  { value: "52", label: "automated tests" },
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
    note: "Adaptation modes (Normal, Frozen, Decay) are implemented (T041). Continual learning and differential privacy remain R01 scope."
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
    note: "Six CLI commands: demo, analyze, report, init-config, status, serve."
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
  ],
  scaffolded: [
    "ZK proof placeholder in proof-carrying metadata — Halo2/SNARK deferred (R12)",
    "TLA+/Alloy export stubs in state machine — formal checker integration deferred (R02)",
    "Checkpoint state restoration — snapshots captured, restore not yet wired (R10)",
    "Post-quantum audit signatures — SHA-256 chain in place, PQ signatures deferred (R11)",
    "Research-track status accounting across all 40 blueprint items",
  ],
  deferred: [
    "Continual learning, replay buffers, on-device model training",
    "Differential privacy guarantees",
    "Zero-knowledge proofs (Halo2, zk-SNARKs)",
    "Formal rule verification / TLA+ model checking",
    "Swarm or cross-device coordination protocols",
    "Quantum-walk anomaly propagation modeling",
    "Secure MPC / private set intersection",
    "Post-quantum signatures and hardware roots of trust",
    "Wasm-based extensible policy plugins",
    "Supply-chain firmware attestation",
    "Energy-harvesting archival scheduling",
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
];

const trackGroups = [
  {
    id: "detection",
    label: "Core Detection & Fusion",
    tracks: [
      {
        code: "R01", status: "foundation",
        title: "Adaptive Anomaly Detection with Continual Learning",
        summary: "On-device adaptive scoring that learns local baselines rather than relying on fixed thresholds or periodic cloud retraining.",
        idea: "TinyML-style continual learning with replay buffer, Laplace noise for differential privacy, and Halo2 circuits for update integrity proofs.",
        matters: "Edge devices drift over time. A static detector becomes unreliable within weeks of deployment in most real environments.",
        state: "Adaptive multi-signal EWMA scoring is implemented with a bounded replay buffer providing windowed statistics. Adaptation controls (freeze, decay, reset) support safe baseline management. Missing: continual learning loop, differential privacy, and proof-carrying updates.",
      },
      {
        code: "R02", status: "scaffolded",
        title: "Formal Verification of Detection Rules",
        summary: "Represent detection logic as a formally specified state machine and verify runtime conformance against that specification.",
        idea: "Embedded TLA+-to-Rust model checker with a zk-SNARK for rule-satisfaction proofs.",
        matters: "Shifts the correctness argument from 'it seems to work' to 'we can state and check what correctness means.'",
        state: "A PolicyStateMachine records and validates all threat-level transitions against formally defined legal rules. Transition traces are exportable for future TLA+/Alloy model checking. Missing: actual TLA+/Alloy integration.",
      },
      {
        code: "R03", status: "future",
        title: "Cross-Device Swarm Intelligence",
        summary: "Privacy-preserving collaborative detection where devices share partial threat signals without exposing raw telemetry.",
        idea: "Private set intersection combined with federated averaging and ZK proofs of honest participation.",
        matters: "Many real attacks only become visible when low-confidence evidence is aggregated across a fleet.",
        state: "No cross-device communication exists in the prototype.",
      },
      {
        code: "R04", status: "future",
        title: "Quantum-Walk Propagation Modeling",
        summary: "Use classical simulation of quantum walks to predict how anomalies spread through mesh topologies.",
        idea: "Discrete-time quantum walk simulation on device topology graphs with learned damping factors.",
        matters: "Would shift SentinelEdge from purely reactive detection toward predictive isolation planning.",
        state: "No propagation graph or predictive spread model exists yet.",
      },
      {
        code: "R05", status: "foundation",
        title: "Model Poisoning Detection and Recovery",
        summary: "Detect when the local model or policy has been tampered with, then recover to a verified safe state.",
        idea: "Spectral poisoning analysis combined with Merkle-rooted model checkpoints and cryptographic recovery proofs.",
        matters: "A detector that can be poisoned without noticing is a fundamentally weak security primitive.",
        state: "Four poisoning heuristics (mean shift, variance spike, drift accumulation, auth burst) analyze replay buffers for manipulation attempts. Adaptation controls allow freezing baselines during suspected poisoning. Missing: verified checkpoint rollback and recovery proofs.",
      },
    ],
  },
  {
    id: "response",
    label: "Response & Mitigation",
    tracks: [
      {
        code: "R06", status: "foundation",
        title: "Energy-Aware Verifiable Isolation",
        summary: "Select mitigations that respect both security urgency and the device energy budget, with proofs that the action matched policy.",
        idea: "Priority queue with energy cost model plus a proof circuit for compliance verification.",
        matters: "Edge security cannot assume desktop-class power or cooling. The mitigation has to fit the device.",
        state: "Energy-aware downgrade logic and pluggable action adapters (logging, throttle, quarantine, isolate) are implemented. Missing: formal proof mechanisms.",
      },
      {
        code: "R07", status: "planned",
        title: "Self-Healing Network Reconfiguration",
        summary: "After isolating compromised nodes, automatically repair the network topology while preserving security invariants.",
        idea: "Graph repair algorithms with zk-SNARK proofs that the new configuration maintains stated invariants.",
        matters: "Isolation without recovery turns defensive action into self-inflicted outage.",
        state: "No topology model or repair engine exists yet.",
      },
      {
        code: "R08", status: "future",
        title: "Privacy-Preserving Coordinated Response",
        summary: "Let devices coordinate defensive actions (e.g., collective quarantine) without revealing individual sensor data.",
        idea: "Secure multi-party computation adapted for low-power device constraints.",
        matters: "Fleet-level response becomes practical when it does not require a centralised view of everything.",
        state: "No secure multi-party coordination path exists yet.",
      },
      {
        code: "R09", status: "foundation",
        title: "Adaptive Response Strength",
        summary: "Map detection confidence and local constraints into different response intensities rather than a single fixed action.",
        idea: "Continuous response scaling: observe → rate-limit → quarantine → rollback-and-escalate, shaped by a learned policy with energy penalty.",
        matters: "Prevents overreaction on benign spikes and underreaction on genuinely dangerous events.",
        state: "Threat score and battery state shape response selection. Pluggable adapters dispatch concrete actions through a composable chain. Adaptation mode controls (Normal, Frozen, Decay) further refine detector sensitivity.",
      },
      {
        code: "R10", status: "foundation",
        title: "Verifiable Rollback and Forensic Recovery",
        summary: "Restore device state to a known-safe checkpoint and preserve a verifiable record of what was changed.",
        idea: "Merkle-based snapshotting with ZK range proofs for restoration integrity.",
        matters: "Recovery is far more credible when it can be replayed and audited after the incident.",
        state: "Rollback checkpoints capture detector state on severe/critical events. Forensic bundle exporter produces human-readable evidence reports. Proof-carrying updates bind every baseline change with SHA-256 cryptographic evidence. Missing: Merkle proofs and actual state restoration.",
      },
    ],
  },
  {
    id: "audit",
    label: "Verifiability & Audit",
    tracks: [
      {
        code: "R11", status: "foundation",
        title: "Post-Quantum Secure Audit Logs",
        summary: "Tamper-evident event logs signed with algorithms that remain viable in a post-quantum setting.",
        idea: "Hybrid classical + PQ signature scheme (Dilithium/Falcon) with a seamless in-place upgrade path.",
        matters: "The entire 'verifiable security' claim depends on the evidence trail remaining trustworthy long-term.",
        state: "SHA-256 cryptographic digest chain and signed audit checkpoints are implemented. End-to-end chain verification is operational. Missing: post-quantum signature upgrade.",
      },
      {
        code: "R12", status: "future",
        title: "Zero-Knowledge Device State Proof",
        summary: "Prove that a device was in a particular historical state without disclosing the underlying data.",
        idea: "Recursive zk-SNARKs over Merkle history for privacy-preserving attestation.",
        matters: "Allows audits and incident response without exposing full device contents to the auditor.",
        state: "No historical state proof machinery exists yet.",
      },
      {
        code: "R13", status: "scaffolded",
        title: "Regulatory-Compliant Selective Disclosure",
        summary: "Export only the subset of logs a regulator requires while proving the rest was not altered.",
        idea: "zk-SNARK-based log redaction with integrity proofs.",
        matters: "Many deployments need to satisfy auditability and privacy constraints simultaneously.",
        state: "Forensic bundle exports provide structured evidence subsets. FP/FN benchmark harness enables precision/recall/F1 measurement for regulatory compliance evidence. ZK-based redaction proofs remain deferred.",
      },
      {
        code: "R14", status: "future",
        title: "Energy-Harvesting Archival Scheduling",
        summary: "Defer expensive archival operations until harvested energy (solar, scavenged) is available.",
        idea: "Predictive harvesting model combined with deferred compaction scheduling.",
        matters: "Long-lived remote edge devices often operate under severe, variable energy constraints.",
        state: "No archival scheduler exists yet.",
      },
      {
        code: "R15", status: "future",
        title: "Cross-Device Threat Intelligence Sharing",
        summary: "Share anonymised threat indicators across devices with proof of provenance and integrity.",
        idea: "Privacy-preserving set union with signed, verifiable provenance chains.",
        matters: "Shared threat signatures become more valuable when receivers can verify their origin.",
        state: "No threat-intelligence exchange protocol exists yet.",
      },
    ],
  },
  {
    id: "advanced",
    label: "Advanced & Forward-Looking",
    tracks: [
      {
        code: "R16", status: "planned",
        title: "Hardware Root-of-Trust Integration",
        summary: "Bind critical keys or trust anchors to TPM / secure enclave hardware where available.",
        idea: "Conditional compilation with hardware-attested key storage and a software fallback path.",
        matters: "The runtime becomes substantially harder to subvert when root secrets are not just files on disk.",
        state: "No hardware-attestation path exists yet.",
      },
      {
        code: "R17", status: "planned",
        title: "Wasm-Based Extensible Policies",
        summary: "Let operators ship custom detection or response logic as sandboxed WebAssembly modules.",
        idea: "Sandboxed Wasm interpreter with resource accounting and energy compliance verification.",
        matters: "Opens the project to domain-specific extension without forking the core runtime.",
        state: "No Wasm policy surface or sandbox exists yet.",
      },
      {
        code: "R18", status: "future",
        title: "Energy-Proportional Model Quantization",
        summary: "Adjust model precision dynamically to save energy while proving accuracy stayed above a threshold.",
        idea: "Quantization-aware training combined with ZK accuracy proofs.",
        matters: "Edge deployments routinely trade precision for power. The question is whether you can do that without losing trust in the result.",
        state: "The prototype does not include quantized models.",
      },
      {
        code: "R19", status: "future",
        title: "Causal False-Positive Reduction",
        summary: "Use lightweight causal inference to distinguish real threats from noisy correlations.",
        idea: "Tiny on-device causal graph inference for anomaly signal filtering.",
        matters: "False positives are one of the fastest ways to erode operator trust in any detection system.",
        state: "No causal inference layer exists yet.",
      },
      {
        code: "R20", status: "planned",
        title: "Supply-Chain Firmware Attestation",
        summary: "Prove that the running firmware and model artifacts match a known-good vendor-signed build.",
        idea: "Remote attestation combined with Merkle root verification of the binary.",
        matters: "Strengthens trust at the base layer — before runtime detection even begins.",
        state: "No firmware or model attestation path exists yet.",
      },
      {
        code: "R21", status: "future",
        title: "Quantum-Resistant Key Rotation",
        summary: "Periodic key rotation using post-quantum algorithms, optimised for battery life.",
        idea: "Key ratcheting combined with energy-aware scheduling of expensive PQ operations.",
        matters: "Key hygiene matters, but heavy cryptography can be prohibitively expensive on small devices.",
        state: "The prototype has no key lifecycle subsystem.",
      },
      {
        code: "R22", status: "future",
        title: "Cross-Platform Binary Self-Optimisation",
        summary: "Let the runtime specialise itself for different target architectures and energy profiles.",
        idea: "JIT-like architecture-aware specialisation for heterogeneous edge hardware.",
        matters: "The project targets edge devices, so hardware diversity is part of the problem space.",
        state: "No architecture-specific specialisation logic exists yet.",
      },
      {
        code: "R23", status: "future",
        title: "Verifiable Swarm Defence Coordination",
        summary: "Multiple devices vote on threats with ZK-verifiable tallying, so no single node must be blindly trusted.",
        idea: "Threshold signatures combined with privacy-preserving voting and Byzantine-fault-tolerant coordination.",
        matters: "Collective defence becomes practical when individual participants cannot be forced to lie undetectably.",
        state: "No multi-device voting or swarm defence layer exists yet.",
      },
      {
        code: "R24", status: "future",
        title: "Energy-Harvesting Posture Adjustment",
        summary: "Adapt cryptographic or defensive intensity based on predicted near-term energy availability.",
        idea: "Predictive energy-aware security posture scheduling with formal trade-off guarantees.",
        matters: "A node on scarce harvested power needs a different security posture than one with mains power.",
        state: "No energy forecasting or posture scheduler exists yet.",
      },
      {
        code: "R25", status: "future",
        title: "Evolutionary Model Improvement",
        summary: "On-device bounded evolutionary search for long-term detection model improvement without cloud dependency.",
        idea: "Genetic algorithms with ZK fitness proofs, operating on a months-long timescale.",
        matters: "The longest-horizon path toward self-improving edge detection without permanent cloud reliance.",
        state: "No long-horizon model adaptation system exists yet.",
      },
    ],
  },
  {
    id: "intelligence",
    label: "Edge Intelligence & Explainability",
    tracks: [
      {
        code: "R26", status: "future",
        title: "Explainable Anomaly Attribution",
        summary: "On-device interpretable attribution tracing each anomaly score to contributing signals and temporal context.",
        idea: "Shapley-value approximation adapted for streaming edge data with bounded compute budget.",
        matters: "Operators need to understand why an alert fired before they can trust and act on it.",
        state: "Human-readable anomaly reasons exist but there is no formal attribution framework (e.g., Shapley values).",
      },
      {
        code: "R27", status: "future",
        title: "Federated Threat Model Distillation",
        summary: "Fleet-wide model improvement through federated learning rounds distilled into compact student models.",
        idea: "Federated averaging with knowledge distillation, differential privacy, and proof-of-participation.",
        matters: "Individual devices see limited threat diversity; federated distillation lets the fleet learn collectively.",
        state: "No federated learning or model distillation infrastructure exists yet.",
      },
      {
        code: "R28", status: "future",
        title: "Adversarial Robustness Testing",
        summary: "Automated red-team harness generating adversarial telemetry sequences to probe detector weaknesses.",
        idea: "Gradient-free black-box attack synthesis (genetic perturbation, boundary probing) with coverage metrics.",
        matters: "A detector never probed adversarially is likely brittle against adaptive attackers.",
        state: "Benchmark harness measures FP/FN on fixed fixtures. No adversarial input generation exists.",
      },
      {
        code: "R29", status: "future",
        title: "Temporal Logic Runtime Monitoring",
        summary: "Lightweight monitor checking live telemetry against LTL/CTL safety and liveness properties.",
        idea: "On-the-fly LTL monitoring with bounded history, automaton compilation, and violation attestation.",
        matters: "Explicit temporal properties enable guarantees like 'a critical alert is always followed by a response within N samples.'",
        state: "The policy state machine validates legal transitions but general temporal logic monitoring is not implemented.",
      },
      {
        code: "R30", status: "future",
        title: "Anomaly Correlation Graph Mining",
        summary: "Construct lightweight causal correlation graphs across signal dimensions for multi-stage attack detection.",
        idea: "Incremental Granger-causality estimation on windowed replay buffers with graph-based alert clustering.",
        matters: "Many advanced attacks present as individually benign signals that become suspicious only when correlated.",
        state: "Signals are scored independently. No cross-signal causal graph exists.",
      },
    ],
  },
  {
    id: "infrastructure",
    label: "Edge Infrastructure & Hardening",
    tracks: [
      {
        code: "R31", status: "future",
        title: "Digital Twin Fleet Simulation",
        summary: "Deterministic simulation harness modelling heterogeneous edge fleets for scenario testing.",
        idea: "Discrete-event simulation with pluggable device profiles, attack injection, and differential comparison.",
        matters: "Testing on a simulated fleet is cheaper and safer than experimenting on production hardware.",
        state: "Deterministic test fixtures exist for single-device scenarios. No fleet-scale simulation.",
      },
      {
        code: "R32", status: "future",
        title: "Autonomous Secure Patch Management",
        summary: "Self-patching runtime that verifies patch integrity and proves post-patch state correctness.",
        idea: "Signed delta patches with Merkle-rooted binary verification and automatic rollback on failure.",
        matters: "Manual patching at scale is infeasible; automated patching without verification is a supply-chain risk.",
        state: "No patch management or binary update mechanism exists.",
      },
      {
        code: "R33", status: "future",
        title: "Deception-Based Threat Engagement",
        summary: "Lightweight honeypots and canary tokens at the edge to detect lateral movement and reconnaissance.",
        idea: "Synthetic service emulation with canary credential injection and automated alert escalation.",
        matters: "Deception forces attackers to reveal themselves by interacting with assets legitimate users never touch.",
        state: "No deception layer or canary token system exists.",
      },
      {
        code: "R34", status: "future",
        title: "Secure Multi-Tenancy Isolation",
        summary: "Namespace-isolated detection and response policies on shared edge hardware.",
        idea: "Per-tenant policy scoping, resource accounting, and cryptographic namespace separation.",
        matters: "Shared edge gateways often serve multiple tenants who must not see each other's data.",
        state: "The runtime is single-tenant. No namespace isolation exists.",
      },
      {
        code: "R35", status: "future",
        title: "Side-Channel Attack Detection",
        summary: "Detect timing, power, and EM side-channel attacks via statistical profiling of device operations.",
        idea: "High-frequency sampling of execution timing and power draw with anomaly detection on side-channel signals.",
        matters: "Side-channel attacks bypass software defenses entirely; detecting them requires hardware-layer observation.",
        state: "All detection is software-telemetry based. No hardware-level side-channel profiling.",
      },
    ],
  },
  {
    id: "resilience",
    label: "Resilience & Long-Horizon",
    tracks: [
      {
        code: "R36", status: "future",
        title: "Edge-Cloud Hybrid Offload",
        summary: "Decide when to offload expensive analysis to the cloud with verifiable computation receipts.",
        idea: "Selective offload policy with encrypted transfer, verifiable computation receipts, and local validation.",
        matters: "Some analyses are too expensive for edge hardware, but blind cloud offload sacrifices privacy and autonomy.",
        state: "Runtime is fully local. No cloud offload path exists.",
      },
      {
        code: "R37", status: "future",
        title: "Resilient Mesh Self-Organisation",
        summary: "Autonomous mesh network formation and repair maintaining security invariants after node loss.",
        idea: "Distributed spanning-tree repair with cryptographic neighbour authentication and convergence proofs.",
        matters: "Edge networks lose nodes to failure and compromise; automatic repair is a prerequisite for collective defense.",
        state: "No topology awareness or mesh networking exists.",
      },
      {
        code: "R38", status: "future",
        title: "Behavioural Device Fingerprinting",
        summary: "Behavioural identity based on operational patterns for impersonation detection without shared secrets.",
        idea: "Statistical device profiling from telemetry baselines with drift-based identity verification.",
        matters: "Device impersonation is a common edge attack; behavioural fingerprints provide a hard-to-forge second factor.",
        state: "Baselines characterise normal behaviour for anomaly scoring but no explicit device identity system exists.",
      },
      {
        code: "R39", status: "future",
        title: "Formal Policy Composition",
        summary: "Compose multiple policies with formal guarantees against contradictions and deadlocks.",
        idea: "Policy algebra with automated conflict detection, priority resolution, and model-checked composition proofs.",
        matters: "Realistic deployments layer vendor, operator, and regulatory policies that can silently conflict.",
        state: "A single policy engine maps scores to actions. No multi-policy composition exists.",
      },
      {
        code: "R40", status: "future",
        title: "Privacy-Preserving Incident Forensics",
        summary: "Cross-device forensic analysis without exposing raw sensor data to investigators.",
        idea: "Secure multi-party computation for forensic queries with ZK evidence-consistency proofs.",
        matters: "Incident response teams need evidence, but sharing raw telemetry can violate privacy regulations.",
        state: "Single-device forensic export exists. No multi-device privacy-preserving forensic protocol.",
      },
    ],
  },
];

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

function renderTracks() {
  const container = document.getElementById("tracks-container");
  if (!container) return;

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
    ".track-group, .start-card, .csv-format, .stat-card, .console-preview"
  );

  const observer = new IntersectionObserver(entries => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add("revealed");
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.1 });

  targets.forEach(t => {
    t.style.opacity = "0";
    t.style.transform = "translateY(16px)";
    t.style.transition = "opacity 500ms ease, transform 500ms ease";
    const delay = t.style.getPropertyValue("--stagger");
    if (delay) t.style.transitionDelay = delay;
    observer.observe(t);
  });
}

// ── Revealed class ────────────────────────────────────────────────────────────

const style = document.createElement("style");
style.textContent = `.revealed { opacity: 1 !important; transform: translateY(0) !important; }`;
document.head.appendChild(style);

// ── Init ──────────────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  renderStats();
  renderPipelineDetails();
  renderStatus();
  renderBacklog();
  renderTracks();
  renderFields();
  initFilters();
  initNav();
  // Small delay to let elements render before observing
  requestAnimationFrame(() => initScrollReveal());
});
