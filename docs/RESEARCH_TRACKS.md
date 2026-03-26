# Research Tracks Status Map

This document translates the raw ideas in [`blueprint.md`](/Users/michelpicker/Library/Mobile Documents/com~apple~CloudDocs/Projekte/SentinelEdge/blueprint.md) into an implementation-aware status map.

Legend:

- **Implemented foundation**: there is already runnable code covering the basic control-loop shape.
- **Scaffolded**: the repo contains semantics or hooks, but not the research-grade mechanism.
- **Planned**: documented and backlog-tracked, but not started in code.
- **Future**: visible in the roadmap, but intentionally deferred until the core runtime matures.

## How to read the tracks

Each track should be read through three lenses:

- **Research idea**: the novel mechanism or systems claim the track is trying to establish.
- **Why it matters**: what capability it would unlock for a real edge-defense runtime.
- **Current repo state**: what the codebase already covers today, if anything.

The current prototype intentionally implements only the smallest useful control loop. Most of the novelty is still roadmap work, but the list below now spells out what each item would actually mean in practice.

## Core detection and fusion

- **R01 Learned Multi-Modal Anomaly Detection with On-Device Continual Learning** - **Implemented foundation**
  - Research idea: let the detector keep adapting to the device's own local patterns instead of relying on fixed thresholds or cloud retraining.
  - Why it matters: edge devices drift over time, so adaptive on-device learning is essential if anomaly detection is supposed to stay useful.
  - Current repo state: adaptive multi-signal scoring exists with a bounded replay buffer providing windowed statistics. Adaptation controls (freeze, decay, reset) support safe baseline management. Missing: continual learning loop, differential privacy, and proof-carrying update generation.
- **R02 Formal Verification of Detection Rules with Runtime Checking** - **Scaffolded**
  - Research idea: represent the detection policy as a formally specified state machine and validate runtime behavior against that specification.
  - Why it matters: it moves the system from "heuristically works" toward "we can state and check what correctness means."
  - Current repo state: a `PolicyStateMachine` records and validates all threat-level transitions against formally defined legal rules. Transition traces are exportable for future TLA+/Alloy model checking. Missing: actual TLA+/Alloy integration and automated invariant checking.
- **R03 Cross-Device Swarm Intelligence for Collective Anomaly Detection** - **Future**
  - Research idea: let multiple devices share partial threat signals and collectively detect patterns that any one node would miss.
  - Why it matters: many real attacks only become obvious when low-confidence evidence is aggregated across a fleet.
  - Current repo state: there is no cross-device communication in the prototype.
- **R04 Quantum-Inspired Anomaly Propagation Modeling** - **Future**
  - Research idea: use quantum-walk-inspired propagation models to predict how suspicious behavior may spread through a mesh or dependency graph.
  - Why it matters: it would turn SentinelEdge from purely reactive detection toward predictive isolation planning.
  - Current repo state: no propagation graph or predictive spread model exists yet.
- **R05 On-Device Model Poisoning Detection and Self-Recovery** - **Implemented foundation**
  - Research idea: detect when the local model or policy has been tampered with and recover to a known-good state.
  - Why it matters: a detector that can be poisoned without noticing is a weak security primitive.
  - Current repo state: four poisoning heuristics (mean shift, variance spike, drift accumulation, auth burst) analyze replay buffers for manipulation attempts. Adaptation controls allow freezing baselines during suspected poisoning. Rollback checkpoints are available. Missing: verified checkpoint rollback automation and recovery proofs.

## Response and mitigation

- **R06 Energy-Aware Verifiable Isolation with Graceful Degradation** - **Implemented foundation**
  - Research idea: choose mitigations that respect both security urgency and the device's energy budget, then prove the action matched policy.
  - Why it matters: edge security cannot assume desktop-class power or cooling.
  - Current repo state: energy-aware downgrade logic exists with pluggable action adapters (throttle, quarantine, isolate). Proof mechanisms are not yet implemented.
- **R07 Self-Healing Network Reconfiguration with ZK Proofs** - **Planned**
  - Research idea: after isolating compromised nodes, automatically repair the network topology while preserving security invariants.
  - Why it matters: isolation without recovery can turn defense into self-inflicted outage.
  - Current repo state: no topology model or repair engine exists yet.
- **R08 Privacy-Preserving Coordinated Response Across Devices** - **Future**
  - Research idea: let devices coordinate a shared defense action without exposing raw local telemetry.
  - Why it matters: fleet response becomes much more useful when it does not require centralized visibility into everything.
  - Current repo state: no secure multi-party coordination path exists yet.
- **R09 Adaptive Response Strength Based on Threat Severity and Battery State** - **Implemented foundation**
  - Research idea: map detection confidence and local constraints into different response intensities rather than a single fixed action.
  - Why it matters: it prevents overreaction on benign spikes and underreaction on truly dangerous events.
  - Current repo state: threat score and battery state shape the response, with pluggable adapter chain for multi-stage enforcement. Adaptation mode controls (Normal, Frozen, Decay) further refine detector sensitivity and baseline drift management.
- **R10 Verifiable Rollback and Forensic Recovery** - **Implemented foundation**
  - Research idea: restore device state to a known-safe checkpoint and preserve a verifiable record of what was changed.
  - Why it matters: recovery is far more credible when it can be replayed and audited after the incident.
  - Current repo state: rollback checkpoints are captured on severe/critical events in a bounded ring buffer. Forensic evidence bundles are exportable. Proof-carrying updates bind every baseline change with SHA-256 cryptographic evidence. Missing: real device state restore and cryptographic proof of restoration.

## Verifiability and audit

- **R11 Post-Quantum Secure Audit Logs** - **Implemented foundation**
  - Research idea: make the event history tamper-evident and signed with algorithms that remain viable in a post-quantum setting.
  - Why it matters: "verifiable security" depends on the evidence trail remaining trustworthy.
  - Current repo state: SHA-256 cryptographic digest chain with signed checkpoints and programmatic chain verification. Missing: post-quantum signature algorithms.
- **R12 Zero-Knowledge Proof of Entire Device State at Time T** - **Future**
  - Research idea: prove that a device was in a particular historical state without disclosing the underlying sensitive data.
  - Why it matters: it would allow audits and incident response without exposing full device contents.
  - Current repo state: there is no historical state proof machinery yet.
- **R13 Regulatory-Compliant Verifiable Export with Selective Disclosure** - **Scaffolded**
  - Research idea: export only the subset of logs or evidence required for a regulator while proving the rest was not altered.
  - Why it matters: many real deployments need auditability and privacy at the same time.
  - Current repo state: forensic bundle export and structured JSON reports provide a foundation. FP/FN benchmark harness enables precision/recall/F1 measurement for regulatory compliance evidence. Missing: selective disclosure and ZK-based redaction.
- **R14 Long-Term Archival with Energy-Harvesting Optimization** - **Future**
  - Research idea: defer expensive archival work until harvested energy is available, such as solar or scavenged power.
  - Why it matters: long-lived remote edge devices often operate under severe energy constraints.
  - Current repo state: there is no archival scheduler yet.
- **R15 Cross-Device Verifiable Threat Intelligence Sharing** - **Future**
  - Research idea: let nodes share threat indicators with proof of provenance and integrity.
  - Why it matters: shared signatures become more trustworthy when receivers can verify where they came from.
  - Current repo state: no threat-intelligence exchange protocol exists yet.

## Advanced and forward-looking

- **R16 On-Device Hardware Root-of-Trust Integration** - **Planned**
  - Research idea: bind critical keys or trust anchors to TPM, secure enclave, or similar hardware where available.
  - Why it matters: the runtime becomes harder to subvert when its root secrets are not just files on disk.
  - Current repo state: no hardware-attestation path exists yet.
- **R17 Wasm-Based Extensible Detection and Response Policies** - **Planned**
  - Research idea: let users ship custom detection or response logic as sandboxed Wasm modules.
  - Why it matters: it opens the project to extension without requiring forks of the core runtime.
  - Current repo state: no Wasm policy surface or sandbox exists yet.
- **R18 Energy-Proportional Model Quantization with Verifiability** - **Future**
  - Research idea: adjust model precision to save energy, while proving the detector stayed within an acceptable accuracy envelope.
  - Why it matters: edge deployments often need to trade precision for power without losing trust in the result.
  - Current repo state: the prototype does not include quantized models.
- **R19 Learned False-Positive Reduction with Causal Reasoning** - **Future**
  - Research idea: use lightweight causal models to distinguish actual threats from noisy correlations.
  - Why it matters: false positives are one of the fastest ways to make operators stop trusting a detector.
  - Current repo state: no causal inference layer exists yet.
- **R20 Verifiable Supply-Chain Attestation for Firmware and Models** - **Planned**
  - Research idea: prove that the running firmware and model artifacts match a known-good build or vendor-signed release.
  - Why it matters: it strengthens trust before runtime detection even begins.
  - Current repo state: no firmware/model attestation path exists yet.
- **R21 Quantum-Resistant Key Rotation with Minimal Energy Overhead** - **Future**
  - Research idea: rotate keys periodically using post-quantum-safe primitives without burning too much device energy.
  - Why it matters: key hygiene is essential, but heavy cryptography can be expensive on small devices.
  - Current repo state: the prototype has no key lifecycle subsystem.
- **R22 Cross-Platform Binary Self-Optimization** - **Future**
  - Research idea: let the runtime specialize itself for different target architectures and energy profiles.
  - Why it matters: the project is explicitly edge-oriented, so hardware diversity is part of the challenge.
  - Current repo state: there is no architecture-specific specialization logic yet.
- **R23 Verifiable Multi-Device Swarm Defense Coordination** - **Future**
  - Research idea: let multiple devices vote or coordinate on defensive action and prove the tally was honest.
  - Why it matters: collective defense becomes much stronger when no single node has to be blindly trusted.
  - Current repo state: there is no multi-device voting or swarm defense layer yet.
- **R24 Energy-Harvesting Aware Security Posture Adjustment** - **Future**
  - Research idea: adapt cryptographic or defensive intensity based on predicted near-term energy availability.
  - Why it matters: a node with scarce harvested power may need a different posture than one with abundant power.
  - Current repo state: there is no energy forecasting or posture scheduler yet.
- **R25 Long-Term Evolutionary Model Improvement** - **Future**
  - Research idea: let local models improve over months using bounded evolutionary search instead of one-shot training.
  - Why it matters: this is the longest-horizon path toward self-improving edge detection without permanent cloud dependence.
  - Current repo state: there is no long-horizon model adaptation system yet.

## Edge intelligence and explainability

- **R26 Explainable Anomaly Attribution** - **Future**
  - Research idea: on-device interpretable attribution that traces each anomaly score back to the contributing signals and their temporal context.
  - Why it matters: operators need to understand why an alert fired before they can trust and act on it. Opaque scores erode confidence.
  - Current repo state: the detector emits human-readable anomaly reasons, but there is no formal attribution framework (e.g., Shapley values).
- **R27 Federated Threat Model Distillation** - **Future**
  - Research idea: fleet-wide model improvement through federated learning rounds that distill knowledge into a compact student model suitable for constrained devices.
  - Why it matters: individual devices see limited threat diversity; federated distillation lets the fleet learn collectively without centralizing raw data.
  - Current repo state: no federated learning or model distillation infrastructure exists yet.
- **R28 Adversarial Robustness Testing Framework** - **Future**
  - Research idea: automated red-team harness that generates adversarial telemetry sequences designed to evade or confuse the detector.
  - Why it matters: a detector whose weaknesses have never been probed systematically is likely brittle against adaptive attackers.
  - Current repo state: benchmark harness measures FP/FN rates on fixed fixtures. No adversarial input generation or evasion testing exists.
- **R29 Temporal Logic Runtime Monitoring** - **Future**
  - Research idea: lightweight runtime monitor that checks live telemetry streams against LTL/CTL safety and liveness properties.
  - Why it matters: explicit temporal properties let the system state guarantees like "a critical alert is always followed by a response within N samples."
  - Current repo state: the policy state machine validates legal transitions, but general temporal logic monitoring is not implemented.
- **R30 Anomaly Correlation Graph Mining** - **Future**
  - Research idea: construct and maintain a lightweight causal correlation graph across signal dimensions to identify multi-stage attack patterns.
  - Why it matters: many advanced attacks show up as individually benign signals that become suspicious only when their temporal and causal relationships are visible.
  - Current repo state: signals are scored independently. No cross-signal causal graph or correlation mining exists.

## Edge infrastructure and hardening

- **R31 Digital Twin Simulation for Edge Fleets** - **Future**
  - Research idea: a deterministic simulation harness that models heterogeneous edge fleets for scenario testing and policy validation before live deployment.
  - Why it matters: testing policies and detection logic on a simulated fleet is far cheaper and safer than experimenting on production hardware.
  - Current repo state: deterministic test fixtures exist for single-device scenarios. No fleet-scale simulation harness exists.
- **R32 Autonomous Secure Patch Management** - **Future**
  - Research idea: self-patching edge runtime that verifies patch integrity before application and proves post-patch state correctness.
  - Why it matters: manual patching at scale is infeasible for large edge deployments; automated patching without verification is a supply-chain risk.
  - Current repo state: no patch management or binary update mechanism exists.
- **R33 Deception-Based Threat Engagement** - **Future**
  - Research idea: deploy lightweight honeypot services and canary tokens at the edge to detect lateral movement and attacker reconnaissance.
  - Why it matters: deception forces attackers to reveal themselves by interacting with synthetic assets that legitimate users never touch.
  - Current repo state: no deception layer or canary token system exists.
- **R34 Secure Multi-Tenancy Isolation** - **Future**
  - Research idea: namespace-isolated detection and response policies on shared edge hardware so multiple tenants coexist without cross-contamination.
  - Why it matters: shared edge infrastructure (e.g., gateways, concentrators) often serves multiple organizational tenants who must not see each other's data or interfere with each other's policies.
  - Current repo state: the runtime is single-tenant. No namespace isolation or per-tenant policy scoping exists.
- **R35 Side-Channel Attack Detection** - **Future**
  - Research idea: detect timing, power, and electromagnetic side-channel attacks using statistical profiling of device operational patterns.
  - Why it matters: side-channel attacks bypass software defenses entirely; detecting them requires observing the hardware layer through statistical anomalies.
  - Current repo state: all detection is based on software telemetry. No hardware-level side-channel profiling exists.

## Resilience and long-horizon

- **R36 Edge-Cloud Hybrid Offload with Verifiability** - **Future**
  - Research idea: decide when to offload expensive analysis to the cloud while proving that the cloud result was computed correctly and the raw data was not leaked.
  - Why it matters: some analyses are too expensive for edge hardware, but blind cloud offload sacrifices the privacy and autonomy advantages of edge processing.
  - Current repo state: the runtime is fully local. No cloud offload path or verifiable computation receipt system exists.
- **R37 Resilient Mesh Topology Self-Organisation** - **Future**
  - Research idea: autonomous mesh network formation and repair that maintains connectivity and security invariants after node loss or compromise.
  - Why it matters: edge networks in the field lose nodes to hardware failure, power loss, and compromise. Automatic topology repair is a prerequisite for sustained collective defense.
  - Current repo state: no topology awareness, mesh networking, or distributed spanning-tree logic exists.
- **R38 Behavioural Device Fingerprinting** - **Future**
  - Research idea: build a behavioural identity for each device based on its operational patterns, enabling impersonation detection without shared secrets.
  - Why it matters: device impersonation is a common edge attack vector. Behavioural fingerprints provide a second authentication factor that is hard to forge.
  - Current repo state: baselines characterize normal device behavior for anomaly scoring, but there is no explicit device identity or impersonation detection path.
- **R39 Formal Policy Composition and Conflict Resolution** - **Future**
  - Research idea: compose multiple detection and response policies with formal guarantees that the combined policy is free of contradictions and deadlocks.
  - Why it matters: realistic deployments layer multiple policies (vendor, operator, regulatory). Without composition guarantees, conflicting rules can cause silent failures or action paralysis.
  - Current repo state: a single policy engine maps scores to actions. No multi-policy composition, priority resolution, or conflict analysis exists.
- **R40 Privacy-Preserving Incident Forensics** - **Future**
  - Research idea: conduct post-incident forensic analysis across multiple devices without exposing raw sensor data to the investigating party.
  - Why it matters: incident response teams need evidence, but sharing raw edge telemetry with external investigators can violate privacy regulations or expose sensitive operational data.
  - Current repo state: forensic bundle export exists for single-device evidence. No multi-device privacy-preserving forensic query protocol exists.

## Interpretation

The codebase now makes the project concrete, but most of the research novelty remains ahead of us. That is deliberate: SentinelEdge can grow from a stable, testable prototype while still keeping the larger research agenda explicit and legible. The expansion from 25 to 40 tracks adds three new thematic areas — explainability and edge intelligence (R26–R30), infrastructure hardening (R31–R35), and long-horizon resilience (R36–R40) — reflecting the breadth of open problems in trustworthy edge security.
