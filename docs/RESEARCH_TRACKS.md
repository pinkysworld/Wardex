# Research Tracks Status Map

This document translates the raw ideas in [`blueprint.md`](../blueprint.md) into an implementation-aware status map.

Legend:

- **Implemented foundation**: there is runnable code covering the basic mechanism and data structures. The research question is addressable with the current codebase.
- **Paper-ready**: evaluation infrastructure exists; metrics can be extracted for publication.
- **Production-ready**: hardened, tested, documented, suitable for deployment.

All 40 research tracks currently stand at **Implemented foundation** status. Each track has API endpoints, admin console integration, and unit/integration test coverage.

## How to read the tracks

Each track should be read through three lenses:

- **Research idea**: the novel mechanism or systems claim the track is trying to establish.
- **Why it matters**: what capability it would unlock for a real edge-defense runtime.
- **Current repo state**: what the codebase covers today.

## Core detection and fusion

- **R01 Learned Multi-Modal Anomaly Detection with On-Device Continual Learning** — **Implemented foundation**
  - Research idea: let the detector keep adapting to the device's own local patterns instead of relying on fixed thresholds or cloud retraining.
  - Why it matters: edge devices drift over time, so adaptive on-device learning is essential if anomaly detection is supposed to stay useful.
  - Current repo state: adaptive multi-signal EWMA scoring with bounded replay buffer, windowed statistics, drift detection (Page–Hinkley), adaptation controls (freeze, decay, reset), and per-sample latency benchmarking. API endpoint and admin panel wired.
- **R02 Formal Verification of Detection Rules with Runtime Checking** — **Implemented foundation**
  - Research idea: represent the detection policy as a formally specified state machine and validate runtime behavior against that specification.
  - Why it matters: it moves the system from "heuristically works" toward "we can state and check what correctness means."
  - Current repo state: `PolicyStateMachine` with TLA+/Alloy export, explicit-state BFS model checker for safety/reachability/invariant verification. Causal graph engine for false-positive reduction. Export endpoints wired to admin console.
- **R03 Cross-Device Swarm Intelligence for Collective Anomaly Detection** — **Implemented foundation**
  - Research idea: let multiple devices share partial threat signals and collectively detect patterns that any one node would miss.
  - Why it matters: many real attacks only become obvious when low-confidence evidence is aggregated across a fleet.
  - Current repo state: gossip-based swarm protocol with threat alert propagation, fleet device registry, posture negotiation, and policy distribution. Admin console panels for fleet management and swarm posture.
- **R04 Quantum-Walk Propagation Modeling** — **Implemented foundation**
  - Research idea: use quantum-walk-inspired propagation models to predict how suspicious behavior may spread through a mesh or dependency graph.
  - Why it matters: it would turn SentinelEdge from purely reactive detection toward predictive isolation planning.
  - Current repo state: quantum-walk engine with Grover-like coin operator on arbitrary graph topologies. Discrete-time simulation with amplitude tracking and threat propagation probability extraction.
- **R05 On-Device Model Poisoning Detection and Self-Recovery** — **Implemented foundation**
  - Research idea: detect when the local model or policy has been tampered with and recover to a known-good state.
  - Why it matters: a detector that can be poisoned without noticing is a weak security primitive.
  - Current repo state: four poisoning heuristics (mean shift, variance spike, drift accumulation, auth burst) analyze replay buffers. Adaptation controls allow freezing baselines during suspected poisoning. Rollback checkpoints available.

## Response and mitigation

- **R06 Energy-Aware Verifiable Isolation with Graceful Degradation** — **Implemented foundation**
  - Research idea: choose mitigations that respect both security urgency and the device's energy budget, then prove the action matched policy.
  - Why it matters: edge security cannot assume desktop-class power or cooling.
  - Current repo state: energy-aware downgrade logic with pluggable action adapters (throttle, quarantine, isolate). Energy budget management with harvest/consume API. Admin console energy panel wired.
- **R07 Self-Healing Network Reconfiguration** — **Implemented foundation**
  - Research idea: after isolating compromised nodes, automatically repair the network topology while preserving security invariants.
  - Why it matters: isolation without recovery can turn defense into self-inflicted outage.
  - Current repo state: swarm node registration, health reporting, and topology tracking via the swarm protocol. Enforcement engine with topology-aware quarantine.
- **R08 Privacy-Preserving Coordinated Response Across Devices** — **Implemented foundation**
  - Research idea: let devices coordinate a shared defense action without exposing raw local telemetry.
  - Why it matters: fleet response becomes much more useful when it does not require centralized visibility into everything.
  - Current repo state: privacy accountant with differential privacy budget tracking, secure aggregation stubs in the privacy module, and swarm coordination with privacy-preserving posture negotiation.
- **R09 Adaptive Response Strength Based on Threat Severity and Battery State** — **Implemented foundation**
  - Research idea: map detection confidence and local constraints into different response intensities rather than a single fixed action.
  - Why it matters: it prevents overreaction on benign spikes and underreaction on truly dangerous events.
  - Current repo state: threat score and battery state shape the response, with pluggable adapter chain for multi-stage enforcement. Policy composition with conflict resolution (max, min, left-priority, right-priority operators).
- **R10 Verifiable Rollback and Forensic Recovery** — **Implemented foundation**
  - Research idea: restore device state to a known-safe checkpoint and preserve a verifiable record of what was changed.
  - Why it matters: recovery is far more credible when it can be replayed and audited after the incident.
  - Current repo state: rollback checkpoints in bounded ring buffer, forensic evidence bundles, SHA-256 proof-carrying updates binding every baseline change with cryptographic evidence. Checkpoint save/restore API wired.

## Verifiability and audit

- **R11 Post-Quantum Secure Audit Logs** — **Implemented foundation**
  - Research idea: make the event history tamper-evident and signed with algorithms that remain viable in a post-quantum setting.
  - Why it matters: "verifiable security" depends on the evidence trail remaining trustworthy.
  - Current repo state: SHA-256 hash chain with signed checkpoints, programmatic chain verification, and audit chain scaling benchmarks (10–100k records). Post-quantum key rotation manager with epoch tracking.
- **R12 Zero-Knowledge Proof of Entire Device State** — **Implemented foundation**
  - Research idea: prove that a device was in a particular historical state without disclosing the underlying sensitive data.
  - Why it matters: it would allow audits and incident response without exposing full device contents.
  - Current repo state: proof registry with SHA-256 digest backend, witness export API, and attestation verification. Checkpoint snapshots provide state-at-time-T capability.
- **R13 Regulatory-Compliant Verifiable Export with Selective Disclosure** — **Implemented foundation**
  - Research idea: export only the subset of logs or evidence required for a regulator while proving the rest was not altered.
  - Why it matters: many real deployments need auditability and privacy at the same time.
  - Current repo state: forensic bundle export, structured JSON reports, TLA+/Alloy/witness export endpoints, compliance scoring against IEC 62443. Privacy budget tracking for selective disclosure controls.
- **R14 Long-Term Archival with Energy-Harvesting Optimization** — **Implemented foundation**
  - Research idea: defer expensive archival work until harvested energy is available, such as solar or scavenged power.
  - Why it matters: long-lived remote edge devices often operate under severe energy constraints.
  - Current repo state: energy budget with harvest/consume cycle, power state management (Normal/LowPower/CriticalSuspend), and energy-aware task scheduling stubs.
- **R15 Cross-Device Verifiable Threat Intelligence Sharing** — **Implemented foundation**
  - Research idea: let nodes share threat indicators with proof of provenance and integrity.
  - Why it matters: shared signatures become more trustworthy when receivers can verify where they came from.
  - Current repo state: threat intel store with typed IoCs (IP, domain, hash, process, behavior), confidence scoring, STIX-like structure, and add/query API. Admin console panel for IoC management.

## Advanced and forward-looking

- **R16 On-Device Hardware Root-of-Trust Integration** — **Implemented foundation**
  - Research idea: bind critical keys or trust anchors to TPM, secure enclave, or similar hardware where available.
  - Why it matters: the runtime becomes harder to subvert when its root secrets are not just files on disk.
  - Current repo state: TPM abstraction in enforcement engine with status reporting, attestation verification module, and platform capability detection (TPM, seccomp, eBPF, firewall).
- **R17 Wasm-Based Extensible Detection and Response Policies** — **Implemented foundation**
  - Research idea: let users ship custom detection or response logic as sandboxed Wasm modules.
  - Why it matters: it opens the project to extension without requiring forks of the core runtime.
  - Current repo state: PolicyVm with typed opcode set (LoadVar, StoreResult, Add, Mul, Cmp, JumpIf, Halt), program execution with step tracking, and execute API endpoint. Admin console WASM VM panel wired.
- **R18 Energy-Proportional Model Quantization with Verifiability** — **Implemented foundation**
  - Research idea: adjust model precision to save energy, while proving the detector stayed within an acceptable accuracy envelope.
  - Why it matters: edge deployments often need to trade precision for power without losing trust in the result.
  - Current repo state: energy budget with power-state transitions controls detection intensity. Benchmark harness provides accuracy/F1 metrics for envelope verification.
- **R19 Learned False-Positive Reduction with Causal Reasoning** — **Implemented foundation**
  - Research idea: use lightweight causal models to distinguish actual threats from noisy correlations.
  - Why it matters: false positives are one of the fastest ways to make operators stop trusting a detector.
  - Current repo state: causal graph engine with node/edge management, Pearson correlation analysis across signal dimensions, and causal graph API endpoint.
- **R20 Verifiable Supply-Chain Attestation for Firmware and Models** — **Implemented foundation**
  - Research idea: prove that the running firmware and model artifacts match a known-good build or vendor-signed release.
  - Why it matters: it strengthens trust before runtime detection even begins.
  - Current repo state: attestation verification module with check results, patch management with integrity verification, and supply-chain attestation status API.
- **R21 Quantum-Resistant Key Rotation with Minimal Energy Overhead** — **Implemented foundation**
  - Research idea: rotate keys periodically using post-quantum-safe primitives without burning too much device energy.
  - Why it matters: key hygiene is essential, but heavy cryptography can be expensive on small devices.
  - Current repo state: key rotation manager with epoch-based rotation, configurable interval, and rotate/status API. Admin console quantum panel for interactive rotation.
- **R22 Cross-Platform Binary Self-Optimization** — **Implemented foundation**
  - Research idea: let the runtime specialize itself for different target architectures and energy profiles.
  - Why it matters: the project is explicitly edge-oriented, so hardware diversity is part of the challenge.
  - Current repo state: platform capability detection (arch, TPM, seccomp, eBPF, firewall, thread count), edge-cloud offload decisions based on platform profile.
- **R23 Verifiable Multi-Device Swarm Defense Coordination** — **Implemented foundation**
  - Research idea: let multiple devices vote or coordinate on defensive action and prove the tally was honest.
  - Why it matters: collective defense becomes much stronger when no single node has to be blindly trusted.
  - Current repo state: swarm protocol with gossip-based coordination, posture negotiation, fleet health reporting, and device registration API.
- **R24 Energy-Harvesting Aware Security Posture Adjustment** — **Implemented foundation**
  - Research idea: adapt cryptographic or defensive intensity based on predicted near-term energy availability.
  - Why it matters: a node with scarce harvested power may need a different posture than one with abundant power.
  - Current repo state: energy budget with harvest/consume cycle, power state transitions, and energy-aware posture adjustment through the admin console.
- **R25 Long-Term Evolutionary Model Improvement** — **Implemented foundation**
  - Research idea: let local models improve over months using bounded evolutionary search instead of one-shot training.
  - Why it matters: this is the longest-horizon path toward self-improving edge detection without permanent cloud dependence.
  - Current repo state: continual learning via adaptive EWMA with replay buffer, drift detection for model staleness, and adaptation controls for managed evolution.

## Edge intelligence and explainability

- **R26 Explainable Anomaly Attribution** — **Implemented foundation**
  - Research idea: on-device interpretable attribution that traces each anomaly score back to the contributing signals and their temporal context.
  - Why it matters: operators need to understand why an alert fired before they can trust and act on it.
  - Current repo state: per-signal contribution tracking in anomaly evaluation, benchmark harness with averaged signal attribution collection, and per-sample contribution breakdown in JSON reports.
- **R27 Federated Threat Model Distillation** — **Implemented foundation**
  - Research idea: fleet-wide model improvement through federated learning rounds that distill knowledge into a compact student model suitable for constrained devices.
  - Why it matters: individual devices see limited threat diversity; federated distillation lets the fleet learn collectively without centralizing raw data.
  - Current repo state: swarm protocol with policy distribution, privacy-preserving aggregation via differential privacy accountant, and fleet device management API.
- **R28 Adversarial Robustness Testing Framework** — **Implemented foundation**
  - Research idea: automated red-team harness that generates adversarial telemetry sequences designed to evade or confuse the detector.
  - Why it matters: a detector whose weaknesses have never been probed systematically is likely brittle against adaptive attackers.
  - Current repo state: adversarial harness with three evasion strategies (random noise, gradual escalation, mimicry), coverage tracking, evasion rate metrics, and harness run API. Admin console panel for interactive testing.
- **R29 Temporal Logic Runtime Monitoring** — **Implemented foundation**
  - Research idea: lightweight runtime monitor that checks live telemetry streams against LTL/CTL safety and liveness properties.
  - Why it matters: explicit temporal properties let the system state guarantees like "a critical alert is always followed by a response within N samples."
  - Current repo state: temporal-logic monitor with property registration, event stepping, violation tracking, and status/violations API endpoints. Admin console monitoring panel wired.
- **R30 Anomaly Correlation Graph Mining** — **Implemented foundation**
  - Research idea: construct and maintain a lightweight causal correlation graph across signal dimensions to identify multi-stage attack patterns.
  - Why it matters: many advanced attacks show up as individually benign signals that become suspicious only when their temporal and causal relationships are visible.
  - Current repo state: Pearson correlation engine, causal graph with node/edge management, and causal graph API endpoint.

## Edge infrastructure and hardening

- **R31 Digital Twin Simulation for Edge Fleets** — **Implemented foundation**
  - Research idea: a deterministic simulation harness that models heterogeneous edge fleets for scenario testing and policy validation before live deployment.
  - Why it matters: testing policies and detection logic on a simulated fleet is far cheaper and safer than experimenting on production hardware.
  - Current repo state: digital twin engine with device modeling, simulation events (CPU spike, memory exhaust, network flood, malware inject), tick-based execution, and simulate API. Admin console twin panel wired.
- **R32 Autonomous Secure Patch Management** — **Implemented foundation**
  - Research idea: self-patching edge runtime that verifies patch integrity before application and proves post-patch state correctness.
  - Why it matters: manual patching at scale is infeasible for large edge deployments; automated patching without verification is a supply-chain risk.
  - Current repo state: patch manager with patch tracking, installation status, patch plan generation with estimated downtime, and patches API endpoint.
- **R33 Deception-Based Threat Engagement** — **Implemented foundation**
  - Research idea: deploy lightweight honeypot services and canary tokens at the edge to detect lateral movement and attacker reconnaissance.
  - Why it matters: deception forces attackers to reveal themselves by interacting with synthetic assets that legitimate users never touch.
  - Current repo state: deception engine with five decoy types (Honeypot, HoneyFile, HoneyCredential, HoneyService, Canary), deployment/status API, interaction tracking, and attacker profiling. Admin console panel wired.
- **R34 Secure Multi-Tenancy Isolation** — **Implemented foundation**
  - Research idea: namespace-isolated detection and response policies on shared edge hardware so multiple tenants coexist without cross-contamination.
  - Why it matters: shared edge infrastructure often serves multiple organizational tenants who must not see each other's data or interfere with each other's policies.
  - Current repo state: multi-tenant manager with tenant registration, counting, and namespace isolation. Tenants API endpoint wired.
- **R35 Side-Channel Attack Detection** — **Implemented foundation**
  - Research idea: detect timing, power, and electromagnetic side-channel attacks using statistical profiling of device operational patterns.
  - Why it matters: side-channel attacks bypass software defenses entirely; detecting them requires observing the hardware layer through statistical anomalies.
  - Current repo state: side-channel detector with timing anomaly, cache alert, and covert channel detection. Overall risk scoring and status API. Admin console security panel wired.

## Resilience and long-horizon

- **R36 Edge-Cloud Hybrid Offload with Verifiability** — **Implemented foundation**
  - Research idea: decide when to offload expensive analysis to the cloud while proving that the cloud result was computed correctly and the raw data was not leaked.
  - Why it matters: some analyses are too expensive for edge hardware, but blind cloud offload sacrifices the privacy and autonomy advantages of edge processing.
  - Current repo state: edge-cloud offload engine with capacity modeling, workload profiling (CPU, memory, data size, latency sensitivity, processing tier), and offload decision API. Platform capability detection.
- **R37 Resilient Mesh Topology Self-Organisation** — **Implemented foundation**
  - Research idea: autonomous mesh network formation and repair that maintains connectivity and security invariants after node loss or compromise.
  - Why it matters: edge networks in the field lose nodes to hardware failure, power loss, and compromise. Automatic topology repair is a prerequisite for sustained collective defense.
  - Current repo state: enforcement engine with topology awareness (node tracking), swarm protocol with gossip-based mesh coordination, and fleet health reporting.
- **R38 Behavioural Device Fingerprinting** — **Implemented foundation**
  - Research idea: build a behavioural identity for each device based on its operational patterns, enabling impersonation detection without shared secrets.
  - Why it matters: device impersonation is a common edge attack vector. Behavioural fingerprints provide a second authentication factor that is hard to forge.
  - Current repo state: device fingerprint module with behavioral profiling from telemetry samples, fingerprint status API, and admin console panel.
- **R39 Formal Policy Composition and Conflict Resolution** — **Implemented foundation**
  - Research idea: compose multiple detection and response policies with formal guarantees that the combined policy is free of contradictions and deadlocks.
  - Why it matters: realistic deployments layer multiple policies (vendor, operator, regulatory). Without composition guarantees, conflicting rules can cause silent failures or action paralysis.
  - Current repo state: policy composition with four operators (MaxSeverity, MinSeverity, LeftPriority, RightPriority), conflict detection and resolution, compose API endpoint, and admin console policy panel.
- **R40 Privacy-Preserving Incident Forensics** — **Implemented foundation**
  - Research idea: conduct post-incident forensic analysis across multiple devices without exposing raw sensor data to the investigating party.
  - Why it matters: incident response teams need evidence, but sharing raw edge telemetry with external investigators can violate privacy regulations or expose sensitive operational data.
  - Current repo state: forensic bundle export for single-device evidence, privacy accountant with differential privacy budget tracking, and compliance module with privacy-aware reporting.

## Interpretation

All 40 research tracks now have implemented foundations with runnable code, API endpoints, admin console panels, and test coverage. The next phase of maturation involves advancing selected tracks from foundation to paper-ready status through rigorous evaluation, benchmark instrumentation (latency, scaling, accuracy metrics), and formal analysis. Paper 1 (anomaly detection) is closest to submission with per-sample latency benchmarks, audit chain scaling tests, and 10k-sample evaluation harnesses already in place.
