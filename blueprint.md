
### **Wardex 

**Core Detection & Fusion Tracks**  
**R01 Learned Multi-Modal Anomaly Detection with On-Device Continual Learning**  
Novelty: First embedded runtime that performs continual learning on-device while preserving differential privacy and generating ZK proofs of model updates. Technical approach: TinyML with replay buffer + Laplace noise + Halo2 circuit for update integrity.

**R02 Formal Verification of Detection Rules with Runtime Checking**  
Novelty: Runtime verification engine that checks detection rules against a formal specification (TLA+ exported to Rust) and proves compliance in ZK. Technical approach: Embedded model checker + zk-SNARK for rule satisfaction.

**R03 Cross-Device Swarm Intelligence for Collective Anomaly Detection**  
Novelty: Devices form ad-hoc swarms and collaboratively detect threats using privacy-preserving gossip + ZK aggregation. Technical approach: Private set intersection + federated averaging with proof of honest participation.

**R04 Quantum-Inspired Anomaly Propagation Modeling**  
Novelty: Uses classical simulation of quantum walks to model how anomalies spread across a mesh, enabling predictive isolation. Technical approach: Discrete-time quantum walk simulation on-device with learned damping factors.

**R05 On-Device Model Poisoning Detection and Self-Recovery**  
Novelty: First runtime that detects poisoned on-device models in real time and rolls back to a verified safe state with cryptographic proof. Technical approach: Spectral signature analysis + Merkle-rooted model checkpoints.

**Response & Mitigation Tracks**  
**R06 Energy-Aware Verifiable Isolation with Graceful Degradation**  
Novelty: Isolation actions are energy-proportional (e.g. soft throttling before full quarantine) and come with ZK proof of correctness. Technical approach: Priority queue with energy cost model + proof circuit.

**R07 Self-Healing Network Reconfiguration with ZK Proofs**  
Novelty: Automatic topology repair after isolation with mathematical proof that the new configuration maintains security invariants. Technical approach: Graph repair algorithms + zk-SNARK for invariant preservation.

**R08 Privacy-Preserving Coordinated Response Across Devices**  
Novelty: Multiple devices coordinate responses (e.g. collective quarantine) without revealing individual sensor data. Technical approach: Secure multi-party computation adapted for low-power devices.

**R09 Adaptive Response Strength Based on Threat Severity and Battery State**  
Novelty: Dynamic response scaling using a learned policy that balances security and energy. Technical approach: Reinforcement learning with energy penalty in reward function.

**R10 Verifiable Rollback and Forensic Recovery**  
Novelty: After attack, the device can prove it returned to a known-safe state with full audit trail. Technical approach: Merkle-based snapshotting + ZK range proofs.

**Verifiability & Audit Tracks**  
**R11 Post-Quantum Secure Audit Logs**  
Novelty: All proofs and logs are post-quantum ready (using Dilithium or Falcon signatures). Technical approach: Hybrid classical + PQ signature scheme with seamless upgrade path.

**R12 Zero-Knowledge Proof of Entire Device State at Time T**  
Novelty: Prove the complete system state (logs + models + configuration) at any past timestamp without revealing data. Technical approach: Recursive zk-SNARKs over Merkle history.

**R13 Regulatory-Compliant Verifiable Export with Selective Disclosure**  
Novelty: Export only the minimum required data for audits while proving the rest was not altered. Technical approach: zk-SNARK-based redaction.

**R14 Long-Term Archival with Energy-Harvesting Optimization**  
Novelty: Archival strategy that only flushes to persistent storage when solar/harvested energy is available. Technical approach: Predictive harvesting model + deferred compaction.

**R15 Cross-Device Verifiable Threat Intelligence Sharing**  
Novelty: Share anonymized threat signatures across devices with ZK proof of origin and integrity. Technical approach: Privacy-preserving set union.

**Advanced & Forward-Looking Tracks**  
**R16 On-Device Hardware Root-of-Trust Integration**  
Novelty: Leverage TPM/secure enclave (when available) for root key storage while keeping the binary single-executable. Technical approach: Conditional compilation with fallback software root.

**R17 Wasm-Based Extensible Detection and Response Policies**  
Novelty: Users upload Wasm modules for custom rules; the runtime proves correct execution and energy compliance. Technical approach: Sandboxed Wasm interpreter with resource accounting.

**R18 Energy-Proportional Model Quantization with Verifiability**  
Novelty: Dynamically switch quantization levels and prove the accuracy stayed above a threshold. Technical approach: Quantization-aware training + ZK accuracy proof.

**R19 Learned False-Positive Reduction with Causal Reasoning**  
Novelty: Use causal inference models on-device to distinguish real threats from false positives. Technical approach: Tiny causal graph inference.

**R20 Verifiable Supply-Chain Attestation for Firmware and Models**  
Novelty: Prove that the running firmware and detection models match a known-good build from the manufacturer. Technical approach: Remote attestation + Merkle root of binary.

**R21 Quantum-Resistant Key Rotation with Minimal Energy Overhead**  
Novelty: Automatic periodic key rotation using post-quantum algorithms optimized for battery life. Technical approach: Ratcheting + energy-aware scheduling.

**R22 Cross-Platform Binary Self-Optimization**  
Novelty: Runtime binary re-optimization for different architectures (x86/ARM/RISC-V/ESP32) with energy profiling. Technical approach: JIT-like specialization.

**R23 Verifiable Multi-Device Swarm Defense Coordination**  
Novelty: Swarm-level defense where devices vote on threats with ZK tallying. Technical approach: Threshold signatures + privacy-preserving voting.

**R24 Energy-Harvesting Aware Security Posture Adjustment**  
Novelty: Dynamically lower security strength (e.g. lighter crypto) when harvesting energy is low, with proof of trade-off. Technical approach: Adaptive security levels.

**R25 Long-Term Evolutionary Model Improvement**  
Novelty: On-device evolutionary algorithm that improves detection models over months while preserving verifiability and privacy. Technical approach: Genetic algorithms with ZK fitness proofs.

**Edge Intelligence & Explainability Tracks**  
**R26 Explainable Anomaly Attribution**  
Novelty: On-device interpretable attribution that traces each anomaly score back to the contributing signals and their temporal context. Technical approach: Shapley-value approximation adapted for streaming edge data with bounded compute budget.

**R27 Federated Threat Model Distillation**  
Novelty: Fleet-wide model improvement through federated learning rounds that distill knowledge into a compact student model suitable for constrained devices. Technical approach: Federated averaging with knowledge distillation, differential privacy guarantees, and proof-of-participation for honest aggregation.

**R28 Adversarial Robustness Testing Framework**  
Novelty: Automated red-team harness that generates adversarial telemetry sequences designed to evade or confuse the detector. Technical approach: Gradient-free black-box attack synthesis (genetic perturbation, boundary probing) with coverage metrics and regression integration.

**R29 Temporal Logic Runtime Monitoring**  
Novelty: Lightweight runtime monitor that checks live telemetry streams against LTL/CTL safety and liveness properties. Technical approach: On-the-fly LTL monitoring with bounded history, automaton compilation, and violation attestation for audit.

**R30 Anomaly Correlation Graph Mining**  
Novelty: Construct and maintain a lightweight causal correlation graph across signal dimensions to identify multi-stage attack patterns. Technical approach: Incremental Granger-causality estimation on windowed replay buffers with graph-based alert clustering.

**Edge Infrastructure & Hardening Tracks**  
**R31 Digital Twin Simulation for Edge Fleets**  
Novelty: A deterministic simulation harness that models heterogeneous edge fleets for scenario testing and policy validation before live deployment. Technical approach: Discrete-event simulation with pluggable device profiles, attack injection, and differential comparison against the real runtime.

**R32 Autonomous Secure Patch Management**  
Novelty: Self-patching edge runtime that verifies patch integrity before application and proves post-patch state correctness. Technical approach: Signed delta patches with Merkle-rooted binary verification, staged rollout with automatic rollback on health-check failure.

**R33 Deception-Based Threat Engagement**  
Novelty: Deploy lightweight honeypot services and canary tokens at the edge to detect lateral movement and attacker reconnaissance. Technical approach: Synthetic service emulation with canary credential injection, interaction logging, and automated alert escalation upon engagement.

**R34 Secure Multi-Tenancy Isolation**  
Novelty: Namespace-isolated detection and response policies on shared edge hardware so multiple tenants coexist without cross-contamination. Technical approach: Per-tenant policy scoping, resource accounting, and cryptographic namespace separation with verifiable isolation proofs.

**R35 Side-Channel Attack Detection**  
Novelty: Detect timing, power, and electromagnetic side-channel attacks using statistical profiling of device operational patterns. Technical approach: High-frequency sampling of execution timing and power draw with anomaly detection on the side-channel signal domain.

**Resilience & Long-Horizon Tracks**  
**R36 Edge-Cloud Hybrid Offload with Verifiability**  
Novelty: Decide when to offload expensive analysis to the cloud while proving that the cloud result was computed correctly and the raw data was not leaked. Technical approach: Selective offload policy with encrypted data transfer, verifiable computation receipts, and local result validation.

**R37 Resilient Mesh Topology Self-Organisation**  
Novelty: Autonomous mesh network formation and repair that maintains connectivity and security invariants after node loss or compromise. Technical approach: Distributed spanning-tree repair with cryptographic neighbor authentication and convergence proofs.

**R38 Behavioural Device Fingerprinting**  
Novelty: Build a behavioural identity for each device based on its operational patterns, enabling impersonation detection without shared secrets. Technical approach: Statistical device profiling from telemetry baselines with drift-based identity verification and false-acceptance rate bounds.

**R39 Formal Policy Composition and Conflict Resolution**  
Novelty: Compose multiple detection and response policies with formal guarantees that the combined policy is free of contradictions and deadlocks. Technical approach: Policy algebra with automated conflict detection, priority resolution, and model-checked composition proofs.

**R40 Privacy-Preserving Incident Forensics**  
Novelty: Conduct post-incident forensic analysis across multiple devices without exposing raw sensor data to the investigating party. Technical approach: Secure multi-party computation for forensic queries combined with ZK proofs of evidence consistency.

