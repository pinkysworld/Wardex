# Research Questions: R36–R40 — Resilience & Long-Horizon

This document formalises the research questions, hypotheses, evaluation
criteria, and implementation sketches for tracks R36 through R40.

---

## R36 — Edge-Cloud Hybrid Offload with Verifiability

### Research question

*Can an edge runtime selectively offload expensive analysis to a cloud backend
while producing a verifiable receipt that proves the result was computed
correctly and that no raw telemetry was exposed to the cloud?*

### Hypothesis

A commit-and-prove offload protocol (blind the input, offload the computation,
verify the proof locally) can provide verifiable cloud results for analyses
that would take > 10× the device's energy budget to run locally, with < 5 %
verification overhead and zero raw-data leakage.

### Sub-questions

1. What classes of analysis (e.g., large-window correlation, model retraining,
   fleet aggregation) benefit most from cloud offload given current edge
   hardware constraints?
2. What is the minimal proof system (SNARK, STARK, MAC-based) that provides
   sufficient assurance of correct computation while remaining verifiable on
   a Cortex-A53 within 100 ms?
3. How should the offload decision be made — static policy, energy-threshold
   trigger, or learned cost model — to minimise total cost (energy + latency +
   privacy risk)?

### Evaluation criteria

| Metric | Target |
|---|---|
| Energy saving vs local-only (offloaded analysis) | ≥ 10× |
| Verification overhead on device | < 5 % of local compute budget |
| Raw data exposure to cloud | zero (formally argued) |
| Offload decision latency | < 10 ms |
| Proof verification time | < 100 ms on Cortex-A53 |

### Implementation sketch

```
struct OffloadRequest {
    task_id: u64,
    blinded_input: Vec<u8>,        // encrypted or committed input
    task_type: OffloadTaskType,    // Correlation | Retrain | Aggregate
    energy_budget_local: f64,      // estimated local cost in mJ
}

struct OffloadReceipt {
    task_id: u64,
    result_commitment: [u8; 32],
    proof: VerificationProof,      // SNARK witness or MAC chain
    cloud_node_id: [u8; 32],
    wall_time_ms: u64,
}

enum OffloadPolicy {
    Static { threshold_mj: f64 },
    EnergyTriggered { battery_floor: f64 },
    Learned { cost_model: CostPredictor },
}
```

The runtime estimates the energy cost of a pending analysis, and if it exceeds
the offload threshold, blinds the input, sends it to the cloud, and waits for
a receipt with an attached proof. The proof is verified locally before the
result is accepted into the detection pipeline.

---

## R37 — Resilient Mesh Topology Self-Organisation

### Research question

*Can a fleet of edge nodes autonomously form and repair a communication mesh
that preserves connectivity and security invariants after node loss, failure,
or compromise, with bounded convergence time?*

### Hypothesis

A gossip-based spanning-tree algorithm with cryptographic neighbour
authentication converges to a connected topology within 30 seconds of a
single-node failure in a 50-node mesh, and isolates a compromised node
within 10 seconds once detection consensus (R23) is reached.

### Sub-questions

1. What is the minimum connectivity degree (k-connected) required to tolerate
   simultaneous loss of up to 3 nodes without partitioning the fleet?
2. How should neighbour authentication be performed to prevent a compromised
   node from poisoning the topology (Sybil attack on the mesh layer)?
3. Can topology repair be combined with swarm voting (R23) so that isolation
   and re-routing happen in a single coordinated round?

### Evaluation criteria

| Metric | Target |
|---|---|
| Convergence time after single failure (50 nodes) | ≤ 30 s |
| Compromised node isolation time | ≤ 10 s post-consensus |
| Simultaneous failure tolerance | ≥ 3 nodes without partition |
| Message overhead per repair round | < 500 bytes per node |
| Sybil resistance | authenticated neighbour set |

### Implementation sketch

```
struct MeshNode {
    id: [u8; 32],
    neighbours: Vec<AuthenticatedPeer>,
    spanning_tree_parent: Option<[u8; 32]>,
    epoch: u64,
}

struct AuthenticatedPeer {
    id: [u8; 32],
    public_key: [u8; 32],
    last_heartbeat: u64,
    link_quality: f64,
}

struct TopologyRepairEvent {
    trigger: RepairTrigger,        // NodeLost | Compromised | LinkDegraded
    affected_node: [u8; 32],
    new_parent: Option<[u8; 32]>,
    epoch_after: u64,
}
```

Each node maintains an authenticated neighbour set and participates in a
lightweight gossip protocol that detects missing heartbeats. On failure
detection, the node's subtree re-parents to the best available alternative.
If the failure is due to compromise (signalled by swarm vote), the node
is removed from all neighbour sets and its credentials are revoked.

---

## R38 — Behavioural Device Fingerprinting

### Research question

*Can an on-device behavioural fingerprint — derived from operational timing
patterns, resource usage profiles, and communication behaviour — reliably
distinguish a legitimate device from an impersonator, without requiring
pre-shared secrets?*

### Hypothesis

A 32-dimensional behavioural feature vector (instruction mix, sleep/wake
timing, network burst patterns) achieves ≥ 95 % device identification accuracy
on a fleet of 50 heterogeneous devices with < 5 % equal-error rate, using
< 1 KB of fingerprint state per device.

### Sub-questions

1. Which behavioural features are most stable over time and most discriminative
   across devices (feature selection and stability analysis)?
2. How should the fingerprint be updated to track legitimate device drift
   (firmware updates, seasonal workload changes) without opening a window
   for gradual impersonation?
3. Can fingerprints be exchanged between nodes in a privacy-preserving way
   (e.g., as commitments) to enable mutual authentication without revealing
   the raw feature vector?

### Evaluation criteria

| Metric | Target |
|---|---|
| Device identification accuracy (50 devices) | ≥ 95 % |
| Equal-error rate | < 5 % |
| Fingerprint state per device | < 1 KB |
| Feature stability over 30 days | ≥ 90 % of features stable |
| Impersonation detection rate | ≥ 90 % |

### Implementation sketch

```
struct DeviceFingerprint {
    device_id: [u8; 32],
    feature_vector: [f64; 32],
    feature_variance: [f64; 32],   // per-feature stability estimate
    epoch: u64,
    sample_count: u64,
}

struct FingerprintMatcher {
    known_prints: Vec<DeviceFingerprint>,
    distance_threshold: f64,
    update_decay: f64,             // EWMA decay for drift tracking
}

struct IdentityChallenge {
    nonce: [u8; 16],
    expected_features: Vec<usize>, // which features to verify
    commitment: [u8; 32],          // verifier's commitment
}
```

Each device maintains its own fingerprint by tracking EWMA statistics over
the selected behavioural features. During authentication, a verifier issues
a challenge requesting specific feature values; the prover responds with
commitments that the verifier checks against the stored fingerprint.

---

## R39 — Formal Policy Composition and Conflict Resolution

### Research question

*Can multiple overlapping detection and response policies (vendor, operator,
regulatory) be composed into a single conflict-free policy with formal
guarantees of no deadlocks, no contradictions, and bounded worst-case
response latency?*

### Hypothesis

An algebraic policy composition framework based on priority lattices and
conflict resolution rules can compose up to 10 overlapping policies and
verify the composed result is deadlock-free and contradiction-free in
< 1 second on host hardware, producing a runtime representation that adds
< 5 % overhead to policy evaluation.

### Sub-questions

1. What formal model (lattice, semiring, process algebra) is most natural
   for representing the priority relationships between SentinelEdge policy
   sources (vendor ≻ operator ≻ default)?
2. How should conflicting response actions (e.g., one policy says isolate,
   another says throttle) be resolved: strict priority, escalation merge,
   or operator-configured resolution function?
3. Can the composition be re-verified incrementally when a single policy
   changes, rather than re-analysing the full composition?

### Evaluation criteria

| Metric | Target |
|---|---|
| Policies composable simultaneously | ≥ 10 |
| Verification time (full composition) | < 1 s on host |
| Incremental re-verification | < 100 ms |
| Runtime overhead of composed policy | < 5 % vs single policy |
| Deadlock freedom guarantee | formally verified |
| Contradiction freedom guarantee | formally verified |

### Implementation sketch

```
struct PolicyLayer {
    name: String,
    priority: u8,                      // higher wins on conflict
    rules: Vec<PolicyRule>,
    source: PolicySource,              // Vendor | Operator | Regulatory
}

struct ComposedPolicy {
    layers: Vec<PolicyLayer>,
    resolution: ConflictResolution,
    compiled_rules: Vec<ResolvedRule>,
    verification_result: VerificationResult,
}

enum ConflictResolution {
    StrictPriority,
    EscalationMerge,                   // take the more severe action
    Custom(fn(&[PolicyRule]) -> PolicyRule),
}

struct VerificationResult {
    deadlock_free: bool,
    contradiction_free: bool,
    worst_case_depth: usize,
    checked_at: u64,
}
```

The composer takes a stack of policy layers, detects pairs of rules whose
conditions overlap but whose actions conflict, and resolves each conflict
according to the configured strategy. The result is verified for deadlock
freedom (no circular action dependencies) and contradiction freedom (no
sample can trigger mutually exclusive actions).

---

## R40 — Privacy-Preserving Incident Forensics

### Research question

*Can a post-incident forensic investigation across multiple edge devices
reconstruct the attack timeline and causal chain without any investigating
party accessing raw telemetry data from any device?*

### Hypothesis

A secure multi-party computation (MPC) protocol operating over encrypted
forensic bundles can reconstruct an ordered attack timeline with ≥ 90 %
event coverage while guaranteeing that no raw sample is revealed to the
investigator, with total protocol execution time < 5 minutes for a
10-device, 1000-event incident.

### Sub-questions

1. What is the minimal forensic query language that investigators need to
   reconstruct attack timelines (temporal ordering, causal links, severity
   filtering)?
2. Can homomorphic operations on encrypted audit log entries support the
   required query types, or is a secret-sharing based MPC more practical
   for this workload?
3. How should the investigation protocol handle devices that are offline,
   compromised, or refuse to participate — what completeness guarantees can
   still be offered?

### Evaluation criteria

| Metric | Target |
|---|---|
| Event coverage (timeline completeness) | ≥ 90 % |
| Raw data exposure to investigator | zero |
| Protocol execution time (10 devices, 1000 events) | < 5 min |
| Offline device tolerance | ≥ 2 of 10 |
| Query expressiveness | temporal order + causal links + severity filter |

### Implementation sketch

```
struct EncryptedForensicBundle {
    device_id: [u8; 32],
    encrypted_events: Vec<EncryptedEvent>,
    commitment: [u8; 32],         // Pedersen commitment to event set
    share_count: u8,              // secret sharing threshold
}

struct ForensicQuery {
    time_range: (u64, u64),
    severity_filter: Option<ThreatLevel>,
    causal_chain: bool,           // reconstruct causal links
    max_events: usize,
}

struct TimelineEntry {
    device_id_masked: [u8; 32],   // pseudonymised
    timestamp: u64,
    event_type: EventType,
    severity: ThreatLevel,
    causal_parent: Option<u64>,   // links to prior event
}

struct InvestigationResult {
    timeline: Vec<TimelineEntry>,
    completeness: f64,            // fraction of events covered
    participating_devices: u8,
    proof_of_correct_execution: [u8; 64],
}
```

Each device secret-shares its encrypted forensic bundle. The investigation
protocol processes shares using MPC to reconstruct the timeline without
any party seeing raw events. The result includes a proof that the
computation was executed correctly over the committed inputs.
