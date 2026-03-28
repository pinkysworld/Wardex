# Research Questions: R31–R35 — Edge Infrastructure & Hardening

This document formalises the research questions, hypotheses, evaluation
criteria, and implementation sketches for tracks R31 through R35.

---

## R31 — Digital Twin Simulation for Edge Fleets

### Research question

*Can a deterministic digital-twin simulator reproduce fleet-scale threat
scenarios faithfully enough to validate detection and response policies
before live deployment, at a fraction of the cost and risk?*

### Hypothesis

A discrete-event simulator modelling 100+ heterogeneous nodes with configurable
latency, failure, and attack injection can reproduce the temporal ordering of
real fleet incidents and predict policy-level outcomes (alert count, response
actions, energy consumption) within 10 % of a physical testbed.

### Sub-questions

1. What minimal device model is sufficient to capture the detection-relevant
   behaviour of real edge nodes (CPU, memory, network, battery)?
2. How should attack scenarios be parameterised to cover the space of known
   threat archetypes (credential storms, lateral movement, firmware
   tampering)?
3. Can simulation results be automatically diffed against live fleet telemetry
   to detect model drift and trigger re-calibration?

### Evaluation criteria

| Metric | Target |
|---|---|
| Alert count prediction accuracy (vs physical testbed) | ≤ 10 % error |
| Simulated fleet size | ≥ 100 nodes |
| Scenario throughput | ≥ 10 000 simulated samples/s on host |
| Model parameters per node | ≤ 20 |
| Calibration drift detection latency | ≤ 1 simulation epoch |

### Implementation sketch

```
struct SimNode {
    id: u32,
    profile: DeviceProfile,        // CPU class, RAM, battery model
    detector: DetectorState,
    policy: PolicyState,
    clock: u64,                    // discrete simulation tick
}

struct FleetSimulator {
    nodes: Vec<SimNode>,
    network: AdjacencyMatrix,
    event_queue: BinaryHeap<SimEvent>,
    attack_scripts: Vec<AttackScript>,
    rng: StdRng,
}

struct SimEvent {
    tick: u64,
    target_node: u32,
    kind: EventKind,               // Telemetry | Attack | Failure | Message
}
```

The simulator initialises nodes from device profiles, injects telemetry and
attack events from scripted scenarios, and steps each node's detector and
policy engine in tick order. Aggregated metrics are compared against a
reference run to validate policy changes.

---

## R32 — Autonomous Secure Patch Management

### Research question

*Can an edge runtime autonomously verify, apply, and validate patches
without human intervention, while maintaining verifiable proof that the
post-patch state matches the vendor-signed intent?*

### Hypothesis

A staged patch pipeline (download → verify signature → snapshot state →
apply → smoke-test → commit or rollback) can achieve a 99 % successful
patch rate while producing a cryptographic receipt chain that proves each
step was executed correctly.

### Sub-questions

1. What is the minimal smoke-test suite that reliably distinguishes a
   successful patch from a broken one without requiring a full system test?
2. How should rollback be structured when the patch modifies both binary
   and configuration state simultaneously?
3. Can the patch verification receipt be composed with the audit log chain
   (R11) to form a single unified trust timeline?

### Evaluation criteria

| Metric | Target |
|---|---|
| Successful patch rate (automated) | ≥ 99 % |
| Rollback success rate on failure | 100 % |
| Verification receipt size | < 2 KB per patch |
| End-to-end patch latency | < 60 s on Cortex-A53 |
| Audit chain integration | receipt verifiable in existing chain |

### Implementation sketch

```
struct PatchManifest {
    version_from: SemVer,
    version_to: SemVer,
    binary_hash: [u8; 32],
    config_diff_hash: [u8; 32],
    vendor_signature: [u8; 64],
}

struct PatchReceipt {
    manifest_hash: [u8; 32],
    pre_snapshot_id: u64,
    post_binary_hash: [u8; 32],
    smoke_test_passed: bool,
    committed: bool,
    receipt_signature: [u8; 64],
}

enum PatchStage {
    Download,
    Verify,
    Snapshot,
    Apply,
    SmokeTest,
    Commit,
    Rollback,
}
```

The patch manager progresses through stages sequentially, producing a signed
receipt at each transition. If the smoke test fails, the manager automatically
rolls back to the pre-patch snapshot and records the failure in the audit chain.

---

## R33 — Deception-Based Threat Engagement

### Research question

*Can lightweight honeypot services and canary tokens deployed at the edge
reliably detect lateral movement and attacker reconnaissance with near-zero
false positives, without consuming significant device resources?*

### Hypothesis

A set of 3–5 synthetic service endpoints (unused ports with minimal protocol
emulation) and 10 canary tokens (file, environment variable, DNS) achieves
a ≥ 95 % detection rate for automated reconnaissance with a near-zero (< 0.1 %)
false-positive rate, consuming < 2 % of CPU and < 512 KB of memory.

### Sub-questions

1. Which synthetic protocols (SSH banner, HTTP 401, MQTT stub) are most
   effective at engaging automated scanners?
2. How should canary token placement be randomised to prevent attackers from
   learning and avoiding known canary patterns?
3. Can honeypot interaction logs be cryptographically chained into the audit
   trail (R11) to provide verifiable evidence of attacker behaviour?

### Evaluation criteria

| Metric | Target |
|---|---|
| Reconnaissance detection rate | ≥ 95 % |
| False-positive rate | < 0.1 % |
| CPU overhead | < 2 % |
| Memory footprint | < 512 KB |
| Canary token types | ≥ 3 (file, env, DNS) |

### Implementation sketch

```
struct HoneypotService {
    port: u16,
    protocol: DecoyProtocol,       // SshBanner | Http401 | MqttStub
    interaction_log: Vec<Interaction>,
}

struct CanaryToken {
    kind: CanaryKind,              // File | EnvVar | DnsRecord
    token_id: [u8; 16],
    placement_path: String,
    triggered: bool,
}

struct Interaction {
    timestamp: u64,
    source_ip_hash: [u8; 32],     // hashed for privacy
    bytes_received: usize,
    protocol_stage_reached: u8,
}
```

Honeypot services bind to unused ports and emulate just enough protocol to
elicit scanner behaviour. Any interaction is a high-confidence indicator of
reconnaissance. Canary tokens are placed in predictable attacker targets
(credentials files, environment variables) and trigger an alert on access.

---

## R34 — Secure Multi-Tenancy Isolation

### Research question

*Can a single edge runtime enforce namespace-isolated detection and response
policies for multiple tenants with formal guarantees of non-interference, while
sharing underlying hardware resources?*

### Hypothesis

A capability-based namespace model with per-tenant policy scoping and telemetry
partitioning achieves complete data isolation (zero cross-tenant information
leakage) with < 5 % throughput overhead compared to a dedicated single-tenant
deployment.

### Sub-questions

1. What is the minimal capability model that prevents cross-tenant data access
   while allowing shared infrastructure services (time, network, storage)?
2. How should resource quotas (CPU time, memory, audit log space) be allocated
   and enforced to prevent one tenant from starving others?
3. Can per-tenant audit chains be structurally independent while still sharing
   a global integrity root for fleet-level verification?

### Evaluation criteria

| Metric | Target |
|---|---|
| Cross-tenant information leakage | 0 (formally verified) |
| Throughput overhead vs single-tenant | < 5 % |
| Supported tenants per device | ≥ 8 |
| Resource quota enforcement accuracy | 100 % |
| Audit chain independence | per-tenant chains, shared root |

### Implementation sketch

```
struct TenantNamespace {
    tenant_id: u32,
    capabilities: CapabilitySet,
    policy: PolicyEngine,
    detector: DetectorState,
    audit_chain: AuditChain,
    resource_quota: ResourceQuota,
}

struct CapabilitySet {
    allowed_signals: Vec<SignalDim>,
    allowed_actions: Vec<ActionKind>,
    max_memory_bytes: usize,
    max_cpu_micros_per_tick: u64,
}

struct MultiTenantRuntime {
    tenants: Vec<TenantNamespace>,
    global_integrity_root: [u8; 32],
    scheduler: FairScheduler,
}
```

Each tenant gets an isolated namespace with its own detector, policy, and audit
chain. The runtime scheduler enforces fair resource allocation, and a global
integrity root hashes all per-tenant chain heads to provide fleet-level
tamper evidence.

---

## R35 — Side-Channel Attack Detection

### Research question

*Can statistical profiling of device operational patterns (instruction timing,
power draw variation, EM emission proxies) detect side-channel attacks in real
time on constrained hardware?*

### Hypothesis

A lightweight statistical model tracking timing variance and power-draw
deviation across operation classes detects ≥ 80 % of simulated cache-timing
and power-analysis attacks with < 10 % false-positive rate, using < 3 % of
device CPU budget.

### Sub-questions

1. What proxy signals (cycle counters, ADC power rail samples, DMA timing)
   are available on common edge SoCs (Cortex-A/M, RISC-V) for side-channel
   profiling?
2. What baseline model (EWMA, histogram, HMM) best captures the normal
   timing distribution for cryptographic operations?
3. Can side-channel detection results be fused into the main anomaly score
   (R01) to produce a unified threat assessment?

### Evaluation criteria

| Metric | Target |
|---|---|
| Cache-timing attack detection rate | ≥ 80 % |
| Power-analysis attack detection rate | ≥ 80 % |
| False-positive rate | < 10 % |
| CPU overhead | < 3 % |
| Fusion with main anomaly score | single composite output |

### Implementation sketch

```
struct SideChannelProfile {
    operation_class: &'static str,     // e.g., "aes_encrypt", "sign"
    timing_baseline: EwmaState,
    power_baseline: EwmaState,
    variance_threshold: f64,
}

struct SideChannelDetector {
    profiles: Vec<SideChannelProfile>,
    alert_buffer: VecDeque<SideChannelAlert>,
}

struct SideChannelAlert {
    operation_class: &'static str,
    deviation_sigma: f64,
    sample_count: u64,
    suspected_attack: SideChannelKind, // CacheTiming | PowerAnalysis | Em
}
```

The detector instruments cryptographic operations with cycle-counter
measurements, compares against the operation's EWMA baseline, and flags
deviations exceeding the configured sigma threshold. Alerts are fed into
the main anomaly score as an additional signal dimension.
