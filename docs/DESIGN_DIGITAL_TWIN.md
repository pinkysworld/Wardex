# Design: Digital-Twin Simulation Architecture (R31)

This document specifies the architecture of a deterministic fleet-scale
simulation harness for Wardex, covering T075 from Phase 7.

---

## 1. Purpose

Provide a simulation environment where detection policies, response strategies,
and fleet coordination protocols can be tested on virtual edge fleets before
deployment to real hardware. The simulator must be deterministic and
reproducible so that experiments can be replayed and compared.

## 2. Design goals

1. **Deterministic**: given the same seed and scenario, the simulator must
   produce identical results on every run.
2. **Scalable**: support fleets of 1–1000 nodes without changing the core loop.
3. **Composable**: accept the same policy and detector configurations used by
   the real runtime.
4. **Observable**: expose per-tick, per-node metrics for analysis and plotting.
5. **Extensible**: new attack scripts, device profiles, and network topologies
   can be added as data files without code changes.

## 3. Simulation model

### 3.1 Time model

Discrete-event simulation with a global tick counter. Events are processed in
strict tick order. Events at the same tick are processed in deterministic node
ID order.

### 3.2 Node model

Each simulated node wraps a real `DetectorState` and `PolicyEngine` instance
from the wardex library, augmented with simulated hardware state:

```rust
struct SimNode {
    id: u32,
    profile: DeviceProfile,
    battery: f64,                  // simulated battery level [0.0, 1.0]
    cpu_load: f64,                 // simulated CPU utilisation
    detector: DetectorState,
    policy: PolicyEngine,
    audit: AuditChain,
    inbox: VecDeque<SimMessage>,
    outbox: VecDeque<SimMessage>,
    alive: bool,
    compromised: bool,
}

struct DeviceProfile {
    name: String,
    cpu_class: CpuClass,          // CortexM4 | CortexA53 | RiscV
    ram_kb: u32,
    battery_capacity_mah: u32,
    drain_rate_mw: f64,           // idle power draw
    detection_cost_mj: f64,       // energy per detection cycle
}
```

### 3.3 Network model

A configurable adjacency matrix with per-link latency, bandwidth, and
failure probability:

```rust
struct NetworkModel {
    adjacency: Vec<Vec<LinkState>>,
    topology: TopologyKind,
}

struct LinkState {
    connected: bool,
    latency_ticks: u32,
    bandwidth_bytes: u32,
    failure_prob: f64,
}

enum TopologyKind {
    FullMesh,
    Star { hub: u32 },
    Ring,
    Random { edge_prob: f64 },
    Custom,
}
```

### 3.4 Event model

```rust
struct SimEvent {
    tick: u64,
    target: EventTarget,
    kind: EventKind,
}

enum EventTarget {
    Node(u32),
    Link(u32, u32),
    Global,
}

enum EventKind {
    Telemetry(TelemetrySample),
    Attack(AttackAction),
    NodeFailure,
    NodeRecovery,
    LinkDown,
    LinkRestore,
    Message(SimMessage),
    BatteryDrain(f64),
    ExternalCommand(String),
}

struct SimMessage {
    from: u32,
    to: u32,
    payload: MessagePayload,
    sent_tick: u64,
}
```

## 4. Attack scenario scripting

Attack scenarios are defined as TOML files that schedule events over time:

```toml
[scenario]
name = "credential_storm_lateral_movement"
description = "Credential stuffing on node 0, then lateral movement to nodes 1–3"
duration_ticks = 5000

[[event]]
tick = 100
target = 0
kind = "attack"
action = "credential_storm"
params = { rate = 50, duration = 200 }

[[event]]
tick = 400
target = 1
kind = "attack"
action = "lateral_move"
params = { source = 0, vector = "ssh" }

[[event]]
tick = 500
target = 2
kind = "attack"
action = "lateral_move"
params = { source = 0, vector = "ssh" }

[[event]]
tick = 800
target = 0
kind = "node_failure"

[[event]]
tick = 1200
target = 0
kind = "node_recovery"
```

### Built-in attack actions

| Action | Parameters | Effect |
|---|---|---|
| credential_storm | rate, duration | inject high auth_events_per_sec |
| lateral_move | source, vector | inject network anomalies on target |
| firmware_tamper | target_hash | modify integrity signal dimension |
| data_exfil | rate_kbps, duration | inject sustained outbound traffic |
| slow_drip | dim, increment, interval | gradually shift a dimension |
| dos_flood | target, rate | overwhelm node's CPU simulation |

## 5. Simulator core loop

```
fn run(sim: &mut Simulator) {
    while sim.tick < sim.scenario.duration_ticks {
        // 1. Inject events scheduled for this tick
        inject_events(sim);

        // 2. Deliver messages whose latency has elapsed
        deliver_messages(sim);

        // 3. Step each alive node
        for node in sim.nodes.iter_mut().filter(|n| n.alive) {
            // a. Drain battery
            node.battery -= node.profile.drain_rate_mw * TICK_DURATION_S;

            // b. Process inbox
            process_inbox(node);

            // c. Run detector on current telemetry
            let score = node.detector.evaluate(&current_sample(node));

            // d. Run policy engine
            let action = node.policy.decide(score, node.battery);

            // e. Record in audit chain
            node.audit.append(score, action);

            // f. Emit outbox messages (e.g., swarm digests)
            emit_swarm_digest(node);
        }

        // 4. Collect metrics
        sim.metrics.record_tick(sim.tick, &sim.nodes);

        sim.tick += 1;
    }
}
```

## 6. Metrics and observability

```rust
struct SimMetrics {
    per_node: Vec<NodeMetrics>,
    fleet: FleetMetrics,
}

struct NodeMetrics {
    node_id: u32,
    scores: Vec<f64>,             // one per tick
    alert_count: u64,
    action_count: u64,
    battery_trace: Vec<f64>,
    compromised_ticks: u64,
    downtime_ticks: u64,
}

struct FleetMetrics {
    total_alerts: u64,
    true_positives: u64,
    false_positives: u64,
    false_negatives: u64,
    mean_detection_latency: f64,  // ticks from attack start to first alert
    mean_response_latency: f64,   // ticks from first alert to first action
    energy_consumed_mj: f64,
}
```

Metrics are exported as JSON for analysis with external tools (Python, R,
or the browser admin console).

## 7. Validation against physical testbed

The simulator's output is compared against a reference trace from a physical
testbed using these criteria:

| Metric | Tolerance |
|---|---|
| Alert count | ≤ 10 % relative error |
| Detection latency | ≤ 5 ticks |
| Energy consumption | ≤ 15 % relative error |
| Action sequence | edit distance ≤ 2 |

When the tolerance is exceeded, the simulator flags the scenario for device
profile re-calibration.

## 8. Implementation phases

| Phase | Deliverable |
|---|---|
| 1 | Define SimNode, DeviceProfile, and SimEvent types in a new `simulation` module |
| 2 | Implement the discrete-event core loop with deterministic seeding |
| 3 | Implement TOML scenario file parser and event scheduler |
| 4 | Wire real DetectorState and PolicyEngine into SimNode |
| 5 | Implement NetworkModel with latency and failure simulation |
| 6 | Implement SimMetrics collection and JSON export |
| 7 | Build 5 reference scenarios covering the built-in attack actions |
| 8 | Add physical testbed comparison tooling |
