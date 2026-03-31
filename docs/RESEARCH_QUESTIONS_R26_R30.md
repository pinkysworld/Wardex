# Research Questions: R26–R30 — Edge Intelligence & Explainability

This document formalises the research questions, hypotheses, evaluation
criteria, and implementation sketches for tracks R26 through R30. Each track
follows a common template so the questions can be directly converted into paper
sections or thesis chapters.

---

## R26 — Explainable Anomaly Attribution

### Research question

*Can a resource-constrained edge device produce per-signal attribution scores
that accurately rank the causal contributors to each anomaly alert, without
exceeding a fixed energy budget per inference?*

### Hypothesis

A lightweight, additive attribution method (marginal-contribution
approximation) can rank signal contributions with ≥ 0.85 rank correlation to
full Shapley values while using < 5 % of the energy budget consumed by an
exact Shapley computation on the same sample.

### Sub-questions

1. What is the minimum number of marginal evaluations needed to maintain rank
   fidelity above 0.85 Spearman ρ on traces with 10–16 signal dimensions?
2. How does attribution stability degrade under concept drift, and can the
   replay buffer be reused to anchor attributions to a recent reference
   distribution?
3. Does presenting top-3 attributed signals to human operators improve triage
   accuracy (measured as correct escalation rate) compared to a raw score
   alone?

### Evaluation criteria

| Metric | Target |
|---|---|
| Attribution rank correlation vs exact Shapley | ρ ≥ 0.85 |
| Energy overhead per sample (relative to detection alone) | < 5 % |
| Operator triage accuracy improvement (user study) | ≥ 15 pp |
| Latency added per sample | < 2 ms on Cortex-A53 class |

### Implementation sketch

```
struct Attribution {
    sample_id: u64,
    contributions: Vec<(SignalDim, f64)>,   // sorted by |contribution|
    method: AttributionMethod,               // Marginal | Shapley | LIME
    baseline_epoch: u64,                     // reference distribution epoch
}
```

A `marginal_attribution()` function evaluates each dimension's drop-out impact
against a masked mean from the replay buffer, producing a contribution vector
in O(d) detector calls (d = number of dimensions). Results are cached per
checkpoint epoch to avoid recomputation.

---

## R27 — Federated Threat Model Distillation

### Research question

*Can a fleet of heterogeneous edge devices collaboratively improve a shared
threat model through periodic distillation rounds, without any single device
transmitting raw telemetry or full model weights?*

### Hypothesis

A compressed gradient-sketch protocol (count-sketch of top-k gradient
components) achieves ≥ 90 % of the detection improvement of full federated
averaging while transmitting < 1 KB per round per device, and reveals no
individual sample under a honest-but-curious threat model.

### Sub-questions

1. How many distillation rounds are needed to converge to ≥ 90 % of the
   centralised-training detection accuracy on a fleet of 50 simulated nodes
   with non-IID threat distributions?
2. What privacy guarantees can be formally stated under (ε, δ)-differential
   privacy when combined with local noise injection, and what is the
   accuracy–privacy tradeoff curve?
3. Can a lightweight student model (< 64 KB parameter footprint) retain the
   distilled knowledge well enough to replace the ensemble on each device?

### Evaluation criteria

| Metric | Target |
|---|---|
| Detection accuracy relative to centralised baseline | ≥ 90 % |
| Per-round upload size per device | < 1 KB |
| Privacy guarantee | (ε ≤ 2, δ ≤ 10⁻⁵) |
| Student model size | < 64 KB |
| Convergence rounds (50 nodes, non-IID) | ≤ 20 |

### Implementation sketch

```
struct DistillationRound {
    round_id: u64,
    sketch: CountSketch,        // compressed top-k gradient sketch
    noise_scale: f64,           // DP noise parameter σ
    contributing_nodes: u32,
}

struct StudentModel {
    weights: Vec<f32>,          // compact weight vector
    architecture_hash: [u8; 32],
    distillation_round: u64,
}
```

Each node computes local gradient updates, compresses them into a count-sketch,
adds calibrated Gaussian noise, and transmits the sketch to an aggregator (or
gossips it in a decentralised topology per R03). The aggregator averages
sketches and broadcasts the merged update for local model adjustment.

---

## R28 — Adversarial Robustness Testing Framework

### Research question

*Can an automated adversarial harness generate telemetry sequences that
reliably evade the detector, and can the resulting failure cases be used to
measurably harden detection without introducing regressions?*

### Hypothesis

A grammar-guided fuzzer that mutates attack traces under detector-reachability
constraints discovers ≥ 3× more evasion paths than random mutation alone, and
retraining on discovered evasions reduces the evasion success rate by ≥ 50 %
without increasing the false-positive rate by more than 2 percentage points.

### Sub-questions

1. What minimal grammar over telemetry sequences is sufficient to express the
   known evasion strategies (slow drip, mimicry, burst masking)?
2. How do we measure "coverage" of the detector's decision surface in a
   meaningful way, analogous to code coverage for fuzzers?
3. Can the fuzzer be made energy-aware so it can run as a background self-test
   on the device itself during low-load periods?

### Evaluation criteria

| Metric | Target |
|---|---|
| Evasion paths found vs random baseline | ≥ 3× |
| Evasion success rate after retraining | ≤ 50 % of pre-retrain |
| FP regression from retraining | ≤ +2 pp |
| Fuzzer throughput | ≥ 1000 traces/s on host |
| Grammar expressiveness | covers slow-drip, mimicry, burst-mask |

### Implementation sketch

```
enum EvasionStrategy {
    SlowDrip { increment: f64, interval_samples: usize },
    Mimicry { benign_template: Vec<TelemetrySample> },
    BurstMask { burst_len: usize, cool_down: usize },
}

struct AdversarialHarness {
    grammar: EvasionGrammar,
    detector: Box<dyn Detector>,
    corpus: Vec<TaggedTrace>,       // traces + labels (evasion/caught)
    coverage: DecisionSurfaceMap,
}
```

The harness generates candidate traces by mutating a seed corpus according to
the grammar, runs each trace through the detector, and classifies the outcome.
Traces that evade detection are added to the failure corpus for retraining
and regression testing.

---

## R29 — Temporal Logic Runtime Monitoring

### Research question

*Can a lightweight runtime monitor check live telemetry streams against
LTL safety and bounded-liveness properties with overhead low enough for
continuous deployment on constrained devices?*

### Hypothesis

A 3-register automaton compiled from an LTL fragment can monitor safety
properties (e.g., "every critical alert is followed by a response within 10
samples") with < 1 % runtime overhead and < 512 bytes of state per property on
a Cortex-M4 class device.

### Sub-questions

1. What subset of LTL (safety + bounded liveness) is sufficient to express the
   properties operators actually care about in Wardex deployments?
2. What is the per-sample monitoring overhead for 5, 10, and 20 simultaneous
   properties on representative hardware?
3. Can property violations be integrated into the anomaly score to create a
   formally grounded composite confidence measure?

### Evaluation criteria

| Metric | Target |
|---|---|
| Per-sample overhead (5 properties) | < 1 % of detection time |
| Monitor state per property | < 512 bytes |
| Violation detection latency | ≤ 1 sample after violation |
| Property language expressiveness | safety + bounded liveness |
| Integration with anomaly score | composite score ≤ 5 % slower |

### Implementation sketch

```
struct LtlProperty {
    name: &'static str,
    automaton: BuchiAutomaton,      // compiled from LTL formula
    registers: [u64; 3],           // bounded state
    horizon: usize,                // bound for liveness properties
}

struct RuntimeMonitor {
    properties: Vec<LtlProperty>,
    violation_log: Vec<Violation>,
}

struct Violation {
    property: &'static str,
    sample_id: u64,
    witness: Vec<u64>,             // sample IDs forming the counterexample
}
```

Properties are compiled offline into small Büchi automata and shipped as part of
the policy configuration. The monitor steps each automaton on every telemetry
sample, recording violations with minimal witness traces for forensic review.

---

## R30 — Anomaly Correlation Graph Mining

### Research question

*Can a lightweight incremental graph-mining algorithm discover multi-stage
attack patterns from pairwise signal correlations, and do the discovered
patterns improve detection of coordinated attacks compared to independent
per-signal scoring?*

### Hypothesis

A sliding-window Pearson correlation tracker with edge-pruning discovers
multi-step attack chains (≥ 3 correlated signals within a window) that
independent scoring misses, improving coordinated-attack detection F1 by
≥ 15 percentage points with < 10 % additional memory overhead.

### Sub-questions

1. What window size and pruning threshold produce the best precision–recall
   tradeoff for known multi-stage attack patterns in IoT telemetry traces?
2. Can the correlation graph be maintained incrementally (O(d²) per sample) on
   a device with ≤ 256 KB available RAM?
3. How do we distinguish causal correlation (attack chain) from coincidental
   correlation (shared environmental factors like temperature or network load)?

### Evaluation criteria

| Metric | Target |
|---|---|
| Coordinated-attack F1 improvement | ≥ +15 pp vs independent scoring |
| Memory overhead | < 10 % of base detector state |
| Incremental update cost per sample | O(d²), d ≤ 16 |
| False correlation rate | < 20 % of discovered edges are non-causal |
| Window size sensitivity | stable across 2× window variation |

### Implementation sketch

```
struct CorrelationGraph {
    dim_count: usize,
    edge_weights: Vec<f64>,         // flattened upper triangle d×d
    window: VecDeque<TelemetrySample>,
    prune_threshold: f64,
}

struct AttackChain {
    signal_path: Vec<SignalDim>,    // ordered list of correlated dimensions
    max_lag: usize,                 // max temporal offset within chain
    confidence: f64,
}
```

On each sample arrival the graph updates the running Pearson coefficients for
all dimension pairs, prunes edges below threshold, and runs a depth-first
search for new chains of length ≥ 3. Discovered chains feed a composite
score that boosts the anomaly output when a coordinated pattern is active.
