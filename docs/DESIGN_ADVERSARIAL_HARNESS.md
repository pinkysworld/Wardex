# Design: Adversarial Robustness Testing Harness (R28)

This document specifies the architecture of an automated adversarial testing
framework for Wardex's anomaly detector, covering T073 from Phase 7.

---

## 1. Purpose

The harness systematically generates adversarial telemetry sequences that
attempt to evade detection, catalogues discovered evasions, and produces
retraining data that hardens the detector against the discovered attack
patterns.

## 2. Threat model

The adversary can:
- observe the detector's output (score, alert level) but not its internal state.
- craft arbitrary telemetry sequences subject to physical plausibility
  constraints (sensor value ranges, temporal smoothness).
- combine multiple evasion strategies in a single trace.

The adversary cannot:
- modify the detector binary or policy at runtime.
- tamper with the audit log or checkpoint system.

## 3. Evasion grammar

```
Grammar ::= Sequence(Strategy+)
Strategy ::= SlowDrip(increment, interval)
           | Mimicry(benign_template)
           | BurstMask(burst_len, cool_down)
           | ValueClamp(dim, min, max)
           | DriftInject(dim, slope, noise)

Constraints:
  - All sample values within [0.0, 10000.0]
  - Consecutive samples differ by ≤ max_delta per dimension
  - Sequence length between 50 and 5000 samples
```

### Strategy definitions

| Strategy | Description |
|---|---|
| SlowDrip | gradually increase a target dimension over many samples to stay below the per-sample delta threshold |
| Mimicry | replay a known-benign template with small perturbations that embed attack payload |
| BurstMask | inject a short high-value burst then immediately cool down to benign levels before the alert fires |
| ValueClamp | hold a dimension at a specific range to manipulate the baseline's EWMA toward a desired bias |
| DriftInject | slowly shift a dimension's mean to create a new normal, then exploit the shifted baseline |

## 4. Coverage metric

Decision surface coverage is measured as the fraction of detector state-space
regions exercised by the corpus:

```
struct CoverageMap {
    score_buckets: [u64; 20],          // 20 bins across [0.0, 1.0]
    dim_activation: Vec<[u64; 20]>,    // per-dimension histograms
    transition_pairs: HashSet<(ScoreBucket, ScoreBucket)>, // consecutive score transitions
}

fn coverage_ratio(map: &CoverageMap) -> f64 {
    let filled = map.score_buckets.iter().filter(|&&c| c > 0).count()
              + map.transition_pairs.len();
    let total = 20 + 20 * 20;  // buckets + possible transitions
    filled as f64 / total as f64
}
```

Target: ≥ 60 % decision surface coverage before the fuzzer terminates.

## 5. Fuzzer architecture

```
                  ┌─────────────┐
                  │  Seed Corpus │
                  └──────┬──────┘
                         │
                  ┌──────▼──────┐
                  │   Mutator   │──── Grammar rules
                  └──────┬──────┘
                         │
                  ┌──────▼──────┐
                  │  Detector   │──── Score + alert level
                  └──────┬──────┘
                         │
              ┌──────────┴──────────┐
              │                     │
        ┌─────▼─────┐       ┌──────▼──────┐
        │  Caught   │       │   Evasion   │
        │  Corpus   │       │   Corpus    │
        └───────────┘       └──────┬──────┘
                                   │
                            ┌──────▼──────┐
                            │  Retrainer  │
                            └─────────────┘
```

### Core structs

```rust
struct FuzzerConfig {
    max_iterations: u64,
    max_trace_len: usize,
    min_trace_len: usize,
    target_coverage: f64,
    strategies: Vec<StrategyWeight>,
}

struct StrategyWeight {
    strategy: EvasionStrategyKind,
    initial_weight: f64,
    // adaptive: boost weight for strategies that find more evasions
}

struct FuzzerState {
    iteration: u64,
    seed_corpus: Vec<TaggedTrace>,
    evasion_corpus: Vec<TaggedTrace>,
    coverage: CoverageMap,
    rng: StdRng,
}

struct TaggedTrace {
    samples: Vec<TelemetrySample>,
    strategy: EvasionStrategyKind,
    detector_scores: Vec<f64>,
    evaded: bool,
    generation: u64,
}
```

### Mutation operators

1. **Strategy application**: apply one grammar strategy to a seed trace.
2. **Splicing**: combine the prefix of one trace with the suffix of another.
3. **Perturbation**: add Gaussian noise to random samples.
4. **Temporal stretching**: duplicate or remove samples to alter timing.

Each mutation is applied with probability proportional to the strategy's
adaptive weight (strategies that have recently found evasions are boosted).

## 6. Retraining pipeline

When the evasion corpus reaches a configurable threshold (default: 50 traces),
the retrainer:

1. Labels all evasion traces as positive (attack).
2. Mixes with an equal number of randomly sampled benign traces.
3. Replays through the detector with adaptation enabled.
4. Measures the post-retraining evasion rate on the evasion corpus.
5. Measures the FP rate on the full benign corpus to detect regression.

Acceptance criteria:
- Evasion rate drops by ≥ 50 %.
- FP rate increases by ≤ 2 pp.

If the FP criterion is violated, the retraining is rejected and the evasion
corpus is flagged for manual review.

## 7. Energy-aware self-test mode

The harness can run in a continuous self-test mode on-device:

```rust
struct SelfTestConfig {
    max_traces_per_cycle: usize,      // limit per low-load window
    battery_floor: f64,               // do not test below this level
    low_load_threshold: f64,          // CPU utilisation below which testing runs
    report_interval_hours: u64,
}
```

Self-test results are appended to the audit log with a distinct event type
so they can be filtered from operational alerts.

## 8. Implementation phases

| Phase | Deliverable |
|---|---|
| 1 | Define EvasionStrategy enum and grammar constraints in a new `adversarial` module |
| 2 | Implement SlowDrip and Mimicry mutators with seed corpus loading |
| 3 | Implement CoverageMap and the fuzzer main loop |
| 4 | Add BurstMask, ValueClamp, DriftInject mutators |
| 5 | Implement the retraining pipeline with acceptance criteria |
| 6 | Add energy-aware self-test mode |
| 7 | Integration tests with existing benchmark fixtures |
