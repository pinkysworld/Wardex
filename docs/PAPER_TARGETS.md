# Research Paper Targets

This document identifies the subset of blueprint tracks closest to publication-ready status and outlines a paper structure that leverages existing implementation.

## Paper 1 — Adaptive Edge Security with Verifiable Audit

**Working title:** *SentinelEdge: An Adaptive Edge Security Runtime with Verifiable Audit Trails and Poisoning-Resilient Detection*

**Thesis:** A single-binary Rust runtime can provide meaningful anomaly detection, policy-driven response, and tamper-evident forensic logging on resource-constrained edge devices — without cloud dependency and with cryptographic guarantees that every decision is auditable.

### Core tracks

| Track | Status | Contribution to paper |
|-------|--------|-----------------------|
| R01 — Adaptive anomaly detection | Foundation | Eight-dimensional EWMA scoring with replay buffer and adaptation controls |
| R05 — Poisoning detection | Foundation | Four heuristics (mean shift, variance spike, drift accumulation, auth burst) with freeze/decay response |
| R06 — Energy-aware isolation | Foundation | Battery-proportional response selection with pluggable adapter chain |
| R09 — Adaptive response strength | Foundation | Score + battery → graded action pipeline (observe → throttle → quarantine → isolate) |
| R10 — Verifiable rollback | Foundation | Bounded checkpoint ring buffer, forensic evidence bundles, proof-carrying baseline updates |
| R11 — Post-quantum secure audit | Foundation | SHA-256 digest chain with signed checkpoints, end-to-end verification |

### Supporting evidence

| Artifact | Location | Purpose |
|----------|----------|---------|
| Benchmark harness | `src/benchmark.rs` | FP/FN, precision, recall, F1 metrics on deterministic fixtures |
| Credential storm scenario | `examples/credential_storm.csv` | Realistic attack trace for evaluation |
| Status manifest | `cargo run -- status-json` | Machine-readable implementation snapshot |
| Browser console | `site/admin.html` | Report visualization for paper figures |

### Evaluation plan

1. **Detection accuracy.** Run the benchmark harness across benign, slow-escalation, credential-storm, and low-battery fixtures. Report precision, recall, F1, and per-dimension contribution breakdowns.
2. **Poisoning resilience.** Inject known poisoning patterns into replay buffers and measure detection latency and false-negative rate for each of the four heuristics.
3. **Energy overhead.** Profile CPU time and memory allocation per sample on representative ARM hardware (Raspberry Pi 4). Compare full-pipeline vs. detection-only runs.
4. **Audit integrity.** Verify the SHA-256 chain end-to-end on runs of 10^3, 10^4, and 10^5 samples. Measure per-entry overhead in bytes and microseconds.
5. **Response latency.** Measure time from telemetry ingestion to adapter dispatch across different threat levels.

### Paper outline

1. Introduction — edge security gap, need for local autonomy
2. System design — ten-stage pipeline, module boundaries
3. Adaptive detection — EWMA baseline, multi-signal scoring, adaptation modes
4. Poisoning resilience — heuristic design, replay buffer integration
5. Energy-aware response — battery-proportional policy, adapter chain architecture
6. Verifiable audit — digest chain, signed checkpoints, proof-carrying updates
7. Evaluation — detection accuracy, poisoning resilience, energy overhead, audit integrity
8. Related work — TinyML security, edge anomaly detection, verifiable logging
9. Limitations and future work — continual learning, ZK proofs, swarm coordination
10. Conclusion

### Gap analysis — what must be added before submission

| Gap | Effort | Blocker? |
|-----|--------|----------|
| ARM cross-compilation and profiling | Medium | No — evaluation can use QEMU or real Pi |
| Additional test fixtures (>=100 samples each) | Low | No |
| Per-dimension contribution breakdown in anomaly explanations | Low | Already partially there in `AnomalySignal.reasons` |
| Formal comparison against a baseline detector (e.g., fixed-threshold, IsolationForest) | Medium | No — can generate from same fixtures |
| Latency micro-benchmarks with `criterion` | Medium | No |

---

## Paper 2 — Formal Policy Verification (future)

**Working title:** *Runtime-Verified Response Policies for Edge Security: From State Machine Models to TLA+ Proofs*

**Primary tracks:** R02 (formal verification), R09 (adaptive response), R10 (verifiable rollback)

**Prerequisite:** TLA+/Alloy integration (T033 completion). Currently scaffolded — export stubs exist, formal checker integration deferred.

---

## Paper 3 — Privacy-Preserving Fleet Security (future)

**Working title:** *Privacy-Preserving Swarm Defense for Edge Fleets: Protocol Design and Zero-Knowledge Coordination*

**Primary tracks:** R03 (swarm intelligence), R08 (coordinated response), R15 (threat intelligence sharing), R23 (swarm defense coordination)

**Prerequisite:** Swarm coordination protocol (T051). Currently no cross-device code exists.

---

## Prioritization rationale

Paper 1 is prioritized because:
- All six core tracks have implemented foundations — no new subsystems required.
- The benchmark harness already produces publishable metrics.
- The evaluation plan uses only existing CLI commands and fixtures.
- The gap analysis shows only low-to-medium effort items remain.

Papers 2 and 3 depend on subsystems that are currently scaffolded or unimplemented. They are documented here to guide the next implementation phases.
