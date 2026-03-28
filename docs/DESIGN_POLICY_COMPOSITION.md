# Design: Formal Policy Composition Algebra (R39)

This document specifies the algebraic framework for composing multiple
overlapping detection and response policies, covering T076 from Phase 7.

---

## 1. Purpose

Real deployments layer policies from multiple sources — vendor defaults,
operator customisations, and regulatory requirements. This design provides a
formal framework to compose those policies, detect conflicts, resolve them
deterministically, and verify that the result is free of deadlocks and
contradictions.

## 2. Policy model

### 2.1 Policy layer

A policy layer is an ordered set of rules from a single source:

```rust
struct PolicyLayer {
    name: String,
    source: PolicySource,
    priority: u8,               // 0 = lowest, 255 = highest
    rules: Vec<PolicyRule>,
    metadata: LayerMetadata,
}

enum PolicySource {
    Vendor,
    Operator,
    Regulatory,
    Extension,                  // e.g., Wasm plugin (R17)
}

struct LayerMetadata {
    version: String,
    author: String,
    valid_from: Option<u64>,    // epoch timestamp
    valid_until: Option<u64>,
    hash: [u8; 32],
}
```

### 2.2 Policy rule

```rust
struct PolicyRule {
    id: String,
    condition: Condition,
    action: ResponseAction,
    priority_override: Option<u8>,  // overrides layer priority for this rule
}

struct Condition {
    predicates: Vec<Predicate>,
    combinator: Combinator,     // All | Any
}

enum Predicate {
    ScoreAbove(f64),
    ScoreBelow(f64),
    BatteryAbove(f64),
    BatteryBelow(f64),
    ThreatLevel(ThreatLevel),
    DimensionAbove(SignalDim, f64),
    TimeOfDay(u8, u8),         // hour range
    Custom(String),             // for Wasm extension predicates
}

enum ResponseAction {
    None,
    Log,
    Throttle { intensity: f64 },
    Quarantine { services: Vec<String> },
    Isolate,
    Alert { channel: String },
    Rollback { checkpoint: Option<u64> },
    Composite(Vec<ResponseAction>),
}
```

## 3. Composition algebra

### 3.1 Conflict definition

Two rules **conflict** when:
1. Their conditions overlap (there exists at least one state that satisfies
   both), AND
2. Their actions are incompatible (they would produce contradictory system
   effects if both executed).

### 3.2 Action compatibility

Actions form a partial order by severity:

```
None < Log < Throttle < Quarantine < Isolate
                                      ↑
                               Rollback (orthogonal)
```

Two actions are **compatible** if they are ordered by this relation (the more
severe one subsumes the less severe). They are **incompatible** if:
- One is `Throttle` and the other is `None` from a rule that explicitly
  prohibits throttling.
- Both are `Quarantine` with conflicting service sets.
- One is `Rollback` and the other prevents state changes.

### 3.3 Condition overlap analysis

Overlap is computed by checking if the intersection of two conditions' predicate
ranges is non-empty:

```rust
fn conditions_overlap(a: &Condition, b: &Condition) -> bool {
    // For each predicate dimension, check if ranges intersect.
    // All-combinator: all pairs must overlap.
    // Any-combinator: at least one pair must overlap.
    ...
}
```

For numeric predicates (score, battery, dimension), this is interval
intersection. For enum predicates (threat level), this is set intersection.

### 3.4 Resolution strategies

```rust
enum ConflictResolution {
    /// The rule with the higher priority (layer or override) wins.
    StrictPriority,

    /// The more severe action wins (escalation merge).
    EscalationMerge,

    /// Both actions execute (parallel). Only valid if non-contradictory.
    ParallelExec,

    /// A custom resolution function.
    Custom(String),  // name of registered resolver
}
```

Default resolution: `StrictPriority` with `EscalationMerge` as the fallback
when priorities are equal.

### 3.5 Composition operator

```
compose(L₁, L₂, ..., Lₙ) → ComposedPolicy
```

1. Collect all rules from all layers.
2. For each pair of rules (r_i, r_j) from different layers:
   a. Check if `conditions_overlap(r_i, r_j)`.
   b. If overlapping, check if `actions_compatible(r_i, r_j)`.
   c. If incompatible, resolve using the configured strategy.
3. Produce a `ResolvedRule` for each conflict resolution.
4. Merge all rules into a flat, priority-sorted list.

```rust
struct ComposedPolicy {
    layers: Vec<PolicyLayer>,
    resolved_rules: Vec<ResolvedRule>,
    conflicts_detected: usize,
    conflicts_resolved: usize,
    verification: VerificationResult,
}

struct ResolvedRule {
    original_rules: Vec<String>,   // IDs of conflicting rules
    resolved_action: ResponseAction,
    resolution_method: ConflictResolution,
    resolved_priority: u8,
}
```

## 4. Verification

### 4.1 Deadlock freedom

A deadlock occurs when the composed policy contains a cycle of rules where each
rule's action triggers the condition of another, creating an infinite loop.

Detection: build a directed graph where an edge from rule A to rule B means
"A's action can trigger B's condition". Deadlock freedom is equivalent to this
graph being acyclic.

```rust
fn check_deadlock_freedom(rules: &[ResolvedRule]) -> bool {
    let graph = build_trigger_graph(rules);
    !has_cycle(&graph)
}
```

### 4.2 Contradiction freedom

A contradiction occurs when a single system state triggers two rules whose
resolved actions are still incompatible (resolution failed or was not possible).

```rust
fn check_contradiction_freedom(rules: &[ResolvedRule]) -> bool {
    for (i, a) in rules.iter().enumerate() {
        for b in &rules[i + 1..] {
            if conditions_overlap(&a.condition, &b.condition)
                && !actions_compatible(&a.resolved_action, &b.resolved_action)
            {
                return false;
            }
        }
    }
    true
}
```

### 4.3 Worst-case response depth

The maximum number of chained rule triggers before the system settles:

```rust
fn worst_case_depth(rules: &[ResolvedRule]) -> usize {
    let graph = build_trigger_graph(rules);
    longest_path(&graph)
}
```

### 4.4 Verification result

```rust
struct VerificationResult {
    deadlock_free: bool,
    contradiction_free: bool,
    worst_case_depth: usize,
    unreachable_rules: Vec<String>,  // rules whose conditions can never fire
    shadowed_rules: Vec<String>,     // rules always overridden by higher priority
    verification_time_ms: u64,
}
```

## 5. Configuration format

Policy layers are loaded from TOML files:

```toml
[layer]
name = "vendor_default"
source = "vendor"
priority = 100

[[layer.rule]]
id = "vendor_critical_isolate"
condition = { predicates = ["score_above:0.95", "threat_level:critical"], combinator = "all" }
action = "isolate"

[[layer.rule]]
id = "vendor_warn_throttle"
condition = { predicates = ["score_above:0.6", "battery_above:0.3"], combinator = "all" }
action = { throttle = { intensity = 0.5 } }
```

```toml
[layer]
name = "operator_override"
source = "operator"
priority = 200

[[layer.rule]]
id = "op_no_isolate_daytime"
condition = { predicates = ["time_of_day:08:18"], combinator = "all" }
action = { quarantine = { services = ["ssh"] } }
priority_override = 250
```

The compositor loads all layer files, runs composition, and writes the verified
result to a compiled policy file that the runtime loads at startup.

## 6. Incremental re-verification

When a single layer is updated, only the rules in that layer need to be
re-checked against all other layers. The complexity is O(k × n) where k is
the number of rules in the changed layer and n is the total rule count,
instead of O(n²) for a full re-verification.

```rust
fn incremental_verify(
    existing: &ComposedPolicy,
    changed_layer: &PolicyLayer,
) -> VerificationResult {
    // 1. Remove old rules from changed layer.
    // 2. Add new rules from changed layer.
    // 3. Check only pairs involving new rules.
    // 4. Re-check trigger graph for cycles involving changed rules.
    ...
}
```

Target: < 100 ms for incremental re-verification with ≤ 10 layers.

## 7. Runtime evaluation

At runtime, the composed policy evaluates incoming samples against the flat
resolved rule list in priority order:

```rust
fn evaluate(policy: &ComposedPolicy, state: &SystemState) -> ResponseAction {
    let mut actions = Vec::new();
    for rule in &policy.resolved_rules {
        if rule.condition.matches(state) {
            actions.push(rule.resolved_action.clone());
        }
    }
    merge_actions(actions)  // apply escalation merge
}
```

The overhead compared to a single-layer policy is the cost of evaluating
additional conditions, which is bounded by the total rule count.

## 8. Implementation phases

| Phase | Deliverable |
|---|---|
| 1 | Define PolicyLayer, PolicyRule, Condition, ResponseAction types in a `composition` module |
| 2 | Implement condition overlap analysis for all predicate types |
| 3 | Implement action compatibility checking and severity ordering |
| 4 | Implement the compose() operator with StrictPriority and EscalationMerge |
| 5 | Implement deadlock and contradiction verification |
| 6 | Add TOML layer loading and compiled policy output |
| 7 | Implement incremental re-verification |
| 8 | Integration tests with multi-layer scenarios |
