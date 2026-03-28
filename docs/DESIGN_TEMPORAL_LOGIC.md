# Design: Temporal-Logic Property Specification Format (R29)

This document specifies the property specification language and runtime monitor
architecture for SentinelEdge, covering T074 from Phase 7.

---

## 1. Purpose

Define a lightweight temporal-logic language that operators and researchers can
use to express safety and bounded-liveness properties over SentinelEdge's
telemetry and alert streams. Properties are compiled into small automata and
monitored at runtime with minimal overhead.

## 2. Property language — SentinelTL

SentinelTL is a restricted LTL fragment supporting safety properties and
bounded liveness (all "eventually" operators carry an explicit bound). This
avoids the need for full Büchi acceptance and keeps monitor state bounded.

### 2.1 Syntax (EBNF)

```
property     ::= "property" IDENT "{" body "}"
body         ::= "on" stream guard? "=>" obligation
stream       ::= "alert" | "sample" | "action" | "transition"
guard        ::= "where" predicate
predicate    ::= atom (("&&" | "||") atom)*
atom         ::= field CMP value
               | "!" atom
               | "(" predicate ")"
field        ::= IDENT ("." IDENT)*
CMP          ::= "==" | "!=" | ">" | ">=" | "<" | "<="
value        ::= NUMBER | STRING | "true" | "false"
obligation   ::= safety | bounded_liveness
safety       ::= "always" predicate
bounded_liveness ::= "within" NUMBER "samples" predicate
```

### 2.2 Examples

```
// Every critical alert is followed by a response action within 10 samples.
property critical_response {
    on alert where severity == "critical"
        => within 10 samples action.kind != "none"
}

// The anomaly score never exceeds 1.0 (invariant / safety).
property score_bounded {
    on sample
        => always score <= 1.0
}

// Battery level must recover above 20% within 100 samples after hitting 10%.
property battery_recovery {
    on sample where battery < 0.10
        => within 100 samples battery >= 0.20
}

// A quarantine action is never issued when battery is below 15%.
property no_quarantine_low_battery {
    on action where kind == "quarantine"
        => always battery >= 0.15
}

// Threat level never jumps from Normal directly to Critical (must escalate).
property no_skip_escalation {
    on transition where from == "normal"
        => always to != "critical"
}
```

### 2.3 Semantics

- **always P**: P must hold on the triggering event and all subsequent events
  in the same stream until the end of the trace. A single violation fails
  the property.
- **within N samples P**: starting from the triggering event, P must hold on
  at least one of the next N events in the stream. If N events pass without
  P holding, the property is violated.

## 3. Compilation to monitor automata

Each property compiles to a small state machine:

```
                ┌─────────┐
                │  Idle   │ ─── guard matches ──▶ ┌──────────┐
                └─────────┘                        │ Tracking │
                     ▲                             └────┬─────┘
                     │                                  │
                     │                    ┌─────────────┼─────────────┐
                     │                    │             │             │
                     │              obligation    counter expired  obligation
                     │                 met              │          not met
                     │                    │             │             │
                     │               ┌────▼───┐   ┌────▼────┐  ┌────▼────┐
                     └───────────────│Satisfied│   │Violated │  │Violated │
                                     └────────┘   └─────────┘  └─────────┘
```

### Compiled representation

```rust
struct CompiledProperty {
    name: String,
    stream: StreamKind,
    guard: CompiledPredicate,
    obligation: CompiledObligation,
    state: MonitorState,
}

enum CompiledObligation {
    Always(CompiledPredicate),
    Within {
        bound: usize,
        predicate: CompiledPredicate,
        counter: usize,
    },
}

enum MonitorState {
    Idle,
    Tracking { remaining: usize },
    Satisfied,
    Violated { witness: Vec<u64> },
}

struct CompiledPredicate {
    bytecode: Vec<PredicateOp>,
}

enum PredicateOp {
    LoadField(FieldPath),
    PushConst(Value),
    Compare(CmpOp),
    And,
    Or,
    Not,
}
```

Predicates compile to a reverse-Polish bytecode that evaluates in a single
stack pass. No heap allocation is needed during evaluation.

## 4. Runtime monitor

```rust
struct RuntimeMonitor {
    properties: Vec<CompiledProperty>,
    violations: Vec<Violation>,
    stats: MonitorStats,
}

struct Violation {
    property_name: String,
    trigger_sample_id: u64,
    violation_sample_id: u64,
    witness: Vec<u64>,
}

struct MonitorStats {
    samples_processed: u64,
    properties_checked: u64,
    violations_found: u64,
    avg_check_ns: f64,
}
```

### Per-sample processing flow

1. For each active property whose stream matches the incoming event:
   a. If state is `Idle`, evaluate the guard. If true, transition to `Tracking`.
   b. If state is `Tracking`:
      - For `Always`: evaluate the predicate. If false, record `Violated`.
      - For `Within`: evaluate the predicate. If true, record `Satisfied` and
        return to `Idle`. If counter reaches zero, record `Violated`.
2. Append any violations to the violation log.
3. Optionally feed the violation count into the anomaly score as an additional
   signal dimension.

### Resource budget

| Resource | Budget |
|---|---|
| State per property | 3 registers + bytecode (< 512 bytes) |
| Time per sample (5 properties) | < 1 % of detection time |
| Violation log | bounded ring buffer (configurable, default 256 entries) |

## 5. Configuration format

Properties are loaded from TOML configuration files alongside the policy:

```toml
[[property]]
name = "critical_response"
stream = "alert"
guard = 'severity == "critical"'
obligation = { kind = "within", bound = 10, predicate = 'action.kind != "none"' }
enabled = true

[[property]]
name = "score_bounded"
stream = "sample"
obligation = { kind = "always", predicate = "score <= 1.0" }
enabled = true
```

## 6. Integration with anomaly score

Violation density (violations per window) can be injected into the detector
as an additional signal dimension:

```
monitor_score = violations_in_window / window_size
composite_score = (1.0 - monitor_weight) * detector_score
               + monitor_weight * monitor_score
```

Default `monitor_weight`: 0.10 (configurable).

## 7. Integration with audit chain

Each violation produces an audit log entry:

```rust
struct ViolationAuditEntry {
    property_name: String,
    trigger_sample_id: u64,
    violation_sample_id: u64,
    witness_hash: [u8; 32],       // SHA-256 of witness sample IDs
    severity: ViolationSeverity,  // Warning | Error | Critical
}
```

Violations are chained into the existing audit log so they participate in the
cryptographic digest chain and can be verified during forensic review.

## 8. Implementation phases

| Phase | Deliverable |
|---|---|
| 1 | Define SentinelTL grammar and parser (pest or nom) |
| 2 | Implement predicate bytecode compiler |
| 3 | Implement CompiledProperty and MonitorState state machine |
| 4 | Implement RuntimeMonitor with per-sample stepping |
| 5 | Add TOML configuration loading |
| 6 | Integrate violation density into anomaly score |
| 7 | Add violation audit entries to the digest chain |
| 8 | Write property library covering all existing policy invariants |
