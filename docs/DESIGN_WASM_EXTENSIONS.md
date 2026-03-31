# Wasm Extension Surface Specification

Design document for R17 (Wasm-Based Extensible Detection and Response Policies).

## Goals

1. Let operators ship custom detection rules or response logic as sandboxed WebAssembly modules.
2. Guarantee that extensions cannot crash the runtime, access host memory, or exceed energy budgets.
3. Provide a narrow, typed API surface — extensions see only what the host explicitly shares.
4. Account for resource consumption (CPU cycles, memory pages) and enforce limits.

## Non-goals

- Full general-purpose plugin system (no file I/O, no networking from Wasm).
- Hot-reloading without restart (initial version loads modules at startup).
- Wasm Component Model compliance (initial version uses core Wasm 1.0 imports/exports).

## Architecture

```
┌──────────────────────────────────────────────┐
│                Wardex Host              │
│                                              │
│  telemetry ─▶ detector ─▶ policy ─▶ actions  │
│                  │           │                │
│                  ▼           ▼                │
│            ┌──────────┐ ┌──────────┐         │
│            │ Wasm     │ │ Wasm     │         │
│            │ Detector │ │ Response │         │
│            │ Plugin   │ │ Plugin   │         │
│            └──────────┘ └──────────┘         │
│                  │           │                │
│            Host API    Host API               │
└──────────────────────────────────────────────┘
```

Wasm plugins run in a sandboxed interpreter (e.g., `wasmtime` or `wasmi`). They receive data through imported host functions and return results through exported functions.

## Plugin types

### 1. Detector plugin

Receives a telemetry sample and returns a supplementary anomaly signal. The host merges this with the built-in EWMA score.

**Exported functions:**

```wat
;; Called once at startup with the plugin configuration.
(func (export "init") (param $config_ptr i32) (param $config_len i32) (result i32))

;; Called for each telemetry sample. Returns a score adjustment.
(func (export "evaluate") (param $sample_ptr i32) (param $sample_len i32) (result f32))

;; Optional: return a human-readable reason string for the last evaluation.
(func (export "explain") (param $buf_ptr i32) (param $buf_len i32) (result i32))
```

**Imported host functions:**

```wat
;; Log a message to the host audit log (severity: 0=debug, 1=info, 2=warn).
(func (import "wardex" "log") (param $severity i32) (param $msg_ptr i32) (param $msg_len i32))

;; Read the current baseline mean for a given dimension (0–7).
(func (import "wardex" "baseline_mean") (param $dim i32) (result f32))

;; Read the current replay buffer statistics for a dimension.
(func (import "wardex" "replay_stat_mean") (param $dim i32) (result f32))
(func (import "wardex" "replay_stat_variance") (param $dim i32) (result f32))
```

### 2. Response plugin

Receives an anomaly signal and the current policy decision, then optionally adjusts the response.

**Exported functions:**

```wat
;; Called once at startup.
(func (export "init") (param $config_ptr i32) (param $config_len i32) (result i32))

;; Called after the built-in policy engine. Receives the signal and decision.
;; Returns an action override code (0 = no override, 1–4 = observe/throttle/quarantine/isolate).
(func (export "adjust") (param $signal_ptr i32) (param $signal_len i32)
                         (param $decision_ptr i32) (param $decision_len i32)
                         (result i32))
```

**Imported host functions:**

```wat
(func (import "wardex" "log") (param $severity i32) (param $msg_ptr i32) (param $msg_len i32))
(func (import "wardex" "battery_pct") (result f32))
(func (import "wardex" "alert_count_window") (result i32))
```

## Data exchange format

All data passed between host and plugin uses a flat, fixed-layout binary format (no serde, no JSON parsing in Wasm):

```
TelemetrySample (80 bytes, little-endian):
  offset  0: timestamp_ms    u64
  offset  8: cpu_load_pct    f32
  offset 12: memory_load_pct f32
  offset 16: temperature_c   f32
  offset 20: network_kbps    f32
  offset 24: auth_failures   u32
  offset 28: battery_pct     f32
  offset 32: integrity_drift f32
  offset 36: process_count   u32
  offset 40: disk_pressure   f32
  offset 44: _padding        [u8; 36]

AnomalySignal (24 bytes):
  offset  0: score           f32
  offset  4: confidence      f32
  offset  8: suspicious_axes u32
  offset 12: _reserved       [u8; 12]

PolicyDecision (16 bytes):
  offset  0: level           u32  (0=nominal, 1=elevated, 2=severe, 3=critical)
  offset  4: action          u32  (0=observe, 1=throttle, 2=quarantine, 3=isolate)
  offset  8: isolation_pct   u32
  offset 12: _reserved       u32
```

## Resource limits

| Resource | Default limit | Configurable? |
|----------|--------------|---------------|
| Memory pages (64 KiB each) | 16 pages (1 MiB) | Yes — `wasm.max_memory_pages` |
| Fuel (instruction count) | 1,000,000 per `evaluate` call | Yes — `wasm.max_fuel` |
| Execution time | 10 ms per call (fuel-derived) | Indirectly via fuel |
| Stack depth | 256 frames | No |
| Imported functions | Only those listed above | No |

When a plugin exceeds its fuel budget, the host traps the execution, logs the event, and falls back to the built-in detector/policy result.

## Configuration

Plugins are declared in the TOML configuration:

```toml
[[wasm.plugins]]
name = "custom-auth-detector"
type = "detector"              # "detector" or "response"
path = "plugins/auth_rule.wasm"
config = '{"threshold": 5}'    # passed to init()
priority = 10                  # merge order when multiple plugins exist
enabled = true

[[wasm.plugins]]
name = "regulatory-response"
type = "response"
path = "plugins/reg_response.wasm"
config = '{}'
priority = 20
enabled = true
```

## Score merging

When multiple detector plugins are active, their scores are combined with the built-in detector:

```
final_score = builtin_score + Σ(plugin_score_i × plugin_weight_i)
```

Weights default to 1.0 and are configurable per plugin. The host clamps the final score to `[0.0, 100.0]`.

## Security model

| Guarantee | Mechanism |
|-----------|-----------|
| Memory isolation | Wasm linear memory — plugin cannot access host memory |
| No host filesystem access | No WASI filesystem imports provided |
| No network access | No WASI socket imports provided |
| Bounded execution | Fuel metering; trap on exhaustion |
| Audit trail | Every plugin call (and trap) is recorded in the audit log |
| Plugin integrity | SHA-256 hash of the `.wasm` binary checked against config at load time |

## Implementation phases

1. **v0.1** — Define the binary data exchange structs in `src/wasm_types.rs`. No actual Wasm runtime.
2. **v0.2** — Add `wasmi` (pure-Rust interpreter) as an optional dependency behind a `wasm` feature flag.
3. **v0.3** — Implement host-side plugin loader with fuel metering and memory limits.
4. **v0.4** — Implement detector plugin integration: call `evaluate`, merge scores.
5. **v0.5** — Implement response plugin integration: call `adjust`, apply overrides.
6. **v0.6** — Add plugin integrity verification (SHA-256 hash check at load time).
7. **v0.7** — Publish example plugins (Rust-to-Wasm, AssemblyScript-to-Wasm).
