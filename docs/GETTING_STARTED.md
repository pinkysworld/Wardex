# Getting Started

## Requirements

- Rust toolchain (`cargo`)
- A recent macOS, Linux, or Windows environment capable of running a single Rust binary

## Build

```bash
cargo build
```

## Run the built-in demo

```bash
cargo run -- demo
```

This executes a short internal telemetry sequence and writes an audit trail to `var/demo.audit.log`.

## Analyze a telemetry trace

CSV format:
```bash
cargo run -- analyze examples/credential_storm.csv
```

JSONL format (auto-detected by `.jsonl` extension):
```bash
cargo run -- analyze examples/credential_storm.jsonl
```

Default audit output for `analyze` is `var/last-run.audit.log`.

## Generate a JSON report for SIEM

```bash
cargo run -- report examples/credential_storm.csv
```

Default output is `var/last-run.report.json`.

## Generate a default configuration file

```bash
cargo run -- init-config
```

Creates `sentineledge.toml` with all default thresholds, battery policies, and output paths. Edit this file to customize the runtime.

## Inspect the project status snapshot

```bash
cargo run -- status
```

## Export structured status JSON for the browser console

```bash
cargo run -- status-json site/data/status.json
```

This writes the structured status snapshot consumed by the read-only browser console.

## Run tests

```bash
cargo test
```

The test suite currently includes 52 tests covering telemetry parsing, anomaly detection, policy evaluation, audit chains, checkpoints, forensics, proof verification, state machine transitions, replay buffers, poisoning heuristics, benchmark scoring, and status export.

## Open the read-only browser admin console

1. Generate a report JSON file:

```bash
cargo run -- report examples/credential_storm.csv site/data/demo-report.json
```

2. Generate a structured status snapshot:

```bash
cargo run -- status-json site/data/status.json
```

3. Open `site/admin.html` in a browser.

The static console can inspect exported JSON artifacts without a running server.

## Live admin console

Start the HTTP server:

```bash
cargo run -- serve
```

This starts a server on port 8080 and prints a one-time authentication token to the terminal. Open `http://localhost:8080/admin.html` in a browser, paste the token, and use the control panel to:

- refresh runtime status and reports live
- run demo analysis
- switch detection mode (normal / frozen / decay)
- reset the detector baseline

Custom port and site directory:

```bash
cargo run -- serve 9090 site
```

## Telemetry CSV format

The parser supports both the legacy 8-column format and the extended 10-column format.

Legacy header (8 columns):
```text
timestamp_ms,cpu_load_pct,memory_load_pct,temperature_c,network_kbps,auth_failures,battery_pct,integrity_drift
```

Extended header (10 columns):
```text
timestamp_ms,cpu_load_pct,memory_load_pct,temperature_c,network_kbps,auth_failures,battery_pct,integrity_drift,process_count,disk_pressure_pct
```

## Telemetry JSONL format

Each line is a JSON object with the same fields:
```json
{"timestamp_ms":1000,"cpu_load_pct":18,"memory_load_pct":32,"temperature_c":41,"network_kbps":500,"auth_failures":0,"battery_pct":94,"integrity_drift":0.01,"process_count":42,"disk_pressure_pct":8}
```

## Example scenarios

| File | Description |
|------|-------------|
| `examples/credential_storm.csv` | Rapid auth failure escalation |
| `examples/credential_storm.jsonl` | Same scenario in JSONL format |
| `examples/benign_baseline.csv` | Normal operation with no anomalies |
| `examples/slow_escalation.csv` | Gradual threat buildup across 15 samples |
| `examples/low_battery_attack.csv` | Attack during low battery conditions |

## Field notes

- `timestamp_ms`: monotonically increasing sample timestamp
- `cpu_load_pct`: 0-100
- `memory_load_pct`: 0-100
- `temperature_c`: operating temperature in Celsius
- `network_kbps`: observed network throughput
- `auth_failures`: failed authentication attempts in the sampling window
- `battery_pct`: 0-100
- `integrity_drift`: normalized 0-1 signal for model/config drift
- `process_count`: number of active processes (optional, defaults to 0)
- `disk_pressure_pct`: disk I/O pressure 0-100 (optional, defaults to 0)
