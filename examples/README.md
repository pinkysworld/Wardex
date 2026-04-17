# Example Telemetry Data

This directory contains sample telemetry traces for testing Wardex's detection and response pipeline.

## CSV Schema

### Standard format (8 columns)

| Column | Type | Description |
|--------|------|-------------|
| `timestamp_ms` | integer | Millisecond timestamp since start |
| `cpu_load_pct` | float | CPU utilisation (0–100%) |
| `memory_load_pct` | float | Memory utilisation (0–100%) |
| `temperature_c` | float | Device temperature in °C |
| `network_kbps` | float | Network bandwidth in Kbps |
| `auth_failures` | integer | Authentication failure count |
| `battery_pct` | float | Battery level (0–100%) |
| `integrity_drift` | float | File integrity drift score (0.0–1.0) |

### Extended format (10 columns)

Adds two additional fields:

| Column | Type | Description |
|--------|------|-------------|
| `process_count` | integer | Number of running processes |
| `disk_pressure_pct` | float | Disk I/O pressure (0–100%) |

### JSONL format

The `.jsonl` files contain one JSON object per line with the same fields as the CSV columns.

## Scenarios

### `benign_baseline` / `benign_extended`
Normal device operation with no attack patterns. Used as a baseline for anomaly detector training and false-positive rate measurement.

### `credential_storm` / `credential_storm_extended`
Simulates a brute-force credential attack. The `auth_failures` field spikes sharply mid-trace, triggering elevated and severe threat levels.

### `low_battery_attack` / `low_battery_extended`
Attack scenario where the device is battery-constrained. Tests the policy engine's ability to downgrade response actions when battery is critically low (graceful degradation).

### `slow_escalation` / `slow_escalation_extended`
Gradual escalation attack that avoids sudden spikes. Tests the detector's sensitivity to slowly drifting baselines — each sample increases load slightly, designed to evade threshold-based detection.

## Usage

```bash
# Analyse a single trace
cargo run -- analyze examples/credential_storm.csv

# Run with extended format
cargo run -- analyze examples/credential_storm_extended.csv

# Generate a structured JSON report
cargo run -- report examples/slow_escalation.csv

# Run the benchmark harness comparing scenarios
cargo run -- benchmark examples/benign_baseline.csv examples/credential_storm.csv
```

## Loading into the admin console

1. Start the backend: `cargo run`
2. Open the embedded local admin console at `http://localhost:8080/admin/`
3. Use the API to inject telemetry: `POST /api/telemetry/ingest` with a JSON body containing the sample data
4. Alternatively, use the live monitor and let the built-in collector generate live telemetry

If you are running the frontend dev server separately, use `http://localhost:5173/admin/`; `:8080` is the backend-served default after `cargo run`.
