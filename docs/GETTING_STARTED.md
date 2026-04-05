# Getting Started

## Requirements

- Rust toolchain with `cargo`
- macOS, Linux, or Windows for local development
- a modern browser for the admin console

## Build

```bash
cargo build --release
```

## Run the demo

```bash
cargo run -- demo
```

This executes the built-in telemetry sequence and writes audit output to `var/demo.audit.log`.

## Analyze a telemetry trace

CSV:

```bash
cargo run -- analyze examples/credential_storm.csv
```

JSONL:

```bash
cargo run -- analyze examples/credential_storm.jsonl
```

Default audit output for `analyze` is `var/last-run.audit.log`.

## Generate a structured report

```bash
cargo run -- report examples/credential_storm.csv
```

Default output is `var/last-run.report.json`.

## Start the live control plane

```bash
cargo run -- serve
```

This starts the HTTP server on port `8080` and prints a one-time admin token to the terminal. Open `http://localhost:8080/admin.html`, paste the token, and use the console to:

- inspect the Dashboard, Fleet & Agents, Threat Detection, Reports, and Settings surfaces
- work cases and alerts in the SOC Workbench
- manage hunts, rules, suppressions, and MITRE coverage in Detection Engineering
- review per-agent activity, deployment health, rollout targets, and rollback controls
- inspect diagnostics, dependency health, audit posture, and identity/provisioning configuration

## Export the static status snapshot

```bash
cargo run -- status-json site/data/status.json
```

This refreshes the structured status payload consumed by the static site and offline views.

## Run tests

```bash
cargo test
```

The current release passes 991 automated tests (981 lib + 10 chaos integration) across unit and integration coverage, including API regression coverage for hunts, content lifecycle, suppressions, entity pivots, incident storyline, governance, and supportability.

## Live validation helpers

- `python3 tests/live_test.py` exercises the live HTTP server paths.
- `python3 tests/verify_admin.py` validates key admin-console data surfaces.
- `tests/playwright/enterprise_console_smoke.spec.js` provides a reusable browser smoke flow for the enterprise console.

## Release packages

Tagged releases are built by GitHub Actions for:

- Linux `x86_64-unknown-linux-musl`
- macOS `aarch64-apple-darwin`
- Windows `x86_64-pc-windows-msvc`

## Telemetry format

The parser supports CSV (legacy 8-column and extended 10-column) and JSONL.

CSV header:

```text
timestamp_ms,cpu_load_pct,memory_load_pct,temperature_c,network_kbps,auth_failures,battery_pct,integrity_drift[,process_count,disk_pressure_pct]
```

JSONL line example:

```json
{"timestamp_ms":1000,"cpu_load_pct":18,"memory_load_pct":32,"temperature_c":41,"network_kbps":500,"auth_failures":0,"battery_pct":94,"integrity_drift":0.01,"process_count":42,"disk_pressure_pct":8}
```
