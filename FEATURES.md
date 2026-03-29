# SentinelEdge — Features

Lightweight Rust edge security runtime that detects anomalies, enforces adaptive policy, and produces cryptographic audit trails — designed for constrained IoT/edge devices.

## Key Capabilities

- **Multi-signal anomaly detection** — EWMA-based scoring across 8 telemetry dimensions (CPU, memory, temperature, network, auth failures, integrity drift, process count, disk pressure)
- **Policy-driven response** — threat-level engine adapts mitigation strength to device battery state with pluggable action adapters (throttle, quarantine, isolate)
- **Cryptographic audit trail** — SHA-256 digest chain with signed checkpoints and programmatic verification for tamper-evident logging
- **Poisoning defence** — four heuristics (mean-shift, variance spike, drift accumulation, auth-burst) detect data manipulation; adaptation can be frozen or decayed
- **Proof backend interface** — pluggable proof backends (`DigestBackend`, `ZkStubBackend`) with witness export for future Halo2/SNARK integration
- **Rollback checkpoints** — bounded ring buffer captures and restores detector state via API
- **Adapter-backed restore** — checkpoint rollback now reapplies abstract device isolation/quarantine state through the action layer
- **Live admin console** — browser-based control plane with token auth, auto-refresh with exponential backoff, file upload (CSV/JSONL), CSV export, threat-level filtering, dark mode
- **Multi-format ingestion** — auto-detects CSV (8 or 10 columns) and JSONL telemetry; file extension or content-type driven
- **Benchmark harness** — precision, recall, F1, and accuracy metrics on labeled datasets for FP/FN trade-off analysis
- **Forensic export** — evidence bundles combining audit log, run summary, and checkpoint history
- **SIEM integration** — structured JSON reports and JSONL streaming output

## Architecture at a Glance

A 10-stage pipeline — ingest → parse → detect → decide → act → audit → checkpoint → replay → benchmark → report — runs as a single-binary Rust process. An embedded HTTP server (`tiny_http`) exposes authenticated REST endpoints for live monitoring, analysis, and control. All state lives in-memory; baselines persist to disk between runs.

## What's Built vs. Roadmap

| Available Now | Research Horizon |
|---|---|
| Adaptive EWMA anomaly scoring | Continual on-device learning |
| Policy state machine with TLA+/Alloy export | Full model-checking integration |
| SHA-256 audit chain with signed checkpoints | Post-quantum signatures (hybrid lattice) |
| Poisoning heuristics (4 detectors) | Differential privacy guarantees |
| Proof backend interface with witness export | Zero-knowledge proof integration (Halo2) |
| Bounded replay buffer with statistics | Swarm/cross-device coordination |
| Token-authenticated HTTP API (11 endpoints) | Wasm-based extensible policies |
| Supply-chain attestation foundations | Full attestation with Ed25519 signing |
| 136 automated tests (115 unit + 21 integration) | Digital-twin fleet simulation |
| Browser admin console with dark mode | Quantum-walk anomaly propagation |
| CSV + JSONL multi-format ingestion | |

## Quick Start

```bash
# Build
cargo build --release

# Run the demo scenario
cargo run -- demo

# Analyze a CSV dataset
cargo run -- analyze examples/credential_storm.csv

# Launch the admin console
cargo run -- serve
```

The `serve` command prints an auth token to the terminal. Open `http://localhost:8080` and paste the token to access the control plane.

## CLI Commands

| Command | Description |
|---|---|
| `demo` | Run built-in telemetry scenario |
| `analyze <file>` | Analyse a CSV or JSONL dataset |
| `report <file>` | Generate JSON report for SIEM |
| `init-config` | Write a starter TOML config |
| `status` | Print implementation status |
| `status-json` | Export status as JSON |
| `harness` | Run adversarial regression traces |
| `export-model` | Export state machine as TLA+ or Alloy |
| `serve` | Launch HTTP server + admin console |
| `help` | Show usage |
