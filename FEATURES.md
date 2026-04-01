# Wardex — Features

Lightweight Rust edge security runtime that detects anomalies, enforces adaptive policy, and produces cryptographic audit trails — designed for constrained IoT/edge devices.

## Key Capabilities

- **Multi-signal anomaly detection** — EWMA-based scoring across 8 telemetry dimensions (CPU, memory, temperature, network, auth failures, integrity drift, process count, disk pressure)
- **Policy-driven response** — threat-level engine adapts mitigation strength to device battery state with pluggable action adapters (throttle, quarantine, isolate)
- **Cryptographic audit trail** — SHA-256 digest chain with signed checkpoints and programmatic verification for tamper-evident logging
- **Poisoning defence** — four heuristics (mean-shift, variance spike, drift accumulation, auth-burst) detect data manipulation; adaptation can be frozen or decayed
- **Proof backend interface** — pluggable proof backends (`DigestBackend`, `ZkStubBackend`) with witness export for future Halo2/SNARK integration
- **Continual learning** — Page-Hinkley drift detection with automatic baseline re-learning when the data distribution shifts (adversarial poisoning or concept drift)
- **Policy composition algebra** — composable multi-rule policies with MaxSeverity/MinSeverity/Priority operators and conflict detection
- **Rollback checkpoints** — bounded ring buffer captures and restores detector state via API
- **Adapter-backed restore** — checkpoint rollback now reapplies abstract device isolation/quarantine state through the action layer
- **Live admin console** — browser-based control plane with token auth, auto-refresh with exponential backoff, file upload (CSV/JSONL), CSV export, threat-level filtering, dark mode, and 14 interactive panels covering all features (security ops, fleet, digital twin, monitoring, compliance, quantum, policy, infrastructure, formal exports)
- **Multi-format ingestion** — auto-detects CSV (8 or 10 columns) and JSONL telemetry; file extension or content-type driven
- **Benchmark harness** — precision, recall, F1, and accuracy metrics on labeled datasets for FP/FN trade-off analysis
- **Forensic export** — evidence bundles combining audit log, run summary, and checkpoint history
- **SIEM integration** — Splunk HEC, Elasticsearch bulk API, Elastic ECS, QRadar LEEF, and generic JSON output with pull-based threat intel feed ingestion
- **XDR fleet management** — central server + lightweight agent architecture with enrollment, heartbeat tracking, event forwarding, and cross-agent correlation
- **Analyst console** — case management with status workflows, alert queue with acknowledgement and assignment, event search, investigation graph, and remediation approval
- **Sigma detection rules** — 25 built-in rules (SE-001 through SE-025) covering credential attacks, lateral movement, exfiltration, cryptomining, and privilege escalation
- **OCSF normalization** — event normalization to Open Cybersecurity Schema Framework with dead-letter queue for rejected events
- **Feature flags** — user/group/percentage targeting with A/B experiment support
- **Process tree analysis** — deep-chain detection, orphan tracking, and injection heuristics
- **Encrypted event spool** — SHA-256 CTR mode encrypted local buffer with retry and dead-letter semantics
- **Role-based access control** — Admin/Operator/Analyst/Viewer roles with endpoint-level RBAC enforcement
- **Platform collectors** — Windows (WMI/registry/event-log), Linux (/proc/journalctl), macOS (sysctl/IOKit/unified-log)
- **Agent auto-update** — binary distribution with SHA-256 verification and semver comparison
- **Cross-platform service installation** — systemd (Linux), launchd (macOS), sc.exe (Windows) service registration

## Architecture at a Glance

A 16-stage enriched pipeline — ingest → parse → detect → decide → threat-intel → enforce → digital-twin → energy → side-channel → compliance → act → audit → checkpoint → replay → benchmark → report — runs as a single-binary Rust process. The binary operates in two modes: **server** (central management with admin console) or **agent** (lightweight endpoint that enrolls with a server, forwards events, and receives policy updates). An embedded HTTP server (`tiny_http`) exposes authenticated REST endpoints for live monitoring, analysis, and control. All state lives in-memory; baselines persist to disk between runs. 58 modules, 637 automated tests.

## What's Built vs. Roadmap

| Available Now | Research Horizon |
|---|---|
| Adaptive EWMA anomaly scoring | Full model-checking integration |
| Continual learning with drift detection | On-device neural adaptation |
| Policy composition algebra with conflict detection | Multi-agent policy negotiation |
| Policy state machine with TLA+/Alloy export | Automated property synthesis |
| SHA-256 audit chain with signed checkpoints | Post-quantum signatures (hybrid lattice) |
| Poisoning heuristics (4 detectors) | Differential privacy guarantees |
| Proof backend interface with witness export | Zero-knowledge proof integration (Halo2) |
| Bounded replay buffer with statistics | Swarm/cross-device coordination |
| Token-authenticated HTTP API (100+ endpoints) | Wasm-based extensible policies |
| Supply-chain attestation foundations | Full attestation with Ed25519 signing |
| Criterion micro-benchmarks (55K samples/sec) | ARM cross-compilation profiling |
| 637 automated tests (523 unit + 114 integration) | Digital-twin fleet simulation |
| Browser admin console with dark mode | Quantum-walk anomaly propagation |
| XDR fleet management with SIEM integration | |
| Analyst console with case management | |
| 25 Sigma detection rules | |
| Platform collectors (Windows/Linux/macOS) | |
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
| `attest` | Generate build attestation manifest |
| `bench` | Run head-to-head detector benchmark |
| `serve` | Launch HTTP server + admin console |
| `help` | Show usage |
