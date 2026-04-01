# Wardex

Wardex is a Rust edge security runtime for anomaly detection, policy-driven response, and verifiable audit trails on constrained devices.

The research blueprint in [blueprint.md](blueprint.md) sketches 40 research tracks across seven thematic categories. The codebase has completed all 18 phases of the engineering backlog — 92/92 tasks complete:

- a configurable Rust runtime for multi-signal anomaly scoring across 8 dimensions
- an energy-aware response policy engine with pluggable device action adapters
- SHA-256 cryptographic audit chain with signed checkpoints and chain verification
- rollback checkpoints, forensic evidence bundles, and structured JSON/JSONL SIEM output
- TOML/JSON configuration, JSONL telemetry ingestion, and baseline persistence
- proof-carrying update metadata with SHA-256 binding and verification
- formally checkable policy state machine with legal transition validation
- bounded replay buffer with windowed statistics for continual learning
- poisoning heuristics (mean shift, variance spike, drift accumulation, auth burst)
- FP/FN benchmark harness with precision, recall, F1, and accuracy metrics
- explainable anomaly attribution, multi-signal correlation analysis, temporal-logic runtime monitoring, and behavioural device fingerprinting
- adapter-backed checkpoint restore that reapplies abstract device state as well as detector baseline state
- TLA+ and Alloy model export of the policy state machine for offline formal verification
- proof backend interface with witness export for future Halo2/SNARK integration
- live browser admin console with token-authenticated HTTP API, auto-refresh, file upload, and dark mode
- research paper targeting, swarm protocol design, Wasm surface spec, supply-chain attestation, post-quantum upgrade path
- research questions formalised for R26–R40 plus design documents for adversarial testing, temporal logic, digital twins, and policy composition
- runtime pipeline enrichment: threat intel, enforcement, digital twin, energy, side-channel, and compliance wired into `execute()`
- continual learning with Page-Hinkley drift detection and automatic baseline re-learning (R01)
- policy composition algebra with conflict detection for multi-rule evaluation (R39)
- criterion micro-benchmarks: ~55K samples/sec throughput, per-stage latency profiling
- full admin console integration with 14 interactive panels: security operations, fleet management, digital twin simulation, adversarial testing, monitoring & analysis, compliance, quantum key management, policy composition, infrastructure control, and formal model exports
- full integration test coverage: 84 HTTP tests covering all 45+ API endpoints with auth rejection validation
- paper evaluation harnesses: per-sample latency benchmarking and audit chain scaling tests (10–100K records)
- cross-platform host telemetry collector with live monitoring, webhook alerts, syslog/CEF output, and file-integrity monitoring
- admin console Live Monitoring panel with auto-polling alert table, settings editor, and toast notifications
- XDR fleet management: central server + lightweight agent architecture, enrollment, event forwarding with cross-agent correlation, policy distribution, SIEM integration (Splunk HEC/Elasticsearch/generic JSON), agent auto-update with SHA-256 verification, cross-platform service installation
- velocity rate-of-change detector, Shannon entropy analysis, and compound multi-axis threat correlation
- server security hardening: canonicalize path traversal, body size limits, security headers (X-Content-Type-Options, X-Frame-Options, Cache-Control, CORS)
- 437+ automated tests with 10k-sample benchmark and criterion benchmarks
- cross-platform CI (Linux, macOS, Windows) with clippy and fmt
- maintained docs, backlog tracking, test fixtures, and a GitHub Pages site

See [FEATURES.md](FEATURES.md) for a one-page capability summary and [CHANGELOG.md](CHANGELOG.md) for version history.

## What ships today

- **Adaptive anomaly scoring:** an EWMA-style baseline learns "normal" telemetry and scores deviations across CPU, memory, temperature, network load, authentication failures, integrity drift, process count, and disk pressure.
- **Configurable runtime:** all thresholds, battery policies, and output paths are externalizable via TOML or JSON configuration.
- **Multi-format ingestion:** CSV (legacy 8-column and extended 10-column) and JSONL telemetry input, auto-detected by file extension.
- **Policy-driven mitigation:** response strength adapts to threat score and battery state with pluggable action adapters (throttle, quarantine, isolate).
- **Cryptographic audit trail:** SHA-256 digest chain with signed checkpoints at configurable intervals and programmatic chain verification.
- **Rollback checkpoints:** bounded ring buffer captures detector state on severe/critical events for future rollback.
- **SIEM integration:** structured JSON reports and JSONL streaming output for alert events.
- **Forensic export:** evidence bundles combining audit log, run summary, and checkpoint history.
- **Baseline persistence:** learned baselines can be saved and reloaded across runs.
- **Proof-carrying updates:** every baseline change is bound to a SHA-256 proof linking prior state, transform, and post state.
- **Policy state machine:** an explicit state machine records and validates all threat-level transitions with formally defined legal rules.
- **Replay buffer:** bounded ring buffer retains recent telemetry for windowed statistical analysis and poisoning detection.
- **Adaptation controls:** detector baseline updates can be frozen, decayed, or reset to contain suspected poisoning.
- **Poisoning heuristics:** four statistical heuristics analyze replay buffers for data manipulation attempts.
- **Benchmark harness:** labeled datasets can be scored for true/false positive/negative rates, precision, recall, and F1.
- **Browser admin console:** a live web UI backed by a token-authenticated HTTP server with auto-refresh polling, connection status indicator, JSONL/CSV file upload via drag-and-drop, decay rate slider, checkpoint save/restore, CSV report export, threat-level filtering, dark mode support, and responsive report tables.
- **Operator-facing docs:** architecture, getting-started, backlog, and track-by-track implementation status in [`docs/`](docs/README.md).

## Quick start

```bash
cargo run -- demo
```

Run the included CSV scenario:

```bash
cargo run -- analyze examples/credential_storm.csv
```

Run the JSONL variant:

```bash
cargo run -- analyze examples/credential_storm.jsonl
```

Generate a JSON report for SIEM:

```bash
cargo run -- report examples/credential_storm.csv
```

Generate a default configuration file:

```bash
cargo run -- init-config
```

Inspect the current implementation snapshot:

```bash
cargo run -- status
```

Export the structured snapshot used by the browser console:

```bash
cargo run -- status-json site/data/status.json
```

Start the admin console HTTP server:

```bash
cargo run -- serve
```

Then open `http://localhost:8080/admin.html` in a browser. The token printed to the terminal is required for authenticated console operations, including settings, alerts, reports, and control actions.

The Settings view includes an OS-aware Monitoring Scope section that shows recommended monitoring points for the current host platform, explains why specific signals are recommended or unavailable, lets you control supported collectors including auth events and platform-specific persistence baselines, and previews the exact active monitoring paths.

The Fleet & Agents view now includes fleet-wide XDR analytics: top attack reasons, severity mix, hot-agent risk summaries, correlation rate, and policy history.

Run tests:

```bash
cargo test
```

## Repository layout

```text
src/                  Rust runtime (44 modules)
examples/             Sample telemetry traces (CSV + JSONL)
docs/                 Design notes, backlog, and status documentation
site/                 Static GitHub Pages site
.github/workflows/    CI and Pages deployment
blueprint.md          Original research track ideation
```

## Documentation

Start with [`docs/README.md`](docs/README.md).

Key documents:

- [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md)
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/STATUS.md`](docs/STATUS.md)
- [`docs/PROJECT_BACKLOG.md`](docs/PROJECT_BACKLOG.md)
- [`docs/RESEARCH_TRACKS.md`](docs/RESEARCH_TRACKS.md)

## GitHub Pages

The static landing page lives in `site/`, and the Pages workflow publishes it on pushes to `main`.

## License

Wardex is released under the **Business Source License 1.1** (BSL 1.1).

- **Free for**: development, testing, evaluation, research, and non-commercial use.
- **Production commercial use** requires a separate commercial license from the author.
- **Converts to Apache 2.0** on 2029-04-01.

See [LICENSE](LICENSE) for the full terms.
