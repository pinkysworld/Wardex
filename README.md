# Wardex

Wardex is a Rust-based XDR and SIEM platform for private-cloud and self-hosted security operations. It combines cross-platform telemetry collection, detection engineering, analyst workflows, approval-gated response, agent lifecycle management, SIEM integrations, and tamper-evident evidence handling in a single deployable product.

## What ships in `v0.52.5`

- 134 Rust source modules covering telemetry collection, detection engineering, hunt/search, SOC workflows, fleet operations, governance, and automated incident response.
- 138 documented OpenAPI paths with authenticated admin-console workflows, fleet controls, reports, hunts, investigations, NDR, and enterprise support surfaces.
- 1500+ automated tests and smoke checks spanning Rust, SDK, admin-console, and Playwright browser coverage.
- **NEW: Investigation and hunt workflow UX** — detection pages now consume `intent=run-hunt`, open a dedicated hunt drawer, save and run hunts inline, surface workflow suggestions, and let the SOC workbench pivot incidents and queue alerts directly into investigation plans or prefilled hunts.
- **NEW: Analyst-quality tuning signals** — false-positive advisor actions now prefill suppressions, suggest safer weight reductions, and display rule-specific feedback instead of raw statistics.
- **NEW: Deeper NDR visibility** — beaconing cadence detection, dedicated anomaly endpoints, and protocol distribution reporting are now wired through the API and console.
- **NEW: Better threat context seeding** — default intel feed sources, sender-domain phishing heuristics, and persistence/startup-path LOLBin reasoning improve the out-of-box signal mix.
- **NEW: Operator documentation and packaging polish** — sizing/HA guidance, native package installation notes, searchable site resources, Homebrew alignment, and SDK drift verification are now part of the shipped product surface.
- **NEW: Deterministic browser smoke coverage** — focused Playwright tests cover the new hunt drawer, saved-hunt execution, investigation planner, and queue-to-hunt pivots without depending on a live backend.

See [FEATURES.md](FEATURES.md) for the concise capability summary, [CHANGELOG.md](CHANGELOG.md) for release history, and [docs/README.md](docs/README.md) for the full documentation map.

## Quick start

Build the project:

```bash
npm ci --prefix admin-console
cargo build --release
```

The embedded admin console is compiled as part of the Rust build, so a clean checkout needs the admin-console npm dependencies installed first.

Run the included demo trace:

```bash
cargo run -- demo
```

Analyze a telemetry scenario:

```bash
cargo run -- analyze examples/credential_storm.csv
```

Start the live control plane:

```bash
cargo run
```

`cargo run` starts the local Rust control plane on port `8080` and serves the embedded admin console from `http://localhost:8080/admin/`. Open that URL, paste the token printed in the terminal, and you will have access to the live admin console, SOC Workbench, fleet controls, detection engineering views, and reports. If you are developing the frontend separately with `npm run dev`, use `http://localhost:5173/admin/` instead; `:8080` is the backend-served local default, not the standalone Vite dev server. Use `cargo run -- serve` only when you explicitly want the web server without the embedded local monitor.

## Core capabilities

- **Detection engineering**: managed Sigma/native rules, YARA engine, malware hash DB, rule testing, promote/rollback lifecycle, suppressions, KQL-like threat hunting, scheduled hunt history, and MITRE coverage.
- **Malware scanning**: file hash lookup against ~48 built-in signatures, YARA pattern matching, verdict classification (malicious/suspicious/clean), and community rule packs.
- **SOC operations**: queued alerts, case management, investigation graph and timelines, entity pivots, storyline generation, evidence export, alert deduplication, and response approvals.
- **Incident automation**: declarative playbook engine with 11 step types, trigger matching, conditional branching, parallel execution, approval gates, and SLA-driven escalation.
- **Fleet operations**: agent enrollment, policy sync, update rollout groups, release assignment, rollback, cancellation, and per-agent activity snapshots.
- **Governance and compliance**: RBAC, admin session control, tamper-evident audit records, compliance evaluation (CIS v8, PCI-DSS v4, SOC 2, NIST CSF 2.0), encrypted backups, and IDP/SCIM configuration.
- **Integrations**: multi-format SIEM export (CEF/LEEF/Syslog/Sentinel/UDM/ECS/QRadar), threat-intel pull, ticket sync, OpenTelemetry tracing, API analytics, and release packaging for Linux, macOS, and Windows.

## Verification

Run the full automated suite:

```bash
cargo test
```

The current release is validated with Rust unit and integration suites, SDK checks, admin-console builds, and focused Playwright smoke coverage. The repo also includes live verification helpers in [`tests/live_test.py`](tests/live_test.py), [`tests/verify_admin.py`](tests/verify_admin.py), [`tests/playwright/enterprise_console_smoke.spec.js`](tests/playwright/enterprise_console_smoke.spec.js), and [`tests/playwright/live_release_smoke.spec.js`](tests/playwright/live_release_smoke.spec.js).

## Repository layout

```text
src/                  Core platform modules (134 Rust source files)
tests/                Integration tests, live checks, and browser smoke coverage
docs/                 Product, architecture, deployment, and runbook documentation
admin-console/        React admin console source (embedded from dist at build time)
site/                 Static product website
.github/workflows/    CI, Pages, and release automation
examples/             Sample telemetry traces for demo and regression scenarios
```

## Documentation

Start with:

- [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md)
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- [`docs/STATUS.md`](docs/STATUS.md)
- [`docs/DEPLOYMENT_MODELS.md`](docs/DEPLOYMENT_MODELS.md)
- [`docs/runbooks/README.md`](docs/runbooks/README.md)

## Releases

Tagged releases are packaged by GitHub Actions into Linux, macOS, and Windows archives. Public release notes and artifacts are published on the GitHub Releases page for this repository.

## License

Wardex is released under the **Business Source License 1.1** (BSL 1.1).

- **Free for**: development, testing, evaluation, research, and non-commercial use.
- **Production commercial use** requires a separate commercial license from the author.
- **Converts to Apache 2.0** on 2029-04-01.

See [LICENSE](LICENSE) for the full terms.
