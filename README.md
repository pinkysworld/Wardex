# Wardex

Wardex is a Rust-based XDR and SIEM platform for private-cloud and self-hosted security operations. It combines cross-platform telemetry collection, detection engineering, analyst workflows, approval-gated response, agent lifecycle management, SIEM integrations, and tamper-evident evidence handling in a single deployable product.

## What ships in `v0.34.0`

- Everything from v0.33.0 plus 12 production-hardening features
- Persistent storage backend with atomic JSON writes, schema migrations, and retention purge
- Real OS enforcement execution with command safety filter and dry-run mode
- Outbound notifications to Slack, Teams, PagerDuty, Webhook, and Email
- Alert deduplication with time-window grouping and cross-device merge
- Atomic agent update with SHA-256 verification and automatic rollback
- Dashboard deep-linking and alert timeline visualization
- Operator runbooks for deployment, upgrades, and troubleshooting
- YARA-style pattern matching engine with built-in threat-detection rules
- CycloneDX 1.5 and SPDX 2.3 SBOM generation for supply-chain compliance
- Multi-tenancy isolation guards and cross-tenant access control
- Real mesh networking with checksummed frames and hop-limited forwarding
- Professional browser console and HTTP API backed by 79 Rust source modules, 155+ documented API paths, and 915 automated tests

See [FEATURES.md](FEATURES.md) for the concise capability summary, [CHANGELOG.md](CHANGELOG.md) for release history, and [docs/README.md](docs/README.md) for the full documentation map.

## Quick start

Build the project:

```bash
cargo build --release
```

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
cargo run -- serve
```

Open `http://localhost:8080/admin.html`, paste the token printed in the terminal, and you will have access to the live admin console, SOC Workbench, fleet controls, detection engineering views, and reports.

## Core capabilities

- **Detection engineering**: managed Sigma/native rules, rule testing, promote/rollback lifecycle, suppressions, hunts, scheduled hunt history, and MITRE coverage.
- **SOC operations**: queued alerts, case management, investigation graph and timelines, entity pivots, storyline generation, evidence export, and response approvals.
- **Fleet operations**: agent enrollment, policy sync, update rollout groups, release assignment, rollback, cancellation, and per-agent activity snapshots.
- **Governance and trust**: RBAC, admin session control, tamper-evident audit records, change control entries, diagnostics bundles, dependency health, and IDP/SCIM configuration.
- **Integrations**: SIEM outputs, threat-intel pull, ticket sync, runbooks, API docs, and release packaging for Linux, macOS, and Windows.

## Verification

Run the full automated suite:

```bash
cargo test
```

The current release passes 915 automated tests across unit and integration coverage. The repo also includes live verification helpers in [`tests/live_test.py`](tests/live_test.py), [`tests/verify_admin.py`](tests/verify_admin.py), and browser smoke coverage in [`tests/playwright/enterprise_console_smoke.spec.js`](tests/playwright/enterprise_console_smoke.spec.js).

## Repository layout

```text
src/                  Core platform modules (79 Rust source files)
tests/                Integration tests, live checks, and browser smoke coverage
docs/                 Product, architecture, deployment, and runbook documentation
site/                 Static website and browser admin console
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
