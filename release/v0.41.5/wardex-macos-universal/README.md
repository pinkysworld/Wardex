# Wardex

Wardex is a Rust-based XDR and SIEM platform for private-cloud and self-hosted security operations. It combines cross-platform telemetry collection, detection engineering, analyst workflows, approval-gated response, agent lifecycle management, SIEM integrations, and tamper-evident evidence handling in a single deployable product.

## What ships in `v0.41.5`

- 105 Rust source modules covering telemetry collection, detection engineering, SOC workflows, fleet operations, governance, and automated incident response
- 119 documented OpenAPI paths with authenticated admin-console workflows, fleet controls, reports, and enterprise support surfaces
- 1258 automated tests (1095 lib + 163 integration) plus live Playwright admin-console smoke coverage for release validation
- Default local control-plane startup via `cargo run`, which launches the server and embedded local monitor together
- GitHub Actions packaging for Linux, macOS, and Windows release archives

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
cargo run
```

Open `http://localhost:8080/admin/`, paste the token printed in the terminal, and you will have access to the live admin console, SOC Workbench, fleet controls, detection engineering views, and reports. Use `cargo run -- serve` only when you explicitly want the web server without the embedded local monitor.

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

The current release passes 1258 automated tests (1095 lib + 163 integration) across unit and integration coverage. The repo also includes live verification helpers in [`tests/live_test.py`](tests/live_test.py), [`tests/verify_admin.py`](tests/verify_admin.py), [`tests/playwright/enterprise_console_smoke.spec.js`](tests/playwright/enterprise_console_smoke.spec.js), and [`tests/playwright/live_release_smoke.spec.js`](tests/playwright/live_release_smoke.spec.js).

## Repository layout

```text
src/                  Core platform modules (105 Rust source files)
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
