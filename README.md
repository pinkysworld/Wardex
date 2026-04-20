# Wardex

[![Site](https://img.shields.io/badge/site-minh.systems%2FWardex-1a6b5a?style=flat-square)](https://minh.systems/Wardex/)
[![Support](https://img.shields.io/badge/support-GitHub%20Sponsors-c47a2e?style=flat-square)](https://github.com/sponsors/pinkysworld)
[![Release](https://img.shields.io/github/v/release/pinkysworld/Wardex?style=flat-square)](https://github.com/pinkysworld/Wardex/releases)

Wardex is a Rust-based XDR and SIEM platform for private-cloud and self-hosted security operations. It combines cross-platform telemetry collection, detection engineering, analyst workflows, approval-gated response, agent lifecycle management, SIEM integrations, and tamper-evident evidence handling in a single deployable product.

## What ships in `v0.53.0`

- 134 Rust source modules covering telemetry collection, detection engineering, hunt/search, SOC workflows, fleet operations, governance, and automated incident response.
- 138 documented OpenAPI paths with authenticated admin-console workflows, fleet controls, reports, hunts, investigations, NDR, and enterprise support surfaces.
- 1500+ automated tests and smoke checks spanning Rust, SDK, admin-console, and Playwright browser coverage.
- **NEW: Detection rules marketplace** — browsable rules index on the site with filters for kind, severity, and MITRE ATT&CK, plus contribution paths for YARA and Sigma packs.
- **NEW: Tiered pricing & checkout** — Community / Starter (€49/mo) / Team / Business / Enterprise, with an annual prepay toggle, a transparent comparison table, and a self-serve checkout landing page.
- **NEW: `wardex doctor` CLI** — one-command preflight diagnostics that check local config, TLS settings, data-directory health, and API reachability before you open a support ticket.
- **NEW: Public status & integrations pages** — release status, uptime signals, signing keys, and first-class integration guides for Splunk, Sentinel, Elastic, Slack, Jira, and more.
- **NEW: Admin-console UX polish** — `ConfirmDialog`, `EmptyState`, copy-to-clipboard helpers, and accessibility fixes across Settings, Fleet, and Reports.
- **NEW: Site presentation fixes** — rebuilt `styles.css` sections for pricing tiers, comparison tables, rules marketplace, feature/architecture pages, and the 404/changelog layouts.
- Investigation and hunt workflow UX (hunt drawer, saved-hunt execution, workflow suggestions).
- Analyst-quality tuning signals (false-positive advisor prefilled suppressions and rule-specific feedback).
- Deeper NDR visibility (beaconing cadence detection, dedicated anomaly endpoints, protocol distribution).
- Better threat context seeding (default intel feed sources, phishing heuristics, LOLBin reasoning).
- Deterministic Playwright browser smoke coverage.

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

## Support

The public support page at [minh.systems/Wardex/donate.html](https://minh.systems/Wardex/donate.html) summarizes sponsorship, commercial licensing, and non-monetary ways to help. You can support ongoing development, release validation, documentation, and SDK maintenance through [GitHub Sponsors](https://github.com/sponsors/pinkysworld). For production deployment or commercial usage under the current BSL 1.1 terms, contact the author for a separate commercial license.

## License

Wardex is released under the **Business Source License 1.1** (BSL 1.1).

- **Free for**: development, testing, evaluation, research, and non-commercial use.
- **Production commercial use** requires a separate commercial license from the author.
- **Converts to Apache 2.0** on 2029-04-01.

See [LICENSE](LICENSE) for the full terms.
