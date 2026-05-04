# Wardex

[![Site](https://img.shields.io/badge/site-minh.systems%2FWardex-1a6b5a?style=flat-square)](https://minh.systems/Wardex/)
[![Support](https://img.shields.io/badge/support-GitHub%20Sponsors-c47a2e?style=flat-square)](https://github.com/sponsors/pinkysworld)
[![Release](https://img.shields.io/github/v/release/pinkysworld/Wardex?style=flat-square)](https://github.com/pinkysworld/Wardex/releases)

Wardex is a Rust-based XDR and SIEM platform for private-cloud and self-hosted security operations. It combines cross-platform telemetry collection, detection engineering, analyst workflows, approval-gated response, agent lifecycle management, SIEM integrations, and tamper-evident evidence handling in a single deployable product.

## What ships in `v0.56.0`

- 139 Rust source modules covering telemetry collection, detection engineering, hunt/search, SOC workflows, fleet operations, governance, and automated incident response.
- A versioned OpenAPI contract with regenerated Python and TypeScript SDKs for authenticated admin-console workflows, explainability, onboarding readiness, threat-intel enrichment, malware analysis, reports, hunts, investigations, NDR, and enterprise support surfaces.
- 1500+ automated tests and smoke checks spanning Rust, SDK, admin-console, and Playwright browser coverage.
- **Control-plane posture evidence** — Help & Docs plus the support-readiness, dependency-health, and backup-status contracts now surface active/passive reference status, backup cadence, latest backup/checkpoint artifacts, and restore readiness so operators can verify recovery posture without reading raw backend JSON.
- **Release guardrails** — Node 22 contributor and CI alignment, checksummed release assets, Debian package install smoke coverage, strict Playwright a11y gates for onboarding and settings, and shared request-ID generation harden the release path.
- **Product Command Center** — `/command` is the analyst default workspace, bringing incident pressure, cases, connector gaps, remediation approvals, rule tuning debt, release readiness, and compliance evidence into one routed surface with inline action drawers, drawer deep-links via `?drawer=<lane>`, and a per-lane `GET /api/command/lanes/{lane}` endpoint for focused refreshes.
- **Guided connector onboarding** — GitHub Audit Log, CrowdStrike Falcon, and Generic Syslog now have saved setup contracts, validation endpoints, sample-event proof, collector status, OpenAPI coverage, and console onboarding flows.
- **Detection trust and explainability** — model-registry status, shadow-mode inference tracking, rollback visibility, analyst feedback capture, entity-centric risk scoring, campaign intelligence, replay-corpus gates, platform/signal-type drift breakdowns, and explainable alert reasoning are now first-class operator workflows instead of backend-only plumbing.
- **Operator-readiness onboarding** — onboarding is now driven by server readiness checks that verify token validity, first agent health, telemetry flow, alert visibility, intel-source health, malware scan readiness, and response dry-run coverage.
- **Incident-first SOC workflows** — SOC Workbench now keeps cases, incidents, notes, evidence, narrative context, and pivots into investigations, response, assistant, and reporting in URL-addressable drawers that can be reopened and shared.
- **Shift and handoff operations** — SOC Workbench and Command Center now expose a Shift Command Board, case handoff packets, team load and ownership, connector coverage impact, and compact detection-review pressure so shift leads can assign work and validate blockers without rebuilding context by hand.
- **Scoped reporting and artifacts** — reports, report runs, schedules, templates, and stored artifacts can now carry case / incident / investigation execution context, with backend filtering and republish flows for older unscoped reports.
- **Artifact persistence and response closure** — compliance exports, evidence bundles, audit exports, privacy snapshots, backend-native alert exports, and response-approval snapshots can now be persisted into scoped run history and reopened with their original payloads.
- **Threat-intel and malware depth** — richer threat-intel `v2` metadata, indicator sightings, deep malware scan `v2` static and behavior profiles, route-aware malware verdict workspaces, and analyst-facing provenance views are now wired through the console.
- **Session and integration hardening** — pasted console tokens are exchanged for HttpOnly admin sessions, while federated sign-in readiness plus cloud, identity, and SaaS collector lanes expose staged validation, lifecycle history, failure streaks, last-success/error checkpoints, and ingestion-health analytics instead of snapshot-only summaries.
- **Remediation review history** — Infrastructure now records approval and recovery notes for malware verdicts and remediation candidates, giving operators a durable change-review ledger for high-risk action paths.
- **Production demo lab** — Help & Docs can seed an evaluation-ready scenario with telemetry, case context, response dry-run approval, report artifacts, and evidence metadata.
- **Manager and analyst efficiency** — morning-brief style dashboard summaries, saved queue filters, deep-linked alert/case selection, and target-aware assistant/reporting handoffs from SOC, NDR, UEBA, detection, attack-graph, and infrastructure flows reduce console re-navigation and make exact workflows shareable.
- **Deterministic regression coverage** — focused Rust, admin-console, and routed Playwright release checks now cover Command Center action drawers, explainability, replay drift, collector timelines, deep malware scan profiles, threat-intel sightings, and scoped report/report-template persistence.

See [FEATURES.md](FEATURES.md) for the concise capability summary, [CHANGELOG.md](CHANGELOG.md) for release history, and [docs/README.md](docs/README.md) for the full documentation map.

## Quick start

The fastest path from a clean checkout to a running local console is:

```bash
npm ci --prefix admin-console
cargo build --release
```

The embedded admin console is compiled as part of the Rust build, so a clean checkout needs the admin-console npm dependencies installed first.

Start Wardex:

```bash
./target/release/wardex start
```

Read the admin token:

```bash
cat var/.wardex_token
```

Open the admin console:

```text
http://localhost:8080/admin/
```

Paste the token from `var/.wardex_token` into the login form.

Important:

- `http://localhost:8080/` is the public product website.
- `http://localhost:8080/admin/` is the actual admin console.
- If you set `WARDEX_ADMIN_TOKEN` yourself, Wardex uses that value and may not create `var/.wardex_token`.
- You can confirm which binary you are running with `./target/release/wardex --version`.

For development, `cargo run` is equivalent to `wardex start` and also serves the console on `http://localhost:8080/admin/`.

Useful next commands:

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

`cargo run` starts the local Rust control plane on port `8080` and serves the embedded admin console from `http://localhost:8080/admin/`. Read the token from `var/.wardex_token`, paste it into the login form, and you will have access to the live admin console, SOC Workbench, fleet controls, detection engineering views, and reports. If you are developing the frontend separately with `npm run dev`, use `http://localhost:5173/admin/` instead; `:8080` is the backend-served local default, not the standalone Vite dev server. Use `cargo run -- serve` only when you explicitly want the web server without the embedded local monitor.

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
