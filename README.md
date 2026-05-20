# Wardex

[![Site](https://img.shields.io/badge/site-minh.systems%2FWardex-1a6b5a?style=flat-square)](https://minh.systems/Wardex/)
[![Support](https://img.shields.io/badge/support-GitHub%20Sponsors-c47a2e?style=flat-square)](https://github.com/sponsors/pinkysworld)
[![Release](https://img.shields.io/github/v/release/pinkysworld/Wardex?style=flat-square)](https://github.com/pinkysworld/Wardex/releases)

Wardex is a Rust-based XDR and SIEM platform for private-cloud and self-hosted security operations. It brings telemetry collection, detection engineering, malware analysis, analyst workflows, approval-gated response, fleet management, evidence handling, and release verification into one deployable product.

## Why Wardex

- **Own the control plane:** run the console, APIs, telemetry, and evidence workflows in your own environment.
- **Investigate in one place:** triage alerts, inspect threads/processes, pivot into cases, and keep source evidence attached.
- **Respond with guardrails:** use approval-aware actions such as block IP, isolate host, kill process, quarantine file, disable account, and rollback.
- **Scan across platforms:** malware, virus, trojan, and rootkit workflows cover Linux, macOS, and Windows with local engines plus optional open-source signature presets.
- **Ship verifiably:** releases include checksums, SBOMs, provenance, signed artifacts, and documented verification gates.

## Current Release: `v1.0.23`

This release replaces several placeholder or simulated subsystems with genuine implementations, lays incremental groundwork for the `server.rs` decomposition, and starts the per-slice TypeScript migration of the admin console.

- **Real ML triage engine** — multiclass gradient-boosted classifier trained at startup (regression trees fitted to softmax cross-entropy gradients, XGBoost-style split gain). The Random Forest now runs as the shadow / fallback backend.
- **Real FIPS 204 post-quantum signatures** — `quantum.rs` ML-DSA-65 via the pure-Rust `ml-dsa` crate; verification uses only the public key.
- **Real GCP collector authentication** — service-account JWT signed with RS256 instead of a placeholder, so Cloud Audit Log polling actually authenticates.
- **Live threat-feed ingestion** — background poll loop + format-specific parsers for Abuse.ch MalwareBazaar (CSV), URLhaus (`json_online`), and Feodo Tracker (C2 IP blocklist); the bundled feeds ingest real indicators out of the box.
- **TLS on by default** so release binaries can make outbound HTTPS, plus a `cluster.require_tls` flag that upgrades peer RPCs to HTTPS and rejects plaintext peer URLs at config-validation time.
- **Server decomposition step 1** — ML, feed-ingestion, and cluster-RPC handlers extracted into dedicated `server_ml.rs` / `server_feeds.rs` / `server_cluster.rs` modules. Visibility groundwork (`AppState` `pub(crate)` plus its needed fields) is in place for the remaining domain extractions.
- **TypeScript migration first slices** — `safeStorage.ts` and `api.ts` (wrapper layer fully typed: generic `request<T>`, typed options/errors, 11 endpoints typed end-to-end via `@wardex/sdk`).
- **OpenAPI 254 documented operations** — the `/api/feeds/*` family is now in the spec; contract-parity gate updated.

See [CHANGELOG.md](CHANGELOG.md) for full release history.

## Quick Start

Install frontend dependencies and build the Rust binary:

```bash
npm ci --prefix admin-console
cargo build --release
```

Start Wardex:

```bash
./target/release/wardex start
```

Read the generated admin token:

```bash
cat var/.wardex_token
```

Open the console:

```text
http://localhost:8080/admin/
```

Notes:

- `http://localhost:8080/` serves the product website.
- `http://localhost:8080/admin/` serves the authenticated admin console.
- If `WARDEX_ADMIN_TOKEN` is set, Wardex uses that token and may not create `var/.wardex_token`.
- Check the running version with `./target/release/wardex --version`.

Useful local commands:

```bash
cargo run -- demo
cargo run -- analyze examples/credential_storm.csv
cargo run
```

## Core Capabilities

- **Telemetry and monitoring:** OS event streams, process trees, file/network activity, kernel-event normalization, and live control-plane views.
- **Detection engineering:** managed Sigma/native rules, YARA content, MITRE ATT&CK coverage, suppressions, replay validation, promotion/rollback, and saved hunts.
- **Malware analysis:** hash and YARA matching, static and behavior profiles, quarantine guidance, open-source signature presets, and on-demand scans.
- **SOC workflows:** alert queue, cases, investigations, notes, timelines, evidence bundles, handoffs, response approvals, and analyst assistant pivots.
- **Response automation:** playbooks, approval gates, platform-aware remediation actions, rollback evidence, and audit history.
- **Fleet operations:** agent enrollment, heartbeat tracking, policy sync, rollout assignment, rollback, recovery focus, and inventory context.
- **Governance:** RBAC, HttpOnly admin sessions, audit chain, retention controls, encrypted evidence buffering, compliance exports, and support bundles.
- **Integrations:** SIEM export, OCSF normalization, live threat-intel feed ingestion (MalwareBazaar, URLhaus, Feodo Tracker), ticket sync, OpenTelemetry, GraphQL, REST OpenAPI, and generated SDKs.

## Documentation

Start here:

- [Getting Started](docs/GETTING_STARTED.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Status](docs/STATUS.md)
- [Compatibility](docs/COMPATIBILITY.md)
- [Release Acceptance](docs/RELEASE_ACCEPTANCE.md)
- [Runbooks](docs/runbooks/README.md)
- [SDK Guide](docs/SDK_GUIDE.md)
- [OpenAPI Contract](docs/openapi.yaml)

The public website lives in [site/](site/) and mirrors the main product, release, and support information.

## Documentation Surfaces

The GitHub docs and the public website now share the same `v1.0.23` release surface for operator guides and API reference.

![Wardex documentation hub](site/media/insights/resources-live.png)

![Wardex API reference](site/media/insights/api-reference-live.png)

## Development and Verification

Common checks:

```bash
cargo test
cargo build --release
npm run build --prefix admin-console
python3 scripts/validate_release_docs.py
make release-acceptance
```

Focused frontend checks can be run from `admin-console/` with Vitest or Playwright, depending on the workflow being changed.

## Releases and Trust

Tagged releases are packaged by GitHub Actions for Linux, macOS, and Windows. The release pipeline publishes checksums, CycloneDX SBOMs, SLSA provenance, cosign signatures, and notarized macOS archives when the required signing secrets are present.

Local signed macOS builds require Developer ID signing and notarization credentials. Unsigned local builds are still useful for development and verification, but tagged CI releases are the distribution path for signed artifacts.

## Repository Layout

```text
src/                  Rust control plane, detection, scanning, response, and API modules
admin-console/        React admin console embedded into release builds
site/                 Static product website
docs/                 Product docs, runbooks, status, architecture, and release guidance
sdk/                  Generated Python and TypeScript SDKs
deploy/               Helm, OTLP, container, signing, and deployment assets
tests/                Integration, live, and browser smoke coverage
examples/             Sample telemetry and demo scenarios
.github/workflows/    CI, Pages, release, signing, and publishing automation
```

## License and Support

Wardex is dual-licensed:

- **Open source:** [AGPL-3.0](LICENSE)
- **Commercial:** [commercial license](LICENSE.COMMERCIAL) for organizations that cannot use AGPL network-service copyleft terms

Support and sponsorship details are available on the [Wardex support page](https://minh.systems/Wardex/donate.html) and through [GitHub Sponsors](https://github.com/sponsors/pinkysworld). For production deployment or commercial licensing, contact **support@wardex.dev**.
