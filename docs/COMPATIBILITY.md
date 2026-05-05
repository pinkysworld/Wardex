# Wardex Compatibility Policy

## Minimum Supported Rust Version (MSRV)

| Release series | MSRV  | Toolchain pin |
|----------------|-------|---------------|
| 1.x            | 1.88.0 | 1.95.0 (rust-toolchain.toml) |

MSRV is updated at most once per minor release. A patch release never raises
the MSRV. When MSRV is raised, it is documented in the CHANGELOG and announced
with at least one prior release's notice.

## Supported Platforms

### Pre-built release binaries

| Platform | Architecture | Tier |
|----------|-------------|------|
| Linux (glibc ≥ 2.31) | x86_64 | 1 — tested in CI, release-blocked |
| Linux (glibc ≥ 2.31) | aarch64 | 1 — tested in CI, release-blocked |
| macOS 13+ | aarch64 (Apple Silicon) | 1 — tested in CI, release-blocked |
| macOS 13+ | x86_64 (Intel) | 2 — built and smoke-tested |
| Windows 10/11 | x86_64 (GNU toolchain) | 2 — built and smoke-tested |

**Tier 1** — Blocked on CI passing. All unit, integration, and e2e tests must
pass. Release artifacts are signed and SHA-256 checksummed.

**Tier 2** — Best-effort. Cross-compiled; smoke-tested at release time. Issues
filed and prioritised but not release-blocking.

### Admin console

| Runtime | Minimum version |
|---------|----------------|
| Node.js | ≥ 20.19.0 LTS |
| npm     | ≥ 10           |

Supported browsers (Playwright-validated on each release):
- Chromium / Chrome ≥ 120
- Safari / WebKit ≥ 17
- Firefox ≥ 120

### SDK

| SDK | Minimum runtime |
|-----|----------------|
| TypeScript / Node.js | Node.js ≥ 20.19.0 |
| Python | CPython ≥ 3.11 |

## Support Window

| Series | Release date | Security patches until |
|--------|-------------|------------------------|
| 1.x (current) | 2026-05-05 | At least 12 months after 2.0 GA |

When a new major version ships, the previous major series receives security
patches for at least 12 months. Feature development concentrates on the
current major series.

## API Stability

The public HTTP API is versioned via the OpenAPI document shipped in
`docs/openapi.yaml`. From v1.0 onward:

- **Backwards-compatible additions** (new optional fields, new endpoints) are
  made in minor releases without bumping the major version.
- **Breaking changes** (endpoint removal, required-field additions, response
  schema changes) require a new major version (2.0).
- Fields or endpoints scheduled for removal are marked `deprecated: true` in
  the OpenAPI document at least one full minor-release cycle before removal.

See `docs/DEPRECATION_POLICY.md` for the full deprecation lifecycle.

## Configuration Compatibility

TOML configuration keys are treated as a public API from v1.0. Renamed or
removed keys are documented in the CHANGELOG with a migration note and
deprecated in the prior minor release where possible.

## Database / Schema Compatibility

SQLite schema migrations are additive in minor releases. Forward migrations are
applied automatically on server start. Downgrading to an older binary after a
schema migration requires restoring a backup made on the older version — see
`docs/DISASTER_RECOVERY.md`.

ClickHouse DDL (events table, materialized views) is managed separately. The
`wardex storage migrate` sub-command applies schema updates and documents the
changes in `docs/SCHEMA_LIFECYCLE.md`.
