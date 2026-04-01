# Schema Lifecycle & Versioning

> T213 — Phase 27

## Overview

Every persistent structure and API contract in Wardex follows a strict
lifecycle so that agents, backends, and third-party integrations can evolve
independently without data loss or silent corruption.

## Versioning Strategy

| Layer | Scheme | Header / Field |
|-------|--------|---------------|
| REST API | URI prefix (`/api/v1/…`) when breaking | `X-API-Version` response header |
| Wire events | Embedded `schema_version` field (semver) | OCSF `metadata.version` |
| Config TOML | `schema_version` key at top level | — |
| Checkpoint files | CRC32 + version byte in header | — |
| Spool records | 1-byte format tag per envelope | — |

### Acceptable changes (patch / minor)

* Adding optional fields with defaults.
* Widening an enum with a new variant that old readers ignore.
* Adding a new API endpoint.

### Breaking changes (major)

* Removing or renaming a required field.
* Changing a field's type (e.g. `u32` → `String`).
* Removing an API endpoint or altering its semantics.

## Compatibility Rules

1. **Wire format**: Every serialized struct must round-trip through the
   *previous* schema version.  `serde(deny_unknown_fields)` is **not** used
   on inbound structs so that old agents can talk to a new backend.
2. **Config migration**: When `schema_version` in a TOML file is older than
   the binary, the server logs a warning and fills missing keys with defaults.
   It never silently drops keys.
3. **Checkpoint forward-compat**: Checkpoints written by version _N_ can be
   read by version _N+1_. A version _N+2_ binary that cannot parse an old
   checkpoint must emit a clear error and offer `--migrate-checkpoints`.

## Migration Process

```
1.  Bump schema_version in the relevant struct.
2.  Write a migration function: fn migrate_vN_to_vN1(old: Value) -> Value.
3.  Add a round-trip test: load fixtures/vN.json, migrate, assert.
4.  Document the change in CHANGELOG.md.
```

## Fixture Validation

The CI test `schema_roundtrip` loads every JSON fixture under
`tests/fixtures/` and verifies:

* Deserialization succeeds without unknown-field warnings.
* Re-serialization produces byte-identical output (canonical JSON).
* The `schema_version` field matches the expected value.

## Related ADRs

* **ADR-0002** — OCSF event schema adoption.
* **ADR-0006** — Spool format and encryption envelope.
