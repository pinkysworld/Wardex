# Wardex Deprecation Policy

This policy applies to the public HTTP API (OpenAPI), CLI commands, TOML
configuration keys, and the TypeScript and Python SDK interfaces from v1.0
onward.

## Principles

- Deprecation is a promise to users that a change is coming, not a surprise
  removal.
- Every deprecated item is given a **minimum sunset window** before it is
  removed.
- Deprecation notices appear in: the OpenAPI document, the CHANGELOG, the
  release notes, and (where applicable) runtime warning logs.

## Sunset Windows

| Item type | Minimum deprecation notice | Earliest removal |
|-----------|--------------------------|-----------------|
| HTTP endpoint | 1 minor release (≥ 3 months) | Next major version |
| Response/request field | 1 minor release (≥ 3 months) | Next major version |
| CLI flag or sub-command | 1 minor release (≥ 3 months) | Next major version |
| TOML configuration key | 1 minor release (≥ 3 months) | Next major version |
| SDK method or type | 1 minor release (≥ 3 months) | Next major version |

A deprecated item is never removed in the same release in which it is first
marked deprecated.

## Deprecation Lifecycle

```
Active → Deprecated → Removed
            │
            └─ Warning logged at runtime (endpoints)
            └─ @deprecated JSDoc / Python DeprecationWarning
            └─ OpenAPI deprecated: true
            └─ CHANGELOG entry
```

### Marking an endpoint deprecated

In `docs/openapi.yaml`, add `deprecated: true` to the operation:

```yaml
/api/v1/old-endpoint:
  get:
    deprecated: true
    description: |
      **Deprecated since v1.2. Use `/api/v1/new-endpoint` instead.**
      Will be removed in v2.0.
```

### Marking a TOML key deprecated

In `src/config.rs`, add a `#[deprecated]` attribute or a log warning when the
key is read, directing operators to the replacement key.

## Versioning and Breaking Changes

Breaking changes are only permitted in a **major version bump** (1.x → 2.0).
A change is considered breaking if it:

- Removes or renames a previously documented API endpoint, field, or CLI flag.
- Changes the semantics of an existing field in a way that breaks existing
  client code without modification.
- Raises the MSRV by more than one stable release without a prior minor-release
  notice.

**Additive changes** (new optional fields, new endpoints, new CLI flags) are
not breaking and may appear in minor releases.

## Experimental Features

Features that are not yet stable may be marked `x-stability: experimental` in
the OpenAPI document. Experimental features are exempt from the sunset window
guarantee until promoted to stable. Promotion from experimental to stable is
announced in the CHANGELOG.

From v1.0 onward, all shipped features are considered stable unless explicitly
marked experimental in the OpenAPI or documentation.

## Communication Channels

Deprecation announcements are published in:

1. The GitHub release notes for the release that introduces the deprecation.
2. The `CHANGELOG.md` file under the relevant version heading.
3. The `docs/openapi.yaml` document (`deprecated: true` + description update).
4. A pinned GitHub issue tagged `deprecation` that lists all active deprecations
   and their planned removal versions.
