# Wardex Contract And State Spine

Wardex should continue to harden around two architecture facts:

- API behavior is already governed by runtime route classification, OpenAPI metadata, SDK parity, and release acceptance.
- Server state is still concentrated in `AppState`, while the codebase has started to identify bounded contexts such as auth, fleet, collectors, SOC operations, detection, and governance.

This document fixes the next decisions so the project can evolve without a risky server rewrite.

## Contract Spine Decisions

1. `Cargo.toml` remains the release/version source of truth.
2. `src/server_routing.rs` remains the runtime auth-class source until a Rust route manifest replaces ad hoc catalogs.
3. Every public API route must have:
   - one route owner in `docs/architecture/contract_state_spine.json`,
   - runtime auth classification in `ApiRouteAccess`,
   - `x-wardex-auth` in `docs/openapi.yaml`,
   - OpenAPI operation metadata,
   - SDK/frontend helper coverage when the route is operator-facing.
4. Production OpenAPI exposure is explicit. The API can still be public in developer mode, but production exposure is controlled by `server.openapi_public` or `WARDEX_OPENAPI_PUBLIC`.
5. Deprecation remains metadata-first: deprecated routes need `x-wardex-deprecated-since`, `x-wardex-sunset`, and `x-wardex-replacement`, plus runtime deprecation headers.

## State Ownership Decisions

`AppState` remains the compatibility shell during `v1.0.x`. The next decomposition should not start by moving route files around. It should start by moving ownership boundaries into stable state shards and guardrails:

1. `platform_identity`
   Owns auth, RBAC, sessions, identity providers, feature flags, config, and route discovery.
2. `fleet_control`
   Owns agent enrollment, heartbeat/update flows, policy distribution, remote installs, and fleet inventory.
3. `telemetry_connectors`
   Owns event ingestion, connectors, feed ingestion, websocket/stream posture, and live telemetry buffers.
4. `detection_intelligence`
   Owns detection engines, alert scoring, malware/threat-intel enrichment, replay, and detection quality.
5. `soc_operations`
   Owns queue, cases, incidents, response, remediation, playbooks, investigations, workbench, tickets, and reports.
6. `governance_reliability`
   Owns tenancy, compliance, release readiness, backups, support evidence, cluster/control-plane reliability, secrets, and host operations.

The migration order should be:

1. Route-owner guardrail
2. Critical contract fields in parity checks
3. Domain-labelled `tracked_lock` coverage on hot routes
4. Shard structs inside `AppState`
5. One lock per shard
6. Bounded-context route modules

## Guardrail

Run:

```bash
python3 scripts/check_architecture_guardrails.py
```

The guardrail validates that:

- every documented OpenAPI path maps to exactly one route domain,
- every runtime `/api/...` path in `src/server.rs` is either documented in
  OpenAPI or explicitly listed as an internal/compatibility exception in
  `docs/architecture/contract_state_spine.json`,
- `x-wardex-auth` values match runtime `ApiRouteAccess` classes,
- every declared state anchor still exists in `AppState`,
- state migration order covers every domain,
- release-blocking stability tests stay wired into both CI and the tag release
  preflight.

The current internal/compatibility route list is intentionally explicit rather
than implicit. New operator-facing routes should graduate into OpenAPI and SDK
or admin-console helpers before they are called stable public API.

Release-blocking stability gates:

```bash
cargo test --test api_integration
cargo test --test concurrent_smoke
cargo test --test failed_auth_lockout
```

`concurrent_smoke` also enforces the state-lock release SLO: the server must keep
exporting tracked-lock wait metrics and `wardex_state_lock_poisoned_total` must
remain `0` under concurrent health/status/metrics load.
