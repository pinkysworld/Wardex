Phase 2: Telemetry ingest and canonical event model.

Read AGENTS.md and docs/EXECUTION_PLAN.md first.

Implement the ingest path and internal canonical event model:
- ingest gateway service
- authenticated telemetry ingestion endpoint
- local buffering/replay contract
- raw event storage
- normalized event storage
- schema registry/versioning approach
- OCSF-aligned canonical event definitions for:
  - process events
  - file events
  - network events
  - DNS events
  - auth/session events
  - configuration/persistence events
- event validation
- dead-letter handling
- idempotency and replay protection
- retention policy scaffolding

Deliverables:
- backend/gateway
- backend/event-normalizer
- schemas under docs/schemas/
- sample event fixtures
- replay and parser tests
- docs for event flow and schema lifecycle

Acceptance criteria:
- sample events can be ingested, validated, normalized, and queried
- malformed events are rejected or dead-lettered correctly
- schema versioning rules are documented and tested
- every canonical event type has examples

Do not build detection logic yet beyond stub interfaces.
