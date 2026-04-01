# ADR 0002: canonical event model

- Status: Accepted
- Date: 2026-04-01

## Context
The product must normalize telemetry from multiple operating systems and export to multiple SIEM schemas without becoming tightly coupled to a single vendor.

## Decision
Adopt an OCSF-aligned canonical event model internally. Maintain raw immutable events and derived investigation-friendly views separately from canonical normalized records.

## Consequences
This improves portability, replay, and forensic integrity. It adds schema governance overhead and requires careful versioning.

## Follow-up
- Revisit this ADR when the corresponding implementation phase begins.
- Update affected docs and architecture diagrams if this ADR changes.
