# ADR 0003: service boundaries

- Status: Accepted
- Date: 2026-04-01

## Context
The platform includes control plane, ingest, normalization, detection, response, integrations, and case management concerns. Over-centralization would slow independent iteration and increase blast radius.

## Decision
Split the backend into bounded services or modules for control plane, identity, gateway, event normalization, detection, response orchestration, integrations, and case/collaboration. Allow early monorepo co-location with clear API boundaries.

## Consequences
This improves isolation and ownership but requires stronger contract testing and observability.

## Follow-up
- Revisit this ADR when the corresponding implementation phase begins.
- Update affected docs and architecture diagrams if this ADR changes.
