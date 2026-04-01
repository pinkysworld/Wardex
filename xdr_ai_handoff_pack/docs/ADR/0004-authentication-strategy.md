# ADR 0004: authentication strategy

- Status: Accepted
- Date: 2026-04-01

## Context
The platform must support users, service accounts, and enrolled devices across multiple tenants with auditable access.

## Decision
Use a layered identity model: SSO-ready user auth, scoped API tokens/service accounts, and device enrollment leading to mTLS-based operational communication. Enforce tenant-aware authorization at every API boundary.

## Consequences
This creates a strong security foundation but adds operational complexity around certificate lifecycle and revocation.

## Follow-up
- Revisit this ADR when the corresponding implementation phase begins.
- Update affected docs and architecture diagrams if this ADR changes.
