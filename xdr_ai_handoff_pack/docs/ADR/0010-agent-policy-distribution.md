# ADR 0010: agent policy distribution

- Status: Proposed
- Date: 2026-04-01

## Context
Agents need signed, versioned, rollback-safe policy updates across multiple environments and tenants.

## Decision
Adopt versioned policy bundles with signature verification, staged rollout support, local cache, and rollback markers.

## Consequences
This improves safety and auditability but requires signing and release workflows to be designed early.

## Follow-up
- Revisit this ADR when the corresponding implementation phase begins.
- Update affected docs and architecture diagrams if this ADR changes.
