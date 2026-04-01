# ADR 0011: multi tenant deployment model

- Status: Proposed
- Date: 2026-04-01

## Context
The product targets SaaS delivery first but must preserve a path for regulated or single-tenant customers.

## Decision
Optimize the architecture for multi-tenant SaaS with strong isolation and regional deployment controls, while keeping interfaces clean enough to support later single-tenant or relay-based deployment models.

## Consequences
This speeds delivery, though some later deployment variants may require refactoring if not anticipated carefully.

## Follow-up
- Revisit this ADR when the corresponding implementation phase begins.
- Update affected docs and architecture diagrams if this ADR changes.
