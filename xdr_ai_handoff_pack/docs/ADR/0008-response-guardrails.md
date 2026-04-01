# ADR 0008: response guardrails

- Status: Proposed
- Date: 2026-04-01

## Context
Response actions can disrupt production systems if executed unsafely.

## Decision
Require approvals, dry-run capability, protected asset tagging, immutable audits, and policy-based restrictions for destructive or high-blast-radius actions.

## Consequences
This reduces operator risk but adds workflow complexity and may slow urgent response if poorly designed.

## Follow-up
- Revisit this ADR when the corresponding implementation phase begins.
- Update affected docs and architecture diagrams if this ADR changes.
