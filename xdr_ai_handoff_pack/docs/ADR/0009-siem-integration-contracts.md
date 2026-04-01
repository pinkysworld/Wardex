# ADR 0009: siem integration contracts

- Status: Proposed
- Date: 2026-04-01

## Context
The product must integrate with multiple SIEM platforms while maintaining stable internal semantics.

## Decision
Treat integrations as explicit contracts with mapping fixtures, parser conformance tests, health telemetry, and versioned compatibility matrices.

## Consequences
This improves integration reliability but adds ongoing maintenance overhead for mapping changes.

## Follow-up
- Revisit this ADR when the corresponding implementation phase begins.
- Update affected docs and architecture diagrams if this ADR changes.
