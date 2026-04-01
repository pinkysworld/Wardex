# ADR 0006: raw normalized derived storage layers

- Status: Proposed
- Date: 2026-04-01

## Context
The system must support forensic replay, schema evolution, and efficient analyst workflows.

## Decision
Keep raw immutable data, canonical normalized data, and derived search or graph views as separate logical layers with explicit lineage.

## Consequences
This increases storage and pipeline complexity but preserves replayability and schema integrity.

## Follow-up
- Revisit this ADR when the corresponding implementation phase begins.
- Update affected docs and architecture diagrams if this ADR changes.
