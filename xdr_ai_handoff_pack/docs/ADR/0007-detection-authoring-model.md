# ADR 0007: detection authoring model

- Status: Proposed
- Date: 2026-04-01

## Context
Detection content must be portable, testable, and explainable to analysts and customers.

## Decision
Use Sigma as the authoring front door where practical, compile or translate it to internal execution formats, and attach ATT&CK metadata, prerequisites, and false-positive notes to every rule.

## Consequences
This improves content portability but requires an internal translation and validation pipeline.

## Follow-up
- Revisit this ADR when the corresponding implementation phase begins.
- Update affected docs and architecture diagrams if this ADR changes.
