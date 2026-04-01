# ADR 0005: os support tiers

- Status: Accepted
- Date: 2026-04-01

## Context
Marketing pressure may encourage broad OS claims, but telemetry depth differs significantly across platforms.

## Decision
Define Tier 1 full-fidelity support for Windows, Windows Server, major Linux distributions, and macOS. Treat niche Unix systems as reduced-fidelity compatibility targets in early releases.

## Consequences
This keeps delivery realistic and reduces support risk, but requires clear messaging on capability differences.

## Follow-up
- Revisit this ADR when the corresponding implementation phase begins.
- Update affected docs and architecture diagrams if this ADR changes.
