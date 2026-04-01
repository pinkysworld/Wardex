# ADR 0001: language runtime split

- Status: Accepted
- Date: 2026-04-01

## Context
The platform spans endpoint code, backend services, integration code, and UI. The endpoint agent needs memory safety, portability, and efficient packaging across Windows, macOS, and Linux.

## Decision
Use Rust for the shared agent core and OS-specific collectors. Allow backend services to use a service-oriented stack selected for delivery speed and operability, but require explicit interface contracts and OpenAPI documentation. Keep the UI as a separate web application.

## Consequences
This improves safety and cross-platform consistency for the agent while preserving flexibility on the backend. It increases polyglot complexity, so interface and build discipline are mandatory.

## Follow-up
- Revisit this ADR when the corresponding implementation phase begins.
- Update affected docs and architecture diagrams if this ADR changes.
