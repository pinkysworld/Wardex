# Project guidance

This repository builds a production-grade XDR platform with SIEM integration.

## Product scope
The system must support:
- Windows 10/11
- Windows Server 2019/2022/2025
- macOS (current -2 major versions)
- Linux (Ubuntu LTS, Debian, RHEL, SUSE, Amazon Linux)
- Reduced-fidelity Unix compatibility collectors later (FreeBSD, AIX, Solaris/Illumos)

## Architecture principles
- Shared cross-platform agent core in Rust
- OS-specific collectors per platform
- Backend services are modular and API-first
- Internal event model is OCSF-aligned
- Telemetry transport should be OpenTelemetry-compatible where practical
- Detections are Sigma-authored and ATT&CK-mapped where possible
- Threat intel exchange should support STIX/TAXII later
- Every security-sensitive action must be auditable

## Engineering rules
- Use ADRs for major design decisions
- No hidden breaking changes
- Every feature must include tests
- Every service must expose health endpoints
- Every API must have OpenAPI specs
- Every schema change must have a migration plan
- Prefer explicit interfaces over magic
- Prefer idempotent operations
- Prefer feature flags for risky capabilities
- Do not claim "production-ready" unless the acceptance criteria for the phase are met

## Repo workflow
- Work one phase at a time
- At the start of each phase, read:
  - AGENTS.md
  - docs/EXECUTION_PLAN.md
  - docs/ARCHITECTURE.md
  - relevant ADRs
- At the end of each phase:
  - update docs
  - update architecture diagrams if needed
  - summarize what changed
  - list unresolved risks
  - list exact commands to verify the phase

## Definition of done
A task is done only when:
- code builds
- tests pass
- lint passes
- docs are updated
- acceptance criteria are explicitly checked off
- known risks and deferred items are documented

## Safety rails
- Do not auto-implement destructive response actions without approval gates
- Do not weaken authentication or transport security for convenience
- Do not store secrets in source control
- Do not add telemetry collection that violates least-privilege without documenting justification
- Do not collect raw sensitive content when metadata is sufficient

## Output format for each phase
Always provide:
1. Plan
2. Files changed
3. Code changes summary
4. Tests added/updated
5. Commands to run
6. Acceptance criteria status
7. Risks / next steps
