# XDR Execution Plan

## Goal
Build a production-grade XDR platform with SIEM integration and phased support for:
- Windows / Windows Server
- macOS
- Linux
- later Unix compatibility collectors

## Non-goals for v1
- full parity on niche Unix platforms
- autonomous remediation without guardrails
- unsupported claims of AI-only detection
- replacing every SIEM workflow

## Product pillars
1. Reliable telemetry collection
2. Accurate normalized data model
3. High-confidence detections
4. Safe and auditable response actions
5. Strong SIEM interoperability
6. Multi-tenant secure control plane
7. Production hardening and compliance
8. Differentiated analyst experience

## Phase order
0. Repo bootstrap and architecture baseline
1. Control plane and identity foundation
2. Telemetry ingest and canonical event model
3. Cross-platform agent core
4. Windows collector
5. Linux collector
6. macOS collector
7. Detection engine and content pipeline
8. SIEM integrations
9. Response orchestration
10. Investigation UI and analyst workflows
11. Production hardening, SRE, compliance
12. Differentiated features and GA readiness

## Mandatory constraints
- Every phase must leave the repo runnable
- Every phase must include tests
- Every phase must update docs
- Every phase must define what is deferred
- No phase may silently expand scope

## Quality gates
- build passes
- tests pass
- lint passes
- security checks pass where relevant
- API/schema docs updated
- architecture docs updated

## Completion policy
A phase is complete only when:
- acceptance criteria are explicitly checked off
- commands to reproduce the result are listed
- gaps and deferred items are listed
- docs and ADRs are updated if architecture changed

## Expected outputs per phase
- implementation plan
- files changed summary
- tests added or updated
- exact build, lint, and test commands
- acceptance criteria checklist
- unresolved risks and next steps
