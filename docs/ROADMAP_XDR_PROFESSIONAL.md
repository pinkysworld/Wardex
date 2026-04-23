# Wardex XDR — Professional Roadmap

## Current release baseline

`v0.53.3` delivers the current private-cloud XDR and SIEM control-plane baseline:

- SOC Workbench for queue, cases, investigations, guided workflows, response approvals, escalation management, and incident-first case/incident drawers
- Analyst Assistant for case-aware questions, citations, ticket-sync pivots, and investigation-scope handoffs inside analyst workflows
- detection engineering with hunts, rule lifecycle, suppressions, content packs, efficacy tracking, and MITRE coverage
- explainable detections, model-registry status, analyst feedback capture, and readiness-driven onboarding
- UEBA, NDR, attack-graph, vulnerability, malware, certificate, and drift-analysis surfaces with threat-intel `v2` metadata, sightings, and deep malware scan profiles
- unified asset inventory, fleet release operations, rollout history, and per-agent activity context
- enterprise controls for RBAC, SCIM, OIDC/SAML SSO, session management, audit, retention, and diagnostics
- authenticated WebSocket event streaming, ClickHouse-backed long-retention integration foundations, and execution-context-aware reporting across reports, runs, schedules, templates, stored artifacts, persisted exports, and response-approval snapshots

## Next priorities

### Operator workflow completion

| Priority | Outcome | Status |
|---|---|---|
| Console parity program | every shipped capability has a reachable, structured UI and no broken JSON-only dead ends | Near complete |
| Analyst workflow depth | stronger investigation planner, active-investigation tracking, and realtime analyst ergonomics | Shipped |
| Dashboard customization | persisted analyst/admin layouts, presets, and shared operational views | Shipped |
| Security policy usability | working advanced-control workflows for policy compose, twin simulate, harness, deception, and enforcement | Shipped |

### Platform scale and integrations

| Priority | Outcome | Status |
|---|---|---|
| Durable event storage | historical hunts, long-range investigations, and manager reporting at scale | Shipped |
| Cloud, SaaS, and identity collectors | guided setup and health visibility for AWS, Azure, GCP, Entra/Okta, M365, Workspace, and analyst-driven ticketing workflows | In progress |
| Secrets-manager integration | Vault and cloud-secret configuration with validation and runtime health visibility | Shipped |
| API and SDK parity | contract diagnostics, GraphQL/API explorer, and generated-SDK verification surfaces | Shipped |

### Documentation and release confidence

| Priority | Outcome | Status |
|---|---|---|
| Searchable docs site | versioned operator documentation with console-linked runbooks | Shipped |
| Browser workflow coverage | deterministic coverage for advanced analyst and admin paths | Shipped |
| Packaging breadth | package-manager distribution and install-path validation | Planned |
| Release-document accuracy | backlog, status, roadmap, and support docs remain synchronized with shipped state | In progress |

## Current gaps

- Full end-to-end federated SSO redirect and callback exchange remains incomplete; the shipped login shell now exposes configured providers, but provider discovery is ahead of full external IdP validation.
- Remaining SaaS and identity collector breadth still extends beyond the shipped cloud, secrets-manager, and case ticket-sync surfaces.
- UEBA, NDR, and infrastructure workflows still need deeper remediation and narrative drill-down closure.
- Entity-centric scoring and sequence/graph detection remain behind the new explainability and case-workspace layers.
- Malware analysis now has deeper API profiles, but the analyst-facing verdict workspace still needs the same end-to-end closure as reporting and cases.

## Success criteria

| Metric | Current (`v0.53.3`) | Target |
|---|---|---|
| Automated tests | 1272 lib + 190 integration + focused browser/admin regressions | maintained and expanded on every release |
| OpenAPI and SDK contract | versioned OpenAPI plus generated Python and TypeScript SDKs | kept in lockstep on every release |
| Release targets | Linux, macOS, Windows | maintained on every tagged release |
| Control-plane posture | private-cloud enterprise deployment | HA-ready, recovery-safe enterprise deployment |
| Production hardening | 100% (59/59) | maintain 100% while adding features |
| Feature usability | many advanced capabilities surfaced, several still shallow | every shipped feature routed, structured, and operator-usable |
| Detection content operations | hunts, rules, suppressions, packs, coverage views | full canary/promote/distribute lifecycle with stronger analytics |
