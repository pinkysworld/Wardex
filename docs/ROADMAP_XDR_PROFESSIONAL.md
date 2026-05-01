# Wardex XDR — Professional Roadmap

## Current release baseline

`v0.55.1` delivers the current private-cloud XDR and SIEM control-plane baseline:

- SOC Workbench for queue, cases, investigations, guided workflows, response approvals, escalation management, and incident-first case/incident drawers
- Product Command Center for incidents, cases, connector gaps, remediation approvals, rule tuning debt, release readiness, and compliance evidence packs with inline action drawers
- Analyst Assistant for case-aware questions, citations, ticket-sync pivots, and investigation-scope handoffs inside analyst workflows
- detection engineering with hunts, rule lifecycle, suppressions, content packs, efficacy tracking, MITRE coverage, replay-corpus promotion gates, and replay drift breakdowns by platform and signal family
- explainable detections, entity-centric scoring, campaign correlation, model-registry status, analyst feedback capture, and readiness-driven onboarding
- UEBA, NDR, attack-graph, vulnerability, malware, certificate, and drift-analysis surfaces with threat-intel `v2` metadata, sightings, and deep malware scan profiles
- unified asset inventory, fleet release operations, rollout history, and per-agent activity context
- enterprise controls for RBAC, SCIM, OIDC/SAML SSO, session management, audit, retention, diagnostics, and routed collector/secrets readiness workflows, including GitHub Audit Log, CrowdStrike Falcon, and Generic Syslog planned onboarding lanes
- authenticated WebSocket event streaming, ClickHouse-backed long-retention integration foundations, and execution-context-aware reporting across reports, runs, schedules, templates, stored artifacts, persisted exports, and response-approval snapshots
- hardened release operations with Node 22 CI alignment, release-asset checksums, package install smoke coverage, strict a11y gates, and shared request-ID generation

## Next priorities

### Operator workflow completion

| Priority | Outcome | Status |
|---|---|---|
| Console parity program | every shipped capability has a reachable, structured UI and no broken JSON-only dead ends | Shipped |
| Analyst workflow depth | stronger investigation planner, active-investigation tracking, and realtime analyst ergonomics | Shipped |
| Dashboard customization | persisted analyst/admin layouts, presets, and shared operational views | Shipped |
| Security policy usability | working advanced-control workflows for policy compose, twin simulate, harness, deception, and enforcement | Shipped |

### Platform scale and integrations

| Priority | Outcome | Status |
|---|---|---|
| Durable event storage | historical hunts, long-range investigations, and manager reporting at scale | Shipped |
| Cloud, SaaS, and identity collectors | guided setup and health visibility for AWS, Azure, GCP, Entra/Okta, M365, Workspace, and analyst-driven ticketing workflows | Shipped |
| Secrets-manager integration | Vault and cloud-secret configuration with validation and runtime health visibility | Shipped |
| API and SDK parity | contract diagnostics, GraphQL/API explorer, and generated-SDK verification surfaces | Shipped |

### Documentation and release confidence

| Priority | Outcome | Status |
|---|---|---|
| Searchable docs site | versioned operator documentation with console-linked runbooks | Shipped |
| Browser workflow coverage | deterministic coverage for advanced analyst and admin paths | Shipped |
| Packaging breadth | package-manager distribution and install-path validation | Shipped |
| Release-document accuracy | backlog, status, roadmap, and support docs remain synchronized with shipped state | Shipped |

## Current gaps

- Federated SSO launch and callback validation now includes provider launch checks for metadata, callback route alignment, client credentials, group mappings, and test-login paths. The remaining work is regression depth as providers evolve.
- Collector routing, readiness, and validation dashboards now include staged ingestion-health timelines, persisted lifecycle history, last-success/error checkpoints, retry/backoff context, freshness, failure-streak analytics, ingestion evidence, and cross-surface SOC/Infrastructure pivots across the shipped cloud, identity, SaaS, EDR, and syslog lanes.
- Command Center, Detection Engineering, Fleet & Agents, SOC Workbench response, collector health, and infrastructure malware/remediation routes are now covered by deterministic browser checks and the live release-gate smoke. The remaining work is keeping that live coverage aligned as those workflows continue to evolve.
- Malware analysis and infrastructure remediation now have route-aware verdict, integrity, guided-remediation, signed multi-approver change reviews, approval-chain digests, rollback proof, remediation-module-backed dry-run rollback verification, opt-in live rollback execution, recovery-history views, focused regression coverage for Linux, macOS, and Windows rollback-recording paths, and local matching-platform execution for restore-file plus explicit kill-process rollback actions when operators also enable `remediation.execute_live_rollback_commands`. The next gap is broadening true adapter execution beyond those current local slices and extracting the remaining review-persistence glue out of `server.rs`.

## Success criteria

| Metric | Current (`v0.55.1`) | Target |
|---|---|---|
| Automated tests | 1413 lib + 212+ integration + focused browser/admin regressions | maintained and expanded on every release |
| OpenAPI and SDK contract | versioned OpenAPI plus generated Python and TypeScript SDKs | kept in lockstep on every release |
| Release targets | Linux, macOS, Windows | maintained on every tagged release |
| Control-plane posture | private-cloud enterprise deployment | HA-ready, recovery-safe enterprise deployment |
| Production hardening | 100% (59/59) | maintain 100% while adding features |
| Feature usability | many advanced capabilities surfaced, several still shallow | every shipped feature routed, structured, and operator-usable |
| Detection content operations | hunts, rules, suppressions, packs, coverage views | full canary/promote/distribute lifecycle with stronger analytics |
