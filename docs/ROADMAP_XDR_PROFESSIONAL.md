# Wardex XDR — Professional Roadmap

## Current release baseline

`v1.0.3` is the current stable patch release of Wardex. It carries all capabilities of `v1.0.0`, the `v1.0.1` CI hardening fixes, the `v1.0.2` macOS release-trust hardening, and the follow-up release CI plus Live Monitor process-analysis regression coverage.

`v1.0.0` is the first stable release of Wardex, delivering a production-hardened private-cloud XDR and SIEM platform with full operator-usable UI for every shipped capability, HA-ready control-plane posture, and AGPL-3.0 open-source licensing.

`v0.56.2` delivered the private-cloud XDR and SIEM control-plane baseline that `v1.0.0` graduates from:

- SOC Workbench for queue, cases, investigations, guided workflows, response approvals, escalation management, and incident-first case/incident drawers
- Product Command Center for incidents, cases, connector gaps, remediation approvals, rule tuning debt, release readiness, and compliance evidence packs with inline action drawers
- Analyst Assistant for case-aware questions, citations, ticket-sync pivots, and investigation-scope handoffs inside analyst workflows
- detection engineering with hunts, rule lifecycle, suppressions, content packs, efficacy tracking, MITRE coverage, replay-corpus promotion gates, and replay drift breakdowns by platform and signal family
- explainable detections, entity-centric scoring, campaign correlation, model-registry status, analyst feedback capture, and readiness-driven onboarding
- UEBA, NDR, attack-graph, vulnerability, malware, certificate, and drift-analysis surfaces with threat-intel `v2` metadata, sightings, and deep malware scan profiles
- unified asset inventory, fleet release operations, rollout history, and per-agent activity context
- enterprise controls for RBAC, SCIM, OIDC/SAML SSO, session management, audit, retention, diagnostics, and routed collector/secrets readiness workflows, including GitHub Audit Log, CrowdStrike Falcon, and Generic Syslog planned onboarding lanes
- control-plane posture evidence for active/passive reference deployments, including backup cadence, latest backup/checkpoint artifacts, and restore readiness surfaced in Help & Docs plus support-readiness and dependency-health APIs
- route-auth contract parity across runtime enforcement, OpenAPI `x-wardex-auth`, endpoint catalog metadata, and static contract checks, plus signed agent update trust with next-ring auto-progress verification
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

- Control-plane posture now surfaces active/passive reference status, backup cadence, observed backups, latest restore artifacts, restore readiness, non-standalone standby or leader-handoff state, and persisted automated failover drill history through Help & Docs plus support/readiness and dependency-health contracts. The next gap is keeping those recovery contracts aligned as deeper clustering and runtime failover execution evolve.
- Threat Detection now ships URL-backed efficacy, ATT&CK gap, suppression-noise, pack-rollout, replay-corpus, hunt-investigation workflows, operator-visible canary auto-promotion, rollout-history evidence, lifecycle distribution analytics, and refreshed promotion evidence in one routed workspace, with focused regression coverage locking in those route contracts and reload paths. The next gap is keeping those routed detection workflows and lifecycle analytics aligned as rule detail evolves.
- Command Center now includes dedicated regression coverage for route-restored remediation, connector, rule, release, and evidence drawers plus drawer-triggered actions, reload behavior, and Settings/Infrastructure/Detection/Reports handoffs. The next gap is keeping those command workflows and lane contracts aligned as drawer detail evolves.
- SOC Workbench now includes dedicated regression coverage for route-backed queue filters, focused case workspaces, URL-addressable incident and case drawers, ticket sync, investigation progress and handoff, response handoff context, grouped response refresh, escalation acknowledge/create/test flows, playbooks-tab restore/run coverage, grouped process-tree refresh, and RBAC refresh/remove plus the campaigns pivot. The next gap is keeping those SOC triage, response, admin, and process workflows aligned as approval detail and operator context evolve.
- UEBA, NDR, and Attack Graph now include dedicated regression coverage for route-seeded entity playbooks, route-aware network narratives, stored-event campaign clustering, temporal-chain drilldowns, and graph-to-SOC/UEBA/NDR/report handoffs. The next gap is keeping those analytics regressions and operator-facing narratives aligned as evidence correlation deepens.
- Federated SSO launch and callback validation now includes provider launch checks for metadata, callback route alignment, client credentials, group mappings, test-login paths, routed Settings launch-path assertions, stale-token session recovery fallback, unauthenticated-shell SSO coherence, and auth-shell provider-launch redirect coverage that preserves hash-backed return paths while stripping transient callback errors. The next gap is keeping those routed and auth-shell regressions aligned as providers evolve.
- Collector routing, readiness, and validation dashboards now include staged ingestion-health timelines, persisted lifecycle history, last-success/error checkpoints, retry/backoff context, freshness, failure-streak analytics, ingestion evidence, and cross-surface SOC/Infrastructure pivots across the shipped cloud, identity, SaaS, EDR, and syslog lanes, with routed browser coverage locking in those pivots and lifecycle details from the Settings integrations surface. The next gap is keeping those routed regressions and operator-facing lifecycle details aligned as provider workflows evolve.
- ClickHouse-backed long-retention search and retention controls now include routed pivots from SOC Workbench rollout context, Threat Detection retained-event replay context, and Reports & Exports retention workflows back into `Long-Retention History`, plus focused regression coverage for seeded retained-event search refresh and Settings admin-tab recovery. The next gap is keeping those analyst handoffs and operator-facing long-retention workflows aligned as surrounding routes evolve.
- Help & Docs support now includes dedicated regression coverage for route-restored contextual scope, docs filters, selected documents, GraphQL sample state, API explorer filters, and routed runbook pivots that preserve carried operator scope. The next gap is keeping those routed support workflows and embedded guidance contracts aligned as runtime, SDK, and documentation content evolve.
- Live Monitor now includes dedicated regression coverage for route-restored monitor tabs, selected alert drawer state, carried queue filters, and preserved scope across tab and drawer transitions. The next gap is keeping those routed monitoring workflows and live-transport affordances aligned as stream detail, process context, and analyst actions evolve.
- Fleet & Agents now includes dedicated regression coverage for route-restored rollout and recovery focus plus carried offline-scope pivots back into filtered agent inventory. The next gap is keeping those routed rollout, recovery, and deployment-health workflows aligned as live release telemetry expands.
- Detection Engineering, collector health, and infrastructure malware/remediation routes are now covered by deterministic browser checks and the live release-gate smoke. The remaining work is keeping that live coverage aligned as those workflows continue to evolve.
- Malware analysis and infrastructure remediation now have route-aware verdict, integrity, exposure, and observability workflows, guided-remediation, signed multi-approver change reviews, approval-chain digests, rollback proof, remediation-module-backed dry-run rollback verification, opt-in live rollback execution, recovery-history views, dedicated regression coverage for route-backed assets explorer state, grouped asset refresh, deep malware scan execution, asset-to-exposure pivots, observability scope restoration, and Linux/macOS/Windows rollback-recording paths, plus matching-platform true execution coverage for restore-file, kill-process, restart-service, block-ip, remove-persistence, disable-account, and flush-dns actions when operators also enable `remediation.execute_live_rollback_commands`. The next gap is keeping those safeguards, regressions, and operator-facing workflows aligned as additional adapters are introduced.

## Remaining closure checklist

- [x] Detection content operations: shipped the rollout-history and distribution analytics tranche so the console now reaches a full canary/promote/distribute lifecycle with stronger operator-facing evidence.
- [x] Control-plane posture: extend the shipped runtime evidence and automated drill coverage into non-standalone failover workflows so standby or leader-handoff state and persisted drill evidence are visible in the operator contracts.
- [ ] Feature-usability maintenance: keep the shipped routed workflows and regression contracts aligned across Detection, Command Center, SOC Workbench, analytics, auth, collectors, long-retention, support, live monitoring, fleet, and remediation as surrounding detail evolves.

## Ranked closure order

1. Usability maintenance and regression alignment across shipped routed workflows.

## Success criteria

| Metric | Current (`v1.0.3`) | Target |
|---|---|---|
| Automated tests | 1413 lib + 212+ integration + focused browser/admin regressions | maintained and expanded on every release |
| OpenAPI and SDK contract | versioned OpenAPI plus generated Python and TypeScript SDKs | kept in lockstep on every release |
| Release targets | Linux, macOS, Windows | maintained on every tagged release |
| Control-plane posture | private-cloud enterprise deployment | HA-ready, recovery-safe enterprise deployment |
| Production hardening | 100% (59/59) | maintain 100% while adding features |
| Feature usability | many advanced capabilities surfaced, several still shallow | every shipped feature routed, structured, and operator-usable |
| Detection content operations | full canary/promote/distribute lifecycle with stronger analytics | maintain routed lifecycle evidence, distribution analytics, and regression coverage as workflows evolve |
