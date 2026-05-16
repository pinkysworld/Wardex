# Wardex XDR — Professional Roadmap

## Current release baseline

`v1.0.20` is the current stable patch release of Wardex. It carries all capabilities of `v1.0.0`, the `v1.0.1` CI hardening fixes, the `v1.0.2` macOS release-trust hardening, the Live Monitor process-analysis regression coverage, the refreshed Developer ID `.p12` signing-secret repair path, the `v1.0.6` resilience/proof tranche, the `v1.0.7` production assurance tranche, the `v1.0.8` release verification/deployment-confidence tranche, the evidence freshness tranche, the `v1.0.10` detection response and malware-scanning polish, the `v1.0.11` CI/release-trust hotfix, the `v1.0.12` operator-trust usability tranche, the `v1.0.13` detection-trust false-positive control tranche, the `v1.0.14` Claude workbench layout tranche, the `v1.0.15` operator onboarding/workflow-depth tranche, the `v1.0.16` operator execution-board tranche, the `v1.0.17` operator continuity/evidence-closure tranche, the `v1.0.18` intelligence-gates tranche, the `v1.0.19` operator-trust continuity tranche, and the `v1.0.20` priority-lane/API-hardening tranche.

The current release adds cross-workspace priority lanes for Dashboard, Fleet, Infrastructure, NDR, UEBA, and SOC; concise focus narratives for lead alerts, endpoint drift, asset exposure, remediation backlog, network anomalies, and entity-risk escalations; authenticated-by-default backend API route classification; and Node/npm dependency hardening in the release baseline. It preserves route-state Live Monitor continuity, Command Center collector lifecycle proof, inline detection promotion blockers, SOC approval/escalation/trace visibility, Response Safety execution-audit continuity, operator-safe triage decision support, assistant quality gates, notification outbox records, canonical Launchpad journeys, evidence-mode rollups, deeper macOS vmmap memory indicators, shift handoff workspace, incident timeline builder, collector onboarding center, release acceptance report, fleet risk heatmap, response playbook simulator depth, evidence coverage, role home screen, visual regression gate, safe assistant boundaries, persistent Connect Agent route, Launchpad morning brief, guided incident path, fleet drilldown, evidence freshness rollup, operator task queue, release gate automation, first-agent onboarding cockpit, SOC explainability, response readiness, process evidence render caps, deployment confidence matrix, Detection Trust scoring, grouped navigation, role workspaces, Detection Lab validation, Response Safety previews, Integrations marketplace summaries, Operations Health SLOs, Malware verdict explanations, release preflight gating, evidence freshness metadata, Launchpad proof badges, release verification evidence, and validation-pack inventory checks shipped in prior releases.

`v1.0.12` added the operator-trust and usability tranche with grouped console navigation, role workspaces, command-palette access to major workflows, Detection Lab validation, Response Safety previews, Integrations marketplace summaries, Operations Health SLOs, Malware verdict explanations, alert feedback summaries, evidence-chain APIs, opt-in signature presets, and scan diffing.

`v1.0.11` added the CI and release-trust hotfix that gates signed-build packaging on Rust formatting, Clippy, admin-console linting, admin-console formatting, admin-console build, and release-doc validation.

`v1.0.10` added the detection response and malware-scanning tranche for source-aware alert analysis, IP/hostname enrichment, alarm-specific response actions, malware/virus/trojan/rootkit scan workflows, open-source signature presets, responsive thread investigation pullouts, live-monitor scroll preservation, and admin-console layout polish.

`v1.0.8` added the release verification/deployment-confidence tranche for clean release cuts, container parity, verification center evidence, self-hosted install plans, data-quality SLOs, scale gates, failover execution, secrets rotation, operator task automation, and detection validation packs.

`v1.0.7` added the production assurance tranche for release provenance, upgrade rehearsal, synthetic console monitoring, incident replay, detection trust, fleet drift, operator queues, retention forecasting, adversarial validation, and support bundle diffing.

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
- Detection Engineering, collector health, and infrastructure malware/remediation routes are now covered by deterministic browser checks and the live release-gate smoke. Rule promotion also has server-side preflight proof for stream, replay, suppression, and content-pack ownership before canary/active changes. The remaining work is keeping that live coverage aligned as those workflows continue to evolve.
- Production assurance now has first-class route coverage for provenance, upgrade rehearsal, synthetic console health, incident replay, detection trust, fleet drift, operator queues, retention forecast, adversarial validation, support bundle diffs, clean release cuts, container parity, release verification, deployment wizard state, data quality, scale baselines, failover execution, secrets rotation, operator task automation, and validation packs. The next gap is keeping those assurance signals backed by real environment-specific evidence as deployments scale.
- Malware analysis and infrastructure remediation now have route-aware verdict, integrity, exposure, and observability workflows, guided-remediation, signed multi-approver change reviews, approval-chain digests, rollback proof, remediation-module-backed dry-run rollback verification, opt-in live rollback execution, recovery-history views, dedicated regression coverage for route-backed assets explorer state, grouped asset refresh, deep malware scan execution, asset-to-exposure pivots, observability scope restoration, and Linux/macOS/Windows rollback-recording paths, plus matching-platform true execution coverage for restore-file, kill-process, restart-service, block-ip, remove-persistence, disable-account, and flush-dns actions when operators also enable `remediation.execute_live_rollback_commands`. The next gap is keeping those safeguards, regressions, and operator-facing workflows aligned as additional adapters are introduced.

## Remaining closure checklist

- [x] Detection content operations: shipped the rollout-history and distribution analytics tranche so the console now reaches a full canary/promote/distribute lifecycle with stronger operator-facing evidence.
- [x] Control-plane posture: extend the shipped runtime evidence and automated drill coverage into non-standalone failover workflows so standby or leader-handoff state and persisted drill evidence are visible in the operator contracts.
- [ ] Feature-usability maintenance: keep the shipped routed workflows and regression contracts aligned across Detection, Command Center, SOC Workbench, analytics, auth, collectors, long-retention, support, live monitoring, fleet, and remediation as surrounding detail evolves.

## Ranked closure order

1. Usability maintenance and regression alignment across shipped routed workflows.

## Success criteria

| Metric | Current (`v1.0.20`) | Target |
|---|---|---|
| Automated tests | 1503 lib + 239 integration + focused browser/admin regressions | maintained and expanded on every release |
| OpenAPI and SDK contract | versioned OpenAPI plus generated Python and TypeScript SDKs | kept in lockstep on every release |
| Release targets | Linux, macOS, Windows | maintained on every tagged release |
| Control-plane posture | private-cloud enterprise deployment | HA-ready, recovery-safe enterprise deployment |
| Production hardening | 100% (59/59) plus freshness-gated release evidence | maintain 100% while adding features |
| Feature usability | many advanced capabilities surfaced, several still shallow | every shipped feature routed, structured, and operator-usable |
| Detection content operations | full canary/promote/distribute lifecycle with stronger analytics | maintain routed lifecycle evidence, distribution analytics, and regression coverage as workflows evolve |
