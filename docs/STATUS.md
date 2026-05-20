# Wardex Status

## Current release

- **Version:** `1.0.23`
- **Positioning:** private-cloud XDR and SIEM platform with enterprise detection engineering, malware scanning, analyst workflows, fleet operations, behavioural analytics, and automated incident response
- **Source footprint:** 146 Rust source modules
- **API contract:** versioned OpenAPI surface with REST, GraphQL, live `/api/openapi.json` export, generated SDK parity diagnostics, authenticated-by-default API route classification, cursor page contracts, release observability/preflight proof APIs, production assurance endpoints, malware scan and response-action contracts, source-aware alert analysis, operator-trust workspaces, alert feedback/evidence-chain contracts, Detection Trust scoring and draft-only tuning APIs, detection validation lab APIs, response safety preview/verification APIs with execution-audit continuity, agent enrollment-token flows, connector marketplace summaries, operations health snapshots, and release verification readiness endpoints with evidence freshness metadata
- **Verification:** release preflight gating for Rust formatting, Clippy, admin-console linting, admin-console formatting, admin-console build, release-doc validation, workspace hygiene, and panic-policy compliance, plus Rust integration coverage, focused Detection Trust endpoint tests, session-cookie exchange tests, collector lifecycle tests, remediation change-review tests, Command Center summary/action-drawer tests, Help & Docs unit coverage, assistant/ticketing/enterprise API regression tests, operator trust workspace unit coverage, SDK regeneration checks, strict Playwright a11y smoke coverage, local Developer ID `.p12` signing validation, focused admin-console regression coverage, thread pullout regression coverage, managed release acceptance coverage, and Launchpad coverage for proof freshness badges and persisted snapshot evidence state
- **Production hardening:** 100% (59/59 controls implemented)

## Shipped in the current platform

### Deep OS-native monitoring

- Unified kernel-event stream normalising eBPF (Linux), ESF (macOS), and ETW (Windows) telemetry
- 22 event kinds: process lifecycle, file ops, network, registry, AMSI, WMI persistence, TCC, Gatekeeper, SELinux/AppArmor denials, container events
- Automatic MITRE ATT&CK technique tagging for kernel events
- Thread-safe ring-buffer with capacity management and type-filtered queries

### Behavioural threat analytics

- UEBA engine with per-entity risk scoring, login-time anomalies, impossible-travel detection, process/port/data-volume baselines, and peer-group comparison
- Kill-chain reconstruction mapping alert sequences through 7 phases with gap analysis
- Lateral movement graph with fan-out analysis, depth scoring, and credential-reuse correlation
- Beacon/C2 detection via inter-arrival jitter, DGA detection (Shannon entropy + consonant ratio), DNS-tunnelling indicators

### SOAR-style incident automation

- Declarative playbook engine with 11 step types, trigger matching, execution tracking, and approval gates
- Live response sessions with per-platform command whitelists and audit logging
- Automated remediation with 14 action types, platform-specific commands, rollback snapshots, and approval gating
- SLA-driven escalation engine with multi-level policies, 7 notification channels, and on-call rotation

### Evidence and containment

- Per-platform evidence collection plans: Linux 20, macOS 18, Windows 17 forensic artifacts
- OS-specific containment commands: cgroup/nftables/seccomp (Linux), sandbox-exec/pfctl/ESF (macOS), Job objects/netsh/AppLocker/WFP (Windows)

### SOC operations

- Dashboard with Recharts visualizations (severity pie, 24h alert timeline, CPU/memory area chart), severity filter, and clickable alert drill-down
- Dashboard with persisted personal presets plus shared analyst/admin layouts for role-specific starting views
- SOC Workbench with queue, cases, guided investigation planning, active step tracking, analyst notes, auto-query pivots, case handoff workflows, storyline views, response approval flows, escalation management, planner-to-hunt handoffs, hunt-to-case promotion, focused case routing, workflow-to-response handoffs, identity-routing readiness, rollout history, content bundle posture, automation history, operational analytics recommendations, shift command board, team load and ownership, connector coverage impact, and URL-backed case/incident drawers
- Structured incident detail view with severity badge, storyline timeline, related events/agents, close/export actions
- Event search, incident timelines, process-tree inspection, and evidence package export
- Inline case title editing, saved queue-filter bookmarks, and bulk case status operations
- Server-driven onboarding readiness checks and manager queue-digest summaries for morning-brief style triage

### Detection engineering

- Sigma and native managed rules
- Rule testing, promotion, rollback, suppressions, content packs, MITRE coverage, inline false-positive advisor actions, first-class efficacy / ATT&CK gap / suppression-noise / rollout drill-downs, and a detection ownership/review calendar in the detection workspace
- Detection explainability, persisted analyst feedback, model-registry status, and shadow/rollback visibility for ML-assisted scoring
- Saved hunts with thresholds, schedules, owners, history, scheduled execution, lifecycle promotion state, canary percentages, target-group routing, and workflow recommendations
- Content pack bundles with saved-search templates, workflow routes, target groups, and rollout notes directly editable from the detection workspace
- Suppression rules management with inline creation form (rule_id, hostname, severity filters)
- Hunt drawer UX with route-driven run-hunt intent, live execution, saved-hunt reopening, and workflow suggestions from selected rule context
- Hunt hypothesis and expected-outcome tracking, retrohunt time windows, cron scheduling, and one-click hunt-to-case escalation
- ATT&CK gap heatmap overlays for rule-and-hunt coverage blind spots

### Fleet and release operations

- Cross-platform enrollment and heartbeat tracking
- Per-agent activity snapshots with version, deployment, inventory, and recent-event context
- Release publishing, rollout assignment, rollback, cancellation, and staged deployment controls

### Governance and enterprise controls

- RBAC, session TTL, token rotation, HttpOnly console sessions, session-backed identity groups, audit and retention controls, ClickHouse-backed retained-event search, and retention apply workflows
- IDP, SCIM, cloud collector, and secrets manager configuration surfaces with validation and health visibility, plus enterprise-provider discovery on the unauthenticated sign-in shell
- Change control entries, admin audit export, diagnostics bundle, dependency health endpoints, persisted rollout history, persisted playbook analytics history, and operator-visible control-plane posture evidence for backup cadence, checkpoint coverage, and restore readiness

### Analyst assistance and case collaboration

- Analyst Assistant routed workspace with case-aware queries, citations, retrieval-first fallback answers, context windows, recent turns, scoped investigation context, and direct pivots back into SOC case workflows
- SOC Workbench case ticket-sync workflow with provider, queue/project, and summary inputs plus the last sync result rendered in place

### Supportability and documentation

- Help & Docs support center with searchable embedded documentation, version-aware runbooks and deployment guidance, operator inbox context, production demo lab, support diagnostics, production-readiness control-plane posture, REST/OpenAPI/GraphQL/SDK parity diagnostics, live GraphQL query execution, and API endpoint exploration
- Help & Docs operational readiness drill timeline with documented RTO/RPO targets, backup/checkpoint evidence, persisted failover-drill history, pass/fail artifact checks, and exportable recovery review payloads
- Operator Trust workspaces with grouped console navigation, role anchors, Detection Lab validation, Response Safety previews, Integrations marketplace cards, Operations Health SLOs, and Malware verdict explanations

### Integrations and evidence

- SIEM output, OCSF normalization, TAXII pull, threat-intel `v2` enrichment metadata, and indicator sightings
- Ticket sync, forensic evidence export, remediation change-review history, collector lifecycle analytics, context-aware report artifacts/templates, persisted response/compliance/audit evidence snapshots, tamper-evident audit chain, encrypted event buffering, and deep malware scan `v2` profiles
- Deployment, disaster recovery, threat model, SLO, and runbook documentation

## Verification snapshot

The current release has been verified with:

- `cargo test` passing across unit and integration suites, including focused support-center parity/docs coverage, OpenAPI support-route coverage, retention-config coverage, and integration-setup persistence coverage
- targeted admin-console unit coverage for auth-shell SSO redirect composition and hash-backed return paths, Threat Detection canary auto-promotion plus rollout-history and distribution analytics, the Help & Docs support center, route-backed Live Monitor tab/filter/drawer state, route-backed Fleet rollout/recovery focus and carried offline-scope pivots, route-backed contextual support state, embedded docs search/load, routed runbook pivots, parity rendering, GraphQL query execution, the analyst assistant, and the remaining workspace shell flows
- targeted API regression coverage for session auth routing, hunt/content lifecycle, playbook execution shape, suppressions, storylines, governance, supportability, retention config patching, integration-setup persistence, assistant responses, and enterprise-provider exposure
- deterministic browser regression coverage of dashboard preset persistence, Command Center action drawers and mobile layout, detection efficacy / ATT&CK gap / suppression / rollout drill-downs, run-hunt routing, hunt-result case promotion, saved-hunt reopen/update behavior, investigation planner start, active investigation progress and handoff workflows, route-backed SOC response/escalation/playbook/process-tree/admin actions, route-backed infrastructure assets/integrity/exposure/observability actions, queue-to-hunt pivots, workflow-to-response context handoffs, signed remediation approval and rollback-proof verification, expanded SOC workbench overview, assistant case queries, scoped reporting handoffs, long-retention history search, collector pivots, IdP launch validation, and collector/secrets setup validation

## Current product posture

Wardex is now positioned as a professional XDR/SIEM control plane with incident-first analyst workflows, explainable detections, context-preserving reporting, operator-visible recovery posture, and explicit shift-lead surfaces for ownership, handoff, and detection-review pressure. The runtime, admin console, release process, and website are aligned around operator trust, workflow closure, deployment readiness, clean release verification, and freshness-gated evidence. The current release replaces several previously simulated or placeholder subsystems with genuine implementations, starts the per-domain decomposition of the monolithic `server.rs`, and opens the per-slice TypeScript migration of the admin console.

## Recently shipped (v1.0.23)

- **Real ML triage engine** — multiclass gradient-boosted classifier (regression trees fitted to softmax cross-entropy gradients, XGBoost-style split gain) trained at startup; Random Forest is retained as the shadow / fallback backend.
- **Real post-quantum signatures** — FIPS 204 ML-DSA-65 via the pure-Rust `ml-dsa` crate; verification uses only the public key.
- **Real GCP collector authentication** — service-account JWT signed with RS256 replaces the prior placeholder, so Cloud Audit Log polling actually authenticates.
- **Live threat-feed ingestion** — background poll loop plus format-specific parsers for Abuse.ch MalwareBazaar (CSV), URLhaus (`json_online`), and Feodo Tracker (C2 IP blocklist); bundled feeds ingest real indicators out of the box.
- **TLS on by default** so release binaries can make outbound HTTPS, plus a `cluster.require_tls` flag that upgrades peer RPCs to HTTPS and rejects plaintext peer URLs at config-validation time.
- **Server decomposition step 1** — ML, feed-ingestion, and cluster-RPC handlers extracted into dedicated `server_ml.rs` / `server_feeds.rs` / `server_cluster.rs` modules (-253 lines net from `server.rs`).
- **TypeScript migration first slices** — `safeStorage.ts` and `api.ts` (typed wrapper layer with generic `request<T>`, typed options/errors, 11 endpoints typed end-to-end via `@wardex/sdk`).
- **OpenAPI surface** — `/api/feeds/*` family added; the contract now documents 254 operations and the parity gate is updated.
- **Release metadata alignment** — Rust, admin-console, Python SDK, TypeScript SDK, Helm, OTLP, OpenAPI, website, install docs, reproducibility docs, and test fixtures now point at the `v1.0.23` baseline.

## Recently shipped (v1.0.21)

- **Operator workflow depth** — Search Palette now prioritizes route-aware actions, Dashboard adds alert-pressure forecasting, Threat Detection shows promotion confidence gates, and SOC Workbench adds case-journal plus related-case continuity.
- **Integration and recovery posture** — Operator Trust and Help & Docs now expose Splunk HEC and ServiceNow destination posture plus replication region, lag, and health visibility.
- **Durable playbook approvals** — playbook approval steps now pause in stored execution state and resume through runtime, OpenAPI, Python SDK, and TypeScript SDK helpers.
- **Documentation and website refresh** — GitHub README, docs index, website resources page, API reference, and fresh documentation screenshots are aligned with the release surface.
- **Release metadata alignment** — Rust, admin-console, Python SDK, TypeScript SDK, Helm, OTLP, OpenAPI, website, install docs, reproducibility docs, and test fixtures now point at the `v1.0.21` workflow-continuity baseline.

## Recently shipped (v1.0.20)

- **Workspace priority lanes** — Dashboard, Fleet, Infrastructure, NDR, UEBA, and SOC now compute dominant queue pressure and provide a direct priority-lane action.
- **Operator focus narratives** — lead alerts, endpoint drift, asset exposure, remediation backlog, network anomalies, and entity-risk escalations now show concise context before drilldown.
- **Authenticated API default** — backend `/api/*` routes now require authenticated access unless explicitly classified as public, agent, or cluster traffic.
- **Runtime and dependency hardening** — Node runtime, npm install, and dependency-refresh cleanup are carried into the release baseline.
- **Release metadata alignment** — Rust, admin-console, Python SDK, TypeScript SDK, Helm, OTLP, OpenAPI, website, install docs, reproducibility docs, and test fixtures now point at the `v1.0.20` priority-lane baseline.

## Recently shipped (v1.0.18)

- **Operator-safe triage intelligence** — managed ML triage now includes calibrated confidence, quality gates, recommended operator journey, evidence mode, and human-approval requirements.
- **Assistant answer quality gates** — Assistant responses include citation, confidence, and execution-boundary checks, with matching UI visibility in the analyst workspace.
- **Notification delivery trail** — alert notifications can be dispatched with deduplicated outbox records that preserve channel, attempts, status, next retry, and last error.
- **Evidence-mode launchpad** — Operator Launchpad adds canonical journey readiness plus evidence-mode rollups for live, persisted, stale, and pending proof paths.
- **macOS memory indicator depth** — vmmap output now contributes RWX and anonymous-executable region findings instead of returning only a basic placeholder.
- **Release metadata alignment** — Rust, admin-console, Python SDK, TypeScript SDK, Helm, OTLP, OpenAPI, website, and test fixtures now point at the `v1.0.18` intelligence-gates baseline.

## Recently shipped (v1.0.17)

- **Shift continuity workspace** — Operator Launchpad now includes exportable next-shift notes that carry queue state, stale evidence, release blockers, fleet watch items, and generated tasks.
- **Incident timeline builder** — Launchpad assembles alert, process/thread, replay, proof, and report handoff context into a downloadable timeline draft.
- **Collector onboarding and fleet risk** — cloud, identity, SaaS, endpoint, and syslog telemetry lanes now sit beside a fleet heatmap for offline, stale heartbeat, version drift, and active-detection risk.
- **Release acceptance and visual gate** — operators can export an acceptance report from live Launchpad signals, and Playwright now captures a screenshot artifact for the continuity board.
- **Role home and safe assistant** — Launchpad adds role-specific home cards plus explicit retrieval-only, citation, and execution boundaries for assistant use.
- **Release metadata alignment** — Rust, admin-console, Python SDK, TypeScript SDK, Helm, OTLP, OpenAPI, website, and test fixtures now point at the `v1.0.17` operator-continuity baseline.

## Recently shipped (v1.0.16)

- **Persistent Connect Agent drawer** — Fleet now exposes the install-bundle and remote-enrollment workflow as a stable URL target for Launchpad and command-palette pivots.
- **Launchpad execution board** — Operator Launchpad now adds morning brief, guided incident path, fleet health drilldown, evidence freshness, operator task queue, response simulator, release gate automation, and demo-scenario rollups.
- **Context-aware command palette** — command search now promotes route-aware actions for Launchpad, Fleet, SOC, release, and detection contexts before the broader command catalog.
- **Focused regression coverage** — Launchpad, Search Palette, and workflow-pivot tests now cover the second-tranche operator execution paths.
- **Release metadata alignment** — Rust, admin-console, Python SDK, TypeScript SDK, Helm, OTLP, OpenAPI, website, and test fixtures now point at the `v1.0.16` operator-execution baseline.

## Recently shipped (v1.0.15)

- **First-agent onboarding cockpit** — setup now explains the connection path, keeps admin API tokens distinct from one-use agent enrollment tokens, generates OS-specific install commands, and refreshes live readiness checks.
- **Operator command palette depth** — command search now highlights connect-agent, SOC queue, response readiness, process workbench, and deployment confidence pivots.
- **SOC workflow polish** — queue rows show why-this-fired evidence and confidence, response requests show approval/rollback/verification readiness, and process evidence rendering is capped for large payloads.
- **Deployment confidence matrix** — Operator Launchpad now summarizes SDK/API contract, signing/provenance, container parity, backup/failover, data quality, scale gates, and install-plan coverage.
- **Release metadata alignment** — Rust, admin-console, Python SDK, TypeScript SDK, Helm, OTLP, OpenAPI, website, and test fixtures now point at the `v1.0.15` operator-workflow baseline.

## Recently shipped (v1.0.14)

- **Claude workbench template** — the admin console shell now adopts the dense root `design/app` workbench template with a compact navigation rail, tighter topbar, darker default surface, scoped chips, compact cards, and process-investigation table hardening.
- **Release metadata alignment** — Rust, admin-console, Python SDK, TypeScript SDK, Helm, OTLP, OpenAPI, website, and test fixtures now point at the `v1.0.14` Claude workbench layout baseline.

## Recently shipped (v1.0.13)

- **Detection Trust layer** — alert feedback, detection feedback, false-positive feedback, suppressions, replay freshness, lifecycle state, source reliability, enrichment quality, ATT&CK impact, alert volume, and campaign context now roll into per-rule trust scoring.
- **Draft-only tuning queue** — Wardex now drafts scoped suppressions, threshold reviews, weight adjustments, stale suppression reviews, noisy rule reviews, and promotion blockers with impact previews and rollback paths, but never auto-applies them.
- **Trust-first console updates** — Threat Detection shows noisy rules, trusted rules, stale suppressions, confidence drivers, and draft impact previews; Alert Drawer explains normalized outcomes and how feedback affects trust.
- **Detection Lab trust deltas** — validation reports now include expected confidence and false-positive impact from Detection Trust.
- **Release metadata alignment** — Rust, admin-console, Python SDK, TypeScript SDK, Helm, OTLP, OpenAPI, installation, reproducibility, website, and test fixtures now point at the `v1.0.13` detection-trust baseline.

## Recently shipped (v1.0.12)

- **Operator usability hardening** — the console groups navigation into Overview, Analyze, Detect, Respond, Operate, Govern, and Support, adds collapsible groups and role workspace anchors, and exposes trust workspaces through the global command palette.
- **Evidence-first alert trust** — alert feedback, feedback summaries, evidence chains, and “why this fired” inputs are available through additive APIs and SDK helpers, with tuning suggestions visible but not automatically applied.
- **Detection and response trust centers** — Detection Lab, Response Safety, Integrations, Operations Health, and Malware transparency workspaces expose validation runs, response previews, connector health, deployment SLOs, support snapshots, malware verdict explanations, opt-in signature presets, and scan diffing.

## Recently shipped (v1.0.11)

- **Release preflight gate** — signed release packaging now waits for Rust formatting, Clippy, admin-console linting, admin-console formatting, admin-console build, and release-doc validation.
- **CI drift cleanup** — scheduled CI is restored by resolving the snapshot evidence Clippy warning and applying the existing Prettier rules to the Operator Launchpad and process-thread drawer.
- **Hotfix metadata alignment** — Rust, admin-console, Python SDK, TypeScript SDK, Helm, OTLP, OpenAPI, installation, reproducibility, website, and test fixtures now point at the `v1.0.11` hotfix baseline.

## Recently shipped (v1.0.10)

- **Detection and response hardening** — alert analysis now carries stronger source attribution, false-positive reasoning, IP/hostname enrichment, and alarm-specific response action recommendations across authentication, network, process, malware, identity, and persistence scenarios.
- **Malware scanning workspace** — malware, virus, trojan, and rootkit operations now have a dedicated dashboard area with on-demand file, folder, and system scan targets plus operator-selectable open-source signature presets.
- **Thread investigation polish** — process-thread analysis now uses responsive card rows, preserves source context, and avoids horizontal scrolling in the analysis pullout.
- **Live monitor and console layout fixes** — live refresh preserves scroll position, and Help, Settings, Detection, Workflow, and Thread views use corrected box sizing and alignment.
- **Evidence freshness contract** — production assurance and release verification payloads now include `wardex.evidence_freshness.v1` metadata with source, mode, environment ID, run/request IDs, collection and expiry timestamps, artifact digest, criticality, status, and stale/unknown reasons.
- **Freshness-gated release readiness** — clean release cut and release verification center gates now treat missing critical proof, including local checksum rows, SBOM, Gatekeeper evidence, provenance, container parity, observability, and synthetic-console evidence, as blockers before signed release promotion.
- **Persisted proof metadata** — operational snapshot envelopes now retain evidence freshness metadata beside payload digests so later support and release reviews can verify the quality of saved evidence.
- **Launchpad proof visibility** — Operator Launchpad release verification, production assurance, and persisted snapshot rows now show fresh/stale/unknown proof badges and proof collection timing.

## Recently shipped (v1.0.8)

- **Release verification endpoints** — clean release cut readiness, container release parity, release verification center, self-hosted deployment wizard, data-quality dashboard, performance/scale baseline, failover execution, secrets rotation operations, operator task automation, and detection validation packs are now exposed as authenticated snapshot-backed routes.
- **Executable release gates** — artifact verification rows, install plans, data-quality SLOs, launchpad performance gates, failover drill targets, secrets-rotation dry-runs, operator action blueprints, and validation-pack inventory checks are wired into the release evidence surface.
- **Launchpad release verification lane** — the Operator Launchpad now renders the release/deployment confidence signals beside the existing production assurance lane, release doctor, workflow preflight, stream readiness, SDK parity, and operational snapshot evidence.
- **Parity and smoke coverage** — runtime OpenAPI, `docs/openapi.yaml`, RBAC, Python SDK, TypeScript SDK, contract parity, release-acceptance live smoke checks, and live Playwright coverage now cover 254 documented operations including the release-verification tranche.

## Recently shipped (v1.0.7)

- **Production assurance endpoints** — release provenance/SBOM, upgrade rehearsal, synthetic console monitor, incident timeline replay, detection trust score, fleet drift compliance, operator work queue, retention forecast, adversarial validation, and support bundle diffing are now exposed as authenticated product routes with persisted operational snapshot metadata.
- **Launchpad assurance view** — the Operator Launchpad now summarizes those signals beside release doctor, workflow preflight, stream readiness, SDK parity, snapshot verification, and support bundle export actions.
- **Contract discipline** — runtime OpenAPI, `docs/openapi.yaml`, RBAC, Python SDK, TypeScript SDK, contract-parity checks, and release-acceptance smoke coverage all include the new assurance routes.

## Recently shipped (v1.0.6)

- **Release observability gates** — release doctor now includes metrics, stream readiness, verified snapshot, and contract-parity gates, backed by new stream queue/drop Prometheus metrics.
- **Workflow and rule preflight proof** — release workflows and content-rule promotion now attach preflight evidence for stream health, replay state, suppressions, content-pack ownership, approval queues, tenant isolation, and observability gates.
- **Cursor pagination and proof APIs** — alerts, events, and audit logs now have cursor-page APIs, while tenant isolation, runtime thread baseline, and snapshot retention/redaction policies are exposed through OpenAPI and both SDKs.
- **Console resilience cleanup** — admin-console API calls gained structured error messages, GET retry/timeout handling, safe browser storage usage, and drawer focus/body-scroll hardening.
- **Release metadata aligned on v1.0.6** — Rust, admin-console, Python SDK, TypeScript SDK, Helm, OTLP, OpenAPI, installation/reproducibility docs, and website release surfaces now point to the same release baseline.

## Recently shipped (v1.0.5)

- **Developer ID signing-secret repair** — release automation now has a checked-in helper that refreshes the GitHub Actions macOS certificate secrets from a locally exported Developer ID `.p12` without printing private material.
- **Local signing validation** — the exported Developer ID Application identity was verified against a temporary macOS binary with timestamped hardened-runtime signing, confirming the `.p12` can drive CI signing once GitHub secrets are refreshed.
- **Release metadata aligned on v1.0.5** — Rust, admin-console, Python SDK, TypeScript SDK, Helm, OTLP, OpenAPI, installation/reproducibility docs, and website release surfaces now point to the same release baseline.

## Recently shipped (v0.56.1)

- **SOC workbench strengthening** — case handoff packets, team load and ownership, and connector coverage impact are now first-class workbench surfaces, so handoffs, queue balancing, and collector-to-detection trust gaps stay visible in the same overview.
- **Detection review calendar** — Threat Detection now shows overdue ownership reviews, due-this-week items, replay blockers, noisy owners, and rule-level next-review timing plus promotion blockers.
- **Command Center review pressure** — the Detection Quality Dashboard now surfaces a compact detection review calendar so shift leads can jump straight from `/command` into the exact rule promotion context that needs attention.
- **Shared rule review history** — rule-level replay deltas and analyst verdict history now feed Threat Detection and SOC Workbench from the same backend review-history contract.
- **Operational readiness drill timeline** — Help & Docs now turns recovery posture into an operator timeline with documented RTO/RPO targets, backup/checkpoint evidence, persisted failover drills, pass/fail checks, and timeline export.
- **0.56.0 quality cleanup** — frontend race conditions, lint/build issues, storage-lock test flakiness, doctest SIGKILL noise, persisted session permissions, and RBAC token hashing/redaction were cleaned up before the strengthening slices were layered in.
- **OIDC cryptographic login hardening** — federated sign-in now uses PKCE `S256`, cryptographically strong state/nonce generation, JWKS-backed `id_token` signature validation, issuer/audience/expiry/nbf enforcement, and nonce/subject mismatch rejection before console sessions are issued.
- **OIDC JWKS rotation hardening** — ID token validation now refreshes provider JWKS at validation time, replaces stale cached keys, rejects revoked cached signing keys, requires issued-at coverage, enforces authorized-party checks for multi-audience tokens, and rejects non-signature/non-verify JWKS keys.
- **Persisted session sealing** — file-backed admin sessions now use a signed persistence envelope with a stable local seal key, reject tampered session payloads during reload, and still accept older unsigned session files long enough to migrate them forward on the next write.
- **Default-deny route auth classification** — API auth enforcement now runs through an explicit route-access classifier for public, agent-token, cluster-token, and authenticated paths, with authenticated as the default for all remaining `/api/*` routes and `/api/endpoints` deriving supplemental auth flags from that same contract.
- **OpenAPI route-auth contract parity** — generated OpenAPI security, `x-wardex-auth`, the endpoint catalog, static `docs/openapi.yaml`, and parity checks now use the runtime classifier as the route-auth source of truth, including agent update-check and artifact-download routes.
- **Signed agent update trust** — agent release artifacts now support Ed25519 signatures, signer trust from bundled defaults plus config, unsigned grace-period handling, replay counters, downgrade rejection, tamper detection, download headers, deployment metadata, and agent-side install re-verification.
- **Auto-progress signed update review fix** — canary-to-next-ring rollout progression now performs the same artifact trust verification as manual deployment, rejects wrong-key signed releases, and records verified signature metadata on generated assignments.
- **Control-plane posture evidence** — support readiness, dependency health, and backup-status routes now expose active/passive reference status, backup cadence, observed backups, latest backup timestamps, checkpoint counts, latest checkpoint timestamps, and restore-readiness directly from live runtime state.
- **Help & Docs recovery summary** — Production Readiness now renders a structured control-plane posture section with durable-storage, restore-artifact, and failover-model checks so operators can review recovery posture without reading raw JSON.
- **HA guidance refresh** — deployment and disaster-recovery docs now tie the active/passive reference pattern to the shipped support/readiness APIs so failover drills have concrete runtime evidence to verify before and after restore.
- **Release metadata aligned on v0.56.1** — Rust, admin-console, Python SDK, TypeScript SDK, Helm, OTLP, OpenAPI, installation/reproducibility docs, and website release surfaces now point to the same release baseline.
- **GitHub CI release gate cleaned up** — the panic-policy baseline is back to zero production `unwrap`/`expect` calls, Rust formatting is clean, and the OS test matrix now reports each platform independently instead of cancelling sibling jobs after the first failure.
- **GitHub release distribution hardened** — the tag release workflow now falls back to the repository token for Pages dispatch, skips optional Homebrew tap publishing when its token is absent, and lets Pages publish static content even when APT signing secrets are not configured.

## Recently shipped (v0.55.1)

- **Release asset trust** — Tagged releases now publish a verified `SHA256SUMS` asset and include checksum guidance in release notes.
- **Package install smoke** — The release workflow installs the generated Debian package and verifies the `wardex` command before publishing.
- **Node baseline aligned** — Admin-console and TypeScript SDK metadata now require Node `>=20.19.0`, `.nvmrc` points contributors at Node 22, and the site quality workflow runs on Node 22.
- **Strict a11y coverage expanded** — Playwright axe checks treat onboarding and welcome screens as strict gates by default, with Settings covered in the browser smoke.
- **Request-ID hardening** — Server responses now share the structured-log request ID generator, with typed clock-error handling and a safe response-boundary fallback.
- **Console reliability cleanup** — Fleet recovery watchlists de-duplicate stale/offline agents, workspace tab tests avoid React act warnings, and Settings configuration rendering is split into a focused component.
- **Release metadata aligned on v0.55.1** — Rust, admin-console, Python SDK, TypeScript SDK, Helm, OTLP, OpenAPI, install docs, reproducibility notes, and website release surfaces now point to the same release baseline.

## Recently shipped (v0.55.0)

- **Per-lane Command Center API** — `GET /api/command/lanes/{lane}` returns a focused slice of the cross-product summary (incidents, remediation, connectors, rule_tuning, release, evidence), so drawers can refresh a single lane without re-pulling the full aggregate. Catalog, OpenAPI, Rust builder, console helper, and integration test all updated.
- **Drawer deep-links** — Command Center drawers now sync to the URL via `?drawer=<lane>`, making the analyst's current view bookmarkable and shareable while preserving local item context.
- **Workflow lint gate** — `.github/workflows/actionlint.yml` runs SHA-pinned `actionlint` 1.7.12 on every workflow change, catching action-spec regressions at PR time.
- **DX scripts** — `npm run e2e` (and `e2e:ui`) alias `playwright test`, `scripts/changelog_reset_unreleased.py` automates the `## [Unreleased]` reset after tagging, and `CONTRIBUTING.md` documents the iCloud Drive `TMPDIR` workaround.
- **Release metadata aligned on v0.55.0** — Rust, admin-console, Python SDK, TypeScript SDK, Helm, OTLP, OpenAPI, install docs, reproducibility notes, and website release surfaces now point to the same release baseline.

## Recently shipped (v0.54.0)

- **Product Command Center action surface** — `/command` is the analyst default workspace and opens connector validation, remediation approval, rule replay, release readiness, and compliance evidence drawers directly from lane metrics.
- **Backend command summary** — `GET /api/command/summary` aggregates incidents, cases, remediation reviews, connector gaps, noisy/stale rules, release metadata, report templates, compliance posture, and fleet gaps for the command workspace.
- **Planned connector onboarding** — GitHub Audit Log, CrowdStrike Falcon, and Generic Syslog now expose setup persistence, validation, sample-event preview, collector status entries, OpenAPI coverage, and console API helpers.
- **Rule tuning readiness** — noisy/stale rules now render a replay, suppression, and promotion checklist before analysts pivot into the full detection workspace.
- **Command Center runbook and browser smoke** — the runbook documents shift-start and escalation workflows, while Playwright covers desktop action drawers and the mobile command layout across Chromium, Firefox, and WebKit.

## Roadmap completion in progress

- **Signed multi-approver remediation** — change reviews now require risk-aware approver counts, record signed approval-chain digests, attach rollback proof with recovery plans when approval quorum is reached, verify rollback through the remediation module in dry-run-first mode, exercise matching-platform true execution for restore-file, kill-process, restart-service, block-ip, remove-persistence, disable-account, and flush-dns actions when both live rollback flags are enabled, and keep mismatched-platform requests recorded-only when the local executor cannot safely run them.
- **Collector ingestion evidence pivots** — collector lifecycle status now carries SOC Workbench and Infrastructure pivots plus recent ingestion evidence for cloud, identity, SaaS, EDR, and syslog lanes, and the Settings integrations workspace now keeps freshness, success rate, failure streak, retry/backoff, and recent-run evidence visible alongside those routed pivots.
- **Expanded production demo lab** — demo seeding now includes cloud, identity, SaaS, UEBA, NDR, and attack-graph evidence alongside case, response, report, and artifact proof.
- **IdP lifecycle validation depth** — identity-provider summaries now expose launch checks for metadata, callback route alignment, client credentials, group mappings, and test-login paths, while routed Settings and auth-shell regressions lock in ready-provider launch paths, callback/session recovery, hash-backed return paths, stale-token fallback behavior, and transient callback-error cleanup.
- **Detection lifecycle distribution analytics** — Threat Detection now surfaces stored-efficacy canary auto-promotion outcomes, rollout-history evidence, lifecycle distribution analytics, routed delivery-lane summaries, and refreshed promotion evidence directly in the detection workspace so operators can review promote-or-rollback decisions without leaving the routed console.
- **SDK parity continuation** — Python and TypeScript SDKs include Command Center summary and per-lane refresh helpers, explicit Command Center response models in both SDKs, collector status, remediation review creation, signed remediation approval, detection tuning/scoring, remote fleet install, process-thread, and backup helpers used by console workflows.
- **Command Center expansion** — the cross-product workspace now has action drawers, routed browser smoke coverage, live enterprise-smoke route and drawer-handoff coverage in the release gate across connector, remediation, release, and evidence handoffs, a backend summary contract, and per-lane annotations with next-step guidance across incident, remediation, connector, rule-tuning, release, and evidence workflows.
- **Remediation module extraction** — remediation change-review JSON envelopes, HTTP error mapping, route-id parsing, body limits, plan JSON wrapping, and rollback policy assembly now live in `remediation.rs`, leaving `server.rs` focused on route dispatch and response wiring.

## Recently shipped (v0.53.7)

- **Zero-warnings ESLint gate** — all 11 long-standing `react-hooks` warnings (NDR Dashboard derived arrays, Onboarding wizard checklist, App.jsx redundant location-key reset effect, AlertDrawer / SSO error mirroring) are resolved or surgically annotated, and `npm run lint` runs with `--max-warnings=0` to block regressions.
- **Vitest coverage gate** — a v8-backed coverage report runs in CI with global thresholds (statements ≥ 60, branches ≥ 55, functions ≥ 55, lines ≥ 60) so coverage cannot silently regress.
- **Knip dead-code gate** — `knip` is installed, configured, and wired into CI as `npm run knip`; `useDraftAutosave` and the over-exported `LOCAL_AGENT` test fixture were removed in the same pass.
- **Panic-policy baseline lowered 19 → 6** — 13 production `unwrap`/`expect` calls in `event_forward.rs`, `incident.rs`, `lateral.rs`, `feed_ingestion.rs`, `oidc.rs`, and `benchmark.rs` were replaced with `let-else` / `match` / `ok_or_else?` patterns, and the panic-policy floor was ratcheted down accordingly.
- **Empty-state migration continues** — Assistant Workspace (5 sites), FleetAgents (1), and ThreatDetection rule list / detail (2) now use `WorkspaceEmptyState` for consistent `role="status"` semantics.

## Recently shipped (v0.53.6)

- **Shared API error formatting** — admin-console workspaces now derive operator error messages through a single `formatApiError` helper, removing four duplicated implementations and surfacing the backend `X-Request-Id` for support correlation.
- **Workspace empty/error primitives** — reusable `WorkspaceEmptyState` and `WorkspaceErrorState` components with proper ARIA semantics now back operator workspaces, with Email Security migrated as the first adopter.
- **Tablist semantics** — Settings, Infrastructure, Reports & Exports, Email Security, and NDR Dashboard tab strips now expose `role="tablist"` / `role="tab"` / `aria-selected` so keyboard and assistive-technology navigation match Live Monitor.
- **Settings module split** — the 5,000-line Settings workspace has been broken into a pure-helpers file and a widget-components file, shrinking the main file by ~14% with no behavior change.
- **Panic-policy CI guard** — a new CI job blocks regressions in non-test `unwrap`/`expect` density against a checked-in baseline; verifiable locally via `python3 scripts/check_panic_policy.py`.
- **Dead-code removal** — a `knip` audit removed three unused admin-console files and two over-exported helpers without test or build regressions.
- **Release-document accuracy** — README, status, roadmap, reproducibility, installation, OpenAPI, helm, otlp, SDK, and website surfaces are aligned on the `v0.53.6` baseline.

## Recently shipped (v0.53.5)

- **Replay-corpus drift analysis** — replay validation now breaks down platform and signal-type deltas for built-in, retained-event, and custom packs so detector promotion can see which slices are regressing.
- **Collector ingestion-health timelines** — the shared collector status contract and Settings workspace now surface staged checkpoint timelines across cloud, identity, and SaaS lanes instead of only flat readiness counts.
- **Broader routed release gate** — live Playwright smoke coverage now walks routed response, collector-health, fleet-rollout, and infrastructure remediation workflows alongside the earlier detection and admin paths.
- **Release-document accuracy** — README, status, roadmap, reproducibility, installation, and OpenAPI surfaces are aligned on the `v0.53.5` baseline, including the real `--version` verification path for built binaries.

## Recently shipped (v0.39.5)

- **Admin console UX overhaul** — Replaced all raw JSON dumps with structured key-value grids, tables, and timeline views across SOCWorkbench (overview, cases, response, entity, timeline), Settings, Infrastructure (monitor, correlation, drift, energy, mesh, system), and ThreatDetection
- **Recharts visualizations** — Dashboard severity breakdown pie chart, 24h alert timeline bar chart, CPU/memory telemetry area chart
- **Config management** — Settings structured form editor with toggle switches and number inputs, config diff view (line-by-line green/red), reset-to-defaults, and monitoring scope toggle tab
- **FP feedback & bulk actions** — Per-alert false-positive button with auto-pattern extraction; bulk select with Mark FP / Triage / Create Incident operations; alert severity filter
- **Cross-signal correlation** — Detector applies bonus multiplier when 3+ signal axes are simultaneously elevated (3→15%, 4→30%, 5→50%, 6+→70%)
- **Auth rate-of-change smoothing** — 8-sample rolling window tracks auth failure acceleration; delta >4.0 over 3 samples triggers additional detection signal
- **Escalation management console** — New SOC Workbench tab: policy CRUD (name, severity, channel, targets, timeout), active escalation tracking with acknowledge workflow
- **Structured incident detail** — Drill-down shows severity badge, status, created/updated, owner, related events/agents, storyline timeline, close and export-report actions
- **Hunt/suppression management** — Full table + inline creation form in ThreatDetection hunts tab; suppressions preview in sigma tab with link to management

## Next release priorities

- extend the control-plane posture program beyond shipped runtime evidence into drill automation and broader failover validation
- continue the broader professional roadmap execution tracked in `docs/ROADMAP_XDR_PROFESSIONAL.md`
- keep shipped control-plane posture, detection rollout analytics, auth-shell, fleet, SOC, command, analytics, and long-retention handoffs aligned as surrounding workflows evolve

## Recently shipped (v0.43.1)

- **Admin console quality** — 6 phases of deep code review identified and fixed ~40 bugs across all admin-console components (Dashboard, Live Monitor, Threat Detection, Fleet & Agents, SOC Workbench, Infrastructure, Settings, Reports & Exports, Security Policy, Help & Docs)
- **Badge CSS correctness** — Fixed malware severity and trace status badges using nonexistent CSS classes throughout Infrastructure views
- **Memory leak fix** — SIEM export blob URLs are now revoked after download, preventing unbounded memory growth
- **Unused API fetch removal** — Eliminated a stale config-drift baselines fetch that fired on every Infrastructure mount
- **Admin console test suite** — 83 automated tests (26 Vitest unit + 57 Playwright e2e) covering authentication, navigation, all page views, responsive layout, onboarding wizard, and zero-JS-crash verification across all routes

## Recently shipped (v0.43.0)

- **Malware hash database** — In-memory threat intel DB with ~48 built-in SHA256/MD5 hashes, JSON/CSV import, community YARA rules
- **Malware scanner** — Hash DB + YARA engine orchestration for file scanning with verdict classification
- **Threat hunting DSL** — KQL-like query language with recursive descent parser, field aliases, wildcards, AND/OR/NOT
- **SIEM export engine** — Multi-format alert export: CEF, LEEF, Syslog RFC 5424, Sentinel, UDM, ECS, QRadar, JSON
- **Compliance report generator** — Full-framework evaluation for CIS v8, PCI-DSS v4, SOC 2 Type II, and NIST CSF 2.0
- **Playbook execution engine** — 11 step types with on_failure jump, template variable substitution, and approval gates
- **Alert deduplication** — Time-window incident merging with configurable cross-device settings
- **API usage analytics** — Per-endpoint request tracking with count, error rate, and latency percentiles
- **OpenTelemetry tracing** — OtelSpan with trace/span IDs, parent chaining, OTLP JSON export
- **Backup encryption** — AES-256-GCM encryption with random salt and nonce, passphrase-derived keys
- **Detection rules CRUD** — List and add custom YARA rules via API
- **TypeScript SDK** — Full typed client with 20+ methods, AbortController timeout, TypeScript interfaces
- **Homebrew formula** — Multi-platform installation with service integration
- **Admin console** — 5 new tabs: Hunt, Compliance, Analytics, Traces, Rules
- **Code review hardening** — Crypto fixes (random nonce/salt), O(1) ring buffers, input validation, JSON injection fixes
- **Fuzz testing infrastructure** — 3 fuzz targets (csv_parse, jsonl_parse, yara_load) with weekly CI job
- **Admin console test suite** — 26 Vitest unit tests with ESLint 9 + Prettier, automated in CI
- **CI quality gates** — 70% coverage threshold, cargo-semver-checks, Trivy container scanning
- **OpenAPI enrichment** — Rate-limit headers (429 responses), concrete examples on 8 endpoints
- **Module-level rustdoc** — `//!` documentation added to 11 source modules

## Recently shipped (v0.42.0)

- **Vulnerability scanner** — CVE correlation engine with 10 built-in advisories, semantic version comparison, and fleet-wide scanning with risk-scored summaries
- **Network Detection & Response** — Netflow ingestion with top-talker analysis, unusual destination detection, protocol anomaly scoring, and encrypted-traffic statistics
- **Container runtime detection** — 13 event kinds and 8 alert types covering escape, privileged exec, untrusted images, sensitive mounts, capabilities abuse, and K8s API abuse
- **TLS certificate monitor** — Tracks certificate expiry (30d warn, 7d critical), self-signed and weak-key detection
- **Configuration drift detection** — Baseline compliance for SSH, kernel, and Docker with MITRE ATT&CK mapping
- **Unified asset inventory** — 9 asset types with upsert, risk scoring, and full-text search
- **Detection efficacy tracker** — Per-rule TP/FP rate tracking, trend analysis, and summary metrics
- **Guided investigation workflows** — 5 built-in playbooks (credential-storm, ransomware-triage, lateral-movement, c2-beacon, container-escape) with step-by-step guidance
- **ML Random Forest triage** — Replaced stub with 5-tree ensemble for alert classification
- **Notification enrichment** — Slack/Teams alerts now include MITRE techniques, kill-chain phase, recommended action, affected hosts, and investigation link
- **Cloud Sigma rules** — 8 new detection rules (IAM role assumption, OAuth consent abuse, S3 cross-account, logging disabled, GCP SA keys, Lambda admin, impossible travel, DB snapshot sharing)
- **Admin console expansion** — 7 new tabs across Infrastructure and SOC Workbench for all new capabilities
- **Python SDK expansion** — 24 new typed methods covering all new API endpoints

## Recently shipped (v0.36.0)

- **GraphQL query layer** — `/api/graphql` endpoint with resolvers for alerts, agents, events, hunts, and status plus introspection
- **Real gzip compression** — archival exports use `flate2` instead of raw DEFLATE stub
- **SMTP email delivery** — notification engine connects to real SMTP servers (RFC 5321) with retry and exponential backoff
- **Mutex poison recovery** — all 230+ lock sites use `unwrap_or_else(|e| e.into_inner())` to prevent cascading panics
- **Syslog forwarding** — HTTP audit log entries forwarded to a UDP syslog target (RFC 5424) via `WARDEX_SYSLOG_TARGET`
- **Database schema version API** — `GET /api/admin/db/version` returns migration history and current schema version
- **Production hardening** — panic hooks, Slowloris protection, secret management, agent auth, auto retention purge, GDPR purge, PII scanner, VecDeque O(1) eviction, memory bounds, K8s probes, X-Request-Id tracing, SBOM API, DB backup

## Recently shipped (v0.36.1)

- **Spool counter safety** — replaced `.expect()` panic with `wrapping_add()` in spool cipher counter
- **WASM div-by-zero fix** — replaced overly strict `f64::EPSILON` comparison with exact zero check
- **Ransomware detector API** — `GET /api/detectors/ransomware` endpoint wired to live detector state
- **Database migration rollback** — `POST /api/admin/db/rollback` with `rollback_migration()` on storage layer
- **Spool tenant isolation** — per-tenant partition methods with 4 new tests

## Recently shipped (v0.36.2)

- **Complete retention purge** — `purge_old_metrics()` and `purge_old_response_actions()` wired into scheduler for all 4 record types
- **Production hardening** — score updated to 95% (56/59 controls)

## Recently shipped (v0.36.3)

- **TLS/HTTPS listener** — opt-in `tls` Cargo feature with `WARDEX_TLS_CERT`/`WARDEX_TLS_KEY` env vars
- **mTLS support** — `ListenerMode::Tls` carries full `TlsConfig` for mutual TLS agent authentication
- **5 new chaos tests** — oversized headers, wrong methods, invalid auth, endpoint sweep, oversized body (total: 10)
- **Production hardening** — score updated to 98% (58/59 controls)
