# Wardex Status

## Current release

- **Version:** `0.55.1`
- **Positioning:** private-cloud XDR and SIEM platform with enterprise detection engineering, malware scanning, analyst workflows, fleet operations, behavioural analytics, and automated incident response
- **Source footprint:** 139 Rust source modules
- **API contract:** versioned OpenAPI surface with REST, GraphQL, live `/api/openapi.json` export, and generated SDK parity diagnostics that surface alignment drift directly in the operator console
- **Verification:** Rust integration coverage, focused session-cookie exchange tests, collector lifecycle tests, remediation change-review tests, Command Center summary/action-drawer tests, Help & Docs unit coverage, assistant/ticketing/enterprise API regression tests, SDK regeneration checks, release-contract validation, strict Playwright a11y smoke coverage, and focused admin-console regression coverage for auth routing, dashboard presets, detection drill-downs, workbench overview, assistant/reporting handoffs, scoped report artifacts/templates, persisted artifact downloads, response snapshots, long-retention history, and collector/secrets setup flows
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
- SOC Workbench with queue, cases, guided investigation planning, active step tracking, analyst notes, auto-query pivots, case handoff workflows, storyline views, response approval flows, escalation management, planner-to-hunt handoffs, hunt-to-case promotion, focused case routing, workflow-to-response handoffs, identity-routing readiness, rollout history, content bundle posture, automation history, operational analytics recommendations, and URL-backed case/incident drawers
- Structured incident detail view with severity badge, storyline timeline, related events/agents, close/export actions
- Event search, incident timelines, process-tree inspection, and evidence package export
- Inline case title editing, saved queue-filter bookmarks, and bulk case status operations
- Server-driven onboarding readiness checks and manager queue-digest summaries for morning-brief style triage

### Detection engineering

- Sigma and native managed rules
- Rule testing, promotion, rollback, suppressions, content packs, MITRE coverage, inline false-positive advisor actions, and first-class efficacy / ATT&CK gap / suppression-noise / rollout drill-downs in the detection workspace
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
- Change control entries, admin audit export, diagnostics bundle, dependency health endpoints, persisted rollout history, and persisted playbook analytics history

### Analyst assistance and case collaboration

- Analyst Assistant routed workspace with case-aware queries, citations, retrieval-first fallback answers, context windows, recent turns, scoped investigation context, and direct pivots back into SOC case workflows
- SOC Workbench case ticket-sync workflow with provider, queue/project, and summary inputs plus the last sync result rendered in place

### Supportability and documentation

- Help & Docs support center with searchable embedded documentation, version-aware runbooks and deployment guidance, operator inbox context, production demo lab, support diagnostics, REST/OpenAPI/GraphQL/SDK parity diagnostics, live GraphQL query execution, and API endpoint exploration

### Integrations and evidence

- SIEM output, OCSF normalization, TAXII pull, threat-intel `v2` enrichment metadata, and indicator sightings
- Ticket sync, forensic evidence export, remediation change-review history, collector lifecycle analytics, context-aware report artifacts/templates, persisted response/compliance/audit evidence snapshots, tamper-evident audit chain, encrypted event buffering, and deep malware scan `v2` profiles
- Deployment, disaster recovery, threat model, SLO, and runbook documentation

## Verification snapshot

The current release has been verified with:

- `cargo test` passing across unit and integration suites, including focused support-center parity/docs coverage, OpenAPI support-route coverage, retention-config coverage, and integration-setup persistence coverage
- targeted admin-console unit coverage for the Help & Docs support center, embedded docs search/load, parity rendering, GraphQL query execution, the analyst assistant, and existing workspace shell flows
- targeted API regression coverage for session auth routing, hunt/content lifecycle, playbook execution shape, suppressions, storylines, governance, supportability, retention config patching, integration-setup persistence, assistant responses, and enterprise-provider exposure
- deterministic browser regression coverage of dashboard preset persistence, Command Center action drawers and mobile layout, detection efficacy / ATT&CK gap / suppression / rollout drill-downs, run-hunt routing, hunt-result case promotion, saved-hunt reopen/update behavior, investigation planner start, active investigation progress and handoff workflows, queue-to-hunt pivots, workflow-to-response context handoffs, signed remediation approval and rollback-proof verification, expanded SOC workbench overview, assistant case queries, scoped reporting handoffs, long-retention history search, collector pivots, IdP launch validation, and collector/secrets setup validation

## Current product posture

Wardex is now positioned as a professional XDR/SIEM control plane with incident-first analyst workflows, explainable detections, and context-preserving reporting. The runtime, admin console, release process, and website are aligned around operator trust, workflow closure, and deployment readiness.

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
- **Collector ingestion evidence pivots** — collector lifecycle status now carries SOC Workbench and Infrastructure pivots plus recent ingestion evidence for cloud, identity, and SaaS lanes.
- **Expanded production demo lab** — demo seeding now includes cloud, identity, SaaS, UEBA, NDR, and attack-graph evidence alongside case, response, report, and artifact proof.
- **IdP lifecycle validation depth** — identity-provider summaries now expose launch checks for metadata, callback route alignment, client credentials, group mappings, and test-login paths.
- **SDK parity continuation** — Python and TypeScript SDKs include Command Center summary and per-lane refresh helpers, explicit Command Center response models in both SDKs, collector status, remediation review creation, signed remediation approval, detection tuning/scoring, remote fleet install, process-thread, and backup helpers used by console workflows.
- **Command Center expansion** — the cross-product workspace now has action drawers, routed browser smoke coverage, live enterprise-smoke route and drawer-handoff coverage in the release gate, a backend summary contract, and per-lane annotations with next-step guidance across incident, remediation, connector, rule-tuning, release, and evidence workflows.
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

- formal Phase 47 backlog is complete; define the next parity or workflow-depth tranche from release planning after this cut

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
