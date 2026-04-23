# Wardex Status

## Current release

- **Version:** `0.53.1-local`
- **Positioning:** private-cloud XDR and SIEM platform with enterprise detection engineering, malware scanning, analyst workflows, fleet operations, behavioural analytics, and automated incident response
- **Source footprint:** 134 Rust source modules
- **API contract:** versioned OpenAPI surface with REST, GraphQL, and generated SDK parity diagnostics that surface alignment drift directly in the operator console
- **Verification:** Rust integration coverage, focused support-center and OpenAPI contract tests, Help & Docs unit coverage, assistant/ticketing/enterprise API regression tests, SDK regeneration checks, and focused admin-console regression coverage for auth routing, dashboard presets, detection drill-downs, workbench overview, investigation-to-response pivots, assistant queries, ticket sync, long-retention history, and collector/secrets setup flows
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
- SOC Workbench with queue, cases, guided investigation planning, active step tracking, analyst notes, auto-query pivots, case handoff workflows, storyline views, response approval flows, escalation management, planner-to-hunt handoffs, hunt-to-case promotion, focused case routing, workflow-to-response handoffs, identity-routing readiness, rollout history, content bundle posture, automation history, and operational analytics recommendations
- Structured incident detail view with severity badge, storyline timeline, related events/agents, close/export actions
- Event search, incident timelines, process-tree inspection, and evidence package export
- Inline case title editing, saved queue-filter bookmarks, and bulk case status operations

### Detection engineering

- Sigma and native managed rules
- Rule testing, promotion, rollback, suppressions, content packs, MITRE coverage, inline false-positive advisor actions, and first-class efficacy / ATT&CK gap / suppression-noise / rollout drill-downs in the detection workspace
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

- RBAC, session TTL, token rotation, session-backed identity groups, audit and retention controls, ClickHouse-backed retained-event search, and retention apply workflows
- IDP, SCIM, cloud collector, and secrets manager configuration surfaces with validation and health visibility, plus enterprise-provider discovery on the unauthenticated sign-in shell
- Change control entries, admin audit export, diagnostics bundle, dependency health endpoints, persisted rollout history, and persisted playbook analytics history

### Analyst assistance and case collaboration

- Analyst Assistant routed workspace with case-aware queries, citations, retrieval-first fallback answers, context windows, recent turns, and direct pivots back into SOC case workflows
- SOC Workbench case ticket-sync workflow with provider, queue/project, and summary inputs plus the last sync result rendered in place

### Supportability and documentation

- Help & Docs support center with searchable embedded documentation, version-aware runbooks and deployment guidance, operator inbox context, support diagnostics, REST/OpenAPI/GraphQL/SDK parity diagnostics, live GraphQL query execution, and API endpoint exploration

### Integrations and evidence

- SIEM output, OCSF normalization, TAXII pull, and threat-intel enrichment
- Ticket sync, forensic evidence export, tamper-evident audit chain, and encrypted event buffering
- Deployment, disaster recovery, threat model, SLO, and runbook documentation

## Verification snapshot

The current release has been verified with:

- `cargo test` passing across unit and integration suites, including focused support-center parity/docs coverage, OpenAPI support-route coverage, retention-config coverage, and integration-setup persistence coverage
- targeted admin-console unit coverage for the Help & Docs support center, embedded docs search/load, parity rendering, GraphQL query execution, the analyst assistant, and existing workspace shell flows
- targeted API regression coverage for session auth routing, hunt/content lifecycle, playbook execution shape, suppressions, storylines, governance, supportability, retention config patching, integration-setup persistence, assistant responses, and enterprise-provider exposure
- deterministic browser regression coverage of dashboard preset persistence, detection efficacy / ATT&CK gap / suppression / rollout drill-downs, run-hunt routing, hunt-result case promotion, saved-hunt reopen/update behavior, investigation planner start, active investigation progress and handoff workflows, queue-to-hunt pivots, workflow-to-response context handoffs, expanded SOC workbench overview, assistant case queries, case ticket sync, enterprise sign-in shell provider exposure, long-retention history search, and collector/secrets setup validation

## Current product posture

Wardex is now positioned as a professional XDR/SIEM control plane rather than an implementation diary. The runtime, admin console, release process, and website have been aligned around operator workflows, deployment readiness, and product documentation.

## Recently shipped (v0.53.1-local)

- **Analyst assistant workflow** — Added a dedicated Analyst Assistant route with case-aware questions, citations, retrieval-mode fallback answers, context windows, recent turns, and direct links back into SOC case handling
- **Case ticket-sync workflow** — SOC Workbench cases now expose analyst-side external ticket sync with provider, queue/project, summary, and last-sync result rendering instead of leaving ticketing as backend-only plumbing
- **Enterprise SSO sign-in shell bridge** — Configured enterprise identity providers now surface on the unauthenticated login shell via `/api/auth/sso/config`, so operator-visible SSO discovery matches provider setup state
- **Support center and docs surface** — Help & Docs now combines support diagnostics, runtime parity reporting, searchable embedded docs, version-aware runbooks, deployment guidance, API contract exploration, and a live GraphQL runner in one routed operator workflow
- **Runtime contract supportability** — OpenAPI now publishes the support parity/docs routes and the GraphQL endpoint alongside the existing endpoint catalog, so contract drift is visible from both the API surface and the console
- **Regression asset expansion** — Added Help & Docs and Analyst Assistant unit coverage plus broader Playwright smoke coverage for dashboard, SOC workbench investigations, settings identity/admin surfaces, advanced operator workflows, and the new assistant/ticket-sync/SSO login-shell path

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

- full enterprise SSO workflows beyond the shipped IDP/SCIM configuration surfaces
- API contract and SDK regeneration follow-up to clear surfaced parity drift during release preparation
- package-manager distribution (APT/YUM, Chocolatey)
- remaining SaaS and identity collector coverage beyond the shipped cloud, secrets-manager, and case ticket-sync flows
- UEBA, NDR, and infrastructure remediation depth on top of the shipped workflow pivots

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
