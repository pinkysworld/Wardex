# Changelog

All notable changes to Wardex are documented in this file.

## [0.28.0] — Research tracks UI, monitoring UX, and code review hardening

### Added
- **Research Tracks panel** — new admin console section displaying all 40 research tracks (R01–R40) grouped into 8 thematic categories, with expandable detail cards showing approach, rationale, and current state. Includes filter-by-status controls (Foundation/Scaffolded/Planned/Future) and live track count.
- **Research Tracks nav item** — dedicated navigation entry between Reports & Exports and Settings.

### Improved
- **Monitoring scope UX (Settings)** — the "Monitoring Scope" header now clearly indicates it applies to the **Main Server & Default for Agents**, with guidance text explaining that per-agent overrides are available in Fleet & Agents.
- **Per-agent monitoring scope layout (Fleet)** — replaced inline flex-wrap with a proper responsive grid layout (`grid-template-columns: repeat(auto-fill, minmax(170px, 1fr))`) for cleaner alignment of the 13 monitoring toggles. Improved description text to reference Settings → Monitoring Scope.

### Fixed
- **Critical: IIFE scope bug** — 11 inline `onclick` handlers referenced functions defined inside the IIFE closure, causing `ReferenceError` at runtime for Sigma Rules refresh, Case Management (refresh/new/submit/cancel), Alert Queue refresh, RBAC (add/refresh), and Feature Flags refresh. Replaced all inline `onclick` attributes with `addEventListener` wiring inside the IIFE.
- **XSS vulnerability** — dynamically generated `onclick` attributes for Alert Queue "Ack" and RBAC "Remove" buttons used single-quoted string literals that could be broken by crafted IDs/usernames. Replaced with `data-*` attribute event delegation pattern.
- **Missing CSS variables** — `--danger`, `--green`, and `--teal` were used but never defined in `:root`. Added definitions: `--danger: #ef4444`, `--green: #22c55e`, `--teal: #14b8a6`.
- **Missing CSS class** — `.dot-teal` was used in Case Management and Process Tree section headers but never defined. Added definition.

## [0.27.1] — Bug-fix: network burst false positives & RBAC admin bypass

### Fixed
- **Critical: macOS network byte overcounting** — `netstat -ib` lists each interface multiple times (once per address: Link, IPv4, IPv6, etc.) with identical cumulative byte counters. The collector summed all rows, inflating the metric by up to 9× on en0. Now only `<Link#N>` rows are counted, yielding accurate kbps values and eliminating cascading false "network burst" alerts.
- **RBAC admin token lockout** — after adding the first RBAC user, the admin token holder was denied sensitive operations (DELETE users, config, shutdown) because the RBAC enforcement checked `"admin-bootstrap"` which didn't exist in the user store. Admin token holders now bypass RBAC entirely.
- **Minimum column check** — macOS `collect_network()` now requires ≥ 10 columns (was 7), matching the actual `netstat -ib` layout.

### Added
- `tests/live_test.py` — comprehensive 77-endpoint live server test harness.
- `tests/verify_admin.py` — admin console data-shape verification script.

## [0.27.0] — Phase 27: Operational contract & production hardening

### Added
- **OpenAPI 3.0 specification** (`docs/openapi.yaml`) covering all 149 API endpoints with schemas, tags, and security annotations.
- **`GET /api/openapi.json`** — public endpoint serving the OpenAPI spec.
- **`GET /api/slo/status`** — service-level objective metrics (latency, error rate, availability, budget).
- **`POST /api/rbac/users`** and **`DELETE /api/rbac/users/{username}`** — RBAC user create/remove endpoints.
- **Schema lifecycle documentation** (`docs/SCHEMA_LIFECYCLE.md`) — versioning strategy, compatibility rules, migration process, fixture validation.
- **Disaster recovery plan** (`docs/DISASTER_RECOVERY.md`) — backup/restore procedures, RTO/RPO, key escrow, DR validation tests.
- **SLO policy** (`docs/SLO_POLICY.md`) — availability, latency, and error budget definitions with alerting rules.
- **Deployment models guide** (`docs/DEPLOYMENT_MODELS.md`) — standalone, multi-tenant, edge relay, regional federation.
- **Threat model** (`docs/THREAT_MODEL.md`) — promoted from handoff pack with adversary profiles, abuse cases, trust boundaries.
- **Production hardening checklist** (`docs/PRODUCTION_HARDENING.md`) — 59-control scorecard (47 implemented, 80%).
- **XDR professional roadmap** (`docs/ROADMAP_XDR_PROFESSIONAL.md`) — Tier 1–4 feature plan through Phase 36.
- Request counter (`request_count`, `error_count`) in server state for SLO computation.

### Fixed
- **Critical: `apiFetch()` undefined in admin console** — 16 call sites used an undefined function, making all newer admin sections non-functional. Defined proper `apiFetch()` helper.
- **Data-shape bugs in admin console** — `refreshSigma()`, `refreshRbac()`, `refreshCases()` now correctly unwrap server response objects (`.rules`, `.users`, `.cases`).
- **Sigma stats field name** — `stats.total_matches` → `stats.total_rules`.
- Separated server rate limiting into read/write/static buckets so authenticated admin polling no longer self-triggers `429 Too Many Requests` under normal use.
- Hardened the default CORS origin to `http://localhost` when `SENTINEL_CORS_ORIGIN` is unset.

### Changed
- Admin console `createCase()` upgraded from browser `prompt()` to professional inline form with priority, description, and tags.
- Admin console ARIA accessibility: skip-to-main link, `role` attributes, `aria-current` navigation, keyboard handlers, focus-visible styles.
- Copyright updated to 2025–2026.
- `generate_admin.py` deprecated — edit `site/admin.html` directly.
- Version bumped to 0.27.0; 160/160 backlog tasks complete; all 27 phases done.

## [Unreleased]

## [0.26.0] — Phase 26: Security audit fixes

### Fixed
- **RBAC enforcement on sensitive writes**: `check_rbac()` previously returned `true` on all paths, effectively bypassing role-based access control. Now uses `RbacStore::check_api_access()` to deny sensitive write operations when RBAC users are configured and the request lacks sufficient privileges.
- **RateLimiter memory leak**: The per-IP rate-limit bucket map never evicted stale entries, allowing unbounded memory growth from ephemeral client IPs. Added periodic cleanup that retains only entries active within the last 120 seconds.
- **Audit log status code accuracy**: `AuditLog::record()` was always called with a hardcoded `200` status. Now extracts the actual HTTP response status via `response.status_code().0` before recording.
- **Spool cipher counter overflow protection**: Upgraded the CTR-mode counter from `u64` to `u128` and switched from wrapping to `checked_add()` to prevent silent counter reuse (theoretical at `u64`, impossible at `u128`).

### Changed
- Version bumped to 0.26.0.

## [0.25.0] — Phase 25: Code review hardening, platform collectors, analyst console

### Added
- **Phase 23 — OCSF, Sigma, Response, Feature Flags, Process Tree, Spool, RBAC** (T188–T194):
  - `ocsf.rs`: OCSF event normalization with dead-letter queue for parse-rejected events, schema registry endpoint (`/api/ocsf/schema`, `/api/ocsf/schema/version`).
  - `sigma.rs`: 25 Sigma detection rules (SE-001 through SE-025) covering credential attacks, lateral movement, data exfiltration, cryptomining, privilege escalation, DNS tunneling, reverse shells, and more. `/api/sigma/rules` and `/api/sigma/stats` endpoints.
  - `response.rs`: Automated response engine with approval workflow, configurable playbooks, pending/audit/stats endpoints.
  - `feature_flags.rs`: Feature flag system with user/group/percentage targeting and A/B experiment support. `/api/feature-flags` endpoint.
  - `process_tree.rs`: Process tree analysis with deep-chain detection (depth ≥5), orphan tracking, and injection heuristics. `/api/process-tree` and `/api/process-tree/deep-chains` endpoints.
  - `spool.rs`: Encrypted local event spool with retry/dead-letter semantics. `/api/spool/stats` endpoint.
  - `rbac.rs`: Role-based access control with Admin/Operator/Analyst/Viewer roles and user management. `/api/rbac/users` endpoint.
- **Phase 24 — Platform collectors, analyst console, SIEM formats, DLQ wiring** (T195–T203):
  - `collector_windows.rs`: Windows collector with WMI queries, registry enumeration, and Windows Event Log parsing (13 tests).
  - `collector_linux.rs`: Linux collector with /proc filesystem, journalctl log parsing, and systemd service enumeration (19 tests).
  - `collector_macos.rs`: macOS collector with sysctl, IOKit power metrics, and unified log parsing (15 tests).
  - `siem.rs`: Added Elastic ECS (`format_elastic_ecs()`) and QRadar LEEF (`format_qradar()`) SIEM output formats alongside existing Splunk HEC.
  - `analyst.rs`: Full analyst console — case management (CRUD, status workflow, priority, assignee, timeline, tags), alert queue with acknowledgement and assignment, full-text event search with faceted filtering, investigation timeline builder, investigation graph with entity relationships, remediation approval workflow with audit trail. 20+ API endpoints.
  - Dead-letter queue wired into server API: `GET /api/dlq` (list), `GET /api/dlq/stats`, `DELETE /api/dlq` (drain).
  - 5 operational runbooks in `docs/runbooks/` (incident response, deployment, monitoring, troubleshooting, disaster recovery).
- **Phase 25 — Code review hardening** (T204–T207):
  - Replaced insecure XOR spool cipher with SHA-256 CTR mode (`spool_cipher`) for semantic security without additional dependencies.
  - Wired `AuditLog::record()` into HTTP request handler — every API call now records method, URL, source IP, status code, and auth flag.
  - Activated `check_rbac()` enforcement on sensitive write endpoints (`/api/config/`, `/api/shutdown`, `/api/updates/`, `/api/enforcement/`, `/api/rbac/`).
  - Removed `#[allow(dead_code)]` suppressions from `AuditLog`, `AuditLog::record()`, and `check_rbac()` in `server.rs`. Three platform-specific suppressions remain in `collector.rs` and `service.rs` (Linux-only fields).

### Changed
- Total modules: 58 (was 44).
- Total tests: 635 (521 unit + 114 integration), up from 437.
- Runtime manifest: 120/120 tasks, 25 phases.
- Version bumped to 0.25.0.

### Added
- **Per-agent monitoring scope**: Each enrolled agent can now have a custom monitoring scope override (CPU, memory, network, disk, processes, auth events, thermal, battery, file integrity, services, LaunchAgents, systemd units, scheduled tasks). `GET/POST /api/agents/{id}/scope` manages overrides; heartbeat responses now include the effective scope so agents can dynamically adjust collection.
- **Cross-platform scope gating**: All 13 monitoring signals in the collector are now individually gated by their respective scope toggle. Previously only 3 of 13 signals respected scope settings.
- **Bulk event triage**: `POST /api/events/bulk-triage` accepts an array of event IDs and applies status, assignee, tags, and notes to all in one call (max 500 events). The event table now has checkboxes for multi-select with a "Bulk Triage" button.
- **Deployment rollback**: `POST /api/updates/rollback` creates a new downgrade deployment targeting a previous release version with `allow_downgrade: true`. Rollback and Cancel buttons appear in the Agent Drilldown when a deployment is active.
- **Deployment cancellation**: `POST /api/updates/cancel` moves a pending deployment to `cancelled` status immediately.
- **Automatic staged rollout progression**: When `auto_progress` is enabled in rollout settings, completed canary deployments auto-progress to ring-1 after the configured soak period, and ring-1 auto-progresses to ring-2. Failed deployments trigger automatic rollback when `auto_rollback` is enabled.
- **Rollout configuration API**: `GET /api/rollout/config` returns current rollout settings; settings are patchable via the config reload endpoint with `{ "rollout": { ... } }`.
- **Admin UI rollout panel**: Auto-rollout settings (progression toggle, soak times, auto-rollback, max failures) are now configurable directly from the Fleet section.
- **Agent monitoring scope panel**: The Fleet section now includes a per-agent monitoring scope configuration panel with 13 toggles and server-default reset functionality.
- **Durable XDR event history**: Fleet events are now persisted to JSON on disk so analyst workflow and fleet history survive server restarts.
- **Event triage workflow**: `POST /api/events/{id}/triage` lets operators assign analysts, attach tags, add notes, and move events through `new`, `acknowledged`, `investigating`, `contained`, and `resolved` states.
- **Rollout controls for remote updates**: Remote deployments now support rollout groups (`direct`, `canary`, `ring-1`, `ring-2`) and explicit downgrade opt-in for controlled rollback scenarios.

### Changed
- **Fleet dashboard payload**: Dashboard analytics now include triage counts, event-history persistence status, and rollout-group summaries for deployments.
- **Admin console Fleet view**: Event Explorer now supports triage-state filtering, inline triage updates, bulk operations, and remote deployments expose rollout-group, rollback, and cancellation controls.
- **Heartbeat protocol**: Heartbeat responses now include `monitor_scope` with the effective monitoring scope for the agent (custom override or server default) and auto-rollout progression checks.
- **Public architecture section**: The GitHub Pages landing page now renders the pipeline stages as a responsive architecture board instead of a cramped horizontal strip.

## [0.23.0] — Fleet drilldowns and remote deployments

### Added
- **Remote agent update assignment**: Operators can now assign a published release to a specific enrolled agent. Assigned versions are surfaced in heartbeat responses and prioritized during agent update checks.
- **Agent drilldown API and UI**: Fleet now exposes per-agent detail views with recent event timelines, risk transitions, aggregate risk metrics, and pending deployment visibility.
- **Filtered event exploration and CSV export**: `GET /api/events` now supports agent, severity, reason, and correlation filters, and `GET /api/events/export` exports the filtered result set as CSV for incident triage.
- **Monitoring path health checks**: Settings now report whether active file-integrity and persistence baseline paths exist and are readable on the current host.

### Changed
- **Fleet dashboard payload**: The Fleet summary now includes recent release catalog data and pending deployment counts so the admin console can drive remote rollout actions directly.
- **Agent update client flow**: Agent downloads now resolve relative update URLs correctly and can react immediately to server-assigned deployment targets instead of waiting only for periodic polling.

## [0.22.0] — XDR analytics and monitoring visibility

### Added
- **Fleet event analytics**: XDR now computes top attack reasons, severity mix, hot-agent risk summaries, and fleet-wide correlation rate from agent event traffic.
- **Policy history visibility**: Admin console can now inspect published policy history instead of only the current active version.
- **Monitoring path visibility**: Settings now show the active file-integrity and persistence baseline paths derived from the current monitoring scope.

### Changed
- **Authenticated event reads**: `GET /api/events` and the new `GET /api/events/summary` now require admin auth while agent-side event ingestion remains tokenless for enrolled agents.
- **Fleet posture freshness**: Agent staleness is refreshed before agent-list and fleet-dashboard reads so XDR analytics use current status rather than stale cached values.

## [0.21.1] — Phase 24 follow-up

### Added
- **Scoped persistence baselines**: Service-persistence monitoring now baselines OS-specific startup locations for `systemd` units, macOS LaunchAgents/LaunchDaemons, and Windows Scheduled Tasks when enabled in Settings.
- **Per-platform operator guidance in Settings**: The Monitoring Scope panel now explains which monitoring points are recommended or unavailable on the current host and shows how many persistence baseline paths are active.

### Changed
- **Auth-event scope toggle is live**: Authentication-event collection is now a real configurable collector toggle instead of a read-only placeholder.
- **Local monitor baselines persist across samples**: File-integrity and persistence monitors now retain their baselines between server refresh cycles instead of being rebuilt on every sample.

## [0.21.0] — Phase 24

### Added
- **OS-aware monitoring scope settings**: Settings now expose a Monitoring Scope section driven by host platform and capability data. Operators can see what is monitored, what is recommended on the current OS, and which signals are planned but not yet available.
- **`GET /api/monitoring/options`**: New authenticated endpoint returns grouped monitoring options, support status, recommendations, and host metadata for the admin console.

### Fixed
- **Frontend auth regressions**: Settings loading, checkpoint counts, detection summary, and thread status requests now consistently send Bearer auth headers after Phase 23 hardening.
- **Alert detail stale reopen**: Manually closed alert detail rows no longer re-open on the next refresh because stale cached detail state is cleared correctly.
- **Live report summary counts**: `/api/report` now reports `critical_count` accurately instead of folding severe alerts into the critical total.
- **Config validation and hot reload semantics**: Negative severity thresholds are rejected, monitor intervals must be positive, numeric fields must be finite, and flat legacy patch fields now override nested objects predictably.
- **File-integrity scope control**: Local file-integrity monitoring now respects the configured monitoring scope instead of running whenever watch paths exist.

### Security
- **Additional sensitive GET endpoints now require auth**: `/api/checkpoints`, `/api/correlation`, `/api/monitoring/options`, and `/api/host/info` metadata are aligned with the authenticated admin-console contract.

## [0.20.0] — Phase 23

### Added
- **Alert sort by criticality**: Dropdown to sort alerts by Critical → Elevated or Elevated → Critical, in addition to default time order.
- **Alert detail survives refresh**: Open detail rows are preserved across auto-refresh cycles instead of being destroyed by table re-render.

### Fixed
- **False alarm suppression**: Raised `elevated_score` from 1.4 → 2.8 and `learn_threshold` from 1.35 → 2.5 so normal system noise (~2.0 score) no longer triggers constant "Elevated" alerts. Baseline now adapts to normal fluctuations instead of freezing.
- **Consecutive-sample confirmation**: Monitor thread requires 2 consecutive elevated-score samples before firing an alert. Critical/Severe bypass confirmation for immediate response.
- **Reports show live data**: `/api/report` now generates report from live monitoring alerts instead of falling back to demo sample data. Empty state returns an empty report rather than synthetic data.

### Security
- **Auth required on sensitive endpoints**: `GET /api/alerts`, `/api/alerts/count`, `/api/report`, `/api/status`, `/api/endpoints`, `/api/threads/status`, `/api/detection/summary`, and `/api/telemetry/*` now require Bearer token authentication. Only `/api/health` remains public.
- **Frontend sends auth headers**: All fetch calls (`refreshAlerts`, `refreshReport`, `refreshStatus`, `refreshTelemetry`, `refreshHostInfo`, `loadApiEndpoints`, `refreshHealth`) now include auth headers.

### Removed
- **Research Blueprint Coverage section** removed from the Help panel along with `renderTracks()` function and related state.

## [0.19.0] — Phase 22

### Added
- **Graceful shutdown via CLI and web console**: Real `ctrlc::set_handler()` for SIGINT/SIGTERM handling. `POST /api/shutdown` endpoint with auth and `server.unblock()` for clean exit. Shutdown button in Settings "Danger Zone" with double-confirmation dialog.
- **Expandable alert detail rows**: Click any alert row to reveal full telemetry snapshot (all 10 metrics) and detection analysis (score, confidence, all reasons, severity classification, recommendation). `GET /api/alerts/{index}` endpoint returns analysis JSON. Accordion-style collapsing (one open at a time).
- **Help section redesign**: Three categorised sections (Getting Started / Detection & Architecture / Reference) with improved spacing, line-height, and typography. All CLI commands and API references updated.
- **Alert detail API**: `GET /api/alerts/{index}` returns full telemetry, all detection reasons, severity class, multi-axis flag, and contextual recommendation.

### Security
- **JSON injection fixes**: Replaced `format!(r#"..."#)` string interpolation with `serde_json::json!()` in agent deregistration, fleet registration, threat-intel IOC, and mode-set endpoints.
- **Bounded body reads for chunked encoding**: New `read_body_limited()` helper using `std::io::Read::take()` enforces 10 MB limit even for chunked transfer encoding. All 17 request body reads migrated.
- **Sensitive GET endpoints require auth**: `/api/telemetry/current`, `/api/telemetry/history`, `/api/host/info`, `/api/config/current` now behind token authentication.
- **Auth on `/api/mesh/heal`**: POST endpoint added to auth-required list.
- **Consistent security headers**: `X-Frame-Options: DENY` on static files (was SAMEORIGIN), `Cache-Control: no-store` added to static responses.

### Changed
- `serve_loop` rewritten from blocking iterator to `recv_timeout(500ms)` + shutdown check loop for clean exit.
- `handle_api` accepts `server: &Server` parameter for shutdown coordination.
- `AppState` gains `shutdown: Arc<AtomicBool>` field.
- Runtime manifest updated to 109/109 tasks, 22 phases.
- Version bumped to 0.19.0.

## [0.18.0] — Phase 21

### Added
- **Velocity rate-of-change detector**: Tracks per-axis first derivative (velocity) and second derivative (acceleration) over a sliding window. Flags ramp-ups where the latest velocity exceeds mean + σ·std, even when absolute values remain below static thresholds. Configurable window size and sigma threshold.
- **Shannon entropy detector**: Computes per-axis entropy over a sliding window using histogram binning. Low entropy (<15% of max) flags constant attack traffic (cryptominers, DDoS floods). High entropy on auth-failures axis (>90%) flags randomised credential stuffing and evasion.
- **Compound multi-axis threat detector**: Counts simultaneously elevated axes and applies a score multiplier (`score × (1 + fraction × 0.5)`) when ≥40% of axes spike together. Detects coordinated attacks that spread across CPU, network, auth, disk, and temperature.
- **Detection analysis panel** in admin console: Threat Detection section now shows velocity, entropy, and compound detector configuration with live status from `/api/detection/summary`.
- **`GET /api/detection/summary`** endpoint returning velocity/entropy/compound detector state.
- **Help & Docs updates**: Three new detection method sections in the "How Detection Works" accordion.

### Security
- **Path traversal hardening**: `canonicalize()` validation on static file serving prevents symlink-based directory escape.
- **Request body size limit**: 10 MB cap on API request bodies with 413 rejection.
- **Security headers**: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store` on JSON responses; `X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`, and CORS headers on static file responses.
- **MIME type coverage**: Added `ico` and `woff2` content types.

### Changed
- Monitor thread now enriches EWMA signals with velocity, entropy, and compound analysis before alert threshold evaluation.
- Runtime manifest updated to 102/102 tasks, 21 phases.
- Version bumped to 0.18.0.

## [0.17.1] — Phase 20

### Added
- **Business Source License 1.1** (BSL 1.1): Free for development, testing, evaluation, and non-commercial use. Production commercial use requires a separate license. Converts to Apache 2.0 on 2029-04-01. See `LICENSE`.
- **Global collapsible activity log panel**: Docked to the bottom of the admin console across all views. Auto-expands when a new log entry arrives. Collapse/expand toggle and clear button. Replaces the Reports-only log area.
- **Icon-only responsive sidebar**: At ≤1024 px the sidebar collapses to 52 px width showing only icons. Hover CSS tooltip shows the full label. Full sidebar visible at >1024 px. Below 680 px the sidebar slides in/out as a drawer overlay (same as before).
- **Ctrl+K / ⌘+K keyboard shortcut**: Focuses the level filter in Reports & Exports, or the API token input on all other views. Also expands the activity log panel.

### Changed
- Version bumped to 0.17.1.
- `Cargo.toml`: `license` field changed from `"MIT"` to `license-file = "LICENSE"` (BSL 1.1).
- `README.md`: License section updated with BSL 1.1 explanation.
- `docs/STATUS.md`: Phase 19 and Phase 20 entries added. Summary updated to Phases 0–20.
- `site/index.html`: Footer updated to v0.17.0, Phase 0–19, 434 tests, BSL 1.1 link.
- Admin console footer now shows "BSL 1.1" with link to LICENSE file.

## [0.17.0]

### Added
- **Phase 19 — Professional admin console, local auto-monitoring, demo mode** (T164–T167).
- **Local system auto-monitoring** (T164): Background telemetry collection thread with 300-sample ring buffer. Server automatically monitors the host it runs on — no separate agent needed. Endpoints: `GET /api/telemetry/current`, `GET /api/telemetry/history`, `GET /api/host/info`, `GET /api/threads/status`.
- **Professional dark-themed admin console** (T165): Complete rewrite of `admin.html`. Dark theme with fixed sidebar navigation across 10 sections (Dashboard, Live Monitor, Threat Detection, Fleet & Agents, Security Policy, Incident Response, Infrastructure, Reports & Exports, Settings, Help & Docs). Canvas-based telemetry sparklines. Responsive layout with mobile sidebar toggle. Self-contained HTML with inline CSS/JS.
- **Demo mode** (T166): Client-side attack simulation toggle. Generates synthetic escalating telemetry (normal baseline → cryptominer + credential stuffing → critical) with real-time gauge and alert updates. No server-side state modification.
- **Comprehensive help & documentation** (T167): Accordion-based help section covering: what is monitored (10 telemetry axes explained), how detection works (EWMA, multi-axis scoring, modes, threat levels), XDR architecture, API reference (auto-loaded from endpoint listing), CLI commands, platform support, getting started guide, demo mode usage. Research Blueprint Coverage moved to Help section.

### Changed
- Version bumped to 0.17.0.
- Status manifest: 96/96 tasks, 19 phases (was 92/92, 18 phases).
- `#[allow(dead_code)]` annotation on `ServiceManager` struct to suppress `display_name` warning.

## [0.16.0]

### Added
- **Phase 18 — XDR fleet management with SIEM integration** (T157–T163).
- **Agent enrollment** (T157): `enrollment.rs` with token-based agent authentication, heartbeat tracking, staleness detection, file-backed JSON store. 5 tests.
- **Agent client** (T158): `agent_client.rs` for lightweight agent mode — enrollment, heartbeat, event forwarding, policy fetching, auto-update check/download/apply. 4 tests.
- **Event forwarding** (T159): `event_forward.rs` with cross-agent correlation (detects same anomaly across multiple agents within time window). 4 tests.
- **Policy distribution** (T160): `policy_dist.rs` with versioned policy bundles and rollback history. 3 tests.
- **Service installation** (T161): `service.rs` with cross-platform service installer — systemd (Linux), launchd (macOS), sc.exe (Windows). 5 tests.
- **SIEM integration** (T162): `siem.rs` with Splunk HEC, Elasticsearch bulk API, and generic JSON output; pull-based threat intel feed ingestion. 11 tests.
- **Agent auto-update** (T163): `auto_update.rs` with SHA-256 binary verification, semver comparison, path traversal protection. 5 tests.
- Central server + lightweight agent architecture: single binary runs as `wardex server` or `wardex agent`.
- XDR Fleet Dashboard in admin console with agent table, correlation alerts, enrollment token creation.
- 15+ new API endpoints for enrollment, heartbeat, event forwarding, policy distribution, SIEM status, fleet dashboard, update management.
- 8 new integration tests covering enrollment lifecycle, event ingestion, policy publish, SIEM status, fleet dashboard, and update checks.

### Changed
- Version bumped to 0.16.0.
- Total modules: 44 (was 37).
- Total tests: 434 (342 unit + 92 integration), up from 387.
- Status manifest: 92/92 tasks, 18 phases.

## [0.15.0]

### Added
- **Phase 17 — Cross-platform XDR agent with live monitoring** (T151–T156).
- **Host telemetry collector** (T151): `collector.rs` (~680 lines) with cross-platform OS detection (`HostPlatform` enum), live metric collection (CPU, memory, temperature, network, auth failures, battery, processes, disk pressure) via `/proc/`, `sysctl`, `vm_stat`, `wmic` dispatch, `FileIntegrityMonitor` with SHA-256 baselines, `AlertRecord` with syslog/CEF formatters. 12 unit tests.
- **Simplified startup** (T152): `cargo run` (no args) defaults to combined serve+monitor mode, `cargo run -- start` for explicit combined mode, `cargo run -- monitor` for CLI-only headless monitor. Auto-creates `var/wardex.toml` on first run. Ctrl+C graceful shutdown.
- **Webhook & alert output** (T153): `send_webhook()` via ureq, `--syslog` and `--cef` CLI flags for standard alert formats.
- **Server alert API & health** (T154): `GET /api/health` (version, uptime, platform), `GET /api/alerts` (last 100), `GET /api/alerts/count` (breakdown by severity), `DELETE /api/alerts` (clear), `GET /api/endpoints` (self-documenting), `POST /api/config/save` (persist to disk). Configurable CORS via `SENTINEL_CORS_ORIGIN` env var. 7 new integration tests.
- **Admin console panels** (T155): Live Monitoring panel with auto-polling alert table (3s), alert summary strip (total/critical/severe/elevated), health bar, CSV export. Settings panel with 6 config sections (Monitor, Notifications, File Integrity, Detection Tuning, Policy Thresholds, Server). Toast notification system. Token show/hide toggle.
- **Monitor config model** (T155): `MonitorSettings` struct in config.rs with interval, threshold, webhook, syslog, CEF, watch paths, dry-run, duration. Nested `ConfigPatch` support for admin console.

### Changed
- Version bumped to 0.15.0.
- ureq promoted from dev-dependencies to dependencies.
- Status manifest: 85/85 tasks, 17 phases.
- Total test count: 387 (303 unit + 84 integration), up from 369.

### Removed
- All hardcoded "2026" date references from source, docs, and site.
- AI tool entries from .gitignore.

## [0.14.0]

### Added
- **Phase 16 — Production hardening & self-healing** (T147–T150).
- **ML-DSA-65 post-quantum hybrid signatures** (T147): `MlDsaKeyPair` with deterministic signing, `HybridSignature` dual-verification (classical Lamport + PQ ML-DSA), `PqHybridCheckpoint` with `sign_checkpoint_hybrid()` / `verify_checkpoint_hybrid()`. 8 new tests.
- **TLS server configuration module** (T148): `TlsConfig` with cert/key paths, mTLS client CA, TLS version enforcement (1.2/1.3), cipher suite selection, Unix key-permission checks, `ListenerMode` abstraction. `GET /api/tls/status` endpoint. 10 unit + 1 integration test.
- **Zero-downtime config hot-reload** (T149): `ConfigPatch` partial-update struct, `apply()` with validation and automatic rollback on failure, `HotReloadResult`. `GET /api/config/current` and `POST /api/config/reload` endpoints. 3 unit + 4 integration tests.
- **Mesh self-healing topology** (T150): BFS spanning-tree computation, connected-component partition detection, repair proposal algorithm (AddEdge, PromoteRelay, Reroute), `SwarmNode::self_heal()` and `apply_repair()` methods. `GET /api/mesh/health` and `POST /api/mesh/heal` endpoints. 12 unit + 2 integration tests.

### Changed
- Version bumped to 0.14.0.
- Status manifest: 81/81 tasks, 16 phases (was 77/77, 15 phases).
- Total test count: 369 (292 unit + 77 integration), up from 329.

## [0.13.0]

### Added
- **Phase 15 — Integration test coverage & paper evaluation harnesses** (T142–T146).
- **49 new HTTP integration tests** (T142): covers all 40+ API endpoints including auth checks for every POST endpoint, bringing integration test count from 21 to 70.
- **Per-sample latency benchmark** (T143): `run_latency_benchmark()` in `src/benchmark.rs` with `LatencyStats` struct (mean, median, p95, p99, min, max in microseconds).
- **Audit chain scaling benchmark** (T143): `run_audit_scaling_benchmark()` measuring append + verify throughput at configurable chain lengths (10–100K records).
- **4 new benchmark unit tests**: latency measurement, audit scaling at 3 sizes, 10K-record audit chain, and 1K-sample latency target.
- **RESEARCH_TRACKS.md rewrite** (T144): all 40 tracks updated from stale (many marked "Future"/"Planned") to accurate "Implemented foundation" status with current repo state descriptions.
- **PAPER_TARGETS.md update** (T145): Paper 1 gap analysis updated (5 of 9 gaps now closed), Papers 2 and 3 prerequisites marked as met.

### Changed
- Version bumped to 0.13.0.
- Status manifest: 77/77 tasks, 15 phases (was 72/72, 14 phases).
- Total test count: 329 (259 unit + 70 integration), up from 276.

## [0.12.0]

### Added
- **Phase 14 — Full admin console integration** (T137–T141): Every feature module is now wired to the admin console with API endpoints and interactive UI panels.
- **18 new API endpoints** (T137): `/api/side-channel/status`, `/api/quantum/key-status`, `/api/quantum/rotate`, `/api/privacy/budget`, `/api/policy-vm/execute`, `/api/fingerprint/status`, `/api/harness/run`, `/api/monitor/status`, `/api/monitor/violations`, `/api/deception/status`, `/api/deception/deploy`, `/api/policy/compose`, `/api/drift/status`, `/api/drift/reset`, `/api/causal/graph`, `/api/patches`, `/api/offload/decide`, `/api/swarm/posture`, `/api/energy/harvest`.
- **Security Operations panel** (T138): enforcement status/quarantine, threat intel IOC management, side-channel risk display, deception engine deploy.
- **Fleet, Digital Twin & Testing panels** (T139): fleet device registration, swarm posture, digital twin simulation, adversarial harness execution.
- **Monitoring & Analysis panel** (T140): temporal monitor status/violations, correlation analysis, drift detection reset, fingerprint status, causal graph.
- **Compliance, Quantum, Policy, Infrastructure, Formal Exports panels** (T141): compliance scoring, attestation status, privacy budget, quantum key rotation, policy composition, WASM VM execution, energy harvest/consume, patch management, workload offload, TLA+/Alloy/witness export.
- `Monitor` `Predicate` trait now requires `Send` for thread-safe admin console state.

### Changed
- Version bumped to 0.12.0 (was 0.10.0 in Cargo.toml, 0.11.0 in changelog).
- Admin console expanded from 6 panels to 14 panels with full feature coverage.
- `AppState` expanded with 10 new module instances for complete feature wiring.

## [0.11.0]

### Added
- **Runtime pipeline wiring** (T132): All Phase 12 modules (threat intel, enforcement, digital twin, energy, side-channel, compliance) are now integrated into the `execute()` pipeline. Enrichment data (enforcement actions, TI matches, energy state, side-channel risk, compliance score) flows through the full pipeline and appears in console reports.
- **Criterion micro-benchmarks** (T133): `benches/pipeline.rs` with four benchmark groups — full pipeline scaling (5/50/200/1000 samples), detector evaluate, policy evaluate, and throughput measurement (~55K samples/sec). Unblocks Paper 1 evaluation methodology.
- **Continual learning loop** (T134): `DriftDetector` (Page-Hinkley algorithm) and `ContinualLearner` wrapper that monitors anomaly score distribution and automatically resets/re-learns the baseline when concept drift is detected. Advances R01 from foundation to research-grade.
- **Policy composition algebra** (T135): `CompositePolicy`, `compose_decisions()`, and `PolicyConflict` types supporting four composition operators (`MaxSeverity`, `MinSeverity`, `LeftPriority`, `RightPriority`) with conflict detection. Advances R39 and enables Paper 2 evaluation.
- 9 new unit tests (276 total: 255 unit + 21 integration).
- `RunResult` now includes `enforcement_actions`, `threat_intel_matches`, `energy_state`, `side_channel`, and `compliance_score` fields.
- Console report output includes enforcement, threat intel, energy, side-channel, and compliance summaries.

### Changed
- `ureq` dev-dependency now uses `default-features = false` to avoid `ring` build issues on some platforms.
- Pipeline throughput improved through integrated module wiring.

## [0.10.0]

### Added
- **Extended test fixtures** (T110): four 120-sample CSV datasets (benign, credential storm, slow escalation, low-battery attack) for paper evaluation.
- **Fixed-threshold baseline detector** (T111): static per-signal threshold detector in `fixed_threshold.rs` with `run_fixed_benchmark` for comparison against adaptive EWMA.
- **`bench` CLI command** (T112): head-to-head detector comparison printing precision/recall/F1/accuracy and throughput.
- **Per-signal contribution aggregation** (T113): `BenchmarkResult` now carries averaged per-signal attribution; printed by `bench` CLI.
- 11 new unit tests (147 total: 126 unit + 21 integration).
- New source module: `fixed_threshold.rs`.

### Changed
- CLI commands increased to 12 (added `bench`).
- `BenchmarkHarness` now tracks and averages per-signal contributions.

## [0.9.0]

### Added
- **Adapter-backed checkpoint restore** (T100): rollback now reapplies abstract device isolation/quarantine state via pluggable action adapters.
- **TLA+ and Alloy model export** (T101): `PolicyStateMachine::export_tla()` and `export_alloy()` produce formal verification modules; `/api/export/tla` and `/api/export/alloy` endpoints.
- **Proof backend interface** (T102): `DigestBackend` and `ZkStubBackend` with serializable witness export; `/api/export/witnesses` endpoint.
- **Single-source research-track data** (T103): canonical `research_tracks.json` consumed by runtime, API (`/api/research-tracks`), and admin console with static-file fallback.
- **Supply-chain attestation foundations** (T104): `BuildManifest` generation with SHA-256 artifact hashing, `TrustStore` management, manifest/artifact verification, `/api/attestation/status` endpoint.
- `export-model` and `attest` CLI commands.
- 31 new unit tests (115 unit + 21 integration).
- New source modules: `attestation.rs`, `proof.rs`.

### Changed
- CLI commands increased to 11 (added `export-model`, `attest`).
- Admin console `trackGroups` replaced with async `loadTrackGroups()` fetching from API/static JSON.

## [0.8.0]

### Added
- **Correlation engine integration** (T090): runtime `execute()` now runs Pearson correlation analysis on the replay buffer and includes results in audit logs and console output.
- **Temporal-logic monitor integration** (T091): runtime pipeline feeds sample, alert, action, and transition events to a default safety monitor; violations are reported in audit and console output.
- **Correlation API endpoint** (T092): `GET /api/correlation` returns live correlation analysis of samples seen by the server-side replay buffer.
- **Harness CLI command** (T093): `cargo run -- harness` runs the adversarial test harness and prints evasion rates and coverage metrics.
- **Behavioural device fingerprinting** (T094): new `fingerprint.rs` module with `DeviceFingerprint` training from telemetry windows and Mahalanobis-inspired impersonation detection (R38).
- Server-side replay buffer in `AppState` — analyzed and demo samples are pushed to a 200-sample ring buffer for live correlation.
- 8 new unit tests across `runtime`, `fingerprint` modules (105 total: 91 unit + 14 integration).
- New source module: `fingerprint.rs`.

### Changed
- `CorrelationResult` and `CorrelatedPair` fields changed from `&'static str` to `String` for serde compatibility.
- CLI commands increased to 9 (added `harness`).
- R38 research track status updated from "future" to "foundation".

### Fixed
- JSONL line numbers in `/api/analyze` now enumerate before filter so errors report original file positions (CQ-12).
- `observed_samples` in detector uses `saturating_add` to prevent overflow (CQ-13).
- State machine `step()` validates transitions via `is_legal()` before accepting (CQ-14).
- Fingerprint standard deviation uses Bessel's correction (n−1) to avoid inflated z-scores with small sample counts (CQ-16).
- `DeviceFingerprint::train()` returns `None` if NaN/Inf propagates through computation (CQ-17).
- Temporal-logic monitor now receives state machine transition events so `no_skip_escalation` property is exercised (CQ-20).

## [0.7.0]

### Added
- **Explainable anomaly attribution** (T080): per-signal contribution breakdown in `AnomalySignal` — each signal dimension's weighted score contribution is captured and included in JSON reports.
- **Config validation** (T081): `Config::validate()` checks threshold ordering (critical > severe > elevated), smoothing in [0.0, 1.0], non-zero warmup, and checkpoint interval. Called automatically on config load.
- **Anomaly correlation engine** (T082): Pearson-based multi-signal co-movement detection across replay buffer windows with co-rising signal identification.
- **Temporal-logic runtime monitor** (T083): lightweight SentinelTL property checker supporting safety (`always P`) and bounded-liveness (`within N samples P`) properties over live event streams.
- **Adversarial test harness** (T084): grammar-based evasion fuzzer with SlowDrip, BurstMask, and DriftInject strategies, decision-surface coverage metrics, and evasion rate measurement.
- 27 new unit tests across `detector`, `config`, `correlation`, `monitor`, and `harness` modules (96 total: 82 unit + 14 integration).
- Three new source modules: `correlation.rs`, `monitor.rs`, `harness.rs`.

## [0.6.0]

### Added
- 14 end-to-end HTTP API integration tests (`tests/api_integration.rs`)
- 10,000-sample benchmark test validating detector performance at scale
- Auto-refresh exponential backoff with resume button in admin console
- Research-track status table (40 tracks) in admin console with badge styling
- Collapsible partially-wired and not-implemented detail lists in status panel
- `FEATURES.md` one-page marketing summary
- `CHANGELOG.md`

### Changed
- CI matrix expanded to Linux, macOS, and Windows with `cargo clippy` and `cargo fmt`
- Version bumped from 0.1.0 to 0.6.0; license set to MIT
- Analyze and run-demo endpoints now feed the live detector baseline (enables meaningful checkpoints)
- Server request loop extracted into `serve_loop` with `spawn_test_server` for integration testing
- `StatusManifest` now includes `research_tracks` field with all 40 R-tracks

### Fixed
- Checkpoint save returned 0 on fresh detector — now works after any analysis run
- `PersistedBaseline` now persists `process_count` and `disk_pressure_pct` (previously lost on checkpoint restore)
- CSV header detection uses exact match against known headers instead of fragile alphabetic heuristic
- Removed panicking `unwrap()` on JSON round-trips in run-demo and analyze handlers; store `JsonReport` directly
- Three endpoints now return HTTP 500 on serialization failure instead of empty 200 responses
- CSV parse error messages now report correct original line numbers
- `auth_burst_detected()` uses `u64` accumulator to prevent overflow on large `auth_failures` sums
- Ring buffers (`ReplayBuffer`, `CheckpointStore`) guard against capacity=0 edge case
- `ProofRegistry::verify()` renamed to `contains()` to avoid implying cryptographic verification
- `network_kbps` and `temperature_c` now reject NaN and Infinity values during validation
- `decay_rate` parameter validated (must be finite, 0.0–1.0) in `/api/control/mode` endpoint
- Admin console enforces 10 MB file size limit on uploads

## [0.5.0]

### Added
- Checkpoint save/restore via API (3 new endpoints)
- CSV report export from admin console
- Threat-level filter dropdown in admin console
- Improved connection error messages (auth failure, server offline, HTTP codes)
- Auto-detecting CSV column count (8 or 10 columns)
- 2 new checkpoint restore tests (54 total unit tests)

### Fixed
- CLI command count corrected to 8 across all files
- Redundant CSV parsing in analyze endpoint removed

## [0.4.0]

### Added
- Admin console auto-refresh (5 s polling) with connection status indicator
- Drag-and-drop JSONL/CSV file upload for custom analysis
- Decay rate slider for adaptation control
- Dark mode support via `prefers-color-scheme: dark`
- CORS hardened to `http://localhost` with `Vary: Origin`

## [0.3.0]

### Added
- All 17 Rust modules with 52 unit tests
- 10-stage pipeline: ingest → parse → detect → decide → act → audit → checkpoint → replay → benchmark → report
- HTTP server with token-authenticated REST API
- Browser admin console and GitHub Pages site
- 8 CLI commands (demo, analyze, report, init-config, status, status-json, serve, help)
- Research documents for phases 5–7 (40 tracks across 7 categories)
