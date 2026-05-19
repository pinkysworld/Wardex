# Wardex — Production & Commercial Readiness Implementation Plan

> Generated: 2026-04-05 | Baseline: v0.39.5 | 16 tasks across 3 phases

> Historical note (2026-04-25): this plan is retained as an implementation archive for the v0.39.5 readiness push. Current release state and priorities live in `docs/STATUS.md`, `docs/ROADMAP_XDR_PROFESSIONAL.md`, `docs/PROJECT_BACKLOG.md`, and `docs/FEATURE_UI_COVERAGE.md`.

## How to use this plan

Each phase contains numbered tasks. Each task is self-contained with:
- **What**: Clear description of the change
- **Where**: Exact files to modify/create
- **How**: Step-by-step implementation instructions
- **Verify**: How to confirm it works

Hand any task to Claude/Codex with: *"Implement task X.Y from this plan in the Wardex project"*

---

## Phase A: Foundation for First Customers (v0.40–0.42)

### A.1 — Replace tiny_http with axum (async HTTP server)

**What:** The current `server.rs` (11,785 lines) uses synchronous `tiny_http`. A slow query blocks all other requests. Replace with `axum` (tokio-based async) to unblock all future work.

**Where:**
- `Cargo.toml` — add `axum`, `tokio`, `tower`, `tower-http`; remove `tiny_http`
- `src/server.rs` — full rewrite as axum router with extractors
- `src/main.rs` — switch to `#[tokio::main]` async entry point
- `src/ws_stream.rs` — migrate WebSocket to axum's built-in WS support

**How:**
1. Add dependencies to `Cargo.toml`:
   ```toml
   axum = "0.8"
   tokio = { version = "1", features = ["full"] }
   tower = "0.5"
   tower-http = { version = "0.6", features = ["cors", "trace", "limit"] }
   ```
2. Create `src/routes/` module directory with sub-modules mirroring the current endpoint groups:
   - `routes/health.rs` — `/api/health`, `/api/healthz/ready`, `/api/healthz/live`
   - `routes/auth.rs` — `/api/auth/*`
   - `routes/alerts.rs` — `/api/alerts/*`
   - `routes/events.rs` — `/api/events/*`
   - `routes/fleet.rs` — `/api/fleet/*`
   - `routes/policy.rs` — `/api/policy/*`
   - `routes/incidents.rs` — `/api/incidents/*`
   - `routes/cases.rs` — `/api/cases/*`
   - `routes/response.rs` — `/api/response/*`
   - `routes/compliance.rs` — `/api/compliance/*`
   - `routes/siem.rs` — `/api/siem/*`
   - `routes/admin.rs` — `/api/admin/*`
   - `routes/config.rs` — `/api/config/*`
   - `routes/graphql.rs` — `/api/graphql`
   - `routes/static_files.rs` — static file serving for admin console
3. Convert the shared `AppState` (currently `Arc<Mutex<...>>` structs) into an axum `State` extractor. Keep the `Arc<Mutex<>>` pattern but wrap in a single `AppState` struct.
4. Convert each endpoint handler from the current pattern:
   ```rust
   // OLD: manual request parsing in server.rs
   if path == "/api/alerts" && method == "GET" { ... }
   ```
   to axum handlers:
   ```rust
   // NEW: axum handler
   async fn list_alerts(State(state): State<AppState>, Query(params): Query<AlertQuery>) -> Json<Vec<Alert>> { ... }
   ```
5. Migrate rate limiting from manual per-IP tracking to `tower::ServiceBuilder` with `tower-http::limit`.
6. Migrate static file serving to `tower-http::services::ServeDir`.
7. Migrate WebSocket from manual RFC 6455 framing to `axum::extract::ws::WebSocket`.
8. Update `main.rs` to use `#[tokio::main]` and `axum::serve()`.
9. Migrate TLS from manual rustls setup to `axum_server::tls_rustls`.

**Verify:**
- `cargo test` — all 1,145 tests pass (update integration tests to use async client)
- `cargo run -- serve` starts on port 8080
- All existing API endpoints respond correctly
- WebSocket streaming works
- Admin console loads and functions

**Estimated scope:** This is the largest single task. ~11K lines of server.rs need to be decomposed. Break into sub-tasks:
- (A.1a) set up axum skeleton + health endpoints
- (A.1b) migrate auth + alerts
- (A.1c) migrate remaining endpoints
- (A.1d) migrate WebSocket + static files
- (A.1e) remove tiny_http

---

### A.2 — OIDC/SAML SSO for Admin Console

**What:** Replace token-in-localStorage auth with real OIDC SSO. Support Okta, Azure AD (Entra), Google Workspace, and generic OIDC providers.

**Where:**
- `Cargo.toml` — add `openidconnect`, `jsonwebtoken`
- `src/auth.rs` (new) — OIDC token exchange, JWK validation, session management
- `src/routes/auth.rs` — SSO callback endpoint, session endpoints
- `src/rbac.rs` — add group-to-role mapping
- `admin-console/src/hooks.jsx` — replace token auth with OIDC redirect flow
- `admin-console/src/components/Auth.jsx` (new or modify existing) — login page with IdP selection

**How:**
1. Add server-side OIDC support:
   ```toml
   openidconnect = "4"
   jsonwebtoken = "9"
   ```
2. Create `src/auth.rs`:
   - `OidcConfig` struct: issuer URL, client ID, client secret, redirect URI, allowed groups
   - `discover_provider()` — fetch `.well-known/openid-configuration`
   - `build_auth_url()` — generate authorization URL with PKCE code challenge
   - `exchange_code()` — exchange authorization code for tokens
   - `validate_id_token()` — verify JWT signature using JWK set, check claims (iss, aud, exp, nonce)
   - `extract_groups()` — pull group claims from ID token for role mapping
   - `SessionStore` — in-memory session store with TTL (keyed by opaque session ID, stores user info + role + expiry)
3. Add config section to `wardex.toml`:
   ```toml
   [auth]
   mode = "token"  # "token" (current) | "oidc"
   [auth.oidc]
   issuer = "https://login.microsoftonline.com/{tenant}/v2.0"
   client_id = "..."
   client_secret = "..."
   redirect_uri = "https://wardex.example.com/auth/callback"
   scopes = ["openid", "profile", "email", "groups"]
   [auth.oidc.group_mapping]
   "Security-Admins" = "admin"
   "SOC-Analysts" = "analyst"
   "SOC-Viewers" = "viewer"
   ```
4. Add routes:
   - `GET /auth/login` — redirect to IdP with PKCE
   - `GET /auth/callback` — exchange code, create session, set cookie, redirect to console
   - `GET /auth/session` — return current session info (user, role, expiry)
   - `POST /auth/logout` — destroy session
5. Keep existing token auth as fallback (`auth.mode = "token"`) for API-only / headless use.
6. Update admin console:
   - If `auth.mode === "oidc"`: redirect to `/auth/login` on 401
   - Store session cookie (HttpOnly, Secure, SameSite=Strict) instead of token in localStorage
   - Add IdP selection on login page if multiple providers configured
   - Add user info display in console header (name, role, logout button)
7. Add SCIM provisioning endpoint:
   - `POST /scim/v2/Users` — create user with role from group mapping
   - `PUT /scim/v2/Users/{id}` — update user
   - `DELETE /scim/v2/Users/{id}` — deactivate user

**Verify:**
- Configure with a test Okta/Azure AD tenant
- Login redirects to IdP, callback creates session, console loads with correct role
- Group-to-role mapping works (admin group -> admin role)
- Token auth still works when `auth.mode = "token"`
- Logout destroys session

---

### A.3 — Wire Cloud Collectors to Real APIs

**What:** The AWS/Azure/GCP collectors (`collector_aws.rs`, `collector_azure.rs`, `collector_gcp.rs`) have event parsers but make no actual API calls. Wire them to real cloud APIs.

**Where:**
- `src/collector_aws.rs` — add CloudTrail, GuardDuty, Security Hub API calls
- `src/collector_azure.rs` — add Azure Monitor, Defender, Activity Log API calls
- `src/collector_gcp.rs` — add Cloud Audit Logs, SCC findings API calls
- `src/config.rs` — add cloud collector config sections
- `Cargo.toml` — `ureq` is already a dependency; add `aws-sigv4` for AWS signing

**How:**
1. **AWS CloudTrail collector:**
   - Add `aws-sigv4 = "1"` and `aws-credential-types = "1"` to Cargo.toml
   - Implement `CloudTrailPoller` struct with:
     - `poll()` — call `LookupEvents` API with SigV4 signing using `ureq`
     - Pagination via `NextToken`
     - Map CloudTrail events to existing `AwsEvent` struct (already defined)
     - Error handling with exponential backoff (1s, 2s, 4s, max 60s)
   - Add GuardDuty `ListFindings` + `GetFindings` polling
   - Add Security Hub `GetFindings` polling (ASFF format)
   - Config:
     ```toml
     [collector.aws]
     enabled = true
     region = "us-east-1"
     access_key_id = "..."
     secret_access_key = "..."
     poll_interval_secs = 300
     services = ["cloudtrail", "guardduty", "securityhub"]
     ```

2. **Azure collector:**
   - Implement OAuth2 client credentials flow for Azure AD token (using `ureq` POST to `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`)
   - `AzurePoller` with:
     - Activity Log: `GET https://management.azure.com/subscriptions/{sub}/providers/Microsoft.Insights/eventtypes/management/values`
     - Defender alerts: `GET https://management.azure.com/subscriptions/{sub}/providers/Microsoft.Security/alerts`
     - Map to existing `AzureEvent` struct
   - Config:
     ```toml
     [collector.azure]
     enabled = true
     tenant_id = "..."
     client_id = "..."
     client_secret = "..."
     subscription_id = "..."
     poll_interval_secs = 300
     ```

3. **GCP collector:**
   - Implement service account JWT auth (sign JWT with service account key, exchange for access token)
   - `GcpPoller` with:
     - Cloud Audit Logs: `POST https://logging.googleapis.com/v2/entries:list`
     - Security Command Center: `GET https://securitycenter.googleapis.com/v1/organizations/{org}/sources/-/findings`
     - Map to existing `GcpEvent` struct
   - Config:
     ```toml
     [collector.gcp]
     enabled = true
     project_id = "..."
     service_account_key_path = "/path/to/key.json"
     poll_interval_secs = 300
     ```

4. Wire collectors into the main runtime loop with configurable poll intervals.

**Verify:**
- Unit tests with mock HTTP responses for each cloud API
- Integration test with real credentials (mark as `#[ignore]` for CI)
- Events appear in the event store and admin console
- Rate limiting and backoff work correctly

---

### A.4 — Expand Sigma Rule Library to 200+

**What:** Increase from 39 built-in Sigma rules to 200+ covering critical detection scenarios across Windows, Linux, cloud, and identity.

**Where:**
- `src/sigma_library.rs` — add new rule definitions
- `rules/` directory — add YAML rule files
- `src/sigma.rs` — add Sigma rule import from YAML files on disk

**How:**
1. Add a `load_rules_from_directory(path: &str)` function to `sigma.rs` that loads `.yml` files from a directory and parses them into `SigmaRule` structs. This enables user-supplied rules alongside built-in ones.
2. Add 160+ new built-in rules in `sigma_library.rs` covering:
   - **Windows (60 rules):** Mimikatz, PsExec, WMI persistence, scheduled task abuse, DLL sideloading, LSASS access, Kerberoasting, DCSync, pass-the-hash, PowerShell obfuscation, AMSI bypass, event log clearing, shadow copy deletion, UAC bypass, registry run key persistence
   - **Linux (40 rules):** Reverse shell detection, crontab persistence, SSH key injection, sudo abuse, container escape, kernel module loading, LD_PRELOAD injection, /etc/passwd modification, auditd tampering, eBPF abuse
   - **Cloud/AWS (25 rules):** IAM policy change, console login without MFA, S3 bucket policy change, CloudTrail disabled, security group change, root account usage, cross-account access, Lambda backdoor
   - **Cloud/Azure (20 rules):** Conditional access policy change, PIM role activation, service principal credential add, diagnostic settings deletion, NSG rule change
   - **Identity (15 rules):** Brute force, password spray, impossible travel, MFA fatigue, service account anomaly, privilege escalation, group membership change
3. Map each rule to MITRE ATT&CK technique IDs.
4. Add a `wardex import-rules <path>` CLI command that imports a directory of Sigma YAML files.

**Verify:**
- `cargo test` — all rules parse and evaluate correctly
- Each rule has at least one test case (positive match)
- `wardex import-rules rules/` loads external rules
- MITRE coverage view in admin console shows increased coverage

---

### A.5 — License Key Management

**What:** Generate and validate signed license keys that encode tier, expiry, seat count, and feature entitlements. Wire into feature flags.

**Where:**
- `src/license.rs` (new) — license key generation, validation, and enforcement
- `src/feature_flags.rs` — connect feature gates to license claims
- `src/multi_tenant.rs` — enforce resource quotas based on license
- `src/config.rs` — add license key config field
- `src/routes/admin.rs` — add license status endpoint

**How:**
1. Create `src/license.rs`:
   - License key format: base64-encoded JSON payload + Ed25519 signature
   - Payload:
     ```json
     {
       "id": "lic_abc123",
       "tier": "enterprise",
       "org": "Acme Corp",
       "max_agents": 100,
       "max_users": 50,
       "features": ["sso", "multi_tenant", "compliance", "playbooks"],
       "issued_at": "2026-04-05T00:00:00Z",
       "expires_at": "2027-04-05T00:00:00Z"
     }
     ```
   - `generate_license(payload, signing_key) -> String` — sign with Ed25519 private key
   - `validate_license(key, public_key) -> Result<LicenseClaims>` — verify signature, check expiry
   - `LicenseEnforcer` — middleware that checks license on startup and periodically (every hour)
   - Grace period: 14 days after expiry before hard lock (read-only mode)
2. Add to `wardex.toml`:
   ```toml
   [license]
   key = "eyJ..."
   ```
3. Wire into `feature_flags.rs`:
   - `is_feature_enabled(name)` checks both feature flags AND license entitlements
   - Unlicensed features return 403 with message: "This feature requires an Enterprise license"
4. Wire into `multi_tenant.rs`:
   - `ResourceQuota` limits enforced based on `max_agents`, `max_users` from license
   - Soft limit warning at 90% usage, hard limit at 100%
5. Add CLI command: `wardex license generate --tier enterprise --org "Acme" --agents 100 --expires 2027-04-05 --signing-key /path/to/key`
6. Add API endpoints:
   - `GET /api/license` — current license status (tier, expiry, usage vs limits)
   - `POST /api/license` — apply new license key
7. Add license status widget to admin console Dashboard.

**Verify:**
- Generate a license, apply it, verify feature gates work
- Expired license enters grace period -> read-only mode after 14 days
- Exceeding agent limit blocks new enrollments with clear error
- License status visible in admin console

---

### A.6 — Admin Console: React Router + RBAC Views

**What:** Replace hash-based navigation with React Router. Filter views based on user role.

**Where:**
- `admin-console/package.json` — add `react-router-dom`
- `admin-console/src/App.jsx` — replace hash routing with React Router
- `admin-console/src/hooks.jsx` — add role-aware context provider
- All component files — wrap in role guards

**How:**
1. Install: `npm install react-router-dom`
2. Replace the current `section` state + hash listener in `App.jsx` with React Router:
   ```jsx
   <BrowserRouter>
     <Routes>
       <Route path="/" element={<Dashboard />} />
       <Route path="/monitor" element={<LiveMonitor />} />
       <Route path="/detection" element={<ThreatDetection />} />
       <Route path="/fleet" element={<FleetAgents />} />
       <Route path="/policy" element={<SecurityPolicy />} />
       <Route path="/soc" element={<SOCWorkbench />} />
       <Route path="/infrastructure" element={<Infrastructure />} />
       <Route path="/reports" element={<ReportsExports />} />
       <Route path="/settings" element={<RequireRole role="admin"><Settings /></RequireRole>} />
       <Route path="/help" element={<HelpDocs />} />
     </Routes>
   </BrowserRouter>
   ```
3. Create `RequireRole` wrapper component:
   ```jsx
   function RequireRole({ role, children }) {
     const { userRole } = useAuth();
     if (!hasPermission(userRole, role)) return <AccessDenied />;
     return children;
   }
   ```
4. Fetch user role from `GET /auth/session` (or `/api/session/info` for token auth) on app load. Store in React context.
5. Role-based visibility rules:
   - **Admin**: All sections visible
   - **Analyst**: Dashboard, Monitor, Detection, Fleet (read), SOC Workbench, Reports — Settings hidden
   - **Viewer**: Dashboard, Monitor (read-only), Reports — no mutation actions, no Settings
   - **ServiceAccount**: Not applicable (API-only)
6. Hide mutation buttons (Create, Delete, Execute, Approve) from Viewer role.
7. Update sidebar navigation to only show sections the user has access to.
8. Update Vite config to support HTML5 history mode (SPA fallback).

**Verify:**
- Direct URL navigation works (e.g., `/soc` loads SOC Workbench)
- Browser back/forward works
- Admin sees all sections; Analyst sees limited set; Viewer is read-only
- Bookmarks work

---

### A.7 — Demo Environment with Seed Data

**What:** Docker Compose setup that boots Wardex pre-populated with realistic data for demos and trials.

**Where:**
- `demo/docker-compose.yml` (new)
- `demo/seed.sh` (new) — script that populates data via API
- `demo/seed-data/` (new) — JSON files with sample alerts, incidents, agents, rules
- `src/routes/admin.rs` — add `POST /api/admin/seed` endpoint (dev/demo mode only)

**How:**
1. Create `demo/docker-compose.yml`:
   ```yaml
   services:
     wardex:
       build: ..
       ports: ["8080:8080"]
       environment:
         WARDEX_MODE: demo
         WARDEX_SEED: "true"
       volumes:
         - wardex-data:/app/var
   ```
2. Create seed data files:
   - `seed-data/alerts.json` — 50 alerts across severity levels (critical: ransomware, severe: lateral movement, elevated: brute force, low: policy violation)
   - `seed-data/incidents.json` — 5 incidents with storylines, related events, evidence
   - `seed-data/agents.json` — 10 agents (mix of Linux/macOS/Windows, healthy + stale)
   - `seed-data/cases.json` — 3 cases in different states (new, investigating, resolved)
   - `seed-data/sigma_rules.json` — 20 active rules with recent match history
   - `seed-data/threat_intel.json` — 30 IoCs from realistic threat feeds
3. Create `demo/seed.sh` that uses `curl` to POST seed data to API endpoints after server starts.
4. Add `--seed` flag to `wardex serve` that loads seed data on startup.
5. Add a demo banner in the admin console when running in demo mode.

**Verify:**
- `docker compose up` in `demo/` boots and populates in <60 seconds
- Admin console shows realistic data on all pages
- Detection, SOC Workbench, Fleet, and Dashboard all have content
- Demo mode clearly indicated in UI

---

### A.8 — Backup Automation

**What:** Scheduled database backups with retention management and verification.

**Where:**
- `src/backup.rs` (new) — backup scheduler, SQLite `.backup` API, verification
- `src/storage.rs` — expose SQLite `.backup` method
- `src/config.rs` — add backup config section
- `src/routes/admin.rs` — backup API endpoints

**How:**
1. Create `src/backup.rs`:
   - `BackupScheduler` — runs on configurable interval (default: daily at 02:00)
   - `create_backup()` — uses SQLite online backup API to create consistent snapshot
   - Backup contents: SQLite DB file + `var/` config files, compressed with gzip
   - Naming: `wardex-backup-{timestamp}.tar.gz`
   - Retention: keep last N backups (configurable, default: 7)
   - Verification: after backup, open the backup DB and run `PRAGMA integrity_check`
   - SHA-256 checksum file alongside each backup
2. Config:
   ```toml
   [backup]
   enabled = true
   schedule = "0 2 * * *"  # cron format: daily at 2am
   retention_count = 7
   path = "var/backups/"
   ```
3. API endpoints:
   - `POST /api/admin/backup` — trigger immediate backup
   - `GET /api/admin/backups` — list available backups (name, size, timestamp, checksum)
   - `POST /api/admin/restore` — restore from a specific backup (requires admin + confirmation token)
   - `DELETE /api/admin/backups/{name}` — delete a specific backup
4. Add backup status to admin console Settings > Database section.

**Verify:**
- Scheduled backup creates valid archive at configured time
- `POST /api/admin/backup` triggers immediate backup
- Restore from backup produces identical database state
- Old backups are pruned after retention_count exceeded
- Integrity check catches corrupt backups

---

## Phase B: Scale Foundation (v0.43–0.45)

### B.1 — ClickHouse for Event/Time-Series Storage

**What:** Add ClickHouse as the primary event store for high-volume telemetry. Keep SQLite for config, cases, audit.

**Where:**
- `Cargo.toml` — add `clickhouse` client crate
- `src/storage_clickhouse.rs` (new) — ClickHouse storage adapter
- `src/storage.rs` — add storage backend abstraction trait
- `src/config.rs` — add ClickHouse config section
- `deploy/docker-compose.yml` — add ClickHouse service

**How:**
1. Add `clickhouse = "0.13"` to Cargo.toml (native async ClickHouse client).
2. Define a `StorageBackend` trait in `storage.rs`:
   ```rust
   trait EventStore: Send + Sync {
       async fn insert_events(&self, events: &[OcsfEvent]) -> Result<()>;
       async fn query_events(&self, filter: &EventFilter) -> Result<Vec<OcsfEvent>>;
       async fn count_events(&self, filter: &EventFilter) -> Result<u64>;
       async fn aggregate(&self, query: &AggregationQuery) -> Result<AggregationResult>;
       async fn purge_before(&self, timestamp: DateTime) -> Result<u64>;
   }
   ```
3. Implement `ClickHouseEventStore`:
   - Table schema optimized for time-series queries:
     ```sql
     CREATE TABLE events (
       timestamp DateTime64(3),
       tenant_id String,
       event_class UInt16,
       severity UInt8,
       device_id String,
       user_name String,
       process_name String,
       src_ip String,
       dst_ip String,
       raw_json String
     ) ENGINE = MergeTree()
     PARTITION BY toYYYYMM(timestamp)
     ORDER BY (tenant_id, timestamp, event_class)
     TTL timestamp + INTERVAL 90 DAY
     ```
   - Materialized views for pre-aggregated dashboards (alerts per hour, top sources, severity breakdown)
   - Batch inserts (buffer 1,000 events or 5 seconds, whichever comes first)
4. Keep `SqliteStore` as the implementation for config, cases, audit, and fleet state.
5. Config:
   ```toml
   [storage]
   event_backend = "clickhouse"  # "sqlite" (default) | "clickhouse"
   [storage.clickhouse]
   url = "http://localhost:8123"
   database = "wardex"
   username = "default"
   password = ""
   batch_size = 1000
   flush_interval_secs = 5
   ```
6. Add ClickHouse to `deploy/docker-compose.yml`:
   ```yaml
   clickhouse:
     image: clickhouse/clickhouse-server:24.3
     ports: ["8123:8123", "9000:9000"]
     volumes: ["clickhouse-data:/var/lib/clickhouse"]
   ```

**Verify:**
- Events ingest into ClickHouse with batch buffering
- Event search queries return results from ClickHouse
- Dashboard aggregations are fast (<100ms for 1M events)
- TTL-based retention works
- Falls back to SQLite when `event_backend = "sqlite"`

---

### B.2 — Async Event Pipeline with Backpressure

**What:** Decouple the event processing pipeline using async channels with backpressure.

**Where:**
- `src/pipeline.rs` (new) — async event pipeline with stages
- `src/runtime.rs` — replace synchronous `execute()` with pipeline submission
- `src/detector.rs` — make detection async-compatible

**How:**
1. Create `src/pipeline.rs` with a staged pipeline:
   ```
   Ingest -> Normalize -> Enrich -> Detect -> Store -> Forward
   ```
   Each stage is a tokio task connected by bounded `mpsc` channels (backpressure when channel full).
2. Pipeline stages:
   - **Ingest**: Accept events from HTTP API, agent heartbeats, cloud collectors, syslog. Push to normalize channel.
   - **Normalize**: OCSF normalization (already in `ocsf.rs`). Extract entities. Push to enrich channel.
   - **Enrich**: Threat intel lookup, GeoIP, asset context. Push to detect channel.
   - **Detect**: Run Sigma rules, anomaly detector, UEBA scoring. Generate alerts. Push events to store channel, alerts to alert channel.
   - **Store**: Write to ClickHouse (events) and SQLite (alerts). Batch writes.
   - **Forward**: Push to SIEM endpoints, WebSocket subscribers, notification channels.
3. Backpressure: Channel capacity = 10,000. When full, ingest stage returns 429 (Too Many Requests) to API clients.
4. Metrics: Add `wardex_pipeline_stage_latency_seconds` histogram and `wardex_pipeline_backpressure_total` counter.
5. Dead letter queue: events that fail processing go to DLQ (already exists, wire it in).

**Verify:**
- Events flow through all pipeline stages
- Backpressure kicks in when overloaded (returns 429)
- Pipeline metrics visible in Prometheus
- No event loss under normal load
- DLQ captures malformed events

---

### B.3 — Real ML Triage Engine — Implemented

**Status:** Implemented as a pure-Rust gradient-boosted classifier rather than
ONNX Runtime. Adding the native `ort`/onnxruntime dependency was rejected to
keep the reproducible-build, container, and package CI free of native runtime
linkage. The result is genuine ML with zero new dependencies.

**What shipped:**
- `src/ml_engine.rs` — `GradientBoostedClassifier`: real multiclass gradient
  boosting (regression trees fitted to softmax cross-entropy gradients/hessians,
  XGBoost-style split gain, Newton-step leaves). Trained at startup on a
  deterministic labelled dataset, so every build produces an identical model.
- `GradientBoostEngine` is the primary triage backend; `RandomForestEngine`
  (the pre-trained 5-tree forest) runs as the shadow/fallback backend.
- `ModelRegistry` orchestrates primary/shadow inference, calibrated confidence,
  rollback, and shadow-drift reporting.
- Serialized classifiers (`*.json`) in the model directory override the
  built-in model, so offline-trained models can be deployed without a rebuild.

**Verified:** model trains deterministically on startup; `/api/ml/triage` and
`/api/ml/triage/v2` return real predictions with calibrated confidence and
shadow comparison.

**Verify:**
- Model loads on startup (or gracefully falls back to stub)
- Alerts include ML triage prediction
- Inference latency <5ms per alert
- Model reloading works without restart (`POST /api/admin/reload-model`)

---

### B.4 — Structured Logging with tracing

**What:** Replace `env_logger` with the `tracing` ecosystem for structured JSON logging with correlation IDs, span context, and external log forwarding.

**Where:**
- `Cargo.toml` — add `tracing`, `tracing-subscriber`, `tracing-opentelemetry` (optional)
- `src/structured_log.rs` — migrate to tracing subscriber
- `src/server.rs` (now routes/) — add tracing spans per request
- All modules — replace `log::info!()` with `tracing::info!()`

**How:**
1. Add dependencies:
   ```toml
   tracing = "0.1"
   tracing-subscriber = { version = "0.3", features = ["json", "env-filter"] }
   ```
2. Initialize subscriber in `main.rs`:
   ```rust
   tracing_subscriber::fmt()
       .json()
       .with_env_filter("wardex=info")
       .with_span_events(FmtSpan::CLOSE)
       .init();
   ```
3. Add request-level spans in axum middleware:
   ```rust
   #[instrument(skip_all, fields(request_id = %req_id, method = %method, path = %path))]
   async fn handle_request(...) { ... }
   ```
4. Replace all `log::info!()`, `log::warn!()`, `log::error!()` calls with `tracing::info!()` etc. (project-wide find-and-replace).
5. Add `tenant_id` and `user` as span fields where available.
6. Keep the existing `structured_log.rs` sinks (file, buffer) but route through tracing subscriber layers.

**Verify:**
- Logs are structured JSON with timestamp, level, module, request_id, span context
- `RUST_LOG=wardex=debug` controls log levels
- Request IDs propagate through the pipeline
- Existing log output still works for console mode

---

### B.5 — Usage Metering + Trial Provisioning

**What:** Track resource consumption per tenant and expose usage dashboards. Add time-boxed trial licenses.

**Where:**
- `src/metering.rs` (new) — usage tracking and reporting
- `src/license.rs` — add trial license support
- `src/routes/admin.rs` — usage endpoints
- `admin-console/src/components/Settings.jsx` — usage dashboard

**How:**
1. Create `src/metering.rs`:
   - Track per-tenant: events_ingested (count + bytes), active_agents, active_users, storage_used_bytes, api_calls
   - Rolling windows: last 1h, 24h, 7d, 30d
   - Store hourly snapshots in SQLite `usage_metrics` table
   - `UsageReport` struct with current vs limit for each metric
2. Add trial license support in `license.rs`:
   - `generate_trial(org, duration_days)` — creates a time-boxed Enterprise-tier license
   - Trial limits: 10 agents, 5 users, 30-day expiry
   - Trial banner in admin console: "Trial: X days remaining"
   - On expiry: graceful degradation to read-only (can still view data, can't create new content)
3. API endpoints:
   - `GET /api/admin/usage` — current usage vs limits
   - `GET /api/admin/usage/history` — usage trend over time
   - `POST /api/license/trial` — generate and apply trial license (first-run only)
4. Admin console: Add "Usage" tab in Settings showing bar charts of consumption vs limits.

**Verify:**
- Usage metrics accurately reflect actual consumption
- Trial license auto-generated on first boot
- Trial expiry shows banner and degrades to read-only
- Usage dashboard shows consumption trends

---

## Phase C: Enterprise Readiness (v0.46–0.50)

### C.1 — Battle-Tested HA Clustering

**What:** Make the Raft-inspired clustering work over real network I/O with persistent log storage, snapshotting, and failure testing.

**Where:**
- `src/cluster.rs` — add persistent log, network transport, snapshotting
- `src/storage.rs` — add Raft log table
- Integration tests with multi-process testing

**How:**
1. Add persistent Raft log in SQLite:
   ```sql
   CREATE TABLE raft_log (
     index INTEGER PRIMARY KEY,
     term INTEGER NOT NULL,
     entry_type TEXT NOT NULL,
     data BLOB NOT NULL
   );
   CREATE TABLE raft_state (
     key TEXT PRIMARY KEY,
     value TEXT NOT NULL
   );
   ```
2. Wire inter-node HTTP transport:
   - `POST /cluster/vote` — RequestVote RPC
   - `POST /cluster/append` — AppendEntries RPC
   - `POST /cluster/snapshot` — InstallSnapshot RPC
3. Add snapshotting: periodically compact the Raft log by creating a snapshot of the state machine and truncating old log entries.
4. Add node discovery: config-based (`cluster.peers = ["node1:8080", "node2:8080"]`) with health checking.
5. Add leader forwarding: writes to follower nodes are proxied to the leader.
6. Create integration test harness that starts 3 wardex processes and tests:
   - Normal operation (leader election, log replication)
   - Leader failure (new election within 5 seconds)
   - Network partition (split-brain prevention)
   - Node recovery (catches up from snapshot)
7. Add cluster status to admin console Infrastructure section.

**Verify:**
- 3-node cluster elects leader, replicates writes
- Leader failure triggers re-election within 5 seconds
- No data loss during failover
- Split-brain prevention works (minority partition becomes read-only)
- New node joins and catches up from snapshot

---

### C.2 — Full-Text Event Search (Tantivy)

**What:** Add full-text search for events using Tantivy (Rust-native search engine).

**Where:**
- `Cargo.toml` — add `tantivy`
- `src/search.rs` (new) — search index management
- `src/routes/events.rs` — search endpoint
- Pipeline — index events on ingest

**How:**
1. Add `tantivy = "0.22"` to Cargo.toml.
2. Create `src/search.rs`:
   - Schema: timestamp (date), device_id (text), event_class (u64), process_name (text), command_line (text), src_ip (text), dst_ip (text), raw_text (text, full-text indexed)
   - `SearchIndex` struct managing index writer and reader
   - `index_event(event)` — add event to index (called from pipeline Store stage)
   - `search(query, filters, limit, offset)` — full-text search with field-specific filters
   - Auto-commit every 10 seconds or 10,000 documents
3. Query language: Support Tantivy's query parser (e.g., `process_name:mimikatz AND src_ip:10.0.0.*`)
4. API endpoint:
   - `GET /api/events/search?q=mimikatz&from=2026-04-01&to=2026-04-05&limit=50`
5. Admin console: Add search bar to SOC Workbench with query builder.

**Verify:**
- Full-text search returns results in <100ms for 1M events
- Field-specific queries work (process_name, src_ip, etc.)
- Search index stays in sync with event store
- Index survives restart (persisted to disk)

---

### C.3 — Real-Time Prevention (Kernel Hooks)

**What:** Add kernel-level blocking capabilities so Wardex can prevent malicious actions before they complete, not just detect them.

**Where:**
- `src/prevention.rs` (new) — prevention policy engine
- `src/collector_linux.rs` — eBPF LSM programs for blocking
- `src/collector_macos.rs` — ESF AUTH event blocking
- `src/collector_windows.rs` — minifilter/ETW blocking (design only, requires Windows driver signing)

**How:**
1. Create `src/prevention.rs`:
   - `PreventionPolicy` — rules that define what to block (process execution, file writes, network connections)
   - `PreventionDecision` enum: Allow, Block, Audit (log but allow)
   - `evaluate(event) -> PreventionDecision` — fast-path evaluation (<1ms)
   - Integration with Sigma rules: rules tagged `response: block` trigger prevention
2. Linux eBPF LSM:
   - Write eBPF programs for `bprm_check_security` (process execution), `file_open` (file access), `socket_connect` (network)
   - Use `aya` crate for eBPF program loading from Rust
   - eBPF program sends event to userspace via ring buffer
   - Userspace evaluates prevention policy and returns decision
   - Note: Requires `CAP_BPF` and kernel >=5.7 with LSM BPF enabled
3. macOS ESF:
   - Use `es_new_client` with AUTH event types (ES_EVENT_TYPE_AUTH_EXEC, ES_EVENT_TYPE_AUTH_OPEN)
   - Return `es_respond_auth_result` with ALLOW or DENY
   - Note: Requires System Extension entitlement and user approval
4. Config:
   ```toml
   [prevention]
   enabled = false  # opt-in, off by default
   mode = "audit"   # "audit" (log only) | "enforce" (block)
   ```
5. Start in audit mode to build confidence before enabling enforcement.

**Verify:**
- Audit mode: logs what would be blocked without blocking
- Enforce mode: blocks processes matching prevention rules
- False-positive-safe: default-allow, only block explicitly matched patterns
- Performance: <1ms decision latency
- Graceful degradation when kernel features unavailable

---

### C.4 — Billing Integration

**What:** Add Stripe integration for automated billing, tier upgrades/downgrades, and usage-based invoicing.

**Where:**
- `src/billing.rs` (new) — Stripe webhook handler, subscription management
- `src/routes/billing.rs` (new) — billing API endpoints
- `src/license.rs` — auto-generate license from Stripe subscription
- Admin console — billing settings page

**How:**
1. Create `src/billing.rs`:
   - Stripe webhook handler for: `customer.subscription.created`, `updated`, `deleted`, `invoice.paid`, `invoice.payment_failed`
   - Map Stripe price IDs to Wardex tiers
   - Auto-generate/revoke license keys on subscription changes
   - Usage reporting to Stripe for consumption-based billing (events ingested, active agents)
2. API endpoints:
   - `POST /api/billing/webhook` — Stripe webhook receiver (verify signature)
   - `GET /api/billing/portal` — generate Stripe Customer Portal link
   - `GET /api/billing/usage` — current billing period usage
3. Config:
   ```toml
   [billing]
   enabled = false
   provider = "stripe"
   webhook_secret = "whsec_..."
   api_key = "sk_..."
   ```
4. Admin console: Add Billing tab in Settings with "Manage Subscription" link to Stripe portal.

**Verify:**
- Stripe webhook correctly provisions/revokes licenses
- Usage metrics reported to Stripe for consumption billing
- Customer portal link works for self-service management
- Payment failure triggers grace period (not immediate lockout)

---

### C.5 — Content Marketplace Foundation

**What:** Enable sharing and distribution of detection content (Sigma rules, playbooks, response templates) as downloadable content packs.

**Where:**
- `src/marketplace.rs` (new) — content pack registry, download, verification
- `src/enterprise.rs` — extend ContentPack with distribution metadata
- `src/routes/marketplace.rs` — marketplace API endpoints
- Admin console — Marketplace section in ThreatDetection

**How:**
1. Content pack format (extend existing `ContentPack`):
   ```json
   {
     "id": "pack_ransomware_v2",
     "name": "Ransomware Detection Pack",
     "version": "2.1.0",
     "author": "Wardex Labs",
     "description": "15 Sigma rules + 2 playbooks for ransomware detection and response",
     "contents": {
       "sigma_rules": [],
       "playbooks": [],
       "response_templates": []
     },
     "signature": "ed25519:...",
     "mitre_coverage": ["T1486", "T1490", "T1027"]
   }
   ```
2. Create `src/marketplace.rs`:
   - `PackRegistry` — maintains list of available packs (from local catalog + remote registry)
   - `download_pack(id)` — fetch pack from registry URL, verify Ed25519 signature
   - `install_pack(pack)` — merge rules/playbooks into active content
   - `uninstall_pack(id)` — remove pack's content
3. Remote registry: simple HTTPS endpoint serving a JSON catalog (can be a static file on S3/CDN initially).
4. API:
   - `GET /api/marketplace/catalog` — list available packs
   - `POST /api/marketplace/install/{id}` — install a pack
   - `DELETE /api/marketplace/packs/{id}` — uninstall
   - `GET /api/marketplace/installed` — list installed packs
5. Admin console: Add "Marketplace" tab in ThreatDetection showing available packs with install/uninstall buttons.

**Verify:**
- Packs install and their content appears in detection rules/playbooks
- Signature verification rejects tampered packs
- Uninstall cleanly removes pack content
- Version upgrades work (replace old pack version with new)

---

## Verification Checklists

### Phase A completion
- [ ] `cargo test` passes all tests (target: 1,300+)
- [ ] `cargo clippy` zero warnings
- [ ] `wardex serve` starts on axum (async, port 8080)
- [ ] Admin console loads with React Router navigation
- [ ] OIDC login works with test IdP
- [ ] At least one cloud collector ingests real events
- [ ] License key applied and feature gates work
- [ ] Demo environment boots with seed data in <60 seconds
- [ ] Backup creates and restores successfully

### Phase B completion
- [ ] Events stored in ClickHouse with <100ms query latency at 1M events
- [ ] Pipeline processes 10K events/sec with backpressure
- [ ] ML model predicts alert triage with >80% accuracy
- [ ] Structured JSON logs with correlation IDs
- [ ] Trial license auto-provisioned on first boot
- [ ] Usage dashboard shows accurate consumption metrics

### Phase C completion
- [ ] 3-node cluster survives leader failure with <5s recovery
- [ ] Full-text search returns results in <100ms at 1M events
- [ ] Prevention mode blocks test malware in audit and enforce modes
- [ ] Stripe webhook provisions licenses automatically
- [ ] Content packs install/uninstall cleanly from marketplace

---

## Task Dependency Graph

```
Phase A (parallel tracks):
  A.1 (axum) ──────────────────> Phase B prerequisite
  A.2 (SSO) ──> A.6 (RBAC views)
  A.3 (cloud collectors)
  A.4 (Sigma rules)
  A.5 (licensing) ────────────> B.5 (metering/trials)
  A.7 (demo env)
  A.8 (backup)

Phase B (after A.1 completes):
  B.1 (ClickHouse) ──> B.2 (pipeline)
  B.3 (ML engine)
  B.4 (tracing)
  B.5 (metering)

Phase C (after Phase B):
  C.1 (HA clustering)
  C.2 (Tantivy search) ── requires B.1 + B.2
  C.3 (prevention) ── independent
  C.4 (billing) ── requires A.5
  C.5 (marketplace) ── requires A.4
```

**Critical path:** A.1 (axum) -> B.1 (ClickHouse) -> B.2 (pipeline) -> C.2 (search)

Most Phase A tasks can be worked in parallel. A.1 is the only hard blocker for Phase B.
