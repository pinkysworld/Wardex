# Wardex — Feature Summary

Wardex is a self-hosted XDR and SIEM platform built in Rust for teams that want enterprise-grade detection, investigation, and fleet control without handing their control plane to a third-party cloud.

## Platform capabilities

- **Detection engineering**
  - Sigma and native detection content with Sigma-KernelEvent bridge
  - Saved hunts with thresholds, schedules, owners, and run history
  - Rule testing, promote/rollback lifecycle, suppressions, and content packs
  - MITRE ATT&CK coverage views and threat-summary dashboards
  - Named entity extraction from alert text (IP, domain, hash, MITRE technique, process)
  - Detection efficacy tracker with per-rule TP/FP rate analysis and trend reporting

- **SOC operations**
  - Alert queue with SLA awareness, acknowledgement, assignment, and escalation
  - Case management, incident tracking, investigation pivots, process-tree and timeline views
  - Guided investigation workflows: 5 built-in playbooks (credential-storm, ransomware-triage, lateral-movement, c2-beacon, container-escape) with step-by-step guidance and auto-queries
  - Live cross-platform process monitoring with CPU/memory usage (macOS, Linux, Windows)
  - Process security analysis: suspicious name detection, resource abuse, deleted-executable detection, LOLBin abuse
  - Installed application inventory (macOS .app bundles, Linux dpkg/rpm, Windows registry/wmic)
  - System inventory: hardware, software packages, services, network ports, users
  - Structured incident detail view: severity badge, status, storyline timeline, related events/agents, close/export
  - Escalation management console: policy CRUD, active escalation tracking with acknowledge workflow
  - Approval-gated response workflows with pending, approved, executed, denied, and expired states
  - Playbook condition DSL with numeric, string, CONTAINS, and AND/OR compound expressions

- **Detection engineering**
  - Sigma and native detection content with Sigma-KernelEvent bridge
  - Saved hunts with management table, inline creation, per-hunt run, thresholds, schedules, owners, and run history
  - Rule testing, promote/rollback lifecycle, suppressions management with inline form, and content packs
  - MITRE ATT&CK coverage views and threat-summary dashboards
  - Named entity extraction from alert text (IP, domain, hash, MITRE technique, process)
  - Cross-signal correlation bonus: 3+ simultaneously elevated axes → 15–70% score multiplier
  - Auth failure rate-of-change smoothing: 8-sample rolling window, acceleration >4.0 triggers signal
  - Memory forensics: RWX region detection, process hollowing analysis, platform-specific collection plans
  - Fleet-wide attack campaign clustering using Jaccard similarity and connected-component analysis
  - Side-channel score fusion integrated into compound threat detector
  - UEBA geo-validation with GeoIP resolver and impossible-travel detection

- **Fleet and deployment**
  - Cross-platform agent enrollment, heartbeat tracking, health snapshots, and per-agent activity
  - Policy distribution, rollout groups, staged deployments, rollback, and cancellation
  - Release catalog management with update checks and deployment history
  - Device fingerprint EWMA drift tracking for impersonation detection

- **Vulnerability and exposure management**
  - CVE correlation engine with built-in advisory database and semantic version comparison
  - Fleet-wide vulnerability scanning with risk-scored summaries
  - Network Detection & Response with netflow ingestion, top-talker analysis, and protocol anomaly scoring
  - Container runtime detection: escape attempts, privileged exec, untrusted images, sensitive mounts, K8s API abuse
  - TLS certificate monitor: expiry tracking (30d/7d), self-signed and weak-key detection
  - Configuration drift detection with SSH, kernel, and Docker baselines and MITRE ATT&CK mappings
  - Unified asset inventory with 9 asset types, upsert, risk scoring, and full-text search

- **Enterprise controls**
  - RBAC with endpoint-level enforcement
  - Session TTL, token rotation, audit and retention controls
  - IDP and SCIM configuration surfaces
  - Change control, admin audit export, diagnostics, and dependency health
  - Digital twin calibration from real-world telemetry

- **Research and AI**
  - Federated learning with convergence loop and differential privacy
  - Deception engine with randomised canary deployment and attacker behavior profiling
  - Privacy-preserving forensics with 4 redaction levels and ZK proofs

- **Integrations and evidence**
  - Structured SIEM output, OCSF normalization, TAXII pull, and threat-intel enrichment
  - Compliance evidence, forensic exports, tamper-evident audit chain, and encrypted event spooling
  - Outbound notifications to Slack, Teams, PagerDuty, Webhook, and Email (real SMTP delivery with retry) with severity filtering
  - CycloneDX 1.5 and SPDX 2.3 SBOM generation from Cargo.lock for supply-chain compliance
  - Runbooks, OpenAPI contract, deployment models, disaster recovery guidance, and production hardening docs
  - Python SDK with ~55 typed API methods and custom exception hierarchy
  - GraphQL query layer for threat-hunting with aliases, sub-field selection, and introspection
  - Prometheus metrics endpoint with 20+ wardex_* counters, gauges, and histograms
  - OpenAPI 3.0.3 machine-readable spec with 90+ endpoints and full schema definitions

- **Production hardening**
  - Persistent JSON storage backend with atomic writes, schema migrations, and retention purge
  - Real OS enforcement execution with command safety filter and dry-run mode
  - Atomic agent update with SHA-256 verification, automatic rollback, and state tracking
  - Alert deduplication with time-window grouping and cross-device merge
  - YARA-style pattern matching engine with built-in threat rules
  - Multi-tenancy isolation guards with cross-tenant access control
  - Real mesh networking with checksummed frames, hop limits, and peer state tracking
  - Dashboard deep-linking and timeline visualization
  - HA clustering with Raft-inspired leader election, log replication, and health monitoring
  - WebSocket event streaming with RFC 6455 framing and pub/sub channels
  - Structured JSON logging with pluggable sinks and per-request context
  - Data archival with real gzip compression (flate2), CSV export, and SHA-256 manifests
  - 210 Sigma detection rules across 22 categories (including cloud-native)
  - ClickHouse storage adapter with buffered batch inserts, MergeTree DDL, and materialized views
  - ML triage engine with 5-tree Random Forest ensemble for true-positive/false-positive/needs-review classification
  - HA cluster snapshots with log compaction and persistent Raft state schema
  - OIDC/SAML SSO with session management (config, login, callback, session, logout)
  - Cloud collectors for AWS CloudTrail, Azure Activity Log, and GCP Audit Log
  - Full-text search index with query parsing and faceted results
  - Usage metering with plan limits and overage calculation
  - Billing engine with subscription management and invoice generation
  - Content marketplace with 10 built-in packs and install/uninstall lifecycle
  - Prevention engine with block/allow/quarantine response policies
  - Ingestion pipeline with backpressure tracking and dead-letter queue
  - Scheduled backup manager with retention and restore verification
  - Ed25519-signed license validation with tier enforcement and feature gating
  - Compliance templates for CIS v8, PCI-DSS v4, SOC 2, and NIST CSF 2.0 with auto-evaluation
  - Kubernetes manifests and Helm chart for production deployment
  - CI hardening with cargo-audit, code coverage, MSRV checks, and dependency caching
  - Mutex poison recovery on all lock sites (230+) to prevent cascading panics
  - Syslog forwarding (RFC 5424 over UDP) for HTTP audit entries via WARDEX_SYSLOG_TARGET
  - Database schema versioning with migration history API endpoint
  - Panic hooks, Slowloris protection, secret management, agent authentication, and memory bounds
  - GDPR right-to-forget purge, PII scanner (email, SSN, credit card), auto retention purge
  - Kubernetes readiness/liveness probes, X-Request-Id tracing, and database backup endpoint
  - TLS/HTTPS listener with opt-in rustls integration and mutual TLS (mTLS) for agent authentication
  - 10 chaos/fault-injection integration tests (token rotation stress, burst load, malformed payloads, invalid auth, path traversal, oversized headers/bodies, wrong methods, endpoint sweep)

## Admin console

- Structured form editor with toggle switches and number inputs (no raw JSON required)
- Config diff view (line-by-line green/red comparison between saved and current)
- Reset-to-defaults and monitoring scope toggles (per-feature enable/disable)
- Dashboard Recharts visualizations: severity pie chart, 24h alert timeline bar chart, CPU/memory area chart
- Clickable/expandable alert and process rows for drill-down inspection
- Per-alert FP feedback button with auto-extracted pattern submission
- Bulk alert actions: Mark as FP, Acknowledge/Triage, Create Incident
- Alert severity filter (all/critical/severe/elevated/low) on Dashboard and Live Monitor
- Fully structured displays across all tabs — zero raw JSON dumps

## Product posture

- 113 Rust source modules
- ~230 API paths
- 1088 lib tests + 163 integration tests, all passing
- Production hardening score: 98% (58/59 controls)
- GitHub Actions release packaging for Linux, macOS, and Windows

## Operator entry points

- `cargo run -- serve` for the live control plane
- `http://localhost:8080/admin/` for the embedded browser console
- `docs/` for architecture, deployment, runbooks, and status
- GitHub Releases for packaged builds
