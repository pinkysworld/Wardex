use super::*;

pub(super) fn register(builder: OpenApiBuilder) -> OpenApiBuilder {
    builder
        // Hunts & content
        .path(
            "/api/hunts",
            "get",
            op("listHunts", "List saved hunts", &["hunts"]),
        )
        .path(
            "/api/hunts",
            "post",
            op_post_status(
                "201",
                "saveHunt",
                "Create or update a saved hunt",
                &["hunts"],
                "Hunt definition",
            ),
        )
        .path(
            "/api/hunts/{id}/run",
            "post",
            op_post_optional(
                "runHunt",
                "Execute a saved hunt immediately",
                &["hunts"],
                "Optional hunt execution payload",
            ),
        )
        .path(
            "/api/hunts/{id}/history",
            "get",
            op(
                "getHuntHistory",
                "Retrieve saved hunt run history",
                &["hunts"],
            ),
        )
        .path(
            "/api/content/rules",
            "get",
            op(
                "listContentRules",
                "List detection content rules",
                &["hunts"],
            ),
        )
        .path(
            "/api/content/rules",
            "post",
            op_post_status(
                "201",
                "saveContentRule",
                "Create or update managed content rules",
                &["hunts"],
                "Rule definition",
            ),
        )
        .path(
            "/api/content/rules/{id}/test",
            "post",
            op_post(
                "testContentRule",
                "Replay a content rule against retained events",
                &["hunts"],
                "Rule test payload",
            ),
        )
        .path(
            "/api/content/rules/{id}/preflight",
            "post",
            op_post(
                "preflightContentRule",
                "Validate stream, replay, suppression, and ownership proof before rule promotion",
                &["hunts"],
                "Rule preflight payload",
            ),
        )
        .path(
            "/api/content/rules/{id}/promote",
            "post",
            op_post(
                "promoteContentRule",
                "Promote a content rule through its lifecycle",
                &["hunts"],
                "Promotion payload",
            ),
        )
        .path(
            "/api/content/rules/{id}/rollback",
            "post",
            op_post(
                "rollbackContentRule",
                "Rollback a content rule to a previous lifecycle state",
                &["hunts"],
                "Rollback payload",
            ),
        )
        .path(
            "/api/content/packs",
            "get",
            op("listContentPacks", "List content packs", &["hunts"]),
        )
        .path(
            "/api/content/packs",
            "post",
            op_post_status(
                "201",
                "saveContentPack",
                "Create or update a content pack",
                &["hunts"],
                "Pack definition",
            ),
        )
        .path(
            "/api/coverage/mitre",
            "get",
            op(
                "getMitreCoverage",
                "MITRE ATT&CK coverage across rules and packs",
                &["hunts"],
            ),
        )
        .path(
            "/api/suppressions",
            "get",
            op("listSuppressions", "List alert suppressions", &["hunts"]),
        )
        .path(
            "/api/suppressions",
            "post",
            op_post_status(
                "201",
                "saveSuppression",
                "Create or update an alert suppression",
                &["hunts"],
                "Suppression definition",
            ),
        )
        // Enterprise investigation & admin
        .path(
            "/api/entities/{kind}/{id}",
            "get",
            op(
                "getEntityProfile",
                "Entity profile pivot",
                &["threat-intel"],
            ),
        )
        .path(
            "/api/entities/{kind}/{id}/timeline",
            "get",
            op(
                "getEntityTimeline",
                "Entity timeline pivot",
                &["threat-intel"],
            ),
        )
        .path(
            "/api/enrichments/connectors",
            "get",
            op(
                "listEnrichmentConnectors",
                "List enrichment connectors",
                &["threat-intel"],
            ),
        )
        .path(
            "/api/enrichments/connectors",
            "post",
            op_post(
                "saveEnrichmentConnector",
                "Create or update an enrichment connector",
                &["threat-intel"],
                "Connector definition",
            ),
        )
        .path(
            "/api/tickets/sync",
            "post",
            op_post(
                "syncTickets",
                "Sync a case or incident to an external ticket system",
                &["incidents"],
                "Ticket sync request",
            ),
        )
        .path(
            "/api/investigations/workflows",
            "get",
            op(
                "listInvestigationWorkflows",
                "List available investigation workflow templates",
                &["incidents"],
            ),
        )
        .path(
            "/api/investigations/workflows/{id}",
            "get",
            op(
                "getInvestigationWorkflow",
                "Get a single investigation workflow template",
                &["incidents"],
            ),
        )
        .path(
            "/api/investigations/start",
            "post",
            op_post(
                "startInvestigationWorkflow",
                "Start a guided investigation workflow",
                &["incidents"],
                "Investigation start request",
            ),
        )
        .path(
            "/api/investigations/active",
            "get",
            op(
                "listActiveInvestigations",
                "List active investigations with workflow metadata and progress",
                &["incidents"],
            ),
        )
        .path(
            "/api/investigations/progress",
            "post",
            op_post(
                "updateInvestigationProgress",
                "Update step completion, notes, findings, or status for an active investigation",
                &["incidents"],
                "Investigation progress update",
            ),
        )
        .path(
            "/api/investigations/handoff",
            "post",
            op_post(
                "handoffInvestigation",
                "Hand an active investigation to another analyst and sync the linked case",
                &["incidents"],
                "Investigation handoff request",
            ),
        )
        .path(
            "/api/investigations/suggest",
            "post",
            op_post(
                "suggestInvestigationWorkflow",
                "Suggest workflows that match the current alert or incident context",
                &["incidents"],
                "Investigation suggestion request",
            ),
        )
        .path(
            "/api/threat-intel/status",
            "get",
            op(
                "getThreatIntelStatus",
                "Threat intelligence indicator inventory status",
                &["threat-intel"],
            ),
        )
        .path(
            "/api/threat-intel/library",
            "get",
            op(
                "getThreatIntelLibrary",
                "List tracked indicators, feeds, and recent matches",
                &["threat-intel"],
            ),
        )
        .path(
            "/api/threat-intel/stats",
            "get",
            op(
                "getThreatIntelStats",
                "Threat intelligence enrichment and feed statistics",
                &["threat-intel"],
            ),
        )
        .path(
            "/api/threat-intel/ioc",
            "post",
            op_post(
                "submitThreatIntelIoc",
                "Submit a new indicator of compromise",
                &["threat-intel"],
                "Indicator submission payload",
            ),
        )
        .path(
            "/api/threat-intel/purge",
            "post",
            op_post(
                "purgeThreatIntelIndicators",
                "Purge expired indicators from the threat intelligence store",
                &["threat-intel"],
                "Threat intelligence purge request",
            ),
        )
        .path(
            "/api/deception/status",
            "get",
            op(
                "getDeceptionStatus",
                "Deception engine status and artifact coverage",
                &["threat-intel"],
            ),
        )
        .path(
            "/api/deception/deploy",
            "post",
            op_post(
                "deployDeceptionArtifacts",
                "Deploy deception artifacts and decoys",
                &["threat-intel"],
                "Decoy deployment request",
            ),
        )
        .path(
            "/api/idp/providers",
            "get",
            op(
                "listIdentityProviders",
                "List configured identity providers",
                &["auth"],
            ),
        )
        .path(
            "/api/idp/providers",
            "post",
            op_post(
                "saveIdentityProvider",
                "Create or update an identity provider",
                &["auth"],
                "Identity provider definition",
            ),
        )
        .path(
            "/api/scim/config",
            "get",
            op(
                "getScimConfig",
                "Get SCIM provisioning configuration",
                &["auth"],
            ),
        )
        .path(
            "/api/scim/config",
            "post",
            op_post(
                "saveScimConfig",
                "Update SCIM provisioning configuration",
                &["auth"],
                "SCIM configuration",
            ),
        )
        .path(
            "/api/processes/threads",
            "get",
            with_parameters(
                op(
                    "getProcessThreads",
                    "Per-process OS thread snapshot with live state, CPU, wait context, and anomaly evidence",
                    &["observability"],
                ),
                vec![integer_parameter(
                    "pid",
                    "query",
                    "Process identifier to inspect",
                    true,
                )],
            ),
        )
        .path(
            "/api/audit/admin",
            "get",
            op(
                "getAdminAudit",
                "Enterprise admin audit trail",
                &["observability"],
            ),
        )
        .path(
            "/api/audit/log",
            "get",
            op(
                "getAuditLog",
                "Recent API audit log entries",
                &["observability"],
            ),
        )
        .path(
            "/api/audit/log/page",
            "get",
            op(
                "getAuditLogCursorPage",
                "Cursor-paginated API audit log entries",
                &["observability"],
            ),
        )
        .path(
            "/api/backups",
            "get",
            op(
                "listBackups",
                "List available database backups",
                &["observability"],
            ),
        )
        .path(
            "/api/backups",
            "post",
            op_post_without_body(
                "createBackup",
                "Create a database backup",
                &["observability"],
            ),
        )
        .path(
            "/api/backup/status",
            "get",
            op(
                "getBackupStatus",
                "Backup configuration and retention status",
                &["observability"],
            ),
        )
        .path(
            "/api/backup/encrypt",
            "post",
            op_post(
                "encryptBackupPayload",
                "Encrypt a backup payload with a passphrase",
                &["observability"],
                "Backup encryption payload",
            ),
        )
        .path(
            "/api/backup/decrypt",
            "post",
            op_post(
                "decryptBackupPayload",
                "Decrypt a backup payload with a passphrase",
                &["observability"],
                "Backup decryption payload",
            ),
        )
        .path(
            "/api/audit/verify",
            "get",
            op(
                "verifyAuditLog",
                "Verify integrity of the cryptographic audit chain",
                &["observability"],
            ),
        )
        .path(
            "/api/support/diagnostics",
            "get",
            op(
                "getSupportDiagnostics",
                "Support diagnostics bundle",
                &["status"],
            ),
        )
        .path(
            "/api/support/readiness-evidence",
            "get",
            op(
                "getReadinessEvidence",
                "Production readiness evidence pack",
                &["status"],
            ),
        )
        .path(
            "/api/support/bundle",
            "get",
            op_with_schema(
                "getSupportBundle",
                "Redacted support bundle with release, stream, and evidence diagnostics",
                &["status"],
                schema_ref("SupportBundleResponse"),
            ),
        )
        .path(
            "/api/operational/snapshots",
            "get",
            op_with_schema(
                "listOperationalSnapshots",
                "List indexed operational evidence snapshots with digest verification status",
                &["observability"],
                schema_ref("OperationalSnapshotsResponse"),
            ),
        )
        .path(
            "/api/operational/snapshots/verify",
            "get",
            op_with_schema(
                "verifyOperationalSnapshot",
                "Verify an operational evidence snapshot by storage key or digest",
                &["observability"],
                schema_ref("OperationalSnapshotVerifyResponse"),
            ),
        )
        .path(
            "/api/operational/snapshots/policy",
            "get",
            op(
                "getOperationalSnapshotPolicy",
                "Operational snapshot retention and redaction policy",
                &["observability"],
            ),
        )
        .path(
            "/api/operational/snapshots/prune",
            "post",
            op_post(
                "pruneOperationalSnapshots",
                "Preview or apply operational snapshot retention pruning",
                &["observability"],
                "Snapshot prune payload",
            ),
        )
        .path(
            "/api/launchpad/evidence-pack",
            "get",
            op(
                "getLaunchpadEvidencePack",
                "Server-generated operator evidence pack for Launchpad export",
                &["status"],
            ),
        )
        .path(
            "/api/launchpad/release-diff",
            "get",
            op(
                "getLaunchpadReleaseDiff",
                "Current runtime versus release-catalog rollout summary",
                &["status"],
            ),
        )
        .path(
            "/api/launchpad/demo-status",
            "get",
            op(
                "getLaunchpadDemoStatus",
                "Demo-lab scenario availability and seeded sample state",
                &["status"],
            ),
        )
        .path(
            "/api/launchpad/demo-reset",
            "post",
            op(
                "resetLaunchpadDemoStatus",
                "Reset transient demo-lab sample state",
                &["status"],
            ),
        )
        .path(
            "/api/release/doctor",
            "get",
            op_with_schema(
                "getReleaseDoctor",
                "Release acceptance doctor with contract, stream, and rollback readiness checks",
                &["status"],
                schema_ref("ReleaseDoctorResponse"),
            ),
        )
        .path(
            "/api/release/observability-gates",
            "get",
            op(
                "getReleaseObservabilityGates",
                "Release observability gates across metrics, stream, snapshots, and contract parity",
                &["status"],
            ),
        )
        .path(
            "/api/release/provenance",
            "get",
            op(
                "getReleaseProvenance",
                "Release provenance, artifact checksum, and SBOM input attestation",
                &["status"],
            ),
        )
        .path(
            "/api/release/upgrade-rehearsal",
            "get",
            op(
                "getReleaseUpgradeRehearsal",
                "Upgrade and rollback rehearsal checks for a target release",
                &["status"],
            ),
        )
        .path(
            "/api/release/clean-cut",
            "get",
            op(
                "getCleanReleaseCut",
                "Clean next-patch release cut readiness across source, artifacts, container parity, and smoke gates",
                &["status"],
            ),
        )
        .path(
            "/api/containers/release-parity",
            "get",
            op(
                "getContainerReleaseParity",
                "Container release parity for build context, scan, signing, and provenance coverage",
                &["observability"],
            ),
        )
        .path(
            "/api/release/verification-center",
            "get",
            op(
                "getReleaseVerificationCenter",
                "Release verification center for checksums, SBOM, provenance, macOS evidence, and container signatures",
                &["status"],
            ),
        )
        .path(
            "/api/release/deployment-trust-report",
            "get",
            op(
                "getDeploymentTrustReport",
                "Deployment trust report across release acceptance, provenance, parity, failover freshness, collector health, and fleet campaign evidence",
                &["status"],
            ),
        )
        .path(
            "/api/deployment/self-hosted-wizard",
            "get",
            op(
                "getSelfHostedDeploymentWizard",
                "Self-hosted deployment wizard readiness for Docker, Helm, systemd, and local binary installs",
                &["status"],
            ),
        )
        .path(
            "/api/data-quality/dashboard",
            "get",
            op(
                "getDataQualityDashboard",
                "Production data quality dashboard for telemetry freshness, DLQ pressure, collector health, and silent agents",
                &["observability"],
            ),
        )
        .path(
            "/api/performance/scale-baseline",
            "get",
            op(
                "getPerformanceScaleBaseline",
                "Performance and scale baseline for API, storage, stream, report, and release-smoke targets",
                &["observability"],
            ),
        )
        .path(
            "/api/cluster/failover-execution",
            "get",
            op(
                "getClusterFailoverExecution",
                "Cluster failover execution readiness with standby, drill history, promotion, and verification steps",
                &["status"],
            ),
        )
        .path(
            "/api/secrets/rotation-operations",
            "get",
            op(
                "getSecretsRotationOperations",
                "Secrets and key rotation operations plan with dry-run and rollback guidance",
                &["status"],
            ),
        )
        .path(
            "/api/operator/task-automation",
            "get",
            op_with_schema(
                "getOperatorTaskAutomation",
                "Operator work queue automation plan with owner, SLA, escalation, and dry-run assignment, snooze, ticketing, preflight, evidence, and closure actions",
                &["status"],
                schema_ref("OperatorTaskAutomationResponse"),
            ),
        )
        .path(
            "/api/detection/validation-packs",
            "get",
            op(
                "getDetectionValidationPacks",
                "Real-world detection validation packs mapped to ATT&CK scenarios and expected evidence outputs",
                &["detection"],
            ),
        )
        .path(
            "/api/monitoring/synthetic-console",
            "get",
            op(
                "getSyntheticConsoleMonitor",
                "Synthetic console monitor covering launchpad-critical API surfaces",
                &["observability"],
            ),
        )
        .path(
            "/api/incidents/timeline-replay",
            "get",
            op(
                "getIncidentTimelineReplay",
                "Incident timeline replay with retained event joins and alert context",
                &["incidents"],
            ),
        )
        .path(
            "/api/detection/trust-score",
            "get",
            op(
                "getDetectionTrustScore",
                "Detection content trust score based on replay, suppression, and pack ownership evidence",
                &["detection"],
            ),
        )
        .path(
            "/api/detection/trust/overview",
            "get",
            op(
                "getDetectionTrustOverview",
                "Detection Trust overview with noisy rules, trusted rules, stale suppressions, confidence drivers, and draft-only tuning queue",
                &["detection"],
            ),
        )
        .path(
            "/api/detection/trust/rules",
            "get",
            op(
                "getDetectionTrustRules",
                "Per-rule Detection Trust scores with feedback rollups, suppression pressure, replay freshness, source quality, enrichment, ATT&CK coverage, and volume trend",
                &["detection"],
            ),
        )
        .path(
            "/api/detection/trust/rules/{id}",
            "get",
            op(
                "getDetectionTrustRule",
                "Detection Trust detail for one rule including analyst feedback history and any draft-only tuning suggestion",
                &["detection"],
            ),
        )
        .path(
            "/api/detection/trust/tuning-drafts",
            "get",
            op(
                "getDetectionTrustTuningDrafts",
                "Draft-only tuning suggestions generated from analyst outcomes, suppressions, replay, and rule lifecycle evidence",
                &["detection"],
            ),
        )
        .path(
            "/api/detection/trust/tuning-drafts",
            "post",
            op_post(
                "createDetectionTrustTuningDraft",
                "Create an operator-reviewed Detection Trust tuning draft without changing production detections",
                &["detection"],
                "Detection Trust tuning draft request",
            ),
        )
        .path(
            "/api/detection/trust/tuning-drafts/{id}/preview",
            "post",
            op_post_optional(
                "previewDetectionTrustTuningDraft",
                "Preview Detection Trust draft impact before any operator-applied change",
                &["detection"],
                "Detection Trust draft preview request",
            ),
        )
        .path(
            "/api/detection/trust/tuning-drafts/{id}/approve",
            "post",
            op_post_optional(
                "approveDetectionTrustTuningDraft",
                "Approve Detection Trust draft intent while keeping production tuning manual and audit-visible",
                &["detection"],
                "Detection Trust draft approval request",
            ),
        )
        .path(
            "/api/fleet/drift-compliance",
            "get",
            op(
                "getFleetDriftCompliance",
                "Fleet version drift, update error, and config compliance summary",
                &["agents"],
            ),
        )
        .path(
            "/api/operator/work-queue",
            "get",
            op_with_schema(
                "getOperatorWorkQueue",
                "Prioritized operator work queue synthesized from release, response, detection, fleet, and retention signals",
                &["status"],
                schema_ref("OperatorWorkQueueResponse"),
            ),
        )
        .path(
            "/api/retention/forecast",
            "get",
            op(
                "getRetentionForecast",
                "Retention utilization, cost risk, and evidence-capacity forecast",
                &["observability"],
            ),
        )
        .path(
            "/api/search/performance-slo",
            "get",
            op(
                "getSearchPerformanceSlo",
                "Long-retention search p95 and p99 latency SLO evidence",
                &["observability"],
            ),
        )
        .path(
            "/api/validation/adversarial",
            "get",
            op(
                "getAdversarialValidation",
                "Adversarial validation dashboard for shipped attack and baseline corpora",
                &["detection"],
            ),
        )
        .path(
            "/api/support/bundle-diff",
            "get",
            op(
                "getSupportBundleDiff",
                "Support bundle snapshot diff with digest and redaction policy status",
                &["status"],
            ),
        )
        .path(
            "/api/workflows/preflight",
            "get",
            op(
                "getWorkflowPreflight",
                "Workflow readiness preflight with stream, approval, tenant, and observability proof",
                &["status"],
            ),
        )
        .path(
            "/api/tenants/isolation-proof",
            "get",
            op(
                "getTenantIsolationProof",
                "Tenant isolation and device partitioning proof",
                &["status"],
            ),
        )
        .path(
            "/api/processes/thread-proof",
            "get",
            op(
                "getThreadDetectionProof",
                "Runtime thread anomaly proof and baseline readiness",
                &["status"],
            ),
        )
        .path(
            "/api/sdk/contract-status",
            "get",
            op(
                "getSdkContractStatus",
                "SDK/OpenAPI contract automation status, parity drift, and release-gate hooks",
                &["status"],
            ),
        )
        .path(
            "/api/support/first-run-proof",
            "post",
            op(
                "runFirstRunProof",
                "Run the first-run operator proof scenario",
                &["status"],
            ),
        )
        .path(
            "/api/control/failover-drill",
            "post",
            op(
                "runFailoverDrill",
                "Run an automated control-plane failover drill against current recovery artifacts",
                &["control"],
            ),
        )
        .path(
            "/api/support/parity",
            "get",
            op(
                "getSupportParity",
                "API, SDK, and GraphQL parity diagnostics",
                &["status"],
            ),
        )
        .path(
            "/api/docs/index",
            "get",
            op(
                "listSupportDocs",
                "Search embedded documentation and runbooks",
                &["status"],
            ),
        )
        .path(
            "/api/docs/content",
            "get",
            op(
                "getSupportDocContent",
                "Load a specific embedded documentation page",
                &["status"],
            ),
        )
        .path(
            "/api/graphql",
            "post",
            op_post(
                "executeGraphql",
                "Execute GraphQL queries against the Wardex schema",
                &["status"],
                "GraphQL request payload",
            ),
        )
        .path(
            "/api/system/health/dependencies",
            "get",
            op(
                "getDependencyHealth",
                "Dependency and rollout health",
                &["status"],
            ),
        )
        // ── Threat-feed ingestion ────────────────────────────────────────────
        .path(
            "/api/feeds",
            "get",
            op(
                "listFeeds",
                "List all configured threat-intel feed sources",
                &["threat-intel"],
            ),
        )
        .path(
            "/api/feeds",
            "post",
            op_post_status(
                "201",
                "createFeed",
                "Register a new threat-intel feed source",
                &["threat-intel"],
                "FeedSource configuration JSON",
            ),
        )
        .path(
            "/api/feeds/{id}",
            "delete",
            op(
                "deleteFeed",
                "Remove a threat-intel feed source by ID",
                &["threat-intel"],
            ),
        )
        .path(
            "/api/feeds/{id}/poll",
            "post",
            op_post(
                "pollFeed",
                "Ingest a caller-supplied payload through the feed's protocol parser",
                &["threat-intel"],
                "Raw feed payload (format depends on the feed's protocol)",
            ),
        )
        .path(
            "/api/feeds/{id}/fetch",
            "post",
            op_post_without_body(
                "fetchFeed",
                "Live HTTPS fetch from the feed URL and ingest the result",
                &["threat-intel"],
            ),
        )
        .path(
            "/api/feeds/stats",
            "get",
            op(
                "getFeedStats",
                "Aggregate threat-feed ingestion statistics",
                &["threat-intel"],
            ),
        )
        .path(
            "/api/feeds/hot-reload/hashes",
            "post",
            op_post(
                "hotReloadMalwareHashes",
                "Hot-reload the malware-hash database from a JSON payload without restart",
                &["threat-intel"],
                "JSON array of malware-hash entries",
            ),
        )
}
