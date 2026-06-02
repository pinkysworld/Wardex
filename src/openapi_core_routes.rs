use super::*;

pub(super) fn register(builder: OpenApiBuilder) -> OpenApiBuilder {
    builder
        // Auth
        .path(
            "/api/auth/check",
            "get",
            op("authCheck", "Check authentication status", &["auth"]),
        )
        .path(
            "/api/auth/sso/login",
            "get",
            with_parameters(
                op_public_with_responses(
                    "startSsoLogin",
                    "Start SSO login and redirect to the configured identity provider",
                    &["auth"],
                    {
                        let mut resp = BTreeMap::new();
                        resp.insert(
                            "302".into(),
                            Response {
                                description: "Redirect to the configured identity provider".into(),
                                content: None,
                            },
                        );
                        resp
                    },
                ),
                vec![
                    string_parameter(
                        "provider_id",
                        "query",
                        "Optional identity provider ID when more than one SSO provider is configured",
                        false,
                    ),
                    string_parameter(
                        "provider",
                        "query",
                        "Legacy alias for provider_id",
                        false,
                    ),
                    string_parameter(
                        "redirect",
                        "query",
                        "Optional console path to resume after authentication",
                        false,
                    ),
                ],
            ),
        )
        .path(
            "/api/auth/sso/callback",
            "get",
            with_parameters(
                op_public_with_responses(
                    "completeSsoCallbackRedirect",
                    "Complete browser-based SSO callback and redirect back to the console",
                    &["auth"],
                    {
                        let mut resp = BTreeMap::new();
                        resp.insert(
                            "302".into(),
                            Response {
                                description: "Redirect to the post-login or error destination".into(),
                                content: None,
                            },
                        );
                        resp
                    },
                ),
                vec![
                    string_parameter(
                        "code",
                        "query",
                        "Authorization code from the identity provider",
                        true,
                    ),
                    string_parameter(
                        "state",
                        "query",
                        "CSRF state value returned by the identity provider",
                        true,
                    ),
                    string_parameter(
                        "provider_id",
                        "query",
                        "Optional identity provider ID hint for multi-provider deployments",
                        false,
                    ),
                    string_parameter(
                        "provider",
                        "query",
                        "Legacy alias for provider_id",
                        false,
                    ),
                ],
            ),
        )
        .path(
            "/api/auth/sso/callback",
            "post",
            op_public_post_with_responses(
                "completeSsoCallback",
                "Complete programmatic SSO callback and create a Wardex session",
                &["auth"],
                "SSO authorization code, state token, and optional provider hint",
                json_response("Programmatic SSO callback completed"),
            ),
        )
        .path(
            "/api/auth/rotate",
            "post",
            op_post_without_body("authRotate", "Rotate API token", &["auth"]),
        )
        .path(
            "/api/session/info",
            "get",
            op(
                "sessionInfo",
                "Get session metadata, uptime, and TTL",
                &["auth"],
            ),
        )
        // Public diagnostics
        .path(
            "/api/health",
            "get",
            op_public("getHealth", "Health check", &["status"]),
        )
        .path(
            "/api/openapi.json",
            "get",
            op_public(
                "getOpenApiSpec",
                "Stable OpenAPI specification for the public Wardex API surface",
                &["status"],
            ),
        )
        .path(
            "/api/metrics",
            "get",
            op_public_with_responses(
                "getMetrics",
                "Prometheus-format metrics",
                &["observability"],
                content_response_status(
                    "200",
                    "Prometheus-format metrics",
                    "text/plain",
                    string_schema(),
                ),
            ),
        )
        .path(
            "/api/ws/stats",
            "get",
            op_public(
                "getWsStats",
                "Realtime stream transport capability and subscriber statistics",
                &["observability"],
            ),
        )
        .path(
            "/api/ws/health",
            "get",
            op(
                "getWsHealth",
                "Realtime stream queue depth, drop count, and backpressure status",
                &["observability"],
            ),
        )
        .path(
            "/api/stream/readiness",
            "get",
            op_with_schema(
                "getStreamReadiness",
                "Realtime stream confidence score for promotion and evidence workflows",
                &["observability"],
                schema_ref("StreamReadinessResponse"),
            ),
        )
        .path(
            "/api/stream/reliability-lab",
            "get",
            op_with_schema(
                "getStreamReliabilityLab",
                "Realtime stream reliability scenarios and cursor recovery checks",
                &["observability"],
                schema_ref("StreamReliabilityLabResponse"),
            ),
        )
        .path(
            "/api/operator/workspaces",
            "get",
            op(
                "getOperatorWorkspaces",
                "Grouped operator navigation, role workspaces, and trust workspace snapshots",
                &["operator-trust"],
            ),
        )
        .path(
            "/api/alerts/feedback",
            "post",
            op_post(
                "submitAlertFeedback",
                "Submit additive alert outcome feedback without automatic tuning",
                &["alerts", "operator-trust"],
                "Alert feedback payload",
            ),
        )
        .path(
            "/api/alerts/feedback/summary",
            "get",
            op(
                "getAlertFeedbackSummary",
                "Alert feedback rollup and tuning suggestions",
                &["alerts", "operator-trust"],
            ),
        )
        .path(
            "/api/alerts/evidence-chain",
            "get",
            op(
                "getAlertEvidenceChain",
                "Source-aware evidence chain, freshness badges, and why-this-fired explanation",
                &["alerts", "operator-trust"],
            ),
        )
        .path(
            "/api/detection-lab/runs",
            "post",
            op_post(
                "createDetectionLabRun",
                "Run a safe detection validation lab workflow",
                &["detection", "operator-trust"],
                "Detection lab run request",
            ),
        )
        .path(
            "/api/detection-lab/status",
            "get",
            op(
                "getDetectionLabStatus",
                "Detection validation modes, expected-vs-observed summary, and recommendations",
                &["detection", "operator-trust"],
            ),
        )
        .path(
            "/api/detection-lab/history",
            "get",
            op(
                "getDetectionLabHistory",
                "Detection validation history and report attachment metadata",
                &["detection", "operator-trust"],
            ),
        )
        .path(
            "/api/detection-lab/report",
            "get",
            op(
                "getDetectionLabReport",
                "Detection validation report export payload",
                &["detection", "operator-trust"],
            ),
        )
        .path(
            "/api/response/safety",
            "get",
            op(
                "getResponseSafety",
                "Response safety center with approvals, dry-run previews, rollback, trace, audit, and verification continuity",
                &["response", "operator-trust"],
            ),
        )
        .path(
            "/api/response/preview",
            "post",
            op_post(
                "previewResponseAction",
                "Preview response action blast radius, approvals, rollback, and platform command mapping",
                &["response", "operator-trust"],
                "Response action preview request",
            ),
        )
        .path(
            "/api/response/verify",
            "post",
            op_post(
                "verifyResponseAction",
                "Record response action verification checklist status",
                &["response", "operator-trust"],
                "Response action verification request",
            ),
        )
        .path(
            "/api/integrations/marketplace",
            "get",
            op(
                "getIntegrationMarketplace",
                "Connector, SIEM export, and ticketing marketplace summaries with health, sample event previews, and impact mapping",
                &["config", "operator-trust"],
            ),
        )
        .path(
            "/api/integrations/validate",
            "post",
            op_post(
                "validateIntegration",
                "Validate connector setup or outbound integration readiness and return sample-event guidance",
                &["config", "operator-trust"],
                "Connector validation request",
            ),
        )
        .path(
            "/api/integrations/sample-event",
            "get",
            op(
                "getIntegrationSampleEvent",
                "Preview a normalized sample event for a connector provider",
                &["config", "operator-trust"],
            ),
        )
        .path(
            "/api/operations/health",
            "get",
            op(
                "getOperationsHealth",
                "Deployment health cards across ingestion, queues, scans, API, storage, fleet, and release posture",
                &["observability", "operator-trust"],
            ),
        )
        .path(
            "/api/operations/health/snapshot",
            "get",
            op(
                "exportOperationsHealthSnapshot",
                "Persist and export operations health for support and release readiness",
                &["observability", "operator-trust"],
            ),
        )
        .path(
            "/api/malware/explain",
            "get",
            op(
                "getMalwareExplanation",
                "Malware verdict explanation contract, signature source presets, and scan transparency",
                &["operator-trust"],
            ),
        )
        .path(
            "/api/malware/scan-diff",
            "get",
            op(
                "getMalwareScanDiff",
                "Compare repeated malware scans for verdict, confidence, matches, and rootkit deltas",
                &["operator-trust"],
            ),
        )
        .path(
            "/api/subscriptions",
            "post",
            op_post_optional(
                "createSubscription",
                "Create a resumable event subscription cursor",
                &["observability"],
                "Subscription lanes and filters",
            ),
        )
        .path(
            "/api/subscriptions/resume",
            "get",
            op_with_schema(
                "resumeSubscription",
                "Resume buffered events from a subscription cursor",
                &["observability"],
                schema_ref("SubscriptionResumeResponse"),
            ),
        )
        .path(
            "/api/policy/current",
            "get",
            op_public("getCurrentPolicy", "Get current active policy", &["policy"]),
        )
        // Status & reports
        .path(
            "/api/status",
            "get",
            op("getStatus", "Platform status manifest", &["status"]),
        )
        .path(
            "/api/report",
            "get",
            op(
                "getReport",
                "Latest analysis report with samples",
                &["reports"],
            ),
        )
        .path(
            "/api/host/info",
            "get",
            op("getHostInfo", "Host system information", &["status"]),
        )
        .path(
            "/api/slo/status",
            "get",
            op(
                "getSloStatus",
                "Service level objective metrics",
                &["observability"],
            ),
        )
        .path(
            "/api/reports",
            "get",
            with_parameters(
                op("listReports", "List stored reports", &["reports"]),
                vec![
                    string_parameter(
                        "case_id",
                        "query",
                        "Filter reports by case handoff id",
                        false,
                    ),
                    string_parameter(
                        "incident_id",
                        "query",
                        "Filter reports by incident handoff id",
                        false,
                    ),
                    string_parameter(
                        "investigation_id",
                        "query",
                        "Filter reports by investigation handoff id",
                        false,
                    ),
                    string_parameter(
                        "source",
                        "query",
                        "Filter reports by execution-context source",
                        false,
                    ),
                    string_parameter(
                        "scope",
                        "query",
                        "Return all, scoped, or unscoped reports (`all`, `scoped`, `unscoped`)",
                        false,
                    ),
                ],
            ),
        )
        .path(
            "/api/reports/{id}",
            "get",
            op("getReportById", "Retrieve a specific report", &["reports"]),
        )
        .path(
            "/api/reports/{id}/context",
            "post",
            op_post(
                "setReportExecutionContext",
                "Attach or update execution context for a stored report",
                &["reports"],
                "Execution context fields for the stored report",
            ),
        )
        .path(
            "/api/reports/{id}/html",
            "get",
            op_with_responses(
                "getReportHtml",
                "HTML report download",
                &["reports"],
                content_response_status(
                    "200",
                    "HTML report download",
                    "text/html",
                    string_schema(),
                ),
            ),
        )
        .path(
            "/api/reports/executive-summary",
            "get",
            op(
                "getExecutiveSummary",
                "Executive summary across reports and incidents",
                &["reports"],
            ),
        )
        .path(
            "/api/report-templates",
            "get",
            with_parameters(
                op(
                    "listReportTemplates",
                    "List reusable report templates and presets",
                    &["reports"],
                ),
                vec![
                    string_parameter(
                        "case_id",
                        "query",
                        "Filter templates by case handoff id",
                        false,
                    ),
                    string_parameter(
                        "incident_id",
                        "query",
                        "Filter templates by incident handoff id",
                        false,
                    ),
                    string_parameter(
                        "investigation_id",
                        "query",
                        "Filter templates by investigation handoff id",
                        false,
                    ),
                    string_parameter(
                        "source",
                        "query",
                        "Filter templates by execution-context source",
                        false,
                    ),
                    string_parameter(
                        "scope",
                        "query",
                        "Return all, scoped, or unscoped templates (`all`, `scoped`, `unscoped`)",
                        false,
                    ),
                ],
            ),
        )
        .path(
            "/api/report-templates",
            "post",
            op_post_status(
                "201",
                "saveReportTemplate",
                "Create or update a reusable report template",
                &["reports"],
                "Report template upsert payload",
            ),
        )
        .path(
            "/api/report-runs",
            "get",
            with_parameters(
                op("listReportRuns", "List persisted report runs", &["reports"]),
                vec![
                    string_parameter("case_id", "query", "Filter runs by case handoff id", false),
                    string_parameter(
                        "incident_id",
                        "query",
                        "Filter runs by incident handoff id",
                        false,
                    ),
                    string_parameter(
                        "investigation_id",
                        "query",
                        "Filter runs by investigation handoff id",
                        false,
                    ),
                    string_parameter(
                        "source",
                        "query",
                        "Filter runs by execution-context source",
                        false,
                    ),
                    string_parameter(
                        "scope",
                        "query",
                        "Return all, scoped, or unscoped runs (`all`, `scoped`, `unscoped`)",
                        false,
                    ),
                ],
            ),
        )
        .path(
            "/api/report-runs",
            "post",
            op_post_status(
                "201",
                "createReportRun",
                "Create a report run and persist its preview artifact",
                &["reports"],
                "Report run creation payload",
            ),
        )
        .path(
            "/api/report-schedules",
            "get",
            with_parameters(
                op(
                    "listReportSchedules",
                    "List saved report schedules",
                    &["reports"],
                ),
                vec![
                    string_parameter(
                        "case_id",
                        "query",
                        "Filter schedules by case handoff id",
                        false,
                    ),
                    string_parameter(
                        "incident_id",
                        "query",
                        "Filter schedules by incident handoff id",
                        false,
                    ),
                    string_parameter(
                        "investigation_id",
                        "query",
                        "Filter schedules by investigation handoff id",
                        false,
                    ),
                    string_parameter(
                        "source",
                        "query",
                        "Filter schedules by execution-context source",
                        false,
                    ),
                    string_parameter(
                        "scope",
                        "query",
                        "Return all, scoped, or unscoped schedules (`all`, `scoped`, `unscoped`)",
                        false,
                    ),
                ],
            ),
        )
        .path(
            "/api/report-schedules",
            "post",
            op_post_status(
                "201",
                "saveReportSchedule",
                "Create or update a report delivery schedule",
                &["reports"],
                "Report schedule upsert payload",
            ),
        )
        .path(
            "/api/workbench/overview",
            "get",
            op(
                "getWorkbenchOverview",
                "SOC Workbench overview",
                &["incidents"],
            ),
        )
        .path(
            "/api/manager/overview",
            "get",
            op(
                "getManagerOverview",
                "Manager operational overview",
                &["reports"],
            ),
        )
        .path(
            "/api/command/summary",
            "get",
            op_with_responses(
                "getCommandSummary",
                "Command Center lane-health summary",
                &["command"],
                content_response_status(
                    "200",
                    "Lane health across incidents, approvals, connectors, rule tuning, releases, and evidence packs",
                    "application/json",
                    schema_ref("CommandCenterSummaryResponse"),
                ),
            ),
        )
        .path(
            "/api/command/lanes/{lane}",
            "get",
            with_parameters(
                op_with_responses(
                    "getCommandLane",
                    "Per-lane slice of the Command Center summary",
                    &["command"],
                    content_response_status(
                        "200",
                        "Single-lane payload with metric key, value, and shared timestamp",
                        "application/json",
                        schema_ref("CommandCenterLaneResponse"),
                    ),
                ),
                vec![Parameter {
                    name: "lane".into(),
                    location: "path".into(),
                    description: Some(
                        "Command Center lane name (incidents, remediation, connectors, rule_tuning, release, evidence)"
                            .into(),
                    ),
                    required: true,
                    schema: string_enum_schema(&[
                        "incidents",
                        "remediation",
                        "connectors",
                        "rule_tuning",
                        "release",
                        "evidence",
                    ]),
                }],
            ),
        )
        // Config
        .path(
            "/api/config/current",
            "get",
            op("getConfig", "Current configuration", &["config"]),
        )
        .path(
            "/api/config/reload",
            "post",
            op_post(
                "reloadConfig",
                "Hot-reload configuration",
                &["config"],
                "Config patch",
            ),
        )
        .path(
            "/api/config/save",
            "post",
            op_post(
                "saveConfig",
                "Persist configuration changes to disk",
                &["config"],
                "Config patch",
            ),
        )
        .path(
            "/api/monitoring/options",
            "get",
            op(
                "getMonitoringOptions",
                "OS-aware monitoring points and recommendations",
                &["config"],
            ),
        )
        .path(
            "/api/monitoring/paths",
            "get",
            op(
                "getMonitoringPaths",
                "Active file-integrity and persistence monitoring paths",
                &["config"],
            ),
        )
        .path(
            "/api/retention/status",
            "get",
            op(
                "getRetentionStatus",
                "Data retention policy status",
                &["config"],
            ),
        )
        .path(
            "/api/retention/apply",
            "post",
            op_post(
                "applyRetention",
                "Apply retention policy now",
                &["config"],
                "Retention application payload",
            ),
        )
}
