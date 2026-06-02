use super::*;

pub(super) fn register(builder: OpenApiBuilder) -> OpenApiBuilder {
    builder
        // Telemetry & alerts
        .path(
            "/api/telemetry/current",
            "get",
            op(
                "getTelemetryCurrent",
                "Current telemetry snapshot",
                &["telemetry"],
            ),
        )
        .path(
            "/api/telemetry/history",
            "get",
            op(
                "getTelemetryHistory",
                "Telemetry time-series history",
                &["telemetry"],
            ),
        )
        .path(
            "/api/events",
            "get",
            op("getEvents", "List stored events", &["telemetry"]),
        )
        .path(
            "/api/events/page",
            "get",
            op(
                "getEventsCursorPage",
                "Cursor-paginated retained events",
                &["telemetry"],
            ),
        )
        .path(
            "/api/events",
            "post",
            op_post(
                "pushEvents",
                "Push an event batch from an agent",
                &["telemetry"],
                "Event batch payload",
            ),
        )
        .path(
            "/api/events/export",
            "get",
            op_with_responses(
                "exportEvents",
                "Export filtered events as CSV",
                &["telemetry"],
                content_response_status(
                    "200",
                    "Export filtered events as CSV",
                    "text/csv",
                    string_schema(),
                ),
            ),
        )
        .path(
            "/api/events/summary",
            "get",
            op(
                "getEventsSummary",
                "Fleet event analytics summary",
                &["telemetry"],
            ),
        )
        .path(
            "/api/events/search",
            "post",
            op_post(
                "searchEvents",
                "Search events with structured analyst filters",
                &["telemetry"],
                "Event search query",
            ),
        )
        .path(
            "/api/events/{id}/triage",
            "post",
            op_post(
                "triageEvent",
                "Update event triage state, assignee, tags, and notes",
                &["telemetry"],
                "Triage update payload",
            ),
        )
        .path(
            "/api/collectors/github",
            "get",
            op("getGithubCollector", "GitHub audit collector setup", &["telemetry"]),
        )
        .path(
            "/api/collectors/github/config",
            "post",
            op_post(
                "saveGithubCollectorConfig",
                "Save GitHub audit collector setup",
                &["telemetry"],
                "GitHub audit connector setup fields",
            ),
        )
        .path(
            "/api/collectors/github/validate",
            "post",
            op_post_without_body(
                "validateGithubCollector",
                "Validate GitHub audit collector setup",
                &["telemetry"],
            ),
        )
        .path(
            "/api/collectors/crowdstrike",
            "get",
            op(
                "getCrowdStrikeCollector",
                "CrowdStrike Falcon collector setup",
                &["telemetry"],
            ),
        )
        .path(
            "/api/collectors/crowdstrike/config",
            "post",
            op_post(
                "saveCrowdStrikeCollectorConfig",
                "Save CrowdStrike Falcon collector setup",
                &["telemetry"],
                "CrowdStrike Falcon connector setup fields",
            ),
        )
        .path(
            "/api/collectors/crowdstrike/validate",
            "post",
            op_post_without_body(
                "validateCrowdStrikeCollector",
                "Validate CrowdStrike Falcon collector setup",
                &["telemetry"],
            ),
        )
        .path(
            "/api/collectors/syslog",
            "get",
            op("getSyslogCollector", "Generic syslog collector setup", &["telemetry"]),
        )
        .path(
            "/api/collectors/syslog/config",
            "post",
            op_post(
                "saveSyslogCollectorConfig",
                "Save generic syslog collector setup",
                &["telemetry"],
                "Generic syslog connector setup fields",
            ),
        )
        .path(
            "/api/collectors/syslog/validate",
            "post",
            op_post_without_body(
                "validateSyslogCollector",
                "Validate generic syslog collector setup",
                &["telemetry"],
            ),
        )
        .path(
            "/api/alerts",
            "get",
            with_parameters(
                op("getAlerts", "List recent alerts", &["alerts"]),
                vec![
                    integer_parameter("limit", "query", "Maximum alerts to return", false),
                    integer_parameter(
                        "offset",
                        "query",
                        "Number of alerts to skip before returning results",
                        false,
                    ),
                ],
            ),
        )
        .path(
            "/api/alerts/{id}",
            "get",
            op("getAlert", "Get alert detail", &["alerts"]),
        )
        .path(
            "/api/alerts",
            "delete",
            op("clearAlerts", "Clear all alerts", &["alerts"]),
        )
        .path(
            "/api/alerts/count",
            "get",
            op("getAlertCount", "Alert count by severity", &["alerts"]),
        )
        .path(
            "/api/alerts/analysis",
            "get",
            op(
                "getAlertAnalysis",
                "Latest alert pattern analysis",
                &["alerts"],
            ),
        )
        .path(
            "/api/alerts/analysis",
            "post",
            op_post_optional(
                "runAlertAnalysis",
                "Run on-demand alert analysis",
                &["alerts"],
                "Alert analysis parameters",
            ),
        )
        .path(
            "/api/alerts/grouped",
            "get",
            op(
                "getGroupedAlerts",
                "Alerts grouped by reason fingerprint",
                &["alerts"],
            ),
        )
        .path(
            "/api/alerts/histogram",
            "get",
            op(
                "getAlertHistogram",
                "Time-bucketed alert histogram with severity breakdowns",
                &["alerts"],
            ),
        )
        .path(
            "/api/alerts/page",
            "get",
            op("getAlertsCursorPage", "Cursor-paginated alerts", &["alerts"]),
        )
        .path(
            "/api/queue/alerts",
            "get",
            op(
                "getAlertQueue",
                "SOC alert queue with SLA status",
                &["alerts"],
            ),
        )
        .path(
            "/api/queue/acknowledge",
            "post",
            op_post(
                "acknowledgeQueueAlert",
                "Acknowledge a queued alert",
                &["alerts"],
                "Queue acknowledgement payload",
            ),
        )
        .path(
            "/api/queue/stats",
            "get",
            op(
                "getAlertQueueStats",
                "Alert queue backlog and SLA summary",
                &["alerts"],
            ),
        )
        .path(
            "/api/queue/assign",
            "post",
            op_post(
                "assignQueueAlert",
                "Assign a queued alert to an analyst",
                &["alerts"],
                "Queue assignment payload",
            ),
        )
        .path(
            "/api/detection/summary",
            "get",
            op(
                "getDetectionSummary",
                "Detector state across velocity, entropy, and compound models",
                &["detection"],
            ),
        )
        .path(
            "/api/detection/recommendations",
            "get",
            op(
                "getDetectionRecommendations",
                "Backend-ranked rule promotion, tuning, suppression, and retirement recommendations",
                &["detection"],
            ),
        )
        .path(
            "/api/detection/tuning/feedback",
            "get",
            op(
                "getDetectionTuningFeedback",
                "Seven-day detection tuning feedback with draft-only impact recommendations",
                &["detection"],
            ),
        )
        .path(
            "/api/detection/readiness",
            "get",
            op(
                "getDetectionReadiness",
                "Collector-to-rule readiness and coverage gaps for detection rollout",
                &["detection"],
            ),
        )
        .path(
            "/api/detection/replay-corpus",
            "get",
            op(
                "getDetectionReplayCorpus",
                "Evaluate the built-in replay corpus against precision, recall, and false-positive gates",
                &["detection"],
            ),
        )
        .path(
            "/api/detection/replay-corpus",
            "post",
            op_post(
                "evaluateDetectionReplayCorpus",
                "Evaluate a custom labeled or retained-event replay-corpus validation pack",
                &["detection"],
                "Replay corpus validation pack",
            ),
        )
        .path(
            "/api/detection/explain",
            "get",
            op(
                "getDetectionExplainability",
                "Explain a detection with evidence, entity scores, feedback, and next steps",
                &["detection"],
            ),
        )
        .path(
            "/api/detection/profile",
            "get",
            op(
                "getDetectionProfile",
                "Current detection tuning profile and sensitivity thresholds",
                &["detection"],
            ),
        )
        .path(
            "/api/detection/profile",
            "put",
            op_put(
                "setDetectionProfile",
                "Set the active detection tuning profile",
                &["detection"],
                "Detection tuning profile payload",
            ),
        )
        .path(
            "/api/detection/score/normalize",
            "get",
            op(
                "normalizeDetectionScore",
                "Normalized 0-100 threat score with severity and confidence labels",
                &["detection"],
            ),
        )
        .path(
            "/api/detection/feedback",
            "get",
            op(
                "listDetectionFeedback",
                "List analyst feedback for detection calibration",
                &["detection"],
            ),
        )
        .path(
            "/api/detection/feedback",
            "post",
            op_post(
                "recordDetectionFeedback",
                "Record analyst detection feedback",
                &["detection"],
                "Detection feedback payload",
            ),
        )
        .path(
            "/api/detection/weights",
            "get",
            op(
                "getDetectionWeights",
                "Current per-dimension detection weights",
                &["detection"],
            ),
        )
        .path(
            "/api/detection/weights",
            "post",
            op_post(
                "setDetectionWeights",
                "Set per-dimension detection weights",
                &["detection"],
                "Detection weight payload",
            ),
        )
        .path(
            "/api/correlation/campaigns",
            "get",
            op(
                "getCorrelationCampaigns",
                "Cluster stored events into campaign summaries, sequence signals, and graph edges",
                &["detection"],
            ),
        )
        // Incidents & cases
        .path(
            "/api/cases",
            "get",
            op("listCases", "List investigation cases", &["incidents"]),
        )
        .path(
            "/api/cases",
            "post",
            op_post_status(
                "201",
                "createCase",
                "Create investigation case",
                &["incidents"],
                "Case definition",
            ),
        )
        .path(
            "/api/cases/{id}",
            "get",
            op("getCase", "Get case detail", &["incidents"]),
        )
        .path(
            "/api/cases/{id}/handoff-packet",
            "get",
            op(
                "getCaseHandoffPacket",
                "Get a structured handoff packet for a case",
                &["incidents"],
            ),
        )
        .path(
            "/api/incidents",
            "get",
            with_parameters(
                op("listIncidents", "List incidents", &["incidents"]),
                vec![
                    string_parameter("status", "query", "Filter incidents by status", false),
                    string_parameter("severity", "query", "Filter incidents by severity", false),
                    integer_parameter("limit", "query", "Maximum incidents to return", false),
                    integer_parameter(
                        "offset",
                        "query",
                        "Number of incidents to skip before returning results",
                        false,
                    ),
                ],
            ),
        )
        .path(
            "/api/incidents",
            "post",
            op_post(
                "createIncident",
                "Create a new incident",
                &["incidents"],
                "Incident title, severity, and optional links",
            ),
        )
        .path(
            "/api/incidents/{id}",
            "get",
            op("getIncident", "Get incident detail", &["incidents"]),
        )
        .path(
            "/api/incidents/{id}/update",
            "post",
            op_post(
                "updateIncident",
                "Update incident status, assignee, or notes",
                &["incidents"],
                "Incident update payload",
            ),
        )
        .path(
            "/api/incidents/{id}/report",
            "get",
            op(
                "getIncidentReport",
                "Generate incident report",
                &["incidents"],
            ),
        )
        .path(
            "/api/incidents/{id}/storyline",
            "get",
            op(
                "getIncidentStoryline",
                "Narrative storyline and evidence package",
                &["incidents"],
            ),
        )
        // Fleet & agents
        .path(
            "/api/agents",
            "get",
            op("listAgents", "List enrolled agents", &["fleet"]),
        )
        .path(
            "/api/agents/{id}/details",
            "get",
            op(
                "getAgentDetails",
                "Retrieve detailed agent snapshot",
                &["fleet"],
            ),
        )
        .path(
            "/api/agents/{id}/activity",
            "get",
            op(
                "getAgentActivity",
                "Deep activity snapshot for a single agent",
                &["fleet"],
            ),
        )
        .path(
            "/api/agents/{id}/logs",
            "get",
            op("getAgentLogs", "Retrieve agent logs", &["fleet"]),
        )
        .path(
            "/api/agents/{id}/inventory",
            "get",
            op("getAgentInventory", "Retrieve agent inventory", &["fleet"]),
        )
        .path(
            "/api/fleet/installs",
            "get",
            op(
                "listFleetRemoteInstalls",
                "Recent remote install attempts and heartbeat outcomes",
                &["fleet"],
            ),
        )
        .path(
            "/api/fleet/install/ssh",
            "post",
            op_post_status(
                "202",
                "runFleetSshInstall",
                "Run a remote Linux or macOS agent install over SSH",
                &["fleet"],
                "SSH remote install request",
            ),
        )
        .path(
            "/api/fleet/install/winrm",
            "post",
            op_post_status(
                "202",
                "runFleetWinrmInstall",
                "Run a remote Windows agent install over WinRM",
                &["fleet"],
                "WinRM remote install request",
            ),
        )
        .path(
            "/api/fleet/inventory",
            "get",
            op(
                "getFleetInventory",
                "Fleet-wide inventory summary",
                &["fleet"],
            ),
        )
        .path(
            "/api/fleet/dashboard",
            "get",
            op(
                "getFleetDashboard",
                "Operational fleet dashboard across agents, events, and deployments",
                &["fleet"],
            ),
        )
        .path(
            "/api/rollout/config",
            "get",
            op(
                "getRolloutConfig",
                "Rollout channel and staged deployment configuration",
                &["updates"],
            ),
        )
        .path(
            "/api/agents/update",
            "get",
            with_parameters(
                op(
                    "checkAgentUpdate",
                    "Check whether an agent update is available",
                    &["updates"],
                ),
                vec![
                    string_parameter("agent_id", "query", "Agent identifier", false),
                    string_parameter("current_version", "query", "Current agent version", false),
                    string_parameter("platform", "query", "Agent platform", false),
                ],
            ),
        )
        .path(
            "/api/updates/releases",
            "get",
            op("listReleases", "List published releases", &["updates"]),
        )
        .path(
            "/api/updates/download/{file_name}",
            "get",
            op_with_responses(
                "downloadRelease",
                "Download an agent release artifact",
                &["updates"],
                content_response_status(
                    "200",
                    "Download an agent release artifact",
                    "application/octet-stream",
                    binary_schema(),
                ),
            ),
        )
        .path(
            "/api/updates/publish",
            "post",
            op_post(
                "publishRelease",
                "Publish a new agent release",
                &["updates"],
                "Release payload",
            ),
        )
        .path(
            "/api/updates/deploy",
            "post",
            op_post(
                "deployUpdate",
                "Assign a published release to an agent",
                &["updates"],
                "Deployment target and version",
            ),
        )
        .path(
            "/api/updates/rollback",
            "post",
            op_post(
                "rollbackUpdate",
                "Rollback a deployment",
                &["updates"],
                "Rollback parameters",
            ),
        )
        .path(
            "/api/updates/cancel",
            "post",
            op_post(
                "cancelUpdate",
                "Cancel an in-progress deployment",
                &["updates"],
                "Deployment ID",
            ),
        )
        // Response
        .path(
            "/api/response/request",
            "post",
            op_post(
                "requestResponse",
                "Submit an approval-gated response action",
                &["response"],
                "Response action request",
            ),
        )
        .path(
            "/api/response/requests",
            "get",
            op(
                "listResponseRequests",
                "List response requests with approval state",
                &["response"],
            ),
        )
        .path(
            "/api/response/audit",
            "get",
            op(
                "listResponseAudit",
                "Response approval and execution audit ledger",
                &["response"],
            ),
        )
        .path(
            "/api/response/execution-audit",
            "get",
            op(
                "listResponseExecutionAudit",
                "Structured response execution command transcripts and verification state",
                &["response"],
            ),
        )
        .path(
            "/api/response/approve",
            "post",
            op_post(
                "approveResponse",
                "Approve or deny a pending response action",
                &["response"],
                "Approval payload",
            ),
        )
        .path(
            "/api/response/execute",
            "post",
            op_post_optional(
                "executeResponse",
                "Execute approved response actions",
                &["response"],
                "Optional execution payload",
            ),
        )
        .path(
            "/api/response/approvals",
            "get",
            op(
                "listResponseApprovals",
                "Approval history for response actions",
                &["response"],
            ),
        )
        .path(
            "/api/response/approval-overview",
            "get",
            op(
                "getResponseApprovalOverview",
                "SOC approval backlog, ready-to-execute counts, and queue guardrails",
                &["response"],
            ),
        )
        .path(
            "/api/admin/rbac-coverage",
            "get",
            op(
                "getAdminRbacCoverage",
                "Route-level RBAC coverage proof for administrators",
                &["admin"],
            ),
        )
        .path(
            "/api/rbac/coverage",
            "get",
            op(
                "getRbacCoverage",
                "Route-level RBAC coverage proof",
                &["admin"],
            ),
        )
        .path(
            "/api/remediation/safety",
            "get",
            op(
                "getRemediationSafety",
                "Rollback execution policy, platform guardrails, and remediation lane status",
                &["response"],
            ),
        )
        .path(
            "/api/playbooks",
            "get",
            op(
                "listPlaybooks",
                "List registered automated response playbooks",
                &["response"],
            ),
        )
        .path(
            "/api/playbooks",
            "post",
            op_post(
                "savePlaybook",
                "Register or update an automated response playbook",
                &["response"],
                "Playbook definition",
            ),
        )
        .path(
            "/api/playbooks/execute",
            "post",
            op_post(
                "executePlaybook",
                "Start a playbook execution for a specific alert",
                &["response"],
                "Playbook execution request",
            ),
        )
        .path(
            "/api/playbooks/run",
            "post",
            op_post(
                "runPlaybook",
                "Run a playbook until it completes or pauses for approval",
                &["response"],
                "Playbook run request",
            ),
        )
        .path(
            "/api/playbooks/resume",
            "post",
            op_post(
                "resumePlaybook",
                "Resume a playbook execution that is waiting for approval",
                &["response"],
                "Playbook approval resume request",
            ),
        )
        .path(
            "/api/playbooks/executions",
            "get",
            op(
                "listPlaybookExecutions",
                "List recent automated response playbook executions",
                &["response"],
            ),
        )
        .path(
            "/api/playbook/execution/{id}/recovery-actions",
            "get",
            op(
                "getPlaybookExecutionRecoveryActions",
                "Suggested recovery actions for failed, paused, or completed playbook executions",
                &["response"],
            ),
        )
        // Policy
        .path(
            "/api/policy/history",
            "get",
            op("getPolicyHistory", "Policy version history", &["policy"]),
        )
        .path(
            "/api/policy/publish",
            "post",
            op_post(
                "publishPolicy",
                "Publish a policy version",
                &["policy"],
                "Policy payload",
            ),
        )
}
