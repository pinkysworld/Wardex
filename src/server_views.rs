use super::*;

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct QueueAlertSummary {
    pub(crate) event_id: u64,
    pub(crate) agent_id: Option<String>,
    pub(crate) score: f64,
    pub(crate) severity: String,
    pub(crate) hostname: String,
    pub(crate) status: String,
    pub(crate) assignee: Option<String>,
    pub(crate) timestamp: String,
    pub(crate) age_secs: Option<u64>,
    pub(crate) sla_deadline: Option<String>,
    pub(crate) sla_breached: bool,
    pub(crate) reasons: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct CaseSummary {
    pub(crate) id: u64,
    pub(crate) title: String,
    pub(crate) status: String,
    pub(crate) priority: String,
    pub(crate) assignee: Option<String>,
    pub(crate) incident_count: usize,
    pub(crate) event_count: usize,
    pub(crate) updated_at: String,
    pub(crate) tags: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct IncidentSummary {
    pub(crate) id: u64,
    pub(crate) title: String,
    pub(crate) severity: String,
    pub(crate) status: String,
    pub(crate) assignee: Option<String>,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
    pub(crate) agent_count: usize,
    pub(crate) event_count: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct HotAgentSummary {
    pub(crate) agent_id: String,
    pub(crate) hostname: Option<String>,
    pub(crate) risk: String,
    pub(crate) status: String,
    pub(crate) event_count: usize,
    pub(crate) correlated_count: usize,
    pub(crate) max_score: f32,
    pub(crate) current_version: Option<String>,
    pub(crate) target_version: Option<String>,
    pub(crate) rollout_group: Option<String>,
    pub(crate) deployment_status: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct UrgentItem {
    pub(crate) kind: String,
    pub(crate) severity: String,
    pub(crate) title: String,
    pub(crate) subtitle: String,
    pub(crate) reference_id: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct WorkbenchQueueOverview {
    pub(crate) pending: usize,
    pub(crate) acknowledged: usize,
    pub(crate) assigned: usize,
    pub(crate) sla_breached: usize,
    pub(crate) items: Vec<QueueAlertSummary>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct WorkbenchCasesOverview {
    pub(crate) total: usize,
    pub(crate) open: usize,
    pub(crate) resolved: usize,
    pub(crate) active: usize,
    pub(crate) items: Vec<CaseSummary>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct WorkbenchIncidentsOverview {
    pub(crate) total: usize,
    pub(crate) open: usize,
    pub(crate) critical_open: usize,
    pub(crate) by_status: HashMap<String, usize>,
    pub(crate) items: Vec<IncidentSummary>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct WorkbenchResponseOverview {
    pub(crate) pending_approval: usize,
    pub(crate) ready_to_execute: usize,
    pub(crate) denied: usize,
    pub(crate) executed: usize,
    pub(crate) protected_assets: usize,
    pub(crate) recent_requests: Vec<serde_json::Value>,
    pub(crate) recent_approvals: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct WorkbenchIdentityOverview {
    pub(crate) providers_configured: usize,
    pub(crate) ready_providers: usize,
    pub(crate) providers_with_gaps: usize,
    pub(crate) scim_status: String,
    pub(crate) mapped_groups: usize,
    pub(crate) automation_targets_aligned: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct WorkbenchRolloutOverview {
    pub(crate) canary_rules: usize,
    pub(crate) canary_hunts: usize,
    pub(crate) promotion_ready_rules: usize,
    pub(crate) active_hunts: usize,
    pub(crate) rollout_targets: usize,
    pub(crate) average_canary_percentage: Option<u8>,
    pub(crate) historical_events: usize,
    pub(crate) rollback_events: usize,
    pub(crate) last_rollout_at: Option<String>,
    pub(crate) recent_history: Vec<crate::enterprise::RolloutAnalyticsRecord>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct WorkbenchContentOverview {
    pub(crate) packs: usize,
    pub(crate) enabled_packs: usize,
    pub(crate) hunt_library: usize,
    pub(crate) scheduled_hunts: usize,
    pub(crate) saved_searches: usize,
    pub(crate) packs_with_workflows: usize,
    pub(crate) latest_pack_update: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct WorkbenchAutomationOverview {
    pub(crate) playbooks: usize,
    pub(crate) workflow_templates: usize,
    pub(crate) dynamic_templates: usize,
    pub(crate) active_executions: usize,
    pub(crate) pending_approvals: usize,
    pub(crate) success_rate: f64,
    pub(crate) avg_execution_ms: Option<u64>,
    pub(crate) active_investigations: usize,
    pub(crate) historical_runs: usize,
    pub(crate) last_execution_at: Option<String>,
    pub(crate) recent_history: Vec<crate::enterprise::PlaybookAnalyticsRecord>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct WorkbenchAnalyticsOverview {
    pub(crate) api_requests: u64,
    pub(crate) api_error_rate: f64,
    pub(crate) unique_endpoints: usize,
    pub(crate) busiest_endpoint: Option<String>,
    pub(crate) worst_p95_ms: Option<u64>,
    pub(crate) search_queries_total: u64,
    pub(crate) hunt_runs_total: u64,
    pub(crate) response_exec_total: u64,
    pub(crate) last_hunt_latency_ms: u64,
    pub(crate) last_response_latency_ms: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct WorkbenchOwnerLoadSummary {
    pub(crate) username: String,
    pub(crate) role: String,
    pub(crate) enabled: bool,
    pub(crate) queue_assigned: usize,
    pub(crate) queue_sla_breached: usize,
    pub(crate) cases_open: usize,
    pub(crate) incidents_open: usize,
    pub(crate) stale_cases: usize,
    pub(crate) stale_incidents: usize,
    pub(crate) load_score: usize,
    pub(crate) status: String,
    pub(crate) last_case_update: Option<String>,
    pub(crate) next_action: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct WorkbenchRoleCoverage {
    pub(crate) role: String,
    pub(crate) count: usize,
    pub(crate) enabled: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct WorkbenchGroupCoverage {
    pub(crate) group: String,
    pub(crate) mapped_role: Option<String>,
    pub(crate) automation_targets: usize,
    pub(crate) status: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct WorkbenchTeamLoadOverview {
    pub(crate) active_owners: usize,
    pub(crate) available_owners: usize,
    pub(crate) pending_approvals: usize,
    pub(crate) unassigned_queue: usize,
    pub(crate) unassigned_cases: usize,
    pub(crate) stale_ownership_items: usize,
    pub(crate) average_load_score: f64,
    pub(crate) balance_spread: usize,
    pub(crate) rebalance_hint: String,
    pub(crate) analysts: Vec<WorkbenchOwnerLoadSummary>,
    pub(crate) role_coverage: Vec<WorkbenchRoleCoverage>,
    pub(crate) group_context: Vec<WorkbenchGroupCoverage>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct WorkbenchConnectorImpactEntry {
    pub(crate) provider: String,
    pub(crate) label: String,
    pub(crate) lane: String,
    pub(crate) status: String,
    pub(crate) enabled: bool,
    pub(crate) affected_detections: usize,
    pub(crate) stale_assets: usize,
    pub(crate) last_good_event: Option<String>,
    pub(crate) validation_failure: Option<String>,
    pub(crate) owner: String,
    pub(crate) sample_detections: Vec<String>,
    pub(crate) rule_owners: Vec<String>,
    pub(crate) route_targets: Vec<String>,
    pub(crate) setup_pivots: Vec<serde_json::Value>,
    pub(crate) next_action: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct WorkbenchConnectorImpactOverview {
    pub(crate) collectors_at_risk: usize,
    pub(crate) impacted_detections: usize,
    pub(crate) stale_assets: usize,
    pub(crate) review_required: usize,
    pub(crate) items: Vec<WorkbenchConnectorImpactEntry>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct WorkbenchDetectionReviewEntry {
    pub(crate) id: String,
    pub(crate) title: String,
    pub(crate) owner: String,
    pub(crate) lifecycle: String,
    pub(crate) next_review_at: Option<String>,
    pub(crate) due_status: String,
    pub(crate) last_test_match_count: usize,
    pub(crate) active_suppressions: usize,
    pub(crate) promotion_blockers: Vec<String>,
    pub(crate) latest_replay_new_match_count: usize,
    pub(crate) latest_replay_cleared_match_count: usize,
    pub(crate) latest_replay_suppressed_count: usize,
    pub(crate) latest_replay_tested_at: Option<String>,
    pub(crate) latest_feedback_verdict: Option<String>,
    pub(crate) latest_feedback_analyst: Option<String>,
    pub(crate) latest_feedback_notes: Option<String>,
    pub(crate) latest_feedback_at: Option<String>,
    pub(crate) href: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct WorkbenchDetectionReviewOverview {
    pub(crate) overdue: usize,
    pub(crate) due_this_week: usize,
    pub(crate) replay_blockers: usize,
    pub(crate) noisy_owners: usize,
    pub(crate) items: Vec<WorkbenchDetectionReviewEntry>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct WorkbenchRecommendation {
    pub(crate) category: String,
    pub(crate) priority: String,
    pub(crate) title: String,
    pub(crate) summary: String,
    pub(crate) action_hint: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct WorkbenchValueBrief {
    pub(crate) status: String,
    pub(crate) analyst_hours_saved_estimate: f64,
    pub(crate) coverage_growth_items: usize,
    pub(crate) collector_freshness_risk: usize,
    pub(crate) blocked_high_risk_actions: usize,
    pub(crate) approval_latency_watch: usize,
    pub(crate) priority_actions: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct WorkbenchOverview {
    pub(crate) generated_at: String,
    pub(crate) queue: WorkbenchQueueOverview,
    pub(crate) cases: WorkbenchCasesOverview,
    pub(crate) incidents: WorkbenchIncidentsOverview,
    pub(crate) response: WorkbenchResponseOverview,
    pub(crate) identity: WorkbenchIdentityOverview,
    pub(crate) rollouts: WorkbenchRolloutOverview,
    pub(crate) content: WorkbenchContentOverview,
    pub(crate) automation: WorkbenchAutomationOverview,
    pub(crate) analytics: WorkbenchAnalyticsOverview,
    pub(crate) team_load: WorkbenchTeamLoadOverview,
    pub(crate) connector_impact: WorkbenchConnectorImpactOverview,
    pub(crate) detection_review: WorkbenchDetectionReviewOverview,
    pub(crate) value_brief: WorkbenchValueBrief,
    pub(crate) hot_agents: Vec<HotAgentSummary>,
    pub(crate) urgent_items: Vec<UrgentItem>,
    pub(crate) recommendations: Vec<WorkbenchRecommendation>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ManagerFleetOverview {
    pub(crate) total_agents: usize,
    pub(crate) online: usize,
    pub(crate) stale: usize,
    pub(crate) offline: usize,
    pub(crate) coverage_pct: f32,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ManagerQueueOverview {
    pub(crate) pending: usize,
    pub(crate) acknowledged: usize,
    pub(crate) assigned: usize,
    pub(crate) sla_breached: usize,
    pub(crate) critical_pending: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ManagerIncidentOverview {
    pub(crate) total: usize,
    pub(crate) open: usize,
    pub(crate) investigating: usize,
    pub(crate) contained: usize,
    pub(crate) resolved: usize,
    pub(crate) false_positive: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ManagerDeploymentOverview {
    pub(crate) published_releases: usize,
    pub(crate) pending: usize,
    pub(crate) by_status: HashMap<String, usize>,
    pub(crate) by_ring: HashMap<String, usize>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ManagerReportOverview {
    pub(crate) total_reports: usize,
    pub(crate) total_alerts: usize,
    pub(crate) critical_alerts: usize,
    pub(crate) avg_score: Option<f32>,
    pub(crate) max_score: f32,
    pub(crate) open_incidents: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ManagerComplianceOverview {
    pub(crate) score: f64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ManagerOperationsOverview {
    pub(crate) pending_approvals: usize,
    pub(crate) ready_to_execute: usize,
    pub(crate) protected_assets: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ManagerOverview {
    pub(crate) generated_at: String,
    pub(crate) fleet: ManagerFleetOverview,
    pub(crate) queue: ManagerQueueOverview,
    pub(crate) incidents: ManagerIncidentOverview,
    pub(crate) deployments: ManagerDeploymentOverview,
    pub(crate) reports: ManagerReportOverview,
    pub(crate) siem: crate::siem::SiemStatus,
    pub(crate) compliance: ManagerComplianceOverview,
    pub(crate) tenants: usize,
    pub(crate) operations: ManagerOperationsOverview,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct EntityRiskComponent {
    pub(crate) name: String,
    pub(crate) score: f64,
    pub(crate) weight: f64,
    pub(crate) rationale: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct EntityRiskScore {
    pub(crate) entity_kind: String,
    pub(crate) entity_id: String,
    pub(crate) score: f64,
    pub(crate) confidence: f64,
    pub(crate) rationale: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) peer_group: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) score_components: Vec<EntityRiskComponent>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) sequence_signals: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) graph_context: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) recommended_pivots: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct OnboardingReadinessCheck {
    pub(crate) key: String,
    pub(crate) label: String,
    pub(crate) ready: bool,
    pub(crate) status: String,
    pub(crate) detail: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct OnboardingReadiness {
    pub(crate) generated_at: String,
    pub(crate) ready: bool,
    pub(crate) completed: usize,
    pub(crate) total: usize,
    pub(crate) estimated_minutes: u64,
    pub(crate) checks: Vec<OnboardingReadinessCheck>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct DetectionExplainability {
    pub(crate) event_id: Option<u64>,
    pub(crate) alert_id: Option<String>,
    pub(crate) severity: String,
    pub(crate) title: String,
    pub(crate) summary: Vec<String>,
    pub(crate) why_fired: Vec<String>,
    pub(crate) why_safe_or_noisy: Vec<String>,
    pub(crate) next_steps: Vec<String>,
    pub(crate) evidence: Vec<crate::detection_feedback::DetectionEvidence>,
    pub(crate) entity_scores: Vec<EntityRiskScore>,
    pub(crate) triage_status: Option<String>,
    pub(crate) related_cases: Vec<String>,
    pub(crate) feedback: Vec<crate::detection_feedback::DetectionFeedback>,
    pub(crate) evidence_chain: Vec<serde_json::Value>,
    pub(crate) matched_rules: Vec<serde_json::Value>,
    pub(crate) similar_past_alerts: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ManagerQueueDigest {
    pub(crate) generated_at: String,
    pub(crate) queue: ManagerQueueOverview,
    pub(crate) stale_cases: usize,
    pub(crate) degraded_collectors: usize,
    pub(crate) pending_dry_run_approvals: usize,
    pub(crate) ready_to_execute: usize,
    pub(crate) recent_suppressions: Vec<serde_json::Value>,
    pub(crate) noisy_reasons: Vec<String>,
    pub(crate) changes_since_last_shift: Vec<String>,
    pub(crate) top_queue_items: Vec<QueueAlertSummary>,
    pub(crate) urgent_items: Vec<UrgentItem>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct AgentLogSummary {
    pub(crate) total_records: usize,
    pub(crate) last_timestamp: Option<String>,
    pub(crate) by_level: HashMap<String, usize>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct AgentInventorySummary {
    pub(crate) collected_at: String,
    pub(crate) software_count: usize,
    pub(crate) services_count: usize,
    pub(crate) network_ports: usize,
    pub(crate) users_count: usize,
    pub(crate) hardware: crate::inventory::HardwareInfo,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct AgentEventAnalyticsSummary {
    pub(crate) event_count: usize,
    pub(crate) correlated_count: usize,
    pub(crate) critical_count: usize,
    pub(crate) average_score: f32,
    pub(crate) max_score: f32,
    pub(crate) highest_level: String,
    pub(crate) risk: String,
    pub(crate) top_reasons: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct AgentActivitySnapshot {
    pub(crate) agent: AgentIdentity,
    pub(crate) local_console: bool,
    pub(crate) computed_status: String,
    pub(crate) heartbeat_age_secs: Option<u64>,
    pub(crate) deployment: Option<AgentDeployment>,
    pub(crate) scope_override: bool,
    pub(crate) effective_scope: crate::config::MonitorScopeSettings,
    pub(crate) health: AgentHealth,
    pub(crate) analytics: AgentEventAnalyticsSummary,
    pub(crate) timeline: Vec<serde_json::Value>,
    pub(crate) risk_transitions: Vec<serde_json::Value>,
    pub(crate) inventory: Option<AgentInventorySummary>,
    pub(crate) log_summary: AgentLogSummary,
}

pub(crate) const LOCAL_CONSOLE_AGENT_ID: &str = "local-console";

pub(crate) fn timestamp_ms_to_rfc3339(timestamp_ms: u64) -> Option<String> {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(timestamp_ms as i64)
        .map(|timestamp| timestamp.to_rfc3339())
}

pub(crate) fn local_console_identity(state: &AppState) -> AgentIdentity {
    let now = chrono::Utc::now().to_rfc3339();
    let enrolled_at = state
        .local_telemetry
        .front()
        .and_then(|sample| timestamp_ms_to_rfc3339(sample.timestamp_ms))
        .unwrap_or_else(|| now.clone());
    let last_seen = state
        .local_telemetry
        .back()
        .and_then(|sample| timestamp_ms_to_rfc3339(sample.timestamp_ms))
        .unwrap_or_else(|| now.clone());
    let mut labels = HashMap::new();
    labels.insert("local_console".to_string(), "true".to_string());
    labels.insert("role".to_string(), "control-plane".to_string());

    AgentIdentity {
        id: LOCAL_CONSOLE_AGENT_ID.to_string(),
        hostname: state.local_host_info.hostname.clone(),
        platform: state.local_host_info.platform.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        enrolled_at,
        last_seen,
        status: AgentStatus::Online,
        labels,
        agent_token_hash: String::new(),
        health: AgentHealth {
            pending_alerts: state
                .alerts
                .iter()
                .filter(|alert| alert.hostname == state.local_host_info.hostname)
                .count(),
            telemetry_queue_depth: state.local_telemetry.len(),
            ..AgentHealth::default()
        },
        monitor_scope: None,
    }
}

pub(crate) fn local_console_agent_summary_json(state: &AppState) -> serde_json::Value {
    let local_agent = local_console_identity(state);
    let latest_sample = state.local_telemetry.back();
    let mut summary = agent_summary_json(
        &local_agent,
        None,
        state.agent_registry.heartbeat_interval(),
        state.policy_store.current_version(),
    );
    if let Some(object) = summary.as_object_mut() {
        object.insert("local_console".to_string(), serde_json::Value::Bool(true));
        object.insert(
            "local_monitoring".to_string(),
            serde_json::Value::Bool(true),
        );
        object.insert(
            "source".to_string(),
            serde_json::Value::String("local".to_string()),
        );
        object.insert(
            "os_version".to_string(),
            serde_json::Value::String(state.local_host_info.os_version.clone()),
        );
        object.insert(
            "arch".to_string(),
            serde_json::Value::String(state.local_host_info.arch.clone()),
        );
        object.insert(
            "telemetry_samples".to_string(),
            serde_json::Value::Number(serde_json::Number::from(state.local_telemetry.len())),
        );
        object.insert(
            "process_count".to_string(),
            serde_json::json!(latest_sample.map(|sample| sample.process_count)),
        );
        object.insert(
            "inventory_available".to_string(),
            serde_json::Value::Bool(state.last_inventory.is_some()),
        );
    }
    summary
}
