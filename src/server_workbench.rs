//! Workbench, manager, and onboarding overview helpers.

use super::*;

fn response_status_counts(requests: &[ResponseRequest]) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    for request in requests {
        let key = format!("{:?}", request.status);
        *counts.entry(key).or_insert(0) += 1;
    }
    counts
}

pub(super) fn queue_alert_summary(
    item: &crate::analyst::QueuedAlert,
    event_store: &EventStore,
) -> QueueAlertSummary {
    let linked_event = event_store.get_event(item.event_id);
    let age_secs = age_secs_since(&item.timestamp);
    let sla_breached = item
        .sla_deadline
        .as_deref()
        .and_then(|deadline| chrono::DateTime::parse_from_rfc3339(deadline).ok())
        .is_some_and(|deadline| chrono::Utc::now() > deadline.with_timezone(&chrono::Utc));
    QueueAlertSummary {
        event_id: item.event_id,
        agent_id: linked_event.map(|event| event.agent_id.clone()),
        score: item.score,
        severity: severity_label(&item.level).to_string(),
        hostname: item.hostname.clone(),
        status: if item.acknowledged {
            "acknowledged".to_string()
        } else if item.assignee.is_some() {
            "assigned".to_string()
        } else {
            "pending".to_string()
        },
        assignee: item.assignee.clone(),
        timestamp: item.timestamp.clone(),
        age_secs,
        sla_deadline: item.sla_deadline.clone(),
        sla_breached,
        reasons: linked_event
            .map(|event| event.alert.reasons.clone())
            .unwrap_or_default(),
    }
}

pub(super) fn case_summary(case: &crate::analyst::Case) -> CaseSummary {
    CaseSummary {
        id: case.id,
        title: case.title.clone(),
        status: format!("{:?}", case.status),
        priority: format!("{:?}", case.priority),
        assignee: case.assignee.clone(),
        incident_count: case.incident_ids.len(),
        event_count: case.event_ids.len(),
        updated_at: case.updated_at.clone(),
        tags: case.tags.clone(),
    }
}

fn incident_summary(incident: &crate::incident::Incident) -> IncidentSummary {
    IncidentSummary {
        id: incident.id,
        title: incident.title.clone(),
        severity: incident.severity.clone(),
        status: format!("{:?}", incident.status),
        assignee: incident.assignee.clone(),
        created_at: incident.created_at.clone(),
        updated_at: incident.updated_at.clone(),
        agent_count: incident.agent_ids.len(),
        event_count: incident.event_ids.len(),
    }
}

fn build_hot_agent_summaries(
    analytics: &EventAnalytics,
    registry: &AgentRegistry,
    deployments: &HashMap<String, AgentDeployment>,
) -> Vec<HotAgentSummary> {
    analytics
        .hot_agents
        .iter()
        .take(5)
        .map(|agent| {
            let registry_agent = registry.get(&agent.agent_id);
            let deployment = deployments.get(&agent.agent_id);
            let (status, _) = registry_agent.map_or_else(
                || ("unknown".to_string(), None),
                |entry| computed_agent_status(entry, registry.heartbeat_interval()),
            );
            HotAgentSummary {
                agent_id: agent.agent_id.clone(),
                hostname: registry_agent.map(|entry| entry.hostname.clone()),
                risk: agent.risk.clone(),
                status,
                event_count: agent.event_count,
                correlated_count: agent.correlated_count,
                max_score: agent.max_score,
                current_version: registry_agent.map(|entry| entry.version.clone()),
                target_version: deployment.map(|entry| entry.version.clone()),
                rollout_group: deployment.map(|entry| entry.rollout_group.clone()),
                deployment_status: deployment.map(|entry| entry.status.clone()),
            }
        })
        .collect()
}

#[derive(Default)]
struct OwnerLoadAccumulator {
    username: String,
    role: String,
    enabled: bool,
    queue_assigned: usize,
    queue_sla_breached: usize,
    cases_open: usize,
    incidents_open: usize,
    stale_cases: usize,
    stale_incidents: usize,
    last_case_update: Option<String>,
}

fn load_owner_status(load_score: usize, stale_items: usize, active_items: usize) -> &'static str {
    if stale_items > 0 || load_score >= 9 {
        "overloaded"
    } else if active_items == 0 {
        "available"
    } else {
        "balanced"
    }
}

fn case_or_incident_is_open(status: &str) -> bool {
    !matches!(
        status,
        "resolved" | "closed" | "falsepositive" | "false_positive"
    )
}

fn stale_ownership(updated_at: &str, threshold_secs: u64) -> bool {
    age_secs_since(updated_at).is_some_and(|age| age >= threshold_secs)
}

fn build_team_load_overview(
    queue_items: &[QueueAlertSummary],
    cases: &[&crate::analyst::Case],
    incidents: &[crate::incident::Incident],
    response_requests: &[ResponseRequest],
    rbac: &crate::rbac::RbacStore,
    mapped_role_context: &HashMap<String, String>,
    automation_targets: &HashSet<String>,
) -> WorkbenchTeamLoadOverview {
    let mut owners: HashMap<String, OwnerLoadAccumulator> = HashMap::new();
    let mut role_coverage: HashMap<String, (usize, usize)> = HashMap::new();

    for user in rbac.list_users() {
        let role = format!("{:?}", user.role);
        let entry = owners.entry(user.username.clone()).or_default();
        entry.username = user.username.clone();
        entry.role = role.clone();
        entry.enabled = user.enabled;
        let coverage = role_coverage.entry(role).or_insert((0, 0));
        coverage.0 += 1;
        if user.enabled {
            coverage.1 += 1;
        }
    }

    for item in queue_items {
        if let Some(assignee) = item.assignee.as_deref() {
            let entry = owners.entry(assignee.to_string()).or_default();
            if entry.username.is_empty() {
                entry.username = assignee.to_string();
                entry.role = "Unmapped".to_string();
                entry.enabled = true;
            }
            entry.queue_assigned += 1;
            if item.sla_breached {
                entry.queue_sla_breached += 1;
            }
        }
    }

    for case in cases {
        if !case_or_incident_is_open(&format!("{:?}", case.status).to_ascii_lowercase()) {
            continue;
        }
        if let Some(assignee) = case.assignee.as_deref() {
            let entry = owners.entry(assignee.to_string()).or_default();
            if entry.username.is_empty() {
                entry.username = assignee.to_string();
                entry.role = "Unmapped".to_string();
                entry.enabled = true;
            }
            entry.cases_open += 1;
            if stale_ownership(&case.updated_at, 4 * 60 * 60) {
                entry.stale_cases += 1;
            }
            if entry
                .last_case_update
                .as_ref()
                .is_none_or(|current| current < &case.updated_at)
            {
                entry.last_case_update = Some(case.updated_at.clone());
            }
        }
    }

    for incident in incidents {
        if !case_or_incident_is_open(&format!("{:?}", incident.status).to_ascii_lowercase()) {
            continue;
        }
        if let Some(assignee) = incident.assignee.as_deref() {
            let entry = owners.entry(assignee.to_string()).or_default();
            if entry.username.is_empty() {
                entry.username = assignee.to_string();
                entry.role = "Unmapped".to_string();
                entry.enabled = true;
            }
            entry.incidents_open += 1;
            if stale_ownership(&incident.updated_at, 6 * 60 * 60) {
                entry.stale_incidents += 1;
            }
        }
    }

    let pending_approvals = response_requests
        .iter()
        .filter(|request| request.status == ApprovalStatus::Pending)
        .count();
    let unassigned_queue = queue_items
        .iter()
        .filter(|item| item.status == "pending" && item.assignee.is_none())
        .count();
    let unassigned_cases = cases
        .iter()
        .filter(|case| {
            case.assignee.is_none()
                && case_or_incident_is_open(&format!("{:?}", case.status).to_ascii_lowercase())
        })
        .count();

    let mut analysts = owners
        .into_values()
        .map(|entry| {
            let stale_items = entry.queue_sla_breached + entry.stale_cases + entry.stale_incidents;
            let active_items = entry.queue_assigned + entry.cases_open + entry.incidents_open;
            let load_score = entry.queue_assigned * 2
                + entry.cases_open * 3
                + entry.incidents_open * 4
                + stale_items * 2;
            let status = load_owner_status(load_score, stale_items, active_items).to_string();
            let next_action = if entry.queue_sla_breached > 0 {
                "Reassign breached queue work or clear the oldest SLA-risk alert.".to_string()
            } else if entry.stale_cases + entry.stale_incidents > 0 {
                "Refresh ownership notes and move dormant investigations before handoff."
                    .to_string()
            } else if active_items == 0 {
                "Pick up unassigned queue work or the next open case.".to_string()
            } else {
                "Keep case notes, queue ownership, and incident next steps current.".to_string()
            };
            WorkbenchOwnerLoadSummary {
                username: entry.username,
                role: entry.role,
                enabled: entry.enabled,
                queue_assigned: entry.queue_assigned,
                queue_sla_breached: entry.queue_sla_breached,
                cases_open: entry.cases_open,
                incidents_open: entry.incidents_open,
                stale_cases: entry.stale_cases,
                stale_incidents: entry.stale_incidents,
                load_score,
                status,
                last_case_update: entry.last_case_update,
                next_action,
            }
        })
        .collect::<Vec<_>>();

    analysts.sort_by(|left, right| {
        right
            .load_score
            .cmp(&left.load_score)
            .then_with(|| left.username.cmp(&right.username))
    });

    let active_owners = analysts
        .iter()
        .filter(|entry| entry.queue_assigned + entry.cases_open + entry.incidents_open > 0)
        .count();
    let available_owners = analysts
        .iter()
        .filter(|entry| entry.status == "available" && entry.enabled)
        .count();
    let stale_ownership_items = analysts
        .iter()
        .map(|entry| entry.queue_sla_breached + entry.stale_cases + entry.stale_incidents)
        .sum();
    let load_scores = analysts
        .iter()
        .map(|entry| entry.load_score)
        .collect::<Vec<_>>();
    let average_load_score = if load_scores.is_empty() {
        0.0
    } else {
        load_scores.iter().sum::<usize>() as f64 / load_scores.len() as f64
    };
    let max_load = load_scores.iter().copied().max().unwrap_or_default();
    let min_load = load_scores.iter().copied().min().unwrap_or_default();
    let overloaded_owners = analysts
        .iter()
        .filter(|entry| entry.status == "overloaded")
        .count();

    let rebalance_hint = if unassigned_queue + unassigned_cases > 0 && available_owners > 0 {
        "Move unassigned queue work and open cases onto available analysts before the next shift."
            .to_string()
    } else if overloaded_owners > 0 && available_owners > 0 {
        "Shift the oldest case or breached queue item away from overloaded owners.".to_string()
    } else if pending_approvals > 0 {
        "Pair the shift lead with an approver so response and remediation requests do not stall."
            .to_string()
    } else {
        "Ownership looks balanced; keep role coverage and group routing aligned with current lanes."
            .to_string()
    };

    let mut role_coverage = role_coverage
        .into_iter()
        .map(|(role, (count, enabled))| WorkbenchRoleCoverage {
            role,
            count,
            enabled,
        })
        .collect::<Vec<_>>();
    role_coverage.sort_by(|left, right| left.role.cmp(&right.role));

    let mut group_context = mapped_role_context
        .iter()
        .map(|(group, mapped_role)| WorkbenchGroupCoverage {
            group: group.clone(),
            mapped_role: Some(mapped_role.clone()),
            automation_targets: usize::from(automation_targets.contains(group)),
            status: if automation_targets.contains(group) {
                "aligned".to_string()
            } else {
                "mapped".to_string()
            },
        })
        .collect::<Vec<_>>();
    for group in automation_targets {
        if group_context.iter().any(|entry| entry.group == *group) {
            continue;
        }
        group_context.push(WorkbenchGroupCoverage {
            group: group.clone(),
            mapped_role: None,
            automation_targets: 1,
            status: "gap".to_string(),
        });
    }
    group_context.sort_by(|left, right| left.group.cmp(&right.group));

    WorkbenchTeamLoadOverview {
        active_owners,
        available_owners,
        pending_approvals,
        unassigned_queue,
        unassigned_cases,
        stale_ownership_items,
        average_load_score,
        balance_spread: max_load.saturating_sub(min_load),
        rebalance_hint,
        analysts,
        role_coverage,
        group_context,
    }
}

fn collector_lane_keywords(lane: &str) -> &'static [&'static str] {
    match lane {
        "identity" => &[
            "identity",
            "auth",
            "credential",
            "okta",
            "entra",
            "mfa",
            "login",
        ],
        "saas" => &["github", "workspace", "m365", "saas", "cloud app", "oauth"],
        "edr" => &[
            "process",
            "endpoint",
            "powershell",
            "execution",
            "edr",
            "host",
        ],
        "network" => &["dns", "tls", "network", "beacon", "traffic", "c2"],
        _ => &["cloud", "aws", "azure", "gcp", "iam", "bucket", "trail"],
    }
}

pub(crate) fn rule_matches_collector_lane(
    rule: &crate::enterprise::ManagedRuleMetadata,
    lane: &str,
) -> bool {
    let haystack = format!(
        "{} {} {} {}",
        rule.title,
        rule.description,
        rule.pack_ids.join(" "),
        rule.owner
    )
    .to_ascii_lowercase();
    collector_lane_keywords(lane)
        .iter()
        .any(|keyword| haystack.contains(keyword))
}

fn asset_matches_collector_lane(asset: &crate::cloud_inventory::UnifiedAsset, lane: &str) -> bool {
    match lane {
        "identity" => matches!(
            asset.asset_type,
            crate::cloud_inventory::AssetType::OnPremHost
                | crate::cloud_inventory::AssetType::CloudService
        ),
        "saas" => matches!(
            asset.asset_type,
            crate::cloud_inventory::AssetType::CloudService
                | crate::cloud_inventory::AssetType::StorageBucket
        ),
        "edr" => {
            asset.agent_id.is_some()
                || matches!(
                    asset.asset_type,
                    crate::cloud_inventory::AssetType::OnPremHost
                        | crate::cloud_inventory::AssetType::Container
                )
        }
        "network" => matches!(
            asset.asset_type,
            crate::cloud_inventory::AssetType::NetworkDevice
                | crate::cloud_inventory::AssetType::LoadBalancer
                | crate::cloud_inventory::AssetType::IoTDevice
        ),
        _ => matches!(
            asset.asset_type,
            crate::cloud_inventory::AssetType::CloudVm
                | crate::cloud_inventory::AssetType::CloudService
                | crate::cloud_inventory::AssetType::Database
                | crate::cloud_inventory::AssetType::KubernetesCluster
                | crate::cloud_inventory::AssetType::StorageBucket
        ),
    }
}

fn asset_is_stale(asset: &crate::cloud_inventory::UnifiedAsset) -> bool {
    asset.status != crate::cloud_inventory::AssetStatus::Active
        || age_secs_since(&asset.last_seen).is_some_and(|age| age >= 24 * 60 * 60)
}

fn default_connector_owner(lane: &str) -> &'static str {
    match lane {
        "identity" => "identity owner",
        "saas" => "saas owner",
        "edr" => "endpoint owner",
        "network" => "network owner",
        _ => "platform owner",
    }
}

fn top_asset_owner(
    assets: &[&crate::cloud_inventory::UnifiedAsset],
    fallback: &str,
) -> (String, usize) {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for asset in assets {
        let owner = asset
            .owner
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(fallback);
        *counts.entry(owner.to_string()).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .max_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)))
        .unwrap_or_else(|| (fallback.to_string(), 0))
}

fn build_connector_impact_overview(
    collectors: &[serde_json::Value],
    rule_metadata: &[crate::enterprise::ManagedRuleMetadata],
    assets: &[crate::cloud_inventory::UnifiedAsset],
) -> WorkbenchConnectorImpactOverview {
    let mut items = collectors
        .iter()
        .map(|collector| {
            let provider = collector
                .get("provider")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("collector")
                .to_string();
            let label = collector
                .get("label")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("Collector")
                .to_string();
            let lane = collector
                .get("lane")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("cloud")
                .to_string();
            let enabled = collector
                .get("enabled")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let freshness = collector
                .get("freshness")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");
            let validation_failure = collector
                .get("validation")
                .and_then(|validation| validation.get("issues"))
                .and_then(serde_json::Value::as_array)
                .and_then(|issues| issues.first())
                .and_then(|issue| issue.get("message"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_string);
            let rules = rule_metadata
                .iter()
                .filter(|rule| rule.enabled && rule_matches_collector_lane(rule, &lane))
                .collect::<Vec<_>>();
            let matched_assets = assets
                .iter()
                .filter(|asset| asset_matches_collector_lane(asset, &lane))
                .collect::<Vec<_>>();
            let stale_assets = matched_assets
                .iter()
                .filter(|asset| asset_is_stale(asset))
                .count();
            let (owner, _) = top_asset_owner(&matched_assets, default_connector_owner(&lane));
            let mut rule_owners = rules
                .iter()
                .map(|rule| rule.owner.clone())
                .filter(|owner| !owner.trim().is_empty())
                .collect::<Vec<_>>();
            rule_owners.sort();
            rule_owners.dedup();
            let sample_detections = rules
                .iter()
                .take(3)
                .map(|rule| format!("{} ({})", rule.title, rule.owner))
                .collect::<Vec<_>>();
            let route_targets = collector
                .get("route_targets")
                .and_then(serde_json::Value::as_array)
                .map(|targets| {
                    targets
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .map(str::to_string)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let setup_pivots = collector
                .get("ingestion_evidence")
                .and_then(|evidence| evidence.get("pivots"))
                .and_then(serde_json::Value::as_array)
                .cloned()
                .unwrap_or_default();
            let status = if !enabled {
                "disabled"
            } else if freshness == "error" || validation_failure.is_some() {
                "review"
            } else if freshness == "stale" || stale_assets > 0 {
                "watch"
            } else {
                "ready"
            }
            .to_string();
            let next_action = if !enabled {
                "Finish collector setup before depending on this lane for downstream detections."
                    .to_string()
            } else if let Some(message) = &validation_failure {
                format!("Resolve validation issue: {message}")
            } else if freshness == "stale" {
                "Confirm the last-good event, refresh credentials, and replay the impacted lane."
                    .to_string()
            } else if stale_assets > 0 {
                "Review stale assets and confirm the affected owner before dismissing connector drift."
                    .to_string()
            } else {
                "Keep validation evidence and downstream detections current for this collector."
                    .to_string()
            };

            WorkbenchConnectorImpactEntry {
                provider,
                label,
                lane,
                status,
                enabled,
                affected_detections: rules.len(),
                stale_assets,
                last_good_event: collector
                    .get("last_success_at")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string),
                validation_failure,
                owner,
                sample_detections,
                rule_owners,
                route_targets,
                setup_pivots,
                next_action,
            }
        })
        .collect::<Vec<_>>();

    items.sort_by(|left, right| {
        let status_rank = |status: &str| match status {
            "review" => 3,
            "watch" => 2,
            "disabled" => 1,
            _ => 0,
        };
        status_rank(&right.status)
            .cmp(&status_rank(&left.status))
            .then_with(|| right.affected_detections.cmp(&left.affected_detections))
            .then_with(|| left.label.cmp(&right.label))
    });

    WorkbenchConnectorImpactOverview {
        collectors_at_risk: items
            .iter()
            .filter(|item| item.status == "review" || item.status == "watch")
            .count(),
        impacted_detections: items.iter().map(|item| item.affected_detections).sum(),
        stale_assets: items.iter().map(|item| item.stale_assets).sum(),
        review_required: items
            .iter()
            .filter(|item| item.validation_failure.is_some() || !item.enabled)
            .count(),
        items,
    }
}

fn build_value_brief(
    connector_impact: &WorkbenchConnectorImpactOverview,
    detection_review: &WorkbenchDetectionReviewOverview,
    response: &WorkbenchResponseOverview,
    content: &WorkbenchContentOverview,
) -> WorkbenchValueBrief {
    let blocked_high_risk_actions = response.pending_approval;
    let coverage_growth_items = content.enabled_packs + content.hunt_library;
    let analyst_hours_saved_estimate = ((detection_review.replay_blockers
        + detection_review.due_this_week
        + connector_impact.impacted_detections) as f64
        * 0.35)
        .max(0.0);
    let mut priority_actions = Vec::new();
    if connector_impact.collectors_at_risk > 0 {
        priority_actions.push(format!(
            "Restore {} collector lane(s) before relying on downstream detections.",
            connector_impact.collectors_at_risk
        ));
    }
    if detection_review.replay_blockers > 0 {
        priority_actions.push(format!(
            "Replay {} blocked detection review item(s) before promotion.",
            detection_review.replay_blockers
        ));
    }
    if blocked_high_risk_actions > 0 {
        priority_actions.push(format!(
            "Review {blocked_high_risk_actions} blocked or approval-gated response action(s)."
        ));
    }
    if priority_actions.is_empty() {
        priority_actions.push(
            "Package current coverage, collector freshness, and response proof for leadership."
                .to_string(),
        );
    }
    WorkbenchValueBrief {
        status: if connector_impact.collectors_at_risk > 0
            || detection_review.replay_blockers > 0
            || blocked_high_risk_actions > 0
        {
            "attention".to_string()
        } else {
            "ready".to_string()
        },
        analyst_hours_saved_estimate,
        coverage_growth_items,
        collector_freshness_risk: connector_impact.collectors_at_risk,
        blocked_high_risk_actions,
        approval_latency_watch: response.pending_approval,
        priority_actions,
    }
}

pub(super) fn build_workbench_overview(
    alert_queue: &AlertQueue,
    case_store: &CaseStore,
    incident_store: &IncidentStore,
    response_orchestrator: &ResponseOrchestrator,
    approval_log: &ApprovalLog,
    analytics: &EventAnalytics,
    event_store: &EventStore,
    agent_registry: &AgentRegistry,
    deployments: &HashMap<String, AgentDeployment>,
    connector_status_entries: &[serde_json::Value],
    assets: &[crate::cloud_inventory::UnifiedAsset],
    rbac: &crate::rbac::RbacStore,
    enterprise: &crate::enterprise::EnterpriseStore,
    detection_feedback: &crate::detection_feedback::DetectionFeedbackStore,
    playbook_engine: &crate::playbook::PlaybookEngine,
    playbook_dsl: &crate::playbook_dsl::PlaybookDslStore,
    workflow_store: &crate::investigation::WorkflowStore,
    api_analytics: &crate::api_analytics::AnalyticsSummary,
) -> WorkbenchOverview {
    let mut queue_items: Vec<QueueAlertSummary> = alert_queue
        .pending()
        .into_iter()
        .map(|item| queue_alert_summary(item, event_store))
        .collect();
    queue_items.sort_by(|left, right| {
        right
            .sla_breached
            .cmp(&left.sla_breached)
            .then_with(|| severity_rank(&right.severity).cmp(&severity_rank(&left.severity)))
            .then_with(|| {
                right
                    .age_secs
                    .unwrap_or_default()
                    .cmp(&left.age_secs.unwrap_or_default())
            })
    });

    let queue_pending = queue_items.len();
    let queue_acknowledged = alert_queue
        .all()
        .iter()
        .filter(|item| item.acknowledged)
        .count();
    let queue_assigned = alert_queue
        .all()
        .iter()
        .filter(|item| item.assignee.is_some())
        .count();
    let queue_breached = queue_items.iter().filter(|item| item.sla_breached).count();

    let mut cases = case_store.list_filtered(None, None, None);
    cases.sort_by(|left, right| right.updated_at.cmp(&left.updated_at));
    let case_total = cases.len();
    let case_open = cases
        .iter()
        .filter(|case| !matches!(case.status, CaseStatus::Resolved | CaseStatus::Closed))
        .count();
    let case_resolved = cases
        .iter()
        .filter(|case| matches!(case.status, CaseStatus::Resolved | CaseStatus::Closed))
        .count();

    let incidents = incident_store.list();
    let mut incident_statuses = HashMap::new();
    for incident in incidents {
        *incident_statuses
            .entry(format!("{:?}", incident.status))
            .or_insert(0) += 1;
    }
    let mut incident_items: Vec<IncidentSummary> = incidents.iter().map(incident_summary).collect();
    incident_items.sort_by(|left, right| right.updated_at.cmp(&left.updated_at));
    let incident_open = incidents
        .iter()
        .filter(|incident| {
            matches!(
                incident.status,
                crate::incident::IncidentStatus::Open
                    | crate::incident::IncidentStatus::Investigating
            )
        })
        .count();
    let incident_critical_open = incidents
        .iter()
        .filter(|incident| {
            incident.severity.eq_ignore_ascii_case("critical")
                && matches!(
                    incident.status,
                    crate::incident::IncidentStatus::Open
                        | crate::incident::IncidentStatus::Investigating
                )
        })
        .count();

    let mut requests = response_orchestrator.all_requests();
    requests.sort_by(|left, right| right.requested_at.cmp(&left.requested_at));
    let response_counts = response_status_counts(&requests);
    let ready_to_execute = requests
        .iter()
        .filter(|request| request.status == ApprovalStatus::Approved && !request.dry_run)
        .count();
    let recent_requests = requests
        .iter()
        .take(6)
        .map(response_request_json)
        .collect::<Vec<_>>();
    let recent_approvals = approval_log
        .recent(6)
        .iter()
        .map(|entry| {
            serde_json::json!({
                "request_id": entry.request_id,
                "decision": format!("{:?}", entry.decision),
                "approver": entry.approver,
                "reason": entry.reason,
                "decided_at": entry.decided_at,
            })
        })
        .collect::<Vec<_>>();

    let identity_summaries = enterprise.idp_provider_summaries();
    let ready_providers = identity_summaries
        .iter()
        .filter(|summary| summary.validation.status == "ready")
        .count();
    let providers_with_gaps = identity_summaries
        .iter()
        .filter(|summary| summary.validation.status != "ready")
        .count();
    let scim_validation = enterprise.scim_validation();
    let mut mapped_groups = HashSet::new();
    let mut mapped_role_context = HashMap::new();
    for summary in &identity_summaries {
        for (group, role) in &summary.provider.group_role_mappings {
            mapped_groups.insert(group.clone());
            mapped_role_context
                .entry(group.clone())
                .or_insert_with(|| role.clone());
        }
    }
    for (group, role) in &enterprise.scim().group_role_mappings {
        mapped_groups.insert(group.clone());
        mapped_role_context.insert(group.clone(), role.clone());
    }

    let hunts = enterprise.hunts();
    let packs = enterprise.packs();
    let automation_targets: HashSet<String> = packs
        .iter()
        .filter_map(|pack| pack.target_group.clone())
        .chain(hunts.iter().filter_map(|hunt| hunt.target_group.clone()))
        .collect();
    let automation_targets_aligned = automation_targets
        .iter()
        .filter(|group| mapped_groups.contains(*group))
        .count();

    let canary_rules = enterprise
        .builtin_rules()
        .iter()
        .filter(|rule| {
            rule.enabled && rule.lifecycle == crate::enterprise::ContentLifecycle::Canary
        })
        .count()
        + enterprise
            .native_rules()
            .iter()
            .filter(|rule| {
                rule.metadata.enabled
                    && rule.metadata.lifecycle == crate::enterprise::ContentLifecycle::Canary
            })
            .count();
    let promotion_ready_rules = enterprise
        .builtin_rules()
        .iter()
        .filter(|rule| {
            matches!(
                rule.lifecycle,
                crate::enterprise::ContentLifecycle::Test
                    | crate::enterprise::ContentLifecycle::Canary
            ) && rule.last_test_at.is_some()
        })
        .count()
        + enterprise
            .native_rules()
            .iter()
            .filter(|rule| {
                matches!(
                    rule.metadata.lifecycle,
                    crate::enterprise::ContentLifecycle::Test
                        | crate::enterprise::ContentLifecycle::Canary
                ) && rule.metadata.last_test_at.is_some()
            })
            .count();
    let canary_hunts = hunts
        .iter()
        .filter(|hunt| hunt.lifecycle == crate::enterprise::ContentLifecycle::Canary)
        .count();
    let active_hunts = hunts.iter().filter(|hunt| hunt.enabled).count();
    let average_canary_percentage = hunts
        .iter()
        .filter(|hunt| hunt.lifecycle == crate::enterprise::ContentLifecycle::Canary)
        .map(|hunt| hunt.canary_percentage as usize)
        .sum::<usize>()
        .checked_div(canary_hunts)
        .map(|average| average as u8);

    let saved_searches = hunts.len()
        + packs
            .iter()
            .map(|pack| pack.saved_searches.len())
            .sum::<usize>();
    let latest_pack_update = packs.iter().map(|pack| pack.updated_at.clone()).max();

    let rollout_history = enterprise.rollout_history();
    let historical_rollout_events = rollout_history.len();
    let rollback_events = rollout_history
        .iter()
        .filter(|event| event.action.ends_with("rollback"))
        .count();
    let last_rollout_at = rollout_history
        .last()
        .map(|event| event.recorded_at.clone());
    let mut recent_rollout_history = rollout_history
        .iter()
        .rev()
        .take(4)
        .cloned()
        .collect::<Vec<_>>();
    recent_rollout_history.reverse();

    let recent_playbook_executions = playbook_engine.recent_executions(50);
    let merged_playbook_history = merge_playbook_history(
        enterprise.playbook_history(),
        &recent_playbook_executions,
        50,
    );
    let historical_playbook_runs = merged_playbook_history.len();
    let completed_playbook_history: Vec<&crate::enterprise::PlaybookAnalyticsRecord> =
        merged_playbook_history
            .iter()
            .filter(|execution| {
                matches!(
                    execution.status.as_str(),
                    "succeeded" | "failed" | "timed_out" | "cancelled"
                )
            })
            .collect();
    let succeeded_historical_runs = completed_playbook_history
        .iter()
        .filter(|execution| execution.status == "succeeded")
        .count();
    let avg_execution_ms = if !completed_playbook_history.is_empty() {
        let durations = completed_playbook_history
            .iter()
            .filter_map(|execution| execution.duration_ms)
            .collect::<Vec<_>>();
        if durations.is_empty() {
            None
        } else {
            Some(durations.iter().sum::<u64>() / durations.len() as u64)
        }
    } else {
        None
    };
    let mut recent_playbook_history = merged_playbook_history
        .iter()
        .rev()
        .take(4)
        .cloned()
        .collect::<Vec<_>>();
    recent_playbook_history.reverse();
    let last_execution_at = merged_playbook_history.last().map(|execution| {
        execution
            .finished_at
            .clone()
            .unwrap_or_else(|| execution.started_at.clone())
    });
    let pending_automation_approvals = merged_playbook_history
        .iter()
        .filter(|execution| execution.status == "awaiting_approval")
        .count()
        .max(
            recent_playbook_executions
                .iter()
                .filter(|execution| {
                    execution.status == crate::playbook::ExecutionStatus::AwaitingApproval
                })
                .count(),
        );

    let enterprise_metrics = enterprise.metrics();
    let busiest_endpoint = api_analytics
        .top_endpoints
        .first()
        .map(|endpoint| format!("{} {}", endpoint.method, endpoint.path));
    let worst_p95_ms = api_analytics
        .top_endpoints
        .iter()
        .map(|endpoint| endpoint.p95_latency_ms.round() as u64)
        .max();
    let rule_metadata = enterprise
        .builtin_rules()
        .iter()
        .cloned()
        .chain(
            enterprise
                .native_rules()
                .iter()
                .map(|rule| rule.metadata.clone()),
        )
        .collect::<Vec<_>>();

    let hot_agents = build_hot_agent_summaries(analytics, agent_registry, deployments);
    let team_load = build_team_load_overview(
        &queue_items,
        &cases,
        incidents,
        &requests,
        rbac,
        &mapped_role_context,
        &automation_targets,
    );
    let connector_impact =
        build_connector_impact_overview(connector_status_entries, &rule_metadata, assets);
    let detection_review = build_detection_review_overview(
        enterprise,
        &rule_metadata,
        detection_feedback,
        enterprise.active_suppression_count(),
    );

    let mut urgent_items = Vec::new();
    for item in queue_items.iter().take(3) {
        urgent_items.push(UrgentItem {
            kind: "queue".to_string(),
            severity: if item.sla_breached {
                "Critical".to_string()
            } else {
                item.severity.clone()
            },
            title: format!("Queue item #{} on {}", item.event_id, item.hostname),
            subtitle: if item.sla_breached {
                "SLA breached".to_string()
            } else {
                format!("{} • {}", item.status, item.reasons.join(", "))
            },
            reference_id: item.event_id.to_string(),
        });
    }
    for incident in incident_items
        .iter()
        .filter(|incident| incident.severity.eq_ignore_ascii_case("critical"))
        .take(2)
    {
        urgent_items.push(UrgentItem {
            kind: "incident".to_string(),
            severity: incident.severity.clone(),
            title: incident.title.clone(),
            subtitle: format!("{} • {} agents", incident.status, incident.agent_count),
            reference_id: incident.id.to_string(),
        });
    }
    if ready_to_execute > 0 {
        urgent_items.push(UrgentItem {
            kind: "response".to_string(),
            severity: "Severe".to_string(),
            title: format!("{ready_to_execute} response action(s) ready to execute"),
            subtitle: "Approved actions are waiting in the response queue".to_string(),
            reference_id: "ready".to_string(),
        });
    }
    if let Some(agent) = hot_agents
        .iter()
        .find(|agent| matches!(agent.status.as_str(), "stale" | "offline"))
    {
        urgent_items.push(UrgentItem {
            kind: "agent".to_string(),
            severity: "Elevated".to_string(),
            title: format!(
                "{} requires attention",
                agent
                    .hostname
                    .clone()
                    .unwrap_or_else(|| agent.agent_id.clone())
            ),
            subtitle: format!("{} endpoint with risk {}", agent.status, agent.risk),
            reference_id: agent.agent_id.clone(),
        });
    }
    if pending_automation_approvals > 0 {
        urgent_items.push(UrgentItem {
            kind: "automation".to_string(),
            severity: "Elevated".to_string(),
            title: format!("{pending_automation_approvals} automation approval(s) waiting"),
            subtitle: "Playbook executions have paused for human approval".to_string(),
            reference_id: "automation-approvals".to_string(),
        });
    }
    if !automation_targets.is_empty() && automation_targets_aligned < automation_targets.len() {
        urgent_items.push(UrgentItem {
            kind: "identity".to_string(),
            severity: "Elevated".to_string(),
            title: "Automation targets are not fully identity-mapped".to_string(),
            subtitle: format!(
                "{} of {} target groups align with IdP or SCIM mappings",
                automation_targets_aligned,
                automation_targets.len()
            ),
            reference_id: "identity-routing".to_string(),
        });
    }
    if canary_rules + canary_hunts > 0 {
        urgent_items.push(UrgentItem {
            kind: "content".to_string(),
            severity: "Info".to_string(),
            title: format!(
                "{} canary content item(s) need promotion tracking",
                canary_rules + canary_hunts
            ),
            subtitle: "Review validation results before promoting hunts and rules broadly"
                .to_string(),
            reference_id: "content-rollout".to_string(),
        });
    }

    let mut recommendations = Vec::new();
    if ready_providers == 0 || scim_validation.status != "ready" {
        recommendations.push(WorkbenchRecommendation {
            category: "identity".to_string(),
            priority: "high".to_string(),
            title: "Complete identity routing".to_string(),
            summary: if identity_summaries.is_empty() {
                "No identity provider is ready for targeted automation routing yet.".to_string()
            } else {
                "Provider or SCIM validation still blocks clean group-based routing.".to_string()
            },
            action_hint:
                "Review IdP and SCIM mappings before widening automated response coverage."
                    .to_string(),
        });
    }
    if canary_rules + canary_hunts > 0 {
        recommendations.push(WorkbenchRecommendation {
            category: "rollout".to_string(),
            priority: "medium".to_string(),
            title: "Promote validated canaries".to_string(),
            summary: format!(
                "{canary_rules} rule(s) and {canary_hunts} hunt(s) are still in canary."
            ),
            action_hint:
                "Use the detection workspace to confirm tests and push mature content to active."
                    .to_string(),
        });
    }
    if packs
        .iter()
        .any(|pack| pack.recommended_workflows.is_empty())
        || packs.iter().any(|pack| pack.saved_searches.is_empty())
    {
        recommendations.push(WorkbenchRecommendation {
            category: "content".to_string(),
            priority: "medium".to_string(),
            title: "Finish pack automation bundles".to_string(),
            summary: "Some content packs still lack saved-search templates or investigation routing."
                .to_string(),
            action_hint: "Attach saved searches and workflow recommendations so packs ship as reusable bundles."
                .to_string(),
        });
    }
    if api_analytics.error_rate > 0.02 || enterprise_metrics.last_hunt_latency_ms > 2_000 {
        recommendations.push(WorkbenchRecommendation {
            category: "analytics".to_string(),
            priority: "medium".to_string(),
            title: "Tighten operational analytics".to_string(),
            summary: format!(
                "API error rate is {:.1}% and the most recent hunt latency is {} ms.",
                api_analytics.error_rate * 100.0,
                enterprise_metrics.last_hunt_latency_ms
            ),
            action_hint: "Use the analytics and infrastructure views to investigate latency and endpoint hotspots."
                .to_string(),
        });
    }
    if pending_automation_approvals > 0 || !workflow_store.active_investigations().is_empty() {
        recommendations.push(WorkbenchRecommendation {
            category: "automation".to_string(),
            priority: "medium".to_string(),
            title: "Clear automation backpressure".to_string(),
            summary: format!(
                "{} approval(s) and {} active investigation(s) are in flight.",
                pending_automation_approvals,
                workflow_store.active_investigations().len()
            ),
            action_hint:
                "Review approvals and active investigations so response playbooks do not stall."
                    .to_string(),
        });
    }

    let response_overview = WorkbenchResponseOverview {
        pending_approval: *response_counts.get("Pending").unwrap_or(&0),
        ready_to_execute,
        denied: *response_counts.get("Denied").unwrap_or(&0),
        executed: *response_counts.get("Executed").unwrap_or(&0),
        protected_assets: response_orchestrator.protected_asset_count(),
        recent_requests,
        recent_approvals,
    };
    let content_overview = WorkbenchContentOverview {
        packs: packs.len(),
        enabled_packs: packs.iter().filter(|pack| pack.enabled).count(),
        hunt_library: hunts.len(),
        scheduled_hunts: hunts
            .iter()
            .filter(|hunt| hunt.schedule_interval_secs.is_some())
            .count(),
        saved_searches,
        packs_with_workflows: packs
            .iter()
            .filter(|pack| !pack.recommended_workflows.is_empty())
            .count(),
        latest_pack_update,
    };
    let value_brief = build_value_brief(
        &connector_impact,
        &detection_review,
        &response_overview,
        &content_overview,
    );

    WorkbenchOverview {
        generated_at: chrono::Utc::now().to_rfc3339(),
        queue: WorkbenchQueueOverview {
            pending: queue_pending,
            acknowledged: queue_acknowledged,
            assigned: queue_assigned,
            sla_breached: queue_breached,
            items: queue_items,
        },
        cases: WorkbenchCasesOverview {
            total: case_total,
            open: case_open,
            resolved: case_resolved,
            active: case_total.saturating_sub(case_resolved),
            items: cases
                .iter()
                .take(8)
                .map(|case| case_summary(case))
                .collect(),
        },
        incidents: WorkbenchIncidentsOverview {
            total: incident_items.len(),
            open: incident_open,
            critical_open: incident_critical_open,
            by_status: incident_statuses,
            items: incident_items.into_iter().take(8).collect(),
        },
        response: response_overview,
        identity: WorkbenchIdentityOverview {
            providers_configured: identity_summaries.len(),
            ready_providers,
            providers_with_gaps,
            scim_status: scim_validation.status,
            mapped_groups: mapped_groups.len(),
            automation_targets_aligned,
        },
        rollouts: WorkbenchRolloutOverview {
            canary_rules,
            canary_hunts,
            promotion_ready_rules,
            active_hunts,
            rollout_targets: automation_targets.len(),
            average_canary_percentage,
            historical_events: historical_rollout_events,
            rollback_events,
            last_rollout_at,
            recent_history: recent_rollout_history,
        },
        content: content_overview,
        automation: WorkbenchAutomationOverview {
            playbooks: playbook_engine.list_playbooks().len(),
            workflow_templates: workflow_store.workflow_count(),
            dynamic_templates: playbook_dsl.list().len(),
            active_executions: playbook_engine.active_count()
                + playbook_dsl.active_executions().len(),
            pending_approvals: pending_automation_approvals,
            success_rate: if completed_playbook_history.is_empty() {
                0.0
            } else {
                succeeded_historical_runs as f64 / completed_playbook_history.len() as f64
            },
            avg_execution_ms,
            active_investigations: workflow_store.active_investigations().len(),
            historical_runs: historical_playbook_runs,
            last_execution_at,
            recent_history: recent_playbook_history,
        },
        analytics: WorkbenchAnalyticsOverview {
            api_requests: api_analytics.total_requests,
            api_error_rate: api_analytics.error_rate,
            unique_endpoints: api_analytics.unique_endpoints,
            busiest_endpoint,
            worst_p95_ms,
            search_queries_total: enterprise_metrics.search_queries_total,
            hunt_runs_total: enterprise_metrics.hunt_runs_total,
            response_exec_total: enterprise_metrics.response_exec_total,
            last_hunt_latency_ms: enterprise_metrics.last_hunt_latency_ms,
            last_response_latency_ms: enterprise_metrics.last_response_latency_ms,
        },
        team_load,
        connector_impact,
        detection_review,
        value_brief,
        hot_agents,
        urgent_items,
        recommendations,
    }
}

pub(super) fn build_manager_overview(
    alert_queue: &AlertQueue,
    incident_store: &IncidentStore,
    response_orchestrator: &ResponseOrchestrator,
    _analytics: &EventAnalytics,
    agent_registry: &AgentRegistry,
    deployments: &HashMap<String, AgentDeployment>,
    published_releases: usize,
    report_store: &crate::report::ReportStore,
    siem_status: crate::siem::SiemStatus,
    tenant_count: usize,
    compliance_score: f64,
) -> ManagerOverview {
    let agents = agent_registry.list();
    let mut online = 0usize;
    let mut stale = 0usize;
    let mut offline = 0usize;
    for agent in agents.iter().copied() {
        match computed_agent_status(agent, agent_registry.heartbeat_interval())
            .0
            .as_str()
        {
            "online" => online += 1,
            "stale" => stale += 1,
            "offline" => offline += 1,
            _ => {}
        }
    }

    let queue_items = alert_queue.all();
    let queue_pending = queue_items.iter().filter(|item| !item.acknowledged).count();
    let queue_acknowledged = queue_items.iter().filter(|item| item.acknowledged).count();
    let queue_assigned = queue_items
        .iter()
        .filter(|item| item.assignee.is_some())
        .count();
    let queue_breached = queue_items
        .iter()
        .filter(|item| {
            !item.acknowledged
                && item
                    .sla_deadline
                    .as_deref()
                    .and_then(|deadline| chrono::DateTime::parse_from_rfc3339(deadline).ok())
                    .is_some_and(|deadline| {
                        chrono::Utc::now() > deadline.with_timezone(&chrono::Utc)
                    })
        })
        .count();
    let critical_pending = queue_items
        .iter()
        .filter(|item| !item.acknowledged && severity_rank(&item.level) >= 3)
        .count();

    let incidents = incident_store.list();
    let mut deployment_status_counts = HashMap::new();
    let mut deployment_ring_counts = HashMap::new();
    for deployment in deployments.values() {
        *deployment_status_counts
            .entry(deployment.status.clone())
            .or_insert(0) += 1;
        *deployment_ring_counts
            .entry(deployment.rollout_group.clone())
            .or_insert(0) += 1;
    }

    let report_summary = report_store.executive_summary(incident_store);
    let requests = response_orchestrator.all_requests();
    let ready_to_execute = requests
        .iter()
        .filter(|request| request.status == ApprovalStatus::Approved && !request.dry_run)
        .count();

    ManagerOverview {
        generated_at: chrono::Utc::now().to_rfc3339(),
        fleet: ManagerFleetOverview {
            total_agents: agents.len(),
            online,
            stale,
            offline,
            coverage_pct: if agents.is_empty() {
                0.0
            } else {
                (online as f32 / agents.len() as f32) * 100.0
            },
        },
        queue: ManagerQueueOverview {
            pending: queue_pending,
            acknowledged: queue_acknowledged,
            assigned: queue_assigned,
            sla_breached: queue_breached,
            critical_pending,
        },
        incidents: ManagerIncidentOverview {
            total: incidents.len(),
            open: incidents
                .iter()
                .filter(|incident| matches!(incident.status, crate::incident::IncidentStatus::Open))
                .count(),
            investigating: incidents
                .iter()
                .filter(|incident| {
                    matches!(
                        incident.status,
                        crate::incident::IncidentStatus::Investigating
                    )
                })
                .count(),
            contained: incidents
                .iter()
                .filter(|incident| {
                    matches!(incident.status, crate::incident::IncidentStatus::Contained)
                })
                .count(),
            resolved: incidents
                .iter()
                .filter(|incident| {
                    matches!(incident.status, crate::incident::IncidentStatus::Resolved)
                })
                .count(),
            false_positive: incidents
                .iter()
                .filter(|incident| {
                    matches!(
                        incident.status,
                        crate::incident::IncidentStatus::FalsePositive
                    )
                })
                .count(),
        },
        deployments: ManagerDeploymentOverview {
            published_releases,
            pending: deployments
                .values()
                .filter(|deployment| deployment_is_pending(deployment, agent_registry))
                .count(),
            by_status: deployment_status_counts,
            by_ring: deployment_ring_counts,
        },
        reports: ManagerReportOverview {
            total_reports: report_summary["total_reports"].as_u64().unwrap_or(0) as usize,
            total_alerts: report_summary["total_alerts"].as_u64().unwrap_or(0) as usize,
            critical_alerts: report_summary["critical_alerts"].as_u64().unwrap_or(0) as usize,
            avg_score: report_summary["avg_score"]
                .as_f64()
                .map(|value| value as f32),
            max_score: report_summary["max_score"].as_f64().unwrap_or(0.0) as f32,
            open_incidents: report_summary["incidents_open"].as_u64().unwrap_or(0) as usize,
        },
        siem: siem_status,
        compliance: ManagerComplianceOverview {
            score: compliance_score,
        },
        tenants: tenant_count,
        operations: ManagerOperationsOverview {
            pending_approvals: response_orchestrator.pending_requests().len(),
            ready_to_execute,
            protected_assets: response_orchestrator.protected_asset_count(),
        },
    }
}

fn onboarding_check(
    key: &str,
    label: &str,
    ready: bool,
    ready_detail: impl Into<String>,
    pending_detail: impl Into<String>,
) -> OnboardingReadinessCheck {
    OnboardingReadinessCheck {
        key: key.to_string(),
        label: label.to_string(),
        ready,
        status: if ready { "ready" } else { "pending" }.to_string(),
        detail: if ready {
            ready_detail.into()
        } else {
            pending_detail.into()
        },
    }
}

pub(super) fn build_onboarding_readiness(state: &mut AppState) -> OnboardingReadiness {
    state.agent_registry.refresh_staleness();
    let agents = state.agent_registry.list();
    let online_agents = agents
        .iter()
        .filter(|agent| {
            let (status, _) =
                computed_agent_status(agent, state.agent_registry.heartbeat_interval());
            status == "online"
        })
        .count();
    let telemetry_events = state.event_store.analytics().total_events;
    let local_samples = state.local_telemetry.len();
    let visible_alerts = state.event_store.all_events().len().max(state.alerts.len());
    let feed_count = state
        .threat_intel
        .feeds()
        .iter()
        .filter(|feed| feed.active)
        .count();
    let scan_stats = state.malware_scanner.stats();
    let response_requests = state.response_orchestrator.all_requests();
    let dry_run_completed = response_requests.iter().any(|request| request.dry_run);

    let checks = vec![
        onboarding_check(
            "token_valid",
            "Token valid",
            true,
            "Authenticated admin session is active.",
            "Authenticate with a valid admin token.",
        ),
        onboarding_check(
            "first_agent_online",
            "First agent online",
            online_agents > 0,
            format!("{online_agents} agent(s) are currently online."),
            "Enroll an agent and wait for the first healthy heartbeat.",
        ),
        onboarding_check(
            "telemetry_flowing",
            "Telemetry flowing",
            telemetry_events > 0 || local_samples > 0,
            format!(
                "Telemetry is flowing ({telemetry_events} stored event(s), {local_samples} local sample(s))."
            ),
            "No events have been observed yet. Confirm collection is enabled on at least one endpoint.",
        ),
        onboarding_check(
            "first_alert_visible",
            "First alert visible",
            visible_alerts > 0,
            format!("{visible_alerts} alert(s) are already visible in the console."),
            "Trigger or ingest one alert so the queue and workbench can be validated.",
        ),
        onboarding_check(
            "intel_source_healthy",
            "Intel source healthy",
            feed_count > 0 || state.threat_intel.ioc_count() > 0,
            format!(
                "{feed_count} active feed(s), {} IoC(s) loaded.",
                state.threat_intel.ioc_count()
            ),
            "Configure at least one feed or import IoCs before analyst workflows depend on enrichment.",
        ),
        onboarding_check(
            "malware_scan_run",
            "Malware scan run",
            scan_stats.total_scans > 0,
            format!(
                "{} malware scan(s) completed with {} suspicious or malicious result(s).",
                scan_stats.total_scans,
                scan_stats.malicious_count + scan_stats.suspicious_count
            ),
            "Run one scan so the malware workflow and provenance data can be verified.",
        ),
        onboarding_check(
            "response_approval_dry_run_completed",
            "Response approval dry-run completed",
            dry_run_completed,
            format!(
                "{} response request(s) recorded, including a dry-run approval path.",
                response_requests.len()
            ),
            "Submit one dry-run response request to validate approval and rollback readiness.",
        ),
    ];
    let completed = checks.iter().filter(|check| check.ready).count();

    OnboardingReadiness {
        generated_at: chrono::Utc::now().to_rfc3339(),
        ready: completed == checks.len(),
        completed,
        total: checks.len(),
        estimated_minutes: 15,
        checks,
    }
}
