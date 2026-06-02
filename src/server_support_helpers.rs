//! Support, persistence, fleet-install, and monitoring helper payloads.

use super::*;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub(crate) struct CollectorCheckpoint {
    pub(crate) last_success_at: Option<String>,
    pub(crate) last_error_at: Option<String>,
    pub(crate) error_category: Option<String>,
    pub(crate) events_ingested: u64,
    pub(crate) lag_seconds: Option<u64>,
    pub(crate) queue_depth: u64,
    pub(crate) checkpoint_id: Option<String>,
    pub(crate) retry_count: u32,
    pub(crate) backoff_seconds: u64,
}

pub(crate) fn load_stored_json<T>(storage: &SharedStorage, key: &str) -> T
where
    T: DeserializeOwned + Default,
{
    storage
        .with(|store| Ok(store.get_config(key)))
        .ok()
        .flatten()
        .and_then(|raw| serde_json::from_str::<T>(&raw).ok())
        .unwrap_or_default()
}

pub(crate) fn save_stored_json<T>(
    storage: &SharedStorage,
    key: &str,
    value: &T,
) -> Result<(), String>
where
    T: serde::Serialize,
{
    let raw = serde_json::to_string(value).map_err(|e| format!("serialization error: {e}"))?;
    storage
        .with(|store| {
            store.set_config(key, &raw)?;
            Ok(())
        })
        .map_err(|e| e.safe_message().to_string())
}

pub(crate) fn persist_failed_auth_tracker_snapshot(storage: &SharedStorage) {
    let snapshot = crate::server_auth::failed_auth_snapshot();
    let _ = save_stored_json(storage, FAILED_AUTH_TRACKER_STORAGE_KEY, &snapshot);
}

pub(crate) fn persist_failed_auth_tracker_snapshot_from_state(state: &Arc<Mutex<AppState>>) {
    let storage = {
        let s = crate::state_lock::tracked_lock(state, "server/failed_auth_storage_handle");
        s.storage.clone()
    };
    persist_failed_auth_tracker_snapshot(&storage);
}

pub(crate) const FLEET_REMOTE_INSTALLS_KEY: &str = "fleet_remote_installs";
const MAX_FLEET_REMOTE_INSTALLS: usize = 100;

pub(crate) fn load_fleet_remote_installs(storage: &SharedStorage) -> Vec<RemoteInstallRecord> {
    load_stored_json(storage, FLEET_REMOTE_INSTALLS_KEY)
}

pub(crate) fn append_fleet_remote_install(
    storage: &SharedStorage,
    record: RemoteInstallRecord,
) -> Result<(), String> {
    let mut installs = load_fleet_remote_installs(storage);
    installs.insert(0, record);
    installs.truncate(MAX_FLEET_REMOTE_INSTALLS);
    save_stored_json(storage, FLEET_REMOTE_INSTALLS_KEY, &installs)
}

fn normalized_remote_install_platform(value: &str) -> &'static str {
    let value = value.trim().to_ascii_lowercase();
    if value.contains("darwin") || value.contains("mac") {
        "macos"
    } else if value.contains("win") {
        "windows"
    } else {
        "linux"
    }
}

fn mark_remote_install_first_heartbeat(
    installs: &mut [RemoteInstallRecord],
    agent_id: &str,
    hostname: &str,
    platform: &str,
    heartbeat_at: &str,
) -> Option<RemoteInstallRecord> {
    let normalized_platform = normalized_remote_install_platform(platform);
    let attempt = installs.iter_mut().find(|attempt| {
        attempt.status == "awaiting_heartbeat"
            && host_matches_local(&attempt.hostname, hostname)
            && normalized_remote_install_platform(&attempt.platform) == normalized_platform
    })?;

    attempt.status = "heartbeat_received".to_string();
    if attempt.agent_id.is_none() {
        attempt.agent_id = Some(agent_id.to_string());
    }
    if attempt.first_heartbeat_at.is_none() {
        attempt.first_heartbeat_at = Some(heartbeat_at.to_string());
    }
    Some(attempt.clone())
}

pub(crate) fn reconcile_fleet_remote_install_heartbeat(
    storage: &SharedStorage,
    agent_id: &str,
    hostname: &str,
    platform: &str,
    heartbeat_at: &str,
) -> Result<Option<RemoteInstallRecord>, String> {
    let mut installs = load_fleet_remote_installs(storage);
    let matched = mark_remote_install_first_heartbeat(
        &mut installs,
        agent_id,
        hostname,
        platform,
        heartbeat_at,
    );
    if matched.is_some() {
        save_stored_json(storage, FLEET_REMOTE_INSTALLS_KEY, &installs)?;
    }
    Ok(matched)
}

fn increment_stage_count(counts: &mut BTreeMap<String, usize>, stage: &str) {
    *counts.entry(stage.to_string()).or_insert(0) += 1;
}

pub(crate) fn summarize_deployment_campaign(state: &AppState) -> serde_json::Value {
    let heartbeat_interval = state.agent_registry.heartbeat_interval();
    let policy_version = state.policy_store.current_version();
    let agents = state.agent_registry.list();
    let installs = load_fleet_remote_installs(&state.storage);

    let mut current_stage_counts = BTreeMap::new();
    let mut milestone_counts = BTreeMap::new();
    for stage in DEPLOYMENT_CAMPAIGN_STAGES {
        current_stage_counts.insert(stage.to_string(), 0usize);
        milestone_counts.insert(stage.to_string(), 0usize);
    }
    let mut remediation = Vec::new();

    for agent in &agents {
        let deployment = state.remote_deployments.get(&agent.id);
        let (computed_status, age_secs) = computed_agent_status(agent, heartbeat_interval);
        let (campaign_state, campaign_progress) = deployment_campaign_progress(
            &computed_status,
            age_secs,
            heartbeat_interval,
            deployment,
            policy_version,
        );
        increment_stage_count(&mut current_stage_counts, &campaign_state);
        for stage in DEPLOYMENT_CAMPAIGN_STAGES {
            if campaign_progress
                .get(stage)
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
            {
                increment_stage_count(&mut milestone_counts, stage);
            }
        }
    }

    for attempt in installs.iter().filter(|attempt| {
        attempt
            .agent_id
            .as_ref()
            .and_then(|agent_id| state.agent_registry.get(agent_id))
            .is_none()
    }) {
        let normalized = attempt.status.trim().to_ascii_lowercase();
        let stage = if normalized == "failed" {
            "failed"
        } else if normalized == "heartbeat_received" {
            "enrolled"
        } else if normalized == "awaiting_heartbeat" {
            "installed"
        } else if normalized == "pending" {
            "sent"
        } else {
            "prepared"
        };
        increment_stage_count(&mut current_stage_counts, stage);
        increment_stage_count(&mut milestone_counts, "prepared");
        if stage != "prepared" {
            increment_stage_count(&mut milestone_counts, "sent");
        }
        if stage == "installed" || stage == "enrolled" || stage == "failed" {
            increment_stage_count(&mut milestone_counts, "installed");
        }
        if stage == "enrolled" || stage == "failed" {
            increment_stage_count(&mut milestone_counts, "enrolled");
        }
        if stage == "failed" {
            increment_stage_count(&mut milestone_counts, "failed");
        }
        if stage == "failed" {
            remediation.push(serde_json::json!({
                "kind": "remote_install",
                "transport": attempt.transport,
                "hostname": attempt.hostname,
                "status": attempt.status,
                "recommended_action": if attempt.transport == "winrm" {
                    "Validate WinRM reachability, credentials, and TLS policy; then retry with a fresh one-use enrollment token."
                } else {
                    "Validate SSH connectivity, privileges, and host key acceptance; then retry with a fresh one-use enrollment token."
                },
                "error": attempt.error,
                "started_at": attempt.started_at,
                "completed_at": attempt.completed_at,
            }));
        }
    }

    for deployment in state
        .remote_deployments
        .values()
        .filter(|deployment| deployment_failed_status(&deployment.status))
    {
        remediation.push(serde_json::json!({
            "kind": "deployment",
            "agent_id": deployment.agent_id,
            "hostname": state
                .agent_registry
                .get(&deployment.agent_id)
                .map(|agent| agent.hostname.clone()),
            "status": deployment.status,
            "target_version": deployment.version,
            "rollout_group": deployment.rollout_group,
            "recommended_action": "Review deployment status reason, confirm endpoint heartbeat, and retry assignment only after host health checks pass.",
            "status_reason": deployment.status_reason,
            "assigned_at": deployment.assigned_at,
            "completed_at": deployment.completed_at,
        }));
    }

    let failed = current_stage_counts
        .get("failed")
        .copied()
        .unwrap_or_default();
    let telemetry_verified = current_stage_counts
        .get("telemetry_verified")
        .copied()
        .unwrap_or_default();
    let enrolled = agents.len();
    let status = if failed > 0 {
        "failed"
    } else if enrolled > 0 && telemetry_verified == enrolled {
        "healthy"
    } else if enrolled == 0 {
        "prepared"
    } else {
        "in_progress"
    };

    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "status": status,
        "stages": DEPLOYMENT_CAMPAIGN_STAGES,
        "current_stage_counts": current_stage_counts,
        "milestone_counts": milestone_counts,
        "enrolled_agents": enrolled,
        "remote_install_attempts": installs.len(),
        "failed_items": failed,
        "remediation": remediation.into_iter().take(25).collect::<Vec<_>>(),
    })
}

pub(crate) fn load_secrets_manager_setup(storage: &SharedStorage) -> SecretsManagerSetup {
    load_stored_json(storage, SECRETS_MANAGER_SETUP_KEY)
}

pub(crate) fn command_summary_payload(state: &mut AppState) -> serde_json::Value {
    state.agent_registry.refresh_staleness();
    let open_incidents = state
        .incident_store
        .list()
        .iter()
        .filter(|incident| {
            matches!(
                incident.status,
                crate::incident::IncidentStatus::Open
                    | crate::incident::IncidentStatus::Investigating
            )
        })
        .count();
    let active_cases = state
        .case_store
        .list()
        .iter()
        .filter(|case| {
            !matches!(
                case.status,
                crate::analyst::CaseStatus::Resolved | crate::analyst::CaseStatus::Closed
            )
        })
        .count();
    let remediation_lane = crate::remediation::remediation_lane_summary(&state.storage);
    let rule_metadata = state
        .enterprise
        .builtin_rules()
        .iter()
        .cloned()
        .chain(
            state
                .enterprise
                .native_rules()
                .iter()
                .map(|rule| rule.metadata.clone()),
        )
        .collect::<Vec<_>>();
    let noisy_rules = rule_metadata
        .iter()
        .filter(|rule| rule.enabled && rule.last_test_match_count >= 5)
        .count()
        .max(state.enterprise.active_suppression_count());
    let stale_rules = rule_metadata
        .iter()
        .filter(|rule| {
            rule.enabled
                && rule.last_test_at.is_none()
                && rule.last_promotion_at.is_none()
                && rule.lifecycle != ContentLifecycle::Active
        })
        .count();
    let connectors = crate::server_collectors::collector_readiness_summary(state);
    let connector_issues = connectors
        .get("collectors")
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter(|item| {
                    item.get("enabled").and_then(serde_json::Value::as_bool) != Some(true)
                        || item
                            .get("last_error_at")
                            .is_some_and(|value| !value.is_null())
                        || item
                            .get("error_category")
                            .is_some_and(|value| !value.is_null())
                })
                .count()
        })
        .unwrap_or_default();
    let release_candidates = state.update_manager.list_releases().len();
    let report_templates = state
        .support_store
        .report_templates_filtered(&crate::support::ReportExecutionContextFilter::default());
    let compliance_report = state
        .compliance
        .report(&crate::compliance::Framework::Iec62443);
    let offline_agents = state
        .agent_registry
        .list()
        .iter()
        .filter(|agent| {
            matches!(
                agent.status,
                crate::enrollment::AgentStatus::Offline | crate::enrollment::AgentStatus::Stale
            )
        })
        .count();
    let shift_board = command_shift_board_payload(
        state,
        open_incidents,
        active_cases,
        remediation_lane.pending_reviews,
        connector_issues,
        noisy_rules,
        stale_rules,
    );

    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "shift_board": shift_board,
        "metrics": {
            "open_incidents": open_incidents,
            "active_cases": active_cases,
            "pending_remediation_reviews": remediation_lane.pending_reviews,
            "rollback_ready_reviews": remediation_lane.rollback_ready,
            "connector_issues": connector_issues,
            "noisy_rules": noisy_rules,
            "stale_rules": stale_rules,
            "release_candidates": release_candidates,
            "compliance_packs": report_templates.len(),
            "offline_agents": offline_agents,
        },
        "lanes": {
            "incidents": {
                "status": if open_incidents > 0 { "attention" } else { "ready" },
                "count": open_incidents,
                "annotation": if open_incidents > 0 {
                    "Active incidents need operator attention before additional pivots or rollout work."
                } else {
                    "Incident backlog is clear enough for proactive hunts and change review."
                },
                "next_step": if open_incidents > 0 {
                    "Use the SOC workspace to confirm ownership, response pressure, and evidence export state."
                } else {
                    "Keep the incident lane warm with attack-story pivots and case follow-ups."
                },
                "href": "/soc",
            },
            "remediation": {
                "status": remediation_lane.status,
                "pending": remediation_lane.pending_reviews,
                "rollback_ready": remediation_lane.rollback_ready,
                "annotation": if remediation_lane.pending_reviews > 0 {
                    "Pending approvals and rollback proofs are waiting for signed operator review."
                } else {
                    "Remediation approvals are current; keep typed-host safeguards in place for live execution."
                },
                "next_step": if remediation_lane.pending_reviews > 0 {
                    "Review blast radius, approval quorum, and rollback proof before any live rollback request."
                } else {
                    "Exercise the rollback path only after confirm_hostname and execution-policy checks are verified."
                },
                "href": "/infrastructure?tab=remediation",
            },
            "connectors": {
                "status": if connector_issues > 0 { "setup_required" } else { "ready" },
                "issues": connector_issues,
                "annotation": if connector_issues > 0 {
                    "One or more collector lanes still need credentials, validation, or fresh ingestion proof."
                } else {
                    "Collector onboarding proof is current across the shipped cloud, identity, SaaS, EDR, and syslog lanes."
                },
                "next_step": if connector_issues > 0 {
                    "Validate connector credentials and recent evidence before operators depend on the lane."
                } else {
                    "Keep summary-driven lane status aligned as new collector workflows are added."
                },
                "readiness": connectors,
                "planned": ["github_audit", "crowdstrike_falcon", "generic_syslog"],
            },
            "rule_tuning": {
                "status": if noisy_rules > 0 || stale_rules > 0 { "review_required" } else { "ready" },
                "noisy": noisy_rules,
                "stale": stale_rules,
                "active_suppressions": state.enterprise.active_suppression_count(),
                "review_calendar": command_rule_review_calendar(
                    &rule_metadata,
                    state.enterprise.active_suppression_count(),
                ),
                "annotation": if noisy_rules > 0 || stale_rules > 0 {
                    "Detection lanes have replay or suppression debt that should be resolved before promotion."
                } else {
                    "Rule replay, suppression, and promotion queues are ready for the next release candidate."
                },
                "next_step": if noisy_rules > 0 || stale_rules > 0 {
                    "Run replay, review suppressions, and update lifecycle evidence before enabling broader rollout."
                } else {
                    "Keep ATT&CK coverage and false-positive debt visible as rules evolve."
                },
                "href": "/detection",
            },
            "release": {
                "status": if release_candidates > 0 { "ready" } else { "missing_catalog" },
                "candidates": release_candidates,
                "current_version": env!("CARGO_PKG_VERSION"),
                "annotation": if release_candidates > 0 {
                    "Candidate metadata is available for rollout review, SBOM checks, and rollback planning."
                } else {
                    "Release metadata is missing, so rollout review and evidence export are blocked."
                },
                "next_step": if release_candidates > 0 {
                    "Review candidate notes, SBOM context, and rollout readiness before promotion."
                } else {
                    "Publish release metadata so the command lane can verify rollout readiness in the acceptance gate."
                },
                "href": "/infrastructure?tab=rollouts",
            },
            "evidence": {
                "status": if compliance_report.score >= 80.0 { "ready" } else { "attention" },
                "score": compliance_report.score,
                "templates": report_templates.len(),
                "annotation": if compliance_report.score >= 80.0 {
                    "Compliance evidence is strong enough to package alongside operational proof and release context."
                } else {
                    "Evidence packs still need stronger compliance posture before audit export."
                },
                "next_step": if compliance_report.score >= 80.0 {
                    "Generate packs from live incidents, release metadata, and report templates when auditors ask."
                } else {
                    "Close posture gaps before promoting the next pack as auditor-ready evidence."
                },
                "href": "/reports",
            }
        }
    })
}

/// Background loop that fetches and ingests threat feeds that are due for
/// polling. Network requests are made without holding the state lock.
pub(crate) fn spawn_feed_ingestion_loop(state: &Arc<Mutex<AppState>>) {
    let state = Arc::clone(state);
    std::thread::spawn(move || {
        loop {
            let shutdown = {
                let s = crate::state_lock::tracked_lock(&state, "server/feed_ingestion_shutdown");
                s.shutdown.load(Ordering::Relaxed)
            };
            if shutdown {
                break;
            }

            let due: Vec<crate::feed_ingestion::FeedSource> = {
                let s =
                    crate::state_lock::tracked_lock(&state, "server/feed_ingestion_due_sources");
                s.feed_engine
                    .sources_due_for_poll()
                    .into_iter()
                    .cloned()
                    .collect()
            };

            for source in due {
                let fetched = crate::feed_ingestion::fetch_feed_data(&source);
                let mut s =
                    crate::state_lock::tracked_lock(&state, "server/feed_ingestion_poll_result");
                match fetched {
                    Ok(data) => {
                        let AppState {
                            ref mut feed_engine,
                            ref mut threat_intel,
                            ref mut malware_hash_db,
                            ref mut yara_engine,
                            ..
                        } = *s;
                        let _ = feed_engine.poll_feed(
                            &source.id,
                            &data,
                            threat_intel,
                            malware_hash_db,
                            yara_engine,
                        );
                    }
                    Err(e) => {
                        s.feed_engine.record_feed_failure(&source.id, &e);
                    }
                }
            }

            std::thread::sleep(std::time::Duration::from_secs(30));
        }
    });
}

pub(crate) fn first_run_operator_proof(
    state: &Arc<Mutex<AppState>>,
    auth: &AuthIdentity,
) -> Response<Body> {
    let demo = runtime::demo_samples();
    let result = runtime::execute(&demo);
    let report = JsonReport::from_run_result(&result);
    let report_size_bytes = serde_json::to_vec(&report)
        .map(|bytes| bytes.len() as u64)
        .unwrap_or(0);
    let requested_by = response_requested_by(auth);
    let now = chrono::Utc::now().to_rfc3339();

    let mut s = crate::state_lock::tracked_lock(state, "server/first_run_operator_proof");
    for (sample, sample_report) in demo.iter().zip(result.reports.iter()) {
        let pre = s
            .detector
            .snapshot()
            .map(|snap| serde_json::to_vec(&snap).unwrap_or_default())
            .unwrap_or_default();
        s.detector.evaluate(sample);
        let post = s
            .detector
            .snapshot()
            .map(|snap| serde_json::to_vec(&snap).unwrap_or_default())
            .unwrap_or_default();
        s.proofs
            .record("first_run_proof_baseline_update", &pre, &post);
        s.device.apply_decision(&sample_report.decision);
        s.replay.push(*sample);
    }

    let case_id = s
        .case_store
        .create(
            "First-run proof investigation".to_string(),
            "Guided demo scenario proving ingest, triage, investigation, response approval, reporting, and evidence packaging end to end.".to_string(),
            CasePriority::High,
            Vec::new(),
            Vec::new(),
            vec!["first-run-proof".to_string(), "demo".to_string()],
        )
        .id;
    let _ = s.case_store.add_comment(
        case_id,
        requested_by.clone(),
        format!(
            "First-run proof ingested {} demo samples and generated {} alert(s).",
            result.summary.total_samples, result.summary.alert_count
        ),
    );

    let execution_context = ReportExecutionContext {
        case_id: Some(case_id.to_string()),
        incident_id: None,
        investigation_id: Some(format!("first-run-proof-{case_id}")),
        source: Some("first_run_proof".to_string()),
    };
    let report_id = s.report_store.store_with_context(
        report.clone(),
        "first_run_proof",
        Some(execution_context.clone()),
    );

    let response_request_id = next_response_request_id();
    let response_request = ResponseRequest {
        id: response_request_id.clone(),
        action: ResponseAction::Isolate,
        target: ResponseTarget {
            hostname: "first-run-demo-host".to_string(),
            agent_uid: None,
            asset_tags: vec!["demo".to_string(), "first-run-proof".to_string()],
        },
        reason: "First-run operator proof dry-run containment".to_string(),
        severity: "high".to_string(),
        tier: ActionTier::Auto,
        status: ApprovalStatus::Pending,
        requested_at: now,
        requested_by: requested_by.clone(),
        approvals: Vec::new(),
        dry_run: true,
        blast_radius: None,
        is_protected_asset: false,
    };
    let stored_response_id = match s.response_orchestrator.submit(response_request) {
        Ok(id) => id,
        Err(e) => return error_json(&format!("first-run response setup failed: {e}"), 500),
    };
    let approver = if requested_by == "first-run-proof-approver" {
        "first-run-proof-reviewer"
    } else {
        "first-run-proof-approver"
    };
    let response_status = s
        .response_orchestrator
        .approve(
            &stored_response_id,
            ResponseApprovalRecord {
                approver: approver.to_string(),
                decision: ResponseApprovalDecision::Approve,
                timestamp: chrono::Utc::now().to_rfc3339(),
                comment: Some(
                    "Approved demo dry-run response for first-run operator proof.".to_string(),
                ),
            },
        )
        .unwrap_or_else(|_| {
            s.response_orchestrator
                .get_request(&stored_response_id)
                .map(|request| request.status)
                .unwrap_or(ApprovalStatus::Pending)
        });
    let response_record = s.response_orchestrator.get_request(&stored_response_id);
    let demo_collectors = [
        ("aws_cloudtrail", 18_u64, None),
        ("okta_identity", 11_u64, None),
        ("m365_saas", 7_u64, None),
        ("workspace_saas", 5_u64, None),
    ];
    for (provider, event_count, error) in demo_collectors {
        let _ = crate::server_collectors::record_collector_checkpoint(
            &s.storage,
            provider,
            true,
            event_count,
            error,
        );
    }
    let demo_surface_evidence = serde_json::json!({
        "cloud": {"provider": "aws_cloudtrail", "events": 18, "pivot": "/settings?tab=integrations"},
        "identity": {"provider": "okta_identity", "events": 11, "pivot": "/soc?collector=okta_identity"},
        "saas": {"provider": "m365_saas", "events": 7, "pivot": "/settings?tab=integrations"},
        "ueba": {"entity": "demo-user@example.com", "risk": "elevated", "pivot": "/ueba?entity=demo-user@example.com"},
        "ndr": {"flow": "10.10.4.22 -> 198.51.100.44", "risk": "c2-beacon", "pivot": "/ndr?host=first-run-demo-host"},
        "attack_graph": {"campaign": "first-run-proof-lateral-path", "nodes": 4, "pivot": "/attack-graph?campaign=first-run-proof"}
    });

    let preview = serde_json::json!({
        "summary": report.summary.clone(),
        "case_id": case_id,
        "report_id": report_id,
        "response_request_id": stored_response_id,
        "response_status": format!("{:?}", response_status),
        "demo_surfaces": demo_surface_evidence,
        "steps": [
            "ingest_sample",
            "seed_cloud_identity_saas_collectors",
            "seed_ueba_ndr_attack_graph_context",
            "triage_alert",
            "open_case",
            "approve_response_dry_run",
            "generate_report",
            "package_evidence"
        ],
    });
    let report_run = s.support_store.add_report_run(
        "First-run Operator Proof".to_string(),
        "first_run_proof".to_string(),
        "case".to_string(),
        "json".to_string(),
        "operator".to_string(),
        "completed".to_string(),
        "Created telemetry, case, response dry-run approval, report, and evidence metadata."
            .to_string(),
        report_size_bytes,
        preview,
        Some(execution_context),
    );

    let evidence_refs = [
        ("telemetry_demo", "runtime::demo_samples".to_string()),
        ("report", report_id.to_string()),
        ("report_run", report_run.id.clone()),
        ("response_request", stored_response_id.clone()),
        (
            "cloud_identity_saas_collectors",
            "aws_cloudtrail,okta_identity,m365_saas,workspace_saas".to_string(),
        ),
        (
            "ueba_ndr_attack_graph_context",
            "demo-user@example.com,first-run-proof-lateral-path".to_string(),
        ),
    ];
    for (kind, reference_id) in evidence_refs {
        let _ = s.case_store.add_evidence(
            case_id,
            kind.to_string(),
            reference_id,
            "First-run proof evidence artifact".to_string(),
        );
    }

    s.last_report = Some(report.clone());
    let report_artifact_metadata = s
        .report_store
        .get(report_id)
        .and_then(|stored| stored.artifact_metadata.clone());
    let proof = serde_json::json!({
        "status": "completed",
        "estimated_minutes": 10,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "actor": requested_by,
        "case_id": case_id,
        "report_id": report_id,
        "report_run_id": report_run.id,
        "response_request_id": stored_response_id,
        "response_status": format!("{:?}", response_status),
        "telemetry": {
            "samples": result.summary.total_samples,
            "alerts": result.summary.alert_count,
            "critical": result.summary.critical_count,
        },
        "artifact_metadata": {
            "report": report_artifact_metadata,
            "support_run": report_run.artifact_metadata,
        },
        "demo_surfaces": demo_surface_evidence,
        "response_history": response_record.as_ref().map(response_request_json),
        "steps": [
            {"name": "ingest_sample", "status": "completed"},
            {"name": "seed_cloud_identity_saas_collectors", "status": "completed"},
            {"name": "seed_ueba_ndr_attack_graph_context", "status": "completed"},
            {"name": "triage_alert", "status": "completed"},
            {"name": "open_case", "status": "completed"},
            {"name": "approve_response_dry_run", "status": "completed"},
            {"name": "generate_report", "status": "completed"},
            {"name": "package_evidence", "status": "completed"}
        ],
    });
    let digest = crate::audit::sha256_hex(proof.to_string().as_bytes());
    json_response(
        &serde_json::json!({
            "proof": proof,
            "digest": digest,
        })
        .to_string(),
        200,
    )
}

pub(crate) fn secret_reference_kind(reference: &str) -> &'static str {
    let trimmed = reference.trim();
    if trimmed.starts_with("${") && trimmed.ends_with('}') {
        "env"
    } else if trimmed.starts_with("file://") {
        "file"
    } else if trimmed.starts_with("vault://") {
        "vault"
    } else {
        "literal"
    }
}

pub(crate) fn masked_secret_preview(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.is_empty() {
        return "".to_string();
    }
    if chars.len() <= 4 {
        return "*".repeat(chars.len());
    }
    let prefix: String = chars.iter().take(2).collect();
    let suffix: String = chars.iter().skip(chars.len() - 2).collect();
    format!("{prefix}…{suffix}")
}

pub(crate) fn parse_query_datetime(
    value: Option<&String>,
    field: &str,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, String> {
    let Some(raw) = value
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };

    chrono::DateTime::parse_from_rfc3339(raw)
        .map(|value| Some(value.with_timezone(&chrono::Utc)))
        .or_else(|_| {
            chrono::NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M")
                .map(|value| Some(value.and_utc()))
        })
        .or_else(|_| {
            chrono::NaiveDate::parse_from_str(raw, "%Y-%m-%d").map(|value| {
                Some(
                    value
                        .and_hms_opt(0, 0, 0)
                        .unwrap_or_else(|| {
                            chrono::NaiveDateTime::new(value, chrono::NaiveTime::MIN)
                        })
                        .and_utc(),
                )
            })
        })
        .map_err(|_| format!("invalid {field} timestamp"))
}

pub(crate) fn incident_related_events(
    incident: &crate::incident::Incident,
    events: &[crate::event_forward::StoredEvent],
) -> Vec<crate::event_forward::StoredEvent> {
    events
        .iter()
        .filter(|event| incident.event_ids.contains(&event.id))
        .cloned()
        .collect()
}

fn monitoring_option(
    id: &str,
    label: &str,
    description: &str,
    selected: bool,
    supported: bool,
    recommended: bool,
    mode: &str,
    reason: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "label": label,
        "description": description,
        "selected": selected,
        "supported": supported,
        "recommended": recommended,
        "mode": mode,
        "reason": reason,
    })
}

fn monitoring_guidance(platform: HostPlatform) -> Vec<&'static str> {
    match platform {
        HostPlatform::Linux => vec![
            "Linux hosts benefit most from auth-failure monitoring and systemd-unit persistence checks because both map directly to common intrusion paths.",
            "Battery coverage depends on power-supply telemetry such as BAT0; server-class systems often report no battery data.",
        ],
        HostPlatform::MacOS => vec![
            "macOS hosts should prioritize LaunchAgents and LaunchDaemons because they are common persistence locations for userland malware.",
            "Thermal telemetry is limited on macOS in the current pure-Rust collector path, so CPU and process signals remain the stronger indicators.",
        ],
        HostPlatform::Windows | HostPlatform::WindowsServer => vec![
            "Windows hosts should prioritize Security-log failures and scheduled-task persistence because both are frequently abused during compromise and re-entry.",
            "Battery and thermal coverage depends on WMI support and may be absent on desktop or virtualized systems.",
        ],
        HostPlatform::Unknown => vec![
            "This host platform could not be classified cleanly, so Wardex recommends sticking to portable telemetry and file-integrity checks.",
            "Platform-specific persistence checks remain unavailable until the runtime can map standard service locations for this OS.",
        ],
    }
}

pub(crate) fn monitoring_options_payload(host: &HostInfo, config: &Config) -> serde_json::Value {
    let platform_key = host_platform_key(host.platform);
    let caps = PlatformCapabilities::detect_current();
    let scope = &config.monitor.scope;
    let persistence_paths = crate::collector::persistence_watch_paths(host.platform, scope);

    let core = vec![
        monitoring_option(
            "cpu_load",
            "CPU load",
            "Monitors sustained or sudden CPU pressure to catch miners, brute-force spikes, and runaway workloads.",
            scope.cpu_load,
            true,
            true,
            "always_on",
            Some("Core telemetry is always collected in the current release."),
        ),
        monitoring_option(
            "memory_pressure",
            "Memory pressure",
            "Tracks RAM consumption trends to surface exhaustion, injection, and staging behavior.",
            scope.memory_pressure,
            true,
            true,
            "always_on",
            Some("Core telemetry is always collected in the current release."),
        ),
        monitoring_option(
            "network_activity",
            "Network activity",
            "Flags bursts or sustained traffic shifts associated with exfiltration, C2, or floods.",
            scope.network_activity,
            true,
            true,
            "always_on",
            Some("Core telemetry is always collected in the current release."),
        ),
        monitoring_option(
            "disk_pressure",
            "Disk pressure",
            "Watches disk utilization changes that can indicate ransomware, log stuffing, or resource starvation.",
            scope.disk_pressure,
            true,
            true,
            "always_on",
            Some("Core telemetry is always collected in the current release."),
        ),
        monitoring_option(
            "process_activity",
            "Process activity",
            "Uses process-count anomalies to highlight fork storms, lateral tooling, and persistence bursts.",
            scope.process_activity,
            true,
            true,
            "always_on",
            Some("Core telemetry is always collected in the current release."),
        ),
    ];

    let security = vec![
        monitoring_option(
            "auth_events",
            "Authentication events",
            "Tracks failed-logon spikes to detect brute-force and credential-stuffing behavior.",
            scope.auth_events,
            true,
            true,
            "configurable",
            Some(
                "Disable only if the host cannot expose auth logs or Security-event access is intentionally restricted.",
            ),
        ),
        monitoring_option(
            "file_integrity",
            "File integrity",
            "Hashes configured paths and alerts on unexpected changes. This is the scope item that directly changes collector behavior now.",
            scope.file_integrity,
            true,
            true,
            "configurable",
            None,
        ),
        monitoring_option(
            "service_persistence",
            "Service persistence",
            "Covers startup services and persistence footholds using OS-specific baseline paths.",
            scope.service_persistence,
            platform_key != "unknown",
            true,
            "configurable",
            Some(if platform_key == "unknown" {
                "Runtime could not determine standard persistence locations for this host."
            } else {
                "Enable this together with the host-specific source below. In the admin console, selecting a host-specific source automatically enables service persistence."
            }),
        ),
    ];

    let host_specific = vec![
        monitoring_option(
            "thermal_state",
            "Thermal state",
            "Adds device-heat context to CPU and workload anomalies.",
            scope.thermal_state,
            true,
            platform_key != "unknown",
            "always_on",
            Some("Collected as part of the current host telemetry pipeline."),
        ),
        monitoring_option(
            "battery_state",
            "Battery state",
            "Useful on mobile or battery-backed devices where power drain can be part of the attack path.",
            scope.battery_state,
            true,
            matches!(
                host.platform,
                HostPlatform::MacOS | HostPlatform::Windows | HostPlatform::WindowsServer
            ),
            "always_on",
            Some("Collected when the host exposes battery data."),
        ),
        monitoring_option(
            "launch_agents",
            "Launch agents",
            "macOS persistence points such as LaunchAgents and LaunchDaemons.",
            scope.launch_agents,
            platform_key == "macos",
            platform_key == "macos",
            "configurable",
            Some(if platform_key == "macos" {
                "Recommended on macOS because LaunchAgents and LaunchDaemons are baselined directly when service persistence is enabled."
            } else {
                "macOS-specific monitoring point."
            }),
        ),
        monitoring_option(
            "systemd_units",
            "systemd units",
            "Linux startup services and unit-file persistence.",
            scope.systemd_units,
            platform_key == "linux",
            platform_key == "linux",
            "configurable",
            Some(if platform_key == "linux" {
                "Recommended on Linux because systemd unit paths are baselined directly when service persistence is enabled."
            } else {
                "Linux-specific monitoring point."
            }),
        ),
        monitoring_option(
            "scheduled_tasks",
            "Scheduled tasks",
            "Windows task-scheduler persistence and delayed execution.",
            scope.scheduled_tasks,
            platform_key == "windows",
            platform_key == "windows",
            "configurable",
            Some(if platform_key == "windows" {
                "Recommended on Windows because Task Scheduler definitions are baselined directly when service persistence is enabled."
            } else {
                "Windows-specific monitoring point."
            }),
        ),
    ];

    let selected_now = vec![
        (scope.cpu_load, "CPU load"),
        (scope.memory_pressure, "Memory pressure"),
        (scope.network_activity, "Network activity"),
        (scope.disk_pressure, "Disk pressure"),
        (scope.process_activity, "Process activity"),
        (scope.auth_events, "Authentication events"),
        (scope.thermal_state, "Thermal state"),
        (scope.battery_state, "Battery state"),
        (scope.file_integrity, "File integrity"),
        (scope.service_persistence, "Service persistence"),
        (scope.launch_agents, "Launch agents"),
        (scope.systemd_units, "systemd units"),
        (scope.scheduled_tasks, "Scheduled tasks"),
    ]
    .into_iter()
    .filter_map(|(enabled, label)| enabled.then_some(label))
    .collect::<Vec<_>>();

    serde_json::json!({
        "host": {
            "platform": host.platform.to_string(),
            "platform_key": platform_key,
            "hostname": host.hostname,
            "os_version": host.os_version,
            "arch": host.arch,
            "has_tpm": caps.has_tpm,
            "has_seccomp": caps.has_seccomp,
            "has_ebpf": caps.has_ebpf,
            "has_firewall": caps.has_firewall,
            "process_control": caps.process_control,
        },
        "summary": {
            "selected_now": selected_now,
            "watch_path_count": config.monitor.watch_paths.len(),
            "persistence_path_count": persistence_paths.len(),
            "platform_guidance": monitoring_guidance(host.platform),
            "notes": [
                "Core telemetry remains always-on unless a scope toggle explicitly gates that collector.",
                "Auth-event collection and persistence baselines now follow the selected monitoring scope in addition to file-integrity paths."
            ]
        },
        "groups": [
            {
                "id": "core_system",
                "label": "Core System",
                "description": "Signals already collected on every sample.",
                "options": core,
            },
            {
                "id": "security_signals",
                "label": "Security Signals",
                "description": "Signals tied to attack behavior and integrity checks.",
                "options": security,
            },
            {
                "id": "host_specific",
                "label": "Host-Specific",
                "description": "OS-aware recommendations and planned collectors for this platform.",
                "options": host_specific,
            }
        ]
    })
}

pub(crate) fn monitoring_paths_payload(host: &HostInfo, config: &Config) -> serde_json::Value {
    let file_paths = if config.monitor.scope.file_integrity {
        config.monitor.watch_paths.clone()
    } else {
        Vec::new()
    };
    let persistence_paths =
        crate::collector::persistence_watch_paths(host.platform, &config.monitor.scope);
    let file_health = file_paths
        .iter()
        .map(|path| path_health(path))
        .collect::<Vec<_>>();
    let persistence_health = persistence_paths
        .iter()
        .map(|path| path_health(path))
        .collect::<Vec<_>>();
    let unhealthy = file_health
        .iter()
        .chain(persistence_health.iter())
        .filter(|entry| entry["health"] != "ok")
        .count();
    serde_json::json!({
        "file_integrity_paths": file_paths,
        "persistence_paths": persistence_paths,
        "file_integrity_health": file_health,
        "persistence_health": persistence_health,
        "summary": {
            "unhealthy_paths": unhealthy,
        },
        "scope": {
            "file_integrity": config.monitor.scope.file_integrity,
            "service_persistence": config.monitor.scope.service_persistence,
            "launch_agents": config.monitor.scope.launch_agents,
            "systemd_units": config.monitor.scope.systemd_units,
            "scheduled_tasks": config.monitor.scope.scheduled_tasks,
        }
    })
}
