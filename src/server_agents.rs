//! Agent lifecycle, enrollment, and scope/update endpoint handlers.
//!
//! Extracted from `server.rs` as part of the incremental decomposition of the
//! monolithic dispatch chain. Each handler takes the inputs it actually needs
//! and returns an [`axum::response::Response`]; the route-matching cascade in
//! `server.rs` calls these and feeds the response into the shared `respond_api`
//! wrap. Shared helpers and `AppState` are imported from `crate::server`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::response::Response;

#[allow(unused_imports)]
use crate::server::*;
use crate::server_response::{error_json, json_response};

pub(crate) fn build_agent_activity_snapshot(
    state: &AppState,
    agent_id: &str,
) -> Result<AgentActivitySnapshot, String> {
    let is_local_console = agent_id == LOCAL_CONSOLE_AGENT_ID;
    let agent = if is_local_console {
        local_console_identity(state)
    } else {
        state
            .agent_registry
            .get(agent_id)
            .cloned()
            .ok_or_else(|| "agent not found".to_string())?
    };
    let events = state.event_store.list(Some(agent_id), 500);
    let total_events = events.len();
    let correlated_count = events.iter().filter(|event| event.correlated).count();
    let critical_count = events
        .iter()
        .filter(|event| severity_rank(&event.alert.level) >= 3)
        .count();
    let average_score = if total_events > 0 {
        events.iter().map(|event| event.alert.score).sum::<f32>() / total_events as f32
    } else {
        0.0
    };
    let max_score = events
        .iter()
        .map(|event| event.alert.score)
        .fold(0.0f32, f32::max);
    let highest_level = events
        .iter()
        .map(|event| severity_rank(&event.alert.level))
        .max()
        .unwrap_or(0);
    let mut reason_counts = HashMap::new();
    for event in &events {
        for reason in &event.alert.reasons {
            *reason_counts.entry(reason.clone()).or_insert(0usize) += 1;
        }
    }
    let mut top_reasons: Vec<(String, usize)> = reason_counts.into_iter().collect();
    top_reasons.sort_by_key(|entry| std::cmp::Reverse(entry.1));

    let timeline = events
        .iter()
        .take(25)
        .map(|event| {
            serde_json::json!({
                "event_id": event.id,
                "received_at": event.received_at,
                "level": event.alert.level,
                "score": event.alert.score,
                "correlated": event.correlated,
                "reasons": event.alert.reasons,
                "action": event.alert.action,
                "triage": event.triage,
            })
        })
        .collect::<Vec<_>>();

    let mut chronological = events.clone();
    chronological.reverse();
    let mut transitions = Vec::new();
    let mut previous_level: Option<String> = None;
    for event in chronological {
        if previous_level.as_deref() != Some(event.alert.level.as_str()) {
            if let Some(from) = previous_level.clone() {
                transitions.push(serde_json::json!({
                    "event_id": event.id,
                    "received_at": event.received_at,
                    "from": from,
                    "to": event.alert.level,
                }));
            }
            previous_level = Some(event.alert.level.clone());
        }
    }

    let mut log_levels = HashMap::new();
    let log_records = state.agent_logs.get(agent_id).cloned().unwrap_or_default();
    for record in &log_records {
        *log_levels.entry(format!("{:?}", record.level)).or_insert(0) += 1;
    }

    let inventory = if is_local_console {
        None
    } else {
        state
            .agent_inventories
            .get(agent_id)
            .map(|inventory| AgentInventorySummary {
                collected_at: inventory.collected_at.clone(),
                software_count: inventory.software.len(),
                services_count: inventory.services.len(),
                network_ports: inventory.network.len(),
                users_count: inventory.users.len(),
                hardware: inventory.hardware.clone(),
            })
    };

    let (computed_status, heartbeat_age_secs) =
        computed_agent_status(&agent, state.agent_registry.heartbeat_interval());
    let effective_scope = if is_local_console {
        state.config.monitor.scope.clone()
    } else {
        state
            .agent_registry
            .get_monitor_scope(agent_id)
            .cloned()
            .unwrap_or_else(|| state.config.monitor.scope.clone())
    };

    Ok(AgentActivitySnapshot {
        agent: agent.clone(),
        local_console: is_local_console,
        computed_status,
        heartbeat_age_secs,
        deployment: state.remote_deployments.get(agent_id).cloned(),
        scope_override: !is_local_console
            && state.agent_registry.get_monitor_scope(agent_id).is_some(),
        effective_scope,
        health: agent.health.clone(),
        analytics: AgentEventAnalyticsSummary {
            event_count: total_events,
            correlated_count,
            critical_count,
            average_score,
            max_score,
            highest_level: match highest_level {
                3 => "Critical".to_string(),
                2 => "Severe".to_string(),
                1 => "Elevated".to_string(),
                _ => "Nominal".to_string(),
            },
            risk: if highest_level >= 3 || correlated_count >= 2 {
                "Critical".to_string()
            } else if highest_level >= 2 || average_score >= 3.0 {
                "Severe".to_string()
            } else if highest_level >= 1 || average_score >= 1.5 {
                "Elevated".to_string()
            } else {
                "Nominal".to_string()
            },
            top_reasons: top_reasons
                .into_iter()
                .take(5)
                .map(|entry| entry.0)
                .collect(),
        },
        timeline,
        risk_transitions: transitions,
        inventory,
        log_summary: AgentLogSummary {
            total_records: log_records.len(),
            last_timestamp: log_records.first().map(|record| record.timestamp.clone()),
            by_level: log_levels,
        },
    })
}

pub(crate) fn handle_agent_enroll(body: &[u8], state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    let req: crate::enrollment::EnrollRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    match s.agent_registry.enroll(&req) {
        Ok(resp) => match serde_json::to_string(&resp) {
            Ok(json) => json_response(&json, 200),
            Err(e) => error_json(&format!("serialization error: {e}"), 500),
        },
        Err(e) => error_json(&e, 403),
    }
}

pub(crate) fn handle_agent_create_token(body: &[u8], state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    #[derive(serde::Deserialize)]
    struct TokenReq {
        #[serde(default = "default_max_uses")]
        max_uses: u32,
        /// Optional TTL in seconds. If set, the token expires after this duration.
        #[serde(default)]
        ttl_secs: Option<u64>,
    }
    fn default_max_uses() -> u32 {
        10
    }
    let req: TokenReq = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => TokenReq {
            max_uses: 10,
            ttl_secs: None,
        },
    };
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    let token = if let Some(ttl) = req.ttl_secs {
        s.agent_registry.create_token_with_ttl(req.max_uses, ttl)
    } else {
        s.agent_registry.create_token(req.max_uses)
    };
    match serde_json::to_string(&token) {
        Ok(json) => json_response(&json, 200),
        Err(e) => error_json(&format!("serialization error: {e}"), 500),
    }
}

pub(crate) fn handle_agent_heartbeat(
    body: &[u8],
    state: &Arc<Mutex<AppState>>,
    agent_id: &str,
) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    #[derive(serde::Deserialize)]
    struct HeartbeatReq {
        #[serde(default)]
        version: String,
        #[serde(default)]
        health: Option<crate::enrollment::AgentHealth>,
    }
    let req: HeartbeatReq = serde_json::from_str(&body).unwrap_or(HeartbeatReq {
        version: env!("CARGO_PKG_VERSION").to_string(),
        health: None,
    });
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    match s
        .agent_registry
        .heartbeat(agent_id, &req.version, req.health.clone())
    {
        Ok(()) => {
            let mut target_version = None;
            let now = chrono::Utc::now().to_rfc3339();
            if let Some(agent) = s.agent_registry.get(agent_id).cloned() {
                let _ = reconcile_fleet_remote_install_heartbeat(
                    &s.storage,
                    agent_id,
                    &agent.hostname,
                    &agent.platform,
                    &now,
                );
            }
            if let Some(deployment) = s.remote_deployments.get_mut(agent_id) {
                deployment.last_heartbeat_at = Some(now.clone());
                if let Some(health) = &req.health
                    && let Some(update_state) = &health.update_state
                {
                    deployment.status = update_state.clone();
                    deployment.status_reason = health.last_update_error.clone();
                    if matches!(
                        update_state.as_str(),
                        "checking" | "downloading" | "downloaded" | "applying"
                    ) && deployment.acknowledged_at.is_none()
                    {
                        deployment.acknowledged_at = Some(now.clone());
                    }
                    if matches!(update_state.as_str(), "restart_pending" | "applied") {
                        deployment.completed_at = Some(now.clone());
                    }
                }
                if deployment.version == req.version {
                    deployment.status = "applied".to_string();
                    deployment.completed_at = Some(now);
                } else {
                    target_version = Some(deployment.version.clone());
                }
            }
            // Auto-rollout progression: if a canary/ring-1 deployment just completed,
            // check if soak time elapsed and auto-progress to next ring.
            let rollout_cfg = s.config.rollout.clone();
            if rollout_cfg.auto_progress {
                // Collect completed deployments that may trigger progression
                let mut progress_candidates: Vec<(String, String, String)> = Vec::new(); // (version, platform, rollout_group)
                for dep in s.remote_deployments.values() {
                    if dep.status == "applied"
                        && let Some(ref completed) = dep.completed_at
                        && let Ok(completed_time) = chrono::DateTime::parse_from_rfc3339(completed)
                    {
                        let elapsed = chrono::Utc::now().signed_duration_since(completed_time);
                        let soak = match dep.rollout_group.as_str() {
                            "canary" => rollout_cfg.canary_soak_secs as i64,
                            "ring-1" => rollout_cfg.ring1_soak_secs as i64,
                            _ => continue,
                        };
                        if elapsed.num_seconds() >= soak {
                            let next_ring = match dep.rollout_group.as_str() {
                                "canary" => "ring-1",
                                "ring-1" => "ring-2",
                                _ => continue,
                            };
                            progress_candidates.push((
                                dep.version.clone(),
                                dep.platform.clone(),
                                next_ring.to_string(),
                            ));
                        }
                    }
                }
                // Check for failures -> auto-rollback
                if rollout_cfg.auto_rollback {
                    let mut rollback_agents: Vec<(String, String)> = Vec::new(); // (agent_id, version_before)
                    for dep in s.remote_deployments.values() {
                        if dep.status == "failed" || dep.status == "error" {
                            // Count failures for this version
                            let fail_count = s
                                .remote_deployments
                                .values()
                                .filter(|d| {
                                    d.version == dep.version
                                        && (d.status == "failed" || d.status == "error")
                                })
                                .count() as u32;
                            if fail_count >= rollout_cfg.max_failures
                                && dep.status_reason.as_deref() != Some("auto_rollback_scheduled")
                            {
                                rollback_agents.push((dep.agent_id.clone(), dep.version.clone()));
                            }
                        }
                    }
                    for (aid, _ver) in &rollback_agents {
                        if let Some(dep) = s.remote_deployments.get_mut(aid) {
                            dep.status = "rollback_pending".to_string();
                            dep.status_reason = Some("auto_rollback_scheduled".to_string());
                        }
                    }
                }
                // Auto-progress: deploy same version to next ring agents that don't already have a deployment
                let update_trust_policy = crate::update_trust::UpdateTrustPolicy::from_settings(
                    &s.config.security.update_signing,
                );
                for (version, platform, next_ring) in progress_candidates {
                    let release = match s.update_manager.get_release(&version, &platform) {
                        Some(release) => release.clone(),
                        None => {
                            log::warn!(
                                "[updates] auto-progress skipped: release {version}/{platform} not found"
                            );
                            continue;
                        }
                    };
                    let release_binary = match s
                        .update_manager
                        .get_release_binary(&release.file_name)
                    {
                        Ok(binary) => binary,
                        Err(e) => {
                            log::warn!(
                                "[updates] auto-progress skipped for {version}/{platform}: release artifact unavailable: {e}"
                            );
                            continue;
                        }
                    };
                    // Find agents enrolled with matching platform that are in the next ring's eligible set
                    let enrolled: Vec<(String, String)> = s
                        .agent_registry
                        .list()
                        .iter()
                        .filter(|a| {
                            a.platform == platform
                                && a.status == crate::enrollment::AgentStatus::Online
                        })
                        .map(|a| (a.id.clone(), a.version.clone()))
                        .collect();
                    for (eid, agent_version) in enrolled {
                        let already_deployed = s
                            .remote_deployments
                            .get(&eid)
                            .map(|d| d.version == version)
                            .unwrap_or(false);
                        if !already_deployed {
                            let last_counter = s
                                .remote_deployments
                                .get(&eid)
                                .and_then(|deployment| deployment.update_counter);
                            let verification = match crate::update_trust::verify_release_artifact(
                                &release,
                                &release_binary,
                                &update_trust_policy,
                                &agent_version,
                                last_counter,
                                false,
                            ) {
                                Ok(verification) => verification,
                                Err(e) => {
                                    log::warn!(
                                        "[updates] auto-progress skipped for agent {eid} to {version}: release trust verification failed: {e}"
                                    );
                                    continue;
                                }
                            };
                            let new_dep = AgentDeployment {
                                agent_id: eid.clone(),
                                version: version.clone(),
                                platform: platform.clone(),
                                mandatory: false,
                                release_notes: format!(
                                    "Auto-progressed from previous ring to {next_ring}"
                                ),
                                status: "assigned".to_string(),
                                status_reason: Some(format!("auto_progress_{next_ring}")),
                                rollout_group: next_ring.clone(),
                                allow_downgrade: false,
                                signature_status: Some(verification.signature_status),
                                signer_pubkey: verification.signer_pubkey,
                                signature_payload_sha256: verification.signature_payload_sha256,
                                update_counter: verification.update_counter,
                                assigned_at: chrono::Utc::now().to_rfc3339(),
                                acknowledged_at: None,
                                completed_at: None,
                                last_heartbeat_at: None,
                            };
                            s.remote_deployments.insert(eid, new_dep);
                        }
                    }
                }
            }
            save_remote_deployments(&s.deployment_store_path, &s.remote_deployments);
            let heartbeat_interval = s.agent_registry.heartbeat_interval();
            // Include agent-specific monitoring scope in heartbeat response
            let agent_scope = s
                .agent_registry
                .get_monitor_scope(agent_id)
                .cloned()
                .unwrap_or_else(|| s.config.monitor.scope.clone());
            let payload = serde_json::json!({
                "status": "ok",
                "interval_secs": heartbeat_interval,
                "heartbeat_interval_secs": heartbeat_interval,
                "update_assigned": target_version.is_some(),
                "target_version": target_version,
                "monitor_scope": agent_scope,
            });
            json_response(&payload.to_string(), 200)
        }
        Err(e) => error_json(&e, 404),
    }
}

pub(crate) fn handle_agent_details(state: &Arc<Mutex<AppState>>, agent_id: &str) -> Response<Body> {
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    match build_agent_activity_snapshot(&s, agent_id) {
        Ok(snapshot) => match serde_json::to_string(&snapshot) {
            Ok(json) => json_response(&json, 200),
            Err(e) => error_json(&format!("serialization error: {e}"), 500),
        },
        Err(e) => error_json(&e, 404),
    }
}

pub(crate) fn handle_agent_update_check(
    _body: &[u8],
    url: &str,
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    // Agent sends GET /api/agents/update?agent_id=xxx&current_version=yyy
    let params = parse_query_string(url);
    let agent_id = params.get("agent_id").cloned();
    let mut current_version = params.get("current_version").cloned().unwrap_or_default();
    let mut platform = params
        .get("platform")
        .cloned()
        .unwrap_or_else(|| "universal".to_string());
    if current_version.is_empty() {
        current_version = env!("CARGO_PKG_VERSION").to_string();
    }
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(agent_id) = agent_id.as_deref() {
        if platform == "universal"
            && let Some(agent) = s.agent_registry.get(agent_id)
        {
            platform = agent.platform.clone();
        }
        if let Some(deployment) = s.remote_deployments.get(agent_id)
            && deployment_requires_action(deployment, &current_version)
            && let Some(release) = s.update_manager.get_release(&deployment.version, &platform)
        {
            let resp = crate::auto_update::UpdateCheckResponse {
                update_available: true,
                version: Some(release.version.clone()),
                platform: Some(release.platform.clone()),
                download_url: Some(format!("/api/updates/download/{}", release.file_name)),
                file_name: Some(release.file_name.clone()),
                file_size: Some(release.file_size),
                sha256: Some(release.sha256.clone()),
                release_notes: Some(release.release_notes.clone()),
                mandatory: Some(release.mandatory),
                allow_downgrade: Some(deployment.allow_downgrade),
                signature: release.signature.clone(),
                signer_pubkey: release.signer_pubkey.clone(),
                signed_at: release.signed_at.clone(),
                signature_payload_sha256: release.signature_payload_sha256.clone(),
                update_counter: release.update_counter,
            };
            return match serde_json::to_string(&resp) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            };
        }
    }
    let resp = s.update_manager.check_update(&current_version, &platform);
    match serde_json::to_string(&resp) {
        Ok(json) => json_response(&json, 200),
        Err(e) => error_json(&format!("serialization error: {e}"), 500),
    }
}

pub(crate) fn handle_agent_set_scope(
    body: &[u8],
    state: &Arc<Mutex<AppState>>,
    agent_id: &str,
) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    // Accept either a full MonitorScopeSettings or {"clear": true} to remove override
    // Try parsing as clear command first
    let clear_check: Result<serde_json::Value, _> = serde_json::from_str(&body);
    let is_clear = clear_check
        .as_ref()
        .ok()
        .and_then(|v| v.get("clear"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    if is_clear {
        match s.agent_registry.set_monitor_scope(agent_id, None) {
            Ok(()) => json_response(
                &serde_json::json!({"status": "scope_cleared", "agent_id": agent_id}).to_string(),
                200,
            ),
            Err(e) => error_json(&e, 404),
        }
    } else {
        let scope: crate::config::MonitorScopeSettings = match serde_json::from_str(&body) {
            Ok(s) => s,
            Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
        };
        match s
            .agent_registry
            .set_monitor_scope(agent_id, Some(scope.clone()))
        {
            Ok(()) => {
                let payload = serde_json::json!({"status": "scope_set", "agent_id": agent_id, "scope": scope});
                json_response(&payload.to_string(), 200)
            }
            Err(e) => error_json(&e, 404),
        }
    }
}

pub(crate) fn handle_agent_get_scope(state: &Arc<Mutex<AppState>>, agent_id: &str) -> Response<Body> {
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    match s.agent_registry.get(agent_id) {
        Some(agent) => {
            let effective_scope = agent
                .monitor_scope
                .as_ref()
                .unwrap_or(&s.config.monitor.scope);
            let payload = serde_json::json!({
                "agent_id": agent_id,
                "override": agent.monitor_scope.is_some(),
                "scope": effective_scope,
                "server_default": s.config.monitor.scope,
            });
            json_response(&payload.to_string(), 200)
        }
        None => error_json("agent not found", 404),
    }
}

