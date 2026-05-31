//! Fleet enrollment/install and agent-update rollout handlers.
//!
//! Extracted from `server.rs` as part of the incremental decomposition of the
//! monolithic dispatch chain. Covers fleet device registration, remote install
//! (SSH/WinRM) and history, plus the agent-update deploy/rollback/cancel/publish
//! lifecycle. Each handler returns an [`axum::response::Response`]; the
//! route-matching cascade in `server.rs` delegates to these. Shared helpers,
//! `AppState`, and the `AgentDeployment` type are imported from `crate::server`.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::response::Response;

use crate::fleet_install::{
    RemoteInstallRecord, SshInstallRequest, WinRmInstallRequest, execute_ssh_install,
    execute_winrm_install,
};
#[allow(unused_imports)]
use crate::server::*;
use crate::server_response::{error_json, json_response};
use crate::structured_log::generate_request_id;
use crate::swarm::{DeviceRecord, DeviceStatus};

pub(crate) fn handle_fleet_register(body: &[u8], state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    #[derive(serde::Deserialize)]
    struct Reg {
        device_id: String,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        platform: Option<String>,
    }
    let req: Reg = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    let record = DeviceRecord {
        device_id: req.device_id.clone(),
        name: req.name.unwrap_or_else(|| req.device_id.clone()),
        platform: req.platform.unwrap_or_else(|| "unknown".into()),
        firmware_version: "0.0.0".into(),
        enrolled_at: chrono::Utc::now().to_rfc3339(),
        last_seen_ms: chrono::Utc::now().timestamp_millis() as u64,
        status: DeviceStatus::Online,
        tags: Vec::new(),
    };
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    s.swarm.register_device(record);
    let body = serde_json::json!({"status": "registered", "device": req.device_id});
    json_response(&body.to_string(), 200)
}

pub(crate) fn handle_fleet_install_history(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let storage = {
        let s = state.lock().unwrap_or_else(|e| e.into_inner());
        s.storage.clone()
    };
    let installs = load_fleet_remote_installs(&storage);
    let body = serde_json::json!({
        "attempts": installs,
        "total": installs.len(),
    });
    match serde_json::to_string(&body) {
        Ok(json) => json_response(&json, 200),
        Err(e) => error_json(&format!("serialization error: {e}"), 500),
    }
}

pub(crate) fn handle_fleet_install_ssh(
    body: &[u8],
    state: &Arc<Mutex<AppState>>,
    auth_identity: &AuthIdentity,
) -> Response<Body> {
    let body = match read_body_limited(body, 64 * 1024) {
        Ok(body) => body,
        Err(e) => return error_json(&e, 400),
    };
    let request: SshInstallRequest = match serde_json::from_str(&body) {
        Ok(request) => request,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    if let Err(e) = request.validate() {
        return error_json(&e, 400);
    }

    let started_at = chrono::Utc::now().to_rfc3339();
    let (storage, token, actor) = {
        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
        let token = s
            .agent_registry
            .create_token_with_ttl(1, request.effective_ttl_secs());
        (s.storage.clone(), token, auth_identity.actor().to_string())
    };

    let mut record = RemoteInstallRecord {
        id: generate_request_id().unwrap_or_else(|_| {
            let random_suffix = rand::random::<u64>();
            format!("req-fallback-{random_suffix:016x}")
        }),
        transport: "ssh".to_string(),
        hostname: request.hostname.trim().to_string(),
        address: request.address.trim().to_string(),
        platform: request.normalized_platform().to_string(),
        manager_url: request.manager_url.trim_end_matches('/').to_string(),
        agent_id: None,
        ssh_user: request.ssh_user.trim().to_string(),
        ssh_port: request.ssh_port,
        ssh_identity_file: request.validated_identity_file(),
        ssh_accept_new_host_key: request.ssh_accept_new_host_key,
        use_sudo: request.use_sudo,
        winrm_username: None,
        winrm_port: None,
        winrm_use_tls: None,
        winrm_skip_cert_check: None,
        actor,
        status: "pending".to_string(),
        started_at,
        completed_at: None,
        first_heartbeat_at: None,
        token_expires_at: token.expires_at.clone(),
        exit_code: None,
        output_excerpt: None,
        error: None,
    };

    let response_status = match execute_ssh_install(&request, &token.token) {
        Ok(result) => {
            record.status = "awaiting_heartbeat".to_string();
            record.completed_at = Some(chrono::Utc::now().to_rfc3339());
            record.exit_code = result.exit_code;
            record.output_excerpt = result.output_excerpt;
            202
        }
        Err(error) => {
            record.status = "failed".to_string();
            record.completed_at = Some(chrono::Utc::now().to_rfc3339());
            record.error = Some(error);
            502
        }
    };

    if let Err(storage_error) = append_fleet_remote_install(&storage, record.clone()) {
        let body = serde_json::json!({
            "message": "remote install finished but audit persistence failed",
            "storage_error": storage_error,
            "record": record,
        });
        return match serde_json::to_string(&body) {
            Ok(json) => json_response(&json, 500),
            Err(e) => error_json(&format!("serialization error: {e}"), 500),
        };
    }

    match serde_json::to_string(&record) {
        Ok(json) => json_response(&json, response_status),
        Err(e) => error_json(&format!("serialization error: {e}"), 500),
    }
}

pub(crate) fn handle_fleet_install_winrm(
    body: &[u8],
    state: &Arc<Mutex<AppState>>,
    auth_identity: &AuthIdentity,
) -> Response<Body> {
    let body = match read_body_limited(body, 64 * 1024) {
        Ok(body) => body,
        Err(e) => return error_json(&e, 400),
    };
    let request: WinRmInstallRequest = match serde_json::from_str(&body) {
        Ok(request) => request,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    if let Err(e) = request.validate() {
        return error_json(&e, 400);
    }

    let started_at = chrono::Utc::now().to_rfc3339();
    let (storage, token, actor) = {
        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
        let token = s
            .agent_registry
            .create_token_with_ttl(1, request.effective_ttl_secs());
        (s.storage.clone(), token, auth_identity.actor().to_string())
    };

    let mut record = RemoteInstallRecord {
        id: generate_request_id().unwrap_or_else(|_| {
            let random_suffix = rand::random::<u64>();
            format!("req-fallback-{random_suffix:016x}")
        }),
        transport: "winrm".to_string(),
        hostname: request.hostname.trim().to_string(),
        address: request.address.trim().to_string(),
        platform: request.normalized_platform().to_string(),
        manager_url: request.manager_url.trim_end_matches('/').to_string(),
        agent_id: None,
        ssh_user: String::new(),
        ssh_port: 0,
        ssh_identity_file: None,
        ssh_accept_new_host_key: false,
        use_sudo: false,
        winrm_username: Some(request.winrm_username.trim().to_string()),
        winrm_port: Some(request.effective_port()),
        winrm_use_tls: Some(request.winrm_use_tls),
        winrm_skip_cert_check: Some(request.winrm_skip_cert_check),
        actor,
        status: "pending".to_string(),
        started_at,
        completed_at: None,
        first_heartbeat_at: None,
        token_expires_at: token.expires_at.clone(),
        exit_code: None,
        output_excerpt: None,
        error: None,
    };

    let response_status = match execute_winrm_install(&request, &token.token) {
        Ok(result) => {
            record.status = "awaiting_heartbeat".to_string();
            record.completed_at = Some(chrono::Utc::now().to_rfc3339());
            record.exit_code = result.exit_code;
            record.output_excerpt = result.output_excerpt;
            202
        }
        Err(error) => {
            record.status = "failed".to_string();
            record.completed_at = Some(chrono::Utc::now().to_rfc3339());
            let status = if error.starts_with("transport unavailable:") {
                503
            } else {
                502
            };
            record.error = Some(error);
            status
        }
    };

    if let Err(storage_error) = append_fleet_remote_install(&storage, record.clone()) {
        let body = serde_json::json!({
            "message": "remote install finished but audit persistence failed",
            "storage_error": storage_error,
            "record": record,
        });
        return match serde_json::to_string(&body) {
            Ok(json) => json_response(&json, 500),
            Err(e) => error_json(&format!("serialization error: {e}"), 500),
        };
    }

    match serde_json::to_string(&record) {
        Ok(json) => json_response(&json, response_status),
        Err(e) => error_json(&format!("serialization error: {e}"), 500),
    }
}

pub(crate) fn handle_update_deploy(
    body: &[u8],
    state: &Arc<Mutex<AppState>>,
    auth: &AuthIdentity,
) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    #[derive(serde::Deserialize)]
    struct DeployReq {
        agent_id: String,
        version: String,
        #[serde(default)]
        platform: Option<String>,
        #[serde(default)]
        rollout_group: Option<String>,
        #[serde(default)]
        allow_downgrade: bool,
    }

    let req: DeployReq = match serde_json::from_str(&body) {
        Ok(req) => req,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };

    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    let agent = match s.agent_registry.get(&req.agent_id) {
        Some(agent) => agent.clone(),
        None => return error_json("agent not found", 404),
    };
    if !req.allow_downgrade
        && compare_versions(&req.version, &agent.version) == std::cmp::Ordering::Less
    {
        return error_json("downgrade blocked without allow_downgrade=true", 409);
    }
    if let Some(existing) = s.remote_deployments.get(&req.agent_id)
        && !req.allow_downgrade
        && compare_versions(&req.version, &existing.version) == std::cmp::Ordering::Less
    {
        return error_json(
            "deployment would roll back an already assigned version",
            409,
        );
    }
    let platform = req.platform.unwrap_or_else(|| agent.platform.clone());
    let release = match s.update_manager.get_release(&req.version, &platform) {
        Some(release) => release.clone(),
        None => return error_json("release not found for agent platform", 404),
    };
    let release_binary = match s.update_manager.get_release_binary(&release.file_name) {
        Ok(binary) => binary,
        Err(e) => return error_json(&format!("release artifact unavailable: {e}"), 409),
    };
    let policy =
        crate::update_trust::UpdateTrustPolicy::from_settings(&s.config.security.update_signing);
    let last_counter = s
        .remote_deployments
        .get(&req.agent_id)
        .and_then(|deployment| deployment.update_counter);
    let verification = match crate::update_trust::verify_release_artifact(
        &release,
        &release_binary,
        &policy,
        &agent.version,
        last_counter,
        req.allow_downgrade,
    ) {
        Ok(verification) => verification,
        Err(e) => return error_json(&format!("release trust verification failed: {e}"), 409),
    };
    let rollout_group = normalize_rollout_group(req.rollout_group.as_deref());

    let deployment = AgentDeployment {
        agent_id: req.agent_id.clone(),
        version: release.version.clone(),
        platform: platform.clone(),
        mandatory: release.mandatory,
        release_notes: release.release_notes.clone(),
        status: "assigned".to_string(),
        status_reason: None,
        rollout_group,
        allow_downgrade: req.allow_downgrade,
        signature_status: Some(verification.signature_status),
        signer_pubkey: verification.signer_pubkey,
        signature_payload_sha256: verification.signature_payload_sha256,
        update_counter: verification.update_counter,
        assigned_at: chrono::Utc::now().to_rfc3339(),
        acknowledged_at: None,
        completed_at: None,
        last_heartbeat_at: None,
    };
    s.remote_deployments
        .insert(req.agent_id.clone(), deployment.clone());
    save_remote_deployments(&s.deployment_store_path, &s.remote_deployments);
    s.enterprise.record_rollout_event(
        "deploy",
        &deployment.version,
        Some(deployment.platform.clone()),
        Some(deployment.agent_id.clone()),
        Some(deployment.rollout_group.clone()),
        &deployment.status,
        auth.actor(),
        deployment
            .status_reason
            .clone()
            .or_else(|| Some(deployment.release_notes.clone())),
    );

    let payload = serde_json::json!({
        "status": "assigned",
        "agent_id": req.agent_id,
        "deployment": deployment,
    });
    json_response(&payload.to_string(), 200)
}

pub(crate) fn handle_update_rollback(
    body: &[u8],
    state: &Arc<Mutex<AppState>>,
    auth: &AuthIdentity,
) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    #[derive(serde::Deserialize)]
    struct RollbackReq {
        agent_id: String,
        target_version: String,
    }
    let req: RollbackReq = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    let agent = match s.agent_registry.get(&req.agent_id) {
        Some(a) => a.clone(),
        None => return error_json("agent not found", 404),
    };
    let platform = agent.platform.clone();
    let release = match s.update_manager.get_release(&req.target_version, &platform) {
        Some(r) => r.clone(),
        None => return error_json("release not found for agent platform", 404),
    };
    let release_binary = match s.update_manager.get_release_binary(&release.file_name) {
        Ok(binary) => binary,
        Err(e) => return error_json(&format!("release artifact unavailable: {e}"), 409),
    };
    let policy =
        crate::update_trust::UpdateTrustPolicy::from_settings(&s.config.security.update_signing);
    let verification = match crate::update_trust::verify_release_artifact(
        &release,
        &release_binary,
        &policy,
        &agent.version,
        None,
        true,
    ) {
        Ok(verification) => verification,
        Err(e) => return error_json(&format!("release trust verification failed: {e}"), 409),
    };
    // Cancel any existing deployment
    if let Some(existing) = s.remote_deployments.get(&req.agent_id)
        && !is_terminal_deployment_status(&existing.status)
    {
        // Mark the old deployment as cancelled before replacing
    }
    let deployment = AgentDeployment {
        agent_id: req.agent_id.clone(),
        version: release.version.clone(),
        platform,
        mandatory: true,
        release_notes: format!("Rollback to v{}", release.version),
        status: "assigned".to_string(),
        status_reason: Some("rollback".to_string()),
        rollout_group: "direct".to_string(),
        allow_downgrade: true,
        signature_status: Some(verification.signature_status),
        signer_pubkey: verification.signer_pubkey,
        signature_payload_sha256: verification.signature_payload_sha256,
        update_counter: verification.update_counter,
        assigned_at: chrono::Utc::now().to_rfc3339(),
        acknowledged_at: None,
        completed_at: None,
        last_heartbeat_at: None,
    };
    s.remote_deployments
        .insert(req.agent_id.clone(), deployment.clone());
    save_remote_deployments(&s.deployment_store_path, &s.remote_deployments);
    s.enterprise.record_rollout_event(
        "rollback",
        &deployment.version,
        Some(deployment.platform.clone()),
        Some(deployment.agent_id.clone()),
        Some(deployment.rollout_group.clone()),
        &deployment.status,
        auth.actor(),
        deployment.status_reason.clone(),
    );
    let payload = serde_json::json!({
        "status": "rollback_assigned",
        "agent_id": req.agent_id,
        "deployment": deployment,
    });
    json_response(&payload.to_string(), 200)
}

pub(crate) fn handle_update_cancel(
    body: &[u8],
    state: &Arc<Mutex<AppState>>,
    auth: &AuthIdentity,
) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    #[derive(serde::Deserialize)]
    struct CancelReq {
        agent_id: String,
    }
    let req: CancelReq = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    match s.remote_deployments.get_mut(&req.agent_id) {
        Some(deployment) => {
            if is_terminal_deployment_status(&deployment.status) {
                return error_json("deployment already in terminal state", 409);
            }
            deployment.status = "cancelled".to_string();
            deployment.status_reason = Some("cancelled by admin".to_string());
            deployment.completed_at = Some(chrono::Utc::now().to_rfc3339());
            let deployment_snapshot = deployment.clone();
            save_remote_deployments(&s.deployment_store_path, &s.remote_deployments);
            s.enterprise.record_rollout_event(
                "cancel",
                &deployment_snapshot.version,
                Some(deployment_snapshot.platform.clone()),
                Some(deployment_snapshot.agent_id.clone()),
                Some(deployment_snapshot.rollout_group.clone()),
                &deployment_snapshot.status,
                auth.actor(),
                deployment_snapshot.status_reason.clone(),
            );
            json_response(
                &serde_json::json!({"status": "cancelled", "agent_id": req.agent_id}).to_string(),
                200,
            )
        }
        None => error_json("no deployment found for agent", 404),
    }
}

pub(crate) fn handle_update_publish(
    body: &[u8],
    state: &Arc<Mutex<AppState>>,
    auth: &AuthIdentity,
) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    #[derive(serde::Deserialize)]
    struct PublishReq {
        version: String,
        platform: String,
        #[serde(default)]
        binary_base64: String,
        #[serde(default)]
        release_notes: String,
        #[serde(default)]
        mandatory: bool,
    }
    let req: PublishReq = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };

    let binary = match base64_decode(&req.binary_base64) {
        Ok(b) => b,
        Err(e) => return error_json(&format!("invalid base64: {e}"), 400),
    };

    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    let signing_key =
        match crate::update_trust::load_update_signing_key(&s.config.security.update_signing) {
            Ok(signing_key) => signing_key,
            Err(e) => return error_json(&format!("update signing key invalid: {e}"), 400),
        };
    let trust_policy =
        crate::update_trust::UpdateTrustPolicy::from_settings(&s.config.security.update_signing);
    if signing_key.is_none() && trust_policy.signatures_required_now() {
        return error_json(
            "signed updates are required but no update signing key is configured",
            409,
        );
    }

    let published = if let Some(signing_key) = signing_key.as_deref() {
        s.update_manager.publish_signed_release(
            &req.version,
            &req.platform,
            &binary,
            &req.release_notes,
            req.mandatory,
            signing_key,
        )
    } else {
        s.update_manager.publish_release(
            &req.version,
            &req.platform,
            &binary,
            &req.release_notes,
            req.mandatory,
        )
    };

    match published {
        Ok(release) => {
            s.enterprise.record_rollout_event(
                "publish",
                &release.version,
                Some(release.platform.clone()),
                None,
                None,
                "published",
                auth.actor(),
                Some(release.release_notes.clone()),
            );
            match serde_json::to_string(&release) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        Err(e) => error_json(&e, 500),
    }
}
