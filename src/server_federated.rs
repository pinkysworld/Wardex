//! Federated-learning admin and agent HTTP handlers (R27).
//!
//! Admin endpoints (`/api/federation/start`, `/stop`, `/status`, `/rounds`)
//! are RBAC-gated (`crate::rbac::endpoint_permission`) like the rest of the
//! authenticated API surface. Agent endpoints (`/api/federation/round`,
//! `/api/federation/round/submit`) always require the per-agent enrollment
//! credential (`X-Wardex-Agent-Id` / `X-Wardex-Agent-Token` headers bound to
//! a registered agent), matching the existing agent↔server channel in
//! `src/agent_client.rs`. The shared `WARDEX_AGENT_TOKEN` and mTLS alone are
//! not accepted here because they do not bind a specific agent id. See
//! `docs/FEDERATED_LEARNING.md` for the protocol and threat model this
//! implements.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::HeaderMap;
use axum::response::Response;
use serde::{Deserialize, Serialize};

#[allow(unused_imports)]
use crate::server::*;
use crate::server_response::{error_json, json_response};

fn persist_federation_state(state: &Arc<Mutex<AppState>>) {
    let (storage, snapshot) = {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (s.storage.clone(), s.federation.clone())
    };
    if let Err(e) = save_stored_json(&storage, FEDERATION_STATE_STORAGE_KEY, &snapshot) {
        log::warn!("[FEDERATION] failed to persist coordinator state: {e}");
    }
}

fn fed_error_status(err: &crate::federated::FedError) -> u16 {
    match err {
        crate::federated::FedError::Disabled => 403,
        crate::federated::FedError::NoOpenRound => 409,
        crate::federated::FedError::WrongRound { .. } => 409,
        crate::federated::FedError::DuplicateSubmission => 409,
        crate::federated::FedError::InvalidShape { .. } => 400,
        crate::federated::FedError::NormExceeded { .. } => 400,
        crate::federated::FedError::NonFiniteUpdate => 400,
        crate::federated::FedError::SampleCountExceeded { .. } => 400,
        crate::federated::FedError::BudgetExhausted => 403,
    }
}

fn fed_error_response(err: crate::federated::FedError) -> Response<Body> {
    let status = fed_error_status(&err);
    let body = serde_json::json!({
        "error": err.to_string(),
        "code": err.code(),
    });
    json_response(&body.to_string(), status)
}

// ── Admin endpoints ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct StartFederationRequest {
    #[serde(default)]
    config: Option<crate::federated::FederationConfig>,
}

/// POST /api/federation/start — (re)start a federation round-robin from a
/// freshly zero-initialized global model. Idempotent: calling it again
/// resets model version, history, and per-agent budgets.
pub(crate) fn handle_federation_start(body: &[u8], state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let body = match read_body_limited(body, 64 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    let req: StartFederationRequest = if body.trim().is_empty() {
        StartFederationRequest { config: None }
    } else {
        match serde_json::from_str(&body) {
            Ok(r) => r,
            Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
        }
    };

    let now = crate::federated::now_ms();
    let snapshot = {
        let mut s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut config = req.config.unwrap_or_else(|| s.config.federation.clone());
        config.enabled = true;
        s.config.federation = config.clone();
        let dim = FEDERATION_PARAM_DIM;
        s.federation.start(config, vec![0.0; dim], now);
        s.federation.clone()
    };
    persist_federation_state(state);
    let body = serde_json::json!({
        "status": "started",
        "model_version": snapshot.model_version,
        "current_round": snapshot.current_round.as_ref().map(|r| r.round_id),
    });
    json_response(&body.to_string(), 200)
}

/// POST /api/federation/stop — halt the federation; any open round is
/// discarded (its submissions so far are dropped, not aggregated).
pub(crate) fn handle_federation_stop(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    {
        let mut s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        s.federation.stop();
        s.config.federation.enabled = false;
    }
    persist_federation_state(state);
    json_response(r#"{"status":"stopped"}"#, 200)
}

#[derive(Debug, Serialize)]
struct FederationStatusResponse {
    enabled: bool,
    running: bool,
    converged: bool,
    model_version: u64,
    current_round: Option<CurrentRoundSummary>,
    completed_rounds: u64,
    agent_budgets: Vec<AgentBudgetSummary>,
}

#[derive(Debug, Serialize)]
struct CurrentRoundSummary {
    round_id: u64,
    status: crate::federated::RoundStatus,
    submissions: usize,
    min_participants: usize,
    opened_at_ms: u64,
    deadline_ms: u64,
}

#[derive(Debug, Serialize)]
struct AgentBudgetSummary {
    agent_id: String,
    spent_epsilon: f64,
    total_epsilon: f64,
    exhausted: bool,
}

/// GET /api/federation/status — coordinator summary: whether it is
/// enabled/running/converged, the current round (if any), and per-agent
/// privacy-budget consumption.
pub(crate) fn handle_federation_status(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    // Opportunistically try to aggregate an overdue round on read, so
    // status reflects reality even if no agent traffic has arrived since
    // the deadline passed.
    try_aggregate_if_ready(state);

    let s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let fed = &s.federation;
    let response = FederationStatusResponse {
        enabled: fed.config.enabled,
        running: fed.is_running(),
        converged: fed.converged,
        model_version: fed.model_version,
        current_round: fed.current_round.as_ref().map(|r| CurrentRoundSummary {
            round_id: r.round_id,
            status: r.status,
            submissions: r.submissions.len(),
            min_participants: r.min_participants,
            opened_at_ms: r.opened_at_ms,
            deadline_ms: r.deadline_ms,
        }),
        completed_rounds: fed.completed_round_count(),
        agent_budgets: fed
            .budget_status()
            .into_iter()
            .map(|(agent_id, spent, total)| AgentBudgetSummary {
                agent_id,
                spent_epsilon: spent,
                total_epsilon: total,
                exhausted: spent >= total,
            })
            .collect(),
    };
    match serde_json::to_string(&response) {
        Ok(json) => json_response(&json, 200),
        Err(e) => error_json(&format!("serialization error: {e}"), 500),
    }
}

/// GET /api/federation/rounds — completed-round history plus the round
/// currently open, newest first.
pub(crate) fn handle_federation_rounds(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    try_aggregate_if_ready(state);
    let s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut history = s.federation.history.clone();
    history.reverse();
    let body = serde_json::json!({
        "history": history,
        "current_round": s.federation.current_round,
        "total": s.federation.completed_round_count(),
    });
    json_response(&body.to_string(), 200)
}

/// Try to close out the current round if it has reached quorum or its
/// deadline. Called opportunistically from status/round-fetch handlers so
/// aggregation does not depend on a background scheduler thread.
fn try_aggregate_if_ready(state: &Arc<Mutex<AppState>>) {
    let now = crate::federated::now_ms();
    let aggregated = {
        let mut s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        s.federation.try_aggregate(now)
    };
    if aggregated.is_some() {
        persist_federation_state(state);
    }
}

// ── Agent endpoints ───────────────────────────────────────────────────────────

/// Resolve the calling agent's id, accepting it only when the presented
/// per-agent token belongs to that registered agent. The request router
/// already enforces this binding for the federation agent routes; checking
/// again here keeps the handlers safe if they are ever reached another way,
/// and guarantees that only registered agents can create budget entries.
fn verified_agent_id(
    headers: &HeaderMap,
    state: &Arc<Mutex<AppState>>,
) -> Result<String, Response<Body>> {
    let Some(agent_id) = header_value(headers, AGENT_ID_HEADER) else {
        return Err(error_json("missing agent identity header", 401));
    };
    let Some(agent_token) = header_value(headers, AGENT_TOKEN_HEADER) else {
        return Err(error_json("per-agent identity binding required", 401));
    };
    let bound = {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        s.agent_registry.agent_token_matches(agent_id, agent_token)
    };
    if bound {
        Ok(agent_id.to_string())
    } else {
        Err(error_json("per-agent identity binding required", 401))
    }
}

/// GET /api/federation/round — an agent polls for the currently open round.
/// Returns 204 if federation is disabled/not running/no round is open, or
/// 403 with `budget_exhausted` if this agent's cumulative privacy budget is
/// spent.
pub(crate) fn handle_federation_fetch_round(
    headers: &HeaderMap,
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    let agent_id = match verified_agent_id(headers, state) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    try_aggregate_if_ready(state);
    let s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match s.federation.fetch_round(&agent_id) {
        Ok(view) => match serde_json::to_string(&view) {
            Ok(json) => json_response(&json, 200),
            Err(e) => error_json(&format!("serialization error: {e}"), 500),
        },
        Err(crate::federated::FedError::Disabled)
        | Err(crate::federated::FedError::NoOpenRound) => json_response("{}", 204),
        Err(e) => fed_error_response(e),
    }
}

#[derive(Debug, Deserialize)]
struct SubmitUpdateRequest {
    round_id: u64,
    params: Vec<f64>,
    sample_count: usize,
    #[serde(default)]
    loss: f64,
}

/// POST /api/federation/round/submit — an agent submits its clipped,
/// noised local-update vector for the round named by `round_id`. The
/// caller must present the per-agent token of the registered agent named in
/// `X-Wardex-Agent-Id`; that verified id (never the request body) is used
/// for replay/budget tracking.
pub(crate) fn handle_federation_submit_update(
    body: &[u8],
    headers: &HeaderMap,
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    let agent_id = match verified_agent_id(headers, state) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let body = match read_body_limited(body, 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    let req: SubmitUpdateRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    if req.params.iter().any(|v| !v.is_finite()) {
        return error_json("update vector must contain only finite values", 400);
    }
    let now = crate::federated::now_ms();
    let result = {
        let mut s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        s.federation.submit_update(
            &agent_id,
            req.round_id,
            req.params,
            req.sample_count,
            req.loss,
            now,
        )
    };
    match result {
        Ok(()) => {
            persist_federation_state(state);
            try_aggregate_if_ready(state);
            json_response(r#"{"status":"accepted"}"#, 200)
        }
        Err(e) => fed_error_response(e),
    }
}

// ── OpenAPI/route-table wiring lives in src/server.rs and
// src/server_routing.rs; see `is_agent_api_endpoint` and the dispatch
// match arms for `/api/federation/*`.
