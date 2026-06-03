//! ML triage and model-registry route handlers.
//!
//! Extracted from `server.rs` as part of the incremental decomposition of the
//! monolithic dispatch chain. Each handler takes the inputs it actually needs
//! and returns an [`axum::response::Response`]; the route-matching cascade in
//! `server.rs` calls these and feeds the response into the shared
//! `respond_api` wrap.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::response::Response;

use crate::server::{AppState, read_body_limited, url_param};
use crate::server_response::{error_json, json_response};

/// `GET /api/ml/models` — public summary of the model registry.
pub(crate) fn handle_ml_models(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let mut s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    s.model_registry.refresh();
    let status = s.model_registry.status();
    let body = serde_json::json!({
        "loaded": status.loaded_models,
        "available": status.available_models,
        "active_backend": status.active_backend,
        "shadow_backend": status.shadow_backend,
        "shadow_mode": status.shadow_mode,
        "gbm_loaded": status.gbm_loaded,
    });
    json_response(&body.to_string(), 200)
}

/// `GET /api/ml/models/status` — full registry status payload.
pub(crate) fn handle_ml_models_status(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let mut s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    s.model_registry.refresh();
    let body = serde_json::to_string(&s.model_registry.status()).unwrap_or_default();
    json_response(&body, 200)
}

/// `POST /api/ml/models/rollback` — flip the primary triage backend off GBM
/// back onto the Random Forest fallback.
pub(crate) fn handle_ml_models_rollback(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let mut s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let changed = s.model_registry.rollback_alert_triage();
    let body = serde_json::json!({
        "status": s.model_registry.status(),
        "changed": changed,
        "rolled_back_at": chrono::Utc::now().to_rfc3339(),
    });
    json_response(&body.to_string(), 200)
}

/// `GET /api/ml/shadow/recent` — recent shadow-comparison reports for drift
/// review (default limit 20, capped at 100).
pub(crate) fn handle_ml_shadow_recent(url: &str, state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let limit = url_param(url, "limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(20)
        .min(100);
    let s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut reports = s.model_registry.status().recent_shadow_reports;
    reports.truncate(limit);
    json_response(
        &serde_json::json!({
            "count": reports.len(),
            "items": reports,
        })
        .to_string(),
        200,
    )
}

/// `POST /api/ml/triage` — quick Random-Forest triage on a feature vector,
/// without touching the managed registry.
pub(crate) fn handle_ml_triage(body: &[u8], _state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let body_str = match read_body_limited(body, 8192) {
        Ok(value) => value,
        Err(error) => return error_json(&error, 400),
    };
    let features: crate::ml_engine::TriageFeatures = match serde_json::from_str(&body_str) {
        Ok(features) => features,
        Err(error) => return error_json(&format!("invalid features: {error}"), 400),
    };
    let engine = crate::ml_engine::RandomForestEngine::new();
    let result = engine.triage_alert(&features);
    let body = serde_json::to_string(&result).unwrap_or_default();
    json_response(&body, 200)
}

/// `POST /api/ml/triage/v2` — managed triage through the registry; returns
/// the full outcome (primary, shadow, calibration, decision support).
pub(crate) fn handle_ml_triage_v2(body: &[u8], state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let body = match read_body_limited(body, 8192) {
        Ok(body) => body,
        Err(error) => return error_json(&error, 400),
    };
    let features: crate::ml_engine::TriageFeatures = match serde_json::from_str(&body) {
        Ok(features) => features,
        Err(error) => return error_json(&format!("invalid features: {error}"), 400),
    };
    let mut s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    s.model_registry.refresh();
    let body = serde_json::to_string(&s.model_registry.triage_alert(&features)).unwrap_or_default();
    json_response(&body, 200)
}
