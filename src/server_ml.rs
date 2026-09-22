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
use chrono::{Datelike, Timelike};

use crate::event_forward::{EventStore, StoredEvent};
use crate::ml_engine::{ForestTrainConfig, TrainingExample, TriageFeatures, TriageLabel};
use crate::server::{AppState, read_body_limited, url_param};
use crate::server_response::{error_json, json_response};
use crate::server::save_stored_json;

/// Storage key the trained Random Forest snapshot is persisted under (see
/// `crate::server_support_helpers::{load_stored_json, save_stored_json}` and
/// `storage::SharedStorage::{get_config, set_config}`).
pub(crate) const RF_MODEL_STORAGE_KEY: &str = "ml_model:random_forest";

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

// ── Random Forest training ────────────────────────────────────────────
//
// Training data comes from analyst verdicts recorded through
// `POST /api/alerts/feedback` (see `crate::detection_feedback`). Each
// feedback entry that references a resolvable event is turned back into the
// `TriageFeatures` vector the alert would have produced at triage time, and
// the analyst's verdict becomes the label. `RandomForest::train` (in
// `ml_engine.rs`) then fits a real bagged CART forest over those examples;
// `ModelRegistry::train_random_forest` keeps the pretrained cold-start
// forest instead when too little labelled data exists.

/// Reconstruct the [`TriageFeatures`] an alert would have produced, from the
/// stored event plus a coarse lookback over recent events for the same host.
///
/// `device_risk_score` has no independent signal recorded elsewhere in the
/// pipeline, so it is approximated from MITRE ATT&CK technique coverage (or,
/// lacking that, from reason keywords associated with higher-risk activity
/// such as lateral movement or C2 beaconing). This is a documented heuristic,
/// not a ground-truth risk score.
pub(crate) fn alert_to_triage_features(store: &EventStore, event: &StoredEvent) -> TriageFeatures {
    let parsed_ts = chrono::DateTime::parse_from_rfc3339(&event.alert.timestamp).ok();
    let (hour_of_day, day_of_week) = parsed_ts
        .map(|ts| {
            (
                u8::try_from(ts.hour()).unwrap_or(12),
                u8::try_from(ts.weekday().num_days_from_monday()).unwrap_or(3),
            )
        })
        .unwrap_or((12, 3));

    let alert_frequency_1h = parsed_ts
        .map(|ts| {
            let cutoff = ts - chrono::Duration::hours(1);
            store
                .all_events()
                .iter()
                .filter(|other| {
                    other.alert.hostname == event.alert.hostname
                        && chrono::DateTime::parse_from_rfc3339(&other.alert.timestamp)
                            .is_ok_and(|other_ts| other_ts >= cutoff && other_ts <= ts)
                })
                .count()
        })
        .unwrap_or(0);
    let alert_frequency_1h = u32::try_from(alert_frequency_1h).unwrap_or(u32::MAX);

    const HIGH_RISK_KEYWORDS: &[&str] =
        &["beacon", "c2", "exfil", "credential", "lateral", "privilege"];
    let high_risk_hits = event
        .alert
        .reasons
        .iter()
        .filter(|reason| {
            let lower = reason.to_ascii_lowercase();
            HIGH_RISK_KEYWORDS.iter().any(|kw| lower.contains(kw))
        })
        .count();
    let device_risk_score = if event.alert.mitre.is_empty() {
        (high_risk_hits as f64 / 3.0).min(1.0)
    } else {
        (event.alert.mitre.len() as f64 / 5.0).min(1.0)
    };

    TriageFeatures {
        anomaly_score: f64::from(event.alert.score).clamp(0.0, 1.0),
        confidence: f64::from(event.alert.confidence).clamp(0.0, 1.0),
        suspicious_axes: u32::try_from(event.alert.reasons.len().min(10)).unwrap_or(0),
        hour_of_day,
        day_of_week,
        alert_frequency_1h,
        device_risk_score,
    }
}

/// Map a normalized detection-feedback verdict to a triage label for
/// training. `benign_true_positive` and `needs_more_data` verdicts are not
/// clear-cut true/false positives, so they train the `NeedsReview` class
/// rather than being discarded or forced into a binary label.
fn verdict_to_triage_label(verdict: &str) -> TriageLabel {
    match crate::server::normalize_detection_outcome(verdict) {
        "valid" => TriageLabel::TruePositive,
        "false_positive" | "duplicate" => TriageLabel::FalsePositive,
        _ => TriageLabel::NeedsReview,
    }
}

/// Build the labelled training set from recorded detection feedback whose
/// originating event can still be resolved.
pub(crate) fn build_training_examples(state: &AppState) -> Vec<TrainingExample> {
    state
        .detection_feedback
        .list()
        .iter()
        .filter_map(|entry| {
            let event = state.event_store.get_event(entry.event_id?)?;
            Some(TrainingExample {
                features: alert_to_triage_features(&state.event_store, event).to_vec(),
                label: verdict_to_triage_label(&entry.verdict),
            })
        })
        .collect()
}

/// `POST /api/ml/train` — retrain the Random Forest triage slot from
/// recorded analyst verdicts. Falls back to (and reports) the pretrained
/// cold-start forest when too few labelled examples are available. On
/// success the trained forest, its metrics, and provenance are persisted to
/// the SQLite-backed config store so they survive a restart.
pub(crate) fn handle_ml_train(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let mut s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let examples = build_training_examples(&s);
    let outcome = s
        .model_registry
        .train_random_forest(&examples, ForestTrainConfig::default());
    if outcome.trained
        && let Some(snapshot) = s.model_registry.export_random_forest_snapshot()
    {
        let storage = s.storage.clone();
        if let Err(error) = save_stored_json(&storage, RF_MODEL_STORAGE_KEY, &Some(snapshot)) {
            eprintln!("[WARN] failed to persist trained random forest: {error}");
        }
    }
    json_response(&serde_json::to_string(&outcome).unwrap_or_default(), 200)
}

/// `GET /api/ml/train/status` — current Random Forest training status:
/// whether a real model is active, sample count, and evaluation metrics
/// (out-of-bag accuracy, per-class precision/recall, confusion matrix,
/// feature importance).
pub(crate) fn handle_ml_train_status(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let status = s.model_registry.random_forest_status();
    json_response(&serde_json::to_string(&status).unwrap_or_default(), 200)
}
