//! Secrets-manager route handlers.
//!
//! Extracted from `server.rs` as part of the incremental decomposition of the
//! monolithic dispatch chain. Each handler takes the inputs it actually needs
//! and returns an [`axum::response::Response`]; the route-matching cascade in
//! `server.rs` calls these and feeds the response into the shared `respond_api`
//! wrap.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::response::Response;

use crate::integration_setup::SecretsManagerSetupPatch;
use crate::server::{
    AppState, SECRETS_MANAGER_SETUP_KEY, build_secrets_rotation_operations,
    load_secrets_manager_setup, masked_secret_preview, read_json_body, read_json_value,
    save_stored_json, secret_reference_kind,
};
use crate::server_evidence::{payload_with_snapshot, persist_operational_snapshot};
use crate::server_response::{error_json, json_response};

/// `GET /api/secrets/rotation-operations` — rotation-operations dashboard with
/// a persisted operational snapshot.
pub(crate) fn handle_secrets_rotation_operations(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let body = build_secrets_rotation_operations(&s);
    let snapshot = persist_operational_snapshot(&s.storage, "secrets_rotation_operations", &body);
    json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
}

/// `GET /api/secrets/status` — secrets-manager configuration, validation, and
/// resolver status.
pub(crate) fn handle_secrets_status(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let setup = load_secrets_manager_setup(&s.storage);
    let resolver = crate::secrets::SecretsResolver::new(setup.to_runtime());
    let body = serde_json::json!({
        "config": setup.view(),
        "validation": setup.validate(),
        "status": resolver.status(),
    });
    json_response(&body.to_string(), 200)
}

/// `POST /api/secrets/config` — save secrets-manager setup fields, preserving
/// the current Vault token when omitted.
pub(crate) fn handle_secrets_config(body: &[u8], state: &Arc<Mutex<AppState>>) -> Response<Body> {
    match read_json_body::<SecretsManagerSetupPatch>(body, 16 * 1024) {
        Ok(patch) => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut setup = load_secrets_manager_setup(&s.storage);
            setup.apply_patch(patch);
            match save_stored_json(&s.storage, SECRETS_MANAGER_SETUP_KEY, &setup) {
                Ok(()) => {
                    let resolver = crate::secrets::SecretsResolver::new(setup.to_runtime());
                    let body = serde_json::json!({
                        "status": "saved",
                        "config": setup.view(),
                        "validation": setup.validate(),
                        "status_summary": resolver.status(),
                    });
                    json_response(&body.to_string(), 200)
                }
                Err(error) => error_json(&error, 500),
            }
        }
        Err(error) => error_json(&error, 400),
    }
}

/// `POST /api/secrets/validate` — resolve and validate a secret reference
/// without disclosing the full plaintext.
pub(crate) fn handle_secrets_validate(body: &[u8], state: &Arc<Mutex<AppState>>) -> Response<Body> {
    match read_json_value(body, 12 * 1024) {
        Ok(payload) => {
            let reference = payload["reference"].as_str().unwrap_or("").trim();
            if reference.is_empty() {
                error_json("reference is required", 400)
            } else {
                let s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let setup = load_secrets_manager_setup(&s.storage);
                let resolver = crate::secrets::SecretsResolver::new(setup.to_runtime());
                match resolver.resolve(reference) {
                    Ok(value) => {
                        let body = serde_json::json!({
                            "ok": true,
                            "reference_kind": secret_reference_kind(reference),
                            "resolved_length": value.chars().count(),
                            "preview": masked_secret_preview(&value),
                            "status": resolver.status(),
                            "validation": setup.validate(),
                        });
                        json_response(&body.to_string(), 200)
                    }
                    Err(error) => {
                        let body = serde_json::json!({
                            "ok": false,
                            "reference_kind": secret_reference_kind(reference),
                            "resolved_length": serde_json::Value::Null,
                            "preview": serde_json::Value::Null,
                            "status": resolver.status(),
                            "validation": setup.validate(),
                            "error": error,
                        });
                        json_response(&body.to_string(), 200)
                    }
                }
            }
        }
        Err(error) => error_json(&error, 400),
    }
}
