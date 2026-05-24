//! Cloud/identity/SaaS collector configuration and validation route handlers.
//!
//! Extracted from `server.rs` as part of the incremental decomposition of the
//! monolithic dispatch chain. Covers the fixed-provider collector endpoints
//! (`/api/collectors/status` plus aws/azure/gcp/okta/entra/m365/workspace
//! GET/config/validate). The dynamic "planned collector" routes remain inline
//! in `server.rs` (they early-`return` from the dispatcher). Shared helpers,
//! setup loaders/types, and `AppState` are imported from `crate::server`.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::response::Response;

#[allow(unused_imports)]
use crate::server::*;
use crate::integration_setup::{
    AwsCollectorSetupPatch, AzureCollectorSetupPatch, EntraCollectorSetupPatch,
    GcpCollectorSetupPatch, M365CollectorSetupPatch, OktaCollectorSetupPatch,
    WorkspaceCollectorSetupPatch,
};
use crate::server_response::{error_json, json_response};

pub(crate) fn handle_collectors_status(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    let aws = load_aws_collector_setup(&s.storage);
    let azure = load_azure_collector_setup(&s.storage);
    let gcp = load_gcp_collector_setup(&s.storage);
    let okta = load_okta_collector_setup(&s.storage);
    let entra = load_entra_collector_setup(&s.storage);
    let m365 = load_m365_collector_setup(&s.storage);
    let workspace = load_workspace_collector_setup(&s.storage);
    let aws_validation = aws.validate();
    let azure_validation = azure.validate();
    let gcp_validation = gcp.validate();
    let okta_validation = okta.validate();
    let entra_validation = entra.validate();
    let m365_validation = m365.validate();
    let workspace_validation = workspace.validate();
    let body = serde_json::json!({
        "collectors": [
            collector_status_entry(
                "aws_cloudtrail",
                aws.enabled,
                aws.poll_interval_secs,
                serde_json::json!({
                    "region": aws.region,
                    "access_key_id": aws.access_key_id,
                    "has_secret_access_key": !aws.secret_access_key.trim().is_empty(),
                    "has_session_token": aws.session_token.as_ref().is_some_and(|value| !value.trim().is_empty()),
                }),
                aws_validation,
                load_collector_checkpoint(&s.storage, "aws_cloudtrail"),
                load_collector_lifecycle(&s.storage, "aws_cloudtrail"),
            ),
            collector_status_entry(
                "azure_activity",
                azure.enabled,
                azure.poll_interval_secs,
                serde_json::json!({
                    "tenant_id": azure.tenant_id,
                    "client_id": azure.client_id,
                    "subscription_id": azure.subscription_id,
                    "has_client_secret": !azure.client_secret.trim().is_empty(),
                }),
                azure_validation,
                load_collector_checkpoint(&s.storage, "azure_activity"),
                load_collector_lifecycle(&s.storage, "azure_activity"),
            ),
            collector_status_entry(
                "gcp_audit",
                gcp.enabled,
                gcp.poll_interval_secs,
                serde_json::json!({
                    "project_id": gcp.project_id,
                    "service_account_email": gcp.service_account_email,
                    "key_file_path": gcp.key_file_path,
                    "has_private_key_pem": gcp.private_key_pem.as_ref().is_some_and(|value| !value.trim().is_empty()),
                }),
                gcp_validation,
                load_collector_checkpoint(&s.storage, "gcp_audit"),
                load_collector_lifecycle(&s.storage, "gcp_audit"),
            ),
            collector_status_entry(
                "okta_identity",
                okta.enabled,
                okta.poll_interval_secs,
                serde_json::json!({
                    "domain": okta.domain,
                    "event_type_count": okta.event_type_filter.len(),
                    "has_api_token": !okta.api_token.trim().is_empty(),
                }),
                okta_validation,
                load_collector_checkpoint(&s.storage, "okta_identity"),
                load_collector_lifecycle(&s.storage, "okta_identity"),
            ),
            collector_status_entry(
                "entra_identity",
                entra.enabled,
                entra.poll_interval_secs,
                serde_json::json!({
                    "tenant_id": entra.tenant_id,
                    "client_id": entra.client_id,
                    "has_client_secret": !entra.client_secret.trim().is_empty(),
                }),
                entra_validation,
                load_collector_checkpoint(&s.storage, "entra_identity"),
                load_collector_lifecycle(&s.storage, "entra_identity"),
            ),
            collector_status_entry(
                "m365_saas",
                m365.enabled,
                m365.poll_interval_secs,
                serde_json::json!({
                    "tenant_id": m365.tenant_id,
                    "client_id": m365.client_id,
                    "content_type_count": m365.content_types.len(),
                    "has_client_secret": !m365.client_secret.trim().is_empty(),
                }),
                m365_validation,
                load_collector_checkpoint(&s.storage, "m365_saas"),
                load_collector_lifecycle(&s.storage, "m365_saas"),
            ),
            collector_status_entry(
                "workspace_saas",
                workspace.enabled,
                workspace.poll_interval_secs,
                serde_json::json!({
                    "customer_id": workspace.customer_id,
                    "delegated_admin_email": workspace.delegated_admin_email,
                    "service_account_email": workspace.service_account_email,
                    "application_count": workspace.applications.len(),
                    "has_credentials_json": !workspace.credentials_json.trim().is_empty(),
                }),
                workspace_validation,
                load_collector_checkpoint(&s.storage, "workspace_saas"),
                load_collector_lifecycle(&s.storage, "workspace_saas"),
            ),
            planned_collector_status_entry(&s.storage, "github_audit"),
            planned_collector_status_entry(&s.storage, "crowdstrike_falcon"),
            planned_collector_status_entry(&s.storage, "generic_syslog"),
        ],
    });
    json_response(&body.to_string(), 200)
}

pub(crate) fn handle_collector_aws_get(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    let setup = load_aws_collector_setup(&s.storage);
    let body = config_validation_payload(setup.view(), setup.validate());
    json_response(&body.to_string(), 200)
}

pub(crate) fn handle_collector_aws_config(body: &[u8], state: &Arc<Mutex<AppState>>) -> Response<Body> {
    match read_json_body::<AwsCollectorSetupPatch>(body, 16 * 1024) {
        Ok(patch) => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let mut setup = load_aws_collector_setup(&s.storage);
            setup.apply_patch(patch);
            match save_stored_json(&s.storage, AWS_COLLECTOR_SETUP_KEY, &setup) {
                Ok(()) => {
                    let body = serde_json::json!({
                        "status": "saved",
                        "provider": "aws_cloudtrail",
                        "config": setup.view(),
                        "validation": setup.validate(),
                    });
                    json_response(&body.to_string(), 200)
                }
                Err(error) => error_json(&error, 500),
            }
        }
        Err(error) => error_json(&error, 400),
    }
}

pub(crate) fn handle_collector_aws_validate(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    let setup = load_aws_collector_setup(&s.storage);
    let validation = setup.validate();
    if validation.status != "ready" {
        let body = serde_json::json!({
            "provider": "aws_cloudtrail",
            "success": false,
            "event_count": 0,
            "sample_events": [],
            "validation": validation,
            "error": "Collector configuration is incomplete.",
        });
        collector_validation_response(&s.storage, "aws_cloudtrail", body)
    } else {
        let resolver = build_secrets_resolver(&s.storage);
        match setup.to_runtime(&resolver) {
            Ok(runtime) => {
                let mut collector =
                    crate::collector_aws::AwsCloudTrailCollector::new(runtime);
                let result = collector.poll();
                let sample_events: Vec<_> =
                    result.events.iter().take(5).cloned().collect();
                let body = serde_json::json!({
                    "provider": "aws_cloudtrail",
                    "success": result.success,
                    "event_count": result.event_count,
                    "polled_at": result.polled_at,
                    "next_token": result.next_token,
                    "sample_events": sample_events,
                    "validation": validation,
                    "error": result.error,
                });
                collector_validation_response(&s.storage, "aws_cloudtrail", body)
            }
            Err(error) => {
                let body = serde_json::json!({
                    "provider": "aws_cloudtrail",
                    "success": false,
                    "event_count": 0,
                    "sample_events": [],
                    "validation": validation,
                    "error": error,
                });
                collector_validation_response(&s.storage, "aws_cloudtrail", body)
            }
        }
    }
}

pub(crate) fn handle_collector_azure_get(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    let setup = load_azure_collector_setup(&s.storage);
    let body = config_validation_payload(setup.view(), setup.validate());
    json_response(&body.to_string(), 200)
}

pub(crate) fn handle_collector_azure_config(body: &[u8], state: &Arc<Mutex<AppState>>) -> Response<Body> {
    match read_json_body::<AzureCollectorSetupPatch>(body, 16 * 1024) {
        Ok(patch) => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let mut setup = load_azure_collector_setup(&s.storage);
            setup.apply_patch(patch);
            match save_stored_json(&s.storage, AZURE_COLLECTOR_SETUP_KEY, &setup) {
                Ok(()) => {
                    let body = serde_json::json!({
                        "status": "saved",
                        "provider": "azure_activity",
                        "config": setup.view(),
                        "validation": setup.validate(),
                    });
                    json_response(&body.to_string(), 200)
                }
                Err(error) => error_json(&error, 500),
            }
        }
        Err(error) => error_json(&error, 400),
    }
}

pub(crate) fn handle_collector_azure_validate(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    let setup = load_azure_collector_setup(&s.storage);
    let validation = setup.validate();
    if validation.status != "ready" {
        let body = serde_json::json!({
            "provider": "azure_activity",
            "success": false,
            "event_count": 0,
            "sample_events": [],
            "validation": validation,
            "error": "Collector configuration is incomplete.",
        });
        collector_validation_response(&s.storage, "azure_activity", body)
    } else {
        let resolver = build_secrets_resolver(&s.storage);
        match setup.to_runtime(&resolver) {
            Ok(runtime) => {
                let mut collector =
                    crate::collector_azure::AzureActivityCollector::new(runtime);
                let result = collector.poll();
                let sample_events: Vec<_> =
                    result.events.iter().take(5).cloned().collect();
                let body = serde_json::json!({
                    "provider": "azure_activity",
                    "success": result.success,
                    "event_count": result.event_count,
                    "polled_at": result.polled_at,
                    "sample_events": sample_events,
                    "validation": validation,
                    "error": result.error,
                });
                collector_validation_response(&s.storage, "azure_activity", body)
            }
            Err(error) => {
                let body = serde_json::json!({
                    "provider": "azure_activity",
                    "success": false,
                    "event_count": 0,
                    "sample_events": [],
                    "validation": validation,
                    "error": error,
                });
                collector_validation_response(&s.storage, "azure_activity", body)
            }
        }
    }
}

pub(crate) fn handle_collector_gcp_get(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    let setup = load_gcp_collector_setup(&s.storage);
    let body = config_validation_payload(setup.view(), setup.validate());
    json_response(&body.to_string(), 200)
}

pub(crate) fn handle_collector_gcp_config(body: &[u8], state: &Arc<Mutex<AppState>>) -> Response<Body> {
    match read_json_body::<GcpCollectorSetupPatch>(body, 20 * 1024) {
        Ok(patch) => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let mut setup = load_gcp_collector_setup(&s.storage);
            setup.apply_patch(patch);
            match save_stored_json(&s.storage, GCP_COLLECTOR_SETUP_KEY, &setup) {
                Ok(()) => {
                    let body = serde_json::json!({
                        "status": "saved",
                        "provider": "gcp_audit",
                        "config": setup.view(),
                        "validation": setup.validate(),
                    });
                    json_response(&body.to_string(), 200)
                }
                Err(error) => error_json(&error, 500),
            }
        }
        Err(error) => error_json(&error, 400),
    }
}

pub(crate) fn handle_collector_gcp_validate(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    let setup = load_gcp_collector_setup(&s.storage);
    let validation = setup.validate();
    if validation.status != "ready" {
        let body = serde_json::json!({
            "provider": "gcp_audit",
            "success": false,
            "event_count": 0,
            "sample_events": [],
            "validation": validation,
            "error": "Collector configuration is incomplete.",
        });
        collector_validation_response(&s.storage, "gcp_audit", body)
    } else {
        let resolver = build_secrets_resolver(&s.storage);
        match setup.to_runtime(&resolver) {
            Ok(runtime) => {
                let mut collector =
                    crate::collector_gcp::GcpAuditCollector::new(runtime);
                let result = collector.poll();
                let sample_events: Vec<_> =
                    result.events.iter().take(5).cloned().collect();
                let body = serde_json::json!({
                    "provider": "gcp_audit",
                    "success": result.success,
                    "event_count": result.event_count,
                    "polled_at": result.polled_at,
                    "next_page_token": result.next_page_token,
                    "sample_events": sample_events,
                    "validation": validation,
                    "error": result.error,
                });
                collector_validation_response(&s.storage, "gcp_audit", body)
            }
            Err(error) => {
                let body = serde_json::json!({
                    "provider": "gcp_audit",
                    "success": false,
                    "event_count": 0,
                    "sample_events": [],
                    "validation": validation,
                    "error": error,
                });
                collector_validation_response(&s.storage, "gcp_audit", body)
            }
        }
    }
}

pub(crate) fn handle_collector_okta_get(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    let setup = load_okta_collector_setup(&s.storage);
    let body = config_validation_payload(setup.view(), setup.validate());
    json_response(&body.to_string(), 200)
}

pub(crate) fn handle_collector_okta_config(body: &[u8], state: &Arc<Mutex<AppState>>) -> Response<Body> {
    match read_json_body::<OktaCollectorSetupPatch>(body, 16 * 1024) {
        Ok(patch) => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let mut setup = load_okta_collector_setup(&s.storage);
            setup.apply_patch(patch);
            match save_stored_json(&s.storage, OKTA_COLLECTOR_SETUP_KEY, &setup) {
                Ok(()) => {
                    let body = serde_json::json!({
                        "status": "saved",
                        "provider": "okta_identity",
                        "config": setup.view(),
                        "validation": setup.validate(),
                    });
                    json_response(&body.to_string(), 200)
                }
                Err(error) => error_json(&error, 500),
            }
        }
        Err(error) => error_json(&error, 400),
    }
}

pub(crate) fn handle_collector_okta_validate(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    let setup = load_okta_collector_setup(&s.storage);
    let resolver = build_secrets_resolver(&s.storage);
    let body = validate_okta_collector(&setup, &resolver);
    collector_validation_response(&s.storage, "okta_identity", body)
}

pub(crate) fn handle_collector_entra_get(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    let setup = load_entra_collector_setup(&s.storage);
    let body = config_validation_payload(setup.view(), setup.validate());
    json_response(&body.to_string(), 200)
}

pub(crate) fn handle_collector_entra_config(body: &[u8], state: &Arc<Mutex<AppState>>) -> Response<Body> {
    match read_json_body::<EntraCollectorSetupPatch>(body, 16 * 1024) {
        Ok(patch) => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let mut setup = load_entra_collector_setup(&s.storage);
            setup.apply_patch(patch);
            match save_stored_json(&s.storage, ENTRA_COLLECTOR_SETUP_KEY, &setup) {
                Ok(()) => {
                    let body = serde_json::json!({
                        "status": "saved",
                        "provider": "entra_identity",
                        "config": setup.view(),
                        "validation": setup.validate(),
                    });
                    json_response(&body.to_string(), 200)
                }
                Err(error) => error_json(&error, 500),
            }
        }
        Err(error) => error_json(&error, 400),
    }
}

pub(crate) fn handle_collector_entra_validate(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    let setup = load_entra_collector_setup(&s.storage);
    let resolver = build_secrets_resolver(&s.storage);
    let body = validate_entra_collector(&setup, &resolver);
    collector_validation_response(&s.storage, "entra_identity", body)
}

pub(crate) fn handle_collector_m365_get(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    let setup = load_m365_collector_setup(&s.storage);
    let body = config_validation_payload(setup.view(), setup.validate());
    json_response(&body.to_string(), 200)
}

pub(crate) fn handle_collector_m365_config(body: &[u8], state: &Arc<Mutex<AppState>>) -> Response<Body> {
    match read_json_body::<M365CollectorSetupPatch>(body, 16 * 1024) {
        Ok(patch) => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let mut setup = load_m365_collector_setup(&s.storage);
            setup.apply_patch(patch);
            match save_stored_json(&s.storage, M365_COLLECTOR_SETUP_KEY, &setup) {
                Ok(()) => {
                    let body = serde_json::json!({
                        "status": "saved",
                        "provider": "m365_saas",
                        "config": setup.view(),
                        "validation": setup.validate(),
                    });
                    json_response(&body.to_string(), 200)
                }
                Err(error) => error_json(&error, 500),
            }
        }
        Err(error) => error_json(&error, 400),
    }
}

pub(crate) fn handle_collector_m365_validate(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    let setup = load_m365_collector_setup(&s.storage);
    let resolver = build_secrets_resolver(&s.storage);
    let body = validate_m365_collector(&setup, &resolver);
    collector_validation_response(&s.storage, "m365_saas", body)
}

pub(crate) fn handle_collector_workspace_get(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    let setup = load_workspace_collector_setup(&s.storage);
    let body = config_validation_payload(setup.view(), setup.validate());
    json_response(&body.to_string(), 200)
}

pub(crate) fn handle_collector_workspace_config(body: &[u8], state: &Arc<Mutex<AppState>>) -> Response<Body> {
    match read_json_body::<WorkspaceCollectorSetupPatch>(body, 32 * 1024) {
        Ok(patch) => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let mut setup = load_workspace_collector_setup(&s.storage);
            setup.apply_patch(patch);
            match save_stored_json(&s.storage, WORKSPACE_COLLECTOR_SETUP_KEY, &setup) {
                Ok(()) => {
                    let body = serde_json::json!({
                        "status": "saved",
                        "provider": "workspace_saas",
                        "config": setup.view(),
                        "validation": setup.validate(),
                    });
                    json_response(&body.to_string(), 200)
                }
                Err(error) => error_json(&error, 500),
            }
        }
        Err(error) => error_json(&error, 400),
    }
}

pub(crate) fn handle_collector_workspace_validate(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    let setup = load_workspace_collector_setup(&s.storage);
    let resolver = build_secrets_resolver(&s.storage);
    let body = validate_workspace_collector(&setup, &resolver);
    collector_validation_response(&s.storage, "workspace_saas", body)
}
