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
use crate::integration_setup::{
    AwsCollectorSetup, AzureCollectorSetup, EntraCollectorSetup, GcpCollectorSetup,
    M365CollectorSetup, OktaCollectorSetup, SetupValidation, SetupValidationIssue,
    WorkspaceCollectorSetup,
};
use crate::server_response::{error_json, json_response};
use crate::storage::SharedStorage;

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

// ── Planned (not-yet-live) collector setup + validation helpers ──

pub(crate) fn planned_collector_provider(slug: &str) -> Option<&'static str> {
    match slug {
        "github" | "github_audit" => Some("github_audit"),
        "crowdstrike" | "crowdstrike_falcon" => Some("crowdstrike_falcon"),
        "syslog" | "generic_syslog" => Some("generic_syslog"),
        _ => None,
    }
}

pub(crate) fn planned_collector_key(provider: &str) -> Option<&'static str> {
    match provider {
        "github_audit" => Some(GITHUB_COLLECTOR_SETUP_KEY),
        "crowdstrike_falcon" => Some(CROWDSTRIKE_COLLECTOR_SETUP_KEY),
        "generic_syslog" => Some(SYSLOG_COLLECTOR_SETUP_KEY),
        _ => None,
    }
}

pub(crate) fn planned_collector_required_fields(provider: &str) -> &'static [&'static str] {
    match provider {
        "github_audit" => &["organization", "token_ref", "webhook_secret_ref"],
        "crowdstrike_falcon" => &["cloud", "client_id", "client_secret_ref", "customer_id"],
        "generic_syslog" => &["bind", "port", "protocol"],
        _ => &[],
    }
}

pub(crate) fn planned_collector_default_setup(provider: &str) -> serde_json::Value {
    match provider {
        "github_audit" => serde_json::json!({
            "enabled": true,
            "organization": "acme-security",
            "token_ref": "secret://github/audit-token",
            "webhook_secret_ref": "secret://github/webhook-secret",
            "poll_interval_secs": 300,
            "repositories": ["platform", "infra"],
        }),
        "crowdstrike_falcon" => serde_json::json!({
            "enabled": true,
            "cloud": "us-1",
            "client_id": "falcon-client-id",
            "client_secret_ref": "secret://crowdstrike/client-secret",
            "customer_id": "cid-00000000000000000000000000000000",
            "poll_interval_secs": 180,
        }),
        "generic_syslog" => serde_json::json!({
            "enabled": true,
            "bind": "0.0.0.0",
            "port": 5514,
            "protocol": "udp",
            "facility": "local4",
            "parse_profile": "auto",
            "poll_interval_secs": 60,
        }),
        _ => serde_json::json!({"enabled": false, "poll_interval_secs": 300}),
    }
}

pub(crate) fn load_planned_collector_setup(storage: &SharedStorage, provider: &str) -> serde_json::Value {
    let Some(key) = planned_collector_key(provider) else {
        return planned_collector_default_setup(provider);
    };
    let value: serde_json::Value = load_stored_json(storage, key);
    if value.is_object() {
        value
    } else {
        planned_collector_default_setup(provider)
    }
}

pub(crate) fn planned_collector_enabled(setup: &serde_json::Value) -> bool {
    setup
        .get("enabled")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

pub(crate) fn planned_collector_poll_interval(setup: &serde_json::Value) -> u64 {
    setup
        .get("poll_interval_secs")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(300)
        .clamp(30, 86_400)
}

pub(crate) fn planned_collector_validation(provider: &str, setup: &serde_json::Value) -> SetupValidation {
    let enabled = planned_collector_enabled(setup);
    let issues = planned_collector_required_fields(provider)
        .iter()
        .filter(|field| {
            setup.get(**field).is_none_or(|value| match value {
                serde_json::Value::String(text) => text.trim().is_empty(),
                serde_json::Value::Array(items) => items.is_empty(),
                serde_json::Value::Null => true,
                _ => false,
            })
        })
        .map(|field| SetupValidationIssue {
            field: (*field).to_string(),
            level: "error".to_string(),
            message: format!("{field} is required before validation can produce sample events."),
        })
        .collect::<Vec<_>>();
    SetupValidation {
        status: if !enabled {
            "disabled".to_string()
        } else if issues.is_empty() {
            "ready".to_string()
        } else {
            "warning".to_string()
        },
        issues,
    }
}

pub(crate) fn planned_collector_public_view(provider: &str, setup: &serde_json::Value) -> serde_json::Value {
    let mut view = setup.clone();
    if let Some(object) = view.as_object_mut() {
        object.insert("provider".to_string(), serde_json::json!(provider));
        object.insert(
            "required_fields".to_string(),
            serde_json::json!(planned_collector_required_fields(provider)),
        );
        let secret_keys = object
            .keys()
            .filter(|key| {
                let lower = key.to_ascii_lowercase();
                lower.contains("secret") || lower.contains("token")
            })
            .cloned()
            .collect::<Vec<_>>();
        for key in secret_keys {
            let has_value = object
                .get(&key)
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| !value.trim().is_empty());
            object.insert(format!("has_{key}"), serde_json::json!(has_value));
            if has_value {
                object.insert(key, serde_json::json!("********"));
            }
        }
    }
    view
}

pub(crate) fn planned_collector_summary(provider: &str, setup: &serde_json::Value) -> serde_json::Value {
    match provider {
        "github_audit" => serde_json::json!({
            "organization": setup.get("organization").and_then(serde_json::Value::as_str).unwrap_or(""),
            "repository_count": setup.get("repositories").and_then(serde_json::Value::as_array).map(Vec::len).unwrap_or(0),
            "has_token_ref": setup.get("token_ref").and_then(serde_json::Value::as_str).is_some_and(|value| !value.trim().is_empty()),
            "has_webhook_secret_ref": setup.get("webhook_secret_ref").and_then(serde_json::Value::as_str).is_some_and(|value| !value.trim().is_empty()),
        }),
        "crowdstrike_falcon" => serde_json::json!({
            "cloud": setup.get("cloud").and_then(serde_json::Value::as_str).unwrap_or(""),
            "client_id": setup.get("client_id").and_then(serde_json::Value::as_str).unwrap_or(""),
            "customer_id": setup.get("customer_id").and_then(serde_json::Value::as_str).unwrap_or(""),
            "has_client_secret_ref": setup.get("client_secret_ref").and_then(serde_json::Value::as_str).is_some_and(|value| !value.trim().is_empty()),
        }),
        "generic_syslog" => serde_json::json!({
            "bind": setup.get("bind").and_then(serde_json::Value::as_str).unwrap_or("0.0.0.0"),
            "port": setup.get("port").and_then(serde_json::Value::as_u64).unwrap_or(5514),
            "protocol": setup.get("protocol").and_then(serde_json::Value::as_str).unwrap_or("udp"),
            "parse_profile": setup.get("parse_profile").and_then(serde_json::Value::as_str).unwrap_or("auto"),
        }),
        _ => serde_json::json!({}),
    }
}

pub(crate) fn planned_collector_sample_events(
    provider: &str,
    setup: &serde_json::Value,
) -> Vec<serde_json::Value> {
    match provider {
        "github_audit" => vec![
            serde_json::json!({
                "action": "org.audit_log_export",
                "actor": "security-admin",
                "organization": setup.get("organization").and_then(serde_json::Value::as_str).unwrap_or("acme-security"),
                "route": "soc.identity.saas",
            }),
            serde_json::json!({
                "action": "repo.visibility_change",
                "actor": "platform-owner",
                "repository": "platform",
                "route": "supply_chain",
            }),
        ],
        "crowdstrike_falcon" => vec![
            serde_json::json!({
                "event_simple_name": "DetectionSummaryEvent",
                "hostname": "workstation-17",
                "severity": "high",
                "route": "soc.edr",
            }),
            serde_json::json!({
                "event_simple_name": "SensorHeartbeat",
                "customer_id": setup.get("customer_id").and_then(serde_json::Value::as_str).unwrap_or("cid"),
                "route": "fleet.health",
            }),
        ],
        "generic_syslog" => vec![
            serde_json::json!({
                "facility": setup.get("facility").and_then(serde_json::Value::as_str).unwrap_or("local4"),
                "severity": "notice",
                "message": "vpn gateway accepted login for analyst",
                "route": "soc.syslog",
            }),
            serde_json::json!({
                "facility": "authpriv",
                "severity": "warning",
                "message": "sudo authentication failure",
                "route": "ueba.identity",
            }),
        ],
        _ => Vec::new(),
    }
}

pub(crate) fn planned_collector_config_payload(storage: &SharedStorage, provider: &str) -> serde_json::Value {
    let setup = load_planned_collector_setup(storage, provider);
    let validation = planned_collector_validation(provider, &setup);
    serde_json::json!({
        "provider": provider,
        "config": planned_collector_public_view(provider, &setup),
        "validation": validation,
    })
}

pub(crate) fn planned_collector_status_entry(storage: &SharedStorage, provider: &str) -> serde_json::Value {
    let setup = load_planned_collector_setup(storage, provider);
    let validation = planned_collector_validation(provider, &setup);
    collector_status_entry(
        provider,
        planned_collector_enabled(&setup),
        planned_collector_poll_interval(&setup),
        planned_collector_summary(provider, &setup),
        validation,
        load_collector_checkpoint(storage, provider),
        load_collector_lifecycle(storage, provider),
    )
}


// ── Collector setup loaders, checkpoint/SLA analytics, validation & status builders ──

pub(crate) fn load_aws_collector_setup(storage: &SharedStorage) -> AwsCollectorSetup {
    load_stored_json(storage, AWS_COLLECTOR_SETUP_KEY)
}

pub(crate) fn load_azure_collector_setup(storage: &SharedStorage) -> AzureCollectorSetup {
    load_stored_json(storage, AZURE_COLLECTOR_SETUP_KEY)
}

pub(crate) fn load_gcp_collector_setup(storage: &SharedStorage) -> GcpCollectorSetup {
    load_stored_json(storage, GCP_COLLECTOR_SETUP_KEY)
}

pub(crate) fn load_okta_collector_setup(storage: &SharedStorage) -> OktaCollectorSetup {
    load_stored_json(storage, OKTA_COLLECTOR_SETUP_KEY)
}

pub(crate) fn load_entra_collector_setup(storage: &SharedStorage) -> EntraCollectorSetup {
    load_stored_json(storage, ENTRA_COLLECTOR_SETUP_KEY)
}

pub(crate) fn load_m365_collector_setup(storage: &SharedStorage) -> M365CollectorSetup {
    load_stored_json(storage, M365_COLLECTOR_SETUP_KEY)
}

pub(crate) fn load_workspace_collector_setup(storage: &SharedStorage) -> WorkspaceCollectorSetup {
    load_stored_json(storage, WORKSPACE_COLLECTOR_SETUP_KEY)
}

pub(crate) fn collector_checkpoint_key(provider: &str) -> String {
    format!("integrations.collectors.{provider}.checkpoint")
}

pub(crate) fn collector_lifecycle_key(provider: &str) -> String {
    format!("integrations.collectors.{provider}.lifecycle")
}

pub(crate) fn load_collector_checkpoint(storage: &SharedStorage, provider: &str) -> CollectorCheckpoint {
    load_stored_json(storage, &collector_checkpoint_key(provider))
}

pub(crate) fn load_collector_lifecycle(storage: &SharedStorage, provider: &str) -> Vec<serde_json::Value> {
    load_stored_json(storage, &collector_lifecycle_key(provider))
}

pub(crate) fn collector_lifecycle_analytics(history: &[serde_json::Value]) -> serde_json::Value {
    let total_runs = history.len();
    let success_runs = history
        .iter()
        .filter(|entry| entry.get("success").and_then(serde_json::Value::as_bool) == Some(true))
        .count();
    let failure_runs = total_runs.saturating_sub(success_runs);
    let recent_failures = history
        .iter()
        .rev()
        .take_while(|entry| entry.get("success").and_then(serde_json::Value::as_bool) != Some(true))
        .count();
    let events_last_24h = history
        .iter()
        .filter_map(|entry| {
            let recorded_at = entry
                .get("recorded_at")
                .and_then(serde_json::Value::as_str)?;
            let parsed = chrono::DateTime::parse_from_rfc3339(recorded_at).ok()?;
            (chrono::Utc::now().signed_duration_since(parsed.with_timezone(&chrono::Utc))
                <= chrono::Duration::hours(24))
            .then(|| {
                entry
                    .get("event_count")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0)
            })
        })
        .sum::<u64>();
    serde_json::json!({
        "total_runs": total_runs,
        "success_runs": success_runs,
        "failure_runs": failure_runs,
        "success_rate": if total_runs == 0 { 0.0 } else { success_runs as f64 / total_runs as f64 },
        "recent_failure_streak": recent_failures,
        "events_last_24h": events_last_24h,
    })
}

pub(crate) fn collector_sla_target_seconds(poll_interval_secs: u64) -> u64 {
    poll_interval_secs.saturating_mul(3).max(300)
}

pub(crate) fn percentile_u64(values: &[u64], percentile: f64) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let rank = ((sorted.len().saturating_sub(1)) as f64 * percentile).round() as usize;
    sorted
        .get(rank.min(sorted.len().saturating_sub(1)))
        .copied()
}

pub(crate) fn collector_lag_percentiles(
    lifecycle: &[serde_json::Value],
    current_lag_seconds: Option<u64>,
) -> serde_json::Value {
    let mut lags = lifecycle
        .iter()
        .filter_map(|entry| entry.get("lag_seconds").and_then(serde_json::Value::as_u64))
        .collect::<Vec<_>>();
    if let Some(current) = current_lag_seconds {
        lags.push(current);
    }
    serde_json::json!({
        "p50_seconds": percentile_u64(&lags, 0.50),
        "p95_seconds": percentile_u64(&lags, 0.95),
        "p99_seconds": percentile_u64(&lags, 0.99),
        "sample_count": lags.len(),
    })
}

pub(crate) fn collector_ingestion_sla_payload(
    enabled: bool,
    poll_interval_secs: u64,
    lag_seconds: Option<u64>,
    queue_depth: u64,
    lifecycle: &[serde_json::Value],
) -> serde_json::Value {
    let target_seconds = collector_sla_target_seconds(poll_interval_secs);
    let lag_breach = enabled && lag_seconds.is_some_and(|lag| lag > target_seconds);
    let queue_breach = enabled && queue_depth > 0;
    let status = if !enabled {
        "disabled"
    } else if lag_breach || queue_breach {
        "breach"
    } else if lag_seconds.is_some() {
        "met"
    } else {
        "unknown"
    };
    let breach_reasons = [
        lag_breach.then_some("lag_exceeded"),
        queue_breach.then_some("queue_backlog"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    serde_json::json!({
        "status": status,
        "target_lag_seconds": target_seconds,
        "observed_lag_seconds": lag_seconds,
        "queue_depth": queue_depth,
        "breach": lag_breach || queue_breach,
        "breach_reasons": breach_reasons,
        "lag_percentiles": collector_lag_percentiles(lifecycle, lag_seconds),
    })
}

pub(crate) fn collector_sla_summary(collectors: &[serde_json::Value]) -> serde_json::Value {
    let enabled = collectors
        .iter()
        .filter(|item| item.get("enabled").and_then(serde_json::Value::as_bool) == Some(true))
        .count();
    let breaches = collectors
        .iter()
        .filter(|item| {
            item.get("ingestion_sla")
                .and_then(|sla| sla.get("breach"))
                .and_then(serde_json::Value::as_bool)
                == Some(true)
        })
        .count();
    let worst_lag_seconds = collectors
        .iter()
        .filter_map(|item| item.get("lag_seconds").and_then(serde_json::Value::as_u64))
        .max();
    let total_queue_depth = collectors
        .iter()
        .filter_map(|item| item.get("queue_depth").and_then(serde_json::Value::as_u64))
        .sum::<u64>();
    serde_json::json!({
        "status": if breaches == 0 { "met" } else { "breach" },
        "enabled_collectors": enabled,
        "breaching_collectors": breaches,
        "worst_lag_seconds": worst_lag_seconds,
        "total_queue_depth": total_queue_depth,
    })
}

pub(crate) fn classify_collector_error(error: Option<&str>) -> Option<String> {
    let text = error?.trim();
    if text.is_empty() {
        return None;
    }
    let lower = text.to_ascii_lowercase();
    let category = if lower.contains("auth")
        || lower.contains("token")
        || lower.contains("credential")
        || lower.contains("unauthorized")
        || lower.contains("forbidden")
    {
        "authentication"
    } else if lower.contains("timeout") || lower.contains("connect") || lower.contains("dns") {
        "network"
    } else if lower.contains("rate") || lower.contains("429") || lower.contains("throttle") {
        "rate_limit"
    } else if lower.contains("parse") || lower.contains("json") || lower.contains("schema") {
        "parse"
    } else if lower.contains("incomplete") || lower.contains("required") {
        "configuration"
    } else {
        "provider"
    };
    Some(category.to_string())
}

pub(crate) fn checkpoint_lag_seconds(last_success_at: Option<&str>) -> Option<u64> {
    let parsed = chrono::DateTime::parse_from_rfc3339(last_success_at?).ok()?;
    let now = chrono::Utc::now();
    Some(
        now.signed_duration_since(parsed.with_timezone(&chrono::Utc))
            .num_seconds()
            .max(0) as u64,
    )
}

pub(crate) fn record_collector_checkpoint(
    storage: &SharedStorage,
    provider: &str,
    success: bool,
    event_count: u64,
    error: Option<&str>,
) -> CollectorCheckpoint {
    record_collector_checkpoint_with_queue(storage, provider, success, event_count, error, 0)
}

pub(crate) fn record_collector_checkpoint_with_queue(
    storage: &SharedStorage,
    provider: &str,
    success: bool,
    event_count: u64,
    error: Option<&str>,
    queue_depth: u64,
) -> CollectorCheckpoint {
    let now = chrono::Utc::now().to_rfc3339();
    let mut checkpoint = load_collector_checkpoint(storage, provider);
    checkpoint.queue_depth = queue_depth;
    if success {
        checkpoint.last_success_at = Some(now.clone());
        checkpoint.error_category = None;
        checkpoint.retry_count = 0;
        checkpoint.backoff_seconds = 0;
        checkpoint.events_ingested = checkpoint.events_ingested.saturating_add(event_count);
    } else {
        checkpoint.last_error_at = Some(now.clone());
        checkpoint.error_category = classify_collector_error(error);
        checkpoint.retry_count = checkpoint.retry_count.saturating_add(1);
        checkpoint.backoff_seconds = 2_u64.saturating_pow(checkpoint.retry_count.min(6)).min(300);
    }
    checkpoint.lag_seconds = checkpoint_lag_seconds(checkpoint.last_success_at.as_deref());
    checkpoint.checkpoint_id = Some(crate::audit::sha256_hex(
        format!(
            "{}|{}|{}|{}|{}",
            provider, now, success, checkpoint.events_ingested, checkpoint.retry_count
        )
        .as_bytes(),
    ));
    let _ = save_stored_json(storage, &collector_checkpoint_key(provider), &checkpoint);
    let mut lifecycle = load_collector_lifecycle(storage, provider);
    lifecycle.push(serde_json::json!({
        "provider": provider,
        "recorded_at": now,
        "success": success,
        "event_count": event_count,
        "total_events_ingested": checkpoint.events_ingested,
        "last_success_at": checkpoint.last_success_at.clone(),
        "last_error_at": checkpoint.last_error_at.clone(),
        "error_category": checkpoint.error_category.clone(),
        "error": error.unwrap_or(""),
        "queue_depth": checkpoint.queue_depth,
        "retry_count": checkpoint.retry_count,
        "backoff_seconds": checkpoint.backoff_seconds,
        "lag_seconds": checkpoint.lag_seconds,
        "checkpoint_id": checkpoint.checkpoint_id.clone(),
    }));
    if lifecycle.len() > 40 {
        let overflow = lifecycle.len() - 40;
        lifecycle.drain(0..overflow);
    }
    let _ = save_stored_json(storage, &collector_lifecycle_key(provider), &lifecycle);
    checkpoint
}

pub(crate) fn collector_validation_response(
    storage: &SharedStorage,
    provider: &str,
    mut body: serde_json::Value,
) -> Response<Body> {
    let success = body
        .get("success")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let event_count = body
        .get("event_count")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let error = body.get("error").and_then(serde_json::Value::as_str);
    let queue_depth = body
        .get("queue_depth")
        .or_else(|| body.get("pending_queue_depth"))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let checkpoint = record_collector_checkpoint_with_queue(
        storage,
        provider,
        success,
        event_count,
        error,
        queue_depth,
    );
    if let Some(object) = body.as_object_mut() {
        object.insert(
            "reliability".to_string(),
            serde_json::to_value(checkpoint).unwrap_or_else(|_| serde_json::json!({})),
        );
    }
    json_response(&body.to_string(), 200)
}

pub(crate) fn build_secrets_resolver(storage: &SharedStorage) -> crate::secrets::SecretsResolver {
    let setup = load_secrets_manager_setup(storage);
    crate::secrets::SecretsResolver::new(setup.to_runtime())
}

pub(crate) fn config_validation_payload<T>(config: T, validation: SetupValidation) -> serde_json::Value
where
    T: serde::Serialize,
{
    serde_json::json!({
        "config": config,
        "validation": validation,
    })
}

pub(crate) fn validate_okta_collector(
    setup: &OktaCollectorSetup,
    resolver: &crate::secrets::SecretsResolver,
) -> serde_json::Value {
    let validation = setup.validate();
    if validation.status != "ready" {
        return serde_json::json!({
            "provider": "okta_identity",
            "success": false,
            "event_count": 0,
            "sample_events": [],
            "summary": {},
            "validation": validation,
            "error": "Collector configuration is incomplete.",
        });
    }

    match setup.to_runtime(resolver) {
        Ok(runtime) => {
            let mut collector = crate::collector_identity::OktaCollector::new(runtime);
            let request_url = collector.build_url();
            match ureq::get(&request_url)
                .set("Authorization", &collector.auth_header())
                .call()
            {
                Ok(response) => {
                    let next_link = response.header("Link").map(|value| value.to_string());
                    match response.into_string() {
                        Ok(body) => {
                            let result = collector.parse_response(&body, next_link.as_deref());
                            let sample_events: Vec<_> =
                                result.events.iter().take(5).cloned().collect();
                            serde_json::json!({
                                "provider": "okta_identity",
                                "success": result.success,
                                "event_count": result.event_count,
                                "polled_at": result.polled_at,
                                "sample_events": sample_events,
                                "summary": crate::collector_identity::identity_summary(&result.events),
                                "validation": validation,
                                "error": result.error,
                            })
                        }
                        Err(error) => serde_json::json!({
                            "provider": "okta_identity",
                            "success": false,
                            "event_count": 0,
                            "sample_events": [],
                            "summary": {},
                            "validation": validation,
                            "error": format!("failed to read Okta response body: {error}"),
                        }),
                    }
                }
                Err(error) => serde_json::json!({
                    "provider": "okta_identity",
                    "success": false,
                    "event_count": 0,
                    "sample_events": [],
                    "summary": {},
                    "validation": validation,
                    "error": format!("Okta validation request failed: {error}"),
                }),
            }
        }
        Err(error) => serde_json::json!({
            "provider": "okta_identity",
            "success": false,
            "event_count": 0,
            "sample_events": [],
            "summary": {},
            "validation": validation,
            "error": error,
        }),
    }
}

pub(crate) fn validate_entra_collector(
    setup: &EntraCollectorSetup,
    resolver: &crate::secrets::SecretsResolver,
) -> serde_json::Value {
    let validation = setup.validate();
    if validation.status != "ready" {
        return serde_json::json!({
            "provider": "entra_identity",
            "success": false,
            "event_count": 0,
            "sample_events": [],
            "summary": {},
            "validation": validation,
            "error": "Collector configuration is incomplete.",
        });
    }

    match setup.to_runtime(resolver) {
        Ok(runtime) => {
            let token_form = format!(
                "grant_type=client_credentials&client_id={}&client_secret={}&scope={}",
                encode_query_component(&runtime.client_id),
                encode_query_component(&runtime.client_secret),
                encode_query_component("https://graph.microsoft.com/.default"),
            );
            let mut collector = crate::collector_identity::EntraCollector::new(runtime);
            let token_endpoint = collector.token_endpoint();
            match ureq::post(&token_endpoint)
                .set("Content-Type", "application/x-www-form-urlencoded")
                .send_string(&token_form)
            {
                Ok(response) => {
                    let token_body: serde_json::Value = match response.into_json() {
                        Ok(body) => body,
                        Err(error) => {
                            return serde_json::json!({
                                "provider": "entra_identity",
                                "success": false,
                                "event_count": 0,
                                "sample_events": [],
                                "summary": {},
                                "validation": validation,
                                "error": format!("failed to parse Entra token response: {error}"),
                            });
                        }
                    };
                    let Some(access_token) = token_body
                        .get("access_token")
                        .and_then(|value| value.as_str())
                    else {
                        return serde_json::json!({
                            "provider": "entra_identity",
                            "success": false,
                            "event_count": 0,
                            "sample_events": [],
                            "summary": {},
                            "validation": validation,
                            "error": "Entra token response did not include an access token.",
                        });
                    };
                    collector.set_token(
                        access_token,
                        token_body
                            .get("expires_in")
                            .and_then(|value| value.as_u64())
                            .unwrap_or(3600),
                    );
                    let request_url = collector.build_url();
                    match ureq::get(&request_url)
                        .set("Authorization", &format!("Bearer {access_token}"))
                        .call()
                    {
                        Ok(response) => match response.into_string() {
                            Ok(body) => {
                                let result = collector.parse_response(&body);
                                let sample_events: Vec<_> =
                                    result.events.iter().take(5).cloned().collect();
                                serde_json::json!({
                                    "provider": "entra_identity",
                                    "success": result.success,
                                    "event_count": result.event_count,
                                    "polled_at": result.polled_at,
                                    "sample_events": sample_events,
                                    "summary": crate::collector_identity::identity_summary(&result.events),
                                    "validation": validation,
                                    "error": result.error,
                                })
                            }
                            Err(error) => serde_json::json!({
                                "provider": "entra_identity",
                                "success": false,
                                "event_count": 0,
                                "sample_events": [],
                                "summary": {},
                                "validation": validation,
                                "error": format!("failed to read Entra response body: {error}"),
                            }),
                        },
                        Err(error) => serde_json::json!({
                            "provider": "entra_identity",
                            "success": false,
                            "event_count": 0,
                            "sample_events": [],
                            "summary": {},
                            "validation": validation,
                            "error": format!("Entra validation request failed: {error}"),
                        }),
                    }
                }
                Err(error) => serde_json::json!({
                    "provider": "entra_identity",
                    "success": false,
                    "event_count": 0,
                    "sample_events": [],
                    "summary": {},
                    "validation": validation,
                    "error": format!("Entra token request failed: {error}"),
                }),
            }
        }
        Err(error) => serde_json::json!({
            "provider": "entra_identity",
            "success": false,
            "event_count": 0,
            "sample_events": [],
            "summary": {},
            "validation": validation,
            "error": error,
        }),
    }
}

pub(crate) fn validate_m365_collector(
    setup: &M365CollectorSetup,
    resolver: &crate::secrets::SecretsResolver,
) -> serde_json::Value {
    let validation = setup.validate();
    if validation.status != "ready" {
        return serde_json::json!({
            "provider": "m365_saas",
            "success": false,
            "event_count": 0,
            "sample_events": [],
            "summary": {},
            "validation": validation,
            "error": "Collector configuration is incomplete.",
        });
    }

    let tenant_id = match resolver.resolve(&setup.tenant_id) {
        Ok(value) => value,
        Err(error) => {
            return serde_json::json!({
                "provider": "m365_saas",
                "success": false,
                "event_count": 0,
                "sample_events": [],
                "summary": {},
                "validation": validation,
                "error": error,
            });
        }
    };
    let client_id = match resolver.resolve(&setup.client_id) {
        Ok(value) => value,
        Err(error) => {
            return serde_json::json!({
                "provider": "m365_saas",
                "success": false,
                "event_count": 0,
                "sample_events": [],
                "summary": {},
                "validation": validation,
                "error": error,
            });
        }
    };
    if let Err(error) = resolver.resolve(&setup.client_secret) {
        return serde_json::json!({
            "provider": "m365_saas",
            "success": false,
            "event_count": 0,
            "sample_events": [],
            "summary": {},
            "validation": validation,
            "error": error,
        });
    }

    let sample_events = setup
        .content_types
        .iter()
        .take(3)
        .enumerate()
        .map(|(index, content_type)| {
            serde_json::json!({
                "content_type": content_type,
                "tenant_id": tenant_id,
                "workload": content_type.split('.').nth(1).unwrap_or(content_type),
                "sample_operation": match index {
                    0 => "UserLoggedIn",
                    1 => "MailboxLogin",
                    _ => "FileAccessed",
                },
                "ingest_status": "shadow-ready",
            })
        })
        .collect::<Vec<_>>();

    serde_json::json!({
        "provider": "m365_saas",
        "success": true,
        "event_count": sample_events.len(),
        "sample_events": sample_events,
        "summary": {
            "tenant_id": tenant_id,
            "client_id": client_id,
            "content_types": setup.content_types,
            "recommended_pivots": ["soc", "ueba", "assistant"],
        },
        "validation": validation,
        "error": serde_json::Value::Null,
    })
}

pub(crate) fn validate_workspace_collector(
    setup: &WorkspaceCollectorSetup,
    resolver: &crate::secrets::SecretsResolver,
) -> serde_json::Value {
    let validation = setup.validate();
    if validation.status != "ready" {
        return serde_json::json!({
            "provider": "workspace_saas",
            "success": false,
            "event_count": 0,
            "sample_events": [],
            "summary": {},
            "validation": validation,
            "error": "Collector configuration is incomplete.",
        });
    }

    let customer_id = match resolver.resolve(&setup.customer_id) {
        Ok(value) => value,
        Err(error) => {
            return serde_json::json!({
                "provider": "workspace_saas",
                "success": false,
                "event_count": 0,
                "sample_events": [],
                "summary": {},
                "validation": validation,
                "error": error,
            });
        }
    };
    let delegated_admin_email = match resolver.resolve(&setup.delegated_admin_email) {
        Ok(value) => value,
        Err(error) => {
            return serde_json::json!({
                "provider": "workspace_saas",
                "success": false,
                "event_count": 0,
                "sample_events": [],
                "summary": {},
                "validation": validation,
                "error": error,
            });
        }
    };
    let service_account_email = match resolver.resolve(&setup.service_account_email) {
        Ok(value) => value,
        Err(error) => {
            return serde_json::json!({
                "provider": "workspace_saas",
                "success": false,
                "event_count": 0,
                "sample_events": [],
                "summary": {},
                "validation": validation,
                "error": error,
            });
        }
    };
    if let Err(error) = resolver.resolve(&setup.credentials_json) {
        return serde_json::json!({
            "provider": "workspace_saas",
            "success": false,
            "event_count": 0,
            "sample_events": [],
            "summary": {},
            "validation": validation,
            "error": error,
        });
    }

    let sample_events = setup
        .applications
        .iter()
        .take(3)
        .enumerate()
        .map(|(index, application)| {
            serde_json::json!({
                "application": application,
                "customer_id": customer_id,
                "actor_email": delegated_admin_email,
                "service_account_email": service_account_email,
                "sample_event": match index {
                    0 => "login_success",
                    1 => "admin_role_assignment",
                    _ => "drive_file_visibility_change",
                },
                "ingest_status": "shadow-ready",
            })
        })
        .collect::<Vec<_>>();

    serde_json::json!({
        "provider": "workspace_saas",
        "success": true,
        "event_count": sample_events.len(),
        "sample_events": sample_events,
        "summary": {
            "customer_id": customer_id,
            "delegated_admin_email": delegated_admin_email,
            "applications": setup.applications,
            "recommended_pivots": ["soc", "ueba", "infrastructure"],
        },
        "validation": validation,
        "error": serde_json::Value::Null,
    })
}

pub(crate) fn collector_lane(name: &str) -> &'static str {
    let normalized = name.to_ascii_lowercase();
    if normalized.contains("okta") || normalized.contains("entra") {
        "identity"
    } else if normalized.contains("m365")
        || normalized.contains("workspace")
        || normalized.contains("github")
    {
        "saas"
    } else if normalized.contains("crowdstrike") {
        "edr"
    } else if normalized.contains("syslog") {
        "network"
    } else {
        "cloud"
    }
}

pub(crate) fn collector_display_label(name: &str) -> &'static str {
    match name {
        "aws_cloudtrail" => "AWS CloudTrail",
        "azure_activity" => "Azure Activity",
        "gcp_audit" => "GCP Audit",
        "okta_identity" => "Okta Identity",
        "entra_identity" => "Microsoft Entra Identity",
        "m365_saas" => "Microsoft 365 Activity",
        "workspace_saas" => "Google Workspace Activity",
        "github_audit" => "GitHub Audit Log",
        "crowdstrike_falcon" => "CrowdStrike Falcon",
        "generic_syslog" => "Generic Syslog",
        _ => "Collector",
    }
}

pub(crate) fn collector_route_targets(name: &str) -> &'static [&'static str] {
    match collector_lane(name) {
        "identity" => &["SOC Queue", "UEBA"],
        "saas" => &["Assistant", "Reports"],
        "edr" => &["SOC Queue", "Live Response"],
        "network" => &["SOC Queue", "Network Detection"],
        _ => &["Infrastructure", "Attack Graph"],
    }
}

pub(crate) fn collector_scope_markers(summary: &serde_json::Value) -> Vec<String> {
    let Some(summary) = summary.as_object() else {
        return Vec::new();
    };

    let mut markers = Vec::new();
    for (key, value) in summary {
        if key.starts_with("has_") {
            continue;
        }

        let label = key.replace('_', " ");
        match value {
            serde_json::Value::String(text) if !text.trim().is_empty() => {
                markers.push(format!("{label}: {text}"));
            }
            serde_json::Value::Number(number) => {
                if let Some(value) = number.as_u64()
                    && value > 0
                {
                    markers.push(format!("{value} {label}"));
                }
            }
            serde_json::Value::Array(items) if !items.is_empty() => {
                markers.push(format!("{} {label}", items.len()));
            }
            _ => {}
        }
    }
    markers.truncate(3);
    markers
}

pub(crate) fn collector_credential_timeline(
    summary: &serde_json::Value,
    validation: &SetupValidation,
) -> (String, String, String) {
    let Some(summary) = summary.as_object() else {
        return (
            validation.status.clone(),
            "Credential coverage".to_string(),
            "No credential state is currently published for this collector.".to_string(),
        );
    };

    let secret_flags = summary
        .iter()
        .filter_map(|(key, value)| {
            key.starts_with("has_")
                .then(|| value.as_bool().map(|present| (key, present)))
                .flatten()
        })
        .collect::<Vec<_>>();

    if secret_flags.is_empty() {
        return (
            validation.status.clone(),
            "Credential coverage".to_string(),
            "Identifiers are present; no separate stored-secret marker is published for this collector."
                .to_string(),
        );
    }

    let missing = secret_flags
        .iter()
        .filter(|(_, present)| !*present)
        .map(|(key, _)| key.trim_start_matches("has_").replace('_', " "))
        .collect::<Vec<_>>();

    if missing.is_empty() {
        (
            "ready".to_string(),
            "Credential coverage".to_string(),
            "Stored credential material is present for the configured collector path.".to_string(),
        )
    } else {
        (
            "warning".to_string(),
            "Credential coverage".to_string(),
            format!("Review missing credential markers: {}.", missing.join(", ")),
        )
    }
}

pub(crate) fn build_collector_timeline(
    name: &str,
    enabled: bool,
    poll_interval_secs: u64,
    summary: &serde_json::Value,
    validation: &SetupValidation,
) -> Vec<serde_json::Value> {
    let route_targets = collector_route_targets(name).join(" • ");
    let scope_markers = collector_scope_markers(summary);
    let (credential_status, credential_title, credential_detail) =
        collector_credential_timeline(summary, validation);
    let validation_detail = if validation.issues.is_empty() {
        "Collector configuration currently passes setup validation.".to_string()
    } else {
        validation
            .issues
            .iter()
            .take(2)
            .map(|issue| issue.message.clone())
            .collect::<Vec<_>>()
            .join(" • ")
    };

    vec![
        serde_json::json!({
            "stage": "Configuration",
            "status": if enabled { "ready" } else { "disabled" },
            "title": if enabled { "Collector enabled" } else { "Collector disabled" },
            "detail": if enabled {
                format!("{} is configured with a {} second polling cadence.", collector_display_label(name), poll_interval_secs)
            } else {
                "Enable this collector before expecting validation or downstream routing signals.".to_string()
            },
        }),
        serde_json::json!({
            "stage": "Credentials",
            "status": credential_status,
            "title": credential_title,
            "detail": credential_detail,
        }),
        serde_json::json!({
            "stage": "Scope",
            "status": if enabled && !scope_markers.is_empty() { "ready" } else if enabled { validation.status.as_str() } else { "disabled" },
            "title": "Collection scope",
            "detail": if scope_markers.is_empty() {
                "No explicit scope markers are configured yet for this collector.".to_string()
            } else {
                scope_markers.join(" • ")
            },
        }),
        serde_json::json!({
            "stage": "Validation",
            "status": validation.status,
            "title": if validation.status == "ready" { "Validation clear" } else { "Validation review" },
            "detail": validation_detail,
        }),
        serde_json::json!({
            "stage": "Routing",
            "status": if enabled { "ready" } else { "disabled" },
            "title": "Downstream pivots",
            "detail": format!("This collector currently routes into: {route_targets}."),
        }),
    ]
}

pub(crate) fn collector_status_entry(
    name: &str,
    enabled: bool,
    poll_interval_secs: u64,
    summary: serde_json::Value,
    validation: SetupValidation,
    reliability: CollectorCheckpoint,
    lifecycle: Vec<serde_json::Value>,
) -> serde_json::Value {
    let lag_seconds =
        checkpoint_lag_seconds(reliability.last_success_at.as_deref()).or(reliability.lag_seconds);
    let lifecycle_analytics = collector_lifecycle_analytics(&lifecycle);
    let queue_depth = reliability.queue_depth.max(if reliability.retry_count > 0 {
        reliability.retry_count as u64
    } else {
        0
    });
    let ingestion_sla = collector_ingestion_sla_payload(
        enabled,
        poll_interval_secs,
        lag_seconds,
        queue_depth,
        &lifecycle,
    );
    let ingestion_evidence = serde_json::json!({
        "provider": name,
        "checkpoint_id": reliability.checkpoint_id,
        "events_ingested": reliability.events_ingested,
        "last_success_at": reliability.last_success_at,
        "last_error_at": reliability.last_error_at,
        "queue_depth": queue_depth,
        "sla": ingestion_sla.clone(),
        "freshness": if !enabled {
            "disabled"
        } else if reliability.last_success_at.is_none() && reliability.last_error_at.is_some() {
            "error"
        } else if lag_seconds.is_some_and(|lag| lag > poll_interval_secs.saturating_mul(3).max(300)) {
            "stale"
        } else if reliability.last_success_at.is_some() {
            "fresh"
        } else {
            "unknown"
        },
        "pivots": [
            {"surface": "SOC Workbench", "href": format!("/soc?collector={name}&lane={}", collector_lane(name)), "label": "Open SOC collector context"},
            {"surface": "Infrastructure", "href": format!("/infrastructure?tab=observability&collector={name}"), "label": "Open infrastructure evidence"}
        ],
    });
    serde_json::json!({
        "name": name,
        "provider": name,
        "label": collector_display_label(name),
        "lane": collector_lane(name),
        "enabled": enabled,
        "poll_interval_secs": poll_interval_secs,
        "total_collected": reliability.events_ingested,
        "last_success_at": reliability.last_success_at,
        "last_error_at": reliability.last_error_at,
        "error_category": reliability.error_category,
        "events_ingested": reliability.events_ingested,
        "lag_seconds": lag_seconds,
        "queue_depth": queue_depth,
        "checkpoint_id": reliability.checkpoint_id,
        "retry_count": reliability.retry_count,
        "backoff_seconds": reliability.backoff_seconds,
        "ingestion_sla": ingestion_sla,
        "freshness": if !enabled {
            "disabled"
        } else if reliability.last_success_at.is_none() && reliability.last_error_at.is_some() {
            "error"
        } else if lag_seconds.is_some_and(|lag| lag > poll_interval_secs.saturating_mul(3).max(300)) {
            "stale"
        } else if reliability.last_success_at.is_some() {
            "fresh"
        } else {
            "unknown"
        },
        "route_targets": collector_route_targets(name),
        "ingestion_evidence": ingestion_evidence,
        "lifecycle": lifecycle.iter().rev().take(8).cloned().collect::<Vec<_>>(),
        "lifecycle_analytics": lifecycle_analytics,
        "summary": summary,
        "validation": validation,
        "timeline": build_collector_timeline(name, enabled, poll_interval_secs, &summary, &validation),
    })
}

pub(crate) fn full_collector_status_entries(state: &AppState) -> Vec<serde_json::Value> {
    let aws = load_aws_collector_setup(&state.storage);
    let azure = load_azure_collector_setup(&state.storage);
    let gcp = load_gcp_collector_setup(&state.storage);
    let okta = load_okta_collector_setup(&state.storage);
    let entra = load_entra_collector_setup(&state.storage);
    let m365 = load_m365_collector_setup(&state.storage);
    let workspace = load_workspace_collector_setup(&state.storage);
    let aws_validation = aws.validate();
    let azure_validation = azure.validate();
    let gcp_validation = gcp.validate();
    let okta_validation = okta.validate();
    let entra_validation = entra.validate();
    let m365_validation = m365.validate();
    let workspace_validation = workspace.validate();

    vec![
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
            load_collector_checkpoint(&state.storage, "aws_cloudtrail"),
            load_collector_lifecycle(&state.storage, "aws_cloudtrail"),
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
            load_collector_checkpoint(&state.storage, "azure_activity"),
            load_collector_lifecycle(&state.storage, "azure_activity"),
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
            load_collector_checkpoint(&state.storage, "gcp_audit"),
            load_collector_lifecycle(&state.storage, "gcp_audit"),
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
            load_collector_checkpoint(&state.storage, "okta_identity"),
            load_collector_lifecycle(&state.storage, "okta_identity"),
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
            load_collector_checkpoint(&state.storage, "entra_identity"),
            load_collector_lifecycle(&state.storage, "entra_identity"),
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
            load_collector_checkpoint(&state.storage, "m365_saas"),
            load_collector_lifecycle(&state.storage, "m365_saas"),
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
            load_collector_checkpoint(&state.storage, "workspace_saas"),
            load_collector_lifecycle(&state.storage, "workspace_saas"),
        ),
        crate::server_collectors::planned_collector_status_entry(&state.storage, "github_audit"),
        crate::server_collectors::planned_collector_status_entry(&state.storage, "crowdstrike_falcon"),
        crate::server_collectors::planned_collector_status_entry(&state.storage, "generic_syslog"),
    ]
}

pub(crate) fn collector_readiness_summary(state: &AppState) -> serde_json::Value {
    let collectors = full_collector_status_entries(state);
    serde_json::json!({
        "enabled": collectors.iter().filter(|item| item.get("enabled").and_then(serde_json::Value::as_bool) == Some(true)).count(),
        "configured": collectors.len(),
        "ingestion_sla": collector_sla_summary(&collectors),
        "collectors": collectors,
    })
}

