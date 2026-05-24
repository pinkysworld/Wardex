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
use crate::integration_setup::{SetupValidation, SetupValidationIssue};
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

