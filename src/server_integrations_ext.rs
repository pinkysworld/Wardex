//! HTTP handlers for the threat-intel enrichment, ticketing, and OTLP
//! export integrations. Follows the storage/secrets pattern already used by
//! the cloud/identity collectors in `server_collectors.rs`: config is
//! persisted as JSON under a storage key, secret-bearing fields are resolved
//! through `SecretsResolver` only at call time, and validation/lookup
//! endpoints degrade gracefully (return a JSON error, never panic) when a
//! provider isn't configured.

use super::*;

use crate::storage::SharedStorage;
use crate::threat_intel_enrich::{EnrichmentConfig, EnrichmentService, IndicatorKind};
use crate::ticketing::{JiraClient, JiraConfig, RemoteTicket, ServiceNowClient, ServiceNowConfig};

const ENRICHMENT_CONFIG_KEY: &str = "integrations.enrichment.config";
const JIRA_TICKETING_CONFIG_KEY: &str = "integrations.ticketing.jira";
const SERVICENOW_TICKETING_CONFIG_KEY: &str = "integrations.ticketing.servicenow";
const OTLP_EXPORT_CONFIG_KEY: &str = "integrations.telemetry.otlp";

// ── Threat-intel enrichment (VirusTotal / AbuseIPDB) ────────────────────────

fn load_enrichment_config(storage: &SharedStorage) -> EnrichmentConfig {
    load_stored_json(storage, ENRICHMENT_CONFIG_KEY)
}

fn enrichment_config_view(cfg: &EnrichmentConfig) -> serde_json::Value {
    serde_json::json!({
        "virustotal": {
            "enabled": cfg.virustotal.enabled,
            "requests_per_minute": cfg.virustotal.requests_per_minute,
            "cache_ttl_secs": cfg.virustotal.cache_ttl_secs,
            "timeout_secs": cfg.virustotal.timeout_secs,
            "base_url": cfg.virustotal.base_url,
            "has_api_key": !cfg.virustotal.api_key.trim().is_empty(),
        },
        "abuseipdb": {
            "enabled": cfg.abuseipdb.enabled,
            "requests_per_minute": cfg.abuseipdb.requests_per_minute,
            "cache_ttl_secs": cfg.abuseipdb.cache_ttl_secs,
            "timeout_secs": cfg.abuseipdb.timeout_secs,
            "max_age_days": cfg.abuseipdb.max_age_days,
            "base_url": cfg.abuseipdb.base_url,
            "has_api_key": !cfg.abuseipdb.api_key.trim().is_empty(),
        },
    })
}

pub(crate) fn handle_enrichment_config_get(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let cfg = load_enrichment_config(&s.storage);
    json_response(&enrichment_config_view(&cfg).to_string(), 200)
}

#[derive(Debug, serde::Deserialize)]
struct EnrichmentConfigPatch {
    #[serde(default)]
    virustotal: Option<VirusTotalPatch>,
    #[serde(default)]
    abuseipdb: Option<AbuseIpDbPatch>,
}

#[derive(Debug, serde::Deserialize)]
struct VirusTotalPatch {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    api_key: Option<String>,
    #[serde(default)]
    requests_per_minute: Option<u32>,
    #[serde(default)]
    cache_ttl_secs: Option<u64>,
    #[serde(default)]
    timeout_secs: Option<u64>,
    #[serde(default)]
    base_url: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct AbuseIpDbPatch {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    api_key: Option<String>,
    #[serde(default)]
    requests_per_minute: Option<u32>,
    #[serde(default)]
    cache_ttl_secs: Option<u64>,
    #[serde(default)]
    timeout_secs: Option<u64>,
    #[serde(default)]
    max_age_days: Option<u32>,
    #[serde(default)]
    base_url: Option<String>,
}

pub(crate) fn handle_enrichment_config_post(
    body: &[u8],
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    match read_json_body::<EnrichmentConfigPatch>(body, 16 * 1024) {
        Ok(patch) => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut cfg = load_enrichment_config(&s.storage);
            if let Some(vt) = patch.virustotal {
                if let Some(v) = vt.enabled {
                    cfg.virustotal.enabled = v;
                }
                if let Some(v) = vt.api_key
                    && !v.trim().is_empty()
                {
                    cfg.virustotal.api_key = v;
                }
                if let Some(v) = vt.requests_per_minute {
                    cfg.virustotal.requests_per_minute = v;
                }
                if let Some(v) = vt.cache_ttl_secs {
                    cfg.virustotal.cache_ttl_secs = v;
                }
                if let Some(v) = vt.timeout_secs {
                    cfg.virustotal.timeout_secs = v;
                }
                if let Some(v) = vt.base_url
                    && !v.trim().is_empty()
                {
                    cfg.virustotal.base_url = v;
                }
            }
            if let Some(ab) = patch.abuseipdb {
                if let Some(v) = ab.enabled {
                    cfg.abuseipdb.enabled = v;
                }
                if let Some(v) = ab.api_key
                    && !v.trim().is_empty()
                {
                    cfg.abuseipdb.api_key = v;
                }
                if let Some(v) = ab.requests_per_minute {
                    cfg.abuseipdb.requests_per_minute = v;
                }
                if let Some(v) = ab.cache_ttl_secs {
                    cfg.abuseipdb.cache_ttl_secs = v;
                }
                if let Some(v) = ab.timeout_secs {
                    cfg.abuseipdb.timeout_secs = v;
                }
                if let Some(v) = ab.max_age_days {
                    cfg.abuseipdb.max_age_days = v;
                }
                if let Some(v) = ab.base_url
                    && !v.trim().is_empty()
                {
                    cfg.abuseipdb.base_url = v;
                }
            }
            match save_stored_json(&s.storage, ENRICHMENT_CONFIG_KEY, &cfg) {
                Ok(()) => json_response(
                    &serde_json::json!({
                        "status": "saved",
                        "config": enrichment_config_view(&cfg),
                    })
                    .to_string(),
                    200,
                ),
                Err(error) => error_json(&error, 500),
            }
        }
        Err(error) => error_json(&error, 400),
    }
}

#[derive(Debug, serde::Deserialize)]
struct EnrichLookupRequest {
    kind: String,
    indicator: String,
}

fn parse_indicator_kind(kind: &str) -> Option<IndicatorKind> {
    match kind {
        "file_hash" | "hash" => Some(IndicatorKind::FileHash),
        "ip_address" | "ip" => Some(IndicatorKind::IpAddress),
        "domain" => Some(IndicatorKind::Domain),
        "url" => Some(IndicatorKind::Url),
        _ => None,
    }
}

/// POST /api/enrich/lookup — authenticated on-demand IOC enrichment against
/// whichever of VirusTotal/AbuseIPDB are configured and enabled.
pub(crate) fn handle_enrich_lookup(body: &[u8], state: &Arc<Mutex<AppState>>) -> Response<Body> {
    match read_json_body::<EnrichLookupRequest>(body, 4 * 1024) {
        Ok(req) => {
            let Some(kind) = parse_indicator_kind(&req.kind) else {
                return error_json(
                    "invalid 'kind': expected file_hash, ip_address, domain, or url",
                    400,
                );
            };
            if req.indicator.trim().is_empty() {
                return error_json("'indicator' must not be empty", 400);
            }
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut cfg = load_enrichment_config(&s.storage);
            let resolver = build_secrets_resolver_ext(&s.storage);
            // Resolve secret references (env/file/vault) for the API keys,
            // same mechanism the cloud collectors use for their credentials.
            if cfg.virustotal.enabled {
                cfg.virustotal.api_key = resolver
                    .resolve(&cfg.virustotal.api_key)
                    .unwrap_or_default();
            }
            if cfg.abuseipdb.enabled {
                cfg.abuseipdb.api_key =
                    resolver.resolve(&cfg.abuseipdb.api_key).unwrap_or_default();
            }
            let service = EnrichmentService::new(cfg);
            if !service.any_enabled() {
                return error_json(
                    "no enrichment provider is enabled; configure VirusTotal and/or AbuseIPDB at POST /api/integrations/enrichment",
                    409,
                );
            }
            let results = service.enrich(kind, &req.indicator);
            json_response(
                &serde_json::json!({
                    "indicator": req.indicator,
                    "kind": req.kind,
                    "results": results,
                })
                .to_string(),
                200,
            )
        }
        Err(error) => error_json(&error, 400),
    }
}

fn build_secrets_resolver_ext(storage: &SharedStorage) -> crate::secrets::SecretsResolver {
    crate::server_collectors::build_secrets_resolver(storage)
}

// ── Ticketing (Jira / ServiceNow) ────────────────────────────────────────────

fn load_jira_config(storage: &SharedStorage) -> JiraConfig {
    load_stored_json(storage, JIRA_TICKETING_CONFIG_KEY)
}

fn load_servicenow_config(storage: &SharedStorage) -> ServiceNowConfig {
    load_stored_json(storage, SERVICENOW_TICKETING_CONFIG_KEY)
}

pub(crate) fn handle_ticketing_jira_get(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let cfg = load_jira_config(&s.storage);
    json_response(
        &serde_json::json!({
            "base_url": cfg.base_url,
            "project_key": cfg.project_key,
            "issue_type": cfg.issue_type,
            "email": cfg.email,
            "timeout_secs": cfg.timeout_secs,
            "enabled": cfg.enabled,
            "has_api_token": !cfg.api_token.trim().is_empty(),
        })
        .to_string(),
        200,
    )
}

pub(crate) fn handle_ticketing_jira_post(
    body: &[u8],
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    match read_json_body::<serde_json::Value>(body, 8 * 1024) {
        Ok(patch) => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut cfg = load_jira_config(&s.storage);
            if let Some(v) = patch.get("base_url").and_then(|v| v.as_str()) {
                cfg.base_url = v.to_string();
            }
            if let Some(v) = patch.get("project_key").and_then(|v| v.as_str()) {
                cfg.project_key = v.to_string();
            }
            if let Some(v) = patch.get("issue_type").and_then(|v| v.as_str()) {
                cfg.issue_type = v.to_string();
            }
            if let Some(v) = patch.get("email").and_then(|v| v.as_str()) {
                cfg.email = v.to_string();
            }
            if let Some(v) = patch.get("api_token").and_then(|v| v.as_str())
                && !v.trim().is_empty()
            {
                cfg.api_token = v.to_string();
            }
            if let Some(v) = patch
                .get("timeout_secs")
                .and_then(serde_json::Value::as_u64)
            {
                cfg.timeout_secs = v;
            }
            if let Some(v) = patch.get("enabled").and_then(serde_json::Value::as_bool) {
                cfg.enabled = v;
            }
            match save_stored_json(&s.storage, JIRA_TICKETING_CONFIG_KEY, &cfg) {
                Ok(()) => json_response(r#"{"status":"saved"}"#, 200),
                Err(error) => error_json(&error, 500),
            }
        }
        Err(error) => error_json(&error, 400),
    }
}

pub(crate) fn handle_ticketing_servicenow_get(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let cfg = load_servicenow_config(&s.storage);
    json_response(
        &serde_json::json!({
            "instance_url": cfg.instance_url,
            "table": cfg.table,
            "username": cfg.username,
            "timeout_secs": cfg.timeout_secs,
            "enabled": cfg.enabled,
            "has_password": !cfg.password.trim().is_empty(),
            "has_oauth_token": !cfg.oauth_token.trim().is_empty(),
        })
        .to_string(),
        200,
    )
}

pub(crate) fn handle_ticketing_servicenow_post(
    body: &[u8],
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    match read_json_body::<serde_json::Value>(body, 8 * 1024) {
        Ok(patch) => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut cfg = load_servicenow_config(&s.storage);
            if let Some(v) = patch.get("instance_url").and_then(|v| v.as_str()) {
                cfg.instance_url = v.to_string();
            }
            if let Some(v) = patch.get("table").and_then(|v| v.as_str()) {
                cfg.table = v.to_string();
            }
            if let Some(v) = patch.get("username").and_then(|v| v.as_str()) {
                cfg.username = v.to_string();
            }
            if let Some(v) = patch.get("password").and_then(|v| v.as_str())
                && !v.trim().is_empty()
            {
                cfg.password = v.to_string();
            }
            if let Some(v) = patch.get("oauth_token").and_then(|v| v.as_str())
                && !v.trim().is_empty()
            {
                cfg.oauth_token = v.to_string();
            }
            if let Some(v) = patch
                .get("timeout_secs")
                .and_then(serde_json::Value::as_u64)
            {
                cfg.timeout_secs = v;
            }
            if let Some(v) = patch.get("enabled").and_then(serde_json::Value::as_bool) {
                cfg.enabled = v;
            }
            match save_stored_json(&s.storage, SERVICENOW_TICKETING_CONFIG_KEY, &cfg) {
                Ok(()) => json_response(r#"{"status":"saved"}"#, 200),
                Err(error) => error_json(&error, 500),
            }
        }
        Err(error) => error_json(&error, 400),
    }
}

/// Resolve secrets and attempt the remote create/update for a ticket sync.
/// Returns `None` when the provider isn't configured/enabled — callers fall
/// back to local-only bookkeeping in that case, so the endpoint stays
/// backward compatible with deployments that never configured a remote.
pub(crate) fn sync_remote_ticket(
    storage: &SharedStorage,
    provider: &str,
    existing_external_key: Option<&str>,
    summary: &str,
    description: &str,
) -> Option<Result<RemoteTicket, String>> {
    let resolver = build_secrets_resolver_ext(storage);
    match provider {
        "jira" => {
            let mut cfg = load_jira_config(storage);
            if !cfg.enabled {
                return None;
            }
            cfg.api_token = resolver.resolve(&cfg.api_token).unwrap_or_default();
            let client = JiraClient::new(cfg);
            Some(client.create_or_update_issue(existing_external_key, summary, description))
        }
        "servicenow" => {
            let mut cfg = load_servicenow_config(storage);
            if !cfg.enabled {
                return None;
            }
            cfg.password = resolver.resolve(&cfg.password).unwrap_or_default();
            cfg.oauth_token = resolver.resolve(&cfg.oauth_token).unwrap_or_default();
            let client = ServiceNowClient::new(cfg);
            Some(client.create_or_update_incident(existing_external_key, summary, description))
        }
        _ => None,
    }
}

/// Pull the current remote status for one ticket sync record and return it,
/// without mutating local bookkeeping (the caller updates the record).
pub(crate) fn pull_remote_ticket_status(
    storage: &SharedStorage,
    provider: &str,
    external_key: &str,
) -> Result<String, String> {
    let resolver = build_secrets_resolver_ext(storage);
    match provider {
        "jira" => {
            let mut cfg = load_jira_config(storage);
            if !cfg.enabled {
                return Err("Jira integration is not enabled".into());
            }
            cfg.api_token = resolver.resolve(&cfg.api_token).unwrap_or_default();
            JiraClient::new(cfg).get_status(external_key)
        }
        "servicenow" => {
            let mut cfg = load_servicenow_config(storage);
            if !cfg.enabled {
                return Err("ServiceNow integration is not enabled".into());
            }
            cfg.password = resolver.resolve(&cfg.password).unwrap_or_default();
            cfg.oauth_token = resolver.resolve(&cfg.oauth_token).unwrap_or_default();
            ServiceNowClient::new(cfg).get_status(external_key)
        }
        other => Err(format!("unsupported ticketing provider '{other}'")),
    }
}

/// POST /api/tickets/pull — bidirectional sync: fetch each (or one) synced
/// ticket's current remote status and refresh the local bookkeeping record.
pub(crate) fn handle_tickets_pull(body: &[u8], state: &Arc<Mutex<AppState>>) -> Response<Body> {
    #[derive(Debug, serde::Deserialize, Default)]
    struct PullRequest {
        #[serde(default)]
        sync_id: Option<String>,
    }
    let req: PullRequest = if body.is_empty() {
        PullRequest::default()
    } else {
        match read_json_body::<PullRequest>(body, 4 * 1024) {
            Ok(v) => v,
            Err(error) => return error_json(&error, 400),
        }
    };

    let mut s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let syncs: Vec<_> = s
        .enterprise
        .ticket_syncs()
        .iter()
        .filter(|sync| req.sync_id.as_deref().is_none_or(|id| id == sync.id))
        .cloned()
        .collect();

    let mut updates = Vec::new();
    for sync in syncs {
        match pull_remote_ticket_status(&s.storage, &sync.provider, &sync.external_key) {
            Ok(status) => {
                s.enterprise.update_ticket_sync_status(&sync.id, &status);
                updates.push(serde_json::json!({
                    "sync_id": sync.id,
                    "external_key": sync.external_key,
                    "status": status,
                    "success": true,
                }));
            }
            Err(error) => {
                updates.push(serde_json::json!({
                    "sync_id": sync.id,
                    "external_key": sync.external_key,
                    "error": error,
                    "success": false,
                }));
            }
        }
    }

    json_response(
        &serde_json::json!({ "pulled": updates.len(), "updates": updates }).to_string(),
        200,
    )
}

// ── OTLP export ──────────────────────────────────────────────────────────────

fn load_otlp_config(storage: &SharedStorage) -> crate::telemetry::OtlpExporterConfig {
    let mut cfg: crate::telemetry::OtlpExporterConfig =
        load_stored_json(storage, OTLP_EXPORT_CONFIG_KEY);
    // `OTEL_EXPORTER_OTLP_ENDPOINT` is the standard OpenTelemetry SDK env
    // var; honour it as a default when no endpoint has been saved via the
    // API yet, so deployments that already set it don't need to repeat it.
    if cfg.endpoint.trim().is_empty()
        && let Ok(endpoint) = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        && !endpoint.trim().is_empty()
    {
        cfg.endpoint = endpoint;
        cfg.enabled = true;
    }
    cfg
}

pub(crate) fn handle_otlp_config_get(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let cfg = load_otlp_config(&s.storage);
    json_response(&serde_json::to_string(&cfg).unwrap_or_default(), 200)
}

pub(crate) fn handle_otlp_config_post(body: &[u8], state: &Arc<Mutex<AppState>>) -> Response<Body> {
    match read_json_body::<crate::telemetry::OtlpExporterConfig>(body, 8 * 1024) {
        Ok(cfg) => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match save_stored_json(&s.storage, OTLP_EXPORT_CONFIG_KEY, &cfg) {
                Ok(()) => json_response(
                    &serde_json::json!({"status": "saved", "config": cfg}).to_string(),
                    200,
                ),
                Err(error) => error_json(&error, 500),
            }
        }
        Err(error) => error_json(&error, 400),
    }
}

/// POST /api/telemetry/otlp/flush — build a one-shot exporter from the
/// stored config, enqueue the server's recent in-memory spans, and flush
/// them to the configured OTLP/HTTP collector immediately. Useful for
/// "test my collector endpoint" workflows and for CI/ops scripts that want
/// a synchronous export rather than waiting on a background loop.
pub(crate) fn handle_otlp_flush(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let cfg = load_otlp_config(&s.storage);
    if !cfg.enabled || cfg.endpoint.trim().is_empty() {
        return error_json(
            "OTLP export is not enabled; configure it at POST /api/telemetry/otlp",
            409,
        );
    }
    let exporter = crate::telemetry::OtlpExporter::new(cfg);
    for span in s.trace_collector.recent(500) {
        exporter.enqueue_span(span.clone());
    }
    let results = exporter.flush_all();
    let stats = exporter.stats();
    json_response(
        &serde_json::json!({ "results": results, "stats": stats }).to_string(),
        200,
    )
}
