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

/// Placeholder returned in place of a secret header value by the OTLP config
/// GET/echo endpoints. When a client PATCHes headers back with this exact
/// value for a given name, the previously stored value is kept rather than
/// being overwritten with the literal placeholder string.
pub(crate) const REDACTED_PLACEHOLDER: &str = "__REDACTED__";

// ── Outbound URL / SSRF hardening ────────────────────────────────────────────
//
// Every admin-configurable outbound URL here (Jira/ServiceNow/OTLP/
// VirusTotal/AbuseIPDB) is paired with a stored credential that a real HTTP
// client will send to whatever host the URL currently resolves to. Without
// validation, an admin (or anyone who can reach these config endpoints)
// could point a configured integration at an attacker-controlled host, an
// internal service, or a cloud metadata endpoint, and have Wardex hand over
// the stored API token/password on the next call.

/// Extract the host portion of an `http(s)://` URL (no scheme, userinfo,
/// port, path, query, or IPv6 brackets). Returns `None` if the URL doesn't
/// parse as `scheme://host...`.
pub(crate) fn url_host(url: &str) -> Option<String> {
    let trimmed = url.trim();
    let (_, rest) = trimmed.split_once("://")?;
    let after_userinfo = rest.rsplit_once('@').map_or(rest, |(_, host)| host);
    let host_port = after_userinfo
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_userinfo);
    let host = if let Some(bracketed) = host_port
        .strip_prefix('[')
        .and_then(|s| s.split_once(']').map(|(h, _)| h))
    {
        // IPv6 literal, e.g. "[::1]:4318".
        bracketed
    } else {
        // Only strip a trailing `:port` when it's actually numeric, so a
        // bare (unbracketed) IPv6 host isn't mangled.
        match host_port.rsplit_once(':') {
            Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => h,
            _ => host_port,
        }
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// Is `host` a loopback address (`localhost`, `127.0.0.0/8`, `::1`)? Used to
/// allow plaintext `http://` for local mock servers in tests without a
/// separate opt-in flag.
fn is_loopback_host(host: &str) -> bool {
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Is `host` a link-local address (`169.254.0.0/16`, `fe80::/10`) or a known
/// cloud metadata endpoint (`169.254.169.254`, `metadata.google.internal`,
/// `fd00:ec2::254`)? These must never be reachable via an admin-configured
/// integration URL, regardless of scheme.
fn is_forbidden_internal_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("metadata.google.internal") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => v4.is_link_local(),
        Ok(std::net::IpAddr::V6(v6)) => {
            // fe80::/10
            (v6.segments()[0] & 0xffc0) == 0xfe80
                // fd00:ec2::254 (AWS IMDSv6)
                || v6 == "fd00:ec2::254".parse::<std::net::Ipv6Addr>().unwrap_or(std::net::Ipv6Addr::UNSPECIFIED)
        }
        Err(_) => false,
    }
}

/// Validate an admin-configured outbound integration URL: only `http(s)` is
/// allowed, plaintext `http` is refused unless the host is loopback (so
/// tests can point at a local mock server), and link-local/cloud-metadata
/// hosts are always rejected regardless of scheme. An empty URL is accepted
/// (treated as "not configured yet"); callers that require a URL check
/// emptiness separately.
pub(crate) fn validate_outbound_url(url: &str) -> Result<(), String> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    let scheme = trimmed
        .split_once("://")
        .map(|(scheme, _)| scheme.to_ascii_lowercase());
    let Some(scheme) = scheme else {
        return Err(format!("'{trimmed}' is not a valid http(s) URL"));
    };
    if scheme != "http" && scheme != "https" {
        return Err(format!(
            "URL scheme '{scheme}' is not allowed; only http:// or https:// URLs may be configured"
        ));
    }
    let Some(host) = url_host(trimmed) else {
        return Err(format!("'{trimmed}' is missing a host"));
    };
    if scheme == "http" && !is_loopback_host(&host) {
        return Err(
            "plaintext http:// URLs are only allowed for localhost/loopback targets; use https:// instead"
                .into(),
        );
    }
    if is_forbidden_internal_host(&host) {
        return Err(format!(
            "'{host}' is a link-local or cloud metadata address and cannot be configured"
        ));
    }
    Ok(())
}

/// Clamp a client-configurable HTTP timeout to a sane range, so a value of
/// `0` (hangs forever with some clients) or an unreasonably large number
/// (ties up a worker thread) can't be configured.
pub(crate) fn clamp_timeout_secs(secs: u64) -> u64 {
    secs.clamp(1, 60)
}

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
                let mut new_key_given = false;
                if let Some(v) = vt.api_key
                    && !v.trim().is_empty()
                {
                    cfg.virustotal.api_key = v;
                    new_key_given = true;
                }
                if let Some(v) = vt.requests_per_minute {
                    cfg.virustotal.requests_per_minute = v;
                }
                if let Some(v) = vt.cache_ttl_secs {
                    cfg.virustotal.cache_ttl_secs = v;
                }
                if let Some(v) = vt.timeout_secs {
                    cfg.virustotal.timeout_secs = clamp_timeout_secs(v);
                }
                if let Some(v) = vt.base_url
                    && !v.trim().is_empty()
                {
                    if let Err(error) = validate_outbound_url(&v) {
                        return error_json(&format!("invalid virustotal.base_url: {error}"), 400);
                    }
                    let old_host = url_host(&cfg.virustotal.base_url);
                    let new_host = url_host(&v);
                    cfg.virustotal.base_url = v;
                    // Changing the endpoint's host without also supplying a
                    // fresh API key must not carry the old key over to the
                    // new host — clear it so it has to be re-entered.
                    if !new_key_given && old_host != new_host {
                        cfg.virustotal.api_key.clear();
                    }
                }
            }
            if let Some(ab) = patch.abuseipdb {
                if let Some(v) = ab.enabled {
                    cfg.abuseipdb.enabled = v;
                }
                let mut new_key_given = false;
                if let Some(v) = ab.api_key
                    && !v.trim().is_empty()
                {
                    cfg.abuseipdb.api_key = v;
                    new_key_given = true;
                }
                if let Some(v) = ab.requests_per_minute {
                    cfg.abuseipdb.requests_per_minute = v;
                }
                if let Some(v) = ab.cache_ttl_secs {
                    cfg.abuseipdb.cache_ttl_secs = v;
                }
                if let Some(v) = ab.timeout_secs {
                    cfg.abuseipdb.timeout_secs = clamp_timeout_secs(v);
                }
                if let Some(v) = ab.max_age_days {
                    cfg.abuseipdb.max_age_days = v;
                }
                if let Some(v) = ab.base_url
                    && !v.trim().is_empty()
                {
                    if let Err(error) = validate_outbound_url(&v) {
                        return error_json(&format!("invalid abuseipdb.base_url: {error}"), 400);
                    }
                    let old_host = url_host(&cfg.abuseipdb.base_url);
                    let new_host = url_host(&v);
                    cfg.abuseipdb.base_url = v;
                    if !new_key_given && old_host != new_host {
                        cfg.abuseipdb.api_key.clear();
                    }
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
            let cfg = {
                let s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let mut cfg = load_enrichment_config(&s.storage);
                let resolver = build_secrets_resolver_ext(&s.storage);
                // Resolve secret references (env/file/vault) for the API
                // keys, same mechanism the cloud collectors use for their
                // credentials.
                if cfg.virustotal.enabled {
                    cfg.virustotal.api_key = resolver
                        .resolve(&cfg.virustotal.api_key)
                        .unwrap_or_default();
                }
                if cfg.abuseipdb.enabled {
                    cfg.abuseipdb.api_key =
                        resolver.resolve(&cfg.abuseipdb.api_key).unwrap_or_default();
                }
                cfg
            };
            // The AppState lock is released above: the actual VirusTotal/
            // AbuseIPDB HTTP calls below can take seconds and must not
            // block every other request that needs AppState.
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
            let mut new_token_given = false;
            if let Some(v) = patch.get("api_token").and_then(|v| v.as_str())
                && !v.trim().is_empty()
            {
                cfg.api_token = v.to_string();
                new_token_given = true;
            }
            if let Some(v) = patch.get("base_url").and_then(|v| v.as_str()) {
                if let Err(error) = validate_outbound_url(v) {
                    return error_json(&format!("invalid base_url: {error}"), 400);
                }
                let old_host = url_host(&cfg.base_url);
                let new_host = url_host(v);
                cfg.base_url = v.to_string();
                // A changed host without a freshly supplied token must not
                // silently carry the old token over to the new endpoint.
                if !new_token_given && old_host != new_host {
                    cfg.api_token.clear();
                }
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
            if let Some(v) = patch
                .get("timeout_secs")
                .and_then(serde_json::Value::as_u64)
            {
                cfg.timeout_secs = clamp_timeout_secs(v);
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
            let mut new_secret_given = false;
            if let Some(v) = patch.get("password").and_then(|v| v.as_str())
                && !v.trim().is_empty()
            {
                cfg.password = v.to_string();
                new_secret_given = true;
            }
            if let Some(v) = patch.get("oauth_token").and_then(|v| v.as_str())
                && !v.trim().is_empty()
            {
                cfg.oauth_token = v.to_string();
                new_secret_given = true;
            }
            if let Some(v) = patch.get("instance_url").and_then(|v| v.as_str()) {
                if let Err(error) = validate_outbound_url(v) {
                    return error_json(&format!("invalid instance_url: {error}"), 400);
                }
                let old_host = url_host(&cfg.instance_url);
                let new_host = url_host(v);
                cfg.instance_url = v.to_string();
                // A changed host without a freshly supplied secret must not
                // silently carry the old password/token over to it.
                if !new_secret_given && old_host != new_host {
                    cfg.password.clear();
                    cfg.oauth_token.clear();
                }
            }
            if let Some(v) = patch.get("table").and_then(|v| v.as_str()) {
                cfg.table = v.to_string();
            }
            if let Some(v) = patch.get("username").and_then(|v| v.as_str()) {
                cfg.username = v.to_string();
            }
            if let Some(v) = patch
                .get("timeout_secs")
                .and_then(serde_json::Value::as_u64)
            {
                cfg.timeout_secs = clamp_timeout_secs(v);
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

    // Lock only long enough to snapshot what's needed, then release the
    // global lock before making sequential network calls to Jira/
    // ServiceNow — those can take seconds each and must not stall every
    // other request that needs AppState.
    let (storage, syncs) = {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let syncs: Vec<_> = s
            .enterprise
            .ticket_syncs()
            .iter()
            .filter(|sync| req.sync_id.as_deref().is_none_or(|id| id == sync.id))
            // A sync with no external key has no remote ticket to pull
            // (never created, or the create attempt failed) — skip it
            // rather than calling the provider with an empty id.
            .filter(|sync| !sync.external_key.is_empty())
            .cloned()
            .collect();
        (s.storage.clone(), syncs)
    };

    let mut results = Vec::new();
    for sync in syncs {
        let outcome = pull_remote_ticket_status(&storage, &sync.provider, &sync.external_key);
        results.push((sync, outcome));
    }

    let mut updates = Vec::new();
    let mut s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for (sync, outcome) in results {
        match outcome {
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

/// View of the OTLP config safe to return to a client: header *values* are
/// auth tokens/API keys and must never round-trip in cleartext, so only the
/// header *names* are exposed, each mapped to [`REDACTED_PLACEHOLDER`].
/// `handle_otlp_config_post` recognizes that placeholder and keeps the
/// previously stored value for a header the client echoes back unchanged.
fn otlp_config_view(cfg: &crate::telemetry::OtlpExporterConfig) -> serde_json::Value {
    let headers: serde_json::Map<String, serde_json::Value> = cfg
        .headers
        .keys()
        .map(|name| {
            (
                name.clone(),
                serde_json::Value::String(REDACTED_PLACEHOLDER.to_string()),
            )
        })
        .collect();
    serde_json::json!({
        "endpoint": cfg.endpoint,
        "enabled": cfg.enabled,
        "headers": headers,
        "has_headers": !cfg.headers.is_empty(),
        "batch_max_size": cfg.batch_max_size,
        "max_queue_size": cfg.max_queue_size,
        "max_retries": cfg.max_retries,
        "timeout_secs": cfg.timeout_secs,
    })
}

pub(crate) fn handle_otlp_config_get(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let cfg = load_otlp_config(&s.storage);
    json_response(&otlp_config_view(&cfg).to_string(), 200)
}

pub(crate) fn handle_otlp_config_post(body: &[u8], state: &Arc<Mutex<AppState>>) -> Response<Body> {
    match read_json_body::<crate::telemetry::OtlpExporterConfig>(body, 8 * 1024) {
        Ok(mut cfg) => {
            if let Err(error) = validate_outbound_url(&cfg.endpoint) {
                return error_json(&format!("invalid endpoint: {error}"), 400);
            }
            cfg.timeout_secs = clamp_timeout_secs(cfg.timeout_secs);

            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let existing = load_otlp_config(&s.storage);

            // Restore any header value the client echoed back as the
            // redacted placeholder; a name with no existing stored value is
            // an error rather than silently persisting the literal
            // placeholder string as a "header value".
            for (name, value) in cfg.headers.iter_mut() {
                if value.as_str() == REDACTED_PLACEHOLDER {
                    match existing.headers.get(name) {
                        Some(previous) => *value = previous.clone(),
                        None => {
                            return error_json(
                                &format!("header '{name}' has no existing stored value to keep"),
                                400,
                            );
                        }
                    }
                }
            }
            let any_new_header_value = cfg
                .headers
                .iter()
                .any(|(name, value)| existing.headers.get(name) != Some(value));
            // If the endpoint's host changed and the client didn't also
            // supply at least one fresh header value, drop the stored
            // headers (likely auth tokens for the old collector) rather
            // than silently sending them to a new, potentially
            // attacker-controlled host.
            if url_host(&existing.endpoint) != url_host(&cfg.endpoint) && !any_new_header_value {
                cfg.headers.clear();
            }

            match save_stored_json(&s.storage, OTLP_EXPORT_CONFIG_KEY, &cfg) {
                Ok(()) => json_response(
                    &serde_json::json!({"status": "saved", "config": otlp_config_view(&cfg)})
                        .to_string(),
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
    // Lock only to read the config and snapshot the recent spans, then
    // release the AppState mutex before the network flush to the collector
    // endpoint, which can take up to the configured timeout.
    let (cfg, spans) = {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let cfg = load_otlp_config(&s.storage);
        let spans: Vec<_> = s.trace_collector.recent(500).into_iter().cloned().collect();
        (cfg, spans)
    };
    if !cfg.enabled || cfg.endpoint.trim().is_empty() {
        return error_json(
            "OTLP export is not enabled; configure it at POST /api/telemetry/otlp",
            409,
        );
    }
    let exporter = crate::telemetry::OtlpExporter::new(cfg);
    for span in spans {
        exporter.enqueue_span(span);
    }
    let results = exporter.flush_all();
    let stats = exporter.stats();
    json_response(
        &serde_json::json!({ "results": results, "stats": stats }).to_string(),
        200,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body_json(resp: Response<Body>) -> serde_json::Value {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let bytes = rt
            .block_on(axum::body::to_bytes(resp.into_body(), 1_000_000))
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[test]
    fn url_host_extracts_bare_host() {
        assert_eq!(
            url_host("https://example.com:4318/v1/traces").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            url_host("http://127.0.0.1:8080/").as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(
            url_host("https://user:pass@host.example/x").as_deref(),
            Some("host.example")
        );
        assert_eq!(url_host("not a url").as_deref(), None);
    }

    #[test]
    fn validate_outbound_url_enforces_https_and_blocks_metadata_hosts() {
        assert!(validate_outbound_url("").is_ok());
        assert!(validate_outbound_url("https://api.example.com").is_ok());
        assert!(validate_outbound_url("http://127.0.0.1:9200").is_ok());
        assert!(validate_outbound_url("http://localhost:9200").is_ok());

        assert!(validate_outbound_url("http://not-loopback.example.com").is_err());
        assert!(validate_outbound_url("ftp://example.com").is_err());
        assert!(validate_outbound_url("https://169.254.169.254").is_err());
        assert!(validate_outbound_url("http://169.254.1.2").is_err());
        assert!(validate_outbound_url("https://metadata.google.internal").is_err());
        assert!(validate_outbound_url("https://[fe80::1]").is_err());
        assert!(validate_outbound_url("https://[fd00:ec2::254]").is_err());
    }

    #[test]
    fn clamp_timeout_secs_bounds_to_sane_range() {
        assert_eq!(clamp_timeout_secs(0), 1);
        assert_eq!(clamp_timeout_secs(30), 30);
        assert_eq!(clamp_timeout_secs(10_000), 60);
    }

    /// White-box coverage for the OTLP header-placeholder handling: the
    /// real header value must be what ends up stored, never the literal
    /// `__REDACTED__` placeholder — the public API never echoes the real
    /// value back out (see the `tests/api_integrations_hardening.rs`
    /// integration tests for the black-box behavior).
    #[test]
    fn otlp_post_keeps_real_header_value_when_placeholder_is_echoed_back() {
        let (_port, _token, state) = crate::server::spawn_test_server_with_state();

        let first = serde_json::json!({
            "endpoint": "https://collector.example.com:4318",
            "enabled": true,
            "headers": {"Authorization": "Bearer super-secret-token"},
            "batch_max_size": 100,
            "max_queue_size": 1000,
            "max_retries": 3,
            "timeout_secs": 5
        })
        .to_string();
        let resp = handle_otlp_config_post(first.as_bytes(), &state);
        assert_eq!(resp.status(), 200);

        let second = serde_json::json!({
            "endpoint": "https://collector.example.com:4318",
            "enabled": true,
            "headers": {"Authorization": REDACTED_PLACEHOLDER},
            "batch_max_size": 200,
            "max_queue_size": 1000,
            "max_retries": 3,
            "timeout_secs": 5
        })
        .to_string();
        let resp = handle_otlp_config_post(second.as_bytes(), &state);
        assert_eq!(resp.status(), 200);
        let body = body_json(resp);
        assert_eq!(
            body["config"]["headers"]["Authorization"].as_str(),
            Some(REDACTED_PLACEHOLDER)
        );

        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let stored = load_otlp_config(&s.storage);
        assert_eq!(
            stored.headers.get("Authorization").map(String::as_str),
            Some("Bearer super-secret-token")
        );
    }

    #[test]
    fn otlp_post_clears_headers_when_host_changes_without_new_header_value() {
        let (_port, _token, state) = crate::server::spawn_test_server_with_state();

        let first = serde_json::json!({
            "endpoint": "https://collector-a.example.com:4318",
            "enabled": true,
            "headers": {"Authorization": "Bearer secret-a"},
            "batch_max_size": 100,
            "max_queue_size": 1000,
            "max_retries": 3,
            "timeout_secs": 5
        })
        .to_string();
        assert_eq!(
            handle_otlp_config_post(first.as_bytes(), &state).status(),
            200
        );

        // Same header set as a placeholder, but a different host: the
        // stale header must be dropped, not sent to the new collector.
        let second = serde_json::json!({
            "endpoint": "https://collector-b.example.com:4318",
            "enabled": true,
            "headers": {"Authorization": REDACTED_PLACEHOLDER},
            "batch_max_size": 100,
            "max_queue_size": 1000,
            "max_retries": 3,
            "timeout_secs": 5
        })
        .to_string();
        // This must be rejected (placeholder with no matching stored value
        // once the header would otherwise be dropped) OR the header must be
        // cleared. Either way the old secret must never reach the new host.
        let resp = handle_otlp_config_post(second.as_bytes(), &state);
        if resp.status() == 200 {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let stored = load_otlp_config(&s.storage);
            assert_ne!(
                stored.headers.get("Authorization").map(String::as_str),
                Some("Bearer secret-a"),
                "old header value must not follow the endpoint to a new host"
            );
        }
    }

    #[test]
    fn jira_post_clears_api_token_when_base_url_host_changes() {
        let (_port, _token, state) = crate::server::spawn_test_server_with_state();

        let first = serde_json::json!({
            "base_url": "https://a.atlassian.net",
            "project_key": "SEC",
            "api_token": "tok-a",
            "enabled": true
        })
        .to_string();
        assert_eq!(
            handle_ticketing_jira_post(first.as_bytes(), &state).status(),
            200
        );
        {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(!load_jira_config(&s.storage).api_token.is_empty());
        }

        let second = serde_json::json!({
            "base_url": "https://b.atlassian.net",
        })
        .to_string();
        assert_eq!(
            handle_ticketing_jira_post(second.as_bytes(), &state).status(),
            200
        );
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            load_jira_config(&s.storage).api_token.is_empty(),
            "api_token must be cleared when base_url's host changes without a new token"
        );
    }

    #[test]
    fn jira_post_rejects_insecure_base_url() {
        let (_port, _token, state) = crate::server::spawn_test_server_with_state();
        let body = serde_json::json!({
            "base_url": "http://not-loopback.example.com",
            "project_key": "SEC",
        })
        .to_string();
        assert_eq!(
            handle_ticketing_jira_post(body.as_bytes(), &state).status(),
            400
        );
    }
}
