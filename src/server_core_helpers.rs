use super::*;

pub(crate) fn generate_token() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.random()).collect();
    hex::encode(bytes)
}

pub(crate) fn build_report_run_preview(
    state: &mut AppState,
    request: &serde_json::Value,
    execution_context_json: serde_json::Value,
) -> serde_json::Value {
    let kind = request["kind"].as_str().unwrap_or("executive_status");
    match kind {
        "control_plane_failover_history" => control_plane_failover_history_preview(state),
        _ => {
            state.agent_registry.refresh_staleness();
            let open_incidents = state
                .incident_store
                .list()
                .iter()
                .filter(|incident| {
                    matches!(
                        incident.status,
                        crate::incident::IncidentStatus::Open
                            | crate::incident::IncidentStatus::Investigating
                    )
                })
                .count();
            let offline_agents = state
                .agent_registry
                .list()
                .iter()
                .filter(|agent| {
                    matches!(
                        agent.status,
                        crate::enrollment::AgentStatus::Offline
                            | crate::enrollment::AgentStatus::Stale
                    )
                })
                .count();
            let queue_pending = state.alert_queue.pending().len();
            serde_json::json!({
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "kind": kind,
                "scope": request["scope"].as_str().unwrap_or("global"),
                "queue_pending": queue_pending,
                "open_incidents": open_incidents,
                "offline_agents": offline_agents,
                "pending_approvals": state.response_orchestrator.pending_requests().len(),
                "stored_reports": state.report_store.list().len(),
                "execution_context": execution_context_json,
                "executive_summary": state.report_store.executive_summary(&state.incident_store),
            })
        }
    }
}

/// Scan text for common PII patterns (email, IPv4, SSN, credit card).
/// Returns a list of category names found.
pub(crate) fn scan_pii(text: &str) -> Vec<String> {
    let mut categories = Vec::new();

    // Email pattern
    let has_email = text.split_whitespace().any(|w| {
        let w = w.trim_matches(|c: char| {
            !c.is_alphanumeric() && c != '@' && c != '.' && c != '_' && c != '-'
        });
        w.contains('@') && w.contains('.') && w.len() > 5
    });
    if has_email {
        categories.push("email".into());
    }

    // SSN pattern (###-##-####)
    let has_ssn = text.as_bytes().windows(11).any(|w| {
        w.len() == 11
            && w[0].is_ascii_digit()
            && w[1].is_ascii_digit()
            && w[2].is_ascii_digit()
            && w[3] == b'-'
            && w[4].is_ascii_digit()
            && w[5].is_ascii_digit()
            && w[6] == b'-'
            && w[7].is_ascii_digit()
            && w[8].is_ascii_digit()
            && w[9].is_ascii_digit()
            && w[10].is_ascii_digit()
    });
    if has_ssn {
        categories.push("ssn".into());
    }

    // Credit card pattern (4 groups of 4 digits separated by spaces or dashes)
    let digits_only: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits_only.len() >= 13 {
        // Luhn check on first 16-digit sequence
        let candidate: Vec<u8> = digits_only.bytes().take(16).map(|b| b - b'0').collect();
        if candidate.len() >= 13 {
            let mut sum = 0u32;
            let mut double = false;
            for &d in candidate.iter().rev() {
                let mut n = d as u32;
                if double {
                    n *= 2;
                    if n > 9 {
                        n -= 9;
                    }
                }
                sum += n;
                double = !double;
            }
            if sum.is_multiple_of(10) {
                categories.push("credit_card".into());
            }
        }
    }

    // IPv4 addresses (not in RFC 1918 private ranges to reduce false positives)
    let has_public_ip = text.split_whitespace().any(|w| {
        let parts: Vec<&str> = w
            .trim_matches(|c: char| !c.is_ascii_digit() && c != '.')
            .split('.')
            .collect();
        if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
            let first: u8 = parts[0].parse().unwrap_or(0);
            let second: u8 = parts[1].parse().unwrap_or(0);
            // Skip private ranges
            !(first == 10
                || first == 127
                || (first == 172 && (16..=31).contains(&second))
                || (first == 192 && second == 168))
        } else {
            false
        }
    });
    if has_public_ip {
        categories.push("ip_address".into());
    }

    categories
}

pub(crate) fn recent_alerts_json(
    alerts: &[AlertRecord],
    limit: usize,
    offset: usize,
    local_hostname: &str,
    process_tree: &crate::process_tree::ProcessTree,
) -> Result<String, String> {
    let capped_limit = limit.min(1000);
    let process_catalog = assemble_alert_process_catalog(local_hostname, process_tree);
    let recent: Vec<_> = alerts
        .iter()
        .enumerate()
        .rev()
        .skip(offset)
        .take(capped_limit)
        .map(|(i, a)| alert_json_value(a, i, local_hostname, &process_catalog))
        .collect();
    serde_json::to_string(&recent).map_err(|e| format!("serialization error: {e}"))
}

pub(crate) fn alert_json_value(
    alert: &AlertRecord,
    index: usize,
    local_hostname: &str,
    process_catalog: &[AlertProcessPivot],
) -> serde_json::Value {
    let mut obj = serde_json::to_value(alert).unwrap_or_default();
    let entities = crate::entity_extract::extract_entities(&alert.reasons);
    let process_names = extract_alert_process_names(&entities);
    let process_candidates =
        resolve_alert_process_pivots(&process_names, process_catalog, &alert.hostname);
    if let Some(map) = obj.as_object_mut() {
        map.insert("id".to_string(), serde_json::json!(index));
        map.insert("_index".to_string(), serde_json::json!(index));
        map.insert(
            "entities".to_string(),
            serde_json::to_value(&entities).unwrap_or_else(|_| serde_json::json!([])),
        );
        map.insert(
            "process_resolution".to_string(),
            serde_json::json!(alert_process_resolution(
                &alert.hostname,
                local_hostname,
                &process_names,
                &process_candidates,
            )),
        );
        if !process_names.is_empty() {
            map.insert(
                "process_names".to_string(),
                serde_json::json!(process_names),
            );
        }
        if !process_candidates.is_empty() {
            map.insert(
                "process_candidates".to_string(),
                serde_json::to_value(&process_candidates).unwrap_or_else(|_| serde_json::json!([])),
            );
            if process_candidates.len() == 1 {
                map.insert(
                    "process".to_string(),
                    serde_json::to_value(&process_candidates[0])
                        .unwrap_or_else(|_| serde_json::json!({})),
                );
            }
        }
    }
    obj
}

pub(crate) fn incidents_json(
    incident_store: &IncidentStore,
    query: &HashMap<String, String>,
) -> Result<String, String> {
    let status = query.get("status").map(|value| value.as_str());
    let severity = query.get("severity").map(|value| value.as_str());
    let offset = query
        .get("offset")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let limit = query
        .get("limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(100)
        .min(1000);

    let incidents = incident_store.list_filtered(status, severity);
    let paged: Vec<_> = incidents.into_iter().skip(offset).take(limit).collect();
    serde_json::to_string(&paged).map_err(|e| format!("serialization error: {e}"))
}

pub(crate) fn prometheus_metrics_payload(state: &AppState) -> String {
    let agents = state.agent_registry.list();
    let heartbeat_interval = state.agent_registry.heartbeat_interval();
    let total_agents = agents.len();
    let online_agents = agents
        .iter()
        .filter(|agent| computed_agent_status(agent, heartbeat_interval).0 == "online")
        .count();
    let pending_deployments = state
        .remote_deployments
        .values()
        .filter(|deployment| deployment_is_pending(deployment, &state.agent_registry))
        .count();
    let stream_stats = state.alert_broadcaster.stats();
    let stream_queue_depth = stream_stats
        .get("subscriber_queue_depth")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let stream_dropped_events = stream_stats
        .get("dropped_events")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let collector_entries = crate::server_collectors::full_collector_status_entries(state);
    let collector_sla = crate::server_collectors::collector_sla_summary(&collector_entries);
    let collector_sla_breach_count = collector_sla
        .get("breach_count")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();

    let lock_stats = crate::state_lock::snapshot();

    let metrics = [
        ("wardex_up", "gauge", 1_u64),
        ("wardex_alerts_total", "gauge", state.alerts.len() as u64),
        (
            "wardex_events_total",
            "gauge",
            state.event_store.count() as u64,
        ),
        ("wardex_agents_total", "gauge", total_agents as u64),
        ("wardex_agents_online", "gauge", online_agents as u64),
        (
            "wardex_incidents_total",
            "gauge",
            state.incident_store.list().len() as u64,
        ),
        (
            "wardex_cases_total",
            "gauge",
            state.case_store.list().len() as u64,
        ),
        (
            "wardex_reports_total",
            "gauge",
            state.report_store.list().len() as u64,
        ),
        (
            "wardex_response_requests_total",
            "gauge",
            state.response_orchestrator.all_requests().len() as u64,
        ),
        (
            "wardex_response_pending_total",
            "gauge",
            state.response_orchestrator.pending_requests().len() as u64,
        ),
        (
            "wardex_deployments_pending_total",
            "gauge",
            pending_deployments as u64,
        ),
        (
            "wardex_collector_ingestion_sla_breach_count",
            "gauge",
            collector_sla_breach_count,
        ),
        ("wardex_stream_queue_depth", "gauge", stream_queue_depth),
        (
            "wardex_stream_dropped_events_total",
            "counter",
            stream_dropped_events,
        ),
        ("wardex_requests_total", "counter", state.request_count),
        ("wardex_request_errors_total", "counter", state.error_count),
        (
            "wardex_uptime_seconds",
            "gauge",
            state.server_start.elapsed().as_secs(),
        ),
        (
            "wardex_state_lock_acquisitions_total",
            "counter",
            lock_stats.acquisitions,
        ),
        (
            "wardex_state_lock_wait_ns_total",
            "counter",
            lock_stats.wait_ns_total,
        ),
        (
            "wardex_state_lock_slow_waits_total",
            "counter",
            lock_stats.slow_waits,
        ),
        (
            "wardex_state_lock_max_wait_ns",
            "gauge",
            lock_stats.max_wait_ns,
        ),
        (
            "wardex_state_lock_poisoned_total",
            "counter",
            lock_stats.poisoned,
        ),
    ];

    let mut body = String::new();
    for (name, metric_type, value) in metrics {
        body.push_str("# HELP ");
        body.push_str(name);
        body.push('\n');
        body.push_str("# TYPE ");
        body.push_str(name);
        body.push(' ');
        body.push_str(metric_type);
        body.push('\n');
        body.push_str(name);
        body.push(' ');
        body.push_str(&value.to_string());
        body.push('\n');
    }

    // Emit the derived mean-wait gauge separately because it is a float and
    // does not fit the (name, type, u64) shape of the array above.
    body.push_str("# HELP wardex_state_lock_mean_wait_ms\n");
    body.push_str("# TYPE wardex_state_lock_mean_wait_ms gauge\n");
    body.push_str(&format!(
        "wardex_state_lock_mean_wait_ms {:.6}\n",
        lock_stats.mean_wait_ms()
    ));

    // Per-callsite (labeled) lock metrics. The label is the static string
    // passed to `tracked_lock(state, "...")`; the rendering helper lives in
    // `src/server_metrics.rs` so this file stays focused on orchestration.
    body.push_str(&crate::server_metrics::render_labeled_lock_metrics());

    // Cardinality-budget drop counters for metrics families that cap dynamic
    // dimensions.
    body.push_str(&crate::server_metrics::render_metrics_drop_metrics());

    // Failed-auth observability counters and active-lockout gauge.
    body.push_str(&crate::server_metrics::render_failed_auth_metrics());

    body.push_str(&crate::server_metrics::render_api_endpoint_metrics(
        &state.api_analytics.metrics(),
    ));

    body
}

pub(crate) fn respond_api(
    state: &Arc<Mutex<AppState>>,
    method: &Method,
    url: &str,
    remote_addr: &str,
    auth_used: bool,
    response: Response<Body>,
) -> Response<Body> {
    respond_api_with_timing(state, method, url, remote_addr, auth_used, None, response)
}

pub(crate) fn respond_api_with_timing(
    state: &Arc<Mutex<AppState>>,
    method: &Method,
    url: &str,
    remote_addr: &str,
    auth_used: bool,
    request_started: Option<std::time::Instant>,
    response: Response<Body>,
) -> Response<Body> {
    let request_id = generate_request_id().unwrap_or_else(|_| {
        let random_suffix = rand::random::<u64>();
        format!("req-fallback-{random_suffix:016x}")
    });
    let status_code = response.status().as_u16();
    let latency_ms = request_started
        .map(|started| started.elapsed().as_secs_f64() * 1000.0)
        .unwrap_or(0.0);
    let route_path = url_path(url);
    {
        let mut s = crate::state_lock::tracked_lock(state, "server/respond_api_audit");
        if status_code >= 400 {
            s.error_count += 1;
        }
        s.api_analytics
            .record(method.as_str(), route_path, latency_ms, status_code >= 400);
        s.audit_log
            .record(method.as_str(), url, remote_addr, status_code, auth_used);
    }
    let (mut parts, body) = response.into_parts();
    if let Ok(hv) = request_id.parse() {
        parts.headers.insert("X-Request-Id", hv);
    }
    if let Some(metadata) = api_deprecation_metadata(method, route_path) {
        apply_api_deprecation_headers(&mut parts.headers, &metadata);
    }
    Response::from_parts(parts, body)
}

#[derive(Debug, Clone)]
pub(crate) struct ApiDeprecationMetadata {
    pub(crate) since: String,
    pub(crate) sunset: String,
    pub(crate) replacement: String,
}

pub(crate) fn apply_api_deprecation_headers(headers: &mut HeaderMap, metadata: &ApiDeprecationMetadata) {
    headers.insert("Deprecation", HeaderValue::from_static("true"));
    if let Ok(value) = HeaderValue::from_str(&metadata.since) {
        headers.insert("X-Wardex-Deprecated-Since", value);
    }
    if let Ok(value) = HeaderValue::from_str(&metadata.sunset) {
        headers.insert("Sunset", value);
    }
    let link = format!("<{}>; rel=\"successor-version\"", metadata.replacement);
    if let Ok(value) = HeaderValue::from_str(&link) {
        headers.insert("Link", value);
    }
}

pub(crate) fn api_deprecation_metadata(method: &Method, path: &str) -> Option<ApiDeprecationMetadata> {
    static DEPRECATIONS: OnceLock<HashMap<(String, String), ApiDeprecationMetadata>> =
        OnceLock::new();
    let deprecations = DEPRECATIONS.get_or_init(|| {
        let spec = crate::openapi::wardex_openapi_spec(env!("CARGO_PKG_VERSION"));
        let mut entries = HashMap::new();
        for (path, item) in spec.paths {
            let operations = [
                ("GET", item.get),
                ("POST", item.post),
                ("PUT", item.put),
                ("DELETE", item.delete),
                ("PATCH", item.patch),
            ];
            for (method, operation) in operations {
                let Some(operation) = operation else {
                    continue;
                };
                if operation.deprecated != Some(true) {
                    continue;
                }
                if let (Some(since), Some(sunset), Some(replacement)) = (
                    operation.deprecated_since,
                    operation.sunset,
                    operation.replacement,
                ) {
                    entries.insert(
                        (method.to_string(), path.clone()),
                        ApiDeprecationMetadata {
                            since,
                            sunset,
                            replacement,
                        },
                    );
                }
            }
        }
        entries
    });
    deprecations
        .get(&(method.as_str().to_string(), path.to_string()))
        .cloned()
}

#[derive(Debug, Clone)]
pub(crate) enum AuthIdentity {
    None,
    AdminToken,
    UserToken(User),
    SessionToken {
        user: User,
        groups: Vec<String>,
        csrf_token: String,
        cookie_authenticated: bool,
    },
}

impl AuthIdentity {
    pub(crate) fn is_authenticated(&self) -> bool {
        !matches!(self, AuthIdentity::None)
    }

    pub(crate) fn is_admin(&self) -> bool {
        matches!(self, AuthIdentity::AdminToken)
    }

    pub(crate) fn actor(&self) -> &str {
        match self {
            AuthIdentity::None => "anonymous",
            AuthIdentity::AdminToken => "admin",
            AuthIdentity::UserToken(user) | AuthIdentity::SessionToken { user, .. } => {
                &user.username
            }
        }
    }

    pub(crate) fn user(&self) -> Option<&User> {
        match self {
            AuthIdentity::UserToken(user) | AuthIdentity::SessionToken { user, .. } => Some(user),
            _ => None,
        }
    }

    pub(crate) fn groups(&self) -> &[String] {
        match self {
            AuthIdentity::SessionToken { groups, .. } => groups,
            _ => &[],
        }
    }

    pub(crate) fn csrf_token(&self) -> Option<&str> {
        match self {
            AuthIdentity::SessionToken { csrf_token, .. } if !csrf_token.is_empty() => {
                Some(csrf_token)
            }
            _ => None,
        }
    }

    pub(crate) fn is_cookie_authenticated(&self) -> bool {
        matches!(
            self,
            AuthIdentity::SessionToken {
                cookie_authenticated: true,
                ..
            }
        )
    }

    fn tenant_id(&self) -> Option<&str> {
        self.user()
            .and_then(|user| user.tenant_id.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }
}

#[allow(clippy::result_large_err)]
pub(crate) fn tenant_filter_for_request(
    auth: &AuthIdentity,
    requested_tenant: Option<&str>,
) -> Result<Option<String>, Response<Body>> {
    let requested = requested_tenant
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let Some(bound_tenant) = auth.tenant_id() else {
        return Ok(requested.map(str::to_string));
    };
    match requested {
        Some(tenant) if tenant != bound_tenant => Err(error_json(
            "forbidden: requested tenant_id is outside the active identity scope",
            403,
        )),
        _ => Ok(Some(bound_tenant.to_string())),
    }
}

pub(crate) fn cluster_request_authorized(headers: &HeaderMap, state: &Arc<Mutex<AppState>>) -> bool {
    let provided = bearer_token(headers);
    let s = crate::state_lock::tracked_lock(state, "server/cluster_request_authorized");
    if let Some(cluster_token) = s.config.cluster.auth_token.as_deref() {
        return secure_token_eq(provided.as_deref(), cluster_token);
    }
    secure_token_eq(provided.as_deref(), &s.token)
}

pub(crate) const SESSION_COOKIE_NAME: &str = "wardex_session";
pub(crate) const CSRF_HEADER_NAME: &str = "x-wardex-csrf";
pub(crate) const MTLS_VERIFY_HEADER: &str = "x-ssl-client-verify";
pub(crate) const MTLS_CERT_HEADER: &str = "x-forwarded-client-cert";
pub(crate) const MTLS_PRESENT_HEADER: &str = "x-client-cert-present";
pub(crate) const AGENT_ID_HEADER: &str = "x-wardex-agent-id";
pub(crate) const AGENT_TOKEN_HEADER: &str = "x-wardex-agent-token";

pub(crate) fn session_cookie_token(headers: &HeaderMap) -> Option<String> {
    let cookie_header = headers.get(COOKIE)?.to_str().ok()?;
    for cookie in cookie_header.split(';') {
        let trimmed = cookie.trim();
        let Some((name, value)) = trimmed.split_once('=') else {
            continue;
        };
        if name.trim() == SESSION_COOKIE_NAME {
            let decoded = decode_query_component(value.trim().trim_matches('"'));
            if !decoded.is_empty() {
                return Some(decoded);
            }
        }
    }
    None
}

pub(crate) fn csrf_header_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(CSRF_HEADER_NAME)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

pub(crate) fn unsafe_method_requires_csrf(method: &Method) -> bool {
    matches!(
        method,
        Method::Post | Method::Put | Method::Patch | Method::Delete
    )
}

pub(crate) fn csrf_request_authorized(headers: &HeaderMap, auth: &AuthIdentity, method: &Method) -> bool {
    if !unsafe_method_requires_csrf(method) || !auth.is_cookie_authenticated() {
        return true;
    }
    let Some(expected) = auth.csrf_token() else {
        return false;
    };
    secure_token_eq(csrf_header_token(headers), expected)
}

pub(crate) fn bool_header_is_true(headers: &HeaderMap, name: &str) -> bool {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .is_some_and(|value| {
            value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("yes") || value == "1"
        })
}

pub(crate) fn agent_mtls_request_verified(headers: &HeaderMap) -> bool {
    let verification_ok = headers
        .get(MTLS_VERIFY_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .is_some_and(|value| {
            value.eq_ignore_ascii_case("success") || value.eq_ignore_ascii_case("verified")
        });
    let cert_present = headers
        .get(MTLS_CERT_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .is_some_and(|value| {
            !value.is_empty() && !value.eq_ignore_ascii_case("none") && value != "-"
        })
        || bool_header_is_true(headers, MTLS_PRESENT_HEADER);
    verification_ok && cert_present
}

pub(crate) fn remote_ip(remote_addr: &str) -> &str {
    remote_addr
        .rsplit_once(':')
        .map(|(host, _)| host.trim_matches(['[', ']']))
        .unwrap_or(remote_addr)
}

pub(crate) fn trusted_mtls_proxy(config: &Config, remote_addr: &str) -> bool {
    let ip = remote_ip(remote_addr);
    config
        .security
        .trusted_mtls_proxy_addrs
        .iter()
        .any(|allowed| allowed.trim() == ip || allowed.trim() == remote_addr)
}

pub(crate) fn agent_mtls_request_trusted(headers: &HeaderMap, config: &Config, remote_addr: &str) -> bool {
    if !agent_mtls_request_verified(headers) {
        return false;
    }
    if is_production_env() {
        return trusted_mtls_proxy(config, remote_addr);
    }
    true
}

pub(crate) fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

pub(crate) fn path_agent_id(route_path: &str, suffix: &str) -> Option<String> {
    route_path
        .strip_prefix("/api/agents/")
        .and_then(|rest| rest.strip_suffix(suffix))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) fn requested_agent_id(
    method: &Method,
    url: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Option<String> {
    let route_path = url_path(url);
    if *method == Method::Post
        && let Some(agent_id) = path_agent_id(route_path, "/heartbeat")
    {
        return Some(agent_id);
    }
    if *method == Method::Post
        && let Some(agent_id) = path_agent_id(route_path, "/logs")
    {
        return Some(agent_id);
    }
    if *method == Method::Post
        && let Some(agent_id) = path_agent_id(route_path, "/inventory")
    {
        return Some(agent_id);
    }
    if route_path == "/api/agents/update" {
        return parse_query_string(url).get("agent_id").cloned();
    }
    if route_path == "/api/events" {
        return serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|value| {
                value
                    .get("agent_id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)
            });
    }
    header_value(headers, AGENT_ID_HEADER).map(str::to_string)
}

pub(crate) fn agent_request_bound_to_agent(
    method: &Method,
    url: &str,
    headers: &HeaderMap,
    body: &[u8],
    state: &Arc<Mutex<AppState>>,
) -> bool {
    let Some(header_agent_id) = header_value(headers, AGENT_ID_HEADER) else {
        return false;
    };
    let Some(agent_token) = header_value(headers, AGENT_TOKEN_HEADER) else {
        return false;
    };
    if let Some(requested_agent_id) = requested_agent_id(method, url, headers, body)
        && requested_agent_id != header_agent_id
    {
        return false;
    }
    let s = crate::state_lock::tracked_lock(state, "server/agent_identity_check");
    s.agent_registry
        .agent_token_matches(header_agent_id, agent_token)
}

pub(crate) fn session_store_path(config_path: &Path) -> String {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("var"))
        .join("sessions.json")
        .to_string_lossy()
        .to_string()
}

pub(crate) fn session_seal_key_path(config_path: &Path) -> String {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("var"))
        .join(".wardex_session_key")
        .to_string_lossy()
        .to_string()
}

pub(crate) fn harden_private_file_permissions(_path: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(_path, std::fs::Permissions::from_mode(0o600));
    }
}

pub(crate) fn load_or_create_session_seal_key(config_path: &Path) -> Vec<u8> {
    if let Ok(value) = std::env::var("WARDEX_SESSION_KEY") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return trimmed.as_bytes().to_vec();
        }
    }

    let path = session_seal_key_path(config_path);
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let trimmed = existing.trim().to_string();
        if !trimmed.is_empty() {
            harden_private_file_permissions(&path);
            return trimmed.into_bytes();
        }
    }

    let generated = generate_token();
    if let Some(parent) = Path::new(&path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&path, &generated);
    harden_private_file_permissions(&path);
    generated.into_bytes()
}

pub(crate) fn user_preferences_store_path(config_path: &Path) -> String {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("var"))
        .join("user_preferences.json")
        .to_string_lossy()
        .to_string()
}

pub(crate) fn detection_feedback_store_path(config_path: &Path) -> String {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("var"))
        .join("detection_feedback.json")
        .to_string_lossy()
        .to_string()
}

pub(crate) fn model_registry_path(config_path: &Path) -> String {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("var"))
        .join("models")
        .to_string_lossy()
        .to_string()
}

pub(crate) fn role_from_session_role(role: &str) -> Role {
    match role.trim().to_ascii_lowercase().as_str() {
        "admin" => Role::Admin,
        "analyst" => Role::Analyst,
        "service" | "serviceaccount" | "service_account" => Role::ServiceAccount,
        _ => Role::Viewer,
    }
}

pub(crate) fn role_label(role: Role) -> &'static str {
    match role {
        Role::Admin => "admin",
        Role::Analyst => "analyst",
        Role::Viewer => "viewer",
        Role::ServiceAccount => "service_account",
    }
}

pub(crate) fn playbook_status_label(status: &crate::playbook::ExecutionStatus) -> &'static str {
    match status {
        crate::playbook::ExecutionStatus::Pending => "pending",
        crate::playbook::ExecutionStatus::Running => "running",
        crate::playbook::ExecutionStatus::Succeeded => "succeeded",
        crate::playbook::ExecutionStatus::Failed => "failed",
        crate::playbook::ExecutionStatus::TimedOut => "timed_out",
        crate::playbook::ExecutionStatus::Skipped => "skipped",
        crate::playbook::ExecutionStatus::AwaitingApproval => "awaiting_approval",
        crate::playbook::ExecutionStatus::Cancelled => "cancelled",
    }
}

pub(crate) fn playbook_timestamp_to_rfc3339(value: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(value as i64)
        .unwrap_or_else(chrono::Utc::now)
        .to_rfc3339()
}

pub(crate) fn playbook_analytics_record_from_execution(
    execution: &crate::playbook::PlaybookExecution,
) -> crate::enterprise::PlaybookAnalyticsRecord {
    crate::enterprise::PlaybookAnalyticsRecord {
        execution_id: execution.execution_id.clone(),
        playbook_id: execution.playbook_id.clone(),
        alert_id: execution.alert_id.clone(),
        executed_by: execution.executed_by.clone(),
        status: playbook_status_label(&execution.status).to_string(),
        started_at: playbook_timestamp_to_rfc3339(execution.started_at),
        finished_at: execution.finished_at.map(playbook_timestamp_to_rfc3339),
        duration_ms: execution
            .finished_at
            .map(|finished_at| finished_at.saturating_sub(execution.started_at)),
        step_count: execution.step_results.len(),
        error: execution.error.clone(),
        recorded_at: playbook_timestamp_to_rfc3339(
            execution.finished_at.unwrap_or(execution.started_at),
        ),
    }
}

pub(crate) fn merge_playbook_history(
    persisted_history: &[crate::enterprise::PlaybookAnalyticsRecord],
    recent_executions: &[&crate::playbook::PlaybookExecution],
    limit: usize,
) -> Vec<crate::enterprise::PlaybookAnalyticsRecord> {
    let mut merged = persisted_history.to_vec();

    for execution in recent_executions {
        let record = playbook_analytics_record_from_execution(execution);
        if let Some(index) = merged
            .iter()
            .position(|entry| entry.execution_id == record.execution_id)
        {
            merged.remove(index);
        }
        merged.push(record);
    }

    merged.sort_by(|left, right| {
        left.recorded_at
            .cmp(&right.recorded_at)
            .then_with(|| left.execution_id.cmp(&right.execution_id))
    });

    if merged.len() > limit {
        let overflow = merged.len() - limit;
        merged.drain(0..overflow);
    }

    merged
}

pub(crate) fn ensure_target_group_access(
    auth: &AuthIdentity,
    target_group: Option<&str>,
) -> Result<(), String> {
    let Some(target_group) = target_group
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(());
    };
    match auth {
        AuthIdentity::SessionToken { groups, .. } => {
            if groups
                .iter()
                .any(|group| group.eq_ignore_ascii_case(target_group))
            {
                Ok(())
            } else {
                Err(format!(
                    "target group '{target_group}' is not assigned to the active session"
                ))
            }
        }
        _ => Ok(()),
    }
}

pub(crate) fn auth_identity_from_session(
    token: String,
    session: crate::auth::Session,
    cookie_authenticated: bool,
) -> AuthIdentity {
    AuthIdentity::SessionToken {
        user: User {
            username: session.user_id,
            role: role_from_session_role(&session.role),
            token_hash: token,
            enabled: true,
            created_at: session.created_at.to_rfc3339(),
            tenant_id: session.tenant_id,
        },
        groups: session.groups,
        csrf_token: session.csrf_token,
        cookie_authenticated,
    }
}

pub(crate) fn session_identity_from_store(
    token: String,
    state: &AppState,
    cookie_authenticated: bool,
) -> Option<AuthIdentity> {
    if let Some(session) = state.session_store.get_session(&token) {
        return Some(auth_identity_from_session(
            token,
            session,
            cookie_authenticated,
        ));
    }
    state.session_store.reload();
    state
        .session_store
        .get_session(&token)
        .map(|session| auth_identity_from_session(token, session, cookie_authenticated))
}

pub(crate) fn encode_query_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len() * 3);
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            b' ' => encoded.push('+'),
            _ => {
                encoded.push('%');
                encoded.push(char::from(b"0123456789ABCDEF"[(byte >> 4) as usize]));
                encoded.push(char::from(b"0123456789ABCDEF"[(byte & 0x0F) as usize]));
            }
        }
    }
    encoded
}

pub(crate) fn normalize_console_redirect(redirect_after: Option<String>) -> String {
    redirect_after
        .map(|value| value.trim().to_string())
        .filter(|value| value.starts_with('/') && !value.starts_with("//"))
        .unwrap_or_else(|| "/".to_string())
}

pub(crate) fn append_query_param(path: &str, key: &str, value: &str) -> String {
    let separator = if path.contains('?') { '&' } else { '?' };
    format!("{path}{separator}{key}={}", encode_query_component(value))
}

pub(crate) fn sso_error_redirect(redirect_after: Option<String>, message: &str) -> String {
    append_query_param(
        &normalize_console_redirect(redirect_after),
        "sso_error",
        message,
    )
}

pub(crate) fn session_cookie_header(session_id: &str, expires_at: chrono::DateTime<chrono::Utc>) -> String {
    let max_age = expires_at
        .signed_duration_since(chrono::Utc::now())
        .num_seconds()
        .max(0);
    let secure = session_cookie_secure();
    let secure_attr = if secure { "; Secure" } else { "" };
    format!(
        "{SESSION_COOKIE_NAME}={session_id}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure_attr}"
    )
}

pub(crate) fn clear_session_cookie_header() -> String {
    format!(
        "{SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
    )
}

pub(crate) fn is_production_env() -> bool {
    std::env::var("WARDEX_ENV")
        .map(|value| value.eq_ignore_ascii_case("production"))
        .unwrap_or(false)
}

pub(crate) fn env_bool(name: &str) -> Option<bool> {
    std::env::var(name)
        .ok()
        .and_then(|value| parse_bool_query(&value))
}

pub(crate) fn session_cookie_secure() -> bool {
    env_bool("WARDEX_SESSION_COOKIE_SECURE").unwrap_or_else(is_production_env)
}

pub(crate) fn apply_server_env_overrides(config: &mut Config) {
    if let Ok(token) = std::env::var("WARDEX_METRICS_TOKEN")
        && !token.trim().is_empty()
    {
        config.server.metrics_bearer_token = Some(token);
    }
    if let Some(public) = env_bool("WARDEX_OPENAPI_PUBLIC") {
        config.server.openapi_public = public;
    }
}

pub(crate) fn validate_production_trust_config(config: &Config) -> Result<(), String> {
    if !is_production_env() {
        return Ok(());
    }
    if std::env::var("WARDEX_ADMIN_TOKEN")
        .map(|token| token.trim().is_empty())
        .unwrap_or(true)
    {
        return Err("WARDEX_ENV=production requires explicit WARDEX_ADMIN_TOKEN".to_string());
    }
    if std::env::var("WARDEX_SPOOL_KEY")
        .map(|key| key.trim().is_empty())
        .unwrap_or(true)
    {
        return Err("WARDEX_ENV=production requires explicit WARDEX_SPOOL_KEY".to_string());
    }
    if std::env::var("WARDEX_OPENAPI_PUBLIC")
        .map(|value| value.trim().is_empty())
        .unwrap_or(true)
    {
        return Err(
            "WARDEX_ENV=production requires explicit WARDEX_OPENAPI_PUBLIC=true or false"
                .to_string(),
        );
    }
    if config
        .security
        .cors_allowed_origins
        .iter()
        .any(|origin| origin.trim() == "*")
        || std::env::var("WARDEX_CORS_ORIGIN")
            .or_else(|_| std::env::var("SENTINEL_CORS_ORIGIN"))
            .map(|origin| origin.trim() == "*")
            .unwrap_or(false)
    {
        return Err("WARDEX_ENV=production rejects wildcard CORS origins".to_string());
    }
    let has_agent_bearer = std::env::var("WARDEX_AGENT_TOKEN")
        .map(|token| !token.trim().is_empty())
        .unwrap_or(false);
    let has_mtls = config.security.require_mtls_agents
        && config
            .security
            .agent_ca_cert_path
            .as_deref()
            .is_some_and(|path| !path.trim().is_empty());
    let has_trusted_mtls_proxy = config
        .security
        .trusted_mtls_proxy_addrs
        .iter()
        .any(|addr| !addr.trim().is_empty());
    if !has_agent_bearer && !has_mtls {
        return Err(
            "WARDEX_ENV=production requires WARDEX_AGENT_TOKEN or configured agent mTLS"
                .to_string(),
        );
    }
    if has_mtls && !has_trusted_mtls_proxy {
        return Err(
            "WARDEX_ENV=production requires security.trusted_mtls_proxy_addrs when trusting agent mTLS headers"
                .to_string(),
        );
    }
    if config
        .server
        .metrics_bearer_token
        .as_deref()
        .is_none_or(|token| token.trim().is_empty())
    {
        return Err(
            "WARDEX_ENV=production requires server.metrics_bearer_token or WARDEX_METRICS_TOKEN"
                .to_string(),
        );
    }
    Ok(())
}

pub(crate) fn apply_set_cookie(mut response: Response<Body>, cookie: &str) -> Response<Body> {
    if let Ok(value) = cookie.parse() {
        response.headers_mut().insert(SET_COOKIE, value);
    }
    response
}

pub(crate) fn create_console_session_for_identity(
    state: &mut AppState,
    identity: &AuthIdentity,
) -> Option<(crate::auth::Session, String)> {
    let ttl_hours = (state.config.security.token_ttl_secs.max(1) / 3600).max(1) as i64;
    match identity {
        AuthIdentity::AdminToken => {
            let session_id = state.session_store.create_session(
                "admin",
                "admin@local.wardex",
                "admin",
                &["wardex-admins".to_string()],
                ttl_hours,
            );
            state
                .session_store
                .get_session(&session_id)
                .map(|session| (session, session_id))
        }
        AuthIdentity::UserToken(user) => {
            let role = role_label(user.role);
            let session_id = state.session_store.create_session(
                &user.username,
                &format!("{}@local.wardex", user.username),
                role,
                &[],
                ttl_hours,
            );
            state
                .session_store
                .get_session(&session_id)
                .map(|session| (session, session_id))
        }
        AuthIdentity::SessionToken { user, groups, .. } => {
            let role = role_label(user.role);
            let session_id = state.session_store.create_session_scoped(
                &user.username,
                &format!("{}@local.wardex", user.username),
                role,
                groups,
                user.tenant_id.clone(),
                ttl_hours,
            );
            state
                .session_store
                .get_session(&session_id)
                .map(|session| (session, session_id))
        }
        AuthIdentity::None => None,
    }
}

pub(crate) fn auth_redirect_response(location: &str) -> Response<Body> {
    safe_body(
        security_headers(Response::builder().status(StatusCode::FOUND)).header(LOCATION, location),
        Body::empty(),
    )
}

pub(crate) fn idp_provider_public_json(
    provider: &crate::enterprise::IdentityProviderConfig,
) -> serde_json::Value {
    let redirect_uri = provider.redirect_uri.as_deref().unwrap_or("").trim();
    let launch_checks = serde_json::json!({
        "metadata_configured": match provider.kind.as_str() {
            "oidc" => provider.issuer_url.as_deref().is_some_and(|value| !value.trim().is_empty()),
            "saml" => provider.sso_url.as_deref().is_some_and(|value| !value.trim().is_empty())
                && provider.entity_id.as_deref().is_some_and(|value| !value.trim().is_empty()),
            _ => false,
        },
        "callback_configured": !redirect_uri.is_empty(),
        "callback_route": "/api/auth/sso/callback",
        "callback_matches_console_route": redirect_uri.ends_with("/api/auth/sso/callback"),
        "client_credentials_present": provider.kind != "oidc"
            || (provider.client_id.as_deref().is_some_and(|value| !value.trim().is_empty())
                && provider.client_secret.as_deref().is_some_and(|value| !value.trim().is_empty())),
        "group_mappings": provider.group_role_mappings.len(),
        "test_login_path": format!("/api/auth/sso/login?provider_id={}", provider.id),
    });
    serde_json::json!({
        "id": provider.id,
        "kind": provider.kind,
        "display_name": provider.display_name,
        "issuer_url": provider.issuer_url,
        "sso_url": provider.sso_url,
        "client_id": provider.client_id,
        "redirect_uri": provider.redirect_uri,
        "entity_id": provider.entity_id,
        "enabled": provider.enabled,
        "status": provider.status,
        "group_role_mappings": provider.group_role_mappings,
        "updated_at": provider.updated_at,
        "launch_validation": launch_checks,
        "has_client_secret": provider
            .client_secret
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty()),
    })
}

pub(crate) fn idp_provider_summary_public_json(
    summary: &crate::enterprise::IdentityProviderSummary,
) -> serde_json::Value {
    let mut value = idp_provider_public_json(&summary.provider);
    if let Some(map) = value.as_object_mut() {
        map.insert(
            "validation".to_string(),
            serde_json::to_value(&summary.validation).unwrap_or(serde_json::Value::Null),
        );
    }
    value
}

pub(crate) fn validate_siem_config(config: &crate::siem::SiemConfig) -> Result<(), String> {
    if config.enabled
        && !config.endpoint.trim().is_empty()
        && !config.endpoint.starts_with("https://")
        && !config.endpoint.starts_with("http://")
    {
        return Err("SIEM endpoint must use http:// or https://".to_string());
    }
    config.validate()
}

pub(crate) fn siem_config_validation_json(
    config: &crate::siem::SiemConfig,
    last_error: Option<&str>,
) -> serde_json::Value {
    let mut issues = Vec::new();
    let mut has_error = false;

    if config.enabled {
        if let Err(error) = validate_siem_config(config) {
            has_error = true;
            issues.push(serde_json::json!({
                "level": "error",
                "field": "config",
                "message": error,
            }));
        }
        if let Some(error) = last_error.filter(|value| !value.trim().is_empty()) {
            issues.push(serde_json::json!({
                "level": "warning",
                "field": "connector",
                "message": error,
            }));
        }
    }

    let status = if !config.enabled {
        "disabled"
    } else if has_error {
        "error"
    } else if issues.is_empty() {
        "ready"
    } else {
        "warning"
    };

    serde_json::json!({
        "status": status,
        "issues": issues,
    })
}

pub(crate) fn normalize_siem_config_update(
    existing: &crate::siem::SiemConfig,
    mut candidate: crate::siem::SiemConfig,
) -> Result<crate::siem::SiemConfig, String> {
    if candidate.auth_token.trim().is_empty() && !existing.auth_token.trim().is_empty() {
        candidate.auth_token = existing.auth_token.clone();
    }
    validate_siem_config(&candidate)?;
    Ok(candidate)
}

pub(crate) fn build_oidc_provider_config(
    provider: &crate::enterprise::IdentityProviderConfig,
) -> Result<crate::oidc::OidcConfig, String> {
    let issuer = provider
        .issuer_url
        .clone()
        .filter(|value| !value.trim().is_empty())
        .ok_or("configured provider is missing an issuer_url")?;
    let client_id = provider
        .client_id
        .clone()
        .filter(|value| !value.trim().is_empty())
        .ok_or("configured provider is missing a client_id")?;
    let client_secret = provider
        .client_secret
        .clone()
        .filter(|value| !value.trim().is_empty())
        .ok_or("configured provider is missing a client_secret")?;
    let redirect_uri = provider
        .redirect_uri
        .clone()
        .filter(|value| !value.trim().is_empty())
        .ok_or("configured provider is missing a redirect_uri")?;

    Ok(crate::oidc::OidcConfig {
        issuer,
        client_id,
        client_secret,
        redirect_uri,
        scopes: vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
            "groups".to_string(),
        ],
        audience: None,
        enabled: provider.enabled,
        auto_provision: true,
        default_role: "viewer".to_string(),
        role_claim: "groups".to_string(),
        role_mapping: provider.group_role_mappings.clone(),
    })
}

pub(crate) fn oidc_provider_config_matches(
    provider: &crate::oidc::OidcProvider,
    desired: &crate::oidc::OidcConfig,
) -> bool {
    let current = provider.config();
    current.issuer == desired.issuer
        && current.client_id == desired.client_id
        && current.client_secret == desired.client_secret
        && current.redirect_uri == desired.redirect_uri
        && current.scopes == desired.scopes
        && current.audience == desired.audience
        && current.enabled == desired.enabled
        && current.auto_provision == desired.auto_provision
        && current.default_role == desired.default_role
        && current.role_claim == desired.role_claim
        && current.role_mapping == desired.role_mapping
}

pub(crate) fn select_ready_oidc_provider(
    app_state: &AppState,
    requested_provider: Option<&str>,
) -> Result<crate::enterprise::IdentityProviderConfig, String> {
    let ready_providers = app_state
        .enterprise
        .idp_provider_summaries()
        .into_iter()
        .filter(|summary| {
            summary.provider.enabled
                && summary.provider.kind.eq_ignore_ascii_case("oidc")
                && summary.validation.status == "ready"
        })
        .collect::<Vec<_>>();

    if let Some(provider_id) = requested_provider
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        ready_providers
            .into_iter()
            .find(|summary| summary.provider.id == provider_id)
            .map(|summary| summary.provider)
            .ok_or_else(|| format!("SSO provider '{provider_id}' is not configured for login"))
    } else {
        match ready_providers.as_slice() {
            [] => Err("no configured SSO providers are ready for login".to_string()),
            [summary] => Ok(summary.provider.clone()),
            _ => Err("multiple SSO providers are configured; specify provider_id".to_string()),
        }
    }
}

pub(crate) fn complete_sso_callback(
    state: &Arc<Mutex<AppState>>,
    provider_hint: Option<String>,
    code: &str,
    csrf_state: &str,
) -> Result<(crate::auth::Session, String, String), String> {
    let mut app_state = crate::state_lock::tracked_lock(state, "server/oidc_callback_exchange");
    let hinted_provider = provider_hint
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .and_then(|provider_id| {
            app_state
                .oidc_providers
                .get(provider_id)
                .and_then(|provider| {
                    provider
                        .has_pending_state(csrf_state)
                        .then(|| provider_id.to_string())
                })
        });
    let provider_id = hinted_provider.or_else(|| {
        app_state
            .oidc_providers
            .iter()
            .find_map(|(provider_id, provider)| {
                provider
                    .has_pending_state(csrf_state)
                    .then(|| provider_id.clone())
            })
    });
    let Some(provider_id) = provider_id else {
        return Err("state parameter is invalid or expired".to_string());
    };
    let provider = app_state
        .oidc_providers
        .get_mut(&provider_id)
        .ok_or_else(|| format!("SSO provider '{provider_id}' is no longer available"))?;
    if !provider.status().discovered {
        provider.discover()?;
    }
    let (sso_session, redirect_after) = provider.exchange_code(code, csrf_state)?;
    let user_id = sso_session
        .user_info
        .preferred_username
        .clone()
        .or_else(|| sso_session.user_info.email.clone())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| sso_session.user_info.sub.clone());
    let email = sso_session
        .user_info
        .email
        .clone()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| user_id.clone());
    let created_at =
        chrono::DateTime::<chrono::Utc>::from_timestamp(sso_session.created_at as i64, 0)
            .unwrap_or_else(chrono::Utc::now);
    let expires_at =
        chrono::DateTime::<chrono::Utc>::from_timestamp(sso_session.expires_at as i64, 0)
            .unwrap_or_else(chrono::Utc::now);
    let session = crate::auth::Session {
        user_id,
        email,
        role: sso_session.wardex_role.clone(),
        groups: sso_session.user_info.groups.clone(),
        tenant_id: sso_session
            .user_info
            .tenant_id
            .clone()
            .filter(|value| !value.trim().is_empty()),
        csrf_token: generate_token(),
        created_at,
        expires_at,
    };
    app_state
        .session_store
        .insert_session(sso_session.session_id.clone(), session.clone());
    Ok((
        session,
        sso_session.session_id,
        normalize_console_redirect(redirect_after),
    ))
}

pub(crate) fn authenticate_request(headers: &HeaderMap, state: &Arc<Mutex<AppState>>) -> AuthIdentity {
    if let Some(token) = bearer_token(headers) {
        let state = crate::state_lock::tracked_lock(state, "server/authenticate_request_bearer");
        let ttl = state.config.security.token_ttl_secs;
        if ttl == 0 || state.token_issued_at.elapsed().as_secs() <= ttl {
            let input = token.as_bytes();
            let expected = state.token.as_bytes();
            if input.len() == expected.len() {
                let mut diff = 0u8;
                for (a, b) in input.iter().zip(expected.iter()) {
                    diff |= a ^ b;
                }
                if diff == 0 {
                    return AuthIdentity::AdminToken;
                }
            }
        }
        if let Some(user) = state.rbac.authenticate(&token) {
            return AuthIdentity::UserToken(user);
        }
        if let Some(identity) = session_identity_from_store(token, &state, false) {
            return identity;
        }
    }
    if let Some(token) = session_cookie_token(headers) {
        let state = crate::state_lock::tracked_lock(state, "server/authenticate_request_session");
        if let Some(identity) = session_identity_from_store(token, &state, true) {
            return identity;
        }
    }
    AuthIdentity::None
}

pub(crate) fn response_requested_by(auth: &AuthIdentity) -> String {
    auth.actor().to_string()
}

pub(crate) fn response_approver(auth: &AuthIdentity) -> String {
    auth.actor().to_string()
}

pub(crate) fn playbook_executor(auth: &AuthIdentity) -> String {
    auth.actor().to_string()
}

pub(crate) fn live_response_operator(auth: &AuthIdentity) -> String {
    auth.actor().to_string()
}

pub(crate) fn host_platform_key(platform: HostPlatform) -> &'static str {
    match platform {
        HostPlatform::Linux => "linux",
        HostPlatform::MacOS => "macos",
        HostPlatform::Windows | HostPlatform::WindowsServer => "windows",
        HostPlatform::Unknown => "unknown",
    }
}

pub(crate) fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn decode_query_component(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                decoded.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                if let (Some(hi), Some(lo)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2])) {
                    decoded.push((hi << 4) | lo);
                    i += 3;
                } else {
                    decoded.push(bytes[i]);
                    i += 1;
                }
            }
            other => {
                decoded.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

pub(crate) fn parse_query_string(url: &str) -> HashMap<String, String> {
    let query = url.split('?').nth(1).unwrap_or("");
    let mut params = HashMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let mut parts = pair.splitn(2, '=');
        let key = parts.next().unwrap_or("");
        let value = parts.next().unwrap_or("");
        if !key.is_empty() {
            params.insert(decode_query_component(key), decode_query_component(value));
        }
    }
    params
}

pub(crate) fn url_path(url: &str) -> &str {
    url.split('?').next().unwrap_or(url)
}

pub(crate) fn url_param(url: &str, key: &str) -> Option<String> {
    parse_query_string(url)
        .get(key)
        .cloned()
        .filter(|v| !v.is_empty())
}

pub(crate) fn report_execution_context_filter_from_query(
    query: &HashMap<String, String>,
) -> crate::support::ReportExecutionContextFilter {
    crate::support::ReportExecutionContextFilter {
        case_id: query
            .get("case_id")
            .cloned()
            .filter(|value| !value.trim().is_empty()),
        incident_id: query
            .get("incident_id")
            .cloned()
            .filter(|value| !value.trim().is_empty()),
        investigation_id: query
            .get("investigation_id")
            .cloned()
            .filter(|value| !value.trim().is_empty()),
        source: query
            .get("source")
            .cloned()
            .filter(|value| !value.trim().is_empty()),
        scope: match query.get("scope").map(String::as_str) {
            Some("scoped") => crate::support::ReportExecutionScopeFilter::Scoped,
            Some("unscoped") => crate::support::ReportExecutionScopeFilter::Unscoped,
            _ => crate::support::ReportExecutionScopeFilter::All,
        },
    }
}

pub(crate) fn parse_numeric_segment<T: FromStr>(segment: &str) -> Option<T> {
    if segment.is_empty() || segment.contains('/') || !segment.chars().all(|ch| ch.is_ascii_digit())
    {
        return None;
    }
    segment.parse().ok()
}

pub(crate) fn parse_numeric_path_suffix<T: FromStr>(path: &str, prefix: &str) -> Option<T> {
    path.strip_prefix(prefix).and_then(parse_numeric_segment)
}

pub(crate) fn parse_numeric_path_between<T: FromStr>(path: &str, prefix: &str, suffix: &str) -> Option<T> {
    path.strip_prefix(prefix)
        .and_then(|rest| rest.strip_suffix(suffix))
        .map(|segment| segment.trim_end_matches('/'))
        .and_then(parse_numeric_segment)
}

pub(crate) fn parse_entity_profile_path(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("/api/entities/")?.trim_matches('/');
    let mut segments = rest.split('/');
    let kind = segments.next()?;
    let id = segments.next()?;
    if kind.is_empty() || id.is_empty() || segments.next().is_some() {
        return None;
    }
    Some((kind, id))
}

pub(crate) fn parse_entity_timeline_path(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("/api/entities/")?.trim_matches('/');
    let mut segments = rest.split('/');
    let kind = segments.next()?;
    let id = segments.next()?;
    let tail = segments.next()?;
    if kind.is_empty() || id.is_empty() || tail != "timeline" || segments.next().is_some() {
        return None;
    }
    Some((kind, id))
}

pub(crate) fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let parse = |value: &str| -> Vec<u32> {
        value
            .split('.')
            .map(|part| part.parse::<u32>().unwrap_or(0))
            .collect()
    };
    parse(a).cmp(&parse(b))
}

pub(crate) fn default_deployment_status() -> String {
    "assigned".to_string()
}

pub(crate) fn default_rollout_group() -> String {
    "direct".to_string()
}

pub(crate) fn normalize_rollout_group(value: Option<&str>) -> String {
    match value
        .unwrap_or("direct")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "canary" => "canary".to_string(),
        "ring-1" | "ring1" => "ring-1".to_string(),
        "ring-2" | "ring2" => "ring-2".to_string(),
        "direct" | "immediate" | "" => "direct".to_string(),
        other => other.to_string(),
    }
}

pub(crate) fn deployment_requires_action(
    deployment: &AgentDeployment,
    current_version: &str,
) -> bool {
    match compare_versions(&deployment.version, current_version) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => deployment.allow_downgrade,
        std::cmp::Ordering::Equal => false,
    }
}

pub(crate) const DEPLOYMENT_CAMPAIGN_STAGES: [&str; 8] = [
    "prepared",
    "sent",
    "installed",
    "enrolled",
    "healthy",
    "policy_synced",
    "telemetry_verified",
    "failed",
];

pub(crate) fn is_terminal_deployment_status(status: &str) -> bool {
    matches!(
        status.trim().to_ascii_lowercase().as_str(),
        "applied" | "completed" | "cancelled"
    )
}

pub(crate) fn deployment_is_pending(deployment: &AgentDeployment, registry: &AgentRegistry) -> bool {
    match registry.get(&deployment.agent_id) {
        Some(agent) => deployment_requires_action(deployment, &agent.version),
        None => !is_terminal_deployment_status(&deployment.status),
    }
}

pub(crate) fn deployment_failed_status(status: &str) -> bool {
    matches!(
        status.trim().to_ascii_lowercase().as_str(),
        "failed" | "error" | "cancelled"
    )
}

pub(crate) fn deployment_campaign_progress(
    computed_status: &str,
    age_secs: Option<u64>,
    heartbeat_interval: u64,
    deployment: Option<&AgentDeployment>,
    policy_version: u64,
) -> (String, serde_json::Value) {
    let prepared = deployment.is_some();
    let sent = prepared;
    let installed = deployment.is_some_and(|entry| {
        entry.acknowledged_at.is_some()
            || entry.completed_at.is_some()
            || matches!(
                entry.status.trim().to_ascii_lowercase().as_str(),
                "completed" | "applied" | "healthy"
            )
    });
    let deployment_failed = deployment
        .map(|entry| deployment_failed_status(&entry.status))
        .unwrap_or(false);
    let enrolled = true;
    let healthy = computed_status == "online" && !deployment_failed;
    let policy_synced = healthy
        && (policy_version == 0
            || deployment.is_none()
            || deployment.is_some_and(|entry| is_terminal_deployment_status(&entry.status)));
    let telemetry_verified =
        policy_synced && age_secs.unwrap_or(u64::MAX) <= heartbeat_interval.saturating_mul(2);
    let failed = deployment_failed;

    let current_state = if failed {
        "failed"
    } else if telemetry_verified {
        "telemetry_verified"
    } else if policy_synced {
        "policy_synced"
    } else if healthy {
        "healthy"
    } else if installed {
        "installed"
    } else if sent {
        "sent"
    } else if prepared {
        "prepared"
    } else if enrolled {
        "enrolled"
    } else {
        "prepared"
    };

    (
        current_state.to_string(),
        serde_json::json!({
            "prepared": prepared,
            "sent": sent,
            "installed": installed,
            "enrolled": enrolled,
            "healthy": healthy,
            "policy_synced": policy_synced,
            "telemetry_verified": telemetry_verified,
            "failed": failed,
        }),
    )
}

pub(crate) fn severity_rank(level: &str) -> u8 {
    match level.to_ascii_lowercase().as_str() {
        "critical" => 3,
        "severe" => 2,
        "elevated" => 1,
        _ => 0,
    }
}

pub(crate) fn severity_label(level: &str) -> &'static str {
    match severity_rank(level) {
        3 => "Critical",
        2 => "Severe",
        1 => "Elevated",
        _ => "Nominal",
    }
}

pub(crate) fn age_secs_since(timestamp: &str) -> Option<u64> {
    let parsed = chrono::DateTime::parse_from_rfc3339(timestamp).ok()?;
    let now = chrono::Utc::now();
    let seconds = now
        .signed_duration_since(parsed.with_timezone(&chrono::Utc))
        .num_seconds();
    Some(seconds.max(0) as u64)
}

pub(crate) fn computed_agent_status(
    agent: &AgentIdentity,
    heartbeat_interval: u64,
) -> (String, Option<u64>) {
    if matches!(agent.status, crate::enrollment::AgentStatus::Deregistered) {
        return ("deregistered".to_string(), age_secs_since(&agent.last_seen));
    }
    let age_secs = age_secs_since(&agent.last_seen);
    let stale_after = heartbeat_interval.saturating_mul(3);
    let offline_after = heartbeat_interval.saturating_mul(6);
    let status = match age_secs {
        Some(age) if age > offline_after => "offline",
        Some(age) if age > stale_after => "stale",
        Some(_) => "online",
        None => "unknown",
    };
    (status.to_string(), age_secs)
}

pub(crate) fn agent_summary_json(
    agent: &AgentIdentity,
    deployment: Option<&AgentDeployment>,
    heartbeat_interval: u64,
    policy_version: u64,
) -> serde_json::Value {
    let (computed_status_value, age_secs) = computed_agent_status(agent, heartbeat_interval);
    let (campaign_state, campaign_progress) = deployment_campaign_progress(
        &computed_status_value,
        age_secs,
        heartbeat_interval,
        deployment,
        policy_version,
    );
    serde_json::json!({
        "id": agent.id,
        "hostname": agent.hostname,
        "platform": agent.platform,
        "version": agent.version,
        "current_version": agent.version,
        "enrolled_at": agent.enrolled_at,
        "last_seen": agent.last_seen,
        "last_seen_age_secs": age_secs,
        "status": computed_status_value,
        "labels": agent.labels,
        "health": agent.health,
        "pending_alerts": agent.health.pending_alerts,
        "telemetry_queue_depth": agent.health.telemetry_queue_depth,
        "target_version": deployment
            .map(|entry| entry.version.clone())
            .or_else(|| agent.health.update_target_version.clone()),
        "rollout_group": deployment.map(|entry| entry.rollout_group.clone()),
        "deployment_status": deployment.map(|entry| entry.status.clone()),
        "campaign_state": campaign_state,
        "campaign_progress": campaign_progress,
        "scope_override": agent.monitor_scope.is_some(),
    })
}

pub(crate) fn path_health(path: &str) -> serde_json::Value {
    let path_ref = Path::new(path);
    match fs::metadata(path_ref) {
        Ok(metadata) => {
            let kind = if metadata.is_dir() {
                "directory"
            } else if metadata.is_file() {
                "file"
            } else {
                "other"
            };
            let readable = if metadata.is_dir() {
                fs::read_dir(path_ref).is_ok()
            } else {
                fs::File::open(path_ref).is_ok()
            };
            serde_json::json!({
                "path": path,
                "exists": true,
                "type": kind,
                "readable": readable,
                "health": if readable { "ok" } else { "restricted" },
                "note": if readable { "Path is available to the current process." } else { "Path exists but could not be read by the current process." },
            })
        }
        Err(_) => serde_json::json!({
            "path": path,
            "exists": false,
            "type": "missing",
            "readable": false,
            "health": "missing",
            "note": "Path is not present on this host.",
        }),
    }
}

pub(crate) fn parse_event_query(url: &str) -> EventQuery {
    let params = parse_query_string(url);
    let limit = params
        .get("limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(200)
        .clamp(1, 1000);
    EventQuery {
        agent_id: params
            .get("agent_id")
            .cloned()
            .filter(|value| !value.is_empty()),
        severity: params
            .get("severity")
            .cloned()
            .filter(|value| !value.is_empty()),
        reason: params
            .get("reason")
            .cloned()
            .filter(|value| !value.is_empty()),
        correlated: params
            .get("correlated")
            .and_then(|value| match value.as_str() {
                "true" | "1" => Some(true),
                "false" | "0" => Some(false),
                _ => None,
            }),
        triage_status: params
            .get("triage_status")
            .cloned()
            .filter(|value| !value.is_empty()),
        assignee: params
            .get("assignee")
            .cloned()
            .filter(|value| !value.is_empty()),
        tag: params.get("tag").cloned().filter(|value| !value.is_empty()),
        limit,
    }
}

pub(crate) fn event_matches_query(event: &crate::event_forward::StoredEvent, query: &EventQuery) -> bool {
    if let Some(agent_id) = &query.agent_id
        && &event.agent_id != agent_id
    {
        return false;
    }
    if let Some(severity) = &query.severity
        && !event.alert.level.eq_ignore_ascii_case(severity)
    {
        return false;
    }
    if let Some(reason) = &query.reason
        && !event
            .alert
            .reasons
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(reason))
    {
        return false;
    }
    if let Some(correlated) = query.correlated
        && event.correlated != correlated
    {
        return false;
    }
    if let Some(triage_status) = &query.triage_status
        && !event.triage.status.eq_ignore_ascii_case(triage_status)
    {
        return false;
    }
    if let Some(assignee) = &query.assignee
        && !event
            .triage
            .assignee
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case(assignee))
    {
        return false;
    }
    if let Some(tag) = &query.tag
        && !event
            .triage
            .tags
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(tag))
    {
        return false;
    }
    true
}

pub(crate) fn filtered_events<'a>(
    store: &'a EventStore,
    query: &EventQuery,
) -> Vec<&'a crate::event_forward::StoredEvent> {
    store
        .list(None, 10_000)
        .into_iter()
        .filter(|event| event_matches_query(event, query))
        .take(query.limit)
        .collect()
}

pub(crate) fn csv_escape(value: &str) -> String {
    // Strip CRLF injection vectors
    let sanitised = value.replace(['\r', '\n'], " ");
    let safe = sanitised.replace('"', "\"\"");
    // Prevent CSV formula injection — unconditionally prefix with single quote
    format!("\"'{}\"", safe)
}

pub(crate) fn ocsf_class_for_event(event: &crate::event_forward::StoredEvent) -> u32 {
    let reasons = event.alert.reasons.join(" ").to_lowercase();
    if reasons.contains("auth") || reasons.contains("login") || reasons.contains("credential") {
        3002 // Authentication
    } else if reasons.contains("network")
        || reasons.contains("connection")
        || reasons.contains("dns")
    {
        4001 // NetworkActivity
    } else {
        2004 // DetectionFinding (default)
    }
}

pub(crate) fn events_to_csv(events: &[&crate::event_forward::StoredEvent]) -> String {
    let mut out = String::from(
        "id,agent_id,received_at,level,score,confidence,correlated,triage_status,assignee,tags,reasons,hostname,platform,action,ocsf_class_id\n",
    );
    for event in events {
        let row = [
            event.id.to_string(),
            csv_escape(&event.agent_id),
            csv_escape(&event.received_at),
            csv_escape(&event.alert.level),
            event.alert.score.to_string(),
            event.alert.confidence.to_string(),
            event.correlated.to_string(),
            csv_escape(&event.triage.status),
            csv_escape(event.triage.assignee.as_deref().unwrap_or("")),
            csv_escape(&event.triage.tags.join("|")),
            csv_escape(&event.alert.reasons.join("|")),
            csv_escape(&event.alert.hostname),
            csv_escape(&event.alert.platform),
            csv_escape(&event.alert.action),
            ocsf_class_for_event(event).to_string(),
        ];
        out.push_str(&row.join(","));
        out.push('\n');
    }
    out
}

pub(crate) fn audit_entries_to_csv(entries: &[AuditEntry]) -> String {
    let mut out = String::from("timestamp,method,path,source_ip,status_code,auth_state\n");
    for entry in entries {
        let auth_state = if entry.auth_used {
            "authenticated"
        } else {
            "anonymous"
        };
        let row = [
            csv_escape(&entry.timestamp),
            csv_escape(&entry.method),
            csv_escape(&entry.path),
            csv_escape(&entry.source_ip),
            entry.status_code.to_string(),
            csv_escape(auth_state),
        ];
        out.push_str(&row.join(","));
        out.push('\n');
    }
    out
}

pub(crate) fn check_rbac(
    state: &Arc<Mutex<AppState>>,
    path: &str,
    method: &Method,
    auth: &AuthIdentity,
) -> bool {
    if auth.is_admin() {
        return true;
    }
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    let Some(user) = auth.user() else {
        return false;
    };
    let method_str = match method {
        Method::Get => "GET",
        Method::Post => "POST",
        Method::Put => "PUT",
        Method::Delete => "DELETE",
        _ => "GET",
    };
    if s.rbac.authenticate(&user.token_hash).is_some() {
        return s
            .rbac
            .check_api_access(&user.token_hash, method_str, path)
            .is_allowed();
    }
    let required = crate::rbac::endpoint_permission(method_str, path);
    role_permissions(user.role).contains(&required)
}

pub(crate) fn is_feature_enabled(state: &Arc<Mutex<AppState>>, feature: &str) -> bool {
    let s = crate::state_lock::tracked_lock(state, "server/is_feature_enabled");
    s.feature_flags.is_enabled(feature, "default")
}

pub(crate) fn load_remote_deployments(path: &str) -> HashMap<String, AgentDeployment> {
    match fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str(&raw).unwrap_or_default(),
        Err(_) => HashMap::new(),
    }
}

pub(crate) fn save_remote_deployments(path: &str, deployments: &HashMap<String, AgentDeployment>) {
    if let Ok(json) = serde_json::to_string_pretty(deployments) {
        let path_ref = Path::new(path);
        if let Some(parent) = path_ref.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let tmp = format!("{path}.tmp");
        if fs::write(&tmp, &json).is_ok() {
            let _ = fs::rename(&tmp, path_ref);
        }
    }
}

pub(crate) fn persist_config_to_path(config: &Config, path: &Path) -> Result<(), String> {
    let toml_str =
        toml::to_string_pretty(config).map_err(|e| format!("failed to serialize config: {e}"))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create config directory: {e}"))?;
    }
    let tmp = path.with_extension("toml.tmp");
    fs::write(&tmp, &toml_str).map_err(|e| format!("failed to write config: {e}"))?;
    fs::rename(&tmp, path).map_err(|e| format!("failed to finalize config write: {e}"))
}

pub(crate) fn sync_enterprise_sigma_engine(state: &mut AppState) {
    let effective_rules = state.enterprise.effective_sigma_rules();
    state.sigma_engine.replace_rules(effective_rules);
}

pub(crate) fn spawn_enterprise_hunt_scheduler(state: &Arc<Mutex<AppState>>) {
    let scheduler_state = Arc::clone(state);
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
            let mut s = match scheduler_state.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            if s.shutdown.load(Ordering::Relaxed) {
                break;
            }
            let due_hunt_ids = s.enterprise.due_hunt_ids();
            if due_hunt_ids.is_empty() {
                continue;
            }
            let events = s.event_store.all_events().to_vec();
            for hunt_id in due_hunt_ids {
                let started = std::time::Instant::now();
                if let Ok(run) = s.enterprise.run_hunt(&hunt_id, &events, None, None) {
                    let hunt = s
                        .enterprise
                        .hunts()
                        .iter()
                        .find(|hunt| hunt.id == run.hunt_id)
                        .cloned();
                    let response_results = if let Some(hunt) = hunt {
                        let AppState {
                            incident_store,
                            enterprise,
                            response_orchestrator,
                            ..
                        } = &mut *s;
                        let response_orchestrator_value = std::mem::take(response_orchestrator);
                        let results = execute_hunt_response_actions(
                            &hunt,
                            &run,
                            &events,
                            incident_store,
                            enterprise,
                            &response_orchestrator_value,
                            "system:scheduler",
                        );
                        *response_orchestrator = response_orchestrator_value;
                        results
                    } else {
                        Vec::new()
                    };
                    s.enterprise
                        .record_hunt_metrics(started.elapsed().as_millis() as u64);
                    if run.threshold_exceeded {
                        let payload = serde_json::json!({
                            "hunt_id": run.hunt_id,
                            "run_id": run.id,
                            "match_count": run.match_count,
                            "suppressed_count": run.suppressed_count,
                            "severity": run.severity,
                            "response_actions": response_results,
                        });
                        let payload_text = payload.to_string();
                        let _ = s.enterprise.record_change(
                            "hunt",
                            &run.hunt_id,
                            &format!(
                                "Scheduled hunt {} exceeded threshold with {} visible match(es)",
                                run.hunt_id, run.match_count
                            ),
                            "system:scheduler",
                            Some(run.id.clone()),
                            Some(&payload_text),
                        );
                    }
                }
            }
        }
    });
}

/// Background thread that runs retention purges every hour.
/// Reads the retention_policy table from SQLite and purges expired
/// alerts, audit entries, metrics, and response actions.
pub(crate) fn spawn_retention_purge_scheduler(state: &Arc<Mutex<AppState>>) {
    let scheduler_state = Arc::clone(state);
    std::thread::spawn(move || {
        // Default retention days per table (matches the retention_policy inserts in storage.rs)
        let defaults: &[(&str, u32)] = &[
            ("alerts", 90),
            ("audit_log", 365),
            ("metrics", 30),
            ("response_actions", 180),
        ];

        loop {
            // Run every hour (3600 seconds)
            std::thread::sleep(std::time::Duration::from_secs(3600));

            let s = match scheduler_state.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            if s.shutdown.load(Ordering::Relaxed) {
                break;
            }
            let storage = s.storage.clone();
            drop(s);

            let mut total_purged = 0usize;
            for &(table, default_days) in defaults {
                // Try to read configured retention from the policy table
                let days =
                    storage
                        .with(|store| {
                            let d = store.conn().query_row(
                            "SELECT retention_days FROM retention_policy WHERE table_name = ?1",
                            rusqlite::params![table],
                            |row| row.get::<_, u32>(0),
                        ).unwrap_or(default_days);
                            Ok(d)
                        })
                        .unwrap_or(default_days);

                let purged = match table {
                    "alerts" => storage
                        .with(|store| store.purge_old_alerts(days))
                        .unwrap_or(0),
                    "audit_log" => storage
                        .with(|store| store.purge_old_audit(days))
                        .unwrap_or(0),
                    "metrics" => storage
                        .with(|store| store.purge_old_metrics(days))
                        .unwrap_or(0),
                    "response_actions" => storage
                        .with(|store| store.purge_old_response_actions(days))
                        .unwrap_or(0),
                    _ => 0,
                };
                total_purged += purged;
            }

            if total_purged > 0 {
                log::info!("[RETENTION] purged {total_purged} expired records");
            }
        }
    });
}

pub(crate) fn read_json_value(body: &[u8], limit: usize) -> Result<serde_json::Value, String> {
    let body_str = read_body_limited(body, limit)?;
    serde_json::from_str::<serde_json::Value>(&body_str).map_err(|e| format!("invalid JSON: {e}"))
}

pub(crate) fn read_json_body<T: DeserializeOwned>(body: &[u8], limit: usize) -> Result<T, String> {
    let body_str = read_body_limited(body, limit)?;
    serde_json::from_str::<T>(&body_str).map_err(|e| format!("invalid JSON: {e}"))
}

pub(crate) const AWS_COLLECTOR_SETUP_KEY: &str = "integrations.collectors.aws";
pub(crate) const AZURE_COLLECTOR_SETUP_KEY: &str = "integrations.collectors.azure";
pub(crate) const GCP_COLLECTOR_SETUP_KEY: &str = "integrations.collectors.gcp";
pub(crate) const OKTA_COLLECTOR_SETUP_KEY: &str = "integrations.collectors.okta";
pub(crate) const ENTRA_COLLECTOR_SETUP_KEY: &str = "integrations.collectors.entra";
pub(crate) const M365_COLLECTOR_SETUP_KEY: &str = "integrations.collectors.m365";
pub(crate) const WORKSPACE_COLLECTOR_SETUP_KEY: &str = "integrations.collectors.workspace";
pub(crate) const GITHUB_COLLECTOR_SETUP_KEY: &str = "integrations.collectors.github";
pub(crate) const CROWDSTRIKE_COLLECTOR_SETUP_KEY: &str = "integrations.collectors.crowdstrike";
pub(crate) const SYSLOG_COLLECTOR_SETUP_KEY: &str = "integrations.collectors.syslog";
pub(crate) const SECRETS_MANAGER_SETUP_KEY: &str = "integrations.secrets.manager";
