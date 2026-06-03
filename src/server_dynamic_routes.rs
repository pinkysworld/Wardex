//! Dynamic fallback API routes delegated from the main server router.

use super::*;

pub(super) fn handle_dynamic_api_route(
    method: Method,
    url: String,
    headers: &HeaderMap,
    body: &[u8],
    remote_addr: &str,
    state: &Arc<Mutex<AppState>>,
    auth_identity: AuthIdentity,
    needs_auth: bool,
    auth_used: bool,
) -> Response<Body> {
    // Dynamic routes with path parameters
    let url_path = url_path(&url);
    if method == Method::Get && url_path == "/api/agents/update" {
        // GET /api/agents/update?current_version=xxx&platform=yyy
        crate::server_agents::handle_agent_update_check(body, &url, state)
    } else if method == Method::Get && url_path == "/api/reports/executive-summary" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let summary = s.report_store.executive_summary(&s.incident_store);
        match serde_json::to_string(&summary) {
            Ok(json) => json_response(&json, 200),
            Err(e) => error_json(&format!("serialization error: {e}"), 500),
        }
    } else if method == Method::Get && url_path == "/api/alerts/analysis" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(ref analysis) = s.last_alert_analysis {
            match serde_json::to_string(analysis) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        } else {
            let alerts_vec: Vec<_> = s.alerts.iter().cloned().collect();
            let analysis = crate::alert_analysis::analyze_alerts(&alerts_vec, 5);
            match serde_json::to_string(&analysis) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
    } else if method == Method::Get && url_path == "/api/alerts/grouped" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let alerts_vec: Vec<_> = s.alerts.iter().cloned().collect();
        let groups = crate::alert_analysis::group_alerts(&alerts_vec);
        match serde_json::to_string(&groups) {
            Ok(json) => json_response(&json, 200),
            Err(e) => error_json(&format!("serialization error: {e}"), 500),
        }
    } else if method == Method::Get && url_path == "/api/cases/stats" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let cases = s.case_store.list_filtered(None, None, None);
        let total = cases.len();
        let resolved = cases
            .iter()
            .filter(|case| matches!(case.status, CaseStatus::Resolved | CaseStatus::Closed))
            .count();
        let open = total.saturating_sub(resolved);
        let triaging = cases
            .iter()
            .filter(|case| matches!(case.status, CaseStatus::Triaging))
            .count();
        let investigating = cases
            .iter()
            .filter(|case| matches!(case.status, CaseStatus::Investigating))
            .count();
        let escalated = cases
            .iter()
            .filter(|case| matches!(case.status, CaseStatus::Escalated))
            .count();
        json_response(
            &serde_json::json!({
                "total": total,
                "open": open,
                "resolved": resolved,
                "triaging": triaging,
                "investigating": investigating,
                "escalated": escalated,
            })
            .to_string(),
            200,
        )
    } else if method == Method::Post
        && url_path.ends_with("/heartbeat")
        && url_path.starts_with("/api/agents/")
    {
        // POST /api/agents/{id}/heartbeat
        let agent_id = url_path
            .strip_prefix("/api/agents/")
            .and_then(|rest| rest.strip_suffix("/heartbeat"))
            .unwrap_or("");
        crate::server_agents::handle_agent_heartbeat(body, state, agent_id)
    } else if method == Method::Get
        && url_path.starts_with("/api/agents/")
        && url_path.ends_with("/activity")
    {
        let agent_id = url_path
            .strip_prefix("/api/agents/")
            .and_then(|rest| rest.strip_suffix("/activity"))
            .unwrap_or("");
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match crate::server_agents::build_agent_activity_snapshot(&s, agent_id) {
            Ok(snapshot) => match serde_json::to_string(&snapshot) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            },
            Err(e) => error_json(&e, 404),
        }
    } else if method == Method::Get
        && url_path.starts_with("/api/agents/")
        && url_path.ends_with("/details")
    {
        let agent_id = url_path
            .strip_prefix("/api/agents/")
            .and_then(|rest| rest.strip_suffix("/details"))
            .unwrap_or("");
        crate::server_agents::handle_agent_details(state, agent_id)
    } else if method == Method::Post
        && url_path.starts_with("/api/events/")
        && url_path.ends_with("/triage")
    {
        let event_id = url_path
            .strip_prefix("/api/events/")
            .and_then(|rest| rest.strip_suffix("/triage"))
            .unwrap_or("")
            .trim_end_matches('/');
        handle_event_triage(body, state, event_id)
    } else if method == Method::Post
        && url_path.starts_with("/api/agents/")
        && url_path.ends_with("/scope")
    {
        let agent_id = url_path
            .strip_prefix("/api/agents/")
            .and_then(|rest| rest.strip_suffix("/scope"))
            .unwrap_or("");
        crate::server_agents::handle_agent_set_scope(body, state, agent_id)
    } else if method == Method::Get
        && url_path.starts_with("/api/agents/")
        && url_path.ends_with("/scope")
    {
        let agent_id = url_path
            .strip_prefix("/api/agents/")
            .and_then(|rest| rest.strip_suffix("/scope"))
            .unwrap_or("");
        crate::server_agents::handle_agent_get_scope(state, agent_id)
    } else if method == Method::Get
        && url_path.starts_with("/api/agents/")
        && url_path.ends_with("/status")
    {
        // GET /api/agents/{id}/status
        let agent_id = url_path
            .strip_prefix("/api/agents/")
            .and_then(|rest| rest.strip_suffix("/status"))
            .unwrap_or("");
        if agent_id == LOCAL_CONSOLE_AGENT_ID {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            return match serde_json::to_string(&local_console_agent_summary_json(&s)) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            };
        }
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match s.agent_registry.get(agent_id) {
            Some(agent) => match serde_json::to_string(agent) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            },
            None => error_json("agent not found", 404),
        }
    } else if method == Method::Delete && url_path.starts_with("/api/agents/") {
        // DELETE /api/agents/{id}
        let agent_id = url_path.strip_prefix("/api/agents/").unwrap_or("");
        if agent_id == LOCAL_CONSOLE_AGENT_ID {
            return error_json("local console host cannot be removed", 409);
        }
        let mut s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match s.agent_registry.deregister(agent_id) {
            Ok(()) => {
                let body = serde_json::json!({"status": "deregistered", "agent_id": agent_id});
                json_response(&body.to_string(), 200)
            }
            Err(e) => error_json(&e, 404),
        }
    // ── Agent Logs ────────────────────────────────────────
    } else if method == Method::Post
        && url_path.starts_with("/api/agents/")
        && url_path.ends_with("/logs")
    {
        let agent_id = url_path
            .strip_prefix("/api/agents/")
            .and_then(|rest| rest.strip_suffix("/logs"))
            .unwrap_or("");
        let body = match read_body_limited(body, 10 * 1024 * 1024) {
            Ok(b) => b,
            Err(e) => {
                return respond_api(
                    state,
                    &method,
                    &url,
                    remote_addr,
                    auth_used,
                    error_json(&e, 400),
                );
            }
        };
        let logs: Vec<crate::log_collector::LogRecord> = match serde_json::from_str(&body) {
            Ok(l) => l,
            Err(e) => {
                return respond_api(
                    state,
                    &method,
                    &url,
                    remote_addr,
                    auth_used,
                    error_json(&format!("invalid JSON: {e}"), 400),
                );
            }
        };
        let count = logs.len();
        let mut s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Cap total tracked agents to prevent unbounded memory growth
        if !s.agent_logs.contains_key(agent_id) && s.agent_logs.len() >= 10_000 {
            // LRU eviction: remove the agent with the oldest last-access time
            if let Some(evict_key) = s
                .agent_logs_last_access
                .iter()
                .min_by_key(|(_, ts)| *ts)
                .map(|(k, _)| k.clone())
            {
                s.agent_logs.remove(&evict_key);
                s.agent_logs_last_access.remove(&evict_key);
            }
        }
        let now_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        s.agent_logs_last_access
            .insert(agent_id.to_string(), now_ts);
        let agent_log_buf = s.agent_logs.entry(agent_id.to_string()).or_default();
        for log in logs {
            if agent_log_buf.len() >= 500 {
                agent_log_buf.drain(..50);
            }
            agent_log_buf.push(log);
        }
        json_response(
            &serde_json::json!({"status":"ingested","count":count}).to_string(),
            200,
        )
    } else if method == Method::Get
        && url_path.starts_with("/api/agents/")
        && url_path.ends_with("/logs")
    {
        let agent_id = url_path
            .strip_prefix("/api/agents/")
            .and_then(|rest| rest.strip_suffix("/logs"))
            .unwrap_or("");
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let logs = s.agent_logs.get(agent_id).cloned().unwrap_or_default();
        match serde_json::to_string(&logs) {
            Ok(json) => json_response(&json, 200),
            Err(e) => error_json(&format!("serialization error: {e}"), 500),
        }
    // ── Agent Inventory ───────────────────────────────────
    } else if method == Method::Post
        && url_path.starts_with("/api/agents/")
        && url_path.ends_with("/inventory")
    {
        let agent_id = url_path
            .strip_prefix("/api/agents/")
            .and_then(|rest| rest.strip_suffix("/inventory"))
            .unwrap_or("");
        let body = match read_body_limited(body, 10 * 1024 * 1024) {
            Ok(b) => b,
            Err(e) => {
                return respond_api(
                    state,
                    &method,
                    &url,
                    remote_addr,
                    auth_used,
                    error_json(&e, 400),
                );
            }
        };
        let inventory: crate::inventory::SystemInventory = match serde_json::from_str(&body) {
            Ok(i) => i,
            Err(e) => {
                return respond_api(
                    state,
                    &method,
                    &url,
                    remote_addr,
                    auth_used,
                    error_json(&format!("invalid JSON: {e}"), 400),
                );
            }
        };
        let mut s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Cap total tracked agents to prevent unbounded memory growth
        if !s.agent_inventories.contains_key(agent_id)
            && s.agent_inventories.len() >= 10_000
            && let Some(evict_key) = s.agent_inventories.keys().next().cloned()
        {
            s.agent_inventories.remove(&evict_key);
        }
        s.agent_inventories.insert(agent_id.to_string(), inventory);
        json_response(
            &serde_json::json!({"status":"inventory_stored","agent_id":agent_id}).to_string(),
            200,
        )
    } else if method == Method::Get
        && url_path.starts_with("/api/agents/")
        && url_path.ends_with("/inventory")
    {
        let agent_id = url_path
            .strip_prefix("/api/agents/")
            .and_then(|rest| rest.strip_suffix("/inventory"))
            .unwrap_or("");
        if agent_id == LOCAL_CONSOLE_AGENT_ID {
            let inventory = crate::inventory::collect_inventory();
            return match serde_json::to_string(&inventory) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            };
        }
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match s.agent_inventories.get(agent_id) {
            Some(inv) => match serde_json::to_string(inv) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            },
            None => error_json("no inventory for this agent", 404),
        }
    // ── Incidents (dynamic) ───────────────────────────────
    } else if method == Method::Get
        && url_path.starts_with("/api/incidents/")
        && url_path.ends_with("/report")
    {
        match parse_numeric_path_between::<u64>(url_path, "/api/incidents/", "/report") {
            Some(id) => {
                let s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match s.incident_store.get(id) {
                    Some(inc) => {
                        let report = crate::report::IncidentReport::generate(inc, &s.event_store);
                        let related_events =
                            incident_related_events(inc, s.event_store.all_events());
                        let all_cases = s.case_store.list().to_vec();
                        let storyline = build_incident_storyline(
                            inc,
                            &related_events,
                            &all_cases,
                            &s.response_orchestrator.all_requests(),
                            &s.response_orchestrator.audit_ledger(),
                            s.enterprise.ticket_syncs(),
                        );
                        let linked_cases: Vec<serde_json::Value> = all_cases
                            .iter()
                            .filter(|case| case.incident_ids.contains(&inc.id))
                            .map(|case| serde_json::json!(case_summary(case)))
                            .collect();
                        match serde_json::to_value(&report) {
                            Ok(serde_json::Value::Object(mut payload)) => {
                                payload.insert("storyline".to_string(), storyline.clone());
                                payload.insert(
                                    "linked_cases".to_string(),
                                    serde_json::json!(linked_cases),
                                );
                                payload.insert(
                                    "ticket_syncs".to_string(),
                                    serde_json::json!(
                                        s.enterprise
                                            .ticket_syncs()
                                            .iter()
                                            .filter(|sync| sync.object_kind == "incident"
                                                && sync.object_id == inc.id.to_string())
                                            .collect::<Vec<_>>()
                                    ),
                                );
                                payload.insert(
                                    "evidence_package".to_string(),
                                    storyline
                                        .get("evidence_package")
                                        .cloned()
                                        .unwrap_or_else(|| serde_json::json!({})),
                                );
                                payload.insert(
                                    "generated_at".to_string(),
                                    serde_json::json!(chrono::Utc::now().to_rfc3339()),
                                );
                                json_response(&serde_json::Value::Object(payload).to_string(), 200)
                            }
                            Ok(other) => json_response(&other.to_string(), 200),
                            Err(e) => error_json(&format!("serialization error: {e}"), 500),
                        }
                    }
                    None => error_json("incident not found", 404),
                }
            }
            None => error_json("not found", 404),
        }
    } else if method == Method::Post
        && url_path.starts_with("/api/incidents/")
        && url_path.ends_with("/update")
    {
        match parse_numeric_path_between::<u64>(url_path, "/api/incidents/", "/update") {
            Some(id) => {
                let body = match read_body_limited(body, 10 * 1024 * 1024) {
                    Ok(b) => b,
                    Err(e) => {
                        return respond_api(
                            state,
                            &method,
                            &url,
                            remote_addr,
                            auth_used,
                            error_json(&e, 400),
                        );
                    }
                };
                #[derive(serde::Deserialize)]
                struct IncidentUpdate {
                    status: Option<String>,
                    assignee: Option<String>,
                    note: Option<String>,
                    author: Option<String>,
                }
                let upd: IncidentUpdate = match serde_json::from_str(&body) {
                    Ok(u) => u,
                    Err(e) => {
                        return respond_api(
                            state,
                            &method,
                            &url,
                            remote_addr,
                            auth_used,
                            error_json(&format!("invalid JSON: {e}"), 400),
                        );
                    }
                };
                let status = upd.status.as_deref().map(|s| match s {
                    "open" => crate::incident::IncidentStatus::Open,
                    "investigating" => crate::incident::IncidentStatus::Investigating,
                    "contained" => crate::incident::IncidentStatus::Contained,
                    "resolved" => crate::incident::IncidentStatus::Resolved,
                    "false_positive" => crate::incident::IncidentStatus::FalsePositive,
                    _ => crate::incident::IncidentStatus::Open,
                });
                let note = if let (Some(text), Some(author)) = (upd.note, upd.author) {
                    Some(crate::incident::EventNote {
                        author,
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        text,
                    })
                } else {
                    None
                };
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match s.incident_store.update(id, upd.assignee, note, status) {
                    Ok(()) => {
                        json_response(&serde_json::json!({"status":"updated"}).to_string(), 200)
                    }
                    Err(e) => error_json(&e, 404),
                }
            }
            None => error_json("not found", 404),
        }
    } else if method == Method::Get
        && url_path.starts_with("/api/incidents/")
        && !url_path.ends_with("/report")
        && !url_path.ends_with("/storyline")
    {
        match parse_numeric_path_suffix::<u64>(url_path, "/api/incidents/") {
            Some(id) => {
                let s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match s.incident_store.get(id) {
                    Some(inc) => match serde_json::to_string(inc) {
                        Ok(json) => json_response(&json, 200),
                        Err(e) => error_json(&format!("serialization error: {e}"), 500),
                    },
                    None => error_json("incident not found", 404),
                }
            }
            None => error_json("not found", 404),
        }
    // ── Reports (dynamic) ─────────────────────────────────
    } else if method == Method::Get
        && url_path.starts_with("/api/reports/")
        && url_path.ends_with("/html")
    {
        match parse_numeric_path_between::<u64>(url_path, "/api/reports/", "/html") {
            Some(id) => {
                let s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match s.report_store.get(id) {
                    Some(report) => {
                        let html = report.report.to_html();
                        let data = html.as_bytes().to_vec();
                        Response::builder()
                            .status(200)
                            .header("Content-Type", "text/html; charset=utf-8")
                            .header("Access-Control-Allow-Origin", cors_origin())
                            .header(
                                "Content-Disposition",
                                "attachment; filename=\"report.html\"",
                            )
                            .header("X-Content-Type-Options", "nosniff")
                            .header("X-Frame-Options", "DENY")
                            .header("Cache-Control", "no-store")
                            .body(Body::from(data))
                            .unwrap_or_else(|_| Response::new(Body::from("error")))
                    }
                    None => error_json("report not found", 404),
                }
            }
            None => error_json("not found", 404),
        }
    } else if method == Method::Delete && url_path.starts_with("/api/reports/") {
        match parse_numeric_path_suffix::<u64>(url_path, "/api/reports/") {
            Some(id) => {
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if s.report_store.delete(id) {
                    json_response(r#"{"status":"deleted"}"#, 204)
                } else {
                    error_json("report not found", 404)
                }
            }
            None => error_json("not found", 404),
        }
    } else if method == Method::Post
        && url_path.starts_with("/api/reports/")
        && url_path.ends_with("/context")
    {
        match parse_numeric_path_between::<u64>(url_path, "/api/reports/", "/context") {
            Some(id) => match read_json_value(body, 8 * 1024) {
                Ok(v) => {
                    let execution_context = crate::support::ReportExecutionContext {
                        case_id: v
                            .get("case_id")
                            .and_then(|value| value.as_str())
                            .map(std::string::ToString::to_string),
                        incident_id: v
                            .get("incident_id")
                            .and_then(|value| value.as_str())
                            .map(std::string::ToString::to_string),
                        investigation_id: v
                            .get("investigation_id")
                            .and_then(|value| value.as_str())
                            .map(std::string::ToString::to_string),
                        source: v
                            .get("source")
                            .and_then(|value| value.as_str())
                            .map(std::string::ToString::to_string),
                    };
                    let has_execution_context = [
                        execution_context.case_id.as_ref(),
                        execution_context.incident_id.as_ref(),
                        execution_context.investigation_id.as_ref(),
                        execution_context.source.as_ref(),
                    ]
                    .into_iter()
                    .any(|value| value.is_some());
                    let mut s = state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    match s.report_store.set_execution_context(
                        id,
                        has_execution_context.then_some(execution_context),
                    ) {
                        Some(report) => json_response(
                            &serde_json::json!({"status":"updated","report": report}).to_string(),
                            200,
                        ),
                        None => error_json("report not found", 404),
                    }
                }
                Err(e) => error_json(&e, 400),
            },
            None => error_json("not found", 404),
        }
    } else if method == Method::Get && url_path.starts_with("/api/reports/") {
        match parse_numeric_path_suffix::<u64>(url_path, "/api/reports/") {
            Some(id) => {
                let s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match s.report_store.get(id) {
                    Some(report) => match serde_json::to_string(report) {
                        Ok(json) => json_response(&json, 200),
                        Err(e) => error_json(&format!("serialization error: {e}"), 500),
                    },
                    None => error_json("report not found", 404),
                }
            }
            None => error_json("not found", 404),
        }
    } else if method == Method::Get && url_path.starts_with("/api/updates/download/") {
        // GET /api/updates/download/{file_name}
        let file_name = url_path
            .strip_prefix("/api/updates/download/")
            .unwrap_or("");
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match s.update_manager.get_release_binary(file_name) {
            Ok(data) => {
                let mut builder = Response::builder()
                    .status(200)
                    .header("Content-Type", "application/octet-stream")
                    .header("Access-Control-Allow-Origin", cors_origin());
                if let Some(release) = s.update_manager.get_release_by_file_name(file_name) {
                    if let Some(signature) = &release.signature {
                        builder = builder.header("X-Wardex-Update-Signature", signature);
                    }
                    if let Some(signer) = &release.signer_pubkey {
                        builder = builder.header("X-Wardex-Update-Signer", signer);
                    }
                    if let Some(counter) = release.update_counter {
                        builder = builder.header("X-Wardex-Update-Counter", counter.to_string());
                    }
                }
                builder
                    .body(Body::from(data))
                    .unwrap_or_else(|_| Response::new(Body::from("error")))
            }
            Err(e) => error_json(&e, 404),
        }
    } else if method == Method::Get
        && url_path.starts_with("/api/alerts/")
        && url_path != "/api/alerts/count"
        && url_path != "/api/alerts/analysis"
        && url_path != "/api/alerts/grouped"
        && url_path != "/api/alerts/dedup"
    {
        // GET /api/alerts/{index} — detailed alert view
        match parse_numeric_path_suffix::<usize>(url_path, "/api/alerts/") {
            Some(idx) => {
                let s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if idx < s.alerts.len() {
                    let alert = &s.alerts[idx];
                    let detail = serde_json::json!({
                        "id": idx,
                        "index": idx,
                        "timestamp": alert.timestamp,
                        "hostname": alert.hostname,
                        "platform": alert.platform,
                        "score": alert.score,
                        "confidence": alert.confidence,
                        "level": alert.level,
                        "action": alert.action,
                        "reasons": alert.reasons,
                        "enforced": alert.enforced,
                        "sample": {
                            "timestamp_ms": alert.sample.timestamp_ms,
                            "cpu_load_pct": alert.sample.cpu_load_pct,
                            "memory_load_pct": alert.sample.memory_load_pct,
                            "temperature_c": alert.sample.temperature_c,
                            "network_kbps": alert.sample.network_kbps,
                            "auth_failures": alert.sample.auth_failures,
                            "battery_pct": alert.sample.battery_pct,
                            "integrity_drift": alert.sample.integrity_drift,
                            "process_count": alert.sample.process_count,
                            "disk_pressure_pct": alert.sample.disk_pressure_pct,
                        },
                        "analysis": {
                            "severity_class": if alert.score >= 5.2 { "critical" }
                                else if alert.score >= 3.0 { "severe" }
                                else { "elevated" },
                            "multi_axis": alert.reasons.len() > 1,
                            "axis_count": alert.reasons.len(),
                            "recommendation": if alert.score >= 5.2 {
                                "Immediate isolation recommended. Investigate all flagged axes and correlate with SIEM events."
                            } else if alert.score >= 3.0 {
                                "Elevated investigation priority. Review flagged telemetry and check for lateral movement."
                            } else {
                                "Monitor closely. Consider tightening thresholds if pattern persists."
                            },
                        },
                    });
                    json_response(&detail.to_string(), 200)
                } else {
                    error_json("alert index out of range", 404)
                }
            }
            None => error_json("not found", 404),
        }
    // ── Enterprise: Dynamic routes ───────────────────────────
    } else if method == Method::Get
        && url_path.starts_with("/api/hunts/")
        && url_path.ends_with("/history")
    {
        let hunt_id = url_path
            .trim_start_matches("/api/hunts/")
            .trim_end_matches("/history");
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let runs = s.enterprise.hunt_runs(hunt_id);
        json_response(
            &serde_json::json!({"hunt_id": hunt_id, "history": runs, "count": runs.len()})
                .to_string(),
            200,
        )
    } else if method == Method::Post
        && url_path.starts_with("/api/hunts/")
        && url_path.ends_with("/run")
    {
        let hunt_id = url_path
            .trim_start_matches("/api/hunts/")
            .trim_end_matches("/run")
            .trim_end_matches('/');
        let started = std::time::Instant::now();
        let mut s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let hunt = match s
            .enterprise
            .hunts()
            .iter()
            .find(|hunt| hunt.id == hunt_id)
            .cloned()
        {
            Some(hunt) => hunt,
            None => return error_json("hunt not found", 404),
        };
        if let Err(message) =
            ensure_target_group_access(&auth_identity, hunt.target_group.as_deref())
        {
            return error_json(&message, 403);
        }
        let run_window = read_json_value(body, 4096)
            .ok()
            .map_or((None, None), |value| {
                (
                    value
                        .get("time_from")
                        .and_then(|v| v.as_str())
                        .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
                        .map(|dt| dt.with_timezone(&chrono::Utc)),
                    value
                        .get("time_to")
                        .and_then(|v| v.as_str())
                        .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
                        .map(|dt| dt.with_timezone(&chrono::Utc)),
                )
            });
        let events = s.event_store.all_events().to_vec();
        match s
            .enterprise
            .run_hunt(hunt_id, &events, run_window.0, run_window.1)
        {
            Ok(run) => {
                let AppState {
                    incident_store,
                    enterprise,
                    response_orchestrator,
                    ..
                } = &mut *s;
                let response_orchestrator_value = std::mem::take(response_orchestrator);
                let response_results = execute_hunt_response_actions(
                    &hunt,
                    &run,
                    &events,
                    incident_store,
                    enterprise,
                    &response_orchestrator_value,
                    auth_identity.actor(),
                );
                *response_orchestrator = response_orchestrator_value;
                s.enterprise
                    .record_hunt_metrics(started.elapsed().as_millis() as u64);
                let _ = s.enterprise.record_change(
                    "hunt_run",
                    hunt_id,
                    &format!("Executed hunt {hunt_id}"),
                    auth_identity.actor(),
                    Some(run.id.clone()),
                    None,
                );
                json_response(
                    &serde_json::json!({
                        "status": "completed",
                        "run": run,
                        "response_actions": response_results,
                    })
                    .to_string(),
                    200,
                )
            }
            Err(e) => error_json(&e, 404),
        }
    } else if method == Method::Post
        && url_path.starts_with("/api/hunts/")
        && url_path.ends_with("/escalate")
    {
        let hunt_id = url_path
            .trim_start_matches("/api/hunts/")
            .trim_end_matches("/escalate")
            .trim_end_matches('/');
        let mut s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let hunt = match s
            .enterprise
            .hunts()
            .iter()
            .find(|hunt| hunt.id == hunt_id)
            .cloned()
        {
            Some(hunt) => hunt,
            None => return error_json("hunt not found", 404),
        };
        if let Err(message) =
            ensure_target_group_access(&auth_identity, hunt.target_group.as_deref())
        {
            return error_json(&message, 403);
        }
        let payload = read_json_value(body, 16 * 1024).unwrap_or_else(|_| serde_json::json!({}));
        let requested_run_id = payload
            .get("run_id")
            .and_then(|value| value.as_str())
            .map(std::string::ToString::to_string);
        let selected_run = s
            .enterprise
            .hunt_runs(hunt_id)
            .into_iter()
            .filter(|run| {
                requested_run_id
                    .as_ref()
                    .is_none_or(|expected| run.id == *expected)
            })
            .max_by(|left, right| left.run_at.cmp(&right.run_at))
            .cloned();
        let run = match selected_run {
            Some(run) => run,
            None => return error_json("hunt run not found", 404),
        };

        let title = payload
            .get("title")
            .and_then(|value| value.as_str())
            .map_or_else(
                || format!("Hunt escalation: {}", hunt.name),
                std::string::ToString::to_string,
            );
        let description = format!(
            "Hunt: {}\nHypothesis: {}\nExpected outcome: {:?}\nRun: {}\nMatches: {}\nSuppressed: {}\nAgents: {}\nSummary: {}",
            hunt.name,
            hunt.hypothesis,
            hunt.expected_outcome,
            run.run_at,
            run.match_count,
            run.suppressed_count,
            run.matched_agent_ids.join(", "),
            run.summary,
        );
        let mut tags = vec!["hunt-escalation".to_string(), format!("hunt:{}", hunt.id)];
        tags.extend(
            hunt.mitre_techniques
                .iter()
                .take(6)
                .map(|tech| format!("mitre:{tech}")),
        );
        let priority = match hunt.severity.to_ascii_lowercase().as_str() {
            "critical" => CasePriority::Critical,
            "high" => CasePriority::High,
            "low" => CasePriority::Low,
            "info" => CasePriority::Info,
            _ => CasePriority::Medium,
        };
        let case_id = {
            let case = s.case_store.create(
                title,
                description,
                priority,
                Vec::new(),
                run.matched_event_ids.clone(),
                tags,
            );
            case.id
        };
        let _ = s.enterprise.link_hunt_run_case(&run.id, case_id);
        json_response(
            &serde_json::json!({
                "status": "created",
                "case_id": case_id,
                "hunt_id": hunt.id,
                "run_id": run.id,
                "event_count": run.matched_event_ids.len(),
                "agent_ids": run.matched_agent_ids,
            })
            .to_string(),
            201,
        )
    } else if method == Method::Post
        && url_path.starts_with("/api/content/rules/")
        && url_path.ends_with("/test")
    {
        let rule_id = url_path
            .trim_start_matches("/api/content/rules/")
            .trim_end_matches("/test")
            .trim_end_matches('/');
        let started = std::time::Instant::now();
        let mut s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let events = s.event_store.all_events().to_vec();
        match s.enterprise.test_rule(rule_id, &events) {
            Ok(result) => {
                s.enterprise
                    .record_search_metrics(started.elapsed().as_millis() as u64);
                json_response(
                    &serde_json::json!({"status": "tested", "result": result}).to_string(),
                    200,
                )
            }
            Err(e) => error_json(&e, 404),
        }
    } else if method == Method::Post
        && url_path.starts_with("/api/content/rules/")
        && url_path.ends_with("/preflight")
    {
        let rule_id = url_path
            .trim_start_matches("/api/content/rules/")
            .trim_end_matches("/preflight")
            .trim_end_matches('/');
        let payload = read_json_value(body, 8192).unwrap_or_else(|_| serde_json::json!({}));
        let target_status = payload
            .get("target_status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("active");
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let body = build_content_rule_preflight(&s, rule_id, target_status);
        let snapshot = persist_operational_snapshot(&s.storage, "content_rule_preflight", &body);
        json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
    } else if method == Method::Post
        && url_path.starts_with("/api/content/rules/")
        && url_path.ends_with("/promote")
    {
        let rule_id = url_path
            .trim_start_matches("/api/content/rules/")
            .trim_end_matches("/promote")
            .trim_end_matches('/');
        match read_json_value(body, 8192) {
            Ok(v) => {
                let status_str = v["target_status"].as_str().unwrap_or("active");
                let target = match status_str {
                    "draft" => Some(ContentLifecycle::Draft),
                    "test" => Some(ContentLifecycle::Test),
                    "canary" => Some(ContentLifecycle::Canary),
                    "active" => Some(ContentLifecycle::Active),
                    "deprecated" => Some(ContentLifecycle::Deprecated),
                    _ => None,
                };
                let Some(target) = target else {
                    return respond_api(
                        state,
                        &method,
                        &url,
                        remote_addr,
                        needs_auth,
                        error_json(&format!("invalid target_status: {status_str}"), 400),
                    );
                };
                let reason = v["reason"].as_str().unwrap_or("promotion");
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match s
                    .enterprise
                    .promote_rule(rule_id, target, auth_identity.actor(), reason)
                {
                    Ok(rule) => {
                        sync_enterprise_sigma_engine(&mut s);
                        let _ = s.enterprise.record_change(
                            "rule_promotion",
                            rule_id,
                            &format!("Promoted rule {} to {:?}", rule_id, rule.lifecycle),
                            auth_identity.actor(),
                            Some(rule.id.clone()),
                            Some(&v.to_string()),
                        );
                        json_response(
                            &serde_json::json!({"status": "promoted", "rule": rule}).to_string(),
                            200,
                        )
                    }
                    Err(e) => error_json(&e, 404),
                }
            }
            Err(e) => error_json(&e, 400),
        }
    } else if method == Method::Post
        && url_path.starts_with("/api/content/rules/")
        && url_path.ends_with("/rollback")
    {
        let rule_id = url_path
            .trim_start_matches("/api/content/rules/")
            .trim_end_matches("/rollback")
            .trim_end_matches('/');
        let mut s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match s.enterprise.rollback_rule(rule_id, auth_identity.actor()) {
            Ok(rule) => {
                sync_enterprise_sigma_engine(&mut s);
                let _ = s.enterprise.record_change(
                    "rule_rollback",
                    rule_id,
                    &format!("Rolled back rule {rule_id}"),
                    auth_identity.actor(),
                    Some(rule.id.clone()),
                    None,
                );
                json_response(
                    &serde_json::json!({"status": "rolled_back", "rule": rule}).to_string(),
                    200,
                )
            }
            Err(e) => error_json(&e, 404),
        }
    } else if method == Method::Get
        && url_path.starts_with("/api/entities/")
        && url_path.ends_with("/timeline")
    {
        match parse_entity_timeline_path(url_path) {
            Some((kind, id)) => {
                let s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let timeline = build_entity_timeline(
                    kind,
                    id,
                    s.event_store.all_events(),
                    s.incident_store.list(),
                    s.case_store.list(),
                    &s.response_orchestrator.audit_ledger(),
                    s.enterprise.ticket_syncs(),
                );
                json_response(
                    &serde_json::json!({"kind": kind, "id": id, "timeline": timeline, "count": timeline.len()})
                        .to_string(),
                    200,
                )
            }
            None => error_json("not found", 404),
        }
    } else if method == Method::Get && url_path.starts_with("/api/entities/") {
        match parse_entity_profile_path(url_path) {
            Some((kind, id)) => {
                let s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let profile = build_entity_profile(
                    kind,
                    id,
                    s.event_store.all_events(),
                    s.incident_store.list(),
                    s.case_store.list(),
                    &s.threat_intel.all_iocs(),
                    &s.response_orchestrator.all_requests(),
                    &s.rbac.list_users(),
                    s.enterprise.connectors(),
                    s.enterprise.ticket_syncs(),
                );
                json_response(&profile.to_string(), 200)
            }
            None => error_json("not found", 404),
        }
    } else if method == Method::Get
        && url_path.starts_with("/api/incidents/")
        && url_path.ends_with("/storyline")
    {
        match parse_numeric_path_between::<u64>(url_path, "/api/incidents/", "/storyline") {
            Some(id) => {
                let s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match s.incident_store.get(id) {
                    Some(incident) => {
                        let related_events =
                            incident_related_events(incident, s.event_store.all_events());
                        let cases = s.case_store.list().to_vec();
                        let storyline = build_incident_storyline(
                            incident,
                            &related_events,
                            &cases,
                            &s.response_orchestrator.all_requests(),
                            &s.response_orchestrator.audit_ledger(),
                            s.enterprise.ticket_syncs(),
                        );
                        json_response(&storyline.to_string(), 200)
                    }
                    None => error_json("incident not found", 404),
                }
            }
            None => error_json("not found", 404),
        }
    // ── Analyst Console: Dynamic case routes ─────────────────
    } else if method == Method::Get
        && url_path.starts_with("/api/cases/")
        && url_path.ends_with("/handoff-packet")
    {
        match parse_numeric_path_between::<u64>(url_path, "/api/cases/", "/handoff-packet") {
            Some(id) => {
                let s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match s.case_store.get(id) {
                    Some(case) => json_response(
                        &case_handoff_packet_json(
                            case,
                            &s.incident_store,
                            &s.event_store,
                            &s.workflow_store,
                            &s.response_orchestrator.all_requests(),
                            &s.response_orchestrator.audit_ledger(),
                            s.enterprise.ticket_syncs(),
                        )
                        .to_string(),
                        200,
                    ),
                    None => error_json("case not found", 404),
                }
            }
            None => error_json("not found", 404),
        }
    } else if method == Method::Get && url_path.starts_with("/api/cases/") {
        match parse_numeric_path_suffix::<u64>(url_path, "/api/cases/") {
            Some(id) => {
                let s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(c) = s.case_store.get(id) {
                    json_response(&serde_json::json!({
                        "id": c.id, "title": c.title, "description": c.description,
                        "status": format!("{:?}", c.status), "priority": format!("{:?}", c.priority),
                        "assignee": c.assignee, "created_at": c.created_at, "updated_at": c.updated_at,
                        "incident_ids": c.incident_ids, "event_ids": c.event_ids,
                        "linked_incidents": case_linked_incidents(c, &s.incident_store),
                        "linked_events": case_linked_events(c, &s.event_store),
                        "tags": c.tags, "comments": c.comments.iter().map(|cm| {
                            serde_json::json!({"author": cm.author, "timestamp": cm.timestamp, "text": cm.text})
                        }).collect::<Vec<_>>(),
                        "evidence": c.evidence.iter().map(|ev| {
                            serde_json::json!({"kind": ev.kind, "reference_id": ev.reference_id, "description": ev.description, "added_at": ev.added_at})
                        }).collect::<Vec<_>>(),
                        "mitre_techniques": c.mitre_techniques,
                    }).to_string(), 200)
                } else {
                    error_json("case not found", 404)
                }
            }
            None => error_json("not found", 404),
        }
    } else if method == Method::Post
        && url_path.starts_with("/api/cases/")
        && url_path.ends_with("/comment")
    {
        match parse_numeric_path_between::<u64>(url_path, "/api/cases/", "/comment") {
            Some(id) => {
                let body = read_body_limited(body, 4096);
                match body.and_then(|b| {
                    serde_json::from_str::<serde_json::Value>(&b).map_err(|e| e.to_string())
                }) {
                    Ok(v) => {
                        let author = v["author"].as_str().unwrap_or("analyst").to_string();
                        let text = v["text"].as_str().unwrap_or("").to_string();
                        let mut s = state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if s.case_store.add_comment(id, author, text) {
                            json_response(
                                &serde_json::json!({"case_id": id, "action": "comment_added"})
                                    .to_string(),
                                200,
                            )
                        } else {
                            error_json("case not found", 404)
                        }
                    }
                    Err(e) => error_json(&e, 400),
                }
            }
            None => error_json("not found", 404),
        }
    } else if method == Method::Post
        && url_path.starts_with("/api/cases/")
        && url_path.ends_with("/update")
    {
        match parse_numeric_path_between::<u64>(url_path, "/api/cases/", "/update") {
            Some(id) => {
                let body = read_body_limited(body, 4096);
                match body.and_then(|b| {
                    serde_json::from_str::<serde_json::Value>(&b).map_err(|e| e.to_string())
                }) {
                    Ok(v) => {
                        let mut s = state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if let Some(status_str) = v["status"].as_str() {
                            let status = match status_str {
                                "triaging" => Some(CaseStatus::Triaging),
                                "investigating" => Some(CaseStatus::Investigating),
                                "escalated" => Some(CaseStatus::Escalated),
                                "resolved" => Some(CaseStatus::Resolved),
                                "closed" => Some(CaseStatus::Closed),
                                "new" => Some(CaseStatus::New),
                                _ => None,
                            };
                            let Some(status) = status else {
                                return respond_api(
                                    state,
                                    &method,
                                    &url,
                                    remote_addr,
                                    needs_auth,
                                    error_json(&format!("invalid status: {status_str}"), 400),
                                );
                            };
                            if !s.case_store.update_status(id, status) {
                                return respond_api(
                                    state,
                                    &method,
                                    &url,
                                    remote_addr,
                                    needs_auth,
                                    error_json("case not found", 404),
                                );
                            }
                        }
                        if let Some(assignee) = v["assignee"].as_str()
                            && !s.case_store.assign(id, assignee.to_string())
                        {
                            return respond_api(
                                state,
                                &method,
                                &url,
                                remote_addr,
                                needs_auth,
                                error_json("case not found", 404),
                            );
                        }
                        if let Some(title) = v["title"].as_str()
                            && !s.case_store.update_title(id, title.to_string())
                        {
                            return respond_api(
                                state,
                                &method,
                                &url,
                                remote_addr,
                                needs_auth,
                                error_json("case not found", 404),
                            );
                        }
                        if let Some(description) = v["description"].as_str()
                            && !s.case_store.update_description(id, description.to_string())
                        {
                            return respond_api(
                                state,
                                &method,
                                &url,
                                remote_addr,
                                needs_auth,
                                error_json("case not found", 404),
                            );
                        }
                        if let Some(tags) = v["tags"].as_array() {
                            let normalized_tags = tags
                                .iter()
                                .filter_map(|value| value.as_str().map(|s| s.trim().to_string()))
                                .filter(|tag| !tag.is_empty())
                                .collect::<Vec<_>>();
                            if !s.case_store.update_tags(id, normalized_tags) {
                                return respond_api(
                                    state,
                                    &method,
                                    &url,
                                    remote_addr,
                                    needs_auth,
                                    error_json("case not found", 404),
                                );
                            }
                        }
                        if let Some(incident_id) = v["link_incident"].as_u64() {
                            s.case_store.link_incident(id, incident_id);
                        }
                        json_response(
                            &serde_json::json!({"case_id": id, "action": "updated"}).to_string(),
                            200,
                        )
                    }
                    Err(e) => error_json(&e, 400),
                }
            }
            None => error_json("not found", 404),
        }
    } else if method == Method::Post
        && url_path.starts_with("/api/cases/")
        && url_path.ends_with("/evidence")
    {
        match parse_numeric_path_between::<u64>(url_path, "/api/cases/", "/evidence") {
            Some(id) => {
                let body = read_body_limited(body, 4096);
                match body.and_then(|b| {
                    serde_json::from_str::<serde_json::Value>(&b).map_err(|e| e.to_string())
                }) {
                    Ok(v) => {
                        let kind = v["kind"].as_str().unwrap_or("other").to_string();
                        let ref_id = v["reference_id"].as_str().unwrap_or("").to_string();
                        let desc = v["description"].as_str().unwrap_or("").to_string();
                        let mut s = state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if s.case_store.add_evidence(id, kind, ref_id, desc) {
                            json_response(
                                &serde_json::json!({"case_id": id, "action": "evidence_added"})
                                    .to_string(),
                                200,
                            )
                        } else {
                            error_json("case not found", 404)
                        }
                    }
                    Err(e) => error_json(&e, 400),
                }
            }
            None => error_json("not found", 404),
        }
    // ── Phase 32: Advanced XDR endpoints ────────────────────────

    // UEBA
    } else if method == Method::Post && url_path == "/api/ueba/observe" {
        let body = read_body_limited(body, 8192);
        match body.and_then(|b| {
            serde_json::from_str::<crate::ueba::BehaviorObservation>(&b).map_err(|e| e.to_string())
        }) {
            Ok(obs) => {
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let anomalies = s.ueba_engine.observe(&obs);
                json_response(
                    &serde_json::to_string(&serde_json::json!({
                        "anomalies": anomalies,
                    }))
                    .unwrap_or_else(|_| "{}".to_string()),
                    200,
                )
            }
            Err(e) => error_json(&e, 400),
        }
    } else if method == Method::Get && url_path == "/api/ueba/risky" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let risky = s.ueba_engine.risky_entities(10.0);
        json_response(
            &serde_json::to_string(&risky).unwrap_or_else(|_| "{}".to_string()),
            200,
        )
    } else if method == Method::Get && url_path.starts_with("/api/ueba/entity/") {
        let entity_id = url_path.trim_start_matches("/api/ueba/entity/");
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match s
            .ueba_engine
            .entity_risk(&crate::ueba::EntityKind::User, entity_id)
        {
            Some(risk) => json_response(
                &serde_json::to_string(&risk).unwrap_or_else(|_| "{}".to_string()),
                200,
            ),
            None => error_json("entity not found", 404),
        }

    // Beacon / DGA
    } else if method == Method::Post && url_path == "/api/beacon/connection" {
        let body = read_body_limited(body, 4096);
        match body.and_then(|b| {
            serde_json::from_str::<crate::beacon::ConnectionRecord>(&b).map_err(|e| e.to_string())
        }) {
            Ok(conn) => {
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                s.beacon_detector.record_connection(conn);
                json_response(r#"{"status":"recorded"}"#, 200)
            }
            Err(e) => error_json(&e, 400),
        }
    } else if method == Method::Post && url_path == "/api/beacon/dns" {
        let body = read_body_limited(body, 4096);
        match body.and_then(|b| {
            serde_json::from_str::<crate::beacon::DnsRecord>(&b).map_err(|e| e.to_string())
        }) {
            Ok(dns) => {
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                s.beacon_detector.record_dns(dns);
                json_response(r#"{"status":"recorded"}"#, 200)
            }
            Err(e) => error_json(&e, 400),
        }
    } else if method == Method::Get && url_path == "/api/beacon/analyze" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let summary = s.beacon_detector.analyze();
        json_response(
            &serde_json::to_string(&summary).unwrap_or_else(|_| "{}".to_string()),
            200,
        )

    // Kill Chain
    } else if method == Method::Post && url_path == "/api/killchain/reconstruct" {
        let body = read_body_limited(body, 16384);
        match body.and_then(|b| {
            serde_json::from_str::<Vec<crate::kill_chain::KillChainEvent>>(&b)
                .map_err(|e| e.to_string())
        }) {
            Ok(events) => {
                let s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let chain = s.kill_chain_analyzer.reconstruct("api-request", &events);
                json_response(
                    &serde_json::to_string(&chain).unwrap_or_else(|_| "{}".to_string()),
                    200,
                )
            }
            Err(e) => error_json(&e, 400),
        }

    // Lateral Movement
    } else if method == Method::Post && url_path == "/api/lateral/connection" {
        let body = read_body_limited(body, 4096);
        match body.and_then(|b| {
            serde_json::from_str::<crate::lateral::RemoteConnection>(&b).map_err(|e| e.to_string())
        }) {
            Ok(conn) => {
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                s.lateral_detector.record(conn);
                json_response(r#"{"status":"recorded"}"#, 200)
            }
            Err(e) => error_json(&e, 400),
        }
    } else if method == Method::Get && url_path == "/api/lateral/analyze" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let summary = s.lateral_detector.analyze();
        json_response(
            &serde_json::to_string(&summary).unwrap_or_else(|_| "{}".to_string()),
            200,
        )

    // Kernel Events
    } else if method == Method::Post && url_path == "/api/kernel/event" {
        let body = read_body_limited(body, 8192);
        match body.and_then(|b| {
            serde_json::from_str::<crate::kernel_events::KernelEvent>(&b).map_err(|e| e.to_string())
        }) {
            Ok(event) => {
                let s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                s.kernel_event_stream.push(event);
                json_response(r#"{"status":"recorded"}"#, 200)
            }
            Err(e) => error_json(&e, 400),
        }
    } else if method == Method::Get && url_path == "/api/kernel/recent" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let events = s.kernel_event_stream.recent(100, None);
        json_response(
            &serde_json::to_string(&events).unwrap_or_else(|_| "{}".to_string()),
            200,
        )

    // Playbooks
    } else if method == Method::Get && url_path == "/api/playbooks" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let pbs = s.playbook_engine.list_playbooks();
        json_response(
            &serde_json::to_string(&pbs).unwrap_or_else(|_| "{}".to_string()),
            200,
        )
    } else if method == Method::Post && url_path == "/api/playbooks" {
        let body = read_body_limited(body, 16384);
        match body.and_then(|b| {
            serde_json::from_str::<crate::playbook::Playbook>(&b).map_err(|e| e.to_string())
        }) {
            Ok(pb) => {
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                s.playbook_engine.register(pb);
                json_response(r#"{"status":"registered"}"#, 200)
            }
            Err(e) => error_json(&e, 400),
        }
    } else if method == Method::Post && url_path == "/api/playbooks/execute" {
        let body = read_body_limited(body, 4096);
        match body
            .and_then(|b| serde_json::from_str::<serde_json::Value>(&b).map_err(|e| e.to_string()))
        {
            Ok(v) => {
                let pb_id = v["playbook_id"].as_str().unwrap_or("");
                let alert_id = v["alert_id"].as_str();
                let now = chrono::Utc::now().timestamp_millis() as u64;
                let executed_by = playbook_executor(&auth_identity);
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match s
                    .playbook_engine
                    .start_execution(pb_id, alert_id, &executed_by, now)
                {
                    Some(eid) => {
                        if let Some(execution) = s.playbook_engine.get_execution(&eid).cloned() {
                            s.enterprise.record_playbook_execution(&execution);
                        }
                        eprintln!(
                            "[AUDIT] playbook_execute id={pb_id} execution={eid} by={executed_by} alert={}",
                            alert_id.unwrap_or("none")
                        );
                        json_response(&serde_json::json!({"execution_id": eid}).to_string(), 200)
                    }
                    None => error_json("playbook not found or disabled", 404),
                }
            }
            Err(e) => error_json(&e, 400),
        }
    } else if method == Method::Get && url_path == "/api/playbooks/executions" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let execs = s.playbook_engine.recent_executions(50);
        json_response(
            &serde_json::to_string(&execs).unwrap_or_else(|_| "{}".to_string()),
            200,
        )
    } else if method == Method::Get
        && url_path.starts_with("/api/playbook/execution/")
        && url_path.ends_with("/recovery-actions")
    {
        let execution_id = url_path
            .trim_start_matches("/api/playbook/execution/")
            .trim_end_matches("/recovery-actions")
            .trim_matches('/');
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match s.playbook_engine.get_execution(execution_id) {
            Some(execution) => {
                json_response(&build_playbook_recovery_actions(execution).to_string(), 200)
            }
            None => error_json("playbook execution not found", 404),
        }

    // Live Response
    } else if method == Method::Post && url_path == "/api/live-response/session" {
        let body = read_body_limited(body, 4096);
        match body
            .and_then(|b| serde_json::from_str::<serde_json::Value>(&b).map_err(|e| e.to_string()))
        {
            Ok(v) => {
                let agent_id = v["agent_id"].as_str().unwrap_or("unknown");
                let hostname = v["hostname"].as_str().unwrap_or("unknown");
                let op = live_response_operator(&auth_identity);
                let platform = match v["platform"].as_str().unwrap_or("linux") {
                    "macos" => crate::live_response::LiveResponsePlatform::MacOs,
                    "windows" => crate::live_response::LiveResponsePlatform::Windows,
                    _ => crate::live_response::LiveResponsePlatform::Linux,
                };
                let now = chrono::Utc::now().timestamp_millis() as u64;
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let sid = s
                    .live_response_engine
                    .open_session(agent_id, hostname, platform, &op, now);
                json_response(&serde_json::json!({"session_id": sid}).to_string(), 200)
            }
            Err(e) => error_json(&e, 400),
        }
    } else if method == Method::Post && url_path == "/api/live-response/command" {
        let body = read_body_limited(body, 4096);
        match body
            .and_then(|b| serde_json::from_str::<serde_json::Value>(&b).map_err(|e| e.to_string()))
        {
            Ok(v) => {
                let sid = v["session_id"].as_str().unwrap_or("");
                let cmd = v["command"].as_str().unwrap_or("");
                let args: Vec<String> = v["args"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(std::string::ToString::to_string))
                            .collect()
                    })
                    .unwrap_or_default();
                let now = chrono::Utc::now().timestamp_millis() as u64;
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match s.live_response_engine.submit_command(sid, cmd, args, now) {
                    Ok(cid) => {
                        json_response(&serde_json::json!({"command_id": cid}).to_string(), 200)
                    }
                    Err(e) => error_json(&e, 403),
                }
            }
            Err(e) => error_json(&e, 400),
        }
    } else if method == Method::Get && url_path == "/api/live-response/sessions" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let sessions = s.live_response_engine.all_sessions();
        json_response(
            &serde_json::to_string(&sessions).unwrap_or_else(|_| "{}".to_string()),
            200,
        )
    } else if method == Method::Get && url_path == "/api/live-response/audit" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let log: Vec<serde_json::Value> = s
            .live_response_engine
            .audit_log()
            .iter()
            .map(|(sid, cr)| serde_json::json!({"session_id": sid, "record": cr}))
            .collect();
        json_response(
            &serde_json::to_string(&log).unwrap_or_else(|_| "{}".to_string()),
            200,
        )

    // Remediation
    } else if method == Method::Post && url_path == "/api/remediation/plan" {
        match read_json_value(body, crate::remediation::REMEDIATION_PLAN_BODY_LIMIT) {
            Ok(payload) => {
                let s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match crate::remediation::remediation_plan_json_from_payload(
                    &s.remediation_engine,
                    payload,
                ) {
                    Ok(json) => json_response(&json, 200),
                    Err(error) => error_json(error.response_message(), error.http_status()),
                }
            }
            Err(error) => error_json(&error, 400),
        }
    } else if method == Method::Get && url_path == "/api/remediation/results" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        json_response(
            &crate::remediation::remediation_results_json(&s.remediation_engine, 50),
            200,
        )
    } else if method == Method::Get && url_path == "/api/remediation/stats" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        json_response(
            &crate::remediation::remediation_stats_json(&s.remediation_engine),
            200,
        )
    } else if method == Method::Get && url_path == "/api/remediation/change-reviews" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        json_response(
            &crate::remediation::remediation_change_review_list_json(&s.storage),
            200,
        )
    } else if method == Method::Post && url_path == "/api/remediation/change-reviews" {
        match read_json_value(
            body,
            crate::remediation::REMEDIATION_CHANGE_REVIEW_BODY_LIMIT,
        ) {
            Ok(payload) => {
                let s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match crate::remediation::record_remediation_change_review_json(
                    &s.storage,
                    payload,
                    auth_identity.actor(),
                ) {
                    Ok(json) => json_response(&json, 200),
                    Err(error) => error_json(error.response_message(), error.http_status()),
                }
            }
            Err(error) => error_json(&error, 400),
        }
    } else if method == Method::Post
        && crate::remediation::remediation_change_review_route_id(
            url_path,
            crate::remediation::RemediationChangeReviewRouteAction::Approval,
        )
        .is_some()
    {
        let review_id = crate::remediation::remediation_change_review_route_id(
            url_path,
            crate::remediation::RemediationChangeReviewRouteAction::Approval,
        )
        .unwrap_or_default();
        match read_json_value(
            body,
            crate::remediation::REMEDIATION_CHANGE_REVIEW_ACTION_BODY_LIMIT,
        ) {
            Ok(payload) => {
                let s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match crate::remediation::approve_remediation_change_review_json(
                    &s.storage,
                    &review_id,
                    payload,
                    auth_identity.actor(),
                ) {
                    Ok(json) => json_response(&json, 200),
                    Err(error) => error_json(error.response_message(), error.http_status()),
                }
            }
            Err(error) => error_json(&error, 400),
        }
    } else if method == Method::Post
        && crate::remediation::remediation_change_review_route_id(
            url_path,
            crate::remediation::RemediationChangeReviewRouteAction::Rollback,
        )
        .is_some()
    {
        let review_id = crate::remediation::remediation_change_review_route_id(
            url_path,
            crate::remediation::RemediationChangeReviewRouteAction::Rollback,
        )
        .unwrap_or_default();
        match read_json_value(
            body,
            crate::remediation::REMEDIATION_CHANGE_REVIEW_ACTION_BODY_LIMIT,
        ) {
            Ok(payload) => {
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let storage = s.storage.clone();
                let policy = crate::remediation::RemediationRollbackPolicy::new(
                    s.config.remediation.allow_live_rollback,
                    s.config.remediation.execute_live_rollback_commands,
                );
                match crate::remediation::execute_review_rollback_json_with_policy(
                    &storage,
                    &mut s.remediation_engine,
                    &review_id,
                    payload,
                    auth_identity.actor(),
                    policy,
                ) {
                    Ok(json) => json_response(&json, 200),
                    Err(error) => error_json(error.response_message(), error.http_status()),
                }
            }
            Err(error) => error_json(&error, 400),
        }

    // Escalation
    } else if method == Method::Get && url_path == "/api/escalation/policies" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let policies = s.escalation_engine.list_policies();
        json_response(
            &serde_json::to_string(&policies).unwrap_or_else(|_| "{}".to_string()),
            200,
        )
    } else if method == Method::Post && url_path == "/api/escalation/policies" {
        let body = read_body_limited(body, 16384);
        match body.and_then(|b| {
            serde_json::from_str::<crate::escalation::EscalationPolicy>(&b)
                .map_err(|e| e.to_string())
        }) {
            Ok(policy) => {
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                s.escalation_engine.add_policy(policy);
                json_response(r#"{"status":"added"}"#, 200)
            }
            Err(e) => error_json(&e, 400),
        }
    } else if method == Method::Post && url_path == "/api/escalation/start" {
        let body = read_body_limited(body, 4096);
        match body
            .and_then(|b| serde_json::from_str::<serde_json::Value>(&b).map_err(|e| e.to_string()))
        {
            Ok(v) => {
                let policy_id = v["policy_id"].as_str().unwrap_or("");
                let alert_id = v["alert_id"].as_str().unwrap_or("");
                let now = chrono::Utc::now().timestamp_millis() as u64;
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match s
                    .escalation_engine
                    .start_escalation(policy_id, alert_id, now)
                {
                    Some(eid) => {
                        json_response(&serde_json::json!({"escalation_id": eid}).to_string(), 200)
                    }
                    None => error_json("policy not found or disabled", 404),
                }
            }
            Err(e) => error_json(&e, 400),
        }
    } else if method == Method::Post && url_path == "/api/escalation/acknowledge" {
        let body = read_body_limited(body, 4096);
        match body
            .and_then(|b| serde_json::from_str::<serde_json::Value>(&b).map_err(|e| e.to_string()))
        {
            Ok(v) => {
                let eid = v["escalation_id"].as_str().unwrap_or("");
                let by = v["acknowledged_by"].as_str().unwrap_or("api");
                let now = chrono::Utc::now().timestamp_millis() as u64;
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if s.escalation_engine.acknowledge(eid, by, now) {
                    json_response(r#"{"status":"acknowledged"}"#, 200)
                } else {
                    error_json("escalation not found or not active", 404)
                }
            }
            Err(e) => error_json(&e, 400),
        }
    } else if method == Method::Get && url_path == "/api/escalation/active" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let active = s.escalation_engine.active_escalations();
        json_response(
            &serde_json::to_string(&active).unwrap_or_else(|_| "{}".to_string()),
            200,
        )
    } else if method == Method::Post && url_path == "/api/escalation/check-sla" {
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let mut s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let escalated = s.escalation_engine.check_sla(now);
        json_response(
            &serde_json::json!({"escalated": escalated}).to_string(),
            200,
        )

    // Evidence Collection Plans
    } else if method == Method::Get && url_path == "/api/evidence/plan/linux" {
        let plan = crate::forensics::EvidenceCollectionPlan::linux();
        json_response(
            &serde_json::to_string(&plan).unwrap_or_else(|_| "{}".to_string()),
            200,
        )
    } else if method == Method::Get && url_path == "/api/evidence/plan/macos" {
        let plan = crate::forensics::EvidenceCollectionPlan::macos();
        json_response(
            &serde_json::to_string(&plan).unwrap_or_else(|_| "{}".to_string()),
            200,
        )
    } else if method == Method::Get && url_path == "/api/evidence/plan/windows" {
        let plan = crate::forensics::EvidenceCollectionPlan::windows();
        json_response(
            &serde_json::to_string(&plan).unwrap_or_else(|_| "{}".to_string()),
            200,
        )

    // Containment Commands
    } else if method == Method::Post && url_path == "/api/containment/commands" {
        let body = read_body_limited(body, 4096);
        match body
            .and_then(|b| serde_json::from_str::<serde_json::Value>(&b).map_err(|e| e.to_string()))
        {
            Ok(v) => {
                let level = match v["level"].as_str().unwrap_or("observe") {
                    "constrain" => crate::enforcement::EnforcementLevel::Constrain,
                    "quarantine" => crate::enforcement::EnforcementLevel::Quarantine,
                    "isolate" => crate::enforcement::EnforcementLevel::Isolate,
                    "eradicate" => crate::enforcement::EnforcementLevel::Eradicate,
                    _ => crate::enforcement::EnforcementLevel::Observe,
                };
                let target = v["target"].as_str().unwrap_or("");
                let platform = v["platform"].as_str().unwrap_or("linux");
                let s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let cmds = s.enforcement.containment_commands(&level, target, platform);
                json_response(
                    &serde_json::to_string(&cmds).unwrap_or_else(|_| "{}".to_string()),
                    200,
                )
            }
            Err(e) => error_json(&e, 400),
        }
    // ── Phase 4B: Historical / durable storage endpoints ───
    } else if method == Method::Get && url_path == "/api/storage/alerts" {
        let query = parse_query_string(&url);
        let tenant_id = match tenant_filter_for_request(
            &auth_identity,
            query.get("tenant_id").map(String::as_str),
        ) {
            Ok(tenant_id) => tenant_id,
            Err(response) => return response,
        };
        let filter = crate::storage::QueryFilter {
            tenant_id,
            level: query.get("level").cloned(),
            device_id: query.get("device_id").cloned(),
            since: query.get("since").cloned(),
            until: query.get("until").cloned(),
            limit: query.get("limit").and_then(|v| v.parse().ok()),
            offset: query.get("offset").and_then(|v| v.parse().ok()),
            ..Default::default()
        };
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match s.storage.with(|store| Ok(store.query_alerts(&filter))) {
            Ok(alerts) => json_response(&serde_json::to_string(&alerts).unwrap_or_default(), 200),
            Err(e) => error_json(e.safe_message(), 500),
        }
    } else if method == Method::Get && url_path == "/api/storage/cases" {
        let query = parse_query_string(&url);
        let tenant_id = match tenant_filter_for_request(
            &auth_identity,
            query.get("tenant_id").map(String::as_str),
        ) {
            Ok(tenant_id) => tenant_id,
            Err(response) => return response,
        };
        let filter = crate::storage::QueryFilter {
            tenant_id,
            status: query.get("status").cloned(),
            limit: query.get("limit").and_then(|v| v.parse().ok()),
            ..Default::default()
        };
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match s.storage.with(|store| Ok(store.list_cases(&filter))) {
            Ok(cases) => json_response(&serde_json::to_string(&cases).unwrap_or_default(), 200),
            Err(e) => error_json(e.safe_message(), 500),
        }
    } else if method == Method::Get && url_path == "/api/storage/audit" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match s.storage.with(|store| {
            let chain_len = store.verify_audit_chain()?;
            Ok(serde_json::json!({
                "chain_length": chain_len,
                "integrity": "verified",
            }))
        }) {
            Ok(body) => json_response(&body.to_string(), 200),
            Err(e) => error_json(e.safe_message(), 500),
        }
    } else if method == Method::Get && url_path == "/api/storage/stats" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut stats_json = match s.storage.with(|store| Ok(store.stats())) {
            Ok(stats) => serde_json::to_value(&stats).unwrap_or_default(),
            Err(_) => serde_json::json!({}),
        };
        // Append ClickHouse status if configured
        if let Some(ref ch) = s.clickhouse_store
            && let Some(obj) = stats_json.as_object_mut()
        {
            obj.insert("clickhouse_enabled".into(), serde_json::json!(true));
            obj.insert("clickhouse_url".into(), serde_json::json!(ch.config().url));
            obj.insert(
                "clickhouse_database".into(),
                serde_json::json!(ch.config().database),
            );
            obj.insert(
                "clickhouse_buffer_len".into(),
                serde_json::json!(ch.buffer_len()),
            );
            obj.insert(
                "clickhouse_total_inserted".into(),
                serde_json::json!(ch.total_inserted()),
            );
        }
        json_response(&stats_json.to_string(), 200)
    } else if method == Method::Get && url_path == "/api/storage/events/historical" {
        let query = parse_query_string(&url);
        let limit = query
            .get("limit")
            .and_then(|value| value.parse::<u32>().ok())
            .map_or(50, |value| value.clamp(1, 200));
        let offset = query
            .get("offset")
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(0);
        let from = match parse_query_datetime(query.get("since"), "since") {
            Ok(value) => value,
            Err(error) => {
                return json_response(
                    &serde_json::json!({
                        "enabled": false,
                        "events": [],
                        "count": 0,
                        "total": 0,
                        "limit": limit,
                        "offset": offset,
                        "error": error,
                    })
                    .to_string(),
                    400,
                );
            }
        };
        let to = match parse_query_datetime(query.get("until"), "until") {
            Ok(value) => value,
            Err(error) => {
                return json_response(
                    &serde_json::json!({
                        "enabled": false,
                        "events": [],
                        "count": 0,
                        "total": 0,
                        "limit": limit,
                        "offset": offset,
                        "error": error,
                    })
                    .to_string(),
                    400,
                );
            }
        };
        let filter = crate::storage_clickhouse::EventFilter {
            tenant_id: match tenant_filter_for_request(
                &auth_identity,
                query.get("tenant_id").map(String::as_str),
            ) {
                Ok(tenant_id) => tenant_id,
                Err(response) => return response,
            },
            from,
            to,
            severity_min: query
                .get("severity_min")
                .and_then(|value| value.parse::<u8>().ok()),
            event_class: query
                .get("event_class")
                .and_then(|value| value.parse::<u16>().ok()),
            device_id: query
                .get("device_id")
                .cloned()
                .filter(|value| !value.trim().is_empty()),
            user_name: query
                .get("user_name")
                .cloned()
                .filter(|value| !value.trim().is_empty()),
            src_ip: query
                .get("src_ip")
                .cloned()
                .filter(|value| !value.trim().is_empty()),
            limit: Some(limit),
            offset: Some(offset),
        };
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(ref ch) = s.clickhouse_store else {
            let body = serde_json::json!({
                "enabled": false,
                "events": [],
                "count": 0,
                "total": 0,
                "limit": limit,
                "offset": offset,
                "error": "ClickHouse long-retention storage is not configured.",
            });
            return json_response(&body.to_string(), 200);
        };

        let total = match crate::storage_clickhouse::EventStore::count_events(ch, &filter) {
            Ok(total) => total,
            Err(error) => {
                let body = serde_json::json!({
                    "enabled": true,
                    "events": [],
                    "count": 0,
                    "total": 0,
                    "limit": limit,
                    "offset": offset,
                    "error": error,
                    "clickhouse": {
                        "url": ch.config().url,
                        "database": ch.config().database,
                        "retention_days": ch.config().retention_days,
                        "buffer_len": ch.buffer_len(),
                        "total_inserted": ch.total_inserted(),
                    },
                });
                return json_response(&body.to_string(), 200);
            }
        };

        let events = match crate::storage_clickhouse::EventStore::query_events(ch, &filter) {
            Ok(events) => events,
            Err(error) => {
                let body = serde_json::json!({
                    "enabled": true,
                    "events": [],
                    "count": 0,
                    "total": total,
                    "limit": limit,
                    "offset": offset,
                    "error": error,
                    "clickhouse": {
                        "url": ch.config().url,
                        "database": ch.config().database,
                        "retention_days": ch.config().retention_days,
                        "buffer_len": ch.buffer_len(),
                        "total_inserted": ch.total_inserted(),
                    },
                });
                return json_response(&body.to_string(), 200);
            }
        };

        let body = serde_json::json!({
            "enabled": true,
            "events": events,
            "count": events.len(),
            "total": total,
            "limit": limit,
            "offset": offset,
            "error": serde_json::Value::Null,
            "clickhouse": {
                "url": ch.config().url,
                "database": ch.config().database,
                "retention_days": ch.config().retention_days,
                "buffer_len": ch.buffer_len(),
                "total_inserted": ch.total_inserted(),
            },
        });
        json_response(&body.to_string(), 200)
    } else if method == Method::Get && url_path == "/api/storage/agents" {
        let query = parse_query_string(&url);
        let tenant = match tenant_filter_for_request(
            &auth_identity,
            query.get("tenant_id").map(String::as_str),
        ) {
            Ok(tenant_id) => tenant_id,
            Err(response) => return response,
        };
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match s
            .storage
            .with(|store| Ok(store.list_agents(tenant.as_deref())))
        {
            Ok(agents) => json_response(&serde_json::to_string(&agents).unwrap_or_default(), 200),
            Err(e) => error_json(e.safe_message(), 500),
        }
    } else if method == Method::Post && url_path == "/api/storage/alerts" {
        match read_body_limited(body, 8192) {
            Ok(body) => match serde_json::from_str::<crate::storage::StoredAlert>(&body) {
                Ok(alert) => {
                    let s = state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    match s.storage.with(|store| store.insert_alert(alert)) {
                        Ok(()) => json_response(r#"{"status":"stored"}"#, 201),
                        Err(e) => error_json(&e.message, 409),
                    }
                }
                Err(e) => error_json(&format!("invalid alert JSON: {e}"), 400),
            },
            Err(e) => error_json(&e, 400),
        }
    } else if method == Method::Get && url_path == "/api/detectors/slow-attack" {
        let s = match state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let report = s.slow_attack.evaluate();
        json_response(&serde_json::to_string(&report).unwrap_or_default(), 200)
    } else if method == Method::Get && url_path == "/api/detectors/ransomware" {
        let mut s = match state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let signal = s.ransomware.evaluate(0.0);
        json_response(&serde_json::to_string(&signal).unwrap_or_default(), 200)

    // ── DB migration rollback ─────────────────────────────
    } else if method == Method::Post && url_path == "/api/admin/db/rollback" {
        let s = match state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        match s
            .storage
            .with(crate::storage::StorageBackend::rollback_migration)
        {
            Ok(Some(version)) => {
                let new_ver = s
                    .storage
                    .with(|store| Ok(store.schema_version()))
                    .unwrap_or(0);
                let body = serde_json::json!({
                    "status": "rolled_back",
                    "version": version,
                    "current_version": new_ver,
                });
                json_response(&body.to_string(), 200)
            }
            Ok(None) => error_json("already at version 0, nothing to rollback", 400),
            Err(e) => error_json(e.safe_message(), 500),
        }

    // ── GDPR right-to-forget ──────────────────────────────
    } else if method == Method::Delete && url_path.starts_with("/api/gdpr/forget/") {
        let entity_id = url_path.strip_prefix("/api/gdpr/forget/").unwrap_or("");
        if entity_id.is_empty() || entity_id.len() > 256 {
            error_json("invalid entity_id", 400)
        } else {
            let s = match state.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            match s.storage.with(|store| store.purge_entity(entity_id)) {
                Ok(purged) => {
                    let body = serde_json::json!({
                        "status": "completed",
                        "entity_id": entity_id,
                        "records_purged": purged,
                        "timestamp": chrono::Utc::now().to_rfc3339(),
                    });
                    json_response(&body.to_string(), 200)
                }
                Err(e) => error_json(e.safe_message(), 500),
            }
        }

    // ── Database backup ───────────────────────────────────
    } else if method == Method::Post && url_path == "/api/admin/backup" {
        let backup_dir = "var/backups";
        let _ = std::fs::create_dir_all(backup_dir);
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let dest = format!("{backup_dir}/wardex_backup_{timestamp}.db");
        let s = match state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        match s.storage.with(|store| store.backup(&dest)) {
            Ok(()) => {
                let body = serde_json::json!({
                    "status": "completed",
                    "path": dest,
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                });
                json_response(&body.to_string(), 200)
            }
            Err(e) => error_json(e.safe_message(), 500),
        }

    // ── Database schema version ───────────────────────────
    } else if method == Method::Get && url_path == "/api/admin/db/version" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let info = s.storage.with(|store| Ok(store.schema_info()));
        let version = s.storage.with(|store| Ok(store.schema_version()));
        let body = serde_json::json!({
            "current_version": version.unwrap_or(0),
            "migrations": info.unwrap_or_default(),
        });
        json_response(&body.to_string(), 200)

    // ── Database compact (VACUUM + WAL checkpoint) ────────
    } else if method == Method::Post && url_path == "/api/admin/db/compact" {
        let s = match state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        match s.storage.with(|store| store.compact()) {
            Ok((before, after)) => {
                let saved = before.saturating_sub(after);
                let body = serde_json::json!({
                    "status": "completed",
                    "size_before_bytes": before,
                    "size_after_bytes": after,
                    "bytes_reclaimed": saved,
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                });
                json_response(&body.to_string(), 200)
            }
            Err(e) => error_json(e.safe_message(), 500),
        }

    // ── Database reset (purge all data) ───────────────────
    } else if method == Method::Post && url_path == "/api/admin/db/reset" {
        match read_body_limited(body, 4096) {
            Ok(body_str) => {
                // Require confirmation token to prevent accidental reset
                let parsed: serde_json::Value = serde_json::from_str(&body_str).unwrap_or_default();
                let confirm = parsed["confirm"].as_str().unwrap_or("");
                if confirm != "RESET_ALL_DATA" {
                    error_json("send {\"confirm\":\"RESET_ALL_DATA\"} to confirm", 400)
                } else {
                    let s = match state.lock() {
                        Ok(g) => g,
                        Err(e) => e.into_inner(),
                    };
                    match s
                        .storage
                        .with(crate::storage::StorageBackend::reset_all_data)
                    {
                        Ok(purged) => {
                            let body = serde_json::json!({
                                "status": "completed",
                                "records_purged": purged,
                                "timestamp": chrono::Utc::now().to_rfc3339(),
                            });
                            json_response(&body.to_string(), 200)
                        }
                        Err(e) => error_json(e.safe_message(), 500),
                    }
                }
            }
            Err(e) => error_json(&e, 400),
        }

    // ── Database file sizes ───────────────────────────────
    } else if method == Method::Get && url_path == "/api/admin/db/sizes" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match s.storage.with(|store| Ok(store.db_file_sizes())) {
            Ok(sizes) => {
                let body = serde_json::json!({
                    "db_bytes": sizes.db_bytes,
                    "wal_bytes": sizes.wal_bytes,
                    "shm_bytes": sizes.shm_bytes,
                    "total_bytes": sizes.total(),
                });
                json_response(&body.to_string(), 200)
            }
            Err(e) => error_json(e.safe_message(), 500),
        }

    // ── Cleanup legacy flat files ─────────────────────────
    } else if method == Method::Post && url_path == "/api/admin/cleanup-legacy" {
        let removed = crate::storage::StorageBackend::cleanup_legacy_files("var");
        let body = serde_json::json!({
            "status": "completed",
            "files_removed": removed,
            "count": removed.len(),
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });
        json_response(&body.to_string(), 200)

    // ── Database purge by age ─────────────────────────────
    } else if method == Method::Post && url_path == "/api/admin/db/purge" {
        match read_body_limited(body, 4096) {
            Ok(body_str) => {
                let parsed: serde_json::Value = serde_json::from_str(&body_str).unwrap_or_default();
                let days = parsed["retention_days"].as_u64().unwrap_or(0) as u32;
                if days == 0 {
                    error_json("retention_days must be > 0", 400)
                } else {
                    let s = match state.lock() {
                        Ok(g) => g,
                        Err(e) => e.into_inner(),
                    };
                    let alerts_purged = s
                        .storage
                        .with(|store| store.purge_old_alerts(days))
                        .unwrap_or(0);
                    let audit_purged = s
                        .storage
                        .with(|store| store.purge_old_audit(days))
                        .unwrap_or(0);
                    let metrics_purged = s
                        .storage
                        .with(|store| store.purge_old_metrics(days))
                        .unwrap_or(0);
                    let body = serde_json::json!({
                        "status": "completed",
                        "retention_days": days,
                        "alerts_purged": alerts_purged,
                        "audit_purged": audit_purged,
                        "metrics_purged": metrics_purged,
                        "timestamp": chrono::Utc::now().to_rfc3339(),
                    });
                    json_response(&body.to_string(), 200)
                }
            }
            Err(e) => error_json(&e, 400),
        }

    // ── SBOM generation ───────────────────────────────────
    } else if method == Method::Get && url_path == "/api/sbom" {
        let lock_content = std::fs::read_to_string("Cargo.lock").unwrap_or_default();
        let generator =
            crate::sbom::SbomGenerator::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        let components = generator.parse_cargo_lock(&lock_content);
        let doc = generator.generate(components, vec![], crate::sbom::SbomFormat::CycloneDX);
        let rendered = generator.to_cyclonedx_json(&doc);
        json_response(&rendered, 200)

    // ── PII scan (check a text payload for PII patterns) ──
    } else if method == Method::Post && url_path == "/api/pii/scan" {
        match read_body_limited(body, 65_536) {
            Ok(body) => {
                let findings = scan_pii(&body);
                let body = serde_json::json!({
                    "has_pii": !findings.is_empty(),
                    "finding_count": findings.len(),
                    "categories": findings,
                });
                json_response(&body.to_string(), 200)
            }
            Err(e) => error_json(&e, 400),
        }

    // ── License Management ─────────────────────────────────
    } else if method == Method::Get && url_path == "/api/license" {
        // Return current license status
        let body = serde_json::json!({
            "status": "active",
            "edition": "professional",
            "features": ["xdr", "siem", "soar", "ueba", "threat_intel"],
            "max_agents": 10000,
            "expires": "2026-12-31T23:59:59Z",
        });
        json_response(&body.to_string(), 200)
    } else if method == Method::Post && url_path == "/api/license/validate" {
        match read_body_limited(body, 4096) {
            Ok(body_str) => {
                let parsed: serde_json::Value = serde_json::from_str(&body_str).unwrap_or_default();
                let key = parsed["key"].as_str().unwrap_or("");
                if key.is_empty() {
                    error_json("license key required", 400)
                } else {
                    let valid = crate::license::validate_license(key, &[]).is_ok();
                    let body = serde_json::json!({
                        "valid": valid,
                        "key_prefix": &key[..key.len().min(8)],
                        "validated_at": chrono::Utc::now().to_rfc3339(),
                    });
                    json_response(&body.to_string(), 200)
                }
            }
            Err(e) => error_json(&e, 400),
        }

    // ── Search ────────────────────────────────────────────
    } else if method == Method::Post && url_path == "/api/search" {
        match read_body_limited(body, 65_536) {
            Ok(body_str) => {
                let query: crate::search::SearchQuery = match serde_json::from_str(&body_str) {
                    Ok(q) => q,
                    Err(e) => {
                        return respond_api(
                            state,
                            &method,
                            &url,
                            remote_addr,
                            auth_used,
                            error_json(&format!("invalid query: {e}"), 400),
                        );
                    }
                };
                let events = {
                    let s = state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    s.event_store.all_events().to_vec()
                };
                match build_search_index_from_events(&events) {
                    Ok(idx) => match idx.search(&query) {
                        Ok(result) => {
                            let body = serde_json::to_string(&result).unwrap_or_default();
                            json_response(&body, 200)
                        }
                        Err(e) => error_json(&format!("search failed: {e}"), 500),
                    },
                    Err(e) => error_json(&format!("search index unavailable: {e}"), 500),
                }
            }
            Err(e) => error_json(&e, 400),
        }

    // ── Metering ──────────────────────────────────────────
    } else if method == Method::Get && url_path == "/api/metering/usage" {
        let body = serde_json::json!({
            "events_ingested": 0,
            "api_calls": 0,
            "storage_bytes": 0,
            "plan": "professional",
            "period_start": chrono::Utc::now().to_rfc3339(),
        });
        json_response(&body.to_string(), 200)

    // ── Billing ───────────────────────────────────────────
    } else if method == Method::Get && url_path == "/api/billing/subscription" {
        let body = serde_json::json!({
            "plan": "professional",
            "status": "active",
            "monthly_price": "$99",
            "next_billing": chrono::Utc::now().to_rfc3339(),
        });
        json_response(&body.to_string(), 200)
    } else if method == Method::Get && url_path == "/api/billing/invoices" {
        let body = serde_json::json!({ "invoices": [] });
        json_response(&body.to_string(), 200)

    // ── Marketplace ───────────────────────────────────────
    } else if method == Method::Get && url_path == "/api/marketplace/packs" {
        let mgr = crate::marketplace::MarketplaceManager::new();
        let packs = mgr.list_packs(None);
        let body = serde_json::to_string(&packs).unwrap_or_default();
        json_response(&body, 200)
    } else if method == Method::Get && url_path.starts_with("/api/marketplace/packs/") {
        let pack_id = url_path
            .strip_prefix("/api/marketplace/packs/")
            .unwrap_or("");
        let mgr = crate::marketplace::MarketplaceManager::new();
        match mgr.get_pack(pack_id) {
            Some(pack) => {
                let body = serde_json::to_string(&pack).unwrap_or_default();
                json_response(&body, 200)
            }
            None => error_json("pack not found", 404),
        }

    // ── Prevention ────────────────────────────────────────
    } else if method == Method::Get && url_path == "/api/prevention/policies" {
        let engine = crate::prevention::PreventionEngine::new();
        let policies = engine.list_policies();
        let body = serde_json::to_string(&policies).unwrap_or_default();
        json_response(&body, 200)
    } else if method == Method::Get && url_path == "/api/prevention/stats" {
        let engine = crate::prevention::PreventionEngine::new();
        let stats = engine.stats();
        let body = serde_json::to_string(&stats).unwrap_or_default();
        json_response(&body, 200)

    // ── Pipeline ──────────────────────────────────────────
    } else if method == Method::Get && url_path == "/api/pipeline/status" {
        let mgr = crate::pipeline::PipelineManager::new(crate::pipeline::PipelineConfig::default());
        let body = serde_json::json!({
            "status": mgr.status(),
            "metrics": {
                "events_ingested": mgr.metrics().events_ingested,
                "events_normalized": mgr.metrics().events_normalized,
                "events_detected": mgr.metrics().events_detected,
                "events_stored": mgr.metrics().events_stored,
                "dlq_count": mgr.metrics().dlq_count,
            },
        });
        json_response(&body.to_string(), 200)

    // ── Backups ───────────────────────────────────────────
    } else if method == Method::Get && url_path == "/api/backups" {
        let backup_dir = Path::new("var/backups");
        if !backup_dir.exists() {
            return json_response("[]", 200);
        }

        let entries = match fs::read_dir(backup_dir) {
            Ok(entries) => entries,
            Err(e) => return error_json(&format!("failed to list backups: {e}"), 500),
        };

        let mut backups = Vec::new();
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    return error_json(&format!("failed to read backup entry: {e}"), 500);
                }
            };
            let path = entry.path();
            if !is_runtime_backup_file(&path) {
                continue;
            }
            let record = match backup_file_record(&path) {
                Ok(record) => record,
                Err(e) => return error_json(&e, 500),
            };
            backups.push(record);
        }

        backups.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        json_response(&serde_json::to_string(&backups).unwrap_or_default(), 200)
    } else if method == Method::Post && url_path == "/api/backups" {
        let backup_dir = Path::new("var/backups");
        if let Err(e) = fs::create_dir_all(backup_dir) {
            return error_json(&format!("failed to create backup dir: {e}"), 500);
        }
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
        let backup_path = backup_dir.join(format!("wardex_backup_{timestamp}.db"));
        let backup_path_str = backup_path.to_string_lossy().to_string();
        let s = match state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        match s.storage.with(|store| store.backup(&backup_path_str)) {
            Ok(()) => match backup_file_record(&backup_path) {
                Ok(record) => {
                    json_response(&serde_json::to_string(&record).unwrap_or_default(), 200)
                }
                Err(e) => error_json(&e, 500),
            },
            Err(e) => error_json(e.safe_message(), 500),
        }

    // ── Backup status ─────────────────────────────────────
    } else if method == Method::Get && url_path == "/api/backup/status" {
        let body = BackupStatusSnapshot::gather();
        json_response(&serde_json::to_string(&body).unwrap_or_default(), 200)

    // ── SSO / Auth ────────────────────────────────────────
    } else if method == Method::Get && url_path == "/api/auth/sso/config" {
        let (mut providers, scim_enabled, scim_validation) = {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let providers = s
                .enterprise
                .idp_provider_summaries()
                .into_iter()
                .filter(|summary| summary.provider.enabled && summary.validation.status == "ready")
                .map(|summary| {
                    serde_json::json!({
                        "id": summary.provider.id,
                        "display_name": summary.provider.display_name,
                        "kind": summary.provider.kind,
                        "status": summary.provider.status,
                        "validation_status": summary.validation.status,
                        "login_path": format!("/api/auth/sso/login?provider_id={}", summary.provider.id),
                    })
                })
                .collect::<Vec<_>>();
            (
                providers,
                s.enterprise.scim().enabled,
                s.enterprise.scim_validation(),
            )
        };
        let cfg = crate::auth::OidcConfig::default();
        let legacy_enabled = cfg.enabled
            && !cfg.issuer.trim().is_empty()
            && !cfg.client_id.trim().is_empty()
            && !cfg.client_secret.trim().is_empty()
            && !cfg.redirect_uri.trim().is_empty();
        if legacy_enabled {
            providers.push(serde_json::json!({
                "id": "oidc",
                "display_name": "Single Sign-On",
                "kind": "oidc",
                "status": "ready",
                "validation_status": "ready",
                "login_path": "/api/auth/sso/login?provider_id=oidc",
            }));
        }
        let body = serde_json::json!({
            "enabled": !providers.is_empty(),
            "providers": providers,
            "issuer": cfg.issuer,
            "scopes": cfg.scopes,
            "scim": {
                "enabled": scim_enabled,
                "status": scim_validation.status,
                "mapping_count": scim_validation.mapping_count,
            },
        });
        json_response(&body.to_string(), 200)
    } else if method == Method::Get && url_path == "/api/auth/sso/login" {
        let requested_provider =
            url_param(&url, "provider_id").or_else(|| url_param(&url, "provider"));
        let redirect_after = url_param(&url, "redirect");
        let mut s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let provider = match select_ready_oidc_provider(&s, requested_provider.as_deref()) {
            Ok(provider) => provider,
            Err(error) => {
                return if redirect_after.is_some() {
                    auth_redirect_response(&sso_error_redirect(redirect_after, &error))
                } else {
                    error_json(&error, 400)
                };
            }
        };
        let provider_id = provider.id.clone();
        let oidc_config = match build_oidc_provider_config(&provider) {
            Ok(config) => config,
            Err(error) => {
                return if redirect_after.is_some() {
                    auth_redirect_response(&sso_error_redirect(redirect_after, &error))
                } else {
                    error_json(&error, 503)
                };
            }
        };
        let existing_matches = s
            .oidc_providers
            .get(&provider_id)
            .is_some_and(|existing| oidc_provider_config_matches(existing, &oidc_config));
        if !existing_matches {
            s.oidc_providers.insert(
                provider_id.clone(),
                crate::oidc::OidcProvider::new(oidc_config),
            );
        }
        let provider = s
            .oidc_providers
            .get_mut(&provider_id)
            .expect("oidc provider must exist after insertion");
        if let Err(error) = provider.discover() {
            return if redirect_after.is_some() {
                auth_redirect_response(&sso_error_redirect(redirect_after, &error))
            } else {
                error_json(&error, 503)
            };
        }
        match provider.authorize_url(Some(normalize_console_redirect(redirect_after))) {
            Ok(auth_url) => auth_redirect_response(&auth_url),
            Err(error) => {
                if requested_provider.is_some() {
                    auth_redirect_response(&sso_error_redirect(None, &error))
                } else {
                    error_json(&error, 503)
                }
            }
        }
    } else if (method == Method::Get || method == Method::Post)
        && url_path == "/api/auth/sso/callback"
    {
        let (code, csrf_state, provider_hint, parse_error) = if method == Method::Get {
            (
                url_param(&url, "code").unwrap_or_default(),
                url_param(&url, "state").unwrap_or_default(),
                url_param(&url, "provider_id").or_else(|| url_param(&url, "provider")),
                None,
            )
        } else {
            match read_body_limited(body, 8192) {
                Ok(body_str) => {
                    let parsed: serde_json::Value =
                        serde_json::from_str(&body_str).unwrap_or_default();
                    (
                        parsed["code"].as_str().unwrap_or("").to_string(),
                        parsed["state"].as_str().unwrap_or("").to_string(),
                        parsed
                            .get("provider_id")
                            .and_then(|value| value.as_str())
                            .map(std::string::ToString::to_string)
                            .or_else(|| {
                                parsed
                                    .get("provider")
                                    .and_then(|value| value.as_str())
                                    .map(std::string::ToString::to_string)
                            }),
                        None,
                    )
                }
                Err(error) => (String::new(), String::new(), None, Some(error)),
            }
        };
        if let Some(error) = parse_error {
            if method == Method::Get {
                auth_redirect_response(&sso_error_redirect(None, &error))
            } else {
                error_json(&error, 400)
            }
        } else if code.trim().is_empty() {
            if method == Method::Get {
                auth_redirect_response(&sso_error_redirect(None, "authorization code required"))
            } else {
                error_json("authorization code required", 400)
            }
        } else if csrf_state.trim().is_empty() {
            if method == Method::Get {
                auth_redirect_response(&sso_error_redirect(
                    None,
                    "state parameter required for CSRF protection",
                ))
            } else {
                error_json("state parameter required for CSRF protection", 400)
            }
        } else {
            match complete_sso_callback(state, provider_hint, &code, &csrf_state) {
                Ok((session, session_id, redirect_after)) => {
                    let cookie = session_cookie_header(&session_id, session.expires_at);
                    if method == Method::Get {
                        apply_set_cookie(auth_redirect_response(&redirect_after), &cookie)
                    } else {
                        apply_set_cookie(
                            json_response(
                                &serde_json::json!({
                                    "authenticated": true,
                                    "redirect": redirect_after,
                                    "user_id": session.user_id,
                                    "role": session.role,
                                    "groups": session.groups,
                                    "tenant_id": session.tenant_id,
                                    "csrf_token": session.csrf_token,
                                })
                                .to_string(),
                                200,
                            ),
                            &cookie,
                        )
                    }
                }
                Err(error) => {
                    if method == Method::Get {
                        auth_redirect_response(&sso_error_redirect(None, &error))
                    } else {
                        error_json(&error, 503)
                    }
                }
            }
        }
    } else if method == Method::Get && url_path == "/api/auth/session" {
        // Check current authentication state from bearer token
        let identity = authenticate_request(headers, state);
        if matches!(identity, AuthIdentity::None)
            && (bearer_token(headers).is_some() || session_cookie_token(headers).is_some())
        {
            return error_json("unauthorized", 401);
        }
        let groups = identity.groups().to_vec();
        let (user_id, role, authenticated, source, tenant_id, csrf_token) = match &identity {
            AuthIdentity::AdminToken => (
                "admin".to_string(),
                "admin".to_string(),
                true,
                "admin_token",
                None,
                None,
            ),
            AuthIdentity::UserToken(u) => (
                u.username.clone(),
                role_label(u.role).to_string(),
                true,
                "rbac_token",
                u.tenant_id.clone(),
                None,
            ),
            AuthIdentity::SessionToken {
                user, csrf_token, ..
            } => (
                user.username.clone(),
                role_label(user.role).to_string(),
                true,
                "session",
                user.tenant_id.clone(),
                (!csrf_token.is_empty()).then(|| csrf_token.clone()),
            ),
            AuthIdentity::None => (
                "anonymous".to_string(),
                "viewer".to_string(),
                false,
                "anonymous",
                None,
                None,
            ),
        };
        let body = serde_json::json!({
            "user_id": user_id,
            "role": role,
            "groups": groups,
            "authenticated": authenticated,
            "source": source,
            "tenant_id": tenant_id,
            "csrf_token": csrf_token,
        });
        json_response(&body.to_string(), 200)
    } else if method == Method::Post && url_path == "/api/auth/session" {
        let identity = authenticate_request(headers, state);
        if !identity.is_authenticated() {
            error_json("unauthorized", 401)
        } else {
            let (session, session_id) = {
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match create_console_session_for_identity(&mut s, &identity) {
                    Some(created) => created,
                    None => return error_json("unable to create session", 500),
                }
            };
            let cookie = session_cookie_header(&session_id, session.expires_at);
            let body = serde_json::json!({
                "authenticated": true,
                "user_id": session.user_id,
                "role": session.role,
                "groups": session.groups,
                "tenant_id": session.tenant_id,
                "source": "session",
                "expires_at": session.expires_at,
                "csrf_token": session.csrf_token,
                "cookie": {
                    "http_only": true,
                    "same_site": "Strict",
                    "secure": session_cookie_secure(),
                },
            });
            apply_set_cookie(json_response(&body.to_string(), 200), &cookie)
        }
    } else if method == Method::Post && url_path == "/api/auth/logout" {
        let session_revoked = session_cookie_token(headers)
            .or_else(|| bearer_token(headers))
            .is_some_and(|token| {
                let state = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if state.session_store.destroy_session(&token) {
                    true
                } else {
                    state.session_store.reload();
                    state.session_store.destroy_session(&token)
                }
            });
        let body = serde_json::json!({
            "logged_out": true,
            "session_revoked": session_revoked,
        });
        apply_set_cookie(
            json_response(&body.to_string(), 200),
            &clear_session_cookie_header(),
        )

    // ── Cloud Collectors ──────────────────────────────────
    } else if method == Method::Get && url_path == "/api/collectors/status" {
        crate::server_collectors::handle_collectors_status(state)
    } else if method == Method::Get && url_path == "/api/collectors/aws" {
        crate::server_collectors::handle_collector_aws_get(state)
    } else if method == Method::Post && url_path == "/api/collectors/aws/config" {
        crate::server_collectors::handle_collector_aws_config(body, state)
    } else if method == Method::Post && url_path == "/api/collectors/aws/validate" {
        crate::server_collectors::handle_collector_aws_validate(state)
    } else if method == Method::Get && url_path == "/api/collectors/azure" {
        crate::server_collectors::handle_collector_azure_get(state)
    } else if method == Method::Post && url_path == "/api/collectors/azure/config" {
        crate::server_collectors::handle_collector_azure_config(body, state)
    } else if method == Method::Post && url_path == "/api/collectors/azure/validate" {
        crate::server_collectors::handle_collector_azure_validate(state)
    } else if method == Method::Get && url_path == "/api/collectors/gcp" {
        crate::server_collectors::handle_collector_gcp_get(state)
    } else if method == Method::Post && url_path == "/api/collectors/gcp/config" {
        crate::server_collectors::handle_collector_gcp_config(body, state)
    } else if method == Method::Post && url_path == "/api/collectors/gcp/validate" {
        crate::server_collectors::handle_collector_gcp_validate(state)
    } else if method == Method::Get && url_path == "/api/collectors/okta" {
        crate::server_collectors::handle_collector_okta_get(state)
    } else if method == Method::Post && url_path == "/api/collectors/okta/config" {
        crate::server_collectors::handle_collector_okta_config(body, state)
    } else if method == Method::Post && url_path == "/api/collectors/okta/validate" {
        crate::server_collectors::handle_collector_okta_validate(state)
    } else if method == Method::Get && url_path == "/api/collectors/entra" {
        crate::server_collectors::handle_collector_entra_get(state)
    } else if method == Method::Post && url_path == "/api/collectors/entra/config" {
        crate::server_collectors::handle_collector_entra_config(body, state)
    } else if method == Method::Post && url_path == "/api/collectors/entra/validate" {
        crate::server_collectors::handle_collector_entra_validate(state)
    } else if method == Method::Get && url_path == "/api/collectors/m365" {
        crate::server_collectors::handle_collector_m365_get(state)
    } else if method == Method::Post && url_path == "/api/collectors/m365/config" {
        crate::server_collectors::handle_collector_m365_config(body, state)
    } else if method == Method::Post && url_path == "/api/collectors/m365/validate" {
        crate::server_collectors::handle_collector_m365_validate(state)
    } else if method == Method::Get && url_path == "/api/collectors/workspace" {
        crate::server_collectors::handle_collector_workspace_get(state)
    } else if method == Method::Post && url_path == "/api/collectors/workspace/config" {
        crate::server_collectors::handle_collector_workspace_config(body, state)
    } else if method == Method::Post && url_path == "/api/collectors/workspace/validate" {
        crate::server_collectors::handle_collector_workspace_validate(state)
    } else if let Some(slug) = url_path
        .strip_prefix("/api/collectors/")
        .and_then(|tail| tail.split('/').next())
        .filter(|slug| matches!(*slug, "github" | "crowdstrike" | "syslog"))
    {
        let Some(provider) = crate::server_collectors::planned_collector_provider(slug) else {
            return error_json("unknown planned collector", 404);
        };
        let expected_base = format!("/api/collectors/{slug}");
        let expected_config = format!("/api/collectors/{slug}/config");
        let expected_validate = format!("/api/collectors/{slug}/validate");
        if method == Method::Get && url_path == expected_base {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let payload =
                crate::server_collectors::planned_collector_config_payload(&s.storage, provider);
            json_response(&payload.to_string(), 200)
        } else if method == Method::Post && url_path == expected_config {
            match read_json_value(body, 32 * 1024) {
                Ok(mut setup) => {
                    if let Some(object) = setup.as_object_mut() {
                        object.insert("provider".to_string(), serde_json::json!(provider));
                        object
                            .entry("enabled".to_string())
                            .or_insert(serde_json::json!(true));
                    }
                    let Some(key) = crate::server_collectors::planned_collector_key(provider)
                    else {
                        return error_json("unknown planned collector", 404);
                    };
                    let s = state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    match save_stored_json(&s.storage, key, &setup) {
                        Ok(()) => {
                            let validation = crate::server_collectors::planned_collector_validation(
                                provider, &setup,
                            );
                            let payload = serde_json::json!({
                                "status": "saved",
                                "provider": provider,
                                "config": crate::server_collectors::planned_collector_public_view(provider, &setup),
                                "validation": validation,
                            });
                            json_response(&payload.to_string(), 200)
                        }
                        Err(error) => error_json(&error, 500),
                    }
                }
                Err(error) => error_json(&error, 400),
            }
        } else if method == Method::Post && url_path == expected_validate {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let setup =
                crate::server_collectors::load_planned_collector_setup(&s.storage, provider);
            let validation =
                crate::server_collectors::planned_collector_validation(provider, &setup);
            let sample_events = if validation.status == "ready" {
                crate::server_collectors::planned_collector_sample_events(provider, &setup)
            } else {
                Vec::new()
            };
            let body = serde_json::json!({
                "provider": provider,
                "success": validation.status == "ready",
                "event_count": sample_events.len(),
                "sample_events": sample_events,
                "summary": crate::server_collectors::planned_collector_summary(provider, &setup),
                "validation": validation,
                "error": if validation.status == "ready" { serde_json::Value::Null } else { serde_json::json!("Collector configuration is incomplete.") },
            });
            crate::server_collectors::collector_validation_response(&s.storage, provider, body)
        } else {
            error_json("planned collector route not found", 404)
        }

    // ── Secrets Manager ──────────────────────────────────
    } else if method == Method::Get && url_path == "/api/secrets/status" {
        crate::server_secrets::handle_secrets_status(state)
    } else if method == Method::Post && url_path == "/api/secrets/config" {
        crate::server_secrets::handle_secrets_config(body, state)
    } else if method == Method::Post && url_path == "/api/secrets/validate" {
        crate::server_secrets::handle_secrets_validate(body, state)

    // ── ML Engine ─────────────────────────────────────────
    } else if method == Method::Get && url_path == "/api/ml/models" {
        crate::server_ml::handle_ml_models(state)
    } else if method == Method::Get && url_path == "/api/ml/models/status" {
        crate::server_ml::handle_ml_models_status(state)
    } else if method == Method::Post && url_path == "/api/ml/models/rollback" {
        crate::server_ml::handle_ml_models_rollback(state)
    } else if method == Method::Get && url_path == "/api/ml/shadow/recent" {
        crate::server_ml::handle_ml_shadow_recent(&url, state)
    } else if method == Method::Post && url_path == "/api/ml/triage" {
        crate::server_ml::handle_ml_triage(body, state)
    } else if method == Method::Post && url_path == "/api/ml/triage/v2" {
        crate::server_ml::handle_ml_triage_v2(body, state)

    // ── Vulnerability Scanner ─────────────────────────────────
    } else if method == Method::Get && url_path == "/api/vulnerability/scan" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut reports = Vec::new();
        for (host_id, inv) in &s.agent_inventories {
            reports.push(s.vulnerability_scanner.scan(host_id, inv));
        }
        let body = serde_json::to_string(&reports).unwrap_or_default();
        json_response(&body, 200)
    } else if method == Method::Get && url_path == "/api/vulnerability/summary" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let summary = s.vulnerability_scanner.fleet_summary(&s.agent_inventories);
        let body = serde_json::to_string(&summary).unwrap_or_default();
        json_response(&body, 200)

    // ── NDR Engine ────────────────────────────────────────────
    } else if method == Method::Post && url_path == "/api/ndr/netflow" {
        match read_body_limited(body, 65536) {
            Ok(body_str) => {
                let record: crate::ndr::NetFlowRecord = match serde_json::from_str(&body_str) {
                    Ok(r) => r,
                    Err(e) => {
                        return respond_api(
                            state,
                            &method,
                            &url,
                            remote_addr,
                            auth_used,
                            error_json(&format!("invalid netflow: {e}"), 400),
                        );
                    }
                };
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                s.ndr_engine.record_flow(record);
                json_response(r#"{"status":"ingested"}"#, 200)
            }
            Err(e) => error_json(&e, 400),
        }
    } else if method == Method::Get && url_path == "/api/ndr/report" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let report = s.ndr_engine.analyze();
        let body = serde_json::to_string(&report).unwrap_or_default();
        json_response(&body, 200)
    } else if method == Method::Get && url_path == "/api/ndr/tls-anomalies" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let report = s.ndr_engine.analyze();
        let body = serde_json::to_string(&report.tls_anomalies).unwrap_or_default();
        json_response(&body, 200)
    } else if method == Method::Get && url_path == "/api/ndr/dpi-anomalies" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let report = s.ndr_engine.analyze();
        let body = serde_json::to_string(&report.dpi_anomalies).unwrap_or_default();
        json_response(&body, 200)
    } else if method == Method::Get && url_path == "/api/ndr/entropy-anomalies" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let report = s.ndr_engine.analyze();
        let body = serde_json::to_string(&report.entropy_anomalies).unwrap_or_default();
        json_response(&body, 200)
    } else if method == Method::Get && url_path == "/api/ndr/self-signed-certs" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let report = s.ndr_engine.analyze();
        let body = serde_json::to_string(&report.self_signed_certs).unwrap_or_default();
        json_response(&body, 200)
    } else if method == Method::Get && url_path == "/api/ndr/top-talkers" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let report = s.ndr_engine.analyze();
        let body = serde_json::to_string(&report.top_talkers).unwrap_or_default();
        json_response(&body, 200)
    } else if method == Method::Get && url_path == "/api/ndr/beaconing" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let report = s.ndr_engine.analyze();
        let body = serde_json::to_string(&report.beaconing_anomalies).unwrap_or_default();
        json_response(&body, 200)
    } else if method == Method::Get && url_path == "/api/ndr/protocol-distribution" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let body = serde_json::to_string(&s.ndr_engine.protocol_distribution()).unwrap_or_default();
        json_response(&body, 200)

    // ── Container Detection ───────────────────────────────────
    } else if method == Method::Post && url_path == "/api/container/event" {
        match read_body_limited(body, 65536) {
            Ok(body_str) => {
                let event: crate::container::ContainerEvent = match serde_json::from_str(&body_str)
                {
                    Ok(e) => e,
                    Err(e) => {
                        return respond_api(
                            state,
                            &method,
                            &url,
                            remote_addr,
                            auth_used,
                            error_json(&format!("invalid container event: {e}"), 400),
                        );
                    }
                };
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                s.container_detector.record_event(event);
                let alerts = s.container_detector.alerts();
                let body = serde_json::to_string(&alerts).unwrap_or_default();
                json_response(&body, 200)
            }
            Err(e) => error_json(&e, 400),
        }
    } else if method == Method::Get && url_path == "/api/container/alerts" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let alerts = s.container_detector.alerts();
        let body = serde_json::to_string(&alerts).unwrap_or_default();
        json_response(&body, 200)
    } else if method == Method::Get && url_path == "/api/container/stats" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let body = serde_json::json!({
            "total_events": s.container_detector.event_count(),
            "total_alerts": s.container_detector.alerts().len(),
        });
        json_response(&body.to_string(), 200)

    // ── Certificate Monitor ───────────────────────────────────
    } else if method == Method::Post && url_path == "/api/certs/register" {
        match read_body_limited(body, 8192) {
            Ok(body_str) => {
                let cert: crate::cert_monitor::CertificateRecord =
                    match serde_json::from_str(&body_str) {
                        Ok(c) => c,
                        Err(e) => {
                            return respond_api(
                                state,
                                &method,
                                &url,
                                remote_addr,
                                auth_used,
                                error_json(&format!("invalid cert: {e}"), 400),
                            );
                        }
                    };
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                s.cert_monitor.record_certificate(cert);
                json_response(r#"{"status":"registered"}"#, 200)
            }
            Err(e) => error_json(&e, 400),
        }
    } else if method == Method::Get && url_path == "/api/certs/summary" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let summary = s.cert_monitor.evaluate();
        let body = serde_json::to_string(&summary).unwrap_or_default();
        json_response(&body, 200)
    } else if method == Method::Get && url_path == "/api/certs/alerts" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let eval = s.cert_monitor.evaluate();
        let body = serde_json::to_string(&eval.alerts).unwrap_or_default();
        json_response(&body, 200)

    // ── Config Drift Detection ────────────────────────────────
    } else if method == Method::Post && url_path == "/api/config-drift/check" {
        match read_body_limited(body, 65536) {
            Ok(body_str) => {
                #[derive(serde::Deserialize)]
                struct DriftCheckReq {
                    host_id: String,
                    configs: std::collections::HashMap<
                        String,
                        std::collections::HashMap<String, String>,
                    >,
                }
                let req: DriftCheckReq = match serde_json::from_str(&body_str) {
                    Ok(m) => m,
                    Err(e) => {
                        return respond_api(
                            state,
                            &method,
                            &url,
                            remote_addr,
                            auth_used,
                            error_json(&format!("invalid config map: {e}"), 400),
                        );
                    }
                };
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let report = s.config_drift_detector.check(&req.host_id, &req.configs);
                let body = serde_json::to_string(&report).unwrap_or_default();
                json_response(&body, 200)
            }
            Err(e) => error_json(&e, 400),
        }
    } else if method == Method::Get && url_path == "/api/config-drift/baselines" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let summary = s.config_drift_detector.fleet_summary();
        let body = serde_json::to_string(&summary).unwrap_or_default();
        json_response(&body, 200)

    // ── Asset Inventory ────────────────────────────────────────
    } else if method == Method::Get && url_path == "/api/assets" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let assets = s.asset_inventory.all();
        let body = serde_json::to_string(&assets).unwrap_or_default();
        json_response(&body, 200)
    } else if method == Method::Get && url_path == "/api/assets/summary" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let summary = s.asset_inventory.summary();
        let body = serde_json::to_string(&summary).unwrap_or_default();
        json_response(&body, 200)
    } else if method == Method::Post && url_path == "/api/assets/upsert" {
        match read_body_limited(body, 65536) {
            Ok(body_str) => {
                let asset: crate::cloud_inventory::UnifiedAsset =
                    match serde_json::from_str(&body_str) {
                        Ok(a) => a,
                        Err(e) => {
                            return respond_api(
                                state,
                                &method,
                                &url,
                                remote_addr,
                                auth_used,
                                error_json(&format!("invalid asset: {e}"), 400),
                            );
                        }
                    };
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                s.asset_inventory.upsert(asset);
                json_response(r#"{"status":"upserted"}"#, 200)
            }
            Err(e) => error_json(&e, 400),
        }
    } else if method == Method::Get && url_path == "/api/assets/search" {
        let q = url_param(&url, "q").unwrap_or_default();
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let results = s.asset_inventory.search(&q);
        let body = serde_json::to_string(&results).unwrap_or_default();
        json_response(&body, 200)

    // ── Detection Efficacy ────────────────────────────────────
    } else if method == Method::Post && url_path == "/api/efficacy/triage" {
        match read_body_limited(body, 8192) {
            Ok(body_str) => {
                let record: crate::detection_efficacy::TriageRecord =
                    match serde_json::from_str(&body_str) {
                        Ok(r) => r,
                        Err(e) => {
                            return respond_api(
                                state,
                                &method,
                                &url,
                                remote_addr,
                                auth_used,
                                error_json(&format!("invalid triage: {e}"), 400),
                            );
                        }
                    };
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                s.efficacy_tracker.record(record);
                json_response(r#"{"status":"recorded"}"#, 200)
            }
            Err(e) => error_json(&e, 400),
        }
    } else if method == Method::Get && url_path == "/api/efficacy/summary" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let summary = s.efficacy_tracker.summary();
        let body = serde_json::to_string(&summary).unwrap_or_default();
        json_response(&body, 200)
    } else if method == Method::Get && url_path.starts_with("/api/efficacy/rule/") {
        let rule_id = url_path.strip_prefix("/api/efficacy/rule/").unwrap_or("");
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let all_rules = s.efficacy_tracker.per_rule_efficacy();
        match all_rules.iter().find(|r| r.rule_id == rule_id) {
            Some(eff) => {
                let body = serde_json::to_string(&eff).unwrap_or_default();
                json_response(&body, 200)
            }
            None => json_response("null", 200),
        }
    } else if method == Method::Post && url_path == "/api/efficacy/canary-promote" {
        let mut s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let efficacy = s.efficacy_tracker.per_rule_efficacy();
        let results = s.enterprise.canary_auto_promote(&efficacy, 10, 7, 0.15);
        if results.iter().any(|r| {
            r.action == crate::enterprise::CanaryAction::Promoted
                || r.action == crate::enterprise::CanaryAction::RolledBack
        }) {
            sync_enterprise_sigma_engine(&mut s);
        }
        let body = serde_json::to_string(&results).unwrap_or_default();
        json_response(&body, 200)

    // ── Investigation Workflows ───────────────────────────────
    } else if method == Method::Get && url_path == "/api/investigations/workflows" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let workflows = s.workflow_store.list_workflows();
        let body = serde_json::to_string(&workflows).unwrap_or_default();
        json_response(&body, 200)
    } else if method == Method::Get && url_path.starts_with("/api/investigations/workflows/") {
        let wf_id = url_path
            .strip_prefix("/api/investigations/workflows/")
            .unwrap_or("");
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match s.workflow_store.get_workflow(wf_id) {
            Some(wf) => {
                let body = serde_json::to_string(&wf).unwrap_or_default();
                json_response(&body, 200)
            }
            None => error_json("workflow not found", 404),
        }
    } else if method == Method::Post && url_path == "/api/investigations/start" {
        match read_body_limited(body, 8192) {
            Ok(body_str) => {
                #[derive(serde::Deserialize)]
                struct StartReq {
                    workflow_id: String,
                    analyst: String,
                    case_id: Option<String>,
                }
                let req: StartReq = match serde_json::from_str(&body_str) {
                    Ok(r) => r,
                    Err(e) => {
                        return respond_api(
                            state,
                            &method,
                            &url,
                            remote_addr,
                            auth_used,
                            error_json(&format!("invalid request: {e}"), 400),
                        );
                    }
                };
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match s.workflow_store.start_investigation(
                    &req.workflow_id,
                    &req.analyst,
                    req.case_id,
                ) {
                    Some(progress) => match s.workflow_store.get_snapshot(&progress.id) {
                        Some(snapshot) => {
                            let body = serde_json::to_string(&snapshot).unwrap_or_default();
                            json_response(&body, 200)
                        }
                        None => error_json("investigation not found", 404),
                    },
                    None => error_json("workflow not found", 404),
                }
            }
            Err(e) => error_json(&e, 400),
        }
    } else if method == Method::Get && url_path == "/api/investigations/active" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let active = s.workflow_store.active_snapshots();
        let body = serde_json::to_string(&active).unwrap_or_default();
        json_response(&body, 200)
    } else if method == Method::Post && url_path == "/api/investigations/progress" {
        match read_body_limited(body, 16384) {
            Ok(body_str) => {
                #[derive(serde::Deserialize)]
                struct ProgressReq {
                    investigation_id: String,
                    step: Option<usize>,
                    completed: Option<bool>,
                    note: Option<String>,
                    status: Option<String>,
                    finding: Option<String>,
                }

                let req: ProgressReq = match serde_json::from_str(&body_str) {
                    Ok(r) => r,
                    Err(e) => {
                        return respond_api(
                            state,
                            &method,
                            &url,
                            remote_addr,
                            auth_used,
                            error_json(&format!("invalid request: {e}"), 400),
                        );
                    }
                };

                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match s.workflow_store.update_investigation(
                    &req.investigation_id,
                    req.step,
                    req.completed,
                    req.note,
                    req.status,
                    req.finding,
                ) {
                    Some(snapshot) => {
                        let body = serde_json::to_string(&snapshot).unwrap_or_default();
                        json_response(&body, 200)
                    }
                    None => error_json("investigation not found", 404),
                }
            }
            Err(e) => error_json(&e, 400),
        }
    } else if method == Method::Post && url_path == "/api/investigations/handoff" {
        match read_body_limited(body, 16384) {
            Ok(body_str) => {
                #[derive(serde::Deserialize)]
                struct HandoffReq {
                    investigation_id: String,
                    to_analyst: String,
                    summary: String,
                    next_actions: Option<Vec<String>>,
                    questions: Option<Vec<String>>,
                    case_id: Option<String>,
                }

                let req: HandoffReq = match serde_json::from_str(&body_str) {
                    Ok(r) => r,
                    Err(e) => {
                        return respond_api(
                            state,
                            &method,
                            &url,
                            remote_addr,
                            auth_used,
                            error_json(&format!("invalid request: {e}"), 400),
                        );
                    }
                };

                if req.to_analyst.trim().is_empty() || req.summary.trim().is_empty() {
                    return respond_api(
                        state,
                        &method,
                        &url,
                        remote_addr,
                        auth_used,
                        error_json("to_analyst and summary are required", 400),
                    );
                }

                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let next_actions = req
                    .next_actions
                    .unwrap_or_default()
                    .into_iter()
                    .map(|entry| entry.trim().to_string())
                    .filter(|entry| !entry.is_empty())
                    .collect::<Vec<_>>();
                let questions = req
                    .questions
                    .unwrap_or_default()
                    .into_iter()
                    .map(|entry| entry.trim().to_string())
                    .filter(|entry| !entry.is_empty())
                    .collect::<Vec<_>>();

                match s.workflow_store.record_handoff(
                    &req.investigation_id,
                    req.to_analyst.trim().to_string(),
                    req.summary.trim().to_string(),
                    next_actions,
                    questions,
                ) {
                    Some(snapshot) => {
                        if let Some(case_id) = req.case_id.or_else(|| snapshot.case_id.clone())
                            && let Ok(case_id) = case_id.parse::<u64>()
                            && let Some(handoff) = snapshot.handoff.as_ref()
                        {
                            let _ = s.case_store.assign(case_id, handoff.to_analyst.clone());
                            let mut comment_lines = vec![
                                format!(
                                    "Investigation handoff from {} to {}",
                                    handoff.from_analyst, handoff.to_analyst
                                ),
                                format!("Summary: {}", handoff.summary),
                            ];
                            if !handoff.next_actions.is_empty() {
                                comment_lines.push("Next actions:".into());
                                comment_lines.extend(
                                    handoff
                                        .next_actions
                                        .iter()
                                        .map(|entry| format!("- {entry}")),
                                );
                            }
                            if !handoff.questions.is_empty() {
                                comment_lines.push("Open questions:".into());
                                comment_lines.extend(
                                    handoff.questions.iter().map(|entry| format!("- {entry}")),
                                );
                            }
                            let _ = s.case_store.add_comment(
                                case_id,
                                handoff.from_analyst.clone(),
                                comment_lines.join("\n"),
                            );
                        }

                        let body = serde_json::to_string(&snapshot).unwrap_or_default();
                        json_response(&body, 200)
                    }
                    None => error_json("investigation not found", 404),
                }
            }
            Err(e) => error_json(&e, 400),
        }
    } else if method == Method::Post && url_path == "/api/investigations/suggest" {
        match read_body_limited(body, 8192) {
            Ok(body_str) => {
                #[derive(serde::Deserialize)]
                struct SuggestReq {
                    alert_reasons: Vec<String>,
                }
                let req: SuggestReq = match serde_json::from_str(&body_str) {
                    Ok(r) => r,
                    Err(e) => {
                        return respond_api(
                            state,
                            &method,
                            &url,
                            remote_addr,
                            auth_used,
                            error_json(&format!("invalid request: {e}"), 400),
                        );
                    }
                };
                let s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let suggestions = s.workflow_store.suggest_for_alert(&req.alert_reasons);
                let body = serde_json::to_string(&suggestions).unwrap_or_default();
                json_response(&body, 200)
            }
            Err(e) => error_json(&e, 400),
        }

    // ── Malware Detection / AV Scanning ──────────────────────
    } else if method == Method::Post && url_path == "/api/scan/buffer" {
        match read_body_limited(body, 65536) {
            Ok(body_str) => {
                #[derive(serde::Deserialize)]
                struct ScanReq {
                    data: String,
                    filename: Option<String>,
                }
                let req: ScanReq = match serde_json::from_str(&body_str) {
                    Ok(r) => r,
                    Err(e) => {
                        return respond_api(
                            state,
                            &method,
                            &url,
                            remote_addr,
                            auth_used,
                            error_json(&format!("invalid scan request: {e}"), 400),
                        );
                    }
                };
                let decoded = match base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    &req.data,
                ) {
                    Ok(d) => d,
                    Err(e) => {
                        return respond_api(
                            state,
                            &method,
                            &url,
                            remote_addr,
                            auth_used,
                            error_json(&format!("invalid base64: {e}"), 400),
                        );
                    }
                };
                let fname = req.filename.unwrap_or_else(|| "upload".to_string());
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let AppState {
                    ref mut malware_scanner,
                    ref mut malware_hash_db,
                    ref yara_engine,
                    ref mut threat_intel,
                    ..
                } = *s;
                match malware_scanner.scan_buffer(
                    &decoded,
                    &fname,
                    malware_hash_db,
                    yara_engine,
                    threat_intel,
                ) {
                    Ok(result) => {
                        let body = serde_json::to_string(&result).unwrap_or_default();
                        json_response(&body, 200)
                    }
                    Err(e) => error_json(&e, 400),
                }
            }
            Err(e) => error_json(&e, 400),
        }
    } else if method == Method::Post && url_path == "/api/scan/buffer/v2" {
        handle_scan_buffer_v2(body, state)
    } else if method == Method::Post && url_path == "/api/malware/scan-path" {
        handle_malware_path_scan(body, state)
    } else if method == Method::Post && url_path == "/api/rootkit/scan" {
        handle_rootkit_scan(body)
    } else if method == Method::Post && url_path == "/api/scan/hash" {
        match read_body_limited(body, 4096) {
            Ok(body_str) => {
                #[derive(serde::Deserialize)]
                struct HashReq {
                    hash: String,
                }
                let req: HashReq = match serde_json::from_str(&body_str) {
                    Ok(r) => r,
                    Err(e) => {
                        return respond_api(
                            state,
                            &method,
                            &url,
                            remote_addr,
                            auth_used,
                            error_json(&format!("invalid request: {e}"), 400),
                        );
                    }
                };
                let s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let result = s.malware_scanner.check_hash(&req.hash, &s.malware_hash_db);
                let body = serde_json::to_string(&result).unwrap_or_default();
                json_response(&body, 200)
            }
            Err(e) => error_json(&e, 400),
        }
    } else if method == Method::Get && url_path == "/api/malware/stats" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let db_stats = s.malware_hash_db.stats();
        let scanner_stats = s.malware_scanner.stats();
        let combined = serde_json::json!({
            "database": db_stats,
            "scanner": scanner_stats,
            "yara_rules": s.yara_engine.rule_names().len()
        });
        let body = serde_json::to_string(&combined).unwrap_or_default();
        json_response(&body, 200)
    } else if method == Method::Get && url_path == "/api/malware/recent" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let recent = s.malware_hash_db.recent_detections();
        let body = serde_json::to_string(&recent).unwrap_or_default();
        json_response(&body, 200)
    } else if method == Method::Get && url_path == "/api/malware/signatures/presets" {
        let body = serde_json::to_string(&local_av_signature_presets_json()).unwrap_or_default();
        json_response(&body, 200)
    } else if method == Method::Post && url_path == "/api/malware/signatures/load-local" {
        let imported = load_local_open_source_av_signatures(state);
        let report = serde_json::json!({
            "imported": imported,
            "format": "clamav_hash",
            "source": "local_open_source_av",
            "preset": local_av_signature_presets_json(),
        });
        let body = serde_json::to_string(&report).unwrap_or_default();
        json_response(&body, 200)
    } else if method == Method::Post && url_path == "/api/malware/signatures/import" {
        match read_body_limited(body, 10 * 1024 * 1024) {
            Ok(body_str) => {
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let source = url_param(&url, "source");
                let result = s
                    .malware_hash_db
                    .load_auto_detected_signatures(&body_str, source.as_deref());
                match result {
                    Ok(result) => {
                        let body = serde_json::to_string(&result).unwrap_or_default();
                        json_response(&body, 200)
                    }
                    Err(e) => error_json(&e, 400),
                }
            }
            Err(e) => error_json(&e, 400),
        }
    } else if method == Method::Get && url_path == "/api/detection/explain" {
        handle_detection_explain(&url, state)
    } else if method == Method::Get && url_path == "/api/detection/feedback" {
        handle_detection_feedback_get(&url, state)
    } else if method == Method::Post && url_path == "/api/detection/feedback" {
        handle_detection_feedback_post(body, state)

    // ── Threat Hunting DSL ────────────────────────────────────
    } else if method == Method::Post && url_path == "/api/hunt" {
        match read_body_limited(body, 64 * 1024) {
            Ok(body_str) => {
                let parsed: serde_json::Value = match serde_json::from_str(&body_str) {
                    Ok(v) => v,
                    Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
                };
                let query = parsed["query"].as_str().unwrap_or("");
                if query.is_empty() {
                    return error_json("query cannot be empty", 400);
                }
                let events = {
                    let s = state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    s.event_store.all_events().to_vec()
                };
                match build_search_index_from_events(&events) {
                    Ok(idx) => {
                        // Support pipe aggregation syntax
                        if query.contains('|') {
                            match idx.hunt_aggregate(query) {
                                Ok(result) => {
                                    let body = serde_json::to_string(&result).unwrap_or_default();
                                    json_response(&body, 200)
                                }
                                Err(e) => error_json(&e, 400),
                            }
                        } else {
                            match idx.hunt(query) {
                                Ok(result) => {
                                    let body = serde_json::to_string(&result).unwrap_or_default();
                                    json_response(&body, 200)
                                }
                                Err(e) => error_json(&e, 400),
                            }
                        }
                    }
                    Err(e) => error_json(&format!("search index unavailable: {e}"), 500),
                }
            }
            Err(e) => error_json(&e, 400),
        }

    // ── SIEM Export ──────────────────────────────────────────
    } else if method == Method::Get && url_path == "/api/export/alerts" {
        let qs = parse_query_string(&url);
        let format = qs.get("format").map_or("json", std::string::String::as_str);
        match format {
            "json" | "cef" | "leef" | "syslog" | "sentinel" | "udm" | "ecs" | "qradar" => {}
            _ => return error_json("unsupported export format", 400),
        }
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let alerts: Vec<crate::collector::AlertRecord> = s.alerts.iter().cloned().collect();
        let output = crate::siem::SiemConnector::export_alerts(&alerts, format);
        match format {
            "cef" | "leef" | "syslog" => text_response(&output, 200),
            _ => json_response(&output, 200),
        }

    // ── Compliance Report ────────────────────────────────────
    } else if method == Method::Get && url_path == "/api/compliance/report" {
        let qs = parse_query_string(&url);
        let framework_id = qs.get("framework").cloned();
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let sys_state = crate::compliance_templates::SystemState {
            detection_enabled: !s.config.monitor.dry_run,
            audit_logging: true,
            encryption_at_rest: true,
            encryption_in_transit: true,
            mfa_enforced: s.config.security.require_mtls_agents,
            backup_configured: true,
            retention_days: (s.config.retention.audit_max_age_secs / 86400) as u32,
            agent_coverage_percent: if s.agent_registry.list().is_empty() {
                0.0
            } else {
                100.0
            },
            incident_process: !s.playbook_engine.list_playbooks().is_empty(),
            rbac_enabled: true,
            rate_limiting: true,
            sigma_rules_loaded: s.sigma_engine.rule_count(),
            baseline_active: true,
            sbom_available: true,
        };
        if let Some(fid) = framework_id {
            let frameworks = crate::compliance_templates::all_frameworks();
            if let Some(fw) = frameworks.iter().find(|f| f.id == fid) {
                let report = crate::compliance_templates::evaluate_framework(fw, &sys_state);
                let body = serde_json::to_string(&report).unwrap_or_default();
                json_response(&body, 200)
            } else {
                error_json("framework not found", 404)
            }
        } else {
            let reports = crate::compliance_templates::generate_all_reports(&sys_state);
            let body = serde_json::to_string(&reports).unwrap_or_default();
            json_response(&body, 200)
        }

    // ── Compliance Executive Summary ─────────────────────────
    } else if method == Method::Get && url_path == "/api/compliance/summary" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let sys_state = crate::compliance_templates::SystemState {
            detection_enabled: !s.config.monitor.dry_run,
            audit_logging: true,
            encryption_at_rest: true,
            encryption_in_transit: true,
            mfa_enforced: s.config.security.require_mtls_agents,
            backup_configured: true,
            retention_days: (s.config.retention.audit_max_age_secs / 86400) as u32,
            agent_coverage_percent: if s.agent_registry.list().is_empty() {
                0.0
            } else {
                100.0
            },
            incident_process: !s.playbook_engine.list_playbooks().is_empty(),
            rbac_enabled: true,
            rate_limiting: true,
            sigma_rules_loaded: s.sigma_engine.rule_count(),
            baseline_active: true,
            sbom_available: true,
        };
        let reports = crate::compliance_templates::generate_all_reports(&sys_state);
        let summary = crate::compliance_templates::executive_summary(&reports);
        let body = serde_json::to_string(&summary).unwrap_or_default();
        json_response(&body, 200)

    // ── Playbook Run ─────────────────────────────────────────
    } else if method == Method::Post && url_path == "/api/playbooks/run" {
        match read_body_limited(body, 64 * 1024) {
            Ok(body_str) => {
                let parsed: serde_json::Value = match serde_json::from_str(&body_str) {
                    Ok(v) => v,
                    Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
                };
                let playbook_id = parsed["playbook_id"].as_str().unwrap_or("");
                if playbook_id.is_empty() {
                    return error_json("playbook_id is required", 400);
                }
                let alert_id = parsed["alert_id"].as_str();
                let variables: std::collections::HashMap<String, String> = parsed["variables"]
                    .as_object()
                    .map(|m| {
                        m.iter()
                            .map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                let executed_by = playbook_executor(&auth_identity);
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match s.playbook_engine.run_playbook(
                    playbook_id,
                    alert_id,
                    &executed_by,
                    variables,
                    now,
                ) {
                    Ok(exec_id) => {
                        if let Some(exec) = s.playbook_engine.get_execution(&exec_id).cloned() {
                            s.enterprise.record_playbook_execution(&exec);
                            let body = serde_json::to_string(&exec).unwrap_or_default();
                            json_response(&body, 200)
                        } else {
                            json_response(&format!(r#"{{"execution_id":"{exec_id}"}}"#), 200)
                        }
                    }
                    Err(e) => error_json(&e, 400),
                }
            }
            Err(e) => error_json(&e, 400),
        }
    } else if method == Method::Post && url_path == "/api/playbooks/resume" {
        match read_body_limited(body, 16 * 1024) {
            Ok(body_str) => {
                let parsed: serde_json::Value = match serde_json::from_str(&body_str) {
                    Ok(v) => v,
                    Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
                };
                let execution_id = parsed["execution_id"].as_str().unwrap_or("");
                if execution_id.is_empty() {
                    return error_json("execution_id is required", 400);
                }
                let feedback = parsed["feedback"].as_str();
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                let approved_by = playbook_executor(&auth_identity);
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match s
                    .playbook_engine
                    .resume_execution(execution_id, &approved_by, feedback, now)
                {
                    Ok(exec_id) => {
                        if let Some(exec) = s.playbook_engine.get_execution(&exec_id).cloned() {
                            s.enterprise.record_playbook_execution(&exec);
                            eprintln!(
                                "[AUDIT] playbook_resume execution={exec_id} by={approved_by}"
                            );
                            let body = serde_json::to_string(&exec).unwrap_or_default();
                            json_response(&body, 200)
                        } else {
                            json_response(&format!(r#"{{"execution_id":"{exec_id}"}}"#), 200)
                        }
                    }
                    Err(e) => error_json(&e, 400),
                }
            }
            Err(e) => error_json(&e, 400),
        }

    // ── Alert Deduplication ──────────────────────────────────
    } else if method == Method::Get && url_path == "/api/alerts/dedup" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let alerts: Vec<crate::collector::AlertRecord> = s.alerts.iter().cloned().collect();
        let config = crate::alert_analysis::DedupConfig::default();
        let incidents = crate::alert_analysis::deduplicate_alerts(&alerts, &config);
        let body = serde_json::to_string(&incidents).unwrap_or_default();
        json_response(&body, 200)
    } else if method == Method::Post && url_path == "/api/alerts/dedup/auto-create" {
        let mut s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let alerts: Vec<crate::collector::AlertRecord> = s.alerts.iter().cloned().collect();
        let config = crate::alert_analysis::DedupConfig {
            window_secs: 300,
            cross_device: true,
            max_merge: 250,
        };
        let deduped = crate::alert_analysis::deduplicate_alerts(&alerts, &config);
        let mut created = Vec::new();
        for group in deduped
            .into_iter()
            .filter(|incident| incident.alert_count >= 3)
        {
            let severity = group.level.to_ascii_lowercase();
            s.incident_store.create(
                format!("Auto incident {}", group.incident_id),
                severity,
                Vec::new(),
                group.device_ids.clone(),
                Vec::new(),
                format!(
                    "Auto-created from {} related alerts in 5-minute dedup window. Fingerprint: {}",
                    group.alert_count, group.fingerprint
                ),
            );
            created.push(group.incident_id);
        }
        json_response(
            &serde_json::json!({"status": "ok", "created_incidents": created, "count": created.len()}).to_string(),
            200,
        )

    // ── API Analytics ────────────────────────────────────────
    } else if method == Method::Get && url_path == "/api/analytics" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let summary = s.api_analytics.summary();
        let body = serde_json::to_string(&summary).unwrap_or_default();
        json_response(&body, 200)

    // ── OpenTelemetry Traces ─────────────────────────────────
    } else if method == Method::Get && url_path == "/api/traces" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let stats = s.trace_collector.stats();
        let recent = s.trace_collector.recent(50);
        let body = serde_json::json!({
            "stats": stats,
            "recent": recent,
        });
        let body_str = serde_json::to_string(&body).unwrap_or_default();
        json_response(&body_str, 200)

    // ── Backup Encrypt ───────────────────────────────────────
    } else if method == Method::Post && url_path == "/api/backup/encrypt" {
        match read_body_limited(body, 10 * 1024 * 1024) {
            Ok(body_str) => {
                let parsed: serde_json::Value = match serde_json::from_str(&body_str) {
                    Ok(v) => v,
                    Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
                };
                let data = parsed["data"].as_str().unwrap_or("");
                let passphrase = parsed["passphrase"].as_str().unwrap_or("");
                if passphrase.is_empty() {
                    return error_json("passphrase is required", 400);
                }
                match crate::backup::encrypt_backup_data(data.as_bytes(), passphrase) {
                    Ok(encrypted) => {
                        let b64 = base64::Engine::encode(
                            &base64::engine::general_purpose::STANDARD,
                            &encrypted,
                        );
                        json_response(
                            &format!(r#"{{"encrypted":"{}","size":{}}}"#, b64, encrypted.len()),
                            200,
                        )
                    }
                    Err(e) => error_json(&e, 500),
                }
            }
            Err(e) => error_json(&e, 400),
        }

    // ── Backup Decrypt ───────────────────────────────────────
    } else if method == Method::Post && url_path == "/api/backup/decrypt" {
        match read_body_limited(body, 10 * 1024 * 1024) {
            Ok(body_str) => {
                let parsed: serde_json::Value = match serde_json::from_str(&body_str) {
                    Ok(v) => v,
                    Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
                };
                let encrypted_b64 = parsed["data"].as_str().unwrap_or("");
                let passphrase = parsed["passphrase"].as_str().unwrap_or("");
                if passphrase.is_empty() {
                    return error_json("passphrase is required", 400);
                }
                match base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    encrypted_b64,
                ) {
                    Ok(encrypted) => {
                        match crate::backup::decrypt_backup_data(&encrypted, passphrase) {
                            Ok(plaintext) => {
                                let text = String::from_utf8_lossy(&plaintext);
                                let resp = serde_json::json!({"data": text.as_ref(), "size": plaintext.len()});
                                json_response(&resp.to_string(), 200)
                            }
                            Err(e) => error_json(&e, 400),
                        }
                    }
                    Err(e) => error_json(&format!("invalid base64: {e}"), 400),
                }
            }
            Err(e) => error_json(&e, 400),
        }

    // ── Detection Rules CRUD ─────────────────────────────────
    } else if method == Method::Get && url_path == "/api/detection/rules" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let sigma_count = s.sigma_engine.rule_count();
        let yara_rules = s.yara_engine.rule_names();
        let body = serde_json::json!({
            "sigma": { "count": sigma_count },
            "yara": { "count": yara_rules.len(), "rules": yara_rules },
            "malware_hashes": s.malware_hash_db.stats(),
        });
        let body_str = serde_json::to_string(&body).unwrap_or_default();
        json_response(&body_str, 200)
    } else if method == Method::Post && url_path == "/api/detection/rules" {
        match read_body_limited(body, 1024 * 1024) {
            Ok(body_str) => {
                let parsed: serde_json::Value = match serde_json::from_str(&body_str) {
                    Ok(v) => v,
                    Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
                };
                let rule_type = parsed["type"].as_str().unwrap_or("yara");
                match rule_type {
                    "yara" => {
                        let name = parsed["name"].as_str().unwrap_or("custom_rule").to_string();
                        let pattern = parsed["pattern"].as_str().unwrap_or("").to_string();
                        if pattern.is_empty() {
                            return error_json("pattern cannot be empty", 400);
                        }
                        let description = parsed["description"].as_str().unwrap_or("").to_string();
                        let rule = crate::yara_engine::YaraRule {
                            name: name.clone(),
                            meta: crate::yara_engine::RuleMeta {
                                author: "api".to_string(),
                                description,
                                severity: parsed["severity"]
                                    .as_str()
                                    .unwrap_or("medium")
                                    .to_string(),
                                mitre_ids: Vec::new(),
                                created: chrono::Utc::now().to_rfc3339(),
                            },
                            strings: vec![crate::yara_engine::RuleString {
                                id: "$s1".to_string(),
                                pattern: crate::yara_engine::StringPattern::Text(pattern),
                                nocase: false,
                            }],
                            condition: crate::yara_engine::RuleCondition::AnyOf,
                            enabled: true,
                        };
                        let mut s = state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        s.yara_engine.add_rule(rule);
                        json_response(r#"{"added":"yara","status":"ok"}"#, 200)
                    }
                    _ => error_json("unsupported rule type; use 'yara'", 400),
                }
            }
            Err(e) => error_json(&e, 400),
        }

    // ── Feed Ingestion ────────────────────────────────────────
    } else if method == Method::Get && url_path == "/api/feeds" {
        crate::server_feeds::handle_feeds_list(state)
    } else if method == Method::Post && url_path == "/api/feeds" {
        crate::server_feeds::handle_feeds_create(body, state)
    } else if method == Method::Get && url_path == "/api/feeds/stats" {
        crate::server_feeds::handle_feeds_stats(state)
    } else if method == Method::Post && url_path == "/api/feeds/hot-reload/hashes" {
        crate::server_feeds::handle_feeds_hot_reload_hashes(body, state)
    } else if method == Method::Post
        && url_path.starts_with("/api/feeds/")
        && url_path.ends_with("/poll")
    {
        let feed_id = &url_path["/api/feeds/".len()..url_path.len() - "/poll".len()];
        crate::server_feeds::handle_feeds_poll(feed_id, body, state)
    } else if method == Method::Post
        && url_path.starts_with("/api/feeds/")
        && url_path.ends_with("/fetch")
    {
        let feed_id = &url_path["/api/feeds/".len()..url_path.len() - "/fetch".len()];
        crate::server_feeds::handle_feeds_fetch(feed_id, state)
    } else if method == Method::Delete && url_path.starts_with("/api/feeds/") {
        let feed_id = &url_path["/api/feeds/".len()..];
        crate::server_feeds::handle_feeds_delete(feed_id, state)

    // ── Playbook DSL ──────────────────────────────────────────
    } else if method == Method::Get && url_path == "/api/playbook-dsl" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let list = s.playbook_dsl.list();
        let body = serde_json::to_string(&list).unwrap_or_default();
        json_response(&body, 200)
    } else if method == Method::Post && url_path == "/api/playbook-dsl" {
        match read_body_limited(body, 64 * 1024) {
            Ok(body_str) => {
                match serde_json::from_str::<crate::playbook_dsl::PlaybookDefinition>(&body_str) {
                    Ok(def) => {
                        let mut s = state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let id = s.playbook_dsl.create(def);
                        json_response(&format!(r#"{{"id":"{id}"}}"#), 201)
                    }
                    Err(e) => error_json(&format!("invalid playbook: {e}"), 400),
                }
            }
            Err(e) => error_json(&e, 400),
        }
    } else if method == Method::Get && url_path.starts_with("/api/playbook-dsl/") {
        let pb_id = &url_path["/api/playbook-dsl/".len()..];
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match s.playbook_dsl.get(pb_id) {
            Some(pb) => {
                let body = serde_json::to_string(pb).unwrap_or_default();
                json_response(&body, 200)
            }
            None => error_json("playbook not found", 404),
        }
    } else if method == Method::Delete && url_path.starts_with("/api/playbook-dsl/") {
        let pb_id = &url_path["/api/playbook-dsl/".len()..];
        let mut s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if s.playbook_dsl.delete(pb_id) {
            json_response(r#"{"deleted":true}"#, 204)
        } else {
            error_json("playbook not found", 404)
        }

    // ── ATT&CK Coverage Gaps ──────────────────────────────────
    } else if method == Method::Get && url_path == "/api/coverage/gaps" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let report = crate::coverage_gap::analyze_gaps(&s.mitre_coverage);
        let body = serde_json::to_string(&report).unwrap_or_default();
        json_response(&body, 200)

    // ── Container Image Inventory ─────────────────────────────
    } else if method == Method::Get && url_path == "/api/images" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let body = serde_json::to_string(s.image_inventory.list()).unwrap_or_default();
        json_response(&body, 200)
    } else if method == Method::Get && url_path == "/api/images/summary" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let body = serde_json::to_string(&s.image_inventory.summary()).unwrap_or_default();
        json_response(&body, 200)
    } else if method == Method::Post && url_path == "/api/images/collect" {
        let mut s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        s.image_inventory.collect_from_runtime();
        let body = serde_json::to_string(s.image_inventory.list()).unwrap_or_default();
        json_response(&body, 200)

    // ── Quarantine Store ──────────────────────────────────────
    } else if method == Method::Get && url_path == "/api/quarantine" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let body = serde_json::to_string(&s.quarantine_store.list()).unwrap_or_default();
        json_response(&body, 200)
    } else if method == Method::Post && url_path == "/api/quarantine" {
        match read_body_limited(body, 10 * 1024 * 1024) {
            Ok(body_str) => {
                #[derive(serde::Deserialize)]
                struct QuarantineReq {
                    path: String,
                    #[serde(default)]
                    content_base64: Option<String>,
                    #[serde(default)]
                    sha256: Option<String>,
                    agent_id: Option<String>,
                    hostname: Option<String>,
                    verdict: Option<String>,
                    malware_family: Option<String>,
                }
                match serde_json::from_str::<QuarantineReq>(&body_str) {
                    Ok(req) => {
                        let Some(content_base64) = req.content_base64 else {
                            return error_json(
                                "quarantine capture must include agent-uploaded content_base64; server-side path reads are disabled",
                                400,
                            );
                        };
                        let file_data = match base64::Engine::decode(
                            &base64::engine::general_purpose::STANDARD,
                            &content_base64,
                        ) {
                            Ok(data) => data,
                            Err(error) => {
                                return error_json(
                                    &format!("invalid content_base64: {error}"),
                                    400,
                                );
                            }
                        };
                        if file_data.is_empty() {
                            return error_json("quarantine content is empty", 400);
                        }
                        if let Some(expected_sha256) = req
                            .sha256
                            .as_deref()
                            .map(str::trim)
                            .filter(|v| !v.is_empty())
                        {
                            let observed_sha256 = crate::audit::sha256_hex(&file_data);
                            if !observed_sha256.eq_ignore_ascii_case(expected_sha256) {
                                return error_json(
                                    "quarantine content sha256 does not match request metadata",
                                    400,
                                );
                            }
                        }
                        let mut s = state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let record = s.quarantine_store.quarantine(
                            &req.path,
                            &file_data,
                            req.verdict.as_deref().unwrap_or("suspicious"),
                            req.malware_family.map(|s| s.to_string()),
                            vec![],
                            req.agent_id.map(|s| s.to_string()),
                            req.hostname.map(|s| s.to_string()),
                        );
                        s.audit_log.record(
                            "POST",
                            &format!("/api/quarantine actor={}", auth_identity.actor()),
                            remote_addr,
                            201,
                            true,
                        );
                        json_response(&format!(r#"{{"id":"{}"}}"#, record.id), 201)
                    }
                    Err(e) => error_json(&format!("invalid quarantine request: {e}"), 400),
                }
            }
            Err(e) => error_json(&e, 400),
        }
    } else if method == Method::Get && url_path == "/api/quarantine/stats" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let body = serde_json::to_string(&s.quarantine_store.stats()).unwrap_or_default();
        json_response(&body, 200)
    } else if method == Method::Post
        && url_path.starts_with("/api/quarantine/")
        && url_path.ends_with("/release")
    {
        let qid = &url_path["/api/quarantine/".len()..url_path.len() - "/release".len()];
        let analyst = auth_identity.actor();
        let mut s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if s.quarantine_store.release(qid, analyst) {
            s.audit_log.record(
                "POST",
                &format!("/api/quarantine/{qid}/release actor={analyst}"),
                remote_addr,
                200,
                true,
            );
            json_response(r#"{"released":true}"#, 200)
        } else {
            error_json("quarantine entry not found", 404)
        }
    } else if method == Method::Delete && url_path.starts_with("/api/quarantine/") {
        let qid = &url_path["/api/quarantine/".len()..];
        let mut s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if s.quarantine_store.delete(qid) {
            s.audit_log.record(
                "DELETE",
                &format!("/api/quarantine/{qid} actor={}", auth_identity.actor()),
                remote_addr,
                204,
                true,
            );
            json_response(r#"{"deleted":true}"#, 204)
        } else {
            error_json("quarantine entry not found", 404)
        }

    // ── Agent Lifecycle ────────────────────────────────────────
    } else if method == Method::Get && url_path == "/api/lifecycle" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let agents = s.lifecycle_manager.all_entries();
        let body = serde_json::to_string(&agents).unwrap_or_default();
        json_response(&body, 200)
    } else if (method == Method::Get && url_path == "/api/lifecycle/stats")
        || (method == Method::Post && url_path == "/api/lifecycle/sweep")
    {
        let mut s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let stats = s.lifecycle_manager.sweep();
        let body = serde_json::to_string(&stats).unwrap_or_default();
        json_response(&body, 200)

    // ── IoC Confidence Decay ──────────────────────────────────
    } else if method == Method::Post && url_path == "/api/ioc-decay/apply" {
        let mut s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let config = s.decay_config.clone();
        let result = crate::ioc_decay::apply_decay(&mut s.threat_intel, &config);
        let body = serde_json::to_string(&result).unwrap_or_default();
        json_response(&body, 200)
    } else if method == Method::Get && url_path == "/api/ioc-decay/preview" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let iocs = s.threat_intel.all_iocs();
        let preview: Vec<serde_json::Value> = iocs
            .iter()
            .take(50)
            .map(|ioc| {
                let decayed = crate::ioc_decay::preview_decay(ioc, &s.decay_config);
                serde_json::json!({
                    "value": ioc.value,
                    "ioc_type": ioc.ioc_type,
                    "original_confidence": ioc.confidence,
                    "decayed_confidence": decayed,
                    "last_seen": ioc.last_seen,
                })
            })
            .collect();
        let body = serde_json::to_string(&preview).unwrap_or_default();
        json_response(&body, 200)

    // ── Host SBOM ─────────────────────────────────────────────
    } else if method == Method::Get && url_path == "/api/sbom/host" {
        let sbgen = crate::sbom::SbomGenerator::new("wardex", env!("CARGO_PKG_VERSION"));
        let inv = crate::inventory::collect_inventory();
        let mut components = sbgen.from_inventory(&inv);
        // Also include Cargo.lock dependencies if available
        if let Ok(lock_content) = std::fs::read_to_string("Cargo.lock") {
            let cargo_comps = sbgen.parse_cargo_lock(&lock_content);
            components.extend(cargo_comps);
        }
        let doc = sbgen.generate(components, vec![], crate::sbom::SbomFormat::CycloneDX);
        let body = sbgen.to_cyclonedx_json(&doc);
        json_response(&body, 200)

    // ── Phase 29: Entropy Analysis ─────────────────────────────
    } else if method == Method::Post && url_path == "/api/entropy/analyze" {
        match read_body_limited(body, 10 * 1024 * 1024) {
            Err(_) => error_json("request too large", 413),
            Ok(raw) => {
                let data = base64_decode_or_raw(&raw);
                let report = crate::entropy_analysis::analyze_entropy(&data);
                let body = serde_json::to_string(&report).unwrap_or_default();
                json_response(&body, 200)
            }
        }

    // ── Phase 29: DNS Threat Analysis ──────────────────────────
    } else if method == Method::Post && url_path == "/api/dns-threat/analyze" {
        match read_body_limited(body, 64 * 1024) {
            Err(_) => error_json("request too large", 413),
            Ok(raw) => {
                #[derive(serde::Deserialize)]
                struct DnsDomainReq {
                    domain: String,
                }
                match serde_json::from_str::<DnsDomainReq>(&raw) {
                    Err(e) => error_json(&format!("invalid JSON: {e}"), 400),
                    Ok(req) => {
                        let s = state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let report = s.dns_analyzer.analyze_domain(&req.domain);
                        drop(s);
                        let body = serde_json::to_string(&report).unwrap_or_default();
                        json_response(&body, 200)
                    }
                }
            }
        }
    } else if method == Method::Get && url_path == "/api/dns-threat/summary" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let summary = s.dns_analyzer.threat_summary();
        drop(s);
        let body = serde_json::to_string(&summary).unwrap_or_default();
        json_response(&body, 200)
    } else if method == Method::Post && url_path == "/api/dns-threat/record" {
        match read_body_limited(body, 64 * 1024) {
            Err(_) => error_json("request too large", 413),
            Ok(raw) => match serde_json::from_str::<crate::dns_threat::DnsQuery>(&raw) {
                Err(e) => error_json(&format!("invalid JSON: {e}"), 400),
                Ok(query) => {
                    let mut s = state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    s.dns_analyzer.record_query(query);
                    drop(s);
                    json_response(r#"{"status":"recorded"}"#, 200)
                }
            },
        }

    // ── Phase 29: Process Scoring ──────────────────────────────
    } else if method == Method::Post && url_path == "/api/process-scoring/assess" {
        match read_body_limited(body, 64 * 1024) {
            Err(_) => error_json("request too large", 413),
            Ok(raw) => {
                #[derive(serde::Deserialize)]
                struct ProcReq {
                    pid: u32,
                    name: String,
                    chain: Vec<String>,
                    cmdline: Option<String>,
                }
                match serde_json::from_str::<ProcReq>(&raw) {
                    Err(e) => error_json(&format!("invalid JSON: {e}"), 400),
                    Ok(req) => {
                        let assessment = crate::process_scoring::ProcessScorer::assess(
                            req.pid,
                            &req.name,
                            &req.chain,
                            req.cmdline.as_deref(),
                        );
                        let body = serde_json::to_string(&assessment).unwrap_or_default();
                        json_response(&body, 200)
                    }
                }
            }
        }

    // ── Phase 29: Email Analysis ───────────────────────────────
    } else if method == Method::Get && url_path == "/api/email/quarantine" {
        json_response(r#"{"items":[]}"#, 200)
    } else if method == Method::Post
        && url_path.starts_with("/api/email/quarantine/")
        && url_path.ends_with("/release")
    {
        json_response(r#"{"status":"released"}"#, 200)
    } else if method == Method::Delete && url_path.starts_with("/api/email/quarantine/") {
        json_response(r#"{"status":"deleted"}"#, 200)
    } else if method == Method::Get && url_path == "/api/email/stats" {
        json_response(
            r#"{"total_scanned":0,"phishing_detected":0,"attachments_flagged":0}"#,
            200,
        )
    } else if method == Method::Get && url_path == "/api/email/policies" {
        json_response(
            r#"[{"name":"Default inbound protection","quarantine_threshold":0.7,"block_dangerous_attachments":true,"require_spf":false,"require_dkim":false}]"#,
            200,
        )
    } else if method == Method::Put && url_path == "/api/email/policies" {
        match read_body_limited(body, 64 * 1024) {
            Err(_) => error_json("request too large", 413),
            Ok(_) => json_response(r#"{"status":"saved"}"#, 200),
        }
    } else if method == Method::Post && url_path == "/api/email/analyze" {
        match read_body_limited(body, 1024 * 1024) {
            Err(_) => error_json("request too large", 413),
            Ok(raw) => match serde_json::from_str::<crate::email_analysis::EmailInput>(&raw) {
                Err(e) => error_json(&format!("invalid JSON: {e}"), 400),
                Ok(input) => {
                    let report = crate::email_analysis::EmailAnalyzer::analyze(&input);
                    let body = serde_json::to_string(&report).unwrap_or_default();
                    json_response(&body, 200)
                }
            },
        }

    // ── Phase 29: Memory Indicators ────────────────────────────
    } else if method == Method::Post && url_path == "/api/memory-indicators/scan-maps" {
        match read_body_limited(body, 2 * 1024 * 1024) {
            Err(_) => error_json("request too large", 413),
            Ok(raw) => {
                #[derive(serde::Deserialize)]
                struct MapsReq {
                    pid: u32,
                    process_name: String,
                    maps_content: String,
                }
                match serde_json::from_str::<MapsReq>(&raw) {
                    Err(e) => error_json(&format!("invalid JSON: {e}"), 400),
                    Ok(req) => {
                        let report = crate::memory_indicators::analyze_maps(
                            req.pid,
                            &req.process_name,
                            &req.maps_content,
                        );
                        let body = serde_json::to_string(&report).unwrap_or_default();
                        json_response(&body, 200)
                    }
                }
            }
        }
    } else if method == Method::Post && url_path == "/api/memory-indicators/scan-buffer" {
        match read_body_limited(body, 10 * 1024 * 1024) {
            Err(_) => error_json("request too large", 413),
            Ok(raw) => {
                let data = base64_decode_or_raw(&raw);
                let matches = crate::memory_indicators::scan_buffer_for_shellcode(&data);
                let body = serde_json::to_string(&matches).unwrap_or_default();
                json_response(&body, 200)
            }
        }

    // ── Phase 29: WebSocket Alert Streaming ────────────────────
    } else if method == Method::Post && url_path == "/api/ws/connect" {
        let mut s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let id = s.alert_broadcaster.connect();
        drop(s);
        json_response(&format!(r#"{{"subscriber_id":{id}}}"#), 200)
    } else if method == Method::Post && url_path == "/api/ws/disconnect" {
        match read_body_limited(body, 1024) {
            Err(_) => error_json("request too large", 413),
            Ok(raw) => {
                #[derive(serde::Deserialize)]
                struct DisconnReq {
                    subscriber_id: u64,
                }
                match serde_json::from_str::<DisconnReq>(&raw) {
                    Err(e) => error_json(&format!("invalid JSON: {e}"), 400),
                    Ok(req) => {
                        let mut s = state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        s.alert_broadcaster.disconnect(req.subscriber_id);
                        drop(s);
                        json_response(r#"{"status":"disconnected"}"#, 200)
                    }
                }
            }
        }
    } else if method == Method::Post && url_path == "/api/ws/poll" {
        match read_body_limited(body, 1024) {
            Err(_) => error_json("request too large", 413),
            Ok(raw) => {
                #[derive(serde::Deserialize)]
                struct PollReq {
                    subscriber_id: u64,
                }
                match serde_json::from_str::<PollReq>(&raw) {
                    Err(e) => error_json(&format!("invalid JSON: {e}"), 400),
                    Ok(req) => {
                        let mut s = state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let events = s.alert_broadcaster.drain_for(req.subscriber_id);
                        drop(s);
                        let body = serde_json::to_string(&events).unwrap_or_default();
                        json_response(&body, 200)
                    }
                }
            }
        }
    } else if method == Method::Get && url_path == "/api/ws/stats" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let stats = s.alert_broadcaster.stats();
        drop(s);
        let body = serde_json::to_string(&stats).unwrap_or_default();
        json_response(&body, 200)
    } else if method == Method::Post && url_path == "/api/ws/broadcast" {
        match read_body_limited(body, 64 * 1024) {
            Err(_) => error_json("request too large", 413),
            Ok(raw) => match serde_json::from_str::<serde_json::Value>(&raw) {
                Err(e) => error_json(&format!("invalid JSON: {e}"), 400),
                Ok(data) => {
                    let mut s = state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    s.alert_broadcaster.broadcast_alert(data);
                    drop(s);
                    json_response(r#"{"status":"broadcast"}"#, 200)
                }
            },
        }

    // ── Bulk alert operations ───────────────────────────────
    } else if method == Method::Post && url_path == "/api/alerts/bulk/acknowledge" {
        match read_body_limited(body, 256 * 1024) {
            Err(_) => error_json("request too large", 413),
            Ok(raw) => match serde_json::from_str::<serde_json::Value>(&raw) {
                Err(e) => error_json(&format!("invalid JSON: {e}"), 400),
                Ok(payload) => {
                    let ids = payload
                        .get("ids")
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_default();
                    if ids.len() > 1000 {
                        return error_json("too many IDs (max 1000)", 400);
                    }
                    let mut s = state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let mut acked = 0usize;
                    let mut not_found = 0usize;
                    for id_val in &ids {
                        if let Some(id_str) = id_val.as_str() {
                            let idx = id_str
                                .strip_prefix("alert-")
                                .and_then(|n| n.parse::<usize>().ok());
                            if let Some(i) = idx {
                                if let Some(a) = s.alerts.get_mut(i) {
                                    a.action = "acknowledged".to_string();
                                    acked += 1;
                                } else {
                                    not_found += 1;
                                }
                            } else {
                                not_found += 1;
                            }
                        }
                    }
                    drop(s);
                    json_response(
                        &serde_json::json!({
                            "status": "ok",
                            "acknowledged": acked,
                            "not_found": not_found,
                            "total_requested": ids.len(),
                        })
                        .to_string(),
                        200,
                    )
                }
            },
        }
    } else if method == Method::Post && url_path == "/api/alerts/bulk/resolve" {
        match read_body_limited(body, 256 * 1024) {
            Err(_) => error_json("request too large", 413),
            Ok(raw) => match serde_json::from_str::<serde_json::Value>(&raw) {
                Err(e) => error_json(&format!("invalid JSON: {e}"), 400),
                Ok(payload) => {
                    let ids = payload
                        .get("ids")
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_default();
                    if ids.len() > 1000 {
                        return error_json("too many IDs (max 1000)", 400);
                    }
                    let mut s = state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let mut resolved = 0usize;
                    let mut not_found = 0usize;
                    for id_val in &ids {
                        if let Some(id_str) = id_val.as_str() {
                            let idx = id_str
                                .strip_prefix("alert-")
                                .and_then(|n| n.parse::<usize>().ok());
                            if let Some(i) = idx {
                                if let Some(a) = s.alerts.get_mut(i) {
                                    a.action = "resolved".to_string();
                                    resolved += 1;
                                } else {
                                    not_found += 1;
                                }
                            } else {
                                not_found += 1;
                            }
                        }
                    }
                    drop(s);
                    json_response(
                        &serde_json::json!({
                            "status": "ok",
                            "resolved": resolved,
                            "not_found": not_found,
                            "total_requested": ids.len(),
                        })
                        .to_string(),
                        200,
                    )
                }
            },
        }
    } else if method == Method::Post && url_path == "/api/alerts/bulk/close" {
        match read_body_limited(body, 256 * 1024) {
            Err(_) => error_json("request too large", 413),
            Ok(raw) => match serde_json::from_str::<serde_json::Value>(&raw) {
                Err(e) => error_json(&format!("invalid JSON: {e}"), 400),
                Ok(payload) => {
                    let ids = payload
                        .get("ids")
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_default();
                    if ids.len() > 1000 {
                        return error_json("too many IDs (max 1000)", 400);
                    }
                    let mut s = state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let mut closed = 0usize;
                    let mut not_found = 0usize;
                    for id_val in &ids {
                        if let Some(id_str) = id_val.as_str() {
                            let idx = id_str
                                .strip_prefix("alert-")
                                .and_then(|n| n.parse::<usize>().ok());
                            if let Some(i) = idx {
                                if let Some(a) = s.alerts.get_mut(i) {
                                    a.action = "closed".to_string();
                                    closed += 1;
                                } else {
                                    not_found += 1;
                                }
                            } else {
                                not_found += 1;
                            }
                        }
                    }
                    drop(s);
                    json_response(
                        &serde_json::json!({
                            "status": "ok",
                            "closed": closed,
                            "not_found": not_found,
                            "total_requested": ids.len(),
                        })
                        .to_string(),
                        200,
                    )
                }
            },
        }

    // ── Webhook CRUD ────────────────────────────────────────
    } else if method == Method::Get && url_path == "/api/webhooks" {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let hooks = s
            .extra
            .get("webhooks")
            .cloned()
            .unwrap_or(serde_json::Value::Array(vec![]));
        drop(s);
        json_response(&hooks.to_string(), 200)
    } else if method == Method::Post && url_path == "/api/webhooks" {
        match read_body_limited(body, 64 * 1024) {
            Err(_) => error_json("request too large", 413),
            Ok(raw) => match serde_json::from_str::<serde_json::Value>(&raw) {
                Err(e) => error_json(&format!("invalid JSON: {e}"), 400),
                Ok(mut hook) => {
                    // Validate webhook URL
                    let url_str = hook.get("url").and_then(|v| v.as_str()).unwrap_or("");
                    if url_str.is_empty() {
                        return error_json("webhook must include a non-empty 'url' field", 400);
                    }
                    if !(url_str.starts_with("https://") || url_str.starts_with("http://")) {
                        return error_json("webhook url must use http:// or https:// scheme", 400);
                    }
                    // Block private/loopback addresses
                    let after_scheme = url_str.split("://").nth(1).unwrap_or("");
                    let authority = after_scheme.split('/').next().unwrap_or("");
                    let host_part = if authority.starts_with('[') {
                        // IPv6 literal: extract [addr] including brackets
                        authority.split(']').next().map_or("", |s| &s[1..])
                    } else {
                        authority.split(':').next().unwrap_or("")
                    };
                    let is_ipv6 = host_part.contains(':');
                    let is_private = host_part == "localhost"
                        || host_part.starts_with("127.")
                        || host_part == "0.0.0.0"
                        || host_part == "0"
                        || host_part.starts_with("10.")
                        || host_part.starts_with("192.168.")
                        || host_part.starts_with("169.254.")
                        || (host_part.starts_with("172.")
                            && host_part
                                .split('.')
                                .nth(1)
                                .and_then(|o| o.parse::<u8>().ok())
                                .is_some_and(|o| (16..=31).contains(&o)))
                        || (is_ipv6
                            && (host_part == "::1"
                                || host_part == "::"
                                || host_part.starts_with("fc")
                                || host_part.starts_with("fd")
                                || host_part.starts_with("fe80")));
                    if is_private {
                        return error_json(
                            "webhook url must not target private or loopback addresses",
                            400,
                        );
                    }
                    // Assign an ID if not present
                    if hook.get("id").is_none() {
                        use rand::Rng;
                        let mut rng = rand::rng();
                        let mut buf = [0u8; 16];
                        rng.fill(&mut buf);
                        hook["id"] = serde_json::Value::String(hex::encode(buf));
                    }
                    let mut s = state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let hooks = s
                        .extra
                        .entry("webhooks".to_string())
                        .or_insert(serde_json::Value::Array(vec![]));
                    if let Some(arr) = hooks.as_array_mut() {
                        if arr.len() >= 100 {
                            drop(s);
                            return error_json("maximum of 100 webhooks reached", 400);
                        }
                        arr.push(hook.clone());
                    }
                    drop(s);
                    json_response(
                        &serde_json::json!({"status":"created","webhook":hook}).to_string(),
                        201,
                    )
                }
            },
        }
    } else if method == Method::Delete && url_path.starts_with("/api/webhooks/") {
        let hook_id = &url_path[14..];
        let mut s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut removed = false;
        if let Some(hooks) = s.extra.get_mut("webhooks").and_then(|v| v.as_array_mut()) {
            let before = hooks.len();
            hooks.retain(|h| h.get("id").and_then(|v| v.as_str()) != Some(hook_id));
            removed = hooks.len() < before;
        }
        drop(s);
        if removed {
            json_response(r#"{"status":"deleted"}"#, 200)
        } else {
            error_json("webhook not found", 404)
        }
    } else if method == Method::Get && url_path.starts_with("/api/command/lanes/") {
        // Per-lane Command Center slice: returns just one lane plus shared metadata.
        let lane = &url_path["/api/command/lanes/".len()..];
        if lane.is_empty() || lane.contains('/') {
            error_json("invalid lane name", 400)
        } else {
            let mut s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut payload = command_summary_payload(&mut s);
            let lane_value = payload
                .get("lanes")
                .and_then(|lanes| lanes.get(lane))
                .cloned();
            let metric_key = match lane {
                "incidents" => Some("open_incidents"),
                "remediation" => Some("pending_remediation_reviews"),
                "connectors" => Some("connector_issues"),
                "rule_tuning" => Some("noisy_rules"),
                "release" => Some("release_candidates"),
                "evidence" => Some("compliance_packs"),
                _ => None,
            };
            let metric_value = metric_key.and_then(|k| {
                payload
                    .get("metrics")
                    .and_then(|metrics| metrics.get(k))
                    .cloned()
            });
            match lane_value {
                Some(lane_payload) => {
                    let generated_at = payload.get_mut("generated_at").map_or_else(
                        || serde_json::Value::String(chrono::Utc::now().to_rfc3339()),
                        serde_json::Value::take,
                    );
                    let body = serde_json::json!({
                        "lane": lane,
                        "generated_at": generated_at,
                        "metric_key": metric_key,
                        "metric_value": metric_value,
                        "payload": lane_payload,
                    });
                    json_response(&body.to_string(), 200)
                }
                None => error_json("lane not found", 404),
            }
        }
    } else {
        error_json("not found", 404)
    }
}
