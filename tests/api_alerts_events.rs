mod common;
use common::*;

// ── GET /api/health ────────────────────────────────────────────

#[test]
fn health_returns_version_and_platform() {
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/health", base(port)))
        .call()
        .expect("health request");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("version").is_some());
    assert!(body.get("uptime_secs").is_some());
    assert!(body.get("platform").is_some());
    assert!(body.get("hostname").is_some());
}

// ── GET /api/alerts ────────────────────────────────────────────

#[test]
fn alerts_returns_empty_list_initially() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/alerts", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("alerts request");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    let arr = body.as_array().unwrap();
    assert!(arr.is_empty());
}

#[test]
fn alerts_query_supports_limit_and_offset() {
    let (port, token) = spawn_test_server();
    for severity in ["elevated", "severe", "critical"] {
        let resp = ureq::post(&format!("{}/api/alerts/sample", base(port)))
            .set("Authorization", &auth_header(&token))
            .send_json(serde_json::json!({ "severity": severity }))
            .expect("inject sample alert");
        assert_eq!(resp.status(), 200);
    }

    let resp = ureq::get(&format!("{}/api/alerts?limit=1&offset=1", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("alerts with pagination");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    let arr = body.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["id"].as_u64(), Some(1));
    assert_eq!(arr[0]["_index"].as_u64(), Some(1));
    assert_eq!(arr[0]["level"].as_str(), Some("Severe"));
}

#[test]
fn alerts_endpoint_returns_enriched_process_fields_for_seeded_alerts() {
    let seeded_alert = AlertRecord {
        timestamp: "2026-04-28T12:00:00Z".to_string(),
        hostname: wardex::collector::detect_platform().hostname,
        platform: std::env::consts::OS.to_string(),
        score: 9.1,
        confidence: 0.97,
        level: "Critical".to_string(),
        action: "monitor".to_string(),
        reasons: vec![
            "python3 spawned curl from /usr/bin/python3 toward login.example.test".to_string(),
        ],
        sample: TelemetrySample {
            timestamp_ms: 1,
            cpu_load_pct: 87.0,
            memory_load_pct: 63.0,
            temperature_c: 0.0,
            network_kbps: 420.0,
            auth_failures: 0,
            battery_pct: 100.0,
            integrity_drift: 0.0,
            process_count: 222,
            disk_pressure_pct: 12.0,
        },
        enforced: false,
        mitre: vec![],
        narrative: None,
    };

    let (port, token) = spawn_test_server_with_seeded_alerts(vec![seeded_alert]);

    let resp = ureq::get(&format!("{}/api/alerts?limit=1", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("alerts enrichment request");
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.into_json().unwrap();
    let arr = body.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    let alert = &arr[0];

    assert!(alert["entities"].is_array());
    assert!(matches!(
        alert["process_resolution"].as_str(),
        Some("unresolved" | "unique" | "multiple" | "remote_host")
    ));
    assert!(
        alert["process_names"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|value| value.as_str())
            .any(|name| name == "python3")
    );
    assert!(
        alert["process_names"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|value| value.as_str())
            .any(|name| name == "curl")
    );
    assert!(
        alert["entities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entity| entity["entity_type"].as_str() == Some("ProcessName"))
    );
    // process_candidates presence depends on what processes are currently running;
    // assert the field is consistent with process_resolution instead.
    let resolution = alert["process_resolution"].as_str().unwrap_or("");
    if resolution == "unresolved" || resolution == "remote_host" {
        assert!(alert.get("process_candidates").is_none());
        assert!(alert.get("process").is_none());
    } else {
        assert!(alert.get("process_candidates").is_some());
    }
}

#[test]
fn process_threads_endpoint_returns_snapshot_for_self_pid() {
    let (port, token) = spawn_test_server();
    let pid = std::process::id();

    let resp = ureq::get(&format!("{}/api/processes/threads?pid={pid}", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("process threads request");
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["pid"].as_u64(), Some(pid as u64));
    assert!(body["hostname"].is_string());
    assert!(body["platform"].is_string());
    assert!(body["identifier_type"].is_string());
    assert!(body["threads"].is_array());
    assert!(body["thread_count"].as_u64().is_some());
    assert!(body["wait_reason_count"].as_u64().is_some());
    assert!(body["hot_threads"].is_array());
    assert!(body["blocked_threads"].is_array());
    assert!(body["top_cpu_percent"].as_f64().is_some());
}

#[test]
fn process_threads_endpoint_requires_auth() {
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/processes/threads?pid=1", base(port))).call();
    assert!(resp.is_err());
    if let Err(ureq::Error::Status(code, _)) = resp {
        assert_eq!(code, 401);
    } else {
        panic!("expected HTTP 401");
    }
}

#[test]
fn process_threads_endpoint_rejects_missing_pid() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/processes/threads", base(port)))
        .set("Authorization", &auth_header(&token))
        .call();
    assert!(resp.is_err());
    if let Err(ureq::Error::Status(code, _)) = resp {
        assert_eq!(code, 400);
    } else {
        panic!("expected HTTP 400");
    }
}

#[test]
fn alerts_query_without_auth_returns_401() {
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/alerts?limit=1", base(port))).call();
    assert!(resp.is_err());
    let err = resp.unwrap_err();
    if let ureq::Error::Status(code, _) = err {
        assert_eq!(code, 401);
    } else {
        panic!("expected HTTP error");
    }
}

#[test]
fn incidents_query_supports_limit_and_offset() {
    let (port, token) = spawn_test_server();
    let mut created_ids = Vec::new();
    for title in ["Incident one", "Incident two", "Incident three"] {
        let created: serde_json::Value = ureq::post(&format!("{}/api/incidents", base(port)))
            .set("Authorization", &auth_header(&token))
            .send_json(serde_json::json!({
                "title": title,
                "severity": "High",
                "summary": format!("{title} summary"),
            }))
            .expect("create incident")
            .into_json()
            .unwrap();
        created_ids.push(created["id"].as_u64().unwrap());
    }

    let resp = ureq::get(&format!("{}/api/incidents?limit=1&offset=1", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("incidents with pagination");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    let arr = body.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["id"].as_u64(), Some(created_ids[1]));
    assert_eq!(arr[0]["title"].as_str(), Some("Incident two"));
}

// ── GET /api/alerts/count ──────────────────────────────────────

#[test]
fn alerts_count_returns_zero_initially() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/alerts/count", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("alerts count request");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["total"], 0);
    assert_eq!(body["critical"], 0);
    assert_eq!(body["severe"], 0);
    assert_eq!(body["elevated"], 0);
}

// ── DELETE /api/alerts — auth required ─────────────────────────

#[test]
fn delete_alerts_without_auth_returns_401() {
    let (port, _token) = spawn_test_server();
    let resp = ureq::delete(&format!("{}/api/alerts", base(port))).call();
    assert!(resp.is_err());
    let err = resp.unwrap_err();
    if let ureq::Error::Status(code, _) = err {
        assert_eq!(code, 401);
    } else {
        panic!("expected HTTP error");
    }
}

#[test]
fn delete_alerts_with_auth_clears() {
    let (port, token) = spawn_test_server();
    let resp = ureq::delete(&format!("{}/api/alerts", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["status"], "cleared");
}

// ── GET /api/endpoints ─────────────────────────────────────────

#[test]
fn endpoints_returns_array() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/endpoints", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("endpoints request");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    let arr = body.as_array().unwrap();
    assert!(arr.len() >= 10);
    assert!(
        arr.iter()
            .any(|entry| entry["path"] == "/api/monitoring/options" && entry["auth"] == true)
    );
    assert!(
        arr.iter()
            .any(|entry| entry["path"] == "/api/host/info" && entry["auth"] == true)
    );
    assert!(
        arr.iter()
            .any(|entry| entry["path"] == "/api/alerts/{id}" && entry["auth"] == true)
    );
    assert!(
        arr.iter()
            .any(|entry| entry["path"] == "/api/threat-intel/status" && entry["auth"] == true)
    );
    assert!(
        arr.iter()
            .any(|entry| entry["path"] == "/api/threat-intel/library" && entry["auth"] == true)
    );
    assert!(
        arr.iter()
            .any(|entry| entry["path"] == "/api/playbooks" && entry["auth"] == true)
    );
    assert!(
        arr.iter()
            .any(|entry| entry["path"] == "/api/fleet/dashboard" && entry["auth"] == true)
    );
    assert!(arr.iter().any(
        |entry| entry["path"] == "/api/release/deployment-trust-report" && entry["auth"] == true
    ));
    assert!(
        arr.iter()
            .any(|entry| entry["path"] == "/api/agents" && entry["auth"] == true)
    );
    assert!(
        arr.iter()
            .any(|entry| entry["path"] == "/api/cases" && entry["auth"] == true)
    );
    assert!(
        arr.iter()
            .any(|entry| entry["path"] == "/api/events" && entry["auth"] == true)
    );
    assert!(
        arr.iter()
            .any(|entry| entry["path"] == "/api/events/search" && entry["auth"] == true)
    );
    assert!(
        arr.iter()
            .any(|entry| entry["path"] == "/api/response/approvals" && entry["auth"] == true)
    );
    assert!(
        arr.iter()
            .any(|entry| entry["path"] == "/api/rollout/config" && entry["auth"] == true)
    );
    assert!(
        arr.iter()
            .any(|entry| entry["path"] == "/api/timeline/host" && entry["auth"] == true)
    );
    assert!(
        arr.iter()
            .any(|entry| entry["path"] == "/api/queue/stats" && entry["auth"] == true)
    );
    assert!(
        arr.iter()
            .any(|entry| entry["path"] == "/api/agents/{id}/status" && entry["auth"] == true)
    );
}

#[test]
fn query_string_subroutes_still_hit_exact_handlers() {
    let (port, token) = spawn_test_server();

    let injected = ureq::post(&format!("{}/api/alerts/sample", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({ "severity": "severe" }))
        .expect("inject sample alert");
    assert_eq!(injected.status(), 200);

    let report_resp = ureq::get(&format!(
        "{}/api/reports/executive-summary?noop=1",
        base(port)
    ))
    .set("Authorization", &auth_header(&token))
    .call()
    .expect("executive summary with query");
    assert_eq!(report_resp.status(), 200);
    let report_body: serde_json::Value = report_resp.into_json().unwrap();
    assert!(report_body.is_object());

    let analysis_resp = ureq::get(&format!("{}/api/alerts/analysis?noop=1", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("alert analysis with query");
    assert_eq!(analysis_resp.status(), 200);
    let analysis_body: serde_json::Value = analysis_resp.into_json().unwrap();
    assert!(analysis_body["total_alerts"].as_u64().unwrap() >= 1);

    let grouped_resp = ureq::get(&format!("{}/api/alerts/grouped?noop=1", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("grouped alerts with query");
    assert_eq!(grouped_resp.status(), 200);
    let grouped_body: serde_json::Value = grouped_resp.into_json().unwrap();
    assert!(grouped_body.as_array().is_some());

    let stats_resp = ureq::get(&format!("{}/api/cases/stats?noop=1", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("case stats with query");
    assert_eq!(stats_resp.status(), 200);
    let stats_body: serde_json::Value = stats_resp.into_json().unwrap();
    assert!(stats_body["total"].as_u64().is_some());
}

#[test]
fn advanced_operational_routes_require_auth_and_accept_query_strings() {
    let (port, token) = spawn_test_server();

    for path in [
        "/api/playbooks",
        "/api/fleet/status",
        "/api/platform",
        "/api/beacon/analyze",
        "/api/evidence/plan/linux",
        "/api/updates/releases",
    ] {
        match ureq::get(&format!("{}{}", base(port), path)).call() {
            Err(ureq::Error::Status(401, _)) => {}
            other => panic!("expected 401 for {path}, got {other:?}"),
        }
    }

    for path in [
        "/api/playbooks?noop=1",
        "/api/fleet/status?noop=1",
        "/api/platform?noop=1",
        "/api/beacon/analyze?noop=1",
        "/api/evidence/plan/linux?noop=1",
        "/api/ueba/risky?noop=1",
        "/api/updates/releases?noop=1",
    ] {
        let resp = ureq::get(&format!("{}{}", base(port), path))
            .set("Authorization", &auth_header(&token))
            .call()
            .unwrap_or_else(|err| panic!("authed request failed for {path}: {err}"));
        assert_eq!(resp.status(), 200, "expected 200 for {path}");
    }
}

#[test]
fn monitoring_options_without_auth_returns_401() {
    let (port, _token) = spawn_test_server();
    let err = ureq::get(&format!("{}/api/monitoring/options", base(port))).call();
    match err {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401, got {other:?}"),
    }
}

#[test]
fn monitoring_options_returns_grouped_payload() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/monitoring/options", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("monitoring options");
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body["host"].is_object());
    assert!(body["groups"].as_array().unwrap().len() >= 2);
    let first_group = &body["groups"].as_array().unwrap()[0];
    assert!(first_group["label"].is_string());
    assert!(
        first_group["options"]
            .as_array()
            .unwrap()
            .iter()
            .all(|option| option["id"].is_string())
    );
    assert!(
        !body["summary"]["platform_guidance"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let auth_option = body["groups"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|group| group["options"].as_array().unwrap().iter())
        .find(|option| option["id"] == "auth_events")
        .expect("auth_events option present");
    assert_eq!(auth_option["mode"], "configurable");
}

#[test]
fn viewer_and_analyst_roles_can_access_operator_read_flows() {
    let (port, token) = spawn_test_server();

    let viewer: serde_json::Value = ureq::post(&format!("{}/api/rbac/users", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "username": "viewer-ops",
            "role": "viewer"
        }))
        .expect("create viewer")
        .into_json()
        .unwrap();
    let viewer_token = viewer["token"].as_str().unwrap().to_string();

    let analyst: serde_json::Value = ureq::post(&format!("{}/api/rbac/users", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "username": "analyst-ops",
            "role": "analyst"
        }))
        .expect("create analyst")
        .into_json()
        .unwrap();
    let analyst_token = analyst["token"].as_str().unwrap().to_string();

    for path in [
        "/api/status",
        "/api/report",
        "/api/telemetry/current",
        "/api/host/info",
        "/api/monitoring/options",
        "/api/slo/status",
        "/api/workbench/overview",
        "/api/cases",
        "/api/cases/stats",
        "/api/queue/alerts",
        "/api/playbooks",
        "/api/updates/releases",
        "/api/threat-intel/status",
        "/api/threat-intel/library",
        "/api/timeline/host?hostname=viewer-ops-host",
    ] {
        let viewer_resp = ureq::get(&format!("{}{}", base(port), path))
            .set("Authorization", &auth_header(&viewer_token))
            .call()
            .unwrap_or_else(|err| panic!("viewer request failed for {path}: {err}"));
        assert_eq!(viewer_resp.status(), 200, "viewer should reach {path}");

        let analyst_resp = ureq::get(&format!("{}{}", base(port), path))
            .set("Authorization", &auth_header(&analyst_token))
            .call()
            .unwrap_or_else(|err| panic!("analyst request failed for {path}: {err}"));
        assert_eq!(analyst_resp.status(), 200, "analyst should reach {path}");
    }

    let search_resp = ureq::post(&format!("{}/api/events/search", base(port)))
        .set("Authorization", &auth_header(&viewer_token))
        .send_json(serde_json::json!({
            "text": "high_cpu",
            "limit": 5
        }))
        .expect("viewer event search");
    assert_eq!(search_resp.status(), 200);

    let graph_resp = ureq::post(&format!("{}/api/investigation/graph", base(port)))
        .set("Authorization", &auth_header(&analyst_token))
        .send_json(serde_json::json!({
            "center": "viewer-ops-host",
            "depth": 1
        }))
        .expect("analyst investigation graph");
    assert_eq!(graph_resp.status(), 200);
}

#[test]
fn rbac_user_reissue_returns_random_token_and_invalidates_old_one() {
    let (port, token) = spawn_test_server();

    let first: serde_json::Value = ureq::post(&format!("{}/api/rbac/users", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "username": "viewer-rotate",
            "role": "viewer"
        }))
        .expect("create initial viewer")
        .into_json()
        .unwrap();
    let first_token = first["token"].as_str().unwrap().to_string();
    assert_eq!(first_token.len(), 64);
    assert!(first_token.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(!first_token.starts_with("tok-"));

    let first_status = ureq::get(&format!("{}/api/status", base(port)))
        .set("Authorization", &auth_header(&first_token))
        .call()
        .expect("viewer status with first token");
    assert_eq!(first_status.status(), 200);

    let second: serde_json::Value = ureq::post(&format!("{}/api/rbac/users", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "username": "viewer-rotate",
            "role": "viewer"
        }))
        .expect("reissue viewer")
        .into_json()
        .unwrap();
    let second_token = second["token"].as_str().unwrap().to_string();
    assert_eq!(second_token.len(), 64);
    assert!(second_token.chars().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(first_token, second_token);

    match ureq::get(&format!("{}/api/status", base(port)))
        .set("Authorization", &auth_header(&first_token))
        .call()
    {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected first token to be invalidated, got {other:?}"),
    }

    let second_status = ureq::get(&format!("{}/api/status", base(port)))
        .set("Authorization", &auth_header(&second_token))
        .call()
        .expect("viewer status with second token");
    assert_eq!(second_status.status(), 200);
}

#[test]
fn malformed_dynamic_paths_return_404() {
    let (port, token) = spawn_test_server();
    for path in [
        "/api/reports/executive-summaryy",
        "/api/alerts/counts",
        "/api/entities/user",
        "/api/entities/user/",
        "/api/entities//timeline",
        "/api/entities/user/alice/timeline/extra",
        "/api/incidents/1/storyline/extra",
        "/api/cases/stats-extra",
    ] {
        match ureq::get(&format!("{}{}", base(port), path))
            .set("Authorization", &auth_header(&token))
            .call()
        {
            Err(ureq::Error::Status(404, _)) => {}
            other => panic!("expected 404 for {path}, got {other:?}"),
        }
    }
}

#[test]
fn prefix_aliases_do_not_match_exact_asset_search_route() {
    let (port, token) = spawn_test_server();
    match ureq::get(&format!("{}/api/assets/searching?q=host", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
    {
        Err(ureq::Error::Status(404, _)) => {}
        other => panic!("expected 404 for /api/assets/searching, got {other:?}"),
    }
}

// ── POST /api/config/save — auth required ──────────────────────

#[test]
fn config_save_without_auth_returns_401() {
    let (port, _token) = spawn_test_server();
    let resp = ureq::post(&format!("{}/api/config/save", base(port))).send_string("");
    assert!(resp.is_err());
    let err = resp.unwrap_err();
    if let ureq::Error::Status(code, _) = err {
        assert_eq!(code, 401);
    } else {
        panic!("expected HTTP error");
    }
}

// ═══════════════════════════════════════════════════════════════════
// XDR Agent Management
// ═══════════════════════════════════════════════════════════════════

// ── POST /api/agents/token ─────────────────────────────────────

#[test]
fn create_enrollment_token_requires_auth() {
    let (port, _token) = spawn_test_server();
    let resp = ureq::post(&format!("{}/api/agents/token", base(port)))
        .set("Content-Type", "application/json")
        .send_string(r#"{"max_uses":5}"#);
    assert!(resp.is_err());
    if let Err(ureq::Error::Status(code, _)) = resp {
        assert_eq!(code, 401);
    }
}

#[test]
fn create_enrollment_token_and_enroll_agent() {
    let (port, token) = spawn_test_server();

    // Create token
    let resp = ureq::post(&format!("{}/api/agents/token", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(r#"{"max_uses":5}"#)
        .expect("create token");
    assert_eq!(resp.status(), 200);
    let tok: serde_json::Value = resp.into_json().unwrap();
    let enrollment_token = tok["token"].as_str().unwrap();
    assert!(!enrollment_token.is_empty());
    assert_eq!(tok["max_uses"].as_u64().unwrap(), 5);

    // Enroll agent
    let body = serde_json::json!({
        "enrollment_token": enrollment_token,
        "hostname": "test-agent-1",
        "platform": "linux",
        "version": "0.15.0",
    });
    let resp = ureq::post(&format!("{}/api/agents/enroll", base(port)))
        .set("Content-Type", "application/json")
        .send_string(&body.to_string())
        .expect("enroll agent");
    assert_eq!(resp.status(), 200);
    let enroll: serde_json::Value = resp.into_json().unwrap();
    let agent_id = enroll["agent_id"].as_str().unwrap();
    assert!(!agent_id.is_empty());
    assert!(enroll.get("heartbeat_interval_secs").is_some());

    // Heartbeat
    let resp = ureq::post(&format!("{}/api/agents/{}/heartbeat", base(port), agent_id))
        .set("Content-Type", "application/json")
        .send_string(r#"{"version":"0.15.0"}"#)
        .expect("heartbeat");
    assert_eq!(resp.status(), 200);
    let hb: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(hb["status"].as_str().unwrap(), "ok");

    // Get agent status
    let resp = ureq::get(&format!("{}/api/agents/{}/status", base(port), agent_id))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("agent status");
    assert_eq!(resp.status(), 200);
    let status: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(status["hostname"].as_str().unwrap(), "test-agent-1");
    assert_eq!(status["status"].as_str().unwrap(), "online");

    // List agents (requires auth)
    let resp = ureq::get(&format!("{}/api/agents", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("list agents");
    assert_eq!(resp.status(), 200);
    let agents: serde_json::Value = resp.into_json().unwrap();
    let agent_entries = agents.as_array().unwrap();
    assert_eq!(agent_entries.len(), 2);
    assert!(
        agent_entries
            .iter()
            .any(|agent| agent["id"] == serde_json::json!(LOCAL_CONSOLE_AGENT_ID))
    );
    assert_eq!(
        find_agent_by_id(&agents, agent_id)["hostname"]
            .as_str()
            .unwrap(),
        "test-agent-1"
    );

    // Deregister agent (requires auth)
    let resp = ureq::request("DELETE", &format!("{}/api/agents/{}", base(port), agent_id))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("deregister");
    assert_eq!(resp.status(), 200);
    let dr: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(dr["status"].as_str().unwrap(), "deregistered");
}

#[test]
fn enroll_with_invalid_token_returns_403() {
    let (port, _token) = spawn_test_server();
    let body = serde_json::json!({
        "enrollment_token": "invalid-token-abc123",
        "hostname": "bad-agent",
        "platform": "linux",
        "version": "0.15.0",
    });
    let resp = ureq::post(&format!("{}/api/agents/enroll", base(port)))
        .set("Content-Type", "application/json")
        .send_string(&body.to_string());
    assert!(resp.is_err());
    if let Err(ureq::Error::Status(code, _)) = resp {
        assert_eq!(code, 403);
    }
}

// ── POST /api/events ──────────────────────────────────────────

#[test]
fn event_ingest_and_list() {
    let (port, token) = spawn_test_server();

    // Create token + enroll
    let resp = ureq::post(&format!("{}/api/agents/token", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(r#"{"max_uses":1}"#)
        .unwrap();
    let tok: serde_json::Value = resp.into_json().unwrap();
    let enrollment_token = tok["token"].as_str().unwrap();

    let body = serde_json::json!({
        "enrollment_token": enrollment_token,
        "hostname": "event-agent",
        "platform": "linux",
        "version": "0.15.0",
    });
    let resp = ureq::post(&format!("{}/api/agents/enroll", base(port)))
        .set("Content-Type", "application/json")
        .send_string(&body.to_string())
        .unwrap();
    let enroll: serde_json::Value = resp.into_json().unwrap();
    let agent_id = enroll["agent_id"].as_str().unwrap();

    // Ingest events
    let batch = serde_json::json!({
        "agent_id": agent_id,
        "events": [{
            "timestamp": "2025-01-01T00:00:00Z",
            "hostname": "event-agent",
            "platform": "linux",
            "score": 7.5,
            "confidence": 0.95,
            "level": "Critical",
            "action": "isolate",
            "reasons": ["high_cpu"],
            "sample": {
                "timestamp_ms": 0, "cpu_load_pct": 95.0, "memory_load_pct": 50.0,
                "temperature_c": 60.0, "network_kbps": 100.0, "auth_failures": 0,
                "battery_pct": 80.0, "integrity_drift": 0.1,
                "process_count": 50, "disk_pressure_pct": 10.0
            },
            "enforced": false
        }]
    });
    let resp = ureq::post(&format!("{}/api/events", base(port)))
        .set("Content-Type", "application/json")
        .send_string(&batch.to_string())
        .expect("ingest events");
    assert_eq!(resp.status(), 200);
    let result: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(result["ingested"].as_u64().unwrap(), 1);

    // List events
    let resp = ureq::get(&format!("{}/api/events", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("list events");
    assert_eq!(resp.status(), 200);
    let events: serde_json::Value = resp.into_json().unwrap();
    assert!(!events.as_array().unwrap().is_empty());

    let summary = ureq::get(&format!("{}/api/events/summary", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("event summary")
        .into_json::<serde_json::Value>()
        .unwrap();
    assert_eq!(summary["total_events"].as_u64().unwrap(), 1);
    assert!(!summary["top_reasons"].as_array().unwrap().is_empty());
}

#[test]
fn event_reads_without_auth_return_401() {
    let (port, _token) = spawn_test_server();
    let err = ureq::get(&format!("{}/api/events", base(port))).call();
    match err {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401, got {other:?}"),
    }

    let err = ureq::get(&format!("{}/api/events/summary", base(port))).call();
    match err {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401, got {other:?}"),
    }
}

// ── Policy distribution ────────────────────────────────────────

#[test]
fn policy_publish_and_current() {
    let (port, token) = spawn_test_server();

    // No policy initially
    let resp = ureq::get(&format!("{}/api/policy/current", base(port)))
        .call()
        .expect("get current policy");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["version"].as_u64().unwrap(), 0);

    // Publish policy (requires auth)
    let policy = serde_json::json!({
        "version": 0,
        "published_at": "",
        "alert_threshold": 4.5,
        "interval_secs": 15,
        "watch_paths": ["/etc", "/var/log"],
        "dry_run": false,
        "syslog": true,
        "cef": false
    });
    let resp = ureq::post(&format!("{}/api/policy/publish", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(&policy.to_string())
        .expect("publish policy");
    assert_eq!(resp.status(), 200);
    let result: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(result["version"].as_u64().unwrap(), 1);

    // Fetch current policy
    let resp = ureq::get(&format!("{}/api/policy/current", base(port)))
        .call()
        .expect("get current policy after publish");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["version"].as_u64().unwrap(), 1);
    assert_eq!(body["alert_threshold"].as_f64().unwrap(), 4.5);

    let history = ureq::get(&format!("{}/api/policy/history", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("get policy history")
        .into_json::<serde_json::Value>()
        .unwrap();
    assert_eq!(history.as_array().unwrap().len(), 0);
}

#[test]
fn policy_history_without_auth_returns_401() {
    let (port, _token) = spawn_test_server();
    let err = ureq::get(&format!("{}/api/policy/history", base(port))).call();
    match err {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401, got {other:?}"),
    }
}

// ── SIEM status ────────────────────────────────────────────────

#[test]
fn siem_status_returns_disabled_by_default() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/siem/status", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("siem status");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(!body["enabled"].as_bool().unwrap());
    assert_eq!(body["total_pushed"].as_u64().unwrap(), 0);
}

// ── Fleet dashboard ────────────────────────────────────────────

#[test]
fn fleet_dashboard_returns_summary() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/fleet/dashboard", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("fleet dashboard");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("fleet").is_some());
    assert!(body.get("events").is_some());
    assert!(body.get("policy").is_some());
    assert!(body.get("updates").is_some());
    assert!(body["updates"]["campaign"].is_object());
    assert!(body["updates"]["campaign"]["current_stage_counts"]["prepared"].is_u64());
    assert!(body.get("siem").is_some());
    assert_eq!(body["fleet"]["total_agents"].as_u64().unwrap(), 1);
    assert!(body["events"]["analytics"].is_object());
    assert!(body["policy"]["history_depth"].is_u64());
}

#[test]
fn monitoring_paths_requires_auth_and_returns_payload() {
    let (port, token) = spawn_test_server();
    let err = ureq::get(&format!("{}/api/monitoring/paths", base(port))).call();
    match err {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401, got {other:?}"),
    }

    let body: serde_json::Value = ureq::get(&format!("{}/api/monitoring/paths", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("monitoring paths")
        .into_json()
        .unwrap();
    assert!(body["file_integrity_paths"].is_array());
    assert!(body["persistence_paths"].is_array());
    assert!(body["scope"].is_object());
}

// ── Update check ──────────────────────────────────────────────

#[test]
fn update_check_no_updates_available() {
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!(
        "{}/api/agents/update?current_version=0.15.0&platform=linux",
        base(port)
    ))
    .call()
    .expect("update check");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(!body["update_available"].as_bool().unwrap());
}

#[test]
fn remote_update_assignment_flows_through_heartbeat_and_update_check() {
    let (port, token) = spawn_test_server();

    let created = ureq::post(&format!("{}/api/agents/token", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(r#"{"max_uses":1}"#)
        .expect("create token")
        .into_json::<serde_json::Value>()
        .unwrap();
    let enrollment_token = created["token"].as_str().unwrap();

    let enrolled = ureq::post(&format!("{}/api/agents/enroll", base(port)))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "enrollment_token": enrollment_token,
                "hostname": "update-agent",
                "platform": "linux",
                "version": "0.15.0",
            })
            .to_string(),
        )
        .expect("enroll agent")
        .into_json::<serde_json::Value>()
        .unwrap();
    let agent_id = enrolled["agent_id"].as_str().unwrap();

    ureq::post(&format!("{}/api/updates/publish", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "version": "0.16.0",
                "platform": "linux",
                "binary_base64": "aGVsbG8=",
                "release_notes": "security fix",
                "mandatory": true,
            })
            .to_string(),
        )
        .expect("publish release");

    let deployed = ureq::post(&format!("{}/api/updates/deploy", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "agent_id": agent_id,
                "version": "0.16.0",
                "platform": "linux",
                "rollout_group": "canary",
            })
            .to_string(),
        )
        .expect("assign deployment")
        .into_json::<serde_json::Value>()
        .unwrap();
    assert_eq!(deployed["status"].as_str().unwrap(), "assigned");
    assert_eq!(
        deployed["deployment"]["rollout_group"].as_str().unwrap(),
        "canary"
    );
    assert!(!deployed["deployment"]["allow_downgrade"].as_bool().unwrap());

    let heartbeat = ureq::post(&format!("{}/api/agents/{}/heartbeat", base(port), agent_id))
        .set("Content-Type", "application/json")
        .send_string(r#"{"version":"0.15.0","health":{"pending_alerts":2,"telemetry_queue_depth":2,"update_state":"downloading","update_target_version":"0.16.0"}}"#)
        .expect("heartbeat")
        .into_json::<serde_json::Value>()
        .unwrap();
    assert!(heartbeat["update_assigned"].as_bool().unwrap());
    assert_eq!(heartbeat["target_version"].as_str().unwrap(), "0.16.0");

    let details = ureq::get(&format!("{}/api/agents/{}/details", base(port), agent_id))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("agent details after heartbeat")
        .into_json::<serde_json::Value>()
        .unwrap();
    assert_eq!(details["health"]["pending_alerts"].as_u64().unwrap(), 2);
    assert_eq!(
        details["deployment"]["status"].as_str().unwrap(),
        "downloading"
    );
    assert_eq!(
        details["deployment"]["rollout_group"].as_str().unwrap(),
        "canary"
    );
    assert!(details["deployment"]["acknowledged_at"].is_string());

    let update = ureq::get(&format!(
        "{}/api/agents/update?agent_id={}&current_version=0.15.0",
        base(port),
        agent_id
    ))
    .call()
    .expect("targeted update check")
    .into_json::<serde_json::Value>()
    .unwrap();
    assert!(update["update_available"].as_bool().unwrap());
    assert_eq!(update["version"].as_str().unwrap(), "0.16.0");
    assert!(
        update["download_url"]
            .as_str()
            .unwrap()
            .starts_with("/api/updates/download/")
    );
}

#[test]
fn agent_client_can_download_assigned_update_binary() {
    let (port, token) = spawn_test_server();

    let enrollment_token = ureq::post(&format!("{}/api/agents/token", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(r#"{"max_uses":1}"#)
        .expect("create token")
        .into_json::<serde_json::Value>()
        .unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();

    let mut client = AgentClient::new(&base(port));
    let enroll = client
        .enroll(&enrollment_token, "download-agent", "linux")
        .expect("agent enroll");

    ureq::post(&format!("{}/api/updates/publish", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "version": "99.0.0",
                "platform": "linux",
                "binary_base64": "aGVsbG8=",
                "release_notes": "download smoke test",
                "mandatory": true,
            })
            .to_string(),
        )
        .expect("publish release");

    ureq::post(&format!("{}/api/updates/deploy", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "agent_id": enroll.agent_id,
                "version": "99.0.0",
                "platform": "linux",
                "rollout_group": "canary",
            })
            .to_string(),
        )
        .expect("assign deployment");

    let target = client.heartbeat().expect("heartbeat after deploy");
    assert_eq!(target.as_deref(), Some("99.0.0"));

    let info = client
        .check_update()
        .expect("check update")
        .expect("update info");
    assert_eq!(info.version, "99.0.0");
    assert_eq!(info.release_notes, "download smoke test");
    assert!(info.mandatory);
    assert!(info.download_url.starts_with("/api/updates/download/"));

    let binary = client.download_update(&info).expect("download update");
    assert_eq!(binary, b"hello");
}
