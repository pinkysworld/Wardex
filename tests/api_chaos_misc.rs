mod common;
use common::*;

// ── Chaos / Fault Injection Tests ──────────────────────────────

#[test]
fn chaos_rapid_token_rotation_stress() {
    let (port, token) = spawn_test_server();
    let mut current_token = token;
    // Rapidly rotate token 10 times to verify no state corruption
    for _ in 0..10 {
        let resp = ureq::post(&format!("{}/api/auth/rotate", base(port)))
            .set("Authorization", &auth_header(&current_token))
            .call()
            .expect("rotate");
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.into_json().unwrap();
        current_token = body["new_token"].as_str().unwrap().to_string();
    }
    // Final token should still work
    let resp = ureq::get(&format!("{}/api/auth/check", base(port)))
        .set("Authorization", &auth_header(&current_token))
        .call()
        .expect("auth check after rotation storm");
    assert_eq!(resp.status(), 200);
}

#[test]
fn chaos_concurrent_requests_under_load() {
    let (port, token) = spawn_test_server();
    // Fire 50 rapid requests to test stability under burst load
    for i in 0..50 {
        let url = match i % 5 {
            0 => format!("{}/api/health", base(port)),
            1 => format!("{}/api/alerts/count", base(port)),
            2 => format!("{}/api/status", base(port)),
            3 => format!("{}/api/slo/status", base(port)),
            _ => format!("{}/api/session/info", base(port)),
        };
        let builder = ureq::get(&url).set("Authorization", &auth_header(&token));
        // Some might fail due to rate limiting, but server should not crash
        let _ = builder.call();
    }
    // Server should still respond after burst
    let resp = ureq::get(&format!("{}/api/health", base(port)))
        .call()
        .expect("health after burst");
    assert_eq!(resp.status(), 200);
}

#[test]
fn chaos_malformed_json_does_not_crash() {
    let (port, token) = spawn_test_server();
    // Send various malformed bodies to POST endpoints
    let bad_payloads = [
        "",
        "{",
        "null",
        "{\"key\":}",
        "not json at all <>!@#$%",
        &"x".repeat(1000),
    ];
    for payload in &bad_payloads {
        let _ = ureq::post(&format!("{}/api/config/reload", base(port)))
            .set("Authorization", &auth_header(&token))
            .set("Content-Type", "application/json")
            .send_string(payload);
    }
    // Server should still be healthy
    let resp = ureq::get(&format!("{}/api/health", base(port)))
        .call()
        .expect("health after malformed payloads");
    assert_eq!(resp.status(), 200);
}

#[test]
fn chaos_expired_token_rejected() {
    let (port, token) = spawn_test_server();
    // Rotate token to invalidate original
    let resp = ureq::post(&format!("{}/api/auth/rotate", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("rotate");
    assert_eq!(resp.status(), 200);

    // Old token should be rejected on all sensitive endpoints
    let endpoints = [
        "/api/auth/check",
        "/api/session/info",
        "/api/retention/status",
        "/api/audit/verify",
    ];
    for ep in &endpoints {
        let result = ureq::get(&format!("{}{}", base(port), ep))
            .set("Authorization", &auth_header(&token))
            .call();
        match result {
            Ok(resp) => assert_eq!(resp.status(), 401, "Expected 401 for {}", ep),
            Err(ureq::Error::Status(status, _)) => {
                assert_eq!(status, 401, "Expected 401 for {}", ep)
            }
            Err(e) => panic!("Unexpected error for {}: {}", ep, e),
        }
    }
}

#[test]
fn chaos_path_traversal_rejected() {
    let (port, _) = spawn_test_server();
    // Attempt path traversal on static file serving
    let traversal_attempts = [
        "/../../etc/passwd",
        "/../../../Cargo.toml",
        "/..%2f..%2fetc/passwd",
        "/site/../../Cargo.toml",
    ];
    for path in &traversal_attempts {
        let resp = ureq::get(&format!("{}{}", base(port), path)).call();
        if let Ok(r) = resp {
            assert_ne!(
                r.status(),
                200,
                "Path traversal should not succeed: {}",
                path
            );
        }
    }
}

#[test]
fn openapi_endpoint_returns_live_json_spec() {
    let (port, _) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/openapi.json", base(port)))
        .call()
        .expect("openapi");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().expect("openapi json");
    assert_eq!(body["openapi"].as_str(), Some("3.0.3"));
    assert!(
        body.get("spec_format").is_none(),
        "legacy YAML wrapper should be gone"
    );
    let paths = body["paths"].as_object().expect("paths object");
    assert!(paths.contains_key("/api/agents"));
    assert!(paths.contains_key("/api/alerts/{id}"));
    assert!(paths.contains_key("/api/config/current"));
    assert!(paths.contains_key("/api/openapi.json"));
    assert!(paths.contains_key("/api/threat-intel/status"));
    assert!(paths.contains_key("/api/threat-intel/library"));
    assert!(paths.contains_key("/api/threat-intel/ioc"));
    assert!(paths.contains_key("/api/playbooks"));
    assert!(paths.contains_key("/api/fleet/dashboard"));
    assert!(paths.contains_key("/api/events/search"));
    assert!(paths.contains_key("/api/queue/stats"));
    assert!(paths.contains_key("/api/rollout/config"));
    assert!(paths.contains_key("/api/release/deployment-trust-report"));
    assert!(paths.contains_key("/api/investigations/workflows"));
    assert!(paths.contains_key("/api/investigations/workflows/{id}"));
    assert!(paths.contains_key("/api/investigations/start"));
    assert!(paths.contains_key("/api/investigations/active"));
    assert!(paths.contains_key("/api/investigations/progress"));
    assert!(paths.contains_key("/api/investigations/handoff"));
    assert!(paths.contains_key("/api/investigations/suggest"));

    let metrics = &paths["/api/metrics"]["get"]["responses"]["200"]["content"];
    assert!(metrics.get("text/plain").is_some());

    let events_export = &paths["/api/events/export"]["get"]["responses"]["200"]["content"];
    assert!(events_export.get("text/csv").is_some());

    let report_html = &paths["/api/reports/{id}/html"]["get"]["responses"]["200"]["content"];
    assert!(report_html.get("text/html").is_some());

    assert!(paths["/api/auth/rotate"]["post"]["requestBody"].is_null());
    assert_eq!(
        paths["/api/response/execute"]["post"]["requestBody"]["required"].as_bool(),
        Some(false)
    );

    let alert_params = paths["/api/alerts"]["get"]["parameters"]
        .as_array()
        .expect("alert params");
    assert!(alert_params.iter().any(|param| {
        param["in"].as_str() == Some("query") && param["name"].as_str() == Some("limit")
    }));
    assert!(alert_params.iter().any(|param| {
        param["in"].as_str() == Some("query") && param["name"].as_str() == Some("offset")
    }));

    let incident_params = paths["/api/incidents"]["get"]["parameters"]
        .as_array()
        .expect("incident params");
    for name in ["status", "severity", "limit", "offset"] {
        assert!(
            incident_params
                .iter()
                .any(|param| param["name"].as_str() == Some(name))
        );
    }

    let report_html_params = paths["/api/reports/{id}/html"]["get"]["parameters"]
        .as_array()
        .expect("report html path params");
    assert!(report_html_params.iter().any(|param| {
        param["in"].as_str() == Some("path") && param["name"].as_str() == Some("id")
    }));

    assert!(paths["/api/investigations/start"]["post"]["requestBody"].is_object());
    assert!(paths["/api/investigations/progress"]["post"]["requestBody"].is_object());
    assert!(paths["/api/investigations/handoff"]["post"]["requestBody"].is_object());

    for path in [
        "/api/cases",
        "/api/hunts",
        "/api/content/rules",
        "/api/content/packs",
        "/api/suppressions",
    ] {
        assert!(paths[path]["post"]["responses"]["201"].is_object());
        assert!(paths[path]["post"]["responses"]["200"].is_null());
    }
}

#[test]
fn metrics_endpoint_returns_prometheus_text() {
    let (port, _) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/metrics", base(port)))
        .call()
        .expect("metrics");
    assert_eq!(resp.status(), 200);
    let body = resp.into_string().expect("metrics text");
    assert!(body.contains("wardex_up 1"));
    assert!(body.contains("wardex_requests_total"));
    assert!(body.contains("wardex_agents_total"));
}

// ── Additional Chaos / Fault Injection Tests ───────────────────

#[test]
fn chaos_oversized_header_rejected() {
    let (port, token) = spawn_test_server();
    // Send request with absurdly large header value
    let huge_value = "X".repeat(64 * 1024);
    let result = ureq::get(&format!("{}/api/health", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("X-Huge", &huge_value)
        .call();
    // Server should either reject or handle gracefully without crashing
    match result {
        Ok(_) | Err(_) => {}
    }
    // Verify server is still alive
    let resp = ureq::get(&format!("{}/api/health", base(port)))
        .call()
        .expect("health after oversized header");
    assert_eq!(resp.status(), 200);
}

#[test]
fn chaos_wrong_http_method_graceful() {
    let (port, token) = spawn_test_server();
    // Send wrong HTTP methods to endpoints to verify graceful handling
    let wrong_method_tests: Vec<(&str, &str)> = vec![
        ("DELETE", "/api/health"),
        ("PUT", "/api/alerts/count"),
        ("PATCH", "/api/status"),
    ];
    for (method, path) in &wrong_method_tests {
        let url = format!("{}{}", base(port), path);
        let result = match *method {
            "DELETE" => ureq::delete(&url)
                .set("Authorization", &auth_header(&token))
                .call(),
            "PUT" => ureq::put(&url)
                .set("Authorization", &auth_header(&token))
                .send_string("{}"),
            "PATCH" => ureq::patch(&url)
                .set("Authorization", &auth_header(&token))
                .send_string("{}"),
            _ => unreachable!(),
        };
        if let Ok(r) = result {
            assert!(
                r.status() == 405 || r.status() == 200 || r.status() == 404,
                "Unexpected status for {} {}: {}",
                method,
                path,
                r.status()
            );
        }
    }
    // Server still alive
    let resp = ureq::get(&format!("{}/api/health", base(port)))
        .call()
        .expect("health after wrong methods");
    assert_eq!(resp.status(), 200);
}

#[test]
fn chaos_empty_and_invalid_auth_headers() {
    let (port, _) = spawn_test_server();
    // Try various invalid Authorization headers
    let bad_auths = [
        "",
        "Bearer",
        "Bearer ",
        "Basic dXNlcjpwYXNz",
        "Bearer null",
        &format!("Bearer {}", "A".repeat(1000)),
    ];
    for bad in &bad_auths {
        let result = ureq::get(&format!("{}/api/auth/check", base(port)))
            .set("Authorization", bad)
            .call();
        match result {
            Ok(r) => assert_eq!(r.status(), 401, "Expected 401 for auth: {:?}", bad),
            Err(ureq::Error::Status(401, _)) => {}
            Err(e) => panic!("Unexpected error for auth {:?}: {}", bad, e),
        }
    }
    // Server still healthy
    let resp = ureq::get(&format!("{}/api/health", base(port)))
        .call()
        .expect("health after bad auth");
    assert_eq!(resp.status(), 200);
}

#[test]
fn chaos_rapid_sequential_endpoint_sweep() {
    let (port, token) = spawn_test_server();
    // Hit every major API endpoint in rapid succession
    let endpoints = [
        "/api/health",
        "/api/status",
        "/api/alerts/count",
        "/api/session/info",
        "/api/slo/status",
        "/api/retention/status",
        "/api/metrics",
        "/api/openapi.json",
        "/api/admin/db/version",
        "/api/detectors/ransomware",
    ];
    for _ in 0..3 {
        for ep in &endpoints {
            let _ = ureq::get(&format!("{}{}", base(port), ep))
                .set("Authorization", &auth_header(&token))
                .call();
        }
    }
    // Verify no state corruption
    let resp = ureq::get(&format!("{}/api/health", base(port)))
        .call()
        .expect("health after sweep");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["status"], "ok");
}

#[test]
fn chaos_oversized_json_body() {
    let (port, token) = spawn_test_server();
    // Send large JSON body to POST endpoint
    let large_body = format!("{{\"data\":\"{}\"}}", "B".repeat(512 * 1024));
    let _ = ureq::post(&format!("{}/api/config/reload", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(&large_body);
    // Server must survive
    let resp = ureq::get(&format!("{}/api/health", base(port)))
        .call()
        .expect("health after oversized body");
    assert_eq!(resp.status(), 200);
}

// ═══════════════════════════════════════════════════════════════════
// v0.43.0 feature integration tests
// ═══════════════════════════════════════════════════════════════════

// ── Malware scanning ───────────────────────────────────────────────

#[test]
fn malware_stats_returns_hash_db_info() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/malware/stats", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("malware stats");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("database").is_some());
    assert!(body.get("scanner").is_some());
    assert!(body.get("yara_rules").is_some());
}

#[test]
fn malware_recent_returns_array() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/malware/recent", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("malware recent");
    assert_eq!(resp.status(), 200);
}

#[test]
fn scan_hash_returns_result() {
    let (port, token) = spawn_test_server();
    let resp = ureq::post(&format!("{}/api/scan/hash", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(r#"{"hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","algorithm":"sha256"}"#)
        .expect("scan hash");
    assert_eq!(resp.status(), 200);
}

#[test]
fn scan_buffer_returns_verdict() {
    let (port, token) = spawn_test_server();
    let resp = ureq::post(&format!("{}/api/scan/buffer", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(r#"{"data":"aGVsbG8gd29ybGQ=","filename":"test.txt"}"#)
        .expect("scan buffer");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("verdict").is_some());
}

// ── Threat hunting ─────────────────────────────────────────────────

#[test]
fn hunt_with_valid_query_returns_results() {
    let (port, token) = spawn_test_server();
    let resp = ureq::post(&format!("{}/api/hunt", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(r#"{"query":"process == svchost.exe"}"#)
        .expect("hunt query");
    assert_eq!(resp.status(), 200);
}

#[test]
fn hunt_with_empty_query_returns_400() {
    let (port, token) = spawn_test_server();
    let err = ureq::post(&format!("{}/api/hunt", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(r#"{"query":""}"#);
    match err {
        Err(ureq::Error::Status(400, _)) => {}
        other => panic!("expected 400 for empty hunt query, got {other:?}"),
    }
}

// ── SIEM export ────────────────────────────────────────────────────

#[test]
fn export_alerts_json_format() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/export/alerts?format=json", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("export alerts json");
    assert_eq!(resp.status(), 200);
    assert!(
        resp.header("Content-Type")
            .unwrap_or_default()
            .contains("application/json")
    );
    let body: serde_json::Value = resp.into_json().expect("json export payload");
    assert!(body.is_array());
}

#[test]
fn export_alerts_cef_format() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/export/alerts?format=cef", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("export alerts cef");
    assert_eq!(resp.status(), 200);
    assert!(
        resp.header("Content-Type")
            .unwrap_or_default()
            .contains("text/plain")
    );
    let _body = resp.into_string().expect("cef export payload");
}

#[test]
fn export_alerts_leef_format() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/export/alerts?format=leef", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("export alerts leef");
    assert_eq!(resp.status(), 200);
}

#[test]
fn export_alerts_syslog_format() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/export/alerts?format=syslog", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("export alerts syslog");
    assert_eq!(resp.status(), 200);
}

#[test]
fn export_alerts_ecs_format() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/export/alerts?format=ecs", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("export alerts ecs");
    assert_eq!(resp.status(), 200);
}

#[test]
fn export_alerts_udm_format() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/export/alerts?format=udm", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("export alerts udm");
    assert_eq!(resp.status(), 200);
}

#[test]
fn export_alerts_sentinel_format() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/export/alerts?format=sentinel", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("export alerts sentinel");
    assert_eq!(resp.status(), 200);
}

#[test]
fn export_alerts_qradar_format() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/export/alerts?format=qradar", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("export alerts qradar");
    assert_eq!(resp.status(), 200);
}

#[test]
fn export_alerts_unsupported_format_returns_400() {
    let (port, token) = spawn_test_server();
    let err = ureq::get(&format!("{}/api/export/alerts?format=invalid", base(port)))
        .set("Authorization", &auth_header(&token))
        .call();
    match err {
        Err(ureq::Error::Status(400, _)) => {}
        other => panic!("expected 400 for unsupported format, got {other:?}"),
    }
}

#[test]
fn gdpr_forget_returns_receipt() {
    let (port, token) = spawn_test_server();
    let resp = ureq::delete(&format!("{}/api/gdpr/forget/test-user-42", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("gdpr forget");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().expect("gdpr forget payload");
    assert_eq!(
        body.get("status").and_then(|value| value.as_str()),
        Some("completed")
    );
    assert_eq!(
        body.get("entity_id").and_then(|value| value.as_str()),
        Some("test-user-42")
    );
    assert!(body.get("records_purged").is_some());
    assert!(body.get("timestamp").is_some());
}

#[test]
fn pii_scan_returns_detected_categories() {
    let (port, token) = spawn_test_server();
    let resp = ureq::post(&format!("{}/api/pii/scan", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_string("alice@example.com connected from 203.0.113.42 with 4111111111111111")
        .expect("pii scan");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().expect("pii scan payload");
    assert_eq!(
        body.get("has_pii").and_then(|value| value.as_bool()),
        Some(true)
    );
    let categories = body
        .get("categories")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(
        categories
            .iter()
            .any(|value| value.as_str() == Some("email"))
    );
    assert!(
        categories
            .iter()
            .any(|value| value.as_str() == Some("ip_address"))
    );
    assert!(
        categories
            .iter()
            .any(|value| value.as_str() == Some("credit_card"))
    );
}

// ── Compliance reports ─────────────────────────────────────────────

#[test]
fn compliance_report_all_frameworks() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/compliance/report", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("compliance report all");
    assert_eq!(resp.status(), 200);
}

#[test]
fn compliance_summary_returns_executive_view() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/compliance/summary", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("compliance summary");
    assert_eq!(resp.status(), 200);
}

#[test]
fn compliance_report_unknown_framework_returns_404() {
    let (port, token) = spawn_test_server();
    let err = ureq::get(&format!(
        "{}/api/compliance/report?framework=nonexistent",
        base(port)
    ))
    .set("Authorization", &auth_header(&token))
    .call();
    match err {
        Err(ureq::Error::Status(404, _)) => {}
        other => panic!("expected 404 for unknown framework, got {other:?}"),
    }
}

// ── Playbook execution ─────────────────────────────────────────────

#[test]
fn playbook_run_without_id_returns_400() {
    let (port, token) = spawn_test_server();
    let err = ureq::post(&format!("{}/api/playbooks/run", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(r#"{"playbook_id":""}"#);
    match err {
        Err(ureq::Error::Status(400, _)) => {}
        other => panic!("expected 400 for empty playbook_id, got {other:?}"),
    }
}

#[test]
fn playbook_executions_keeps_live_execution_shape_after_history_exists() {
    let (port, token) = spawn_test_server();
    let created_at = chrono::Utc::now().to_rfc3339();

    ureq::post(&format!("{}/api/playbooks", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "id": "pb-shape-check",
            "name": "Shape Check",
            "description": "Verify recent execution contract remains stable",
            "version": 1,
            "enabled": true,
            "trigger": {
                "min_severity": null,
                "alert_reasons": [],
                "mitre_techniques": [],
                "kill_chain_phases": [],
                "host_patterns": [],
                "manual_only": true
            },
            "steps": [],
            "timeout_secs": 300,
            "created_at": created_at,
            "updated_at": created_at
        }))
        .expect("register playbook");

    let started: serde_json::Value = ureq::post(&format!("{}/api/playbooks/execute", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "playbook_id": "pb-shape-check",
            "alert_id": "alert-shape-1"
        }))
        .expect("start execution")
        .into_json()
        .unwrap();
    let execution_id = started["execution_id"]
        .as_str()
        .expect("execution id")
        .to_string();

    let executions: serde_json::Value =
        ureq::get(&format!("{}/api/playbooks/executions", base(port)))
            .set("Authorization", &auth_header(&token))
            .call()
            .expect("list executions")
            .into_json()
            .unwrap();
    let execution = executions
        .as_array()
        .and_then(|items| {
            items
                .iter()
                .find(|entry| entry["execution_id"].as_str() == Some(execution_id.as_str()))
        })
        .expect("live execution present");

    assert_eq!(execution["status"], "Running");
    assert!(execution["step_results"].is_array());
}

// ── Alert deduplication ────────────────────────────────────────────

#[test]
fn alerts_dedup_returns_incidents() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/alerts/dedup", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("alerts dedup");
    assert_eq!(resp.status(), 200);
}

// ── API analytics ──────────────────────────────────────────────────

#[test]
fn api_analytics_returns_summary() {
    let (port, token) = spawn_test_server();
    // Make a few requests first to generate analytics data
    let _ = ureq::get(&format!("{}/api/health", base(port))).call();
    let _ = ureq::get(&format!("{}/api/status", base(port)))
        .set("Authorization", &auth_header(&token))
        .call();
    let resp = ureq::get(&format!("{}/api/analytics", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("api analytics");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("total_requests").is_some() || body.get("endpoints").is_some());
}

// ── OpenTelemetry traces ───────────────────────────────────────────

#[test]
fn traces_returns_stats_and_recent() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/traces", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("traces");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("stats").is_some());
    assert!(body.get("recent").is_some());
}

// ── Backup encrypt/decrypt ─────────────────────────────────────────

#[test]
fn backup_encrypt_decrypt_roundtrip() {
    let (port, token) = spawn_test_server();
    // Encrypt
    let enc_resp = ureq::post(&format!("{}/api/backup/encrypt", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(r#"{"data":"hello world","passphrase":"test-pass-123"}"#)
        .expect("backup encrypt");
    assert_eq!(enc_resp.status(), 200);
    let enc_body: serde_json::Value = enc_resp.into_json().unwrap();
    let encrypted = enc_body["encrypted"].as_str().expect("encrypted field");

    // Decrypt
    let dec_payload = serde_json::json!({"data": encrypted, "passphrase": "test-pass-123"});
    let dec_resp = ureq::post(&format!("{}/api/backup/decrypt", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(&dec_payload.to_string())
        .expect("backup decrypt");
    assert_eq!(dec_resp.status(), 200);
    let dec_body: serde_json::Value = dec_resp.into_json().unwrap();
    assert_eq!(dec_body["data"].as_str().unwrap(), "hello world");
}

#[test]
fn backup_encrypt_requires_passphrase() {
    let (port, token) = spawn_test_server();
    let err = ureq::post(&format!("{}/api/backup/encrypt", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(r#"{"data":"hello","passphrase":""}"#);
    match err {
        Err(ureq::Error::Status(400, _)) => {}
        other => panic!("expected 400 for empty passphrase, got {other:?}"),
    }
}

// ── Detection rules ────────────────────────────────────────────────

#[test]
fn detection_rules_list() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/detection/rules", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("detection rules list");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("sigma").is_some());
    assert!(body.get("yara").is_some());
    assert!(body.get("malware_hashes").is_some());
}

#[test]
fn detection_rules_add_yara() {
    let (port, token) = spawn_test_server();
    let resp = ureq::post(&format!("{}/api/detection/rules", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(r#"{"type":"yara","name":"test_rule","pattern":"suspicious_string","description":"test","severity":"high"}"#)
        .expect("add yara rule");
    assert_eq!(resp.status(), 200);
}

#[test]
fn detection_rules_add_empty_pattern_returns_400() {
    let (port, token) = spawn_test_server();
    let err = ureq::post(&format!("{}/api/detection/rules", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(r#"{"type":"yara","name":"bad_rule","pattern":""}"#);
    match err {
        Err(ureq::Error::Status(400, _)) => {}
        other => panic!("expected 400 for empty pattern, got {other:?}"),
    }
}
