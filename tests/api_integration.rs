use sentineledge::server::spawn_test_server;

fn base(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

fn auth_header(token: &str) -> String {
    format!("Bearer {token}")
}

// ── GET /api/status ────────────────────────────────────────────

#[test]
fn status_returns_200_with_expected_keys() {
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/status", base(port)))
        .call()
        .expect("status request");
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("updated_at").is_some());
    assert!(body.get("backlog_completed").is_some());
    assert!(body.get("cli_commands").is_some());
    assert!(body.get("implemented").is_some());
    assert!(body.get("partially_wired").is_some());
    assert!(body.get("not_implemented").is_some());
}

// ── GET /api/report ────────────────────────────────────────────

#[test]
fn report_returns_200_with_summary_and_samples() {
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/report", base(port)))
        .call()
        .expect("report request");
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("summary").is_some());
    assert!(body.get("samples").is_some());
    let samples = body["samples"].as_array().unwrap();
    assert!(!samples.is_empty());
}

// ── POST /api/analyze — auth required ──────────────────────────

#[test]
fn analyze_without_auth_returns_401() {
    let (port, _token) = spawn_test_server();
    let csv = "1000,18.0,32.0,41.0,500.0,0,94.0,0.01,42,8.0\n";
    let err = ureq::post(&format!("{}/api/analyze", base(port)))
        .set("Content-Type", "text/csv")
        .send_string(csv);
    match err {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401, got {other:?}"),
    }
}

#[test]
fn analyze_csv_returns_report() {
    let (port, token) = spawn_test_server();
    let csv = "1000,18.0,32.0,41.0,500.0,0,94.0,0.01,42,8.0\n\
               2000,64.0,58.0,51.0,5400.0,8,63.0,0.11,98,55.0\n";
    let resp = ureq::post(&format!("{}/api/analyze", base(port)))
        .set("Content-Type", "text/csv")
        .set("Authorization", &auth_header(&token))
        .send_string(csv)
        .expect("analyze csv");
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("summary").is_some());
    assert_eq!(body["summary"]["total_samples"].as_u64().unwrap(), 2);
}

#[test]
fn analyze_jsonl_returns_report() {
    let (port, token) = spawn_test_server();
    let jsonl = r#"{"timestamp_ms":1000,"cpu_load_pct":18.0,"memory_load_pct":32.0,"temperature_c":41.0,"network_kbps":500.0,"auth_failures":0,"battery_pct":94.0,"integrity_drift":0.01,"process_count":42,"disk_pressure_pct":8.0}"#;
    let resp = ureq::post(&format!("{}/api/analyze", base(port)))
        .set("Content-Type", "application/json")
        .set("Authorization", &auth_header(&token))
        .send_string(jsonl)
        .expect("analyze jsonl");
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["summary"]["total_samples"].as_u64().unwrap(), 1);
}

// ── POST /api/control/mode ─────────────────────────────────────

#[test]
fn set_mode_frozen() {
    let (port, token) = spawn_test_server();
    let resp = ureq::post(&format!("{}/api/control/mode", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({"mode": "frozen"}))
        .expect("set mode frozen");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body["status"].as_str().unwrap().contains("frozen"));
}

#[test]
fn set_mode_decay() {
    let (port, token) = spawn_test_server();
    let resp = ureq::post(&format!("{}/api/control/mode", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({"mode": "decay", "decay_rate": 0.1}))
        .expect("set mode decay");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body["status"].as_str().unwrap().contains("decay"));
}

#[test]
fn set_mode_unknown_returns_400() {
    let (port, token) = spawn_test_server();
    let err = ureq::post(&format!("{}/api/control/mode", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({"mode": "turbo"}));
    match err {
        Err(ureq::Error::Status(400, _)) => {}
        other => panic!("expected 400, got {other:?}"),
    }
}

// ── POST /api/control/reset-baseline ───────────────────────────

#[test]
fn reset_baseline_returns_200() {
    let (port, token) = spawn_test_server();
    let resp = ureq::post(&format!("{}/api/control/reset-baseline", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_string("")
        .expect("reset baseline");
    assert_eq!(resp.status(), 200);
}

// ── POST /api/control/run-demo ─────────────────────────────────

#[test]
fn run_demo_returns_report() {
    let (port, token) = spawn_test_server();
    let resp = ureq::post(&format!("{}/api/control/run-demo", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_string("")
        .expect("run demo");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("summary").is_some());
    assert!(body.get("samples").is_some());
}

// ── Checkpoint round-trip ──────────────────────────────────────

#[test]
fn checkpoint_save_and_restore_round_trip() {
    let (port, token) = spawn_test_server();
    let auth = auth_header(&token);

    // Feed samples so the detector has a baseline to snapshot
    let csv = "1000,18.0,32.0,41.0,500.0,0,94.0,0.01,42,8.0\n";
    ureq::post(&format!("{}/api/analyze", base(port)))
        .set("Authorization", &auth)
        .set("Content-Type", "text/csv")
        .send_string(csv)
        .expect("analyze for baseline");

    // Save a checkpoint
    let resp = ureq::post(&format!("{}/api/control/checkpoint", base(port)))
        .set("Authorization", &auth)
        .send_string("")
        .expect("checkpoint save");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["total"].as_u64().unwrap(), 1);

    // List checkpoints
    let resp = ureq::get(&format!("{}/api/checkpoints", base(port)))
        .call()
        .expect("list checkpoints");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["count"].as_u64().unwrap(), 1);
    assert_eq!(body["device_states"].as_array().unwrap().len(), 1);

    // Restore checkpoint
    let resp = ureq::post(&format!("{}/api/control/restore-checkpoint", base(port)))
        .set("Authorization", &auth)
        .send_string("")
        .expect("restore checkpoint");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["status"].as_str().unwrap(), "checkpoint restored");
    assert!(body["baseline_restored"].as_bool().unwrap());
    assert!(body["device_state"].is_object());
    assert!(!body["actions"].as_array().unwrap().is_empty());
}

#[test]
fn restore_without_checkpoints_returns_404() {
    let (port, token) = spawn_test_server();
    let err = ureq::post(&format!("{}/api/control/restore-checkpoint", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_string("");
    match err {
        Err(ureq::Error::Status(404, _)) => {}
        other => panic!("expected 404, got {other:?}"),
    }
}

#[test]
fn checkpoint_restore_reapplies_saved_device_state() {
    let (port, token) = spawn_test_server();
    let auth = auth_header(&token);

    let csv = "1000,18.0,32.0,41.0,500.0,0,94.0,0.01,42,8.0\n\
               2000,64.0,58.0,51.0,5400.0,8,63.0,0.11,98,55.0\n";
    ureq::post(&format!("{}/api/analyze", base(port)))
        .set("Authorization", &auth)
        .set("Content-Type", "text/csv")
        .send_string(csv)
        .expect("analyze for quarantine state");

    ureq::post(&format!("{}/api/control/checkpoint", base(port)))
        .set("Authorization", &auth)
        .send_string("")
        .expect("checkpoint save");

    let checkpoint_state = ureq::get(&format!("{}/api/checkpoints", base(port)))
        .call()
        .expect("list checkpoints")
        .into_json::<serde_json::Value>()
        .unwrap()["device_states"][0]
        .clone();

    let resp = ureq::post(&format!("{}/api/control/restore-checkpoint", base(port)))
        .set("Authorization", &auth)
        .send_string("")
        .expect("restore checkpoint");
    let body: serde_json::Value = resp.into_json().unwrap();

    assert_eq!(body["device_state"], checkpoint_state);
}

// ── OPTIONS (CORS preflight) ──────────────────────────────────

#[test]
fn options_returns_cors_headers() {
    let (port, _token) = spawn_test_server();
    let resp = ureq::request("OPTIONS", &format!("{}/api/status", base(port)))
        .call()
        .expect("options request");
    assert_eq!(resp.status(), 204);
    assert!(resp.header("Access-Control-Allow-Methods").is_some());
    assert!(resp.header("Access-Control-Allow-Headers").is_some());
}

// ── Unknown endpoint ──────────────────────────────────────────

#[test]
fn unknown_api_endpoint_returns_404() {
    let (port, _token) = spawn_test_server();
    let err = ureq::get(&format!("{}/api/nonexistent", base(port))).call();
    match err {
        Err(ureq::Error::Status(404, _)) => {}
        other => panic!("expected 404, got {other:?}"),
    }
}
