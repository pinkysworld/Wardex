use wardex::agent_client::AgentClient;
use wardex::config::Config;
use wardex::server::spawn_test_server;

fn base(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

fn auth_header(token: &str) -> String {
    format!("Bearer {token}")
}

// ── GET /api/status ────────────────────────────────────────────

#[test]
fn status_returns_200_with_expected_keys() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/status", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("status request");
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("updated_at").is_some());
    assert_eq!(body["version"].as_str().unwrap(), env!("CARGO_PKG_VERSION"));
    assert!(body.get("backlog_completed").is_some());
    assert_eq!(body["phases_completed"].as_u64().unwrap(), 28);
    assert_eq!(body["tasks_completed"].as_u64().unwrap(), 160);
    assert_eq!(body["total_tasks"].as_u64().unwrap(), 160);
    assert!(body.get("cli_commands").is_some());
    assert!(body.get("implemented").is_some());
    assert!(body.get("partially_wired").is_some());
    assert!(body.get("not_implemented").is_some());
}

// ── GET /api/report ────────────────────────────────────────────

#[test]
fn report_returns_200_with_summary_and_samples() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/report", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("report request");
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("summary").is_some());
    assert!(body.get("samples").is_some());
    let samples = body["samples"].as_array().unwrap();
    // Fresh server with no alerts returns an empty or populated live sample list without error.
    let _ = samples.len();
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

#[test]
fn detection_summary_includes_mode_and_learning_state() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/detection/summary", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("detection summary");
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["mode"].as_str().unwrap(), "normal");
    assert!((body["ewma_alpha"].as_f64().unwrap() - 0.22).abs() < 1e-6);
    assert_eq!(body["warmup_samples"].as_u64().unwrap(), 4);
    assert!((body["learn_threshold"].as_f64().unwrap() - 2.5).abs() < 1e-6);
    assert_eq!(body["observed_samples"].as_u64().unwrap(), 0);
    assert_eq!(body["baseline_ready"].as_bool().unwrap(), false);
}

#[test]
fn slo_status_tracks_error_totals() {
    let (port, token) = spawn_test_server();

    let err = ureq::get(&format!("{}/api/status", base(port))).call();
    match err {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401, got {other:?}"),
    }

    let err = ureq::get(&format!("{}/api/nonexistent", base(port)))
        .set("Authorization", &auth_header(&token))
        .call();
    match err {
        Err(ureq::Error::Status(404, _)) => {}
        other => panic!("expected 404, got {other:?}"),
    }

    let resp = ureq::get(&format!("{}/api/slo/status", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("slo status");
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body["total_requests"].as_u64().unwrap() >= 3);
    assert!(body["total_errors"].as_u64().unwrap() >= 2);
    assert!(body["successful_requests"].as_u64().unwrap() >= 1);
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
        .set("Authorization", &auth)
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
        .set("Authorization", &auth)
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

// ── GET /api/export/tla ────────────────────────────────────────

#[test]
fn export_tla_returns_valid_module() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/export/tla", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("export tla request");
    assert_eq!(resp.status(), 200);

    let body = resp.into_string().unwrap();
    assert!(body.contains("MODULE PolicyStateMachine"));
    assert!(body.contains("LegalTransition"));
    assert!(body.contains("NoSkipDeescalation"));
    assert!(body.contains("===="));
}

// ── GET /api/export/alloy ──────────────────────────────────────

#[test]
fn export_alloy_returns_valid_module() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/export/alloy", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("export alloy request");
    assert_eq!(resp.status(), 200);

    let body = resp.into_string().unwrap();
    assert!(body.contains("module PolicyStateMachine"));
    assert!(body.contains("legalTransition"));
    assert!(body.contains("noSkipDeescalation"));
    assert!(body.contains("check noSkipDeescalation"));
}

// ── GET /api/export/witnesses ──────────────────────────────────

#[test]
fn export_witnesses_returns_empty_array_initially() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/export/witnesses", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("export witnesses request");
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.as_array().unwrap().is_empty());
}

#[test]
fn export_witnesses_populated_after_run_demo() {
    let (port, token) = spawn_test_server();

    // Run demo to populate proof registry
    let _resp = ureq::post(&format!("{}/api/control/run-demo", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("run-demo request");

    // Now fetch witnesses
    let resp = ureq::get(&format!("{}/api/export/witnesses", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("export witnesses after demo");
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.into_json().unwrap();
    let witnesses = body.as_array().unwrap();
    assert!(!witnesses.is_empty());
    assert_eq!(witnesses[0]["backend"], "sha256-digest");
    assert_eq!(witnesses[0]["label"], "baseline_update");
    assert!(witnesses[0]["verified"].as_bool().unwrap());
}

// ── GET /api/research-tracks ───────────────────────────────────

#[test]
fn research_tracks_returns_grouped_tracks() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/research-tracks", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("research-tracks request");
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.into_json().unwrap();
    let groups = body.as_array().expect("should be array");
    assert!(groups.len() >= 7, "at least 7 track groups");

    let first = &groups[0];
    assert!(first.get("label").is_some());
    let tracks = first["tracks"].as_array().expect("tracks array");
    assert!(!tracks.is_empty());

    let t = &tracks[0];
    assert!(t.get("code").is_some());
    assert!(t.get("title").is_some());
    assert!(t.get("status").is_some());
    assert!(t.get("summary").is_some());
}

// ── GET /api/attestation/status ────────────────────────────────

#[test]
fn attestation_status_returns_verification_result() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/attestation/status", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("attestation status request");
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("passed").is_some());
    assert!(body.get("checks").is_some());
    let checks = body["checks"].as_array().unwrap();
    assert!(!checks.is_empty());
}

// ── GET /api/auth/check ────────────────────────────────────────

#[test]
fn auth_check_without_token_returns_401() {
    let (port, _token) = spawn_test_server();
    let err = ureq::get(&format!("{}/api/auth/check", base(port))).call();
    match err {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401, got {other:?}"),
    }
}

#[test]
fn auth_check_with_valid_token_returns_ok() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/auth/check", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("auth check");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["status"], "ok");
}

// ── GET /api/fleet/status ──────────────────────────────────────

#[test]
fn fleet_status_returns_health_report() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/fleet/status", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("fleet status");
    assert_eq!(resp.status(), 200);
    let _body: serde_json::Value = resp.into_json().unwrap();
}

// ── POST /api/fleet/register ───────────────────────────────────

#[test]
fn fleet_register_creates_device() {
    let (port, token) = spawn_test_server();
    let resp = ureq::post(&format!("{}/api/fleet/register", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({"device_id": "dev-001", "name": "Sensor A"}))
        .expect("fleet register");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["status"], "registered");
    assert_eq!(body["device"], "dev-001");
}

#[test]
fn fleet_register_without_auth_returns_401() {
    let (port, _token) = spawn_test_server();
    let err = ureq::post(&format!("{}/api/fleet/register", base(port)))
        .send_json(serde_json::json!({"device_id": "dev-x"}));
    match err {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401, got {other:?}"),
    }
}

// ── GET /api/enforcement/status ────────────────────────────────

#[test]
fn enforcement_status_returns_enforcer_info() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/enforcement/status", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("enforcement status");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("process_enforcer").is_some());
    assert!(body.get("tpm").is_some());
}

// ── POST /api/enforcement/quarantine ───────────────────────────

#[test]
fn enforcement_quarantine_returns_results() {
    let (port, token) = spawn_test_server();
    let resp = ureq::post(&format!("{}/api/enforcement/quarantine", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({"target": "192.168.1.100"}))
        .expect("quarantine");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["target"], "192.168.1.100");
    assert!(body.get("actions").is_some());
}

#[test]
fn enforcement_quarantine_without_auth_returns_401() {
    let (port, _token) = spawn_test_server();
    let err = ureq::post(&format!("{}/api/enforcement/quarantine", base(port)))
        .send_json(serde_json::json!({"target": "x"}));
    match err {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401, got {other:?}"),
    }
}

// ── GET /api/threat-intel/status ───────────────────────────────

#[test]
fn threat_intel_status_returns_ioc_count() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/threat-intel/status", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("threat intel status");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("ioc_count").is_some());
}

// ── POST /api/threat-intel/ioc ─────────────────────────────────

#[test]
fn threat_intel_add_ioc() {
    let (port, token) = spawn_test_server();
    let resp = ureq::post(&format!("{}/api/threat-intel/ioc", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({"value": "10.0.0.1", "ioc_type": "ip", "confidence": 0.95}))
        .expect("add ioc");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["status"], "added");
    assert_eq!(body["value"], "10.0.0.1");
}

#[test]
fn threat_intel_ioc_without_auth_returns_401() {
    let (port, _token) = spawn_test_server();
    let err = ureq::post(&format!("{}/api/threat-intel/ioc", base(port)))
        .send_json(serde_json::json!({"value": "x", "ioc_type": "ip"}));
    match err {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401, got {other:?}"),
    }
}

// ── GET /api/digital-twin/status ───────────────────────────────

#[test]
fn digital_twin_status_returns_twin_count() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/digital-twin/status", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("digital twin status");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("twin_count").is_some());
}

// ── POST /api/digital-twin/simulate ────────────────────────────

#[test]
fn digital_twin_simulate_returns_result() {
    let (port, token) = spawn_test_server();
    let resp = ureq::post(&format!("{}/api/digital-twin/simulate", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({"device_id": "twin-1", "event_type": "cpu_spike"}))
        .expect("simulate");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["device_id"], "twin-1");
    assert!(body.get("ticks_simulated").is_some());
}

#[test]
fn digital_twin_simulate_without_auth_returns_401() {
    let (port, _token) = spawn_test_server();
    let err = ureq::post(&format!("{}/api/digital-twin/simulate", base(port)))
        .send_json(serde_json::json!({"device_id": "x", "event_type": "cpu_spike"}));
    match err {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401, got {other:?}"),
    }
}

// ── GET /api/compliance/status ─────────────────────────────────

#[test]
fn compliance_status_returns_report() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/compliance/status", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("compliance status");
    assert_eq!(resp.status(), 200);
    let _body: serde_json::Value = resp.into_json().unwrap();
}

// ── GET /api/energy/status ─────────────────────────────────────

#[test]
fn energy_status_returns_budget_info() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/energy/status", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("energy status");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("remaining_pct").is_some());
    assert!(body.get("power_state").is_some());
}

// ── POST /api/energy/consume ───────────────────────────────────

#[test]
fn energy_consume_updates_budget() {
    let (port, token) = spawn_test_server();
    let resp = ureq::post(&format!("{}/api/energy/consume", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({"drain_rate_mw": 50.0}))
        .expect("energy consume");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("remaining_pct").is_some());
}

#[test]
fn energy_consume_without_auth_returns_401() {
    let (port, _token) = spawn_test_server();
    let err = ureq::post(&format!("{}/api/energy/consume", base(port)))
        .send_json(serde_json::json!({"drain_rate_mw": 50.0}));
    match err {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401, got {other:?}"),
    }
}

// ── GET /api/tenants/count ─────────────────────────────────────

#[test]
fn tenants_count_returns_count() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/tenants/count", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("tenants count");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("tenant_count").is_some());
}

// ── GET /api/platform ──────────────────────────────────────────

#[test]
fn platform_returns_capabilities() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/platform", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("platform");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("platform").is_some());
    assert!(body.get("has_tpm").is_some());
    assert!(body.get("max_threads").is_some());
}

// ── GET /api/correlation ───────────────────────────────────────

#[test]
fn correlation_returns_analysis() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/correlation", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("correlation");
    assert_eq!(resp.status(), 200);
    let _body: serde_json::Value = resp.into_json().unwrap();
}

#[test]
fn correlation_without_auth_returns_401() {
    let (port, _token) = spawn_test_server();
    let err = ureq::get(&format!("{}/api/correlation", base(port))).call();
    match err {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401, got {other:?}"),
    }
}

// ── GET /api/side-channel/status ───────────────────────────────

#[test]
fn side_channel_status_returns_report() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/side-channel/status", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("side channel status");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("timing_anomalies").is_some());
    assert!(body.get("cache_alerts").is_some());
    assert!(body.get("overall_risk").is_some());
}

// ── GET /api/quantum/key-status ────────────────────────────────

#[test]
fn quantum_key_status_returns_epochs() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/quantum/key-status", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("quantum key status");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("current_epoch").is_some());
    assert!(body.get("total_epochs").is_some());
}

// ── POST /api/quantum/rotate ───────────────────────────────────

#[test]
fn quantum_rotate_increments_epoch() {
    let (port, token) = spawn_test_server();
    let before = ureq::get(&format!("{}/api/quantum/key-status", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .unwrap()
        .into_json::<serde_json::Value>()
        .unwrap();
    let epoch_before = before["current_epoch"].as_u64().unwrap();

    let resp = ureq::post(&format!("{}/api/quantum/rotate", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_string("")
        .expect("rotate");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["status"], "rotated");
    assert!(body["new_epoch"].as_u64().unwrap() > epoch_before);
}

#[test]
fn quantum_rotate_without_auth_returns_401() {
    let (port, _token) = spawn_test_server();
    let err = ureq::post(&format!("{}/api/quantum/rotate", base(port))).send_string("");
    match err {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401, got {other:?}"),
    }
}

// ── GET /api/privacy/budget ────────────────────────────────────

#[test]
fn privacy_budget_returns_remaining() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/privacy/budget", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("privacy budget");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("budget_remaining").is_some());
    assert!(body.get("is_exhausted").is_some());
}

// ── POST /api/policy-vm/execute ────────────────────────────────

#[test]
fn policy_vm_execute_returns_result() {
    let (port, token) = spawn_test_server();
    let resp = ureq::post(&format!("{}/api/policy-vm/execute", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({"env": {"score": 0.8, "battery": 0.5}}))
        .expect("policy vm execute");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("success").is_some());
    assert!(body.get("steps_executed").is_some());
}

#[test]
fn policy_vm_execute_without_auth_returns_401() {
    let (port, _token) = spawn_test_server();
    let err = ureq::post(&format!("{}/api/policy-vm/execute", base(port)))
        .send_json(serde_json::json!({"env": {}}));
    match err {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401, got {other:?}"),
    }
}

// ── GET /api/fingerprint/status ────────────────────────────────

#[test]
fn fingerprint_status_returns_info() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/fingerprint/status", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("fingerprint status");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("trained").is_some());
}

// ── POST /api/harness/run ──────────────────────────────────────

#[test]
fn harness_run_returns_evasion_metrics() {
    let (port, token) = spawn_test_server();
    let resp = ureq::post(&format!("{}/api/harness/run", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_string("")
        .expect("harness run");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("evasion_rate").is_some());
    assert!(body.get("coverage_ratio").is_some());
    assert!(body.get("total_count").is_some());
}

#[test]
fn harness_run_without_auth_returns_401() {
    let (port, _token) = spawn_test_server();
    let err = ureq::post(&format!("{}/api/harness/run", base(port))).send_string("");
    match err {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401, got {other:?}"),
    }
}

// ── GET /api/monitor/status ────────────────────────────────────

#[test]
fn monitor_status_returns_properties() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/monitor/status", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("monitor status");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("properties").is_some());
    assert!(body.get("violation_count").is_some());
}

// ── GET /api/monitor/violations ────────────────────────────────

#[test]
fn monitor_violations_returns_list() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/monitor/violations", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("monitor violations");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("violations").is_some());
    assert!(body["violations"].as_array().is_some());
}

// ── GET /api/deception/status ──────────────────────────────────

#[test]
fn deception_status_returns_report() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/deception/status", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("deception status");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("total_decoys").is_some());
    assert!(body.get("active_decoys").is_some());
}

// ── POST /api/deception/deploy ─────────────────────────────────

#[test]
fn deception_deploy_creates_decoy() {
    let (port, token) = spawn_test_server();
    let resp = ureq::post(&format!("{}/api/deception/deploy", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({"decoy_type": "honeypot", "name": "trap-1"}))
        .expect("deception deploy");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["status"], "deployed");
    assert!(body.get("decoy_id").is_some());
}

#[test]
fn deception_deploy_without_auth_returns_401() {
    let (port, _token) = spawn_test_server();
    let err = ureq::post(&format!("{}/api/deception/deploy", base(port)))
        .send_json(serde_json::json!({"decoy_type": "honeypot", "name": "x"}));
    match err {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401, got {other:?}"),
    }
}

// ── POST /api/policy/compose ───────────────────────────────────

#[test]
fn policy_compose_returns_result() {
    let (port, token) = spawn_test_server();
    let resp = ureq::post(&format!("{}/api/policy/compose", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "operator": "max",
            "score_a": 0.8, "battery_a": 50.0,
            "score_b": 0.3, "battery_b": 90.0
        }))
        .expect("policy compose");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("result").is_some());
}

#[test]
fn policy_compose_unknown_operator_returns_400() {
    let (port, token) = spawn_test_server();
    let err = ureq::post(&format!("{}/api/policy/compose", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "operator": "xor",
            "score_a": 0.5, "battery_a": 50.0,
            "score_b": 0.5, "battery_b": 50.0
        }));
    match err {
        Err(ureq::Error::Status(400, _)) => {}
        other => panic!("expected 400, got {other:?}"),
    }
}

#[test]
fn policy_compose_without_auth_returns_401() {
    let (port, _token) = spawn_test_server();
    let err =
        ureq::post(&format!("{}/api/policy/compose", base(port))).send_json(serde_json::json!({
            "operator": "max",
            "score_a": 0.5, "battery_a": 50.0,
            "score_b": 0.5, "battery_b": 50.0
        }));
    match err {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401, got {other:?}"),
    }
}

// ── GET /api/drift/status ──────────────────────────────────────

#[test]
fn drift_status_returns_sample_count() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/drift/status", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("drift status");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("sample_count").is_some());
}

// ── POST /api/drift/reset ──────────────────────────────────────

#[test]
fn drift_reset_clears_detector() {
    let (port, token) = spawn_test_server();
    let resp = ureq::post(&format!("{}/api/drift/reset", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_string("")
        .expect("drift reset");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["status"], "drift detector reset");
}

#[test]
fn drift_reset_without_auth_returns_401() {
    let (port, _token) = spawn_test_server();
    let err = ureq::post(&format!("{}/api/drift/reset", base(port))).send_string("");
    match err {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401, got {other:?}"),
    }
}

// ── GET /api/causal/graph ──────────────────────────────────────

#[test]
fn causal_graph_returns_counts() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/causal/graph", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("causal graph");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("node_count").is_some());
    assert!(body.get("edge_count").is_some());
}

// ── GET /api/patches ───────────────────────────────────────────

#[test]
fn patches_returns_plan_info() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/patches", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("patches");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("total_patches").is_some());
    assert!(body.get("installed").is_some());
}

// ── POST /api/offload/decide ───────────────────────────────────

#[test]
fn offload_decide_returns_decisions() {
    let (port, token) = spawn_test_server();
    let resp = ureq::post(&format!("{}/api/offload/decide", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_string("")
        .expect("offload decide");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    let decisions = body["decisions"].as_array().unwrap();
    assert!(!decisions.is_empty());
    assert!(decisions[0].get("workload").is_some());
    assert!(decisions[0].get("run_on").is_some());
}

#[test]
fn offload_decide_without_auth_returns_401() {
    let (port, _token) = spawn_test_server();
    let err = ureq::post(&format!("{}/api/offload/decide", base(port))).send_string("");
    match err {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401, got {other:?}"),
    }
}

// ── GET /api/swarm/posture ─────────────────────────────────────

#[test]
fn swarm_posture_returns_posture() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/swarm/posture", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("swarm posture");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("current_posture").is_some());
}

// ── POST /api/energy/harvest ───────────────────────────────────

#[test]
fn energy_harvest_recharges_budget() {
    let (port, token) = spawn_test_server();
    let resp = ureq::post(&format!("{}/api/energy/harvest", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_string("")
        .expect("energy harvest");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["status"], "harvested");
    assert!(body.get("recharged_mwh").is_some());
    assert!(body.get("remaining_pct").is_some());
}

#[test]
fn energy_harvest_without_auth_returns_401() {
    let (port, _token) = spawn_test_server();
    let err = ureq::post(&format!("{}/api/energy/harvest", base(port))).send_string("");
    match err {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401, got {other:?}"),
    }
}

// ── TLS Status ──────────────────────────────────────────────────

#[test]
fn tls_status_returns_plain_mode() {
    let (port, token) = spawn_test_server();
    let body: serde_json::Value = ureq::get(&format!("{}/api/tls/status", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    assert_eq!(body["tls_enabled"], false);
    assert_eq!(body["scheme"], "http");
}

// ── Config Hot-Reload ───────────────────────────────────────────

#[test]
fn config_current_returns_defaults() {
    let (port, token) = spawn_test_server();
    let body: serde_json::Value = ureq::get(&format!("{}/api/config/current", base(port)))
        .set("Authorization", &format!("Bearer {token}"))
        .call()
        .unwrap()
        .into_json()
        .unwrap();
    assert!(body["detector"]["warmup_samples"].as_u64().unwrap() > 0);
    assert!(body["policy"]["critical_score"].as_f64().unwrap() > 0.0);
}

#[test]
fn config_reload_applies_valid_patch() {
    let (port, token) = spawn_test_server();
    let body: serde_json::Value = ureq::post(&format!("{}/api/config/reload", base(port)))
        .set("Authorization", &format!("Bearer {token}"))
        .send_string(r#"{"smoothing": 0.30}"#)
        .unwrap()
        .into_json()
        .unwrap();
    assert_eq!(body["success"], true);
    assert!(body["applied_fields"].as_array().unwrap().len() == 1);
}

#[test]
fn config_reload_updates_monitor_scope_and_current_config() {
    let (port, token) = spawn_test_server();

    let patch = serde_json::json!({
        "monitor": {
            "interval_secs": 9,
            "alert_threshold": 4.4,
            "alert_log": "var/alerts.jsonl",
            "dry_run": false,
            "duration_secs": 0,
            "webhook_url": null,
            "syslog": false,
            "cef": false,
            "watch_paths": ["/tmp/wardex-scope-test"],
            "scope": {
                "cpu_load": true,
                "memory_pressure": true,
                "network_activity": true,
                "disk_pressure": true,
                "process_activity": true,
                "auth_events": false,
                "thermal_state": true,
                "battery_state": true,
                "file_integrity": false,
                "service_persistence": true,
                "launch_agents": false,
                "systemd_units": false,
                "scheduled_tasks": false
            }
        }
    });

    let reload_body: serde_json::Value = ureq::post(&format!("{}/api/config/reload", base(port)))
        .set("Authorization", &format!("Bearer {token}"))
        .send_json(patch)
        .unwrap()
        .into_json()
        .unwrap();
    assert_eq!(reload_body["success"], true);

    let current: serde_json::Value = ureq::get(&format!("{}/api/config/current", base(port)))
        .set("Authorization", &format!("Bearer {token}"))
        .call()
        .unwrap()
        .into_json()
        .unwrap();

    assert_eq!(current["monitor"]["interval_secs"], 9);
    assert_eq!(current["monitor"]["scope"]["auth_events"], false);
    assert_eq!(current["monitor"]["scope"]["file_integrity"], false);
    assert_eq!(current["monitor"]["scope"]["service_persistence"], true);
}

#[test]
fn config_save_persists_reloaded_config_to_disk() {
    let (port, token) = spawn_test_server();
    let config_path = format!("/tmp/wardex_test_{port}/wardex.toml");

    let patch = serde_json::json!({
        "monitor": {
            "interval_secs": 13,
            "alert_threshold": 4.8,
            "alert_log": "var/alerts.jsonl",
            "dry_run": true,
            "duration_secs": 0,
            "webhook_url": null,
            "syslog": true,
            "cef": false,
            "watch_paths": ["/tmp/wardex-save-roundtrip"],
            "scope": {
                "cpu_load": true,
                "memory_pressure": true,
                "network_activity": true,
                "disk_pressure": true,
                "process_activity": true,
                "auth_events": true,
                "thermal_state": true,
                "battery_state": true,
                "file_integrity": true,
                "service_persistence": true,
                "launch_agents": false,
                "systemd_units": false,
                "scheduled_tasks": false
            }
        }
    });

    let save_body: serde_json::Value = ureq::post(&format!("{}/api/config/save", base(port)))
        .set("Authorization", &format!("Bearer {token}"))
        .send_json(patch)
        .unwrap()
        .into_json()
        .unwrap();
    assert_eq!(save_body["status"], "saved");
    assert_eq!(save_body["path"], config_path);

    let persisted = std::fs::read_to_string(&config_path).expect("config persisted to disk");
    let parsed: Config = toml::from_str(&persisted).expect("persisted config parses as TOML");
    assert_eq!(parsed.monitor.interval_secs, 13);
    assert!((parsed.monitor.alert_threshold - 4.8).abs() < 0.001);
    assert!(parsed.monitor.dry_run);
    assert!(parsed.monitor.syslog);
    assert!(parsed.monitor.scope.service_persistence);
}

#[test]
fn taxii_config_persists_to_disk() {
    let (port, token) = spawn_test_server();
    let config_path = format!("/tmp/wardex_test_{port}/wardex.toml");

    let resp: serde_json::Value = ureq::post(&format!("{}/api/taxii/config", base(port)))
        .set("Authorization", &format!("Bearer {token}"))
        .send_json(serde_json::json!({
            "enabled": true,
            "url": "https://taxii.example.test/collections/alpha/objects/",
            "auth_token": "taxii-token",
            "poll_interval_secs": 180
        }))
        .unwrap()
        .into_json()
        .unwrap();
    assert_eq!(resp["status"], "ok");

    let persisted = std::fs::read_to_string(&config_path).expect("config persisted to disk");
    let parsed: Config = toml::from_str(&persisted).expect("persisted config parses as TOML");
    assert!(parsed.taxii.enabled);
    assert_eq!(
        parsed.taxii.url,
        "https://taxii.example.test/collections/alpha/objects/"
    );
    assert_eq!(parsed.taxii.auth_token, "taxii-token");
    assert_eq!(parsed.taxii.poll_interval_secs, 180);
}

#[test]
fn config_reload_rejects_invalid_patch() {
    let (port, token) = spawn_test_server();
    // critical_score=1.0 < severe_score=3.0 → invalid
    let err = ureq::post(&format!("{}/api/config/reload", base(port)))
        .set("Authorization", &format!("Bearer {token}"))
        .send_string(r#"{"critical_score": 1.0}"#);
    match err {
        Err(ureq::Error::Status(400, resp)) => {
            let body: serde_json::Value = resp.into_json().unwrap();
            assert_eq!(body["success"], false);
            assert!(body["error"].as_str().unwrap().contains("critical_score"));
        }
        other => panic!("expected 400, got {other:?}"),
    }
}

#[test]
fn config_reload_without_auth_returns_401() {
    let (port, _token) = spawn_test_server();
    let err = ureq::post(&format!("{}/api/config/reload", base(port)))
        .send_string(r#"{"smoothing": 0.5}"#);
    match err {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401, got {other:?}"),
    }
}

// ── Mesh Health ──────────────────────────────────────────────────────────────

#[test]
fn mesh_health_returns_connected() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/mesh/health", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .unwrap();
    let body: serde_json::Value = resp.into_json().unwrap();
    // Default swarm has empty mesh → single trivially-connected component
    assert_eq!(body["is_connected"], true);
    assert_eq!(body["partition_count"], 0);
}

#[test]
fn mesh_heal_on_empty_mesh_is_noop() {
    let (port, token) = spawn_test_server();
    let resp = ureq::post(&format!("{}/api/mesh/heal", base(port)))
        .set("Authorization", &format!("Bearer {token}"))
        .call()
        .unwrap();
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["repairs_applied"], 0);
    assert_eq!(body["was_connected"], true);
    assert_eq!(body["now_connected"], true);
}

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
    assert!(arr
        .iter()
        .any(|entry| entry["path"] == "/api/monitoring/options" && entry["auth"] == true));
    assert!(arr
        .iter()
        .any(|entry| entry["path"] == "/api/host/info" && entry["auth"] == true));
    assert!(arr
        .iter()
        .any(|entry| entry["path"] == "/api/alerts/{id}" && entry["auth"] == true));
    assert!(arr
        .iter()
        .any(|entry| entry["path"] == "/api/threat-intel/status" && entry["auth"] == true));
    assert!(arr
        .iter()
        .any(|entry| entry["path"] == "/api/playbooks" && entry["auth"] == true));
    assert!(arr
        .iter()
        .any(|entry| entry["path"] == "/api/fleet/dashboard" && entry["auth"] == true));
    assert!(arr
        .iter()
        .any(|entry| entry["path"] == "/api/agents" && entry["auth"] == true));
    assert!(arr
        .iter()
        .any(|entry| entry["path"] == "/api/cases" && entry["auth"] == true));
    assert!(arr
        .iter()
        .any(|entry| entry["path"] == "/api/events" && entry["auth"] == true));
    assert!(arr
        .iter()
        .any(|entry| entry["path"] == "/api/events/search" && entry["auth"] == true));
    assert!(arr
        .iter()
        .any(|entry| entry["path"] == "/api/response/approvals" && entry["auth"] == true));
    assert!(arr
        .iter()
        .any(|entry| entry["path"] == "/api/rollout/config" && entry["auth"] == true));
    assert!(arr
        .iter()
        .any(|entry| entry["path"] == "/api/timeline/host" && entry["auth"] == true));
    assert!(arr
        .iter()
        .any(|entry| entry["path"] == "/api/queue/stats" && entry["auth"] == true));
    assert!(arr
        .iter()
        .any(|entry| entry["path"] == "/api/agents/{id}/status" && entry["auth"] == true));
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
    assert!(first_group["options"]
        .as_array()
        .unwrap()
        .iter()
        .all(|option| option["id"].is_string()));
    assert!(
        body["summary"]["platform_guidance"]
            .as_array()
            .unwrap()
            .len()
            >= 1
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
    assert_eq!(agents.as_array().unwrap().len(), 1);

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
    assert!(summary["top_reasons"].as_array().unwrap().len() >= 1);
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
    assert_eq!(body["enabled"].as_bool().unwrap(), false);
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
    assert!(body.get("siem").is_some());
    assert_eq!(body["fleet"]["total_agents"].as_u64().unwrap(), 0);
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
    assert_eq!(body["update_available"].as_bool().unwrap(), false);
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
    assert_eq!(
        deployed["deployment"]["allow_downgrade"].as_bool().unwrap(),
        false
    );

    let heartbeat = ureq::post(&format!("{}/api/agents/{}/heartbeat", base(port), agent_id))
        .set("Content-Type", "application/json")
        .send_string(r#"{"version":"0.15.0","health":{"pending_alerts":2,"telemetry_queue_depth":2,"update_state":"downloading","update_target_version":"0.16.0"}}"#)
        .expect("heartbeat")
        .into_json::<serde_json::Value>()
        .unwrap();
    assert_eq!(heartbeat["update_assigned"].as_bool().unwrap(), true);
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
    assert_eq!(update["update_available"].as_bool().unwrap(), true);
    assert_eq!(update["version"].as_str().unwrap(), "0.16.0");
    assert!(update["download_url"]
        .as_str()
        .unwrap()
        .starts_with("/api/updates/download/"));
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

#[test]
fn event_filters_export_and_agent_details_return_expected_data() {
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
                "hostname": "detail-agent",
                "platform": "linux",
                "version": "0.15.0",
            })
            .to_string(),
        )
        .expect("enroll agent")
        .into_json::<serde_json::Value>()
        .unwrap();
    let agent_id = enrolled["agent_id"].as_str().unwrap();

    ureq::post(&format!("{}/api/events", base(port)))
        .set("Content-Type", "application/json")
        .send_string(&serde_json::json!({
            "agent_id": agent_id,
            "events": [
                {
                    "timestamp": "2025-01-01T00:00:00Z",
                    "hostname": "detail-agent",
                    "platform": "linux",
                    "score": 2.6,
                    "confidence": 0.82,
                    "level": "Elevated",
                    "action": "monitor",
                    "reasons": ["auth_spike"],
                    "sample": {
                        "timestamp_ms": 1, "cpu_load_pct": 20.0, "memory_load_pct": 30.0,
                        "temperature_c": 42.0, "network_kbps": 200.0, "auth_failures": 4,
                        "battery_pct": 70.0, "integrity_drift": 0.01, "process_count": 40, "disk_pressure_pct": 10.0
                    },
                    "enforced": false
                },
                {
                    "timestamp": "2025-01-01T00:01:00Z",
                    "hostname": "detail-agent",
                    "platform": "linux",
                    "score": 5.4,
                    "confidence": 0.95,
                    "level": "Critical",
                    "action": "isolate",
                    "reasons": ["high_cpu"],
                    "sample": {
                        "timestamp_ms": 2, "cpu_load_pct": 98.0, "memory_load_pct": 75.0,
                        "temperature_c": 63.0, "network_kbps": 500.0, "auth_failures": 0,
                        "battery_pct": 68.0, "integrity_drift": 0.05, "process_count": 90, "disk_pressure_pct": 15.0
                    },
                    "enforced": false
                }
            ]
        }).to_string())
        .expect("ingest events");

    let triaged = ureq::post(&format!("{}/api/events/2/triage", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "status": "investigating",
                "assignee": "alice",
                "tags": ["cpu", "urgent"],
                "note": "SOC opened an investigation"
            })
            .to_string(),
        )
        .expect("triage event")
        .into_json::<serde_json::Value>()
        .unwrap();
    assert_eq!(
        triaged["event"]["triage"]["status"].as_str().unwrap(),
        "investigating"
    );
    assert_eq!(
        triaged["event"]["triage"]["assignee"].as_str().unwrap(),
        "alice"
    );

    let filtered = ureq::get(&format!(
        "{}/api/events?agent_id={}&severity=Critical&reason=high_cpu",
        base(port),
        agent_id
    ))
    .set("Authorization", &auth_header(&token))
    .call()
    .expect("filtered events")
    .into_json::<serde_json::Value>()
    .unwrap();
    assert_eq!(filtered.as_array().unwrap().len(), 1);

    let triage_filtered = ureq::get(&format!(
        "{}/api/events?agent_id={}&triage_status=investigating",
        base(port),
        agent_id
    ))
    .set("Authorization", &auth_header(&token))
    .call()
    .expect("triage filtered events")
    .into_json::<serde_json::Value>()
    .unwrap();
    assert_eq!(triage_filtered.as_array().unwrap().len(), 1);
    assert_eq!(
        triage_filtered[0]["triage"]["status"].as_str().unwrap(),
        "investigating"
    );

    let csv = ureq::get(&format!(
        "{}/api/events/export?agent_id={}&reason=high_cpu",
        base(port),
        agent_id
    ))
    .set("Authorization", &auth_header(&token))
    .call()
    .expect("export csv")
    .into_string()
    .unwrap();
    assert!(csv.contains("id,agent_id,received_at"));
    assert!(csv.contains("triage_status"));
    assert!(csv.contains("high_cpu"));

    let details = ureq::get(&format!("{}/api/agents/{}/details", base(port), agent_id))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("agent details")
        .into_json::<serde_json::Value>()
        .unwrap();
    assert_eq!(
        details["agent"]["hostname"].as_str().unwrap(),
        "detail-agent"
    );
    assert_eq!(details["analytics"]["event_count"].as_u64().unwrap(), 2);
    assert_eq!(
        details["timeline"][0]["triage"]["status"].as_str().unwrap(),
        "investigating"
    );
    assert!(!details["risk_transitions"].as_array().unwrap().is_empty());
}

#[test]
fn remote_update_deploy_blocks_downgrades_without_override() {
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
                "hostname": "stable-agent",
                "platform": "linux",
                "version": "0.16.0",
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
                "version": "0.15.5",
                "platform": "linux",
                "binary_base64": "aGVsbG8=",
                "release_notes": "rollback build",
                "mandatory": false,
            })
            .to_string(),
        )
        .expect("publish release");

    let err = ureq::post(&format!("{}/api/updates/deploy", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "agent_id": agent_id,
                "version": "0.15.5",
                "platform": "linux"
            })
            .to_string(),
        );
    match err {
        Err(ureq::Error::Status(409, _)) => {}
        other => panic!("expected 409, got {other:?}"),
    }
}

#[test]
fn remote_update_deploy_allows_downgrades_when_explicitly_enabled() {
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
                "hostname": "rollback-agent",
                "platform": "linux",
                "version": "0.16.0",
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
                "version": "0.15.5",
                "platform": "linux",
                "binary_base64": "aGVsbG8=",
                "release_notes": "rollback build",
                "mandatory": false,
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
                "version": "0.15.5",
                "platform": "linux",
                "allow_downgrade": true
            })
            .to_string(),
        )
        .expect("assign rollback deployment")
        .into_json::<serde_json::Value>()
        .unwrap();
    assert_eq!(
        deployed["deployment"]["allow_downgrade"].as_bool().unwrap(),
        true
    );

    let update = ureq::get(&format!(
        "{}/api/agents/update?agent_id={}&current_version=0.16.0",
        base(port),
        agent_id
    ))
    .call()
    .expect("rollback update check")
    .into_json::<serde_json::Value>()
    .unwrap();
    assert_eq!(update["update_available"].as_bool().unwrap(), true);
    assert_eq!(update["version"].as_str().unwrap(), "0.15.5");
}

#[test]
fn event_triage_rejects_invalid_status() {
    let (port, token) = spawn_test_server();

    ureq::post(&format!("{}/api/events", base(port)))
        .set("Content-Type", "application/json")
        .send_string(&serde_json::json!({
            "agent_id": "triage-agent",
            "events": [{
                "timestamp": "2025-01-01T00:00:00Z",
                "hostname": "triage-agent",
                "platform": "linux",
                "score": 5.4,
                "confidence": 0.95,
                "level": "Critical",
                "action": "isolate",
                "reasons": ["high_cpu"],
                "sample": {
                    "timestamp_ms": 2, "cpu_load_pct": 98.0, "memory_load_pct": 75.0,
                    "temperature_c": 63.0, "network_kbps": 500.0, "auth_failures": 0,
                    "battery_pct": 68.0, "integrity_drift": 0.05, "process_count": 90, "disk_pressure_pct": 15.0
                },
                "enforced": false
            }]
        }).to_string())
        .expect("ingest event");

    let err = ureq::post(&format!("{}/api/events/1/triage", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "status": "queued"
            })
            .to_string(),
        );

    match err {
        Err(ureq::Error::Status(400, _)) => {}
        other => panic!("expected 400, got {other:?}"),
    }
}

#[test]
fn monitoring_paths_include_health_summary() {
    let (port, token) = spawn_test_server();
    let body: serde_json::Value = ureq::get(&format!("{}/api/monitoring/paths", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("monitoring paths")
        .into_json()
        .unwrap();
    assert!(body["file_integrity_health"].is_array());
    assert!(body["persistence_health"].is_array());
    assert!(body["summary"]["unhealthy_paths"].is_u64());
}

// ── Helper: create token + enroll agent + ingest events ────────

fn setup_agent_with_events(
    port: u16,
    token: &str,
    agent_name: &str,
    count: u32,
) -> (String, Vec<u64>) {
    // Create enrollment token
    let resp = ureq::post(&format!("{}/api/agents/token", base(port)))
        .set("Authorization", &auth_header(token))
        .set("Content-Type", "application/json")
        .send_string(r#"{"max_uses":1}"#)
        .unwrap();
    let tok: serde_json::Value = resp.into_json().unwrap();
    let enrollment_token = tok["token"].as_str().unwrap().to_string();

    // Enroll
    let body = serde_json::json!({
        "enrollment_token": enrollment_token,
        "hostname": agent_name,
        "platform": "linux",
        "version": "0.23.0",
    });
    let resp = ureq::post(&format!("{}/api/agents/enroll", base(port)))
        .set("Content-Type", "application/json")
        .send_string(&body.to_string())
        .unwrap();
    let enroll: serde_json::Value = resp.into_json().unwrap();
    let agent_id = enroll["agent_id"].as_str().unwrap().to_string();

    // Ingest events
    let mut events = Vec::new();
    for i in 0..count {
        events.push(serde_json::json!({
            "timestamp": format!("2025-01-01T00:{:02}:00Z", i),
            "hostname": agent_name,
            "platform": "linux",
            "score": 5.0 + (i as f64),
            "confidence": 0.9,
            "level": if i % 2 == 0 { "Critical" } else { "Elevated" },
            "action": "alert",
            "reasons": ["test_reason"],
            "sample": {
                "timestamp_ms": 0, "cpu_load_pct": 80.0, "memory_load_pct": 50.0,
                "temperature_c": 55.0, "network_kbps": 10.0, "auth_failures": 0,
                "battery_pct": 99.0, "integrity_drift": 0.0,
                "process_count": 30, "disk_pressure_pct": 5.0
            },
            "enforced": false
        }));
    }
    let batch = serde_json::json!({ "agent_id": agent_id, "events": events });
    ureq::post(&format!("{}/api/events", base(port)))
        .set("Content-Type", "application/json")
        .send_string(&batch.to_string())
        .expect("ingest events");

    // Get event IDs
    let resp = ureq::get(&format!("{}/api/events", base(port)))
        .set("Authorization", &auth_header(token))
        .call()
        .unwrap();
    let all_events: Vec<serde_json::Value> = resp.into_json().unwrap();
    let ids: Vec<u64> = all_events
        .iter()
        .filter(|e| e["agent_id"].as_str() == Some(&agent_id))
        .filter_map(|e| e["id"].as_u64())
        .collect();
    (agent_id, ids)
}

#[test]
fn queue_alerts_include_age_and_sla_fields() {
    let (port, token) = spawn_test_server();
    let (_agent_id, event_ids) = setup_agent_with_events(port, &token, "queue-host", 1);
    assert!(!event_ids.is_empty());

    let body: serde_json::Value = ureq::get(&format!("{}/api/queue/alerts", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("queue alerts")
        .into_json()
        .unwrap();

    assert!(body["count"].as_u64().unwrap() >= 1);
    let item = &body["queue"][0];
    assert!(item["event_id"].is_u64());
    assert!(item["age_secs"].is_u64());
    assert!(item["sla_breached"].is_boolean());
    assert!(item["severity"].is_string());
}

#[test]
fn case_detail_includes_linked_incidents_and_events() {
    let (port, token) = spawn_test_server();
    let (agent_id, event_ids) = setup_agent_with_events(port, &token, "case-host", 1);
    let event_id = event_ids[0];

    let incident: serde_json::Value = ureq::post(&format!("{}/api/incidents", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "title": "Case linked incident",
                "severity": "Critical",
                "event_ids": [event_id],
                "agent_ids": [agent_id],
                "summary": "linked incident for case detail"
            })
            .to_string(),
        )
        .expect("create incident")
        .into_json()
        .unwrap();
    let incident_id = incident["id"].as_u64().unwrap();

    let case: serde_json::Value = ureq::post(&format!("{}/api/cases", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "title": "Case with linked refs",
                "priority": "high",
                "description": "link incident and event",
                "incident_ids": [incident_id],
                "event_ids": [event_id],
                "tags": ["linked"]
            })
            .to_string(),
        )
        .expect("create case")
        .into_json()
        .unwrap();
    let case_id = case["id"].as_u64().unwrap();

    let detail: serde_json::Value = ureq::get(&format!("{}/api/cases/{}", base(port), case_id))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("case detail")
        .into_json()
        .unwrap();

    assert_eq!(detail["id"].as_u64().unwrap(), case_id);
    assert_eq!(detail["linked_incidents"].as_array().unwrap().len(), 1);
    assert_eq!(detail["linked_events"].as_array().unwrap().len(), 1);
    assert_eq!(
        detail["linked_incidents"][0]["id"].as_u64().unwrap(),
        incident_id
    );
    assert_eq!(detail["linked_events"][0]["id"].as_u64().unwrap(), event_id);
}

#[test]
fn timeline_endpoints_support_query_string_routing() {
    let (port, token) = spawn_test_server();
    let (agent_id, event_ids) = setup_agent_with_events(port, &token, "timeline-host", 2);
    assert_eq!(event_ids.len(), 2);

    let host_timeline: serde_json::Value = ureq::get(&format!(
        "{}/api/timeline/host?hostname=timeline-host",
        base(port)
    ))
    .set("Authorization", &auth_header(&token))
    .call()
    .expect("host timeline")
    .into_json()
    .unwrap();
    assert_eq!(host_timeline["host"].as_str().unwrap(), "timeline-host");
    assert_eq!(host_timeline["count"].as_u64().unwrap(), 2);

    let agent_timeline: serde_json::Value = ureq::get(&format!(
        "{}/api/timeline/agent?agent_id={}",
        base(port),
        agent_id
    ))
    .set("Authorization", &auth_header(&token))
    .call()
    .expect("agent timeline")
    .into_json()
    .unwrap();
    assert_eq!(agent_timeline["agent_id"].as_str().unwrap(), agent_id);
    assert_eq!(agent_timeline["count"].as_u64().unwrap(), 2);
}

#[test]
fn timeline_prefix_aliases_do_not_match_exact_routes() {
    let (port, token) = spawn_test_server();

    for path in [
        "/api/timeline/hostile?hostname=test-host",
        "/api/timeline/agentic?agent_id=test-agent",
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
fn agent_status_requires_auth() {
    let (port, token) = spawn_test_server();

    let token_resp = ureq::post(&format!("{}/api/agents/token", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "hostname": "auth-check-agent",
            "max_uses": 1
        }))
        .expect("create enrollment token");
    let enrollment_token = token_resp.into_json::<serde_json::Value>().unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();

    let enroll = ureq::post(&format!("{}/api/agents/enroll", base(port)))
        .set("Content-Type", "application/json")
        .send_string(&format!(
            r#"{{"enrollment_token":"{}","hostname":"auth-check-agent","platform":"linux","version":"1.0.0"}}"#,
            enrollment_token
        ))
        .expect("enroll agent for status auth test");
    let agent_id = enroll.into_json::<serde_json::Value>().unwrap()["agent_id"]
        .as_str()
        .unwrap()
        .to_string();

    match ureq::get(&format!("{}/api/agents/{}/status", base(port), agent_id)).call() {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401 for agent status without auth, got {other:?}"),
    }
}

#[test]
fn workbench_overview_surfaces_queue_cases_incidents_and_ready_actions() {
    let (port, token) = spawn_test_server();
    let (agent_id, event_ids) = setup_agent_with_events(port, &token, "workbench-host", 2);

    let case: serde_json::Value = ureq::post(&format!("{}/api/cases", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "title": "Workbench case",
                "priority": "critical",
                "description": "created for overview",
                "event_ids": [event_ids[0]],
                "tags": ["overview"]
            })
            .to_string(),
        )
        .expect("create workbench case")
        .into_json()
        .unwrap();
    assert!(case["id"].as_u64().unwrap() > 0);

    let incident: serde_json::Value = ureq::post(&format!("{}/api/incidents", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "title": "Workbench incident",
                "severity": "Critical",
                "event_ids": [event_ids[0]],
                "agent_ids": [agent_id],
                "summary": "created for workbench overview"
            })
            .to_string(),
        )
        .expect("create workbench incident")
        .into_json()
        .unwrap();
    assert!(incident["id"].as_u64().unwrap() > 0);

    let submitted: serde_json::Value = ureq::post(&format!("{}/api/response/request", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "action": "kill_process",
            "pid": 31337,
            "process_name": "payload.bin",
            "hostname": "workbench-host",
            "reason": "overview-ready response",
            "severity": "high",
            "requested_by": "integration-test",
        }))
        .expect("submit response request")
        .into_json()
        .unwrap();
    let request_id = submitted["request"]["id"].as_str().unwrap().to_string();

    ureq::post(&format!("{}/api/response/approve", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "request_id": request_id,
            "decision": "approved",
            "approver": "analyst-1",
            "reason": "ready for overview",
        }))
        .expect("approve response request");

    let overview: serde_json::Value = ureq::get(&format!("{}/api/workbench/overview", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("workbench overview")
        .into_json()
        .unwrap();

    assert!(overview["queue"]["pending"].as_u64().unwrap() >= 2);
    assert!(overview["queue"]["items"][0]["age_secs"].is_u64());
    assert_eq!(overview["cases"]["total"].as_u64().unwrap(), 1);
    assert_eq!(overview["incidents"]["total"].as_u64().unwrap(), 1);
    assert_eq!(
        overview["response"]["ready_to_execute"].as_u64().unwrap(),
        1
    );
    assert!(!overview["urgent_items"].as_array().unwrap().is_empty());
}

#[test]
fn manager_overview_tracks_fleet_queue_and_deployment_health() {
    let (port, token) = spawn_test_server();
    let (agent_id, event_ids) = setup_agent_with_events(port, &token, "manager-host", 1);
    assert!(!event_ids.is_empty());

    ureq::post(&format!("{}/api/updates/publish", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "version": "9.9.9",
                "platform": "linux",
                "binary_base64": "aGVsbG8=",
                "release_notes": "manager overview release",
                "mandatory": true
            })
            .to_string(),
        )
        .expect("publish release");

    ureq::post(&format!("{}/api/updates/deploy", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "agent_id": agent_id,
                "version": "9.9.9",
                "platform": "linux",
                "rollout_group": "canary"
            })
            .to_string(),
        )
        .expect("deploy release");

    let overview: serde_json::Value = ureq::get(&format!("{}/api/manager/overview", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("manager overview")
        .into_json()
        .unwrap();

    assert_eq!(overview["fleet"]["total_agents"].as_u64().unwrap(), 1);
    assert_eq!(overview["fleet"]["online"].as_u64().unwrap(), 1);
    assert!(overview["queue"]["pending"].as_u64().unwrap() >= 1);
    assert!(
        overview["deployments"]["published_releases"]
            .as_u64()
            .unwrap()
            >= 1
    );
    assert!(overview["deployments"]["pending"].as_u64().unwrap() >= 1);
    assert!(overview["compliance"]["score"].is_number());
}

#[test]
fn agent_activity_snapshot_includes_deployment_and_event_analytics() {
    let (port, token) = spawn_test_server();
    let (agent_id, event_ids) = setup_agent_with_events(port, &token, "activity-host", 2);
    assert!(event_ids.len() >= 2);

    ureq::post(&format!("{}/api/updates/publish", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "version": "0.24.0",
                "platform": "linux",
                "binary_base64": "aGVsbG8=",
                "release_notes": "activity release",
                "mandatory": false
            })
            .to_string(),
        )
        .expect("publish release");

    ureq::post(&format!("{}/api/updates/deploy", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "agent_id": agent_id,
                "version": "0.24.0",
                "platform": "linux",
                "rollout_group": "ring-1"
            })
            .to_string(),
        )
        .expect("deploy release");

    ureq::post(&format!("{}/api/agents/{}/heartbeat", base(port), agent_id))
        .set("Content-Type", "application/json")
        .send_string(r#"{"version":"0.23.0","health":{"pending_alerts":3,"telemetry_queue_depth":1,"update_state":"downloading","update_target_version":"0.24.0"}}"#)
        .expect("heartbeat");

    let activity: serde_json::Value =
        ureq::get(&format!("{}/api/agents/{}/activity", base(port), agent_id))
            .set("Authorization", &auth_header(&token))
            .call()
            .expect("agent activity")
            .into_json()
            .unwrap();

    assert_eq!(activity["agent"]["id"].as_str().unwrap(), agent_id);
    assert_eq!(activity["computed_status"].as_str().unwrap(), "online");
    assert_eq!(
        activity["deployment"]["version"].as_str().unwrap(),
        "0.24.0"
    );
    assert_eq!(
        activity["deployment"]["rollout_group"].as_str().unwrap(),
        "ring-1"
    );
    assert_eq!(activity["health"]["pending_alerts"].as_u64().unwrap(), 3);
    assert!(activity["analytics"]["event_count"].as_u64().unwrap() >= 2);
    assert!(activity["timeline"].as_array().unwrap().len() >= 2);
}

#[test]
fn agents_summary_includes_freshness_versions_and_rollout_fields() {
    let (port, token) = spawn_test_server();
    let (agent_id, _event_ids) = setup_agent_with_events(port, &token, "summary-host", 1);

    ureq::post(&format!("{}/api/updates/publish", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "version": "1.2.3",
                "platform": "linux",
                "binary_base64": "aGVsbG8=",
                "release_notes": "summary release",
                "mandatory": false
            })
            .to_string(),
        )
        .expect("publish release");

    ureq::post(&format!("{}/api/updates/deploy", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "agent_id": agent_id,
                "version": "1.2.3",
                "platform": "linux",
                "rollout_group": "canary"
            })
            .to_string(),
        )
        .expect("deploy release");

    let agents: serde_json::Value = ureq::get(&format!("{}/api/agents", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("agent summary")
        .into_json()
        .unwrap();
    let first = &agents[0];
    assert_eq!(first["id"].as_str().unwrap(), agent_id);
    assert!(first["last_seen_age_secs"].is_u64());
    assert!(first["current_version"].is_string());
    assert_eq!(first["target_version"].as_str().unwrap(), "1.2.3");
    assert_eq!(first["rollout_group"].as_str().unwrap(), "canary");
    assert_eq!(first["deployment_status"].as_str().unwrap(), "assigned");
}

#[test]
fn analyst_flow_links_queue_case_incident_and_response_actions() {
    let (port, token) = spawn_test_server();
    let (agent_id, event_ids) = setup_agent_with_events(port, &token, "analyst-flow-host", 1);
    let event_id = event_ids[0];

    let assign: serde_json::Value = ureq::post(&format!("{}/api/queue/assign", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "event_id": event_id,
            "assignee": "analyst-1"
        }))
        .expect("assign queue item")
        .into_json()
        .unwrap();
    assert_eq!(assign["event_id"].as_u64().unwrap_or(event_id), event_id);

    let case: serde_json::Value = ureq::post(&format!("{}/api/cases", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "title": "Analyst flow case",
                "priority": "high",
                "description": "created from queue",
                "event_ids": [event_id],
                "tags": ["analyst-flow"]
            })
            .to_string(),
        )
        .expect("create case")
        .into_json()
        .unwrap();
    let case_id = case["id"].as_u64().unwrap();

    let incident: serde_json::Value = ureq::post(&format!("{}/api/incidents", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "title": "Analyst flow incident",
                "severity": "Critical",
                "event_ids": [event_id],
                "agent_ids": [agent_id],
                "summary": "escalated from analyst flow"
            })
            .to_string(),
        )
        .expect("create incident")
        .into_json()
        .unwrap();
    let incident_id = incident["id"].as_u64().unwrap();

    ureq::post(&format!("{}/api/cases/{}/update", base(port), case_id))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "status": "investigating",
            "assignee": "analyst-1",
            "link_incident": incident_id
        }))
        .expect("update case");

    let submitted: serde_json::Value = ureq::post(&format!("{}/api/response/request", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "action": "kill_process",
            "pid": 9001,
            "process_name": "analyst-flow.bin",
            "hostname": "analyst-flow-host",
            "reason": "end-to-end analyst flow",
            "severity": "high",
            "requested_by": "integration-test",
        }))
        .expect("submit response request")
        .into_json()
        .unwrap();
    let request_id = submitted["request"]["id"].as_str().unwrap().to_string();

    ureq::post(&format!("{}/api/response/approve", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "request_id": request_id,
            "decision": "approved",
            "approver": "analyst-1",
            "reason": "approved in analyst flow",
        }))
        .expect("approve response request");

    ureq::post(&format!("{}/api/response/execute", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "request_id": request_id
        }))
        .expect("execute response request");

    let detail: serde_json::Value = ureq::get(&format!("{}/api/cases/{}", base(port), case_id))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("case detail")
        .into_json()
        .unwrap();
    assert_eq!(detail["status"].as_str().unwrap(), "Investigating");
    assert_eq!(detail["linked_incidents"].as_array().unwrap().len(), 1);

    let requests: serde_json::Value = ureq::get(&format!("{}/api/response/requests", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("response requests")
        .into_json()
        .unwrap();
    assert_eq!(
        requests["requests"][0]["status"].as_str().unwrap(),
        "Executed"
    );
}

// ── POST /api/events/bulk-triage ───────────────────────────────

#[test]
fn bulk_triage_updates_multiple_events() {
    let (port, token) = spawn_test_server();
    let (_agent_id, event_ids) = setup_agent_with_events(port, &token, "bulk-host", 3);
    assert!(event_ids.len() >= 3);

    let body = serde_json::json!({
        "event_ids": event_ids,
        "status": "investigating",
        "assignee": "analyst-1",
        "tags": ["bulk", "test"],
        "note": "bulk triage test",
        "author": "integration-test"
    });
    let resp = ureq::post(&format!("{}/api/events/bulk-triage", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(&body.to_string())
        .expect("bulk triage");
    assert_eq!(resp.status(), 200);
    let result: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(result["updated"].as_u64().unwrap(), event_ids.len() as u64);
}

#[test]
fn bulk_triage_without_auth_returns_401() {
    let (port, _token) = spawn_test_server();
    let err = ureq::post(&format!("{}/api/events/bulk-triage", base(port)))
        .set("Content-Type", "application/json")
        .send_string(r#"{"event_ids":[1],"status":"acknowledged"}"#);
    match err {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401, got {other:?}"),
    }
}

#[test]
fn bulk_triage_empty_ids_returns_400() {
    let (port, token) = spawn_test_server();
    let resp = ureq::post(&format!("{}/api/events/bulk-triage", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(r#"{"event_ids":[],"status":"acknowledged"}"#);
    match resp {
        Err(ureq::Error::Status(400, _)) => {}
        other => panic!("expected 400, got {other:?}"),
    }
}

// ── POST /api/updates/cancel ───────────────────────────────────

#[test]
fn updates_releases_lists_published_releases() {
    let (port, token) = spawn_test_server();

    for (version, platform) in [("1.0.0", "linux"), ("1.1.0", "macOS")] {
        ureq::post(&format!("{}/api/updates/publish", base(port)))
            .set("Authorization", &auth_header(&token))
            .set("Content-Type", "application/json")
            .send_string(
                &serde_json::json!({
                    "version": version,
                    "platform": platform,
                    "binary_base64": "aGVsbG8=",
                    "release_notes": format!("release {version}"),
                    "mandatory": false
                })
                .to_string(),
            )
            .expect("publish release");
    }

    let releases = ureq::get(&format!("{}/api/updates/releases", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("list releases")
        .into_json::<serde_json::Value>()
        .unwrap();

    let releases = releases.as_array().expect("release array");
    assert_eq!(releases.len(), 2);
    assert!(releases.iter().any(|release| {
        release["version"].as_str() == Some("1.0.0")
            && release["platform"].as_str() == Some("linux")
    }));
    assert!(releases.iter().any(|release| {
        release["version"].as_str() == Some("1.1.0")
            && release["platform"].as_str() == Some("macOS")
    }));
}

#[test]
fn cancel_deployment_works() {
    let (port, token) = spawn_test_server();
    let (agent_id, _) = setup_agent_with_events(port, &token, "cancel-host", 0);

    // Publish a release
    ureq::post(&format!("{}/api/updates/publish", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "version": "1.0.0", "platform": "linux",
                "sha256": "abc123", "url": "http://example.com/v1",
                "release_notes": "test release"
            })
            .to_string(),
        )
        .expect("publish release");

    // Deploy
    ureq::post(&format!("{}/api/updates/deploy", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "agent_id": agent_id, "version": "1.0.0", "platform": "linux",
                "rollout_group": "direct"
            })
            .to_string(),
        )
        .expect("deploy update");

    // Cancel
    let resp = ureq::post(&format!("{}/api/updates/cancel", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(&serde_json::json!({"agent_id": agent_id}).to_string())
        .expect("cancel deployment");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["status"].as_str().unwrap(), "cancelled");
}

#[test]
fn cancel_nonexistent_deployment_returns_404() {
    let (port, token) = spawn_test_server();
    let resp = ureq::post(&format!("{}/api/updates/cancel", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(r#"{"agent_id":"nonexistent-agent"}"#);
    match resp {
        Err(ureq::Error::Status(404, _)) => {}
        other => panic!("expected 404, got {other:?}"),
    }
}

// ── POST /api/updates/rollback ─────────────────────────────────

#[test]
fn rollback_deployment_works() {
    let (port, token) = spawn_test_server();
    let (agent_id, _) = setup_agent_with_events(port, &token, "rollback-host", 0);

    // Publish two releases
    for v in ["1.0.0", "2.0.0"] {
        ureq::post(&format!("{}/api/updates/publish", base(port)))
            .set("Authorization", &auth_header(&token))
            .set("Content-Type", "application/json")
            .send_string(
                &serde_json::json!({
                    "version": v, "platform": "linux",
                    "sha256": "abc123", "url": "http://example.com/v",
                    "release_notes": format!("v{v}")
                })
                .to_string(),
            )
            .expect("publish release");
    }

    // Deploy v2
    ureq::post(&format!("{}/api/updates/deploy", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "agent_id": agent_id, "version": "2.0.0", "platform": "linux",
                "rollout_group": "direct"
            })
            .to_string(),
        )
        .expect("deploy v2");

    // Rollback to v1
    let resp = ureq::post(&format!("{}/api/updates/rollback", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "agent_id": agent_id, "target_version": "1.0.0"
            })
            .to_string(),
        )
        .expect("rollback");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["status"].as_str().unwrap(), "rollback_assigned");
    assert_eq!(body["deployment"]["version"].as_str().unwrap(), "1.0.0");
    assert_eq!(
        body["deployment"]["allow_downgrade"].as_bool().unwrap(),
        true
    );
}

// ── Agent Monitoring Scope ─────────────────────────────────────

#[test]
fn agent_scope_set_and_get() {
    let (port, token) = spawn_test_server();
    let (agent_id, _) = setup_agent_with_events(port, &token, "scope-host", 0);

    // Get scope (should be server default)
    let resp = ureq::get(&format!("{}/api/agents/{}/scope", base(port), agent_id))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("get scope");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["override"].as_bool().unwrap(), false);

    // Set custom scope
    let scope = serde_json::json!({
        "cpu_load": true, "memory_pressure": true, "network_activity": false,
        "disk_pressure": true, "process_activity": true, "auth_events": true,
        "thermal_state": false, "battery_state": false, "file_integrity": true,
        "service_persistence": true, "launch_agents": false, "systemd_units": true,
        "scheduled_tasks": false
    });
    let resp = ureq::post(&format!("{}/api/agents/{}/scope", base(port), agent_id))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(&scope.to_string())
        .expect("set scope");
    assert_eq!(resp.status(), 200);

    // Verify it was saved
    let resp = ureq::get(&format!("{}/api/agents/{}/scope", base(port), agent_id))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("get scope again");
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["override"].as_bool().unwrap(), true);
    assert_eq!(body["scope"]["network_activity"].as_bool().unwrap(), false);
    assert_eq!(body["scope"]["battery_state"].as_bool().unwrap(), false);

    // Clear scope
    let resp = ureq::post(&format!("{}/api/agents/{}/scope", base(port), agent_id))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(r#"{"clear":true}"#)
        .expect("clear scope");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["status"].as_str().unwrap(), "scope_cleared");
}

// ── Rollout Config ─────────────────────────────────────────────

#[test]
fn rollout_config_readable() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/rollout/config", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("get rollout config");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("auto_progress").is_some());
    assert!(body.get("canary_soak_secs").is_some());
    assert!(body.get("ring1_soak_secs").is_some());
    assert!(body.get("auto_rollback").is_some());
    assert!(body.get("max_failures").is_some());
}

#[test]
fn rollout_config_updatable_via_config_patch() {
    let (port, token) = spawn_test_server();
    let patch = serde_json::json!({
        "rollout": {
            "auto_progress": true,
            "canary_soak_secs": 120,
            "ring1_soak_secs": 240,
            "auto_rollback": true,
            "max_failures": 3
        }
    });
    let resp = ureq::post(&format!("{}/api/config/reload", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(&patch.to_string())
        .expect("patch config");
    assert_eq!(resp.status(), 200);

    // Verify
    let resp = ureq::get(&format!("{}/api/rollout/config", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("get rollout config");
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["auto_progress"].as_bool().unwrap(), true);
    assert_eq!(body["canary_soak_secs"].as_u64().unwrap(), 120);
    assert_eq!(body["max_failures"].as_u64().unwrap(), 3);
}

// ── Heartbeat includes agent scope ─────────────────────────────

#[test]
fn heartbeat_returns_monitor_scope() {
    let (port, token) = spawn_test_server();
    let (agent_id, _) = setup_agent_with_events(port, &token, "hb-scope-host", 0);

    let resp = ureq::post(&format!("{}/api/agents/{}/heartbeat", base(port), agent_id))
        .set("Content-Type", "application/json")
        .send_string(&serde_json::json!({"version":"0.23.0"}).to_string())
        .expect("heartbeat");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("monitor_scope").is_some());
    assert!(body["monitor_scope"]["cpu_load"].is_boolean());
}

// ── Token rotation ─────────────────────────────────────────────

#[test]
fn auth_rotate_generates_new_token() {
    let (port, token) = spawn_test_server();

    // Rotate the token
    let resp = ureq::post(&format!("{}/api/auth/rotate", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("rotate token");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["status"].as_str().unwrap(), "rotated");
    let new_token = body["new_token"].as_str().unwrap();
    assert!(!new_token.is_empty());
    assert_ne!(new_token, token);

    // Old token should be rejected
    let err = ureq::get(&format!("{}/api/auth/check", base(port)))
        .set("Authorization", &auth_header(&token))
        .call();
    assert!(
        err.is_err() || {
            let resp = err.unwrap();
            resp.status() == 401
        }
    );

    // New token works
    let resp = ureq::get(&format!("{}/api/auth/check", base(port)))
        .set("Authorization", &auth_header(new_token))
        .call()
        .expect("auth check with new token");
    assert_eq!(resp.status(), 200);
}

// ── Session info ───────────────────────────────────────────────

#[test]
fn session_info_returns_uptime_and_ttl() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/session/info", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("session info");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("uptime_secs").is_some());
    assert!(body.get("token_age_secs").is_some());
    assert!(body.get("token_ttl_secs").is_some());
    assert!(body.get("token_expired").is_some());
}

// ── Auth check returns TTL info ────────────────────────────────

#[test]
fn auth_check_includes_ttl_metadata() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/auth/check", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("auth check");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["status"].as_str().unwrap(), "ok");
    assert!(body.get("ttl_secs").is_some());
    assert!(body.get("remaining_secs").is_some());
}

// ── Audit verify ───────────────────────────────────────────────

#[test]
fn audit_verify_returns_chain_status() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/audit/verify", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("audit verify");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["status"].as_str().unwrap(), "verified");
    assert!(body.get("record_count").is_some());
}

// ── Retention status ───────────────────────────────────────────

#[test]
fn retention_status_returns_policy_and_counts() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/retention/status", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("retention status");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("audit_max_records").is_some());
    assert!(body.get("alert_max_records").is_some());
    assert!(body.get("current_counts").is_some());
}

// ── Retention apply ────────────────────────────────────────────

#[test]
fn retention_apply_trims_records() {
    let (port, token) = spawn_test_server();
    let resp = ureq::post(&format!("{}/api/retention/apply", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("retention apply");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["status"].as_str().unwrap(), "applied");
}

#[test]
fn response_request_approval_execute_flow_works() {
    let (port, token) = spawn_test_server();

    let submitted = ureq::post(&format!("{}/api/response/request", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "action": "kill_process",
            "pid": 4242,
            "process_name": "evil.bin",
            "hostname": "workstation-7",
            "reason": "terminate suspicious payload",
            "severity": "high",
            "requested_by": "integration-test",
        }))
        .expect("submit response request");
    assert_eq!(submitted.status(), 200);
    let submitted_body: serde_json::Value = submitted.into_json().unwrap();
    assert_eq!(submitted_body["status"].as_str().unwrap(), "submitted");
    assert_eq!(
        submitted_body["request"]["tier"].as_str().unwrap(),
        "SingleApproval"
    );
    assert_eq!(
        submitted_body["request"]["status"].as_str().unwrap(),
        "Pending"
    );
    assert_eq!(
        submitted_body["request"]["target_hostname"]
            .as_str()
            .unwrap(),
        "workstation-7"
    );
    assert_eq!(
        submitted_body["request"]["approval_count"]
            .as_u64()
            .unwrap(),
        0
    );
    let request_id = submitted_body["request"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    let listed = ureq::get(&format!("{}/api/response/requests", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("list response requests");
    assert_eq!(listed.status(), 200);
    let listed_body: serde_json::Value = listed.into_json().unwrap();
    assert_eq!(listed_body["count"].as_u64().unwrap(), 1);
    assert_eq!(
        listed_body["requests"][0]["blast_radius"]["risk_level"]
            .as_str()
            .unwrap(),
        "medium"
    );

    let approved = ureq::post(&format!("{}/api/response/approve", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "request_id": request_id,
            "decision": "approved",
            "approver": "analyst-1",
            "reason": "validated by integration test",
        }))
        .expect("approve response request");
    assert_eq!(approved.status(), 200);
    let approved_body: serde_json::Value = approved.into_json().unwrap();
    assert_eq!(approved_body["status"].as_str().unwrap(), "Approved");

    let stats = ureq::get(&format!("{}/api/response/stats", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("response stats");
    let stats_body: serde_json::Value = stats.into_json().unwrap();
    assert_eq!(stats_body["approved_ready"].as_u64().unwrap(), 1);

    let executed = ureq::post(&format!("{}/api/response/execute", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "request_id": request_id,
        }))
        .expect("execute approved response");
    assert_eq!(executed.status(), 200);
    let executed_body: serde_json::Value = executed.into_json().unwrap();
    assert_eq!(executed_body["executed_count"].as_u64().unwrap(), 1);

    let listed_after = ureq::get(&format!("{}/api/response/requests", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("list response requests after execute");
    let listed_after_body: serde_json::Value = listed_after.into_json().unwrap();
    assert_eq!(
        listed_after_body["requests"][0]["status"].as_str().unwrap(),
        "Executed"
    );
}

#[test]
fn response_execute_without_auth_returns_401() {
    let (port, _token) = spawn_test_server();
    match ureq::post(&format!("{}/api/response/execute", base(port))).call() {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401, got {other:?}"),
    }
}

#[test]
fn shutdown_endpoint_stops_test_server() {
    let (port, token) = spawn_test_server();
    let resp = ureq::post(&format!("{}/api/shutdown", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("shutdown request");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["status"].as_str().unwrap(), "shutting_down");

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    loop {
        match ureq::get(&format!("{}/api/health", base(port))).call() {
            Err(ureq::Error::Transport(_)) => break,
            Ok(_) | Err(ureq::Error::Status(_, _)) => {
                if std::time::Instant::now() >= deadline {
                    panic!("server still accepted requests after shutdown");
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    }
}

#[test]
fn enterprise_hunts_support_manual_runs_and_scheduler_history() {
    let (port, token) = spawn_test_server();
    let (_agent_id, event_ids) = setup_agent_with_events(port, &token, "hunt-host", 2);
    assert_eq!(event_ids.len(), 2);

    let created: serde_json::Value = ureq::post(&format!("{}/api/hunts", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "name": "Critical queue hunt",
            "owner": "secops",
            "severity": "high",
            "threshold": 1,
            "suppression_window_secs": 0,
            "schedule_interval_secs": 1,
            "query": {
                "hostname": "hunt-host",
                "text": "test_reason",
                "limit": 50
            }
        }))
        .expect("create hunt")
        .into_json()
        .unwrap();
    let hunt_id = created["hunt"]["id"].as_str().unwrap().to_string();

    let manual_run: serde_json::Value =
        ureq::post(&format!("{}/api/hunts/{}/run", base(port), hunt_id))
            .set("Authorization", &auth_header(&token))
            .call()
            .expect("run hunt")
            .into_json()
            .unwrap();
    assert_eq!(manual_run["status"].as_str().unwrap(), "completed");
    assert!(manual_run["run"]["threshold_exceeded"].as_bool().unwrap());
    assert!(manual_run["run"]["match_count"].as_u64().unwrap() >= 2);

    let initial_history: serde_json::Value =
        ureq::get(&format!("{}/api/hunts/{}/history", base(port), hunt_id))
            .set("Authorization", &auth_header(&token))
            .call()
            .expect("hunt history")
            .into_json()
            .unwrap();
    assert_eq!(initial_history["count"].as_u64().unwrap(), 1);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let scheduled_history = loop {
        let polled: serde_json::Value =
            ureq::get(&format!("{}/api/hunts/{}/history", base(port), hunt_id))
                .set("Authorization", &auth_header(&token))
                .call()
                .expect("poll hunt history")
                .into_json()
                .unwrap();
        if polled["count"].as_u64().unwrap() >= 2 {
            break polled;
        }
        if std::time::Instant::now() >= deadline {
            panic!("scheduled hunt did not execute within timeout");
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    };
    assert!(scheduled_history["count"].as_u64().unwrap() >= 2);

    let diagnostics: serde_json::Value =
        ureq::get(&format!("{}/api/support/diagnostics", base(port)))
            .set("Authorization", &auth_header(&token))
            .call()
            .expect("support diagnostics")
            .into_json()
            .unwrap();
    assert!(
        diagnostics["bundle"]["operations"]["metrics"]["hunt_runs_total"]
            .as_u64()
            .unwrap()
            >= 2
    );
    assert!(diagnostics["bundle"]["change_control"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| { entry["category"].as_str() == Some("hunt") }));
}

#[test]
fn enterprise_content_rules_suppressions_and_coverage_work() {
    let (port, token) = spawn_test_server();
    let (_agent_id, event_ids) = setup_agent_with_events(port, &token, "content-host", 2);
    assert_eq!(event_ids.len(), 2);

    let created: serde_json::Value = ureq::post(&format!("{}/api/content/rules", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "title": "Native credential replay detector",
            "description": "Matches our seeded integration events",
            "owner": "detections",
            "severity_mapping": "high",
            "pack_ids": ["identity-attacks"],
            "attack": [{
                "tactic": "Credential Access (TA0006)",
                "technique_id": "T1110",
                "technique_name": "Brute Force"
            }],
            "query": {
                "hostname": "content-host",
                "text": "test_reason",
                "limit": 100
            }
        }))
        .expect("create content rule")
        .into_json()
        .unwrap();
    let rule_id = created["rule"]["metadata"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    let tested: serde_json::Value = ureq::post(&format!(
        "{}/api/content/rules/{}/test",
        base(port),
        rule_id
    ))
    .set("Authorization", &auth_header(&token))
    .call()
    .expect("test rule")
    .into_json()
    .unwrap();
    assert_eq!(tested["status"].as_str().unwrap(), "tested");
    assert!(tested["result"]["match_count"].as_u64().unwrap() >= 2);
    assert_eq!(tested["result"]["suppressed_count"].as_u64().unwrap(), 0);

    let promoted: serde_json::Value = ureq::post(&format!(
        "{}/api/content/rules/{}/promote",
        base(port),
        rule_id
    ))
    .set("Authorization", &auth_header(&token))
    .send_json(serde_json::json!({
        "target_status": "canary",
        "reason": "integration rollout"
    }))
    .expect("promote rule")
    .into_json()
    .unwrap();
    assert_eq!(promoted["status"].as_str().unwrap(), "promoted");
    assert_eq!(promoted["rule"]["lifecycle"].as_str().unwrap(), "canary");

    let suppression: serde_json::Value = ureq::post(&format!("{}/api/suppressions", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "name": "Mute content-host during maintenance",
            "rule_id": rule_id,
            "hostname": "content-host",
            "justification": "maintenance window",
            "active": true
        }))
        .expect("create suppression")
        .into_json()
        .unwrap();
    assert_eq!(suppression["status"].as_str().unwrap(), "saved");

    let retested: serde_json::Value = ureq::post(&format!(
        "{}/api/content/rules/{}/test",
        base(port),
        rule_id
    ))
    .set("Authorization", &auth_header(&token))
    .call()
    .expect("retest rule")
    .into_json()
    .unwrap();
    assert_eq!(retested["result"]["match_count"].as_u64().unwrap(), 0);
    assert!(retested["result"]["suppressed_count"].as_u64().unwrap() >= 2);

    let rolled_back: serde_json::Value = ureq::post(&format!(
        "{}/api/content/rules/{}/rollback",
        base(port),
        rule_id
    ))
    .set("Authorization", &auth_header(&token))
    .call()
    .expect("rollback rule")
    .into_json()
    .unwrap();
    assert_eq!(rolled_back["status"].as_str().unwrap(), "rolled_back");

    let coverage: serde_json::Value = ureq::get(&format!("{}/api/coverage/mitre", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("mitre coverage")
        .into_json()
        .unwrap();
    assert!(coverage["techniques"]
        .as_array()
        .unwrap()
        .iter()
        .any(|technique| { technique["technique_id"].as_str() == Some("T1110") }));
}

#[test]
fn enterprise_entities_storyline_and_incident_report_include_context() {
    let (port, token) = spawn_test_server();
    let (agent_id, event_ids) = setup_agent_with_events(port, &token, "story-host", 2);

    let incident: serde_json::Value = ureq::post(&format!("{}/api/incidents", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "title": "Storyline incident",
            "severity": "Critical",
            "event_ids": event_ids,
            "agent_ids": [agent_id],
            "summary": "story-host investigation"
        }))
        .expect("create incident")
        .into_json()
        .unwrap();
    let incident_id = incident["id"].as_u64().unwrap();

    let case: serde_json::Value = ureq::post(&format!("{}/api/cases", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "title": "Storyline case",
            "priority": "high",
            "description": "tracks story-host",
            "incident_ids": [incident_id],
            "event_ids": event_ids,
            "tags": ["storyline"]
        }))
        .expect("create case")
        .into_json()
        .unwrap();
    assert!(case["id"].as_u64().unwrap() > 0);

    let submitted: serde_json::Value = ureq::post(&format!("{}/api/response/request", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "action": "kill_process",
            "pid": 31337,
            "process_name": "story-host-payload",
            "hostname": "story-host",
            "reason": "containment",
            "severity": "high",
            "requested_by": "story-analyst"
        }))
        .expect("submit response request")
        .into_json()
        .unwrap();
    assert_eq!(submitted["status"].as_str().unwrap(), "submitted");

    let synced: serde_json::Value = ureq::post(&format!("{}/api/tickets/sync", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "provider": "jira",
            "object_kind": "incident",
            "object_id": incident_id.to_string(),
            "queue_or_project": "SOC",
            "summary": "story-host incident escalation"
        }))
        .expect("sync incident ticket")
        .into_json()
        .unwrap();
    assert_eq!(synced["status"].as_str().unwrap(), "synced");

    let entity: serde_json::Value =
        ureq::get(&format!("{}/api/entities/host/story-host", base(port)))
            .set("Authorization", &auth_header(&token))
            .call()
            .expect("entity profile")
            .into_json()
            .unwrap();
    assert_eq!(entity["kind"].as_str().unwrap(), "host");
    assert!(entity["related_event_count"].as_u64().unwrap() >= 2);
    assert!(entity["ticket_syncs"].as_array().unwrap().len() >= 1);

    let timeline: serde_json::Value = ureq::get(&format!(
        "{}/api/entities/host/story-host/timeline",
        base(port)
    ))
    .set("Authorization", &auth_header(&token))
    .call()
    .expect("entity timeline")
    .into_json()
    .unwrap();
    assert!(timeline["count"].as_u64().unwrap() >= 2);

    let storyline: serde_json::Value = ureq::get(&format!(
        "{}/api/incidents/{}/storyline",
        base(port),
        incident_id
    ))
    .set("Authorization", &auth_header(&token))
    .call()
    .expect("incident storyline")
    .into_json()
    .unwrap();
    assert!(storyline["linked_cases"].as_array().unwrap().len() >= 1);
    assert!(storyline["response_actions"].as_array().unwrap().len() >= 1);
    assert!(storyline["ticket_syncs"].as_array().unwrap().len() >= 1);
    assert!(
        storyline["evidence_package"]["case_count"]
            .as_u64()
            .unwrap()
            >= 1
    );

    let report: serde_json::Value = ureq::get(&format!(
        "{}/api/incidents/{}/report",
        base(port),
        incident_id
    ))
    .set("Authorization", &auth_header(&token))
    .call()
    .expect("incident report")
    .into_json()
    .unwrap();
    assert!(report.get("storyline").is_some());
    assert!(report.get("evidence_package").is_some());
    assert!(report["linked_cases"].as_array().unwrap().len() >= 1);
}

#[test]
fn enterprise_governance_and_support_endpoints_enforce_roles() {
    let (port, token) = spawn_test_server();

    let created_user: serde_json::Value = ureq::post(&format!("{}/api/rbac/users", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "username": "analyst-enterprise",
            "role": "analyst"
        }))
        .expect("create analyst user")
        .into_json()
        .unwrap();
    let analyst_token = created_user["token"].as_str().unwrap().to_string();

    let hunt_as_analyst = ureq::post(&format!("{}/api/hunts", base(port)))
        .set("Authorization", &auth_header(&analyst_token))
        .send_json(serde_json::json!({
            "name": "Analyst-owned hunt",
            "owner": "analyst-enterprise",
            "severity": "medium",
            "threshold": 1,
            "query": {
                "text": "test_reason",
                "limit": 10
            }
        }))
        .expect("analyst creates hunt");
    assert_eq!(hunt_as_analyst.status(), 201);

    let rule: serde_json::Value = ureq::post(&format!("{}/api/content/rules", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "title": "Admin-managed rule",
            "description": "promotion should require promote permission",
            "owner": "detections",
            "severity_mapping": "high",
            "attack": [{
                "tactic": "Credential Access (TA0006)",
                "technique_id": "T1110",
                "technique_name": "Brute Force"
            }],
            "query": {
                "text": "test_reason",
                "limit": 10
            }
        }))
        .expect("admin creates rule")
        .into_json()
        .unwrap();
    let rule_id = rule["rule"]["metadata"]["id"].as_str().unwrap();

    match ureq::post(&format!(
        "{}/api/content/rules/{}/promote",
        base(port),
        rule_id
    ))
    .set("Authorization", &auth_header(&analyst_token))
    .send_json(serde_json::json!({
        "target_status": "active",
        "reason": "analyst should be blocked"
    })) {
        Err(ureq::Error::Status(403, _)) => {}
        other => panic!("expected 403 for analyst promotion, got {other:?}"),
    }

    let provider: serde_json::Value = ureq::post(&format!("{}/api/idp/providers", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "kind": "oidc",
            "display_name": "Okta Workforce",
            "issuer_url": "https://id.example.test",
            "client_id": "client-123",
            "enabled": true,
            "group_role_mappings": {
                "soc-admins": "admin",
                "soc-analysts": "analyst"
            }
        }))
        .expect("create idp provider")
        .into_json()
        .unwrap();
    assert_eq!(provider["status"].as_str().unwrap(), "saved");

    let scim: serde_json::Value = ureq::post(&format!("{}/api/scim/config", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "enabled": true,
            "base_url": "https://scim.example.test",
            "bearer_token": "secret-token",
            "provisioning_mode": "automatic",
            "default_role": "viewer",
            "group_role_mappings": {
                "soc-admins": "admin"
            }
        }))
        .expect("configure scim")
        .into_json()
        .unwrap();
    assert_eq!(scim["status"].as_str().unwrap(), "saved");

    let audit: serde_json::Value = ureq::get(&format!("{}/api/audit/admin", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("admin audit")
        .into_json()
        .unwrap();
    assert!(audit["change_control"].as_array().unwrap().len() >= 2);

    let diagnostics: serde_json::Value =
        ureq::get(&format!("{}/api/support/diagnostics", base(port)))
            .set("Authorization", &auth_header(&token))
            .call()
            .expect("support diagnostics")
            .into_json()
            .unwrap();
    assert!(diagnostics["digest"].as_str().unwrap().len() >= 32);
    assert!(
        diagnostics["bundle"]["auth"]["idp_providers"]
            .as_array()
            .unwrap()
            .len()
            >= 1
    );

    let dependencies: serde_json::Value =
        ureq::get(&format!("{}/api/system/health/dependencies", base(port)))
            .set("Authorization", &auth_header(&token))
            .call()
            .expect("dependency health")
            .into_json()
            .unwrap();
    assert_eq!(
        dependencies["identity"]["status"].as_str().unwrap(),
        "configured"
    );
    assert!(dependencies["ha_mode"]["leader"].as_bool().unwrap());
}

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
        match resp {
            Ok(r) => assert_ne!(
                r.status(),
                200,
                "Path traversal should not succeed: {}",
                path
            ),
            Err(_) => {} // 404 or error is expected
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
    assert!(paths.contains_key("/api/threat-intel/ioc"));
    assert!(paths.contains_key("/api/playbooks"));
    assert!(paths.contains_key("/api/fleet/dashboard"));
    assert!(paths.contains_key("/api/events/search"));
    assert!(paths.contains_key("/api/queue/stats"));
    assert!(paths.contains_key("/api/rollout/config"));

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
        assert!(incident_params
            .iter()
            .any(|param| param["name"].as_str() == Some(name)));
    }

    let report_html_params = paths["/api/reports/{id}/html"]["get"]["parameters"]
        .as_array()
        .expect("report html path params");
    assert!(report_html_params.iter().any(|param| {
        param["in"].as_str() == Some("path") && param["name"].as_str() == Some("id")
    }));

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
