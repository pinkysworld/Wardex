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

// ── GET /api/export/tla ────────────────────────────────────────

#[test]
fn export_tla_returns_valid_module() {
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/export/tla", base(port)))
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
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/export/alloy", base(port)))
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
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/export/witnesses", base(port)))
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
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/research-tracks", base(port)))
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
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/attestation/status", base(port)))
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
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/fleet/status", base(port)))
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
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/enforcement/status", base(port)))
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
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/threat-intel/status", base(port)))
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
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/digital-twin/status", base(port)))
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
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/compliance/status", base(port)))
        .call()
        .expect("compliance status");
    assert_eq!(resp.status(), 200);
    let _body: serde_json::Value = resp.into_json().unwrap();
}

// ── GET /api/energy/status ─────────────────────────────────────

#[test]
fn energy_status_returns_budget_info() {
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/energy/status", base(port)))
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
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/tenants/count", base(port)))
        .call()
        .expect("tenants count");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("tenant_count").is_some());
}

// ── GET /api/platform ──────────────────────────────────────────

#[test]
fn platform_returns_capabilities() {
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/platform", base(port)))
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
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/correlation", base(port)))
        .call()
        .expect("correlation");
    assert_eq!(resp.status(), 200);
    let _body: serde_json::Value = resp.into_json().unwrap();
}

// ── GET /api/side-channel/status ───────────────────────────────

#[test]
fn side_channel_status_returns_report() {
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/side-channel/status", base(port)))
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
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/quantum/key-status", base(port)))
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
    let err = ureq::post(&format!("{}/api/quantum/rotate", base(port)))
        .send_string("");
    match err {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401, got {other:?}"),
    }
}

// ── GET /api/privacy/budget ────────────────────────────────────

#[test]
fn privacy_budget_returns_remaining() {
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/privacy/budget", base(port)))
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
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/fingerprint/status", base(port)))
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
    let err = ureq::post(&format!("{}/api/harness/run", base(port)))
        .send_string("");
    match err {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401, got {other:?}"),
    }
}

// ── GET /api/monitor/status ────────────────────────────────────

#[test]
fn monitor_status_returns_properties() {
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/monitor/status", base(port)))
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
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/monitor/violations", base(port)))
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
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/deception/status", base(port)))
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
    let err = ureq::post(&format!("{}/api/policy/compose", base(port)))
        .send_json(serde_json::json!({
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
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/drift/status", base(port)))
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
    let err = ureq::post(&format!("{}/api/drift/reset", base(port)))
        .send_string("");
    match err {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401, got {other:?}"),
    }
}

// ── GET /api/causal/graph ──────────────────────────────────────

#[test]
fn causal_graph_returns_counts() {
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/causal/graph", base(port)))
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
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/patches", base(port)))
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
    let err = ureq::post(&format!("{}/api/offload/decide", base(port)))
        .send_string("");
    match err {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401, got {other:?}"),
    }
}

// ── GET /api/swarm/posture ─────────────────────────────────────

#[test]
fn swarm_posture_returns_posture() {
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/swarm/posture", base(port)))
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
    let err = ureq::post(&format!("{}/api/energy/harvest", base(port)))
        .send_string("");
    match err {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401, got {other:?}"),
    }
}

// ── TLS Status ──────────────────────────────────────────────────

#[test]
fn tls_status_returns_plain_mode() {
    let (port, _token) = spawn_test_server();
    let body: serde_json::Value = ureq::get(&format!("{}/api/tls/status", base(port)))
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
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/mesh/health", base(port)))
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
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/alerts", base(port)))
        .call()
        .expect("alerts request");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    let arr = body.as_array().unwrap();
    assert!(arr.is_empty());
}

// ── GET /api/alerts/count ──────────────────────────────────────

#[test]
fn alerts_count_returns_zero_initially() {
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/alerts/count", base(port)))
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
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/endpoints", base(port)))
        .call()
        .expect("endpoints request");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    let arr = body.as_array().unwrap();
    assert!(arr.len() >= 10);
}

// ── POST /api/config/save — auth required ──────────────────────

#[test]
fn config_save_without_auth_returns_401() {
    let (port, _token) = spawn_test_server();
    let resp = ureq::post(&format!("{}/api/config/save", base(port)))
        .send_string("");
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
        .call()
        .expect("list events");
    assert_eq!(resp.status(), 200);
    let events: serde_json::Value = resp.into_json().unwrap();
    assert!(!events.as_array().unwrap().is_empty());
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
}

// ── Update check ──────────────────────────────────────────────

#[test]
fn update_check_no_updates_available() {
    let (port, _token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/agents/update?current_version=0.15.0&platform=linux", base(port)))
        .call()
        .expect("update check");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["update_available"].as_bool().unwrap(), false);
}
