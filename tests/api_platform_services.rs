mod common;
use common::*;

#[test]
fn sso_login_returns_400_when_no_provider_is_ready() {
    let (port, _token) = spawn_test_server();
    match ureq::get(&format!("{}/api/auth/sso/login", base(port))).call() {
        Err(ureq::Error::Status(400, response)) => {
            let body: serde_json::Value = response.into_json().unwrap();
            assert_eq!(
                body["error"],
                "no configured SSO providers are ready for login"
            );
            assert_eq!(body["code"], "VALIDATION_ERROR");
        }
        other => panic!("expected 400 for unconfigured SSO login, got {other:?}"),
    }
}

#[test]
fn sso_callback_returns_invalid_state_before_provider_config_check() {
    let (port, _token) = spawn_test_server();
    match ureq::post(&format!("{}/api/auth/sso/callback", base(port)))
        .send_json(serde_json::json!({"code": "test-code", "state": "test-state"}))
    {
        Err(ureq::Error::Status(503, response)) => {
            let body: serde_json::Value = response.into_json().unwrap();
            assert_eq!(body["error"], "state parameter is invalid or expired");
            assert_eq!(body["code"], "SERVICE_UNAVAILABLE");
        }
        other => panic!("expected 503 for SSO callback without pending state, got {other:?}"),
    }
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

#[test]
fn fleet_install_history_returns_empty_array_by_default() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/fleet/installs", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("fleet installs history");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["total"], 0);
    assert_eq!(body["attempts"], serde_json::json!([]));
}

#[test]
fn fleet_install_history_marks_first_heartbeat_for_matching_host() {
    let (port, token) = spawn_test_server_with_seeded_remote_installs(vec![RemoteInstallRecord {
        id: "install-1".to_string(),
        transport: "ssh".to_string(),
        hostname: "edge-02".to_string(),
        address: "10.0.4.12".to_string(),
        platform: "linux".to_string(),
        manager_url: "https://manager.example.com:9090".to_string(),
        agent_id: None,
        ssh_user: "root".to_string(),
        ssh_port: 22,
        ssh_identity_file: None,
        ssh_accept_new_host_key: true,
        use_sudo: true,
        winrm_username: None,
        winrm_port: None,
        winrm_use_tls: None,
        winrm_skip_cert_check: None,
        actor: "admin".to_string(),
        status: "awaiting_heartbeat".to_string(),
        started_at: "2026-04-28T09:00:00Z".to_string(),
        completed_at: Some("2026-04-28T09:00:08Z".to_string()),
        first_heartbeat_at: None,
        token_expires_at: Some("2026-04-29T09:00:00Z".to_string()),
        exit_code: Some(0),
        output_excerpt: Some("systemctl enable --now wardex-agent".to_string()),
        error: None,
    }]);

    let agent_id = enroll_test_agent(port, &token, "edge-02");

    let resp = ureq::post(&format!("{}/api/agents/{}/heartbeat", base(port), agent_id))
        .set("Content-Type", "application/json")
        .send_string(r#"{"version":"0.15.0"}"#)
        .expect("first heartbeat");
    assert_eq!(resp.status(), 200);

    let resp = ureq::get(&format!("{}/api/fleet/installs", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("fleet installs history after heartbeat");
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.into_json().unwrap();
    let attempt = &body["attempts"][0];
    assert_eq!(attempt["status"], serde_json::json!("heartbeat_received"));
    assert_eq!(attempt["agent_id"], serde_json::json!(agent_id));
    assert!(attempt["first_heartbeat_at"].as_str().is_some());
    assert_eq!(
        attempt["completed_at"],
        serde_json::json!("2026-04-28T09:00:08Z")
    );
}

#[test]
fn fleet_install_ssh_rejects_windows_platform() {
    let (port, token) = spawn_test_server();
    let err = ureq::post(&format!("{}/api/fleet/install/ssh", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "hostname": "edge-win-01",
            "address": "10.0.4.13",
            "platform": "windows",
            "manager_url": format!("http://127.0.0.1:{port}"),
            "ssh_user": "Administrator",
            "ssh_port": 22
        }));
    match err {
        Err(ureq::Error::Status(400, response)) => {
            let body: serde_json::Value = response.into_json().unwrap();
            assert!(
                body["error"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("Linux and macOS only")
            );
        }
        other => panic!("expected 400, got {other:?}"),
    }
}

#[test]
fn fleet_install_ssh_requires_auth() {
    let (port, _token) = spawn_test_server();
    let err =
        ureq::post(&format!("{}/api/fleet/install/ssh", base(port))).send_json(serde_json::json!({
            "hostname": "edge-02",
            "address": "10.0.4.12",
            "platform": "linux",
            "manager_url": format!("http://127.0.0.1:{port}"),
            "ssh_user": "root",
            "ssh_port": 22
        }));
    match err {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401, got {other:?}"),
    }
}

#[test]
fn fleet_install_winrm_rejects_linux_platform() {
    let (port, token) = spawn_test_server();
    let err = ureq::post(&format!("{}/api/fleet/install/winrm", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "hostname": "edge-linux-01",
            "address": "10.0.4.14",
            "platform": "linux",
            "manager_url": format!("http://127.0.0.1:{port}"),
            "winrm_username": "Administrator",
            "winrm_password": "Sup3rSecret!",
            "winrm_port": 5985
        }));
    match err {
        Err(ureq::Error::Status(400, response)) => {
            let body: serde_json::Value = response.into_json().unwrap();
            assert!(
                body["error"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("Windows only")
            );
        }
        other => panic!("expected 400, got {other:?}"),
    }
}

#[test]
fn fleet_install_winrm_requires_auth() {
    let (port, _token) = spawn_test_server();
    let err = ureq::post(&format!("{}/api/fleet/install/winrm", base(port))).send_json(
        serde_json::json!({
            "hostname": "win-01",
            "address": "10.0.4.20",
            "platform": "windows",
            "manager_url": format!("http://127.0.0.1:{port}"),
            "winrm_username": "Administrator",
            "winrm_password": "Sup3rSecret!",
            "winrm_port": 5985
        }),
    );
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
    assert!(body.get("history_len").is_some());
    assert!(body["recent_history"].as_array().is_some());
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
    assert!(body["results"].as_array().is_some());
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

#[test]
fn quarantine_rejects_server_side_path_capture_without_content() {
    let (port, token) = spawn_test_server();
    let temp_file = test_state_root(port).join("server-side-capture.bin");
    std::fs::write(&temp_file, b"do-not-read-from-server").expect("write temp sample");

    let err = ureq::post(&format!("{}/api/quarantine", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "path": temp_file.display().to_string(),
            "verdict": "suspicious"
        }));
    match err {
        Err(ureq::Error::Status(400, response)) => {
            let body = response.into_string().unwrap();
            assert!(body.contains("content_base64"));
        }
        other => panic!("expected 400 for server-side path capture, got {other:?}"),
    }
}

#[test]
fn quarantine_accepts_agent_uploaded_content_with_digest() {
    use base64::Engine;
    use sha2::{Digest, Sha256};

    let (port, token) = spawn_test_server();
    let content = b"agent-uploaded-sample";
    let encoded = base64::engine::general_purpose::STANDARD.encode(content);
    let sha256 = hex::encode(Sha256::digest(content));

    let resp = ureq::post(&format!("{}/api/quarantine", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "path": "/agent/evidence/sample.bin",
            "content_base64": encoded,
            "sha256": sha256,
            "agent_id": "agent-test",
            "hostname": "host-test",
            "verdict": "malicious"
        }))
        .expect("agent-uploaded quarantine content");
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body["id"].as_str().is_some());
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

#[test]
fn threat_intel_library_returns_added_iocs() {
    let (port, token) = spawn_test_server();
    let add_resp = ureq::post(&format!("{}/api/threat-intel/ioc", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(
            serde_json::json!({"value": "evil.example", "ioc_type": "domain", "confidence": 0.91}),
        )
        .expect("add threat intel ioc");
    assert_eq!(add_resp.status(), 200);

    let resp = ureq::get(&format!("{}/api/threat-intel/library", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("threat intel library");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    let iocs = body["iocs"].as_array().expect("ioc array");
    assert!(body["count"].as_u64().unwrap_or_default() >= 1);
    assert!(iocs.iter().any(|ioc| ioc["value"] == "evil.example"));
    assert!(
        body.get("feeds")
            .and_then(|value| value.as_array())
            .is_some()
    );
    assert!(
        body.get("recent_matches")
            .and_then(|value| value.as_array())
            .is_some()
    );
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
    assert!(body["devices"].as_array().is_some());
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
    assert_eq!(body["event_type"], "cpu_spike");
    assert!(body.get("ticks_simulated").is_some());
    assert!(body.get("seeded_device").is_some());
    assert!(body.get("final_state").is_some());
    assert!(body["alerts_generated"].as_array().is_some());
    assert!(body["state_transitions"].as_array().is_some());
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
        .send_json(serde_json::json!({
            "traces_per_strategy": 4,
            "trace_length": 60,
            "evasion_threshold": 1.25
        }))
        .expect("harness run");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body.get("evasion_rate").is_some());
    assert!(body.get("coverage_ratio").is_some());
    assert!(body.get("total_count").is_some());
    assert_eq!(body["config"]["traces_per_strategy"], 4);
    assert_eq!(body["config"]["trace_length"], 60);
    assert_eq!(body["config"]["evasion_threshold"], 1.25);
    assert!(body["score_buckets"].as_array().is_some());
    assert!(body["strategies"].as_array().is_some());
    assert!(body.get("transition_count").is_some());
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
    assert!(body["attacker_profiles"].as_array().is_some());
    assert!(body["decoys"].as_array().is_some());
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
    let config_path = test_state_path(port, "wardex.toml");

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
    let config_path = test_state_path(port, "wardex.toml");

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
