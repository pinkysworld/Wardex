mod common;
use common::*;

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
    assert!(body["deployment"]["allow_downgrade"].as_bool().unwrap());
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
    assert!(!body["override"].as_bool().unwrap());

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
    assert!(body["override"].as_bool().unwrap());
    assert!(!body["scope"]["network_activity"].as_bool().unwrap());
    assert!(!body["scope"]["battery_state"].as_bool().unwrap());

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
    assert!(body["auto_progress"].as_bool().unwrap());
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
    let approver_token = create_rbac_user_token(port, &token, "response-approver", "admin");

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
        .set("Authorization", &auth_header(&approver_token))
        .send_json(serde_json::json!({
            "request_id": request_id,
            "decision": "approved",
            "approver": "response-approver",
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
    // The target PID/host in this test does not exist on the test node, so the
    // node-local enforcer reports honest failure. The end-to-end approve →
    // execute flow is still proven; "Failed" is the truthful terminal state.
    assert_eq!(
        listed_after_body["requests"][0]["status"].as_str().unwrap(),
        "Failed"
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
    assert!(
        diagnostics["bundle"]["change_control"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| { entry["category"].as_str() == Some("hunt") })
    );
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

    let feedback = ureq::post(&format!("{}/api/detection/feedback", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "rule_id": rule_id,
                "analyst": "detections",
                "verdict": "true_positive",
                "notes": "Shift review confirmed the replay delta is expected.",
            })
            .to_string(),
        )
        .expect("record rule feedback");
    assert_eq!(feedback.status(), 200);

    let content_rules: serde_json::Value = ureq::get(&format!("{}/api/content/rules", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("content rules")
        .into_json()
        .unwrap();
    let rule_view = content_rules["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"].as_str() == Some(rule_id.as_str()))
        .expect("native rule present");
    assert_eq!(
        rule_view["review_history"]["latest_replay"]["suppressed_count"]
            .as_u64()
            .unwrap(),
        retested["result"]["suppressed_count"].as_u64().unwrap()
    );
    assert_eq!(
        rule_view["review_history"]["analyst_feedback"]["latest_verdict"]
            .as_str()
            .unwrap(),
        "valid"
    );
    assert_eq!(
        rule_view["review_history"]["analyst_feedback"]["total"]
            .as_u64()
            .unwrap(),
        1
    );

    let coverage: serde_json::Value = ureq::get(&format!("{}/api/coverage/mitre", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("mitre coverage")
        .into_json()
        .unwrap();
    assert!(
        coverage["techniques"]
            .as_array()
            .unwrap()
            .iter()
            .any(|technique| { technique["technique_id"].as_str() == Some("T1110") })
    );
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
    assert!(!entity["ticket_syncs"].as_array().unwrap().is_empty());

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
    assert!(!storyline["linked_cases"].as_array().unwrap().is_empty());
    assert!(!storyline["response_actions"].as_array().unwrap().is_empty());
    assert!(!storyline["ticket_syncs"].as_array().unwrap().is_empty());
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
    assert!(!report["linked_cases"].as_array().unwrap().is_empty());
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
            "client_secret": "super-secret",
            "redirect_uri": format!("{}/api/auth/sso/callback", base(port)),
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
        !diagnostics["bundle"]["auth"]["idp_providers"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let readiness: serde_json::Value =
        ureq::get(&format!("{}/api/support/readiness-evidence", base(port)))
            .set("Authorization", &auth_header(&token))
            .call()
            .expect("support readiness evidence")
            .into_json()
            .unwrap();
    assert_eq!(
        readiness["evidence"]["control_plane"]["ha_mode"]
            .as_str()
            .unwrap(),
        "active_passive_reference"
    );
    assert_eq!(
        readiness["evidence"]["backup"]["observed_backups"]
            .as_u64()
            .unwrap(),
        0
    );
    assert!(
        !readiness["evidence"]["control_plane"]["restore_ready"]
            .as_bool()
            .unwrap()
    );
    assert_eq!(
        readiness["evidence"]["control_plane"]["orchestration_scope"]
            .as_str()
            .unwrap(),
        "standalone_reference"
    );
    assert_eq!(
        readiness["evidence"]["control_plane"]["failover_drill"]["status"]
            .as_str()
            .unwrap(),
        "not_run"
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
    assert_eq!(
        dependencies["ha_mode"]["mode"].as_str().unwrap(),
        "active_passive_reference"
    );
    assert!(dependencies["ha_mode"]["leader"].as_bool().unwrap());
    assert_eq!(
        dependencies["ha_mode"]["checkpoint_count"]
            .as_u64()
            .unwrap(),
        0
    );
    assert!(!dependencies["ha_mode"]["restore_ready"].as_bool().unwrap());
    assert_eq!(
        dependencies["ha_mode"]["failover_drill"]["status"]
            .as_str()
            .unwrap(),
        "not_run"
    );
}
