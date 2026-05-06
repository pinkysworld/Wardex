use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use wardex::agent_client::AgentClient;
use wardex::auth::SessionStore;
use wardex::collector::AlertRecord;
use wardex::config::Config;
use wardex::fleet_install::RemoteInstallRecord;
use wardex::server::{
    spawn_test_server, spawn_test_server_with_live_rollback_enabled,
    spawn_test_server_with_live_rollback_execution_enabled, spawn_test_server_with_seeded_alerts,
    spawn_test_server_with_seeded_remote_installs,
};
use wardex::telemetry::TelemetrySample;

static COMMAND_PATH_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

fn base(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

fn auth_header(token: &str) -> String {
    format!("Bearer {token}")
}

const LOCAL_CONSOLE_AGENT_ID: &str = "local-console";

fn find_agent_by_id<'a>(agents: &'a serde_json::Value, agent_id: &str) -> &'a serde_json::Value {
    agents
        .as_array()
        .and_then(|entries| {
            entries
                .iter()
                .find(|agent| agent["id"] == serde_json::Value::String(agent_id.to_string()))
        })
        .unwrap_or_else(|| panic!("missing agent {agent_id}"))
}

fn test_state_root(port: u16) -> PathBuf {
    PathBuf::from(format!("/tmp/wardex_test_{port}"))
}

fn test_state_path(port: u16, file_name: &str) -> String {
    test_state_root(port).join(file_name).display().to_string()
}

fn create_approved_remediation_review(
    port: u16,
    token: &str,
    asset_id: &str,
    evidence: serde_json::Value,
) -> String {
    let payload = serde_json::json!({
        "title": "Review live-rollback gating",
        "asset_id": asset_id,
        "change_type": "malware_containment",
        "source": "malware-verdict",
        "summary": "Create an approved review for live rollback coverage.",
        "risk": "high",
        "approval_status": "pending_review",
        "recovery_status": "not_started",
        "evidence": evidence,
    });
    let created: serde_json::Value =
        ureq::post(&format!("{}/api/remediation/change-reviews", base(port)))
            .set("Authorization", &auth_header(token))
            .set("Content-Type", "application/json")
            .send_string(&payload.to_string())
            .expect("record remediation review")
            .into_json()
            .unwrap();
    let review_id = created["review"]["id"]
        .as_str()
        .expect("review id")
        .to_string();

    for approver in ["primary-reviewer", "secondary-reviewer"] {
        ureq::post(&format!(
            "{}/api/remediation/change-reviews/{}/approval",
            base(port),
            review_id
        ))
        .set("Authorization", &auth_header(token))
        .send_json(serde_json::json!({
            "approver": approver,
            "decision": "approve",
            "comment": "ok"
        }))
        .expect("signed approval");
    }

    review_id
}

fn current_live_rollback_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "linux"
    }
}

fn current_restart_service_command() -> &'static str {
    if cfg!(target_os = "macos") {
        "launchctl"
    } else if cfg!(target_os = "windows") {
        "sc"
    } else {
        "systemctl"
    }
}

fn current_block_ip_command() -> &'static str {
    if cfg!(target_os = "macos") {
        "pfctl"
    } else if cfg!(target_os = "windows") {
        "netsh"
    } else {
        "iptables"
    }
}

fn nonmatching_live_rollback_platform() -> &'static str {
    if cfg!(target_os = "windows") {
        "linux"
    } else {
        "windows"
    }
}

fn disable_account_command_for_platform(platform: &str) -> &'static str {
    match platform {
        "macos" => "dscl",
        "windows" => "net",
        _ => "usermod",
    }
}

fn flush_dns_command_for_platform(platform: &str) -> &'static str {
    match platform {
        "macos" => "dscacheutil",
        "windows" => "ipconfig",
        _ => "systemd-resolve",
    }
}

fn current_disable_account_command() -> &'static str {
    if cfg!(target_os = "macos") {
        "dscl"
    } else if cfg!(target_os = "windows") {
        "net"
    } else {
        "usermod"
    }
}

fn current_flush_dns_command() -> &'static str {
    if cfg!(target_os = "macos") {
        "dscacheutil"
    } else if cfg!(target_os = "windows") {
        "ipconfig"
    } else {
        "systemd-resolve"
    }
}

fn with_stubbed_commands_path<T>(commands: &[(&str, &str)], test: impl FnOnce() -> T) -> T {
    let _guard = COMMAND_PATH_MUTEX
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("command path mutex");
    let dir = tempfile::tempdir().expect("tempdir");

    for (command_name, script) in commands {
        let command_path = if cfg!(windows) {
            dir.path().join(format!("{command_name}.cmd"))
        } else {
            dir.path().join(command_name)
        };
        std::fs::write(&command_path, script).expect("write command stub");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut permissions = std::fs::metadata(&command_path)
                .expect("command stub metadata")
                .permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&command_path, permissions)
                .expect("set command stub permissions");
        }
    }

    wardex::remediation::set_execution_command_override_dir(Some(dir.path().to_path_buf()));
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(test));
    wardex::remediation::set_execution_command_override_dir(None);
    match result {
        Ok(value) => value,
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

fn with_stubbed_command_path<T>(command_name: &str, script: &str, test: impl FnOnce() -> T) -> T {
    with_stubbed_commands_path(&[(command_name, script)], test)
}

fn enroll_test_agent(port: u16, token: &str, hostname: &str) -> String {
    let resp = ureq::post(&format!("{}/api/agents/token", base(port)))
        .set("Authorization", &auth_header(token))
        .set("Content-Type", "application/json")
        .send_string(r#"{"max_uses":1}"#)
        .expect("create enrollment token");
    let tok: serde_json::Value = resp.into_json().unwrap();
    let enrollment_token = tok["token"].as_str().unwrap();

    let body = serde_json::json!({
        "enrollment_token": enrollment_token,
        "hostname": hostname,
        "platform": "linux",
        "version": "0.15.0",
    });
    let resp = ureq::post(&format!("{}/api/agents/enroll", base(port)))
        .set("Content-Type", "application/json")
        .send_string(&body.to_string())
        .expect("enroll agent");
    let enroll: serde_json::Value = resp.into_json().unwrap();
    enroll["agent_id"].as_str().unwrap().to_string()
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

#[test]
fn command_summary_returns_lane_health() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/command/summary", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("command summary request");
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(body["generated_at"].as_str().is_some());
    assert!(body["metrics"]["open_incidents"].as_u64().is_some());
    assert!(
        body["metrics"]["pending_remediation_reviews"]
            .as_u64()
            .is_some()
    );
    assert!(body["metrics"]["connector_issues"].as_u64().is_some());
    assert!(
        body["shift_board"]["active_owner"]["name"]
            .as_str()
            .is_some()
    );
    assert!(
        body["shift_board"]["sla_age_buckets"]["breached"]
            .as_u64()
            .is_some()
    );
    assert!(
        body["shift_board"]["lanes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|lane| lane["id"] == "cases" && lane["next_action"].as_str().is_some())
    );
    assert_eq!(
        body["lanes"]["release"]["current_version"]
            .as_str()
            .unwrap(),
        env!("CARGO_PKG_VERSION")
    );
    let planned = body["lanes"]["connectors"]["planned"].as_array().unwrap();
    assert!(planned.iter().any(|entry| entry == "github_audit"));
    assert!(planned.iter().any(|entry| entry == "crowdstrike_falcon"));
    assert!(planned.iter().any(|entry| entry == "generic_syslog"));
    assert!(body["lanes"]["rule_tuning"]["review_calendar"]["items"].is_array());
}

#[test]
fn command_lane_endpoint_returns_per_lane_slice() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/command/lanes/release", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("command lane release request");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["lane"].as_str().unwrap(), "release");
    assert!(body["generated_at"].as_str().is_some());
    assert_eq!(
        body["payload"]["current_version"].as_str().unwrap(),
        env!("CARGO_PKG_VERSION")
    );
    assert!(body["payload"]["status"].as_str().is_some());

    // Unknown lane returns 404.
    let resp = ureq::get(&format!("{}/api/command/lanes/bogus", base(port)))
        .set("Authorization", &auth_header(&token))
        .call();
    let status = match resp {
        Ok(r) => r.status(),
        Err(ureq::Error::Status(code, _)) => code,
        Err(other) => panic!("unexpected error: {other:?}"),
    };
    assert_eq!(status, 404);
}

#[test]
fn websocket_stats_exposes_transport_capability() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!("{}/api/ws/stats", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("websocket stats request");
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["connected_clients"].as_u64().unwrap(), 0);
    assert_eq!(body["subscribers"].as_u64().unwrap(), 0);
    assert_eq!(body["native_websocket_supported"].as_bool(), Some(false));
}

#[test]
fn planned_connector_config_and_validation_persist() {
    let (port, token) = spawn_test_server();
    let config = serde_json::json!({
        "enabled": true,
        "organization": "wardex-labs",
        "token_ref": "secret://github/audit-token",
        "webhook_secret_ref": "secret://github/webhook-secret",
        "poll_interval_secs": 300,
        "repositories": ["wardex"],
    });
    let saved = ureq::post(&format!("{}/api/collectors/github/config", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(&config.to_string())
        .expect("save github collector setup");
    assert_eq!(saved.status(), 200);
    let saved_body: serde_json::Value = saved.into_json().unwrap();
    assert_eq!(saved_body["provider"].as_str().unwrap(), "github_audit");
    assert_eq!(
        saved_body["validation"]["status"].as_str().unwrap(),
        "ready"
    );
    assert_eq!(
        saved_body["config"]["token_ref"].as_str().unwrap(),
        "********"
    );
    assert!(saved_body["config"]["has_token_ref"].as_bool().unwrap());

    let loaded = ureq::get(&format!("{}/api/collectors/github", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("load github collector setup");
    let loaded_body: serde_json::Value = loaded.into_json().unwrap();
    assert_eq!(
        loaded_body["validation"]["status"].as_str().unwrap(),
        "ready"
    );
    assert_eq!(
        loaded_body["config"]["organization"].as_str().unwrap(),
        "wardex-labs"
    );

    let validated = ureq::post(&format!("{}/api/collectors/github/validate", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string("{}")
        .expect("validate github collector setup");
    let validation_body: serde_json::Value = validated.into_json().unwrap();
    assert_eq!(
        validation_body["provider"].as_str().unwrap(),
        "github_audit"
    );
    assert!(validation_body["success"].as_bool().unwrap());
    assert!(validation_body["event_count"].as_u64().unwrap() > 0);
    assert!(
        validation_body["reliability"]["checkpoint_id"]
            .as_str()
            .is_some()
    );

    let status = ureq::get(&format!("{}/api/collectors/status", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("collector status request");
    let status_body: serde_json::Value = status.into_json().unwrap();
    let collectors = status_body["collectors"].as_array().unwrap();
    assert!(collectors.iter().any(|collector| {
        collector["provider"] == "github_audit"
            && collector["label"] == "GitHub Audit Log"
            && collector["freshness"] == "fresh"
    }));
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

#[test]
fn onboarding_readiness_and_manager_queue_digest_return_structured_payloads() {
    let (port, token) = spawn_test_server();
    let auth = auth_header(&token);

    let readiness = ureq::get(&format!("{}/api/onboarding/readiness", base(port)))
        .set("Authorization", &auth)
        .call()
        .expect("onboarding readiness");
    assert_eq!(readiness.status(), 200);
    let readiness_body: serde_json::Value = readiness.into_json().unwrap();
    assert!(readiness_body["total"].as_u64().unwrap() >= 7);
    assert!(readiness_body["checks"].as_array().unwrap().len() >= 7);

    let digest = ureq::get(&format!("{}/api/manager/queue-digest", base(port)))
        .set("Authorization", &auth)
        .call()
        .expect("manager queue digest");
    assert_eq!(digest.status(), 200);
    let digest_body: serde_json::Value = digest.into_json().unwrap();
    assert!(digest_body.get("queue").is_some());
    assert!(digest_body.get("changes_since_last_shift").is_some());
}

#[test]
fn detection_feedback_roundtrip_and_explainability_include_feedback() {
    let (port, token) = spawn_test_server();
    let auth = auth_header(&token);
    let agent_id = enroll_test_agent(port, &token, "feedback-agent");

    let batch = serde_json::json!({
        "agent_id": agent_id,
        "events": [{
            "timestamp": "2026-04-22T10:00:00Z",
            "hostname": "feedback-agent",
            "platform": "linux",
            "score": 8.4,
            "confidence": 0.93,
            "level": "Critical",
            "action": "credential_access",
            "reasons": ["credential_dump_attempt user=alice", "lsass_access dst=10.0.0.5 c2_beacon"],
            "sample": {
                "timestamp_ms": 0, "cpu_load_pct": 40.0, "memory_load_pct": 50.0,
                "temperature_c": 60.0, "network_kbps": 100.0, "auth_failures": 3,
                "battery_pct": 80.0, "integrity_drift": 0.1,
                "process_count": 50, "disk_pressure_pct": 10.0
            },
            "enforced": false
        }]
    });
    ureq::post(&format!("{}/api/events", base(port)))
        .set("Content-Type", "application/json")
        .send_string(&batch.to_string())
        .expect("ingest event");

    let feedback = ureq::post(&format!("{}/api/detection/feedback", base(port)))
        .set("Authorization", &auth)
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "event_id": 1,
                "rule_id": "builtin:sigma:credential-access",
                "analyst": "alice",
                "verdict": "true_positive",
                "reason_pattern": "credential_dump_attempt, lsass_access",
                "notes": "validated with host context",
                "evidence": [{
                    "kind": "reason",
                    "label": "Rule",
                    "value": "credential_dump_attempt",
                    "confidence": 0.93,
                    "source": "detector"
                }]
            })
            .to_string(),
        )
        .expect("record feedback");
    assert_eq!(feedback.status(), 200);

    let listed = ureq::get(&format!("{}/api/detection/feedback?event_id=1", base(port)))
        .set("Authorization", &auth)
        .call()
        .expect("list feedback");
    let listed_body: serde_json::Value = listed.into_json().unwrap();
    assert_eq!(listed_body["summary"]["total"].as_u64().unwrap(), 1);
    assert_eq!(
        listed_body["items"][0]["analyst"].as_str().unwrap(),
        "alice"
    );

    let by_rule = ureq::get(&format!(
        "{}/api/detection/feedback?rule_id={}",
        base(port),
        "builtin%3Asigma%3Acredential-access"
    ))
    .set("Authorization", &auth)
    .call()
    .expect("list feedback by rule");
    let by_rule_body: serde_json::Value = by_rule.into_json().unwrap();
    assert_eq!(by_rule_body["summary"]["total"].as_u64().unwrap(), 1);
    assert_eq!(
        by_rule_body["items"][0]["rule_id"].as_str().unwrap(),
        "builtin:sigma:credential-access"
    );

    let explain = ureq::get(&format!("{}/api/detection/explain?event_id=1", base(port)))
        .set("Authorization", &auth)
        .call()
        .expect("detection explain");
    assert_eq!(explain.status(), 200);
    let explain_body: serde_json::Value = explain.into_json().unwrap();
    assert!(!explain_body["why_fired"].as_array().unwrap().is_empty());
    assert_eq!(explain_body["feedback"].as_array().unwrap().len(), 1);
    let entity_scores = explain_body["entity_scores"].as_array().unwrap();
    assert!(
        entity_scores
            .iter()
            .any(|score| score["entity_kind"] == "host")
    );
    assert!(
        entity_scores
            .iter()
            .any(|score| score["entity_kind"] == "user")
    );
    assert!(
        entity_scores
            .iter()
            .any(|score| score["entity_kind"] == "network_destination")
    );
    let host_score = entity_scores
        .iter()
        .find(|score| score["entity_kind"] == "host")
        .unwrap();
    assert!(host_score["score_components"].as_array().unwrap().len() >= 2);
    assert!(
        !host_score["sequence_signals"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(!host_score["graph_context"].as_array().unwrap().is_empty());
    assert!(
        !host_score["recommended_pivots"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn correlation_campaigns_cluster_stored_events_into_graph_view() {
    let (port, token) = spawn_test_server();
    let auth = auth_header(&token);
    let agent_a = enroll_test_agent(port, &token, "campaign-a");
    let agent_b = enroll_test_agent(port, &token, "campaign-b");

    for (agent_id, hostname, timestamp) in [
        (&agent_a, "campaign-a", "2026-04-22T10:00:00Z"),
        (&agent_b, "campaign-b", "2026-04-22T10:02:00Z"),
    ] {
        let batch = serde_json::json!({
            "agent_id": agent_id,
            "events": [{
                "timestamp": timestamp,
                "hostname": hostname,
                "platform": "linux",
                "score": 8.2,
                "confidence": 0.91,
                "level": "Critical",
                "action": "remote_execution",
                "reasons": ["credential_access", "lateral_movement", "c2_beacon"],
                "sample": {
                    "timestamp_ms": 0, "cpu_load_pct": 40.0, "memory_load_pct": 50.0,
                    "temperature_c": 60.0, "network_kbps": 100.0, "auth_failures": 3,
                    "battery_pct": 80.0, "integrity_drift": 0.1,
                    "process_count": 50, "disk_pressure_pct": 10.0
                },
                "enforced": false
            }]
        });
        ureq::post(&format!("{}/api/events", base(port)))
            .set("Content-Type", "application/json")
            .send_string(&batch.to_string())
            .expect("ingest campaign event");
    }

    let response = ureq::get(&format!("{}/api/correlation/campaigns", base(port)))
        .set("Authorization", &auth)
        .call()
        .expect("campaign correlation view");
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.into_json().unwrap();
    assert_eq!(body["summary"]["campaign_count"].as_u64().unwrap(), 1);
    assert!(
        body["campaigns"].as_array().unwrap()[0]["hosts"]
            .as_array()
            .unwrap()
            .len()
            >= 2
    );
    assert!(body["graph"]["nodes"].as_array().unwrap().len() >= 2);
    assert!(!body["graph"]["edges"].as_array().unwrap().is_empty());
    assert!(
        body["sequence_summaries"].as_array().unwrap()[0]["sequence_signals"]
            .as_array()
            .unwrap()
            .len()
            >= 2
    );
}

#[test]
fn detection_replay_corpus_exposes_acceptance_gate() {
    let (port, token) = spawn_test_server();
    let auth = auth_header(&token);
    let response = ureq::get(&format!("{}/api/detection/replay-corpus", base(port)))
        .set("Authorization", &auth)
        .call()
        .expect("replay corpus gate");
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.into_json().unwrap();
    assert!(body["summary"]["total_samples"].as_u64().unwrap() >= 6);
    assert!(body["summary"]["precision"].as_f64().unwrap() >= 0.0);
    assert!(
        body["acceptance_targets"]["precision_min"]
            .as_f64()
            .unwrap()
            > 0.0
    );
    let categories = body["categories"].as_array().unwrap();
    assert!(categories.iter().any(|item| item["id"] == "benign_admin"));
    assert!(
        categories
            .iter()
            .any(|item| item["id"] == "lateral_movement")
    );
    assert!(body["platform_deltas"].as_array().unwrap().len() >= 2);
    assert!(body["signal_type_deltas"].as_array().unwrap().len() >= 3);
    assert!(categories.iter().any(|item| item["platform"] == "linux"));
    assert!(
        categories
            .iter()
            .any(|item| item["signal_type"] == "identity")
    );
}

#[test]
fn detection_replay_corpus_accepts_custom_validation_pack() {
    let (port, token) = spawn_test_server();
    let auth = auth_header(&token);
    let response = ureq::post(&format!("{}/api/detection/replay-corpus", base(port)))
        .set("Authorization", &auth)
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "name": "customer-pack-alpha",
                "threshold": 2.0,
                "samples": [
                    {
                        "id": "admin-maintenance",
                        "label": "Admin maintenance window",
                        "expected": "benign",
                        "platform": "linux",
                        "signal_type": "admin_activity",
                        "sample": {
                            "timestamp_ms": 1,
                            "cpu_load_pct": 25.0,
                            "memory_load_pct": 35.0,
                            "temperature_c": 40.0,
                            "network_kbps": 750.0,
                            "auth_failures": 0,
                            "battery_pct": 90.0,
                            "integrity_drift": 0.01,
                            "process_count": 50,
                            "disk_pressure_pct": 12.0
                        }
                    },
                    {
                        "id": "credential-lateral-chain",
                        "label": "Credential theft and lateral movement",
                        "expected": "malicious",
                        "platform": "windows",
                        "signal_type": "identity",
                        "sample": {
                            "timestamp_ms": 2,
                            "cpu_load_pct": 86.0,
                            "memory_load_pct": 80.0,
                            "temperature_c": 60.0,
                            "network_kbps": 8600.0,
                            "auth_failures": 20,
                            "battery_pct": 70.0,
                            "integrity_drift": 0.32,
                            "process_count": 180,
                            "disk_pressure_pct": 80.0
                        }
                    }
                ]
            })
            .to_string(),
        )
        .expect("custom replay corpus gate");
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.into_json().unwrap();
    assert_eq!(body["corpus_kind"], serde_json::json!("custom"));
    assert_eq!(body["pack_name"], serde_json::json!("customer-pack-alpha"));
    assert_eq!(body["summary"]["total_samples"].as_u64().unwrap(), 2);
    assert!(
        body["categories"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["id"] == "credential-lateral-chain")
    );
    assert!(
        body["platform_deltas"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["group"] == "windows")
    );
    assert!(
        body["signal_type_deltas"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["group"] == "identity")
    );
}

#[test]
fn detection_replay_corpus_accepts_retained_event_source() {
    let (port, token) = spawn_test_server();
    let auth = auth_header(&token);
    let agent_id = enroll_test_agent(port, &token, "retained-replay-agent");

    let batch = serde_json::json!({
        "agent_id": agent_id,
        "events": [
            {
                "timestamp": "2026-04-23T09:00:00Z",
                "hostname": "retained-replay-agent",
                "platform": "linux",
                "score": 0.8,
                "confidence": 0.82,
                "level": "Info",
                "action": "admin_maintenance",
                "reasons": ["approved_admin_script"],
                "sample": {
                    "timestamp_ms": 1,
                    "cpu_load_pct": 28.0,
                    "memory_load_pct": 35.0,
                    "temperature_c": 40.0,
                    "network_kbps": 650.0,
                    "auth_failures": 0,
                    "battery_pct": 88.0,
                    "integrity_drift": 0.01,
                    "process_count": 55,
                    "disk_pressure_pct": 10.0
                },
                "enforced": false
            },
            {
                "timestamp": "2026-04-23T09:05:00Z",
                "hostname": "retained-replay-agent",
                "platform": "linux",
                "score": 8.9,
                "confidence": 0.95,
                "level": "Critical",
                "action": "credential_access",
                "reasons": ["credential_dump_attempt", "lateral_movement"],
                "sample": {
                    "timestamp_ms": 2,
                    "cpu_load_pct": 91.0,
                    "memory_load_pct": 82.0,
                    "temperature_c": 65.0,
                    "network_kbps": 9600.0,
                    "auth_failures": 25,
                    "battery_pct": 70.0,
                    "integrity_drift": 0.38,
                    "process_count": 210,
                    "disk_pressure_pct": 82.0
                },
                "enforced": false
            }
        ]
    });
    ureq::post(&format!("{}/api/events", base(port)))
        .set("Content-Type", "application/json")
        .send_string(&batch.to_string())
        .expect("ingest retained replay events");

    let response = ureq::post(&format!("{}/api/detection/replay-corpus", base(port)))
        .set("Authorization", &auth)
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "source": "retained_events",
                "name": "retained-last-alerts",
                "threshold": 2.0,
                "limit": 10
            })
            .to_string(),
        )
        .expect("retained-event replay corpus gate");
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.into_json().unwrap();
    assert_eq!(body["corpus_kind"], serde_json::json!("retained_events"));
    assert_eq!(body["pack_name"], serde_json::json!("retained-last-alerts"));
    assert_eq!(body["summary"]["total_samples"].as_u64().unwrap(), 2);
    assert!(
        body["categories"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["id"] == "event-1")
    );
    assert!(
        body["platform_deltas"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["group"] == "linux")
    );
    assert!(
        body["signal_type_deltas"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["group"] == "identity")
    );
}

#[test]
fn deep_scan_v2_and_threat_intel_v2_expose_profiles_and_sightings() {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    let (port, token) = spawn_test_server();
    let auth = auth_header(&token);
    let data = b"powershell Invoke-WebRequest https://malicious.example/payload";
    let sha256 = {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    };

    ureq::post(&format!("{}/api/threat-intel/ioc", base(port)))
        .set("Authorization", &auth)
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "ioc_type": "hash",
                "value": sha256,
                "confidence": 0.91
            })
            .to_string(),
        )
        .expect("add threat intel ioc");

    let scan = ureq::post(&format!("{}/api/scan/buffer/v2", base(port)))
        .set("Authorization", &auth)
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "filename": "suspicious.ps1",
                "data": base64::engine::general_purpose::STANDARD.encode(data),
                "behavior": {
                    "suspicious_process_tree": true,
                    "defense_evasion": false,
                    "persistence_installed": true,
                    "c2_beaconing_detected": true,
                    "credential_access": false
                },
                "allowlist": {
                    "trusted_publishers": ["microsoft"],
                    "internal_tools": ["internal-updater"]
                }
            })
            .to_string(),
        )
        .expect("deep scan v2");
    assert_eq!(scan.status(), 200);
    let scan_body: serde_json::Value = scan.into_json().unwrap();
    assert!(scan_body.get("static_profile").is_some());
    assert!(scan_body.get("behavior_profile").is_some());
    assert!(!scan_body["scan"]["matches"].as_array().unwrap().is_empty());

    let library = ureq::get(&format!("{}/api/threat-intel/library/v2", base(port)))
        .set("Authorization", &auth)
        .call()
        .expect("threat intel library v2");
    let library_body: serde_json::Value = library.into_json().unwrap();
    assert!(library_body.get("indicators").is_some());
    assert!(library_body.get("recent_sightings").is_some());

    let sightings = ureq::get(&format!(
        "{}/api/threat-intel/sightings?limit=10",
        base(port)
    ))
    .set("Authorization", &auth)
    .call()
    .expect("threat intel sightings");
    let sightings_body: serde_json::Value = sightings.into_json().unwrap();
    assert!(sightings_body["count"].as_u64().unwrap() >= 1);
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
    assert!(!body["baseline_ready"].as_bool().unwrap());
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

#[test]
fn first_run_proof_creates_reopenable_evidence() {
    let (port, token) = spawn_test_server();
    let resp = ureq::post(&format!("{}/api/support/first-run-proof", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_string("")
        .expect("first-run proof");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert!(
        body["digest"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
    assert_eq!(body["proof"]["status"], serde_json::json!("completed"));
    assert!(body["proof"]["case_id"].as_u64().is_some());
    assert!(body["proof"]["report_id"].as_u64().is_some());
    assert_eq!(
        body["proof"]["response_status"],
        serde_json::json!("DryRunCompleted")
    );
    assert!(
        body["proof"]["artifact_metadata"]["support_run"]["artifact_hash"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
    assert_eq!(
        body["proof"]["demo_surfaces"]["identity"]["provider"],
        serde_json::json!("okta_identity")
    );
    assert_eq!(
        body["proof"]["demo_surfaces"]["attack_graph"]["campaign"],
        serde_json::json!("first-run-proof-lateral-path")
    );
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
    let (port, token) = spawn_test_server();
    let err = ureq::get(&format!("{}/api/nonexistent", base(port)))
        .set("Authorization", &auth_header(&token))
        .call();
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

#[test]
fn auth_session_exchange_sets_cookie_and_accepts_cookie_session() {
    let (port, token) = spawn_test_server();
    let resp = ureq::post(&format!("{}/api/auth/session", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("session exchange");
    assert_eq!(resp.status(), 200);
    let cookie = resp
        .header("Set-Cookie")
        .expect("session exchange should set a cookie")
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["authenticated"], true);
    assert_eq!(body["role"], "admin");
    assert_eq!(body["cookie"]["http_only"], true);
    assert_eq!(body["cookie"]["same_site"], "Lax");

    let session = ureq::get(&format!("{}/api/auth/session", base(port)))
        .set("Cookie", &cookie)
        .call()
        .expect("cookie-backed auth session");
    let session_body: serde_json::Value = session.into_json().unwrap();
    assert_eq!(session_body["authenticated"], true);
    assert_eq!(session_body["source"], "session");
    assert_eq!(session_body["role"], "admin");
}

#[test]
fn auth_session_accepts_sso_session_token_and_logout_revokes_it() {
    let (port, _token) = spawn_test_server();
    let session_path = test_state_path(port, "sessions.json");
    let key_path = test_state_root(port).join(".wardex_session_key");
    let seal_key = std::fs::read_to_string(&key_path)
        .ok()
        .map(|s| s.trim().as_bytes().to_vec());
    let store = SessionStore::with_persistence_key(&session_path, seal_key);
    let session_id = store.create_session(
        "sso-user",
        "sso@example.com",
        "analyst",
        &["soc-analysts".to_string()],
        8,
    );

    let resp = ureq::get(&format!("{}/api/auth/session", base(port)))
        .set("Authorization", &auth_header(&session_id))
        .call()
        .expect("auth session with SSO token");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["authenticated"], true);
    assert_eq!(body["role"], "analyst");
    assert_eq!(body["user_id"], "sso-user");
    assert_eq!(body["source"], "session");
    assert_eq!(body["groups"], serde_json::json!(["soc-analysts"]));

    let logout = ureq::post(&format!("{}/api/auth/logout", base(port)))
        .set("Authorization", &auth_header(&session_id))
        .call()
        .expect("logout SSO session");
    assert_eq!(logout.status(), 200);
    let logout_body: serde_json::Value = logout.into_json().unwrap();
    assert_eq!(logout_body["logged_out"], true);
    assert_eq!(logout_body["session_revoked"], true);

    match ureq::get(&format!("{}/api/auth/session", base(port)))
        .set("Authorization", &auth_header(&session_id))
        .call()
    {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401 after SSO logout, got {other:?}"),
    }
}

#[test]
fn remediation_change_reviews_can_be_recorded_and_listed() {
    let (port, token) = spawn_test_server();
    let payload = serde_json::json!({
        "title": "Review suspicious binary quarantine",
        "asset_id": "host-a:/tmp/dropper",
        "change_type": "malware_containment",
        "source": "malware-verdict",
        "summary": "Validate blast radius before quarantine.",
        "risk": "high",
        "approval_status": "pending_review",
        "recovery_status": "not_started",
        "evidence": {"sha256": "abc123", "path": "/tmp/dropper"}
    });
    let created = ureq::post(&format!("{}/api/remediation/change-reviews", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(&payload.to_string())
        .expect("record remediation review");
    assert_eq!(created.status(), 200);
    let created_body: serde_json::Value = created.into_json().unwrap();
    assert_eq!(created_body["status"], "recorded");
    assert_eq!(created_body["review"]["requested_by"], "admin");
    assert_eq!(
        created_body["review"]["required_approvers"],
        serde_json::json!(2)
    );

    let review_id = created_body["review"]["id"].as_str().unwrap();
    let first_approval = ureq::post(&format!(
        "{}/api/remediation/change-reviews/{}/approval",
        base(port),
        review_id
    ))
    .set("Authorization", &auth_header(&token))
    .send_json(serde_json::json!({
        "approver": "primary-reviewer",
        "decision": "approve",
        "comment": "Blast radius validated."
    }))
    .expect("first signed approval")
    .into_json::<serde_json::Value>()
    .unwrap();
    assert_eq!(
        first_approval["review"]["approval_status"],
        serde_json::json!("pending_review")
    );

    let second_approval = ureq::post(&format!(
        "{}/api/remediation/change-reviews/{}/approval",
        base(port),
        review_id
    ))
    .set("Authorization", &auth_header(&token))
    .send_json(serde_json::json!({
        "approver": "secondary-reviewer",
        "decision": "approve",
        "comment": "Rollback checkpoint verified."
    }))
    .expect("second signed approval")
    .into_json::<serde_json::Value>()
    .unwrap();
    assert_eq!(
        second_approval["review"]["approval_status"],
        serde_json::json!("approved")
    );
    assert!(
        second_approval["review"]["approval_chain_digest"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
    assert_eq!(
        second_approval["review"]["rollback_proof"]["status"],
        serde_json::json!("ready")
    );

    let rollback = ureq::post(&format!(
        "{}/api/remediation/change-reviews/{}/rollback",
        base(port),
        review_id
    ))
    .set("Authorization", &auth_header(&token))
    .send_json(serde_json::json!({
        "dry_run": true,
        "platform": "linux"
    }))
    .expect("execute rollback proof")
    .into_json::<serde_json::Value>()
    .unwrap();
    assert_eq!(rollback["status"], serde_json::json!("rollback_recorded"));
    assert_eq!(
        rollback["review"]["rollback_proof"]["status"],
        serde_json::json!("dry_run_verified")
    );
    assert_eq!(
        rollback["review"]["rollback_proof"]["execution_result"]["commands"][0]["program"],
        serde_json::json!("cp")
    );

    let listed = ureq::get(&format!("{}/api/remediation/change-reviews", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("list remediation reviews");
    let listed_body: serde_json::Value = listed.into_json().unwrap();
    assert_eq!(listed_body["summary"]["pending"].as_u64().unwrap(), 0);
    assert_eq!(
        listed_body["summary"]["multi_approver_ready"]
            .as_u64()
            .unwrap(),
        1
    );
    assert_eq!(
        listed_body["summary"]["rollback_proofs"].as_u64().unwrap(),
        1
    );
    assert_eq!(listed_body["reviews"][0]["asset_id"], "host-a:/tmp/dropper");
}

#[test]
fn live_rollback_is_blocked_when_allow_live_rollback_is_disabled() {
    let (port, token) = spawn_test_server();
    let review_id = create_approved_remediation_review(
        port,
        &token,
        "host-live-1:/etc/cron.d/payload",
        serde_json::json!({"sha256": "deadbeef"}),
    );

    // Attempt 1: live rollback without confirm_hostname must be 403 (allow_live disabled by default).
    let blocked = ureq::post(&format!(
        "{}/api/remediation/change-reviews/{}/rollback",
        base(port),
        review_id
    ))
    .set("Authorization", &auth_header(&token))
    .send_json(serde_json::json!({
        "dry_run": false,
        "platform": "linux",
        "confirm_hostname": "host-live-1:/etc/cron.d/payload"
    }));
    match blocked {
        Err(ureq::Error::Status(403, resp)) => {
            let body: serde_json::Value = resp.into_json().unwrap();
            assert!(
                body["error"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("disabled"),
                "unexpected error body: {body}"
            );
        }
        other => panic!("expected 403 for live rollback when disabled, got {other:?}"),
    }

    // Dry-run rollback still works while live rollback is disabled.
    let dry_run: serde_json::Value = ureq::post(&format!(
        "{}/api/remediation/change-reviews/{}/rollback",
        base(port),
        review_id
    ))
    .set("Authorization", &auth_header(&token))
    .send_json(serde_json::json!({
        "dry_run": true,
        "platform": "linux"
    }))
    .expect("dry-run rollback")
    .into_json()
    .unwrap();
    assert_eq!(dry_run["status"], "rollback_recorded");
    assert_eq!(
        dry_run["review"]["rollback_proof"]["status"],
        "dry_run_verified"
    );
}

#[test]
fn live_rollback_requires_matching_confirm_hostname_when_enabled() {
    let (port, token) = spawn_test_server_with_live_rollback_enabled();
    let review_id = create_approved_remediation_review(
        port,
        &token,
        "host-live-2:/Library/LaunchDaemons/com.bad.actor.plist",
        serde_json::json!({"addr": "203.0.113.10"}),
    );

    let mismatch = ureq::post(&format!(
        "{}/api/remediation/change-reviews/{}/rollback",
        base(port),
        review_id
    ))
    .set("Authorization", &auth_header(&token))
    .send_json(serde_json::json!({
        "dry_run": false,
        "platform": "macos",
        "confirm_hostname": "host-live-2"
    }));
    match mismatch {
        Err(ureq::Error::Status(400, resp)) => {
            let body: serde_json::Value = resp.into_json().unwrap();
            assert!(
                body["error"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("confirm_hostname")
            );
        }
        other => panic!("expected 400 for mismatched confirm_hostname, got {other:?}"),
    }
}

#[test]
fn live_rollback_records_macos_execution_when_enabled() {
    let (port, token) = spawn_test_server_with_live_rollback_enabled();
    let asset_id = "host-live-3:/Library/LaunchDaemons/com.bad.actor.plist";
    let review_id = create_approved_remediation_review(
        port,
        &token,
        asset_id,
        serde_json::json!({"addr": "203.0.113.10"}),
    );

    let rollback: serde_json::Value = ureq::post(&format!(
        "{}/api/remediation/change-reviews/{}/rollback",
        base(port),
        review_id
    ))
    .set("Authorization", &auth_header(&token))
    .send_json(serde_json::json!({
        "dry_run": false,
        "platform": "macos",
        "confirm_hostname": asset_id
    }))
    .expect("execute macos live rollback")
    .into_json()
    .unwrap();

    assert_eq!(rollback["status"], "rollback_recorded");
    assert_eq!(rollback["review"]["rollback_proof"]["status"], "executed");
    assert_eq!(rollback["review"]["recovery_status"], "executed");
    assert_eq!(
        rollback["review"]["rollback_proof"]["execution_result"]["platform"],
        serde_json::json!("MacOs")
    );
    assert_eq!(
        rollback["review"]["rollback_proof"]["execution_result"]["commands"][0]["program"],
        serde_json::json!("pfctl")
    );
}

#[test]
fn live_rollback_records_windows_execution_when_enabled() {
    let (port, token) = spawn_test_server_with_live_rollback_enabled();
    let asset_id = r"host-live-4:C:\Temp\payload.exe";
    let review_id = create_approved_remediation_review(
        port,
        &token,
        asset_id,
        serde_json::json!({"src_ip": "198.51.100.25"}),
    );

    let rollback: serde_json::Value = ureq::post(&format!(
        "{}/api/remediation/change-reviews/{}/rollback",
        base(port),
        review_id
    ))
    .set("Authorization", &auth_header(&token))
    .send_json(serde_json::json!({
        "dry_run": false,
        "platform": "windows",
        "confirm_hostname": asset_id
    }))
    .expect("execute windows live rollback")
    .into_json()
    .unwrap();

    assert_eq!(rollback["status"], "rollback_recorded");
    assert_eq!(rollback["review"]["rollback_proof"]["status"], "executed");
    assert_eq!(rollback["review"]["recovery_status"], "executed");
    assert_eq!(
        rollback["review"]["rollback_proof"]["execution_result"]["platform"],
        serde_json::json!("Windows")
    );
    assert_eq!(
        rollback["review"]["rollback_proof"]["execution_result"]["commands"][0]["program"],
        serde_json::json!("netsh")
    );
}

#[test]
fn live_rollback_executes_local_restore_when_execution_policy_is_enabled() {
    let (port, token) = spawn_test_server_with_live_rollback_execution_enabled();
    let temp = tempfile::tempdir().expect("tempdir");
    let source = temp.path().join("rollback-source.txt");
    let target = temp.path().join("rollback-target.txt");
    std::fs::write(&source, "restored-from-source\n").expect("write source");
    std::fs::write(&target, "stale-target\n").expect("write target");

    let review_id = create_approved_remediation_review(
        port,
        &token,
        "host-live-local",
        serde_json::json!({
            "path": target.display().to_string(),
            "rollback_source": source.display().to_string()
        }),
    );
    let platform = if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "linux"
    };

    let rollback: serde_json::Value = ureq::post(&format!(
        "{}/api/remediation/change-reviews/{}/rollback",
        base(port),
        review_id
    ))
    .set("Authorization", &auth_header(&token))
    .send_json(serde_json::json!({
        "dry_run": false,
        "platform": platform,
        "confirm_hostname": "host-live-local"
    }))
    .expect("execute local live rollback")
    .into_json()
    .unwrap();

    assert_eq!(rollback["status"], "rollback_recorded");
    assert_eq!(rollback["review"]["rollback_proof"]["status"], "executed");
    assert_eq!(rollback["review"]["recovery_status"], "executed");
    assert_eq!(
        rollback["review"]["rollback_proof"]["execution_result"]["live_execution"],
        serde_json::json!("executed")
    );
    assert_eq!(
        rollback["review"]["rollback_proof"]["execution_result"]["command_executions"][0]["executed"],
        serde_json::json!(true)
    );
    assert_eq!(
        rollback["review"]["rollback_proof"]["execution_result"]["command_executions"][0]["exit_code"],
        serde_json::json!(0)
    );

    let restored = std::fs::read_to_string(&target).expect("read restored target");
    assert_eq!(restored, "restored-from-source\n");
}

#[test]
fn live_rollback_executes_explicit_kill_process_action_when_execution_policy_is_enabled() {
    let (port, token) = spawn_test_server_with_live_rollback_execution_enabled();
    #[cfg(windows)]
    let mut child = std::process::Command::new("cmd")
        .args(["/C", "ping", "-t", "127.0.0.1"])
        .spawn()
        .expect("spawn child process");
    #[cfg(not(windows))]
    let mut child = std::process::Command::new("sleep")
        .arg("60")
        .spawn()
        .expect("spawn child process");

    let review_id = create_approved_remediation_review(
        port,
        &token,
        "host-live-kill",
        serde_json::json!({
            "rollback_action": {
                "type": "kill_process",
                "pid": child.id(),
                "name": "rollback-target"
            }
        }),
    );
    let platform = if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "linux"
    };

    let rollback_result = ureq::post(&format!(
        "{}/api/remediation/change-reviews/{}/rollback",
        base(port),
        review_id
    ))
    .set("Authorization", &auth_header(&token))
    .send_json(serde_json::json!({
        "dry_run": false,
        "platform": platform,
        "confirm_hostname": "host-live-kill"
    }));

    let rollback: serde_json::Value = rollback_result
        .expect("execute local kill-process rollback")
        .into_json()
        .unwrap();

    assert_eq!(rollback["status"], "rollback_recorded");
    assert_eq!(rollback["review"]["rollback_proof"]["status"], "executed");
    assert_eq!(rollback["review"]["recovery_status"], "executed");
    assert_eq!(
        rollback["review"]["rollback_proof"]["execution_result"]["live_execution"],
        serde_json::json!("executed")
    );
    #[cfg(windows)]
    assert_eq!(
        rollback["review"]["rollback_proof"]["execution_result"]["commands"][0]["program"],
        serde_json::json!("taskkill")
    );
    #[cfg(not(windows))]
    assert_eq!(
        rollback["review"]["rollback_proof"]["execution_result"]["commands"][0]["program"],
        serde_json::json!("kill")
    );

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
    let mut terminated = false;
    while std::time::Instant::now() < deadline {
        if child.try_wait().expect("query child status").is_some() {
            terminated = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    if !terminated {
        let _ = child.kill();
    }
    let _ = child.wait();
    if !terminated {
        panic!("expected live rollback to terminate spawned child process");
    }
}

#[test]
fn live_rollback_executes_restart_service_action_when_execution_policy_is_enabled() {
    let (port, token) = spawn_test_server_with_live_rollback_execution_enabled();
    let platform = current_live_rollback_platform();
    let command_name = current_restart_service_command();
    let temp = tempfile::tempdir().expect("tempdir");
    let log_path = temp.path().join("restart-service.log");
    let script = if cfg!(windows) {
        format!(
            "@echo off\r\necho %*>>\"{}\"\r\nexit /b 0\r\n",
            log_path.display()
        )
    } else {
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"{}\"\nexit 0\n",
            log_path.display()
        )
    };

    let rollback = with_stubbed_command_path(command_name, &script, || {
        let review_id = create_approved_remediation_review(
            port,
            &token,
            "host-live-restart",
            serde_json::json!({"service_name": "wardex-agent"}),
        );

        ureq::post(&format!(
            "{}/api/remediation/change-reviews/{}/rollback",
            base(port),
            review_id
        ))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "dry_run": false,
            "platform": platform,
            "confirm_hostname": "host-live-restart"
        }))
        .expect("execute restart-service live rollback")
        .into_json::<serde_json::Value>()
        .unwrap()
    });

    assert_eq!(rollback["status"], "rollback_recorded");
    assert_eq!(rollback["review"]["rollback_proof"]["status"], "executed");
    assert_eq!(rollback["review"]["recovery_status"], "executed");
    assert_eq!(
        rollback["review"]["rollback_proof"]["execution_result"]["live_execution"],
        serde_json::json!("executed")
    );
    assert_eq!(
        rollback["review"]["rollback_proof"]["execution_result"]["commands"][0]["program"],
        serde_json::json!(command_name)
    );
    assert_eq!(
        rollback["review"]["rollback_proof"]["execution_result"]["command_executions"][0]["exit_code"],
        serde_json::json!(0)
    );

    let logged = std::fs::read_to_string(&log_path).expect("read restart-service log");
    if cfg!(target_os = "macos") {
        assert!(logged.contains("kickstart system/wardex-agent"));
    } else if cfg!(target_os = "windows") {
        assert!(logged.contains("start wardex-agent"));
    } else {
        assert!(logged.contains("restart wardex-agent"));
    }
}

#[test]
fn live_rollback_executes_block_ip_action_when_execution_policy_is_enabled() {
    let (port, token) = spawn_test_server_with_live_rollback_execution_enabled();
    let platform = current_live_rollback_platform();
    let command_name = current_block_ip_command();
    let blocked_ip = "203.0.113.77";
    let temp = tempfile::tempdir().expect("tempdir");
    let log_path = temp.path().join("block-ip.log");
    let script = if cfg!(windows) {
        format!(
            "@echo off\r\necho %*>>\"{}\"\r\nexit /b 0\r\n",
            log_path.display()
        )
    } else {
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"{}\"\nexit 0\n",
            log_path.display()
        )
    };

    let rollback = with_stubbed_command_path(command_name, &script, || {
        let review_id = create_approved_remediation_review(
            port,
            &token,
            "host-live-block-ip",
            serde_json::json!({"addr": blocked_ip}),
        );

        ureq::post(&format!(
            "{}/api/remediation/change-reviews/{}/rollback",
            base(port),
            review_id
        ))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "dry_run": false,
            "platform": platform,
            "confirm_hostname": "host-live-block-ip"
        }))
        .expect("execute block-ip live rollback")
        .into_json::<serde_json::Value>()
        .unwrap()
    });

    assert_eq!(rollback["status"], "rollback_recorded");
    assert_eq!(rollback["review"]["rollback_proof"]["status"], "executed");
    assert_eq!(rollback["review"]["recovery_status"], "executed");
    assert_eq!(
        rollback["review"]["rollback_proof"]["execution_result"]["live_execution"],
        serde_json::json!("executed")
    );
    assert_eq!(
        rollback["review"]["rollback_proof"]["execution_result"]["commands"][0]["program"],
        serde_json::json!(command_name)
    );
    assert_eq!(
        rollback["review"]["rollback_proof"]["execution_result"]["command_executions"][0]["exit_code"],
        serde_json::json!(0)
    );

    let logged = std::fs::read_to_string(&log_path).expect("read block-ip log");
    if cfg!(target_os = "macos") {
        assert!(logged.contains("-t blocked -T add"));
        assert!(logged.contains(blocked_ip));
    } else if cfg!(target_os = "windows") {
        assert!(logged.contains("advfirewall firewall add rule"));
        assert!(logged.contains(&format!("remoteip={blocked_ip}")));
    } else {
        assert!(logged.contains("-A INPUT -s"));
        assert!(logged.contains(blocked_ip));
        assert!(logged.contains("-j DROP"));
    }
}

#[test]
fn live_rollback_executes_disable_account_action_when_execution_policy_is_enabled() {
    let (port, token) = spawn_test_server_with_live_rollback_execution_enabled();
    let platform = current_live_rollback_platform();
    let command_name = current_disable_account_command();
    let username = "wardex-disabled";
    let temp = tempfile::tempdir().expect("tempdir");
    let log_path = temp.path().join("disable-account.log");
    let script = if cfg!(windows) {
        format!(
            "@echo off\r\necho %*>>\"{}\"\r\nexit /b 0\r\n",
            log_path.display()
        )
    } else {
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"{}\"\nexit 0\n",
            log_path.display()
        )
    };

    let rollback = with_stubbed_command_path(command_name, &script, || {
        let review_id = create_approved_remediation_review(
            port,
            &token,
            "host-live-disable-account",
            serde_json::json!({
                "rollback_action": {
                    "type": "disable_account",
                    "username": username
                }
            }),
        );

        ureq::post(&format!(
            "{}/api/remediation/change-reviews/{}/rollback",
            base(port),
            review_id
        ))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "dry_run": false,
            "platform": platform,
            "confirm_hostname": "host-live-disable-account"
        }))
        .expect("execute disable-account live rollback")
        .into_json::<serde_json::Value>()
        .unwrap()
    });

    assert_eq!(rollback["status"], "rollback_recorded");
    assert_eq!(rollback["review"]["rollback_proof"]["status"], "executed");
    assert_eq!(rollback["review"]["recovery_status"], "executed");
    assert_eq!(
        rollback["review"]["rollback_proof"]["execution_result"]["live_execution"],
        serde_json::json!("executed")
    );
    assert_eq!(
        rollback["review"]["rollback_proof"]["execution_result"]["commands"][0]["program"],
        serde_json::json!(command_name)
    );
    assert_eq!(
        rollback["review"]["rollback_proof"]["execution_result"]["command_executions"][0]["exit_code"],
        serde_json::json!(0)
    );

    let logged = std::fs::read_to_string(&log_path).expect("read disable-account log");
    if cfg!(target_os = "macos") {
        assert!(logged.contains(&format!(
            "-create /Users/{username} AuthenticationAuthority ;DisabledUser;"
        )));
    } else if cfg!(target_os = "windows") {
        assert!(logged.contains(&format!("user {username} /active:no")));
    } else {
        assert!(logged.contains(&format!("-L {username}")));
    }
}

#[test]
fn live_rollback_executes_flush_dns_action_when_execution_policy_is_enabled() {
    let (port, token) = spawn_test_server_with_live_rollback_execution_enabled();
    let platform = current_live_rollback_platform();
    let command_name = current_flush_dns_command();
    let temp = tempfile::tempdir().expect("tempdir");
    let log_path = temp.path().join("flush-dns.log");
    let script = if cfg!(windows) {
        format!(
            "@echo off\r\necho %*>>\"{}\"\r\nexit /b 0\r\n",
            log_path.display()
        )
    } else {
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"{}\"\nexit 0\n",
            log_path.display()
        )
    };

    let rollback = with_stubbed_command_path(command_name, &script, || {
        let review_id = create_approved_remediation_review(
            port,
            &token,
            "host-live-flush-dns",
            serde_json::json!({
                "rollback_action": {
                    "type": "flush_dns"
                }
            }),
        );

        ureq::post(&format!(
            "{}/api/remediation/change-reviews/{}/rollback",
            base(port),
            review_id
        ))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "dry_run": false,
            "platform": platform,
            "confirm_hostname": "host-live-flush-dns"
        }))
        .expect("execute flush-dns live rollback")
        .into_json::<serde_json::Value>()
        .unwrap()
    });

    assert_eq!(rollback["status"], "rollback_recorded");
    assert_eq!(rollback["review"]["rollback_proof"]["status"], "executed");
    assert_eq!(rollback["review"]["recovery_status"], "executed");
    assert_eq!(
        rollback["review"]["rollback_proof"]["execution_result"]["live_execution"],
        serde_json::json!("executed")
    );
    assert_eq!(
        rollback["review"]["rollback_proof"]["execution_result"]["commands"][0]["program"],
        serde_json::json!(command_name)
    );
    assert_eq!(
        rollback["review"]["rollback_proof"]["execution_result"]["command_executions"][0]["exit_code"],
        serde_json::json!(0)
    );

    let logged = std::fs::read_to_string(&log_path).expect("read flush-dns log");
    if cfg!(target_os = "macos") {
        assert!(logged.contains("-flushcache"));
    } else if cfg!(target_os = "windows") {
        assert!(logged.contains("/flushdns"));
    } else {
        assert!(logged.contains("--flush-caches"));
    }
}

#[test]
fn live_rollback_records_new_adapters_when_requested_platform_does_not_match_host() {
    let (port, token) = spawn_test_server_with_live_rollback_execution_enabled();
    let platform = nonmatching_live_rollback_platform();

    let disable_account = {
        let review_id = create_approved_remediation_review(
            port,
            &token,
            "host-live-disable-account-mismatch",
            serde_json::json!({
                "rollback_action": {
                    "type": "disable_account",
                    "username": "wardex-disabled"
                }
            }),
        );

        ureq::post(&format!(
            "{}/api/remediation/change-reviews/{}/rollback",
            base(port),
            review_id
        ))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "dry_run": false,
            "platform": platform,
            "confirm_hostname": "host-live-disable-account-mismatch"
        }))
        .expect("record disable-account rollback when platform mismatches host")
        .into_json::<serde_json::Value>()
        .unwrap()
    };

    assert_eq!(disable_account["status"], "rollback_recorded");
    assert_eq!(
        disable_account["review"]["rollback_proof"]["status"],
        "executed"
    );
    assert_eq!(disable_account["review"]["recovery_status"], "executed");
    assert_eq!(
        disable_account["review"]["rollback_proof"]["execution_result"]["live_execution"],
        serde_json::json!("recorded_platform_unavailable")
    );
    assert_eq!(
        disable_account["review"]["rollback_proof"]["execution_result"]["commands"][0]["program"],
        serde_json::json!(disable_account_command_for_platform(platform))
    );
    assert!(
        disable_account["review"]["rollback_proof"]["execution_result"]["command_executions"]
            .as_array()
            .expect("disable-account command executions array")
            .is_empty()
    );
    assert_eq!(
        disable_account["review"]["rollback_proof"]["execution_result"]["result"]["output"],
        serde_json::json!(
            "rollback execution recorded; local remediation executor unavailable for requested platform"
        )
    );

    let flush_dns = {
        let review_id = create_approved_remediation_review(
            port,
            &token,
            "host-live-flush-dns-mismatch",
            serde_json::json!({
                "rollback_action": {
                    "type": "flush_dns"
                }
            }),
        );

        ureq::post(&format!(
            "{}/api/remediation/change-reviews/{}/rollback",
            base(port),
            review_id
        ))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "dry_run": false,
            "platform": platform,
            "confirm_hostname": "host-live-flush-dns-mismatch"
        }))
        .expect("record flush-dns rollback when platform mismatches host")
        .into_json::<serde_json::Value>()
        .unwrap()
    };

    assert_eq!(flush_dns["status"], "rollback_recorded");
    assert_eq!(flush_dns["review"]["rollback_proof"]["status"], "executed");
    assert_eq!(flush_dns["review"]["recovery_status"], "executed");
    assert_eq!(
        flush_dns["review"]["rollback_proof"]["execution_result"]["live_execution"],
        serde_json::json!("recorded_platform_unavailable")
    );
    assert_eq!(
        flush_dns["review"]["rollback_proof"]["execution_result"]["commands"][0]["program"],
        serde_json::json!(flush_dns_command_for_platform(platform))
    );
    assert!(
        flush_dns["review"]["rollback_proof"]["execution_result"]["command_executions"]
            .as_array()
            .expect("flush-dns command executions array")
            .is_empty()
    );
    assert_eq!(
        flush_dns["review"]["rollback_proof"]["execution_result"]["result"]["output"],
        serde_json::json!(
            "rollback execution recorded; local remediation executor unavailable for requested platform"
        )
    );
}

#[test]
fn live_rollback_executes_remove_persistence_action_when_execution_policy_is_enabled() {
    let (port, token) = spawn_test_server_with_live_rollback_execution_enabled();
    let platform = current_live_rollback_platform();
    let temp = tempfile::tempdir().expect("tempdir");
    let log_path = temp.path().join("remove-persistence.log");

    let (expected_programs, commands, evidence, expected_log_lines): (
        Vec<&str>,
        Vec<(&str, String)>,
        serde_json::Value,
        Vec<String>,
    ) = if cfg!(target_os = "macos") {
        let launch_item_path = temp.path().join("com.wardex.bad.plist");
        let launch_item = launch_item_path.display().to_string();
        (
            vec!["launchctl", "mv"],
            vec![
                (
                    "launchctl",
                    format!(
                        "#!/bin/sh\nprintf '%s %s\\n' 'launchctl' \"$*\" >> \"{}\"\nexit 0\n",
                        log_path.display()
                    ),
                ),
                (
                    "mv",
                    format!(
                        "#!/bin/sh\nprintf '%s %s\\n' 'mv' \"$*\" >> \"{}\"\nexit 0\n",
                        log_path.display()
                    ),
                ),
            ],
            serde_json::json!({
                "rollback_action": {
                    "type": "remove_persistence",
                    "mechanism_type": "launch_item",
                    "path": launch_item,
                    "item_type": "daemon"
                }
            }),
            vec![
                format!("launchctl unload {}", launch_item_path.display()),
                format!(
                    "mv {} /var/quarantine/com.wardex.bad.plist",
                    launch_item_path.display()
                ),
            ],
        )
    } else if cfg!(target_os = "windows") {
        (
            vec!["reg"],
            vec![(
                "reg",
                format!(
                    "@echo off\r\necho reg %*>>\"{}\"\r\nexit /b 0\r\n",
                    log_path.display()
                ),
            )],
            serde_json::json!({
                "rollback_action": {
                    "type": "remove_persistence",
                    "mechanism_type": "registry_run_key",
                    "hive": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                    "value_name": "WardexAgent"
                }
            }),
            vec![
                r"reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v WardexAgent /f"
                    .to_string(),
            ],
        )
    } else {
        (
            vec!["systemctl", "systemctl"],
            vec![(
                "systemctl",
                format!(
                    "#!/bin/sh\nprintf '%s %s\\n' 'systemctl' \"$*\" >> \"{}\"\nexit 0\n",
                    log_path.display()
                ),
            )],
            serde_json::json!({
                "rollback_action": {
                    "type": "remove_persistence",
                    "mechanism_type": "systemd_unit",
                    "name": "wardex-agent"
                }
            }),
            vec![
                "systemctl stop wardex-agent".to_string(),
                "systemctl disable wardex-agent".to_string(),
            ],
        )
    };
    let command_refs: Vec<(&str, &str)> = commands
        .iter()
        .map(|(command_name, script)| (*command_name, script.as_str()))
        .collect();

    let rollback = with_stubbed_commands_path(&command_refs, || {
        let review_id = create_approved_remediation_review(
            port,
            &token,
            "host-live-remove-persistence",
            evidence.clone(),
        );

        ureq::post(&format!(
            "{}/api/remediation/change-reviews/{}/rollback",
            base(port),
            review_id
        ))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "dry_run": false,
            "platform": platform,
            "confirm_hostname": "host-live-remove-persistence"
        }))
        .expect("execute remove-persistence live rollback")
        .into_json::<serde_json::Value>()
        .unwrap()
    });

    assert_eq!(rollback["status"], "rollback_recorded");
    assert_eq!(rollback["review"]["rollback_proof"]["status"], "executed");
    assert_eq!(rollback["review"]["recovery_status"], "executed");
    assert_eq!(
        rollback["review"]["rollback_proof"]["execution_result"]["live_execution"],
        serde_json::json!("executed")
    );

    let execution_result = &rollback["review"]["rollback_proof"]["execution_result"];
    let programs: Vec<&str> = execution_result["commands"]
        .as_array()
        .expect("commands array")
        .iter()
        .map(|command| command["program"].as_str().expect("command program"))
        .collect();
    assert_eq!(programs, expected_programs);

    let command_executions = execution_result["command_executions"]
        .as_array()
        .expect("command executions array");
    assert_eq!(command_executions.len(), expected_programs.len());
    for execution in command_executions {
        assert_eq!(execution["exit_code"], serde_json::json!(0));
    }

    let logged = std::fs::read_to_string(&log_path).expect("read remove-persistence log");
    for expected_line in expected_log_lines {
        assert!(
            logged.contains(&expected_line),
            "missing {expected_line:?} in log {logged:?}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn live_rollback_executes_systemd_unit_removal_with_instance_name_when_execution_policy_is_enabled()
{
    let (port, token) = spawn_test_server_with_live_rollback_execution_enabled();
    let service_name = "wardex-agent@blue.service";
    let temp = tempfile::tempdir().expect("tempdir");
    let log_path = temp.path().join("systemd-instance.log");
    let systemctl_script = format!(
        "#!/bin/sh\nprintf 'systemctl\\n' >> \"{}\"\nfor arg in \"$@\"; do\n  printf '%s\\n' \"$arg\" >> \"{}\"\ndone\nexit 0\n",
        log_path.display(),
        log_path.display()
    );

    let rollback = with_stubbed_commands_path(&[("systemctl", systemctl_script.as_str())], || {
        let review_id = create_approved_remediation_review(
            port,
            &token,
            "host-live-systemd-instance",
            serde_json::json!({
                "rollback_action": {
                    "type": "remove_persistence",
                    "mechanism_type": "systemd_unit",
                    "name": service_name
                }
            }),
        );

        ureq::post(&format!(
            "{}/api/remediation/change-reviews/{}/rollback",
            base(port),
            review_id
        ))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "dry_run": false,
            "platform": "linux",
            "confirm_hostname": "host-live-systemd-instance"
        }))
        .expect("execute systemd unit live rollback")
        .into_json::<serde_json::Value>()
        .unwrap()
    });

    assert_eq!(rollback["status"], "rollback_recorded");
    assert_eq!(rollback["review"]["rollback_proof"]["status"], "executed");
    assert_eq!(rollback["review"]["recovery_status"], "executed");
    assert_eq!(
        rollback["review"]["rollback_proof"]["execution_result"]["live_execution"],
        serde_json::json!("executed")
    );

    let execution_result = &rollback["review"]["rollback_proof"]["execution_result"];
    let programs: Vec<&str> = execution_result["commands"]
        .as_array()
        .expect("commands array")
        .iter()
        .map(|command| command["program"].as_str().expect("command program"))
        .collect();
    assert_eq!(programs, vec!["systemctl", "systemctl"]);

    let command_executions = execution_result["command_executions"]
        .as_array()
        .expect("command executions array");
    assert_eq!(command_executions.len(), 2);
    for execution in command_executions {
        assert_eq!(execution["exit_code"], serde_json::json!(0));
    }

    let logged = std::fs::read_to_string(&log_path).expect("read systemd instance log");
    assert!(logged.contains(&format!("systemctl\nstop\n{service_name}\n")));
    assert!(logged.contains(&format!("systemctl\ndisable\n{service_name}\n")));
}

#[cfg(target_os = "macos")]
#[test]
fn live_rollback_executes_launch_item_removal_with_spaced_path_when_execution_policy_is_enabled() {
    let (port, token) = spawn_test_server_with_live_rollback_execution_enabled();
    let temp = tempfile::tempdir().expect("tempdir");
    let launch_agents_dir = temp.path().join("Launch Agents");
    std::fs::create_dir_all(&launch_agents_dir).expect("create launch agents dir");
    let launch_item_path = launch_agents_dir.join("com wardex helper.plist");
    std::fs::write(&launch_item_path, "plist payload").expect("write launch item");
    let log_path = temp.path().join("launch-item-edge.log");
    let launchctl_script = format!(
        "#!/bin/sh\nprintf 'launchctl\\n' >> \"{}\"\nfor arg in \"$@\"; do\n  printf '%s\\n' \"$arg\" >> \"{}\"\ndone\nexit 0\n",
        log_path.display(),
        log_path.display()
    );
    let mv_script = format!(
        "#!/bin/sh\nprintf 'mv\\n' >> \"{}\"\nfor arg in \"$@\"; do\n  printf '%s\\n' \"$arg\" >> \"{}\"\ndone\nexit 0\n",
        log_path.display(),
        log_path.display()
    );
    let rollback = with_stubbed_commands_path(
        &[
            ("launchctl", launchctl_script.as_str()),
            ("mv", mv_script.as_str()),
        ],
        || {
            let review_id = create_approved_remediation_review(
                port,
                &token,
                "host-live-launch-item-edge",
                serde_json::json!({
                    "rollback_action": {
                        "type": "remove_persistence",
                        "mechanism_type": "launch_item",
                        "path": launch_item_path.display().to_string(),
                        "item_type": "agent"
                    }
                }),
            );

            ureq::post(&format!(
                "{}/api/remediation/change-reviews/{}/rollback",
                base(port),
                review_id
            ))
            .set("Authorization", &auth_header(&token))
            .send_json(serde_json::json!({
                "dry_run": false,
                "platform": "macos",
                "confirm_hostname": "host-live-launch-item-edge"
            }))
            .expect("execute launch item live rollback")
            .into_json::<serde_json::Value>()
            .unwrap()
        },
    );

    assert_eq!(rollback["status"], "rollback_recorded");
    assert_eq!(rollback["review"]["rollback_proof"]["status"], "executed");
    assert_eq!(rollback["review"]["recovery_status"], "executed");
    assert_eq!(
        rollback["review"]["rollback_proof"]["execution_result"]["live_execution"],
        serde_json::json!("executed")
    );

    let execution_result = &rollback["review"]["rollback_proof"]["execution_result"];
    let programs: Vec<&str> = execution_result["commands"]
        .as_array()
        .expect("commands array")
        .iter()
        .map(|command| command["program"].as_str().expect("command program"))
        .collect();
    assert_eq!(programs, vec!["launchctl", "mv"]);

    let command_executions = execution_result["command_executions"]
        .as_array()
        .expect("command executions array");
    assert_eq!(command_executions.len(), 2);
    for execution in command_executions {
        assert_eq!(execution["exit_code"], serde_json::json!(0));
    }

    let logged = std::fs::read_to_string(&log_path).expect("read launch-item edge log");
    assert!(logged.contains(&format!(
        "launchctl\nunload\n{}\n",
        launch_item_path.display()
    )));
    assert!(logged.contains(&format!(
        "mv\n{}\n/var/quarantine/com wardex helper.plist\n",
        launch_item_path.display()
    )));
}

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
    assert!(deployed["deployment"]["allow_downgrade"].as_bool().unwrap());

    let update = ureq::get(&format!(
        "{}/api/agents/update?agent_id={}&current_version=0.16.0",
        base(port),
        agent_id
    ))
    .call()
    .expect("rollback update check")
    .into_json::<serde_json::Value>()
    .unwrap();
    assert!(update["update_available"].as_bool().unwrap());
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
fn investigation_progress_endpoint_updates_active_snapshot() {
    let (port, token) = spawn_test_server();

    let started: serde_json::Value =
        ureq::post(&format!("{}/api/investigations/start", base(port)))
            .set("Authorization", &auth_header(&token))
            .send_json(serde_json::json!({
                "workflow_id": "credential-storm",
                "analyst": "analyst-1"
            }))
            .expect("start investigation")
            .into_json()
            .unwrap();

    let investigation_id = started["id"].as_str().expect("investigation id");
    assert!(investigation_id.starts_with("inv-"));
    assert_eq!(started["workflow_id"].as_str(), Some("credential-storm"));
    assert_eq!(started["status"].as_str(), Some("in-progress"));

    let updated: serde_json::Value =
        ureq::post(&format!("{}/api/investigations/progress", base(port)))
            .set("Authorization", &auth_header(&token))
            .send_json(serde_json::json!({
                "investigation_id": investigation_id,
                "step": 1,
                "completed": true,
                "note": "VPN telemetry reviewed",
                "finding": "Lockout pattern confirmed from single ASN"
            }))
            .expect("update investigation progress")
            .into_json()
            .unwrap();

    assert_eq!(updated["id"].as_str(), Some(investigation_id));
    assert_eq!(
        updated["notes"]["1"].as_str(),
        Some("VPN telemetry reviewed")
    );
    assert!(
        updated["completed_steps"]
            .as_array()
            .map(|items| items.iter().any(|value| value.as_u64() == Some(1)))
            .unwrap_or(false)
    );
    assert!(
        updated["findings"]
            .as_array()
            .map(|items| {
                items.iter().any(|value| {
                    value.as_str() == Some("Lockout pattern confirmed from single ASN")
                })
            })
            .unwrap_or(false)
    );
    assert!(updated["completion_percent"].as_u64().unwrap_or_default() > 0);
    assert_eq!(updated["next_step"]["order"].as_u64(), Some(2));

    let active: serde_json::Value = ureq::get(&format!("{}/api/investigations/active", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("active investigations")
        .into_json()
        .unwrap();

    let active_items = active.as_array().expect("active investigation array");
    let snapshot = active_items
        .iter()
        .find(|entry| entry["id"].as_str() == Some(investigation_id))
        .expect("active snapshot present");
    assert_eq!(
        snapshot["notes"]["1"].as_str(),
        Some("VPN telemetry reviewed")
    );
    assert_eq!(
        snapshot["workflow_name"].as_str(),
        Some("Investigate Credential Storm")
    );
}

#[test]
fn investigation_handoff_updates_linked_case_assignment_and_commentary() {
    let (port, token) = spawn_test_server();

    let case: serde_json::Value = ureq::post(&format!("{}/api/cases", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "title": "Identity escalation case",
            "priority": "high",
            "description": "Tracks credential storm investigation",
            "tags": ["identity", "handoff"]
        }))
        .expect("create case")
        .into_json()
        .unwrap();
    let case_id = case["id"].as_u64().expect("case id");

    let started: serde_json::Value =
        ureq::post(&format!("{}/api/investigations/start", base(port)))
            .set("Authorization", &auth_header(&token))
            .send_json(serde_json::json!({
                "workflow_id": "credential-storm",
                "analyst": "analyst-1",
                "case_id": case_id.to_string()
            }))
            .expect("start investigation")
            .into_json()
            .unwrap();

    let investigation_id = started["id"].as_str().expect("investigation id");
    let handed_off: serde_json::Value =
        ureq::post(&format!("{}/api/investigations/handoff", base(port)))
            .set("Authorization", &auth_header(&token))
            .send_json(serde_json::json!({
                "investigation_id": investigation_id,
                "to_analyst": "analyst-2",
                "summary": "Containment is in place but MFA bypass scope still needs confirmation.",
                "next_actions": [
                    "Confirm all targeted accounts were reset",
                    "Validate VPN source IP blocks"
                ],
                "questions": [
                    "Was any successful login followed by privilege escalation?"
                ],
                "case_id": case_id.to_string()
            }))
            .expect("handoff investigation")
            .into_json()
            .unwrap();

    assert_eq!(handed_off["status"].as_str(), Some("handoff-ready"));
    assert_eq!(handed_off["analyst"].as_str(), Some("analyst-2"));
    assert_eq!(
        handed_off["handoff"]["from_analyst"].as_str(),
        Some("analyst-1")
    );
    assert_eq!(
        handed_off["handoff"]["to_analyst"].as_str(),
        Some("analyst-2")
    );
    assert!(
        handed_off["handoff"]["next_actions"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .any(|value| value.as_str() == Some("Confirm all targeted accounts were reset"))
            })
            .unwrap_or(false)
    );

    let detail: serde_json::Value = ureq::get(&format!("{}/api/cases/{}", base(port), case_id))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("case detail")
        .into_json()
        .unwrap();

    assert_eq!(detail["assignee"].as_str(), Some("analyst-2"));
    let comments = detail["comments"].as_array().expect("case comments");
    assert!(comments.iter().any(|entry| {
        entry["text"]
            .as_str()
            .map(|text| {
                text.contains("Investigation handoff from analyst-1 to analyst-2")
                    && text.contains("Validate VPN source IP blocks")
            })
            .unwrap_or(false)
    }));
}

#[test]
fn case_handoff_packet_includes_linked_handoff_context() {
    let (port, token) = spawn_test_server();
    let (agent_id, event_ids) = setup_agent_with_events(port, &token, "handoff-packet-host", 2);
    assert_eq!(event_ids.len(), 2);

    let incident: serde_json::Value = ureq::post(&format!("{}/api/incidents", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "title": "Credential storm incident",
            "severity": "Critical",
            "event_ids": event_ids,
            "agent_ids": [agent_id],
            "summary": "Investigate suspicious auth activity on handoff-packet-host"
        }))
        .expect("create incident")
        .into_json()
        .unwrap();
    let incident_id = incident["id"].as_u64().expect("incident id");

    let case: serde_json::Value = ureq::post(&format!("{}/api/cases", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "title": "Identity escalation case",
            "priority": "high",
            "description": "Tracks credential storm investigation",
            "incident_ids": [incident_id],
            "event_ids": event_ids,
            "tags": ["identity", "handoff"]
        }))
        .expect("create case")
        .into_json()
        .unwrap();
    let case_id = case["id"].as_u64().expect("case id");

    ureq::post(&format!("{}/api/cases/{}/comment", base(port), case_id))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "author": "analyst-1",
            "text": "Escalation path validated and containment owner identified."
        }))
        .expect("add case comment");

    ureq::post(&format!("{}/api/cases/{}/evidence", base(port), case_id))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "kind": "query_result",
            "reference_id": "hunt-4242",
            "description": "Correlated VPN and Okta sign-in evidence"
        }))
        .expect("add case evidence");

    let started: serde_json::Value =
        ureq::post(&format!("{}/api/investigations/start", base(port)))
            .set("Authorization", &auth_header(&token))
            .send_json(serde_json::json!({
                "workflow_id": "credential-storm",
                "analyst": "analyst-1",
                "case_id": case_id.to_string()
            }))
            .expect("start investigation")
            .into_json()
            .unwrap();

    let investigation_id = started["id"].as_str().expect("investigation id");
    ureq::post(&format!("{}/api/investigations/handoff", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "investigation_id": investigation_id,
            "to_analyst": "analyst-2",
            "summary": "Containment is in place but MFA bypass scope still needs confirmation.",
            "next_actions": [
                "Confirm all targeted accounts were reset",
                "Validate VPN source IP blocks"
            ],
            "questions": [
                "Was any successful login followed by privilege escalation?"
            ],
            "case_id": case_id.to_string()
        }))
        .expect("handoff investigation");

    let packet: serde_json::Value = ureq::get(&format!(
        "{}/api/cases/{}/handoff-packet",
        base(port),
        case_id
    ))
    .set("Authorization", &auth_header(&token))
    .call()
    .expect("fetch handoff packet")
    .into_json()
    .unwrap();

    assert_eq!(
        packet["case"]["summary"].as_str(),
        Some("Containment is in place but MFA bypass scope still needs confirmation.")
    );
    assert_eq!(
        packet["linked_investigation"]["id"].as_str(),
        Some(investigation_id)
    );
    assert_eq!(
        packet["linked_investigation"]["status"].as_str(),
        Some("handoff-ready")
    );
    assert_eq!(
        packet["linked_investigation"]["analyst"].as_str(),
        Some("analyst-2")
    );
    assert_eq!(
        packet["next_actions"],
        serde_json::json!([
            "Confirm all targeted accounts were reset",
            "Validate VPN source IP blocks"
        ])
    );
    assert_eq!(
        packet["unresolved_questions"],
        serde_json::json!(["Was any successful login followed by privilege escalation?"])
    );
    assert_eq!(
        packet["checklist_state"]["evidence_items"].as_u64(),
        Some(1)
    );
    assert_eq!(packet["checklist_state"]["analyst_notes"].as_u64(), Some(2));
    assert_eq!(
        packet["checklist_state"]["linked_incidents"].as_u64(),
        Some(1)
    );
    assert_eq!(packet["checklist_state"]["linked_events"].as_u64(), Some(2));
    assert_eq!(packet["checklist_state"]["next_actions"].as_u64(), Some(2));
    assert_eq!(
        packet["checklist_state"]["unresolved_questions"].as_u64(),
        Some(1)
    );
    assert_eq!(
        packet["reopen_case_url"].as_str(),
        Some(format!("/soc?case={case_id}&drawer=case-workspace&casePanel=handoff#cases").as_str())
    );
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

    let content_rule: serde_json::Value = ureq::post(&format!("{}/api/content/rules", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "title": "Workbench review rule",
            "description": "Used to validate SOC workbench review history.",
            "owner": "detections",
            "severity_mapping": "high",
            "pack_ids": ["identity-attacks"],
            "query": {
                "hostname": "workbench-host",
                "text": "test_reason",
                "limit": 100
            }
        }))
        .expect("create review rule")
        .into_json()
        .unwrap();
    let rule_id = content_rule["rule"]["metadata"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    ureq::post(&format!(
        "{}/api/content/rules/{}/test",
        base(port),
        rule_id
    ))
    .set("Authorization", &auth_header(&token))
    .call()
    .expect("test review rule");

    ureq::post(&format!("{}/api/detection/feedback", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "rule_id": rule_id,
            "analyst": "analyst-1",
            "verdict": "true_positive",
            "notes": "SOC handoff confirmed the replay noise is expected."
        }))
        .expect("record review feedback");

    let rules_catalog: serde_json::Value = ureq::get(&format!("{}/api/content/rules", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("content rules catalog")
        .into_json()
        .unwrap();
    for seed_rule_id in rules_catalog["rules"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item["id"].as_str())
        .take(10)
    {
        ureq::post(&format!("{}/api/detection/feedback", base(port)))
            .set("Authorization", &auth_header(&token))
            .send_json(serde_json::json!({
                "rule_id": seed_rule_id,
                "analyst": "analyst-1",
                "verdict": "true_positive",
                "notes": "SOC handoff confirmed the replay noise is expected."
            }))
            .expect("seed review feedback");
    }

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
    assert!(overview["team_load"]["active_owners"].is_u64());
    assert!(overview["team_load"]["rebalance_hint"].is_string());
    assert!(overview["connector_impact"]["collectors_at_risk"].is_u64());
    assert!(overview["connector_impact"]["items"].is_array());
    let detection_review_item = overview["detection_review"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| {
            item["latest_feedback_verdict"].as_str() == Some("true_positive")
                && item["latest_feedback_notes"].as_str()
                    == Some("SOC handoff confirmed the replay noise is expected.")
        })
        .expect("review row with analyst history appears in workbench");
    assert!(detection_review_item["latest_replay_new_match_count"].is_u64());
    assert!(detection_review_item["latest_replay_cleared_match_count"].is_u64());
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
    assert!(
        agents
            .as_array()
            .unwrap()
            .iter()
            .any(|agent| agent["id"] == serde_json::json!(LOCAL_CONSOLE_AGENT_ID))
    );
    let enrolled_agent = find_agent_by_id(&agents, &agent_id);
    assert_eq!(enrolled_agent["id"].as_str().unwrap(), agent_id);
    assert!(enrolled_agent["last_seen_age_secs"].is_u64());
    assert!(enrolled_agent["current_version"].is_string());
    assert_eq!(enrolled_agent["target_version"].as_str().unwrap(), "1.2.3");
    assert_eq!(enrolled_agent["rollout_group"].as_str().unwrap(), "canary");
    assert_eq!(
        enrolled_agent["deployment_status"].as_str().unwrap(),
        "assigned"
    );
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
        "true_positive"
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
