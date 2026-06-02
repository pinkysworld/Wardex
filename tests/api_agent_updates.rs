mod common;
use common::*;

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
