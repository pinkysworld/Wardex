//! Regression tests for the threat-intel/ticketing/OTLP integration
//! hardening: OTLP header redaction, outbound-URL SSRF validation +
//! credential clearing on host change, and ticket-sync failure handling.

mod common;
use common::*;

// ── OTLP: header redaction ──────────────────────────────────────────────────

#[test]
fn otlp_config_never_echoes_header_values() {
    let (port, token) = spawn_test_server();

    let saved: serde_json::Value = ureq::post(&format!("{}/api/telemetry/otlp", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "endpoint": "https://collector.example.com:4318",
            "enabled": true,
            "headers": {"Authorization": "Bearer super-secret-token"},
            "batch_max_size": 100,
            "max_queue_size": 1000,
            "max_retries": 3,
            "timeout_secs": 5
        }))
        .expect("save otlp config")
        .into_json()
        .unwrap();
    let saved_headers = saved["config"]["headers"].clone();
    assert_eq!(
        saved_headers["Authorization"].as_str().unwrap(),
        "__REDACTED__"
    );
    assert!(!saved.to_string().contains("super-secret-token"));

    let fetched: serde_json::Value = ureq::get(&format!("{}/api/telemetry/otlp", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("get otlp config")
        .into_json()
        .unwrap();
    assert_eq!(
        fetched["headers"]["Authorization"].as_str().unwrap(),
        "__REDACTED__"
    );
    assert_eq!(fetched["has_headers"].as_bool(), Some(true));
    assert!(!fetched.to_string().contains("super-secret-token"));
}

#[test]
fn otlp_config_placeholder_headers_are_accepted_and_stay_redacted() {
    let (port, token) = spawn_test_server();

    ureq::post(&format!("{}/api/telemetry/otlp", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "endpoint": "https://collector.example.com:4318",
            "enabled": true,
            "headers": {"Authorization": "Bearer super-secret-token"},
            "batch_max_size": 100,
            "max_queue_size": 1000,
            "max_retries": 3,
            "timeout_secs": 5
        }))
        .expect("save otlp config")
        .into_json::<serde_json::Value>()
        .unwrap();

    // Re-save with the same endpoint host and the redacted placeholder for
    // the header (as the admin UI would after a GET, changing only an
    // unrelated field) — this must be accepted (the placeholder is
    // recognized, not persisted literally), and the header stays reported
    // as present but redacted. The actual stored value never round-trips
    // through the API by design; `src/server_integrations_ext.rs`'s unit
    // tests cover that the real value is what's kept internally.
    let resaved: serde_json::Value = ureq::post(&format!("{}/api/telemetry/otlp", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "endpoint": "https://collector.example.com:4318",
            "enabled": true,
            "headers": {"Authorization": "__REDACTED__"},
            "batch_max_size": 200,
            "max_queue_size": 1000,
            "max_retries": 3,
            "timeout_secs": 5
        }))
        .expect("re-save otlp config with placeholder header")
        .into_json()
        .unwrap();
    assert_eq!(resaved["status"].as_str(), Some("saved"));
    assert_eq!(
        resaved["config"]["headers"]["Authorization"].as_str(),
        Some("__REDACTED__")
    );
    assert_eq!(resaved["config"]["has_headers"].as_bool(), Some(true));
    assert!(!resaved.to_string().contains("super-secret-token"));
}

#[test]
fn otlp_config_rejects_placeholder_for_a_header_with_no_prior_value() {
    let (port, token) = spawn_test_server();
    let result = ureq::post(&format!("{}/api/telemetry/otlp", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "endpoint": "https://collector.example.com:4318",
            "enabled": true,
            "headers": {"X-Never-Set-Before": "__REDACTED__"},
            "batch_max_size": 100,
            "max_queue_size": 1000,
            "max_retries": 3,
            "timeout_secs": 5
        }));
    match result {
        Err(ureq::Error::Status(400, _)) => {}
        other => panic!("expected 400 for an unknown placeholder header, got {other:?}"),
    }
}

// ── Outbound URL / SSRF validation ──────────────────────────────────────────

#[test]
fn otlp_config_rejects_plaintext_http_to_non_loopback_host() {
    let (port, token) = spawn_test_server();
    let result = ureq::post(&format!("{}/api/telemetry/otlp", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "endpoint": "http://collector.example.com:4318",
            "enabled": true,
            "headers": {},
            "batch_max_size": 100,
            "max_queue_size": 1000,
            "max_retries": 3,
            "timeout_secs": 5
        }));
    match result {
        Err(ureq::Error::Status(400, _)) => {}
        other => panic!("expected 400 for plaintext http to a non-loopback host, got {other:?}"),
    }
}

#[test]
fn otlp_config_rejects_link_local_and_metadata_hosts() {
    let (port, token) = spawn_test_server();
    for endpoint in [
        "https://169.254.169.254",
        "https://metadata.google.internal",
        "http://169.254.1.5",
    ] {
        let result = ureq::post(&format!("{}/api/telemetry/otlp", base(port)))
            .set("Authorization", &auth_header(&token))
            .send_json(serde_json::json!({
                "endpoint": endpoint,
                "enabled": true,
                "headers": {},
                "batch_max_size": 100,
                "max_queue_size": 1000,
                "max_retries": 3,
                "timeout_secs": 5
            }));
        assert!(result.is_err(), "expected {endpoint} to be rejected");
    }
}

#[test]
fn jira_config_rejects_bad_urls_and_accepts_https() {
    let (port, token) = spawn_test_server();

    let rejected = ureq::post(&format!("{}/api/integrations/ticketing/jira", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "base_url": "http://internal-jira.example.com",
            "project_key": "SEC",
            "api_token": "tok-1"
        }));
    assert!(rejected.is_err());

    let ok: serde_json::Value =
        ureq::post(&format!("{}/api/integrations/ticketing/jira", base(port)))
            .set("Authorization", &auth_header(&token))
            .send_json(serde_json::json!({
                "base_url": "https://wardex-test.atlassian.net",
                "project_key": "SEC",
                "api_token": "tok-1"
            }))
            .expect("valid https base_url accepted")
            .into_json()
            .unwrap();
    assert_eq!(ok["status"].as_str(), Some("saved"));
}

#[test]
fn jira_config_clears_token_when_base_url_host_changes_without_new_token() {
    let (port, token) = spawn_test_server();

    ureq::post(&format!("{}/api/integrations/ticketing/jira", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "base_url": "https://wardex-test.atlassian.net",
            "project_key": "SEC",
            "api_token": "tok-1",
            "enabled": true
        }))
        .expect("initial jira config")
        .into_json::<serde_json::Value>()
        .unwrap();

    let before: serde_json::Value =
        ureq::get(&format!("{}/api/integrations/ticketing/jira", base(port)))
            .set("Authorization", &auth_header(&token))
            .call()
            .expect("get jira config")
            .into_json()
            .unwrap();
    assert_eq!(before["has_api_token"].as_bool(), Some(true));

    // Change only the host, without supplying a new token.
    ureq::post(&format!("{}/api/integrations/ticketing/jira", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "base_url": "https://a-different-jira-instance.atlassian.net",
        }))
        .expect("change base_url host")
        .into_json::<serde_json::Value>()
        .unwrap();

    let after: serde_json::Value =
        ureq::get(&format!("{}/api/integrations/ticketing/jira", base(port)))
            .set("Authorization", &auth_header(&token))
            .call()
            .expect("get jira config after host change")
            .into_json()
            .unwrap();
    assert_eq!(
        after["has_api_token"].as_bool(),
        Some(false),
        "the old token must not be carried over to the new host"
    );
}

#[test]
fn jira_config_keeps_token_when_host_unchanged() {
    let (port, token) = spawn_test_server();

    ureq::post(&format!("{}/api/integrations/ticketing/jira", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "base_url": "https://wardex-test.atlassian.net",
            "project_key": "SEC",
            "api_token": "tok-1",
            "enabled": true
        }))
        .expect("initial jira config")
        .into_json::<serde_json::Value>()
        .unwrap();

    // Same host, different path/trailing slash — and no new token.
    ureq::post(&format!("{}/api/integrations/ticketing/jira", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "base_url": "https://wardex-test.atlassian.net/",
            "project_key": "SEC2",
        }))
        .expect("update project_key only")
        .into_json::<serde_json::Value>()
        .unwrap();

    let after: serde_json::Value =
        ureq::get(&format!("{}/api/integrations/ticketing/jira", base(port)))
            .set("Authorization", &auth_header(&token))
            .call()
            .expect("get jira config")
            .into_json()
            .unwrap();
    assert_eq!(after["has_api_token"].as_bool(), Some(true));
    assert_eq!(after["project_key"].as_str(), Some("SEC2"));
}

// ── Ticket sync failure handling ────────────────────────────────────────────

#[test]
fn ticket_sync_failure_does_not_fabricate_external_key() {
    let (port, token) = spawn_test_server();

    // Point Jira at a loopback port nothing is listening on, so the create
    // call fails with a connection error — "configured but unreachable",
    // not "not configured".
    let unused_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve port");
    let dead_port = unused_listener.local_addr().unwrap().port();
    drop(unused_listener);

    ureq::post(&format!("{}/api/integrations/ticketing/jira", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "base_url": format!("http://127.0.0.1:{dead_port}"),
            "project_key": "SEC",
            "api_token": "tok-1",
            "enabled": true,
            "timeout_secs": 2
        }))
        .expect("configure jira pointing at a dead port")
        .into_json::<serde_json::Value>()
        .unwrap();

    let synced: serde_json::Value = ureq::post(&format!("{}/api/tickets/sync", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "provider": "jira",
            "object_kind": "incident",
            "object_id": "999",
            "summary": "unreachable jira test"
        }))
        .expect("sync request itself succeeds (failure is reported in the body)")
        .into_json()
        .unwrap();

    assert!(synced["remote_sync_error"].is_string());
    assert_eq!(synced["sync"]["status"].as_str(), Some("failed"));
    assert_eq!(synced["sync"]["external_key"].as_str(), Some(""));
}

#[test]
fn ticket_sync_retry_after_failure_creates_a_real_ticket() {
    let (port, token) = spawn_test_server();

    // First attempt: Jira configured but pointing at a dead port, so the
    // create call fails.
    let unused_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve port");
    let dead_port = unused_listener.local_addr().unwrap().port();
    drop(unused_listener);

    ureq::post(&format!("{}/api/integrations/ticketing/jira", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "base_url": format!("http://127.0.0.1:{dead_port}"),
            "project_key": "SEC",
            "api_token": "tok-1",
            "enabled": true,
            "timeout_secs": 2
        }))
        .expect("configure jira pointing at a dead port")
        .into_json::<serde_json::Value>()
        .unwrap();

    let first: serde_json::Value = ureq::post(&format!("{}/api/tickets/sync", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "provider": "jira",
            "object_kind": "incident",
            "object_id": "42",
            "summary": "retry test"
        }))
        .expect("first sync attempt")
        .into_json()
        .unwrap();
    assert_eq!(first["sync"]["status"].as_str(), Some("failed"));
    assert_eq!(first["sync"]["external_key"].as_str(), Some(""));

    // Now point Jira at a real (mock) server that will accept a create —
    // if the retry treated the failed record's (empty) key as an existing
    // ticket, it would try to PATCH/comment a nonexistent id instead of
    // creating one; the mock only implements POST .../issue (create).
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind mock jira");
    let mock_port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        use std::io::{Read, Write};
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 8192];
            let mut received = Vec::new();
            loop {
                let n = stream.read(&mut buf).unwrap_or(0);
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&buf[..n]);
                if received.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let request_line = String::from_utf8_lossy(&received);
            assert!(
                request_line.starts_with("POST"),
                "retry must create a new ticket, not PATCH/comment: {request_line}"
            );
            let body = r#"{"key":"SEC-77","id":"10001"}"#;
            let response = format!(
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });

    ureq::post(&format!("{}/api/integrations/ticketing/jira", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "base_url": format!("http://127.0.0.1:{mock_port}"),
            "project_key": "SEC",
            "api_token": "tok-1",
            "enabled": true,
            "timeout_secs": 5
        }))
        .expect("re-point jira at working mock")
        .into_json::<serde_json::Value>()
        .unwrap();

    let second: serde_json::Value = ureq::post(&format!("{}/api/tickets/sync", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "provider": "jira",
            "object_kind": "incident",
            "object_id": "42",
            "summary": "retry test"
        }))
        .expect("retry sync attempt")
        .into_json()
        .unwrap();
    handle.join().expect("mock jira server thread");

    assert!(second["remote_sync_error"].is_null());
    assert_eq!(second["sync"]["external_key"].as_str(), Some("SEC-77"));
}
