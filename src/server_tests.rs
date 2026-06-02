//! Unit tests for the server module.

    use super::*;
    use crate::analyst::ApprovalDecision as AnalystApprovalDecision;
    use crate::collector::AlertRecord;
    use crate::enrollment::EnrollRequest;
    use crate::event_forward::EventBatch;
    use crate::response::{ApprovalDecision as ResponseApprovalDecision, ApprovalRecord};
    use crate::server_auth::{
        FAILED_AUTH_INITIAL_LOCKOUT_SECS, FAILED_AUTH_MAX_LOCKOUT_SECS, FAILED_AUTH_THRESHOLD,
        FailedAuthTracker,
    };
    use crate::telemetry::TelemetrySample;
    use std::collections::HashMap as StdHashMap;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    #[test]
    fn secure_token_eq_compares_in_constant_time_semantics() {
        // None provided fails.
        assert!(!secure_token_eq(None, "anything"));
        // Equal-length match succeeds.
        assert!(secure_token_eq(Some("abc123"), "abc123"));
        // Equal length but different fails.
        assert!(!secure_token_eq(Some("abc123"), "abc124"));
        // Length mismatch fails.
        assert!(!secure_token_eq(Some("abc"), "abc123"));
        assert!(!secure_token_eq(Some(""), "abc"));
    }

    #[test]
    fn failed_auth_tracker_locks_after_threshold() {
        let mut t = FailedAuthTracker::new();
        let ip = "203.0.113.7";
        for i in 0..(FAILED_AUTH_THRESHOLD - 1) {
            assert!(
                t.record_failure(ip).is_none(),
                "should not lock before threshold (i={i})"
            );
            assert!(t.locked_remaining(ip).is_none());
        }
        // Final failure trips the lockout.
        let lockout = t.record_failure(ip).expect("lockout triggered");
        assert_eq!(lockout, FAILED_AUTH_INITIAL_LOCKOUT_SECS);
        let remaining = t.locked_remaining(ip).expect("locked");
        assert!(remaining > 0 && remaining <= FAILED_AUTH_INITIAL_LOCKOUT_SECS);
    }

    #[test]
    fn failed_auth_tracker_exempts_loopback() {
        let mut t = FailedAuthTracker::new();
        for _ in 0..(FAILED_AUTH_THRESHOLD + 3) {
            assert!(t.record_failure("127.0.0.1").is_none());
        }
        assert!(t.locked_remaining("127.0.0.1").is_none());
        assert!(t.locked_remaining("::1").is_none());
        assert!(t.locked_remaining("unknown").is_none());
    }

    #[test]
    fn failed_auth_tracker_success_resets_counter() {
        let mut t = FailedAuthTracker::new();
        let ip = "198.51.100.4";
        for _ in 0..(FAILED_AUTH_THRESHOLD - 1) {
            assert!(t.record_failure(ip).is_none());
        }
        t.record_success(ip);
        // Counter has been cleared, so one more failure should not lock.
        assert!(t.record_failure(ip).is_none());
        assert!(t.locked_remaining(ip).is_none());
    }

    #[test]
    fn failed_auth_tracker_backoff_doubles() {
        let mut t = FailedAuthTracker::new();
        let ip = "198.51.100.99";
        // First lockout window.
        for _ in 0..FAILED_AUTH_THRESHOLD {
            t.record_failure(ip);
        }
        let stored = t.entries.get(ip).expect("entry");
        // After the first lockout, the next lockout window doubles (cap-bounded).
        assert!(stored.lockout_secs >= FAILED_AUTH_INITIAL_LOCKOUT_SECS * 2);
        assert!(stored.lockout_secs <= FAILED_AUTH_MAX_LOCKOUT_SECS);
    }

    fn temp_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "wardex_server_{}_{}_{}.json",
            name,
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        path
    }

    fn wait_until(timeout: Duration, mut predicate: impl FnMut() -> bool) {
        let deadline = Instant::now() + timeout;
        loop {
            if predicate() {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "condition not met before timeout"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    #[test]
    fn collector_ingestion_sla_and_summary_surface_breach_details() {
        let lifecycle = vec![
            serde_json::json!({ "lag_seconds": 60 }),
            serde_json::json!({ "lag_seconds": 120 }),
        ];
        let breached = crate::server_collectors::collector_ingestion_sla_payload(
            true,
            30,
            Some(400),
            2,
            &lifecycle,
        );

        assert_eq!(breached["status"], serde_json::json!("breach"));
        assert_eq!(breached["target_lag_seconds"], serde_json::json!(300));
        assert_eq!(breached["breach"], serde_json::json!(true));
        assert_eq!(
            breached["breach_reasons"],
            serde_json::json!(["lag_exceeded", "queue_backlog"])
        );
        assert_eq!(
            breached["lag_percentiles"]["sample_count"],
            serde_json::json!(3)
        );
        assert_eq!(
            breached["lag_percentiles"]["p99_seconds"],
            serde_json::json!(400)
        );

        let healthy =
            crate::server_collectors::collector_ingestion_sla_payload(true, 600, Some(10), 0, &[]);
        let disabled =
            crate::server_collectors::collector_ingestion_sla_payload(false, 600, None, 0, &[]);
        let summary = crate::server_collectors::collector_sla_summary(&[
            serde_json::json!({
                "enabled": true,
                "lag_seconds": 400,
                "queue_depth": 2,
                "ingestion_sla": breached,
            }),
            serde_json::json!({
                "enabled": true,
                "lag_seconds": 10,
                "queue_depth": 0,
                "ingestion_sla": healthy,
            }),
            serde_json::json!({
                "enabled": false,
                "lag_seconds": 0,
                "queue_depth": 0,
                "ingestion_sla": disabled,
            }),
        ]);

        assert_eq!(summary["status"], serde_json::json!("breach"));
        assert_eq!(summary["enabled_collectors"], serde_json::json!(2));
        assert_eq!(summary["breaching_collectors"], serde_json::json!(1));
        assert_eq!(summary["worst_lag_seconds"], serde_json::json!(400));
        assert_eq!(summary["total_queue_depth"], serde_json::json!(2));
    }

    #[test]
    fn rbac_coverage_payload_lists_operator_proof_routes() {
        let payload = rbac_coverage_payload();
        assert_eq!(payload["status"], serde_json::json!("covered"));
        assert_eq!(payload["coverage_pct"], serde_json::json!(100.0));

        let roles = payload["roles"].as_array().expect("roles array");
        assert!(
            roles
                .iter()
                .any(|role| role["role"] == serde_json::json!("service_account"))
        );

        let routes = payload["routes"].as_array().expect("routes array");
        let rbac_route = routes
            .iter()
            .find(|route| route["path"] == serde_json::json!("/api/admin/rbac-coverage"))
            .expect("rbac coverage route");
        assert_eq!(
            rbac_route["guard"],
            serde_json::json!("endpoint_permission")
        );
        assert!(
            rbac_route["allowed_roles"]
                .as_array()
                .expect("allowed roles")
                .iter()
                .any(|role| role == "admin")
        );

        let execution_audit_route = routes
            .iter()
            .find(|route| route["path"] == serde_json::json!("/api/response/execution-audit"))
            .expect("response execution audit route");
        assert_eq!(
            execution_audit_route["permission"],
            serde_json::json!("ViewAuditLog")
        );
        assert_eq!(
            execution_audit_route["guard"],
            serde_json::json!("endpoint_permission")
        );
    }

    #[test]
    fn operator_trust_endpoints_return_structured_payloads() {
        let (port, token, _state) = spawn_test_server_with_state();
        let base_url = format!("http://127.0.0.1:{port}");
        let agent = ureq::AgentBuilder::new().build();

        let feedback_response: serde_json::Value = serde_json::from_str(
            &agent
                .post(&format!("{base_url}/api/alerts/feedback"))
                .set("Authorization", &format!("Bearer {token}"))
                .send_string(
                    r#"{"alert_id":"latest","state":"false_positive","reason":"test_noise","analyst":"test"}"#,
                )
                .expect("alert feedback response")
                .into_string()
                .expect("alert feedback body"),
        )
        .expect("alert feedback json");
        assert_eq!(feedback_response["recorded"], serde_json::json!(true));
        assert_eq!(feedback_response["auto_tuning"], serde_json::json!(false));

        for path in [
            "/api/operator/workspaces",
            "/api/alerts/evidence-chain",
            "/api/detection-lab/status",
            "/api/response/safety",
            "/api/integrations/marketplace",
            "/api/operations/health",
            "/api/malware/explain",
        ] {
            let response: serde_json::Value = serde_json::from_str(
                &agent
                    .get(&format!("{base_url}{path}"))
                    .set("Authorization", &format!("Bearer {token}"))
                    .call()
                    .unwrap_or_else(|error| panic!("{path} response failed: {error}"))
                    .into_string()
                    .unwrap_or_else(|error| panic!("{path} body failed: {error}")),
            )
            .unwrap_or_else(|error| panic!("{path} json failed: {error}"));
            assert!(
                response.get("generated_at").is_some()
                    || response.get("navigation_groups").is_some()
                    || response.get("summary").is_some(),
                "{path} should expose structured operator trust data"
            );
        }
    }

    #[test]
    fn response_execution_audit_endpoint_links_request_approval_and_execution() {
        let (port, token, state) = spawn_test_server_with_state();
        let base_url = format!("http://127.0.0.1:{port}");
        let auth_header = format!("Bearer {token}");
        let submit_auth_header = {
            let state = state.lock().unwrap_or_else(|e| e.into_inner());
            let session_id = state.session_store.create_session(
                "analyst-1",
                "analyst-1@local.wardex",
                "admin",
                &["wardex-admins".to_string()],
                1,
            );
            format!("Bearer {session_id}")
        };
        let agent = ureq::AgentBuilder::new().build();

        let submitted: serde_json::Value = agent
            .post(&format!("{base_url}/api/response/request"))
            .set("Authorization", &submit_auth_header)
            .send_json(serde_json::json!({
                "action": "kill_process",
                "hostname": "audit-host",
                "pid": 31337,
                "process_name": "suspicious-worker",
                "reason": "integration audit proof",
                "severity": "high"
            }))
            .expect("submit response request")
            .into_json()
            .expect("submitted json");
        let request_id = submitted["request"]["id"]
            .as_str()
            .expect("submitted request id")
            .to_string();

        let approved: serde_json::Value = agent
            .post(&format!("{base_url}/api/response/approve"))
            .set("Authorization", &auth_header)
            .send_json(serde_json::json!({
                "request_id": request_id.clone(),
                "decision": "approved",
                "approver": "admin",
                "reason": "blast radius reviewed"
            }))
            .expect("approve response request")
            .into_json()
            .expect("approved json");
        assert_eq!(approved["status"], serde_json::json!("Approved"));

        let executed: serde_json::Value = agent
            .post(&format!("{base_url}/api/response/execute"))
            .set("Authorization", &auth_header)
            .send_json(serde_json::json!({ "request_id": request_id.clone() }))
            .expect("execute response request")
            .into_json()
            .expect("executed json");
        assert_eq!(executed["executed_count"], serde_json::json!(1));

        let audit: serde_json::Value = agent
            .get(&format!(
                "{base_url}/api/response/execution-audit?request_id={request_id}&action_id=kill-process"
            ))
            .set("Authorization", &auth_header)
            .call()
            .expect("execution audit response")
            .into_json()
            .expect("execution audit json");
        assert_eq!(audit["count"], serde_json::json!(1));
        assert_eq!(
            audit["audits"][0]["request_id"],
            serde_json::json!(request_id)
        );
        assert_eq!(audit["audits"][0]["operator"], serde_json::json!("admin"));
        // PID 31337 is not present on the test node, so the local enforcement
        // engine honestly reports the kill as not executed rather than
        // fabricating success.
        assert_eq!(
            audit["audits"][0]["verification_status"],
            serde_json::json!("not_executed")
        );
        assert!(
            audit["audits"][0]["commands"][0]["command"]
                .as_str()
                .expect("command string")
                .contains("--pid 31337")
        );
    }

    #[test]
    fn integrations_marketplace_surfaces_export_and_ticketing_cards() {
        let (port, token, state) = spawn_test_server_with_state();
        {
            let mut s = state.lock().unwrap_or_else(|error| error.into_inner());
            let splunk_config = crate::siem::SiemConfig {
                enabled: true,
                siem_type: "splunk".to_string(),
                endpoint: "https://splunk.example/services/collector".to_string(),
                auth_token: "test-hec-token".to_string(),
                index: "security_events".to_string(),
                source_type: "wardex:xdr".to_string(),
                ..crate::siem::SiemConfig::default()
            };
            s.config.siem = splunk_config.clone();
            s.siem_connector.update_config(splunk_config);
            let _ = s.enterprise.sync_ticket(
                "servicenow".to_string(),
                "case".to_string(),
                "42".to_string(),
                Some("SECOPS".to_string()),
                "Escalate identity investigation to the service desk".to_string(),
                "tester".to_string(),
            );
            s.enterprise.record_ticket_sync_metrics(120);
        }

        let base_url = format!("http://127.0.0.1:{port}");
        let agent = ureq::AgentBuilder::new().build();
        let marketplace: serde_json::Value = serde_json::from_str(
            &agent
                .get(&format!("{base_url}/api/integrations/marketplace"))
                .set("Authorization", &format!("Bearer {token}"))
                .call()
                .expect("marketplace response")
                .into_string()
                .expect("marketplace body"),
        )
        .expect("marketplace json");

        let connectors = marketplace["connectors"]
            .as_array()
            .expect("connectors array");
        let splunk = connectors
            .iter()
            .find(|entry| entry["id"] == serde_json::json!("splunk_hec"))
            .expect("splunk marketplace card");
        assert_eq!(splunk["setup_status"], serde_json::json!("configured"));
        assert_eq!(splunk["validation"]["status"], serde_json::json!("ready"));
        assert_eq!(
            splunk["destination"],
            serde_json::json!("security_events / wardex:xdr")
        );
        assert_eq!(
            splunk["action_href"],
            serde_json::json!("/settings?tab=integrations")
        );

        let servicenow = connectors
            .iter()
            .find(|entry| entry["id"] == serde_json::json!("servicenow"))
            .expect("servicenow marketplace card");
        assert_eq!(servicenow["setup_status"], serde_json::json!("configured"));
        assert_eq!(
            servicenow["validation"]["status"],
            serde_json::json!("ready")
        );
        assert_eq!(
            servicenow["sync_status"]["latest_queue_or_project"],
            serde_json::json!("SECOPS")
        );
        assert_eq!(servicenow["action_href"], serde_json::json!("/soc#cases"));
    }

    #[test]
    fn detection_trust_endpoints_are_draft_only_and_normalized() {
        let (port, token, _state) = spawn_test_server_with_state();
        let base_url = format!("http://127.0.0.1:{port}");
        let agent = ureq::AgentBuilder::new().build();

        let feedback_response: serde_json::Value = serde_json::from_str(
            &agent
                .post(&format!("{base_url}/api/detection/feedback"))
                .set("Authorization", &format!("Bearer {token}"))
                .send_string(
                    r#"{"rule_id":"test-rule","analyst":"unit","verdict":"fp","reason_pattern":"release test","notes":"normalize outcome"}"#,
                )
                .expect("detection feedback response")
                .into_string()
                .expect("detection feedback body"),
        )
        .expect("detection feedback json");
        assert_eq!(
            feedback_response["verdict"],
            serde_json::json!("false_positive")
        );

        let overview: serde_json::Value = serde_json::from_str(
            &agent
                .get(&format!("{base_url}/api/detection/trust/overview"))
                .set("Authorization", &format!("Bearer {token}"))
                .call()
                .expect("trust overview response")
                .into_string()
                .expect("trust overview body"),
        )
        .expect("trust overview json");
        assert_eq!(overview["draft_only_tuning"], serde_json::json!(true));
        assert_eq!(overview["auto_apply"], serde_json::json!(false));
        assert!(
            overview["states"]
                .as_array()
                .unwrap()
                .iter()
                .any(|state| state == "false_positive")
        );

        let rules: serde_json::Value = serde_json::from_str(
            &agent
                .get(&format!("{base_url}/api/detection/trust/rules"))
                .set("Authorization", &format!("Bearer {token}"))
                .call()
                .expect("trust rules response")
                .into_string()
                .expect("trust rules body"),
        )
        .expect("trust rules json");
        assert!(rules["rules"].as_array().is_some());

        let created: serde_json::Value = serde_json::from_str(
            &agent
                .post(&format!("{base_url}/api/detection/trust/tuning-drafts"))
                .set("Authorization", &format!("Bearer {token}"))
                .send_string(
                    r#"{"rule_id":"test-rule","draft_type":"noisy_rule_review","analyst_note":"unit test"}"#,
                )
                .expect("draft create response")
                .into_string()
                .expect("draft create body"),
        )
        .expect("draft create json");
        assert_eq!(created["created"], serde_json::json!(true));
        assert_eq!(created["draft"]["auto_apply"], serde_json::json!(false));

        let preview: serde_json::Value = serde_json::from_str(
            &agent
                .post(&format!(
                    "{base_url}/api/detection/trust/tuning-drafts/noisy_rule_review-test-rule/preview"
                ))
                .set("Authorization", &format!("Bearer {token}"))
                .send_string("{}")
                .expect("draft preview response")
                .into_string()
                .expect("draft preview body"),
        )
        .expect("draft preview json");
        assert_eq!(preview["auto_apply"], serde_json::json!(false));

        let approval: serde_json::Value = serde_json::from_str(
            &agent
                .post(&format!(
                    "{base_url}/api/detection/trust/tuning-drafts/noisy_rule_review-test-rule/approve"
                ))
                .set("Authorization", &format!("Bearer {token}"))
                .send_string("{}")
                .expect("draft approval response")
                .into_string()
                .expect("draft approval body"),
        )
        .expect("draft approval json");
        assert_eq!(approval["approved"], serde_json::json!(true));
        assert_eq!(approval["applied"], serde_json::json!(false));
    }

    #[test]
    fn backup_records_ignore_non_backup_files() {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "wardex_backup_status_{}_{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        fs::create_dir_all(&dir).expect("create backup status dir");

        fs::write(dir.join(".DS_Store"), b"finder-noise").expect("write ds_store");
        fs::write(dir.join("notes.txt"), b"operator notes").expect("write notes");
        fs::write(
            dir.join("wardex_backup_20260502_000000.db"),
            b"sqlite-backup-artifact",
        )
        .expect("write backup artifact");

        let records = backup_records_in_dir(&dir);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, "wardex_backup_20260502_000000.db");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn failover_drill_endpoint_records_latest_result() {
        let (port, token, state) = spawn_test_server_with_state();
        {
            let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
            state.detector.evaluate(&TelemetrySample {
                timestamp_ms: 1_000,
                cpu_load_pct: 21.0,
                memory_load_pct: 34.0,
                temperature_c: 41.0,
                network_kbps: 18.0,
                auth_failures: 0,
                battery_pct: 96.0,
                integrity_drift: 0.01,
                process_count: 81,
                disk_pressure_pct: 12.0,
            });
            let snapshot = state.detector.snapshot().expect("detector snapshot");
            let device_state = state.device.snapshot();
            state.checkpoints.push_snapshot(snapshot, device_state);
        }

        let base_url = format!("http://127.0.0.1:{port}");
        let auth_header = format!("Bearer {token}");

        let drill: serde_json::Value =
            ureq::post(&format!("{base_url}/api/control/failover-drill"))
                .set("Authorization", &auth_header)
                .call()
                .expect("run failover drill")
                .into_json()
                .expect("failover drill json");
        assert_eq!(drill["drill"]["status"], serde_json::json!("passed"));
        assert_eq!(
            drill["drill"]["artifact_source"],
            serde_json::json!("checkpoint")
        );
        assert_eq!(
            drill["drill"]["orchestration_scope"],
            serde_json::json!("standalone_reference")
        );
        assert!(drill["drill"]["last_run_at"].as_str().is_some());
        assert!(drill["digest"].as_str().unwrap_or_default().len() >= 32);

        let readiness: serde_json::Value =
            ureq::get(&format!("{base_url}/api/support/readiness-evidence"))
                .set("Authorization", &auth_header)
                .call()
                .expect("support readiness evidence")
                .into_json()
                .expect("support readiness json");
        assert_eq!(
            readiness["evidence"]["control_plane"]["failover_drill"]["status"],
            serde_json::json!("passed")
        );
        assert_eq!(
            readiness["evidence"]["control_plane"]["failover_drill"]["artifact_source"],
            serde_json::json!("checkpoint")
        );
        assert_eq!(
            readiness["evidence"]["control_plane"]["recovery_targets"][0]["scenario"],
            serde_json::json!("Config corruption")
        );
        assert_eq!(
            readiness["evidence"]["control_plane"]["recovery_targets"][0]["rto"],
            serde_json::json!("< 5 min")
        );

        let dependencies: serde_json::Value =
            ureq::get(&format!("{base_url}/api/system/health/dependencies"))
                .set("Authorization", &auth_header)
                .call()
                .expect("dependency health")
                .into_json()
                .expect("dependency health json");
        assert_eq!(
            dependencies["ha_mode"]["failover_drill"]["status"],
            serde_json::json!("passed")
        );
    }

    #[test]
    fn clustered_failover_posture_surfaces_external_standby_and_history() {
        let (leader_port, _leader_token, leader_state) = spawn_test_server_with_state();
        let (port, token, state) = spawn_test_server_with_state();
        let cluster_token = "cluster-runtime-token".to_string();

        {
            let mut leader = leader_state.lock().unwrap_or_else(|e| e.into_inner());
            leader.config.cluster.node_id = crate::cluster::NodeId("cluster-node-1".to_string());
            leader.config.cluster.auth_token = Some(cluster_token.clone());
            leader.config.cluster.heartbeat_interval_ms = 25;
            leader.config.cluster.election_timeout_ms = 90;
            leader.config.cluster.peers = vec![crate::cluster::PeerConfig {
                node_id: crate::cluster::NodeId("cluster-node-2".to_string()),
                addr: format!("http://127.0.0.1:{port}"),
            }];
            leader.cluster = ClusterNode::new(leader.config.cluster.clone());
        }

        let support_store_path = {
            let mut follower = state.lock().unwrap_or_else(|e| e.into_inner());
            follower.config.cluster.node_id = crate::cluster::NodeId("cluster-node-2".to_string());
            follower.config.cluster.auth_token = Some(cluster_token);
            follower.config.cluster.heartbeat_interval_ms = 25;
            follower.config.cluster.election_timeout_ms = 10_000;
            follower.config.cluster.peers = vec![crate::cluster::PeerConfig {
                node_id: crate::cluster::NodeId("cluster-node-1".to_string()),
                addr: format!("http://127.0.0.1:{leader_port}"),
            }];
            follower.cluster = ClusterNode::new(follower.config.cluster.clone());

            follower.detector.evaluate(&TelemetrySample {
                timestamp_ms: 2_000,
                cpu_load_pct: 25.0,
                memory_load_pct: 39.0,
                temperature_c: 43.0,
                network_kbps: 21.0,
                auth_failures: 0,
                battery_pct: 94.0,
                integrity_drift: 0.01,
                process_count: 84,
                disk_pressure_pct: 14.0,
            });
            let snapshot = follower.detector.snapshot().expect("detector snapshot");
            let device_state = follower.device.snapshot();
            follower.checkpoints.push_snapshot(snapshot, device_state);

            follower
                .config_path
                .parent()
                .expect("state root")
                .join("support.json")
        };

        let base_url = format!("http://127.0.0.1:{port}");
        let auth_header = format!("Bearer {token}");

        wait_until(Duration::from_secs(10), || {
            let response = ureq::get(&format!("{base_url}/api/support/readiness-evidence"))
                .set("Authorization", &auth_header)
                .call();
            let Ok(response) = response else {
                return false;
            };
            let Ok(readiness) = response.into_json::<serde_json::Value>() else {
                return false;
            };
            readiness["evidence"]["control_plane"]["cluster"]["leader_id"]
                == serde_json::json!("cluster-node-1")
                && readiness["evidence"]["control_plane"]["cluster"]["peers_reachable"]
                    == serde_json::json!(1)
                && readiness["evidence"]["control_plane"]["cluster"]["healthy"]
                    == serde_json::json!(true)
        });

        let drill: serde_json::Value =
            ureq::post(&format!("{base_url}/api/control/failover-drill"))
                .set("Authorization", &auth_header)
                .call()
                .expect("run clustered failover drill")
                .into_json()
                .expect("clustered failover drill json");
        assert_eq!(
            drill["drill"]["orchestration_scope"],
            serde_json::json!("non_standalone_orchestrated")
        );
        assert_eq!(
            drill["drill"]["drill_type"],
            serde_json::json!("leader_handoff_restore_dry_run")
        );

        let readiness: serde_json::Value =
            ureq::get(&format!("{base_url}/api/support/readiness-evidence"))
                .set("Authorization", &auth_header)
                .call()
                .expect("clustered support readiness evidence")
                .into_json()
                .expect("clustered support readiness json");
        assert_eq!(
            readiness["evidence"]["control_plane"]["topology"],
            serde_json::json!("clustered")
        );
        assert_eq!(
            readiness["evidence"]["control_plane"]["ha_mode"],
            serde_json::json!("external_standby")
        );
        assert_eq!(
            readiness["evidence"]["control_plane"]["cluster"]["role"],
            serde_json::json!("follower")
        );
        assert_eq!(
            readiness["evidence"]["control_plane"]["cluster"]["leader_id"],
            serde_json::json!("cluster-node-1")
        );
        assert_eq!(
            readiness["evidence"]["control_plane"]["cluster"]["primary_region"],
            serde_json::json!("local-lab")
        );
        assert_eq!(
            readiness["evidence"]["control_plane"]["cluster"]["replication_health"],
            serde_json::json!("healthy")
        );
        assert_eq!(
            readiness["evidence"]["control_plane"]["cluster"]["replica_lag_entries"],
            serde_json::json!(0)
        );
        assert_eq!(
            readiness["evidence"]["control_plane"]["failover_drill_history"][0]["status"],
            serde_json::json!("passed")
        );
        assert_eq!(
            readiness["evidence"]["control_plane"]["failover_drill_history"][0]["orchestration_scope"],
            serde_json::json!("non_standalone_orchestrated")
        );

        let dependencies: serde_json::Value =
            ureq::get(&format!("{base_url}/api/system/health/dependencies"))
                .set("Authorization", &auth_header)
                .call()
                .expect("clustered dependency health")
                .into_json()
                .expect("clustered dependency health json");
        assert_eq!(
            dependencies["ha_mode"]["mode"],
            serde_json::json!("external_standby")
        );
        assert_eq!(
            dependencies["ha_mode"]["topology"],
            serde_json::json!("clustered")
        );
        assert_eq!(
            dependencies["ha_mode"]["cluster"]["role"],
            serde_json::json!("follower")
        );
        assert_eq!(
            dependencies["ha_mode"]["cluster"]["peers_reachable"],
            serde_json::json!(1)
        );
        assert_eq!(
            dependencies["ha_mode"]["cluster"]["healthy"],
            serde_json::json!(true)
        );
        assert_eq!(
            dependencies["ha_mode"]["status"],
            serde_json::json!("ready_for_orchestrated_failover")
        );
        assert_eq!(
            dependencies["ha_mode"]["failover_drill_history_count"],
            serde_json::json!(1)
        );

        let failover = {
            let state = state.lock().unwrap_or_else(|e| e.into_inner());
            build_cluster_failover_execution(&state)
        };
        assert_eq!(
            failover["cluster"]["replication_health"],
            serde_json::json!("healthy")
        );
        assert_eq!(
            failover["cluster"]["replica_lag_entries"],
            serde_json::json!(0)
        );
        assert!(
            failover["checks"]
                .as_array()
                .expect("failover checks")
                .iter()
                .any(|check| check["id"] == serde_json::json!("replication_health"))
        );

        let reloaded = SupportStore::new(&support_store_path.to_string_lossy());
        assert_eq!(
            reloaded
                .latest_failover_drill()
                .expect("persisted failover drill")
                .orchestration_scope,
            "non_standalone_orchestrated"
        );
    }

    #[test]
    fn failover_history_report_run_emits_standalone_artifact_preview() {
        let (port, token, state) = spawn_test_server_with_state();
        {
            let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
            state.detector.evaluate(&TelemetrySample {
                timestamp_ms: 3_000,
                cpu_load_pct: 24.0,
                memory_load_pct: 33.0,
                temperature_c: 42.0,
                network_kbps: 17.0,
                auth_failures: 0,
                battery_pct: 97.0,
                integrity_drift: 0.01,
                process_count: 82,
                disk_pressure_pct: 11.0,
            });
            let snapshot = state.detector.snapshot().expect("detector snapshot");
            let device_state = state.device.snapshot();
            state.checkpoints.push_snapshot(snapshot, device_state);
        }

        let base_url = format!("http://127.0.0.1:{port}");
        let auth_header = format!("Bearer {token}");

        let drill: serde_json::Value =
            ureq::post(&format!("{base_url}/api/control/failover-drill"))
                .set("Authorization", &auth_header)
                .call()
                .expect("run failover drill for report preview")
                .into_json()
                .expect("failover drill json");
        assert_eq!(drill["drill"]["status"], serde_json::json!("passed"));

        let run_request = serde_json::json!({
            "name": "Failover Drill History",
            "kind": "control_plane_failover_history",
            "scope": "control_plane",
            "format": "json",
            "audience": "audit"
        });
        let run: serde_json::Value = ureq::post(&format!("{base_url}/api/report-runs"))
            .set("Authorization", &auth_header)
            .send_string(&run_request.to_string())
            .expect("create failover history report run")
            .into_json()
            .expect("report run json");

        assert_eq!(
            run["run"]["kind"],
            serde_json::json!("control_plane_failover_history")
        );
        assert_eq!(
            run["run"]["preview"]["kind"],
            serde_json::json!("control_plane_failover_history")
        );
        assert_eq!(run["run"]["preview"]["drill_count"], serde_json::json!(1));
        assert_eq!(
            run["run"]["preview"]["latest_drill"]["status"],
            serde_json::json!("passed")
        );
        assert_eq!(
            run["run"]["preview"]["history"][0]["artifact_source"],
            serde_json::json!("checkpoint")
        );

        let run_id = run["run"]["id"]
            .as_str()
            .expect("report run id")
            .to_string();
        let listed: serde_json::Value = ureq::get(&format!("{base_url}/api/report-runs"))
            .set("Authorization", &auth_header)
            .call()
            .expect("list report runs")
            .into_json()
            .expect("report runs json");
        assert!(
            listed["runs"]
                .as_array()
                .expect("report runs array")
                .iter()
                .any(|entry| {
                    entry["id"] == serde_json::json!(run_id)
                        && entry["preview"]["kind"]
                            == serde_json::json!("control_plane_failover_history")
                        && entry["preview"]["history"][0]["status"] == serde_json::json!("passed")
                })
        );
    }

    fn sample_alert(hostname: &str, level: &str, score: f32, reason: &str) -> AlertRecord {
        AlertRecord {
            timestamp: chrono::Utc::now().to_rfc3339(),
            hostname: hostname.to_string(),
            platform: "linux".to_string(),
            score,
            confidence: 0.95,
            level: level.to_string(),
            action: "alert".to_string(),
            reasons: vec![reason.to_string()],
            sample: TelemetrySample {
                timestamp_ms: 0,
                cpu_load_pct: 72.0,
                memory_load_pct: 61.0,
                temperature_c: 51.0,
                network_kbps: 240.0,
                auth_failures: 0,
                battery_pct: 100.0,
                integrity_drift: 0.02,
                process_count: 88,
                disk_pressure_pct: 18.0,
            },
            enforced: false,
            mitre: Vec::new(),
            narrative: None,
        }
    }

    #[test]
    fn alert_histogram_filters_by_severity() {
        let mut alerts = VecDeque::new();
        alerts.push_back(sample_alert("alpha", "high", 0.91, "credential storm"));
        alerts.push_back(sample_alert("beta", "low", 0.21, "baseline"));

        let payload = build_alert_histogram(&alerts, 60 * 60, 60 * 60, Some("high"));

        assert_eq!(payload["total"], serde_json::json!(1));
        assert_eq!(
            payload["buckets"][0]["severity_breakdown"]["high"],
            serde_json::json!(1)
        );
    }

    #[test]
    fn stream_readiness_degrades_on_drops() {
        let payload = stream_readiness_payload(serde_json::json!({
            "subscriber_queue_depth": 150,
            "max_observed_queue_depth": 200,
            "dropped_events": 20,
            "latency_slo_ms": 1000,
        }));

        assert_eq!(payload["status"], serde_json::json!("backpressure"));
        assert_eq!(
            payload["promotion_guard"],
            serde_json::json!("recover_stream_first")
        );
    }

    #[test]
    fn stream_reliability_lab_flags_dropped_events() {
        let payload = stream_reliability_lab_payload(serde_json::json!({
            "subscriber_queue_depth": 12,
            "max_observed_queue_depth": 20,
            "dropped_events": 3,
            "latency_slo_ms": 1000,
        }));

        assert_eq!(payload["status"], serde_json::json!("fail"));
        assert!(
            payload["scenarios"]
                .as_array()
                .unwrap()
                .iter()
                .any(|scenario| {
                    scenario["id"] == serde_json::json!("drop_detection")
                        && scenario["status"] == serde_json::json!("fail")
                })
        );
    }

    #[test]
    fn support_redaction_removes_nested_sensitive_values() {
        let mut payload = serde_json::json!({
            "safe": "visible",
            "nested": { "api_key": "secret", "token_hint": "secret" },
            "items": [{ "password": "secret" }],
        });
        let mut redacted = Vec::new();

        redact_support_payload(&mut payload, "", &mut redacted);

        assert_eq!(payload["safe"], serde_json::json!("visible"));
        assert_eq!(
            payload["nested"]["api_key"],
            serde_json::json!("[REDACTED]")
        );
        assert_eq!(
            payload["items"][0]["password"],
            serde_json::json!("[REDACTED]")
        );
        assert!(redacted.iter().any(|path| path == "nested.api_key"));
    }

    #[test]
    fn snapshot_entry_verifies_digest() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("operational_snapshots");
        let dir = root.join("stream_readiness");
        fs::create_dir_all(&dir).expect("snapshot dir");
        let payload = serde_json::json!({ "status": "ready", "score": 99 });
        let digest = crate::audit::sha256_hex(payload.to_string().as_bytes());
        let path = dir.join("1-test.json");
        fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "kind": "stream_readiness",
                "digest": digest,
                "generated_at": "2026-05-08T00:00:00Z",
                "payload": payload,
            }))
            .unwrap(),
        )
        .expect("write snapshot");

        let entry = snapshot_entry_from_path(&root, &path, false).expect("entry");

        assert_eq!(entry["verified"], serde_json::json!(true));
        assert_eq!(
            entry["storage_key"],
            serde_json::json!("operational_snapshots/stream_readiness/1-test.json")
        );
    }

    #[test]
    fn product_contract_endpoint_inventory_is_complete() {
        let catalog = crate::openapi::endpoint_catalog(env!("CARGO_PKG_VERSION"));
        assert!(product_contract_missing_from_catalog(&catalog).is_empty());
        assert!(
            product_contract_missing_from_source(include_str!("../docs/openapi.yaml")).is_empty()
        );
        assert!(
            product_contract_missing_from_source(include_str!("../scripts/release_acceptance.sh"))
                .is_empty()
        );
    }

    #[test]
    fn release_readiness_builders_expose_operator_evidence() {
        let (_port, _token, state) = spawn_test_server_with_state();
        let state = state.lock().unwrap_or_else(|e| e.into_inner());

        let clean_cut = build_clean_release_cut(&state);
        assert_eq!(
            clean_cut["target_version"],
            serde_json::json!(env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(
            clean_cut["synthetic_console"]["mode"],
            serde_json::json!("clean_cut_summary")
        );
        assert!(clean_cut["release_steps"].as_array().unwrap().len() >= 4);

        let verification = build_release_verification_center(&state);
        assert!(verification["verify_commands"].as_array().unwrap().len() >= 4);

        let deployment = build_self_hosted_deployment_wizard(&state);
        assert!(deployment["install_plans"].as_array().unwrap().len() >= 4);

        let data_quality = build_data_quality_dashboard(&state);
        assert_eq!(data_quality["slo_summary"]["total"], serde_json::json!(4));

        let performance = build_performance_scale_baseline(&state);
        assert!(performance["load_gate"].as_array().unwrap().len() >= 4);

        let failover = build_cluster_failover_execution(&state);
        assert_eq!(
            failover["drill_execution"]["execute_api"],
            serde_json::json!("/api/control/failover-drill")
        );

        let secrets = build_secrets_rotation_operations(&state);
        assert!(secrets["dry_runs"].as_array().unwrap().len() >= 5);

        let automation = build_operator_task_automation(&state);
        assert_eq!(
            automation["mutation_guard"]["status"],
            serde_json::json!("dry_run_only")
        );

        let validation = build_detection_validation_packs(&state);
        assert_eq!(validation["pack_count"], serde_json::json!(5));
        assert_eq!(
            validation["suite_execution"]["command"],
            serde_json::json!("bash scripts/detection_validation_packs.sh")
        );
    }

    fn enroll_test_agent(
        registry: &mut AgentRegistry,
        hostname: &str,
        platform: &str,
        version: &str,
    ) -> String {
        let token = registry.create_token(1);
        registry
            .enroll(&EnrollRequest {
                enrollment_token: token.token,
                hostname: hostname.to_string(),
                platform: platform.to_string(),
                version: version.to_string(),
                labels: None,
            })
            .expect("enroll test agent")
            .agent_id
    }

    fn completed_canary_deployment(
        agent_id: &str,
        release: &crate::auto_update::Release,
    ) -> AgentDeployment {
        AgentDeployment {
            agent_id: agent_id.to_string(),
            version: release.version.clone(),
            platform: release.platform.clone(),
            mandatory: release.mandatory,
            release_notes: release.release_notes.clone(),
            status: "applied".to_string(),
            status_reason: None,
            rollout_group: "canary".to_string(),
            allow_downgrade: false,
            signature_status: Some("signed".to_string()),
            signer_pubkey: release.signer_pubkey.clone(),
            signature_payload_sha256: release.signature_payload_sha256.clone(),
            update_counter: release.update_counter,
            assigned_at: chrono::Utc::now().to_rfc3339(),
            acknowledged_at: Some(chrono::Utc::now().to_rfc3339()),
            completed_at: Some((chrono::Utc::now() - chrono::Duration::seconds(5)).to_rfc3339()),
            last_heartbeat_at: None,
        }
    }

    #[test]
    fn auto_progress_records_verified_update_signature_metadata() {
        let (_port, _token, state) = spawn_test_server_with_state();
        let (canary_id, ring_id, signer_pubkey, payload_hash, counter) = {
            let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
            state.config.rollout.auto_progress = true;
            state.config.rollout.canary_soak_secs = 0;
            state.config.security.update_signing.require_signed_updates = true;
            let canary_id =
                enroll_test_agent(&mut state.agent_registry, "canary-host", "linux", "1.0.0");
            let ring_id =
                enroll_test_agent(&mut state.agent_registry, "ring-host", "linux", "1.0.0");
            let release = state
                .update_manager
                .publish_signed_release(
                    "2.0.0",
                    "linux",
                    b"trusted update binary",
                    "trusted rollout",
                    true,
                    &[7u8; 32],
                )
                .expect("signed release");
            state.remote_deployments.insert(
                canary_id.clone(),
                completed_canary_deployment(&canary_id, &release),
            );
            (
                canary_id,
                ring_id,
                release.signer_pubkey.clone(),
                release.signature_payload_sha256.clone(),
                release.update_counter,
            )
        };

        let body = serde_json::json!({ "version": "2.0.0" }).to_string();
        let response =
            crate::server_agents::handle_agent_heartbeat(body.as_bytes(), &state, &canary_id);
        assert_eq!(response.status(), StatusCode::OK);

        let state = state.lock().unwrap_or_else(|e| e.into_inner());
        let deployment = state
            .remote_deployments
            .get(&ring_id)
            .expect("next-ring deployment should be assigned");
        assert_eq!(deployment.rollout_group, "ring-1");
        assert_eq!(
            deployment.status_reason.as_deref(),
            Some("auto_progress_ring-1")
        );
        assert_eq!(deployment.signature_status.as_deref(), Some("signed"));
        assert_eq!(deployment.signer_pubkey, signer_pubkey);
        assert_eq!(deployment.signature_payload_sha256, payload_hash);
        assert_eq!(deployment.update_counter, counter);
    }

    #[test]
    fn auto_progress_rejects_untrusted_signed_release() {
        let (_port, _token, state) = spawn_test_server_with_state();
        let (canary_id, ring_id) = {
            let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
            state.config.rollout.auto_progress = true;
            state.config.rollout.canary_soak_secs = 0;
            state.config.security.update_signing.require_signed_updates = true;
            let canary_id = enroll_test_agent(
                &mut state.agent_registry,
                "canary-untrusted",
                "linux",
                "1.0.0",
            );
            let ring_id = enroll_test_agent(
                &mut state.agent_registry,
                "ring-untrusted",
                "linux",
                "1.0.0",
            );
            let release = state
                .update_manager
                .publish_signed_release(
                    "2.0.0",
                    "linux",
                    b"untrusted update binary",
                    "untrusted rollout",
                    true,
                    &[8u8; 32],
                )
                .expect("signed release");
            state.remote_deployments.insert(
                canary_id.clone(),
                completed_canary_deployment(&canary_id, &release),
            );
            (canary_id, ring_id)
        };

        let body = serde_json::json!({ "version": "2.0.0" }).to_string();
        let response =
            crate::server_agents::handle_agent_heartbeat(body.as_bytes(), &state, &canary_id);
        assert_eq!(response.status(), StatusCode::OK);

        let state = state.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            !state.remote_deployments.contains_key(&ring_id),
            "auto-progress must not assign releases signed by untrusted keys"
        );
    }

    #[test]
    fn local_console_host_is_exposed_through_fleet_endpoints() {
        let (port, token) = spawn_test_server();
        let base_url = format!("http://127.0.0.1:{port}");
        let auth_header = format!("Bearer {token}");

        let agents_response = ureq::get(&format!("{base_url}/api/agents"))
            .set("Authorization", &auth_header)
            .call()
            .expect("agents response");
        let agents: serde_json::Value =
            serde_json::from_str(&agents_response.into_string().expect("agents response body"))
                .expect("agents json");
        let local_agent = agents
            .as_array()
            .and_then(|entries| {
                entries
                    .iter()
                    .find(|entry| entry["id"] == serde_json::json!(LOCAL_CONSOLE_AGENT_ID))
            })
            .expect("local console agent in fleet list");
        assert_eq!(local_agent["local_console"], serde_json::json!(true));
        assert_eq!(local_agent["source"], serde_json::json!("local"));

        let details_response = ureq::get(&format!(
            "{base_url}/api/agents/{LOCAL_CONSOLE_AGENT_ID}/details"
        ))
        .set("Authorization", &auth_header)
        .call()
        .expect("agent details response");
        let details: serde_json::Value =
            serde_json::from_str(&details_response.into_string().expect("agent details body"))
                .expect("agent details json");
        assert_eq!(details["local_console"], serde_json::json!(true));
        assert_eq!(
            details["agent"]["id"],
            serde_json::json!(LOCAL_CONSOLE_AGENT_ID)
        );

        let fleet_health_response = ureq::get(&format!("{base_url}/api/fleet/health"))
            .set("Authorization", &auth_header)
            .call()
            .expect("fleet health response");
        let fleet_health: serde_json::Value = serde_json::from_str(
            &fleet_health_response
                .into_string()
                .expect("fleet health body"),
        )
        .expect("fleet health json");
        assert_eq!(fleet_health["total_agents"], serde_json::json!(1));
        assert_eq!(fleet_health["online"], serde_json::json!(1));

        match ureq::delete(&format!("{base_url}/api/agents/{LOCAL_CONSOLE_AGENT_ID}"))
            .set("Authorization", &auth_header)
            .call()
        {
            Err(ureq::Error::Status(409, response)) => {
                let body = response.into_string().expect("delete error body");
                assert!(body.contains("local console host cannot be removed"));
            }
            Ok(_) => panic!("local console delete unexpectedly succeeded"),
            Err(err) => panic!("unexpected delete error: {err}"),
        }
    }

    #[test]
    fn user_preferences_round_trip_and_merge() {
        let (port, token) = spawn_test_server();
        let base_url = format!("http://127.0.0.1:{port}");
        let auth_header = format!("Bearer {token}");

        let initial_response = ureq::get(&format!("{base_url}/api/user/preferences"))
            .set("Authorization", &auth_header)
            .call()
            .expect("initial preferences response");
        let initial: serde_json::Value = serde_json::from_str(
            &initial_response
                .into_string()
                .expect("initial preferences body"),
        )
        .expect("initial preferences json");
        assert_eq!(initial["theme"], serde_json::Value::Null);
        assert_eq!(initial["pinned_sections"], serde_json::json!([]));

        let update_response = ureq::put(&format!("{base_url}/api/user/preferences"))
            .set("Authorization", &auth_header)
            .send_string(r#"{"theme":"dark","pinned_sections":["fleet","monitor"]}"#)
            .expect("update preferences response");
        let updated: serde_json::Value = serde_json::from_str(
            &update_response
                .into_string()
                .expect("update preferences body"),
        )
        .expect("update preferences json");
        assert_eq!(updated["theme"], serde_json::json!("dark"));
        assert_eq!(
            updated["pinned_sections"],
            serde_json::json!(["fleet", "monitor"])
        );
        assert!(updated["updated_at"].as_str().is_some());

        let merge_response = ureq::put(&format!("{base_url}/api/user/preferences"))
            .set("Authorization", &auth_header)
            .send_string(r#"{"theme":"light"}"#)
            .expect("merge preferences response");
        let merged: serde_json::Value = serde_json::from_str(
            &merge_response
                .into_string()
                .expect("merge preferences body"),
        )
        .expect("merge preferences json");
        assert_eq!(merged["theme"], serde_json::json!("light"));
        assert_eq!(
            merged["pinned_sections"],
            serde_json::json!(["fleet", "monitor"])
        );

        let final_response = ureq::get(&format!("{base_url}/api/user/preferences"))
            .set("Authorization", &auth_header)
            .call()
            .expect("final preferences response");
        let final_value: serde_json::Value = serde_json::from_str(
            &final_response
                .into_string()
                .expect("final preferences body"),
        )
        .expect("final preferences json");
        assert_eq!(final_value["theme"], serde_json::json!("light"));
        assert_eq!(
            final_value["pinned_sections"],
            serde_json::json!(["fleet", "monitor"])
        );
    }

    #[test]
    fn audit_log_page_returns_newest_entries_first_with_metadata() {
        let mut audit_log = AuditLog::new(10);
        audit_log.record("GET", "/api/status", "127.0.0.1", 200, true);
        audit_log.record("POST", "/api/alerts/sample", "127.0.0.1", 202, true);
        audit_log.record("DELETE", "/api/agents/test", "127.0.0.1", 409, true);

        let first_page = audit_log.page(2, 0);
        assert_eq!(first_page.total, 3);
        assert_eq!(first_page.offset, 0);
        assert_eq!(first_page.limit, 2);
        assert_eq!(first_page.count, 2);
        assert!(first_page.has_more);
        assert_eq!(
            first_page
                .entries
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<Vec<_>>(),
            vec!["/api/agents/test", "/api/alerts/sample"]
        );

        let second_page = audit_log.page(2, 2);
        assert_eq!(second_page.total, 3);
        assert_eq!(second_page.offset, 2);
        assert_eq!(second_page.count, 1);
        assert!(!second_page.has_more);
        assert_eq!(second_page.entries[0].path, "/api/status");
    }

    #[test]
    fn audit_log_page_filters_entries() {
        let mut audit_log = AuditLog::new(10);
        audit_log.record("GET", "/api/status", "127.0.0.1", 200, true);
        audit_log.record("POST", "/api/alerts/sample", "127.0.0.1", 200, true);
        audit_log.record("GET", "/api/login", "10.0.0.5", 401, false);

        let filter = AuditLogFilter {
            query: Some("alerts".into()),
            method: Some("POST".into()),
            status: Some(AuditStatusFilter::Class(2)),
            auth_used: Some(true),
        };

        let page = audit_log.page_filtered(25, 0, &filter);
        assert_eq!(page.total, 1);
        assert_eq!(page.count, 1);
        assert_eq!(page.entries[0].path, "/api/alerts/sample");
        assert_eq!(page.entries[0].method, "POST");
    }

    #[test]
    fn audit_log_endpoint_supports_limit_and_offset_metadata() {
        let (port, token) = spawn_test_server();
        let base_url = format!("http://127.0.0.1:{port}");
        let auth_header = format!("Bearer {token}");

        for path in ["/api/status", "/api/health", "/api/platform"] {
            ureq::get(&format!("{base_url}{path}"))
                .set("Authorization", &auth_header)
                .call()
                .expect("seed audit entry");
        }

        let audit_response = ureq::get(&format!("{base_url}/api/audit/log?limit=2&offset=0"))
            .set("Authorization", &auth_header)
            .call()
            .expect("audit log response");
        let audit_page: serde_json::Value =
            serde_json::from_str(&audit_response.into_string().expect("audit log body"))
                .expect("audit log json");

        assert_eq!(audit_page["total"], serde_json::json!(3));
        assert_eq!(audit_page["offset"], serde_json::json!(0));
        assert_eq!(audit_page["limit"], serde_json::json!(2));
        assert_eq!(audit_page["count"], serde_json::json!(2));
        assert_eq!(audit_page["has_more"], serde_json::json!(true));
        let entries = audit_page["entries"]
            .as_array()
            .expect("audit entries array");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["path"], serde_json::json!("/api/platform"));
        assert_eq!(entries[1]["path"], serde_json::json!("/api/health"));
    }

    #[test]
    fn audit_log_endpoint_filters_and_exports_csv() {
        let (port, token) = spawn_test_server();
        let base_url = format!("http://127.0.0.1:{port}");
        let auth_header = format!("Bearer {token}");

        ureq::get(&format!("{base_url}/api/status"))
            .set("Authorization", &auth_header)
            .call()
            .expect("seed authenticated get");
        ureq::post(&format!("{base_url}/api/alerts/sample"))
            .set("Authorization", &auth_header)
            .send_string(r#"{"severity":"warning"}"#)
            .expect("seed authenticated post");

        match ureq::get(&format!("{base_url}/api/status")).call() {
            Err(ureq::Error::Status(401, response)) => {
                let _ = response.into_string().expect("anonymous response body");
            }
            Ok(_) => panic!("anonymous request unexpectedly succeeded"),
            Err(err) => panic!("unexpected anonymous request error: {err}"),
        }

        let filtered_response = ureq::get(&format!(
            "{base_url}/api/audit/log?method=POST&status=2xx&auth=authenticated&q=alerts"
        ))
        .set("Authorization", &auth_header)
        .call()
        .expect("filtered audit log response");
        let filtered_page: serde_json::Value = serde_json::from_str(
            &filtered_response
                .into_string()
                .expect("filtered audit log body"),
        )
        .expect("filtered audit log json");
        let entries = filtered_page["entries"]
            .as_array()
            .expect("filtered entries array");
        assert_eq!(filtered_page["total"], serde_json::json!(1));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["path"], serde_json::json!("/api/alerts/sample"));
        assert_eq!(entries[0]["method"], serde_json::json!("POST"));

        let export_response = ureq::get(&format!(
            "{base_url}/api/audit/log/export?status=401&auth=anonymous"
        ))
        .set("Authorization", &auth_header)
        .call()
        .expect("audit export response");
        let csv = export_response.into_string().expect("audit export body");
        assert!(csv.starts_with("timestamp,method,path,source_ip,status_code,auth_state\n"));
        assert!(csv.contains("\"'GET\""));
        assert!(csv.contains("\"'/api/status\""));
        assert!(csv.contains(",401,"));
        assert!(csv.contains("\"'anonymous\""));
        assert!(!csv.contains("/api/alerts/sample"));
    }

    #[test]
    fn sso_login_callback_creates_cookie_backed_session() {
        fn spawn_mock_oidc_provider() -> (
            String,
            std::sync::Arc<std::sync::Mutex<Vec<String>>>,
            std::sync::Arc<std::sync::Mutex<Option<String>>>,
            std::thread::JoinHandle<()>,
        ) {
            use base64::Engine;
            use std::io::{Read, Write};

            let listener =
                std::net::TcpListener::bind("127.0.0.1:0").expect("bind mock oidc provider");
            let port = listener.local_addr().expect("mock oidc addr").port();
            let issuer_url = format!("http://127.0.0.1:{port}");
            let server_base = issuer_url.clone();
            let token_bodies = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let token_bodies_for_server = std::sync::Arc::clone(&token_bodies);
            let expected_nonce = std::sync::Arc::new(std::sync::Mutex::new(None));
            let expected_nonce_for_server = std::sync::Arc::clone(&expected_nonce);
            let shared_secret = b"wardex-mock-oidc-signing-secret";
            let jwk_secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(shared_secret);
            let handle = std::thread::spawn(move || {
                for _ in 0..4 {
                    let (mut stream, _) = listener.accept().expect("accept mock oidc request");
                    let mut request_bytes = Vec::new();
                    let mut buffer = [0u8; 2048];
                    let mut header_end = None;
                    let mut content_length = 0usize;

                    loop {
                        let read = stream.read(&mut buffer).expect("read mock oidc request");
                        if read == 0 {
                            break;
                        }
                        request_bytes.extend_from_slice(&buffer[..read]);

                        if header_end.is_none() {
                            header_end = request_bytes
                                .windows(4)
                                .position(|window| window == b"\r\n\r\n");
                            if let Some(end) = header_end {
                                let headers = String::from_utf8_lossy(&request_bytes[..end]);
                                content_length = headers
                                    .lines()
                                    .find_map(|line| {
                                        let (name, value) = line.split_once(':')?;
                                        name.eq_ignore_ascii_case("Content-Length")
                                            .then(|| value.trim().parse::<usize>().ok())
                                            .flatten()
                                    })
                                    .unwrap_or(0);
                            }
                        }

                        if let Some(end) = header_end {
                            // Drain POST bodies before replying; some platforms can surface
                            // client-side read errors when the server responds too early.
                            if request_bytes.len() >= end + 4 + content_length {
                                break;
                            }
                        }
                    }

                    let request = String::from_utf8_lossy(&request_bytes);
                    let path = request
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/");
                    if path.starts_with("/token")
                        && let Some(end) = header_end
                    {
                        let body = String::from_utf8_lossy(&request_bytes[end + 4..]).to_string();
                        token_bodies_for_server
                            .lock()
                            .expect("token body log")
                            .push(body);
                    }
                    let (status_line, body, content_type) = if path
                        .starts_with("/.well-known/openid-configuration")
                    {
                        (
                            "HTTP/1.1 200 OK",
                            serde_json::json!({
                                "issuer": server_base,
                                "authorization_endpoint": format!("{}/authorize", server_base),
                                "token_endpoint": format!("{}/token", server_base),
                                "userinfo_endpoint": format!("{}/userinfo", server_base),
                                "jwks_uri": format!("{}/jwks", server_base),
                                "response_types_supported": ["code"],
                                "scopes_supported": ["openid", "profile", "email", "groups"],
                            })
                            .to_string(),
                            "application/json",
                        )
                    } else if path.starts_with("/token") {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs() as usize;
                        let nonce = expected_nonce_for_server
                            .lock()
                            .expect("expected nonce")
                            .clone()
                            .expect("nonce should be set before callback");
                        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
                        header.kid = Some("mock-key-1".to_string());
                        let id_token = jsonwebtoken::encode(
                            &header,
                            &serde_json::json!({
                                "iss": server_base,
                                "sub": "oidc-user-1",
                                "aud": "wardex-admin",
                                "exp": now + 3600,
                                "iat": now,
                                "nonce": nonce,
                            }),
                            &jsonwebtoken::EncodingKey::from_secret(shared_secret),
                        )
                        .expect("encode mock id token");
                        (
                            "HTTP/1.1 200 OK",
                            serde_json::json!({
                                "access_token": "mock-access-token",
                                "token_type": "Bearer",
                                "expires_in": 3600,
                                "id_token": id_token,
                            })
                            .to_string(),
                            "application/json",
                        )
                    } else if path.starts_with("/jwks") {
                        (
                            "HTTP/1.1 200 OK",
                            serde_json::json!({
                                "keys": [{
                                    "kty": "oct",
                                    "alg": "HS256",
                                    "kid": "mock-key-1",
                                    "k": jwk_secret,
                                }]
                            })
                            .to_string(),
                            "application/json",
                        )
                    } else if path.starts_with("/userinfo") {
                        (
                            "HTTP/1.1 200 OK",
                            serde_json::json!({
                                "sub": "oidc-user-1",
                                "email": "sso-user@example.com",
                                "groups": ["Security"],
                            })
                            .to_string(),
                            "application/json",
                        )
                    } else {
                        (
                            "HTTP/1.1 404 Not Found",
                            "not found".to_string(),
                            "text/plain; charset=utf-8",
                        )
                    };
                    let response = format!(
                        "{status_line}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    stream
                        .write_all(response.as_bytes())
                        .expect("write mock oidc response");
                    stream.flush().expect("flush mock oidc response");
                }
            });
            (issuer_url, token_bodies, expected_nonce, handle)
        }

        let (issuer_url, token_bodies, expected_nonce, provider_handle) =
            spawn_mock_oidc_provider();
        let (port, token) = spawn_test_server();
        let base_url = format!("http://127.0.0.1:{port}");
        let auth_header = format!("Bearer {token}");
        let redirect_uri = format!("{base_url}/api/auth/sso/callback");

        let saved_provider: serde_json::Value =
            ureq::post(&format!("{base_url}/api/idp/providers"))
                .set("Authorization", &auth_header)
                .send_json(serde_json::json!({
                    "id": "corp-sso",
                    "kind": "oidc",
                    "display_name": "Corporate SSO",
                    "issuer_url": issuer_url,
                    "client_id": "wardex-admin",
                    "client_secret": "super-secret",
                    "redirect_uri": redirect_uri,
                    "enabled": true,
                    "group_role_mappings": {
                        "Security": "admin"
                    }
                }))
                .expect("seed sso provider")
                .into_json()
                .expect("seed sso provider json");
        let provider_id = saved_provider["provider"]["id"]
            .as_str()
            .expect("saved provider id");

        let agent = ureq::builder().redirects(0).build();
        let login_response = match agent
            .get(&format!(
                "{base_url}/api/auth/sso/login?provider_id={provider_id}&redirect=%2Fworkbench"
            ))
            .call()
        {
            Ok(response) => response,
            Err(ureq::Error::Status(_, response)) => response,
            Err(err) => panic!("unexpected login error: {err}"),
        };
        assert_eq!(login_response.status(), 302);
        let location = login_response
            .header("Location")
            .expect("login redirect location")
            .to_string();
        assert!(location.starts_with(&format!("{}/authorize?", issuer_url)));
        assert!(location.contains("code_challenge="));
        assert!(location.contains("code_challenge_method=S256"));
        let callback_state = parse_query_string(&location)
            .get("state")
            .cloned()
            .expect("authorization state");
        let callback_nonce = parse_query_string(&location)
            .get("nonce")
            .cloned()
            .expect("authorization nonce");
        *expected_nonce.lock().expect("expected nonce") = Some(callback_nonce);

        let callback_response = match agent
            .get(&format!(
                "{base_url}/api/auth/sso/callback?code=test-code&state={}",
                encode_query_component(&callback_state)
            ))
            .call()
        {
            Ok(response) => response,
            Err(ureq::Error::Status(_, response)) => response,
            Err(err) => panic!("unexpected callback error: {err}"),
        };
        assert_eq!(callback_response.status(), 302);
        assert_eq!(callback_response.header("Location"), Some("/workbench"));
        let set_cookie = callback_response
            .header("Set-Cookie")
            .expect("callback set-cookie")
            .to_string();
        assert!(set_cookie.contains("wardex_session="));
        let session_cookie = set_cookie
            .split(';')
            .next()
            .expect("session cookie pair")
            .to_string();

        let session_response: serde_json::Value =
            ureq::get(&format!("{base_url}/api/auth/session"))
                .set("Cookie", &session_cookie)
                .call()
                .expect("session status response")
                .into_json()
                .expect("session status json");
        assert_eq!(session_response["authenticated"], serde_json::json!(true));
        assert_eq!(
            session_response["user_id"],
            serde_json::json!("sso-user@example.com")
        );
        assert_eq!(session_response["role"], serde_json::json!("admin"));
        assert_eq!(session_response["source"], serde_json::json!("session"));
        assert_eq!(session_response["groups"][0], serde_json::json!("Security"));
        let recorded_token_bodies = token_bodies.lock().expect("token body log");
        assert_eq!(recorded_token_bodies.len(), 1);
        let token_body = &recorded_token_bodies[0];
        assert!(token_body.contains("grant_type=authorization_code"));
        assert!(token_body.contains("code_verifier="));

        provider_handle
            .join()
            .expect("mock oidc provider should finish cleanly");
    }

    #[test]
    fn idp_provider_endpoint_saves_and_rejects_invalid_configs() {
        let (port, token) = spawn_test_server();
        let base_url = format!("http://127.0.0.1:{port}");
        let auth_header = format!("Bearer {token}");

        let save_response = ureq::post(&format!("{base_url}/api/idp/providers"))
            .set("Authorization", &auth_header)
            .send_string(
                r#"{"kind":"oidc","display_name":"Corporate SSO","issuer_url":"https://issuer.example.com","client_id":"wardex-admin","client_secret":"super-secret","redirect_uri":"https://console.example.com/api/auth/sso/callback","enabled":true,"group_role_mappings":{"Security":"admin"}}"#,
            )
            .expect("save idp provider response");
        let saved: serde_json::Value =
            serde_json::from_str(&save_response.into_string().expect("save idp provider body"))
                .expect("save idp provider json");
        assert_eq!(saved["status"], serde_json::json!("saved"));
        assert_eq!(
            saved["provider"]["display_name"],
            serde_json::json!("Corporate SSO")
        );
        assert_eq!(
            saved["provider"]["redirect_uri"],
            serde_json::json!("https://console.example.com/api/auth/sso/callback")
        );
        assert_eq!(
            saved["provider"]["has_client_secret"],
            serde_json::json!(true)
        );
        assert_eq!(saved["validation"]["status"], serde_json::json!("ready"));
        assert_eq!(saved["validation"]["mapping_count"], serde_json::json!(1));

        let providers_response = ureq::get(&format!("{base_url}/api/idp/providers"))
            .set("Authorization", &auth_header)
            .call()
            .expect("list idp providers response");
        let providers: serde_json::Value = serde_json::from_str(
            &providers_response
                .into_string()
                .expect("list idp providers body"),
        )
        .expect("list idp providers json");
        assert_eq!(providers["count"], serde_json::json!(1));
        assert_eq!(providers["healthy"], serde_json::json!(1));
        assert_eq!(
            providers["providers"][0]["group_role_mappings"]["Security"],
            serde_json::json!("admin")
        );

        let sso_config_response = ureq::get(&format!("{base_url}/api/auth/sso/config"))
            .call()
            .expect("sso config response");
        let sso_config: serde_json::Value =
            serde_json::from_str(&sso_config_response.into_string().expect("sso config body"))
                .expect("sso config json");
        assert_eq!(sso_config["enabled"], serde_json::json!(true));
        assert_eq!(
            sso_config["providers"].as_array().map(|items| items.len()),
            Some(1)
        );
        assert_eq!(
            sso_config["providers"][0]["display_name"],
            serde_json::json!("Corporate SSO")
        );
        let provider_id = saved["provider"]["id"]
            .as_str()
            .expect("saved provider id should be present");
        assert_eq!(
            sso_config["providers"][0]["login_path"],
            serde_json::json!(format!("/api/auth/sso/login?provider_id={provider_id}"))
        );

        match ureq::post(&format!("{base_url}/api/idp/providers"))
            .set("Authorization", &auth_header)
            .send_string(r#"{"kind":"oidc","display_name":"Broken OIDC","enabled":true}"#)
        {
            Err(ureq::Error::Status(400, response)) => {
                let body: serde_json::Value =
                    serde_json::from_str(&response.into_string().expect("invalid idp body"))
                        .expect("invalid idp json");
                assert_eq!(body["code"], serde_json::json!("VALIDATION_ERROR"));
                assert_eq!(
                    body["error"],
                    serde_json::json!("enabled OIDC providers require issuer_url")
                );
            }
            Ok(_) => panic!("invalid idp provider unexpectedly succeeded"),
            Err(err) => panic!("unexpected invalid idp provider error: {err}"),
        }
    }

    #[test]
    fn identity_and_saas_collector_routes_save_config_and_appear_in_summary() {
        let (port, token) = spawn_test_server();
        let base_url = format!("http://127.0.0.1:{port}");
        let auth_header = format!("Bearer {token}");

        let okta_saved: serde_json::Value =
            ureq::post(&format!("{base_url}/api/collectors/okta/config"))
                .set("Authorization", &auth_header)
                .send_json(serde_json::json!({
                    "enabled": true,
                    "domain": "dev-123456.okta.com",
                    "api_token": "okta-secret",
                    "poll_interval_secs": 45,
                    "event_type_filter": ["user.session.start", "user.account.lock"],
                }))
                .expect("save okta collector response")
                .into_json()
                .expect("save okta collector json");
        assert_eq!(okta_saved["status"], serde_json::json!("saved"));
        assert_eq!(okta_saved["provider"], serde_json::json!("okta_identity"));
        assert_eq!(
            okta_saved["validation"]["status"],
            serde_json::json!("ready")
        );
        assert_eq!(
            okta_saved["config"]["has_api_token"],
            serde_json::json!(true)
        );

        let entra_saved: serde_json::Value =
            ureq::post(&format!("{base_url}/api/collectors/entra/config"))
                .set("Authorization", &auth_header)
                .send_json(serde_json::json!({
                    "enabled": true,
                    "tenant_id": "tenant-guid",
                    "client_id": "client-guid",
                    "client_secret": "entra-secret",
                    "poll_interval_secs": 60,
                }))
                .expect("save entra collector response")
                .into_json()
                .expect("save entra collector json");
        assert_eq!(entra_saved["status"], serde_json::json!("saved"));
        assert_eq!(entra_saved["provider"], serde_json::json!("entra_identity"));
        assert_eq!(
            entra_saved["validation"]["status"],
            serde_json::json!("ready")
        );
        assert_eq!(
            entra_saved["config"]["has_client_secret"],
            serde_json::json!(true)
        );

        let m365_saved: serde_json::Value =
            ureq::post(&format!("{base_url}/api/collectors/m365/config"))
                .set("Authorization", &auth_header)
                .send_json(serde_json::json!({
                    "enabled": true,
                    "tenant_id": "m365-tenant-guid",
                    "client_id": "m365-client-guid",
                    "client_secret": "m365-secret",
                    "poll_interval_secs": 90,
                    "content_types": ["Audit.AzureActiveDirectory", "Audit.Exchange"],
                }))
                .expect("save m365 collector response")
                .into_json()
                .expect("save m365 collector json");
        assert_eq!(m365_saved["status"], serde_json::json!("saved"));
        assert_eq!(m365_saved["provider"], serde_json::json!("m365_saas"));
        assert_eq!(
            m365_saved["validation"]["status"],
            serde_json::json!("ready")
        );
        assert_eq!(
            m365_saved["config"]["has_client_secret"],
            serde_json::json!(true)
        );

        let workspace_saved: serde_json::Value =
            ureq::post(&format!("{base_url}/api/collectors/workspace/config"))
                .set("Authorization", &auth_header)
                .send_json(serde_json::json!({
                    "enabled": true,
                    "customer_id": "my_customer",
                    "delegated_admin_email": "admin@example.com",
                    "service_account_email": "collector@workspace.example.iam.gserviceaccount.com",
                    "credentials_json": "{\"type\":\"service_account\"}",
                    "poll_interval_secs": 120,
                    "applications": ["login", "admin", "drive"],
                }))
                .expect("save workspace collector response")
                .into_json()
                .expect("save workspace collector json");
        assert_eq!(workspace_saved["status"], serde_json::json!("saved"));
        assert_eq!(
            workspace_saved["provider"],
            serde_json::json!("workspace_saas")
        );
        assert_eq!(
            workspace_saved["validation"]["status"],
            serde_json::json!("ready")
        );
        assert_eq!(
            workspace_saved["config"]["has_credentials_json"],
            serde_json::json!(true)
        );

        let summary: serde_json::Value = ureq::get(&format!("{base_url}/api/collectors/status"))
            .set("Authorization", &auth_header)
            .call()
            .expect("collector summary response")
            .into_json()
            .expect("collector summary json");
        let collectors = summary["collectors"]
            .as_array()
            .expect("collector summary array");
        assert!(
            collectors
                .iter()
                .any(|entry| entry["name"] == serde_json::json!("okta_identity"))
        );
        assert!(
            collectors
                .iter()
                .any(|entry| entry["name"] == serde_json::json!("entra_identity"))
        );
        assert!(
            collectors
                .iter()
                .any(|entry| entry["name"] == serde_json::json!("m365_saas"))
        );
        assert!(
            collectors
                .iter()
                .any(|entry| entry["name"] == serde_json::json!("workspace_saas"))
        );
        let m365_summary = collectors
            .iter()
            .find(|entry| entry["name"] == serde_json::json!("m365_saas"))
            .expect("m365 collector summary");
        assert_eq!(m365_summary["lane"], serde_json::json!("saas"));
        assert_eq!(
            m365_summary["label"],
            serde_json::json!("Microsoft 365 Activity")
        );
        assert!(
            m365_summary["route_targets"]
                .as_array()
                .is_some_and(|targets| targets.iter().any(|value| value == "Reports"))
        );
        assert!(
            m365_summary["timeline"]
                .as_array()
                .is_some_and(|timeline| timeline.len() >= 5)
        );
        assert!(
            m365_summary["timeline"]
                .as_array()
                .is_some_and(|timeline| timeline.iter().any(|entry| {
                    entry["stage"] == serde_json::json!("Validation")
                        && entry["status"] == serde_json::json!("ready")
                }))
        );
    }

    #[test]
    fn siem_config_routes_redact_token_and_preserve_existing_secret() {
        let (port, token) = spawn_test_server();
        let base_url = format!("http://127.0.0.1:{port}");
        let auth_header = format!("Bearer {token}");

        let saved: serde_json::Value = ureq::post(&format!("{base_url}/api/siem/config"))
            .set("Authorization", &auth_header)
            .send_json(serde_json::json!({
                "enabled": true,
                "siem_type": "splunk",
                "endpoint": "https://siem.example.test/hec",
                "auth_token": "hec-token",
                "index": "wardex",
                "source_type": "wardex:xdr",
                "poll_interval_secs": 90,
                "pull_enabled": true,
                "pull_query": "search index=wardex",
                "batch_size": 25,
                "verify_tls": true,
            }))
            .expect("save siem config response")
            .into_json()
            .expect("save siem config json");
        assert_eq!(saved["status"], serde_json::json!("saved"));
        assert_eq!(saved["config"]["siem_type"], serde_json::json!("splunk"));
        assert_eq!(saved["config"]["has_auth_token"], serde_json::json!(true));
        assert_eq!(saved["config"]["auth_token"], serde_json::Value::Null);
        assert_eq!(saved["validation"]["status"], serde_json::json!("ready"));

        let listed: serde_json::Value = ureq::get(&format!("{base_url}/api/siem/config"))
            .set("Authorization", &auth_header)
            .call()
            .expect("get siem config response")
            .into_json()
            .expect("get siem config json");
        assert_eq!(
            listed["config"]["endpoint"],
            serde_json::json!("https://siem.example.test/hec")
        );
        assert_eq!(listed["config"]["has_auth_token"], serde_json::json!(true));
        assert_eq!(listed["validation"]["status"], serde_json::json!("ready"));

        let validated: serde_json::Value = ureq::post(&format!("{base_url}/api/siem/validate"))
            .set("Authorization", &auth_header)
            .send_json(serde_json::json!({
                "enabled": true,
                "siem_type": "splunk",
                "endpoint": "https://siem.example.test/hec/secondary",
                "auth_token": "",
                "index": "wardex-updated",
                "source_type": "wardex:alerts",
                "poll_interval_secs": 120,
                "pull_enabled": false,
                "pull_query": "",
                "batch_size": 30,
                "verify_tls": true,
            }))
            .expect("validate siem config response")
            .into_json()
            .expect("validate siem config json");
        assert_eq!(validated["success"], serde_json::json!(true));
        assert_eq!(
            validated["config"]["endpoint"],
            serde_json::json!("https://siem.example.test/hec/secondary")
        );
        assert_eq!(
            validated["config"]["has_auth_token"],
            serde_json::json!(true)
        );
        assert_eq!(
            validated["validation"]["status"],
            serde_json::json!("ready")
        );

        let saved_again: serde_json::Value = ureq::post(&format!("{base_url}/api/siem/config"))
            .set("Authorization", &auth_header)
            .send_json(serde_json::json!({
                "enabled": true,
                "siem_type": "splunk",
                "endpoint": "https://siem.example.test/hec/secondary",
                "auth_token": "",
                "index": "wardex-updated",
                "source_type": "wardex:alerts",
                "poll_interval_secs": 120,
                "pull_enabled": false,
                "pull_query": "",
                "batch_size": 30,
                "verify_tls": true,
            }))
            .expect("save siem config without token response")
            .into_json()
            .expect("save siem config without token json");
        assert_eq!(
            saved_again["config"]["has_auth_token"],
            serde_json::json!(true)
        );

        let listed_again: serde_json::Value = ureq::get(&format!("{base_url}/api/siem/config"))
            .set("Authorization", &auth_header)
            .call()
            .expect("get siem config response after update")
            .into_json()
            .expect("get siem config json after update");
        assert_eq!(
            listed_again["config"]["endpoint"],
            serde_json::json!("https://siem.example.test/hec/secondary")
        );
        assert_eq!(
            listed_again["config"]["has_auth_token"],
            serde_json::json!(true)
        );
    }

    #[test]
    fn scim_config_endpoint_saves_and_rejects_invalid_roles() {
        let (port, token) = spawn_test_server();
        let base_url = format!("http://127.0.0.1:{port}");
        let auth_header = format!("Bearer {token}");

        let save_response = ureq::post(&format!("{base_url}/api/scim/config"))
            .set("Authorization", &auth_header)
            .send_string(
                r#"{"enabled":true,"base_url":"https://scim.example.com","bearer_token":"super-secret-token","provisioning_mode":"automatic","default_role":"viewer","group_role_mappings":{"Security":"analyst"}}"#,
            )
            .expect("save scim config response");
        let saved: serde_json::Value =
            serde_json::from_str(&save_response.into_string().expect("save scim config body"))
                .expect("save scim config json");
        assert_eq!(saved["status"], serde_json::json!("saved"));
        assert_eq!(saved["config"]["default_role"], serde_json::json!("viewer"));
        assert_eq!(saved["validation"]["status"], serde_json::json!("ready"));
        assert_eq!(saved["validation"]["mapping_count"], serde_json::json!(1));

        let config_response = ureq::get(&format!("{base_url}/api/scim/config"))
            .set("Authorization", &auth_header)
            .call()
            .expect("get scim config response");
        let config: serde_json::Value =
            serde_json::from_str(&config_response.into_string().expect("get scim config body"))
                .expect("get scim config json");
        assert_eq!(
            config["config"]["provisioning_mode"],
            serde_json::json!("automatic")
        );
        assert_eq!(config["validation"]["status"], serde_json::json!("ready"));

        match ureq::post(&format!("{base_url}/api/scim/config"))
            .set("Authorization", &auth_header)
            .send_string(
                r#"{"enabled":false,"provisioning_mode":"manual","default_role":"owner","group_role_mappings":{}}"#,
            )
        {
            Err(ureq::Error::Status(400, response)) => {
                let body: serde_json::Value = serde_json::from_str(
                    &response.into_string().expect("invalid scim body"),
                )
                .expect("invalid scim json");
                assert_eq!(body["code"], serde_json::json!("VALIDATION_ERROR"));
                assert_eq!(
                    body["error"],
                    serde_json::json!(
                        "invalid role 'owner'; expected one of admin, analyst, viewer"
                    )
                );
            }
            Ok(_) => panic!("invalid scim config unexpectedly succeeded"),
            Err(err) => panic!("unexpected invalid scim config error: {err}"),
        }
    }

    #[test]
    fn assistant_status_and_query_include_case_context_and_citations() {
        let (port, token, state) = spawn_test_server_with_state();
        {
            let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
            state.event_store.ingest(&crate::event_forward::EventBatch {
                agent_id: "agent-assistant-1".to_string(),
                events: vec![
                    sample_alert(
                        "db-01",
                        "Critical",
                        9.1,
                        "credential dumping observed on privileged session",
                    ),
                    sample_alert(
                        "db-01",
                        "Elevated",
                        4.6,
                        "suspicious service install on database host",
                    ),
                ],
            });
            let created = state.case_store.create(
                "Database credential theft".to_string(),
                "Investigate suspicious admin activity on db-01".to_string(),
                CasePriority::Critical,
                Vec::new(),
                vec![1, 2],
                vec!["identity".to_string(), "database".to_string()],
            );
            let case_id = created.id;
            assert!(state.case_store.add_comment(
                case_id,
                "analyst-1".to_string(),
                "Credential theft path needs immediate review".to_string(),
            ));
        }

        let base_url = format!("http://127.0.0.1:{port}");
        let auth_header = format!("Bearer {token}");

        let status_response = ureq::get(&format!("{base_url}/api/assistant/status"))
            .set("Authorization", &auth_header)
            .call()
            .expect("assistant status response");
        let status: serde_json::Value = serde_json::from_str(
            &status_response
                .into_string()
                .expect("assistant status body"),
        )
        .expect("assistant status json");
        assert_eq!(status["mode"], serde_json::json!("retrieval-only"));

        let query_response = ureq::post(&format!("{base_url}/api/assistant/query"))
            .set("Authorization", &auth_header)
            .send_string(
                r#"{"question":"Summarize the current case and cite the strongest evidence","case_id":1}"#,
            )
            .expect("assistant query response");
        let body: serde_json::Value =
            serde_json::from_str(&query_response.into_string().expect("assistant query body"))
                .expect("assistant query json");
        assert_eq!(body["mode"], serde_json::json!("retrieval-only"));
        assert_eq!(body["case_context"]["case"]["id"], serde_json::json!(1));
        assert_eq!(
            body["case_context"]["case"]["title"],
            serde_json::json!("Database credential theft")
        );
        assert!(
            body["answer"]
                .as_str()
                .expect("assistant answer")
                .contains("Database credential theft")
        );
        assert_eq!(
            body["citations"]
                .as_array()
                .map(|items| items.len())
                .unwrap_or(0),
            2
        );
        assert_eq!(body["citations"][0]["source_id"], serde_json::json!("1"));
        assert!(
            body["warnings"]
                .as_array()
                .expect("assistant warnings")
                .iter()
                .any(|item| item
                    .as_str()
                    .is_some_and(|value| value.contains("retrieval-only")))
        );
    }

    #[test]
    fn sample_alerts_are_streamed_to_ws_poll_subscribers() {
        let (port, token) = spawn_test_server();
        let base_url = format!("http://127.0.0.1:{port}");
        let auth_header = format!("Bearer {token}");

        let connect_response = ureq::post(&format!("{base_url}/api/ws/connect"))
            .set("Authorization", &auth_header)
            .call()
            .expect("connect ws subscriber");
        let connected: serde_json::Value = serde_json::from_str(
            &connect_response
                .into_string()
                .expect("connect response body"),
        )
        .expect("connect response json");
        let subscriber_id = connected["subscriber_id"].as_u64().expect("subscriber id");

        ureq::post(&format!("{base_url}/api/alerts/sample"))
            .set("Authorization", &auth_header)
            .send_string(r#"{"severity":"critical"}"#)
            .expect("inject sample alert");

        let poll_response = ureq::post(&format!("{base_url}/api/ws/poll"))
            .set("Authorization", &auth_header)
            .send_string(&format!(r#"{{"subscriber_id":{subscriber_id}}}"#))
            .expect("poll ws subscriber");
        let events: serde_json::Value =
            serde_json::from_str(&poll_response.into_string().expect("poll response body"))
                .expect("poll response json");
        let first_event = events
            .as_array()
            .and_then(|entries| entries.first())
            .expect("streamed alert event");
        assert_eq!(first_event["type"], serde_json::json!("alert"));
        assert!(first_event["data"]["id"].is_number());
        assert_eq!(first_event["data"]["level"], serde_json::json!("Critical"));
    }

    #[test]
    fn rate_limiter_separates_status_reads_from_writes() {
        let mut limiter = RateLimiter::new(3, 1);

        assert!(limiter.check("127.0.0.1", &Method::Get, "/api/status"));
        assert!(limiter.check("127.0.0.1", &Method::Get, "/api/status"));
        assert!(limiter.check("127.0.0.1", &Method::Get, "/api/status"));
        assert!(!limiter.check("127.0.0.1", &Method::Get, "/api/status"));

        assert!(limiter.check("127.0.0.1", &Method::Post, "/api/config/reload"));
        assert!(!limiter.check("127.0.0.1", &Method::Post, "/api/config/reload"));
    }

    #[test]
    fn rate_limiter_gives_static_assets_a_separate_bucket() {
        let mut limiter = RateLimiter::new(2, 1);

        assert!(limiter.check("127.0.0.1", &Method::Get, "/admin/"));
        assert!(limiter.check("127.0.0.1", &Method::Get, "/admin/assets/index.js"));
        assert!(limiter.check("127.0.0.1", &Method::Get, "/site/styles.css"));
        assert!(limiter.check("127.0.0.1", &Method::Get, "/site/app.js"));
        assert!(!limiter.check("127.0.0.1", &Method::Get, "/site/index.html"));
    }

    #[test]
    fn rate_limiter_zero_limits_disable_throttling() {
        let mut limiter = RateLimiter::new(0, 0);

        for _ in 0..10 {
            assert!(limiter.check("127.0.0.1", &Method::Get, "/api/status"));
            assert!(limiter.check("127.0.0.1", &Method::Post, "/api/config/reload"));
            assert!(limiter.check("127.0.0.1", &Method::Get, "/admin/assets/index.js"));
        }
    }

    #[test]
    fn load_remote_deployments_accepts_legacy_records() {
        let path = format!(
            "/tmp/wardex_test_deployments_{}_legacy.json",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        );
        fs::write(
            &path,
            r#"{
  "agent-1": {
    "agent_id": "agent-1",
    "version": "0.16.0",
    "platform": "linux",
    "mandatory": true,
    "release_notes": "legacy deployment",
    "assigned_at": "2026-01-01T00:00:00Z"
  }
}"#,
        )
        .expect("write legacy deployment fixture");

        let deployments = load_remote_deployments(&path);
        let deployment = deployments.get("agent-1").expect("deployment loaded");
        assert_eq!(deployment.status, "assigned");
        assert_eq!(deployment.rollout_group, "direct");
        assert!(!deployment.allow_downgrade);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn build_workbench_overview_aggregates_queue_cases_incidents_and_response() {
        let case_path = temp_path("cases");
        let incident_path = temp_path("incidents");
        let agent_path = temp_path("agents");
        let enterprise_path = temp_path("workbench_enterprise");

        let mut queue = AlertQueue::new();
        let mut case_store = CaseStore::new(case_path.to_str().unwrap());
        let mut incident_store = IncidentStore::new(incident_path.to_str().unwrap());
        let mut approvals = ApprovalLog::new();
        let response = ResponseOrchestrator::new();
        let mut events = EventStore::new(100);
        let mut registry = AgentRegistry::new(agent_path.to_str().unwrap());
        let rbac = crate::rbac::RbacStore::new();
        let mut enterprise = EnterpriseStore::new(enterprise_path.to_str().unwrap());
        let mut playbook_engine = crate::playbook::PlaybookEngine::new();
        let mut playbook_dsl = crate::playbook_dsl::PlaybookDslStore::new();
        let mut workflow_store = crate::investigation::WorkflowStore::new();
        let mut api_analytics = crate::api_analytics::ApiAnalytics::new();

        let agent_id = enroll_test_agent(&mut registry, "workbench-host", "linux", "1.0.0");
        events.ingest(&EventBatch {
            agent_id: agent_id.clone(),
            events: vec![
                sample_alert("workbench-host", "Critical", 8.4, "credential dumping"),
                sample_alert("workbench-host", "Elevated", 3.2, "suspicious service"),
            ],
        });
        let stored = events.all_events();
        queue.enqueue(
            stored[0].id,
            stored[0].alert.score as f64,
            stored[0].alert.level.clone(),
            stored[0].alert.hostname.clone(),
            stored[0].alert.timestamp.clone(),
        );
        queue.enqueue(
            stored[1].id,
            stored[1].alert.score as f64,
            stored[1].alert.level.clone(),
            stored[1].alert.hostname.clone(),
            stored[1].alert.timestamp.clone(),
        );
        queue.assign(stored[0].id, "analyst-1".to_string());

        case_store.create(
            "Credential dumping case".to_string(),
            "Escalated from queue".to_string(),
            CasePriority::Critical,
            Vec::new(),
            vec![stored[0].id],
            vec!["credential_access".to_string()],
        );
        incident_store.create(
            "Credential dumping incident".to_string(),
            "Critical".to_string(),
            vec![stored[0].id],
            vec![agent_id.clone()],
            Vec::new(),
            "Investigate workstation credential theft".to_string(),
        );

        response
            .submit(ResponseRequest {
                id: "resp-1".to_string(),
                action: ResponseAction::KillProcess {
                    pid: 4444,
                    process_name: "evil.bin".to_string(),
                },
                target: ResponseTarget {
                    hostname: "workbench-host".to_string(),
                    agent_uid: Some(agent_id.clone()),
                    asset_tags: Vec::new(),
                },
                reason: "Terminate malicious process".to_string(),
                severity: "high".to_string(),
                tier: ActionTier::SingleApproval,
                status: ApprovalStatus::Pending,
                requested_at: chrono::Utc::now().to_rfc3339(),
                requested_by: "unit-test".to_string(),
                approvals: Vec::new(),
                dry_run: false,
                blast_radius: None,
                is_protected_asset: false,
            })
            .expect("submit response");
        response
            .approve(
                "resp-1",
                ApprovalRecord {
                    approver: "analyst-1".to_string(),
                    decision: ResponseApprovalDecision::Approve,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    comment: Some("validated".to_string()),
                },
            )
            .expect("approve response");
        approvals.record(
            "resp-1".to_string(),
            AnalystApprovalDecision::Approved,
            "analyst-1".to_string(),
            "validated".to_string(),
        );
        rbac.add_user(crate::rbac::User {
            username: "analyst-1".to_string(),
            role: crate::rbac::Role::Analyst,
            token_hash: "analyst-1-token".to_string(),
            enabled: true,
            created_at: chrono::Utc::now().to_rfc3339(),
            tenant_id: None,
        });
        rbac.add_user(crate::rbac::User {
            username: "analyst-2".to_string(),
            role: crate::rbac::Role::Analyst,
            token_hash: "analyst-2-token".to_string(),
            enabled: true,
            created_at: chrono::Utc::now().to_rfc3339(),
            tenant_id: None,
        });

        let mut group_mappings = StdHashMap::new();
        group_mappings.insert("soc-analysts".to_string(), "analyst".to_string());
        enterprise
            .create_or_update_idp_provider(
                None,
                "oidc".to_string(),
                "Corp Identity".to_string(),
                Some("https://id.example.com".to_string()),
                None,
                Some("wardex-admin".to_string()),
                Some("super-secret".to_string()),
                Some("https://console.example.com/api/auth/sso/callback".to_string()),
                None,
                true,
                group_mappings.clone(),
            )
            .expect("idp config");
        enterprise
            .update_scim(
                true,
                Some("https://scim.example.com".to_string()),
                Some("token".to_string()),
                "automatic".to_string(),
                "analyst".to_string(),
                group_mappings,
            )
            .expect("scim config");
        enterprise.create_or_update_hunt(
            None,
            "Credential Storm Hunt".to_string(),
            "analyst-1".to_string(),
            "high".to_string(),
            1,
            0,
            Some(300),
            Some("0 * * * *".to_string()),
            crate::analyst::SearchQuery {
                text: Some("credential".to_string()),
                hostname: None,
                level: None,
                agent_id: None,
                from_ts: None,
                to_ts: None,
                limit: Some(50),
            },
            "Credential abuse should persist across the hour".to_string(),
            crate::enterprise::HuntExpectedOutcome::Confirm,
            crate::enterprise::ContentLifecycle::Canary,
            15,
            Some("identity-attacks".to_string()),
            vec!["credential-storm".to_string()],
            Some("soc-analysts".to_string()),
        );
        enterprise.record_hunt_metrics(220);
        enterprise.record_response_metrics(90);

        let created_at = chrono::Utc::now().to_rfc3339();
        let approval_playbook = crate::playbook::Playbook {
            id: "pb-approval".to_string(),
            name: "Approval Route".to_string(),
            description: "Approval-gated response".to_string(),
            version: 1,
            enabled: true,
            trigger: crate::playbook::PlaybookTrigger {
                min_severity: None,
                alert_reasons: Vec::new(),
                mitre_techniques: Vec::new(),
                kill_chain_phases: Vec::new(),
                host_patterns: Vec::new(),
                manual_only: true,
            },
            steps: Vec::new(),
            timeout_secs: 300,
            created_at: created_at.clone(),
            updated_at: created_at.clone(),
        };
        let success_playbook = crate::playbook::Playbook {
            id: "pb-success".to_string(),
            name: "Success Route".to_string(),
            description: "Successful automation path".to_string(),
            version: 1,
            enabled: true,
            trigger: crate::playbook::PlaybookTrigger {
                min_severity: None,
                alert_reasons: Vec::new(),
                mitre_techniques: Vec::new(),
                kill_chain_phases: Vec::new(),
                host_patterns: Vec::new(),
                manual_only: true,
            },
            steps: Vec::new(),
            timeout_secs: 300,
            created_at: created_at.clone(),
            updated_at: created_at.clone(),
        };
        playbook_engine.register(approval_playbook);
        playbook_engine.register(success_playbook);
        let approval_exec = playbook_engine
            .start_execution("pb-approval", None, "analyst-1", 1_000)
            .expect("approval execution");
        assert!(playbook_engine.finish_execution(
            &approval_exec,
            crate::playbook::ExecutionStatus::AwaitingApproval,
            None,
            1_200,
        ));
        let success_exec = playbook_engine
            .start_execution("pb-success", None, "analyst-1", 2_000)
            .expect("success execution");
        assert!(playbook_engine.finish_execution(
            &success_exec,
            crate::playbook::ExecutionStatus::Succeeded,
            None,
            2_450,
        ));

        playbook_dsl.create(crate::playbook_dsl::PlaybookDefinition {
            id: "dsl-credential".to_string(),
            name: "Credential Branching".to_string(),
            description: "Dynamic investigation routing".to_string(),
            version: "1.0.0".to_string(),
            author: "analyst-1".to_string(),
            severity: "high".to_string(),
            mitre_techniques: vec!["T1110".to_string()],
            trigger_conditions: vec!["credential".to_string()],
            nodes: vec![crate::playbook_dsl::PlaybookNode::Step {
                id: "step-1".to_string(),
                title: "Review auth failures".to_string(),
                description: "Inspect auth anomalies".to_string(),
                api_pivot: None,
                actions: vec!["Query auth logs".to_string()],
                evidence: vec!["Affected usernames".to_string()],
                auto_queries: Vec::new(),
            }],
            entry_nodes: vec!["step-1".to_string()],
            created_at: created_at.clone(),
            updated_at: created_at.clone(),
            status: crate::playbook_dsl::PlaybookStatus::Active,
        });
        workflow_store
            .start_investigation("credential-storm", "analyst-1", None)
            .expect("workflow progress");

        api_analytics.record("GET", "/api/workbench/overview", 12.0, false);
        api_analytics.record("POST", "/api/hunts", 145.0, false);

        let analytics = events.analytics();
        let api_summary = api_analytics.summary();
        let feedback_path = temp_path("workbench_feedback");
        let mut detection_feedback =
            crate::detection_feedback::DetectionFeedbackStore::new(feedback_path.to_str().unwrap());
        let review_rule_ids = enterprise
            .builtin_rules()
            .iter()
            .take(12)
            .map(|rule| rule.id.clone())
            .collect::<Vec<_>>();
        for review_rule_id in &review_rule_ids {
            let _ = enterprise.test_rule(review_rule_id, events.all_events());
            let _ = detection_feedback.record(
                None,
                None,
                Some(review_rule_id.clone()),
                "analyst-1".to_string(),
                "true_positive".to_string(),
                None,
                "Reviewed burst against shift handoff evidence.".to_string(),
                Vec::new(),
            );
        }
        let connector_status_entries = vec![serde_json::json!({
            "provider": "okta_identity",
            "label": "Okta Identity",
            "lane": "identity",
            "enabled": true,
            "freshness": "stale",
            "last_success_at": "2024-01-01T00:00:00Z",
            "validation": {
                "status": "warning",
                "issues": [
                    {"field": "api_token", "level": "warning", "message": "Token rotation required."}
                ]
            },
            "route_targets": ["SOC Queue", "UEBA"],
            "ingestion_evidence": {
                "pivots": [
                    {"surface": "SOC Workbench", "href": "/soc?collector=okta_identity&lane=identity", "label": "Open SOC collector context"}
                ]
            }
        })];
        let overview = build_workbench_overview(
            &queue,
            &case_store,
            &incident_store,
            &response,
            &approvals,
            &analytics,
            &events,
            &registry,
            &StdHashMap::new(),
            &connector_status_entries,
            &[],
            &rbac,
            &enterprise,
            &detection_feedback,
            &playbook_engine,
            &playbook_dsl,
            &workflow_store,
            &api_summary,
        );

        assert_eq!(overview.queue.pending, 2);
        assert_eq!(overview.queue.assigned, 1);
        assert_eq!(overview.cases.total, 1);
        assert_eq!(overview.incidents.total, 1);
        assert_eq!(overview.response.ready_to_execute, 1);
        assert_eq!(overview.identity.ready_providers, 1);
        assert_eq!(overview.rollouts.canary_hunts, 1);
        assert!(overview.content.saved_searches > 0);
        assert_eq!(overview.automation.pending_approvals, 1);
        assert_eq!(overview.analytics.api_requests, 2);
        assert_eq!(overview.team_load.active_owners, 1);
        assert_eq!(overview.team_load.available_owners, 1);
        assert_eq!(overview.team_load.pending_approvals, 0);
        assert_eq!(overview.team_load.analysts[0].username, "analyst-1");
        assert!(
            overview
                .team_load
                .role_coverage
                .iter()
                .any(|entry| entry.role == "Analyst" && entry.count == 2)
        );
        assert!(
            overview
                .team_load
                .group_context
                .iter()
                .any(|entry| entry.group == "soc-analysts" && entry.status == "aligned")
        );
        assert_eq!(overview.connector_impact.collectors_at_risk, 1);
        assert!(
            overview
                .connector_impact
                .items
                .iter()
                .any(|item| item.provider == "okta_identity" && item.affected_detections > 0)
        );
        assert!(!overview.detection_review.items.is_empty());
        assert!(
            overview
                .detection_review
                .items
                .iter()
                .any(|item| !item.promotion_blockers.is_empty())
        );
        assert!(overview.detection_review.items.iter().any(|item| {
            item.latest_feedback_verdict.as_deref() == Some("true_positive")
                && item.latest_feedback_notes.as_deref()
                    == Some("Reviewed burst against shift handoff evidence.")
        }));
        assert_eq!(overview.rollouts.rollback_events, 0);
        assert!(
            overview
                .recommendations
                .iter()
                .any(|item| item.category == "rollout" || item.category == "automation")
        );
        assert!(overview.urgent_items.iter().any(|item| item.kind == "queue"
            || item.kind == "response"
            || item.kind == "automation"));
        assert_eq!(overview.hot_agents.len(), 1);

        let _ = fs::remove_file(case_path);
        let _ = fs::remove_file(incident_path);
        let _ = fs::remove_file(agent_path);
        let _ = fs::remove_file(enterprise_path);
        let _ = fs::remove_file(feedback_path);
    }

    #[test]
    fn build_workbench_overview_counts_content_rollbacks() {
        let case_path = temp_path("cases");
        let incident_path = temp_path("incidents");
        let agent_path = temp_path("agents");
        let enterprise_path = temp_path("workbench_rollouts");

        let queue = AlertQueue::new();
        let case_store = CaseStore::new(case_path.to_str().unwrap());
        let incident_store = IncidentStore::new(incident_path.to_str().unwrap());
        let approvals = ApprovalLog::new();
        let response = ResponseOrchestrator::new();
        let events = EventStore::new(16);
        let registry = AgentRegistry::new(agent_path.to_str().unwrap());
        let rbac = crate::rbac::RbacStore::new();
        let mut enterprise = EnterpriseStore::new(enterprise_path.to_str().unwrap());
        let playbook_engine = crate::playbook::PlaybookEngine::new();
        let playbook_dsl = crate::playbook_dsl::PlaybookDslStore::new();
        let workflow_store = crate::investigation::WorkflowStore::new();
        let api_summary = crate::api_analytics::ApiAnalytics::new().summary();
        let feedback_path = temp_path("workbench_rollouts_feedback");
        let detection_feedback =
            crate::detection_feedback::DetectionFeedbackStore::new(feedback_path.to_str().unwrap());
        let connector_status_entries = vec![serde_json::json!({
            "provider": "aws_cloudtrail",
            "label": "AWS CloudTrail",
            "lane": "cloud",
            "enabled": false,
            "freshness": "disabled",
            "last_success_at": serde_json::Value::Null,
            "validation": {"status": "disabled", "issues": []},
            "route_targets": ["Infrastructure", "Attack Graph"],
            "ingestion_evidence": {"pivots": []}
        })];

        enterprise.record_rollout_event(
            "content-rollback",
            "Suspicious PowerShell v3",
            Some("content-rule".to_string()),
            Some("rule-1".to_string()),
            Some("test".to_string()),
            "succeeded",
            "analyst-1",
            Some("Rule rule-1 rolled back from canary to test.".to_string()),
        );

        let overview = build_workbench_overview(
            &queue,
            &case_store,
            &incident_store,
            &response,
            &approvals,
            &events.analytics(),
            &events,
            &registry,
            &StdHashMap::new(),
            &connector_status_entries,
            &[],
            &rbac,
            &enterprise,
            &detection_feedback,
            &playbook_engine,
            &playbook_dsl,
            &workflow_store,
            &api_summary,
        );

        assert_eq!(overview.rollouts.historical_events, 1);
        assert_eq!(overview.rollouts.rollback_events, 1);
        assert_eq!(overview.rollouts.recent_history.len(), 1);

        let _ = fs::remove_file(case_path);
        let _ = fs::remove_file(incident_path);
        let _ = fs::remove_file(agent_path);
        let _ = fs::remove_file(enterprise_path);
        let _ = fs::remove_file(feedback_path);
    }

    #[test]
    fn build_search_index_preserves_alert_event_class_contract() {
        let mut store = EventStore::new(16);
        store.ingest(&EventBatch {
            agent_id: "agent-search".to_string(),
            events: vec![sample_alert(
                "search-host",
                "Critical",
                8.1,
                "credential dumping",
            )],
        });

        let index = build_search_index_from_events(store.all_events()).expect("search index");
        let result = index
            .search(&crate::search::SearchQuery {
                query: "credential dumping".to_string(),
                fields: Vec::new(),
                from: None,
                to: None,
                limit: 10,
                offset: 0,
                sort_by: None,
                sort_desc: false,
            })
            .expect("search result");

        assert_eq!(result.hits.len(), 1);
        assert_eq!(result.hits[0].event_class, "alert");
        assert_ne!(result.hits[0].event_class, "Critical");
    }

    #[test]
    fn build_manager_overview_tracks_fleet_queue_and_deployments() {
        let incident_path = temp_path("manager_incidents");
        let report_path = temp_path("manager_reports");
        let agent_path = temp_path("manager_agents");

        let mut queue = AlertQueue::new();
        let mut incidents = IncidentStore::new(incident_path.to_str().unwrap());
        let response = ResponseOrchestrator::new();
        let mut registry = AgentRegistry::new(agent_path.to_str().unwrap());
        let reports = crate::report::ReportStore::new(report_path.to_str().unwrap());
        let mut events = EventStore::new(50);

        let agent_id = enroll_test_agent(&mut registry, "manager-host", "linux", "2.0.0");
        events.ingest(&EventBatch {
            agent_id: agent_id.clone(),
            events: vec![sample_alert(
                "manager-host",
                "Critical",
                7.8,
                "lateral movement",
            )],
        });
        let event = events.all_events()[0].clone();
        queue.enqueue(
            event.id,
            event.alert.score as f64,
            event.alert.level.clone(),
            event.alert.hostname.clone(),
            event.alert.timestamp.clone(),
        );
        incidents.create(
            "Lateral movement incident".to_string(),
            "Critical".to_string(),
            vec![event.id],
            vec![agent_id.clone()],
            Vec::new(),
            "Manager view incident".to_string(),
        );

        let mut deployments = StdHashMap::new();
        deployments.insert(
            agent_id.clone(),
            AgentDeployment {
                agent_id: agent_id.clone(),
                version: "2.1.0".to_string(),
                platform: "linux".to_string(),
                mandatory: true,
                release_notes: "stability release".to_string(),
                status: "assigned".to_string(),
                status_reason: None,
                rollout_group: "canary".to_string(),
                allow_downgrade: false,
                signature_status: None,
                signer_pubkey: None,
                signature_payload_sha256: None,
                update_counter: None,
                assigned_at: chrono::Utc::now().to_rfc3339(),
                acknowledged_at: None,
                completed_at: None,
                last_heartbeat_at: None,
            },
        );

        let overview = build_manager_overview(
            &queue,
            &incidents,
            &response,
            &events.analytics(),
            &registry,
            &deployments,
            1,
            &reports,
            crate::siem::SiemStatus {
                enabled: true,
                siem_type: "generic".to_string(),
                endpoint: "https://siem.example.test".to_string(),
                pending_events: 4,
                total_pushed: 12,
                total_pulled: 3,
                last_error: None,
                pull_enabled: true,
            },
            2,
            97.5,
        );

        assert_eq!(overview.fleet.total_agents, 1);
        assert_eq!(overview.fleet.online, 1);
        assert_eq!(overview.queue.pending, 1);
        assert_eq!(overview.incidents.total, 1);
        assert_eq!(overview.deployments.published_releases, 1);
        assert_eq!(overview.deployments.pending, 1);
        assert_eq!(overview.tenants, 2);
        assert_eq!(overview.compliance.score, 97.5);

        let _ = fs::remove_file(incident_path);
        let _ = fs::remove_file(report_path);
        let _ = fs::remove_file(agent_path);
    }

    #[test]
    fn graphql_aggregate_json_groups_events_by_level() {
        let mut events = EventStore::new(50);
        events.ingest(&EventBatch {
            agent_id: "agent-1".to_string(),
            events: vec![
                sample_alert("agg-host", "Critical", 9.1, "credential dump"),
                sample_alert("agg-host", "Critical", 8.2, "lateral movement"),
                sample_alert("agg-host", "Elevated", 4.4, "recon"),
            ],
        });

        let args = StdHashMap::from([
            ("source".to_string(), serde_json::json!("events")),
            ("op".to_string(), serde_json::json!("count")),
            ("field".to_string(), serde_json::json!("score")),
            ("group_by".to_string(), serde_json::json!("event_type")),
        ]);
        let agg_agents = temp_path("agg_agents");
        let agg_enterprise = temp_path("agg_enterprise");
        let agg_incidents = temp_path("agg_incidents");

        let aggregated = graphql_aggregate_json(
            &args,
            &VecDeque::new(),
            &AgentRegistry::new(agg_agents.to_str().unwrap()),
            &events,
            &EnterpriseStore::new(agg_enterprise.to_str().unwrap()),
            &IncidentStore::new(agg_incidents.to_str().unwrap()),
            &ThreatIntelStore::new(),
        );

        let groups = aggregated["groups"].as_array().expect("groups array");
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0]["key"], serde_json::json!("Critical"));
        assert_eq!(groups[0]["value"], serde_json::json!(2));
        assert_eq!(groups[1]["key"], serde_json::json!("Elevated"));
        assert_eq!(groups[1]["value"], serde_json::json!(1));

        let _ = fs::remove_file(agg_agents);
        let _ = fs::remove_file(agg_enterprise);
        let _ = fs::remove_file(agg_incidents);
    }

    #[test]
    fn execute_hunt_response_actions_applies_side_effects() {
        let enterprise_path = temp_path("hunt_enterprise");
        let incident_path = temp_path("hunt_incidents");
        let agent_path = temp_path("hunt_agents");
        let mut enterprise = EnterpriseStore::new(enterprise_path.to_str().unwrap());
        let mut incidents = IncidentStore::new(incident_path.to_str().unwrap());
        let response = ResponseOrchestrator::new();
        let mut registry = AgentRegistry::new(agent_path.to_str().unwrap());
        let agent_id = enroll_test_agent(&mut registry, "hunt-host", "linux", "1.0.0");
        let mut events = EventStore::new(20);
        events.ingest(&EventBatch {
            agent_id: agent_id.clone(),
            events: vec![sample_alert(
                "hunt-host",
                "Critical",
                9.7,
                "credential storm",
            )],
        });
        let stored_events = events.all_events().to_vec();

        let hunt = SavedHunt {
            id: "hunt-automation".to_string(),
            name: "Credential Storm".to_string(),
            owner: "secops".to_string(),
            enabled: true,
            severity: "high".to_string(),
            threshold: 1,
            suppression_window_secs: 0,
            schedule_interval_secs: None,
            schedule_cron: None,
            last_run_at: None,
            next_run_at: None,
            query: crate::analyst::SearchQuery {
                text: None,
                hostname: None,
                level: None,
                agent_id: None,
                from_ts: None,
                to_ts: None,
                limit: None,
            },
            hypothesis: "Credential storm should produce correlated host-level evidence"
                .to_string(),
            expected_outcome: crate::enterprise::HuntExpectedOutcome::Confirm,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
            lifecycle: crate::enterprise::ContentLifecycle::Canary,
            canary_percentage: 10,
            pack_id: Some("identity-attacks".to_string()),
            recommended_workflows: vec!["credential-storm".to_string()],
            target_group: Some("soc-analysts".to_string()),
            response_actions: vec![
                HuntResponseAction::Notify {
                    channel: "ops-slack".to_string(),
                    min_level: "medium".to_string(),
                },
                HuntResponseAction::CreateIncident {
                    severity: "high".to_string(),
                    title_template: "{hunt_name}: {match_count} hits".to_string(),
                },
                HuntResponseAction::AutoSuppress {
                    duration_secs: 600,
                    justification: "automatic cool-down".to_string(),
                },
                HuntResponseAction::IsolateAgent,
            ],
            tags: vec![],
            mitre_techniques: vec![],
        };
        let run = HuntRun {
            id: "run-automation".to_string(),
            hunt_id: hunt.id.clone(),
            run_at: chrono::Utc::now().to_rfc3339(),
            match_count: 1,
            suppressed_count: 0,
            threshold_exceeded: true,
            severity: "high".to_string(),
            case_id: None,
            time_from: None,
            time_to: None,
            yield_rate: 1.0,
            matched_event_ids: vec![stored_events[0].id],
            matched_agent_ids: vec![agent_id],
            sample_event_ids: vec![stored_events[0].id],
            summary: "one matching event".to_string(),
        };

        let results = execute_hunt_response_actions(
            &hunt,
            &run,
            &stored_events,
            &mut incidents,
            &mut enterprise,
            &response,
            "system:test",
        );

        assert_eq!(results.len(), 4);
        assert!(results[0].executed);
        assert!(results[0].detail.contains("ops-slack"));
        assert_eq!(incidents.list().len(), 1);
        assert!(
            incidents.list()[0]
                .title
                .contains("Credential Storm: 1 hits")
        );
        assert_eq!(enterprise.suppressions().len(), 1);
        assert_eq!(response.all_requests().len(), 2);
        assert!(
            response
                .all_requests()
                .iter()
                .any(|request| request.action == ResponseAction::Alert
                    && request.status == ApprovalStatus::Executed)
        );
        assert!(
            response
                .all_requests()
                .iter()
                .any(|request| request.action == ResponseAction::Isolate
                    && request.status == ApprovalStatus::Pending)
        );

        let _ = fs::remove_file(enterprise_path);
        let _ = fs::remove_file(incident_path);
        let _ = fs::remove_file(agent_path);
    }

    #[test]
    fn execute_hunt_response_actions_targets_agents_sharing_hostname() {
        let enterprise_path = temp_path("hunt_shared_host_enterprise");
        let incident_path = temp_path("hunt_shared_host_incidents");
        let mut enterprise = EnterpriseStore::new(enterprise_path.to_str().unwrap());
        let mut incidents = IncidentStore::new(incident_path.to_str().unwrap());
        let response = ResponseOrchestrator::new();

        let event_a = crate::event_forward::StoredEvent {
            id: 1,
            agent_id: "agent-a".into(),
            received_at: chrono::Utc::now().to_rfc3339(),
            alert: sample_alert("shared-host", "Critical", 9.0, "burst-a"),
            correlated: false,
            triage: Default::default(),
        };
        let event_b = crate::event_forward::StoredEvent {
            id: 2,
            agent_id: "agent-b".into(),
            received_at: chrono::Utc::now().to_rfc3339(),
            alert: sample_alert("shared-host", "Critical", 9.1, "burst-b"),
            correlated: false,
            triage: Default::default(),
        };
        let hunt = SavedHunt {
            id: "hunt-shared-host".to_string(),
            name: "Shared Host Hunt".to_string(),
            owner: "secops".to_string(),
            enabled: true,
            severity: "high".to_string(),
            threshold: 1,
            suppression_window_secs: 0,
            schedule_interval_secs: None,
            schedule_cron: None,
            last_run_at: None,
            next_run_at: None,
            query: crate::analyst::SearchQuery {
                text: None,
                hostname: None,
                level: None,
                agent_id: None,
                from_ts: None,
                to_ts: None,
                limit: None,
            },
            hypothesis: "Shared host should fan out to both endpoints".to_string(),
            expected_outcome: crate::enterprise::HuntExpectedOutcome::Confirm,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
            lifecycle: crate::enterprise::ContentLifecycle::Canary,
            canary_percentage: 25,
            pack_id: Some("lateral-movement".to_string()),
            recommended_workflows: vec!["lateral-movement".to_string()],
            target_group: Some("soc-analysts".to_string()),
            response_actions: vec![HuntResponseAction::IsolateAgent],
            tags: vec![],
            mitre_techniques: vec![],
        };
        let run = HuntRun {
            id: "run-shared-host".to_string(),
            hunt_id: hunt.id.clone(),
            run_at: chrono::Utc::now().to_rfc3339(),
            match_count: 2,
            suppressed_count: 0,
            threshold_exceeded: true,
            severity: "high".to_string(),
            case_id: None,
            time_from: None,
            time_to: None,
            yield_rate: 1.0,
            matched_event_ids: vec![1, 2],
            matched_agent_ids: vec!["agent-a".into(), "agent-b".into()],
            sample_event_ids: vec![1, 2],
            summary: "two matching agents on shared host".to_string(),
        };

        let results = execute_hunt_response_actions(
            &hunt,
            &run,
            &[event_a, event_b],
            &mut incidents,
            &mut enterprise,
            &response,
            "system:test",
        );

        assert_eq!(results.len(), 1);
        assert!(results[0].executed);
        let requests = response.all_requests();
        assert_eq!(requests.len(), 2);
        assert!(
            requests
                .iter()
                .any(|request| request.target.agent_uid.as_deref() == Some("agent-a"))
        );
        assert!(
            requests
                .iter()
                .any(|request| request.target.agent_uid.as_deref() == Some("agent-b"))
        );

        let _ = fs::remove_file(enterprise_path);
        let _ = fs::remove_file(incident_path);
    }

    #[test]
    fn execute_hunt_response_actions_reuses_existing_hunt_incident() {
        let enterprise_path = temp_path("hunt_reuse_enterprise");
        let incident_path = temp_path("hunt_reuse_incidents");
        let mut enterprise = EnterpriseStore::new(enterprise_path.to_str().unwrap());
        let mut incidents = IncidentStore::new(incident_path.to_str().unwrap());
        let response = ResponseOrchestrator::new();
        let events = vec![crate::event_forward::StoredEvent {
            id: 11,
            agent_id: "agent-a".into(),
            received_at: chrono::Utc::now().to_rfc3339(),
            alert: sample_alert("reuse-host", "Critical", 8.8, "reuse"),
            correlated: false,
            triage: Default::default(),
        }];
        let hunt = SavedHunt {
            id: "hunt-reuse".to_string(),
            name: "Reuse Incident Hunt".to_string(),
            owner: "secops".to_string(),
            enabled: true,
            severity: "high".to_string(),
            threshold: 1,
            suppression_window_secs: 0,
            schedule_interval_secs: None,
            schedule_cron: None,
            last_run_at: None,
            next_run_at: None,
            query: crate::analyst::SearchQuery {
                text: None,
                hostname: None,
                level: None,
                agent_id: None,
                from_ts: None,
                to_ts: None,
                limit: None,
            },
            hypothesis: "Repeated runs should reuse prior incident marker".to_string(),
            expected_outcome: crate::enterprise::HuntExpectedOutcome::Confirm,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
            lifecycle: crate::enterprise::ContentLifecycle::Active,
            canary_percentage: 100,
            pack_id: Some("identity-attacks".to_string()),
            recommended_workflows: vec!["credential-storm".to_string()],
            target_group: Some("soc-analysts".to_string()),
            response_actions: vec![HuntResponseAction::CreateIncident {
                severity: "high".to_string(),
                title_template: "{hunt_name}: {match_count} hits".to_string(),
            }],
            tags: vec![],
            mitre_techniques: vec![],
        };
        let run = HuntRun {
            id: "run-reuse-1".to_string(),
            hunt_id: hunt.id.clone(),
            run_at: chrono::Utc::now().to_rfc3339(),
            match_count: 1,
            suppressed_count: 0,
            threshold_exceeded: true,
            severity: "high".to_string(),
            case_id: None,
            time_from: None,
            time_to: None,
            yield_rate: 1.0,
            matched_event_ids: vec![11],
            matched_agent_ids: vec!["agent-a".into()],
            sample_event_ids: vec![11],
            summary: "first run".to_string(),
        };
        let run_again = HuntRun {
            id: "run-reuse-2".to_string(),
            hunt_id: hunt.id.clone(),
            run_at: chrono::Utc::now().to_rfc3339(),
            match_count: 1,
            suppressed_count: 0,
            threshold_exceeded: true,
            severity: "high".to_string(),
            case_id: None,
            time_from: None,
            time_to: None,
            yield_rate: 1.0,
            matched_event_ids: vec![11],
            matched_agent_ids: vec!["agent-a".into()],
            sample_event_ids: vec![11],
            summary: "second run".to_string(),
        };

        let first = execute_hunt_response_actions(
            &hunt,
            &run,
            &events,
            &mut incidents,
            &mut enterprise,
            &response,
            "system:test",
        );
        let second = execute_hunt_response_actions(
            &hunt,
            &run_again,
            &events,
            &mut incidents,
            &mut enterprise,
            &response,
            "system:test",
        );

        assert_eq!(incidents.list().len(), 1);
        assert!(first[0].detail.contains("Create high incident #"));
        assert!(
            second[0]
                .detail
                .contains("Updated existing high incident #")
        );
        assert!(incidents.list()[0].summary.contains("hunt_id=hunt-reuse"));

        let _ = fs::remove_file(enterprise_path);
        let _ = fs::remove_file(incident_path);
    }

    #[test]
    fn next_response_request_id_is_unique() {
        let first = next_response_request_id();
        let second = next_response_request_id();
        assert_ne!(first, second);
    }

    #[test]
    fn response_request_actor_uses_authenticated_identity() {
        let auth = AuthIdentity::UserToken(User {
            username: "analyst-1".into(),
            role: Role::Analyst,
            token_hash: "analyst-token".into(),
            enabled: true,
            created_at: "now".into(),
            tenant_id: None,
        });

        assert_eq!(response_requested_by(&auth), "analyst-1");
        assert_eq!(response_approver(&auth), "analyst-1");
    }

    #[test]
    fn response_request_actor_uses_admin_identity() {
        assert_eq!(response_requested_by(&AuthIdentity::AdminToken), "admin");
        assert_eq!(response_approver(&AuthIdentity::AdminToken), "admin");
    }

    #[test]
    fn playbook_and_live_response_actor_helpers_use_authenticated_identity() {
        let auth = AuthIdentity::UserToken(User {
            username: "analyst-2".into(),
            role: Role::Analyst,
            token_hash: "analyst-token-2".into(),
            enabled: true,
            created_at: "now".into(),
            tenant_id: None,
        });

        assert_eq!(playbook_executor(&auth), "analyst-2");
        assert_eq!(live_response_operator(&auth), "analyst-2");
    }

    #[test]
    fn session_identity_enforces_target_group_access() {
        let auth = auth_identity_from_session(
            "session-token".to_string(),
            crate::auth::Session {
                user_id: "analyst-3".to_string(),
                email: "analyst-3@example.test".to_string(),
                role: "analyst".to_string(),
                groups: vec!["soc-analysts".to_string(), "canary-lane".to_string()],
                tenant_id: Some("tenant-a".to_string()),
                csrf_token: "csrf-token".to_string(),
                created_at: chrono::Utc::now(),
                expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
            },
            true,
        );

        assert!(ensure_target_group_access(&auth, Some("soc-analysts")).is_ok());
        assert!(ensure_target_group_access(&auth, Some("SOC-ANALYSTS")).is_ok());
        assert!(ensure_target_group_access(&auth, Some("tier-3")).is_err());
    }

    #[test]
    fn non_session_identity_bypasses_target_group_guard() {
        let auth = AuthIdentity::UserToken(User {
            username: "analyst-4".into(),
            role: Role::Analyst,
            token_hash: "rbac-token".into(),
            enabled: true,
            created_at: "now".into(),
            tenant_id: None,
        });

        assert!(ensure_target_group_access(&auth, Some("soc-analysts")).is_ok());
        assert!(
            ensure_target_group_access(&AuthIdentity::AdminToken, Some("soc-analysts")).is_ok()
        );
    }

    #[test]
    fn tenant_filter_for_bound_identity_overrides_missing_query() {
        let auth = AuthIdentity::UserToken(User {
            username: "tenant-user".into(),
            role: Role::Analyst,
            token_hash: "rbac-token".into(),
            enabled: true,
            created_at: "now".into(),
            tenant_id: Some("tenant-a".into()),
        });

        assert_eq!(
            tenant_filter_for_request(&auth, None).unwrap(),
            Some("tenant-a".into())
        );
        assert_eq!(
            tenant_filter_for_request(&auth, Some("tenant-a")).unwrap(),
            Some("tenant-a".into())
        );
        assert!(tenant_filter_for_request(&auth, Some("tenant-b")).is_err());
    }

    #[test]
    fn tenant_filter_for_unbound_identity_preserves_query() {
        let auth = AuthIdentity::AdminToken;
        assert_eq!(
            tenant_filter_for_request(&auth, Some("tenant-b")).unwrap(),
            Some("tenant-b".into())
        );
    }

    #[test]
    fn error_json_includes_structured_code() {
        let resp = error_json("not found", 404);
        assert_eq!(resp.status(), 404);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let bytes = rt
            .block_on(axum::body::to_bytes(resp.into_body(), 1_000_000))
            .unwrap();
        let body = std::str::from_utf8(&bytes).unwrap();
        let v: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(v["code"], "NOT_FOUND");
        assert_eq!(v["error"], "not found");
    }

    #[test]
    fn error_json_codes_for_common_statuses() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let cases = [
            (400, "VALIDATION_ERROR"),
            (401, "AUTH_REQUIRED"),
            (403, "FORBIDDEN"),
            (429, "RATE_LIMITED"),
            (500, "INTERNAL_ERROR"),
        ];
        for (status, expected_code) in cases {
            let resp = error_json("msg", status);
            let bytes = rt
                .block_on(axum::body::to_bytes(resp.into_body(), 1_000_000))
                .unwrap();
            let body = std::str::from_utf8(&bytes).unwrap();
            let v: serde_json::Value = serde_json::from_str(body).unwrap();
            assert_eq!(
                v["code"].as_str().unwrap(),
                expected_code,
                "status {status}"
            );
        }
    }

    #[test]
    fn safe_body_fallback_on_invalid_status() {
        // Status 0 is invalid — safe_body should return 500 fallback
        let r = safe_body(Response::builder().status(0), Body::empty());
        assert_eq!(r.status(), 500);
    }

    #[test]
    fn parse_query_string_decodes_percent_escapes_and_plus() {
        let params =
            parse_query_string("/api/assets/search?q=host%3Aprod+web&owner=alice%40example.com");
        assert_eq!(params.get("q").map(String::as_str), Some("host:prod web"));
        assert_eq!(
            params.get("owner").map(String::as_str),
            Some("alice@example.com")
        );
    }

    #[test]
    fn api_route_access_defaults_api_routes_to_authenticated() {
        assert_eq!(
            api_route_access(&Method::Get, "/api/license"),
            ApiRouteAccess::Authenticated
        );
        assert_eq!(
            api_route_access(&Method::Post, "/api/search"),
            ApiRouteAccess::Authenticated
        );
    }

    #[test]
    fn api_route_access_keeps_public_and_agent_routes_explicit() {
        assert_eq!(
            api_route_access(&Method::Get, "/api/health"),
            ApiRouteAccess::Public
        );
        assert_eq!(
            api_route_access(&Method::Get, "/api/auth/sso/login"),
            ApiRouteAccess::Public
        );
        assert_eq!(
            api_route_access(&Method::Get, "/api/auth/session"),
            ApiRouteAccess::Public
        );
        assert_eq!(
            api_route_access(&Method::Post, "/api/auth/session"),
            ApiRouteAccess::Authenticated
        );
        assert_eq!(
            api_route_access(&Method::Post, "/api/events"),
            ApiRouteAccess::Agent
        );
        assert_eq!(
            classify_api_route_access("get", "/api/agents/update"),
            Some(ApiRouteAccess::Agent)
        );
        assert_eq!(
            classify_api_route_access("GET", "/api/updates/download/wardex-2.0.0-linux"),
            Some(ApiRouteAccess::Agent)
        );
        assert_eq!(
            api_route_access(&Method::Get, "/api/cluster/status"),
            ApiRouteAccess::Cluster
        );
    }

    #[test]
    fn bearer_token_accepts_case_insensitive_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            axum::http::HeaderValue::from_static("bearer secret-token"),
        );
        assert_eq!(bearer_token(&headers).as_deref(), Some("secret-token"));
    }

    #[test]
    fn agent_mtls_request_verified_requires_cert_and_verification_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            MTLS_VERIFY_HEADER,
            axum::http::HeaderValue::from_static("SUCCESS"),
        );
        headers.insert(
            MTLS_CERT_HEADER,
            axum::http::HeaderValue::from_static("Hash=abc123;Subject=\"CN=agent-1\""),
        );
        assert!(agent_mtls_request_verified(&headers));
    }

    #[test]
    fn agent_mtls_request_verified_rejects_partial_or_empty_headers() {
        let mut verification_only = HeaderMap::new();
        verification_only.insert(
            MTLS_VERIFY_HEADER,
            axum::http::HeaderValue::from_static("SUCCESS"),
        );
        assert!(!agent_mtls_request_verified(&verification_only));

        let mut cert_only = HeaderMap::new();
        cert_only.insert(
            MTLS_CERT_HEADER,
            axum::http::HeaderValue::from_static("Hash=abc123;Subject=\"CN=agent-1\""),
        );
        assert!(!agent_mtls_request_verified(&cert_only));

        let mut empty_cert = HeaderMap::new();
        empty_cert.insert(
            MTLS_VERIFY_HEADER,
            axum::http::HeaderValue::from_static("SUCCESS"),
        );
        empty_cert.insert(MTLS_CERT_HEADER, axum::http::HeaderValue::from_static("-"));
        assert!(!agent_mtls_request_verified(&empty_cert));
    }

    #[test]
    fn trusted_mtls_proxy_requires_configured_remote_address() {
        let mut config = Config::default();
        config
            .security
            .trusted_mtls_proxy_addrs
            .push("10.0.0.5".to_string());

        assert!(trusted_mtls_proxy(&config, "10.0.0.5:443"));
        assert!(!trusted_mtls_proxy(&config, "10.0.0.6:443"));
    }

    #[test]
    fn agent_identity_binding_requires_matching_agent_token_and_requested_agent() {
        let (_port, _token, state) = spawn_test_server_with_state();
        let (agent_id, agent_token) = {
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            let token = s.agent_registry.create_token(1);
            let enrolled = s
                .agent_registry
                .enroll(&EnrollRequest {
                    enrollment_token: token.token,
                    hostname: "bound-agent".to_string(),
                    platform: "linux".to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    labels: None,
                })
                .expect("agent enroll");
            (
                enrolled.agent_id,
                enrolled.agent_token.expect("agent token"),
            )
        };
        let url = format!("/api/agents/{agent_id}/heartbeat");
        let mut headers = HeaderMap::new();
        headers.insert(
            AGENT_ID_HEADER,
            axum::http::HeaderValue::from_str(&agent_id).expect("agent id header"),
        );
        headers.insert(
            AGENT_TOKEN_HEADER,
            axum::http::HeaderValue::from_str(&agent_token).expect("agent token header"),
        );

        assert!(agent_request_bound_to_agent(
            &Method::Post,
            &url,
            &headers,
            br#"{"version":"1.0.27"}"#,
            &state,
        ));

        assert!(!agent_request_bound_to_agent(
            &Method::Post,
            "/api/agents/other-agent/heartbeat",
            &headers,
            br#"{"version":"1.0.27"}"#,
            &state,
        ));
    }

    #[test]
    fn apply_api_deprecation_headers_sets_successor_metadata() {
        let mut headers = HeaderMap::new();
        apply_api_deprecation_headers(
            &mut headers,
            &ApiDeprecationMetadata {
                since: "1.0.0".to_string(),
                sunset: "1.1.0".to_string(),
                replacement: "/api/replacement".to_string(),
            },
        );

        assert_eq!(
            headers
                .get("Deprecation")
                .and_then(|value| value.to_str().ok()),
            Some("true")
        );
        assert_eq!(
            headers
                .get("X-Wardex-Deprecated-Since")
                .and_then(|value| value.to_str().ok()),
            Some("1.0.0")
        );
        assert_eq!(
            headers.get("Sunset").and_then(|value| value.to_str().ok()),
            Some("1.1.0")
        );
        assert_eq!(
            headers.get("Link").and_then(|value| value.to_str().ok()),
            Some("</api/replacement>; rel=\"successor-version\"")
        );
    }

    #[test]
    fn case_store_canonicalizes_path() {
        let dir = std::env::temp_dir();
        let path = dir.join("wardex_test_cases_canon.json");
        let store = crate::analyst::CaseStore::new(&path.to_string_lossy());
        // Store should have loaded without panic
        assert_eq!(store.list().len(), 0);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn incident_store_canonicalizes_path() {
        let dir = std::env::temp_dir();
        let path = dir.join("wardex_test_incidents_canon.json");
        let store = crate::incident::IncidentStore::new(&path.to_string_lossy());
        assert_eq!(store.list().len(), 0);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn collector_checkpoint_persists_success_and_failure() {
        let dir = std::env::temp_dir().join(format!(
            "wardex_collector_checkpoint_{}",
            rand::random::<u32>()
        ));
        let storage = SharedStorage::open(dir.to_str().unwrap()).expect("shared storage");

        let success = crate::server_collectors::record_collector_checkpoint(
            &storage,
            "aws_cloudtrail",
            true,
            9,
            None,
        );
        assert_eq!(success.events_ingested, 9);
        assert!(success.last_success_at.is_some());
        assert!(success.checkpoint_id.is_some());

        let reloaded =
            crate::server_collectors::load_collector_checkpoint(&storage, "aws_cloudtrail");
        assert_eq!(reloaded.events_ingested, 9);
        assert_eq!(reloaded.retry_count, 0);

        let failure = crate::server_collectors::record_collector_checkpoint_with_queue(
            &storage,
            "aws_cloudtrail",
            false,
            0,
            Some("unauthorized token"),
            3,
        );
        assert_eq!(failure.events_ingested, 9);
        assert_eq!(failure.error_category.as_deref(), Some("authentication"));
        assert_eq!(failure.queue_depth, 3);
        assert_eq!(failure.retry_count, 1);
        assert!(failure.backoff_seconds > 0);

        let status = crate::server_collectors::collector_status_entry(
            "aws_cloudtrail",
            true,
            60,
            serde_json::json!({"region": "eu-central-1"}),
            crate::integration_setup::SetupValidation {
                status: "ready".to_string(),
                issues: Vec::new(),
            },
            failure,
            crate::server_collectors::load_collector_lifecycle(&storage, "aws_cloudtrail"),
        );
        assert_eq!(
            status
                .get("ingestion_sla")
                .and_then(|sla| sla.get("breach"))
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn report_store_canonicalizes_path() {
        let dir = std::env::temp_dir();
        let path = dir.join("wardex_test_reports_canon.json");
        let store = crate::report::ReportStore::new(&path.to_string_lossy());
        assert_eq!(store.list().len(), 0);
        let _ = std::fs::remove_file(&path);
    }
