mod common;
use common::*;

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
    let primary_approver_token = create_rbac_user_token(port, &token, "primary-reviewer", "admin");
    let second_approver_token = create_rbac_user_token(port, &token, "secondary-reviewer", "admin");

    let first_approval = ureq::post(&format!(
        "{}/api/remediation/change-reviews/{}/approval",
        base(port),
        review_id
    ))
    .set("Authorization", &auth_header(&primary_approver_token))
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
    .set("Authorization", &auth_header(&second_approver_token))
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
