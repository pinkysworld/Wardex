#![allow(dead_code, unused_imports)]

use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
pub use wardex::agent_client::AgentClient;
pub use wardex::auth::SessionStore;
pub use wardex::collector::AlertRecord;
pub use wardex::config::Config;
pub use wardex::fleet_install::RemoteInstallRecord;
pub use wardex::server::{
    spawn_test_server, spawn_test_server_with_live_rollback_enabled,
    spawn_test_server_with_live_rollback_execution_enabled, spawn_test_server_with_seeded_alerts,
    spawn_test_server_with_seeded_remote_installs,
};
pub use wardex::telemetry::TelemetrySample;

static COMMAND_PATH_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

pub fn base(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

pub fn auth_header(token: &str) -> String {
    format!("Bearer {token}")
}

pub fn create_rbac_user_token(port: u16, admin_token: &str, username: &str, role: &str) -> String {
    let created: serde_json::Value = ureq::post(&format!("{}/api/rbac/users", base(port)))
        .set("Authorization", &auth_header(admin_token))
        .send_json(serde_json::json!({
            "username": username,
            "role": role
        }))
        .unwrap_or_else(|error| panic!("create rbac user {username}: {error}"))
        .into_json()
        .unwrap_or_else(|error| panic!("rbac user {username} json: {error}"));
    created["token"]
        .as_str()
        .unwrap_or_else(|| panic!("rbac user {username} token"))
        .to_string()
}

pub const LOCAL_CONSOLE_AGENT_ID: &str = "local-console";

pub fn find_agent_by_id<'a>(
    agents: &'a serde_json::Value,
    agent_id: &str,
) -> &'a serde_json::Value {
    agents
        .as_array()
        .and_then(|entries| {
            entries
                .iter()
                .find(|agent| agent["id"] == serde_json::Value::String(agent_id.to_string()))
        })
        .unwrap_or_else(|| panic!("missing agent {agent_id}"))
}

pub fn test_state_root(port: u16) -> PathBuf {
    PathBuf::from(format!("/tmp/wardex_test_{port}"))
}

pub fn test_state_path(port: u16, file_name: &str) -> String {
    test_state_root(port).join(file_name).display().to_string()
}

pub fn create_approved_remediation_review(
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

    let approvers = [
        (
            "primary-reviewer",
            create_rbac_user_token(port, token, "primary-reviewer", "admin"),
        ),
        (
            "secondary-reviewer",
            create_rbac_user_token(port, token, "secondary-reviewer", "admin"),
        ),
    ];

    for (approver, approver_token) in approvers {
        ureq::post(&format!(
            "{}/api/remediation/change-reviews/{}/approval",
            base(port),
            review_id
        ))
        .set("Authorization", &auth_header(&approver_token))
        .send_json(serde_json::json!({
            "approver": approver,
            "decision": "approve",
            "comment": "ok"
        }))
        .expect("signed approval");
    }

    review_id
}

pub fn current_live_rollback_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "linux"
    }
}

pub fn current_restart_service_command() -> &'static str {
    if cfg!(target_os = "macos") {
        "launchctl"
    } else if cfg!(target_os = "windows") {
        "sc"
    } else {
        "systemctl"
    }
}

pub fn current_block_ip_command() -> &'static str {
    if cfg!(target_os = "macos") {
        "pfctl"
    } else if cfg!(target_os = "windows") {
        "netsh"
    } else {
        "iptables"
    }
}

pub fn nonmatching_live_rollback_platform() -> &'static str {
    if cfg!(target_os = "windows") {
        "linux"
    } else {
        "windows"
    }
}

pub fn disable_account_command_for_platform(platform: &str) -> &'static str {
    match platform {
        "macos" => "dscl",
        "windows" => "net",
        _ => "usermod",
    }
}

pub fn flush_dns_command_for_platform(platform: &str) -> &'static str {
    match platform {
        "macos" => "dscacheutil",
        "windows" => "ipconfig",
        _ => "systemd-resolve",
    }
}

pub fn current_disable_account_command() -> &'static str {
    if cfg!(target_os = "macos") {
        "dscl"
    } else if cfg!(target_os = "windows") {
        "net"
    } else {
        "usermod"
    }
}

pub fn current_flush_dns_command() -> &'static str {
    if cfg!(target_os = "macos") {
        "dscacheutil"
    } else if cfg!(target_os = "windows") {
        "ipconfig"
    } else {
        "systemd-resolve"
    }
}

pub fn with_stubbed_commands_path<T>(commands: &[(&str, &str)], test: impl FnOnce() -> T) -> T {
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

pub fn with_stubbed_command_path<T>(
    command_name: &str,
    script: &str,
    test: impl FnOnce() -> T,
) -> T {
    with_stubbed_commands_path(&[(command_name, script)], test)
}

pub fn enroll_test_agent(port: u16, token: &str, hostname: &str) -> String {
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

// ── Helper: create token + enroll agent + ingest events ────────

pub fn setup_agent_with_events(
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
            "score": 5.0 + f64::from(i),
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
