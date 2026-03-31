use serde::{Deserialize, Serialize};
use std::thread;
use std::time::Duration;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::collector::{self, AlertRecord, MonitorConfig};
use crate::config::Config;
use crate::enrollment::{EnrollRequest, EnrollResponse};

/// Agent-side client that communicates with the Wardex central server.
pub struct AgentClient {
    server_url: String,
    agent_id: Option<String>,
    heartbeat_interval: u64,
    policy_poll_interval: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HeartbeatPayload {
    version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EventBatch {
    agent_id: String,
    events: Vec<AlertRecord>,
}

impl AgentClient {
    pub fn new(server_url: &str) -> Self {
        Self {
            server_url: server_url.trim_end_matches('/').to_string(),
            agent_id: None,
            heartbeat_interval: 30,
            policy_poll_interval: 60,
        }
    }

    /// Enroll this agent with the server.
    pub fn enroll(&mut self, token: &str, hostname: &str, platform: &str) -> Result<EnrollResponse, String> {
        let req = EnrollRequest {
            enrollment_token: token.to_string(),
            hostname: hostname.to_string(),
            platform: platform.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            labels: None,
        };

        let body = serde_json::to_string(&req)
            .map_err(|e| format!("failed to serialize enrollment: {e}"))?;

        let resp = ureq::post(&format!("{}/api/agents/enroll", self.server_url))
            .set("Content-Type", "application/json")
            .send_string(&body)
            .map_err(|e| format!("enrollment request failed: {e}"))?;

        if resp.status() != 200 {
            return Err(format!("enrollment failed with status {}", resp.status()));
        }

        let enroll_resp: EnrollResponse = resp
            .into_json()
            .map_err(|e| format!("invalid enrollment response: {e}"))?;

        self.agent_id = Some(enroll_resp.agent_id.clone());
        self.heartbeat_interval = enroll_resp.heartbeat_interval_secs;
        self.policy_poll_interval = enroll_resp.policy_poll_interval_secs;

        Ok(enroll_resp)
    }

    /// Send heartbeat to server.
    pub fn heartbeat(&self) -> Result<(), String> {
        let agent_id = self.agent_id.as_ref().ok_or("not enrolled")?;
        let payload = HeartbeatPayload {
            version: env!("CARGO_PKG_VERSION").to_string(),
        };
        let body = serde_json::to_string(&payload)
            .map_err(|e| format!("failed to serialize heartbeat: {e}"))?;

        let url = format!("{}/api/agents/{}/heartbeat", self.server_url, agent_id);
        let resp = ureq::post(&url)
            .set("Content-Type", "application/json")
            .send_string(&body)
            .map_err(|e| format!("heartbeat failed: {e}"))?;

        if resp.status() != 200 {
            return Err(format!("heartbeat rejected: status {}", resp.status()));
        }
        Ok(())
    }

    /// Forward alert events to the server.
    pub fn forward_events(&self, events: &[AlertRecord]) -> Result<(), String> {
        let agent_id = self.agent_id.as_ref().ok_or("not enrolled")?;
        if events.is_empty() {
            return Ok(());
        }

        let batch = EventBatch {
            agent_id: agent_id.clone(),
            events: events.to_vec(),
        };
        let body = serde_json::to_string(&batch)
            .map_err(|e| format!("failed to serialize events: {e}"))?;

        let url = format!("{}/api/events", self.server_url);
        let resp = ureq::post(&url)
            .set("Content-Type", "application/json")
            .send_string(&body)
            .map_err(|e| format!("event forward failed: {e}"))?;

        if resp.status() != 200 {
            return Err(format!("event forward rejected: status {}", resp.status()));
        }
        Ok(())
    }

    /// Fetch the latest policy from the server.
    pub fn fetch_policy(&self) -> Result<Option<PolicyPayload>, String> {
        let url = format!("{}/api/policy/current", self.server_url);
        let resp = ureq::get(&url)
            .call()
            .map_err(|e| format!("policy fetch failed: {e}"))?;

        if resp.status() == 204 {
            return Ok(None);
        }
        if resp.status() != 200 {
            return Err(format!("policy fetch rejected: status {}", resp.status()));
        }

        let policy: PolicyPayload = resp
            .into_json()
            .map_err(|e| format!("invalid policy response: {e}"))?;
        Ok(Some(policy))
    }

    /// Check for available updates from the server.
    pub fn check_update(&self) -> Result<Option<UpdateInfo>, String> {
        let agent_id = self.agent_id.as_ref().ok_or("not enrolled")?;
        let current_version = env!("CARGO_PKG_VERSION");
        let url = format!(
            "{}/api/agents/update?agent_id={}&current_version={}",
            self.server_url, agent_id, current_version
        );
        let resp = ureq::get(&url)
            .call()
            .map_err(|e| format!("update check failed: {e}"))?;

        if resp.status() == 204 {
            return Ok(None);
        }
        if resp.status() != 200 {
            return Err(format!("update check rejected: status {}", resp.status()));
        }

        let info: UpdateInfo = resp
            .into_json()
            .map_err(|e| format!("invalid update response: {e}"))?;
        Ok(Some(info))
    }

    /// Download an update binary from the server.
    pub fn download_update(&self, info: &UpdateInfo) -> Result<Vec<u8>, String> {
        let resp = ureq::get(&info.download_url)
            .call()
            .map_err(|e| format!("download failed: {e}"))?;

        if resp.status() != 200 {
            return Err(format!("download rejected: status {}", resp.status()));
        }

        let mut buf = Vec::new();
        resp.into_reader()
            .read_to_end(&mut buf)
            .map_err(|e| format!("failed to read update binary: {e}"))?;

        // Verify checksum
        use sha2::{Sha256, Digest};
        let hash = hex::encode(Sha256::digest(&buf));
        if hash != info.sha256 {
            return Err(format!(
                "checksum mismatch: expected {}, got {}",
                info.sha256, hash
            ));
        }

        Ok(buf)
    }

    pub fn agent_id(&self) -> Option<&str> {
        self.agent_id.as_deref()
    }
}

/// Policy payload received from the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyPayload {
    pub version: u64,
    pub alert_threshold: Option<f32>,
    pub interval_secs: Option<u64>,
    pub watch_paths: Option<Vec<String>>,
    pub dry_run: Option<bool>,
    pub syslog: Option<bool>,
    pub cef: Option<bool>,
}

/// Update information from the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateInfo {
    pub version: String,
    pub download_url: String,
    pub sha256: String,
    pub release_notes: String,
    pub mandatory: bool,
}

/// Run the agent main loop: heartbeat + monitor + event forwarding.
pub fn run_agent(
    server_url: &str,
    enrollment_token: &str,
    config: &Config,
    monitor_args: &collector::MonitorConfig,
    shutdown: Arc<AtomicBool>,
) -> Result<(), String> {
    // Detect host info
    let host_info = collector::detect_platform();

    eprintln!("Wardex Agent v{}", env!("CARGO_PKG_VERSION"));
    eprintln!("  Platform: {} ({})", host_info.platform, host_info.hostname);
    eprintln!("  Server: {}", server_url);

    // Enroll
    let mut client = AgentClient::new(server_url);
    let resp = client.enroll(enrollment_token, &host_info.hostname, &host_info.platform.to_string())?;
    eprintln!("  Enrolled as: {}", resp.agent_id);
    eprintln!("  Heartbeat interval: {}s", resp.heartbeat_interval_secs);
    eprintln!();

    // Background heartbeat thread
    let heartbeat_interval = resp.heartbeat_interval_secs;
    let heartbeat_shutdown = shutdown.clone();
    let heartbeat_server = server_url.to_string();
    let heartbeat_agent_id = resp.agent_id.clone();
    thread::spawn(move || {
        let mut hb_client = AgentClient::new(&heartbeat_server);
        hb_client.agent_id = Some(heartbeat_agent_id);
        loop {
            if heartbeat_shutdown.load(Ordering::Relaxed) {
                break;
            }
            thread::sleep(Duration::from_secs(heartbeat_interval));
            if heartbeat_shutdown.load(Ordering::Relaxed) {
                break;
            }
            if let Err(e) = hb_client.heartbeat() {
                eprintln!("heartbeat error: {e}");
            }
        }
    });

    // Background update check thread
    let update_shutdown = shutdown.clone();
    let update_server = server_url.to_string();
    let update_agent_id = resp.agent_id.clone();
    thread::spawn(move || {
        let mut upd_client = AgentClient::new(&update_server);
        upd_client.agent_id = Some(update_agent_id);
        loop {
            if update_shutdown.load(Ordering::Relaxed) {
                break;
            }
            // Check for updates every 5 minutes
            thread::sleep(Duration::from_secs(300));
            if update_shutdown.load(Ordering::Relaxed) {
                break;
            }
            match upd_client.check_update() {
                Ok(Some(info)) => {
                    eprintln!("[update] New version available: v{}", info.version);
                    if info.mandatory {
                        eprintln!("[update] Mandatory update — downloading...");
                    }
                    match upd_client.download_update(&info) {
                        Ok(binary) => {
                            eprintln!("[update] Downloaded {} bytes, checksum verified", binary.len());
                            if let Err(e) = apply_update(&binary, &info.version) {
                                eprintln!("[update] Failed to apply: {e}");
                            } else {
                                eprintln!("[update] Update applied — restart required");
                            }
                        }
                        Err(e) => eprintln!("[update] Download failed: {e}"),
                    }
                }
                Ok(None) => {} // no update available
                Err(e) => eprintln!("[update] Check failed: {e}"),
            }
        }
    });

    // Run local monitor, collecting alerts for forwarding
    let interval = Duration::from_secs(config.monitor.interval_secs);
    let alert_threshold = if monitor_args.alert_threshold != MonitorConfig::default().alert_threshold {
        monitor_args.alert_threshold
    } else {
        config.monitor.alert_threshold
    };

    let mut detector = crate::detector::AnomalyDetector::default();
    let policy = crate::policy::PolicyEngine::default();
    let mut collector_state = collector::CollectorState::default();
    let fim = if !config.monitor.watch_paths.is_empty() {
        Some(collector::FileIntegrityMonitor::new(&config.monitor.watch_paths))
    } else if !monitor_args.watch_paths.is_empty() {
        Some(collector::FileIntegrityMonitor::new(&monitor_args.watch_paths))
    } else {
        None
    };

    // SIEM connector
    let mut siem_connector = if config.siem.enabled {
        Some(crate::siem::SiemConnector::new(config.siem.clone()))
    } else {
        None
    };

    let mut pending_alerts: Vec<AlertRecord> = Vec::new();
    let mut sample_count = 0u64;

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let sample = collector::collect_sample(&mut collector_state, fim.as_ref());
        let signal = detector.evaluate(&sample);
        sample_count += 1;

        if signal.score >= alert_threshold {
            let decision = policy.evaluate(&signal, &sample);
            let level_str = format!("{:?}", decision.level);
            let alert = AlertRecord {
                timestamp: chrono::Utc::now().to_rfc3339(),
                hostname: host_info.hostname.clone(),
                platform: host_info.platform.to_string(),
                score: signal.score,
                confidence: signal.confidence,
                level: level_str,
                action: format!("{:?}", decision.action),
                reasons: signal.reasons.clone(),
                sample,
                enforced: false,
            };
            pending_alerts.push(alert.clone());

            // Push to SIEM if configured
            if let Some(ref mut siem) = siem_connector {
                siem.queue_alert(&alert);
            }
        }

        // Forward events every 10 samples or when we have 5+ alerts
        if sample_count % 10 == 0 || pending_alerts.len() >= 5 {
            if !pending_alerts.is_empty() {
                match client.forward_events(&pending_alerts) {
                    Ok(()) => {
                        eprintln!("[agent] Forwarded {} alerts to server", pending_alerts.len());
                        pending_alerts.clear();
                    }
                    Err(e) => eprintln!("[agent] Forward failed (will retry): {e}"),
                }
            }
        }

        thread::sleep(interval);
    }

    // Final flush
    if !pending_alerts.is_empty() {
        let _ = client.forward_events(&pending_alerts);
    }
    if let Some(ref mut siem) = siem_connector {
        let _ = siem.flush();
    }

    Ok(())
}

/// Apply a downloaded update binary.
fn apply_update(binary: &[u8], version: &str) -> Result<(), String> {
    let exe_path = std::env::current_exe()
        .map_err(|e| format!("cannot determine current executable: {e}"))?;
    let backup_path = exe_path.with_extension("bak");

    // Create backup of current binary
    std::fs::copy(&exe_path, &backup_path)
        .map_err(|e| format!("failed to backup current binary: {e}"))?;

    // Write new binary
    std::fs::write(&exe_path, binary)
        .map_err(|e| {
            // Restore backup on failure
            let _ = std::fs::copy(&backup_path, &exe_path);
            format!("failed to write update: {e}")
        })?;

    // Set executable permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&exe_path, std::fs::Permissions::from_mode(0o755));
    }

    eprintln!("[update] Updated to v{version}. Backup at: {}", backup_path.display());
    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_client_creation() {
        let client = AgentClient::new("http://localhost:8080");
        assert_eq!(client.server_url, "http://localhost:8080");
        assert!(client.agent_id.is_none());
    }

    #[test]
    fn agent_client_trailing_slash() {
        let client = AgentClient::new("http://localhost:8080/");
        assert_eq!(client.server_url, "http://localhost:8080");
    }

    #[test]
    fn policy_payload_deserializes() {
        let json = r#"{"version":1,"alert_threshold":5.0}"#;
        let policy: PolicyPayload = serde_json::from_str(json).unwrap();
        assert_eq!(policy.version, 1);
        assert_eq!(policy.alert_threshold, Some(5.0));
        assert!(policy.watch_paths.is_none());
    }

    #[test]
    fn update_info_deserializes() {
        let json = r#"{
            "version": "0.16.0",
            "download_url": "http://localhost:8080/api/agents/update/download",
            "sha256": "abcd1234",
            "release_notes": "bug fixes",
            "mandatory": false
        }"#;
        let info: UpdateInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.version, "0.16.0");
        assert!(!info.mandatory);
    }
}
