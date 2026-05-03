//! Agent-side HTTP client: enrollment, heartbeats, alert forwarding, and policy polling.

use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::collector::{self, AlertRecord, MonitorConfig};
use crate::config::Config;
use crate::enrollment::{AgentHealth, EnrollRequest, EnrollResponse};

/// Agent-side client that communicates with the Wardex central server.
pub struct AgentClient {
    server_url: String,
    agent_id: Option<String>,
    heartbeat_interval: u64,
    policy_poll_interval: u64,
    runtime_status: Option<Arc<Mutex<AgentRuntimeStatus>>>,
}

#[derive(Debug, Clone, Default)]
struct AgentRuntimeStatus {
    pending_alerts: usize,
    telemetry_queue_depth: usize,
    update_state: Option<String>,
    update_target_version: Option<String>,
    last_update_error: Option<String>,
    last_update_at: Option<String>,
}

const DEFAULT_AGENT_HEARTBEAT_INTERVAL_SECS: u64 = 30;
const DEFAULT_AGENT_POLICY_POLL_INTERVAL_SECS: u64 = 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HeartbeatPayload {
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    health: Option<AgentHealth>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HeartbeatResponse {
    heartbeat_interval_secs: u64,
    #[serde(default)]
    update_assigned: bool,
    #[serde(default)]
    target_version: Option<String>,
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
            runtime_status: None,
        }
    }

    fn attach_runtime_status(&mut self, runtime_status: Arc<Mutex<AgentRuntimeStatus>>) {
        self.runtime_status = Some(runtime_status);
    }

    /// Enroll this agent with the server.
    pub fn enroll(
        &mut self,
        token: &str,
        hostname: &str,
        platform: &str,
    ) -> Result<EnrollResponse, String> {
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
    pub fn heartbeat(&self) -> Result<Option<String>, String> {
        let agent_id = self.agent_id.as_ref().ok_or("not enrolled")?;
        let payload = HeartbeatPayload {
            version: env!("CARGO_PKG_VERSION").to_string(),
            health: self.runtime_health_snapshot(),
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

        let response: HeartbeatResponse = resp
            .into_json()
            .map_err(|e| format!("invalid heartbeat response: {e}"))?;
        self.self_log_update_hint(&response);
        Ok(response.target_version)
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

    fn self_log_update_hint(&self, response: &HeartbeatResponse) {
        if response.update_assigned
            && let Some(version) = &response.target_version
        {
            log::info!("[update] Server assigned remote deployment for v{version}");
        }
    }

    fn process_update(&self, target_version: Option<&str>) {
        self.set_update_state("checking", target_version, None);
        match self.check_update() {
            Ok(Some(info)) => {
                if let Some(expected) = target_version
                    && info.version != expected
                {
                    self.set_update_state(
                        "mismatch",
                        Some(expected),
                        Some(format!(
                            "server returned {} instead of assigned target",
                            info.version
                        )),
                    );
                    log::warn!(
                        "[update] Assigned target {expected}, but server returned {}",
                        info.version
                    );
                    return;
                }
                log::info!("[update] New version available: v{}", info.version);
                if info.mandatory {
                    log::info!("[update] Mandatory update - downloading...");
                }
                self.set_update_state("downloading", Some(&info.version), None);
                match self.download_update(&info) {
                    Ok(binary) => {
                        self.set_update_state("downloaded", Some(&info.version), None);
                        log::info!(
                            "[update] Downloaded {} bytes, checksum verified",
                            binary.len()
                        );
                        self.set_update_state("applying", Some(&info.version), None);
                        if let Err(e) = apply_update(&binary, &info.version) {
                            self.set_update_state("failed", Some(&info.version), Some(e.clone()));
                            log::error!("[update] Failed to apply: {e}");
                        } else {
                            self.set_update_state("restart_pending", Some(&info.version), None);
                            log::info!("[update] Update applied — restart required");
                        }
                    }
                    Err(e) => {
                        self.set_update_state("failed", Some(&info.version), Some(e.clone()));
                        log::error!("[update] Download failed: {e}");
                    }
                }
            }
            Ok(None) => {
                self.set_update_state("idle", None, None);
            }
            Err(e) => {
                self.set_update_state("failed", target_version, Some(e.clone()));
                log::error!("[update] Check failed: {e}");
            }
        }
    }

    fn runtime_health_snapshot(&self) -> Option<AgentHealth> {
        let runtime_status = self.runtime_status.as_ref()?;
        let status = runtime_status.lock().ok()?;
        Some(AgentHealth {
            pending_alerts: status.pending_alerts,
            telemetry_queue_depth: status.telemetry_queue_depth,
            update_state: status.update_state.clone(),
            update_target_version: status.update_target_version.clone(),
            last_update_error: status.last_update_error.clone(),
            last_update_at: status.last_update_at.clone(),
        })
    }

    fn update_runtime_status<F>(&self, mutate: F)
    where
        F: FnOnce(&mut AgentRuntimeStatus),
    {
        if let Some(runtime_status) = &self.runtime_status
            && let Ok(mut status) = runtime_status.lock()
        {
            mutate(&mut status);
        }
    }

    fn set_queue_depth(&self, queue_depth: usize) {
        self.update_runtime_status(|status| {
            status.telemetry_queue_depth = queue_depth;
            status.pending_alerts = queue_depth;
        });
    }

    fn set_update_state(&self, state: &str, target_version: Option<&str>, error: Option<String>) {
        let timestamp = chrono::Utc::now().to_rfc3339();
        self.update_runtime_status(|status| {
            status.update_state = Some(state.to_string());
            status.update_target_version = target_version.map(|value| value.to_string());
            status.last_update_error = error;
            status.last_update_at = Some(timestamp);
        });
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
        let download_url = if info.download_url.starts_with("http://")
            || info.download_url.starts_with("https://")
        {
            info.download_url.clone()
        } else {
            format!("{}{}", self.server_url, info.download_url)
        };

        let resp = ureq::get(&download_url)
            .call()
            .map_err(|e| format!("download failed: {e}"))?;

        if resp.status() != 200 {
            return Err(format!("download rejected: status {}", resp.status()));
        }

        let mut buf = Vec::new();
        const MAX_UPDATE_SIZE: u64 = 500 * 1024 * 1024; // 500 MB
        resp.into_reader()
            .take(MAX_UPDATE_SIZE)
            .read_to_end(&mut buf)
            .map_err(|e| format!("failed to read update binary: {e}"))?;

        // Verify checksum
        use sha2::{Digest, Sha256};
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

    /// Forward collected logs to the server.
    pub fn forward_logs(&self, logs: &[crate::log_collector::LogRecord]) -> Result<(), String> {
        let agent_id = self.agent_id.as_ref().ok_or("not enrolled")?;
        if logs.is_empty() {
            return Ok(());
        }
        let body =
            serde_json::to_string(logs).map_err(|e| format!("failed to serialize logs: {e}"))?;
        let url = format!("{}/api/agents/{}/logs", self.server_url, agent_id);
        let resp = ureq::post(&url)
            .set("Content-Type", "application/json")
            .send_string(&body)
            .map_err(|e| format!("log forward failed: {e}"))?;
        if resp.status() != 200 {
            return Err(format!("log forward rejected: status {}", resp.status()));
        }
        Ok(())
    }

    /// Report system inventory to the server.
    pub fn report_inventory(
        &self,
        inventory: &crate::inventory::SystemInventory,
    ) -> Result<(), String> {
        let agent_id = self.agent_id.as_ref().ok_or("not enrolled")?;
        let body = serde_json::to_string(inventory)
            .map_err(|e| format!("failed to serialize inventory: {e}"))?;
        let url = format!("{}/api/agents/{}/inventory", self.server_url, agent_id);
        let resp = ureq::post(&url)
            .set("Content-Type", "application/json")
            .send_string(&body)
            .map_err(|e| format!("inventory report failed: {e}"))?;
        if resp.status() != 200 {
            return Err(format!(
                "inventory report rejected: status {}",
                resp.status()
            ));
        }
        Ok(())
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

    log::info!("Wardex Agent v{}", env!("CARGO_PKG_VERSION"));
    log::info!(
        "  Platform: {} ({})",
        host_info.platform,
        host_info.hostname
    );
    log::info!("  Server: {}", server_url);

    let mut client = AgentClient::new(server_url);
    let runtime_status = Arc::new(Mutex::new(AgentRuntimeStatus::default()));
    client.attach_runtime_status(runtime_status.clone());
    let persisted_agent_id = config
        .agent
        .agent_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);

    let (agent_id, heartbeat_interval, policy_poll_interval) =
        if let Some(agent_id) = persisted_agent_id {
            log::info!("  Resuming enrolled agent: {agent_id}");
            client.agent_id = Some(agent_id.clone());
            (
                agent_id,
                DEFAULT_AGENT_HEARTBEAT_INTERVAL_SECS,
                DEFAULT_AGENT_POLICY_POLL_INTERVAL_SECS,
            )
        } else {
            let resp = client.enroll(
                enrollment_token,
                &host_info.hostname,
                &host_info.platform.to_string(),
            )?;
            persist_agent_runtime_config(config, server_url, &resp.agent_id)?;
            log::info!("  Enrolled as: {}", resp.agent_id);
            log::info!("  Heartbeat interval: {}s", resp.heartbeat_interval_secs);
            log::info!("");
            (
                resp.agent_id,
                resp.heartbeat_interval_secs,
                resp.policy_poll_interval_secs,
            )
        };

    // Background heartbeat thread
    let heartbeat_shutdown = shutdown.clone();
    let heartbeat_server = server_url.to_string();
    let heartbeat_agent_id = agent_id.clone();
    let heartbeat_runtime_status = runtime_status.clone();
    thread::spawn(move || {
        let mut hb_client = AgentClient::new(&heartbeat_server);
        hb_client.agent_id = Some(heartbeat_agent_id);
        hb_client.attach_runtime_status(heartbeat_runtime_status);
        loop {
            if heartbeat_shutdown.load(Ordering::Relaxed) {
                break;
            }
            thread::sleep(Duration::from_secs(heartbeat_interval));
            if heartbeat_shutdown.load(Ordering::Relaxed) {
                break;
            }
            match hb_client.heartbeat() {
                Ok(target_version) => {
                    if target_version.is_some() {
                        hb_client.process_update(target_version.as_deref());
                    }
                }
                Err(e) => log::error!("heartbeat error: {e}"),
            }
        }
    });

    // Background update check thread
    let update_shutdown = shutdown.clone();
    let update_server = server_url.to_string();
    let update_agent_id = agent_id.clone();
    let update_runtime_status = runtime_status.clone();
    let update_interval_secs = config.agent.update_check_interval_secs.max(60);
    thread::spawn(move || {
        let mut upd_client = AgentClient::new(&update_server);
        upd_client.agent_id = Some(update_agent_id);
        upd_client.attach_runtime_status(update_runtime_status);
        loop {
            if update_shutdown.load(Ordering::Relaxed) {
                break;
            }
            thread::sleep(Duration::from_secs(update_interval_secs));
            if update_shutdown.load(Ordering::Relaxed) {
                break;
            }
            upd_client.process_update(None);
        }
    });

    // Active alert threshold and interval — may be updated by policy enforcement
    let active_threshold = Arc::new(Mutex::new(
        if monitor_args.alert_threshold != MonitorConfig::default().alert_threshold {
            monitor_args.alert_threshold
        } else {
            config.monitor.alert_threshold
        },
    ));
    let active_interval = Arc::new(Mutex::new(config.monitor.interval_secs));

    // Background policy enforcement thread
    let policy_shutdown = shutdown.clone();
    let policy_server = server_url.to_string();
    let policy_agent_id = agent_id.clone();
    let policy_threshold = active_threshold.clone();
    let policy_interval_secs = active_interval.clone();
    thread::spawn(move || {
        let mut pol_client = AgentClient::new(&policy_server);
        pol_client.agent_id = Some(policy_agent_id);
        let mut current_version: u64 = 0;
        loop {
            if policy_shutdown.load(Ordering::Relaxed) {
                break;
            }
            thread::sleep(Duration::from_secs(policy_poll_interval));
            if policy_shutdown.load(Ordering::Relaxed) {
                break;
            }
            match pol_client.fetch_policy() {
                Ok(Some(p)) if p.version > current_version => {
                    current_version = p.version;
                    log::info!("[policy] Applying policy v{}", p.version);
                    if let Some(t) = p.alert_threshold
                        && let Ok(mut th) = policy_threshold.lock()
                    {
                        *th = t;
                        log::info!("[policy]   alert_threshold = {t}");
                    }
                    if let Some(i) = p.interval_secs
                        && let Ok(mut iv) = policy_interval_secs.lock()
                    {
                        *iv = i;
                        log::info!("[policy]   interval_secs = {i}");
                    }
                }
                Ok(_) => {} // no change or no policy
                Err(e) => log::error!("[policy] fetch error: {e}"),
            }
        }
    });

    // Run local monitor, collecting alerts for forwarding
    let interval = Duration::from_secs(config.monitor.interval_secs);

    let mut detector = crate::detector::AnomalyDetector::default();
    let policy = crate::policy::PolicyEngine;
    let mut collector_state = collector::CollectorState::default();
    let fim = if !config.monitor.watch_paths.is_empty() {
        Some(collector::FileIntegrityMonitor::new(
            &config.monitor.watch_paths,
        ))
    } else if !monitor_args.watch_paths.is_empty() {
        Some(collector::FileIntegrityMonitor::new(
            &monitor_args.watch_paths,
        ))
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
    let mut last_inventory_at = 0u64;
    let inventory_interval = 900u64; // every 15 minutes

    // Report initial inventory on enrollment
    {
        let inv = crate::inventory::collect_inventory();
        if let Err(e) = client.report_inventory(&inv) {
            log::error!("[agent] Initial inventory report failed: {e}");
        } else {
            log::info!("[agent] Initial inventory reported");
        }
    }

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let sample = collector::collect_sample(&mut collector_state, fim.as_ref());
        let signal = detector.evaluate(&sample);
        sample_count += 1;

        // Use policy-enforced threshold (may change via server policy push)
        let current_threshold = active_threshold
            .lock()
            .map(|t| *t)
            .unwrap_or(config.monitor.alert_threshold);
        if signal.score >= current_threshold {
            let decision = policy.evaluate(&signal, &sample);
            let level_str = format!("{:?}", decision.level);
            let mitre = crate::telemetry::map_alert_to_mitre(&signal.reasons);
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
                mitre,
                narrative: None,
            };
            pending_alerts.push(alert.clone());
            client.set_queue_depth(pending_alerts.len());

            // Push to SIEM if configured
            if let Some(ref mut siem) = siem_connector {
                siem.queue_alert(&alert);
            }
        }

        // Forward events every 10 samples or when we have 5+ alerts
        if (sample_count.is_multiple_of(10) || pending_alerts.len() >= 5)
            && !pending_alerts.is_empty()
        {
            match client.forward_events(&pending_alerts) {
                Ok(()) => {
                    log::info!(
                        "[agent] Forwarded {} alerts to server",
                        pending_alerts.len()
                    );
                    pending_alerts.clear();
                    client.set_queue_depth(0);
                }
                Err(e) => log::error!("[agent] Forward failed (will retry): {e}"),
            }
        }

        // Collect and forward logs every heartbeat cycle
        if sample_count.is_multiple_of(10) {
            let logs = crate::log_collector::collect_recent_logs(50);
            if !logs.is_empty() {
                match client.forward_logs(&logs) {
                    Ok(()) => log::info!("[agent] Forwarded {} log records", logs.len()),
                    Err(e) => log::error!("[agent] Log forward failed: {e}"),
                }
                if let Some(ref mut siem) = siem_connector {
                    for log in &logs {
                        siem.queue_log(log);
                    }
                }
            }
        }

        // Re-report inventory periodically
        let elapsed = sample_count * config.monitor.interval_secs;
        if elapsed - last_inventory_at >= inventory_interval {
            last_inventory_at = elapsed;
            let inv = crate::inventory::collect_inventory();
            if let Err(e) = client.report_inventory(&inv) {
                log::error!("[agent] Inventory report failed: {e}");
            }
            if let Some(ref mut siem) = siem_connector {
                siem.push_inventory(&inv, client.agent_id().unwrap_or("unknown"));
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
    let exe_path =
        std::env::current_exe().map_err(|e| format!("cannot determine current executable: {e}"))?;
    let backup_path = exe_path.with_extension("bak");

    // Create backup of current binary
    std::fs::copy(&exe_path, &backup_path)
        .map_err(|e| format!("failed to backup current binary: {e}"))?;

    // Write new binary
    std::fs::write(&exe_path, binary).map_err(|e| {
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

    log::info!(
        "[update] Updated to v{version}. Backup at: {}",
        backup_path.display()
    );
    Ok(())
}

fn persist_agent_runtime_config(
    config: &Config,
    server_url: &str,
    agent_id: &str,
) -> Result<(), String> {
    let path = crate::config::runtime_config_path();
    persist_agent_runtime_config_at_path(config, server_url, agent_id, &path)
}

fn persist_agent_runtime_config_at_path(
    config: &Config,
    server_url: &str,
    agent_id: &str,
    path: &Path,
) -> Result<(), String> {
    let mut next = config.clone();
    next.agent.server_url = server_url.to_string();
    next.agent.enrollment_token.clear();
    next.agent.agent_id = Some(agent_id.to_string());

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create agent config directory: {e}"))?;
    }

    let raw = toml::to_string_pretty(&next)
        .map_err(|e| format!("failed to serialize agent config: {e}"))?;
    std::fs::write(path, raw).map_err(|e| format!("failed to write agent config: {e}"))
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

    #[test]
    fn persist_agent_runtime_config_clears_token_and_stores_agent_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.toml");
        let mut config = Config::default();
        config.agent.server_url = "http://old.example.com:8080".into();
        config.agent.enrollment_token = "single-use-token".into();

        persist_agent_runtime_config_at_path(
            &config,
            "https://manager.example.com:9090",
            "agent-123",
            &path,
        )
        .unwrap();

        let saved = std::fs::read_to_string(path).unwrap();
        assert!(saved.contains("server_url = \"https://manager.example.com:9090\""));
        assert!(saved.contains("agent_id = \"agent-123\""));
        assert!(saved.contains("enrollment_token = \"\""));
    }
}
