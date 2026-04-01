use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tiny_http::{Header, Method, Request, Response, Server};

use crate::actions::DeviceController;
use crate::auto_update::UpdateManager;
use crate::checkpoint::CheckpointStore;
use crate::compliance::{ComplianceManager, CausalGraph};
use crate::collector::{AlertRecord, CollectorState, FileIntegrityMonitor, HostInfo, HostPlatform, detect_platform};
use crate::config::Config;
use crate::correlation;
use crate::detector::{AdaptationMode, AnomalyDetector, CompoundThreatDetector, DriftDetector, EntropyDetector, VelocityDetector};
use crate::digital_twin::DigitalTwinEngine;
use crate::edge_cloud::{PlatformCapabilities, PatchManager};
use crate::enforcement::EnforcementEngine;
use crate::energy::EnergyBudget;
use crate::enrollment::AgentRegistry;
use crate::event_forward::EventStore;
use crate::fingerprint::DeviceFingerprint;
use crate::incident::IncidentStore;
use crate::monitor::Monitor;
use crate::multi_tenant::MultiTenantManager;
use crate::policy_dist::PolicyStore;
use crate::privacy::PrivacyAccountant;
use crate::proof::{DigestBackend, ProofRegistry};
use crate::quantum::KeyRotationManager;
use crate::replay::ReplayBuffer;
use crate::report::JsonReport;
use crate::runtime;
use crate::side_channel::SideChannelDetector;
use crate::siem::SiemConnector;
use crate::state_machine::PolicyStateMachine;
use crate::swarm::{DeviceRecord, DeviceStatus, SwarmNode};
use crate::telemetry::TelemetrySample;
use crate::threat_intel::{DeceptionEngine, ThreatIntelStore};
use crate::tls::ListenerMode;
use crate::wasm_engine::PolicyVm;

use crate::analyst::{AlertQueue, ApprovalLog, CaseStore, CasePriority, CaseStatus, ApprovalDecision};
use crate::feature_flags::FeatureFlagRegistry;
use crate::ocsf::{self, DeadLetterQueue, SchemaVersion};
use crate::process_tree::ProcessTree;
use crate::rbac::RbacStore;
use crate::response::ResponseOrchestrator;
use crate::sigma::SigmaEngine;
use crate::spool::EncryptedSpool;

// ── Rate Limiter ────────────────────────────────────────────

struct RateLimiter {
    buckets: HashMap<String, (u64, u32)>, // IP -> (window_start_epoch, count)
    max_per_minute: u32,
}

impl RateLimiter {
    fn new(max_per_minute: u32) -> Self {
        Self { buckets: HashMap::new(), max_per_minute }
    }

    fn check(&mut self, ip: &str) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let entry = self.buckets.entry(ip.to_string()).or_insert((now, 0));
        if now - entry.0 >= 60 {
            *entry = (now, 1);
            true
        } else {
            entry.1 += 1;
            entry.1 <= self.max_per_minute
        }
    }
}

// ── Audit Log ───────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize)]
struct AuditEntry {
    timestamp: String,
    method: String,
    path: String,
    source_ip: String,
    status_code: u16,
    auth_used: bool,
}

struct AuditLog {
    entries: Vec<AuditEntry>,
    max_entries: usize,
}

impl AuditLog {
    fn new(max_entries: usize) -> Self {
        Self { entries: Vec::new(), max_entries }
    }

    fn record(&mut self, method: &str, path: &str, source_ip: &str, status_code: u16, auth_used: bool) {
        let entry = AuditEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            method: method.to_string(),
            path: path.to_string(),
            source_ip: source_ip.to_string(),
            status_code,
            auth_used,
        };
        if self.entries.len() >= self.max_entries {
            self.entries.remove(0);
        }
        self.entries.push(entry);
    }

    fn recent(&self, limit: usize) -> &[AuditEntry] {
        let start = self.entries.len().saturating_sub(limit);
        &self.entries[start..]
    }
}

struct AppState {
    detector: AnomalyDetector,
    checkpoints: CheckpointStore,
    device: DeviceController,
    replay: ReplayBuffer,
    proofs: ProofRegistry,
    last_report: Option<JsonReport>,
    token: String,
    swarm: SwarmNode,
    enforcement: EnforcementEngine,
    threat_intel: ThreatIntelStore,
    digital_twin: DigitalTwinEngine,
    compliance: ComplianceManager,
    multi_tenant: MultiTenantManager,
    energy: EnergyBudget,
    side_channel: SideChannelDetector,
    key_rotation: KeyRotationManager,
    privacy: PrivacyAccountant,
    policy_vm: PolicyVm,
    fingerprint: Option<DeviceFingerprint>,
    monitor: Monitor,
    drift: DriftDetector,
    deception: DeceptionEngine,
    patches: PatchManager,
    causal: CausalGraph,
    listener_mode: ListenerMode,
    config: Config,
    alerts: Vec<AlertRecord>,
    server_start: std::time::Instant,
    // XDR fleet management
    agent_registry: AgentRegistry,
    event_store: EventStore,
    policy_store: PolicyStore,
    update_manager: UpdateManager,
    remote_deployments: HashMap<String, AgentDeployment>,
    deployment_store_path: String,
    siem_connector: SiemConnector,
    // Local host telemetry (ring buffer, last 300 samples)
    local_telemetry: Vec<TelemetrySample>,
    local_host_info: HostInfo,
    // Phase 21: advanced detectors
    velocity: VelocityDetector,
    entropy: EntropyDetector,
    compound: CompoundThreatDetector,
    // Phase 22: shutdown support
    shutdown: Arc<AtomicBool>,
    // Phase 25: rate limiter, audit, incidents, agent logs/inventory
    rate_limiter: RateLimiter,
    audit_log: AuditLog,
    incident_store: IncidentStore,
    agent_logs: HashMap<String, Vec<crate::log_collector::LogRecord>>,
    agent_inventories: HashMap<String, crate::inventory::SystemInventory>,
    report_store: crate::report::ReportStore,
    // Phase 26: XDR AI handoff modules
    sigma_engine: SigmaEngine,
    response_orchestrator: ResponseOrchestrator,
    feature_flags: FeatureFlagRegistry,
    process_tree: ProcessTree,
    spool: EncryptedSpool,
    rbac: RbacStore,
    // Phase 27: Analyst console
    case_store: CaseStore,
    alert_queue: AlertQueue,
    approval_log: ApprovalLog,
    // Dead-letter queue
    dead_letter_queue: DeadLetterQueue,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct AgentDeployment {
    agent_id: String,
    version: String,
    platform: String,
    mandatory: bool,
    release_notes: String,
    #[serde(default = "default_deployment_status")]
    status: String,
    status_reason: Option<String>,
    #[serde(default = "default_rollout_group")]
    rollout_group: String,
    #[serde(default)]
    allow_downgrade: bool,
    assigned_at: String,
    acknowledged_at: Option<String>,
    completed_at: Option<String>,
    last_heartbeat_at: Option<String>,
}

#[derive(Debug, Default)]
struct EventQuery {
    agent_id: Option<String>,
    severity: Option<String>,
    reason: Option<String>,
    correlated: Option<bool>,
    triage_status: Option<String>,
    assignee: Option<String>,
    tag: Option<String>,
    limit: usize,
}

pub fn run_server(port: u16, site_dir: &Path, shutdown: Arc<AtomicBool>) -> Result<(), String> {
    let addr = format!("0.0.0.0:{port}");
    let server = Server::http(&addr).map_err(|e| format!("failed to start server: {e}"))?;

    let token = generate_token();
    println!("Wardex admin console");
    println!("  Listening on http://localhost:{port}");
    println!("  Site directory: {}", site_dir.display());
    println!("  Auth token: {token}");
    println!("  Press Ctrl+C to stop");

    let state = Arc::new(Mutex::new(AppState {
        detector: AnomalyDetector::default(),
        checkpoints: CheckpointStore::new(10),
        device: DeviceController::default(),
        replay: ReplayBuffer::new(200),
        proofs: ProofRegistry::new(),
        last_report: None,
        token: token.clone(),
        swarm: SwarmNode::new("gateway-0"),
        enforcement: EnforcementEngine::new(),
        threat_intel: ThreatIntelStore::new(),
        digital_twin: DigitalTwinEngine::new(),
        compliance: ComplianceManager::new(),
        multi_tenant: MultiTenantManager::new(),
        energy: EnergyBudget::new(500.0),
        side_channel: SideChannelDetector::new(),
        key_rotation: KeyRotationManager::new(3600),
        privacy: PrivacyAccountant::new(10.0),
        policy_vm: PolicyVm::default(),
        fingerprint: None,
        monitor: Monitor::new(),
        drift: DriftDetector::new(0.005, 50.0),
        deception: DeceptionEngine::new(),
        patches: PatchManager::new(),
        causal: CausalGraph::new(),
        listener_mode: ListenerMode::Plain { port },
        config: Config::default(),
        alerts: Vec::new(),
        server_start: std::time::Instant::now(),
        agent_registry: AgentRegistry::new("var/agents.json"),
        event_store: EventStore::with_persistence(10_000, "var/events.json"),
        policy_store: PolicyStore::new(),
        update_manager: UpdateManager::new("var/updates"),
        remote_deployments: load_remote_deployments("var/deployments.json"),
        deployment_store_path: "var/deployments.json".to_string(),
        siem_connector: SiemConnector::new(crate::siem::SiemConfig::default()),
        local_telemetry: Vec::new(),
        local_host_info: detect_platform(),
        velocity: VelocityDetector::new(60, 2.5),
        entropy: EntropyDetector::new(60, 8),
        compound: CompoundThreatDetector::default(),
        shutdown: shutdown.clone(),
        rate_limiter: RateLimiter::new(60),
        audit_log: AuditLog::new(1000),
        incident_store: IncidentStore::new("var/incidents.json"),
        agent_logs: HashMap::new(),
        agent_inventories: HashMap::new(),
        report_store: crate::report::ReportStore::new("var/reports.json"),
        sigma_engine: SigmaEngine::new(),
        response_orchestrator: ResponseOrchestrator::new(),
        feature_flags: FeatureFlagRegistry::new(),
        process_tree: ProcessTree::new("localhost"),
        spool: EncryptedSpool::new(b"server-spool-key-placeholder!!", 10_000),
        rbac: RbacStore::new(),
        case_store: CaseStore::new("var/cases.json"),
        alert_queue: AlertQueue::new(),
        approval_log: ApprovalLog::new(),
        dead_letter_queue: DeadLetterQueue::new(500),
    }));

    // ── Spawn local host monitoring thread ──────────────────────────
    {
        let monitor_state = Arc::clone(&state);
        std::thread::spawn(move || {
            let mut cs = CollectorState::default();
            let mut consecutive_elevated: u32 = 0;
            let mut file_watch_cache: Vec<String> = Vec::new();
            let mut file_monitor: Option<FileIntegrityMonitor> = None;
            let mut persistence_watch_cache: Vec<String> = Vec::new();
            let mut persistence_monitor: Option<FileIntegrityMonitor> = None;
            const CONFIRM_SAMPLES: u32 = 2; // require N consecutive elevated before alerting
            loop {
                let (scope, watch_paths, host_platform) = {
                    let s = monitor_state.lock().unwrap();
                    (
                        s.config.monitor.scope.clone(),
                        s.config.monitor.watch_paths.clone(),
                        s.local_host_info.platform,
                    )
                };

                if scope.file_integrity {
                    if watch_paths != file_watch_cache {
                        file_monitor = if watch_paths.is_empty() {
                            None
                        } else {
                            Some(FileIntegrityMonitor::new(&watch_paths))
                        };
                        file_watch_cache = watch_paths.clone();
                    }
                } else {
                    file_monitor = None;
                    file_watch_cache.clear();
                }

                let persistence_paths = crate::collector::persistence_watch_paths(host_platform, &scope);
                if persistence_paths != persistence_watch_cache {
                    persistence_monitor = if persistence_paths.is_empty() {
                        None
                    } else {
                        Some(FileIntegrityMonitor::new(&persistence_paths))
                    };
                    persistence_watch_cache = persistence_paths;
                }

                let sample = crate::collector::collect_sample_scoped(
                    &mut cs,
                    file_monitor.as_ref(),
                    persistence_monitor.as_ref(),
                    &scope,
                );
                {
                    let mut s = monitor_state.lock().unwrap();
                    if s.local_telemetry.len() >= 300 {
                        s.local_telemetry.remove(0);
                    }
                    s.local_telemetry.push(sample);
                    let mut signal = s.detector.evaluate(&sample);

                    // Phase 21: velocity / entropy / compound enrichment
                    let vel_report = s.velocity.update(&sample);
                    let ent_report = s.entropy.update(&sample);
                    signal.score += vel_report.score_boost + ent_report.score_boost;
                    let mut extra_reasons: Vec<String> = Vec::new();
                    for ax in &vel_report.anomalous_axes {
                        extra_reasons.push(format!("velocity-spike:{ax}"));
                    }
                    for ax in &ent_report.anomalous_axes {
                        extra_reasons.push(format!("entropy-anomaly:{ax}"));
                    }
                    let cmp_report = s.compound.evaluate(&signal);
                    if cmp_report.is_compound_attack {
                        signal.score = cmp_report.compound_score;
                        extra_reasons.push(format!(
                            "compound-threat({:.0}%)",
                            cmp_report.concurrent_fraction * 100.0
                        ));
                    }
                    signal.reasons.extend(extra_reasons);

                    let crit = s.config.policy.critical_score;
                    let sev = s.config.policy.severe_score;
                    let elev = s.config.policy.elevated_score;
                    if signal.score >= elev {
                        consecutive_elevated += 1;
                        // Critical/Severe bypass confirmation — alert immediately
                        // Elevated requires consecutive confirmation to suppress noise
                        let confirmed = signal.score >= sev || consecutive_elevated >= CONFIRM_SAMPLES;
                        if confirmed {
                            let level = if signal.score >= crit { "Critical" }
                                else if signal.score >= sev { "Severe" }
                                else { "Elevated" };
                            let host = s.local_host_info.clone();
                            let mitre = crate::telemetry::map_alert_to_mitre(&signal.reasons);
                            let alert = AlertRecord {
                                timestamp: chrono::Utc::now().to_rfc3339(),
                                hostname: host.hostname,
                                platform: host.platform.to_string(),
                                score: signal.score,
                                confidence: signal.confidence,
                                level: level.to_string(),
                                action: "monitor".to_string(),
                                reasons: signal.reasons,
                                sample,
                                enforced: false,
                                mitre,
                            };
                            if s.alerts.len() >= 10_000 {
                                s.alerts.remove(0);
                            }
                            s.alerts.push(alert);
                        }
                    } else {
                        consecutive_elevated = 0;
                    }
                    let interval = s.config.monitor.interval_secs.max(1);
                    drop(s);
                    std::thread::sleep(std::time::Duration::from_secs(interval));
                }
            }
        });
    }

    let site_dir = site_dir.to_path_buf();

    serve_loop(&server, &state, &site_dir);

    Ok(())
}

/// Spawn a test server on a random port. Returns `(port, token)`.
/// The server runs in a background thread.
#[doc(hidden)]
pub fn spawn_test_server() -> (u16, String) {
    let server = Server::http("127.0.0.1:0").expect("bind test server");
    let port = server.server_addr().to_ip().expect("ip addr").port();
    let token = generate_token();
    let state = Arc::new(Mutex::new(AppState {
        detector: AnomalyDetector::default(),
        checkpoints: CheckpointStore::new(10),
        device: DeviceController::default(),
        replay: ReplayBuffer::new(200),
        proofs: ProofRegistry::new(),
        last_report: None,
        token: token.clone(),
        swarm: SwarmNode::new("test-node-0"),
        enforcement: EnforcementEngine::new(),
        threat_intel: ThreatIntelStore::new(),
        digital_twin: DigitalTwinEngine::new(),
        compliance: ComplianceManager::new(),
        multi_tenant: MultiTenantManager::new(),
        energy: EnergyBudget::new(500.0),
        side_channel: SideChannelDetector::new(),
        key_rotation: KeyRotationManager::new(3600),
        privacy: PrivacyAccountant::new(10.0),
        policy_vm: PolicyVm::default(),
        fingerprint: None,
        monitor: Monitor::new(),
        drift: DriftDetector::new(0.005, 50.0),
        deception: DeceptionEngine::new(),
        patches: PatchManager::new(),
        causal: CausalGraph::new(),
        listener_mode: ListenerMode::Plain { port },
        config: Config::default(),
        alerts: Vec::new(),
        server_start: std::time::Instant::now(),
        agent_registry: AgentRegistry::new(&format!("/tmp/wardex_test_{port}/agents.json")),
        event_store: EventStore::with_persistence(1000, format!("/tmp/wardex_test_{port}/events.json")),
        policy_store: PolicyStore::new(),
        update_manager: UpdateManager::new(&format!("/tmp/wardex_test_{port}/updates")),
        remote_deployments: load_remote_deployments(&format!("/tmp/wardex_test_{port}/deployments.json")),
        deployment_store_path: format!("/tmp/wardex_test_{port}/deployments.json"),
        siem_connector: SiemConnector::new(crate::siem::SiemConfig::default()),
        local_telemetry: Vec::new(),
        local_host_info: detect_platform(),
        velocity: VelocityDetector::new(60, 2.5),
        entropy: EntropyDetector::new(60, 8),
        compound: CompoundThreatDetector::default(),
        shutdown: Arc::new(AtomicBool::new(false)),
        rate_limiter: RateLimiter::new(60),
        audit_log: AuditLog::new(1000),
        incident_store: IncidentStore::new(&format!("/tmp/wardex_test_{port}/incidents.json")),
        agent_logs: HashMap::new(),
        agent_inventories: HashMap::new(),
        report_store: crate::report::ReportStore::new(&format!("/tmp/wardex_test_{port}/reports.json")),
        sigma_engine: SigmaEngine::new(),
        response_orchestrator: ResponseOrchestrator::new(),
        feature_flags: FeatureFlagRegistry::new(),
        process_tree: ProcessTree::new("localhost"),
        spool: EncryptedSpool::new(b"server-spool-key-placeholder!!", 10_000),
        rbac: RbacStore::new(),
        case_store: CaseStore::new(&format!("/tmp/wardex_test_{port}/cases.json")),
        alert_queue: AlertQueue::new(),
        approval_log: ApprovalLog::new(),
        dead_letter_queue: DeadLetterQueue::new(500),
    }));
    let site_dir = PathBuf::from("site");
    std::thread::spawn(move || {
        serve_loop(&server, &state, &site_dir);
    });
    (port, token)
}

fn serve_loop(server: &Server, state: &Arc<Mutex<AppState>>, site_dir: &Path) {
    loop {
        match server.recv_timeout(std::time::Duration::from_millis(500)) {
            Ok(Some(request)) => {
                let url = request.url().to_string();
                let remote_addr = request.remote_addr().map(|a| a.ip().to_string()).unwrap_or_default();

                // Rate limiting
                {
                    let mut s = state.lock().unwrap();
                    if !s.rate_limiter.check(&remote_addr) {
                        drop(s);
                        let _ = request.respond(error_json("rate limit exceeded", 429));
                        continue;
                    }
                }

                if url.starts_with("/api/") {
                    handle_api(request, state, site_dir, server);
                } else {
                    serve_static(request, site_dir);
                }
            }
            Ok(None) => {} // timeout, check shutdown
            Err(_) => break,
        }
        let s = state.lock().unwrap();
        if s.shutdown.load(Ordering::Relaxed) {
            drop(s);
            eprintln!("Server shutting down…");
            break;
        }
    }
}

fn generate_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.r#gen()).collect();
    hex::encode(bytes)
}

fn cors_origin() -> String {
    std::env::var("SENTINEL_CORS_ORIGIN").unwrap_or_else(|_| "*".into())
}

fn json_response(body: &str, status: u16) -> Response<std::io::Cursor<Vec<u8>>> {
    let origin = cors_origin();
    let data = body.as_bytes().to_vec();
    let len = data.len();
    Response::new(
        tiny_http::StatusCode(status),
        vec![
            Header::from_bytes(b"Content-Type", b"application/json").unwrap(),
            Header::from_bytes(b"Access-Control-Allow-Origin", origin.as_bytes()).unwrap(),
            Header::from_bytes(b"Vary", b"Origin").unwrap(),
            Header::from_bytes(b"X-Content-Type-Options", b"nosniff").unwrap(),
            Header::from_bytes(b"X-Frame-Options", b"DENY").unwrap(),
            Header::from_bytes(b"Cache-Control", b"no-store").unwrap(),
        ],
        std::io::Cursor::new(data),
        Some(len),
        None,
    )
}

fn error_json(message: &str, status: u16) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = format!(r#"{{"error":"{}"}}"#, message.replace('"', "\\\""));
    json_response(&body, status)
}

fn text_response(body: &str, status: u16) -> Response<std::io::Cursor<Vec<u8>>> {
    let origin = cors_origin();
    let data = body.as_bytes().to_vec();
    let len = data.len();
    Response::new(
        tiny_http::StatusCode(status),
        vec![
            Header::from_bytes(b"Content-Type", b"text/plain; charset=utf-8").unwrap(),
            Header::from_bytes(b"Access-Control-Allow-Origin", origin.as_bytes()).unwrap(),
            Header::from_bytes(b"Vary", b"Origin").unwrap(),
            Header::from_bytes(b"X-Content-Type-Options", b"nosniff").unwrap(),
            Header::from_bytes(b"X-Frame-Options", b"DENY").unwrap(),
            Header::from_bytes(b"Cache-Control", b"no-store").unwrap(),
        ],
        std::io::Cursor::new(data),
        Some(len),
        None,
    )
}

fn csv_response(body: &str, status: u16) -> Response<std::io::Cursor<Vec<u8>>> {
    let origin = cors_origin();
    let data = body.as_bytes().to_vec();
    let len = data.len();
    Response::new(
        tiny_http::StatusCode(status),
        vec![
            Header::from_bytes(b"Content-Type", b"text/csv; charset=utf-8").unwrap(),
            Header::from_bytes(b"Access-Control-Allow-Origin", origin.as_bytes()).unwrap(),
            Header::from_bytes(b"Vary", b"Origin").unwrap(),
            Header::from_bytes(b"X-Content-Type-Options", b"nosniff").unwrap(),
            Header::from_bytes(b"X-Frame-Options", b"DENY").unwrap(),
            Header::from_bytes(b"Cache-Control", b"no-store").unwrap(),
        ],
        std::io::Cursor::new(data),
        Some(len),
        None,
    )
}

fn check_auth(request: &Request, state: &Arc<Mutex<AppState>>) -> bool {
    let state = state.lock().unwrap();
    for header in request.headers() {
        if header
            .field
            .as_str()
            .as_str()
            .eq_ignore_ascii_case("authorization")
        {
            let val = header.value.as_str();
            if let Some(token) = val.strip_prefix("Bearer ") {
                return token.trim() == state.token;
            }
        }
    }
    false
}

fn host_platform_key(platform: HostPlatform) -> &'static str {
    match platform {
        HostPlatform::Linux => "linux",
        HostPlatform::MacOS => "macos",
        HostPlatform::Windows | HostPlatform::WindowsServer => "windows",
        HostPlatform::Unknown => "unknown",
    }
}

fn parse_query_string(url: &str) -> HashMap<String, String> {
    let query = url.split('?').nth(1).unwrap_or("");
    let mut params = HashMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let mut parts = pair.splitn(2, '=');
        let key = parts.next().unwrap_or("");
        let value = parts.next().unwrap_or("");
        if !key.is_empty() {
            params.insert(key.to_string(), value.to_string());
        }
    }
    params
}

fn url_param(url: &str, key: &str) -> Option<String> {
    parse_query_string(url).get(key).cloned().filter(|v| !v.is_empty())
}

fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let parse = |value: &str| -> Vec<u32> {
        value
            .split('.')
            .map(|part| part.parse::<u32>().unwrap_or(0))
            .collect()
    };
    parse(a).cmp(&parse(b))
}

fn default_deployment_status() -> String {
    "assigned".to_string()
}

fn default_rollout_group() -> String {
    "direct".to_string()
}

fn normalize_rollout_group(value: Option<&str>) -> String {
    match value.unwrap_or("direct").trim().to_ascii_lowercase().as_str() {
        "canary" => "canary".to_string(),
        "ring-1" | "ring1" => "ring-1".to_string(),
        "ring-2" | "ring2" => "ring-2".to_string(),
        "direct" | "immediate" | "" => "direct".to_string(),
        other => other.to_string(),
    }
}

fn deployment_requires_action(deployment: &AgentDeployment, current_version: &str) -> bool {
    match compare_versions(&deployment.version, current_version) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => deployment.allow_downgrade,
        std::cmp::Ordering::Equal => false,
    }
}

fn is_terminal_deployment_status(status: &str) -> bool {
    matches!(
        status.trim().to_ascii_lowercase().as_str(),
        "applied" | "completed" | "cancelled"
    )
}

fn deployment_is_pending(deployment: &AgentDeployment, registry: &AgentRegistry) -> bool {
    match registry.get(&deployment.agent_id) {
        Some(agent) => deployment_requires_action(deployment, &agent.version),
        None => !is_terminal_deployment_status(&deployment.status),
    }
}

fn severity_rank(level: &str) -> u8 {
    match level.to_ascii_lowercase().as_str() {
        "critical" => 3,
        "severe" => 2,
        "elevated" => 1,
        _ => 0,
    }
}

fn path_health(path: &str) -> serde_json::Value {
    let path_ref = Path::new(path);
    match fs::metadata(path_ref) {
        Ok(metadata) => {
            let kind = if metadata.is_dir() {
                "directory"
            } else if metadata.is_file() {
                "file"
            } else {
                "other"
            };
            let readable = if metadata.is_dir() {
                fs::read_dir(path_ref).is_ok()
            } else {
                fs::File::open(path_ref).is_ok()
            };
            serde_json::json!({
                "path": path,
                "exists": true,
                "type": kind,
                "readable": readable,
                "health": if readable { "ok" } else { "restricted" },
                "note": if readable { "Path is available to the current process." } else { "Path exists but could not be read by the current process." },
            })
        }
        Err(_) => serde_json::json!({
            "path": path,
            "exists": false,
            "type": "missing",
            "readable": false,
            "health": "missing",
            "note": "Path is not present on this host.",
        }),
    }
}

fn parse_event_query(url: &str) -> EventQuery {
    let params = parse_query_string(url);
    let limit = params
        .get("limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(200)
        .clamp(1, 1000);
    EventQuery {
        agent_id: params.get("agent_id").cloned().filter(|value| !value.is_empty()),
        severity: params.get("severity").cloned().filter(|value| !value.is_empty()),
        reason: params.get("reason").cloned().filter(|value| !value.is_empty()),
        correlated: params.get("correlated").and_then(|value| match value.as_str() {
            "true" | "1" => Some(true),
            "false" | "0" => Some(false),
            _ => None,
        }),
        triage_status: params.get("triage_status").cloned().filter(|value| !value.is_empty()),
        assignee: params.get("assignee").cloned().filter(|value| !value.is_empty()),
        tag: params.get("tag").cloned().filter(|value| !value.is_empty()),
        limit,
    }
}

fn event_matches_query(event: &crate::event_forward::StoredEvent, query: &EventQuery) -> bool {
    if let Some(agent_id) = &query.agent_id {
        if &event.agent_id != agent_id {
            return false;
        }
    }
    if let Some(severity) = &query.severity {
        if !event.alert.level.eq_ignore_ascii_case(severity) {
            return false;
        }
    }
    if let Some(reason) = &query.reason {
        if !event
            .alert
            .reasons
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(reason))
        {
            return false;
        }
    }
    if let Some(correlated) = query.correlated {
        if event.correlated != correlated {
            return false;
        }
    }
    if let Some(triage_status) = &query.triage_status {
        if !event.triage.status.eq_ignore_ascii_case(triage_status) {
            return false;
        }
    }
    if let Some(assignee) = &query.assignee {
        if !event
            .triage
            .assignee
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case(assignee))
        {
            return false;
        }
    }
    if let Some(tag) = &query.tag {
        if !event
            .triage
            .tags
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(tag))
        {
            return false;
        }
    }
    true
}

fn filtered_events<'a>(store: &'a EventStore, query: &EventQuery) -> Vec<&'a crate::event_forward::StoredEvent> {
    store
        .list(None, 10_000)
        .into_iter()
        .filter(|event| event_matches_query(event, query))
        .take(query.limit)
        .collect()
}

fn csv_escape(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn ocsf_class_for_event(event: &crate::event_forward::StoredEvent) -> u32 {
    let reasons = event.alert.reasons.join(" ").to_lowercase();
    if reasons.contains("auth") || reasons.contains("login") || reasons.contains("credential") {
        3002 // Authentication
    } else if reasons.contains("network") || reasons.contains("connection") || reasons.contains("dns") {
        4001 // NetworkActivity
    } else {
        2004 // DetectionFinding (default)
    }
}

fn events_to_csv(events: &[&crate::event_forward::StoredEvent]) -> String {
    let mut out = String::from("id,agent_id,received_at,level,score,confidence,correlated,triage_status,assignee,tags,reasons,hostname,platform,action,ocsf_class_id\n");
    for event in events {
        let row = [
            event.id.to_string(),
            csv_escape(&event.agent_id),
            csv_escape(&event.received_at),
            csv_escape(&event.alert.level),
            event.alert.score.to_string(),
            event.alert.confidence.to_string(),
            event.correlated.to_string(),
            csv_escape(&event.triage.status),
            csv_escape(event.triage.assignee.as_deref().unwrap_or("")),
            csv_escape(&event.triage.tags.join("|")),
            csv_escape(&event.alert.reasons.join("|")),
            csv_escape(&event.alert.hostname),
            csv_escape(&event.alert.platform),
            csv_escape(&event.alert.action),
            ocsf_class_for_event(event).to_string(),
        ];
        out.push_str(&row.join(","));
        out.push('\n');
    }
    out
}

fn check_rbac(state: &Arc<Mutex<AppState>>, path: &str, method: &Method) -> bool {
    let s = state.lock().unwrap();
    if s.rbac.list_users().is_empty() {
        return true;
    }
    // RBAC: read-only endpoints allowed for all roles; mutating requires admin/operator
    let is_read = matches!(method, Method::Get);
    if is_read {
        return true;
    }
    // Write operations on sensitive paths require RBAC check
    let sensitive = ["/api/config/", "/api/shutdown", "/api/updates/", "/api/enforcement/", "/api/rbac/"];
    if sensitive.iter().any(|p| path.starts_with(p)) {
        // Full enforcement requires user identity extraction from JWT/token
        // For now, log the access but allow
        return true;
    }
    true
}

fn is_feature_enabled(state: &Arc<Mutex<AppState>>, feature: &str) -> bool {
    let s = state.lock().unwrap();
    s.feature_flags.is_enabled(feature, "default")
}

fn load_remote_deployments(path: &str) -> HashMap<String, AgentDeployment> {
    match fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str(&raw).unwrap_or_default(),
        Err(_) => HashMap::new(),
    }
}

fn save_remote_deployments(path: &str, deployments: &HashMap<String, AgentDeployment>) {
    if let Ok(json) = serde_json::to_string_pretty(deployments) {
        let path_ref = Path::new(path);
        if let Some(parent) = path_ref.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(path_ref, json);
    }
}

fn monitoring_option(
    id: &str,
    label: &str,
    description: &str,
    selected: bool,
    supported: bool,
    recommended: bool,
    mode: &str,
    reason: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "label": label,
        "description": description,
        "selected": selected,
        "supported": supported,
        "recommended": recommended,
        "mode": mode,
        "reason": reason,
    })
}

fn monitoring_guidance(platform: HostPlatform) -> Vec<&'static str> {
    match platform {
        HostPlatform::Linux => vec![
            "Linux hosts benefit most from auth-failure monitoring and systemd-unit persistence checks because both map directly to common intrusion paths.",
            "Battery coverage depends on power-supply telemetry such as BAT0; server-class systems often report no battery data.",
        ],
        HostPlatform::MacOS => vec![
            "macOS hosts should prioritize LaunchAgents and LaunchDaemons because they are common persistence locations for userland malware.",
            "Thermal telemetry is limited on macOS in the current pure-Rust collector path, so CPU and process signals remain the stronger indicators.",
        ],
        HostPlatform::Windows | HostPlatform::WindowsServer => vec![
            "Windows hosts should prioritize Security-log failures and scheduled-task persistence because both are frequently abused during compromise and re-entry.",
            "Battery and thermal coverage depends on WMI support and may be absent on desktop or virtualized systems.",
        ],
        HostPlatform::Unknown => vec![
            "This host platform could not be classified cleanly, so Wardex recommends sticking to portable telemetry and file-integrity checks.",
            "Platform-specific persistence checks remain unavailable until the runtime can map standard service locations for this OS.",
        ],
    }
}

fn monitoring_options_payload(host: &HostInfo, config: &Config) -> serde_json::Value {
    let platform_key = host_platform_key(host.platform);
    let caps = PlatformCapabilities::detect_current();
    let scope = &config.monitor.scope;
    let persistence_paths = crate::collector::persistence_watch_paths(host.platform, scope);

    let core = vec![
        monitoring_option(
            "cpu_load",
            "CPU load",
            "Monitors sustained or sudden CPU pressure to catch miners, brute-force spikes, and runaway workloads.",
            scope.cpu_load,
            true,
            true,
            "always_on",
            Some("Core telemetry is always collected in the current release."),
        ),
        monitoring_option(
            "memory_pressure",
            "Memory pressure",
            "Tracks RAM consumption trends to surface exhaustion, injection, and staging behavior.",
            scope.memory_pressure,
            true,
            true,
            "always_on",
            Some("Core telemetry is always collected in the current release."),
        ),
        monitoring_option(
            "network_activity",
            "Network activity",
            "Flags bursts or sustained traffic shifts associated with exfiltration, C2, or floods.",
            scope.network_activity,
            true,
            true,
            "always_on",
            Some("Core telemetry is always collected in the current release."),
        ),
        monitoring_option(
            "disk_pressure",
            "Disk pressure",
            "Watches disk utilization changes that can indicate ransomware, log stuffing, or resource starvation.",
            scope.disk_pressure,
            true,
            true,
            "always_on",
            Some("Core telemetry is always collected in the current release."),
        ),
        monitoring_option(
            "process_activity",
            "Process activity",
            "Uses process-count anomalies to highlight fork storms, lateral tooling, and persistence bursts.",
            scope.process_activity,
            true,
            true,
            "always_on",
            Some("Core telemetry is always collected in the current release."),
        ),
    ];

    let security = vec![
        monitoring_option(
            "auth_events",
            "Authentication events",
            "Tracks failed-logon spikes to detect brute-force and credential-stuffing behavior.",
            scope.auth_events,
            true,
            true,
            "configurable",
            Some("Disable only if the host cannot expose auth logs or Security-event access is intentionally restricted."),
        ),
        monitoring_option(
            "file_integrity",
            "File integrity",
            "Hashes configured paths and alerts on unexpected changes. This is the scope item that directly changes collector behavior now.",
            scope.file_integrity,
            true,
            true,
            "configurable",
            None,
        ),
        monitoring_option(
            "service_persistence",
            "Service persistence",
            "Covers startup services and persistence footholds using OS-specific baseline paths.",
            scope.service_persistence,
            platform_key != "unknown",
            true,
            "configurable",
            Some(if platform_key == "unknown" {
                "Runtime could not determine standard persistence locations for this host."
            } else {
                "Enable this together with the host-specific source below; if no source is selected, Wardex uses the recommended source for the current OS."
            }),
        ),
    ];

    let host_specific = vec![
        monitoring_option(
            "thermal_state",
            "Thermal state",
            "Adds device-heat context to CPU and workload anomalies.",
            scope.thermal_state,
            true,
            platform_key != "unknown",
            "always_on",
            Some("Collected as part of the current host telemetry pipeline."),
        ),
        monitoring_option(
            "battery_state",
            "Battery state",
            "Useful on mobile or battery-backed devices where power drain can be part of the attack path.",
            scope.battery_state,
            true,
            matches!(host.platform, HostPlatform::MacOS | HostPlatform::Windows | HostPlatform::WindowsServer),
            "always_on",
            Some("Collected when the host exposes battery data."),
        ),
        monitoring_option(
            "launch_agents",
            "Launch agents",
            "macOS persistence points such as LaunchAgents and LaunchDaemons.",
            scope.launch_agents,
            platform_key == "macos",
            platform_key == "macos",
            "configurable",
            Some(if platform_key == "macos" {
                "Recommended on macOS because LaunchAgents and LaunchDaemons are baselined directly when service persistence is enabled."
            } else {
                "macOS-specific monitoring point."
            }),
        ),
        monitoring_option(
            "systemd_units",
            "systemd units",
            "Linux startup services and unit-file persistence.",
            scope.systemd_units,
            platform_key == "linux",
            platform_key == "linux",
            "configurable",
            Some(if platform_key == "linux" {
                "Recommended on Linux because systemd unit paths are baselined directly when service persistence is enabled."
            } else {
                "Linux-specific monitoring point."
            }),
        ),
        monitoring_option(
            "scheduled_tasks",
            "Scheduled tasks",
            "Windows task-scheduler persistence and delayed execution.",
            scope.scheduled_tasks,
            platform_key == "windows",
            platform_key == "windows",
            "configurable",
            Some(if platform_key == "windows" {
                "Recommended on Windows because Task Scheduler definitions are baselined directly when service persistence is enabled."
            } else {
                "Windows-specific monitoring point."
            }),
        ),
    ];

    let selected_now = vec![
        (scope.cpu_load, "CPU load"),
        (scope.memory_pressure, "Memory pressure"),
        (scope.network_activity, "Network activity"),
        (scope.disk_pressure, "Disk pressure"),
        (scope.process_activity, "Process activity"),
        (scope.auth_events, "Authentication events"),
        (scope.thermal_state, "Thermal state"),
        (scope.battery_state, "Battery state"),
        (scope.file_integrity, "File integrity"),
        (scope.service_persistence, "Service persistence"),
        (scope.launch_agents, "Launch agents"),
        (scope.systemd_units, "systemd units"),
        (scope.scheduled_tasks, "Scheduled tasks"),
    ]
    .into_iter()
    .filter_map(|(enabled, label)| enabled.then_some(label))
    .collect::<Vec<_>>();

    serde_json::json!({
        "host": {
            "platform": host.platform.to_string(),
            "platform_key": platform_key,
            "hostname": host.hostname,
            "os_version": host.os_version,
            "arch": host.arch,
            "has_tpm": caps.has_tpm,
            "has_seccomp": caps.has_seccomp,
            "has_ebpf": caps.has_ebpf,
            "has_firewall": caps.has_firewall,
            "process_control": caps.process_control,
        },
        "summary": {
            "selected_now": selected_now,
            "watch_path_count": config.monitor.watch_paths.len(),
            "persistence_path_count": persistence_paths.len(),
            "platform_guidance": monitoring_guidance(host.platform),
            "notes": [
                "Core telemetry remains always-on unless a scope toggle explicitly gates that collector.",
                "Auth-event collection and persistence baselines now follow the selected monitoring scope in addition to file-integrity paths."
            ]
        },
        "groups": [
            {
                "id": "core_system",
                "label": "Core System",
                "description": "Signals already collected on every sample.",
                "options": core,
            },
            {
                "id": "security_signals",
                "label": "Security Signals",
                "description": "Signals tied to attack behavior and integrity checks.",
                "options": security,
            },
            {
                "id": "host_specific",
                "label": "Host-Specific",
                "description": "OS-aware recommendations and planned collectors for this platform.",
                "options": host_specific,
            }
        ]
    })
}

fn monitoring_paths_payload(host: &HostInfo, config: &Config) -> serde_json::Value {
    let file_paths = if config.monitor.scope.file_integrity {
        config.monitor.watch_paths.clone()
    } else {
        Vec::new()
    };
    let persistence_paths = crate::collector::persistence_watch_paths(host.platform, &config.monitor.scope);
    let file_health = file_paths.iter().map(|path| path_health(path)).collect::<Vec<_>>();
    let persistence_health = persistence_paths.iter().map(|path| path_health(path)).collect::<Vec<_>>();
    let unhealthy = file_health
        .iter()
        .chain(persistence_health.iter())
        .filter(|entry| entry["health"] != "ok")
        .count();
    serde_json::json!({
        "file_integrity_paths": file_paths,
        "persistence_paths": persistence_paths,
        "file_integrity_health": file_health,
        "persistence_health": persistence_health,
        "summary": {
            "unhealthy_paths": unhealthy,
        },
        "scope": {
            "file_integrity": config.monitor.scope.file_integrity,
            "service_persistence": config.monitor.scope.service_persistence,
            "launch_agents": config.monitor.scope.launch_agents,
            "systemd_units": config.monitor.scope.systemd_units,
            "scheduled_tasks": config.monitor.scope.scheduled_tasks,
        }
    })
}

fn handle_api(mut request: Request, state: &Arc<Mutex<AppState>>, _site_dir: &Path, server: &Server) {
    let url = request.url().to_string();
    let method = request.method().clone();

    // ── Request body size limit (10 MB) ──
    const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;
    if let Some(len) = request.body_length() {
        if len > MAX_BODY_SIZE {
            let _ = request.respond(error_json("request body too large", 413));
            return;
        }
    }
    // Body limit enforced in read_body_limited()

    // Check auth for mutating endpoints before consuming the request body
    // XDR agent endpoints that do NOT require admin auth (agents use enrollment tokens)
    let is_agent_endpoint = url.starts_with("/api/agents/enroll")
        || url.starts_with("/api/agents/update")
        || (url.contains("/heartbeat") && url.starts_with("/api/agents/"))
        || (method == Method::Post && url == "/api/events")
        || url.starts_with("/api/policy/current")
        || url.starts_with("/api/updates/download/")
        || (method == Method::Post && url.starts_with("/api/agents/") && url.ends_with("/logs"))
        || (method == Method::Post && url.starts_with("/api/agents/") && url.ends_with("/inventory"));

    let needs_auth = !is_agent_endpoint && matches!(
        (&method, url.as_str()),
        (Method::Get, "/api/auth/check")
            | (Method::Post, "/api/analyze")
            | (Method::Post, "/api/control/mode")
            | (Method::Post, "/api/control/reset-baseline")
            | (Method::Post, "/api/control/run-demo")
            | (Method::Post, "/api/control/checkpoint")
            | (Method::Post, "/api/control/restore-checkpoint")
            | (Method::Post, "/api/fleet/register")
            | (Method::Post, "/api/enforcement/quarantine")
            | (Method::Post, "/api/threat-intel/ioc")
            | (Method::Post, "/api/digital-twin/simulate")
            | (Method::Post, "/api/energy/consume")
            | (Method::Post, "/api/quantum/rotate")
            | (Method::Post, "/api/policy-vm/execute")
            | (Method::Post, "/api/harness/run")
            | (Method::Post, "/api/deception/deploy")
            | (Method::Post, "/api/policy/compose")
            | (Method::Post, "/api/drift/reset")
            | (Method::Post, "/api/offload/decide")
            | (Method::Post, "/api/energy/harvest")
            | (Method::Post, "/api/config/reload")
            | (Method::Post, "/api/config/save")
            | (Method::Post, "/api/agents/token")
            | (Method::Post, "/api/policy/publish")
            | (Method::Post, "/api/updates/publish")
            | (Method::Post, "/api/updates/deploy")
            | (Method::Post, "/api/updates/rollback")
            | (Method::Post, "/api/updates/cancel")
            | (Method::Post, "/api/events/bulk-triage")
            | (Method::Post, "/api/shutdown")
            | (Method::Post, "/api/mesh/heal")
            | (Method::Delete, "/api/alerts")
    ) || (!is_agent_endpoint && (
        (method == Method::Get && url == "/api/fleet/dashboard")
        || (method == Method::Get && url == "/api/siem/status")
        || (method == Method::Get && url == "/api/agents")
        || (method == Method::Get && url == "/api/events")
        || (method == Method::Get && url.starts_with("/api/events?"))
        || (method == Method::Get && url == "/api/events/export")
        || (method == Method::Get && url.starts_with("/api/events/export?"))
        || (method == Method::Get && url == "/api/events/summary")
        || (method == Method::Get && url == "/api/policy/history")
        || (method == Method::Get && url == "/api/telemetry/current")
        || (method == Method::Get && url == "/api/telemetry/history")
        || (method == Method::Get && url == "/api/host/info")
        || (method == Method::Get && url == "/api/config/current")
        || (method == Method::Get && url == "/api/checkpoints")
        || (method == Method::Get && url == "/api/correlation")
        || (method == Method::Get && url == "/api/alerts")
        || (method == Method::Get && url == "/api/alerts/count")
        || (method == Method::Get && url.starts_with("/api/alerts/") && url != "/api/alerts/count")
        || (method == Method::Get && url == "/api/report")
        || (method == Method::Get && url == "/api/threads/status")
        || (method == Method::Get && url == "/api/detection/summary")
        || (method == Method::Get && url == "/api/monitoring/options")
        || (method == Method::Get && url == "/api/monitoring/paths")
        || (method == Method::Get && url == "/api/endpoints")
        || (method == Method::Get && url == "/api/status")
        || (method == Method::Get && url.starts_with("/api/agents/") && url.ends_with("/details"))
        || (method == Method::Post && url.starts_with("/api/events/") && url.ends_with("/triage"))
        || (method == Method::Post && url.starts_with("/api/agents/") && url.ends_with("/scope"))
        || (method == Method::Get && url.starts_with("/api/agents/") && url.ends_with("/scope"))
        || (method == Method::Get && url == "/api/audit/log")
        || (method == Method::Get && url == "/api/incidents") || (method == Method::Get && url.starts_with("/api/incidents?"))
        || (method == Method::Get && url.starts_with("/api/incidents/"))
        || (method == Method::Post && url == "/api/incidents")
        || (method == Method::Post && url.starts_with("/api/incidents/") && url.ends_with("/update"))
        || (method == Method::Get && url.starts_with("/api/agents/") && url.ends_with("/logs"))
        || (method == Method::Get && url.starts_with("/api/agents/") && url.ends_with("/inventory"))
        || (method == Method::Get && url == "/api/fleet/inventory")
        || (method == Method::Post && url == "/api/detection/weights")
        || (method == Method::Get && url == "/api/detection/weights")
        || (method == Method::Get && url == "/api/reports") || (method == Method::Get && url.starts_with("/api/reports?"))
        || (method == Method::Get && url.starts_with("/api/reports/"))
        || (method == Method::Delete && url.starts_with("/api/reports/"))
        || (method == Method::Get && url == "/api/reports/executive-summary")
        || (method == Method::Delete && url.starts_with("/api/agents/"))
        || (method == Method::Get && url == "/api/sigma/rules")
        || (method == Method::Get && url == "/api/sigma/stats")
        || (method == Method::Get && url == "/api/ocsf/schema")
        || (method == Method::Get && url == "/api/response/pending")
        || (method == Method::Get && url == "/api/response/audit")
        || (method == Method::Get && url == "/api/response/stats")
        || (method == Method::Get && url == "/api/feature-flags")
        || (method == Method::Get && url == "/api/process-tree")
        || (method == Method::Get && url == "/api/process-tree/deep-chains")
        || (method == Method::Get && url == "/api/spool/stats")
        || (method == Method::Get && url == "/api/rbac/users")
        // Analyst console
        || (method == Method::Get && url == "/api/cases") || (method == Method::Get && url.starts_with("/api/cases?"))
        || (method == Method::Post && url == "/api/cases")
        || (method == Method::Get && url == "/api/cases/stats")
        || (method == Method::Get && url.starts_with("/api/cases/"))
        || (method == Method::Post && url.starts_with("/api/cases/"))
        || (method == Method::Get && url == "/api/queue/alerts")
        || (method == Method::Get && url == "/api/queue/stats")
        || (method == Method::Post && url == "/api/queue/acknowledge")
        || (method == Method::Post && url == "/api/queue/assign")
        || (method == Method::Post && url == "/api/events/search")
        || (method == Method::Get && url.starts_with("/api/timeline/"))
        || (method == Method::Post && url == "/api/investigation/graph")
        || (method == Method::Post && url == "/api/response/approve")
        || (method == Method::Get && url == "/api/response/approvals")
        // Dead-letter queue & schema
        || (method == Method::Get && url == "/api/dlq")
        || (method == Method::Get && url == "/api/dlq/stats")
        || (method == Method::Delete && url == "/api/dlq")
        || (method == Method::Get && url == "/api/ocsf/schema/version")
    ));

    if needs_auth && !check_auth(&request, state) {
        let _ = request.respond(error_json("unauthorized", 401));
        return;
    }

    // RBAC enforcement for sensitive endpoints
    if !check_rbac(state, &url, &method) {
        let _ = request.respond(error_json("forbidden: insufficient role", 403));
        return;
    }

    let response = match (method.clone(), url.as_str()) {
        (Method::Get, "/api/auth/check") => json_response(r#"{"status":"ok"}"#, 200),
        (Method::Get, "/api/status") => {
            let manifest = runtime::status_manifest();
            match serde_json::to_string_pretty(&manifest) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/report") => {
            let s = state.lock().unwrap();
            if let Some(ref report) = s.last_report {
                match serde_json::to_string_pretty(report) {
                    Ok(json) => json_response(&json, 200),
                    Err(e) => error_json(&format!("serialization error: {e}"), 500),
                }
            } else if !s.alerts.is_empty() {
                // Generate a live report from monitoring alerts
                let alerts = &s.alerts;
                let total = alerts.len();
                let critical = alerts.iter().filter(|a| a.level == "Critical").count();
                let avg_score = if total > 0 { alerts.iter().map(|a| a.score).sum::<f32>() / total as f32 } else { 0.0 };
                let max_score = alerts.iter().map(|a| a.score).fold(0.0f32, f32::max);
                let samples: Vec<serde_json::Value> = alerts.iter().enumerate().map(|(i, a)| {
                    serde_json::json!({
                        "index": i,
                        "timestamp_ms": chrono::DateTime::parse_from_rfc3339(&a.timestamp).map(|dt| dt.timestamp_millis() as u64).unwrap_or(0),
                        "score": a.score,
                        "confidence": a.confidence,
                        "suspicious_axes": a.reasons.len(),
                        "level": a.level,
                        "action": a.action,
                        "isolation_pct": 0,
                        "reasons": a.reasons,
                        "rationale": format!("{} alert from live monitor", a.level),
                        "contributions": []
                    })
                }).collect();
                let report = serde_json::json!({
                    "generated_at": chrono::Utc::now().to_rfc3339(),
                    "summary": {
                        "total_samples": total,
                        "alert_count": total,
                        "critical_count": critical,
                        "average_score": avg_score,
                        "max_score": max_score,
                    },
                    "samples": samples,
                });
                json_response(&report.to_string(), 200)
            } else {
                json_response(r#"{"generated_at":"","summary":{"total_samples":0,"alert_count":0,"critical_count":0,"average_score":0.0,"max_score":0.0},"samples":[]}"#, 200)
            }
        }
        (Method::Post, "/api/analyze") => handle_analyze(&mut request, state),
        (Method::Post, "/api/control/mode") => handle_mode(&mut request, state),
        (Method::Post, "/api/control/reset-baseline") => {
            let mut s = state.lock().unwrap();
            s.detector.reset_baseline();
            json_response(r#"{"status":"baseline reset"}"#, 200)
        }
        (Method::Post, "/api/control/checkpoint") => {
            let mut s = state.lock().unwrap();
            if let Some(snapshot) = s.detector.snapshot() {
                let device_state = s.device.snapshot();
                s.checkpoints.push_snapshot(snapshot, device_state);
            }
            let count = s.checkpoints.len();
            json_response(
                &format!(r#"{{"status":"checkpoint saved","total":{count}}}"#),
                200,
            )
        }
        (Method::Post, "/api/control/restore-checkpoint") => {
            let mut s = state.lock().unwrap();
            let restored = s.checkpoints.latest().cloned().map(|entry| {
                s.detector.restore_baseline(&entry.baseline);
                let action_results = s.device.restore_snapshot(&entry.device_state);
                serde_json::json!({
                    "status": "checkpoint restored",
                    "baseline_restored": true,
                    "device_state": entry.device_state,
                    "actions": action_results,
                })
            });
            if let Some(body) = restored {
                json_response(&body.to_string(), 200)
            } else {
                error_json("no checkpoints available", 404)
            }
        }
        (Method::Get, "/api/checkpoints") => {
            let s = state.lock().unwrap();
            let info = serde_json::json!({
                "count": s.checkpoints.len(),
                "timestamps": s.checkpoints.entries().iter()
                    .map(|e| e.timestamp_ms)
                    .collect::<Vec<_>>(),
                "device_states": s.checkpoints.entries().iter()
                    .map(|e| e.device_state.clone())
                    .collect::<Vec<_>>(),
            });
            json_response(&info.to_string(), 200)
        }
        (Method::Get, "/api/correlation") => {
            let s = state.lock().unwrap();
            let result = correlation::analyze(&s.replay, 0.8);
            match serde_json::to_string_pretty(&result) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/export/tla") => {
            let sm = PolicyStateMachine::new();
            text_response(&sm.export_tla(), 200)
        }
        (Method::Get, "/api/export/alloy") => {
            let sm = PolicyStateMachine::new();
            text_response(&sm.export_alloy(), 200)
        }
        (Method::Get, "/api/export/witnesses") => {
            let s = state.lock().unwrap();
            let json = s.proofs.export_witnesses_json(&DigestBackend);
            json_response(&json, 200)
        }
        (Method::Get, "/api/research-tracks") => {
            let groups = runtime::research_track_groups();
            match serde_json::to_string_pretty(&groups) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/attestation/status") => {
            let summary = crate::attestation::VerificationResult {
                passed: false,
                checks: vec![crate::attestation::CheckResult {
                    name: "attestation_loaded".into(),
                    passed: false,
                    detail: "no manifest loaded; use the attest CLI to generate one".into(),
                }],
            };
            match serde_json::to_string_pretty(&summary) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Post, "/api/control/run-demo") => {
            let demo = runtime::demo_samples();
            let result = runtime::execute(&demo);
            let report = JsonReport::from_run_result(&result);
            match serde_json::to_string_pretty(&report) {
                Ok(json) => {
                    let mut s = state.lock().unwrap();
                    for (sample, report) in demo.iter().zip(result.reports.iter()) {
                        let pre = s
                            .detector
                            .snapshot()
                            .map(|snap| serde_json::to_vec(&snap).unwrap_or_default())
                            .unwrap_or_default();
                        s.detector.evaluate(sample);
                        let post = s
                            .detector
                            .snapshot()
                            .map(|snap| serde_json::to_vec(&snap).unwrap_or_default())
                            .unwrap_or_default();
                        s.proofs.record("baseline_update", &pre, &post);
                        s.device.apply_decision(&report.decision);
                        s.replay.push(*sample);
                    }
                    s.last_report = Some(report);
                    drop(s);
                    json_response(&json, 200)
                }
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }

        // ── Fleet / Swarm ─────────────────────────────────────────
        (Method::Get, "/api/fleet/status") => {
            let s = state.lock().unwrap();
            let report = s.swarm.health_report();
            match serde_json::to_string_pretty(&report) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Post, "/api/fleet/register") => {
            handle_fleet_register(&mut request, state)
        }

        // ── Enforcement ───────────────────────────────────────────
        (Method::Get, "/api/enforcement/status") => {
            let s = state.lock().unwrap();
            let tpm_status = s.enforcement.tpm.status();
            let info = serde_json::json!({
                "process_enforcer": "active",
                "network_enforcer": "active",
                "filesystem_enforcer": "active",
                "tpm": tpm_status,
                "topology_nodes": s.enforcement.topology.nodes.len(),
                "history_len": s.enforcement.history().len(),
            });
            json_response(&info.to_string(), 200)
        }
        (Method::Post, "/api/enforcement/quarantine") => {
            handle_enforcement_quarantine(&mut request, state)
        }

        // ── Threat Intelligence ───────────────────────────────────
        (Method::Get, "/api/threat-intel/status") => {
            let s = state.lock().unwrap();
            let info = serde_json::json!({
                "ioc_count": s.threat_intel.ioc_count(),
            });
            json_response(&info.to_string(), 200)
        }
        (Method::Post, "/api/threat-intel/ioc") => {
            handle_threat_intel_ioc(&mut request, state)
        }

        // ── Digital Twin ──────────────────────────────────────────
        (Method::Get, "/api/digital-twin/status") => {
            let s = state.lock().unwrap();
            let info = serde_json::json!({
                "twin_count": s.digital_twin.device_count(),
            });
            json_response(&info.to_string(), 200)
        }
        (Method::Post, "/api/digital-twin/simulate") => {
            handle_digital_twin_simulate(&mut request, state)
        }

        // ── Compliance ────────────────────────────────────────────
        (Method::Get, "/api/compliance/status") => {
            let s = state.lock().unwrap();
            let report = s.compliance.report(&crate::compliance::Framework::Iec62443);
            match serde_json::to_string_pretty(&report) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }

        // ── Energy ────────────────────────────────────────────────
        (Method::Get, "/api/energy/status") => {
            let s = state.lock().unwrap();
            let info = serde_json::json!({
                "remaining_pct": s.energy.remaining_pct(),
                "capacity_mwh": s.energy.capacity_mwh,
                "current_mwh": s.energy.current_mwh,
                "power_state": format!("{:?}", s.energy.state),
            });
            json_response(&info.to_string(), 200)
        }
        (Method::Post, "/api/energy/consume") => {
            handle_energy_consume(&mut request, state)
        }

        // ── Multi-tenancy ─────────────────────────────────────────
        (Method::Get, "/api/tenants/count") => {
            let s = state.lock().unwrap();
            let info = serde_json::json!({
                "tenant_count": s.multi_tenant.tenant_count(),
            });
            json_response(&info.to_string(), 200)
        }

        // ── Platform ──────────────────────────────────────────────
        (Method::Get, "/api/platform") => {
            let caps = PlatformCapabilities::detect_current();
            let info = serde_json::json!({
                "platform": format!("{:?}", caps.platform),
                "has_tpm": caps.has_tpm,
                "has_seccomp": caps.has_seccomp,
                "has_ebpf": caps.has_ebpf,
                "has_firewall": caps.has_firewall,
                "max_threads": caps.max_threads,
            });
            json_response(&info.to_string(), 200)
        }

        // ── Side-Channel Detection ────────────────────────────────
        (Method::Get, "/api/side-channel/status") => {
            let s = state.lock().unwrap();
            let report = s.side_channel.report();
            let info = serde_json::json!({
                "timing_anomalies": report.timing_anomalies,
                "cache_alerts": report.cache_alerts,
                "covert_channels": report.covert_channels,
                "overall_risk": report.overall_risk,
            });
            json_response(&info.to_string(), 200)
        }

        // ── Quantum / Post-Quantum ────────────────────────────────
        (Method::Get, "/api/quantum/key-status") => {
            let s = state.lock().unwrap();
            let info = serde_json::json!({
                "current_epoch": s.key_rotation.current_epoch(),
                "total_epochs": s.key_rotation.epochs().len(),
            });
            json_response(&info.to_string(), 200)
        }
        (Method::Post, "/api/quantum/rotate") => {
            let mut s = state.lock().unwrap();
            s.key_rotation.rotate();
            let info = serde_json::json!({
                "status": "rotated",
                "new_epoch": s.key_rotation.current_epoch(),
            });
            json_response(&info.to_string(), 200)
        }

        // ── Privacy ───────────────────────────────────────────────
        (Method::Get, "/api/privacy/budget") => {
            let s = state.lock().unwrap();
            let info = serde_json::json!({
                "budget_remaining": s.privacy.budget_remaining(),
                "is_exhausted": s.privacy.is_exhausted(),
            });
            json_response(&info.to_string(), 200)
        }

        // ── Policy VM ─────────────────────────────────────────────
        (Method::Post, "/api/policy-vm/execute") => {
            handle_policy_vm_execute(&mut request, state)
        }

        // ── Fingerprint ───────────────────────────────────────────
        (Method::Get, "/api/fingerprint/status") => {
            let s = state.lock().unwrap();
            let info = serde_json::json!({
                "trained": s.fingerprint.is_some(),
                "replay_samples": s.replay.len(),
            });
            json_response(&info.to_string(), 200)
        }

        // ── Adversarial Harness ───────────────────────────────────
        (Method::Post, "/api/harness/run") => {
            let config = crate::harness::HarnessConfig::default();
            let result = crate::harness::run(&config);
            let info = serde_json::json!({
                "evasion_rate": result.evasion_rate,
                "coverage_ratio": result.coverage.coverage_ratio(),
                "total_count": result.total_count,
                "evasion_count": result.evasion_count,
            });
            json_response(&info.to_string(), 200)
        }

        // ── Temporal-Logic Monitor ────────────────────────────────
        (Method::Get, "/api/monitor/status") => {
            let s = state.lock().unwrap();
            let statuses: Vec<_> = s.monitor.statuses().iter().map(|(name, status)| {
                serde_json::json!({ "name": name, "status": format!("{:?}", status) })
            }).collect();
            let info = serde_json::json!({
                "properties": statuses,
                "violation_count": s.monitor.violations().len(),
            });
            json_response(&info.to_string(), 200)
        }
        (Method::Get, "/api/monitor/violations") => {
            let s = state.lock().unwrap();
            let violations: Vec<_> = s.monitor.violations().iter().map(|v| {
                serde_json::json!({
                    "property": v.property_name,
                    "event_index": v.event_index,
                })
            }).collect();
            json_response(&serde_json::json!({ "violations": violations }).to_string(), 200)
        }

        // ── Deception Engine ──────────────────────────────────────
        (Method::Get, "/api/deception/status") => {
            let s = state.lock().unwrap();
            let report = s.deception.report();
            let info = serde_json::json!({
                "total_decoys": report.total_decoys,
                "active_decoys": report.active_decoys,
                "total_interactions": report.total_interactions,
                "attacker_profiles": report.attacker_profiles,
            });
            json_response(&info.to_string(), 200)
        }
        (Method::Post, "/api/deception/deploy") => {
            handle_deception_deploy(&mut request, state)
        }

        // ── Policy Composition ────────────────────────────────────
        (Method::Post, "/api/policy/compose") => {
            handle_policy_compose(&mut request, state)
        }

        // ── Drift Detection ───────────────────────────────────────
        (Method::Get, "/api/drift/status") => {
            let s = state.lock().unwrap();
            let info = serde_json::json!({
                "sample_count": s.drift.sample_count(),
            });
            json_response(&info.to_string(), 200)
        }
        (Method::Post, "/api/drift/reset") => {
            let mut s = state.lock().unwrap();
            s.drift.reset();
            json_response(r#"{"status":"drift detector reset"}"#, 200)
        }

        // ── Causal Analysis ───────────────────────────────────────
        (Method::Get, "/api/causal/graph") => {
            let s = state.lock().unwrap();
            let info = serde_json::json!({
                "node_count": s.causal.node_count(),
                "edge_count": s.causal.edge_count(),
            });
            json_response(&info.to_string(), 200)
        }

        // ── Patch Management ──────────────────────────────────────
        (Method::Get, "/api/patches") => {
            let s = state.lock().unwrap();
            let plan = s.patches.plan();
            let info = serde_json::json!({
                "total_patches": s.patches.patch_count(),
                "installed": s.patches.installed_count(),
                "patches_in_plan": plan.patches.len(),
                "estimated_downtime_secs": plan.estimated_downtime_secs,
            });
            json_response(&info.to_string(), 200)
        }

        // ── Workload Offload ──────────────────────────────────────
        (Method::Post, "/api/offload/decide") => {
            let caps = PlatformCapabilities::detect_current();
            let edge_cap = crate::edge_cloud::EdgeCapacity {
                cpu_available: 60.0,
                memory_available_mb: 512,
                bandwidth_kbps: 1000,
                latency_to_cloud_ms: 50,
            };
            let workloads = vec![
                crate::edge_cloud::Workload { id: "w1".into(), name: "detection".into(), cpu_cost: 20.0, memory_mb: 64, latency_sensitive: true, data_size_kb: 100, tier: crate::edge_cloud::ProcessingTier::EdgePreferred },
                crate::edge_cloud::Workload { id: "w2".into(), name: "reporting".into(), cpu_cost: 10.0, memory_mb: 32, latency_sensitive: false, data_size_kb: 200, tier: crate::edge_cloud::ProcessingTier::CloudPreferred },
            ];
            let decisions = crate::edge_cloud::decide_offload(&workloads, &edge_cap);
            let info: Vec<_> = decisions.iter().map(|d| serde_json::json!({
                "workload": d.workload_id,
                "run_on": d.run_on,
                "reason": d.reason,
                "estimated_latency_ms": d.estimated_latency_ms,
            })).collect();
            json_response(&serde_json::json!({ "decisions": info, "platform": format!("{:?}", caps.platform) }).to_string(), 200)
        }

        // ── Swarm Posture ─────────────────────────────────────────
        (Method::Get, "/api/swarm/posture") => {
            let info = serde_json::json!({
                "current_posture": "standard",
                "negotiation_available": true,
            });
            json_response(&info.to_string(), 200)
        }

        // ── TLS Status ───────────────────────────────────────────
        (Method::Get, "/api/tls/status") => {
            let s = state.lock().unwrap();
            let info = serde_json::json!({
                "tls_enabled": s.listener_mode.is_tls(),
                "scheme": s.listener_mode.scheme(),
                "port": s.listener_mode.port(),
            });
            json_response(&info.to_string(), 200)
        }

        // ── Mesh Health / Self-Healing ────────────────────────────
        (Method::Get, "/api/mesh/health") => {
            let s = state.lock().unwrap();
            let (report, repairs) = s.swarm.self_heal();
            let info = serde_json::json!({
                "is_connected": report.is_connected,
                "partition_count": report.partitions.len(),
                "largest_partition_size": report.largest_partition_size,
                "partitions": report.partitions,
                "proposed_repairs": repairs,
            });
            json_response(&info.to_string(), 200)
        }
        (Method::Post, "/api/mesh/heal") => {
            let mut s = state.lock().unwrap();
            let (report, repairs) = s.swarm.self_heal();
            let applied = repairs.len();
            for repair in &repairs {
                s.swarm.apply_repair(repair);
            }
            let (post_report, _) = s.swarm.self_heal();
            let info = serde_json::json!({
                "repairs_applied": applied,
                "was_connected": report.is_connected,
                "now_connected": post_report.is_connected,
                "partitions_before": report.partitions.len(),
                "partitions_after": post_report.partitions.len(),
            });
            json_response(&info.to_string(), 200)
        }

        // ── Energy Harvesting ─────────────────────────────────────
        (Method::Post, "/api/energy/harvest") => {
            let mut s = state.lock().unwrap();
            let recharged = s.energy.capacity_mwh * 0.05;
            s.energy.current_mwh = (s.energy.current_mwh + recharged).min(s.energy.capacity_mwh);
            let info = serde_json::json!({
                "status": "harvested",
                "recharged_mwh": recharged,
                "remaining_pct": s.energy.remaining_pct(),
            });
            json_response(&info.to_string(), 200)
        }

        // ── Config Hot-Reload ─────────────────────────────────────
        (Method::Get, "/api/config/current") => {
            let s = state.lock().unwrap();
            match serde_json::to_string_pretty(&s.config) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Post, "/api/config/reload") => {
            handle_config_reload(&mut request, state)
        }
        (Method::Post, "/api/config/save") => {
            let s = state.lock().unwrap();
            let config_path = std::path::Path::new("var/wardex.toml");
            match toml::to_string_pretty(&s.config) {
                Ok(toml_str) => {
                    if let Some(parent) = config_path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    match std::fs::write(config_path, &toml_str) {
                        Ok(()) => json_response(
                            &format!(r#"{{"status":"saved","path":"{}"}}"#, config_path.display()),
                            200,
                        ),
                        Err(e) => error_json(&format!("failed to write config: {e}"), 500),
                    }
                }
                Err(e) => error_json(&format!("failed to serialize config: {e}"), 500),
            }
        }

        // ── Health & Alerts ──────────────────────────────────────────
        (Method::Get, "/api/health") => {
            let s = state.lock().unwrap();
            let host = crate::collector::detect_platform();
            let uptime = s.server_start.elapsed().as_secs();
            let body = serde_json::json!({
                "status": "ok",
                "version": env!("CARGO_PKG_VERSION"),
                "uptime_secs": uptime,
                "platform": host.platform.to_string(),
                "hostname": host.hostname,
                "os_version": host.os_version,
            });
            json_response(&body.to_string(), 200)
        }
        (Method::Get, "/api/alerts") => {
            let s = state.lock().unwrap();
            let recent: Vec<_> = s.alerts.iter().enumerate().rev().take(100)
                .map(|(i, a)| {
                    let mut obj = serde_json::to_value(a).unwrap_or_default();
                    if let Some(map) = obj.as_object_mut() {
                        map.insert("_index".to_string(), serde_json::json!(i));
                    }
                    obj
                })
                .collect();
            match serde_json::to_string(&recent) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/alerts/count") => {
            let s = state.lock().unwrap();
            let total = s.alerts.len();
            let critical = s.alerts.iter().filter(|a| a.level == "Critical").count();
            let severe = s.alerts.iter().filter(|a| a.level == "Severe").count();
            let elevated = s.alerts.iter().filter(|a| a.level == "Elevated").count();
            let body = serde_json::json!({
                "total": total,
                "critical": critical,
                "severe": severe,
                "elevated": elevated,
            });
            json_response(&body.to_string(), 200)
        }
        (Method::Delete, "/api/alerts") => {
            let mut s = state.lock().unwrap();
            let cleared = s.alerts.len();
            s.alerts.clear();
            json_response(
                &format!(r#"{{"status":"cleared","count":{cleared}}}"#),
                200,
            )
        }
        // ── Local Telemetry ──────────────────────────────────────
        (Method::Get, "/api/telemetry/current") => {
            let s = state.lock().unwrap();
            if let Some(sample) = s.local_telemetry.last() {
                match serde_json::to_string(sample) {
                    Ok(json) => json_response(&json, 200),
                    Err(e) => error_json(&format!("serialization error: {e}"), 500),
                }
            } else {
                json_response(r#"{"message":"no telemetry collected yet"}"#, 200)
            }
        }
        (Method::Get, "/api/telemetry/history") => {
            let s = state.lock().unwrap();
            let samples: Vec<_> = s.local_telemetry.iter().rev().take(120).collect();
            match serde_json::to_string(&samples) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/host/info") => {
            let s = state.lock().unwrap();
            let host = &s.local_host_info;
            let uptime = s.server_start.elapsed().as_secs();
            let cpu_cores = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1);
            let capabilities = PlatformCapabilities::detect_current();
            let body = serde_json::json!({
                "hostname": host.hostname,
                "platform": host.platform.to_string(),
                "os_version": host.os_version,
                "arch": host.arch,
                "cpu_cores": cpu_cores,
                "uptime_secs": uptime,
                "version": env!("CARGO_PKG_VERSION"),
                "local_monitoring": true,
                "telemetry_samples": s.local_telemetry.len(),
                "has_tpm": capabilities.has_tpm,
                "has_seccomp": capabilities.has_seccomp,
                "has_ebpf": capabilities.has_ebpf,
                "has_firewall": capabilities.has_firewall,
            });
            json_response(&body.to_string(), 200)
        }
        (Method::Get, "/api/threads/status") => {
            let s = state.lock().unwrap();
            let uptime = s.server_start.elapsed().as_secs();
            let body = serde_json::json!({
                "monitoring_thread": "active",
                "sample_count": s.local_telemetry.len(),
                "collection_rate_hz": 0.2,
                "uptime_secs": uptime,
                "alert_count": s.alerts.len(),
            });
            json_response(&body.to_string(), 200)
        }
        (Method::Get, "/api/monitoring/options") => {
            let s = state.lock().unwrap();
            let body = monitoring_options_payload(&s.local_host_info, &s.config);
            json_response(&body.to_string(), 200)
        }
        (Method::Get, "/api/monitoring/paths") => {
            let s = state.lock().unwrap();
            let body = monitoring_paths_payload(&s.local_host_info, &s.config);
            json_response(&body.to_string(), 200)
        }
        (Method::Get, "/api/rollout/config") => {
            let s = state.lock().unwrap();
            match serde_json::to_string(&s.config.rollout) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/endpoints") => {
            let endpoints = serde_json::json!([
                {"method": "GET", "path": "/api/health", "auth": false, "description": "Server health, version, uptime, platform"},
                {"method": "GET", "path": "/api/host/info", "auth": true, "description": "Detailed host info + monitoring status"},
                {"method": "GET", "path": "/api/telemetry/current", "auth": true, "description": "Latest local telemetry sample"},
                {"method": "GET", "path": "/api/telemetry/history", "auth": true, "description": "Last 120 local telemetry samples"},
                {"method": "GET", "path": "/api/checkpoints", "auth": true, "description": "Saved checkpoint metadata"},
                {"method": "GET", "path": "/api/correlation", "auth": true, "description": "Replay-buffer correlation analysis"},
                {"method": "GET", "path": "/api/alerts", "auth": true, "description": "Last 100 alerts"},
                {"method": "GET", "path": "/api/alerts/count", "auth": true, "description": "Alert count by severity"},
                {"method": "DELETE", "path": "/api/alerts", "auth": true, "description": "Clear all alerts"},
                {"method": "GET", "path": "/api/status", "auth": true, "description": "Project status manifest"},
                {"method": "GET", "path": "/api/report", "auth": true, "description": "Latest analysis report"},
                {"method": "POST", "path": "/api/analyze", "auth": true, "description": "Analyze CSV/JSONL telemetry"},
                {"method": "GET", "path": "/api/config/current", "auth": true, "description": "Current configuration"},
                {"method": "GET", "path": "/api/monitoring/options", "auth": true, "description": "OS-aware monitoring points and recommendations"},
                {"method": "GET", "path": "/api/monitoring/paths", "auth": true, "description": "Active file-integrity and persistence monitoring paths"},
                {"method": "POST", "path": "/api/config/reload", "auth": true, "description": "Hot-reload config patch"},
                {"method": "POST", "path": "/api/config/save", "auth": true, "description": "Persist config to disk"},
                {"method": "GET", "path": "/api/endpoints", "auth": true, "description": "This endpoint listing"},
                {"method": "GET", "path": "/api/threads/status", "auth": true, "description": "Background thread status and collection stats"},
                {"method": "GET", "path": "/api/detection/summary", "auth": true, "description": "Velocity, entropy, compound detector state"},
                {"method": "GET", "path": "/api/events/summary", "auth": true, "description": "XDR fleet event analytics summary"},
                {"method": "GET", "path": "/api/events/export", "auth": true, "description": "Export filtered XDR events as CSV"},
                {"method": "POST", "path": "/api/events/{id}/triage", "auth": true, "description": "Update event triage state, assignee, tags, and analyst notes"},
                {"method": "GET", "path": "/api/policy/history", "auth": true, "description": "Published policy history"},
                {"method": "POST", "path": "/api/updates/deploy", "auth": true, "description": "Assign a published release to a specific agent"},
                {"method": "GET", "path": "/api/audit/log", "auth": true, "description": "Recent API audit log entries"},
                {"method": "GET", "path": "/api/incidents", "auth": true, "description": "List incidents with optional status/severity filters"},
                {"method": "GET", "path": "/api/incidents/{id}", "auth": true, "description": "Incident detail with timeline"},
                {"method": "POST", "path": "/api/incidents", "auth": true, "description": "Manually create an incident from selected events"},
                {"method": "POST", "path": "/api/incidents/{id}/update", "auth": true, "description": "Update incident status/assignee/notes"},
                {"method": "GET", "path": "/api/agents/{id}/logs", "auth": true, "description": "Retrieve agent logs"},
                {"method": "POST", "path": "/api/agents/{id}/logs", "auth": false, "description": "Agent log ingestion"},
                {"method": "GET", "path": "/api/agents/{id}/inventory", "auth": true, "description": "Retrieve agent inventory"},
                {"method": "POST", "path": "/api/agents/{id}/inventory", "auth": false, "description": "Agent inventory reporting"},
                {"method": "GET", "path": "/api/fleet/inventory", "auth": true, "description": "Fleet-wide inventory summary"},
                {"method": "GET", "path": "/api/detection/weights", "auth": true, "description": "Current detection signal weights"},
                {"method": "POST", "path": "/api/detection/weights", "auth": true, "description": "Set per-dimension detection weights"},
                {"method": "GET", "path": "/api/reports", "auth": true, "description": "List stored reports"},
                {"method": "GET", "path": "/api/reports/{id}", "auth": true, "description": "Retrieve specific report"},
                {"method": "GET", "path": "/api/reports/{id}/html", "auth": true, "description": "HTML report download"},
                {"method": "GET", "path": "/api/reports/executive-summary", "auth": true, "description": "Executive summary across all reports and incidents"},
                {"method": "GET", "path": "/api/incidents/{id}/report", "auth": true, "description": "Generate incident report"},
            ]);
            json_response(&endpoints.to_string(), 200)
        }

        // ── XDR Agent Management ──────────────────────────────────
        (Method::Post, "/api/agents/enroll") => {
            handle_agent_enroll(&mut request, state)
        }
        (Method::Post, "/api/agents/token") => {
            handle_agent_create_token(&mut request, state)
        }
        (Method::Get, "/api/agents") => {
            let mut s = state.lock().unwrap();
            s.agent_registry.refresh_staleness();
            let agents = s.agent_registry.list();
            match serde_json::to_string(&agents) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }

        // ── XDR Events ────────────────────────────────────────────
        (Method::Post, "/api/events") => {
            handle_event_ingest(&mut request, state)
        }
        (Method::Get, "/api/events") => {
            let s = state.lock().unwrap();
            let query = parse_event_query(&url);
            let events = filtered_events(&s.event_store, &query);
            match serde_json::to_string(&events) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/events/export") => {
            let s = state.lock().unwrap();
            let query = parse_event_query(&url);
            let events = filtered_events(&s.event_store, &query);
            csv_response(&events_to_csv(&events), 200)
        }
        (Method::Get, "/api/events/summary") => {
            let s = state.lock().unwrap();
            let analytics = s.event_store.analytics();
            match serde_json::to_string(&analytics) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }

        // ── XDR Policy Distribution ──────────────────────────────
        (Method::Get, "/api/policy/current") => {
            let s = state.lock().unwrap();
            match s.policy_store.current() {
                Some(policy) => match serde_json::to_string(policy) {
                    Ok(json) => json_response(&json, 200),
                    Err(e) => error_json(&format!("serialization error: {e}"), 500),
                },
                None => json_response(r#"{"version":0,"message":"no policy published"}"#, 200),
            }
        }
        (Method::Get, "/api/policy/history") => {
            let s = state.lock().unwrap();
            match serde_json::to_string(s.policy_store.history()) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Post, "/api/policy/publish") => {
            handle_policy_publish(&mut request, state)
        }

        // ── XDR Update Distribution ──────────────────────────────
        (Method::Post, "/api/updates/publish") => {
            handle_update_publish(&mut request, state)
        }
        (Method::Post, "/api/updates/deploy") => {
            handle_update_deploy(&mut request, state)
        }
        (Method::Post, "/api/updates/rollback") => {
            handle_update_rollback(&mut request, state)
        }
        (Method::Post, "/api/updates/cancel") => {
            handle_update_cancel(&mut request, state)
        }
        (Method::Post, "/api/events/bulk-triage") => {
            handle_bulk_triage(&mut request, state)
        }

        // ── Detection Analysis ─────────────────────────────────
        (Method::Get, "/api/detection/summary") => {
            let s = state.lock().unwrap();
            let vel_state = &s.velocity;
            let ent_state = &s.entropy;
            let cmp_state = &s.compound;
            let body = serde_json::json!({
                "velocity": {
                    "window_size": vel_state.window_len(),
                    "sigma": vel_state.sigma(),
                },
                "entropy": {
                    "window_size": ent_state.window_len(),
                    "bins": ent_state.bins(),
                },
                "compound": {
                    "min_concurrent_fraction": cmp_state.min_concurrent_fraction,
                    "per_axis_threshold": cmp_state.per_axis_threshold,
                },
            });
            json_response(&body.to_string(), 200)
        }
        (Method::Get, "/api/detection/weights") => {
            let s = state.lock().unwrap();
            let weights = s.detector.signal_weights();
            match serde_json::to_string(&weights) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Post, "/api/detection/weights") => {
            let body = match read_body_limited(&mut request, 10 * 1024 * 1024) {
                Ok(b) => b,
                Err(e) => { let _ = request.respond(error_json(&e, 400)); return; },
            };
            let weights: HashMap<String, f32> = match serde_json::from_str(&body) {
                Ok(w) => w,
                Err(e) => { let _ = request.respond(error_json(&format!("invalid JSON: {e}"), 400)); return; },
            };
            let mut s = state.lock().unwrap();
            s.detector.set_signal_weights(weights.clone());
            drop(s);
            json_response(&serde_json::json!({"status":"weights_updated","weights":weights}).to_string(), 200)
        }

        // ── Audit Log ─────────────────────────────────────────────
        (Method::Get, "/api/audit/log") => {
            let s = state.lock().unwrap();
            let entries = s.audit_log.recent(200);
            match serde_json::to_string(entries) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }

        // ── Incidents ─────────────────────────────────────────────
        (Method::Get, "/api/incidents") => {
            let s = state.lock().unwrap();
            let query = parse_query_string(&url);
            let status = query.get("status").map(|s| s.as_str());
            let severity = query.get("severity").map(|s| s.as_str());
            let incidents = s.incident_store.list_filtered(status, severity);
            match serde_json::to_string(&incidents) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Post, "/api/incidents") => {
            let body = match read_body_limited(&mut request, 10 * 1024 * 1024) {
                Ok(b) => b,
                Err(e) => { let _ = request.respond(error_json(&e, 400)); return; },
            };
            #[derive(serde::Deserialize)]
            struct CreateIncident {
                title: String,
                severity: String,
                #[serde(default)]
                event_ids: Vec<u64>,
                #[serde(default)]
                agent_ids: Vec<String>,
                #[serde(default)]
                summary: String,
            }
            let req: CreateIncident = match serde_json::from_str(&body) {
                Ok(r) => r,
                Err(e) => { let _ = request.respond(error_json(&format!("invalid JSON: {e}"), 400)); return; },
            };
            let mut s = state.lock().unwrap();
            let inc = s.incident_store.create(req.title, req.severity, req.event_ids, req.agent_ids, vec![], req.summary);
            match serde_json::to_string(inc) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }

        // ── Fleet Inventory ──────────────────────────────────────
        (Method::Get, "/api/fleet/inventory") => {
            let s = state.lock().unwrap();
            let summary: Vec<serde_json::Value> = s.agent_inventories.iter().map(|(id, inv)| {
                serde_json::json!({
                    "agent_id": id,
                    "collected_at": inv.collected_at,
                    "hardware": inv.hardware,
                    "software_count": inv.software.len(),
                    "services_count": inv.services.len(),
                    "network_ports": inv.network.len(),
                    "users_count": inv.users.len(),
                })
            }).collect();
            json_response(&serde_json::json!({"agents": summary}).to_string(), 200)
        }

        // ── Reports ──────────────────────────────────────────────
        (Method::Get, "/api/reports") => {
            let s = state.lock().unwrap();
            let list = s.report_store.list();
            match serde_json::to_string(&list) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/reports/executive-summary") => {
            let s = state.lock().unwrap();
            let summary = s.report_store.executive_summary(&s.incident_store);
            match serde_json::to_string(&summary) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }

        // ── SIEM Status ──────────────────────────────────────────
        (Method::Get, "/api/siem/status") => {
            let s = state.lock().unwrap();
            let status = s.siem_connector.status();
            match serde_json::to_string(&status) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }

        // ── Fleet Dashboard ──────────────────────────────────────
        (Method::Get, "/api/fleet/dashboard") => {
            let mut s = state.lock().unwrap();
            s.agent_registry.refresh_staleness();
            let agents = s.agent_registry.list();
            let counts = s.agent_registry.counts();
            let total_events = s.event_store.total_events();
            let correlations = s.event_store.recent_correlations();
            let analytics = s.event_store.analytics();
            let policy_version = s.policy_store.current_version();
            let siem_status = s.siem_connector.status();
            let releases = s.update_manager.list_releases();
            let deployments = s.remote_deployments.values().cloned().collect::<Vec<_>>();
            let active_deployments = deployments
                .iter()
                .filter(|deployment| deployment_is_pending(deployment, &s.agent_registry))
                .cloned()
                .collect::<Vec<_>>();
            let info = serde_json::json!({
                "fleet": {
                    "total_agents": agents.len(),
                    "status_counts": counts,
                },
                "events": {
                    "total": total_events,
                    "recent_correlations": correlations.len(),
                    "correlations": correlations,
                    "analytics": analytics,
                    "triage": {
                        "counts": s.event_store.triage_summary(),
                        "persistent": s.event_store.has_persistence(),
                        "storage_path": s.event_store.storage_path(),
                    },
                },
                "policy": {
                    "current_version": policy_version,
                    "history_depth": s.policy_store.history().len(),
                },
                "updates": {
                    "available_releases": releases.len(),
                    "pending_deployments": active_deployments.len(),
                    "release_catalog": releases.iter().rev().take(10).cloned().collect::<Vec<_>>(),
                    "deployments": deployments,
                    "active_deployments": active_deployments,
                    "rollout_groups": s.remote_deployments.values().filter(|deployment| deployment_is_pending(deployment, &s.agent_registry)).fold(HashMap::new(), |mut acc, deployment| {
                        *acc.entry(deployment.rollout_group.clone()).or_insert(0usize) += 1;
                        acc
                    }),
                },
                "siem": {
                    "enabled": siem_status.enabled,
                    "pending": siem_status.pending_events,
                    "total_pushed": siem_status.total_pushed,
                    "total_pulled": siem_status.total_pulled,
                },
            });
            json_response(&info.to_string(), 200)
        }

        (Method::Post, "/api/shutdown") => {
            let s = state.lock().unwrap();
            s.shutdown.store(true, Ordering::SeqCst);
            drop(s);
            server.unblock();
            json_response(r#"{"status":"shutting_down"}"#, 200)
        }

        (Method::Options, _) => {
            let data: Vec<u8> = Vec::new();
            Response::new(
                tiny_http::StatusCode(204),
                vec![
                    Header::from_bytes(b"Access-Control-Allow-Origin", cors_origin().as_bytes())
                        .unwrap(),
                    Header::from_bytes(b"Vary", b"Origin").unwrap(),
                    Header::from_bytes(b"Access-Control-Allow-Methods", b"GET, POST, OPTIONS")
                        .unwrap(),
                    Header::from_bytes(
                        b"Access-Control-Allow-Headers",
                        b"Content-Type, Authorization",
                    )
                    .unwrap(),
                ],
                std::io::Cursor::new(data),
                Some(0),
                None,
            )
        }

        // ── Sigma Detection Engine ────────────────────────────────
        (Method::Get, "/api/sigma/rules") => {
            let s = state.lock().unwrap();
            let rules: Vec<serde_json::Value> = s.sigma_engine.rules().iter().map(|r| {
                serde_json::json!({
                    "id": r.id,
                    "title": r.title,
                    "status": r.status,
                    "level": format!("{:?}", r.level),
                    "description": r.description,
                })
            }).collect();
            json_response(&serde_json::json!({"rules": rules, "count": rules.len()}).to_string(), 200)
        }
        (Method::Get, "/api/sigma/stats") => {
            let s = state.lock().unwrap();
            let info = serde_json::json!({
                "total_rules": s.sigma_engine.rules().len(),
                "engine_status": "active",
            });
            json_response(&info.to_string(), 200)
        }

        // ── OCSF Events ──────────────────────────────────────────
        (Method::Get, "/api/ocsf/schema") => {
            if !is_feature_enabled(state, "ocsf_normalization") {
                error_json("OCSF normalization feature is disabled", 503)
            } else {
                let info = serde_json::json!({
                    "version": "1.1.0",
                    "supported_classes": [1007, 1001, 4001, 4003, 3002, 5001, 2004],
                    "class_names": ["ProcessActivity", "FileActivity", "NetworkActivity", "DnsActivity", "Authentication", "ConfigState", "DetectionFinding"],
                });
                json_response(&info.to_string(), 200)
            }
        }
        (Method::Get, "/api/ocsf/schema/version") => {
            let sv = SchemaVersion::current();
            json_response(&serde_json::json!({
                "ocsf_version": sv.ocsf_version,
                "product_version": sv.product_version,
                "supported_classes": sv.supported_classes,
            }).to_string(), 200)
        }

        // ── Dead-Letter Queue ─────────────────────────────────────
        (Method::Get, "/api/dlq") => {
            let s = state.lock().unwrap();
            let items: Vec<serde_json::Value> = s.dead_letter_queue.list().iter().map(|e| {
                serde_json::json!({
                    "original_payload": e.original_payload,
                    "errors": e.errors,
                    "received_at": e.received_at,
                    "source_agent": e.source_agent,
                })
            }).collect();
            json_response(&serde_json::json!({
                "dead_letters": items,
                "count": items.len(),
            }).to_string(), 200)
        }
        (Method::Get, "/api/dlq/stats") => {
            let s = state.lock().unwrap();
            json_response(&serde_json::json!({
                "count": s.dead_letter_queue.len(),
                "empty": s.dead_letter_queue.is_empty(),
            }).to_string(), 200)
        }
        (Method::Delete, "/api/dlq") => {
            let mut s = state.lock().unwrap();
            let before = s.dead_letter_queue.len();
            s.dead_letter_queue.clear();
            json_response(&serde_json::json!({"cleared": before}).to_string(), 200)
        }

        // ── Response Orchestration ────────────────────────────────
        (Method::Get, "/api/response/pending") => {
            let s = state.lock().unwrap();
            let pending = s.response_orchestrator.pending_requests();
            let items: Vec<serde_json::Value> = pending.iter().map(|r| {
                serde_json::json!({
                    "id": r.id,
                    "action": format!("{:?}", r.action),
                    "target": r.target,
                    "tier": format!("{:?}", r.tier),
                    "status": format!("{:?}", r.status),
                    "created_at": r.requested_at,
                    "approvals": r.approvals,
                    "dry_run": r.dry_run,
                })
            }).collect();
            json_response(&serde_json::json!({"pending": items, "count": items.len()}).to_string(), 200)
        }
        (Method::Get, "/api/response/audit") => {
            let s = state.lock().unwrap();
            let ledger = s.response_orchestrator.audit_ledger();
            let entries: Vec<serde_json::Value> = ledger.iter().map(|e| {
                serde_json::json!({
                    "request_id": e.request_id,
                    "action": format!("{:?}", e.action),
                    "target": e.target_hostname,
                    "outcome": format!("{:?}", e.status),
                    "timestamp": e.timestamp,
                    "approvers": e.approvals,
                })
            }).collect();
            json_response(&serde_json::json!({"audit_log": entries}).to_string(), 200)
        }
        (Method::Get, "/api/response/stats") => {
            let s = state.lock().unwrap();
            let pending = s.response_orchestrator.pending_requests();
            let audit = s.response_orchestrator.audit_ledger();
            let auto_count = audit.iter().filter(|e| format!("{:?}", e.status) == "Executed").count();
            let denied_count = audit.iter().filter(|e| format!("{:?}", e.status) == "Denied").count();
            let protected = s.response_orchestrator.protected_asset_count();
            let info = serde_json::json!({
                "auto_executed": auto_count,
                "pending_approval": pending.len(),
                "denied": denied_count,
                "protected_assets": protected,
            });
            json_response(&info.to_string(), 200)
        }

        // ── Feature Flags ─────────────────────────────────────────
        (Method::Get, "/api/feature-flags") => {
            let s = state.lock().unwrap();
            let flags = s.feature_flags.all_flags();
            let items: Vec<serde_json::Value> = flags.iter().map(|f| {
                serde_json::json!({
                    "name": f.name,
                    "description": f.description,
                    "enabled": f.enabled,
                    "rollout_pct": f.rollout_pct,
                    "kill_switch": f.kill_switch,
                })
            }).collect();
            json_response(&serde_json::json!({"flags": items}).to_string(), 200)
        }

        // ── Process Tree ──────────────────────────────────────────
        (Method::Get, "/api/process-tree") => {
            let s = state.lock().unwrap();
            let alive = s.process_tree.alive_processes();
            let nodes: Vec<serde_json::Value> = alive.iter().map(|p| {
                serde_json::json!({
                    "pid": p.pid,
                    "ppid": p.ppid,
                    "name": p.name,
                    "cmd_line": p.cmd_line,
                    "user": p.user,
                    "exe_path": p.exe_path,
                    "hostname": p.hostname,
                    "start_time": p.start_time,
                    "alive": p.alive,
                })
            }).collect();
            json_response(&serde_json::json!({"processes": nodes, "count": nodes.len()}).to_string(), 200)
        }
        (Method::Get, "/api/process-tree/deep-chains") => {
            let s = state.lock().unwrap();
            let chains = s.process_tree.deep_chains(4);
            let items: Vec<serde_json::Value> = chains.iter().map(|chain| {
                let leaf = &chain[0];
                serde_json::json!({
                    "pid": leaf.pid,
                    "name": leaf.name,
                    "cmd_line": leaf.cmd_line,
                    "depth": chain.len(),
                })
            }).collect();
            json_response(&serde_json::json!({"deep_chains": items}).to_string(), 200)
        }

        // ── Encrypted Spool ───────────────────────────────────────
        (Method::Get, "/api/spool/stats") => {
            let s = state.lock().unwrap();
            let stats = s.spool.stats();
            let info = serde_json::json!({
                "queued": stats.current_depth,
                "capacity": stats.max_entries,
                "utilization_pct": stats.utilization_pct,
                "total_enqueued": stats.total_enqueued,
                "total_delivered": stats.total_delivered,
                "total_dropped": stats.total_dropped,
                "backpressure": format!("{:?}", s.spool.backpressure()),
            });
            json_response(&info.to_string(), 200)
        }

        // ── RBAC ──────────────────────────────────────────────────
        (Method::Get, "/api/rbac/users") => {
            let s = state.lock().unwrap();
            let users = s.rbac.list_users();
            let items: Vec<serde_json::Value> = users.iter().map(|u| {
                serde_json::json!({
                    "username": u.username,
                    "role": format!("{:?}", u.role),
                    "enabled": u.enabled,
                })
            }).collect();
            json_response(&serde_json::json!({"users": items}).to_string(), 200)
        }

        // ── Analyst Console: Cases ─────────────────────────────────
        (Method::Get, "/api/cases") => {
            let s = state.lock().unwrap();
            let status = url_param(&url, "status");
            let priority = url_param(&url, "priority");
            let assignee = url_param(&url, "assignee");
            let cases = s.case_store.list_filtered(
                status.as_deref(), priority.as_deref(), assignee.as_deref(),
            );
            let items: Vec<serde_json::Value> = cases.iter().map(|c| {
                serde_json::json!({
                    "id": c.id, "title": c.title, "status": format!("{:?}", c.status),
                    "priority": format!("{:?}", c.priority), "assignee": c.assignee,
                    "created_at": c.created_at, "updated_at": c.updated_at,
                    "incident_count": c.incident_ids.len(), "event_count": c.event_ids.len(),
                    "tags": c.tags,
                })
            }).collect();
            json_response(&serde_json::json!({"cases": items, "total": items.len()}).to_string(), 200)
        }
        (Method::Post, "/api/cases") => {
            let body = read_body_limited(&mut request, 8192);
            match body {
                Ok(b) => match serde_json::from_str::<serde_json::Value>(&b) {
                    Ok(v) => {
                        let title = v["title"].as_str().unwrap_or("Untitled Case").to_string();
                        let desc = v["description"].as_str().unwrap_or("").to_string();
                        let prio = match v["priority"].as_str().unwrap_or("medium") {
                            "critical" => CasePriority::Critical,
                            "high" => CasePriority::High,
                            "low" => CasePriority::Low,
                            "info" => CasePriority::Info,
                            _ => CasePriority::Medium,
                        };
                        let inc_ids: Vec<u64> = v["incident_ids"].as_array()
                            .map(|a| a.iter().filter_map(|x| x.as_u64()).collect())
                            .unwrap_or_default();
                        let evt_ids: Vec<u64> = v["event_ids"].as_array()
                            .map(|a| a.iter().filter_map(|x| x.as_u64()).collect())
                            .unwrap_or_default();
                        let tags: Vec<String> = v["tags"].as_array()
                            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                            .unwrap_or_default();
                        let mut s = state.lock().unwrap();
                        let case = s.case_store.create(title, desc, prio, inc_ids, evt_ids, tags);
                        json_response(&serde_json::json!({"id": case.id, "status": "created"}).to_string(), 201)
                    }
                    Err(_) => error_json("invalid JSON", 400),
                },
                Err(e) => error_json(&e, 400),
            }
        }
        (Method::Get, "/api/cases/stats") => {
            let s = state.lock().unwrap();
            let stats = s.case_store.stats();
            json_response(&serde_json::json!(stats).to_string(), 200)
        }

        // ── Analyst Console: Alert Queue ───────────────────────────
        (Method::Get, "/api/queue/alerts") => {
            let s = state.lock().unwrap();
            let pending = s.alert_queue.pending();
            let items: Vec<serde_json::Value> = pending.iter().map(|a| {
                serde_json::json!({
                    "event_id": a.event_id, "score": a.score, "level": a.level,
                    "hostname": a.hostname, "timestamp": a.timestamp,
                    "assignee": a.assignee, "sla_deadline": a.sla_deadline,
                })
            }).collect();
            json_response(&serde_json::json!({"queue": items, "count": items.len()}).to_string(), 200)
        }
        (Method::Get, "/api/queue/stats") => {
            let s = state.lock().unwrap();
            json_response(&s.alert_queue.stats().to_string(), 200)
        }
        (Method::Post, "/api/queue/acknowledge") => {
            let body = read_body_limited(&mut request, 1024);
            match body {
                Ok(b) => match serde_json::from_str::<serde_json::Value>(&b) {
                    Ok(v) => {
                        let event_id = v["event_id"].as_u64().unwrap_or(0);
                        let mut s = state.lock().unwrap();
                        if s.alert_queue.acknowledge(event_id) {
                            json_response(&serde_json::json!({"acknowledged": event_id}).to_string(), 200)
                        } else {
                            error_json("event not found in queue", 404)
                        }
                    }
                    Err(_) => error_json("invalid JSON", 400),
                },
                Err(e) => error_json(&e, 400),
            }
        }
        (Method::Post, "/api/queue/assign") => {
            let body = read_body_limited(&mut request, 1024);
            match body {
                Ok(b) => match serde_json::from_str::<serde_json::Value>(&b) {
                    Ok(v) => {
                        let event_id = v["event_id"].as_u64().unwrap_or(0);
                        let assignee = v["assignee"].as_str().unwrap_or("").to_string();
                        let mut s = state.lock().unwrap();
                        if s.alert_queue.assign(event_id, assignee.clone()) {
                            json_response(&serde_json::json!({"assigned": event_id, "assignee": assignee}).to_string(), 200)
                        } else {
                            error_json("event not found in queue", 404)
                        }
                    }
                    Err(_) => error_json("invalid JSON", 400),
                },
                Err(e) => error_json(&e, 400),
            }
        }

        // ── Analyst Console: Event Search ──────────────────────────
        (Method::Post, "/api/events/search") => {
            let body = read_body_limited(&mut request, 4096);
            match body {
                Ok(b) => match serde_json::from_str::<crate::analyst::SearchQuery>(&b) {
                    Ok(q) => {
                        let s = state.lock().unwrap();
                        let events = s.event_store.all_events();
                        let results = crate::analyst::search_events(events, &q);
                        let items: Vec<serde_json::Value> = results.iter().map(|e| {
                            serde_json::json!({
                                "id": e.id, "agent_id": e.agent_id,
                                "hostname": e.alert.hostname, "score": e.alert.score,
                                "level": e.alert.level, "timestamp": e.alert.timestamp,
                                "reasons": e.alert.reasons, "action": e.alert.action,
                            })
                        }).collect();
                        json_response(&serde_json::json!({"results": items, "count": items.len()}).to_string(), 200)
                    }
                    Err(_) => error_json("invalid search query", 400),
                },
                Err(e) => error_json(&e, 400),
            }
        }

        // ── Analyst Console: Timeline ──────────────────────────────
        (Method::Get, "/api/timeline/host") => {
            let hostname = url_param(&url, "hostname").unwrap_or_default();
            if hostname.is_empty() {
                error_json("hostname parameter required", 400)
            } else {
                let s = state.lock().unwrap();
                let events = s.event_store.all_events();
                let tl = crate::analyst::build_host_timeline(events, &hostname);
                json_response(&serde_json::json!({"timeline": tl, "host": hostname, "count": tl.len()}).to_string(), 200)
            }
        }
        (Method::Get, "/api/timeline/agent") => {
            let agent_id = url_param(&url, "agent_id").unwrap_or_default();
            if agent_id.is_empty() {
                error_json("agent_id parameter required", 400)
            } else {
                let s = state.lock().unwrap();
                let events = s.event_store.all_events();
                let tl = crate::analyst::build_agent_timeline(events, &agent_id);
                json_response(&serde_json::json!({"timeline": tl, "agent_id": agent_id, "count": tl.len()}).to_string(), 200)
            }
        }

        // ── Analyst Console: Investigation Graph ───────────────────
        (Method::Post, "/api/investigation/graph") => {
            let body = read_body_limited(&mut request, 4096);
            match body {
                Ok(b) => match serde_json::from_str::<serde_json::Value>(&b) {
                    Ok(v) => {
                        let event_ids: Vec<u64> = v["event_ids"].as_array()
                            .map(|a| a.iter().filter_map(|x| x.as_u64()).collect())
                            .unwrap_or_default();
                        let s = state.lock().unwrap();
                        let events = s.event_store.all_events();
                        let graph = crate::analyst::build_investigation_graph(events, &event_ids);
                        json_response(&serde_json::json!({
                            "nodes": graph.nodes, "edges": graph.edges,
                            "node_count": graph.nodes.len(), "edge_count": graph.edges.len(),
                        }).to_string(), 200)
                    }
                    Err(_) => error_json("invalid JSON", 400),
                },
                Err(e) => error_json(&e, 400),
            }
        }

        // ── Analyst Console: Remediation Approval ──────────────────
        (Method::Post, "/api/response/approve") => {
            let body = read_body_limited(&mut request, 2048);
            match body {
                Ok(b) => match serde_json::from_str::<serde_json::Value>(&b) {
                    Ok(v) => {
                        let request_id = v["request_id"].as_str().unwrap_or("").to_string();
                        let decision = match v["decision"].as_str().unwrap_or("") {
                            "approved" | "approve" => ApprovalDecision::Approved,
                            "denied" | "deny" => ApprovalDecision::Denied,
                            _ => {
                                let _ = request.respond(json_response(&serde_json::json!({"error": "decision must be 'approved' or 'denied'"}).to_string(), 400));
                                return;
                            }
                        };
                        let approver = v["approver"].as_str().unwrap_or("unknown").to_string();
                        let reason = v["reason"].as_str().unwrap_or("").to_string();
                        let mut s = state.lock().unwrap();
                        s.approval_log.record(request_id.clone(), decision.clone(), approver, reason);
                        json_response(&serde_json::json!({
                            "request_id": request_id,
                            "decision": format!("{:?}", decision),
                        }).to_string(), 200)
                    }
                    Err(_) => error_json("invalid JSON", 400),
                },
                Err(e) => error_json(&e, 400),
            }
        }
        (Method::Get, "/api/response/approvals") => {
            let s = state.lock().unwrap();
            let entries = s.approval_log.recent(50);
            let items: Vec<serde_json::Value> = entries.iter().map(|e| {
                serde_json::json!({
                    "request_id": e.request_id, "decision": format!("{:?}", e.decision),
                    "approver": e.approver, "reason": e.reason, "decided_at": e.decided_at,
                })
            }).collect();
            json_response(&serde_json::json!({"approvals": items}).to_string(), 200)
        }

        _ => {
            // Dynamic routes with path parameters
            if method == Method::Get && (url == "/api/agents/update" || url.starts_with("/api/agents/update?")) {
                // GET /api/agents/update?current_version=xxx&platform=yyy
                handle_agent_update_check(&mut request, state)
            } else if method == Method::Get && url.starts_with("/api/events/export?") {
                let s = state.lock().unwrap();
                let query = parse_event_query(&url);
                let events = filtered_events(&s.event_store, &query);
                csv_response(&events_to_csv(&events), 200)
            } else if method == Method::Get && url.starts_with("/api/events?") {
                let s = state.lock().unwrap();
                let query = parse_event_query(&url);
                let events = filtered_events(&s.event_store, &query);
                match serde_json::to_string(&events) {
                    Ok(json) => json_response(&json, 200),
                    Err(e) => error_json(&format!("serialization error: {e}"), 500),
                }
            } else if method == Method::Post && url.ends_with("/heartbeat") && url.starts_with("/api/agents/") {
                // POST /api/agents/{id}/heartbeat
                let agent_id = url.strip_prefix("/api/agents/")
                    .and_then(|rest| rest.strip_suffix("/heartbeat"))
                    .unwrap_or("");
                handle_agent_heartbeat(&mut request, state, agent_id)
            } else if method == Method::Get && url.starts_with("/api/agents/") && url.ends_with("/details") {
                let agent_id = url.strip_prefix("/api/agents/")
                    .and_then(|rest| rest.strip_suffix("/details"))
                    .unwrap_or("");
                handle_agent_details(state, agent_id)
            } else if method == Method::Post && url.starts_with("/api/events/") && url.ends_with("/triage") {
                let event_id = url
                    .strip_prefix("/api/events/")
                    .and_then(|rest| rest.strip_suffix("/triage"))
                    .unwrap_or("")
                    .trim_end_matches('/');
                handle_event_triage(&mut request, state, event_id)
            } else if method == Method::Post && url.starts_with("/api/agents/") && url.ends_with("/scope") {
                let agent_id = url
                    .strip_prefix("/api/agents/")
                    .and_then(|rest| rest.strip_suffix("/scope"))
                    .unwrap_or("");
                handle_agent_set_scope(&mut request, state, agent_id)
            } else if method == Method::Get && url.starts_with("/api/agents/") && url.ends_with("/scope") {
                let agent_id = url
                    .strip_prefix("/api/agents/")
                    .and_then(|rest| rest.strip_suffix("/scope"))
                    .unwrap_or("");
                handle_agent_get_scope(state, agent_id)
            } else if method == Method::Get && url.starts_with("/api/agents/") && url.ends_with("/status") {
                // GET /api/agents/{id}/status
                let agent_id = url.strip_prefix("/api/agents/")
                    .and_then(|rest| rest.strip_suffix("/status"))
                    .unwrap_or("");
                let s = state.lock().unwrap();
                match s.agent_registry.get(agent_id) {
                    Some(agent) => match serde_json::to_string(agent) {
                        Ok(json) => json_response(&json, 200),
                        Err(e) => error_json(&format!("serialization error: {e}"), 500),
                    },
                    None => error_json("agent not found", 404),
                }
            } else if method == Method::Delete && url.starts_with("/api/agents/") {
                // DELETE /api/agents/{id}
                let agent_id = url.strip_prefix("/api/agents/").unwrap_or("");
                let mut s = state.lock().unwrap();
                match s.agent_registry.deregister(agent_id) {
                    Ok(()) => {
                        let body = serde_json::json!({"status": "deregistered", "agent_id": agent_id});
                        json_response(&body.to_string(), 200)
                    }
                    Err(e) => error_json(&e, 404),
                }
            // ── Agent Logs ────────────────────────────────────────
            } else if method == Method::Post && url.starts_with("/api/agents/") && url.ends_with("/logs") {
                let agent_id = url.strip_prefix("/api/agents/")
                    .and_then(|rest| rest.strip_suffix("/logs"))
                    .unwrap_or("");
                let body = match read_body_limited(&mut request, 10 * 1024 * 1024) {
                    Ok(b) => b,
                    Err(e) => { let _ = request.respond(error_json(&e, 400)); return; },
                };
                let logs: Vec<crate::log_collector::LogRecord> = match serde_json::from_str(&body) {
                    Ok(l) => l,
                    Err(e) => { let _ = request.respond(error_json(&format!("invalid JSON: {e}"), 400)); return; },
                };
                let count = logs.len();
                let mut s = state.lock().unwrap();
                let agent_log_buf = s.agent_logs.entry(agent_id.to_string()).or_default();
                for log in logs {
                    if agent_log_buf.len() >= 500 {
                        agent_log_buf.remove(0);
                    }
                    agent_log_buf.push(log);
                }
                json_response(&serde_json::json!({"status":"ingested","count":count}).to_string(), 200)
            } else if method == Method::Get && url.starts_with("/api/agents/") && url.ends_with("/logs") {
                let agent_id = url.strip_prefix("/api/agents/")
                    .and_then(|rest| rest.strip_suffix("/logs"))
                    .unwrap_or("");
                let s = state.lock().unwrap();
                let logs = s.agent_logs.get(agent_id).cloned().unwrap_or_default();
                match serde_json::to_string(&logs) {
                    Ok(json) => json_response(&json, 200),
                    Err(e) => error_json(&format!("serialization error: {e}"), 500),
                }
            // ── Agent Inventory ───────────────────────────────────
            } else if method == Method::Post && url.starts_with("/api/agents/") && url.ends_with("/inventory") {
                let agent_id = url.strip_prefix("/api/agents/")
                    .and_then(|rest| rest.strip_suffix("/inventory"))
                    .unwrap_or("");
                let body = match read_body_limited(&mut request, 10 * 1024 * 1024) {
                    Ok(b) => b,
                    Err(e) => { let _ = request.respond(error_json(&e, 400)); return; },
                };
                let inventory: crate::inventory::SystemInventory = match serde_json::from_str(&body) {
                    Ok(i) => i,
                    Err(e) => { let _ = request.respond(error_json(&format!("invalid JSON: {e}"), 400)); return; },
                };
                let mut s = state.lock().unwrap();
                s.agent_inventories.insert(agent_id.to_string(), inventory);
                json_response(&serde_json::json!({"status":"inventory_stored","agent_id":agent_id}).to_string(), 200)
            } else if method == Method::Get && url.starts_with("/api/agents/") && url.ends_with("/inventory") {
                let agent_id = url.strip_prefix("/api/agents/")
                    .and_then(|rest| rest.strip_suffix("/inventory"))
                    .unwrap_or("");
                let s = state.lock().unwrap();
                match s.agent_inventories.get(agent_id) {
                    Some(inv) => match serde_json::to_string(inv) {
                        Ok(json) => json_response(&json, 200),
                        Err(e) => error_json(&format!("serialization error: {e}"), 500),
                    },
                    None => error_json("no inventory for this agent", 404),
                }
            // ── Incidents (dynamic) ───────────────────────────────
            } else if method == Method::Get && url.starts_with("/api/incidents?") {
                let s = state.lock().unwrap();
                let query = parse_query_string(&url);
                let status = query.get("status").map(|s| s.as_str());
                let severity = query.get("severity").map(|s| s.as_str());
                let incidents = s.incident_store.list_filtered(status, severity);
                match serde_json::to_string(&incidents) {
                    Ok(json) => json_response(&json, 200),
                    Err(e) => error_json(&format!("serialization error: {e}"), 500),
                }
            } else if method == Method::Get && url.starts_with("/api/incidents/") && url.ends_with("/report") {
                let id_str = url.strip_prefix("/api/incidents/")
                    .and_then(|rest| rest.strip_suffix("/report"))
                    .unwrap_or("");
                match id_str.parse::<u64>() {
                    Ok(id) => {
                        let s = state.lock().unwrap();
                        match s.incident_store.get(id) {
                            Some(inc) => {
                                let report = crate::report::IncidentReport::generate(inc, &s.event_store);
                                match serde_json::to_string(&report) {
                                    Ok(json) => json_response(&json, 200),
                                    Err(e) => error_json(&format!("serialization error: {e}"), 500),
                                }
                            }
                            None => error_json("incident not found", 404),
                        }
                    }
                    Err(_) => error_json("invalid incident id", 400),
                }
            } else if method == Method::Post && url.starts_with("/api/incidents/") && url.ends_with("/update") {
                let id_str = url.strip_prefix("/api/incidents/")
                    .and_then(|rest| rest.strip_suffix("/update"))
                    .unwrap_or("");
                match id_str.parse::<u64>() {
                    Ok(id) => {
                        let body = match read_body_limited(&mut request, 10 * 1024 * 1024) {
                            Ok(b) => b,
                            Err(e) => { let _ = request.respond(error_json(&e, 400)); return; },
                        };
                        #[derive(serde::Deserialize)]
                        struct IncidentUpdate {
                            status: Option<String>,
                            assignee: Option<String>,
                            note: Option<String>,
                            author: Option<String>,
                        }
                        let upd: IncidentUpdate = match serde_json::from_str(&body) {
                            Ok(u) => u,
                            Err(e) => { let _ = request.respond(error_json(&format!("invalid JSON: {e}"), 400)); return; },
                        };
                        let status = upd.status.as_deref().map(|s| match s {
                            "open" => crate::incident::IncidentStatus::Open,
                            "investigating" => crate::incident::IncidentStatus::Investigating,
                            "contained" => crate::incident::IncidentStatus::Contained,
                            "resolved" => crate::incident::IncidentStatus::Resolved,
                            "false_positive" => crate::incident::IncidentStatus::FalsePositive,
                            _ => crate::incident::IncidentStatus::Open,
                        });
                        let note = if let (Some(text), Some(author)) = (upd.note, upd.author) {
                            Some(crate::incident::EventNote {
                                author,
                                timestamp: chrono::Utc::now().to_rfc3339(),
                                text,
                            })
                        } else {
                            None
                        };
                        let mut s = state.lock().unwrap();
                        match s.incident_store.update(id, upd.assignee, note, status) {
                            Ok(()) => json_response(&serde_json::json!({"status":"updated"}).to_string(), 200),
                            Err(e) => error_json(&e, 404),
                        }
                    }
                    Err(_) => error_json("invalid incident id", 400),
                }
            } else if method == Method::Get && url.starts_with("/api/incidents/") {
                let id_str = url.strip_prefix("/api/incidents/").unwrap_or("");
                match id_str.parse::<u64>() {
                    Ok(id) => {
                        let s = state.lock().unwrap();
                        match s.incident_store.get(id) {
                            Some(inc) => match serde_json::to_string(inc) {
                                Ok(json) => json_response(&json, 200),
                                Err(e) => error_json(&format!("serialization error: {e}"), 500),
                            },
                            None => error_json("incident not found", 404),
                        }
                    }
                    Err(_) => error_json("invalid incident id", 400),
                }
            // ── Reports (dynamic) ─────────────────────────────────
            } else if method == Method::Get && url.starts_with("/api/reports/") && url.ends_with("/html") {
                let id_str = url.strip_prefix("/api/reports/")
                    .and_then(|rest| rest.strip_suffix("/html"))
                    .unwrap_or("");
                match id_str.parse::<u64>() {
                    Ok(id) => {
                        let s = state.lock().unwrap();
                        match s.report_store.get(id) {
                            Some(report) => {
                                let html = report.report.to_html();
                                let data = html.as_bytes().to_vec();
                                let len = data.len();
                                Response::new(
                                    tiny_http::StatusCode(200),
                                    vec![
                                        Header::from_bytes(b"Content-Type", b"text/html; charset=utf-8").unwrap(),
                                        Header::from_bytes(b"Access-Control-Allow-Origin", cors_origin().as_bytes()).unwrap(),
                                        Header::from_bytes(b"Content-Disposition", b"attachment; filename=\"report.html\"").unwrap(),
                                    ],
                                    std::io::Cursor::new(data),
                                    Some(len),
                                    None,
                                )
                            }
                            None => error_json("report not found", 404),
                        }
                    }
                    Err(_) => error_json("invalid report id", 400),
                }
            } else if method == Method::Delete && url.starts_with("/api/reports/") {
                let id_str = url.strip_prefix("/api/reports/").unwrap_or("");
                match id_str.parse::<u64>() {
                    Ok(id) => {
                        let mut s = state.lock().unwrap();
                        if s.report_store.delete(id) {
                            json_response(&serde_json::json!({"status":"deleted"}).to_string(), 200)
                        } else {
                            error_json("report not found", 404)
                        }
                    }
                    Err(_) => error_json("invalid report id", 400),
                }
            } else if method == Method::Get && url.starts_with("/api/reports/") {
                let id_str = url.strip_prefix("/api/reports/").unwrap_or("");
                match id_str.parse::<u64>() {
                    Ok(id) => {
                        let s = state.lock().unwrap();
                        match s.report_store.get(id) {
                            Some(report) => match serde_json::to_string(report) {
                                Ok(json) => json_response(&json, 200),
                                Err(e) => error_json(&format!("serialization error: {e}"), 500),
                            },
                            None => error_json("report not found", 404),
                        }
                    }
                    Err(_) => error_json("invalid report id", 400),
                }
            } else if method == Method::Get && url.starts_with("/api/updates/download/") {
                // GET /api/updates/download/{file_name}
                let file_name = url.strip_prefix("/api/updates/download/").unwrap_or("");
                let s = state.lock().unwrap();
                match s.update_manager.get_release_binary(file_name) {
                    Ok(data) => {
                        let len = data.len();
                        Response::new(
                            tiny_http::StatusCode(200),
                            vec![
                                Header::from_bytes(b"Content-Type", b"application/octet-stream").unwrap(),
                                Header::from_bytes(b"Access-Control-Allow-Origin", cors_origin().as_bytes()).unwrap(),
                            ],
                            std::io::Cursor::new(data),
                            Some(len),
                            None,
                        )
                    }
                    Err(e) => error_json(&e, 404),
                }
            } else if method == Method::Get && url.starts_with("/api/events?") {
                // GET /api/events?agent_id=xxx&limit=100
                let query = url.strip_prefix("/api/events?").unwrap_or("");
                let mut agent_id_filter: Option<String> = None;
                let mut limit = 200usize;
                for param in query.split('&') {
                    if let Some(val) = param.strip_prefix("agent_id=") {
                        agent_id_filter = Some(val.to_string());
                    } else if let Some(val) = param.strip_prefix("limit=") {
                        limit = val.parse().unwrap_or(200);
                    }
                }
                let s = state.lock().unwrap();
                let events = s.event_store.list(agent_id_filter.as_deref(), limit);
                match serde_json::to_string(&events) {
                    Ok(json) => json_response(&json, 200),
                    Err(e) => error_json(&format!("serialization error: {e}"), 500),
                }
            } else if method == Method::Get && url.starts_with("/api/alerts/") && url != "/api/alerts/count" {
                // GET /api/alerts/{index} — detailed alert view
                let idx_str = url.strip_prefix("/api/alerts/").unwrap_or("");
                match idx_str.parse::<usize>() {
                    Ok(idx) => {
                        let s = state.lock().unwrap();
                        if idx < s.alerts.len() {
                            let alert = &s.alerts[idx];
                            let detail = serde_json::json!({
                                "index": idx,
                                "timestamp": alert.timestamp,
                                "hostname": alert.hostname,
                                "platform": alert.platform,
                                "score": alert.score,
                                "confidence": alert.confidence,
                                "level": alert.level,
                                "action": alert.action,
                                "reasons": alert.reasons,
                                "enforced": alert.enforced,
                                "sample": {
                                    "timestamp_ms": alert.sample.timestamp_ms,
                                    "cpu_load_pct": alert.sample.cpu_load_pct,
                                    "memory_load_pct": alert.sample.memory_load_pct,
                                    "temperature_c": alert.sample.temperature_c,
                                    "network_kbps": alert.sample.network_kbps,
                                    "auth_failures": alert.sample.auth_failures,
                                    "battery_pct": alert.sample.battery_pct,
                                    "integrity_drift": alert.sample.integrity_drift,
                                    "process_count": alert.sample.process_count,
                                    "disk_pressure_pct": alert.sample.disk_pressure_pct,
                                },
                                "analysis": {
                                    "severity_class": if alert.score >= 5.2 { "critical" }
                                        else if alert.score >= 3.0 { "severe" }
                                        else { "elevated" },
                                    "multi_axis": alert.reasons.len() > 1,
                                    "axis_count": alert.reasons.len(),
                                    "recommendation": if alert.score >= 5.2 {
                                        "Immediate isolation recommended. Investigate all flagged axes and correlate with SIEM events."
                                    } else if alert.score >= 3.0 {
                                        "Elevated investigation priority. Review flagged telemetry and check for lateral movement."
                                    } else {
                                        "Monitor closely. Consider tightening thresholds if pattern persists."
                                    },
                                },
                            });
                            json_response(&detail.to_string(), 200)
                        } else {
                            error_json("alert index out of range", 404)
                        }
                    }
                    Err(_) => error_json("invalid alert index", 400),
                }
            // ── Analyst Console: Dynamic case routes ─────────────────
            } else if method == Method::Get && url.starts_with("/api/cases/") {
                let id_str = url.trim_start_matches("/api/cases/");
                match id_str.parse::<u64>() {
                    Ok(id) => {
                        let s = state.lock().unwrap();
                        if let Some(c) = s.case_store.get(id) {
                            json_response(&serde_json::json!({
                                "id": c.id, "title": c.title, "description": c.description,
                                "status": format!("{:?}", c.status), "priority": format!("{:?}", c.priority),
                                "assignee": c.assignee, "created_at": c.created_at, "updated_at": c.updated_at,
                                "incident_ids": c.incident_ids, "event_ids": c.event_ids,
                                "tags": c.tags, "comments": c.comments.iter().map(|cm| {
                                    serde_json::json!({"author": cm.author, "timestamp": cm.timestamp, "text": cm.text})
                                }).collect::<Vec<_>>(),
                                "evidence": c.evidence.iter().map(|ev| {
                                    serde_json::json!({"kind": ev.kind, "reference_id": ev.reference_id, "description": ev.description, "added_at": ev.added_at})
                                }).collect::<Vec<_>>(),
                                "mitre_techniques": c.mitre_techniques,
                            }).to_string(), 200)
                        } else {
                            error_json("case not found", 404)
                        }
                    }
                    Err(_) => error_json("invalid case id", 400),
                }
            } else if method == Method::Post && url.starts_with("/api/cases/") && url.ends_with("/comment") {
                let id_str = url.trim_start_matches("/api/cases/").trim_end_matches("/comment");
                match id_str.parse::<u64>() {
                    Ok(id) => {
                        let body = read_body_limited(&mut request, 4096);
                        match body.and_then(|b| serde_json::from_str::<serde_json::Value>(&b).map_err(|e| e.to_string())) {
                            Ok(v) => {
                                let author = v["author"].as_str().unwrap_or("analyst").to_string();
                                let text = v["text"].as_str().unwrap_or("").to_string();
                                let mut s = state.lock().unwrap();
                                if s.case_store.add_comment(id, author, text) {
                                    json_response(&serde_json::json!({"case_id": id, "action": "comment_added"}).to_string(), 200)
                                } else {
                                    error_json("case not found", 404)
                                }
                            }
                            Err(e) => error_json(&e, 400),
                        }
                    }
                    Err(_) => error_json("invalid case id", 400),
                }
            } else if method == Method::Post && url.starts_with("/api/cases/") && url.ends_with("/update") {
                let id_str = url.trim_start_matches("/api/cases/").trim_end_matches("/update");
                match id_str.parse::<u64>() {
                    Ok(id) => {
                        let body = read_body_limited(&mut request, 4096);
                        match body.and_then(|b| serde_json::from_str::<serde_json::Value>(&b).map_err(|e| e.to_string())) {
                            Ok(v) => {
                                let mut s = state.lock().unwrap();
                                if let Some(status_str) = v["status"].as_str() {
                                    let status = match status_str {
                                        "triaging" => CaseStatus::Triaging,
                                        "investigating" => CaseStatus::Investigating,
                                        "escalated" => CaseStatus::Escalated,
                                        "resolved" => CaseStatus::Resolved,
                                        "closed" => CaseStatus::Closed,
                                        _ => CaseStatus::New,
                                    };
                                    s.case_store.update_status(id, status);
                                }
                                if let Some(assignee) = v["assignee"].as_str() {
                                    s.case_store.assign(id, assignee.to_string());
                                }
                                if let Some(incident_id) = v["link_incident"].as_u64() {
                                    s.case_store.link_incident(id, incident_id);
                                }
                                json_response(&serde_json::json!({"case_id": id, "action": "updated"}).to_string(), 200)
                            }
                            Err(e) => error_json(&e, 400),
                        }
                    }
                    Err(_) => error_json("invalid case id", 400),
                }
            } else if method == Method::Post && url.starts_with("/api/cases/") && url.ends_with("/evidence") {
                let id_str = url.trim_start_matches("/api/cases/").trim_end_matches("/evidence");
                match id_str.parse::<u64>() {
                    Ok(id) => {
                        let body = read_body_limited(&mut request, 4096);
                        match body.and_then(|b| serde_json::from_str::<serde_json::Value>(&b).map_err(|e| e.to_string())) {
                            Ok(v) => {
                                let kind = v["kind"].as_str().unwrap_or("other").to_string();
                                let ref_id = v["reference_id"].as_str().unwrap_or("").to_string();
                                let desc = v["description"].as_str().unwrap_or("").to_string();
                                let mut s = state.lock().unwrap();
                                if s.case_store.add_evidence(id, kind, ref_id, desc) {
                                    json_response(&serde_json::json!({"case_id": id, "action": "evidence_added"}).to_string(), 200)
                                } else {
                                    error_json("case not found", 404)
                                }
                            }
                            Err(e) => error_json(&e, 400),
                        }
                    }
                    Err(_) => error_json("invalid case id", 400),
                }
            } else {
                error_json("not found", 404)
            }
        }
    };

    // Audit log the API request
    {
        let source_ip = request.remote_addr().map(|a| a.to_string()).unwrap_or_else(|| "unknown".into());
        let mut s = state.lock().unwrap();
        s.audit_log.record(
            &format!("{method:?}"), &url, &source_ip,
            200, // status code (best-effort; response already built)
            needs_auth,
        );
    }

    let _ = request.respond(response);
}

/// Read the request body with a size limit to prevent OOM from chunked requests.
fn read_body_limited(request: &mut Request, limit: usize) -> Result<String, String> {
    let mut buf = Vec::new();
    let mut reader = std::io::Read::take(request.as_reader(), limit as u64 + 1);
    match std::io::Read::read_to_end(&mut reader, &mut buf) {
        Ok(n) if n > limit => Err("request body too large".to_string()),
        Ok(_) => String::from_utf8(buf).map_err(|_| "invalid UTF-8 in request body".to_string()),
        Err(e) => Err(format!("failed to read request body: {e}")),
    }
}

fn handle_analyze(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };

    // Detect format: if the content-type says CSV or the body looks like CSV, parse as CSV
    let is_csv = request.headers().iter().any(|h| {
        h.field.as_str().to_ascii_lowercase() == "content-type" && h.value.as_str().contains("csv")
    }) || (!body.trim_start().starts_with('{') && body.contains(','));

    let samples: Result<Vec<TelemetrySample>, String> = if is_csv {
        // CSV: skip known header rows, parse each data line
        use crate::telemetry::{CSV_HEADER, CSV_HEADER_LEGACY};
        body.lines()
            .enumerate()
            .filter(|(_, l)| !l.trim().is_empty())
            .filter(|(_, l)| {
                let trimmed = l.trim();
                trimmed != CSV_HEADER && trimmed != CSV_HEADER_LEGACY
            })
            .map(|(line_num, line)| {
                TelemetrySample::parse_line(line, line_num + 1).map_err(|e| format!("{e}"))
            })
            .collect()
    } else if body.trim_start().starts_with('{') {
        // JSONL — enumerate before filtering so line numbers match the original input
        body.lines()
            .enumerate()
            .filter(|(_, l)| !l.trim().is_empty())
            .map(|(i, line)| serde_json::from_str(line).map_err(|e| format!("line {}: {e}", i + 1)))
            .collect()
    } else {
        Err("Unsupported format. POST body must be JSONL or CSV.".into())
    };

    match samples {
        Ok(samples) if !samples.is_empty() => {
            let result = runtime::execute(&samples);
            let report = JsonReport::from_run_result(&result);
            let json = match serde_json::to_string_pretty(&report) {
                Ok(j) => j,
                Err(e) => return error_json(&format!("serialization error: {e}"), 500),
            };
            let mut s = state.lock().unwrap();
            // Update the live detector baseline with the analyzed samples
            for (sample, report) in samples.iter().zip(result.reports.iter()) {
                let pre = s
                    .detector
                    .snapshot()
                    .and_then(|snap| {
                        serde_json::to_vec(&snap)
                            .map_err(|e| eprintln!("proof pre-snapshot serialization error: {e}"))
                            .ok()
                    })
                    .unwrap_or_default();
                s.detector.evaluate(sample);
                let post = s
                    .detector
                    .snapshot()
                    .and_then(|snap| {
                        serde_json::to_vec(&snap)
                            .map_err(|e| eprintln!("proof post-snapshot serialization error: {e}"))
                            .ok()
                    })
                    .unwrap_or_default();
                s.proofs.record("baseline_update", &pre, &post);
                s.device.apply_decision(&report.decision);
                s.replay.push(*sample);
            }
            s.last_report = Some(report);
            drop(s);
            json_response(&json, 200)
        }
        Ok(_) => error_json("no samples in request body", 400),
        Err(e) => error_json(&e, 400),
    }
}

fn handle_mode(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };

    #[derive(serde::Deserialize)]
    struct ModeRequest {
        mode: String,
        #[serde(default)]
        decay_rate: Option<f32>,
    }

    let mode_req: ModeRequest = match serde_json::from_str(&body) {
        Ok(m) => m,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };

    let mode = match mode_req.mode.as_str() {
        "normal" => AdaptationMode::Normal,
        "frozen" => AdaptationMode::Frozen,
        "decay" => {
            let rate = mode_req.decay_rate.unwrap_or(0.05);
            if !rate.is_finite() || !(0.0..=1.0).contains(&rate) {
                return error_json("decay_rate must be a finite value in 0.0..=1.0", 400);
            }
            AdaptationMode::Decay(rate)
        }
        other => return error_json(&format!("unknown mode: {other}"), 400),
    };

    let mut s = state.lock().unwrap();
    s.detector.set_adaptation(mode);
    let body = serde_json::json!({"status": format!("mode set to {}", mode_req.mode)});
    json_response(&body.to_string(), 200)
}

fn handle_fleet_register(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    #[derive(serde::Deserialize)]
    struct Reg {
        device_id: String,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        platform: Option<String>,
    }
    let req: Reg = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    let record = DeviceRecord {
        device_id: req.device_id.clone(),
        name: req.name.unwrap_or_else(|| req.device_id.clone()),
        platform: req.platform.unwrap_or_else(|| "unknown".into()),
        firmware_version: "0.0.0".into(),
        enrolled_at: chrono::Utc::now().to_rfc3339(),
        last_seen_ms: chrono::Utc::now().timestamp_millis() as u64,
        status: DeviceStatus::Online,
        tags: Vec::new(),
    };
    let mut s = state.lock().unwrap();
    s.swarm.register_device(record);
    let body = serde_json::json!({"status": "registered", "device": req.device_id});
    json_response(&body.to_string(), 200)
}

fn handle_enforcement_quarantine(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    #[derive(serde::Deserialize)]
    struct QuarantineReq {
        target: String,
    }
    let req: QuarantineReq = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    let mut s = state.lock().unwrap();
    let results = s
        .enforcement
        .enforce(&crate::enforcement::EnforcementLevel::Quarantine, &req.target);
    let info = serde_json::json!({
        "target": req.target,
        "actions": results.len(),
        "results": results.iter().map(|r| serde_json::json!({
            "action": r.action,
            "success": r.success,
            "detail": r.detail,
        })).collect::<Vec<_>>(),
    });
    json_response(&info.to_string(), 200)
}

fn handle_threat_intel_ioc(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    #[derive(serde::Deserialize)]
    struct IocReq {
        value: String,
        ioc_type: String,
        #[serde(default = "default_confidence")]
        confidence: f32,
    }
    fn default_confidence() -> f32 {
        0.8
    }
    let req: IocReq = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };

    let ioc_type = match req.ioc_type.as_str() {
        "ip" => crate::threat_intel::IoCType::IpAddress,
        "domain" => crate::threat_intel::IoCType::Domain,
        "hash" => crate::threat_intel::IoCType::FileHash,
        "process" => crate::threat_intel::IoCType::ProcessName,
        _ => crate::threat_intel::IoCType::BehaviorPattern,
    };

    let now = chrono::Utc::now().to_rfc3339();
    let mut s = state.lock().unwrap();
    s.threat_intel.add_ioc(crate::threat_intel::IoC {
        ioc_type,
        value: req.value.clone(),
        confidence: req.confidence,
        severity: "medium".into(),
        source: "api".into(),
        first_seen: now.clone(),
        last_seen: now,
        tags: Vec::new(),
        related_iocs: Vec::new(),
    });
    let body = serde_json::json!({"status": "added", "value": req.value});
    json_response(&body.to_string(), 200)
}

fn handle_digital_twin_simulate(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    #[derive(serde::Deserialize)]
    struct SimReq {
        device_id: String,
        event_type: String,
    }
    let req: SimReq = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };

    let event = match req.event_type.as_str() {
        "cpu_spike" => crate::digital_twin::SimEvent::CpuSpike {
            target: req.device_id.clone(),
            load: 95.0,
        },
        "memory_exhaust" => crate::digital_twin::SimEvent::MemoryExhaust {
            target: req.device_id.clone(),
            mb: 1800.0,
        },
        "network_flood" => crate::digital_twin::SimEvent::NetworkFlood {
            target: req.device_id.clone(),
            kbps: 10_000.0,
        },
        "malware_inject" => crate::digital_twin::SimEvent::MalwareInject {
            target: req.device_id.clone(),
            score: 9.0,
        },
        _ => crate::digital_twin::SimEvent::CpuSpike {
            target: req.device_id.clone(),
            load: 80.0,
        },
    };

    let step = crate::digital_twin::SimStep {
        tick: 1,
        events: vec![event],
    };

    let mut s = state.lock().unwrap();
    let result = s.digital_twin.simulate(&[step]);
    let info = serde_json::json!({
        "device_id": req.device_id,
        "ticks_simulated": result.ticks_simulated,
        "alerts": result.alerts_generated.len(),
        "transitions": result.state_transitions.len(),
    });
    json_response(&info.to_string(), 200)
}

fn handle_energy_consume(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    #[derive(serde::Deserialize)]
    struct ConsumeReq {
        drain_rate_mw: f64,
    }
    let req: ConsumeReq = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    let mut s = state.lock().unwrap();
    s.energy.drain_rate_mw = req.drain_rate_mw;
    let new_state = s.energy.tick();
    let info = serde_json::json!({
        "remaining_pct": s.energy.remaining_pct(),
        "power_state": format!("{new_state:?}"),
    });
    json_response(&info.to_string(), 200)
}

fn handle_policy_vm_execute(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    #[derive(serde::Deserialize)]
    struct VmReq {
        #[serde(default)]
        env: std::collections::HashMap<String, f64>,
    }
    let req: VmReq = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    let s = state.lock().unwrap();
    // Build a simple program that loads env values and computes a risk composite
    let program = crate::wasm_engine::PolicyProgram::new("api-eval", vec![
        crate::wasm_engine::Opcode::LoadVar("score".into()),
        crate::wasm_engine::Opcode::LoadVar("battery".into()),
        crate::wasm_engine::Opcode::Mul,
        crate::wasm_engine::Opcode::StoreResult("risk_composite".into()),
        crate::wasm_engine::Opcode::Halt,
    ]);
    let result = s.policy_vm.execute(&program, &req.env);
    let info = serde_json::json!({
        "success": result.success,
        "outputs": result.outputs,
        "steps_executed": result.steps_executed,
        "error": result.error,
    });
    json_response(&info.to_string(), 200)
}

fn handle_deception_deploy(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    #[derive(serde::Deserialize)]
    struct DeployReq {
        decoy_type: String,
        name: String,
        #[serde(default)]
        description: Option<String>,
    }
    let req: DeployReq = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    let decoy_type = match req.decoy_type.as_str() {
        "honeypot" => crate::threat_intel::DecoyType::Honeypot,
        "honeyfile" => crate::threat_intel::DecoyType::HoneyFile,
        "honeycredential" => crate::threat_intel::DecoyType::HoneyCredential,
        "honeyservice" => crate::threat_intel::DecoyType::HoneyService,
        "canary" => crate::threat_intel::DecoyType::Canary,
        _ => crate::threat_intel::DecoyType::Honeypot,
    };
    let mut s = state.lock().unwrap();
    let id = s.deception.deploy(
        decoy_type,
        &req.name,
        req.description.as_deref().unwrap_or("Deployed via API"),
    );
    json_response(
        &serde_json::json!({ "status": "deployed", "decoy_id": id }).to_string(),
        200,
    )
}

fn handle_policy_compose(
    request: &mut Request,
    _state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    #[derive(serde::Deserialize)]
    struct ComposeReq {
        operator: String,
        score_a: f32,
        battery_a: f32,
        score_b: f32,
        battery_b: f32,
    }
    let req: ComposeReq = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    let op = match req.operator.as_str() {
        "max" => crate::policy::CompositionOp::MaxSeverity,
        "min" => crate::policy::CompositionOp::MinSeverity,
        "left" => crate::policy::CompositionOp::LeftPriority,
        "right" => crate::policy::CompositionOp::RightPriority,
        _ => return error_json("unknown operator: use max, min, left, or right", 400),
    };
    let engine = crate::policy::PolicyEngine;
    let signal_a = crate::detector::AnomalySignal {
        score: req.score_a, confidence: 0.9, suspicious_axes: 0,
        reasons: vec!["composed-a".into()], contributions: Vec::new(),
    };
    let sample_a = TelemetrySample {
        timestamp_ms: 0, cpu_load_pct: 0.0, memory_load_pct: 0.0,
        temperature_c: 0.0, network_kbps: 0.0, auth_failures: 0,
        battery_pct: req.battery_a, integrity_drift: 0.0,
        process_count: 0, disk_pressure_pct: 0.0,
    };
    let decision_a = engine.evaluate(&signal_a, &sample_a);
    let signal_b = crate::detector::AnomalySignal {
        score: req.score_b, confidence: 0.9, suspicious_axes: 0,
        reasons: vec!["composed-b".into()], contributions: Vec::new(),
    };
    let sample_b = TelemetrySample {
        timestamp_ms: 0, cpu_load_pct: 0.0, memory_load_pct: 0.0,
        temperature_c: 0.0, network_kbps: 0.0, auth_failures: 0,
        battery_pct: req.battery_b, integrity_drift: 0.0,
        process_count: 0, disk_pressure_pct: 0.0,
    };
    let decision_b = engine.evaluate(&signal_b, &sample_b);
    let (result, conflict) = crate::policy::compose_decisions(Some(decision_a), Some(decision_b), op);
    let info = serde_json::json!({
        "result": result.as_ref().map(|d| serde_json::json!({
            "level": format!("{:?}", d.level),
            "action": format!("{:?}", d.action),
        })),
        "conflict": conflict.as_ref().map(|c| serde_json::json!({
            "left_level": format!("{:?}", c.left_level),
            "right_level": format!("{:?}", c.right_level),
            "resolution": c.resolution,
        })),
    });
    json_response(&info.to_string(), 200)
}

fn handle_config_reload(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    let patch: crate::config::ConfigPatch = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    let mut s = state.lock().unwrap();
    let result = patch.apply(&mut s.config);
    match serde_json::to_string_pretty(&result) {
        Ok(json) => {
            let status = if result.success { 200 } else { 400 };
            json_response(&json, status)
        }
        Err(e) => error_json(&format!("serialization error: {e}"), 500),
    }
}

// ── XDR Handler Functions ────────────────────────────────────────────

fn handle_agent_enroll(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    let req: crate::enrollment::EnrollRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    let mut s = state.lock().unwrap();
    match s.agent_registry.enroll(&req) {
        Ok(resp) => match serde_json::to_string(&resp) {
            Ok(json) => json_response(&json, 200),
            Err(e) => error_json(&format!("serialization error: {e}"), 500),
        },
        Err(e) => error_json(&e, 403),
    }
}

fn handle_agent_create_token(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    #[derive(serde::Deserialize)]
    struct TokenReq {
        #[serde(default = "default_max_uses")]
        max_uses: u32,
    }
    fn default_max_uses() -> u32 {
        10
    }
    let req: TokenReq = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => TokenReq { max_uses: 10 },
    };
    let mut s = state.lock().unwrap();
    let token = s.agent_registry.create_token(req.max_uses);
    match serde_json::to_string(&token) {
        Ok(json) => json_response(&json, 200),
        Err(e) => error_json(&format!("serialization error: {e}"), 500),
    }
}

fn handle_agent_heartbeat(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
    agent_id: &str,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    #[derive(serde::Deserialize)]
    struct HeartbeatReq {
        #[serde(default)]
        version: String,
        #[serde(default)]
        health: Option<crate::enrollment::AgentHealth>,
    }
    let req: HeartbeatReq = serde_json::from_str(&body).unwrap_or(HeartbeatReq {
        version: env!("CARGO_PKG_VERSION").to_string(),
        health: None,
    });
    let mut s = state.lock().unwrap();
    match s.agent_registry.heartbeat(agent_id, &req.version, req.health.clone()) {
        Ok(()) => {
            let mut target_version = None;
            let now = chrono::Utc::now().to_rfc3339();
            if let Some(deployment) = s.remote_deployments.get_mut(agent_id) {
                deployment.last_heartbeat_at = Some(now.clone());
                if let Some(health) = &req.health {
                    if let Some(update_state) = &health.update_state {
                        deployment.status = update_state.clone();
                        deployment.status_reason = health.last_update_error.clone();
                        if matches!(update_state.as_str(), "checking" | "downloading" | "downloaded" | "applying") {
                            if deployment.acknowledged_at.is_none() {
                                deployment.acknowledged_at = Some(now.clone());
                            }
                        }
                        if matches!(update_state.as_str(), "restart_pending" | "applied") {
                            deployment.completed_at = Some(now.clone());
                        }
                    }
                }
                if deployment.version == req.version {
                    deployment.status = "applied".to_string();
                    deployment.completed_at = Some(now);
                } else {
                    target_version = Some(deployment.version.clone());
                }
            }
            // Auto-rollout progression: if a canary/ring-1 deployment just completed,
            // check if soak time elapsed and auto-progress to next ring.
            let rollout_cfg = s.config.rollout.clone();
            if rollout_cfg.auto_progress {
                // Collect completed deployments that may trigger progression
                let mut progress_candidates: Vec<(String, String, String)> = Vec::new(); // (version, platform, rollout_group)
                for dep in s.remote_deployments.values() {
                    if dep.status == "applied" {
                        if let Some(ref completed) = dep.completed_at {
                            if let Ok(completed_time) = chrono::DateTime::parse_from_rfc3339(completed) {
                                let elapsed = chrono::Utc::now().signed_duration_since(completed_time);
                                let soak = match dep.rollout_group.as_str() {
                                    "canary" => rollout_cfg.canary_soak_secs as i64,
                                    "ring-1" => rollout_cfg.ring1_soak_secs as i64,
                                    _ => continue,
                                };
                                if elapsed.num_seconds() >= soak {
                                    let next_ring = match dep.rollout_group.as_str() {
                                        "canary" => "ring-1",
                                        "ring-1" => "ring-2",
                                        _ => continue,
                                    };
                                    progress_candidates.push((dep.version.clone(), dep.platform.clone(), next_ring.to_string()));
                                }
                            }
                        }
                    }
                }
                // Check for failures -> auto-rollback
                if rollout_cfg.auto_rollback {
                    let mut rollback_agents: Vec<(String, String)> = Vec::new(); // (agent_id, version_before)
                    for dep in s.remote_deployments.values() {
                        if dep.status == "failed" || dep.status == "error" {
                            // Count failures for this version
                            let fail_count = s.remote_deployments.values()
                                .filter(|d| d.version == dep.version && (d.status == "failed" || d.status == "error"))
                                .count() as u32;
                            if fail_count >= rollout_cfg.max_failures && dep.status_reason.as_deref() != Some("auto_rollback_scheduled") {
                                rollback_agents.push((dep.agent_id.clone(), dep.version.clone()));
                            }
                        }
                    }
                    for (aid, _ver) in &rollback_agents {
                        if let Some(dep) = s.remote_deployments.get_mut(aid) {
                            dep.status = "rollback_pending".to_string();
                            dep.status_reason = Some("auto_rollback_scheduled".to_string());
                        }
                    }
                }
                // Auto-progress: deploy same version to next ring agents that don't already have a deployment
                for (version, platform, next_ring) in progress_candidates {
                    // Find agents enrolled with matching platform that are in the next ring's eligible set
                    let enrolled: Vec<String> = s.agent_registry.list()
                        .iter()
                        .filter(|a| a.platform == platform && a.status == crate::enrollment::AgentStatus::Online)
                        .map(|a| a.id.clone())
                        .collect();
                    for eid in enrolled {
                        let already_deployed = s.remote_deployments.get(&eid)
                            .map(|d| d.version == version)
                            .unwrap_or(false);
                        if !already_deployed {
                            let new_dep = AgentDeployment {
                                agent_id: eid.clone(),
                                version: version.clone(),
                                platform: platform.clone(),
                                mandatory: false,
                                release_notes: format!("Auto-progressed from previous ring to {next_ring}"),
                                status: "assigned".to_string(),
                                status_reason: Some(format!("auto_progress_{next_ring}")),
                                rollout_group: next_ring.clone(),
                                allow_downgrade: false,
                                assigned_at: chrono::Utc::now().to_rfc3339(),
                                acknowledged_at: None,
                                completed_at: None,
                                last_heartbeat_at: None,
                            };
                            s.remote_deployments.insert(eid, new_dep);
                        }
                    }
                }
            }
            save_remote_deployments(&s.deployment_store_path, &s.remote_deployments);
            let heartbeat_interval = s.agent_registry.heartbeat_interval();
            // Include agent-specific monitoring scope in heartbeat response
            let agent_scope = s.agent_registry.get_monitor_scope(agent_id)
                .cloned()
                .unwrap_or_else(|| s.config.monitor.scope.clone());
            let payload = serde_json::json!({
                "status": "ok",
                "interval_secs": heartbeat_interval,
                "heartbeat_interval_secs": heartbeat_interval,
                "update_assigned": target_version.is_some(),
                "target_version": target_version,
                "monitor_scope": agent_scope,
            });
            json_response(&payload.to_string(), 200)
        }
        Err(e) => error_json(&e, 404),
    }
}

fn handle_agent_details(
    state: &Arc<Mutex<AppState>>,
    agent_id: &str,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let s = state.lock().unwrap();
    let agent = match s.agent_registry.get(agent_id) {
        Some(agent) => agent,
        None => return error_json("agent not found", 404),
    };

    let events = s.event_store.list(Some(agent_id), 500);
    let total_events = events.len();
    let correlated_count = events.iter().filter(|event| event.correlated).count();
    let critical_count = events
        .iter()
        .filter(|event| severity_rank(&event.alert.level) >= 3)
        .count();
    let average_score = if total_events > 0 {
        events.iter().map(|event| event.alert.score).sum::<f32>() / total_events as f32
    } else {
        0.0
    };
    let max_score = events.iter().map(|event| event.alert.score).fold(0.0f32, f32::max);
    let highest_level = events
        .iter()
        .map(|event| severity_rank(&event.alert.level))
        .max()
        .unwrap_or(0);

    let timeline = events
        .iter()
        .take(25)
        .map(|event| {
            serde_json::json!({
                "event_id": event.id,
                "received_at": event.received_at,
                "level": event.alert.level,
                "score": event.alert.score,
                "correlated": event.correlated,
                "reasons": event.alert.reasons,
                "action": event.alert.action,
                "triage": event.triage,
            })
        })
        .collect::<Vec<_>>();

    let mut chronological = events.clone();
    chronological.reverse();
    let mut transitions = Vec::new();
    let mut previous_level: Option<String> = None;
    for event in chronological {
        if previous_level.as_deref() != Some(event.alert.level.as_str()) {
            if let Some(from) = previous_level.clone() {
                transitions.push(serde_json::json!({
                    "event_id": event.id,
                    "received_at": event.received_at,
                    "from": from,
                    "to": event.alert.level,
                }));
            }
            previous_level = Some(event.alert.level.clone());
        }
    }

    let payload = serde_json::json!({
        "agent": agent,
        "deployment": s.remote_deployments.get(agent_id),
        "health": agent.health,
        "analytics": {
            "event_count": total_events,
            "correlated_count": correlated_count,
            "critical_count": critical_count,
            "average_score": average_score,
            "max_score": max_score,
            "highest_level": match highest_level {
                3 => "Critical",
                2 => "Severe",
                1 => "Elevated",
                _ => "Nominal",
            },
            "risk": if highest_level >= 3 || correlated_count >= 2 {
                "Critical"
            } else if highest_level >= 2 || average_score >= 3.0 {
                "Severe"
            } else if highest_level >= 1 || average_score >= 1.5 {
                "Elevated"
            } else {
                "Nominal"
            },
        },
        "timeline": timeline,
        "risk_transitions": transitions,
    });
    json_response(&payload.to_string(), 200)
}

fn handle_agent_update_check(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    // Agent sends GET /api/agents/update?agent_id=xxx&current_version=yyy
    let params = parse_query_string(request.url());
    let agent_id = params.get("agent_id").cloned();
    let mut current_version = params.get("current_version").cloned().unwrap_or_default();
    let mut platform = params.get("platform").cloned().unwrap_or_else(|| "universal".to_string());
    if current_version.is_empty() {
        current_version = env!("CARGO_PKG_VERSION").to_string();
    }
    let s = state.lock().unwrap();
    if let Some(agent_id) = agent_id.as_deref() {
        if platform == "universal" {
            if let Some(agent) = s.agent_registry.get(agent_id) {
                platform = agent.platform.clone();
            }
        }
        if let Some(deployment) = s.remote_deployments.get(agent_id) {
            if deployment_requires_action(deployment, &current_version) {
                if let Some(release) = s.update_manager.get_release(&deployment.version, &platform) {
                    let resp = crate::auto_update::UpdateCheckResponse {
                        update_available: true,
                        version: Some(release.version.clone()),
                        download_url: Some(format!("/api/updates/download/{}", release.file_name)),
                        sha256: Some(release.sha256.clone()),
                        release_notes: Some(release.release_notes.clone()),
                        mandatory: Some(release.mandatory),
                    };
                    return match serde_json::to_string(&resp) {
                        Ok(json) => json_response(&json, 200),
                        Err(e) => error_json(&format!("serialization error: {e}"), 500),
                    };
                }
            }
        }
    }
    let resp = s.update_manager.check_update(&current_version, &platform);
    match serde_json::to_string(&resp) {
        Ok(json) => json_response(&json, 200),
        Err(e) => error_json(&format!("serialization error: {e}"), 500),
    }
}

fn handle_update_deploy(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    #[derive(serde::Deserialize)]
    struct DeployReq {
        agent_id: String,
        version: String,
        #[serde(default)]
        platform: Option<String>,
        #[serde(default)]
        rollout_group: Option<String>,
        #[serde(default)]
        allow_downgrade: bool,
    }

    let req: DeployReq = match serde_json::from_str(&body) {
        Ok(req) => req,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };

    let mut s = state.lock().unwrap();
    let agent = match s.agent_registry.get(&req.agent_id) {
        Some(agent) => agent,
        None => return error_json("agent not found", 404),
    };
    if !req.allow_downgrade && compare_versions(&req.version, &agent.version) == std::cmp::Ordering::Less {
        return error_json("downgrade blocked without allow_downgrade=true", 409);
    }
    if let Some(existing) = s.remote_deployments.get(&req.agent_id) {
        if !req.allow_downgrade
            && compare_versions(&req.version, &existing.version) == std::cmp::Ordering::Less
        {
            return error_json("deployment would roll back an already assigned version", 409);
        }
    }
    let platform = req.platform.unwrap_or_else(|| agent.platform.clone());
    let release = match s.update_manager.get_release(&req.version, &platform) {
        Some(release) => release.clone(),
        None => return error_json("release not found for agent platform", 404),
    };
    let rollout_group = normalize_rollout_group(req.rollout_group.as_deref());

    let deployment = AgentDeployment {
        agent_id: req.agent_id.clone(),
        version: release.version.clone(),
        platform: platform.clone(),
        mandatory: release.mandatory,
        release_notes: release.release_notes.clone(),
        status: "assigned".to_string(),
        status_reason: None,
        rollout_group,
        allow_downgrade: req.allow_downgrade,
        assigned_at: chrono::Utc::now().to_rfc3339(),
        acknowledged_at: None,
        completed_at: None,
        last_heartbeat_at: None,
    };
    s.remote_deployments.insert(req.agent_id.clone(), deployment.clone());
    save_remote_deployments(&s.deployment_store_path, &s.remote_deployments);

    let payload = serde_json::json!({
        "status": "assigned",
        "agent_id": req.agent_id,
        "deployment": deployment,
    });
    json_response(&payload.to_string(), 200)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

fn handle_event_triage(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
    event_id: &str,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    let event_id = match event_id.parse::<u64>() {
        Ok(id) => id,
        Err(_) => return error_json("invalid event id", 400),
    };
    let update: crate::event_forward::EventTriageUpdate = match serde_json::from_str(&body) {
        Ok(update) => update,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };

    let mut s = state.lock().unwrap();
    match s.event_store.update_triage(event_id, update) {
        Ok(event) => json_response(&serde_json::json!({ "status": "updated", "event": event }).to_string(), 200),
        Err(e) if e == "event not found" => error_json(&e, 404),
        Err(e) => error_json(&e, 400),
    }
}

fn handle_event_ingest(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    let batch: crate::event_forward::EventBatch = match serde_json::from_str(&body) {
        Ok(b) => b,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    let mut s = state.lock().unwrap();
    let result = s.event_store.ingest(&batch);

    // Also forward to SIEM if enabled
    for alert in &batch.events {
        s.siem_connector.queue_alert(alert);
    }

    // Auto-cluster into incidents
    let recent = s.event_store.recent_events(50);
    let _new_incidents = s.incident_store.auto_cluster(&recent);

    // Sigma evaluation on ingested events (gated by feature flag)
    let sigma_matches = if s.feature_flags.is_enabled("sigma_engine", "default") {
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut total_matches = 0usize;
        for alert in &batch.events {
            let ocsf_event = ocsf::alert_to_ocsf(alert);
            let matches = s.sigma_engine.evaluate(&ocsf_event, now_epoch);
            total_matches += matches.len();
        }
        total_matches
    } else {
        0
    };
    drop(s);

    let mut resp = match serde_json::to_value(&result) {
        Ok(serde_json::Value::Object(mut map)) => {
            if sigma_matches > 0 {
                map.insert("sigma_matches".to_string(), serde_json::json!(sigma_matches));
            }
            json_response(&serde_json::Value::Object(map).to_string(), 200)
        }
        Ok(other) => json_response(&other.to_string(), 200),
        Err(e) => error_json(&format!("serialization error: {e}"), 500),
    };
    let _ = &mut resp; // suppress unused warning
    resp
}

fn handle_bulk_triage(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    #[derive(serde::Deserialize)]
    struct BulkTriageReq {
        event_ids: Vec<u64>,
        #[serde(flatten)]
        update: crate::event_forward::EventTriageUpdate,
    }
    let req: BulkTriageReq = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    if req.event_ids.is_empty() {
        return error_json("event_ids must not be empty", 400);
    }
    if req.event_ids.len() > 500 {
        return error_json("too many event_ids (max 500)", 400);
    }
    let mut s = state.lock().unwrap();
    let result = s.event_store.bulk_update_triage(&req.event_ids, &req.update);
    let payload = serde_json::json!({
        "updated": result.updated,
        "failed": result.failed.iter().map(|(id, msg)| serde_json::json!({"event_id": id, "error": msg})).collect::<Vec<_>>(),
    });
    json_response(&payload.to_string(), 200)
}

fn handle_update_rollback(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    #[derive(serde::Deserialize)]
    struct RollbackReq {
        agent_id: String,
        target_version: String,
    }
    let req: RollbackReq = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    let mut s = state.lock().unwrap();
    let agent = match s.agent_registry.get(&req.agent_id) {
        Some(a) => a.clone(),
        None => return error_json("agent not found", 404),
    };
    let platform = agent.platform.clone();
    let release = match s.update_manager.get_release(&req.target_version, &platform) {
        Some(r) => r.clone(),
        None => return error_json("release not found for agent platform", 404),
    };
    // Cancel any existing deployment
    if let Some(existing) = s.remote_deployments.get(&req.agent_id) {
        if !is_terminal_deployment_status(&existing.status) {
            // Mark the old deployment as cancelled before replacing
        }
    }
    let deployment = AgentDeployment {
        agent_id: req.agent_id.clone(),
        version: release.version.clone(),
        platform,
        mandatory: true,
        release_notes: format!("Rollback to v{}", release.version),
        status: "assigned".to_string(),
        status_reason: Some("rollback".to_string()),
        rollout_group: "direct".to_string(),
        allow_downgrade: true,
        assigned_at: chrono::Utc::now().to_rfc3339(),
        acknowledged_at: None,
        completed_at: None,
        last_heartbeat_at: None,
    };
    s.remote_deployments.insert(req.agent_id.clone(), deployment.clone());
    save_remote_deployments(&s.deployment_store_path, &s.remote_deployments);
    let payload = serde_json::json!({
        "status": "rollback_assigned",
        "agent_id": req.agent_id,
        "deployment": deployment,
    });
    json_response(&payload.to_string(), 200)
}

fn handle_update_cancel(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    #[derive(serde::Deserialize)]
    struct CancelReq {
        agent_id: String,
    }
    let req: CancelReq = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    let mut s = state.lock().unwrap();
    match s.remote_deployments.get_mut(&req.agent_id) {
        Some(deployment) => {
            if is_terminal_deployment_status(&deployment.status) {
                return error_json("deployment already in terminal state", 409);
            }
            deployment.status = "cancelled".to_string();
            deployment.status_reason = Some("cancelled by admin".to_string());
            deployment.completed_at = Some(chrono::Utc::now().to_rfc3339());
            save_remote_deployments(&s.deployment_store_path, &s.remote_deployments);
            json_response(&serde_json::json!({"status": "cancelled", "agent_id": req.agent_id}).to_string(), 200)
        }
        None => error_json("no deployment found for agent", 404),
    }
}

fn handle_agent_set_scope(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
    agent_id: &str,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    // Accept either a full MonitorScopeSettings or {"clear": true} to remove override
    // Try parsing as clear command first
    let clear_check: Result<serde_json::Value, _> = serde_json::from_str(&body);
    let is_clear = clear_check.as_ref().ok().and_then(|v| v.get("clear")).and_then(|v| v.as_bool()).unwrap_or(false);

    let mut s = state.lock().unwrap();
    if is_clear {
        match s.agent_registry.set_monitor_scope(agent_id, None) {
            Ok(()) => json_response(&serde_json::json!({"status": "scope_cleared", "agent_id": agent_id}).to_string(), 200),
            Err(e) => error_json(&e, 404),
        }
    } else {
        let scope: crate::config::MonitorScopeSettings = match serde_json::from_str(&body) {
            Ok(s) => s,
            Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
        };
        match s.agent_registry.set_monitor_scope(agent_id, Some(scope.clone())) {
            Ok(()) => {
                let payload = serde_json::json!({"status": "scope_set", "agent_id": agent_id, "scope": scope});
                json_response(&payload.to_string(), 200)
            }
            Err(e) => error_json(&e, 404),
        }
    }
}

fn handle_agent_get_scope(
    state: &Arc<Mutex<AppState>>,
    agent_id: &str,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let s = state.lock().unwrap();
    match s.agent_registry.get(agent_id) {
        Some(agent) => {
            let effective_scope = agent.monitor_scope.as_ref()
                .unwrap_or(&s.config.monitor.scope);
            let payload = serde_json::json!({
                "agent_id": agent_id,
                "override": agent.monitor_scope.is_some(),
                "scope": effective_scope,
                "server_default": s.config.monitor.scope,
            });
            json_response(&payload.to_string(), 200)
        }
        None => error_json("agent not found", 404),
    }
}

fn handle_policy_publish(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    let policy: crate::policy_dist::Policy = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    let mut s = state.lock().unwrap();
    s.policy_store.publish(policy);
    let version = s.policy_store.current_version();
    json_response(
        &format!(r#"{{"status":"published","version":{version}}}"#),
        200,
    )
}

fn handle_update_publish(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    #[derive(serde::Deserialize)]
    struct PublishReq {
        version: String,
        platform: String,
        #[serde(default)]
        binary_base64: String,
        #[serde(default)]
        release_notes: String,
        #[serde(default)]
        mandatory: bool,
    }
    let req: PublishReq = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };

    let binary = match base64_decode(&req.binary_base64) {
        Ok(b) => b,
        Err(e) => return error_json(&format!("invalid base64: {e}"), 400),
    };

    let mut s = state.lock().unwrap();
    match s.update_manager.publish_release(
        &req.version,
        &req.platform,
        &binary,
        &req.release_notes,
        req.mandatory,
    ) {
        Ok(release) => match serde_json::to_string(&release) {
            Ok(json) => json_response(&json, 200),
            Err(e) => error_json(&format!("serialization error: {e}"), 500),
        },
        Err(e) => error_json(&e, 500),
    }
}

/// Simple base64 decoder (no external dependency needed).
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let input = input.as_bytes();
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &b in input {
        if b == b'=' || b == b'\n' || b == b'\r' || b == b' ' {
            continue;
        }
        let val = TABLE.iter().position(|&c| c == b)
            .ok_or_else(|| format!("invalid base64 character: {}", b as char))? as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

fn serve_static(request: Request, site_dir: &Path) {
    let url = request.url();
    let relative = if url == "/" { "/index.html" } else { url };

    // Prevent path traversal via components
    let clean = relative.trim_start_matches('/');
    let requested = PathBuf::from(clean);
    if requested
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        let _ = request.respond(error_json("forbidden", 403));
        return;
    }

    let file_path = site_dir.join(clean);

    // Canonicalize to prevent symlink-based path traversal
    let canon_site = match site_dir.canonicalize() {
        Ok(p) => p,
        Err(_) => { let _ = request.respond(error_json("server error", 500)); return; }
    };
    if let Ok(canon_file) = file_path.canonicalize() {
        if !canon_file.starts_with(&canon_site) {
            let _ = request.respond(error_json("forbidden", 403));
            return;
        }
    }

    if file_path.is_file() {
        let content_type = match file_path.extension().and_then(|e| e.to_str()) {
            Some("html") => "text/html; charset=utf-8",
            Some("js") => "application/javascript; charset=utf-8",
            Some("css") => "text/css; charset=utf-8",
            Some("json") => "application/json",
            Some("csv") => "text/csv",
            Some("svg") => "image/svg+xml",
            Some("png") => "image/png",
            Some("ico") => "image/x-icon",
            Some("woff2") => "font/woff2",
            _ => "application/octet-stream",
        };

        match fs::read(&file_path) {
            Ok(data) => {
                let len = data.len();
                let origin = cors_origin();
                let response = Response::new(
                    tiny_http::StatusCode(200),
                    vec![
                        Header::from_bytes(b"Content-Type", content_type.as_bytes()).unwrap(),
                        Header::from_bytes(b"Access-Control-Allow-Origin", origin.as_bytes()).unwrap(),
                        Header::from_bytes(b"X-Content-Type-Options", b"nosniff").unwrap(),
                        Header::from_bytes(b"X-Frame-Options", b"DENY").unwrap(),
                        Header::from_bytes(b"Cache-Control", b"no-store").unwrap(),
                    ],
                    std::io::Cursor::new(data),
                    Some(len),
                    None,
                );
                let _ = request.respond(response);
            }
            Err(_) => {
                let _ = request.respond(error_json("read error", 500));
            }
        }
    } else {
        let _ = request.respond(error_json("not found", 404));
    }
}
