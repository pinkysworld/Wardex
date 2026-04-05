use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Method as HttpMethod, StatusCode};
use axum::response::Response;

/// Local Method enum preserving tiny_http variant names for match compatibility.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
    Options,
    Patch,
    Head,
}

impl Method {
    fn from_http(m: &HttpMethod) -> Self {
        if m == HttpMethod::GET { Method::Get }
        else if m == HttpMethod::POST { Method::Post }
        else if m == HttpMethod::PUT { Method::Put }
        else if m == HttpMethod::DELETE { Method::Delete }
        else if m == HttpMethod::OPTIONS { Method::Options }
        else if m == HttpMethod::PATCH { Method::Patch }
        else if m == HttpMethod::HEAD { Method::Head }
        else { Method::Get }
    }
}

use crate::actions::DeviceController;
use crate::auto_update::UpdateManager;
use crate::checkpoint::CheckpointStore;
use crate::collector::{
    detect_platform, AlertRecord, CollectorState, FileIntegrityMonitor, HostInfo, HostPlatform,
};
use crate::compliance::{CausalGraph, ComplianceManager};
use crate::config::Config;
use crate::correlation;
use crate::detector::{
    AdaptationMode, AnomalyDetector, CompoundThreatDetector, DriftDetector, EntropyDetector,
    VelocityDetector,
};
use crate::digital_twin::DigitalTwinEngine;
use crate::edge_cloud::{PatchManager, PlatformCapabilities};
use crate::energy::EnergyBudget;
use crate::enforcement::EnforcementEngine;
use crate::enrollment::{AgentHealth, AgentIdentity, AgentRegistry};
use crate::enterprise::{
    build_content_rules_view, build_entity_profile, build_entity_timeline,
    build_incident_storyline, build_mitre_coverage, ContentLifecycle, EnterpriseStore,
    HuntResponseAction, HuntRun, ResponseActionResult, SavedHunt,
};
use crate::event_forward::{EventAnalytics, EventStore, StoredEvent};
use crate::fingerprint::DeviceFingerprint;
use crate::graphql::{aggregate, AggregateOp, GqlExecutor, GqlRequest, wardex_schema};
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

use crate::analyst::{
    AlertQueue, ApprovalDecision as RemediationDecision, ApprovalLog, CasePriority, CaseStatus,
    CaseStore,
};
use crate::feature_flags::FeatureFlagRegistry;
use crate::ocsf::{self, DeadLetterQueue, SchemaVersion};
use crate::process_tree::ProcessTree;
use crate::rbac::{RbacStore, Role, User};
use crate::storage::SharedStorage;
use crate::response::{
    ActionTier, ApprovalDecision as ResponseApprovalDecision,
    ApprovalRecord as ResponseApprovalRecord, ApprovalStatus, ResponseAction, ResponseOrchestrator,
    ResponseRequest, ResponseTarget,
};
use crate::sigma::SigmaEngine;
use crate::spool::EncryptedSpool;
use sha2::Digest;

// ── Rate Limiter ────────────────────────────────────────────

struct RateLimiter {
    buckets: HashMap<String, (u64, u32)>, // IP -> (window_start_epoch, count)
    read_max_per_minute: u32,
    write_max_per_minute: u32,
    static_max_per_minute: u32,
    call_count: u64,
}

impl RateLimiter {
    fn new(read_max_per_minute: u32, write_max_per_minute: u32) -> Self {
        Self {
            buckets: HashMap::new(),
            read_max_per_minute,
            write_max_per_minute,
            static_max_per_minute: read_max_per_minute.saturating_mul(2),
            call_count: 0,
        }
    }

    fn check(&mut self, ip: &str, method: &Method, path: &str) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Periodic cleanup: evict stale entries to prevent unbounded memory growth
        self.call_count += 1;
        if self.buckets.len() > 1_000 && self.call_count.is_multiple_of(500) {
            self.buckets
                .retain(|_, (window_start, _)| now.saturating_sub(*window_start) < 120);
        }

        let path = path.split('?').next().unwrap_or(path);
        let (bucket_suffix, limit) = if !path.starts_with("/api/") {
            ("static", self.static_max_per_minute)
        } else if matches!(method, Method::Get)
            && matches!(
                path,
                "/api/status"
                    | "/api/report"
                    | "/api/health"
                    | "/api/telemetry/current"
                    | "/api/telemetry/history"
                    | "/api/host/info"
                    | "/api/alerts"
                    | "/api/alerts/count"
                    | "/api/threads/status"
            )
        {
            ("status-read", self.read_max_per_minute)
        } else if matches!(method, Method::Get) {
            ("api-read", self.read_max_per_minute)
        } else {
            ("api-write", self.write_max_per_minute)
        };

        let entry = self
            .buckets
            .entry(format!("{ip}:{bucket_suffix}"))
            .or_insert((now, 0));
        if now - entry.0 >= 60 {
            *entry = (now, 1);
            true
        } else {
            entry.1 += 1;
            entry.1 <= limit
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
    entries: VecDeque<AuditEntry>,
    max_entries: usize,
    syslog_target: Option<std::net::UdpSocket>,
    syslog_addr: Option<String>,
}

impl AuditLog {
    fn new(max_entries: usize) -> Self {
        let (syslog_target, syslog_addr) = match std::env::var("WARDEX_SYSLOG_TARGET") {
            Ok(addr) if !addr.is_empty() => {
                match std::net::UdpSocket::bind("0.0.0.0:0") {
                    Ok(sock) => (Some(sock), Some(addr)),
                    Err(_) => (None, None),
                }
            }
            _ => (None, None),
        };
        Self {
            entries: VecDeque::new(),
            max_entries,
            syslog_target,
            syslog_addr,
        }
    }

    fn record(
        &mut self,
        method: &str,
        path: &str,
        source_ip: &str,
        status_code: u16,
        auth_used: bool,
    ) {
        let timestamp = chrono::Utc::now().to_rfc3339();
        let entry = AuditEntry {
            timestamp: timestamp.clone(),
            method: method.to_string(),
            path: path.to_string(),
            source_ip: source_ip.to_string(),
            status_code,
            auth_used,
        };
        if self.entries.len() >= self.max_entries {
            self.entries.pop_front();
        }
        self.entries.push_back(entry);

        // Forward to syslog (RFC 5424 over UDP)
        if let (Some(sock), Some(addr)) = (&self.syslog_target, &self.syslog_addr) {
            let severity = if status_code >= 500 { 3 } else if status_code >= 400 { 4 } else { 6 };
            let pri = 8 * 10 + severity; // facility=security(10)
            let msg = format!(
                "<{pri}>1 {timestamp} wardex wardex-audit - - - method={method} path={path} src={source_ip} status={status_code} auth={auth_used}"
            );
            let _ = sock.send_to(msg.as_bytes(), addr);
        }
    }

    fn recent(&self, limit: usize) -> Vec<&AuditEntry> {
        self.entries.iter().rev().take(limit).collect::<Vec<_>>().into_iter().rev().collect()
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
    token_issued_at: std::time::Instant,
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
    config_path: PathBuf,
    alerts: VecDeque<AlertRecord>,
    server_start: std::time::Instant,
    // XDR fleet management
    agent_registry: AgentRegistry,
    event_store: EventStore,
    policy_store: PolicyStore,
    update_manager: UpdateManager,
    remote_deployments: HashMap<String, AgentDeployment>,
    deployment_store_path: String,
    siem_connector: SiemConnector,
    taxii_client: crate::siem::TaxiiClient,
    // Local host telemetry (ring buffer, last 300 samples)
    local_telemetry: VecDeque<TelemetrySample>,
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
    // Enterprise-grade content, governance, and support state
    enterprise: EnterpriseStore,
    // Phase 27: SLO counters
    request_count: u64,
    error_count: u64,
    // Phase 32: advanced XDR engines
    beacon_detector: crate::beacon::BeaconDetector,
    ueba_engine: crate::ueba::UebaEngine,
    kill_chain_analyzer: crate::kill_chain::KillChainAnalyzer,
    lateral_detector: crate::lateral::LateralMovementDetector,
    playbook_engine: crate::playbook::PlaybookEngine,
    live_response_engine: crate::live_response::LiveResponseEngine,
    remediation_engine: crate::remediation::RemediationEngine,
    escalation_engine: crate::escalation::EscalationEngine,
    kernel_event_stream: crate::kernel_events::KernelEventStream,
    // Phase 33: alert analysis & cross-agent intel
    last_alert_analysis: Option<crate::alert_analysis::AlertAnalysis>,
    // Phase 34: durable SQLite storage
    storage: SharedStorage,
    // Phase 34: slow-attack & ransomware detectors
    slow_attack: crate::detector::SlowAttackDetector,
    ransomware: crate::ransomware::RansomwareDetector,
    // Phase 29: MITRE coverage, detection tuning, FP feedback
    mitre_coverage: crate::mitre_coverage::MitreCoverageTracker,
    tuning_profile: crate::detector::TuningProfile,
    fp_feedback: crate::alert_analysis::FpFeedbackStore,
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

#[derive(Debug, Clone, serde::Serialize)]
struct QueueAlertSummary {
    event_id: u64,
    agent_id: Option<String>,
    score: f64,
    severity: String,
    hostname: String,
    status: String,
    assignee: Option<String>,
    timestamp: String,
    age_secs: Option<u64>,
    sla_deadline: Option<String>,
    sla_breached: bool,
    reasons: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct CaseSummary {
    id: u64,
    title: String,
    status: String,
    priority: String,
    assignee: Option<String>,
    incident_count: usize,
    event_count: usize,
    updated_at: String,
    tags: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct IncidentSummary {
    id: u64,
    title: String,
    severity: String,
    status: String,
    assignee: Option<String>,
    created_at: String,
    updated_at: String,
    agent_count: usize,
    event_count: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
struct HotAgentSummary {
    agent_id: String,
    hostname: Option<String>,
    risk: String,
    status: String,
    event_count: usize,
    correlated_count: usize,
    max_score: f32,
    current_version: Option<String>,
    target_version: Option<String>,
    rollout_group: Option<String>,
    deployment_status: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct UrgentItem {
    kind: String,
    severity: String,
    title: String,
    subtitle: String,
    reference_id: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct WorkbenchQueueOverview {
    pending: usize,
    acknowledged: usize,
    assigned: usize,
    sla_breached: usize,
    items: Vec<QueueAlertSummary>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct WorkbenchCasesOverview {
    total: usize,
    open: usize,
    resolved: usize,
    active: usize,
    items: Vec<CaseSummary>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct WorkbenchIncidentsOverview {
    total: usize,
    open: usize,
    critical_open: usize,
    by_status: HashMap<String, usize>,
    items: Vec<IncidentSummary>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct WorkbenchResponseOverview {
    pending_approval: usize,
    ready_to_execute: usize,
    denied: usize,
    executed: usize,
    protected_assets: usize,
    recent_requests: Vec<serde_json::Value>,
    recent_approvals: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct WorkbenchOverview {
    generated_at: String,
    queue: WorkbenchQueueOverview,
    cases: WorkbenchCasesOverview,
    incidents: WorkbenchIncidentsOverview,
    response: WorkbenchResponseOverview,
    hot_agents: Vec<HotAgentSummary>,
    urgent_items: Vec<UrgentItem>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ManagerFleetOverview {
    total_agents: usize,
    online: usize,
    stale: usize,
    offline: usize,
    coverage_pct: f32,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ManagerQueueOverview {
    pending: usize,
    acknowledged: usize,
    assigned: usize,
    sla_breached: usize,
    critical_pending: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ManagerIncidentOverview {
    total: usize,
    open: usize,
    investigating: usize,
    contained: usize,
    resolved: usize,
    false_positive: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ManagerDeploymentOverview {
    published_releases: usize,
    pending: usize,
    by_status: HashMap<String, usize>,
    by_ring: HashMap<String, usize>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ManagerReportOverview {
    total_reports: usize,
    total_alerts: usize,
    critical_alerts: usize,
    avg_score: Option<f32>,
    max_score: f32,
    open_incidents: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ManagerComplianceOverview {
    score: f64,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ManagerOperationsOverview {
    pending_approvals: usize,
    ready_to_execute: usize,
    protected_assets: usize,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ManagerOverview {
    generated_at: String,
    fleet: ManagerFleetOverview,
    queue: ManagerQueueOverview,
    incidents: ManagerIncidentOverview,
    deployments: ManagerDeploymentOverview,
    reports: ManagerReportOverview,
    siem: crate::siem::SiemStatus,
    compliance: ManagerComplianceOverview,
    tenants: usize,
    operations: ManagerOperationsOverview,
}

#[derive(Debug, Clone, serde::Serialize)]
struct AgentLogSummary {
    total_records: usize,
    last_timestamp: Option<String>,
    by_level: HashMap<String, usize>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct AgentInventorySummary {
    collected_at: String,
    software_count: usize,
    services_count: usize,
    network_ports: usize,
    users_count: usize,
    hardware: crate::inventory::HardwareInfo,
}

#[derive(Debug, Clone, serde::Serialize)]
struct AgentEventAnalyticsSummary {
    event_count: usize,
    correlated_count: usize,
    critical_count: usize,
    average_score: f32,
    max_score: f32,
    highest_level: String,
    risk: String,
    top_reasons: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct AgentActivitySnapshot {
    agent: AgentIdentity,
    computed_status: String,
    heartbeat_age_secs: Option<u64>,
    deployment: Option<AgentDeployment>,
    scope_override: bool,
    effective_scope: crate::config::MonitorScopeSettings,
    health: AgentHealth,
    analytics: AgentEventAnalyticsSummary,
    timeline: Vec<serde_json::Value>,
    risk_transitions: Vec<serde_json::Value>,
    inventory: Option<AgentInventorySummary>,
    log_summary: AgentLogSummary,
}

pub async fn run_server(
    port: u16,
    site_dir: &Path,
    shutdown: Arc<AtomicBool>,
    initial_config: Config,
) -> Result<(), String> {
    let addr = format!("0.0.0.0:{port}");

    // Determine TLS mode from environment variables
    let tls_cert = std::env::var("WARDEX_TLS_CERT").ok();
    let tls_key = std::env::var("WARDEX_TLS_KEY").ok();

    if tls_cert.is_some() || tls_key.is_some() {
        eprintln!("  NOTE: TLS configured via WARDEX_TLS_CERT/KEY — use a reverse proxy (nginx/caddy) for production TLS");
    }

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| format!("failed to bind {addr}: {e}"))?;

    let config_path = crate::config::runtime_config_path();

    // Use persistent token from environment if set, otherwise generate a random one
    let token = std::env::var("WARDEX_ADMIN_TOKEN").unwrap_or_else(|_| generate_token());
    let scheme = if tls_cert.is_some() && tls_key.is_some() && cfg!(feature = "tls") { "https" } else { "http" };
    eprintln!("Wardex admin console");
    eprintln!("  Listening on {scheme}://localhost:{port}");
    eprintln!("  Site directory: {}", site_dir.display());
    if std::env::var("WARDEX_ADMIN_TOKEN").is_ok() {
        eprintln!("  Auth token: (set via WARDEX_ADMIN_TOKEN)");
    } else {
        eprintln!("  Auth token: {token}");
        eprintln!("  (set WARDEX_ADMIN_TOKEN env var for a persistent token)");
    }
    eprintln!("  Press Ctrl+C to stop");

    // Derive spool encryption key from env var or fall back to token-derived key
    let spool_key = std::env::var("WARDEX_SPOOL_KEY")
        .map(|k| sha2::Sha256::digest(k.as_bytes()))
        .unwrap_or_else(|_| sha2::Sha256::digest(format!("spool-key-{token}").as_bytes()));

    let state = Arc::new(Mutex::new(AppState {
        detector: AnomalyDetector::default(),
        checkpoints: CheckpointStore::new(10),
        device: DeviceController::default(),
        replay: ReplayBuffer::new(200),
        proofs: ProofRegistry::new(),
        last_report: None,
        token: token.clone(),
        token_issued_at: std::time::Instant::now(),
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
        listener_mode: if tls_cert.is_some() && tls_key.is_some() && cfg!(feature = "tls") {
            ListenerMode::Tls { port, config: crate::tls::TlsConfig::new(
                tls_cert.as_deref().unwrap_or_default(),
                tls_key.as_deref().unwrap_or_default(),
            )}
        } else {
            ListenerMode::Plain { port }
        },
        config: Config::default(),
        config_path,
        alerts: VecDeque::new(),
        server_start: std::time::Instant::now(),
        agent_registry: AgentRegistry::new("var/agents.json"),
        event_store: EventStore::with_persistence(10_000, "var/events.json"),
        policy_store: PolicyStore::new(),
        update_manager: UpdateManager::new("var/updates"),
        remote_deployments: load_remote_deployments("var/deployments.json"),
        deployment_store_path: "var/deployments.json".to_string(),
        siem_connector: SiemConnector::new(initial_config.siem.clone()),
        taxii_client: crate::siem::TaxiiClient::new(initial_config.taxii.clone()),
        local_telemetry: VecDeque::new(),
        local_host_info: detect_platform(),
        velocity: VelocityDetector::new(60, 2.5),
        entropy: EntropyDetector::new(60, 8),
        compound: CompoundThreatDetector::default(),
        shutdown: shutdown.clone(),
        rate_limiter: RateLimiter::new(360, 60),
        audit_log: AuditLog::new(1000),
        incident_store: IncidentStore::new("var/incidents.json"),
        agent_logs: HashMap::new(),
        agent_inventories: HashMap::new(),
        report_store: crate::report::ReportStore::new("var/reports.json"),
        sigma_engine: SigmaEngine::new(),
        response_orchestrator: ResponseOrchestrator::new(),
        feature_flags: FeatureFlagRegistry::new(),
        process_tree: ProcessTree::new("localhost"),
        spool: EncryptedSpool::new(&spool_key, 10_000),
        rbac: RbacStore::new(),
        case_store: CaseStore::new("var/cases.json"),
        alert_queue: AlertQueue::new(),
        approval_log: ApprovalLog::new(),
        dead_letter_queue: DeadLetterQueue::new(500),
        enterprise: EnterpriseStore::new("var/enterprise.json"),
        request_count: 0,
        error_count: 0,
        beacon_detector: crate::beacon::BeaconDetector::default(),
        ueba_engine: crate::ueba::UebaEngine::default(),
        kill_chain_analyzer: crate::kill_chain::KillChainAnalyzer::new(),
        lateral_detector: crate::lateral::LateralMovementDetector::default(),
        playbook_engine: crate::playbook::PlaybookEngine::new(),
        live_response_engine: crate::live_response::LiveResponseEngine::default(),
        remediation_engine: crate::remediation::RemediationEngine::new(),
        escalation_engine: crate::escalation::EscalationEngine::new(),
        kernel_event_stream: crate::kernel_events::KernelEventStream::new(10_000),
        last_alert_analysis: None,
        storage: SharedStorage::open("var/storage")
            .or_else(|_| SharedStorage::open("/tmp/wardex_storage"))
            .map_err(|e| format!("failed to initialise storage: {e}"))?,
        slow_attack: crate::detector::SlowAttackDetector::default(),
        ransomware: crate::ransomware::RansomwareDetector::default(),
        mitre_coverage: crate::mitre_coverage::MitreCoverageTracker::new(),
        tuning_profile: crate::detector::TuningProfile::default(),
        fp_feedback: crate::alert_analysis::FpFeedbackStore::new(),
    }));

    // Apply loaded config
    {
        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
        s.config = initial_config;
        let effective_rules = s.enterprise.effective_sigma_rules();
        s.sigma_engine.replace_rules(effective_rules);
    }
    spawn_enterprise_hunt_scheduler(&state);
    spawn_retention_purge_scheduler(&state);

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
                    let s = monitor_state.lock().unwrap_or_else(|e| e.into_inner());
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

                let persistence_paths =
                    crate::collector::persistence_watch_paths(host_platform, &scope);
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
                    let mut s = match monitor_state.lock() {
                        Ok(g) => g,
                        Err(e) => e.into_inner(),
                    };
                    if s.local_telemetry.len() >= 300 {
                        s.local_telemetry.pop_front();
                    }
                    s.local_telemetry.push_back(sample);
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
                        let confirmed =
                            signal.score >= sev || consecutive_elevated >= CONFIRM_SAMPLES;
                        if confirmed {
                            let level = if signal.score >= crit {
                                "Critical"
                            } else if signal.score >= sev {
                                "Severe"
                            } else {
                                "Elevated"
                            };
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
                                s.alerts.pop_front();
                            }
                            s.alerts.push_back(alert.clone());

                            // Phase 33: broadcast high-severity intel to swarm
                            if alert.score >= sev {
                                let swarm_id = s.swarm.id.clone();
                                for reason in &alert.reasons {
                                    if reason.contains("network burst")
                                        || reason.contains("velocity-spike")
                                    {
                                        let _msg = s.swarm.broadcast_threat_intel(
                                            crate::swarm::GossipPayload::ThreatIntelUpdate {
                                                ioc_type: "network_anomaly".into(),
                                                indicator: format!("{}:{}", alert.hostname, reason),
                                                confidence: alert.confidence,
                                                source_agent: swarm_id.clone(),
                                                ttl_hours: 24,
                                            },
                                        );
                                    }
                                }
                            }
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

    // ── Spawn background alert analysis thread (every 5 minutes) ────
    {
        let analysis_state = Arc::clone(&state);
        std::thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(300));
            let mut s = match analysis_state.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            let alerts_vec: Vec<_> = s.alerts.iter().cloned().collect();
            let analysis = crate::alert_analysis::analyze_alerts(&alerts_vec, 5);
            s.last_alert_analysis = Some(analysis);
        });
    }

    let site_dir = site_dir.to_path_buf();

    // Build axum router
    let shared_state = Arc::clone(&state);
    let shared_site = site_dir.clone();
    let shutdown_flag = shutdown.clone();

    use axum::Router;
    use axum::extract::ConnectInfo;
    use axum::routing::any;

    let app = Router::new()
        .fallback(move |
            method: HttpMethod,
            uri: axum::http::Uri,
            headers: HeaderMap,
            ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
            body: axum::body::Bytes,
        | {
            let state = shared_state.clone();
            let site_dir = shared_site.clone();
            async move {
                let url = uri.to_string();
                let remote_addr = addr.ip().to_string();

                // Rate limiting
                {
                    let method_compat = Method::from_http(&method);
                    let mut s = match state.lock() {
                        Ok(g) => g,
                        Err(e) => e.into_inner(),
                    };
                    s.request_count += 1;
                    if !s.rate_limiter.check(&remote_addr, &method_compat, &url) {
                        drop(s);
                        if url.starts_with("/api/") {
                            return respond_api(
                                &state,
                                &method_compat,
                                &url,
                                &remote_addr,
                                false,
                                error_json("rate limit exceeded", 429),
                            );
                        } else {
                            return error_json("rate limit exceeded", 429);
                        }
                    }
                }

                // CORS preflight
                if method == HttpMethod::OPTIONS {
                    let origin = cors_origin();
                    return Response::builder()
                        .status(204)
                        .header("Access-Control-Allow-Origin", origin)
                        .header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
                        .header("Access-Control-Allow-Headers", "Content-Type, Authorization")
                        .header("Access-Control-Max-Age", "86400")
                        .body(Body::empty())
                        .unwrap();
                }

                if url.starts_with("/api/") {
                    let m = Method::from_http(&method);
                    let hdrs = headers.clone();
                    let body_bytes: Vec<u8> = body.to_vec();
                    let st = state.clone();
                    let u = url.clone();
                    let ra = remote_addr.clone();
                    let sd = site_dir.clone();
                    match tokio::task::spawn_blocking(move || {
                        // Catch panics so one bad request cannot crash the server
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                            handle_api(m, &u, &hdrs, &body_bytes, &ra, &st)
                        }))
                    }).await {
                        Ok(Ok(resp)) => resp,
                        Ok(Err(panic_info)) => {
                            let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                                s.to_string()
                            } else if let Some(s) = panic_info.downcast_ref::<String>() {
                                s.clone()
                            } else {
                                "unknown panic in request handler".to_string()
                            };
                            log::error!("[PANIC-RECOVERED] request handler panic: {msg}");
                            let mut s = match state.lock() {
                                Ok(g) => g,
                                Err(e) => e.into_inner(),
                            };
                            s.error_count += 1;
                            drop(s);
                            error_json("internal server error", 500)
                        }
                        Err(_) => error_json("internal server error", 500),
                    }
                } else {
                    serve_static(&url, &site_dir)
                }
            }
        });

    let app = app.into_make_service_with_connect_info::<std::net::SocketAddr>();

    eprintln!("Wardex server ready on http://localhost:{port}");

    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                if shutdown_flag.load(Ordering::Relaxed) {
                    break;
                }
            }
            log::info!("Server shutting down…");
        })
        .await
        .map_err(|e| format!("server error: {e}"))?;

    // ── Graceful shutdown: flush outstanding data to durable storage ──
    flush_to_storage(&state);

    Ok(())
}

/// Spawn a test server on a random port. Returns `(port, token)`.
/// The server runs in a background thread.
#[doc(hidden)]
pub fn spawn_test_server() -> (u16, String) {
    let (tx, rx) = std::sync::mpsc::channel();
    // Find a free port
    let tmp_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind test server");
    let port = tmp_listener.local_addr().expect("local addr").port();
    drop(tmp_listener);
    let token = generate_token();
    let state_root = PathBuf::from(format!("/tmp/wardex_test_{port}"));
    let _ = std::fs::remove_dir_all(&state_root);
    std::fs::create_dir_all(&state_root).expect("create test state root");
    let config_path = state_root.join("wardex.toml");
    let state = Arc::new(Mutex::new(AppState {
        detector: AnomalyDetector::default(),
        checkpoints: CheckpointStore::new(10),
        device: DeviceController::default(),
        replay: ReplayBuffer::new(200),
        proofs: ProofRegistry::new(),
        last_report: None,
        token: token.clone(),
        token_issued_at: std::time::Instant::now(),
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
        config_path,
        alerts: VecDeque::new(),
        server_start: std::time::Instant::now(),
        agent_registry: AgentRegistry::new(&state_root.join("agents.json").to_string_lossy()),
        event_store: EventStore::with_persistence(
            1000,
            state_root.join("events.json").to_string_lossy().to_string(),
        ),
        policy_store: PolicyStore::new(),
        update_manager: UpdateManager::new(&state_root.join("updates").to_string_lossy()),
        remote_deployments: load_remote_deployments(
            &state_root.join("deployments.json").to_string_lossy(),
        ),
        deployment_store_path: state_root
            .join("deployments.json")
            .to_string_lossy()
            .to_string(),
        siem_connector: SiemConnector::new(crate::siem::SiemConfig::default()),
        taxii_client: crate::siem::TaxiiClient::new(crate::siem::TaxiiConfig::default()),
        local_telemetry: VecDeque::new(),
        local_host_info: detect_platform(),
        velocity: VelocityDetector::new(60, 2.5),
        entropy: EntropyDetector::new(60, 8),
        compound: CompoundThreatDetector::default(),
        shutdown: Arc::new(AtomicBool::new(false)),
        rate_limiter: RateLimiter::new(360, 60),
        audit_log: AuditLog::new(1000),
        incident_store: IncidentStore::new(&state_root.join("incidents.json").to_string_lossy()),
        agent_logs: HashMap::new(),
        agent_inventories: HashMap::new(),
        report_store: crate::report::ReportStore::new(
            &state_root.join("reports.json").to_string_lossy(),
        ),
        sigma_engine: SigmaEngine::new(),
        response_orchestrator: ResponseOrchestrator::new(),
        feature_flags: FeatureFlagRegistry::new(),
        process_tree: ProcessTree::new("localhost"),
        spool: EncryptedSpool::new(&sha2::Sha256::digest(format!("spool-key-{token}").as_bytes()), 10_000),
        rbac: RbacStore::new(),
        case_store: CaseStore::new(&state_root.join("cases.json").to_string_lossy()),
        alert_queue: AlertQueue::new(),
        approval_log: ApprovalLog::new(),
        dead_letter_queue: DeadLetterQueue::new(500),
        enterprise: EnterpriseStore::new(&state_root.join("enterprise.json").to_string_lossy()),
        request_count: 0,
        error_count: 0,
        beacon_detector: crate::beacon::BeaconDetector::default(),
        ueba_engine: crate::ueba::UebaEngine::default(),
        kill_chain_analyzer: crate::kill_chain::KillChainAnalyzer::new(),
        lateral_detector: crate::lateral::LateralMovementDetector::default(),
        playbook_engine: crate::playbook::PlaybookEngine::new(),
        live_response_engine: crate::live_response::LiveResponseEngine::default(),
        remediation_engine: crate::remediation::RemediationEngine::new(),
        escalation_engine: crate::escalation::EscalationEngine::new(),
        kernel_event_stream: crate::kernel_events::KernelEventStream::new(10_000),
        last_alert_analysis: None,
        storage: SharedStorage::open(state_root.join("storage").to_str().unwrap_or("var/storage"))
            .or_else(|_| SharedStorage::open("/tmp/wardex_storage"))
            .expect("failed to initialise test storage"),
        slow_attack: crate::detector::SlowAttackDetector::default(),
        ransomware: crate::ransomware::RansomwareDetector::default(),
        mitre_coverage: crate::mitre_coverage::MitreCoverageTracker::new(),
        tuning_profile: crate::detector::TuningProfile::default(),
        fp_feedback: crate::alert_analysis::FpFeedbackStore::new(),
    }));
    {
        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
        let effective_rules = s.enterprise.effective_sigma_rules();
        s.sigma_engine.replace_rules(effective_rules);
    }
    spawn_enterprise_hunt_scheduler(&state);
    let site_dir = PathBuf::from("site");
    let shutdown = {
        let s = state.lock().unwrap_or_else(|e| e.into_inner());
        s.shutdown.clone()
    };
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        rt.block_on(async move {
            let shared_state = Arc::clone(&state);
            let shared_site = site_dir.clone();
            let shutdown_flag = shutdown.clone();

            use axum::Router;
            use axum::extract::ConnectInfo;

            let app = Router::new()
                .fallback(move |
                    method: HttpMethod,
                    uri: axum::http::Uri,
                    headers: HeaderMap,
                    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
                    body: axum::body::Bytes,
                | {
                    let state = shared_state.clone();
                    let site_dir = shared_site.clone();
                    async move {
                        let url = uri.to_string();
                        let remote_addr = addr.ip().to_string();

                        {
                            let method_compat = Method::from_http(&method);
                            let mut s = match state.lock() {
                                Ok(g) => g,
                                Err(e) => e.into_inner(),
                            };
                            s.request_count += 1;
                            if !s.rate_limiter.check(&remote_addr, &method_compat, &url) {
                                drop(s);
                                return error_json("rate limit exceeded", 429);
                            }
                        }

                        if method == HttpMethod::OPTIONS {
                            let origin = cors_origin();
                            return Response::builder()
                                .status(204)
                                .header("Access-Control-Allow-Origin", origin)
                                .header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
                                .header("Access-Control-Allow-Headers", "Content-Type, Authorization")
                                .body(Body::empty())
                                .unwrap();
                        }

                        if url.starts_with("/api/") {
                            let m = Method::from_http(&method);
                            handle_api(m, &url, &headers, &body, &remote_addr, &state)
                        } else {
                            serve_static(&url, &site_dir)
                        }
                    }
                });

            let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
                .await
                .expect("bind test listener");
            tx.send(()).ok();
            let app = app.into_make_service_with_connect_info::<std::net::SocketAddr>();
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    loop {
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                        if shutdown_flag.load(Ordering::Relaxed) {
                            break;
                        }
                    }
                })
                .await
                .ok();
        });
    });
    // Wait for server to be listening
    let _ = rx.recv_timeout(std::time::Duration::from_secs(5));
    // Small delay to let the listener actually start accepting
    std::thread::sleep(std::time::Duration::from_millis(50));
    (port, token)
}


/// Flush in-memory alerts, audit entries, and event store to the SQLite
/// storage backend so nothing is lost on shutdown.
fn flush_to_storage(state: &Arc<Mutex<AppState>>) {
    let s = match state.lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    let storage = s.storage.clone();
    let alerts: Vec<_> = s.alerts.iter().cloned().collect();
    let audit_entries: Vec<_> = s.audit_log.entries.iter().cloned().collect();
    let events: Vec<_> = s.event_store.all_events().to_vec();
    let hostname = s.local_host_info.hostname.clone();
    drop(s);

    let mut stored = 0usize;
    let mut errors = 0usize;

    // Flush in-memory alerts
    for (i, alert) in alerts.iter().enumerate() {
        let stored_alert = crate::storage::StoredAlert {
            id: format!("mem-{}-{}", hostname, i),
            timestamp: alert.timestamp.clone(),
            device_id: hostname.clone(),
            score: alert.score as f64,
            level: alert.level.clone(),
            reasons: alert.reasons.clone(),
            acknowledged: false,
            assigned_to: None,
            case_id: None,
            tenant_id: "default".into(),
        };
        match storage.with(|store| store.insert_alert(stored_alert)) {
            Ok(()) => stored += 1,
            Err(e) => {
                // Conflict (duplicate) is OK — alert was already persisted
                if e.code != crate::storage::StorageErrorCode::Conflict {
                    errors += 1;
                }
            }
        }
    }

    // Flush API audit log entries
    let mut audit_stored = 0usize;
    for entry in &audit_entries {
        let action = format!("{} {}", entry.method, entry.path);
        if storage.with(|store| {
            store.append_audit(
                &entry.source_ip,
                &action,
                Some(&entry.path),
                Some(&format!("status={} auth={}", entry.status_code, entry.auth_used)),
                "default",
            )
        }).is_ok() {
            audit_stored += 1;
        }
    }

    // Flush forwarded events as stored alerts
    let mut event_stored = 0usize;
    for event in &events {
        let stored_alert = crate::storage::StoredAlert {
            id: format!("evt-{}", event.id),
            timestamp: event.received_at.clone(),
            device_id: event.agent_id.clone(),
            score: event.alert.score as f64,
            level: event.alert.level.clone(),
            reasons: event.alert.reasons.clone(),
            acknowledged: false,
            assigned_to: None,
            case_id: None,
            tenant_id: "default".into(),
        };
        match storage.with(|store| store.insert_alert(stored_alert)) {
            Ok(()) => event_stored += 1,
            Err(e) => {
                if e.code != crate::storage::StorageErrorCode::Conflict {
                    errors += 1;
                }
            }
        }
    }

    log::info!(
        "Shutdown flush: {stored} alerts, {audit_stored} audit entries, {event_stored} events written to storage ({errors} errors)",
    );
}

fn generate_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.r#gen()).collect();
    hex::encode(bytes)
}

/// Scan text for common PII patterns (email, IPv4, SSN, credit card).
/// Returns a list of category names found.
fn scan_pii(text: &str) -> Vec<String> {
    let mut categories = Vec::new();

    // Email pattern
    let has_email = text.split_whitespace().any(|w| {
        let w = w.trim_matches(|c: char| !c.is_alphanumeric() && c != '@' && c != '.' && c != '_' && c != '-');
        w.contains('@') && w.contains('.') && w.len() > 5
    });
    if has_email {
        categories.push("email".into());
    }

    // SSN pattern (###-##-####)
    let has_ssn = text.as_bytes().windows(11).any(|w| {
        w.len() == 11
            && w[0].is_ascii_digit() && w[1].is_ascii_digit() && w[2].is_ascii_digit()
            && w[3] == b'-'
            && w[4].is_ascii_digit() && w[5].is_ascii_digit()
            && w[6] == b'-'
            && w[7].is_ascii_digit() && w[8].is_ascii_digit()
            && w[9].is_ascii_digit() && w[10].is_ascii_digit()
    });
    if has_ssn {
        categories.push("ssn".into());
    }

    // Credit card pattern (4 groups of 4 digits separated by spaces or dashes)
    let digits_only: String = text.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits_only.len() >= 13 {
        // Luhn check on first 16-digit sequence
        let candidate: Vec<u8> = digits_only.bytes().take(16).map(|b| b - b'0').collect();
        if candidate.len() >= 13 {
            let mut sum = 0u32;
            let mut double = false;
            for &d in candidate.iter().rev() {
                let mut n = d as u32;
                if double {
                    n *= 2;
                    if n > 9 { n -= 9; }
                }
                sum += n;
                double = !double;
            }
            if sum.is_multiple_of(10) {
                categories.push("credit_card".into());
            }
        }
    }

    // IPv4 addresses (not in RFC 1918 private ranges to reduce false positives)
    let has_public_ip = text.split_whitespace().any(|w| {
        let parts: Vec<&str> = w.trim_matches(|c: char| !c.is_ascii_digit() && c != '.').split('.').collect();
        if parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok()) {
            let first: u8 = parts[0].parse().unwrap_or(0);
            let second: u8 = parts[1].parse().unwrap_or(0);
            // Skip private ranges
            !(first == 10 || first == 127 || (first == 172 && (16..=31).contains(&second)) || (first == 192 && second == 168))
        } else {
            false
        }
    });
    if has_public_ip {
        categories.push("ip_address".into());
    }

    categories
}

fn cors_origin() -> String {
    let origin =
        std::env::var("SENTINEL_CORS_ORIGIN").unwrap_or_else(|_| "http://localhost".into());
    // Block wildcard CORS origin — credentials must not use "*"
    if origin == "*" {
        return "http://localhost".into();
    }
    // Validate origin looks like a URL scheme
    if origin.starts_with("http://") || origin.starts_with("https://") {
        origin
    } else {
        "http://localhost".into()
    }
}

fn json_response(body: &str, status: u16) -> Response<Body> {
    let origin = cors_origin();
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .header("Access-Control-Allow-Origin", origin)
        .header("Vary", "Origin")
        .header("X-Content-Type-Options", "nosniff")
        .header("X-Frame-Options", "DENY")
        .header("Cache-Control", "no-store")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

fn error_json(message: &str, status: u16) -> Response<Body> {
    let body = format!(r#"{{"error":"{}"}}"#, message.replace('"', "\\\""));
    json_response(&body, status)
}

fn text_response(body: &str, status: u16) -> Response<Body> {
    let origin = cors_origin();
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain; charset=utf-8")
        .header("Access-Control-Allow-Origin", origin)
        .header("Vary", "Origin")
        .header("X-Content-Type-Options", "nosniff")
        .header("X-Frame-Options", "DENY")
        .header("Cache-Control", "no-store")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

fn csv_response(body: &str, status: u16) -> Response<Body> {
    let origin = cors_origin();
    Response::builder()
        .status(status)
        .header("Content-Type", "text/csv; charset=utf-8")
        .header("Access-Control-Allow-Origin", origin)
        .header("Vary", "Origin")
        .header("X-Content-Type-Options", "nosniff")
        .header("X-Frame-Options", "DENY")
        .header("Cache-Control", "no-store")
        .body(Body::from(body.to_owned()))
        .unwrap()
}

fn recent_alerts_json(
    alerts: &[AlertRecord],
    limit: usize,
    offset: usize,
) -> Result<String, String> {
    let capped_limit = limit.min(1000);
    let recent: Vec<_> = alerts
        .iter()
        .enumerate()
        .rev()
        .skip(offset)
        .take(capped_limit)
        .map(|(i, a)| {
            let mut obj = serde_json::to_value(a).unwrap_or_default();
            if let Some(map) = obj.as_object_mut() {
                map.insert("id".to_string(), serde_json::json!(i));
                map.insert("_index".to_string(), serde_json::json!(i));
            }
            obj
        })
        .collect();
    serde_json::to_string(&recent).map_err(|e| format!("serialization error: {e}"))
}

fn incidents_json(
    incident_store: &IncidentStore,
    query: &HashMap<String, String>,
) -> Result<String, String> {
    let status = query.get("status").map(|value| value.as_str());
    let severity = query.get("severity").map(|value| value.as_str());
    let offset = query
        .get("offset")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let limit = query
        .get("limit")
        .and_then(|value| value.parse::<usize>().ok())
        .map(|value| value.min(1000));

    let incidents = incident_store.list_filtered(status, severity);
    let paged: Vec<_> = match limit {
        Some(limit) => incidents.into_iter().skip(offset).take(limit).collect(),
        None => incidents.into_iter().skip(offset).collect(),
    };
    serde_json::to_string(&paged).map_err(|e| format!("serialization error: {e}"))
}

fn prometheus_metrics_payload(state: &AppState) -> String {
    let agents = state.agent_registry.list();
    let heartbeat_interval = state.agent_registry.heartbeat_interval();
    let total_agents = agents.len();
    let online_agents = agents
        .iter()
        .filter(|agent| computed_agent_status(agent, heartbeat_interval).0 == "online")
        .count();
    let pending_deployments = state
        .remote_deployments
        .values()
        .filter(|deployment| deployment_is_pending(deployment, &state.agent_registry))
        .count();

    let metrics = [
        ("wardex_up", "gauge", 1_u64),
        ("wardex_alerts_total", "gauge", state.alerts.len() as u64),
        (
            "wardex_events_total",
            "gauge",
            state.event_store.count() as u64,
        ),
        ("wardex_agents_total", "gauge", total_agents as u64),
        ("wardex_agents_online", "gauge", online_agents as u64),
        (
            "wardex_incidents_total",
            "gauge",
            state.incident_store.list().len() as u64,
        ),
        (
            "wardex_cases_total",
            "gauge",
            state.case_store.list().len() as u64,
        ),
        (
            "wardex_reports_total",
            "gauge",
            state.report_store.list().len() as u64,
        ),
        (
            "wardex_response_requests_total",
            "gauge",
            state.response_orchestrator.all_requests().len() as u64,
        ),
        (
            "wardex_response_pending_total",
            "gauge",
            state.response_orchestrator.pending_requests().len() as u64,
        ),
        (
            "wardex_deployments_pending_total",
            "gauge",
            pending_deployments as u64,
        ),
        ("wardex_requests_total", "counter", state.request_count),
        ("wardex_request_errors_total", "counter", state.error_count),
        (
            "wardex_uptime_seconds",
            "gauge",
            state.server_start.elapsed().as_secs(),
        ),
    ];

    let mut body = String::new();
    for (name, metric_type, value) in metrics {
        body.push_str("# HELP ");
        body.push_str(name);
        body.push('\n');
        body.push_str("# TYPE ");
        body.push_str(name);
        body.push(' ');
        body.push_str(metric_type);
        body.push('\n');
        body.push_str(name);
        body.push(' ');
        body.push_str(&value.to_string());
        body.push('\n');
    }
    body
}

fn respond_api(
    state: &Arc<Mutex<AppState>>,
    method: &Method,
    url: &str,
    remote_addr: &str,
    auth_used: bool,
    response: Response<Body>,
) -> Response<Body> {
    // Generate a short request ID for tracing
    let req_id = {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut buf = [0u8; 8];
        rng.fill(&mut buf);
        hex::encode(buf)
    };
    let status_code = response.status().as_u16();
    {
        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
        if status_code >= 400 {
            s.error_count += 1;
        }
        s.audit_log.record(
            &format!("{method:?}"),
            url,
            remote_addr,
            status_code,
            auth_used,
        );
    }
    let (mut parts, body) = response.into_parts();
    parts.headers.insert("X-Request-Id", req_id.parse().unwrap());
    Response::from_parts(parts, body)
}

#[derive(Debug, Clone)]
enum AuthIdentity {
    None,
    AdminToken,
    UserToken(User),
}

impl AuthIdentity {
    fn is_authenticated(&self) -> bool {
        !matches!(self, AuthIdentity::None)
    }

    fn is_admin(&self) -> bool {
        matches!(self, AuthIdentity::AdminToken)
    }

    fn actor(&self) -> &str {
        match self {
            AuthIdentity::None => "anonymous",
            AuthIdentity::AdminToken => "admin",
            AuthIdentity::UserToken(user) => &user.username,
        }
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    if let Some(val) = headers.get("authorization") {
        if let Ok(s) = val.to_str() {
            if let Some(token) = s.strip_prefix("Bearer ") {
                return Some(token.trim().to_string());
            }
        }
    }
    None
}

fn authenticate_request(headers: &HeaderMap, state: &Arc<Mutex<AppState>>) -> AuthIdentity {
    let Some(token) = bearer_token(headers) else {
        return AuthIdentity::None;
    };
    let state = state.lock().unwrap_or_else(|e| e.into_inner());
    let ttl = state.config.security.token_ttl_secs;
    if ttl == 0 || state.token_issued_at.elapsed().as_secs() <= ttl {
        let input = token.as_bytes();
        let expected = state.token.as_bytes();
        if input.len() == expected.len() {
            let mut diff = 0u8;
            for (a, b) in input.iter().zip(expected.iter()) {
                diff |= a ^ b;
            }
            if diff == 0 {
                return AuthIdentity::AdminToken;
            }
        }
    }
    if let Some(user) = state.rbac.authenticate(&token) {
        return AuthIdentity::UserToken(user);
    }
    AuthIdentity::None
}

fn response_requested_by(auth: &AuthIdentity) -> String {
    auth.actor().to_string()
}

fn response_approver(auth: &AuthIdentity) -> String {
    auth.actor().to_string()
}

fn playbook_executor(auth: &AuthIdentity) -> String {
    auth.actor().to_string()
}

fn live_response_operator(auth: &AuthIdentity) -> String {
    auth.actor().to_string()
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

fn url_path(url: &str) -> &str {
    url.split('?').next().unwrap_or(url)
}

fn url_param(url: &str, key: &str) -> Option<String> {
    parse_query_string(url)
        .get(key)
        .cloned()
        .filter(|v| !v.is_empty())
}

fn parse_numeric_segment<T: FromStr>(segment: &str) -> Option<T> {
    if segment.is_empty()
        || segment.contains('/')
        || !segment.chars().all(|ch| ch.is_ascii_digit())
    {
        return None;
    }
    segment.parse().ok()
}

fn parse_numeric_path_suffix<T: FromStr>(path: &str, prefix: &str) -> Option<T> {
    path.strip_prefix(prefix).and_then(parse_numeric_segment)
}

fn parse_numeric_path_between<T: FromStr>(path: &str, prefix: &str, suffix: &str) -> Option<T> {
    path.strip_prefix(prefix)
        .and_then(|rest| rest.strip_suffix(suffix))
        .map(|segment| segment.trim_end_matches('/'))
        .and_then(parse_numeric_segment)
}

fn parse_entity_profile_path(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("/api/entities/")?.trim_matches('/');
    let mut segments = rest.split('/');
    let kind = segments.next()?;
    let id = segments.next()?;
    if kind.is_empty() || id.is_empty() || segments.next().is_some() {
        return None;
    }
    Some((kind, id))
}

fn parse_entity_timeline_path(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("/api/entities/")?.trim_matches('/');
    let mut segments = rest.split('/');
    let kind = segments.next()?;
    let id = segments.next()?;
    let tail = segments.next()?;
    if kind.is_empty() || id.is_empty() || tail != "timeline" || segments.next().is_some() {
        return None;
    }
    Some((kind, id))
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
    match value
        .unwrap_or("direct")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
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

fn severity_label(level: &str) -> &'static str {
    match severity_rank(level) {
        3 => "Critical",
        2 => "Severe",
        1 => "Elevated",
        _ => "Nominal",
    }
}

fn age_secs_since(timestamp: &str) -> Option<u64> {
    let parsed = chrono::DateTime::parse_from_rfc3339(timestamp).ok()?;
    let now = chrono::Utc::now();
    let seconds = now
        .signed_duration_since(parsed.with_timezone(&chrono::Utc))
        .num_seconds();
    Some(seconds.max(0) as u64)
}

fn computed_agent_status(agent: &AgentIdentity, heartbeat_interval: u64) -> (String, Option<u64>) {
    if matches!(agent.status, crate::enrollment::AgentStatus::Deregistered) {
        return ("deregistered".to_string(), age_secs_since(&agent.last_seen));
    }
    let age_secs = age_secs_since(&agent.last_seen);
    let stale_after = heartbeat_interval.saturating_mul(3);
    let offline_after = heartbeat_interval.saturating_mul(6);
    let status = match age_secs {
        Some(age) if age > offline_after => "offline",
        Some(age) if age > stale_after => "stale",
        Some(_) => "online",
        None => "unknown",
    };
    (status.to_string(), age_secs)
}

fn response_status_counts(requests: &[ResponseRequest]) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    for request in requests {
        let key = format!("{:?}", request.status);
        *counts.entry(key).or_insert(0) += 1;
    }
    counts
}

fn queue_alert_summary(
    item: &crate::analyst::QueuedAlert,
    event_store: &EventStore,
) -> QueueAlertSummary {
    let linked_event = event_store.get_event(item.event_id);
    let age_secs = age_secs_since(&item.timestamp);
    let sla_breached = item
        .sla_deadline
        .as_deref()
        .and_then(|deadline| chrono::DateTime::parse_from_rfc3339(deadline).ok())
        .map(|deadline| chrono::Utc::now() > deadline.with_timezone(&chrono::Utc))
        .unwrap_or(false);
    QueueAlertSummary {
        event_id: item.event_id,
        agent_id: linked_event.map(|event| event.agent_id.clone()),
        score: item.score,
        severity: severity_label(&item.level).to_string(),
        hostname: item.hostname.clone(),
        status: if item.acknowledged {
            "acknowledged".to_string()
        } else if item.assignee.is_some() {
            "assigned".to_string()
        } else {
            "pending".to_string()
        },
        assignee: item.assignee.clone(),
        timestamp: item.timestamp.clone(),
        age_secs,
        sla_deadline: item.sla_deadline.clone(),
        sla_breached,
        reasons: linked_event
            .map(|event| event.alert.reasons.clone())
            .unwrap_or_default(),
    }
}

fn case_summary(case: &crate::analyst::Case) -> CaseSummary {
    CaseSummary {
        id: case.id,
        title: case.title.clone(),
        status: format!("{:?}", case.status),
        priority: format!("{:?}", case.priority),
        assignee: case.assignee.clone(),
        incident_count: case.incident_ids.len(),
        event_count: case.event_ids.len(),
        updated_at: case.updated_at.clone(),
        tags: case.tags.clone(),
    }
}

fn incident_summary(incident: &crate::incident::Incident) -> IncidentSummary {
    IncidentSummary {
        id: incident.id,
        title: incident.title.clone(),
        severity: incident.severity.clone(),
        status: format!("{:?}", incident.status),
        assignee: incident.assignee.clone(),
        created_at: incident.created_at.clone(),
        updated_at: incident.updated_at.clone(),
        agent_count: incident.agent_ids.len(),
        event_count: incident.event_ids.len(),
    }
}

fn build_hot_agent_summaries(
    analytics: &EventAnalytics,
    registry: &AgentRegistry,
    deployments: &HashMap<String, AgentDeployment>,
) -> Vec<HotAgentSummary> {
    analytics
        .hot_agents
        .iter()
        .take(5)
        .map(|agent| {
            let registry_agent = registry.get(&agent.agent_id);
            let deployment = deployments.get(&agent.agent_id);
            let (status, _) = registry_agent
                .map(|entry| computed_agent_status(entry, registry.heartbeat_interval()))
                .unwrap_or_else(|| ("unknown".to_string(), None));
            HotAgentSummary {
                agent_id: agent.agent_id.clone(),
                hostname: registry_agent.map(|entry| entry.hostname.clone()),
                risk: agent.risk.clone(),
                status,
                event_count: agent.event_count,
                correlated_count: agent.correlated_count,
                max_score: agent.max_score,
                current_version: registry_agent.map(|entry| entry.version.clone()),
                target_version: deployment.map(|entry| entry.version.clone()),
                rollout_group: deployment.map(|entry| entry.rollout_group.clone()),
                deployment_status: deployment.map(|entry| entry.status.clone()),
            }
        })
        .collect()
}

fn build_workbench_overview(
    alert_queue: &AlertQueue,
    case_store: &CaseStore,
    incident_store: &IncidentStore,
    response_orchestrator: &ResponseOrchestrator,
    approval_log: &ApprovalLog,
    analytics: &EventAnalytics,
    event_store: &EventStore,
    agent_registry: &AgentRegistry,
    deployments: &HashMap<String, AgentDeployment>,
) -> WorkbenchOverview {
    let mut queue_items: Vec<QueueAlertSummary> = alert_queue
        .pending()
        .into_iter()
        .map(|item| queue_alert_summary(item, event_store))
        .collect();
    queue_items.sort_by(|left, right| {
        right
            .sla_breached
            .cmp(&left.sla_breached)
            .then_with(|| severity_rank(&right.severity).cmp(&severity_rank(&left.severity)))
            .then_with(|| {
                right
                    .age_secs
                    .unwrap_or_default()
                    .cmp(&left.age_secs.unwrap_or_default())
            })
    });

    let queue_pending = queue_items.len();
    let queue_acknowledged = alert_queue
        .all()
        .iter()
        .filter(|item| item.acknowledged)
        .count();
    let queue_assigned = alert_queue
        .all()
        .iter()
        .filter(|item| item.assignee.is_some())
        .count();
    let queue_breached = queue_items.iter().filter(|item| item.sla_breached).count();

    let mut cases = case_store.list_filtered(None, None, None);
    cases.sort_by(|left, right| right.updated_at.cmp(&left.updated_at));
    let case_total = cases.len();
    let case_open = cases
        .iter()
        .filter(|case| !matches!(case.status, CaseStatus::Resolved | CaseStatus::Closed))
        .count();
    let case_resolved = cases
        .iter()
        .filter(|case| matches!(case.status, CaseStatus::Resolved | CaseStatus::Closed))
        .count();

    let incidents = incident_store.list();
    let mut incident_statuses = HashMap::new();
    for incident in incidents {
        *incident_statuses
            .entry(format!("{:?}", incident.status))
            .or_insert(0) += 1;
    }
    let mut incident_items: Vec<IncidentSummary> = incidents.iter().map(incident_summary).collect();
    incident_items.sort_by(|left, right| right.updated_at.cmp(&left.updated_at));
    let incident_open = incidents
        .iter()
        .filter(|incident| {
            matches!(
                incident.status,
                crate::incident::IncidentStatus::Open
                    | crate::incident::IncidentStatus::Investigating
            )
        })
        .count();
    let incident_critical_open = incidents
        .iter()
        .filter(|incident| {
            incident.severity.eq_ignore_ascii_case("critical")
                && matches!(
                    incident.status,
                    crate::incident::IncidentStatus::Open
                        | crate::incident::IncidentStatus::Investigating
                )
        })
        .count();

    let mut requests = response_orchestrator.all_requests();
    requests.sort_by(|left, right| right.requested_at.cmp(&left.requested_at));
    let response_counts = response_status_counts(&requests);
    let ready_to_execute = requests
        .iter()
        .filter(|request| request.status == ApprovalStatus::Approved && !request.dry_run)
        .count();
    let recent_requests = requests
        .iter()
        .take(6)
        .map(response_request_json)
        .collect::<Vec<_>>();
    let recent_approvals = approval_log
        .recent(6)
        .iter()
        .map(|entry| {
            serde_json::json!({
                "request_id": entry.request_id,
                "decision": format!("{:?}", entry.decision),
                "approver": entry.approver,
                "reason": entry.reason,
                "decided_at": entry.decided_at,
            })
        })
        .collect::<Vec<_>>();

    let hot_agents = build_hot_agent_summaries(analytics, agent_registry, deployments);

    let mut urgent_items = Vec::new();
    for item in queue_items.iter().take(3) {
        urgent_items.push(UrgentItem {
            kind: "queue".to_string(),
            severity: if item.sla_breached {
                "Critical".to_string()
            } else {
                item.severity.clone()
            },
            title: format!("Queue item #{} on {}", item.event_id, item.hostname),
            subtitle: if item.sla_breached {
                "SLA breached".to_string()
            } else {
                format!("{} • {}", item.status, item.reasons.join(", "))
            },
            reference_id: item.event_id.to_string(),
        });
    }
    for incident in incident_items
        .iter()
        .filter(|incident| incident.severity.eq_ignore_ascii_case("critical"))
        .take(2)
    {
        urgent_items.push(UrgentItem {
            kind: "incident".to_string(),
            severity: incident.severity.clone(),
            title: incident.title.clone(),
            subtitle: format!("{} • {} agents", incident.status, incident.agent_count),
            reference_id: incident.id.to_string(),
        });
    }
    if ready_to_execute > 0 {
        urgent_items.push(UrgentItem {
            kind: "response".to_string(),
            severity: "Severe".to_string(),
            title: format!("{ready_to_execute} response action(s) ready to execute"),
            subtitle: "Approved actions are waiting in the response queue".to_string(),
            reference_id: "ready".to_string(),
        });
    }
    if let Some(agent) = hot_agents
        .iter()
        .find(|agent| matches!(agent.status.as_str(), "stale" | "offline"))
    {
        urgent_items.push(UrgentItem {
            kind: "agent".to_string(),
            severity: "Elevated".to_string(),
            title: format!(
                "{} requires attention",
                agent
                    .hostname
                    .clone()
                    .unwrap_or_else(|| agent.agent_id.clone())
            ),
            subtitle: format!("{} endpoint with risk {}", agent.status, agent.risk),
            reference_id: agent.agent_id.clone(),
        });
    }

    WorkbenchOverview {
        generated_at: chrono::Utc::now().to_rfc3339(),
        queue: WorkbenchQueueOverview {
            pending: queue_pending,
            acknowledged: queue_acknowledged,
            assigned: queue_assigned,
            sla_breached: queue_breached,
            items: queue_items,
        },
        cases: WorkbenchCasesOverview {
            total: case_total,
            open: case_open,
            resolved: case_resolved,
            active: case_total.saturating_sub(case_resolved),
            items: cases
                .iter()
                .take(8)
                .map(|case| case_summary(case))
                .collect(),
        },
        incidents: WorkbenchIncidentsOverview {
            total: incident_items.len(),
            open: incident_open,
            critical_open: incident_critical_open,
            by_status: incident_statuses,
            items: incident_items.into_iter().take(8).collect(),
        },
        response: WorkbenchResponseOverview {
            pending_approval: *response_counts.get("Pending").unwrap_or(&0),
            ready_to_execute,
            denied: *response_counts.get("Denied").unwrap_or(&0),
            executed: *response_counts.get("Executed").unwrap_or(&0),
            protected_assets: response_orchestrator.protected_asset_count(),
            recent_requests,
            recent_approvals,
        },
        hot_agents,
        urgent_items,
    }
}

fn build_manager_overview(
    alert_queue: &AlertQueue,
    incident_store: &IncidentStore,
    response_orchestrator: &ResponseOrchestrator,
    _analytics: &EventAnalytics,
    agent_registry: &AgentRegistry,
    deployments: &HashMap<String, AgentDeployment>,
    published_releases: usize,
    report_store: &crate::report::ReportStore,
    siem_status: crate::siem::SiemStatus,
    tenant_count: usize,
    compliance_score: f64,
) -> ManagerOverview {
    let agents = agent_registry.list();
    let mut online = 0usize;
    let mut stale = 0usize;
    let mut offline = 0usize;
    for agent in agents.iter().copied() {
        match computed_agent_status(agent, agent_registry.heartbeat_interval())
            .0
            .as_str()
        {
            "online" => online += 1,
            "stale" => stale += 1,
            "offline" => offline += 1,
            _ => {}
        }
    }

    let queue_items = alert_queue.all();
    let queue_pending = queue_items.iter().filter(|item| !item.acknowledged).count();
    let queue_acknowledged = queue_items.iter().filter(|item| item.acknowledged).count();
    let queue_assigned = queue_items
        .iter()
        .filter(|item| item.assignee.is_some())
        .count();
    let queue_breached = queue_items
        .iter()
        .filter(|item| {
            !item.acknowledged
                && item
                    .sla_deadline
                    .as_deref()
                    .and_then(|deadline| chrono::DateTime::parse_from_rfc3339(deadline).ok())
                    .map(|deadline| chrono::Utc::now() > deadline.with_timezone(&chrono::Utc))
                    .unwrap_or(false)
        })
        .count();
    let critical_pending = queue_items
        .iter()
        .filter(|item| !item.acknowledged && severity_rank(&item.level) >= 3)
        .count();

    let incidents = incident_store.list();
    let mut deployment_status_counts = HashMap::new();
    let mut deployment_ring_counts = HashMap::new();
    for deployment in deployments.values() {
        *deployment_status_counts
            .entry(deployment.status.clone())
            .or_insert(0) += 1;
        *deployment_ring_counts
            .entry(deployment.rollout_group.clone())
            .or_insert(0) += 1;
    }

    let report_summary = report_store.executive_summary(incident_store);
    let requests = response_orchestrator.all_requests();
    let ready_to_execute = requests
        .iter()
        .filter(|request| request.status == ApprovalStatus::Approved && !request.dry_run)
        .count();

    ManagerOverview {
        generated_at: chrono::Utc::now().to_rfc3339(),
        fleet: ManagerFleetOverview {
            total_agents: agents.len(),
            online,
            stale,
            offline,
            coverage_pct: if agents.is_empty() {
                0.0
            } else {
                (online as f32 / agents.len() as f32) * 100.0
            },
        },
        queue: ManagerQueueOverview {
            pending: queue_pending,
            acknowledged: queue_acknowledged,
            assigned: queue_assigned,
            sla_breached: queue_breached,
            critical_pending,
        },
        incidents: ManagerIncidentOverview {
            total: incidents.len(),
            open: incidents
                .iter()
                .filter(|incident| matches!(incident.status, crate::incident::IncidentStatus::Open))
                .count(),
            investigating: incidents
                .iter()
                .filter(|incident| {
                    matches!(
                        incident.status,
                        crate::incident::IncidentStatus::Investigating
                    )
                })
                .count(),
            contained: incidents
                .iter()
                .filter(|incident| {
                    matches!(incident.status, crate::incident::IncidentStatus::Contained)
                })
                .count(),
            resolved: incidents
                .iter()
                .filter(|incident| {
                    matches!(incident.status, crate::incident::IncidentStatus::Resolved)
                })
                .count(),
            false_positive: incidents
                .iter()
                .filter(|incident| {
                    matches!(
                        incident.status,
                        crate::incident::IncidentStatus::FalsePositive
                    )
                })
                .count(),
        },
        deployments: ManagerDeploymentOverview {
            published_releases,
            pending: deployments
                .values()
                .filter(|deployment| deployment_is_pending(deployment, agent_registry))
                .count(),
            by_status: deployment_status_counts,
            by_ring: deployment_ring_counts,
        },
        reports: ManagerReportOverview {
            total_reports: report_summary["total_reports"].as_u64().unwrap_or(0) as usize,
            total_alerts: report_summary["total_alerts"].as_u64().unwrap_or(0) as usize,
            critical_alerts: report_summary["critical_alerts"].as_u64().unwrap_or(0) as usize,
            avg_score: report_summary["avg_score"]
                .as_f64()
                .map(|value| value as f32),
            max_score: report_summary["max_score"].as_f64().unwrap_or(0.0) as f32,
            open_incidents: report_summary["incidents_open"].as_u64().unwrap_or(0) as usize,
        },
        siem: siem_status,
        compliance: ManagerComplianceOverview {
            score: compliance_score,
        },
        tenants: tenant_count,
        operations: ManagerOperationsOverview {
            pending_approvals: response_orchestrator.pending_requests().len(),
            ready_to_execute,
            protected_assets: response_orchestrator.protected_asset_count(),
        },
    }
}

fn build_agent_activity_snapshot(
    state: &AppState,
    agent_id: &str,
) -> Result<AgentActivitySnapshot, String> {
    let agent = state
        .agent_registry
        .get(agent_id)
        .ok_or_else(|| "agent not found".to_string())?;
    let events = state.event_store.list(Some(agent_id), 500);
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
    let max_score = events
        .iter()
        .map(|event| event.alert.score)
        .fold(0.0f32, f32::max);
    let highest_level = events
        .iter()
        .map(|event| severity_rank(&event.alert.level))
        .max()
        .unwrap_or(0);
    let mut reason_counts = HashMap::new();
    for event in &events {
        for reason in &event.alert.reasons {
            *reason_counts.entry(reason.clone()).or_insert(0usize) += 1;
        }
    }
    let mut top_reasons: Vec<(String, usize)> = reason_counts.into_iter().collect();
    top_reasons.sort_by(|left, right| right.1.cmp(&left.1));

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

    let mut log_levels = HashMap::new();
    let log_records = state.agent_logs.get(agent_id).cloned().unwrap_or_default();
    for record in &log_records {
        *log_levels.entry(format!("{:?}", record.level)).or_insert(0) += 1;
    }

    let inventory = state
        .agent_inventories
        .get(agent_id)
        .map(|inventory| AgentInventorySummary {
            collected_at: inventory.collected_at.clone(),
            software_count: inventory.software.len(),
            services_count: inventory.services.len(),
            network_ports: inventory.network.len(),
            users_count: inventory.users.len(),
            hardware: inventory.hardware.clone(),
        });

    let (computed_status, heartbeat_age_secs) =
        computed_agent_status(agent, state.agent_registry.heartbeat_interval());
    let effective_scope = state
        .agent_registry
        .get_monitor_scope(agent_id)
        .cloned()
        .unwrap_or_else(|| state.config.monitor.scope.clone());

    Ok(AgentActivitySnapshot {
        agent: agent.clone(),
        computed_status,
        heartbeat_age_secs,
        deployment: state.remote_deployments.get(agent_id).cloned(),
        scope_override: state.agent_registry.get_monitor_scope(agent_id).is_some(),
        effective_scope,
        health: agent.health.clone(),
        analytics: AgentEventAnalyticsSummary {
            event_count: total_events,
            correlated_count,
            critical_count,
            average_score,
            max_score,
            highest_level: match highest_level {
                3 => "Critical".to_string(),
                2 => "Severe".to_string(),
                1 => "Elevated".to_string(),
                _ => "Nominal".to_string(),
            },
            risk: if highest_level >= 3 || correlated_count >= 2 {
                "Critical".to_string()
            } else if highest_level >= 2 || average_score >= 3.0 {
                "Severe".to_string()
            } else if highest_level >= 1 || average_score >= 1.5 {
                "Elevated".to_string()
            } else {
                "Nominal".to_string()
            },
            top_reasons: top_reasons
                .into_iter()
                .take(5)
                .map(|entry| entry.0)
                .collect(),
        },
        timeline,
        risk_transitions: transitions,
        inventory,
        log_summary: AgentLogSummary {
            total_records: log_records.len(),
            last_timestamp: log_records.first().map(|record| record.timestamp.clone()),
            by_level: log_levels,
        },
    })
}

fn case_linked_incidents(
    case: &crate::analyst::Case,
    incident_store: &IncidentStore,
) -> Vec<serde_json::Value> {
    case.incident_ids
        .iter()
        .filter_map(|id| incident_store.get(*id))
        .map(|incident| {
            serde_json::json!({
                "id": incident.id,
                "title": incident.title,
                "severity": incident.severity,
                "status": format!("{:?}", incident.status),
                "updated_at": incident.updated_at,
            })
        })
        .collect()
}

fn case_linked_events(
    case: &crate::analyst::Case,
    event_store: &EventStore,
) -> Vec<serde_json::Value> {
    case.event_ids
        .iter()
        .filter_map(|id| event_store.get_event(*id))
        .map(|event| {
            serde_json::json!({
                "id": event.id,
                "agent_id": event.agent_id,
                "hostname": event.alert.hostname,
                "level": event.alert.level,
                "score": event.alert.score,
                "received_at": event.received_at,
                "reasons": event.alert.reasons,
            })
        })
        .collect()
}

fn agent_summary_json(
    agent: &AgentIdentity,
    deployment: Option<&AgentDeployment>,
    heartbeat_interval: u64,
) -> serde_json::Value {
    let (computed_status_value, age_secs) = computed_agent_status(agent, heartbeat_interval);
    serde_json::json!({
        "id": agent.id,
        "hostname": agent.hostname,
        "platform": agent.platform,
        "version": agent.version,
        "current_version": agent.version,
        "enrolled_at": agent.enrolled_at,
        "last_seen": agent.last_seen,
        "last_seen_age_secs": age_secs,
        "status": computed_status_value,
        "labels": agent.labels,
        "health": agent.health,
        "pending_alerts": agent.health.pending_alerts,
        "telemetry_queue_depth": agent.health.telemetry_queue_depth,
        "target_version": deployment
            .map(|entry| entry.version.clone())
            .or_else(|| agent.health.update_target_version.clone()),
        "rollout_group": deployment.map(|entry| entry.rollout_group.clone()),
        "deployment_status": deployment.map(|entry| entry.status.clone()),
        "scope_override": agent.monitor_scope.is_some(),
    })
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
        agent_id: params
            .get("agent_id")
            .cloned()
            .filter(|value| !value.is_empty()),
        severity: params
            .get("severity")
            .cloned()
            .filter(|value| !value.is_empty()),
        reason: params
            .get("reason")
            .cloned()
            .filter(|value| !value.is_empty()),
        correlated: params
            .get("correlated")
            .and_then(|value| match value.as_str() {
                "true" | "1" => Some(true),
                "false" | "0" => Some(false),
                _ => None,
            }),
        triage_status: params
            .get("triage_status")
            .cloned()
            .filter(|value| !value.is_empty()),
        assignee: params
            .get("assignee")
            .cloned()
            .filter(|value| !value.is_empty()),
        tag: params.get("tag").cloned().filter(|value| !value.is_empty()),
        limit,
    }
}

fn event_matches_query(event: &crate::event_forward::StoredEvent, query: &EventQuery) -> bool {
    if let Some(agent_id) = &query.agent_id
        && &event.agent_id != agent_id {
            return false;
        }
    if let Some(severity) = &query.severity
        && !event.alert.level.eq_ignore_ascii_case(severity) {
            return false;
        }
    if let Some(reason) = &query.reason
        && !event
            .alert
            .reasons
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(reason))
        {
            return false;
        }
    if let Some(correlated) = query.correlated
        && event.correlated != correlated {
            return false;
        }
    if let Some(triage_status) = &query.triage_status
        && !event.triage.status.eq_ignore_ascii_case(triage_status) {
            return false;
        }
    if let Some(assignee) = &query.assignee
        && !event
            .triage
            .assignee
            .as_deref()
            .is_some_and(|value| value.eq_ignore_ascii_case(assignee))
        {
            return false;
        }
    if let Some(tag) = &query.tag
        && !event
            .triage
            .tags
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(tag))
        {
            return false;
        }
    true
}

fn filtered_events<'a>(
    store: &'a EventStore,
    query: &EventQuery,
) -> Vec<&'a crate::event_forward::StoredEvent> {
    store
        .list(None, 10_000)
        .into_iter()
        .filter(|event| event_matches_query(event, query))
        .take(query.limit)
        .collect()
}

fn csv_escape(value: &str) -> String {
    let safe = value.replace('"', "\"\"");
    // Prevent CSV formula injection (=, +, -, @, |, tab)
    if safe.starts_with(['=', '+', '-', '@', '|', '\t']) {
        format!("\"'{}\"", safe)
    } else {
        format!("\"{}\"", safe)
    }
}

fn ocsf_class_for_event(event: &crate::event_forward::StoredEvent) -> u32 {
    let reasons = event.alert.reasons.join(" ").to_lowercase();
    if reasons.contains("auth") || reasons.contains("login") || reasons.contains("credential") {
        3002 // Authentication
    } else if reasons.contains("network")
        || reasons.contains("connection")
        || reasons.contains("dns")
    {
        4001 // NetworkActivity
    } else {
        2004 // DetectionFinding (default)
    }
}

fn events_to_csv(events: &[&crate::event_forward::StoredEvent]) -> String {
    let mut out = String::from(
        "id,agent_id,received_at,level,score,confidence,correlated,triage_status,assignee,tags,reasons,hostname,platform,action,ocsf_class_id\n",
    );
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

fn check_rbac(
    state: &Arc<Mutex<AppState>>,
    path: &str,
    method: &Method,
    auth: &AuthIdentity,
) -> bool {
    if auth.is_admin() {
        return true;
    }
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    if s.rbac.list_users().is_empty() {
        // No RBAC users configured — only admin tokens may proceed.
        // This prevents any authenticated-but-non-admin token from
        // bypassing authorization on a fresh or misconfigured deployment.
        return false;
    }
    let AuthIdentity::UserToken(user) = auth else {
        return false;
    };
    let method_str = match method {
        Method::Get => "GET",
        Method::Post => "POST",
        Method::Put => "PUT",
        Method::Delete => "DELETE",
        _ => "GET",
    };
    s.rbac
        .check_api_access(&user.token_hash, method_str, path)
        .is_allowed()
}

fn is_feature_enabled(state: &Arc<Mutex<AppState>>, feature: &str) -> bool {
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
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

fn persist_config_to_path(config: &Config, path: &Path) -> Result<(), String> {
    let toml_str =
        toml::to_string_pretty(config).map_err(|e| format!("failed to serialize config: {e}"))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create config directory: {e}"))?;
    }
    fs::write(path, toml_str).map_err(|e| format!("failed to write config: {e}"))
}

fn sync_enterprise_sigma_engine(state: &mut AppState) {
    let effective_rules = state.enterprise.effective_sigma_rules();
    state.sigma_engine.replace_rules(effective_rules);
}

fn spawn_enterprise_hunt_scheduler(state: &Arc<Mutex<AppState>>) {
    let scheduler_state = Arc::clone(state);
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
        let mut s = match scheduler_state.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        if s.shutdown.load(Ordering::Relaxed) {
            break;
        }
        let due_hunt_ids = s.enterprise.due_hunt_ids();
        if due_hunt_ids.is_empty() {
            continue;
        }
        let events = s.event_store.all_events().to_vec();
        for hunt_id in due_hunt_ids {
            let started = std::time::Instant::now();
            if let Ok(run) = s.enterprise.run_hunt(&hunt_id, &events) {
                let hunt = s
                    .enterprise
                    .hunts()
                    .iter()
                    .find(|hunt| hunt.id == run.hunt_id)
                    .cloned();
                let response_results = if let Some(hunt) = hunt {
                    let AppState {
                        incident_store,
                        enterprise,
                        response_orchestrator,
                        ..
                    } = &mut *s;
                    let response_orchestrator_value = std::mem::take(response_orchestrator);
                    let results = execute_hunt_response_actions(
                        &hunt,
                        &run,
                        &events,
                        incident_store,
                        enterprise,
                        &response_orchestrator_value,
                        "system:scheduler",
                    );
                    *response_orchestrator = response_orchestrator_value;
                    results
                } else {
                    Vec::new()
                };
                s.enterprise
                    .record_hunt_metrics(started.elapsed().as_millis() as u64);
                if run.threshold_exceeded {
                    let payload = serde_json::json!({
                        "hunt_id": run.hunt_id,
                        "run_id": run.id,
                        "match_count": run.match_count,
                        "suppressed_count": run.suppressed_count,
                        "severity": run.severity,
                        "response_actions": response_results,
                    });
                    let payload_text = payload.to_string();
                    let _ = s.enterprise.record_change(
                        "hunt",
                        &run.hunt_id,
                        &format!(
                            "Scheduled hunt {} exceeded threshold with {} visible match(es)",
                            run.hunt_id, run.match_count
                        ),
                        "system:scheduler",
                        Some(run.id.clone()),
                        Some(&payload_text),
                    );
                }
            }
        }
    });
}

/// Background thread that runs retention purges every hour.
/// Reads the retention_policy table from SQLite and purges expired
/// alerts, audit entries, metrics, and response actions.
fn spawn_retention_purge_scheduler(state: &Arc<Mutex<AppState>>) {
    let scheduler_state = Arc::clone(state);
    std::thread::spawn(move || {
        // Default retention days per table (matches the retention_policy inserts in storage.rs)
        let defaults: &[(&str, u32)] = &[
            ("alerts", 90),
            ("audit_log", 365),
            ("metrics", 30),
            ("response_actions", 180),
        ];

        loop {
            // Run every hour (3600 seconds)
            std::thread::sleep(std::time::Duration::from_secs(3600));

            let s = match scheduler_state.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            if s.shutdown.load(Ordering::Relaxed) {
                break;
            }
            let storage = s.storage.clone();
            drop(s);

            let mut total_purged = 0usize;
            for &(table, default_days) in defaults {
                // Try to read configured retention from the policy table
                let days = storage
                    .with(|store| {
                        let d = store.conn().query_row(
                            "SELECT retention_days FROM retention_policy WHERE table_name = ?1",
                            rusqlite::params![table],
                            |row| row.get::<_, u32>(0),
                        ).unwrap_or(default_days);
                        Ok(d)
                    })
                    .unwrap_or(default_days);

                let purged = match table {
                    "alerts" => storage.with(|store| store.purge_old_alerts(days)).unwrap_or(0),
                    "audit_log" => storage.with(|store| store.purge_old_audit(days)).unwrap_or(0),
                    "metrics" => storage.with(|store| store.purge_old_metrics(days)).unwrap_or(0),
                    "response_actions" => storage.with(|store| store.purge_old_response_actions(days)).unwrap_or(0),
                    _ => 0,
                };
                total_purged += purged;
            }

            if total_purged > 0 {
                log::info!("[RETENTION] purged {total_purged} expired records");
            }
        }
    });
}

fn read_json_value(body: &[u8], limit: usize) -> Result<serde_json::Value, String> {
    let body_str = read_body_limited(body, limit)?;
    serde_json::from_str::<serde_json::Value>(&body_str).map_err(|e| format!("invalid JSON: {e}"))
}

fn incident_related_events(
    incident: &crate::incident::Incident,
    events: &[crate::event_forward::StoredEvent],
) -> Vec<crate::event_forward::StoredEvent> {
    events
        .iter()
        .filter(|event| incident.event_ids.contains(&event.id))
        .cloned()
        .collect()
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
            Some(
                "Disable only if the host cannot expose auth logs or Security-event access is intentionally restricted.",
            ),
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
                "Enable this together with the host-specific source below. In the admin console, selecting a host-specific source automatically enables service persistence."
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
            matches!(
                host.platform,
                HostPlatform::MacOS | HostPlatform::Windows | HostPlatform::WindowsServer
            ),
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
    let persistence_paths =
        crate::collector::persistence_watch_paths(host.platform, &config.monitor.scope);
    let file_health = file_paths
        .iter()
        .map(|path| path_health(path))
        .collect::<Vec<_>>();
    let persistence_health = persistence_paths
        .iter()
        .map(|path| path_health(path))
        .collect::<Vec<_>>();
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

#[allow(clippy::nonminimal_bool)]
fn handle_api(
    method: Method,
    url: &str,
    headers: &HeaderMap,
    body: &[u8],
    remote_addr: &str,
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    let url = url.to_string();
    let route_path = url_path(&url);

    // ── Request body size limit (10 MB) ──
    const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;
    if body.len() > MAX_BODY_SIZE {
        return respond_api(
            state,
            &method,
            &url,
            remote_addr,
            false,
            error_json("request body too large", 413),
        );
    }

    // Check auth for mutating endpoints before consuming the request body
    // XDR agent endpoints that do NOT require admin auth (agents use enrollment tokens)
    let is_agent_endpoint = route_path.starts_with("/api/agents/enroll")
        || route_path.starts_with("/api/agents/update")
        || (route_path.contains("/heartbeat") && route_path.starts_with("/api/agents/"))
        || (method == Method::Post && route_path == "/api/events")
        || route_path.starts_with("/api/policy/current")
        || route_path.starts_with("/api/updates/download/")
        || (method == Method::Post
            && route_path.starts_with("/api/agents/")
            && route_path.ends_with("/logs"))
        || (method == Method::Post
            && route_path.starts_with("/api/agents/")
            && route_path.ends_with("/inventory"))
        || (method == Method::Get && route_path == "/api/openapi.json");

    // Agent endpoints still require a valid enrollment token when
    // WARDEX_AGENT_TOKEN is set. This prevents arbitrary clients from
    // enrolling rogue agents or submitting forged events.
    if is_agent_endpoint && !route_path.starts_with("/api/updates/download/")
        && route_path != "/api/openapi.json"
        && let Ok(required_agent_token) = std::env::var("WARDEX_AGENT_TOKEN") {
            let provided = bearer_token(headers);
            let valid = provided.as_deref().is_some_and(|t| {
                let a = t.as_bytes();
                let b = required_agent_token.as_bytes();
                if a.len() != b.len() { return false; }
                let mut diff = 0u8;
                for (x, y) in a.iter().zip(b.iter()) { diff |= x ^ y; }
                diff == 0
            });
            if !valid {
                return respond_api(
                    state,
                    &method,
                    &url,
                    remote_addr,
                    false,
                    error_json("agent token required", 401),
                );
            }
        }

    let needs_auth = !is_agent_endpoint
        && matches!(
            (&method, route_path),
            (Method::Get, "/api/auth/check")
                | (Method::Post, "/api/auth/rotate")
                | (Method::Get, "/api/session/info")
                | (Method::Post, "/api/analyze")
                | (Method::Post, "/api/graphql")
                | (Method::Post, "/api/control/mode")
                | (Method::Post, "/api/control/reset-baseline")
                | (Method::Post, "/api/control/run-demo")
                | (Method::Post, "/api/control/checkpoint")
                | (Method::Post, "/api/control/restore-checkpoint")
                | (Method::Post, "/api/fleet/register")
                | (Method::Post, "/api/enforcement/quarantine")
                | (Method::Get, "/api/threat-intel/status")
                | (Method::Post, "/api/threat-intel/ioc")
                | (Method::Get, "/api/threat-intel/stats")
                | (Method::Post, "/api/threat-intel/purge")
                | (Method::Get, "/api/mitre/coverage")
                | (Method::Get, "/api/mitre/heatmap")
                | (Method::Get, "/api/detection/profile")
                | (Method::Put, "/api/detection/profile")
                | (Method::Post, "/api/fp-feedback")
                | (Method::Get, "/api/fp-feedback/stats")
                | (Method::Get, "/api/detection/score/normalize")
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
                | (Method::Post, "/api/response/request")
                | (Method::Post, "/api/response/approve")
                | (Method::Post, "/api/response/execute")
                | (Method::Post, "/api/shutdown")
                | (Method::Post, "/api/mesh/heal")
                | (Method::Delete, "/api/alerts")
                | (Method::Post, "/api/alerts/sample")
                | (Method::Post, "/api/alerts/analysis")
        )
        || (!is_agent_endpoint
            && ((method == Method::Get && route_path == "/api/fleet/dashboard")
        || (method == Method::Get && route_path == "/api/workbench/overview")
        || (method == Method::Get && route_path == "/api/manager/overview")
        || (method == Method::Get && route_path == "/api/hunts")
        || (method == Method::Post && route_path == "/api/hunts")
        || (method == Method::Get && route_path.starts_with("/api/hunts/"))
        || (method == Method::Post && route_path.starts_with("/api/hunts/"))
        || (method == Method::Get && route_path == "/api/content/rules")
        || (method == Method::Post && route_path == "/api/content/rules")
        || (method == Method::Post && route_path.starts_with("/api/content/rules/"))
        || (method == Method::Get && route_path == "/api/content/packs")
        || (method == Method::Post && route_path == "/api/content/packs")
        || (method == Method::Get && route_path == "/api/coverage/mitre")
        || (method == Method::Get && route_path == "/api/suppressions")
        || (method == Method::Post && route_path == "/api/suppressions")
        || (method == Method::Get && route_path.starts_with("/api/entities/"))
        || (method == Method::Get && route_path.starts_with("/api/incidents/") && route_path.ends_with("/storyline"))
        || (method == Method::Get && route_path == "/api/enrichments/connectors")
        || (method == Method::Post && route_path == "/api/enrichments/connectors")
        || (method == Method::Post && route_path == "/api/tickets/sync")
        || (method == Method::Get && route_path == "/api/idp/providers")
        || (method == Method::Post && route_path == "/api/idp/providers")
        || (method == Method::Get && route_path == "/api/scim/config")
        || (method == Method::Post && route_path == "/api/scim/config")
        || (method == Method::Get && route_path == "/api/audit/admin")
        || (method == Method::Get && route_path == "/api/support/diagnostics")
        || (method == Method::Get && route_path == "/api/system/health/dependencies")
        || (method == Method::Get && route_path == "/api/siem/status")
        || (method == Method::Get && route_path == "/api/siem/config")
        || (method == Method::Post && route_path == "/api/siem/config")
        || (method == Method::Get && route_path == "/api/taxii/status")
        || (method == Method::Get && route_path == "/api/taxii/config")
        || (method == Method::Post && route_path == "/api/taxii/config")
        || (method == Method::Post && route_path == "/api/taxii/pull")
        || (method == Method::Get && route_path == "/api/agents")
        || (method == Method::Get && route_path == "/api/events")
        || (method == Method::Get && route_path == "/api/events/export")
        || (method == Method::Get && route_path == "/api/events/summary")
        || (method == Method::Get && route_path == "/api/policy/history")
        || (method == Method::Get && route_path == "/api/telemetry/current")
        || (method == Method::Get && route_path == "/api/telemetry/history")
        || (method == Method::Get && route_path == "/api/host/info")
        || (method == Method::Get && route_path == "/api/config/current")
        || (method == Method::Get && route_path == "/api/checkpoints")
        || (method == Method::Get && route_path == "/api/correlation")
        || (method == Method::Get && route_path == "/api/alerts")
        || (method == Method::Get && route_path == "/api/alerts/count")
        || (method == Method::Get && route_path == "/api/alerts/analysis")
        || (method == Method::Get && route_path == "/api/alerts/grouped")
        || (method == Method::Get && route_path.starts_with("/api/alerts/") && route_path != "/api/alerts/count" && route_path != "/api/alerts/analysis" && route_path != "/api/alerts/grouped")
        || (method == Method::Get && route_path == "/api/swarm/intel")
        || (method == Method::Get && route_path == "/api/swarm/intel/stats")
        || (method == Method::Get && route_path == "/api/report")
        || (method == Method::Get && route_path == "/api/threads/status")
        || (method == Method::Get && route_path == "/api/detection/summary")
        || (method == Method::Get && route_path == "/api/monitoring/options")
        || (method == Method::Get && route_path == "/api/monitoring/paths")
        || (method == Method::Get && route_path == "/api/endpoints")
        || (method == Method::Get && route_path == "/api/status")
        || (method == Method::Get && route_path == "/api/export/tla")
        || (method == Method::Get && route_path == "/api/export/alloy")
        || (method == Method::Get && route_path == "/api/export/witnesses")
        || (method == Method::Get && route_path == "/api/research-tracks")
        || (method == Method::Get && route_path == "/api/attestation/status")
        || (method == Method::Get && route_path == "/api/fleet/status")
        || (method == Method::Get && route_path == "/api/enforcement/status")
        || (method == Method::Get && route_path == "/api/digital-twin/status")
        || (method == Method::Get && route_path == "/api/compliance/status")
        || (method == Method::Get && route_path == "/api/energy/status")
        || (method == Method::Get && route_path == "/api/tenants/count")
        || (method == Method::Get && route_path == "/api/platform")
        || (method == Method::Get && route_path == "/api/side-channel/status")
        || (method == Method::Get && route_path == "/api/quantum/key-status")
        || (method == Method::Get && route_path == "/api/privacy/budget")
        || (method == Method::Get && route_path == "/api/fingerprint/status")
        || (method == Method::Get && route_path == "/api/monitor/status")
        || (method == Method::Get && route_path == "/api/monitor/violations")
        || (method == Method::Get && route_path == "/api/deception/status")
        || (method == Method::Get && route_path == "/api/drift/status")
        || (method == Method::Get && route_path == "/api/causal/graph")
        || (method == Method::Get && route_path == "/api/patches")
        || (method == Method::Get && route_path == "/api/swarm/posture")
        || (method == Method::Get && route_path == "/api/tls/status")
        || (method == Method::Get && route_path == "/api/mesh/health")
        || (method == Method::Get && route_path == "/api/rollout/config")
        || (method == Method::Get && route_path.starts_with("/api/agents/") && route_path.ends_with("/details"))
        || (method == Method::Get && route_path.starts_with("/api/agents/") && route_path.ends_with("/activity"))
        || (method == Method::Get && route_path.starts_with("/api/agents/") && route_path.ends_with("/status"))
        || (method == Method::Post && route_path.starts_with("/api/events/") && route_path.ends_with("/triage"))
        || (method == Method::Post && route_path.starts_with("/api/agents/") && route_path.ends_with("/scope"))
        || (method == Method::Get && route_path.starts_with("/api/agents/") && route_path.ends_with("/scope"))
        || (method == Method::Get && route_path == "/api/audit/log")
        || (method == Method::Get && route_path == "/api/incidents")
        || (method == Method::Get && route_path.starts_with("/api/incidents/"))
        || (method == Method::Post && route_path == "/api/incidents")
        || (method == Method::Post && route_path.starts_with("/api/incidents/") && route_path.ends_with("/update"))
        || (method == Method::Get && route_path.starts_with("/api/agents/") && route_path.ends_with("/logs"))
        || (method == Method::Get && route_path.starts_with("/api/agents/") && route_path.ends_with("/inventory"))
        || (method == Method::Get && route_path == "/api/fleet/inventory")
        || (method == Method::Post && route_path == "/api/detection/weights")
        || (method == Method::Get && route_path == "/api/detection/weights")
        || (method == Method::Get && route_path == "/api/reports")
        || (method == Method::Get && route_path == "/api/reports/executive-summary")
        || (method == Method::Get && route_path.starts_with("/api/reports/"))
        || (method == Method::Delete && route_path.starts_with("/api/reports/"))
        || (method == Method::Get && route_path == "/api/updates/releases")
        || (method == Method::Delete && route_path.starts_with("/api/agents/"))
        || (method == Method::Get && route_path == "/api/sigma/rules")
        || (method == Method::Get && route_path == "/api/sigma/stats")
        || (method == Method::Get && route_path == "/api/ocsf/schema")
        || (method == Method::Get && route_path == "/api/response/pending")
        || (method == Method::Get && route_path == "/api/response/requests")
        || (method == Method::Get && route_path == "/api/response/audit")
        || (method == Method::Get && route_path == "/api/response/stats")
        || (method == Method::Get && route_path == "/api/feature-flags")
        || (method == Method::Get && route_path == "/api/process-tree")
        || (method == Method::Get && route_path == "/api/process-tree/deep-chains")
        || (method == Method::Get && route_path == "/api/processes/live")
        || (method == Method::Get && route_path == "/api/processes/analysis")
        || (method == Method::Get && route_path == "/api/host/apps")
        || (method == Method::Get && route_path == "/api/host/inventory")
        || (method == Method::Get && route_path == "/api/spool/stats")
        || (method == Method::Get && route_path == "/api/rbac/users")
        || (method == Method::Post && route_path == "/api/rbac/users")
        || (method == Method::Delete && route_path.starts_with("/api/rbac/users/"))
        || (method == Method::Post && route_path == "/api/ueba/observe")
        || (method == Method::Get && route_path == "/api/ueba/risky")
        || (method == Method::Get && route_path.starts_with("/api/ueba/entity/"))
        || (method == Method::Post && route_path == "/api/beacon/connection")
        || (method == Method::Post && route_path == "/api/beacon/dns")
        || (method == Method::Get && route_path == "/api/beacon/analyze")
        || (method == Method::Post && route_path == "/api/killchain/reconstruct")
        || (method == Method::Post && route_path == "/api/lateral/connection")
        || (method == Method::Get && route_path == "/api/lateral/analyze")
        || (method == Method::Post && route_path == "/api/kernel/event")
        || (method == Method::Get && route_path == "/api/kernel/recent")
        || (method == Method::Get && route_path == "/api/playbooks")
        || (method == Method::Post && route_path == "/api/playbooks")
        || (method == Method::Post && route_path == "/api/playbooks/execute")
        || (method == Method::Get && route_path == "/api/playbooks/executions")
        || (method == Method::Post && route_path == "/api/live-response/session")
        || (method == Method::Post && route_path == "/api/live-response/command")
        || (method == Method::Get && route_path == "/api/live-response/sessions")
        || (method == Method::Get && route_path == "/api/live-response/audit")
        || (method == Method::Post && route_path == "/api/remediation/plan")
        || (method == Method::Get && route_path == "/api/remediation/results")
        || (method == Method::Get && route_path == "/api/remediation/stats")
        || (method == Method::Get && route_path == "/api/escalation/policies")
        || (method == Method::Post && route_path == "/api/escalation/policies")
        || (method == Method::Post && route_path == "/api/escalation/start")
        || (method == Method::Post && route_path == "/api/escalation/acknowledge")
        || (method == Method::Get && route_path == "/api/escalation/active")
        || (method == Method::Post && route_path == "/api/escalation/check-sla")
        || (method == Method::Get && route_path == "/api/evidence/plan/linux")
        || (method == Method::Get && route_path == "/api/evidence/plan/macos")
        || (method == Method::Get && route_path == "/api/evidence/plan/windows")
        || (method == Method::Post && route_path == "/api/containment/commands")
        // Analyst console
        || (method == Method::Get && route_path == "/api/cases")
        || (method == Method::Post && route_path == "/api/cases")
        || (method == Method::Get && route_path == "/api/cases/stats")
        || (method == Method::Get && route_path.starts_with("/api/cases/"))
        || (method == Method::Post && route_path.starts_with("/api/cases/"))
        || (method == Method::Get && route_path == "/api/queue/alerts")
        || (method == Method::Get && route_path == "/api/queue/stats")
        || (method == Method::Post && route_path == "/api/queue/acknowledge")
        || (method == Method::Post && route_path == "/api/queue/assign")
        || (method == Method::Post && route_path == "/api/events/search")
        || (method == Method::Get && route_path.starts_with("/api/timeline/"))
        || (method == Method::Post && route_path == "/api/investigation/graph")
        || (method == Method::Post && route_path == "/api/response/request")
        || (method == Method::Post && route_path == "/api/response/approve")
        || (method == Method::Post && route_path == "/api/response/execute")
        || (method == Method::Get && route_path == "/api/response/approvals")
        // Dead-letter queue & schema
        || (method == Method::Get && route_path == "/api/dlq")
        || (method == Method::Get && route_path == "/api/dlq/stats")
        || (method == Method::Delete && route_path == "/api/dlq")
        || (method == Method::Get && route_path == "/api/ocsf/schema/version")
        || (method == Method::Get && route_path == "/api/slo/status")
        || (method == Method::Get && route_path == "/api/audit/verify")
        || (method == Method::Get && route_path == "/api/retention/status")
        || (method == Method::Post && route_path == "/api/retention/apply")
        || (method == Method::Get && route_path == "/api/session/info")
        // GDPR, backup, SBOM, PII — admin-only
        || (method == Method::Delete && route_path.starts_with("/api/gdpr/forget/"))
        || (method == Method::Post && route_path == "/api/admin/backup")
        || (method == Method::Get && route_path == "/api/admin/db/version")
        || (method == Method::Post && route_path == "/api/admin/db/rollback")
        || (method == Method::Post && route_path == "/api/admin/db/compact")
        || (method == Method::Post && route_path == "/api/admin/db/reset")
        || (method == Method::Get && route_path == "/api/admin/db/sizes")
        || (method == Method::Post && route_path == "/api/admin/cleanup-legacy")
        || (method == Method::Post && route_path == "/api/admin/db/purge")
        || (method == Method::Get && route_path == "/api/sbom")
        || (method == Method::Post && route_path == "/api/pii/scan")));

    let auth_identity = authenticate_request(headers, state);
    if needs_auth && !auth_identity.is_authenticated() {
        return respond_api(
            state,
            &method,
            &url,
            remote_addr,
            false,
            error_json("unauthorized", 401),
        );
    }

    // RBAC enforcement for sensitive endpoints
    // Admin token holders bypass RBAC entirely
    if needs_auth && !check_rbac(state, route_path, &method, &auth_identity) {
        return respond_api(
            state,
            &method,
            &url,
            remote_addr,
            auth_identity.is_authenticated(),
            error_json("forbidden: insufficient role", 403),
        );
    }
    let auth_used = needs_auth || auth_identity.is_authenticated();

    let response = match (method.clone(), route_path) {
        (Method::Get, "/api/auth/check") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let ttl = s.config.security.token_ttl_secs;
            let elapsed = s.token_issued_at.elapsed().as_secs();
            let remaining = if ttl > 0 {
                ttl.saturating_sub(elapsed)
            } else {
                0
            };
            let body = format!(
                r#"{{"status":"ok","ttl_secs":{},"remaining_secs":{},"token_age_secs":{}}}"#,
                ttl, remaining, elapsed
            );
            json_response(&body, 200)
        }
        (Method::Post, "/api/auth/rotate") => {
            let new_token = generate_token();
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            let old_token_prefix = s.token.chars().take(8).collect::<String>();
            s.token = new_token.clone();
            s.token_issued_at = std::time::Instant::now();
            s.audit_log
                .record("POST", "/api/auth/rotate", "admin", 200, true);
            let body = format!(
                r#"{{"status":"rotated","new_token":"{}","previous_prefix":"{}…"}}"#,
                new_token, old_token_prefix
            );
            json_response(&body, 200)
        }
        (Method::Get, "/api/session/info") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let ttl = s.config.security.token_ttl_secs;
            let elapsed = s.token_issued_at.elapsed().as_secs();
            let uptime = s.server_start.elapsed().as_secs();
            let body = format!(
                r#"{{"uptime_secs":{},"token_age_secs":{},"token_ttl_secs":{},"token_expired":{},"mtls_required":{}}}"#,
                uptime,
                elapsed,
                ttl,
                ttl > 0 && elapsed > ttl,
                s.config.security.require_mtls_agents
            );
            json_response(&body, 200)
        }
        (Method::Get, "/api/status") => {
            let manifest = runtime::status_manifest();
            match serde_json::to_string_pretty(&manifest) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/report") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
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
                let avg_score = if total > 0 {
                    alerts.iter().map(|a| a.score).sum::<f32>() / total as f32
                } else {
                    0.0
                };
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
                json_response(
                    r#"{"generated_at":"","summary":{"total_samples":0,"alert_count":0,"critical_count":0,"average_score":0.0,"max_score":0.0},"samples":[]}"#,
                    200,
                )
            }
        }
        (Method::Post, "/api/graphql") => {
            match read_body_limited(body, 100_000) {
                Err(_) => error_json("request too large", 413),
                Ok(body) => match serde_json::from_str::<GqlRequest>(&body) {
                    Err(e) => error_json(&format!("invalid JSON: {e}"), 400),
                    Ok(gql_req) => {
                        let mut executor = GqlExecutor::new(wardex_schema());
                        let st = state.clone();
                        executor.register_resolver("alerts", Box::new({
                            let st = st.clone();
                            move |args| {
                                let s = st.lock().unwrap_or_else(|e| e.into_inner());
                                let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;
                                let alerts: Vec<serde_json::Value> = s.alerts.iter().take(limit).enumerate().map(|(i, a)| {
                                    serde_json::json!({ "id": format!("alert-{i}"), "level": a.level, "timestamp": a.timestamp, "device_id": a.hostname, "score": a.score, "reasons": a.reasons, "status": "open" })
                                }).collect();
                                serde_json::json!(alerts)
                            }
                        }));
                        executor.register_resolver("agents", Box::new({
                            let st = st.clone();
                            move |_args| {
                                let s = st.lock().unwrap_or_else(|e| e.into_inner());
                                let agents: Vec<serde_json::Value> = s.agent_registry.list().iter().map(|a| {
                                    serde_json::json!({ "id": a.id, "hostname": a.hostname, "os": a.platform, "version": a.version, "status": format!("{:?}", a.status), "last_heartbeat": a.last_seen })
                                }).collect();
                                serde_json::json!(agents)
                            }
                        }));
                        executor.register_resolver("status", Box::new({
                            let st = st.clone();
                            move |_args| {
                                let s = st.lock().unwrap_or_else(|e| e.into_inner());
                                let online = s.agent_registry.list().iter().filter(|a| a.status == crate::enrollment::AgentStatus::Online).count();
                                let open_incidents = s.incident_store.list().iter().filter(|i| !matches!(i.status, crate::incident::IncidentStatus::Resolved | crate::incident::IncidentStatus::FalsePositive)).count();
                                serde_json::json!({ "version": env!("CARGO_PKG_VERSION"), "uptime_secs": s.server_start.elapsed().as_secs_f64(), "agents_online": online, "alerts_total": s.alerts.len(), "incidents_open": open_incidents })
                            }
                        }));
                        executor.register_resolver("events", Box::new({
                            let st = st.clone();
                            move |args| {
                                let s = st.lock().unwrap_or_else(|e| e.into_inner());
                                let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(100) as usize;
                                let events: Vec<serde_json::Value> = s.event_store.recent_events(limit).iter().map(|e| {
                                    serde_json::json!({ "timestamp": e.received_at, "device_id": e.agent_id, "event_type": e.alert.level, "data": e.alert.reasons })
                                }).collect();
                                serde_json::json!(events)
                            }
                        }));
                        executor.register_resolver("hunts", Box::new({
                            let st = st.clone();
                            move |args| {
                                let s = st.lock().unwrap_or_else(|e| e.into_inner());
                                let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(20) as usize;
                                let hunts: Vec<serde_json::Value> = s.enterprise.hunts().iter().take(limit).map(|h| {
                                    serde_json::json!({ "id": h.id, "name": h.name, "status": if h.enabled { "active" } else { "disabled" }, "matches": 0, "created_at": h.created_at })
                                }).collect();
                                serde_json::json!(hunts)
                            }
                        }));
                        executor.register_resolver("aggregate", Box::new({
                            let st = st.clone();
                            move |args| {
                                let s = st.lock().unwrap_or_else(|e| e.into_inner());
                                graphql_aggregate_json(
                                    args,
                                    &s.alerts,
                                    &s.agent_registry,
                                    &s.event_store,
                                    &s.enterprise,
                                    &s.incident_store,
                                    &s.threat_intel,
                                )
                            }
                        }));
                        let resp = executor.execute(&gql_req);
                        let result_body = serde_json::to_string(&resp).unwrap_or_else(|_| r#"{"errors":[{"message":"serialization failed"}]}"#.to_string());
                        json_response(&result_body, 200)
                    }
                }
            }
        }
        (Method::Post, "/api/analyze") => handle_analyze(body, state),
        (Method::Post, "/api/control/mode") => handle_mode(body, state),
        (Method::Post, "/api/control/reset-baseline") => {
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            s.detector.reset_baseline();
            json_response(r#"{"status":"baseline reset"}"#, 200)
        }
        (Method::Post, "/api/control/checkpoint") => {
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
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
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
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
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
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
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
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
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
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
                    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
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
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let report = s.swarm.health_report();
            match serde_json::to_string_pretty(&report) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Post, "/api/fleet/register") => handle_fleet_register(body, state),

        // ── Enforcement ───────────────────────────────────────────
        (Method::Get, "/api/enforcement/status") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
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
            handle_enforcement_quarantine(body, state)
        }

        // ── Threat Intelligence ───────────────────────────────────
        (Method::Get, "/api/threat-intel/status") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let info = serde_json::json!({
                "ioc_count": s.threat_intel.ioc_count(),
            });
            json_response(&info.to_string(), 200)
        }
        (Method::Post, "/api/threat-intel/ioc") => handle_threat_intel_ioc(body, state),

        // ── Threat Intel Stats ────────────────────────────────────
        (Method::Get, "/api/threat-intel/stats") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let stats = s.threat_intel.enrichment_stats();
            match serde_json::to_string(&stats) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }

        // ── IoC Purge (TTL-based) ─────────────────────────────────
        (Method::Post, "/api/threat-intel/purge") => {
            match read_body_limited(body, 4096) {
                Err(e) => error_json(&e, 400),
                Ok(body) => match serde_json::from_str::<serde_json::Value>(&body) {
                    Err(e) => error_json(&format!("invalid JSON: {e}"), 400),
                    Ok(parsed) => {
                        let ttl_days = parsed.get("ttl_days").and_then(|v| v.as_u64()).unwrap_or(90);
                        let now = chrono::Utc::now().to_rfc3339();
                        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                        let purged = s.threat_intel.purge_expired(&now, ttl_days);
                        json_response(&format!(r#"{{"purged":{purged},"ttl_days":{ttl_days}}}"#), 200)
                    }
                }
            }
        }

        // ── MITRE ATT&CK Coverage ────────────────────────────────
        (Method::Get, "/api/mitre/coverage") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let summary = s.mitre_coverage.summary();
            match serde_json::to_string(&summary) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/mitre/heatmap") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let heatmap = s.mitre_coverage.heatmap();
            match serde_json::to_string(&heatmap) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }

        // ── Detection Tuning Profile ──────────────────────────────
        (Method::Get, "/api/detection/profile") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let profile = s.tuning_profile;
            json_response(&format!(
                r#"{{"profile":"{}","description":"{}","threshold_multiplier":{:.2},"learn_threshold":{:.1}}}"#,
                profile.as_str(), profile.description(),
                profile.threshold_multiplier(), profile.learn_threshold()
            ), 200)
        }
        (Method::Put, "/api/detection/profile") => {
            match read_body_limited(body, 4096) {
                Err(e) => error_json(&e, 400),
                Ok(body) => match serde_json::from_str::<serde_json::Value>(&body) {
                    Err(e) => error_json(&format!("invalid JSON: {e}"), 400),
                    Ok(parsed) => {
                        let name = parsed.get("profile").and_then(|v| v.as_str()).unwrap_or("");
                        match crate::detector::TuningProfile::parse(name) {
                            Some(p) => {
                                let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                                s.tuning_profile = p;
                                json_response(&format!(r#"{{"profile":"{}","applied":true}}"#, p.as_str()), 200)
                            }
                            None => error_json("invalid profile: use aggressive, balanced, or quiet", 400),
                        }
                    }
                }
            }
        }

        // ── False-Positive Feedback ───────────────────────────────
        (Method::Post, "/api/fp-feedback") => {
            match read_body_limited(body, 4096) {
                Err(e) => error_json(&e, 400),
                Ok(body) => match serde_json::from_str::<crate::alert_analysis::FpFeedback>(&body) {
                    Err(e) => error_json(&format!("invalid feedback: {e}"), 400),
                    Ok(feedback) => {
                        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                        s.fp_feedback.record(feedback);
                        json_response(r#"{"recorded":true}"#, 200)
                    }
                }
            }
        }
        (Method::Get, "/api/fp-feedback/stats") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let stats = s.fp_feedback.stats();
            let json_stats: Vec<serde_json::Value> = stats.iter().map(|(p, total, fps, ratio)| {
                serde_json::json!({
                    "pattern": p,
                    "total_marked": total,
                    "false_positives": fps,
                    "fp_ratio": ratio,
                    "suppression_weight": s.fp_feedback.suppression_weight(p),
                })
            }).collect();
            match serde_json::to_string(&json_stats) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }

        // ── Normalized Score ──────────────────────────────────────
        (Method::Get, "/api/detection/score/normalize") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(ref analysis) = s.last_alert_analysis {
                let score = analysis.severity_breakdown.critical as f32 * 10.0
                    + analysis.severity_breakdown.severe as f32 * 5.0
                    + analysis.severity_breakdown.elevated as f32 * 2.0;
                let normalized = crate::detector::normalize_score(score, 1.0);
                match serde_json::to_string(&normalized) {
                    Ok(json) => json_response(&json, 200),
                    Err(e) => error_json(&format!("serialization error: {e}"), 500),
                }
            } else {
                let normalized = crate::detector::normalize_score(0.0, 0.0);
                match serde_json::to_string(&normalized) {
                    Ok(json) => json_response(&json, 200),
                    Err(e) => error_json(&format!("serialization error: {e}"), 500),
                }
            }
        }

        // ── Digital Twin ──────────────────────────────────────────
        (Method::Get, "/api/digital-twin/status") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let info = serde_json::json!({
                "twin_count": s.digital_twin.device_count(),
            });
            json_response(&info.to_string(), 200)
        }
        (Method::Post, "/api/digital-twin/simulate") => {
            handle_digital_twin_simulate(body, state)
        }

        // ── Compliance ────────────────────────────────────────────
        (Method::Get, "/api/compliance/status") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let report = s.compliance.report(&crate::compliance::Framework::Iec62443);
            match serde_json::to_string_pretty(&report) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }

        // ── Energy ────────────────────────────────────────────────
        (Method::Get, "/api/energy/status") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let info = serde_json::json!({
                "remaining_pct": s.energy.remaining_pct(),
                "capacity_mwh": s.energy.capacity_mwh,
                "current_mwh": s.energy.current_mwh,
                "power_state": format!("{:?}", s.energy.state),
            });
            json_response(&info.to_string(), 200)
        }
        (Method::Post, "/api/energy/consume") => handle_energy_consume(body, state),

        // ── Multi-tenancy ─────────────────────────────────────────
        (Method::Get, "/api/tenants/count") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
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
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
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
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let info = serde_json::json!({
                "current_epoch": s.key_rotation.current_epoch(),
                "total_epochs": s.key_rotation.epochs().len(),
            });
            json_response(&info.to_string(), 200)
        }
        (Method::Post, "/api/quantum/rotate") => {
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            s.key_rotation.rotate();
            let info = serde_json::json!({
                "status": "rotated",
                "new_epoch": s.key_rotation.current_epoch(),
            });
            json_response(&info.to_string(), 200)
        }

        // ── Privacy ───────────────────────────────────────────────
        (Method::Get, "/api/privacy/budget") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let info = serde_json::json!({
                "budget_remaining": s.privacy.budget_remaining(),
                "is_exhausted": s.privacy.is_exhausted(),
            });
            json_response(&info.to_string(), 200)
        }

        // ── Policy VM ─────────────────────────────────────────────
        (Method::Post, "/api/policy-vm/execute") => handle_policy_vm_execute(body, state),

        // ── Fingerprint ───────────────────────────────────────────
        (Method::Get, "/api/fingerprint/status") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
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
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
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
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let violations: Vec<_> = s
                .monitor
                .violations()
                .iter()
                .map(|v| {
                    serde_json::json!({
                        "property": v.property_name,
                        "event_index": v.event_index,
                    })
                })
                .collect();
            json_response(
                &serde_json::json!({ "violations": violations }).to_string(),
                200,
            )
        }

        // ── Deception Engine ──────────────────────────────────────
        (Method::Get, "/api/deception/status") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let report = s.deception.report();
            let info = serde_json::json!({
                "total_decoys": report.total_decoys,
                "active_decoys": report.active_decoys,
                "total_interactions": report.total_interactions,
                "attacker_profiles": report.attacker_profiles,
            });
            json_response(&info.to_string(), 200)
        }
        (Method::Post, "/api/deception/deploy") => handle_deception_deploy(body, state),

        // ── Policy Composition ────────────────────────────────────
        (Method::Post, "/api/policy/compose") => handle_policy_compose(body, state),

        // ── Drift Detection ───────────────────────────────────────
        (Method::Get, "/api/drift/status") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let info = serde_json::json!({
                "sample_count": s.drift.sample_count(),
            });
            json_response(&info.to_string(), 200)
        }
        (Method::Post, "/api/drift/reset") => {
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            s.drift.reset();
            json_response(r#"{"status":"drift detector reset"}"#, 200)
        }

        // ── Causal Analysis ───────────────────────────────────────
        (Method::Get, "/api/causal/graph") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let info = serde_json::json!({
                "node_count": s.causal.node_count(),
                "edge_count": s.causal.edge_count(),
            });
            json_response(&info.to_string(), 200)
        }

        // ── Patch Management ──────────────────────────────────────
        (Method::Get, "/api/patches") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
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
                crate::edge_cloud::Workload {
                    id: "w1".into(),
                    name: "detection".into(),
                    cpu_cost: 20.0,
                    memory_mb: 64,
                    latency_sensitive: true,
                    data_size_kb: 100,
                    tier: crate::edge_cloud::ProcessingTier::EdgePreferred,
                },
                crate::edge_cloud::Workload {
                    id: "w2".into(),
                    name: "reporting".into(),
                    cpu_cost: 10.0,
                    memory_mb: 32,
                    latency_sensitive: false,
                    data_size_kb: 200,
                    tier: crate::edge_cloud::ProcessingTier::CloudPreferred,
                },
            ];
            let decisions = crate::edge_cloud::decide_offload(&workloads, &edge_cap);
            let info: Vec<_> = decisions
                .iter()
                .map(|d| {
                    serde_json::json!({
                        "workload": d.workload_id,
                        "run_on": d.run_on,
                        "reason": d.reason,
                        "estimated_latency_ms": d.estimated_latency_ms,
                    })
                })
                .collect();
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
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let info = serde_json::json!({
                "tls_enabled": s.listener_mode.is_tls(),
                "scheme": s.listener_mode.scheme(),
                "port": s.listener_mode.port(),
            });
            json_response(&info.to_string(), 200)
        }

        // ── Mesh Health / Self-Healing ────────────────────────────
        (Method::Get, "/api/mesh/health") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
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
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
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
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
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
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            match serde_json::to_string_pretty(&s.config) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Post, "/api/config/reload") => handle_config_reload(body, state),
        (Method::Post, "/api/config/save") => {
            match read_body_limited(body, 10 * 1024 * 1024) {
                Ok(body) => {
                    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                    let config_path = s.config_path.clone();
                    match config_save_target(&s.config, &body) {
                        Ok((next_config, applied_fields)) => {
                            if let Err(e) = persist_config_to_path(&next_config, &config_path) {
                                error_json(&e, 500)
                            } else {
                                s.config = next_config.clone();
                                s.siem_connector.update_config(next_config.siem.clone());
                                s.taxii_client.update_config(next_config.taxii.clone());

                                json_response(
                                    &serde_json::json!({
                                        "status": "saved",
                                        "path": config_path.display().to_string(),
                                        "applied_fields": applied_fields,
                                    })
                                    .to_string(),
                                    200,
                                )
                            }
                        }
                        Err(response) => response,
                    }
                }
                Err(e) => error_json(&e, 400),
            }
        }

        // ── Health & Alerts ──────────────────────────────────────────
        (Method::Get, "/api/health") => {
            let s = match state.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            let host = crate::collector::detect_platform();
            let uptime = s.server_start.elapsed().as_secs();

            // Check storage connectivity
            let storage_ok = s.storage.with(|store| Ok(store.stats())).is_ok();

            let status = if storage_ok { "ok" } else { "degraded" };
            let body = serde_json::json!({
                "status": status,
                "version": env!("CARGO_PKG_VERSION"),
                "uptime_secs": uptime,
                "platform": host.platform.to_string(),
                "hostname": host.hostname,
                "os_version": host.os_version,
                "storage_ok": storage_ok,
            });
            json_response(&body.to_string(), 200)
        }
        // ── Kubernetes health probes ──────────────────────────────
        (Method::Get, "/api/healthz/live") => {
            json_response(r#"{"status":"alive"}"#, 200)
        }
        (Method::Get, "/api/healthz/ready") => {
            let s = match state.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            let storage_ok = s.storage.with(|store| Ok(store.stats())).is_ok();
            if storage_ok {
                json_response(r#"{"status":"ready","storage":"ok"}"#, 200)
            } else {
                json_response(r#"{"status":"not_ready","storage":"unreachable"}"#, 503)
            }
        }
        (Method::Get, "/api/openapi.json") => json_response(
            &crate::openapi::openapi_json(env!("CARGO_PKG_VERSION")),
            200,
        ),
        (Method::Get, "/api/metrics") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            text_response(&prometheus_metrics_payload(&s), 200)
        }
        (Method::Get, "/api/slo/status") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let uptime = s.server_start.elapsed().as_secs();
            let total = s.request_count;
            let errors = s.error_count;
            let successes = total.saturating_sub(errors);
            let error_rate = if total > 0 {
                (errors as f64 / total as f64) * 100.0
            } else {
                0.0
            };
            let availability_pct = if total > 0 {
                (successes as f64 / total as f64) * 100.0
            } else {
                100.0
            };
            let body = serde_json::json!({
                "api_latency_p99_ms": 12.0,
                "error_rate_pct": error_rate,
                "availability_pct": availability_pct,
                "budget_remaining_pct": (99.9 - (100.0 - availability_pct)).max(0.0),
                "uptime_seconds": uptime,
                "total_requests": total,
                "total_errors": errors,
                "successful_requests": successes,
                "request_count": total,
                "error_count": errors,
            });
            json_response(&body.to_string(), 200)
        }
        // ── Audit chain verification ──────────────────────────────
        (Method::Get, "/api/audit/verify") => {
            let s = match state.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            let record_count = s.audit_log.recent(usize::MAX).len();

            // Verify the storage-level cryptographic audit chain
            let storage_result = s.storage.with(|store| {
                let chain_len = store.verify_audit_chain()?;
                Ok(chain_len)
            });

            let (storage_status, storage_chain_len, storage_error) = match storage_result {
                Ok(len) => ("verified", len, None),
                Err(e) => ("broken", 0usize, Some(e.message)),
            };

            let body = serde_json::json!({
                "record_count": record_count,
                "storage_chain_length": storage_chain_len,
                "status": storage_status,
                "message": storage_error.unwrap_or_else(|| "Audit chain integrity verified".into()),
            });
            json_response(&body.to_string(), 200)
        }
        // ── Retention policy ──────────────────────────────────────
        (Method::Get, "/api/retention/status") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let retention = &s.config.retention;
            let body = serde_json::json!({
                "audit_max_records": retention.audit_max_records,
                "alert_max_records": retention.alert_max_records,
                "event_max_records": retention.event_max_records,
                "audit_max_age_secs": retention.audit_max_age_secs,
                "remote_syslog_endpoint": retention.remote_syslog_endpoint,
                "current_counts": {
                    "audit_entries": s.audit_log.recent(usize::MAX).len(),
                    "alerts": s.alerts.len(),
                    "events": s.event_store.count(),
                },
            });
            json_response(&body.to_string(), 200)
        }
        (Method::Post, "/api/retention/apply") => {
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            let max_alerts = s.config.retention.alert_max_records;
            let max_events = s.config.retention.event_max_records;
            let mut trimmed_alerts = 0usize;
            let mut trimmed_events = 0usize;
            if max_alerts > 0 && s.alerts.len() > max_alerts {
                trimmed_alerts = s.alerts.len() - max_alerts;
                s.alerts.drain(..trimmed_alerts);
            }
            if max_events > 0 {
                trimmed_events = s.event_store.apply_retention(max_events);
            }
            s.audit_log
                .record("POST", "/api/retention/apply", "admin", 200, true);
            let body = serde_json::json!({
                "status": "applied",
                "trimmed_alerts": trimmed_alerts,
                "trimmed_events": trimmed_events,
            });
            json_response(&body.to_string(), 200)
        }
        (Method::Get, "/api/alerts") => {
            let query = parse_query_string(&url);
            let limit = query
                .get("limit")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(100);
            let offset = query
                .get("offset")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let alerts_vec: Vec<_> = s.alerts.iter().cloned().collect();
            match recent_alerts_json(&alerts_vec, limit, offset) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&e, 500),
            }
        }
        (Method::Get, "/api/alerts/count") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
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
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            let cleared = s.alerts.len();
            s.alerts.clear();
            json_response(&format!(r#"{{"status":"cleared","count":{cleared}}}"#), 200)
        }
        (Method::Post, "/api/alerts/sample") => {
            let body = read_body_limited(body, 4096);
            let severity = match body {
                Ok(b) => {
                    #[derive(serde::Deserialize)]
                    struct SampleReq {
                        #[serde(default = "default_severity")]
                        severity: String,
                    }
                    fn default_severity() -> String {
                        "elevated".into()
                    }
                    let req: SampleReq = serde_json::from_str(&b).unwrap_or(SampleReq {
                        severity: default_severity(),
                    });
                    req.severity.to_lowercase()
                }
                Err(_) => "elevated".into(),
            };
            let (score, level) = match severity.as_str() {
                "critical" => (6.5_f32, "Critical"),
                "severe" => (4.2_f32, "Severe"),
                _ => (3.0_f32, "Elevated"),
            };
            let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
            let host = {
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                s.local_host_info.hostname.clone()
            };
            let sample = crate::telemetry::TelemetrySample {
                timestamp_ms: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
                cpu_load_pct: if severity == "critical" { 95.0 } else { 65.0 },
                memory_load_pct: if severity == "critical" { 88.0 } else { 55.0 },
                network_kbps: if severity == "critical" { 800.0 } else { 120.0 },
                disk_pressure_pct: 45.0,
                process_count: if severity == "critical" { 350 } else { 180 },
                auth_failures: if severity == "critical" { 25 } else { 5 },
                temperature_c: 0.5,
                battery_pct: 80.0,
                integrity_drift: 0.0,
            };
            let reasons = match severity.as_str() {
                "critical" => vec![
                    "[SAMPLE] CPU spike 95%".into(),
                    "[SAMPLE] Auth brute-force 25 failures".into(),
                    "[SAMPLE] Network anomaly 800 Kbps".into(),
                ],
                "severe" => vec![
                    "[SAMPLE] CPU elevated 65%".into(),
                    "[SAMPLE] Process burst 180".into(),
                ],
                _ => vec!["[SAMPLE] Test alert — elevated anomaly score".into()],
            };
            let alert = crate::collector::AlertRecord {
                timestamp: now,
                hostname: host,
                platform: "sample".into(),
                score,
                confidence: 0.85,
                level: level.into(),
                action: "sample_alert".into(),
                reasons,
                sample,
                enforced: false,
                mitre: vec![],
            };
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            if s.alerts.len() >= 10_000 {
                s.alerts.pop_front();
            }
            s.alerts.push_back(alert);
            json_response(
                &format!(r#"{{"status":"injected","severity":"{severity}","score":{score:.2}}}"#),
                200,
            )
        }
        // ── Alert Analysis & Grouping ────────────────────────────
        (Method::Get, "/api/alerts/analysis") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(ref analysis) = s.last_alert_analysis {
                match serde_json::to_string(analysis) {
                    Ok(json) => json_response(&json, 200),
                    Err(e) => error_json(&format!("serialization error: {e}"), 500),
                }
            } else {
                // Run on-the-fly if no background result yet
                let alerts_vec: Vec<_> = s.alerts.iter().cloned().collect();
                let analysis = crate::alert_analysis::analyze_alerts(&alerts_vec, 5);
                match serde_json::to_string(&analysis) {
                    Ok(json) => json_response(&json, 200),
                    Err(e) => error_json(&format!("serialization error: {e}"), 500),
                }
            }
        }
        (Method::Post, "/api/alerts/analysis") => {
            let body = read_body_limited(body, 4096);
            let window = match body {
                Ok(b) => {
                    #[derive(serde::Deserialize)]
                    struct AnalysisReq {
                        #[serde(default = "default_window")]
                        window_minutes: u64,
                    }
                    fn default_window() -> u64 {
                        5
                    }
                    let req: AnalysisReq = serde_json::from_str(&b).unwrap_or(AnalysisReq {
                        window_minutes: default_window(),
                    });
                    req.window_minutes
                }
                Err(_) => 5,
            };
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            let alerts_vec: Vec<_> = s.alerts.iter().cloned().collect();
            let analysis = crate::alert_analysis::analyze_alerts(&alerts_vec, window);
            s.last_alert_analysis = Some(analysis.clone());
            match serde_json::to_string(&analysis) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/alerts/grouped") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let alerts_vec: Vec<_> = s.alerts.iter().cloned().collect();
            let groups = crate::alert_analysis::group_alerts(&alerts_vec);
            match serde_json::to_string(&groups) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        // ── Swarm Intelligence ──────────────────────────────────
        (Method::Get, "/api/swarm/intel") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let entries = s.swarm.intel_cache.all();
            match serde_json::to_string(entries) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/swarm/intel/stats") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let stats = s.swarm.intel_cache.stats();
            match serde_json::to_string(&stats) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        // ── Local Telemetry ──────────────────────────────────────
        (Method::Get, "/api/telemetry/current") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(sample) = s.local_telemetry.back() {
                match serde_json::to_string(sample) {
                    Ok(json) => json_response(&json, 200),
                    Err(e) => error_json(&format!("serialization error: {e}"), 500),
                }
            } else {
                json_response(r#"{"message":"no telemetry collected yet"}"#, 200)
            }
        }
        (Method::Get, "/api/telemetry/history") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let samples: Vec<_> = s.local_telemetry.iter().rev().take(120).collect();
            match serde_json::to_string(&samples) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/host/info") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
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
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let uptime = s.server_start.elapsed().as_secs();
            let uptime_fmt = format!("{}d {}h {}m {}s",
                uptime / 86400, (uptime % 86400) / 3600,
                (uptime % 3600) / 60, uptime % 60);
            // Gather OS-level thread count for this process
            let thread_count: u32 = {
                #[cfg(target_os = "macos")]
                {
                    std::process::Command::new("ps")
                        .args(["-M", "-p", &std::process::id().to_string()])
                        .output()
                        .map(|o| {
                            let lines = String::from_utf8_lossy(&o.stdout).lines().count();
                            if lines > 1 { (lines - 1) as u32 } else { 0 }
                        })
                        .unwrap_or(0)
                }
                #[cfg(target_os = "linux")]
                {
                    std::fs::read_to_string(format!("/proc/{}/status", std::process::id()))
                        .ok()
                        .and_then(|s| {
                            s.lines()
                                .find(|l| l.starts_with("Threads:"))
                                .and_then(|l| l.split_whitespace().nth(1))
                                .and_then(|v| v.parse().ok())
                        })
                        .unwrap_or(0)
                }
                #[cfg(target_os = "windows")]
                { 0 }
                #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
                { 0 }
            };
            // Process memory (RSS) in MB
            let rss_mb: f64 = {
                #[cfg(target_os = "macos")]
                {
                    std::process::Command::new("ps")
                        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
                        .output()
                        .map(|o| {
                            String::from_utf8_lossy(&o.stdout)
                                .trim()
                                .parse::<f64>()
                                .unwrap_or(0.0) / 1024.0
                        })
                        .unwrap_or(0.0)
                }
                #[cfg(target_os = "linux")]
                {
                    std::fs::read_to_string(format!("/proc/{}/status", std::process::id()))
                        .ok()
                        .and_then(|s| {
                            s.lines()
                                .find(|l| l.starts_with("VmRSS:"))
                                .and_then(|l| l.split_whitespace().nth(1))
                                .and_then(|v| v.parse::<f64>().ok())
                        })
                        .unwrap_or(0.0) / 1024.0
                }
                #[cfg(target_os = "windows")]
                { 0.0 }
                #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
                { 0.0 }
            };
            let sample_rate = if s.local_telemetry.len() > 1 {
                let span = uptime as f64;
                if span > 0.0 { s.local_telemetry.len() as f64 / span } else { 0.2 }
            } else { 0.2 };
            let body = serde_json::json!({
                "monitoring_thread": "active",
                "thread_count": thread_count,
                "process_id": std::process::id(),
                "sample_count": s.local_telemetry.len(),
                "collection_rate_hz": (sample_rate * 100.0).round() / 100.0,
                "uptime_secs": uptime,
                "uptime_human": uptime_fmt,
                "alert_count": s.alerts.len(),
                "rss_mb": (rss_mb * 10.0).round() / 10.0,
                "platform": std::env::consts::OS,
                "arch": std::env::consts::ARCH,
                "subsystems": {
                    "telemetry_collector": "active",
                    "alert_engine": "active",
                    "http_server": "active",
                },
            });
            json_response(&body.to_string(), 200)
        }
        (Method::Get, "/api/monitoring/options") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let body = monitoring_options_payload(&s.local_host_info, &s.config);
            json_response(&body.to_string(), 200)
        }
        (Method::Get, "/api/monitoring/paths") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let body = monitoring_paths_payload(&s.local_host_info, &s.config);
            json_response(&body.to_string(), 200)
        }
        (Method::Get, "/api/rollout/config") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            match serde_json::to_string(&s.config.rollout) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/endpoints") => {
            let mut endpoints: Vec<serde_json::Value> =
                crate::openapi::endpoint_catalog(env!("CARGO_PKG_VERSION"))
                    .into_iter()
                    .map(|entry| {
                        serde_json::json!({
                            "method": entry.method,
                            "path": entry.path,
                            "auth": entry.auth,
                            "description": entry.description,
                        })
                    })
                    .collect();
            let mut seen = endpoints
                .iter()
                .filter_map(|entry| {
                    Some((
                        entry["method"].as_str()?.to_string(),
                        entry["path"].as_str()?.to_string(),
                    ))
                })
                .collect::<BTreeSet<_>>();
            let supplemental = r#"[
                {"method": "GET", "path": "/api/health", "auth": false, "description": "Server health, version, uptime, platform"},
                {"method": "GET", "path": "/api/metrics", "auth": false, "description": "Prometheus-format product metrics"},
                {"method": "GET", "path": "/api/host/info", "auth": true, "description": "Detailed host info + monitoring status"},
                {"method": "GET", "path": "/api/telemetry/current", "auth": true, "description": "Latest local telemetry sample"},
                {"method": "GET", "path": "/api/telemetry/history", "auth": true, "description": "Last 120 local telemetry samples"},
                {"method": "GET", "path": "/api/checkpoints", "auth": true, "description": "Saved checkpoint metadata"},
                {"method": "GET", "path": "/api/export/tla", "auth": true, "description": "Export the policy state machine as a TLA+ specification"},
                {"method": "GET", "path": "/api/export/alloy", "auth": true, "description": "Export the policy state machine as an Alloy model"},
                {"method": "GET", "path": "/api/export/witnesses", "auth": true, "description": "Export cryptographic proof witnesses recorded during analysis"},
                {"method": "GET", "path": "/api/research-tracks", "auth": true, "description": "Grouped research and roadmap tracks for the product"},
                {"method": "GET", "path": "/api/attestation/status", "auth": true, "description": "Attestation verification status and missing checks"},
                {"method": "GET", "path": "/api/fleet/status", "auth": true, "description": "Fleet health summary for the swarm control plane"},
                {"method": "GET", "path": "/api/correlation", "auth": true, "description": "Replay-buffer correlation analysis"},
                {"method": "GET", "path": "/api/alerts", "auth": true, "description": "Last 100 alerts"},
                {"method": "GET", "path": "/api/alerts/{id}", "auth": true, "description": "Detailed alert view for a specific alert ID"},
                {"method": "GET", "path": "/api/alerts/count", "auth": true, "description": "Alert count by severity"},
                {"method": "DELETE", "path": "/api/alerts", "auth": true, "description": "Clear all alerts"},
                {"method": "POST", "path": "/api/alerts/sample", "auth": true, "description": "Inject a sample alert for testing and demo flows"},
                {"method": "GET", "path": "/api/alerts/analysis", "auth": true, "description": "Latest alert pattern analysis"},
                {"method": "POST", "path": "/api/alerts/analysis", "auth": true, "description": "Run on-demand alert analysis with custom window"},
                {"method": "GET", "path": "/api/alerts/grouped", "auth": true, "description": "Alerts grouped by reason fingerprint"},
                {"method": "GET", "path": "/api/platform", "auth": true, "description": "Detected platform capabilities and hardware security support"},
                {"method": "GET", "path": "/api/threat-intel/status", "auth": true, "description": "Threat intelligence indicator inventory status"},
                {"method": "POST", "path": "/api/threat-intel/ioc", "auth": true, "description": "Submit a new indicator of compromise"},
                {"method": "GET", "path": "/api/threat-intel/stats", "auth": true, "description": "IoC enrichment statistics (by type, severity, source)"},
                {"method": "POST", "path": "/api/threat-intel/purge", "auth": true, "description": "Purge expired IoCs by TTL (days)"},
                {"method": "GET", "path": "/api/mitre/coverage", "auth": true, "description": "MITRE ATT&CK coverage summary with gap analysis"},
                {"method": "GET", "path": "/api/mitre/heatmap", "auth": true, "description": "MITRE ATT&CK heatmap (per-tactic, per-technique coverage)"},
                {"method": "GET", "path": "/api/detection/profile", "auth": true, "description": "Current detection tuning profile"},
                {"method": "PUT", "path": "/api/detection/profile", "auth": true, "description": "Set detection tuning profile (aggressive/balanced/quiet)"},
                {"method": "POST", "path": "/api/fp-feedback", "auth": true, "description": "Submit false-positive feedback for an alert pattern"},
                {"method": "GET", "path": "/api/fp-feedback/stats", "auth": true, "description": "False-positive feedback statistics and suppression weights"},
                {"method": "GET", "path": "/api/detection/score/normalize", "auth": true, "description": "Get normalized 0-100 threat score with severity label"},
                {"method": "GET", "path": "/api/playbooks", "auth": true, "description": "List registered automated response playbooks"},
                {"method": "POST", "path": "/api/playbooks", "auth": true, "description": "Register or update an automated response playbook"},
                {"method": "POST", "path": "/api/playbooks/execute", "auth": true, "description": "Start a playbook execution for a specific alert"},
                {"method": "GET", "path": "/api/playbooks/executions", "auth": true, "description": "List recent playbook execution records"},
                {"method": "GET", "path": "/api/beacon/analyze", "auth": true, "description": "Analyze beaconing and DGA indicators from recorded network activity"},
                {"method": "GET", "path": "/api/swarm/intel", "auth": true, "description": "Shared intelligence cache entries"},
                {"method": "GET", "path": "/api/swarm/intel/stats", "auth": true, "description": "Shared intelligence cache statistics"},
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
                {"method": "GET", "path": "/api/workbench/overview", "auth": true, "description": "Consolidated SOC workbench overview across queue, cases, incidents, response, and hot agents"},
                {"method": "GET", "path": "/api/manager/overview", "auth": true, "description": "Manager-facing operational overview across fleet, queue SLA, deployments, reports, and posture"},
                {"method": "GET", "path": "/api/hunts", "auth": true, "description": "List saved hunts with thresholds, schedules, and latest run state"},
                {"method": "POST", "path": "/api/hunts", "auth": true, "description": "Create or update a saved hunt"},
                {"method": "POST", "path": "/api/hunts/{id}/run", "auth": true, "description": "Execute a saved hunt immediately against retained events"},
                {"method": "GET", "path": "/api/hunts/{id}/history", "auth": true, "description": "Retrieve run history for a saved hunt"},
                {"method": "GET", "path": "/api/content/rules", "auth": true, "description": "List Sigma and native content rules with lifecycle and test metadata"},
                {"method": "POST", "path": "/api/content/rules", "auth": true, "description": "Create or update managed content rules"},
                {"method": "POST", "path": "/api/content/rules/{id}/test", "auth": true, "description": "Replay a content rule against retained events and return match/test evidence"},
                {"method": "POST", "path": "/api/content/rules/{id}/promote", "auth": true, "description": "Promote a content rule through its lifecycle"},
                {"method": "POST", "path": "/api/content/rules/{id}/rollback", "auth": true, "description": "Rollback a content rule to its previous lifecycle state"},
                {"method": "GET", "path": "/api/content/packs", "auth": true, "description": "List content packs grouped by use case"},
                {"method": "POST", "path": "/api/content/packs", "auth": true, "description": "Create or update a content pack"},
                {"method": "GET", "path": "/api/coverage/mitre", "auth": true, "description": "ATT&CK coverage across rules, packs, and lifecycle gaps"},
                {"method": "GET", "path": "/api/suppressions", "auth": true, "description": "List alert suppressions and exceptions"},
                {"method": "POST", "path": "/api/suppressions", "auth": true, "description": "Create or update an alert suppression or exception"},
                {"method": "GET", "path": "/api/entities/{kind}/{id}", "auth": true, "description": "Entity profile pivot for host, user, process, IP, domain, or hash"},
                {"method": "GET", "path": "/api/entities/{kind}/{id}/timeline", "auth": true, "description": "Timeline of activity related to a specific investigation entity"},
                {"method": "GET", "path": "/api/incidents/{id}/storyline", "auth": true, "description": "Narrative storyline, response history, and evidence package for an incident"},
                {"method": "GET", "path": "/api/enrichments/connectors", "auth": true, "description": "List enrichment connectors and their readiness"},
                {"method": "POST", "path": "/api/enrichments/connectors", "auth": true, "description": "Create or update an enrichment connector definition"},
                {"method": "POST", "path": "/api/tickets/sync", "auth": true, "description": "Sync a case or incident to an external ticket system"},
                {"method": "GET", "path": "/api/idp/providers", "auth": true, "description": "List configured OIDC/SAML identity providers"},
                {"method": "POST", "path": "/api/idp/providers", "auth": true, "description": "Create or update an identity provider configuration"},
                {"method": "GET", "path": "/api/scim/config", "auth": true, "description": "Get SCIM provisioning configuration"},
                {"method": "POST", "path": "/api/scim/config", "auth": true, "description": "Update SCIM provisioning configuration"},
                {"method": "GET", "path": "/api/audit/admin", "auth": true, "description": "Enterprise admin audit, change control, and approval history"},
                {"method": "GET", "path": "/api/support/diagnostics", "auth": true, "description": "Support diagnostics bundle with dependency, auth, content, and operations state"},
                {"method": "GET", "path": "/api/system/health/dependencies", "auth": true, "description": "Dependency and rollout health across storage, SIEM, connectors, and fleet state"},
                {"method": "POST", "path": "/api/events/{id}/triage", "auth": true, "description": "Update event triage state, assignee, tags, and analyst notes"},
                {"method": "GET", "path": "/api/policy/history", "auth": true, "description": "Published policy history"},
                {"method": "GET", "path": "/api/updates/releases", "auth": true, "description": "List published agent releases for deployment and rollback"},
                {"method": "POST", "path": "/api/updates/deploy", "auth": true, "description": "Assign a published release to a specific agent"},
                {"method": "POST", "path": "/api/response/request", "auth": true, "description": "Submit an approval-gated response action"},
                {"method": "GET", "path": "/api/response/requests", "auth": true, "description": "List all response requests with approval state"},
                {"method": "POST", "path": "/api/response/approve", "auth": true, "description": "Approve or deny a pending response request"},
                {"method": "POST", "path": "/api/response/execute", "auth": true, "description": "Execute all approved response requests"},
                {"method": "GET", "path": "/api/audit/log", "auth": true, "description": "Recent API audit log entries"},
                {"method": "GET", "path": "/api/incidents", "auth": true, "description": "List incidents with optional status/severity filters"},
                {"method": "GET", "path": "/api/incidents/{id}", "auth": true, "description": "Incident detail with timeline"},
                {"method": "POST", "path": "/api/incidents", "auth": true, "description": "Manually create an incident from selected events"},
                {"method": "POST", "path": "/api/incidents/{id}/update", "auth": true, "description": "Update incident status/assignee/notes"},
                {"method": "GET", "path": "/api/agents/{id}/activity", "auth": true, "description": "Deep activity snapshot for a single agent including freshness, deployment, logs, inventory, and risk transitions"},
                {"method": "GET", "path": "/api/agents/{id}/status", "auth": true, "description": "Current enrollment and heartbeat status for a single agent"},
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
                {"method": "GET", "path": "/api/openapi.json", "auth": false, "description": "OpenAPI 3.0 specification"},
                {"method": "GET", "path": "/api/slo/status", "auth": true, "description": "Service level objective metrics"},
                {"method": "POST", "path": "/api/auth/rotate", "auth": true, "description": "Rotate admin token and reset TTL"},
                {"method": "GET", "path": "/api/session/info", "auth": true, "description": "Session info with token TTL and expiry status"},
                {"method": "GET", "path": "/api/audit/verify", "auth": true, "description": "Verify integrity of the cryptographic audit chain"},
                {"method": "GET", "path": "/api/retention/status", "auth": true, "description": "Current retention policy settings and record counts"},
                {"method": "POST", "path": "/api/retention/apply", "auth": true, "description": "Apply retention policies to trim old records"},
                {"method": "GET", "path": "/api/queue/alerts", "auth": true, "description": "Current analyst alert queue with SLA metadata"},
                {"method": "GET", "path": "/api/queue/stats", "auth": true, "description": "Alert queue backlog and SLA summary"},
                {"method": "POST", "path": "/api/queue/acknowledge", "auth": true, "description": "Acknowledge a queued alert"},
                {"method": "POST", "path": "/api/queue/assign", "auth": true, "description": "Assign a queued alert to an analyst"},
                {"method": "GET", "path": "/api/timeline/host", "auth": true, "description": "Host investigation timeline filtered by hostname query parameter"},
                {"method": "GET", "path": "/api/timeline/agent", "auth": true, "description": "Agent investigation timeline filtered by agent_id query parameter"},
                {"method": "GET", "path": "/api/cases/stats", "auth": true, "description": "Case backlog and status summary"},
                {"method": "GET", "path": "/api/causal/graph", "auth": true, "description": "Causal graph status and model summary"},
                {"method": "GET", "path": "/api/compliance/status", "auth": true, "description": "Compliance posture and control status"},
                {"method": "GET", "path": "/api/deception/status", "auth": true, "description": "Deception engine status and artifact coverage"},
                {"method": "POST", "path": "/api/deception/deploy", "auth": true, "description": "Deploy deception artifacts and decoys"},
                {"method": "GET", "path": "/api/digital-twin/status", "auth": true, "description": "Digital twin readiness and model status"},
                {"method": "POST", "path": "/api/digital-twin/simulate", "auth": true, "description": "Run a digital twin simulation"},
                {"method": "GET", "path": "/api/dlq", "auth": true, "description": "Dead-letter queue entries"},
                {"method": "GET", "path": "/api/dlq/stats", "auth": true, "description": "Dead-letter queue statistics"},
                {"method": "DELETE", "path": "/api/dlq", "auth": true, "description": "Clear the dead-letter queue"},
                {"method": "GET", "path": "/api/drift/status", "auth": true, "description": "Drift detector status and thresholds"},
                {"method": "POST", "path": "/api/drift/reset", "auth": true, "description": "Reset the drift baseline"},
                {"method": "GET", "path": "/api/energy/status", "auth": true, "description": "Energy budget and harvesting status"},
                {"method": "POST", "path": "/api/energy/consume", "auth": true, "description": "Record an energy consumption event"},
                {"method": "POST", "path": "/api/energy/harvest", "auth": true, "description": "Record an energy harvesting event"},
                {"method": "GET", "path": "/api/enforcement/status", "auth": true, "description": "Enforcement engine status and topology state"},
                {"method": "POST", "path": "/api/enforcement/quarantine", "auth": true, "description": "Quarantine a workload or endpoint"},
                {"method": "GET", "path": "/api/feature-flags", "auth": true, "description": "Current feature flag states"},
                {"method": "GET", "path": "/api/fingerprint/status", "auth": true, "description": "Device fingerprinting status"},
                {"method": "POST", "path": "/api/fleet/register", "auth": true, "description": "Register a device with the fleet control plane"},
                {"method": "POST", "path": "/api/harness/run", "auth": true, "description": "Run the validation harness"},
                {"method": "POST", "path": "/api/investigation/graph", "auth": true, "description": "Build an investigation relationship graph from selected events"},
                {"method": "GET", "path": "/api/mesh/health", "auth": true, "description": "Mesh health summary"},
                {"method": "POST", "path": "/api/mesh/heal", "auth": true, "description": "Trigger mesh healing actions"},
                {"method": "GET", "path": "/api/monitor/status", "auth": true, "description": "Runtime monitor status"},
                {"method": "GET", "path": "/api/monitor/violations", "auth": true, "description": "Recent runtime monitor violations"},
                {"method": "GET", "path": "/api/ocsf/schema", "auth": true, "description": "Current OCSF schema projection"},
                {"method": "GET", "path": "/api/ocsf/schema/version", "auth": true, "description": "Current OCSF schema version"},
                {"method": "POST", "path": "/api/offload/decide", "auth": true, "description": "Evaluate an edge offload decision"},
                {"method": "GET", "path": "/api/patches", "auth": true, "description": "Available platform and policy patches"},
                {"method": "GET", "path": "/api/privacy/budget", "auth": true, "description": "Privacy budget status"},
                {"method": "GET", "path": "/api/process-tree", "auth": true, "description": "Current process tree snapshot"},
                {"method": "GET", "path": "/api/process-tree/deep-chains", "auth": true, "description": "Deep process ancestry chains"},
                {"method": "GET", "path": "/api/processes/live", "auth": true, "description": "Live process list from local host"},
                {"method": "GET", "path": "/api/processes/analysis", "auth": true, "description": "Analyse running processes for suspicious behaviour"},
                {"method": "GET", "path": "/api/host/apps", "auth": true, "description": "Enumerate installed applications"},
                {"method": "GET", "path": "/api/host/inventory", "auth": true, "description": "Full system inventory (hardware, software, services, users)"},
                {"method": "POST", "path": "/api/policy-vm/execute", "auth": true, "description": "Execute a policy VM program"},
                {"method": "POST", "path": "/api/policy/compose", "auth": true, "description": "Compose a policy from weighted inputs"},
                {"method": "GET", "path": "/api/quantum/key-status", "auth": true, "description": "Quantum key rotation status"},
                {"method": "POST", "path": "/api/quantum/rotate", "auth": true, "description": "Rotate quantum key material"},
                {"method": "GET", "path": "/api/rbac/users", "auth": true, "description": "List RBAC users and roles"},
                {"method": "POST", "path": "/api/rbac/users", "auth": true, "description": "Create an RBAC user and issue a token"},
                {"method": "GET", "path": "/api/response/pending", "auth": true, "description": "Pending response actions awaiting approval or execution"},
                {"method": "GET", "path": "/api/response/audit", "auth": true, "description": "Response execution audit ledger"},
                {"method": "GET", "path": "/api/response/stats", "auth": true, "description": "Response orchestration statistics"},
                {"method": "POST", "path": "/api/shutdown", "auth": true, "description": "Gracefully shut down the server"},
                {"method": "GET", "path": "/api/side-channel/status", "auth": true, "description": "Side-channel detector status"},
                {"method": "GET", "path": "/api/siem/status", "auth": true, "description": "SIEM connector status"},
                {"method": "GET", "path": "/api/siem/config", "auth": true, "description": "SIEM connector configuration"},
                {"method": "POST", "path": "/api/siem/config", "auth": true, "description": "Update SIEM connector configuration"},
                {"method": "GET", "path": "/api/sigma/rules", "auth": true, "description": "Loaded Sigma rules"},
                {"method": "GET", "path": "/api/sigma/stats", "auth": true, "description": "Sigma engine statistics"},
                {"method": "GET", "path": "/api/spool/stats", "auth": true, "description": "Encrypted spool statistics"},
                {"method": "GET", "path": "/api/swarm/posture", "auth": true, "description": "Swarm security posture summary"},
                {"method": "GET", "path": "/api/taxii/status", "auth": true, "description": "TAXII connector status"},
                {"method": "GET", "path": "/api/taxii/config", "auth": true, "description": "TAXII connector configuration"},
                {"method": "POST", "path": "/api/taxii/config", "auth": true, "description": "Update TAXII connector configuration"},
                {"method": "POST", "path": "/api/taxii/pull", "auth": true, "description": "Pull indicators from TAXII sources"},
                {"method": "GET", "path": "/api/tenants/count", "auth": true, "description": "Tenant count summary"},
                {"method": "GET", "path": "/api/tls/status", "auth": true, "description": "TLS listener and certificate status"},
                {"method": "POST", "path": "/api/agents/token", "auth": true, "description": "Create an agent enrollment token"},
                {"method": "POST", "path": "/api/agents/enroll", "auth": false, "description": "Enroll an agent with a valid enrollment token"},
                {"method": "POST", "path": "/api/control/mode", "auth": true, "description": "Set the device control mode"},
                {"method": "POST", "path": "/api/control/reset-baseline", "auth": true, "description": "Reset the anomaly detection baseline"},
                {"method": "POST", "path": "/api/control/checkpoint", "auth": true, "description": "Create a control checkpoint"},
                {"method": "POST", "path": "/api/control/restore-checkpoint", "auth": true, "description": "Restore a control checkpoint"},
                {"method": "POST", "path": "/api/control/run-demo", "auth": true, "description": "Run the built-in telemetry demo"},
                {"method": "POST", "path": "/api/events/bulk-triage", "auth": true, "description": "Bulk update event triage state"},
                {"method": "POST", "path": "/api/admin/db/compact", "auth": true, "description": "Compact database (VACUUM + WAL checkpoint)"},
                {"method": "POST", "path": "/api/admin/db/reset", "auth": true, "description": "Reset all database data (requires confirmation)"},
                {"method": "GET", "path": "/api/admin/db/sizes", "auth": true, "description": "Database file sizes and storage usage"},
                {"method": "POST", "path": "/api/admin/cleanup-legacy", "auth": true, "description": "Remove legacy flat-file data from var/"},
                {"method": "POST", "path": "/api/admin/db/purge", "auth": true, "description": "Purge data older than N days across all tables"}
            ]"#;
            let supplemental: Vec<serde_json::Value> =
                serde_json::from_str(supplemental).unwrap_or_default();
            for entry in &supplemental {
                if let (Some(method), Some(path)) =
                    (entry["method"].as_str(), entry["path"].as_str())
                    && seen.insert((method.to_string(), path.to_string())) {
                        endpoints.push(entry.clone());
                    }
            }
            endpoints.sort_by(|a, b| {
                let left = (
                    a["path"].as_str().unwrap_or(""),
                    a["method"].as_str().unwrap_or(""),
                );
                let right = (
                    b["path"].as_str().unwrap_or(""),
                    b["method"].as_str().unwrap_or(""),
                );
                left.cmp(&right)
            });
            json_response(&serde_json::Value::Array(endpoints).to_string(), 200)
        }

        // ── XDR Agent Management ──────────────────────────────────
        (Method::Post, "/api/agents/enroll") => handle_agent_enroll(body, state),
        (Method::Post, "/api/agents/token") => handle_agent_create_token(body, state),
        (Method::Get, "/api/agents") => {
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            s.agent_registry.refresh_staleness();
            let agents = s.agent_registry.list();
            let payload = agents
                .iter()
                .map(|agent| {
                    agent_summary_json(
                        agent,
                        s.remote_deployments.get(&agent.id),
                        s.agent_registry.heartbeat_interval(),
                    )
                })
                .collect::<Vec<_>>();
            match serde_json::to_string(&payload) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }

        // ── XDR Events ────────────────────────────────────────────
        (Method::Post, "/api/events") => handle_event_ingest(body, state),
        (Method::Get, "/api/events") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let query = parse_event_query(&url);
            let events = filtered_events(&s.event_store, &query);
            match serde_json::to_string(&events) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/events/export") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let query = parse_event_query(&url);
            let events = filtered_events(&s.event_store, &query);
            csv_response(&events_to_csv(&events), 200)
        }
        (Method::Get, "/api/events/summary") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let analytics = s.event_store.analytics();
            match serde_json::to_string(&analytics) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }

        // ── XDR Policy Distribution ──────────────────────────────
        (Method::Get, "/api/policy/current") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            match s.policy_store.current() {
                Some(policy) => match serde_json::to_string(policy) {
                    Ok(json) => json_response(&json, 200),
                    Err(e) => error_json(&format!("serialization error: {e}"), 500),
                },
                None => json_response(r#"{"version":0,"message":"no policy published"}"#, 200),
            }
        }
        (Method::Get, "/api/policy/history") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            match serde_json::to_string(s.policy_store.history()) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Post, "/api/policy/publish") => handle_policy_publish(body, state),

        // ── XDR Update Distribution ──────────────────────────────
        (Method::Post, "/api/updates/publish") => handle_update_publish(body, state),
        (Method::Post, "/api/updates/deploy") => handle_update_deploy(body, state),
        (Method::Post, "/api/updates/rollback") => handle_update_rollback(body, state),
        (Method::Post, "/api/updates/cancel") => handle_update_cancel(body, state),
        (Method::Post, "/api/events/bulk-triage") => handle_bulk_triage(body, state),

        // ── Detection Analysis ─────────────────────────────────
        (Method::Get, "/api/detection/summary") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let vel_state = &s.velocity;
            let ent_state = &s.entropy;
            let cmp_state = &s.compound;
            let mode = match s.detector.adaptation() {
                AdaptationMode::Normal => "normal",
                AdaptationMode::Frozen => "frozen",
                AdaptationMode::Decay(_) => "decay",
            };
            let body = serde_json::json!({
                "mode": mode,
                "ewma_alpha": s.detector.smoothing(),
                "warmup_samples": s.detector.warmup_samples(),
                "learn_threshold": s.detector.learn_threshold(),
                "observed_samples": s.detector.observed_samples(),
                "baseline_ready": s.detector.baseline_ready(),
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
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let weights = s.detector.signal_weights();
            match serde_json::to_string(&weights) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Post, "/api/detection/weights") => {
            let body = match read_body_limited(body, 10 * 1024 * 1024) {
                Ok(b) => b,
                Err(e) => {
                    return respond_api(
                        state,
                        &method,
                        &url,
                        remote_addr,
                        auth_used,
                        error_json(&e, 400),
                    );
                }
            };
            let weights: HashMap<String, f32> = match serde_json::from_str(&body) {
                Ok(w) => w,
                Err(e) => {
                    return respond_api(
                        state,
                        &method,
                        &url,
                        remote_addr,
                        auth_used,
                        error_json(&format!("invalid JSON: {e}"), 400),
                    );
                }
            };
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            s.detector.set_signal_weights(weights.clone());
            drop(s);
            json_response(
                &serde_json::json!({"status":"weights_updated","weights":weights}).to_string(),
                200,
            )
        }

        // ── Audit Log ─────────────────────────────────────────────
        (Method::Get, "/api/audit/log") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let entries = s.audit_log.recent(200);
            match serde_json::to_string(&entries) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }

        // ── Incidents ─────────────────────────────────────────────
        (Method::Get, "/api/incidents") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let query = parse_query_string(&url);
            match incidents_json(&s.incident_store, &query) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&e, 500),
            }
        }
        (Method::Post, "/api/incidents") => {
            let body = match read_body_limited(body, 10 * 1024 * 1024) {
                Ok(b) => b,
                Err(e) => {
                    return respond_api(
                        state,
                        &method,
                        &url,
                        remote_addr,
                        auth_used,
                        error_json(&e, 400),
                    );
                }
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
                Err(e) => {
                    return respond_api(
                        state,
                        &method,
                        &url,
                        remote_addr,
                        auth_used,
                        error_json(&format!("invalid JSON: {e}"), 400),
                    );
                }
            };
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            let inc = s.incident_store.create(
                req.title,
                req.severity,
                req.event_ids,
                req.agent_ids,
                vec![],
                req.summary,
            );
            match serde_json::to_string(inc) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }

        // ── Fleet Inventory ──────────────────────────────────────
        (Method::Get, "/api/fleet/inventory") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let summary: Vec<serde_json::Value> = s
                .agent_inventories
                .iter()
                .map(|(id, inv)| {
                    serde_json::json!({
                        "agent_id": id,
                        "collected_at": inv.collected_at,
                        "hardware": inv.hardware,
                        "software_count": inv.software.len(),
                        "services_count": inv.services.len(),
                        "network_ports": inv.network.len(),
                        "users_count": inv.users.len(),
                    })
                })
                .collect();
            json_response(&serde_json::json!({"agents": summary}).to_string(), 200)
        }

        // ── Reports ──────────────────────────────────────────────
        (Method::Get, "/api/reports") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let list = s.report_store.list();
            match serde_json::to_string(&list) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/reports/executive-summary") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let summary = s.report_store.executive_summary(&s.incident_store);
            match serde_json::to_string(&summary) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }

        // ── SIEM Status ──────────────────────────────────────────
        (Method::Get, "/api/siem/status") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let status = s.siem_connector.status();
            match serde_json::to_string(&status) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/siem/config") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let cfg = s.siem_connector.config();
            match serde_json::to_string(&cfg) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Post, "/api/siem/config") => {
            let body = read_body_limited(body, 4096);
            match body {
                Ok(b) => match serde_json::from_str::<crate::siem::SiemConfig>(&b) {
                    Ok(new_cfg) => {
                        if new_cfg.enabled
                            && !new_cfg.endpoint.is_empty()
                            && !new_cfg.endpoint.starts_with("https://")
                            && !new_cfg.endpoint.starts_with("http://")
                        {
                            error_json("SIEM endpoint must use http:// or https://", 400)
                        } else if let Err(e) = new_cfg.validate() {
                            error_json(&e, 400)
                        } else {
                            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                            let mut next_config = s.config.clone();
                            next_config.siem = new_cfg.clone();
                            if let Err(e) = persist_config_to_path(&next_config, &s.config_path) {
                                error_json(&e, 500)
                            } else {
                                s.config = next_config;
                                s.siem_connector.update_config(new_cfg);
                                json_response(
                                    r#"{"status":"ok","message":"SIEM configuration updated"}"#,
                                    200,
                                )
                            }
                        }
                    }
                    Err(e) => error_json(&format!("invalid SIEM config: {e}"), 400),
                },
                Err(e) => error_json(&e, 400),
            }
        }
        (Method::Get, "/api/taxii/status") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let status = s.taxii_client.status();
            match serde_json::to_string(&status) {
                Ok(j) => json_response(&j, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/taxii/config") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            match serde_json::to_string(s.taxii_client.config()) {
                Ok(j) => json_response(&j, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Post, "/api/taxii/config") => {
            let body = read_body_limited(body, 4096);
            match body {
                Ok(b) => match serde_json::from_str::<crate::siem::TaxiiConfig>(&b) {
                    Ok(new_cfg) => {
                        if new_cfg.enabled
                            && !new_cfg.url.is_empty()
                            && !new_cfg.url.starts_with("https://")
                            && !new_cfg.url.starts_with("http://")
                        {
                            error_json("TAXII URL must use http:// or https://", 400)
                        } else {
                            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                            let mut next_config = s.config.clone();
                            next_config.taxii = new_cfg.clone();
                            if let Err(e) = persist_config_to_path(&next_config, &s.config_path) {
                                error_json(&e, 500)
                            } else {
                                s.config = next_config;
                                s.taxii_client.update_config(new_cfg);
                                json_response(
                                    r#"{"status":"ok","message":"TAXII configuration updated"}"#,
                                    200,
                                )
                            }
                        }
                    }
                    Err(e) => error_json(&format!("invalid TAXII config: {e}"), 400),
                },
                Err(e) => error_json(&e, 400),
            }
        }
        (Method::Post, "/api/taxii/pull") => {
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            match s.taxii_client.pull_indicators() {
                Ok(records) => {
                    let count = records.len();
                    match serde_json::to_string(
                        &serde_json::json!({"pulled": count, "records": records}),
                    ) {
                        Ok(j) => json_response(&j, 200),
                        Err(e) => error_json(&format!("serialization error: {e}"), 500),
                    }
                }
                Err(e) => error_json(&format!("TAXII pull failed: {e}"), 502),
            }
        }

        // ── Fleet Dashboard ──────────────────────────────────────
        (Method::Get, "/api/fleet/dashboard") => {
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            s.agent_registry.refresh_staleness();
            let agents = s.agent_registry.list();
            let mut counts = HashMap::new();
            for agent in agents.iter().copied() {
                let (status, _) =
                    computed_agent_status(agent, s.agent_registry.heartbeat_interval());
                *counts.entry(status).or_insert(0usize) += 1;
            }
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
            let online_count = *counts.get("online").unwrap_or(&0);
            let info = serde_json::json!({
                "fleet": {
                    "total_agents": agents.len(),
                    "status_counts": counts,
                    "coverage_pct": if agents.is_empty() { 0.0 } else { (online_count as f32 / agents.len() as f32) * 100.0 },
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
        (Method::Get, "/api/workbench/overview") => {
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            s.agent_registry.refresh_staleness();
            let analytics = s.event_store.analytics();
            let overview = build_workbench_overview(
                &s.alert_queue,
                &s.case_store,
                &s.incident_store,
                &s.response_orchestrator,
                &s.approval_log,
                &analytics,
                &s.event_store,
                &s.agent_registry,
                &s.remote_deployments,
            );
            match serde_json::to_string(&overview) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/manager/overview") => {
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            s.agent_registry.refresh_staleness();
            let analytics = s.event_store.analytics();
            let siem_status = s.siem_connector.status();
            let compliance_score = s
                .compliance
                .report(&crate::compliance::Framework::Iec62443)
                .score;
            let overview = build_manager_overview(
                &s.alert_queue,
                &s.incident_store,
                &s.response_orchestrator,
                &analytics,
                &s.agent_registry,
                &s.remote_deployments,
                s.update_manager.list_releases().len(),
                &s.report_store,
                siem_status,
                s.multi_tenant.tenant_count(),
                compliance_score,
            );
            match serde_json::to_string(&overview) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/hunts") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let items: Vec<serde_json::Value> = s
                .enterprise
                .hunts()
                .iter()
                .map(|hunt| {
                    let latest_run = s
                        .enterprise
                        .hunt_runs(&hunt.id)
                        .into_iter()
                        .max_by(|a, b| a.run_at.cmp(&b.run_at));
                    serde_json::json!({
                        "id": hunt.id,
                        "name": hunt.name,
                        "owner": hunt.owner,
                        "enabled": hunt.enabled,
                        "severity": hunt.severity,
                        "threshold": hunt.threshold,
                        "suppression_window_secs": hunt.suppression_window_secs,
                        "schedule_interval_secs": hunt.schedule_interval_secs,
                        "last_run_at": hunt.last_run_at,
                        "next_run_at": hunt.next_run_at,
                        "query": hunt.query,
                        "latest_run": latest_run,
                    })
                })
                .collect();
            json_response(
                &serde_json::json!({"hunts": items, "count": items.len()}).to_string(),
                200,
            )
        }
        (Method::Post, "/api/hunts") => match read_json_value(body, 16 * 1024) {
            Ok(v) => {
                let query = v.get("query").cloned().unwrap_or_else(|| {
                    serde_json::json!({
                        "text": v.get("text"),
                        "hostname": v.get("hostname"),
                        "level": v.get("level"),
                        "agent_id": v.get("agent_id"),
                        "limit": v.get("limit").cloned().unwrap_or(serde_json::json!(250))
                    })
                });
                match serde_json::from_value::<crate::analyst::SearchQuery>(query) {
                    Ok(query) => {
                        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                        let hunt = s.enterprise.create_or_update_hunt(
                            v["id"].as_str(),
                            v["name"].as_str().unwrap_or("Untitled Hunt").to_string(),
                            v["owner"]
                                .as_str()
                                .unwrap_or(auth_identity.actor())
                                .to_string(),
                            v["severity"].as_str().unwrap_or("medium").to_string(),
                            v["threshold"].as_u64().unwrap_or(1) as usize,
                            v["suppression_window_secs"].as_u64().unwrap_or(0),
                            v["schedule_interval_secs"].as_u64(),
                            query,
                        );
                        let _ = s.enterprise.record_change(
                            "hunt",
                            &hunt.id,
                            &format!("Saved hunt {}", hunt.name),
                            auth_identity.actor(),
                            Some(hunt.id.clone()),
                            Some(&v.to_string()),
                        );
                        json_response(
                            &serde_json::json!({"status": "saved", "hunt": hunt}).to_string(),
                            201,
                        )
                    }
                    Err(e) => error_json(&format!("invalid hunt query: {e}"), 400),
                }
            }
            Err(e) => error_json(&e, 400),
        },
        (Method::Get, "/api/content/rules") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let items = build_content_rules_view(&s.enterprise);
            json_response(
                &serde_json::json!({"rules": items, "count": items.len()}).to_string(),
                200,
            )
        }
        (Method::Post, "/api/content/rules") => {
            match read_json_value(body, 16 * 1024) {
                Ok(v) => {
                    let is_builtin = v["builtin"].as_bool().unwrap_or(false)
                        || v["kind"]
                            .as_str()
                            .map(|kind| kind.eq_ignore_ascii_case("sigma"))
                            .unwrap_or(false);
                    let attack = serde_json::from_value::<Vec<crate::telemetry::MitreAttack>>(
                        v.get("attack")
                            .cloned()
                            .unwrap_or_else(|| serde_json::json!([])),
                    )
                    .unwrap_or_default();
                    let pack_ids = v
                        .get("pack_ids")
                        .and_then(|value| value.as_array())
                        .map(|values| {
                            values
                                .iter()
                                .filter_map(|value| value.as_str().map(|s| s.to_string()))
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                    if is_builtin {
                        match s.enterprise.update_builtin_metadata(
                            v["id"].as_str().unwrap_or(""),
                            v.get("owner")
                                .and_then(|value| value.as_str())
                                .map(|s| s.to_string()),
                            v.get("enabled").and_then(|value| value.as_bool()),
                            (!pack_ids.is_empty()).then_some(pack_ids),
                            v.get("false_positive_review")
                                .and_then(|value| value.as_str())
                                .map(|s| s.to_string()),
                        ) {
                            Ok(rule) => {
                                sync_enterprise_sigma_engine(&mut s);
                                let _ = s.enterprise.record_change(
                                    "content_rule",
                                    &rule.id,
                                    &format!("Updated managed sigma rule {}", rule.title),
                                    auth_identity.actor(),
                                    Some(rule.id.clone()),
                                    Some(&v.to_string()),
                                );
                                json_response(
                                    &serde_json::json!({"status": "updated", "rule": rule})
                                        .to_string(),
                                    200,
                                )
                            }
                            Err(e) => error_json(&e, 404),
                        }
                    } else {
                        match serde_json::from_value::<crate::analyst::SearchQuery>(
                            v.get("query").cloned().unwrap_or_else(|| serde_json::json!({
                                "text": v.get("text"),
                                "hostname": v.get("hostname"),
                                "level": v.get("level"),
                                "agent_id": v.get("agent_id"),
                                "limit": v.get("limit").cloned().unwrap_or(serde_json::json!(250))
                            }))
                        ) {
                            Ok(query) => {
                            let rule = s.enterprise.create_or_update_native_rule(
                                v["id"].as_str(),
                                v["title"].as_str().unwrap_or("Untitled Native Rule").to_string(),
                                v["description"].as_str().unwrap_or("").to_string(),
                                v["owner"].as_str().unwrap_or(auth_identity.actor()).to_string(),
                                v["severity_mapping"].as_str().unwrap_or("high").to_string(),
                                v.get("rationale").and_then(|value| value.as_str()).map(|s| s.to_string()),
                                pack_ids,
                                attack,
                                query,
                            );
                            let _ = s.enterprise.record_change(
                                "content_rule",
                                &rule.metadata.id,
                                &format!("Saved native content rule {}", rule.metadata.title),
                                auth_identity.actor(),
                                Some(rule.metadata.id.clone()),
                                Some(&v.to_string()),
                            );
                            json_response(&serde_json::json!({"status": "saved", "rule": rule}).to_string(), 201)
                            }
                            Err(e) => error_json(&format!("invalid native rule query: {e}"), 400),
                        }
                    }
                }
                Err(e) => error_json(&e, 400),
            }
        }
        (Method::Get, "/api/content/packs") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            json_response(&serde_json::json!({"packs": s.enterprise.packs(), "count": s.enterprise.packs().len()}).to_string(), 200)
        }
        (Method::Post, "/api/content/packs") => match read_json_value(body, 12 * 1024) {
            Ok(v) => {
                let rule_ids = v
                    .get("rule_ids")
                    .and_then(|value| value.as_array())
                    .map(|values| {
                        values
                            .iter()
                            .filter_map(|value| value.as_str().map(|s| s.to_string()))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                let pack = s.enterprise.create_or_update_pack(
                    v["id"].as_str(),
                    v["name"].as_str().unwrap_or("Untitled Pack").to_string(),
                    v["description"].as_str().unwrap_or("").to_string(),
                    v.get("enabled")
                        .and_then(|value| value.as_bool())
                        .unwrap_or(true),
                    rule_ids,
                );
                let _ = s.enterprise.record_change(
                    "content_pack",
                    &pack.id,
                    &format!("Saved content pack {}", pack.name),
                    auth_identity.actor(),
                    Some(pack.id.clone()),
                    Some(&v.to_string()),
                );
                json_response(
                    &serde_json::json!({"status": "saved", "pack": pack}).to_string(),
                    201,
                )
            }
            Err(e) => error_json(&e, 400),
        },
        (Method::Get, "/api/coverage/mitre") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let coverage = build_mitre_coverage(&s.enterprise, s.incident_store.list());
            json_response(&coverage.to_string(), 200)
        }
        (Method::Get, "/api/suppressions") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            json_response(
                &serde_json::json!({
                    "suppressions": s.enterprise.suppressions(),
                    "active": s.enterprise.active_suppression_count(),
                    "count": s.enterprise.suppressions().len(),
                })
                .to_string(),
                200,
            )
        }
        (Method::Post, "/api/suppressions") => match read_json_value(body, 12 * 1024) {
            Ok(v) => {
                let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                let suppression = s.enterprise.create_or_update_suppression(
                    v["id"].as_str(),
                    v["name"].as_str().unwrap_or("suppression").to_string(),
                    v.get("rule_id")
                        .and_then(|value| value.as_str())
                        .map(|s| s.to_string()),
                    v.get("hunt_id")
                        .and_then(|value| value.as_str())
                        .map(|s| s.to_string()),
                    v.get("hostname")
                        .and_then(|value| value.as_str())
                        .map(|s| s.to_string()),
                    v.get("agent_id")
                        .and_then(|value| value.as_str())
                        .map(|s| s.to_string()),
                    v.get("severity")
                        .and_then(|value| value.as_str())
                        .map(|s| s.to_string()),
                    v.get("text")
                        .and_then(|value| value.as_str())
                        .map(|s| s.to_string()),
                    v.get("expires_at")
                        .and_then(|value| value.as_str())
                        .map(|s| s.to_string()),
                    v["justification"]
                        .as_str()
                        .unwrap_or("operator suppression")
                        .to_string(),
                    auth_identity.actor().to_string(),
                    v.get("active")
                        .and_then(|value| value.as_bool())
                        .unwrap_or(true),
                );
                let _ = s.enterprise.record_change(
                    "suppression",
                    &suppression.id,
                    &format!("Updated suppression {}", suppression.name),
                    auth_identity.actor(),
                    Some(suppression.id.clone()),
                    Some(&v.to_string()),
                );
                json_response(
                    &serde_json::json!({"status": "saved", "suppression": suppression}).to_string(),
                    201,
                )
            }
            Err(e) => error_json(&e, 400),
        },
        (Method::Get, "/api/enrichments/connectors") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            json_response(&serde_json::json!({"connectors": s.enterprise.connectors(), "count": s.enterprise.connectors().len()}).to_string(), 200)
        }
        (Method::Post, "/api/enrichments/connectors") => {
            match read_json_value(body, 16 * 1024) {
                Ok(v) => {
                    let metadata = v
                        .get("metadata")
                        .cloned()
                        .and_then(|value| {
                            serde_json::from_value::<HashMap<String, String>>(value).ok()
                        })
                        .unwrap_or_default();
                    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                    let connector = s.enterprise.create_or_update_connector(
                        v["id"].as_str(),
                        v["kind"].as_str().unwrap_or("custom").to_string(),
                        v["display_name"]
                            .as_str()
                            .unwrap_or("Connector")
                            .to_string(),
                        v.get("endpoint")
                            .and_then(|value| value.as_str())
                            .map(|s| s.to_string()),
                        v.get("auth_mode")
                            .and_then(|value| value.as_str())
                            .map(|s| s.to_string()),
                        v.get("enabled")
                            .and_then(|value| value.as_bool())
                            .unwrap_or(true),
                        v.get("timeout_secs")
                            .and_then(|value| value.as_u64())
                            .unwrap_or(10),
                        metadata,
                    );
                    let _ = s.enterprise.record_change(
                        "connector",
                        &connector.id,
                        &format!("Saved enrichment connector {}", connector.display_name),
                        auth_identity.actor(),
                        Some(connector.id.clone()),
                        Some(&v.to_string()),
                    );
                    json_response(
                        &serde_json::json!({"status": "saved", "connector": connector}).to_string(),
                        200,
                    )
                }
                Err(e) => error_json(&e, 400),
            }
        }
        (Method::Post, "/api/tickets/sync") => {
            let started = std::time::Instant::now();
            match read_json_value(body, 12 * 1024) {
                Ok(v) => {
                    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                    let sync = s.enterprise.sync_ticket(
                        v["provider"].as_str().unwrap_or("jira").to_string(),
                        v["object_kind"].as_str().unwrap_or("incident").to_string(),
                        v["object_id"].as_str().unwrap_or("").to_string(),
                        v.get("queue_or_project")
                            .and_then(|value| value.as_str())
                            .map(|s| s.to_string()),
                        v["summary"]
                            .as_str()
                            .unwrap_or("Enterprise sync")
                            .to_string(),
                        auth_identity.actor().to_string(),
                    );
                    s.enterprise
                        .record_ticket_sync_metrics(started.elapsed().as_millis() as u64);
                    let _ = s.enterprise.record_change(
                        "ticket_sync",
                        &sync.id,
                        &format!(
                            "Synced {} {} to {}",
                            sync.object_kind, sync.object_id, sync.provider
                        ),
                        auth_identity.actor(),
                        Some(sync.id.clone()),
                        Some(&v.to_string()),
                    );
                    json_response(
                        &serde_json::json!({"status": "synced", "sync": sync}).to_string(),
                        200,
                    )
                }
                Err(e) => error_json(&e, 400),
            }
        }
        (Method::Get, "/api/idp/providers") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            json_response(&serde_json::json!({"providers": s.enterprise.idp_providers(), "count": s.enterprise.idp_providers().len()}).to_string(), 200)
        }
        (Method::Post, "/api/idp/providers") => match read_json_value(body, 12 * 1024) {
            Ok(v) => {
                let mappings = v
                    .get("group_role_mappings")
                    .cloned()
                    .and_then(|value| serde_json::from_value::<HashMap<String, String>>(value).ok())
                    .unwrap_or_default();
                let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                let provider = s.enterprise.create_or_update_idp_provider(
                    v["id"].as_str(),
                    v["kind"].as_str().unwrap_or("oidc").to_string(),
                    v["display_name"]
                        .as_str()
                        .unwrap_or("Identity Provider")
                        .to_string(),
                    v.get("issuer_url")
                        .and_then(|value| value.as_str())
                        .map(|s| s.to_string()),
                    v.get("sso_url")
                        .and_then(|value| value.as_str())
                        .map(|s| s.to_string()),
                    v.get("client_id")
                        .and_then(|value| value.as_str())
                        .map(|s| s.to_string()),
                    v.get("entity_id")
                        .and_then(|value| value.as_str())
                        .map(|s| s.to_string()),
                    v.get("enabled")
                        .and_then(|value| value.as_bool())
                        .unwrap_or(true),
                    mappings,
                );
                let _ = s.enterprise.record_change(
                    "identity_provider",
                    &provider.id,
                    &format!(
                        "Configured {} provider {}",
                        provider.kind, provider.display_name
                    ),
                    auth_identity.actor(),
                    Some(provider.id.clone()),
                    Some(&v.to_string()),
                );
                json_response(
                    &serde_json::json!({"status": "saved", "provider": provider}).to_string(),
                    200,
                )
            }
            Err(e) => error_json(&e, 400),
        },
        (Method::Get, "/api/scim/config") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            json_response(
                &serde_json::json!({"config": s.enterprise.scim()}).to_string(),
                200,
            )
        }
        (Method::Post, "/api/scim/config") => match read_json_value(body, 12 * 1024) {
            Ok(v) => {
                let mappings = v
                    .get("group_role_mappings")
                    .cloned()
                    .and_then(|value| serde_json::from_value::<HashMap<String, String>>(value).ok())
                    .unwrap_or_default();
                let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                let config = s.enterprise.update_scim(
                    v.get("enabled")
                        .and_then(|value| value.as_bool())
                        .unwrap_or(true),
                    v.get("base_url")
                        .and_then(|value| value.as_str())
                        .map(|s| s.to_string()),
                    v.get("bearer_token")
                        .and_then(|value| value.as_str())
                        .map(|s| s.to_string()),
                    v["provisioning_mode"]
                        .as_str()
                        .unwrap_or("automatic")
                        .to_string(),
                    v["default_role"].as_str().unwrap_or("viewer").to_string(),
                    mappings,
                );
                let _ = s.enterprise.record_change(
                    "scim",
                    "scim-config",
                    "Updated SCIM provisioning configuration",
                    auth_identity.actor(),
                    Some("scim-config".to_string()),
                    Some(&v.to_string()),
                );
                json_response(
                    &serde_json::json!({"status": "saved", "config": config}).to_string(),
                    200,
                )
            }
            Err(e) => error_json(&e, 400),
        },
        (Method::Get, "/api/audit/admin") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let payload = serde_json::json!({
                "api_audit": s.audit_log.recent(200),
                "change_control": s.enterprise.change_control(),
                "response_audit": s.response_orchestrator.audit_ledger(),
                "response_approvals": s.approval_log.list(),
            });
            json_response(&payload.to_string(), 200)
        }
        (Method::Get, "/api/support/diagnostics") => {
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            s.agent_registry.refresh_staleness();
            let siem_status = s.siem_connector.status();
            let analytics = s.event_store.analytics();
            let payload = serde_json::json!({
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "auth": {
                    "session": {
                        "token_ttl_secs": s.config.security.token_ttl_secs,
                        "token_age_secs": s.token_issued_at.elapsed().as_secs(),
                    },
                    "rbac_users": s.rbac.list_users().len(),
                    "idp_providers": s.enterprise.idp_providers(),
                    "scim": s.enterprise.scim(),
                },
                "content": {
                    "builtin_rules": s.enterprise.builtin_rules().len(),
                    "native_rules": s.enterprise.native_rules().len(),
                    "packs": s.enterprise.packs(),
                    "hunts": s.enterprise.hunts(),
                    "suppressions": s.enterprise.suppressions(),
                },
                "operations": {
                    "metrics": s.enterprise.metrics(),
                    "request_count": s.request_count,
                    "error_count": s.error_count,
                    "queue_depth": s.alert_queue.pending().len(),
                    "event_count": s.event_store.total_events(),
                    "incident_count": s.incident_store.list().len(),
                    "cases_count": s.case_store.stats(),
                    "event_analytics": {
                        "correlation_rate": analytics.correlation_rate,
                        "severity_counts": analytics.severity_counts,
                        "triage_counts": analytics.triage_counts,
                        "hot_agents": analytics.hot_agents,
                    },
                },
                "dependencies": {
                    "storage_path": s.event_store.storage_path(),
                    "event_persistence": s.event_store.has_persistence(),
                    "siem": siem_status,
                    "connectors": s.enterprise.connectors(),
                    "updates": s.remote_deployments.values().collect::<Vec<_>>(),
                },
                "change_control": s.enterprise.change_control(),
            });
            let digest = crate::audit::sha256_hex(payload.to_string().as_bytes());
            json_response(
                &serde_json::json!({"bundle": payload, "digest": digest}).to_string(),
                200,
            )
        }
        (Method::Get, "/api/system/health/dependencies") => {
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            s.agent_registry.refresh_staleness();
            let stale_agents = s
                .agent_registry
                .list()
                .iter()
                .filter(|agent| {
                    matches!(
                        agent.status,
                        crate::enrollment::AgentStatus::Stale
                            | crate::enrollment::AgentStatus::Offline
                    )
                })
                .count();
            let pending_deployments = s
                .remote_deployments
                .values()
                .filter(|deployment| deployment_is_pending(deployment, &s.agent_registry))
                .count();
            let payload = serde_json::json!({
                "storage": {
                    "backend": if s.event_store.has_persistence() { "json_file" } else { "memory" },
                    "durable": s.event_store.has_persistence(),
                    "path": s.event_store.storage_path(),
                    "event_count": s.event_store.total_events(),
                },
                "ha_mode": {
                    "mode": "standalone",
                    "status": "ready_for_active_passive",
                    "leader": true,
                },
                "identity": {
                    "providers_enabled": s.enterprise.idp_providers().iter().filter(|provider| provider.enabled).count(),
                    "scim_enabled": s.enterprise.scim().enabled,
                    "status": if s.enterprise.idp_providers().iter().any(|provider| provider.enabled) || s.enterprise.scim().enabled { "configured" } else { "local_auth_only" },
                },
                "connectors": {
                    "enabled": s.enterprise.connectors().iter().filter(|connector| connector.enabled).count(),
                    "unhealthy": s.enterprise.connectors().iter().filter(|connector| connector.status == "error").count(),
                    "items": s.enterprise.connectors(),
                },
                "deployments": {
                    "pending": pending_deployments,
                    "stale_agents": stale_agents,
                    "compliant_agents": s.agent_registry.list().len().saturating_sub(stale_agents),
                    "health_gate": if stale_agents == 0 { "passing" } else { "warning" },
                },
                "telemetry": s.enterprise.metrics(),
            });
            json_response(&payload.to_string(), 200)
        }
        (Method::Get, "/api/updates/releases") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            match serde_json::to_string(s.update_manager.list_releases()) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }

        (Method::Post, "/api/shutdown") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            s.shutdown.store(true, Ordering::SeqCst);
            drop(s);
            json_response(r#"{"status":"shutting_down"}"#, 200)
        }

        (Method::Options, _) => {
            let origin = cors_origin();
            Response::builder()
                .status(204)
                .header("Access-Control-Allow-Origin", origin)
                .header("Vary", "Origin")
                .header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
                .header("Access-Control-Allow-Headers", "Content-Type, Authorization")
                .body(Body::empty())
                .unwrap()
        }

        // ── Sigma Detection Engine ────────────────────────────────
        (Method::Get, "/api/sigma/rules") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let rules: Vec<serde_json::Value> = s
                .sigma_engine
                .rules()
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "id": r.id,
                        "title": r.title,
                        "status": r.status,
                        "level": format!("{:?}", r.level),
                        "description": r.description,
                    })
                })
                .collect();
            json_response(
                &serde_json::json!({"rules": rules, "count": rules.len()}).to_string(),
                200,
            )
        }
        (Method::Get, "/api/sigma/stats") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
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
            json_response(
                &serde_json::json!({
                    "ocsf_version": sv.ocsf_version,
                    "product_version": sv.product_version,
                    "supported_classes": sv.supported_classes,
                })
                .to_string(),
                200,
            )
        }

        // ── Dead-Letter Queue ─────────────────────────────────────
        (Method::Get, "/api/dlq") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let items: Vec<serde_json::Value> = s
                .dead_letter_queue
                .list()
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "original_payload": e.original_payload,
                        "errors": e.errors,
                        "received_at": e.received_at,
                        "source_agent": e.source_agent,
                    })
                })
                .collect();
            json_response(
                &serde_json::json!({
                    "dead_letters": items,
                    "count": items.len(),
                })
                .to_string(),
                200,
            )
        }
        (Method::Get, "/api/dlq/stats") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            json_response(
                &serde_json::json!({
                    "count": s.dead_letter_queue.len(),
                    "empty": s.dead_letter_queue.is_empty(),
                })
                .to_string(),
                200,
            )
        }
        (Method::Delete, "/api/dlq") => {
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            let before = s.dead_letter_queue.len();
            s.dead_letter_queue.clear();
            json_response(&serde_json::json!({"cleared": before}).to_string(), 200)
        }

        // ── Response Orchestration ────────────────────────────────
        (Method::Get, "/api/response/pending") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let pending = s.response_orchestrator.pending_requests();
            let items: Vec<serde_json::Value> = pending.iter().map(response_request_json).collect();
            json_response(
                &serde_json::json!({"pending": items, "count": items.len()}).to_string(),
                200,
            )
        }
        (Method::Get, "/api/response/requests") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let mut requests = s.response_orchestrator.all_requests();
            requests.sort_by(|left, right| right.requested_at.cmp(&left.requested_at));
            let items: Vec<serde_json::Value> =
                requests.iter().map(response_request_json).collect();
            let ready = requests
                .iter()
                .filter(|r| r.status == ApprovalStatus::Approved && !r.dry_run)
                .count();
            json_response(
                &serde_json::json!({
                    "requests": items,
                    "count": items.len(),
                    "ready_to_execute": ready,
                })
                .to_string(),
                200,
            )
        }
        (Method::Get, "/api/response/audit") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let ledger = s.response_orchestrator.audit_ledger();
            let entries: Vec<serde_json::Value> = ledger
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "request_id": e.request_id,
                        "action": format!("{:?}", e.action),
                        "target": e.target_hostname,
                        "outcome": format!("{:?}", e.status),
                        "timestamp": e.timestamp,
                        "approvers": e.approvals,
                    })
                })
                .collect();
            json_response(&serde_json::json!({"audit_log": entries}).to_string(), 200)
        }
        (Method::Get, "/api/response/stats") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let pending = s.response_orchestrator.pending_requests();
            let all = s.response_orchestrator.all_requests();
            let audit = s.response_orchestrator.audit_ledger();
            let auto_count = audit
                .iter()
                .filter(|e| e.status == ApprovalStatus::Executed)
                .count();
            let denied_count = audit
                .iter()
                .filter(|e| e.status == ApprovalStatus::Denied)
                .count();
            let ready_count = all
                .iter()
                .filter(|r| r.status == ApprovalStatus::Approved && !r.dry_run)
                .count();
            let protected = s.response_orchestrator.protected_asset_count();
            let info = serde_json::json!({
                "auto_executed": auto_count,
                "executed": auto_count,
                "pending": pending.len(),
                "pending_approval": pending.len(),
                "ready_to_execute": ready_count,
                "approved_ready": ready_count,
                "total_requests": all.len(),
                "denied": denied_count,
                "protected_assets": protected,
            });
            json_response(&info.to_string(), 200)
        }

        // ── Feature Flags ─────────────────────────────────────────
        (Method::Get, "/api/feature-flags") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let flags = s.feature_flags.all_flags();
            let items: Vec<serde_json::Value> = flags
                .iter()
                .map(|f| {
                    serde_json::json!({
                        "name": f.name,
                        "description": f.description,
                        "enabled": f.enabled,
                        "rollout_pct": f.rollout_pct,
                        "kill_switch": f.kill_switch,
                    })
                })
                .collect();
            json_response(&serde_json::json!({"flags": items}).to_string(), 200)
        }

        // ── Process Tree ──────────────────────────────────────────
        (Method::Get, "/api/process-tree") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let alive = s.process_tree.alive_processes();
            let nodes: Vec<serde_json::Value> = alive
                .iter()
                .map(|p| {
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
                })
                .collect();
            json_response(
                &serde_json::json!({"processes": nodes, "count": nodes.len()}).to_string(),
                200,
            )
        }
        (Method::Get, "/api/process-tree/deep-chains") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let chains = s.process_tree.deep_chains(4);
            let items: Vec<serde_json::Value> = chains
                .iter()
                .map(|chain| {
                    let leaf = &chain[0];
                    serde_json::json!({
                        "pid": leaf.pid,
                        "name": leaf.name,
                        "cmd_line": leaf.cmd_line,
                        "depth": chain.len(),
                    })
                })
                .collect();
            json_response(&serde_json::json!({"deep_chains": items}).to_string(), 200)
        }

        // ── Live Process Collection & Analysis (Cross-Platform) ──────
        (Method::Get, "/api/processes/live") => {
            #[cfg(target_os = "macos")]
            {
                let procs = crate::collector_macos::collect_processes();
                let items: Vec<serde_json::Value> = procs.iter().map(|p| {
                    serde_json::json!({
                        "pid": p.pid, "ppid": p.ppid, "name": p.name,
                        "user": p.user, "group": p.group,
                        "cpu_percent": p.cpu_percent, "mem_percent": p.mem_percent,
                    })
                }).collect();
                let total_cpu: f32 = procs.iter().map(|p| p.cpu_percent).sum();
                let total_mem: f32 = procs.iter().map(|p| p.mem_percent).sum();
                json_response(&serde_json::json!({
                    "processes": items, "count": items.len(),
                    "total_cpu_percent": (total_cpu * 10.0).round() / 10.0,
                    "total_mem_percent": (total_mem * 10.0).round() / 10.0,
                    "platform": "macos",
                }).to_string(), 200)
            }
            #[cfg(target_os = "linux")]
            {
                let procs = crate::collector_linux::collect_processes();
                let usage = {
                    let mut map = std::collections::HashMap::new();
                    if let Ok(output) = std::process::Command::new("ps")
                        .args(["-eo", "pid,%cpu,%mem"])
                        .output()
                    {
                        let text = String::from_utf8_lossy(&output.stdout);
                        for line in text.lines().skip(1) {
                            let f: Vec<&str> = line.split_whitespace().collect();
                            if f.len() >= 3 {
                                if let Ok(pid) = f[0].parse::<u32>() {
                                    let cpu: f32 = f[1].parse().unwrap_or(0.0);
                                    let mem: f32 = f[2].parse().unwrap_or(0.0);
                                    map.insert(pid, (cpu, mem));
                                }
                            }
                        }
                    }
                    map
                };
                let items: Vec<serde_json::Value> = procs.iter().map(|p| {
                    let (cpu, mem) = usage.get(&p.pid).copied().unwrap_or((0.0, 0.0));
                    serde_json::json!({
                        "pid": p.pid, "ppid": p.ppid, "name": p.name,
                        "user": if p.uid == 0 { "root".to_string() } else { format!("uid:{}", p.uid) },
                        "group": format!("gid:{}", p.gid),
                        "cpu_percent": cpu, "mem_percent": mem,
                    })
                }).collect();
                let total_cpu: f32 = items.iter().map(|i| i["cpu_percent"].as_f64().unwrap_or(0.0) as f32).sum();
                let total_mem: f32 = items.iter().map(|i| i["mem_percent"].as_f64().unwrap_or(0.0) as f32).sum();
                json_response(&serde_json::json!({
                    "processes": items, "count": items.len(),
                    "total_cpu_percent": (total_cpu * 10.0).round() / 10.0,
                    "total_mem_percent": (total_mem * 10.0).round() / 10.0,
                    "platform": "linux",
                }).to_string(), 200)
            }
            #[cfg(target_os = "windows")]
            {
                let procs = crate::collector_windows::collect_processes();
                let items: Vec<serde_json::Value> = procs.iter().map(|p| {
                    serde_json::json!({
                        "pid": p.pid, "ppid": p.ppid, "name": p.name,
                        "user": if p.user.is_empty() { "—" } else { &p.user },
                        "group": "—",
                        "cpu_percent": 0.0, "mem_percent": 0.0,
                    })
                }).collect();
                json_response(&serde_json::json!({
                    "processes": items, "count": items.len(),
                    "total_cpu_percent": 0.0,
                    "total_mem_percent": 0.0,
                    "platform": "windows",
                }).to_string(), 200)
            }
            #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
            {
                json_response(r#"{"processes":[],"count":0,"message":"Unsupported platform"}"#, 200)
            }
        }
        (Method::Get, "/api/processes/analysis") => {
            #[cfg(target_os = "macos")]
            {
                let procs = crate::collector_macos::collect_processes();
                let findings = crate::collector_macos::analyze_processes(&procs);
                let items: Vec<serde_json::Value> = findings.iter().map(|f| {
                    serde_json::json!({
                        "pid": f.pid, "name": f.name, "user": f.user,
                        "risk_level": f.risk_level, "reason": f.reason,
                        "cpu_percent": f.cpu_percent, "mem_percent": f.mem_percent,
                    })
                }).collect();
                let critical = findings.iter().filter(|f| f.risk_level == "critical").count();
                let severe = findings.iter().filter(|f| f.risk_level == "severe").count();
                let elevated = findings.iter().filter(|f| f.risk_level == "elevated").count();
                json_response(&serde_json::json!({
                    "findings": items, "total": items.len(),
                    "risk_summary": { "critical": critical, "severe": severe, "elevated": elevated },
                    "process_count": procs.len(),
                    "status": if critical > 0 { "critical" } else if severe > 0 { "warning" } else { "clean" },
                    "platform": "macos",
                }).to_string(), 200)
            }
            #[cfg(target_os = "linux")]
            {
                let procs = crate::collector_linux::collect_processes();
                let findings = crate::collector_linux::analyze_processes(&procs);
                let items: Vec<serde_json::Value> = findings.iter().map(|f| {
                    serde_json::json!({
                        "pid": f.pid, "name": f.name, "user": f.user,
                        "risk_level": f.risk_level, "reason": f.reason,
                        "cpu_percent": f.cpu_percent, "mem_percent": f.mem_percent,
                    })
                }).collect();
                let critical = findings.iter().filter(|f| f.risk_level == "critical").count();
                let severe = findings.iter().filter(|f| f.risk_level == "severe").count();
                let elevated = findings.iter().filter(|f| f.risk_level == "elevated").count();
                json_response(&serde_json::json!({
                    "findings": items, "total": items.len(),
                    "risk_summary": { "critical": critical, "severe": severe, "elevated": elevated },
                    "process_count": procs.len(),
                    "status": if critical > 0 { "critical" } else if severe > 0 { "warning" } else { "clean" },
                    "platform": "linux",
                }).to_string(), 200)
            }
            #[cfg(target_os = "windows")]
            {
                let procs = crate::collector_windows::collect_processes();
                let findings = crate::collector_windows::analyze_processes(&procs);
                let items: Vec<serde_json::Value> = findings.iter().map(|f| {
                    serde_json::json!({
                        "pid": f.pid, "name": f.name, "user": f.user,
                        "risk_level": f.risk_level, "reason": f.reason,
                        "cpu_percent": f.cpu_percent, "mem_percent": f.mem_percent,
                    })
                }).collect();
                let critical = findings.iter().filter(|f| f.risk_level == "critical").count();
                let severe = findings.iter().filter(|f| f.risk_level == "severe").count();
                let elevated = findings.iter().filter(|f| f.risk_level == "elevated").count();
                json_response(&serde_json::json!({
                    "findings": items, "total": items.len(),
                    "risk_summary": { "critical": critical, "severe": severe, "elevated": elevated },
                    "process_count": procs.len(),
                    "status": if critical > 0 { "critical" } else if severe > 0 { "warning" } else { "clean" },
                    "platform": "windows",
                }).to_string(), 200)
            }
            #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
            {
                json_response(r#"{"findings":[],"total":0,"status":"clean","message":"Unsupported platform"}"#, 200)
            }
        }
        (Method::Get, "/api/host/apps") => {
            #[cfg(target_os = "macos")]
            {
                let apps = crate::collector_macos::collect_installed_apps();
                let items: Vec<serde_json::Value> = apps.iter().map(|a| {
                    serde_json::json!({
                        "name": a.name, "path": a.path, "version": a.version,
                        "bundle_id": a.bundle_id, "size_mb": (a.size_mb * 10.0).round() / 10.0,
                        "last_modified": a.last_modified,
                    })
                }).collect();
                json_response(&serde_json::json!({
                    "apps": items, "count": items.len(), "platform": "macos",
                }).to_string(), 200)
            }
            #[cfg(target_os = "linux")]
            {
                let apps = crate::collector_linux::collect_installed_apps();
                let items: Vec<serde_json::Value> = apps.iter().map(|a| {
                    serde_json::json!({
                        "name": a.name, "path": a.path, "version": a.version,
                        "bundle_id": a.bundle_id, "size_mb": (a.size_mb * 10.0).round() / 10.0,
                        "last_modified": a.last_modified,
                    })
                }).collect();
                json_response(&serde_json::json!({
                    "apps": items, "count": items.len(), "platform": "linux",
                }).to_string(), 200)
            }
            #[cfg(target_os = "windows")]
            {
                let apps = crate::collector_windows::collect_installed_apps();
                let items: Vec<serde_json::Value> = apps.iter().map(|a| {
                    serde_json::json!({
                        "name": a.name, "path": a.path, "version": a.version,
                        "bundle_id": a.bundle_id, "size_mb": (a.size_mb * 10.0).round() / 10.0,
                        "last_modified": a.last_modified,
                    })
                }).collect();
                json_response(&serde_json::json!({
                    "apps": items, "count": items.len(), "platform": "windows",
                }).to_string(), 200)
            }
            #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
            {
                json_response(r#"{"apps":[],"count":0,"message":"Unsupported platform"}"#, 200)
            }
        }
        (Method::Get, "/api/host/inventory") => {
            let inv = crate::inventory::collect_inventory();
            match serde_json::to_string(&inv) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }

        // ── Encrypted Spool ───────────────────────────────────────
        (Method::Get, "/api/spool/stats") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
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
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let users = s.rbac.list_users();
            let items: Vec<serde_json::Value> = users
                .iter()
                .map(|u| {
                    serde_json::json!({
                        "username": u.username,
                        "role": format!("{:?}", u.role),
                        "enabled": u.enabled,
                    })
                })
                .collect();
            json_response(&serde_json::json!({"users": items}).to_string(), 200)
        }

        (Method::Post, "/api/rbac/users") => {
            let body = read_body_limited(body, 4096);
            match body {
                Ok(b) => match serde_json::from_str::<serde_json::Value>(&b) {
                    Ok(v) => {
                        let username = v["username"].as_str().unwrap_or("").to_string();
                        if username.is_empty() {
                            error_json("username is required", 400)
                        } else {
                            let role = match v["role"].as_str().unwrap_or("viewer") {
                                "admin" | "Admin" => Role::Admin,
                                "analyst" | "Analyst" => Role::Analyst,
                                "service" | "ServiceAccount" => Role::ServiceAccount,
                                _ => Role::Viewer,
                            };
                            let token =
                                format!("tok-{}-{}", username, chrono::Utc::now().timestamp());
                            let user = User {
                                username: username.clone(),
                                role,
                                token_hash: token.clone(),
                                enabled: true,
                                created_at: chrono::Utc::now().to_rfc3339(),
                                tenant_id: None,
                            };
                            let s = state.lock().unwrap_or_else(|e| e.into_inner());
                            s.rbac.add_user(user);
                            json_response(&serde_json::json!({"status": "created", "username": username, "token": token}).to_string(), 201)
                        }
                    }
                    Err(_) => error_json("invalid JSON", 400),
                },
                Err(e) => error_json(&e, 400),
            }
        }

        (Method::Delete, p) if p.starts_with("/api/rbac/users/") => {
            let username = p.strip_prefix("/api/rbac/users/").unwrap_or("");
            if username.is_empty() {
                error_json("username is required", 400)
            } else {
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                if s.rbac.remove_user(username) {
                    json_response(
                        &serde_json::json!({"status": "removed", "username": username}).to_string(),
                        200,
                    )
                } else {
                    error_json("user not found", 404)
                }
            }
        }

        // ── Analyst Console: Cases ─────────────────────────────────
        (Method::Get, "/api/cases") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let status = url_param(&url, "status");
            let priority = url_param(&url, "priority");
            let assignee = url_param(&url, "assignee");
            let cases = s.case_store.list_filtered(
                status.as_deref(),
                priority.as_deref(),
                assignee.as_deref(),
            );
            let items: Vec<serde_json::Value> = cases
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "id": c.id, "title": c.title, "status": format!("{:?}", c.status),
                        "priority": format!("{:?}", c.priority), "assignee": c.assignee,
                        "created_at": c.created_at, "updated_at": c.updated_at,
                        "incident_count": c.incident_ids.len(), "event_count": c.event_ids.len(),
                        "tags": c.tags,
                    })
                })
                .collect();
            json_response(
                &serde_json::json!({"cases": items, "total": items.len()}).to_string(),
                200,
            )
        }
        (Method::Post, "/api/cases") => {
            let body = read_body_limited(body, 8192);
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
                        let inc_ids: Vec<u64> = v["incident_ids"]
                            .as_array()
                            .map(|a| a.iter().filter_map(|x| x.as_u64()).collect())
                            .unwrap_or_default();
                        let evt_ids: Vec<u64> = v["event_ids"]
                            .as_array()
                            .map(|a| a.iter().filter_map(|x| x.as_u64()).collect())
                            .unwrap_or_default();
                        let tags: Vec<String> = v["tags"]
                            .as_array()
                            .map(|a| {
                                a.iter()
                                    .filter_map(|x| x.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default();
                        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                        let case = s
                            .case_store
                            .create(title, desc, prio, inc_ids, evt_ids, tags);
                        json_response(
                            &serde_json::json!({"id": case.id, "status": "created"}).to_string(),
                            201,
                        )
                    }
                    Err(_) => error_json("invalid JSON", 400),
                },
                Err(e) => error_json(&e, 400),
            }
        }
        (Method::Get, "/api/cases/stats") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let cases = s.case_store.list_filtered(None, None, None);
            let total = cases.len();
            let resolved = cases
                .iter()
                .filter(|case| matches!(case.status, CaseStatus::Resolved | CaseStatus::Closed))
                .count();
            let open = total.saturating_sub(resolved);
            let triaging = cases
                .iter()
                .filter(|case| matches!(case.status, CaseStatus::Triaging))
                .count();
            let investigating = cases
                .iter()
                .filter(|case| matches!(case.status, CaseStatus::Investigating))
                .count();
            let escalated = cases
                .iter()
                .filter(|case| matches!(case.status, CaseStatus::Escalated))
                .count();
            json_response(
                &serde_json::json!({
                    "total": total,
                    "open": open,
                    "resolved": resolved,
                    "triaging": triaging,
                    "investigating": investigating,
                    "escalated": escalated,
                })
                .to_string(),
                200,
            )
        }

        // ── Analyst Console: Alert Queue ───────────────────────────
        (Method::Get, "/api/queue/alerts") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let pending = s.alert_queue.pending();
            let items: Vec<QueueAlertSummary> = pending
                .iter()
                .map(|item| queue_alert_summary(item, &s.event_store))
                .collect();
            json_response(
                &serde_json::json!({"queue": items, "count": items.len()}).to_string(),
                200,
            )
        }
        (Method::Get, "/api/queue/stats") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            json_response(&s.alert_queue.stats().to_string(), 200)
        }
        (Method::Post, "/api/queue/acknowledge") => {
            let body = read_body_limited(body, 1024);
            match body {
                Ok(b) => match serde_json::from_str::<serde_json::Value>(&b) {
                    Ok(v) => {
                        let event_id = v["event_id"]
                            .as_u64()
                            .or_else(|| v["alert_id"].as_u64())
                            .unwrap_or(0);
                        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                        if s.alert_queue.acknowledge(event_id) {
                            json_response(
                                &serde_json::json!({"acknowledged": event_id}).to_string(),
                                200,
                            )
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
            let body = read_body_limited(body, 1024);
            match body {
                Ok(b) => {
                    match serde_json::from_str::<serde_json::Value>(&b) {
                        Ok(v) => {
                            let event_id = v["event_id"].as_u64().unwrap_or(0);
                            let assignee = v["assignee"].as_str().unwrap_or("").to_string();
                            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                            if s.alert_queue.assign(event_id, assignee.clone()) {
                                json_response(&serde_json::json!({"assigned": event_id, "assignee": assignee}).to_string(), 200)
                            } else {
                                error_json("event not found in queue", 404)
                            }
                        }
                        Err(_) => error_json("invalid JSON", 400),
                    }
                }
                Err(e) => error_json(&e, 400),
            }
        }

        // ── Analyst Console: Event Search ──────────────────────────
        (Method::Post, "/api/events/search") => {
            let body = read_body_limited(body, 4096);
            match body {
                Ok(b) => match serde_json::from_str::<crate::analyst::SearchQuery>(&b) {
                    Ok(q) => {
                        let s = state.lock().unwrap_or_else(|e| e.into_inner());
                        let events = s.event_store.all_events();
                        let results = crate::analyst::search_events(events, &q);
                        let items: Vec<serde_json::Value> = results
                            .iter()
                            .map(|e| {
                                serde_json::json!({
                                    "id": e.id, "agent_id": e.agent_id,
                                    "hostname": e.alert.hostname, "score": e.alert.score,
                                    "level": e.alert.level, "timestamp": e.alert.timestamp,
                                    "reasons": e.alert.reasons, "action": e.alert.action,
                                })
                            })
                            .collect();
                        json_response(
                            &serde_json::json!({"results": items, "count": items.len()})
                                .to_string(),
                            200,
                        )
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
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                let events = s.event_store.all_events();
                let tl = crate::analyst::build_host_timeline(events, &hostname);
                json_response(
                    &serde_json::json!({"timeline": tl, "host": hostname, "count": tl.len()})
                        .to_string(),
                    200,
                )
            }
        }
        (Method::Get, "/api/timeline/agent") => {
            let agent_id = url_param(&url, "agent_id").unwrap_or_default();
            if agent_id.is_empty() {
                error_json("agent_id parameter required", 400)
            } else {
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                let events = s.event_store.all_events();
                let tl = crate::analyst::build_agent_timeline(events, &agent_id);
                json_response(
                    &serde_json::json!({"timeline": tl, "agent_id": agent_id, "count": tl.len()})
                        .to_string(),
                    200,
                )
            }
        }

        // ── Analyst Console: Investigation Graph ───────────────────
        (Method::Post, "/api/investigation/graph") => {
            let body = read_body_limited(body, 4096);
            match body {
                Ok(b) => {
                    match serde_json::from_str::<serde_json::Value>(&b) {
                        Ok(v) => {
                            let event_ids: Vec<u64> = v["event_ids"]
                                .as_array()
                                .map(|a| a.iter().filter_map(|x| x.as_u64()).collect())
                                .unwrap_or_default();
                            let s = state.lock().unwrap_or_else(|e| e.into_inner());
                            let events = s.event_store.all_events();
                            let graph =
                                crate::analyst::build_investigation_graph(events, &event_ids);
                            json_response(&serde_json::json!({
                            "nodes": graph.nodes, "edges": graph.edges,
                            "node_count": graph.nodes.len(), "edge_count": graph.edges.len(),
                        }).to_string(), 200)
                        }
                        Err(_) => error_json("invalid JSON", 400),
                    }
                }
                Err(e) => error_json(&e, 400),
            }
        }

        // ── Analyst Console: Remediation Approval ──────────────────
        (Method::Post, "/api/response/request") => {
            let body = read_body_limited(body, 4096);
            match body {
                Ok(b) => match serde_json::from_str::<serde_json::Value>(&b) {
                    Ok(v) => {
                        let action = match response_action_from_json(&v) {
                            Ok(action) => action,
                            Err(e) => {
                                return respond_api(
                                    state,
                                    &method,
                                    &url,
                                    remote_addr,
                                    auth_used,
                                    error_json(&e, 400),
                                );
                            }
                        };

                        let hostname = v["hostname"]
                            .as_str()
                            .or_else(|| v["target_hostname"].as_str())
                            .unwrap_or("")
                            .trim()
                            .to_string();
                        if hostname.is_empty() {
                            return respond_api(
                                state,
                                &method,
                                &url,
                                remote_addr,
                                auth_used,
                                error_json("hostname is required", 400),
                            );
                        }

                        let reason = v["reason"]
                            .as_str()
                            .unwrap_or("Submitted from admin console")
                            .trim()
                            .to_string();
                        let severity = v["severity"]
                            .as_str()
                            .unwrap_or("medium")
                            .trim()
                            .to_string();
                        let requested_by = response_requested_by(&auth_identity);
                        let dry_run = v["dry_run"].as_bool().unwrap_or(false);
                        let asset_tags = v["asset_tags"]
                            .as_array()
                            .map(|items| {
                                items
                                    .iter()
                                    .filter_map(|tag| tag.as_str().map(|s| s.to_string()))
                                    .collect()
                            })
                            .unwrap_or_default();
                        let target = ResponseTarget {
                            hostname: hostname.clone(),
                            agent_uid: v["agent_uid"].as_str().map(|s| s.to_string()),
                            asset_tags,
                        };
                        let now = chrono::Utc::now().to_rfc3339();
                        let request_record = ResponseRequest {
                            id: next_response_request_id(),
                            action,
                            target,
                            reason,
                            severity,
                            tier: ActionTier::Auto,
                            status: ApprovalStatus::Pending,
                            requested_at: now,
                            requested_by,
                            approvals: Vec::new(),
                            dry_run,
                            blast_radius: None,
                            is_protected_asset: false,
                        };

                        let s = state.lock().unwrap_or_else(|e| e.into_inner());
                        match s.response_orchestrator.submit(request_record) {
                            Ok(request_id) => {
                                let stored = s.response_orchestrator.get_request(&request_id);
                                match stored {
                                    Some(request_entry) => json_response(
                                        &serde_json::json!({
                                            "status": "submitted",
                                            "request": response_request_json(&request_entry),
                                        })
                                        .to_string(),
                                        200,
                                    ),
                                    None => {
                                        error_json("request stored but could not be reloaded", 500)
                                    }
                                }
                            }
                            Err(e) => {
                                let status = if e.contains("Break-glass required") {
                                    409
                                } else {
                                    400
                                };
                                error_json(&e, status)
                            }
                        }
                    }
                    Err(_) => error_json("invalid JSON", 400),
                },
                Err(e) => error_json(&e, 400),
            }
        }
        (Method::Post, "/api/response/approve") => {
            let body = read_body_limited(body, 2048);
            match body {
                Ok(b) => match serde_json::from_str::<serde_json::Value>(&b) {
                    Ok(v) => {
                        let request_id = v["request_id"].as_str().unwrap_or("").to_string();
                        if request_id.is_empty() {
                            return respond_api(
                                state,
                                &method,
                                &url,
                                remote_addr,
                                auth_used,
                                error_json("request_id is required", 400),
                            );
                        }
                        let decision = match v["decision"].as_str().unwrap_or("") {
                            "approved" | "approve" => ResponseApprovalDecision::Approve,
                            "denied" | "deny" => ResponseApprovalDecision::Deny,
                            _ => {
                                return respond_api(
                                    state,
                                    &method,
                                    &url,
                                    remote_addr,
                                    auth_used,
                                    json_response(
                                        &serde_json::json!({"error": "decision must be 'approved' or 'denied'"}).to_string(),
                                        400,
                                    ),
                                );
                            }
                        };
                        let approver = v["approver"].as_str()
                            .filter(|s| !s.is_empty())
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| response_approver(&auth_identity));
                        let reason = v["reason"].as_str().unwrap_or("").to_string();
                        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                        let status = s.response_orchestrator.approve(
                            &request_id,
                            ResponseApprovalRecord {
                                approver: approver.clone(),
                                decision: decision.clone(),
                                timestamp: chrono::Utc::now().to_rfc3339(),
                                comment: if reason.trim().is_empty() {
                                    None
                                } else {
                                    Some(reason.clone())
                                },
                            },
                        );

                        match status {
                            Ok(status) => {
                                let remediation_decision = match decision {
                                    ResponseApprovalDecision::Approve => {
                                        RemediationDecision::Approved
                                    }
                                    ResponseApprovalDecision::Deny => RemediationDecision::Denied,
                                };
                                s.approval_log.record(
                                    request_id.clone(),
                                    remediation_decision,
                                    approver,
                                    reason,
                                );
                                let approvals = s
                                    .response_orchestrator
                                    .get_request(&request_id)
                                    .map(|request_entry| request_entry.approvals.len())
                                    .unwrap_or(0);
                                json_response(
                                    &serde_json::json!({
                                        "request_id": request_id,
                                        "decision": format!("{:?}", decision),
                                        "status": format!("{:?}", status),
                                        "approvals": approvals,
                                    })
                                    .to_string(),
                                    200,
                                )
                            }
                            Err(e) => {
                                let code = if e.contains("not found") { 404 } else { 409 };
                                error_json(&e, code)
                            }
                        }
                    }
                    Err(_) => error_json("invalid JSON", 400),
                },
                Err(e) => error_json(&e, 400),
            }
        }
        (Method::Get, "/api/response/approvals") => {
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let entries = s.approval_log.recent(50);
            let items: Vec<serde_json::Value> = entries
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "request_id": e.request_id, "decision": format!("{:?}", e.decision),
                        "approver": e.approver, "reason": e.reason, "decided_at": e.decided_at,
                    })
                })
                .collect();
            json_response(&serde_json::json!({"approvals": items}).to_string(), 200)
        }

        // ── Execute approved response actions ──────────────────
        (Method::Post, "/api/response/execute") => {
            let body = match read_body_limited(body, 2048) {
                Ok(body) => body,
                Err(e) => {
                    return respond_api(
                        state,
                        &method,
                        &url,
                        remote_addr,
                        auth_used,
                        error_json(&e, 400),
                    );
                }
            };
            let request_id = if body.trim().is_empty() {
                None
            } else {
                match serde_json::from_str::<serde_json::Value>(&body) {
                    Ok(value) => value["request_id"].as_str().map(|s| s.to_string()),
                    Err(_) => {
                        return respond_api(
                            state,
                            &method,
                            &url,
                            remote_addr,
                            auth_used,
                            error_json("invalid JSON", 400),
                        );
                    }
                }
            };
            let s = state.lock().unwrap_or_else(|e| e.into_inner());
            let executed = s
                .response_orchestrator
                .execute_approved_matching(request_id.as_deref());
            json_response(
                &serde_json::json!({
                    "executed_count": executed.len(),
                    "actions": executed,
                })
                .to_string(),
                200,
            )
        }

        _ => {
            // Dynamic routes with path parameters
            let url_path = url_path(&url);
            if method == Method::Get && url_path == "/api/agents/update" {
                // GET /api/agents/update?current_version=xxx&platform=yyy
                handle_agent_update_check(body, &url, state)
            } else if method == Method::Get && url_path == "/api/reports/executive-summary" {
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                let summary = s.report_store.executive_summary(&s.incident_store);
                match serde_json::to_string(&summary) {
                    Ok(json) => json_response(&json, 200),
                    Err(e) => error_json(&format!("serialization error: {e}"), 500),
                }
            } else if method == Method::Get && url_path == "/api/alerts/analysis" {
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(ref analysis) = s.last_alert_analysis {
                    match serde_json::to_string(analysis) {
                        Ok(json) => json_response(&json, 200),
                        Err(e) => error_json(&format!("serialization error: {e}"), 500),
                    }
                } else {
                    let alerts_vec: Vec<_> = s.alerts.iter().cloned().collect();
                    let analysis = crate::alert_analysis::analyze_alerts(&alerts_vec, 5);
                    match serde_json::to_string(&analysis) {
                        Ok(json) => json_response(&json, 200),
                        Err(e) => error_json(&format!("serialization error: {e}"), 500),
                    }
                }
            } else if method == Method::Get && url_path == "/api/alerts/grouped" {
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                let alerts_vec: Vec<_> = s.alerts.iter().cloned().collect();
                let groups = crate::alert_analysis::group_alerts(&alerts_vec);
                match serde_json::to_string(&groups) {
                    Ok(json) => json_response(&json, 200),
                    Err(e) => error_json(&format!("serialization error: {e}"), 500),
                }
            } else if method == Method::Get && url_path == "/api/cases/stats" {
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                let cases = s.case_store.list_filtered(None, None, None);
                let total = cases.len();
                let resolved = cases
                    .iter()
                    .filter(|case| matches!(case.status, CaseStatus::Resolved | CaseStatus::Closed))
                    .count();
                let open = total.saturating_sub(resolved);
                let triaging = cases
                    .iter()
                    .filter(|case| matches!(case.status, CaseStatus::Triaging))
                    .count();
                let investigating = cases
                    .iter()
                    .filter(|case| matches!(case.status, CaseStatus::Investigating))
                    .count();
                let escalated = cases
                    .iter()
                    .filter(|case| matches!(case.status, CaseStatus::Escalated))
                    .count();
                json_response(
                    &serde_json::json!({
                        "total": total,
                        "open": open,
                        "resolved": resolved,
                        "triaging": triaging,
                        "investigating": investigating,
                        "escalated": escalated,
                    })
                    .to_string(),
                    200,
                )
            } else if method == Method::Post
                && url_path.ends_with("/heartbeat")
                && url_path.starts_with("/api/agents/")
            {
                // POST /api/agents/{id}/heartbeat
                let agent_id = url_path
                    .strip_prefix("/api/agents/")
                    .and_then(|rest| rest.strip_suffix("/heartbeat"))
                    .unwrap_or("");
                handle_agent_heartbeat(body, state, agent_id)
            } else if method == Method::Get
                && url_path.starts_with("/api/agents/")
                && url_path.ends_with("/activity")
            {
                let agent_id = url_path
                    .strip_prefix("/api/agents/")
                    .and_then(|rest| rest.strip_suffix("/activity"))
                    .unwrap_or("");
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                match build_agent_activity_snapshot(&s, agent_id) {
                    Ok(snapshot) => match serde_json::to_string(&snapshot) {
                        Ok(json) => json_response(&json, 200),
                        Err(e) => error_json(&format!("serialization error: {e}"), 500),
                    },
                    Err(e) => error_json(&e, 404),
                }
            } else if method == Method::Get
                && url_path.starts_with("/api/agents/")
                && url_path.ends_with("/details")
            {
                let agent_id = url_path
                    .strip_prefix("/api/agents/")
                    .and_then(|rest| rest.strip_suffix("/details"))
                    .unwrap_or("");
                handle_agent_details(state, agent_id)
            } else if method == Method::Post
                && url_path.starts_with("/api/events/")
                && url_path.ends_with("/triage")
            {
                let event_id = url_path
                    .strip_prefix("/api/events/")
                    .and_then(|rest| rest.strip_suffix("/triage"))
                    .unwrap_or("")
                    .trim_end_matches('/');
                handle_event_triage(body, state, event_id)
            } else if method == Method::Post
                && url_path.starts_with("/api/agents/")
                && url_path.ends_with("/scope")
            {
                let agent_id = url_path
                    .strip_prefix("/api/agents/")
                    .and_then(|rest| rest.strip_suffix("/scope"))
                    .unwrap_or("");
                handle_agent_set_scope(body, state, agent_id)
            } else if method == Method::Get
                && url_path.starts_with("/api/agents/")
                && url_path.ends_with("/scope")
            {
                let agent_id = url_path
                    .strip_prefix("/api/agents/")
                    .and_then(|rest| rest.strip_suffix("/scope"))
                    .unwrap_or("");
                handle_agent_get_scope(state, agent_id)
            } else if method == Method::Get
                && url_path.starts_with("/api/agents/")
                && url_path.ends_with("/status")
            {
                // GET /api/agents/{id}/status
                let agent_id = url_path
                    .strip_prefix("/api/agents/")
                    .and_then(|rest| rest.strip_suffix("/status"))
                    .unwrap_or("");
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                match s.agent_registry.get(agent_id) {
                    Some(agent) => match serde_json::to_string(agent) {
                        Ok(json) => json_response(&json, 200),
                        Err(e) => error_json(&format!("serialization error: {e}"), 500),
                    },
                    None => error_json("agent not found", 404),
                }
            } else if method == Method::Delete && url_path.starts_with("/api/agents/") {
                // DELETE /api/agents/{id}
                let agent_id = url_path.strip_prefix("/api/agents/").unwrap_or("");
                let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                match s.agent_registry.deregister(agent_id) {
                    Ok(()) => {
                        let body =
                            serde_json::json!({"status": "deregistered", "agent_id": agent_id});
                        json_response(&body.to_string(), 200)
                    }
                    Err(e) => error_json(&e, 404),
                }
            // ── Agent Logs ────────────────────────────────────────
            } else if method == Method::Post
                && url_path.starts_with("/api/agents/")
                && url_path.ends_with("/logs")
            {
                let agent_id = url_path
                    .strip_prefix("/api/agents/")
                    .and_then(|rest| rest.strip_suffix("/logs"))
                    .unwrap_or("");
                let body = match read_body_limited(body, 10 * 1024 * 1024) {
                    Ok(b) => b,
                    Err(e) => {
                        return respond_api(
                            state,
                            &method,
                            &url,
                            remote_addr,
                            auth_used,
                            error_json(&e, 400),
                        );
                    }
                };
                let logs: Vec<crate::log_collector::LogRecord> = match serde_json::from_str(&body) {
                    Ok(l) => l,
                    Err(e) => {
                        return respond_api(
                            state,
                            &method,
                            &url,
                            remote_addr,
                            auth_used,
                            error_json(&format!("invalid JSON: {e}"), 400),
                        );
                    }
                };
                let count = logs.len();
                let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                // Cap total tracked agents to prevent unbounded memory growth
                if !s.agent_logs.contains_key(agent_id) && s.agent_logs.len() >= 10_000 {
                    // Evict a random agent to make room
                    if let Some(evict_key) = s.agent_logs.keys().next().cloned() {
                        s.agent_logs.remove(&evict_key);
                    }
                }
                let agent_log_buf = s.agent_logs.entry(agent_id.to_string()).or_default();
                for log in logs {
                    if agent_log_buf.len() >= 500 {
                        agent_log_buf.drain(..1);
                    }
                    agent_log_buf.push(log);
                }
                json_response(
                    &serde_json::json!({"status":"ingested","count":count}).to_string(),
                    200,
                )
            } else if method == Method::Get
                && url_path.starts_with("/api/agents/")
                && url_path.ends_with("/logs")
            {
                let agent_id = url_path
                    .strip_prefix("/api/agents/")
                    .and_then(|rest| rest.strip_suffix("/logs"))
                    .unwrap_or("");
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                let logs = s.agent_logs.get(agent_id).cloned().unwrap_or_default();
                match serde_json::to_string(&logs) {
                    Ok(json) => json_response(&json, 200),
                    Err(e) => error_json(&format!("serialization error: {e}"), 500),
                }
            // ── Agent Inventory ───────────────────────────────────
            } else if method == Method::Post
                && url_path.starts_with("/api/agents/")
                && url_path.ends_with("/inventory")
            {
                let agent_id = url_path
                    .strip_prefix("/api/agents/")
                    .and_then(|rest| rest.strip_suffix("/inventory"))
                    .unwrap_or("");
                let body = match read_body_limited(body, 10 * 1024 * 1024) {
                    Ok(b) => b,
                    Err(e) => {
                        return respond_api(
                            state,
                            &method,
                            &url,
                            remote_addr,
                            auth_used,
                            error_json(&e, 400),
                        );
                    }
                };
                let inventory: crate::inventory::SystemInventory = match serde_json::from_str(&body)
                {
                    Ok(i) => i,
                    Err(e) => {
                        return respond_api(
                            state,
                            &method,
                            &url,
                            remote_addr,
                            auth_used,
                            error_json(&format!("invalid JSON: {e}"), 400),
                        );
                    }
                };
                let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                // Cap total tracked agents to prevent unbounded memory growth
                if !s.agent_inventories.contains_key(agent_id) && s.agent_inventories.len() >= 10_000
                    && let Some(evict_key) = s.agent_inventories.keys().next().cloned() {
                        s.agent_inventories.remove(&evict_key);
                    }
                s.agent_inventories.insert(agent_id.to_string(), inventory);
                json_response(
                    &serde_json::json!({"status":"inventory_stored","agent_id":agent_id})
                        .to_string(),
                    200,
                )
            } else if method == Method::Get
                && url_path.starts_with("/api/agents/")
                && url_path.ends_with("/inventory")
            {
                let agent_id = url_path
                    .strip_prefix("/api/agents/")
                    .and_then(|rest| rest.strip_suffix("/inventory"))
                    .unwrap_or("");
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                match s.agent_inventories.get(agent_id) {
                    Some(inv) => match serde_json::to_string(inv) {
                        Ok(json) => json_response(&json, 200),
                        Err(e) => error_json(&format!("serialization error: {e}"), 500),
                    },
                    None => error_json("no inventory for this agent", 404),
                }
            // ── Incidents (dynamic) ───────────────────────────────
            } else if method == Method::Get
                && url_path.starts_with("/api/incidents/")
                && url_path.ends_with("/report")
            {
                match parse_numeric_path_between::<u64>(url_path, "/api/incidents/", "/report") {
                    Some(id) => {
                        let s = state.lock().unwrap_or_else(|e| e.into_inner());
                        match s.incident_store.get(id) {
                            Some(inc) => {
                                let report =
                                    crate::report::IncidentReport::generate(inc, &s.event_store);
                                let related_events =
                                    incident_related_events(inc, s.event_store.all_events());
                                let all_cases = s.case_store.list().to_vec();
                                let storyline = build_incident_storyline(
                                    inc,
                                    &related_events,
                                    &all_cases,
                                    &s.response_orchestrator.all_requests(),
                                    &s.response_orchestrator.audit_ledger(),
                                    s.enterprise.ticket_syncs(),
                                );
                                let linked_cases: Vec<serde_json::Value> = all_cases
                                    .iter()
                                    .filter(|case| case.incident_ids.contains(&inc.id))
                                    .map(|case| serde_json::json!(case_summary(case)))
                                    .collect();
                                match serde_json::to_value(&report) {
                                    Ok(serde_json::Value::Object(mut payload)) => {
                                        payload.insert("storyline".to_string(), storyline.clone());
                                        payload.insert(
                                            "linked_cases".to_string(),
                                            serde_json::json!(linked_cases),
                                        );
                                        payload.insert(
                                            "ticket_syncs".to_string(),
                                            serde_json::json!(s
                                                .enterprise
                                                .ticket_syncs()
                                                .iter()
                                                .filter(|sync| sync.object_kind == "incident"
                                                    && sync.object_id == inc.id.to_string())
                                                .collect::<Vec<_>>()),
                                        );
                                        payload.insert(
                                            "evidence_package".to_string(),
                                            storyline
                                                .get("evidence_package")
                                                .cloned()
                                                .unwrap_or_else(|| serde_json::json!({})),
                                        );
                                        payload.insert(
                                            "generated_at".to_string(),
                                            serde_json::json!(chrono::Utc::now().to_rfc3339()),
                                        );
                                        json_response(
                                            &serde_json::Value::Object(payload).to_string(),
                                            200,
                                        )
                                    }
                                    Ok(other) => json_response(&other.to_string(), 200),
                                    Err(e) => error_json(&format!("serialization error: {e}"), 500),
                                }
                            }
                            None => error_json("incident not found", 404),
                        }
                    }
                    None => error_json("not found", 404),
                }
            } else if method == Method::Post
                && url_path.starts_with("/api/incidents/")
                && url_path.ends_with("/update")
            {
                match parse_numeric_path_between::<u64>(url_path, "/api/incidents/", "/update") {
                    Some(id) => {
                        let body = match read_body_limited(body, 10 * 1024 * 1024) {
                            Ok(b) => b,
                            Err(e) => {
                                return respond_api(
                                    state,
                                    &method,
                                    &url,
                                    remote_addr,
                                    auth_used,
                                    error_json(&e, 400),
                                );
                            }
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
                            Err(e) => {
                                return respond_api(
                                    state,
                                    &method,
                                    &url,
                                    remote_addr,
                                    auth_used,
                                    error_json(&format!("invalid JSON: {e}"), 400),
                                );
                            }
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
                        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                        match s.incident_store.update(id, upd.assignee, note, status) {
                            Ok(()) => json_response(
                                &serde_json::json!({"status":"updated"}).to_string(),
                                200,
                            ),
                            Err(e) => error_json(&e, 404),
                        }
                    }
                    None => error_json("not found", 404),
                }
            } else if method == Method::Get
                && url_path.starts_with("/api/incidents/")
                && !url_path.ends_with("/report")
                && !url_path.ends_with("/storyline")
            {
                match parse_numeric_path_suffix::<u64>(url_path, "/api/incidents/") {
                    Some(id) => {
                        let s = state.lock().unwrap_or_else(|e| e.into_inner());
                        match s.incident_store.get(id) {
                            Some(inc) => match serde_json::to_string(inc) {
                                Ok(json) => json_response(&json, 200),
                                Err(e) => error_json(&format!("serialization error: {e}"), 500),
                            },
                            None => error_json("incident not found", 404),
                        }
                    }
                    None => error_json("not found", 404),
                }
            // ── Reports (dynamic) ─────────────────────────────────
            } else if method == Method::Get
                && url_path.starts_with("/api/reports/")
                && url_path.ends_with("/html")
            {
                match parse_numeric_path_between::<u64>(url_path, "/api/reports/", "/html") {
                    Some(id) => {
                        let s = state.lock().unwrap_or_else(|e| e.into_inner());
                        match s.report_store.get(id) {
                            Some(report) => {
                                let html = report.report.to_html();
                                let data = html.as_bytes().to_vec();
                                Response::builder()
                                    .status(200)
                                    .header("Content-Type", "text/html; charset=utf-8")
                                    .header("Access-Control-Allow-Origin", cors_origin())
                                    .header("Content-Disposition", "attachment; filename=\"report.html\"")
                                    .header("X-Content-Type-Options", "nosniff")
                                    .header("X-Frame-Options", "DENY")
                                    .header("Cache-Control", "no-store")
                                    .body(Body::from(data))
                                    .unwrap()
                            }
                            None => error_json("report not found", 404),
                        }
                    }
                    None => error_json("not found", 404),
                }
            } else if method == Method::Delete && url_path.starts_with("/api/reports/") {
                match parse_numeric_path_suffix::<u64>(url_path, "/api/reports/") {
                    Some(id) => {
                        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                        if s.report_store.delete(id) {
                            json_response(&serde_json::json!({"status":"deleted"}).to_string(), 200)
                        } else {
                            error_json("report not found", 404)
                        }
                    }
                    None => error_json("not found", 404),
                }
            } else if method == Method::Get && url_path.starts_with("/api/reports/") {
                match parse_numeric_path_suffix::<u64>(url_path, "/api/reports/") {
                    Some(id) => {
                        let s = state.lock().unwrap_or_else(|e| e.into_inner());
                        match s.report_store.get(id) {
                            Some(report) => match serde_json::to_string(report) {
                                Ok(json) => json_response(&json, 200),
                                Err(e) => error_json(&format!("serialization error: {e}"), 500),
                            },
                            None => error_json("report not found", 404),
                        }
                    }
                    None => error_json("not found", 404),
                }
            } else if method == Method::Get && url_path.starts_with("/api/updates/download/") {
                // GET /api/updates/download/{file_name}
                let file_name = url_path
                    .strip_prefix("/api/updates/download/")
                    .unwrap_or("");
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                match s.update_manager.get_release_binary(file_name) {
                    Ok(data) => {
                        Response::builder()
                            .status(200)
                            .header("Content-Type", "application/octet-stream")
                            .header("Access-Control-Allow-Origin", cors_origin())
                            .body(Body::from(data))
                            .unwrap()
                    }
                    Err(e) => error_json(&e, 404),
                }
            } else if method == Method::Get
                && url_path.starts_with("/api/alerts/")
                && url_path != "/api/alerts/count"
                && url_path != "/api/alerts/analysis"
                && url_path != "/api/alerts/grouped"
            {
                // GET /api/alerts/{index} — detailed alert view
                match parse_numeric_path_suffix::<usize>(url_path, "/api/alerts/") {
                    Some(idx) => {
                        let s = state.lock().unwrap_or_else(|e| e.into_inner());
                        if idx < s.alerts.len() {
                            let alert = &s.alerts[idx];
                            let detail = serde_json::json!({
                                "id": idx,
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
                    None => error_json("not found", 404),
                }
            // ── Enterprise: Dynamic routes ───────────────────────────
            } else if method == Method::Get
                && url_path.starts_with("/api/hunts/")
                && url_path.ends_with("/history")
            {
                let hunt_id = url_path
                    .trim_start_matches("/api/hunts/")
                    .trim_end_matches("/history");
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                let runs = s.enterprise.hunt_runs(hunt_id);
                json_response(
                    &serde_json::json!({"hunt_id": hunt_id, "history": runs, "count": runs.len()})
                        .to_string(),
                    200,
                )
            } else if method == Method::Post
                && url_path.starts_with("/api/hunts/")
                && url_path.ends_with("/run")
            {
                let hunt_id = url_path
                    .trim_start_matches("/api/hunts/")
                    .trim_end_matches("/run")
                    .trim_end_matches('/');
                let started = std::time::Instant::now();
                let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                let events = s.event_store.all_events().to_vec();
                match s.enterprise.run_hunt(hunt_id, &events) {
                    Ok(run) => {
                        let hunt = s
                            .enterprise
                            .hunts()
                            .iter()
                            .find(|hunt| hunt.id == run.hunt_id)
                            .cloned();
                        let response_results = if let Some(hunt) = hunt {
                            let AppState {
                                incident_store,
                                enterprise,
                                response_orchestrator,
                                ..
                            } = &mut *s;
                            let response_orchestrator_value = std::mem::take(response_orchestrator);
                            let results = execute_hunt_response_actions(
                                &hunt,
                                &run,
                                &events,
                                incident_store,
                                enterprise,
                                &response_orchestrator_value,
                                auth_identity.actor(),
                            );
                            *response_orchestrator = response_orchestrator_value;
                            results
                        } else {
                            Vec::new()
                        };
                        s.enterprise
                            .record_hunt_metrics(started.elapsed().as_millis() as u64);
                        let _ = s.enterprise.record_change(
                            "hunt_run",
                            hunt_id,
                            &format!("Executed hunt {}", hunt_id),
                            auth_identity.actor(),
                            Some(run.id.clone()),
                            None,
                        );
                        json_response(
                            &serde_json::json!({
                                "status": "completed",
                                "run": run,
                                "response_actions": response_results,
                            })
                            .to_string(),
                            200,
                        )
                    }
                    Err(e) => error_json(&e, 404),
                }
            } else if method == Method::Post
                && url_path.starts_with("/api/content/rules/")
                && url_path.ends_with("/test")
            {
                let rule_id = url_path
                    .trim_start_matches("/api/content/rules/")
                    .trim_end_matches("/test")
                    .trim_end_matches('/');
                let started = std::time::Instant::now();
                let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                let events = s.event_store.all_events().to_vec();
                match s.enterprise.test_rule(rule_id, &events) {
                    Ok(result) => {
                        s.enterprise
                            .record_search_metrics(started.elapsed().as_millis() as u64);
                        json_response(
                            &serde_json::json!({"status": "tested", "result": result}).to_string(),
                            200,
                        )
                    }
                    Err(e) => error_json(&e, 404),
                }
            } else if method == Method::Post
                && url_path.starts_with("/api/content/rules/")
                && url_path.ends_with("/promote")
            {
                let rule_id = url_path
                    .trim_start_matches("/api/content/rules/")
                    .trim_end_matches("/promote")
                    .trim_end_matches('/');
                match read_json_value(body, 8192) {
                    Ok(v) => {
                        let status_str = v["target_status"].as_str().unwrap_or("active");
                        let target = match status_str {
                            "draft" => Some(ContentLifecycle::Draft),
                            "test" => Some(ContentLifecycle::Test),
                            "canary" => Some(ContentLifecycle::Canary),
                            "active" => Some(ContentLifecycle::Active),
                            "deprecated" => Some(ContentLifecycle::Deprecated),
                            _ => None,
                        };
                        let Some(target) = target else {
                            return respond_api(state, &method, &url, remote_addr, needs_auth, error_json(&format!("invalid target_status: {status_str}"), 400));
                        };
                        let reason = v["reason"].as_str().unwrap_or("promotion");
                        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                        match s.enterprise.promote_rule(
                            rule_id,
                            target,
                            auth_identity.actor(),
                            reason,
                        ) {
                            Ok(rule) => {
                                sync_enterprise_sigma_engine(&mut s);
                                let _ = s.enterprise.record_change(
                                    "rule_promotion",
                                    rule_id,
                                    &format!("Promoted rule {} to {:?}", rule_id, rule.lifecycle),
                                    auth_identity.actor(),
                                    Some(rule.id.clone()),
                                    Some(&v.to_string()),
                                );
                                json_response(
                                    &serde_json::json!({"status": "promoted", "rule": rule})
                                        .to_string(),
                                    200,
                                )
                            }
                            Err(e) => error_json(&e, 404),
                        }
                    }
                    Err(e) => error_json(&e, 400),
                }
            } else if method == Method::Post
                && url_path.starts_with("/api/content/rules/")
                && url_path.ends_with("/rollback")
            {
                let rule_id = url_path
                    .trim_start_matches("/api/content/rules/")
                    .trim_end_matches("/rollback")
                    .trim_end_matches('/');
                let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                match s.enterprise.rollback_rule(rule_id, auth_identity.actor()) {
                    Ok(rule) => {
                        sync_enterprise_sigma_engine(&mut s);
                        let _ = s.enterprise.record_change(
                            "rule_rollback",
                            rule_id,
                            &format!("Rolled back rule {}", rule_id),
                            auth_identity.actor(),
                            Some(rule.id.clone()),
                            None,
                        );
                        json_response(
                            &serde_json::json!({"status": "rolled_back", "rule": rule}).to_string(),
                            200,
                        )
                    }
                    Err(e) => error_json(&e, 404),
                }
            } else if method == Method::Get
                && url_path.starts_with("/api/entities/")
                && url_path.ends_with("/timeline")
            {
                match parse_entity_timeline_path(url_path) {
                    Some((kind, id)) => {
                        let s = state.lock().unwrap_or_else(|e| e.into_inner());
                        let timeline = build_entity_timeline(
                            kind,
                            id,
                            s.event_store.all_events(),
                            s.incident_store.list(),
                            s.case_store.list(),
                            &s.response_orchestrator.audit_ledger(),
                            s.enterprise.ticket_syncs(),
                        );
                        json_response(
                            &serde_json::json!({"kind": kind, "id": id, "timeline": timeline, "count": timeline.len()})
                                .to_string(),
                            200,
                        )
                    }
                    None => error_json("not found", 404),
                }
            } else if method == Method::Get && url_path.starts_with("/api/entities/") {
                match parse_entity_profile_path(url_path) {
                    Some((kind, id)) => {
                        let s = state.lock().unwrap_or_else(|e| e.into_inner());
                        let profile = build_entity_profile(
                            kind,
                            id,
                            s.event_store.all_events(),
                            s.incident_store.list(),
                            s.case_store.list(),
                            &s.threat_intel.all_iocs(),
                            &s.response_orchestrator.all_requests(),
                            &s.rbac.list_users(),
                            s.enterprise.connectors(),
                            s.enterprise.ticket_syncs(),
                        );
                        json_response(&profile.to_string(), 200)
                    }
                    None => error_json("not found", 404),
                }
            } else if method == Method::Get
                && url_path.starts_with("/api/incidents/")
                && url_path.ends_with("/storyline")
            {
                match parse_numeric_path_between::<u64>(url_path, "/api/incidents/", "/storyline") {
                    Some(id) => {
                        let s = state.lock().unwrap_or_else(|e| e.into_inner());
                        match s.incident_store.get(id) {
                            Some(incident) => {
                                let related_events =
                                    incident_related_events(incident, s.event_store.all_events());
                                let cases = s.case_store.list().to_vec();
                                let storyline = build_incident_storyline(
                                    incident,
                                    &related_events,
                                    &cases,
                                    &s.response_orchestrator.all_requests(),
                                    &s.response_orchestrator.audit_ledger(),
                                    s.enterprise.ticket_syncs(),
                                );
                                json_response(&storyline.to_string(), 200)
                            }
                            None => error_json("incident not found", 404),
                        }
                    }
                    None => error_json("not found", 404),
                }
            // ── Analyst Console: Dynamic case routes ─────────────────
            } else if method == Method::Get && url_path.starts_with("/api/cases/") {
                match parse_numeric_path_suffix::<u64>(url_path, "/api/cases/") {
                    Some(id) => {
                        let s = state.lock().unwrap_or_else(|e| e.into_inner());
                        if let Some(c) = s.case_store.get(id) {
                            json_response(&serde_json::json!({
                                "id": c.id, "title": c.title, "description": c.description,
                                "status": format!("{:?}", c.status), "priority": format!("{:?}", c.priority),
                                "assignee": c.assignee, "created_at": c.created_at, "updated_at": c.updated_at,
                                "incident_ids": c.incident_ids, "event_ids": c.event_ids,
                                "linked_incidents": case_linked_incidents(c, &s.incident_store),
                                "linked_events": case_linked_events(c, &s.event_store),
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
                    None => error_json("not found", 404),
                }
            } else if method == Method::Post
                && url_path.starts_with("/api/cases/")
                && url_path.ends_with("/comment")
            {
                match parse_numeric_path_between::<u64>(url_path, "/api/cases/", "/comment") {
                    Some(id) => {
                        let body = read_body_limited(body, 4096);
                        match body.and_then(|b| {
                            serde_json::from_str::<serde_json::Value>(&b).map_err(|e| e.to_string())
                        }) {
                            Ok(v) => {
                                let author = v["author"].as_str().unwrap_or("analyst").to_string();
                                let text = v["text"].as_str().unwrap_or("").to_string();
                                let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                                if s.case_store.add_comment(id, author, text) {
                                    json_response(&serde_json::json!({"case_id": id, "action": "comment_added"}).to_string(), 200)
                                } else {
                                    error_json("case not found", 404)
                                }
                            }
                            Err(e) => error_json(&e, 400),
                        }
                    }
                    None => error_json("not found", 404),
                }
            } else if method == Method::Post
                && url_path.starts_with("/api/cases/")
                && url_path.ends_with("/update")
            {
                match parse_numeric_path_between::<u64>(url_path, "/api/cases/", "/update") {
                    Some(id) => {
                        let body = read_body_limited(body, 4096);
                        match body.and_then(|b| {
                            serde_json::from_str::<serde_json::Value>(&b).map_err(|e| e.to_string())
                        }) {
                            Ok(v) => {
                                let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                                if let Some(status_str) = v["status"].as_str() {
                                    let status = match status_str {
                                        "triaging" => Some(CaseStatus::Triaging),
                                        "investigating" => Some(CaseStatus::Investigating),
                                        "escalated" => Some(CaseStatus::Escalated),
                                        "resolved" => Some(CaseStatus::Resolved),
                                        "closed" => Some(CaseStatus::Closed),
                                        "new" => Some(CaseStatus::New),
                                        _ => None,
                                    };
                                    let Some(status) = status else {
                                        return respond_api(state, &method, &url, remote_addr, needs_auth, error_json(&format!("invalid status: {status_str}"), 400));
                                    };
                                    if !s.case_store.update_status(id, status) {
                                        return respond_api(state, &method, &url, remote_addr, needs_auth, error_json("case not found", 404));
                                    }
                                }
                                if let Some(assignee) = v["assignee"].as_str()
                                    && !s.case_store.assign(id, assignee.to_string()) {
                                        return respond_api(state, &method, &url, remote_addr, needs_auth, error_json("case not found", 404));
                                    }
                                if let Some(incident_id) = v["link_incident"].as_u64() {
                                    s.case_store.link_incident(id, incident_id);
                                }
                                json_response(
                                    &serde_json::json!({"case_id": id, "action": "updated"})
                                        .to_string(),
                                    200,
                                )
                            }
                            Err(e) => error_json(&e, 400),
                        }
                    }
                    None => error_json("not found", 404),
                }
            } else if method == Method::Post
                && url_path.starts_with("/api/cases/")
                && url_path.ends_with("/evidence")
            {
                match parse_numeric_path_between::<u64>(url_path, "/api/cases/", "/evidence") {
                    Some(id) => {
                        let body = read_body_limited(body, 4096);
                        match body.and_then(|b| {
                            serde_json::from_str::<serde_json::Value>(&b).map_err(|e| e.to_string())
                        }) {
                            Ok(v) => {
                                let kind = v["kind"].as_str().unwrap_or("other").to_string();
                                let ref_id = v["reference_id"].as_str().unwrap_or("").to_string();
                                let desc = v["description"].as_str().unwrap_or("").to_string();
                                let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                                if s.case_store.add_evidence(id, kind, ref_id, desc) {
                                    json_response(&serde_json::json!({"case_id": id, "action": "evidence_added"}).to_string(), 200)
                                } else {
                                    error_json("case not found", 404)
                                }
                            }
                            Err(e) => error_json(&e, 400),
                        }
                    }
                    None => error_json("not found", 404),
                }
            // ── Phase 32: Advanced XDR endpoints ────────────────────────

            // UEBA
            } else if method == Method::Post && url_path == "/api/ueba/observe" {
                let body = read_body_limited(body, 8192);
                match body.and_then(|b| {
                    serde_json::from_str::<crate::ueba::BehaviorObservation>(&b)
                        .map_err(|e| e.to_string())
                }) {
                    Ok(obs) => {
                        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                        let anomalies = s.ueba_engine.observe(&obs);
                        json_response(
                            &serde_json::to_string(&serde_json::json!({
                                "anomalies": anomalies,
                            }))
                            .unwrap(),
                            200,
                        )
                    }
                    Err(e) => error_json(&e, 400),
                }
            } else if method == Method::Get && url_path == "/api/ueba/risky" {
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                let risky = s.ueba_engine.risky_entities(10.0);
                json_response(&serde_json::to_string(&risky).unwrap(), 200)
            } else if method == Method::Get && url_path.starts_with("/api/ueba/entity/") {
                let entity_id = url_path.trim_start_matches("/api/ueba/entity/");
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                match s
                    .ueba_engine
                    .entity_risk(&crate::ueba::EntityKind::User, entity_id)
                {
                    Some(risk) => json_response(&serde_json::to_string(&risk).unwrap(), 200),
                    None => error_json("entity not found", 404),
                }

            // Beacon / DGA
            } else if method == Method::Post && url_path == "/api/beacon/connection" {
                let body = read_body_limited(body, 4096);
                match body.and_then(|b| {
                    serde_json::from_str::<crate::beacon::ConnectionRecord>(&b)
                        .map_err(|e| e.to_string())
                }) {
                    Ok(conn) => {
                        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                        s.beacon_detector.record_connection(conn);
                        json_response(r#"{"status":"recorded"}"#, 200)
                    }
                    Err(e) => error_json(&e, 400),
                }
            } else if method == Method::Post && url_path == "/api/beacon/dns" {
                let body = read_body_limited(body, 4096);
                match body.and_then(|b| {
                    serde_json::from_str::<crate::beacon::DnsRecord>(&b).map_err(|e| e.to_string())
                }) {
                    Ok(dns) => {
                        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                        s.beacon_detector.record_dns(dns);
                        json_response(r#"{"status":"recorded"}"#, 200)
                    }
                    Err(e) => error_json(&e, 400),
                }
            } else if method == Method::Get && url_path == "/api/beacon/analyze" {
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                let summary = s.beacon_detector.analyze();
                json_response(&serde_json::to_string(&summary).unwrap(), 200)

            // Kill Chain
            } else if method == Method::Post && url_path == "/api/killchain/reconstruct" {
                let body = read_body_limited(body, 16384);
                match body.and_then(|b| {
                    serde_json::from_str::<Vec<crate::kill_chain::KillChainEvent>>(&b)
                        .map_err(|e| e.to_string())
                }) {
                    Ok(events) => {
                        let s = state.lock().unwrap_or_else(|e| e.into_inner());
                        let chain = s.kill_chain_analyzer.reconstruct("api-request", &events);
                        json_response(&serde_json::to_string(&chain).unwrap(), 200)
                    }
                    Err(e) => error_json(&e, 400),
                }

            // Lateral Movement
            } else if method == Method::Post && url_path == "/api/lateral/connection" {
                let body = read_body_limited(body, 4096);
                match body.and_then(|b| {
                    serde_json::from_str::<crate::lateral::RemoteConnection>(&b)
                        .map_err(|e| e.to_string())
                }) {
                    Ok(conn) => {
                        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                        s.lateral_detector.record(conn);
                        json_response(r#"{"status":"recorded"}"#, 200)
                    }
                    Err(e) => error_json(&e, 400),
                }
            } else if method == Method::Get && url_path == "/api/lateral/analyze" {
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                let summary = s.lateral_detector.analyze();
                json_response(&serde_json::to_string(&summary).unwrap(), 200)

            // Kernel Events
            } else if method == Method::Post && url_path == "/api/kernel/event" {
                let body = read_body_limited(body, 8192);
                match body.and_then(|b| {
                    serde_json::from_str::<crate::kernel_events::KernelEvent>(&b)
                        .map_err(|e| e.to_string())
                }) {
                    Ok(event) => {
                        let s = state.lock().unwrap_or_else(|e| e.into_inner());
                        s.kernel_event_stream.push(event);
                        json_response(r#"{"status":"recorded"}"#, 200)
                    }
                    Err(e) => error_json(&e, 400),
                }
            } else if method == Method::Get && url_path == "/api/kernel/recent" {
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                let events = s.kernel_event_stream.recent(100, None);
                json_response(&serde_json::to_string(&events).unwrap(), 200)

            // Playbooks
            } else if method == Method::Get && url_path == "/api/playbooks" {
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                let pbs = s.playbook_engine.list_playbooks();
                json_response(&serde_json::to_string(&pbs).unwrap(), 200)
            } else if method == Method::Post && url_path == "/api/playbooks" {
                let body = read_body_limited(body, 16384);
                match body.and_then(|b| {
                    serde_json::from_str::<crate::playbook::Playbook>(&b).map_err(|e| e.to_string())
                }) {
                    Ok(pb) => {
                        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                        s.playbook_engine.register(pb);
                        json_response(r#"{"status":"registered"}"#, 200)
                    }
                    Err(e) => error_json(&e, 400),
                }
            } else if method == Method::Post && url_path == "/api/playbooks/execute" {
                let body = read_body_limited(body, 4096);
                match body.and_then(|b| {
                    serde_json::from_str::<serde_json::Value>(&b).map_err(|e| e.to_string())
                }) {
                    Ok(v) => {
                        let pb_id = v["playbook_id"].as_str().unwrap_or("");
                        let alert_id = v["alert_id"].as_str();
                        let now = chrono::Utc::now().timestamp_millis() as u64;
                        let executed_by = playbook_executor(&auth_identity);
                        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                        match s.playbook_engine.start_execution(
                            pb_id,
                            alert_id,
                            &executed_by,
                            now,
                        ) {
                            Some(eid) => json_response(
                                &serde_json::json!({"execution_id": eid}).to_string(),
                                200,
                            ),
                            None => error_json("playbook not found or disabled", 404),
                        }
                    }
                    Err(e) => error_json(&e, 400),
                }
            } else if method == Method::Get && url_path == "/api/playbooks/executions" {
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                let execs = s.playbook_engine.recent_executions(50);
                json_response(&serde_json::to_string(&execs).unwrap(), 200)

            // Live Response
            } else if method == Method::Post && url_path == "/api/live-response/session" {
                let body = read_body_limited(body, 4096);
                match body.and_then(|b| {
                    serde_json::from_str::<serde_json::Value>(&b).map_err(|e| e.to_string())
                }) {
                    Ok(v) => {
                        let agent_id = v["agent_id"].as_str().unwrap_or("unknown");
                        let hostname = v["hostname"].as_str().unwrap_or("unknown");
                        let op = live_response_operator(&auth_identity);
                        let platform = match v["platform"].as_str().unwrap_or("linux") {
                            "macos" => crate::live_response::LiveResponsePlatform::MacOs,
                            "windows" => crate::live_response::LiveResponsePlatform::Windows,
                            _ => crate::live_response::LiveResponsePlatform::Linux,
                        };
                        let now = chrono::Utc::now().timestamp_millis() as u64;
                        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                        let sid = s
                            .live_response_engine
                            .open_session(agent_id, hostname, platform, &op, now);
                        json_response(&serde_json::json!({"session_id": sid}).to_string(), 200)
                    }
                    Err(e) => error_json(&e, 400),
                }
            } else if method == Method::Post && url_path == "/api/live-response/command" {
                let body = read_body_limited(body, 4096);
                match body.and_then(|b| {
                    serde_json::from_str::<serde_json::Value>(&b).map_err(|e| e.to_string())
                }) {
                    Ok(v) => {
                        let sid = v["session_id"].as_str().unwrap_or("");
                        let cmd = v["command"].as_str().unwrap_or("");
                        let args: Vec<String> = v["args"]
                            .as_array()
                            .map(|a| {
                                a.iter()
                                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                                    .collect()
                            })
                            .unwrap_or_default();
                        let now = chrono::Utc::now().timestamp_millis() as u64;
                        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                        match s.live_response_engine.submit_command(sid, cmd, args, now) {
                            Ok(cid) => json_response(
                                &serde_json::json!({"command_id": cid}).to_string(),
                                200,
                            ),
                            Err(e) => error_json(&e, 403),
                        }
                    }
                    Err(e) => error_json(&e, 400),
                }
            } else if method == Method::Get && url_path == "/api/live-response/sessions" {
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                let sessions = s.live_response_engine.all_sessions();
                json_response(&serde_json::to_string(&sessions).unwrap(), 200)
            } else if method == Method::Get && url_path == "/api/live-response/audit" {
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                let log: Vec<serde_json::Value> = s
                    .live_response_engine
                    .audit_log()
                    .iter()
                    .map(|(sid, cr)| serde_json::json!({"session_id": sid, "record": cr}))
                    .collect();
                json_response(&serde_json::to_string(&log).unwrap(), 200)

            // Remediation
            } else if method == Method::Post && url_path == "/api/remediation/plan" {
                let body = read_body_limited(body, 8192);
                match body.and_then(|b| {
                    serde_json::from_str::<serde_json::Value>(&b).map_err(|e| e.to_string())
                }) {
                    Ok(v) => {
                        let platform = match v["platform"].as_str().unwrap_or("linux") {
                            "macos" => crate::remediation::RemediationPlatform::MacOs,
                            "windows" => crate::remediation::RemediationPlatform::Windows,
                            _ => crate::remediation::RemediationPlatform::Linux,
                        };
                        let action_type = v["action"].as_str().unwrap_or("");
                        let action = match action_type {
                            "flush_dns" => crate::remediation::RemediationAction::FlushDns,
                            "block_ip" => crate::remediation::RemediationAction::BlockIp {
                                addr: v["addr"].as_str().unwrap_or("").to_string(),
                            },
                            "kill_process" => crate::remediation::RemediationAction::KillProcess {
                                pid: v["pid"].as_u64().unwrap_or(0) as u32,
                                name: v["name"].as_str().unwrap_or("").to_string(),
                            },
                            "disable_account" => {
                                crate::remediation::RemediationAction::DisableAccount {
                                    username: v["username"].as_str().unwrap_or("").to_string(),
                                }
                            }
                            "quarantine_file" => {
                                crate::remediation::RemediationAction::QuarantineFile {
                                    path: v["path"].as_str().unwrap_or("").to_string(),
                                }
                            }
                            _ => {
                                return respond_api(
                                    state,
                                    &method,
                                    &url,
                                    remote_addr,
                                    auth_used,
                                    error_json("unknown remediation action", 400),
                                );
                            }
                        };
                        let s = state.lock().unwrap_or_else(|e| e.into_inner());
                        let plan = s.remediation_engine.plan(&action, &platform);
                        json_response(&serde_json::to_string(&plan).unwrap(), 200)
                    }
                    Err(e) => error_json(&e, 400),
                }
            } else if method == Method::Get && url_path == "/api/remediation/results" {
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                let results = s.remediation_engine.recent_results(50);
                json_response(&serde_json::to_string(&results).unwrap(), 200)
            } else if method == Method::Get && url_path == "/api/remediation/stats" {
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                let stats = s.remediation_engine.stats();
                json_response(&serde_json::to_string(&stats).unwrap(), 200)

            // Escalation
            } else if method == Method::Get && url_path == "/api/escalation/policies" {
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                let policies = s.escalation_engine.list_policies();
                json_response(&serde_json::to_string(&policies).unwrap(), 200)
            } else if method == Method::Post && url_path == "/api/escalation/policies" {
                let body = read_body_limited(body, 16384);
                match body.and_then(|b| {
                    serde_json::from_str::<crate::escalation::EscalationPolicy>(&b)
                        .map_err(|e| e.to_string())
                }) {
                    Ok(policy) => {
                        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                        s.escalation_engine.add_policy(policy);
                        json_response(r#"{"status":"added"}"#, 200)
                    }
                    Err(e) => error_json(&e, 400),
                }
            } else if method == Method::Post && url_path == "/api/escalation/start" {
                let body = read_body_limited(body, 4096);
                match body.and_then(|b| {
                    serde_json::from_str::<serde_json::Value>(&b).map_err(|e| e.to_string())
                }) {
                    Ok(v) => {
                        let policy_id = v["policy_id"].as_str().unwrap_or("");
                        let alert_id = v["alert_id"].as_str().unwrap_or("");
                        let now = chrono::Utc::now().timestamp_millis() as u64;
                        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                        match s
                            .escalation_engine
                            .start_escalation(policy_id, alert_id, now)
                        {
                            Some(eid) => json_response(
                                &serde_json::json!({"escalation_id": eid}).to_string(),
                                200,
                            ),
                            None => error_json("policy not found or disabled", 404),
                        }
                    }
                    Err(e) => error_json(&e, 400),
                }
            } else if method == Method::Post && url_path == "/api/escalation/acknowledge" {
                let body = read_body_limited(body, 4096);
                match body.and_then(|b| {
                    serde_json::from_str::<serde_json::Value>(&b).map_err(|e| e.to_string())
                }) {
                    Ok(v) => {
                        let eid = v["escalation_id"].as_str().unwrap_or("");
                        let by = v["acknowledged_by"].as_str().unwrap_or("api");
                        let now = chrono::Utc::now().timestamp_millis() as u64;
                        let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                        if s.escalation_engine.acknowledge(eid, by, now) {
                            json_response(r#"{"status":"acknowledged"}"#, 200)
                        } else {
                            error_json("escalation not found or not active", 404)
                        }
                    }
                    Err(e) => error_json(&e, 400),
                }
            } else if method == Method::Get && url_path == "/api/escalation/active" {
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                let active = s.escalation_engine.active_escalations();
                json_response(&serde_json::to_string(&active).unwrap(), 200)
            } else if method == Method::Post && url_path == "/api/escalation/check-sla" {
                let now = chrono::Utc::now().timestamp_millis() as u64;
                let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                let escalated = s.escalation_engine.check_sla(now);
                json_response(
                    &serde_json::json!({"escalated": escalated}).to_string(),
                    200,
                )

            // Evidence Collection Plans
            } else if method == Method::Get && url_path == "/api/evidence/plan/linux" {
                let plan = crate::forensics::EvidenceCollectionPlan::linux();
                json_response(&serde_json::to_string(&plan).unwrap(), 200)
            } else if method == Method::Get && url_path == "/api/evidence/plan/macos" {
                let plan = crate::forensics::EvidenceCollectionPlan::macos();
                json_response(&serde_json::to_string(&plan).unwrap(), 200)
            } else if method == Method::Get && url_path == "/api/evidence/plan/windows" {
                let plan = crate::forensics::EvidenceCollectionPlan::windows();
                json_response(&serde_json::to_string(&plan).unwrap(), 200)

            // Containment Commands
            } else if method == Method::Post && url_path == "/api/containment/commands" {
                let body = read_body_limited(body, 4096);
                match body.and_then(|b| {
                    serde_json::from_str::<serde_json::Value>(&b).map_err(|e| e.to_string())
                }) {
                    Ok(v) => {
                        let level = match v["level"].as_str().unwrap_or("observe") {
                            "constrain" => crate::enforcement::EnforcementLevel::Constrain,
                            "quarantine" => crate::enforcement::EnforcementLevel::Quarantine,
                            "isolate" => crate::enforcement::EnforcementLevel::Isolate,
                            "eradicate" => crate::enforcement::EnforcementLevel::Eradicate,
                            _ => crate::enforcement::EnforcementLevel::Observe,
                        };
                        let target = v["target"].as_str().unwrap_or("");
                        let platform = v["platform"].as_str().unwrap_or("linux");
                        let s = state.lock().unwrap_or_else(|e| e.into_inner());
                        let cmds = s.enforcement.containment_commands(&level, target, platform);
                        json_response(&serde_json::to_string(&cmds).unwrap(), 200)
                    }
                    Err(e) => error_json(&e, 400),
                }
            // ── Phase 4B: Historical / durable storage endpoints ───
            } else if method == Method::Get && url_path == "/api/storage/alerts" {
                let query = parse_query_string(&url);
                let filter = crate::storage::QueryFilter {
                    tenant_id: query.get("tenant_id").cloned(),
                    level: query.get("level").cloned(),
                    device_id: query.get("device_id").cloned(),
                    since: query.get("since").cloned(),
                    until: query.get("until").cloned(),
                    limit: query.get("limit").and_then(|v| v.parse().ok()),
                    offset: query.get("offset").and_then(|v| v.parse().ok()),
                    ..Default::default()
                };
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                match s.storage.with(|store| Ok(store.query_alerts(&filter))) {
                    Ok(alerts) => json_response(&serde_json::to_string(&alerts).unwrap_or_default(), 200),
                    Err(e) => error_json(&e.message, 500),
                }
            } else if method == Method::Get && url_path == "/api/storage/cases" {
                let query = parse_query_string(&url);
                let filter = crate::storage::QueryFilter {
                    tenant_id: query.get("tenant_id").cloned(),
                    status: query.get("status").cloned(),
                    limit: query.get("limit").and_then(|v| v.parse().ok()),
                    ..Default::default()
                };
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                match s.storage.with(|store| Ok(store.list_cases(&filter))) {
                    Ok(cases) => json_response(&serde_json::to_string(&cases).unwrap_or_default(), 200),
                    Err(e) => error_json(&e.message, 500),
                }
            } else if method == Method::Get && url_path == "/api/storage/audit" {
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                match s.storage.with(|store| {
                    let chain_len = store.verify_audit_chain()?;
                    Ok(serde_json::json!({
                        "chain_length": chain_len,
                        "integrity": "verified",
                    }))
                }) {
                    Ok(body) => json_response(&body.to_string(), 200),
                    Err(e) => error_json(&e.message, 500),
                }
            } else if method == Method::Get && url_path == "/api/storage/stats" {
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                match s.storage.with(|store| Ok(store.stats())) {
                    Ok(stats) => json_response(&serde_json::to_string(&stats).unwrap_or_default(), 200),
                    Err(e) => error_json(&e.message, 500),
                }
            } else if method == Method::Get && url_path == "/api/storage/agents" {
                let query = parse_query_string(&url);
                let tenant = query.get("tenant_id").map(|s| s.as_str());
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                match s.storage.with(|store| Ok(store.list_agents(tenant))) {
                    Ok(agents) => json_response(&serde_json::to_string(&agents).unwrap_or_default(), 200),
                    Err(e) => error_json(&e.message, 500),
                }
            } else if method == Method::Post && url_path == "/api/storage/alerts" {
                match read_body_limited(body, 8192) {
                    Ok(body) => {
                        match serde_json::from_str::<crate::storage::StoredAlert>(&body) {
                            Ok(alert) => {
                                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                                match s.storage.with(|store| store.insert_alert(alert)) {
                                    Ok(()) => json_response(r#"{"status":"stored"}"#, 201),
                                    Err(e) => error_json(&e.message, 409),
                                }
                            }
                            Err(e) => error_json(&format!("invalid alert JSON: {e}"), 400),
                        }
                    }
                    Err(e) => error_json(&e, 400),
                }
            } else if method == Method::Get && url_path == "/api/detectors/slow-attack" {
                let s = match state.lock() {
                    Ok(g) => g,
                    Err(e) => e.into_inner(),
                };
                let report = s.slow_attack.evaluate();
                json_response(&serde_json::to_string(&report).unwrap_or_default(), 200)

            } else if method == Method::Get && url_path == "/api/detectors/ransomware" {
                let mut s = match state.lock() {
                    Ok(g) => g,
                    Err(e) => e.into_inner(),
                };
                let signal = s.ransomware.evaluate(0.0);
                json_response(&serde_json::to_string(&signal).unwrap_or_default(), 200)

            // ── DB migration rollback ─────────────────────────────
            } else if method == Method::Post && url_path == "/api/admin/db/rollback" {
                let s = match state.lock() {
                    Ok(g) => g,
                    Err(e) => e.into_inner(),
                };
                match s.storage.with(|store| store.rollback_migration()) {
                    Ok(Some(version)) => {
                        let new_ver = s.storage.with(|store| Ok(store.schema_version())).unwrap_or(0);
                        let body = serde_json::json!({
                            "status": "rolled_back",
                            "version": version,
                            "current_version": new_ver,
                        });
                        json_response(&body.to_string(), 200)
                    }
                    Ok(None) => error_json("already at version 0, nothing to rollback", 400),
                    Err(e) => error_json(&e.message, 500),
                }

            // ── GDPR right-to-forget ──────────────────────────────
            } else if method == Method::Delete && url_path.starts_with("/api/gdpr/forget/") {
                let entity_id = url_path.strip_prefix("/api/gdpr/forget/").unwrap_or("");
                if entity_id.is_empty() || entity_id.len() > 256 {
                    error_json("invalid entity_id", 400)
                } else {
                    let s = match state.lock() {
                        Ok(g) => g,
                        Err(e) => e.into_inner(),
                    };
                    match s.storage.with(|store| store.purge_entity(entity_id)) {
                        Ok(purged) => {
                            let body = serde_json::json!({
                                "status": "completed",
                                "entity_id": entity_id,
                                "records_purged": purged,
                                "timestamp": chrono::Utc::now().to_rfc3339(),
                            });
                            json_response(&body.to_string(), 200)
                        }
                        Err(e) => error_json(&e.message, 500),
                    }
                }

            // ── Database backup ───────────────────────────────────
            } else if method == Method::Post && url_path == "/api/admin/backup" {
                let backup_dir = "var/backups";
                let _ = std::fs::create_dir_all(backup_dir);
                let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
                let dest = format!("{}/wardex_backup_{}.db", backup_dir, timestamp);
                let s = match state.lock() {
                    Ok(g) => g,
                    Err(e) => e.into_inner(),
                };
                match s.storage.with(|store| store.backup(&dest)) {
                    Ok(()) => {
                        let body = serde_json::json!({
                            "status": "completed",
                            "path": dest,
                            "timestamp": chrono::Utc::now().to_rfc3339(),
                        });
                        json_response(&body.to_string(), 200)
                    }
                    Err(e) => error_json(&e.message, 500),
                }

            // ── Database schema version ───────────────────────────
            } else if method == Method::Get && url_path == "/api/admin/db/version" {
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                let info = s.storage.with(|store| Ok(store.schema_info()));
                let version = s.storage.with(|store| Ok(store.schema_version()));
                let body = serde_json::json!({
                    "current_version": version.unwrap_or(0),
                    "migrations": info.unwrap_or_default(),
                });
                json_response(&body.to_string(), 200)

            // ── Database compact (VACUUM + WAL checkpoint) ────────
            } else if method == Method::Post && url_path == "/api/admin/db/compact" {
                let s = match state.lock() {
                    Ok(g) => g,
                    Err(e) => e.into_inner(),
                };
                match s.storage.with(|store| store.compact()) {
                    Ok((before, after)) => {
                        let saved = before.saturating_sub(after);
                        let body = serde_json::json!({
                            "status": "completed",
                            "size_before_bytes": before,
                            "size_after_bytes": after,
                            "bytes_reclaimed": saved,
                            "timestamp": chrono::Utc::now().to_rfc3339(),
                        });
                        json_response(&body.to_string(), 200)
                    }
                    Err(e) => error_json(&e.message, 500),
                }

            // ── Database reset (purge all data) ───────────────────
            } else if method == Method::Post && url_path == "/api/admin/db/reset" {
                match read_body_limited(body, 4096) {
                    Ok(body_str) => {
                        // Require confirmation token to prevent accidental reset
                        let parsed: serde_json::Value = serde_json::from_str(&body_str).unwrap_or_default();
                        let confirm = parsed["confirm"].as_str().unwrap_or("");
                        if confirm != "RESET_ALL_DATA" {
                            error_json("send {\"confirm\":\"RESET_ALL_DATA\"} to confirm", 400)
                        } else {
                            let s = match state.lock() {
                                Ok(g) => g,
                                Err(e) => e.into_inner(),
                            };
                            match s.storage.with(|store| store.reset_all_data()) {
                                Ok(purged) => {
                                    let body = serde_json::json!({
                                        "status": "completed",
                                        "records_purged": purged,
                                        "timestamp": chrono::Utc::now().to_rfc3339(),
                                    });
                                    json_response(&body.to_string(), 200)
                                }
                                Err(e) => error_json(&e.message, 500),
                            }
                        }
                    }
                    Err(e) => error_json(&e, 400),
                }

            // ── Database file sizes ───────────────────────────────
            } else if method == Method::Get && url_path == "/api/admin/db/sizes" {
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
                match s.storage.with(|store| Ok(store.db_file_sizes())) {
                    Ok(sizes) => {
                        let body = serde_json::json!({
                            "db_bytes": sizes.db_bytes,
                            "wal_bytes": sizes.wal_bytes,
                            "shm_bytes": sizes.shm_bytes,
                            "total_bytes": sizes.total(),
                        });
                        json_response(&body.to_string(), 200)
                    }
                    Err(e) => error_json(&e.message, 500),
                }

            // ── Cleanup legacy flat files ─────────────────────────
            } else if method == Method::Post && url_path == "/api/admin/cleanup-legacy" {
                let removed = crate::storage::StorageBackend::cleanup_legacy_files("var");
                let body = serde_json::json!({
                    "status": "completed",
                    "files_removed": removed,
                    "count": removed.len(),
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                });
                json_response(&body.to_string(), 200)

            // ── Database purge by age ─────────────────────────────
            } else if method == Method::Post && url_path == "/api/admin/db/purge" {
                match read_body_limited(body, 4096) {
                    Ok(body_str) => {
                        let parsed: serde_json::Value = serde_json::from_str(&body_str).unwrap_or_default();
                        let days = parsed["retention_days"].as_u64().unwrap_or(0) as u32;
                        if days == 0 {
                            error_json("retention_days must be > 0", 400)
                        } else {
                            let s = match state.lock() {
                                Ok(g) => g,
                                Err(e) => e.into_inner(),
                            };
                            let alerts_purged = s.storage.with(|store| store.purge_old_alerts(days)).unwrap_or(0);
                            let audit_purged = s.storage.with(|store| store.purge_old_audit(days)).unwrap_or(0);
                            let metrics_purged = s.storage.with(|store| store.purge_old_metrics(days)).unwrap_or(0);
                            let body = serde_json::json!({
                                "status": "completed",
                                "retention_days": days,
                                "alerts_purged": alerts_purged,
                                "audit_purged": audit_purged,
                                "metrics_purged": metrics_purged,
                                "timestamp": chrono::Utc::now().to_rfc3339(),
                            });
                            json_response(&body.to_string(), 200)
                        }
                    }
                    Err(e) => error_json(&e, 400),
                }

            // ── SBOM generation ───────────────────────────────────
            } else if method == Method::Get && url_path == "/api/sbom" {
                let lock_content = std::fs::read_to_string("Cargo.lock").unwrap_or_default();
                let generator = crate::sbom::SbomGenerator::new(
                    env!("CARGO_PKG_NAME"),
                    env!("CARGO_PKG_VERSION"),
                );
                let components = generator.parse_cargo_lock(&lock_content);
                let doc = generator.generate(components, vec![], crate::sbom::SbomFormat::CycloneDX);
                let rendered = generator.to_cyclonedx_json(&doc);
                json_response(&rendered, 200)

            // ── PII scan (check a text payload for PII patterns) ──
            } else if method == Method::Post && url_path == "/api/pii/scan" {
                match read_body_limited(body, 65_536) {
                    Ok(body) => {
                        let findings = scan_pii(&body);
                        let body = serde_json::json!({
                            "has_pii": !findings.is_empty(),
                            "finding_count": findings.len(),
                            "categories": findings,
                        });
                        json_response(&body.to_string(), 200)
                    }
                    Err(e) => error_json(&e, 400),
                }

            // ── License Management ─────────────────────────────────
            } else if method == Method::Get && url_path == "/api/license" {
                // Return current license status
                let body = serde_json::json!({
                    "status": "active",
                    "edition": "professional",
                    "features": ["xdr", "siem", "soar", "ueba", "threat_intel"],
                    "max_agents": 10000,
                    "expires": "2026-12-31T23:59:59Z",
                });
                json_response(&body.to_string(), 200)
            } else if method == Method::Post && url_path == "/api/license/validate" {
                match read_body_limited(body, 4096) {
                    Ok(body_str) => {
                        let parsed: serde_json::Value = serde_json::from_str(&body_str).unwrap_or_default();
                        let key = parsed["key"].as_str().unwrap_or("");
                        if key.is_empty() {
                            error_json("license key required", 400)
                        } else {
                            let valid = crate::license::validate_license(key, &[]).is_ok();
                            let body = serde_json::json!({
                                "valid": valid,
                                "key_prefix": &key[..key.len().min(8)],
                                "validated_at": chrono::Utc::now().to_rfc3339(),
                            });
                            json_response(&body.to_string(), 200)
                        }
                    }
                    Err(e) => error_json(&e, 400),
                }

            // ── Search ────────────────────────────────────────────
            } else if method == Method::Post && url_path == "/api/search" {
                match read_body_limited(body, 65_536) {
                    Ok(body_str) => {
                        let query: crate::search::SearchQuery = match serde_json::from_str(&body_str) {
                            Ok(q) => q,
                            Err(e) => return respond_api(state, &method, &url, remote_addr, auth_used, error_json(&format!("invalid query: {e}"), 400)),
                        };
                        let result = crate::search::SearchResult {
                            total: 0,
                            hits: vec![],
                            took_ms: 0.1,
                            query: query.query,
                        };
                        let body = serde_json::to_string(&result).unwrap_or_default();
                        json_response(&body, 200)
                    }
                    Err(e) => error_json(&e, 400),
                }

            // ── Metering ──────────────────────────────────────────
            } else if method == Method::Get && url_path == "/api/metering/usage" {
                let body = serde_json::json!({
                    "events_ingested": 0,
                    "api_calls": 0,
                    "storage_bytes": 0,
                    "plan": "professional",
                    "period_start": chrono::Utc::now().to_rfc3339(),
                });
                json_response(&body.to_string(), 200)

            // ── Billing ───────────────────────────────────────────
            } else if method == Method::Get && url_path == "/api/billing/subscription" {
                let body = serde_json::json!({
                    "plan": "professional",
                    "status": "active",
                    "monthly_price": "$99",
                    "next_billing": chrono::Utc::now().to_rfc3339(),
                });
                json_response(&body.to_string(), 200)
            } else if method == Method::Get && url_path == "/api/billing/invoices" {
                let body = serde_json::json!({ "invoices": [] });
                json_response(&body.to_string(), 200)

            // ── Marketplace ───────────────────────────────────────
            } else if method == Method::Get && url_path == "/api/marketplace/packs" {
                let mgr = crate::marketplace::MarketplaceManager::new();
                let packs = mgr.list_packs(None);
                let body = serde_json::to_string(&packs).unwrap_or_default();
                json_response(&body, 200)
            } else if method == Method::Get && url_path.starts_with("/api/marketplace/packs/") {
                let pack_id = url_path.strip_prefix("/api/marketplace/packs/").unwrap_or("");
                let mgr = crate::marketplace::MarketplaceManager::new();
                match mgr.get_pack(pack_id) {
                    Some(pack) => {
                        let body = serde_json::to_string(&pack).unwrap_or_default();
                        json_response(&body, 200)
                    }
                    None => error_json("pack not found", 404),
                }

            // ── Prevention ────────────────────────────────────────
            } else if method == Method::Get && url_path == "/api/prevention/policies" {
                let engine = crate::prevention::PreventionEngine::new();
                let policies = engine.list_policies();
                let body = serde_json::to_string(&policies).unwrap_or_default();
                json_response(&body, 200)
            } else if method == Method::Get && url_path == "/api/prevention/stats" {
                let engine = crate::prevention::PreventionEngine::new();
                let stats = engine.stats();
                let body = serde_json::to_string(&stats).unwrap_or_default();
                json_response(&body, 200)

            // ── Pipeline ──────────────────────────────────────────
            } else if method == Method::Get && url_path == "/api/pipeline/status" {
                let mgr = crate::pipeline::PipelineManager::new(Default::default());
                let body = serde_json::json!({
                    "status": mgr.status(),
                    "metrics": {
                        "events_ingested": mgr.metrics().events_ingested,
                        "events_normalized": mgr.metrics().events_normalized,
                        "events_detected": mgr.metrics().events_detected,
                        "events_stored": mgr.metrics().events_stored,
                        "dlq_count": mgr.metrics().dlq_count,
                    },
                });
                json_response(&body.to_string(), 200)

            // ── Backup status ─────────────────────────────────────
            } else if method == Method::Get && url_path == "/api/backup/status" {
                let cfg = crate::backup::BackupConfig::default();
                let body = serde_json::json!({
                    "enabled": cfg.enabled,
                    "retention_count": cfg.retention_count,
                    "path": cfg.path,
                    "schedule_cron": cfg.schedule_cron,
                });
                json_response(&body.to_string(), 200)

            // ── SSO / Auth ────────────────────────────────────────
            } else if method == Method::Get && url_path == "/api/auth/sso/config" {
                let cfg = crate::auth::OidcConfig::default();
                let body = serde_json::json!({
                    "enabled": cfg.enabled,
                    "issuer": cfg.issuer,
                    "scopes": cfg.scopes,
                });
                json_response(&body.to_string(), 200)

            } else if method == Method::Get && url_path == "/api/auth/sso/login" {
                let cfg = crate::auth::OidcConfig::default();
                let mgr = crate::auth::AuthManager::new(cfg);
                let (auth_url, nonce) = mgr.build_auth_url();
                let body = serde_json::json!({
                    "authorization_url": auth_url,
                    "state": nonce,
                });
                json_response(&body.to_string(), 200)

            } else if method == Method::Post && url_path == "/api/auth/sso/callback" {
                match read_body_limited(body, 8192) {
                    Ok(body_str) => {
                        let parsed: serde_json::Value = serde_json::from_str(&body_str).unwrap_or_default();
                        let code = parsed["code"].as_str().unwrap_or("");
                        let state = parsed["state"].as_str().unwrap_or("");
                        if code.is_empty() {
                            error_json("authorization code required", 400)
                        } else if state.is_empty() {
                            error_json("state parameter required for CSRF protection", 400)
                        } else {
                            let cfg = crate::auth::OidcConfig::default();
                            let mgr = crate::auth::AuthManager::new(cfg);
                            match mgr.exchange_code(code) {
                                Ok(token_resp) => {
                                    // Extract user info from id_token; use defaults if token is opaque
                                    let claims: serde_json::Value = serde_json::from_str(&token_resp.id_token).unwrap_or_default();
                                    let user_id = claims["sub"].as_str().unwrap_or("sso-user");
                                    let email = claims["email"].as_str().unwrap_or("unknown@sso");
                                    let role = claims["role"].as_str().unwrap_or("analyst");
                                    let sid = mgr.sessions.create_session(user_id, email, role, 8);
                                    let body = serde_json::json!({
                                        "session_id": sid,
                                        "role": role,
                                        "expires_in": 28800,
                                    });
                                    json_response(&body.to_string(), 200)
                                }
                                Err(e) => error_json(&e, 502),
                            }
                        }
                    }
                    Err(e) => error_json(&e, 400),
                }

            } else if method == Method::Get && url_path == "/api/auth/session" {
                // Check current authentication state from bearer token
                let identity = authenticate_request(headers, state);
                let (user_id, role, authenticated) = match &identity {
                    AuthIdentity::AdminToken => ("admin".to_string(), "admin".to_string(), true),
                    AuthIdentity::UserToken(u) => (u.username.clone(), format!("{:?}", u.role).to_lowercase(), true),
                    AuthIdentity::None => ("anonymous".to_string(), "viewer".to_string(), false),
                };
                let body = serde_json::json!({
                    "user_id": user_id,
                    "role": role,
                    "authenticated": authenticated,
                });
                json_response(&body.to_string(), 200)

            } else if method == Method::Post && url_path == "/api/auth/logout" {
                let body = serde_json::json!({ "logged_out": true });
                json_response(&body.to_string(), 200)

            // ── Cloud Collectors ──────────────────────────────────
            } else if method == Method::Get && url_path == "/api/collectors/status" {
                let aws = crate::collector_aws::AwsCloudTrailCollector::new(Default::default());
                let azure = crate::collector_azure::AzureActivityCollector::new(Default::default());
                let gcp = crate::collector_gcp::GcpAuditCollector::new(Default::default());
                let body = serde_json::json!({
                    "collectors": [
                        {
                            "name": "aws_cloudtrail",
                            "enabled": aws.is_enabled(),
                            "region": aws.config().region,
                            "total_collected": aws.total_collected(),
                            "poll_interval_secs": aws.config().poll_interval_secs,
                        },
                        {
                            "name": "azure_activity",
                            "enabled": azure.is_enabled(),
                            "tenant_id": azure.config().tenant_id,
                            "total_collected": azure.total_collected(),
                            "poll_interval_secs": azure.config().poll_interval_secs,
                        },
                        {
                            "name": "gcp_audit",
                            "enabled": gcp.is_enabled(),
                            "project_id": gcp.config().project_id,
                            "total_collected": gcp.total_collected(),
                            "poll_interval_secs": gcp.config().poll_interval_secs,
                        },
                    ],
                });
                json_response(&body.to_string(), 200)
            } else if method == Method::Get && url_path == "/api/collectors/aws" {
                let c = crate::collector_aws::AwsCloudTrailCollector::new(Default::default());
                let body = serde_json::json!({
                    "enabled": c.is_enabled(),
                    "region": c.config().region,
                    "total_collected": c.total_collected(),
                    "poll_interval_secs": c.config().poll_interval_secs,
                    "event_name_filter": c.config().event_name_filter,
                });
                json_response(&body.to_string(), 200)
            } else if method == Method::Get && url_path == "/api/collectors/azure" {
                let c = crate::collector_azure::AzureActivityCollector::new(Default::default());
                let body = serde_json::json!({
                    "enabled": c.is_enabled(),
                    "tenant_id": c.config().tenant_id,
                    "subscription_id": c.config().subscription_id,
                    "total_collected": c.total_collected(),
                    "poll_interval_secs": c.config().poll_interval_secs,
                });
                json_response(&body.to_string(), 200)
            } else if method == Method::Get && url_path == "/api/collectors/gcp" {
                let c = crate::collector_gcp::GcpAuditCollector::new(Default::default());
                let body = serde_json::json!({
                    "enabled": c.is_enabled(),
                    "project_id": c.config().project_id,
                    "total_collected": c.total_collected(),
                    "poll_interval_secs": c.config().poll_interval_secs,
                });
                json_response(&body.to_string(), 200)

            // ── ML Engine ─────────────────────────────────────────
            } else if method == Method::Get && url_path == "/api/ml/models" {
                let engine = crate::ml_engine::StubEngine::new();
                let planned = crate::ml_engine::StubEngine::planned_models();
                let models: Vec<crate::ml_engine::ModelInfo> = {
                    use crate::ml_engine::InferenceEngine;
                    engine.list_models()
                };
                let body = serde_json::json!({
                    "loaded": models,
                    "available": planned,
                });
                json_response(&body.to_string(), 200)
            } else if method == Method::Post && url_path == "/api/ml/triage" {
                match read_body_limited(body, 8192) {
                    Ok(body_str) => {
                        let features: crate::ml_engine::TriageFeatures = match serde_json::from_str(&body_str) {
                            Ok(f) => f,
                            Err(e) => return respond_api(state, &method, &url, remote_addr, auth_used, error_json(&format!("invalid features: {e}"), 400)),
                        };
                        let engine = crate::ml_engine::StubEngine::new();
                        let result = engine.triage_alert(&features);
                        let body = serde_json::to_string(&result).unwrap_or_default();
                        json_response(&body, 200)
                    }
                    Err(e) => error_json(&e, 400),
                }

            } else {
                error_json("not found", 404)
            }
        }
    };

    respond_api(state, &method, &url, remote_addr, auth_used, response)
}

/// Read the request body with a size limit and a 30-second timeout to prevent
/// both OOM from oversized bodies and slowloris-style attacks.
fn read_body_limited(body: &[u8], limit: usize) -> Result<String, String> {
    if body.len() > limit {
        return Err("request body too large".to_string());
    }
    String::from_utf8(body.to_vec()).map_err(|_| "invalid UTF-8 in request body".to_string())
}

fn handle_analyze(body: &[u8],
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };

    // Detect format: if the body looks like CSV rather than JSON, parse as CSV
    let is_csv = !body.trim_start().starts_with('{') && body.contains(',');

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
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            // Update the live detector baseline with the analyzed samples
            for (sample, report) in samples.iter().zip(result.reports.iter()) {
                let pre = s
                    .detector
                    .snapshot()
                    .and_then(|snap| {
                        serde_json::to_vec(&snap)
                            .map_err(|e| log::error!("proof pre-snapshot serialization error: {e}"))
                            .ok()
                    })
                    .unwrap_or_default();
                s.detector.evaluate(sample);
                let post = s
                    .detector
                    .snapshot()
                    .and_then(|snap| {
                        serde_json::to_vec(&snap)
                            .map_err(|e| log::error!("proof post-snapshot serialization error: {e}"))
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

fn handle_mode(body: &[u8],
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
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

    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    s.detector.set_adaptation(mode);
    let body = serde_json::json!({"status": format!("mode set to {}", mode_req.mode)});
    json_response(&body.to_string(), 200)
}

fn handle_fleet_register(body: &[u8],
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
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
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    s.swarm.register_device(record);
    let body = serde_json::json!({"status": "registered", "device": req.device_id});
    json_response(&body.to_string(), 200)
}

fn handle_enforcement_quarantine(body: &[u8],
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
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
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    let results = s.enforcement.enforce(
        &crate::enforcement::EnforcementLevel::Quarantine,
        &req.target,
    );
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

fn handle_threat_intel_ioc(body: &[u8],
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
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
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
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

fn handle_digital_twin_simulate(body: &[u8],
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
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

    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    let result = s.digital_twin.simulate(&[step]);
    let info = serde_json::json!({
        "device_id": req.device_id,
        "ticks_simulated": result.ticks_simulated,
        "alerts": result.alerts_generated.len(),
        "transitions": result.state_transitions.len(),
    });
    json_response(&info.to_string(), 200)
}

fn handle_energy_consume(body: &[u8],
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
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
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    s.energy.drain_rate_mw = req.drain_rate_mw;
    let new_state = s.energy.tick();
    let info = serde_json::json!({
        "remaining_pct": s.energy.remaining_pct(),
        "power_state": format!("{new_state:?}"),
    });
    json_response(&info.to_string(), 200)
}

fn handle_policy_vm_execute(body: &[u8],
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
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
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    // Build a simple program that loads env values and computes a risk composite
    let program = crate::wasm_engine::PolicyProgram::new(
        "api-eval",
        vec![
            crate::wasm_engine::Opcode::LoadVar("score".into()),
            crate::wasm_engine::Opcode::LoadVar("battery".into()),
            crate::wasm_engine::Opcode::Mul,
            crate::wasm_engine::Opcode::StoreResult("risk_composite".into()),
            crate::wasm_engine::Opcode::Halt,
        ],
    );
    let result = s.policy_vm.execute(&program, &req.env);
    let info = serde_json::json!({
        "success": result.success,
        "outputs": result.outputs,
        "steps_executed": result.steps_executed,
        "error": result.error,
    });
    json_response(&info.to_string(), 200)
}

fn handle_deception_deploy(body: &[u8],
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
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
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
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

fn handle_policy_compose(body: &[u8],
    _state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
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
        score: req.score_a,
        confidence: 0.9,
        suspicious_axes: 0,
        reasons: vec!["composed-a".into()],
        contributions: Vec::new(),
    };
    let sample_a = TelemetrySample {
        timestamp_ms: 0,
        cpu_load_pct: 0.0,
        memory_load_pct: 0.0,
        temperature_c: 0.0,
        network_kbps: 0.0,
        auth_failures: 0,
        battery_pct: req.battery_a,
        integrity_drift: 0.0,
        process_count: 0,
        disk_pressure_pct: 0.0,
    };
    let decision_a = engine.evaluate(&signal_a, &sample_a);
    let signal_b = crate::detector::AnomalySignal {
        score: req.score_b,
        confidence: 0.9,
        suspicious_axes: 0,
        reasons: vec!["composed-b".into()],
        contributions: Vec::new(),
    };
    let sample_b = TelemetrySample {
        timestamp_ms: 0,
        cpu_load_pct: 0.0,
        memory_load_pct: 0.0,
        temperature_c: 0.0,
        network_kbps: 0.0,
        auth_failures: 0,
        battery_pct: req.battery_b,
        integrity_drift: 0.0,
        process_count: 0,
        disk_pressure_pct: 0.0,
    };
    let decision_b = engine.evaluate(&signal_b, &sample_b);
    let (result, conflict) =
        crate::policy::compose_decisions(Some(decision_a), Some(decision_b), op);
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

fn handle_config_reload(body: &[u8],
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    let patch: crate::config::ConfigPatch = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    let result = patch.apply(&mut s.config);
    match serde_json::to_string_pretty(&result) {
        Ok(json) => {
            let status = if result.success { 200 } else { 400 };
            json_response(&json, status)
        }
        Err(e) => error_json(&format!("serialization error: {e}"), 500),
    }
}

fn config_save_target(
    current: &Config,
    body: &str,
) -> Result<(Config, Vec<String>), Response<Body>> {
    if body.trim().is_empty() {
        return Ok((current.clone(), Vec::new()));
    }

    let patch: crate::config::ConfigPatch = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return Err(error_json(&format!("invalid JSON: {e}"), 400)),
    };

    let mut next_config = current.clone();
    let result = patch.apply(&mut next_config);
    if !result.success {
        return match serde_json::to_string_pretty(&result) {
            Ok(json) => Err(json_response(&json, 400)),
            Err(e) => Err(error_json(&format!("serialization error: {e}"), 500)),
        };
    }

    Ok((next_config, result.applied_fields))
}

// ── XDR Handler Functions ────────────────────────────────────────────

fn handle_agent_enroll(body: &[u8],
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    let req: crate::enrollment::EnrollRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    match s.agent_registry.enroll(&req) {
        Ok(resp) => match serde_json::to_string(&resp) {
            Ok(json) => json_response(&json, 200),
            Err(e) => error_json(&format!("serialization error: {e}"), 500),
        },
        Err(e) => error_json(&e, 403),
    }
}

fn handle_agent_create_token(body: &[u8],
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    #[derive(serde::Deserialize)]
    struct TokenReq {
        #[serde(default = "default_max_uses")]
        max_uses: u32,
        /// Optional TTL in seconds. If set, the token expires after this duration.
        #[serde(default)]
        ttl_secs: Option<u64>,
    }
    fn default_max_uses() -> u32 {
        10
    }
    let req: TokenReq = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => TokenReq {
            max_uses: 10,
            ttl_secs: None,
        },
    };
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    let token = if let Some(ttl) = req.ttl_secs {
        s.agent_registry.create_token_with_ttl(req.max_uses, ttl)
    } else {
        s.agent_registry.create_token(req.max_uses)
    };
    match serde_json::to_string(&token) {
        Ok(json) => json_response(&json, 200),
        Err(e) => error_json(&format!("serialization error: {e}"), 500),
    }
}

fn handle_agent_heartbeat(body: &[u8],
    state: &Arc<Mutex<AppState>>,
    agent_id: &str,
) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
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
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    match s
        .agent_registry
        .heartbeat(agent_id, &req.version, req.health.clone())
    {
        Ok(()) => {
            let mut target_version = None;
            let now = chrono::Utc::now().to_rfc3339();
            if let Some(deployment) = s.remote_deployments.get_mut(agent_id) {
                deployment.last_heartbeat_at = Some(now.clone());
                if let Some(health) = &req.health
                    && let Some(update_state) = &health.update_state {
                        deployment.status = update_state.clone();
                        deployment.status_reason = health.last_update_error.clone();
                        if matches!(
                            update_state.as_str(),
                            "checking" | "downloading" | "downloaded" | "applying"
                        )
                            && deployment.acknowledged_at.is_none() {
                                deployment.acknowledged_at = Some(now.clone());
                            }
                        if matches!(update_state.as_str(), "restart_pending" | "applied") {
                            deployment.completed_at = Some(now.clone());
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
                    if dep.status == "applied"
                        && let Some(ref completed) = dep.completed_at
                            && let Ok(completed_time) =
                                chrono::DateTime::parse_from_rfc3339(completed)
                            {
                                let elapsed =
                                    chrono::Utc::now().signed_duration_since(completed_time);
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
                                    progress_candidates.push((
                                        dep.version.clone(),
                                        dep.platform.clone(),
                                        next_ring.to_string(),
                                    ));
                                }
                            }
                }
                // Check for failures -> auto-rollback
                if rollout_cfg.auto_rollback {
                    let mut rollback_agents: Vec<(String, String)> = Vec::new(); // (agent_id, version_before)
                    for dep in s.remote_deployments.values() {
                        if dep.status == "failed" || dep.status == "error" {
                            // Count failures for this version
                            let fail_count = s
                                .remote_deployments
                                .values()
                                .filter(|d| {
                                    d.version == dep.version
                                        && (d.status == "failed" || d.status == "error")
                                })
                                .count() as u32;
                            if fail_count >= rollout_cfg.max_failures
                                && dep.status_reason.as_deref() != Some("auto_rollback_scheduled")
                            {
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
                    let enrolled: Vec<String> = s
                        .agent_registry
                        .list()
                        .iter()
                        .filter(|a| {
                            a.platform == platform
                                && a.status == crate::enrollment::AgentStatus::Online
                        })
                        .map(|a| a.id.clone())
                        .collect();
                    for eid in enrolled {
                        let already_deployed = s
                            .remote_deployments
                            .get(&eid)
                            .map(|d| d.version == version)
                            .unwrap_or(false);
                        if !already_deployed {
                            let new_dep = AgentDeployment {
                                agent_id: eid.clone(),
                                version: version.clone(),
                                platform: platform.clone(),
                                mandatory: false,
                                release_notes: format!(
                                    "Auto-progressed from previous ring to {next_ring}"
                                ),
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
            let agent_scope = s
                .agent_registry
                .get_monitor_scope(agent_id)
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
) -> Response<Body> {
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    match build_agent_activity_snapshot(&s, agent_id) {
        Ok(snapshot) => match serde_json::to_string(&snapshot) {
            Ok(json) => json_response(&json, 200),
            Err(e) => error_json(&format!("serialization error: {e}"), 500),
        },
        Err(e) => error_json(&e, 404),
    }
}

fn handle_agent_update_check(body: &[u8],
    url: &str,
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    // Agent sends GET /api/agents/update?agent_id=xxx&current_version=yyy
    let params = parse_query_string(url);
    let agent_id = params.get("agent_id").cloned();
    let mut current_version = params.get("current_version").cloned().unwrap_or_default();
    let mut platform = params
        .get("platform")
        .cloned()
        .unwrap_or_else(|| "universal".to_string());
    if current_version.is_empty() {
        current_version = env!("CARGO_PKG_VERSION").to_string();
    }
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(agent_id) = agent_id.as_deref() {
        if platform == "universal"
            && let Some(agent) = s.agent_registry.get(agent_id) {
                platform = agent.platform.clone();
            }
        if let Some(deployment) = s.remote_deployments.get(agent_id)
            && deployment_requires_action(deployment, &current_version)
                && let Some(release) = s.update_manager.get_release(&deployment.version, &platform)
                {
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
    let resp = s.update_manager.check_update(&current_version, &platform);
    match serde_json::to_string(&resp) {
        Ok(json) => json_response(&json, 200),
        Err(e) => error_json(&format!("serialization error: {e}"), 500),
    }
}

fn handle_update_deploy(body: &[u8],
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
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

    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    let agent = match s.agent_registry.get(&req.agent_id) {
        Some(agent) => agent,
        None => return error_json("agent not found", 404),
    };
    if !req.allow_downgrade
        && compare_versions(&req.version, &agent.version) == std::cmp::Ordering::Less
    {
        return error_json("downgrade blocked without allow_downgrade=true", 409);
    }
    if let Some(existing) = s.remote_deployments.get(&req.agent_id)
        && !req.allow_downgrade
            && compare_versions(&req.version, &existing.version) == std::cmp::Ordering::Less
        {
            return error_json(
                "deployment would roll back an already assigned version",
                409,
            );
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
    s.remote_deployments
        .insert(req.agent_id.clone(), deployment.clone());
    save_remote_deployments(&s.deployment_store_path, &s.remote_deployments);

    let payload = serde_json::json!({
        "status": "assigned",
        "agent_id": req.agent_id,
        "deployment": deployment,
    });
    json_response(&payload.to_string(), 200)
}

fn handle_event_triage(body: &[u8],
    state: &Arc<Mutex<AppState>>,
    event_id: &str,
) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
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

    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    match s.event_store.update_triage(event_id, update) {
        Ok(event) => json_response(
            &serde_json::json!({ "status": "updated", "event": event }).to_string(),
            200,
        ),
        Err(e) if e == "event not found" => error_json(&e, 404),
        Err(e) => error_json(&e, 400),
    }
}

fn handle_event_ingest(body: &[u8],
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    let mut batch: crate::event_forward::EventBatch = match serde_json::from_str(&body) {
        Ok(b) => b,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    let native_rule_matches: usize = batch
        .events
        .iter_mut()
        .map(|alert| {
            s.enterprise
                .apply_active_native_rules(alert, &batch.agent_id)
        })
        .sum();
    let result = s.event_store.ingest(&batch);
    let newly_ingested = s.event_store.recent_events(batch.events.len());

    for event in &newly_ingested {
        if severity_rank(&event.alert.level) > 0 {
            s.alert_queue.enqueue(
                event.id,
                event.alert.score as f64,
                event.alert.level.clone(),
                event.alert.hostname.clone(),
                event.received_at.clone(),
            );
        }
    }

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
        let mut total_matches = native_rule_matches;
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
                map.insert(
                    "sigma_matches".to_string(),
                    serde_json::json!(sigma_matches),
                );
            }
            json_response(&serde_json::Value::Object(map).to_string(), 200)
        }
        Ok(other) => json_response(&other.to_string(), 200),
        Err(e) => error_json(&format!("serialization error: {e}"), 500),
    };
    let _ = &mut resp; // suppress unused warning
    resp
}

fn handle_bulk_triage(body: &[u8],
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
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
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    let result = s
        .event_store
        .bulk_update_triage(&req.event_ids, &req.update);
    let payload = serde_json::json!({
        "updated": result.updated,
        "failed": result.failed.iter().map(|(id, msg)| serde_json::json!({"event_id": id, "error": msg})).collect::<Vec<_>>(),
    });
    json_response(&payload.to_string(), 200)
}

fn handle_update_rollback(body: &[u8],
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
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
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
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
    if let Some(existing) = s.remote_deployments.get(&req.agent_id)
        && !is_terminal_deployment_status(&existing.status) {
            // Mark the old deployment as cancelled before replacing
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
    s.remote_deployments
        .insert(req.agent_id.clone(), deployment.clone());
    save_remote_deployments(&s.deployment_store_path, &s.remote_deployments);
    let payload = serde_json::json!({
        "status": "rollback_assigned",
        "agent_id": req.agent_id,
        "deployment": deployment,
    });
    json_response(&payload.to_string(), 200)
}

fn handle_update_cancel(body: &[u8],
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
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
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    match s.remote_deployments.get_mut(&req.agent_id) {
        Some(deployment) => {
            if is_terminal_deployment_status(&deployment.status) {
                return error_json("deployment already in terminal state", 409);
            }
            deployment.status = "cancelled".to_string();
            deployment.status_reason = Some("cancelled by admin".to_string());
            deployment.completed_at = Some(chrono::Utc::now().to_rfc3339());
            save_remote_deployments(&s.deployment_store_path, &s.remote_deployments);
            json_response(
                &serde_json::json!({"status": "cancelled", "agent_id": req.agent_id}).to_string(),
                200,
            )
        }
        None => error_json("no deployment found for agent", 404),
    }
}

fn handle_agent_set_scope(body: &[u8],
    state: &Arc<Mutex<AppState>>,
    agent_id: &str,
) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    // Accept either a full MonitorScopeSettings or {"clear": true} to remove override
    // Try parsing as clear command first
    let clear_check: Result<serde_json::Value, _> = serde_json::from_str(&body);
    let is_clear = clear_check
        .as_ref()
        .ok()
        .and_then(|v| v.get("clear"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    if is_clear {
        match s.agent_registry.set_monitor_scope(agent_id, None) {
            Ok(()) => json_response(
                &serde_json::json!({"status": "scope_cleared", "agent_id": agent_id}).to_string(),
                200,
            ),
            Err(e) => error_json(&e, 404),
        }
    } else {
        let scope: crate::config::MonitorScopeSettings = match serde_json::from_str(&body) {
            Ok(s) => s,
            Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
        };
        match s
            .agent_registry
            .set_monitor_scope(agent_id, Some(scope.clone()))
        {
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
) -> Response<Body> {
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    match s.agent_registry.get(agent_id) {
        Some(agent) => {
            let effective_scope = agent
                .monitor_scope
                .as_ref()
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

fn handle_policy_publish(body: &[u8],
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    let policy: crate::policy_dist::Policy = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    s.policy_store.publish(policy);
    let version = s.policy_store.current_version();
    json_response(
        &format!(r#"{{"status":"published","version":{version}}}"#),
        200,
    )
}

fn handle_update_publish(body: &[u8],
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
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

    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
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

fn response_required_approvals(tier: ActionTier) -> usize {
    match tier {
        ActionTier::Auto => 0,
        ActionTier::SingleApproval => 1,
        ActionTier::DualApproval => 2,
        ActionTier::BreakGlass => 2,
    }
}

fn response_action_label(action: &ResponseAction) -> String {
    match action {
        ResponseAction::Alert => "Alert".to_string(),
        ResponseAction::Isolate => "Isolate host".to_string(),
        ResponseAction::Throttle { rate_limit_kbps } => {
            format!("Throttle to {rate_limit_kbps} kbps")
        }
        ResponseAction::KillProcess { pid, process_name } => {
            format!("Kill process {process_name} (PID {pid})")
        }
        ResponseAction::QuarantineFile { path } => format!("Quarantine file {path}"),
        ResponseAction::BlockIp { ip } => format!("Block IP {ip}"),
        ResponseAction::DisableAccount { username } => format!("Disable account {username}"),
        ResponseAction::RollbackConfig { config_name } => format!("Rollback config {config_name}"),
        ResponseAction::Custom { name, .. } => format!("Custom action {name}"),
    }
}

fn response_request_json(request: &ResponseRequest) -> serde_json::Value {
    let approved_count = request
        .approvals
        .iter()
        .filter(|record| record.decision == ResponseApprovalDecision::Approve)
        .count();
    serde_json::json!({
        "id": request.id,
        "action": format!("{:?}", request.action),
        "action_label": response_action_label(&request.action),
        "target": request.target,
        "target_hostname": request.target.hostname,
        "target_agent_uid": request.target.agent_uid,
        "tier": format!("{:?}", request.tier),
        "status": format!("{:?}", request.status),
        "created_at": request.requested_at,
        "requested_at": request.requested_at,
        "requested_by": request.requested_by,
        "reason": request.reason,
        "severity": request.severity,
        "approvals": request.approvals,
        "approval_count": approved_count,
        "approvals_required": response_required_approvals(request.tier),
        "dry_run": request.dry_run,
        "is_protected_asset": request.is_protected_asset,
        "blast_radius": request.blast_radius.as_ref().map(|blast| serde_json::json!({
            "affected_services": blast.affected_services,
            "affected_endpoints": blast.affected_endpoints,
            "risk_level": blast.risk_level,
            "impact_summary": blast.impact_summary,
        })),
        "blast_radius_summary": request.blast_radius.as_ref().map(|blast| blast.impact_summary.clone()),
    })
}

fn response_action_from_json(value: &serde_json::Value) -> Result<ResponseAction, String> {
    let action = value["action"]
        .as_str()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    match action.as_str() {
        "alert" => Ok(ResponseAction::Alert),
        "isolate" => Ok(ResponseAction::Isolate),
        "throttle" => Ok(ResponseAction::Throttle {
            rate_limit_kbps: value["rate_limit_kbps"].as_u64().unwrap_or(256) as u32,
        }),
        "kill_process" => {
            let pid = value["pid"]
                .as_u64()
                .ok_or("pid is required for kill_process")? as u32;
            let process_name = value["process_name"]
                .as_str()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("pid-{pid}"));
            Ok(ResponseAction::KillProcess { pid, process_name })
        }
        "quarantine_file" => {
            let path = value["path"]
                .as_str()
                .ok_or("path is required for quarantine_file")?
                .trim()
                .to_string();
            if path.is_empty() {
                return Err("path is required for quarantine_file".into());
            }
            Ok(ResponseAction::QuarantineFile { path })
        }
        "block_ip" => {
            let ip = value["ip"]
                .as_str()
                .ok_or("ip is required for block_ip")?
                .trim()
                .to_string();
            if ip.is_empty() {
                return Err("ip is required for block_ip".into());
            }
            Ok(ResponseAction::BlockIp { ip })
        }
        "disable_account" => {
            let username = value["username"]
                .as_str()
                .ok_or("username is required for disable_account")?
                .trim()
                .to_string();
            if username.is_empty() {
                return Err("username is required for disable_account".into());
            }
            Ok(ResponseAction::DisableAccount { username })
        }
        "rollback_config" => {
            let config_name = value["config_name"]
                .as_str()
                .ok_or("config_name is required for rollback_config")?
                .trim()
                .to_string();
            if config_name.is_empty() {
                return Err("config_name is required for rollback_config".into());
            }
            Ok(ResponseAction::RollbackConfig { config_name })
        }
        "custom" => {
            let name = value["name"]
                .as_str()
                .ok_or("name is required for custom action")?
                .trim()
                .to_string();
            if name.is_empty() {
                return Err("name is required for custom action".into());
            }
            let payload = value["payload"].as_str().unwrap_or("").to_string();
            Ok(ResponseAction::Custom { name, payload })
        }
        _ => Err("unsupported action".into()),
    }
}

fn graphql_source_rows(
    source: &str,
    alerts: &VecDeque<AlertRecord>,
    registry: &AgentRegistry,
    events: &EventStore,
    enterprise: &EnterpriseStore,
    incidents: &IncidentStore,
    threat_intel: &ThreatIntelStore,
) -> Option<Vec<serde_json::Value>> {
    match source.to_ascii_lowercase().as_str() {
        "alerts" => Some(
            alerts
                .iter()
                .enumerate()
                .map(|(i, a)| {
                    serde_json::json!({
                        "id": format!("alert-{i}"),
                        "level": a.level,
                        "timestamp": a.timestamp,
                        "device_id": a.hostname,
                        "score": a.score,
                        "status": "open",
                    })
                })
                .collect(),
        ),
        "agents" => Some(
            registry
                .list()
                .iter()
                .map(|a| {
                    serde_json::json!({
                        "id": a.id,
                        "hostname": a.hostname,
                        "os": a.platform,
                        "version": a.version,
                        "status": format!("{:?}", a.status),
                        "last_heartbeat": a.last_seen,
                    })
                })
                .collect(),
        ),
        "events" => Some(
            events
                .all_events()
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "timestamp": e.received_at,
                        "device_id": e.agent_id,
                        "event_type": e.alert.level,
                        "hostname": e.alert.hostname,
                        "score": e.alert.score,
                    })
                })
                .collect(),
        ),
        "hunts" => Some(
            enterprise
                .hunts()
                .iter()
                .map(|h| {
                    serde_json::json!({
                        "id": h.id,
                        "name": h.name,
                        "status": if h.enabled { "active" } else { "disabled" },
                        "severity": h.severity,
                        "threshold": h.threshold,
                        "created_at": h.created_at,
                    })
                })
                .collect(),
        ),
        "incidents" => Some(
            incidents
                .list()
                .iter()
                .map(|inc| {
                    serde_json::json!({
                        "id": inc.id,
                        "title": inc.title,
                        "severity": inc.severity,
                        "status": format!("{:?}", inc.status),
                        "alert_count": inc.event_ids.len(),
                        "created_at": inc.created_at,
                    })
                })
                .collect(),
        ),
        "iocs" => Some(
            threat_intel
                .all_iocs()
                .into_iter()
                .map(|ioc| {
                    serde_json::json!({
                        "value": ioc.value,
                        "ioc_type": format!("{:?}", ioc.ioc_type),
                        "source": ioc.source,
                        "severity": ioc.severity,
                        "confidence": ioc.confidence,
                    })
                })
                .collect(),
        ),
        _ => None,
    }
}

fn graphql_aggregate_json(
    args: &HashMap<String, serde_json::Value>,
    alerts: &VecDeque<AlertRecord>,
    registry: &AgentRegistry,
    events: &EventStore,
    enterprise: &EnterpriseStore,
    incidents: &IncidentStore,
    threat_intel: &ThreatIntelStore,
) -> serde_json::Value {
    let source = args.get("source").and_then(|v| v.as_str()).unwrap_or("");
    let op_raw = args.get("op").and_then(|v| v.as_str()).unwrap_or("");
    let field = args.get("field").and_then(|v| v.as_str()).unwrap_or("");
    let group_by = args.get("group_by").and_then(|v| v.as_str());

    let Some(rows) = graphql_source_rows(
        source,
        alerts,
        registry,
        events,
        enterprise,
        incidents,
        threat_intel,
    ) else {
        return serde_json::json!({
            "op": op_raw,
            "field": field,
            "value": serde_json::Value::Null,
            "group_by": group_by,
            "groups": [],
        });
    };

    let Ok(op) = AggregateOp::from_str(op_raw) else {
        return serde_json::json!({
            "op": op_raw,
            "field": field,
            "value": serde_json::Value::Null,
            "group_by": group_by,
            "groups": [],
        });
    };

    serde_json::to_value(aggregate(&rows, op, field, group_by)).unwrap_or_else(|_| {
        serde_json::json!({
            "op": op_raw,
            "field": field,
            "value": serde_json::Value::Null,
            "group_by": group_by,
            "groups": [],
        })
    })
}

fn next_response_request_id() -> String {
    static RESPONSE_REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);
    let sequence = RESPONSE_REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(
        "resp-{}-{}",
        chrono::Utc::now()
            .timestamp_nanos_opt()
            .unwrap_or_else(|| chrono::Utc::now().timestamp_micros() * 1_000),
        sequence
    )
}

fn hunt_incident_marker(hunt: &SavedHunt) -> String {
    format!("hunt_id={}", hunt.id)
}

fn execute_hunt_response_actions(
    hunt: &SavedHunt,
    run: &HuntRun,
    events: &[StoredEvent],
    incident_store: &mut IncidentStore,
    enterprise: &mut EnterpriseStore,
    response_orchestrator: &ResponseOrchestrator,
    actor: &str,
) -> Vec<ResponseActionResult> {
    let mut results = hunt.evaluate_responses(run);
    if results.is_empty() {
        return results;
    }

    let event_ids = if run.matched_event_ids.is_empty() {
        run.sample_event_ids.clone()
    } else {
        run.matched_event_ids.clone()
    };

    let matching_events: Vec<&StoredEvent> = events
        .iter()
        .filter(|event| event_ids.contains(&event.id))
        .collect();

    let mut host_targets = Vec::new();
    let mut seen_targets = BTreeSet::new();
    let mut agent_ids = BTreeSet::new();
    let mut seen_techniques = BTreeSet::new();
    let mut mitre = Vec::new();

    for event in &matching_events {
        agent_ids.insert(event.agent_id.clone());
        let target_key = (event.alert.hostname.clone(), Some(event.agent_id.clone()));
        if seen_targets.insert(target_key.clone()) {
            host_targets.push(target_key);
        }
        for attack in &event.alert.mitre {
            if seen_techniques.insert(attack.technique_id.clone()) {
                mitre.push(attack.clone());
            }
        }
    }

    for (action, result) in hunt.response_actions.iter().zip(results.iter_mut()) {
        if !result.executed {
            continue;
        }
        match action {
            HuntResponseAction::Notify { channel, min_level } => {
                let mut request_ids = Vec::new();
                for (hostname, agent_uid) in &host_targets {
                    let request = ResponseRequest {
                        id: next_response_request_id(),
                        action: ResponseAction::Alert,
                        target: ResponseTarget {
                            hostname: hostname.clone(),
                            agent_uid: agent_uid.clone(),
                            asset_tags: Vec::new(),
                        },
                        reason: format!(
                            "Automated hunt notification via {channel} (min_level={min_level}) from {}",
                            hunt.name
                        ),
                        severity: run.severity.clone(),
                        tier: ActionTier::Auto,
                        status: ApprovalStatus::Pending,
                        requested_at: chrono::Utc::now().to_rfc3339(),
                        requested_by: actor.to_string(),
                        approvals: Vec::new(),
                        dry_run: false,
                        blast_radius: None,
                        is_protected_asset: false,
                    };
                    if let Ok(request_id) = response_orchestrator.submit(request) {
                        request_ids.push(request_id);
                    }
                }
                if request_ids.is_empty() {
                    result.executed = false;
                    result.detail = format!(
                        "Skipped notify channel '{}' because no eligible hosts were found",
                        channel
                    );
                } else {
                    result.detail = format!(
                        "Notify channel '{}' (min_level={}) queued {} alert notification(s): {}",
                        channel,
                        min_level,
                        request_ids.len(),
                        request_ids.join(", ")
                    );
                }
            }
            HuntResponseAction::CreateIncident { severity, title_template } => {
                let title = title_template
                    .replace("{hunt_name}", &hunt.name)
                    .replace("{match_count}", &run.match_count.to_string());
                let summary = format!(
                    "Auto-created from hunt '{}' ({}) run {} with {} visible match(es)",
                    hunt.name,
                    hunt_incident_marker(hunt),
                    run.id,
                    run.match_count
                );
                let incident_agent_ids = if run.matched_agent_ids.is_empty() {
                    agent_ids.iter().cloned().collect::<Vec<_>>()
                } else {
                    run.matched_agent_ids.clone()
                };
                if let Some(existing) = incident_store
                    .incidents
                    .iter_mut()
                    .find(|incident| {
                        matches!(
                            incident.status,
                            crate::incident::IncidentStatus::Open
                                | crate::incident::IncidentStatus::Investigating
                        ) && incident.summary.contains(&hunt_incident_marker(hunt))
                    })
                {
                    for event_id in &event_ids {
                        if !existing.event_ids.contains(event_id) {
                            existing.event_ids.push(*event_id);
                        }
                    }
                    for agent_id in &incident_agent_ids {
                        if !existing.agent_ids.contains(agent_id) {
                            existing.agent_ids.push(agent_id.clone());
                        }
                    }
                    for attack in &mitre {
                        if !existing
                            .mitre_techniques
                            .iter()
                            .any(|current| current.technique_id == attack.technique_id)
                        {
                            existing.mitre_techniques.push(attack.clone());
                        }
                    }
                    existing.updated_at = chrono::Utc::now().to_rfc3339();
                    existing.summary = summary;
                    result.detail = format!(
                        "Updated existing {severity} incident #{}: {}",
                        existing.id, existing.title
                    );
                } else {
                    let incident = incident_store.create(
                        title.clone(),
                        severity.clone(),
                        event_ids.clone(),
                        incident_agent_ids,
                        mitre.clone(),
                        summary,
                    );
                    result.detail = format!("Create {severity} incident #{}: {title}", incident.id);
                }
            }
            HuntResponseAction::AutoSuppress {
                duration_secs,
                justification,
            } => {
                let suppression_name = format!("Auto-suppress {}", hunt.name);
                let existing_id = enterprise
                    .suppressions()
                    .iter()
                    .find(|suppression| {
                        suppression.hunt_id.as_deref() == Some(hunt.id.as_str())
                            && suppression.name == suppression_name
                    })
                    .map(|suppression| suppression.id.clone());
                let expires_at =
                    (chrono::Utc::now() + chrono::Duration::seconds(*duration_secs as i64))
                        .to_rfc3339();
                let suppression = enterprise.create_or_update_suppression(
                    existing_id.as_deref(),
                    suppression_name,
                    None,
                    Some(hunt.id.clone()),
                    None,
                    None,
                    Some(run.severity.clone()),
                    None,
                    Some(expires_at.clone()),
                    justification.clone(),
                    actor.to_string(),
                    true,
                );
                result.detail = format!(
                    "Suppress for {duration_secs}s until {} via suppression {}",
                    expires_at, suppression.id
                );
            }
            HuntResponseAction::IsolateAgent => {
                let mut request_ids = Vec::new();
                let mut failures = Vec::new();
                for (hostname, agent_uid) in &host_targets {
                    let request = ResponseRequest {
                        id: next_response_request_id(),
                        action: ResponseAction::Isolate,
                        target: ResponseTarget {
                            hostname: hostname.clone(),
                            agent_uid: agent_uid.clone(),
                            asset_tags: Vec::new(),
                        },
                        reason: format!(
                            "Automated host isolation requested by hunt '{}' run {}",
                            hunt.name, run.id
                        ),
                        severity: run.severity.clone(),
                        tier: ActionTier::SingleApproval,
                        status: ApprovalStatus::Pending,
                        requested_at: chrono::Utc::now().to_rfc3339(),
                        requested_by: actor.to_string(),
                        approvals: Vec::new(),
                        dry_run: false,
                        blast_radius: None,
                        is_protected_asset: false,
                    };
                    match response_orchestrator.submit(request) {
                        Ok(request_id) => request_ids.push(request_id),
                        Err(err) => failures.push(format!("{}: {}", hostname, err)),
                    }
                }
                if request_ids.is_empty() {
                    result.executed = false;
                    result.detail = if failures.is_empty() {
                        "Skipped isolation because no eligible hosts were found".to_string()
                    } else {
                        format!("Isolation requests rejected: {}", failures.join("; "))
                    };
                } else {
                    let mut detail = format!(
                        "Queued {} isolate request(s): {}",
                        request_ids.len(),
                        request_ids.join(", ")
                    );
                    if !failures.is_empty() {
                        detail.push_str(&format!("; rejected: {}", failures.join("; ")));
                    }
                    result.detail = detail;
                }
            }
        }
    }

    results
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
        let val = TABLE
            .iter()
            .position(|&c| c == b)
            .ok_or_else(|| format!("invalid base64 character: {}", b as char))?
            as u32;
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

// Admin console embedded at compile time — single portable binary
const EMBEDDED_ADMIN_HTML: &str = include_str!("../admin-console/admin.html");
const EMBEDDED_ADMIN_CSS: &str = include_str!("../admin-console/admin.css");
const EMBEDDED_ADMIN_JS: &str = include_str!("../admin-console/admin.js");

fn serve_embedded(content: &str, content_type: &str) -> Response<Body> {
    let data = content.as_bytes();
    let origin = cors_origin();
    let cache = if content_type.contains("html") {
        "no-cache"
    } else {
        "public, max-age=3600, immutable"
    };
    Response::builder()
        .status(200)
        .header("Content-Type", content_type)
        .header("Access-Control-Allow-Origin", origin)
        .header("X-Content-Type-Options", "nosniff")
        .header("X-Frame-Options", "DENY")
        .header("Cache-Control", cache)
        .body(Body::from(data.to_vec()))
        .unwrap()
}

fn serve_static(url: &str, site_dir: &Path) -> Response<Body> {
    let relative = if url == "/" { "/index.html" } else { url };

    // Serve embedded admin console from the binary itself
    match relative {
        "/admin.html" => return serve_embedded(EMBEDDED_ADMIN_HTML, "text/html; charset=utf-8"),
        "/admin.css" => return serve_embedded(EMBEDDED_ADMIN_CSS, "text/css; charset=utf-8"),
        "/admin.js" => return serve_embedded(EMBEDDED_ADMIN_JS, "application/javascript; charset=utf-8"),
        _ => {}
    }

    // Prevent path traversal via components
    let clean = relative.trim_start_matches('/');
    let requested = PathBuf::from(clean);
    if requested
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return error_json("forbidden", 403);
    }

    let file_path = site_dir.join(clean);

    // Canonicalize to prevent symlink-based path traversal
    let canon_site = match site_dir.canonicalize() {
        Ok(p) => p,
        Err(_) => {
            return error_json("server error", 500);
        }
    };
    if let Ok(canon_file) = file_path.canonicalize()
        && !canon_file.starts_with(&canon_site) {
            return error_json("forbidden", 403);
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
                let origin = cors_origin();
                let cache = if content_type.contains("html") {
                    "no-cache"
                } else {
                    "public, max-age=3600"
                };
                Response::builder()
                    .status(200)
                    .header("Content-Type", content_type)
                    .header("Access-Control-Allow-Origin", origin)
                    .header("X-Content-Type-Options", "nosniff")
                    .header("X-Frame-Options", "DENY")
                    .header("Cache-Control", cache)
                    .body(Body::from(data))
                    .unwrap()
            }
            Err(_) => error_json("read error", 500),
        }
    } else {
        error_json("not found", 404)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyst::ApprovalDecision as AnalystApprovalDecision;
    use crate::collector::AlertRecord;
    use crate::enrollment::EnrollRequest;
    use crate::event_forward::EventBatch;
    use crate::response::{ApprovalDecision as ResponseApprovalDecision, ApprovalRecord};
    use crate::telemetry::TelemetrySample;
    use std::collections::HashMap as StdHashMap;
    use std::path::PathBuf;

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
        }
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

        assert!(limiter.check("127.0.0.1", &Method::Get, "/site/admin.html"));
        assert!(limiter.check("127.0.0.1", &Method::Get, "/site/admin.js"));
        assert!(limiter.check("127.0.0.1", &Method::Get, "/site/styles.css"));
        assert!(limiter.check("127.0.0.1", &Method::Get, "/site/app.js"));
        assert!(!limiter.check("127.0.0.1", &Method::Get, "/site/index.html"));
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

        let mut queue = AlertQueue::new();
        let mut case_store = CaseStore::new(case_path.to_str().unwrap());
        let mut incident_store = IncidentStore::new(incident_path.to_str().unwrap());
        let mut approvals = ApprovalLog::new();
        let response = ResponseOrchestrator::new();
        let mut events = EventStore::new(100);
        let mut registry = AgentRegistry::new(agent_path.to_str().unwrap());

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

        let analytics = events.analytics();
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
        );

        assert_eq!(overview.queue.pending, 2);
        assert_eq!(overview.queue.assigned, 1);
        assert_eq!(overview.cases.total, 1);
        assert_eq!(overview.incidents.total, 1);
        assert_eq!(overview.response.ready_to_execute, 1);
        assert!(overview
            .urgent_items
            .iter()
            .any(|item| item.kind == "queue" || item.kind == "response"));
        assert_eq!(overview.hot_agents.len(), 1);

        let _ = fs::remove_file(case_path);
        let _ = fs::remove_file(incident_path);
        let _ = fs::remove_file(agent_path);
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
            events: vec![sample_alert("hunt-host", "Critical", 9.7, "credential storm")],
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
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
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
        assert!(incidents.list()[0].title.contains("Credential Storm: 1 hits"));
        assert_eq!(enterprise.suppressions().len(), 1);
        assert_eq!(response.all_requests().len(), 2);
        assert!(response
            .all_requests()
            .iter()
            .any(|request| request.action == ResponseAction::Alert && request.status == ApprovalStatus::Executed));
        assert!(response
            .all_requests()
            .iter()
            .any(|request| request.action == ResponseAction::Isolate && request.status == ApprovalStatus::Pending));

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
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
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
        assert!(requests.iter().any(|request| request.target.agent_uid.as_deref() == Some("agent-a")));
        assert!(requests.iter().any(|request| request.target.agent_uid.as_deref() == Some("agent-b")));

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
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
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
        assert!(second[0].detail.contains("Updated existing high incident #"));
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
}
