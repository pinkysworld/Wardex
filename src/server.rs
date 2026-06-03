//! Axum-based HTTP API server serving REST endpoints, the admin console, and static assets.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use axum::body::Body;
use axum::http::header::{COOKIE, LOCATION, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, Method as HttpMethod, StatusCode};
use axum::response::Response;
use serde::de::DeserializeOwned;

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
        if m == HttpMethod::GET {
            Method::Get
        } else if m == HttpMethod::POST {
            Method::Post
        } else if m == HttpMethod::PUT {
            Method::Put
        } else if m == HttpMethod::DELETE {
            Method::Delete
        } else if m == HttpMethod::OPTIONS {
            Method::Options
        } else if m == HttpMethod::PATCH {
            Method::Patch
        } else if m == HttpMethod::HEAD {
            Method::Head
        } else {
            Method::Get
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
            Method::Options => "OPTIONS",
            Method::Patch => "PATCH",
            Method::Head => "HEAD",
        }
    }
}

use crate::actions::DeviceController;
use crate::auto_update::UpdateManager;
use crate::checkpoint::CheckpointStore;
use crate::cluster::ClusterNode;
use crate::collector::{
    AlertRecord, CollectorState, FileIntegrityMonitor, HostInfo, HostPlatform, detect_platform,
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
use crate::enrollment::{AgentHealth, AgentIdentity, AgentRegistry, AgentStatus};
use crate::enterprise::{
    ContentLifecycle, EnterpriseStore, HuntResponseAction, HuntRun, IdentityConfigValidation,
    ResponseActionResult, SavedHunt, build_content_rules_view, build_entity_profile,
    build_entity_timeline, build_incident_storyline, build_mitre_coverage,
};
use crate::event_forward::{EventAnalytics, EventStore, StoredEvent};
use crate::fingerprint::DeviceFingerprint;
use crate::fleet_install::RemoteInstallRecord;
use crate::graphql::{AggregateOp, GqlExecutor, GqlRequest, aggregate, wardex_schema};
use crate::incident::IncidentStore;
use crate::integration_setup::SecretsManagerSetup;
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
use crate::swarm::SwarmNode;
use crate::telemetry::TelemetrySample;
use crate::threat_intel::{DeceptionEngine, ThreatIntelStore};
use crate::tls::ListenerMode;
use crate::user_preferences::{UserPreferencesPatch, UserPreferencesStore};
use crate::wasm_engine::PolicyVm;

use crate::analyst::{
    AlertQueue, ApprovalDecision as RemediationDecision, ApprovalLog, CasePriority, CaseStatus,
    CaseStore,
};
use crate::feature_flags::FeatureFlagRegistry;
use crate::ocsf::{self, DeadLetterQueue, SchemaVersion};
use crate::process_tree::ProcessTree;
use crate::rbac::{RbacStore, Role, User, role_permissions};
use crate::response::{
    ActionTier, ApprovalDecision as ResponseApprovalDecision,
    ApprovalRecord as ResponseApprovalRecord, ApprovalStatus, ResponseAction, ResponseOrchestrator,
    ResponseRequest, ResponseTarget,
};
use crate::server_alerts::{
    AlertProcessPivot, alert_process_resolution, assemble_alert_process_catalog,
    extract_alert_process_names, host_matches_local, resolve_alert_process_pivots,
};
use crate::server_auth::{
    bearer_token, failed_auth_clear_request, failed_auth_locked_request,
    failed_auth_locked_response, failed_auth_record_request, failed_auth_subject, secure_token_eq,
};
use crate::server_av::{load_local_open_source_av_signatures, local_av_signature_presets_json};
#[cfg(test)]
use crate::server_control_plane::backup_records_in_dir;
use crate::server_control_plane::{
    BackupStatusSnapshot, ControlPlanePostureSnapshot, backup_file_record,
    control_plane_failover_history_preview, is_runtime_backup_file,
};
#[cfg(test)]
use crate::server_evidence::snapshot_entry_from_path;
use crate::server_evidence::{
    build_snapshot_policy_payload, list_operational_snapshots, payload_with_snapshot,
    persist_operational_snapshot, prune_operational_snapshots, verify_operational_snapshot,
};
#[path = "server_operator.rs"]
mod server_operator;
pub(crate) use server_operator::*;
#[path = "server_processes.rs"]
mod server_processes;
pub(crate) use server_processes::*;
#[path = "server_workbench.rs"]
mod server_workbench;
use server_workbench::*;
#[path = "server_detection.rs"]
mod server_detection;
use server_detection::*;
#[path = "server_api_handlers.rs"]
mod server_api_handlers;
use server_api_handlers::*;
pub(crate) use server_api_handlers::{
    base64_decode, read_body_limited, response_action_from_json, response_action_label,
    response_request_json, response_required_approvals, response_reversal_path,
};
#[path = "server_assistant.rs"]
mod server_assistant;
use server_assistant::*;
#[path = "server_support_helpers.rs"]
mod server_support_helpers;
pub(crate) use server_support_helpers::*;
#[path = "server_runtime.rs"]
mod server_runtime;
#[cfg(test)]
pub(crate) use server_runtime::spawn_test_server_with_state;
pub use server_runtime::{
    run_server, spawn_test_server, spawn_test_server_with_live_rollback_enabled,
    spawn_test_server_with_live_rollback_execution_enabled, spawn_test_server_with_seeded_alerts,
    spawn_test_server_with_seeded_remote_installs,
};
#[path = "server_core_helpers.rs"]
mod server_core_helpers;
pub(crate) use server_core_helpers::*;
#[path = "server_dynamic_routes.rs"]
mod server_dynamic_routes;
use server_dynamic_routes::handle_dynamic_api_route;
#[path = "server_views.rs"]
mod server_views;
use crate::server_response::{
    cors_origin, csv_response, error_json, json_response, safe_body, security_headers,
    text_response,
};
use crate::server_routing::{api_route_access, method_from_name};
use crate::sigma::SigmaEngine;
use crate::spool::EncryptedSpool;
use crate::storage::SharedStorage;
use crate::structured_log::generate_request_id;
use crate::support::{FailoverDrillRecord, InboxItem, ReportExecutionContext, SupportStore};
pub(crate) use server_views::*;
use sha2::Digest;

pub use crate::server_routing::{ApiRouteAccess, classify_api_route_access};

const FAILED_AUTH_TRACKER_STORAGE_KEY: &str = "server.failed_auth_tracker";

// ── Rate Limiter ────────────────────────────────────────────

struct RateLimiter {
    buckets: HashMap<String, (u64, u32)>, // IP -> (window_start_epoch, count)
    read_max_per_minute: u32,
    write_max_per_minute: u32,
    static_max_per_minute: u32,
    call_count: u64,
    last_cleanup: u64,
}

impl RateLimiter {
    fn new(read_max_per_minute: u32, write_max_per_minute: u32) -> Self {
        Self {
            buckets: HashMap::new(),
            read_max_per_minute,
            write_max_per_minute,
            static_max_per_minute: read_max_per_minute.saturating_mul(2),
            call_count: 0,
            last_cleanup: 0,
        }
    }

    fn check(&mut self, ip: &str, method: &Method, path: &str) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Periodic TTL-based cleanup: evict stale entries every 30 seconds
        self.call_count += 1;
        if now.saturating_sub(self.last_cleanup) >= 30 {
            self.buckets
                .retain(|_, (window_start, _)| now.saturating_sub(*window_start) < 120);
            self.last_cleanup = now;
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

        if limit == 0 {
            return true;
        }

        let entry = self
            .buckets
            .entry(format!("{ip}:{bucket_suffix}"))
            .or_insert((now, 0));
        if now.saturating_sub(entry.0) >= 60 {
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
pub(crate) struct AuditEntry {
    timestamp: String,
    method: String,
    path: String,
    source_ip: String,
    status_code: u16,
    auth_used: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
struct AuditLogPage {
    entries: Vec<AuditEntry>,
    total: usize,
    offset: usize,
    limit: usize,
    count: usize,
    has_more: bool,
}

#[derive(Debug, Clone, Copy)]
enum AuditStatusFilter {
    Exact(u16),
    Class(u16),
}

#[derive(Debug, Clone, Default)]
pub(crate) struct AuditLogFilter {
    query: Option<String>,
    method: Option<String>,
    status: Option<AuditStatusFilter>,
    auth_used: Option<bool>,
}

impl AuditLogFilter {
    pub(crate) fn from_query(query: &HashMap<String, String>) -> Self {
        Self {
            query: query
                .get("q")
                .map(|value| value.trim().to_ascii_lowercase())
                .filter(|value| !value.is_empty()),
            method: query
                .get("method")
                .map(|value| value.trim().to_ascii_uppercase())
                .filter(|value| !value.is_empty()),
            status: query
                .get("status")
                .and_then(|value| parse_audit_status_filter(value)),
            auth_used: query.get("auth").and_then(|value| parse_bool_query(value)),
        }
    }

    fn matches(&self, entry: &AuditEntry) -> bool {
        if let Some(method) = &self.method
            && !entry.method.eq_ignore_ascii_case(method)
        {
            return false;
        }

        if let Some(status_filter) = self.status {
            let status_matches = match status_filter {
                AuditStatusFilter::Exact(code) => entry.status_code == code,
                AuditStatusFilter::Class(class) => entry.status_code / 100 == class,
            };
            if !status_matches {
                return false;
            }
        }

        if let Some(auth_used) = self.auth_used
            && entry.auth_used != auth_used
        {
            return false;
        }

        if let Some(query) = &self.query {
            let auth_state = if entry.auth_used {
                "authenticated"
            } else {
                "anonymous"
            };
            let status_code = entry.status_code.to_string();
            let matches_query = entry.timestamp.to_ascii_lowercase().contains(query)
                || entry.method.to_ascii_lowercase().contains(query)
                || entry.path.to_ascii_lowercase().contains(query)
                || entry.source_ip.to_ascii_lowercase().contains(query)
                || status_code.contains(query)
                || auth_state.contains(query);
            if !matches_query {
                return false;
            }
        }

        true
    }
}

fn parse_audit_status_filter(value: &str) -> Option<AuditStatusFilter> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.len() == 3
        && normalized.ends_with("xx")
        && let Some(class) = normalized.chars().next().and_then(|ch| ch.to_digit(10))
        && (1..=5).contains(&class)
    {
        return Some(AuditStatusFilter::Class(class as u16));
    }

    normalized.parse::<u16>().ok().map(AuditStatusFilter::Exact)
}

fn parse_bool_query(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "authenticated" => Some(true),
        "0" | "false" | "no" | "anonymous" => Some(false),
        _ => None,
    }
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
            Ok(addr) if !addr.is_empty() => match std::net::UdpSocket::bind("0.0.0.0:0") {
                Ok(sock) => (Some(sock), Some(addr)),
                Err(_) => (None, None),
            },
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
            let severity = if status_code >= 500 {
                3
            } else if status_code >= 400 {
                4
            } else {
                6
            };
            let pri = 8 * 10 + severity; // facility=security(10)
            let msg = format!(
                "<{pri}>1 {timestamp} wardex wardex-audit - - - method={method} path={path} src={source_ip} status={status_code} auth={auth_used}"
            );
            let _ = sock.send_to(msg.as_bytes(), addr);
        }
    }

    fn recent(&self, limit: usize) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .rev()
            .take(limit)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect()
    }

    fn filtered_entries(&self, filter: &AuditLogFilter) -> Vec<AuditEntry> {
        self.entries
            .iter()
            .rev()
            .filter(|entry| filter.matches(entry))
            .cloned()
            .collect()
    }

    #[cfg(test)]
    fn page(&self, limit: usize, offset: usize) -> AuditLogPage {
        self.page_filtered(limit, offset, &AuditLogFilter::default())
    }

    fn page_filtered(&self, limit: usize, offset: usize, filter: &AuditLogFilter) -> AuditLogPage {
        let filtered = self.filtered_entries(filter);
        let total = filtered.len();
        let effective_offset = offset.min(total);
        let entries = filtered
            .into_iter()
            .skip(effective_offset)
            .take(limit)
            .collect::<Vec<_>>();
        let count = entries.len();
        AuditLogPage {
            entries,
            total,
            offset: effective_offset,
            limit,
            count,
            has_more: effective_offset.saturating_add(count) < total,
        }
    }
}

// ── Grouped sub-structures for AppState ──────────────────────────────────────

/// Authentication, RBAC, and session management sub-state.
#[allow(dead_code)]
struct AuthSystems {
    token: String,
    token_issued_at: std::time::Instant,
    rbac: RbacStore,
}

/// Detection engines and analytics sub-state.
#[allow(dead_code)]
struct DetectionSystems {
    detector: AnomalyDetector,
    velocity: VelocityDetector,
    entropy: EntropyDetector,
    compound: CompoundThreatDetector,
    slow_attack: crate::detector::SlowAttackDetector,
    sigma_engine: SigmaEngine,
    beacon_detector: crate::beacon::BeaconDetector,
    ueba_engine: crate::ueba::UebaEngine,
    kill_chain_analyzer: crate::kill_chain::KillChainAnalyzer,
    lateral_detector: crate::lateral::LateralMovementDetector,
    dns_analyzer: crate::dns_threat::DnsAnalyzer,
    side_channel: SideChannelDetector,
    ransomware: crate::ransomware::RansomwareDetector,
    container_detector: crate::container::ContainerDetector,
    ndr_engine: crate::ndr::NdrEngine,
    feed_engine: crate::feed_ingestion::FeedIngestionEngine,
    tuning_profile: crate::detector::TuningProfile,
    fp_feedback: crate::alert_analysis::FpFeedbackStore,
}

/// Fleet management, agents, and deployment sub-state.
#[allow(dead_code)]
struct FleetSystems {
    agent_registry: AgentRegistry,
    remote_deployments: HashMap<String, AgentDeployment>,
    deployment_store_path: String,
    update_manager: UpdateManager,
    lifecycle_manager: crate::agent_lifecycle::LifecycleManager,
    agent_logs: HashMap<String, Vec<crate::log_collector::LogRecord>>,
    agent_inventories: HashMap<String, crate::inventory::SystemInventory>,
}

/// SOC operations, case management, and response sub-state.
#[allow(dead_code)]
struct SocSystems {
    case_store: CaseStore,
    alert_queue: AlertQueue,
    incident_store: IncidentStore,
    approval_log: ApprovalLog,
    response_orchestrator: ResponseOrchestrator,
    playbook_engine: crate::playbook::PlaybookEngine,
    playbook_dsl: crate::playbook_dsl::PlaybookDslStore,
    live_response_engine: crate::live_response::LiveResponseEngine,
    remediation_engine: crate::remediation::RemediationEngine,
    escalation_engine: crate::escalation::EscalationEngine,
    workflow_store: crate::investigation::WorkflowStore,
}

/// Compliance, governance, and enterprise sub-state.
#[allow(dead_code)]
struct ComplianceSystems {
    compliance: ComplianceManager,
    multi_tenant: MultiTenantManager,
    privacy: PrivacyAccountant,
    enterprise: EnterpriseStore,
    feature_flags: FeatureFlagRegistry,
}

/// Observability, metrics, and audit sub-state.
#[allow(dead_code)]
struct ObservabilitySystems {
    rate_limiter: RateLimiter,
    audit_log: AuditLog,
    api_analytics: crate::api_analytics::ApiAnalytics,
    trace_collector: crate::telemetry::TraceCollector,
    request_count: u64,
    error_count: u64,
    alert_broadcaster: crate::ws_stream::AlertBroadcaster,
}

pub(crate) struct AppState {
    detector: AnomalyDetector,
    pub(crate) checkpoints: CheckpointStore,
    device: DeviceController,
    replay: ReplayBuffer,
    proofs: ProofRegistry,
    last_report: Option<JsonReport>,
    pub(crate) last_failover_drill: Option<FailoverDrillRecord>,
    pub(crate) token: String,
    token_issued_at: std::time::Instant,
    session_store: crate::auth::SessionStore,
    oidc_providers: HashMap<String, crate::oidc::OidcProvider>,
    user_preferences: UserPreferencesStore,
    pub(crate) swarm: SwarmNode,
    pub(crate) cluster: ClusterNode,
    enforcement: EnforcementEngine,
    pub(crate) threat_intel: ThreatIntelStore,
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
    pub(crate) config: Config,
    pub(crate) config_path: PathBuf,
    alerts: VecDeque<AlertRecord>,
    server_start: std::time::Instant,
    // XDR fleet management
    pub(crate) agent_registry: AgentRegistry,
    pub(crate) event_store: EventStore,
    clickhouse_store: Option<crate::storage_clickhouse::ClickHouseStorage>,
    policy_store: PolicyStore,
    pub(crate) update_manager: UpdateManager,
    pub(crate) remote_deployments: HashMap<String, AgentDeployment>,
    pub(crate) deployment_store_path: String,
    siem_connector: SiemConnector,
    taxii_client: crate::siem::TaxiiClient,
    // Local host telemetry (ring buffer, last 300 samples)
    local_telemetry: VecDeque<TelemetrySample>,
    pub(crate) local_host_info: HostInfo,
    // Cached host inventory (processes + sockets) refreshed by the monitor loop
    last_inventory: Option<crate::collector::HostInventory>,
    last_inventory_at_ms: u64,
    // Phase 21: advanced detectors
    velocity: VelocityDetector,
    entropy: EntropyDetector,
    compound: CompoundThreatDetector,
    // Phase 22: shutdown support
    pub(crate) shutdown: Arc<AtomicBool>,
    // Phase 25: rate limiter, audit, incidents, agent logs/inventory
    rate_limiter: RateLimiter,
    audit_log: AuditLog,
    incident_store: IncidentStore,
    pub(crate) agent_logs: HashMap<String, Vec<crate::log_collector::LogRecord>>,
    agent_logs_last_access: HashMap<String, u64>,
    pub(crate) agent_inventories: HashMap<String, crate::inventory::SystemInventory>,
    report_store: crate::report::ReportStore,
    pub(crate) support_store: SupportStore,
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
    pub(crate) enterprise: EnterpriseStore,
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
    pub(crate) storage: SharedStorage,
    // Phase 34: slow-attack & ransomware detectors
    slow_attack: crate::detector::SlowAttackDetector,
    ransomware: crate::ransomware::RansomwareDetector,
    // Phase 29: MITRE coverage, detection tuning, FP feedback
    mitre_coverage: crate::mitre_coverage::MitreCoverageTracker,
    tuning_profile: crate::detector::TuningProfile,
    fp_feedback: crate::alert_analysis::FpFeedbackStore,
    // Phase 42: advanced detection & inventory
    vulnerability_scanner: crate::vulnerability::VulnerabilityScanner,
    ndr_engine: crate::ndr::NdrEngine,
    container_detector: crate::container::ContainerDetector,
    cert_monitor: crate::cert_monitor::CertMonitor,
    config_drift_detector: crate::config_drift::ConfigDriftDetector,
    asset_inventory: crate::cloud_inventory::AssetInventory,
    efficacy_tracker: crate::detection_efficacy::EfficacyTracker,
    workflow_store: crate::investigation::WorkflowStore,
    llm_analyst: Arc<Mutex<crate::llm_analyst::LlmAnalyst>>,
    pub(crate) model_registry: crate::ml_engine::ModelRegistry,
    detection_feedback: crate::detection_feedback::DetectionFeedbackStore,
    // Phase 43: malware detection
    pub(crate) malware_hash_db: crate::malware_signatures::MalwareHashDb,
    malware_scanner: crate::malware_scanner::MalwareScanner,
    pub(crate) yara_engine: crate::yara_engine::YaraEngine,
    api_analytics: crate::api_analytics::ApiAnalytics,
    trace_collector: crate::telemetry::TraceCollector,
    // Phase 44: advanced threat analysis, inventory, malware, UX
    pub(crate) feed_engine: crate::feed_ingestion::FeedIngestionEngine,
    playbook_dsl: crate::playbook_dsl::PlaybookDslStore,
    image_inventory: crate::container_image::ImageInventory,
    quarantine_store: crate::quarantine::QuarantineStore,
    lifecycle_manager: crate::agent_lifecycle::LifecycleManager,
    decay_config: crate::ioc_decay::DecayConfig,
    // Phase 29: advanced detection engines
    dns_analyzer: crate::dns_threat::DnsAnalyzer,
    alert_broadcaster: crate::ws_stream::AlertBroadcaster,
    // Phase 46: extensible key-value store for webhooks etc.
    extra: HashMap<String, serde_json::Value>,
}

fn build_search_index_from_events(
    events: &[crate::event_forward::StoredEvent],
) -> Result<crate::search::SearchIndex, String> {
    let index = crate::search::SearchIndex::new("/tmp/wardex-search")?;
    for event in events {
        let mut fields = HashMap::new();
        fields.insert("timestamp".to_string(), event.alert.timestamp.clone());
        fields.insert("device_id".to_string(), event.alert.hostname.clone());
        fields.insert("event_class".to_string(), "alert".to_string());
        fields.insert("process_name".to_string(), event.alert.action.clone());
        fields.insert("command_line".to_string(), event.alert.reasons.join("; "));
        fields.insert("src_ip".to_string(), String::new());
        fields.insert("dst_ip".to_string(), String::new());
        fields.insert("user_name".to_string(), String::new());
        fields.insert(
            "raw_text".to_string(),
            format!(
                "{} {} {} {} {}",
                event.agent_id,
                event.alert.hostname,
                event.alert.action,
                event.alert.level,
                event.alert.reasons.join(" ")
            ),
        );
        index.index_event(fields)?;
    }
    let _ = index.commit()?;
    Ok(index)
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct AgentDeployment {
    pub(crate) agent_id: String,
    pub(crate) version: String,
    pub(crate) platform: String,
    pub(crate) mandatory: bool,
    pub(crate) release_notes: String,
    #[serde(default = "default_deployment_status")]
    pub(crate) status: String,
    pub(crate) status_reason: Option<String>,
    #[serde(default = "default_rollout_group")]
    pub(crate) rollout_group: String,
    #[serde(default)]
    pub(crate) allow_downgrade: bool,
    #[serde(default)]
    pub(crate) signature_status: Option<String>,
    #[serde(default)]
    pub(crate) signer_pubkey: Option<String>,
    #[serde(default)]
    pub(crate) signature_payload_sha256: Option<String>,
    #[serde(default)]
    pub(crate) update_counter: Option<u64>,
    pub(crate) assigned_at: String,
    pub(crate) acknowledged_at: Option<String>,
    pub(crate) completed_at: Option<String>,
    pub(crate) last_heartbeat_at: Option<String>,
}

#[derive(Debug, Default)]
pub(crate) struct EventQuery {
    agent_id: Option<String>,
    severity: Option<String>,
    reason: Option<String>,
    correlated: Option<bool>,
    triage_status: Option<String>,
    assignee: Option<String>,
    tag: Option<String>,
    limit: usize,
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
    let request_started = crate::api_analytics::ApiAnalytics::start_timer();
    // ── API versioning: /api/v1/... → /api/... ──────────────────
    let url = if let Some(stripped) = url.strip_prefix("/api/v1/") {
        format!("/api/{stripped}")
    } else {
        url.to_string()
    };
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

    // Check auth before consuming the request body. API routes are default-deny
    // unless they are explicitly public, agent-token, or cluster-token routes.
    let route_access = api_route_access(&method, route_path);
    let is_agent_endpoint = matches!(route_access, ApiRouteAccess::Agent);
    let is_cluster_endpoint = matches!(route_access, ApiRouteAccess::Cluster);

    // Up-front failed-auth lockout: if this IP or presented-token bucket has
    // been throttled by repeated failures, return 429 immediately for any
    // authenticated/agent/cluster route. Public routes are still served so
    // health checks survive.
    let auth_gated = is_agent_endpoint
        || is_cluster_endpoint
        || matches!(route_access, ApiRouteAccess::Authenticated);
    let presented_bearer_token = bearer_token(headers);
    let failed_auth_key = failed_auth_subject(remote_addr, presented_bearer_token.as_deref());
    if auth_gated
        && let Some(retry_after) = failed_auth_locked_request(remote_addr, &failed_auth_key)
    {
        return failed_auth_locked_response(retry_after);
    }

    // Agent endpoints require either a configured bearer token or production
    // mTLS posture. Development keeps legacy tokenless routes for local labs,
    // while production fails closed at startup and at request time.
    if is_agent_endpoint {
        let required_agent_token = std::env::var("WARDEX_AGENT_TOKEN")
            .ok()
            .filter(|token| !token.trim().is_empty());
        let (mtls_configured, mtls_verified) = {
            let s = crate::state_lock::tracked_lock(state, "server/agent_trust_config_check");
            let configured = s.config.security.require_mtls_agents
                && s.config
                    .security
                    .agent_ca_cert_path
                    .as_deref()
                    .is_some_and(|path| !path.trim().is_empty());
            (
                configured,
                configured && agent_mtls_request_trusted(headers, &s.config, remote_addr),
            )
        };
        let bound_agent_identity = route_path != "/api/agents/enroll"
            && agent_request_bound_to_agent(&method, &url, headers, body, state);
        let trust_configured = required_agent_token.is_some() || mtls_configured;
        if trust_configured || is_production_env() {
            let valid = required_agent_token.as_deref().is_some_and(|expected| {
                secure_token_eq(presented_bearer_token.as_deref(), expected)
            }) || mtls_verified
                || bound_agent_identity;
            if !valid {
                let lockout = failed_auth_record_request(remote_addr, &failed_auth_key);
                if !crate::server_auth::FailedAuthTracker::is_exempt(remote_addr) {
                    persist_failed_auth_tracker_snapshot_from_state(state);
                }
                if let Some(lockout) = lockout {
                    let mut s = crate::state_lock::tracked_lock(
                        state,
                        "server/failed_auth_agent_lockout_audit",
                    );
                    s.audit_log
                        .record("POST", "/api/_failed_auth", remote_addr, 429, false);
                    let _ = lockout; // recorded; audit entry above carries the signal
                }
                return respond_api(
                    state,
                    &method,
                    &url,
                    remote_addr,
                    false,
                    error_json(
                        "agent bearer identity or verified mTLS identity required",
                        401,
                    ),
                );
            }
            if is_production_env() && route_path != "/api/agents/enroll" && !bound_agent_identity {
                return respond_api(
                    state,
                    &method,
                    &url,
                    remote_addr,
                    false,
                    error_json("per-agent identity binding required", 401),
                );
            }
        }
    }

    if is_cluster_endpoint && !cluster_request_authorized(headers, state) {
        let lockout = failed_auth_record_request(remote_addr, &failed_auth_key);
        if !crate::server_auth::FailedAuthTracker::is_exempt(remote_addr) {
            persist_failed_auth_tracker_snapshot_from_state(state);
        }
        if let Some(_lockout) = lockout {
            let mut s =
                crate::state_lock::tracked_lock(state, "server/failed_auth_cluster_lockout_audit");
            s.audit_log
                .record("POST", "/api/_failed_auth", remote_addr, 429, false);
        }
        return respond_api(
            state,
            &method,
            &url,
            remote_addr,
            false,
            error_json("cluster token required", 401),
        );
    }

    let needs_auth = matches!(route_access, ApiRouteAccess::Authenticated);

    let auth_identity = authenticate_request(headers, state);
    if needs_auth && !auth_identity.is_authenticated() {
        let lockout = failed_auth_record_request(remote_addr, &failed_auth_key);
        if !crate::server_auth::FailedAuthTracker::is_exempt(remote_addr) {
            persist_failed_auth_tracker_snapshot_from_state(state);
        }
        if let Some(_lockout) = lockout {
            let mut s =
                crate::state_lock::tracked_lock(state, "server/failed_auth_user_lockout_audit");
            s.audit_log
                .record("POST", "/api/_failed_auth", remote_addr, 429, false);
        }
        return respond_api(
            state,
            &method,
            &url,
            remote_addr,
            false,
            error_json("unauthorized", 401),
        );
    }

    if needs_auth && !csrf_request_authorized(headers, &auth_identity, &method) {
        return respond_api(
            state,
            &method,
            &url,
            remote_addr,
            true,
            error_json("csrf token required", 403),
        );
    }

    // Reset the failed-auth counter on any successful authenticated request so
    // legitimate clients aren't penalised after a single bad attempt.
    if auth_identity.is_authenticated() && failed_auth_clear_request(remote_addr, &failed_auth_key)
    {
        persist_failed_auth_tracker_snapshot_from_state(state);
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
            let s = crate::state_lock::tracked_lock(state, "server/api_auth_check");
            let ttl = s.config.security.token_ttl_secs;
            let elapsed = s.token_issued_at.elapsed().as_secs();
            let remaining = if ttl > 0 {
                ttl.saturating_sub(elapsed)
            } else {
                0
            };
            let body = format!(
                r#"{{"status":"ok","ttl_secs":{ttl},"remaining_secs":{remaining},"token_age_secs":{elapsed}}}"#
            );
            json_response(&body, 200)
        }
        (Method::Post, "/api/auth/rotate") => {
            let new_token = generate_token();
            let mut s = crate::state_lock::tracked_lock(state, "server/api_auth_rotate");
            let old_token_prefix = s.token.chars().take(8).collect::<String>();
            s.token = new_token.clone();
            s.token_issued_at = std::time::Instant::now();
            s.audit_log
                .record("POST", "/api/auth/rotate", "admin", 200, true);
            let body = format!(
                r#"{{"status":"rotated","new_token":"{new_token}","previous_prefix":"{old_token_prefix}…"}}"#
            );
            json_response(&body, 200)
        }
        (Method::Get, "/api/session/info") => {
            let s = crate::state_lock::tracked_lock(state, "server/api_session_info");
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
        (Method::Get, "/api/user/preferences") => {
            let prefs = {
                let s = crate::state_lock::tracked_lock(state, "server/api_user_preferences_get");
                s.user_preferences.get(auth_identity.actor())
            };
            match serde_json::to_string_pretty(&prefs) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Put, "/api/user/preferences") => match read_body_limited(body, 64 * 1024) {
            Ok(raw) => match serde_json::from_str::<UserPreferencesPatch>(&raw) {
                Ok(patch) => {
                    let result = {
                        let mut s = crate::state_lock::tracked_lock(
                            state,
                            "server/api_user_preferences_put",
                        );
                        s.user_preferences.upsert(auth_identity.actor(), patch)
                    };
                    match result {
                        Ok(prefs) => match serde_json::to_string_pretty(&prefs) {
                            Ok(json) => json_response(&json, 200),
                            Err(e) => error_json(&format!("serialization error: {e}"), 500),
                        },
                        Err(e) => error_json(&e, 400),
                    }
                }
                Err(e) => error_json(&format!("invalid JSON: {e}"), 400),
            },
            Err(e) => error_json(&e, 400),
        },
        (Method::Get, "/api/status") => {
            let manifest = runtime::status_manifest();
            match serde_json::to_string_pretty(&manifest) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/report") => {
            let s = crate::state_lock::tracked_lock(state, "server/api_report_get");
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
        (Method::Post, "/api/graphql") => match read_body_limited(body, 100_000) {
            Err(_) => error_json("request too large", 413),
            Ok(body) => match serde_json::from_str::<GqlRequest>(&body) {
                Err(e) => error_json(&format!("invalid JSON: {e}"), 400),
                Ok(gql_req) => {
                    let mut executor = GqlExecutor::new(wardex_schema());
                    let st = state.clone();
                    executor.register_resolver("alerts", Box::new({
                            let st = st.clone();
                            move |args| {
                                let s = st.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                                let limit = args.get("limit").and_then(serde_json::Value::as_u64).unwrap_or(50).min(1000) as usize;
                                let alerts: Vec<serde_json::Value> = s.alerts.iter().take(limit).enumerate().map(|(i, a)| {
                                    serde_json::json!({ "id": format!("alert-{i}"), "level": a.level, "timestamp": a.timestamp, "device_id": a.hostname, "score": a.score, "reasons": a.reasons, "status": "open" })
                                }).collect();
                                serde_json::json!(alerts)
                            }
                        }));
                    executor.register_resolver("agents", Box::new({
                            let st = st.clone();
                            move |_args| {
                                let s = st.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                                let agents: Vec<serde_json::Value> = s.agent_registry.list().iter().map(|a| {
                                    serde_json::json!({ "id": a.id, "hostname": a.hostname, "os": a.platform, "version": a.version, "status": format!("{:?}", a.status), "last_heartbeat": a.last_seen })
                                }).collect();
                                serde_json::json!(agents)
                            }
                        }));
                    executor.register_resolver("status", Box::new({
                            let st = st.clone();
                            move |_args| {
                                let s = st.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                                let online = s.agent_registry.list().iter().filter(|a| a.status == crate::enrollment::AgentStatus::Online).count();
                                let open_incidents = s.incident_store.list().iter().filter(|i| !matches!(i.status, crate::incident::IncidentStatus::Resolved | crate::incident::IncidentStatus::FalsePositive)).count();
                                serde_json::json!({ "version": env!("CARGO_PKG_VERSION"), "uptime_secs": s.server_start.elapsed().as_secs_f64(), "agents_online": online, "alerts_total": s.alerts.len(), "incidents_open": open_incidents })
                            }
                        }));
                    executor.register_resolver("events", Box::new({
                            let st = st.clone();
                            move |args| {
                                let s = st.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                                let limit = args.get("limit").and_then(serde_json::Value::as_u64).unwrap_or(100).min(1000) as usize;
                                let events: Vec<serde_json::Value> = s.event_store.recent_events(limit).iter().map(|e| {
                                    serde_json::json!({ "timestamp": e.received_at, "device_id": e.agent_id, "event_type": e.alert.level, "data": e.alert.reasons })
                                }).collect();
                                serde_json::json!(events)
                            }
                        }));
                    executor.register_resolver("hunts", Box::new({
                            let st = st.clone();
                            move |args| {
                                let s = st.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                                let limit = args.get("limit").and_then(serde_json::Value::as_u64).unwrap_or(20).min(1000) as usize;
                                let hunts: Vec<serde_json::Value> = s.enterprise.hunts().iter().take(limit).map(|h| {
                                    serde_json::json!({ "id": h.id, "name": h.name, "status": if h.enabled { "active" } else { "disabled" }, "matches": 0, "created_at": h.created_at })
                                }).collect();
                                serde_json::json!(hunts)
                            }
                        }));
                    executor.register_resolver(
                        "aggregate",
                        Box::new({
                            let st = st.clone();
                            move |args| {
                                let s =
                                    st.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
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
                        }),
                    );
                    let resp = executor.execute(&gql_req);
                    let result_body = serde_json::to_string(&resp).unwrap_or_else(|_| {
                        r#"{"errors":[{"message":"serialization failed"}]}"#.to_string()
                    });
                    json_response(&result_body, 200)
                }
            },
        },
        (Method::Post, "/api/analyze") => handle_analyze(body, state),
        (Method::Post, "/api/control/mode") => handle_mode(body, state),
        (Method::Post, "/api/control/reset-baseline") => {
            let mut s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            s.detector.reset_baseline();
            json_response(r#"{"status":"baseline reset"}"#, 200)
        }
        (Method::Post, "/api/control/checkpoint") => {
            let mut s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let mut s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        (Method::Post, "/api/control/failover-drill") => run_failover_drill(state, &auth_identity),
        (Method::Get, "/api/cluster/health") => crate::server_cluster::handle_cluster_health(state),
        (Method::Post, "/api/cluster/vote") => {
            crate::server_cluster::handle_cluster_vote(body, state)
        }
        (Method::Post, "/api/cluster/append") => {
            crate::server_cluster::handle_cluster_append(body, state)
        }
        (Method::Post, "/api/cluster/snapshot") => {
            crate::server_cluster::handle_cluster_snapshot(body, state)
        }
        (Method::Get, "/api/checkpoints") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let result = correlation::analyze(&s.replay, 0.8);
            match serde_json::to_string_pretty(&result) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/correlation/campaigns") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let events = s.event_store.all_events().to_vec();
            drop(s);
            let view = build_campaign_correlation_view(&events);
            match serde_json::to_string_pretty(&view) {
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                    let mut s = state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let report = s.swarm.health_report();
            match serde_json::to_string_pretty(&report) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Post, "/api/fleet/register") => {
            crate::server_fleet::handle_fleet_register(body, state)
        }

        // ── Enforcement ───────────────────────────────────────────
        (Method::Get, "/api/enforcement/status") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let tpm_status = s.enforcement.tpm.status();
            let recent_history: Vec<_> = s
                .enforcement
                .history()
                .iter()
                .rev()
                .take(8)
                .map(|entry| {
                    serde_json::json!({
                        "action": entry.action,
                        "success": entry.success,
                        "detail": entry.detail,
                        "rollback_command": entry.rollback_command,
                    })
                })
                .collect();
            let info = serde_json::json!({
                "process_enforcer": "active",
                "network_enforcer": "active",
                "filesystem_enforcer": "active",
                "tpm": tpm_status,
                "topology_nodes": s.enforcement.topology.nodes.len(),
                "history_len": s.enforcement.history().len(),
                "recent_history": recent_history,
            });
            json_response(&info.to_string(), 200)
        }
        (Method::Post, "/api/enforcement/quarantine") => {
            handle_enforcement_quarantine(body, state, &auth_identity, remote_addr)
        }

        // ── Threat Intelligence ───────────────────────────────────
        (Method::Get, "/api/threat-intel/status") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let info = serde_json::json!({
                "ioc_count": s.threat_intel.ioc_count(),
            });
            json_response(&info.to_string(), 200)
        }
        (Method::Get, "/api/threat-intel/library") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut iocs = s.threat_intel.all_iocs();
            iocs.sort_by(|left, right| {
                right
                    .last_seen
                    .cmp(&left.last_seen)
                    .then_with(|| left.value.cmp(&right.value))
            });
            let mut feeds = s.threat_intel.feeds().to_vec();
            feeds.sort_by(|left, right| {
                right
                    .last_updated
                    .cmp(&left.last_updated)
                    .then_with(|| left.name.cmp(&right.name))
            });
            let recent_matches: Vec<_> = s
                .threat_intel
                .match_history()
                .iter()
                .rev()
                .take(20)
                .cloned()
                .collect();
            let info = serde_json::json!({
                "count": iocs.len(),
                "iocs": iocs,
                "feeds": feeds,
                "recent_matches": recent_matches,
            });
            json_response(&info.to_string(), 200)
        }
        (Method::Get, "/api/threat-intel/library/v2") => handle_threat_intel_library_v2(state),
        (Method::Get, "/api/threat-intel/sightings") => handle_threat_intel_sightings(&url, state),
        (Method::Post, "/api/threat-intel/ioc") => handle_threat_intel_ioc(body, state),

        // ── Threat Intel Stats ────────────────────────────────────
        (Method::Get, "/api/threat-intel/stats") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let stats = s.threat_intel.enrichment_stats();
            match serde_json::to_string(&stats) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }

        // ── IoC Purge (TTL-based) ─────────────────────────────────
        (Method::Post, "/api/threat-intel/purge") => match read_body_limited(body, 4096) {
            Err(e) => error_json(&e, 400),
            Ok(body) => match serde_json::from_str::<serde_json::Value>(&body) {
                Err(e) => error_json(&format!("invalid JSON: {e}"), 400),
                Ok(parsed) => {
                    let ttl_days = parsed
                        .get("ttl_days")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(90);
                    let now = chrono::Utc::now().to_rfc3339();
                    let mut s = state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let purged = s.threat_intel.purge_expired(&now, ttl_days);
                    json_response(
                        &format!(r#"{{"purged":{purged},"ttl_days":{ttl_days}}}"#),
                        200,
                    )
                }
            },
        },

        // ── MITRE ATT&CK Coverage ────────────────────────────────
        (Method::Get, "/api/mitre/coverage") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let summary = s.mitre_coverage.summary();
            match serde_json::to_string(&summary) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/mitre/heatmap") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let heatmap = s.mitre_coverage.heatmap();
            match serde_json::to_string(&heatmap) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }

        // ── Detection Tuning Profile ──────────────────────────────
        (Method::Get, "/api/detection/profile") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let profile = s.tuning_profile;
            json_response(
                &format!(
                    r#"{{"profile":"{}","description":"{}","threshold_multiplier":{:.2},"learn_threshold":{:.1}}}"#,
                    profile.as_str(),
                    profile.description(),
                    profile.threshold_multiplier(),
                    profile.learn_threshold()
                ),
                200,
            )
        }
        (Method::Put, "/api/detection/profile") => match read_body_limited(body, 4096) {
            Err(e) => error_json(&e, 400),
            Ok(body) => match serde_json::from_str::<serde_json::Value>(&body) {
                Err(e) => error_json(&format!("invalid JSON: {e}"), 400),
                Ok(parsed) => {
                    let name = parsed.get("profile").and_then(|v| v.as_str()).unwrap_or("");
                    match crate::detector::TuningProfile::parse(name) {
                        Some(p) => {
                            let mut s = state
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            s.tuning_profile = p;
                            json_response(
                                &format!(r#"{{"profile":"{}","applied":true}}"#, p.as_str()),
                                200,
                            )
                        }
                        None => {
                            error_json("invalid profile: use aggressive, balanced, or quiet", 400)
                        }
                    }
                }
            },
        },

        // ── False-Positive Feedback ───────────────────────────────
        (Method::Post, "/api/fp-feedback") => match read_body_limited(body, 4096) {
            Err(e) => error_json(&e, 400),
            Ok(body) => match serde_json::from_str::<crate::alert_analysis::FpFeedback>(&body) {
                Err(e) => error_json(&format!("invalid feedback: {e}"), 400),
                Ok(feedback) => {
                    let mut s = state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    s.fp_feedback.record(feedback);
                    json_response(r#"{"recorded":true}"#, 200)
                }
            },
        },
        (Method::Get, "/api/fp-feedback/stats") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let stats = s.fp_feedback.stats();
            let json_stats: Vec<serde_json::Value> = stats
                .iter()
                .map(|(p, total, fps, ratio)| {
                    serde_json::json!({
                        "pattern": p,
                        "total_marked": total,
                        "false_positives": fps,
                        "fp_ratio": ratio,
                        "suppression_weight": s.fp_feedback.suppression_weight(p),
                    })
                })
                .collect();
            match serde_json::to_string(&json_stats) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/detection/trust/overview") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            json_response(&build_detection_trust_overview(&s).to_string(), 200)
        }
        (Method::Get, "/api/detection/tuning/feedback") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            json_response(&build_detection_tuning_feedback(&s).to_string(), 200)
        }
        (Method::Get, "/api/detection/trust/rules") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            json_response(&build_detection_trust_rules(&s).to_string(), 200)
        }
        (Method::Get, path) if path.starts_with("/api/detection/trust/rules/") => {
            let rule_id = path
                .trim_start_matches("/api/detection/trust/rules/")
                .trim();
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            json_response(
                &build_detection_trust_rule_detail(&s, rule_id).to_string(),
                200,
            )
        }
        (Method::Get, "/api/detection/trust/tuning-drafts") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            json_response(
                &serde_json::json!({
                    "generated_at": chrono::Utc::now().to_rfc3339(),
                    "draft_only_tuning": true,
                    "auto_apply": false,
                    "drafts": detection_trust_drafts(&s),
                })
                .to_string(),
                200,
            )
        }
        (Method::Post, "/api/detection/trust/tuning-drafts") => {
            match read_json_value(body, 16 * 1024) {
                Err(e) => error_json(&e, 400),
                Ok(parsed) => {
                    let s = state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let draft = create_detection_trust_draft_from_body(&s, &parsed);
                    json_response(
                    &serde_json::json!({
                        "created": true,
                        "draft": draft,
                        "auto_apply": false,
                        "guardrail": "Draft created for operator review only; no production tuning changed.",
                    })
                    .to_string(),
                    200,
                )
                }
            }
        }
        (Method::Post, path)
            if path.starts_with("/api/detection/trust/tuning-drafts/")
                && path.ends_with("/preview") =>
        {
            let draft_id = path
                .trim_start_matches("/api/detection/trust/tuning-drafts/")
                .trim_end_matches("/preview")
                .trim_matches('/');
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            json_response(
                &build_detection_trust_draft_preview(&s, draft_id).to_string(),
                200,
            )
        }
        (Method::Post, path)
            if path.starts_with("/api/detection/trust/tuning-drafts/")
                && path.ends_with("/approve") =>
        {
            let draft_id = path
                .trim_start_matches("/api/detection/trust/tuning-drafts/")
                .trim_end_matches("/approve")
                .trim_matches('/');
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let preview = build_detection_trust_draft_preview(&s, draft_id);
            json_response(
                &serde_json::json!({
                    "approved": true,
                    "draft_id": draft_id,
                    "applied": false,
                    "auto_apply": false,
                    "application_mode": "manual_operator_apply_required",
                    "preview": preview,
                    "rollback_path": "Production tuning is unchanged. If operators apply the suggested suppression or threshold later, rollback by expiring/removing that specific tuning object.",
                    "guardrail": "Approval records operator intent but does not silently weaken production detections.",
                })
                .to_string(),
                200,
            )
        }
        (Method::Post, "/api/alerts/feedback") => match read_json_value(body, 16 * 1024) {
            Err(e) => error_json(&e, 400),
            Ok(parsed) => {
                let state_value = parsed
                    .get("state")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("needs_more_data")
                    .trim();
                let normalized_state = normalize_detection_outcome(state_value);
                let reason_pattern = parsed
                    .get("reason")
                    .or_else(|| parsed.get("reason_pattern"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("operator_feedback")
                    .trim()
                    .to_string();
                let feedback = crate::alert_analysis::FpFeedback {
                    alert_fingerprint: parsed
                        .get("alert_id")
                        .or_else(|| parsed.get("alert_fingerprint"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("latest")
                        .to_string(),
                    marked_fp: detection_outcome_is_noise(normalized_state),
                    analyst: parsed
                        .get("analyst")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_else(|| auth_identity.actor())
                        .to_string(),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    reason_pattern: reason_pattern.clone(),
                };
                let summary = {
                    let mut s = state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    s.fp_feedback.record(feedback);
                    if let Some(rule_id) = parsed
                        .get("rule_id")
                        .and_then(serde_json::Value::as_str)
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                    {
                        let _ = s.detection_feedback.record(
                            parsed.get("event_id").and_then(serde_json::Value::as_u64),
                            parsed
                                .get("alert_id")
                                .and_then(serde_json::Value::as_str)
                                .map(str::to_string),
                            Some(rule_id.to_string()),
                            parsed
                                .get("analyst")
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or_else(|| auth_identity.actor())
                                .to_string(),
                            normalized_state.to_string(),
                            Some(reason_pattern.clone()),
                            parsed
                                .get("note")
                                .or_else(|| parsed.get("notes"))
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or("")
                                .to_string(),
                            Vec::new(),
                        );
                    }
                    alert_feedback_summary(&s)
                };
                json_response(
                    &serde_json::json!({
                        "recorded": true,
                        "state": normalized_state,
                        "summary": summary,
                        "auto_tuning": false,
                    })
                    .to_string(),
                    200,
                )
            }
        },
        (Method::Get, "/api/alerts/feedback/summary") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            json_response(&alert_feedback_summary(&s).to_string(), 200)
        }
        (Method::Get, "/api/alerts/evidence-chain") => {
            let alert_id =
                url_param(&url, "alert_id").and_then(|value| value.parse::<usize>().ok());
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            json_response(&alert_evidence_chain_payload(&s, alert_id).to_string(), 200)
        }
        (Method::Get, "/api/operator/workspaces") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = serde_json::json!({
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "roles": [
                    {"id": "soc_analyst", "label": "SOC Analyst", "default_route": "/admin/soc"},
                    {"id": "detection_engineer", "label": "Detection Engineer", "default_route": "/admin/detection-lab"},
                    {"id": "incident_commander", "label": "Incident Commander", "default_route": "/admin/response-safety"},
                    {"id": "platform_operator", "label": "Platform Operator", "default_route": "/admin/operations-health"},
                    {"id": "auditor", "label": "Auditor", "default_route": "/admin/reports"}
                ],
                "navigation_groups": ["Overview", "Analyze", "Detect", "Respond", "Operate", "Govern", "Support"],
                "active_routes": ["/admin/detection-lab", "/admin/response-safety", "/admin/integrations", "/admin/operations-health", "/admin/malware"],
                "snapshots": {
                    "detection_lab": build_detection_lab_payload(&s),
                    "response_safety": response_safety_payload(&s),
                    "integrations": integrations_marketplace_payload(&s),
                    "operations": operations_health_payload(&s),
                    "malware": malware_explanation_payload(&s),
                }
            });
            json_response(&body.to_string(), 200)
        }
        (Method::Post, "/api/detection-lab/runs") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = build_detection_lab_payload(&s);
            let snapshot = persist_operational_snapshot(&s.storage, "detection_lab_run", &body);
            json_response(
                &serde_json::json!({
                    "status": "completed",
                    "mode": "dry_run_validation",
                    "run": body,
                    "snapshot": snapshot,
                })
                .to_string(),
                200,
            )
        }
        (
            Method::Get,
            "/api/detection-lab/status"
            | "/api/detection-lab/history"
            | "/api/detection-lab/report",
        ) => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            json_response(&build_detection_lab_payload(&s).to_string(), 200)
        }
        (Method::Get, "/api/response/safety") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            json_response(&response_safety_payload(&s).to_string(), 200)
        }
        (Method::Post, "/api/response/preview") => response_preview_from_body(body),
        (Method::Post, "/api/response/verify") => response_verify_from_body(body),
        (Method::Get, "/api/integrations/marketplace") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            json_response(&integrations_marketplace_payload(&s).to_string(), 200)
        }
        (Method::Post, "/api/integrations/validate") => match read_json_value(body, 16 * 1024) {
            Err(e) => error_json(&e, 400),
            Ok(parsed) => {
                let provider = parsed
                    .get("provider")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("generic_syslog");
                let s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                json_response(
                    &integration_validation_payload(&s, provider).to_string(),
                    200,
                )
            }
        },
        (Method::Get, "/api/integrations/sample-event") => {
            let provider = url_param(&url, "provider").unwrap_or_else(|| "generic_syslog".into());
            json_response(&sample_event_for_connector(&provider).to_string(), 200)
        }
        (Method::Get, "/api/operations/health") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            json_response(&operations_health_payload(&s).to_string(), 200)
        }
        (Method::Get, "/api/operations/health/snapshot") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = operations_health_payload(&s);
            let snapshot = persist_operational_snapshot(&s.storage, "operations_health", &body);
            json_response(
                &serde_json::json!({"snapshot": snapshot, "health": body}).to_string(),
                200,
            )
        }
        (Method::Get, "/api/malware/explain") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            json_response(&malware_explanation_payload(&s).to_string(), 200)
        }
        (Method::Get, "/api/malware/scan-diff") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            json_response(
                &serde_json::json!({
                    "generated_at": chrono::Utc::now().to_rfc3339(),
                    "status": "ready",
                    "baseline": malware_explanation_payload(&s),
                    "comparison": {
                        "verdict_changed": false,
                        "confidence_delta": 0.0,
                        "new_matches": [],
                        "cleared_matches": [],
                        "rootkit_delta": "no repeated scan selected",
                    },
                    "next_action": "Run two scans of the same target to compare verdict, confidence, matches, hash, rootkit findings, and skipped checks.",
                })
                .to_string(),
                200,
            )
        }

        // ── Normalized Score ──────────────────────────────────────
        (Method::Get, "/api/detection/score/normalize") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let mut devices: Vec<_> = s.digital_twin.all_snapshots().values().cloned().collect();
            devices.sort_by(|left, right| left.device_id.cmp(&right.device_id));
            let devices: Vec<_> = devices
                .into_iter()
                .map(|snapshot| {
                    serde_json::json!({
                        "device_id": snapshot.device_id,
                        "state": format!("{:?}", snapshot.state),
                        "cpu_load": snapshot.cpu_load,
                        "memory_used_mb": snapshot.memory_used_mb,
                        "open_connections": snapshot.open_connections,
                        "processes": snapshot.processes,
                        "threat_score": snapshot.threat_score,
                        "uptime_secs": snapshot.uptime_secs,
                    })
                })
                .collect();
            let info = serde_json::json!({
                "twin_count": s.digital_twin.device_count(),
                "devices": devices,
            });
            json_response(&info.to_string(), 200)
        }
        (Method::Post, "/api/digital-twin/simulate") => handle_digital_twin_simulate(body, state),

        // ── Compliance ────────────────────────────────────────────
        (Method::Get, "/api/compliance/status") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let report = s.compliance.report(&crate::compliance::Framework::Iec62443);
            match serde_json::to_string_pretty(&report) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }

        // ── Energy ────────────────────────────────────────────────
        (Method::Get, "/api/energy/status") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let info = serde_json::json!({
                "current_epoch": s.key_rotation.current_epoch(),
                "total_epochs": s.key_rotation.epochs().len(),
            });
            json_response(&info.to_string(), 200)
        }
        (Method::Post, "/api/quantum/rotate") => {
            let mut s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            s.key_rotation.rotate();
            let info = serde_json::json!({
                "status": "rotated",
                "new_epoch": s.key_rotation.current_epoch(),
            });
            json_response(&info.to_string(), 200)
        }

        // ── Privacy ───────────────────────────────────────────────
        (Method::Get, "/api/privacy/budget") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let info = serde_json::json!({
                "trained": s.fingerprint.is_some(),
                "replay_samples": s.replay.len(),
            });
            json_response(&info.to_string(), 200)
        }

        // ── Adversarial Harness ───────────────────────────────────
        (Method::Post, "/api/harness/run") => handle_harness_run(body, state),

        // ── Temporal-Logic Monitor ────────────────────────────────
        (Method::Get, "/api/monitor/status") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let report = s.deception.report();
            let mut decoys: Vec<_> = s
                .deception
                .decoys()
                .iter()
                .map(|decoy| {
                    let avg_threat_score = if decoy.interactions.is_empty() {
                        0.0_f32
                    } else {
                        decoy
                            .interactions
                            .iter()
                            .map(|interaction| interaction.threat_score)
                            .sum::<f32>()
                            / decoy.interactions.len() as f32
                    };
                    serde_json::json!({
                        "id": decoy.id,
                        "decoy_type": format!("{:?}", decoy.decoy_type),
                        "name": decoy.name,
                        "description": decoy.description,
                        "deployed": decoy.deployed,
                        "interaction_count": decoy.interactions.len(),
                        "avg_threat_score": avg_threat_score,
                        "fingerprint": decoy.fingerprint,
                        "last_interaction": decoy.interactions.last(),
                    })
                })
                .collect();
            decoys.sort_by(|left, right| {
                let left_name = left
                    .get("name")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default();
                let right_name = right
                    .get("name")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default();
                left_name.cmp(right_name)
            });
            let info = serde_json::json!({
                "total_decoys": report.total_decoys,
                "active_decoys": report.active_decoys,
                "total_interactions": report.total_interactions,
                "high_threat_interactions": report.high_threat_interactions,
                "attacker_profiles": report.attacker_profiles,
                "decoys": decoys,
            });
            json_response(&info.to_string(), 200)
        }
        (Method::Post, "/api/deception/deploy") => handle_deception_deploy(body, state),

        // ── Policy Composition ────────────────────────────────────
        (Method::Post, "/api/policy/compose") => handle_policy_compose(body, state),

        // ── Drift Detection ───────────────────────────────────────
        (Method::Get, "/api/drift/status") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let info = serde_json::json!({
                "sample_count": s.drift.sample_count(),
            });
            json_response(&info.to_string(), 200)
        }
        (Method::Post, "/api/drift/reset") => {
            let mut s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            s.drift.reset();
            json_response(r#"{"status":"drift detector reset"}"#, 200)
        }

        // ── Causal Analysis ───────────────────────────────────────
        (Method::Get, "/api/causal/graph") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let info = serde_json::json!({
                "node_count": s.causal.node_count(),
                "edge_count": s.causal.edge_count(),
            });
            json_response(&info.to_string(), 200)
        }

        // ── Patch Management ──────────────────────────────────────
        (Method::Get, "/api/patches") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let info = serde_json::json!({
                "tls_enabled": s.listener_mode.is_tls(),
                "scheme": s.listener_mode.scheme(),
                "port": s.listener_mode.port(),
            });
            json_response(&info.to_string(), 200)
        }

        // ── Mesh Health / Self-Healing ────────────────────────────
        (Method::Get, "/api/mesh/health") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let mut s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let mut s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match serde_json::to_string_pretty(&s.config) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Post, "/api/config/reload") => handle_config_reload(body, state),
        (Method::Post, "/api/config/save") => match read_body_limited(body, 10 * 1024 * 1024) {
            Ok(body) => {
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let config_path = s.config_path.clone();
                match config_save_target(&s.config, &body) {
                    Ok((next_config, applied_fields)) => {
                        if let Err(e) = persist_config_to_path(&next_config, &config_path) {
                            error_json(&e, 500)
                        } else {
                            s.config = next_config.clone();
                            s.cluster = ClusterNode::new(next_config.cluster.clone());
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
                    Err(response) => *response,
                }
            }
            Err(e) => error_json(&e, 400),
        },

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
        (Method::Get, "/api/healthz/live") => json_response(r#"{"status":"alive"}"#, 200),
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
        (Method::Get, "/api/fleet/health") => {
            let s = match state.lock() {
                Ok(g) => g,
                Err(e) => e.into_inner(),
            };
            let agents = s.agent_registry.list();
            let heartbeat_interval = s.agent_registry.heartbeat_interval();
            let local_agent = local_console_identity(&s);
            let total_agents = agents.len() + 1;
            let online = agents
                .iter()
                .filter(|agent| computed_agent_status(agent, heartbeat_interval).0 == "online")
                .count();
            let local_online =
                usize::from(computed_agent_status(&local_agent, heartbeat_interval).0 == "online");
            let stale = total_agents.saturating_sub(online + local_online);
            let logs_tracked = s.agent_logs.len();
            let inventories_tracked = s.agent_inventories.len() + 1;
            json_response(
                &serde_json::json!({
                    "total_agents": total_agents,
                    "online": online + local_online,
                    "stale": stale,
                    "logs_tracked": logs_tracked,
                    "inventories_tracked": inventories_tracked,
                })
                .to_string(),
                200,
            )
        }
        (Method::Get, "/api/openapi.json") => {
            let openapi_public = {
                let s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                s.config.server.openapi_public
            };
            if is_production_env() && !openapi_public && !auth_identity.is_authenticated() {
                return respond_api(
                    state,
                    &method,
                    &url,
                    remote_addr,
                    false,
                    error_json("openapi endpoint requires authentication", 401),
                );
            }
            json_response(
                &crate::openapi::openapi_json(env!("CARGO_PKG_VERSION")),
                200,
            )
        }
        (Method::Get, "/api/metrics") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // Optional bearer-token gate (config.server.metrics_bearer_token).
            // When the token is set, the client must present a matching
            // `Authorization: Bearer <token>` header; otherwise the endpoint
            // is public (legacy behaviour preserved for drop-in deployments).
            if let Some(expected) = s
                .config
                .server
                .metrics_bearer_token
                .as_deref()
                .filter(|t| !t.is_empty())
            {
                let provided = bearer_token(headers);
                let ok = matches!(&provided, Some(t) if {
                    let a = t.as_bytes();
                    let b = expected.as_bytes();
                    if a.len() != b.len() {
                        false
                    } else {
                        let mut diff = 0u8;
                        for (x, y) in a.iter().zip(b.iter()) {
                            diff |= x ^ y;
                        }
                        diff == 0
                    }
                });
                if !ok {
                    return respond_api(
                        state,
                        &method,
                        &url,
                        remote_addr,
                        false,
                        error_json("metrics endpoint requires bearer token", 401),
                    );
                }
            }
            text_response(&prometheus_metrics_payload(&s), 200)
        }
        (Method::Get, "/api/slo/status") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let mut s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        (Method::Get, "/api/alerts/page") => {
            let (cursor, limit) = parse_cursor_page_params(&url, 100, 1000);
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = alert_cursor_page_payload(&s, cursor, limit);
            json_response(&body.to_string(), 200)
        }
        (Method::Get, "/api/alerts") => {
            let query = parse_query_string(&url);
            let limit = query
                .get("limit")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(100)
                .min(1_000);
            let offset = query
                .get("offset")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0)
                .min(100_000);
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let alerts_vec: Vec<_> = s.alerts.iter().cloned().collect();
            match recent_alerts_json(
                &alerts_vec,
                limit,
                offset,
                &s.local_host_info.hostname,
                &s.process_tree,
            ) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&e, 500),
            }
        }
        (Method::Get, "/api/alerts/count") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let mut s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                let s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                s.local_host_info.hostname.clone()
            };
            let process_catalog = {
                let s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                assemble_alert_process_catalog(&host, &s.process_tree)
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
                hostname: host.clone(),
                platform: "sample".into(),
                score,
                confidence: 0.85,
                level: level.into(),
                action: "sample_alert".into(),
                reasons,
                sample,
                enforced: false,
                mitre: vec![],
                narrative: None,
            };
            let mut s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if s.alerts.len() >= 10_000 {
                s.alerts.pop_front();
            }
            s.alerts.push_back(alert.clone());
            let alert_event = alert_json_value(
                &alert,
                s.alerts.len().saturating_sub(1),
                &host,
                &process_catalog,
            );
            s.alert_broadcaster.broadcast_alert(alert_event);
            json_response(
                &format!(r#"{{"status":"injected","severity":"{severity}","score":{score:.2}}}"#),
                200,
            )
        }
        // ── Alert Analysis & Grouping ────────────────────────────
        (Method::Get, "/api/alerts/analysis") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let mut s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let alerts_vec: Vec<_> = s.alerts.iter().cloned().collect();
            let analysis = crate::alert_analysis::analyze_alerts(&alerts_vec, window);
            s.last_alert_analysis = Some(analysis.clone());
            match serde_json::to_string(&analysis) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/alerts/grouped") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let alerts_vec: Vec<_> = s.alerts.iter().cloned().collect();
            let groups = crate::alert_analysis::group_alerts(&alerts_vec);
            match serde_json::to_string(&groups) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/alerts/histogram") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let window_secs = url_param(&url, "window")
                .as_deref()
                .and_then(parse_duration_seconds)
                .unwrap_or(60 * 60 * 24);
            let bucket_secs = url_param(&url, "bucket")
                .as_deref()
                .and_then(parse_duration_seconds)
                .unwrap_or(60 * 60);
            let severity = url_param(&url, "severity");
            let body =
                build_alert_histogram(&s.alerts, window_secs, bucket_secs, severity.as_deref());
            json_response(&body.to_string(), 200)
        }
        // ── Swarm Intelligence ──────────────────────────────────
        (Method::Get, "/api/swarm/intel") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let entries = s.swarm.intel_cache.all();
            match serde_json::to_string(entries) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/swarm/intel/stats") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let stats = s.swarm.intel_cache.stats();
            match serde_json::to_string(&stats) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        // ── Local Telemetry ──────────────────────────────────────
        (Method::Get, "/api/telemetry/current") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let samples: Vec<_> = s.local_telemetry.iter().rev().take(120).collect();
            match serde_json::to_string(&samples) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/host/info") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let host = &s.local_host_info;
            let uptime = s.server_start.elapsed().as_secs();
            let cpu_cores = std::thread::available_parallelism()
                .map(std::num::NonZero::get)
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let uptime = s.server_start.elapsed().as_secs();
            let uptime_fmt = format!(
                "{}d {}h {}m {}s",
                uptime / 86400,
                (uptime % 86400) / 3600,
                (uptime % 3600) / 60,
                uptime % 60
            );
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
                {
                    0
                }
                #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
                {
                    0
                }
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
                                .unwrap_or(0.0)
                                / 1024.0
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
                        .unwrap_or(0.0)
                        / 1024.0
                }
                #[cfg(target_os = "windows")]
                {
                    0.0
                }
                #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
                {
                    0.0
                }
            };
            let sample_rate = if s.local_telemetry.len() > 1 {
                let span = uptime as f64;
                if span > 0.0 {
                    s.local_telemetry.len() as f64 / span
                } else {
                    0.2
                }
            } else {
                0.2
            };
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
                "thread_baseline": {
                    "status": if thread_count > 128 { "deviated" } else if thread_count == 0 { "collection_gap" } else { "within_baseline" },
                    "expected_thread_count": { "min": 1, "max": 128 },
                    "thread_count_deviation": thread_count.saturating_sub(128),
                    "sample_count": s.local_telemetry.len(),
                    "confidence": if thread_count == 0 { "low" } else if s.local_telemetry.len() >= 3 { "high" } else { "medium" },
                    "next_action": if thread_count > 128 {
                        "Open the process thread drawer and compare thread fan-out against workload scale."
                    } else {
                        "Keep this runtime thread count as baseline evidence for future anomaly review."
                    },
                },
            });
            json_response(&body.to_string(), 200)
        }
        (Method::Get, "/api/monitoring/options") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = monitoring_options_payload(&s.local_host_info, &s.config);
            json_response(&body.to_string(), 200)
        }
        (Method::Get, "/api/monitoring/paths") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = monitoring_paths_payload(&s.local_host_info, &s.config);
            json_response(&body.to_string(), 200)
        }
        (Method::Get, "/api/rollout/config") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                {"method": "GET", "path": "/api/health", "description": "Server health, version, uptime, platform"},
                {"method": "GET", "path": "/api/metrics", "description": "Prometheus-format product metrics"},
                {"method": "GET", "path": "/api/host/info", "description": "Detailed host info + monitoring status"},
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
                {"method": "GET", "path": "/api/correlation/campaigns", "auth": true, "description": "Campaign clustering, sequence summaries, and attack-graph edges from stored events"},
                {"method": "GET", "path": "/api/alerts", "auth": true, "description": "Last 100 alerts"},
                {"method": "GET", "path": "/api/alerts/page", "auth": true, "description": "Cursor-paginated alerts"},
                {"method": "GET", "path": "/api/alerts/{id}", "auth": true, "description": "Detailed alert view for a specific alert ID"},
                {"method": "GET", "path": "/api/alerts/count", "auth": true, "description": "Alert count by severity"},
                {"method": "DELETE", "path": "/api/alerts", "auth": true, "description": "Clear all alerts"},
                {"method": "POST", "path": "/api/alerts/sample", "auth": true, "description": "Inject a sample alert for testing and demo flows"},
                {"method": "GET", "path": "/api/alerts/analysis", "auth": true, "description": "Latest alert pattern analysis"},
                {"method": "POST", "path": "/api/alerts/analysis", "auth": true, "description": "Run on-demand alert analysis with custom window"},
                {"method": "GET", "path": "/api/alerts/grouped", "auth": true, "description": "Alerts grouped by reason fingerprint"},
                {"method": "POST", "path": "/api/alerts/feedback", "auth": true, "description": "Submit alert outcome feedback states without automatic tuning"},
                {"method": "GET", "path": "/api/alerts/feedback/summary", "auth": true, "description": "Alert feedback rollup and tuning suggestions"},
                {"method": "GET", "path": "/api/alerts/evidence-chain", "auth": true, "description": "Source-aware evidence chain and why-this-fired explanation"},
                {"method": "GET", "path": "/api/operator/workspaces", "auth": true, "description": "Grouped operator navigation and trust workspace snapshots"},
                {"method": "POST", "path": "/api/detection-lab/runs", "auth": true, "description": "Run safe detection validation lab workflow"},
                {"method": "GET", "path": "/api/detection-lab/status", "auth": true, "description": "Detection lab status, modes, history, and recommendations"},
                {"method": "GET", "path": "/api/detection-lab/history", "auth": true, "description": "Detection validation history"},
                {"method": "GET", "path": "/api/detection-lab/report", "auth": true, "description": "Detection validation report export payload"},
                {"method": "GET", "path": "/api/response/safety", "auth": true, "description": "Response dry-run, approvals, rollback, and verification center"},
                {"method": "GET", "path": "/api/response/execution-audit", "auth": true, "description": "Response execution transcripts, command summaries, exit status, rollback, and verification evidence"},
                {"method": "POST", "path": "/api/response/preview", "auth": true, "description": "Preview response blast radius, approval, rollback, and platform mapping"},
                {"method": "POST", "path": "/api/response/verify", "auth": true, "description": "Record response verification checklist state"},
                {"method": "GET", "path": "/api/integrations/marketplace", "auth": true, "description": "Connector marketplace summaries, health, sample event preview, and impact mapping"},
                {"method": "POST", "path": "/api/integrations/validate", "auth": true, "description": "Validate connector setup and sample-event readiness"},
                {"method": "GET", "path": "/api/integrations/sample-event", "auth": true, "description": "Preview normalized connector sample event"},
                {"method": "GET", "path": "/api/operations/health", "auth": true, "description": "Production deployment health and SLO cards"},
                {"method": "GET", "path": "/api/operations/health/snapshot", "auth": true, "description": "Persist and export operations health evidence"},
                {"method": "GET", "path": "/api/malware/explain", "auth": true, "description": "Malware verdict explanation, signature sources, and scan transparency"},
                {"method": "GET", "path": "/api/malware/scan-diff", "auth": true, "description": "Repeated malware scan comparison summary"},
                {"method": "GET", "path": "/api/platform", "auth": true, "description": "Detected platform capabilities and hardware security support"},
                {"method": "GET", "path": "/api/threat-intel/status", "auth": true, "description": "Threat intelligence indicator inventory status"},
                {"method": "GET", "path": "/api/threat-intel/library", "auth": true, "description": "Threat intelligence indicator library, feeds, and recent match activity"},
                {"method": "POST", "path": "/api/threat-intel/ioc", "auth": true, "description": "Submit a new indicator of compromise"},
                {"method": "GET", "path": "/api/threat-intel/stats", "auth": true, "description": "IoC enrichment statistics (by type, severity, source)"},
                {"method": "POST", "path": "/api/threat-intel/purge", "auth": true, "description": "Purge expired IoCs by TTL (days)"},
                {"method": "GET", "path": "/api/mitre/coverage", "auth": true, "description": "MITRE ATT&CK coverage summary with gap analysis"},
                {"method": "GET", "path": "/api/mitre/heatmap", "auth": true, "description": "MITRE ATT&CK heatmap (per-tactic, per-technique coverage)"},
                {"method": "GET", "path": "/api/detection/profile", "auth": true, "description": "Current detection tuning profile"},
                {"method": "PUT", "path": "/api/detection/profile", "auth": true, "description": "Set detection tuning profile (aggressive/balanced/quiet)"},
                {"method": "GET", "path": "/api/detection/replay-corpus", "auth": true, "description": "Built-in replay-corpus precision, recall, false-positive, and category gate"},
                {"method": "POST", "path": "/api/detection/replay-corpus", "auth": true, "description": "Evaluate a custom labeled or retained-event replay-corpus validation pack"},
                {"method": "POST", "path": "/api/fp-feedback", "auth": true, "description": "Submit false-positive feedback for an alert pattern"},
                {"method": "GET", "path": "/api/fp-feedback/stats", "auth": true, "description": "False-positive feedback statistics and suppression weights"},
                {"method": "GET", "path": "/api/detection/trust/overview", "auth": true, "description": "Detection Trust overview with noisy rules, trusted rules, stale suppressions, and draft-only tuning queue"},
                {"method": "GET", "path": "/api/detection/tuning/feedback", "auth": true, "description": "Seven-day detection tuning impact feedback with draft-only suggested actions"},
                {"method": "GET", "path": "/api/detection/trust/rules", "auth": true, "description": "Per-rule Detection Trust scores, confidence drivers, feedback rollups, and tuning recommendations"},
                {"method": "GET", "path": "/api/detection/trust/rules/{id}", "auth": true, "description": "Detailed Detection Trust evidence and feedback history for one rule"},
                {"method": "GET", "path": "/api/detection/trust/tuning-drafts", "auth": true, "description": "Draft-only tuning suggestions generated from feedback, suppressions, replay, and rule lifecycle"},
                {"method": "POST", "path": "/api/detection/trust/tuning-drafts", "auth": true, "description": "Create an operator-reviewed tuning draft without changing production detections"},
                {"method": "POST", "path": "/api/detection/trust/tuning-drafts/{id}/preview", "auth": true, "description": "Preview tuning draft impact before any operator-applied change"},
                {"method": "POST", "path": "/api/detection/trust/tuning-drafts/{id}/approve", "auth": true, "description": "Approve draft intent while keeping production tuning manual and audit-visible"},
                {"method": "GET", "path": "/api/ndr/report", "auth": true, "description": "Aggregate NDR analysis report with anomaly summaries"},
                {"method": "GET", "path": "/api/ndr/tls-anomalies", "auth": true, "description": "TLS fingerprint anomalies from the current NDR window"},
                {"method": "GET", "path": "/api/ndr/dpi-anomalies", "auth": true, "description": "DPI protocol mismatches from the current NDR window"},
                {"method": "GET", "path": "/api/ndr/entropy-anomalies", "auth": true, "description": "High-entropy encrypted sessions from the current NDR window"},
                {"method": "GET", "path": "/api/ndr/self-signed-certs", "auth": true, "description": "Self-signed certificate detections from the current NDR window"},
                {"method": "GET", "path": "/api/ndr/top-talkers", "auth": true, "description": "Top talkers from the current NDR window"},
                {"method": "GET", "path": "/api/ndr/beaconing", "auth": true, "description": "Regular outbound cadence anomalies that resemble beaconing"},
                {"method": "GET", "path": "/api/ndr/protocol-distribution", "auth": true, "description": "Protocol traffic distribution from the current NDR window"},
                {"method": "GET", "path": "/api/detection/score/normalize", "auth": true, "description": "Get normalized 0-100 threat score with severity label"},
                {"method": "GET", "path": "/api/playbooks", "auth": true, "description": "List registered automated response playbooks"},
                {"method": "POST", "path": "/api/playbooks", "auth": true, "description": "Register or update an automated response playbook"},
                {"method": "POST", "path": "/api/playbooks/execute", "auth": true, "description": "Start a playbook execution for a specific alert"},
                {"method": "POST", "path": "/api/playbooks/run", "auth": true, "description": "Run a playbook until it completes or pauses for approval"},
                {"method": "POST", "path": "/api/playbooks/resume", "auth": true, "description": "Resume an approval-gated playbook execution"},
                {"method": "GET", "path": "/api/playbooks/executions", "auth": true, "description": "List recent playbook execution records"},
                {"method": "GET", "path": "/api/playbook/execution/{id}/recovery-actions", "auth": true, "description": "Suggested recovery actions for failed, paused, or completed playbook executions"},
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
                {"method": "GET", "path": "/api/events/page", "auth": true, "description": "Cursor-paginated retained XDR events"},
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
                {"method": "POST", "path": "/api/content/rules/{id}/preflight", "auth": true, "description": "Validate stream, replay, suppression, and ownership proof before rule promotion"},
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
                {"method": "GET", "path": "/api/assistant/status", "auth": true, "description": "Assistant provider status, mode, and conversation health"},
                {"method": "POST", "path": "/api/assistant/query", "auth": true, "description": "Ask the analyst assistant with optional case-aware context and citations"},
                {"method": "GET", "path": "/api/idp/providers", "auth": true, "description": "List configured OIDC/SAML identity providers"},
                {"method": "POST", "path": "/api/idp/providers", "auth": true, "description": "Create or update an identity provider configuration"},
                {"method": "GET", "path": "/api/scim/config", "auth": true, "description": "Get SCIM provisioning configuration"},
                {"method": "POST", "path": "/api/scim/config", "auth": true, "description": "Update SCIM provisioning configuration"},
                {"method": "GET", "path": "/api/audit/admin", "auth": true, "description": "Enterprise admin audit, change control, and approval history"},
                {"method": "GET", "path": "/api/support/diagnostics", "auth": true, "description": "Support diagnostics bundle with dependency, auth, content, and operations state"},
                {"method": "GET", "path": "/api/support/readiness-evidence", "auth": true, "description": "Production readiness evidence pack for support, audit, and procurement review"},
                {"method": "POST", "path": "/api/support/first-run-proof", "auth": true, "description": "Run the first-run operator proof scenario end to end"},
                {"method": "GET", "path": "/api/system/health/dependencies", "auth": true, "description": "Dependency and rollout health across storage, SIEM, connectors, and fleet state"},
                {"method": "POST", "path": "/api/events/{id}/triage", "auth": true, "description": "Update event triage state, assignee, tags, and analyst notes"},
                {"method": "GET", "path": "/api/policy/history", "auth": true, "description": "Published policy history"},
                {"method": "GET", "path": "/api/updates/releases", "auth": true, "description": "List published agent releases for deployment and rollback"},
                {"method": "POST", "path": "/api/updates/deploy", "auth": true, "description": "Assign a published release to a specific agent"},
                {"method": "POST", "path": "/api/response/request", "auth": true, "description": "Submit an approval-gated response action"},
                {"method": "GET", "path": "/api/response/requests", "auth": true, "description": "List all response requests with approval state"},
                {"method": "POST", "path": "/api/response/approve", "auth": true, "description": "Approve or deny a pending response request"},
                {"method": "POST", "path": "/api/response/execute", "auth": true, "description": "Execute all approved response requests"},
                {"method": "GET", "path": "/api/audit/log", "auth": true, "description": "Paginated API audit log entries with search and filter metadata"},
                {"method": "GET", "path": "/api/audit/log/page", "auth": true, "description": "Cursor-paginated API audit log entries"},
                {"method": "GET", "path": "/api/audit/log/export", "auth": true, "description": "Export filtered API audit log entries as CSV"},
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
                {"method": "GET", "path": "/api/report-templates", "auth": true, "description": "List reusable report templates and presets"},
                {"method": "POST", "path": "/api/report-templates", "auth": true, "description": "Create or update a reusable report template"},
                {"method": "GET", "path": "/api/report-runs", "auth": true, "description": "List report run history with preview metadata"},
                {"method": "POST", "path": "/api/report-runs", "auth": true, "description": "Create a report run and persist its preview summary"},
                {"method": "GET", "path": "/api/report-schedules", "auth": true, "description": "List lightweight report delivery schedules"},
                {"method": "POST", "path": "/api/report-schedules", "auth": true, "description": "Create or update a daily or weekly report schedule"},
                {"method": "GET", "path": "/api/inbox", "auth": true, "description": "Persistent operator inbox across approvals, fleet health, and delivery issues"},
                {"method": "POST", "path": "/api/inbox/ack", "auth": true, "description": "Acknowledge an operator inbox item"},
                {"method": "GET", "path": "/api/incidents/{id}/report", "auth": true, "description": "Generate incident report"},
                {"method": "GET", "path": "/api/openapi.json", "description": "OpenAPI 3.0 specification"},
                {"method": "GET", "path": "/api/slo/status", "description": "Service level objective metrics"},
                {"method": "POST", "path": "/api/auth/rotate", "description": "Rotate admin token and reset TTL"},
                {"method": "GET", "path": "/api/session/info", "description": "Session info with token TTL and expiry status"},
                {"method": "GET", "path": "/api/user/preferences", "description": "Retrieve persisted theme and pinned-view preferences for the current actor"},
                {"method": "PUT", "path": "/api/user/preferences", "auth": true, "description": "Update persisted theme and pinned-view preferences for the current actor"},
                {"method": "GET", "path": "/api/audit/verify", "auth": true, "description": "Verify integrity of the cryptographic audit chain"},
                {"method": "GET", "path": "/api/retention/status", "auth": true, "description": "Current retention policy settings and record counts"},
                {"method": "POST", "path": "/api/retention/apply", "auth": true, "description": "Apply retention policies to trim old records"},
                {"method": "GET", "path": "/api/storage/events/historical", "auth": true, "description": "Query ClickHouse-backed long-retention events with time and entity filters"},
                {"method": "GET", "path": "/api/search/performance-slo", "auth": true, "description": "Long-retention search p95 and p99 latency SLO evidence"},
                {"method": "GET", "path": "/api/collectors/status", "auth": true, "description": "Summarize structured collector setup, validation, and ingestion-health timeline checkpoints"},
                {"method": "GET", "path": "/api/command/summary", "auth": true, "description": "Summarize Command Center lane health across incidents, remediation, connectors, rules, releases, and compliance evidence"},
                {"method": "GET", "path": "/api/command/lanes/{lane}", "auth": true, "description": "Per-lane slice of the Command Center summary (incidents, remediation, connectors, rule_tuning, release, evidence)"},
                {"method": "GET", "path": "/api/collectors/aws", "auth": true, "description": "Retrieve AWS CloudTrail setup details and validation status"},
                {"method": "POST", "path": "/api/collectors/aws/config", "auth": true, "description": "Save AWS CloudTrail setup fields while preserving existing secrets when omitted"},
                {"method": "POST", "path": "/api/collectors/aws/validate", "auth": true, "description": "Run an on-demand AWS CloudTrail validation poll and return sample events"},
                {"method": "GET", "path": "/api/collectors/azure", "auth": true, "description": "Retrieve Azure Activity setup details and validation status"},
                {"method": "POST", "path": "/api/collectors/azure/config", "auth": true, "description": "Save Azure Activity setup fields while preserving existing secrets when omitted"},
                {"method": "POST", "path": "/api/collectors/azure/validate", "auth": true, "description": "Run an on-demand Azure Activity validation poll and return sample events"},
                {"method": "GET", "path": "/api/collectors/gcp", "auth": true, "description": "Retrieve GCP Audit setup details and validation status"},
                {"method": "POST", "path": "/api/collectors/gcp/config", "auth": true, "description": "Save GCP Audit setup fields while preserving existing secrets when omitted"},
                {"method": "POST", "path": "/api/collectors/gcp/validate", "auth": true, "description": "Run an on-demand GCP Audit validation poll and return sample events"},
                {"method": "GET", "path": "/api/collectors/okta", "auth": true, "description": "Retrieve Okta identity collector setup details and validation status"},
                {"method": "POST", "path": "/api/collectors/okta/config", "auth": true, "description": "Save Okta identity collector setup fields while preserving the current API token when omitted"},
                {"method": "POST", "path": "/api/collectors/okta/validate", "auth": true, "description": "Run an on-demand Okta identity validation poll and return sample events"},
                {"method": "GET", "path": "/api/collectors/entra", "auth": true, "description": "Retrieve Microsoft Entra identity collector setup details and validation status"},
                {"method": "POST", "path": "/api/collectors/entra/config", "auth": true, "description": "Save Microsoft Entra identity collector setup fields while preserving the current client secret when omitted"},
                {"method": "POST", "path": "/api/collectors/entra/validate", "auth": true, "description": "Run an on-demand Microsoft Entra identity validation poll and return sample events"},
                {"method": "GET", "path": "/api/collectors/m365", "auth": true, "description": "Retrieve Microsoft 365 SaaS collector setup details and validation status"},
                {"method": "POST", "path": "/api/collectors/m365/config", "auth": true, "description": "Save Microsoft 365 collector setup fields while preserving the current client secret when omitted"},
                {"method": "POST", "path": "/api/collectors/m365/validate", "auth": true, "description": "Run an on-demand Microsoft 365 validation and return sample audit events"},
                {"method": "GET", "path": "/api/collectors/workspace", "auth": true, "description": "Retrieve Google Workspace collector setup details and validation status"},
                {"method": "POST", "path": "/api/collectors/workspace/config", "auth": true, "description": "Save Google Workspace collector setup fields while preserving the current credentials blob when omitted"},
                {"method": "POST", "path": "/api/collectors/workspace/validate", "auth": true, "description": "Run an on-demand Google Workspace validation and return sample audit events"},
                {"method": "GET", "path": "/api/collectors/github", "auth": true, "description": "Retrieve planned GitHub audit connector setup details and validation status"},
                {"method": "POST", "path": "/api/collectors/github/config", "auth": true, "description": "Save planned GitHub audit connector setup fields"},
                {"method": "POST", "path": "/api/collectors/github/validate", "auth": true, "description": "Validate GitHub audit setup and return sample audit events"},
                {"method": "GET", "path": "/api/collectors/crowdstrike", "auth": true, "description": "Retrieve planned CrowdStrike Falcon connector setup details and validation status"},
                {"method": "POST", "path": "/api/collectors/crowdstrike/config", "auth": true, "description": "Save planned CrowdStrike Falcon connector setup fields"},
                {"method": "POST", "path": "/api/collectors/crowdstrike/validate", "auth": true, "description": "Validate CrowdStrike Falcon setup and return sample EDR events"},
                {"method": "GET", "path": "/api/collectors/syslog", "auth": true, "description": "Retrieve planned generic syslog connector setup details and validation status"},
                {"method": "POST", "path": "/api/collectors/syslog/config", "auth": true, "description": "Save planned generic syslog connector setup fields"},
                {"method": "POST", "path": "/api/collectors/syslog/validate", "auth": true, "description": "Validate generic syslog setup and return sample parsed events"},
                {"method": "GET", "path": "/api/secrets/status", "auth": true, "description": "Retrieve secrets-manager configuration, validation, and resolver status"},
                {"method": "POST", "path": "/api/secrets/config", "auth": true, "description": "Save secrets-manager setup fields while preserving the current Vault token when omitted"},
                {"method": "POST", "path": "/api/secrets/validate", "auth": true, "description": "Resolve and validate a secret reference without disclosing the full plaintext"},
                {"method": "GET", "path": "/api/queue/alerts", "auth": true, "description": "Current analyst alert queue with SLA metadata"},
                {"method": "GET", "path": "/api/queue/stats", "auth": true, "description": "Alert queue backlog and SLA summary"},
                {"method": "POST", "path": "/api/queue/acknowledge", "auth": true, "description": "Acknowledge a queued alert"},
                {"method": "POST", "path": "/api/queue/assign", "auth": true, "description": "Assign a queued alert to an analyst"},
                {"method": "GET", "path": "/api/timeline/host", "auth": true, "description": "Host investigation timeline filtered by hostname query parameter"},
                {"method": "GET", "path": "/api/timeline/agent", "auth": true, "description": "Agent investigation timeline filtered by agent_id query parameter"},
                {"method": "GET", "path": "/api/cases/stats", "auth": true, "description": "Case backlog and status summary"},
                {"method": "GET", "path": "/api/cases/{id}/handoff-packet", "auth": true, "description": "Structured case handoff packet with summary, timeline, evidence, and ticket context"},
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
                {"method": "GET", "path": "/api/investigations/workflows", "auth": true, "description": "List available investigation workflow templates"},
                {"method": "POST", "path": "/api/investigations/start", "auth": true, "description": "Start a new guided investigation workflow"},
                {"method": "GET", "path": "/api/investigations/active", "auth": true, "description": "List active investigations with step progress, notes, and next pivots"},
                {"method": "POST", "path": "/api/investigations/progress", "auth": true, "description": "Update step completion, notes, findings, or status for an active investigation"},
                {"method": "POST", "path": "/api/investigations/handoff", "auth": true, "description": "Hand an active investigation to another analyst and sync the linked case owner"},
                {"method": "POST", "path": "/api/investigations/suggest", "auth": true, "description": "Suggest workflows that match the current alert or incident context"},
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
                {"method": "GET", "path": "/api/processes/detail?pid=<pid>", "auth": true, "description": "Detailed local process investigation view for a specific PID"},
                {"method": "GET", "path": "/api/processes/threads?pid=<pid>", "auth": true, "description": "Per-process OS thread snapshot with live state, CPU, and priority context"},
                {"method": "GET", "path": "/api/processes/thread-proof", "auth": true, "description": "Runtime thread anomaly proof and baseline readiness"},
                {"method": "GET", "path": "/api/host/apps", "auth": true, "description": "Enumerate installed applications"},
                {"method": "GET", "path": "/api/host/inventory", "auth": true, "description": "Full system inventory (hardware, software, services, users)"},
                {"method": "POST", "path": "/api/policy-vm/execute", "auth": true, "description": "Execute a policy VM program"},
                {"method": "POST", "path": "/api/policy/compose", "auth": true, "description": "Compose a policy from weighted inputs"},
                {"method": "GET", "path": "/api/quantum/key-status", "auth": true, "description": "Quantum key rotation status"},
                {"method": "POST", "path": "/api/quantum/rotate", "auth": true, "description": "Rotate quantum key material"},
                {"method": "GET", "path": "/api/admin/rbac-coverage", "auth": true, "description": "RBAC route coverage proof with required permissions and allowed roles"},
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
                {"method": "POST", "path": "/api/siem/validate", "auth": true, "description": "Validate SIEM connector configuration without persisting it"},
                {"method": "GET", "path": "/api/sigma/rules", "auth": true, "description": "Loaded Sigma rules"},
                {"method": "GET", "path": "/api/sigma/stats", "auth": true, "description": "Sigma engine statistics"},
                {"method": "GET", "path": "/api/spool/stats", "auth": true, "description": "Encrypted spool statistics"},
                {"method": "GET", "path": "/api/swarm/posture", "auth": true, "description": "Swarm security posture summary"},
                {"method": "GET", "path": "/api/taxii/status", "auth": true, "description": "TAXII connector status"},
                {"method": "GET", "path": "/api/taxii/config", "auth": true, "description": "TAXII connector configuration"},
                {"method": "POST", "path": "/api/taxii/config", "auth": true, "description": "Update TAXII connector configuration"},
                {"method": "POST", "path": "/api/taxii/pull", "auth": true, "description": "Pull indicators from TAXII sources"},
                {"method": "GET", "path": "/api/tenants/count", "auth": true, "description": "Tenant count summary"},
                {"method": "GET", "path": "/api/tenants/isolation-proof", "auth": true, "description": "Tenant isolation and device partitioning proof"},
                {"method": "GET", "path": "/api/tls/status", "auth": true, "description": "TLS listener and certificate status"},
                {"method": "POST", "path": "/api/agents/token", "auth": true, "description": "Create an agent enrollment token"},
                {"method": "POST", "path": "/api/agents/enroll", "auth": false, "description": "Enroll an agent with a valid enrollment token"},
                {"method": "GET", "path": "/api/fleet/installs", "auth": true, "description": "Recent remote install attempts and outcomes"},
                {"method": "POST", "path": "/api/fleet/install/ssh", "auth": true, "description": "Run a remote agent install over SSH for Linux or macOS hosts"},
                {"method": "POST", "path": "/api/fleet/install/winrm", "auth": true, "description": "Run a remote agent install over WinRM for Windows hosts"},
                {"method": "POST", "path": "/api/control/mode", "auth": true, "description": "Set the device control mode"},
                {"method": "POST", "path": "/api/control/reset-baseline", "auth": true, "description": "Reset the anomaly detection baseline"},
                {"method": "POST", "path": "/api/control/checkpoint", "auth": true, "description": "Create a control checkpoint"},
                {"method": "POST", "path": "/api/control/restore-checkpoint", "auth": true, "description": "Restore a control checkpoint"},
                {"method": "POST", "path": "/api/control/failover-drill", "auth": true, "description": "Run an automated control-plane failover drill against current recovery artifacts"},
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
                    && seen.insert((method.to_string(), path.to_string()))
                {
                    let auth = method_from_name(method).map_or(
                        entry["auth"].as_bool().unwrap_or(true),
                        |parsed| {
                            matches!(
                                api_route_access(&parsed, path),
                                ApiRouteAccess::Authenticated
                            )
                        },
                    );
                    endpoints.push(serde_json::json!({
                        "method": method,
                        "path": path,
                        "auth": auth,
                        "description": entry["description"].as_str().unwrap_or(""),
                    }));
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
        (Method::Post, "/api/agents/enroll") => {
            crate::server_agents::handle_agent_enroll(body, state)
        }
        (Method::Post, "/api/agents/token") => {
            crate::server_agents::handle_agent_create_token(body, state)
        }
        (Method::Get, "/api/fleet/installs") => {
            crate::server_fleet::handle_fleet_install_history(state)
        }
        (Method::Post, "/api/fleet/install/ssh") => {
            crate::server_fleet::handle_fleet_install_ssh(body, state, &auth_identity)
        }
        (Method::Post, "/api/fleet/install/winrm") => {
            crate::server_fleet::handle_fleet_install_winrm(body, state, &auth_identity)
        }
        (Method::Get, "/api/agents") => {
            let mut s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            s.agent_registry.refresh_staleness();
            let agents = s.agent_registry.list();
            let heartbeat_interval = s.agent_registry.heartbeat_interval();
            let params = parse_query_string(&url);
            let limit = params
                .get("limit")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(200)
                .min(1000);
            let offset = params
                .get("offset")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0);
            let mut payload = Vec::with_capacity(agents.len() + 1);
            payload.push(local_console_agent_summary_json(&s));
            payload.extend(agents.iter().map(|agent| {
                agent_summary_json(
                    agent,
                    s.remote_deployments.get(&agent.id),
                    heartbeat_interval,
                    s.policy_store.current_version(),
                )
            }));
            let payload = payload
                .into_iter()
                .skip(offset)
                .take(limit)
                .collect::<Vec<_>>();
            match serde_json::to_string(&payload) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }

        // ── Local console host inventory (processes + sockets) ───
        (Method::Get, "/api/agents/local-console/inventory") => {
            let cached = {
                let s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                s.last_inventory.clone()
            };
            let inventory = cached.unwrap_or_else(|| {
                let fresh = crate::collector::collect_host_inventory(50, 50);
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                s.last_inventory = Some(fresh.clone());
                s.last_inventory_at_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                fresh
            });
            match serde_json::to_string(&inventory) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }

        // ── XDR Events ────────────────────────────────────────────
        (Method::Post, "/api/events") => handle_event_ingest(body, state),
        (Method::Get, "/api/events/page") => {
            let (cursor, limit) = parse_cursor_page_params(&url, 100, 1000);
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = event_cursor_page_payload(&s, &url, cursor, limit);
            json_response(&body.to_string(), 200)
        }
        (Method::Get, "/api/events") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let query = parse_event_query(&url);
            let all_events = filtered_events(&s.event_store, &query);
            let params = parse_query_string(&url);
            let limit = params
                .get("limit")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(100)
                .min(1000);
            let offset = params
                .get("offset")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0);
            let paged: Vec<_> = all_events.into_iter().skip(offset).take(limit).collect();
            match serde_json::to_string(&paged) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/events/export") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let query = parse_event_query(&url);
            let events = filtered_events(&s.event_store, &query);
            csv_response(&events_to_csv(&events), 200)
        }
        (Method::Get, "/api/events/summary") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let analytics = s.event_store.analytics();
            match serde_json::to_string(&analytics) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }

        // ── XDR Policy Distribution ──────────────────────────────
        (Method::Get, "/api/policy/current") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match s.policy_store.current() {
                Some(policy) => match serde_json::to_string(policy) {
                    Ok(json) => json_response(&json, 200),
                    Err(e) => error_json(&format!("serialization error: {e}"), 500),
                },
                None => json_response(r#"{"version":0,"message":"no policy published"}"#, 200),
            }
        }
        (Method::Get, "/api/policy/history") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match serde_json::to_string(s.policy_store.history()) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Post, "/api/policy/publish") => handle_policy_publish(body, state),

        // ── XDR Update Distribution ──────────────────────────────
        (Method::Post, "/api/updates/publish") => {
            crate::server_fleet::handle_update_publish(body, state, &auth_identity)
        }
        (Method::Post, "/api/updates/deploy") => {
            crate::server_fleet::handle_update_deploy(body, state, &auth_identity)
        }
        (Method::Post, "/api/updates/rollback") => {
            crate::server_fleet::handle_update_rollback(body, state, &auth_identity)
        }
        (Method::Post, "/api/updates/cancel") => {
            crate::server_fleet::handle_update_cancel(body, state, &auth_identity)
        }
        (Method::Post, "/api/events/bulk-triage") => handle_bulk_triage(body, state),

        // ── Detection Analysis ─────────────────────────────────
        (Method::Get, "/api/detection/replay-corpus") => {
            let body = build_replay_corpus_evaluation();
            match serde_json::to_string_pretty(&body) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Post, "/api/detection/replay-corpus") => {
            let raw = match read_body_limited(body, 256 * 1024) {
                Ok(body) => body,
                Err(e) => return error_json(&e, 400),
            };
            let (source, pack_name, threshold, limit, entries) =
                match parse_replay_corpus_pack(&raw) {
                    Ok(parsed) => parsed,
                    Err(e) => return error_json(&e, 400),
                };
            let entries = if source == "retained_events" {
                let s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let events = s.event_store.all_events().to_vec();
                drop(s);
                let retained_entries =
                    retained_event_replay_entries(&events, limit.unwrap_or(100), threshold);
                if retained_entries.is_empty() {
                    return error_json("no retained events available for replay corpus", 400);
                }
                retained_entries
            } else {
                entries
            };
            let body = build_replay_corpus_evaluation_for(&source, &pack_name, &entries, threshold);
            match serde_json::to_string_pretty(&body) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/detection/summary") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        (Method::Get, "/api/detection/recommendations") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let limit = url_param(&url, "limit")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(10);
            let body = build_detection_recommendations(&s, limit);
            let snapshot =
                persist_operational_snapshot(&s.storage, "detection_recommendations", &body);
            json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
        }
        (Method::Get, "/api/detection/readiness") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let limit = url_param(&url, "limit")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(20);
            let body = build_detection_readiness(&s, limit);
            let snapshot = persist_operational_snapshot(&s.storage, "detection_readiness", &body);
            json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
        }
        (Method::Get, "/api/detection/weights") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let mut s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            s.detector.set_signal_weights(weights.clone());
            drop(s);
            json_response(
                &serde_json::json!({"status":"weights_updated","weights":weights}).to_string(),
                200,
            )
        }

        (Method::Get, "/api/audit/log/export") => {
            let query = parse_query_string(&url);
            let filter = AuditLogFilter::from_query(&query);
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let entries = s.audit_log.filtered_entries(&filter);
            csv_response(&audit_entries_to_csv(&entries), 200)
        }

        // ── Audit Log ─────────────────────────────────────────────
        (Method::Get, "/api/audit/log/page") => {
            let (cursor, limit) = parse_cursor_page_params(&url, 50, 200);
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = audit_cursor_page_payload(&s, &url, cursor, limit);
            json_response(&body.to_string(), 200)
        }
        (Method::Get, "/api/audit/log") => {
            let query = parse_query_string(&url);
            let filter = AuditLogFilter::from_query(&query);
            let limit = query
                .get("limit")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(50)
                .clamp(1, 200);
            let offset = query
                .get("offset")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0)
                .min(100_000);
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let page = s.audit_log.page_filtered(limit, offset, &filter);
            match serde_json::to_string(&page) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }

        // ── Incidents ─────────────────────────────────────────────
        (Method::Get, "/api/incidents") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let mut s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let query = parse_query_string(&url);
            let filter = crate::report::ReportListFilter {
                case_id: query
                    .get("case_id")
                    .cloned()
                    .filter(|value| !value.trim().is_empty()),
                incident_id: query
                    .get("incident_id")
                    .cloned()
                    .filter(|value| !value.trim().is_empty()),
                investigation_id: query
                    .get("investigation_id")
                    .cloned()
                    .filter(|value| !value.trim().is_empty()),
                source: query
                    .get("source")
                    .cloned()
                    .filter(|value| !value.trim().is_empty()),
                scope: match query.get("scope").map(String::as_str) {
                    Some("scoped") => crate::report::ReportScopeFilter::Scoped,
                    Some("unscoped") => crate::report::ReportScopeFilter::Unscoped,
                    _ => crate::report::ReportScopeFilter::All,
                },
            };
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let list = s.report_store.list_filtered(&filter);
            match serde_json::to_string(&list) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/reports/executive-summary") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let summary = s.report_store.executive_summary(&s.incident_store);
            match serde_json::to_string(&summary) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/report-templates") => {
            let query = parse_query_string(&url);
            let filter = report_execution_context_filter_from_query(&query);
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let templates = s.support_store.report_templates_filtered(&filter);
            let body = serde_json::json!({
                "templates": templates,
                "count": templates.len(),
            });
            json_response(&body.to_string(), 200)
        }
        (Method::Post, "/api/report-templates") => match read_json_value(body, 12 * 1024) {
            Ok(v) => {
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let execution_context = crate::support::ReportExecutionContext {
                    case_id: v
                        .get("case_id")
                        .and_then(|value| value.as_str())
                        .map(std::string::ToString::to_string),
                    incident_id: v
                        .get("incident_id")
                        .and_then(|value| value.as_str())
                        .map(std::string::ToString::to_string),
                    investigation_id: v
                        .get("investigation_id")
                        .and_then(|value| value.as_str())
                        .map(std::string::ToString::to_string),
                    source: v
                        .get("source")
                        .and_then(|value| value.as_str())
                        .map(std::string::ToString::to_string),
                };
                let has_execution_context = [
                    execution_context.case_id.as_ref(),
                    execution_context.incident_id.as_ref(),
                    execution_context.investigation_id.as_ref(),
                    execution_context.source.as_ref(),
                ]
                .into_iter()
                .any(|value| value.is_some());
                let template = s.support_store.upsert_report_template(
                    v.get("id").and_then(|value| value.as_str()),
                    v["name"].as_str().unwrap_or("Saved Template").to_string(),
                    v["kind"].as_str().unwrap_or("executive_status").to_string(),
                    v["scope"].as_str().unwrap_or("global").to_string(),
                    v["format"].as_str().unwrap_or("json").to_string(),
                    v["status"].as_str().unwrap_or("ready").to_string(),
                    v["audience"].as_str().unwrap_or("operations").to_string(),
                    v["description"]
                        .as_str()
                        .unwrap_or("Reusable report template")
                        .to_string(),
                    has_execution_context.then_some(execution_context),
                );
                json_response(
                    &serde_json::json!({"status": "saved", "template": template}).to_string(),
                    201,
                )
            }
            Err(e) => error_json(&e, 400),
        },
        (Method::Get, "/api/report-runs") => {
            let query = parse_query_string(&url);
            let filter = report_execution_context_filter_from_query(&query);
            let runs = {
                let s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                s.support_store.report_runs_filtered(&filter)
            };
            let body = serde_json::json!({
                "runs": runs,
                "count": runs.len(),
            });
            json_response(&body.to_string(), 200)
        }
        (Method::Post, "/api/report-runs") => match read_json_value(body, 16 * 1024) {
            Ok(v) => {
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let execution_context = crate::support::ReportExecutionContext {
                    case_id: v
                        .get("case_id")
                        .and_then(|value| value.as_str())
                        .map(std::string::ToString::to_string),
                    incident_id: v
                        .get("incident_id")
                        .and_then(|value| value.as_str())
                        .map(std::string::ToString::to_string),
                    investigation_id: v
                        .get("investigation_id")
                        .and_then(|value| value.as_str())
                        .map(std::string::ToString::to_string),
                    source: v
                        .get("source")
                        .and_then(|value| value.as_str())
                        .map(std::string::ToString::to_string),
                };
                let execution_context_json = serde_json::json!({
                    "case_id": execution_context.case_id.clone(),
                    "incident_id": execution_context.incident_id.clone(),
                    "investigation_id": execution_context.investigation_id.clone(),
                    "source": execution_context.source.clone(),
                });
                let has_execution_context = execution_context_json
                    .as_object()
                    .is_some_and(|object| object.values().any(|value| !value.is_null()));
                let preview = v
                    .get("preview_override")
                    .filter(|value| value.is_object())
                    .cloned()
                    .unwrap_or_else(|| {
                        build_report_run_preview(&mut s, &v, execution_context_json)
                    });
                let pretty_preview =
                    serde_json::to_string_pretty(&preview).unwrap_or_else(|_| preview.to_string());
                let run = s.support_store.add_report_run(
                    v["name"].as_str().unwrap_or("Report Run").to_string(),
                    v["kind"].as_str().unwrap_or("executive_status").to_string(),
                    v["scope"].as_str().unwrap_or("global").to_string(),
                    v["format"].as_str().unwrap_or("json").to_string(),
                    v["audience"].as_str().unwrap_or("operations").to_string(),
                    v["status"].as_str().unwrap_or("completed").to_string(),
                    v["summary"]
                        .as_str()
                        .unwrap_or("Preview generated and persisted for operator review.")
                        .to_string(),
                    pretty_preview.len() as u64,
                    preview,
                    has_execution_context.then_some(execution_context),
                );
                json_response(
                    &serde_json::json!({"status": "created", "run": run}).to_string(),
                    201,
                )
            }
            Err(e) => error_json(&e, 400),
        },
        (Method::Get, "/api/report-schedules") => {
            let query = parse_query_string(&url);
            let filter = report_execution_context_filter_from_query(&query);
            let schedules = {
                let s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                s.support_store.report_schedules_filtered(&filter)
            };
            let body = serde_json::json!({
                "schedules": schedules,
                "count": schedules.len(),
            });
            json_response(&body.to_string(), 200)
        }
        (Method::Post, "/api/report-schedules") => match read_json_value(body, 12 * 1024) {
            Ok(v) => {
                let cadence = v["cadence"].as_str().unwrap_or("weekly");
                if cadence != "daily" && cadence != "weekly" {
                    return error_json("cadence must be daily or weekly", 400);
                }
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let execution_context = crate::support::ReportExecutionContext {
                    case_id: v
                        .get("case_id")
                        .and_then(|value| value.as_str())
                        .map(std::string::ToString::to_string),
                    incident_id: v
                        .get("incident_id")
                        .and_then(|value| value.as_str())
                        .map(std::string::ToString::to_string),
                    investigation_id: v
                        .get("investigation_id")
                        .and_then(|value| value.as_str())
                        .map(std::string::ToString::to_string),
                    source: v
                        .get("source")
                        .and_then(|value| value.as_str())
                        .map(std::string::ToString::to_string),
                };
                let has_execution_context = [
                    execution_context.case_id.as_ref(),
                    execution_context.incident_id.as_ref(),
                    execution_context.investigation_id.as_ref(),
                    execution_context.source.as_ref(),
                ]
                .into_iter()
                .any(|value| value.is_some());
                let schedule = s.support_store.upsert_report_schedule(
                    v.get("id").and_then(|value| value.as_str()),
                    v["name"].as_str().unwrap_or("Scheduled Report").to_string(),
                    v["kind"].as_str().unwrap_or("executive_status").to_string(),
                    v["scope"].as_str().unwrap_or("global").to_string(),
                    v["format"].as_str().unwrap_or("json").to_string(),
                    cadence.to_string(),
                    v["target"]
                        .as_str()
                        .unwrap_or("ops@wardex.local")
                        .to_string(),
                    v.get("next_run_at")
                        .and_then(|value| value.as_str())
                        .map(std::string::ToString::to_string),
                    v["status"].as_str().unwrap_or("active").to_string(),
                    has_execution_context.then_some(execution_context),
                );
                json_response(
                    &serde_json::json!({"status": "saved", "schedule": schedule}).to_string(),
                    201,
                )
            }
            Err(e) => error_json(&e, 400),
        },
        (Method::Get, "/api/inbox") => {
            let mut s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let items = build_operator_inbox(&mut s);
            json_response(
                &serde_json::json!({"items": items, "count": s.support_store.inbox_items().len()})
                    .to_string(),
                200,
            )
        }
        (Method::Post, "/api/inbox/ack") => match read_json_value(body, 4096) {
            Ok(v) => {
                let Some(item_id) = v.get("id").and_then(|value| value.as_str()) else {
                    return error_json("id is required", 400);
                };
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match s.support_store.acknowledge_inbox(item_id) {
                    Some(item) => json_response(
                        &serde_json::json!({"status": "acknowledged", "item": item}).to_string(),
                        200,
                    ),
                    None => error_json("inbox item not found", 404),
                }
            }
            Err(e) => error_json(&e, 400),
        },

        // ── SIEM Status ──────────────────────────────────────────
        (Method::Get, "/api/siem/status") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let status = s.siem_connector.status();
            match serde_json::to_string(&status) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/siem/config") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let status = s.siem_connector.status();
            let cfg = s.siem_connector.config();
            let payload = serde_json::json!({
                "config": crate::siem::public_config_json(cfg),
                "validation": siem_config_validation_json(cfg, status.last_error.as_deref()),
            });
            match serde_json::to_string(&payload) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Post, "/api/siem/config") => {
            let body = read_body_limited(body, 4096);
            match body {
                Ok(b) => match serde_json::from_str::<crate::siem::SiemConfig>(&b) {
                    Ok(new_cfg) => {
                        let mut s = state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let new_cfg = match normalize_siem_config_update(&s.config.siem, new_cfg) {
                            Ok(config) => config,
                            Err(error) => return error_json(&error, 400),
                        };
                        let mut next_config = s.config.clone();
                        next_config.siem = new_cfg.clone();
                        if let Err(e) = persist_config_to_path(&next_config, &s.config_path) {
                            error_json(&e, 500)
                        } else {
                            s.config = next_config;
                            s.siem_connector.update_config(new_cfg.clone());
                            let payload = serde_json::json!({
                                "status": "saved",
                                "config": crate::siem::public_config_json(&new_cfg),
                                "validation": siem_config_validation_json(&new_cfg, None),
                            });
                            json_response(&payload.to_string(), 200)
                        }
                    }
                    Err(e) => error_json(&format!("invalid SIEM config: {e}"), 400),
                },
                Err(e) => error_json(&e, 400),
            }
        }
        (Method::Post, "/api/siem/validate") => {
            let body = read_body_limited(body, 4096);
            match body {
                Ok(b) => match serde_json::from_str::<crate::siem::SiemConfig>(&b) {
                    Ok(candidate) => {
                        let s = state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        match normalize_siem_config_update(&s.config.siem, candidate) {
                            Ok(config) => {
                                let payload = serde_json::json!({
                                    "success": true,
                                    "config": crate::siem::public_config_json(&config),
                                    "validation": siem_config_validation_json(&config, None),
                                });
                                json_response(&payload.to_string(), 200)
                            }
                            Err(error) => error_json(&error, 400),
                        }
                    }
                    Err(e) => error_json(&format!("invalid SIEM config: {e}"), 400),
                },
                Err(e) => error_json(&e, 400),
            }
        }
        (Method::Get, "/api/taxii/status") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let status = s.taxii_client.status();
            match serde_json::to_string(&status) {
                Ok(j) => json_response(&j, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/taxii/config") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                            let mut s = state
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let mut s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let mut s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            s.agent_registry.refresh_staleness();
            let agents = s.agent_registry.list();
            let heartbeat_interval = s.agent_registry.heartbeat_interval();
            let mut counts = HashMap::new();
            for agent in agents.iter().copied() {
                let (status, _) = computed_agent_status(agent, heartbeat_interval);
                *counts.entry(status).or_insert(0usize) += 1;
            }
            let local_agent = local_console_identity(&s);
            let (local_status, _) = computed_agent_status(&local_agent, heartbeat_interval);
            *counts.entry(local_status).or_insert(0usize) += 1;
            let total_agents = agents.len() + 1;
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
                    "total_agents": total_agents,
                    "status_counts": counts,
                    "coverage_pct": if total_agents == 0 { 0.0 } else { (online_count as f32 / total_agents as f32) * 100.0 },
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
                    "campaign": summarize_deployment_campaign(&s),
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
            let mut s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            s.agent_registry.refresh_staleness();
            let analytics = s.event_store.analytics();
            let api_analytics = s.api_analytics.summary();
            let connector_status_entries =
                crate::server_collectors::full_collector_status_entries(&s);
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
                &connector_status_entries,
                s.asset_inventory.all(),
                &s.rbac,
                &s.enterprise,
                &s.detection_feedback,
                &s.playbook_engine,
                &s.playbook_dsl,
                &s.workflow_store,
                &api_analytics,
            );
            match serde_json::to_string(&overview) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/manager/overview") => {
            let mut s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        (Method::Get, "/api/manager/queue-digest") => handle_manager_queue_digest(state),
        (Method::Get, "/api/onboarding/readiness") => handle_onboarding_readiness(state),
        (Method::Get, "/api/command/summary") => {
            let mut s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let payload = command_summary_payload(&mut s);
            json_response(&payload.to_string(), 200)
        }
        (Method::Get, "/api/hunts") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                        "lifecycle": hunt.lifecycle,
                        "canary_percentage": hunt.canary_percentage,
                        "pack_id": hunt.pack_id,
                        "recommended_workflows": hunt.recommended_workflows,
                        "target_group": hunt.target_group,
                        "severity": hunt.severity,
                        "threshold": hunt.threshold,
                        "suppression_window_secs": hunt.suppression_window_secs,
                        "schedule_interval_secs": hunt.schedule_interval_secs,
                        "schedule_cron": hunt.schedule_cron,
                        "hypothesis": hunt.hypothesis,
                        "expected_outcome": hunt.expected_outcome,
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
                        let lifecycle = match v
                            .get("lifecycle")
                            .and_then(|value| value.as_str())
                            .unwrap_or("draft")
                        {
                            "test" => crate::enterprise::ContentLifecycle::Test,
                            "canary" => crate::enterprise::ContentLifecycle::Canary,
                            "active" => crate::enterprise::ContentLifecycle::Active,
                            "deprecated" => crate::enterprise::ContentLifecycle::Deprecated,
                            "rolled_back" => crate::enterprise::ContentLifecycle::RolledBack,
                            _ => crate::enterprise::ContentLifecycle::Draft,
                        };
                        let recommended_workflows = v
                            .get("recommended_workflows")
                            .and_then(|value| value.as_array())
                            .map(|values| {
                                values
                                    .iter()
                                    .filter_map(|value| {
                                        value.as_str().map(std::string::ToString::to_string)
                                    })
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default();
                        let requested_pack_id = v
                            .get("pack_id")
                            .and_then(|value| value.as_str())
                            .map(std::string::ToString::to_string);
                        let requested_target_group = v
                            .get("target_group")
                            .and_then(|value| value.as_str())
                            .map(std::string::ToString::to_string);
                        let pack_id_field_present = v.get("pack_id").is_some();
                        let target_group_field_present = v.get("target_group").is_some();
                        let workflow_field_present = v.get("recommended_workflows").is_some();
                        let mut s = state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let existing_hunt = v["id"].as_str().and_then(|hunt_id| {
                            s.enterprise
                                .hunts()
                                .iter()
                                .find(|hunt| hunt.id == hunt_id)
                                .cloned()
                        });
                        let pack_id = if pack_id_field_present {
                            requested_pack_id.clone()
                        } else {
                            existing_hunt.as_ref().and_then(|hunt| hunt.pack_id.clone())
                        };
                        let inherited_pack = pack_id.as_ref().and_then(|pack_id| {
                            s.enterprise
                                .packs()
                                .iter()
                                .find(|pack| pack.id == pack_id.as_str())
                                .cloned()
                        });
                        let target_group = if target_group_field_present {
                            requested_target_group.clone()
                        } else {
                            existing_hunt
                                .as_ref()
                                .and_then(|hunt| hunt.target_group.clone())
                                .or_else(|| {
                                    inherited_pack
                                        .as_ref()
                                        .and_then(|pack| pack.target_group.clone())
                                })
                        };
                        let effective_target_group = target_group
                            .clone()
                            .or_else(|| {
                                existing_hunt
                                    .as_ref()
                                    .and_then(|hunt| hunt.target_group.clone())
                            })
                            .or_else(|| {
                                inherited_pack
                                    .as_ref()
                                    .and_then(|pack| pack.target_group.clone())
                            });
                        if let Err(message) = ensure_target_group_access(
                            &auth_identity,
                            effective_target_group.as_deref(),
                        ) {
                            return error_json(&message, 403);
                        }
                        let persisted_workflows = if workflow_field_present {
                            recommended_workflows
                        } else {
                            existing_hunt
                                .as_ref()
                                .map(|hunt| hunt.recommended_workflows.clone())
                                .filter(|workflows| !workflows.is_empty())
                                .or_else(|| {
                                    inherited_pack
                                        .as_ref()
                                        .map(|pack| pack.recommended_workflows.clone())
                                })
                                .unwrap_or_default()
                        };
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
                            v.get("schedule_cron")
                                .and_then(|value| value.as_str())
                                .map(std::string::ToString::to_string),
                            query,
                            v.get("hypothesis")
                                .and_then(|value| value.as_str())
                                .unwrap_or_default()
                                .to_string(),
                            match v
                                .get("expected_outcome")
                                .and_then(|value| value.as_str())
                                .unwrap_or("explore")
                            {
                                "confirm" => crate::enterprise::HuntExpectedOutcome::Confirm,
                                "refute" => crate::enterprise::HuntExpectedOutcome::Refute,
                                _ => crate::enterprise::HuntExpectedOutcome::Explore,
                            },
                            lifecycle,
                            v["canary_percentage"].as_u64().unwrap_or(100) as u8,
                            pack_id,
                            persisted_workflows,
                            target_group,
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let items = build_content_rules_view(&s.enterprise, &s.detection_feedback);
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
                            .is_some_and(|kind| kind.eq_ignore_ascii_case("sigma"));
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
                                .filter_map(|value| {
                                    value.as_str().map(std::string::ToString::to_string)
                                })
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    let mut s = state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if is_builtin {
                        match s.enterprise.update_builtin_metadata(
                            v["id"].as_str().unwrap_or(""),
                            v.get("owner")
                                .and_then(|value| value.as_str())
                                .map(std::string::ToString::to_string),
                            v.get("enabled").and_then(serde_json::Value::as_bool),
                            (!pack_ids.is_empty()).then_some(pack_ids),
                            v.get("false_positive_review")
                                .and_then(|value| value.as_str())
                                .map(std::string::ToString::to_string),
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
                                v.get("rationale").and_then(|value| value.as_str()).map(std::string::ToString::to_string),
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                            .filter_map(|value| {
                                value.as_str().map(std::string::ToString::to_string)
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let saved_searches = v
                    .get("saved_searches")
                    .and_then(|value| value.as_array())
                    .map(|values| {
                        values
                            .iter()
                            .filter_map(|value| {
                                value.as_str().map(std::string::ToString::to_string)
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let recommended_workflows = v
                    .get("recommended_workflows")
                    .and_then(|value| value.as_array())
                    .map(|values| {
                        values
                            .iter()
                            .filter_map(|value| {
                                value.as_str().map(std::string::ToString::to_string)
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let requested_target_group = v
                    .get("target_group")
                    .and_then(|value| value.as_str())
                    .map(std::string::ToString::to_string);
                let target_group_field_present = v.get("target_group").is_some();
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let existing_pack = v["id"].as_str().and_then(|pack_id| {
                    s.enterprise
                        .packs()
                        .iter()
                        .find(|pack| pack.id == pack_id)
                        .cloned()
                });
                let target_group = if target_group_field_present {
                    requested_target_group.clone()
                } else {
                    existing_pack
                        .as_ref()
                        .and_then(|pack| pack.target_group.clone())
                };
                let effective_target_group = target_group.clone().or_else(|| {
                    existing_pack
                        .as_ref()
                        .and_then(|pack| pack.target_group.clone())
                });
                if let Err(message) =
                    ensure_target_group_access(&auth_identity, effective_target_group.as_deref())
                {
                    return error_json(&message, 403);
                }
                let pack = s.enterprise.create_or_update_pack(
                    v["id"].as_str(),
                    v["name"].as_str().unwrap_or("Untitled Pack").to_string(),
                    v["description"].as_str().unwrap_or("").to_string(),
                    v.get("enabled")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(true),
                    rule_ids,
                    saved_searches,
                    recommended_workflows,
                    target_group,
                    v.get("rollout_notes")
                        .and_then(|value| value.as_str())
                        .map(std::string::ToString::to_string),
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let coverage = build_mitre_coverage(&s.enterprise, s.incident_store.list());
            json_response(&coverage.to_string(), 200)
        }
        (Method::Get, "/api/suppressions") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let suppression = s.enterprise.create_or_update_suppression(
                    v["id"].as_str(),
                    v["name"].as_str().unwrap_or("suppression").to_string(),
                    v.get("rule_id")
                        .and_then(|value| value.as_str())
                        .map(std::string::ToString::to_string),
                    v.get("hunt_id")
                        .and_then(|value| value.as_str())
                        .map(std::string::ToString::to_string),
                    v.get("hostname")
                        .and_then(|value| value.as_str())
                        .map(std::string::ToString::to_string),
                    v.get("agent_id")
                        .and_then(|value| value.as_str())
                        .map(std::string::ToString::to_string),
                    v.get("severity")
                        .and_then(|value| value.as_str())
                        .map(std::string::ToString::to_string),
                    v.get("text")
                        .and_then(|value| value.as_str())
                        .map(std::string::ToString::to_string),
                    v.get("expires_at")
                        .and_then(|value| value.as_str())
                        .map(std::string::ToString::to_string),
                    v["justification"]
                        .as_str()
                        .unwrap_or("operator suppression")
                        .to_string(),
                    auth_identity.actor().to_string(),
                    v.get("active")
                        .and_then(serde_json::Value::as_bool)
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            json_response(&serde_json::json!({"connectors": s.enterprise.connectors(), "count": s.enterprise.connectors().len()}).to_string(), 200)
        }
        (Method::Post, "/api/enrichments/connectors") => match read_json_value(body, 16 * 1024) {
            Ok(v) => {
                let metadata = v
                    .get("metadata")
                    .cloned()
                    .and_then(|value| serde_json::from_value::<HashMap<String, String>>(value).ok())
                    .unwrap_or_default();
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let connector = s.enterprise.create_or_update_connector(
                    v["id"].as_str(),
                    v["kind"].as_str().unwrap_or("custom").to_string(),
                    v["display_name"]
                        .as_str()
                        .unwrap_or("Connector")
                        .to_string(),
                    v.get("endpoint")
                        .and_then(|value| value.as_str())
                        .map(std::string::ToString::to_string),
                    v.get("auth_mode")
                        .and_then(|value| value.as_str())
                        .map(std::string::ToString::to_string),
                    v.get("enabled")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(true),
                    v.get("timeout_secs")
                        .and_then(serde_json::Value::as_u64)
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
        },
        (Method::Post, "/api/tickets/sync") => {
            let started = std::time::Instant::now();
            match read_json_value(body, 12 * 1024) {
                Ok(v) => {
                    let mut s = state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let sync = s.enterprise.sync_ticket(
                        v["provider"].as_str().unwrap_or("jira").to_string(),
                        v["object_kind"].as_str().unwrap_or("incident").to_string(),
                        v["object_id"].as_str().unwrap_or("").to_string(),
                        v.get("queue_or_project")
                            .and_then(|value| value.as_str())
                            .map(std::string::ToString::to_string),
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let providers = s.enterprise.idp_provider_summaries();
            let healthy = providers
                .iter()
                .filter(|provider| provider.validation.status == "ready")
                .count();
            let providers_json = providers
                .iter()
                .map(idp_provider_summary_public_json)
                .collect::<Vec<_>>();
            json_response(
                &serde_json::json!({
                    "providers": providers_json,
                    "count": s.enterprise.idp_providers().len(),
                    "healthy": healthy,
                })
                .to_string(),
                200,
            )
        }
        (Method::Post, "/api/idp/providers") => match read_json_value(body, 12 * 1024) {
            Ok(v) => {
                let mappings = v
                    .get("group_role_mappings")
                    .cloned()
                    .and_then(|value| serde_json::from_value::<HashMap<String, String>>(value).ok())
                    .unwrap_or_default();
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match s.enterprise.create_or_update_idp_provider(
                    v["id"].as_str(),
                    v["kind"].as_str().unwrap_or("oidc").to_string(),
                    v["display_name"]
                        .as_str()
                        .unwrap_or("Identity Provider")
                        .to_string(),
                    v.get("issuer_url")
                        .and_then(|value| value.as_str())
                        .map(std::string::ToString::to_string),
                    v.get("sso_url")
                        .and_then(|value| value.as_str())
                        .map(std::string::ToString::to_string),
                    v.get("client_id")
                        .and_then(|value| value.as_str())
                        .map(std::string::ToString::to_string),
                    v.get("client_secret")
                        .and_then(|value| value.as_str())
                        .map(std::string::ToString::to_string),
                    v.get("redirect_uri")
                        .and_then(|value| value.as_str())
                        .map(std::string::ToString::to_string),
                    v.get("entity_id")
                        .and_then(|value| value.as_str())
                        .map(std::string::ToString::to_string),
                    v.get("enabled")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(true),
                    mappings,
                ) {
                    Ok(provider) => {
                        let validation = s
                            .enterprise
                            .idp_provider_summaries()
                            .into_iter()
                            .find(|summary| summary.provider.id == provider.id)
                            .map_or_else(
                                || IdentityConfigValidation {
                                    status: if provider.enabled {
                                        "ready".to_string()
                                    } else {
                                        "disabled".to_string()
                                    },
                                    issues: Vec::new(),
                                    mapping_count: provider.group_role_mappings.len(),
                                },
                                |summary| summary.validation,
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
                            &serde_json::json!({
                                "status": "saved",
                                "provider": idp_provider_public_json(&provider),
                                "validation": validation,
                            })
                            .to_string(),
                            200,
                        )
                    }
                    Err(e) => error_json(&e, 400),
                }
            }
            Err(e) => error_json(&e, 400),
        },
        (Method::Get, "/api/scim/config") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            json_response(
                &serde_json::json!({"config": s.enterprise.scim(), "validation": s.enterprise.scim_validation()}).to_string(),
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
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                match s.enterprise.update_scim(
                    v.get("enabled")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(true),
                    v.get("base_url")
                        .and_then(|value| value.as_str())
                        .map(std::string::ToString::to_string),
                    v.get("bearer_token")
                        .and_then(|value| value.as_str())
                        .map(std::string::ToString::to_string),
                    v["provisioning_mode"]
                        .as_str()
                        .unwrap_or("automatic")
                        .to_string(),
                    v["default_role"].as_str().unwrap_or("viewer").to_string(),
                    mappings,
                ) {
                    Ok(config) => {
                        let validation = s.enterprise.scim_validation();
                        let _ = s.enterprise.record_change(
                            "scim",
                            "scim-config",
                            "Updated SCIM provisioning configuration",
                            auth_identity.actor(),
                            Some("scim-config".to_string()),
                            Some(&v.to_string()),
                        );
                        json_response(
                            &serde_json::json!({"status": "saved", "config": config, "validation": validation})
                                .to_string(),
                            200,
                        )
                    }
                    Err(e) => error_json(&e, 400),
                }
            }
            Err(e) => error_json(&e, 400),
        },
        (Method::Get, "/api/audit/admin") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let payload = serde_json::json!({
                "api_audit": s.audit_log.recent(200),
                "change_control": s.enterprise.change_control(),
                "response_audit": s.response_orchestrator.audit_ledger(),
                "response_approvals": s.approval_log.list(),
            });
            json_response(&payload.to_string(), 200)
        }
        (Method::Get, "/api/support/diagnostics") => {
            let mut s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        (Method::Get, "/api/support/readiness-evidence") => {
            let mut s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let payload = production_readiness_evidence(&mut s);
            let digest = crate::audit::sha256_hex(payload.to_string().as_bytes());
            json_response(
                &serde_json::json!({"evidence": payload, "digest": digest}).to_string(),
                200,
            )
        }
        (Method::Get, "/api/support/bundle") => {
            let mut s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = build_support_bundle(&mut s);
            let snapshot = persist_operational_snapshot(&s.storage, "support_bundle", &body);
            json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
        }
        (Method::Post, "/api/support/first-run-proof") => {
            first_run_operator_proof(state, &auth_identity)
        }
        (Method::Get, "/api/operational/snapshots") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let limit = url_param(&url, "limit")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(50);
            let body =
                list_operational_snapshots(&s.storage, url_param(&url, "kind").as_deref(), limit);
            json_response(&body.to_string(), 200)
        }
        (Method::Get, "/api/operational/snapshots/verify") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = verify_operational_snapshot(
                &s.storage,
                url_param(&url, "storage_key").as_deref(),
                url_param(&url, "digest").as_deref(),
            );
            json_response(&body.to_string(), 200)
        }
        (Method::Get, "/api/operational/snapshots/policy") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = build_snapshot_policy_payload(&s.storage);
            json_response(&body.to_string(), 200)
        }
        (Method::Post, "/api/operational/snapshots/prune") => {
            let payload = read_json_value(body, 8 * 1024).unwrap_or_else(|_| serde_json::json!({}));
            let keep_latest = payload
                .get("keep_latest_per_kind")
                .or_else(|| payload.get("keep_latest"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(25) as usize;
            let dry_run = payload
                .get("dry_run")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true);
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = prune_operational_snapshots(&s.storage, keep_latest, dry_run);
            json_response(&body.to_string(), 200)
        }
        (Method::Get, "/api/launchpad/evidence-pack") => {
            let mut s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let payload = build_launchpad_evidence_pack(&mut s);
            let digest = crate::audit::sha256_hex(payload.to_string().as_bytes());
            let snapshot =
                persist_operational_snapshot(&s.storage, "launchpad_evidence_pack", &payload);
            json_response(
                &serde_json::json!({"evidence": payload, "digest": digest, "snapshot": snapshot})
                    .to_string(),
                200,
            )
        }
        (Method::Get, "/api/launchpad/release-diff") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let payload = build_launchpad_release_diff(&s);
            let snapshot =
                persist_operational_snapshot(&s.storage, "launchpad_release_diff", &payload);
            json_response(&payload_with_snapshot(payload, snapshot).to_string(), 200)
        }
        (Method::Get, "/api/launchpad/demo-status") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let payload = build_launchpad_demo_status(&s);
            let snapshot =
                persist_operational_snapshot(&s.storage, "launchpad_demo_status", &payload);
            json_response(&payload_with_snapshot(payload, snapshot).to_string(), 200)
        }
        (Method::Post, "/api/launchpad/demo-reset") => {
            let mut s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let before = s.alerts.len();
            s.alerts.retain(|alert| {
                !(alert.platform == "sample"
                    || alert
                        .reasons
                        .iter()
                        .any(|reason| reason.contains("[SAMPLE]")))
            });
            let removed_alerts = before.saturating_sub(s.alerts.len());
            let status = build_launchpad_demo_status(&s);
            let snapshot =
                persist_operational_snapshot(&s.storage, "launchpad_demo_reset", &status);
            json_response(
                &serde_json::json!({
                    "status": "reset_recorded",
                    "removed_transient_alerts": removed_alerts,
                    "demo_status": status,
                    "snapshot": snapshot,
                })
                .to_string(),
                200,
            )
        }
        (Method::Get, "/api/release/doctor") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = release_doctor_payload(&s);
            let snapshot = persist_operational_snapshot(&s.storage, "release_doctor", &body);
            json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
        }
        (Method::Get, "/api/release/observability-gates") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = build_release_observability_gates(&s);
            let snapshot =
                persist_operational_snapshot(&s.storage, "release_observability_gates", &body);
            json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
        }
        (Method::Get, "/api/release/provenance") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = build_release_provenance(&s);
            let snapshot = persist_operational_snapshot(&s.storage, "release_provenance", &body);
            json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
        }
        (Method::Get, "/api/release/upgrade-rehearsal") => {
            let target = url_param(&url, "target_version").unwrap_or_default();
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = build_upgrade_rehearsal(&s, &target);
            let snapshot =
                persist_operational_snapshot(&s.storage, "release_upgrade_rehearsal", &body);
            json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
        }
        (Method::Get, "/api/release/clean-cut") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = build_clean_release_cut(&s);
            let snapshot = persist_operational_snapshot(&s.storage, "clean_release_cut", &body);
            json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
        }
        (Method::Get, "/api/containers/release-parity") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = build_container_release_parity(&s);
            let snapshot =
                persist_operational_snapshot(&s.storage, "container_release_parity", &body);
            json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
        }
        (Method::Get, "/api/release/verification-center") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = build_release_verification_center(&s);
            let snapshot =
                persist_operational_snapshot(&s.storage, "release_verification_center", &body);
            json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
        }
        (Method::Get, "/api/release/deployment-trust-report") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = build_deployment_trust_report(&s);
            let snapshot =
                persist_operational_snapshot(&s.storage, "deployment_trust_report", &body);
            json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
        }
        (Method::Get, "/api/deployment/self-hosted-wizard") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = build_self_hosted_deployment_wizard(&s);
            let snapshot =
                persist_operational_snapshot(&s.storage, "self_hosted_deployment_wizard", &body);
            json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
        }
        (Method::Get, "/api/data-quality/dashboard") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = build_data_quality_dashboard(&s);
            let snapshot =
                persist_operational_snapshot(&s.storage, "data_quality_dashboard", &body);
            json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
        }
        (Method::Get, "/api/performance/scale-baseline") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = build_performance_scale_baseline(&s);
            let snapshot =
                persist_operational_snapshot(&s.storage, "performance_scale_baseline", &body);
            json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
        }
        (Method::Get, "/api/cluster/failover-execution") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = build_cluster_failover_execution(&s);
            let snapshot =
                persist_operational_snapshot(&s.storage, "cluster_failover_execution", &body);
            json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
        }
        (Method::Get, "/api/secrets/rotation-operations") => {
            crate::server_secrets::handle_secrets_rotation_operations(state)
        }
        (Method::Get, "/api/operator/task-automation") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = build_operator_task_automation(&s);
            let snapshot =
                persist_operational_snapshot(&s.storage, "operator_task_automation", &body);
            json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
        }
        (Method::Get, "/api/detection/validation-packs") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = build_detection_validation_packs(&s);
            let snapshot =
                persist_operational_snapshot(&s.storage, "detection_validation_packs", &body);
            json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
        }
        (Method::Get, "/api/monitoring/synthetic-console") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = build_synthetic_console_monitor(&s);
            let snapshot =
                persist_operational_snapshot(&s.storage, "synthetic_console_monitor", &body);
            json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
        }
        (Method::Get, "/api/incidents/timeline-replay") => {
            let incident_id = url_param(&url, "incident_id");
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = build_incident_timeline_replay(&s, incident_id.as_deref());
            let snapshot =
                persist_operational_snapshot(&s.storage, "incident_timeline_replay", &body);
            json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
        }
        (Method::Get, "/api/detection/trust-score") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = build_detection_trust_score(&s);
            let snapshot = persist_operational_snapshot(&s.storage, "detection_trust_score", &body);
            json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
        }
        (Method::Get, "/api/fleet/drift-compliance") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = build_fleet_drift_compliance(&s);
            let snapshot =
                persist_operational_snapshot(&s.storage, "fleet_drift_compliance", &body);
            json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
        }
        (Method::Get, "/api/operator/work-queue") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = build_operator_work_queue(&s);
            let snapshot = persist_operational_snapshot(&s.storage, "operator_work_queue", &body);
            json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
        }
        (Method::Get, "/api/retention/forecast") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = build_retention_forecast(&s);
            let snapshot = persist_operational_snapshot(&s.storage, "retention_forecast", &body);
            json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
        }
        (Method::Get, "/api/search/performance-slo") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = build_search_performance_slo(&s);
            let snapshot =
                persist_operational_snapshot(&s.storage, "search_performance_slo", &body);
            json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
        }
        (Method::Get, "/api/validation/adversarial") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = build_adversarial_validation(&s);
            let snapshot =
                persist_operational_snapshot(&s.storage, "adversarial_validation", &body);
            json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
        }
        (Method::Get, "/api/support/bundle-diff") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = build_support_bundle_diff(&s);
            let snapshot = persist_operational_snapshot(&s.storage, "support_bundle_diff", &body);
            json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
        }
        (Method::Post, "/api/demo/lab") => first_run_operator_proof(state, &auth_identity),
        (Method::Get, "/api/workflows/preflight") => {
            let workflow = url_param(&url, "workflow").unwrap_or_else(|| "release".to_string());
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = build_workflow_preflight(&s, &workflow);
            let snapshot = persist_operational_snapshot(&s.storage, "workflow_preflight", &body);
            json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
        }
        (Method::Get, "/api/tenants/isolation-proof") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = build_tenant_isolation_proof(&s);
            let snapshot =
                persist_operational_snapshot(&s.storage, "tenant_isolation_proof", &body);
            json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
        }
        (Method::Get, "/api/processes/thread-proof") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = build_thread_detection_proof(&s);
            let snapshot =
                persist_operational_snapshot(&s.storage, "thread_detection_proof", &body);
            json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
        }
        (Method::Get, "/api/support/parity") => {
            let payload = crate::support_center::support_parity(env!("CARGO_PKG_VERSION"));
            json_response(&payload.to_string(), 200)
        }
        (Method::Get, "/api/response/approval-overview") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = build_response_approval_overview(&s);
            let snapshot =
                persist_operational_snapshot(&s.storage, "response_approval_overview", &body);
            json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
        }
        (Method::Get, "/api/remediation/safety") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = build_remediation_safety_status(&s);
            let snapshot = persist_operational_snapshot(&s.storage, "remediation_safety", &body);
            json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
        }
        (Method::Get, "/api/ws/health") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let stats = s.alert_broadcaster.stats();
            let dropped = stats
                .get("dropped_events")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or_default();
            let queue_depth = stats
                .get("subscriber_queue_depth")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or_default();
            let readiness = stream_readiness_payload(stats.clone());
            json_response(
                &serde_json::json!({
                    "generated_at": chrono::Utc::now().to_rfc3339(),
                    "status": if dropped > 0 || queue_depth > 100 { "backpressure" } else { "healthy" },
                    "stats": stats,
                    "readiness": readiness,
                    "latency_slo_ms": 1000,
                    "backpressure_threshold": 100,
                })
                .to_string(),
                200,
            )
        }
        (Method::Get, "/api/stream/readiness") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = stream_readiness_payload(s.alert_broadcaster.stats());
            let snapshot = persist_operational_snapshot(&s.storage, "stream_readiness", &body);
            json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
        }
        (Method::Get, "/api/stream/reliability-lab") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = stream_reliability_lab_payload(s.alert_broadcaster.stats());
            let snapshot =
                persist_operational_snapshot(&s.storage, "stream_reliability_lab", &body);
            json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
        }
        (Method::Get, "/api/sdk/contract-status") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let body = build_sdk_contract_status(&s);
            let snapshot = persist_operational_snapshot(&s.storage, "sdk_contract_status", &body);
            json_response(&payload_with_snapshot(body, snapshot).to_string(), 200)
        }
        (Method::Post, "/api/subscriptions") => {
            #[derive(serde::Deserialize)]
            struct SubscriptionRequest {
                lanes: Option<Vec<String>>,
                filters: Option<serde_json::Value>,
            }
            let body = match read_body_limited(body, 16 * 1024) {
                Ok(raw) if raw.trim().is_empty() => SubscriptionRequest {
                    lanes: None,
                    filters: None,
                },
                Ok(raw) => match serde_json::from_str::<SubscriptionRequest>(&raw) {
                    Ok(value) => value,
                    Err(err) => {
                        return error_json(&format!("invalid subscription request: {err}"), 400);
                    }
                },
                Err(err) => return error_json(&err, 413),
            };
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let lanes = body
                .lanes
                .filter(|items| !items.is_empty())
                .unwrap_or_else(|| vec!["alerts".to_string()]);
            let filters = body.filters.unwrap_or_else(|| serde_json::json!({}));
            let subscription_id = subscription_id_for(&lanes, &filters);
            let now = chrono::Utc::now();
            let expires_at = now + chrono::Duration::days(7);
            let payload = serde_json::json!({
                "status": "created",
                "subscription_id": subscription_id,
                "lanes": lanes,
                "filters": filters,
                "cursor": s.alerts.len().to_string(),
                "created_at": now.to_rfc3339(),
                "updated_at": now.to_rfc3339(),
                "expires_at": expires_at.to_rfc3339(),
                "durable": true,
                "current_high_watermark": s.alerts.len(),
                "retention_floor": 0,
                "retention_window": "current_alert_buffer",
            });
            let cursor_store = persist_subscription_cursor(&s.storage, &payload);
            let snapshot =
                persist_operational_snapshot(&s.storage, "subscription_cursor", &payload);
            json_response(
                &serde_json::json!({ "subscription": payload, "cursor_store": cursor_store, "snapshot": snapshot }).to_string(),
                200,
            )
        }
        (Method::Get, "/api/subscriptions/resume") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let subscription_id = url_param(&url, "subscription_id")
                .and_then(|value| safe_subscription_id(&value))
                .unwrap_or_else(|| "ad-hoc".to_string());
            let stored_cursor = read_subscription_cursor(&s.storage, &subscription_id);
            let requested_cursor = url_param(&url, "cursor")
                .and_then(|value| value.parse::<usize>().ok())
                .or_else(|| {
                    stored_cursor
                        .as_ref()
                        .and_then(|cursor| cursor.get("cursor"))
                        .and_then(serde_json::Value::as_str)
                        .and_then(|value| value.parse::<usize>().ok())
                })
                .unwrap_or(0);
            let cursor = requested_cursor.min(s.alerts.len());
            let gap_detected = requested_cursor > s.alerts.len();
            let replay_gap = requested_cursor.saturating_sub(s.alerts.len());
            let limit = url_param(&url, "limit")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(100)
                .clamp(1, 1000);
            let events = s
                .alerts
                .iter()
                .enumerate()
                .skip(cursor)
                .take(limit)
                .map(|(index, alert)| {
                    serde_json::json!({
                        "cursor": (index + 1).to_string(),
                        "lane": "alerts",
                        "event_type": "alert",
                        "data": alert_json_value(alert, index, "", &[]),
                    })
                })
                .collect::<Vec<_>>();
            let next_cursor = cursor + events.len();
            let now = chrono::Utc::now();
            let expires_at = now + chrono::Duration::days(7);
            let cursor_record = serde_json::json!({
                "status": if gap_detected { "gap_detected" } else { "resumed" },
                "subscription_id": subscription_id.clone(),
                "lanes": stored_cursor
                    .as_ref()
                    .and_then(|cursor| cursor.get("lanes"))
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!(["alerts"])),
                "filters": stored_cursor
                    .as_ref()
                    .and_then(|cursor| cursor.get("filters"))
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({})),
                "cursor": next_cursor.to_string(),
                "created_at": stored_cursor
                    .as_ref()
                    .and_then(|cursor| cursor.get("created_at"))
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!(now.to_rfc3339())),
                "updated_at": now.to_rfc3339(),
                "expires_at": expires_at.to_rfc3339(),
                "durable": subscription_id != "ad-hoc",
                "current_high_watermark": s.alerts.len(),
                "retention_floor": 0,
                "retention_window": "current_alert_buffer",
                "last_replay_count": events.len(),
                "gap_detected": gap_detected,
                "replay_gap": replay_gap,
            });
            let cursor_store = if subscription_id == "ad-hoc" {
                serde_json::json!({ "persisted": false, "reason": "ad_hoc_subscription" })
            } else {
                persist_subscription_cursor(&s.storage, &cursor_record)
            };
            json_response(
                &serde_json::json!({
                    "subscription_id": subscription_id,
                    "cursor": cursor.to_string(),
                    "requested_cursor": requested_cursor.to_string(),
                    "next_cursor": next_cursor.to_string(),
                    "events": events,
                    "has_more": next_cursor < s.alerts.len(),
                    "gap_detected": gap_detected,
                    "replay_gap": replay_gap,
                    "retention_floor": 0,
                    "current_high_watermark": s.alerts.len(),
                    "durable": subscription_id != "ad-hoc",
                    "cursor_store": cursor_store,
                    "expired": false,
                })
                .to_string(),
                200,
            )
        }
        (Method::Get, "/api/docs/index") => {
            let payload = crate::support_center::docs_index(
                env!("CARGO_PKG_VERSION"),
                url_param(&url, "q").as_deref(),
                url_param(&url, "section").as_deref(),
                url_param(&url, "limit")
                    .and_then(|value| value.parse::<usize>().ok())
                    .unwrap_or(24),
            );
            json_response(&payload.to_string(), 200)
        }
        (Method::Get, "/api/docs/content") => {
            let Some(path) = url_param(&url, "path") else {
                return error_json("path query parameter required", 400);
            };
            match crate::support_center::doc_content(env!("CARGO_PKG_VERSION"), &path) {
                Some(payload) => json_response(&payload.to_string(), 200),
                None => error_json("document not found", 404),
            }
        }
        (Method::Get, "/api/system/health/dependencies") => {
            let mut s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let backup_status = BackupStatusSnapshot::gather();
            let control_plane = ControlPlanePostureSnapshot::gather(&s, &backup_status);
            let payload = serde_json::json!({
                "storage": {
                    "backend": if s.event_store.has_persistence() { "json_file" } else { "memory" },
                    "durable": s.event_store.has_persistence(),
                    "path": s.event_store.storage_path(),
                    "event_count": s.event_store.total_events(),
                },
                "ha_mode": control_plane.ha_mode_payload(),
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match serde_json::to_string(s.update_manager.list_releases()) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }

        (Method::Post, "/api/shutdown") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                .header(
                    "Access-Control-Allow-Headers",
                    "Content-Type, Authorization",
                )
                .body(Body::empty())
                .unwrap_or_else(|_| Response::new(Body::empty()))
        }

        // ── Sigma Detection Engine ────────────────────────────────
        (Method::Get, "/api/sigma/rules") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let mut s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let before = s.dead_letter_queue.len();
            s.dead_letter_queue.clear();
            json_response(&serde_json::json!({"cleared": before}).to_string(), 200)
        }

        // ── Response Orchestration ────────────────────────────────
        (Method::Get, "/api/response/pending") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let pending = s.response_orchestrator.pending_requests();
            let items: Vec<serde_json::Value> = pending.iter().map(response_request_json).collect();
            json_response(
                &serde_json::json!({"pending": items, "count": items.len()}).to_string(),
                200,
            )
        }
        (Method::Get, "/api/response/requests") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let ledger = s.response_orchestrator.audit_ledger();
            let entries: Vec<serde_json::Value> = ledger
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "request_id": e.request_id.clone(),
                        "action": e.action.clone(),
                        "target": e.target_hostname.clone(),
                        "outcome": format!("{:?}", e.status),
                        "timestamp": e.timestamp.clone(),
                        "approvers": e.approvals.clone(),
                        "actor": e.actor.clone(),
                        "reason": e.reason.clone(),
                        "input_context": e.input_context.clone(),
                        "dry_run_result": e.dry_run_result.clone(),
                        "execution_result": e.execution_result.clone(),
                        "execution_audit": e.execution_audit.clone(),
                        "reversal_path": e.reversal_path.clone(),
                    })
                })
                .collect();
            json_response(&serde_json::json!({"audit_log": entries}).to_string(), 200)
        }
        (Method::Get, "/api/response/execution-audit") => {
            let request_id = url_param(&url, "request_id");
            let action_id = url_param(&url, "action_id");
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let audits = s
                .response_orchestrator
                .execution_audits_filtered(request_id.as_deref(), action_id.as_deref());
            json_response(
                &serde_json::json!({
                    "request_id": request_id,
                    "action_id": action_id,
                    "count": audits.len(),
                    "audits": audits,
                })
                .to_string(),
                200,
            )
        }
        (Method::Get, "/api/response/stats") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                let items: Vec<serde_json::Value> = procs
                    .iter()
                    .map(|p| {
                        serde_json::json!({
                            "pid": p.pid, "ppid": p.ppid, "name": p.name,
                            "user": p.user, "group": p.group,
                            "cpu_percent": p.cpu_percent, "mem_percent": p.mem_percent,
                        })
                    })
                    .collect();
                let total_cpu: f32 = procs.iter().map(|p| p.cpu_percent).sum();
                let total_mem: f32 = procs.iter().map(|p| p.mem_percent).sum();
                json_response(
                    &serde_json::json!({
                        "processes": items, "count": items.len(),
                        "total_cpu_percent": (total_cpu * 10.0).round() / 10.0,
                        "total_mem_percent": (total_mem * 10.0).round() / 10.0,
                        "platform": "macos",
                    })
                    .to_string(),
                    200,
                )
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
                            if f.len() >= 3
                                && let Ok(pid) = f[0].parse::<u32>()
                            {
                                let cpu: f32 = f[1].parse().unwrap_or(0.0);
                                let mem: f32 = f[2].parse().unwrap_or(0.0);
                                map.insert(pid, (cpu, mem));
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
                let total_cpu: f32 = items
                    .iter()
                    .map(|i| i["cpu_percent"].as_f64().unwrap_or(0.0) as f32)
                    .sum();
                let total_mem: f32 = items
                    .iter()
                    .map(|i| i["mem_percent"].as_f64().unwrap_or(0.0) as f32)
                    .sum();
                json_response(
                    &serde_json::json!({
                        "processes": items, "count": items.len(),
                        "total_cpu_percent": (total_cpu * 10.0).round() / 10.0,
                        "total_mem_percent": (total_mem * 10.0).round() / 10.0,
                        "platform": "linux",
                    })
                    .to_string(),
                    200,
                )
            }
            #[cfg(target_os = "windows")]
            {
                let procs = crate::collector_windows::collect_processes();
                let items: Vec<serde_json::Value> = procs
                    .iter()
                    .map(|p| {
                        serde_json::json!({
                            "pid": p.pid, "ppid": p.ppid, "name": p.name,
                            "user": if p.user.is_empty() { "—" } else { &p.user },
                            "group": "—",
                            "cpu_percent": 0.0, "mem_percent": 0.0,
                        })
                    })
                    .collect();
                json_response(
                    &serde_json::json!({
                        "processes": items, "count": items.len(),
                        "total_cpu_percent": 0.0,
                        "total_mem_percent": 0.0,
                        "platform": "windows",
                    })
                    .to_string(),
                    200,
                )
            }
            #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
            {
                json_response(
                    r#"{"processes":[],"count":0,"message":"Unsupported platform"}"#,
                    200,
                )
            }
        }
        (Method::Get, "/api/processes/analysis") => {
            #[cfg(target_os = "macos")]
            {
                let procs = crate::collector_macos::collect_processes();
                let findings = crate::collector_macos::analyze_processes(&procs);
                let items: Vec<serde_json::Value> = findings
                    .iter()
                    .map(|f| {
                        serde_json::json!({
                            "pid": f.pid, "name": f.name, "user": f.user,
                            "risk_level": f.risk_level, "reason": f.reason,
                            "cpu_percent": f.cpu_percent, "mem_percent": f.mem_percent,
                        })
                    })
                    .collect();
                let critical = findings
                    .iter()
                    .filter(|f| f.risk_level == "critical")
                    .count();
                let severe = findings.iter().filter(|f| f.risk_level == "severe").count();
                let elevated = findings
                    .iter()
                    .filter(|f| f.risk_level == "elevated")
                    .count();
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
                let items: Vec<serde_json::Value> = findings
                    .iter()
                    .map(|f| {
                        serde_json::json!({
                            "pid": f.pid, "name": f.name, "user": f.user,
                            "risk_level": f.risk_level, "reason": f.reason,
                            "cpu_percent": f.cpu_percent, "mem_percent": f.mem_percent,
                        })
                    })
                    .collect();
                let critical = findings
                    .iter()
                    .filter(|f| f.risk_level == "critical")
                    .count();
                let severe = findings.iter().filter(|f| f.risk_level == "severe").count();
                let elevated = findings
                    .iter()
                    .filter(|f| f.risk_level == "elevated")
                    .count();
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
                let items: Vec<serde_json::Value> = findings
                    .iter()
                    .map(|f| {
                        serde_json::json!({
                            "pid": f.pid, "name": f.name, "user": f.user,
                            "risk_level": f.risk_level, "reason": f.reason,
                            "cpu_percent": f.cpu_percent, "mem_percent": f.mem_percent,
                        })
                    })
                    .collect();
                let critical = findings
                    .iter()
                    .filter(|f| f.risk_level == "critical")
                    .count();
                let severe = findings.iter().filter(|f| f.risk_level == "severe").count();
                let elevated = findings
                    .iter()
                    .filter(|f| f.risk_level == "elevated")
                    .count();
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
                json_response(
                    r#"{"findings":[],"total":0,"status":"clean","message":"Unsupported platform"}"#,
                    200,
                )
            }
        }
        (Method::Get, "/api/processes/detail") => {
            if let Some(pid) = url_param(&url, "pid").and_then(|value| value.parse::<u32>().ok()) {
                let hostname = {
                    let s = state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    s.local_host_info.hostname.clone()
                };
                match process_detail_json(pid, &hostname) {
                    Some(detail) => json_response(&detail.to_string(), 200),
                    None => error_json("process not found", 404),
                }
            } else {
                error_json("pid query parameter required", 400)
            }
        }
        (Method::Get, "/api/processes/threads") => {
            if let Some(pid) = url_param(&url, "pid").and_then(|value| value.parse::<u32>().ok()) {
                let hostname = {
                    let s = state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    s.local_host_info.hostname.clone()
                };
                match process_threads_json(pid, &hostname) {
                    Some(detail) => json_response(&detail.to_string(), 200),
                    None => error_json("process not found", 404),
                }
            } else {
                error_json("pid query parameter required", 400)
            }
        }
        (Method::Get, "/api/host/apps") => {
            #[cfg(target_os = "macos")]
            {
                let apps = crate::collector_macos::collect_installed_apps();
                let items: Vec<serde_json::Value> = apps
                    .iter()
                    .map(|a| {
                        serde_json::json!({
                            "name": a.name, "path": a.path, "version": a.version,
                            "bundle_id": a.bundle_id, "size_mb": (a.size_mb * 10.0).round() / 10.0,
                            "last_modified": a.last_modified,
                        })
                    })
                    .collect();
                json_response(
                    &serde_json::json!({
                        "apps": items, "count": items.len(), "platform": "macos",
                    })
                    .to_string(),
                    200,
                )
            }
            #[cfg(target_os = "linux")]
            {
                let apps = crate::collector_linux::collect_installed_apps();
                let items: Vec<serde_json::Value> = apps
                    .iter()
                    .map(|a| {
                        serde_json::json!({
                            "name": a.name, "path": a.path, "version": a.version,
                            "bundle_id": a.bundle_id, "size_mb": (a.size_mb * 10.0).round() / 10.0,
                            "last_modified": a.last_modified,
                        })
                    })
                    .collect();
                json_response(
                    &serde_json::json!({
                        "apps": items, "count": items.len(), "platform": "linux",
                    })
                    .to_string(),
                    200,
                )
            }
            #[cfg(target_os = "windows")]
            {
                let apps = crate::collector_windows::collect_installed_apps();
                let items: Vec<serde_json::Value> = apps
                    .iter()
                    .map(|a| {
                        serde_json::json!({
                            "name": a.name, "path": a.path, "version": a.version,
                            "bundle_id": a.bundle_id, "size_mb": (a.size_mb * 10.0).round() / 10.0,
                            "last_modified": a.last_modified,
                        })
                    })
                    .collect();
                json_response(
                    &serde_json::json!({
                        "apps": items, "count": items.len(), "platform": "windows",
                    })
                    .to_string(),
                    200,
                )
            }
            #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
            {
                json_response(
                    r#"{"apps":[],"count":0,"message":"Unsupported platform"}"#,
                    200,
                )
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        (Method::Get, "/api/admin/rbac-coverage" | "/api/rbac/coverage") => {
            json_response(&rbac_coverage_payload().to_string(), 200)
        }

        (Method::Get, "/api/rbac/users") => {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                            let token = generate_token();
                            let user = User {
                                username: username.clone(),
                                role,
                                token_hash: token.clone(),
                                enabled: true,
                                created_at: chrono::Utc::now().to_rfc3339(),
                                tenant_id: None,
                            };
                            let s = state
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                let s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let params = parse_query_string(&url);
            let status = url_param(&url, "status");
            let priority = url_param(&url, "priority");
            let assignee = url_param(&url, "assignee");
            let limit = params
                .get("limit")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(100)
                .min(1000);
            let offset = params
                .get("offset")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(0);
            let cases = s.case_store.list_filtered(
                status.as_deref(),
                priority.as_deref(),
                assignee.as_deref(),
            );
            let total = cases.len();
            let items: Vec<serde_json::Value> = cases
                .iter()
                .skip(offset)
                .take(limit)
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
                &serde_json::json!({"cases": items, "total": total, "limit": limit, "offset": offset}).to_string(),
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
                            .map(|a| a.iter().filter_map(serde_json::Value::as_u64).collect())
                            .unwrap_or_default();
                        let evt_ids: Vec<u64> = v["event_ids"]
                            .as_array()
                            .map(|a| a.iter().filter_map(serde_json::Value::as_u64).collect())
                            .unwrap_or_default();
                        let tags: Vec<String> = v["tags"]
                            .as_array()
                            .map(|a| {
                                a.iter()
                                    .filter_map(|x| x.as_str().map(String::from))
                                    .collect()
                            })
                            .unwrap_or_default();
                        let mut s = state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                        let mut s = state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                            let mut s = state
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
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

        // ── Analyst Assistant ──────────────────────────────
        (Method::Get, "/api/assistant/status") => {
            let assistant = {
                let s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                Arc::clone(&s.llm_analyst)
            };
            let status = assistant
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .status();
            let payload = assistant_status_response(&status);
            json_response(
                &serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string()),
                200,
            )
        }
        (Method::Post, "/api/assistant/query") => {
            let started = std::time::Instant::now();
            match read_json_body::<AssistantQueryRequest>(body, 16 * 1024) {
                Ok(mut request) => {
                    request.question = request.question.trim().to_string();
                    request.investigation_id =
                        assistant_normalize_optional(request.investigation_id);
                    request.source = assistant_normalize_optional(request.source);
                    if request.question.is_empty() {
                        error_json("question is required", 400)
                    } else {
                        let (assistant, scope, case_context, context_events) = {
                            let s = state
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            let investigation = match request.investigation_id.as_deref() {
                                Some(investigation_id) => {
                                    match s.workflow_store.get_snapshot(investigation_id) {
                                        Some(snapshot) => Some(snapshot),
                                        None => return error_json("investigation not found", 404),
                                    }
                                }
                                None => None,
                            };
                            let incident = match request.incident_id {
                                Some(incident_id) => {
                                    match s.incident_store.get(incident_id).cloned() {
                                        Some(incident) => Some(incident),
                                        None => return error_json("incident not found", 404),
                                    }
                                }
                                None => None,
                            };
                            let investigation_case_id = match investigation
                                .as_ref()
                                .and_then(|snapshot| snapshot.case_id.as_deref())
                            {
                                Some(raw_case_id) => {
                                    let trimmed = raw_case_id.trim();
                                    if trimmed.is_empty() {
                                        None
                                    } else {
                                        match trimmed.parse::<u64>() {
                                            Ok(parsed) => Some(parsed),
                                            Err(_) => {
                                                return error_json(
                                                    "investigation scope has an invalid case reference",
                                                    400,
                                                );
                                            }
                                        }
                                    }
                                }
                                None => None,
                            };
                            if let (Some(case_id), Some(linked_case_id)) =
                                (request.case_id, investigation_case_id)
                                && case_id != linked_case_id
                            {
                                return error_json(
                                    "case scope conflicts with investigation scope",
                                    400,
                                );
                            }
                            let resolved_case_id = request.case_id.or(investigation_case_id);
                            let case = match resolved_case_id {
                                Some(case_id) => match s.case_store.get(case_id).cloned() {
                                    Some(case) => Some(case),
                                    None => return error_json("case not found", 404),
                                },
                                None => None,
                            };
                            if let (Some(incident), Some(case)) = (incident.as_ref(), case.as_ref())
                                && !case.incident_ids.contains(&incident.id)
                            {
                                return error_json(
                                    "incident scope is not linked to the selected case",
                                    400,
                                );
                            }

                            let mut scoped_event_ids = case
                                .as_ref()
                                .map(|entry| entry.event_ids.clone())
                                .unwrap_or_default();
                            if let Some(incident) = incident.as_ref() {
                                scoped_event_ids.extend(incident.event_ids.iter().copied());
                            }
                            let linked_events = assistant_linked_events_by_ids(
                                &scoped_event_ids,
                                &s.event_store,
                                request.limit.unwrap_or(8).clamp(1, 20),
                            );
                            let case_context = case.map(|case| AssistantCaseContext {
                                case,
                                linked_events: linked_events.clone(),
                            });
                            let scope_event_ids = (!scoped_event_ids.is_empty())
                                .then(|| scoped_event_ids.iter().copied().collect::<HashSet<_>>());
                            let context_events = assistant_context_events(
                                &s.event_store,
                                &request,
                                case_context.as_ref().map(|context| &context.case),
                                &linked_events,
                                scope_event_ids.as_ref(),
                            );
                            let scope = AssistantScopeContext {
                                case_id: case_context.as_ref().map(|context| context.case.id),
                                incident_id: incident.as_ref().map(|entry| entry.id),
                                investigation_id: investigation.map(|entry| entry.id),
                                source: request.source.clone(),
                            };

                            (
                                Arc::clone(&s.llm_analyst),
                                scope,
                                case_context,
                                context_events,
                            )
                        };

                        let status = assistant
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .status();
                        let mode = assistant_mode(&status);
                        if mode == "llm" {
                            let llm_query = crate::llm_analyst::AnalystQuery {
                                question: request.question.clone(),
                                context_filter: request.context_filter.clone(),
                                conversation_id: request.conversation_id.clone(),
                            };
                            let llm_result = assistant
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .ask(&llm_query, &context_events);
                            match llm_result {
                                Ok(response) => {
                                    let quality_gates = assistant_quality_gates(
                                        &response.citations,
                                        response.confidence,
                                        &mode,
                                    );
                                    let structured = assistant_structured_output(
                                        &response.answer,
                                        case_context.as_ref(),
                                        &context_events,
                                        &response.citations,
                                        response.confidence,
                                    );
                                    let payload = AssistantQueryResponse {
                                        answer: response.answer,
                                        structured,
                                        citations: response.citations,
                                        confidence: response.confidence,
                                        model_used: response.model_used,
                                        tokens_used: response.tokens_used,
                                        response_time_ms: response.response_time_ms,
                                        conversation_id: response.conversation_id,
                                        mode,
                                        scope,
                                        case_context,
                                        context_events,
                                        warnings: Vec::new(),
                                        quality_gates,
                                    };
                                    json_response(
                                        &serde_json::to_string(&payload)
                                            .unwrap_or_else(|_| "{}".to_string()),
                                        200,
                                    )
                                }
                                Err(error) => {
                                    let payload = assistant_response_from_fallback(
                                        &request,
                                        scope,
                                        case_context,
                                        context_events,
                                        vec![format!(
                                            "LLM assistant unavailable; using retrieval-only synthesis ({error})"
                                        )],
                                        started.elapsed().as_millis() as u64,
                                    );
                                    json_response(
                                        &serde_json::to_string(&payload)
                                            .unwrap_or_else(|_| "{}".to_string()),
                                        200,
                                    )
                                }
                            }
                        } else {
                            let payload = assistant_response_from_fallback(
                                &request,
                                scope,
                                case_context,
                                context_events,
                                vec![
                                    "LLM assistant is not configured; using retrieval-only synthesis"
                                        .to_string(),
                                ],
                                started.elapsed().as_millis() as u64,
                            );
                            json_response(
                                &serde_json::to_string(&payload)
                                    .unwrap_or_else(|_| "{}".to_string()),
                                200,
                            )
                        }
                    }
                }
                Err(error) => error_json(&error, 400),
            }
        }

        // ── Analyst Console: Event Search ──────────────────────────
        (Method::Post, "/api/events/search") => {
            let body = read_body_limited(body, 4096);
            match body {
                Ok(b) => match serde_json::from_str::<crate::analyst::SearchQuery>(&b) {
                    Ok(q) => {
                        let s = state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                let s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                let s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                                .map(|a| a.iter().filter_map(serde_json::Value::as_u64).collect())
                                .unwrap_or_default();
                            let s = state
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                                    .filter_map(|tag| {
                                        tag.as_str().map(std::string::ToString::to_string)
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();
                        let target = ResponseTarget {
                            hostname: hostname.clone(),
                            agent_uid: v["agent_uid"]
                                .as_str()
                                .map(std::string::ToString::to_string),
                            asset_tags,
                        };
                        let now = chrono::Utc::now().to_rfc3339();
                        let audit_user = requested_by.clone();
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

                        let s = state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        match s.response_orchestrator.submit(request_record) {
                            Ok(request_id) => {
                                let safe_host: String =
                                    hostname.chars().filter(|c| !c.is_control()).collect();
                                eprintln!(
                                    "[AUDIT] response_request submitted id={request_id} by={audit_user} hostname={safe_host} dry_run={dry_run}"
                                );
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
                        if let Some(submitted) = v["approver"].as_str().map(str::trim)
                            && !submitted.is_empty()
                            && submitted != response_approver(&auth_identity)
                        {
                            return respond_api(
                                state,
                                &method,
                                &url,
                                remote_addr,
                                auth_used,
                                error_json("approver must match the authenticated actor", 403),
                            );
                        }
                        let approver = response_approver(&auth_identity);
                        let reason = v["reason"].as_str().unwrap_or("").to_string();
                        let mut s = state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                                eprintln!(
                                    "[AUDIT] response_approve request={request_id} decision={decision:?} by={approver}"
                                );
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
                                    .map_or(0, |request_entry| request_entry.approvals.len());
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                    Ok(value) => value["request_id"]
                        .as_str()
                        .map(std::string::ToString::to_string),
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
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
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

        _ => handle_dynamic_api_route(
            method.clone(),
            url.clone(),
            headers,
            body,
            remote_addr,
            state,
            auth_identity.clone(),
            needs_auth,
            auth_used,
        ),
    };

    respond_api_with_timing(
        state,
        &method,
        &url,
        remote_addr,
        auth_used,
        Some(request_started),
        response,
    )
}

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;
