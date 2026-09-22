//! Runtime configuration: workspace discovery, `wardex.toml` loading, and settings structs.

use crate::siem::{SiemConfig, TaxiiConfig};

use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

static RUNTIME_CONFIG_OVERRIDE: OnceLock<PathBuf> = OnceLock::new();

fn looks_like_runtime_root(path: &Path) -> bool {
    path.join("var/wardex.toml").exists()
        || path.join("site/index.html").exists()
        || path.join("admin-console/package.json").exists()
        || path.join("Cargo.toml").exists()
        || path.join("Wardex.code-workspace").exists()
}

fn explicit_runtime_config_path() -> Option<PathBuf> {
    env::var_os("WARDEX_CONFIG_PATH")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| RUNTIME_CONFIG_OVERRIDE.get().cloned())
}

pub fn set_runtime_config_override(path: PathBuf) -> Result<(), String> {
    if let Some(current) = RUNTIME_CONFIG_OVERRIDE.get() {
        if current == &path {
            return Ok(());
        }
        return Err(format!(
            "runtime config override already set to {}",
            current.display()
        ));
    }

    RUNTIME_CONFIG_OVERRIDE
        .set(path)
        .map_err(|_| "failed to set runtime config override".to_string())
}

pub fn runtime_root_dir() -> PathBuf {
    let mut candidates = Vec::new();

    if let Ok(current_dir) = env::current_dir() {
        candidates.push(current_dir);
    }

    if let Ok(exe_path) = env::current_exe()
        && let Some(parent) = exe_path.parent()
    {
        for ancestor in parent.ancestors() {
            candidates.push(ancestor.to_path_buf());
        }
    }

    candidates
        .into_iter()
        .find(|path| looks_like_runtime_root(path))
        .unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

pub fn runtime_config_path() -> PathBuf {
    if let Some(path) = explicit_runtime_config_path() {
        return path;
    }

    runtime_root_dir().join("var/wardex.toml")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorSettings {
    pub warmup_samples: usize,
    pub smoothing: f32,
    pub learn_threshold: f32,
}

impl Default for DetectorSettings {
    fn default() -> Self {
        Self {
            warmup_samples: 4,
            smoothing: 0.22,
            learn_threshold: 2.5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySettings {
    pub critical_score: f32,
    pub severe_score: f32,
    pub elevated_score: f32,
    pub critical_integrity_drift: f32,
    pub low_battery_threshold: f32,
}

impl Default for PolicySettings {
    fn default() -> Self {
        Self {
            critical_score: 5.2,
            severe_score: 3.0,
            elevated_score: 2.8,
            critical_integrity_drift: 0.45,
            low_battery_threshold: 20.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputSettings {
    pub audit_path: String,
    pub report_path: String,
    pub checkpoint_interval: usize,
}

impl Default for OutputSettings {
    fn default() -> Self {
        Self {
            audit_path: "var/last-run.audit.log".into(),
            report_path: "var/last-run.report.json".into(),
            checkpoint_interval: 5,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorScopeSettings {
    pub cpu_load: bool,
    pub memory_pressure: bool,
    pub network_activity: bool,
    pub disk_pressure: bool,
    pub process_activity: bool,
    pub auth_events: bool,
    pub thermal_state: bool,
    pub battery_state: bool,
    pub file_integrity: bool,
    pub service_persistence: bool,
    pub launch_agents: bool,
    pub systemd_units: bool,
    pub scheduled_tasks: bool,
}

impl MonitorScopeSettings {
    pub fn normalize(&mut self) {
        let specific_persistence_selected =
            self.launch_agents || self.systemd_units || self.scheduled_tasks;
        if specific_persistence_selected {
            self.service_persistence = true;
        }
        if !self.service_persistence {
            self.launch_agents = false;
            self.systemd_units = false;
            self.scheduled_tasks = false;
        }
    }
}

impl Default for MonitorScopeSettings {
    fn default() -> Self {
        Self {
            cpu_load: true,
            memory_pressure: true,
            network_activity: true,
            disk_pressure: true,
            process_activity: true,
            auth_events: true,
            thermal_state: true,
            battery_state: true,
            file_integrity: true,
            service_persistence: false,
            launch_agents: false,
            systemd_units: false,
            scheduled_tasks: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorSettings {
    pub interval_secs: u64,
    pub alert_threshold: f32,
    pub alert_log: String,
    pub dry_run: bool,
    pub duration_secs: u64,
    pub webhook_url: Option<String>,
    pub syslog: bool,
    pub cef: bool,
    pub watch_paths: Vec<String>,
    #[serde(default)]
    pub scope: MonitorScopeSettings,
}

impl Default for MonitorSettings {
    fn default() -> Self {
        Self {
            interval_secs: 5,
            alert_threshold: 3.5,
            alert_log: "var/alerts.jsonl".into(),
            dry_run: false,
            duration_secs: 0,
            webhook_url: None,
            syslog: false,
            cef: false,
            watch_paths: Vec::new(),
            scope: MonitorScopeSettings::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    pub detector: DetectorSettings,
    pub policy: PolicySettings,
    pub output: OutputSettings,
    #[serde(default)]
    pub monitor: MonitorSettings,
    #[serde(default)]
    pub siem: SiemConfig,
    #[serde(default)]
    pub taxii: TaxiiConfig,
    #[serde(default)]
    pub agent: AgentSettings,
    #[serde(default)]
    pub rollout: RolloutSettings,
    #[serde(default)]
    pub security: SecuritySettings,
    #[serde(default)]
    pub retention: RetentionSettings,
    #[serde(default)]
    pub malware: MalwareScannerSettings,
    #[serde(default)]
    pub playbook: PlaybookSettings,
    #[serde(default)]
    pub remediation: RemediationSettings,
    #[serde(default)]
    pub compliance: ComplianceSettings,
    #[serde(default)]
    pub tracing: TracingSettings,
    #[serde(default)]
    pub server: ServerSettings,
    #[serde(default)]
    pub cluster: crate::cluster::ClusterConfig,
    #[serde(default)]
    pub clickhouse: Option<crate::storage_clickhouse::ClickHouseConfig>,
    /// Live container (Docker/Podman) and Kubernetes event sources.
    #[serde(default)]
    pub container: crate::container_runtime::ContainerRuntimeConfig,
    /// Local telemetry collection cadence.
    #[serde(default)]
    pub collection: CollectionSettings,
    /// Detection engine tuning, including the low-and-slow window.
    #[serde(default)]
    pub detection: DetectionSettings,
    /// Platform collector backend selection (eBPF/ETW/AMSI/WMI) and scan cadences.
    #[serde(default)]
    pub collectors: CollectorsSettings,
    /// Relay/edge sync settings.
    #[serde(default)]
    pub relay: RelaySettings,
    /// Supply-chain attestation settings.
    #[serde(default)]
    pub attestation: AttestationSettings,
    /// Full-text search index (Tantivy): index path, writer memory budget,
    /// commit interval, and retention. All fields have serde defaults so
    /// existing config files load unchanged.
    #[serde(default)]
    pub search: crate::search::EventStoreConfig,
}

/// `[collection]` — local telemetry collection cadence, documented in
/// `docs/CONFIGURATION.md`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionSettings {
    /// How often to collect local telemetry, in seconds. Drives the
    /// agent's main sampling loop cadence (see `agent_client::run_monitor_loop`).
    #[serde(default = "default_collection_interval_secs")]
    pub collection_interval_secs: u64,
    /// Event batch size for SIEM forwarding.
    #[serde(default = "default_max_events_per_batch")]
    pub max_events_per_batch: usize,
}

fn default_collection_interval_secs() -> u64 {
    10
}
fn default_max_events_per_batch() -> usize {
    500
}

impl Default for CollectionSettings {
    fn default() -> Self {
        Self {
            collection_interval_secs: default_collection_interval_secs(),
            max_events_per_batch: default_max_events_per_batch(),
        }
    }
}

/// `[detection]` — detection engine tuning, documented in `docs/CONFIGURATION.md`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionSettings {
    /// Detection sensitivity profile: "aggressive", "balanced", or "quiet".
    #[serde(default = "default_detection_profile")]
    pub profile: String,
    /// Anomaly score threshold above which a sample is treated as anomalous.
    #[serde(default = "default_anomaly_threshold")]
    pub anomaly_threshold: f32,
    /// Long-window size, in seconds, for low-and-slow attack detection
    /// (see `detector::SlowAttackDetector`). Converted to a sample count
    /// assuming one sample per `collection.collection_interval_secs`.
    #[serde(default = "default_slow_attack_window_secs")]
    pub slow_attack_window_secs: u64,
    /// Canary directories monitored for ransomware-style mass file changes.
    #[serde(default)]
    pub ransomware_canary_dirs: Vec<String>,
}

fn default_detection_profile() -> String {
    "balanced".into()
}
fn default_anomaly_threshold() -> f32 {
    0.75
}
fn default_slow_attack_window_secs() -> u64 {
    3600
}

impl Default for DetectionSettings {
    fn default() -> Self {
        Self {
            profile: default_detection_profile(),
            anomaly_threshold: default_anomaly_threshold(),
            slow_attack_window_secs: default_slow_attack_window_secs(),
            ransomware_canary_dirs: Vec::new(),
        }
    }
}

impl DetectionSettings {
    /// Build a [`crate::detector::SlowAttackConfig`] whose long window
    /// covers `slow_attack_window_secs`, sampling once per
    /// `sample_interval_secs` (typically `collection.collection_interval_secs`).
    pub fn slow_attack_config(
        &self,
        sample_interval_secs: u64,
    ) -> crate::detector::SlowAttackConfig {
        let interval = sample_interval_secs.max(1);
        let long_window = (self.slow_attack_window_secs / interval).max(1) as usize;
        let short_window = (long_window / 24).max(1);
        crate::detector::SlowAttackConfig {
            short_window,
            long_window,
            ..crate::detector::SlowAttackConfig::default()
        }
    }
}

/// `[collectors]` — platform collector backend selection and scan
/// cadences, documented in the Linux/Windows agent runbooks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorsSettings {
    /// Prefer the eBPF backend when the kernel supports it; `false` force-disables
    /// it even if available. When no eBPF backend is compiled in, this is a no-op
    /// and collectors log that the backend is unavailable in this build.
    #[serde(default = "default_backend_enabled")]
    pub ebpf_enabled: bool,
    /// eBPF programs to attach when `ebpf_enabled` and the backend is available.
    #[serde(default)]
    pub ebpf_programs: Vec<String>,
    /// Prefer the Windows ETW backend when available; `false` force-disables it.
    #[serde(default = "default_backend_enabled")]
    pub etw_enabled: bool,
    /// Prefer the AMSI backend for script-content inspection; `false` force-disables it.
    #[serde(default = "default_backend_enabled")]
    pub amsi_enabled: bool,
    /// Enable the WMI/PowerShell-based Windows collector paths (process,
    /// registry, service, and PowerShell activity collection).
    #[serde(default = "default_backend_enabled")]
    pub wmi_enabled: bool,
    /// Windows registry persistence-key scan cadence, in seconds.
    #[serde(default = "default_registry_scan_interval_secs")]
    pub registry_scan_interval_secs: u64,
    /// Process inventory scan cadence, in seconds.
    #[serde(default = "default_process_scan_interval_secs")]
    pub process_scan_interval_secs: u64,
    /// Network connection scan cadence, in seconds.
    #[serde(default = "default_network_scan_interval_secs")]
    pub network_scan_interval_secs: u64,
}

fn default_backend_enabled() -> bool {
    true
}
fn default_registry_scan_interval_secs() -> u64 {
    300
}
fn default_process_scan_interval_secs() -> u64 {
    30
}
fn default_network_scan_interval_secs() -> u64 {
    15
}

impl CollectorsSettings {
    /// Log a clear, honest message for every backend the operator asked
    /// to prefer (`*_enabled = true`) that is not compiled into this
    /// build, so a "why isn't eBPF/ETW/AMSI running?" question has an
    /// obvious answer in the logs instead of silent no-op behaviour.
    pub fn log_backend_status(&self) {
        if self.ebpf_enabled {
            log::warn!(
                "ebpf_enabled=true but this build has no eBPF backend compiled in; \
                 falling back to non-eBPF collection"
            );
        }
        #[cfg(not(target_os = "windows"))]
        {
            if self.etw_enabled {
                log::warn!("etw_enabled=true but ETW is only available on Windows");
            }
            if self.amsi_enabled {
                log::warn!("amsi_enabled=true but AMSI is only available on Windows");
            }
        }
    }
}

impl Default for CollectorsSettings {
    fn default() -> Self {
        Self {
            ebpf_enabled: default_backend_enabled(),
            ebpf_programs: Vec::new(),
            etw_enabled: default_backend_enabled(),
            amsi_enabled: default_backend_enabled(),
            wmi_enabled: default_backend_enabled(),
            registry_scan_interval_secs: default_registry_scan_interval_secs(),
            process_scan_interval_secs: default_process_scan_interval_secs(),
            network_scan_interval_secs: default_network_scan_interval_secs(),
        }
    }
}

/// `[relay]` — edge/relay-mode sync settings, documented in
/// `docs/DEPLOYMENT_MODELS.md`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelaySettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub upstream: String,
    /// How often the relay pushes its spool to the upstream, in seconds.
    #[serde(default = "default_sync_interval_secs")]
    pub sync_interval_secs: u64,
    #[serde(default = "default_spool_max_bytes")]
    pub spool_max_bytes: u64,
}

fn default_sync_interval_secs() -> u64 {
    300
}
fn default_spool_max_bytes() -> u64 {
    104_857_600
}

impl Default for RelaySettings {
    fn default() -> Self {
        Self {
            enabled: false,
            upstream: String::new(),
            sync_interval_secs: default_sync_interval_secs(),
            spool_max_bytes: default_spool_max_bytes(),
        }
    }
}

/// `[attestation]` — supply-chain attestation settings, documented in
/// `docs/DESIGN_SUPPLY_CHAIN.md`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationSettings {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub manifest_path: String,
    #[serde(default)]
    pub require_at_boot: bool,
    #[serde(default = "default_periodic_check_minutes")]
    pub periodic_check_minutes: u64,
    /// Path to the local JSON trust store of accepted release-signer
    /// public keys (see `attestation::TrustStore`).
    #[serde(default)]
    pub trust_store_path: String,
}

fn default_periodic_check_minutes() -> u64 {
    30
}

impl Default for AttestationSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            manifest_path: String::new(),
            require_at_boot: false,
            periodic_check_minutes: default_periodic_check_minutes(),
            trust_store_path: String::new(),
        }
    }
    /// Federated-learning configuration (disabled by default). See
    /// `docs/FEDERATED_LEARNING.md` for the protocol and threat model.
    #[serde(default)]
    pub federation: crate::federated::FederationConfig,
}

/// Security-related settings for token management and session control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySettings {
    /// Token time-to-live in seconds (0 = no expiry).
    #[serde(default = "default_token_ttl_secs")]
    pub token_ttl_secs: u64,
    /// Whether to require mTLS client certificates for agent connections.
    #[serde(default)]
    pub require_mtls_agents: bool,
    /// Path to CA certificate for verifying agent client certs.
    #[serde(default)]
    pub agent_ca_cert_path: Option<String>,
    /// Reverse-proxy source addresses allowed to assert verified agent mTLS headers.
    #[serde(default)]
    pub trusted_mtls_proxy_addrs: Vec<String>,
    /// Allowed CORS origins (empty = allow same-origin only).
    #[serde(default)]
    pub cors_allowed_origins: Vec<String>,
    /// Agent update signing, trust anchors, and legacy unsigned grace policy.
    #[serde(default)]
    pub update_signing: UpdateSigningSettings,
}

/// Agent update artifact signing and verification policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSigningSettings {
    /// Reject unsigned update artifacts immediately when true.
    #[serde(default = "default_require_signed_updates")]
    pub require_signed_updates: bool,
    /// Additional trusted Ed25519 signer public keys, base64-encoded.
    #[serde(default)]
    pub trusted_update_signers: Vec<String>,
    /// Optional file containing the Ed25519 signing key used by the server when publishing releases.
    #[serde(default)]
    pub signing_key_path: Option<String>,
    /// Grace-period cutoff for accepting legacy unsigned releases.
    #[serde(default)]
    pub legacy_unsigned_grace_until: Option<String>,
    /// Last accepted update counter seed for agent-side replay protection.
    #[serde(default)]
    pub last_accepted_update_counter: Option<u64>,
}

fn default_require_signed_updates() -> bool {
    true
}

fn default_token_ttl_secs() -> u64 {
    3600
}

/// Server operational settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSettings {
    /// Maximum read requests per minute per IP (0 = unlimited).
    #[serde(default = "default_read_rate_limit")]
    pub rate_limit_read_per_minute: u32,
    /// Maximum write requests per minute per IP (0 = unlimited).
    #[serde(default = "default_write_rate_limit")]
    pub rate_limit_write_per_minute: u32,
    /// Graceful shutdown timeout in seconds.
    #[serde(default = "default_shutdown_timeout_secs")]
    pub shutdown_timeout_secs: u64,
    /// Optional bearer token required for `/api/metrics`.
    ///
    /// When `None` or empty the endpoint is public (legacy behaviour).
    /// When set, clients must send `Authorization: Bearer <token>` or the
    /// request returns `401 Unauthorized`. Reads from `WARDEX_METRICS_TOKEN`
    /// at startup if the config value is empty.
    #[serde(default)]
    pub metrics_bearer_token: Option<String>,
    /// Whether `/api/openapi.json` remains public in production.
    ///
    /// Development keeps the historical public contract endpoint, but
    /// production deployments should set this explicitly when anonymous
    /// contract discovery is intended.
    #[serde(default = "default_openapi_public")]
    pub openapi_public: bool,
}

fn default_read_rate_limit() -> u32 {
    360
}
fn default_write_rate_limit() -> u32 {
    60
}
fn default_shutdown_timeout_secs() -> u64 {
    30
}
fn default_openapi_public() -> bool {
    true
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            rate_limit_read_per_minute: default_read_rate_limit(),
            rate_limit_write_per_minute: default_write_rate_limit(),
            shutdown_timeout_secs: default_shutdown_timeout_secs(),
            metrics_bearer_token: None,
            openapi_public: default_openapi_public(),
        }
    }
}

impl Default for SecuritySettings {
    fn default() -> Self {
        Self {
            token_ttl_secs: default_token_ttl_secs(),
            require_mtls_agents: false,
            agent_ca_cert_path: None,
            trusted_mtls_proxy_addrs: Vec::new(),
            cors_allowed_origins: Vec::new(),
            update_signing: UpdateSigningSettings::default(),
        }
    }
}

impl Default for UpdateSigningSettings {
    fn default() -> Self {
        Self {
            require_signed_updates: default_require_signed_updates(),
            trusted_update_signers: Vec::new(),
            signing_key_path: None,
            legacy_unsigned_grace_until: None,
            last_accepted_update_counter: None,
        }
    }
}

/// Data retention policy settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionSettings {
    /// Maximum number of audit records to keep (0 = unlimited).
    #[serde(default = "default_audit_max_records")]
    pub audit_max_records: usize,
    /// Maximum number of alerts to keep (0 = unlimited).
    #[serde(default = "default_alert_max_records")]
    pub alert_max_records: usize,
    /// Maximum number of events to keep (0 = unlimited).
    #[serde(default = "default_event_max_records")]
    pub event_max_records: usize,
    /// Maximum age in seconds for audit records (0 = no age limit).
    #[serde(default)]
    pub audit_max_age_secs: u64,
    /// Remote syslog endpoint for log forwarding (e.g. "udp://syslog.example.com:514").
    #[serde(default)]
    pub remote_syslog_endpoint: Option<String>,
}

fn default_audit_max_records() -> usize {
    100_000
}
fn default_alert_max_records() -> usize {
    50_000
}
fn default_event_max_records() -> usize {
    100_000
}

impl Default for RetentionSettings {
    fn default() -> Self {
        Self {
            audit_max_records: default_audit_max_records(),
            alert_max_records: default_alert_max_records(),
            event_max_records: default_event_max_records(),
            audit_max_age_secs: 0,
            remote_syslog_endpoint: None,
        }
    }
}

/// Malware scanner configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareScannerSettings {
    /// Enable or disable the malware scanner.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Maximum file size in megabytes for buffer scans (0 = no limit).
    #[serde(default = "default_max_scan_size_mb")]
    pub max_scan_size_mb: usize,
    /// Path to an external signature database (JSON). Empty = use built-in only.
    #[serde(default)]
    pub signature_db_path: Option<String>,
}

fn default_max_scan_size_mb() -> usize {
    50
}
fn default_true() -> bool {
    true
}

impl Default for MalwareScannerSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            max_scan_size_mb: default_max_scan_size_mb(),
            signature_db_path: None,
        }
    }
}

/// Playbook engine configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookSettings {
    /// Enable or disable the playbook execution engine.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Default step timeout in seconds.
    #[serde(default = "default_step_timeout_secs")]
    pub step_timeout_secs: u64,
    /// Maximum concurrent playbook executions.
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: usize,
}

fn default_step_timeout_secs() -> u64 {
    300
}
fn default_max_concurrent() -> usize {
    10
}

impl Default for PlaybookSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            step_timeout_secs: default_step_timeout_secs(),
            max_concurrent: default_max_concurrent(),
        }
    }
}

/// Remediation engine configuration.
///
/// Controls live-rollback execution policy. By default, rollback runs are
/// recorded as dry-runs only; environments that explicitly authorise active
/// recovery must opt in via `allow_live_rollback = true` AND the operator
/// must confirm by typing the asset hostname into the request payload.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemediationSettings {
    /// Allow live (non-dry-run) rollback execution. Default `false`.
    ///
    /// When `false`, any `dry_run = false` rollback request is rejected with
    /// `403 Forbidden` and an audit-log entry. When `true`, the request must
    /// also include `confirm_hostname` matching the change-review's
    /// `asset_id` (case-insensitive) to be accepted.
    #[serde(default)]
    pub allow_live_rollback: bool,
    /// Allow the rollback handler to execute planned remediation commands
    /// locally when live rollback is enabled and the requested platform
    /// matches the current OS. Default `false`.
    ///
    /// When `false`, accepted live rollback requests still record the command
    /// plan and proof metadata, but they do not invoke OS commands.
    #[serde(default)]
    pub execute_live_rollback_commands: bool,
}

/// Compliance evaluation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceSettings {
    /// Enable or disable compliance reporting.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Frameworks to evaluate (empty = all).
    #[serde(default)]
    pub frameworks: Vec<String>,
    /// Cache TTL for compliance reports in seconds.
    #[serde(default = "default_report_cache_ttl")]
    pub report_cache_ttl_secs: u64,
}

fn default_report_cache_ttl() -> u64 {
    3600
}

impl Default for ComplianceSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            frameworks: Vec::new(),
            report_cache_ttl_secs: default_report_cache_ttl(),
        }
    }
}

/// OpenTelemetry tracing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingSettings {
    /// Enable or disable OTel trace collection.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Sampling rate (0.0 to 1.0, where 1.0 = sample everything).
    #[serde(default = "default_sample_rate")]
    pub sample_rate: f64,
    /// Maximum number of trace spans to retain in memory.
    #[serde(default = "default_max_spans")]
    pub max_spans: usize,
}

fn default_sample_rate() -> f64 {
    1.0
}
fn default_max_spans() -> usize {
    10_000
}

impl Default for TracingSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            sample_rate: default_sample_rate(),
            max_spans: default_max_spans(),
        }
    }
}

/// Agent-mode settings (for `wardex agent`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSettings {
    /// Server URL to connect to.
    pub server_url: String,
    /// Enrollment token for initial registration.
    pub enrollment_token: String,
    /// Persisted agent identity used after the first successful enrollment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Per-agent bearer secret returned after enrollment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_token: Option<String>,
    /// Enable auto-update checking.
    #[serde(default = "default_auto_update")]
    pub auto_update: bool,
    /// Update check interval in seconds.
    #[serde(default = "default_update_interval")]
    pub update_check_interval_secs: u64,
}

/// Rollout progression settings for staged deployments.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolloutSettings {
    /// Enable automatic staged rollout progression (canary → ring-1 → ring-2).
    #[serde(default)]
    pub auto_progress: bool,
    /// Minimum time in seconds a canary deployment must stay healthy before promoting.
    #[serde(default = "default_canary_soak_secs")]
    pub canary_soak_secs: u64,
    /// Minimum time in seconds ring-1 must stay healthy before promoting to ring-2.
    #[serde(default = "default_ring1_soak_secs")]
    pub ring1_soak_secs: u64,
    /// Auto-rollback on deployment failure.
    #[serde(default = "default_auto_rollback")]
    pub auto_rollback: bool,
    /// Maximum allowed failure count before blocking progression.
    #[serde(default = "default_max_failures")]
    pub max_failures: u32,
}

fn default_canary_soak_secs() -> u64 {
    300
}
fn default_ring1_soak_secs() -> u64 {
    600
}
fn default_auto_rollback() -> bool {
    true
}
fn default_max_failures() -> u32 {
    1
}

impl Default for RolloutSettings {
    fn default() -> Self {
        Self {
            auto_progress: false,
            canary_soak_secs: default_canary_soak_secs(),
            ring1_soak_secs: default_ring1_soak_secs(),
            auto_rollback: default_auto_rollback(),
            max_failures: default_max_failures(),
        }
    }
}

fn default_auto_update() -> bool {
    true
}
fn default_update_interval() -> u64 {
    300
}

impl Default for AgentSettings {
    fn default() -> Self {
        Self {
            server_url: "http://localhost:8080".into(),
            enrollment_token: String::new(),
            agent_id: None,
            agent_token: None,
            auto_update: true,
            update_check_interval_secs: 300,
        }
    }
}

impl Config {
    pub fn normalize(&mut self) {
        self.monitor.scope.normalize();
    }

    pub fn write_default_toml(path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("failed to create directory: {e}"))?;
        }
        let config = Self::default();
        let toml_str =
            toml::to_string_pretty(&config).map_err(|e| format!("failed to serialize: {e}"))?;
        fs::write(path, toml_str).map_err(|e| format!("failed to write config: {e}"))
    }

    pub fn load_from_path(path: &Path) -> Result<Self, String> {
        let raw = fs::read_to_string(path).map_err(|e| format!("failed to read config: {e}"))?;

        let mut config: Self = match path.extension().and_then(|e| e.to_str()) {
            Some("json") => {
                serde_json::from_str(&raw).map_err(|e| format!("invalid JSON config: {e}"))?
            }
            _ => toml::from_str(&raw).map_err(|e| format!("invalid TOML config: {e}"))?,
        };
        config.normalize();
        config.validate()?;
        Ok(config)
    }

    /// Validate invariants: threshold ordering, non-negative values, ranges.
    pub fn validate(&self) -> Result<(), String> {
        fn finite_non_negative(name: &str, value: f32) -> Result<(), String> {
            if !value.is_finite() {
                return Err(format!("{name} must be finite, got {value}"));
            }
            if value < 0.0 {
                return Err(format!("{name} must be >= 0.0, got {value}"));
            }
            Ok(())
        }

        let d = &self.detector;
        if d.warmup_samples == 0 {
            return Err("detector.warmup_samples must be >= 1".into());
        }
        if !d.smoothing.is_finite() {
            return Err(format!(
                "detector.smoothing must be finite, got {}",
                d.smoothing
            ));
        }
        if !(0.0..=1.0).contains(&d.smoothing) {
            return Err(format!(
                "detector.smoothing must be in [0.0, 1.0], got {}",
                d.smoothing
            ));
        }
        finite_non_negative("detector.learn_threshold", d.learn_threshold)?;

        let p = &self.policy;
        finite_non_negative("policy.critical_score", p.critical_score)?;
        finite_non_negative("policy.severe_score", p.severe_score)?;
        finite_non_negative("policy.elevated_score", p.elevated_score)?;
        if p.critical_score <= p.severe_score {
            return Err(format!(
                "policy.critical_score ({}) must be > severe_score ({})",
                p.critical_score, p.severe_score
            ));
        }
        if p.severe_score <= p.elevated_score {
            return Err(format!(
                "policy.severe_score ({}) must be > elevated_score ({})",
                p.severe_score, p.elevated_score
            ));
        }
        if !p.critical_integrity_drift.is_finite() {
            return Err(format!(
                "policy.critical_integrity_drift must be finite, got {}",
                p.critical_integrity_drift
            ));
        }
        if p.critical_integrity_drift < 0.0 || p.critical_integrity_drift > 1.0 {
            return Err(format!(
                "policy.critical_integrity_drift must be in [0.0, 1.0], got {}",
                p.critical_integrity_drift
            ));
        }
        if !p.low_battery_threshold.is_finite() {
            return Err(format!(
                "policy.low_battery_threshold must be finite, got {}",
                p.low_battery_threshold
            ));
        }
        if p.low_battery_threshold < 0.0 || p.low_battery_threshold > 100.0 {
            return Err(format!(
                "policy.low_battery_threshold must be in [0.0, 100.0], got {}",
                p.low_battery_threshold
            ));
        }

        let m = &self.monitor;
        if m.interval_secs == 0 {
            return Err("monitor.interval_secs must be >= 1".into());
        }
        finite_non_negative("monitor.alert_threshold", m.alert_threshold)?;

        let o = &self.output;
        if o.checkpoint_interval == 0 {
            return Err("output.checkpoint_interval must be >= 1".into());
        }

        let cluster = &self.cluster;
        if cluster.node_id.0.trim().is_empty() {
            return Err("cluster.node_id must not be empty".into());
        }
        if cluster.heartbeat_interval_ms == 0 {
            return Err("cluster.heartbeat_interval_ms must be >= 1".into());
        }
        if cluster.election_timeout_ms <= cluster.heartbeat_interval_ms {
            return Err(format!(
                "cluster.election_timeout_ms ({}) must be greater than heartbeat_interval_ms ({})",
                cluster.election_timeout_ms, cluster.heartbeat_interval_ms
            ));
        }
        if cluster.replication_batch_size == 0 {
            return Err("cluster.replication_batch_size must be >= 1".into());
        }
        let mut peer_ids = std::collections::HashSet::new();
        for peer in &cluster.peers {
            if peer.node_id == cluster.node_id {
                return Err("cluster.peers must not contain the local node_id".into());
            }
            if peer.addr.trim().is_empty() {
                return Err(format!(
                    "cluster peer {} must have a non-empty addr",
                    peer.node_id
                ));
            }
            if !peer_ids.insert(peer.node_id.0.clone()) {
                return Err(format!(
                    "cluster peer {} is configured more than once",
                    peer.node_id
                ));
            }
            if cluster.require_tls {
                let addr = peer.addr.trim().trim_end_matches('/');
                if addr.starts_with("http://") {
                    return Err(format!(
                        "cluster peer {} uses http://; cluster.require_tls is on (peers must be https:// or a bare host:port that will be upgraded)",
                        peer.node_id
                    ));
                }
            }
        }

        Ok(())
    }
}

// ── Hot-Reload Support ───────────────────────────────────────────────

/// Result of a hot-reload operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotReloadResult {
    pub success: bool,
    pub applied_fields: Vec<String>,
    pub previous_values: std::collections::HashMap<String, String>,
    pub error: Option<String>,
}

/// A partial config update for hot-reloading.
/// Only fields that are `Some` will be applied.
/// Accepts both flat fields (legacy) and nested objects.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConfigPatch {
    // Flat fields (legacy / backward compat)
    #[serde(default)]
    pub warmup_samples: Option<usize>,
    #[serde(default)]
    pub smoothing: Option<f32>,
    #[serde(default)]
    pub learn_threshold: Option<f32>,
    #[serde(default)]
    pub critical_score: Option<f32>,
    #[serde(default)]
    pub severe_score: Option<f32>,
    #[serde(default)]
    pub elevated_score: Option<f32>,
    #[serde(default)]
    pub critical_integrity_drift: Option<f32>,
    #[serde(default)]
    pub low_battery_threshold: Option<f32>,

    // Nested objects (from admin console settings panel)
    #[serde(default)]
    pub detector: Option<DetectorSettings>,
    #[serde(default)]
    pub policy: Option<PolicySettings>,
    #[serde(default)]
    pub monitor: Option<MonitorSettings>,
    #[serde(default)]
    pub rollout: Option<RolloutSettings>,
    #[serde(default)]
    pub retention: Option<RetentionSettings>,
    #[serde(default)]
    pub cluster: Option<crate::cluster::ClusterConfig>,
}

impl ConfigPatch {
    /// Apply this patch to a Config, validate the result, and return
    /// the list of changed fields with their previous values.
    pub fn apply(&self, config: &mut Config) -> HotReloadResult {
        let mut applied = Vec::new();
        let mut previous = std::collections::HashMap::new();

        // Snapshot the original config for rollback on validation failure
        let original = config.clone();

        // Nested objects (from admin console settings panel)
        if let Some(ref d) = self.detector {
            previous.insert("detector".into(), format!("{:?}", config.detector));
            config.detector = d.clone();
            applied.push("detector".into());
        }
        if let Some(ref p) = self.policy {
            previous.insert("policy".into(), format!("{:?}", config.policy));
            config.policy = p.clone();
            applied.push("policy".into());
        }
        if let Some(ref m) = self.monitor {
            previous.insert("monitor".into(), format!("{:?}", config.monitor));
            config.monitor = m.clone();
            applied.push("monitor".into());
        }
        if let Some(ref r) = self.rollout {
            previous.insert("rollout".into(), format!("{:?}", config.rollout));
            config.rollout = r.clone();
            applied.push("rollout".into());
        }
        if let Some(ref retention) = self.retention {
            previous.insert("retention".into(), format!("{:?}", config.retention));
            config.retention = retention.clone();
            applied.push("retention".into());
        }
        if let Some(ref cluster) = self.cluster {
            previous.insert("cluster".into(), format!("{:?}", config.cluster));
            config.cluster = cluster.clone();
            applied.push("cluster".into());
        }

        if let Some(v) = self.warmup_samples {
            previous.insert(
                "warmup_samples".into(),
                config.detector.warmup_samples.to_string(),
            );
            config.detector.warmup_samples = v;
            applied.push("warmup_samples".into());
        }
        if let Some(v) = self.smoothing {
            previous.insert("smoothing".into(), config.detector.smoothing.to_string());
            config.detector.smoothing = v;
            applied.push("smoothing".into());
        }
        if let Some(v) = self.learn_threshold {
            previous.insert(
                "learn_threshold".into(),
                config.detector.learn_threshold.to_string(),
            );
            config.detector.learn_threshold = v;
            applied.push("learn_threshold".into());
        }
        if let Some(v) = self.critical_score {
            previous.insert(
                "critical_score".into(),
                config.policy.critical_score.to_string(),
            );
            config.policy.critical_score = v;
            applied.push("critical_score".into());
        }
        if let Some(v) = self.severe_score {
            previous.insert(
                "severe_score".into(),
                config.policy.severe_score.to_string(),
            );
            config.policy.severe_score = v;
            applied.push("severe_score".into());
        }
        if let Some(v) = self.elevated_score {
            previous.insert(
                "elevated_score".into(),
                config.policy.elevated_score.to_string(),
            );
            config.policy.elevated_score = v;
            applied.push("elevated_score".into());
        }
        if let Some(v) = self.critical_integrity_drift {
            previous.insert(
                "critical_integrity_drift".into(),
                config.policy.critical_integrity_drift.to_string(),
            );
            config.policy.critical_integrity_drift = v;
            applied.push("critical_integrity_drift".into());
        }
        if let Some(v) = self.low_battery_threshold {
            previous.insert(
                "low_battery_threshold".into(),
                config.policy.low_battery_threshold.to_string(),
            );
            config.policy.low_battery_threshold = v;
            applied.push("low_battery_threshold".into());
        }

        config.normalize();

        // Validate the patched config
        if let Err(e) = config.validate() {
            // Rollback
            *config = original;
            return HotReloadResult {
                success: false,
                applied_fields: Vec::new(),
                previous_values: std::collections::HashMap::new(),
                error: Some(e),
            };
        }

        HotReloadResult {
            success: true,
            applied_fields: applied,
            previous_values: previous,
            error: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Config, ConfigPatch, MonitorScopeSettings, MonitorSettings, PolicySettings,
        RetentionSettings,
    };

    #[test]
    fn default_round_trip_toml() {
        let config = Config::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.detector.warmup_samples, 4);
        assert!((parsed.detector.smoothing - 0.22).abs() < 0.001);
    }

    #[test]
    fn default_round_trip_json() {
        let config = Config::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: Config = serde_json::from_str(&json).unwrap();
        assert!((parsed.policy.critical_score - 5.2).abs() < 0.001);
    }

    #[test]
    fn write_and_load() {
        let dir = std::env::temp_dir().join("wardex_test_config");
        let path = dir.join("config.toml");

        Config::write_default_toml(&path).unwrap();
        let loaded = Config::load_from_path(&path).unwrap();
        assert_eq!(loaded.output.checkpoint_interval, 5);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn default_config_validates() {
        Config::default().validate().unwrap();
    }

    #[test]
    fn rejects_inverted_thresholds() {
        let mut config = Config::default();
        config.policy.critical_score = 2.0;
        config.policy.severe_score = 3.0;
        let err = config.validate().unwrap_err();
        assert!(err.contains("critical_score"), "error: {err}");
    }

    #[test]
    fn rejects_zero_warmup() {
        let mut config = Config::default();
        config.detector.warmup_samples = 0;
        let err = config.validate().unwrap_err();
        assert!(err.contains("warmup_samples"), "error: {err}");
    }

    #[test]
    fn rejects_smoothing_out_of_range() {
        let mut config = Config::default();
        config.detector.smoothing = 1.5;
        let err = config.validate().unwrap_err();
        assert!(err.contains("smoothing"), "error: {err}");
    }

    #[test]
    fn rejects_zero_checkpoint_interval() {
        let mut config = Config::default();
        config.output.checkpoint_interval = 0;
        let err = config.validate().unwrap_err();
        assert!(err.contains("checkpoint_interval"), "error: {err}");
    }

    #[test]
    fn hot_reload_applies_partial_patch() {
        let mut config = Config::default();
        let patch = ConfigPatch {
            smoothing: Some(0.35),
            critical_score: Some(6.0),
            ..Default::default()
        };
        let result = patch.apply(&mut config);
        assert!(result.success);
        assert_eq!(result.applied_fields.len(), 2);
        assert!((config.detector.smoothing - 0.35).abs() < 0.001);
        assert!((config.policy.critical_score - 6.0).abs() < 0.001);
        // Previous values recorded
        assert!(result.previous_values.contains_key("smoothing"));
    }

    #[test]
    fn hot_reload_rolls_back_on_invalid() {
        let mut config = Config::default();
        let original_critical = config.policy.critical_score;
        // Set critical_score below severe_score (invalid)
        let patch = ConfigPatch {
            critical_score: Some(1.0),
            ..Default::default()
        };
        let result = patch.apply(&mut config);
        assert!(!result.success);
        assert!(result.error.is_some());
        // Config should be rolled back
        assert!((config.policy.critical_score - original_critical).abs() < 0.001);
    }

    #[test]
    fn hot_reload_empty_patch_is_noop() {
        let mut config = Config::default();
        let patch = ConfigPatch::default();
        let result = patch.apply(&mut config);
        assert!(result.success);
        assert!(result.applied_fields.is_empty());
    }

    #[test]
    fn hot_reload_updates_retention_section() {
        let mut config = Config::default();
        let patch = ConfigPatch {
            retention: Some(RetentionSettings {
                audit_max_records: 10_000,
                alert_max_records: 5_000,
                event_max_records: 20_000,
                audit_max_age_secs: 86_400,
                remote_syslog_endpoint: Some("udp://syslog.example.com:514".into()),
            }),
            ..Default::default()
        };

        let result = patch.apply(&mut config);

        assert!(result.success);
        assert_eq!(config.retention.audit_max_records, 10_000);
        assert_eq!(config.retention.alert_max_records, 5_000);
        assert_eq!(config.retention.event_max_records, 20_000);
        assert_eq!(config.retention.audit_max_age_secs, 86_400);
        assert_eq!(
            config.retention.remote_syslog_endpoint.as_deref(),
            Some("udp://syslog.example.com:514"),
        );
        assert!(result.applied_fields.contains(&"retention".to_string()));
    }

    #[test]
    fn rejects_negative_severe_score() {
        let mut config = Config::default();
        config.policy.severe_score = -1.0;
        let err = config.validate().unwrap_err();
        assert!(err.contains("policy.severe_score"), "error: {err}");
    }

    #[test]
    fn rejects_zero_monitor_interval() {
        let mut config = Config::default();
        config.monitor.interval_secs = 0;
        let err = config.validate().unwrap_err();
        assert!(err.contains("monitor.interval_secs"), "error: {err}");
    }

    #[test]
    fn hot_reload_nested_then_flat_fields_preserve_flat_override() {
        let mut config = Config::default();
        let patch = ConfigPatch {
            critical_score: Some(6.4),
            policy: Some(PolicySettings {
                critical_score: 5.8,
                ..PolicySettings::default()
            }),
            ..Default::default()
        };

        let result = patch.apply(&mut config);
        assert!(result.success);
        assert!((config.policy.critical_score - 6.4).abs() < 0.001);
    }

    #[test]
    fn monitor_scope_round_trips_through_json() {
        let config = Config::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: Config = serde_json::from_str(&json).unwrap();
        assert!(parsed.monitor.scope.cpu_load);
        assert!(parsed.monitor.scope.file_integrity);
        assert!(!parsed.monitor.scope.systemd_units);
    }

    #[test]
    fn monitor_patch_updates_scope() {
        let mut config = Config::default();
        let monitor = MonitorSettings {
            scope: MonitorScopeSettings {
                file_integrity: false,
                systemd_units: true,
                ..MonitorScopeSettings::default()
            },
            ..MonitorSettings::default()
        };
        let patch = ConfigPatch {
            monitor: Some(monitor),
            ..Default::default()
        };

        let result = patch.apply(&mut config);
        assert!(result.success);
        assert!(!config.monitor.scope.file_integrity);
        assert!(config.monitor.scope.systemd_units);
    }

    #[test]
    fn monitor_scope_normalization_enables_service_persistence_for_specific_sources() {
        let mut scope = MonitorScopeSettings {
            service_persistence: false,
            launch_agents: true,
            ..MonitorScopeSettings::default()
        };
        scope.normalize();
        assert!(scope.service_persistence);
        assert!(scope.launch_agents);
    }

    #[test]
    fn config_load_normalizes_inconsistent_monitor_scope() {
        let dir = std::env::temp_dir().join("wardex_test_config_scope_normalize");
        let path = dir.join("config.toml");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            &path,
            r#"
[detector]
warmup_samples = 4
smoothing = 0.22
learn_threshold = 2.5

[policy]
critical_score = 5.2
severe_score = 3.0
elevated_score = 2.8
critical_integrity_drift = 0.5
low_battery_threshold = 20.0

[output]
audit_path = "var/last-run.audit.log"
report_path = "var/last-run.report.json"
checkpoint_interval = 5

[monitor]
interval_secs = 5
alert_threshold = 3.5
alert_log = "var/alerts.jsonl"
dry_run = false
duration_secs = 0
syslog = false
cef = false
watch_paths = []

[monitor.scope]
cpu_load = true
memory_pressure = true
network_activity = true
disk_pressure = true
process_activity = true
auth_events = true
thermal_state = true
battery_state = true
file_integrity = true
service_persistence = false
launch_agents = true
systemd_units = false
scheduled_tasks = false
"#,
        )
        .unwrap();

        let loaded = Config::load_from_path(&path).unwrap();
        assert!(loaded.monitor.scope.service_persistence);
        assert!(loaded.monitor.scope.launch_agents);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn security_settings_defaults() {
        let config = Config::default();
        assert_eq!(config.security.token_ttl_secs, 3600);
        assert!(!config.security.require_mtls_agents);
        assert!(config.security.agent_ca_cert_path.is_none());
    }

    #[test]
    fn retention_settings_defaults() {
        let config = Config::default();
        assert_eq!(config.retention.audit_max_records, 100_000);
        assert_eq!(config.retention.alert_max_records, 50_000);
        assert_eq!(config.retention.event_max_records, 100_000);
        assert_eq!(config.retention.audit_max_age_secs, 0);
        assert!(config.retention.remote_syslog_endpoint.is_none());
    }

    #[test]
    fn security_and_retention_round_trip_toml() {
        let mut config = Config::default();
        config.security.token_ttl_secs = 7200;
        config.retention.audit_max_records = 5000;
        config.retention.remote_syslog_endpoint = Some("udp://syslog:514".into());
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.security.token_ttl_secs, 7200);
        assert_eq!(parsed.retention.audit_max_records, 5000);
        assert_eq!(
            parsed.retention.remote_syslog_endpoint.as_deref(),
            Some("udp://syslog:514")
        );
    }

    #[test]
    fn collection_detection_collectors_relay_attestation_defaults() {
        let config = Config::default();
        assert_eq!(config.collection.collection_interval_secs, 10);
        assert_eq!(config.collection.max_events_per_batch, 500);
        assert_eq!(config.detection.slow_attack_window_secs, 3600);
        assert!((config.detection.anomaly_threshold - 0.75).abs() < 0.001);
        assert!(config.collectors.ebpf_enabled);
        assert!(config.collectors.etw_enabled);
        assert!(config.collectors.wmi_enabled);
        assert!(config.collectors.amsi_enabled);
        assert_eq!(config.collectors.registry_scan_interval_secs, 300);
        assert_eq!(config.collectors.process_scan_interval_secs, 30);
        assert_eq!(config.collectors.network_scan_interval_secs, 15);
        assert_eq!(config.relay.sync_interval_secs, 300);
        assert_eq!(config.attestation.periodic_check_minutes, 30);
        assert!(!config.container.docker_enabled);
        assert_eq!(config.container.docker_socket_path, "/var/run/docker.sock");
    }

    #[test]
    fn new_sections_round_trip_toml() {
        let mut config = Config::default();
        config.collection.collection_interval_secs = 20;
        config.detection.slow_attack_window_secs = 7200;
        config.collectors.wmi_enabled = false;
        config.relay.sync_interval_secs = 600;
        config.attestation.trust_store_path = "/etc/wardex/trust_store.json".into();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.collection.collection_interval_secs, 20);
        assert_eq!(parsed.detection.slow_attack_window_secs, 7200);
        assert!(!parsed.collectors.wmi_enabled);
        assert_eq!(parsed.relay.sync_interval_secs, 600);
        assert_eq!(
            parsed.attestation.trust_store_path,
            "/etc/wardex/trust_store.json"
        );
    }

    #[test]
    fn slow_attack_config_converts_window_secs_to_samples() {
        let detection = super::DetectionSettings {
            slow_attack_window_secs: 3600,
            ..super::DetectionSettings::default()
        };
        let cfg = detection.slow_attack_config(10);
        assert_eq!(cfg.long_window, 360);
        assert_eq!(cfg.short_window, 15);
    }

    #[test]
    fn collectors_log_backend_status_does_not_panic() {
        // Exercises the "backend not available in this build" logging
        // path; nothing to assert beyond "doesn't panic".
        super::CollectorsSettings::default().log_backend_status();
    }
}
