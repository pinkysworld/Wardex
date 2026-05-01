//! Automated remediation engine with per-platform adapters.
//!
//! Provides a catalog of remediation actions, prerequisite checks,
//! rollback snapshots, and platform-specific execution paths.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use crate::storage::SharedStorage;

static EXECUTION_COMMAND_OVERRIDE_DIR: OnceLock<Mutex<Option<PathBuf>>> = OnceLock::new();

// ── Remediation actions ─────────────────────────────────────────

/// A remediation action that can be applied to a host.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum RemediationAction {
    /// Kill a malicious process.
    KillProcess { pid: u32, name: String },
    /// Quarantine a file (move to secure vault).
    QuarantineFile { path: String },
    /// Restore a file from a known-good copy.
    RestoreFile { path: String, source: String },
    /// Delete a persistence mechanism.
    RemovePersistence { mechanism: PersistenceMechanism },
    /// Revert a registry change (Windows).
    RevertRegistry {
        key: String,
        value_name: String,
        original_data: String,
    },
    /// Block an IP at host firewall.
    BlockIp { addr: String },
    /// Disable a user account.
    DisableAccount { username: String },
    /// Revoke authentication tokens/sessions.
    RevokeTokens { username: String },
    /// Restart a service.
    RestartService { service_name: String },
    /// Apply a patch / update a package.
    PatchPackage { package: String, version: String },
    /// Reset file permissions.
    ResetPermissions { path: String, mode: String },
    /// Clear scheduled task.
    RemoveScheduledTask { task_name: String },
    /// Flush DNS cache.
    FlushDns,
    /// Custom remediation command.
    Custom {
        label: String,
        command: String,
        args: Vec<String>,
    },
}

/// Persistence mechanisms across platforms.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PersistenceMechanism {
    /// Linux: systemd unit file.
    SystemdUnit { name: String },
    /// Linux: crontab entry.
    CronJob { user: String, pattern: String },
    /// Linux/macOS: rc.local or init script.
    InitScript { path: String },
    /// macOS: LaunchDaemon or LaunchAgent plist.
    LaunchItem {
        path: String,
        item_type: LaunchItemType,
    },
    /// macOS: login item.
    LoginItem { name: String },
    /// Windows: Run/RunOnce registry key.
    RegistryRunKey { hive: String, value_name: String },
    /// Windows: scheduled task.
    ScheduledTask { name: String },
    /// Windows: WMI event subscription.
    WmiSubscription { name: String },
    /// Windows: service.
    WindowsService { name: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum LaunchItemType {
    Daemon,
    Agent,
}

// ── Platform adapters ───────────────────────────────────────────

/// Platform-specific remediation commands.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RemediationPlatform {
    Linux,
    MacOs,
    Windows,
}

/// Convert a remediation action to platform-specific commands.
pub fn platform_commands(
    action: &RemediationAction,
    platform: &RemediationPlatform,
) -> Vec<RemediationCommand> {
    match action {
        RemediationAction::KillProcess { pid, .. } => match platform {
            RemediationPlatform::Linux | RemediationPlatform::MacOs => {
                vec![RemediationCommand::new(
                    "kill",
                    vec!["-9".into(), pid.to_string()],
                    true,
                )]
            }
            RemediationPlatform::Windows => {
                vec![RemediationCommand::new(
                    "taskkill",
                    vec!["/PID".into(), pid.to_string(), "/F".into()],
                    true,
                )]
            }
        },
        RemediationAction::QuarantineFile { path } => match platform {
            RemediationPlatform::Linux | RemediationPlatform::MacOs => {
                vec![RemediationCommand::new(
                    "mv",
                    vec![
                        path.clone(),
                        format!("/var/quarantine/{}", sanitize_filename(path)),
                    ],
                    true,
                )]
            }
            RemediationPlatform::Windows => {
                vec![RemediationCommand::new(
                    "move",
                    vec![
                        path.clone(),
                        format!("C:\\Quarantine\\{}", sanitize_filename(path)),
                    ],
                    true,
                )]
            }
        },
        RemediationAction::BlockIp { addr } => match platform {
            RemediationPlatform::Linux => {
                vec![RemediationCommand::new(
                    "iptables",
                    vec![
                        "-A".into(),
                        "INPUT".into(),
                        "-s".into(),
                        addr.clone(),
                        "-j".into(),
                        "DROP".into(),
                    ],
                    true,
                )]
            }
            RemediationPlatform::MacOs => {
                vec![RemediationCommand::new(
                    "pfctl",
                    vec![
                        "-t".into(),
                        "blocked".into(),
                        "-T".into(),
                        "add".into(),
                        addr.clone(),
                    ],
                    true,
                )]
            }
            RemediationPlatform::Windows => {
                vec![RemediationCommand::new(
                    "netsh",
                    vec![
                        "advfirewall".into(),
                        "firewall".into(),
                        "add".into(),
                        "rule".into(),
                        format!("name=Block_{addr}"),
                        "dir=in".into(),
                        "action=block".into(),
                        format!("remoteip={addr}"),
                    ],
                    true,
                )]
            }
        },
        RemediationAction::DisableAccount { username } => match platform {
            RemediationPlatform::Linux => {
                vec![RemediationCommand::new(
                    "usermod",
                    vec!["-L".into(), username.clone()],
                    true,
                )]
            }
            RemediationPlatform::MacOs => {
                vec![RemediationCommand::new(
                    "dscl",
                    vec![
                        ".".into(),
                        "-create".into(),
                        format!("/Users/{username}"),
                        "AuthenticationAuthority".into(),
                        ";DisabledUser;".into(),
                    ],
                    true,
                )]
            }
            RemediationPlatform::Windows => {
                vec![RemediationCommand::new(
                    "net",
                    vec!["user".into(), username.clone(), "/active:no".into()],
                    true,
                )]
            }
        },
        RemediationAction::RemovePersistence { mechanism } => {
            persistence_removal_commands(mechanism, platform)
        }
        RemediationAction::FlushDns => match platform {
            RemediationPlatform::Linux => {
                vec![RemediationCommand::new(
                    "systemd-resolve",
                    vec!["--flush-caches".into()],
                    false,
                )]
            }
            RemediationPlatform::MacOs => {
                vec![RemediationCommand::new(
                    "dscacheutil",
                    vec!["-flushcache".into()],
                    false,
                )]
            }
            RemediationPlatform::Windows => {
                vec![RemediationCommand::new(
                    "ipconfig",
                    vec!["/flushdns".into()],
                    false,
                )]
            }
        },
        RemediationAction::RestoreFile { path, source } => match platform {
            RemediationPlatform::Linux | RemediationPlatform::MacOs => {
                vec![RemediationCommand::new(
                    "cp",
                    vec![source.clone(), path.clone()],
                    true,
                )]
            }
            RemediationPlatform::Windows => vec![RemediationCommand::new(
                "copy",
                vec![source.clone(), path.clone()],
                true,
            )],
        },
        RemediationAction::RestartService { service_name } => match platform {
            RemediationPlatform::Linux => vec![RemediationCommand::new(
                "systemctl",
                vec!["restart".into(), service_name.clone()],
                true,
            )],
            RemediationPlatform::MacOs => vec![RemediationCommand::new(
                "launchctl",
                vec!["kickstart".into(), format!("system/{service_name}")],
                true,
            )],
            RemediationPlatform::Windows => vec![RemediationCommand::new(
                "sc",
                vec!["start".into(), service_name.clone()],
                true,
            )],
        },
        RemediationAction::RemoveScheduledTask { task_name } => match platform {
            RemediationPlatform::Linux => {
                vec![] // cron handled via RemovePersistence
            }
            RemediationPlatform::MacOs => {
                vec![] // launchd handled via RemovePersistence
            }
            RemediationPlatform::Windows => {
                vec![RemediationCommand::new(
                    "schtasks",
                    vec![
                        "/Delete".into(),
                        "/TN".into(),
                        task_name.clone(),
                        "/F".into(),
                    ],
                    true,
                )]
            }
        },
        _ => vec![],
    }
}

fn persistence_removal_commands(
    mechanism: &PersistenceMechanism,
    platform: &RemediationPlatform,
) -> Vec<RemediationCommand> {
    match mechanism {
        PersistenceMechanism::SystemdUnit { name } => {
            if *platform == RemediationPlatform::Linux {
                vec![
                    RemediationCommand::new("systemctl", vec!["stop".into(), name.clone()], true),
                    RemediationCommand::new(
                        "systemctl",
                        vec!["disable".into(), name.clone()],
                        true,
                    ),
                ]
            } else {
                vec![]
            }
        }
        PersistenceMechanism::LaunchItem { path, .. } => {
            if *platform == RemediationPlatform::MacOs {
                let label = path
                    .rsplit('/')
                    .next()
                    .unwrap_or(path)
                    .trim_end_matches(".plist");
                vec![
                    RemediationCommand::new("launchctl", vec!["unload".into(), path.clone()], true),
                    RemediationCommand::new(
                        "mv",
                        vec![path.clone(), format!("/var/quarantine/{label}.plist")],
                        true,
                    ),
                ]
            } else {
                vec![]
            }
        }
        PersistenceMechanism::RegistryRunKey { hive, value_name } => {
            if *platform == RemediationPlatform::Windows {
                vec![RemediationCommand::new(
                    "reg",
                    vec![
                        "delete".into(),
                        hive.clone(),
                        "/v".into(),
                        value_name.clone(),
                        "/f".into(),
                    ],
                    true,
                )]
            } else {
                vec![]
            }
        }
        PersistenceMechanism::CronJob { user, .. } => {
            if *platform == RemediationPlatform::Linux || *platform == RemediationPlatform::MacOs {
                // List cron for audit, actual removal needs manual crontab edit
                vec![RemediationCommand::new(
                    "crontab",
                    vec!["-l".into(), "-u".into(), user.clone()],
                    false,
                )]
            } else {
                vec![]
            }
        }
        PersistenceMechanism::ScheduledTask { name }
        | PersistenceMechanism::WmiSubscription { name } => {
            if *platform == RemediationPlatform::Windows {
                vec![RemediationCommand::new(
                    "schtasks",
                    vec!["/Delete".into(), "/TN".into(), name.clone(), "/F".into()],
                    true,
                )]
            } else {
                vec![]
            }
        }
        PersistenceMechanism::WindowsService { name } => {
            if *platform == RemediationPlatform::Windows {
                vec![
                    RemediationCommand::new("sc", vec!["stop".into(), name.clone()], true),
                    RemediationCommand::new("sc", vec!["delete".into(), name.clone()], true),
                ]
            } else {
                vec![]
            }
        }
        _ => vec![],
    }
}

/// A concrete command to execute on the target host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationCommand {
    pub program: String,
    pub args: Vec<String>,
    pub requires_elevation: bool,
}

impl RemediationCommand {
    pub fn new(program: &str, args: Vec<String>, requires_elevation: bool) -> Self {
        Self {
            program: program.into(),
            args,
            requires_elevation,
        }
    }
}

/// Result of attempting to execute a remediation command locally.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationCommandExecution {
    pub program: String,
    pub args: Vec<String>,
    pub executed: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
}

pub fn local_execution_supported(platform: &RemediationPlatform) -> bool {
    matches!(
        (platform, std::env::consts::OS),
        (RemediationPlatform::Linux, "linux")
            | (RemediationPlatform::MacOs, "macos")
            | (RemediationPlatform::Windows, "windows")
    )
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewRollbackRequest {
    pub review_id: String,
    pub asset_id: String,
    pub approval_chain_digest: Option<String>,
    pub evidence: serde_json::Value,
    pub platform: RemediationPlatform,
    pub dry_run: bool,
    pub execute_live_commands: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewRollbackOutcome {
    pub action: RemediationAction,
    pub platform: RemediationPlatform,
    pub snapshot_id: String,
    pub commands: Vec<RemediationCommand>,
    pub command_executions: Vec<RemediationCommandExecution>,
    pub execution_mode: String,
    pub result: RemediationResult,
    pub proof_status: String,
    pub recovery_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationChangeReview {
    pub id: String,
    pub title: String,
    pub asset_id: String,
    pub change_type: String,
    pub source: String,
    pub summary: String,
    pub risk: String,
    pub approval_status: String,
    pub recovery_status: String,
    pub requested_by: String,
    pub requested_at: String,
    #[serde(default = "default_required_approvers")]
    pub required_approvers: usize,
    #[serde(default)]
    pub approvals: Vec<RemediationReviewApproval>,
    #[serde(default)]
    pub approval_chain_digest: Option<String>,
    #[serde(default)]
    pub rollback_proof: Option<RemediationRollbackProof>,
    pub evidence: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RemediationReviewApproval {
    pub approver: String,
    pub decision: String,
    pub comment: Option<String>,
    pub signed_at: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RemediationRollbackProof {
    pub proof_id: String,
    pub generated_at: String,
    pub status: String,
    pub pre_change_digest: String,
    pub recovery_plan: Vec<String>,
    pub verification_digest: String,
    pub verified_by: Option<String>,
    #[serde(default)]
    pub executed_at: Option<String>,
    #[serde(default)]
    pub execution_result: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemediationChangeReviewSummary {
    pub total: usize,
    pub pending: usize,
    pub approved: usize,
    pub recovery_ready: usize,
    pub signed: usize,
    pub multi_approver_ready: usize,
    pub rollback_proofs: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemediationChangeReviewMetrics {
    pub pending_reviews: usize,
    pub rollback_ready: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemediationLaneSummary {
    pub pending_reviews: usize,
    pub rollback_ready: usize,
    pub status: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationChangeReviewList {
    pub summary: RemediationChangeReviewSummary,
    pub reviews: Vec<RemediationChangeReview>,
}

#[derive(Debug)]
pub enum RemediationChangeReviewStoreError {
    NotFound,
    Invalid(String),
    Storage(String),
}

impl RemediationChangeReviewStoreError {
    pub fn http_status(&self) -> u16 {
        match self {
            Self::NotFound => 404,
            Self::Invalid(_) => 400,
            Self::Storage(_) => 500,
        }
    }

    pub fn response_message(&self) -> &str {
        match self {
            Self::NotFound => "remediation change review not found",
            Self::Invalid(error) | Self::Storage(error) => error.as_str(),
        }
    }
}

#[derive(Debug)]
pub enum RecordRemediationChangeReviewError {
    Invalid(String),
    Storage(String),
}

impl RecordRemediationChangeReviewError {
    pub fn http_status(&self) -> u16 {
        match self {
            Self::Invalid(_) => 400,
            Self::Storage(_) => 500,
        }
    }

    pub fn response_message(&self) -> &str {
        match self {
            Self::Invalid(error) | Self::Storage(error) => error.as_str(),
        }
    }
}

#[derive(Debug)]
pub enum ExecuteReviewRollbackError {
    NotFound,
    Invalid(String),
    LiveRollbackDisabled { review_id: String },
    HostnameConfirmationMismatch { review_id: String },
    Storage(String),
}

impl ExecuteReviewRollbackError {
    pub fn http_status(&self) -> u16 {
        match self {
            Self::NotFound => 404,
            Self::Invalid(_) => 400,
            Self::LiveRollbackDisabled { .. } => 403,
            Self::HostnameConfirmationMismatch { .. } => 400,
            Self::Storage(_) => 500,
        }
    }

    pub fn response_message(&self) -> &str {
        match self {
            Self::NotFound => "remediation change review not found",
            Self::Invalid(error) | Self::Storage(error) => error.as_str(),
            Self::LiveRollbackDisabled { .. } => {
                "live rollback execution is disabled; set remediation.allow_live_rollback = true to enable"
            }
            Self::HostnameConfirmationMismatch { .. } => {
                "live rollback requires confirm_hostname matching change-review asset_id"
            }
        }
    }
}

pub const REMEDIATION_PLAN_BODY_LIMIT: usize = 8 * 1024;
pub const REMEDIATION_CHANGE_REVIEW_BODY_LIMIT: usize = 64 * 1024;
pub const REMEDIATION_CHANGE_REVIEW_ACTION_BODY_LIMIT: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemediationChangeReviewRouteAction {
    Approval,
    Rollback,
}

impl RemediationChangeReviewRouteAction {
    fn suffix(self) -> &'static str {
        match self {
            Self::Approval => "/approval",
            Self::Rollback => "/rollback",
        }
    }
}

pub fn remediation_change_review_route_id(
    path: &str,
    action: RemediationChangeReviewRouteAction,
) -> Option<String> {
    path.strip_prefix("/api/remediation/change-reviews/")
        .and_then(|tail| tail.strip_suffix(action.suffix()))
        .map(|review_id| review_id.trim_matches('/'))
        .filter(|review_id| !review_id.is_empty() && !review_id.contains('/'))
        .map(str::to_string)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemediationRollbackPolicy {
    pub allow_live_rollback: bool,
    pub execute_live_commands: bool,
}

impl RemediationRollbackPolicy {
    pub fn new(allow_live_rollback: bool, execute_live_commands: bool) -> Self {
        Self {
            allow_live_rollback,
            execute_live_commands,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExecuteReviewRollbackRequest {
    pub review_id: String,
    pub payload: serde_json::Value,
    pub actor: String,
    pub allow_live_rollback: bool,
    pub execute_live_commands: bool,
}

pub fn remediation_change_review_response(
    status: &str,
    review: RemediationChangeReview,
) -> serde_json::Value {
    serde_json::json!({
        "status": status,
        "review": review,
    })
}

pub fn review_recorded_response(review: RemediationChangeReview) -> serde_json::Value {
    remediation_change_review_response("recorded", review)
}

pub fn review_approval_response(review: RemediationChangeReview) -> serde_json::Value {
    remediation_change_review_response("approved", review)
}

pub fn review_rollback_response(review: RemediationChangeReview) -> serde_json::Value {
    remediation_change_review_response("rollback_recorded", review)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemediationApiError {
    status: u16,
    message: String,
}

impl RemediationApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: 400,
            message: message.into(),
        }
    }

    pub fn http_status(&self) -> u16 {
        self.status
    }

    pub fn response_message(&self) -> &str {
        &self.message
    }
}

impl From<RemediationChangeReviewStoreError> for RemediationApiError {
    fn from(error: RemediationChangeReviewStoreError) -> Self {
        Self {
            status: error.http_status(),
            message: error.response_message().to_string(),
        }
    }
}

impl From<RecordRemediationChangeReviewError> for RemediationApiError {
    fn from(error: RecordRemediationChangeReviewError) -> Self {
        Self {
            status: error.http_status(),
            message: error.response_message().to_string(),
        }
    }
}

impl From<ExecuteReviewRollbackError> for RemediationApiError {
    fn from(error: ExecuteReviewRollbackError) -> Self {
        Self {
            status: error.http_status(),
            message: error.response_message().to_string(),
        }
    }
}

fn serialize_json<T>(value: &T) -> String
where
    T: Serialize,
{
    serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string())
}

pub fn remediation_plan_json(plan: &RemediationPlan) -> String {
    serialize_json(plan)
}

pub fn remediation_plan_json_from_payload(
    engine: &RemediationEngine,
    payload: serde_json::Value,
) -> Result<String, RemediationApiError> {
    let plan = remediation_plan_from_payload(engine, payload).map_err(RemediationApiError::bad_request)?;
    Ok(remediation_plan_json(&plan))
}

pub fn remediation_results_json(engine: &RemediationEngine, limit: usize) -> String {
    let results: Vec<RemediationResult> = engine.recent_results(limit).into_iter().cloned().collect();
    serialize_json(&results)
}

pub fn remediation_stats_json(engine: &RemediationEngine) -> String {
    serialize_json(&engine.stats())
}

pub fn remediation_change_review_list_json(storage: &SharedStorage) -> String {
    serialize_json(&remediation_change_review_list(storage))
}

pub fn record_remediation_change_review_json(
    storage: &SharedStorage,
    payload: serde_json::Value,
    actor: &str,
) -> Result<String, RemediationApiError> {
    let review = record_remediation_change_review(storage, payload, actor)?;
    Ok(serialize_json(&review_recorded_response(review)))
}

pub fn approve_remediation_change_review_json(
    storage: &SharedStorage,
    review_id: &str,
    payload: serde_json::Value,
    actor: &str,
) -> Result<String, RemediationApiError> {
    let review = approve_remediation_change_review(storage, review_id, payload, actor)?;
    Ok(serialize_json(&review_approval_response(review)))
}

pub fn execute_review_rollback_json(
    storage: &SharedStorage,
    engine: &mut RemediationEngine,
    request: ExecuteReviewRollbackRequest,
) -> Result<String, RemediationApiError> {
    let review = execute_and_record_review_rollback(storage, engine, request)?;
    Ok(serialize_json(&review_rollback_response(review)))
}

pub fn execute_review_rollback_json_with_policy(
    storage: &SharedStorage,
    engine: &mut RemediationEngine,
    review_id: &str,
    payload: serde_json::Value,
    actor: &str,
    policy: RemediationRollbackPolicy,
) -> Result<String, RemediationApiError> {
    execute_review_rollback_json(
        storage,
        engine,
        ExecuteReviewRollbackRequest {
            review_id: review_id.to_string(),
            payload,
            actor: actor.to_string(),
            allow_live_rollback: policy.allow_live_rollback,
            execute_live_commands: policy.execute_live_commands,
        },
    )
}

pub fn remediation_platform_from_payload(payload: &serde_json::Value) -> RemediationPlatform {
    match payload
        .get("platform")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("linux")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "macos" | "darwin" => RemediationPlatform::MacOs,
        "windows" | "win32" => RemediationPlatform::Windows,
        _ => RemediationPlatform::Linux,
    }
}

pub fn remediation_action_from_plan_payload(
    payload: &serde_json::Value,
) -> Result<RemediationAction, String> {
    let action_type = payload
        .get("action")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    match action_type.as_str() {
        "flush_dns" => Ok(RemediationAction::FlushDns),
        "block_ip" => Ok(RemediationAction::BlockIp {
            addr: payload
                .get("addr")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string(),
        }),
        "kill_process" => Ok(RemediationAction::KillProcess {
            pid: payload
                .get("pid")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as u32,
            name: payload
                .get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string(),
        }),
        "disable_account" => Ok(RemediationAction::DisableAccount {
            username: payload
                .get("username")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string(),
        }),
        "quarantine_file" => Ok(RemediationAction::QuarantineFile {
            path: payload
                .get("path")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string(),
        }),
        _ => Err("unknown remediation action".to_string()),
    }
}

pub fn remediation_plan_from_payload(
    engine: &RemediationEngine,
    payload: serde_json::Value,
) -> Result<RemediationPlan, String> {
    let platform = remediation_platform_from_payload(&payload);
    let action = remediation_action_from_plan_payload(&payload)?;
    Ok(engine.plan(&action, &platform))
}

const REMEDIATION_CHANGE_REVIEWS_KEY: &str = "remediation.change_reviews";
const MAX_REMEDIATION_CHANGE_REVIEWS: usize = 100;

fn default_required_approvers() -> usize {
    1
}

fn load_config_json<T>(storage: &SharedStorage, key: &str) -> T
where
    T: DeserializeOwned + Default,
{
    storage
        .with(|store| Ok(store.get_config(key)))
        .ok()
        .flatten()
        .and_then(|raw| serde_json::from_str::<T>(&raw).ok())
        .unwrap_or_default()
}

fn save_config_json<T>(storage: &SharedStorage, key: &str, value: &T) -> Result<(), String>
where
    T: Serialize,
{
    let raw = serde_json::to_string(value).map_err(|e| format!("serialization error: {e}"))?;
    storage
        .with(|store| {
            store.set_config(key, &raw)?;
            Ok(())
        })
        .map_err(|e| e.safe_message().to_string())
}

fn normalize_remediation_change_reviews(reviews: &mut Vec<RemediationChangeReview>) {
    reviews.sort_by(|left, right| left.requested_at.cmp(&right.requested_at));
    if reviews.len() > MAX_REMEDIATION_CHANGE_REVIEWS {
        let overflow = reviews.len() - MAX_REMEDIATION_CHANGE_REVIEWS;
        reviews.drain(0..overflow);
    }
}

pub fn load_remediation_change_reviews(storage: &SharedStorage) -> Vec<RemediationChangeReview> {
    load_config_json(storage, REMEDIATION_CHANGE_REVIEWS_KEY)
}

pub fn save_remediation_change_reviews(
    storage: &SharedStorage,
    reviews: &[RemediationChangeReview],
) -> Result<(), String> {
    save_config_json(storage, REMEDIATION_CHANGE_REVIEWS_KEY, &reviews)
}

pub fn list_remediation_change_reviews(storage: &SharedStorage) -> Vec<RemediationChangeReview> {
    let mut reviews = load_remediation_change_reviews(storage);
    reviews.sort_by(|left, right| right.requested_at.cmp(&left.requested_at));
    reviews
}

fn is_pending_remediation_change_review(review: &RemediationChangeReview) -> bool {
    matches!(
        review.approval_status.as_str(),
        "pending_review" | "pending" | "requested"
    )
}

fn remediation_change_review_metrics_from_reviews(
    reviews: &[RemediationChangeReview],
) -> RemediationChangeReviewMetrics {
    RemediationChangeReviewMetrics {
        pending_reviews: reviews
            .iter()
            .filter(|review| is_pending_remediation_change_review(review))
            .count(),
        rollback_ready: reviews
            .iter()
            .filter(|review| review.rollback_proof.is_some())
            .count(),
    }
}

pub fn remediation_change_review_metrics(
    storage: &SharedStorage,
) -> RemediationChangeReviewMetrics {
    remediation_change_review_metrics_from_reviews(&load_remediation_change_reviews(storage))
}

fn remediation_lane_summary_from_metrics(
    metrics: RemediationChangeReviewMetrics,
) -> RemediationLaneSummary {
    let pending_reviews = metrics.pending_reviews;
    let rollback_ready = metrics.rollback_ready;
    RemediationLaneSummary {
        pending_reviews,
        rollback_ready,
        status: if pending_reviews > 0 {
            "approval_required"
        } else {
            "ready"
        },
    }
}

pub fn remediation_lane_summary(storage: &SharedStorage) -> RemediationLaneSummary {
    remediation_lane_summary_from_metrics(remediation_change_review_metrics(storage))
}

pub fn summarize_remediation_change_reviews(
    reviews: &[RemediationChangeReview],
) -> RemediationChangeReviewSummary {
    RemediationChangeReviewSummary {
        total: reviews.len(),
        pending: reviews
            .iter()
            .filter(|review| is_pending_remediation_change_review(review))
            .count(),
        approved: reviews
            .iter()
            .filter(|review| review.approval_status == "approved")
            .count(),
        recovery_ready: reviews
            .iter()
            .filter(|review| matches!(review.recovery_status.as_str(), "ready" | "verified"))
            .count(),
        signed: reviews
            .iter()
            .filter(|review| review.approval_chain_digest.is_some())
            .count(),
        multi_approver_ready: reviews
            .iter()
            .filter(|review| {
                review
                    .approvals
                    .iter()
                    .filter(|approval| approval.decision == "approve")
                    .count()
                    >= review.required_approvers
            })
            .count(),
        rollback_proofs: reviews
            .iter()
            .filter(|review| review.rollback_proof.is_some())
            .count(),
    }
}

pub fn remediation_change_review_list(storage: &SharedStorage) -> RemediationChangeReviewList {
    let reviews = list_remediation_change_reviews(storage);
    let summary = summarize_remediation_change_reviews(&reviews);
    RemediationChangeReviewList { summary, reviews }
}

pub fn upsert_remediation_change_review(
    storage: &SharedStorage,
    review: RemediationChangeReview,
) -> Result<RemediationChangeReview, String> {
    let mut reviews = load_remediation_change_reviews(storage);
    reviews.retain(|entry| entry.id != review.id);
    reviews.push(review.clone());
    normalize_remediation_change_reviews(&mut reviews);
    save_remediation_change_reviews(storage, &reviews)?;
    Ok(review)
}

pub fn update_remediation_change_review<F>(
    storage: &SharedStorage,
    review_id: &str,
    update: F,
) -> Result<RemediationChangeReview, RemediationChangeReviewStoreError>
where
    F: FnOnce(RemediationChangeReview) -> Result<RemediationChangeReview, String>,
{
    let mut reviews = load_remediation_change_reviews(storage);
    let Some(position) = reviews.iter().position(|entry| entry.id == review_id) else {
        return Err(RemediationChangeReviewStoreError::NotFound);
    };
    let review = reviews.remove(position);
    let review = update(review).map_err(RemediationChangeReviewStoreError::Invalid)?;
    reviews.push(review.clone());
    normalize_remediation_change_reviews(&mut reviews);
    save_remediation_change_reviews(storage, &reviews)
        .map_err(RemediationChangeReviewStoreError::Storage)?;
    Ok(review)
}

pub fn record_remediation_change_review(
    storage: &SharedStorage,
    payload: serde_json::Value,
    actor: &str,
) -> Result<RemediationChangeReview, RecordRemediationChangeReviewError> {
    let review = remediation_review_from_payload(payload, actor)
        .map_err(RecordRemediationChangeReviewError::Invalid)?;
    upsert_remediation_change_review(storage, review)
        .map_err(RecordRemediationChangeReviewError::Storage)
}

pub fn approve_remediation_change_review(
    storage: &SharedStorage,
    review_id: &str,
    payload: serde_json::Value,
    actor: &str,
) -> Result<RemediationChangeReview, RemediationChangeReviewStoreError> {
    update_remediation_change_review(storage, review_id, |review| {
        apply_remediation_review_approval(review, payload, actor)
    })
}

pub fn execute_and_record_review_rollback(
    storage: &SharedStorage,
    engine: &mut RemediationEngine,
    request: ExecuteReviewRollbackRequest,
) -> Result<RemediationChangeReview, ExecuteReviewRollbackError> {
    let platform = rollback_platform_from_payload(&request.payload);
    let dry_run = request
        .payload
        .get("dry_run")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    let confirm_hostname = request
        .payload
        .get("confirm_hostname")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .unwrap_or("");

    let mut reviews = load_remediation_change_reviews(storage);
    let Some(position) = reviews.iter().position(|entry| entry.id == request.review_id) else {
        return Err(ExecuteReviewRollbackError::NotFound);
    };
    let mut review = reviews.remove(position);

    if !dry_run {
        let asset_id = review.asset_id.trim();
        let host_match = !confirm_hostname.is_empty()
            && !asset_id.is_empty()
            && confirm_hostname.eq_ignore_ascii_case(asset_id);
        if !request.allow_live_rollback {
            log::warn!(
                "remediation.rollback.live_blocked actor={} review={} reason=allow_live_rollback_disabled",
                request.actor,
                review.id,
            );
            return Err(ExecuteReviewRollbackError::LiveRollbackDisabled {
                review_id: review.id.clone(),
            });
        }
        if !host_match {
            log::warn!(
                "remediation.rollback.live_blocked actor={} review={} reason=hostname_confirmation_mismatch",
                request.actor,
                review.id,
            );
            return Err(ExecuteReviewRollbackError::HostnameConfirmationMismatch {
                review_id: review.id.clone(),
            });
        }
    }

    log::info!(
        "remediation.rollback.{} actor={} review={} platform={:?}",
        if dry_run { "dry_run" } else { "live" },
        request.actor,
        review.id,
        platform,
    );

    if review.approval_status != "approved" {
        return Err(ExecuteReviewRollbackError::Invalid(
            "rollback requires approved change review".to_string(),
        ));
    }
    if review.rollback_proof.is_none() {
        review.rollback_proof = Some(build_remediation_rollback_proof(&review));
    }

    let rollback = execute_review_rollback(
        engine,
        ReviewRollbackRequest {
            review_id: review.id.clone(),
            asset_id: review.asset_id.clone(),
            approval_chain_digest: review.approval_chain_digest.clone(),
            evidence: review.evidence.clone(),
            platform,
            dry_run,
            execute_live_commands: request.execute_live_commands,
        },
    )
    .map_err(ExecuteReviewRollbackError::Invalid)?;

    let executed_at = chrono::Utc::now().to_rfc3339();
    let proof = review
        .rollback_proof
        .as_mut()
        .expect("rollback proof present");
    proof.status = rollback.proof_status.clone();
    proof.verified_by = Some(request.actor);
    proof.executed_at = Some(executed_at);
    proof.execution_result = Some(serde_json::json!({
        "dry_run": dry_run,
        "platform": rollback.platform,
        "snapshot_id": rollback.snapshot_id,
        "commands": rollback.commands,
        "command_executions": rollback.command_executions,
        "live_execution": rollback.execution_mode,
        "result": rollback.result,
    }));
    review.recovery_status = rollback.recovery_status;

    reviews.push(review.clone());
    normalize_remediation_change_reviews(&mut reviews);
    save_remediation_change_reviews(storage, &reviews)
        .map_err(ExecuteReviewRollbackError::Storage)?;
    Ok(review)
}

impl Default for RemediationChangeReview {
    fn default() -> Self {
        Self {
            id: String::new(),
            title: String::new(),
            asset_id: String::new(),
            change_type: "remediation".to_string(),
            source: "infrastructure".to_string(),
            summary: String::new(),
            risk: "medium".to_string(),
            approval_status: "pending_review".to_string(),
            recovery_status: "not_started".to_string(),
            requested_by: "system".to_string(),
            requested_at: chrono::Utc::now().to_rfc3339(),
            required_approvers: default_required_approvers(),
            approvals: Vec::new(),
            approval_chain_digest: None,
            rollback_proof: None,
            evidence: serde_json::json!({}),
        }
    }
}

pub fn remediation_review_from_payload(
    payload: serde_json::Value,
    actor: &str,
) -> Result<RemediationChangeReview, String> {
    let title = payload
        .get("title")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .trim();
    if title.is_empty() {
        return Err("title is required".to_string());
    }
    let now = chrono::Utc::now().to_rfc3339();
    let risk = payload
        .get("risk")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("medium")
        .trim()
        .to_string();
    let required_approvers = remediation_required_approvers(
        &risk,
        payload
            .get("required_approvers")
            .and_then(serde_json::Value::as_u64),
    );
    let mut review = RemediationChangeReview {
        id: payload
            .get("id")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| {
                format!(
                    "review-{}",
                    chrono::Utc::now().timestamp_millis().unsigned_abs()
                )
            }),
        title: title.to_string(),
        asset_id: payload
            .get("asset_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unscoped")
            .trim()
            .to_string(),
        change_type: payload
            .get("change_type")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("remediation")
            .trim()
            .to_string(),
        source: payload
            .get("source")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("infrastructure")
            .trim()
            .to_string(),
        summary: payload
            .get("summary")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string(),
        risk,
        approval_status: payload
            .get("approval_status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("pending_review")
            .trim()
            .to_string(),
        recovery_status: payload
            .get("recovery_status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("not_started")
            .trim()
            .to_string(),
        requested_by: actor.to_string(),
        requested_at: now,
        required_approvers,
        approvals: Vec::new(),
        approval_chain_digest: None,
        rollback_proof: None,
        evidence: payload
            .get("evidence")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({})),
    };
    if review.summary.is_empty() {
        review.summary = format!("Review {} for {}.", review.change_type, review.asset_id);
    }
    if let Some(approvals) = payload
        .get("approvals")
        .and_then(serde_json::Value::as_array)
    {
        for approval in approvals {
            review = apply_remediation_review_approval(review, approval.clone(), actor)?;
        }
    }
    Ok(review)
}

pub fn apply_remediation_review_approval(
    mut review: RemediationChangeReview,
    payload: serde_json::Value,
    actor: &str,
) -> Result<RemediationChangeReview, String> {
    let decision = payload
        .get("decision")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("approve")
        .trim()
        .to_ascii_lowercase();
    if !matches!(decision.as_str(), "approve" | "deny") {
        return Err("decision must be approve or deny".to_string());
    }
    let approver = payload
        .get("approver")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(actor)
        .to_string();
    let comment = payload
        .get("comment")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let signed_at = chrono::Utc::now().to_rfc3339();
    let evidence_digest = crate::audit::sha256_hex(review.evidence.to_string().as_bytes());
    let approval = RemediationReviewApproval {
        signature: remediation_approval_signature(
            &review.id,
            &approver,
            &decision,
            &signed_at,
            comment.as_deref(),
            &evidence_digest,
        ),
        approver,
        decision: decision.clone(),
        comment,
        signed_at,
    };
    review
        .approvals
        .retain(|entry| entry.approver != approval.approver);
    review.approvals.push(approval);
    review.approval_chain_digest = remediation_approval_chain_digest(&review);
    let approved_count = review
        .approvals
        .iter()
        .filter(|entry| entry.decision == "approve")
        .count();
    let denied = review.approvals.iter().any(|entry| entry.decision == "deny");
    review.approval_status = if denied {
        "denied".to_string()
    } else if approved_count >= review.required_approvers {
        "approved".to_string()
    } else {
        "pending_review".to_string()
    };
    if review.approval_status == "approved" && review.rollback_proof.is_none() {
        review.rollback_proof = Some(build_remediation_rollback_proof(&review));
        review.recovery_status = "ready".to_string();
    }
    Ok(review)
}

pub fn build_remediation_rollback_proof(
    review: &RemediationChangeReview,
) -> RemediationRollbackProof {
    let generated_at = chrono::Utc::now().to_rfc3339();
    let pre_change_digest = crate::audit::sha256_hex(
        serde_json::json!({
            "asset_id": review.asset_id,
            "change_type": review.change_type,
            "evidence": review.evidence,
        })
        .to_string()
        .as_bytes(),
    );
    let recovery_plan = remediation_recovery_plan(review);
    let verification_digest = crate::audit::sha256_hex(
        serde_json::json!({
            "review_id": review.id,
            "pre_change_digest": pre_change_digest,
            "approval_chain_digest": review.approval_chain_digest,
            "recovery_plan": recovery_plan,
        })
        .to_string()
        .as_bytes(),
    );
    RemediationRollbackProof {
        proof_id: format!("rollback-proof-{}", &verification_digest[..12]),
        generated_at,
        status: "ready".to_string(),
        pre_change_digest,
        recovery_plan,
        verification_digest,
        verified_by: None,
        executed_at: None,
        execution_result: None,
    }
}

fn remediation_required_approvers(risk: &str, requested: Option<u64>) -> usize {
    let minimum = match risk.trim().to_ascii_lowercase().as_str() {
        "critical" | "high" => 2,
        _ => 1,
    };
    requested.unwrap_or(minimum as u64).max(minimum as u64).min(5) as usize
}

fn remediation_approval_signature(
    review_id: &str,
    approver: &str,
    decision: &str,
    signed_at: &str,
    comment: Option<&str>,
    evidence_digest: &str,
) -> String {
    crate::audit::sha256_hex(
        format!(
            "{review_id}|{approver}|{decision}|{signed_at}|{}|{evidence_digest}",
            comment.unwrap_or("")
        )
        .as_bytes(),
    )
}

fn remediation_approval_chain_digest(review: &RemediationChangeReview) -> Option<String> {
    if review.approvals.is_empty() {
        return None;
    }
    let chain = review
        .approvals
        .iter()
        .map(|approval| approval.signature.as_str())
        .collect::<Vec<_>>()
        .join("|");
    Some(crate::audit::sha256_hex(
        format!("{}|{chain}", review.id).as_bytes(),
    ))
}

fn remediation_recovery_plan(review: &RemediationChangeReview) -> Vec<String> {
    let mut steps = vec![
        format!("Capture pre-change state for {}", review.asset_id),
        "Execute remediation through the approved response workflow".to_string(),
        "Validate service health and telemetry recovery after the change".to_string(),
    ];
    match review.change_type.as_str() {
        "malware_containment" => steps.push(
            "Retain quarantine artifact hash and restore from clean backup if validation fails"
                .to_string(),
        ),
        "infrastructure_remediation" => steps.push(
            "Apply the saved configuration checkpoint or redeploy the previous known-good bundle"
                .to_string(),
        ),
        _ => steps.push(
            "Revert using the recorded pre-change checkpoint if risk increases".to_string(),
        ),
    }
    steps
}

pub fn rollback_platform_from_payload(payload: &serde_json::Value) -> RemediationPlatform {
    remediation_platform_from_payload(payload)
}

pub fn rollback_action_from_evidence(
    evidence: &serde_json::Value,
) -> Result<RemediationAction, String> {
    if let Some(explicit_action) = evidence.get("rollback_action") {
        return parse_explicit_rollback_action(explicit_action);
    }
    if let Some(path) = evidence_string(evidence, "path").or_else(|| evidence_string(evidence, "file")) {
        return Ok(RemediationAction::RestoreFile {
            path: path.clone(),
            source: evidence_string(evidence, "rollback_source")
                .or_else(|| evidence_string(evidence, "restore_source"))
                .unwrap_or_else(|| {
                    format!(
                        "/var/quarantine/{}",
                        path.replace(['/', '\\'], "_").trim_start_matches('_')
                    )
                }),
        });
    }
    if let Some(addr) = evidence_string(evidence, "addr")
        .or_else(|| evidence_string(evidence, "ip"))
        .or_else(|| evidence_string(evidence, "src_ip"))
    {
        return Ok(RemediationAction::BlockIp { addr });
    }
    if let Some(service_name) = evidence_string(evidence, "service")
        .or_else(|| evidence_string(evidence, "service_name"))
    {
        return Ok(RemediationAction::RestartService { service_name });
    }
    Ok(RemediationAction::FlushDns)
}

pub fn execute_review_rollback(
    engine: &mut RemediationEngine,
    request: ReviewRollbackRequest,
) -> Result<ReviewRollbackOutcome, String> {
    let action = rollback_action_from_evidence(&request.evidence)?;
    let commands = platform_commands(&action, &request.platform);
    let execute_live_commands = !request.dry_run
        && request.execute_live_commands
        && local_execution_supported(&request.platform)
        && !commands.is_empty();
    let command_executions = if execute_live_commands {
        execute_commands(&commands)
    } else {
        Vec::new()
    };
    let execution_failures = command_executions
        .iter()
        .filter(|entry| !entry.executed || entry.exit_code != Some(0))
        .count();
    let execution_status = if request.dry_run || command_executions.is_empty() {
        RemediationStatus::RolledBack
    } else if execution_failures == 0 {
        RemediationStatus::RolledBack
    } else if execution_failures < command_executions.len() {
        RemediationStatus::PartialSuccess
    } else {
        RemediationStatus::Failed
    };
    let execution_error = command_executions
        .iter()
        .find(|entry| !entry.executed || entry.exit_code != Some(0))
        .map(|entry| {
            if entry.stderr.trim().is_empty() {
                format!(
                    "{} failed with exit code {:?}",
                    entry.program, entry.exit_code
                )
            } else {
                entry.stderr.clone()
            }
        });
    let execution_mode = if request.dry_run {
        "dry_run".to_string()
    } else if commands.is_empty() {
        "recorded_no_commands".to_string()
    } else if execute_live_commands {
        "executed".to_string()
    } else if request.execute_live_commands {
        "recorded_platform_unavailable".to_string()
    } else {
        "recorded".to_string()
    };
    let now_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
    let snapshot_id = engine.record_snapshot(
        action.clone(),
        request.platform.clone(),
        &request.asset_id,
        Vec::new(),
        HashMap::from([
            ("review_id".to_string(), request.review_id.clone()),
            (
                "approval_chain_digest".to_string(),
                request.approval_chain_digest.clone().unwrap_or_default(),
            ),
        ]),
        now_ms,
    );
    let result = RemediationResult {
        action: action.clone(),
        status: execution_status,
        commands_run: commands.clone(),
        snapshot_id: Some(snapshot_id.clone()),
        output: Some(match execution_mode.as_str() {
            "dry_run" => "rollback dry-run planned through remediation adapter".to_string(),
            "executed" if execution_failures == 0 => {
                "rollback executed through remediation adapter".to_string()
            }
            "executed" => {
                "rollback execution attempted through remediation adapter with failures"
                    .to_string()
            }
            "recorded_platform_unavailable" => {
                "rollback execution recorded; local remediation executor unavailable for requested platform"
                    .to_string()
            }
            "recorded_no_commands" => {
                "rollback execution recorded; rollback action produced no commands for requested platform"
                    .to_string()
            }
            _ => "rollback execution recorded through remediation adapter".to_string(),
        }),
        error: execution_error,
        duration_ms: command_executions.iter().map(|entry| entry.duration_ms).sum(),
    };
    engine.record_result(result.clone());

    Ok(ReviewRollbackOutcome {
        action,
        platform: request.platform,
        snapshot_id,
        commands,
        command_executions,
        proof_status: if request.dry_run {
            "dry_run_verified".to_string()
        } else if matches!(result.status, RemediationStatus::Failed | RemediationStatus::PartialSuccess) {
            "execution_failed".to_string()
        } else {
            "executed".to_string()
        },
        recovery_status: if request.dry_run {
            "verified".to_string()
        } else if matches!(result.status, RemediationStatus::Failed | RemediationStatus::PartialSuccess) {
            "failed".to_string()
        } else {
            "executed".to_string()
        },
        execution_mode,
        result,
    })
}

pub fn execute_commands(commands: &[RemediationCommand]) -> Vec<RemediationCommandExecution> {
    let mut results = Vec::new();
    for command in commands {
        let started = Instant::now();
        if !is_allowed_execution_program(&command.program) {
            results.push(RemediationCommandExecution {
                program: command.program.clone(),
                args: command.args.clone(),
                executed: false,
                exit_code: None,
                stdout: String::new(),
                stderr: format!(
                    "command blocked by remediation safety filter: {}",
                    command.program
                ),
                duration_ms: started.elapsed().as_millis() as u64,
            });
            break;
        }

        let result = match run_remediation_command(command) {
            Ok((exit_code, stdout, stderr)) => RemediationCommandExecution {
                program: command.program.clone(),
                args: command.args.clone(),
                executed: true,
                exit_code: Some(exit_code),
                stdout,
                stderr,
                duration_ms: started.elapsed().as_millis() as u64,
            },
            Err(error) => RemediationCommandExecution {
                program: command.program.clone(),
                args: command.args.clone(),
                executed: false,
                exit_code: None,
                stdout: String::new(),
                stderr: error,
                duration_ms: started.elapsed().as_millis() as u64,
            },
        };
        let failed = !result.executed || result.exit_code != Some(0);
        results.push(result);
        if failed {
            break;
        }
    }
    results
}

fn is_allowed_execution_program(program: &str) -> bool {
    matches!(
        program,
        "cp"
            | "mv"
            | "mkdir"
            | "chmod"
            | "kill"
            | "taskkill"
            | "pfctl"
            | "iptables"
            | "nft"
            | "netsh"
            | "usermod"
            | "dscl"
            | "net"
            | "systemd-resolve"
            | "systemctl"
            | "launchctl"
            | "dscacheutil"
            | "ipconfig"
            | "sc"
            | "schtasks"
            | "reg"
            | "crontab"
            | "copy"
            | "move"
    )
}

fn resolve_execution_program(program: &str) -> PathBuf {
    let override_dir = EXECUTION_COMMAND_OVERRIDE_DIR
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();

    if let Some(dir) = override_dir {
        for candidate in command_override_candidates(&dir, program) {
            if candidate.exists() {
                return candidate;
            }
        }
    }

    PathBuf::from(program)
}

fn command_override_candidates(dir: &std::path::Path, program: &str) -> Vec<PathBuf> {
    let candidates = vec![dir.join(program)];
    #[cfg(windows)]
    {
        let mut candidates = candidates;
        candidates.extend(
            ["exe", "cmd", "bat", "com"]
                .into_iter()
                .map(|ext| dir.join(format!("{program}.{ext}"))),
        );
        return candidates;
    }
    candidates
}

#[doc(hidden)]
pub fn set_execution_command_override_dir(path: Option<PathBuf>) {
    let mut guard = EXECUTION_COMMAND_OVERRIDE_DIR
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    *guard = path;
}

fn evidence_string(evidence: &serde_json::Value, key: &str) -> Option<String> {
    evidence
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn parse_explicit_rollback_action(
    explicit_action: &serde_json::Value,
) -> Result<RemediationAction, String> {
    let action_type = explicit_action
        .as_str()
        .or_else(|| explicit_action.get("type").and_then(serde_json::Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "rollback_action must provide a non-empty type".to_string())?
        .to_ascii_lowercase();
    match action_type.as_str() {
        "flush_dns" => Ok(RemediationAction::FlushDns),
        "restore_file" => {
            let path = evidence_string(explicit_action, "path")
                .ok_or_else(|| "rollback_action.restore_file requires path".to_string())?;
            let source = evidence_string(explicit_action, "source")
                .or_else(|| evidence_string(explicit_action, "rollback_source"))
                .or_else(|| evidence_string(explicit_action, "restore_source"))
                .ok_or_else(|| "rollback_action.restore_file requires source".to_string())?;
            Ok(RemediationAction::RestoreFile { path, source })
        }
        "block_ip" => {
            let addr = evidence_string(explicit_action, "addr")
                .or_else(|| evidence_string(explicit_action, "ip"))
                .ok_or_else(|| "rollback_action.block_ip requires addr".to_string())?;
            Ok(RemediationAction::BlockIp { addr })
        }
        "restart_service" => {
            let service_name = evidence_string(explicit_action, "service_name")
                .or_else(|| evidence_string(explicit_action, "service"))
                .ok_or_else(|| {
                    "rollback_action.restart_service requires service_name".to_string()
                })?;
            Ok(RemediationAction::RestartService { service_name })
        }
        "kill_process" => {
            let pid = explicit_action
                .get("pid")
                .and_then(serde_json::Value::as_u64)
                .and_then(|value| u32::try_from(value).ok())
                .filter(|value| *value > 0)
                .ok_or_else(|| "rollback_action.kill_process requires positive pid".to_string())?;
            let name = evidence_string(explicit_action, "name").unwrap_or_else(|| "process".to_string());
            Ok(RemediationAction::KillProcess { pid, name })
        }
        "disable_account" => {
            let username = evidence_string(explicit_action, "username")
                .ok_or_else(|| "rollback_action.disable_account requires username".to_string())?;
            Ok(RemediationAction::DisableAccount { username })
        }
        "remove_scheduled_task" => {
            let task_name = evidence_string(explicit_action, "task_name")
                .ok_or_else(|| {
                    "rollback_action.remove_scheduled_task requires task_name".to_string()
                })?;
            Ok(RemediationAction::RemoveScheduledTask { task_name })
        }
        "remove_persistence" => {
            let mechanism_type = evidence_string(explicit_action, "mechanism_type")
                .ok_or_else(|| {
                    "rollback_action.remove_persistence requires mechanism_type".to_string()
                })?;
            let mechanism = match mechanism_type.to_ascii_lowercase().as_str() {
                "systemd_unit" => PersistenceMechanism::SystemdUnit {
                    name: evidence_string(explicit_action, "name").ok_or_else(|| {
                        "rollback_action.remove_persistence systemd_unit requires name".to_string()
                    })?,
                },
                "launch_item" => PersistenceMechanism::LaunchItem {
                    path: evidence_string(explicit_action, "path").ok_or_else(|| {
                        "rollback_action.remove_persistence launch_item requires path".to_string()
                    })?,
                    item_type: match evidence_string(explicit_action, "item_type")
                        .unwrap_or_else(|| "daemon".to_string())
                        .to_ascii_lowercase()
                        .as_str()
                    {
                        "agent" => LaunchItemType::Agent,
                        _ => LaunchItemType::Daemon,
                    },
                },
                "scheduled_task" => PersistenceMechanism::ScheduledTask {
                    name: evidence_string(explicit_action, "name").ok_or_else(|| {
                        "rollback_action.remove_persistence scheduled_task requires name".to_string()
                    })?,
                },
                "windows_service" => PersistenceMechanism::WindowsService {
                    name: evidence_string(explicit_action, "name").ok_or_else(|| {
                        "rollback_action.remove_persistence windows_service requires name".to_string()
                    })?,
                },
                "registry_run_key" => PersistenceMechanism::RegistryRunKey {
                    hive: evidence_string(explicit_action, "hive").ok_or_else(|| {
                        "rollback_action.remove_persistence registry_run_key requires hive".to_string()
                    })?,
                    value_name: evidence_string(explicit_action, "value_name").ok_or_else(|| {
                        "rollback_action.remove_persistence registry_run_key requires value_name"
                            .to_string()
                    })?,
                },
                other => {
                    return Err(format!(
                        "rollback_action.remove_persistence mechanism_type {other} is not supported"
                    ));
                }
            };
            Ok(RemediationAction::RemovePersistence { mechanism })
        }
        other => Err(format!("rollback_action type {other} is not supported")),
    }
}

#[cfg(windows)]
fn run_remediation_command(command: &RemediationCommand) -> Result<(i32, String, String), String> {
    use std::process::Command;
    let output = if matches!(command.program.as_str(), "copy" | "move") {
        let mut args = vec!["/C".to_string(), command.program.clone()];
        args.extend(command.args.clone());
        Command::new(resolve_execution_program("cmd"))
            .args(&args)
            .output()
            .map_err(|e| format!("failed to execute {}: {e}", command.program))?
    } else {
        Command::new(resolve_execution_program(&command.program))
            .args(&command.args)
            .output()
            .map_err(|e| format!("failed to execute {}: {e}", command.program))?
    };
    Ok((
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    ))
}

#[cfg(not(windows))]
fn run_remediation_command(command: &RemediationCommand) -> Result<(i32, String, String), String> {
    use std::process::Command;
    let output = Command::new(resolve_execution_program(&command.program))
        .args(&command.args)
        .output()
        .map_err(|e| format!("failed to execute {}: {e}", command.program))?;
    Ok((
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    ))
}

// ── Execution tracking ──────────────────────────────────────────

/// Snapshot taken before remediation for rollback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationSnapshot {
    pub snapshot_id: String,
    pub action: RemediationAction,
    pub platform: RemediationPlatform,
    pub hostname: String,
    /// Files backed up before modification.
    pub backed_up_files: Vec<String>,
    /// State values recorded before change.
    pub prior_state: HashMap<String, String>,
    pub taken_at: u64,
}

/// Outcome of a remediation attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationResult {
    pub action: RemediationAction,
    pub status: RemediationStatus,
    pub commands_run: Vec<RemediationCommand>,
    pub snapshot_id: Option<String>,
    pub output: Option<String>,
    pub error: Option<String>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RemediationStatus {
    Success,
    PartialSuccess,
    Failed,
    RolledBack,
    Skipped,
    PendingApproval,
}

// ── Engine ──────────────────────────────────────────────────────

/// Remediation engine tracking actions, snapshots, and results.
pub struct RemediationEngine {
    snapshots: Vec<RemediationSnapshot>,
    results: Vec<RemediationResult>,
    /// Actions requiring human approval before execution.
    approval_required: Vec<RemediationAction>,
    next_snapshot_id: u64,
}

impl Default for RemediationEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl RemediationEngine {
    pub fn new() -> Self {
        Self {
            snapshots: Vec::new(),
            results: Vec::new(),
            approval_required: vec![
                RemediationAction::DisableAccount {
                    username: String::new(),
                },
                RemediationAction::Custom {
                    label: String::new(),
                    command: String::new(),
                    args: vec![],
                },
            ],
            next_snapshot_id: 1,
        }
    }

    /// Check whether an action needs approval (matches by variant only).
    pub fn needs_approval(&self, action: &RemediationAction) -> bool {
        self.approval_required
            .iter()
            .any(|a| std::mem::discriminant(a) == std::mem::discriminant(action))
    }

    /// Set which action types need approval.
    pub fn set_approval_required(&mut self, actions: Vec<RemediationAction>) {
        self.approval_required = actions;
    }

    /// Plan remediation: generate platform commands and prerequisite checks.
    pub fn plan(
        &self,
        action: &RemediationAction,
        platform: &RemediationPlatform,
    ) -> RemediationPlan {
        let commands = platform_commands(action, platform);
        let needs_approval = self.needs_approval(action);
        let prerequisites = prerequisite_checks(action, platform);

        RemediationPlan {
            action: action.clone(),
            platform: platform.clone(),
            commands,
            prerequisites,
            needs_approval,
        }
    }

    /// Record a snapshot for rollback.
    pub fn record_snapshot(
        &mut self,
        action: RemediationAction,
        platform: RemediationPlatform,
        hostname: &str,
        backed_up: Vec<String>,
        prior_state: HashMap<String, String>,
        now_ms: u64,
    ) -> String {
        let id = format!("snap-{}", self.next_snapshot_id);
        self.next_snapshot_id += 1;
        self.snapshots.push(RemediationSnapshot {
            snapshot_id: id.clone(),
            action,
            platform,
            hostname: hostname.into(),
            backed_up_files: backed_up,
            prior_state,
            taken_at: now_ms,
        });
        id
    }

    /// Record a remediation result.
    pub fn record_result(&mut self, result: RemediationResult) {
        self.results.push(result);
    }

    /// Get snapshot for potential rollback.
    pub fn get_snapshot(&self, id: &str) -> Option<&RemediationSnapshot> {
        self.snapshots.iter().find(|s| s.snapshot_id == id)
    }

    /// Recent remediation results.
    pub fn recent_results(&self, limit: usize) -> Vec<&RemediationResult> {
        let start = self.results.len().saturating_sub(limit);
        self.results[start..].iter().collect()
    }

    /// Stats: success / failure counts.
    pub fn stats(&self) -> RemediationStats {
        let mut stats = RemediationStats::default();
        for r in &self.results {
            match r.status {
                RemediationStatus::Success => stats.succeeded += 1,
                RemediationStatus::PartialSuccess => stats.partial += 1,
                RemediationStatus::Failed => stats.failed += 1,
                RemediationStatus::RolledBack => stats.rolled_back += 1,
                RemediationStatus::Skipped => stats.skipped += 1,
                RemediationStatus::PendingApproval => stats.pending += 1,
            }
        }
        stats
    }
}

/// A planned remediation before execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationPlan {
    pub action: RemediationAction,
    pub platform: RemediationPlatform,
    pub commands: Vec<RemediationCommand>,
    pub prerequisites: Vec<String>,
    pub needs_approval: bool,
}

/// Prerequisite checks for a remediation action.
fn prerequisite_checks(action: &RemediationAction, _platform: &RemediationPlatform) -> Vec<String> {
    match action {
        RemediationAction::KillProcess { pid, .. } => {
            vec![format!("Process {pid} exists and is running")]
        }
        RemediationAction::QuarantineFile { path } => {
            vec![
                format!("File {path} exists"),
                "Quarantine directory is writable".into(),
            ]
        }
        RemediationAction::BlockIp { addr } => {
            vec![format!("IP {addr} is not in allow-list")]
        }
        RemediationAction::DisableAccount { username } => {
            vec![
                format!("Account {username} exists"),
                format!("Account {username} is not a service account"),
            ]
        }
        RemediationAction::RestoreFile { path, source } => {
            vec![
                format!("Backup source {source} exists"),
                format!("Restore target {path} is writable"),
            ]
        }
        RemediationAction::RestartService { service_name } => {
            vec![format!("Service {service_name} exists")]
        }
        _ => vec![],
    }
}

/// Remediation statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemediationStats {
    pub succeeded: u64,
    pub partial: u64,
    pub failed: u64,
    pub rolled_back: u64,
    pub skipped: u64,
    pub pending: u64,
}

// ── Helpers ─────────────────────────────────────────────────────

fn sanitize_filename(path: &str) -> String {
    path.replace(['/', '\\'], "_")
        .trim_start_matches('_')
        .to_string()
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn temp_shared_storage() -> (tempfile::TempDir, SharedStorage) {
        let dir = tempfile::tempdir().expect("tempdir");
        let storage = SharedStorage::open(dir.path().to_str().expect("utf8 temp path"))
            .expect("shared storage");
        (dir, storage)
    }

    #[test]
    fn remediation_change_review_route_id_parses_action_paths() {
        assert_eq!(
            remediation_change_review_route_id(
                "/api/remediation/change-reviews/review-123/approval",
                RemediationChangeReviewRouteAction::Approval,
            ),
            Some("review-123".to_string())
        );
        assert_eq!(
            remediation_change_review_route_id(
                "/api/remediation/change-reviews/review-123/rollback",
                RemediationChangeReviewRouteAction::Rollback,
            ),
            Some("review-123".to_string())
        );
        assert_eq!(
            remediation_change_review_route_id(
                "/api/remediation/change-reviews/review-123/rollback",
                RemediationChangeReviewRouteAction::Approval,
            ),
            None
        );
        assert_eq!(
            remediation_change_review_route_id(
                "/api/remediation/change-reviews/nested/review/approval",
                RemediationChangeReviewRouteAction::Approval,
            ),
            None
        );
    }

    #[test]
    fn remediation_review_payload_defaults_summary_and_required_approvers() {
        let review = remediation_review_from_payload(
            json!({
                "title": "Review suspicious service restart",
                "asset_id": "host-22",
                "change_type": "infrastructure_remediation",
                "risk": "high",
                "summary": "",
                "evidence": {"service_name": "sshd"}
            }),
            "operator",
        )
        .expect("review payload should parse");

        assert_eq!(review.requested_by, "operator");
        assert_eq!(review.required_approvers, 2);
        assert_eq!(
            review.summary,
            "Review infrastructure_remediation for host-22."
        );
    }

    #[test]
    fn remediation_review_approval_generates_ready_rollback_proof() {
        let review = remediation_review_from_payload(
            json!({
                "title": "Review quarantine rollback",
                "asset_id": "host-7:/tmp/dropper",
                "change_type": "malware_containment",
                "risk": "high",
                "evidence": {"path": "/tmp/dropper"}
            }),
            "operator",
        )
        .expect("review payload should parse");

        let review = apply_remediation_review_approval(
            review,
            json!({
                "approver": "primary-reviewer",
                "decision": "approve"
            }),
            "operator",
        )
        .expect("first approval should succeed");
        assert_eq!(review.approval_status, "pending_review");
        assert!(review.rollback_proof.is_none());

        let review = apply_remediation_review_approval(
            review,
            json!({
                "approver": "secondary-reviewer",
                "decision": "approve",
                "comment": "Recovery checkpoint verified."
            }),
            "operator",
        )
        .expect("second approval should succeed");

        assert_eq!(review.approval_status, "approved");
        assert_eq!(review.recovery_status, "ready");
        assert!(review.approval_chain_digest.is_some());
        assert_eq!(
            review.rollback_proof.as_ref().map(|proof| proof.status.as_str()),
            Some("ready")
        );
    }

    #[test]
    fn remediation_change_review_json_wrappers_record_approve_and_rollback() {
        let (_dir, storage) = temp_shared_storage();
        let mut engine = RemediationEngine::new();

        let created = record_remediation_change_review_json(
            &storage,
            json!({
                "id": "review-json-1",
                "title": "Review rollback wrapper",
                "asset_id": "host-json",
                "risk": "low",
                "evidence": {
                    "path": "/tmp/payload",
                    "rollback_source": "/tmp/clean"
                }
            }),
            "operator",
        )
        .expect("record review json");
        let created: serde_json::Value = serde_json::from_str(&created).expect("created json");
        assert_eq!(created["status"], json!("recorded"));
        assert_eq!(created["review"]["id"], json!("review-json-1"));

        let listed = remediation_change_review_list_json(&storage);
        let listed: serde_json::Value = serde_json::from_str(&listed).expect("list json");
        assert_eq!(listed["summary"]["total"], json!(1));

        let approved = approve_remediation_change_review_json(
            &storage,
            "review-json-1",
            json!({"approver": "primary-reviewer", "decision": "approve"}),
            "operator",
        )
        .expect("approve review json");
        let approved: serde_json::Value = serde_json::from_str(&approved).expect("approved json");
        assert_eq!(approved["status"], json!("approved"));
        assert_eq!(approved["review"]["approval_status"], json!("approved"));

        let rollback = execute_review_rollback_json_with_policy(
            &storage,
            &mut engine,
            "review-json-1",
            json!({"dry_run": true, "platform": "linux"}),
            "operator",
            RemediationRollbackPolicy::new(false, false),
        )
        .expect("rollback review json");
        let rollback: serde_json::Value = serde_json::from_str(&rollback).expect("rollback json");
        assert_eq!(rollback["status"], json!("rollback_recorded"));
        assert_eq!(rollback["review"]["recovery_status"], json!("verified"));
        assert_eq!(
            rollback["review"]["rollback_proof"]["status"],
            json!("dry_run_verified")
        );
    }

    #[test]
    fn remediation_change_review_json_wrappers_map_missing_review_to_not_found() {
        let (_dir, storage) = temp_shared_storage();
        let error = approve_remediation_change_review_json(
            &storage,
            "missing-review",
            json!({"decision": "approve"}),
            "operator",
        )
        .expect_err("missing review should map to API error");

        assert_eq!(error.http_status(), 404);
        assert_eq!(
            error.response_message(),
            "remediation change review not found"
        );
    }

    #[test]
    fn remediation_change_review_metrics_count_legacy_pending_statuses() {
        let reviews = vec![
            RemediationChangeReview {
                id: "review-1".to_string(),
                approval_status: "pending_review".to_string(),
                ..RemediationChangeReview::default()
            },
            RemediationChangeReview {
                id: "review-2".to_string(),
                approval_status: "pending".to_string(),
                rollback_proof: Some(RemediationRollbackProof::default()),
                ..RemediationChangeReview::default()
            },
            RemediationChangeReview {
                id: "review-3".to_string(),
                approval_status: "requested".to_string(),
                ..RemediationChangeReview::default()
            },
            RemediationChangeReview {
                id: "review-4".to_string(),
                approval_status: "approved".to_string(),
                rollback_proof: Some(RemediationRollbackProof::default()),
                ..RemediationChangeReview::default()
            },
        ];

        let summary = summarize_remediation_change_reviews(&reviews);
        let metrics = remediation_change_review_metrics_from_reviews(&reviews);

        assert_eq!(summary.pending, 3);
        assert_eq!(summary.rollback_proofs, 2);
        assert_eq!(metrics.pending_reviews, 3);
        assert_eq!(metrics.rollback_ready, 2);
    }

    #[test]
    fn remediation_lane_summary_requires_approval_when_reviews_are_pending() {
        let summary = remediation_lane_summary_from_metrics(RemediationChangeReviewMetrics {
            pending_reviews: 2,
            rollback_ready: 1,
        });

        assert_eq!(summary.pending_reviews, 2);
        assert_eq!(summary.rollback_ready, 1);
        assert_eq!(summary.status, "approval_required");
    }

    #[test]
    fn kill_process_linux() {
        let cmds = platform_commands(
            &RemediationAction::KillProcess {
                pid: 1234,
                name: "malware".into(),
            },
            &RemediationPlatform::Linux,
        );
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "kill");
        assert!(cmds[0].args.contains(&"1234".to_string()));
    }

    #[test]
    fn kill_process_windows() {
        let cmds = platform_commands(
            &RemediationAction::KillProcess {
                pid: 5678,
                name: "malware.exe".into(),
            },
            &RemediationPlatform::Windows,
        );
        assert_eq!(cmds[0].program, "taskkill");
    }

    #[test]
    fn block_ip_per_platform() {
        let action = RemediationAction::BlockIp {
            addr: "10.0.0.99".into(),
        };
        let linux = platform_commands(&action, &RemediationPlatform::Linux);
        assert_eq!(linux[0].program, "iptables");

        let mac = platform_commands(&action, &RemediationPlatform::MacOs);
        assert_eq!(mac[0].program, "pfctl");

        let win = platform_commands(&action, &RemediationPlatform::Windows);
        assert_eq!(win[0].program, "netsh");
    }

    #[test]
    fn disable_account_macos() {
        let cmds = platform_commands(
            &RemediationAction::DisableAccount {
                username: "attacker".into(),
            },
            &RemediationPlatform::MacOs,
        );
        assert_eq!(cmds[0].program, "dscl");
    }

    #[test]
    fn remove_systemd_persistence() {
        let cmds = platform_commands(
            &RemediationAction::RemovePersistence {
                mechanism: PersistenceMechanism::SystemdUnit {
                    name: "evil.service".into(),
                },
            },
            &RemediationPlatform::Linux,
        );
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].program, "systemctl");
    }

    #[test]
    fn remove_launch_item_macos() {
        let cmds = platform_commands(
            &RemediationAction::RemovePersistence {
                mechanism: PersistenceMechanism::LaunchItem {
                    path: "/Library/LaunchDaemons/com.evil.plist".into(),
                    item_type: LaunchItemType::Daemon,
                },
            },
            &RemediationPlatform::MacOs,
        );
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].program, "launchctl");
    }

    #[test]
    fn needs_approval_check() {
        let engine = RemediationEngine::new();
        assert!(engine.needs_approval(&RemediationAction::DisableAccount {
            username: "bob".into(),
        }));
        assert!(!engine.needs_approval(&RemediationAction::FlushDns));
    }

    #[test]
    fn plan_includes_prerequisites() {
        let engine = RemediationEngine::new();
        let plan = engine.plan(
            &RemediationAction::KillProcess {
                pid: 42,
                name: "evil".into(),
            },
            &RemediationPlatform::Linux,
        );
        assert!(!plan.prerequisites.is_empty());
        assert!(!plan.needs_approval);
    }

    #[test]
    fn remediation_plan_payload_maps_block_ip_request() {
        let engine = RemediationEngine::new();
        let plan = remediation_plan_from_payload(
            &engine,
            json!({
                "platform": "macos",
                "action": "block_ip",
                "addr": "203.0.113.20"
            }),
        )
        .expect("plan payload should parse");

        assert!(matches!(plan.platform, RemediationPlatform::MacOs));
        assert!(matches!(
            plan.action,
            RemediationAction::BlockIp { ref addr } if addr == "203.0.113.20"
        ));
        assert_eq!(plan.commands[0].program, "pfctl");
    }

    #[test]
    fn remediation_plan_json_from_payload_maps_plan_response() {
        let engine = RemediationEngine::new();
        let body = remediation_plan_json_from_payload(
            &engine,
            json!({
                "platform": "linux",
                "action": "kill_process",
                "pid": 42,
                "name": "payload"
            }),
        )
        .expect("plan json should parse");
        let body: serde_json::Value = serde_json::from_str(&body).expect("plan json");

        assert_eq!(body["platform"], json!("Linux"));
        assert_eq!(body["action"]["KillProcess"]["pid"], json!(42));
        assert_eq!(body["commands"][0]["program"], json!("kill"));
    }

    #[test]
    fn remediation_plan_payload_rejects_unknown_action() {
        let engine = RemediationEngine::new();
        let error = remediation_plan_from_payload(
            &engine,
            json!({
                "platform": "linux",
                "action": "unknown_action"
            }),
        )
        .expect_err("unknown action should fail");

        assert_eq!(error, "unknown remediation action");
    }

    #[test]
    fn remediation_results_json_serializes_recent_results() {
        let mut engine = RemediationEngine::new();
        engine.record_result(RemediationResult {
            action: RemediationAction::FlushDns,
            status: RemediationStatus::Success,
            commands_run: vec![],
            snapshot_id: Some("snapshot-1".to_string()),
            output: Some("ok".to_string()),
            error: None,
            duration_ms: 12,
        });

        let json = remediation_results_json(&engine, 50);
        let value: serde_json::Value = serde_json::from_str(&json).expect("results json");
        assert_eq!(value.as_array().map(Vec::len), Some(1));
        assert_eq!(value[0]["status"], json!("Success"));
    }

    #[test]
    fn remediation_stats_json_serializes_counts() {
        let mut engine = RemediationEngine::new();
        engine.record_result(RemediationResult {
            action: RemediationAction::FlushDns,
            status: RemediationStatus::Success,
            commands_run: vec![],
            snapshot_id: None,
            output: None,
            error: None,
            duration_ms: 5,
        });

        let json = remediation_stats_json(&engine);
        let value: serde_json::Value = serde_json::from_str(&json).expect("stats json");
        assert_eq!(value["succeeded"], json!(1));
        assert_eq!(value["failed"], json!(0));
    }

    #[test]
    fn snapshot_and_result_tracking() {
        let mut engine = RemediationEngine::new();
        let sid = engine.record_snapshot(
            RemediationAction::FlushDns,
            RemediationPlatform::Linux,
            "host1",
            vec![],
            HashMap::new(),
            1000,
        );
        assert!(engine.get_snapshot(&sid).is_some());

        engine.record_result(RemediationResult {
            action: RemediationAction::FlushDns,
            status: RemediationStatus::Success,
            commands_run: vec![],
            snapshot_id: Some(sid),
            output: None,
            error: None,
            duration_ms: 50,
        });
        let stats = engine.stats();
        assert_eq!(stats.succeeded, 1);
    }

    #[test]
    fn restore_file_and_restart_service_are_adapter_backed() {
        let restore = platform_commands(
            &RemediationAction::RestoreFile {
                path: "/tmp/dropper".into(),
                source: "/var/quarantine/tmp_dropper".into(),
            },
            &RemediationPlatform::Linux,
        );
        assert_eq!(restore[0].program, "cp");
        assert_eq!(restore[0].args[0], "/var/quarantine/tmp_dropper");

        let restart = platform_commands(
            &RemediationAction::RestartService {
                service_name: "wardex-agent".into(),
            },
            &RemediationPlatform::Linux,
        );
        assert_eq!(restart[0].program, "systemctl");
        assert!(restart[0].args.contains(&"restart".to_string()));
    }

    #[test]
    fn sanitize_filename_strips_slashes() {
        assert_eq!(sanitize_filename("/etc/passwd"), "etc_passwd");
        assert_eq!(
            sanitize_filename("C:\\Windows\\file.exe"),
            "C:_Windows_file.exe"
        );
    }
}
