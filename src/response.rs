// Response orchestration with approval workflows, protected assets, blast-radius checks.
// ADR-0008: Response guardrails.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Mutex;

use crate::enforcement::{
    EnforcementResult, FilesystemEnforcer, NetworkEnforcer, ProcessEnforcer, ProcessTarget,
};

// ── Data model ──────────────────────────────────────────────────

/// Severity-based action tiers controlling automatic vs manual response.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ActionTier {
    /// Fully automatic, no approval needed (e.g. log, alert).
    Auto,
    /// Requires single analyst approval within SLA.
    SingleApproval,
    /// Requires two independent approvals for high-impact actions.
    DualApproval,
    /// Blocked — only permitted via break-glass procedure.
    BreakGlass,
}

/// A response action request flowing through the approval pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseRequest {
    pub id: String,
    pub action: ResponseAction,
    pub target: ResponseTarget,
    pub reason: String,
    pub severity: String,
    pub tier: ActionTier,
    pub status: ApprovalStatus,
    pub requested_at: String,
    pub requested_by: String,
    pub approvals: Vec<ApprovalRecord>,
    pub dry_run: bool,
    /// Blast-radius assessment result.
    pub blast_radius: Option<BlastRadius>,
    /// Whether the target is a protected asset.
    pub is_protected_asset: bool,
}

/// Concrete response action types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ResponseAction {
    Alert,
    Isolate,
    Throttle { rate_limit_kbps: u32 },
    KillProcess { pid: u32, process_name: String },
    QuarantineFile { path: String },
    BlockIp { ip: String },
    DisableAccount { username: String },
    RollbackConfig { config_name: String },
    Custom { name: String, payload: String },
}

/// What the response action targets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseTarget {
    pub hostname: String,
    pub agent_uid: Option<String>,
    pub asset_tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
    Executed,
    DryRunCompleted,
    /// Execution was attempted but the enforcement engine reported failure
    /// (e.g. the target process/host is not present on this node, or no
    /// enforcement backend is wired for the action). Never used to mean
    /// "succeeded" — this is the honest outcome for a non-effecting action.
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRecord {
    pub approver: String,
    pub decision: ApprovalDecision,
    pub timestamp: String,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ApprovalDecision {
    Approve,
    Deny,
}

/// Blast-radius assessment for a proposed response action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastRadius {
    /// Number of users/services affected.
    pub affected_services: u32,
    /// Number of endpoints affected.
    pub affected_endpoints: u32,
    /// Risk level: low, medium, high, critical.
    pub risk_level: String,
    /// Description of potential impact.
    pub impact_summary: String,
}

// ── Protected asset registry ────────────────────────────────────

/// Assets that require elevated approval for any response action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedAsset {
    pub hostname: String,
    pub asset_type: ProtectedAssetType,
    pub owner: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProtectedAssetType {
    DomainController,
    JumpBox,
    CiRunner,
    Database,
    CriticalService,
    Executive,
}

// ── Orchestrator ────────────────────────────────────────────────

/// Response orchestrator managing the approval pipeline.
pub struct ResponseOrchestrator {
    requests: Mutex<Vec<ResponseRequest>>,
    protected_assets: Vec<ProtectedAsset>,
    /// Immutable audit ledger of all response decisions.
    audit_ledger: Mutex<Vec<ResponseAuditEntry>>,
    /// SLA timeout for approval in seconds (default 300).
    pub approval_sla_secs: u64,
    /// Node-local OS enforcement engines. Approved/auto actions are carried out
    /// by these (real syscalls on Unix; honestly labelled simulation on other
    /// platforms). Actions targeting a resource not present on this node report
    /// failure rather than a fabricated success.
    process_enforcer: Mutex<ProcessEnforcer>,
    network_enforcer: Mutex<NetworkEnforcer>,
    filesystem_enforcer: Mutex<FilesystemEnforcer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseAuditEntry {
    pub request_id: String,
    pub action: String,
    pub target_hostname: String,
    pub tier: ActionTier,
    pub status: ApprovalStatus,
    pub timestamp: String,
    pub dry_run: bool,
    pub approvals: Vec<ApprovalRecord>,
    pub actor: String,
    pub reason: String,
    pub input_context: serde_json::Value,
    pub dry_run_result: Option<DryRunResult>,
    pub execution_result: Option<String>,
    pub execution_audit: Option<ResponseExecutionAudit>,
    pub reversal_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseExecutionAudit {
    pub request_id: String,
    pub action: String,
    pub target_hostname: String,
    pub operator: String,
    pub started_at: String,
    pub completed_at: String,
    pub status: String,
    pub commands: Vec<ResponseCommandAudit>,
    pub result_summary: String,
    pub reversal_path: String,
    pub verification_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseCommandAudit {
    pub timestamp: String,
    pub host: String,
    pub command: String,
    pub command_summary: String,
    pub exit_code: i32,
    pub status: String,
    pub stdout_excerpt: Option<String>,
    pub stderr_excerpt: Option<String>,
}

impl ResponseOrchestrator {
    pub fn new() -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            protected_assets: Vec::new(),
            audit_ledger: Mutex::new(Vec::new()),
            approval_sla_secs: 300,
            process_enforcer: Mutex::new(ProcessEnforcer::new()),
            network_enforcer: Mutex::new(NetworkEnforcer::new()),
            filesystem_enforcer: Mutex::new(FilesystemEnforcer::new()),
        }
    }

    /// Carry out a response action via the node-local enforcement engines and
    /// return the real [`EnforcementResult`]. Actions with no wired backend
    /// return an unsuccessful result with an honest explanation — they are
    /// never reported as executed.
    fn enforce_action(
        &self,
        action: &ResponseAction,
        target: &ResponseTarget,
    ) -> EnforcementResult {
        let unsupported = |what: &str, why: &str| EnforcementResult {
            action: what.to_string(),
            success: false,
            detail: format!("not executed: {why}"),
            rollback_command: None,
        };
        match action {
            ResponseAction::KillProcess { pid, process_name } => self
                .process_enforcer
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .kill_process(&ProcessTarget {
                    pid: *pid,
                    name: process_name.clone(),
                    user: String::new(),
                }),
            ResponseAction::Isolate => self
                .network_enforcer
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .block_all(&target.hostname),
            ResponseAction::Throttle { rate_limit_kbps } => self
                .network_enforcer
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .rate_limit(&target.hostname, *rate_limit_kbps),
            ResponseAction::QuarantineFile { path } => self
                .filesystem_enforcer
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .quarantine_path(Path::new(path)),
            ResponseAction::Alert => EnforcementResult {
                action: "alert".to_string(),
                success: true,
                detail: format!("Alert notification recorded for {}", target.hostname),
                rollback_command: None,
            },
            ResponseAction::BlockIp { ip } => unsupported(
                &format!("block_ip({ip})"),
                "no network ACL/firewall backend is wired for IP blocking on this node",
            ),
            ResponseAction::DisableAccount { username } => unsupported(
                &format!("disable_account({username})"),
                "no identity-provider backend is wired for account disabling on this node",
            ),
            ResponseAction::RollbackConfig { config_name } => unsupported(
                &format!("rollback_config({config_name})"),
                "no configuration-management backend is wired for config rollback on this node",
            ),
            ResponseAction::Custom { name, .. } => unsupported(
                &format!("custom({name})"),
                "custom actions have no automated enforcement backend",
            ),
        }
    }

    pub fn register_protected_asset(&mut self, asset: ProtectedAsset) {
        self.protected_assets.push(asset);
    }

    pub fn protected_assets(&self) -> &[ProtectedAsset] {
        &self.protected_assets
    }

    pub fn protected_asset_count(&self) -> usize {
        self.protected_assets.len()
    }

    fn is_protected(&self, hostname: &str) -> bool {
        self.protected_assets.iter().any(|a| a.hostname == hostname)
    }

    /// Determine the action tier for a given response action + target.
    pub fn determine_tier(&self, action: &ResponseAction, target: &ResponseTarget) -> ActionTier {
        let is_protected = self.is_protected(&target.hostname);

        match action {
            ResponseAction::Alert => ActionTier::Auto,
            ResponseAction::Throttle { .. } => {
                if is_protected {
                    ActionTier::SingleApproval
                } else {
                    ActionTier::Auto
                }
            }
            ResponseAction::KillProcess { .. } | ResponseAction::QuarantineFile { .. } => {
                if is_protected {
                    ActionTier::DualApproval
                } else {
                    ActionTier::SingleApproval
                }
            }
            ResponseAction::Isolate | ResponseAction::BlockIp { .. } => {
                if is_protected {
                    ActionTier::BreakGlass
                } else {
                    ActionTier::SingleApproval
                }
            }
            ResponseAction::DisableAccount { .. } => {
                if is_protected {
                    ActionTier::BreakGlass
                } else {
                    ActionTier::DualApproval
                }
            }
            ResponseAction::RollbackConfig { .. } => ActionTier::SingleApproval,
            ResponseAction::Custom { .. } => {
                if is_protected {
                    ActionTier::DualApproval
                } else {
                    ActionTier::SingleApproval
                }
            }
        }
    }

    /// Assess blast radius for a response action.
    pub fn assess_blast_radius(
        &self,
        action: &ResponseAction,
        target: &ResponseTarget,
    ) -> BlastRadius {
        let (services, endpoints, risk) = match action {
            ResponseAction::Alert => (0, 0, "low"),
            ResponseAction::Throttle { .. } => (1, 1, "low"),
            ResponseAction::KillProcess { .. } => (1, 1, "medium"),
            ResponseAction::QuarantineFile { .. } => (1, 1, "medium"),
            ResponseAction::BlockIp { .. } => {
                // Blocking an IP could affect multiple endpoints
                (
                    3,
                    5,
                    if self.is_protected(&target.hostname) {
                        "critical"
                    } else {
                        "high"
                    },
                )
            }
            ResponseAction::Isolate => (
                5,
                1,
                if self.is_protected(&target.hostname) {
                    "critical"
                } else {
                    "high"
                },
            ),
            ResponseAction::DisableAccount { .. } => (10, 10, "critical"),
            ResponseAction::RollbackConfig { .. } => (2, 1, "medium"),
            ResponseAction::Custom { .. } => (1, 1, "medium"),
        };

        BlastRadius {
            affected_services: services,
            affected_endpoints: endpoints,
            risk_level: risk.into(),
            impact_summary: format!(
                "Action {:?} on {} may affect {} services across {} endpoints",
                std::mem::discriminant(action),
                target.hostname,
                services,
                endpoints
            ),
        }
    }

    /// Submit a response request through the approval pipeline.
    pub fn submit(&self, mut request: ResponseRequest) -> Result<String, String> {
        let tier = self.determine_tier(&request.action, &request.target);
        request.tier = tier;
        request.is_protected_asset = self.is_protected(&request.target.hostname);
        request.blast_radius = Some(self.assess_blast_radius(&request.action, &request.target));

        // BreakGlass actions cannot be submitted through normal flow
        if tier == ActionTier::BreakGlass && !request.dry_run {
            return Err("Break-glass required: this action on a protected asset requires emergency authorization".into());
        }

        // Auto-tier actions execute immediately (or simulate in dry-run). The
        // non-dry-run path performs real enforcement and records the actual
        // result; status reflects whether the enforcement engine succeeded.
        if tier == ActionTier::Auto && !request.dry_run {
            let result = self.enforce_action(&request.action, &request.target);
            request.status = if result.success {
                ApprovalStatus::Executed
            } else {
                ApprovalStatus::Failed
            };
            let id = request.id.clone();
            let description = result.detail.clone();
            let execution_audit = response_execution_audit(&request, &result);
            self.record_audit_with_result(&request, Some(description), Some(execution_audit));
            self.requests
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(request);
            return Ok(id);
        }

        request.status = if tier == ActionTier::Auto {
            ApprovalStatus::DryRunCompleted
        } else {
            ApprovalStatus::Pending
        };

        let id = request.id.clone();
        self.record_audit(&request);
        self.requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(request);
        Ok(id)
    }

    /// Process an approval decision for a pending request.
    pub fn approve(
        &self,
        request_id: &str,
        record: ApprovalRecord,
    ) -> Result<ApprovalStatus, String> {
        let mut requests = self.requests.lock().unwrap_or_else(|e| e.into_inner());
        let req = requests
            .iter_mut()
            .find(|r| r.id == request_id)
            .ok_or_else(|| format!("Request {} not found", request_id))?;

        if req.status != ApprovalStatus::Pending {
            return Err(format!(
                "Request {} is not pending (status: {:?})",
                request_id, req.status
            ));
        }

        if record.decision == ApprovalDecision::Deny {
            req.status = ApprovalStatus::Denied;
            req.approvals.push(record);
            self.record_audit_inner(req);
            return Ok(ApprovalStatus::Denied);
        }

        if record.approver == req.requested_by {
            return Err("Requester cannot approve their own response request".into());
        }

        // Check for duplicate approver
        if req.approvals.iter().any(|a| a.approver == record.approver) {
            return Err("Same approver cannot approve twice".into());
        }

        req.approvals.push(record);

        let required_approvals = match req.tier {
            ActionTier::SingleApproval => 1,
            ActionTier::DualApproval => 2,
            _ => 1,
        };

        let approve_count = req
            .approvals
            .iter()
            .filter(|a| a.decision == ApprovalDecision::Approve)
            .count();

        if approve_count >= required_approvals {
            req.status = if req.dry_run {
                ApprovalStatus::DryRunCompleted
            } else {
                ApprovalStatus::Approved
            };
        }

        let status = req.status.clone();
        self.record_audit_inner(req);
        Ok(status)
    }

    /// Get pending requests.
    pub fn pending_requests(&self) -> Vec<ResponseRequest> {
        self.requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|r| r.status == ApprovalStatus::Pending)
            .cloned()
            .collect()
    }

    /// Get all requests.
    pub fn all_requests(&self) -> Vec<ResponseRequest> {
        self.requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Get a request by ID.
    pub fn get_request(&self, id: &str) -> Option<ResponseRequest> {
        self.requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|r| r.id == id)
            .cloned()
    }

    /// Expire pending requests past SLA.
    pub fn expire_stale(&self, now_epoch: u64) {
        let mut requests = self.requests.lock().unwrap_or_else(|e| e.into_inner());
        for req in requests.iter_mut() {
            if req.status == ApprovalStatus::Pending {
                // Try RFC3339 first, then fall back to plain epoch
                let req_epoch =
                    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&req.requested_at) {
                        dt.timestamp() as u64
                    } else {
                        req.requested_at.parse::<u64>().unwrap_or(0)
                    };
                if now_epoch.saturating_sub(req_epoch) >= self.approval_sla_secs {
                    req.status = ApprovalStatus::Expired;
                    self.record_audit_inner(req);
                }
            }
        }
    }

    /// Immutable audit ledger entries.
    pub fn audit_ledger(&self) -> Vec<ResponseAuditEntry> {
        self.audit_ledger
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn execution_audits(&self, request_id: Option<&str>) -> Vec<ResponseExecutionAudit> {
        self.execution_audits_filtered(request_id, None)
    }

    pub fn execution_audits_filtered(
        &self,
        request_id: Option<&str>,
        action_id: Option<&str>,
    ) -> Vec<ResponseExecutionAudit> {
        self.audit_ledger
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|entry| {
                request_id
                    .map(|target_id| entry.request_id == target_id)
                    .unwrap_or(true)
            })
            .filter_map(|entry| entry.execution_audit.clone())
            .filter(|audit| {
                action_id
                    .map(|target_action| {
                        response_action_filter_matches(&audit.action, target_action)
                    })
                    .unwrap_or(true)
            })
            .collect()
    }

    fn record_audit(&self, req: &ResponseRequest) {
        self.record_audit_with_result(req, None, None);
    }

    fn record_audit_with_result(
        &self,
        req: &ResponseRequest,
        execution_result: Option<String>,
        execution_audit: Option<ResponseExecutionAudit>,
    ) {
        self.audit_ledger
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(ResponseAuditEntry {
                request_id: req.id.clone(),
                action: format!("{:?}", req.action),
                target_hostname: req.target.hostname.clone(),
                tier: req.tier,
                status: req.status.clone(),
                timestamp: req.requested_at.clone(),
                dry_run: req.dry_run,
                approvals: req.approvals.clone(),
                actor: req.requested_by.clone(),
                reason: req.reason.clone(),
                input_context: response_input_context(req),
                dry_run_result: req.dry_run.then(|| {
                    let Some(blast_radius) = req.blast_radius.clone() else {
                        return dry_run_simulate(self, &req.action, &req.target);
                    };
                    DryRunResult {
                        request_id: req.id.clone(),
                        would_execute: req.tier != ActionTier::BreakGlass,
                        tier: req.tier,
                        blast_radius,
                        is_protected: req.is_protected_asset,
                        approvals_required: approvals_required(req.tier),
                        simulated_effects: simulated_effects(&req.action, &req.target),
                    }
                }),
                execution_result,
                execution_audit,
                reversal_path: reversal_path(&req.action, &req.target),
            });
    }

    fn record_audit_inner(&self, req: &ResponseRequest) {
        self.audit_ledger
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(ResponseAuditEntry {
                request_id: req.id.clone(),
                action: format!("{:?}", req.action),
                target_hostname: req.target.hostname.clone(),
                tier: req.tier,
                status: req.status.clone(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                dry_run: req.dry_run,
                approvals: req.approvals.clone(),
                actor: req
                    .approvals
                    .last()
                    .map(|record| record.approver.clone())
                    .unwrap_or_else(|| req.requested_by.clone()),
                reason: req.reason.clone(),
                input_context: response_input_context(req),
                dry_run_result: req.dry_run.then(|| DryRunResult {
                    request_id: req.id.clone(),
                    would_execute: req.tier != ActionTier::BreakGlass,
                    tier: req.tier,
                    blast_radius: req
                        .blast_radius
                        .clone()
                        .unwrap_or_else(|| self.assess_blast_radius(&req.action, &req.target)),
                    is_protected: req.is_protected_asset,
                    approvals_required: approvals_required(req.tier),
                    simulated_effects: simulated_effects(&req.action, &req.target),
                }),
                execution_result: None,
                execution_audit: None,
                reversal_path: reversal_path(&req.action, &req.target),
            });
    }

    /// Execute all approved (non-dry-run) requests by invoking the node-local
    /// enforcement engine for each action, and return the real per-action
    /// result detail. Each request's status becomes `Executed` only when the
    /// enforcement engine reports success, otherwise `Failed`. Actions whose
    /// target resource is not present on this node (or that have no wired
    /// backend) report failure rather than a fabricated success.
    pub fn execute_approved(&self) -> Vec<String> {
        self.execute_approved_matching(None)
    }

    /// Execute approved requests, optionally narrowing to a specific request id.
    pub fn execute_approved_matching(&self, request_id: Option<&str>) -> Vec<String> {
        let mut requests = self.requests.lock().unwrap_or_else(|e| e.into_inner());
        let mut executed = Vec::new();
        let mut executed_reqs = Vec::new();
        for req in requests.iter_mut() {
            if let Some(target_id) = request_id
                && req.id != target_id
            {
                continue;
            }
            if req.status != ApprovalStatus::Approved || req.dry_run {
                continue;
            }
            let result = self.enforce_action(&req.action, &req.target);
            req.status = if result.success {
                ApprovalStatus::Executed
            } else {
                ApprovalStatus::Failed
            };
            let description = result.detail.clone();
            let execution_audit = response_execution_audit(req, &result);
            executed.push(description.clone());
            executed_reqs.push((req.clone(), description, execution_audit));
        }
        drop(requests);
        for (req, description, execution_audit) in &executed_reqs {
            self.record_audit_with_result(
                req,
                Some(description.clone()),
                Some(execution_audit.clone()),
            );
        }
        executed
    }
}

fn response_action_filter_matches(action: &str, filter: &str) -> bool {
    let normalized_filter = filter.trim().to_ascii_lowercase().replace('-', "_");
    let normalized_action = action.trim().to_ascii_lowercase();
    if normalized_filter.is_empty() {
        return true;
    }
    match normalized_filter.as_str() {
        "kill_process" => normalized_action.starts_with("killprocess"),
        "block_ip" => normalized_action.starts_with("blockip"),
        "quarantine_file" => normalized_action.starts_with("quarantinefile"),
        "disable_account" => normalized_action.starts_with("disableaccount"),
        "rollback_config" => normalized_action.starts_with("rollbackconfig"),
        "alert" => normalized_action.starts_with("alert"),
        "isolate" => normalized_action.starts_with("isolate"),
        "throttle" => normalized_action.starts_with("throttle"),
        other => normalized_action.contains(other),
    }
}

impl Default for ResponseOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

// ── Dry-run simulation ──────────────────────────────────────────

/// Result of a dry-run simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DryRunResult {
    pub request_id: String,
    pub would_execute: bool,
    pub tier: ActionTier,
    pub blast_radius: BlastRadius,
    pub is_protected: bool,
    pub approvals_required: usize,
    pub simulated_effects: Vec<String>,
}

/// Simulate a response action without executing it.
pub fn dry_run_simulate(
    orchestrator: &ResponseOrchestrator,
    action: &ResponseAction,
    target: &ResponseTarget,
) -> DryRunResult {
    let tier = orchestrator.determine_tier(action, target);
    let blast = orchestrator.assess_blast_radius(action, target);
    let is_protected = orchestrator.is_protected(&target.hostname);

    let approvals_required = match tier {
        ActionTier::Auto => 0,
        ActionTier::SingleApproval => 1,
        ActionTier::DualApproval => 2,
        ActionTier::BreakGlass => usize::MAX,
    };

    DryRunResult {
        request_id: "dry-run".into(),
        would_execute: tier != ActionTier::BreakGlass,
        tier,
        blast_radius: blast,
        is_protected,
        approvals_required,
        simulated_effects: simulated_effects(action, target),
    }
}

fn approvals_required(tier: ActionTier) -> usize {
    match tier {
        ActionTier::Auto => 0,
        ActionTier::SingleApproval => 1,
        ActionTier::DualApproval => 2,
        ActionTier::BreakGlass => usize::MAX,
    }
}

fn response_input_context(req: &ResponseRequest) -> serde_json::Value {
    serde_json::json!({
        "target": req.target.clone(),
        "severity": req.severity.clone(),
        "tier": req.tier,
        "dry_run": req.dry_run,
        "protected_asset": req.is_protected_asset,
        "blast_radius": req.blast_radius.clone(),
        "requested_at": req.requested_at.clone(),
    })
}

fn simulated_effects(action: &ResponseAction, target: &ResponseTarget) -> Vec<String> {
    match action {
        ResponseAction::KillProcess { pid, process_name } => {
            vec![format!("Would kill process {} (PID {})", process_name, pid)]
        }
        ResponseAction::Isolate => vec![format!("Would isolate host {}", target.hostname)],
        ResponseAction::BlockIp { ip } => vec![format!("Would block IP {}", ip)],
        ResponseAction::QuarantineFile { path } => {
            vec![format!("Would quarantine file {}", path)]
        }
        ResponseAction::DisableAccount { username } => {
            vec![format!("Would disable account {}", username)]
        }
        ResponseAction::Throttle { rate_limit_kbps } => {
            vec![format!("Would throttle to {} kbps", rate_limit_kbps)]
        }
        ResponseAction::RollbackConfig { config_name } => {
            vec![format!("Would rollback config {}", config_name)]
        }
        ResponseAction::Alert => vec!["Would generate alert notification".into()],
        ResponseAction::Custom { name, .. } => {
            vec![format!("Would execute custom action: {}", name)]
        }
    }
}

fn response_execution_audit(
    req: &ResponseRequest,
    result: &EnforcementResult,
) -> ResponseExecutionAudit {
    let completed_at = chrono::Utc::now().to_rfc3339();
    let command = response_command_string(&req.action, &req.target);
    let success = result.success;
    ResponseExecutionAudit {
        request_id: req.id.clone(),
        action: format!("{:?}", req.action),
        target_hostname: req.target.hostname.clone(),
        operator: req
            .approvals
            .last()
            .map(|record| record.approver.clone())
            .unwrap_or_else(|| req.requested_by.clone()),
        started_at: completed_at.clone(),
        completed_at: completed_at.clone(),
        status: if success { "completed" } else { "failed" }.to_string(),
        commands: vec![ResponseCommandAudit {
            timestamp: completed_at,
            host: req.target.hostname.clone(),
            command: command.clone(),
            command_summary: response_command_summary(&req.action),
            exit_code: if success { 0 } else { 1 },
            status: if success { "success" } else { "failed" }.to_string(),
            stdout_excerpt: success.then(|| result.detail.clone()),
            stderr_excerpt: (!success).then(|| result.detail.clone()),
        }],
        result_summary: result.detail.clone(),
        reversal_path: reversal_path(&req.action, &req.target),
        verification_status: if success {
            "pending_post_action_evidence"
        } else {
            "not_executed"
        }
        .to_string(),
    }
}

fn response_command_summary(action: &ResponseAction) -> String {
    match action {
        ResponseAction::Alert => "Send alert notification".to_string(),
        ResponseAction::Isolate => "Isolate host".to_string(),
        ResponseAction::Throttle { .. } => "Apply network throttle".to_string(),
        ResponseAction::KillProcess { process_name, .. } => format!("Kill process {process_name}"),
        ResponseAction::QuarantineFile { .. } => "Quarantine file".to_string(),
        ResponseAction::BlockIp { .. } => "Block network address".to_string(),
        ResponseAction::DisableAccount { .. } => "Disable account".to_string(),
        ResponseAction::RollbackConfig { .. } => "Rollback configuration".to_string(),
        ResponseAction::Custom { name, .. } => format!("Execute custom action {name}"),
    }
}

fn response_command_string(action: &ResponseAction, target: &ResponseTarget) -> String {
    match action {
        ResponseAction::Alert => format!(
            "wardex-response notify --host {}",
            shell_escape(&target.hostname)
        ),
        ResponseAction::Isolate => format!(
            "wardex-response isolate-host --host {}",
            shell_escape(&target.hostname)
        ),
        ResponseAction::Throttle { rate_limit_kbps } => format!(
            "wardex-response throttle --host {} --kbps {}",
            shell_escape(&target.hostname),
            rate_limit_kbps
        ),
        ResponseAction::KillProcess { pid, process_name } => format!(
            "wardex-response kill-process --host {} --pid {} --name {}",
            shell_escape(&target.hostname),
            pid,
            shell_escape(process_name)
        ),
        ResponseAction::QuarantineFile { path } => format!(
            "wardex-response quarantine-file --host {} --path {}",
            shell_escape(&target.hostname),
            shell_escape(path)
        ),
        ResponseAction::BlockIp { ip } => format!(
            "wardex-response block-ip --host {} --ip {}",
            shell_escape(&target.hostname),
            shell_escape(ip)
        ),
        ResponseAction::DisableAccount { username } => format!(
            "wardex-response disable-account --host {} --username {}",
            shell_escape(&target.hostname),
            shell_escape(username)
        ),
        ResponseAction::RollbackConfig { config_name } => format!(
            "wardex-response rollback-config --host {} --config {}",
            shell_escape(&target.hostname),
            shell_escape(config_name)
        ),
        ResponseAction::Custom { name, .. } => format!(
            "wardex-response custom --host {} --name {} --payload [redacted]",
            shell_escape(&target.hostname),
            shell_escape(name)
        ),
    }
}

fn shell_escape(value: &str) -> String {
    let safe = value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | ':' | '/' | '@'));
    if safe {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn reversal_path(action: &ResponseAction, target: &ResponseTarget) -> String {
    match action {
        ResponseAction::Alert => "No reversal required; notification-only action.".to_string(),
        ResponseAction::Isolate => format!(
            "Remove host {} from isolation and verify heartbeat plus policy sync.",
            target.hostname
        ),
        ResponseAction::Throttle { .. } => format!(
            "Restore normal rate limits for {} and verify service latency.",
            target.hostname
        ),
        ResponseAction::KillProcess { process_name, .. } => {
            format!(
                "Restart {process_name} only from a verified clean binary if business impact requires it."
            )
        }
        ResponseAction::QuarantineFile { path } => {
            format!("Release {path} from quarantine only after hash, YARA, and provenance review.")
        }
        ResponseAction::BlockIp { ip } => {
            format!(
                "Remove block for {ip} from network controls and confirm no active incident dependency."
            )
        }
        ResponseAction::DisableAccount { username } => {
            format!(
                "Re-enable {username} after credential reset, MFA verification, and owner approval."
            )
        }
        ResponseAction::RollbackConfig { config_name } => {
            format!(
                "Reapply the superseded {config_name} config through change control if rollback is no longer needed."
            )
        }
        ResponseAction::Custom { name, .. } => {
            format!("Follow the documented reversal procedure for custom action {name}.")
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_target(hostname: &str) -> ResponseTarget {
        ResponseTarget {
            hostname: hostname.into(),
            agent_uid: None,
            asset_tags: Vec::new(),
        }
    }

    fn make_request(
        id: &str,
        action: ResponseAction,
        hostname: &str,
        dry_run: bool,
    ) -> ResponseRequest {
        ResponseRequest {
            id: id.into(),
            action,
            target: make_target(hostname),
            reason: "test".into(),
            severity: "high".into(),
            tier: ActionTier::Auto,
            status: ApprovalStatus::Pending,
            requested_at: "1000".into(),
            requested_by: "system".into(),
            approvals: Vec::new(),
            dry_run,
            blast_radius: None,
            is_protected_asset: false,
        }
    }

    #[test]
    fn auto_tier_executes_immediately() {
        let orch = ResponseOrchestrator::new();
        let req = make_request("r1", ResponseAction::Alert, "host-1", false);
        let id = orch.submit(req).unwrap();
        let r = orch.get_request(&id).unwrap();
        assert_eq!(r.status, ApprovalStatus::Executed);
        assert_eq!(r.tier, ActionTier::Auto);
    }

    #[test]
    fn single_approval_workflow() {
        let orch = ResponseOrchestrator::new();
        let req = make_request(
            "r2",
            ResponseAction::KillProcess {
                pid: 100,
                process_name: "evil".into(),
            },
            "host-1",
            false,
        );
        let id = orch.submit(req).unwrap();

        let r = orch.get_request(&id).unwrap();
        assert_eq!(r.status, ApprovalStatus::Pending);
        assert_eq!(r.tier, ActionTier::SingleApproval);

        let status = orch
            .approve(
                &id,
                ApprovalRecord {
                    approver: "analyst-1".into(),
                    decision: ApprovalDecision::Approve,
                    timestamp: "now".into(),
                    comment: None,
                },
            )
            .unwrap();
        assert_eq!(status, ApprovalStatus::Approved);
    }

    #[test]
    fn execution_audit_records_command_transcript() {
        let orch = ResponseOrchestrator::new();
        let req = make_request(
            "r-exec",
            ResponseAction::KillProcess {
                pid: 31337,
                process_name: "suspicious worker".into(),
            },
            "host-1",
            false,
        );
        let id = orch.submit(req).unwrap();
        orch.approve(
            &id,
            ApprovalRecord {
                approver: "analyst-2".into(),
                decision: ApprovalDecision::Approve,
                timestamp: "1001".into(),
                comment: Some("verified blast radius".into()),
            },
        )
        .unwrap();

        let executed = orch.execute_approved_matching(Some(&id));
        assert_eq!(executed.len(), 1);

        let audits = orch.execution_audits(Some(&id));
        assert_eq!(audits.len(), 1);
        let audit = &audits[0];
        assert_eq!(audit.request_id, id);
        assert_eq!(audit.operator, "analyst-2");
        assert_eq!(audit.commands.len(), 1);
        // PID 31337 does not exist on the test node, so the local enforcement
        // engine honestly reports failure rather than a fabricated success.
        assert_eq!(audit.commands[0].exit_code, 1);
        assert_eq!(audit.status, "failed");
        assert!(audit.commands[0].command.contains("kill-process"));
        assert!(audit.commands[0].command.contains("--pid 31337"));
        assert_eq!(audit.verification_status, "not_executed");
    }

    #[test]
    fn execution_audit_records_successful_action() {
        // An Alert action always succeeds (it records a notification), so the
        // audit reflects a real completed execution — proving the success path.
        let orch = ResponseOrchestrator::new();
        let req = make_request("r-alert", ResponseAction::Alert, "host-1", false);
        // Alert is auto-tier, so submit() executes it immediately.
        let id = orch.submit(req).unwrap();

        let audits = orch.execution_audits(Some(&id));
        assert_eq!(audits.len(), 1);
        let audit = &audits[0];
        assert_eq!(audit.status, "completed");
        assert_eq!(audit.commands[0].exit_code, 0);
        assert_eq!(audit.verification_status, "pending_post_action_evidence");

        let status = orch.get_request(&id).map(|r| r.status).unwrap();
        assert_eq!(status, ApprovalStatus::Executed);
    }

    #[test]
    fn execution_audit_filters_by_action_id_alias() {
        let orch = ResponseOrchestrator::new();
        let req = make_request(
            "r-action-filter",
            ResponseAction::KillProcess {
                pid: 4242,
                process_name: "worker".into(),
            },
            "host-1",
            false,
        );
        let id = orch.submit(req).unwrap();
        orch.approve(
            &id,
            ApprovalRecord {
                approver: "analyst-2".into(),
                decision: ApprovalDecision::Approve,
                timestamp: "1001".into(),
                comment: None,
            },
        )
        .unwrap();
        orch.execute_approved_matching(Some(&id));

        assert_eq!(
            orch.execution_audits_filtered(None, Some("kill-process"))
                .len(),
            1
        );
        assert_eq!(
            orch.execution_audits_filtered(None, Some("block-ip")).len(),
            0
        );
    }

    #[test]
    fn protected_asset_elevates_tier() {
        let mut orch = ResponseOrchestrator::new();
        orch.register_protected_asset(ProtectedAsset {
            hostname: "dc-01".into(),
            asset_type: ProtectedAssetType::DomainController,
            owner: "infra-team".into(),
            reason: "Primary domain controller".into(),
        });

        // Kill on protected: DualApproval
        let req = make_request(
            "r3",
            ResponseAction::KillProcess {
                pid: 50,
                process_name: "svc".into(),
            },
            "dc-01",
            false,
        );
        let id = orch.submit(req).unwrap();
        let r = orch.get_request(&id).unwrap();
        assert_eq!(r.tier, ActionTier::DualApproval);
        assert!(r.is_protected_asset);

        // Need two approvals
        orch.approve(
            &id,
            ApprovalRecord {
                approver: "analyst-1".into(),
                decision: ApprovalDecision::Approve,
                timestamp: "now".into(),
                comment: None,
            },
        )
        .unwrap();
        let r = orch.get_request(&id).unwrap();
        assert_eq!(r.status, ApprovalStatus::Pending); // Still pending

        let status = orch
            .approve(
                &id,
                ApprovalRecord {
                    approver: "analyst-2".into(),
                    decision: ApprovalDecision::Approve,
                    timestamp: "now".into(),
                    comment: None,
                },
            )
            .unwrap();
        assert_eq!(status, ApprovalStatus::Approved);
    }

    #[test]
    fn break_glass_blocks_normal_submit() {
        let mut orch = ResponseOrchestrator::new();
        orch.register_protected_asset(ProtectedAsset {
            hostname: "dc-01".into(),
            asset_type: ProtectedAssetType::DomainController,
            owner: "infra".into(),
            reason: "DC".into(),
        });

        let req = make_request("r4", ResponseAction::Isolate, "dc-01", false);
        let result = orch.submit(req);
        assert!(result.is_err(), "Isolating a DC should require break-glass");
    }

    #[test]
    fn break_glass_allows_dry_run() {
        let mut orch = ResponseOrchestrator::new();
        orch.register_protected_asset(ProtectedAsset {
            hostname: "dc-01".into(),
            asset_type: ProtectedAssetType::DomainController,
            owner: "infra".into(),
            reason: "DC".into(),
        });

        let req = make_request("r5", ResponseAction::Isolate, "dc-01", true);
        let result = orch.submit(req);
        assert!(result.is_ok(), "Dry-run on break-glass should succeed");
    }

    #[test]
    fn deny_stops_workflow() {
        let orch = ResponseOrchestrator::new();
        let req = make_request(
            "r6",
            ResponseAction::KillProcess {
                pid: 1,
                process_name: "x".into(),
            },
            "host-1",
            false,
        );
        orch.submit(req).unwrap();

        let status = orch
            .approve(
                "r6",
                ApprovalRecord {
                    approver: "analyst".into(),
                    decision: ApprovalDecision::Deny,
                    timestamp: "now".into(),
                    comment: Some("Not warranted".into()),
                },
            )
            .unwrap();

        assert_eq!(status, ApprovalStatus::Denied);
    }

    #[test]
    fn duplicate_approver_rejected() {
        let orch = ResponseOrchestrator::new();
        let req = make_request(
            "r7",
            ResponseAction::KillProcess {
                pid: 1,
                process_name: "x".into(),
            },
            "host-1",
            false,
        );
        orch.submit(req).unwrap();

        orch.approve(
            "r7",
            ApprovalRecord {
                approver: "analyst-1".into(),
                decision: ApprovalDecision::Approve,
                timestamp: "now".into(),
                comment: None,
            },
        )
        .unwrap();
        let result = orch.approve(
            "r7",
            ApprovalRecord {
                approver: "analyst-1".into(),
                decision: ApprovalDecision::Approve,
                timestamp: "now".into(),
                comment: None,
            },
        );
        assert!(result.is_err());
    }

    #[test]
    fn requester_cannot_self_approve() {
        let orch = ResponseOrchestrator::new();
        let mut req = make_request(
            "r7-self",
            ResponseAction::KillProcess {
                pid: 1,
                process_name: "x".into(),
            },
            "host-1",
            false,
        );
        req.requested_by = "analyst-1".into();
        orch.submit(req).unwrap();

        let result = orch.approve(
            "r7-self",
            ApprovalRecord {
                approver: "analyst-1".into(),
                decision: ApprovalDecision::Approve,
                timestamp: "now".into(),
                comment: None,
            },
        );

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("Requester cannot approve their own response request")
        );
        assert_eq!(
            orch.get_request("r7-self").unwrap().status,
            ApprovalStatus::Pending
        );
    }

    #[test]
    fn blast_radius_assessment() {
        let orch = ResponseOrchestrator::new();
        let target = make_target("host-1");
        let br = orch.assess_blast_radius(&ResponseAction::Isolate, &target);
        assert_eq!(br.risk_level, "high");
        assert!(br.affected_services > 0);
    }

    #[test]
    fn dry_run_simulation() {
        let mut orch = ResponseOrchestrator::new();
        orch.register_protected_asset(ProtectedAsset {
            hostname: "jump-box".into(),
            asset_type: ProtectedAssetType::JumpBox,
            owner: "sec".into(),
            reason: "Jump box".into(),
        });

        let result = dry_run_simulate(
            &orch,
            &ResponseAction::KillProcess {
                pid: 42,
                process_name: "malware.bin".into(),
            },
            &make_target("jump-box"),
        );
        assert!(result.is_protected);
        assert_eq!(result.tier, ActionTier::DualApproval);
        assert_eq!(result.approvals_required, 2);
        assert!(!result.simulated_effects.is_empty());
    }

    #[test]
    fn audit_ledger_records() {
        let orch = ResponseOrchestrator::new();
        let req = make_request("r8", ResponseAction::Alert, "host-1", false);
        orch.submit(req).unwrap();
        let ledger = orch.audit_ledger();
        assert!(!ledger.is_empty());
        assert_eq!(ledger[0].request_id, "r8");
        assert_eq!(ledger[0].actor, "system");
        assert_eq!(ledger[0].reason, "test");
        assert!(ledger[0].input_context.is_object());
        assert!(ledger[0].reversal_path.contains("No reversal required"));
    }

    #[test]
    fn dry_run_audit_record_is_reopenable() {
        let orch = ResponseOrchestrator::new();
        let req = make_request("r8-dry", ResponseAction::Isolate, "host-1", true);
        orch.submit(req).unwrap();
        orch.approve(
            "r8-dry",
            ApprovalRecord {
                approver: "analyst".into(),
                decision: ApprovalDecision::Approve,
                timestamp: "now".into(),
                comment: Some("reviewed dry-run".into()),
            },
        )
        .unwrap();

        let ledger = orch.audit_ledger();
        let completed = ledger
            .iter()
            .find(|entry| entry.status == ApprovalStatus::DryRunCompleted)
            .expect("dry-run completion audit entry");
        assert_eq!(completed.actor, "analyst");
        assert!(completed.dry_run_result.is_some());
        assert_eq!(completed.input_context["target"]["hostname"], "host-1");
        assert!(completed.reversal_path.contains("Remove host"));
    }

    #[test]
    fn expire_stale_requests() {
        let orch = ResponseOrchestrator::new();
        let req = make_request(
            "r9",
            ResponseAction::KillProcess {
                pid: 1,
                process_name: "x".into(),
            },
            "host-1",
            false,
        );
        orch.submit(req).unwrap();

        orch.expire_stale(2000); // 2000 - 1000 = 1000 > 300 SLA
        let r = orch.get_request("r9").unwrap();
        assert_eq!(r.status, ApprovalStatus::Expired);
    }

    #[test]
    fn pending_requests_filter() {
        let orch = ResponseOrchestrator::new();
        orch.submit(make_request("p1", ResponseAction::Alert, "h", false))
            .unwrap();
        orch.submit(make_request(
            "p2",
            ResponseAction::KillProcess {
                pid: 1,
                process_name: "x".into(),
            },
            "h",
            false,
        ))
        .unwrap();
        let pending = orch.pending_requests();
        assert_eq!(pending.len(), 1); // Only p2 is pending; p1 auto-executed
    }
}
