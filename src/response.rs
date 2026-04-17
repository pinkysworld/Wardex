// Response orchestration with approval workflows, protected assets, blast-radius checks.
// ADR-0008: Response guardrails.

use serde::{Deserialize, Serialize};
use std::sync::Mutex;

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
}

impl ResponseOrchestrator {
    pub fn new() -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
            protected_assets: Vec::new(),
            audit_ledger: Mutex::new(Vec::new()),
            approval_sla_secs: 300,
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

        // Auto-tier actions execute immediately (or simulate in dry-run)
        if tier == ActionTier::Auto {
            request.status = if request.dry_run {
                ApprovalStatus::DryRunCompleted
            } else {
                ApprovalStatus::Executed
            };
        } else {
            request.status = ApprovalStatus::Pending;
        }

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

    fn record_audit(&self, req: &ResponseRequest) {
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
            });
    }

    /// Execute all approved (non-dry-run) requests. Returns a summary of
    /// executed actions.  In production this would call out to enforcement
    /// agents; here we record the execution transition and produce a
    /// human-readable log line for each action.
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
            let description = match &req.action {
                ResponseAction::KillProcess { pid, process_name } => format!(
                    "Killed process {} (PID {}) on {}",
                    process_name, pid, req.target.hostname
                ),
                ResponseAction::Isolate => format!("Isolated host {}", req.target.hostname),
                ResponseAction::BlockIp { ip } => {
                    format!("Blocked IP {} via {}", ip, req.target.hostname)
                }
                ResponseAction::QuarantineFile { path } => {
                    format!("Quarantined file {} on {}", path, req.target.hostname)
                }
                ResponseAction::DisableAccount { username } => {
                    format!("Disabled account {} on {}", username, req.target.hostname)
                }
                ResponseAction::Throttle { rate_limit_kbps } => format!(
                    "Throttled {} to {} kbps",
                    req.target.hostname, rate_limit_kbps
                ),
                ResponseAction::RollbackConfig { config_name } => format!(
                    "Rolled back config {} on {}",
                    config_name, req.target.hostname
                ),
                ResponseAction::Alert => {
                    format!("Alert notification sent for {}", req.target.hostname)
                }
                ResponseAction::Custom { name, .. } => format!(
                    "Custom action '{}' executed on {}",
                    name, req.target.hostname
                ),
            };
            req.status = ApprovalStatus::Executed;
            executed.push(description);
            executed_reqs.push(req.clone());
        }
        drop(requests);
        for req in &executed_reqs {
            self.record_audit(req);
        }
        executed
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

    let mut effects = Vec::new();
    match action {
        ResponseAction::KillProcess { pid, process_name } => {
            effects.push(format!("Would kill process {} (PID {})", process_name, pid))
        }
        ResponseAction::Isolate => effects.push(format!("Would isolate host {}", target.hostname)),
        ResponseAction::BlockIp { ip } => effects.push(format!("Would block IP {}", ip)),
        ResponseAction::QuarantineFile { path } => {
            effects.push(format!("Would quarantine file {}", path))
        }
        ResponseAction::DisableAccount { username } => {
            effects.push(format!("Would disable account {}", username))
        }
        ResponseAction::Throttle { rate_limit_kbps } => {
            effects.push(format!("Would throttle to {} kbps", rate_limit_kbps))
        }
        ResponseAction::RollbackConfig { config_name } => {
            effects.push(format!("Would rollback config {}", config_name))
        }
        ResponseAction::Alert => effects.push("Would generate alert notification".into()),
        ResponseAction::Custom { name, .. } => {
            effects.push(format!("Would execute custom action: {}", name))
        }
    }

    DryRunResult {
        request_id: "dry-run".into(),
        would_execute: tier != ActionTier::BreakGlass,
        tier,
        blast_radius: blast,
        is_protected,
        approvals_required,
        simulated_effects: effects,
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
