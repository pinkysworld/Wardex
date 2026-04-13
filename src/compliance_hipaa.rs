// ── HIPAA Compliance Module ───────────────────────────────────────────────────
//
// Implements HIPAA Security Rule technical safeguards for Protected Health
// Information (PHI) in healthcare IoT/OT environments.
//
// Covers:
//   - §164.312(a)(1) Access Control
//   - §164.312(b)    Audit Controls
//   - §164.312(c)(1) Integrity Controls
//   - §164.312(d)    Authentication
//   - §164.312(e)(1) Transmission Security
//   - §164.308(a)(6) Security Incident Procedures
//   - §164.308(a)(7) Contingency Plan
//   - §164.314       Business Associate Requirements

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

// ── HIPAA Control Definitions ────────────────────────────────────────────────

/// HIPAA Security Rule control requirement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HipaaControl {
    pub id: String,
    pub title: String,
    pub section: String,
    pub category: HipaaCategory,
    pub requirement: String,
    pub implementation_spec: ImplementationSpec,
    pub status: ControlStatus,
    pub evidence: Vec<ControlEvidence>,
    pub last_assessed: Option<u64>,
}

/// HIPAA safeguard categories.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum HipaaCategory {
    Administrative,
    Physical,
    Technical,
    OrganizationalRequirements,
}

/// Whether the implementation spec is required or addressable.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ImplementationSpec {
    Required,
    Addressable,
}

/// Current compliance status of a control.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ControlStatus {
    Compliant,
    PartiallyCompliant,
    NonCompliant,
    NotAssessed,
    NotApplicable,
}

/// Evidence supporting a control's compliance status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlEvidence {
    pub evidence_type: String,
    pub description: String,
    pub collected_at: u64,
    pub source: String,
}

// ── HIPAA Compliance Manager ─────────────────────────────────────────────────

/// Manages HIPAA compliance assessment and monitoring.
#[derive(Debug)]
pub struct HipaaComplianceManager {
    controls: Vec<HipaaControl>,
    phi_data_flows: Vec<PhiDataFlow>,
    breach_log: Vec<BreachRecord>,
    audit_log: Vec<HipaaAuditEntry>,
}

/// Tracks PHI data flows through the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhiDataFlow {
    pub flow_id: String,
    pub source: String,
    pub destination: String,
    pub data_types: Vec<String>,
    pub encryption: EncryptionStatus,
    pub access_controls: Vec<String>,
    pub retention_days: u32,
    pub last_reviewed: u64,
}

/// Encryption status for a data flow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionStatus {
    EncryptedAtRest,
    EncryptedInTransit,
    EncryptedBoth,
    Unencrypted,
}

/// HIPAA breach record (§164.308(a)(6)).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreachRecord {
    pub id: String,
    pub detected_at: u64,
    pub reported_at: Option<u64>,
    pub description: String,
    pub affected_individuals: u32,
    pub phi_types: Vec<String>,
    pub root_cause: String,
    pub remediation: String,
    pub status: BreachStatus,
    pub notification_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum BreachStatus {
    Detected,
    Investigating,
    Contained,
    Remediated,
    Reported,
    Closed,
}

/// HIPAA-specific audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HipaaAuditEntry {
    pub timestamp: u64,
    pub user: String,
    pub action: String,
    pub resource: String,
    pub phi_accessed: bool,
    pub outcome: String,
    pub source_ip: Option<String>,
}

impl HipaaComplianceManager {
    /// Create a new manager with default HIPAA Security Rule controls.
    pub fn new() -> Self {
        let controls = Self::default_controls();
        Self {
            controls,
            phi_data_flows: Vec::new(),
            breach_log: Vec::new(),
            audit_log: Vec::new(),
        }
    }

    /// Run a compliance assessment against all controls.
    pub fn assess(&mut self) -> HipaaAssessmentReport {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut compliant = 0;
        let mut partial = 0;
        let mut non_compliant = 0;
        let mut not_assessed = 0;

        for control in &self.controls {
            match control.status {
                ControlStatus::Compliant => compliant += 1,
                ControlStatus::PartiallyCompliant => partial += 1,
                ControlStatus::NonCompliant => non_compliant += 1,
                ControlStatus::NotAssessed => not_assessed += 1,
                ControlStatus::NotApplicable => {}
            }
        }

        let total = self.controls.len();
        let score = if total > 0 {
            ((compliant as f32 + partial as f32 * 0.5) / total as f32 * 100.0) as u32
        } else {
            0
        };

        HipaaAssessmentReport {
            assessed_at: now,
            total_controls: total,
            compliant,
            partially_compliant: partial,
            non_compliant,
            not_assessed,
            compliance_score: score,
            phi_data_flows: self.phi_data_flows.len(),
            active_breaches: self
                .breach_log
                .iter()
                .filter(|b| b.status != BreachStatus::Closed)
                .count(),
            findings: self.generate_findings(),
        }
    }

    /// Record a PHI access audit entry.
    pub fn log_phi_access(
        &mut self,
        user: &str,
        action: &str,
        resource: &str,
        source_ip: Option<&str>,
        outcome: &str,
    ) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.audit_log.push(HipaaAuditEntry {
            timestamp: now,
            user: user.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            phi_accessed: true,
            outcome: outcome.to_string(),
            source_ip: source_ip.map(String::from),
        });
    }

    /// Record a breach incident.
    pub fn record_breach(&mut self, breach: BreachRecord) {
        self.breach_log.push(breach);
    }

    /// Register a PHI data flow.
    pub fn register_data_flow(&mut self, flow: PhiDataFlow) {
        self.phi_data_flows.push(flow);
    }

    /// Update a control's compliance status.
    pub fn update_control_status(
        &mut self,
        control_id: &str,
        status: ControlStatus,
        evidence: Option<ControlEvidence>,
    ) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if let Some(control) = self.controls.iter_mut().find(|c| c.id == control_id) {
            control.status = status;
            control.last_assessed = Some(now);
            if let Some(ev) = evidence {
                control.evidence.push(ev);
            }
            true
        } else {
            false
        }
    }

    /// Get all controls with a specific status.
    pub fn controls_by_status(&self, status: &ControlStatus) -> Vec<&HipaaControl> {
        self.controls.iter().filter(|c| &c.status == status).collect()
    }

    /// Get breach records.
    pub fn breaches(&self) -> &[BreachRecord] {
        &self.breach_log
    }

    /// Get audit log entries within a time range.
    pub fn audit_log_range(&self, from: u64, to: u64) -> Vec<&HipaaAuditEntry> {
        self.audit_log
            .iter()
            .filter(|e| e.timestamp >= from && e.timestamp <= to)
            .collect()
    }

    /// HIPAA status summary.
    pub fn status(&self) -> HipaaStatus {
        let report = self.controls.iter().fold(
            (0u32, 0u32, 0u32),
            |(comp, part, non), c| match c.status {
                ControlStatus::Compliant => (comp + 1, part, non),
                ControlStatus::PartiallyCompliant => (comp, part + 1, non),
                ControlStatus::NonCompliant => (comp, part, non + 1),
                _ => (comp, part, non),
            },
        );

        HipaaStatus {
            total_controls: self.controls.len(),
            compliant: report.0 as usize,
            partial: report.1 as usize,
            non_compliant: report.2 as usize,
            active_breaches: self
                .breach_log
                .iter()
                .filter(|b| b.status != BreachStatus::Closed)
                .count(),
            phi_data_flows: self.phi_data_flows.len(),
            audit_entries: self.audit_log.len(),
        }
    }

    fn generate_findings(&self) -> Vec<ComplianceFinding> {
        let mut findings = Vec::new();

        // Check for unencrypted PHI data flows
        for flow in &self.phi_data_flows {
            if flow.encryption == EncryptionStatus::Unencrypted {
                findings.push(ComplianceFinding {
                    severity: "high".into(),
                    control_id: "164.312(e)(1)".into(),
                    description: format!(
                        "Unencrypted PHI data flow from {} to {}",
                        flow.source, flow.destination
                    ),
                    recommendation: "Enable encryption for PHI data in transit and at rest".into(),
                });
            }
        }

        // Check for unreported breaches past 60-day window
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for breach in &self.breach_log {
            if breach.notification_required
                && breach.reported_at.is_none()
                && now - breach.detected_at > 60 * 86400
            {
                findings.push(ComplianceFinding {
                    severity: "critical".into(),
                    control_id: "164.308(a)(6)".into(),
                    description: format!(
                        "Breach {} detected >60 days ago but not yet reported",
                        breach.id
                    ),
                    recommendation: "Report breach to HHS within 60 days of discovery".into(),
                });
            }
        }

        // Check for non-compliant required controls
        for control in &self.controls {
            if control.implementation_spec == ImplementationSpec::Required
                && control.status == ControlStatus::NonCompliant
            {
                findings.push(ComplianceFinding {
                    severity: "high".into(),
                    control_id: control.id.clone(),
                    description: format!("Required control '{}' is non-compliant", control.title),
                    recommendation: format!("Implement {}: {}", control.section, control.requirement),
                });
            }
        }

        findings
    }

    fn default_controls() -> Vec<HipaaControl> {
        vec![
            HipaaControl {
                id: "164.312(a)(1)".into(),
                title: "Access Control".into(),
                section: "§164.312(a)(1)".into(),
                category: HipaaCategory::Technical,
                requirement: "Implement technical policies and procedures for electronic information systems that maintain ePHI to allow access only to authorized persons or software programs".into(),
                implementation_spec: ImplementationSpec::Required,
                status: ControlStatus::Compliant,
                evidence: vec![],
                last_assessed: None,
            },
            HipaaControl {
                id: "164.312(a)(2)(i)".into(),
                title: "Unique User Identification".into(),
                section: "§164.312(a)(2)(i)".into(),
                category: HipaaCategory::Technical,
                requirement: "Assign a unique name and/or number for identifying and tracking user identity".into(),
                implementation_spec: ImplementationSpec::Required,
                status: ControlStatus::Compliant,
                evidence: vec![],
                last_assessed: None,
            },
            HipaaControl {
                id: "164.312(a)(2)(ii)".into(),
                title: "Emergency Access Procedure".into(),
                section: "§164.312(a)(2)(ii)".into(),
                category: HipaaCategory::Technical,
                requirement: "Establish procedures for obtaining necessary ePHI during an emergency".into(),
                implementation_spec: ImplementationSpec::Required,
                status: ControlStatus::NotAssessed,
                evidence: vec![],
                last_assessed: None,
            },
            HipaaControl {
                id: "164.312(a)(2)(iii)".into(),
                title: "Automatic Logoff".into(),
                section: "§164.312(a)(2)(iii)".into(),
                category: HipaaCategory::Technical,
                requirement: "Implement electronic procedures to terminate session after inactivity".into(),
                implementation_spec: ImplementationSpec::Addressable,
                status: ControlStatus::Compliant,
                evidence: vec![],
                last_assessed: None,
            },
            HipaaControl {
                id: "164.312(a)(2)(iv)".into(),
                title: "Encryption and Decryption".into(),
                section: "§164.312(a)(2)(iv)".into(),
                category: HipaaCategory::Technical,
                requirement: "Implement a mechanism to encrypt and decrypt ePHI".into(),
                implementation_spec: ImplementationSpec::Addressable,
                status: ControlStatus::Compliant,
                evidence: vec![],
                last_assessed: None,
            },
            HipaaControl {
                id: "164.312(b)".into(),
                title: "Audit Controls".into(),
                section: "§164.312(b)".into(),
                category: HipaaCategory::Technical,
                requirement: "Implement hardware, software, and/or procedural mechanisms that record and examine activity in systems containing ePHI".into(),
                implementation_spec: ImplementationSpec::Required,
                status: ControlStatus::Compliant,
                evidence: vec![],
                last_assessed: None,
            },
            HipaaControl {
                id: "164.312(c)(1)".into(),
                title: "Integrity Controls".into(),
                section: "§164.312(c)(1)".into(),
                category: HipaaCategory::Technical,
                requirement: "Implement policies and procedures to protect ePHI from improper alteration or destruction".into(),
                implementation_spec: ImplementationSpec::Required,
                status: ControlStatus::Compliant,
                evidence: vec![],
                last_assessed: None,
            },
            HipaaControl {
                id: "164.312(d)".into(),
                title: "Person or Entity Authentication".into(),
                section: "§164.312(d)".into(),
                category: HipaaCategory::Technical,
                requirement: "Implement procedures to verify identity of persons seeking access to ePHI".into(),
                implementation_spec: ImplementationSpec::Required,
                status: ControlStatus::Compliant,
                evidence: vec![],
                last_assessed: None,
            },
            HipaaControl {
                id: "164.312(e)(1)".into(),
                title: "Transmission Security".into(),
                section: "§164.312(e)(1)".into(),
                category: HipaaCategory::Technical,
                requirement: "Implement technical security measures to guard against unauthorized access to ePHI transmitted over electronic communications network".into(),
                implementation_spec: ImplementationSpec::Required,
                status: ControlStatus::Compliant,
                evidence: vec![],
                last_assessed: None,
            },
            HipaaControl {
                id: "164.308(a)(1)".into(),
                title: "Security Management Process".into(),
                section: "§164.308(a)(1)".into(),
                category: HipaaCategory::Administrative,
                requirement: "Implement policies and procedures to prevent, detect, contain, and correct security violations".into(),
                implementation_spec: ImplementationSpec::Required,
                status: ControlStatus::PartiallyCompliant,
                evidence: vec![],
                last_assessed: None,
            },
            HipaaControl {
                id: "164.308(a)(5)".into(),
                title: "Security Awareness and Training".into(),
                section: "§164.308(a)(5)".into(),
                category: HipaaCategory::Administrative,
                requirement: "Implement a security awareness and training program for all workforce members".into(),
                implementation_spec: ImplementationSpec::Addressable,
                status: ControlStatus::NotAssessed,
                evidence: vec![],
                last_assessed: None,
            },
            HipaaControl {
                id: "164.308(a)(6)".into(),
                title: "Security Incident Procedures".into(),
                section: "§164.308(a)(6)".into(),
                category: HipaaCategory::Administrative,
                requirement: "Implement policies and procedures to address security incidents".into(),
                implementation_spec: ImplementationSpec::Required,
                status: ControlStatus::Compliant,
                evidence: vec![],
                last_assessed: None,
            },
            HipaaControl {
                id: "164.308(a)(7)".into(),
                title: "Contingency Plan".into(),
                section: "§164.308(a)(7)".into(),
                category: HipaaCategory::Administrative,
                requirement: "Establish policies for responding to an emergency that damages systems with ePHI".into(),
                implementation_spec: ImplementationSpec::Required,
                status: ControlStatus::NotAssessed,
                evidence: vec![],
                last_assessed: None,
            },
            HipaaControl {
                id: "164.314(a)(1)".into(),
                title: "Business Associate Contracts".into(),
                section: "§164.314(a)(1)".into(),
                category: HipaaCategory::OrganizationalRequirements,
                requirement: "Contracts between covered entity and business associates must meet requirements".into(),
                implementation_spec: ImplementationSpec::Required,
                status: ControlStatus::NotAssessed,
                evidence: vec![],
                last_assessed: None,
            },
        ]
    }
}

impl Default for HipaaComplianceManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── Assessment Report ────────────────────────────────────────────────────────

/// HIPAA compliance assessment report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HipaaAssessmentReport {
    pub assessed_at: u64,
    pub total_controls: usize,
    pub compliant: usize,
    pub partially_compliant: usize,
    pub non_compliant: usize,
    pub not_assessed: usize,
    pub compliance_score: u32,
    pub phi_data_flows: usize,
    pub active_breaches: usize,
    pub findings: Vec<ComplianceFinding>,
}

/// Individual compliance finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceFinding {
    pub severity: String,
    pub control_id: String,
    pub description: String,
    pub recommendation: String,
}

/// HIPAA system status summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HipaaStatus {
    pub total_controls: usize,
    pub compliant: usize,
    pub partial: usize,
    pub non_compliant: usize,
    pub active_breaches: usize,
    pub phi_data_flows: usize,
    pub audit_entries: usize,
}

// ── GDPR Enhancement ────────────────────────────────────────────────────────

/// GDPR Data Subject Access Request (DSAR) handler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSubjectRequest {
    pub id: String,
    pub request_type: DsarType,
    pub subject_id: String,
    pub subject_email: String,
    pub requested_at: u64,
    pub due_by: u64,
    pub status: DsarStatus,
    pub data_categories: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DsarType {
    Access,
    Rectification,
    Erasure,
    Portability,
    Restriction,
    Objection,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DsarStatus {
    Received,
    InProgress,
    Completed,
    Denied,
    Overdue,
}

/// Manages GDPR data subject requests.
#[derive(Debug, Default)]
pub struct GdprDsarManager {
    requests: Vec<DataSubjectRequest>,
    retention_policies: HashMap<String, RetentionPolicy>,
}

/// Data retention policy per category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub category: String,
    pub retention_days: u32,
    pub legal_basis: String,
    pub auto_delete: bool,
}

impl GdprDsarManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Submit a new DSAR.
    pub fn submit_request(&mut self, request: DataSubjectRequest) {
        self.requests.push(request);
    }

    /// Get pending requests.
    pub fn pending_requests(&self) -> Vec<&DataSubjectRequest> {
        self.requests
            .iter()
            .filter(|r| r.status == DsarStatus::Received || r.status == DsarStatus::InProgress)
            .collect()
    }

    /// Get overdue requests (past due_by timestamp).
    pub fn overdue_requests(&self) -> Vec<&DataSubjectRequest> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.requests
            .iter()
            .filter(|r| {
                r.due_by < now
                    && r.status != DsarStatus::Completed
                    && r.status != DsarStatus::Denied
            })
            .collect()
    }

    /// Register a data retention policy.
    pub fn set_retention_policy(&mut self, policy: RetentionPolicy) {
        self.retention_policies
            .insert(policy.category.clone(), policy);
    }

    /// Get all retention policies.
    pub fn retention_policies(&self) -> &HashMap<String, RetentionPolicy> {
        &self.retention_policies
    }

    /// Update a request status.
    pub fn update_status(&mut self, request_id: &str, status: DsarStatus) -> bool {
        if let Some(req) = self.requests.iter_mut().find(|r| r.id == request_id) {
            req.status = status;
            true
        } else {
            false
        }
    }

    /// GDPR DSAR summary.
    pub fn status(&self) -> GdprDsarStatus {
        GdprDsarStatus {
            total_requests: self.requests.len(),
            pending: self.pending_requests().len(),
            overdue: self.overdue_requests().len(),
            retention_policies: self.retention_policies.len(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GdprDsarStatus {
    pub total_requests: usize,
    pub pending: usize,
    pub overdue: usize,
    pub retention_policies: usize,
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hipaa_default_controls() {
        let mgr = HipaaComplianceManager::new();
        assert!(mgr.controls.len() >= 14);
        let status = mgr.status();
        assert!(status.total_controls >= 14);
    }

    #[test]
    fn hipaa_assessment() {
        let mut mgr = HipaaComplianceManager::new();
        let report = mgr.assess();
        assert!(report.total_controls > 0);
        assert!(report.compliance_score > 0);
    }

    #[test]
    fn hipaa_control_update() {
        let mut mgr = HipaaComplianceManager::new();
        assert!(mgr.update_control_status(
            "164.312(a)(1)",
            ControlStatus::Compliant,
            Some(ControlEvidence {
                evidence_type: "automated_test".into(),
                description: "RBAC enforcement verified".into(),
                collected_at: 1700000000,
                source: "wardex-ci".into(),
            }),
        ));
        assert!(!mgr.update_control_status("nonexistent", ControlStatus::Compliant, None));
    }

    #[test]
    fn phi_access_logging() {
        let mut mgr = HipaaComplianceManager::new();
        mgr.log_phi_access("analyst-1", "view", "/patient/123", Some("10.0.0.5"), "success");
        mgr.log_phi_access("analyst-2", "export", "/patient/456", None, "denied");
        assert_eq!(mgr.audit_log.len(), 2);
        assert!(mgr.audit_log[0].phi_accessed);
    }

    #[test]
    fn breach_recording() {
        let mut mgr = HipaaComplianceManager::new();
        mgr.record_breach(BreachRecord {
            id: "BR-001".into(),
            detected_at: 1700000000,
            reported_at: None,
            description: "Unauthorized access to patient records".into(),
            affected_individuals: 150,
            phi_types: vec!["name".into(), "ssn".into(), "diagnosis".into()],
            root_cause: "Misconfigured access controls".into(),
            remediation: "Restrict access, rotate credentials".into(),
            status: BreachStatus::Investigating,
            notification_required: true,
        });
        assert_eq!(mgr.breaches().len(), 1);
        assert_eq!(mgr.status().active_breaches, 1);
    }

    #[test]
    fn phi_data_flow_registration() {
        let mut mgr = HipaaComplianceManager::new();
        mgr.register_data_flow(PhiDataFlow {
            flow_id: "DF-001".into(),
            source: "ehr-system".into(),
            destination: "analytics-db".into(),
            data_types: vec!["diagnosis".into(), "lab_results".into()],
            encryption: EncryptionStatus::EncryptedBoth,
            access_controls: vec!["rbac".into(), "mfa".into()],
            retention_days: 365,
            last_reviewed: 1700000000,
        });
        assert_eq!(mgr.phi_data_flows.len(), 1);
    }

    #[test]
    fn unencrypted_flow_finding() {
        let mut mgr = HipaaComplianceManager::new();
        mgr.register_data_flow(PhiDataFlow {
            flow_id: "DF-BAD".into(),
            source: "device".into(),
            destination: "cloud".into(),
            data_types: vec!["vitals".into()],
            encryption: EncryptionStatus::Unencrypted,
            access_controls: vec![],
            retention_days: 30,
            last_reviewed: 0,
        });
        let report = mgr.assess();
        assert!(report.findings.iter().any(|f| f.severity == "high" && f.control_id == "164.312(e)(1)"));
    }

    #[test]
    fn controls_by_status_filter() {
        let mgr = HipaaComplianceManager::new();
        let compliant = mgr.controls_by_status(&ControlStatus::Compliant);
        assert!(!compliant.is_empty());
        let not_assessed = mgr.controls_by_status(&ControlStatus::NotAssessed);
        assert!(!not_assessed.is_empty());
    }

    // ── GDPR DSAR Tests ──────────────────────────────────────────────────────

    #[test]
    fn gdpr_dsar_submit() {
        let mut mgr = GdprDsarManager::new();
        mgr.submit_request(DataSubjectRequest {
            id: "DSAR-001".into(),
            request_type: DsarType::Access,
            subject_id: "user-42".into(),
            subject_email: "user@example.com".into(),
            requested_at: 1700000000,
            due_by: 1702592000,
            status: DsarStatus::Received,
            data_categories: vec!["personal".into(), "usage".into()],
            notes: vec![],
        });
        assert_eq!(mgr.pending_requests().len(), 1);
        assert_eq!(mgr.status().total_requests, 1);
    }

    #[test]
    fn gdpr_retention_policy() {
        let mut mgr = GdprDsarManager::new();
        mgr.set_retention_policy(RetentionPolicy {
            category: "security_logs".into(),
            retention_days: 90,
            legal_basis: "Legitimate interest".into(),
            auto_delete: true,
        });
        assert_eq!(mgr.retention_policies().len(), 1);
    }

    #[test]
    fn gdpr_status_update() {
        let mut mgr = GdprDsarManager::new();
        mgr.submit_request(DataSubjectRequest {
            id: "DSAR-002".into(),
            request_type: DsarType::Erasure,
            subject_id: "user-99".into(),
            subject_email: "del@example.com".into(),
            requested_at: 1700000000,
            due_by: 1702592000,
            status: DsarStatus::Received,
            data_categories: vec!["all".into()],
            notes: vec![],
        });
        assert!(mgr.update_status("DSAR-002", DsarStatus::Completed));
        assert!(!mgr.update_status("DSAR-NONE", DsarStatus::Completed));
        assert_eq!(mgr.pending_requests().len(), 0);
    }
}
