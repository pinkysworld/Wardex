// ── Compliance Report Templates ───────────────────────────────────────────────
//
// Pre-built compliance mappings for CIS Controls v8, PCI-DSS v4.0, SOC 2
// Type II, and NIST CSF 2.0.  Each template maps Wardex capabilities to
// specific controls and can auto-evaluate pass/fail status.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceFramework {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub controls: Vec<ComplianceControl>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceControl {
    pub control_id: String,
    pub title: String,
    pub description: String,
    pub wardex_mapping: Vec<String>,
    pub evidence_sources: Vec<String>,
    pub auto_check: Option<AutoCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoCheck {
    pub check_type: CheckType,
    pub parameter: String,
    pub expected: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckType {
    ConfigEnabled,
    PolicyExists,
    AgentCoverage,
    RetentionDays,
    DetectionEnabled,
    MfaEnforced,
    EncryptionEnabled,
    AuditLogging,
    IncidentProcess,
    BackupExists,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub framework_id: String,
    pub framework_name: String,
    pub generated_at: String,
    pub total_controls: usize,
    pub passed: usize,
    pub failed: usize,
    pub not_applicable: usize,
    pub manual_review: usize,
    pub score_percent: f64,
    pub findings: Vec<ControlFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFinding {
    pub control_id: String,
    pub title: String,
    pub status: FindingStatus,
    pub evidence: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Pass,
    Fail,
    NotApplicable,
    ManualReview,
}

// ── System State (for auto-evaluation) ───────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct SystemState {
    pub detection_enabled: bool,
    pub audit_logging: bool,
    pub encryption_at_rest: bool,
    pub encryption_in_transit: bool,
    pub mfa_enforced: bool,
    pub backup_configured: bool,
    pub retention_days: u32,
    pub agent_coverage_percent: f64,
    pub incident_process: bool,
    pub rbac_enabled: bool,
    pub rate_limiting: bool,
    pub sigma_rules_loaded: usize,
    pub baseline_active: bool,
    pub sbom_available: bool,
}

// ── Framework Templates ──────────────────────────────────────────────────────

pub fn cis_controls_v8() -> ComplianceFramework {
    ComplianceFramework {
        id: "cis-v8".into(),
        name: "CIS Controls".into(),
        version: "8.0".into(),
        description: "Center for Internet Security Controls Version 8".into(),
        controls: vec![
            ctrl("CIS-1.1", "Enterprise Asset Inventory",
                "Establish and maintain an accurate, detailed, and up-to-date inventory of all enterprise assets.",
                &["fleet.agents", "fleet.discovery"], &["GET /api/fleet/agents"],
                Some(AutoCheck { check_type: CheckType::AgentCoverage, parameter: "coverage".into(), expected: ">=80".into() })),
            ctrl("CIS-2.1", "Software Inventory",
                "Establish and maintain a detailed inventory of all licensed software.",
                &["sbom.generate", "sbom.verify"], &["GET /api/sbom"],
                Some(AutoCheck { check_type: CheckType::ConfigEnabled, parameter: "sbom".into(), expected: "true".into() })),
            ctrl("CIS-3.1", "Data Protection",
                "Establish and maintain a data management process.",
                &["storage.encryption", "archival"], &["GET /api/config"],
                Some(AutoCheck { check_type: CheckType::EncryptionEnabled, parameter: "at_rest".into(), expected: "true".into() })),
            ctrl("CIS-4.1", "Secure Configuration",
                "Establish and maintain a secure configuration process for enterprise assets.",
                &["policy.engine", "config.audit"], &["GET /api/policies"],
                Some(AutoCheck { check_type: CheckType::PolicyExists, parameter: "hardening".into(), expected: "true".into() })),
            ctrl("CIS-5.1", "Account Management",
                "Establish and maintain an inventory of all accounts.",
                &["auth.rbac", "auth.audit"], &["GET /api/auth/users"],
                Some(AutoCheck { check_type: CheckType::MfaEnforced, parameter: "mfa".into(), expected: "true".into() })),
            ctrl("CIS-6.1", "Access Control Management",
                "Establish and maintain an access control process.",
                &["auth.rbac", "auth.tokens"], &["GET /api/auth/roles"],
                None),
            ctrl("CIS-8.1", "Audit Log Management",
                "Establish and maintain an audit log management process.",
                &["audit.log", "structured_log"], &["GET /api/audit/logs"],
                Some(AutoCheck { check_type: CheckType::AuditLogging, parameter: "enabled".into(), expected: "true".into() })),
            ctrl("CIS-8.9", "Log Retention",
                "Centralize, retain audit logs for at least 90 days.",
                &["archival", "storage.retention"], &["GET /api/config"],
                Some(AutoCheck { check_type: CheckType::RetentionDays, parameter: "retention".into(), expected: ">=90".into() })),
            ctrl("CIS-10.1", "Malware Defenses",
                "Deploy and maintain anti-malware software.",
                &["detection.engine", "yara_engine", "sigma_library"], &["GET /api/detection/status"],
                Some(AutoCheck { check_type: CheckType::DetectionEnabled, parameter: "detection".into(), expected: "true".into() })),
            ctrl("CIS-13.1", "Network Monitoring",
                "Centralize security event alerting.",
                &["correlation.engine", "alerts", "incidents"], &["GET /api/alerts"],
                Some(AutoCheck { check_type: CheckType::DetectionEnabled, parameter: "correlation".into(), expected: "true".into() })),
            ctrl("CIS-17.1", "Incident Response",
                "Designate personnel to manage incident handling.",
                &["incidents", "response.playbooks"], &["GET /api/incidents"],
                Some(AutoCheck { check_type: CheckType::IncidentProcess, parameter: "incident_process".into(), expected: "true".into() })),
        ],
    }
}

pub fn pci_dss_v4() -> ComplianceFramework {
    ComplianceFramework {
        id: "pci-dss-v4".into(),
        name: "PCI-DSS".into(),
        version: "4.0".into(),
        description: "Payment Card Industry Data Security Standard Version 4.0".into(),
        controls: vec![
            ctrl("PCI-1.1", "Network Security Controls",
                "Install and maintain network security controls.",
                &["policy.firewall", "network.segmentation"], &["GET /api/policies"],
                None),
            ctrl("PCI-2.1", "Secure Configurations",
                "Apply secure configurations to all system components.",
                &["policy.hardening", "config.audit"], &["GET /api/config"],
                None),
            ctrl("PCI-3.1", "Protect Stored Account Data",
                "Protect stored account data with strong cryptography.",
                &["storage.encryption"], &["GET /api/config"],
                Some(AutoCheck { check_type: CheckType::EncryptionEnabled, parameter: "at_rest".into(), expected: "true".into() })),
            ctrl("PCI-5.1", "Anti-Malware",
                "Protect systems against malware with anti-malware solutions.",
                &["detection.engine", "yara_engine"], &["GET /api/detection/status"],
                Some(AutoCheck { check_type: CheckType::DetectionEnabled, parameter: "detection".into(), expected: "true".into() })),
            ctrl("PCI-6.1", "Secure Development",
                "Develop and maintain secure systems and software.",
                &["sbom", "supply_chain"], &["GET /api/sbom"],
                None),
            ctrl("PCI-7.1", "Access Restriction",
                "Restrict access to system components by business need to know.",
                &["auth.rbac"], &["GET /api/auth/roles"],
                None),
            ctrl("PCI-8.1", "User Identification",
                "Identify users and authenticate access.",
                &["auth.tokens", "auth.mfa"], &["GET /api/auth/users"],
                Some(AutoCheck { check_type: CheckType::MfaEnforced, parameter: "mfa".into(), expected: "true".into() })),
            ctrl("PCI-10.1", "Log and Monitor",
                "Log and monitor all access to system components and cardholder data.",
                &["audit.log", "structured_log", "metrics"], &["GET /api/audit/logs"],
                Some(AutoCheck { check_type: CheckType::AuditLogging, parameter: "enabled".into(), expected: "true".into() })),
            ctrl("PCI-10.7", "Log Retention",
                "Retain audit trail history for at least 12 months.",
                &["archival", "storage.retention"], &["GET /api/config"],
                Some(AutoCheck { check_type: CheckType::RetentionDays, parameter: "retention".into(), expected: ">=365".into() })),
            ctrl("PCI-11.1", "Security Testing",
                "Regularly test security of systems and networks.",
                &["harness", "detection.test"], &["GET /api/harness/results"],
                None),
            ctrl("PCI-12.10", "Incident Response",
                "Implement an incident response plan.",
                &["incidents", "response.playbooks"], &["GET /api/incidents"],
                Some(AutoCheck { check_type: CheckType::IncidentProcess, parameter: "incident_process".into(), expected: "true".into() })),
        ],
    }
}

pub fn soc2_type2() -> ComplianceFramework {
    ComplianceFramework {
        id: "soc2-type2".into(),
        name: "SOC 2 Type II".into(),
        version: "2024".into(),
        description: "AICPA SOC 2 Type II Trust Services Criteria".into(),
        controls: vec![
            ctrl("CC6.1", "Logical Access Security",
                "Logical access security software, infrastructure, and architectures.",
                &["auth.rbac", "auth.tokens", "rate_limiting"], &["GET /api/auth/roles"],
                None),
            ctrl("CC6.2", "User Authentication",
                "User credentials and identity management.",
                &["auth.mfa", "auth.tokens"], &["GET /api/auth/users"],
                Some(AutoCheck { check_type: CheckType::MfaEnforced, parameter: "mfa".into(), expected: "true".into() })),
            ctrl("CC6.3", "Authorized Access",
                "Only authorized persons access facilities and information.",
                &["auth.rbac", "policy.engine"], &["GET /api/auth/roles"],
                None),
            ctrl("CC6.6", "External Threats",
                "Security measures against threats from outside system boundaries.",
                &["detection.engine", "correlation.engine", "sigma_library"], &["GET /api/detection/status"],
                Some(AutoCheck { check_type: CheckType::DetectionEnabled, parameter: "detection".into(), expected: "true".into() })),
            ctrl("CC7.1", "Monitoring",
                "Detection and monitoring procedures.",
                &["monitor", "alerts", "metrics"], &["GET /api/alerts"],
                Some(AutoCheck { check_type: CheckType::DetectionEnabled, parameter: "monitoring".into(), expected: "true".into() })),
            ctrl("CC7.2", "Anomaly Detection",
                "Anomalies identified and evaluated.",
                &["baseline", "correlation.engine", "detector"], &["GET /api/detection/baseline"],
                Some(AutoCheck { check_type: CheckType::DetectionEnabled, parameter: "baseline".into(), expected: "true".into() })),
            ctrl("CC7.3", "Incident Response",
                "Procedures for security incidents exist and are evaluated.",
                &["incidents", "response.actions"], &["GET /api/incidents"],
                Some(AutoCheck { check_type: CheckType::IncidentProcess, parameter: "incident_process".into(), expected: "true".into() })),
            ctrl("CC8.1", "Change Management",
                "Changes to infrastructure and software are controlled.",
                &["auto_update", "sbom", "audit.log"], &["GET /api/updates"],
                None),
            ctrl("A1.2", "Data Backup",
                "Recovery infrastructure and data backed up.",
                &["checkpoint", "archival"], &["GET /api/checkpoints"],
                Some(AutoCheck { check_type: CheckType::BackupExists, parameter: "backup".into(), expected: "true".into() })),
        ],
    }
}

pub fn nist_csf_v2() -> ComplianceFramework {
    ComplianceFramework {
        id: "nist-csf-v2".into(),
        name: "NIST CSF".into(),
        version: "2.0".into(),
        description: "NIST Cybersecurity Framework Version 2.0".into(),
        controls: vec![
            ctrl("ID.AM-1", "Asset Inventory",
                "Physical devices and systems are inventoried.",
                &["fleet.agents", "fleet.discovery"], &["GET /api/fleet/agents"],
                Some(AutoCheck { check_type: CheckType::AgentCoverage, parameter: "coverage".into(), expected: ">=80".into() })),
            ctrl("ID.AM-2", "Software Inventory",
                "Software platforms and applications are inventoried.",
                &["sbom.generate"], &["GET /api/sbom"],
                None),
            ctrl("PR.AC-1", "Identity Management",
                "Identities, credentials, and access are managed.",
                &["auth.rbac", "auth.tokens", "auth.mfa"], &["GET /api/auth/users"],
                Some(AutoCheck { check_type: CheckType::MfaEnforced, parameter: "mfa".into(), expected: "true".into() })),
            ctrl("PR.DS-1", "Data-at-Rest Protection",
                "Data-at-rest is protected.",
                &["storage.encryption"], &["GET /api/config"],
                Some(AutoCheck { check_type: CheckType::EncryptionEnabled, parameter: "at_rest".into(), expected: "true".into() })),
            ctrl("PR.DS-2", "Data-in-Transit Protection",
                "Data-in-transit is protected.",
                &["tls", "encryption"], &["GET /api/config"],
                Some(AutoCheck { check_type: CheckType::EncryptionEnabled, parameter: "in_transit".into(), expected: "true".into() })),
            ctrl("PR.PT-1", "Audit Logging",
                "Audit/log records are determined, documented, and reviewed.",
                &["audit.log", "structured_log"], &["GET /api/audit/logs"],
                Some(AutoCheck { check_type: CheckType::AuditLogging, parameter: "enabled".into(), expected: "true".into() })),
            ctrl("DE.CM-1", "Network Monitoring",
                "The network is monitored to detect potential cybersecurity events.",
                &["monitor", "correlation.engine"], &["GET /api/alerts"],
                Some(AutoCheck { check_type: CheckType::DetectionEnabled, parameter: "correlation".into(), expected: "true".into() })),
            ctrl("DE.AE-1", "Baseline of Operations",
                "A baseline of network operations is established and managed.",
                &["baseline", "detector"], &["GET /api/detection/baseline"],
                Some(AutoCheck { check_type: CheckType::DetectionEnabled, parameter: "baseline".into(), expected: "true".into() })),
            ctrl("RS.RP-1", "Response Plan",
                "Response plan is executed during or after an incident.",
                &["incidents", "response.playbooks", "response.actions"], &["GET /api/incidents"],
                Some(AutoCheck { check_type: CheckType::IncidentProcess, parameter: "incident_process".into(), expected: "true".into() })),
            ctrl("RC.RP-1", "Recovery Plan",
                "Recovery plan is executed during or after a cybersecurity incident.",
                &["checkpoint", "archival"], &["GET /api/checkpoints"],
                Some(AutoCheck { check_type: CheckType::BackupExists, parameter: "backup".into(), expected: "true".into() })),
        ],
    }
}

fn ctrl(
    id: &str, title: &str, desc: &str,
    mappings: &[&str], evidence: &[&str],
    check: Option<AutoCheck>,
) -> ComplianceControl {
    ComplianceControl {
        control_id: id.into(),
        title: title.into(),
        description: desc.into(),
        wardex_mapping: mappings.iter().map(|s| s.to_string()).collect(),
        evidence_sources: evidence.iter().map(|s| s.to_string()).collect(),
        auto_check: check,
    }
}

// ── Evaluation Engine ────────────────────────────────────────────────────────

pub fn evaluate_framework(framework: &ComplianceFramework, state: &SystemState) -> ComplianceReport {
    let mut findings = Vec::new();
    let mut passed = 0;
    let mut failed = 0;
    let mut na = 0;
    let mut manual = 0;

    for control in &framework.controls {
        let (status, evidence, remediation) = match &control.auto_check {
            Some(check) => evaluate_check(check, state),
            None => (FindingStatus::ManualReview, "Manual verification required".into(), String::new()),
        };

        match status {
            FindingStatus::Pass => passed += 1,
            FindingStatus::Fail => failed += 1,
            FindingStatus::NotApplicable => na += 1,
            FindingStatus::ManualReview => manual += 1,
        }

        findings.push(ControlFinding {
            control_id: control.control_id.clone(),
            title: control.title.clone(),
            status,
            evidence,
            remediation,
        });
    }

    let total = framework.controls.len();
    let evaluable = total - na;
    let score = if evaluable > 0 {
        (passed as f64 / evaluable as f64) * 100.0
    } else {
        100.0
    };

    ComplianceReport {
        framework_id: framework.id.clone(),
        framework_name: framework.name.clone(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        total_controls: total,
        passed,
        failed,
        not_applicable: na,
        manual_review: manual,
        score_percent: (score * 10.0).round() / 10.0,
        findings,
    }
}

fn evaluate_check(check: &AutoCheck, state: &SystemState) -> (FindingStatus, String, String) {
    match check.check_type {
        CheckType::DetectionEnabled => {
            if state.detection_enabled {
                (FindingStatus::Pass, "Detection engine is active".into(), String::new())
            } else {
                (FindingStatus::Fail, "Detection engine is not active".into(),
                 "Enable detection engine in configuration".into())
            }
        }
        CheckType::AuditLogging => {
            if state.audit_logging {
                (FindingStatus::Pass, "Audit logging is enabled".into(), String::new())
            } else {
                (FindingStatus::Fail, "Audit logging is disabled".into(),
                 "Enable audit logging in wardex.toml".into())
            }
        }
        CheckType::EncryptionEnabled => {
            let ok = match check.parameter.as_str() {
                "at_rest" => state.encryption_at_rest,
                "in_transit" => state.encryption_in_transit,
                _ => state.encryption_at_rest && state.encryption_in_transit,
            };
            if ok {
                (FindingStatus::Pass, format!("Encryption ({}) is enabled", check.parameter), String::new())
            } else {
                (FindingStatus::Fail, format!("Encryption ({}) is not enabled", check.parameter),
                 "Enable encryption in configuration".into())
            }
        }
        CheckType::MfaEnforced => {
            if state.mfa_enforced {
                (FindingStatus::Pass, "MFA is enforced".into(), String::new())
            } else {
                (FindingStatus::Fail, "MFA is not enforced".into(),
                 "Enable MFA enforcement for all users".into())
            }
        }
        CheckType::RetentionDays => {
            let required: u32 = check.expected.trim_start_matches(">=").parse().unwrap_or(90);
            if state.retention_days >= required {
                (FindingStatus::Pass,
                 format!("Retention: {} days (>= {} required)", state.retention_days, required),
                 String::new())
            } else {
                (FindingStatus::Fail,
                 format!("Retention: {} days (< {} required)", state.retention_days, required),
                 format!("Increase retention to at least {} days", required))
            }
        }
        CheckType::AgentCoverage => {
            if state.agent_coverage_percent >= 80.0 {
                (FindingStatus::Pass,
                 format!("Agent coverage: {:.0}%", state.agent_coverage_percent),
                 String::new())
            } else {
                (FindingStatus::Fail,
                 format!("Agent coverage: {:.0}% (< 80% required)", state.agent_coverage_percent),
                 "Deploy agents to remaining assets".into())
            }
        }
        CheckType::IncidentProcess => {
            if state.incident_process {
                (FindingStatus::Pass, "Incident response process is active".into(), String::new())
            } else {
                (FindingStatus::Fail, "No incident response process configured".into(),
                 "Configure incident response playbooks".into())
            }
        }
        CheckType::BackupExists => {
            if state.backup_configured {
                (FindingStatus::Pass, "Backups are configured".into(), String::new())
            } else {
                (FindingStatus::Fail, "No backup configuration found".into(),
                 "Configure checkpoint/backup strategy".into())
            }
        }
        CheckType::ConfigEnabled | CheckType::PolicyExists => {
            // Generic — pass if detection + baseline are active
            if state.detection_enabled && state.baseline_active {
                (FindingStatus::Pass, "Configuration verified".into(), String::new())
            } else {
                (FindingStatus::Fail, "Configuration incomplete".into(),
                 "Review and complete security configuration".into())
            }
        }
    }
}

// ── All frameworks ───────────────────────────────────────────────────────────

pub fn all_frameworks() -> Vec<ComplianceFramework> {
    vec![cis_controls_v8(), pci_dss_v4(), soc2_type2(), nist_csf_v2()]
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn full_state() -> SystemState {
        SystemState {
            detection_enabled: true,
            audit_logging: true,
            encryption_at_rest: true,
            encryption_in_transit: true,
            mfa_enforced: true,
            backup_configured: true,
            retention_days: 365,
            agent_coverage_percent: 95.0,
            incident_process: true,
            rbac_enabled: true,
            rate_limiting: true,
            sigma_rules_loaded: 50,
            baseline_active: true,
            sbom_available: true,
        }
    }

    #[test]
    fn cis_framework_has_controls() {
        let f = cis_controls_v8();
        assert_eq!(f.id, "cis-v8");
        assert!(!f.controls.is_empty());
    }

    #[test]
    fn pci_framework_has_controls() {
        let f = pci_dss_v4();
        assert_eq!(f.id, "pci-dss-v4");
        assert!(!f.controls.is_empty());
    }

    #[test]
    fn soc2_framework_has_controls() {
        let f = soc2_type2();
        assert_eq!(f.id, "soc2-type2");
        assert!(!f.controls.is_empty());
    }

    #[test]
    fn nist_framework_has_controls() {
        let f = nist_csf_v2();
        assert_eq!(f.id, "nist-csf-v2");
        assert!(!f.controls.is_empty());
    }

    #[test]
    fn all_frameworks_returns_four() {
        assert_eq!(all_frameworks().len(), 4);
    }

    #[test]
    fn full_compliance_all_pass() {
        let state = full_state();
        for fw in all_frameworks() {
            let report = evaluate_framework(&fw, &state);
            assert!(report.score_percent > 0.0,
                "{} score should be > 0, got {}", fw.id, report.score_percent);
            assert_eq!(report.failed, 0,
                "{} should have 0 failures, got {}", fw.id, report.failed);
        }
    }

    #[test]
    fn failing_state_reports_failures() {
        let state = SystemState::default(); // everything false/zero
        let report = evaluate_framework(&cis_controls_v8(), &state);
        assert!(report.failed > 0);
        assert!(report.score_percent < 100.0);
    }

    #[test]
    fn report_json_serializable() {
        let state = full_state();
        let report = evaluate_framework(&cis_controls_v8(), &state);
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("cis-v8"));
        assert!(json.contains("score_percent"));
    }

    #[test]
    fn retention_check_boundary() {
        let mut state = full_state();
        state.retention_days = 89;
        let report = evaluate_framework(&cis_controls_v8(), &state);
        let retention_finding = report.findings.iter()
            .find(|f| f.control_id == "CIS-8.9").unwrap();
        assert_eq!(retention_finding.status, FindingStatus::Fail);

        state.retention_days = 90;
        let report = evaluate_framework(&cis_controls_v8(), &state);
        let retention_finding = report.findings.iter()
            .find(|f| f.control_id == "CIS-8.9").unwrap();
        assert_eq!(retention_finding.status, FindingStatus::Pass);
    }

    #[test]
    fn agent_coverage_threshold() {
        let mut state = full_state();
        state.agent_coverage_percent = 50.0;
        let report = evaluate_framework(&nist_csf_v2(), &state);
        let coverage = report.findings.iter()
            .find(|f| f.control_id == "ID.AM-1").unwrap();
        assert_eq!(coverage.status, FindingStatus::Fail);
    }

    #[test]
    fn controls_have_mappings() {
        for fw in all_frameworks() {
            for ctrl in &fw.controls {
                assert!(!ctrl.wardex_mapping.is_empty(),
                    "{}:{} has no wardex_mapping", fw.id, ctrl.control_id);
            }
        }
    }
}
