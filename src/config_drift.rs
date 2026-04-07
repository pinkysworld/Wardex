//! Configuration drift detection.
//!
//! Compares current system configuration against a golden baseline
//! to detect unauthorised changes to critical settings (sshd, firewall,
//! kernel parameters, etc.).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Configuration baseline ──────────────────────────────────────

/// A golden baseline for a configuration file or setting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigBaseline {
    pub path: String,
    pub category: ConfigCategory,
    pub expected_hash: String,
    pub expected_values: HashMap<String, String>,
    pub host_class: String,
    pub created_at: String,
}

/// Categories of monitored configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ConfigCategory {
    SshServer,
    Firewall,
    KernelParams,
    AuthConfig,
    NetworkConfig,
    DockerDaemon,
    KubeConfig,
    NtpConfig,
    AuditRules,
    Custom(String),
}

/// A detected configuration change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigChange {
    pub path: String,
    pub category: ConfigCategory,
    pub key: String,
    pub expected: String,
    pub actual: String,
    pub severity: DriftSeverity,
    pub host_id: String,
    pub detected_at: String,
    pub mitre_techniques: Vec<String>,
}

/// Severity of configuration drift.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DriftSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Configuration drift report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftReport {
    pub host_id: String,
    pub scan_timestamp: String,
    pub baselines_checked: usize,
    pub drifts_found: usize,
    pub critical_drifts: usize,
    pub high_drifts: usize,
    pub changes: Vec<ConfigChange>,
    pub compliant: bool,
}

// ── Drift detection engine ──────────────────────────────────────

/// Configuration drift detection engine.
pub struct ConfigDriftDetector {
    baselines: Vec<ConfigBaseline>,
    reports: Vec<DriftReport>,
}

impl Default for ConfigDriftDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigDriftDetector {
    pub fn new() -> Self {
        Self {
            baselines: builtin_baselines(),
            reports: Vec::new(),
        }
    }

    /// Add a custom baseline.
    pub fn add_baseline(&mut self, baseline: ConfigBaseline) {
        self.baselines.push(baseline);
    }

    /// Number of baselines tracked.
    pub fn baseline_count(&self) -> usize {
        self.baselines.len()
    }

    /// Check actual configuration against baselines.
    pub fn check(&mut self, host_id: &str, actual_configs: &HashMap<String, HashMap<String, String>>) -> DriftReport {
        let mut changes = Vec::new();
        let ts = chrono::Utc::now().to_rfc3339();

        for baseline in &self.baselines {
            if let Some(actual) = actual_configs.get(&baseline.path) {
                for (key, expected_value) in &baseline.expected_values {
                    if let Some(actual_value) = actual.get(key) {
                        if actual_value != expected_value {
                            let severity = classify_severity(&baseline.category, key);
                            let mitre = mitre_for_category(&baseline.category);
                            changes.push(ConfigChange {
                                path: baseline.path.clone(),
                                category: baseline.category.clone(),
                                key: key.clone(),
                                expected: expected_value.clone(),
                                actual: actual_value.clone(),
                                severity,
                                host_id: host_id.to_string(),
                                detected_at: ts.clone(),
                                mitre_techniques: mitre,
                            });
                        }
                    }
                    // Missing keys are drift too
                    else {
                        changes.push(ConfigChange {
                            path: baseline.path.clone(),
                            category: baseline.category.clone(),
                            key: key.clone(),
                            expected: expected_value.clone(),
                            actual: "(missing)".into(),
                            severity: DriftSeverity::Medium,
                            host_id: host_id.to_string(),
                            detected_at: ts.clone(),
                            mitre_techniques: vec![],
                        });
                    }
                }
            }
        }

        let critical_drifts = changes.iter().filter(|c| c.severity == DriftSeverity::Critical).count();
        let high_drifts = changes.iter().filter(|c| c.severity == DriftSeverity::High).count();

        let report = DriftReport {
            host_id: host_id.to_string(),
            scan_timestamp: ts,
            baselines_checked: self.baselines.len(),
            drifts_found: changes.len(),
            critical_drifts,
            high_drifts,
            changes,
            compliant: critical_drifts == 0 && high_drifts == 0,
        };

        self.reports.push(report.clone());
        report
    }

    /// Get all reports.
    pub fn reports(&self) -> &[DriftReport] {
        &self.reports
    }

    /// Fleet-wide drift summary.
    pub fn fleet_summary(&self) -> serde_json::Value {
        let total_hosts = self.reports.len();
        let compliant = self.reports.iter().filter(|r| r.compliant).count();
        let total_drifts: usize = self.reports.iter().map(|r| r.drifts_found).sum();
        let critical: usize = self.reports.iter().map(|r| r.critical_drifts).sum();

        serde_json::json!({
            "total_hosts_scanned": total_hosts,
            "compliant_hosts": compliant,
            "non_compliant_hosts": total_hosts - compliant,
            "compliance_pct": if total_hosts > 0 { (compliant as f64 / total_hosts as f64 * 100.0).round() } else { 0.0 },
            "total_drifts": total_drifts,
            "critical_drifts": critical,
            "baselines": self.baselines.len(),
        })
    }
}

fn classify_severity(category: &ConfigCategory, key: &str) -> DriftSeverity {
    match category {
        ConfigCategory::SshServer => {
            if key == "PermitRootLogin" || key == "PasswordAuthentication" {
                DriftSeverity::Critical
            } else {
                DriftSeverity::High
            }
        }
        ConfigCategory::Firewall => DriftSeverity::High,
        ConfigCategory::KernelParams => {
            if key.contains("randomize") || key.contains("exec_shield") {
                DriftSeverity::Critical
            } else {
                DriftSeverity::Medium
            }
        }
        ConfigCategory::AuthConfig => DriftSeverity::High,
        ConfigCategory::DockerDaemon => DriftSeverity::High,
        _ => DriftSeverity::Medium,
    }
}

fn mitre_for_category(category: &ConfigCategory) -> Vec<String> {
    match category {
        ConfigCategory::SshServer => vec!["T1098".into(), "T1556".into()],
        ConfigCategory::Firewall => vec!["T1562.004".into()],
        ConfigCategory::KernelParams => vec!["T1014".into()],
        ConfigCategory::AuthConfig => vec!["T1556".into()],
        ConfigCategory::DockerDaemon => vec!["T1611".into()],
        _ => vec![],
    }
}

fn builtin_baselines() -> Vec<ConfigBaseline> {
    vec![
        ConfigBaseline {
            path: "/etc/ssh/sshd_config".into(),
            category: ConfigCategory::SshServer,
            expected_hash: String::new(),
            expected_values: HashMap::from([
                ("PermitRootLogin".into(), "no".into()),
                ("PasswordAuthentication".into(), "no".into()),
                ("X11Forwarding".into(), "no".into()),
                ("MaxAuthTries".into(), "3".into()),
                ("Protocol".into(), "2".into()),
            ]),
            host_class: "default".into(),
            created_at: "2025-01-01T00:00:00Z".into(),
        },
        ConfigBaseline {
            path: "kernel.params".into(),
            category: ConfigCategory::KernelParams,
            expected_hash: String::new(),
            expected_values: HashMap::from([
                ("kernel.randomize_va_space".into(), "2".into()),
                ("net.ipv4.ip_forward".into(), "0".into()),
                ("net.ipv4.conf.all.accept_redirects".into(), "0".into()),
                ("net.ipv4.conf.all.send_redirects".into(), "0".into()),
            ]),
            host_class: "default".into(),
            created_at: "2025-01-01T00:00:00Z".into(),
        },
        ConfigBaseline {
            path: "/etc/docker/daemon.json".into(),
            category: ConfigCategory::DockerDaemon,
            expected_hash: String::new(),
            expected_values: HashMap::from([
                ("no-new-privileges".into(), "true".into()),
                ("icc".into(), "false".into()),
                ("live-restore".into(), "true".into()),
                ("userland-proxy".into(), "false".into()),
            ]),
            host_class: "default".into(),
            created_at: "2025-01-01T00:00:00Z".into(),
        },
    ]
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_ssh_drift() {
        let mut detector = ConfigDriftDetector::new();
        let mut actual = HashMap::new();
        actual.insert("/etc/ssh/sshd_config".to_string(), HashMap::from([
            ("PermitRootLogin".into(), "yes".into()),  // DRIFT
            ("PasswordAuthentication".into(), "no".into()),
            ("X11Forwarding".into(), "no".into()),
            ("MaxAuthTries".into(), "3".into()),
            ("Protocol".into(), "2".into()),
        ]));
        let report = detector.check("host-1", &actual);
        assert!(report.drifts_found > 0);
        assert!(report.critical_drifts > 0);
        assert!(!report.compliant);
    }

    #[test]
    fn compliant_host() {
        let mut detector = ConfigDriftDetector::new();
        let mut actual = HashMap::new();
        actual.insert("/etc/ssh/sshd_config".to_string(), HashMap::from([
            ("PermitRootLogin".into(), "no".into()),
            ("PasswordAuthentication".into(), "no".into()),
            ("X11Forwarding".into(), "no".into()),
            ("MaxAuthTries".into(), "3".into()),
            ("Protocol".into(), "2".into()),
        ]));
        actual.insert("kernel.params".to_string(), HashMap::from([
            ("kernel.randomize_va_space".into(), "2".into()),
            ("net.ipv4.ip_forward".into(), "0".into()),
            ("net.ipv4.conf.all.accept_redirects".into(), "0".into()),
            ("net.ipv4.conf.all.send_redirects".into(), "0".into()),
        ]));
        actual.insert("/etc/docker/daemon.json".to_string(), HashMap::from([
            ("no-new-privileges".into(), "true".into()),
            ("icc".into(), "false".into()),
            ("live-restore".into(), "true".into()),
            ("userland-proxy".into(), "false".into()),
        ]));
        let report = detector.check("host-1", &actual);
        assert!(report.compliant);
    }
}
