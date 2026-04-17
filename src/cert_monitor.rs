//! TLS certificate expiry monitoring.
//!
//! Discovers and tracks TLS certificates across the fleet, alerting
//! on upcoming expirations and providing a fleet-wide certificate
//! inventory.

use serde::{Deserialize, Serialize};

// ── Certificate record ──────────────────────────────────────────

/// A discovered TLS certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateRecord {
    pub hostname: String,
    pub port: u16,
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub not_before: String,
    pub not_after: String,
    pub days_until_expiry: i64,
    pub fingerprint_sha256: String,
    pub san_domains: Vec<String>,
    pub key_algorithm: String,
    pub key_size_bits: u32,
    pub is_self_signed: bool,
    pub is_expired: bool,
    pub is_expiring_soon: bool,
    pub agent_id: Option<String>,
    pub discovered_at: String,
}

/// Certificate health status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CertHealth {
    Valid,
    ExpiringSoon,
    Expired,
    SelfSigned,
    WeakKey,
}

/// A certificate alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertAlert {
    pub certificate: CertificateRecord,
    pub health: CertHealth,
    pub severity: String,
    pub message: String,
}

/// Fleet-wide certificate summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertSummary {
    pub total_certificates: usize,
    pub valid: usize,
    pub expiring_30d: usize,
    pub expiring_7d: usize,
    pub expired: usize,
    pub self_signed: usize,
    pub weak_key: usize,
    pub alerts: Vec<CertAlert>,
    pub certificates: Vec<CertificateRecord>,
}

// ── Certificate monitor ─────────────────────────────────────────

/// Certificate monitoring engine.
pub struct CertMonitor {
    certificates: Vec<CertificateRecord>,
    /// Days before expiry to start warning (default: 30).
    expiry_warning_days: i64,
    /// Days before expiry considered critical (default: 7).
    expiry_critical_days: i64,
    /// Minimum key size considered secure (default: 2048).
    min_key_size: u32,
}

impl Default for CertMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl CertMonitor {
    pub fn new() -> Self {
        Self {
            certificates: Vec::new(),
            expiry_warning_days: 30,
            expiry_critical_days: 7,
            min_key_size: 2048,
        }
    }

    /// Record a discovered certificate.
    pub fn record_certificate(&mut self, mut cert: CertificateRecord) {
        cert.is_expired = cert.days_until_expiry < 0;
        cert.is_expiring_soon =
            cert.days_until_expiry >= 0 && cert.days_until_expiry <= self.expiry_warning_days;

        // Replace existing cert for the same host:port
        self.certificates
            .retain(|c| !(c.hostname == cert.hostname && c.port == cert.port));
        self.certificates.push(cert);
    }

    /// Import certificates from an agent's TLS scan.
    pub fn import_agent_certs(&mut self, agent_id: &str, certs: Vec<CertificateRecord>) {
        for mut cert in certs {
            cert.agent_id = Some(agent_id.to_string());
            self.record_certificate(cert);
        }
    }

    /// Number of tracked certificates.
    pub fn certificate_count(&self) -> usize {
        self.certificates.len()
    }

    /// Evaluate all certificates and produce a summary with alerts.
    pub fn evaluate(&self) -> CertSummary {
        let mut alerts = Vec::new();
        let mut valid = 0;
        let mut expiring_30d = 0;
        let mut expiring_7d = 0;
        let mut expired = 0;
        let mut self_signed = 0;
        let mut weak_key = 0;

        for cert in &self.certificates {
            if cert.is_expired {
                expired += 1;
                alerts.push(CertAlert {
                    certificate: cert.clone(),
                    health: CertHealth::Expired,
                    severity: "Critical".into(),
                    message: format!(
                        "Certificate expired {} days ago: {} on {}:{}",
                        -cert.days_until_expiry, cert.subject, cert.hostname, cert.port
                    ),
                });
            } else if cert.days_until_expiry <= self.expiry_critical_days {
                expiring_7d += 1;
                expiring_30d += 1;
                alerts.push(CertAlert {
                    certificate: cert.clone(),
                    health: CertHealth::ExpiringSoon,
                    severity: "High".into(),
                    message: format!(
                        "Certificate expires in {} days: {} on {}:{}",
                        cert.days_until_expiry, cert.subject, cert.hostname, cert.port
                    ),
                });
            } else if cert.days_until_expiry <= self.expiry_warning_days {
                expiring_30d += 1;
                alerts.push(CertAlert {
                    certificate: cert.clone(),
                    health: CertHealth::ExpiringSoon,
                    severity: "Medium".into(),
                    message: format!(
                        "Certificate expires in {} days: {} on {}:{}",
                        cert.days_until_expiry, cert.subject, cert.hostname, cert.port
                    ),
                });
            } else {
                valid += 1;
            }

            if cert.is_self_signed {
                self_signed += 1;
                alerts.push(CertAlert {
                    certificate: cert.clone(),
                    health: CertHealth::SelfSigned,
                    severity: "Low".into(),
                    message: format!(
                        "Self-signed certificate: {} on {}:{}",
                        cert.subject, cert.hostname, cert.port
                    ),
                });
            }

            if cert.key_size_bits > 0 && cert.key_size_bits < self.min_key_size {
                weak_key += 1;
                alerts.push(CertAlert {
                    certificate: cert.clone(),
                    health: CertHealth::WeakKey,
                    severity: "Medium".into(),
                    message: format!(
                        "Weak key ({} bits) for {} on {}:{}",
                        cert.key_size_bits, cert.subject, cert.hostname, cert.port
                    ),
                });
            }
        }

        // Sort alerts by severity
        alerts.sort_by(|a, b| severity_rank(&a.severity).cmp(&severity_rank(&b.severity)));

        CertSummary {
            total_certificates: self.certificates.len(),
            valid,
            expiring_30d,
            expiring_7d,
            expired,
            self_signed,
            weak_key,
            alerts,
            certificates: self.certificates.clone(),
        }
    }
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "Critical" => 0,
        "High" => 1,
        "Medium" => 2,
        "Low" => 3,
        _ => 4,
    }
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cert(hostname: &str, days: i64) -> CertificateRecord {
        CertificateRecord {
            hostname: hostname.into(),
            port: 443,
            subject: format!("CN={hostname}"),
            issuer: "CN=Test CA".into(),
            serial_number: "001".into(),
            not_before: "2025-01-01T00:00:00Z".into(),
            not_after: "2026-01-01T00:00:00Z".into(),
            days_until_expiry: days,
            fingerprint_sha256: "abc123".into(),
            san_domains: vec![hostname.to_string()],
            key_algorithm: "RSA".into(),
            key_size_bits: 2048,
            is_self_signed: false,
            is_expired: days < 0,
            is_expiring_soon: days >= 0 && days <= 30,
            agent_id: None,
            discovered_at: "2025-06-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn detects_expired_cert() {
        let mut mon = CertMonitor::new();
        mon.record_certificate(make_cert("expired.example.com", -5));
        let summary = mon.evaluate();
        assert_eq!(summary.expired, 1);
        assert!(!summary.alerts.is_empty());
    }

    #[test]
    fn detects_expiring_soon() {
        let mut mon = CertMonitor::new();
        mon.record_certificate(make_cert("soon.example.com", 5));
        let summary = mon.evaluate();
        assert_eq!(summary.expiring_7d, 1);
    }

    #[test]
    fn valid_cert_no_alert() {
        let mut mon = CertMonitor::new();
        mon.record_certificate(make_cert("good.example.com", 365));
        let summary = mon.evaluate();
        assert_eq!(summary.valid, 1);
        assert!(summary.alerts.is_empty());
    }

    #[test]
    fn detects_weak_key() {
        let mut mon = CertMonitor::new();
        let mut cert = make_cert("weak.example.com", 365);
        cert.key_size_bits = 1024;
        mon.record_certificate(cert);
        let summary = mon.evaluate();
        assert_eq!(summary.weak_key, 1);
    }
}
