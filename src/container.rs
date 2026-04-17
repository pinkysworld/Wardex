//! Container and workload detection engine.
//!
//! Detects container escape attempts, privileged container spawns,
//! unusual image pulls, Kubernetes RBAC abuse, and suspicious
//! container runtime behaviour.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Container event model ───────────────────────────────────────

/// Types of container events to monitor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ContainerEventKind {
    ContainerStart,
    ContainerStop,
    ContainerExec,
    ImagePull,
    ImageDelete,
    VolumeMount,
    PrivilegedRun,
    CapabilityAdded,
    NamespaceEscape,
    ProcessEscape,
    K8sRbacChange,
    K8sSecretAccess,
    K8sServiceAccountUse,
    K8sAdmissionDenied,
}

/// A container runtime event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerEvent {
    pub timestamp_ms: u64,
    pub kind: ContainerEventKind,
    pub container_id: String,
    pub container_name: String,
    pub image: String,
    pub hostname: String,
    pub namespace: Option<String>,
    pub user: Option<String>,
    pub command: Option<String>,
    pub details: HashMap<String, String>,
    pub agent_id: Option<String>,
}

// ── Detection results ───────────────────────────────────────────

/// A container security alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerAlert {
    pub id: String,
    pub timestamp: String,
    pub severity: ContainerSeverity,
    pub kind: ContainerAlertKind,
    pub container_id: String,
    pub container_name: String,
    pub image: String,
    pub hostname: String,
    pub description: String,
    pub risk_score: f32,
    pub mitre_techniques: Vec<String>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ContainerSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ContainerAlertKind {
    PrivilegedContainer,
    ContainerEscape,
    SuspiciousExec,
    UnusualImagePull,
    SensitiveMount,
    CapabilityAbuse,
    K8sRbacEscalation,
    K8sSecretExfiltration,
}

/// Container workload summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerSummary {
    pub total_events: usize,
    pub total_alerts: usize,
    pub critical_alerts: usize,
    pub active_containers: usize,
    pub privileged_containers: usize,
    pub unique_images: usize,
    pub alerts: Vec<ContainerAlert>,
    pub image_stats: Vec<ImageStat>,
}

/// Per-image statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageStat {
    pub image: String,
    pub container_count: usize,
    pub event_count: usize,
    pub alert_count: usize,
    pub privileged: bool,
}

// ── Detection engine ────────────────────────────────────────────

/// Container workload detection engine.
pub struct ContainerDetector {
    events: Vec<ContainerEvent>,
    alerts: Vec<ContainerAlert>,
    alert_counter: u64,
    /// Known-good images that are expected in the environment.
    trusted_images: Vec<String>,
    /// Sensitive mount paths that should trigger alerts.
    sensitive_mounts: Vec<String>,
    /// Dangerous capabilities.
    dangerous_caps: Vec<String>,
}

impl Default for ContainerDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ContainerDetector {
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            alerts: Vec::new(),
            alert_counter: 0,
            trusted_images: Vec::new(),
            sensitive_mounts: vec![
                "/var/run/docker.sock".into(),
                "/proc".into(),
                "/sys".into(),
                "/etc/shadow".into(),
                "/etc/kubernetes".into(),
                "/root/.kube".into(),
            ],
            dangerous_caps: vec![
                "SYS_ADMIN".into(),
                "SYS_PTRACE".into(),
                "NET_ADMIN".into(),
                "DAC_OVERRIDE".into(),
                "SYS_RAWIO".into(),
            ],
        }
    }

    /// Add trusted images that won't trigger unusual-image alerts.
    pub fn add_trusted_images(&mut self, images: Vec<String>) {
        self.trusted_images.extend(images);
    }

    /// Record a container event and evaluate it for threats.
    pub fn record_event(&mut self, event: ContainerEvent) {
        let new_alerts = self.evaluate(&event);
        self.alerts.extend(new_alerts);
        self.events.push(event);
    }

    /// Get current alerts.
    pub fn alerts(&self) -> &[ContainerAlert] {
        &self.alerts
    }

    /// Total events recorded.
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Evict old events.
    pub fn evict_before(&mut self, cutoff_ms: u64) {
        self.events.retain(|e| e.timestamp_ms >= cutoff_ms);
    }

    /// Generate a summary report.
    pub fn summary(&self) -> ContainerSummary {
        let active_containers: std::collections::HashSet<&str> = self
            .events
            .iter()
            .filter(|e| e.kind == ContainerEventKind::ContainerStart)
            .map(|e| e.container_id.as_str())
            .collect();
        let stopped: std::collections::HashSet<&str> = self
            .events
            .iter()
            .filter(|e| e.kind == ContainerEventKind::ContainerStop)
            .map(|e| e.container_id.as_str())
            .collect();
        let running = active_containers.difference(&stopped).count();
        let privileged = self
            .events
            .iter()
            .filter(|e| e.kind == ContainerEventKind::PrivilegedRun)
            .map(|e| e.container_id.as_str())
            .collect::<std::collections::HashSet<_>>()
            .len();
        let unique_images: std::collections::HashSet<&str> = self
            .events
            .iter()
            .map(|e| e.image.as_str())
            .filter(|i| !i.is_empty())
            .collect();

        // Per-image stats
        let mut image_map: HashMap<&str, (usize, usize, usize, bool)> = HashMap::new();
        for e in &self.events {
            if e.image.is_empty() {
                continue;
            }
            let entry = image_map.entry(&e.image).or_insert((0, 0, 0, false));
            if e.kind == ContainerEventKind::ContainerStart {
                entry.0 += 1;
            }
            entry.1 += 1;
            if e.kind == ContainerEventKind::PrivilegedRun {
                entry.3 = true;
            }
        }
        for alert in &self.alerts {
            if let Some(entry) = image_map.get_mut(alert.image.as_str()) {
                entry.2 += 1;
            }
        }
        let image_stats: Vec<ImageStat> = image_map
            .into_iter()
            .map(|(img, (cc, ec, ac, priv_flag))| ImageStat {
                image: img.to_string(),
                container_count: cc,
                event_count: ec,
                alert_count: ac,
                privileged: priv_flag,
            })
            .collect();

        let critical_alerts = self
            .alerts
            .iter()
            .filter(|a| a.severity == ContainerSeverity::Critical)
            .count();

        ContainerSummary {
            total_events: self.events.len(),
            total_alerts: self.alerts.len(),
            critical_alerts,
            active_containers: running,
            privileged_containers: privileged,
            unique_images: unique_images.len(),
            alerts: self.alerts.clone(),
            image_stats,
        }
    }

    fn next_alert_id(&mut self) -> String {
        self.alert_counter += 1;
        format!("container-alert-{}", self.alert_counter)
    }

    fn evaluate(&mut self, event: &ContainerEvent) -> Vec<ContainerAlert> {
        let mut alerts = Vec::new();
        let ts = chrono::Utc::now().to_rfc3339();

        match event.kind {
            ContainerEventKind::PrivilegedRun => {
                alerts.push(ContainerAlert {
                    id: self.next_alert_id(),
                    timestamp: ts.clone(),
                    severity: ContainerSeverity::High,
                    kind: ContainerAlertKind::PrivilegedContainer,
                    container_id: event.container_id.clone(),
                    container_name: event.container_name.clone(),
                    image: event.image.clone(),
                    hostname: event.hostname.clone(),
                    description: format!(
                        "Privileged container started: {} ({})",
                        event.container_name, event.image
                    ),
                    risk_score: 7.5,
                    mitre_techniques: vec!["T1610".into(), "T1611".into()],
                    recommendations: vec![
                        "Review whether privileged mode is required".into(),
                        "Use seccomp/AppArmor profiles instead".into(),
                    ],
                });
            }
            ContainerEventKind::NamespaceEscape | ContainerEventKind::ProcessEscape => {
                alerts.push(ContainerAlert {
                    id: self.next_alert_id(),
                    timestamp: ts.clone(),
                    severity: ContainerSeverity::Critical,
                    kind: ContainerAlertKind::ContainerEscape,
                    container_id: event.container_id.clone(),
                    container_name: event.container_name.clone(),
                    image: event.image.clone(),
                    hostname: event.hostname.clone(),
                    description: format!(
                        "Container escape detected: {} on {}",
                        event.container_name, event.hostname
                    ),
                    risk_score: 9.5,
                    mitre_techniques: vec!["T1611".into()],
                    recommendations: vec![
                        "Isolate affected host immediately".into(),
                        "Investigate container image for compromise".into(),
                        "Review container runtime version for known CVEs".into(),
                    ],
                });
            }
            ContainerEventKind::ContainerExec => {
                if let Some(cmd) = &event.command {
                    let suspicious_cmds = [
                        "bash", "sh", "/bin/sh", "nc", "ncat", "curl", "wget", "python", "perl",
                    ];
                    if suspicious_cmds.iter().any(|s| cmd.contains(s)) {
                        alerts.push(ContainerAlert {
                            id: self.next_alert_id(),
                            timestamp: ts.clone(),
                            severity: ContainerSeverity::Medium,
                            kind: ContainerAlertKind::SuspiciousExec,
                            container_id: event.container_id.clone(),
                            container_name: event.container_name.clone(),
                            image: event.image.clone(),
                            hostname: event.hostname.clone(),
                            description: format!("Suspicious exec in container: {cmd}"),
                            risk_score: 5.0,
                            mitre_techniques: vec!["T1059".into()],
                            recommendations: vec![
                                "Verify exec is authorised operational activity".into(),
                            ],
                        });
                    }
                }
            }
            ContainerEventKind::ImagePull => {
                if !self.trusted_images.is_empty()
                    && !self
                        .trusted_images
                        .iter()
                        .any(|t| event.image.starts_with(t))
                {
                    alerts.push(ContainerAlert {
                        id: self.next_alert_id(),
                        timestamp: ts.clone(),
                        severity: ContainerSeverity::Medium,
                        kind: ContainerAlertKind::UnusualImagePull,
                        container_id: event.container_id.clone(),
                        container_name: event.container_name.clone(),
                        image: event.image.clone(),
                        hostname: event.hostname.clone(),
                        description: format!("Untrusted image pulled: {}", event.image),
                        risk_score: 4.0,
                        mitre_techniques: vec!["T1610".into()],
                        recommendations: vec![
                            "Verify image provenance and signature".into(),
                            "Check for known CVEs in image".into(),
                        ],
                    });
                }
            }
            ContainerEventKind::VolumeMount => {
                if let Some(path) = event.details.get("mount_path") {
                    if self.sensitive_mounts.iter().any(|s| path.starts_with(s)) {
                        alerts.push(ContainerAlert {
                            id: self.next_alert_id(),
                            timestamp: ts.clone(),
                            severity: ContainerSeverity::High,
                            kind: ContainerAlertKind::SensitiveMount,
                            container_id: event.container_id.clone(),
                            container_name: event.container_name.clone(),
                            image: event.image.clone(),
                            hostname: event.hostname.clone(),
                            description: format!("Sensitive host path mounted: {path}"),
                            risk_score: 7.0,
                            mitre_techniques: vec!["T1611".into()],
                            recommendations: vec![
                                "Restrict volume mounts to necessary paths only".into(),
                            ],
                        });
                    }
                }
            }
            ContainerEventKind::CapabilityAdded => {
                if let Some(cap) = event.details.get("capability") {
                    if self.dangerous_caps.iter().any(|c| cap == c) {
                        alerts.push(ContainerAlert {
                            id: self.next_alert_id(),
                            timestamp: ts.clone(),
                            severity: ContainerSeverity::High,
                            kind: ContainerAlertKind::CapabilityAbuse,
                            container_id: event.container_id.clone(),
                            container_name: event.container_name.clone(),
                            image: event.image.clone(),
                            hostname: event.hostname.clone(),
                            description: format!("Dangerous capability added: {cap}"),
                            risk_score: 6.5,
                            mitre_techniques: vec!["T1611".into()],
                            recommendations: vec![format!(
                                "Remove {cap} capability if not strictly needed"
                            )],
                        });
                    }
                }
            }
            ContainerEventKind::K8sRbacChange => {
                alerts.push(ContainerAlert {
                    id: self.next_alert_id(),
                    timestamp: ts.clone(),
                    severity: ContainerSeverity::High,
                    kind: ContainerAlertKind::K8sRbacEscalation,
                    container_id: event.container_id.clone(),
                    container_name: event.container_name.clone(),
                    image: event.image.clone(),
                    hostname: event.hostname.clone(),
                    description: "Kubernetes RBAC modification detected".into(),
                    risk_score: 7.0,
                    mitre_techniques: vec!["T1078.004".into()],
                    recommendations: vec!["Review RBAC change in audit log".into()],
                });
            }
            ContainerEventKind::K8sSecretAccess => {
                alerts.push(ContainerAlert {
                    id: self.next_alert_id(),
                    timestamp: ts.clone(),
                    severity: ContainerSeverity::Medium,
                    kind: ContainerAlertKind::K8sSecretExfiltration,
                    container_id: event.container_id.clone(),
                    container_name: event.container_name.clone(),
                    image: event.image.clone(),
                    hostname: event.hostname.clone(),
                    description: "Kubernetes secret access detected".into(),
                    risk_score: 5.5,
                    mitre_techniques: vec!["T1552.007".into()],
                    recommendations: vec!["Verify authorised secret access".into()],
                });
            }
            _ => {}
        }

        alerts
    }
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn base_event(kind: ContainerEventKind) -> ContainerEvent {
        ContainerEvent {
            timestamp_ms: 1000,
            kind,
            container_id: "abc123".into(),
            container_name: "test-container".into(),
            image: "nginx:latest".into(),
            hostname: "worker-1".into(),
            namespace: Some("default".into()),
            user: None,
            command: None,
            details: HashMap::new(),
            agent_id: None,
        }
    }

    #[test]
    fn detects_privileged_container() {
        let mut det = ContainerDetector::new();
        det.record_event(base_event(ContainerEventKind::PrivilegedRun));
        assert_eq!(det.alerts().len(), 1);
        assert_eq!(
            det.alerts()[0].kind,
            ContainerAlertKind::PrivilegedContainer
        );
    }

    #[test]
    fn detects_container_escape() {
        let mut det = ContainerDetector::new();
        det.record_event(base_event(ContainerEventKind::NamespaceEscape));
        assert_eq!(det.alerts().len(), 1);
        assert_eq!(det.alerts()[0].severity, ContainerSeverity::Critical);
    }

    #[test]
    fn detects_suspicious_exec() {
        let mut det = ContainerDetector::new();
        let mut event = base_event(ContainerEventKind::ContainerExec);
        event.command = Some("/bin/bash".into());
        det.record_event(event);
        assert_eq!(det.alerts().len(), 1);
    }

    #[test]
    fn normal_events_no_alerts() {
        let mut det = ContainerDetector::new();
        det.record_event(base_event(ContainerEventKind::ContainerStart));
        det.record_event(base_event(ContainerEventKind::ContainerStop));
        assert!(det.alerts().is_empty());
    }
}
