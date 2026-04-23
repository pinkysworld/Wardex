// OCSF-aligned canonical event model for cross-platform normalization.
// Based on Open Cybersecurity Schema Framework (OCSF) v1.1+ class structure.
// See: https://schema.ocsf.io

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── OCSF envelope ────────────────────────────────────────────────

/// Top-level OCSF event envelope wrapping all canonical event types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcsfEvent {
    /// OCSF class_uid identifying the event category.
    pub class_uid: u32,
    /// Activity ID within the class.
    pub activity_id: u32,
    /// Human-readable category name.
    pub category_name: String,
    /// Human-readable class name.
    pub class_name: String,
    /// Severity ID: 0=Unknown, 1=Info, 2=Low, 3=Medium, 4=High, 5=Critical, 6=Fatal.
    pub severity_id: u8,
    /// ISO-8601 timestamp.
    pub time: String,
    /// Event-specific data.
    pub data: OcsfData,
    /// Observables enrichment (optional).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observables: Vec<Observable>,
    /// Source metadata.
    pub metadata: EventMetadata,
}

/// Source metadata attached to every OCSF event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventMetadata {
    pub product: ProductInfo,
    /// Schema version.
    pub version: String,
    /// Unique event ID.
    pub uid: String,
    /// Original raw event ID (optional).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_uid: Option<String>,
    /// Tenant ID for multi-tenant isolation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_uid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductInfo {
    pub name: String,
    pub vendor_name: String,
    pub version: String,
}

/// Observable indicator extracted from the event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Observable {
    pub name: String,
    pub value: String,
    #[serde(rename = "type")]
    pub obs_type: String,
}

// ── OCSF event data variants ────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum OcsfData {
    Process(ProcessEvent),
    File(FileEvent),
    Network(NetworkEvent),
    Dns(DnsEvent),
    Auth(AuthEvent),
    Config(ConfigEvent),
    Detection(DetectionEvent),
}

// ── Class 1007: Process Activity ────────────────────────────────

/// OCSF Process Activity event (class_uid 1007).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessEvent {
    /// Activity: 1=Launch, 2=Terminate, 3=Open, 4=Inject, 99=Other.
    pub activity_id: u32,
    pub actor: ActorProcess,
    pub process: ProcessInfo,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_process: Option<ProcessInfo>,
    pub device: DeviceInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActorProcess {
    pub process: ProcessInfo,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<UserInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmd_line: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<FileInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
}

// ── Class 1001: File Activity ───────────────────────────────────

/// OCSF File Activity event (class_uid 1001).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    /// Activity: 1=Create, 2=Read, 3=Update, 4=Delete, 5=Rename, 6=SetAttr.
    pub activity_id: u32,
    pub file: FileInfo,
    pub actor: ActorProcess,
    pub device: DeviceInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub name: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hashes: Option<Vec<HashInfo>>,
    #[serde(rename = "type")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashInfo {
    pub algorithm: String,
    pub value: String,
}

// ── Class 4001: Network Activity ────────────────────────────────

/// OCSF Network Activity event (class_uid 4001).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEvent {
    /// Activity: 1=Open, 2=Close, 3=Reset, 4=Fail, 5=Refuse.
    pub activity_id: u32,
    pub src_endpoint: Endpoint,
    pub dst_endpoint: Endpoint,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_in: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_out: Option<u64>,
    pub device: DeviceInfo,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection_uid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endpoint {
    pub ip: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
}

// ── Class 4003: DNS Activity ────────────────────────────────────

/// OCSF DNS Activity event (class_uid 4003).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsEvent {
    /// Activity: 1=Query, 2=Response, 6=Traffic.
    pub activity_id: u32,
    pub query: DnsQuery,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub answers: Vec<DnsAnswer>,
    pub src_endpoint: Endpoint,
    pub device: DeviceInfo,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rcode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    pub hostname: String,
    #[serde(rename = "type")]
    pub query_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsAnswer {
    pub rdata: String,
    #[serde(rename = "type")]
    pub answer_type: String,
}

// ── Class 3002: Authentication ──────────────────────────────────

/// OCSF Authentication event (class_uid 3002).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthEvent {
    /// Activity: 1=Logon, 2=Logoff, 3=AuthTicket, 4=ServiceTicket.
    pub activity_id: u32,
    pub auth_protocol: Option<String>,
    pub user: UserInfo,
    pub src_endpoint: Endpoint,
    pub device: DeviceInfo,
    /// Status: 1=Success, 2=Failure, 99=Other.
    pub status_id: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logon_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(rename = "type")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_type: Option<String>,
}

// ── Class 5001: Configuration Activity ──────────────────────────

/// OCSF Device Config State event (class_uid 5001).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigEvent {
    /// Activity: 1=Create, 2=Update, 3=Delete, 4=Enable, 5=Disable.
    pub activity_id: u32,
    pub device: DeviceInfo,
    pub config_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_value: Option<String>,
    /// E.g. service, registry, crontab, launchd, group_policy.
    pub config_type: String,
}

// ── Class 2004: Detection Finding ───────────────────────────────

/// OCSF Detection Finding event (class_uid 2004).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionEvent {
    /// Activity: 1=Create, 2=Update, 3=Close.
    pub activity_id: u32,
    pub finding: FindingInfo,
    pub device: DeviceInfo,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attacks: Vec<AttackInfo>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidences: Vec<EvidenceInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingInfo {
    pub title: String,
    pub uid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desc: Option<String>,
    /// Confidence: 0-100.
    pub confidence: u8,
    pub severity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackInfo {
    pub tactic: String,
    pub technique_id: String,
    pub technique_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceInfo {
    #[serde(rename = "type")]
    pub evidence_type: String,
    pub data: String,
}

// ── Shared types ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub hostname: String,
    pub os: OsInfo,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_uid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    pub name: String,
    #[serde(rename = "type")]
    pub os_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

// ── Builder / normalization helpers ─────────────────────────────

impl OcsfEvent {
    fn base_metadata(uid: &str) -> EventMetadata {
        EventMetadata {
            product: ProductInfo {
                name: "Wardex".into(),
                vendor_name: "Wardex".into(),
                version: env!("CARGO_PKG_VERSION").into(),
            },
            version: "1.1.0".into(),
            uid: uid.into(),
            original_uid: None,
            tenant_uid: None,
        }
    }

    pub fn process(uid: &str, time: &str, severity_id: u8, event: ProcessEvent) -> Self {
        Self {
            class_uid: 1007,
            activity_id: event.activity_id,
            category_name: "System Activity".into(),
            class_name: "Process Activity".into(),
            severity_id,
            time: time.into(),
            data: OcsfData::Process(event),
            observables: Vec::new(),
            metadata: Self::base_metadata(uid),
        }
    }

    pub fn file(uid: &str, time: &str, severity_id: u8, event: FileEvent) -> Self {
        Self {
            class_uid: 1001,
            activity_id: event.activity_id,
            category_name: "System Activity".into(),
            class_name: "File Activity".into(),
            severity_id,
            time: time.into(),
            data: OcsfData::File(event),
            observables: Vec::new(),
            metadata: Self::base_metadata(uid),
        }
    }

    pub fn network(uid: &str, time: &str, severity_id: u8, event: NetworkEvent) -> Self {
        Self {
            class_uid: 4001,
            activity_id: event.activity_id,
            category_name: "Network Activity".into(),
            class_name: "Network Activity".into(),
            severity_id,
            time: time.into(),
            data: OcsfData::Network(event),
            observables: Vec::new(),
            metadata: Self::base_metadata(uid),
        }
    }

    pub fn dns(uid: &str, time: &str, severity_id: u8, event: DnsEvent) -> Self {
        Self {
            class_uid: 4003,
            activity_id: event.activity_id,
            category_name: "Network Activity".into(),
            class_name: "DNS Activity".into(),
            severity_id,
            time: time.into(),
            data: OcsfData::Dns(event),
            observables: Vec::new(),
            metadata: Self::base_metadata(uid),
        }
    }

    pub fn auth(uid: &str, time: &str, severity_id: u8, event: AuthEvent) -> Self {
        Self {
            class_uid: 3002,
            activity_id: event.activity_id,
            category_name: "Identity & Access Management".into(),
            class_name: "Authentication".into(),
            severity_id,
            time: time.into(),
            data: OcsfData::Auth(event),
            observables: Vec::new(),
            metadata: Self::base_metadata(uid),
        }
    }

    pub fn config(uid: &str, time: &str, severity_id: u8, event: ConfigEvent) -> Self {
        Self {
            class_uid: 5001,
            activity_id: event.activity_id,
            category_name: "Application Activity".into(),
            class_name: "Device Config State".into(),
            severity_id,
            time: time.into(),
            data: OcsfData::Config(event),
            observables: Vec::new(),
            metadata: Self::base_metadata(uid),
        }
    }

    pub fn detection(uid: &str, time: &str, severity_id: u8, event: DetectionEvent) -> Self {
        Self {
            class_uid: 2004,
            activity_id: event.activity_id,
            category_name: "Findings".into(),
            class_name: "Detection Finding".into(),
            severity_id,
            time: time.into(),
            data: OcsfData::Detection(event),
            observables: Vec::new(),
            metadata: Self::base_metadata(uid),
        }
    }
}

/// Normalize an AlertRecord into an OCSF DetectionEvent.
pub fn alert_to_ocsf(alert: &crate::collector::AlertRecord) -> OcsfEvent {
    let uid = format!("{:x}", rand::random::<u64>());
    let attacks: Vec<AttackInfo> = alert
        .mitre
        .iter()
        .map(|m| AttackInfo {
            tactic: m.tactic.clone(),
            technique_id: m.technique_id.clone(),
            technique_name: m.technique_name.clone(),
        })
        .collect();

    let severity_id = match alert.level.to_lowercase().as_str() {
        "critical" => 5,
        "severe" => 4,
        "elevated" => 3,
        _ => 1,
    };

    let confidence = (alert.confidence * 100.0).min(100.0) as u8;
    let event = DetectionEvent {
        activity_id: 1,
        finding: FindingInfo {
            title: alert
                .reasons
                .first()
                .cloned()
                .unwrap_or_else(|| "anomaly".into()),
            uid: uid.clone(),
            desc: Some(alert.reasons.join("; ")),
            confidence,
            severity: alert.level.clone(),
            src_url: None,
        },
        device: DeviceInfo {
            hostname: alert.hostname.clone(),
            os: OsInfo {
                name: alert.platform.clone(),
                os_type: alert.platform.clone(),
                version: None,
            },
            ip: None,
            agent_uid: None,
        },
        attacks,
        evidences: Vec::new(),
    };

    OcsfEvent::detection(&uid, &alert.timestamp, severity_id, event)
}

// ── Schema versioning ───────────────────────────────────────────

/// Schema version registry for tracking supported OCSF versions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaVersion {
    pub ocsf_version: String,
    pub product_version: String,
    pub supported_classes: Vec<u32>,
}

impl SchemaVersion {
    pub fn current() -> Self {
        Self {
            ocsf_version: "1.1.0".into(),
            product_version: env!("CARGO_PKG_VERSION").into(),
            supported_classes: vec![1001, 1007, 2004, 3002, 4001, 4003, 5001],
        }
    }
}

/// Validate that an OcsfEvent has all required fields populated.
pub fn validate_event(event: &OcsfEvent) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    if event.time.is_empty() {
        errors.push("time is required".into());
    }
    if event.metadata.uid.is_empty() {
        errors.push("metadata.uid is required".into());
    }
    if event.class_uid == 0 {
        errors.push("class_uid must be non-zero".into());
    }

    match &event.data {
        OcsfData::Process(p) => {
            if p.process.name.is_empty() {
                errors.push("process.name is required".into());
            }
            if p.device.hostname.is_empty() {
                errors.push("device.hostname is required".into());
            }
        }
        OcsfData::File(f) => {
            if f.file.path.is_empty() {
                errors.push("file.path is required".into());
            }
            if f.device.hostname.is_empty() {
                errors.push("device.hostname is required".into());
            }
        }
        OcsfData::Network(n) => {
            if n.src_endpoint.ip.is_empty() {
                errors.push("src_endpoint.ip is required".into());
            }
            if n.device.hostname.is_empty() {
                errors.push("device.hostname is required".into());
            }
        }
        OcsfData::Dns(d) => {
            if d.query.hostname.is_empty() {
                errors.push("query.hostname is required".into());
            }
        }
        OcsfData::Auth(a) => {
            if a.user.name.is_empty() {
                errors.push("user.name is required".into());
            }
        }
        OcsfData::Config(c) => {
            if c.config_name.is_empty() {
                errors.push("config_name is required".into());
            }
        }
        OcsfData::Detection(d) => {
            if d.finding.title.is_empty() {
                errors.push("finding.title is required".into());
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

// ── Dead-letter handling ────────────────────────────────────────

/// Dead-lettered event that failed validation or normalization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeadLetterEvent {
    pub original_payload: String,
    pub errors: Vec<String>,
    pub received_at: String,
    pub source_agent: Option<String>,
}

/// Dead-letter queue for malformed or unprocessable events.
pub struct DeadLetterQueue {
    events: Vec<DeadLetterEvent>,
    max_size: usize,
}

impl DeadLetterQueue {
    pub fn new(max_size: usize) -> Self {
        Self {
            events: Vec::new(),
            max_size,
        }
    }

    pub fn push(&mut self, event: DeadLetterEvent) {
        if self.events.len() >= self.max_size {
            self.events.remove(0);
        }
        self.events.push(event);
    }

    pub fn list(&self) -> &[DeadLetterEvent] {
        &self.events
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn clear(&mut self) {
        self.events.clear();
    }
}

// ── Idempotency ─────────────────────────────────────────────────

/// Tracks event UIDs to prevent duplicate processing.
pub struct IdempotencyTracker {
    seen: HashMap<String, String>, // uid -> timestamp
    order: Vec<String>,            // insertion order for FIFO eviction
    max_size: usize,
}

impl IdempotencyTracker {
    pub fn new(max_size: usize) -> Self {
        Self {
            seen: HashMap::new(),
            order: Vec::new(),
            max_size,
        }
    }

    /// Returns true if this event was already processed.
    pub fn is_duplicate(&self, uid: &str) -> bool {
        self.seen.contains_key(uid)
    }

    /// Record an event UID as processed. Returns false if it was already seen.
    pub fn record(&mut self, uid: String, timestamp: String) -> bool {
        if self.seen.contains_key(&uid) {
            return false;
        }
        if self.seen.len() >= self.max_size {
            // Evict oldest entry (FIFO)
            if let Some(oldest_key) = self.order.first().cloned() {
                self.seen.remove(&oldest_key);
                self.order.remove(0);
            }
        }
        self.order.push(uid.clone());
        self.seen.insert(uid, timestamp);
        true
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_device() -> DeviceInfo {
        DeviceInfo {
            hostname: "test-host".into(),
            os: OsInfo {
                name: "linux".into(),
                os_type: "Linux".into(),
                version: Some("6.1".into()),
            },
            ip: Some("10.0.0.1".into()),
            agent_uid: Some("agent-001".into()),
        }
    }

    #[test]
    fn create_process_event() {
        let pe = ProcessEvent {
            activity_id: 1,
            actor: ActorProcess {
                process: ProcessInfo {
                    pid: 1,
                    ppid: Some(0),
                    name: "init".into(),
                    cmd_line: None,
                    file: None,
                    created_time: None,
                    uid: None,
                },
                user: Some(UserInfo {
                    name: "root".into(),
                    uid: Some("0".into()),
                    domain: None,
                    email: None,
                    user_type: None,
                }),
            },
            process: ProcessInfo {
                pid: 1234,
                ppid: Some(1),
                name: "suspicious.bin".into(),
                cmd_line: Some("/tmp/suspicious.bin --payload".into()),
                file: None,
                created_time: None,
                uid: None,
            },
            parent_process: None,
            device: sample_device(),
        };

        let event = OcsfEvent::process("uid-001", "2026-04-01T00:00:00Z", 4, pe);
        assert_eq!(event.class_uid, 1007);
        assert_eq!(event.class_name, "Process Activity");
        assert_eq!(event.severity_id, 4);
        assert!(validate_event(&event).is_ok());
    }

    #[test]
    fn create_file_event() {
        let fe = FileEvent {
            activity_id: 1,
            file: FileInfo {
                name: "malware.exe".into(),
                path: "/tmp/malware.exe".into(),
                size: Some(4096),
                hashes: None,
                file_type: Some("Regular".into()),
            },
            actor: ActorProcess {
                process: ProcessInfo {
                    pid: 100,
                    ppid: None,
                    name: "bash".into(),
                    cmd_line: None,
                    file: None,
                    created_time: None,
                    uid: None,
                },
                user: None,
            },
            device: sample_device(),
        };
        let event = OcsfEvent::file("uid-002", "2026-04-01T00:01:00Z", 3, fe);
        assert_eq!(event.class_uid, 1001);
        assert!(validate_event(&event).is_ok());
    }

    #[test]
    fn create_network_event() {
        let ne = NetworkEvent {
            activity_id: 1,
            src_endpoint: Endpoint {
                ip: "10.0.0.5".into(),
                port: 45321,
                hostname: None,
            },
            dst_endpoint: Endpoint {
                ip: "185.66.15.3".into(),
                port: 443,
                hostname: Some("c2.evil.com".into()),
            },
            protocol_name: Some("TCP".into()),
            bytes_in: Some(1200),
            bytes_out: Some(54000),
            device: sample_device(),
            connection_uid: None,
        };
        let event = OcsfEvent::network("uid-003", "2026-04-01T00:02:00Z", 4, ne);
        assert_eq!(event.class_uid, 4001);
        assert!(validate_event(&event).is_ok());
    }

    #[test]
    fn create_dns_event() {
        let de = DnsEvent {
            activity_id: 1,
            query: DnsQuery {
                hostname: "evil.com".into(),
                query_type: "A".into(),
                class: None,
            },
            answers: vec![DnsAnswer {
                rdata: "185.66.15.3".into(),
                answer_type: "A".into(),
            }],
            src_endpoint: Endpoint {
                ip: "10.0.0.5".into(),
                port: 53,
                hostname: None,
            },
            device: sample_device(),
            rcode: Some("NOERROR".into()),
        };
        let event = OcsfEvent::dns("uid-004", "2026-04-01T00:03:00Z", 2, de);
        assert_eq!(event.class_uid, 4003);
        assert!(validate_event(&event).is_ok());
    }

    #[test]
    fn create_auth_event() {
        let ae = AuthEvent {
            activity_id: 1,
            auth_protocol: Some("Kerberos".into()),
            user: UserInfo {
                name: "admin".into(),
                uid: Some("500".into()),
                domain: Some("CORP".into()),
                email: None,
                user_type: None,
            },
            src_endpoint: Endpoint {
                ip: "10.0.0.100".into(),
                port: 49152,
                hostname: None,
            },
            device: sample_device(),
            status_id: 2,
            logon_type: Some("Network".into()),
        };
        let event = OcsfEvent::auth("uid-005", "2026-04-01T00:04:00Z", 4, ae);
        assert_eq!(event.class_uid, 3002);
        assert!(validate_event(&event).is_ok());
    }

    #[test]
    fn create_config_event() {
        let ce = ConfigEvent {
            activity_id: 2,
            device: sample_device(),
            config_name: "sshd_config".into(),
            prev_value: Some("PermitRootLogin no".into()),
            new_value: Some("PermitRootLogin yes".into()),
            config_type: "service".into(),
        };
        let event = OcsfEvent::config("uid-006", "2026-04-01T00:05:00Z", 4, ce);
        assert_eq!(event.class_uid, 5001);
        assert!(validate_event(&event).is_ok());
    }

    #[test]
    fn validate_catches_missing_fields() {
        let event = OcsfEvent {
            class_uid: 0,
            activity_id: 0,
            category_name: String::new(),
            class_name: String::new(),
            severity_id: 0,
            time: String::new(),
            data: OcsfData::Detection(DetectionEvent {
                activity_id: 1,
                finding: FindingInfo {
                    title: String::new(),
                    uid: String::new(),
                    desc: None,
                    confidence: 0,
                    severity: String::new(),
                    src_url: None,
                },
                device: DeviceInfo {
                    hostname: String::new(),
                    os: OsInfo {
                        name: String::new(),
                        os_type: String::new(),
                        version: None,
                    },
                    ip: None,
                    agent_uid: None,
                },
                attacks: Vec::new(),
                evidences: Vec::new(),
            }),
            observables: Vec::new(),
            metadata: EventMetadata {
                product: ProductInfo {
                    name: String::new(),
                    vendor_name: String::new(),
                    version: String::new(),
                },
                version: String::new(),
                uid: String::new(),
                original_uid: None,
                tenant_uid: None,
            },
        };
        let result = validate_event(&event);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.len() >= 3);
    }

    #[test]
    fn dead_letter_queue_operations() {
        let mut dlq = DeadLetterQueue::new(3);
        assert!(dlq.is_empty());
        dlq.push(DeadLetterEvent {
            original_payload: "bad1".into(),
            errors: vec!["err".into()],
            received_at: "now".into(),
            source_agent: None,
        });
        dlq.push(DeadLetterEvent {
            original_payload: "bad2".into(),
            errors: vec!["err".into()],
            received_at: "now".into(),
            source_agent: None,
        });
        dlq.push(DeadLetterEvent {
            original_payload: "bad3".into(),
            errors: vec!["err".into()],
            received_at: "now".into(),
            source_agent: None,
        });
        assert_eq!(dlq.len(), 3);
        // Overflow evicts oldest
        dlq.push(DeadLetterEvent {
            original_payload: "bad4".into(),
            errors: vec!["err".into()],
            received_at: "now".into(),
            source_agent: None,
        });
        assert_eq!(dlq.len(), 3);
        assert_eq!(dlq.list()[0].original_payload, "bad2");
    }

    #[test]
    fn idempotency_tracker() {
        let mut tracker = IdempotencyTracker::new(100);
        assert!(tracker.record("uid-1".into(), "t1".into()));
        assert!(!tracker.record("uid-1".into(), "t2".into())); // duplicate
        assert!(tracker.is_duplicate("uid-1"));
        assert!(!tracker.is_duplicate("uid-999"));
    }

    #[test]
    fn schema_version() {
        let v = SchemaVersion::current();
        assert_eq!(v.ocsf_version, "1.1.0");
        assert!(v.supported_classes.contains(&1007));
        assert!(v.supported_classes.contains(&4003));
    }

    #[test]
    fn alert_to_ocsf_conversion() {
        let alert = crate::collector::AlertRecord {
            timestamp: "2026-04-01T00:00:00Z".into(),
            hostname: "my-host".into(),
            platform: "linux".into(),
            score: 5.5,
            confidence: 0.92,
            level: "critical".into(),
            action: "isolate".into(),
            reasons: vec!["auth_failures".into()],
            sample: crate::telemetry::TelemetrySample {
                timestamp_ms: 0,
                cpu_load_pct: 0.0,
                memory_load_pct: 0.0,
                temperature_c: 0.0,
                network_kbps: 0.0,
                auth_failures: 0,
                battery_pct: 100.0,
                integrity_drift: 0.0,
                process_count: 0,
                disk_pressure_pct: 0.0,
            },
            enforced: false,
            mitre: vec![crate::telemetry::MitreAttack {
                tactic: "Credential Access".into(),
                technique_id: "T1110".into(),
                technique_name: "Brute Force".into(),
            }],
            narrative: None,
        };
        let ocsf = alert_to_ocsf(&alert);
        assert_eq!(ocsf.class_uid, 2004);
        assert_eq!(ocsf.severity_id, 5);
        if let OcsfData::Detection(d) = &ocsf.data {
            assert_eq!(d.attacks.len(), 1);
            assert_eq!(d.attacks[0].technique_id, "T1110");
        } else {
            panic!("expected DetectionEvent");
        }
    }
}
