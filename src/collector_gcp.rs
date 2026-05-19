//! GCP Cloud Audit Log collector.
//!
//! Polls GCP Cloud Audit Logs via the Cloud Logging v2 REST API.
//! Uses service-account JWT-based authentication and normalises audit
//! events for downstream detection and correlation.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Configuration ─────────────────────────────────────────────────────────────

/// GCP collector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcpCollectorConfig {
    /// GCP project ID.
    pub project_id: String,
    /// Service account email.
    pub service_account_email: String,
    /// Path to the service account JSON key file (local only).
    pub key_file_path: Option<String>,
    /// Pre-loaded private key PEM (alternative to key_file_path).
    #[serde(skip_serializing)]
    pub private_key_pem: Option<String>,
    /// Polling interval in seconds.
    pub poll_interval_secs: u64,
    /// Log filter (Cloud Logging filter syntax).
    pub log_filter: String,
    /// Maximum entries per page.
    pub page_size: u32,
    /// Whether the collector is enabled.
    pub enabled: bool,
}

impl Default for GcpCollectorConfig {
    fn default() -> Self {
        Self {
            project_id: String::new(),
            service_account_email: String::new(),
            key_file_path: None,
            private_key_pem: None,
            poll_interval_secs: 60,
            log_filter: r#"logName:"cloudaudit.googleapis.com" AND (protoPayload.methodName:"SetIamPolicy" OR protoPayload.methodName:"CreateServiceAccount" OR protoPayload.methodName:"delete" OR protoPayload.methodName:"insert" OR protoPayload.methodName:"Stop" OR protoPayload.methodName:"setMetadata" OR severity>=WARNING)"#.into(),
            page_size: 100,
            enabled: false,
        }
    }
}

// ── Event Types ───────────────────────────────────────────────────────────────

/// A normalised GCP audit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcpAuditEvent {
    /// Log entry insert ID.
    pub insert_id: String,
    /// Method name (e.g. "google.iam.admin.v1.SetIamPolicy").
    pub method_name: String,
    /// Service name (e.g. "iam.googleapis.com").
    pub service_name: String,
    /// Resource name.
    pub resource_name: Option<String>,
    /// Resource type (e.g. "gce_instance", "gcs_bucket").
    pub resource_type: Option<String>,
    /// Timestamp as ISO-8601.
    pub timestamp: String,
    /// Caller IP.
    pub caller_ip: Option<String>,
    /// Principal email.
    pub principal_email: Option<String>,
    /// Severity level.
    pub severity: String,
    /// Status code (0 = OK).
    pub status_code: i32,
    /// Status message.
    pub status_message: Option<String>,
    /// Project ID.
    pub project_id: String,
    /// Risk assessment score (0.0-10.0).
    pub risk_score: f32,
    /// MITRE ATT&CK technique mappings.
    pub mitre_techniques: Vec<String>,
}

/// Result of a GCP poll cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcpPollResult {
    pub events: Vec<GcpAuditEvent>,
    pub event_count: usize,
    pub success: bool,
    pub error: Option<String>,
    pub polled_at: String,
    pub next_page_token: Option<String>,
}

// ── Risk Scoring ──────────────────────────────────────────────────────────────

fn score_gcp_event(method: &str, status_code: i32) -> (f32, Vec<String>) {
    let is_error = status_code != 0;
    let method_lower = method.to_lowercase();

    let (base_score, techniques) = if method_lower.contains("setiampolicy") {
        (7.5, vec!["T1098".into()])
    } else if method_lower.contains("createserviceaccount") {
        (6.0, vec!["T1136.003".into()])
    } else if method_lower.contains("createserviceaccountkey") {
        (7.0, vec!["T1098.001".into()])
    } else if method_lower.contains("deleteserviceaccount") {
        (5.0, vec!["T1531".into()])
    } else if method_lower.contains("setsinkdestination") || method_lower.contains("deletesink") {
        (9.0, vec!["T1562.008".into()])
    } else if method_lower.contains("delete") && method_lower.contains("bucket") {
        (7.0, vec!["T1485".into()])
    } else if method_lower.contains("insert") && method_lower.contains("firewall") {
        (6.0, vec!["T1562.007".into()])
    } else if method_lower.contains("delete") && method_lower.contains("firewall") {
        (6.5, vec!["T1562.007".into()])
    } else if method_lower.contains("insert") && method_lower.contains("instance") {
        (3.5, vec!["T1578.002".into()])
    } else if method_lower.contains("delete") && method_lower.contains("instance") {
        (5.0, vec!["T1485".into()])
    } else if method_lower.contains("stop") {
        (3.0, vec![])
    } else if method_lower.contains("setmetadata") {
        (4.0, vec!["T1525".into()])
    } else {
        (1.0, vec![])
    };

    let score: f32 = if is_error {
        (base_score + 1.0_f32).min(10.0)
    } else {
        base_score
    };
    (score, techniques)
}

// ── Collector ─────────────────────────────────────────────────────────────────

/// GCP Cloud Audit Log collector.
#[derive(Debug)]
pub struct GcpAuditCollector {
    config: GcpCollectorConfig,
    /// Cached access token.
    access_token: Option<String>,
    /// Token expiry.
    token_expires_at: u64,
    /// Last timestamp for deduplication.
    last_seen: Option<String>,
    /// Page token.
    next_page_token: Option<String>,
    /// Total events collected.
    total_collected: u64,
    /// Pending events.
    pending: Vec<GcpAuditEvent>,
}

impl GcpAuditCollector {
    pub fn new(config: GcpCollectorConfig) -> Self {
        Self {
            config,
            access_token: None,
            token_expires_at: 0,
            last_seen: None,
            next_page_token: None,
            total_collected: 0,
            pending: Vec::new(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled && !self.config.project_id.is_empty()
    }

    /// Set access token from a token response.
    pub fn set_token(&mut self, token: &str, expires_in_secs: u64) {
        self.access_token = Some(token.to_string());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.token_expires_at = now + expires_in_secs.saturating_sub(60);
    }

    pub fn token_valid(&self) -> bool {
        if self.access_token.is_none() {
            return false;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now < self.token_expires_at
    }

    /// Build the Cloud Logging entries.list request body.
    pub fn build_request_body(&self) -> String {
        let mut body = serde_json::json!({
            "resourceNames": [format!("projects/{}", self.config.project_id)],
            "filter": self.config.log_filter,
            "pageSize": self.config.page_size,
            "orderBy": "timestamp desc",
        });

        if let Some(ref token) = self.next_page_token {
            body["pageToken"] = serde_json::json!(token);
        }

        body.to_string()
    }

    /// Logging API endpoint.
    pub fn api_endpoint(&self) -> &str {
        "https://logging.googleapis.com/v2/entries:list"
    }

    /// Parse the Cloud Logging JSON response.
    pub fn parse_response(&mut self, json_body: &str) -> GcpPollResult {
        let now = chrono::Utc::now().to_rfc3339();

        let parsed: Result<serde_json::Value, _> = serde_json::from_str(json_body);
        let root = match parsed {
            Ok(v) => v,
            Err(e) => {
                return GcpPollResult {
                    events: Vec::new(),
                    event_count: 0,
                    success: false,
                    error: Some(format!("JSON parse error: {e}")),
                    polled_at: now,
                    next_page_token: None,
                };
            }
        };

        let next_page_token = root
            .get("nextPageToken")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let raw_entries = match root.get("entries").and_then(|v| v.as_array()) {
            Some(arr) => arr,
            None => {
                return GcpPollResult {
                    events: Vec::new(),
                    event_count: 0,
                    success: true,
                    error: None,
                    polled_at: now,
                    next_page_token,
                };
            }
        };

        let mut events = Vec::new();
        for entry in raw_entries {
            let proto = entry.get("protoPayload");

            let method_name = proto
                .and_then(|p| p.get("methodName"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();

            let service_name = proto
                .and_then(|p| p.get("serviceName"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let status_code = proto
                .and_then(|p| p.get("status"))
                .and_then(|s| s.get("code"))
                .and_then(|v| v.as_i64())
                .unwrap_or(0) as i32;

            let status_message = proto
                .and_then(|p| p.get("status"))
                .and_then(|s| s.get("message"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let (risk_score, mitre_techniques) = score_gcp_event(&method_name, status_code);

            let event = GcpAuditEvent {
                insert_id: entry
                    .get("insertId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                method_name,
                service_name,
                resource_name: entry
                    .get("resource")
                    .and_then(|r| r.get("labels"))
                    .and_then(|l| l.get("instance_id").or(l.get("bucket_name")))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                resource_type: entry
                    .get("resource")
                    .and_then(|r| r.get("type"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                timestamp: entry
                    .get("timestamp")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                caller_ip: proto
                    .and_then(|p| p.get("requestMetadata"))
                    .and_then(|r| r.get("callerIp"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                principal_email: proto
                    .and_then(|p| p.get("authenticationInfo"))
                    .and_then(|a| a.get("principalEmail"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                severity: entry
                    .get("severity")
                    .and_then(|v| v.as_str())
                    .unwrap_or("DEFAULT")
                    .to_string(),
                status_code,
                status_message,
                project_id: self.config.project_id.clone(),
                risk_score,
                mitre_techniques,
            };

            events.push(event);
        }

        self.next_page_token = next_page_token.clone();
        let event_count = events.len();
        self.total_collected += event_count as u64;

        if let Some(last) = events.last() {
            self.last_seen = Some(last.timestamp.clone());
        }

        self.pending.extend(events.clone());

        GcpPollResult {
            events,
            event_count,
            success: true,
            error: None,
            polled_at: now,
            next_page_token,
        }
    }

    /// Drain pending events.
    pub fn drain_pending(&mut self) -> Vec<GcpAuditEvent> {
        std::mem::take(&mut self.pending)
    }

    pub fn total_collected(&self) -> u64 {
        self.total_collected
    }

    pub fn config(&self) -> &GcpCollectorConfig {
        &self.config
    }

    /// Get high-risk events.
    pub fn high_risk_events(events: &[GcpAuditEvent], threshold: f32) -> Vec<&GcpAuditEvent> {
        events
            .iter()
            .filter(|e| e.risk_score >= threshold)
            .collect()
    }

    /// Summarise events by service.
    pub fn summarise_by_service(events: &[GcpAuditEvent]) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for e in events {
            *counts.entry(e.service_name.clone()).or_insert(0) += 1;
        }
        counts
    }

    /// Poll GCP Cloud Audit Logs via the Logging v2 REST API.
    pub fn poll(&mut self) -> GcpPollResult {
        let now = chrono::Utc::now().to_rfc3339();

        if !self.is_enabled() {
            return GcpPollResult {
                events: Vec::new(),
                event_count: 0,
                success: false,
                error: Some("Collector not enabled or not configured".into()),
                polled_at: now,
                next_page_token: None,
            };
        }

        // Authenticate if needed
        if !self.token_valid()
            && let Err(e) = self.authenticate()
        {
            return GcpPollResult {
                events: Vec::new(),
                event_count: 0,
                success: false,
                error: Some(e),
                polled_at: now,
                next_page_token: None,
            };
        }

        let token = match &self.access_token {
            Some(t) => t.clone(),
            None => {
                return GcpPollResult {
                    events: Vec::new(),
                    event_count: 0,
                    success: false,
                    error: Some("No access token available".into()),
                    polled_at: now,
                    next_page_token: None,
                };
            }
        };

        let endpoint = self.api_endpoint().to_string();
        let body = self.build_request_body();

        let result = ureq::post(&endpoint)
            .set("Authorization", &format!("Bearer {token}"))
            .set("Content-Type", "application/json")
            .send_string(&body);

        match result {
            Ok(resp) => {
                let resp_body = resp.into_string().unwrap_or_default();
                self.parse_response(&resp_body)
            }
            Err(e) => GcpPollResult {
                events: Vec::new(),
                event_count: 0,
                success: false,
                error: Some(format!("Cloud Logging API call failed: {e}")),
                polled_at: now,
                next_page_token: None,
            },
        }
    }

    /// Authenticate using a service account JWT to obtain an access token.
    fn authenticate(&mut self) -> Result<(), String> {
        let pem = if let Some(ref pem) = self.config.private_key_pem {
            pem.clone()
        } else if let Some(ref path) = self.config.key_file_path {
            let key_file: serde_json::Value = serde_json::from_str(
                &std::fs::read_to_string(path)
                    .map_err(|e| format!("Failed to read key file: {e}"))?,
            )
            .map_err(|e| format!("Failed to parse key file: {e}"))?;

            key_file
                .get("private_key")
                .and_then(|v| v.as_str())
                .ok_or("No private_key in key file")?
                .to_string()
        } else {
            return Err("No private key configured".into());
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let jwt = sign_service_account_jwt(&pem, &self.config.service_account_email, now)?;

        let resp: serde_json::Value = ureq::post("https://oauth2.googleapis.com/token")
            .set("Content-Type", "application/x-www-form-urlencoded")
            .send_string(&format!(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={}",
                jwt
            ))
            .map_err(|e| format!("GCP token request failed: {e}"))?
            .into_json()
            .map_err(|e| format!("GCP token parse failed: {e}"))?;

        let token = resp
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or("No access_token in GCP response")?;

        let expires_in = resp
            .get("expires_in")
            .and_then(|v| v.as_u64())
            .unwrap_or(3600);

        self.set_token(token, expires_in);
        Ok(())
    }
}

/// Claims for the service-account JWT assertion used in the OAuth2
/// jwt-bearer flow to obtain a Cloud Logging access token.
#[derive(Serialize)]
struct ServiceAccountClaims {
    iss: String,
    scope: String,
    aud: String,
    iat: u64,
    exp: u64,
}

/// Build and RS256-sign a service-account JWT assertion from a PEM private key.
fn sign_service_account_jwt(
    private_key_pem: &str,
    service_account_email: &str,
    now: u64,
) -> Result<String, String> {
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};

    let claims = ServiceAccountClaims {
        iss: service_account_email.to_string(),
        scope: "https://www.googleapis.com/auth/logging.read".to_string(),
        aud: "https://oauth2.googleapis.com/token".to_string(),
        iat: now,
        exp: now + 3600,
    };
    let key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
        .map_err(|e| format!("invalid service account private key: {e}"))?;
    encode(&Header::new(Algorithm::RS256), &claims, &key)
        .map_err(|e| format!("failed to sign service account JWT: {e}"))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> GcpCollectorConfig {
        GcpCollectorConfig {
            project_id: "my-project-123".into(),
            service_account_email: "sa@my-project-123.iam.gserviceaccount.com".into(),
            key_file_path: None,
            private_key_pem: None,
            poll_interval_secs: 60,
            log_filter: String::new(),
            page_size: 50,
            enabled: true,
        }
    }

    #[test]
    fn parse_audit_log_response() {
        let mut collector = GcpAuditCollector::new(test_config());
        let json = r#"{
            "entries": [
                {
                    "insertId": "entry-1",
                    "timestamp": "2026-04-01T10:00:00Z",
                    "severity": "NOTICE",
                    "resource": {"type": "gce_instance", "labels": {"instance_id": "inst-123"}},
                    "protoPayload": {
                        "methodName": "v1.compute.instances.insert",
                        "serviceName": "compute.googleapis.com",
                        "authenticationInfo": {"principalEmail": "admin@example.com"},
                        "requestMetadata": {"callerIp": "198.51.100.1"},
                        "status": {"code": 0}
                    }
                },
                {
                    "insertId": "entry-2",
                    "timestamp": "2026-04-01T10:05:00Z",
                    "severity": "WARNING",
                    "resource": {"type": "logging_sink"},
                    "protoPayload": {
                        "methodName": "google.logging.v2.ConfigServiceV2.DeleteSink",
                        "serviceName": "logging.googleapis.com",
                        "authenticationInfo": {"principalEmail": "attacker@example.com"},
                        "requestMetadata": {"callerIp": "198.51.100.2"},
                        "status": {"code": 0}
                    }
                }
            ],
            "nextPageToken": "page2"
        }"#;

        let result = collector.parse_response(json);
        assert!(result.success);
        assert_eq!(result.event_count, 2);
        assert_eq!(result.next_page_token, Some("page2".into()));

        // Instance insert: moderate risk
        assert!(result.events[0].risk_score >= 3.0);

        // DeleteSink: very high risk (defence evasion)
        assert!(result.events[1].risk_score >= 9.0);
        assert!(
            result.events[1]
                .mitre_techniques
                .contains(&"T1562.008".into())
        );
    }

    #[test]
    fn risk_scoring() {
        let (score, techniques) =
            score_gcp_event("google.logging.v2.ConfigServiceV2.DeleteSink", 0);
        assert!(score >= 9.0);
        assert!(techniques.contains(&"T1562.008".to_string()));

        let (score, _) = score_gcp_event("google.iam.admin.v1.SetIamPolicy", 0);
        assert!(score >= 7.0);

        let (score, _) = score_gcp_event("v1.compute.instances.get", 0);
        assert!(score <= 2.0);
    }

    #[test]
    fn token_lifecycle() {
        let mut collector = GcpAuditCollector::new(test_config());
        assert!(!collector.token_valid());
        collector.set_token("test-token", 3600);
        assert!(collector.token_valid());
    }

    #[test]
    fn drain_pending() {
        let mut collector = GcpAuditCollector::new(test_config());
        let json = r#"{
            "entries": [
                {"insertId":"e1","timestamp":"t","severity":"INFO","protoPayload":{"methodName":"m","serviceName":"s","status":{"code":0}}}
            ]
        }"#;
        collector.parse_response(json);
        assert_eq!(collector.drain_pending().len(), 1);
        assert_eq!(collector.drain_pending().len(), 0);
    }

    #[test]
    fn disabled_collector() {
        let mut config = test_config();
        config.enabled = false;
        let collector = GcpAuditCollector::new(config);
        assert!(!collector.is_enabled());
    }

    #[test]
    fn empty_response() {
        let mut collector = GcpAuditCollector::new(test_config());
        let result = collector.parse_response(r#"{"entries": []}"#);
        assert!(result.success);
        assert_eq!(result.event_count, 0);
    }

    // Throwaway 2048-bit RSA key for signing tests only — never used in production.
    const TEST_RSA_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC84GY7mGFHbdaD\n\
jc1FYO6uHVAyyYDCJxftjealIymIAus9XqWCB3UfVxjJec0qwD4FQfM6eljNORue\n\
rClWL93ChWgoxHjgVwC73E8w6Y5WjS2LgppXAJxBxg4/TehJgW6qS4y3l0vtbS6G\n\
AErjbV+qsOlfaXD5ybghyif2ENDxgpRfivQFNAz0shHNU1BD9GjLinZ57qEfsj8/\n\
05aeeeoq7pUav3BzieoxGRbHR1S2tuX+c60FPqdsP7SK+K4oAFyERJYX8YKFKe+G\n\
nSk/2GPKWSr4a8dT8989uKSovH5S/GAmW4hDHNSegrKOF3hFchvI2miyc4fOX5W9\n\
QOH7EXTvAgMBAAECggEAGo5YgW+S2eatHxEMeAFBfdScRo/DXUj+2cU2VSik+b0j\n\
Ux0gGzCuPIpT71wDR0wBTF7x8lpqauxpID2nkDkprmRweS7qqexBq6g1sDRecXfn\n\
G/LwfWQWFD9jGG59Rvx+UU5PCi8pG0hbHrci0Gg757V5EpOyMUS18XZJeRTzM8mA\n\
hr9YDs4XUx/Nwg/4OP9RgENJKETxmtzQF27nCWLZFYcdJ8AYfQJlnKJ7N3Ql0p5g\n\
JDmshfcwx9VjSWZ5RjPmEU6IKrvfPSY01veMBIzx1GaCuS2RZM4VMBn3IpFgWJCi\n\
2Q/yUA4Q9ryC1i7MJDQbfAyej9yV5D7s1FdmgDGfLQKBgQD4IbdxMk4xkFKMMEJo\n\
b80jU/hIOImAkhUXz9SwdMMw5nzlxFfLobeSq9P56q3LRrU1h/SZ0WCEv/1lSFpu\n\
iwRhfhbckPdgusP/iH1BeR4XPo2VWx/SN7DNLyeBwmdNQwVqG7Iyyc1gtYjQex1w\n\
+AybA7evp4+qTWCBK4i1SbRgbQKBgQDC3alQrDFoSLZYSloP9g+A7s3/ibkzLDYf\n\
6mB8OJSbnPsTwqpeypn33YED+HgbaYce1tKflStV6qrSwn4rQf4SE+Z6TR6OKzUG\n\
7BG8oK5QdCu8S8oLoajLreFZ5NUMVfZzFZJchEKMILjULXafhYKEMmL67cUopVOs\n\
5GSmx47pSwKBgE/uzKFyiy38SBtREJOEMJlI25qoW+NHK/RXxzRw6NA/78w0y/OV\n\
TQW6xLalmwb46DcubOWARY9+KasO+9LQhcDCVasIKCjJAYq39WG6Gq9yPzn1+PJH\n\
bnUq05dBgPWquXvNIEKsL7UPxdsjTgCuZ6EoOWwklmtOMeBqnceIzsqhAoGBAIXb\n\
tIJJNstXH4M41/Mc6Pt9j55ZIhJH7Yow+0R5rYPT6xlg4J2q+OcujoCGvyK9c+c4\n\
VIjw9ErZn6yVlAvtEjWi2/DpZvLsNUnjAjAcBIIZuy1mto0U6Jm5gRK6QatupZPa\n\
nqbU583QcIa4EEN2d/iNkDak/Il2QCuE3KtAbChPAoGASot/+5jyeobrn9kROPU7\n\
X7e31rJLM9nBjQ9jyQD67leZFDYuE9NNdbt0ClEe5wVVm19CJFDFbw9qNdxuNlT9\n\
HgPodx7ZsVpEIYzm1lrL6HI5zsdEGvW2p9Ssg2GXZWCC/2QMTdIn8/Cl7VErdWwu\n\
PkuO1vaopMZbRmtehDfFSXA=\n\
-----END PRIVATE KEY-----\n";

    #[test]
    fn signs_service_account_jwt() {
        let jwt = sign_service_account_jwt(TEST_RSA_PEM, "sa@example.iam.gserviceaccount.com", 1_700_000_000)
            .expect("signing should succeed with a valid RSA key");
        let segments: Vec<&str> = jwt.split('.').collect();
        assert_eq!(segments.len(), 3, "JWT must have header.claims.signature");
        assert!(!segments[2].is_empty(), "signature segment must not be empty");

        use base64::Engine;
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(segments[0])
            .expect("header must be base64url");
        let header: serde_json::Value = serde_json::from_slice(&header).unwrap();
        assert_eq!(header["alg"], "RS256");
    }

    #[test]
    fn rejects_invalid_private_key() {
        let result = sign_service_account_jwt("not-a-pem-key", "sa@example.com", 1_700_000_000);
        assert!(result.is_err());
    }
}
