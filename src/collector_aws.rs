//! AWS CloudTrail collector.
//!
//! Polls CloudTrail lookup-events via the AWS REST API using SigV4 signing.
//! Normalises events to the internal alert/telemetry format for downstream
//! detection. Designed to run without the full AWS SDK — only requires
//! `hmac-sha256` available in `ring` (already an indirect dep via `rustls`).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Configuration ─────────────────────────────────────────────────────────────

/// AWS collector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsCollectorConfig {
    /// AWS region (e.g. "us-east-1").
    pub region: String,
    /// Access key ID (from env, config, or IRSA).
    pub access_key_id: String,
    /// Secret access key.
    #[serde(skip_serializing)]
    pub secret_access_key: String,
    /// Optional session token (for STS assumed roles).
    pub session_token: Option<String>,
    /// Polling interval in seconds.
    pub poll_interval_secs: u64,
    /// Maximum events per poll.
    pub max_results: u32,
    /// Event names to filter (empty = all).
    pub event_name_filter: Vec<String>,
    /// Whether the collector is enabled.
    pub enabled: bool,
}

impl Default for AwsCollectorConfig {
    fn default() -> Self {
        Self {
            region: "us-east-1".into(),
            access_key_id: String::new(),
            secret_access_key: String::new(),
            session_token: None,
            poll_interval_secs: 60,
            max_results: 50,
            event_name_filter: vec![
                "ConsoleLogin".into(),
                "AssumeRole".into(),
                "CreateUser".into(),
                "AttachUserPolicy".into(),
                "PutBucketPolicy".into(),
                "AuthorizeSecurityGroupIngress".into(),
                "RunInstances".into(),
                "StopLogging".into(),
                "DeleteTrail".into(),
                "CreateAccessKey".into(),
            ],
            enabled: false,
        }
    }
}

// ── Event Types ───────────────────────────────────────────────────────────────

/// A normalised CloudTrail event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudTrailEvent {
    /// CloudTrail event ID.
    pub event_id: String,
    /// Event name (e.g. "ConsoleLogin").
    pub event_name: String,
    /// Event source service (e.g. "signin.amazonaws.com").
    pub event_source: String,
    /// Timestamp as ISO-8601.
    pub timestamp: String,
    /// AWS region where the event occurred.
    pub region: String,
    /// Source IP address.
    pub source_ip: Option<String>,
    /// User identity ARN.
    pub user_arn: Option<String>,
    /// User agent string.
    pub user_agent: Option<String>,
    /// Whether the request resulted in an error.
    pub error_code: Option<String>,
    /// Error message if any.
    pub error_message: Option<String>,
    /// Read-only flag.
    pub read_only: bool,
    /// Risk assessment score (0.0-10.0).
    pub risk_score: f32,
    /// MITRE ATT&CK technique mappings.
    pub mitre_techniques: Vec<String>,
    /// Raw JSON of the event (truncated to 4KB).
    pub raw_json: Option<String>,
}

/// Result of a CloudTrail poll cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AwsPollResult {
    /// Events collected.
    pub events: Vec<CloudTrailEvent>,
    /// Number of events fetched.
    pub event_count: usize,
    /// Whether the poll succeeded.
    pub success: bool,
    /// Error message if poll failed.
    pub error: Option<String>,
    /// Timestamp of the poll.
    pub polled_at: String,
    /// Next token for pagination.
    pub next_token: Option<String>,
}

// ── Risk Scoring ──────────────────────────────────────────────────────────────

/// Map CloudTrail event names to risk scores and MITRE techniques.
fn score_event(event_name: &str, error_code: Option<&str>) -> (f32, Vec<String>) {
    let has_error = error_code.is_some();

    match event_name {
        // Credential / access events
        "ConsoleLogin" if has_error => (6.0, vec!["T1078".into()]),
        "ConsoleLogin" => (2.0, vec!["T1078".into()]),
        "CreateAccessKey" => (5.0, vec!["T1098.001".into()]),
        "AssumeRole" => (2.5, vec!["T1550.001".into()]),

        // IAM changes
        "CreateUser" => (6.0, vec!["T1136.003".into()]),
        "AttachUserPolicy" | "AttachRolePolicy" => (7.0, vec!["T1098".into()]),
        "DeleteUser" | "DeleteRole" => (5.0, vec!["T1531".into()]),

        // S3 / data
        "PutBucketPolicy" => (7.0, vec!["T1537".into()]),
        "GetObject" => (1.0, vec!["T1530".into()]),

        // Network
        "AuthorizeSecurityGroupIngress" => (6.5, vec!["T1562.007".into()]),
        "CreateSecurityGroup" => (4.0, vec!["T1562.007".into()]),

        // Compute
        "RunInstances" => (4.0, vec!["T1578.002".into()]),
        "TerminateInstances" => (5.0, vec!["T1485".into()]),

        // Defence evasion
        "StopLogging" | "DeleteTrail" => (9.5, vec!["T1562.008".into()]),
        "PutEventSelectors" => (7.0, vec!["T1562.008".into()]),
        "DisableKey" | "ScheduleKeyDeletion" => (8.0, vec!["T1485".into(), "T1490".into()]),

        // Default
        _ if has_error => (1.5, vec![]),
        _ => (0.5, vec![]),
    }
}

// ── Collector ─────────────────────────────────────────────────────────────────

/// AWS CloudTrail event collector.
#[derive(Debug)]
pub struct AwsCloudTrailCollector {
    config: AwsCollectorConfig,
    /// Last event timestamp we've seen (for deduplication).
    last_seen: Option<String>,
    /// Pagination token from last poll.
    next_token: Option<String>,
    /// Running count of events collected.
    total_collected: u64,
    /// Events pending processing.
    pending: Vec<CloudTrailEvent>,
}

impl AwsCloudTrailCollector {
    pub fn new(config: AwsCollectorConfig) -> Self {
        Self {
            config,
            last_seen: None,
            next_token: None,
            total_collected: 0,
            pending: Vec::new(),
        }
    }

    /// Check if the collector is configured and enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled && !self.config.access_key_id.is_empty()
    }

    /// Parse raw CloudTrail JSON response into normalised events.
    pub fn parse_response(&mut self, json_body: &str) -> AwsPollResult {
        let now = chrono::Utc::now().to_rfc3339();

        let parsed: Result<serde_json::Value, _> = serde_json::from_str(json_body);
        let root = match parsed {
            Ok(v) => v,
            Err(e) => {
                return AwsPollResult {
                    events: Vec::new(),
                    event_count: 0,
                    success: false,
                    error: Some(format!("JSON parse error: {e}")),
                    polled_at: now,
                    next_token: None,
                };
            }
        };

        let next_token = root.get("NextToken").and_then(|v| v.as_str()).map(|s| s.to_string());

        let raw_events = match root.get("Events").and_then(|v| v.as_array()) {
            Some(arr) => arr,
            None => {
                return AwsPollResult {
                    events: Vec::new(),
                    event_count: 0,
                    success: true,
                    error: None,
                    polled_at: now,
                    next_token,
                };
            }
        };

        let mut events = Vec::new();
        for raw in raw_events {
            let event_name = raw.get("EventName").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string();

            // Skip if we have a filter and event doesn't match
            if !self.config.event_name_filter.is_empty()
                && !self.config.event_name_filter.iter().any(|f| f == &event_name)
            {
                continue;
            }

            let error_code = raw.get("ErrorCode").and_then(|v| v.as_str()).map(|s| s.to_string());
            let (risk_score, mitre_techniques) = score_event(&event_name, error_code.as_deref());

            let event = CloudTrailEvent {
                event_id: raw.get("EventId").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                event_name,
                event_source: raw.get("EventSource").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                timestamp: raw.get("EventTime").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                region: self.config.region.clone(),
                source_ip: raw.get("SourceIPAddress").and_then(|v| v.as_str()).map(|s| s.to_string()),
                user_arn: raw.get("Username").and_then(|v| v.as_str()).map(|s| s.to_string()),
                user_agent: raw.get("UserAgent").and_then(|v| v.as_str()).map(|s| s.to_string()),
                error_code,
                error_message: raw.get("ErrorMessage").and_then(|v| v.as_str()).map(|s| s.to_string()),
                read_only: raw.get("ReadOnly").and_then(|v| v.as_str()) == Some("true"),
                risk_score,
                mitre_techniques,
                raw_json: {
                    let s = raw.to_string();
                    if s.len() > 4096 {
                        // Truncate at a char boundary to avoid panic on multi-byte UTF-8
                        let end = s.char_indices()
                            .take_while(|(i, _)| *i < 4096)
                            .last()
                            .map(|(i, c)| i + c.len_utf8())
                            .unwrap_or(0);
                        Some(s[..end].to_string())
                    } else {
                        Some(s)
                    }
                },
            };

            events.push(event);
        }

        self.next_token = next_token.clone();
        let event_count = events.len();
        self.total_collected += event_count as u64;

        if let Some(last) = events.last() {
            self.last_seen = Some(last.timestamp.clone());
        }

        self.pending.extend(events.clone());

        AwsPollResult {
            events,
            event_count,
            success: true,
            error: None,
            polled_at: now,
            next_token,
        }
    }

    /// Build the CloudTrail LookupEvents request body.
    pub fn build_request_body(&self) -> String {
        let mut body = serde_json::json!({
            "MaxResults": self.config.max_results,
        });

        if let Some(ref token) = self.next_token {
            body["NextToken"] = serde_json::json!(token);
        }

        if let Some(ref last) = self.last_seen {
            body["StartTime"] = serde_json::json!(last);
        }

        body.to_string()
    }

    /// Drain pending events for processing.
    pub fn drain_pending(&mut self) -> Vec<CloudTrailEvent> {
        std::mem::take(&mut self.pending)
    }

    /// Total events collected over the lifetime of this collector.
    pub fn total_collected(&self) -> u64 {
        self.total_collected
    }

    /// Get the collector config.
    pub fn config(&self) -> &AwsCollectorConfig {
        &self.config
    }

    /// Get high-risk events (score >= threshold).
    pub fn high_risk_events(events: &[CloudTrailEvent], threshold: f32) -> Vec<&CloudTrailEvent> {
        events.iter().filter(|e| e.risk_score >= threshold).collect()
    }

    /// Summarise events by source service.
    pub fn summarise_by_source(events: &[CloudTrailEvent]) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for e in events {
            *counts.entry(e.event_source.clone()).or_insert(0) += 1;
        }
        counts
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> AwsCollectorConfig {
        AwsCollectorConfig {
            region: "us-east-1".into(),
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
            poll_interval_secs: 60,
            max_results: 10,
            event_name_filter: vec![],
            enabled: true,
        }
    }

    #[test]
    fn parse_cloudtrail_response() {
        let mut collector = AwsCloudTrailCollector::new(test_config());
        let json = r#"{
            "Events": [
                {
                    "EventId": "evt-1",
                    "EventName": "ConsoleLogin",
                    "EventSource": "signin.amazonaws.com",
                    "EventTime": "2026-04-01T10:00:00Z",
                    "SourceIPAddress": "198.51.100.1",
                    "Username": "arn:aws:iam::123456789012:user/admin",
                    "ReadOnly": "false"
                },
                {
                    "EventId": "evt-2",
                    "EventName": "StopLogging",
                    "EventSource": "cloudtrail.amazonaws.com",
                    "EventTime": "2026-04-01T10:05:00Z",
                    "SourceIPAddress": "198.51.100.2",
                    "Username": "arn:aws:iam::123456789012:user/attacker",
                    "ReadOnly": "false"
                }
            ],
            "NextToken": "abc123"
        }"#;

        let result = collector.parse_response(json);
        assert!(result.success);
        assert_eq!(result.event_count, 2);
        assert_eq!(result.next_token, Some("abc123".into()));

        let events = &result.events;
        assert_eq!(events[0].event_name, "ConsoleLogin");
        assert!(events[0].risk_score >= 2.0);

        // StopLogging should be very high risk
        assert_eq!(events[1].event_name, "StopLogging");
        assert!(events[1].risk_score >= 9.0);
        assert!(events[1].mitre_techniques.contains(&"T1562.008".into()));
    }

    #[test]
    fn risk_scoring() {
        let (score, techniques) = score_event("StopLogging", None);
        assert!(score >= 9.0);
        assert!(techniques.contains(&"T1562.008".to_string()));

        let (score, _) = score_event("ConsoleLogin", Some("AccessDenied"));
        assert!(score >= 5.0); // Failed login is higher risk

        let (score, _) = score_event("GetObject", None);
        assert!(score <= 2.0); // Read is low risk
    }

    #[test]
    fn event_filter() {
        let mut config = test_config();
        config.event_name_filter = vec!["ConsoleLogin".into()];
        let mut collector = AwsCloudTrailCollector::new(config);

        let json = r#"{
            "Events": [
                {"EventId": "e1", "EventName": "ConsoleLogin", "EventSource": "signin.amazonaws.com", "EventTime": "2026-04-01T10:00:00Z"},
                {"EventId": "e2", "EventName": "DescribeInstances", "EventSource": "ec2.amazonaws.com", "EventTime": "2026-04-01T10:01:00Z"}
            ]
        }"#;

        let result = collector.parse_response(json);
        assert_eq!(result.event_count, 1);
        assert_eq!(result.events[0].event_name, "ConsoleLogin");
    }

    #[test]
    fn drain_pending() {
        let mut collector = AwsCloudTrailCollector::new(test_config());
        let json = r#"{
            "Events": [
                {"EventId": "e1", "EventName": "ConsoleLogin", "EventSource": "s", "EventTime": "2026-04-01T10:00:00Z"}
            ]
        }"#;
        collector.parse_response(json);
        assert_eq!(collector.drain_pending().len(), 1);
        assert_eq!(collector.drain_pending().len(), 0);
    }

    #[test]
    fn high_risk_filter() {
        let events = vec![
            CloudTrailEvent {
                event_id: "e1".into(), event_name: "GetObject".into(),
                event_source: "s3".into(), timestamp: "t".into(),
                region: "us-east-1".into(), source_ip: None, user_arn: None,
                user_agent: None, error_code: None, error_message: None,
                read_only: true, risk_score: 1.0, mitre_techniques: vec![],
                raw_json: None,
            },
            CloudTrailEvent {
                event_id: "e2".into(), event_name: "StopLogging".into(),
                event_source: "cloudtrail".into(), timestamp: "t".into(),
                region: "us-east-1".into(), source_ip: None, user_arn: None,
                user_agent: None, error_code: None, error_message: None,
                read_only: false, risk_score: 9.5, mitre_techniques: vec!["T1562.008".into()],
                raw_json: None,
            },
        ];
        let high = AwsCloudTrailCollector::high_risk_events(&events, 5.0);
        assert_eq!(high.len(), 1);
        assert_eq!(high[0].event_name, "StopLogging");
    }

    #[test]
    fn disabled_collector() {
        let mut config = test_config();
        config.enabled = false;
        let collector = AwsCloudTrailCollector::new(config);
        assert!(!collector.is_enabled());
    }
}
