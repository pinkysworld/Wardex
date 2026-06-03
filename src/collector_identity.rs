//! Identity provider event collectors.
//!
//! Collects authentication and access events from identity providers:
//! - Okta System Log API
//! - Microsoft Entra ID (Graph API sign-in logs)
//!
//! Events are normalised to a common `IdentityEvent` format for
//! downstream UEBA and lateral-movement detection.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Common Types ──────────────────────────────────────────────────────────────

/// Provider type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityProvider {
    Okta,
    MicrosoftEntra,
}

impl std::fmt::Display for IdentityProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Okta => write!(f, "Okta"),
            Self::MicrosoftEntra => write!(f, "Microsoft Entra ID"),
        }
    }
}

/// Normalised identity event from any provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityEvent {
    /// Unique event ID from the provider.
    pub event_id: String,
    /// Which provider sourced this event.
    pub provider: IdentityProvider,
    /// Event type (e.g. "user.session.start", "signIn").
    pub event_type: String,
    /// Outcome: "SUCCESS", "FAILURE", "UNKNOWN".
    pub outcome: String,
    /// Timestamp as ISO-8601.
    pub timestamp: String,
    /// User principal / login.
    pub user_principal: Option<String>,
    /// Display name.
    pub user_display_name: Option<String>,
    /// Source IP address.
    pub source_ip: Option<String>,
    /// User agent / client application.
    pub user_agent: Option<String>,
    /// Geographic location.
    pub location: Option<String>,
    /// Target application / resource.
    pub target_app: Option<String>,
    /// MFA used.
    pub mfa_used: bool,
    /// Risk level from the provider ("low", "medium", "high", "none").
    pub provider_risk: Option<String>,
    /// Computed risk score (0.0-10.0).
    pub risk_score: f32,
    /// MITRE ATT&CK techniques.
    pub mitre_techniques: Vec<String>,
    /// Reason for failure (if applicable).
    pub failure_reason: Option<String>,
}

/// Result of an identity poll cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityPollResult {
    pub provider: IdentityProvider,
    pub events: Vec<IdentityEvent>,
    pub event_count: usize,
    pub success: bool,
    pub error: Option<String>,
    pub polled_at: String,
}

// ── Configuration ─────────────────────────────────────────────────────────────

/// Okta collector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OktaConfig {
    /// Okta org domain (e.g. "dev-123456.okta.com").
    pub domain: String,
    /// API token (SSWS).
    #[serde(skip_serializing)]
    pub api_token: String,
    /// Polling interval in seconds.
    pub poll_interval_secs: u64,
    /// Event types to collect (empty = all).
    pub event_type_filter: Vec<String>,
    pub enabled: bool,
}

impl Default for OktaConfig {
    fn default() -> Self {
        Self {
            domain: String::new(),
            api_token: String::new(),
            poll_interval_secs: 30,
            event_type_filter: vec![
                "user.session.start".into(),
                "user.authentication.sso".into(),
                "user.account.lock".into(),
                "user.mfa.factor.deactivate".into(),
                "policy.lifecycle.update".into(),
                "system.api_token.create".into(),
                "user.lifecycle.create".into(),
                "user.lifecycle.deactivate".into(),
                "application.lifecycle.create".into(),
            ],
            enabled: false,
        }
    }
}

/// Microsoft Entra ID collector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntraConfig {
    /// Azure AD tenant ID.
    pub tenant_id: String,
    /// Application (client) ID.
    pub client_id: String,
    /// Client secret.
    #[serde(skip_serializing)]
    pub client_secret: String,
    /// Polling interval in seconds.
    pub poll_interval_secs: u64,
    pub enabled: bool,
}

impl Default for EntraConfig {
    fn default() -> Self {
        Self {
            tenant_id: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            poll_interval_secs: 30,
            enabled: false,
        }
    }
}

// ── Risk Scoring ──────────────────────────────────────────────────────────────

fn score_identity_event(
    event_type: &str,
    outcome: &str,
    mfa_used: bool,
    provider_risk: Option<&str>,
) -> (f32, Vec<String>) {
    let is_failure = outcome == "FAILURE";
    let et_lower = event_type.to_lowercase();

    let mut base_score: f32;
    let mut techniques = Vec::new();

    // Login events
    if et_lower.contains("session.start")
        || et_lower.contains("signin")
        || et_lower.contains("authentication")
    {
        if is_failure {
            base_score = 4.0;
            techniques.push("T1078".into()); // Valid Accounts
            techniques.push("T1110".into()); // Brute Force
        } else if !mfa_used {
            base_score = 3.0;
            techniques.push("T1078".into());
        } else {
            base_score = 1.0;
            techniques.push("T1078".into());
        }
    }
    // Account lockout
    else if et_lower.contains("account.lock") {
        base_score = 6.0;
        techniques.push("T1110".into());
    }
    // MFA factor changes
    else if et_lower.contains("mfa.factor.deactivate") || et_lower.contains("mfa") {
        base_score = 7.0;
        techniques.push("T1556.006".into()); // MFA modification
    }
    // API token creation
    else if et_lower.contains("api_token.create") {
        base_score = 6.5;
        techniques.push("T1098.001".into()); // Additional Cloud Credentials
    }
    // User lifecycle
    else if et_lower.contains("lifecycle.create") && et_lower.contains("user") {
        base_score = 4.0;
        techniques.push("T1136".into()); // Create Account
    } else if et_lower.contains("lifecycle.deactivate") {
        base_score = 3.0;
        techniques.push("T1531".into()); // Account Access Removal
    }
    // Policy changes
    else if et_lower.contains("policy") {
        base_score = 5.0;
        techniques.push("T1562.001".into()); // Disable or Modify Tools
    }
    // Application changes
    else if et_lower.contains("application") {
        base_score = 4.0;
        techniques.push("T1098".into());
    }
    // Default
    else {
        base_score = 1.0;
    }

    // Boost based on provider risk assessment
    match provider_risk {
        Some("high") => base_score = (base_score + 2.0).min(10.0),
        Some("medium") => base_score = (base_score + 1.0).min(10.0),
        _ => {}
    }

    (base_score, techniques)
}

// ── Okta Collector ────────────────────────────────────────────────────────────

/// Okta System Log collector.
#[derive(Debug)]
pub struct OktaCollector {
    config: OktaConfig,
    /// Pagination cursor ("after" link).
    after_cursor: Option<String>,
    total_collected: u64,
    pending: Vec<IdentityEvent>,
}

impl OktaCollector {
    pub fn new(config: OktaConfig) -> Self {
        Self {
            config,
            after_cursor: None,
            total_collected: 0,
            pending: Vec::new(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled && !self.config.domain.is_empty() && !self.config.api_token.is_empty()
    }

    /// System Log API URL.
    pub fn build_url(&self) -> String {
        let mut url = format!(
            "https://{}/api/v1/logs?sortOrder=ASCENDING&limit=100",
            self.config.domain
        );
        if let Some(ref cursor) = self.after_cursor {
            url.push_str(&format!("&after={cursor}"));
        }
        url
    }

    /// Auth header value.
    pub fn auth_header(&self) -> String {
        format!("SSWS {}", self.config.api_token)
    }

    /// Parse Okta System Log JSON response.
    pub fn parse_response(
        &mut self,
        json_body: &str,
        next_link: Option<&str>,
    ) -> IdentityPollResult {
        let now = chrono::Utc::now().to_rfc3339();

        let parsed: Result<Vec<serde_json::Value>, _> = serde_json::from_str(json_body);
        let entries = match parsed {
            Ok(v) => v,
            Err(e) => {
                return IdentityPollResult {
                    provider: IdentityProvider::Okta,
                    events: Vec::new(),
                    event_count: 0,
                    success: false,
                    error: Some(format!("JSON parse error: {e}")),
                    polled_at: now,
                };
            }
        };

        // Extract cursor from next link
        if let Some(link) = next_link
            && let Some(after) = link.split("after=").nth(1)
        {
            let cursor = after.split('&').next().unwrap_or(after);
            self.after_cursor = Some(cursor.to_string());
        }

        let mut events = Vec::new();
        for entry in &entries {
            let event_type = entry
                .get("eventType")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();

            // Apply filter
            if !self.config.event_type_filter.is_empty()
                && !self
                    .config
                    .event_type_filter
                    .iter()
                    .any(|f| f == &event_type)
            {
                continue;
            }

            let outcome = entry
                .get("outcome")
                .and_then(|o| o.get("result"))
                .and_then(|v| v.as_str())
                .unwrap_or("UNKNOWN")
                .to_string();

            let provider_risk = entry
                .get("securityContext")
                .and_then(|s| s.get("riskLevel"))
                .and_then(|v| v.as_str())
                .map(str::to_lowercase);

            // Check for MFA
            let mfa_used = entry
                .get("authenticationContext")
                .and_then(|a| a.get("credentialType"))
                .and_then(|v| v.as_str())
                .is_some_and(|c| c.contains("MFA"));

            let (risk_score, mitre_techniques) =
                score_identity_event(&event_type, &outcome, mfa_used, provider_risk.as_deref());

            let actor = entry.get("actor");
            let client = entry.get("client");

            let event = IdentityEvent {
                event_id: entry
                    .get("uuid")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                provider: IdentityProvider::Okta,
                event_type,
                outcome: outcome.clone(),
                timestamp: entry
                    .get("published")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                user_principal: actor
                    .and_then(|a| a.get("alternateId"))
                    .and_then(|v| v.as_str())
                    .map(std::string::ToString::to_string),
                user_display_name: actor
                    .and_then(|a| a.get("displayName"))
                    .and_then(|v| v.as_str())
                    .map(std::string::ToString::to_string),
                source_ip: client
                    .and_then(|c| c.get("ipAddress"))
                    .and_then(|v| v.as_str())
                    .map(std::string::ToString::to_string),
                user_agent: client
                    .and_then(|c| c.get("userAgent"))
                    .and_then(|u| u.get("rawUserAgent"))
                    .and_then(|v| v.as_str())
                    .map(std::string::ToString::to_string),
                location: client
                    .and_then(|c| c.get("geographicalContext"))
                    .and_then(|g| g.get("country"))
                    .and_then(|v| v.as_str())
                    .map(std::string::ToString::to_string),
                target_app: entry
                    .get("target")
                    .and_then(|t| t.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|t| t.get("displayName"))
                    .and_then(|v| v.as_str())
                    .map(std::string::ToString::to_string),
                mfa_used,
                provider_risk,
                risk_score,
                mitre_techniques,
                failure_reason: if outcome == "FAILURE" {
                    entry
                        .get("outcome")
                        .and_then(|o| o.get("reason"))
                        .and_then(|v| v.as_str())
                        .map(std::string::ToString::to_string)
                } else {
                    None
                },
            };

            events.push(event);
        }

        let event_count = events.len();
        self.total_collected += event_count as u64;
        self.pending.extend(events.clone());

        IdentityPollResult {
            provider: IdentityProvider::Okta,
            events,
            event_count,
            success: true,
            error: None,
            polled_at: now,
        }
    }

    pub fn drain_pending(&mut self) -> Vec<IdentityEvent> {
        std::mem::take(&mut self.pending)
    }

    pub fn total_collected(&self) -> u64 {
        self.total_collected
    }
}

// ── Microsoft Entra ID Collector ──────────────────────────────────────────────

/// Microsoft Entra ID (Azure AD) sign-in log collector.
#[derive(Debug)]
pub struct EntraCollector {
    config: EntraConfig,
    access_token: Option<String>,
    token_expires_at: u64,
    last_seen: Option<String>,
    total_collected: u64,
    pending: Vec<IdentityEvent>,
}

impl EntraCollector {
    pub fn new(config: EntraConfig) -> Self {
        Self {
            config,
            access_token: None,
            token_expires_at: 0,
            last_seen: None,
            total_collected: 0,
            pending: Vec::new(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
            && !self.config.tenant_id.is_empty()
            && !self.config.client_id.is_empty()
    }

    pub fn set_token(&mut self, token: &str, expires_in_secs: u64) {
        self.access_token = Some(token.to_string());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.token_expires_at = now + expires_in_secs.saturating_sub(60);
    }

    pub fn token_valid(&self) -> bool {
        match &self.access_token {
            None => false,
            Some(_) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                now < self.token_expires_at
            }
        }
    }

    /// Token endpoint.
    pub fn token_endpoint(&self) -> String {
        format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.config.tenant_id
        )
    }

    /// Graph sign-in logs URL.
    pub fn build_url(&self) -> String {
        let mut url = "https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=100&$orderby=createdDateTime desc".to_string();
        if let Some(ref since) = self.last_seen {
            url.push_str(&format!("&$filter=createdDateTime ge {since}"));
        }
        url
    }

    /// Parse Microsoft Graph sign-in logs response.
    pub fn parse_response(&mut self, json_body: &str) -> IdentityPollResult {
        let now = chrono::Utc::now().to_rfc3339();

        let parsed: Result<serde_json::Value, _> = serde_json::from_str(json_body);
        let root = match parsed {
            Ok(v) => v,
            Err(e) => {
                return IdentityPollResult {
                    provider: IdentityProvider::MicrosoftEntra,
                    events: Vec::new(),
                    event_count: 0,
                    success: false,
                    error: Some(format!("JSON parse error: {e}")),
                    polled_at: now,
                };
            }
        };

        let entries = match root.get("value").and_then(|v| v.as_array()) {
            Some(arr) => arr,
            None => {
                return IdentityPollResult {
                    provider: IdentityProvider::MicrosoftEntra,
                    events: Vec::new(),
                    event_count: 0,
                    success: true,
                    error: None,
                    polled_at: now,
                };
            }
        };

        let mut events = Vec::new();
        for entry in entries {
            let status = entry.get("status");
            let error_code = status
                .and_then(|s| s.get("errorCode"))
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0);

            let outcome = if error_code == 0 {
                "SUCCESS"
            } else {
                "FAILURE"
            }
            .to_string();

            let mfa_detail = entry.get("mfaDetail");
            let mfa_used =
                mfa_detail.is_some() && mfa_detail.and_then(|m| m.get("authMethod")).is_some();

            let risk_level = entry
                .get("riskLevelDuringSignIn")
                .and_then(|v| v.as_str())
                .and_then(|r| if r == "none" { None } else { Some(r) })
                .map(std::string::ToString::to_string);

            let (risk_score, mitre_techniques) =
                score_identity_event("signIn", &outcome, mfa_used, risk_level.as_deref());

            let event = IdentityEvent {
                event_id: entry
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                provider: IdentityProvider::MicrosoftEntra,
                event_type: "signIn".to_string(),
                outcome,
                timestamp: entry
                    .get("createdDateTime")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                user_principal: entry
                    .get("userPrincipalName")
                    .and_then(|v| v.as_str())
                    .map(std::string::ToString::to_string),
                user_display_name: entry
                    .get("userDisplayName")
                    .and_then(|v| v.as_str())
                    .map(std::string::ToString::to_string),
                source_ip: entry
                    .get("ipAddress")
                    .and_then(|v| v.as_str())
                    .map(std::string::ToString::to_string),
                user_agent: entry
                    .get("clientAppUsed")
                    .and_then(|v| v.as_str())
                    .map(std::string::ToString::to_string),
                location: entry
                    .get("location")
                    .and_then(|l| l.get("countryOrRegion"))
                    .and_then(|v| v.as_str())
                    .map(std::string::ToString::to_string),
                target_app: entry
                    .get("appDisplayName")
                    .and_then(|v| v.as_str())
                    .map(std::string::ToString::to_string),
                mfa_used,
                provider_risk: risk_level,
                risk_score,
                mitre_techniques,
                failure_reason: if error_code != 0 {
                    status
                        .and_then(|s| s.get("failureReason"))
                        .and_then(|v| v.as_str())
                        .map(std::string::ToString::to_string)
                } else {
                    None
                },
            };

            events.push(event);
        }

        let event_count = events.len();
        self.total_collected += event_count as u64;

        if let Some(last) = events.last() {
            self.last_seen = Some(last.timestamp.clone());
        }

        self.pending.extend(events.clone());

        IdentityPollResult {
            provider: IdentityProvider::MicrosoftEntra,
            events,
            event_count,
            success: true,
            error: None,
            polled_at: now,
        }
    }

    pub fn drain_pending(&mut self) -> Vec<IdentityEvent> {
        std::mem::take(&mut self.pending)
    }

    pub fn total_collected(&self) -> u64 {
        self.total_collected
    }
}

// ── Unified identity summary ─────────────────────────────────────────────────

/// Aggregate statistics across all identity providers.
pub fn identity_summary(events: &[IdentityEvent]) -> HashMap<String, serde_json::Value> {
    let mut summary = HashMap::new();

    let total = events.len();
    let failures = events.iter().filter(|e| e.outcome == "FAILURE").count();
    let no_mfa = events
        .iter()
        .filter(|e| !e.mfa_used && e.outcome == "SUCCESS")
        .count();
    let high_risk = events.iter().filter(|e| e.risk_score >= 6.0).count();

    let mut by_provider: HashMap<String, usize> = HashMap::new();
    for e in events {
        *by_provider.entry(e.provider.to_string()).or_insert(0) += 1;
    }

    summary.insert("total_events".into(), serde_json::json!(total));
    summary.insert("total_failures".into(), serde_json::json!(failures));
    summary.insert("no_mfa_successes".into(), serde_json::json!(no_mfa));
    summary.insert("high_risk_events".into(), serde_json::json!(high_risk));
    summary.insert("by_provider".into(), serde_json::json!(by_provider));

    summary
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_okta_system_log() {
        let config = OktaConfig {
            domain: "dev-test.okta.com".into(),
            api_token: "test-token".into(),
            poll_interval_secs: 30,
            event_type_filter: vec![],
            enabled: true,
        };
        let mut collector = OktaCollector::new(config);

        let json = r#"[
            {
                "uuid": "evt-1",
                "eventType": "user.session.start",
                "published": "2026-04-01T10:00:00Z",
                "outcome": {"result": "SUCCESS"},
                "actor": {"alternateId": "admin@example.com", "displayName": "Admin User"},
                "client": {"ipAddress": "198.51.100.1", "userAgent": {"rawUserAgent": "Mozilla/5.0"}, "geographicalContext": {"country": "US"}},
                "target": [{"displayName": "Dashboard"}],
                "securityContext": {},
                "authenticationContext": {"credentialType": "PASSWORD"}
            },
            {
                "uuid": "evt-2",
                "eventType": "user.account.lock",
                "published": "2026-04-01T10:05:00Z",
                "outcome": {"result": "FAILURE", "reason": "Too many failed attempts"},
                "actor": {"alternateId": "user@example.com", "displayName": "Locked User"},
                "client": {"ipAddress": "198.51.100.2"},
                "securityContext": {"riskLevel": "HIGH"},
                "authenticationContext": {}
            }
        ]"#;

        let result = collector.parse_response(json, None);
        assert!(result.success);
        assert_eq!(result.event_count, 2);

        // Session start without MFA
        assert!(result.events[0].risk_score >= 1.0);
        assert!(!result.events[0].mfa_used);

        // Account lockout with high provider risk
        assert!(result.events[1].risk_score >= 6.0);
        assert!(result.events[1].mitre_techniques.contains(&"T1110".into()));
    }

    #[test]
    fn parse_entra_sign_in_logs() {
        let config = EntraConfig {
            tenant_id: "test-tenant".into(),
            client_id: "test-client".into(),
            client_secret: "test-secret".into(),
            poll_interval_secs: 30,
            enabled: true,
        };
        let mut collector = EntraCollector::new(config);

        let json = r#"{
            "value": [
                {
                    "id": "sign-1",
                    "createdDateTime": "2026-04-01T10:00:00Z",
                    "userPrincipalName": "admin@contoso.com",
                    "userDisplayName": "Admin",
                    "ipAddress": "198.51.100.1",
                    "clientAppUsed": "Browser",
                    "appDisplayName": "Azure Portal",
                    "status": {"errorCode": 0},
                    "location": {"countryOrRegion": "US"},
                    "riskLevelDuringSignIn": "none"
                },
                {
                    "id": "sign-2",
                    "createdDateTime": "2026-04-01T10:05:00Z",
                    "userPrincipalName": "attacker@contoso.com",
                    "ipAddress": "198.51.100.2",
                    "status": {"errorCode": 50126, "failureReason": "Invalid username or password"},
                    "riskLevelDuringSignIn": "high"
                }
            ]
        }"#;

        let result = collector.parse_response(json);
        assert!(result.success);
        assert_eq!(result.event_count, 2);

        // Successful login
        assert_eq!(result.events[0].outcome, "SUCCESS");

        // Failed login with high risk
        assert_eq!(result.events[1].outcome, "FAILURE");
        assert!(result.events[1].risk_score >= 6.0);
        assert!(result.events[1].failure_reason.is_some());
    }

    #[test]
    fn identity_event_scoring() {
        let (score, _) = score_identity_event("user.account.lock", "FAILURE", false, Some("high"));
        assert!(score >= 6.0);

        let (score, techniques) =
            score_identity_event("user.mfa.factor.deactivate", "SUCCESS", false, None);
        assert!(score >= 7.0);
        assert!(techniques.contains(&"T1556.006".to_string()));

        let (score, _) = score_identity_event("user.session.start", "SUCCESS", true, None);
        assert!(score <= 2.0); // MFA used, low risk
    }

    #[test]
    fn identity_summary_stats() {
        let events = vec![
            IdentityEvent {
                event_id: "1".into(),
                provider: IdentityProvider::Okta,
                event_type: "login".into(),
                outcome: "SUCCESS".into(),
                timestamp: "t".into(),
                user_principal: None,
                user_display_name: None,
                source_ip: None,
                user_agent: None,
                location: None,
                target_app: None,
                mfa_used: true,
                provider_risk: None,
                risk_score: 1.0,
                mitre_techniques: vec![],
                failure_reason: None,
            },
            IdentityEvent {
                event_id: "2".into(),
                provider: IdentityProvider::MicrosoftEntra,
                event_type: "signIn".into(),
                outcome: "FAILURE".into(),
                timestamp: "t".into(),
                user_principal: None,
                user_display_name: None,
                source_ip: None,
                user_agent: None,
                location: None,
                target_app: None,
                mfa_used: false,
                provider_risk: Some("high".into()),
                risk_score: 7.0,
                mitre_techniques: vec!["T1078".into()],
                failure_reason: Some("bad password".into()),
            },
        ];

        let summary = identity_summary(&events);
        assert_eq!(summary["total_events"], serde_json::json!(2));
        assert_eq!(summary["total_failures"], serde_json::json!(1));
        assert_eq!(summary["high_risk_events"], serde_json::json!(1));
    }

    #[test]
    fn okta_disabled() {
        let config = OktaConfig {
            enabled: false,
            ..OktaConfig::default()
        };
        let collector = OktaCollector::new(config);
        assert!(!collector.is_enabled());
    }

    #[test]
    fn entra_token_lifecycle() {
        let mut collector = EntraCollector::new(EntraConfig::default());
        assert!(!collector.token_valid());
        collector.set_token("tok", 3600);
        assert!(collector.token_valid());
    }

    #[test]
    fn okta_event_filter() {
        let config = OktaConfig {
            domain: "dev-test.okta.com".into(),
            api_token: "tok".into(),
            poll_interval_secs: 30,
            event_type_filter: vec!["user.session.start".into()],
            enabled: true,
        };
        let mut collector = OktaCollector::new(config);

        let json = r#"[
            {"uuid":"e1","eventType":"user.session.start","published":"t","outcome":{"result":"SUCCESS"},"actor":{},"client":{},"securityContext":{},"authenticationContext":{}},
            {"uuid":"e2","eventType":"user.lifecycle.create","published":"t","outcome":{"result":"SUCCESS"},"actor":{},"client":{},"securityContext":{},"authenticationContext":{}}
        ]"#;

        let result = collector.parse_response(json, None);
        assert_eq!(result.event_count, 1);
        assert_eq!(result.events[0].event_type, "user.session.start");
    }
}
