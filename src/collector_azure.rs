//! Azure Activity Log collector.
//!
//! Polls Azure Activity Log events via the Azure Monitor REST API.
//! Uses OAuth2 client-credential flow for authentication and normalises
//! events for downstream detection and correlation.

use serde::{Deserialize, Serialize};

// ── Configuration ─────────────────────────────────────────────────────────────

/// Azure collector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureCollectorConfig {
    /// Azure AD tenant ID.
    pub tenant_id: String,
    /// Application (client) ID.
    pub client_id: String,
    /// Client secret.
    #[serde(skip_serializing)]
    pub client_secret: String,
    /// Subscription ID to monitor.
    pub subscription_id: String,
    /// Polling interval in seconds.
    pub poll_interval_secs: u64,
    /// Event categories to collect (e.g. "Administrative", "Security", "Alert").
    pub categories: Vec<String>,
    /// Whether the collector is enabled.
    pub enabled: bool,
}

impl Default for AzureCollectorConfig {
    fn default() -> Self {
        Self {
            tenant_id: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            subscription_id: String::new(),
            poll_interval_secs: 60,
            categories: vec![
                "Administrative".into(),
                "Security".into(),
                "Alert".into(),
                "Policy".into(),
            ],
            enabled: false,
        }
    }
}

// ── Event Types ───────────────────────────────────────────────────────────────

/// A normalised Azure Activity event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzureActivityEvent {
    /// Unique event correlation ID.
    pub event_id: String,
    /// Operation name (e.g. "Microsoft.Compute/virtualMachines/write").
    pub operation_name: String,
    /// Event category.
    pub category: String,
    /// Result type (e.g. "Success", "Failure", "Start").
    pub result_type: String,
    /// Caller identity (UPN or service principal).
    pub caller: Option<String>,
    /// Timestamp as ISO-8601.
    pub timestamp: String,
    /// Resource ID.
    pub resource_id: Option<String>,
    /// Resource group.
    pub resource_group: Option<String>,
    /// Level (Critical, Error, Warning, Informational).
    pub level: String,
    /// Subscription ID.
    pub subscription_id: String,
    /// Source IP (if available from claims).
    pub source_ip: Option<String>,
    /// Risk assessment score (0.0-10.0).
    pub risk_score: f32,
    /// MITRE ATT&CK technique mappings.
    pub mitre_techniques: Vec<String>,
}

/// Result of an Azure poll cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AzurePollResult {
    pub events: Vec<AzureActivityEvent>,
    pub event_count: usize,
    pub success: bool,
    pub error: Option<String>,
    pub polled_at: String,
}

// ── Risk Scoring ──────────────────────────────────────────────────────────────

fn score_azure_event(operation: &str, result: &str, category: &str) -> (f32, Vec<String>) {
    let is_failure = result == "Failure";

    // Normalise operation to the resource type + action
    let op_lower = operation.to_lowercase();

    let (base_score, techniques) = if op_lower.contains("roleassignments/write") {
        (7.5, vec!["T1098".into()])
    } else if op_lower.contains("roleassignments/delete") {
        (6.0, vec!["T1531".into()])
    } else if op_lower.contains("networkSecurityGroups".to_lowercase().as_str())
        || op_lower.contains("networksecuritygroups")
    {
        (5.5, vec!["T1562.007".into()])
    } else if op_lower.contains("vault") && op_lower.contains("delete") {
        (8.5, vec!["T1485".into(), "T1490".into()])
    } else if op_lower.contains("diagnosticSettings".to_lowercase().as_str())
        || op_lower.contains("diagnosticsettings")
    {
        if op_lower.contains("delete") {
            (9.0, vec!["T1562.008".into()])
        } else {
            (3.0, vec![])
        }
    } else if op_lower.contains("policyassignments") {
        (5.0, vec!["T1562.001".into()])
    } else if op_lower.contains("virtualmachines") && op_lower.contains("write") {
        (3.5, vec!["T1578.002".into()])
    } else if op_lower.contains("virtualmachines") && op_lower.contains("delete") {
        (6.0, vec!["T1485".into()])
    } else if op_lower.contains("storageaccounts") && op_lower.contains("delete") {
        (7.0, vec!["T1485".into()])
    } else if category == "Security" || category == "Alert" {
        (5.0, vec![])
    } else {
        (1.0, vec![])
    };

    let score: f32 = if is_failure {
        (base_score + 1.5_f32).min(10.0)
    } else {
        base_score
    };
    (score, techniques)
}

// ── Collector ─────────────────────────────────────────────────────────────────

/// Azure Activity Log collector.
#[derive(Debug)]
pub struct AzureActivityCollector {
    config: AzureCollectorConfig,
    /// Cached OAuth2 access token.
    access_token: Option<String>,
    /// Token expiry (unix timestamp seconds).
    token_expires_at: u64,
    /// Last event timestamp for pagination.
    last_seen: Option<String>,
    /// Total events collected.
    total_collected: u64,
    /// Pending events.
    pending: Vec<AzureActivityEvent>,
}

impl AzureActivityCollector {
    pub fn new(config: AzureCollectorConfig) -> Self {
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

    /// Build the OAuth2 token request body.
    pub fn build_token_request(&self) -> String {
        format!(
            "grant_type=client_credentials&client_id={}&client_secret={}&resource=https%3A%2F%2Fmanagement.azure.com%2F",
            self.config.client_id, self.config.client_secret
        )
    }

    /// Token endpoint URL.
    pub fn token_endpoint(&self) -> String {
        format!(
            "https://login.microsoftonline.com/{}/oauth2/token",
            self.config.tenant_id
        )
    }

    /// Set the access token from a token response.
    pub fn set_token(&mut self, token: &str, expires_in_secs: u64) {
        self.access_token = Some(token.to_string());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // Subtract 60s for safety margin
        self.token_expires_at = now + expires_in_secs.saturating_sub(60);
    }

    /// Check if the current token is valid.
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

    /// Build the Activity Log query URL with OData filter.
    pub fn build_query_url(&self) -> String {
        let filter = if let Some(ref since) = self.last_seen {
            format!("eventTimestamp ge '{since}'")
        } else {
            // Default: last hour
            let since = chrono::Utc::now() - chrono::Duration::hours(1);
            format!("eventTimestamp ge '{}'", since.to_rfc3339())
        };

        format!(
            "https://management.azure.com/subscriptions/{}/providers/Microsoft.Insights/eventtypes/management/values?api-version=2015-04-01&$filter={}",
            self.config.subscription_id, filter
        )
    }

    /// Parse the Activity Log JSON response.
    pub fn parse_response(&mut self, json_body: &str) -> AzurePollResult {
        let now = chrono::Utc::now().to_rfc3339();

        let parsed: Result<serde_json::Value, _> = serde_json::from_str(json_body);
        let root = match parsed {
            Ok(v) => v,
            Err(e) => {
                return AzurePollResult {
                    events: Vec::new(),
                    event_count: 0,
                    success: false,
                    error: Some(format!("JSON parse error: {e}")),
                    polled_at: now,
                };
            }
        };

        let raw_events = match root.get("value").and_then(|v| v.as_array()) {
            Some(arr) => arr,
            None => {
                return AzurePollResult {
                    events: Vec::new(),
                    event_count: 0,
                    success: true,
                    error: None,
                    polled_at: now,
                };
            }
        };

        let mut events = Vec::new();
        for raw in raw_events {
            let category = raw
                .get("category")
                .and_then(|c| c.get("value"))
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
                .to_string();

            // Apply category filter
            if !self.config.categories.is_empty()
                && !self.config.categories.iter().any(|c| c == &category)
            {
                continue;
            }

            let operation_name = raw
                .get("operationName")
                .and_then(|o| o.get("value"))
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
                .to_string();

            let result_type = raw
                .get("status")
                .and_then(|s| s.get("value"))
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown")
                .to_string();

            let (risk_score, mitre_techniques) =
                score_azure_event(&operation_name, &result_type, &category);

            let event = AzureActivityEvent {
                event_id: raw
                    .get("correlationId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                operation_name,
                category,
                result_type,
                caller: raw
                    .get("caller")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                timestamp: raw
                    .get("eventTimestamp")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                resource_id: raw
                    .get("resourceId")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                resource_group: raw
                    .get("resourceGroupName")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                level: raw
                    .get("level")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Informational")
                    .to_string(),
                subscription_id: self.config.subscription_id.clone(),
                source_ip: raw
                    .get("claims")
                    .and_then(|c| c.get("ipaddr"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                risk_score,
                mitre_techniques,
            };

            events.push(event);
        }

        let event_count = events.len();
        self.total_collected += event_count as u64;

        if let Some(last) = events.last() {
            self.last_seen = Some(last.timestamp.clone());
        }

        self.pending.extend(events.clone());

        AzurePollResult {
            events,
            event_count,
            success: true,
            error: None,
            polled_at: now,
        }
    }

    /// Drain pending events.
    pub fn drain_pending(&mut self) -> Vec<AzureActivityEvent> {
        std::mem::take(&mut self.pending)
    }

    pub fn total_collected(&self) -> u64 {
        self.total_collected
    }

    pub fn config(&self) -> &AzureCollectorConfig {
        &self.config
    }

    /// Get high-risk events.
    pub fn high_risk_events(
        events: &[AzureActivityEvent],
        threshold: f32,
    ) -> Vec<&AzureActivityEvent> {
        events
            .iter()
            .filter(|e| e.risk_score >= threshold)
            .collect()
    }

    /// Authenticate with Azure AD and obtain an access token.
    pub fn authenticate(&mut self) -> Result<(), String> {
        if self.token_valid() {
            return Ok(());
        }

        let url = self.token_endpoint();
        let body = self.build_token_request();

        let resp: serde_json::Value = ureq::post(&url)
            .set("Content-Type", "application/x-www-form-urlencoded")
            .send_string(&body)
            .map_err(|e| format!("Azure AD auth failed: {e}"))?
            .into_json()
            .map_err(|e| format!("Azure AD token parse failed: {e}"))?;

        let token = resp
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or("No access_token in response")?;

        let expires_in = resp
            .get("expires_in")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(3600);

        self.set_token(token, expires_in);
        Ok(())
    }

    /// Poll Azure Activity Log via the Management REST API.
    pub fn poll(&mut self) -> AzurePollResult {
        let now = chrono::Utc::now().to_rfc3339();

        if !self.is_enabled() {
            return AzurePollResult {
                events: Vec::new(),
                event_count: 0,
                success: false,
                error: Some("Collector not enabled or not configured".into()),
                polled_at: now,
            };
        }

        // Authenticate if needed
        if let Err(e) = self.authenticate() {
            return AzurePollResult {
                events: Vec::new(),
                event_count: 0,
                success: false,
                error: Some(e),
                polled_at: now,
            };
        }

        let token = match &self.access_token {
            Some(t) => t.clone(),
            None => {
                return AzurePollResult {
                    events: Vec::new(),
                    event_count: 0,
                    success: false,
                    error: Some("No access token available".into()),
                    polled_at: now,
                };
            }
        };

        let url = self.build_query_url();
        let result = ureq::get(&url)
            .set("Authorization", &format!("Bearer {token}"))
            .call();

        match result {
            Ok(resp) => {
                let resp_body = resp.into_string()
                    .unwrap_or_default();
                self.parse_response(&resp_body)
            }
            Err(e) => AzurePollResult {
                events: Vec::new(),
                event_count: 0,
                success: false,
                error: Some(format!("Azure Activity Log API call failed: {e}")),
                polled_at: now,
            },
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> AzureCollectorConfig {
        AzureCollectorConfig {
            tenant_id: "test-tenant-id".into(),
            client_id: "test-client-id".into(),
            client_secret: "test-secret".into(),
            subscription_id: "sub-12345".into(),
            poll_interval_secs: 60,
            categories: vec![],
            enabled: true,
        }
    }

    #[test]
    fn parse_activity_log() {
        let mut collector = AzureActivityCollector::new(test_config());
        let json = r#"{
            "value": [
                {
                    "correlationId": "corr-1",
                    "operationName": {"value": "Microsoft.Authorization/roleAssignments/write", "localizedValue": "Create role assignment"},
                    "category": {"value": "Administrative"},
                    "status": {"value": "Success"},
                    "caller": "admin@contoso.com",
                    "eventTimestamp": "2026-04-01T10:00:00Z",
                    "resourceId": "/subscriptions/sub-12345/providers/Microsoft.Authorization/roleAssignments/ra-1",
                    "level": "Informational"
                },
                {
                    "correlationId": "corr-2",
                    "operationName": {"value": "Microsoft.Insights/diagnosticSettings/delete", "localizedValue": "Delete diagnostic setting"},
                    "category": {"value": "Administrative"},
                    "status": {"value": "Success"},
                    "caller": "attacker@contoso.com",
                    "eventTimestamp": "2026-04-01T10:05:00Z",
                    "level": "Warning"
                }
            ]
        }"#;

        let result = collector.parse_response(json);
        assert!(result.success);
        assert_eq!(result.event_count, 2);

        // Role assignment should be high risk
        assert!(result.events[0].risk_score >= 7.0);
        assert!(result.events[0].mitre_techniques.contains(&"T1098".into()));

        // Deleting diagnostic settings is defence evasion
        assert!(result.events[1].risk_score >= 9.0);
        assert!(
            result.events[1]
                .mitre_techniques
                .contains(&"T1562.008".into())
        );
    }

    #[test]
    fn token_lifecycle() {
        let mut collector = AzureActivityCollector::new(test_config());
        assert!(!collector.token_valid());

        collector.set_token("test-token", 3600);
        assert!(collector.token_valid());
    }

    #[test]
    fn category_filter() {
        let mut config = test_config();
        config.categories = vec!["Security".into()];
        let mut collector = AzureActivityCollector::new(config);

        let json = r#"{
            "value": [
                {
                    "correlationId": "c1",
                    "operationName": {"value": "op1"},
                    "category": {"value": "Administrative"},
                    "status": {"value": "Success"},
                    "eventTimestamp": "2026-04-01T10:00:00Z",
                    "level": "Informational"
                },
                {
                    "correlationId": "c2",
                    "operationName": {"value": "op2"},
                    "category": {"value": "Security"},
                    "status": {"value": "Success"},
                    "eventTimestamp": "2026-04-01T10:01:00Z",
                    "level": "Warning"
                }
            ]
        }"#;

        let result = collector.parse_response(json);
        assert_eq!(result.event_count, 1);
        assert_eq!(result.events[0].category, "Security");
    }

    #[test]
    fn disabled_collector() {
        let mut config = test_config();
        config.enabled = false;
        let collector = AzureActivityCollector::new(config);
        assert!(!collector.is_enabled());
    }

    #[test]
    fn drain_and_count() {
        let mut collector = AzureActivityCollector::new(test_config());
        let json = r#"{
            "value": [
                {"correlationId":"c1","operationName":{"value":"op1"},"category":{"value":"Administrative"},"status":{"value":"Success"},"eventTimestamp":"2026-04-01T10:00:00Z","level":"Informational"}
            ]
        }"#;
        collector.parse_response(json);
        assert_eq!(collector.total_collected(), 1);
        assert_eq!(collector.drain_pending().len(), 1);
        assert_eq!(collector.drain_pending().len(), 0);
    }
}
