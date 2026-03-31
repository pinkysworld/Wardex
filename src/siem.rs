use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::collector::AlertRecord;

/// SIEM integration configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemConfig {
    /// Enable SIEM integration.
    #[serde(default)]
    pub enabled: bool,
    /// SIEM type: "splunk", "elastic", "sentinel", "qradar", "generic".
    #[serde(default = "default_siem_type")]
    pub siem_type: String,
    /// SIEM endpoint URL (e.g., HEC endpoint for Splunk, Elasticsearch bulk API).
    #[serde(default)]
    pub endpoint: String,
    /// Authentication token or API key.
    #[serde(default)]
    pub auth_token: String,
    /// Custom index or data stream name.
    #[serde(default = "default_index")]
    pub index: String,
    /// Source type label for the SIEM.
    #[serde(default = "default_source_type")]
    pub source_type: String,
    /// Poll interval in seconds for pulling events from SIEM.
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,
    /// Enable pulling threat intel / saved searches from SIEM.
    #[serde(default)]
    pub pull_enabled: bool,
    /// Saved search or query name for pulling.
    #[serde(default)]
    pub pull_query: String,
    /// Batch size for pushing events.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    /// Enable TLS verification (set false for self-signed certs in lab).
    #[serde(default = "default_verify_tls")]
    pub verify_tls: bool,
}

fn default_siem_type() -> String {
    "generic".into()
}
fn default_index() -> String {
    "wardex".into()
}
fn default_source_type() -> String {
    "wardex:xdr".into()
}
fn default_poll_interval() -> u64 {
    60
}
fn default_batch_size() -> usize {
    50
}
fn default_verify_tls() -> bool {
    true
}

impl Default for SiemConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            siem_type: default_siem_type(),
            endpoint: String::new(),
            auth_token: String::new(),
            index: default_index(),
            source_type: default_source_type(),
            poll_interval_secs: default_poll_interval(),
            pull_enabled: false,
            pull_query: String::new(),
            batch_size: default_batch_size(),
            verify_tls: default_verify_tls(),
        }
    }
}

impl SiemConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.enabled && self.endpoint.is_empty() {
            return Err("siem.endpoint must be set when SIEM is enabled".into());
        }
        if self.poll_interval_secs == 0 {
            return Err("siem.poll_interval_secs must be >= 1".into());
        }
        if self.batch_size == 0 {
            return Err("siem.batch_size must be >= 1".into());
        }
        Ok(())
    }
}

/// SIEM connector that pushes alerts and optionally pulls threat intel.
pub struct SiemConnector {
    config: SiemConfig,
    pending: Vec<AlertRecord>,
    push_count: u64,
    pull_count: u64,
    last_error: Option<String>,
}

impl SiemConnector {
    pub fn new(config: SiemConfig) -> Self {
        Self {
            config,
            pending: Vec::new(),
            push_count: 0,
            pull_count: 0,
            last_error: None,
        }
    }

    /// Queue an alert for batch pushing to SIEM.
    pub fn queue_alert(&mut self, alert: &AlertRecord) {
        self.pending.push(alert.clone());
        if self.pending.len() >= self.config.batch_size {
            if let Err(e) = self.flush() {
                self.last_error = Some(e);
            }
        }
    }

    /// Flush all pending alerts to the SIEM.
    pub fn flush(&mut self) -> Result<usize, String> {
        if self.pending.is_empty() {
            return Ok(0);
        }
        if !self.config.enabled {
            self.pending.clear();
            return Ok(0);
        }

        let count = self.pending.len();
        let payload = self.format_batch(&self.pending.clone())?;

        self.send_to_siem(&payload)?;
        self.push_count += count as u64;
        self.pending.clear();
        self.last_error = None;

        Ok(count)
    }

    /// Pull threat intelligence or saved search results from the SIEM.
    pub fn pull_intel(&mut self) -> Result<Vec<SiemIntelRecord>, String> {
        if !self.config.enabled || !self.config.pull_enabled {
            return Ok(Vec::new());
        }

        let url = match self.config.siem_type.as_str() {
            "splunk" => format!(
                "{}/services/search/jobs/export?search={}&output_mode=json",
                self.config.endpoint,
                urlencoding(&self.config.pull_query),
            ),
            "elastic" => format!(
                "{}/_search",
                self.config.endpoint,
            ),
            _ => format!(
                "{}/api/search?q={}",
                self.config.endpoint,
                urlencoding(&self.config.pull_query),
            ),
        };

        let resp = ureq::get(&url)
            .set("Authorization", &format!("Bearer {}", self.config.auth_token))
            .call()
            .map_err(|e| format!("SIEM pull failed: {e}"))?;

        if resp.status() != 200 {
            return Err(format!("SIEM pull returned status {}", resp.status()));
        }

        let body = resp.into_string()
            .map_err(|e| format!("failed to read SIEM response: {e}"))?;

        let records = self.parse_intel_response(&body)?;
        self.pull_count += records.len() as u64;
        Ok(records)
    }

    /// Get connector status.
    pub fn status(&self) -> SiemStatus {
        SiemStatus {
            enabled: self.config.enabled,
            siem_type: self.config.siem_type.clone(),
            endpoint: self.config.endpoint.clone(),
            pending_events: self.pending.len(),
            total_pushed: self.push_count,
            total_pulled: self.pull_count,
            last_error: self.last_error.clone(),
            pull_enabled: self.config.pull_enabled,
        }
    }

    fn format_batch(&self, alerts: &[AlertRecord]) -> Result<String, String> {
        match self.config.siem_type.as_str() {
            "splunk" => self.format_splunk_hec(alerts),
            "elastic" => self.format_elastic_bulk(alerts),
            _ => self.format_generic_json(alerts),
        }
    }

    /// Splunk HTTP Event Collector (HEC) format.
    fn format_splunk_hec(&self, alerts: &[AlertRecord]) -> Result<String, String> {
        let mut lines = Vec::new();
        for alert in alerts {
            let event = serde_json::json!({
                "event": alert,
                "sourcetype": self.config.source_type,
                "index": self.config.index,
                "time": parse_epoch(&alert.timestamp),
            });
            lines.push(serde_json::to_string(&event)
                .map_err(|e| format!("JSON error: {e}"))?);
        }
        Ok(lines.join("\n"))
    }

    /// Elasticsearch bulk API format.
    fn format_elastic_bulk(&self, alerts: &[AlertRecord]) -> Result<String, String> {
        let mut lines = Vec::new();
        for alert in alerts {
            let action = serde_json::json!({
                "index": { "_index": self.config.index }
            });
            lines.push(serde_json::to_string(&action)
                .map_err(|e| format!("JSON error: {e}"))?);
            lines.push(serde_json::to_string(alert)
                .map_err(|e| format!("JSON error: {e}"))?);
        }
        // Elasticsearch bulk API requires trailing newline
        let mut result = lines.join("\n");
        result.push('\n');
        Ok(result)
    }

    /// Generic JSON array format.
    fn format_generic_json(&self, alerts: &[AlertRecord]) -> Result<String, String> {
        serde_json::to_string(alerts)
            .map_err(|e| format!("JSON error: {e}"))
    }

    fn send_to_siem(&self, payload: &str) -> Result<(), String> {
        let content_type = match self.config.siem_type.as_str() {
            "elastic" => "application/x-ndjson",
            _ => "application/json",
        };

        let auth_header = match self.config.siem_type.as_str() {
            "splunk" => format!("Splunk {}", self.config.auth_token),
            _ => format!("Bearer {}", self.config.auth_token),
        };

        let resp = ureq::post(&self.config.endpoint)
            .set("Content-Type", content_type)
            .set("Authorization", &auth_header)
            .send_string(payload)
            .map_err(|e| format!("SIEM send failed: {e}"))?;

        if resp.status() >= 400 {
            return Err(format!("SIEM returned error status: {}", resp.status()));
        }

        Ok(())
    }

    fn parse_intel_response(&self, body: &str) -> Result<Vec<SiemIntelRecord>, String> {
        // Try to parse as JSON array of records
        if let Ok(records) = serde_json::from_str::<Vec<SiemIntelRecord>>(body) {
            return Ok(records);
        }

        // Try Splunk-style results wrapper
        #[derive(Deserialize)]
        struct SplunkResults {
            results: Option<Vec<SiemIntelRecord>>,
        }
        if let Ok(wrapper) = serde_json::from_str::<SplunkResults>(body) {
            if let Some(results) = wrapper.results {
                return Ok(results);
            }
        }

        // Try Elasticsearch-style hits wrapper
        #[derive(Deserialize)]
        struct EsHits {
            hits: Option<EsHitsInner>,
        }
        #[derive(Deserialize)]
        struct EsHitsInner {
            hits: Option<Vec<EsHit>>,
        }
        #[derive(Deserialize)]
        struct EsHit {
            _source: Option<SiemIntelRecord>,
        }
        if let Ok(wrapper) = serde_json::from_str::<EsHits>(body) {
            if let Some(hits) = wrapper.hits.and_then(|h| h.hits) {
                return Ok(hits.into_iter().filter_map(|h| h._source).collect());
            }
        }

        Ok(Vec::new())
    }
}

/// A threat intelligence record pulled from a SIEM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemIntelRecord {
    #[serde(default)]
    pub indicator_type: String,
    #[serde(default)]
    pub indicator_value: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub description: String,
}

/// Status of the SIEM connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemStatus {
    pub enabled: bool,
    pub siem_type: String,
    pub endpoint: String,
    pub pending_events: usize,
    pub total_pushed: u64,
    pub total_pulled: u64,
    pub last_error: Option<String>,
    pub pull_enabled: bool,
}

/// Run SIEM polling loop in background (when pull_enabled is true).
pub fn start_siem_poller(
    config: SiemConfig,
    shutdown: Arc<AtomicBool>,
) -> Option<thread::JoinHandle<()>> {
    if !config.enabled || !config.pull_enabled {
        return None;
    }

    let interval = Duration::from_secs(config.poll_interval_secs);

    Some(thread::spawn(move || {
        let mut connector = SiemConnector::new(config);
        loop {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
            thread::sleep(interval);
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
            match connector.pull_intel() {
                Ok(records) if !records.is_empty() => {
                    eprintln!("[siem] Pulled {} intel records", records.len());
                    for record in &records {
                        eprintln!(
                            "[siem]   {} = {} ({})",
                            record.indicator_type, record.indicator_value, record.severity
                        );
                    }
                }
                Err(e) => eprintln!("[siem] Pull error: {e}"),
                _ => {}
            }
        }
    }))
}

fn parse_epoch(timestamp: &str) -> f64 {
    chrono::DateTime::parse_from_rfc3339(timestamp)
        .map(|dt| dt.timestamp() as f64)
        .unwrap_or(0.0)
}

fn urlencoding(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{:02X}", b),
        })
        .collect()
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::TelemetrySample;

    fn make_alert() -> AlertRecord {
        AlertRecord {
            timestamp: chrono::Utc::now().to_rfc3339(),
            hostname: "test-host".into(),
            platform: "linux".into(),
            score: 5.5,
            confidence: 0.92,
            level: "critical".into(),
            action: "isolate".into(),
            reasons: vec!["high_cpu".into(), "auth_failures".into()],
            sample: TelemetrySample {
                timestamp_ms: 0, cpu_load_pct: 0.0, memory_load_pct: 0.0,
                temperature_c: 0.0, network_kbps: 0.0, auth_failures: 0,
                battery_pct: 100.0, integrity_drift: 0.0,
                process_count: 0, disk_pressure_pct: 0.0,
            },
            enforced: false,
        }
    }

    #[test]
    fn config_defaults() {
        let config = SiemConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.siem_type, "generic");
        assert_eq!(config.poll_interval_secs, 60);
        assert_eq!(config.batch_size, 50);
    }

    #[test]
    fn config_validation() {
        let mut config = SiemConfig::default();
        config.enabled = true;
        assert!(config.validate().is_err()); // no endpoint

        config.endpoint = "http://localhost:8088".into();
        assert!(config.validate().is_ok());

        config.poll_interval_secs = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn queue_and_status() {
        let config = SiemConfig::default();
        let mut connector = SiemConnector::new(config);
        assert_eq!(connector.status().pending_events, 0);

        connector.queue_alert(&make_alert());
        assert_eq!(connector.status().pending_events, 1);
    }

    #[test]
    fn flush_when_disabled_clears_queue() {
        let config = SiemConfig::default(); // enabled = false
        let mut connector = SiemConnector::new(config);
        connector.queue_alert(&make_alert());
        connector.queue_alert(&make_alert());
        let flushed = connector.flush().unwrap();
        assert_eq!(flushed, 0);
        assert_eq!(connector.status().pending_events, 0);
    }

    #[test]
    fn splunk_hec_format() {
        let config = SiemConfig {
            siem_type: "splunk".into(),
            index: "main".into(),
            source_type: "wardex:xdr".into(),
            ..Default::default()
        };
        let connector = SiemConnector::new(config);
        let alerts = vec![make_alert()];
        let payload = connector.format_splunk_hec(&alerts).unwrap();
        assert!(payload.contains("sourcetype"));
        assert!(payload.contains("wardex:xdr"));
    }

    #[test]
    fn elastic_bulk_format() {
        let config = SiemConfig {
            siem_type: "elastic".into(),
            index: "wardex-events".into(),
            ..Default::default()
        };
        let connector = SiemConnector::new(config);
        let alerts = vec![make_alert()];
        let payload = connector.format_elastic_bulk(&alerts).unwrap();
        assert!(payload.contains("wardex-events"));
        assert!(payload.ends_with('\n'));
    }

    #[test]
    fn generic_json_format() {
        let config = SiemConfig::default();
        let connector = SiemConnector::new(config);
        let alerts = vec![make_alert(), make_alert()];
        let payload = connector.format_generic_json(&alerts).unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&payload).unwrap();
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn intel_record_deserialize() {
        let json = r#"{"indicator_type":"ip","indicator_value":"1.2.3.4","severity":"high","source":"SIEM","description":"C2 server"}"#;
        let record: SiemIntelRecord = serde_json::from_str(json).unwrap();
        assert_eq!(record.indicator_type, "ip");
        assert_eq!(record.indicator_value, "1.2.3.4");
    }

    #[test]
    fn urlencoding_works() {
        assert_eq!(urlencoding("hello world"), "hello%20world");
        assert_eq!(urlencoding("test=1&x=2"), "test%3D1%26x%3D2");
    }

    #[test]
    fn parse_intel_json_array() {
        let config = SiemConfig::default();
        let connector = SiemConnector::new(config);
        let body = r#"[{"indicator_type":"ip","indicator_value":"10.0.0.1"}]"#;
        let records = connector.parse_intel_response(body).unwrap();
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn parse_intel_splunk_wrapper() {
        let config = SiemConfig::default();
        let connector = SiemConnector::new(config);
        let body = r#"{"results":[{"indicator_type":"domain","indicator_value":"evil.com"}]}"#;
        let records = connector.parse_intel_response(body).unwrap();
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn siem_poller_not_started_when_disabled() {
        let config = SiemConfig::default();
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = start_siem_poller(config, shutdown);
        assert!(handle.is_none());
    }
}
