use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
    pending_logs: Vec<crate::log_collector::LogRecord>,
    push_count: u64,
    pull_count: u64,
    last_error: Option<String>,
}

impl SiemConnector {
    pub fn new(config: SiemConfig) -> Self {
        Self {
            config,
            pending: Vec::new(),
            pending_logs: Vec::new(),
            push_count: 0,
            pull_count: 0,
            last_error: None,
        }
    }

    /// Queue an alert for batch pushing to SIEM.
    pub fn queue_alert(&mut self, alert: &AlertRecord) {
        const MAX_PENDING: usize = 10_000;
        if self.pending.len() >= MAX_PENDING {
            eprintln!("[WARN] SIEM alert queue full ({MAX_PENDING}), dropping oldest");
            self.pending.drain(..self.pending.len() / 2);
        }
        self.pending.push(alert.clone());
        if self.pending.len() >= self.config.batch_size
            && let Err(e) = self.flush()
        {
            self.last_error = Some(e);
        }
    }

    /// Queue a log record for batch pushing to SIEM.
    pub fn queue_log(&mut self, log: &crate::log_collector::LogRecord) {
        const MAX_PENDING: usize = 10_000;
        if self.pending_logs.len() >= MAX_PENDING {
            eprintln!("[WARN] SIEM log queue full ({MAX_PENDING}), dropping oldest");
            self.pending_logs.drain(..self.pending_logs.len() / 2);
        }
        self.pending_logs.push(log.clone());
        if self.pending_logs.len() >= self.config.batch_size
            && let Err(e) = self.flush_logs()
        {
            eprintln!("[WARN] SIEM flush_logs failed: {e}");
            self.last_error = Some(e);
        }
    }

    /// Push inventory to SIEM as an event.
    pub fn push_inventory(
        &mut self,
        inventory: &crate::inventory::SystemInventory,
        agent_id: &str,
    ) {
        if !self.config.enabled {
            return;
        }
        let payload = match self.config.siem_type.as_str() {
            "splunk" => {
                let event = serde_json::json!({
                    "event": { "type": "inventory", "agent_id": agent_id, "inventory": inventory },
                    "sourcetype": "wardex:inventory",
                    "index": self.config.index,
                });
                serde_json::to_string(&event).unwrap_or_default()
            }
            _ => serde_json::json!({
                "type": "inventory",
                "agent_id": agent_id,
                "inventory": inventory,
            })
            .to_string(),
        };
        if let Err(e) = self.send_to_siem(&payload) {
            eprintln!("[WARN] SIEM push_inventory failed: {e}");
            self.last_error = Some(e);
        }
    }

    fn flush_logs(&mut self) -> Result<usize, String> {
        if self.pending_logs.is_empty() || !self.config.enabled {
            self.pending_logs.clear();
            return Ok(0);
        }
        let count = self.pending_logs.len();
        let payload = match self.config.siem_type.as_str() {
            "splunk" => {
                let lines: Vec<String> = self
                    .pending_logs
                    .iter()
                    .map(|log| {
                        serde_json::json!({
                            "event": log,
                            "sourcetype": "wardex:logs",
                            "index": self.config.index,
                        })
                        .to_string()
                    })
                    .collect();
                lines.join("\n")
            }
            "elastic" => {
                let mut lines = Vec::new();
                for log in &self.pending_logs {
                    let action = serde_json::json!({"index": {"_index": format!("{}-logs", self.config.index)}});
                    lines.push(serde_json::to_string(&action).unwrap_or_default());
                    lines.push(serde_json::to_string(log).unwrap_or_default());
                }
                let mut result = lines.join("\n");
                result.push('\n');
                result
            }
            _ => serde_json::to_string(&self.pending_logs).unwrap_or_default(),
        };
        self.send_to_siem(&payload)?;
        self.push_count += count as u64;
        self.pending_logs.clear();
        Ok(count)
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
            "elastic" => format!("{}/_search", self.config.endpoint,),
            _ => format!(
                "{}/api/search?q={}",
                self.config.endpoint,
                urlencoding(&self.config.pull_query),
            ),
        };

        let resp = ureq::get(&url)
            .set(
                "Authorization",
                &format!("Bearer {}", self.config.auth_token),
            )
            .call()
            .map_err(|e| format!("SIEM pull failed: {e}"))?;

        if resp.status() != 200 {
            return Err(format!("SIEM pull returned status {}", resp.status()));
        }

        let body = resp
            .into_string()
            .map_err(|e| format!("failed to read SIEM response: {e}"))?;

        let records = self.parse_intel_response(&body)?;
        self.pull_count += records.len() as u64;
        Ok(records)
    }

    /// Return a reference to the current SIEM configuration.
    pub fn config(&self) -> &SiemConfig {
        &self.config
    }

    /// Replace the SIEM configuration at runtime.
    pub fn update_config(&mut self, new_config: SiemConfig) {
        self.config = new_config;
        self.last_error = None;
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
            "sentinel" => Ok(Self::format_sentinel_asim(alerts)),
            "google" | "secops" | "udm" => Ok(Self::format_google_udm(alerts)),
            "ecs" | "elastic-ecs" => Ok(Self::format_elastic_ecs(alerts)),
            "qradar" | "ibm" => Ok(Self::format_qradar(alerts)),
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
            lines.push(serde_json::to_string(&event).map_err(|e| format!("JSON error: {e}"))?);
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
            lines.push(serde_json::to_string(&action).map_err(|e| format!("JSON error: {e}"))?);
            lines.push(serde_json::to_string(alert).map_err(|e| format!("JSON error: {e}"))?);
        }
        // Elasticsearch bulk API requires trailing newline
        let mut result = lines.join("\n");
        result.push('\n');
        Ok(result)
    }

    /// Generic JSON array format.
    fn format_generic_json(&self, alerts: &[AlertRecord]) -> Result<String, String> {
        serde_json::to_string(alerts).map_err(|e| format!("JSON error: {e}"))
    }

    /// Format alerts in ArcSight Common Event Format (CEF).
    pub fn format_cef(alerts: &[AlertRecord]) -> String {
        alerts.iter().map(|a| {
            let severity = match a.level.as_str() {
                "critical" => "10",
                "severe" => "8",
                "elevated" => "5",
                _ => "3",
            };
            let mitre_str = a.mitre.iter()
                .map(|m| format!("{}:{}", m.technique_id, m.tactic))
                .collect::<Vec<_>>().join(",");
            format!(
                "CEF:0|Wardex|Wardex|1.0|alert|{}|{}|src={} dst={} cs1={} cs1Label=reasons cs2={} cs2Label=mitre cfp1={:.2} cfp1Label=score",
                a.action,
                severity,
                a.hostname,
                a.hostname,
                a.reasons.join("; "),
                mitre_str,
                a.score,
            )
        }).collect::<Vec<_>>().join("\n")
    }

    /// Format alerts in IBM QRadar Log Event Extended Format (LEEF).
    pub fn format_leef(alerts: &[AlertRecord]) -> String {
        alerts.iter().map(|a| {
            let mitre_str = a.mitre.iter()
                .map(|m| format!("{}:{}", m.technique_id, m.tactic))
                .collect::<Vec<_>>().join(",");
            format!(
                "LEEF:2.0|Wardex|Wardex|1.0|alert|\tdevTime={}\tsrc={}\tsev={}\taction={}\treasons={}\tmitre={}\tscore={:.2}",
                a.timestamp,
                a.hostname,
                a.level,
                a.action,
                a.reasons.join("; "),
                mitre_str,
                a.score,
            )
        }).collect::<Vec<_>>().join("\n")
    }

    /// Format alerts in Microsoft Sentinel ASIM (Advanced Security Information Model) format.
    /// Follows SecurityEvent / ASIMProcessEvent normalized schema.
    pub fn format_sentinel_asim(alerts: &[AlertRecord]) -> String {
        let events: Vec<serde_json::Value> = alerts
            .iter()
            .map(|a| {
                let severity = match a.level.as_str() {
                    "critical" => "High",
                    "severe" => "High",
                    "elevated" => "Medium",
                    _ => "Low",
                };
                let mitre_techniques: Vec<String> =
                    a.mitre.iter().map(|m| m.technique_id.clone()).collect();
                let mitre_tactics: Vec<String> = a.mitre.iter().map(|m| m.tactic.clone()).collect();
                serde_json::json!({
                    "TimeGenerated": a.timestamp,
                    "EventProduct": "Wardex",
                    "EventVendor": "Wardex",
                    "EventSchemaVersion": "0.1",
                    "EventType": "Alert",
                    "EventSeverity": severity,
                    "EventResult": if a.enforced { "Success" } else { "NA" },
                    "DvcHostname": a.hostname,
                    "DvcOs": a.platform,
                    "EventOriginalUid": format!("{}-{:.0}", a.hostname, a.score * 1000.0),
                    "ThreatConfidence": (a.confidence * 100.0) as u32,
                    "ThreatCategory": a.reasons.first().cloned().unwrap_or_default(),
                    "ThreatName": a.reasons.join("; "),
                    "AdditionalFields": {
                        "score": a.score,
                        "action": &a.action,
                        "mitre_techniques": mitre_techniques,
                        "mitre_tactics": mitre_tactics,
                    },
                })
            })
            .collect();
        serde_json::to_string(&events).unwrap_or_else(|_| "[]".into())
    }

    /// Format alerts in Google SecOps Unified Data Model (UDM) format.
    /// Follows chronicle.googleapis.com/v1alpha UDM event schema.
    pub fn format_google_udm(alerts: &[AlertRecord]) -> String {
        let events: Vec<serde_json::Value> = alerts
            .iter()
            .map(|a| {
                let severity_enum = match a.level.as_str() {
                    "critical" => "CRITICAL",
                    "severe" => "HIGH",
                    "elevated" => "MEDIUM",
                    _ => "LOW",
                };
                let security_result_category = if a.mitre.is_empty() {
                    "UNKNOWN_CATEGORY"
                } else {
                    "SOFTWARE_MALICIOUS"
                };
                let attacks: Vec<serde_json::Value> = a
                    .mitre
                    .iter()
                    .map(|m| {
                        serde_json::json!({
                            "attack": {
                                "tactic": m.tactic,
                                "technique": m.technique_id,
                                "technique_label": m.technique_name,
                            }
                        })
                    })
                    .collect();

                serde_json::json!({
                    "metadata": {
                        "event_timestamp": a.timestamp,
                        "event_type": "GENERIC_EVENT",
                        "vendor_name": "Wardex",
                        "product_name": "Wardex",
                        "product_event_type": "alert",
                        "product_log_id": format!("{}-{:.0}", a.hostname, a.score * 1000.0),
                    },
                    "principal": {
                        "hostname": a.hostname,
                        "platform": match a.platform.as_str() {
                            "linux" => "LINUX",
                            "macos" => "MAC",
                            "windows" => "WINDOWS",
                            _ => "UNKNOWN_PLATFORM",
                        },
                    },
                    "securityResult": [{
                        "severity": severity_enum,
                        "confidence_score": (a.confidence * 100.0) as u32,
                        "summary": a.reasons.join("; "),
                        "category": security_result_category,
                        "action": [if a.enforced { "BLOCK" } else { "ALLOW" }],
                        "attack_details": attacks,
                    }],
                    "additional": {
                        "score": a.score,
                        "action_taken": &a.action,
                        "reasons": &a.reasons,
                    },
                })
            })
            .collect();
        serde_json::to_string(&events).unwrap_or_else(|_| "[]".into())
    }

    /// Format alerts in Elastic Common Schema (ECS) format for Elasticsearch.
    pub fn format_elastic_ecs(alerts: &[AlertRecord]) -> String {
        let events: Vec<serde_json::Value> = alerts
            .iter()
            .map(|a| {
                let severity_num: u8 = match a.level.as_str() {
                    "critical" => 4,
                    "severe" => 3,
                    "elevated" => 2,
                    _ => 1,
                };
                let mitre_ids: Vec<String> =
                    a.mitre.iter().map(|m| m.technique_id.clone()).collect();
                let mitre_names: Vec<String> =
                    a.mitre.iter().map(|m| m.technique_name.clone()).collect();
                let mitre_tactics: Vec<String> = a.mitre.iter().map(|m| m.tactic.clone()).collect();
                serde_json::json!({
                    "@timestamp": a.timestamp,
                    "event": {
                        "kind": "alert",
                        "category": ["threat"],
                        "type": ["indicator"],
                        "severity": severity_num,
                        "risk_score": a.score,
                        "module": "wardex",
                        "dataset": "wardex.alert",
                        "outcome": if a.enforced { "success" } else { "unknown" },
                    },
                    "host": {
                        "hostname": a.hostname,
                        "os": {
                            "platform": a.platform.to_lowercase(),
                        },
                    },
                    "rule": {
                        "name": a.reasons.first().cloned().unwrap_or_default(),
                        "description": a.reasons.join("; "),
                    },
                    "threat": {
                        "framework": "MITRE ATT&CK",
                        "technique": {
                            "id": mitre_ids,
                            "name": mitre_names,
                        },
                        "tactic": {
                            "name": mitre_tactics,
                        },
                    },
                    "observer": {
                        "vendor": "Wardex",
                        "product": "Wardex",
                        "type": "ids",
                    },
                    "wardex": {
                        "score": a.score,
                        "confidence": a.confidence,
                        "action": &a.action,
                        "level": &a.level,
                    },
                })
            })
            .collect();
        serde_json::to_string(&events).unwrap_or_else(|_| "[]".into())
    }

    /// Format alerts in IBM QRadar Log Source format (JSON payload).
    pub fn format_qradar(alerts: &[AlertRecord]) -> String {
        let events: Vec<serde_json::Value> = alerts
            .iter()
            .map(|a| {
                let severity: u8 = match a.level.as_str() {
                    "critical" => 10,
                    "severe" => 7,
                    "elevated" => 4,
                    _ => 1,
                };
                let mitre_str: String = a
                    .mitre
                    .iter()
                    .map(|m| format!("{}/{}", m.tactic, m.technique_id))
                    .collect::<Vec<_>>()
                    .join(",");
                serde_json::json!({
                    "HEADER": {
                        "logSourceTypeName": "Wardex XDR",
                        "logSourceName": format!("wardex-{}", a.hostname),
                    },
                    "EventName": a.reasons.first().cloned().unwrap_or("alert".into()),
                    "EventTime": a.timestamp,
                    "Severity": severity,
                    "SourceHostName": a.hostname,
                    "Platform": a.platform,
                    "AnomalyScore": a.score,
                    "Confidence": (a.confidence * 100.0) as u32,
                    "RiskLevel": &a.level,
                    "ResponseAction": &a.action,
                    "Enforced": a.enforced,
                    "Description": a.reasons.join("; "),
                    "MitreAttack": mitre_str,
                    "CustomFields": {
                        "reasons": &a.reasons,
                        "cpu_load_pct": a.sample.cpu_load_pct,
                        "memory_load_pct": a.sample.memory_load_pct,
                        "network_kbps": a.sample.network_kbps,
                        "auth_failures": a.sample.auth_failures,
                    },
                })
            })
            .collect();
        serde_json::to_string(&events).unwrap_or_else(|_| "[]".into())
    }

    /// Format alerts as Syslog RFC 5424 messages.
    /// Facility=local4 (20), severity mapped from alert level.
    pub fn format_syslog_rfc5424(alerts: &[AlertRecord]) -> String {
        alerts.iter().map(|a| {
            // RFC 5424 severity: 0=Emergency..7=Debug
            // Map: critical→2(Critical), severe→3(Error), elevated→4(Warning), _→6(Informational)
            let sev = match a.level.as_str() {
                "critical" => 2u8,
                "severe" => 3,
                "elevated" => 4,
                _ => 6,
            };
            // PRI = facility * 8 + severity; facility=local4=20
            let pri = 20 * 8 + sev;
            let mitre_str = a.mitre.iter()
                .map(|m| format!("{}:{}", m.technique_id, m.tactic))
                .collect::<Vec<_>>().join(",");
            // <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
            format!(
                "<{pri}>1 {ts} {host} Wardex - {action} [wardex@48710 score=\"{score:.2}\" level=\"{level}\" confidence=\"{conf:.2}\" mitre=\"{mitre}\"] {reasons}",
                pri = pri,
                ts = a.timestamp,
                host = a.hostname,
                action = a.action,
                score = a.score,
                level = a.level,
                conf = a.confidence,
                mitre = mitre_str,
                reasons = a.reasons.join("; "),
            )
        }).collect::<Vec<_>>().join("\n")
    }

    /// Export alerts in the requested format.
    pub fn export_alerts(alerts: &[AlertRecord], format: &str) -> String {
        match format {
            "cef" => Self::format_cef(alerts),
            "leef" => Self::format_leef(alerts),
            "syslog" | "rfc5424" => Self::format_syslog_rfc5424(alerts),
            "sentinel" | "asim" => Self::format_sentinel_asim(alerts),
            "udm" | "google" => Self::format_google_udm(alerts),
            "ecs" => Self::format_elastic_ecs(alerts),
            "qradar" => Self::format_qradar(alerts),
            _ => serde_json::to_string(alerts).unwrap_or_else(|_| "[]".into()),
        }
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

        let max_retries = 3u32;
        let mut last_err = String::new();
        for attempt in 0..max_retries {
            if attempt > 0 {
                let backoff = Duration::from_millis(500 * 2u64.pow(attempt - 1));
                thread::sleep(backoff);
            }
            match ureq::post(&self.config.endpoint)
                .set("Content-Type", content_type)
                .set("Authorization", &auth_header)
                .send_string(payload)
            {
                Ok(resp) if resp.status() >= 400 && resp.status() < 500 => {
                    // Client errors (4xx) are not retryable
                    return Err(format!("SIEM returned client error: {}", resp.status()));
                }
                Ok(resp) if resp.status() >= 500 => {
                    last_err = format!("SIEM returned server error: {}", resp.status());
                }
                Ok(_) => return Ok(()),
                Err(e) => {
                    last_err = format!("SIEM send failed: {e}");
                }
            }
        }
        Err(last_err)
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
        if let Ok(wrapper) = serde_json::from_str::<SplunkResults>(body)
            && let Some(results) = wrapper.results
        {
            return Ok(results);
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
        if let Ok(wrapper) = serde_json::from_str::<EsHits>(body)
            && let Some(hits) = wrapper.hits.and_then(|h| h.hits)
        {
            return Ok(hits.into_iter().filter_map(|h| h._source).collect());
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
                    log::info!("[siem] Pulled {} intel records", records.len());
                    for record in &records {
                        log::info!(
                            "[siem]   {} = {} ({})",
                            record.indicator_type,
                            record.indicator_value,
                            record.severity
                        );
                    }
                }
                Err(e) => log::error!("[siem] Pull error: {e}"),
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

// ── STIX/TAXII 2.1 Client ────────────────────────────────────────────

/// Configuration for a TAXII 2.1 threat intel source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaxiiConfig {
    /// TAXII discovery/collection URL (e.g., https://taxii.example.com/api/collections/abc/objects/).
    #[serde(default)]
    pub url: String,
    /// Bearer or basic auth token.
    #[serde(default)]
    pub auth_token: String,
    /// Only pull indicators newer than this timestamp (RFC 3339).
    #[serde(default)]
    pub added_after: String,
    /// Poll interval in seconds.
    #[serde(default = "default_taxii_poll")]
    pub poll_interval_secs: u64,
    #[serde(default)]
    pub enabled: bool,
}

fn default_taxii_poll() -> u64 {
    300
}

impl Default for TaxiiConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            auth_token: String::new(),
            added_after: String::new(),
            poll_interval_secs: default_taxii_poll(),
            enabled: false,
        }
    }
}

/// Pulls STIX 2.1 indicators from a TAXII server and converts them to `SiemIntelRecord`.
pub struct TaxiiClient {
    config: TaxiiConfig,
    pull_count: u64,
    last_error: Option<String>,
}

impl TaxiiClient {
    pub fn new(config: TaxiiConfig) -> Self {
        Self {
            config,
            pull_count: 0,
            last_error: None,
        }
    }

    pub fn config(&self) -> &TaxiiConfig {
        &self.config
    }

    pub fn update_config(&mut self, cfg: TaxiiConfig) {
        self.config = cfg;
        self.last_error = None;
    }

    /// Pull STIX indicator objects from the TAXII collection endpoint.
    pub fn pull_indicators(&mut self) -> Result<Vec<SiemIntelRecord>, String> {
        if !self.config.enabled || self.config.url.is_empty() {
            return Ok(Vec::new());
        }

        let mut url = self.config.url.clone();
        if !self.config.added_after.is_empty() {
            let sep = if url.contains('?') { '&' } else { '?' };
            url = format!(
                "{url}{sep}added_after={}",
                urlencoding(&self.config.added_after)
            );
        }

        let resp = ureq::get(&url)
            .set("Accept", "application/taxii+json;version=2.1")
            .set(
                "Authorization",
                &format!("Bearer {}", self.config.auth_token),
            )
            .call()
            .map_err(|e| {
                let msg = format!("TAXII fetch failed: {e}");
                self.last_error = Some(msg.clone());
                msg
            })?;

        if resp.status() != 200 {
            let msg = format!("TAXII returned status {}", resp.status());
            self.last_error = Some(msg.clone());
            return Err(msg);
        }

        let body = resp
            .into_string()
            .map_err(|e| format!("Failed to read TAXII response: {e}"))?;

        let records = Self::parse_stix_bundle(&body);
        self.pull_count += records.len() as u64;
        self.last_error = None;
        Ok(records)
    }

    /// Parse a STIX 2.1 bundle envelope and extract indicator objects.
    fn parse_stix_bundle(body: &str) -> Vec<SiemIntelRecord> {
        let parsed: serde_json::Value = match serde_json::from_str(body) {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };

        // STIX bundle: { "type": "bundle", "objects": [...] }
        // Or TAXII envelope: { "objects": [...] }
        let objects = parsed.get("objects").and_then(|o| o.as_array());
        let Some(objects) = objects else {
            return Vec::new();
        };

        objects
            .iter()
            .filter_map(|obj| {
                let obj_type = obj.get("type")?.as_str()?;
                if obj_type != "indicator" {
                    return None;
                }
                let pattern = obj.get("pattern").and_then(|p| p.as_str()).unwrap_or("");
                let (ind_type, ind_value) = Self::parse_stix_pattern(pattern);
                let name = obj.get("name").and_then(|n| n.as_str()).unwrap_or("");
                let desc = obj
                    .get("description")
                    .and_then(|d| d.as_str())
                    .unwrap_or(name);

                // Map confidence (0-100) to severity
                let confidence = obj.get("confidence").and_then(|c| c.as_u64()).unwrap_or(50);
                let severity = if confidence >= 80 {
                    "critical"
                } else if confidence >= 60 {
                    "high"
                } else if confidence >= 40 {
                    "medium"
                } else {
                    "low"
                };

                Some(SiemIntelRecord {
                    indicator_type: ind_type,
                    indicator_value: ind_value,
                    severity: severity.into(),
                    source: obj
                        .get("created_by_ref")
                        .and_then(|c| c.as_str())
                        .unwrap_or("taxii")
                        .into(),
                    description: desc.into(),
                })
            })
            .collect()
    }

    /// Extract indicator type and value from a STIX 2.1 pattern string.
    /// Example: "[ipv4-addr:value = '198.51.100.1']" → ("ipv4-addr", "198.51.100.1")
    fn parse_stix_pattern(pattern: &str) -> (String, String) {
        // Simplified parser: extract `object-type:property = 'value'`
        let trimmed = pattern.trim_start_matches('[').trim_end_matches(']').trim();
        if let Some((lhs, rhs)) = trimmed.split_once('=') {
            let ind_type = lhs
                .split(':')
                .next()
                .unwrap_or("unknown")
                .trim()
                .to_string();
            let ind_value = rhs.trim().trim_matches('\'').trim().to_string();
            (ind_type, ind_value)
        } else {
            ("unknown".into(), pattern.into())
        }
    }

    pub fn status(&self) -> TaxiiStatus {
        TaxiiStatus {
            enabled: self.config.enabled,
            url: self.config.url.clone(),
            pull_count: self.pull_count,
            last_error: self.last_error.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaxiiStatus {
    pub enabled: bool,
    pub url: String,
    pub pull_count: u64,
    pub last_error: Option<String>,
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
            mitre: vec![],
            narrative: None,
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
        let mut config = SiemConfig {
            enabled: true,
            ..SiemConfig::default()
        };
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

    #[test]
    fn sentinel_asim_format() {
        let alert = make_alert();
        let output = SiemConnector::format_sentinel_asim(&[alert]);
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["EventProduct"], "Wardex");
        assert_eq!(parsed[0]["EventVendor"], "Wardex");
        assert_eq!(parsed[0]["DvcHostname"], "test-host");
        assert!(parsed[0]["ThreatConfidence"].as_u64().unwrap() > 0);
    }

    #[test]
    fn sentinel_asim_severity_mapping() {
        let mut alert = make_alert();
        alert.level = "critical".into();
        let output = SiemConnector::format_sentinel_asim(&[alert]);
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed[0]["EventSeverity"], "High");
    }

    #[test]
    fn google_udm_format() {
        let alert = make_alert();
        let output = SiemConnector::format_google_udm(&[alert]);
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["metadata"]["vendor_name"], "Wardex");
        assert_eq!(parsed[0]["metadata"]["product_name"], "Wardex");
        assert_eq!(parsed[0]["principal"]["hostname"], "test-host");
        assert_eq!(parsed[0]["principal"]["platform"], "LINUX");
    }

    #[test]
    fn google_udm_severity_and_mitre() {
        let mut alert = make_alert();
        alert.level = "severe".into();
        alert.mitre = vec![crate::telemetry::MitreAttack {
            tactic: "Execution".into(),
            technique_id: "T1059".into(),
            technique_name: "Command and Scripting Interpreter".into(),
        }];
        let output = SiemConnector::format_google_udm(&[alert]);
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed[0]["securityResult"][0]["severity"], "HIGH");
        assert_eq!(
            parsed[0]["securityResult"][0]["category"],
            "SOFTWARE_MALICIOUS"
        );
        assert!(
            !parsed[0]["securityResult"][0]["attack_details"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn cef_format_output() {
        let alerts = vec![make_alert()];
        let output = SiemConnector::format_cef(&alerts);
        assert!(output.starts_with("CEF:0|Wardex|Wardex|"));
        assert!(output.contains("src=test-host"));
    }

    #[test]
    fn leef_format_output() {
        let alerts = vec![make_alert()];
        let output = SiemConnector::format_leef(&alerts);
        assert!(output.starts_with("LEEF:2.0|Wardex|Wardex|"));
        assert!(output.contains("src=test-host"));
    }

    #[test]
    fn elastic_ecs_format() {
        let alerts = vec![make_alert()];
        let output = SiemConnector::format_elastic_ecs(&alerts);
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed.len(), 1);
        let ev = &parsed[0];
        assert_eq!(ev["event"]["kind"], "alert");
        assert_eq!(ev["observer"]["vendor"], "Wardex");
        assert_eq!(ev["host"]["hostname"], "test-host");
        assert!(ev["wardex"]["score"].as_f64().unwrap() > 0.0);
    }

    #[test]
    fn elastic_ecs_severity_mapping() {
        let mut a = make_alert();
        a.level = "critical".into();
        let output = SiemConnector::format_elastic_ecs(&[a]);
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed[0]["event"]["severity"], 4);
    }

    #[test]
    fn qradar_format() {
        let alerts = vec![make_alert()];
        let output = SiemConnector::format_qradar(&alerts);
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed.len(), 1);
        let ev = &parsed[0];
        assert_eq!(ev["HEADER"]["logSourceTypeName"], "Wardex XDR");
        assert_eq!(ev["SourceHostName"], "test-host");
        assert!(ev["Severity"].as_u64().unwrap() > 0);
    }

    #[test]
    fn qradar_severity_critical() {
        let mut a = make_alert();
        a.level = "critical".into();
        let output = SiemConnector::format_qradar(&[a]);
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed[0]["Severity"], 10);
    }

    #[test]
    fn stix_pattern_parsing() {
        let (t, v) = TaxiiClient::parse_stix_pattern("[ipv4-addr:value = '198.51.100.1']");
        assert_eq!(t, "ipv4-addr");
        assert_eq!(v, "198.51.100.1");
    }

    #[test]
    fn stix_bundle_parsing() {
        let bundle = r#"{
            "type": "bundle",
            "id": "bundle--1",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--1",
                    "name": "Malicious IP",
                    "pattern": "[ipv4-addr:value = '10.0.0.1']",
                    "confidence": 85,
                    "created_by_ref": "identity--test"
                },
                {
                    "type": "malware",
                    "id": "malware--1",
                    "name": "ignored"
                },
                {
                    "type": "indicator",
                    "id": "indicator--2",
                    "name": "Bad domain",
                    "pattern": "[domain-name:value = 'evil.example.com']",
                    "confidence": 30
                }
            ]
        }"#;
        let records = TaxiiClient::parse_stix_bundle(bundle);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].indicator_type, "ipv4-addr");
        assert_eq!(records[0].indicator_value, "10.0.0.1");
        assert_eq!(records[0].severity, "critical");
        assert_eq!(records[0].source, "identity--test");
        assert_eq!(records[1].indicator_type, "domain-name");
        assert_eq!(records[1].indicator_value, "evil.example.com");
        assert_eq!(records[1].severity, "low");
    }

    #[test]
    fn taxii_disabled_returns_empty() {
        let mut client = TaxiiClient::new(TaxiiConfig::default());
        assert!(client.pull_indicators().unwrap().is_empty());
    }

    #[test]
    fn siem_config_getter() {
        let cfg = SiemConfig {
            enabled: true,
            siem_type: "splunk".into(),
            ..Default::default()
        };
        let conn = SiemConnector::new(cfg);
        assert_eq!(conn.config().siem_type, "splunk");
        assert!(conn.config().enabled);
    }

    #[test]
    fn siem_update_config() {
        let cfg = SiemConfig::default();
        let mut conn = SiemConnector::new(cfg);
        assert!(!conn.config().enabled);
        let new_cfg = SiemConfig {
            enabled: true,
            siem_type: "elastic".into(),
            ..Default::default()
        };
        conn.update_config(new_cfg);
        assert!(conn.config().enabled);
        assert_eq!(conn.config().siem_type, "elastic");
    }

    #[test]
    fn syslog_rfc5424_format() {
        let alerts = vec![make_alert()];
        let output = SiemConnector::format_syslog_rfc5424(&alerts);
        // PRI = 20*8 + 2 = 162 for critical
        assert!(output.starts_with("<162>1 "));
        assert!(output.contains("Wardex"));
        assert!(output.contains("[wardex@48710"));
        assert!(output.contains("score="));
    }

    #[test]
    fn export_alerts_dispatches_correctly() {
        let alerts = vec![make_alert()];
        let cef = SiemConnector::export_alerts(&alerts, "cef");
        assert!(cef.starts_with("CEF:0|"));
        let syslog = SiemConnector::export_alerts(&alerts, "syslog");
        assert!(syslog.contains("<162>1 "));
        let json = SiemConnector::export_alerts(&alerts, "json");
        assert!(json.starts_with('['));
    }
}
