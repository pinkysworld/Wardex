//! Live threat-feed ingestion engine.
//!
//! Implements automatic pull-based feed ingestion from TAXII 2.1
//! servers, Abuse.ch MalwareBazaar, and custom URL feeds. Supports
//! scheduled polling, deduplication, and incremental updates.

use serde::{Deserialize, Serialize};

use crate::malware_signatures::{MalwareEntry, MalwareHashDb, MalwareSeverity};
use crate::threat_intel::{IoC, IoCType, ThreatIntelStore};
use crate::yara_engine::YaraEngine;

// ── Feed Types ───────────────────────────────────────────────────────

/// Supported feed protocols.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FeedProtocol {
    Taxii21,
    AbuseCh,
    CustomUrl,
    StixBundle,
}

/// Configuration for a single feed source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedSource {
    pub id: String,
    pub name: String,
    pub protocol: FeedProtocol,
    pub url: String,
    pub api_key: Option<String>,
    pub poll_interval_secs: u64,
    pub enabled: bool,
    pub last_poll: Option<String>,
    pub last_success: Option<String>,
    pub iocs_ingested: usize,
    pub errors: Vec<String>,
    pub collection_id: Option<String>,
}

/// Result of a feed poll operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedPollResult {
    pub feed_id: String,
    pub new_iocs: usize,
    pub updated_iocs: usize,
    pub new_hashes: usize,
    pub new_yara_rules: usize,
    pub errors: Vec<String>,
    pub poll_time_ms: u64,
    pub timestamp: String,
}

/// Feed ingestion statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedIngestionStats {
    pub total_sources: usize,
    pub active_sources: usize,
    pub total_polls: u64,
    pub total_iocs_ingested: u64,
    pub total_hashes_imported: u64,
    pub total_yara_imported: u64,
    pub last_poll_results: Vec<FeedPollResult>,
    pub errors_last_24h: usize,
}

// ── Feed Ingestion Engine ────────────────────────────────────────────

/// Central feed ingestion manager.
#[derive(Debug)]
pub struct FeedIngestionEngine {
    sources: Vec<FeedSource>,
    poll_results: Vec<FeedPollResult>,
    total_polls: u64,
    total_iocs_ingested: u64,
    total_hashes_imported: u64,
    total_yara_imported: u64,
}

impl Default for FeedIngestionEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl FeedIngestionEngine {
    pub fn new() -> Self {
        Self {
            sources: Vec::new(),
            poll_results: Vec::new(),
            total_polls: 0,
            total_iocs_ingested: 0,
            total_hashes_imported: 0,
            total_yara_imported: 0,
        }
    }

    pub fn new_with_defaults() -> Self {
        let mut engine = Self::new();
        for source in default_feed_sources() {
            engine.add_source(source);
        }
        engine
    }

    /// Register a new feed source.
    pub fn add_source(&mut self, source: FeedSource) -> String {
        let id = source.id.clone();
        if !self.sources.iter().any(|s| s.id == id) {
            self.sources.push(source);
        }
        id
    }

    /// Remove a feed source by ID.
    pub fn remove_source(&mut self, id: &str) -> bool {
        let before = self.sources.len();
        self.sources.retain(|s| s.id != id);
        self.sources.len() < before
    }

    /// Enable or disable a feed source.
    pub fn set_enabled(&mut self, id: &str, enabled: bool) -> bool {
        if let Some(src) = self.sources.iter_mut().find(|s| s.id == id) {
            src.enabled = enabled;
            true
        } else {
            false
        }
    }

    /// List all feed sources.
    pub fn sources(&self) -> &[FeedSource] {
        &self.sources
    }

    /// Poll a specific feed source and ingest results.
    /// In production this would make HTTP requests; here we parse
    /// provided data in the appropriate format.
    pub fn poll_feed(
        &mut self,
        feed_id: &str,
        data: &str,
        threat_intel: &mut ThreatIntelStore,
        hash_db: &mut MalwareHashDb,
        _yara: &mut YaraEngine,
    ) -> Result<FeedPollResult, String> {
        let source = self
            .sources
            .iter_mut()
            .find(|s| s.id == feed_id)
            .ok_or_else(|| format!("feed source '{feed_id}' not found"))?;

        if !source.enabled {
            return Err(format!("feed source '{feed_id}' is disabled"));
        }

        let start = std::time::Instant::now();
        let mut result = FeedPollResult {
            feed_id: feed_id.to_string(),
            new_iocs: 0,
            updated_iocs: 0,
            new_hashes: 0,
            new_yara_rules: 0,
            errors: Vec::new(),
            poll_time_ms: 0,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        match &source.protocol {
            FeedProtocol::Taxii21 | FeedProtocol::StixBundle => {
                let before = threat_intel.ioc_count();
                let count = threat_intel.ingest_stix_bundle(feed_id, data);
                result.new_iocs = count;
                result.updated_iocs = if threat_intel.ioc_count() < before + count {
                    count - (threat_intel.ioc_count() - before)
                } else {
                    0
                };
            }
            FeedProtocol::AbuseCh => {
                // Abuse.ch MalwareBazaar format: JSON lines with sha256_hash, md5_hash, etc.
                let parsed = parse_abusech_feed(data);
                for entry in &parsed.iocs {
                    threat_intel.add_ioc(entry.clone());
                    result.new_iocs += 1;
                }
                for entry in &parsed.malware_entries {
                    hash_db.insert(entry.clone());
                    result.new_hashes += 1;
                }
            }
            FeedProtocol::CustomUrl => {
                // JSON-lines format (one IoC per line)
                let count = threat_intel.ingest_feed(feed_id, data);
                result.new_iocs = count;
            }
        }

        result.poll_time_ms = start.elapsed().as_millis() as u64;

        // Update source metadata
        let source = self
            .sources
            .iter_mut()
            .find(|s| s.id == feed_id)
            .ok_or_else(|| format!("feed source '{feed_id}' vanished mid-poll"))?;
        source.last_poll = Some(result.timestamp.clone());
        source.last_success = Some(result.timestamp.clone());
        source.iocs_ingested += result.new_iocs;

        self.total_polls += 1;
        self.total_iocs_ingested += result.new_iocs as u64;
        self.total_hashes_imported += result.new_hashes as u64;
        self.total_yara_imported += result.new_yara_rules as u64;

        // Keep last 50 poll results
        self.poll_results.push(result.clone());
        if self.poll_results.len() > 50 {
            self.poll_results.remove(0);
        }

        Ok(result)
    }

    /// Get all sources due for polling (last_poll older than interval).
    pub fn sources_due_for_poll(&self) -> Vec<&FeedSource> {
        let now = chrono::Utc::now();
        self.sources
            .iter()
            .filter(|s| {
                if !s.enabled {
                    return false;
                }
                match &s.last_poll {
                    None => true,
                    Some(ts) => {
                        if let Ok(last) = chrono::DateTime::parse_from_rfc3339(ts) {
                            let elapsed = (now - last.with_timezone(&chrono::Utc))
                                .num_seconds()
                                .unsigned_abs();
                            elapsed >= s.poll_interval_secs
                        } else {
                            true
                        }
                    }
                }
            })
            .collect()
    }

    /// Ingestion statistics.
    pub fn stats(&self) -> FeedIngestionStats {
        let now = chrono::Utc::now();
        let day_ago = (now - chrono::Duration::hours(24)).to_rfc3339();
        let errors_24h = self
            .poll_results
            .iter()
            .filter(|r| r.timestamp.as_str() > day_ago.as_str() && !r.errors.is_empty())
            .count();

        FeedIngestionStats {
            total_sources: self.sources.len(),
            active_sources: self.sources.iter().filter(|s| s.enabled).count(),
            total_polls: self.total_polls,
            total_iocs_ingested: self.total_iocs_ingested,
            total_hashes_imported: self.total_hashes_imported,
            total_yara_imported: self.total_yara_imported,
            last_poll_results: self.poll_results.iter().rev().take(10).cloned().collect(),
            errors_last_24h: errors_24h,
        }
    }

    /// Get recent poll results.
    pub fn recent_polls(&self) -> &[FeedPollResult] {
        &self.poll_results
    }

    /// Hot-reload: push new malware hashes from a JSON array without restarting.
    pub fn hot_reload_hashes(
        &mut self,
        json: &str,
        hash_db: &mut MalwareHashDb,
    ) -> Result<usize, String> {
        let count = hash_db.load_from_json(json)?;
        self.total_hashes_imported += count as u64;
        Ok(count)
    }

    /// Hot-reload: push a new YARA rule without restarting.
    pub fn hot_reload_yara_rule(
        &mut self,
        rule: crate::yara_engine::YaraRule,
        yara: &mut YaraEngine,
    ) -> String {
        let name = rule.name.clone();
        yara.add_rule(rule);
        self.total_yara_imported += 1;
        name
    }
}

// ── Abuse.ch Parser ──────────────────────────────────────────────────

struct AbusechParsed {
    iocs: Vec<IoC>,
    malware_entries: Vec<MalwareEntry>,
}

fn default_feed_sources() -> Vec<FeedSource> {
    vec![
        FeedSource {
            id: "abusech-malwarebazaar".into(),
            name: "Abuse.ch MalwareBazaar".into(),
            protocol: FeedProtocol::AbuseCh,
            url: "https://bazaar.abuse.ch/export/jsonl/recent/".into(),
            api_key: None,
            poll_interval_secs: 900,
            enabled: true,
            last_poll: None,
            last_success: None,
            iocs_ingested: 0,
            errors: vec![],
            collection_id: None,
        },
        FeedSource {
            id: "cisa-stix".into(),
            name: "CISA STIX Bundle".into(),
            protocol: FeedProtocol::StixBundle,
            url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json".into(),
            api_key: None,
            poll_interval_secs: 3600,
            enabled: true,
            last_poll: None,
            last_success: None,
            iocs_ingested: 0,
            errors: vec![],
            collection_id: None,
        },
        FeedSource {
            id: "urlhaus-online".into(),
            name: "URLhaus Online URLs".into(),
            protocol: FeedProtocol::CustomUrl,
            url: "https://urlhaus.abuse.ch/downloads/json_online/".into(),
            api_key: None,
            poll_interval_secs: 1800,
            enabled: true,
            last_poll: None,
            last_success: None,
            iocs_ingested: 0,
            errors: vec![],
            collection_id: None,
        },
        FeedSource {
            id: "otx-export".into(),
            name: "OTX Pulse Export".into(),
            protocol: FeedProtocol::CustomUrl,
            url: "https://otx.alienvault.com/api/v1/pulses/subscribed".into(),
            api_key: None,
            poll_interval_secs: 3600,
            enabled: false,
            last_poll: None,
            last_success: None,
            iocs_ingested: 0,
            errors: vec![],
            collection_id: None,
        },
    ]
}

fn parse_abusech_feed(data: &str) -> AbusechParsed {
    let mut iocs = Vec::new();
    let mut malware_entries = Vec::new();
    let now = chrono::Utc::now().to_rfc3339();

    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) {
            // Extract SHA256 hash as IoC
            if let Some(sha256) = entry.get("sha256_hash").and_then(|v| v.as_str()) {
                iocs.push(IoC {
                    ioc_type: IoCType::FileHash,
                    value: sha256.to_string(),
                    confidence: 0.85,
                    severity: entry
                        .get("threat_level")
                        .and_then(|v| v.as_str())
                        .unwrap_or("high")
                        .to_string(),
                    source: "abuse.ch".to_string(),
                    first_seen: entry
                        .get("first_seen")
                        .and_then(|v| v.as_str())
                        .unwrap_or(&now)
                        .to_string(),
                    last_seen: now.clone(),
                    tags: entry
                        .get("tags")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default(),
                    related_iocs: vec![],
                    metadata: crate::threat_intel::IndicatorMetadata::default(),
                    sightings: Vec::new(),
                });
                let signature = entry
                    .get("signature")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                let md5 = entry
                    .get("md5_hash")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_lowercase());
                let tags: Vec<String> = entry
                    .get("tags")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_else(|| vec!["malwarebazaar".into()]);
                malware_entries.push(MalwareEntry {
                    sha256: sha256.to_lowercase(),
                    md5,
                    name: signature.clone(),
                    family: signature,
                    severity: MalwareSeverity::High,
                    source: "abuse.ch".into(),
                    first_seen: entry
                        .get("first_seen")
                        .and_then(|v| v.as_str())
                        .unwrap_or(&now)
                        .to_string(),
                    tags,
                });
            }
            // Extract domain
            if let Some(domain) = entry
                .get("url_domain")
                .or_else(|| entry.get("domain"))
                .and_then(|v| v.as_str())
                && !domain.is_empty()
            {
                iocs.push(IoC {
                    ioc_type: IoCType::Domain,
                    value: domain.to_string(),
                    confidence: 0.75,
                    severity: "medium".to_string(),
                    source: "abuse.ch".to_string(),
                    first_seen: now.clone(),
                    last_seen: now.clone(),
                    tags: vec!["malware-distribution".to_string()],
                    related_iocs: vec![],
                    metadata: crate::threat_intel::IndicatorMetadata::default(),
                    sightings: Vec::new(),
                });
            }
        }
    }

    AbusechParsed {
        iocs,
        malware_entries,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_and_list_sources() {
        let mut engine = FeedIngestionEngine::new();
        let src = FeedSource {
            id: "test-feed".into(),
            name: "Test Feed".into(),
            protocol: FeedProtocol::CustomUrl,
            url: "https://example.com/feed.json".into(),
            api_key: None,
            poll_interval_secs: 3600,
            enabled: true,
            last_poll: None,
            last_success: None,
            iocs_ingested: 0,
            errors: vec![],
            collection_id: None,
        };
        engine.add_source(src);
        assert_eq!(engine.sources().len(), 1);
    }

    #[test]
    fn poll_custom_url_feed() {
        let mut engine = FeedIngestionEngine::new();
        let mut ti = ThreatIntelStore::new();
        let mut hash_db = MalwareHashDb::new();
        let mut yara = YaraEngine::new();

        engine.add_source(FeedSource {
            id: "f1".into(),
            name: "Custom".into(),
            protocol: FeedProtocol::CustomUrl,
            url: "https://example.com/feed".into(),
            api_key: None,
            poll_interval_secs: 300,
            enabled: true,
            last_poll: None,
            last_success: None,
            iocs_ingested: 0,
            errors: vec![],
            collection_id: None,
        });

        let data = r#"{"ioc_type":"IpAddress","value":"10.0.0.1","confidence":0.9,"severity":"high","source":"test","first_seen":"2026-01-01T00:00:00Z","last_seen":"2026-01-01T00:00:00Z","tags":[],"related_iocs":[]}"#;
        let result = engine
            .poll_feed("f1", data, &mut ti, &mut hash_db, &mut yara)
            .unwrap();
        assert_eq!(result.new_iocs, 1);
        assert_eq!(ti.ioc_count(), 1);
    }

    #[test]
    fn poll_stix_bundle() {
        let mut engine = FeedIngestionEngine::new();
        let mut ti = ThreatIntelStore::new();
        let mut hash_db = MalwareHashDb::new();
        let mut yara = YaraEngine::new();

        engine.add_source(FeedSource {
            id: "taxii1".into(),
            name: "TAXII".into(),
            protocol: FeedProtocol::Taxii21,
            url: "https://taxii.example.com".into(),
            api_key: None,
            poll_interval_secs: 600,
            enabled: true,
            last_poll: None,
            last_success: None,
            iocs_ingested: 0,
            errors: vec![],
            collection_id: Some("collection-1".into()),
        });

        let bundle = r#"{"type":"bundle","id":"bundle--1","objects":[{"type":"indicator","pattern":"[ipv4-addr:value = '192.168.1.1']","confidence":80,"created":"2026-01-01T00:00:00Z","labels":["malicious"]}]}"#;
        let result = engine
            .poll_feed("taxii1", bundle, &mut ti, &mut hash_db, &mut yara)
            .unwrap();
        assert!(result.new_iocs >= 1);
    }

    #[test]
    fn poll_abusech_feed() {
        let mut engine = FeedIngestionEngine::new();
        let mut ti = ThreatIntelStore::new();
        let mut hash_db = MalwareHashDb::new();
        let mut yara = YaraEngine::new();

        engine.add_source(FeedSource {
            id: "abuse1".into(),
            name: "Abuse.ch".into(),
            protocol: FeedProtocol::AbuseCh,
            url: "https://bazaar.abuse.ch".into(),
            api_key: None,
            poll_interval_secs: 1800,
            enabled: true,
            last_poll: None,
            last_success: None,
            iocs_ingested: 0,
            errors: vec![],
            collection_id: None,
        });

        let data = r#"{"sha256_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","threat_level":"high","tags":["emotet"],"url_domain":"evil.example.com"}"#;
        let result = engine
            .poll_feed("abuse1", data, &mut ti, &mut hash_db, &mut yara)
            .unwrap();
        assert!(result.new_iocs >= 1);
    }

    #[test]
    fn disabled_feed_errors() {
        let mut engine = FeedIngestionEngine::new();
        let mut ti = ThreatIntelStore::new();
        let mut hash_db = MalwareHashDb::new();
        let mut yara = YaraEngine::new();

        engine.add_source(FeedSource {
            id: "disabled".into(),
            name: "Disabled".into(),
            protocol: FeedProtocol::CustomUrl,
            url: "https://example.com".into(),
            api_key: None,
            poll_interval_secs: 300,
            enabled: false,
            last_poll: None,
            last_success: None,
            iocs_ingested: 0,
            errors: vec![],
            collection_id: None,
        });

        let result = engine.poll_feed("disabled", "{}", &mut ti, &mut hash_db, &mut yara);
        assert!(result.is_err());
    }

    #[test]
    fn stats_reports_correctly() {
        let engine = FeedIngestionEngine::new();
        let stats = engine.stats();
        assert_eq!(stats.total_sources, 0);
        assert_eq!(stats.total_polls, 0);
    }

    #[test]
    fn default_sources_seed_common_hash_and_ioc_feeds() {
        let engine = FeedIngestionEngine::new_with_defaults();
        let ids: Vec<_> = engine
            .sources()
            .iter()
            .map(|source| source.id.as_str())
            .collect();

        assert!(ids.contains(&"abusech-malwarebazaar"));
        assert!(ids.contains(&"cisa-stix"));
        assert!(ids.contains(&"urlhaus-online"));
    }
}
