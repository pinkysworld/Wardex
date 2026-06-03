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
    /// Abuse.ch MalwareBazaar recent-samples CSV export.
    MalwareBazaar,
    /// Abuse.ch URLhaus `json_online` export (object keyed by entry ID).
    UrlHaus,
    /// Abuse.ch Feodo Tracker botnet C2 IP blocklist (JSON array).
    FeodoTracker,
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

    /// Fetch a feed source over HTTP and ingest the result.
    ///
    /// This is the live counterpart to [`poll_feed`](Self::poll_feed): it
    /// performs the network request to the source URL, then runs the same
    /// protocol-specific ingestion. Fetch failures are recorded on the source.
    pub fn poll_feed_live(
        &mut self,
        feed_id: &str,
        threat_intel: &mut ThreatIntelStore,
        hash_db: &mut MalwareHashDb,
        yara: &mut YaraEngine,
    ) -> Result<FeedPollResult, String> {
        let source = self
            .sources
            .iter()
            .find(|s| s.id == feed_id)
            .ok_or_else(|| format!("feed source '{feed_id}' not found"))?
            .clone();

        if !source.enabled {
            return Err(format!("feed source '{feed_id}' is disabled"));
        }

        match fetch_feed_data(&source) {
            Ok(data) => self.poll_feed(feed_id, &data, threat_intel, hash_db, yara),
            Err(e) => {
                self.record_feed_failure(feed_id, &e);
                Err(e)
            }
        }
    }

    /// Record a failed poll attempt so a broken feed is not retried every tick.
    pub fn record_feed_failure(&mut self, feed_id: &str, error: &str) {
        if let Some(src) = self.sources.iter_mut().find(|s| s.id == feed_id) {
            src.last_poll = Some(chrono::Utc::now().to_rfc3339());
            src.errors.push(error.to_string());
            if src.errors.len() > 20 {
                src.errors.remove(0);
            }
        }
    }

    /// Fetch and ingest every source that is due for polling.
    pub fn poll_due_feeds(
        &mut self,
        threat_intel: &mut ThreatIntelStore,
        hash_db: &mut MalwareHashDb,
        yara: &mut YaraEngine,
    ) -> Vec<FeedPollResult> {
        let due: Vec<String> = self
            .sources_due_for_poll()
            .iter()
            .map(|s| s.id.clone())
            .collect();
        let mut results = Vec::new();
        for id in due {
            if let Ok(result) = self.poll_feed_live(&id, threat_intel, hash_db, yara) {
                results.push(result);
            }
        }
        results
    }

    /// Poll a specific feed source and ingest already-fetched `data`.
    ///
    /// Use [`poll_feed_live`](Self::poll_feed_live) to fetch over the network.
    /// This entry point ingests a caller-supplied payload, which is what the
    /// manual `/poll` API and tests use.
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
            FeedProtocol::MalwareBazaar => {
                let parsed = parse_malwarebazaar_csv(data);
                for entry in &parsed.iocs {
                    threat_intel.add_ioc(entry.clone());
                    result.new_iocs += 1;
                }
                for entry in &parsed.malware_entries {
                    hash_db.insert(entry.clone());
                    result.new_hashes += 1;
                }
            }
            FeedProtocol::UrlHaus => {
                for ioc in parse_urlhaus_json(data) {
                    threat_intel.add_ioc(ioc);
                    result.new_iocs += 1;
                }
            }
            FeedProtocol::FeodoTracker => {
                for ioc in parse_feodo_json(data) {
                    threat_intel.add_ioc(ioc);
                    result.new_iocs += 1;
                }
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
            protocol: FeedProtocol::MalwareBazaar,
            url: "https://bazaar.abuse.ch/export/csv/recent/".into(),
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
            id: "feodo-tracker".into(),
            name: "Abuse.ch Feodo Tracker C2".into(),
            protocol: FeedProtocol::FeodoTracker,
            url: "https://feodotracker.abuse.ch/downloads/ipblocklist.json".into(),
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
            protocol: FeedProtocol::UrlHaus,
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

/// Fetch the raw payload of a feed source over HTTP.
///
/// Applies protocol-appropriate headers: Abuse.ch services authenticate with
/// an `Auth-Key` header, TAXII 2.1 servers expect the taxii media type, and
/// other feeds use bearer auth when an API key is configured.
pub fn fetch_feed_data(source: &FeedSource) -> Result<String, String> {
    let mut request = ureq::get(&source.url)
        .timeout(std::time::Duration::from_secs(30))
        .set("User-Agent", "Wardex-FeedIngestion/1.0");

    if let Some(ref key) = source.api_key {
        request = match source.protocol {
            // Abuse.ch services authenticate with an `Auth-Key` header.
            FeedProtocol::AbuseCh
            | FeedProtocol::MalwareBazaar
            | FeedProtocol::UrlHaus
            | FeedProtocol::FeodoTracker => request.set("Auth-Key", key),
            _ => request.set("Authorization", &format!("Bearer {key}")),
        };
    }

    if source.protocol == FeedProtocol::Taxii21 {
        request = request.set("Accept", "application/taxii+json;version=2.1");
    }

    let response = request
        .call()
        .map_err(|e| format!("feed '{}' fetch failed: {e}", source.id))?;

    response
        .into_string()
        .map_err(|e| format!("feed '{}' response read failed: {e}", source.id))
}

/// Split one CSV line into fields, honouring double-quoted values.
fn split_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if in_quotes && chars.peek() == Some(&'"') => {
                current.push('"');
                chars.next();
            }
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                fields.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(c),
        }
    }
    fields.push(current.trim().to_string());
    fields
}

/// Parse the Abuse.ch MalwareBazaar recent-samples CSV export.
///
/// Columns: first_seen, sha256, md5, sha1, reporter, file_name, file_type,
/// mime_type, signature, clamav, ...
fn parse_malwarebazaar_csv(data: &str) -> AbusechParsed {
    let mut iocs = Vec::new();
    let mut malware_entries = Vec::new();
    let now = chrono::Utc::now().to_rfc3339();

    for line in data.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = split_csv_line(line);
        if fields.len() < 9 {
            continue;
        }
        let sha256 = fields[1].to_lowercase();
        if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
            continue; // skip the header row and any malformed line
        }
        let first_seen = fields[0].clone();
        let md5 = {
            let m = fields[2].to_lowercase();
            (m.len() == 32 && m.chars().all(|c| c.is_ascii_hexdigit())).then_some(m)
        };
        let signature = match fields[8].trim() {
            "" | "n/a" => "unknown",
            other => other,
        };
        let file_type = fields.get(6).map_or("", String::as_str);

        let mut tags = vec!["malwarebazaar".to_string()];
        if !file_type.is_empty() && file_type != "n/a" {
            tags.push(file_type.to_string());
        }
        if signature != "unknown" {
            tags.push(signature.to_string());
        }

        iocs.push(IoC {
            ioc_type: IoCType::FileHash,
            value: sha256.clone(),
            confidence: 0.9,
            severity: "high".to_string(),
            source: "abuse.ch/malwarebazaar".to_string(),
            first_seen: first_seen.clone(),
            last_seen: now.clone(),
            tags: tags.clone(),
            related_iocs: vec![],
            metadata: crate::threat_intel::IndicatorMetadata::default(),
            sightings: Vec::new(),
        });
        malware_entries.push(MalwareEntry {
            sha256,
            md5,
            name: signature.to_string(),
            family: signature.to_string(),
            severity: MalwareSeverity::High,
            source: "abuse.ch/malwarebazaar".into(),
            first_seen,
            tags,
        });
    }

    AbusechParsed {
        iocs,
        malware_entries,
    }
}

/// Extract the host (domain or IP, without scheme/port/path) from a URL.
fn host_from_url(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if host_port.is_empty() {
        return None;
    }
    let host = if let Some(rest) = host_port.strip_prefix('[') {
        // Bracketed IPv6 literal: [addr]:port
        rest.split_once(']').map_or(rest, |(addr, _)| addr)
    } else if let Some((h, port)) = host_port.rsplit_once(':') {
        // Strip a trailing :port only when it is genuinely numeric, so a bare
        // IPv6 address (multiple colons) is left intact.
        if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            h
        } else {
            host_port
        }
    } else {
        host_port
    };
    (!host.is_empty()).then(|| host.to_string())
}

/// Parse the Abuse.ch URLhaus `json_online` export — an object keyed by entry
/// ID, each value an array of URL records. The host is extracted from `url`.
fn parse_urlhaus_json(data: &str) -> Vec<IoC> {
    let now = chrono::Utc::now().to_rfc3339();
    let Ok(root) = serde_json::from_str::<serde_json::Value>(data) else {
        return Vec::new();
    };
    let Some(map) = root.as_object() else {
        return Vec::new();
    };

    let mut iocs = Vec::new();
    for entry in map.values().flat_map(|v| v.as_array()).flatten() {
        let Some(url) = entry.get("url").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(host) = host_from_url(url) else {
            continue;
        };
        let ioc_type = if host.parse::<std::net::IpAddr>().is_ok() {
            IoCType::IpAddress
        } else {
            IoCType::Domain
        };
        let mut tags: Vec<String> = entry
            .get("tags")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        tags.push("urlhaus".to_string());
        tags.push(format!("url:{url}"));
        if let Some(threat) = entry.get("threat").and_then(|v| v.as_str()) {
            tags.push(threat.to_string());
        }
        iocs.push(IoC {
            ioc_type,
            value: host,
            confidence: 0.8,
            severity: "high".to_string(),
            source: "abuse.ch/urlhaus".to_string(),
            first_seen: entry
                .get("dateadded")
                .and_then(|v| v.as_str())
                .unwrap_or(&now)
                .to_string(),
            last_seen: now.clone(),
            tags,
            related_iocs: vec![],
            metadata: crate::threat_intel::IndicatorMetadata::default(),
            sightings: Vec::new(),
        });
    }
    iocs
}

/// Parse the Abuse.ch Feodo Tracker botnet C2 IP blocklist (JSON array).
fn parse_feodo_json(data: &str) -> Vec<IoC> {
    let now = chrono::Utc::now().to_rfc3339();
    let Ok(entries) = serde_json::from_str::<Vec<serde_json::Value>>(data) else {
        return Vec::new();
    };

    let mut iocs = Vec::new();
    for entry in &entries {
        let Some(ip) = entry.get("ip_address").and_then(|v| v.as_str()) else {
            continue;
        };
        if ip.parse::<std::net::IpAddr>().is_err() {
            continue;
        }
        let malware = entry
            .get("malware")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let mut tags = vec!["feodotracker".to_string(), "botnet-c2".to_string()];
        if !malware.is_empty() && malware != "unknown" {
            tags.push(malware.to_lowercase());
        }
        iocs.push(IoC {
            ioc_type: IoCType::IpAddress,
            value: ip.to_string(),
            confidence: 0.9,
            severity: "high".to_string(),
            source: "abuse.ch/feodotracker".to_string(),
            first_seen: entry
                .get("first_seen")
                .and_then(|v| v.as_str())
                .unwrap_or(&now)
                .to_string(),
            last_seen: entry
                .get("last_online")
                .and_then(|v| v.as_str())
                .unwrap_or(&now)
                .to_string(),
            tags,
            related_iocs: vec![],
            metadata: crate::threat_intel::IndicatorMetadata::default(),
            sightings: Vec::new(),
        });
    }
    iocs
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
                    .map(str::to_lowercase);
                let tags: Vec<String> = entry.get("tags").and_then(|v| v.as_array()).map_or_else(
                    || vec!["malwarebazaar".into()],
                    |arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    },
                );
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
    fn poll_feed_live_rejects_disabled_source() {
        let mut engine = FeedIngestionEngine::new();
        let mut ti = ThreatIntelStore::new();
        let mut hash_db = MalwareHashDb::new();
        let mut yara = YaraEngine::new();

        engine.add_source(FeedSource {
            id: "off".into(),
            name: "Off".into(),
            protocol: FeedProtocol::CustomUrl,
            url: "https://example.com/feed".into(),
            api_key: None,
            poll_interval_secs: 300,
            enabled: false,
            last_poll: None,
            last_success: None,
            iocs_ingested: 0,
            errors: vec![],
            collection_id: None,
        });

        let result = engine.poll_feed_live("off", &mut ti, &mut hash_db, &mut yara);
        assert!(result.is_err());
    }

    #[test]
    fn poll_feed_live_unknown_source_errors() {
        let mut engine = FeedIngestionEngine::new();
        let mut ti = ThreatIntelStore::new();
        let mut hash_db = MalwareHashDb::new();
        let mut yara = YaraEngine::new();
        let result = engine.poll_feed_live("missing", &mut ti, &mut hash_db, &mut yara);
        assert!(result.is_err());
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
        assert!(ids.contains(&"feodo-tracker"));
        assert!(ids.contains(&"urlhaus-online"));
    }

    #[test]
    fn split_csv_line_handles_quotes() {
        let fields = split_csv_line(r#""2026-05-19 09:33:02", "abc", "n/a", "with, comma""#);
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0], "2026-05-19 09:33:02");
        assert_eq!(fields[3], "with, comma");
    }

    #[test]
    fn parse_malwarebazaar_csv_extracts_hashes() {
        let csv = concat!(
            "################################################################\n",
            "# MalwareBazaar recent malware samples (CSV)                   #\n",
            "#\n",
            "# \"first_seen_utc\",\"sha256_hash\",\"md5_hash\",\"sha1_hash\"\n",
            "\"2026-05-19 09:33:02\", \"f68e160f1af6992aa57eaca163e2fbb534369b862ddec67083cbdcacdc1466fe\", \"84442168d1f31869c5c2bbdae69b8a21\", \"9d5c4f46f2b8e68d2e2067c0ad9f70750f028943\", \"JAMESWT_WT\", \"sample.tar\", \"tar\", \"application/x-tar\", \"AgentTesla\", \"n/a\"\n",
        );
        let parsed = parse_malwarebazaar_csv(csv);
        assert_eq!(parsed.iocs.len(), 1);
        assert_eq!(parsed.malware_entries.len(), 1);
        assert_eq!(parsed.iocs[0].ioc_type, IoCType::FileHash);
        assert_eq!(parsed.malware_entries[0].family, "AgentTesla");
    }

    #[test]
    fn host_from_url_strips_scheme_port_path() {
        assert_eq!(
            host_from_url("http://evil.example.com/x"),
            Some("evil.example.com".into())
        );
        assert_eq!(
            host_from_url("http://203.0.113.7:59614/bin.sh"),
            Some("203.0.113.7".into())
        );
        assert_eq!(
            host_from_url("https://user:pw@bad.example.com:8443/p"),
            Some("bad.example.com".into())
        );
        assert_eq!(
            host_from_url("http://[2001:db8::1]:80/x"),
            Some("2001:db8::1".into())
        );
    }

    #[test]
    fn parse_urlhaus_json_extracts_hosts_from_urls() {
        // Real URLhaus json_online shape: no `host` field — host comes from `url`.
        let json = r#"{
            "3850011": [
                {"dateadded":"2026-05-19 10:45:20 UTC","url":"http://evil.example.com/x","url_status":"online","threat":"malware_download","tags":["elf","Mozi"]}
            ],
            "3850012": [
                {"dateadded":"2026-05-19 10:40:24 UTC","url":"http://203.0.113.7:46885/i","url_status":"online"}
            ]
        }"#;
        let iocs = parse_urlhaus_json(json);
        assert_eq!(iocs.len(), 2);
        assert!(
            iocs.iter()
                .any(|i| i.ioc_type == IoCType::Domain && i.value == "evil.example.com")
        );
        assert!(
            iocs.iter()
                .any(|i| i.ioc_type == IoCType::IpAddress && i.value == "203.0.113.7")
        );
    }

    #[test]
    fn parse_feodo_json_extracts_c2_ips() {
        let json = r#"[
            {"ip_address":"162.243.103.246","port":8080,"status":"offline","malware":"Emotet"},
            {"ip_address":"50.16.16.211","port":443,"status":"online","malware":"Dridex"},
            {"ip_address":"not-an-ip","malware":"Bad"}
        ]"#;
        let iocs = parse_feodo_json(json);
        assert_eq!(iocs.len(), 2);
        assert!(iocs.iter().all(|i| i.ioc_type == IoCType::IpAddress));
        assert!(iocs[0].tags.contains(&"botnet-c2".to_string()));
    }

    #[test]
    fn malwarebazaar_feed_ingests_end_to_end() {
        let mut engine = FeedIngestionEngine::new();
        let mut ti = ThreatIntelStore::new();
        let mut hash_db = MalwareHashDb::new();
        let mut yara = YaraEngine::new();

        engine.add_source(FeedSource {
            id: "mb".into(),
            name: "MalwareBazaar".into(),
            protocol: FeedProtocol::MalwareBazaar,
            url: "https://bazaar.abuse.ch/export/csv/recent/".into(),
            api_key: None,
            poll_interval_secs: 900,
            enabled: true,
            last_poll: None,
            last_success: None,
            iocs_ingested: 0,
            errors: vec![],
            collection_id: None,
        });

        let csv = "# header\n\"2026-05-19 09:33:02\", \"f68e160f1af6992aa57eaca163e2fbb534369b862ddec67083cbdcacdc1466fe\", \"84442168d1f31869c5c2bbdae69b8a21\", \"sha1\", \"rep\", \"f.exe\", \"exe\", \"application/x-dosexec\", \"AgentTesla\", \"n/a\"\n";
        let result = engine
            .poll_feed("mb", csv, &mut ti, &mut hash_db, &mut yara)
            .unwrap();
        assert_eq!(result.new_iocs, 1);
        assert_eq!(result.new_hashes, 1);
    }
}
