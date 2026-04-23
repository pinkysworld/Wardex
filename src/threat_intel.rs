//! Threat intelligence sharing and deception-based engagement.
//!
//! Implements indicator-of-compromise (IoC) management, threat feed
//! ingestion, intelligence correlation, honeypot deployment, and
//! attacker tracking with decoy services.
//! Covers R15 (threat intelligence sharing), R33 (deception engagement).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::audit::sha256_hex;

// ── Indicators of Compromise ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum IoCType {
    IpAddress,
    Domain,
    FileHash,
    ProcessName,
    BehaviorPattern,
    NetworkSignature,
    RegistryKey,
    Certificate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoC {
    pub ioc_type: IoCType,
    pub value: String,
    pub confidence: f32,
    pub severity: String,
    pub source: String,
    pub first_seen: String,
    pub last_seen: String,
    pub tags: Vec<String>,
    pub related_iocs: Vec<String>,
    #[serde(default)]
    pub metadata: IndicatorMetadata,
    #[serde(default)]
    pub sightings: Vec<IndicatorSighting>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFeed {
    pub feed_id: String,
    pub name: String,
    pub url: String,
    pub format: String,
    pub last_updated: String,
    pub ioc_count: usize,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndicatorMetadata {
    pub normalized_value: String,
    pub ttl_days: u64,
    pub source_weight: f32,
    pub confidence_decay: f32,
    #[serde(default)]
    pub last_sighting: Option<String>,
    #[serde(default)]
    pub sightings: u64,
}

impl Default for IndicatorMetadata {
    fn default() -> Self {
        Self {
            normalized_value: String::new(),
            ttl_days: 90,
            source_weight: 1.0,
            confidence_decay: 0.98,
            last_sighting: None,
            sightings: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndicatorSighting {
    pub timestamp: String,
    pub source: String,
    pub context: String,
    pub weight: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndicatorSightingRecord {
    pub ioc_type: IoCType,
    pub value: String,
    pub severity: String,
    pub confidence: f32,
    pub timestamp: String,
    pub source: String,
    pub context: String,
    pub weight: f32,
}

// ── IoC Store & Matching ─────────────────────────────────────────────────────

/// Enrichment statistics across the IoC store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoCEnrichmentStats {
    pub total_iocs: usize,
    pub by_type: HashMap<String, usize>,
    pub by_severity: HashMap<String, usize>,
    pub by_source: HashMap<String, usize>,
    pub avg_confidence: f32,
    pub active_feeds: usize,
    pub total_feeds: usize,
    pub match_history_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchResult {
    pub matched: bool,
    pub ioc: Option<IoC>,
    pub match_type: String,
    pub context: String,
}

#[derive(Debug)]
pub struct ThreatIntelStore {
    iocs: HashMap<String, IoC>,
    feeds: Vec<ThreatFeed>,
    match_history: Vec<MatchResult>,
}

impl Default for ThreatIntelStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatIntelStore {
    pub fn new() -> Self {
        Self {
            iocs: HashMap::new(),
            feeds: Vec::new(),
            match_history: Vec::new(),
        }
    }

    /// Add an IoC to the store.
    pub fn add_ioc(&mut self, mut ioc: IoC) {
        hydrate_ioc_metadata(&mut ioc);
        let key = format!(
            "{:?}:{}",
            ioc.ioc_type,
            normalize_ioc_value(&ioc.ioc_type, &ioc.value)
        );
        self.iocs.insert(key, ioc);
    }

    /// Check a value against all IoCs of a given type.
    pub fn check(&mut self, ioc_type: &IoCType, value: &str) -> MatchResult {
        let key = format!("{ioc_type:?}:{}", normalize_ioc_value(ioc_type, value));
        let result = if let Some(ioc) = self.iocs.get_mut(&key) {
            record_ioc_sighting(ioc, "match", &format!("matched {ioc_type:?} indicator: {value}"));
            MatchResult {
                matched: true,
                ioc: Some(ioc.clone()),
                match_type: "exact".into(),
                context: format!("matched {ioc_type:?} indicator: {value}"),
            }
        } else {
            // Fuzzy matching only for behavioral IoC types where substring
            // matching is meaningful. Structured types (IPs, hashes, domains)
            // require exact matches to avoid false positives.
            let partial = if matches!(
                ioc_type,
                IoCType::BehaviorPattern | IoCType::NetworkSignature
            ) {
                self.iocs.iter_mut().find_map(|(_, ioc)| {
                    if ioc.ioc_type == *ioc_type
                        && (value.contains(&ioc.value) || ioc.value.contains(value))
                    {
                        Some(ioc)
                    } else {
                        None
                    }
                })
            } else {
                None
            };
            if let Some(ioc) = partial {
                record_ioc_sighting(ioc, "partial_match", &format!("partial match on {ioc_type:?}: {value}"));
                MatchResult {
                    matched: true,
                    ioc: Some(ioc.clone()),
                    match_type: "partial".into(),
                    context: format!("partial match on {ioc_type:?}: {value}"),
                }
            } else {
                MatchResult {
                    matched: false,
                    ioc: None,
                    match_type: "none".into(),
                    context: format!("no match for {ioc_type:?}: {value}"),
                }
            }
        };
        self.match_history.push(result.clone());
        result
    }

    /// Correlate telemetry signals with known IoCs.
    pub fn correlate_signals(&mut self, signals: &[(String, f64)]) -> Vec<MatchResult> {
        let mut results = Vec::new();
        for (signal_name, value) in signals {
            // Check if signal pattern matches a behavior IoC
            let pattern = format!("{signal_name}:{value:.1}");
            let result = self.check(&IoCType::BehaviorPattern, &pattern);
            if result.matched {
                results.push(result);
            }
        }
        results
    }

    /// Register a threat feed source.
    pub fn register_feed(&mut self, feed: ThreatFeed) {
        self.feeds.push(feed);
    }

    /// Ingest IoCs from a JSON-lines string (simulating a feed update).
    pub fn ingest_feed(&mut self, feed_id: &str, data: &str) -> usize {
        let mut count = 0;
        for line in data.lines() {
            if let Ok(ioc) = serde_json::from_str::<IoC>(line.trim()) {
                self.add_ioc(ioc);
                count += 1;
            }
        }
        // Update feed metadata
        if let Some(feed) = self.feeds.iter_mut().find(|f| f.feed_id == feed_id) {
            feed.ioc_count += count;
            feed.last_updated = chrono::Utc::now().to_rfc3339();
        }
        count
    }

    pub fn ioc_count(&self) -> usize {
        self.iocs.len()
    }

    pub fn all_iocs(&self) -> Vec<IoC> {
        self.iocs.values().cloned().collect()
    }

    pub fn recent_sightings(&self, limit: usize) -> Vec<IndicatorSightingRecord> {
        let mut sightings = self.all_sightings();
        sightings.sort_by(|left, right| right.timestamp.cmp(&left.timestamp));
        sightings.into_iter().take(limit).collect()
    }

    pub fn all_sightings(&self) -> Vec<IndicatorSightingRecord> {
        let mut records = Vec::new();
        for ioc in self.iocs.values() {
            for sighting in &ioc.sightings {
                records.push(IndicatorSightingRecord {
                    ioc_type: ioc.ioc_type.clone(),
                    value: ioc.value.clone(),
                    severity: ioc.severity.clone(),
                    confidence: ioc.confidence,
                    timestamp: sighting.timestamp.clone(),
                    source: sighting.source.clone(),
                    context: sighting.context.clone(),
                    weight: sighting.weight,
                });
            }
        }
        records
    }

    pub fn match_history(&self) -> &[MatchResult] {
        &self.match_history
    }

    pub fn feeds(&self) -> &[ThreatFeed] {
        &self.feeds
    }

    /// Ingest IoCs from a STIX 2.1 JSON bundle.
    /// Extracts indicators from the `objects` array where `type == "indicator"`.
    pub fn ingest_stix_bundle(&mut self, feed_id: &str, json_data: &str) -> usize {
        let parsed: serde_json::Value = match serde_json::from_str(json_data) {
            Ok(v) => v,
            Err(_) => return 0,
        };
        let objects = match parsed.get("objects").and_then(|o| o.as_array()) {
            Some(arr) => arr,
            None => return 0,
        };
        let mut count = 0;
        for obj in objects {
            if obj.get("type").and_then(|t| t.as_str()) != Some("indicator") {
                continue;
            }
            let pattern = match obj.get("pattern").and_then(|p| p.as_str()) {
                Some(p) => p,
                None => continue,
            };
            // Parse simple STIX patterns like [ipv4-addr:value = '1.2.3.4']
            let (ioc_type, value) = match parse_stix_pattern(pattern) {
                Some(pair) => pair,
                None => continue,
            };
            let name = obj.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let confidence = obj
                .get("confidence")
                .and_then(|c| c.as_f64())
                .unwrap_or(50.0) as f32
                / 100.0;
            let now = chrono::Utc::now().to_rfc3339();
            let ioc = IoC {
                ioc_type,
                value,
                confidence,
                severity: if confidence > 0.7 { "high" } else { "medium" }.into(),
                source: feed_id.to_string(),
                first_seen: obj
                    .get("created")
                    .and_then(|c| c.as_str())
                    .unwrap_or(&now)
                    .to_string(),
                last_seen: obj
                    .get("modified")
                    .and_then(|m| m.as_str())
                    .unwrap_or(&now)
                    .to_string(),
                tags: obj
                    .get("labels")
                    .and_then(|l| l.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default(),
                related_iocs: vec![],
                metadata: IndicatorMetadata::default(),
                sightings: Vec::new(),
            };
            self.add_ioc(ioc);
            count += 1;
            let _ = name; // used in source context
        }
        if let Some(feed) = self.feeds.iter_mut().find(|f| f.feed_id == feed_id) {
            feed.ioc_count += count;
            feed.last_updated = chrono::Utc::now().to_rfc3339();
            feed.format = "stix2.1".to_string();
        }
        count
    }

    /// Batch-check multiple values against the IoC store.
    /// Returns only matches (filters out non-matches).
    pub fn batch_check(&mut self, checks: &[(IoCType, String)]) -> Vec<MatchResult> {
        checks
            .iter()
            .map(|(ioc_type, value)| self.check(ioc_type, value))
            .filter(|r| r.matched)
            .collect()
    }

    /// Get IoCs expiring before a given timestamp (for feed rotation).
    pub fn expiring_iocs(&self, before: &str) -> Vec<&IoC> {
        let before_ts = chrono::DateTime::parse_from_rfc3339(before)
            .ok()
            .map(|ts| ts.with_timezone(&chrono::Utc));
        self.iocs
            .values()
            .filter(|ioc| {
                match (
                    before_ts.as_ref(),
                    chrono::DateTime::parse_from_rfc3339(&ioc.last_seen)
                        .ok()
                        .map(|ts| ts.with_timezone(&chrono::Utc)),
                ) {
                    (Some(before_ts), Some(last_seen)) => last_seen < *before_ts,
                    (None, None) => ioc.last_seen.as_str() < before,
                    _ => false,
                }
            })
            .collect()
    }

    /// Purge IoCs whose `last_seen` is older than `ttl_days` from `now`.
    /// Returns the number of IoCs removed.
    pub fn purge_expired(&mut self, now: &str, ttl_days: u64) -> usize {
        let now_ts = match chrono::DateTime::parse_from_rfc3339(now) {
            Ok(ts) => ts.with_timezone(&chrono::Utc),
            Err(_) => return 0,
        };
        let cutoff = now_ts - chrono::Duration::days(ttl_days as i64);
        let before = self.iocs.len();
        self.iocs.retain(|_, ioc| {
            match chrono::DateTime::parse_from_rfc3339(&ioc.last_seen) {
                Ok(ts) => ts.with_timezone(&chrono::Utc) >= cutoff,
                Err(_) => true, // Keep IoCs with unparseable timestamps
            }
        });
        before - self.iocs.len()
    }

    /// Compute enrichment statistics across all IoCs.
    pub fn enrichment_stats(&self) -> IoCEnrichmentStats {
        let mut by_type: HashMap<String, usize> = HashMap::new();
        let mut by_severity: HashMap<String, usize> = HashMap::new();
        let mut by_source: HashMap<String, usize> = HashMap::new();
        let mut total_confidence: f32 = 0.0;

        for ioc in self.iocs.values() {
            *by_type.entry(format!("{:?}", ioc.ioc_type)).or_insert(0) += 1;
            *by_severity.entry(ioc.severity.clone()).or_insert(0) += 1;
            *by_source.entry(ioc.source.clone()).or_insert(0) += 1;
            total_confidence += ioc.confidence;
        }

        let total = self.iocs.len();
        IoCEnrichmentStats {
            total_iocs: total,
            by_type,
            by_severity,
            by_source,
            avg_confidence: if total > 0 {
                total_confidence / total as f32
            } else {
                0.0
            },
            active_feeds: self.feeds.iter().filter(|f| f.active).count(),
            total_feeds: self.feeds.len(),
            match_history_size: self.match_history.len(),
        }
    }
}

fn normalize_ioc_value(ioc_type: &IoCType, value: &str) -> String {
    let trimmed = value.trim();
    match ioc_type {
        IoCType::Domain
        | IoCType::FileHash
        | IoCType::ProcessName
        | IoCType::BehaviorPattern
        | IoCType::NetworkSignature
        | IoCType::RegistryKey
        | IoCType::Certificate => trimmed.to_ascii_lowercase(),
        IoCType::IpAddress => trimmed.to_string(),
    }
}

fn default_source_weight(source: &str) -> f32 {
    let normalized = source.trim().to_ascii_lowercase();
    if normalized.contains("internal") || normalized.contains("misp") {
        1.2
    } else if normalized.contains("community") || normalized.contains("public") {
        0.9
    } else {
        1.0
    }
}

fn hydrate_ioc_metadata(ioc: &mut IoC) {
    if ioc.metadata.normalized_value.is_empty() {
        ioc.metadata.normalized_value = normalize_ioc_value(&ioc.ioc_type, &ioc.value);
    }
    if ioc.metadata.ttl_days == 0 {
        ioc.metadata.ttl_days = 90;
    }
    if ioc.metadata.source_weight <= 0.0 {
        ioc.metadata.source_weight = default_source_weight(&ioc.source);
    }
    if ioc.metadata.confidence_decay <= 0.0 {
        ioc.metadata.confidence_decay = 0.98;
    }
    if ioc.metadata.sightings == 0 && !ioc.sightings.is_empty() {
        ioc.metadata.sightings = ioc.sightings.len() as u64;
    }
}

fn record_ioc_sighting(ioc: &mut IoC, source: &str, context: &str) {
    hydrate_ioc_metadata(ioc);
    let now = chrono::Utc::now().to_rfc3339();
    ioc.last_seen = now.clone();
    ioc.metadata.last_sighting = Some(now.clone());
    ioc.metadata.sightings = ioc.metadata.sightings.saturating_add(1);
    ioc.sightings.push(IndicatorSighting {
        timestamp: now,
        source: source.to_string(),
        context: context.to_string(),
        weight: ioc.metadata.source_weight,
    });
    if ioc.sightings.len() > 64 {
        let drop_count = ioc.sightings.len() - 64;
        ioc.sightings.drain(0..drop_count);
    }
    let confidence_boost = 0.02 * ioc.metadata.source_weight.max(0.2);
    ioc.confidence = (ioc.confidence + confidence_boost).clamp(0.0, 1.0);
}

/// Parse a simple STIX 2.1 indicator pattern.
/// Supports: `[ipv4-addr:value = 'x']`, `[domain-name:value = 'x']`,
/// `[file:hashes.'SHA-256' = 'x']`, `[process:name = 'x']`.
fn parse_stix_pattern(pattern: &str) -> Option<(IoCType, String)> {
    let inner = pattern.trim().trim_start_matches('[').trim_end_matches(']');
    let (obj_path, value_part) = inner.split_once('=')?;
    let obj_path = obj_path.trim();
    let value = value_part
        .trim()
        .trim_matches('\'')
        .trim_matches('"')
        .to_string();
    if value.is_empty() {
        return None;
    }
    let ioc_type = if obj_path.starts_with("ipv4-addr") || obj_path.starts_with("ipv6-addr") {
        IoCType::IpAddress
    } else if obj_path.starts_with("domain-name") {
        IoCType::Domain
    } else if obj_path.contains("hashes") {
        IoCType::FileHash
    } else if obj_path.starts_with("process") {
        IoCType::ProcessName
    } else if obj_path.starts_with("network-traffic") {
        IoCType::NetworkSignature
    } else if obj_path.starts_with("windows-registry-key") {
        IoCType::RegistryKey
    } else if obj_path.starts_with("x509-certificate") {
        IoCType::Certificate
    } else {
        IoCType::BehaviorPattern
    };
    Some((ioc_type, value))
}

// ── Deception Engine (R33) ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DecoyType {
    Honeypot,
    HoneyFile,
    HoneyCredential,
    HoneyService,
    Canary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decoy {
    pub id: String,
    pub decoy_type: DecoyType,
    pub name: String,
    pub description: String,
    pub deployed: bool,
    pub interactions: Vec<DecoyInteraction>,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoyInteraction {
    pub timestamp: String,
    pub source_info: String,
    pub action: String,
    pub detail: String,
    pub threat_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeceptionReport {
    pub total_decoys: usize,
    pub active_decoys: usize,
    pub total_interactions: usize,
    pub high_threat_interactions: usize,
    pub attacker_profiles: Vec<AttackerProfile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackerProfile {
    pub source_id: String,
    pub interaction_count: usize,
    pub decoys_touched: Vec<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub threat_score: f32,
}

/// Deception engine managing honeypots, honey files, and canary tokens.
#[derive(Debug)]
pub struct DeceptionEngine {
    decoys: Vec<Decoy>,
    attacker_map: HashMap<String, Vec<usize>>, // source → decoy indices
}

impl Default for DeceptionEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DeceptionEngine {
    pub fn new() -> Self {
        Self {
            decoys: Vec::new(),
            attacker_map: HashMap::new(),
        }
    }

    /// Deploy a new decoy.
    pub fn deploy(&mut self, decoy_type: DecoyType, name: &str, description: &str) -> String {
        let id = sha256_hex(format!("{name}:{:?}:{}", decoy_type, self.decoys.len()).as_bytes())
            [..16]
            .to_string();
        let fingerprint = sha256_hex(format!("decoy:{id}:{name}").as_bytes())[..32].to_string();
        self.decoys.push(Decoy {
            id: id.clone(),
            decoy_type,
            name: name.to_string(),
            description: description.to_string(),
            deployed: true,
            interactions: Vec::new(),
            fingerprint,
        });
        id
    }

    /// Record an interaction with a decoy (attacker touched it).
    pub fn record_interaction(
        &mut self,
        decoy_id: &str,
        source_info: &str,
        action: &str,
        detail: &str,
    ) -> Option<f32> {
        let decoy_idx = self.decoys.iter().position(|d| d.id == decoy_id)?;

        // Threat score increases with repeated interactions
        let prior_count = self.decoys[decoy_idx].interactions.len();
        let threat_score = match self.decoys[decoy_idx].decoy_type {
            DecoyType::Honeypot => 5.0 + prior_count as f32 * 0.5,
            DecoyType::HoneyFile => 3.0 + prior_count as f32 * 1.0,
            DecoyType::HoneyCredential => 8.0 + prior_count as f32 * 2.0,
            DecoyType::HoneyService => 4.0 + prior_count as f32 * 0.8,
            DecoyType::Canary => 6.0 + prior_count as f32 * 1.5,
        };

        let interaction = DecoyInteraction {
            timestamp: chrono::Utc::now().to_rfc3339(),
            source_info: source_info.to_string(),
            action: action.to_string(),
            detail: detail.to_string(),
            threat_score,
        };
        self.decoys[decoy_idx].interactions.push(interaction);

        // Track attacker (deduplicate decoy indices)
        let entry = self
            .attacker_map
            .entry(source_info.to_string())
            .or_default();
        if !entry.contains(&decoy_idx) {
            entry.push(decoy_idx);
        }

        Some(threat_score)
    }

    /// Generate a deception report with attacker profiles.
    pub fn report(&self) -> DeceptionReport {
        let total = self.decoys.len();
        let active = self.decoys.iter().filter(|d| d.deployed).count();
        let total_interactions: usize = self.decoys.iter().map(|d| d.interactions.len()).sum();
        let high_threat = self
            .decoys
            .iter()
            .flat_map(|d| &d.interactions)
            .filter(|i| i.threat_score >= 7.0)
            .count();

        let profiles: Vec<AttackerProfile> = self
            .attacker_map
            .iter()
            .map(|(source, indices)| {
                let decoys_touched: Vec<String> = indices
                    .iter()
                    .filter_map(|&i| self.decoys.get(i).map(|d| d.name.clone()))
                    .collect();
                let interactions: Vec<&DecoyInteraction> = indices
                    .iter()
                    .filter_map(|&i| self.decoys.get(i))
                    .flat_map(|d| {
                        d.interactions
                            .iter()
                            .filter(|int| int.source_info == *source)
                    })
                    .collect();
                let max_score = interactions
                    .iter()
                    .map(|i| i.threat_score)
                    .fold(0.0_f32, f32::max);

                AttackerProfile {
                    source_id: source.clone(),
                    interaction_count: interactions.len(),
                    decoys_touched,
                    first_seen: interactions
                        .first()
                        .map(|i| i.timestamp.clone())
                        .unwrap_or_default(),
                    last_seen: interactions
                        .last()
                        .map(|i| i.timestamp.clone())
                        .unwrap_or_default(),
                    threat_score: max_score,
                }
            })
            .collect();

        DeceptionReport {
            total_decoys: total,
            active_decoys: active,
            total_interactions,
            high_threat_interactions: high_threat,
            attacker_profiles: profiles,
        }
    }

    pub fn decoys(&self) -> &[Decoy] {
        &self.decoys
    }

    /// Deactivate a decoy.
    pub fn deactivate(&mut self, decoy_id: &str) -> bool {
        if let Some(decoy) = self.decoys.iter_mut().find(|d| d.id == decoy_id) {
            decoy.deployed = false;
            true
        } else {
            false
        }
    }

    /// Deploy a randomised canary set: one of each decoy type with
    /// generated names. Returns the IDs of the deployed decoys.
    pub fn deploy_random_canary_set(&mut self) -> Vec<String> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let suffix: u32 = rng.r#gen::<u32>() % 10000;
        let configs = [
            (
                DecoyType::Honeypot,
                format!("ssh-{suffix}"),
                "Auto-deployed SSH honeypot".to_string(),
            ),
            (
                DecoyType::HoneyFile,
                format!("credentials-{suffix}.txt"),
                "Auto-deployed honey file".to_string(),
            ),
            (
                DecoyType::HoneyCredential,
                format!("api-key-{suffix}"),
                "Auto-deployed honey credential".to_string(),
            ),
            (
                DecoyType::HoneyService,
                format!("svc-internal-{suffix}"),
                "Auto-deployed honey service".to_string(),
            ),
            (
                DecoyType::Canary,
                format!("canary-token-{suffix}"),
                "Auto-deployed canary token".to_string(),
            ),
        ];
        configs
            .into_iter()
            .map(|(dt, name, desc)| self.deploy(dt, &name, &desc))
            .collect()
    }

    /// Build an attacker behavior profile from interaction history,
    /// reconstructing the likely attack path across decoys.
    pub fn attacker_behavior_profile(&self, source_id: &str) -> Option<AttackerProfile> {
        let indices = self.attacker_map.get(source_id)?;
        let interactions: Vec<&DecoyInteraction> = indices
            .iter()
            .filter_map(|&i| self.decoys.get(i))
            .flat_map(|d| {
                d.interactions
                    .iter()
                    .filter(|int| int.source_info == source_id)
            })
            .collect();
        if interactions.is_empty() {
            return None;
        }
        let decoys_touched: Vec<String> = indices
            .iter()
            .filter_map(|&i| self.decoys.get(i).map(|d| d.name.clone()))
            .collect();
        let max_score = interactions
            .iter()
            .map(|i| i.threat_score)
            .fold(0.0_f32, f32::max);
        Some(AttackerProfile {
            source_id: source_id.to_string(),
            interaction_count: interactions.len(),
            decoys_touched,
            first_seen: interactions
                .first()
                .map(|i| i.timestamp.clone())
                .unwrap_or_default(),
            last_seen: interactions
                .last()
                .map(|i| i.timestamp.clone())
                .unwrap_or_default(),
            threat_score: max_score,
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioc_store_exact_match() {
        let mut store = ThreatIntelStore::new();
        store.add_ioc(IoC {
            ioc_type: IoCType::IpAddress,
            value: "10.0.0.99".into(),
            confidence: 0.95,
            severity: "critical".into(),
            source: "internal".into(),
            first_seen: "T0".into(),
            last_seen: "T1".into(),
            tags: vec!["c2".into()],
            related_iocs: vec![],
            metadata: IndicatorMetadata::default(),
            sightings: Vec::new(),
        });

        let result = store.check(&IoCType::IpAddress, "10.0.0.99");
        assert!(result.matched);
        assert_eq!(result.match_type, "exact");
    }

    #[test]
    fn ioc_store_no_match() {
        let mut store = ThreatIntelStore::new();
        let result = store.check(&IoCType::IpAddress, "192.168.1.1");
        assert!(!result.matched);
    }

    #[test]
    fn ioc_partial_match() {
        let mut store = ThreatIntelStore::new();
        store.add_ioc(IoC {
            ioc_type: IoCType::BehaviorPattern,
            value: "auth_burst".into(),
            confidence: 0.8,
            severity: "elevated".into(),
            source: "research".into(),
            first_seen: "T0".into(),
            last_seen: "T1".into(),
            tags: vec![],
            related_iocs: vec![],
            metadata: IndicatorMetadata::default(),
            sightings: Vec::new(),
        });

        let result = store.check(&IoCType::BehaviorPattern, "auth_burst_detected");
        assert!(result.matched);
        assert_eq!(result.match_type, "partial");
    }

    #[test]
    fn threat_feed_registration() {
        let mut store = ThreatIntelStore::new();
        store.register_feed(ThreatFeed {
            feed_id: "feed-1".into(),
            name: "Internal TI".into(),
            url: "https://ti.internal/feed".into(),
            format: "jsonl".into(),
            last_updated: String::new(),
            ioc_count: 0,
            active: true,
        });
        assert_eq!(store.feeds().len(), 1);
    }

    #[test]
    fn deception_engine_deploy_and_interact() {
        let mut engine = DeceptionEngine::new();
        let id = engine.deploy(DecoyType::Honeypot, "fake-ssh", "SSH honeypot on port 2222");
        assert!(!id.is_empty());
        assert_eq!(engine.decoys().len(), 1);

        let score = engine.record_interaction(
            &id,
            "attacker-1",
            "connection",
            "SSH login attempt with root",
        );
        assert!(score.is_some());
        assert!(score.unwrap() >= 5.0);
    }

    #[test]
    fn deception_engine_tracks_attackers() {
        let mut engine = DeceptionEngine::new();
        let hp = engine.deploy(DecoyType::Honeypot, "fake-http", "HTTP honeypot");
        let hf = engine.deploy(DecoyType::HoneyFile, "passwords.txt", "Canary file");

        engine.record_interaction(&hp, "attacker-X", "scan", "port scan");
        engine.record_interaction(&hf, "attacker-X", "read", "file access");
        engine.record_interaction(&hp, "attacker-Y", "connect", "HTTP GET");

        let report = engine.report();
        assert_eq!(report.total_decoys, 2);
        assert_eq!(report.total_interactions, 3);
        assert_eq!(report.attacker_profiles.len(), 2);

        let attacker_x = report
            .attacker_profiles
            .iter()
            .find(|p| p.source_id == "attacker-X")
            .unwrap();
        assert_eq!(attacker_x.interaction_count, 2);
        assert_eq!(attacker_x.decoys_touched.len(), 2);
    }

    #[test]
    fn honey_credential_high_threat() {
        let mut engine = DeceptionEngine::new();
        let id = engine.deploy(DecoyType::HoneyCredential, "admin-token", "Fake API token");
        let score = engine
            .record_interaction(&id, "insider", "use", "API call with fake token")
            .unwrap();
        // HoneyCredential starts at 8.0
        assert!(score >= 8.0);
    }

    #[test]
    fn deactivate_decoy() {
        let mut engine = DeceptionEngine::new();
        let id = engine.deploy(DecoyType::Canary, "canary-dns", "DNS canary");
        assert!(engine.decoys()[0].deployed);

        engine.deactivate(&id);
        assert!(!engine.decoys()[0].deployed);
    }

    #[test]
    fn deception_report_aggregation() {
        let mut engine = DeceptionEngine::new();
        let id = engine.deploy(DecoyType::HoneyCredential, "cred", "fake cred");
        // Generate multiple interactions to trigger high-threat
        engine.record_interaction(&id, "apt-group", "auth", "credential use");
        engine.record_interaction(&id, "apt-group", "auth", "second use");

        let report = engine.report();
        assert!(report.high_threat_interactions > 0);
    }

    #[test]
    fn signal_correlation_with_iocs() {
        let mut store = ThreatIntelStore::new();
        store.add_ioc(IoC {
            ioc_type: IoCType::BehaviorPattern,
            value: "cpu_load:95.0".into(),
            confidence: 0.7,
            severity: "elevated".into(),
            source: "ml-model".into(),
            first_seen: "T0".into(),
            last_seen: "T1".into(),
            tags: vec!["crypto-mining".into()],
            related_iocs: vec![],
            metadata: IndicatorMetadata::default(),
            sightings: Vec::new(),
        });

        let signals = vec![("cpu_load".to_string(), 95.0)];
        let matches = store.correlate_signals(&signals);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].matched);
    }

    #[test]
    fn random_canary_set_deploys_five() {
        let mut engine = DeceptionEngine::new();
        let ids = engine.deploy_random_canary_set();
        assert_eq!(ids.len(), 5);
        assert_eq!(engine.decoys().len(), 5);
    }

    #[test]
    fn attacker_behavior_profile_works() {
        let mut engine = DeceptionEngine::new();
        let hp = engine.deploy(DecoyType::Honeypot, "ssh", "SSH");
        let hf = engine.deploy(DecoyType::HoneyFile, "secrets.txt", "File");
        engine.record_interaction(&hp, "apt-1", "ssh_login", "root login attempt");
        engine.record_interaction(&hf, "apt-1", "file_read", "read secrets.txt");

        let profile = engine.attacker_behavior_profile("apt-1").unwrap();
        assert_eq!(profile.interaction_count, 2);
        assert_eq!(profile.decoys_touched.len(), 2);
        assert!(profile.threat_score > 0.0);
    }

    #[test]
    fn feed_polling_roundtrip() {
        let mut store = ThreatIntelStore::new();
        store.register_feed(ThreatFeed {
            feed_id: "test-feed".into(),
            name: "Test".into(),
            url: "https://example.com".into(),
            format: "jsonl".into(),
            last_updated: String::new(),
            ioc_count: 0,
            active: true,
        });
        // Simulate polling with inline data
        let data = r#"{"ioc_type":"IpAddress","value":"203.0.113.50","confidence":0.9,"severity":"critical","source":"feed","first_seen":"T0","last_seen":"T1","tags":[],"related_iocs":[]}"#;
        let count = store.ingest_feed("test-feed", data);
        assert_eq!(count, 1);
        let m = store.check(&IoCType::IpAddress, "203.0.113.50");
        assert!(m.matched);
    }

    #[test]
    fn stix_bundle_ingestion() {
        let mut store = ThreatIntelStore::new();
        store.register_feed(ThreatFeed {
            feed_id: "stix-feed".into(),
            name: "STIX Test".into(),
            url: "https://example.com/stix".into(),
            format: "stix2.1".into(),
            last_updated: String::new(),
            ioc_count: 0,
            active: true,
        });

        let bundle = r#"{
            "type": "bundle",
            "id": "bundle--001",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--001",
                    "name": "Malicious IP",
                    "pattern": "[ipv4-addr:value = '198.51.100.42']",
                    "confidence": 85,
                    "labels": ["malware", "c2"]
                },
                {
                    "type": "indicator",
                    "id": "indicator--002",
                    "name": "Bad domain",
                    "pattern": "[domain-name:value = 'evil.example.com']",
                    "confidence": 70
                },
                {
                    "type": "malware",
                    "id": "malware--001",
                    "name": "Not an indicator"
                }
            ]
        }"#;

        let count = store.ingest_stix_bundle("stix-feed", bundle);
        assert_eq!(count, 2);
        assert_eq!(store.ioc_count(), 2);

        // Check the IP IoC
        let m = store.check(&IoCType::IpAddress, "198.51.100.42");
        assert!(m.matched);
        assert_eq!(m.match_type, "exact");
        let ioc = m.ioc.unwrap();
        assert!(ioc.tags.contains(&"malware".to_string()));
        assert!(ioc.confidence > 0.8);

        // Check the domain IoC
        let m2 = store.check(&IoCType::Domain, "evil.example.com");
        assert!(m2.matched);
    }

    #[test]
    fn stix_pattern_parsing() {
        let cases = vec![
            (
                "[ipv4-addr:value = '1.2.3.4']",
                IoCType::IpAddress,
                "1.2.3.4",
            ),
            (
                "[domain-name:value = 'test.com']",
                IoCType::Domain,
                "test.com",
            ),
            (
                "[file:hashes.'SHA-256' = 'abc123']",
                IoCType::FileHash,
                "abc123",
            ),
            (
                "[process:name = 'evil.exe']",
                IoCType::ProcessName,
                "evil.exe",
            ),
        ];
        for (pattern, expected_type, expected_value) in cases {
            let (ioc_type, value) =
                parse_stix_pattern(pattern).unwrap_or_else(|| panic!("failed to parse: {pattern}"));
            assert_eq!(ioc_type, expected_type);
            assert_eq!(value, expected_value);
        }
    }

    #[test]
    fn batch_check_returns_only_matches() {
        let mut store = ThreatIntelStore::new();
        store.add_ioc(IoC {
            ioc_type: IoCType::IpAddress,
            value: "10.0.0.1".into(),
            confidence: 0.9,
            severity: "high".into(),
            source: "test".into(),
            first_seen: "t0".into(),
            last_seen: "t1".into(),
            tags: vec![],
            related_iocs: vec![],
            metadata: IndicatorMetadata::default(),
            sightings: Vec::new(),
        });

        let checks = vec![
            (IoCType::IpAddress, "10.0.0.1".into()),
            (IoCType::IpAddress, "10.0.0.2".into()),
            (IoCType::Domain, "safe.example.com".into()),
        ];
        let results = store.batch_check(&checks);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].ioc.as_ref().unwrap().value, "10.0.0.1");
    }

    #[test]
    fn expiring_iocs_uses_timestamp_order_not_string_order() {
        let mut store = ThreatIntelStore::new();
        store.add_ioc(IoC {
            ioc_type: IoCType::IpAddress,
            value: "203.0.113.5".into(),
            confidence: 0.8,
            severity: "medium".into(),
            source: "test".into(),
            first_seen: "2026-04-03T22:00:00Z".into(),
            last_seen: "2026-04-04T01:00:00+02:00".into(),
            tags: vec![],
            related_iocs: vec![],
            metadata: IndicatorMetadata::default(),
            sightings: Vec::new(),
        });

        let expiring = store.expiring_iocs("2026-04-03T23:30:00Z");
        assert_eq!(
            expiring.len(),
            1,
            "offset-aware comparison should treat 01:00+02:00 as earlier than 23:30Z"
        );
    }

    #[test]
    fn expiring_iocs_does_not_mix_parsed_and_lexicographic_fallbacks() {
        let mut store = ThreatIntelStore::new();
        store.add_ioc(IoC {
            ioc_type: IoCType::Domain,
            value: "mixed-mode.example".into(),
            confidence: 0.7,
            severity: "low".into(),
            source: "test".into(),
            first_seen: "2026-04-03T22:00:00Z".into(),
            last_seen: "garbage".into(),
            tags: vec![],
            related_iocs: vec![],
            metadata: IndicatorMetadata::default(),
            sightings: Vec::new(),
        });

        let expiring = store.expiring_iocs("2026-04-03T23:30:00Z");
        assert!(
            expiring.is_empty(),
            "invalid IoC timestamps should not be expired by mixed-mode fallback when cutoff is RFC3339"
        );
    }

    #[test]
    fn purge_expired_removes_old_iocs() {
        let mut store = ThreatIntelStore::new();
        store.add_ioc(IoC {
            ioc_type: IoCType::IpAddress,
            value: "10.0.0.1".into(),
            confidence: 0.9,
            severity: "high".into(),
            source: "test".into(),
            first_seen: "2026-01-01T00:00:00Z".into(),
            last_seen: "2026-01-01T00:00:00Z".into(),
            tags: vec![],
            related_iocs: vec![],
            metadata: IndicatorMetadata::default(),
            sightings: Vec::new(),
        });
        store.add_ioc(IoC {
            ioc_type: IoCType::IpAddress,
            value: "10.0.0.2".into(),
            confidence: 0.9,
            severity: "high".into(),
            source: "test".into(),
            first_seen: "2026-04-01T00:00:00Z".into(),
            last_seen: "2026-04-01T00:00:00Z".into(),
            tags: vec![],
            related_iocs: vec![],
            metadata: IndicatorMetadata::default(),
            sightings: Vec::new(),
        });
        assert_eq!(store.ioc_count(), 2);
        let purged = store.purge_expired("2026-04-05T00:00:00Z", 30);
        assert_eq!(purged, 1); // Jan IoC is > 30 days old
        assert_eq!(store.ioc_count(), 1);
    }

    #[test]
    fn enrichment_stats_populated() {
        let mut store = ThreatIntelStore::new();
        store.add_ioc(IoC {
            ioc_type: IoCType::IpAddress,
            value: "10.0.0.1".into(),
            confidence: 0.9,
            severity: "high".into(),
            source: "feed-a".into(),
            first_seen: "t0".into(),
            last_seen: "t1".into(),
            tags: vec![],
            related_iocs: vec![],
            metadata: IndicatorMetadata::default(),
            sightings: Vec::new(),
        });
        store.add_ioc(IoC {
            ioc_type: IoCType::Domain,
            value: "evil.com".into(),
            confidence: 0.7,
            severity: "medium".into(),
            source: "feed-b".into(),
            first_seen: "t0".into(),
            last_seen: "t1".into(),
            tags: vec![],
            related_iocs: vec![],
            metadata: IndicatorMetadata::default(),
            sightings: Vec::new(),
        });
        let stats = store.enrichment_stats();
        assert_eq!(stats.total_iocs, 2);
        assert_eq!(stats.by_type.len(), 2);
        assert_eq!(stats.by_source.len(), 2);
        assert!((stats.avg_confidence - 0.8).abs() < 0.01);
    }
}
