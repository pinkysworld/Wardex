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

// ── IoC Store & Matching ─────────────────────────────────────────────────────

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
    pub fn add_ioc(&mut self, ioc: IoC) {
        let key = format!("{:?}:{}", ioc.ioc_type, ioc.value);
        self.iocs.insert(key, ioc);
    }

    /// Check a value against all IoCs of a given type.
    pub fn check(&mut self, ioc_type: &IoCType, value: &str) -> MatchResult {
        let key = format!("{ioc_type:?}:{value}");
        let result = if let Some(ioc) = self.iocs.get(&key) {
            MatchResult {
                matched: true,
                ioc: Some(ioc.clone()),
                match_type: "exact".into(),
                context: format!("matched {ioc_type:?} indicator: {value}"),
            }
        } else {
            // Fuzzy matching for behavior patterns
            let partial = self.iocs.values().find(|ioc| {
                ioc.ioc_type == *ioc_type
                    && (value.contains(&ioc.value) || ioc.value.contains(value))
            });
            if let Some(ioc) = partial {
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
    pub fn correlate_signals(
        &mut self,
        signals: &[(String, f64)],
    ) -> Vec<MatchResult> {
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

    pub fn match_history(&self) -> &[MatchResult] {
        &self.match_history
    }

    pub fn feeds(&self) -> &[ThreatFeed] {
        &self.feeds
    }
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
        let fingerprint =
            sha256_hex(format!("decoy:{id}:{name}").as_bytes())[..32].to_string();
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

        // Track attacker
        self.attacker_map
            .entry(source_info.to_string())
            .or_default()
            .push(decoy_idx);

        Some(threat_score)
    }

    /// Generate a deception report with attacker profiles.
    pub fn report(&self) -> DeceptionReport {
        let total = self.decoys.len();
        let active = self.decoys.iter().filter(|d| d.deployed).count();
        let total_interactions: usize =
            self.decoys.iter().map(|d| d.interactions.len()).sum();
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
                    .flat_map(|d| d.interactions.iter().filter(|int| int.source_info == *source))
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
        let id = engine.deploy(
            DecoyType::Honeypot,
            "fake-ssh",
            "SSH honeypot on port 2222",
        );
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
        let id = engine.deploy(
            DecoyType::HoneyCredential,
            "admin-token",
            "Fake API token",
        );
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
        });

        let signals = vec![("cpu_load".to_string(), 95.0)];
        let matches = store.correlate_signals(&signals);
        assert_eq!(matches.len(), 1);
        assert!(matches[0].matched);
    }
}
