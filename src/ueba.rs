//! User and Entity Behavior Analytics (UEBA) engine.
//!
//! Tracks per-user and per-entity (host, IP, process) behavioral baselines using
//! EWMA smoothing (same approach as `AnomalyDetector`), detects deviations from
//! learned patterns, and assigns cumulative risk scores with time-based decay.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Configuration ───────────────────────────────────────────────

/// UEBA engine configuration.
#[derive(Debug, Clone)]
pub struct UebaConfig {
    /// EWMA smoothing factor (0–1). Higher = more weight to recent observations.
    pub alpha: f32,
    /// Number of observations before baseline is considered ready.
    pub warmup_observations: usize,
    /// Risk score decay per hour (multiplied each hour of inactivity).
    pub risk_decay_per_hour: f32,
    /// Threshold for flagging an anomaly (0–100).
    pub anomaly_threshold: f32,
    /// Maximum risk score (cap).
    pub max_risk: f32,
}

impl Default for UebaConfig {
    fn default() -> Self {
        Self {
            alpha: 0.15,
            warmup_observations: 10,
            risk_decay_per_hour: 0.95,
            anomaly_threshold: 65.0,
            max_risk: 100.0,
        }
    }
}

// ── Anomaly types ───────────────────────────────────────────────

/// Types of behavioral anomalies detected by the UEBA engine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum UebaAnomalyType {
    /// Login from impossible geographic distance given time delta.
    ImpossibleTravel,
    /// Login at unusual hour for this user's baseline pattern.
    UnusualLoginTime,
    /// Access to resource not in this user's normal pattern.
    AnomalousAccess,
    /// Sequence of privilege escalation steps detected.
    PrivilegeEscalationChain,
    /// Data volume or transfer pattern consistent with exfiltration.
    DataExfiltrationPattern,
    /// Evidence of lateral movement across hosts.
    LateralMovement,
    /// Unusual process execution for this host.
    AnomalousProcess,
    /// Deviation from normal service/port pattern for entity.
    ServiceAnomaly,
    /// Unusual data volume for this entity.
    DataVolumeAnomaly,
    /// First-time activity (new user, process, or service).
    FirstTimeActivity,
}

/// A detected behavioral anomaly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UebaAnomaly {
    pub anomaly_type: UebaAnomalyType,
    pub entity_kind: EntityKind,
    pub entity_id: String,
    pub score: f32,
    pub description: String,
    pub timestamp_ms: u64,
    pub evidence: Vec<String>,
    pub mitre_technique: Option<String>,
}

// ── Entity model ────────────────────────────────────────────────

/// Kind of entity tracked by the UEBA engine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum EntityKind {
    User,
    Host,
    IpAddress,
    Process,
    Service,
}

/// Behavioral observation fed into the UEBA engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorObservation {
    pub timestamp_ms: u64,
    pub entity_kind: EntityKind,
    pub entity_id: String,
    /// Hour of day (0–23) for login-time analysis.
    pub hour_of_day: Option<u8>,
    /// Geographic latitude (for impossible-travel).
    pub geo_lat: Option<f64>,
    /// Geographic longitude.
    pub geo_lon: Option<f64>,
    /// Target resource accessed (hostname, file path, etc.).
    pub resource: Option<String>,
    /// Data volume in bytes (for exfiltration detection).
    pub data_bytes: Option<u64>,
    /// Process name/path (for process anomaly).
    pub process: Option<String>,
    /// Network port (for service anomaly).
    pub port: Option<u16>,
    /// Peer group label (department, role, etc.).
    pub peer_group: Option<String>,
}

/// Internal per-entity behavioral profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityProfile {
    pub entity_kind: EntityKind,
    pub entity_id: String,
    /// EWMA baseline for hour-of-day histogram (24 bins).
    pub hour_histogram: [f32; 24],
    /// Set of resources normally accessed (up to top N).
    pub known_resources: Vec<String>,
    /// EWMA baseline for data volume per observation.
    pub avg_data_bytes: f64,
    /// Set of processes normally run.
    pub known_processes: Vec<String>,
    /// Set of ports normally used.
    pub known_ports: Vec<u16>,
    /// Last observed geographic position.
    pub last_geo: Option<(f64, f64)>,
    /// Last observation timestamp.
    pub last_seen_ms: u64,
    /// Total observations (for warmup tracking).
    pub observation_count: usize,
    /// Cumulative risk score (0–max_risk).
    pub risk_score: f32,
    /// Peer group label.
    pub peer_group: Option<String>,
}

impl EntityProfile {
    fn new(kind: EntityKind, id: &str) -> Self {
        Self {
            entity_kind: kind,
            entity_id: id.to_string(),
            hour_histogram: [0.0; 24],
            known_resources: Vec::new(),
            avg_data_bytes: 0.0,
            known_processes: Vec::new(),
            known_ports: Vec::new(),
            last_geo: None,
            last_seen_ms: 0,
            observation_count: 0,
            risk_score: 0.0,
            peer_group: None,
        }
    }

    fn is_warm(&self, config: &UebaConfig) -> bool {
        self.observation_count >= config.warmup_observations
    }
}

/// Risk summary for an entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityRisk {
    pub entity_kind: EntityKind,
    pub entity_id: String,
    pub risk_score: f32,
    pub observation_count: usize,
    pub last_seen_ms: u64,
    pub anomaly_count: usize,
    pub peer_group: Option<String>,
}

// ── UEBA engine ─────────────────────────────────────────────────

/// The User and Entity Behavior Analytics engine.
pub struct UebaEngine {
    config: UebaConfig,
    profiles: HashMap<String, EntityProfile>,
    anomalies: Vec<UebaAnomaly>,
    /// Maximum anomalies retained.
    anomaly_cap: usize,
}

impl Default for UebaEngine {
    fn default() -> Self {
        Self::new(UebaConfig::default())
    }
}

impl UebaEngine {
    pub fn new(config: UebaConfig) -> Self {
        Self {
            config,
            profiles: HashMap::new(),
            anomalies: Vec::new(),
            anomaly_cap: 5000,
        }
    }

    fn profile_key(kind: &EntityKind, id: &str) -> String {
        format!("{kind:?}:{id}")
    }

    /// Feed a behavioral observation and return any detected anomalies.
    pub fn observe(&mut self, obs: &BehaviorObservation) -> Vec<UebaAnomaly> {
        let key = Self::profile_key(&obs.entity_kind, &obs.entity_id);
        let profile = self
            .profiles
            .entry(key)
            .or_insert_with(|| EntityProfile::new(obs.entity_kind.clone(), &obs.entity_id));

        // Apply time-based risk decay
        if profile.last_seen_ms > 0 && obs.timestamp_ms > profile.last_seen_ms {
            let hours_elapsed =
                (obs.timestamp_ms - profile.last_seen_ms) as f64 / 3_600_000.0;
            if hours_elapsed > 0.0 {
                let decay = (self.config.risk_decay_per_hour as f64).powf(hours_elapsed);
                profile.risk_score *= decay as f32;
            }
        }

        let mut detected = Vec::new();
        let is_warm = profile.is_warm(&self.config);
        let alpha = self.config.alpha;

        // ── Login time anomaly ───────────────────────────────
        if let Some(hour) = obs.hour_of_day {
            if hour < 24 {
                if is_warm {
                    let baseline_freq = profile.hour_histogram[hour as usize];
                    let total: f32 = profile.hour_histogram.iter().sum();
                    if total > 0.0 && baseline_freq / total < 0.02 {
                        let score = 25.0 * (1.0 - baseline_freq / total);
                        detected.push(UebaAnomaly {
                            anomaly_type: UebaAnomalyType::UnusualLoginTime,
                            entity_kind: obs.entity_kind.clone(),
                            entity_id: obs.entity_id.clone(),
                            score,
                            description: format!(
                                "Login at hour {hour} is unusual (baseline frequency {:.1}%)",
                                baseline_freq / total * 100.0
                            ),
                            timestamp_ms: obs.timestamp_ms,
                            evidence: vec![format!("hour={hour}")],
                            mitre_technique: Some("T1078".into()),
                        });
                    }
                }
                // Update histogram
                profile.hour_histogram[hour as usize] =
                    blend_f32(profile.hour_histogram[hour as usize], 1.0, alpha);
                for h in 0..24 {
                    if h != hour as usize {
                        profile.hour_histogram[h] *= 1.0 - alpha * 0.1;
                    }
                }
            }
        }

        // ── Impossible travel ────────────────────────────────
        if let (Some(lat), Some(lon)) = (obs.geo_lat, obs.geo_lon) {
            if let Some((prev_lat, prev_lon)) = profile.last_geo {
                if profile.last_seen_ms > 0 {
                    let dist_km = haversine(prev_lat, prev_lon, lat, lon);
                    let hours =
                        (obs.timestamp_ms - profile.last_seen_ms) as f64 / 3_600_000.0;
                    if hours > 0.0 {
                        let speed_kmh = dist_km / hours;
                        // Flag if travel speed exceeds 900 km/h (≈ commercial jet)
                        if speed_kmh > 900.0 && dist_km > 100.0 {
                            let score = (speed_kmh / 900.0 * 30.0).min(50.0) as f32;
                            detected.push(UebaAnomaly {
                                anomaly_type: UebaAnomalyType::ImpossibleTravel,
                                entity_kind: obs.entity_kind.clone(),
                                entity_id: obs.entity_id.clone(),
                                score,
                                description: format!(
                                    "Travel of {dist_km:.0} km in {hours:.1}h ({speed_kmh:.0} km/h)"
                                ),
                                timestamp_ms: obs.timestamp_ms,
                                evidence: vec![
                                    format!("from=({prev_lat:.2},{prev_lon:.2})"),
                                    format!("to=({lat:.2},{lon:.2})"),
                                ],
                                mitre_technique: Some("T1078".into()),
                            });
                        }
                    }
                }
            }
            profile.last_geo = Some((lat, lon));
        }

        // ── Anomalous resource access ────────────────────────
        if let Some(ref resource) = obs.resource {
            if is_warm && !profile.known_resources.contains(resource) {
                detected.push(UebaAnomaly {
                    anomaly_type: UebaAnomalyType::AnomalousAccess,
                    entity_kind: obs.entity_kind.clone(),
                    entity_id: obs.entity_id.clone(),
                    score: 15.0,
                    description: format!("First access to resource '{resource}'"),
                    timestamp_ms: obs.timestamp_ms,
                    evidence: vec![format!("resource={resource}")],
                    mitre_technique: None,
                });
            }
            if !profile.known_resources.contains(resource) {
                if profile.known_resources.len() < 500 {
                    profile.known_resources.push(resource.clone());
                }
            }
        }

        // ── Anomalous process ────────────────────────────────
        if let Some(ref process) = obs.process {
            if is_warm && !profile.known_processes.contains(process) {
                detected.push(UebaAnomaly {
                    anomaly_type: UebaAnomalyType::AnomalousProcess,
                    entity_kind: obs.entity_kind.clone(),
                    entity_id: obs.entity_id.clone(),
                    score: 20.0,
                    description: format!("First-time process execution: '{process}'"),
                    timestamp_ms: obs.timestamp_ms,
                    evidence: vec![format!("process={process}")],
                    mitre_technique: Some("T1059".into()),
                });
            }
            if !profile.known_processes.contains(process) {
                if profile.known_processes.len() < 500 {
                    profile.known_processes.push(process.clone());
                }
            }
        }

        // ── Data volume anomaly ──────────────────────────────
        if let Some(data_bytes) = obs.data_bytes {
            let vol = data_bytes as f64;
            if is_warm && profile.avg_data_bytes > 0.0 {
                let ratio = vol / profile.avg_data_bytes;
                if ratio > 5.0 {
                    let score = ((ratio - 5.0) * 10.0).min(40.0) as f32;
                    detected.push(UebaAnomaly {
                        anomaly_type: UebaAnomalyType::DataVolumeAnomaly,
                        entity_kind: obs.entity_kind.clone(),
                        entity_id: obs.entity_id.clone(),
                        score,
                        description: format!(
                            "Data volume {vol:.0} bytes is {ratio:.1}x baseline ({:.0})",
                            profile.avg_data_bytes
                        ),
                        timestamp_ms: obs.timestamp_ms,
                        evidence: vec![format!("bytes={data_bytes}")],
                        mitre_technique: Some("T1041".into()),
                    });
                }
            }
            profile.avg_data_bytes =
                blend_f64(profile.avg_data_bytes, vol, alpha as f64);
        }

        // ── Service / port anomaly ───────────────────────────
        if let Some(port) = obs.port {
            if is_warm && !profile.known_ports.contains(&port) {
                detected.push(UebaAnomaly {
                    anomaly_type: UebaAnomalyType::ServiceAnomaly,
                    entity_kind: obs.entity_kind.clone(),
                    entity_id: obs.entity_id.clone(),
                    score: 12.0,
                    description: format!("First-time connection on port {port}"),
                    timestamp_ms: obs.timestamp_ms,
                    evidence: vec![format!("port={port}")],
                    mitre_technique: None,
                });
            }
            if !profile.known_ports.contains(&port) {
                if profile.known_ports.len() < 200 {
                    profile.known_ports.push(port);
                }
            }
        }

        // ── Update risk score ────────────────────────────────
        let anomaly_risk: f32 = detected.iter().map(|a| a.score).sum();
        profile.risk_score = (profile.risk_score + anomaly_risk).min(self.config.max_risk);
        profile.last_seen_ms = obs.timestamp_ms;
        profile.observation_count += 1;
        if let Some(ref pg) = obs.peer_group {
            profile.peer_group = Some(pg.clone());
        }

        // Store anomalies
        for a in &detected {
            if self.anomalies.len() >= self.anomaly_cap {
                self.anomalies.remove(0);
            }
            self.anomalies.push(a.clone());
        }

        detected
    }

    /// Get risk summary for a specific entity.
    pub fn entity_risk(&self, kind: &EntityKind, id: &str) -> Option<EntityRisk> {
        let key = Self::profile_key(kind, id);
        self.profiles.get(&key).map(|p| EntityRisk {
            entity_kind: p.entity_kind.clone(),
            entity_id: p.entity_id.clone(),
            risk_score: p.risk_score,
            observation_count: p.observation_count,
            last_seen_ms: p.last_seen_ms,
            anomaly_count: self
                .anomalies
                .iter()
                .filter(|a| a.entity_kind == *kind && a.entity_id == id)
                .count(),
            peer_group: p.peer_group.clone(),
        })
    }

    /// List all entity profiles with risk > 0.
    pub fn risky_entities(&self, min_risk: f32) -> Vec<EntityRisk> {
        self.profiles
            .values()
            .filter(|p| p.risk_score >= min_risk)
            .map(|p| EntityRisk {
                entity_kind: p.entity_kind.clone(),
                entity_id: p.entity_id.clone(),
                risk_score: p.risk_score,
                observation_count: p.observation_count,
                last_seen_ms: p.last_seen_ms,
                anomaly_count: self
                    .anomalies
                    .iter()
                    .filter(|a| {
                        a.entity_kind == p.entity_kind && a.entity_id == p.entity_id
                    })
                    .count(),
                peer_group: p.peer_group.clone(),
            })
            .collect()
    }

    /// Get recent anomalies, optionally filtered by entity.
    pub fn recent_anomalies(
        &self,
        limit: usize,
        entity_filter: Option<(&EntityKind, &str)>,
    ) -> Vec<UebaAnomaly> {
        let iter = self.anomalies.iter().rev();
        if let Some((kind, id)) = entity_filter {
            iter.filter(|a| a.entity_kind == *kind && a.entity_id == id)
                .take(limit)
                .cloned()
                .collect()
        } else {
            iter.take(limit).cloned().collect()
        }
    }

    /// Get risk scores for all entities in a peer group.
    pub fn peer_group_risks(&self, group: &str) -> Vec<EntityRisk> {
        self.profiles
            .values()
            .filter(|p| p.peer_group.as_deref() == Some(group))
            .map(|p| EntityRisk {
                entity_kind: p.entity_kind.clone(),
                entity_id: p.entity_id.clone(),
                risk_score: p.risk_score,
                observation_count: p.observation_count,
                last_seen_ms: p.last_seen_ms,
                anomaly_count: 0,
                peer_group: p.peer_group.clone(),
            })
            .collect()
    }

    /// Total number of tracked entity profiles.
    pub fn profile_count(&self) -> usize {
        self.profiles.len()
    }

    /// Total anomalies stored.
    pub fn anomaly_count(&self) -> usize {
        self.anomalies.len()
    }
}

// ── Helpers ─────────────────────────────────────────────────────

fn blend_f32(baseline: f32, sample: f32, alpha: f32) -> f32 {
    (1.0 - alpha) * baseline + alpha * sample
}

fn blend_f64(baseline: f64, sample: f64, alpha: f64) -> f64 {
    (1.0 - alpha) * baseline + alpha * sample
}

/// Haversine distance in kilometres.
fn haversine(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let r = 6371.0; // Earth radius km
    let d_lat = (lat2 - lat1).to_radians();
    let d_lon = (lon2 - lon1).to_radians();
    let lat1_r = lat1.to_radians();
    let lat2_r = lat2.to_radians();
    let a = (d_lat / 2.0).sin().powi(2)
        + lat1_r.cos() * lat2_r.cos() * (d_lon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().asin();
    r * c
}

// ── GeoIP Validation ────────────────────────────────────────────

/// Lightweight GeoIP lookup entry for IP→location mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpEntry {
    pub ip_prefix: String,
    pub country: String,
    pub city: String,
    pub latitude: f64,
    pub longitude: f64,
}

/// GeoIP resolver for IP-to-location mapping.
/// Uses prefix matching against a loaded table.
pub struct GeoIpResolver {
    entries: Vec<GeoIpEntry>,
}

impl Default for GeoIpResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl GeoIpResolver {
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Load GeoIP entries from a JSON string (array of GeoIpEntry).
    pub fn load_json(&mut self, data: &str) -> usize {
        if let Ok(entries) = serde_json::from_str::<Vec<GeoIpEntry>>(data) {
            let count = entries.len();
            self.entries.extend(entries);
            count
        } else {
            0
        }
    }

    /// Add a single entry.
    pub fn add_entry(&mut self, entry: GeoIpEntry) {
        self.entries.push(entry);
    }

    /// Resolve an IP address to a geographic location.
    /// Uses longest-prefix matching.
    pub fn resolve(&self, ip: &str) -> Option<&GeoIpEntry> {
        self.entries
            .iter()
            .filter(|e| ip.starts_with(&e.ip_prefix))
            .max_by_key(|e| e.ip_prefix.len())
    }

    /// Validate whether a login from `ip` is plausible given the
    /// entity's last known location and elapsed time.
    /// Returns Some(speed_kmh) if impossible travel is detected.
    pub fn validate_geo(
        &self,
        ip: &str,
        last_lat: f64,
        last_lon: f64,
        elapsed_hours: f64,
    ) -> Option<f64> {
        let entry = self.resolve(ip)?;
        let dist = haversine(last_lat, last_lon, entry.latitude, entry.longitude);
        if elapsed_hours > 0.0 {
            let speed = dist / elapsed_hours;
            if speed > 900.0 && dist > 100.0 {
                return Some(speed);
            }
        }
        None
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_obs(entity: &str, ts: u64) -> BehaviorObservation {
        BehaviorObservation {
            timestamp_ms: ts,
            entity_kind: EntityKind::User,
            entity_id: entity.to_string(),
            hour_of_day: None,
            geo_lat: None,
            geo_lon: None,
            resource: None,
            data_bytes: None,
            process: None,
            port: None,
            peer_group: None,
        }
    }

    #[test]
    fn warmup_suppresses_anomalies() {
        let mut engine = UebaEngine::new(UebaConfig {
            warmup_observations: 3,
            ..Default::default()
        });
        let mut obs = make_obs("alice", 1000);
        obs.resource = Some("server-A".into());
        // First 3 observations: warmup, no anomalies
        for i in 0..3 {
            obs.timestamp_ms = 1000 + i;
            let res = engine.observe(&obs);
            assert!(res.is_empty(), "warmup should not flag anomalies");
        }
        // 4th observation with new resource: should flag
        obs.timestamp_ms = 2000;
        obs.resource = Some("server-NEW".into());
        let res = engine.observe(&obs);
        assert!(res.iter().any(|a| a.anomaly_type == UebaAnomalyType::AnomalousAccess));
    }

    #[test]
    fn impossible_travel_detected() {
        let mut engine = UebaEngine::default();
        let mut obs = make_obs("bob", 1000);
        obs.geo_lat = Some(48.8566); // Paris
        obs.geo_lon = Some(2.3522);
        engine.observe(&obs);

        // 30 minutes later, from Tokyo
        obs.timestamp_ms = 1000 + 30 * 60 * 1000;
        obs.geo_lat = Some(35.6762);
        obs.geo_lon = Some(139.6503);
        let res = engine.observe(&obs);
        assert!(res.iter().any(|a| a.anomaly_type == UebaAnomalyType::ImpossibleTravel));
    }

    #[test]
    fn unusual_login_time() {
        let mut engine = UebaEngine::new(UebaConfig {
            warmup_observations: 5,
            ..Default::default()
        });
        // Train baseline: always logs in at hour 9
        for i in 0..10 {
            let mut obs = make_obs("carol", 1000 + i * 3_600_000);
            obs.hour_of_day = Some(9);
            engine.observe(&obs);
        }
        // Now login at 3 AM
        let mut obs = make_obs("carol", 100_000_000);
        obs.hour_of_day = Some(3);
        let res = engine.observe(&obs);
        assert!(res.iter().any(|a| a.anomaly_type == UebaAnomalyType::UnusualLoginTime));
    }

    #[test]
    fn data_volume_anomaly() {
        let mut engine = UebaEngine::new(UebaConfig {
            warmup_observations: 5,
            ..Default::default()
        });
        // Normal volume: ~1000 bytes
        for i in 0..10 {
            let mut obs = make_obs("dave", 1000 + i * 60_000);
            obs.data_bytes = Some(1000);
            engine.observe(&obs);
        }
        // Spike: 50KB
        let mut obs = make_obs("dave", 2_000_000);
        obs.data_bytes = Some(50_000);
        let res = engine.observe(&obs);
        assert!(res.iter().any(|a| a.anomaly_type == UebaAnomalyType::DataVolumeAnomaly));
    }

    #[test]
    fn risk_score_decays() {
        let mut engine = UebaEngine::new(UebaConfig {
            warmup_observations: 1,
            risk_decay_per_hour: 0.5,
            ..Default::default()
        });
        let mut obs = make_obs("eve", 0);
        obs.resource = Some("a".into());
        engine.observe(&obs);
        // Trigger anomaly
        obs.timestamp_ms = 1;
        obs.resource = Some("new-resource".into());
        engine.observe(&obs);
        let risk_before = engine.entity_risk(&EntityKind::User, "eve").unwrap().risk_score;
        assert!(risk_before > 0.0);

        // 2 hours later, empty observation
        obs.timestamp_ms = 1 + 2 * 3_600_000;
        obs.resource = None;
        engine.observe(&obs);
        let risk_after = engine.entity_risk(&EntityKind::User, "eve").unwrap().risk_score;
        assert!(risk_after < risk_before);
    }

    #[test]
    fn anomalous_process_detection() {
        let mut engine = UebaEngine::new(UebaConfig {
            warmup_observations: 3,
            ..Default::default()
        });
        for i in 0..5 {
            let mut obs = make_obs("host1", 1000 + i * 1000);
            obs.entity_kind = EntityKind::Host;
            obs.process = Some("nginx".into());
            engine.observe(&obs);
        }
        let mut obs = make_obs("host1", 10_000);
        obs.entity_kind = EntityKind::Host;
        obs.process = Some("mimikatz.exe".into());
        let res = engine.observe(&obs);
        assert!(res.iter().any(|a| a.anomaly_type == UebaAnomalyType::AnomalousProcess));
    }

    #[test]
    fn port_anomaly_detection() {
        let mut engine = UebaEngine::new(UebaConfig {
            warmup_observations: 3,
            ..Default::default()
        });
        for i in 0..5 {
            let mut obs = make_obs("srv", 1000 + i * 1000);
            obs.entity_kind = EntityKind::Host;
            obs.port = Some(443);
            engine.observe(&obs);
        }
        let mut obs = make_obs("srv", 20_000);
        obs.entity_kind = EntityKind::Host;
        obs.port = Some(4444); // Meterpreter default
        let res = engine.observe(&obs);
        assert!(res.iter().any(|a| a.anomaly_type == UebaAnomalyType::ServiceAnomaly));
    }

    #[test]
    fn peer_group_tracking() {
        let mut engine = UebaEngine::default();
        let mut obs = make_obs("alice", 1000);
        obs.peer_group = Some("engineering".into());
        engine.observe(&obs);
        let mut obs2 = make_obs("bob", 2000);
        obs2.peer_group = Some("engineering".into());
        engine.observe(&obs2);
        let peers = engine.peer_group_risks("engineering");
        assert_eq!(peers.len(), 2);
    }

    #[test]
    fn risky_entities_filter() {
        let mut engine = UebaEngine::new(UebaConfig {
            warmup_observations: 1,
            ..Default::default()
        });
        let mut obs = make_obs("risky-user", 0);
        obs.resource = Some("a".into());
        engine.observe(&obs);
        obs.timestamp_ms = 1;
        obs.resource = Some("b".into());
        engine.observe(&obs);
        let risky = engine.risky_entities(1.0);
        assert!(!risky.is_empty());
        let safe = engine.risky_entities(999.0);
        assert!(safe.is_empty());
    }

    #[test]
    fn haversine_distance() {
        let d = haversine(48.8566, 2.3522, 35.6762, 139.6503);
        assert!(d > 9000.0 && d < 10000.0, "Paris to Tokyo ≈ 9700 km, got {d}");
    }

    #[test]
    fn geoip_resolver_validates() {
        let mut resolver = GeoIpResolver::new();
        resolver.add_entry(GeoIpEntry {
            ip_prefix: "203.0.113".into(),
            country: "JP".into(),
            city: "Tokyo".into(),
            latitude: 35.6762,
            longitude: 139.6503,
        });
        resolver.add_entry(GeoIpEntry {
            ip_prefix: "198.51.100".into(),
            country: "FR".into(),
            city: "Paris".into(),
            latitude: 48.8566,
            longitude: 2.3522,
        });

        // Resolve Tokyo IP
        let entry = resolver.resolve("203.0.113.50").unwrap();
        assert_eq!(entry.country, "JP");

        // Check impossible travel: Paris → Tokyo in 0.5h
        let speed = resolver.validate_geo("203.0.113.50", 48.8566, 2.3522, 0.5);
        assert!(speed.is_some(), "should detect impossible travel");
        assert!(speed.unwrap() > 900.0);

        // Plausible travel: Paris → Tokyo in 24h
        let plausible = resolver.validate_geo("203.0.113.50", 48.8566, 2.3522, 24.0);
        assert!(plausible.is_none(), "24h travel should be plausible");
    }
}
