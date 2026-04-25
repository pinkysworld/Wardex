//! Lateral movement detection across fleet agents.
//!
//! Tracks cross-host authentication and remote service connections (SMB, RDP,
//! SSH, WinRM) to identify credential reuse, pass-the-hash, and sequential
//! host compromise patterns.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// ── Configuration ───────────────────────────────────────────────

/// Lateral movement detector configuration.
#[derive(Debug, Clone)]
pub struct LateralConfig {
    /// Maximum age of connections (ms) before they're considered stale.
    pub window_ms: u64,
    /// Minimum hops for a path to be flagged as lateral movement.
    pub min_hops: usize,
    /// Score boost applied to anomaly scores when lateral movement detected.
    pub score_boost: f32,
    /// Credential reuse across this many hosts triggers an alert.
    pub credential_reuse_threshold: usize,
}

impl Default for LateralConfig {
    fn default() -> Self {
        Self {
            window_ms: 3_600_000, // 1 hour
            min_hops: 2,
            score_boost: 3.0,
            credential_reuse_threshold: 3,
        }
    }
}

// ── Connection / session model ──────────────────────────────────

/// Protocol used for remote access.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum RemoteProtocol {
    Ssh,
    Rdp,
    Smb,
    WinRm,
    PsExec,
    Wmi,
    Other(String),
}

impl RemoteProtocol {
    /// Infer protocol from port number.
    pub fn from_port(port: u16) -> Self {
        match port {
            22 => Self::Ssh,
            3389 => Self::Rdp,
            445 | 139 => Self::Smb,
            5985 | 5986 => Self::WinRm,
            _ => Self::Other(format!("port-{port}")),
        }
    }
}

/// A single remote connection event observed in the fleet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteConnection {
    pub timestamp_ms: u64,
    pub src_host: String,
    pub dst_host: String,
    pub protocol: RemoteProtocol,
    /// User/credential used for the connection.
    pub credential: Option<String>,
    /// Source agent UID.
    pub src_agent: Option<String>,
    /// Destination agent UID.
    pub dst_agent: Option<String>,
    /// Whether authentication succeeded.
    pub auth_success: bool,
    /// Associated process (e.g. sshd, mstsc.exe).
    pub process: Option<String>,
}

// ── Lateral movement path ───────────────────────────────────────

/// A detected lateral movement path through the fleet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LateralPath {
    /// Ordered list of hops in the path.
    pub hops: Vec<LateralHop>,
    /// Credentials observed along the path.
    pub credentials_used: Vec<String>,
    /// Total time span of the path (ms).
    pub duration_ms: u64,
    /// Risk score for this path.
    pub risk_score: f32,
    /// Detection patterns observed.
    pub patterns: Vec<LateralPattern>,
    /// MITRE technique IDs.
    pub mitre_techniques: Vec<String>,
}

/// A single hop in a lateral movement path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LateralHop {
    pub timestamp_ms: u64,
    pub src_host: String,
    pub dst_host: String,
    pub protocol: RemoteProtocol,
    pub credential: Option<String>,
}

/// Patterns indicative of lateral movement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LateralPattern {
    /// Same credential used across multiple hosts.
    CredentialReuse,
    /// NTLM auth after Kerberos failure (pass-the-hash indicator).
    PassTheHash,
    /// Sequential compromise of hosts in quick succession.
    SequentialCompromise,
    /// Use of admin tools (PsExec, WMI, PowerShell remoting).
    AdminToolAbuse,
    /// Same source accessing many destinations.
    FanOut,
}

/// Summary of lateral movement activity across the fleet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LateralSummary {
    pub active_paths: Vec<LateralPath>,
    pub total_connections: usize,
    pub unique_credentials: usize,
    pub hosts_involved: usize,
    pub highest_risk: f32,
}

// ── Detector ────────────────────────────────────────────────────

/// Cross-agent lateral movement detector.
pub struct LateralMovementDetector {
    config: LateralConfig,
    connections: Vec<RemoteConnection>,
}

impl Default for LateralMovementDetector {
    fn default() -> Self {
        Self::new(LateralConfig::default())
    }
}

impl LateralMovementDetector {
    pub fn new(config: LateralConfig) -> Self {
        Self {
            config,
            connections: Vec::new(),
        }
    }

    /// Record a remote connection event.
    pub fn record(&mut self, conn: RemoteConnection) {
        self.connections.push(conn);
    }

    /// Evict connections older than the analysis window.
    pub fn evict_stale(&mut self, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(self.config.window_ms);
        self.connections.retain(|c| c.timestamp_ms >= cutoff);
    }

    /// Analyse recorded connections for lateral movement patterns.
    pub fn analyze(&self) -> LateralSummary {
        let successful: Vec<_> = self.connections.iter().filter(|c| c.auth_success).collect();

        // Build adjacency: src → [(dst, credential, timestamp, protocol)]
        let mut adjacency: HashMap<&str, Vec<(&str, Option<&str>, u64, &RemoteProtocol)>> =
            HashMap::new();
        for conn in &successful {
            adjacency.entry(&conn.src_host).or_default().push((
                &conn.dst_host,
                conn.credential.as_deref(),
                conn.timestamp_ms,
                &conn.protocol,
            ));
        }

        // Detect credential reuse across hosts
        let mut credential_hosts: HashMap<&str, HashSet<&str>> = HashMap::new();
        for conn in &successful {
            if let Some(ref cred) = conn.credential {
                credential_hosts
                    .entry(cred)
                    .or_default()
                    .insert(&conn.src_host);
                credential_hosts
                    .entry(cred)
                    .or_default()
                    .insert(&conn.dst_host);
            }
        }

        // Find paths via DFS from each source
        let mut paths: Vec<LateralPath> = Vec::new();
        let mut all_hosts: HashSet<&str> = HashSet::new();

        for start in adjacency.keys() {
            let mut visited: HashSet<&str> = HashSet::new();
            let mut stack: Vec<(&str, Vec<LateralHop>)> = vec![(start, Vec::new())];

            while let Some((current, hops)) = stack.pop() {
                if visited.contains(current) {
                    continue;
                }
                visited.insert(current);
                all_hosts.insert(current);

                if let Some(neighbours) = adjacency.get(current) {
                    for (dst, cred, ts, proto) in neighbours {
                        all_hosts.insert(dst);
                        let mut new_hops = hops.clone();
                        new_hops.push(LateralHop {
                            timestamp_ms: *ts,
                            src_host: current.to_string(),
                            dst_host: dst.to_string(),
                            protocol: (*proto).clone(),
                            credential: cred.map(|s| s.to_string()),
                        });

                        if new_hops.len() >= self.config.min_hops {
                            let mut patterns = Vec::new();
                            let creds: Vec<String> = new_hops
                                .iter()
                                .filter_map(|h| h.credential.clone())
                                .collect();
                            let cred_set: HashSet<_> = creds.iter().collect();

                            // Credential reuse
                            for c in &cred_set {
                                if let Some(hosts) = credential_hosts.get(c.as_str())
                                    && hosts.len() >= self.config.credential_reuse_threshold
                                {
                                    patterns.push(LateralPattern::CredentialReuse);
                                    break;
                                }
                            }

                            // Admin tool abuse
                            if new_hops.iter().any(|h| {
                                matches!(h.protocol, RemoteProtocol::PsExec | RemoteProtocol::Wmi)
                            }) {
                                patterns.push(LateralPattern::AdminToolAbuse);
                            }

                            // Sequential compromise: all hops within 10 minutes
                            let timestamps: Vec<u64> =
                                new_hops.iter().map(|h| h.timestamp_ms).collect();
                            if let (Some(min), Some(max)) =
                                (timestamps.iter().min(), timestamps.iter().max())
                            {
                                let span = max - min;
                                if span < 600_000 {
                                    patterns.push(LateralPattern::SequentialCompromise);
                                }
                            }

                            // Fan-out: same source hitting 3+ destinations
                            if let Some(nbrs) = adjacency.get(start) {
                                let unique_dsts: HashSet<_> = nbrs.iter().map(|n| n.0).collect();
                                if unique_dsts.len() >= 3 {
                                    patterns.push(LateralPattern::FanOut);
                                }
                            }

                            patterns.sort_by_key(|p| format!("{p:?}"));
                            patterns.dedup();

                            let duration = match (timestamps.iter().min(), timestamps.iter().max())
                            {
                                (Some(min), Some(max)) => max - min,
                                _ => 0,
                            };

                            let base_risk = new_hops.len() as f32 * 15.0;
                            let pattern_bonus = patterns.len() as f32 * 10.0;
                            let risk_score = (base_risk + pattern_bonus).min(100.0);

                            let mut mitre = vec!["T1021".to_string()]; // Remote Services
                            if patterns.contains(&LateralPattern::PassTheHash) {
                                mitre.push("T1550".to_string()); // Use Alternate Auth Material
                            }
                            if patterns.contains(&LateralPattern::AdminToolAbuse) {
                                mitre.push("T1569".to_string()); // System Services
                            }

                            paths.push(LateralPath {
                                hops: new_hops.clone(),
                                credentials_used: creds,
                                duration_ms: duration,
                                risk_score,
                                patterns,
                                mitre_techniques: mitre,
                            });
                        }

                        if !visited.contains(dst) {
                            stack.push((dst, new_hops));
                        }
                    }
                }
            }
        }

        // Sort paths by risk descending
        paths.sort_by(|a, b| {
            b.risk_score
                .partial_cmp(&a.risk_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let unique_creds: HashSet<_> = successful
            .iter()
            .filter_map(|c| c.credential.as_deref())
            .collect();

        let highest = paths.first().map(|p| p.risk_score).unwrap_or(0.0);

        LateralSummary {
            active_paths: paths,
            total_connections: successful.len(),
            unique_credentials: unique_creds.len(),
            hosts_involved: all_hosts.len(),
            highest_risk: highest,
        }
    }

    /// Total recorded connections.
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(src: &str, dst: &str, cred: &str, ts: u64, port: u16) -> RemoteConnection {
        RemoteConnection {
            timestamp_ms: ts,
            src_host: src.into(),
            dst_host: dst.into(),
            protocol: RemoteProtocol::from_port(port),
            credential: Some(cred.into()),
            src_agent: None,
            dst_agent: None,
            auth_success: true,
            process: None,
        }
    }

    #[test]
    fn detects_multi_hop_lateral() {
        let mut det = LateralMovementDetector::new(LateralConfig {
            min_hops: 2,
            ..Default::default()
        });
        det.record(conn("host-a", "host-b", "admin", 1000, 22));
        det.record(conn("host-b", "host-c", "admin", 2000, 22));
        let summary = det.analyze();
        assert!(!summary.active_paths.is_empty());
        assert!(summary.active_paths[0].hops.len() >= 2);
    }

    #[test]
    fn credential_reuse_pattern() {
        let mut det = LateralMovementDetector::new(LateralConfig {
            min_hops: 2,
            credential_reuse_threshold: 3,
            ..Default::default()
        });
        det.record(conn("a", "b", "admin", 1000, 445));
        det.record(conn("b", "c", "admin", 2000, 445));
        det.record(conn("c", "d", "admin", 3000, 445));
        let summary = det.analyze();
        let has_reuse = summary
            .active_paths
            .iter()
            .any(|p| p.patterns.contains(&LateralPattern::CredentialReuse));
        assert!(has_reuse);
    }

    #[test]
    fn fan_out_detection() {
        let mut det = LateralMovementDetector::new(LateralConfig {
            min_hops: 2,
            ..Default::default()
        });
        det.record(conn("attacker", "srv1", "admin", 1000, 3389));
        det.record(conn("attacker", "srv2", "admin", 1500, 3389));
        det.record(conn("attacker", "srv3", "admin", 2000, 3389));
        det.record(conn("srv1", "srv4", "admin", 3000, 3389));
        let summary = det.analyze();
        let has_fanout = summary
            .active_paths
            .iter()
            .any(|p| p.patterns.contains(&LateralPattern::FanOut));
        assert!(has_fanout);
    }

    #[test]
    fn sequential_compromise() {
        let mut det = LateralMovementDetector::new(LateralConfig {
            min_hops: 2,
            ..Default::default()
        });
        // All within 5 minutes
        det.record(conn("a", "b", "user", 1000, 22));
        det.record(conn("b", "c", "user", 60_000, 22));
        det.record(conn("c", "d", "user", 120_000, 22));
        let summary = det.analyze();
        let has_seq = summary
            .active_paths
            .iter()
            .any(|p| p.patterns.contains(&LateralPattern::SequentialCompromise));
        assert!(has_seq);
    }

    #[test]
    fn failed_auth_excluded() {
        let mut det = LateralMovementDetector::default();
        let mut c = conn("a", "b", "admin", 1000, 22);
        c.auth_success = false;
        det.record(c);
        det.record(conn("b", "c", "admin", 2000, 22));
        let summary = det.analyze();
        // Only 1 successful connection → not enough hops
        assert!(summary.active_paths.is_empty());
    }

    #[test]
    fn evict_stale_connections() {
        let mut det = LateralMovementDetector::new(LateralConfig {
            window_ms: 1000,
            ..Default::default()
        });
        det.record(conn("a", "b", "user", 100, 22));
        det.record(conn("c", "d", "user", 5000, 22));
        det.evict_stale(5500);
        assert_eq!(det.connection_count(), 1);
    }

    #[test]
    fn protocol_from_port() {
        assert_eq!(RemoteProtocol::from_port(22), RemoteProtocol::Ssh);
        assert_eq!(RemoteProtocol::from_port(3389), RemoteProtocol::Rdp);
        assert_eq!(RemoteProtocol::from_port(445), RemoteProtocol::Smb);
        assert_eq!(RemoteProtocol::from_port(5985), RemoteProtocol::WinRm);
    }

    #[test]
    fn admin_tool_abuse_pattern() {
        let mut det = LateralMovementDetector::new(LateralConfig {
            min_hops: 2,
            ..Default::default()
        });
        det.record(RemoteConnection {
            timestamp_ms: 1000,
            src_host: "a".into(),
            dst_host: "b".into(),
            protocol: RemoteProtocol::PsExec,
            credential: Some("admin".into()),
            src_agent: None,
            dst_agent: None,
            auth_success: true,
            process: Some("psexec.exe".into()),
        });
        det.record(RemoteConnection {
            timestamp_ms: 2000,
            src_host: "b".into(),
            dst_host: "c".into(),
            protocol: RemoteProtocol::Wmi,
            credential: Some("admin".into()),
            src_agent: None,
            dst_agent: None,
            auth_success: true,
            process: None,
        });
        let summary = det.analyze();
        let has_admin = summary
            .active_paths
            .iter()
            .any(|p| p.patterns.contains(&LateralPattern::AdminToolAbuse));
        assert!(has_admin);
    }

    #[test]
    fn empty_connections_safe() {
        let det = LateralMovementDetector::default();
        let summary = det.analyze();
        assert!(summary.active_paths.is_empty());
        assert_eq!(summary.total_connections, 0);
    }
}
