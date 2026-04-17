//! Network Detection and Response (NDR) signals module.
//!
//! Analyses network flow metadata to detect anomalous traffic patterns:
//! top talkers, unusual external destinations, protocol anomalies,
//! encrypted traffic volume baselines, and connection profiling.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Flow record ─────────────────────────────────────────────────

/// A network flow record for analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetFlowRecord {
    pub timestamp_ms: u64,
    pub src_addr: String,
    pub src_port: u16,
    pub dst_addr: String,
    pub dst_port: u16,
    pub protocol: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets: u64,
    pub duration_ms: u64,
    pub hostname: String,
    pub is_encrypted: bool,
    /// JA3 TLS client fingerprint hash (32-char hex MD5).
    #[serde(default)]
    pub ja3_hash: Option<String>,
    /// JA3S TLS server fingerprint hash.
    #[serde(default)]
    pub ja3s_hash: Option<String>,
    /// JA4 next-gen TLS fingerprint (protocol_version + ciphers + extensions).
    #[serde(default)]
    pub ja4_fingerprint: Option<String>,
    /// TLS Server Name Indication (SNI).
    #[serde(default)]
    pub tls_sni: Option<String>,
    /// TLS certificate issuer CN.
    #[serde(default)]
    pub tls_issuer: Option<String>,
    /// TLS certificate subject CN.
    #[serde(default)]
    pub tls_subject: Option<String>,
    /// TLS protocol version (e.g. "TLSv1.3").
    #[serde(default)]
    pub tls_version: Option<String>,
    /// Whether the TLS certificate is self-signed.
    #[serde(default)]
    pub tls_self_signed: bool,
    /// Shannon entropy of the payload (0.0–8.0).
    #[serde(default)]
    pub payload_entropy: Option<f32>,
    /// DPI-detected application protocol (e.g. "HTTP/2", "SSH", "DNS-over-HTTPS").
    #[serde(default)]
    pub dpi_protocol: Option<String>,
}

// ── Configuration ───────────────────────────────────────────────

/// NDR analysis configuration.
#[derive(Debug, Clone)]
pub struct NdrConfig {
    /// Number of top talkers to track.
    pub top_n: usize,
    /// Threshold (bytes) above which an external destination is flagged.
    pub unusual_volume_threshold: u64,
    /// Window size (ms) for traffic baseline.
    pub baseline_window_ms: u64,
    /// Minimum flows to compute a meaningful baseline.
    pub min_flows: usize,
}

impl Default for NdrConfig {
    fn default() -> Self {
        Self {
            top_n: 10,
            unusual_volume_threshold: 100_000_000, // 100 MB
            baseline_window_ms: 3_600_000,         // 1 hour
            min_flows: 10,
        }
    }
}

// ── Detection results ───────────────────────────────────────────

/// A top-talker summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopTalker {
    pub addr: String,
    pub total_bytes: u64,
    pub flow_count: usize,
    pub unique_destinations: usize,
    pub protocols: Vec<String>,
}

/// An unusual external destination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnusualDestination {
    pub dst_addr: String,
    pub dst_port: u16,
    pub total_bytes: u64,
    pub flow_count: usize,
    pub first_seen_ms: u64,
    pub risk_score: f32,
    pub reason: String,
}

/// Protocol anomaly detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolAnomaly {
    pub protocol: String,
    pub port: u16,
    pub expected_protocol: String,
    pub flow_count: usize,
    pub risk_score: f32,
}

/// Encrypted traffic statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedTrafficStats {
    pub total_flows: usize,
    pub encrypted_flows: usize,
    pub encrypted_ratio: f32,
    pub encrypted_bytes: u64,
    pub total_bytes: u64,
}

/// Complete NDR analysis report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NdrReport {
    pub analysis_timestamp: String,
    pub total_flows_analysed: usize,
    pub total_bytes: u64,
    pub top_talkers: Vec<TopTalker>,
    pub unusual_destinations: Vec<UnusualDestination>,
    pub protocol_anomalies: Vec<ProtocolAnomaly>,
    pub encrypted_traffic: EncryptedTrafficStats,
    pub unique_external_destinations: usize,
    pub connections_per_second: f32,
    /// DNS threat analysis results.
    pub dns_threats: Vec<crate::dns_threat::DnsThreatReport>,
    /// JA3/JA4 TLS fingerprint anomalies.
    pub tls_anomalies: Vec<TlsFingerprintAnomaly>,
    /// DPI protocol mismatches.
    pub dpi_anomalies: Vec<DpiAnomaly>,
    /// High-entropy encrypted traffic sessions (potential C2/exfil).
    pub entropy_anomalies: Vec<EntropyAnomaly>,
    /// Regular outbound cadence anomalies (potential beaconing).
    pub beaconing_anomalies: Vec<BeaconingAnomaly>,
    /// Self-signed certificate detections.
    pub self_signed_certs: Vec<SelfSignedCert>,
}

/// TLS fingerprint anomaly detection (JA3/JA4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsFingerprintAnomaly {
    pub ja3_hash: String,
    pub ja4_fingerprint: String,
    pub src_addr: String,
    pub dst_addr: String,
    pub dst_port: u16,
    pub tls_sni: String,
    pub tls_version: String,
    pub risk_score: f32,
    pub reason: String,
    pub flow_count: usize,
}

/// DPI protocol mismatch anomaly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpiAnomaly {
    pub src_addr: String,
    pub dst_addr: String,
    pub dst_port: u16,
    pub expected_protocol: String,
    pub detected_protocol: String,
    pub risk_score: f32,
    pub flow_count: usize,
}

/// High-entropy payload anomaly (potential encrypted C2 or data exfiltration).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyAnomaly {
    pub src_addr: String,
    pub dst_addr: String,
    pub dst_port: u16,
    pub avg_entropy: f32,
    pub total_bytes: u64,
    pub flow_count: usize,
    pub risk_score: f32,
}

/// Regular interval outbound traffic anomaly (potential beaconing/C2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconingAnomaly {
    pub src_addr: String,
    pub dst_addr: String,
    pub dst_port: u16,
    pub protocol: String,
    pub avg_interval_ms: u64,
    pub jitter_pct: f32,
    pub total_bytes: u64,
    pub flow_count: usize,
    pub risk_score: f32,
    pub reason: String,
}

/// Protocol distribution summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolDistribution {
    pub protocol: String,
    pub flow_count: usize,
    pub total_bytes: u64,
    pub encrypted_ratio: f32,
}

/// Self-signed TLS certificate detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfSignedCert {
    pub dst_addr: String,
    pub dst_port: u16,
    pub tls_sni: String,
    pub tls_issuer: String,
    pub tls_subject: String,
    pub flow_count: usize,
    pub risk_score: f32,
}

/// Known-malicious JA3 hashes (commonly seen in C2 frameworks).
const KNOWN_BAD_JA3: &[&str] = &[
    "51c64c77e60f3980eea90869b68c58a8", // CobaltStrike default
    "72a589da586844d7f0818ce684948eea", // Metasploit Meterpreter
    "e7d705a3286e19ea42f587b344ee6865", // Empire default
    "6734f37431670b3ab4292b8f60f29984", // Trickbot default
    "4d7a28d6f2263ed61de88ca66eb011e3", // Sliver C2
    "b32309a26951912be7dba376398abc3b", // PoshC2 default
];

// ── NDR Engine ──────────────────────────────────────────────────

/// Network Detection and Response engine.
pub struct NdrEngine {
    config: NdrConfig,
    flows: Vec<NetFlowRecord>,
    /// Known internal network prefixes.
    internal_prefixes: Vec<String>,
}

impl Default for NdrEngine {
    fn default() -> Self {
        Self::new(NdrConfig::default())
    }
}

impl NdrEngine {
    pub fn new(config: NdrConfig) -> Self {
        Self {
            config,
            flows: Vec::new(),
            internal_prefixes: vec![
                "10.".into(),
                "172.16.".into(),
                "172.17.".into(),
                "172.18.".into(),
                "172.19.".into(),
                "172.20.".into(),
                "172.21.".into(),
                "172.22.".into(),
                "172.23.".into(),
                "172.24.".into(),
                "172.25.".into(),
                "172.26.".into(),
                "172.27.".into(),
                "172.28.".into(),
                "172.29.".into(),
                "172.30.".into(),
                "172.31.".into(),
                "192.168.".into(),
                "127.".into(),
                "::1".into(),
                "fe80:".into(),
            ],
        }
    }

    /// Record a network flow.
    pub fn record_flow(&mut self, flow: NetFlowRecord) {
        self.flows.push(flow);
    }

    /// Evict flows older than cutoff.
    pub fn evict_before(&mut self, cutoff_ms: u64) {
        self.flows.retain(|f| f.timestamp_ms >= cutoff_ms);
    }

    /// Number of tracked flows.
    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    fn is_external(&self, addr: &str) -> bool {
        !self.internal_prefixes.iter().any(|p| addr.starts_with(p))
    }

    /// Run full NDR analysis.
    pub fn analyze(&self) -> NdrReport {
        let top_talkers = self.compute_top_talkers();
        let unusual_destinations = self.detect_unusual_destinations();
        let protocol_anomalies = self.detect_protocol_anomalies();
        let encrypted_traffic = self.compute_encrypted_stats();
        let tls_anomalies = self.detect_tls_anomalies();
        let dpi_anomalies = self.detect_dpi_anomalies();
        let entropy_anomalies = self.detect_entropy_anomalies();
        let beaconing_anomalies = self.detect_beaconing_anomalies();
        let self_signed_certs = self.detect_self_signed_certs();

        let external_dests: std::collections::HashSet<&str> = self
            .flows
            .iter()
            .filter(|f| self.is_external(&f.dst_addr))
            .map(|f| f.dst_addr.as_str())
            .collect();

        let total_bytes: u64 = self
            .flows
            .iter()
            .map(|f| f.bytes_sent + f.bytes_received)
            .sum();

        let duration_ms = if self.flows.len() >= 2 {
            let min_ts = self.flows.iter().map(|f| f.timestamp_ms).min().unwrap_or(0);
            let max_ts = self.flows.iter().map(|f| f.timestamp_ms).max().unwrap_or(0);
            max_ts.saturating_sub(min_ts).max(1)
        } else {
            1
        };
        let cps = (self.flows.len() as f32 / duration_ms as f32) * 1000.0;

        NdrReport {
            analysis_timestamp: chrono::Utc::now().to_rfc3339(),
            total_flows_analysed: self.flows.len(),
            total_bytes,
            top_talkers,
            unusual_destinations,
            protocol_anomalies,
            encrypted_traffic,
            unique_external_destinations: external_dests.len(),
            connections_per_second: (cps * 100.0).round() / 100.0,
            dns_threats: Vec::new(),
            tls_anomalies,
            dpi_anomalies,
            entropy_anomalies,
            beaconing_anomalies,
            self_signed_certs,
        }
    }

    pub fn protocol_distribution(&self) -> Vec<ProtocolDistribution> {
        let mut by_protocol: HashMap<&str, (usize, u64, usize)> = HashMap::new();
        for flow in &self.flows {
            let entry = by_protocol.entry(&flow.protocol).or_insert((0, 0, 0));
            entry.0 += 1;
            entry.1 += flow.bytes_sent + flow.bytes_received;
            if flow.is_encrypted {
                entry.2 += 1;
            }
        }

        let mut items: Vec<ProtocolDistribution> = by_protocol
            .into_iter()
            .map(
                |(protocol, (flow_count, total_bytes, encrypted_count))| ProtocolDistribution {
                    protocol: protocol.to_string(),
                    flow_count,
                    total_bytes,
                    encrypted_ratio: if flow_count > 0 {
                        encrypted_count as f32 / flow_count as f32
                    } else {
                        0.0
                    },
                },
            )
            .collect();

        items.sort_by(|left, right| {
            right
                .total_bytes
                .cmp(&left.total_bytes)
                .then_with(|| right.flow_count.cmp(&left.flow_count))
        });
        items
    }

    fn compute_top_talkers(&self) -> Vec<TopTalker> {
        let mut by_src: HashMap<
            &str,
            (
                u64,
                usize,
                std::collections::HashSet<&str>,
                std::collections::HashSet<&str>,
            ),
        > = HashMap::new();
        for f in &self.flows {
            let entry = by_src.entry(&f.src_addr).or_insert_with(|| {
                (
                    0,
                    0,
                    std::collections::HashSet::new(),
                    std::collections::HashSet::new(),
                )
            });
            entry.0 += f.bytes_sent + f.bytes_received;
            entry.1 += 1;
            entry.2.insert(&f.dst_addr);
            entry.3.insert(&f.protocol);
        }
        let mut talkers: Vec<TopTalker> = by_src
            .into_iter()
            .map(|(addr, (bytes, count, dests, protos))| TopTalker {
                addr: addr.to_string(),
                total_bytes: bytes,
                flow_count: count,
                unique_destinations: dests.len(),
                protocols: protos.into_iter().map(|s| s.to_string()).collect(),
            })
            .collect();
        talkers.sort_by_key(|b| std::cmp::Reverse(b.total_bytes));
        talkers.truncate(self.config.top_n);
        talkers
    }

    fn detect_unusual_destinations(&self) -> Vec<UnusualDestination> {
        let mut by_dst: HashMap<(&str, u16), (u64, usize, u64)> = HashMap::new();
        for f in &self.flows {
            if self.is_external(&f.dst_addr) {
                let entry = by_dst
                    .entry((&f.dst_addr, f.dst_port))
                    .or_insert_with(|| (0, 0, f.timestamp_ms));
                entry.0 += f.bytes_sent + f.bytes_received;
                entry.1 += 1;
                if f.timestamp_ms < entry.2 {
                    entry.2 = f.timestamp_ms;
                }
            }
        }
        let mut unusual: Vec<UnusualDestination> = by_dst
            .into_iter()
            .filter(|(_, (bytes, _, _))| *bytes > self.config.unusual_volume_threshold)
            .map(|((addr, port), (bytes, count, first))| {
                let risk =
                    ((bytes as f32 / self.config.unusual_volume_threshold as f32) * 3.0).min(10.0);
                UnusualDestination {
                    dst_addr: addr.to_string(),
                    dst_port: port,
                    total_bytes: bytes,
                    flow_count: count,
                    first_seen_ms: first,
                    risk_score: (risk * 100.0).round() / 100.0,
                    reason: format!(
                        "High-volume external transfer: {} bytes to {}:{}",
                        bytes, addr, port
                    ),
                }
            })
            .collect();
        unusual.sort_by(|a, b| b.risk_score.total_cmp(&a.risk_score));
        unusual
    }

    fn detect_protocol_anomalies(&self) -> Vec<ProtocolAnomaly> {
        // Well-known port-to-protocol mapping
        let expected: HashMap<u16, &str> = HashMap::from([
            (22, "SSH"),
            (80, "HTTP"),
            (443, "HTTPS"),
            (53, "DNS"),
            (25, "SMTP"),
            (3306, "MySQL"),
            (5432, "PostgreSQL"),
            (6379, "Redis"),
            (8080, "HTTP"),
            (8443, "HTTPS"),
        ]);

        let mut port_protocols: HashMap<u16, HashMap<&str, usize>> = HashMap::new();
        for f in &self.flows {
            *port_protocols
                .entry(f.dst_port)
                .or_default()
                .entry(&f.protocol)
                .or_insert(0) += 1;
        }

        let mut anomalies = Vec::new();
        for (port, protos) in &port_protocols {
            if let Some(expected_proto) = expected.get(port) {
                for (proto, count) in protos {
                    if !proto.eq_ignore_ascii_case(expected_proto) && *count >= 3 {
                        anomalies.push(ProtocolAnomaly {
                            protocol: proto.to_string(),
                            port: *port,
                            expected_protocol: expected_proto.to_string(),
                            flow_count: *count,
                            risk_score: (((*count as f32).ln() + 1.0) * 2.0).min(10.0),
                        });
                    }
                }
            }
        }
        anomalies.sort_by(|a, b| b.risk_score.total_cmp(&a.risk_score));
        anomalies
    }

    fn compute_encrypted_stats(&self) -> EncryptedTrafficStats {
        let total = self.flows.len();
        let encrypted = self.flows.iter().filter(|f| f.is_encrypted).count();
        let total_bytes: u64 = self
            .flows
            .iter()
            .map(|f| f.bytes_sent + f.bytes_received)
            .sum();
        let encrypted_bytes: u64 = self
            .flows
            .iter()
            .filter(|f| f.is_encrypted)
            .map(|f| f.bytes_sent + f.bytes_received)
            .sum();

        EncryptedTrafficStats {
            total_flows: total,
            encrypted_flows: encrypted,
            encrypted_ratio: if total > 0 {
                encrypted as f32 / total as f32
            } else {
                0.0
            },
            encrypted_bytes,
            total_bytes,
        }
    }

    /// Detect TLS fingerprint anomalies using JA3/JA4 hashes.
    fn detect_tls_anomalies(&self) -> Vec<TlsFingerprintAnomaly> {
        let mut anomalies = Vec::new();
        let mut ja3_groups: HashMap<String, Vec<&NetFlowRecord>> = HashMap::new();

        for f in &self.flows {
            if let Some(ref ja3) = f.ja3_hash {
                ja3_groups.entry(ja3.clone()).or_default().push(f);
            }
        }

        for (ja3, flows) in &ja3_groups {
            // Check against known-malicious JA3 hashes
            if KNOWN_BAD_JA3.contains(&ja3.as_str())
                && let Some(first) = flows.first()
            {
                anomalies.push(TlsFingerprintAnomaly {
                    ja3_hash: ja3.clone(),
                    ja4_fingerprint: first.ja4_fingerprint.clone().unwrap_or_default(),
                    src_addr: first.src_addr.clone(),
                    dst_addr: first.dst_addr.clone(),
                    dst_port: first.dst_port,
                    tls_sni: first.tls_sni.clone().unwrap_or_default(),
                    tls_version: first.tls_version.clone().unwrap_or_default(),
                    risk_score: 9.0,
                    reason: format!("Known malicious JA3 fingerprint: {ja3}"),
                    flow_count: flows.len(),
                });
            }

            // Flag rare JA3 fingerprints (seen in < 3 flows with external destinations)
            if flows.len() <= 2 {
                let has_external = flows.iter().any(|f| self.is_external(&f.dst_addr));
                if has_external && let Some(first) = flows.first() {
                    anomalies.push(TlsFingerprintAnomaly {
                        ja3_hash: ja3.clone(),
                        ja4_fingerprint: first.ja4_fingerprint.clone().unwrap_or_default(),
                        src_addr: first.src_addr.clone(),
                        dst_addr: first.dst_addr.clone(),
                        dst_port: first.dst_port,
                        tls_sni: first.tls_sni.clone().unwrap_or_default(),
                        tls_version: first.tls_version.clone().unwrap_or_default(),
                        risk_score: 4.0,
                        reason: format!(
                            "Rare JA3 fingerprint seen in only {} flow(s)",
                            flows.len()
                        ),
                        flow_count: flows.len(),
                    });
                }
            }
        }

        anomalies.sort_by(|a, b| b.risk_score.total_cmp(&a.risk_score));
        anomalies
    }

    /// Detect DPI protocol mismatches (e.g. SSH on port 443).
    fn detect_dpi_anomalies(&self) -> Vec<DpiAnomaly> {
        let port_to_dpi: HashMap<u16, &str> = HashMap::from([
            (80, "HTTP"),
            (443, "HTTPS"),
            (22, "SSH"),
            (53, "DNS"),
            (25, "SMTP"),
            (110, "POP3"),
            (143, "IMAP"),
            (993, "IMAPS"),
            (3306, "MySQL"),
            (5432, "PostgreSQL"),
            (6379, "Redis"),
        ]);

        let mut mismatches: HashMap<(String, String, u16, String), usize> = HashMap::new();

        for f in &self.flows {
            if let Some(ref dpi_proto) = f.dpi_protocol
                && let Some(expected) = port_to_dpi.get(&f.dst_port)
            {
                let dpi_upper = dpi_proto.to_uppercase();
                let exp_upper = expected.to_uppercase();
                if !dpi_upper.starts_with(&exp_upper) && !exp_upper.starts_with(&dpi_upper) {
                    let key = (
                        f.src_addr.clone(),
                        f.dst_addr.clone(),
                        f.dst_port,
                        dpi_proto.clone(),
                    );
                    *mismatches.entry(key).or_insert(0) += 1;
                }
            }
        }

        let mut anomalies: Vec<DpiAnomaly> = mismatches
            .into_iter()
            .filter(|(_, count)| *count >= 2)
            .map(|((src, dst, port, detected), count)| {
                let expected = port_to_dpi.get(&port).unwrap_or(&"unknown").to_string();
                DpiAnomaly {
                    src_addr: src,
                    dst_addr: dst,
                    dst_port: port,
                    expected_protocol: expected,
                    detected_protocol: detected,
                    risk_score: (((count as f32).ln() + 1.0) * 3.0).min(10.0),
                    flow_count: count,
                }
            })
            .collect();

        anomalies.sort_by(|a, b| b.risk_score.total_cmp(&a.risk_score));
        anomalies
    }

    /// Detect high-entropy encrypted sessions (potential C2 or exfiltration).
    fn detect_entropy_anomalies(&self) -> Vec<EntropyAnomaly> {
        // Group external encrypted flows by (src, dst, port)
        let mut groups: HashMap<(&str, &str, u16), (f64, u64, usize)> = HashMap::new();

        for f in &self.flows {
            if let Some(entropy) = f.payload_entropy
                && self.is_external(&f.dst_addr)
                && entropy > 7.5
            {
                let entry = groups
                    .entry((&f.src_addr, &f.dst_addr, f.dst_port))
                    .or_insert((0.0, 0, 0));
                entry.0 += entropy as f64;
                entry.1 += f.bytes_sent + f.bytes_received;
                entry.2 += 1;
            }
        }

        let mut anomalies: Vec<EntropyAnomaly> = groups
            .into_iter()
            .filter(|(_, (_, _, count))| *count >= 3)
            .map(|((src, dst, port), (entropy_sum, bytes, count))| {
                let avg_entropy = (entropy_sum / count as f64) as f32;
                let risk = ((avg_entropy - 7.0) * 5.0 + (count as f32).ln()).min(10.0);
                EntropyAnomaly {
                    src_addr: src.to_string(),
                    dst_addr: dst.to_string(),
                    dst_port: port,
                    avg_entropy: (avg_entropy * 100.0).round() / 100.0,
                    total_bytes: bytes,
                    flow_count: count,
                    risk_score: (risk * 100.0).round() / 100.0,
                }
            })
            .collect();

        anomalies.sort_by(|a, b| b.risk_score.total_cmp(&a.risk_score));
        anomalies
    }

    /// Detect outbound traffic with a stable cadence that resembles beaconing.
    fn detect_beaconing_anomalies(&self) -> Vec<BeaconingAnomaly> {
        let mut groups: HashMap<(&str, &str, u16, &str), Vec<&NetFlowRecord>> = HashMap::new();

        for flow in &self.flows {
            if self.is_external(&flow.dst_addr) {
                groups
                    .entry((
                        &flow.src_addr,
                        &flow.dst_addr,
                        flow.dst_port,
                        &flow.protocol,
                    ))
                    .or_default()
                    .push(flow);
            }
        }

        let mut anomalies = Vec::new();
        for ((src, dst, port, protocol), mut flows) in groups {
            if flows.len() < 4 {
                continue;
            }

            flows.sort_by_key(|flow| flow.timestamp_ms);
            let intervals: Vec<f32> = flows
                .windows(2)
                .map(|pair| pair[1].timestamp_ms.saturating_sub(pair[0].timestamp_ms) as f32)
                .filter(|interval| *interval > 0.0)
                .collect();
            if intervals.len() < 3 {
                continue;
            }

            let avg_interval = intervals.iter().sum::<f32>() / intervals.len() as f32;
            if !(10_000.0..=900_000.0).contains(&avg_interval) {
                continue;
            }

            let variance = intervals
                .iter()
                .map(|interval| {
                    let delta = interval - avg_interval;
                    delta * delta
                })
                .sum::<f32>()
                / intervals.len() as f32;
            let stddev = variance.sqrt();
            let jitter_ratio = if avg_interval > 0.0 {
                stddev / avg_interval
            } else {
                1.0
            };
            if jitter_ratio > 0.15 {
                continue;
            }

            let total_bytes: u64 = flows
                .iter()
                .map(|flow| flow.bytes_sent + flow.bytes_received)
                .sum();
            let encrypted_ratio =
                flows.iter().filter(|flow| flow.is_encrypted).count() as f32 / flows.len() as f32;
            let cadence_bonus = ((flows.len() as f32).ln() * 1.6).min(2.5);
            let jitter_bonus = ((0.15 - jitter_ratio).max(0.0) * 20.0).min(2.0);
            let risk = (4.0 + cadence_bonus + jitter_bonus + encrypted_ratio).min(10.0);

            anomalies.push(BeaconingAnomaly {
                src_addr: src.to_string(),
                dst_addr: dst.to_string(),
                dst_port: port,
                protocol: protocol.to_string(),
                avg_interval_ms: avg_interval.round() as u64,
                jitter_pct: (jitter_ratio * 1000.0).round() / 10.0,
                total_bytes,
                flow_count: flows.len(),
                risk_score: (risk * 100.0).round() / 100.0,
                reason: format!(
                    "Regular outbound cadence: {} flow(s) every ~{}s with {:.1}% jitter",
                    flows.len(),
                    (avg_interval / 1000.0).round(),
                    jitter_ratio * 100.0,
                ),
            });
        }

        anomalies.sort_by(|left, right| right.risk_score.total_cmp(&left.risk_score));
        anomalies
    }

    /// Detect self-signed TLS certificates.
    fn detect_self_signed_certs(&self) -> Vec<SelfSignedCert> {
        let mut seen: HashMap<(&str, u16), (&NetFlowRecord, usize)> = HashMap::new();

        for f in &self.flows {
            if f.tls_self_signed {
                let entry = seen.entry((&f.dst_addr, f.dst_port)).or_insert((f, 0));
                entry.1 += 1;
            }
        }

        let mut certs: Vec<SelfSignedCert> = seen
            .into_iter()
            .map(|((addr, port), (flow, count))| {
                let is_external = self.is_external(addr);
                SelfSignedCert {
                    dst_addr: addr.to_string(),
                    dst_port: port,
                    tls_sni: flow.tls_sni.clone().unwrap_or_default(),
                    tls_issuer: flow.tls_issuer.clone().unwrap_or_default(),
                    tls_subject: flow.tls_subject.clone().unwrap_or_default(),
                    flow_count: count,
                    risk_score: if is_external { 6.0 } else { 2.0 },
                }
            })
            .collect();

        certs.sort_by(|a, b| b.risk_score.total_cmp(&a.risk_score));
        certs
    }
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_flow(src: &str, dst: &str, port: u16, bytes: u64) -> NetFlowRecord {
        NetFlowRecord {
            timestamp_ms: 1000,
            src_addr: src.into(),
            src_port: 50000,
            dst_addr: dst.into(),
            dst_port: port,
            protocol: "TCP".into(),
            bytes_sent: bytes,
            bytes_received: bytes / 2,
            packets: 10,
            duration_ms: 1000,
            hostname: "test-host".into(),
            is_encrypted: port == 443,
            ja3_hash: None,
            ja3s_hash: None,
            ja4_fingerprint: None,
            tls_sni: None,
            tls_issuer: None,
            tls_subject: None,
            tls_version: None,
            tls_self_signed: false,
            payload_entropy: None,
            dpi_protocol: None,
        }
    }

    fn make_tls_flow(src: &str, dst: &str, ja3: &str) -> NetFlowRecord {
        let mut f = make_flow(src, dst, 443, 1000);
        f.ja3_hash = Some(ja3.into());
        f.tls_sni = Some("example.com".into());
        f.tls_version = Some("TLSv1.3".into());
        f
    }

    #[test]
    fn top_talkers_sorted() {
        let mut engine = NdrEngine::default();
        engine.record_flow(make_flow("10.0.0.1", "8.8.8.8", 443, 1000));
        engine.record_flow(make_flow("10.0.0.2", "8.8.8.8", 443, 5000));
        let report = engine.analyze();
        assert!(!report.top_talkers.is_empty());
        assert_eq!(report.top_talkers[0].addr, "10.0.0.2");
    }

    #[test]
    fn encrypted_stats() {
        let mut engine = NdrEngine::default();
        engine.record_flow(make_flow("10.0.0.1", "1.1.1.1", 443, 1000)); // encrypted
        engine.record_flow(make_flow("10.0.0.1", "1.1.1.1", 80, 1000)); // not encrypted
        let report = engine.analyze();
        assert_eq!(report.encrypted_traffic.encrypted_flows, 1);
        assert_eq!(report.encrypted_traffic.total_flows, 2);
    }

    #[test]
    fn external_detection() {
        let engine = NdrEngine::default();
        assert!(engine.is_external("8.8.8.8"));
        assert!(!engine.is_external("10.0.0.1"));
        assert!(!engine.is_external("192.168.1.1"));
        assert!(!engine.is_external("127.0.0.1"));
    }

    #[test]
    fn known_bad_ja3_detected() {
        let mut engine = NdrEngine::default();
        engine.record_flow(make_tls_flow(
            "10.0.0.5",
            "8.8.4.4",
            "51c64c77e60f3980eea90869b68c58a8",
        ));
        let report = engine.analyze();
        assert!(!report.tls_anomalies.is_empty());
        assert!(report.tls_anomalies[0].risk_score >= 9.0);
        assert!(report.tls_anomalies[0].reason.contains("malicious"));
    }

    #[test]
    fn rare_ja3_flagged() {
        let mut engine = NdrEngine::default();
        engine.record_flow(make_tls_flow(
            "10.0.0.5",
            "1.2.3.4",
            "deadbeef00000000deadbeef00000000",
        ));
        let report = engine.analyze();
        let rare: Vec<_> = report
            .tls_anomalies
            .iter()
            .filter(|a| a.reason.contains("Rare"))
            .collect();
        assert!(!rare.is_empty());
    }

    #[test]
    fn dpi_mismatch_detected() {
        let mut engine = NdrEngine::default();
        for _ in 0..3 {
            let mut f = make_flow("10.0.0.1", "8.8.8.8", 443, 500);
            f.dpi_protocol = Some("SSH".into());
            engine.record_flow(f);
        }
        let report = engine.analyze();
        assert!(!report.dpi_anomalies.is_empty());
        assert_eq!(report.dpi_anomalies[0].detected_protocol, "SSH");
    }

    #[test]
    fn high_entropy_detected() {
        let mut engine = NdrEngine::default();
        for _ in 0..5 {
            let mut f = make_flow("10.0.0.1", "5.6.7.8", 443, 2000);
            f.payload_entropy = Some(7.9);
            engine.record_flow(f);
        }
        let report = engine.analyze();
        assert!(!report.entropy_anomalies.is_empty());
        assert!(report.entropy_anomalies[0].avg_entropy > 7.5);
    }

    #[test]
    fn self_signed_cert_detected() {
        let mut engine = NdrEngine::default();
        let mut f = make_flow("10.0.0.1", "9.8.7.6", 443, 500);
        f.tls_self_signed = true;
        f.tls_issuer = Some("Evil CA".into());
        f.tls_subject = Some("evil.com".into());
        engine.record_flow(f);
        let report = engine.analyze();
        assert!(!report.self_signed_certs.is_empty());
        assert!(report.self_signed_certs[0].risk_score > 0.0);
    }

    #[test]
    fn stable_beaconing_detected() {
        let mut engine = NdrEngine::default();
        for idx in 0..5 {
            let mut flow = make_flow("10.0.0.4", "45.77.10.10", 443, 1200);
            flow.timestamp_ms = 60_000 * idx as u64;
            flow.is_encrypted = true;
            engine.record_flow(flow);
        }

        let report = engine.analyze();
        assert!(!report.beaconing_anomalies.is_empty());
        assert_eq!(report.beaconing_anomalies[0].avg_interval_ms, 60_000);
        assert!(report.beaconing_anomalies[0].jitter_pct <= 0.1);
    }

    #[test]
    fn irregular_bursts_do_not_trigger_beaconing() {
        let mut engine = NdrEngine::default();
        for ts in [1_000_u64, 8_000, 90_000, 105_000, 410_000] {
            let mut flow = make_flow("10.0.0.4", "45.77.10.10", 443, 1200);
            flow.timestamp_ms = ts;
            flow.is_encrypted = true;
            engine.record_flow(flow);
        }

        let report = engine.analyze();
        assert!(report.beaconing_anomalies.is_empty());
    }
}
