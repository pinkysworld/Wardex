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
            baseline_window_ms: 3_600_000,          // 1 hour
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
}

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
                "172.16.".into(), "172.17.".into(), "172.18.".into(), "172.19.".into(),
                "172.20.".into(), "172.21.".into(), "172.22.".into(), "172.23.".into(),
                "172.24.".into(), "172.25.".into(), "172.26.".into(), "172.27.".into(),
                "172.28.".into(), "172.29.".into(), "172.30.".into(), "172.31.".into(),
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

        let external_dests: std::collections::HashSet<&str> = self.flows.iter()
            .filter(|f| self.is_external(&f.dst_addr))
            .map(|f| f.dst_addr.as_str())
            .collect();

        let total_bytes: u64 = self.flows.iter().map(|f| f.bytes_sent + f.bytes_received).sum();

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
        }
    }

    fn compute_top_talkers(&self) -> Vec<TopTalker> {
        let mut by_src: HashMap<&str, (u64, usize, std::collections::HashSet<&str>, std::collections::HashSet<&str>)> = HashMap::new();
        for f in &self.flows {
            let entry = by_src.entry(&f.src_addr).or_insert_with(|| (0, 0, std::collections::HashSet::new(), std::collections::HashSet::new()));
            entry.0 += f.bytes_sent + f.bytes_received;
            entry.1 += 1;
            entry.2.insert(&f.dst_addr);
            entry.3.insert(&f.protocol);
        }
        let mut talkers: Vec<TopTalker> = by_src.into_iter().map(|(addr, (bytes, count, dests, protos))| {
            TopTalker {
                addr: addr.to_string(),
                total_bytes: bytes,
                flow_count: count,
                unique_destinations: dests.len(),
                protocols: protos.into_iter().map(|s| s.to_string()).collect(),
            }
        }).collect();
        talkers.sort_by(|a, b| b.total_bytes.cmp(&a.total_bytes));
        talkers.truncate(self.config.top_n);
        talkers
    }

    fn detect_unusual_destinations(&self) -> Vec<UnusualDestination> {
        let mut by_dst: HashMap<(&str, u16), (u64, usize, u64)> = HashMap::new();
        for f in &self.flows {
            if self.is_external(&f.dst_addr) {
                let entry = by_dst.entry((&f.dst_addr, f.dst_port)).or_insert_with(|| (0, 0, f.timestamp_ms));
                entry.0 += f.bytes_sent + f.bytes_received;
                entry.1 += 1;
                if f.timestamp_ms < entry.2 {
                    entry.2 = f.timestamp_ms;
                }
            }
        }
        let mut unusual: Vec<UnusualDestination> = by_dst.into_iter()
            .filter(|(_, (bytes, _, _))| *bytes > self.config.unusual_volume_threshold)
            .map(|((addr, port), (bytes, count, first))| {
                let risk = ((bytes as f32 / self.config.unusual_volume_threshold as f32) * 3.0).min(10.0);
                UnusualDestination {
                    dst_addr: addr.to_string(),
                    dst_port: port,
                    total_bytes: bytes,
                    flow_count: count,
                    first_seen_ms: first,
                    risk_score: (risk * 100.0).round() / 100.0,
                    reason: format!("High-volume external transfer: {} bytes to {}:{}", bytes, addr, port),
                }
            })
            .collect();
        unusual.sort_by(|a, b| b.risk_score.total_cmp(&a.risk_score));
        unusual
    }

    fn detect_protocol_anomalies(&self) -> Vec<ProtocolAnomaly> {
        // Well-known port-to-protocol mapping
        let expected: HashMap<u16, &str> = HashMap::from([
            (22, "SSH"), (80, "HTTP"), (443, "HTTPS"), (53, "DNS"),
            (25, "SMTP"), (3306, "MySQL"), (5432, "PostgreSQL"),
            (6379, "Redis"), (8080, "HTTP"), (8443, "HTTPS"),
        ]);

        let mut port_protocols: HashMap<u16, HashMap<&str, usize>> = HashMap::new();
        for f in &self.flows {
            *port_protocols.entry(f.dst_port).or_default().entry(&f.protocol).or_insert(0) += 1;
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
        let total_bytes: u64 = self.flows.iter().map(|f| f.bytes_sent + f.bytes_received).sum();
        let encrypted_bytes: u64 = self.flows.iter().filter(|f| f.is_encrypted).map(|f| f.bytes_sent + f.bytes_received).sum();

        EncryptedTrafficStats {
            total_flows: total,
            encrypted_flows: encrypted,
            encrypted_ratio: if total > 0 { encrypted as f32 / total as f32 } else { 0.0 },
            encrypted_bytes,
            total_bytes,
        }
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
        }
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
        engine.record_flow(make_flow("10.0.0.1", "1.1.1.1", 80, 1000));  // not encrypted
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
}
