//! Beacon and DGA (Domain Generation Algorithm) detection.
//!
//! Analyses outbound connection timing for periodic C2 callback patterns,
//! applies Shannon entropy and n-gram analysis to DNS queries for DGA domain
//! detection, and identifies DNS tunnelling indicators.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Configuration ───────────────────────────────────────────────

/// Beacon detector configuration.
#[derive(Debug, Clone)]
pub struct BeaconConfig {
    /// Minimum number of connections to analyse for beaconing.
    pub min_samples: usize,
    /// Jitter tolerance as a fraction (0–1). 0.2 = 20% jitter allowed.
    pub jitter_tolerance: f32,
    /// Minimum beacon score (0–1) to flag as suspicious.
    pub beacon_threshold: f32,
    /// Shannon entropy threshold for DGA detection.
    pub dga_entropy_threshold: f32,
    /// Minimum domain length to analyse for DGA.
    pub dga_min_length: usize,
    /// DNS query length threshold for tunnelling detection.
    pub tunnel_query_length: usize,
    /// NXDOMAIN ratio threshold for DGA indicators.
    pub nxdomain_ratio_threshold: f32,
}

impl Default for BeaconConfig {
    fn default() -> Self {
        Self {
            min_samples: 5,
            jitter_tolerance: 0.2,
            beacon_threshold: 0.6,
            dga_entropy_threshold: 3.5,
            dga_min_length: 8,
            tunnel_query_length: 50,
            nxdomain_ratio_threshold: 0.5,
        }
    }
}

// ── Connection / DNS records ────────────────────────────────────

/// An outbound connection timestamp for beacon analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionRecord {
    pub timestamp_ms: u64,
    pub dst_addr: String,
    pub dst_port: u16,
    pub hostname: String,
    pub process: Option<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

/// A DNS query record for DGA / tunnelling analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub timestamp_ms: u64,
    pub domain: String,
    pub query_type: String,
    pub response_code: DnsResponseCode,
    pub hostname: String,
    pub process: Option<String>,
}

/// DNS response codes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DnsResponseCode {
    NoError,
    NxDomain,
    ServFail,
    Refused,
    Other(String),
}

// ── Detection results ───────────────────────────────────────────

/// A suspicious beacon candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconCandidate {
    pub dst_addr: String,
    pub dst_port: u16,
    /// Detected beacon interval (ms).
    pub interval_ms: u64,
    /// Jitter as a fraction of interval (0–1).
    pub jitter: f32,
    /// Beacon confidence score (0–1).
    pub score: f32,
    /// Number of connections analysed.
    pub sample_count: usize,
    /// Source hostname.
    pub hostname: String,
    /// Source process if known.
    pub process: Option<String>,
    /// Total data transferred.
    pub total_bytes: u64,
}

/// A suspicious DGA domain candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DgaCandidate {
    pub domain: String,
    /// Shannon entropy of the domain label.
    pub entropy: f32,
    /// Consonant-to-vowel ratio.
    pub consonant_ratio: f32,
    /// DGA confidence score (0–1).
    pub score: f32,
    /// Number of queries for this domain.
    pub query_count: usize,
    /// Whether NXDOMAIN was returned.
    pub nxdomain: bool,
}

/// DNS tunnelling indicator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelIndicator {
    pub domain: String,
    /// Average query label length.
    pub avg_query_length: f32,
    /// Fraction of TXT record queries.
    pub txt_ratio: f32,
    /// NXDOMAIN ratio for this domain.
    pub nxdomain_ratio: f32,
    /// Tunnel confidence score (0–1).
    pub score: f32,
    pub query_count: usize,
}

/// Combined beacon analysis summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconSummary {
    pub beacons: Vec<BeaconCandidate>,
    pub dga_domains: Vec<DgaCandidate>,
    pub tunnel_indicators: Vec<TunnelIndicator>,
    pub total_connections_analysed: usize,
    pub total_dns_queries_analysed: usize,
}

// ── Detector ────────────────────────────────────────────────────

/// Beacon and DGA detection engine.
pub struct BeaconDetector {
    config: BeaconConfig,
    connections: Vec<ConnectionRecord>,
    dns_records: Vec<DnsRecord>,
}

impl Default for BeaconDetector {
    fn default() -> Self {
        Self::new(BeaconConfig::default())
    }
}

impl BeaconDetector {
    pub fn new(config: BeaconConfig) -> Self {
        Self {
            config,
            connections: Vec::new(),
            dns_records: Vec::new(),
        }
    }

    /// Record an outbound connection.
    pub fn record_connection(&mut self, conn: ConnectionRecord) {
        self.connections.push(conn);
    }

    /// Record a DNS query.
    pub fn record_dns(&mut self, dns: DnsRecord) {
        self.dns_records.push(dns);
    }

    /// Evict records older than `cutoff_ms`.
    pub fn evict_before(&mut self, cutoff_ms: u64) {
        self.connections.retain(|c| c.timestamp_ms >= cutoff_ms);
        self.dns_records.retain(|d| d.timestamp_ms >= cutoff_ms);
    }

    /// Run full analysis: beaconing + DGA + tunnelling.
    pub fn analyze(&self) -> BeaconSummary {
        let beacons = self.detect_beacons();
        let dga_domains = self.detect_dga();
        let tunnel_indicators = self.detect_tunnelling();

        BeaconSummary {
            beacons,
            dga_domains,
            tunnel_indicators,
            total_connections_analysed: self.connections.len(),
            total_dns_queries_analysed: self.dns_records.len(),
        }
    }

    // ── Beacon detection ────────────────────────────────────

    fn detect_beacons(&self) -> Vec<BeaconCandidate> {
        // Group connections by (dst_addr, dst_port)
        let mut groups: HashMap<(&str, u16), Vec<&ConnectionRecord>> = HashMap::new();
        for conn in &self.connections {
            groups
                .entry((&conn.dst_addr, conn.dst_port))
                .or_default()
                .push(conn);
        }

        let mut candidates = Vec::new();

        for ((addr, port), mut conns) in groups {
            if conns.len() < self.config.min_samples {
                continue;
            }
            conns.sort_by_key(|c| c.timestamp_ms);

            // Calculate inter-arrival times
            let intervals: Vec<u64> = conns
                .windows(2)
                .map(|w| w[1].timestamp_ms.saturating_sub(w[0].timestamp_ms))
                .filter(|&i| i > 0)
                .collect();

            if intervals.is_empty() {
                continue;
            }

            // Median interval (more robust than mean for beaconing)
            let mut sorted_intervals = intervals.clone();
            sorted_intervals.sort();
            let median = sorted_intervals[sorted_intervals.len() / 2];

            if median == 0 {
                continue;
            }

            // Calculate jitter: median absolute deviation / median
            let mad: f64 = sorted_intervals
                .iter()
                .map(|&i| (i as f64 - median as f64).abs())
                .sum::<f64>()
                / sorted_intervals.len() as f64;
            let jitter = (mad / median as f64) as f32;

            // Beacon score: low jitter + regular intervals = high score
            let regularity = (1.0 - jitter.min(1.0)).max(0.0);
            let count_factor = (conns.len() as f32 / 20.0).min(1.0);
            let score = regularity * 0.7 + count_factor * 0.3;

            if score >= self.config.beacon_threshold {
                let total_bytes: u64 = conns
                    .iter()
                    .map(|c| c.bytes_sent + c.bytes_received)
                    .sum();
                let hostname = conns[0].hostname.clone();
                let process = conns[0].process.clone();

                candidates.push(BeaconCandidate {
                    dst_addr: addr.to_string(),
                    dst_port: port,
                    interval_ms: median,
                    jitter,
                    score,
                    sample_count: conns.len(),
                    hostname,
                    process,
                    total_bytes,
                });
            }
        }

        candidates.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        candidates
    }

    // ── DGA detection ───────────────────────────────────────

    fn detect_dga(&self) -> Vec<DgaCandidate> {
        // Group DNS queries by domain
        let mut domain_counts: HashMap<&str, (usize, bool)> = HashMap::new();
        for dns in &self.dns_records {
            let entry = domain_counts
                .entry(&dns.domain)
                .or_insert((0, false));
            entry.0 += 1;
            if dns.response_code == DnsResponseCode::NxDomain {
                entry.1 = true;
            }
        }

        let mut candidates = Vec::new();

        for (domain, (count, nxdomain)) in domain_counts {
            let label = extract_effective_label(domain);
            if label.len() < self.config.dga_min_length {
                continue;
            }

            let entropy = shannon_entropy(label);
            let consonant_ratio = compute_consonant_ratio(label);

            // DGA score: high entropy + high consonant ratio + NXDOMAIN
            let entropy_factor =
                ((entropy - 2.5) / 2.0).max(0.0).min(1.0);
            let consonant_factor = ((consonant_ratio - 0.5) / 0.3).max(0.0).min(1.0);
            let nx_bonus = if nxdomain { 0.2 } else { 0.0 };
            let score = entropy_factor * 0.5 + consonant_factor * 0.3 + nx_bonus;

            if entropy >= self.config.dga_entropy_threshold || (nxdomain && entropy >= 3.0) {
                candidates.push(DgaCandidate {
                    domain: domain.to_string(),
                    entropy,
                    consonant_ratio,
                    score,
                    query_count: count,
                    nxdomain,
                });
            }
        }

        candidates.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        candidates
    }

    // ── DNS tunnelling detection ────────────────────────────

    fn detect_tunnelling(&self) -> Vec<TunnelIndicator> {
        // Group by base domain (2nd-level)
        let mut domain_groups: HashMap<String, Vec<&DnsRecord>> = HashMap::new();
        for dns in &self.dns_records {
            let base = extract_base_domain(&dns.domain);
            domain_groups.entry(base).or_default().push(dns);
        }

        let mut indicators = Vec::new();

        for (base_domain, records) in &domain_groups {
            if records.len() < 3 {
                continue;
            }

            let avg_length: f32 = records
                .iter()
                .map(|r| r.domain.len() as f32)
                .sum::<f32>()
                / records.len() as f32;

            let txt_count = records
                .iter()
                .filter(|r| r.query_type.eq_ignore_ascii_case("TXT"))
                .count();
            let txt_ratio = txt_count as f32 / records.len() as f32;

            let nx_count = records
                .iter()
                .filter(|r| r.response_code == DnsResponseCode::NxDomain)
                .count();
            let nxdomain_ratio = nx_count as f32 / records.len() as f32;

            // Tunnelling score
            let length_factor = ((avg_length - 30.0) / 40.0).max(0.0).min(1.0);
            let txt_factor = txt_ratio;
            let nx_factor = if nxdomain_ratio > self.config.nxdomain_ratio_threshold {
                0.3
            } else {
                0.0
            };
            let score = length_factor * 0.4 + txt_factor * 0.3 + nx_factor * 0.3;

            if avg_length > self.config.tunnel_query_length as f32
                || txt_ratio > 0.5
                || nxdomain_ratio > self.config.nxdomain_ratio_threshold
            {
                indicators.push(TunnelIndicator {
                    domain: base_domain.clone(),
                    avg_query_length: avg_length,
                    txt_ratio,
                    nxdomain_ratio,
                    score,
                    query_count: records.len(),
                });
            }
        }

        indicators.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        indicators
    }

    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    pub fn dns_record_count(&self) -> usize {
        self.dns_records.len()
    }
}

// ── Helpers ─────────────────────────────────────────────────────

/// Shannon entropy of a string.
fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq: HashMap<char, f32> = HashMap::new();
    let len = s.len() as f32;
    for c in s.chars() {
        *freq.entry(c.to_ascii_lowercase()).or_insert(0.0) += 1.0;
    }
    -freq
        .values()
        .map(|&count| {
            let p = count / len;
            if p > 0.0 {
                p * p.log2()
            } else {
                0.0
            }
        })
        .sum::<f32>()
}

/// Consonant-to-total ratio of alphabetic characters.
fn compute_consonant_ratio(s: &str) -> f32 {
    let alpha: Vec<char> = s.chars().filter(|c| c.is_ascii_alphabetic()).collect();
    if alpha.is_empty() {
        return 0.0;
    }
    let vowels = "aeiouAEIOU";
    let consonants = alpha.iter().filter(|c| !vowels.contains(**c)).count();
    consonants as f32 / alpha.len() as f32
}

/// Extract the effective label (subdomain) for entropy analysis.
/// For "abc123.evil.com" returns "abc123".
fn extract_effective_label(domain: &str) -> &str {
    domain.split('.').next().unwrap_or(domain)
}

/// Extract base domain (last two labels) for grouping.
/// For "sub.evil.com" returns "evil.com".
fn extract_base_domain(domain: &str) -> String {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() >= 2 {
        parts[parts.len() - 2..].join(".")
    } else {
        domain.to_string()
    }
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_conn(addr: &str, port: u16, ts: u64) -> ConnectionRecord {
        ConnectionRecord {
            timestamp_ms: ts,
            dst_addr: addr.into(),
            dst_port: port,
            hostname: "test-host".into(),
            process: None,
            bytes_sent: 100,
            bytes_received: 200,
        }
    }

    fn make_dns(domain: &str, ts: u64, rcode: DnsResponseCode) -> DnsRecord {
        DnsRecord {
            timestamp_ms: ts,
            domain: domain.into(),
            query_type: "A".into(),
            response_code: rcode,
            hostname: "test-host".into(),
            process: None,
        }
    }

    #[test]
    fn detects_regular_beacon() {
        let mut det = BeaconDetector::default();
        // Regular 60-second beacon
        for i in 0..20 {
            det.record_connection(make_conn("10.10.10.10", 443, i * 60_000));
        }
        let summary = det.analyze();
        assert!(!summary.beacons.is_empty());
        let beacon = &summary.beacons[0];
        assert_eq!(beacon.dst_addr, "10.10.10.10");
        assert!(beacon.score >= 0.6);
        assert!(beacon.jitter < 0.1);
    }

    #[test]
    fn jittery_connections_lower_score() {
        let mut det = BeaconDetector::default();
        // Irregular connection timing
        let times = [0, 100, 5000, 5100, 20000, 21000, 50000, 50500, 100000, 105000];
        for ts in &times {
            det.record_connection(make_conn("1.2.3.4", 80, *ts));
        }
        let summary = det.analyze();
        // May or may not be flagged, but score should be lower than a regular beacon
        if !summary.beacons.is_empty() {
            assert!(summary.beacons[0].score < 0.9);
        }
    }

    #[test]
    fn detects_dga_domain() {
        let mut det = BeaconDetector::default();
        det.record_dns(make_dns(
            "xkwqzpft.evil.com",
            1000,
            DnsResponseCode::NxDomain,
        ));
        let summary = det.analyze();
        assert!(!summary.dga_domains.is_empty());
        assert!(summary.dga_domains[0].entropy >= 3.0);
    }

    #[test]
    fn normal_domain_not_dga() {
        let mut det = BeaconDetector::default();
        det.record_dns(make_dns("www.google.com", 1000, DnsResponseCode::NoError));
        let summary = det.analyze();
        // "www" is only 3 chars, below min_length threshold
        assert!(summary.dga_domains.is_empty());
    }

    #[test]
    fn detects_dns_tunnelling() {
        let mut det = BeaconDetector::new(BeaconConfig {
            tunnel_query_length: 30,
            ..Default::default()
        });
        // Long subdomains typical of DNS tunnelling
        for i in 0..10 {
            let long_sub = format!(
                "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHR1bm5lbA{i}.tunnel.evil.com"
            );
            let mut dns = make_dns(&long_sub, i * 1000, DnsResponseCode::NoError);
            dns.query_type = "TXT".into();
            det.record_dns(dns);
        }
        let summary = det.analyze();
        assert!(!summary.tunnel_indicators.is_empty());
    }

    #[test]
    fn shannon_entropy_uniform() {
        let e = shannon_entropy("abcdefgh");
        assert!(e > 2.5, "high entropy for uniform distribution: {e}");
    }

    #[test]
    fn shannon_entropy_repetitive() {
        let e = shannon_entropy("aaaaaaa");
        assert!(e < 0.01, "near-zero entropy for repeated chars: {e}");
    }

    #[test]
    fn consonant_ratio_all_consonants() {
        let r = compute_consonant_ratio("bcdfghjk");
        assert!((r - 1.0).abs() < 0.01);
    }

    #[test]
    fn consonant_ratio_balanced() {
        let r = compute_consonant_ratio("abcde");
        assert!(r > 0.3 && r < 0.8);
    }

    #[test]
    fn extract_label_works() {
        assert_eq!(extract_effective_label("sub.domain.com"), "sub");
        assert_eq!(extract_effective_label("single"), "single");
    }

    #[test]
    fn extract_base_domain_works() {
        assert_eq!(extract_base_domain("sub.evil.com"), "evil.com");
        assert_eq!(extract_base_domain("evil.com"), "evil.com");
    }

    #[test]
    fn evict_before_cleans_old() {
        let mut det = BeaconDetector::default();
        det.record_connection(make_conn("1.1.1.1", 80, 100));
        det.record_connection(make_conn("1.1.1.1", 80, 5000));
        det.record_dns(make_dns("test.com", 100, DnsResponseCode::NoError));
        det.evict_before(1000);
        assert_eq!(det.connection_count(), 1);
        assert_eq!(det.dns_record_count(), 0);
    }
}
