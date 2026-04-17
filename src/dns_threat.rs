//! DNS threat detection: DGA scoring, tunneling detection, and fast-flux analysis.
//!
//! Analyzes domain names and DNS query patterns to identify algorithmically
//! generated domains, data exfiltration via DNS tunneling, and fast-flux
//! hosting used by botnets.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Types ────────────────────────────────────────────────────────────────────

/// Verdict for a DNS analysis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DnsVerdict {
    Clean,
    Suspicious,
    Malicious,
}

impl std::fmt::Display for DnsVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Clean => write!(f, "clean"),
            Self::Suspicious => write!(f, "suspicious"),
            Self::Malicious => write!(f, "malicious"),
        }
    }
}

/// Single-domain analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsThreatReport {
    pub domain: String,
    pub dga_score: f32,
    pub tunnel_score: f32,
    pub fast_flux_score: f32,
    pub verdict: DnsVerdict,
    pub indicators: Vec<String>,
    pub tld_risk: f32,
    pub overall_score: f32,
    pub doh_bypass_detected: bool,
}

/// DNS query record for aggregation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    pub domain: String,
    pub query_type: String,
    pub response_ips: Vec<String>,
    pub ttl: Option<u32>,
    pub timestamp: String,
    pub response_size: Option<usize>,
}

/// Aggregated DNS threat view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsThreatSummary {
    pub total_queries_analyzed: usize,
    pub suspicious_domains: Vec<DnsThreatReport>,
    pub dga_candidates: usize,
    pub tunnel_candidates: usize,
    pub fast_flux_candidates: usize,
    pub top_queried: Vec<(String, usize)>,
}

// ── DGA Detection ────────────────────────────────────────────────────────────

/// Known high-risk TLDs frequently abused.
const HIGH_RISK_TLDS: &[(&str, f32)] = &[
    (".tk", 0.8),
    (".top", 0.7),
    (".xyz", 0.6),
    (".buzz", 0.7),
    (".cyou", 0.7),
    (".icu", 0.6),
    (".club", 0.5),
    (".gq", 0.8),
    (".ml", 0.8),
    (".cf", 0.8),
    (".ga", 0.8),
    (".wang", 0.5),
    (".work", 0.5),
    (".click", 0.6),
    (".link", 0.4),
    (".loan", 0.6),
    (".racing", 0.6),
    (".win", 0.6),
    (".bid", 0.6),
    (".stream", 0.5),
];

const VOWELS: &[u8] = b"aeiou";

/// Calculate DGA score for a domain (0.0 = legitimate, 1.0 = definitely DGA).
fn dga_score(domain: &str) -> (f32, Vec<String>) {
    let mut score = 0.0_f32;
    let mut indicators = Vec::new();

    // Extract the registrable domain (remove TLD, take second-level label)
    let labels: Vec<&str> = domain.split('.').collect();
    let sld = if labels.len() >= 2 {
        labels[labels.len() - 2]
    } else {
        domain
    };

    // 1. Length scoring (DGA domains tend to be long)
    let len = sld.len();
    if len > 20 {
        score += 0.3;
        indicators.push(format!("very long SLD ({len} chars)"));
    } else if len > 14 {
        score += 0.15;
        indicators.push(format!("long SLD ({len} chars)"));
    }

    // 2. Consonant-vowel ratio
    let vowel_count = sld
        .bytes()
        .filter(|b| VOWELS.contains(&b.to_ascii_lowercase()))
        .count();
    let consonant_count = sld
        .bytes()
        .filter(|b| b.is_ascii_alphabetic() && !VOWELS.contains(&b.to_ascii_lowercase()))
        .count();
    if consonant_count > 0 {
        let ratio = vowel_count as f32 / consonant_count as f32;
        if ratio < 0.15 {
            score += 0.25;
            indicators.push("very low vowel ratio".into());
        } else if ratio < 0.25 {
            score += 0.1;
            indicators.push("low vowel ratio".into());
        }
    }

    // 3. Digit ratio (DGA often mixes many digits)
    let digit_count = sld.bytes().filter(|b| b.is_ascii_digit()).count();
    let digit_ratio = digit_count as f32 / len.max(1) as f32;
    if digit_ratio > 0.4 {
        score += 0.2;
        indicators.push(format!("high digit ratio ({:.0}%)", digit_ratio * 100.0));
    }

    // 4. Bigram entropy (character pair frequency)
    let bigram_ent = bigram_entropy(sld);
    if bigram_ent > 3.5 {
        score += 0.2;
        indicators.push(format!("high bigram entropy ({bigram_ent:.2})"));
    }

    // 5. Consecutive consonants (natural languages rarely have >4)
    let max_consec = max_consecutive_consonants(sld);
    if max_consec >= 5 {
        score += 0.15;
        indicators.push(format!("{max_consec} consecutive consonants"));
    }

    // 6. No dictionary-like patterns (all-random characters)
    if !has_common_bigrams(sld) && len > 8 {
        score += 0.1;
        indicators.push("no common bigrams detected".into());
    }

    (score.min(1.0), indicators)
}

fn bigram_entropy(s: &str) -> f32 {
    if s.len() < 2 {
        return 0.0;
    }
    let bytes = s.as_bytes();
    let mut freq: HashMap<(u8, u8), usize> = HashMap::new();
    let total = bytes.len() - 1;
    for i in 0..total {
        *freq
            .entry((
                bytes[i].to_ascii_lowercase(),
                bytes[i + 1].to_ascii_lowercase(),
            ))
            .or_default() += 1;
    }
    let mut ent = 0.0_f32;
    for &count in freq.values() {
        let p = count as f32 / total as f32;
        ent -= p * p.log2();
    }
    ent
}

fn max_consecutive_consonants(s: &str) -> usize {
    let mut max = 0;
    let mut current = 0;
    for b in s.bytes() {
        if b.is_ascii_alphabetic() && !VOWELS.contains(&b.to_ascii_lowercase()) {
            current += 1;
            max = max.max(current);
        } else {
            current = 0;
        }
    }
    max
}

/// Check for common English bigrams.
const COMMON_BIGRAMS: &[&str] = &[
    "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd", "ti", "es", "or", "te", "of", "ed",
    "is", "it", "al", "ar", "st", "to", "nt", "ng", "se", "ha", "ou", "io", "le", "ve",
];

fn has_common_bigrams(s: &str) -> bool {
    let lower = s.to_lowercase();
    let matches = COMMON_BIGRAMS
        .iter()
        .filter(|bg| lower.contains(*bg))
        .count();
    matches >= 3
}

// ── Tunneling Detection ──────────────────────────────────────────────────────

/// Analyze DNS queries for tunneling indicators.
fn tunnel_score(queries: &[DnsQuery], domain: &str) -> (f32, Vec<String>) {
    let mut score = 0.0_f32;
    let mut indicators = Vec::new();

    let domain_queries: Vec<_> = queries
        .iter()
        .filter(|q| q.domain.ends_with(domain) || q.domain == domain)
        .collect();

    if domain_queries.is_empty() {
        return (0.0, indicators);
    }

    // 1. Subdomain depth
    let max_depth = domain_queries
        .iter()
        .map(|q| q.domain.split('.').count())
        .max()
        .unwrap_or(2);
    if max_depth > 5 {
        score += 0.3;
        indicators.push(format!("deep subdomains (depth {max_depth})"));
    }

    // 2. Average query length (tunneling = long encoded payloads)
    let avg_len: f32 = domain_queries
        .iter()
        .map(|q| q.domain.len() as f32)
        .sum::<f32>()
        / domain_queries.len() as f32;
    if avg_len > 50.0 {
        score += 0.3;
        indicators.push(format!("avg query length {avg_len:.0} chars"));
    } else if avg_len > 30.0 {
        score += 0.15;
    }

    // 3. TXT record ratio (tunneling often uses TXT for larger payloads)
    let txt_count = domain_queries
        .iter()
        .filter(|q| q.query_type == "TXT")
        .count();
    let txt_ratio = txt_count as f32 / domain_queries.len() as f32;
    if txt_ratio > 0.5 {
        score += 0.2;
        indicators.push(format!("{:.0}% TXT queries", txt_ratio * 100.0));
    }

    // 4. Query volume burst (many queries in short time = data transfer)
    if domain_queries.len() > 50 {
        score += 0.2;
        indicators.push(format!("{} queries to zone", domain_queries.len()));
    }

    (score.min(1.0), indicators)
}

// ── Fast-Flux Detection ──────────────────────────────────────────────────────

/// Analyze DNS responses for fast-flux hosting indicators.
fn fast_flux_score(queries: &[DnsQuery], domain: &str) -> (f32, Vec<String>) {
    let mut score = 0.0_f32;
    let mut indicators = Vec::new();

    let domain_queries: Vec<_> = queries.iter().filter(|q| q.domain == domain).collect();

    if domain_queries.is_empty() {
        return (0.0, indicators);
    }

    // 1. Unique IP addresses
    let mut all_ips: Vec<&str> = domain_queries
        .iter()
        .flat_map(|q| q.response_ips.iter().map(|s| s.as_str()))
        .collect();
    all_ips.sort();
    all_ips.dedup();

    if all_ips.len() > 10 {
        score += 0.4;
        indicators.push(format!("{} unique IPs", all_ips.len()));
    } else if all_ips.len() > 5 {
        score += 0.2;
        indicators.push(format!("{} IPs rotating", all_ips.len()));
    }

    // 2. Low TTL
    let low_ttl_count = domain_queries
        .iter()
        .filter(|q| q.ttl.map(|t| t < 300).unwrap_or(false))
        .count();
    let low_ttl_ratio = low_ttl_count as f32 / domain_queries.len().max(1) as f32;
    if low_ttl_ratio > 0.5 {
        score += 0.3;
        indicators.push(format!("{:.0}% low TTL (<300s)", low_ttl_ratio * 100.0));
    }

    // 3. IP diversity per query (single query returning many IPs)
    let max_ips_per_query = domain_queries
        .iter()
        .map(|q| q.response_ips.len())
        .max()
        .unwrap_or(0);
    if max_ips_per_query > 5 {
        score += 0.2;
        indicators.push(format!("{max_ips_per_query} IPs in single response"));
    }

    (score.min(1.0), indicators)
}

// ── TLD Risk ─────────────────────────────────────────────────────────────────

fn tld_risk(domain: &str) -> f32 {
    for &(tld, risk) in HIGH_RISK_TLDS {
        if domain.ends_with(tld) {
            return risk;
        }
    }
    0.0
}

// ── Public API ───────────────────────────────────────────────────────────────

/// DNS analysis engine.
pub struct DnsAnalyzer {
    query_history: Vec<DnsQuery>,
    #[allow(dead_code)]
    domain_scores: HashMap<String, DnsThreatReport>,
    max_history: usize,
}

impl Default for DnsAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsAnalyzer {
    pub fn new() -> Self {
        Self {
            query_history: Vec::new(),
            domain_scores: HashMap::new(),
            max_history: 100_000,
        }
    }

    /// Record a DNS query for pattern analysis.
    pub fn record_query(&mut self, query: DnsQuery) {
        if self.query_history.len() >= self.max_history {
            self.query_history.drain(0..self.max_history / 4);
        }
        self.query_history.push(query);
    }

    /// Analyze a single domain.
    pub fn analyze_domain(&self, domain: &str) -> DnsThreatReport {
        let (dga, mut indicators) = dga_score(domain);
        let (tunnel, tunnel_ind) = tunnel_score(&self.query_history, domain);
        let (flux, flux_ind) = fast_flux_score(&self.query_history, domain);
        let tld = tld_risk(domain);

        indicators.extend(tunnel_ind);
        indicators.extend(flux_ind);

        if tld > 0.0 {
            indicators.push(format!("high-risk TLD (risk {tld:.1})"));
        }

        let doh_bypass = is_known_doh_resolver(domain);
        if doh_bypass {
            indicators.push("DoH/DoT bypass: known encrypted DNS resolver".to_string());
        }

        let overall = (dga * 0.35 + tunnel * 0.25 + flux * 0.25 + tld * 0.15).min(1.0);

        let verdict = if overall > 0.7 {
            DnsVerdict::Malicious
        } else if overall > 0.4 {
            DnsVerdict::Suspicious
        } else {
            DnsVerdict::Clean
        };

        DnsThreatReport {
            domain: domain.to_string(),
            dga_score: dga,
            tunnel_score: tunnel,
            fast_flux_score: flux,
            verdict,
            indicators,
            tld_risk: tld,
            overall_score: overall,
            doh_bypass_detected: doh_bypass,
        }
    }

    /// Get aggregated threat summary.
    pub fn threat_summary(&self) -> DnsThreatSummary {
        let mut domain_counts: HashMap<String, usize> = HashMap::new();
        for q in &self.query_history {
            *domain_counts.entry(q.domain.clone()).or_default() += 1;
        }

        let mut suspicious = Vec::new();
        let mut dga_count = 0;
        let mut tunnel_count = 0;
        let mut flux_count = 0;

        for domain in domain_counts.keys() {
            let report = self.analyze_domain(domain);
            if report.verdict != DnsVerdict::Clean {
                if report.dga_score > 0.5 {
                    dga_count += 1;
                }
                if report.tunnel_score > 0.5 {
                    tunnel_count += 1;
                }
                if report.fast_flux_score > 0.5 {
                    flux_count += 1;
                }
                suspicious.push(report);
            }
        }

        suspicious.sort_by(|a, b| {
            b.overall_score
                .partial_cmp(&a.overall_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let mut top_queried: Vec<_> = domain_counts.into_iter().collect();
        top_queried.sort_by(|a, b| b.1.cmp(&a.1));
        top_queried.truncate(20);

        DnsThreatSummary {
            total_queries_analyzed: self.query_history.len(),
            suspicious_domains: suspicious,
            dga_candidates: dga_count,
            tunnel_candidates: tunnel_count,
            fast_flux_candidates: flux_count,
            top_queried,
        }
    }
}

// ── DoH/DoT Bypass Detection ─────────────────────────────────────────────────

/// Known DNS-over-HTTPS and DNS-over-TLS resolver domains.
const DOH_RESOLVERS: &[&str] = &[
    "dns.cloudflare.com",
    "cloudflare-dns.com",
    "one.one.one.one",
    "dns.google",
    "dns.google.com",
    "dns.quad9.net",
    "dns9.quad9.net",
    "dns.nextdns.io",
    "doh.opendns.com",
    "dns.adguard.com",
    "doh.cleanbrowsing.org",
    "dns.mullvad.net",
    "freedns.controld.com",
    "dns.switch.ch",
    "ordns.he.net",
    "doh.applied-privacy.net",
    "doh.dns.sb",
    "resolver1.dns.watch",
    "resolver2.dns.watch",
];

/// Known DoH resolver IP addresses (primary endpoints).
const DOH_RESOLVER_IPS: &[&str] = &[
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
    "94.140.14.14",
    "94.140.15.15",
    "185.228.168.168",
    "76.76.2.0",
    "76.76.10.0",
    "193.110.81.0",
    "185.253.5.0",
];

/// Check if a domain is a known DoH/DoT resolver.
fn is_known_doh_resolver(domain: &str) -> bool {
    let lower = domain.to_lowercase();
    DOH_RESOLVERS
        .iter()
        .any(|&r| lower == r || lower.ends_with(&format!(".{r}")))
}

/// Check if an IP address belongs to a known DoH resolver.
pub fn is_doh_resolver_ip(ip: &str) -> bool {
    DOH_RESOLVER_IPS.contains(&ip)
}

/// Detect potential DoH bypass: returns list of (domain_or_ip, resolver_name)
/// pairs from DNS query history that contact known DoH endpoints.
pub fn detect_doh_bypass(queries: &[DnsQuery]) -> Vec<(String, String)> {
    let mut detections = Vec::new();
    for q in queries {
        if is_known_doh_resolver(&q.domain) {
            detections.push((q.domain.clone(), "Domain matches known DoH resolver".into()));
        }
        for ip in &q.response_ips {
            if is_doh_resolver_ip(ip) {
                detections.push((
                    ip.clone(),
                    format!("Response IP {ip} matches known DoH resolver"),
                ));
            }
        }
    }
    detections.sort();
    detections.dedup();
    detections
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legitimate_domain_scores_low() {
        let analyzer = DnsAnalyzer::new();
        let report = analyzer.analyze_domain("google.com");
        assert!(
            report.dga_score < 0.3,
            "google.com dga_score={}",
            report.dga_score
        );
        assert_eq!(report.verdict, DnsVerdict::Clean);
        assert!(!report.doh_bypass_detected);
    }

    #[test]
    fn dga_domain_scores_high() {
        let analyzer = DnsAnalyzer::new();
        let report = analyzer.analyze_domain("xkjhqwzrtplmnbvc.tk");
        assert!(report.dga_score > 0.4, "dga_score={}", report.dga_score);
        assert!(
            report.overall_score > 0.3,
            "overall={}",
            report.overall_score
        );
    }

    #[test]
    fn high_risk_tld_flagged() {
        let analyzer = DnsAnalyzer::new();
        let report = analyzer.analyze_domain("something.tk");
        assert!(report.tld_risk > 0.5);
    }

    #[test]
    fn empty_history_safe() {
        let analyzer = DnsAnalyzer::new();
        let summary = analyzer.threat_summary();
        assert_eq!(summary.total_queries_analyzed, 0);
    }

    #[test]
    fn doh_bypass_detection() {
        let analyzer = DnsAnalyzer::new();
        let report = analyzer.analyze_domain("dns.cloudflare.com");
        assert!(report.doh_bypass_detected);
        assert!(report.indicators.iter().any(|i| i.contains("DoH")));
    }

    #[test]
    fn doh_resolver_ip_detection() {
        assert!(is_doh_resolver_ip("1.1.1.1"));
        assert!(is_doh_resolver_ip("8.8.8.8"));
        assert!(!is_doh_resolver_ip("192.168.1.1"));
    }

    #[test]
    fn detect_doh_bypass_from_queries() {
        let queries = vec![
            DnsQuery {
                domain: "dns.google".into(),
                query_type: "A".into(),
                response_ips: vec!["8.8.8.8".into()],
                ttl: Some(300),
                timestamp: "2026-01-01T00:00:00Z".into(),
                response_size: None,
            },
            DnsQuery {
                domain: "example.com".into(),
                query_type: "A".into(),
                response_ips: vec!["93.184.216.34".into()],
                ttl: Some(3600),
                timestamp: "2026-01-01T00:01:00Z".into(),
                response_size: None,
            },
        ];
        let detections = detect_doh_bypass(&queries);
        assert!(!detections.is_empty());
    }
}
