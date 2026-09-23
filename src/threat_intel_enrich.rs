//! Threat-intelligence enrichment clients: VirusTotal and AbuseIPDB.
//!
//! Provides on-demand lookups for file hashes, IP addresses, domains, and
//! URLs against VirusTotal's public v3 API, and IP reputation checks against
//! AbuseIPDB's v2 API. Both clients apply per-provider rate limiting,
//! response caching with a TTL, request timeouts, and degrade gracefully
//! (return a typed error rather than panicking) when the provider is
//! unreachable, misconfigured, or rate-limited.
//!
//! Configuration follows the same shape as the cloud collectors
//! (`collector_aws`, `collector_azure`, `collector_gcp`): a `Config` struct
//! with `enabled`/API-key fields resolved through the existing
//! `secrets::SecretsResolver`, constructed by the caller before use.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ── Configuration ────────────────────────────────────────────────────────────

/// VirusTotal enrichment configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirusTotalConfig {
    /// VT v3 API key (or a secret reference resolved before use).
    #[serde(skip_serializing)]
    pub api_key: String,
    /// Whether the VirusTotal enrichment provider is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Requests allowed per rolling minute window (public API default: 4).
    #[serde(default = "default_vt_rpm")]
    pub requests_per_minute: u32,
    /// Cache TTL for lookup results, in seconds.
    #[serde(default = "default_cache_ttl_secs")]
    pub cache_ttl_secs: u64,
    /// Request timeout, in seconds.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    /// API base URL override (used by tests to point at a mock server).
    #[serde(default = "default_vt_base_url")]
    pub base_url: String,
}

fn default_vt_rpm() -> u32 {
    4
}
fn default_cache_ttl_secs() -> u64 {
    3600
}
fn default_timeout_secs() -> u64 {
    10
}
fn default_vt_base_url() -> String {
    "https://www.virustotal.com/api/v3".to_string()
}

impl Default for VirusTotalConfig {
    fn default() -> Self {
        Self {
            api_key: String::new(),
            enabled: false,
            requests_per_minute: default_vt_rpm(),
            cache_ttl_secs: default_cache_ttl_secs(),
            timeout_secs: default_timeout_secs(),
            base_url: default_vt_base_url(),
        }
    }
}

/// AbuseIPDB enrichment configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbuseIpDbConfig {
    /// AbuseIPDB v2 API key (or a secret reference resolved before use).
    #[serde(skip_serializing)]
    pub api_key: String,
    /// Whether the AbuseIPDB enrichment provider is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Requests allowed per rolling minute window.
    #[serde(default = "default_abuseipdb_rpm")]
    pub requests_per_minute: u32,
    /// Cache TTL for lookup results, in seconds.
    #[serde(default = "default_cache_ttl_secs")]
    pub cache_ttl_secs: u64,
    /// Request timeout, in seconds.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    /// Maximum age (days) of reports to consider.
    #[serde(default = "default_max_age_days")]
    pub max_age_days: u32,
    /// API base URL override (used by tests to point at a mock server).
    #[serde(default = "default_abuseipdb_base_url")]
    pub base_url: String,
}

fn default_abuseipdb_rpm() -> u32 {
    60
}
fn default_max_age_days() -> u32 {
    90
}
fn default_abuseipdb_base_url() -> String {
    "https://api.abuseipdb.com/api/v2".to_string()
}

impl Default for AbuseIpDbConfig {
    fn default() -> Self {
        Self {
            api_key: String::new(),
            enabled: false,
            requests_per_minute: default_abuseipdb_rpm(),
            cache_ttl_secs: default_cache_ttl_secs(),
            timeout_secs: default_timeout_secs(),
            max_age_days: default_max_age_days(),
            base_url: default_abuseipdb_base_url(),
        }
    }
}

/// Aggregate enrichment configuration for both providers.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnrichmentConfig {
    #[serde(default)]
    pub virustotal: VirusTotalConfig,
    #[serde(default)]
    pub abuseipdb: AbuseIpDbConfig,
}

// ── Kinds of lookups ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorKind {
    FileHash,
    IpAddress,
    Domain,
    Url,
}

// ── Results ──────────────────────────────────────────────────────────────────

/// Normalised enrichment verdict, provider-agnostic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentResult {
    pub provider: String,
    pub indicator: String,
    pub kind: IndicatorKind,
    /// True if the lookup itself succeeded (regardless of verdict).
    pub success: bool,
    /// True if the provider considers the indicator malicious/abusive.
    pub malicious: bool,
    /// 0-100 normalised confidence/reputation score.
    pub score: u32,
    /// Human-readable summary.
    pub summary: String,
    /// Raw provider response (truncated), for audit/debugging.
    pub raw: Option<serde_json::Value>,
    /// Set when the result was served from cache.
    #[serde(default)]
    pub cached: bool,
    /// Error message when `success` is false.
    pub error: Option<String>,
    pub looked_up_at: String,
}

// ── Rate limiter ─────────────────────────────────────────────────────────────

/// A simple fixed-window-per-minute rate limiter shared across a client.
#[derive(Debug)]
struct RateLimiter {
    per_minute: u32,
    window_start: Instant,
    count_in_window: u32,
}

impl RateLimiter {
    fn new(per_minute: u32) -> Self {
        Self {
            per_minute: per_minute.max(1),
            window_start: Instant::now(),
            count_in_window: 0,
        }
    }

    /// Returns `Ok(())` if a request may proceed now, or `Err(wait)` with the
    /// duration the caller should wait before retrying.
    fn check(&mut self) -> Result<(), Duration> {
        let elapsed = self.window_start.elapsed();
        if elapsed >= Duration::from_secs(60) {
            self.window_start = Instant::now();
            self.count_in_window = 0;
        }
        if self.count_in_window >= self.per_minute {
            let remaining = Duration::from_secs(60).saturating_sub(elapsed);
            return Err(remaining);
        }
        self.count_in_window += 1;
        Ok(())
    }
}

// ── Cache ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct CacheEntry {
    result: EnrichmentResult,
    fetched_at: Instant,
}

#[derive(Debug, Default)]
struct ResultCache {
    entries: Mutex<HashMap<String, CacheEntry>>,
}

impl ResultCache {
    fn get(&self, key: &str, ttl: Duration) -> Option<EnrichmentResult> {
        let entries = self.entries.lock().ok()?;
        let entry = entries.get(key)?;
        if entry.fetched_at.elapsed() < ttl {
            let mut result = entry.result.clone();
            result.cached = true;
            Some(result)
        } else {
            None
        }
    }

    fn put(&self, key: String, result: EnrichmentResult) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.insert(
                key,
                CacheEntry {
                    result,
                    fetched_at: Instant::now(),
                },
            );
            if entries.len() > 10_000 {
                // Best-effort bound: drop an arbitrary entry rather than grow
                // unbounded. Cache correctness only affects latency, not
                // safety, so this is an acceptable eviction policy.
                if let Some(key) = entries.keys().next().cloned() {
                    entries.remove(&key);
                }
            }
        }
    }
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

// ── VirusTotal client ────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct VirusTotalClient {
    config: VirusTotalConfig,
    limiter: Mutex<RateLimiter>,
    cache: ResultCache,
}

impl VirusTotalClient {
    pub fn new(config: VirusTotalConfig) -> Self {
        let limiter = RateLimiter::new(config.requests_per_minute);
        Self {
            config,
            limiter: Mutex::new(limiter),
            cache: ResultCache::default(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled && !self.config.api_key.trim().is_empty()
    }

    fn cache_key(&self, kind: IndicatorKind, indicator: &str) -> String {
        format!("vt:{kind:?}:{indicator}")
    }

    /// Look up an indicator. `kind` selects the VT endpoint:
    /// FileHash -> /files/{hash}, IpAddress -> /ip_addresses/{ip},
    /// Domain -> /domains/{domain}, Url -> /urls/{sha256(url) base64 id}.
    pub fn lookup(&self, kind: IndicatorKind, indicator: &str) -> EnrichmentResult {
        let now = now_rfc3339();
        if !self.is_enabled() {
            return EnrichmentResult {
                provider: "virustotal".into(),
                indicator: indicator.into(),
                kind,
                success: false,
                malicious: false,
                score: 0,
                summary: "VirusTotal enrichment is not enabled or configured.".into(),
                raw: None,
                cached: false,
                error: Some("virustotal not configured".into()),
                looked_up_at: now,
            };
        }

        let key = self.cache_key(kind, indicator);
        if let Some(cached) = self
            .cache
            .get(&key, Duration::from_secs(self.config.cache_ttl_secs))
        {
            return cached;
        }

        if let Ok(mut limiter) = self.limiter.lock()
            && let Err(wait) = limiter.check()
        {
            return EnrichmentResult {
                provider: "virustotal".into(),
                indicator: indicator.into(),
                kind,
                success: false,
                malicious: false,
                score: 0,
                summary: format!(
                    "VirusTotal rate limit reached; retry in {}s",
                    wait.as_secs()
                ),
                raw: None,
                cached: false,
                error: Some("rate_limited".into()),
                looked_up_at: now,
            };
        }

        let url = self.build_url(kind, indicator);
        let result = self.fetch(kind, indicator, &url, &now);
        if result.success {
            self.cache.put(key, result.clone());
        }
        result
    }

    fn build_url(&self, kind: IndicatorKind, indicator: &str) -> String {
        let base = self.config.base_url.trim_end_matches('/');
        match kind {
            IndicatorKind::FileHash => format!("{base}/files/{indicator}"),
            IndicatorKind::IpAddress => format!("{base}/ip_addresses/{indicator}"),
            IndicatorKind::Domain => format!("{base}/domains/{indicator}"),
            IndicatorKind::Url => {
                // VT identifies URLs by the base64url (no padding) of the URL.
                use base64::Engine;
                let id =
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(indicator.as_bytes());
                format!("{base}/urls/{id}")
            }
        }
    }

    fn fetch(
        &self,
        kind: IndicatorKind,
        indicator: &str,
        url: &str,
        now: &str,
    ) -> EnrichmentResult {
        let timeout = Duration::from_secs(self.config.timeout_secs);
        let response = ureq::get(url)
            .set("x-apikey", &self.config.api_key)
            .timeout(timeout)
            .call();

        match response {
            Ok(resp) => match resp.into_json::<serde_json::Value>() {
                Ok(body) => self.parse_response(kind, indicator, &body, now),
                Err(e) => EnrichmentResult {
                    provider: "virustotal".into(),
                    indicator: indicator.into(),
                    kind,
                    success: false,
                    malicious: false,
                    score: 0,
                    summary: "Failed to parse VirusTotal response".into(),
                    raw: None,
                    cached: false,
                    error: Some(format!("parse error: {e}")),
                    looked_up_at: now.into(),
                },
            },
            Err(ureq::Error::Status(404, _)) => EnrichmentResult {
                provider: "virustotal".into(),
                indicator: indicator.into(),
                kind,
                success: true,
                malicious: false,
                score: 0,
                summary: "No VirusTotal record found for this indicator.".into(),
                raw: None,
                cached: false,
                error: None,
                looked_up_at: now.into(),
            },
            Err(e) => EnrichmentResult {
                provider: "virustotal".into(),
                indicator: indicator.into(),
                kind,
                success: false,
                malicious: false,
                score: 0,
                summary: "VirusTotal request failed".into(),
                raw: None,
                cached: false,
                error: Some(format!("request error: {e}")),
                looked_up_at: now.into(),
            },
        }
    }

    fn parse_response(
        &self,
        kind: IndicatorKind,
        indicator: &str,
        body: &serde_json::Value,
        now: &str,
    ) -> EnrichmentResult {
        let stats = body
            .pointer("/data/attributes/last_analysis_stats")
            .cloned()
            .unwrap_or_default();
        let malicious_count = stats.get("malicious").and_then(|v| v.as_u64()).unwrap_or(0);
        let suspicious_count = stats
            .get("suspicious")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let harmless_count = stats.get("harmless").and_then(|v| v.as_u64()).unwrap_or(0);
        let undetected = stats.get("undetected").and_then(|v| v.as_u64()).unwrap_or(0);
        let total = malicious_count + suspicious_count + harmless_count + undetected;
        let score = if total == 0 {
            0
        } else {
            (((malicious_count + suspicious_count) as f64 / total as f64) * 100.0).round() as u32
        };
        let malicious = malicious_count > 0 || suspicious_count > 0;

        EnrichmentResult {
            provider: "virustotal".into(),
            indicator: indicator.into(),
            kind,
            success: true,
            malicious,
            score,
            summary: format!(
                "{malicious_count} malicious / {suspicious_count} suspicious / {total} engines"
            ),
            raw: Some(truncate_json(body)),
            cached: false,
            error: None,
            looked_up_at: now.into(),
        }
    }
}

// ── AbuseIPDB client ─────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct AbuseIpDbClient {
    config: AbuseIpDbConfig,
    limiter: Mutex<RateLimiter>,
    cache: ResultCache,
}

impl AbuseIpDbClient {
    pub fn new(config: AbuseIpDbConfig) -> Self {
        let limiter = RateLimiter::new(config.requests_per_minute);
        Self {
            config,
            limiter: Mutex::new(limiter),
            cache: ResultCache::default(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled && !self.config.api_key.trim().is_empty()
    }

    pub fn lookup_ip(&self, ip: &str) -> EnrichmentResult {
        let now = now_rfc3339();
        if !self.is_enabled() {
            return EnrichmentResult {
                provider: "abuseipdb".into(),
                indicator: ip.into(),
                kind: IndicatorKind::IpAddress,
                success: false,
                malicious: false,
                score: 0,
                summary: "AbuseIPDB enrichment is not enabled or configured.".into(),
                raw: None,
                cached: false,
                error: Some("abuseipdb not configured".into()),
                looked_up_at: now,
            };
        }

        let key = format!("abuseipdb:{ip}");
        if let Some(cached) = self
            .cache
            .get(&key, Duration::from_secs(self.config.cache_ttl_secs))
        {
            return cached;
        }

        if let Ok(mut limiter) = self.limiter.lock()
            && let Err(wait) = limiter.check()
        {
            return EnrichmentResult {
                provider: "abuseipdb".into(),
                indicator: ip.into(),
                kind: IndicatorKind::IpAddress,
                success: false,
                malicious: false,
                score: 0,
                summary: format!(
                    "AbuseIPDB rate limit reached; retry in {}s",
                    wait.as_secs()
                ),
                raw: None,
                cached: false,
                error: Some("rate_limited".into()),
                looked_up_at: now,
            };
        }

        let url = format!(
            "{}/check?ipAddress={}&maxAgeInDays={}",
            self.config.base_url.trim_end_matches('/'),
            urlencode(ip),
            self.config.max_age_days
        );
        let timeout = Duration::from_secs(self.config.timeout_secs);
        let response = ureq::get(&url)
            .set("Key", &self.config.api_key)
            .set("Accept", "application/json")
            .timeout(timeout)
            .call();

        let result = match response {
            Ok(resp) => match resp.into_json::<serde_json::Value>() {
                Ok(body) => self.parse_response(ip, &body, &now),
                Err(e) => EnrichmentResult {
                    provider: "abuseipdb".into(),
                    indicator: ip.into(),
                    kind: IndicatorKind::IpAddress,
                    success: false,
                    malicious: false,
                    score: 0,
                    summary: "Failed to parse AbuseIPDB response".into(),
                    raw: None,
                    cached: false,
                    error: Some(format!("parse error: {e}")),
                    looked_up_at: now,
                },
            },
            Err(e) => EnrichmentResult {
                provider: "abuseipdb".into(),
                indicator: ip.into(),
                kind: IndicatorKind::IpAddress,
                success: false,
                malicious: false,
                score: 0,
                summary: "AbuseIPDB request failed".into(),
                raw: None,
                cached: false,
                error: Some(format!("request error: {e}")),
                looked_up_at: now,
            },
        };

        if result.success {
            self.cache.put(key, result.clone());
        }
        result
    }

    fn parse_response(&self, ip: &str, body: &serde_json::Value, now: &str) -> EnrichmentResult {
        let score = body
            .pointer("/data/abuseConfidenceScore")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let total_reports = body
            .pointer("/data/totalReports")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let is_whitelisted = body
            .pointer("/data/isWhitelisted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let malicious = score >= 50 && !is_whitelisted;

        EnrichmentResult {
            provider: "abuseipdb".into(),
            indicator: ip.into(),
            kind: IndicatorKind::IpAddress,
            success: true,
            malicious,
            score,
            summary: format!(
                "Abuse confidence {score}% across {total_reports} report(s){}",
                if is_whitelisted { " (whitelisted)" } else { "" }
            ),
            raw: Some(truncate_json(body)),
            cached: false,
            error: None,
            looked_up_at: now.into(),
        }
    }
}

fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn truncate_json(value: &serde_json::Value) -> serde_json::Value {
    let s = value.to_string();
    if s.len() <= 8192 {
        return value.clone();
    }
    serde_json::json!({ "truncated": true, "preview": s.chars().take(8192).collect::<String>() })
}

// ── Combined enrichment service ─────────────────────────────────────────────

/// Aggregates both providers for use by alert/IOC enrichment pipelines and
/// the on-demand lookup API endpoint.
#[derive(Debug)]
pub struct EnrichmentService {
    pub virustotal: VirusTotalClient,
    pub abuseipdb: AbuseIpDbClient,
}

impl EnrichmentService {
    pub fn new(config: EnrichmentConfig) -> Self {
        Self {
            virustotal: VirusTotalClient::new(config.virustotal),
            abuseipdb: AbuseIpDbClient::new(config.abuseipdb),
        }
    }

    /// Enrich an indicator using whichever configured provider is
    /// appropriate for its kind. IP addresses are checked against both
    /// providers when both are enabled; other kinds only support VT today.
    pub fn enrich(&self, kind: IndicatorKind, indicator: &str) -> Vec<EnrichmentResult> {
        let mut results = Vec::new();
        if self.virustotal.is_enabled() {
            results.push(self.virustotal.lookup(kind, indicator));
        }
        if kind == IndicatorKind::IpAddress && self.abuseipdb.is_enabled() {
            results.push(self.abuseipdb.lookup_ip(indicator));
        }
        results
    }

    pub fn any_enabled(&self) -> bool {
        self.virustotal.is_enabled() || self.abuseipdb.is_enabled()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// Spawn a tiny single-request mock HTTP server that always returns the
    /// given body with a 200 status, and returns its base URL.
    fn spawn_mock_server(status_line: &'static str, body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let port = listener.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let mut buf = [0u8; 4096];
                let mut received = Vec::new();
                loop {
                    let n = stream.read(&mut buf).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    received.extend_from_slice(&buf[..n]);
                    if received.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let response = format!(
                    "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
                break;
            }
        });
        format!("http://127.0.0.1:{port}")
    }

    #[test]
    fn vt_disabled_returns_error_without_network() {
        let client = VirusTotalClient::new(VirusTotalConfig::default());
        let result = client.lookup(IndicatorKind::IpAddress, "1.2.3.4");
        assert!(!result.success);
        assert!(result.error.is_some());
    }

    #[test]
    fn vt_lookup_parses_malicious_verdict() {
        let base_url = spawn_mock_server(
            "HTTP/1.1 200 OK",
            r#"{"data":{"attributes":{"last_analysis_stats":{"malicious":10,"suspicious":2,"harmless":50,"undetected":8}}}}"#,
        );
        let client = VirusTotalClient::new(VirusTotalConfig {
            api_key: "test-key".into(),
            enabled: true,
            requests_per_minute: 100,
            base_url,
            ..Default::default()
        });
        let result = client.lookup(IndicatorKind::FileHash, "deadbeef");
        assert!(result.success);
        assert!(result.malicious);
        assert!(result.score > 0);
    }

    #[test]
    fn vt_lookup_caches_result() {
        let base_url = spawn_mock_server(
            "HTTP/1.1 200 OK",
            r#"{"data":{"attributes":{"last_analysis_stats":{"malicious":0,"suspicious":0,"harmless":10,"undetected":0}}}}"#,
        );
        let client = VirusTotalClient::new(VirusTotalConfig {
            api_key: "test-key".into(),
            enabled: true,
            requests_per_minute: 100,
            base_url,
            ..Default::default()
        });
        let first = client.lookup(IndicatorKind::Domain, "example.com");
        assert!(!first.cached);
        let second = client.lookup(IndicatorKind::Domain, "example.com");
        assert!(second.cached);
    }

    #[test]
    fn vt_rate_limit_blocks_excess_requests() {
        let base_url = spawn_mock_server(
            "HTTP/1.1 200 OK",
            r#"{"data":{"attributes":{"last_analysis_stats":{}}}}"#,
        );
        let client = VirusTotalClient::new(VirusTotalConfig {
            api_key: "test-key".into(),
            enabled: true,
            requests_per_minute: 1,
            base_url,
            ..Default::default()
        });
        let first = client.lookup(IndicatorKind::IpAddress, "1.1.1.1");
        assert!(first.success);
        let second = client.lookup(IndicatorKind::IpAddress, "2.2.2.2");
        assert!(!second.success);
        assert_eq!(second.error.as_deref(), Some("rate_limited"));
    }

    #[test]
    fn vt_not_found_is_a_successful_empty_result() {
        let base_url = spawn_mock_server("HTTP/1.1 404 Not Found", r#"{"error":"not found"}"#);
        let client = VirusTotalClient::new(VirusTotalConfig {
            api_key: "test-key".into(),
            enabled: true,
            requests_per_minute: 100,
            base_url,
            ..Default::default()
        });
        let result = client.lookup(IndicatorKind::IpAddress, "9.9.9.9");
        assert!(result.success);
        assert!(!result.malicious);
    }

    #[test]
    fn abuseipdb_disabled_returns_error_without_network() {
        let client = AbuseIpDbClient::new(AbuseIpDbConfig::default());
        let result = client.lookup_ip("1.2.3.4");
        assert!(!result.success);
    }

    #[test]
    fn abuseipdb_lookup_parses_confidence_score() {
        let base_url = spawn_mock_server(
            "HTTP/1.1 200 OK",
            r#"{"data":{"ipAddress":"1.2.3.4","abuseConfidenceScore":87,"totalReports":42,"isWhitelisted":false}}"#,
        );
        let client = AbuseIpDbClient::new(AbuseIpDbConfig {
            api_key: "test-key".into(),
            enabled: true,
            requests_per_minute: 100,
            base_url,
            ..Default::default()
        });
        let result = client.lookup_ip("1.2.3.4");
        assert!(result.success);
        assert!(result.malicious);
        assert_eq!(result.score, 87);
    }

    #[test]
    fn abuseipdb_whitelisted_high_score_is_not_malicious() {
        let base_url = spawn_mock_server(
            "HTTP/1.1 200 OK",
            r#"{"data":{"abuseConfidenceScore":90,"totalReports":5,"isWhitelisted":true}}"#,
        );
        let client = AbuseIpDbClient::new(AbuseIpDbConfig {
            api_key: "test-key".into(),
            enabled: true,
            requests_per_minute: 100,
            base_url,
            ..Default::default()
        });
        let result = client.lookup_ip("8.8.8.8");
        assert!(!result.malicious);
    }

    #[test]
    fn enrichment_service_combines_providers_for_ip() {
        let vt_url = spawn_mock_server(
            "HTTP/1.1 200 OK",
            r#"{"data":{"attributes":{"last_analysis_stats":{"malicious":1,"suspicious":0,"harmless":10,"undetected":0}}}}"#,
        );
        let abuse_url = spawn_mock_server(
            "HTTP/1.1 200 OK",
            r#"{"data":{"abuseConfidenceScore":10,"totalReports":1,"isWhitelisted":false}}"#,
        );
        let service = EnrichmentService::new(EnrichmentConfig {
            virustotal: VirusTotalConfig {
                api_key: "vt-key".into(),
                enabled: true,
                base_url: vt_url,
                ..Default::default()
            },
            abuseipdb: AbuseIpDbConfig {
                api_key: "abuse-key".into(),
                enabled: true,
                base_url: abuse_url,
                ..Default::default()
            },
        });
        assert!(service.any_enabled());
        let results = service.enrich(IndicatorKind::IpAddress, "5.6.7.8");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn enrichment_service_skips_disabled_providers() {
        let service = EnrichmentService::new(EnrichmentConfig::default());
        assert!(!service.any_enabled());
        let results = service.enrich(IndicatorKind::Domain, "example.com");
        assert!(results.is_empty());
    }

    #[test]
    fn rate_limiter_allows_after_check_calls_reset_manually() {
        let mut limiter = RateLimiter::new(2);
        assert!(limiter.check().is_ok());
        assert!(limiter.check().is_ok());
        assert!(limiter.check().is_err());
    }
}
