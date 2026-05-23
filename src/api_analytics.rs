// ── API Usage Analytics ──────────────────────────────────────────────────────
//
// Tracks request counts, latency percentiles, and error rates per API
// endpoint.  Lightweight in-memory metrics — no external dependency.

use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::time::Instant;

const LATENCY_HISTOGRAM_BUCKETS_MS: [f64; 7] = [50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0];

#[derive(Debug, Clone, Serialize)]
pub struct LatencyBucket {
    pub le_ms: f64,
    pub count: u64,
}

/// Per-endpoint metrics.
#[derive(Debug, Clone, Serialize)]
pub struct EndpointMetrics {
    pub path: String,
    pub method: String,
    pub request_count: u64,
    pub error_count: u64,
    pub total_latency_ms: f64,
    pub min_latency_ms: f64,
    pub max_latency_ms: f64,
    pub avg_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub latency_histogram: Vec<LatencyBucket>,
}

/// A single request record.
#[derive(Debug, Clone)]
struct RequestRecord {
    latency_ms: f64,
    is_error: bool,
}

/// API analytics tracker.
#[derive(Debug)]
pub struct ApiAnalytics {
    endpoints: HashMap<String, VecDeque<RequestRecord>>,
    global_count: u64,
    global_errors: u64,
    max_records_per_endpoint: usize,
    max_endpoints: usize,
}

impl Default for ApiAnalytics {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiAnalytics {
    pub fn new() -> Self {
        Self {
            endpoints: HashMap::new(),
            global_count: 0,
            global_errors: 0,
            max_records_per_endpoint: 1000,
            max_endpoints: 500,
        }
    }

    /// Record a completed API request.
    pub fn record(&mut self, method: &str, path: &str, latency_ms: f64, is_error: bool) {
        // Guard against NaN/Infinity/negative latencies
        let latency_ms = if latency_ms.is_finite() && latency_ms >= 0.0 {
            latency_ms
        } else {
            0.0
        };
        let key = format!("{} {}", method, canonicalize_path(path));
        let records = self.endpoints.entry(key).or_default();
        records.push_back(RequestRecord {
            latency_ms,
            is_error,
        });
        // Keep only the most recent entries
        if records.len() > self.max_records_per_endpoint {
            records.pop_front();
        }
        self.global_count += 1;
        if is_error {
            self.global_errors += 1;
        }
        // Evict least-used endpoints when we exceed the cap
        if self.endpoints.len() > self.max_endpoints
            && let Some(smallest_key) = self
                .endpoints
                .iter()
                .min_by_key(|(_, v)| v.len())
                .map(|(k, _)| k.clone())
        {
            self.endpoints.remove(&smallest_key);
        }
    }

    /// Start a timer for measuring request latency.
    pub fn start_timer() -> Instant {
        Instant::now()
    }

    /// Compute per-endpoint metrics.
    pub fn metrics(&self) -> Vec<EndpointMetrics> {
        let mut result = Vec::new();
        for (key, records) in &self.endpoints {
            let parts: Vec<&str> = key.splitn(2, ' ').collect();
            let method = parts.first().copied().unwrap_or("?").to_string();
            let path = parts.get(1).copied().unwrap_or("?").to_string();

            let count = records.len() as u64;
            let errors = records.iter().filter(|r| r.is_error).count() as u64;
            let total: f64 = records.iter().map(|r| r.latency_ms).sum();
            let min = records
                .iter()
                .map(|r| r.latency_ms)
                .fold(f64::MAX, f64::min);
            let max = records.iter().map(|r| r.latency_ms).fold(0.0_f64, f64::max);
            let avg = if count > 0 { total / count as f64 } else { 0.0 };

            let mut latencies: Vec<f64> = records.iter().map(|r| r.latency_ms).collect();
            latencies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let percentile = |p: f64| {
                let idx = ((latencies.len() as f64) * p) as usize;
                latencies
                    .get(idx.min(latencies.len().saturating_sub(1)))
                    .copied()
                    .unwrap_or(0.0)
            };
            let p95 = percentile(0.95);
            let p99 = percentile(0.99);
            let latency_histogram = LATENCY_HISTOGRAM_BUCKETS_MS
                .into_iter()
                .map(|le_ms| LatencyBucket {
                    le_ms,
                    count: latencies.iter().filter(|latency| **latency <= le_ms).count() as u64,
                })
                .collect();

            result.push(EndpointMetrics {
                path,
                method,
                request_count: count,
                error_count: errors,
                total_latency_ms: total,
                min_latency_ms: if min == f64::MAX { 0.0 } else { min },
                max_latency_ms: max,
                avg_latency_ms: avg,
                p95_latency_ms: p95,
                p99_latency_ms: p99,
                latency_histogram,
            });
        }
        // Sort by request count descending
        result.sort_by_key(|b| std::cmp::Reverse(b.request_count));
        result
    }

    /// Global summary.
    pub fn summary(&self) -> AnalyticsSummary {
        let metrics = self.metrics();
        AnalyticsSummary {
            total_requests: self.global_count,
            total_errors: self.global_errors,
            error_rate: if self.global_count > 0 {
                self.global_errors as f64 / self.global_count as f64
            } else {
                0.0
            },
            unique_endpoints: metrics.len(),
            top_endpoints: metrics.into_iter().take(10).collect(),
        }
    }
}

fn canonicalize_path(path: &str) -> String {
    let mut canonical_segments = Vec::new();
    for segment in path.split('/') {
        if segment.is_empty() {
            continue;
        }
        if is_dynamic_segment(segment) {
            canonical_segments.push("{id}".to_string());
        } else {
            canonical_segments.push(segment.to_string());
        }
    }

    if canonical_segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", canonical_segments.join("/"))
    }
}

fn is_dynamic_segment(segment: &str) -> bool {
    if segment.is_empty() || segment.contains('.') {
        return false;
    }
    if segment.chars().all(|ch| ch.is_ascii_digit()) {
        return true;
    }
    if is_uuid_like(segment) {
        return true;
    }
    if segment.len() >= 16 && segment.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return true;
    }
    if let Some((prefix, suffix)) = segment.rsplit_once('-') {
        return !prefix.is_empty() && suffix.chars().all(|ch| ch.is_ascii_hexdigit());
    }
    false
}

fn is_uuid_like(segment: &str) -> bool {
    let mut parts = segment.split('-');
    matches!(
        (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ),
        (Some(a), Some(b), Some(c), Some(d), Some(e), None)
            if [a.len(), b.len(), c.len(), d.len(), e.len()] == [8, 4, 4, 4, 12]
                && [a, b, c, d, e]
                    .into_iter()
                    .all(|part| part.chars().all(|ch| ch.is_ascii_hexdigit()))
    )
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalyticsSummary {
    pub total_requests: u64,
    pub total_errors: u64,
    pub error_rate: f64,
    pub unique_endpoints: usize,
    pub top_endpoints: Vec<EndpointMetrics>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_metrics() {
        let mut analytics = ApiAnalytics::new();
        analytics.record("GET", "/api/health", 1.5, false);
        analytics.record("GET", "/api/health", 2.0, false);
        analytics.record("POST", "/api/scan/buffer", 50.0, false);
        analytics.record("POST", "/api/scan/buffer", 100.0, true);

        let metrics = analytics.metrics();
        assert_eq!(metrics.len(), 2);
    }

    #[test]
    fn summary_totals() {
        let mut analytics = ApiAnalytics::new();
        for i in 0..10 {
            analytics.record("GET", "/api/alerts", i as f64, i == 5);
        }
        let summary = analytics.summary();
        assert_eq!(summary.total_requests, 10);
        assert_eq!(summary.total_errors, 1);
        assert!(summary.error_rate > 0.0);
    }

    #[test]
    fn p95_calculation() {
        let mut analytics = ApiAnalytics::new();
        for i in 1..=100 {
            analytics.record("GET", "/api/test", i as f64, false);
        }
        let metrics = analytics.metrics();
        let m = &metrics[0];
        assert!(m.p95_latency_ms >= 95.0);
        assert!(m.p99_latency_ms >= 99.0);
        assert_eq!(m.min_latency_ms, 1.0);
        assert_eq!(m.max_latency_ms, 100.0);
        assert_eq!(m.latency_histogram.last().map(|bucket| bucket.count), Some(100));
    }

    #[test]
    fn empty_analytics() {
        let analytics = ApiAnalytics::new();
        let summary = analytics.summary();
        assert_eq!(summary.total_requests, 0);
        assert_eq!(summary.unique_endpoints, 0);
    }

    #[test]
    fn record_canonicalizes_dynamic_path_segments() {
        let mut analytics = ApiAnalytics::new();
        analytics.record("GET", "/api/cases/123", 4.0, false);
        analytics.record("GET", "/api/cases/456", 6.0, false);
        analytics.record(
            "GET",
            "/api/playbook/execution/exec-1/recovery-actions",
            8.0,
            false,
        );
        analytics.record(
            "GET",
            "/api/playbook/execution/exec-9/recovery-actions",
            9.0,
            false,
        );
        analytics.record(
            "GET",
            "/api/agents/550e8400-e29b-41d4-a716-446655440000",
            5.0,
            false,
        );

        let metrics = analytics.metrics();
        assert!(metrics.iter().any(|metric| metric.path == "/api/cases/{id}"));
        assert!(metrics.iter().any(|metric| metric.path == "/api/playbook/execution/{id}/recovery-actions"));
        assert!(metrics.iter().any(|metric| metric.path == "/api/agents/{id}"));
        assert_eq!(metrics.iter().filter(|metric| metric.path == "/api/cases/{id}").count(), 1);
    }

    #[test]
    fn canonicalization_preserves_versioned_artifact_paths() {
        assert_eq!(
            canonicalize_path("/api/updates/download/wardex-2.0.0-linux"),
            "/api/updates/download/wardex-2.0.0-linux"
        );
    }
}
