// ── Prometheus Metrics ────────────────────────────────────────────────────────
//
// Counters, gauges, and histograms exported in Prometheus text exposition format
// at GET /api/metrics.  No external dependency required — we emit the simple
// text format (content-type: text/plain; version=0.0.4).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

// ── Metric types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum MetricValue {
    Counter(f64),
    Gauge(f64),
    Histogram { sum: f64, count: u64, buckets: Vec<(f64, u64)> },
}

#[derive(Debug, Clone)]
pub struct MetricEntry {
    pub name: String,
    pub help: String,
    pub metric_type: String, // "counter", "gauge", "histogram"
    pub labels: BTreeMap<String, String>,
    pub value: MetricValue,
}

// ── Registry ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MetricsRegistry {
    entries: BTreeMap<String, Vec<MetricEntry>>,
    start_time: Instant,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            start_time: Instant::now(),
        }
    }

    pub fn counter(&mut self, name: &str, help: &str, labels: BTreeMap<String, String>, value: f64) {
        let entry = MetricEntry {
            name: name.into(),
            help: help.into(),
            metric_type: "counter".into(),
            labels,
            value: MetricValue::Counter(value),
        };
        self.entries.entry(name.into()).or_default().push(entry);
    }

    pub fn gauge(&mut self, name: &str, help: &str, labels: BTreeMap<String, String>, value: f64) {
        let entry = MetricEntry {
            name: name.into(),
            help: help.into(),
            metric_type: "gauge".into(),
            labels,
            value: MetricValue::Gauge(value),
        };
        self.entries.entry(name.into()).or_default().push(entry);
    }

    pub fn histogram(&mut self, name: &str, help: &str, labels: BTreeMap<String, String>, sum: f64, count: u64, buckets: Vec<(f64, u64)>) {
        let entry = MetricEntry {
            name: name.into(),
            help: help.into(),
            metric_type: "histogram".into(),
            labels,
            value: MetricValue::Histogram { sum, count, buckets },
        };
        self.entries.entry(name.into()).or_default().push(entry);
    }

    pub fn render(&self) -> String {
        let mut out = String::with_capacity(4096);
        for (name, entries) in &self.entries {
            if let Some(first) = entries.first() {
                out.push_str(&format!("# HELP {} {}\n", name, first.help));
                out.push_str(&format!("# TYPE {} {}\n", name, first.metric_type));
            }
            for e in entries {
                match &e.value {
                    MetricValue::Counter(v) | MetricValue::Gauge(v) => {
                        out.push_str(&format!("{}{} {}\n", e.name, format_labels(&e.labels), v));
                    }
                    MetricValue::Histogram { sum, count, buckets } => {
                        for (le, c) in buckets {
                            let mut lb = e.labels.clone();
                            lb.insert("le".into(), format!("{}", le));
                            out.push_str(&format!("{}_bucket{} {}\n", e.name, format_labels(&lb), c));
                        }
                        let mut lb_inf = e.labels.clone();
                        lb_inf.insert("le".into(), "+Inf".into());
                        out.push_str(&format!("{}_bucket{} {}\n", e.name, format_labels(&lb_inf), count));
                        out.push_str(&format!("{}_sum{} {}\n", e.name, format_labels(&e.labels), sum));
                        out.push_str(&format!("{}_count{} {}\n", e.name, format_labels(&e.labels), count));
                    }
                }
            }
        }
        out
    }

    pub fn uptime_secs(&self) -> f64 {
        self.start_time.elapsed().as_secs_f64()
    }
}

fn format_labels(labels: &BTreeMap<String, String>) -> String {
    if labels.is_empty() {
        return String::new();
    }
    let pairs: Vec<String> = labels
        .iter()
        .map(|(k, v)| format!("{}=\"{}\"", k, v.replace('\\', "\\\\").replace('"', "\\\"")))
        .collect();
    format!("{{{}}}", pairs.join(","))
}

// ── Shared thread-safe collector ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SharedMetrics {
    inner: Arc<Mutex<LiveCounters>>,
    start: Instant,
}

#[derive(Debug, Clone)]
pub struct LiveCounters {
    pub http_requests_total: u64,
    pub http_requests_by_method: BTreeMap<String, u64>,
    pub http_requests_by_status: BTreeMap<u16, u64>,
    pub http_request_duration_sum_ms: f64,
    pub http_request_count: u64,
    pub alerts_total: u64,
    pub alerts_by_level: BTreeMap<String, u64>,
    pub incidents_open: u64,
    pub incidents_total: u64,
    pub agents_online: u64,
    pub agents_total: u64,
    pub events_ingested: u64,
    pub auth_failures: u64,
    pub rate_limit_hits: u64,
    pub detection_runs: u64,
    pub response_actions: u64,
    pub storage_bytes: u64,
    pub queue_depth: u64,
}

impl Default for LiveCounters {
    fn default() -> Self {
        Self {
            http_requests_total: 0,
            http_requests_by_method: BTreeMap::new(),
            http_requests_by_status: BTreeMap::new(),
            http_request_duration_sum_ms: 0.0,
            http_request_count: 0,
            alerts_total: 0,
            alerts_by_level: BTreeMap::new(),
            incidents_open: 0,
            incidents_total: 0,
            agents_online: 0,
            agents_total: 0,
            events_ingested: 0,
            auth_failures: 0,
            rate_limit_hits: 0,
            detection_runs: 0,
            response_actions: 0,
            storage_bytes: 0,
            queue_depth: 0,
        }
    }
}

impl SharedMetrics {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(LiveCounters::default())),
            start: Instant::now(),
        }
    }

    pub fn record_request(&self, method: &str, status: u16, duration_ms: f64) {
        if let Ok(mut c) = self.inner.lock() {
            c.http_requests_total += 1;
            *c.http_requests_by_method.entry(method.to_uppercase()).or_insert(0) += 1;
            *c.http_requests_by_status.entry(status).or_insert(0) += 1;
            c.http_request_duration_sum_ms += duration_ms;
            c.http_request_count += 1;
        }
    }

    pub fn inc_alerts(&self, level: &str) {
        if let Ok(mut c) = self.inner.lock() {
            c.alerts_total += 1;
            *c.alerts_by_level.entry(level.to_string()).or_insert(0) += 1;
        }
    }

    pub fn inc_events(&self, count: u64) {
        if let Ok(mut c) = self.inner.lock() {
            c.events_ingested += count;
        }
    }

    pub fn inc_auth_failures(&self) {
        if let Ok(mut c) = self.inner.lock() {
            c.auth_failures += 1;
        }
    }

    pub fn inc_rate_limit_hits(&self) {
        if let Ok(mut c) = self.inner.lock() {
            c.rate_limit_hits += 1;
        }
    }

    pub fn inc_detection_runs(&self) {
        if let Ok(mut c) = self.inner.lock() {
            c.detection_runs += 1;
        }
    }

    pub fn inc_response_actions(&self) {
        if let Ok(mut c) = self.inner.lock() {
            c.response_actions += 1;
        }
    }

    pub fn set_agents(&self, online: u64, total: u64) {
        if let Ok(mut c) = self.inner.lock() {
            c.agents_online = online;
            c.agents_total = total;
        }
    }

    pub fn set_incidents(&self, open: u64, total: u64) {
        if let Ok(mut c) = self.inner.lock() {
            c.incidents_open = open;
            c.incidents_total = total;
        }
    }

    pub fn set_queue_depth(&self, depth: u64) {
        if let Ok(mut c) = self.inner.lock() {
            c.queue_depth = depth;
        }
    }

    pub fn set_storage_bytes(&self, bytes: u64) {
        if let Ok(mut c) = self.inner.lock() {
            c.storage_bytes = bytes;
        }
    }

    pub fn snapshot(&self) -> LiveCounters {
        self.inner.lock().map(|c| c.clone()).unwrap_or_default()
    }

    pub fn render_prometheus(&self) -> String {
        let c = self.snapshot();
        let uptime = self.start.elapsed().as_secs_f64();
        let mut reg = MetricsRegistry::new();

        // Process
        reg.gauge("wardex_uptime_seconds", "Seconds since server start", BTreeMap::new(), uptime);
        reg.gauge("wardex_info", "Platform info", {
            let mut m = BTreeMap::new();
            m.insert("version".into(), env!("CARGO_PKG_VERSION").into());
            m
        }, 1.0);

        // HTTP
        reg.counter("wardex_http_requests_total", "Total HTTP requests", BTreeMap::new(), c.http_requests_total as f64);
        for (method, count) in &c.http_requests_by_method {
            reg.counter("wardex_http_requests_by_method", "HTTP requests by method", {
                let mut m = BTreeMap::new();
                m.insert("method".into(), method.clone());
                m
            }, *count as f64);
        }
        for (status, count) in &c.http_requests_by_status {
            reg.counter("wardex_http_responses_by_status", "HTTP responses by status code", {
                let mut m = BTreeMap::new();
                m.insert("status".into(), status.to_string());
                m
            }, *count as f64);
        }
        if c.http_request_count > 0 {
            let avg = c.http_request_duration_sum_ms / c.http_request_count as f64;
            reg.gauge("wardex_http_request_duration_avg_ms", "Average HTTP request duration in ms", BTreeMap::new(), avg);
        }

        // Alerts
        reg.counter("wardex_alerts_total", "Total alerts generated", BTreeMap::new(), c.alerts_total as f64);
        for (level, count) in &c.alerts_by_level {
            reg.counter("wardex_alerts_by_level", "Alerts by severity level", {
                let mut m = BTreeMap::new();
                m.insert("level".into(), level.clone());
                m
            }, *count as f64);
        }

        // Incidents
        reg.gauge("wardex_incidents_open", "Currently open incidents", BTreeMap::new(), c.incidents_open as f64);
        reg.counter("wardex_incidents_total", "Total incidents created", BTreeMap::new(), c.incidents_total as f64);

        // Fleet
        reg.gauge("wardex_agents_online", "Currently online agents", BTreeMap::new(), c.agents_online as f64);
        reg.gauge("wardex_agents_total", "Total enrolled agents", BTreeMap::new(), c.agents_total as f64);

        // Events
        reg.counter("wardex_events_ingested_total", "Total events ingested", BTreeMap::new(), c.events_ingested as f64);

        // Security
        reg.counter("wardex_auth_failures_total", "Total authentication failures", BTreeMap::new(), c.auth_failures as f64);
        reg.counter("wardex_rate_limit_hits_total", "Total rate limit rejections", BTreeMap::new(), c.rate_limit_hits as f64);

        // Operations
        reg.counter("wardex_detection_runs_total", "Total detection pipeline runs", BTreeMap::new(), c.detection_runs as f64);
        reg.counter("wardex_response_actions_total", "Total response actions executed", BTreeMap::new(), c.response_actions as f64);

        // Storage
        reg.gauge("wardex_storage_bytes", "Storage backend size in bytes", BTreeMap::new(), c.storage_bytes as f64);
        reg.gauge("wardex_queue_depth", "Current alert queue depth", BTreeMap::new(), c.queue_depth as f64);

        reg.render()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_renders_counter() {
        let mut reg = MetricsRegistry::new();
        reg.counter("test_counter", "A test counter", BTreeMap::new(), 42.0);
        let out = reg.render();
        assert!(out.contains("# HELP test_counter A test counter"));
        assert!(out.contains("# TYPE test_counter counter"));
        assert!(out.contains("test_counter 42"));
    }

    #[test]
    fn registry_renders_gauge() {
        let mut reg = MetricsRegistry::new();
        reg.gauge("test_gauge", "A test gauge", BTreeMap::new(), 3.14);
        let out = reg.render();
        assert!(out.contains("# TYPE test_gauge gauge"));
        assert!(out.contains("test_gauge 3.14"));
    }

    #[test]
    fn registry_renders_labels() {
        let mut reg = MetricsRegistry::new();
        let mut labels = BTreeMap::new();
        labels.insert("method".into(), "GET".into());
        labels.insert("status".into(), "200".into());
        reg.counter("http_total", "Total HTTP", labels, 100.0);
        let out = reg.render();
        assert!(out.contains("method=\"GET\""));
        assert!(out.contains("status=\"200\""));
    }

    #[test]
    fn registry_renders_histogram() {
        let mut reg = MetricsRegistry::new();
        let buckets = vec![(10.0, 5), (50.0, 8), (100.0, 10)];
        reg.histogram("req_duration", "Request duration", BTreeMap::new(), 350.0, 10, buckets);
        let out = reg.render();
        assert!(out.contains("req_duration_bucket{le=\"10\"} 5"));
        assert!(out.contains("req_duration_bucket{le=\"+Inf\"} 10"));
        assert!(out.contains("req_duration_sum 350"));
        assert!(out.contains("req_duration_count 10"));
    }

    #[test]
    fn shared_metrics_record_request() {
        let m = SharedMetrics::new();
        m.record_request("GET", 200, 5.0);
        m.record_request("POST", 201, 10.0);
        m.record_request("GET", 200, 3.0);
        let snap = m.snapshot();
        assert_eq!(snap.http_requests_total, 3);
        assert_eq!(snap.http_requests_by_method["GET"], 2);
        assert_eq!(snap.http_requests_by_method["POST"], 1);
        assert_eq!(snap.http_requests_by_status[&200], 2);
    }

    #[test]
    fn shared_metrics_alerts() {
        let m = SharedMetrics::new();
        m.inc_alerts("critical");
        m.inc_alerts("critical");
        m.inc_alerts("elevated");
        let snap = m.snapshot();
        assert_eq!(snap.alerts_total, 3);
        assert_eq!(snap.alerts_by_level["critical"], 2);
        assert_eq!(snap.alerts_by_level["elevated"], 1);
    }

    #[test]
    fn shared_metrics_render_prometheus() {
        let m = SharedMetrics::new();
        m.record_request("GET", 200, 5.0);
        m.inc_alerts("severe");
        m.set_agents(3, 5);
        m.set_incidents(2, 10);
        let out = m.render_prometheus();
        assert!(out.contains("wardex_uptime_seconds"));
        assert!(out.contains("wardex_http_requests_total"));
        assert!(out.contains("wardex_alerts_total"));
        assert!(out.contains("wardex_agents_online"));
        assert!(out.contains("wardex_incidents_open"));
    }

    #[test]
    fn shared_metrics_thread_safe() {
        let m = SharedMetrics::new();
        let m2 = m.clone();
        let h = std::thread::spawn(move || {
            for _ in 0..100 {
                m2.record_request("GET", 200, 1.0);
            }
        });
        for _ in 0..100 {
            m.record_request("POST", 201, 2.0);
        }
        h.join().unwrap();
        let snap = m.snapshot();
        assert_eq!(snap.http_requests_total, 200);
    }

    #[test]
    fn format_labels_escapes_quotes() {
        let mut labels = BTreeMap::new();
        labels.insert("path".into(), "/api/\"test\"".into());
        let result = format_labels(&labels);
        assert!(result.contains("\\\"test\\\""));
    }

    #[test]
    fn empty_registry_renders_empty() {
        let reg = MetricsRegistry::new();
        assert!(reg.render().is_empty());
    }
}
