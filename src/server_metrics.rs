//! Prometheus exposition helpers extracted from `src/server.rs`.
//!
//! The orchestrator (`prometheus_metrics_payload`) still lives in `server.rs`
//! because it touches many crate-private `AppState` fields. The two helpers
//! below render self-contained blocks of the exposition body off process-global
//! observability sources, so they are easy to lift out and unit-test
//! independently.

/// Escape a Prometheus label value per the exposition format: backslash,
/// double-quote, and newline must be backslash-escaped.
pub(crate) fn prom_escape_label(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

/// Render the per-callsite (labeled) lock metrics block.
///
/// Pulls a fresh snapshot from `crate::state_lock::label_snapshot()` and
/// emits the five `wardex_state_lock_labeled_*` series. Returns an empty
/// string when no labels have been recorded yet (so the caller can simply
/// `push_str` the result without conditionals).
pub(crate) fn render_labeled_lock_metrics() -> String {
    let label_stats = crate::state_lock::label_snapshot();
    if label_stats.is_empty() {
        return String::new();
    }

    let mut body = String::new();

    body.push_str("# HELP wardex_state_lock_labeled_acquisitions_total\n");
    body.push_str("# TYPE wardex_state_lock_labeled_acquisitions_total counter\n");
    for (label, stats) in &label_stats {
        body.push_str(&format!(
            "wardex_state_lock_labeled_acquisitions_total{{label=\"{}\"}} {}\n",
            prom_escape_label(label),
            stats.acquisitions
        ));
    }

    body.push_str("# HELP wardex_state_lock_labeled_wait_ns_total\n");
    body.push_str("# TYPE wardex_state_lock_labeled_wait_ns_total counter\n");
    for (label, stats) in &label_stats {
        body.push_str(&format!(
            "wardex_state_lock_labeled_wait_ns_total{{label=\"{}\"}} {}\n",
            prom_escape_label(label),
            stats.wait_ns_total
        ));
    }

    body.push_str("# HELP wardex_state_lock_labeled_slow_waits_total\n");
    body.push_str("# TYPE wardex_state_lock_labeled_slow_waits_total counter\n");
    for (label, stats) in &label_stats {
        body.push_str(&format!(
            "wardex_state_lock_labeled_slow_waits_total{{label=\"{}\"}} {}\n",
            prom_escape_label(label),
            stats.slow_waits
        ));
    }

    body.push_str("# HELP wardex_state_lock_labeled_max_wait_ns\n");
    body.push_str("# TYPE wardex_state_lock_labeled_max_wait_ns gauge\n");
    for (label, stats) in &label_stats {
        body.push_str(&format!(
            "wardex_state_lock_labeled_max_wait_ns{{label=\"{}\"}} {}\n",
            prom_escape_label(label),
            stats.max_wait_ns
        ));
    }

    body.push_str("# HELP wardex_state_lock_labeled_mean_wait_ms\n");
    body.push_str("# TYPE wardex_state_lock_labeled_mean_wait_ms gauge\n");
    for (label, stats) in &label_stats {
        body.push_str(&format!(
            "wardex_state_lock_labeled_mean_wait_ms{{label=\"{}\"}} {:.6}\n",
            prom_escape_label(label),
            stats.mean_wait_ms()
        ));
    }

    body
}

/// Render metric-budget drops for process-global observability sources.
pub(crate) fn render_metrics_drop_metrics() -> String {
    let dropped = crate::state_lock::label_drop_snapshot();
    format!(
        concat!(
            "# HELP wardex_metrics_dropped_total\n",
            "# TYPE wardex_metrics_dropped_total counter\n",
            "wardex_metrics_dropped_total{{family=\"wardex_state_lock_labeled\",reason=\"label_limit\"}} {}\n"
        ),
        dropped
    )
}

/// Render the failed-auth observability block.
///
/// Pulls a snapshot from `crate::server_auth::failed_auth_stats()` and emits
/// the five counters plus two gauges that the lockout/rate-limit detection
/// stack exposes.
pub(crate) fn render_failed_auth_metrics() -> String {
    let auth_stats = crate::server_auth::failed_auth_stats();
    let mut body = String::new();

    for (name, metric_type, value) in [
        (
            "wardex_failed_auth_failures_total",
            "counter",
            auth_stats.failures_total,
        ),
        (
            "wardex_failed_auth_lockouts_triggered_total",
            "counter",
            auth_stats.lockouts_triggered_total,
        ),
        (
            "wardex_failed_auth_lockout_breach_attempts_total",
            "counter",
            auth_stats.lockout_breach_attempts_total,
        ),
        (
            "wardex_failed_auth_resets_total",
            "counter",
            auth_stats.resets_total,
        ),
        (
            "wardex_failed_auth_exempt_skips_total",
            "counter",
            auth_stats.exempt_skips_total,
        ),
        (
            "wardex_failed_auth_active_lockouts",
            "gauge",
            auth_stats.active_lockouts,
        ),
        (
            "wardex_failed_auth_tracked_entries",
            "gauge",
            auth_stats.tracked_entries,
        ),
    ] {
        body.push_str("# HELP ");
        body.push_str(name);
        body.push('\n');
        body.push_str("# TYPE ");
        body.push_str(name);
        body.push(' ');
        body.push_str(metric_type);
        body.push('\n');
        body.push_str(name);
        body.push(' ');
        body.push_str(&value.to_string());
        body.push('\n');
    }

    body
}

/// Render bounded per-endpoint request SLO metrics from the in-memory API
/// analytics tracker.
pub(crate) fn render_api_endpoint_metrics(
    metrics: &[crate::api_analytics::EndpointMetrics],
) -> String {
    if metrics.is_empty() {
        return String::new();
    }

    let mut body = String::new();
    body.push_str("# HELP wardex_api_endpoint_requests_total\n");
    body.push_str("# TYPE wardex_api_endpoint_requests_total counter\n");

    fn endpoint_p95(metric: &crate::api_analytics::EndpointMetrics) -> f64 {
        metric.p95_latency_ms
    }

    fn endpoint_p99(metric: &crate::api_analytics::EndpointMetrics) -> f64 {
        metric.p99_latency_ms
    }
    for metric in metrics.iter().take(50) {
        body.push_str(&format!(
            "wardex_api_endpoint_requests_total{{method=\"{}\",path=\"{}\"}} {}\n",
            prom_escape_label(&metric.method),
            prom_escape_label(&metric.path),
            metric.request_count
        ));
    }

    body.push_str("# HELP wardex_api_endpoint_errors_total\n");
    body.push_str("# TYPE wardex_api_endpoint_errors_total counter\n");
    for metric in metrics.iter().take(50) {
        body.push_str(&format!(
            "wardex_api_endpoint_errors_total{{method=\"{}\",path=\"{}\"}} {}\n",
            prom_escape_label(&metric.method),
            prom_escape_label(&metric.path),
            metric.error_count
        ));
    }

    body.push_str(
        "# HELP wardex_api_endpoint_latency_ms Request latency histogram per canonical endpoint\n",
    );
    body.push_str("# TYPE wardex_api_endpoint_latency_ms histogram\n");
    for metric in metrics.iter().take(50) {
        for bucket in &metric.latency_histogram {
            body.push_str(&format!(
                "wardex_api_endpoint_latency_ms_bucket{{method=\"{}\",path=\"{}\",le=\"{}\"}} {}\n",
                prom_escape_label(&metric.method),
                prom_escape_label(&metric.path),
                prom_format_bucket(bucket.le_ms),
                bucket.count
            ));
        }
        body.push_str(&format!(
            "wardex_api_endpoint_latency_ms_bucket{{method=\"{}\",path=\"{}\",le=\"+Inf\"}} {}\n",
            prom_escape_label(&metric.method),
            prom_escape_label(&metric.path),
            metric.request_count
        ));
        body.push_str(&format!(
            "wardex_api_endpoint_latency_ms_sum{{method=\"{}\",path=\"{}\"}} {:.3}\n",
            prom_escape_label(&metric.method),
            prom_escape_label(&metric.path),
            metric.total_latency_ms
        ));
        body.push_str(&format!(
            "wardex_api_endpoint_latency_ms_count{{method=\"{}\",path=\"{}\"}} {}\n",
            prom_escape_label(&metric.method),
            prom_escape_label(&metric.path),
            metric.request_count
        ));
    }

    let latency_fields: [(&str, fn(&crate::api_analytics::EndpointMetrics) -> f64); 2] = [
        ("wardex_api_endpoint_latency_p95_ms", endpoint_p95),
        ("wardex_api_endpoint_latency_p99_ms", endpoint_p99),
    ];
    for (name, field) in latency_fields {
        body.push_str(&format!("# HELP {name}\n"));
        body.push_str(&format!("# TYPE {name} gauge\n"));
        for metric in metrics.iter().take(50) {
            body.push_str(&format!(
                "{name}{{method=\"{}\",path=\"{}\"}} {:.3}\n",
                prom_escape_label(&metric.method),
                prom_escape_label(&metric.path),
                field(metric)
            ));
        }
    }

    body
}

fn prom_format_bucket(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{value:.0}")
    } else {
        format!("{value:.3}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prom_escape_label_quotes_special_chars() {
        assert_eq!(prom_escape_label("plain"), "plain");
        assert_eq!(prom_escape_label("a\\b"), "a\\\\b");
        assert_eq!(prom_escape_label("a\"b"), "a\\\"b");
        assert_eq!(prom_escape_label("a\nb"), "a\\nb");
        assert_eq!(prom_escape_label("\\\"\n"), "\\\\\\\"\\n");
    }

    #[test]
    fn api_endpoint_metrics_render_request_error_and_tail_latency() {
        let metrics = vec![crate::api_analytics::EndpointMetrics {
            path: "/api/example\"route".to_string(),
            method: "GET".to_string(),
            request_count: 7,
            error_count: 2,
            total_latency_ms: 70.0,
            min_latency_ms: 1.0,
            max_latency_ms: 30.0,
            avg_latency_ms: 10.0,
            p95_latency_ms: 25.0,
            p99_latency_ms: 30.0,
            latency_histogram: vec![
                crate::api_analytics::LatencyBucket {
                    le_ms: 50.0,
                    count: 7,
                },
                crate::api_analytics::LatencyBucket {
                    le_ms: 100.0,
                    count: 7,
                },
            ],
        }];

        let rendered = render_api_endpoint_metrics(&metrics);
        assert!(rendered.contains("wardex_api_endpoint_requests_total"));
        assert!(rendered.contains("wardex_api_endpoint_errors_total"));
        assert!(rendered.contains("wardex_api_endpoint_latency_ms_bucket"));
        assert!(rendered.contains("le=\"50\""));
        assert!(rendered.contains("wardex_api_endpoint_latency_p99_ms"));
        assert!(rendered.contains("/api/example\\\"route"));
    }

    #[test]
    fn failed_auth_metrics_block_emits_all_series() {
        let body = render_failed_auth_metrics();
        for name in [
            "wardex_failed_auth_failures_total",
            "wardex_failed_auth_lockouts_triggered_total",
            "wardex_failed_auth_lockout_breach_attempts_total",
            "wardex_failed_auth_resets_total",
            "wardex_failed_auth_exempt_skips_total",
            "wardex_failed_auth_active_lockouts",
            "wardex_failed_auth_tracked_entries",
        ] {
            assert!(
                body.contains(&format!("# TYPE {name} ")),
                "missing TYPE line for {name}",
            );
        }
    }

    #[test]
    fn metrics_drop_block_emits_budget_series() {
        let body = render_metrics_drop_metrics();
        assert!(body.contains("# TYPE wardex_metrics_dropped_total counter"));
        assert!(body.contains(
            "wardex_metrics_dropped_total{family=\"wardex_state_lock_labeled\",reason=\"label_limit\"}"
        ));
    }
}
