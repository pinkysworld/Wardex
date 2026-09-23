use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

pub const CSV_HEADER: &str = "timestamp_ms,cpu_load_pct,memory_load_pct,temperature_c,network_kbps,auth_failures,battery_pct,integrity_drift,process_count,disk_pressure_pct";

// ── OpenTelemetry-compatible tracing ────────────────────────────

static TRACE_ID_COUNTER: AtomicU64 = AtomicU64::new(1);
static SPAN_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Generate a new trace ID (hex string).
pub fn new_trace_id() -> String {
    let id = TRACE_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{id:032x}")
}

/// Generate a new span ID (hex string).
pub fn new_span_id() -> String {
    let id = SPAN_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{id:016x}")
}

/// An OpenTelemetry-compatible span.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtelSpan {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub operation_name: String,
    pub service_name: String,
    pub start_time_ms: u64,
    pub end_time_ms: Option<u64>,
    pub status: SpanStatus,
    pub attributes: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SpanStatus {
    Unset,
    Ok,
    Error,
}

impl OtelSpan {
    pub fn new(operation: &str) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            trace_id: new_trace_id(),
            span_id: new_span_id(),
            parent_span_id: None,
            operation_name: operation.to_string(),
            service_name: "wardex".into(),
            start_time_ms: now,
            end_time_ms: None,
            status: SpanStatus::Unset,
            attributes: Vec::new(),
        }
    }

    pub fn child(&self, operation: &str) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            trace_id: self.trace_id.clone(),
            span_id: new_span_id(),
            parent_span_id: Some(self.span_id.clone()),
            operation_name: operation.to_string(),
            service_name: "wardex".into(),
            start_time_ms: now,
            end_time_ms: None,
            status: SpanStatus::Unset,
            attributes: Vec::new(),
        }
    }

    pub fn set_attribute(&mut self, key: &str, value: &str) {
        self.attributes.push((key.to_string(), value.to_string()));
    }

    pub fn finish(&mut self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        self.end_time_ms = Some(now);
        if self.status == SpanStatus::Unset {
            self.status = SpanStatus::Ok;
        }
    }

    pub fn finish_error(&mut self, error_msg: &str) {
        self.finish();
        self.status = SpanStatus::Error;
        self.set_attribute("error.message", error_msg);
    }

    pub fn duration_ms(&self) -> Option<u64> {
        self.end_time_ms
            .map(|end| end.saturating_sub(self.start_time_ms))
    }

    /// Export span in OTLP-compatible JSON format.
    pub fn to_otlp_json(&self) -> serde_json::Value {
        serde_json::json!({
            "resourceSpans": [{
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": self.service_name}},
                    ]
                },
                "scopeSpans": [{
                    "spans": [{
                        "traceId": self.trace_id,
                        "spanId": self.span_id,
                        "parentSpanId": self.parent_span_id,
                        "name": self.operation_name,
                        "startTimeUnixNano": self.start_time_ms * 1_000_000,
                        "endTimeUnixNano": self.end_time_ms.unwrap_or(0) * 1_000_000,
                        "status": {"code": match self.status {
                            SpanStatus::Unset => 0,
                            SpanStatus::Ok => 1,
                            SpanStatus::Error => 2,
                        }},
                        "attributes": self.attributes.iter().map(|(k, v)| {
                            serde_json::json!({"key": k, "value": {"stringValue": v}})
                        }).collect::<Vec<_>>(),
                    }]
                }]
            }]
        })
    }
}

/// Trace collector for aggregating spans.
#[derive(Debug, Default)]
pub struct TraceCollector {
    spans: std::collections::VecDeque<OtelSpan>,
    max_spans: usize,
}

impl TraceCollector {
    pub fn new(max_spans: usize) -> Self {
        Self {
            spans: std::collections::VecDeque::new(),
            max_spans,
        }
    }

    pub fn record(&mut self, span: OtelSpan) {
        self.spans.push_back(span);
        if self.spans.len() > self.max_spans {
            self.spans.pop_front();
        }
    }

    pub fn recent(&self, limit: usize) -> Vec<&OtelSpan> {
        self.spans.iter().rev().take(limit).collect()
    }

    pub fn stats(&self) -> TraceStats {
        let total = self.spans.len();
        let errors = self
            .spans
            .iter()
            .filter(|s| s.status == SpanStatus::Error)
            .count();
        let avg_duration = if total > 0 {
            let sum: u64 = self.spans.iter().filter_map(OtelSpan::duration_ms).sum();
            sum as f64 / total as f64
        } else {
            0.0
        };
        TraceStats {
            total_spans: total,
            error_spans: errors,
            avg_duration_ms: avg_duration,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TraceStats {
    pub total_spans: usize,
    pub error_spans: usize,
    pub avg_duration_ms: f64,
}

// ── MITRE ATT&CK Mapping ──────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MitreAttack {
    pub tactic: String,
    pub technique_id: String,
    pub technique_name: String,
}

/// Map alert reasons to MITRE ATT&CK techniques.
pub fn map_alert_to_mitre(reasons: &[String]) -> Vec<MitreAttack> {
    let mut result = Vec::new();
    let joined = reasons.join(" ");
    let j = joined.to_lowercase();

    if j.contains("auth") || j.contains("brute") || j.contains("credential") {
        result.push(MitreAttack {
            tactic: "Credential Access (TA0006)".into(),
            technique_id: "T1110".into(),
            technique_name: "Brute Force".into(),
        });
    }
    if (j.contains("cpu") && j.contains("network")) || j.contains("mining") || j.contains("hijack")
    {
        result.push(MitreAttack {
            tactic: "Impact (TA0040)".into(),
            technique_id: "T1496".into(),
            technique_name: "Resource Hijacking".into(),
        });
    }
    if j.contains("integrity") || j.contains("drift") || j.contains("tamper") {
        result.push(MitreAttack {
            tactic: "Impact (TA0040)".into(),
            technique_id: "T1565".into(),
            technique_name: "Data Manipulation".into(),
        });
    }
    if j.contains("network") && !j.contains("cpu") {
        result.push(MitreAttack {
            tactic: "Command and Control (TA0011)".into(),
            technique_id: "T1071".into(),
            technique_name: "Application Layer Protocol".into(),
        });
    }
    if j.contains("process") || j.contains("injection") {
        result.push(MitreAttack {
            tactic: "Defense Evasion (TA0005)".into(),
            technique_id: "T1055".into(),
            technique_name: "Process Injection".into(),
        });
    }
    if j.contains("compound") || j.contains("multi") {
        result.push(MitreAttack {
            tactic: "Execution (TA0002)".into(),
            technique_id: "T1059".into(),
            technique_name: "Command and Scripting Interpreter".into(),
        });
    }
    if j.contains("exfil") || j.contains("data_transfer") {
        result.push(MitreAttack {
            tactic: "Exfiltration (TA0010)".into(),
            technique_id: "T1041".into(),
            technique_name: "Exfiltration Over C2 Channel".into(),
        });
    }
    if j.contains("persist")
        || j.contains("launch_agent")
        || j.contains("systemd")
        || j.contains("scheduled")
    {
        result.push(MitreAttack {
            tactic: "Persistence (TA0003)".into(),
            technique_id: "T1053".into(),
            technique_name: "Scheduled Task/Job".into(),
        });
    }
    result
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct TelemetrySample {
    pub timestamp_ms: u64,
    pub cpu_load_pct: f32,
    pub memory_load_pct: f32,
    pub temperature_c: f32,
    pub network_kbps: f32,
    pub auth_failures: u32,
    pub battery_pct: f32,
    pub integrity_drift: f32,
    /// Number of active processes (T014). Defaults to 0 when absent.
    #[serde(default)]
    pub process_count: u32,
    /// Disk I/O pressure as a percentage 0-100 (T014). Defaults to 0.
    #[serde(default)]
    pub disk_pressure_pct: f32,
}

#[derive(Debug, Clone)]
pub struct ParseTelemetryError {
    message: String,
}

impl ParseTelemetryError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ParseTelemetryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for ParseTelemetryError {}

pub const CSV_HEADER_LEGACY: &str = "timestamp_ms,cpu_load_pct,memory_load_pct,temperature_c,network_kbps,auth_failures,battery_pct,integrity_drift";

impl TelemetrySample {
    pub fn parse_csv(path: &Path) -> Result<Vec<Self>, ParseTelemetryError> {
        let raw = fs::read_to_string(path).map_err(|error| {
            ParseTelemetryError::new(format!("failed to read {}: {error}", path.display()))
        })?;

        let mut lines = raw.lines().filter(|line| !line.trim().is_empty());
        let header = lines
            .next()
            .ok_or_else(|| ParseTelemetryError::new("telemetry file is empty"))?;

        let trimmed_header = header.trim();
        let columns = if trimmed_header == CSV_HEADER {
            10
        } else if trimmed_header == CSV_HEADER_LEGACY {
            8
        } else {
            return Err(ParseTelemetryError::new(format!(
                "unexpected CSV header. expected `{CSV_HEADER}` or `{CSV_HEADER_LEGACY}`"
            )));
        };

        let mut samples = Vec::new();
        for (line_offset, line) in lines.enumerate() {
            samples.push(Self::parse_line_cols(line, line_offset + 2, columns)?);
        }

        if samples.is_empty() {
            return Err(ParseTelemetryError::new(
                "telemetry file contained a header but no samples",
            ));
        }

        Ok(samples)
    }

    /// Parse from a JSONL file where each line is a JSON object.
    pub fn parse_jsonl(path: &Path) -> Result<Vec<Self>, ParseTelemetryError> {
        let raw = fs::read_to_string(path).map_err(|error| {
            ParseTelemetryError::new(format!("failed to read {}: {error}", path.display()))
        })?;

        let mut samples = Vec::new();
        for (line_num, line) in raw.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let sample: Self = serde_json::from_str(trimmed).map_err(|error| {
                ParseTelemetryError::new(format!("line {}: invalid JSON: {error}", line_num + 1,))
            })?;
            sample.validate(line_num + 1)?;
            samples.push(sample);
        }

        if samples.is_empty() {
            return Err(ParseTelemetryError::new("JSONL file contained no samples"));
        }

        Ok(samples)
    }

    /// Auto-detect format (CSV or JSONL) based on file extension.
    pub fn parse_auto(path: &Path) -> Result<Vec<Self>, ParseTelemetryError> {
        match path.extension().and_then(|e| e.to_str()) {
            Some("jsonl" | "ndjson") => Self::parse_jsonl(path),
            _ => Self::parse_csv(path),
        }
    }

    pub fn parse_line(line: &str, line_number: usize) -> Result<Self, ParseTelemetryError> {
        let cols = line.split(',').count();
        if cols == 9 {
            return Err(ParseTelemetryError::new(format!(
                "line {line_number}: expected 8 or 10 columns, found 9"
            )));
        }
        let expected = if cols >= 10 { 10 } else { 8 };
        Self::parse_line_cols(line, line_number, expected)
    }

    fn parse_line_cols(
        line: &str,
        line_number: usize,
        expected_cols: usize,
    ) -> Result<Self, ParseTelemetryError> {
        let parts: Vec<_> = line.split(',').map(str::trim).collect();
        if parts.len() != expected_cols {
            return Err(ParseTelemetryError::new(format!(
                "line {line_number}: expected {expected_cols} columns, found {}",
                parts.len()
            )));
        }

        let mut sample = Self {
            timestamp_ms: parse(parts[0], line_number, "timestamp_ms")?,
            cpu_load_pct: parse(parts[1], line_number, "cpu_load_pct")?,
            memory_load_pct: parse(parts[2], line_number, "memory_load_pct")?,
            temperature_c: parse(parts[3], line_number, "temperature_c")?,
            network_kbps: parse(parts[4], line_number, "network_kbps")?,
            auth_failures: parse(parts[5], line_number, "auth_failures")?,
            battery_pct: parse(parts[6], line_number, "battery_pct")?,
            integrity_drift: parse(parts[7], line_number, "integrity_drift")?,
            process_count: 0,
            disk_pressure_pct: 0.0,
        };

        if expected_cols >= 10 {
            sample.process_count = parse(parts[8], line_number, "process_count")?;
            sample.disk_pressure_pct = parse(parts[9], line_number, "disk_pressure_pct")?;
        }

        sample.validate(line_number)?;
        Ok(sample)
    }

    fn validate(&self, line_number: usize) -> Result<(), ParseTelemetryError> {
        validate_range(self.cpu_load_pct, 0.0, 100.0, line_number, "cpu_load_pct")?;
        validate_range(
            self.memory_load_pct,
            0.0,
            100.0,
            line_number,
            "memory_load_pct",
        )?;
        validate_range(self.battery_pct, 0.0, 100.0, line_number, "battery_pct")?;
        validate_range(
            self.integrity_drift,
            0.0,
            1.0,
            line_number,
            "integrity_drift",
        )?;
        validate_range(
            self.disk_pressure_pct,
            0.0,
            100.0,
            line_number,
            "disk_pressure_pct",
        )?;

        if self.network_kbps.is_nan() || self.network_kbps.is_infinite() || self.network_kbps < 0.0
        {
            return Err(ParseTelemetryError::new(format!(
                "line {line_number}: network_kbps must be a finite non-negative value"
            )));
        }

        if self.temperature_c.is_nan() || self.temperature_c.is_infinite() {
            return Err(ParseTelemetryError::new(format!(
                "line {line_number}: temperature_c must be a finite value"
            )));
        }

        Ok(())
    }
}

fn parse<T>(raw: &str, line_number: usize, field: &str) -> Result<T, ParseTelemetryError>
where
    T: std::str::FromStr,
    T::Err: fmt::Display,
{
    raw.parse::<T>().map_err(|error| {
        ParseTelemetryError::new(format!(
            "line {line_number}: invalid {field} value `{raw}`: {error}"
        ))
    })
}

fn validate_range(
    value: f32,
    min: f32,
    max: f32,
    line_number: usize,
    field: &str,
) -> Result<(), ParseTelemetryError> {
    if !(min..=max).contains(&value) {
        return Err(ParseTelemetryError::new(format!(
            "line {line_number}: {field} must be in range {min}..={max}"
        )));
    }

    Ok(())
}

// ── OTLP/HTTP exporter ───────────────────────────────────────────

/// Configuration for exporting spans/logs/metrics to an OTLP/HTTP collector.
///
/// Follows the shape of the cloud collector configs: an `enabled` flag, a
/// base endpoint, and serde defaults so existing configs without this
/// section keep loading unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtlpExporterConfig {
    /// Base collector URL, e.g. "http://otel-collector:4318". Signal paths
    /// ("/v1/traces", "/v1/logs", "/v1/metrics") are appended.
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub enabled: bool,
    /// Extra headers sent with every export request (e.g. an auth header).
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
    /// Maximum spans/records batched into a single export request.
    #[serde(default = "default_otlp_batch_size")]
    pub batch_max_size: usize,
    /// Maximum items buffered before new items are dropped.
    #[serde(default = "default_otlp_queue_size")]
    pub max_queue_size: usize,
    /// Export attempts per batch before giving up.
    #[serde(default = "default_otlp_max_retries")]
    pub max_retries: u32,
    /// Per-request timeout, in seconds.
    #[serde(default = "default_otlp_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_otlp_batch_size() -> usize {
    100
}
fn default_otlp_queue_size() -> usize {
    10_000
}
fn default_otlp_max_retries() -> u32 {
    3
}
fn default_otlp_timeout_secs() -> u64 {
    10
}

impl Default for OtlpExporterConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            enabled: false,
            headers: std::collections::HashMap::new(),
            batch_max_size: default_otlp_batch_size(),
            max_queue_size: default_otlp_queue_size(),
            max_retries: default_otlp_max_retries(),
            timeout_secs: default_otlp_timeout_secs(),
        }
    }
}

/// Bounded-queue, batching OTLP/HTTP JSON exporter.
///
/// Spans (and arbitrary log/metric records) are enqueued cheaply from any
/// call site; a caller periodically invokes `flush_traces`/`flush_logs`/
/// `flush_metrics` (or `flush_all`) to batch-export and drain the queue,
/// retrying transient failures with exponential backoff. When the queue is
/// full, new items are dropped and counted so operators can see loss rather
/// than have it happen silently.
#[derive(Debug)]
pub struct OtlpExporter {
    config: OtlpExporterConfig,
    trace_queue: std::sync::Mutex<std::collections::VecDeque<OtelSpan>>,
    log_queue: std::sync::Mutex<std::collections::VecDeque<serde_json::Value>>,
    metric_queue: std::sync::Mutex<std::collections::VecDeque<serde_json::Value>>,
    dropped: AtomicU64,
    exported: AtomicU64,
    export_failures: AtomicU64,
}

/// Outcome of a single flush call.
#[derive(Debug, Clone, Serialize)]
pub struct OtlpFlushResult {
    pub signal: &'static str,
    pub attempted: usize,
    pub exported: usize,
    pub success: bool,
    pub error: Option<String>,
}

/// Exporter counters for observability/health endpoints.
#[derive(Debug, Clone, Serialize)]
pub struct OtlpExporterStats {
    pub enabled: bool,
    pub queued_traces: usize,
    pub queued_logs: usize,
    pub queued_metrics: usize,
    pub exported_total: u64,
    pub dropped_total: u64,
    pub export_failures_total: u64,
}

impl OtlpExporter {
    pub fn new(config: OtlpExporterConfig) -> Self {
        Self {
            config,
            trace_queue: std::sync::Mutex::new(std::collections::VecDeque::new()),
            log_queue: std::sync::Mutex::new(std::collections::VecDeque::new()),
            metric_queue: std::sync::Mutex::new(std::collections::VecDeque::new()),
            dropped: AtomicU64::new(0),
            exported: AtomicU64::new(0),
            export_failures: AtomicU64::new(0),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled && !self.config.endpoint.trim().is_empty()
    }

    fn enqueue<T>(
        queue: &std::sync::Mutex<std::collections::VecDeque<T>>,
        item: T,
        cap: usize,
        dropped: &AtomicU64,
    ) {
        if let Ok(mut q) = queue.lock() {
            if q.len() >= cap {
                q.pop_front();
                dropped.fetch_add(1, Ordering::Relaxed);
            }
            q.push_back(item);
        }
    }

    pub fn enqueue_span(&self, span: OtelSpan) {
        if !self.is_enabled() {
            return;
        }
        Self::enqueue(
            &self.trace_queue,
            span,
            self.config.max_queue_size,
            &self.dropped,
        );
    }

    pub fn enqueue_log(&self, record: serde_json::Value) {
        if !self.is_enabled() {
            return;
        }
        Self::enqueue(
            &self.log_queue,
            record,
            self.config.max_queue_size,
            &self.dropped,
        );
    }

    pub fn enqueue_metric(&self, record: serde_json::Value) {
        if !self.is_enabled() {
            return;
        }
        Self::enqueue(
            &self.metric_queue,
            record,
            self.config.max_queue_size,
            &self.dropped,
        );
    }

    fn drain_batch<T>(
        queue: &std::sync::Mutex<std::collections::VecDeque<T>>,
        max: usize,
    ) -> Vec<T> {
        let mut out = Vec::new();
        if let Ok(mut q) = queue.lock() {
            for _ in 0..max {
                match q.pop_front() {
                    Some(item) => out.push(item),
                    None => break,
                }
            }
        }
        out
    }

    fn post_with_retry(&self, url: &str, body: &serde_json::Value) -> Result<(), String> {
        let mut last_err = String::new();
        for attempt in 0..self.config.max_retries.max(1) {
            let mut req = ureq::post(url)
                .set("Content-Type", "application/json")
                .timeout(std::time::Duration::from_secs(self.config.timeout_secs));
            for (k, v) in &self.config.headers {
                req = req.set(k, v);
            }
            match req.send_string(&body.to_string()) {
                Ok(resp) if (200..300).contains(&resp.status()) => return Ok(()),
                Ok(resp) => {
                    last_err = format!("OTLP export got HTTP {}", resp.status());
                }
                Err(e) => {
                    last_err = format!("OTLP export request failed: {e}");
                }
            }
            if attempt + 1 < self.config.max_retries {
                std::thread::sleep(std::time::Duration::from_millis(
                    100 * 2u64.saturating_pow(attempt),
                ));
            }
        }
        Err(last_err)
    }

    /// Flush queued spans as a single OTLP/HTTP JSON batch to `{endpoint}/v1/traces`.
    pub fn flush_traces(&self) -> OtlpFlushResult {
        if !self.is_enabled() {
            return OtlpFlushResult {
                signal: "traces",
                attempted: 0,
                exported: 0,
                success: true,
                error: None,
            };
        }
        let batch = Self::drain_batch(&self.trace_queue, self.config.batch_max_size);
        let attempted = batch.len();
        if batch.is_empty() {
            return OtlpFlushResult {
                signal: "traces",
                attempted: 0,
                exported: 0,
                success: true,
                error: None,
            };
        }
        let spans_json: Vec<serde_json::Value> = batch
            .iter()
            .map(|span| {
                span.to_otlp_json()["resourceSpans"][0]["scopeSpans"][0]["spans"][0].clone()
            })
            .collect();
        let service_name = batch
            .first()
            .map(|s| s.service_name.clone())
            .unwrap_or_else(|| "wardex".to_string());
        let payload = serde_json::json!({
            "resourceSpans": [{
                "resource": { "attributes": [
                    {"key": "service.name", "value": {"stringValue": service_name}},
                ]},
                "scopeSpans": [{ "spans": spans_json }],
            }]
        });
        let url = format!("{}/v1/traces", self.config.endpoint.trim_end_matches('/'));
        match self.post_with_retry(&url, &payload) {
            Ok(()) => {
                self.exported.fetch_add(attempted as u64, Ordering::Relaxed);
                OtlpFlushResult {
                    signal: "traces",
                    attempted,
                    exported: attempted,
                    success: true,
                    error: None,
                }
            }
            Err(e) => {
                self.export_failures.fetch_add(1, Ordering::Relaxed);
                OtlpFlushResult {
                    signal: "traces",
                    attempted,
                    exported: 0,
                    success: false,
                    error: Some(e),
                }
            }
        }
    }

    /// Flush queued log records as OTLP/HTTP JSON to `{endpoint}/v1/logs`.
    ///
    /// Records are caller-supplied JSON objects; at minimum they should
    /// carry a `body`/`message` and `severityText` field, which are mapped
    /// into the OTLP log record shape best-effort.
    pub fn flush_logs(&self) -> OtlpFlushResult {
        if !self.is_enabled() {
            return OtlpFlushResult {
                signal: "logs",
                attempted: 0,
                exported: 0,
                success: true,
                error: None,
            };
        }
        let batch = Self::drain_batch(&self.log_queue, self.config.batch_max_size);
        let attempted = batch.len();
        if batch.is_empty() {
            return OtlpFlushResult {
                signal: "logs",
                attempted: 0,
                exported: 0,
                success: true,
                error: None,
            };
        }
        let log_records: Vec<serde_json::Value> = batch
            .into_iter()
            .map(|record| {
                let body = record
                    .get("message")
                    .or_else(|| record.get("body"))
                    .cloned()
                    .unwrap_or(record.clone());
                serde_json::json!({
                    "timeUnixNano": chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
                    "severityText": record.get("level").and_then(|v| v.as_str()).unwrap_or("INFO"),
                    "body": {"stringValue": body.to_string()},
                    "attributes": [],
                })
            })
            .collect();
        let payload = serde_json::json!({
            "resourceLogs": [{
                "resource": { "attributes": [
                    {"key": "service.name", "value": {"stringValue": "wardex"}},
                ]},
                "scopeLogs": [{ "logRecords": log_records }],
            }]
        });
        let url = format!("{}/v1/logs", self.config.endpoint.trim_end_matches('/'));
        match self.post_with_retry(&url, &payload) {
            Ok(()) => {
                self.exported.fetch_add(attempted as u64, Ordering::Relaxed);
                OtlpFlushResult {
                    signal: "logs",
                    attempted,
                    exported: attempted,
                    success: true,
                    error: None,
                }
            }
            Err(e) => {
                self.export_failures.fetch_add(1, Ordering::Relaxed);
                OtlpFlushResult {
                    signal: "logs",
                    attempted,
                    exported: 0,
                    success: false,
                    error: Some(e),
                }
            }
        }
    }

    /// Flush queued metric data points as OTLP/HTTP JSON to `{endpoint}/v1/metrics`.
    /// Each queued record is expected to already be a valid OTLP metric object.
    pub fn flush_metrics(&self) -> OtlpFlushResult {
        if !self.is_enabled() {
            return OtlpFlushResult {
                signal: "metrics",
                attempted: 0,
                exported: 0,
                success: true,
                error: None,
            };
        }
        let batch = Self::drain_batch(&self.metric_queue, self.config.batch_max_size);
        let attempted = batch.len();
        if batch.is_empty() {
            return OtlpFlushResult {
                signal: "metrics",
                attempted: 0,
                exported: 0,
                success: true,
                error: None,
            };
        }
        let payload = serde_json::json!({
            "resourceMetrics": [{
                "resource": { "attributes": [
                    {"key": "service.name", "value": {"stringValue": "wardex"}},
                ]},
                "scopeMetrics": [{ "metrics": batch }],
            }]
        });
        let url = format!("{}/v1/metrics", self.config.endpoint.trim_end_matches('/'));
        match self.post_with_retry(&url, &payload) {
            Ok(()) => {
                self.exported.fetch_add(attempted as u64, Ordering::Relaxed);
                OtlpFlushResult {
                    signal: "metrics",
                    attempted,
                    exported: attempted,
                    success: true,
                    error: None,
                }
            }
            Err(e) => {
                self.export_failures.fetch_add(1, Ordering::Relaxed);
                OtlpFlushResult {
                    signal: "metrics",
                    attempted,
                    exported: 0,
                    success: false,
                    error: Some(e),
                }
            }
        }
    }

    /// Flush all three signal queues; returns one result per signal.
    pub fn flush_all(&self) -> Vec<OtlpFlushResult> {
        vec![self.flush_traces(), self.flush_logs(), self.flush_metrics()]
    }

    pub fn stats(&self) -> OtlpExporterStats {
        OtlpExporterStats {
            enabled: self.is_enabled(),
            queued_traces: self.trace_queue.lock().map(|q| q.len()).unwrap_or(0),
            queued_logs: self.log_queue.lock().map(|q| q.len()).unwrap_or(0),
            queued_metrics: self.metric_queue.lock().map(|q| q.len()).unwrap_or(0),
            exported_total: self.exported.load(Ordering::Relaxed),
            dropped_total: self.dropped.load(Ordering::Relaxed),
            export_failures_total: self.export_failures.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TelemetrySample;

    #[test]
    fn parses_line_legacy_8_cols() {
        let sample = TelemetrySample::parse_line("42,10,20,35,1200,2,80,0.15", 3).unwrap();

        assert_eq!(sample.timestamp_ms, 42);
        assert_eq!(sample.auth_failures, 2);
        assert_eq!(sample.integrity_drift, 0.15);
        assert_eq!(sample.process_count, 0);
        assert_eq!(sample.disk_pressure_pct, 0.0);
    }

    #[test]
    fn parses_line_10_cols() {
        let sample =
            TelemetrySample::parse_line_cols("42,10,20,35,1200,2,80,0.15,120,45.5", 3, 10).unwrap();
        assert_eq!(sample.process_count, 120);
        assert!((sample.disk_pressure_pct - 45.5).abs() < 0.01);
    }

    #[test]
    fn rejects_bad_range() {
        let error = TelemetrySample::parse_line("42,101,20,35,1200,2,80,0.15", 3).unwrap_err();
        assert!(error.to_string().contains("cpu_load_pct"));
    }

    #[test]
    fn jsonl_round_trip() {
        let sample = TelemetrySample {
            timestamp_ms: 100,
            cpu_load_pct: 25.0,
            memory_load_pct: 30.0,
            temperature_c: 40.0,
            network_kbps: 500.0,
            auth_failures: 1,
            battery_pct: 85.0,
            integrity_drift: 0.03,
            process_count: 42,
            disk_pressure_pct: 12.5,
        };
        let json = serde_json::to_string(&sample).unwrap();
        let parsed: TelemetrySample = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.process_count, 42);
    }

    #[test]
    fn parse_benign_extended_fixture() {
        let samples =
            TelemetrySample::parse_csv(std::path::Path::new("examples/benign_extended.csv"))
                .unwrap();
        assert_eq!(samples.len(), 120);
        assert!(samples.iter().all(|s| s.auth_failures == 0));
    }

    #[test]
    fn parse_credential_storm_extended_fixture() {
        let samples = TelemetrySample::parse_csv(std::path::Path::new(
            "examples/credential_storm_extended.csv",
        ))
        .unwrap();
        assert_eq!(samples.len(), 120);
        assert!(samples.iter().any(|s| s.auth_failures > 10));
    }

    #[test]
    fn parse_slow_escalation_extended_fixture() {
        let samples = TelemetrySample::parse_csv(std::path::Path::new(
            "examples/slow_escalation_extended.csv",
        ))
        .unwrap();
        assert_eq!(samples.len(), 120);
        // starts benign, ramps to high CPU
        assert!(samples.first().unwrap().cpu_load_pct < 15.0);
        assert!(samples.iter().any(|s| s.cpu_load_pct > 85.0));
    }

    #[test]
    fn parse_low_battery_extended_fixture() {
        let samples =
            TelemetrySample::parse_csv(std::path::Path::new("examples/low_battery_extended.csv"))
                .unwrap();
        assert_eq!(samples.len(), 120);
        // starts with low battery, degrades further
        assert!(samples.first().unwrap().battery_pct < 20.0);
        assert!(samples.iter().any(|s| s.battery_pct < 1.0));
    }

    #[test]
    fn otel_span_lifecycle() {
        let mut span = super::OtelSpan::new("test.operation");
        assert!(!span.trace_id.is_empty());
        assert!(!span.span_id.is_empty());
        assert!(span.parent_span_id.is_none());
        assert_eq!(span.status, super::SpanStatus::Unset);

        span.set_attribute("http.method", "GET");
        span.finish();
        assert_eq!(span.status, super::SpanStatus::Ok);
        assert!(span.end_time_ms.is_some());
        assert!(span.duration_ms().is_some());
    }

    #[test]
    fn otel_span_child() {
        let parent = super::OtelSpan::new("parent");
        let child = parent.child("child");
        assert_eq!(child.trace_id, parent.trace_id);
        assert_eq!(child.parent_span_id, Some(parent.span_id.clone()));
        assert_ne!(child.span_id, parent.span_id);
    }

    #[test]
    fn otel_span_error() {
        let mut span = super::OtelSpan::new("failing.op");
        span.finish_error("connection refused");
        assert_eq!(span.status, super::SpanStatus::Error);
        assert!(span.attributes.iter().any(|(k, _)| k == "error.message"));
    }

    #[test]
    fn otel_otlp_json() {
        let mut span = super::OtelSpan::new("export.test");
        span.finish();
        let json = span.to_otlp_json();
        assert!(json["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["traceId"].is_string());
    }

    #[test]
    fn trace_collector_aggregation() {
        let mut collector = super::TraceCollector::new(100);
        let mut span = super::OtelSpan::new("op1");
        span.finish();
        collector.record(span);

        let mut span2 = super::OtelSpan::new("op2");
        span2.finish_error("fail");
        collector.record(span2);

        let stats = collector.stats();
        assert_eq!(stats.total_spans, 2);
        assert_eq!(stats.error_spans, 1);
        assert!(stats.avg_duration_ms >= 0.0);
    }

    // ── OTLP exporter tests ─────────────────────────────────────

    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

    /// Mock collector endpoint that records how many requests it received
    /// and always answers with the given status.
    fn spawn_mock_collector(status_line: &'static str) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock collector");
        let port = listener.local_addr().expect("addr").port();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_thread = hits.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let mut buf = [0u8; 8192];
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
                hits_thread.fetch_add(1, AtomicOrdering::SeqCst);
                let body = "{}";
                let response = format!(
                    "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        (format!("http://127.0.0.1:{port}"), hits)
    }

    #[test]
    fn otlp_exporter_disabled_is_a_noop() {
        let exporter = super::OtlpExporter::new(super::OtlpExporterConfig::default());
        let mut span = super::OtelSpan::new("noop");
        span.finish();
        exporter.enqueue_span(span);
        assert_eq!(exporter.stats().queued_traces, 0);
        let result = exporter.flush_traces();
        assert!(result.success);
        assert_eq!(result.attempted, 0);
    }

    #[test]
    fn otlp_exporter_exports_batched_spans() {
        let (endpoint, hits) = spawn_mock_collector("HTTP/1.1 200 OK");
        let exporter = super::OtlpExporter::new(super::OtlpExporterConfig {
            endpoint,
            enabled: true,
            max_retries: 1,
            ..Default::default()
        });
        for i in 0..3 {
            let mut span = super::OtelSpan::new(&format!("op{i}"));
            span.finish();
            exporter.enqueue_span(span);
        }
        assert_eq!(exporter.stats().queued_traces, 3);
        let result = exporter.flush_traces();
        assert!(result.success);
        assert_eq!(result.exported, 3);
        assert_eq!(exporter.stats().queued_traces, 0);
        assert_eq!(exporter.stats().exported_total, 3);
        assert_eq!(hits.load(AtomicOrdering::SeqCst), 1);
    }

    #[test]
    fn otlp_exporter_retries_then_fails_and_counts_failure() {
        let (endpoint, hits) = spawn_mock_collector("HTTP/1.1 500 Internal Server Error");
        let exporter = super::OtlpExporter::new(super::OtlpExporterConfig {
            endpoint,
            enabled: true,
            max_retries: 2,
            ..Default::default()
        });
        let mut span = super::OtelSpan::new("will-fail");
        span.finish();
        exporter.enqueue_span(span);
        let result = exporter.flush_traces();
        assert!(!result.success);
        assert_eq!(exporter.stats().export_failures_total, 1);
        // One request per retry attempt.
        assert_eq!(hits.load(AtomicOrdering::SeqCst), 2);
    }

    #[test]
    fn otlp_exporter_bounded_queue_drops_and_counts() {
        let exporter = super::OtlpExporter::new(super::OtlpExporterConfig {
            endpoint: "http://127.0.0.1:1".into(),
            enabled: true,
            max_queue_size: 2,
            ..Default::default()
        });
        for i in 0..5 {
            let mut span = super::OtelSpan::new(&format!("op{i}"));
            span.finish();
            exporter.enqueue_span(span);
        }
        assert_eq!(exporter.stats().queued_traces, 2);
        assert_eq!(exporter.stats().dropped_total, 3);
    }

    #[test]
    fn otlp_exporter_flushes_logs_and_metrics() {
        let (endpoint, hits) = spawn_mock_collector("HTTP/1.1 200 OK");
        let exporter = super::OtlpExporter::new(super::OtlpExporterConfig {
            endpoint,
            enabled: true,
            max_retries: 1,
            ..Default::default()
        });
        exporter.enqueue_log(serde_json::json!({"level": "INFO", "message": "hello"}));
        exporter.enqueue_metric(serde_json::json!({"name": "wardex.alerts", "value": 1}));
        let results = exporter.flush_all();
        assert!(results.iter().all(|r| r.success));
        assert_eq!(hits.load(AtomicOrdering::SeqCst), 2); // logs + metrics (traces queue was empty)
    }
}
