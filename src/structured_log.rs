// ── Structured Logging ────────────────────────────────────────────────────────
//
// JSON-structured log output with severity levels, timestamps, context fields,
// and pluggable sinks (stdout, file, buffer).  Designed for ingestion by
// log aggregators (ELK, Loki, Splunk).

use chrono::Utc;
use std::collections::BTreeMap;
use std::fmt;
use std::io::Write;
use std::sync::{Arc, Mutex};

// ── Log Level ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Trace => write!(f, "trace"),
            Self::Debug => write!(f, "debug"),
            Self::Info  => write!(f, "info"),
            Self::Warn  => write!(f, "warn"),
            Self::Error => write!(f, "error"),
            Self::Fatal => write!(f, "fatal"),
        }
    }
}

impl LogLevel {
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "trace" => Self::Trace,
            "debug" => Self::Debug,
            "info"  => Self::Info,
            "warn" | "warning" => Self::Warn,
            "error" | "err" => Self::Error,
            "fatal" | "critical" => Self::Fatal,
            _ => Self::Info,
        }
    }
}

// ── Log Entry ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: LogLevel,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, serde_json::Value>,
}

impl LogEntry {
    pub fn new(level: LogLevel, message: impl Into<String>) -> Self {
        Self {
            timestamp: Utc::now().to_rfc3339(),
            level,
            message: message.into(),
            target: None,
            module: None,
            request_id: None,
            fields: BTreeMap::new(),
        }
    }

    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    pub fn with_module(mut self, module: impl Into<String>) -> Self {
        self.module = Some(module.into());
        self
    }

    pub fn with_request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }

    pub fn with_field(mut self, key: impl Into<String>, value: impl serde::Serialize) -> Self {
        if let Ok(v) = serde_json::to_value(value) {
            self.fields.insert(key.into(), v);
        }
        self
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

// ── Sink trait ───────────────────────────────────────────────────────────────

pub trait LogSink: Send + Sync {
    fn write_entry(&self, entry: &LogEntry);
    fn flush(&self) {}
}

// ── Stdout sink ──────────────────────────────────────────────────────────────

pub struct StdoutSink {
    pretty: bool,
}

impl StdoutSink {
    pub fn new(pretty: bool) -> Self {
        Self { pretty }
    }
}

impl LogSink for StdoutSink {
    fn write_entry(&self, entry: &LogEntry) {
        let json = if self.pretty {
            entry.to_json_pretty()
        } else {
            entry.to_json()
        };
        let _ = writeln!(std::io::stdout(), "{}", json);
    }

    fn flush(&self) {
        let _ = std::io::stdout().flush();
    }
}

// ── Buffer sink (for testing / in-memory) ────────────────────────────────────

#[derive(Clone)]
pub struct BufferSink {
    entries: Arc<Mutex<Vec<LogEntry>>>,
}

impl BufferSink {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn entries(&self) -> Vec<LogEntry> {
        self.entries.lock().map(|e| e.clone()).unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        self.entries.lock().map(|e| e.len()).unwrap_or(0)
    }

    pub fn clear(&self) {
        if let Ok(mut e) = self.entries.lock() {
            e.clear();
        }
    }
}

impl LogSink for BufferSink {
    fn write_entry(&self, entry: &LogEntry) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.push(entry.clone());
        }
    }
}

// ── File sink ────────────────────────────────────────────────────────────────

pub struct FileSink {
    writer: Mutex<std::io::BufWriter<std::fs::File>>,
}

impl FileSink {
    pub fn new(path: &str) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self {
            writer: Mutex::new(std::io::BufWriter::new(file)),
        })
    }
}

impl LogSink for FileSink {
    fn write_entry(&self, entry: &LogEntry) {
        if let Ok(mut w) = self.writer.lock() {
            let _ = writeln!(w, "{}", entry.to_json());
        }
    }

    fn flush(&self) {
        if let Ok(mut w) = self.writer.lock() {
            let _ = w.flush();
        }
    }
}

// ── Logger ───────────────────────────────────────────────────────────────────

pub struct Logger {
    min_level: LogLevel,
    sinks: Vec<Box<dyn LogSink>>,
    default_fields: BTreeMap<String, serde_json::Value>,
}

impl Logger {
    pub fn new(min_level: LogLevel) -> Self {
        Self {
            min_level,
            sinks: Vec::new(),
            default_fields: BTreeMap::new(),
        }
    }

    pub fn add_sink(&mut self, sink: Box<dyn LogSink>) {
        self.sinks.push(sink);
    }

    pub fn set_default_field(&mut self, key: impl Into<String>, value: impl serde::Serialize) {
        if let Ok(v) = serde_json::to_value(value) {
            self.default_fields.insert(key.into(), v);
        }
    }

    pub fn log(&self, mut entry: LogEntry) {
        if entry.level < self.min_level {
            return;
        }
        // Merge default fields (entry fields take precedence)
        for (k, v) in &self.default_fields {
            entry.fields.entry(k.clone()).or_insert_with(|| v.clone());
        }
        for sink in &self.sinks {
            sink.write_entry(&entry);
        }
    }

    pub fn trace(&self, msg: impl Into<String>) {
        self.log(LogEntry::new(LogLevel::Trace, msg));
    }

    pub fn debug(&self, msg: impl Into<String>) {
        self.log(LogEntry::new(LogLevel::Debug, msg));
    }

    pub fn info(&self, msg: impl Into<String>) {
        self.log(LogEntry::new(LogLevel::Info, msg));
    }

    pub fn warn(&self, msg: impl Into<String>) {
        self.log(LogEntry::new(LogLevel::Warn, msg));
    }

    pub fn error(&self, msg: impl Into<String>) {
        self.log(LogEntry::new(LogLevel::Error, msg));
    }

    pub fn fatal(&self, msg: impl Into<String>) {
        self.log(LogEntry::new(LogLevel::Fatal, msg));
    }

    pub fn flush(&self) {
        for sink in &self.sinks {
            sink.flush();
        }
    }
}

// ── SharedLogger (thread-safe wrapper) ───────────────────────────────────────

#[derive(Clone)]
pub struct SharedLogger {
    inner: Arc<Mutex<Logger>>,
}

impl SharedLogger {
    pub fn new(min_level: LogLevel) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Logger::new(min_level))),
        }
    }

    pub fn add_sink(&self, sink: Box<dyn LogSink>) {
        if let Ok(mut logger) = self.inner.lock() {
            logger.add_sink(sink);
        }
    }

    pub fn set_default_field(&self, key: impl Into<String>, value: impl serde::Serialize) {
        if let Ok(mut logger) = self.inner.lock() {
            logger.set_default_field(key, value);
        }
    }

    pub fn log(&self, entry: LogEntry) {
        if let Ok(logger) = self.inner.lock() {
            logger.log(entry);
        }
    }

    pub fn info(&self, msg: impl Into<String>) {
        self.log(LogEntry::new(LogLevel::Info, msg));
    }

    pub fn warn(&self, msg: impl Into<String>) {
        self.log(LogEntry::new(LogLevel::Warn, msg));
    }

    pub fn error(&self, msg: impl Into<String>) {
        self.log(LogEntry::new(LogLevel::Error, msg));
    }

    pub fn flush(&self) {
        if let Ok(logger) = self.inner.lock() {
            logger.flush();
        }
    }
}

// ── Request context helper ───────────────────────────────────────────────────

pub fn request_log(
    method: &str,
    path: &str,
    status: u16,
    duration_ms: f64,
    request_id: Option<&str>,
) -> LogEntry {
    let level = if status >= 500 {
        LogLevel::Error
    } else if status >= 400 {
        LogLevel::Warn
    } else {
        LogLevel::Info
    };

    let mut entry = LogEntry::new(level, format!("{} {} → {}", method, path, status))
        .with_target("http")
        .with_field("method", method)
        .with_field("path", path)
        .with_field("status", status)
        .with_field("duration_ms", duration_ms);

    if let Some(rid) = request_id {
        entry = entry.with_request_id(rid);
    }
    entry
}

pub fn security_log(event: &str, source_ip: &str, details: &str) -> LogEntry {
    LogEntry::new(LogLevel::Warn, format!("security: {}", event))
        .with_target("security")
        .with_field("event", event)
        .with_field("source_ip", source_ip)
        .with_field("details", details)
}

pub fn audit_log(actor: &str, action: &str, resource: &str) -> LogEntry {
    LogEntry::new(LogLevel::Info, format!("audit: {} {} {}", actor, action, resource))
        .with_target("audit")
        .with_field("actor", actor)
        .with_field("action", action)
        .with_field("resource", resource)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_entry_serializes_to_json() {
        let entry = LogEntry::new(LogLevel::Info, "test message")
            .with_target("server")
            .with_field("key", "value");
        let json = entry.to_json();
        assert!(json.contains("\"level\":\"info\""));
        assert!(json.contains("\"message\":\"test message\""));
        assert!(json.contains("\"target\":\"server\""));
        assert!(json.contains("\"key\":\"value\""));
    }

    #[test]
    fn log_entry_omits_none_fields() {
        let entry = LogEntry::new(LogLevel::Debug, "short");
        let json = entry.to_json();
        assert!(!json.contains("target"));
        assert!(!json.contains("module"));
        assert!(!json.contains("request_id"));
    }

    #[test]
    fn log_level_ordering() {
        assert!(LogLevel::Trace < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Error);
        assert!(LogLevel::Error < LogLevel::Fatal);
    }

    #[test]
    fn log_level_from_str_loose() {
        assert_eq!(LogLevel::from_str_loose("info"), LogLevel::Info);
        assert_eq!(LogLevel::from_str_loose("WARNING"), LogLevel::Warn);
        assert_eq!(LogLevel::from_str_loose("err"), LogLevel::Error);
        assert_eq!(LogLevel::from_str_loose("critical"), LogLevel::Fatal);
        assert_eq!(LogLevel::from_str_loose("unknown"), LogLevel::Info);
    }

    #[test]
    fn buffer_sink_captures_entries() {
        let sink = BufferSink::new();
        let mut logger = Logger::new(LogLevel::Debug);
        logger.add_sink(Box::new(sink.clone()));
        logger.info("hello");
        logger.debug("detail");
        logger.trace("skipped"); // below Debug threshold
        assert_eq!(sink.len(), 2);
        let entries = sink.entries();
        assert_eq!(entries[0].message, "hello");
        assert_eq!(entries[1].message, "detail");
    }

    #[test]
    fn logger_min_level_filters() {
        let sink = BufferSink::new();
        let mut logger = Logger::new(LogLevel::Warn);
        logger.add_sink(Box::new(sink.clone()));
        logger.info("skip");
        logger.warn("keep");
        logger.error("keep2");
        assert_eq!(sink.len(), 2);
    }

    #[test]
    fn default_fields_merged() {
        let sink = BufferSink::new();
        let mut logger = Logger::new(LogLevel::Info);
        logger.add_sink(Box::new(sink.clone()));
        logger.set_default_field("service", "wardex");
        logger.set_default_field("version", "0.35.0");
        logger.info("test");
        let entries = sink.entries();
        assert_eq!(entries[0].fields.get("service").unwrap(), "wardex");
    }

    #[test]
    fn entry_fields_override_defaults() {
        let sink = BufferSink::new();
        let mut logger = Logger::new(LogLevel::Info);
        logger.add_sink(Box::new(sink.clone()));
        logger.set_default_field("env", "prod");
        logger.log(LogEntry::new(LogLevel::Info, "test").with_field("env", "staging"));
        let entries = sink.entries();
        assert_eq!(entries[0].fields.get("env").unwrap(), "staging");
    }

    #[test]
    fn request_log_helper() {
        let entry = request_log("GET", "/api/status", 200, 1.5, Some("req-123"));
        assert_eq!(entry.level, LogLevel::Info);
        assert!(entry.message.contains("200"));
        assert_eq!(entry.request_id.as_deref(), Some("req-123"));

        let warn = request_log("POST", "/api/bad", 404, 2.0, None);
        assert_eq!(warn.level, LogLevel::Warn);

        let err = request_log("GET", "/crash", 500, 100.0, None);
        assert_eq!(err.level, LogLevel::Error);
    }

    #[test]
    fn security_log_helper() {
        let entry = security_log("brute_force", "10.0.0.1", "5 failed logins");
        assert_eq!(entry.level, LogLevel::Warn);
        assert!(entry.message.contains("security"));
        assert_eq!(entry.fields.get("source_ip").unwrap(), "10.0.0.1");
    }

    #[test]
    fn audit_log_helper() {
        let entry = audit_log("admin", "update_policy", "fw-rule-1");
        assert_eq!(entry.level, LogLevel::Info);
        assert_eq!(entry.fields.get("actor").unwrap(), "admin");
    }

    #[test]
    fn shared_logger_thread_safe() {
        let sink = BufferSink::new();
        let logger = SharedLogger::new(LogLevel::Info);
        logger.add_sink(Box::new(sink.clone()));

        let logger2 = logger.clone();
        let h = std::thread::spawn(move || {
            for i in 0..20 {
                logger2.info(format!("thread msg {}", i));
            }
        });
        for i in 0..20 {
            logger.info(format!("main msg {}", i));
        }
        h.join().unwrap();
        assert_eq!(sink.len(), 40);
    }

    #[test]
    fn buffer_sink_clear() {
        let sink = BufferSink::new();
        let mut logger = Logger::new(LogLevel::Info);
        logger.add_sink(Box::new(sink.clone()));
        logger.info("a");
        logger.info("b");
        assert_eq!(sink.len(), 2);
        sink.clear();
        assert_eq!(sink.len(), 0);
    }
}
