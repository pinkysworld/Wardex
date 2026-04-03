use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LogSource {
    System,
    Auth,
    Application,
    Security,
    Custom(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRecord {
    pub timestamp: String,
    pub source: LogSource,
    pub level: LogLevel,
    pub message: String,
    #[serde(default)]
    pub raw: Option<String>,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// Collect recent OS/auth/app logs from the current platform.
pub fn collect_recent_logs(since_secs: u64) -> Vec<LogRecord> {
    let mut logs = Vec::new();
    let platform = std::env::consts::OS;
    match platform {
        "linux" => collect_linux_logs(&mut logs, since_secs),
        "macos" => collect_macos_logs(&mut logs, since_secs),
        "windows" => collect_windows_logs(&mut logs, since_secs),
        _ => {}
    }
    logs
}

#[cfg(target_os = "linux")]
fn collect_linux_logs(logs: &mut Vec<LogRecord>, _since_secs: u64) {
    // /var/log/syslog or /var/log/messages
    for (path, source) in &[
        ("/var/log/syslog", LogSource::System),
        ("/var/log/auth.log", LogSource::Auth),
        ("/var/log/messages", LogSource::System),
    ] {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines().rev().take(200) {
                let level = classify_log_level(line);
                logs.push(LogRecord {
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    source: source.clone(),
                    level,
                    message: line.chars().take(1024).collect(),
                    raw: Some(line.to_string()),
                    metadata: HashMap::new(),
                });
                if logs.len() >= 500 {
                    break;
                }
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn collect_linux_logs(_logs: &mut Vec<LogRecord>, _since_secs: u64) {}

#[cfg(target_os = "macos")]
fn collect_macos_logs(logs: &mut Vec<LogRecord>, since_secs: u64) {
    let minutes = (since_secs / 60).max(1);
    let output = std::process::Command::new("log")
        .args(["show", "--last", &format!("{minutes}m"), "--style", "json"])
        .output();
    if let Ok(out) = output {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            if let Ok(entries) = serde_json::from_str::<Vec<serde_json::Value>>(&text) {
                for entry in entries.iter().take(500) {
                    let msg = entry["eventMessage"].as_str().unwrap_or("").to_string();
                    let process = entry["processImagePath"].as_str().unwrap_or("");
                    let source = if process.contains("auth") || process.contains("security") {
                        LogSource::Auth
                    } else {
                        LogSource::System
                    };
                    let level = classify_log_level(&msg);
                    let mut meta = HashMap::new();
                    if let Some(p) = entry["processImagePath"].as_str() {
                        meta.insert("process".into(), p.to_string());
                    }
                    logs.push(LogRecord {
                        timestamp: entry["timestamp"].as_str().unwrap_or("").to_string(),
                        source,
                        level,
                        message: msg.chars().take(1024).collect(),
                        raw: None,
                        metadata: meta,
                    });
                }
            }
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn collect_macos_logs(_logs: &mut Vec<LogRecord>, _since_secs: u64) {}

#[cfg(target_os = "windows")]
fn collect_windows_logs(logs: &mut Vec<LogRecord>, _since_secs: u64) {
    for (channel, source) in &[
        ("System", LogSource::System),
        ("Security", LogSource::Security),
        ("Application", LogSource::Application),
    ] {
        let output = std::process::Command::new("wevtutil")
            .args(["qe", channel, "/c:100", "/f:text", "/rd:true"])
            .output();
        if let Ok(out) = output {
            if out.status.success() {
                let text = String::from_utf8_lossy(&out.stdout);
                for block in text.split("\r\n\r\n").take(200) {
                    if block.trim().is_empty() {
                        continue;
                    }
                    let level = classify_log_level(block);
                    let message: String = block.lines()
                        .find(|l| l.trim_start().starts_with("Message"))
                        .map(|l| l.trim_start_matches("Message").trim_start_matches('=').trim().to_string())
                        .unwrap_or_else(|| block.lines().next().unwrap_or("").to_string());
                    logs.push(LogRecord {
                        timestamp: chrono::Utc::now().to_rfc3339(),
                        source: source.clone(),
                        level,
                        message: message.chars().take(1024).collect(),
                        raw: Some(block.to_string()),
                        metadata: HashMap::new(),
                    });
                    if logs.len() >= 500 {
                        break;
                    }
                }
            }
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn collect_windows_logs(_logs: &mut Vec<LogRecord>, _since_secs: u64) {}

fn classify_log_level(text: &str) -> LogLevel {
    let lower = text.to_lowercase();
    if lower.contains("critical") || lower.contains("emergency") || lower.contains("panic") {
        LogLevel::Critical
    } else if lower.contains("error") || lower.contains("fail") {
        LogLevel::Error
    } else if lower.contains("warn") {
        LogLevel::Warning
    } else if lower.contains("debug") || lower.contains("trace") {
        LogLevel::Debug
    } else {
        LogLevel::Info
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_level_classification() {
        assert_eq!(classify_log_level("Critical error occurred"), LogLevel::Critical);
        assert_eq!(classify_log_level("error: disk full"), LogLevel::Error);
        assert_eq!(classify_log_level("warning: low space"), LogLevel::Warning);
        assert_eq!(classify_log_level("debug: entering foo"), LogLevel::Debug);
        assert_eq!(classify_log_level("user logged in"), LogLevel::Info);
    }

    #[test]
    fn log_record_serialization() {
        let record = LogRecord {
            timestamp: "2025-01-01T00:00:00Z".into(),
            source: LogSource::Auth,
            level: LogLevel::Error,
            message: "Failed login for root".into(),
            raw: None,
            metadata: HashMap::new(),
        };
        let json = serde_json::to_string(&record).unwrap();
        let parsed: LogRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.source, LogSource::Auth);
        assert_eq!(parsed.level, LogLevel::Error);
    }

    #[test]
    fn collect_logs_returns_without_panic() {
        let logs = collect_recent_logs(300);
        // Should not panic on any platform, may return empty on CI
        let _ = logs.len();
    }

    #[test]
    fn mitre_mapping_from_reasons() {
        use crate::telemetry::map_alert_to_mitre;
        let reasons = vec!["auth_failures_exceeded".to_string()];
        let mitre = map_alert_to_mitre(&reasons);
        assert!(!mitre.is_empty());
        assert!(mitre.iter().any(|m| m.technique_id == "T1110"));
    }
}
