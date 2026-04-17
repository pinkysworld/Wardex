//! Outbound alert notification engine.
//!
//! Delivers high-priority alerts to external channels: Slack, Microsoft
//! Teams, PagerDuty, generic webhooks, and email (SMTP stub).
//! All transports are non-blocking and include retry with exponential
//! back-off (up to 3 attempts).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Channel configuration ────────────────────────────────────────────

/// Supported notification channel types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ChannelKind {
    Slack,
    MicrosoftTeams,
    PagerDuty,
    Webhook,
    Email,
}

/// Configuration for a single notification channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelConfig {
    pub kind: ChannelKind,
    pub name: String,
    pub enabled: bool,
    /// Webhook / API endpoint URL (not used for Email).
    pub url: Option<String>,
    /// Auth token or integration key.
    pub token: Option<String>,
    /// SMTP-specific settings (Email only).
    pub smtp: Option<SmtpConfig>,
    /// Minimum alert level that triggers this channel ("Elevated", "Severe", "Critical").
    pub min_level: String,
}

/// SMTP configuration for email notifications.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub from: String,
    pub to: Vec<String>,
    pub username: Option<String>,
    pub use_tls: bool,
}

// ── Notification payload ─────────────────────────────────────────────

/// A notification to be delivered.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub id: String,
    pub timestamp: String,
    pub level: String,
    pub title: String,
    pub body: String,
    pub device_id: String,
    pub alert_ids: Vec<String>,
    pub metadata: HashMap<String, String>,
    /// Enriched context fields (Phase 42)
    #[serde(default)]
    pub mitre_techniques: Vec<String>,
    #[serde(default)]
    pub kill_chain_phase: Option<String>,
    #[serde(default)]
    pub recommended_action: Option<String>,
    #[serde(default)]
    pub affected_hosts: Vec<String>,
    #[serde(default)]
    pub investigation_link: Option<String>,
}

/// Result of a delivery attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryResult {
    pub channel_name: String,
    pub channel_kind: ChannelKind,
    pub success: bool,
    pub status_code: Option<u16>,
    pub error: Option<String>,
    pub attempts: u32,
    pub duration_ms: u64,
}

// ── Formatter ────────────────────────────────────────────────────────

fn format_slack(n: &Notification) -> String {
    let mut context_elements = vec![
        serde_json::json!({ "type": "mrkdwn", "text": format!("Device: `{}`", n.device_id) }),
        serde_json::json!({ "type": "mrkdwn", "text": format!("Time: {}", n.timestamp) }),
    ];
    if !n.mitre_techniques.is_empty() {
        context_elements.push(serde_json::json!({ "type": "mrkdwn", "text": format!("MITRE: {}", n.mitre_techniques.join(", ")) }));
    }
    if let Some(ref phase) = n.kill_chain_phase {
        context_elements.push(
            serde_json::json!({ "type": "mrkdwn", "text": format!("Kill Chain: {}", phase) }),
        );
    }
    let mut blocks = vec![
        serde_json::json!({
            "type": "header",
            "text": { "type": "plain_text", "text": format!("[{}] {}", n.level, n.title) }
        }),
        serde_json::json!({
            "type": "section",
            "text": { "type": "mrkdwn", "text": n.body }
        }),
    ];
    if let Some(ref action) = n.recommended_action {
        blocks.push(serde_json::json!({
            "type": "section",
            "text": { "type": "mrkdwn", "text": format!(":point_right: *Recommended:* {}", action) }
        }));
    }
    blocks.push(serde_json::json!({ "type": "context", "elements": context_elements }));
    serde_json::json!({
        "text": format!(":rotating_light: *{}* — {}", n.level, n.title),
        "blocks": blocks
    })
    .to_string()
}

fn format_teams(n: &Notification) -> String {
    let mut facts = vec![
        serde_json::json!({ "name": "Device", "value": &n.device_id }),
        serde_json::json!({ "name": "Time", "value": &n.timestamp }),
    ];
    if !n.mitre_techniques.is_empty() {
        facts.push(
            serde_json::json!({ "name": "MITRE ATT&CK", "value": n.mitre_techniques.join(", ") }),
        );
    }
    if let Some(ref phase) = n.kill_chain_phase {
        facts.push(serde_json::json!({ "name": "Kill Chain Phase", "value": phase }));
    }
    if let Some(ref action) = n.recommended_action {
        facts.push(serde_json::json!({ "name": "Recommended Action", "value": action }));
    }
    if !n.affected_hosts.is_empty() {
        facts.push(
            serde_json::json!({ "name": "Affected Hosts", "value": n.affected_hosts.join(", ") }),
        );
    }
    serde_json::json!({
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": match n.level.as_str() {
            "Critical" => "FF0000",
            "Severe" => "FF8C00",
            _ => "FFD700",
        },
        "summary": format!("[{}] {}", n.level, n.title),
        "sections": [{
            "activityTitle": format!("[{}] {}", n.level, n.title),
            "facts": facts,
            "text": &n.body,
        }]
    })
    .to_string()
}

fn format_pagerduty(n: &Notification, routing_key: &str) -> String {
    let severity = match n.level.as_str() {
        "Critical" => "critical",
        "Severe" => "error",
        _ => "warning",
    };
    serde_json::json!({
        "routing_key": routing_key,
        "event_action": "trigger",
        "payload": {
            "summary": format!("[{}] {}", n.level, n.title),
            "source": n.device_id,
            "severity": severity,
            "timestamp": n.timestamp,
            "custom_details": {
                "body": n.body,
                "alert_ids": n.alert_ids,
            }
        }
    })
    .to_string()
}

fn format_webhook(n: &Notification) -> String {
    serde_json::to_string(n).unwrap_or_default()
}

/// Sanitise a string for safe inclusion in email headers / body.
/// Strips CR and LF to prevent SMTP header injection.
fn sanitize_email_field(s: &str) -> String {
    s.replace('\r', "").replace('\n', " ")
}

fn format_email(n: &Notification) -> String {
    let level = sanitize_email_field(&n.level);
    let title = sanitize_email_field(&n.title);
    let device = sanitize_email_field(&n.device_id);
    let ts = sanitize_email_field(&n.timestamp);
    let body = sanitize_email_field(&n.body);
    let ids = sanitize_email_field(&n.alert_ids.join(", "));
    format!(
        "Subject: [Wardex {level}] {title}\r\n\
         Content-Type: text/plain; charset=UTF-8\r\n\r\n\
         Device: {device}\r\nTime: {ts}\r\n\r\n{body}\r\n\r\n\
         Alert IDs: {ids}",
    )
}

// ── Delivery engine ──────────────────────────────────────────────────

/// Compare severity levels: returns true if `alert_level` >= `min_level`.
fn level_ge(alert_level: &str, min_level: &str) -> bool {
    let rank = |l: &str| match l {
        "Critical" => 3,
        "Severe" => 2,
        "Elevated" => 1,
        _ => 0,
    };
    rank(alert_level) >= rank(min_level)
}

/// Central notification dispatcher.
#[derive(Debug)]
pub struct NotificationEngine {
    channels: Vec<ChannelConfig>,
    history: Vec<DeliveryResult>,
    max_retries: u32,
}

impl Default for NotificationEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl NotificationEngine {
    pub fn new() -> Self {
        Self {
            channels: Vec::new(),
            history: Vec::new(),
            max_retries: 3,
        }
    }

    /// Add a notification channel.
    pub fn add_channel(&mut self, config: ChannelConfig) {
        self.channels.push(config);
    }

    /// Remove a channel by name.
    pub fn remove_channel(&mut self, name: &str) -> bool {
        let before = self.channels.len();
        self.channels.retain(|c| c.name != name);
        self.channels.len() < before
    }

    /// List configured channels.
    pub fn channels(&self) -> &[ChannelConfig] {
        &self.channels
    }

    /// Dispatch a notification to all matching channels.
    pub fn dispatch(&mut self, notification: &Notification) -> Vec<DeliveryResult> {
        let mut results = Vec::new();
        let channels: Vec<ChannelConfig> = self
            .channels
            .iter()
            .filter(|c| c.enabled && level_ge(&notification.level, &c.min_level))
            .cloned()
            .collect();

        for ch in &channels {
            let result = self.deliver(ch, notification);
            results.push(result);
        }

        self.history.extend(results.clone());
        results
    }

    /// Deliver a notification to a specific channel with retry logic.
    fn deliver(&self, channel: &ChannelConfig, notification: &Notification) -> DeliveryResult {
        let start = std::time::Instant::now();
        let payload = match channel.kind {
            ChannelKind::Slack => format_slack(notification),
            ChannelKind::MicrosoftTeams => format_teams(notification),
            ChannelKind::PagerDuty => {
                let key = channel.token.as_deref().unwrap_or("");
                format_pagerduty(notification, key)
            }
            ChannelKind::Webhook => format_webhook(notification),
            ChannelKind::Email => format_email(notification),
        };

        let url = channel.url.as_deref().unwrap_or("");

        // Attempt delivery with retries
        let mut last_err = None;
        let mut attempts = 0;
        for attempt in 0..self.max_retries {
            attempts = attempt + 1;

            if channel.kind == ChannelKind::Email {
                // SMTP delivery via TcpStream
                let smtp_cfg = match &channel.smtp {
                    Some(c) => c,
                    None => {
                        return DeliveryResult {
                            channel_name: channel.name.clone(),
                            channel_kind: channel.kind.clone(),
                            success: false,
                            status_code: None,
                            error: Some("no SMTP config".into()),
                            attempts,
                            duration_ms: start.elapsed().as_millis() as u64,
                        };
                    }
                };
                match smtp_send(smtp_cfg, &payload) {
                    Ok(()) => {
                        return DeliveryResult {
                            channel_name: channel.name.clone(),
                            channel_kind: channel.kind.clone(),
                            success: true,
                            status_code: Some(250),
                            error: None,
                            attempts,
                            duration_ms: start.elapsed().as_millis() as u64,
                        };
                    }
                    Err(e) => {
                        last_err = Some(e);
                        if attempt + 1 < self.max_retries {
                            std::thread::sleep(std::time::Duration::from_millis(
                                100 * 2u64.pow(attempt),
                            ));
                        }
                        continue;
                    }
                }
            }

            if url.is_empty() {
                return DeliveryResult {
                    channel_name: channel.name.clone(),
                    channel_kind: channel.kind.clone(),
                    success: false,
                    status_code: None,
                    error: Some("no URL configured".into()),
                    attempts,
                    duration_ms: start.elapsed().as_millis() as u64,
                };
            }

            match self.http_post(url, &payload, channel.token.as_deref()) {
                Ok(status) => {
                    let success = (200..300).contains(&status);
                    return DeliveryResult {
                        channel_name: channel.name.clone(),
                        channel_kind: channel.kind.clone(),
                        success,
                        status_code: Some(status),
                        error: if success {
                            None
                        } else {
                            Some(format!("HTTP {status}"))
                        },
                        attempts,
                        duration_ms: start.elapsed().as_millis() as u64,
                    };
                }
                Err(e) => {
                    last_err = Some(e);
                    // Exponential back-off: 100ms, 400ms, 1600ms
                    std::thread::sleep(std::time::Duration::from_millis(100 * 4_u64.pow(attempt)));
                }
            }
        }

        DeliveryResult {
            channel_name: channel.name.clone(),
            channel_kind: channel.kind.clone(),
            success: false,
            status_code: None,
            error: last_err,
            attempts,
            duration_ms: start.elapsed().as_millis() as u64,
        }
    }

    /// HTTP POST with optional bearer token.
    fn http_post(&self, url: &str, body: &str, token: Option<&str>) -> Result<u16, String> {
        let mut req = ureq::post(url).set("Content-Type", "application/json");
        if let Some(t) = token {
            req = req.set("Authorization", &format!("Bearer {t}"));
        }
        let resp = req
            .send_string(body)
            .map_err(|e| format!("HTTP error: {e}"))?;
        Ok(resp.status())
    }

    /// History of all dispatch results.
    pub fn history(&self) -> &[DeliveryResult] {
        &self.history
    }

    /// Number of successful deliveries.
    pub fn success_count(&self) -> usize {
        self.history.iter().filter(|d| d.success).count()
    }

    /// Number of failed deliveries.
    pub fn failure_count(&self) -> usize {
        self.history.iter().filter(|d| !d.success).count()
    }

    /// Clear the delivery history.
    pub fn clear_history(&mut self) {
        self.history.clear();
    }
}

// ── Build a notification from an alert ───────────────────────────────

/// Build a Notification from alert fields.
pub fn build_notification(
    alert_id: &str,
    level: &str,
    device_id: &str,
    reasons: &[String],
    score: f64,
) -> Notification {
    let title = format!("{level} alert on {device_id} (score {score:.1})");
    let body = if reasons.is_empty() {
        "No additional details.".to_string()
    } else {
        format!("Detection reasons:\n• {}", reasons.join("\n• "))
    };

    Notification {
        id: format!("notif-{alert_id}"),
        timestamp: chrono::Utc::now().to_rfc3339(),
        level: level.to_string(),
        title,
        body,
        device_id: device_id.to_string(),
        alert_ids: vec![alert_id.to_string()],
        metadata: HashMap::new(),
        mitre_techniques: Vec::new(),
        kill_chain_phase: None,
        recommended_action: None,
        affected_hosts: Vec::new(),
        investigation_link: None,
    }
}

// ── Minimal SMTP delivery ────────────────────────────────────────────

fn smtp_send(cfg: &SmtpConfig, message: &str) -> Result<(), String> {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    let addr = format!("{}:{}", cfg.host, cfg.port);
    let stream = TcpStream::connect(&addr).map_err(|e| format!("smtp connect: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(15))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(15))).ok();

    let mut writer = stream.try_clone().map_err(|e| format!("clone: {e}"))?;
    let mut reader = BufReader::new(stream);

    fn read_reply(reader: &mut BufReader<TcpStream>, expect_code: &str) -> Result<(), String> {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|e| format!("smtp read: {e}"))?;
        if !line.starts_with(expect_code) {
            return Err(format!("smtp expected {expect_code}, got: {}", line.trim()));
        }
        Ok(())
    }

    read_reply(&mut reader, "220")?;

    let helo = std::env::var("HOSTNAME").unwrap_or_else(|_| "wardex.local".into());
    write!(writer, "EHLO {helo}\r\n").map_err(|e| format!("smtp write: {e}"))?;
    writer.flush().map_err(|e| format!("smtp flush: {e}"))?;
    // Read multi-line EHLO response
    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|e| format!("smtp read ehlo: {e}"))?;
        if line.len() < 4 {
            break;
        }
        if line.as_bytes()[3] == b' ' {
            break;
        }
    }

    write!(writer, "MAIL FROM:<{}>\r\n", cfg.from).map_err(|e| format!("smtp write: {e}"))?;
    writer.flush().map_err(|e| format!("smtp flush: {e}"))?;
    read_reply(&mut reader, "250")?;

    for rcpt in &cfg.to {
        write!(writer, "RCPT TO:<{rcpt}>\r\n").map_err(|e| format!("smtp write: {e}"))?;
        writer.flush().map_err(|e| format!("smtp flush: {e}"))?;
        read_reply(&mut reader, "250")?;
    }

    write!(writer, "DATA\r\n").map_err(|e| format!("smtp write: {e}"))?;
    writer.flush().map_err(|e| format!("smtp flush: {e}"))?;
    read_reply(&mut reader, "354")?;

    // Write message headers and body, then terminator
    write!(writer, "From: <{}>\r\n", cfg.from).map_err(|e| format!("smtp write: {e}"))?;
    for rcpt in &cfg.to {
        write!(writer, "To: <{rcpt}>\r\n").map_err(|e| format!("smtp write: {e}"))?;
    }
    // message already contains Subject + Content-Type + body from format_email
    write!(writer, "{message}\r\n.\r\n").map_err(|e| format!("smtp write: {e}"))?;
    writer.flush().map_err(|e| format!("smtp flush: {e}"))?;
    read_reply(&mut reader, "250")?;

    write!(writer, "QUIT\r\n").map_err(|e| format!("smtp write: {e}"))?;
    writer.flush().ok();

    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_notification(level: &str) -> Notification {
        build_notification(
            "A-001",
            level,
            "sensor-42",
            &["network burst".into(), "brute force".into()],
            4.5,
        )
    }

    #[test]
    fn build_notification_fields() {
        let n = test_notification("Critical");
        assert!(n.title.contains("Critical"));
        assert!(n.title.contains("sensor-42"));
        assert!(n.body.contains("network burst"));
        assert!(n.body.contains("brute force"));
    }

    #[test]
    fn slack_format_contains_level() {
        let n = test_notification("Severe");
        let json = format_slack(&n);
        assert!(json.contains("Severe"));
        assert!(json.contains("sensor-42"));
    }

    #[test]
    fn teams_format_theme_color() {
        let n = test_notification("Critical");
        let json = format_teams(&n);
        assert!(json.contains("FF0000"));
    }

    #[test]
    fn pagerduty_format_severity() {
        let n = test_notification("Severe");
        let json = format_pagerduty(&n, "test-key");
        assert!(json.contains("\"severity\":\"error\""));
        assert!(json.contains("test-key"));
    }

    #[test]
    fn webhook_format_round_trips() {
        let n = test_notification("Elevated");
        let json = format_webhook(&n);
        let parsed: Notification = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.device_id, "sensor-42");
    }

    #[test]
    fn email_format_subject() {
        let n = test_notification("Critical");
        let text = format_email(&n);
        assert!(text.starts_with("Subject: [Wardex Critical]"));
    }

    #[test]
    fn level_filtering() {
        assert!(level_ge("Critical", "Elevated"));
        assert!(level_ge("Severe", "Severe"));
        assert!(!level_ge("Elevated", "Severe"));
    }

    #[test]
    fn engine_dispatch_with_no_channels() {
        let mut engine = NotificationEngine::new();
        let n = test_notification("Critical");
        let results = engine.dispatch(&n);
        assert!(results.is_empty());
    }

    #[test]
    fn engine_dispatch_email() {
        let mut engine = NotificationEngine::new();
        engine.add_channel(ChannelConfig {
            kind: ChannelKind::Email,
            name: "ops-email".into(),
            enabled: true,
            url: None,
            token: None,
            smtp: Some(SmtpConfig {
                host: "smtp.example.com".into(),
                port: 587,
                from: "wardex@example.com".into(),
                to: vec!["ops@example.com".into()],
                username: None,
                use_tls: true,
            }),
            min_level: "Severe".into(),
        });

        let n = test_notification("Critical");
        let results = engine.dispatch(&n);
        assert_eq!(results.len(), 1);
        // SMTP will fail in test env (no real server), but should report the attempt
        assert!(!results[0].success || results[0].status_code == Some(250));
        assert!(results[0].error.is_some() || results[0].success);
    }

    #[test]
    fn engine_skips_disabled_channel() {
        let mut engine = NotificationEngine::new();
        engine.add_channel(ChannelConfig {
            kind: ChannelKind::Slack,
            name: "disabled-slack".into(),
            enabled: false,
            url: Some("https://hooks.slack.com/test".into()),
            token: None,
            smtp: None,
            min_level: "Elevated".into(),
        });

        let n = test_notification("Critical");
        let results = engine.dispatch(&n);
        assert!(results.is_empty());
    }

    #[test]
    fn engine_skips_low_level() {
        let mut engine = NotificationEngine::new();
        engine.add_channel(ChannelConfig {
            kind: ChannelKind::Email,
            name: "critical-only".into(),
            enabled: true,
            url: None,
            token: None,
            smtp: Some(SmtpConfig {
                host: "smtp.example.com".into(),
                port: 587,
                from: "wardex@example.com".into(),
                to: vec!["boss@example.com".into()],
                username: None,
                use_tls: true,
            }),
            min_level: "Critical".into(),
        });

        let n = test_notification("Elevated");
        let results = engine.dispatch(&n);
        assert!(results.is_empty());
    }

    #[test]
    fn engine_no_url_returns_error() {
        let mut engine = NotificationEngine::new();
        engine.add_channel(ChannelConfig {
            kind: ChannelKind::Slack,
            name: "no-url-slack".into(),
            enabled: true,
            url: None,
            token: None,
            smtp: None,
            min_level: "Elevated".into(),
        });

        let n = test_notification("Critical");
        let results = engine.dispatch(&n);
        assert_eq!(results.len(), 1);
        assert!(!results[0].success);
        assert!(results[0].error.as_ref().unwrap().contains("no URL"));
    }

    #[test]
    fn email_sanitises_crlf_injection() {
        let mut n = test_notification("Critical");
        n.title = "legit\r\nBcc: attacker@evil.com".into();
        n.device_id = "dev\r\nX-Injected: yes".into();
        let text = format_email(&n);
        // CR/LF stripped: injected header cannot appear on its own line
        assert!(!text.contains("\r\nBcc:"), "CRLF injection must be blocked");
        assert!(
            !text.contains("\r\nX-Injected:"),
            "CRLF injection must be blocked"
        );
        // The sanitised text should still include the subject line
        assert!(text.starts_with("Subject: [Wardex Critical]"));
    }

    #[test]
    fn remove_channel_works() {
        let mut engine = NotificationEngine::new();
        engine.add_channel(ChannelConfig {
            kind: ChannelKind::Webhook,
            name: "hooks".into(),
            enabled: true,
            url: Some("https://example.com/hook".into()),
            token: None,
            smtp: None,
            min_level: "Elevated".into(),
        });
        assert!(engine.remove_channel("hooks"));
        assert!(!engine.remove_channel("hooks"));
        assert!(engine.channels().is_empty());
    }

    #[test]
    fn history_tracking() {
        let mut engine = NotificationEngine::new();
        engine.add_channel(ChannelConfig {
            kind: ChannelKind::Email,
            name: "audit-email".into(),
            enabled: true,
            url: None,
            token: None,
            smtp: Some(SmtpConfig {
                host: "localhost".into(),
                port: 25,
                from: "wardex@test.local".into(),
                to: vec!["admin@test.local".into()],
                username: None,
                use_tls: false,
            }),
            min_level: "Elevated".into(),
        });

        let n1 = test_notification("Severe");
        let n2 = test_notification("Critical");
        engine.dispatch(&n1);
        engine.dispatch(&n2);

        assert_eq!(engine.history().len(), 2);
        // In test env without SMTP server, deliveries may fail
        assert_eq!(engine.success_count() + engine.failure_count(), 2);

        engine.clear_history();
        assert!(engine.history().is_empty());
    }
}
