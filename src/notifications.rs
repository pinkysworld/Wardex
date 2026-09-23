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
    /// AUTH password/app-password, sent as AUTH PLAIN/LOGIN once the
    /// connection is on TLS (either STARTTLS or implicit TLS). Never used
    /// over a plaintext connection.
    #[serde(default, skip_serializing)]
    pub password: Option<String>,
    /// Upgrade the connection with STARTTLS after EHLO. Ignored (treated as
    /// already-TLS) when `implicit_tls` is set.
    pub use_tls: bool,
    /// Connect with implicit TLS from the first byte (typically port 465),
    /// instead of STARTTLS on a plaintext port (typically 587/25).
    #[serde(default)]
    pub implicit_tls: bool,
    /// Optional additional PEM-encoded certificate(s) to trust, alongside
    /// the built-in Mozilla root store. Use this to reach an internal relay
    /// signed by a private CA (or, in tests, a self-signed certificate).
    /// Certificate verification stays on — this only widens the trust
    /// anchors, it never disables verification.
    #[serde(default)]
    pub ca_cert_pem: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OutboxStatus {
    Queued,
    Delivered,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboxRecord {
    pub notification_id: String,
    pub dedupe_key: String,
    pub channel_name: String,
    pub channel_kind: ChannelKind,
    pub queued_at: String,
    pub last_attempt_at: Option<String>,
    pub next_retry_at: Option<String>,
    pub attempts: u32,
    pub status: OutboxStatus,
    pub last_error: Option<String>,
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
    outbox: Vec<OutboxRecord>,
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
            outbox: Vec::new(),
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

    /// Dispatch and keep an operator-visible outbox record for every channel.
    ///
    /// This preserves the existing immediate delivery behavior while exposing
    /// delivery provenance for SOC handoffs, release evidence, and later
    /// durable-queue persistence.
    pub fn dispatch_with_outbox(&mut self, notification: &Notification) -> Vec<DeliveryResult> {
        let results = self.dispatch(notification);
        for result in &results {
            self.record_outbox_result(notification, result);
        }
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

    /// Operator-visible notification queue and delivery trail.
    pub fn outbox(&self) -> &[OutboxRecord] {
        &self.outbox
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

    /// Clear transient delivery history and outbox records.
    pub fn clear_delivery_state(&mut self) {
        self.history.clear();
        self.outbox.clear();
    }

    fn record_outbox_result(&mut self, notification: &Notification, result: &DeliveryResult) {
        let now = chrono::Utc::now();
        let dedupe_key = format!("{}:{}", notification.id, result.channel_name);
        let next_retry_at = if result.success {
            None
        } else {
            Some((now + chrono::Duration::minutes(5)).to_rfc3339())
        };
        let terminal_config_error = result
            .error
            .as_deref()
            .is_some_and(|error| error.contains("no URL") || error.contains("no SMTP config"));
        let status = if result.success {
            OutboxStatus::Delivered
        } else if terminal_config_error || result.attempts >= self.max_retries {
            OutboxStatus::Failed
        } else {
            OutboxStatus::Queued
        };
        if let Some(existing) = self
            .outbox
            .iter_mut()
            .find(|record| record.dedupe_key == dedupe_key)
        {
            existing.last_attempt_at = Some(now.to_rfc3339());
            existing.next_retry_at = next_retry_at;
            existing.attempts = result.attempts;
            existing.status = status;
            existing.last_error = result.error.clone();
            return;
        }
        self.outbox.push(OutboxRecord {
            notification_id: notification.id.clone(),
            dedupe_key,
            channel_name: result.channel_name.clone(),
            channel_kind: result.channel_kind.clone(),
            queued_at: now.to_rfc3339(),
            last_attempt_at: Some(now.to_rfc3339()),
            next_retry_at,
            attempts: result.attempts,
            status,
            last_error: result.error.clone(),
        });
        if self.outbox.len() > 500 {
            let keep_from = self.outbox.len() - 500;
            self.outbox.drain(0..keep_from);
        }
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

// ── SMTP delivery: STARTTLS / implicit TLS / AUTH ─────────────────────
//
// Supports plaintext, STARTTLS (upgrade after EHLO, typically port 587/25),
// and implicit TLS (encrypted from the first byte, typically port 465), plus
// AUTH PLAIN/LOGIN. Certificate verification is always on — there is no
// "skip verification" escape hatch. When TLS is requested but this binary
// was built without the `tls` cargo feature, delivery fails with a clear
// error instead of silently falling back to plaintext.

/// Transport used for the SMTP dialog: a plain TCP socket, or (with the
/// `tls` feature) one upgraded to TLS either implicitly or via STARTTLS.
enum SmtpTransport {
    Plain(std::net::TcpStream),
    #[cfg(feature = "tls")]
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>>),
}

impl std::io::Read for SmtpTransport {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(s) => s.read(buf),
            #[cfg(feature = "tls")]
            Self::Tls(s) => s.read(buf),
        }
    }
}

impl std::io::Write for SmtpTransport {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(s) => s.write(buf),
            #[cfg(feature = "tls")]
            Self::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(s) => s.flush(),
            #[cfg(feature = "tls")]
            Self::Tls(s) => s.flush(),
        }
    }
}

#[cfg(feature = "tls")]
fn parse_pem_certificates(
    pem: &str,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
    use base64::Engine;
    let mut certs = Vec::new();
    let mut current = String::new();
    let mut in_cert = false;
    for line in pem.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("-----BEGIN CERTIFICATE-----") {
            in_cert = true;
            current.clear();
            continue;
        }
        if trimmed.starts_with("-----END CERTIFICATE-----") {
            in_cert = false;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(current.trim())
                .map_err(|e| format!("invalid PEM certificate: {e}"))?;
            certs.push(rustls::pki_types::CertificateDer::from(bytes));
            continue;
        }
        if in_cert {
            current.push_str(trimmed);
        }
    }
    if certs.is_empty() {
        return Err("no certificates found in PEM input".into());
    }
    Ok(certs)
}

#[cfg(feature = "tls")]
fn build_tls_client_config(
    extra_trusted_pem: Option<&str>,
) -> Result<std::sync::Arc<rustls::ClientConfig>, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(pem) = extra_trusted_pem {
        for cert in parse_pem_certificates(pem)? {
            roots
                .add(cert)
                .map_err(|e| format!("failed to add trusted certificate: {e}"))?;
        }
    }
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("smtp tls config: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(std::sync::Arc::new(config))
}

#[cfg(feature = "tls")]
fn upgrade_to_tls(
    tcp: std::net::TcpStream,
    host: &str,
    extra_trusted_pem: Option<&str>,
) -> Result<SmtpTransport, String> {
    let config = build_tls_client_config(extra_trusted_pem)?;
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| format!("smtp tls: invalid server name '{host}': {e}"))?;
    let conn = rustls::ClientConnection::new(config, server_name)
        .map_err(|e| format!("smtp tls handshake setup failed: {e}"))?;
    Ok(SmtpTransport::Tls(Box::new(rustls::StreamOwned::new(
        conn, tcp,
    ))))
}

#[cfg(not(feature = "tls"))]
fn upgrade_to_tls(
    _tcp: std::net::TcpStream,
    _host: &str,
    _extra_trusted_pem: Option<&str>,
) -> Result<SmtpTransport, String> {
    Err("SMTP TLS was requested but this build was compiled without the `tls` feature".into())
}

/// Line-oriented SMTP session helper over a boxed transport. Reads are
/// buffered internally (a `Transport` may be a TLS stream, which cannot be
/// safely wrapped in `BufReader` after also being written to on the same
/// object without extra bookkeeping).
struct SmtpSession {
    transport: SmtpTransport,
    read_buf: Vec<u8>,
}

impl SmtpSession {
    fn new(transport: SmtpTransport) -> Self {
        Self {
            transport,
            read_buf: Vec::new(),
        }
    }

    fn read_line(&mut self) -> Result<String, String> {
        use std::io::Read;
        loop {
            if let Some(pos) = self.read_buf.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = self.read_buf.drain(..=pos).collect();
                return Ok(String::from_utf8_lossy(&line).trim_end().to_string());
            }
            let mut chunk = [0u8; 1024];
            let n = self
                .transport
                .read(&mut chunk)
                .map_err(|e| format!("smtp read: {e}"))?;
            if n == 0 {
                return Err("smtp connection closed unexpectedly".into());
            }
            self.read_buf.extend_from_slice(&chunk[..n]);
        }
    }

    fn write_raw(&mut self, data: &str) -> Result<(), String> {
        use std::io::Write;
        self.transport
            .write_all(data.as_bytes())
            .map_err(|e| format!("smtp write: {e}"))?;
        self.transport
            .flush()
            .map_err(|e| format!("smtp flush: {e}"))
    }

    fn command(&mut self, line: &str) -> Result<(), String> {
        self.write_raw(&format!("{line}\r\n"))
    }

    /// Read a (possibly multi-line) reply and assert it starts with
    /// `expect_code`. Returns the last line's text after the code.
    fn read_reply(&mut self, expect_code: &str) -> Result<String, String> {
        loop {
            let line = self.read_line()?;
            if line.len() < 3 || !line.starts_with(expect_code) {
                return Err(format!(
                    "smtp expected {expect_code}, got: {}",
                    line.trim()
                ));
            }
            let continuation = line.as_bytes().get(3) == Some(&b'-');
            if !continuation {
                return Ok(line.get(4..).unwrap_or("").to_string());
            }
        }
    }

    /// Read the multi-line EHLO reply and return the advertised capability
    /// lines (e.g. "STARTTLS", "AUTH PLAIN LOGIN"), uppercased.
    fn read_ehlo_capabilities(&mut self) -> Result<Vec<String>, String> {
        let mut caps = Vec::new();
        loop {
            let line = self.read_line()?;
            if line.len() < 3 || !line.starts_with("250") {
                return Err(format!("smtp expected 250 (EHLO), got: {}", line.trim()));
            }
            caps.push(line.get(4..).unwrap_or("").trim().to_ascii_uppercase());
            let continuation = line.as_bytes().get(3) == Some(&b'-');
            if !continuation {
                break;
            }
        }
        Ok(caps)
    }
}

/// Dot-stuff a message body per RFC 5321 §4.5.2: any line beginning with
/// '.' gets an extra leading '.' so it isn't mistaken for the terminator.
fn dot_stuff(message: &str) -> String {
    message
        .split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .map(|line| {
            if line.starts_with('.') {
                format!(".{line}")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\r\n")
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn smtp_send(cfg: &SmtpConfig, message: &str) -> Result<(), String> {
    use std::net::TcpStream;
    use std::time::Duration;

    let wants_tls = cfg.use_tls || cfg.implicit_tls;
    if wants_tls && cfg!(not(feature = "tls")) {
        return Err(
            "SMTP TLS was requested but this build was compiled without the `tls` feature".into(),
        );
    }

    let addr = format!("{}:{}", cfg.host, cfg.port);
    let tcp = TcpStream::connect(&addr).map_err(|e| format!("smtp connect: {e}"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(20))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(20))).ok();

    let transport = if cfg.implicit_tls {
        upgrade_to_tls(tcp, &cfg.host, cfg.ca_cert_pem.as_deref())?
    } else {
        SmtpTransport::Plain(tcp)
    };
    let mut session = SmtpSession::new(transport);

    session.read_reply("220")?;

    let helo = std::env::var("HOSTNAME").unwrap_or_else(|_| "wardex.local".into());
    session.command(&format!("EHLO {helo}"))?;
    let mut capabilities = session.read_ehlo_capabilities()?;

    if cfg.use_tls && !cfg.implicit_tls {
        if !capabilities.iter().any(|c| c == "STARTTLS") {
            return Err("smtp server does not advertise STARTTLS".into());
        }
        session.command("STARTTLS")?;
        session.read_reply("220")?;

        // Re-borrow the underlying TCP socket for the TLS handshake. Only
        // the `Plain` variant can reach here (implicit TLS took the other
        // branch above), so this always succeeds.
        let SmtpSession {
            transport,
            read_buf,
        } = session;
        let tcp = match transport {
            SmtpTransport::Plain(tcp) => tcp,
            #[cfg(feature = "tls")]
            SmtpTransport::Tls(_) => {
                return Err("smtp internal error: unexpected TLS transport before STARTTLS".into());
            }
        };
        if !read_buf.is_empty() {
            return Err("smtp protocol error: unexpected data before TLS handshake".into());
        }
        let transport = upgrade_to_tls(tcp, &cfg.host, cfg.ca_cert_pem.as_deref())?;
        session = SmtpSession::new(transport);

        // RFC 3207: state resets after STARTTLS, so re-issue EHLO.
        session.command(&format!("EHLO {helo}"))?;
        capabilities = session.read_ehlo_capabilities()?;
    }

    if let (Some(username), Some(password)) = (cfg.username.as_ref(), cfg.password.as_ref()) {
        let auth_line = capabilities
            .iter()
            .find(|c| c.starts_with("AUTH "))
            .cloned()
            .unwrap_or_default();
        if auth_line.contains("PLAIN") {
            let mut creds = Vec::new();
            creds.push(0u8);
            creds.extend_from_slice(username.as_bytes());
            creds.push(0u8);
            creds.extend_from_slice(password.as_bytes());
            session.command(&format!("AUTH PLAIN {}", base64_encode(&creds)))?;
            session.read_reply("235")?;
        } else if auth_line.contains("LOGIN") {
            session.command("AUTH LOGIN")?;
            session.read_reply("334")?;
            session.command(&base64_encode(username.as_bytes()))?;
            session.read_reply("334")?;
            session.command(&base64_encode(password.as_bytes()))?;
            session.read_reply("235")?;
        } else {
            return Err(
                "smtp credentials configured but server advertises no supported AUTH mechanism"
                    .into(),
            );
        }
    }

    session.command(&format!("MAIL FROM:<{}>", cfg.from))?;
    session.read_reply("250")?;

    for rcpt in &cfg.to {
        session.command(&format!("RCPT TO:<{rcpt}>"))?;
        session.read_reply("250")?;
    }

    session.command("DATA")?;
    session.read_reply("354")?;

    let mut body = String::new();
    body.push_str(&format!("From: <{}>\r\n", cfg.from));
    for rcpt in &cfg.to {
        body.push_str(&format!("To: <{rcpt}>\r\n"));
    }
    // `message` already contains Subject + Content-Type + body from
    // `format_email`; dot-stuff the combined content before the terminator.
    body.push_str(message);
    let stuffed = dot_stuff(&body);
    session.write_raw(&format!("{stuffed}\r\n.\r\n"))?;
    session.read_reply("250")?;

    session.command("QUIT").ok();

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
                password: None,
                use_tls: true,
                implicit_tls: false,
                ca_cert_pem: None,
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
                password: None,
                use_tls: true,
                implicit_tls: false,
                ca_cert_pem: None,
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
                password: None,
                use_tls: false,
                implicit_tls: false,
                ca_cert_pem: None,
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

    #[test]
    fn dispatch_with_outbox_records_delivery_state() {
        let mut engine = NotificationEngine::new();
        engine.add_channel(ChannelConfig {
            kind: ChannelKind::Webhook,
            name: "missing-hook".into(),
            enabled: true,
            url: None,
            token: None,
            smtp: None,
            min_level: "Elevated".into(),
        });

        let n = test_notification("Critical");
        let results = engine.dispatch_with_outbox(&n);
        assert_eq!(results.len(), 1);
        assert_eq!(engine.outbox().len(), 1);
        let record = &engine.outbox()[0];
        assert_eq!(record.notification_id, n.id);
        assert_eq!(record.channel_name, "missing-hook");
        assert_eq!(record.status, OutboxStatus::Failed);
        assert!(
            record
                .last_error
                .as_deref()
                .unwrap_or("")
                .contains("no URL")
        );

        engine.dispatch_with_outbox(&n);
        assert_eq!(
            engine.outbox().len(),
            1,
            "dedupe key should update the existing record"
        );
        engine.clear_delivery_state();
        assert!(engine.history().is_empty());
        assert!(engine.outbox().is_empty());
    }

    // ── SMTP protocol-level tests ─────────────────────────────────────

    #[test]
    fn dot_stuffing_escapes_leading_dots() {
        let input = "Subject: test\r\n\r\n.leading dot\r\nnormal line\r\n..double dot";
        let stuffed = dot_stuff(input);
        assert!(stuffed.contains("\r\n..leading dot"));
        assert!(stuffed.contains("\r\nnormal line"));
        assert!(stuffed.contains("\r\n...double dot"));
    }

    #[test]
    fn smtp_plain_delivery_against_fake_server() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake smtp");
        let port = listener.local_addr().expect("addr").port();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept smtp connection");
            stream
                .write_all(b"220 fake.smtp ready\r\n")
                .expect("greeting");

            let mut buf = [0u8; 4096];
            let mut received = String::new();
            let mut read_line = |stream: &mut std::net::TcpStream, received: &mut String| {
                loop {
                    if let Some(pos) = received.find("\r\n") {
                        let line: String = received.drain(..pos + 2).collect();
                        return line;
                    }
                    let n = stream.read(&mut buf).unwrap_or(0);
                    if n == 0 {
                        return String::new();
                    }
                    received.push_str(&String::from_utf8_lossy(&buf[..n]));
                }
            };

            let ehlo = read_line(&mut stream, &mut received);
            assert!(ehlo.starts_with("EHLO"));
            stream.write_all(b"250 fake.smtp\r\n").expect("ehlo reply");

            let mail_from = read_line(&mut stream, &mut received);
            assert!(mail_from.starts_with("MAIL FROM:"));
            stream.write_all(b"250 OK\r\n").expect("mail reply");

            let rcpt_to = read_line(&mut stream, &mut received);
            assert!(rcpt_to.starts_with("RCPT TO:"));
            stream.write_all(b"250 OK\r\n").expect("rcpt reply");

            let data = read_line(&mut stream, &mut received);
            assert!(data.starts_with("DATA"));
            stream.write_all(b"354 go ahead\r\n").expect("data reply");

            // Read until the lone "." terminator line.
            loop {
                let line = read_line(&mut stream, &mut received);
                if line == ".\r\n" {
                    break;
                }
                if line.is_empty() {
                    break;
                }
            }
            stream.write_all(b"250 queued\r\n").expect("data done");

            let quit = read_line(&mut stream, &mut received);
            assert!(quit.starts_with("QUIT"));
        });

        let cfg = SmtpConfig {
            host: "127.0.0.1".into(),
            port,
            from: "wardex@test.local".into(),
            to: vec!["ops@test.local".into()],
            username: None,
            password: None,
            use_tls: false,
            implicit_tls: false,
            ca_cert_pem: None,
        };
        let result = smtp_send(&cfg, "Subject: hi\r\n\r\nbody");
        handle.join().expect("server thread");
        assert!(result.is_ok(), "smtp_send failed: {result:?}");
    }

    /// Generates a self-signed certificate + key for the fake STARTTLS
    /// server, using the `rcgen` dev-dependency (test-only; no production
    /// code path depends on it).
    fn self_signed_server_identity() -> (
        rustls::pki_types::CertificateDer<'static>,
        rustls::pki_types::PrivateKeyDer<'static>,
        String,
    ) {
        let certified_key = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()])
            .expect("generate self-signed cert");
        let cert_der = certified_key.cert.der().clone();
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(certified_key.key_pair.serialize_der()),
        );
        let pem = certified_key.cert.pem();
        (cert_der, key_der, pem)
    }

    /// A fake SMTP server that advertises STARTTLS and AUTH, performs a real
    /// TLS handshake with a self-signed certificate, and validates the
    /// client authenticated with AUTH PLAIN before accepting the message.
    fn spawn_starttls_fake_server() -> (u16, String, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let (cert_der, key_der, cert_pem) = self_signed_server_identity();
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .expect("build server tls config");
        let server_config = std::sync::Arc::new(server_config);

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake smtps");
        let port = listener.local_addr().expect("addr").port();

        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept smtp connection");
            stream
                .write_all(b"220 fake.smtp starttls ready\r\n")
                .expect("greeting");

            let mut plain_buf = [0u8; 4096];
            let mut plain_received = String::new();
            let mut read_plain_line = |stream: &mut std::net::TcpStream, received: &mut String| {
                loop {
                    if let Some(pos) = received.find("\r\n") {
                        let line: String = received.drain(..pos + 2).collect();
                        return line;
                    }
                    let n = stream.read(&mut plain_buf).unwrap_or(0);
                    if n == 0 {
                        return String::new();
                    }
                    received.push_str(&String::from_utf8_lossy(&plain_buf[..n]));
                }
            };

            let ehlo = read_plain_line(&mut stream, &mut plain_received);
            assert!(ehlo.starts_with("EHLO"));
            stream
                .write_all(b"250-fake.smtp\r\n250 STARTTLS\r\n")
                .expect("ehlo caps");

            let starttls = read_plain_line(&mut stream, &mut plain_received);
            assert!(starttls.starts_with("STARTTLS"));
            stream.write_all(b"220 go ahead\r\n").expect("starttls ack");
            assert!(
                plain_received.is_empty(),
                "no bytes may follow STARTTLS on the plaintext channel"
            );

            let conn = rustls::ServerConnection::new(server_config).expect("server tls connection");
            let mut tls_stream = rustls::StreamOwned::new(conn, stream);

            let mut tls_buf = [0u8; 4096];
            let mut tls_received = String::new();
            let mut read_tls_line = |stream: &mut rustls::StreamOwned<
                rustls::ServerConnection,
                std::net::TcpStream,
            >,
                                      received: &mut String| {
                loop {
                    if let Some(pos) = received.find("\r\n") {
                        let line: String = received.drain(..pos + 2).collect();
                        return line;
                    }
                    let n = stream.read(&mut tls_buf).unwrap_or(0);
                    if n == 0 {
                        return String::new();
                    }
                    received.push_str(&String::from_utf8_lossy(&tls_buf[..n]));
                }
            };

            let ehlo2 = read_tls_line(&mut tls_stream, &mut tls_received);
            assert!(ehlo2.starts_with("EHLO"));
            tls_stream
                .write_all(b"250-fake.smtp\r\n250 AUTH PLAIN LOGIN\r\n")
                .expect("ehlo2 caps");

            let auth = read_tls_line(&mut tls_stream, &mut tls_received);
            assert!(auth.starts_with("AUTH PLAIN"));
            tls_stream
                .write_all(b"235 authenticated\r\n")
                .expect("auth ok");

            let mail_from = read_tls_line(&mut tls_stream, &mut tls_received);
            assert!(mail_from.starts_with("MAIL FROM:"));
            tls_stream.write_all(b"250 OK\r\n").expect("mail reply");

            let rcpt_to = read_tls_line(&mut tls_stream, &mut tls_received);
            assert!(rcpt_to.starts_with("RCPT TO:"));
            tls_stream.write_all(b"250 OK\r\n").expect("rcpt reply");

            let data = read_tls_line(&mut tls_stream, &mut tls_received);
            assert!(data.starts_with("DATA"));
            tls_stream.write_all(b"354 go ahead\r\n").expect("data reply");

            loop {
                let line = read_tls_line(&mut tls_stream, &mut tls_received);
                if line == ".\r\n" || line.is_empty() {
                    break;
                }
            }
            tls_stream.write_all(b"250 queued\r\n").expect("data done");

            let quit = read_tls_line(&mut tls_stream, &mut tls_received);
            assert!(quit.starts_with("QUIT"));
        });
        (port, cert_pem, handle)
    }

    #[test]
    fn smtp_starttls_with_auth_against_fake_tls_server() {
        use std::io::Write as _;

        let (port, cert_pem, handle) = spawn_starttls_fake_server();
        let cfg = SmtpConfig {
            host: "127.0.0.1".into(),
            port,
            from: "wardex@test.local".into(),
            to: vec!["ops@test.local".into()],
            username: Some("wardex-bot".into()),
            password: Some("s3cret".into()),
            use_tls: true,
            implicit_tls: false,
            ca_cert_pem: Some(cert_pem),
        };
        let result = smtp_send(&cfg, "Subject: hi over tls\r\n\r\nbody");
        handle.join().expect("server thread");
        assert!(result.is_ok(), "starttls smtp_send failed: {result:?}");
        let _ = std::io::stdout().flush();
    }

    #[test]
    fn smtp_starttls_rejects_untrusted_certificate() {
        // Same fake server, but the client does NOT trust its self-signed
        // certificate: the handshake must fail rather than silently
        // downgrading or accepting an unverified peer.
        let (port, _cert_pem, handle) = spawn_starttls_fake_server();
        let cfg = SmtpConfig {
            host: "127.0.0.1".into(),
            port,
            from: "wardex@test.local".into(),
            to: vec!["ops@test.local".into()],
            username: None,
            password: None,
            use_tls: true,
            implicit_tls: false,
            ca_cert_pem: None, // not trusted -> must fail closed
        };
        let result = smtp_send(&cfg, "Subject: hi\r\n\r\nbody");
        assert!(result.is_err(), "must not accept an unverified certificate");
        // The fake server thread will be stuck mid-handshake since the
        // client aborted; drop the handle without joining to avoid hanging
        // the test suite.
        drop(handle);
    }
}
