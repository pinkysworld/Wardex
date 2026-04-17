//! Email and phishing header analysis.
//!
//! Analyzes email headers for authentication failures (SPF/DKIM/DMARC),
//! sender mismatches, suspicious URLs, attachment risks, and urgency heuristics.

use serde::{Deserialize, Serialize};

// ── Types ────────────────────────────────────────────────────────────────────

/// Email authentication status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuthStatus {
    Pass,
    Fail,
    SoftFail,
    None,
    Unknown,
}

impl std::fmt::Display for AuthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pass => write!(f, "pass"),
            Self::Fail => write!(f, "fail"),
            Self::SoftFail => write!(f, "softfail"),
            Self::None => write!(f, "none"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Combined authentication results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResults {
    pub spf: AuthStatus,
    pub dkim: AuthStatus,
    pub dmarc: AuthStatus,
    pub auth_score: f32,
}

/// URL finding in email body/headers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UrlFinding {
    pub url: String,
    pub risk_score: f32,
    pub indicators: Vec<String>,
}

/// Attachment finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentFinding {
    pub filename: String,
    pub content_type: Option<String>,
    pub sha256: Option<String>,
    pub risk_score: f32,
    pub indicators: Vec<String>,
}

/// Structured email input for analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailInput {
    pub from: String,
    pub reply_to: Option<String>,
    pub return_path: Option<String>,
    pub to: Option<String>,
    pub subject: Option<String>,
    pub received_chain: Vec<String>,
    pub authentication_results: Option<String>,
    pub body_text: Option<String>,
    pub body_html: Option<String>,
    pub attachments: Vec<AttachmentInfo>,
    pub message_id: Option<String>,
}

/// Attachment metadata in the input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentInfo {
    pub filename: String,
    pub content_type: Option<String>,
    pub sha256: Option<String>,
    pub size_bytes: Option<usize>,
}

/// Complete email threat report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailThreatReport {
    pub message_id: String,
    pub auth_results: AuthResults,
    pub sender_mismatch: bool,
    pub url_findings: Vec<UrlFinding>,
    pub attachment_findings: Vec<AttachmentFinding>,
    pub urgency_score: f32,
    pub phishing_score: f32,
    pub indicators: Vec<String>,
}

// ── URL Shortener & Suspicious TLD lists ─────────────────────────────────────

const URL_SHORTENERS: &[&str] = &[
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "adf.ly",
    "tiny.cc",
    "rb.gy",
    "cutt.ly",
    "shorturl.at",
];

const SUSPICIOUS_TLDS: &[&str] = &[
    ".tk", ".top", ".xyz", ".buzz", ".cyou", ".icu", ".gq", ".ml", ".cf", ".ga", ".click", ".link",
    ".loan", ".racing", ".win",
];

/// High-risk attachment extensions.
const DANGEROUS_EXTENSIONS: &[&str] = &[
    ".exe", ".scr", ".pif", ".bat", ".cmd", ".com", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".ps1", ".msi", ".hta", ".cpl", ".dll", ".lnk", ".inf", ".reg",
];

/// Macro-enabled Office formats.
const MACRO_FORMATS: &[&str] = &[
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".ppam", ".sldm", ".xlam",
];

/// Urgency keywords in subject lines.
const URGENCY_KEYWORDS: &[(&str, f32)] = &[
    ("urgent", 0.3),
    ("immediately", 0.3),
    ("action required", 0.3),
    ("verify your", 0.4),
    ("confirm your", 0.3),
    ("suspended", 0.4),
    ("locked", 0.3),
    ("invoice", 0.2),
    ("payment", 0.2),
    ("password", 0.3),
    ("expire", 0.3),
    ("security alert", 0.3),
    ("unusual activity", 0.3),
    ("unauthorized", 0.3),
    ("click here", 0.2),
    ("act now", 0.3),
    ("limited time", 0.2),
    ("prize", 0.3),
    ("winner", 0.3),
    ("congratulations", 0.3),
    ("inheritance", 0.4),
];

// ── Email Analyzer ───────────────────────────────────────────────────────────

pub struct EmailAnalyzer;

impl EmailAnalyzer {
    /// Analyze an email for phishing indicators.
    pub fn analyze(input: &EmailInput) -> EmailThreatReport {
        let mut indicators = Vec::new();

        // 1. Authentication analysis
        let auth_results = Self::check_auth(input, &mut indicators);

        // 2. Sender mismatch
        let sender_mismatch = Self::check_sender_mismatch(input, &mut indicators);

        // 2b. Sender domain heuristics
        let sender_domain_score = Self::check_sender_domains(input, &mut indicators);

        // 3. URL analysis
        let body = [input.body_text.as_deref(), input.body_html.as_deref()]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join("\n");
        let url_findings = Self::analyze_urls(&body, &mut indicators);

        // 4. Attachment analysis
        let attachment_findings = Self::analyze_attachments(&input.attachments, &mut indicators);

        // 5. Urgency scoring
        let urgency_score =
            Self::urgency_score(input.subject.as_deref().unwrap_or(""), &mut indicators);

        // 6. Received chain analysis
        Self::check_received_chain(&input.received_chain, &mut indicators);

        // Composite phishing score
        let phishing_score = Self::compute_phishing_score(
            &auth_results,
            sender_mismatch,
            &url_findings,
            &attachment_findings,
            urgency_score,
            sender_domain_score,
        );

        EmailThreatReport {
            message_id: input.message_id.clone().unwrap_or_default(),
            auth_results,
            sender_mismatch,
            url_findings,
            attachment_findings,
            urgency_score,
            phishing_score,
            indicators,
        }
    }

    fn check_auth(input: &EmailInput, indicators: &mut Vec<String>) -> AuthResults {
        let auth_str = input
            .authentication_results
            .as_deref()
            .unwrap_or("")
            .to_lowercase();

        let spf = if auth_str.contains("spf=pass") {
            AuthStatus::Pass
        } else if auth_str.contains("spf=fail") {
            AuthStatus::Fail
        } else if auth_str.contains("spf=softfail") {
            AuthStatus::SoftFail
        } else if auth_str.contains("spf=none") {
            AuthStatus::None
        } else {
            AuthStatus::Unknown
        };

        let dkim = if auth_str.contains("dkim=pass") {
            AuthStatus::Pass
        } else if auth_str.contains("dkim=fail") {
            AuthStatus::Fail
        } else {
            AuthStatus::Unknown
        };

        let dmarc = if auth_str.contains("dmarc=pass") {
            AuthStatus::Pass
        } else if auth_str.contains("dmarc=fail") {
            AuthStatus::Fail
        } else {
            AuthStatus::Unknown
        };

        let mut auth_score: f32 = 0.0;
        if spf == AuthStatus::Fail {
            auth_score += 0.3;
            indicators.push("SPF fail".into());
        }
        if spf == AuthStatus::SoftFail {
            auth_score += 0.15;
            indicators.push("SPF softfail".into());
        }
        if spf == AuthStatus::None {
            auth_score += 0.1;
            indicators.push("no SPF record".into());
        }
        if dkim == AuthStatus::Fail {
            auth_score += 0.3;
            indicators.push("DKIM fail".into());
        }
        if dmarc == AuthStatus::Fail {
            auth_score += 0.3;
            indicators.push("DMARC fail".into());
        }

        AuthResults {
            spf,
            dkim,
            dmarc,
            auth_score: auth_score.min(1.0),
        }
    }

    fn check_sender_mismatch(input: &EmailInput, indicators: &mut Vec<String>) -> bool {
        let from_domain = extract_domain(&input.from);

        let reply_mismatch = input
            .reply_to
            .as_ref()
            .map(|r| extract_domain(r) != from_domain)
            .unwrap_or(false);

        let return_mismatch = input
            .return_path
            .as_ref()
            .map(|r| extract_domain(r) != from_domain)
            .unwrap_or(false);

        if reply_mismatch {
            indicators.push(format!(
                "Reply-To domain differs from From ({})",
                input.reply_to.as_deref().unwrap_or("?")
            ));
        }
        if return_mismatch {
            indicators.push(format!(
                "Return-Path domain differs from From ({})",
                input.return_path.as_deref().unwrap_or("?")
            ));
        }

        reply_mismatch || return_mismatch
    }

    fn check_sender_domains(input: &EmailInput, indicators: &mut Vec<String>) -> f32 {
        let from_domain = extract_domain(&input.from);
        let mut score = 0.0_f32;
        let mut seen = std::collections::HashSet::new();

        for domain in [
            Some(from_domain.clone()),
            input.reply_to.as_ref().map(|value| extract_domain(value)),
            input
                .return_path
                .as_ref()
                .map(|value| extract_domain(value)),
        ]
        .into_iter()
        .flatten()
        {
            if domain.is_empty() || !seen.insert(domain.clone()) {
                continue;
            }

            if domain.contains("xn--") {
                score += 0.3;
                indicators.push(format!("punycode sender domain: {domain}"));
            }
            if SUSPICIOUS_TLDS.iter().any(|tld| domain.ends_with(tld)) {
                score += 0.2;
                indicators.push(format!("sender domain uses suspicious TLD: {domain}"));
            }
            if has_homoglyphs(&domain) {
                score += 0.35;
                indicators.push(format!(
                    "sender domain contains possible homoglyphs: {domain}"
                ));
            }
            if domain.chars().all(|c| c.is_ascii_digit() || c == '.')
                && domain.split('.').count() == 4
            {
                score += 0.25;
                indicators.push(format!("sender domain is an IP literal: {domain}"));
            }
        }

        if let Some(message_id_domain) = input.message_id.as_deref().map(extract_domain) {
            if !from_domain.is_empty()
                && !message_id_domain.is_empty()
                && message_id_domain != from_domain
            {
                score += 0.15;
                indicators.push(format!(
                    "Message-ID domain differs from From ({message_id_domain})"
                ));
            }
        }

        score.min(1.0)
    }

    fn analyze_urls(body: &str, indicators: &mut Vec<String>) -> Vec<UrlFinding> {
        let mut findings = Vec::new();

        for url in extract_urls(body) {
            let mut risk = 0.0_f32;
            let mut url_indicators = Vec::new();

            // Check URL shorteners
            if URL_SHORTENERS.iter().any(|s| url.contains(s)) {
                risk += 0.3;
                url_indicators.push("URL shortener".into());
            }

            // Check suspicious TLDs
            if SUSPICIOUS_TLDS
                .iter()
                .any(|t| url.ends_with(t) || url.contains(&format!("{t}/")))
            {
                risk += 0.3;
                url_indicators.push("suspicious TLD".into());
            }

            // Homoglyph detection (mixed scripts/lookalikes)
            if has_homoglyphs(&url) {
                risk += 0.5;
                url_indicators.push("possible homoglyph domain".into());
            }

            // IP address in URL
            if url.contains("://") && url_host_is_ip(&url) {
                risk += 0.3;
                url_indicators.push("IP address in URL".into());
            }

            if risk > 0.0 {
                indicators.extend(url_indicators.iter().cloned());
                findings.push(UrlFinding {
                    url,
                    risk_score: risk.min(1.0),
                    indicators: url_indicators,
                });
            }
        }

        findings
    }

    fn analyze_attachments(
        attachments: &[AttachmentInfo],
        indicators: &mut Vec<String>,
    ) -> Vec<AttachmentFinding> {
        let mut findings = Vec::new();

        for att in attachments {
            let mut risk = 0.0_f32;
            let mut att_indicators = Vec::new();
            let lower = att.filename.to_lowercase();

            // Double extension (e.g., report.pdf.exe)
            let dots: Vec<_> = lower.match_indices('.').collect();
            if dots.len() >= 2 {
                if let Some(&(last_dot_pos, _)) = dots.last() {
                    let last_ext = &lower[last_dot_pos..];
                    if DANGEROUS_EXTENSIONS.contains(&last_ext) {
                        risk += 0.8;
                        att_indicators
                            .push("double extension with dangerous final extension".into());
                    }
                }
            }

            // Dangerous extension
            if DANGEROUS_EXTENSIONS.iter().any(|e| lower.ends_with(e)) {
                risk += 0.6;
                att_indicators.push(format!(
                    "dangerous extension: {}",
                    lower.rsplit('.').next().unwrap_or("")
                ));
            }

            // Macro-enabled Office
            if MACRO_FORMATS.iter().any(|e| lower.ends_with(e)) {
                risk += 0.4;
                att_indicators.push("macro-enabled Office format".into());
            }

            // Archive that might contain executables
            if lower.ends_with(".zip")
                || lower.ends_with(".rar")
                || lower.ends_with(".7z")
                || lower.ends_with(".iso")
            {
                risk += 0.2;
                att_indicators.push("archive attachment (may contain executables)".into());
            }

            if risk > 0.0 || !att_indicators.is_empty() {
                indicators.extend(att_indicators.iter().cloned());
                findings.push(AttachmentFinding {
                    filename: att.filename.clone(),
                    content_type: att.content_type.clone(),
                    sha256: att.sha256.clone(),
                    risk_score: risk.min(1.0),
                    indicators: att_indicators,
                });
            }
        }

        findings
    }

    fn urgency_score(subject: &str, indicators: &mut Vec<String>) -> f32 {
        let lower = subject.to_lowercase();
        let mut score = 0.0_f32;

        for &(keyword, weight) in URGENCY_KEYWORDS {
            if lower.contains(keyword) {
                score += weight;
                indicators.push(format!("urgency keyword: \"{keyword}\""));
            }
        }

        // ALL CAPS subject
        if subject.len() > 10
            && subject
                .chars()
                .filter(|c| c.is_alphabetic())
                .all(|c| c.is_uppercase())
        {
            score += 0.2;
            indicators.push("ALL CAPS subject".into());
        }

        // Excessive punctuation
        let excl = subject.matches('!').count();
        if excl >= 3 {
            score += 0.15;
            indicators.push(format!("{excl} exclamation marks"));
        }

        score.min(1.0)
    }

    fn check_received_chain(chain: &[String], indicators: &mut Vec<String>) {
        // Too many hops may indicate relaying through open relays
        if chain.len() > 8 {
            indicators.push(format!(
                "{} hops in Received chain (possible relay abuse)",
                chain.len()
            ));
        }
    }

    fn compute_phishing_score(
        auth: &AuthResults,
        sender_mismatch: bool,
        urls: &[UrlFinding],
        attachments: &[AttachmentFinding],
        urgency: f32,
        sender_domain_score: f32,
    ) -> f32 {
        let auth_component = auth.auth_score * 0.22;
        let mismatch_component = if sender_mismatch { 0.14 } else { 0.0 };
        let sender_component = sender_domain_score * 0.2;
        let url_component = urls.iter().map(|u| u.risk_score).sum::<f32>().min(1.0) * 0.2;
        let attachment_component = attachments
            .iter()
            .map(|a| a.risk_score)
            .sum::<f32>()
            .min(1.0)
            * 0.18;
        let urgency_component = urgency * 0.12;

        (auth_component
            + mismatch_component
            + sender_component
            + url_component
            + attachment_component
            + urgency_component)
            .min(1.0)
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn extract_domain(email_or_addr: &str) -> String {
    let s = email_or_addr
        .trim()
        .trim_start_matches('<')
        .trim_end_matches('>');
    s.rsplit('@').next().unwrap_or(s).to_lowercase()
}

fn extract_urls(text: &str) -> Vec<String> {
    let mut urls = Vec::new();
    for word in text.split_whitespace() {
        let trimmed = word.trim_matches(|c: char| c == '<' || c == '>' || c == '"' || c == '\'');
        if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            urls.push(trimmed.to_string());
        }
    }
    urls
}

fn has_homoglyphs(url: &str) -> bool {
    // Check for Cyrillic/Greek lookalikes in domain portion
    let domain_part = url
        .split("://")
        .nth(1)
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or("");
    domain_part.chars().any(|c| {
        matches!(c,
            '\u{0430}'..='\u{044F}' | // Cyrillic lowercase
            '\u{0410}'..='\u{042F}' | // Cyrillic uppercase
            '\u{0391}'..='\u{03C9}'   // Greek
        )
    })
}

fn url_host_is_ip(url: &str) -> bool {
    let host = url
        .split("://")
        .nth(1)
        .unwrap_or("")
        .split('/')
        .next()
        .unwrap_or("");
    let host = host.split(':').next().unwrap_or(host); // strip port
    host.chars().all(|c| c.is_ascii_digit() || c == '.') && host.split('.').count() == 4
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_input(from: &str, subject: &str, auth: &str) -> EmailInput {
        EmailInput {
            from: from.into(),
            reply_to: None,
            return_path: None,
            to: Some("victim@example.com".into()),
            subject: Some(subject.into()),
            received_chain: vec![],
            authentication_results: Some(auth.into()),
            body_text: None,
            body_html: None,
            attachments: vec![],
            message_id: Some("test@msg".into()),
        }
    }

    #[test]
    fn spf_fail_flagged() {
        let input = make_input("attacker@evil.com", "Hello", "spf=fail; dkim=none");
        let report = EmailAnalyzer::analyze(&input);
        assert_eq!(report.auth_results.spf, AuthStatus::Fail);
        assert!(report.phishing_score > 0.0);
    }

    #[test]
    fn sender_mismatch_detected() {
        let mut input = make_input("ceo@company.com", "Urgent", "spf=pass");
        input.reply_to = Some("attacker@evil.tk".into());
        let report = EmailAnalyzer::analyze(&input);
        assert!(report.sender_mismatch);
    }

    #[test]
    fn dangerous_attachment_flagged() {
        let mut input = make_input("sender@test.com", "Invoice", "spf=pass");
        input.attachments.push(AttachmentInfo {
            filename: "invoice.pdf.exe".into(),
            content_type: None,
            sha256: None,
            size_bytes: None,
        });
        let report = EmailAnalyzer::analyze(&input);
        assert!(!report.attachment_findings.is_empty());
        assert!(report.attachment_findings[0].risk_score > 0.5);
    }

    #[test]
    fn urgency_keywords_scored() {
        let input = make_input(
            "bank@phishing.com",
            "URGENT: Verify your account immediately!",
            "spf=fail",
        );
        let report = EmailAnalyzer::analyze(&input);
        assert!(report.urgency_score > 0.3);
    }

    #[test]
    fn legitimate_email_low_score() {
        let input = make_input(
            "colleague@company.com",
            "Meeting notes",
            "spf=pass; dkim=pass; dmarc=pass",
        );
        let report = EmailAnalyzer::analyze(&input);
        assert!(
            report.phishing_score < 0.1,
            "score={}",
            report.phishing_score
        );
    }

    #[test]
    fn attachment_without_dots_does_not_panic() {
        let mut input = make_input("user@example.com", "File attached", "spf=pass");
        input.attachments.push(AttachmentInfo {
            filename: "README".into(),
            content_type: Some("application/octet-stream".into()),
            sha256: None,
            size_bytes: Some(100),
        });
        // Should not panic even though filename has no dots
        let report = EmailAnalyzer::analyze(&input);
        assert!(report.phishing_score >= 0.0);
    }

    #[test]
    fn double_extension_detected() {
        let mut input = make_input("attacker@phish.com", "Invoice", "");
        input.attachments.push(AttachmentInfo {
            filename: "invoice.pdf.exe".into(),
            content_type: Some("application/octet-stream".into()),
            sha256: None,
            size_bytes: Some(500),
        });
        let report = EmailAnalyzer::analyze(&input);
        assert!(!report.attachment_findings.is_empty());
        assert!(report.attachment_findings[0].risk_score > 0.5);
    }

    #[test]
    fn suspicious_sender_domain_is_scored() {
        let input = make_input(
            "security@micr0soft-support.top",
            "Security alert",
            "spf=pass",
        );
        let report = EmailAnalyzer::analyze(&input);
        assert!(
            report.phishing_score > 0.1,
            "score={}",
            report.phishing_score
        );
        assert!(
            report
                .indicators
                .iter()
                .any(|indicator| indicator.contains("suspicious TLD"))
        );
    }

    #[test]
    fn message_id_domain_mismatch_is_flagged() {
        let mut input = make_input(
            "alerts@company.com",
            "Quarterly report",
            "spf=pass; dkim=pass",
        );
        input.message_id = Some("<12345@mailer.evil.example>".into());
        let report = EmailAnalyzer::analyze(&input);
        assert!(
            report
                .indicators
                .iter()
                .any(|indicator| indicator.contains("Message-ID domain differs"))
        );
    }
}
