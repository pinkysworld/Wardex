//! Alert auto-analysis engine: pattern classification, temporal clustering,
//! score-trend detection, alert grouping, and operator summary generation.

use crate::collector::AlertRecord;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Result types ─────────────────────────────────────────────────────

/// Classification of the overall alert pattern in a time window.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertPattern {
    /// Normal baseline with no significant spikes.
    Baseline,
    /// Periodic bursts of elevated activity.
    PeriodicBursts {
        avg_interval_secs: f64,
        burst_severity: String,
    },
    /// Steadily increasing scores over time.
    Escalating,
    /// Sustained high-severity activity.
    Sustained { severity: String },
    /// Mixed pattern that doesn't fit a single classification.
    Mixed,
}

/// Direction and magnitude of the score trend.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScoreTrend {
    Stable,
    Rising { slope: f64 },
    Falling { slope: f64 },
    Volatile,
}

/// A cluster of temporally adjacent alerts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertCluster {
    pub start: String,
    pub end: String,
    pub count: usize,
    pub avg_score: f64,
    pub max_score: f64,
    pub representative_reasons: Vec<String>,
    pub level: String,
}

/// An outlier alert that deviates significantly from the mean.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertAnomaly {
    pub index: usize,
    pub timestamp: String,
    pub score: f64,
    pub reasons: Vec<String>,
    pub deviation_from_mean: f64,
}

/// Full analysis result for a time window of alerts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertAnalysis {
    pub window_start: String,
    pub window_end: String,
    pub total_alerts: usize,
    pub pattern: AlertPattern,
    pub score_trend: ScoreTrend,
    pub dominant_reasons: Vec<(String, usize)>,
    pub clusters: Vec<AlertCluster>,
    pub anomalies: Vec<AlertAnomaly>,
    pub severity_breakdown: SeverityBreakdown,
    pub isolation_guidance: Vec<IsolationGuidance>,
    pub summary: String,
}

/// Counts by severity level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityBreakdown {
    pub critical: usize,
    pub severe: usize,
    pub elevated: usize,
}

/// Per-reason isolation and remediation guidance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationGuidance {
    pub reason: String,
    pub threat_description: String,
    pub steps: Vec<String>,
}

/// A group of alerts sharing the same reason fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertGroup {
    pub id: usize,
    pub first_seen: String,
    pub last_seen: String,
    pub count: usize,
    pub avg_score: f64,
    pub max_score: f64,
    pub level: String,
    pub reason_fingerprint: String,
    pub representative_reasons: Vec<String>,
    pub indices: Vec<usize>,
}

// ── Alert deduplication ──────────────────────────────────────────────

/// A deduplicated incident created by merging related alerts within a
/// configurable time window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DedupIncident {
    pub incident_id: String,
    pub first_seen: String,
    pub last_seen: String,
    pub alert_count: usize,
    pub merged_alert_ids: Vec<usize>,
    pub device_ids: Vec<String>,
    pub level: String,
    pub representative_reasons: Vec<String>,
    pub avg_score: f64,
    pub max_score: f64,
    pub fingerprint: String,
}

/// Deduplication configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DedupConfig {
    /// Time window (seconds) within which similar alerts are merged.
    pub window_secs: u64,
    /// Whether to merge across different devices.
    pub cross_device: bool,
    /// Maximum number of alerts per incident before splitting.
    pub max_merge: usize,
}

impl Default for DedupConfig {
    fn default() -> Self {
        Self {
            window_secs: 300, // 5 minutes
            cross_device: false,
            max_merge: 100,
        }
    }
}

/// Deduplicate and merge related alerts into incidents.
pub fn deduplicate_alerts(alerts: &[AlertRecord], config: &DedupConfig) -> Vec<DedupIncident> {
    if alerts.is_empty() {
        return Vec::new();
    }

    // Build fingerprint → groups, optionally scoped by device.
    let mut buckets: HashMap<String, Vec<(usize, &AlertRecord)>> = HashMap::new();
    for (i, a) in alerts.iter().enumerate() {
        let fp = reason_fingerprint(a);
        let key = if config.cross_device {
            fp
        } else {
            format!("{}@{}", fp, a.hostname)
        };
        buckets.entry(key).or_default().push((i, a));
    }

    let mut incidents: Vec<DedupIncident> = Vec::new();
    let mut incident_counter = 0_usize;

    for (fp, members) in &mut buckets {
        members.sort_by(|a, b| a.1.timestamp.cmp(&b.1.timestamp));
        // Within each fingerprint bucket, split by time-window gaps.
        let mut window: Vec<(usize, &AlertRecord)> = Vec::new();

        for &(idx, alert) in members.iter() {
            if let Some(last) = window.last() {
                let gap = timestamp_gap(&last.1.timestamp, &alert.timestamp);
                if gap > config.window_secs as f64 || window.len() >= config.max_merge {
                    // Flush current window as an incident.
                    incidents.push(build_incident(incident_counter, fp, &window));
                    incident_counter += 1;
                    window.clear();
                }
            }
            window.push((idx, alert));
        }
        if !window.is_empty() {
            incidents.push(build_incident(incident_counter, fp, &window));
            incident_counter += 1;
        }
    }

    // Sort most recent first.
    incidents.sort_by_key(|b| std::cmp::Reverse(b.last_seen.clone()));
    incidents
}

fn build_incident(id: usize, fp: &str, members: &[(usize, &AlertRecord)]) -> DedupIncident {
    let scores: Vec<f64> = members.iter().map(|(_, a)| a.score as f64).collect();
    let avg = scores.iter().sum::<f64>() / scores.len().max(1) as f64;
    let max = scores.iter().cloned().fold(0.0_f64, f64::max);
    let levels: Vec<&str> = members.iter().map(|(_, a)| a.level.as_str()).collect();
    let mut device_ids: Vec<String> = members.iter().map(|(_, a)| a.hostname.clone()).collect();
    device_ids.sort();
    device_ids.dedup();

    DedupIncident {
        incident_id: format!("INC-{id:04}"),
        first_seen: members
            .first()
            .map(|(_, a)| a.timestamp.clone())
            .unwrap_or_default(),
        last_seen: members
            .last()
            .map(|(_, a)| a.timestamp.clone())
            .unwrap_or_default(),
        alert_count: members.len(),
        merged_alert_ids: members.iter().map(|(i, _)| *i).collect(),
        device_ids,
        level: highest_level(&levels),
        representative_reasons: members
            .first()
            .map(|(_, a)| a.reasons.clone())
            .unwrap_or_default(),
        avg_score: (avg * 100.0).round() / 100.0,
        max_score: (max * 100.0).round() / 100.0,
        fingerprint: fp.to_string(),
    }
}

fn timestamp_gap(a: &str, b: &str) -> f64 {
    let parse = |s: &str| {
        chrono::DateTime::parse_from_rfc3339(s)
            .map(|dt| dt.timestamp() as f64)
            .unwrap_or(f64::NAN)
    };
    let ta = parse(a);
    let tb = parse(b);
    if ta.is_nan() || tb.is_nan() {
        return f64::MAX;
    }
    (tb - ta).abs()
}

// ── Public API ───────────────────────────────────────────────────────

/// Run analysis over a slice of alerts within a given window (minutes).
/// If `window_minutes` is 0, analyse all supplied alerts.
pub fn analyze_alerts(alerts: &[AlertRecord], window_minutes: u64) -> AlertAnalysis {
    let mut filtered = if window_minutes == 0 || alerts.is_empty() {
        alerts.to_vec()
    } else {
        let cutoff = chrono::Utc::now() - chrono::Duration::minutes(window_minutes as i64);
        let cutoff_str = cutoff.to_rfc3339();
        alerts
            .iter()
            .filter(|a| a.timestamp >= cutoff_str)
            .cloned()
            .collect::<Vec<_>>()
    };

    // Sort by timestamp to ensure correct gap-based clustering
    filtered.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    if filtered.is_empty() {
        return AlertAnalysis {
            window_start: String::new(),
            window_end: String::new(),
            total_alerts: 0,
            pattern: AlertPattern::Baseline,
            score_trend: ScoreTrend::Stable,
            dominant_reasons: Vec::new(),
            clusters: Vec::new(),
            anomalies: Vec::new(),
            severity_breakdown: SeverityBreakdown {
                critical: 0,
                severe: 0,
                elevated: 0,
            },
            isolation_guidance: Vec::new(),
            summary: "No alerts in the selected window.".into(),
        };
    }

    let window_start = filtered
        .first()
        .map(|a| a.timestamp.clone())
        .unwrap_or_default();
    let window_end = filtered
        .last()
        .map(|a| a.timestamp.clone())
        .unwrap_or_default();
    let severity_breakdown = compute_severity(&filtered);
    let dominant_reasons = compute_reason_histogram(&filtered);
    let clusters = compute_clusters(&filtered, 30.0);
    let anomalies = compute_anomalies(&filtered);
    let score_trend = compute_trend(&filtered);
    let pattern = classify_pattern(&filtered, &clusters, &score_trend, &severity_breakdown);
    let summary = generate_summary(
        &filtered,
        &pattern,
        &score_trend,
        &dominant_reasons,
        &clusters,
        &anomalies,
        &severity_breakdown,
    );
    let isolation_guidance = generate_isolation_guidance(&dominant_reasons);

    AlertAnalysis {
        window_start,
        window_end,
        total_alerts: filtered.len(),
        pattern,
        score_trend,
        dominant_reasons,
        clusters,
        anomalies,
        severity_breakdown,
        isolation_guidance,
        summary,
    }
}

/// Group alerts by their reason-set fingerprint (sorted reasons + level).
pub fn group_alerts(alerts: &[AlertRecord]) -> Vec<AlertGroup> {
    let mut map: HashMap<String, Vec<(usize, &AlertRecord)>> = HashMap::new();
    for (i, a) in alerts.iter().enumerate() {
        let fp = reason_fingerprint(a);
        map.entry(fp).or_default().push((i, a));
    }

    let mut groups: Vec<AlertGroup> = map
        .into_iter()
        .enumerate()
        .map(|(gid, (fp, mut members))| {
            // Sort members by timestamp so first_seen/last_seen are accurate
            members.sort_by(|(_, a), (_, b)| a.timestamp.cmp(&b.timestamp));
            let count = members.len();
            let first_seen = members
                .first()
                .map(|(_, a)| a.timestamp.clone())
                .unwrap_or_default();
            let last_seen = members
                .last()
                .map(|(_, a)| a.timestamp.clone())
                .unwrap_or_default();
            let scores: Vec<f64> = members.iter().map(|(_, a)| a.score as f64).collect();
            let avg_score = scores.iter().sum::<f64>() / count as f64;
            let max_score = scores.iter().cloned().fold(0.0_f64, f64::max);
            let level = highest_level(
                &members
                    .iter()
                    .map(|(_, a)| a.level.as_str())
                    .collect::<Vec<_>>(),
            );
            let representative_reasons = members
                .first()
                .map(|(_, a)| a.reasons.clone())
                .unwrap_or_default();
            let indices = members.iter().map(|(i, _)| *i).collect();

            AlertGroup {
                id: gid,
                first_seen,
                last_seen,
                count,
                avg_score,
                max_score,
                level,
                reason_fingerprint: fp,
                representative_reasons,
                indices,
            }
        })
        .collect();

    // Sort by most recent first, then by count descending
    groups.sort_by(|a, b| b.last_seen.cmp(&a.last_seen).then(b.count.cmp(&a.count)));
    // Reassign IDs after sort
    for (i, g) in groups.iter_mut().enumerate() {
        g.id = i;
    }
    groups
}

// ── Internal helpers ─────────────────────────────────────────────────

fn reason_fingerprint(alert: &AlertRecord) -> String {
    let mut reasons = alert.reasons.clone();
    // Normalise numeric suffixes for grouping — e.g. "network burst (+3731.88)" → "network burst"
    for r in &mut reasons {
        if let Some(paren) = r.find(" (+") {
            r.truncate(paren);
        }
        if let Some(paren) = r.find(" (-") {
            r.truncate(paren);
        }
    }
    reasons.sort();
    format!("{}:{}", alert.level, reasons.join("|"))
}

fn compute_severity(alerts: &[AlertRecord]) -> SeverityBreakdown {
    SeverityBreakdown {
        critical: alerts.iter().filter(|a| a.level == "Critical").count(),
        severe: alerts.iter().filter(|a| a.level == "Severe").count(),
        elevated: alerts.iter().filter(|a| a.level == "Elevated").count(),
    }
}

fn compute_reason_histogram(alerts: &[AlertRecord]) -> Vec<(String, usize)> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for a in alerts {
        for r in &a.reasons {
            // Normalise numeric values for counting
            let key = if let Some(paren) = r.find(" (+") {
                r[..paren].to_string()
            } else if let Some(paren) = r.find(" (-") {
                r[..paren].to_string()
            } else {
                r.clone()
            };
            *counts.entry(key).or_default() += 1;
        }
    }
    let mut sorted: Vec<(String, usize)> = counts.into_iter().collect();
    sorted.sort_by_key(|b| std::cmp::Reverse(b.1));
    sorted.truncate(10);
    sorted
}

/// Gap-based temporal clustering: consecutive alerts within `gap_secs` of
/// each other are merged into a cluster.
fn compute_clusters(alerts: &[AlertRecord], gap_secs: f64) -> Vec<AlertCluster> {
    if alerts.is_empty() {
        return Vec::new();
    }

    let timestamps = parse_timestamps(alerts);
    let mut clusters: Vec<Vec<usize>> = Vec::new();
    let mut current: Vec<usize> = vec![0];

    for i in 1..alerts.len() {
        let gap = (timestamps[i] - timestamps[i - 1]).abs();
        if gap <= gap_secs {
            current.push(i);
        } else {
            clusters.push(std::mem::take(&mut current));
            current = vec![i];
        }
    }
    if !current.is_empty() {
        clusters.push(current);
    }

    clusters
        .into_iter()
        .filter(|c| c.len() >= 2) // Only clusters with ≥2 alerts
        .map(|indices| {
            let subset: Vec<&AlertRecord> = indices.iter().map(|&i| &alerts[i]).collect();
            let scores: Vec<f64> = subset.iter().map(|a| a.score as f64).collect();
            let avg = scores.iter().sum::<f64>() / scores.len() as f64;
            let max = scores.iter().cloned().fold(0.0_f64, f64::max);
            let levels: Vec<&str> = subset.iter().map(|a| a.level.as_str()).collect();
            let top_reason =
                compute_reason_histogram(&subset.iter().copied().cloned().collect::<Vec<_>>())
                    .into_iter()
                    .take(3)
                    .map(|(r, _)| r)
                    .collect();

            AlertCluster {
                start: subset
                    .first()
                    .map(|a| a.timestamp.clone())
                    .unwrap_or_default(),
                end: subset
                    .last()
                    .map(|a| a.timestamp.clone())
                    .unwrap_or_default(),
                count: subset.len(),
                avg_score: (avg * 100.0).round() / 100.0,
                max_score: (max * 100.0).round() / 100.0,
                representative_reasons: top_reason,
                level: highest_level(&levels),
            }
        })
        .collect()
}

fn compute_anomalies(alerts: &[AlertRecord]) -> Vec<AlertAnomaly> {
    if alerts.len() < 3 {
        return Vec::new();
    }
    let scores: Vec<f64> = alerts.iter().map(|a| a.score as f64).collect();
    let mean = scores.iter().sum::<f64>() / scores.len() as f64;
    let variance = scores.iter().map(|s| (s - mean).powi(2)).sum::<f64>() / scores.len() as f64;
    let std_dev = variance.sqrt();
    if std_dev < 0.01 {
        return Vec::new();
    }

    let threshold = 2.0; // 2 standard deviations
    let mut anomalies: Vec<AlertAnomaly> = Vec::new();
    for (i, a) in alerts.iter().enumerate() {
        let deviation = (a.score as f64 - mean) / std_dev;
        if deviation.abs() >= threshold {
            anomalies.push(AlertAnomaly {
                index: i,
                timestamp: a.timestamp.clone(),
                score: a.score as f64,
                reasons: a.reasons.clone(),
                deviation_from_mean: (deviation * 100.0).round() / 100.0,
            });
        }
    }
    anomalies
}

/// Simple linear regression on scores (x = index, y = score).
fn compute_trend(alerts: &[AlertRecord]) -> ScoreTrend {
    if alerts.len() < 3 {
        return ScoreTrend::Stable;
    }
    let n = alerts.len() as f64;
    let scores: Vec<f64> = alerts.iter().map(|a| a.score as f64).collect();
    let mean_x = (n - 1.0) / 2.0;
    let mean_y = scores.iter().sum::<f64>() / n;

    let mut num = 0.0;
    let mut den = 0.0;
    for (i, &y) in scores.iter().enumerate() {
        let x = i as f64;
        num += (x - mean_x) * (y - mean_y);
        den += (x - mean_x).powi(2);
    }
    if den.abs() < 1e-9 {
        return ScoreTrend::Stable;
    }
    let slope = num / den;

    // Check volatility: coefficient of variation
    let variance = scores.iter().map(|s| (s - mean_y).powi(2)).sum::<f64>() / n;
    let cv = if mean_y.abs() > 0.01 {
        variance.sqrt() / mean_y.abs()
    } else {
        0.0
    };
    if cv > 0.5 {
        return ScoreTrend::Volatile;
    }

    let slope_rounded = (slope * 1000.0).round() / 1000.0;
    if slope_rounded > 0.01 {
        ScoreTrend::Rising {
            slope: slope_rounded,
        }
    } else if slope_rounded < -0.01 {
        ScoreTrend::Falling {
            slope: slope_rounded,
        }
    } else {
        ScoreTrend::Stable
    }
}

fn classify_pattern(
    alerts: &[AlertRecord],
    clusters: &[AlertCluster],
    trend: &ScoreTrend,
    severity: &SeverityBreakdown,
) -> AlertPattern {
    let total = alerts.len();
    if total == 0 {
        return AlertPattern::Baseline;
    }

    // All elevated, low variation → Baseline
    let high_sev = severity.critical + severity.severe;
    if high_sev == 0 {
        return AlertPattern::Baseline;
    }

    // Clear upward trend (check before sustained – escalation is a stronger signal)
    // Only classify as escalating if early alerts are NOT already mostly severe
    if matches!(trend, ScoreTrend::Rising { slope } if *slope > 0.05) {
        let first_half = &alerts[..total / 2];
        let early_high = first_half
            .iter()
            .filter(|a| a.level == "Severe" || a.level == "Critical")
            .count();
        if (early_high as f64 / first_half.len().max(1) as f64) < 0.5 {
            return AlertPattern::Escalating;
        }
    }

    // Mostly high-severity and sustained
    if high_sev as f64 / total as f64 > 0.6 {
        let dominant = if severity.critical > severity.severe {
            "Critical"
        } else {
            "Severe"
        };
        return AlertPattern::Sustained {
            severity: dominant.into(),
        };
    }

    // Distinct clusters with gaps → PeriodicBursts
    if clusters.len() >= 2 {
        let timestamps = parse_timestamps(alerts);
        let cluster_starts: Vec<f64> = clusters
            .iter()
            .filter_map(|c| {
                chrono::DateTime::parse_from_rfc3339(&c.start)
                    .ok()
                    .map(|dt| dt.timestamp() as f64)
            })
            .collect();
        if cluster_starts.len() >= 2 {
            let intervals: Vec<f64> = cluster_starts.windows(2).map(|w| w[1] - w[0]).collect();
            let avg_interval = intervals.iter().sum::<f64>() / intervals.len() as f64;
            let _ = timestamps; // consumed above
            let burst_sev = highest_level(
                &clusters
                    .iter()
                    .map(|c| c.level.as_str())
                    .collect::<Vec<_>>(),
            );
            return AlertPattern::PeriodicBursts {
                avg_interval_secs: (avg_interval * 10.0).round() / 10.0,
                burst_severity: burst_sev,
            };
        }
    }

    AlertPattern::Mixed
}

fn generate_summary(
    alerts: &[AlertRecord],
    pattern: &AlertPattern,
    trend: &ScoreTrend,
    dominant_reasons: &[(String, usize)],
    clusters: &[AlertCluster],
    anomalies: &[AlertAnomaly],
    severity: &SeverityBreakdown,
) -> String {
    let total = alerts.len();
    let mut parts: Vec<String> = Vec::new();

    // Pattern description
    match pattern {
        AlertPattern::Baseline => {
            parts.push(format!(
                "{total} alerts observed in baseline state — no high-severity activity detected."
            ));
        }
        AlertPattern::PeriodicBursts {
            avg_interval_secs,
            burst_severity,
        } => {
            parts.push(format!(
                "{total} alerts with periodic {burst_severity}-severity bursts averaging {avg_interval_secs:.0}s apart."
            ));
        }
        AlertPattern::Escalating => {
            parts.push(format!(
                "{total} alerts with escalating score trend — possible ongoing attack."
            ));
        }
        AlertPattern::Sustained { severity: sev } => {
            parts.push(format!(
                "{total} alerts showing sustained {sev}-severity activity."
            ));
        }
        AlertPattern::Mixed => {
            parts.push(format!("{total} alerts with mixed severity patterns."));
        }
    }

    // Severity breakdown
    if severity.critical > 0 || severity.severe > 0 {
        parts.push(format!(
            "Severity breakdown: {} critical, {} severe, {} elevated.",
            severity.critical, severity.severe, severity.elevated
        ));
    }

    // Trend
    match trend {
        ScoreTrend::Rising { slope } => {
            parts.push(format!(
                "Scores are rising (slope {slope:+.3} per sample) — investigate immediately."
            ));
        }
        ScoreTrend::Volatile => {
            parts.push("Score volatility is high — intermittent anomaly activity.".into());
        }
        ScoreTrend::Falling { slope } => {
            parts.push(format!(
                "Scores are declining (slope {slope:+.3}) — threat may be subsiding."
            ));
        }
        ScoreTrend::Stable => {}
    }

    // Top reasons
    if let Some((top, count)) = dominant_reasons.first() {
        parts.push(format!(
            "Top detection reason: \"{top}\" ({count} occurrences)."
        ));
    }

    // Clusters
    if !clusters.is_empty() {
        parts.push(format!(
            "{} temporal cluster(s) identified; largest contains {} alerts.",
            clusters.len(),
            clusters.iter().map(|c| c.count).max().unwrap_or(0)
        ));
    }

    // Anomalies
    if !anomalies.is_empty() {
        let top = &anomalies[0];
        parts.push(format!(
            "{} outlier alert(s); highest deviation: score {:.2} ({:+.1}σ from mean).",
            anomalies.len(),
            top.score,
            top.deviation_from_mean
        ));
    }

    parts.join(" ")
}

fn generate_isolation_guidance(dominant_reasons: &[(String, usize)]) -> Vec<IsolationGuidance> {
    let mut guidance = Vec::new();

    for (reason, _count) in dominant_reasons {
        let r = reason.to_lowercase();
        let g = if r.contains("network burst") {
            IsolationGuidance {
                reason: reason.clone(),
                threat_description: "Abnormal network traffic spike detected — may indicate data exfiltration, C2 communication, lateral movement, or a DDoS amplification attack.".into(),
                steps: vec![
                    "Isolate the affected host from the network or move to a quarantine VLAN.".into(),
                    "Capture a packet trace (tcpdump/Wireshark) on the host to identify destination IPs and protocols.".into(),
                    "Check firewall and proxy logs for connections to known-bad IPs or unusual ports.".into(),
                    "Review running processes for unexpected network-capable binaries (netstat -tlnp / lsof -i).".into(),
                    "If exfiltration is suspected, disable the host's internet access immediately and preserve forensic evidence.".into(),
                    "Cross-reference destination IPs with threat intelligence feeds.".into(),
                ],
            }
        } else if r.contains("auth failures surge") || r.contains("auth_failures") {
            IsolationGuidance {
                reason: reason.clone(),
                threat_description: "Spike in authentication failures — may indicate brute-force attack, credential stuffing, or compromised credential reuse attempts.".into(),
                steps: vec![
                    "Temporarily lock the targeted accounts and enforce password resets.".into(),
                    "Enable or strengthen rate-limiting on authentication endpoints.".into(),
                    "Review source IPs of failed attempts for known-bad actors.".into(),
                    "Check for successful logins from the same source IPs (potential breach indicator).".into(),
                    "Enable MFA on all affected accounts if not already enabled.".into(),
                    "Consider geofencing or IP-blocking if attempts originate from unexpected regions.".into(),
                ],
            }
        } else if r.contains("integrity drift") {
            IsolationGuidance {
                reason: reason.clone(),
                threat_description: "File integrity drift detected — critical system files may have been modified, indicating rootkit installation, malware persistence, or unauthorized configuration changes.".into(),
                steps: vec![
                    "Immediately isolate the host from production networks.".into(),
                    "Run a full file integrity check against known-good baselines.".into(),
                    "Compare modified files with original versions to identify nature of changes.".into(),
                    "Check for new cron jobs, startup items, systemd services, or scheduled tasks.".into(),
                    "Scan for rootkits (rkhunter, chkrootkit, OSSEC).".into(),
                    "If compromise is confirmed, re-image the host from a trusted golden image.".into(),
                ],
            }
        } else if r.contains("process count spike") || r.contains("process_count") {
            IsolationGuidance {
                reason: reason.clone(),
                threat_description: "Unusual increase in running processes — may indicate fork bomb, crypto-miner deployment, malware spawning child processes, or lateral movement tooling.".into(),
                steps: vec![
                    "List all processes with their parent PIDs to identify the spawning chain (ps auxf / pstree).".into(),
                    "Kill suspicious process trees and note their binary paths for forensic analysis.".into(),
                    "Check for unknown executables in /tmp, /dev/shm, or user home directories.".into(),
                    "Review process memory maps for injected code or suspicious shared libraries.".into(),
                    "If crypto-mining is suspected, check CPU usage patterns and network connections to mining pools.".into(),
                ],
            }
        } else if r.contains("entropy") && r.contains("low_entropy") {
            IsolationGuidance {
                reason: reason.clone(),
                threat_description: "Abnormally low entropy in telemetry dimensions — may indicate steady-state attack traffic (crypto-miner at fixed load), sensor tampering, or replay attacks feeding constant values.".into(),
                steps: vec![
                    "Verify sensor/agent health — constant readings may indicate a stuck or tampered sensor.".into(),
                    "Check if affected metrics (CPU, temperature, battery) are genuinely stable or artificially clamped.".into(),
                    "Look for processes holding CPU at a fixed percentage (common crypto-miner signature).".into(),
                    "On single development hosts, low entropy on battery/temperature is often benign — consider tuning thresholds.".into(),
                    "If tampering is suspected, compare agent-reported values against out-of-band monitoring (IPMI, cloud provider metrics).".into(),
                ],
            }
        } else if r.contains("entropy") && r.contains("high_entropy") {
            IsolationGuidance {
                reason: reason.clone(),
                threat_description: "Abnormally high entropy in authentication metrics — highly randomised failure patterns may indicate automated credential-stuffing or evasion-aware brute-force tools.".into(),
                steps: vec![
                    "Review authentication logs for patterns (rotating usernames, varied passwords).".into(),
                    "Block source IP ranges showing randomised failure patterns.".into(),
                    "Deploy CAPTCHA or proof-of-work challenges on affected auth endpoints.".into(),
                    "Correlate with network burst alerts for complete attack picture.".into(),
                    "Enable account lockout policies with progressive backoff.".into(),
                ],
            }
        } else if r.contains("memory pressure") {
            IsolationGuidance {
                reason: reason.clone(),
                threat_description: "Elevated memory usage — may indicate memory-resident malware, in-memory crypto-mining, or a memory-leak DoS attack.".into(),
                steps: vec![
                    "Identify the top memory consumers (top/htop sorted by RES).".into(),
                    "Check for memory-mapped files or suspicious shared memory segments (ipcs).".into(),
                    "Review OOM-killer logs for repeated victims indicating resource exhaustion attack.".into(),
                    "If a specific process is responsible, dump its memory for forensic analysis before killing.".into(),
                ],
            }
        } else if r.contains("thermal deviation") || r.contains("temperature") {
            IsolationGuidance {
                reason: reason.clone(),
                threat_description: "Unusual temperature increase — sustained compute-intensive operations may indicate crypto-mining, resource abuse, or hardware-level compromise.".into(),
                steps: vec![
                    "Correlate with CPU and process count metrics for the same time window.".into(),
                    "Check for GPU-intensive or CPU-intensive processes that shouldn't be running.".into(),
                    "Verify environmental controls (HVAC) haven't failed, which could cause thermal event.".into(),
                    "If crypto-mining is confirmed, isolate host, terminate miners, and audit deployment vector.".into(),
                ],
            }
        } else if r.contains("disk_pressure") || r.contains("disk pressure") {
            IsolationGuidance {
                reason: reason.clone(),
                threat_description: "Disk pressure increase detected — may indicate ransomware encryption activity, log flooding for evasion, or data staging for exfiltration.".into(),
                steps: vec![
                    "Check for rapid file creation or modification in data directories (find / -mmin -5 -type f).".into(),
                    "Look for file extensions associated with ransomware (.encrypted, .locked, .cry).".into(),
                    "Review disk I/O by process (iotop) to identify the source.".into(),
                    "If ransomware is suspected, immediately disconnect from network and do NOT restart the host.".into(),
                    "Preserve disk state for forensic recovery before any remediation.".into(),
                ],
            }
        } else {
            // Generic guidance for unrecognised reasons
            IsolationGuidance {
                reason: reason.clone(),
                threat_description: format!("Detection trigger: {} — review the affected host for anomalous behaviour.", reason),
                steps: vec![
                    "Correlate this alert with other concurrent detections for a complete threat picture.".into(),
                    "Review host logs, process lists, and network connections for suspicious activity.".into(),
                    "If the alert persists, consider isolating the host pending investigation.".into(),
                    "Escalate to the SOC team if the root cause cannot be determined within 15 minutes.".into(),
                ],
            }
        };
        guidance.push(g);
    }

    guidance
}

fn parse_timestamps(alerts: &[AlertRecord]) -> Vec<f64> {
    alerts
        .iter()
        .map(|a| {
            chrono::DateTime::parse_from_rfc3339(&a.timestamp)
                .map(|dt| dt.timestamp() as f64)
                .unwrap_or(f64::NAN)
        })
        .collect()
}

fn highest_level(levels: &[&str]) -> String {
    if levels.contains(&"Critical") {
        "Critical".into()
    } else if levels.contains(&"Severe") {
        "Severe".into()
    } else {
        "Elevated".into()
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::TelemetrySample;

    fn sample() -> TelemetrySample {
        TelemetrySample {
            timestamp_ms: 1000,
            cpu_load_pct: 50.0,
            memory_load_pct: 40.0,
            temperature_c: 55.0,
            network_kbps: 100.0,
            auth_failures: 0,
            battery_pct: 80.0,
            integrity_drift: 0.0,
            process_count: 100,
            disk_pressure_pct: 20.0,
        }
    }

    fn alert(ts: &str, score: f32, level: &str, reasons: Vec<&str>) -> AlertRecord {
        AlertRecord {
            timestamp: ts.into(),
            hostname: "test-host".into(),
            platform: "test".into(),
            score,
            confidence: 0.85,
            level: level.into(),
            action: "monitor".into(),
            reasons: reasons.into_iter().map(String::from).collect(),
            sample: sample(),
            enforced: false,
            mitre: vec![],
            narrative: None,
        }
    }

    #[test]
    fn empty_window_returns_baseline() {
        let result = analyze_alerts(&[], 5);
        assert_eq!(result.total_alerts, 0);
        assert_eq!(result.pattern, AlertPattern::Baseline);
        assert_eq!(result.score_trend, ScoreTrend::Stable);
    }

    #[test]
    fn baseline_pattern_all_elevated() {
        let alerts = vec![
            alert(
                "2026-04-02T10:00:00Z",
                2.1,
                "Elevated",
                vec!["within learned baseline"],
            ),
            alert(
                "2026-04-02T10:00:05Z",
                2.0,
                "Elevated",
                vec!["within learned baseline"],
            ),
            alert(
                "2026-04-02T10:00:10Z",
                2.2,
                "Elevated",
                vec!["within learned baseline"],
            ),
            alert(
                "2026-04-02T10:00:15Z",
                2.0,
                "Elevated",
                vec!["within learned baseline"],
            ),
        ];
        let result = analyze_alerts(&alerts, 0);
        assert_eq!(result.pattern, AlertPattern::Baseline);
        assert!(result.summary.contains("baseline"));
    }

    #[test]
    fn detects_escalating_trend() {
        let alerts = vec![
            alert("2026-04-02T10:00:00Z", 2.0, "Elevated", vec!["test"]),
            alert("2026-04-02T10:00:10Z", 2.5, "Elevated", vec!["test"]),
            alert("2026-04-02T10:00:20Z", 3.0, "Severe", vec!["test"]),
            alert("2026-04-02T10:00:30Z", 3.8, "Severe", vec!["test"]),
            alert("2026-04-02T10:00:40Z", 4.5, "Severe", vec!["test"]),
            alert("2026-04-02T10:00:50Z", 5.5, "Critical", vec!["test"]),
        ];
        let result = analyze_alerts(&alerts, 0);
        assert_eq!(result.pattern, AlertPattern::Escalating);
        assert!(matches!(result.score_trend, ScoreTrend::Rising { .. }));
    }

    #[test]
    fn detects_sustained_severe() {
        let alerts = vec![
            alert("2026-04-02T10:00:00Z", 4.0, "Severe", vec!["network burst"]),
            alert("2026-04-02T10:00:05Z", 4.2, "Severe", vec!["network burst"]),
            alert("2026-04-02T10:00:10Z", 4.5, "Severe", vec!["network burst"]),
            alert(
                "2026-04-02T10:00:15Z",
                5.8,
                "Critical",
                vec!["compound-threat"],
            ),
            alert("2026-04-02T10:00:20Z", 4.1, "Severe", vec!["network burst"]),
        ];
        let result = analyze_alerts(&alerts, 0);
        assert!(matches!(result.pattern, AlertPattern::Sustained { .. }));
    }

    #[test]
    fn detects_anomaly_outliers() {
        let mut alerts: Vec<AlertRecord> = (0..20)
            .map(|i| {
                alert(
                    &format!("2026-04-02T10:00:{:02}Z", i * 5),
                    2.0,
                    "Elevated",
                    vec!["within learned baseline"],
                )
            })
            .collect();
        // Inject a spike
        alerts[10].score = 6.5;
        alerts[10].level = "Critical".into();
        alerts[10].reasons = vec!["network burst (+3731.88)".into()];

        let result = analyze_alerts(&alerts, 0);
        assert!(!result.anomalies.is_empty());
        assert_eq!(result.anomalies[0].index, 10);
    }

    #[test]
    fn reason_histogram_normalises_values() {
        let alerts = vec![
            alert(
                "2026-04-02T10:00:00Z",
                4.0,
                "Severe",
                vec!["network burst (+3731.88)"],
            ),
            alert(
                "2026-04-02T10:00:05Z",
                3.5,
                "Severe",
                vec!["network burst (+1798.02)"],
            ),
            alert(
                "2026-04-02T10:00:10Z",
                2.0,
                "Elevated",
                vec!["within learned baseline"],
            ),
        ];
        let result = analyze_alerts(&alerts, 0);
        // Both "network burst" variants should merge
        let nb = result
            .dominant_reasons
            .iter()
            .find(|(r, _)| r == "network burst");
        assert_eq!(nb.map(|(_, c)| *c), Some(2));
    }

    #[test]
    fn group_alerts_by_reason_fingerprint() {
        let alerts = vec![
            alert(
                "2026-04-02T10:00:00Z",
                2.0,
                "Elevated",
                vec!["within learned baseline"],
            ),
            alert(
                "2026-04-02T10:00:05Z",
                2.1,
                "Elevated",
                vec!["within learned baseline"],
            ),
            alert(
                "2026-04-02T10:00:10Z",
                4.7,
                "Severe",
                vec!["network burst (+3731.88)"],
            ),
            alert(
                "2026-04-02T10:00:15Z",
                2.0,
                "Elevated",
                vec!["within learned baseline"],
            ),
            alert(
                "2026-04-02T10:00:20Z",
                3.3,
                "Severe",
                vec!["network burst (+1798.02)"],
            ),
        ];
        let groups = group_alerts(&alerts);
        assert_eq!(groups.len(), 2);
        // Both groups should have correct counts
        let baseline = groups
            .iter()
            .find(|g| g.reason_fingerprint.contains("baseline"));
        assert_eq!(baseline.map(|g| g.count), Some(3));
        let burst = groups
            .iter()
            .find(|g| g.reason_fingerprint.contains("network burst"));
        assert_eq!(burst.map(|g| g.count), Some(2));
    }

    #[test]
    fn trend_stable_for_flat_scores() {
        let alerts = vec![
            alert("2026-04-02T10:00:00Z", 2.0, "Elevated", vec!["test"]),
            alert("2026-04-02T10:00:10Z", 2.0, "Elevated", vec!["test"]),
            alert("2026-04-02T10:00:20Z", 2.0, "Elevated", vec!["test"]),
            alert("2026-04-02T10:00:30Z", 2.0, "Elevated", vec!["test"]),
        ];
        let result = analyze_alerts(&alerts, 0);
        assert_eq!(result.score_trend, ScoreTrend::Stable);
    }

    #[test]
    fn cluster_detection_gap_based() {
        let alerts = vec![
            alert("2026-04-02T10:00:00Z", 2.0, "Elevated", vec!["a"]),
            alert("2026-04-02T10:00:05Z", 2.0, "Elevated", vec!["a"]),
            alert("2026-04-02T10:00:10Z", 2.0, "Elevated", vec!["a"]),
            // 2-minute gap
            alert("2026-04-02T10:02:10Z", 4.0, "Severe", vec!["b"]),
            alert("2026-04-02T10:02:15Z", 4.5, "Severe", vec!["b"]),
        ];
        let result = analyze_alerts(&alerts, 0);
        assert_eq!(result.clusters.len(), 2);
    }

    #[test]
    fn dedup_merges_same_fingerprint() {
        let alerts = vec![
            alert("2026-04-02T10:00:00Z", 3.0, "Severe", vec!["network burst"]),
            alert("2026-04-02T10:00:30Z", 3.5, "Severe", vec!["network burst"]),
            alert("2026-04-02T10:01:00Z", 3.2, "Severe", vec!["network burst"]),
        ];
        let cfg = DedupConfig {
            window_secs: 300,
            cross_device: false,
            max_merge: 100,
        };
        let incidents = deduplicate_alerts(&alerts, &cfg);
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].alert_count, 3);
        assert!(incidents[0].incident_id.starts_with("INC-"));
    }

    #[test]
    fn dedup_splits_by_time_gap() {
        let alerts = vec![
            alert("2026-04-02T10:00:00Z", 3.0, "Severe", vec!["brute force"]),
            alert("2026-04-02T10:00:10Z", 3.1, "Severe", vec!["brute force"]),
            // 10-minute gap exceeds window
            alert("2026-04-02T10:11:00Z", 3.0, "Severe", vec!["brute force"]),
        ];
        let cfg = DedupConfig {
            window_secs: 300,
            cross_device: false,
            max_merge: 100,
        };
        let incidents = deduplicate_alerts(&alerts, &cfg);
        assert_eq!(incidents.len(), 2);
    }

    #[test]
    fn dedup_different_fingerprints_separate() {
        let alerts = vec![
            alert("2026-04-02T10:00:00Z", 3.0, "Severe", vec!["network burst"]),
            alert("2026-04-02T10:00:05Z", 4.0, "Severe", vec!["brute force"]),
        ];
        let cfg = DedupConfig::default();
        let incidents = deduplicate_alerts(&alerts, &cfg);
        assert_eq!(incidents.len(), 2);
    }

    #[test]
    fn dedup_cross_device_merge() {
        let mut a1 = alert("2026-04-02T10:00:00Z", 3.0, "Severe", vec!["network burst"]);
        a1.hostname = "host-A".into();
        let mut a2 = alert("2026-04-02T10:00:10Z", 3.5, "Severe", vec!["network burst"]);
        a2.hostname = "host-B".into();

        // Without cross-device → 2 incidents
        let cfg = DedupConfig {
            window_secs: 300,
            cross_device: false,
            max_merge: 100,
        };
        assert_eq!(deduplicate_alerts(&[a1.clone(), a2.clone()], &cfg).len(), 2);

        // With cross-device → 1 incident
        let cfg = DedupConfig {
            window_secs: 300,
            cross_device: true,
            max_merge: 100,
        };
        let incidents = deduplicate_alerts(&[a1, a2], &cfg);
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].device_ids.len(), 2);
    }

    #[test]
    fn dedup_max_merge_limit() {
        let alerts: Vec<AlertRecord> = (0..10)
            .map(|i| {
                alert(
                    &format!("2026-04-02T10:00:{:02}Z", i),
                    3.0,
                    "Severe",
                    vec!["same reason"],
                )
            })
            .collect();
        let cfg = DedupConfig {
            window_secs: 300,
            cross_device: false,
            max_merge: 3,
        };
        let incidents = deduplicate_alerts(&alerts, &cfg);
        // 10 alerts, max 3 per incident → at least 4 incidents
        assert!(incidents.len() >= 3);
    }

    #[test]
    fn dedup_empty_input() {
        let incidents = deduplicate_alerts(&[], &DedupConfig::default());
        assert!(incidents.is_empty());
    }
}

// ── False-positive feedback loop ─────────────────────────────────

/// Analyst feedback on an alert outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FpFeedback {
    pub alert_fingerprint: String,
    pub marked_fp: bool,
    pub analyst: String,
    pub timestamp: String,
    pub reason_pattern: String,
}

/// Accumulates false-positive feedback and computes per-pattern
/// suppression weights that downstream detection can use to
/// auto-lower confidence on recurring FP patterns.
#[derive(Debug, Clone, Default)]
pub struct FpFeedbackStore {
    entries: Vec<FpFeedback>,
    /// Pattern → (total_marked, fp_count)
    pattern_stats: HashMap<String, (u64, u64)>,
}

impl FpFeedbackStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record analyst feedback for an alert.
    pub fn record(&mut self, feedback: FpFeedback) {
        let key = feedback.reason_pattern.clone();
        let entry = self.pattern_stats.entry(key).or_insert((0, 0));
        entry.0 += 1;
        if feedback.marked_fp {
            entry.1 += 1;
        }
        self.entries.push(feedback);
    }

    /// Get the FP ratio for a given reason pattern (0.0–1.0).
    /// Returns `None` if no feedback exists for the pattern.
    pub fn fp_ratio(&self, pattern: &str) -> Option<f32> {
        self.pattern_stats.get(pattern).map(|(total, fps)| {
            if *total == 0 {
                0.0
            } else {
                *fps as f32 / *total as f32
            }
        })
    }

    /// Compute a suppression weight (0.0–1.0) for a reason pattern.
    /// High FP ratio → lower weight (suppress more). Requires ≥5 samples.
    pub fn suppression_weight(&self, pattern: &str) -> f32 {
        match self.pattern_stats.get(pattern) {
            Some((total, fps)) if *total >= 5 => {
                let ratio = *fps as f32 / *total as f32;
                (1.0 - ratio * 0.8).max(0.1) // Never fully suppress
            }
            _ => 1.0, // No suppression without enough data
        }
    }

    /// List all patterns with their FP statistics.
    pub fn stats(&self) -> Vec<(String, u64, u64, f32)> {
        self.pattern_stats
            .iter()
            .map(|(pattern, (total, fps))| {
                let ratio = if *total == 0 {
                    0.0
                } else {
                    *fps as f32 / *total as f32
                };
                (pattern.clone(), *total, *fps, ratio)
            })
            .collect()
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn entries(&self) -> &[FpFeedback] {
        &self.entries
    }
}

#[cfg(test)]
mod fp_tests {
    use super::*;

    fn fb(pattern: &str, fp: bool) -> FpFeedback {
        FpFeedback {
            alert_fingerprint: "test".into(),
            marked_fp: fp,
            analyst: "analyst1".into(),
            timestamp: "2026-04-05T00:00:00Z".into(),
            reason_pattern: pattern.into(),
        }
    }

    #[test]
    fn fp_ratio_tracks_correctly() {
        let mut store = FpFeedbackStore::new();
        for _ in 0..7 {
            store.record(fb("brute force", true));
        }
        for _ in 0..3 {
            store.record(fb("brute force", false));
        }
        let ratio = store.fp_ratio("brute force").unwrap();
        assert!((ratio - 0.7).abs() < 0.01);
    }

    #[test]
    fn suppression_requires_minimum_samples() {
        let mut store = FpFeedbackStore::new();
        for _ in 0..3 {
            store.record(fb("network burst", true));
        }
        // Only 3 samples — not enough for suppression
        assert!((store.suppression_weight("network burst") - 1.0).abs() < 0.001);
    }

    #[test]
    fn suppression_weight_decreases_with_fp_ratio() {
        let mut store = FpFeedbackStore::new();
        for _ in 0..8 {
            store.record(fb("thermal", true));
        }
        for _ in 0..2 {
            store.record(fb("thermal", false));
        }
        let w = store.suppression_weight("thermal");
        assert!(w < 0.5); // 80% FP rate → heavy suppression
        assert!(w >= 0.1); // Never fully suppressed
    }

    #[test]
    fn unknown_pattern_no_suppression() {
        let store = FpFeedbackStore::new();
        assert!((store.suppression_weight("unknown") - 1.0).abs() < 0.001);
        assert!(store.fp_ratio("unknown").is_none());
    }
}
