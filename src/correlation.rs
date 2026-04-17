use serde::{Deserialize, Serialize};

use crate::replay::ReplayBuffer;

/// A detected multi-signal correlation pattern (T082 / R30).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationResult {
    /// Pearson correlation coefficient between each signal pair that
    /// exceeds the threshold, along with the signal names.
    pub correlated_pairs: Vec<CorrelatedPair>,
    /// Number of signals that are simultaneously trending upward
    /// (positive slope over the replay window).
    pub co_rising_count: usize,
    /// Names of signals trending upward.
    pub co_rising_signals: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelatedPair {
    pub signal_a: String,
    pub signal_b: String,
    pub coefficient: f32,
}

/// Extract named signal vectors from the replay buffer for correlation analysis.
fn extract_signals(buf: &ReplayBuffer) -> Vec<(&'static str, Vec<f32>)> {
    let samples = buf.samples();
    let mut cpu = Vec::with_capacity(samples.len());
    let mut mem = Vec::with_capacity(samples.len());
    let mut net = Vec::with_capacity(samples.len());
    let mut auth = Vec::with_capacity(samples.len());
    let mut drift = Vec::with_capacity(samples.len());
    let mut proc = Vec::with_capacity(samples.len());
    let mut disk = Vec::with_capacity(samples.len());
    let mut temp = Vec::with_capacity(samples.len());

    for s in samples {
        cpu.push(s.cpu_load_pct);
        mem.push(s.memory_load_pct);
        net.push(s.network_kbps);
        auth.push(s.auth_failures as f32);
        drift.push(s.integrity_drift);
        proc.push(s.process_count as f32);
        disk.push(s.disk_pressure_pct);
        temp.push(s.temperature_c);
    }

    vec![
        ("cpu_load_pct", cpu),
        ("memory_load_pct", mem),
        ("network_kbps", net),
        ("auth_failures", auth),
        ("integrity_drift", drift),
        ("process_count", proc),
        ("disk_pressure_pct", disk),
        ("temperature_c", temp),
    ]
}

/// Compute Pearson correlation coefficient between two equal-length slices.
fn pearson(a: &[f32], b: &[f32]) -> f32 {
    let n = a.len() as f32;
    if n < 3.0 {
        return 0.0;
    }

    let mean_a: f32 = a.iter().sum::<f32>() / n;
    let mean_b: f32 = b.iter().sum::<f32>() / n;

    let mut cov = 0.0_f32;
    let mut var_a = 0.0_f32;
    let mut var_b = 0.0_f32;

    for (x, y) in a.iter().zip(b.iter()) {
        let da = x - mean_a;
        let db = y - mean_b;
        cov += da * db;
        var_a += da * da;
        var_b += db * db;
    }

    let denom = (var_a * var_b).sqrt();
    if denom < 1e-10 {
        return 0.0;
    }
    cov / denom
}

/// Simple linear trend: positive slope → signal is rising.
fn is_rising(values: &[f32]) -> bool {
    if values.len() < 3 {
        return false;
    }
    let n = values.len() as f32;
    let x_mean = (n - 1.0) / 2.0;
    let y_mean: f32 = values.iter().sum::<f32>() / n;

    let mut num = 0.0_f32;
    let mut den = 0.0_f32;
    for (i, &y) in values.iter().enumerate() {
        let dx = i as f32 - x_mean;
        num += dx * (y - y_mean);
        den += dx * dx;
    }

    if den < 1e-10 {
        return false;
    }
    // Require a meaningfully positive slope, not just noise.
    num / den > 0.01
}

/// Analyze the replay buffer for multi-signal correlation patterns.
///
/// `threshold` is the minimum absolute Pearson coefficient (typically 0.8)
/// to consider two signals correlated.
pub fn analyze(buf: &ReplayBuffer, threshold: f32) -> CorrelationResult {
    let signals = extract_signals(buf);
    let mut correlated_pairs = Vec::new();
    let mut co_rising_signals = Vec::new();

    // Pairwise correlation
    for i in 0..signals.len() {
        for j in (i + 1)..signals.len() {
            let r = pearson(&signals[i].1, &signals[j].1);
            if r.abs() >= threshold {
                correlated_pairs.push(CorrelatedPair {
                    signal_a: signals[i].0.to_string(),
                    signal_b: signals[j].0.to_string(),
                    coefficient: r,
                });
            }
        }
    }

    // Co-rising detection
    for (name, values) in &signals {
        if is_rising(values) {
            co_rising_signals.push(name.to_string());
        }
    }

    let co_rising_count = co_rising_signals.len();

    CorrelationResult {
        correlated_pairs,
        co_rising_count,
        co_rising_signals,
    }
}

// ── Fleet-Wide Credential Spray Detection ─────────────────────────────────────

/// An authentication failure event reported by an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthFailureEvent {
    pub agent_id: String,
    pub username: String,
    pub timestamp_epoch: i64,
    pub source_ip: Option<String>,
}

/// Alert generated when credential spray is detected across multiple agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialSprayAlert {
    pub target_account: String,
    pub involved_agents: Vec<String>,
    pub agent_count: usize,
    pub time_window_secs: i64,
    pub first_seen: i64,
    pub last_seen: i64,
    pub source_ips: Vec<String>,
}

/// Detect fleet-wide credential spray: a single username failing authentication
/// across `min_agents` or more agents within `window_secs`.
pub fn detect_credential_spray(
    events: &[AuthFailureEvent],
    window_secs: i64,
    min_agents: usize,
) -> Vec<CredentialSprayAlert> {
    use std::collections::{BTreeMap, HashSet};

    if events.is_empty() || min_agents == 0 {
        return Vec::new();
    }

    // Group events by username
    let mut by_user: BTreeMap<&str, Vec<&AuthFailureEvent>> = BTreeMap::new();
    for ev in events {
        by_user.entry(&ev.username).or_default().push(ev);
    }

    let mut alerts = Vec::new();

    for (username, user_events) in &by_user {
        if user_events.len() < min_agents {
            continue;
        }

        // Sort by timestamp
        let mut sorted: Vec<&&AuthFailureEvent> = user_events.iter().collect();
        sorted.sort_by_key(|e| e.timestamp_epoch);

        // Sliding window: find clusters of events within the window
        let mut i = 0;
        while i < sorted.len() {
            let window_start = sorted[i].timestamp_epoch;
            let window_end = window_start.saturating_add(window_secs);

            let mut agents: HashSet<&str> = HashSet::new();
            let mut ips: HashSet<&str> = HashSet::new();
            let mut last_ts = window_start;
            let mut j = i;

            while j < sorted.len() && sorted[j].timestamp_epoch <= window_end {
                agents.insert(&sorted[j].agent_id);
                if let Some(ref ip) = sorted[j].source_ip {
                    ips.insert(ip);
                }
                last_ts = sorted[j].timestamp_epoch;
                j += 1;
            }

            if agents.len() >= min_agents {
                let mut agent_list: Vec<String> = agents.iter().map(|a| a.to_string()).collect();
                agent_list.sort();
                let mut ip_list: Vec<String> = ips.iter().map(|i| i.to_string()).collect();
                ip_list.sort();

                alerts.push(CredentialSprayAlert {
                    target_account: username.to_string(),
                    involved_agents: agent_list.clone(),
                    agent_count: agents.len(),
                    time_window_secs: window_secs,
                    first_seen: window_start,
                    last_seen: last_ts,
                    source_ips: ip_list,
                });

                // Skip past this window to avoid duplicate alerts
                i = j;
            } else {
                i += 1;
            }
        }
    }

    alerts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::TelemetrySample;

    fn sample_with(ts: u64, cpu: f32, mem: f32, net: f32) -> TelemetrySample {
        TelemetrySample {
            timestamp_ms: ts,
            cpu_load_pct: cpu,
            memory_load_pct: mem,
            temperature_c: 38.0,
            network_kbps: net,
            auth_failures: 0,
            battery_pct: 90.0,
            integrity_drift: 0.01,
            process_count: 40,
            disk_pressure_pct: 10.0,
        }
    }

    #[test]
    fn detects_correlated_rise() {
        let mut buf = ReplayBuffer::new(20);
        // CPU, memory, and network all rise linearly together
        for i in 0..10 {
            buf.push(sample_with(
                i as u64,
                20.0 + i as f32 * 5.0,
                30.0 + i as f32 * 4.0,
                500.0 + i as f32 * 300.0,
            ));
        }

        let result = analyze(&buf, 0.8);
        assert!(
            result
                .correlated_pairs
                .iter()
                .any(
                    |p| (p.signal_a == "cpu_load_pct" && p.signal_b == "memory_load_pct")
                        || (p.signal_a == "memory_load_pct" && p.signal_b == "cpu_load_pct")
                ),
            "expected cpu-memory correlation"
        );
        assert!(
            result.co_rising_count >= 3,
            "expected at least 3 co-rising signals"
        );
        assert!(result.co_rising_signals.iter().any(|s| s == "cpu_load_pct"));
    }

    #[test]
    fn stable_signals_not_correlated() {
        let mut buf = ReplayBuffer::new(20);
        // Flat constant signals — no meaningful correlation
        for i in 0..10 {
            buf.push(sample_with(i as u64, 50.0, 50.0, 1000.0));
        }

        let result = analyze(&buf, 0.8);
        assert!(
            result.correlated_pairs.is_empty(),
            "flat signals should not appear correlated"
        );
        assert_eq!(result.co_rising_count, 0);
    }

    #[test]
    fn empty_buffer_returns_empty() {
        let buf = ReplayBuffer::new(10);
        let result = analyze(&buf, 0.8);
        assert!(result.correlated_pairs.is_empty());
        assert_eq!(result.co_rising_count, 0);
    }

    #[test]
    fn pearson_perfect_correlation() {
        let a = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let b = vec![2.0, 4.0, 6.0, 8.0, 10.0];
        let r = pearson(&a, &b);
        assert!(
            (r - 1.0).abs() < 0.001,
            "perfect positive correlation, got {r}"
        );
    }

    #[test]
    fn pearson_negative_correlation() {
        let a = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let b = vec![10.0, 8.0, 6.0, 4.0, 2.0];
        let r = pearson(&a, &b);
        assert!(
            (r - (-1.0)).abs() < 0.001,
            "perfect negative correlation, got {r}"
        );
    }

    #[test]
    fn credential_spray_detected() {
        let events = vec![
            AuthFailureEvent {
                agent_id: "agent-1".into(),
                username: "admin".into(),
                timestamp_epoch: 1000,
                source_ip: Some("10.0.0.1".into()),
            },
            AuthFailureEvent {
                agent_id: "agent-2".into(),
                username: "admin".into(),
                timestamp_epoch: 1100,
                source_ip: Some("10.0.0.2".into()),
            },
            AuthFailureEvent {
                agent_id: "agent-3".into(),
                username: "admin".into(),
                timestamp_epoch: 1200,
                source_ip: Some("10.0.0.3".into()),
            },
        ];
        let alerts = detect_credential_spray(&events, 600, 3);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].target_account, "admin");
        assert_eq!(alerts[0].agent_count, 3);
    }

    #[test]
    fn credential_spray_not_triggered_below_threshold() {
        let events = vec![
            AuthFailureEvent {
                agent_id: "agent-1".into(),
                username: "admin".into(),
                timestamp_epoch: 1000,
                source_ip: None,
            },
            AuthFailureEvent {
                agent_id: "agent-2".into(),
                username: "admin".into(),
                timestamp_epoch: 1100,
                source_ip: None,
            },
        ];
        let alerts = detect_credential_spray(&events, 600, 3);
        assert!(alerts.is_empty());
    }

    #[test]
    fn credential_spray_outside_window() {
        let events = vec![
            AuthFailureEvent {
                agent_id: "agent-1".into(),
                username: "admin".into(),
                timestamp_epoch: 1000,
                source_ip: None,
            },
            AuthFailureEvent {
                agent_id: "agent-2".into(),
                username: "admin".into(),
                timestamp_epoch: 1100,
                source_ip: None,
            },
            AuthFailureEvent {
                agent_id: "agent-3".into(),
                username: "admin".into(),
                timestamp_epoch: 5000, // far outside window
                source_ip: None,
            },
        ];
        let alerts = detect_credential_spray(&events, 600, 3);
        assert!(alerts.is_empty());
    }
}
