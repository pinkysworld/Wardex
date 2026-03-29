//! Side-channel detection engine.
//!
//! Implements timing analysis, cache-line probing detection, frequency
//! anomaly detection, and covert channel identification.
//! Covers R35 (side-channel countermeasures).

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

// ── Timing Analysis ──────────────────────────────────────────────────────────

/// Rolling statistics tracker for timing measurements (nanoseconds).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingAnalyzer {
    window: usize,
    samples: VecDeque<u64>,
    mean: f64,
    m2: f64,
    count: u64,
    jitter_threshold: f64,
}

impl TimingAnalyzer {
    pub fn new(window: usize, jitter_threshold_ns: f64) -> Self {
        Self {
            window,
            samples: VecDeque::with_capacity(window),
            mean: 0.0,
            m2: 0.0,
            count: 0,
            jitter_threshold: jitter_threshold_ns,
        }
    }

    /// Push a new timing sample and return whether jitter exceeds threshold.
    pub fn push(&mut self, sample_ns: u64) -> TimingVerdict {
        // Welford's online algorithm for variance
        self.count += 1;
        let delta = sample_ns as f64 - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = sample_ns as f64 - self.mean;
        self.m2 += delta * delta2;

        if self.samples.len() >= self.window {
            self.samples.pop_front();
        }
        self.samples.push_back(sample_ns);

        let variance = if self.count > 1 {
            self.m2 / (self.count - 1) as f64
        } else {
            0.0
        };
        let stddev = variance.sqrt();

        // Z-score of current sample
        let z_score = if stddev > 0.0 {
            (sample_ns as f64 - self.mean).abs() / stddev
        } else if self.count > 10 && (sample_ns as f64 - self.mean).abs() > 1.0 {
            // stddev is 0 (all prior samples identical), but this one differs → anomaly
            f64::INFINITY
        } else {
            0.0
        };

        // Check for timing anomaly
        if z_score > self.jitter_threshold && self.count > 10 {
            TimingVerdict::Anomaly {
                sample_ns,
                z_score,
                mean: self.mean,
                stddev,
            }
        } else {
            TimingVerdict::Normal {
                sample_ns,
                z_score,
            }
        }
    }

    pub fn mean(&self) -> f64 {
        self.mean
    }

    pub fn stddev(&self) -> f64 {
        if self.count > 1 {
            (self.m2 / (self.count - 1) as f64).sqrt()
        } else {
            0.0
        }
    }

    pub fn sample_count(&self) -> u64 {
        self.count
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TimingVerdict {
    Normal { sample_ns: u64, z_score: f64 },
    Anomaly { sample_ns: u64, z_score: f64, mean: f64, stddev: f64 },
}

// ── Cache Behaviour Monitor ──────────────────────────────────────────────────

/// Monitors cache miss rates to detect Flush+Reload / Prime+Probe attacks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheMonitor {
    baseline_miss_rate: f64,
    threshold_factor: f64,
    history: VecDeque<CacheSample>,
    max_history: usize,
    alerts: Vec<CacheAlert>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheSample {
    pub timestamp: String,
    pub hits: u64,
    pub misses: u64,
    pub miss_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheAlert {
    pub timestamp: String,
    pub observed_miss_rate: f64,
    pub baseline: f64,
    pub factor: f64,
    pub suspected_attack: String,
}

impl CacheMonitor {
    /// `threshold_factor`: alert if miss rate exceeds baseline × this factor.
    pub fn new(baseline_miss_rate: f64, threshold_factor: f64, max_history: usize) -> Self {
        Self {
            baseline_miss_rate,
            threshold_factor,
            history: VecDeque::with_capacity(max_history),
            max_history,
            alerts: Vec::new(),
        }
    }

    /// Record a cache-performance sample. Returns an alert if anomalous.
    pub fn record(&mut self, hits: u64, misses: u64) -> Option<CacheAlert> {
        let total = hits + misses;
        if total == 0 {
            return None;
        }
        let miss_rate = misses as f64 / total as f64;
        let sample = CacheSample {
            timestamp: chrono::Utc::now().to_rfc3339(),
            hits,
            misses,
            miss_rate,
        };

        if self.history.len() >= self.max_history {
            self.history.pop_front();
        }
        self.history.push_back(sample);

        if miss_rate > self.baseline_miss_rate * self.threshold_factor {
            let factor = miss_rate / self.baseline_miss_rate;
            let suspected = if factor > 10.0 {
                "flush+reload"
            } else if factor > 5.0 {
                "prime+probe"
            } else {
                "evict+time"
            };
            let alert = CacheAlert {
                timestamp: chrono::Utc::now().to_rfc3339(),
                observed_miss_rate: miss_rate,
                baseline: self.baseline_miss_rate,
                factor,
                suspected_attack: suspected.to_string(),
            };
            self.alerts.push(alert.clone());
            Some(alert)
        } else {
            None
        }
    }

    pub fn alerts(&self) -> &[CacheAlert] {
        &self.alerts
    }

    /// Recalibrate baseline from recent samples.
    pub fn recalibrate(&mut self) {
        if self.history.is_empty() {
            return;
        }
        let avg: f64 = self.history.iter().map(|s| s.miss_rate).sum::<f64>()
            / self.history.len() as f64;
        self.baseline_miss_rate = avg;
    }
}

// ── Frequency Analysis ───────────────────────────────────────────────────────

/// Detect periodic patterns in timing data that suggest covert channels.
#[derive(Debug, Clone)]
pub struct FrequencyAnalyzer {
    samples: Vec<f64>,
    sample_rate: f64,
}

impl FrequencyAnalyzer {
    pub fn new(sample_rate_hz: f64) -> Self {
        Self {
            samples: Vec::new(),
            sample_rate: sample_rate_hz,
        }
    }

    pub fn push(&mut self, value: f64) {
        self.samples.push(value);
    }

    /// Compute DFT magnitudes and return dominant frequencies.
    /// Uses a simplified DFT (not FFT) suitable for small windows.
    pub fn dominant_frequencies(&self, top_n: usize) -> Vec<(f64, f64)> {
        let n = self.samples.len();
        if n < 4 {
            return vec![];
        }

        // Remove DC component
        let mean: f64 = self.samples.iter().sum::<f64>() / n as f64;
        let centered: Vec<f64> = self.samples.iter().map(|v| v - mean).collect();

        // Compute magnitudes for each discrete frequency bin
        let half_n = n / 2;
        let mut magnitudes: Vec<(f64, f64)> = (1..half_n)
            .map(|k| {
                let mut re = 0.0_f64;
                let mut im = 0.0_f64;
                for (i, val) in centered.iter().enumerate() {
                    let angle =
                        2.0 * std::f64::consts::PI * k as f64 * i as f64 / n as f64;
                    re += val * angle.cos();
                    im -= val * angle.sin();
                }
                let mag = (re * re + im * im).sqrt() / n as f64;
                let freq = k as f64 * self.sample_rate / n as f64;
                (freq, mag)
            })
            .collect();

        magnitudes.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        magnitudes.truncate(top_n);
        magnitudes
    }

    /// Detect if there is a strong periodic component (possible covert channel).
    pub fn detect_covert_channel(&self, strength_threshold: f64) -> Option<CovertChannelAlert> {
        let freqs = self.dominant_frequencies(3);
        if freqs.is_empty() {
            return None;
        }

        let (peak_freq, peak_mag) = freqs[0];
        let avg_mag = if freqs.len() > 1 {
            freqs[1..].iter().map(|(_, m)| m).sum::<f64>() / (freqs.len() - 1) as f64
        } else {
            0.0
        };

        let ratio = if avg_mag > 0.0 {
            peak_mag / avg_mag
        } else if peak_mag > 0.0 {
            f64::INFINITY
        } else {
            0.0
        };

        if ratio > strength_threshold {
            Some(CovertChannelAlert {
                dominant_frequency_hz: peak_freq,
                magnitude: peak_mag,
                ratio_to_background: ratio,
                sample_count: self.samples.len(),
            })
        } else {
            None
        }
    }

    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CovertChannelAlert {
    pub dominant_frequency_hz: f64,
    pub magnitude: f64,
    pub ratio_to_background: f64,
    pub sample_count: usize,
}

// ── Composite Side-Channel Detector ──────────────────────────────────────────

/// Composite detector combining timing, cache, and frequency analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SideChannelReport {
    pub timing_anomalies: usize,
    pub cache_alerts: usize,
    pub covert_channels: usize,
    pub overall_risk: String,
}

pub struct SideChannelDetector {
    pub timing: TimingAnalyzer,
    pub cache: CacheMonitor,
    pub frequency: FrequencyAnalyzer,
    timing_anomaly_count: usize,
}

impl SideChannelDetector {
    pub fn new() -> Self {
        Self {
            timing: TimingAnalyzer::new(1000, 3.0),
            cache: CacheMonitor::new(0.05, 3.0, 500),
            frequency: FrequencyAnalyzer::new(1000.0),
            timing_anomaly_count: 0,
        }
    }

    /// Feed a timing sample and return verdict.
    pub fn observe_timing(&mut self, ns: u64) -> TimingVerdict {
        let verdict = self.timing.push(ns);
        if matches!(verdict, TimingVerdict::Anomaly { .. }) {
            self.timing_anomaly_count += 1;
        }
        // Also feed into frequency analyzer (inter-arrival time)
        self.frequency.push(ns as f64);
        verdict
    }

    /// Feed a cache performance sample.
    pub fn observe_cache(&mut self, hits: u64, misses: u64) -> Option<CacheAlert> {
        self.cache.record(hits, misses)
    }

    /// Produce a composite risk report.
    pub fn report(&self) -> SideChannelReport {
        let covert = if self.frequency.detect_covert_channel(5.0).is_some() {
            1
        } else {
            0
        };
        let cache_count = self.cache.alerts().len();
        let risk = match (self.timing_anomaly_count, cache_count, covert) {
            (t, c, ch) if t > 10 || c > 5 || ch > 0 => "critical",
            (t, c, _) if t > 5 || c > 2 => "elevated",
            (t, _, _) if t > 0 => "low",
            _ => "nominal",
        };
        SideChannelReport {
            timing_anomalies: self.timing_anomaly_count,
            cache_alerts: cache_count,
            covert_channels: covert,
            overall_risk: risk.to_string(),
        }
    }
}

impl Default for SideChannelDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timing_normal_samples() {
        let mut ta = TimingAnalyzer::new(100, 3.0);
        for _ in 0..20 {
            let v = ta.push(1000);
            assert!(matches!(v, TimingVerdict::Normal { .. }));
        }
        assert!((ta.mean() - 1000.0).abs() < 1.0);
    }

    #[test]
    fn timing_detects_anomaly() {
        let mut ta = TimingAnalyzer::new(100, 3.0);
        // Establish baseline
        for _ in 0..50 {
            ta.push(1000);
        }
        // Inject spike
        let v = ta.push(100_000);
        assert!(matches!(v, TimingVerdict::Anomaly { .. }));
    }

    #[test]
    fn cache_monitor_normal() {
        let mut cm = CacheMonitor::new(0.05, 3.0, 100);
        let alert = cm.record(950, 50); // 5% miss rate = baseline
        assert!(alert.is_none());
    }

    #[test]
    fn cache_monitor_detects_attack() {
        let mut cm = CacheMonitor::new(0.05, 3.0, 100);
        // Miss rate 60% → 12× baseline
        let alert = cm.record(400, 600);
        assert!(alert.is_some());
        let a = alert.unwrap();
        assert_eq!(a.suspected_attack, "flush+reload");
    }

    #[test]
    fn cache_recalibrate() {
        let mut cm = CacheMonitor::new(0.05, 3.0, 100);
        cm.record(900, 100); // 10%
        cm.record(850, 150); // ~15%
        cm.recalibrate();
        assert!(cm.baseline_miss_rate > 0.10);
    }

    #[test]
    fn frequency_detects_periodic() {
        let mut fa = FrequencyAnalyzer::new(100.0);
        // Generate a signal with a strong 10 Hz component
        for i in 0..200 {
            let t = i as f64 / 100.0;
            let val = (2.0 * std::f64::consts::PI * 10.0 * t).sin() * 100.0;
            fa.push(val);
        }
        let freqs = fa.dominant_frequencies(3);
        assert!(!freqs.is_empty());
        // Dominant frequency should be near 10 Hz
        assert!((freqs[0].0 - 10.0).abs() < 1.5);
    }

    #[test]
    fn covert_channel_detection() {
        let mut fa = FrequencyAnalyzer::new(1000.0);
        // Use 500 samples so freq 50 Hz lands on exact DFT bin (k=25)
        for i in 0..500 {
            let t = i as f64 / 1000.0;
            let signal = (2.0 * std::f64::consts::PI * 50.0 * t).sin() * 500.0;
            fa.push(signal + 100.0);
        }
        let alert = fa.detect_covert_channel(3.0);
        assert!(alert.is_some());
    }

    #[test]
    fn composite_detector_report() {
        let mut det = SideChannelDetector::new();
        // Feed normal timing data
        for _ in 0..20 {
            det.observe_timing(1000);
        }
        let report = det.report();
        assert_eq!(report.overall_risk, "nominal");
    }

    #[test]
    fn composite_elevated_risk() {
        let mut det = SideChannelDetector::new();
        // Establish solid baseline
        for _ in 0..100 {
            det.observe_timing(1000);
        }
        // Interleave spikes with baseline to prevent Welford from adapting
        for _ in 0..8 {
            det.observe_timing(500_000);
            for _ in 0..10 {
                det.observe_timing(1000);
            }
        }
        let report = det.report();
        assert!(report.timing_anomalies > 5);
        assert!(report.overall_risk == "elevated" || report.overall_risk == "critical");
    }
}
