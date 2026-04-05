use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::baseline::PersistedBaseline;
use crate::telemetry::TelemetrySample;

#[derive(Debug, Clone, Copy)]
struct TelemetryBaseline {
    cpu_load_pct: f32,
    memory_load_pct: f32,
    temperature_c: f32,
    network_kbps: f32,
    auth_failures: f32,
    battery_pct: f32,
    integrity_drift: f32,
    process_count: f32,
    disk_pressure_pct: f32,
}

impl TelemetryBaseline {
    fn from_sample(sample: &TelemetrySample) -> Self {
        Self {
            cpu_load_pct: sample.cpu_load_pct,
            memory_load_pct: sample.memory_load_pct,
            temperature_c: sample.temperature_c,
            network_kbps: sample.network_kbps,
            auth_failures: sample.auth_failures as f32,
            battery_pct: sample.battery_pct,
            integrity_drift: sample.integrity_drift,
            process_count: sample.process_count as f32,
            disk_pressure_pct: sample.disk_pressure_pct,
        }
    }

    fn from_persisted(p: &PersistedBaseline) -> Self {
        Self {
            cpu_load_pct: p.cpu_load_pct,
            memory_load_pct: p.memory_load_pct,
            temperature_c: p.temperature_c,
            network_kbps: p.network_kbps,
            auth_failures: p.auth_failures,
            battery_pct: p.battery_pct,
            integrity_drift: p.integrity_drift,
            process_count: p.process_count,
            disk_pressure_pct: p.disk_pressure_pct,
        }
    }

    fn update(&mut self, sample: &TelemetrySample, alpha: f32) {
        self.cpu_load_pct = blend(self.cpu_load_pct, sample.cpu_load_pct, alpha);
        self.memory_load_pct = blend(self.memory_load_pct, sample.memory_load_pct, alpha);
        self.temperature_c = blend(self.temperature_c, sample.temperature_c, alpha);
        self.network_kbps = blend(self.network_kbps, sample.network_kbps, alpha);
        self.auth_failures = blend(self.auth_failures, sample.auth_failures as f32, alpha);
        self.battery_pct = blend(self.battery_pct, sample.battery_pct, alpha);
        self.integrity_drift = blend(self.integrity_drift, sample.integrity_drift, alpha);
        self.process_count = blend(self.process_count, sample.process_count as f32, alpha);
        self.disk_pressure_pct = blend(self.disk_pressure_pct, sample.disk_pressure_pct, alpha);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DetectorConfig {
    pub warmup_samples: usize,
    pub smoothing: f32,
    pub learn_threshold: f32,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            warmup_samples: 4,
            smoothing: 0.22,
            learn_threshold: 2.5,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AnomalySignal {
    pub score: f32,
    pub confidence: f32,
    pub suspicious_axes: usize,
    pub reasons: Vec<String>,
    /// Per-signal contribution to the total score (T080 — explainable attribution).
    /// Each entry is `(signal_name, contribution)` where contribution is the
    /// weighted score contributed by that signal dimension. Sum of contributions
    /// equals `score` (before history_factor scaling) when history_factor is 1.0.
    pub contributions: Vec<(&'static str, f32)>,
}

/// Controls how the detector updates its learned baseline (T041).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum AdaptationMode {
    /// Normal EWMA-based learning (default).
    #[default]
    Normal,
    /// Freeze the baseline — evaluate but never update.
    Frozen,
    /// Decay the baseline toward a neutral midpoint at the given rate
    /// per sample. Useful for slowly "forgetting" to detect gradual
    /// poisoning.
    Decay(f32),
}

pub struct AnomalyDetector {
    config: DetectorConfig,
    baseline: Option<TelemetryBaseline>,
    observed_samples: usize,
    adaptation: AdaptationMode,
    custom_weights: Option<HashMap<String, f32>>,
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new(DetectorConfig::default())
    }
}

impl AnomalyDetector {
    pub fn new(config: DetectorConfig) -> Self {
        Self {
            config,
            baseline: None,
            observed_samples: 0,
            adaptation: AdaptationMode::Normal,
            custom_weights: None,
        }
    }

    pub fn set_signal_weights(&mut self, weights: HashMap<String, f32>) {
        self.custom_weights = Some(weights);
    }

    pub fn signal_weights(&self) -> HashMap<String, f32> {
        if let Some(ref w) = self.custom_weights {
            return w.clone();
        }
        let mut defaults = HashMap::new();
        defaults.insert("cpu_load_pct".into(), 0.85);
        defaults.insert("memory_load_pct".into(), 0.7);
        defaults.insert("temperature_c".into(), 0.8);
        defaults.insert("network_kbps".into(), 1.1);
        defaults.insert("auth_failures".into(), 1.6);
        defaults.insert("integrity_drift".into(), 1.9);
        defaults.insert("process_count".into(), 0.65);
        defaults.insert("disk_pressure_pct".into(), 0.6);
        defaults.insert("battery_pct".into(), 0.35);
        defaults
    }

    fn weight_for(&self, axis: &str, default: f32) -> f32 {
        self.custom_weights.as_ref()
            .and_then(|w| w.get(axis).copied())
            .unwrap_or(default)
    }

    /// Set the baseline adaptation mode (T041).
    pub fn set_adaptation(&mut self, mode: AdaptationMode) {
        self.adaptation = mode;
    }

    pub fn adaptation(&self) -> AdaptationMode {
        self.adaptation
    }

    pub fn smoothing(&self) -> f32 {
        self.config.smoothing
    }

    pub fn warmup_samples(&self) -> usize {
        self.config.warmup_samples
    }

    pub fn learn_threshold(&self) -> f32 {
        self.config.learn_threshold
    }

    pub fn observed_samples(&self) -> usize {
        self.observed_samples
    }

    pub fn baseline_ready(&self) -> bool {
        self.observed_samples >= self.config.warmup_samples && self.baseline.is_some()
    }

    /// Reset the baseline so the detector re-learns from scratch.
    /// Useful when poisoning is suspected.
    pub fn reset_baseline(&mut self) {
        self.baseline = None;
        self.observed_samples = 0;
    }

    /// Restore from a persisted baseline so the detector continues
    /// where a previous run left off (T013).
    pub fn restore_baseline(&mut self, persisted: &PersistedBaseline) {
        self.baseline = Some(TelemetryBaseline::from_persisted(persisted));
        self.observed_samples = persisted.observed_samples;
    }

    /// Export the current baseline for persistence.
    pub fn snapshot(&self) -> Option<PersistedBaseline> {
        self.baseline.map(|b| PersistedBaseline {
            cpu_load_pct: b.cpu_load_pct,
            memory_load_pct: b.memory_load_pct,
            temperature_c: b.temperature_c,
            network_kbps: b.network_kbps,
            auth_failures: b.auth_failures,
            battery_pct: b.battery_pct,
            integrity_drift: b.integrity_drift,
            process_count: b.process_count,
            disk_pressure_pct: b.disk_pressure_pct,
            observed_samples: self.observed_samples,
        })
    }

    pub fn evaluate(&mut self, sample: &TelemetrySample) -> AnomalySignal {
        match self.baseline {
            None => {
                self.baseline = Some(TelemetryBaseline::from_sample(sample));
                self.observed_samples = 1;

                AnomalySignal {
                    score: 0.0,
                    confidence: 0.25,
                    suspicious_axes: 0,
                    reasons: vec!["baseline initialized".to_string()],
                    contributions: Vec::new(),
                }
            }
            Some(mut baseline) => {
                let mut reasons = Vec::new();
                let mut suspicious_axes = 0usize;
                let mut contributions: Vec<(&'static str, f32)> = Vec::new();
                let history_factor = (self.observed_samples as f32
                    / self.config.warmup_samples.max(1) as f32)
                    .clamp(0.35, 1.0);

                let mut score = 0.0;
                let c = weighted_positive_delta(
                    sample.cpu_load_pct - baseline.cpu_load_pct,
                    18.0,
                    self.weight_for("cpu_load_pct", 0.85),
                    "cpu load spike",
                    &mut reasons,
                    &mut suspicious_axes,
                );
                if c > 0.0 {
                    contributions.push(("cpu_load_pct", c));
                }
                score += c;
                let c = weighted_positive_delta(
                    sample.memory_load_pct - baseline.memory_load_pct,
                    14.0,
                    self.weight_for("memory_load_pct", 0.7),
                    "memory pressure increase",
                    &mut reasons,
                    &mut suspicious_axes,
                );
                if c > 0.0 {
                    contributions.push(("memory_load_pct", c));
                }
                score += c;
                let c = weighted_positive_delta(
                    sample.temperature_c - baseline.temperature_c,
                    7.0,
                    self.weight_for("temperature_c", 0.8),
                    "thermal deviation",
                    &mut reasons,
                    &mut suspicious_axes,
                );
                if c > 0.0 {
                    contributions.push(("temperature_c", c));
                }
                score += c;
                let c = weighted_positive_delta(
                    sample.network_kbps - baseline.network_kbps,
                    1800.0,
                    self.weight_for("network_kbps", 1.1),
                    "network burst",
                    &mut reasons,
                    &mut suspicious_axes,
                );
                if c > 0.0 {
                    contributions.push(("network_kbps", c));
                }
                score += c;
                let c = weighted_positive_delta(
                    sample.auth_failures as f32 - baseline.auth_failures,
                    3.0,
                    self.weight_for("auth_failures", 1.6),
                    "auth failures surge",
                    &mut reasons,
                    &mut suspicious_axes,
                );
                if c > 0.0 {
                    contributions.push(("auth_failures", c));
                }
                score += c;
                let c = weighted_positive_delta(
                    sample.integrity_drift - baseline.integrity_drift,
                    0.06,
                    self.weight_for("integrity_drift", 1.9),
                    "integrity drift increase",
                    &mut reasons,
                    &mut suspicious_axes,
                );
                if c > 0.0 {
                    contributions.push(("integrity_drift", c));
                }
                score += c;

                // T014: process count anomaly
                let c = weighted_positive_delta(
                    sample.process_count as f32 - baseline.process_count,
                    20.0,
                    self.weight_for("process_count", 0.65),
                    "process count spike",
                    &mut reasons,
                    &mut suspicious_axes,
                );
                if c > 0.0 {
                    contributions.push(("process_count", c));
                }
                score += c;

                // T014: disk pressure anomaly
                let c = weighted_positive_delta(
                    sample.disk_pressure_pct - baseline.disk_pressure_pct,
                    25.0,
                    self.weight_for("disk_pressure_pct", 0.6),
                    "disk pressure increase",
                    &mut reasons,
                    &mut suspicious_axes,
                );
                if c > 0.0 {
                    contributions.push(("disk_pressure_pct", c));
                }
                score += c;

                if sample.battery_pct < baseline.battery_pct - 18.0 {
                    let bw = self.weight_for("battery_pct", 0.35);
                    score += bw;
                    contributions.push(("battery_pct", bw));
                    reasons.push("battery dropped sharply under load".to_string());
                    suspicious_axes += 1;
                }

                score *= history_factor;

                // T041: respect adaptation mode
                match self.adaptation {
                    AdaptationMode::Normal => {
                        if score < self.config.learn_threshold {
                            baseline.update(sample, self.config.smoothing);
                        }
                    }
                    AdaptationMode::Frozen => {
                        // Do not update baseline at all.
                    }
                    AdaptationMode::Decay(rate) => {
                        // Nudge each dimension toward a neutral midpoint.
                        let mid = TelemetryBaseline {
                            cpu_load_pct: 50.0,
                            memory_load_pct: 50.0,
                            temperature_c: 40.0,
                            network_kbps: 1000.0,
                            auth_failures: 0.0,
                            battery_pct: 50.0,
                            integrity_drift: 0.0,
                            process_count: 50.0,
                            disk_pressure_pct: 50.0,
                        };
                        baseline.cpu_load_pct =
                            blend(baseline.cpu_load_pct, mid.cpu_load_pct, rate);
                        baseline.memory_load_pct =
                            blend(baseline.memory_load_pct, mid.memory_load_pct, rate);
                        baseline.temperature_c =
                            blend(baseline.temperature_c, mid.temperature_c, rate);
                        baseline.network_kbps =
                            blend(baseline.network_kbps, mid.network_kbps, rate);
                        baseline.auth_failures =
                            blend(baseline.auth_failures, mid.auth_failures, rate);
                        baseline.battery_pct = blend(baseline.battery_pct, mid.battery_pct, rate);
                        baseline.integrity_drift =
                            blend(baseline.integrity_drift, mid.integrity_drift, rate);
                        baseline.process_count =
                            blend(baseline.process_count, mid.process_count, rate);
                        baseline.disk_pressure_pct =
                            blend(baseline.disk_pressure_pct, mid.disk_pressure_pct, rate);
                    }
                }

                self.baseline = Some(baseline);
                self.observed_samples = self.observed_samples.saturating_add(1);

                if reasons.is_empty() {
                    reasons.push("within learned baseline".to_string());
                }

                // Scale contributions by history_factor to match final score.
                for c in &mut contributions {
                    c.1 *= history_factor;
                }

                AnomalySignal {
                    score,
                    confidence: history_factor,
                    suspicious_axes,
                    reasons,
                    contributions,
                }
            }
        }
    }
}

fn blend(current: f32, next: f32, alpha: f32) -> f32 {
    ((1.0 - alpha) * current) + (alpha * next)
}

fn weighted_positive_delta(
    delta: f32,
    scale: f32,
    weight: f32,
    label: &str,
    reasons: &mut Vec<String>,
    suspicious_axes: &mut usize,
) -> f32 {
    if delta <= 0.0 {
        return 0.0;
    }

    let normalized = if scale > 0.0 { delta / scale } else { 0.0 };
    if normalized >= 0.5 {
        reasons.push(format!("{label} (+{delta:.2})"));
        *suspicious_axes += 1;
    }

    normalized * weight
}

// ─── Continual learning: concept drift detection (R01) ───

/// Result of a drift check on a signal stream.
#[derive(Debug, Clone)]
pub struct DriftResult {
    pub drifted: bool,
    pub cumulative_sum: f64,
    pub threshold: f64,
    pub samples_since_reset: usize,
}

/// Page-Hinkley drift detector for a single signal stream.
///
/// Monitors a running mean and accumulates deviations. When the
/// cumulative deviation exceeds `threshold` the detector signals a
/// distribution shift, which the runtime can use to trigger baseline
/// re-learning or alert on adversarial poisoning.
#[derive(Debug, Clone)]
pub struct DriftDetector {
    /// Minimum deviation before accumulation starts (filters noise).
    delta: f64,
    /// Drift alarm threshold on cumulative sum.
    threshold: f64,
    mean: f64,
    sum: f64,
    min_sum: f64,
    count: usize,
}

impl DriftDetector {
    pub fn new(delta: f64, threshold: f64) -> Self {
        Self {
            delta,
            threshold,
            mean: 0.0,
            sum: 0.0,
            min_sum: 0.0,
            count: 0,
        }
    }

    /// Feed a new observation and return drift status.
    pub fn update(&mut self, value: f64) -> DriftResult {
        self.count += 1;
        self.mean += (value - self.mean) / self.count as f64;
        self.sum += value - self.mean - self.delta;
        if self.sum < self.min_sum {
            self.min_sum = self.sum;
        }
        let test_stat = self.sum - self.min_sum;
        DriftResult {
            drifted: test_stat > self.threshold,
            cumulative_sum: test_stat,
            threshold: self.threshold,
            samples_since_reset: self.count,
        }
    }

    /// Reset the detector after a drift alarm is handled.
    pub fn reset(&mut self) {
        self.mean = 0.0;
        self.sum = 0.0;
        self.min_sum = 0.0;
        self.count = 0;
    }

    pub fn sample_count(&self) -> usize {
        self.count
    }
}

// ─── Rate-of-change velocity detector (R01 / Phase 21) ───

/// Tracks per-dimension velocity (first derivative) and acceleration (second
/// derivative). A sudden spike in velocity that exceeds the historical mean
/// by `velocity_sigma` standard deviations indicates an attack ramp-up even
/// when absolute values haven't yet breached fixed thresholds.
#[derive(Debug, Clone)]
pub struct VelocityDetector {
    history: Vec<[f32; 9]>,
    window_cap: usize,
    velocity_sigma: f32,
}

/// Result from a velocity analysis pass.
#[derive(Debug, Clone)]
pub struct VelocityReport {
    pub anomalous_axes: Vec<String>,
    pub max_velocity: f32,
    pub max_acceleration: f32,
    pub score_boost: f32,
}

impl VelocityDetector {
    pub fn new(window_cap: usize, velocity_sigma: f32) -> Self {
        Self {
            history: Vec::with_capacity(window_cap),
            window_cap,
            velocity_sigma,
        }
    }

    pub fn sigma(&self) -> f32 { self.velocity_sigma }

    fn sample_to_array(s: &TelemetrySample) -> [f32; 9] {
        [
            s.cpu_load_pct,
            s.memory_load_pct,
            s.temperature_c,
            s.network_kbps,
            s.auth_failures as f32,
            s.battery_pct,
            s.integrity_drift,
            s.process_count as f32,
            s.disk_pressure_pct,
        ]
    }

    const AXIS_NAMES: [&'static str; 9] = [
        "cpu_load_pct", "memory_load_pct", "temperature_c", "network_kbps",
        "auth_failures", "battery_pct", "integrity_drift", "process_count",
        "disk_pressure_pct",
    ];

    /// Feed a new sample and return velocity anomalies.
    pub fn update(&mut self, sample: &TelemetrySample) -> VelocityReport {
        let arr = Self::sample_to_array(sample);
        if self.history.len() >= self.window_cap {
            self.history.remove(0);
        }
        self.history.push(arr);

        if self.history.len() < 3 {
            return VelocityReport {
                anomalous_axes: vec![],
                max_velocity: 0.0,
                max_acceleration: 0.0,
                score_boost: 0.0,
            };
        }

        let _n = self.history.len();
        let mut anomalous = Vec::new();
        let mut max_vel: f32 = 0.0;
        let mut max_acc: f32 = 0.0;
        let mut boost: f32 = 0.0;

        for dim in 0..9 {
            // Compute velocities (first differences)
            let velocities: Vec<f32> = self.history.windows(2)
                .map(|w| w[1][dim] - w[0][dim])
                .collect();

            // Last velocity
            let last_vel = velocities.last().copied().unwrap_or(0.0);
            let vel_abs = last_vel.abs();
            if vel_abs > max_vel { max_vel = vel_abs; }

            // Acceleration (second differences)
            if velocities.len() >= 2 {
                let tail = velocities.len();
                let acc = (velocities[tail - 1] - velocities[tail - 2]).abs();
                if acc > max_acc { max_acc = acc; }
            }

            // Mean and std of velocity history
            let v_mean: f32 = velocities.iter().sum::<f32>() / velocities.len() as f32;
            let v_var: f32 = velocities.iter()
                .map(|v| (v - v_mean).powi(2))
                .sum::<f32>() / velocities.len() as f32;
            let v_std = v_var.sqrt().max(0.001);

            // Check if latest velocity is an outlier (proper z-score)
            let z = (last_vel - v_mean).abs() / v_std;
            if z > self.velocity_sigma && vel_abs > 0.5 {
                anomalous.push(Self::AXIS_NAMES[dim].to_string());
                boost += (z - self.velocity_sigma) / 10.0;
            }
        }

        VelocityReport {
            anomalous_axes: anomalous,
            max_velocity: max_vel,
            max_acceleration: max_acc,
            score_boost: boost.min(2.5),
        }
    }

    pub fn window_len(&self) -> usize {
        self.history.len()
    }
}

// ─── Shannon entropy anomaly scorer (Phase 21) ───

/// Computes Shannon entropy over the distribution of telemetry values
/// in a sliding window. Abnormally low entropy (uniform/constant attack
/// traffic) or abnormally high entropy (randomised evasion) both signal
/// anomalous behaviour.
#[derive(Debug, Clone)]
pub struct EntropyDetector {
    window: Vec<[f32; 9]>,
    window_cap: usize,
    bins: usize,
}

/// Result from an entropy analysis pass.
#[derive(Debug, Clone)]
pub struct EntropyReport {
    pub entropies: Vec<(String, f32)>,
    pub anomalous_axes: Vec<String>,
    pub score_boost: f32,
}

impl EntropyDetector {
    pub fn new(window_cap: usize, bins: usize) -> Self {
        Self {
            window: Vec::with_capacity(window_cap),
            window_cap,
            bins: bins.max(4),
        }
    }

    pub fn window_len(&self) -> usize { self.window.len() }
    pub fn bins(&self) -> usize { self.bins }

    /// Feed a new sample and compute per-axis Shannon entropy.
    pub fn update(&mut self, sample: &TelemetrySample) -> EntropyReport {
        let arr = VelocityDetector::sample_to_array(sample);
        if self.window.len() >= self.window_cap {
            self.window.remove(0);
        }
        self.window.push(arr);

        if self.window.len() < 5 {
            return EntropyReport {
                entropies: vec![],
                anomalous_axes: vec![],
                score_boost: 0.0,
            };
        }

        let n = self.window.len() as f32;
        let mut entropies = Vec::new();
        let mut anomalous = Vec::new();
        let mut boost: f32 = 0.0;

        for dim in 0..9 {
            let values: Vec<f32> = self.window.iter().map(|a| a[dim]).collect();
            let min_v = values.iter().cloned().fold(f32::INFINITY, f32::min);
            let max_v = values.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
            let range = (max_v - min_v).max(0.001);

            // Bin the values
            let mut hist = vec![0u32; self.bins];
            for &v in &values {
                let idx = (((v - min_v) / range) * (self.bins as f32 - 1.0)) as usize;
                let idx = idx.min(self.bins - 1);
                hist[idx] += 1;
            }

            // Shannon entropy H = -Σ p*log2(p)
            let mut h: f32 = 0.0;
            for &count in &hist {
                if count > 0 {
                    let p = count as f32 / n;
                    h -= p * p.log2();
                }
            }

            let max_entropy = (self.bins as f32).log2();
            let name = VelocityDetector::AXIS_NAMES[dim].to_string();
            entropies.push((name.clone(), h));

            // Very low entropy = suspicious uniformity (cryptominer steady-state)
            if h < max_entropy * 0.15 && n >= 10.0 {
                anomalous.push(format!("{name}:low_entropy"));
                boost += 0.4;
            }
            // Very high entropy where it shouldn't be (e.g. randomised auth failures)
            if h > max_entropy * 0.9 && dim == 4 && n >= 10.0 {
                anomalous.push(format!("{name}:high_entropy"));
                boost += 0.6;
            }
        }

        EntropyReport {
            entropies,
            anomalous_axes: anomalous,
            score_boost: boost.min(2.0),
        }
    }
}

// ─── Compound multi-axis threat detector (Phase 21) ───

/// Detects coordinated multi-axis attacks where individual dimensions
/// may be below threshold but their simultaneous co-elevation indicates
/// a sophisticated attack pattern (e.g. CPU + network + auth rising
/// together).
#[derive(Debug, Clone)]
pub struct CompoundThreatDetector {
    /// Minimum fraction of axes that must be simultaneously elevated.
    pub min_concurrent_fraction: f32,
    /// Threshold: each axis must deviate by at least this fraction of
    /// its scale to count as "elevated".
    pub per_axis_threshold: f32,
}

/// Result from compound threat analysis.
#[derive(Debug, Clone)]
pub struct CompoundThreatReport {
    pub elevated_axes: Vec<String>,
    pub concurrent_fraction: f32,
    pub compound_score: f32,
    pub is_compound_attack: bool,
}

impl Default for CompoundThreatDetector {
    fn default() -> Self {
        Self {
            min_concurrent_fraction: 0.4,
            per_axis_threshold: 0.3,
        }
    }
}

impl CompoundThreatDetector {
    pub fn new(min_concurrent_fraction: f32, per_axis_threshold: f32) -> Self {
        Self { min_concurrent_fraction, per_axis_threshold }
    }

    /// Analyse how many axes are simultaneously elevated relative to
    /// their baseline contribution. Takes the per-signal contributions
    /// from `AnomalySignal`.
    pub fn evaluate(&self, signal: &AnomalySignal) -> CompoundThreatReport {
        self.evaluate_with_side_channel(signal, None)
    }

    /// Evaluate with optional side-channel risk fusion.
    /// When a `SideChannelReport` is provided and its `overall_risk` is
    /// "elevated" or "critical", the compound score is boosted.
    pub fn evaluate_with_side_channel(
        &self,
        signal: &AnomalySignal,
        side_channel: Option<&crate::side_channel::SideChannelReport>,
    ) -> CompoundThreatReport {
        // Count axes with non-trivial contribution
        let elevated: Vec<String> = signal.contributions.iter()
            .filter(|(_, v)| *v >= self.per_axis_threshold)
            .map(|(name, _)| name.to_string())
            .collect();

        let total_axes = 9.0_f32;
        let fraction = elevated.len() as f32 / total_axes;
        let is_compound = fraction >= self.min_concurrent_fraction;

        // Compound multiplier: the more axes are co-elevated, the greater
        // the effective threat (sophisticated coordinated attack)
        let mut compound_score = if is_compound {
            signal.score * (1.0 + fraction * 0.5)
        } else {
            signal.score
        };

        // Side-channel score fusion: boost when side-channel risk is elevated
        if let Some(sc) = side_channel {
            let sc_boost = match sc.overall_risk.as_str() {
                "critical" => 1.5,
                "elevated" => 0.8,
                "low" => 0.2,
                _ => 0.0,
            };
            compound_score += sc_boost;
        }

        CompoundThreatReport {
            elevated_axes: elevated,
            concurrent_fraction: fraction,
            compound_score,
            is_compound_attack: is_compound,
        }
    }
}

/// Multi-signal continual-learning monitor that wraps an `AnomalyDetector`
/// with per-dimension drift detection and automatic baseline re-learning.
pub struct ContinualLearner {
    pub detector: AnomalyDetector,
    drift_score: DriftDetector,
    relearn_count: usize,
    window: Vec<TelemetrySample>,
    window_cap: usize,
}

impl ContinualLearner {
    pub fn new(detector: AnomalyDetector, window_cap: usize) -> Self {
        Self {
            detector,
            drift_score: DriftDetector::new(0.5, 15.0),
            relearn_count: 0,
            window: Vec::with_capacity(window_cap),
            window_cap,
        }
    }

    /// Evaluate a sample and perform drift-triggered re-learning.
    ///
    /// If the drift detector fires, the detector baseline is reset and
    /// the recent window of samples is replayed so the model quickly
    /// adapts to the new distribution.
    pub fn step(&mut self, sample: &TelemetrySample) -> (AnomalySignal, Option<DriftResult>) {
        let signal = self.detector.evaluate(sample);

        // Maintain a sliding window for re-learning
        if self.window.len() >= self.window_cap {
            self.window.remove(0);
        }
        self.window.push(*sample);

        let drift = self.drift_score.update(signal.score as f64);
        if drift.drifted {
            // Concept drift detected — reset baseline and re-learn from window
            self.detector.reset_baseline();
            let window_copy: Vec<TelemetrySample> = self.window.clone();
            for ws in &window_copy {
                let _ = self.detector.evaluate(ws);
            }
            self.drift_score.reset();
            self.relearn_count += 1;
            // Re-evaluate the current sample against the fresh baseline
            let fresh_signal = self.detector.evaluate(sample);
            return (fresh_signal, Some(drift));
        }

        (signal, None)
    }

    pub fn relearn_count(&self) -> usize {
        self.relearn_count
    }

    pub fn window_len(&self) -> usize {
        self.window.len()
    }
}

// ─── Detection tuning profiles (Phase 29) ───

/// Pre-configured detection sensitivity profiles.
/// - **Aggressive**: Low thresholds, catches more threats but may increase FP rate.
/// - **Balanced**: Default settings, tuned for production use.
/// - **Quiet**: High thresholds, lower FP rate but may miss subtle attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TuningProfile {
    Aggressive,
    Balanced,
    Quiet,
}

impl Default for TuningProfile {
    fn default() -> Self {
        Self::Balanced
    }
}

impl TuningProfile {
    /// Returns the threshold multiplier applied to detection scales.
    /// Lower multiplier = more sensitive (more alerts).
    pub fn threshold_multiplier(&self) -> f32 {
        match self {
            Self::Aggressive => 0.6,
            Self::Balanced => 1.0,
            Self::Quiet => 1.8,
        }
    }

    /// Returns the learn threshold for the anomaly detector.
    pub fn learn_threshold(&self) -> f32 {
        match self {
            Self::Aggressive => 1.5,
            Self::Balanced => 2.5,
            Self::Quiet => 4.0,
        }
    }

    /// Returns a human-readable description.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Aggressive => "Maximum sensitivity — catches more threats but may increase false positives",
            Self::Balanced => "Default — tuned for production with good precision/recall balance",
            Self::Quiet => "Minimal alerts — high thresholds, lower false positives, may miss subtle attacks",
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Aggressive => "aggressive",
            Self::Balanced => "balanced",
            Self::Quiet => "quiet",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "aggressive" => Some(Self::Aggressive),
            "balanced" => Some(Self::Balanced),
            "quiet" => Some(Self::Quiet),
            _ => None,
        }
    }
}

/// Normalized threat score in the 0–100 range with severity label.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedScore {
    pub raw_score: f32,
    pub normalized: u8,
    pub severity: String,
    pub confidence: String,
}

/// Normalize an unbounded anomaly score to the 0–100 range.
/// Uses a sigmoid-like mapping: `100 * (1 - e^(-score/k))`.
pub fn normalize_score(raw: f32, confidence: f32) -> NormalizedScore {
    let k = 5.0_f32; // Controls curve steepness
    let normalized = (100.0 * (1.0 - (-raw / k).exp())).round().min(100.0).max(0.0) as u8;
    let severity = match normalized {
        0..=20 => "info",
        21..=40 => "low",
        41..=60 => "medium",
        61..=80 => "high",
        81..=100 => "critical",
        _ => "info",
    };
    let conf = match confidence {
        c if c >= 0.9 => "high",
        c if c >= 0.6 => "medium",
        _ => "low",
    };
    NormalizedScore {
        raw_score: raw,
        normalized,
        severity: severity.to_string(),
        confidence: conf.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::AnomalyDetector;
    use crate::telemetry::TelemetrySample;

    #[test]
    fn benign_samples_stay_low() {
        let mut detector = AnomalyDetector::default();
        let samples = [
            TelemetrySample {
                timestamp_ms: 1,
                cpu_load_pct: 12.0,
                memory_load_pct: 20.0,
                temperature_c: 35.0,
                network_kbps: 300.0,
                auth_failures: 0,
                battery_pct: 92.0,
                integrity_drift: 0.01,
                process_count: 50,
                disk_pressure_pct: 10.0,
            },
            TelemetrySample {
                timestamp_ms: 2,
                cpu_load_pct: 13.0,
                memory_load_pct: 21.0,
                temperature_c: 36.0,
                network_kbps: 320.0,
                auth_failures: 0,
                battery_pct: 91.0,
                integrity_drift: 0.01,
                process_count: 52,
                disk_pressure_pct: 11.0,
            },
            TelemetrySample {
                timestamp_ms: 3,
                cpu_load_pct: 14.0,
                memory_load_pct: 22.0,
                temperature_c: 36.5,
                network_kbps: 330.0,
                auth_failures: 0,
                battery_pct: 90.0,
                integrity_drift: 0.01,
                process_count: 51,
                disk_pressure_pct: 12.0,
            },
        ];

        let mut last_score = 0.0;
        for sample in &samples {
            last_score = detector.evaluate(sample).score;
        }

        assert!(last_score < 0.5);
    }

    #[test]
    fn auth_storm_scores_high() {
        let mut detector = AnomalyDetector::default();
        for timestamp in 0..4 {
            let _ = detector.evaluate(&TelemetrySample {
                timestamp_ms: timestamp,
                cpu_load_pct: 18.0,
                memory_load_pct: 24.0,
                temperature_c: 37.0,
                network_kbps: 500.0,
                auth_failures: 0,
                battery_pct: 88.0,
                integrity_drift: 0.02,
                process_count: 45,
                disk_pressure_pct: 8.0,
            });
        }

        let signal = detector.evaluate(&TelemetrySample {
            timestamp_ms: 5,
            cpu_load_pct: 62.0,
            memory_load_pct: 55.0,
            temperature_c: 49.0,
            network_kbps: 4400.0,
            auth_failures: 11,
            battery_pct: 63.0,
            integrity_drift: 0.17,
            process_count: 120,
            disk_pressure_pct: 65.0,
        });

        assert!(signal.score > 5.0);
        assert!(signal.reasons.iter().any(|reason| reason.contains("auth")));
    }

    #[test]
    fn snapshot_round_trip() {
        let mut detector = AnomalyDetector::default();
        detector.evaluate(&TelemetrySample {
            timestamp_ms: 1,
            cpu_load_pct: 20.0,
            memory_load_pct: 30.0,
            temperature_c: 38.0,
            network_kbps: 400.0,
            auth_failures: 0,
            battery_pct: 90.0,
            integrity_drift: 0.01,
            process_count: 40,
            disk_pressure_pct: 5.0,
        });

        let snapshot = detector.snapshot().unwrap();
        assert_eq!(snapshot.observed_samples, 1);

        let mut detector2 = AnomalyDetector::default();
        detector2.restore_baseline(&snapshot);
        assert_eq!(detector2.snapshot().unwrap().observed_samples, 1);
    }

    #[test]
    fn frozen_mode_prevents_baseline_update() {
        let mut detector = AnomalyDetector::default();
        // Initialize baseline
        detector.evaluate(&TelemetrySample {
            timestamp_ms: 1,
            cpu_load_pct: 20.0,
            memory_load_pct: 30.0,
            temperature_c: 38.0,
            network_kbps: 400.0,
            auth_failures: 0,
            battery_pct: 90.0,
            integrity_drift: 0.01,
            process_count: 40,
            disk_pressure_pct: 5.0,
        });
        let snap_before = detector.snapshot().unwrap();

        detector.set_adaptation(super::AdaptationMode::Frozen);
        // Feed a benign sample — should NOT update baseline
        detector.evaluate(&TelemetrySample {
            timestamp_ms: 2,
            cpu_load_pct: 22.0,
            memory_load_pct: 32.0,
            temperature_c: 39.0,
            network_kbps: 420.0,
            auth_failures: 0,
            battery_pct: 89.0,
            integrity_drift: 0.01,
            process_count: 42,
            disk_pressure_pct: 6.0,
        });
        let snap_after = detector.snapshot().unwrap();
        assert!((snap_before.cpu_load_pct - snap_after.cpu_load_pct).abs() < 0.001);
    }

    #[test]
    fn contributions_sum_to_score() {
        let mut detector = AnomalyDetector::default();
        // Build baseline over warmup period
        for ts in 0..5 {
            detector.evaluate(&TelemetrySample {
                timestamp_ms: ts,
                cpu_load_pct: 18.0,
                memory_load_pct: 24.0,
                temperature_c: 37.0,
                network_kbps: 500.0,
                auth_failures: 0,
                battery_pct: 88.0,
                integrity_drift: 0.02,
                process_count: 45,
                disk_pressure_pct: 8.0,
            });
        }
        // Inject anomalous sample
        let signal = detector.evaluate(&TelemetrySample {
            timestamp_ms: 6,
            cpu_load_pct: 62.0,
            memory_load_pct: 55.0,
            temperature_c: 49.0,
            network_kbps: 4400.0,
            auth_failures: 11,
            battery_pct: 63.0,
            integrity_drift: 0.17,
            process_count: 120,
            disk_pressure_pct: 65.0,
        });

        assert!(
            !signal.contributions.is_empty(),
            "anomaly should have contributions"
        );
        let sum: f32 = signal.contributions.iter().map(|(_, v)| v).sum();
        assert!(
            (sum - signal.score).abs() < 0.01,
            "contribution sum {sum:.4} should match score {:.4}",
            signal.score,
        );
        // Verify that CPU contribution is present and labelled
        assert!(
            signal
                .contributions
                .iter()
                .any(|(name, _)| *name == "cpu_load_pct"),
            "expected cpu_load_pct in contributions"
        );
    }

    #[test]
    fn benign_samples_have_no_contributions() {
        let mut detector = AnomalyDetector::default();
        let signal = detector.evaluate(&TelemetrySample {
            timestamp_ms: 1,
            cpu_load_pct: 20.0,
            memory_load_pct: 30.0,
            temperature_c: 38.0,
            network_kbps: 400.0,
            auth_failures: 0,
            battery_pct: 90.0,
            integrity_drift: 0.01,
            process_count: 40,
            disk_pressure_pct: 5.0,
        });
        assert!(
            signal.contributions.is_empty(),
            "first sample (baseline init) should have no contributions"
        );
    }

    #[test]
    fn drift_detector_fires_on_shift() {
        let mut dd = super::DriftDetector::new(0.1, 5.0);
        // Feed stable values
        for _ in 0..20 {
            let r = dd.update(1.0);
            assert!(!r.drifted);
        }
        // Sudden shift upward
        let mut fired = false;
        for _ in 0..50 {
            let r = dd.update(10.0);
            if r.drifted {
                fired = true;
                break;
            }
        }
        assert!(fired, "drift detector should fire after distribution shift");
    }

    #[test]
    fn drift_detector_reset_clears_state() {
        let mut dd = super::DriftDetector::new(0.1, 5.0);
        for _ in 0..10 {
            dd.update(5.0);
        }
        dd.reset();
        assert_eq!(dd.sample_count(), 0);
    }

    #[test]
    fn continual_learner_relearns_on_drift() {
        let detector = AnomalyDetector::default();
        let mut learner = super::ContinualLearner::new(detector, 20);

        // Feed stable benign samples
        let benign = TelemetrySample {
            timestamp_ms: 0,
            cpu_load_pct: 15.0,
            memory_load_pct: 25.0,
            temperature_c: 36.0,
            network_kbps: 300.0,
            auth_failures: 0,
            battery_pct: 90.0,
            integrity_drift: 0.01,
            process_count: 40,
            disk_pressure_pct: 5.0,
        };
        for i in 0..10 {
            let mut s = benign;
            s.timestamp_ms = i;
            learner.step(&s);
        }
        assert_eq!(learner.relearn_count(), 0);

        // Feed high-anomaly samples to trigger drift
        let anomalous = TelemetrySample {
            timestamp_ms: 100,
            cpu_load_pct: 95.0,
            memory_load_pct: 90.0,
            temperature_c: 70.0,
            network_kbps: 20_000.0,
            auth_failures: 30,
            battery_pct: 20.0,
            integrity_drift: 0.5,
            process_count: 300,
            disk_pressure_pct: 95.0,
        };
        let mut drift_triggered = false;
        for i in 0..50 {
            let mut s = anomalous;
            s.timestamp_ms = 100 + i;
            let (_, drift) = learner.step(&s);
            if drift.is_some() {
                drift_triggered = true;
                break;
            }
        }
        assert!(
            drift_triggered,
            "continual learner should trigger re-learn on distribution shift"
        );
        assert!(learner.relearn_count() >= 1);
    }

    #[test]
    fn velocity_detector_flags_rapid_ramp() {
        use super::VelocityDetector;

        let mut vel = VelocityDetector::new(20, 2.0);
        // Feed stable samples
        for i in 0..10 {
            let s = TelemetrySample {
                timestamp_ms: i,
                cpu_load_pct: 15.0,
                memory_load_pct: 25.0,
                temperature_c: 38.0,
                network_kbps: 400.0,
                auth_failures: 0,
                battery_pct: 90.0,
                integrity_drift: 0.01,
                process_count: 50,
                disk_pressure_pct: 10.0,
            };
            vel.update(&s);
        }
        // Inject rapid CPU ramp
        let report = vel.update(&TelemetrySample {
            timestamp_ms: 10,
            cpu_load_pct: 85.0,
            memory_load_pct: 25.0,
            temperature_c: 38.0,
            network_kbps: 400.0,
            auth_failures: 0,
            battery_pct: 90.0,
            integrity_drift: 0.01,
            process_count: 50,
            disk_pressure_pct: 10.0,
        });
        assert!(!report.anomalous_axes.is_empty(), "should flag velocity anomaly on cpu ramp");
        assert!(report.score_boost > 0.0);
    }

    #[test]
    fn entropy_detector_flags_uniformity() {
        use super::EntropyDetector;

        let mut ent = EntropyDetector::new(30, 8);
        // Feed identical samples (zero entropy = suspicious)
        for i in 0..15 {
            let s = TelemetrySample {
                timestamp_ms: i,
                cpu_load_pct: 80.0,
                memory_load_pct: 60.0,
                temperature_c: 55.0,
                network_kbps: 5000.0,
                auth_failures: 0,
                battery_pct: 80.0,
                integrity_drift: 0.05,
                process_count: 100,
                disk_pressure_pct: 30.0,
            };
            ent.update(&s);
        }
        let report = ent.update(&TelemetrySample {
            timestamp_ms: 15,
            cpu_load_pct: 80.0,
            memory_load_pct: 60.0,
            temperature_c: 55.0,
            network_kbps: 5000.0,
            auth_failures: 0,
            battery_pct: 80.0,
            integrity_drift: 0.05,
            process_count: 100,
            disk_pressure_pct: 30.0,
        });
        assert!(!report.anomalous_axes.is_empty(), "constant values should flag low entropy");
        assert!(report.score_boost > 0.0);
    }

    #[test]
    fn compound_detector_flags_multi_axis() {
        use super::CompoundThreatDetector;

        let compound = CompoundThreatDetector::default();
        // Build a signal with 5 axes contributing
        let signal = super::AnomalySignal {
            score: 4.0,
            confidence: 1.0,
            suspicious_axes: 5,
            reasons: vec!["cpu".into(), "mem".into(), "net".into(), "auth".into(), "disk".into()],
            contributions: vec![
                ("cpu_load_pct", 0.8),
                ("memory_load_pct", 0.7),
                ("network_kbps", 1.0),
                ("auth_failures", 0.9),
                ("disk_pressure_pct", 0.6),
            ],
        };
        let report = compound.evaluate(&signal);
        assert!(report.is_compound_attack, "5 of 9 axes elevated should trigger compound");
        assert!(report.compound_score > signal.score, "compound score should be boosted");
    }

    #[test]
    fn side_channel_fusion_boosts_score() {
        use super::CompoundThreatDetector;
        use crate::side_channel::SideChannelReport;

        let compound = CompoundThreatDetector::default();
        let signal = super::AnomalySignal {
            score: 3.0,
            confidence: 1.0,
            suspicious_axes: 1,
            reasons: vec!["cpu".into()],
            contributions: vec![("cpu_load_pct", 0.5)],
        };
        let sc_report = SideChannelReport {
            timing_anomalies: 12,
            cache_alerts: 3,
            covert_channels: 1,
            overall_risk: "critical".into(),
        };
        let without = compound.evaluate(&signal);
        let with = compound.evaluate_with_side_channel(&signal, Some(&sc_report));
        assert!(with.compound_score > without.compound_score, "side-channel fusion should boost score");
    }

    #[test]
    fn slow_attack_cumulative_detection() {
        use super::SlowAttackDetector;
        let mut det = SlowAttackDetector::default();
        // Feed gradual auth failures: 1 per sample over 50 samples
        for _ in 0..50 {
            let sample = TelemetrySample {
                timestamp_ms: 0,
                cpu_load_pct: 30.0,
                memory_load_pct: 40.0,
                temperature_c: 50.0,
                network_kbps: 100.0,
                auth_failures: 1,
                battery_pct: 80.0,
                integrity_drift: 0.0,
                process_count: 100,
                disk_pressure_pct: 30.0,
            };
            det.observe(&sample);
        }
        let report = det.evaluate();
        assert!(report.cumulative_auth_failures >= 50);
        assert!(report.auth_failure_rate > 0.0);
    }

    #[test]
    fn tuning_profile_thresholds() {
        use super::TuningProfile;
        assert!(TuningProfile::Aggressive.threshold_multiplier() < 1.0);
        assert!((TuningProfile::Balanced.threshold_multiplier() - 1.0).abs() < 0.001);
        assert!(TuningProfile::Quiet.threshold_multiplier() > 1.0);
        assert!(TuningProfile::Aggressive.learn_threshold() < TuningProfile::Balanced.learn_threshold());
        assert!(TuningProfile::Balanced.learn_threshold() < TuningProfile::Quiet.learn_threshold());
    }

    #[test]
    fn tuning_profile_round_trip() {
        use super::TuningProfile;
        for p in [TuningProfile::Aggressive, TuningProfile::Balanced, TuningProfile::Quiet] {
            let s = p.as_str();
            assert_eq!(TuningProfile::from_str(s), Some(p));
        }
        assert_eq!(TuningProfile::from_str("unknown"), None);
    }

    #[test]
    fn normalize_score_bounds() {
        use super::normalize_score;
        let low = normalize_score(0.0, 1.0);
        assert_eq!(low.normalized, 0);
        assert_eq!(low.severity, "info");

        let mid = normalize_score(5.0, 0.8);
        assert!(mid.normalized > 40 && mid.normalized < 80);
        assert_eq!(mid.confidence, "medium");

        let high = normalize_score(25.0, 1.0);
        assert!(high.normalized >= 95);
        assert_eq!(high.severity, "critical");
        assert_eq!(high.confidence, "high");
    }
}

// ─── Slow / Low-and-Slow Attack Detector ──────────────────────────

/// Detects gradual, below-threshold attacks that accumulate over
/// long horizons (hours/days). Maintains sliding-window aggregates
/// and cumulative counters alongside the fast EWMA baseline.
#[derive(Debug, Clone)]
pub struct SlowAttackConfig {
    /// Short window for rate computation (samples).
    pub short_window: usize,
    /// Long window for cumulative tracking (samples).
    pub long_window: usize,
    /// Cumulative auth failure threshold to trigger alert.
    pub auth_cumulative_threshold: u64,
    /// Auth failure rate (per sample) that is considered suspicious.
    pub auth_rate_threshold: f32,
    /// Network bytes cumulative anomaly threshold (KB).
    pub network_cumulative_threshold: f64,
    /// Score threshold for alert.
    pub alert_threshold: f32,
}

impl Default for SlowAttackConfig {
    fn default() -> Self {
        Self {
            short_window: 60,       // ~1 hour at 1 sample/min
            long_window: 1440,      // ~24 hours at 1 sample/min
            auth_cumulative_threshold: 100,
            auth_rate_threshold: 0.5,
            network_cumulative_threshold: 500_000.0, // 500 MB
            alert_threshold: 3.0,
        }
    }
}

/// Result of slow-attack analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlowAttackReport {
    /// Combined slow-attack risk score.
    pub score: f32,
    /// Whether the score exceeds the alert threshold.
    pub alert: bool,
    /// Cumulative auth failures in the long window.
    pub cumulative_auth_failures: u64,
    /// Auth failure rate (failures per sample) in short window.
    pub auth_failure_rate: f32,
    /// Cumulative network KB in the long window.
    pub cumulative_network_kb: f64,
    /// Number of samples observed.
    pub samples_observed: u64,
    /// Detected patterns.
    pub patterns: Vec<String>,
    /// MITRE ATT&CK technique IDs.
    pub mitre_techniques: Vec<String>,
}

/// Slow-attack detector using long-horizon aggregation.
pub struct SlowAttackDetector {
    config: SlowAttackConfig,
    /// Short-window auth failure ring.
    short_auth: std::collections::VecDeque<u32>,
    /// Long-window auth failure ring.
    long_auth: std::collections::VecDeque<u32>,
    /// Long-window network KB ring.
    long_network: std::collections::VecDeque<f32>,
    /// Total samples observed.
    total_samples: u64,
}

impl std::fmt::Debug for SlowAttackDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlowAttackDetector")
            .field("total_samples", &self.total_samples)
            .finish()
    }
}

impl Default for SlowAttackDetector {
    fn default() -> Self {
        Self::new(SlowAttackConfig::default())
    }
}

impl SlowAttackDetector {
    pub fn new(config: SlowAttackConfig) -> Self {
        Self {
            short_auth: std::collections::VecDeque::with_capacity(config.short_window),
            long_auth: std::collections::VecDeque::with_capacity(config.long_window),
            long_network: std::collections::VecDeque::with_capacity(config.long_window),
            config,
            total_samples: 0,
        }
    }

    /// Ingest a telemetry sample.
    pub fn observe(&mut self, sample: &TelemetrySample) {
        self.total_samples += 1;

        // Short window
        if self.short_auth.len() >= self.config.short_window {
            self.short_auth.pop_front();
        }
        self.short_auth.push_back(sample.auth_failures);

        // Long window
        if self.long_auth.len() >= self.config.long_window {
            self.long_auth.pop_front();
        }
        self.long_auth.push_back(sample.auth_failures);

        if self.long_network.len() >= self.config.long_window {
            self.long_network.pop_front();
        }
        self.long_network.push_back(sample.network_kbps);
    }

    /// Evaluate slow-attack signals.
    pub fn evaluate(&self) -> SlowAttackReport {
        let cumulative_auth: u64 = self.long_auth.iter().map(|&f| f as u64).sum();
        let short_auth_sum: u32 = self.short_auth.iter().sum();
        let auth_rate = if self.short_auth.is_empty() {
            0.0
        } else {
            short_auth_sum as f32 / self.short_auth.len() as f32
        };

        let cumulative_network_kb: f64 = self.long_network.iter().map(|&k| k as f64).sum();

        let mut score = 0.0f32;
        let mut patterns = Vec::new();

        // Auth failure accumulation
        if cumulative_auth >= self.config.auth_cumulative_threshold {
            let ratio = cumulative_auth as f32 / self.config.auth_cumulative_threshold as f32;
            score += ratio.min(3.0) * 1.5;
            patterns.push(format!(
                "cumulative_auth_failures:{cumulative_auth} (threshold:{})",
                self.config.auth_cumulative_threshold
            ));
        }

        // Sustained auth failure rate (below burst threshold but persistent)
        if auth_rate >= self.config.auth_rate_threshold && self.short_auth.len() >= 10 {
            score += (auth_rate / self.config.auth_rate_threshold).min(2.0);
            patterns.push(format!("sustained_auth_rate:{auth_rate:.2}/sample"));
        }

        // Cumulative network anomaly (slow exfiltration)
        if cumulative_network_kb >= self.config.network_cumulative_threshold {
            let ratio = cumulative_network_kb / self.config.network_cumulative_threshold;
            score += (ratio as f32).min(2.0);
            patterns.push(format!(
                "cumulative_network_kb:{cumulative_network_kb:.0} (threshold:{})",
                self.config.network_cumulative_threshold
            ));
        }

        let score = score.min(10.0);
        let alert = score >= self.config.alert_threshold;

        let mut mitre = Vec::new();
        if alert {
            if cumulative_auth >= self.config.auth_cumulative_threshold {
                mitre.push("T1110".into()); // Brute Force
                mitre.push("T1110.001".into()); // Password Guessing
            }
            if cumulative_network_kb >= self.config.network_cumulative_threshold {
                mitre.push("T1048".into()); // Exfiltration Over Alternative Protocol
                mitre.push("T1030".into()); // Data Transfer Size Limits
            }
        }

        SlowAttackReport {
            score,
            alert,
            cumulative_auth_failures: cumulative_auth,
            auth_failure_rate: auth_rate,
            cumulative_network_kb,
            samples_observed: self.total_samples,
            patterns,
            mitre_techniques: mitre,
        }
    }

    /// Get the configuration.
    pub fn config(&self) -> &SlowAttackConfig {
        &self.config
    }

    /// Total samples observed.
    pub fn total_samples(&self) -> u64 {
        self.total_samples
    }
}
