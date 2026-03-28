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
            learn_threshold: 1.35,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AnomalySignal {
    pub score: f32,
    pub confidence: f32,
    pub suspicious_axes: usize,
    pub reasons: Vec<String>,
}

/// Controls how the detector updates its learned baseline (T041).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AdaptationMode {
    /// Normal EWMA-based learning (default).
    Normal,
    /// Freeze the baseline — evaluate but never update.
    Frozen,
    /// Decay the baseline toward a neutral midpoint at the given rate
    /// per sample. Useful for slowly "forgetting" to detect gradual
    /// poisoning.
    Decay(f32),
}

impl Default for AdaptationMode {
    fn default() -> Self {
        Self::Normal
    }
}

pub struct AnomalyDetector {
    config: DetectorConfig,
    baseline: Option<TelemetryBaseline>,
    observed_samples: usize,
    adaptation: AdaptationMode,
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
        }
    }

    /// Set the baseline adaptation mode (T041).
    pub fn set_adaptation(&mut self, mode: AdaptationMode) {
        self.adaptation = mode;
    }

    pub fn adaptation(&self) -> AdaptationMode {
        self.adaptation
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
                }
            }
            Some(mut baseline) => {
                let mut reasons = Vec::new();
                let mut suspicious_axes = 0usize;
                let history_factor = (self.observed_samples as f32
                    / self.config.warmup_samples as f32)
                    .clamp(0.35, 1.0);

                let mut score = 0.0;
                score += weighted_positive_delta(
                    sample.cpu_load_pct - baseline.cpu_load_pct,
                    18.0,
                    0.85,
                    "cpu load spike",
                    &mut reasons,
                    &mut suspicious_axes,
                );
                score += weighted_positive_delta(
                    sample.memory_load_pct - baseline.memory_load_pct,
                    14.0,
                    0.7,
                    "memory pressure increase",
                    &mut reasons,
                    &mut suspicious_axes,
                );
                score += weighted_positive_delta(
                    sample.temperature_c - baseline.temperature_c,
                    7.0,
                    0.8,
                    "thermal deviation",
                    &mut reasons,
                    &mut suspicious_axes,
                );
                score += weighted_positive_delta(
                    sample.network_kbps - baseline.network_kbps,
                    1800.0,
                    1.1,
                    "network burst",
                    &mut reasons,
                    &mut suspicious_axes,
                );
                score += weighted_positive_delta(
                    sample.auth_failures as f32 - baseline.auth_failures,
                    3.0,
                    1.6,
                    "auth failures surge",
                    &mut reasons,
                    &mut suspicious_axes,
                );
                score += weighted_positive_delta(
                    sample.integrity_drift - baseline.integrity_drift,
                    0.06,
                    1.9,
                    "integrity drift increase",
                    &mut reasons,
                    &mut suspicious_axes,
                );

                // T014: process count anomaly
                score += weighted_positive_delta(
                    sample.process_count as f32 - baseline.process_count,
                    20.0,
                    0.65,
                    "process count spike",
                    &mut reasons,
                    &mut suspicious_axes,
                );

                // T014: disk pressure anomaly
                score += weighted_positive_delta(
                    sample.disk_pressure_pct - baseline.disk_pressure_pct,
                    25.0,
                    0.6,
                    "disk pressure increase",
                    &mut reasons,
                    &mut suspicious_axes,
                );

                if sample.battery_pct < baseline.battery_pct - 18.0 {
                    score += 0.35;
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
                        baseline.cpu_load_pct = blend(baseline.cpu_load_pct, mid.cpu_load_pct, rate);
                        baseline.memory_load_pct = blend(baseline.memory_load_pct, mid.memory_load_pct, rate);
                        baseline.temperature_c = blend(baseline.temperature_c, mid.temperature_c, rate);
                        baseline.network_kbps = blend(baseline.network_kbps, mid.network_kbps, rate);
                        baseline.auth_failures = blend(baseline.auth_failures, mid.auth_failures, rate);
                        baseline.battery_pct = blend(baseline.battery_pct, mid.battery_pct, rate);
                        baseline.integrity_drift = blend(baseline.integrity_drift, mid.integrity_drift, rate);
                        baseline.process_count = blend(baseline.process_count, mid.process_count, rate);
                        baseline.disk_pressure_pct = blend(baseline.disk_pressure_pct, mid.disk_pressure_pct, rate);
                    }
                }

                self.baseline = Some(baseline);
                self.observed_samples += 1;

                if reasons.is_empty() {
                    reasons.push("within learned baseline".to_string());
                }

                AnomalySignal {
                    score,
                    confidence: history_factor,
                    suspicious_axes,
                    reasons,
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

    let normalized = delta / scale;
    if normalized >= 0.5 {
        reasons.push(format!("{label} (+{delta:.2})"));
        *suspicious_axes += 1;
    }

    normalized * weight
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
}
