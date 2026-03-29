use crate::detector::AnomalySignal;
use crate::telemetry::TelemetrySample;

/// Fixed-threshold baseline detector for paper comparison against the adaptive
/// EWMA detector (T111). Each signal dimension has a static upper threshold.
/// The anomaly score is the number of breached thresholds, normalised into the
/// same 0–10 range used by `AnomalyDetector`.
#[derive(Debug, Clone)]
pub struct FixedThresholdDetector {
    pub cpu_max: f32,
    pub memory_max: f32,
    pub temperature_max: f32,
    pub network_max: f32,
    pub auth_failures_max: u32,
    pub integrity_drift_max: f32,
    pub process_count_max: u32,
    pub disk_pressure_max: f32,
    pub battery_min: f32,
}

impl Default for FixedThresholdDetector {
    fn default() -> Self {
        Self {
            cpu_max: 70.0,
            memory_max: 65.0,
            temperature_max: 50.0,
            network_max: 1500.0,
            auth_failures_max: 5,
            integrity_drift_max: 0.10,
            process_count_max: 120,
            disk_pressure_max: 40.0,
            battery_min: 15.0,
        }
    }
}

impl FixedThresholdDetector {
    pub fn evaluate(&self, sample: &TelemetrySample) -> AnomalySignal {
        let mut breached: usize = 0;
        let mut reasons = Vec::new();
        let mut contributions: Vec<(&'static str, f32)> = Vec::new();

        let total_dimensions: f32 = 9.0;

        if sample.cpu_load_pct > self.cpu_max {
            breached += 1;
            reasons.push(format!(
                "cpu_load_pct {} > {}",
                sample.cpu_load_pct, self.cpu_max
            ));
            contributions.push(("cpu_load_pct", 10.0 / total_dimensions));
        }
        if sample.memory_load_pct > self.memory_max {
            breached += 1;
            reasons.push(format!(
                "memory_load_pct {} > {}",
                sample.memory_load_pct, self.memory_max
            ));
            contributions.push(("memory_load_pct", 10.0 / total_dimensions));
        }
        if sample.temperature_c > self.temperature_max {
            breached += 1;
            reasons.push(format!(
                "temperature_c {} > {}",
                sample.temperature_c, self.temperature_max
            ));
            contributions.push(("temperature_c", 10.0 / total_dimensions));
        }
        if sample.network_kbps > self.network_max {
            breached += 1;
            reasons.push(format!(
                "network_kbps {} > {}",
                sample.network_kbps, self.network_max
            ));
            contributions.push(("network_kbps", 10.0 / total_dimensions));
        }
        if sample.auth_failures > self.auth_failures_max {
            breached += 1;
            reasons.push(format!(
                "auth_failures {} > {}",
                sample.auth_failures, self.auth_failures_max
            ));
            contributions.push(("auth_failures", 10.0 / total_dimensions));
        }
        if sample.integrity_drift > self.integrity_drift_max {
            breached += 1;
            reasons.push(format!(
                "integrity_drift {} > {}",
                sample.integrity_drift, self.integrity_drift_max
            ));
            contributions.push(("integrity_drift", 10.0 / total_dimensions));
        }
        if sample.process_count > self.process_count_max {
            breached += 1;
            reasons.push(format!(
                "process_count {} > {}",
                sample.process_count, self.process_count_max
            ));
            contributions.push(("process_count", 10.0 / total_dimensions));
        }
        if sample.disk_pressure_pct > self.disk_pressure_max {
            breached += 1;
            reasons.push(format!(
                "disk_pressure_pct {} > {}",
                sample.disk_pressure_pct, self.disk_pressure_max
            ));
            contributions.push(("disk_pressure_pct", 10.0 / total_dimensions));
        }
        if sample.battery_pct < self.battery_min {
            breached += 1;
            reasons.push(format!(
                "battery_pct {} < {}",
                sample.battery_pct, self.battery_min
            ));
            contributions.push(("battery_pct", 10.0 / total_dimensions));
        }

        let score = (breached as f32 / total_dimensions) * 10.0;

        if reasons.is_empty() {
            reasons.push("all signals within static thresholds".to_string());
        }

        AnomalySignal {
            score,
            confidence: 1.0,
            suspicious_axes: breached,
            reasons,
            contributions,
        }
    }
}

/// Run benchmark using the fixed-threshold detector. Analogous to
/// `benchmark::run_benchmark` but for the static baseline.
pub fn run_fixed_benchmark(
    detector: &FixedThresholdDetector,
    labeled_samples: &[(TelemetrySample, bool)],
    threshold: f32,
) -> crate::benchmark::BenchmarkResult {
    let mut harness = crate::benchmark::BenchmarkHarness::new();
    for (sample, is_anomaly) in labeled_samples {
        let signal = detector.evaluate(sample);
        let predicted = signal.score >= threshold;
        harness.record(predicted, *is_anomaly);
        harness.record_contributions(&signal.contributions);
    }
    harness.result()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::TelemetrySample;

    fn benign_sample() -> TelemetrySample {
        TelemetrySample {
            timestamp_ms: 1,
            cpu_load_pct: 15.0,
            memory_load_pct: 25.0,
            temperature_c: 36.0,
            network_kbps: 400.0,
            auth_failures: 0,
            battery_pct: 90.0,
            integrity_drift: 0.01,
            process_count: 40,
            disk_pressure_pct: 10.0,
        }
    }

    fn attack_sample() -> TelemetrySample {
        TelemetrySample {
            timestamp_ms: 2,
            cpu_load_pct: 92.0,
            memory_load_pct: 85.0,
            temperature_c: 58.0,
            network_kbps: 3000.0,
            auth_failures: 20,
            battery_pct: 5.0,
            integrity_drift: 0.25,
            process_count: 200,
            disk_pressure_pct: 80.0,
        }
    }

    #[test]
    fn benign_scores_zero() {
        let detector = FixedThresholdDetector::default();
        let signal = detector.evaluate(&benign_sample());
        assert_eq!(signal.score, 0.0);
        assert_eq!(signal.suspicious_axes, 0);
        assert!(signal.reasons[0].contains("within static thresholds"));
    }

    #[test]
    fn attack_triggers_all_thresholds() {
        let detector = FixedThresholdDetector::default();
        let signal = detector.evaluate(&attack_sample());
        assert_eq!(signal.suspicious_axes, 9);
        assert!((signal.score - 10.0).abs() < 0.01);
    }

    #[test]
    fn partial_breach() {
        let detector = FixedThresholdDetector::default();
        let mut sample = benign_sample();
        sample.cpu_load_pct = 85.0;
        sample.auth_failures = 10;
        let signal = detector.evaluate(&sample);
        assert_eq!(signal.suspicious_axes, 2);
        assert!(signal.score > 0.0 && signal.score < 10.0);
    }

    #[test]
    fn custom_thresholds() {
        let detector = FixedThresholdDetector {
            cpu_max: 20.0,
            ..Default::default()
        };
        let mut sample = benign_sample();
        sample.cpu_load_pct = 25.0;
        let signal = detector.evaluate(&sample);
        assert_eq!(signal.suspicious_axes, 1);
    }

    #[test]
    fn run_fixed_benchmark_sanity() {
        let detector = FixedThresholdDetector::default();
        let labeled = vec![
            (benign_sample(), false),
            (benign_sample(), false),
            (attack_sample(), true),
            (attack_sample(), true),
        ];
        let result = run_fixed_benchmark(&detector, &labeled, 2.0);
        assert_eq!(result.true_positives, 2);
        assert_eq!(result.true_negatives, 2);
        assert_eq!(result.false_positives, 0);
        assert_eq!(result.false_negatives, 0);
        assert!((result.f1 - 1.0).abs() < 0.001);
    }

    #[test]
    fn contributions_sum_to_score() {
        let detector = FixedThresholdDetector::default();
        let signal = detector.evaluate(&attack_sample());
        let total: f32 = signal.contributions.iter().map(|(_, v)| v).sum();
        assert!((total - signal.score).abs() < 0.01);
    }
}
