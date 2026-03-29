use std::collections::BTreeMap;

use crate::detector::AnomalyDetector;
use crate::telemetry::TelemetrySample;

#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    pub true_positives: usize,
    pub false_positives: usize,
    pub true_negatives: usize,
    pub false_negatives: usize,
    pub precision: f32,
    pub recall: f32,
    pub f1: f32,
    pub accuracy: f32,
    /// Average per-signal contribution across all samples (T113).
    /// Sorted by signal name. Empty when collected without attribution.
    pub signal_contributions: Vec<(String, f32)>,
}

#[derive(Default)]
pub struct BenchmarkHarness {
    true_positives: usize,
    false_positives: usize,
    true_negatives: usize,
    false_negatives: usize,
    contribution_sums: BTreeMap<String, f32>,
    sample_count: usize,
}

impl BenchmarkHarness {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, predicted: bool, actual: bool) {
        match (predicted, actual) {
            (true, true) => self.true_positives += 1,
            (true, false) => self.false_positives += 1,
            (false, true) => self.false_negatives += 1,
            (false, false) => self.true_negatives += 1,
        }
    }

    /// Record per-signal contributions from an anomaly signal evaluation.
    pub fn record_contributions(&mut self, contributions: &[(&str, f32)]) {
        self.sample_count += 1;
        for (name, value) in contributions {
            *self
                .contribution_sums
                .entry((*name).to_string())
                .or_insert(0.0) += value;
        }
    }

    pub fn result(&self) -> BenchmarkResult {
        let tp = self.true_positives as f32;
        let fp = self.false_positives as f32;
        let tn = self.true_negatives as f32;
        let fn_ = self.false_negatives as f32;
        let total = tp + fp + tn + fn_;

        let precision = if tp + fp > 0.0 { tp / (tp + fp) } else { 0.0 };
        let recall = if tp + fn_ > 0.0 { tp / (tp + fn_) } else { 0.0 };
        let f1 = if precision + recall > 0.0 {
            2.0 * precision * recall / (precision + recall)
        } else {
            0.0
        };
        let accuracy = if total > 0.0 { (tp + tn) / total } else { 0.0 };

        let signal_contributions: Vec<(String, f32)> = if self.sample_count > 0 {
            self.contribution_sums
                .iter()
                .map(|(name, sum)| (name.clone(), sum / self.sample_count as f32))
                .collect()
        } else {
            Vec::new()
        };

        BenchmarkResult {
            true_positives: self.true_positives,
            false_positives: self.false_positives,
            true_negatives: self.true_negatives,
            false_negatives: self.false_negatives,
            precision,
            recall,
            f1,
            accuracy,
            signal_contributions,
        }
    }
}

pub fn run_benchmark(
    detector: &mut AnomalyDetector,
    labeled_samples: &[(TelemetrySample, bool)],
    threshold: f32,
) -> BenchmarkResult {
    let mut harness = BenchmarkHarness::new();
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
    use super::{BenchmarkHarness, run_benchmark};
    use crate::detector::AnomalyDetector;
    use crate::telemetry::TelemetrySample;

    #[test]
    fn perfect_classification() {
        let mut harness = BenchmarkHarness::new();
        harness.record(true, true);
        harness.record(true, true);
        harness.record(false, false);
        harness.record(false, false);

        let result = harness.result();
        assert!((result.precision - 1.0).abs() < 0.001);
        assert!((result.recall - 1.0).abs() < 0.001);
        assert!((result.f1 - 1.0).abs() < 0.001);
        assert!((result.accuracy - 1.0).abs() < 0.001);
    }

    #[test]
    fn all_false_positives() {
        let mut harness = BenchmarkHarness::new();
        harness.record(true, false);
        harness.record(true, false);

        let result = harness.result();
        assert_eq!(result.precision, 0.0);
        assert_eq!(result.false_positives, 2);
    }

    #[test]
    fn mixed_results() {
        let mut harness = BenchmarkHarness::new();
        harness.record(true, true); // TP
        harness.record(true, false); // FP
        harness.record(false, true); // FN
        harness.record(false, false); // TN

        let result = harness.result();
        assert!((result.precision - 0.5).abs() < 0.001);
        assert!((result.recall - 0.5).abs() < 0.001);
        assert!((result.accuracy - 0.5).abs() < 0.001);
    }

    #[test]
    fn run_benchmark_with_detector() {
        let mut detector = AnomalyDetector::default();
        let benign = TelemetrySample {
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
        };
        let attack = TelemetrySample {
            timestamp_ms: 2,
            cpu_load_pct: 85.0,
            memory_load_pct: 80.0,
            temperature_c: 60.0,
            network_kbps: 8000.0,
            auth_failures: 20,
            battery_pct: 30.0,
            integrity_drift: 0.25,
            process_count: 200,
            disk_pressure_pct: 90.0,
        };

        let labeled = vec![
            (benign, false),
            (benign, false),
            (benign, false),
            (benign, false),
            (attack, true),
        ];

        let result = run_benchmark(&mut detector, &labeled, 2.0);
        assert!(result.true_positives + result.true_negatives > 0);
    }

    #[test]
    fn benchmark_10k_samples() {
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let anomaly_rate = 0.05; // 5% anomaly injection
        let n = 10_000;

        let mut labeled: Vec<(TelemetrySample, bool)> = Vec::with_capacity(n);
        for i in 0..n {
            let is_anomaly = rng.r#gen::<f64>() < anomaly_rate;
            let sample = if is_anomaly {
                // Attack profile: elevated across all axes
                TelemetrySample {
                    timestamp_ms: i as u64,
                    cpu_load_pct: 70.0 + rng.r#gen::<f32>() * 25.0,
                    memory_load_pct: 65.0 + rng.r#gen::<f32>() * 30.0,
                    temperature_c: 55.0 + rng.r#gen::<f32>() * 15.0,
                    network_kbps: 5000.0 + rng.r#gen::<f32>() * 5000.0,
                    auth_failures: (5.0 + rng.r#gen::<f32>() * 20.0) as u32,
                    battery_pct: 20.0 + rng.r#gen::<f32>() * 30.0,
                    integrity_drift: 0.10 + rng.r#gen::<f32>() * 0.20,
                    process_count: (100.0 + rng.r#gen::<f32>() * 150.0) as u32,
                    disk_pressure_pct: 60.0 + rng.r#gen::<f32>() * 35.0,
                }
            } else {
                // Benign profile: normal operating range
                TelemetrySample {
                    timestamp_ms: i as u64,
                    cpu_load_pct: 10.0 + rng.r#gen::<f32>() * 25.0,
                    memory_load_pct: 20.0 + rng.r#gen::<f32>() * 25.0,
                    temperature_c: 35.0 + rng.r#gen::<f32>() * 12.0,
                    network_kbps: 200.0 + rng.r#gen::<f32>() * 600.0,
                    auth_failures: if rng.r#gen::<f32>() < 0.1 { 1 } else { 0 },
                    battery_pct: 70.0 + rng.r#gen::<f32>() * 28.0,
                    integrity_drift: rng.r#gen::<f32>() * 0.03,
                    process_count: (30.0 + rng.r#gen::<f32>() * 30.0) as u32,
                    disk_pressure_pct: 5.0 + rng.r#gen::<f32>() * 20.0,
                }
            };
            labeled.push((sample, is_anomaly));
        }

        let start = std::time::Instant::now();
        let mut detector = AnomalyDetector::default();
        let result = run_benchmark(&mut detector, &labeled, 2.0);
        let elapsed = start.elapsed();

        // Performance: 10k samples should complete in well under 1 second
        assert!(elapsed.as_secs() < 1, "10k benchmark took {:?}", elapsed);

        // Sanity: we should have some of each category
        let total = result.true_positives
            + result.false_positives
            + result.true_negatives
            + result.false_negatives;
        assert_eq!(total, n);

        // The detector should achieve > 50% accuracy on this well-separated dataset
        assert!(
            result.accuracy > 0.5,
            "accuracy {} too low",
            result.accuracy
        );

        // F1 should be non-trivial on a 5% anomaly rate with clear separation
        assert!(
            result.f1 > 0.0,
            "F1 score is zero — detector not detecting anomalies"
        );
    }

    #[test]
    fn benchmark_collects_signal_contributions() {
        let mut detector = AnomalyDetector::default();
        let benign = TelemetrySample {
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
        };
        let attack = TelemetrySample {
            timestamp_ms: 2,
            cpu_load_pct: 85.0,
            memory_load_pct: 80.0,
            temperature_c: 60.0,
            network_kbps: 8000.0,
            auth_failures: 20,
            battery_pct: 30.0,
            integrity_drift: 0.25,
            process_count: 200,
            disk_pressure_pct: 90.0,
        };
        let labeled = vec![
            (benign, false),
            (benign, false),
            (benign, false),
            (attack, true),
            (attack, true),
        ];
        let result = run_benchmark(&mut detector, &labeled, 2.0);
        assert!(
            !result.signal_contributions.is_empty(),
            "expected signal contributions to be populated"
        );
        // Contributions are averages, should be non-negative
        for (name, val) in &result.signal_contributions {
            assert!(*val >= 0.0, "{name} had negative contribution {val}");
        }
    }
}
