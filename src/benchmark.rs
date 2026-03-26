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
}

pub struct BenchmarkHarness {
    true_positives: usize,
    false_positives: usize,
    true_negatives: usize,
    false_negatives: usize,
}

impl BenchmarkHarness {
    pub fn new() -> Self {
        Self {
            true_positives: 0,
            false_positives: 0,
            true_negatives: 0,
            false_negatives: 0,
        }
    }

    pub fn record(&mut self, predicted: bool, actual: bool) {
        match (predicted, actual) {
            (true, true) => self.true_positives += 1,
            (true, false) => self.false_positives += 1,
            (false, true) => self.false_negatives += 1,
            (false, false) => self.true_negatives += 1,
        }
    }

    pub fn result(&self) -> BenchmarkResult {
        let tp = self.true_positives as f32;
        let fp = self.false_positives as f32;
        let tn = self.true_negatives as f32;
        let fn_ = self.false_negatives as f32;
        let total = tp + fp + tn + fn_;

        let precision = if tp + fp > 0.0 { tp / (tp + fp) } else { 0.0 };
        let recall = if tp + fn_ > 0.0 {
            tp / (tp + fn_)
        } else {
            0.0
        };
        let f1 = if precision + recall > 0.0 {
            2.0 * precision * recall / (precision + recall)
        } else {
            0.0
        };
        let accuracy = if total > 0.0 {
            (tp + tn) / total
        } else {
            0.0
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
        harness.record(true, true);   // TP
        harness.record(true, false);  // FP
        harness.record(false, true);  // FN
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
}
