//! Detector accuracy benchmarks: precision, recall, F1, and per-signal contribution attribution.

use std::collections::BTreeMap;

use crate::detector::AnomalyDetector;
use crate::telemetry::TelemetrySample;

#[derive(Debug, Clone, serde::Serialize)]
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

// ── Paper-grade evaluation harnesses (Phase 15) ───────────────

/// Per-sample latency statistics for paper tables.
#[derive(Debug, Clone)]
pub struct LatencyStats {
    pub count: usize,
    pub mean_us: f64,
    pub median_us: f64,
    pub p95_us: f64,
    pub p99_us: f64,
    pub min_us: f64,
    pub max_us: f64,
}

impl LatencyStats {
    fn from_durations(durations: &mut [f64]) -> Self {
        let count = durations.len();
        if count == 0 {
            return Self {
                count: 0,
                mean_us: 0.0,
                median_us: 0.0,
                p95_us: 0.0,
                p99_us: 0.0,
                min_us: 0.0,
                max_us: 0.0,
            };
        }
        durations.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let sum: f64 = durations.iter().sum();
        let mean_us = sum / count as f64;
        let median_us = if count.is_multiple_of(2) {
            (durations[count / 2 - 1] + durations[count / 2]) / 2.0
        } else {
            durations[count / 2]
        };
        let p95_us = durations[((count - 1) as f64 * 0.95) as usize];
        let p99_us = durations[((count - 1) as f64 * 0.99) as usize];
        let min_us = durations[0];
        let max_us = durations[count - 1];
        Self {
            count,
            mean_us,
            median_us,
            p95_us,
            p99_us,
            min_us,
            max_us,
        }
    }
}

/// Measure per-sample ingestion-to-decision latency.
pub fn run_latency_benchmark(
    detector: &mut AnomalyDetector,
    samples: &[TelemetrySample],
) -> LatencyStats {
    use std::time::Instant;
    let mut durations: Vec<f64> = Vec::with_capacity(samples.len());
    for sample in samples {
        let start = Instant::now();
        let _ = detector.evaluate(sample);
        let elapsed = start.elapsed();
        durations.push(elapsed.as_secs_f64() * 1_000_000.0); // microseconds
    }
    LatencyStats::from_durations(&mut durations)
}

/// Audit-chain append + verify throughput at a given chain length.
#[derive(Debug, Clone)]
pub struct AuditScalingResult {
    pub chain_length: usize,
    pub append_total_us: f64,
    pub append_per_record_us: f64,
    pub verify_total_us: f64,
    pub verify_per_record_us: f64,
}

/// Benchmark audit-chain scaling at multiple sizes.
pub fn run_audit_scaling_benchmark(sizes: &[usize]) -> Vec<AuditScalingResult> {
    use crate::audit::AuditLog;
    use std::time::Instant;

    sizes
        .iter()
        .map(|&n| {
            let mut log = AuditLog::new();
            let start = Instant::now();
            for i in 0..n {
                log.record("bench", format!("record-{i}"));
            }
            let append_us = start.elapsed().as_secs_f64() * 1_000_000.0;

            let start = Instant::now();
            log.verify_chain().expect("chain verification failed");
            let verify_us = start.elapsed().as_secs_f64() * 1_000_000.0;

            AuditScalingResult {
                chain_length: n,
                append_total_us: append_us,
                append_per_record_us: if n > 0 { append_us / n as f64 } else { 0.0 },
                verify_total_us: verify_us,
                verify_per_record_us: if n > 0 { verify_us / n as f64 } else { 0.0 },
            }
        })
        .collect()
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

        // Keep this as a regression guard against accidental quadratic slowdowns,
        // but allow normal debug-build variance on clean machines and CI runners.
        assert!(
            elapsed.as_secs_f64() < 2.0,
            "10k benchmark took {:?}",
            elapsed
        );

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

    // ── Paper evaluation tests (Phase 15) ─────────────────────

    #[test]
    fn latency_benchmark_measures_microseconds() {
        let mut detector = AnomalyDetector::default();
        let samples: Vec<TelemetrySample> = (0..100)
            .map(|i| TelemetrySample {
                timestamp_ms: i,
                cpu_load_pct: 20.0,
                memory_load_pct: 30.0,
                temperature_c: 40.0,
                network_kbps: 500.0,
                auth_failures: 0,
                battery_pct: 90.0,
                integrity_drift: 0.01,
                process_count: 42,
                disk_pressure_pct: 10.0,
            })
            .collect();
        let stats = super::run_latency_benchmark(&mut detector, &samples);
        assert_eq!(stats.count, 100);
        assert!(stats.mean_us > 0.0, "mean latency should be positive");
        assert!(stats.median_us > 0.0);
        assert!(stats.p95_us >= stats.median_us);
        assert!(stats.p99_us >= stats.p95_us);
        assert!(stats.min_us <= stats.median_us);
        assert!(stats.max_us >= stats.p99_us);
    }

    #[test]
    fn audit_scaling_benchmark_runs() {
        let sizes = vec![10, 100, 1_000];
        let results = super::run_audit_scaling_benchmark(&sizes);
        assert_eq!(results.len(), 3);
        for r in &results {
            assert!(r.append_total_us > 0.0);
            assert!(r.verify_total_us > 0.0);
            assert!(
                r.append_per_record_us > 0.0,
                "per-record append latency should be positive"
            );
        }
        // Verify time should scale — larger chains take longer to verify
        assert!(results[2].verify_total_us > results[0].verify_total_us);
    }

    #[test]
    fn audit_scaling_10k_records() {
        let results = super::run_audit_scaling_benchmark(&[10_000]);
        let r = &results[0];
        assert_eq!(r.chain_length, 10_000);
        // 10k records should verify in under 5 seconds even on slow machines
        assert!(
            r.verify_total_us < 5_000_000.0,
            "10k chain verify took {:.1}ms",
            r.verify_total_us / 1000.0
        );
    }

    #[cfg_attr(tarpaulin, ignore)]
    #[test]
    fn latency_1k_samples_under_100ms() {
        let mut detector = AnomalyDetector::default();
        let samples: Vec<TelemetrySample> = (0..1000)
            .map(|i| TelemetrySample {
                timestamp_ms: i,
                cpu_load_pct: 15.0 + (i % 50) as f32,
                memory_load_pct: 20.0 + (i % 40) as f32,
                temperature_c: 35.0 + (i % 20) as f32,
                network_kbps: 300.0 + (i % 100) as f32 * 10.0,
                auth_failures: (i % 5) as u32,
                battery_pct: 80.0 - (i % 30) as f32,
                integrity_drift: 0.01 + (i % 10) as f32 * 0.005,
                process_count: 30 + (i % 40) as u32,
                disk_pressure_pct: 5.0 + (i % 20) as f32,
            })
            .collect();
        let stats = super::run_latency_benchmark(&mut detector, &samples);
        assert_eq!(stats.count, 1000);
        // Total time (mean * count) should be under 100ms
        let total_ms = stats.mean_us * stats.count as f64 / 1000.0;
        assert!(
            total_ms < 100.0,
            "1k samples took {total_ms:.1}ms (target: <100ms)"
        );
    }
}
