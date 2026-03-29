//! Adversarial testing harness (T084 / R28 / T073).
//!
//! Implements grammar-based evasion strategies from
//! DESIGN_ADVERSARIAL_HARNESS.md. Generates adversarial telemetry
//! sequences that attempt to evade the anomaly detector, and measures
//! evasion rates and decision-surface coverage.

use crate::detector::AnomalyDetector;
use crate::telemetry::TelemetrySample;

// ─── Evasion strategies ─────────────────────────────────────────────

/// Types of evasion strategies from the design grammar.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Strategy {
    /// Gradually increase a target dimension to stay below per-sample thresholds.
    SlowDrip,
    /// Inject a short burst then immediately cool down.
    BurstMask,
    /// Slowly shift a dimension's mean to bias the EWMA baseline.
    DriftInject,
}

/// Configuration for the adversarial harness.
#[derive(Debug, Clone)]
pub struct HarnessConfig {
    /// Number of traces to generate per strategy.
    pub traces_per_strategy: usize,
    /// Length of each generated trace.
    pub trace_length: usize,
    /// Score threshold: if the max score stays below this, the trace evaded.
    pub evasion_threshold: f32,
}

impl Default for HarnessConfig {
    fn default() -> Self {
        Self {
            traces_per_strategy: 10,
            trace_length: 50,
            evasion_threshold: 1.5,
        }
    }
}

/// A generated adversarial trace and its evaluation result.
#[derive(Debug, Clone)]
pub struct AdversarialTrace {
    pub strategy: Strategy,
    pub samples: Vec<TelemetrySample>,
    pub max_score: f32,
    pub evaded: bool,
}

/// Coverage map across detector score space.
#[derive(Debug, Clone)]
pub struct CoverageMap {
    /// 20 buckets across [0.0, 1.0] score range (scores > 1.0 go in last bucket).
    pub score_buckets: [u64; 20],
    /// Number of distinct consecutive-score bucket transitions observed.
    pub transition_count: usize,
}

impl CoverageMap {
    fn new() -> Self {
        Self {
            score_buckets: [0; 20],
            transition_count: 0,
        }
    }

    fn record_score(&mut self, score: f32) {
        let bucket = ((score.clamp(0.0, 0.999) * 20.0) as usize).min(19);
        self.score_buckets[bucket] += 1;
    }

    /// Fraction of score buckets that have been exercised.
    pub fn coverage_ratio(&self) -> f64 {
        let filled = self.score_buckets.iter().filter(|&&c| c > 0).count();
        filled as f64 / 20.0
    }
}

/// Result of a full adversarial harness run.
#[derive(Debug, Clone)]
pub struct HarnessResult {
    pub traces: Vec<AdversarialTrace>,
    pub evasion_count: usize,
    pub total_count: usize,
    pub evasion_rate: f64,
    pub coverage: CoverageMap,
}

// ─── Trace generators ───────────────────────────────────────────────

fn benign_baseline() -> TelemetrySample {
    TelemetrySample {
        timestamp_ms: 0,
        cpu_load_pct: 20.0,
        memory_load_pct: 30.0,
        temperature_c: 38.0,
        network_kbps: 500.0,
        auth_failures: 0,
        battery_pct: 90.0,
        integrity_drift: 0.01,
        process_count: 45,
        disk_pressure_pct: 10.0,
    }
}

/// SlowDrip: gradually escalate CPU and memory across the trace.
fn generate_slow_drip(length: usize, intensity: f32) -> Vec<TelemetrySample> {
    let base = benign_baseline();
    (0..length)
        .map(|i| {
            let frac = i as f32 / length as f32;
            TelemetrySample {
                timestamp_ms: (i as u64 + 1) * 1000,
                cpu_load_pct: base.cpu_load_pct + frac * intensity * 0.7,
                memory_load_pct: base.memory_load_pct + frac * intensity * 0.5,
                temperature_c: base.temperature_c + frac * intensity * 0.1,
                network_kbps: base.network_kbps + frac * intensity * 20.0,
                auth_failures: if frac > 0.8 { 1 } else { 0 },
                battery_pct: base.battery_pct - frac * 5.0,
                integrity_drift: base.integrity_drift + frac * 0.005,
                process_count: base.process_count + (frac * 5.0) as u32,
                disk_pressure_pct: base.disk_pressure_pct + frac * intensity * 0.3,
            }
        })
        .collect()
}

/// BurstMask: stay benign, inject a 3-sample burst, then return to benign.
fn generate_burst_mask(length: usize, burst_magnitude: f32) -> Vec<TelemetrySample> {
    let base = benign_baseline();
    let burst_start = length / 2;
    let burst_end = (burst_start + 3).min(length);

    (0..length)
        .map(|i| {
            let in_burst = i >= burst_start && i < burst_end;
            TelemetrySample {
                timestamp_ms: (i as u64 + 1) * 1000,
                cpu_load_pct: if in_burst {
                    base.cpu_load_pct + burst_magnitude
                } else {
                    base.cpu_load_pct + (i as f32 * 0.1)
                },
                memory_load_pct: if in_burst {
                    base.memory_load_pct + burst_magnitude * 0.6
                } else {
                    base.memory_load_pct
                },
                temperature_c: base.temperature_c,
                network_kbps: if in_burst {
                    base.network_kbps + burst_magnitude * 50.0
                } else {
                    base.network_kbps
                },
                auth_failures: if in_burst { 5 } else { 0 },
                battery_pct: base.battery_pct - i as f32 * 0.2,
                integrity_drift: base.integrity_drift,
                process_count: base.process_count,
                disk_pressure_pct: base.disk_pressure_pct,
            }
        })
        .collect()
}

/// DriftInject: slowly shift a dimension's mean to bias the baseline.
fn generate_drift_inject(length: usize, drift_rate: f32) -> Vec<TelemetrySample> {
    let base = benign_baseline();
    (0..length)
        .map(|i| {
            let drift = i as f32 * drift_rate;
            TelemetrySample {
                timestamp_ms: (i as u64 + 1) * 1000,
                cpu_load_pct: base.cpu_load_pct + drift,
                memory_load_pct: base.memory_load_pct + drift * 0.8,
                temperature_c: base.temperature_c + drift * 0.05,
                network_kbps: base.network_kbps + drift * 10.0,
                auth_failures: 0,
                battery_pct: base.battery_pct,
                integrity_drift: base.integrity_drift,
                process_count: base.process_count,
                disk_pressure_pct: base.disk_pressure_pct + drift * 0.2,
            }
        })
        .collect()
}

// ─── Harness execution ──────────────────────────────────────────────

/// Evaluate a single trace against a fresh detector.
fn evaluate_trace(
    samples: &[TelemetrySample],
    threshold: f32,
    coverage: &mut CoverageMap,
) -> (f32, bool) {
    let mut detector = AnomalyDetector::default();
    let mut max_score: f32 = 0.0;

    for sample in samples {
        let signal = detector.evaluate(sample);
        coverage.record_score(signal.score);
        max_score = max_score.max(signal.score);
    }

    (max_score, max_score < threshold)
}

/// Run the full adversarial test harness.
pub fn run(config: &HarnessConfig) -> HarnessResult {
    let mut traces = Vec::new();
    let mut coverage = CoverageMap::new();

    let strategies = [
        (
            Strategy::SlowDrip,
            vec![10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 100.0],
        ),
        (
            Strategy::BurstMask,
            vec![10.0, 20.0, 30.0, 40.0, 50.0, 60.0, 70.0, 80.0, 90.0, 100.0],
        ),
        (
            Strategy::DriftInject,
            vec![0.1, 0.2, 0.3, 0.5, 0.7, 1.0, 1.5, 2.0, 3.0, 5.0],
        ),
    ];

    for (strategy, intensities) in &strategies {
        let count = config.traces_per_strategy.min(intensities.len());
        for &intensity in &intensities[..count] {
            let samples = match strategy {
                Strategy::SlowDrip => generate_slow_drip(config.trace_length, intensity),
                Strategy::BurstMask => generate_burst_mask(config.trace_length, intensity),
                Strategy::DriftInject => generate_drift_inject(config.trace_length, intensity),
            };

            let (max_score, evaded) =
                evaluate_trace(&samples, config.evasion_threshold, &mut coverage);

            traces.push(AdversarialTrace {
                strategy: *strategy,
                samples,
                max_score,
                evaded,
            });
        }
    }

    let evasion_count = traces.iter().filter(|t| t.evaded).count();
    let total_count = traces.len();
    let evasion_rate = if total_count > 0 {
        evasion_count as f64 / total_count as f64
    } else {
        0.0
    };

    HarnessResult {
        traces,
        evasion_count,
        total_count,
        evasion_rate,
        coverage,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harness_runs_with_defaults() {
        let config = HarnessConfig::default();
        let result = run(&config);

        assert_eq!(result.total_count, 30); // 10 per strategy × 3
        assert!(result.evasion_rate >= 0.0 && result.evasion_rate <= 1.0);
        // Coverage should exercise at least a few score buckets.
        assert!(result.coverage.coverage_ratio() > 0.0);
    }

    #[test]
    fn slow_drip_generates_valid_trace() {
        let trace = generate_slow_drip(20, 50.0);
        assert_eq!(trace.len(), 20);
        // Values should be monotonically increasing for CPU
        for i in 1..trace.len() {
            assert!(trace[i].cpu_load_pct >= trace[i - 1].cpu_load_pct);
        }
    }

    #[test]
    fn burst_mask_generates_valid_trace() {
        let trace = generate_burst_mask(20, 40.0);
        assert_eq!(trace.len(), 20);
        // The burst should cause a spike in the middle
        let mid = trace.len() / 2;
        assert!(trace[mid].cpu_load_pct > trace[0].cpu_load_pct);
    }

    #[test]
    fn drift_inject_generates_valid_trace() {
        let trace = generate_drift_inject(20, 1.0);
        assert_eq!(trace.len(), 20);
        assert!(trace.last().unwrap().cpu_load_pct > trace[0].cpu_load_pct);
    }

    #[test]
    fn high_intensity_detected() {
        // Very high intensity should NOT evade the detector
        let samples = generate_slow_drip(50, 200.0);
        let mut coverage = CoverageMap::new();
        let (max_score, evaded) = evaluate_trace(&samples, 1.5, &mut coverage);
        assert!(max_score > 1.5, "high intensity should produce high scores");
        assert!(!evaded, "high intensity should be detected");
    }

    #[test]
    fn coverage_map_records_scores() {
        let mut cov = CoverageMap::new();
        cov.record_score(0.0);
        cov.record_score(0.5);
        cov.record_score(0.99);
        assert!(cov.coverage_ratio() > 0.0);
        assert!(cov.score_buckets[0] > 0); // bucket for 0.0
        assert!(cov.score_buckets[10] > 0); // bucket for 0.5
    }

    #[test]
    fn custom_config() {
        let config = HarnessConfig {
            traces_per_strategy: 3,
            trace_length: 20,
            evasion_threshold: 2.0,
        };
        let result = run(&config);
        assert_eq!(result.total_count, 9); // 3 per strategy × 3
    }
}
