//! Behavioural device fingerprinting (T094 / R38).
//!
//! Builds a statistical profile from observed telemetry and detects
//! anomalous deviations that may indicate device impersonation or
//! tampering. The fingerprint captures per-signal mean and standard
//! deviation from a training window, then scores new samples against
//! the learned profile using Mahalanobis-inspired distance.

use serde::{Deserialize, Serialize};

use crate::telemetry::TelemetrySample;

/// Number of signal dimensions in the fingerprint.
const DIM: usize = 9;

/// A learned behavioural profile for a single device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceFingerprint {
    /// Mean of each signal dimension.
    pub means: [f32; DIM],
    /// Standard deviation of each signal dimension.
    pub stddevs: [f32; DIM],
    /// Number of samples used to train the profile.
    pub trained_samples: usize,
}

/// Result of matching a sample against a fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintMatch {
    /// Aggregate distance score (sum of per-dimension z-scores).
    pub distance: f32,
    /// Per-dimension z-scores in the same order as the fingerprint.
    pub z_scores: [f32; DIM],
    /// Whether the sample exceeds the anomaly threshold.
    pub anomalous: bool,
}

/// Signal dimension names, in order.
pub const SIGNAL_NAMES: [&str; DIM] = [
    "cpu_load_pct",
    "memory_load_pct",
    "temperature_c",
    "network_kbps",
    "auth_failures",
    "battery_pct",
    "integrity_drift",
    "process_count",
    "disk_pressure_pct",
];

/// Extract a fixed-size feature vector from a telemetry sample.
fn to_features(sample: &TelemetrySample) -> [f32; DIM] {
    [
        sample.cpu_load_pct,
        sample.memory_load_pct,
        sample.temperature_c,
        sample.network_kbps,
        sample.auth_failures as f32,
        sample.battery_pct,
        sample.integrity_drift,
        sample.process_count as f32,
        sample.disk_pressure_pct,
    ]
}

impl DeviceFingerprint {
    /// Train a fingerprint from a slice of telemetry samples.
    ///
    /// Returns `None` if fewer than 3 samples are provided (insufficient
    /// data for a meaningful standard deviation).
    pub fn train(samples: &[TelemetrySample]) -> Option<Self> {
        let n = samples.len();
        if n < 3 {
            return None;
        }
        let nf = n as f32;

        let mut sums = [0.0_f32; DIM];
        for s in samples {
            let f = to_features(s);
            for (i, val) in f.iter().enumerate() {
                sums[i] += val;
            }
        }
        let mut means = [0.0_f32; DIM];
        for i in 0..DIM {
            means[i] = sums[i] / nf;
        }

        let mut var_sums = [0.0_f32; DIM];
        for s in samples {
            let f = to_features(s);
            for (i, val) in f.iter().enumerate() {
                let d = val - means[i];
                var_sums[i] += d * d;
            }
        }
        let mut stddevs = [0.0_f32; DIM];
        for i in 0..DIM {
            // Bessel's correction: divide by n-1 for sample stddev
            stddevs[i] = (var_sums[i] / (nf - 1.0)).sqrt();
        }

        // Guard against NaN/Inf from corrupted input
        if means.iter().any(|v| !v.is_finite()) || stddevs.iter().any(|v| !v.is_finite()) {
            return None;
        }

        Some(Self {
            means,
            stddevs,
            trained_samples: n,
        })
    }

    /// Match a single sample against this fingerprint.
    ///
    /// `threshold` is the maximum acceptable aggregate z-score distance.
    /// A typical value is 3.0 * DIM (one z-score = 3 per dimension on
    /// average for a Gaussian distribution).
    pub fn match_sample(&self, sample: &TelemetrySample, threshold: f32) -> FingerprintMatch {
        let features = to_features(sample);
        let mut z_scores = [0.0_f32; DIM];
        let mut distance = 0.0_f32;

        for i in 0..DIM {
            let z = if self.stddevs[i] > 1e-6 {
                ((features[i] - self.means[i]) / self.stddevs[i]).abs()
            } else if (features[i] - self.means[i]).abs() > 1e-6 {
                // Zero stddev but different value → very anomalous
                10.0
            } else {
                0.0
            };
            z_scores[i] = z;
            distance += z;
        }

        FingerprintMatch {
            distance,
            z_scores,
            anomalous: distance > threshold,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::TelemetrySample;

    fn benign_sample(ts: u64) -> TelemetrySample {
        TelemetrySample {
            timestamp_ms: ts,
            cpu_load_pct: 20.0 + (ts as f32 * 0.1),
            memory_load_pct: 30.0 + (ts as f32 * 0.05),
            temperature_c: 40.0,
            network_kbps: 500.0,
            auth_failures: 0,
            battery_pct: 90.0,
            integrity_drift: 0.01,
            process_count: 42,
            disk_pressure_pct: 10.0,
        }
    }

    #[test]
    fn train_requires_minimum_samples() {
        let samples: Vec<_> = (0..2).map(|i| benign_sample(i)).collect();
        assert!(DeviceFingerprint::train(&samples).is_none());
    }

    #[test]
    fn train_produces_fingerprint() {
        let samples: Vec<_> = (0..10).map(|i| benign_sample(i)).collect();
        let fp = DeviceFingerprint::train(&samples).unwrap();
        assert_eq!(fp.trained_samples, 10);
        // CPU mean should be around 20.45 (20.0 + avg of 0.0..0.9)
        assert!(fp.means[0] > 19.0 && fp.means[0] < 22.0);
    }

    #[test]
    fn benign_sample_matches() {
        let training: Vec<_> = (0..20).map(|i| benign_sample(i)).collect();
        let fp = DeviceFingerprint::train(&training).unwrap();

        let test_sample = benign_sample(5);
        let result = fp.match_sample(&test_sample, 27.0); // 3.0 * 9 dims
        assert!(!result.anomalous, "benign sample should match fingerprint");
    }

    #[test]
    fn anomalous_sample_detected() {
        let training: Vec<_> = (0..20).map(|i| benign_sample(i)).collect();
        let fp = DeviceFingerprint::train(&training).unwrap();

        // Wildly different sample — impersonation attempt
        let impostor = TelemetrySample {
            timestamp_ms: 100,
            cpu_load_pct: 95.0,
            memory_load_pct: 95.0,
            temperature_c: 80.0,
            network_kbps: 50_000.0,
            auth_failures: 50,
            battery_pct: 10.0,
            integrity_drift: 0.9,
            process_count: 500,
            disk_pressure_pct: 95.0,
        };
        let result = fp.match_sample(&impostor, 27.0);
        assert!(result.anomalous, "impostor should be detected as anomalous");
        assert!(result.distance > 27.0, "distance should exceed threshold");
    }

    #[test]
    fn fingerprint_serializes() {
        let training: Vec<_> = (0..10).map(|i| benign_sample(i)).collect();
        let fp = DeviceFingerprint::train(&training).unwrap();
        let json = serde_json::to_string(&fp).unwrap();
        assert!(json.contains("means"));
        let deserialized: DeviceFingerprint = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.trained_samples, fp.trained_samples);
    }

    #[test]
    fn zero_variance_dimension_detects_deviation() {
        // All training samples have identical temperature (40.0) → zero stddev
        let constant_sample = TelemetrySample {
            timestamp_ms: 0,
            cpu_load_pct: 20.0,
            memory_load_pct: 30.0,
            temperature_c: 40.0,
            network_kbps: 500.0,
            auth_failures: 0,
            battery_pct: 90.0,
            integrity_drift: 0.01,
            process_count: 42,
            disk_pressure_pct: 10.0,
        };
        let training: Vec<_> = (0..10).map(|_| constant_sample).collect();
        let fp = DeviceFingerprint::train(&training).unwrap();

        // Match a sample that differs only on temperature
        let mut deviant = constant_sample;
        deviant.temperature_c = 60.0;
        let result = fp.match_sample(&deviant, 27.0);
        // The temperature dimension (index 2) should get the sentinel z=10.0
        assert!(
            (result.z_scores[2] - 10.0).abs() < 0.01,
            "zero-variance dimension should get sentinel z-score of 10.0"
        );
    }
}
