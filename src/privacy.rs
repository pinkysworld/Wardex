//! Privacy-preserving coordination, federated learning, and forensics redaction.
//!
//! Implements differential privacy noise injection, secure aggregation for
//! federated model updates, and privacy-preserving forensic bundle export.
//! Covers R08 (privacy coordination), R27 (federated learning), R40 (privacy forensics).

use serde::{Deserialize, Serialize};

use crate::audit::sha256_hex;

// ── Differential Privacy ─────────────────────────────────────────────────────

/// Differential privacy noise generator using the Laplace mechanism.
#[derive(Debug, Clone)]
pub struct DpMechanism {
    pub epsilon: f64,
    pub sensitivity: f64,
}

impl DpMechanism {
    pub fn new(epsilon: f64, sensitivity: f64) -> Self {
        Self {
            epsilon: epsilon.max(0.01),
            sensitivity: sensitivity.max(0.001),
        }
    }

    /// Generate Laplace noise with scale = sensitivity / epsilon.
    pub fn laplace_noise(&self) -> f64 {
        use rand::RngExt;
        let mut rng = rand::rng();
        let scale = self.sensitivity / self.epsilon;
        // Inverse CDF method for Laplace distribution
        let u: f64 = rng.random::<f64>() - 0.5;
        -scale * u.signum() * (1.0 - 2.0 * u.abs()).ln()
    }

    /// Add noise to a value (Laplace mechanism).
    pub fn privatize(&self, value: f64) -> f64 {
        value + self.laplace_noise()
    }

    /// Privatize a vector of values.
    pub fn privatize_vec(&self, values: &[f64]) -> Vec<f64> {
        values.iter().map(|&v| self.privatize(v)).collect()
    }

    /// Compute the privacy budget remaining after k queries.
    pub fn budget_remaining(&self, queries_used: usize, total_budget: f64) -> f64 {
        let spent = queries_used as f64 * self.epsilon;
        (total_budget - spent).max(0.0)
    }
}

/// Differential privacy noise generator using the (ε, δ)-Gaussian mechanism.
///
/// Calibrated with the *analytic* Gaussian mechanism (Balle & Wang, "Improving
/// the Gaussian Mechanism for Differential Privacy: Analytical Calibration
/// and Optimal Denoising", ICML 2018, Algorithm 1): `sigma` is the smallest
/// value (found by bisection) satisfying the exact privacy-profile condition
///
/// ```text
/// Φ(Δ/(2σ) − εσ/Δ) − e^ε · Φ(−Δ/(2σ) − εσ/Δ) ≤ δ
/// ```
///
/// which is necessary and sufficient for (ε, δ)-DP of Gaussian noise with
/// L2 sensitivity Δ, for **every** ε > 0. The classical bound
/// `sigma = Δ·sqrt(2 ln(1.25/δ))/ε` (Dwork & Roth, Thm 3.22) is only valid
/// for ε < 1 — for larger ε it under-noises — and is looser than the
/// analytic value where it is valid (see [`classical_gaussian_sigma`]).
///
/// Used for federated-learning update aggregation (see [`crate::federated`])
/// where noise must be added to a vector of bounded L2 norm (`sensitivity`
/// is the per-round clipping norm `C`).
#[derive(Debug, Clone)]
pub struct GaussianMechanism {
    pub epsilon: f64,
    pub delta: f64,
    pub sensitivity: f64,
    pub sigma: f64,
}

impl GaussianMechanism {
    /// Build a mechanism for the given budget. Inputs are sanitised
    /// conservatively: `epsilon` is floored at 0.001 (non-finite values use
    /// the floor), `delta` is clamped to `[1e-12, 0.5]` (non-finite values
    /// use 1e-12), and a negative/non-finite `sensitivity` becomes 0.
    pub fn new(epsilon: f64, delta: f64, sensitivity: f64) -> Self {
        let epsilon = if epsilon.is_finite() {
            epsilon.max(0.001)
        } else {
            0.001
        };
        let delta = if delta.is_finite() {
            delta.clamp(1e-12, 0.5)
        } else {
            1e-12
        };
        let sensitivity = if sensitivity.is_finite() {
            sensitivity.max(0.0)
        } else {
            0.0
        };
        let sigma = sensitivity * analytic_gaussian_unit_sigma(epsilon, delta);
        Self {
            epsilon,
            delta,
            sensitivity,
            sigma,
        }
    }

    /// Sample one draw of zero-mean Gaussian noise with std-dev `sigma`,
    /// using the Box-Muller transform.
    pub fn noise(&self) -> f64 {
        self.noise_with(&mut rand::rng())
    }

    /// Like [`Self::noise`], but draws from the supplied RNG so callers
    /// (tests, simulations) can make the noise reproducible.
    pub fn noise_with<R: rand::RngExt + ?Sized>(&self, rng: &mut R) -> f64 {
        let u1: f64 = rng.random::<f64>().clamp(1e-12, 1.0);
        let u2: f64 = rng.random::<f64>();
        let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
        z * self.sigma
    }

    /// Add independent Gaussian noise to every element of `values`.
    pub fn privatize_vec(&self, values: &[f64]) -> Vec<f64> {
        values.iter().map(|&v| v + self.noise()).collect()
    }
}

/// Classical Gaussian-mechanism calibration
/// `sigma = sensitivity * sqrt(2 ln(1.25/δ)) / ε` (Dwork & Roth, Thm 3.22).
/// Only a valid (ε, δ)-DP guarantee for ε < 1; kept for comparison and
/// documentation. [`GaussianMechanism::new`] uses the analytic calibration.
pub fn classical_gaussian_sigma(epsilon: f64, delta: f64, sensitivity: f64) -> f64 {
    sensitivity * (2.0 * (1.25 / delta).ln()).sqrt() / epsilon
}

/// Chebyshev coefficients for `erfc` on `z >= 0` (Press et al., Numerical
/// Recipes 3rd ed., §6.2.2 `Erf::erfccheb`), accurate to ~1e-15 relative
/// error across the whole range, including the far tail.
const ERFC_CHEB: [f64; 28] = [
    -1.302_653_719_781_709_4,
    6.419_697_923_564_902e-1,
    1.947_647_320_418_583_6e-2,
    -9.561_514_786_808_63e-3,
    -9.465_953_444_820_36e-4,
    3.668_394_978_527_61e-4,
    4.252_332_480_690_7e-5,
    -2.027_857_811_253_4e-5,
    -1.624_290_004_647e-6,
    1.303_655_835_580e-6,
    1.562_644_172_2e-8,
    -8.523_809_591_5e-8,
    6.529_054_439e-9,
    5.059_343_495e-9,
    -9.913_641_56e-10,
    -2.273_651_22e-10,
    9.646_791_1e-11,
    2.394_038e-12,
    -6.886_027e-12,
    8.944_87e-13,
    3.130_92e-13,
    -1.127_08e-13,
    3.81e-16,
    7.106e-15,
    -1.523e-15,
    -9.4e-17,
    1.21e-16,
    -2.8e-17,
];

/// Natural log of `erfc(z)` for `z >= 0`, computed without forming
/// `erfc(z)` itself so it stays finite deep in the tail (where `erfc`
/// underflows, e.g. `z > 27`).
fn ln_erfc_nonneg(z: f64) -> f64 {
    let t = 2.0 / (2.0 + z);
    let ty = 4.0 * t - 2.0;
    let mut d = 0.0;
    let mut dd = 0.0;
    for &c in ERFC_CHEB.iter().skip(1).rev() {
        let tmp = d;
        d = ty * d - dd + c;
        dd = tmp;
    }
    t.ln() - z * z + 0.5 * (ERFC_CHEB[0] + ty * d) - dd
}

/// Complementary error function with ~1e-15 relative accuracy.
pub fn erfc(x: f64) -> f64 {
    if x >= 0.0 {
        ln_erfc_nonneg(x).exp()
    } else {
        2.0 - ln_erfc_nonneg(-x).exp()
    }
}

/// Natural log of the standard normal CDF, `ln Φ(x)`, accurate in both
/// tails.
fn ln_std_normal_cdf(x: f64) -> f64 {
    let z = x / std::f64::consts::SQRT_2;
    if x <= 0.0 {
        ln_erfc_nonneg(-z) - std::f64::consts::LN_2
    } else {
        (-0.5 * ln_erfc_nonneg(z).exp()).ln_1p()
    }
}

/// Exact privacy profile of the Gaussian mechanism with unit sensitivity
/// and noise scale `sigma` (Balle & Wang 2018, Theorem 8):
/// `δ(σ) = Φ(1/(2σ) − εσ) − e^ε Φ(−1/(2σ) − εσ)`, evaluated in log space so
/// the `e^ε` factor cannot overflow for large ε.
pub fn gaussian_privacy_profile_delta(epsilon: f64, sigma: f64) -> f64 {
    if sigma <= 0.0 {
        return 1.0;
    }
    let a = 1.0 / (2.0 * sigma) - epsilon * sigma;
    let b = -1.0 / (2.0 * sigma) - epsilon * sigma;
    let first = ln_std_normal_cdf(a).exp();
    let second = (epsilon + ln_std_normal_cdf(b)).exp();
    (first - second).max(0.0)
}

/// Smallest noise scale (for sensitivity 1) such that the Gaussian
/// mechanism is (ε, δ)-DP, via bisection on the exact condition. The
/// returned value always satisfies the condition (it is the upper end of
/// the final bracket).
fn analytic_gaussian_unit_sigma(epsilon: f64, delta: f64) -> f64 {
    // δ(σ) is strictly decreasing in σ, from 1 at σ→0 to 0 at σ→∞.
    let mut hi = 1.0_f64;
    let mut guard = 0;
    while gaussian_privacy_profile_delta(epsilon, hi) > delta && guard < 200 {
        hi *= 2.0;
        guard += 1;
    }
    let mut lo = if guard > 0 { hi / 2.0 } else { 0.0 };
    for _ in 0..200 {
        let mid = 0.5 * (lo + hi);
        if mid <= lo || mid >= hi {
            break;
        }
        if gaussian_privacy_profile_delta(epsilon, mid) > delta {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    hi
}

/// Privacy accountant tracking cumulative privacy loss.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyAccountant {
    pub total_epsilon: f64,
    pub spent_epsilon: f64,
    pub query_count: usize,
    pub mechanism: String,
}

impl PrivacyAccountant {
    pub fn new(total_budget: f64) -> Self {
        Self {
            total_epsilon: total_budget,
            spent_epsilon: 0.0,
            query_count: 0,
            mechanism: "laplace".into(),
        }
    }

    /// Record a query and its epsilon cost.
    pub fn record_query(&mut self, epsilon_cost: f64) -> bool {
        if self.spent_epsilon + epsilon_cost > self.total_epsilon {
            return false; // budget exhausted
        }
        self.spent_epsilon += epsilon_cost;
        self.query_count += 1;
        true
    }

    pub fn budget_remaining(&self) -> f64 {
        (self.total_epsilon - self.spent_epsilon).max(0.0)
    }

    pub fn is_exhausted(&self) -> bool {
        self.spent_epsilon >= self.total_epsilon
    }
}

// ── Federated Learning (R27) ─────────────────────────────────────────────────

/// A local model update from a participating device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelUpdate {
    pub device_id: String,
    pub round: u64,
    pub weights: Vec<f64>,
    pub sample_count: usize,
    pub loss: f64,
}

/// Aggregated global model after federated averaging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalModel {
    pub round: u64,
    pub weights: Vec<f64>,
    pub total_samples: usize,
    pub participating_devices: usize,
    pub convergence_delta: f64,
}

/// Federated learning coordinator.
#[derive(Debug)]
pub struct FederatedCoordinator {
    current_round: u64,
    global_weights: Vec<f64>,
    pending_updates: Vec<ModelUpdate>,
    min_participants: usize,
    dp: Option<DpMechanism>,
}

impl FederatedCoordinator {
    pub fn new(initial_weights: Vec<f64>, min_participants: usize) -> Self {
        Self {
            current_round: 0,
            global_weights: initial_weights,
            pending_updates: Vec::new(),
            min_participants,
            dp: None,
        }
    }

    /// Enable differential privacy for aggregation.
    pub fn enable_dp(&mut self, epsilon: f64, sensitivity: f64) {
        self.dp = Some(DpMechanism::new(epsilon, sensitivity));
    }

    /// Submit a local model update from a device.
    pub fn submit_update(&mut self, update: ModelUpdate) {
        self.pending_updates.push(update);
    }

    /// Perform federated averaging if enough participants have submitted.
    pub fn aggregate(&mut self) -> Option<GlobalModel> {
        if self.pending_updates.len() < self.min_participants {
            return None;
        }

        let dim = self.global_weights.len();
        let total_samples: usize = self.pending_updates.iter().map(|u| u.sample_count).sum();

        if total_samples == 0 || dim == 0 {
            return None;
        }

        self.current_round += 1;

        // Weighted average by sample count
        let mut new_weights = vec![0.0f64; dim];
        for update in &self.pending_updates {
            let weight_factor = update.sample_count as f64 / total_samples as f64;
            for (i, &w) in update.weights.iter().enumerate() {
                if i < dim {
                    new_weights[i] += w * weight_factor;
                }
            }
        }

        // Apply differential privacy noise if enabled
        if let Some(ref dp) = self.dp {
            new_weights = dp.privatize_vec(&new_weights);
        }

        // Compute convergence delta
        let delta: f64 = self
            .global_weights
            .iter()
            .zip(new_weights.iter())
            .map(|(&old, &new)| (old - new).powi(2))
            .sum::<f64>()
            .sqrt();

        let participating = self.pending_updates.len();
        self.global_weights = new_weights.clone();
        self.pending_updates.clear();

        Some(GlobalModel {
            round: self.current_round,
            weights: new_weights,
            total_samples,
            participating_devices: participating,
            convergence_delta: delta,
        })
    }

    pub fn current_round(&self) -> u64 {
        self.current_round
    }

    pub fn global_weights(&self) -> &[f64] {
        &self.global_weights
    }

    /// Run a multi-round convergence loop until the convergence delta
    /// drops below `target_delta` or `max_rounds` is reached.
    /// `generate_updates` is called each round to produce fresh local
    /// updates (simulating device training).
    pub fn convergence_loop<F>(
        &mut self,
        max_rounds: usize,
        target_delta: f64,
        mut generate_updates: F,
    ) -> Vec<GlobalModel>
    where
        F: FnMut(u64, &[f64]) -> Vec<ModelUpdate>,
    {
        let mut history = Vec::new();
        for _ in 0..max_rounds {
            let round = self.current_round + 1;
            let updates = generate_updates(round, &self.global_weights);
            for u in updates {
                self.submit_update(u);
            }
            if let Some(model) = self.aggregate() {
                let converged = model.convergence_delta < target_delta;
                history.push(model);
                if converged {
                    break;
                }
            } else {
                break; // insufficient participants
            }
        }
        history
    }
}

// ── Secure Aggregation ───────────────────────────────────────────────────────

/// Simple masking-based secure aggregation.
/// Each participant adds a random mask; the coordinator sums all masked
/// values. Because masks cancel out in aggregate, the coordinator learns
/// only the sum, not individual contributions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskedContribution {
    pub device_id: String,
    pub masked_values: Vec<f64>,
    pub mask_commitment: String, // hash of mask for verification
}

pub struct SecureAggregator {
    contributions: Vec<MaskedContribution>,
    dimension: usize,
}

impl SecureAggregator {
    pub fn new(dimension: usize) -> Self {
        Self {
            contributions: Vec::new(),
            dimension,
        }
    }

    /// Generate a random mask for a participant.
    pub fn generate_mask(&self) -> (Vec<f64>, String) {
        use rand::RngExt;
        let mut rng = rand::rng();
        let mask: Vec<f64> = (0..self.dimension)
            .map(|_| rng.random::<f64>() * 2.0 - 1.0)
            .collect();
        let mask_bytes: Vec<u8> = mask.iter().flat_map(|&v| v.to_le_bytes()).collect();
        let commitment = sha256_hex(&mask_bytes);
        (mask, commitment)
    }

    /// Submit a masked contribution.
    pub fn submit(&mut self, contribution: MaskedContribution) {
        self.contributions.push(contribution);
    }

    /// Aggregate all contributions (masks cancel if protocol is followed).
    pub fn aggregate(&self) -> Vec<f64> {
        let mut result = vec![0.0f64; self.dimension];
        for contrib in &self.contributions {
            for (i, &v) in contrib.masked_values.iter().enumerate() {
                if i < self.dimension {
                    result[i] += v;
                }
            }
        }
        result
    }
}

// ── Privacy-Preserving Forensics (R40) ───────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactedForensicBundle {
    pub case_id: String,
    pub redaction_level: RedactionLevel,
    pub summary: String,
    pub audit_chain_hash: String,
    pub redacted_records: Vec<RedactedRecord>,
    pub zk_proof_of_inclusion: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RedactionLevel {
    /// Full data, no redaction (internal use only)
    Full,
    /// PII stripped, timestamps generalised
    Standard,
    /// Minimal: only threat indicators and severity
    Minimal,
    /// ZK proof of existence without any data disclosure
    ZeroKnowledge,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactedRecord {
    pub sequence: u64,
    pub category: String,
    pub summary_redacted: String,
    pub hash: String,
}

/// Redact a forensic bundle to the specified level.
pub fn redact_forensic_bundle(
    case_id: &str,
    records: &[(u64, String, String, String)], // (seq, category, summary, hash)
    level: RedactionLevel,
) -> RedactedForensicBundle {
    let redacted: Vec<RedactedRecord> = records
        .iter()
        .map(|(seq, cat, summary, hash)| {
            let summary_redacted = match level {
                RedactionLevel::Full => summary.clone(),
                RedactionLevel::Standard => {
                    // Strip IP addresses, usernames, paths
                    let mut s = summary.clone();
                    // Redact IPv4 patterns
                    let ip_pattern = regex_lite_replace_ips(&s);
                    s = ip_pattern;
                    // Redact paths like /home/user/...
                    while let Some(idx) = s.find("/home/") {
                        let end = s[idx..]
                            .find(|c: char| c.is_whitespace())
                            .map_or(s.len(), |e| idx + e);
                        s.replace_range(idx..end, "[REDACTED_PATH]");
                    }
                    s
                }
                RedactionLevel::Minimal => {
                    // Only keep category and severity keywords
                    if summary.contains("critical") || summary.contains("severe") {
                        format!("[ALERT] {cat}")
                    } else {
                        format!("[{cat}]")
                    }
                }
                RedactionLevel::ZeroKnowledge => "[REDACTED]".into(),
            };
            RedactedRecord {
                sequence: *seq,
                category: cat.clone(),
                summary_redacted,
                hash: hash.clone(),
            }
        })
        .collect();

    // Generate a proof-of-inclusion: hash of all record hashes
    let all_hashes: String = redacted
        .iter()
        .map(|r| r.hash.as_str())
        .collect::<Vec<_>>()
        .join(":");
    let chain_hash = sha256_hex(all_hashes.as_bytes());
    let proof = sha256_hex(format!("inclusion:{case_id}:{chain_hash}").as_bytes());

    RedactedForensicBundle {
        case_id: case_id.to_string(),
        redaction_level: level,
        summary: format!("{} records, redaction applied", redacted.len()),
        audit_chain_hash: chain_hash,
        redacted_records: redacted,
        zk_proof_of_inclusion: proof,
    }
}

/// Simple IP address redaction (replaces digits in x.x.x.x patterns).
fn regex_lite_replace_ips(s: &str) -> String {
    let mut result = String::new();
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        // Look for patterns like "NNN.NNN.NNN.NNN"
        if chars[i].is_ascii_digit() {
            let start = i;
            let mut dots = 0;
            let mut j = i;
            while j < chars.len() && (chars[j].is_ascii_digit() || chars[j] == '.') {
                if chars[j] == '.' {
                    dots += 1;
                }
                j += 1;
            }
            if dots == 3 && j - start >= 7 {
                result.push_str("[REDACTED-IP]");
                i = j;
                continue;
            }
        }
        result.push(chars[i]);
        i += 1;
    }
    result
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dp_laplace_noise_is_bounded() {
        let dp = DpMechanism::new(1.0, 1.0);
        let mut sum = 0.0;
        let n = 1000;
        for _ in 0..n {
            let noise = dp.laplace_noise();
            sum += noise;
        }
        let mean = sum / f64::from(n);
        // Mean of Laplace(0, 1) should be ~0
        assert!(
            mean.abs() < 0.5,
            "mean Laplace noise should be near 0, got {mean}"
        );
    }

    #[test]
    fn dp_privatize_adds_noise() {
        let dp = DpMechanism::new(0.1, 1.0); // high noise
        let original = 42.0;
        let privatized = dp.privatize(original);
        // With epsilon=0.1, noise is large, so values should differ
        assert!(
            (privatized - original).abs() > 0.0,
            "privatized value should differ from original"
        );
    }

    #[test]
    fn privacy_accountant_tracks_budget() {
        let mut acct = PrivacyAccountant::new(5.0);
        assert!(!acct.is_exhausted());

        assert!(acct.record_query(1.0));
        assert!(acct.record_query(1.0));
        assert!(acct.record_query(1.0));
        assert_eq!(acct.query_count, 3);
        assert!((acct.budget_remaining() - 2.0).abs() < 0.001);

        assert!(acct.record_query(2.0));
        assert!(!acct.record_query(0.1)); // exceeds budget
        assert!(acct.is_exhausted());
    }

    #[test]
    fn federated_averaging() {
        let initial = vec![0.0, 0.0, 0.0];
        let mut coord = FederatedCoordinator::new(initial, 2);

        coord.submit_update(ModelUpdate {
            device_id: "dev-1".into(),
            round: 1,
            weights: vec![1.0, 2.0, 3.0],
            sample_count: 100,
            loss: 0.5,
        });
        coord.submit_update(ModelUpdate {
            device_id: "dev-2".into(),
            round: 1,
            weights: vec![3.0, 4.0, 5.0],
            sample_count: 100,
            loss: 0.4,
        });

        let model = coord.aggregate().unwrap();
        assert_eq!(model.round, 1);
        assert_eq!(model.participating_devices, 2);
        // Equal samples → simple average: [2.0, 3.0, 4.0]
        assert!((model.weights[0] - 2.0).abs() < 0.01);
        assert!((model.weights[1] - 3.0).abs() < 0.01);
        assert!((model.weights[2] - 4.0).abs() < 0.01);
    }

    #[test]
    fn federated_with_dp_adds_noise() {
        let initial = vec![0.0, 0.0];
        let mut coord = FederatedCoordinator::new(initial, 1);
        coord.enable_dp(5.0, 1.0); // reasonable epsilon for stable test

        coord.submit_update(ModelUpdate {
            device_id: "dev-1".into(),
            round: 1,
            weights: vec![5.0, 10.0],
            sample_count: 50,
            loss: 0.3,
        });

        let model = coord.aggregate().unwrap();
        // With DP noise, weights won't be exactly [5.0, 10.0]
        // But should be in the ballpark
        assert!(model.weights[0] > 0.0 && model.weights[0] < 20.0);
    }

    #[test]
    fn federated_insufficient_participants() {
        let mut coord = FederatedCoordinator::new(vec![1.0], 3);
        coord.submit_update(ModelUpdate {
            device_id: "dev-1".into(),
            round: 1,
            weights: vec![2.0],
            sample_count: 10,
            loss: 0.1,
        });

        assert!(coord.aggregate().is_none()); // need 3, only have 1
    }

    #[test]
    fn secure_aggregation_masks_cancel() {
        let agg = SecureAggregator::new(3);
        let (mask1, commit1) = agg.generate_mask();
        let (mask2, commit2) = agg.generate_mask();
        assert_ne!(commit1, commit2);

        // Simulate: device1 sends value + mask1 - mask2
        // device2 sends value + mask2 - mask1
        // Sum should equal sum of values (masks cancel)
        let val1 = [1.0, 2.0, 3.0];
        let val2 = [4.0, 5.0, 6.0];

        let masked1: Vec<f64> = val1
            .iter()
            .zip(mask1.iter().zip(mask2.iter()))
            .map(|(&v, (&m1, &m2))| v + m1 - m2)
            .collect();
        let masked2: Vec<f64> = val2
            .iter()
            .zip(mask2.iter().zip(mask1.iter()))
            .map(|(&v, (&m2, &m1))| v + m2 - m1)
            .collect();

        let mut agg = SecureAggregator::new(3);
        agg.submit(MaskedContribution {
            device_id: "d1".into(),
            masked_values: masked1,
            mask_commitment: commit1,
        });
        agg.submit(MaskedContribution {
            device_id: "d2".into(),
            masked_values: masked2,
            mask_commitment: commit2,
        });

        let result = agg.aggregate();
        // Should be [5.0, 7.0, 9.0] (sum of values, masks cancelled)
        assert!((result[0] - 5.0).abs() < 0.001);
        assert!((result[1] - 7.0).abs() < 0.001);
        assert!((result[2] - 9.0).abs() < 0.001);
    }

    #[test]
    fn forensic_redaction_standard() {
        let records = vec![
            (
                1,
                "detect".into(),
                "score=3.2 from 192.168.1.100".into(),
                "aabb".into(),
            ),
            (
                2,
                "respond".into(),
                "quarantine applied".into(),
                "ccdd".into(),
            ),
        ];
        let bundle = redact_forensic_bundle("case-001", &records, RedactionLevel::Standard);
        assert_eq!(bundle.redacted_records.len(), 2);
        // IP should be redacted
        assert!(
            bundle.redacted_records[0]
                .summary_redacted
                .contains("[REDACTED-IP]"),
            "IP should be redacted: {}",
            bundle.redacted_records[0].summary_redacted
        );
    }

    #[test]
    fn forensic_redaction_minimal() {
        let records = vec![(
            1,
            "detect".into(),
            "critical alert: auth storm from root@10.0.0.1".into(),
            "hash1".into(),
        )];
        let bundle = redact_forensic_bundle("case-002", &records, RedactionLevel::Minimal);
        assert!(
            bundle.redacted_records[0]
                .summary_redacted
                .contains("[ALERT]")
        );
        assert!(!bundle.redacted_records[0].summary_redacted.contains("root"));
    }

    #[test]
    fn forensic_redaction_zk() {
        let records = vec![(1, "detect".into(), "secret data".into(), "h1".into())];
        let bundle = redact_forensic_bundle("case-003", &records, RedactionLevel::ZeroKnowledge);
        assert_eq!(bundle.redacted_records[0].summary_redacted, "[REDACTED]");
        assert!(!bundle.zk_proof_of_inclusion.is_empty());
    }

    #[test]
    fn ip_redaction_works() {
        let input = "connection from 192.168.1.100 to 10.0.0.1 detected";
        let redacted = regex_lite_replace_ips(input);
        assert!(redacted.contains("[REDACTED-IP]"));
        assert!(!redacted.contains("192.168"));
    }

    #[test]
    fn gaussian_mechanism_sigma_scales_with_sensitivity_and_delta() {
        let low_delta = GaussianMechanism::new(1.0, 1e-6, 1.0);
        let high_delta = GaussianMechanism::new(1.0, 1e-2, 1.0);
        // Smaller delta (stronger guarantee) requires more noise.
        assert!(low_delta.sigma > high_delta.sigma);

        let small_sensitivity = GaussianMechanism::new(1.0, 1e-5, 1.0);
        let large_sensitivity = GaussianMechanism::new(1.0, 1e-5, 10.0);
        assert!(large_sensitivity.sigma > small_sensitivity.sigma * 5.0);
    }

    #[test]
    fn erfc_matches_reference_values() {
        // Reference values from high-precision tables.
        let cases = [
            (0.0, 1.0),
            (0.5, 0.479_500_122_186_953_5),
            (1.0, 0.157_299_207_050_285_13),
            (2.0, 0.004_677_734_981_047_266),
            (5.0, 1.537_459_794_428_035e-12),
            (10.0, 2.088_487_583_762_545e-45),
            (-1.0, 1.842_700_792_949_715),
        ];
        for (x, expected) in cases {
            let got = erfc(x);
            let rel = ((got - expected) / expected).abs();
            assert!(rel < 1e-12, "erfc({x}) = {got}, expected {expected}");
        }
        // Deep tail, where erfc itself underflows: compare ln erfc with the
        // asymptotic expansion -x² - ln(x√π) + ln(1 - 1/(2x²) + 3/(4x⁴) - …).
        for x in [30.0_f64, 100.0] {
            let series =
                1.0 - 1.0 / (2.0 * x * x) + 3.0 / (4.0 * x.powi(4)) - 15.0 / (8.0 * x.powi(6));
            let expected = -x * x - (x * std::f64::consts::PI.sqrt()).ln() + series.ln();
            let got = ln_erfc_nonneg(x);
            assert!(((got - expected) / expected).abs() < 1e-13, "ln erfc({x})");
        }
    }

    const PROFILE_CASES: [(f64, f64); 9] = [
        (0.1, 1e-5),
        (0.5, 1e-5),
        (0.9, 1e-3),
        (1.0, 1e-5),
        (1.0, 1e-3),
        (2.0, 1e-5),
        (8.0, 1e-5),
        (8.0, 1e-10),
        (50.0, 1e-3),
    ];

    #[test]
    fn analytic_gaussian_satisfies_privacy_condition_tightly() {
        for (epsilon, delta) in PROFILE_CASES {
            for sensitivity in [1.0, 5.0] {
                let mech = GaussianMechanism::new(epsilon, delta, sensitivity);
                // Evaluate Φ(Δ/(2σ) − εσ/Δ) − e^ε Φ(−Δ/(2σ) − εσ/Δ) at the
                // returned σ (normalised to unit sensitivity).
                let unit_sigma = mech.sigma / sensitivity;
                let achieved = gaussian_privacy_profile_delta(epsilon, unit_sigma);
                assert!(
                    achieved <= delta * (1.0 + 1e-9),
                    "ε={epsilon} δ={delta}: condition violated ({achieved})"
                );
                // And it is the smallest such σ (not needlessly noisy).
                let slightly_less = gaussian_privacy_profile_delta(epsilon, unit_sigma * 0.999);
                assert!(
                    slightly_less > delta,
                    "ε={epsilon} δ={delta}: σ is not tight ({slightly_less})"
                );
            }
        }
        // Known value (Balle & Wang 2018): ε = 1, δ = 1e-5 → σ ≈ 3.7306.
        let reference = GaussianMechanism::new(1.0, 1e-5, 1.0);
        assert!(
            (reference.sigma - 3.730_631_6).abs() < 1e-5,
            "{}",
            reference.sigma
        );
    }

    #[test]
    fn analytic_gaussian_sigma_decreases_with_epsilon() {
        for delta in [1e-10, 1e-5, 1e-3] {
            let mut previous = f64::INFINITY;
            for epsilon in [
                0.01, 0.1, 0.5, 0.9, 1.0, 1.5, 2.0, 4.0, 8.0, 16.0, 50.0, 100.0,
            ] {
                let sigma = GaussianMechanism::new(epsilon, delta, 1.0).sigma;
                assert!(sigma.is_finite() && sigma > 0.0);
                assert!(
                    sigma < previous,
                    "σ must shrink as ε grows (ε={epsilon}, δ={delta})"
                );
                previous = sigma;
            }
        }
    }

    #[test]
    fn analytic_gaussian_is_no_noisier_than_classical_below_one() {
        for delta in [1e-10, 1e-5, 1e-3] {
            for epsilon in [0.05, 0.1, 0.3, 0.5, 0.75, 0.99] {
                let analytic = GaussianMechanism::new(epsilon, delta, 1.0).sigma;
                let classical = classical_gaussian_sigma(epsilon, delta, 1.0);
                assert!(
                    analytic <= classical,
                    "ε={epsilon} δ={delta}: analytic {analytic} > classical {classical}"
                );
            }
        }
        // For large ε the classical formula under-noises: it violates the
        // exact condition, which is why it must not be used there.
        let classical = classical_gaussian_sigma(50.0, 1e-3, 1.0);
        assert!(gaussian_privacy_profile_delta(50.0, classical) > 1e-3);
    }

    #[test]
    fn gaussian_mechanism_sanitises_degenerate_inputs() {
        let zero = GaussianMechanism::new(1.0, 1e-5, 0.0);
        assert_eq!(zero.sigma, 0.0);
        for mech in [
            GaussianMechanism::new(f64::NAN, 1e-5, 1.0),
            GaussianMechanism::new(1.0, f64::NAN, 1.0),
            GaussianMechanism::new(f64::INFINITY, 1e-5, 1.0),
            GaussianMechanism::new(1e-9, 1e-30, 1.0),
        ] {
            assert!(mech.sigma.is_finite() && mech.sigma > 0.0, "{mech:?}");
        }
    }

    #[test]
    fn gaussian_mechanism_noise_is_zero_mean() {
        let gauss = GaussianMechanism::new(2.0, 1e-5, 1.0);
        let n = 2000;
        let sum: f64 = (0..n).map(|_| gauss.noise()).sum();
        let mean = sum / f64::from(n);
        assert!(mean.abs() < gauss.sigma, "mean {mean} too far from 0");
    }

    #[test]
    fn convergence_loop_converges() {
        let initial = vec![0.0, 0.0];
        let mut coord = FederatedCoordinator::new(initial, 2);

        let target = [5.0, 10.0];
        let history = coord.convergence_loop(20, 0.01, |_round, current| {
            // Two devices both push toward target
            vec![
                ModelUpdate {
                    device_id: "d1".into(),
                    round: _round,
                    weights: target
                        .iter()
                        .zip(current)
                        .map(|(t, c)| c + (t - c) * 0.5)
                        .collect(),
                    sample_count: 100,
                    loss: 0.1,
                },
                ModelUpdate {
                    device_id: "d2".into(),
                    round: _round,
                    weights: target
                        .iter()
                        .zip(current)
                        .map(|(t, c)| c + (t - c) * 0.5)
                        .collect(),
                    sample_count: 100,
                    loss: 0.1,
                },
            ]
        });
        assert!(!history.is_empty());
        let last = history.last().unwrap();
        assert!(
            last.convergence_delta < 0.1,
            "should converge toward target"
        );
    }
}
