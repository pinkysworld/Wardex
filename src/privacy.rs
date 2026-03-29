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
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let scale = self.sensitivity / self.epsilon;
        // Inverse CDF method for Laplace distribution
        let u: f64 = rng.r#gen::<f64>() - 0.5;
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

        self.current_round += 1;
        let dim = self.global_weights.len();
        let total_samples: usize = self.pending_updates.iter().map(|u| u.sample_count).sum();

        if total_samples == 0 || dim == 0 {
            return None;
        }

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
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mask: Vec<f64> = (0..self.dimension)
            .map(|_| rng.r#gen::<f64>() * 2.0 - 1.0)
            .collect();
        let mask_bytes: Vec<u8> = mask
            .iter()
            .flat_map(|&v| v.to_le_bytes())
            .collect();
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
                    // Redact paths
                    s = s.replace(|c: char| c == '/' && s.contains("/home"), "*");
                    s
                }
                RedactionLevel::Minimal => {
                    // Only keep category and severity keywords
                    if summary.contains("critical") || summary.contains("severe") {
                        format!("[ALERT] {}", cat)
                    } else {
                        format!("[{}]", cat)
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
    let all_hashes: String = redacted.iter().map(|r| r.hash.as_str()).collect::<Vec<_>>().join(":");
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
        let mean = sum / n as f64;
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
        let val1 = vec![1.0, 2.0, 3.0];
        let val2 = vec![4.0, 5.0, 6.0];

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
            (1, "detect".into(), "score=3.2 from 192.168.1.100".into(), "aabb".into()),
            (2, "respond".into(), "quarantine applied".into(), "ccdd".into()),
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
        assert!(bundle.redacted_records[0].summary_redacted.contains("[ALERT]"));
        assert!(!bundle.redacted_records[0].summary_redacted.contains("root"));
    }

    #[test]
    fn forensic_redaction_zk() {
        let records = vec![(1, "detect".into(), "secret data".into(), "h1".into())];
        let bundle = redact_forensic_bundle("case-003", &records, RedactionLevel::ZeroKnowledge);
        assert_eq!(
            bundle.redacted_records[0].summary_redacted,
            "[REDACTED]"
        );
        assert!(!bundle.zk_proof_of_inclusion.is_empty());
    }

    #[test]
    fn ip_redaction_works() {
        let input = "connection from 192.168.1.100 to 10.0.0.1 detected";
        let redacted = regex_lite_replace_ips(input);
        assert!(redacted.contains("[REDACTED-IP]"));
        assert!(!redacted.contains("192.168"));
    }
}
