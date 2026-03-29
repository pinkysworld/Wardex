//! Post-quantum cryptography, quantum-walk propagation, and key rotation.
//!
//! Implements Lamport one-time signatures (hash-based, quantum-resistant),
//! quantum-walk threat propagation models, and automated key rotation.
//! Covers research tracks R04 (quantum walk), R11 (PQ audit), R21 (PQ key rotation).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::audit::sha256_hex;

// ── Lamport One-Time Signatures (Post-Quantum) ───────────────────────────────

/// A Lamport private key: 256 pairs of 256-bit random values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LamportPrivateKey {
    /// 256 pairs of (zero_preimage, one_preimage), each 32 bytes hex-encoded
    pub pairs: Vec<(String, String)>,
    pub key_id: String,
    pub used: bool,
}

/// A Lamport public key: 256 pairs of hash values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LamportPublicKey {
    /// 256 pairs of (H(zero_preimage), H(one_preimage))
    pub pairs: Vec<(String, String)>,
    pub key_id: String,
}

/// A Lamport signature: 256 revealed preimages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LamportSignature {
    pub revealed: Vec<String>,
    pub key_id: String,
}

impl LamportPrivateKey {
    /// Generate a new Lamport private key using the system RNG.
    pub fn generate() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let key_id = hex::encode((0..8).map(|_| rng.r#gen::<u8>()).collect::<Vec<_>>());
        let pairs: Vec<(String, String)> = (0..256)
            .map(|_| {
                let zero: Vec<u8> = (0..32).map(|_| rng.r#gen()).collect();
                let one: Vec<u8> = (0..32).map(|_| rng.r#gen()).collect();
                (hex::encode(&zero), hex::encode(&one))
            })
            .collect();
        Self {
            pairs,
            key_id,
            used: false,
        }
    }

    /// Derive the corresponding public key.
    pub fn public_key(&self) -> LamportPublicKey {
        let pairs = self
            .pairs
            .iter()
            .map(|(zero, one)| {
                let h0 = sha256_hex(zero.as_bytes());
                let h1 = sha256_hex(one.as_bytes());
                (h0, h1)
            })
            .collect();
        LamportPublicKey {
            pairs,
            key_id: self.key_id.clone(),
        }
    }

    /// Sign a message (the key should only be used once).
    pub fn sign(&mut self, message: &[u8]) -> LamportSignature {
        self.used = true;
        let msg_hash = sha256_hex(message);
        let hash_bytes = hex::decode(&msg_hash).unwrap_or_else(|_| vec![0u8; 32]);

        let revealed: Vec<String> = (0..256)
            .map(|i| {
                let byte_idx = i / 8;
                let bit_idx = 7 - (i % 8);
                let bit = (hash_bytes[byte_idx] >> bit_idx) & 1;
                if bit == 0 {
                    self.pairs[i].0.clone()
                } else {
                    self.pairs[i].1.clone()
                }
            })
            .collect();

        LamportSignature {
            revealed,
            key_id: self.key_id.clone(),
        }
    }
}

impl LamportPublicKey {
    /// Verify a Lamport signature against this public key.
    pub fn verify(&self, message: &[u8], signature: &LamportSignature) -> bool {
        if signature.revealed.len() != 256 || self.pairs.len() != 256 {
            return false;
        }
        if signature.key_id != self.key_id {
            return false;
        }

        let msg_hash = sha256_hex(message);
        let hash_bytes = hex::decode(&msg_hash).unwrap_or_else(|_| vec![0u8; 32]);

        for i in 0..256 {
            let byte_idx = i / 8;
            let bit_idx = 7 - (i % 8);
            let bit = (hash_bytes[byte_idx] >> bit_idx) & 1;

            let hashed_revealed = sha256_hex(signature.revealed[i].as_bytes());
            let expected = if bit == 0 {
                &self.pairs[i].0
            } else {
                &self.pairs[i].1
            };

            if hashed_revealed != *expected {
                return false;
            }
        }
        true
    }
}

// ── Key Rotation Protocol (R21) ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEpoch {
    pub epoch: u64,
    pub key_id: String,
    pub created_at: String,
    pub expires_at: String,
    pub algorithm: String,
    pub status: String, // "active" | "retiring" | "expired"
}

#[derive(Debug)]
pub struct KeyRotationManager {
    epochs: Vec<KeyEpoch>,
    current_epoch: u64,
    rotation_interval_secs: u64,
    active_keys: HashMap<String, LamportPublicKey>,
}

impl KeyRotationManager {
    pub fn new(rotation_interval_secs: u64) -> Self {
        Self {
            epochs: Vec::new(),
            current_epoch: 0,
            rotation_interval_secs,
            active_keys: HashMap::new(),
        }
    }

    /// Generate a new key pair and advance the epoch.
    pub fn rotate(&mut self) -> (LamportPrivateKey, LamportPublicKey) {
        self.current_epoch += 1;
        let private = LamportPrivateKey::generate();
        let public = private.public_key();

        // Retire previous active keys
        for epoch in &mut self.epochs {
            if epoch.status == "active" {
                epoch.status = "retiring".into();
            }
        }

        let now = chrono::Utc::now();
        let expires = now
            + chrono::Duration::seconds(self.rotation_interval_secs as i64);

        self.epochs.push(KeyEpoch {
            epoch: self.current_epoch,
            key_id: public.key_id.clone(),
            created_at: now.to_rfc3339(),
            expires_at: expires.to_rfc3339(),
            algorithm: "lamport-sha256".into(),
            status: "active".into(),
        });

        self.active_keys
            .insert(public.key_id.clone(), public.clone());
        (private, public)
    }

    /// Verify a signature using any active or retiring key.
    pub fn verify_with_any(
        &self,
        message: &[u8],
        signature: &LamportSignature,
    ) -> bool {
        if let Some(pubkey) = self.active_keys.get(&signature.key_id) {
            pubkey.verify(message, signature)
        } else {
            false
        }
    }

    /// Get current epoch number.
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Get all epoch records.
    pub fn epochs(&self) -> &[KeyEpoch] {
        &self.epochs
    }

    /// Expire keys older than the rotation interval.
    pub fn expire_old_keys(&mut self) {
        let now = chrono::Utc::now();
        for epoch in &mut self.epochs {
            if epoch.status == "retiring" {
                if let Ok(expires) = chrono::DateTime::parse_from_rfc3339(&epoch.expires_at) {
                    if now > expires {
                        epoch.status = "expired".into();
                        self.active_keys.remove(&epoch.key_id);
                    }
                }
            }
        }
    }
}

// ── Quantum-Walk Threat Propagation (R04) ────────────────────────────────────

/// A node in the quantum-walk graph representing a device or service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QwNode {
    pub id: String,
    pub amplitude: f64, // probability amplitude (complex modulus)
    pub phase: f64,     // phase angle in radians
    pub threat_level: f64,
}

/// Result of a quantum walk simulation step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QwStepResult {
    pub step: usize,
    pub node_states: Vec<QwNode>,
    pub total_probability: f64,
    pub max_threat_node: String,
    pub max_threat_level: f64,
}

/// Quantum-walk propagation engine.
///
/// Models threat spread across a network using quantum walk dynamics.
/// Each node has a complex amplitude; the walk operator distributes
/// probability amplitudes to neighbours at each step.
#[derive(Debug)]
pub struct QuantumWalkEngine {
    nodes: Vec<QwNode>,
    adjacency: Vec<Vec<f64>>, // adjacency/transition matrix
}

impl QuantumWalkEngine {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            adjacency: Vec::new(),
        }
    }

    /// Initialize the graph with a set of node IDs.
    pub fn init_graph(&mut self, node_ids: &[&str]) {
        self.nodes = node_ids
            .iter()
            .map(|&id| QwNode {
                id: id.to_string(),
                amplitude: 0.0,
                phase: 0.0,
                threat_level: 0.0,
            })
            .collect();
        let n = node_ids.len();
        self.adjacency = vec![vec![0.0; n]; n];
    }

    /// Add a weighted edge between two nodes.
    pub fn add_edge(&mut self, from_idx: usize, to_idx: usize, weight: f64) {
        if from_idx < self.adjacency.len() && to_idx < self.adjacency.len() {
            self.adjacency[from_idx][to_idx] = weight;
            self.adjacency[to_idx][from_idx] = weight; // undirected
        }
    }

    /// Inject initial threat at a specific node.
    pub fn inject_threat(&mut self, node_idx: usize, amplitude: f64) {
        if node_idx < self.nodes.len() {
            self.nodes[node_idx].amplitude = amplitude;
            self.nodes[node_idx].threat_level = amplitude * amplitude;
        }
    }

    /// Execute one step of the quantum walk.
    ///
    /// Uses a Grover-like coin operator: at each node, the amplitude is
    /// distributed to neighbours proportionally to edge weights, with a
    /// phase shift determined by the coin operator.
    pub fn step(&mut self) -> QwStepResult {
        let n = self.nodes.len();
        let mut new_amplitudes = vec![0.0f64; n];

        for i in 0..n {
            let degree: f64 = self.adjacency[i].iter().sum();
            if degree <= 0.0 {
                // Isolated node: amplitude stays
                new_amplitudes[i] += self.nodes[i].amplitude;
                continue;
            }

            // Grover diffusion: reflect amplitude through average
            let coin_factor = 2.0 / degree;
            for j in 0..n {
                if self.adjacency[i][j] > 0.0 {
                    let transfer = self.nodes[i].amplitude * self.adjacency[i][j] * coin_factor;
                    new_amplitudes[j] += transfer;
                }
            }
            // Subtract the original amplitude (Grover reflection)
            new_amplitudes[i] -= self.nodes[i].amplitude;
        }

        // Update node states
        let mut total_prob = 0.0;
        for (i, node) in self.nodes.iter_mut().enumerate() {
            node.amplitude = new_amplitudes[i];
            node.threat_level = node.amplitude * node.amplitude;
            total_prob += node.threat_level;
        }

        // Normalize to preserve total probability
        if total_prob > 0.0 {
            let norm = (1.0_f64 / total_prob).sqrt();
            for node in &mut self.nodes {
                node.amplitude *= norm;
                node.threat_level = node.amplitude * node.amplitude;
            }
        }

        let (max_idx, max_threat) = self
            .nodes
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| {
                a.threat_level
                    .partial_cmp(&b.threat_level)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(i, n)| (i, n.threat_level))
            .unwrap_or((0, 0.0));

        QwStepResult {
            step: 0, // caller tracks step count
            node_states: self.nodes.clone(),
            total_probability: self
                .nodes
                .iter()
                .map(|n| n.threat_level)
                .sum(),
            max_threat_node: self
                .nodes
                .get(max_idx)
                .map(|n| n.id.clone())
                .unwrap_or_default(),
            max_threat_level: max_threat,
        }
    }

    /// Run the quantum walk for multiple steps and return the trace.
    pub fn run(&mut self, steps: usize) -> Vec<QwStepResult> {
        let mut trace = Vec::with_capacity(steps);
        for s in 0..steps {
            let mut result = self.step();
            result.step = s + 1;
            trace.push(result);
        }
        trace
    }

    /// Get current node states.
    pub fn nodes(&self) -> &[QwNode] {
        &self.nodes
    }
}

// ── Post-Quantum Audit Log Signing (R11) ─────────────────────────────────────

/// A PQ-signed audit checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqSignedCheckpoint {
    pub sequence: u64,
    pub cumulative_hash: String,
    pub epoch: u64,
    pub key_id: String,
    pub signature: LamportSignature,
}

/// Sign an audit checkpoint hash with a Lamport key.
pub fn sign_checkpoint(
    seq: u64,
    cumulative_hash: &str,
    private_key: &mut LamportPrivateKey,
    epoch: u64,
) -> PqSignedCheckpoint {
    let message = format!("{seq}:{cumulative_hash}:{epoch}");
    let signature = private_key.sign(message.as_bytes());
    PqSignedCheckpoint {
        sequence: seq,
        cumulative_hash: cumulative_hash.to_string(),
        epoch,
        key_id: private_key.key_id.clone(),
        signature,
    }
}

/// Verify a PQ-signed checkpoint.
pub fn verify_checkpoint(checkpoint: &PqSignedCheckpoint, public_key: &LamportPublicKey) -> bool {
    let message = format!(
        "{}:{}:{}",
        checkpoint.sequence, checkpoint.cumulative_hash, checkpoint.epoch
    );
    public_key.verify(message.as_bytes(), &checkpoint.signature)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lamport_keygen_produces_256_pairs() {
        let private = LamportPrivateKey::generate();
        assert_eq!(private.pairs.len(), 256);
        assert!(!private.used);

        let public = private.public_key();
        assert_eq!(public.pairs.len(), 256);
        assert_eq!(public.key_id, private.key_id);
    }

    #[test]
    fn lamport_sign_and_verify() {
        let mut private = LamportPrivateKey::generate();
        let public = private.public_key();
        let message = b"SentinelEdge audit checkpoint #42";

        let signature = private.sign(message);
        assert!(private.used);
        assert_eq!(signature.revealed.len(), 256);

        assert!(public.verify(message, &signature));
    }

    #[test]
    fn lamport_rejects_tampered_message() {
        let mut private = LamportPrivateKey::generate();
        let public = private.public_key();
        let signature = private.sign(b"original message");

        assert!(!public.verify(b"tampered message", &signature));
    }

    #[test]
    fn lamport_rejects_wrong_key() {
        let mut private1 = LamportPrivateKey::generate();
        let private2 = LamportPrivateKey::generate();
        let public2 = private2.public_key();

        let signature = private1.sign(b"test");
        assert!(!public2.verify(b"test", &signature));
    }

    #[test]
    fn key_rotation_advances_epoch() {
        let mut mgr = KeyRotationManager::new(3600);
        assert_eq!(mgr.current_epoch(), 0);

        let (_priv1, _pub1) = mgr.rotate();
        assert_eq!(mgr.current_epoch(), 1);
        assert_eq!(mgr.epochs().len(), 1);
        assert_eq!(mgr.epochs()[0].status, "active");

        let (_priv2, _pub2) = mgr.rotate();
        assert_eq!(mgr.current_epoch(), 2);
        // First key should be retiring
        assert_eq!(mgr.epochs()[0].status, "retiring");
        assert_eq!(mgr.epochs()[1].status, "active");

        // Verify with any active key
        let mut priv_test = LamportPrivateKey::generate();
        let pub_test = priv_test.public_key();
        mgr.active_keys
            .insert(pub_test.key_id.clone(), pub_test.clone());
        let sig = priv_test.sign(b"test");
        assert!(mgr.verify_with_any(b"test", &sig));
    }

    #[test]
    fn quantum_walk_propagation() {
        let mut engine = QuantumWalkEngine::new();
        engine.init_graph(&["A", "B", "C", "D"]);
        engine.add_edge(0, 1, 1.0); // A-B
        engine.add_edge(1, 2, 1.0); // B-C
        engine.add_edge(2, 3, 1.0); // C-D

        // Inject threat at node A
        engine.inject_threat(0, 1.0);
        assert!(engine.nodes()[0].threat_level > 0.0);

        // Run 5 steps
        let trace = engine.run(5);
        assert_eq!(trace.len(), 5);

        // Threat should propagate to other nodes
        let final_state = &trace[4];
        let non_zero_threats = final_state
            .node_states
            .iter()
            .filter(|n| n.threat_level > 0.01)
            .count();
        assert!(non_zero_threats > 1, "threat should propagate to multiple nodes");
    }

    #[test]
    fn quantum_walk_total_probability_normalized() {
        let mut engine = QuantumWalkEngine::new();
        engine.init_graph(&["X", "Y", "Z"]);
        engine.add_edge(0, 1, 1.0);
        engine.add_edge(1, 2, 1.0);
        engine.add_edge(0, 2, 0.5);
        engine.inject_threat(0, 1.0);

        let trace = engine.run(10);
        let final_prob = trace.last().unwrap().total_probability;
        // Total probability should be approximately 1.0 (normalized)
        assert!(
            (final_prob - 1.0).abs() < 0.1,
            "total probability should be ~1.0, got {}",
            final_prob
        );
    }

    #[test]
    fn pq_signed_checkpoint_roundtrip() {
        let mut private = LamportPrivateKey::generate();
        let public = private.public_key();

        let checkpoint = sign_checkpoint(42, "abcdef1234567890", &mut private, 1);
        assert_eq!(checkpoint.sequence, 42);
        assert_eq!(checkpoint.epoch, 1);

        assert!(verify_checkpoint(&checkpoint, &public));
    }

    #[test]
    fn pq_signed_checkpoint_rejects_tamper() {
        let mut private = LamportPrivateKey::generate();
        let public = private.public_key();

        let mut checkpoint = sign_checkpoint(42, "original-hash", &mut private, 1);
        checkpoint.cumulative_hash = "tampered-hash".into();

        assert!(!verify_checkpoint(&checkpoint, &public));
    }
}
