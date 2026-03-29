use serde::{Deserialize, Serialize};

use crate::audit::sha256_hex;

#[derive(Debug, Clone)]
pub struct ProofEntry {
    pub label: String,
    pub pre_digest: String,
    pub post_digest: String,
    pub timestamp: String,
}

/// Serializable witness bundle that a future ZK prover (Halo2, SNARK) can consume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessBundle {
    pub backend: String,
    pub label: String,
    pub pre_digest: String,
    pub post_digest: String,
    pub timestamp: String,
    /// Opaque witness payload (backend-specific encoding).
    pub witness_hex: String,
    /// If the backend produces a proof, it appears here.
    pub proof_hex: Option<String>,
    pub verified: bool,
}

/// Trait for pluggable proof backends.
pub trait ProofBackend {
    fn backend_name(&self) -> &str;
    fn generate_witness(&self, entry: &ProofEntry) -> WitnessBundle;
    fn verify_witness(&self, witness: &WitnessBundle) -> bool;
}

/// SHA-256 digest backend — the default backend that ships today.
///
/// Witness payload is the concatenation of pre and post digests.
/// Verification re-derives the concatenation and compares.
pub struct DigestBackend;

impl ProofBackend for DigestBackend {
    fn backend_name(&self) -> &str {
        "sha256-digest"
    }

    fn generate_witness(&self, entry: &ProofEntry) -> WitnessBundle {
        let concatenated = format!("{}:{}", entry.pre_digest, entry.post_digest);
        let witness_hex = sha256_hex(concatenated.as_bytes());
        WitnessBundle {
            backend: self.backend_name().into(),
            label: entry.label.clone(),
            pre_digest: entry.pre_digest.clone(),
            post_digest: entry.post_digest.clone(),
            timestamp: entry.timestamp.clone(),
            witness_hex,
            proof_hex: None,
            verified: true,
        }
    }

    fn verify_witness(&self, witness: &WitnessBundle) -> bool {
        let concatenated = format!("{}:{}", witness.pre_digest, witness.post_digest);
        let expected = sha256_hex(concatenated.as_bytes());
        witness.witness_hex == expected
    }
}

/// Stub backend for future Halo2/SNARK integration.
///
/// Generates witness bundles in the same schema but does not produce
/// an actual zero-knowledge proof.  The `proof_hex` field is `None`
/// and `verified` is always `false`, signalling that the proof has
/// not been generated yet.
pub struct ZkStubBackend;

impl ProofBackend for ZkStubBackend {
    fn backend_name(&self) -> &str {
        "zk-stub"
    }

    fn generate_witness(&self, entry: &ProofEntry) -> WitnessBundle {
        // Witness data is the same digest pair — a real backend would
        // encode circuit-specific private inputs here.
        let concatenated = format!("{}:{}", entry.pre_digest, entry.post_digest);
        let witness_hex = sha256_hex(concatenated.as_bytes());
        WitnessBundle {
            backend: self.backend_name().into(),
            label: entry.label.clone(),
            pre_digest: entry.pre_digest.clone(),
            post_digest: entry.post_digest.clone(),
            timestamp: entry.timestamp.clone(),
            witness_hex,
            proof_hex: None,
            verified: false,
        }
    }

    fn verify_witness(&self, _witness: &WitnessBundle) -> bool {
        // No proof to verify — always returns false.
        false
    }
}

#[derive(Default)]
pub struct ProofRegistry {
    proofs: Vec<ProofEntry>,
}

impl ProofRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, label: &str, pre: &[u8], post: &[u8]) {
        self.proofs.push(ProofEntry {
            label: label.to_string(),
            pre_digest: sha256_hex(pre),
            post_digest: sha256_hex(post),
            timestamp: chrono::Utc::now().to_rfc3339(),
        });
    }

    pub fn proofs(&self) -> &[ProofEntry] {
        &self.proofs
    }

    pub fn contains(&self, label: &str) -> bool {
        self.proofs.iter().any(|p| p.label == label)
    }

    /// Export all proof entries as witness bundles using the given backend.
    pub fn export_witnesses(&self, backend: &dyn ProofBackend) -> Vec<WitnessBundle> {
        self.proofs
            .iter()
            .map(|e| backend.generate_witness(e))
            .collect()
    }

    /// Export all proof entries as a JSON string using the given backend.
    pub fn export_witnesses_json(&self, backend: &dyn ProofBackend) -> String {
        let bundles = self.export_witnesses(backend);
        serde_json::to_string_pretty(&bundles).unwrap_or_else(|_| "[]".into())
    }
}

#[cfg(test)]
mod tests {
    use super::{DigestBackend, ProofBackend, ProofRegistry, ZkStubBackend};

    #[test]
    fn record_and_retrieve() {
        let mut registry = ProofRegistry::new();
        registry.record("baseline_update", b"before", b"after");

        assert_eq!(registry.proofs().len(), 1);
        assert_eq!(registry.proofs()[0].label, "baseline_update");
        assert_ne!(
            registry.proofs()[0].pre_digest,
            registry.proofs()[0].post_digest
        );
    }

    #[test]
    fn contains_finds_existing_label() {
        let mut registry = ProofRegistry::new();
        registry.record("test_proof", b"a", b"b");

        assert!(registry.contains("test_proof"));
        assert!(!registry.contains("nonexistent"));
    }

    #[test]
    fn digests_are_sha256_hex() {
        let mut registry = ProofRegistry::new();
        registry.record("check", b"data", b"data2");

        let proof = &registry.proofs()[0];
        assert_eq!(proof.pre_digest.len(), 64);
        assert!(proof.pre_digest.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn digest_backend_generates_verified_witness() {
        let mut registry = ProofRegistry::new();
        registry.record("update", b"state_a", b"state_b");

        let backend = DigestBackend;
        let witnesses = registry.export_witnesses(&backend);
        assert_eq!(witnesses.len(), 1);
        assert_eq!(witnesses[0].backend, "sha256-digest");
        assert_eq!(witnesses[0].label, "update");
        assert!(witnesses[0].verified);
        assert!(witnesses[0].proof_hex.is_none());
        assert!(backend.verify_witness(&witnesses[0]));
    }

    #[test]
    fn digest_backend_rejects_tampered_witness() {
        let mut registry = ProofRegistry::new();
        registry.record("update", b"state_a", b"state_b");

        let backend = DigestBackend;
        let mut witness = registry.export_witnesses(&backend).remove(0);
        witness.pre_digest = "0000".repeat(16);
        assert!(!backend.verify_witness(&witness));
    }

    #[test]
    fn zk_stub_backend_generates_unverified_witness() {
        let mut registry = ProofRegistry::new();
        registry.record("update", b"x", b"y");

        let stub = ZkStubBackend;
        let witnesses = registry.export_witnesses(&stub);
        assert_eq!(witnesses.len(), 1);
        assert_eq!(witnesses[0].backend, "zk-stub");
        assert!(!witnesses[0].verified);
        assert!(witnesses[0].proof_hex.is_none());
        assert!(!stub.verify_witness(&witnesses[0]));
    }

    #[test]
    fn export_witnesses_json_produces_valid_json() {
        let mut registry = ProofRegistry::new();
        registry.record("a", b"1", b"2");
        registry.record("b", b"3", b"4");

        let json = registry.export_witnesses_json(&DigestBackend);
        let parsed: Vec<super::WitnessBundle> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].label, "a");
        assert_eq!(parsed[1].label, "b");
    }

    #[test]
    fn backend_name_is_consistent() {
        assert_eq!(DigestBackend.backend_name(), "sha256-digest");
        assert_eq!(ZkStubBackend.backend_name(), "zk-stub");
    }
}
