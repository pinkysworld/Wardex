use crate::audit::sha256_hex;

#[derive(Debug, Clone)]
pub struct ProofEntry {
    pub label: String,
    pub pre_digest: String,
    pub post_digest: String,
    pub timestamp: String,
}

pub struct ProofRegistry {
    proofs: Vec<ProofEntry>,
}

impl ProofRegistry {
    pub fn new() -> Self {
        Self { proofs: Vec::new() }
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

    pub fn verify(&self, label: &str) -> bool {
        self.proofs.iter().any(|p| p.label == label)
    }
}

#[cfg(test)]
mod tests {
    use super::ProofRegistry;

    #[test]
    fn record_and_retrieve() {
        let mut registry = ProofRegistry::new();
        registry.record("baseline_update", b"before", b"after");

        assert_eq!(registry.proofs().len(), 1);
        assert_eq!(registry.proofs()[0].label, "baseline_update");
        assert_ne!(registry.proofs()[0].pre_digest, registry.proofs()[0].post_digest);
    }

    #[test]
    fn verify_finds_existing_label() {
        let mut registry = ProofRegistry::new();
        registry.record("test_proof", b"a", b"b");

        assert!(registry.verify("test_proof"));
        assert!(!registry.verify("nonexistent"));
    }

    #[test]
    fn digests_are_sha256_hex() {
        let mut registry = ProofRegistry::new();
        registry.record("check", b"data", b"data2");

        let proof = &registry.proofs()[0];
        assert_eq!(proof.pre_digest.len(), 64);
        assert!(proof.pre_digest.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
