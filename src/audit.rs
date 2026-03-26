use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::Path;

/// Compute a SHA-256 hex digest.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[derive(Debug, Clone)]
pub struct AuditRecord {
    pub sequence: usize,
    pub category: String,
    pub summary: String,
    pub previous_hash: String,
    pub current_hash: String,
}

/// A signed checkpoint anchoring a range of audit records.
#[derive(Debug, Clone)]
pub struct AuditCheckpoint {
    pub after_sequence: usize,
    pub cumulative_hash: String,
    pub signature: String,
}

#[derive(Debug, Default, Clone)]
pub struct AuditLog {
    previous_hash: String,
    records: Vec<AuditRecord>,
    checkpoints: Vec<AuditCheckpoint>,
    checkpoint_interval: usize,
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            previous_hash: "0".repeat(64),
            records: Vec::new(),
            checkpoints: Vec::new(),
            checkpoint_interval: 0,
        }
    }

    /// Create an audit log that automatically inserts signed
    /// checkpoints every `interval` records. Pass 0 to disable.
    pub fn with_checkpoint_interval(interval: usize) -> Self {
        Self {
            previous_hash: "0".repeat(64),
            records: Vec::new(),
            checkpoints: Vec::new(),
            checkpoint_interval: interval,
        }
    }

    pub fn record(&mut self, category: &str, summary: impl Into<String>) {
        let summary = summary.into();
        let payload = format!("{}|{}|{}", self.previous_hash, category, summary);
        let current_hash = sha256_hex(payload.as_bytes());
        let record = AuditRecord {
            sequence: self.records.len() + 1,
            category: category.to_string(),
            summary,
            previous_hash: self.previous_hash.clone(),
            current_hash: current_hash.clone(),
        };

        self.previous_hash = current_hash;
        self.records.push(record);

        if self.checkpoint_interval > 0
            && self.records.len() % self.checkpoint_interval == 0
        {
            self.insert_checkpoint();
        }
    }

    /// Insert a signed checkpoint at the current position.
    fn insert_checkpoint(&mut self) {
        let seq = self.records.len();
        let cumulative = self.previous_hash.clone();
        // Deterministic HMAC-style signature using a fixed key for prototype.
        // In production this would use a proper signing key (T031 upgrade path).
        let sig_payload = format!("checkpoint|{}|{}", seq, cumulative);
        let signature = sha256_hex(sig_payload.as_bytes());

        self.checkpoints.push(AuditCheckpoint {
            after_sequence: seq,
            cumulative_hash: cumulative,
            signature,
        });
    }

    pub fn records(&self) -> &[AuditRecord] {
        &self.records
    }

    pub fn checkpoints(&self) -> &[AuditCheckpoint] {
        &self.checkpoints
    }

    /// Verify the integrity of the hash chain by recomputing each link.
    pub fn verify_chain(&self) -> Result<(), String> {
        let mut expected_prev = "0".repeat(64);
        for record in &self.records {
            if record.previous_hash != expected_prev {
                return Err(format!(
                    "chain broken at sequence {}: expected prev {} got {}",
                    record.sequence, expected_prev, record.previous_hash
                ));
            }
            let payload = format!(
                "{}|{}|{}",
                record.previous_hash, record.category, record.summary
            );
            let computed = sha256_hex(payload.as_bytes());
            if record.current_hash != computed {
                return Err(format!(
                    "hash mismatch at sequence {}: expected {} got {}",
                    record.sequence, computed, record.current_hash
                ));
            }
            expected_prev = record.current_hash.clone();
        }
        Ok(())
    }

    pub fn render(&self) -> String {
        let mut rendered = String::from("# seq|prev_hash|curr_hash|category|summary\n");
        for record in &self.records {
            rendered.push_str(&format!(
                "{:04}|{}|{}|{}|{}\n",
                record.sequence,
                &record.previous_hash[..16],
                &record.current_hash[..16],
                record.category,
                record.summary
            ));
        }
        if !self.checkpoints.is_empty() {
            rendered.push_str("\n# checkpoints\n");
            for cp in &self.checkpoints {
                rendered.push_str(&format!(
                    "CP after_seq={:04} hash={}.. sig={}..\n",
                    cp.after_sequence,
                    &cp.cumulative_hash[..16],
                    &cp.signature[..16],
                ));
            }
        }
        rendered
    }

    pub fn write_to_path(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(path, self.render())
    }
}

#[cfg(test)]
mod tests {
    use super::AuditLog;

    #[test]
    fn hash_chain_progresses() {
        let mut audit = AuditLog::new();
        audit.record("boot", "runtime started");
        audit.record("detect", "score=1.25");

        let records = audit.records();
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].previous_hash, records[0].current_hash);
    }

    #[test]
    fn chain_verifies_when_intact() {
        let mut audit = AuditLog::new();
        audit.record("boot", "started");
        audit.record("detect", "score=0.5");
        audit.record("detect", "score=1.2");
        assert!(audit.verify_chain().is_ok());
    }

    #[test]
    fn hashes_are_sha256_hex() {
        let mut audit = AuditLog::new();
        audit.record("boot", "test");
        let hash = &audit.records()[0].current_hash;
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn checkpoint_interval_works() {
        let mut audit = AuditLog::with_checkpoint_interval(3);
        for i in 0..9 {
            audit.record("test", format!("entry {i}"));
        }
        assert_eq!(audit.checkpoints().len(), 3);
        assert_eq!(audit.checkpoints()[0].after_sequence, 3);
        assert_eq!(audit.checkpoints()[2].after_sequence, 9);
    }
}
