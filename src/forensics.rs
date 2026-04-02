use serde::Serialize;
use std::fs;
use std::path::Path;

use crate::runtime::RunResult;

use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use aes_gcm::aead::generic_array::GenericArray;
use rand::RngCore;

#[derive(Debug, Clone, Serialize)]
pub struct ForensicBundle {
    pub generated_at: String,
    pub total_samples: usize,
    pub alert_count: usize,
    pub critical_count: usize,
    pub average_score: f32,
    pub max_score: f32,
    pub audit_records: Vec<ForensicAuditEntry>,
    pub checkpoints: Vec<ForensicCheckpointEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ForensicAuditEntry {
    pub sequence: usize,
    pub category: String,
    pub summary: String,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ForensicCheckpointEntry {
    pub after_sequence: usize,
    pub cumulative_hash: String,
    pub signature: String,
}

impl ForensicBundle {
    pub fn from_run_result(result: &RunResult) -> Self {
        let audit_records = result
            .audit
            .records()
            .iter()
            .map(|r| ForensicAuditEntry {
                sequence: r.sequence,
                category: r.category.clone(),
                summary: r.summary.clone(),
                hash: r.current_hash.clone(),
            })
            .collect();

        let checkpoints = result
            .audit
            .checkpoints()
            .iter()
            .map(|cp| ForensicCheckpointEntry {
                after_sequence: cp.after_sequence,
                cumulative_hash: cp.cumulative_hash.clone(),
                signature: cp.signature.clone(),
            })
            .collect();

        Self {
            generated_at: chrono::Utc::now().to_rfc3339(),
            total_samples: result.summary.total_samples,
            alert_count: result.summary.alert_count,
            critical_count: result.summary.critical_count,
            average_score: result.summary.average_score,
            max_score: result.summary.max_score,
            audit_records,
            checkpoints,
        }
    }

    pub fn write_to_path(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create bundle directory: {e}"))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("failed to serialize forensic bundle: {e}"))?;
        fs::write(path, json).map_err(|e| format!("failed to write forensic bundle: {e}"))
    }

    /// Write the forensic bundle encrypted with AES-256-GCM.
    /// `key` must be exactly 32 bytes. The output file contains: 12-byte nonce ∥ ciphertext.
    pub fn write_encrypted(&self, path: &Path, key: &[u8; 32]) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create bundle directory: {e}"))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("failed to serialize forensic bundle: {e}"))?;

        let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = GenericArray::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, json.as_bytes())
            .map_err(|e| format!("AES-GCM encryption failed: {e}"))?;

        let mut output = Vec::with_capacity(12 + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);

        fs::write(path, output)
            .map_err(|e| format!("failed to write encrypted forensic bundle: {e}"))
    }

    /// Read and decrypt an AES-256-GCM encrypted forensic bundle.
    pub fn read_encrypted(path: &Path, key: &[u8; 32]) -> Result<String, String> {
        let data = fs::read(path)
            .map_err(|e| format!("failed to read encrypted bundle: {e}"))?;
        if data.len() < 12 {
            return Err("encrypted bundle too short".into());
        }
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
        let nonce = GenericArray::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("AES-GCM decryption failed: {e}"))?;

        String::from_utf8(plaintext)
            .map_err(|e| format!("decrypted bundle is not valid UTF-8: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::ForensicBundle;
    use crate::runtime::{demo_samples, execute};

    #[test]
    fn bundle_captures_audit_records() {
        let result = execute(&demo_samples());
        let bundle = ForensicBundle::from_run_result(&result);

        assert_eq!(bundle.total_samples, 5);
        assert!(!bundle.audit_records.is_empty());
        assert!(bundle.max_score > 4.0);
    }

    #[test]
    fn bundle_serializes_to_json() {
        let result = execute(&demo_samples());
        let bundle = ForensicBundle::from_run_result(&result);
        let json = serde_json::to_string_pretty(&bundle).unwrap();

        assert!(json.contains("audit_records"));
        assert!(json.contains("checkpoints"));
        assert!(json.contains("generated_at"));
    }

    #[test]
    fn bundle_encrypt_decrypt_round_trip() {
        let result = execute(&demo_samples());
        let bundle = ForensicBundle::from_run_result(&result);
        let key: [u8; 32] = [0x42; 32];
        let dir = std::env::temp_dir().join("wardex_test_forensic_enc");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("bundle.enc");

        bundle.write_encrypted(&path, &key).unwrap();
        let decrypted = ForensicBundle::read_encrypted(&path, &key).unwrap();
        assert!(decrypted.contains("audit_records"));
        assert!(decrypted.contains("generated_at"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bundle_decrypt_wrong_key_fails() {
        let result = execute(&demo_samples());
        let bundle = ForensicBundle::from_run_result(&result);
        let key: [u8; 32] = [0x42; 32];
        let wrong_key: [u8; 32] = [0x99; 32];
        let dir = std::env::temp_dir().join("wardex_test_forensic_wrong_key");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("bundle.enc");

        bundle.write_encrypted(&path, &key).unwrap();
        assert!(ForensicBundle::read_encrypted(&path, &wrong_key).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
