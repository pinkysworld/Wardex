//! Malware quarantine workflow.
//!
//! Captures, isolates, and stores suspected malicious files for
//! analyst retrieval and forensic analysis. Files are encrypted
//! at rest to prevent accidental execution.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// A quarantined file record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantinedFile {
    pub id: String,
    pub original_path: String,
    pub filename: String,
    pub sha256: String,
    pub md5: String,
    pub size_bytes: usize,
    pub quarantined_at: String,
    pub agent_id: Option<String>,
    pub hostname: Option<String>,
    pub verdict: String,
    pub malware_family: Option<String>,
    pub scan_matches: Vec<String>,
    pub status: QuarantineStatus,
    pub analyst_notes: Option<String>,
    pub released_at: Option<String>,
    pub released_by: Option<String>,
}

/// Quarantine status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum QuarantineStatus {
    Quarantined,
    UnderAnalysis,
    Confirmed,
    FalsePositive,
    Released,
    Deleted,
}

/// Quarantine statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineStats {
    pub total_files: usize,
    pub quarantined: usize,
    pub under_analysis: usize,
    pub confirmed_malicious: usize,
    pub false_positives: usize,
    pub released: usize,
    pub total_size_bytes: u64,
    pub families: Vec<String>,
}

/// Quarantine store.
#[derive(Debug)]
pub struct QuarantineStore {
    files: Vec<QuarantinedFile>,
    /// In-memory encrypted file content store (id → XOR-obfuscated bytes).
    /// Real implementation would use disk-backed encrypted storage.
    content_store: HashMap<String, Vec<u8>>,
    next_id: u64,
}

impl Default for QuarantineStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Simple XOR obfuscation key for quarantine storage.
/// Not cryptographic — prevents accidental execution only.
const QUARANTINE_XOR_KEY: &[u8] = b"WARDEX_QUARANTINE_v1";

impl QuarantineStore {
    pub fn new() -> Self {
        Self {
            files: Vec::new(),
            content_store: HashMap::new(),
            next_id: 1,
        }
    }

    /// Quarantine a file with its content.
    pub fn quarantine(
        &mut self,
        original_path: &str,
        content: &[u8],
        verdict: &str,
        malware_family: Option<String>,
        scan_matches: Vec<String>,
        agent_id: Option<String>,
        hostname: Option<String>,
    ) -> QuarantinedFile {
        let sha256 = {
            let mut hasher = Sha256::new();
            hasher.update(content);
            hex::encode(hasher.finalize())
        };
        let md5 = format!("{:x}", md5::compute(content));

        let id = format!("q-{}", self.next_id);
        self.next_id += 1;

        let filename = std::path::Path::new(original_path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let record = QuarantinedFile {
            id: id.clone(),
            original_path: original_path.to_string(),
            filename,
            sha256,
            md5,
            size_bytes: content.len(),
            quarantined_at: chrono::Utc::now().to_rfc3339(),
            agent_id,
            hostname,
            verdict: verdict.to_string(),
            malware_family,
            scan_matches,
            status: QuarantineStatus::Quarantined,
            analyst_notes: None,
            released_at: None,
            released_by: None,
        };

        // Obfuscate content before storing
        let obfuscated = xor_obfuscate(content);
        self.content_store.insert(id, obfuscated);
        self.files.push(record.clone());
        record
    }

    /// List all quarantined files.
    pub fn list(&self) -> &[QuarantinedFile] {
        &self.files
    }

    /// Get a quarantined file by ID.
    pub fn get(&self, id: &str) -> Option<&QuarantinedFile> {
        self.files.iter().find(|f| f.id == id)
    }

    /// Retrieve quarantined file content (de-obfuscated).
    pub fn retrieve_content(&self, id: &str) -> Option<Vec<u8>> {
        self.content_store.get(id).map(|obf| xor_obfuscate(obf))
    }

    /// Update status and add analyst notes.
    pub fn update_status(
        &mut self,
        id: &str,
        status: QuarantineStatus,
        notes: Option<String>,
    ) -> bool {
        if let Some(file) = self.files.iter_mut().find(|f| f.id == id) {
            file.status = status;
            if let Some(n) = notes {
                file.analyst_notes = Some(n);
            }
            true
        } else {
            false
        }
    }

    /// Release a quarantined file (mark as false positive).
    pub fn release(&mut self, id: &str, analyst: &str) -> bool {
        if let Some(file) = self.files.iter_mut().find(|f| f.id == id) {
            file.status = QuarantineStatus::Released;
            file.released_at = Some(chrono::Utc::now().to_rfc3339());
            file.released_by = Some(analyst.to_string());
            // Remove content from store
            self.content_store.remove(id);
            true
        } else {
            false
        }
    }

    /// Delete a quarantined file permanently.
    pub fn delete(&mut self, id: &str) -> bool {
        self.content_store.remove(id);
        let before = self.files.len();
        self.files.retain(|f| f.id != id);
        self.files.len() < before
    }

    /// Search quarantined files by hash or filename.
    pub fn search(&self, query: &str) -> Vec<&QuarantinedFile> {
        let q = query.to_lowercase();
        self.files
            .iter()
            .filter(|f| {
                f.sha256.contains(&q)
                    || f.md5.contains(&q)
                    || f.filename.to_lowercase().contains(&q)
                    || f.original_path.to_lowercase().contains(&q)
            })
            .collect()
    }

    /// Quarantine statistics.
    pub fn stats(&self) -> QuarantineStats {
        let mut families: Vec<String> = self
            .files
            .iter()
            .filter_map(|f| f.malware_family.clone())
            .collect();
        families.sort();
        families.dedup();

        QuarantineStats {
            total_files: self.files.len(),
            quarantined: self
                .files
                .iter()
                .filter(|f| f.status == QuarantineStatus::Quarantined)
                .count(),
            under_analysis: self
                .files
                .iter()
                .filter(|f| f.status == QuarantineStatus::UnderAnalysis)
                .count(),
            confirmed_malicious: self
                .files
                .iter()
                .filter(|f| f.status == QuarantineStatus::Confirmed)
                .count(),
            false_positives: self
                .files
                .iter()
                .filter(|f| f.status == QuarantineStatus::FalsePositive)
                .count(),
            released: self
                .files
                .iter()
                .filter(|f| f.status == QuarantineStatus::Released)
                .count(),
            total_size_bytes: self
                .files
                .iter()
                .map(|f| f.size_bytes as u64)
                .sum(),
            families,
        }
    }
}

fn xor_obfuscate(data: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ QUARANTINE_XOR_KEY[i % QUARANTINE_XOR_KEY.len()])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quarantine_and_retrieve() {
        let mut store = QuarantineStore::new();
        let content = b"malicious content here";
        let record = store.quarantine(
            "/tmp/evil.exe",
            content,
            "malicious",
            Some("Emotet".into()),
            vec!["hash_db: emotet variant".into()],
            None,
            None,
        );
        assert_eq!(record.status, QuarantineStatus::Quarantined);
        assert_eq!(record.size_bytes, content.len());

        // Retrieve and verify roundtrip
        let retrieved = store.retrieve_content(&record.id).unwrap();
        assert_eq!(retrieved, content);
    }

    #[test]
    fn release_removes_content() {
        let mut store = QuarantineStore::new();
        let record = store.quarantine("/tmp/fp.bin", b"safe", "suspicious", None, vec![], None, None);
        assert!(store.release(&record.id, "analyst1"));
        assert!(store.retrieve_content(&record.id).is_none());
        assert_eq!(
            store.get(&record.id).unwrap().status,
            QuarantineStatus::Released
        );
    }

    #[test]
    fn search_by_hash_and_name() {
        let mut store = QuarantineStore::new();
        let record = store.quarantine("/var/tmp/test.dll", b"test", "suspicious", None, vec![], None, None);
        assert_eq!(store.search("test.dll").len(), 1);
        assert_eq!(store.search(&record.sha256[..8]).len(), 1);
    }

    #[test]
    fn stats_report() {
        let mut store = QuarantineStore::new();
        store.quarantine("/a", b"a", "malicious", Some("FamilyA".into()), vec![], None, None);
        store.quarantine("/b", b"b", "suspicious", None, vec![], None, None);
        let stats = store.stats();
        assert_eq!(stats.total_files, 2);
        assert_eq!(stats.quarantined, 2);
    }
}
