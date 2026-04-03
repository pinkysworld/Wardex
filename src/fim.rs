//! File Integrity Monitoring (FIM).
//!
//! Tracks checksums of critical system files and detects drift,
//! unauthorized modifications, and new/deleted files.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::audit::sha256_hex;

/// A tracked file with its baseline checksum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedFile {
    pub path: String,
    pub baseline_hash: String,
    pub last_hash: Option<String>,
    pub last_checked: String,
    pub size_bytes: u64,
    pub modified: bool,
}

/// Result of a FIM scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FimScanResult {
    pub timestamp: String,
    pub files_checked: usize,
    pub modified: Vec<FimChange>,
    pub new_files: Vec<String>,
    pub deleted_files: Vec<String>,
    pub errors: Vec<String>,
}

/// A detected file change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FimChange {
    pub path: String,
    pub old_hash: String,
    pub new_hash: String,
    pub change_type: ChangeType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChangeType {
    Modified,
    Created,
    Deleted,
    PermissionChanged,
}

/// FIM policy: which paths to monitor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FimPolicy {
    pub id: String,
    pub name: String,
    pub paths: Vec<String>,
    pub recursive: bool,
    pub exclude_patterns: Vec<String>,
    pub interval_secs: u64,
    pub enabled: bool,
}

/// File Integrity Monitor engine.
pub struct FimEngine {
    policies: Vec<FimPolicy>,
    baselines: HashMap<String, TrackedFile>,
    scan_history: Vec<FimScanResult>,
}

impl Default for FimEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl FimEngine {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
            baselines: HashMap::new(),
            scan_history: Vec::new(),
        }
    }

    /// Add a FIM policy.
    pub fn add_policy(&mut self, policy: FimPolicy) {
        self.policies.retain(|p| p.id != policy.id);
        self.policies.push(policy);
    }

    /// Remove a FIM policy.
    pub fn remove_policy(&mut self, id: &str) -> bool {
        let before = self.policies.len();
        self.policies.retain(|p| p.id != id);
        self.policies.len() < before
    }

    /// List policies.
    pub fn policies(&self) -> &[FimPolicy] {
        &self.policies
    }

    /// Set baseline for a file.
    pub fn set_baseline(&mut self, path: &str, content: &[u8], size: u64) {
        let hash = sha256_hex(content);
        let now = chrono::Utc::now().to_rfc3339();
        self.baselines.insert(
            path.to_string(),
            TrackedFile {
                path: path.to_string(),
                baseline_hash: hash.clone(),
                last_hash: Some(hash),
                last_checked: now,
                size_bytes: size,
                modified: false,
            },
        );
    }

    /// Check a file against its baseline. Returns change if detected.
    pub fn check_file(&mut self, path: &str, content: &[u8]) -> Option<FimChange> {
        let new_hash = sha256_hex(content);
        let now = chrono::Utc::now().to_rfc3339();

        if let Some(tracked) = self.baselines.get_mut(path) {
            tracked.last_checked = now;
            tracked.last_hash = Some(new_hash.clone());
            if new_hash != tracked.baseline_hash {
                tracked.modified = true;
                Some(FimChange {
                    path: path.to_string(),
                    old_hash: tracked.baseline_hash.clone(),
                    new_hash,
                    change_type: ChangeType::Modified,
                })
            } else {
                tracked.modified = false;
                None
            }
        } else {
            // New file not in baseline
            self.set_baseline(path, content, content.len() as u64);
            Some(FimChange {
                path: path.to_string(),
                old_hash: String::new(),
                new_hash,
                change_type: ChangeType::Created,
            })
        }
    }

    /// Run a scan, comparing provided file states against baselines.
    pub fn scan(&mut self, files: &[(&str, &[u8])]) -> FimScanResult {
        let now = chrono::Utc::now().to_rfc3339();
        let mut modified = Vec::new();
        let mut new_files = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for (path, content) in files {
            seen.insert(path.to_string());
            if let Some(change) = self.check_file(path, content) {
                match change.change_type {
                    ChangeType::Created => new_files.push(path.to_string()),
                    _ => modified.push(change),
                }
            }
        }

        // Detect deleted files
        let deleted: Vec<String> = self
            .baselines
            .keys()
            .filter(|p| !seen.contains(p.as_str()))
            .cloned()
            .collect();

        let result = FimScanResult {
            timestamp: now,
            files_checked: files.len(),
            modified,
            new_files,
            deleted_files: deleted,
            errors: Vec::new(),
        };
        self.scan_history.push(result.clone());
        result
    }

    /// Get baseline info.
    pub fn baselines(&self) -> Vec<&TrackedFile> {
        self.baselines.values().collect()
    }

    /// Recent scan history.
    pub fn scan_history(&self, limit: usize) -> &[FimScanResult] {
        let start = self.scan_history.len().saturating_sub(limit);
        &self.scan_history[start..]
    }

    /// Count tracked files.
    pub fn tracked_count(&self) -> usize {
        self.baselines.len()
    }

    /// Count modified files.
    pub fn modified_count(&self) -> usize {
        self.baselines.values().filter(|f| f.modified).count()
    }

    /// Default critical paths per platform.
    pub fn default_critical_paths(platform: &str) -> Vec<String> {
        match platform {
            "linux" => vec![
                "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/ssh/sshd_config",
                "/etc/pam.d/", "/etc/crontab", "/etc/hosts", "/etc/resolv.conf",
                "/usr/bin/sudo", "/usr/bin/ssh",
            ],
            "macos" => vec![
                "/etc/hosts", "/etc/sudoers", "/etc/ssh/sshd_config",
                "/Library/LaunchDaemons/", "/Library/LaunchAgents/",
                "/System/Library/LaunchDaemons/",
            ],
            "windows" => vec![
                "C:\\Windows\\System32\\drivers\\etc\\hosts",
                "C:\\Windows\\System32\\config\\SAM",
                "C:\\Windows\\System32\\config\\SYSTEM",
            ],
            _ => vec![],
        }
        .into_iter()
        .map(String::from)
        .collect()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_and_unchanged() {
        let mut fim = FimEngine::new();
        fim.set_baseline("/etc/passwd", b"root:x:0:0", 10);
        assert!(fim.check_file("/etc/passwd", b"root:x:0:0").is_none());
    }

    #[test]
    fn detects_modification() {
        let mut fim = FimEngine::new();
        fim.set_baseline("/etc/passwd", b"root:x:0:0", 10);
        let change = fim.check_file("/etc/passwd", b"root:x:0:0\nhacker:x:1000:1000");
        assert!(change.is_some());
        assert_eq!(change.unwrap().change_type, ChangeType::Modified);
    }

    #[test]
    fn detects_new_file() {
        let mut fim = FimEngine::new();
        let change = fim.check_file("/tmp/new_file", b"malware");
        assert!(change.is_some());
        assert_eq!(change.unwrap().change_type, ChangeType::Created);
    }

    #[test]
    fn scan_detects_deleted() {
        let mut fim = FimEngine::new();
        fim.set_baseline("/etc/passwd", b"data", 4);
        fim.set_baseline("/etc/shadow", b"data", 4);
        let result = fim.scan(&[("/etc/passwd", b"data")]);
        assert_eq!(result.deleted_files.len(), 1);
        assert_eq!(result.deleted_files[0], "/etc/shadow");
    }

    #[test]
    fn default_paths_linux() {
        let paths = FimEngine::default_critical_paths("linux");
        assert!(paths.iter().any(|p| p.contains("passwd")));
    }

    #[test]
    fn policy_management() {
        let mut fim = FimEngine::new();
        fim.add_policy(FimPolicy {
            id: "p1".into(),
            name: "System files".into(),
            paths: vec!["/etc/".into()],
            recursive: true,
            exclude_patterns: vec![],
            interval_secs: 300,
            enabled: true,
        });
        assert_eq!(fim.policies().len(), 1);
        assert!(fim.remove_policy("p1"));
        assert_eq!(fim.policies().len(), 0);
    }
}
