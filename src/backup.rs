use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct BackupConfig {
    pub enabled: bool,
    pub retention_count: u32,
    pub path: String,
    pub schedule_cron: String,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            retention_count: 7,
            path: "var/backups/".to_string(),
            schedule_cron: "0 2 * * *".to_string(),
        }
    }
}

#[derive(Debug, Serialize, Clone)]
pub struct BackupRecord {
    pub name: String,
    pub timestamp: String,
    pub size_bytes: u64,
    pub checksum: String,
    pub verified: bool,
}

pub struct BackupManager {
    config: BackupConfig,
    records: Vec<BackupRecord>,
}

impl BackupManager {
    pub fn new(config: BackupConfig) -> Self {
        Self {
            config,
            records: Vec::new(),
        }
    }

    pub fn create_backup(&mut self, source_dir: &Path) -> Result<BackupRecord, String> {
        let now = Utc::now();
        let name = format!("wardex-backup-{}", now.format("%Y%m%d-%H%M%S"));
        let backup_dir = Path::new(&self.config.path).join(&name);

        fs::create_dir_all(&backup_dir).map_err(|e| format!("failed to create backup dir: {e}"))?;

        // Collect file list from source
        let mut files: Vec<String> = Vec::new();
        collect_files(source_dir, source_dir, &mut files)
            .map_err(|e| format!("failed to read source dir: {e}"))?;

        // Write manifest.json
        let manifest = serde_json::json!({
            "timestamp": now.to_rfc3339(),
            "source": source_dir.to_string_lossy(),
            "files": files,
        });
        let manifest_path = backup_dir.join("manifest.json");
        let manifest_bytes = serde_json::to_string_pretty(&manifest)
            .map_err(|e| format!("failed to serialize manifest: {e}"))?;
        fs::write(&manifest_path, &manifest_bytes)
            .map_err(|e| format!("failed to write manifest: {e}"))?;

        // Copy files into backup data directory
        let data_dir = backup_dir.join("data");
        for rel in &files {
            let src = source_dir.join(rel);
            let dst = data_dir.join(rel);
            if let Some(parent) = dst.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("failed to create dir {}: {e}", parent.display()))?;
            }
            fs::copy(&src, &dst)
                .map_err(|e| format!("failed to copy {}: {e}", rel))?;
        }

        // Write data.json with serialized state
        let state = serde_json::json!({
            "backup_name": name,
            "timestamp": now.to_rfc3339(),
            "file_count": files.len(),
            "files": files,
        });
        let data_json_path = backup_dir.join("data.json");
        let data_bytes = serde_json::to_string_pretty(&state)
            .map_err(|e| format!("failed to serialize state: {e}"))?;
        fs::write(&data_json_path, &data_bytes)
            .map_err(|e| format!("failed to write data.json: {e}"))?;

        // Compute SHA-256 of data.json
        let checksum = sha256_file(&data_json_path)
            .map_err(|e| format!("failed to compute checksum: {e}"))?;

        let size_bytes = dir_size(&backup_dir).unwrap_or(0);

        let record = BackupRecord {
            name: name.clone(),
            timestamp: now.to_rfc3339(),
            size_bytes,
            checksum,
            verified: true,
        };

        self.records.push(record.clone());
        Ok(record)
    }

    pub fn list_backups(&self) -> Vec<BackupRecord> {
        let mut sorted = self.records.clone();
        sorted.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        sorted
    }

    pub fn prune_old_backups(&mut self) -> Vec<String> {
        let mut removed = Vec::new();
        let retention = self.config.retention_count as usize;

        if self.records.len() <= retention {
            return removed;
        }

        // Sort by timestamp ascending so oldest come first
        self.records.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        let to_remove = self.records.len() - retention;
        let pruned: Vec<BackupRecord> = self.records.drain(..to_remove).collect();

        for rec in &pruned {
            let backup_path = Path::new(&self.config.path).join(&rec.name);
            if backup_path.exists() {
                let _ = fs::remove_dir_all(&backup_path);
            }
            removed.push(rec.name.clone());
        }

        removed
    }

    pub fn verify_backup(&self, name: &str) -> Result<bool, String> {
        let record = self
            .records
            .iter()
            .find(|r| r.name == name)
            .ok_or_else(|| format!("backup not found: {name}"))?;

        let data_json_path = Path::new(&self.config.path).join(name).join("data.json");
        if !data_json_path.exists() {
            return Err(format!("data.json missing for backup: {name}"));
        }

        let current_checksum = sha256_file(&data_json_path)
            .map_err(|e| format!("failed to compute checksum: {e}"))?;

        Ok(current_checksum == record.checksum)
    }

    pub fn delete_backup(&mut self, name: &str) -> Result<(), String> {
        let idx = self
            .records
            .iter()
            .position(|r| r.name == name)
            .ok_or_else(|| format!("backup not found: {name}"))?;

        let backup_path = Path::new(&self.config.path).join(name);
        if backup_path.exists() {
            fs::remove_dir_all(&backup_path)
                .map_err(|e| format!("failed to remove backup dir: {e}"))?;
        }

        self.records.remove(idx);
        Ok(())
    }
}

fn collect_files(
    base: &Path,
    dir: &Path,
    out: &mut Vec<String>,
) -> Result<(), std::io::Error> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        // Skip symlinks to prevent infinite recursion on cycles
        if path.is_symlink() {
            continue;
        }
        if path.is_dir() {
            collect_files(base, &path, out)?;
        } else {
            let rel = path
                .strip_prefix(base)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();
            out.push(rel);
        }
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, std::io::Error> {
    let data = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Ok(hex::encode(hasher.finalize()))
}

fn dir_size(path: &Path) -> Result<u64, std::io::Error> {
    let mut total: u64 = 0;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let meta = entry.metadata()?;
        if meta.is_dir() {
            total += dir_size(&entry.path())?;
        } else {
            total += meta.len();
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_backup_env() -> (tempfile::TempDir, tempfile::TempDir, BackupConfig) {
        let source = tempfile::tempdir().unwrap();
        let backup_root = tempfile::tempdir().unwrap();

        // Create some source files
        fs::write(source.path().join("config.toml"), b"[server]\nport = 8080").unwrap();
        fs::create_dir_all(source.path().join("rules")).unwrap();
        fs::write(source.path().join("rules/sigma.yml"), b"id: test-rule").unwrap();

        let config = BackupConfig {
            enabled: true,
            retention_count: 2,
            path: backup_root.path().to_string_lossy().to_string(),
            schedule_cron: "0 2 * * *".to_string(),
        };

        (source, backup_root, config)
    }

    #[test]
    fn test_default_config() {
        let cfg = BackupConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.retention_count, 7);
        assert_eq!(cfg.path, "var/backups/");
        assert_eq!(cfg.schedule_cron, "0 2 * * *");
    }

    #[test]
    fn test_create_backup() {
        let (source, _backup_root, config) = temp_backup_env();
        let mut mgr = BackupManager::new(config);

        let record = mgr.create_backup(source.path()).unwrap();
        assert!(record.name.starts_with("wardex-backup-"));
        assert!(record.size_bytes > 0);
        assert!(!record.checksum.is_empty());
        assert!(record.verified);
        assert!(!record.timestamp.is_empty());
    }

    #[test]
    fn test_list_shows_created_backup() {
        let (source, _backup_root, config) = temp_backup_env();
        let mut mgr = BackupManager::new(config);

        mgr.create_backup(source.path()).unwrap();
        let list = mgr.list_backups();
        assert_eq!(list.len(), 1);
        assert!(list[0].name.starts_with("wardex-backup-"));
    }

    #[test]
    fn test_prune_removes_old_backups() {
        let (source, _backup_root, config) = temp_backup_env();
        let mut mgr = BackupManager::new(config); // retention_count = 2

        // Create 4 backups, manually adjusting timestamps to ensure ordering
        for i in 0..4 {
            let _rec = mgr.create_backup(source.path()).unwrap();
            // Mutate the last record's timestamp to force ordering
            let idx = mgr.records.len() - 1;
            mgr.records[idx].timestamp =
                format!("2025-01-0{}T02:00:00+00:00", i + 1);
            mgr.records[idx].name = format!("wardex-backup-{}", i);
        }

        assert_eq!(mgr.records.len(), 4);
        let removed = mgr.prune_old_backups();
        assert_eq!(removed.len(), 2);
        assert_eq!(mgr.records.len(), 2);
    }

    #[test]
    fn test_delete_specific_backup() {
        let (source, _backup_root, config) = temp_backup_env();
        let mut mgr = BackupManager::new(config);

        let rec = mgr.create_backup(source.path()).unwrap();
        let name = rec.name.clone();

        assert_eq!(mgr.list_backups().len(), 1);
        mgr.delete_backup(&name).unwrap();
        assert_eq!(mgr.list_backups().len(), 0);
    }

    #[test]
    fn test_delete_nonexistent_errors() {
        let config = BackupConfig::default();
        let mut mgr = BackupManager::new(config);
        assert!(mgr.delete_backup("no-such-backup").is_err());
    }

    #[test]
    fn test_verify_checksum_matches() {
        let (source, _backup_root, config) = temp_backup_env();
        let mut mgr = BackupManager::new(config);

        let rec = mgr.create_backup(source.path()).unwrap();
        let valid = mgr.verify_backup(&rec.name).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_verify_detects_tampering() {
        let (source, _backup_root, config) = temp_backup_env();
        let mut mgr = BackupManager::new(config.clone());

        let rec = mgr.create_backup(source.path()).unwrap();

        // Tamper with data.json
        let data_path = Path::new(&config.path)
            .join(&rec.name)
            .join("data.json");
        fs::write(&data_path, b"tampered content").unwrap();

        let valid = mgr.verify_backup(&rec.name).unwrap();
        assert!(!valid);
    }
}
