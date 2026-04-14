use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Server-side update manager for distributing agent updates.
pub struct UpdateManager {
    releases: Vec<Release>,
    store_dir: String,
}

/// A release available for distribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Release {
    pub version: String,
    pub platform: String,
    pub sha256: String,
    pub file_name: String,
    pub file_size: u64,
    pub release_notes: String,
    pub mandatory: bool,
    pub published_at: String,
}

/// Update check request from an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCheckRequest {
    pub current_version: String,
    pub platform: String,
    pub agent_id: String,
}

/// Update check response to an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCheckResponse {
    pub update_available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release_notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mandatory: Option<bool>,
}

impl UpdateManager {
    pub fn new(store_dir: &str) -> Self {
        let mut mgr = Self {
            releases: Vec::new(),
            store_dir: store_dir.to_string(),
        };
        mgr.load();
        mgr
    }

    /// Publish a new release binary.
    pub fn publish_release(
        &mut self,
        version: &str,
        platform: &str,
        binary: &[u8],
        release_notes: &str,
        mandatory: bool,
    ) -> Result<Release, String> {
        use sha2::{Digest, Sha256};
        // Prevent path traversal via version/platform
        if version.contains("..") || version.contains('/') || version.contains('\\')
            || platform.contains("..") || platform.contains('/') || platform.contains('\\')
        {
            return Err("invalid version or platform name".into());
        }
        let sha256 = hex::encode(Sha256::digest(binary));
        let file_name = format!("wardex-{}-{}", version, platform);

        let releases_dir = format!("{}/releases", self.store_dir);
        let _ = fs::create_dir_all(&releases_dir);
        let file_path = format!("{}/{}", releases_dir, file_name);

        fs::write(&file_path, binary)
            .map_err(|e| format!("failed to write release binary: {e}"))?;

        let release = Release {
            version: version.to_string(),
            platform: platform.to_string(),
            sha256,
            file_name,
            file_size: binary.len() as u64,
            release_notes: release_notes.to_string(),
            mandatory,
            published_at: chrono::Utc::now().to_rfc3339(),
        };

        self.releases.push(release.clone());
        self.save();

        Ok(release)
    }

    /// Check if an update is available for the given version and platform.
    pub fn check_update(&self, current_version: &str, platform: &str) -> UpdateCheckResponse {
        let latest = self
            .releases
            .iter()
            .filter(|r| r.platform == platform || r.platform == "universal")
            .max_by(|a, b| version_cmp(&a.version, &b.version));

        match latest {
            Some(release)
                if version_cmp(&release.version, current_version)
                    == std::cmp::Ordering::Greater =>
            {
                UpdateCheckResponse {
                    update_available: true,
                    version: Some(release.version.clone()),
                    download_url: Some(format!("/api/updates/download/{}", release.file_name)),
                    sha256: Some(release.sha256.clone()),
                    release_notes: Some(release.release_notes.clone()),
                    mandatory: Some(release.mandatory),
                }
            }
            _ => UpdateCheckResponse {
                update_available: false,
                version: None,
                download_url: None,
                sha256: None,
                release_notes: None,
                mandatory: None,
            },
        }
    }

    /// Get the binary content for a release download.
    pub fn get_release_binary(&self, file_name: &str) -> Result<Vec<u8>, String> {
        // Validate file_name to prevent path traversal
        if file_name.contains("..") || file_name.contains('/') || file_name.contains('\\') {
            return Err("invalid file name".into());
        }

        let base = std::path::Path::new(&self.store_dir).join("releases");
        let requested = base.join(file_name);

        // Defence-in-depth: verify resolved path is still within releases/
        let canonical_base = base.canonicalize().unwrap_or_else(|_| base.clone());
        let canonical_req = requested.canonicalize().map_err(|_| "release not found".to_string())?;
        if !canonical_req.starts_with(&canonical_base) {
            return Err("invalid file name".into());
        }

        fs::read(&canonical_req).map_err(|e| format!("release not found: {e}"))
    }

    /// List all published releases.
    pub fn list_releases(&self) -> &[Release] {
        &self.releases
    }

    pub fn get_release(&self, version: &str, platform: &str) -> Option<&Release> {
        self.releases.iter().find(|release| {
            release.version == version
                && (release.platform == platform || release.platform == "universal")
        })
    }

    fn save(&self) {
        let index_path = format!("{}/releases.json", self.store_dir);
        if let Ok(json) = serde_json::to_string_pretty(&self.releases) {
            let _ = fs::create_dir_all(&self.store_dir);
            let tmp = format!("{}/releases.json.tmp", self.store_dir);
            if fs::write(&tmp, &json).is_ok() {
                let _ = fs::rename(&tmp, &index_path);
            }
        }
    }

    fn load(&mut self) {
        let index_path = format!("{}/releases.json", self.store_dir);
        if let Ok(raw) = fs::read_to_string(Path::new(&index_path))
            && let Ok(releases) = serde_json::from_str(&raw)
        {
            self.releases = releases;
        }
    }
}

/// Simple semver comparison (major.minor.patch).
fn version_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let parse = |v: &str| -> Vec<u32> { v.split('.').map(|s| s.parse().unwrap_or(0)).collect() };
    let va = parse(a);
    let vb = parse(b);
    va.cmp(&vb)
}

// ── Atomic update with rollback ──────────────────────────────────────

/// State of an atomic update operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum UpdateState {
    Idle,
    Downloading,
    Verifying,
    BackingUp,
    Swapping,
    Validating,
    Complete,
    RolledBack,
    Failed { reason: String },
}

/// Record of a completed update attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateRecord {
    pub from_version: String,
    pub to_version: String,
    pub state: UpdateState,
    pub started_at: String,
    pub completed_at: String,
    pub rollback: bool,
}

/// Atomic updater that backs up the current binary, swaps in the new
/// one, validates it, and rolls back on failure.
#[derive(Debug)]
pub struct AtomicUpdater {
    /// Directory for storing backups and staging files.
    staging_dir: String,
    /// Current running version.
    current_version: String,
    /// Current state machine position.
    state: UpdateState,
    /// History of all update attempts.
    history: Vec<UpdateRecord>,
}

impl AtomicUpdater {
    pub fn new(staging_dir: &str, current_version: &str) -> Self {
        let _ = fs::create_dir_all(staging_dir);
        Self {
            staging_dir: staging_dir.to_string(),
            current_version: current_version.to_string(),
            state: UpdateState::Idle,
            history: Vec::new(),
        }
    }

    pub fn state(&self) -> &UpdateState {
        &self.state
    }

    pub fn history(&self) -> &[UpdateRecord] {
        &self.history
    }

    /// Execute a full atomic update cycle.
    ///
    /// Steps:
    /// 1. Download — write `binary` to staging.
    /// 2. Verify — check SHA-256 matches `expected_sha`.
    /// 3. Back up — copy current binary to backup location.
    /// 4. Swap — rename staged binary into place.
    /// 5. Validate — run basic health check.
    /// 6. Rollback if validation fails.
    pub fn apply_update(
        &mut self,
        new_version: &str,
        binary: &[u8],
        expected_sha: &str,
        current_binary_path: &str,
    ) -> Result<(), String> {
        use sha2::{Digest, Sha256};

        let started = chrono::Utc::now().to_rfc3339();
        // Prevent path traversal via new_version
        if new_version.contains("..") || new_version.contains('/') || new_version.contains('\\') {
            return Err("invalid version name".into());
        }
        let staged_path = format!("{}/staged-{}", self.staging_dir, new_version);
        let backup_path = format!("{}/backup-{}", self.staging_dir, self.current_version);

        // 1. Download / write staged.
        self.state = UpdateState::Downloading;
        fs::write(&staged_path, binary)
            .map_err(|e| self.fail(&started, new_version, format!("staging write: {e}"), false))?;

        // 2. Verify SHA-256.
        self.state = UpdateState::Verifying;
        let actual_sha = hex::encode(Sha256::digest(binary));
        if actual_sha != expected_sha {
            let _ = fs::remove_file(&staged_path);
            return Err(self.fail(
                &started,
                new_version,
                format!("SHA mismatch: expected {expected_sha}, got {actual_sha}"),
                false,
            ));
        }

        // 3. Back up current binary.
        self.state = UpdateState::BackingUp;
        if Path::new(current_binary_path).exists() {
            fs::copy(current_binary_path, &backup_path)
                .map_err(|e| self.fail(&started, new_version, format!("backup: {e}"), false))?;
        }

        // 4. Swap staged → current.
        self.state = UpdateState::Swapping;
        if let Err(e) = fs::rename(&staged_path, current_binary_path) {
            // Rollback: restore backup.
            if Path::new(&backup_path).exists() {
                let _ = fs::rename(&backup_path, current_binary_path);
            }
            return Err(self.fail(&started, new_version, format!("swap: {e}"), true));
        }

        // 5. Validate (simple: check file size and readability).
        self.state = UpdateState::Validating;
        match fs::metadata(current_binary_path) {
            Ok(m) if m.len() == binary.len() as u64 => {
                // Validation passed.
            }
            Ok(m) => {
                self.rollback(current_binary_path, &backup_path);
                return Err(self.fail(
                    &started,
                    new_version,
                    format!(
                        "validation: size mismatch ({} vs {})",
                        m.len(),
                        binary.len()
                    ),
                    true,
                ));
            }
            Err(e) => {
                self.rollback(current_binary_path, &backup_path);
                return Err(self.fail(&started, new_version, format!("validation: {e}"), true));
            }
        }

        // Success.
        self.state = UpdateState::Complete;
        self.history.push(UpdateRecord {
            from_version: self.current_version.clone(),
            to_version: new_version.to_string(),
            state: UpdateState::Complete,
            started_at: started,
            completed_at: chrono::Utc::now().to_rfc3339(),
            rollback: false,
        });
        self.current_version = new_version.to_string();
        Ok(())
    }

    /// Explicitly rollback to the previous version.
    pub fn rollback_to_previous(&mut self, current_binary_path: &str) -> Result<(), String> {
        // Look for any backup file.
        let entries = fs::read_dir(&self.staging_dir).map_err(|e| e.to_string())?;
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("backup-") {
                fs::rename(entry.path(), current_binary_path)
                    .map_err(|e| format!("rollback: {e}"))?;
                self.state = UpdateState::RolledBack;
                return Ok(());
            }
        }
        Err(format!("no backup found in {}", self.staging_dir))
    }

    fn rollback(&self, current_path: &str, backup_path: &str) {
        if Path::new(backup_path).exists() {
            let _ = fs::rename(backup_path, current_path);
        }
    }

    fn fail(
        &mut self,
        started_at: &str,
        to_version: &str,
        reason: String,
        rolled_back: bool,
    ) -> String {
        self.state = UpdateState::Failed {
            reason: reason.clone(),
        };
        self.history.push(UpdateRecord {
            from_version: self.current_version.clone(),
            to_version: to_version.to_string(),
            state: UpdateState::Failed {
                reason: reason.clone(),
            },
            started_at: started_at.to_string(),
            completed_at: chrono::Utc::now().to_rfc3339(),
            rollback: rolled_back,
        });
        reason
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_comparison() {
        assert_eq!(version_cmp("0.15.0", "0.14.0"), std::cmp::Ordering::Greater);
        assert_eq!(version_cmp("0.15.0", "0.15.0"), std::cmp::Ordering::Equal);
        assert_eq!(version_cmp("0.15.0", "0.16.0"), std::cmp::Ordering::Less);
        assert_eq!(version_cmp("1.0.0", "0.99.99"), std::cmp::Ordering::Greater);
    }

    #[test]
    fn check_update_no_releases() {
        let mgr = UpdateManager {
            releases: Vec::new(),
            store_dir: "/tmp/wardex_test_updates".into(),
        };
        let resp = mgr.check_update("0.15.0", "linux");
        assert!(!resp.update_available);
    }

    #[test]
    fn check_update_newer_available() {
        let mgr = UpdateManager {
            releases: vec![Release {
                version: "0.16.0".into(),
                platform: "linux".into(),
                sha256: "abc123".into(),
                file_name: "wardex-0.16.0-linux".into(),
                file_size: 1024,
                release_notes: "bug fixes".into(),
                mandatory: false,
                published_at: "2026-03-01T00:00:00Z".into(),
            }],
            store_dir: "/tmp/wardex_test_updates".into(),
        };
        let resp = mgr.check_update("0.15.0", "linux");
        assert!(resp.update_available);
        assert_eq!(resp.version.unwrap(), "0.16.0");
    }

    #[test]
    fn check_update_already_current() {
        let mgr = UpdateManager {
            releases: vec![Release {
                version: "0.15.0".into(),
                platform: "linux".into(),
                sha256: "abc123".into(),
                file_name: "wardex-0.15.0-linux".into(),
                file_size: 1024,
                release_notes: "current".into(),
                mandatory: false,
                published_at: "2026-03-01T00:00:00Z".into(),
            }],
            store_dir: "/tmp/wardex_test_updates".into(),
        };
        let resp = mgr.check_update("0.15.0", "linux");
        assert!(!resp.update_available);
    }

    #[test]
    fn publish_and_retrieve() {
        let dir = std::env::temp_dir().join("wardex_test_publish");
        let _ = fs::create_dir_all(&dir);

        let mut mgr = UpdateManager::new(dir.to_str().unwrap());
        let binary = b"fake binary content";
        let release = mgr
            .publish_release("0.16.0", "linux", binary, "test notes", false)
            .unwrap();

        assert_eq!(release.version, "0.16.0");
        assert_eq!(release.file_size, binary.len() as u64);
        assert!(!release.sha256.is_empty());

        // Can retrieve the binary
        let data = mgr.get_release_binary(&release.file_name).unwrap();
        assert_eq!(data, binary);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn path_traversal_rejected() {
        let mgr = UpdateManager {
            releases: Vec::new(),
            store_dir: "/tmp/wardex_test_traversal".into(),
        };
        assert!(mgr.get_release_binary("../etc/passwd").is_err());
        assert!(mgr.get_release_binary("foo/../../bar").is_err());
    }

    #[test]
    fn atomic_update_success() {
        use sha2::{Digest, Sha256};

        let dir = std::env::temp_dir().join("wardex_test_atomic");
        let _ = fs::create_dir_all(&dir);
        let bin_path = dir.join("wardex");
        fs::write(&bin_path, b"old binary v1").unwrap();

        let new_binary = b"new binary v2";
        let expected_sha = hex::encode(Sha256::digest(new_binary));

        let mut updater = AtomicUpdater::new(dir.join("staging").to_str().unwrap(), "1.0.0");

        let result = updater.apply_update(
            "2.0.0",
            new_binary,
            &expected_sha,
            bin_path.to_str().unwrap(),
        );
        assert!(result.is_ok());
        assert_eq!(*updater.state(), UpdateState::Complete);
        assert_eq!(updater.history().len(), 1);

        let content = fs::read(&bin_path).unwrap();
        assert_eq!(content, new_binary);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_update_sha_mismatch_fails() {
        let dir = std::env::temp_dir().join("wardex_test_sha_fail");
        let _ = fs::create_dir_all(&dir);

        let mut updater = AtomicUpdater::new(dir.join("staging").to_str().unwrap(), "1.0.0");

        let result = updater.apply_update("2.0.0", b"data", "wrong-sha", "/tmp/nonexistent");
        assert!(result.is_err());
        assert!(matches!(updater.state(), UpdateState::Failed { .. }));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_update_rollback() {
        use sha2::{Digest, Sha256};

        let dir = std::env::temp_dir().join("wardex_test_rollback");
        let _ = fs::create_dir_all(&dir);
        let bin_path = dir.join("wardex-rb");
        let old = b"version-1-content";
        fs::write(&bin_path, old).unwrap();

        let new_binary = b"version-2-content";
        let sha = hex::encode(Sha256::digest(new_binary));

        let mut updater = AtomicUpdater::new(dir.join("staging").to_str().unwrap(), "1.0.0");

        // First, apply successfully.
        updater
            .apply_update("2.0.0", new_binary, &sha, bin_path.to_str().unwrap())
            .unwrap();

        // Then rollback.
        let rb = updater.rollback_to_previous(bin_path.to_str().unwrap());
        assert!(rb.is_ok());
        assert_eq!(*updater.state(), UpdateState::RolledBack);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_update_history_tracked() {
        let dir = std::env::temp_dir().join("wardex_test_history");
        let _ = fs::create_dir_all(&dir);

        let mut updater = AtomicUpdater::new(dir.join("staging").to_str().unwrap(), "1.0.0");

        // A failed attempt.
        let _ = updater.apply_update("2.0.0", b"x", "bad-sha", "/tmp/nope");
        assert_eq!(updater.history().len(), 1);
        assert!(matches!(
            updater.history()[0].state,
            UpdateState::Failed { .. }
        ));

        let _ = fs::remove_dir_all(&dir);
    }
}
