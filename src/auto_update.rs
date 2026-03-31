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
        use sha2::{Sha256, Digest};
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
            Some(release) if version_cmp(&release.version, current_version) == std::cmp::Ordering::Greater => {
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

        let file_path = format!("{}/releases/{}", self.store_dir, file_name);
        fs::read(&file_path)
            .map_err(|e| format!("release not found: {e}"))
    }

    /// List all published releases.
    pub fn list_releases(&self) -> &[Release] {
        &self.releases
    }

    fn save(&self) {
        let index_path = format!("{}/releases.json", self.store_dir);
        if let Ok(json) = serde_json::to_string_pretty(&self.releases) {
            let _ = fs::create_dir_all(&self.store_dir);
            let _ = fs::write(index_path, json);
        }
    }

    fn load(&mut self) {
        let index_path = format!("{}/releases.json", self.store_dir);
        if let Ok(raw) = fs::read_to_string(Path::new(&index_path)) {
            if let Ok(releases) = serde_json::from_str(&raw) {
                self.releases = releases;
            }
        }
    }
}

/// Simple semver comparison (major.minor.patch).
fn version_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let parse = |v: &str| -> Vec<u32> {
        v.split('.')
            .map(|s| s.parse().unwrap_or(0))
            .collect()
    };
    let va = parse(a);
    let vb = parse(b);
    va.cmp(&vb)
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
}
