use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::audit::sha256_hex;

// ── Data Structures ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactEntry {
    pub path: String,
    pub hash: String,
    #[serde(default)]
    pub min_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildManifest {
    pub version: String,
    pub commit: String,
    pub build_time: String,
    pub target: String,
    pub binary_hash: String,
    #[serde(default)]
    pub source_merkle_root: String,
    #[serde(default)]
    pub artifact_hashes: Vec<ArtifactEntry>,
    #[serde(default)]
    pub signature: String,
    #[serde(default)]
    pub signer_pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedKey {
    pub pubkey: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub valid_from: u64,
    #[serde(default)]
    pub valid_until: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustStore {
    pub trusted_keys: Vec<TrustedKey>,
    #[serde(default)]
    pub min_binary_version: u32,
    #[serde(default)]
    pub require_attestation_at_boot: bool,
}

// ── Verification Results ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub passed: bool,
    pub checks: Vec<CheckResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

// ── Build Manifest Generation ─────────────────────────────────────────────────

impl BuildManifest {
    pub fn generate(binary_path: &Path, artifacts: &[&Path]) -> Result<Self, String> {
        let binary_bytes = fs::read(binary_path)
            .map_err(|e| format!("failed to read binary {}: {e}", binary_path.display()))?;
        let binary_hash = sha256_hex(&binary_bytes);

        let artifact_hashes: Vec<ArtifactEntry> = artifacts
            .iter()
            .map(|p| {
                let bytes = fs::read(p)
                    .map_err(|e| format!("failed to read artifact {}: {e}", p.display()))?;
                Ok(ArtifactEntry {
                    path: p.to_string_lossy().into_owned(),
                    hash: sha256_hex(&bytes),
                    min_version: 0,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;

        Ok(BuildManifest {
            version: env!("CARGO_PKG_VERSION").to_string(),
            commit: String::new(),
            build_time: chrono::Utc::now().to_rfc3339(),
            target: std::env::consts::ARCH.to_string(),
            binary_hash,
            source_merkle_root: String::new(),
            artifact_hashes,
            signature: String::new(),
            signer_pubkey: String::new(),
        })
    }

    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| format!("failed to serialize manifest: {e}"))
    }

    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| format!("failed to parse manifest: {e}"))
    }

    pub fn write_to_path(&self, path: &Path) -> Result<(), String> {
        let json = self.to_json()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("failed to create directory: {e}"))?;
        }
        fs::write(path, json).map_err(|e| format!("failed to write manifest: {e}"))
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let data = fs::read_to_string(path).map_err(|e| format!("failed to read manifest: {e}"))?;
        Self::from_json(&data)
    }
}

// ── Trust Store ───────────────────────────────────────────────────────────────

impl TrustStore {
    pub fn load(path: &Path) -> Result<Self, String> {
        let data =
            fs::read_to_string(path).map_err(|e| format!("failed to read trust store: {e}"))?;
        serde_json::from_str(&data).map_err(|e| format!("failed to parse trust store: {e}"))
    }

    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| format!("failed to serialize trust store: {e}"))
    }

    pub fn write_to_path(&self, path: &Path) -> Result<(), String> {
        let json = self.to_json()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("failed to create directory: {e}"))?;
        }
        fs::write(path, json).map_err(|e| format!("failed to write trust store: {e}"))
    }

    pub fn has_key(&self, pubkey: &str) -> bool {
        self.trusted_keys.iter().any(|k| k.pubkey == pubkey)
    }
}

// ── Verification Hooks ────────────────────────────────────────────────────────

pub fn verify_manifest(manifest: &BuildManifest, trust_store: &TrustStore) -> VerificationResult {
    let mut checks = Vec::new();

    // Check 1: signer key is in the trust store
    let signer_trusted = if manifest.signer_pubkey.is_empty() {
        checks.push(CheckResult {
            name: "signer_key".into(),
            passed: false,
            detail: "manifest has no signer public key".into(),
        });
        false
    } else if trust_store.has_key(&manifest.signer_pubkey) {
        checks.push(CheckResult {
            name: "signer_key".into(),
            passed: true,
            detail: format!(
                "signer key {} is trusted",
                &manifest.signer_pubkey[..8.min(manifest.signer_pubkey.len())]
            ),
        });
        true
    } else {
        checks.push(CheckResult {
            name: "signer_key".into(),
            passed: false,
            detail: "signer key not found in trust store".into(),
        });
        false
    };
    let _ = signer_trusted; // used in future signature verification

    // Check 2: version is not empty
    let version_ok = !manifest.version.is_empty();
    checks.push(CheckResult {
        name: "version_present".into(),
        passed: version_ok,
        detail: if version_ok {
            format!("version: {}", manifest.version)
        } else {
            "manifest has no version".into()
        },
    });

    // Check 3: binary hash is not empty
    let hash_ok = !manifest.binary_hash.is_empty();
    checks.push(CheckResult {
        name: "binary_hash_present".into(),
        passed: hash_ok,
        detail: if hash_ok {
            format!(
                "binary hash: {}…",
                &manifest.binary_hash[..16.min(manifest.binary_hash.len())]
            )
        } else {
            "manifest has no binary hash".into()
        },
    });

    let passed = checks.iter().all(|c| c.passed);
    VerificationResult { passed, checks }
}

pub fn verify_artifact(artifact_path: &Path, expected_hash: &str) -> CheckResult {
    match fs::read(artifact_path) {
        Ok(bytes) => {
            let actual = sha256_hex(&bytes);
            let passed = actual == expected_hash;
            CheckResult {
                name: format!("artifact:{}", artifact_path.display()),
                passed,
                detail: if passed {
                    "hash matches".into()
                } else {
                    format!("expected {expected_hash}, got {actual}")
                },
            }
        }
        Err(e) => CheckResult {
            name: format!("artifact:{}", artifact_path.display()),
            passed: false,
            detail: format!("failed to read: {e}"),
        },
    }
}

pub fn verify_artifacts(manifest: &BuildManifest) -> VerificationResult {
    let checks: Vec<CheckResult> = manifest
        .artifact_hashes
        .iter()
        .map(|entry| verify_artifact(Path::new(&entry.path), &entry.hash))
        .collect();
    let passed = !checks.is_empty() && checks.iter().all(|c| c.passed);
    VerificationResult { passed, checks }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_file(name: &str, content: &[u8]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("wardex_attest_test");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(content).unwrap();
        path
    }

    #[test]
    fn generate_manifest_captures_binary_hash() {
        let bin = temp_file("fake_binary", b"sentinel-binary-content");
        let manifest = BuildManifest::generate(&bin, &[]).unwrap();
        assert_eq!(manifest.binary_hash, sha256_hex(b"sentinel-binary-content"));
        assert!(!manifest.version.is_empty());
    }

    #[test]
    fn manifest_roundtrip_json() {
        let bin = temp_file("rt_binary", b"roundtrip");
        let manifest = BuildManifest::generate(&bin, &[]).unwrap();
        let json = manifest.to_json().unwrap();
        let loaded = BuildManifest::from_json(&json).unwrap();
        assert_eq!(loaded.binary_hash, manifest.binary_hash);
        assert_eq!(loaded.version, manifest.version);
    }

    #[test]
    fn manifest_with_artifacts() {
        let bin = temp_file("art_binary", b"binary");
        let art = temp_file("baseline.json", b"{\"mean\":1.0}");
        let manifest = BuildManifest::generate(&bin, &[art.as_path()]).unwrap();
        assert_eq!(manifest.artifact_hashes.len(), 1);
        assert_eq!(
            manifest.artifact_hashes[0].hash,
            sha256_hex(b"{\"mean\":1.0}")
        );
    }

    #[test]
    fn trust_store_roundtrip() {
        let store = TrustStore {
            trusted_keys: vec![TrustedKey {
                pubkey: "abc123".into(),
                label: "test-key".into(),
                valid_from: 0,
                valid_until: 0,
            }],
            min_binary_version: 1,
            require_attestation_at_boot: true,
        };
        let json = store.to_json().unwrap();
        let dir = std::env::temp_dir().join("wardex_attest_test");
        let path = dir.join("trust_store.json");
        store.write_to_path(&path).unwrap();
        let loaded = TrustStore::load(&path).unwrap();
        assert_eq!(loaded.trusted_keys.len(), 1);
        assert!(loaded.has_key("abc123"));
        assert!(!loaded.has_key("xyz"));
        assert_eq!(loaded.min_binary_version, 1);

        let parsed: TrustStore = serde_json::from_str(&json).unwrap();
        assert!(parsed.require_attestation_at_boot);
    }

    #[test]
    fn verify_manifest_all_pass() {
        let store = TrustStore {
            trusted_keys: vec![TrustedKey {
                pubkey: "signer-key-001".into(),
                label: "release".into(),
                valid_from: 0,
                valid_until: 0,
            }],
            min_binary_version: 0,
            require_attestation_at_boot: false,
        };
        let manifest = BuildManifest {
            version: "0.2.0".into(),
            commit: "abc123".into(),
            build_time: "T0".into(),
            target: "x86_64".into(),
            binary_hash: "deadbeef".into(),
            source_merkle_root: String::new(),
            artifact_hashes: vec![],
            signature: "sig".into(),
            signer_pubkey: "signer-key-001".into(),
        };
        let result = verify_manifest(&manifest, &store);
        assert!(result.passed);
        assert_eq!(result.checks.len(), 3);
    }

    #[test]
    fn verify_manifest_fails_unknown_signer() {
        let store = TrustStore {
            trusted_keys: vec![],
            min_binary_version: 0,
            require_attestation_at_boot: false,
        };
        let manifest = BuildManifest {
            version: "0.2.0".into(),
            commit: String::new(),
            build_time: String::new(),
            target: String::new(),
            binary_hash: "hash".into(),
            source_merkle_root: String::new(),
            artifact_hashes: vec![],
            signature: String::new(),
            signer_pubkey: "unknown-key".into(),
        };
        let result = verify_manifest(&manifest, &store);
        assert!(!result.passed);
        assert!(!result.checks[0].passed);
    }

    #[test]
    fn verify_artifact_matching_hash() {
        let path = temp_file("verified_art", b"content-to-hash");
        let expected = sha256_hex(b"content-to-hash");
        let check = verify_artifact(&path, &expected);
        assert!(check.passed);
    }

    #[test]
    fn verify_artifact_mismatched_hash() {
        let path = temp_file("tampered_art", b"original");
        let check = verify_artifact(&path, "wrong-hash");
        assert!(!check.passed);
        assert!(check.detail.contains("expected wrong-hash"));
    }

    #[test]
    fn verify_artifacts_all_pass() {
        let a1 = temp_file("a1.bin", b"alpha");
        let a2 = temp_file("a2.bin", b"beta");
        let manifest = BuildManifest {
            version: "0.1.0".into(),
            commit: String::new(),
            build_time: String::new(),
            target: String::new(),
            binary_hash: String::new(),
            source_merkle_root: String::new(),
            artifact_hashes: vec![
                ArtifactEntry {
                    path: a1.to_string_lossy().into(),
                    hash: sha256_hex(b"alpha"),
                    min_version: 0,
                },
                ArtifactEntry {
                    path: a2.to_string_lossy().into(),
                    hash: sha256_hex(b"beta"),
                    min_version: 0,
                },
            ],
            signature: String::new(),
            signer_pubkey: String::new(),
        };
        let result = verify_artifacts(&manifest);
        assert!(result.passed);
        assert_eq!(result.checks.len(), 2);
    }

    #[test]
    fn verify_artifacts_detects_tamper() {
        let a1 = temp_file("tamper1.bin", b"original-content");
        let manifest = BuildManifest {
            version: "0.1.0".into(),
            commit: String::new(),
            build_time: String::new(),
            target: String::new(),
            binary_hash: String::new(),
            source_merkle_root: String::new(),
            artifact_hashes: vec![ArtifactEntry {
                path: a1.to_string_lossy().into(),
                hash: sha256_hex(b"different-content"),
                min_version: 0,
            }],
            signature: String::new(),
            signer_pubkey: String::new(),
        };
        let result = verify_artifacts(&manifest);
        assert!(!result.passed);
    }
}
