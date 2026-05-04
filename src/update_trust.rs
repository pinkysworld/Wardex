//! Agent update trust policy and signed-artifact verification.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as b64;
use chrono::{DateTime, Utc};

use crate::auto_update::{Release, verify_update_counter, verify_update_not_downgrade};
use crate::config::UpdateSigningSettings;

pub const BUNDLED_TRUSTED_UPDATE_SIGNERS: &[&str] =
    &["6kpsY+KcUgq+9VB7Ey7F+ZVHdq6+vnuSQh7qaRRG0iw="];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateTrustPolicy {
    pub require_signed_updates: bool,
    pub trusted_update_signers: Vec<String>,
    pub legacy_unsigned_grace_until: Option<String>,
    pub last_accepted_update_counter: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateVerification {
    pub signature_status: String,
    pub signer_pubkey: Option<String>,
    pub signature_payload_sha256: Option<String>,
    pub update_counter: Option<u64>,
}

impl UpdateTrustPolicy {
    pub fn from_settings(settings: &UpdateSigningSettings) -> Self {
        let mut trusted_update_signers = BUNDLED_TRUSTED_UPDATE_SIGNERS
            .iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>();
        for signer in &settings.trusted_update_signers {
            let trimmed = signer.trim();
            if !trimmed.is_empty() && !trusted_update_signers.iter().any(|value| value == trimmed) {
                trusted_update_signers.push(trimmed.to_string());
            }
        }
        Self {
            require_signed_updates: settings.require_signed_updates,
            trusted_update_signers,
            legacy_unsigned_grace_until: settings.legacy_unsigned_grace_until.clone(),
            last_accepted_update_counter: settings.last_accepted_update_counter,
        }
    }

    pub fn signatures_required_now(&self) -> bool {
        if self.require_signed_updates {
            return true;
        }
        match self.legacy_unsigned_grace_until.as_deref() {
            Some(raw) => match DateTime::parse_from_rfc3339(raw) {
                Ok(cutoff) => Utc::now() > cutoff.with_timezone(&Utc),
                Err(_) => true,
            },
            None => true,
        }
    }
}

impl Default for UpdateTrustPolicy {
    fn default() -> Self {
        Self::from_settings(&UpdateSigningSettings::default())
    }
}

pub fn load_update_signing_key(
    settings: &UpdateSigningSettings,
) -> Result<Option<Vec<u8>>, String> {
    if let Ok(raw) = std::env::var("WARDEX_UPDATE_SIGNING_KEY_BASE64") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return decode_update_signing_key(trimmed.as_bytes()).map(Some);
        }
    }
    let Some(path) = settings
        .signing_key_path
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    let raw = std::fs::read(path).map_err(|e| format!("read update signing key: {e}"))?;
    decode_update_signing_key(&raw).map(Some)
}

pub fn decode_update_signing_key(raw: &[u8]) -> Result<Vec<u8>, String> {
    let trimmed = String::from_utf8_lossy(raw).trim().to_string();
    if !trimmed.is_empty() {
        if let Ok(decoded) = b64.decode(trimmed.as_bytes()) {
            return validate_signing_key_len(decoded);
        }
        if let Ok(decoded) = hex::decode(&trimmed) {
            return validate_signing_key_len(decoded);
        }
    }
    validate_signing_key_len(raw.to_vec())
}

pub fn verify_release_artifact(
    release: &Release,
    binary: &[u8],
    policy: &UpdateTrustPolicy,
    current_version: &str,
    last_accepted_counter: Option<u64>,
    allow_downgrade: bool,
) -> Result<UpdateVerification, String> {
    if release.file_size != binary.len() as u64 {
        return Err(format!(
            "update artifact size mismatch: expected {}, got {}",
            release.file_size,
            binary.len()
        ));
    }
    verify_update_not_downgrade(current_version, &release.version, allow_downgrade)?;

    if release.signature.is_none() {
        return if policy.signatures_required_now() {
            Err("missing update signature".to_string())
        } else {
            Ok(UpdateVerification {
                signature_status: "legacy_unsigned_grace".to_string(),
                signer_pubkey: None,
                signature_payload_sha256: None,
                update_counter: None,
            })
        };
    }

    release.verify_signature_for_binary(binary, &policy.trusted_update_signers, true)?;
    let update_counter = release
        .update_counter
        .ok_or_else(|| "missing update counter".to_string())?;
    if !allow_downgrade {
        verify_update_counter(update_counter, last_accepted_counter)?;
    }

    Ok(UpdateVerification {
        signature_status: "signed".to_string(),
        signer_pubkey: release.signer_pubkey.clone(),
        signature_payload_sha256: release.signature_payload_sha256.clone(),
        update_counter: Some(update_counter),
    })
}

fn validate_signing_key_len(key: Vec<u8>) -> Result<Vec<u8>, String> {
    if key.len() == 32 {
        Ok(key)
    } else {
        Err("update signing key must be 32 bytes".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auto_update::Release;
    use sha2::{Digest, Sha256};

    fn release_for(binary: &[u8]) -> Release {
        Release {
            version: "2.0.0".into(),
            platform: "linux".into(),
            sha256: hex::encode(Sha256::digest(binary)),
            file_name: "wardex-2.0.0-linux".into(),
            file_size: binary.len() as u64,
            release_notes: "signed".into(),
            mandatory: false,
            published_at: "2026-05-04T00:00:00Z".into(),
            signature: None,
            signer_pubkey: None,
            signed_at: None,
            signature_payload_sha256: None,
            update_counter: None,
        }
    }

    #[test]
    fn bundled_signer_accepts_signed_release_and_rejects_replay() {
        let binary = b"signed update";
        let mut release = release_for(binary);
        release.attach_signature(&[7u8; 32], 10).unwrap();
        let policy = UpdateTrustPolicy::default();

        let verification =
            verify_release_artifact(&release, binary, &policy, "1.0.0", Some(9), false).unwrap();
        assert_eq!(verification.signature_status, "signed");
        assert!(
            verify_release_artifact(&release, binary, &policy, "1.0.0", Some(10), false).is_err()
        );
    }

    #[test]
    fn unsigned_release_uses_grace_but_strict_rejects() {
        let binary = b"unsigned update";
        let release = release_for(binary);
        let policy = UpdateTrustPolicy::default();
        assert_eq!(
            verify_release_artifact(&release, binary, &policy, "1.0.0", None, false)
                .unwrap()
                .signature_status,
            "legacy_unsigned_grace"
        );

        let mut strict = policy.clone();
        strict.require_signed_updates = true;
        assert!(verify_release_artifact(&release, binary, &strict, "1.0.0", None, false).is_err());
    }

    #[test]
    fn tamper_wrong_key_and_downgrade_are_rejected() {
        let binary = b"signed update";
        let mut release = release_for(binary);
        release.attach_signature(&[7u8; 32], 10).unwrap();
        let policy = UpdateTrustPolicy::default();

        assert!(
            verify_release_artifact(&release, b"tampered", &policy, "1.0.0", None, false).is_err()
        );

        let mut wrong_policy = policy.clone();
        wrong_policy.trusted_update_signers =
            vec!["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string()];
        assert!(
            verify_release_artifact(&release, binary, &wrong_policy, "1.0.0", None, false).is_err()
        );

        let mut downgrade = release_for(binary);
        downgrade.version = "0.9.0".into();
        downgrade.attach_signature(&[7u8; 32], 11).unwrap();
        assert!(
            verify_release_artifact(&downgrade, binary, &policy, "1.0.0", None, false).is_err()
        );
        assert!(verify_release_artifact(&downgrade, binary, &policy, "1.0.0", None, true).is_ok());
    }
}
