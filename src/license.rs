use base64::engine::general_purpose::STANDARD as b64;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

// ── Data Structures ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseClaims {
    pub id: String,
    pub tier: String,
    pub org: String,
    pub max_agents: u32,
    pub max_users: u32,
    pub features: Vec<String>,
    pub issued_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LicenseStatus {
    pub valid: bool,
    pub tier: String,
    pub org: String,
    pub expires_at: String,
    pub days_remaining: i64,
    pub in_grace_period: bool,
    pub max_agents: u32,
    pub max_users: u32,
    pub features: Vec<String>,
}

// ── License Key Generation & Validation ───────────────────────────────────────

/// Sign claims with Ed25519, returning `base64(payload).base64(signature)`.
pub fn generate_license(claims: &LicenseClaims, signing_key: &[u8]) -> Result<String, String> {
    let key_bytes: [u8; 32] = signing_key
        .try_into()
        .map_err(|_| "signing key must be 32 bytes".to_string())?;
    let key = SigningKey::from_bytes(&key_bytes);

    let payload_json =
        serde_json::to_string(claims).map_err(|e| format!("serialize claims: {e}"))?;
    let payload_b64 = b64.encode(payload_json.as_bytes());

    let sig = key.sign(payload_b64.as_bytes());
    let sig_b64 = b64.encode(sig.to_bytes());

    Ok(format!("{payload_b64}.{sig_b64}"))
}

/// Verify signature and check expiry, returning the decoded claims.
pub fn validate_license(key: &str, public_key: &[u8]) -> Result<LicenseClaims, String> {
    let parts: Vec<&str> = key.splitn(2, '.').collect();
    if parts.len() != 2 {
        return Err("invalid license format: expected payload.signature".into());
    }
    let (payload_b64, sig_b64) = (parts[0], parts[1]);

    let pk_bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| "public key must be 32 bytes".to_string())?;
    let verifying_key =
        VerifyingKey::from_bytes(&pk_bytes).map_err(|e| format!("invalid public key: {e}"))?;

    let sig_bytes = b64
        .decode(sig_b64)
        .map_err(|e| format!("decode signature: {e}"))?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "signature must be 64 bytes".to_string())?;
    let signature = Signature::from_bytes(&sig_arr);

    verifying_key
        .verify(payload_b64.as_bytes(), &signature)
        .map_err(|_| "invalid license signature".to_string())?;

    let payload_bytes = b64
        .decode(payload_b64)
        .map_err(|e| format!("decode payload: {e}"))?;
    let claims: LicenseClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("parse claims: {e}"))?;

    let expires = DateTime::parse_from_rfc3339(&claims.expires_at)
        .map_err(|e| format!("parse expires_at: {e}"))?;
    if Utc::now() > expires {
        return Err(format!("license expired on {}", claims.expires_at));
    }

    Ok(claims)
}

/// Create a 30-day enterprise trial license.
pub fn generate_trial(org: &str) -> LicenseClaims {
    let now = Utc::now();
    LicenseClaims {
        id: format!("trial-{}", now.timestamp()),
        tier: "enterprise".into(),
        org: org.into(),
        max_agents: 10,
        max_users: 5,
        features: vec![
            "sso".into(),
            "multi_tenant".into(),
            "compliance".into(),
            "playbooks".into(),
        ],
        issued_at: now.to_rfc3339(),
        expires_at: (now + Duration::days(30)).to_rfc3339(),
    }
}

// ── License Enforcer ──────────────────────────────────────────────────────────

pub struct LicenseEnforcer {
    claims: Option<LicenseClaims>,
    public_key: Vec<u8>,
    grace_period_days: u32,
}

impl LicenseEnforcer {
    pub fn new(public_key: Vec<u8>) -> Self {
        Self {
            claims: None,
            public_key,
            grace_period_days: 14,
        }
    }

    pub fn with_grace_period(mut self, days: u32) -> Self {
        self.grace_period_days = days;
        self
    }

    /// Validate and store a license key. Accepts expired licenses so the
    /// grace-period logic can still apply; only rejects invalid signatures.
    pub fn load(&mut self, key: &str) -> Result<(), String> {
        let parts: Vec<&str> = key.splitn(2, '.').collect();
        if parts.len() != 2 {
            return Err("invalid license format".into());
        }
        let (payload_b64, sig_b64) = (parts[0], parts[1]);

        let pk_bytes: [u8; 32] = self
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| "public key must be 32 bytes".to_string())?;
        let verifying_key = VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|e| format!("invalid public key: {e}"))?;

        let sig_bytes = b64
            .decode(sig_b64)
            .map_err(|e| format!("decode signature: {e}"))?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| "signature must be 64 bytes".to_string())?;
        let signature = Signature::from_bytes(&sig_arr);

        verifying_key
            .verify(payload_b64.as_bytes(), &signature)
            .map_err(|_| "invalid license signature".to_string())?;

        let payload_bytes = b64
            .decode(payload_b64)
            .map_err(|e| format!("decode payload: {e}"))?;
        let claims: LicenseClaims = serde_json::from_slice(&payload_bytes)
            .map_err(|e| format!("parse claims: {e}"))?;

        self.claims = Some(claims);
        Ok(())
    }

    pub fn days_remaining(&self) -> Option<i64> {
        let claims = self.claims.as_ref()?;
        let expires = DateTime::parse_from_rfc3339(&claims.expires_at).ok()?;
        let diff = expires.signed_duration_since(Utc::now());
        Some(diff.num_days())
    }

    pub fn in_grace_period(&self) -> bool {
        match self.days_remaining() {
            Some(days) => days < 0 && days.unsigned_abs() <= u64::from(self.grace_period_days),
            None => false,
        }
    }

    pub fn is_valid(&self) -> bool {
        match self.days_remaining() {
            Some(days) if days >= 0 => true,
            _ => self.in_grace_period(),
        }
    }

    pub fn is_feature_allowed(&self, feature: &str) -> bool {
        if !self.is_valid() {
            return false;
        }
        match &self.claims {
            Some(c) => c.features.iter().any(|f| f == feature),
            None => false,
        }
    }

    pub fn check_agent_limit(&self, current: u32) -> bool {
        match &self.claims {
            Some(c) if self.is_valid() => current <= c.max_agents,
            _ => false,
        }
    }

    pub fn check_user_limit(&self, current: u32) -> bool {
        match &self.claims {
            Some(c) if self.is_valid() => current <= c.max_users,
            _ => false,
        }
    }

    pub fn status(&self) -> LicenseStatus {
        match &self.claims {
            Some(c) => LicenseStatus {
                valid: self.is_valid(),
                tier: c.tier.clone(),
                org: c.org.clone(),
                expires_at: c.expires_at.clone(),
                days_remaining: self.days_remaining().unwrap_or(0),
                in_grace_period: self.in_grace_period(),
                max_agents: c.max_agents,
                max_users: c.max_users,
                features: c.features.clone(),
            },
            None => LicenseStatus {
                valid: false,
                tier: "none".into(),
                org: String::new(),
                expires_at: String::new(),
                days_remaining: 0,
                in_grace_period: false,
                max_agents: 0,
                max_users: 0,
                features: vec![],
            },
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn test_keypair() -> (Vec<u8>, Vec<u8>) {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key();
        (sk.to_bytes().to_vec(), pk.to_bytes().to_vec())
    }

    fn valid_claims() -> LicenseClaims {
        let now = Utc::now();
        LicenseClaims {
            id: "test-001".into(),
            tier: "professional".into(),
            org: "Acme Corp".into(),
            max_agents: 50,
            max_users: 20,
            features: vec!["sso".into(), "compliance".into()],
            issued_at: now.to_rfc3339(),
            expires_at: (now + Duration::days(365)).to_rfc3339(),
        }
    }

    fn expired_claims(days_ago: i64) -> LicenseClaims {
        let now = Utc::now();
        LicenseClaims {
            id: "expired-001".into(),
            tier: "enterprise".into(),
            org: "Old Co".into(),
            max_agents: 10,
            max_users: 5,
            features: vec!["sso".into()],
            issued_at: (now - Duration::days(days_ago + 30)).to_rfc3339(),
            expires_at: (now - Duration::days(days_ago)).to_rfc3339(),
        }
    }

    #[test]
    fn generate_and_validate_roundtrip() {
        let (sk, pk) = test_keypair();
        let claims = valid_claims();
        let key = generate_license(&claims, &sk).unwrap();
        assert!(key.contains('.'));

        let decoded = validate_license(&key, &pk).unwrap();
        assert_eq!(decoded.id, "test-001");
        assert_eq!(decoded.tier, "professional");
        assert_eq!(decoded.org, "Acme Corp");
        assert_eq!(decoded.max_agents, 50);
        assert_eq!(decoded.max_users, 20);
        assert_eq!(decoded.features, vec!["sso", "compliance"]);
    }

    #[test]
    fn tampered_signature_rejected() {
        let (sk, pk) = test_keypair();
        let claims = valid_claims();
        let key = generate_license(&claims, &sk).unwrap();

        // Flip a character in the signature portion
        let parts: Vec<&str> = key.splitn(2, '.').collect();
        let mut sig = parts[1].to_string();
        let replacement = if sig.ends_with('A') { 'B' } else { 'A' };
        sig.pop();
        sig.push(replacement);
        let tampered = format!("{}.{}", parts[0], sig);

        let result = validate_license(&tampered, &pk);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("signature"));
    }

    #[test]
    fn expired_license_rejected_by_validate() {
        let (sk, pk) = test_keypair();
        let claims = expired_claims(5);
        let key = generate_license(&claims, &sk).unwrap();

        let result = validate_license(&key, &pk);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expired"));
    }

    #[test]
    fn enforcer_grace_period() {
        let (sk, pk) = test_keypair();
        // Expired 3 days ago — within default 14-day grace period
        let claims = expired_claims(3);
        let key = generate_license(&claims, &sk).unwrap();

        let mut enforcer = LicenseEnforcer::new(pk.clone());
        enforcer.load(&key).unwrap();

        assert!(enforcer.in_grace_period());
        assert!(enforcer.is_valid());
        assert!(enforcer.days_remaining().unwrap() < 0);
    }

    #[test]
    fn enforcer_past_grace_period() {
        let (sk, pk) = test_keypair();
        // Expired 30 days ago — past the 14-day grace period
        let claims = expired_claims(30);
        let key = generate_license(&claims, &sk).unwrap();

        let mut enforcer = LicenseEnforcer::new(pk.clone());
        enforcer.load(&key).unwrap();

        assert!(!enforcer.in_grace_period());
        assert!(!enforcer.is_valid());
    }

    #[test]
    fn trial_license_generation() {
        let trial = generate_trial("TestOrg");
        assert_eq!(trial.tier, "enterprise");
        assert_eq!(trial.org, "TestOrg");
        assert_eq!(trial.max_agents, 10);
        assert_eq!(trial.max_users, 5);
        assert!(trial.features.contains(&"sso".to_string()));
        assert!(trial.features.contains(&"multi_tenant".to_string()));
        assert!(trial.features.contains(&"compliance".to_string()));
        assert!(trial.features.contains(&"playbooks".to_string()));
        assert!(trial.id.starts_with("trial-"));

        // Verify the trial is valid for ~30 days
        let issued = DateTime::parse_from_rfc3339(&trial.issued_at).unwrap();
        let expires = DateTime::parse_from_rfc3339(&trial.expires_at).unwrap();
        let diff = expires.signed_duration_since(issued).num_days();
        assert_eq!(diff, 30);
    }

    #[test]
    fn feature_checking() {
        let (sk, pk) = test_keypair();
        let claims = valid_claims(); // has ["sso", "compliance"]
        let key = generate_license(&claims, &sk).unwrap();

        let mut enforcer = LicenseEnforcer::new(pk);
        enforcer.load(&key).unwrap();

        assert!(enforcer.is_feature_allowed("sso"));
        assert!(enforcer.is_feature_allowed("compliance"));
        assert!(!enforcer.is_feature_allowed("multi_tenant"));
        assert!(!enforcer.is_feature_allowed("playbooks"));
    }

    #[test]
    fn agent_limit_checking() {
        let (sk, pk) = test_keypair();
        let claims = valid_claims(); // max_agents = 50
        let key = generate_license(&claims, &sk).unwrap();

        let mut enforcer = LicenseEnforcer::new(pk);
        enforcer.load(&key).unwrap();

        assert!(enforcer.check_agent_limit(0));
        assert!(enforcer.check_agent_limit(50));
        assert!(!enforcer.check_agent_limit(51));
    }

    #[test]
    fn user_limit_checking() {
        let (sk, pk) = test_keypair();
        let claims = valid_claims(); // max_users = 20
        let key = generate_license(&claims, &sk).unwrap();

        let mut enforcer = LicenseEnforcer::new(pk);
        enforcer.load(&key).unwrap();

        assert!(enforcer.check_user_limit(0));
        assert!(enforcer.check_user_limit(20));
        assert!(!enforcer.check_user_limit(21));
    }

    #[test]
    fn enforcer_status_valid() {
        let (sk, pk) = test_keypair();
        let claims = valid_claims();
        let key = generate_license(&claims, &sk).unwrap();

        let mut enforcer = LicenseEnforcer::new(pk);
        enforcer.load(&key).unwrap();

        let status = enforcer.status();
        assert!(status.valid);
        assert_eq!(status.tier, "professional");
        assert_eq!(status.org, "Acme Corp");
        assert!(!status.in_grace_period);
        assert!(status.days_remaining > 0);
        assert_eq!(status.max_agents, 50);
        assert_eq!(status.max_users, 20);
    }

    #[test]
    fn enforcer_status_no_license() {
        let enforcer = LicenseEnforcer::new(vec![0u8; 32]);
        let status = enforcer.status();
        assert!(!status.valid);
        assert_eq!(status.tier, "none");
        assert_eq!(status.max_agents, 0);
    }

    #[test]
    fn wrong_public_key_rejected() {
        let (sk, _pk) = test_keypair();
        let (_sk2, pk2) = test_keypair();
        let claims = valid_claims();
        let key = generate_license(&claims, &sk).unwrap();

        let result = validate_license(&key, &pk2);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_key_format_rejected() {
        let result = validate_license("no-dot-here", &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn enforcer_custom_grace_period() {
        let (sk, pk) = test_keypair();
        // Expired 5 days ago
        let claims = expired_claims(5);
        let key = generate_license(&claims, &sk).unwrap();

        // Grace period of only 3 days — should be invalid
        let mut enforcer = LicenseEnforcer::new(pk).with_grace_period(3);
        enforcer.load(&key).unwrap();

        assert!(!enforcer.in_grace_period());
        assert!(!enforcer.is_valid());
    }
}
