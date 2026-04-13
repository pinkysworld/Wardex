// ── OIDC/SAML SSO Authentication ─────────────────────────────────────────────
//
// Provides OpenID Connect and SAML 2.0 single-sign-on support for enterprise
// deployments. Supports Okta, Azure AD, Google Workspace, and any
// OIDC-compliant identity provider.
//
// Flow: /api/auth/oidc/login → redirect to IdP → callback → JWT session

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

// ── OIDC Configuration ───────────────────────────────────────────────────────

/// OpenID Connect provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    #[serde(skip_serializing)]
    pub client_secret: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub auto_provision: bool,
    #[serde(default)]
    pub default_role: String,
    #[serde(default)]
    pub role_claim: String,
    #[serde(default)]
    pub role_mapping: HashMap<String, String>,
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            redirect_uri: "http://localhost:8080/api/auth/oidc/callback".into(),
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
            audience: None,
            enabled: false,
            auto_provision: true,
            default_role: "analyst".into(),
            role_claim: "roles".into(),
            role_mapping: HashMap::new(),
        }
    }
}

/// SAML 2.0 provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlConfig {
    pub entity_id: String,
    pub sso_url: String,
    pub certificate_pem: String,
    pub acs_url: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub attribute_mapping: HashMap<String, String>,
}

impl Default for SamlConfig {
    fn default() -> Self {
        Self {
            entity_id: String::new(),
            sso_url: String::new(),
            certificate_pem: String::new(),
            acs_url: "http://localhost:8080/api/auth/saml/acs".into(),
            enabled: false,
            attribute_mapping: HashMap::new(),
        }
    }
}

// ── OIDC Discovery & Token Exchange ──────────────────────────────────────────

/// Parsed OIDC discovery document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcDiscovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub end_session_endpoint: Option<String>,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    #[serde(default)]
    pub response_types_supported: Vec<String>,
}

/// OAuth2 token response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub scope: Option<String>,
}

/// User info from the OIDC provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcUserInfo {
    pub sub: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
}

/// SSO session stored server-side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoSession {
    pub session_id: String,
    pub user_info: OidcUserInfo,
    pub wardex_role: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub refresh_token: Option<String>,
    pub provider: String,
}

// ── OIDC Provider ────────────────────────────────────────────────────────────

/// OIDC provider that manages discovery, authorization, and token exchange.
#[derive(Debug)]
pub struct OidcProvider {
    config: OidcConfig,
    discovery: Option<OidcDiscovery>,
    sessions: HashMap<String, SsoSession>,
    pending_states: HashMap<String, PendingAuth>,
}

#[derive(Debug, Clone)]
struct PendingAuth {
    state: String,
    nonce: String,
    created_at: u64,
    redirect_after: Option<String>,
}

impl OidcProvider {
    pub fn new(config: OidcConfig) -> Self {
        Self {
            config,
            discovery: None,
            sessions: HashMap::new(),
            pending_states: HashMap::new(),
        }
    }

    /// Fetch the OIDC discovery document from the issuer.
    pub fn discover(&mut self) -> Result<&OidcDiscovery, String> {
        let url = format!("{}/.well-known/openid-configuration", self.config.issuer.trim_end_matches('/'));
        let discovery: OidcDiscovery = ureq::get(&url)
            .call()
            .map_err(|e| format!("OIDC discovery failed: {e}"))?
            .into_json()
            .map_err(|e| format!("OIDC discovery parse failed: {e}"))?;
        self.discovery = Some(discovery);
        Ok(self.discovery.as_ref().unwrap())
    }

    /// Generate an authorization URL for the user to visit.
    pub fn authorize_url(&mut self, redirect_after: Option<String>) -> Result<String, String> {
        let discovery = self.discovery.as_ref().ok_or("OIDC not discovered yet")?;
        let state = generate_random_string(32);
        let nonce = generate_random_string(32);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.pending_states.insert(
            state.clone(),
            PendingAuth {
                state: state.clone(),
                nonce: nonce.clone(),
                created_at: now,
                redirect_after,
            },
        );

        let scopes = self.config.scopes.join(" ");
        let url = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}",
            discovery.authorization_endpoint,
            urlencoded(&self.config.client_id),
            urlencoded(&self.config.redirect_uri),
            urlencoded(&scopes),
            urlencoded(&state),
            urlencoded(&nonce),
        );

        Ok(url)
    }

    /// Exchange an authorization code for tokens and create a session.
    pub fn exchange_code(&mut self, code: &str, state: &str) -> Result<SsoSession, String> {
        let pending = self
            .pending_states
            .remove(state)
            .ok_or("Invalid or expired state parameter")?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Expire states older than 10 minutes
        if now - pending.created_at > 600 {
            return Err("Authorization state expired".into());
        }

        let discovery = self.discovery.as_ref().ok_or("OIDC not discovered")?;

        // Token exchange
        let form = format!(
            "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&client_secret={}",
            urlencoded(code),
            urlencoded(&self.config.redirect_uri),
            urlencoded(&self.config.client_id),
            urlencoded(&self.config.client_secret),
        );

        let token_resp: TokenResponse = ureq::post(&discovery.token_endpoint)
            .set("Content-Type", "application/x-www-form-urlencoded")
            .send_string(&form)
            .map_err(|e| format!("Token exchange failed: {e}"))?
            .into_json()
            .map_err(|e| format!("Token parse failed: {e}"))?;

        // Fetch user info
        let user_info: OidcUserInfo = ureq::get(&discovery.userinfo_endpoint)
            .set("Authorization", &format!("Bearer {}", token_resp.access_token))
            .call()
            .map_err(|e| format!("UserInfo fetch failed: {e}"))?
            .into_json()
            .map_err(|e| format!("UserInfo parse failed: {e}"))?;

        // Determine Wardex role from claims
        let role = self.resolve_role(&user_info);

        let session_id = generate_random_string(48);
        let expires_in = token_resp.expires_in.unwrap_or(3600);

        let session = SsoSession {
            session_id: session_id.clone(),
            user_info,
            wardex_role: role,
            created_at: now,
            expires_at: now + expires_in,
            refresh_token: token_resp.refresh_token,
            provider: "oidc".into(),
        };

        self.sessions.insert(session_id, session.clone());
        Ok(session)
    }

    /// Validate a session ID and return the session if valid.
    pub fn validate_session(&self, session_id: &str) -> Option<&SsoSession> {
        let session = self.sessions.get(session_id)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now > session.expires_at {
            return None;
        }
        Some(session)
    }

    /// Invalidate/logout a session.
    pub fn logout(&mut self, session_id: &str) -> bool {
        self.sessions.remove(session_id).is_some()
    }

    /// Get active session count.
    pub fn active_sessions(&self) -> usize {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.sessions.values().filter(|s| s.expires_at > now).count()
    }

    /// Get SSO provider status.
    pub fn status(&self) -> SsoStatus {
        SsoStatus {
            oidc_enabled: self.config.enabled,
            discovered: self.discovery.is_some(),
            issuer: self.config.issuer.clone(),
            active_sessions: self.active_sessions(),
            auto_provision: self.config.auto_provision,
        }
    }

    pub fn config(&self) -> &OidcConfig {
        &self.config
    }

    fn resolve_role(&self, user_info: &OidcUserInfo) -> String {
        // Check role mapping first
        for role in &user_info.roles {
            if let Some(wardex_role) = self.config.role_mapping.get(role) {
                return wardex_role.clone();
            }
        }
        for group in &user_info.groups {
            if let Some(wardex_role) = self.config.role_mapping.get(group) {
                return wardex_role.clone();
            }
        }
        self.config.default_role.clone()
    }
}

/// SSO system status summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoStatus {
    pub oidc_enabled: bool,
    pub discovered: bool,
    pub issuer: String,
    pub active_sessions: usize,
    pub auto_provision: bool,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn generate_random_string(len: usize) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut hasher = DefaultHasher::new();
    seed.hash(&mut hasher);
    std::thread::current().id().hash(&mut hasher);
    let hash = hasher.finish();
    format!("{hash:016x}{:016x}", hash.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407))
        .chars()
        .take(len)
        .collect()
}

fn urlencoded(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(char::from(b"0123456789ABCDEF"[(b >> 4) as usize]));
                out.push(char::from(b"0123456789ABCDEF"[(b & 0xF) as usize]));
            }
        }
    }
    out
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> OidcConfig {
        OidcConfig {
            issuer: "https://accounts.google.com".into(),
            client_id: "test-client-id".into(),
            client_secret: "test-secret".into(),
            redirect_uri: "http://localhost:8080/api/auth/oidc/callback".into(),
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
            audience: None,
            enabled: true,
            auto_provision: true,
            default_role: "analyst".into(),
            role_claim: "roles".into(),
            role_mapping: {
                let mut m = HashMap::new();
                m.insert("SecurityAdmin".into(), "admin".into());
                m.insert("SecurityAnalyst".into(), "analyst".into());
                m
            },
        }
    }

    #[test]
    fn oidc_provider_creation() {
        let provider = OidcProvider::new(test_config());
        assert_eq!(provider.active_sessions(), 0);
        assert!(provider.discovery.is_none());
        let status = provider.status();
        assert!(status.oidc_enabled);
        assert!(!status.discovered);
    }

    #[test]
    fn role_mapping() {
        let provider = OidcProvider::new(test_config());
        let user = OidcUserInfo {
            sub: "user-123".into(),
            name: Some("Test User".into()),
            email: Some("test@example.com".into()),
            email_verified: Some(true),
            preferred_username: Some("testuser".into()),
            roles: vec!["SecurityAdmin".into()],
            groups: vec![],
        };
        assert_eq!(provider.resolve_role(&user), "admin");

        let analyst_user = OidcUserInfo {
            roles: vec!["SecurityAnalyst".into()],
            ..user.clone()
        };
        assert_eq!(provider.resolve_role(&analyst_user), "analyst");

        let unknown_user = OidcUserInfo {
            roles: vec!["UnknownRole".into()],
            groups: vec![],
            ..user.clone()
        };
        assert_eq!(provider.resolve_role(&unknown_user), "analyst"); // default
    }

    #[test]
    fn urlencoded_special_chars() {
        assert_eq!(urlencoded("hello world"), "hello%20world");
        assert_eq!(urlencoded("foo@bar.com"), "foo%40bar.com");
        assert_eq!(urlencoded("a+b=c"), "a%2Bb%3Dc");
    }

    #[test]
    fn saml_config_default() {
        let config = SamlConfig::default();
        assert!(!config.enabled);
        assert!(config.entity_id.is_empty());
    }

    #[test]
    fn session_validation() {
        let mut provider = OidcProvider::new(test_config());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let session = SsoSession {
            session_id: "test-session-123".into(),
            user_info: OidcUserInfo {
                sub: "user-1".into(),
                name: Some("Test".into()),
                email: Some("t@t.com".into()),
                email_verified: Some(true),
                preferred_username: None,
                roles: vec![],
                groups: vec![],
            },
            wardex_role: "analyst".into(),
            created_at: now,
            expires_at: now + 3600,
            refresh_token: None,
            provider: "oidc".into(),
        };

        provider.sessions.insert("test-session-123".into(), session);
        assert!(provider.validate_session("test-session-123").is_some());
        assert!(provider.validate_session("nonexistent").is_none());
        assert_eq!(provider.active_sessions(), 1);

        // Logout
        assert!(provider.logout("test-session-123"));
        assert!(provider.validate_session("test-session-123").is_none());
        assert_eq!(provider.active_sessions(), 0);
    }

    #[test]
    fn authorize_url_requires_discovery() {
        let mut provider = OidcProvider::new(test_config());
        assert!(provider.authorize_url(None).is_err());
    }

    #[test]
    fn exchange_code_rejects_invalid_state() {
        let mut provider = OidcProvider::new(test_config());
        assert!(provider.exchange_code("code", "bad-state").is_err());
    }
}
