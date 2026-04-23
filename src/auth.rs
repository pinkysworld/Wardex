// OIDC/SAML SSO authentication and session management for the Admin Console.
// ADR-0004: Layered identity model — extends RBAC with federated identity.

use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

// ── Auth mode ───────────────────────────────────────────────────

/// Authentication mode for the admin console.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// Static bearer-token authentication.
    Token,
    /// OpenID Connect SSO.
    Oidc,
}

// ── OIDC configuration ─────────────────────────────────────────

/// OIDC provider configuration loaded from the main config file.
#[derive(Debug, Clone, Deserialize)]
pub struct OidcConfig {
    pub enabled: bool,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    /// Maps IdP group names to Wardex role names (e.g. "soc-admins" -> "admin").
    pub group_mapping: HashMap<String, String>,
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            issuer: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            redirect_uri: String::new(),
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
            group_mapping: HashMap::new(),
        }
    }
}

// ── Token response ──────────────────────────────────────────────

/// Response from the OIDC token endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub id_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

// ── Session ─────────────────────────────────────────────────────

/// A user session created after successful authentication.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Session {
    pub user_id: String,
    pub email: String,
    pub role: String,
    #[serde(default)]
    pub groups: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Thread-safe session store with optional file-backed persistence.
pub struct SessionStore {
    sessions: Mutex<HashMap<String, Session>>,
    store_path: Option<String>,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            store_path: None,
        }
    }

    /// Create a session store that persists to disk at the given path.
    pub fn with_persistence(path: &str) -> Self {
        let store = Self {
            sessions: Mutex::new(HashMap::new()),
            store_path: Some(path.to_string()),
        };
        store.load();
        store
    }

    /// Load sessions from disk, discarding any expired entries.
    fn load(&self) {
        let Some(ref path) = self.store_path else {
            return;
        };
        let Ok(data) = std::fs::read_to_string(path) else {
            return;
        };
        let Ok(map) = serde_json::from_str::<HashMap<String, Session>>(&data) else {
            return;
        };
        let now = Utc::now();
        let valid: HashMap<String, Session> = map
            .into_iter()
            .filter(|(_, s)| s.expires_at > now)
            .collect();
        let mut store = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        *store = valid;
    }

    /// Reload sessions from disk, replacing the in-memory view.
    pub fn reload(&self) {
        self.load();
    }

    /// Persist current sessions to disk (best-effort).
    fn save(&self) {
        let Some(ref path) = self.store_path else {
            return;
        };
        let store = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        if let Ok(json) = serde_json::to_string(&*store) {
            if let Some(parent) = Path::new(path).parent()
                && !parent.as_os_str().is_empty()
                && std::fs::create_dir_all(parent).is_err()
            {
                return;
            }
            let tmp = format!("{path}.tmp");
            if std::fs::write(&tmp, &json).is_ok() {
                let _ = std::fs::rename(&tmp, path);
            }
        }
    }

    /// Create a new session and return an opaque session ID (random hex).
    pub fn create_session(
        &self,
        user_id: &str,
        email: &str,
        role: &str,
        groups: &[String],
        ttl_hours: i64,
    ) -> String {
        let mut rng = rand::thread_rng();
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        let session_id = hex::encode(buf);

        let now = Utc::now();
        let session = Session {
            user_id: user_id.to_string(),
            email: email.to_string(),
            role: role.to_string(),
            groups: groups.to_vec(),
            created_at: now,
            expires_at: now + Duration::hours(ttl_hours),
        };

        let mut store = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        store.insert(session_id.clone(), session);
        drop(store);
        self.save();
        session_id
    }

    /// Insert or replace a session using a caller-supplied session ID.
    pub fn insert_session(&self, session_id: String, session: Session) {
        let mut store = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        store.insert(session_id, session);
        drop(store);
        self.save();
    }

    /// Retrieve a session by ID. Returns `None` if missing or expired.
    /// Expired sessions are removed on access.
    pub fn get_session(&self, id: &str) -> Option<Session> {
        let mut store = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(session) = store.get(id) {
            if Utc::now() < session.expires_at {
                return Some(session.clone());
            }
            // Expired — remove it.
            store.remove(id);
            drop(store);
            self.save();
        }
        None
    }

    /// Destroy a session. Returns `true` if it existed.
    pub fn destroy_session(&self, id: &str) -> bool {
        let mut store = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let existed = store.remove(id).is_some();
        drop(store);
        if existed {
            self.save();
        }
        existed
    }

    /// Remove all expired sessions.
    pub fn cleanup_expired(&self) {
        let mut store = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let before = store.len();
        let now = Utc::now();
        store.retain(|_, s| s.expires_at > now);
        let changed = store.len() != before;
        drop(store);
        if changed {
            self.save();
        }
    }
}

// ── AuthManager ─────────────────────────────────────────────────

/// Central authentication manager holding OIDC config and session state.
pub struct AuthManager {
    pub config: OidcConfig,
    pub sessions: SessionStore,
}

impl AuthManager {
    pub fn new(config: OidcConfig) -> Self {
        Self {
            config,
            sessions: SessionStore::with_persistence("var/sessions.json"),
        }
    }

    /// Build the OIDC authorization URL and a random state nonce.
    /// Returns `(authorization_url, state_nonce)`.
    pub fn build_auth_url(&self) -> (String, String) {
        let mut rng = rand::thread_rng();
        let mut nonce_buf = [0u8; 16];
        rng.fill(&mut nonce_buf);
        let nonce = hex::encode(nonce_buf);

        let scope = self.config.scopes.join(" ");
        let url = format!(
            "{}/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}",
            self.config.issuer.trim_end_matches('/'),
            url_encode_component(&self.config.client_id),
            url_encode_component(&self.config.redirect_uri),
            url_encode_component(&scope),
            url_encode_component(&nonce),
        );
        (url, nonce)
    }

    /// Exchange an authorization code for tokens.
    /// Placeholder — returns an error because real HTTP exchange is not wired up yet.
    pub fn exchange_code(&self, _code: &str) -> Result<TokenResponse, String> {
        Err("OIDC token exchange not configured".into())
    }

    /// Validate a session cookie value and return the session if still valid.
    pub fn validate_session_cookie(&self, cookie: &str) -> Option<Session> {
        self.sessions.get_session(cookie)
    }

    /// Map IdP group names to a Wardex role using the configured group_mapping.
    /// Returns the highest-privilege matching role, or `"viewer"` if no group matches.
    pub fn extract_role_from_groups(&self, groups: &[String]) -> String {
        // Priority order: admin > analyst > viewer.
        let priority = ["admin", "analyst", "viewer"];

        let mut best: Option<&str> = None;
        for group in groups {
            if let Some(role) = self.config.group_mapping.get(group) {
                let role_str = role.as_str();
                match best {
                    None => best = Some(role_str),
                    Some(current) => {
                        let cur_idx = priority
                            .iter()
                            .position(|&p| p == current)
                            .unwrap_or(usize::MAX);
                        let new_idx = priority
                            .iter()
                            .position(|&p| p == role_str)
                            .unwrap_or(usize::MAX);
                        if new_idx < cur_idx {
                            best = Some(role_str);
                        }
                    }
                }
            }
        }
        best.unwrap_or("viewer").to_string()
    }
}

fn url_encode_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 3);
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                out.push('%');
                out.push(char::from(b"0123456789ABCDEF"[(byte >> 4) as usize]));
                out.push(char::from(b"0123456789ABCDEF"[(byte & 0x0F) as usize]));
            }
        }
    }
    out
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> OidcConfig {
        let mut group_mapping = HashMap::new();
        group_mapping.insert("soc-admins".into(), "admin".into());
        group_mapping.insert("soc-analysts".into(), "analyst".into());
        group_mapping.insert("soc-viewers".into(), "viewer".into());

        OidcConfig {
            enabled: true,
            issuer: "https://idp.example.com".into(),
            client_id: "wardex-console".into(),
            client_secret: "super-secret".into(),
            redirect_uri: "https://wardex.local/callback".into(),
            scopes: vec![
                "openid".into(),
                "profile".into(),
                "email".into(),
                "groups".into(),
            ],
            group_mapping,
        }
    }

    #[test]
    fn default_config_disabled() {
        let cfg = OidcConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.issuer.is_empty());
        assert!(cfg.group_mapping.is_empty());
    }

    // ── Session lifecycle ───────────────────────────────────────

    #[test]
    fn session_create_and_get() {
        let store = SessionStore::new();
        let sid = store.create_session(
            "u1",
            "u1@example.com",
            "admin",
            &["soc-admins".to_string(), "credential-routing".to_string()],
            8,
        );

        assert_eq!(sid.len(), 64); // 32 bytes hex-encoded
        let session = store.get_session(&sid).expect("session should exist");
        assert_eq!(session.user_id, "u1");
        assert_eq!(session.email, "u1@example.com");
        assert_eq!(session.role, "admin");
        assert_eq!(session.groups, vec!["soc-admins", "credential-routing"]);
    }

    #[test]
    fn session_insert_preserves_expiry() {
        let store = SessionStore::new();
        let expires_at = Utc::now() + Duration::minutes(45);
        store.insert_session(
            "oidc-session".into(),
            Session {
                user_id: "sso-user".into(),
                email: "sso@example.com".into(),
                role: "analyst".into(),
                groups: vec!["Security".into()],
                created_at: Utc::now(),
                expires_at,
            },
        );

        let session = store
            .get_session("oidc-session")
            .expect("inserted session should exist");
        assert_eq!(session.user_id, "sso-user");
        assert_eq!(session.expires_at.timestamp(), expires_at.timestamp());
    }

    #[test]
    fn session_destroy() {
        let store = SessionStore::new();
        let sid = store.create_session("u2", "u2@example.com", "viewer", &[], 1);

        assert!(store.destroy_session(&sid));
        assert!(store.get_session(&sid).is_none());
        // Double-destroy returns false.
        assert!(!store.destroy_session(&sid));
    }

    #[test]
    fn session_expired_is_none() {
        let store = SessionStore::new();
        // Create a session with 0-hour TTL — already expired.
        let sid = store.create_session("u3", "u3@example.com", "analyst", &[], 0);
        // The session expires_at == created_at, so Utc::now() >= expires_at.
        assert!(store.get_session(&sid).is_none());
    }

    #[test]
    fn cleanup_expired_sessions() {
        let store = SessionStore::new();
        let _expired = store.create_session("old", "old@example.com", "viewer", &[], 0);
        let alive = store.create_session("new", "new@example.com", "admin", &[], 8);

        store.cleanup_expired();
        assert!(store.get_session(&_expired).is_none());
        assert!(store.get_session(&alive).is_some());
    }

    // ── Role mapping ────────────────────────────────────────────

    #[test]
    fn role_mapping_admin() {
        let mgr = AuthManager::new(test_config());
        let role = mgr.extract_role_from_groups(&["soc-admins".into()]);
        assert_eq!(role, "admin");
    }

    #[test]
    fn role_mapping_highest_wins() {
        let mgr = AuthManager::new(test_config());
        let role = mgr.extract_role_from_groups(&[
            "soc-viewers".into(),
            "soc-analysts".into(),
            "soc-admins".into(),
        ]);
        assert_eq!(role, "admin");
    }

    #[test]
    fn role_mapping_unknown_defaults_to_viewer() {
        let mgr = AuthManager::new(test_config());
        let role = mgr.extract_role_from_groups(&["random-group".into()]);
        assert_eq!(role, "viewer");
    }

    #[test]
    fn role_mapping_empty_groups() {
        let mgr = AuthManager::new(test_config());
        let role = mgr.extract_role_from_groups(&[]);
        assert_eq!(role, "viewer");
    }

    // ── Auth URL construction ───────────────────────────────────

    #[test]
    fn build_auth_url_has_required_params() {
        let mgr = AuthManager::new(test_config());
        let (url, nonce) = mgr.build_auth_url();

        assert!(url.starts_with("https://idp.example.com/authorize?"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=wardex-console"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fwardex.local%2Fcallback"));
        assert!(url.contains("scope=openid%20profile%20email%20groups"));
        assert!(url.contains(&format!("state={}", nonce)));
        assert_eq!(nonce.len(), 32); // 16 bytes hex-encoded
    }

    #[test]
    fn build_auth_url_encodes_special_characters() {
        let mut cfg = test_config();
        cfg.client_id = "wardex console".into();
        cfg.redirect_uri = "https://wardex.local/callback?tenant=acme&next=/admin".into();
        cfg.scopes = vec!["openid".into(), "profile email".into()];

        let mgr = AuthManager::new(cfg);
        let (url, _) = mgr.build_auth_url();

        assert!(url.contains("client_id=wardex%20console"));
        assert!(url.contains(
            "redirect_uri=https%3A%2F%2Fwardex.local%2Fcallback%3Ftenant%3Dacme%26next%3D%2Fadmin"
        ));
        assert!(url.contains("scope=openid%20profile%20email"));
    }

    // ── Exchange code placeholder ───────────────────────────────

    #[test]
    fn exchange_code_returns_error() {
        let mgr = AuthManager::new(test_config());
        let result = mgr.exchange_code("auth-code-123");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "OIDC token exchange not configured");
    }

    // ── Session cookie validation ───────────────────────────────

    #[test]
    fn validate_session_cookie_valid() {
        let mgr = AuthManager::new(test_config());
        let sid = mgr.sessions.create_session(
            "u5",
            "u5@example.com",
            "analyst",
            &["soc-analysts".to_string()],
            8,
        );
        let session = mgr.validate_session_cookie(&sid).expect("should be valid");
        assert_eq!(session.email, "u5@example.com");
        assert_eq!(session.groups, vec!["soc-analysts"]);
    }

    #[test]
    fn validate_session_cookie_invalid() {
        let mgr = AuthManager::new(test_config());
        assert!(mgr.validate_session_cookie("bogus-cookie").is_none());
    }

    #[test]
    fn session_persistence_round_trip() {
        let dir = std::env::temp_dir();
        let path = dir.join("wardex_test_sessions.json");
        let path_str = path.to_string_lossy().to_string();

        // Create store with a session, which triggers save
        {
            let store = SessionStore::with_persistence(&path_str);
            store.create_session(
                "u1",
                "u1@example.com",
                "admin",
                &["soc-admins".to_string()],
                8,
            );
        }

        // Load into a new store and verify the session survived
        let store2 = SessionStore::with_persistence(&path_str);
        let sessions = store2.sessions.lock().unwrap();
        assert_eq!(sessions.len(), 1);
        let session = sessions.values().next().unwrap();
        assert_eq!(session.email, "u1@example.com");
        assert_eq!(session.role, "admin");
        assert_eq!(session.groups, vec!["soc-admins"]);
        drop(sessions);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn session_load_missing_file_no_panic() {
        let store = SessionStore::with_persistence("/tmp/wardex_nonexistent_sessions.json");
        assert!(store.sessions.lock().unwrap().is_empty());
    }

    #[test]
    fn session_load_invalid_json_no_panic() {
        let dir = std::env::temp_dir();
        let path = dir.join("wardex_test_bad_sessions.json");
        std::fs::write(&path, "not valid json {{{").unwrap();
        let store = SessionStore::with_persistence(&path.to_string_lossy());
        assert!(store.sessions.lock().unwrap().is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn session_persistence_creates_missing_parent_directories() {
        let root =
            std::env::temp_dir().join(format!("wardex_sessions_nested_{}", std::process::id()));
        let path = root.join("nested").join("sessions.json");
        let path_str = path.to_string_lossy().to_string();

        {
            let store = SessionStore::with_persistence(&path_str);
            store.create_session("u9", "u9@example.com", "admin", &[], 8);
        }

        assert!(path.exists());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(&root);
    }
}
