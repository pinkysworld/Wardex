// ── OIDC/SAML SSO Authentication ─────────────────────────────────────────────
//
// Provides OpenID Connect and SAML 2.0 single-sign-on support for enterprise
// deployments. Supports Okta, Azure AD, Google Workspace, and any
// OIDC-compliant identity provider.
//
// Flow: /api/auth/oidc/login → redirect to IdP → callback → JWT session

use base64::Engine;
use jsonwebtoken::jwk::{Jwk, JwkSet, KeyOperations, PublicKeyUse};
use jsonwebtoken::{DecodingKey, Header, TokenData, Validation, decode, decode_header};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum age in seconds for pending OIDC authorization states (10 minutes).
const PENDING_STATE_TTL_SECS: u64 = 600;

/// Default token expiry in seconds when the IdP does not provide one.
const DEFAULT_TOKEN_EXPIRY_SECS: u64 = 3600;

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

#[derive(Debug, Clone, Deserialize)]
struct OidcIdTokenClaims {
    iss: String,
    sub: String,
    aud: OneOrManyStrings,
    exp: u64,
    #[serde(default)]
    iat: Option<u64>,
    #[serde(default)]
    nbf: Option<u64>,
    #[serde(default)]
    azp: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum OneOrManyStrings {
    One(String),
    Many(Vec<String>),
}

// ── OIDC Provider ────────────────────────────────────────────────────────────

/// OIDC provider that manages discovery, authorization, and token exchange.
#[derive(Debug)]
pub struct OidcProvider {
    config: OidcConfig,
    discovery: Option<OidcDiscovery>,
    jwks_cache: Option<CachedJwks>,
    sessions: HashMap<String, SsoSession>,
    pending_states: HashMap<String, PendingAuth>,
}

#[derive(Debug, Clone)]
struct CachedJwks {
    jwks: JwkSet,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct PendingAuth {
    state: String,
    nonce: String,
    code_verifier: String,
    created_at: u64,
    redirect_after: Option<String>,
}

impl OidcProvider {
    pub fn new(config: OidcConfig) -> Self {
        Self {
            config,
            discovery: None,
            jwks_cache: None,
            sessions: HashMap::new(),
            pending_states: HashMap::new(),
        }
    }

    /// Fetch the OIDC discovery document from the issuer.
    pub fn discover(&mut self) -> Result<&OidcDiscovery, String> {
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.config.issuer.trim_end_matches('/')
        );
        let discovery: OidcDiscovery = ureq::get(&url)
            .call()
            .map_err(|e| format!("OIDC discovery failed: {e}"))?
            .into_json()
            .map_err(|e| format!("OIDC discovery parse failed: {e}"))?;
        self.discovery = Some(discovery);
        self.discovery
            .as_ref()
            .ok_or_else(|| "OIDC discovery state missing after assignment".to_string())
    }

    /// Generate an authorization URL for the user to visit.
    pub fn authorize_url(&mut self, redirect_after: Option<String>) -> Result<String, String> {
        let discovery = self.discovery.as_ref().ok_or("OIDC not discovered yet")?;
        let state = generate_random_string(32);
        let nonce = generate_random_string(32);
        let code_verifier = generate_pkce_code_verifier();
        let code_challenge = pkce_code_challenge(&code_verifier);

        let now = current_unix_secs();

        // Purge stale pending states older than 10 minutes
        self.pending_states
            .retain(|_, pa| now - pa.created_at < PENDING_STATE_TTL_SECS);

        self.pending_states.insert(
            state.clone(),
            PendingAuth {
                state: state.clone(),
                nonce: nonce.clone(),
                code_verifier: code_verifier.clone(),
                created_at: now,
                redirect_after,
            },
        );

        let scopes = self.config.scopes.join(" ");
        let url = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
            discovery.authorization_endpoint,
            urlencoded(&self.config.client_id),
            urlencoded(&self.config.redirect_uri),
            urlencoded(&scopes),
            urlencoded(&state),
            urlencoded(&nonce),
            urlencoded(&code_challenge),
        );

        Ok(url)
    }

    pub fn has_pending_state(&self, state: &str) -> bool {
        self.pending_states.contains_key(state)
    }

    /// Exchange an authorization code for tokens and create a session.
    pub fn exchange_code(
        &mut self,
        code: &str,
        state: &str,
    ) -> Result<(SsoSession, Option<String>), String> {
        let pending = self
            .pending_states
            .remove(state)
            .ok_or("Invalid or expired state parameter")?;

        let now = current_unix_secs();

        // Expire states older than 10 minutes
        if now - pending.created_at > PENDING_STATE_TTL_SECS {
            return Err("Authorization state expired".into());
        }

        let discovery = self.discovery.clone().ok_or("OIDC not discovered")?;

        // Token exchange
        let form = format!(
            "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&client_secret={}&code_verifier={}",
            urlencoded(code),
            urlencoded(&self.config.redirect_uri),
            urlencoded(&self.config.client_id),
            urlencoded(&self.config.client_secret),
            urlencoded(&pending.code_verifier),
        );

        let token_resp: TokenResponse = ureq::post(&discovery.token_endpoint)
            .set("Content-Type", "application/x-www-form-urlencoded")
            .send_string(&form)
            .map_err(|e| format!("Token exchange failed: {e}"))?
            .into_json()
            .map_err(|e| format!("Token parse failed: {e}"))?;
        let id_token = self.validate_id_token(&discovery, &token_resp, &pending)?;

        // Fetch user info
        let user_info: OidcUserInfo = ureq::get(&discovery.userinfo_endpoint)
            .set(
                "Authorization",
                &format!("Bearer {}", token_resp.access_token),
            )
            .call()
            .map_err(|e| format!("UserInfo fetch failed: {e}"))?
            .into_json()
            .map_err(|e| format!("UserInfo parse failed: {e}"))?;
        if user_info.sub != id_token.claims.sub {
            return Err("OIDC userinfo subject did not match validated id_token".into());
        }

        // Determine Wardex role from claims
        let role = self.resolve_role(&user_info);

        let session_id = generate_random_string(48);
        let expires_in = token_resp.expires_in.unwrap_or(DEFAULT_TOKEN_EXPIRY_SECS);

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
        Ok((session, pending.redirect_after))
    }

    /// Validate a session ID and return the session if valid.
    pub fn validate_session(&self, session_id: &str) -> Option<&SsoSession> {
        let session = self.sessions.get(session_id)?;
        let now = current_unix_secs();
        if now > session.expires_at {
            return None;
        }
        Some(session)
    }

    /// Purge expired sessions and stale pending states.
    pub fn cleanup_expired(&mut self) {
        let now = current_unix_secs();
        self.sessions.retain(|_, s| s.expires_at > now);
        self.pending_states
            .retain(|_, pa| now - pa.created_at < PENDING_STATE_TTL_SECS);
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
        self.sessions
            .values()
            .filter(|s| s.expires_at > now)
            .count()
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

    fn validate_id_token(
        &mut self,
        discovery: &OidcDiscovery,
        token_resp: &TokenResponse,
        pending: &PendingAuth,
    ) -> Result<TokenData<OidcIdTokenClaims>, String> {
        let id_token = token_resp
            .id_token
            .as_deref()
            .ok_or("OIDC token response missing id_token")?;
        let header =
            decode_header(id_token).map_err(|e| format!("OIDC id_token header invalid: {e}"))?;
        let expected_issuer = normalize_issuer(&discovery.issuer);
        let configured_issuer = normalize_issuer(&self.config.issuer);
        if configured_issuer != expected_issuer {
            return Err("OIDC discovery issuer did not match configured issuer".into());
        }
        let expected_audience = self
            .config
            .audience
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(self.config.client_id.as_str())
            .to_string();
        let jwks = self.refresh_jwks(discovery)?;
        validate_id_token_with_jwks(
            jwks,
            id_token,
            &header,
            expected_issuer.as_str(),
            expected_audience.as_str(),
            pending.nonce.as_str(),
        )
    }

    fn refresh_jwks(&mut self, discovery: &OidcDiscovery) -> Result<&JwkSet, String> {
        let jwks: JwkSet = ureq::get(&discovery.jwks_uri)
            .call()
            .map_err(|e| format!("OIDC JWKS fetch failed: {e}"))?
            .into_json()
            .map_err(|e| format!("OIDC JWKS parse failed: {e}"))?;
        self.jwks_cache = Some(CachedJwks { jwks });
        self.jwks_cache
            .as_ref()
            .map(|cached| &cached.jwks)
            .ok_or_else(|| "OIDC JWKS cache was not updated".to_string())
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

impl OneOrManyStrings {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::One(value) => value == expected,
            Self::Many(values) => values.iter().any(|value| value == expected),
        }
    }

    fn requires_authorized_party(&self) -> bool {
        matches!(self, Self::Many(values) if values.len() > 1)
    }
}

fn validate_id_token_with_jwks(
    jwks: &JwkSet,
    id_token: &str,
    header: &Header,
    expected_issuer: &str,
    expected_audience: &str,
    expected_nonce: &str,
) -> Result<TokenData<OidcIdTokenClaims>, String> {
    let jwk = select_signing_jwk(jwks, header)?;
    let decoding_key = DecodingKey::from_jwk(jwk)
        .map_err(|e| format!("OIDC signing key could not be decoded from JWKS: {e}"))?;
    let mut validation = Validation::new(header.alg);
    validation.validate_nbf = true;
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation.set_issuer(&[expected_issuer]);
    validation.set_audience(&[expected_audience]);
    let token = decode::<OidcIdTokenClaims>(id_token, &decoding_key, &validation)
        .map_err(|e| format!("OIDC id_token validation failed: {e}"))?;
    validate_id_token_claims(
        &token.claims,
        expected_issuer,
        expected_audience,
        expected_nonce,
    )?;
    Ok(token)
}

fn select_signing_jwk<'a>(jwks: &'a JwkSet, header: &Header) -> Result<&'a Jwk, String> {
    let jwk = match header.kid.as_deref() {
        Some(kid) => jwks
            .keys
            .iter()
            .find(|candidate| candidate.common.key_id.as_deref() == Some(kid))
            .ok_or_else(|| format!("OIDC JWKS did not contain signing key '{kid}'"))?,
        None => match jwks.keys.as_slice() {
            [candidate] => candidate,
            _ => {
                return Err(
                    "OIDC id_token header omitted kid and JWKS contains multiple keys".into(),
                );
            }
        },
    };
    validate_jwk_for_id_token(jwk, header)?;
    Ok(jwk)
}

fn validate_jwk_for_id_token(jwk: &Jwk, header: &Header) -> Result<(), String> {
    if let Some(public_key_use) = &jwk.common.public_key_use
        && !matches!(public_key_use, PublicKeyUse::Signature)
    {
        return Err("OIDC JWKS signing key is not marked for signature verification".into());
    }
    if let Some(key_operations) = &jwk.common.key_operations
        && !key_operations
            .iter()
            .any(|operation| matches!(operation, KeyOperations::Verify))
    {
        return Err("OIDC JWKS signing key does not allow verify operations".into());
    }
    if let Some(key_algorithm) = jwk.common.key_algorithm {
        let key_algorithm = key_algorithm.to_string();
        let header_algorithm = format!("{:?}", header.alg);
        if key_algorithm != header_algorithm {
            return Err("OIDC JWKS signing key algorithm did not match id_token header".into());
        }
    }
    Ok(())
}

fn validate_id_token_claims(
    claims: &OidcIdTokenClaims,
    expected_issuer: &str,
    expected_audience: &str,
    expected_nonce: &str,
) -> Result<(), String> {
    if claims.nonce.as_deref() != Some(expected_nonce) {
        return Err("OIDC id_token nonce did not match the login request".into());
    }
    if normalize_issuer(&claims.iss) != expected_issuer {
        return Err("OIDC id_token issuer did not match discovery issuer".into());
    }
    if claims.sub.trim().is_empty() {
        return Err("OIDC id_token subject claim was empty".into());
    }
    if !claims.aud.contains(expected_audience) {
        return Err("OIDC id_token audience did not include the configured client".into());
    }
    if claims.aud.requires_authorized_party() && claims.azp.as_deref() != Some(expected_audience) {
        return Err("OIDC id_token authorized party did not match the configured client".into());
    }
    if claims.exp == 0 {
        return Err("OIDC id_token expiration claim was invalid".into());
    }
    let issued_at = claims
        .iat
        .ok_or("OIDC id_token issued-at claim was missing")?;
    if issued_at == 0 {
        return Err("OIDC id_token issued-at claim was invalid".into());
    }
    let now = current_unix_secs();
    if issued_at > now + 60 {
        return Err("OIDC id_token issued-at claim was in the future".into());
    }
    if claims.exp <= issued_at {
        return Err("OIDC id_token expiration was not after issued-at".into());
    }
    if claims.nbf.is_some_and(|not_before| not_before > claims.exp) {
        return Err("OIDC id_token not-before claim was after expiration".into());
    }
    Ok(())
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
    let mut bytes = vec![0u8; len.div_ceil(2)];
    OsRng.fill_bytes(&mut bytes);
    let encoded = hex::encode(bytes);
    encoded.chars().take(len).collect()
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn generate_pkce_code_verifier() -> String {
    let mut bytes = [0u8; 64];
    OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn pkce_code_challenge(code_verifier: &str) -> String {
    let digest = Sha256::digest(code_verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

fn normalize_issuer(value: &str) -> String {
    value.trim().trim_end_matches('/').to_string()
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
    use jsonwebtoken::jwk::{Jwk, KeyOperations, PublicKeyUse};
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use std::io::{Read, Write};
    use std::thread::JoinHandle;

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

    fn test_discovery(jwks_uri: String) -> OidcDiscovery {
        OidcDiscovery {
            issuer: test_config().issuer,
            authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth".into(),
            token_endpoint: "https://oauth2.googleapis.com/token".into(),
            userinfo_endpoint: "https://openidconnect.googleapis.com/v1/userinfo".into(),
            jwks_uri,
            end_session_endpoint: None,
            response_types_supported: vec!["code".into()],
            scopes_supported: vec!["openid".into(), "profile".into(), "email".into()],
        }
    }

    fn test_pending(nonce: &str) -> PendingAuth {
        PendingAuth {
            state: "state-1".into(),
            nonce: nonce.into(),
            code_verifier: "verifier".into(),
            created_at: current_unix_secs(),
            redirect_after: None,
        }
    }

    fn test_token_response(id_token: String) -> TokenResponse {
        TokenResponse {
            access_token: "access-token".into(),
            token_type: "Bearer".into(),
            id_token: Some(id_token),
            refresh_token: None,
            expires_in: Some(3600),
            scope: Some("openid profile email".into()),
        }
    }

    fn hmac_jwk(kid: &str, secret: &[u8]) -> Jwk {
        let encoding_key = EncodingKey::from_secret(secret);
        let mut jwk = Jwk::from_encoding_key(&encoding_key, Algorithm::HS256)
            .expect("test hmac jwk should encode");
        jwk.common.key_id = Some(kid.into());
        jwk.common.public_key_use = Some(PublicKeyUse::Signature);
        jwk.common.key_operations = Some(vec![KeyOperations::Verify]);
        jwk
    }

    fn valid_id_token_claims(nonce: &str) -> serde_json::Value {
        let now = current_unix_secs();
        serde_json::json!({
            "iss": test_config().issuer,
            "sub": "oidc-user-1",
            "aud": test_config().client_id,
            "exp": now + 3600,
            "iat": now,
            "nonce": nonce,
        })
    }

    fn encode_id_token(kid: &str, secret: &[u8], claims: serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(kid.into());
        encode(&header, &claims, &EncodingKey::from_secret(secret))
            .expect("test id token should encode")
    }

    fn spawn_jwks_server(jwks: JwkSet) -> (String, JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind jwks server");
        let port = listener.local_addr().expect("jwks server addr").port();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept jwks request");
            let mut request_bytes = Vec::new();
            let mut buffer = [0u8; 1024];
            loop {
                let read = stream.read(&mut buffer).expect("read jwks request");
                if read == 0 {
                    break;
                }
                request_bytes.extend_from_slice(&buffer[..read]);
                if request_bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let body = serde_json::to_string(&jwks).expect("serialize jwks");
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream
                .write_all(response.as_bytes())
                .expect("write jwks response");
            stream.flush().expect("flush jwks response");
        });
        (format!("http://127.0.0.1:{port}/jwks"), handle)
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
    fn authorize_url_includes_pkce_parameters() {
        let mut provider = OidcProvider::new(test_config());
        provider.discovery = Some(OidcDiscovery {
            issuer: "https://accounts.google.com".into(),
            authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth".into(),
            token_endpoint: "https://oauth2.googleapis.com/token".into(),
            userinfo_endpoint: "https://openidconnect.googleapis.com/v1/userinfo".into(),
            jwks_uri: "https://www.googleapis.com/oauth2/v3/certs".into(),
            end_session_endpoint: None,
            response_types_supported: vec!["code".into()],
            scopes_supported: vec!["openid".into(), "profile".into(), "email".into()],
        });

        let url = provider
            .authorize_url(Some("/workbench".into()))
            .expect("authorize url");
        assert!(url.contains("code_challenge="));
        assert!(url.contains("code_challenge_method=S256"));

        let query = url.split('?').nth(1).expect("authorize url query");
        let params = query
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .collect::<HashMap<_, _>>();
        let state = params.get("state").expect("state");
        let pending = provider.pending_states.get(*state).expect("pending state");
        assert_eq!(pending.state, *state);
        assert_eq!(
            params.get("code_challenge").copied(),
            Some(pkce_code_challenge(&pending.code_verifier).as_str())
        );
        assert!(pending.nonce.len() >= 32);
        assert!(pending.code_verifier.len() >= 43);
    }

    #[test]
    fn exchange_code_rejects_invalid_state() {
        let mut provider = OidcProvider::new(test_config());
        assert!(provider.exchange_code("code", "bad-state").is_err());
    }

    #[test]
    fn id_token_validation_refreshes_jwks_cache_for_rotated_key() {
        let old_secret = b"old-oidc-signing-secret";
        let new_secret = b"new-oidc-signing-secret";
        let new_jwks = JwkSet {
            keys: vec![hmac_jwk("new-key", new_secret)],
        };
        let (jwks_uri, handle) = spawn_jwks_server(new_jwks);
        let mut provider = OidcProvider::new(test_config());
        provider.jwks_cache = Some(CachedJwks {
            jwks: JwkSet {
                keys: vec![hmac_jwk("old-key", old_secret)],
            },
        });

        let nonce = "nonce-rotated";
        let id_token = encode_id_token("new-key", new_secret, valid_id_token_claims(nonce));
        let validated = provider.validate_id_token(
            &test_discovery(jwks_uri),
            &test_token_response(id_token),
            &test_pending(nonce),
        );

        assert!(validated.is_ok(), "rotated JWKS key should validate");
        let cached = provider.jwks_cache.as_ref().expect("refreshed jwks cache");
        assert_eq!(
            cached.jwks.keys[0].common.key_id.as_deref(),
            Some("new-key")
        );
        handle.join().expect("jwks server should finish");
    }

    #[test]
    fn id_token_validation_rejects_revoked_cached_signing_key() {
        let old_secret = b"old-oidc-signing-secret";
        let new_secret = b"new-oidc-signing-secret";
        let new_jwks = JwkSet {
            keys: vec![hmac_jwk("new-key", new_secret)],
        };
        let (jwks_uri, handle) = spawn_jwks_server(new_jwks);
        let mut provider = OidcProvider::new(test_config());
        provider.jwks_cache = Some(CachedJwks {
            jwks: JwkSet {
                keys: vec![hmac_jwk("old-key", old_secret)],
            },
        });

        let nonce = "nonce-revoked";
        let id_token = encode_id_token("old-key", old_secret, valid_id_token_claims(nonce));
        let error = provider
            .validate_id_token(
                &test_discovery(jwks_uri),
                &test_token_response(id_token),
                &test_pending(nonce),
            )
            .expect_err("revoked cached JWKS key should fail closed");

        assert!(error.contains("OIDC JWKS did not contain signing key 'old-key'"));
        handle.join().expect("jwks server should finish");
    }

    #[test]
    fn id_token_validation_rejects_missing_issued_at_claim() {
        let secret = b"oidc-signing-secret";
        let nonce = "nonce-missing-iat";
        let mut claims = valid_id_token_claims(nonce);
        claims.as_object_mut().expect("claims object").remove("iat");
        let id_token = encode_id_token("key-1", secret, claims);
        let header = decode_header(&id_token).expect("id token header");
        let jwks = JwkSet {
            keys: vec![hmac_jwk("key-1", secret)],
        };

        let error = validate_id_token_with_jwks(
            &jwks,
            &id_token,
            &header,
            &test_config().issuer,
            &test_config().client_id,
            nonce,
        )
        .expect_err("missing iat should be rejected");

        assert!(error.contains("issued-at claim was missing"));
    }

    #[test]
    fn id_token_validation_requires_azp_for_multi_audience_tokens() {
        let secret = b"oidc-signing-secret";
        let nonce = "nonce-azp";
        let mut claims = valid_id_token_claims(nonce);
        claims["aud"] = serde_json::json!([test_config().client_id, "another-client"]);
        let id_token = encode_id_token("key-1", secret, claims);
        let header = decode_header(&id_token).expect("id token header");
        let jwks = JwkSet {
            keys: vec![hmac_jwk("key-1", secret)],
        };

        let error = validate_id_token_with_jwks(
            &jwks,
            &id_token,
            &header,
            &test_config().issuer,
            &test_config().client_id,
            nonce,
        )
        .expect_err("multi-audience token without azp should be rejected");

        assert!(error.contains("authorized party did not match"));
    }

    #[test]
    fn id_token_validation_rejects_non_signature_jwks_key_use() {
        let secret = b"oidc-signing-secret";
        let nonce = "nonce-key-use";
        let id_token = encode_id_token("key-1", secret, valid_id_token_claims(nonce));
        let header = decode_header(&id_token).expect("id token header");
        let mut jwk = hmac_jwk("key-1", secret);
        jwk.common.public_key_use = Some(PublicKeyUse::Encryption);
        let jwks = JwkSet { keys: vec![jwk] };

        let error = validate_id_token_with_jwks(
            &jwks,
            &id_token,
            &header,
            &test_config().issuer,
            &test_config().client_id,
            nonce,
        )
        .expect_err("encryption-only JWKS key should be rejected");

        assert!(error.contains("not marked for signature verification"));
    }

    #[test]
    fn cleanup_expired_removes_old_sessions() {
        let mut provider = OidcProvider::new(test_config());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Insert an already-expired session
        provider.sessions.insert(
            "expired-session".into(),
            SsoSession {
                session_id: "expired-session".into(),
                user_info: OidcUserInfo {
                    sub: "u1".into(),
                    name: None,
                    email: None,
                    email_verified: None,
                    preferred_username: None,
                    roles: vec![],
                    groups: vec![],
                },
                wardex_role: "analyst".into(),
                created_at: now - 7200,
                expires_at: now - 3600, // expired 1 hour ago
                refresh_token: None,
                provider: "oidc".into(),
            },
        );
        // Insert a valid session
        provider.sessions.insert(
            "valid-session".into(),
            SsoSession {
                session_id: "valid-session".into(),
                user_info: OidcUserInfo {
                    sub: "u2".into(),
                    name: None,
                    email: None,
                    email_verified: None,
                    preferred_username: None,
                    roles: vec![],
                    groups: vec![],
                },
                wardex_role: "admin".into(),
                created_at: now,
                expires_at: now + 3600,
                refresh_token: None,
                provider: "oidc".into(),
            },
        );

        assert_eq!(provider.sessions.len(), 2);
        provider.cleanup_expired();
        assert_eq!(provider.sessions.len(), 1);
        assert!(provider.sessions.contains_key("valid-session"));
        assert!(!provider.sessions.contains_key("expired-session"));
    }

    #[test]
    fn expired_session_not_validated() {
        let mut provider = OidcProvider::new(test_config());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        provider.sessions.insert(
            "expired".into(),
            SsoSession {
                session_id: "expired".into(),
                user_info: OidcUserInfo {
                    sub: "u1".into(),
                    name: None,
                    email: None,
                    email_verified: None,
                    preferred_username: None,
                    roles: vec![],
                    groups: vec![],
                },
                wardex_role: "analyst".into(),
                created_at: now - 7200,
                expires_at: now - 1, // just expired
                refresh_token: None,
                provider: "oidc".into(),
            },
        );
        assert!(provider.validate_session("expired").is_none());
    }

    #[test]
    fn role_mapping_group_fallback() {
        let mut config = test_config();
        config
            .role_mapping
            .insert("SecurityOps".into(), "admin".into());
        let provider = OidcProvider::new(config);

        let user = OidcUserInfo {
            sub: "u1".into(),
            name: None,
            email: None,
            email_verified: None,
            preferred_username: None,
            roles: vec!["UnknownRole".into()],
            groups: vec!["SecurityOps".into()], // should match via group
        };
        assert_eq!(provider.resolve_role(&user), "admin");
    }

    #[test]
    fn status_reflects_state() {
        let provider = OidcProvider::new(test_config());
        let status = provider.status();
        assert!(status.oidc_enabled);
        assert!(!status.discovered);
        assert_eq!(status.active_sessions, 0);
        assert!(status.auto_provision);
    }

    #[test]
    fn sso_session_serialization() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let session = SsoSession {
            session_id: "s1".into(),
            user_info: OidcUserInfo {
                sub: "u1".into(),
                name: Some("Test User".into()),
                email: Some("test@example.com".into()),
                email_verified: Some(true),
                preferred_username: None,
                roles: vec!["admin".into()],
                groups: vec![],
            },
            wardex_role: "admin".into(),
            created_at: now,
            expires_at: now + 3600,
            refresh_token: Some("refresh-tok".into()),
            provider: "oidc".into(),
        };
        let json = serde_json::to_string(&session).unwrap();
        let back: SsoSession = serde_json::from_str(&json).unwrap();
        assert_eq!(back.session_id, "s1");
        assert_eq!(back.user_info.email.unwrap(), "test@example.com");
        assert_eq!(back.wardex_role, "admin");
    }

    #[test]
    fn oidc_config_serialization_hides_secret() {
        let config = test_config();
        let json = serde_json::to_string(&config).unwrap();
        assert!(!json.contains("test-secret"));
    }

    #[test]
    fn constants_have_expected_values() {
        assert_eq!(PENDING_STATE_TTL_SECS, 600);
        assert_eq!(DEFAULT_TOKEN_EXPIRY_SECS, 3600);
    }
}
