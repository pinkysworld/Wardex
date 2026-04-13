// ── Secrets Management ────────────────────────────────────────────────────────
//
// Centralised secret resolution for Wardex configurations.
// Supports:
//   1. Environment variable expansion: ${ENV_VAR_NAME}
//   2. File-based secrets:             file:///run/secrets/my_key
//   3. HashiCorp Vault (KV v2):        vault://secret/data/wardex/api_key
//
// Usage:
//   let resolver = SecretsResolver::new(vault_config);
//   let plaintext = resolver.resolve("${API_KEY}")?;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

// ── Configuration ────────────────────────────────────────────────────────────

/// Vault integration configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    pub address: String,
    #[serde(skip_serializing)]
    pub token: String,
    #[serde(default = "default_mount")]
    pub mount: String,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_ttl")]
    pub cache_ttl_secs: u64,
}

fn default_mount() -> String {
    "secret".into()
}
fn default_ttl() -> u64 {
    300
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            address: "http://127.0.0.1:8200".into(),
            token: String::new(),
            mount: "secret".into(),
            namespace: None,
            enabled: false,
            cache_ttl_secs: 300,
        }
    }
}

/// Secrets management configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecretsConfig {
    #[serde(default)]
    pub vault: VaultConfig,
    #[serde(default)]
    pub env_prefix: Option<String>,
    #[serde(default)]
    pub secrets_dir: Option<String>,
}

// ── Resolver ─────────────────────────────────────────────────────────────────

/// Resolves secret references to their plaintext values.
#[derive(Debug)]
pub struct SecretsResolver {
    config: SecretsConfig,
    cache: Mutex<HashMap<String, CachedSecret>>,
    env_overrides: HashMap<String, String>,
}

#[derive(Debug, Clone)]
struct CachedSecret {
    value: String,
    fetched_at: u64,
}

impl SecretsResolver {
    pub fn new(config: SecretsConfig) -> Self {
        Self {
            config,
            cache: Mutex::new(HashMap::new()),
            env_overrides: HashMap::new(),
        }
    }

    /// Resolve a secret reference to its plaintext value.
    ///
    /// Supported formats:
    /// - `${VAR_NAME}` → reads from environment
    /// - `file:///path/to/file` → reads file contents (trimmed)
    /// - `vault://mount/path#key` → reads from Vault KV v2
    /// - Anything else → returned as-is (literal value)
    pub fn resolve(&self, reference: &str) -> Result<String, String> {
        let trimmed = reference.trim();

        // Environment variable: ${VAR_NAME}
        if trimmed.starts_with("${") && trimmed.ends_with('}') {
            let var_name = &trimmed[2..trimmed.len() - 1];
            return self.resolve_env(var_name);
        }

        // File-based secret: file:///path
        if let Some(path) = trimmed.strip_prefix("file://") {
            return self.resolve_file(path);
        }

        // Vault secret: vault://path#key
        if let Some(vault_ref) = trimmed.strip_prefix("vault://") {
            return self.resolve_vault(vault_ref);
        }

        // Literal value
        Ok(trimmed.to_string())
    }

    /// Resolve all ${...} placeholders in a string, leaving the rest intact.
    pub fn expand_string(&self, input: &str) -> Result<String, String> {
        let mut result = String::with_capacity(input.len());
        let mut chars = input.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '$' && chars.peek() == Some(&'{') {
                chars.next(); // consume '{'
                let mut var_name = String::new();
                let mut found_close = false;
                for c2 in chars.by_ref() {
                    if c2 == '}' {
                        found_close = true;
                        break;
                    }
                    var_name.push(c2);
                }
                if found_close {
                    let value = self.resolve_env(&var_name)?;
                    result.push_str(&value);
                } else {
                    result.push_str("${");
                    result.push_str(&var_name);
                }
            } else {
                result.push(c);
            }
        }

        Ok(result)
    }

    /// Resolve a map of config values, expanding any secret references.
    pub fn resolve_map(&self, map: &HashMap<String, String>) -> Result<HashMap<String, String>, String> {
        let mut resolved = HashMap::new();
        for (key, value) in map {
            resolved.insert(key.clone(), self.resolve(value)?);
        }
        Ok(resolved)
    }

    fn resolve_env(&self, var_name: &str) -> Result<String, String> {
        let effective_name = if let Some(prefix) = &self.config.env_prefix {
            format!("{prefix}{var_name}")
        } else {
            var_name.to_string()
        };
        // Check overrides first (used in tests)
        if let Some(val) = self.env_overrides.get(&effective_name) {
            return Ok(val.clone());
        }
        std::env::var(&effective_name)
            .map_err(|_| format!("Environment variable '{effective_name}' not set"))
    }

    fn resolve_file(&self, path: &str) -> Result<String, String> {
        // Prevent path traversal
        let canonical = std::fs::canonicalize(path)
            .map_err(|e| format!("Secret file not found: {path}: {e}"))?;

        if let Some(dir) = &self.config.secrets_dir {
            let base = std::fs::canonicalize(dir)
                .map_err(|e| format!("Secrets dir not found: {dir}: {e}"))?;
            if !canonical.starts_with(&base) {
                return Err(format!(
                    "Secret file {path} is outside allowed secrets directory {dir}"
                ));
            }
        }

        std::fs::read_to_string(&canonical)
            .map(|s| s.trim().to_string())
            .map_err(|e| format!("Failed to read secret file {path}: {e}"))
    }

    fn resolve_vault(&self, vault_ref: &str) -> Result<String, String> {
        if !self.config.vault.enabled {
            return Err("Vault not enabled".into());
        }

        // Check cache
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if let Ok(cache) = self.cache.lock() {
            if let Some(cached) = cache.get(vault_ref) {
                if now - cached.fetched_at < self.config.vault.cache_ttl_secs {
                    return Ok(cached.value.clone());
                }
            }
        }

        // Parse vault://mount/path#key
        let (path, key) = match vault_ref.split_once('#') {
            Some((p, k)) => (p, Some(k)),
            None => (vault_ref, None),
        };

        let url = format!(
            "{}/v1/{}/data/{}",
            self.config.vault.address.trim_end_matches('/'),
            self.config.vault.mount,
            path
        );

        let mut req = ureq::get(&url).set("X-Vault-Token", &self.config.vault.token);

        if let Some(ns) = &self.config.vault.namespace {
            req = req.set("X-Vault-Namespace", ns);
        }

        let resp: serde_json::Value = req
            .call()
            .map_err(|e| format!("Vault request failed: {e}"))?
            .into_json()
            .map_err(|e| format!("Vault response parse failed: {e}"))?;

        let data = resp
            .get("data")
            .and_then(|d| d.get("data"))
            .ok_or("Vault response missing data field")?;

        let value = if let Some(k) = key {
            data.get(k)
                .and_then(|v| v.as_str())
                .ok_or(format!("Key '{k}' not found in Vault secret"))?
                .to_string()
        } else {
            // Return first value if no key specified
            data.as_object()
                .and_then(|obj| obj.values().next())
                .and_then(|v| v.as_str())
                .ok_or("Empty Vault secret")?
                .to_string()
        };

        // Update cache
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(
                vault_ref.to_string(),
                CachedSecret {
                    value: value.clone(),
                    fetched_at: now,
                },
            );
        }

        Ok(value)
    }

    /// Return resolver status for health checks.
    pub fn status(&self) -> SecretsStatus {
        let cache_size = self.cache.lock().map(|c| c.len()).unwrap_or(0);
        SecretsStatus {
            vault_enabled: self.config.vault.enabled,
            vault_address: self.config.vault.address.clone(),
            cache_size,
            env_prefix: self.config.env_prefix.clone(),
            secrets_dir: self.config.secrets_dir.clone(),
        }
    }
}

/// Secrets system status summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsStatus {
    pub vault_enabled: bool,
    pub vault_address: String,
    pub cache_size: usize,
    pub env_prefix: Option<String>,
    pub secrets_dir: Option<String>,
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn default_resolver() -> SecretsResolver {
        SecretsResolver::new(SecretsConfig::default())
    }

    #[test]
    fn resolve_literal_value() {
        let r = default_resolver();
        assert_eq!(r.resolve("plain-text").unwrap(), "plain-text");
        assert_eq!(r.resolve("12345").unwrap(), "12345");
    }

    #[test]
    fn resolve_env_variable() {
        let mut r = default_resolver();
        r.env_overrides.insert("WARDEX_TEST_SECRET_42".into(), "hunter2".into());
        assert_eq!(r.resolve("${WARDEX_TEST_SECRET_42}").unwrap(), "hunter2");
    }

    #[test]
    fn resolve_env_with_prefix() {
        let mut r = SecretsResolver::new(SecretsConfig {
            env_prefix: Some("WDX_".into()),
            ..Default::default()
        });
        r.env_overrides.insert("WDX_API_KEY".into(), "secret123".into());
        assert_eq!(r.resolve("${API_KEY}").unwrap(), "secret123");
    }

    #[test]
    fn resolve_missing_env() {
        let r = default_resolver();
        assert!(r.resolve("${NONEXISTENT_VAR_XYZ_123}").is_err());
    }

    #[test]
    fn expand_string_mixed() {
        let mut r = default_resolver();
        r.env_overrides.insert("WARDEX_HOST_TEST".into(), "localhost".into());
        r.env_overrides.insert("WARDEX_PORT_TEST".into(), "8080".into());
        let result = r
            .expand_string("http://${WARDEX_HOST_TEST}:${WARDEX_PORT_TEST}/api")
            .unwrap();
        assert_eq!(result, "http://localhost:8080/api");
    }

    #[test]
    fn resolve_file_not_found() {
        let r = default_resolver();
        assert!(r.resolve("file:///nonexistent/path/secret.txt").is_err());
    }

    #[test]
    fn vault_disabled_by_default() {
        let r = default_resolver();
        assert!(r.resolve("vault://secret/wardex/api_key").is_err());
    }

    #[test]
    fn resolve_map_all_types() {
        let mut r = default_resolver();
        r.env_overrides.insert("WARDEX_TEST_MAP_KEY".into(), "resolved_value".into());
        let mut map = HashMap::new();
        map.insert("literal".into(), "plain".into());
        map.insert("env".into(), "${WARDEX_TEST_MAP_KEY}".into());

        let resolved = r.resolve_map(&map).unwrap();
        assert_eq!(resolved["literal"], "plain");
        assert_eq!(resolved["env"], "resolved_value");
    }

    #[test]
    fn status_report() {
        let r = default_resolver();
        let status = r.status();
        assert!(!status.vault_enabled);
        assert_eq!(status.cache_size, 0);
    }
}
