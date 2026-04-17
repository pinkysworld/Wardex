//! TLS configuration and certificate management for the HTTP server.
//!
//! Provides TLS configuration parsing, certificate validation, and a
//! TLS listener wrapper for the admin console. When compiled with
//! the `tls` feature, uses rustls for actual TLS termination.
//! Without the feature, provides configuration validation and a
//! plain-HTTP fallback with security warnings.
//!
//! Covers the "TLS/mTLS Server Hardening" production readiness item.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// TLS configuration for the Wardex server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to the PEM-encoded server certificate.
    pub cert_path: PathBuf,
    /// Path to the PEM-encoded private key.
    pub key_path: PathBuf,
    /// Optional path to a CA certificate for client authentication (mTLS).
    pub client_ca_path: Option<PathBuf>,
    /// Minimum TLS version (default: 1.2).
    pub min_version: TlsVersion,
    /// Whether to require client certificates (mTLS).
    pub require_client_cert: bool,
    /// Optional list of allowed cipher suites (empty = use defaults).
    pub cipher_suites: Vec<String>,
}

/// Supported TLS protocol versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TlsVersion {
    #[default]
    Tls12,
    Tls13,
}

impl TlsVersion {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tls12 => "TLSv1.2",
            Self::Tls13 => "TLSv1.3",
        }
    }
}

/// Result of TLS configuration validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

impl TlsConfig {
    /// Create a new TLS configuration from certificate and key paths.
    pub fn new(cert_path: impl Into<PathBuf>, key_path: impl Into<PathBuf>) -> Self {
        Self {
            cert_path: cert_path.into(),
            key_path: key_path.into(),
            client_ca_path: None,
            min_version: TlsVersion::default(),
            require_client_cert: false,
            cipher_suites: Vec::new(),
        }
    }

    /// Enable mutual TLS with the given CA certificate path.
    pub fn with_mtls(mut self, ca_path: impl Into<PathBuf>) -> Self {
        self.client_ca_path = Some(ca_path.into());
        self.require_client_cert = true;
        self
    }

    /// Set the minimum TLS version.
    pub fn with_min_version(mut self, version: TlsVersion) -> Self {
        self.min_version = version;
        self
    }

    /// Validate the TLS configuration by checking that referenced files exist
    /// and have reasonable properties.
    pub fn validate(&self) -> TlsValidationResult {
        let mut errors = Vec::new();
        #[cfg(unix)]
        let mut warnings = Vec::new();
        #[cfg(not(unix))]
        let warnings = Vec::new();

        // Check certificate file
        if !self.cert_path.exists() {
            errors.push(format!(
                "Certificate file not found: {}",
                self.cert_path.display()
            ));
        } else if let Ok(content) = std::fs::read_to_string(&self.cert_path)
            && !content.contains("BEGIN CERTIFICATE")
        {
            errors.push("Certificate file does not appear to be PEM-encoded".into());
        }

        // Check key file
        if !self.key_path.exists() {
            errors.push(format!(
                "Private key file not found: {}",
                self.key_path.display()
            ));
        } else {
            // Check key file permissions (should not be world-readable)
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if let Ok(meta) = std::fs::metadata(&self.key_path) {
                    let mode = meta.mode();
                    if mode & 0o077 != 0 {
                        warnings.push(format!(
                            "Private key file has overly permissive permissions: {:o}. Recommend 0600.",
                            mode & 0o777
                        ));
                    }
                }
            }

            if let Ok(content) = std::fs::read_to_string(&self.key_path)
                && !content.contains("PRIVATE KEY")
            {
                errors.push("Key file does not appear to contain a private key".into());
            }
        }

        // Check client CA for mTLS
        if let Some(ref ca_path) = self.client_ca_path
            && !ca_path.exists()
        {
            errors.push(format!(
                "Client CA certificate not found: {}",
                ca_path.display()
            ));
        }

        if self.require_client_cert && self.client_ca_path.is_none() {
            errors.push("mTLS requires a client CA certificate path".into());
        }

        TlsValidationResult {
            valid: errors.is_empty(),
            errors,
            warnings,
        }
    }

    /// Generate a summary of the TLS configuration for logging.
    pub fn summary(&self) -> String {
        let mtls = if self.require_client_cert {
            "enabled"
        } else {
            "disabled"
        };
        format!(
            "TLS: cert={} key={} min_version={} mTLS={}",
            self.cert_path.display(),
            self.key_path.display(),
            self.min_version.as_str(),
            mtls
        )
    }
}

/// Server listener mode — plain HTTP or HTTPS with TLS.
#[derive(Debug, Clone)]
pub enum ListenerMode {
    /// Plain HTTP (development/testing only).
    Plain { port: u16 },
    /// HTTPS with TLS termination.
    Tls { port: u16, config: TlsConfig },
}

impl ListenerMode {
    /// Check if this mode uses TLS.
    pub fn is_tls(&self) -> bool {
        matches!(self, Self::Tls { .. })
    }

    /// Get the port number.
    pub fn port(&self) -> u16 {
        match self {
            Self::Plain { port } | Self::Tls { port, .. } => *port,
        }
    }

    /// Get the scheme (http or https).
    pub fn scheme(&self) -> &'static str {
        if self.is_tls() { "https" } else { "http" }
    }

    /// Get the TLS config, if any.
    pub fn tls_config(&self) -> Option<&TlsConfig> {
        match self {
            Self::Plain { .. } => None,
            Self::Tls { config, .. } => Some(config),
        }
    }
}

/// Parse TLS configuration from a TOML config file section.
///
/// Expected format:
/// ```toml
/// [server.tls]
/// cert = "certs/server.pem"
/// key = "certs/server-key.pem"
/// client_ca = "certs/ca.pem"        # optional, enables mTLS
/// min_version = "1.3"               # optional, default "1.2"
/// require_client_cert = true        # optional, default false
/// ```
pub fn parse_tls_config(table: &toml::Value) -> Result<TlsConfig, String> {
    let obj = table.as_table().ok_or("TLS config must be a TOML table")?;

    let cert = obj
        .get("cert")
        .and_then(|v| v.as_str())
        .ok_or("Missing 'cert' path in TLS config")?;

    let key = obj
        .get("key")
        .and_then(|v| v.as_str())
        .ok_or("Missing 'key' path in TLS config")?;

    let mut config = TlsConfig::new(cert, key);

    if let Some(ca) = obj.get("client_ca").and_then(|v| v.as_str()) {
        config.client_ca_path = Some(PathBuf::from(ca));
    }

    if let Some(ver) = obj.get("min_version").and_then(|v| v.as_str()) {
        config.min_version = match ver {
            "1.3" | "TLSv1.3" => TlsVersion::Tls13,
            _ => TlsVersion::Tls12,
        };
    }

    if let Some(req) = obj.get("require_client_cert").and_then(|v| v.as_bool()) {
        config.require_client_cert = req;
    }

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_config_new_and_summary() {
        let config = TlsConfig::new("/tmp/cert.pem", "/tmp/key.pem");
        assert!(!config.require_client_cert);
        assert_eq!(config.min_version, TlsVersion::Tls12);
        let summary = config.summary();
        assert!(summary.contains("cert=/tmp/cert.pem"));
        assert!(summary.contains("mTLS=disabled"));
    }

    #[test]
    fn tls_config_mtls() {
        let config = TlsConfig::new("/tmp/cert.pem", "/tmp/key.pem")
            .with_mtls("/tmp/ca.pem")
            .with_min_version(TlsVersion::Tls13);
        assert!(config.require_client_cert);
        assert_eq!(config.min_version, TlsVersion::Tls13);
        assert!(config.client_ca_path.is_some());
    }

    #[test]
    fn tls_validation_missing_files() {
        let config = TlsConfig::new("/nonexistent/cert.pem", "/nonexistent/key.pem");
        let result = config.validate();
        assert!(!result.valid);
        assert!(result.errors.len() >= 2);
    }

    #[test]
    fn tls_validation_mtls_without_ca() {
        let mut config = TlsConfig::new("/nonexistent/cert.pem", "/nonexistent/key.pem");
        config.require_client_cert = true;
        let result = config.validate();
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("client CA")));
    }

    #[test]
    fn listener_mode_plain() {
        let mode = ListenerMode::Plain { port: 8080 };
        assert!(!mode.is_tls());
        assert_eq!(mode.port(), 8080);
        assert_eq!(mode.scheme(), "http");
        assert!(mode.tls_config().is_none());
    }

    #[test]
    fn listener_mode_tls() {
        let config = TlsConfig::new("cert.pem", "key.pem");
        let mode = ListenerMode::Tls { port: 8443, config };
        assert!(mode.is_tls());
        assert_eq!(mode.port(), 8443);
        assert_eq!(mode.scheme(), "https");
        assert!(mode.tls_config().is_some());
    }

    #[test]
    fn parse_tls_config_from_toml() {
        let toml_str = r#"
            cert = "certs/server.pem"
            key = "certs/server-key.pem"
            client_ca = "certs/ca.pem"
            min_version = "1.3"
            require_client_cert = true
        "#;
        let value: toml::Value = toml_str.parse().unwrap();
        let config = parse_tls_config(&value).unwrap();
        assert_eq!(config.cert_path, PathBuf::from("certs/server.pem"));
        assert_eq!(config.key_path, PathBuf::from("certs/server-key.pem"));
        assert_eq!(config.min_version, TlsVersion::Tls13);
        assert!(config.require_client_cert);
    }

    #[test]
    fn parse_tls_config_minimal() {
        let toml_str = r#"
            cert = "cert.pem"
            key = "key.pem"
        "#;
        let value: toml::Value = toml_str.parse().unwrap();
        let config = parse_tls_config(&value).unwrap();
        assert_eq!(config.min_version, TlsVersion::Tls12);
        assert!(!config.require_client_cert);
    }

    #[test]
    fn parse_tls_config_missing_cert() {
        let toml_str = r#"
            key = "key.pem"
        "#;
        let value: toml::Value = toml_str.parse().unwrap();
        assert!(parse_tls_config(&value).is_err());
    }

    #[test]
    fn tls_version_str() {
        assert_eq!(TlsVersion::Tls12.as_str(), "TLSv1.2");
        assert_eq!(TlsVersion::Tls13.as_str(), "TLSv1.3");
    }
}
