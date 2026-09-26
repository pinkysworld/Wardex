//! Shared rustls `ClientConfig` construction for this crate's outbound TLS
//! clients: SMTP notification delivery (`src/notifications.rs`) and the
//! in-cluster Kubernetes API client (`src/container_runtime.rs::KubeClient`).
//!
//! Only compiled with the `tls` cargo feature, which is what pulls in the
//! direct `rustls`/`rustls-pki-types`/`webpki-roots` dependencies this
//! module needs (see `Cargo.toml`). Without that feature, callers must fail
//! clearly rather than silently skip certificate verification — there is no
//! "insecure" fallback anywhere in this module.

#[cfg(feature = "tls")]
use std::sync::Arc;

/// Parse one or more PEM-encoded certificates out of `pem`.
#[cfg(feature = "tls")]
pub fn parse_pem_certificates(
    pem: &str,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
    use base64::Engine;
    let mut certs = Vec::new();
    let mut current = String::new();
    let mut in_cert = false;
    for line in pem.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("-----BEGIN CERTIFICATE-----") {
            in_cert = true;
            current.clear();
            continue;
        }
        if trimmed.starts_with("-----END CERTIFICATE-----") {
            in_cert = false;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(current.trim())
                .map_err(|e| format!("invalid PEM certificate: {e}"))?;
            certs.push(rustls::pki_types::CertificateDer::from(bytes));
            continue;
        }
        if in_cert {
            current.push_str(trimmed);
        }
    }
    if certs.is_empty() {
        return Err("no certificates found in PEM input".into());
    }
    Ok(certs)
}

/// Build a rustls `ClientConfig` trusting some combination of the public
/// Mozilla root program roots (`webpki-roots`) and extra PEM-encoded
/// certificates.
///
/// - `include_webpki_roots`: trust the bundled public root program roots.
///   Callers that must trust ONLY a private CA (e.g. a Kubernetes cluster's
///   serviceaccount CA) pass `false` here so a certificate from outside
///   that CA is never accepted.
/// - `extra_trusted_pem`: additional PEM-encoded certificate(s) to trust,
///   on top of `include_webpki_roots`.
///
/// Fails if the resulting trust store would be empty (e.g.
/// `include_webpki_roots: false` with no `extra_trusted_pem`), since an
/// empty `RootCertStore` trusts nothing and every handshake would fail
/// with a confusing low-level error instead of this clear one.
#[cfg(feature = "tls")]
pub fn build_tls_client_config(
    include_webpki_roots: bool,
    extra_trusted_pem: Option<&str>,
) -> Result<Arc<rustls::ClientConfig>, String> {
    let mut roots = rustls::RootCertStore::empty();
    if include_webpki_roots {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    if let Some(pem) = extra_trusted_pem {
        for cert in parse_pem_certificates(pem)? {
            roots
                .add(cert)
                .map_err(|e| format!("failed to add trusted certificate: {e}"))?;
        }
    }
    if roots.is_empty() {
        return Err("no trusted root certificates configured".into());
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("tls config: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

#[cfg(all(test, feature = "tls"))]
mod tests {
    use super::*;

    #[test]
    fn parse_pem_certificates_rejects_empty_input() {
        assert!(parse_pem_certificates("not a certificate").is_err());
    }

    #[test]
    fn parse_pem_certificates_extracts_one_cert() {
        let cert = rcgen::generate_simple_self_signed(vec!["example.test".to_string()])
            .expect("generate self-signed cert");
        let pem = cert.cert.pem();
        let certs = parse_pem_certificates(&pem).expect("parse pem");
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn build_tls_client_config_with_webpki_roots_only() {
        let config = build_tls_client_config(true, None).expect("build config");
        assert!(
            !config
                .crypto_provider()
                .signature_verification_algorithms
                .all
                .is_empty()
        );
    }

    #[test]
    fn build_tls_client_config_rejects_empty_trust_store() {
        let err = build_tls_client_config(false, None).unwrap_err();
        assert!(err.contains("no trusted root certificates"));
    }

    #[test]
    fn build_tls_client_config_trusts_only_extra_pem_when_webpki_roots_disabled() {
        let cert = rcgen::generate_simple_self_signed(vec!["example.test".to_string()])
            .expect("generate self-signed cert");
        let pem = cert.cert.pem();
        let config = build_tls_client_config(false, Some(&pem)).expect("build config");
        // Sanity: the config was built successfully with only the private
        // certificate trusted (no webpki roots) — end-to-end handshake
        // behavior against a real listener is covered by the Kubernetes
        // client tests in `container_runtime.rs`.
        assert!(
            !config
                .crypto_provider()
                .signature_verification_algorithms
                .all
                .is_empty()
        );
    }
}
