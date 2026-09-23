//! Runtime capability probing for macOS Endpoint Security telemetry.
//!
//! The Endpoint Security Framework (ESF) requires all of the following
//! before `es_new_client()` will succeed:
//!
//!   1. The `com.apple.developer.endpoint-security.client` entitlement,
//!      granted by Apple and baked into a code-signed binary.
//!   2. The user's Full Disk Access (TCC) approval for that binary.
//!   3. The client process running as root.
//!
//! None of this can be arranged or verified in this environment (there is
//! no macOS host here, let alone one enrolled with an Apple-signed
//! entitlement), so this module — like `kernel_windows::capability` — is
//! split into a real, `#[cfg(...)]`-gated check and a pure, always-tested
//! decision function that takes the check's result as a plain bool.

use serde::{Deserialize, Serialize};

/// Which concrete mechanism is producing telemetry for macOS collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosBackendKind {
    /// A real Endpoint Security Framework client subscribed to process and
    /// file events. Only ever selected when built with the `macos-es`
    /// feature *and* `es_new_client()` actually succeeds at runtime.
    EsfMacos,
    /// The pre-existing `ps`/`lsof`/`mount`/`last` polling collector in
    /// `collector_macos.rs`. Used whenever ESF isn't compiled in, isn't
    /// entitled, or `es_new_client()` otherwise fails.
    PollingMacos,
}

/// A full capability + backend-selection report for macOS telemetry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacosTelemetryCapability {
    pub backend: MacosBackendKind,
    pub backend_reason: String,
    /// Whether this binary was even *built* with the `macos-es` feature —
    /// independent of whether it would actually be entitled to use it.
    pub compiled_with_es_feature: bool,
    /// Whether the current process is running as root (`uid == 0`), a
    /// necessary but not sufficient condition for `es_new_client()`.
    pub is_root: bool,
}

impl MacosTelemetryCapability {
    pub fn summary(&self) -> String {
        format!(
            "backend={:?} ({}); compiled_with_es_feature={}; is_root={}",
            self.backend, self.backend_reason, self.compiled_with_es_feature, self.is_root
        )
    }

    pub fn fully_degraded(&self) -> bool {
        self.backend == MacosBackendKind::PollingMacos
    }
}

/// Shell out to `id -u` rather than calling `geteuid(2)` directly: this
/// crate forbids `unsafe_code`, and every other macOS capability check in
/// `collector_macos.rs` already shells out to system tools (`csrutil`,
/// `spctl`, `sqlite3`) instead of calling libc/Foundation directly, so this
/// stays consistent with that pattern.
#[cfg(target_os = "macos")]
fn is_root() -> bool {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}

#[cfg(not(target_os = "macos"))]
fn is_root() -> bool {
    false
}

/// Run the full capability probe against the live host.
pub fn detect_capability() -> MacosTelemetryCapability {
    detect_capability_with(is_root(), cfg!(target_os = "macos"), cfg!(feature = "macos-es"))
}

/// Testable core of [`detect_capability`], parameterized so the decision
/// logic can be exercised on any host regardless of OS or build features.
pub(crate) fn detect_capability_with(
    is_root: bool,
    is_macos: bool,
    compiled_with_es_feature: bool,
) -> MacosTelemetryCapability {
    if !is_macos {
        return MacosTelemetryCapability {
            backend: MacosBackendKind::PollingMacos,
            backend_reason: "not running on macOS".to_string(),
            compiled_with_es_feature,
            is_root: false,
        };
    }

    if !compiled_with_es_feature {
        return MacosTelemetryCapability {
            backend: MacosBackendKind::PollingMacos,
            backend_reason: "built without the `macos-es` cargo feature (off by default: it \
                needs the com.apple.developer.endpoint-security.client entitlement and a \
                signed binary/system extension to do anything — see \
                docs/runbooks/macos-agent.md)"
                .to_string(),
            compiled_with_es_feature: false,
            is_root: false,
        };
    }

    if !is_root {
        return MacosTelemetryCapability {
            backend: MacosBackendKind::PollingMacos,
            backend_reason: "not running as root; es_new_client() requires root even with the \
                entitlement and TCC approval in place"
                .to_string(),
            compiled_with_es_feature: true,
            is_root: false,
        };
    }

    // Being root and built with the feature is necessary but not
    // sufficient — the entitlement and TCC approval can still be missing,
    // which only `es_new_client()` itself can detect. The caller
    // (`es_consumer::EsSession::start`) reports that failure and this
    // capability is downgraded at the `spawn()` call site if it happens;
    // see `kernel_macos::spawn`.
    MacosTelemetryCapability {
        backend: MacosBackendKind::EsfMacos,
        backend_reason: "built with `macos-es` and running as root; attempting to open an ESF \
            client (still subject to entitlement/TCC approval at runtime)"
            .to_string(),
        compiled_with_es_feature: true,
        is_root: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_macos_always_polls() {
        let cap = detect_capability_with(true, false, true);
        assert_eq!(cap.backend, MacosBackendKind::PollingMacos);
        assert!(cap.fully_degraded());
    }

    #[test]
    fn macos_without_feature_polls() {
        let cap = detect_capability_with(true, true, false);
        assert_eq!(cap.backend, MacosBackendKind::PollingMacos);
        assert!(!cap.compiled_with_es_feature);
        assert!(cap.backend_reason.contains("macos-es"));
    }

    #[test]
    fn macos_with_feature_but_not_root_polls() {
        let cap = detect_capability_with(false, true, true);
        assert_eq!(cap.backend, MacosBackendKind::PollingMacos);
        assert!(cap.compiled_with_es_feature);
        assert!(!cap.is_root);
        assert!(cap.backend_reason.contains("root"));
    }

    #[test]
    fn macos_root_with_feature_attempts_esf() {
        let cap = detect_capability_with(true, true, true);
        assert_eq!(cap.backend, MacosBackendKind::EsfMacos);
        assert!(!cap.fully_degraded());
    }

    #[test]
    fn summary_mentions_backend() {
        let cap = detect_capability_with(true, true, true);
        assert!(cap.summary().contains("EsfMacos"));
    }
}
