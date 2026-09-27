//! Runtime capability probing for Windows kernel telemetry.
//!
//! ETW's kernel-mode manifest providers (`Microsoft-Windows-Kernel-Process`,
//! `-Kernel-File`, `-Kernel-Network`) can only be consumed from a real-time
//! trace session created by a process running elevated (a member of the
//! `Administrators` group / `SeSystemProfilePrivilege`-capable). When that
//! is not the case, this module reports the fallback reason so the agent
//! degrades to the existing WMI/PowerShell polling collector and says why,
//! the same way `kernel_linux::capability` reports its own fallbacks.

use serde::{Deserialize, Serialize};

/// Which concrete mechanism is producing telemetry for Windows collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsBackendKind {
    /// A real-time ETW consumer session against the kernel process/file/
    /// network providers (and optionally DNS-Client/PowerShell/AMSI).
    EtwWindows,
    /// The pre-existing WMI/PowerShell/`reg.exe`/`netstat` polling
    /// collector in `collector_windows.rs`. Used whenever ETW can't be
    /// started (not elevated, or session creation failed).
    WmiPoll,
}

/// A full capability + backend-selection report for Windows telemetry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsTelemetryCapability {
    /// Backend actively used (or that would be used) for process/file/
    /// network telemetry.
    pub backend: WindowsBackendKind,
    /// Human-readable reason for that choice.
    pub backend_reason: String,
    /// Whether the current process token is elevated (a member of
    /// `Administrators`, required to open a real-time ETW session against
    /// the kernel providers).
    pub is_elevated: bool,
    /// Whether Microsoft-Antimalware-Scan-Interface ETW telemetry (a proxy
    /// for real AMSI provider integration, which would need a registered
    /// COM DLL — out of scope here) is being consumed. Only meaningful
    /// when `backend == EtwWindows`.
    pub amsi_etw_active: bool,
    /// True implementation of an AMSI *provider* (a registered COM DLL
    /// that intercepts every AMSI client's `AmsiScanBuffer` call) is not
    /// implemented by this agent — see `docs/runbooks/windows-agent.md`.
    /// Always `false`; kept as a distinct, explicit field so this is never
    /// confused with `amsi_etw_active` above.
    pub amsi_provider_active: bool,
}

impl WindowsTelemetryCapability {
    /// Short combined summary line, suitable for a single doctor row.
    pub fn summary(&self) -> String {
        format!(
            "backend={:?} ({}); elevated={}; AMSI ETW consumer active={}; AMSI provider (COM DLL) implemented={}",
            self.backend,
            self.backend_reason,
            self.is_elevated,
            self.amsi_etw_active,
            self.amsi_provider_active
        )
    }

    /// True when telemetry is degraded to plain polling — i.e. no
    /// kernel-pushed ETW events at all.
    pub fn fully_degraded(&self) -> bool {
        self.backend == WindowsBackendKind::WmiPoll
    }
}

/// Detect whether the current process token is elevated.
///
/// Implemented by shelling out to `net session` rather than calling the
/// Win32 token APIs directly: `net session` with no arguments succeeds
/// (exit code 0) only when run from an elevated prompt, and fails
/// otherwise (`ERROR_ACCESS_DENIED`) — a well-known, dependency-free way to
/// check elevation that needs no `unsafe` FFI, matching how the rest of
/// this crate's Windows collector shells out to `wmic`/`reg`/`netstat`
/// instead of calling the Win32 API directly (`unsafe_code = "forbid"`
/// applies to this crate; `net.exe` output is a hint, not a trust boundary
/// we defend against a hostile administrator).
#[cfg(windows)]
fn is_elevated() -> bool {
    std::process::Command::new("net")
        .args(["session"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(not(windows))]
fn is_elevated() -> bool {
    false
}

/// Run the full capability probe against the live host.
pub fn detect_capability() -> WindowsTelemetryCapability {
    detect_capability_with(is_elevated(), cfg!(windows))
}

/// Testable core of [`detect_capability`], parameterized on the elevation
/// check and whether we are actually compiled for Windows, so the decision
/// logic can be exercised on any host.
pub(crate) fn detect_capability_with(
    is_elevated: bool,
    is_windows: bool,
) -> WindowsTelemetryCapability {
    if !is_windows {
        return WindowsTelemetryCapability {
            backend: WindowsBackendKind::WmiPoll,
            backend_reason: "not running on Windows".to_string(),
            is_elevated: false,
            amsi_etw_active: false,
            amsi_provider_active: false,
        };
    }

    if is_elevated {
        WindowsTelemetryCapability {
            backend: WindowsBackendKind::EtwWindows,
            backend_reason: "process token is elevated; a real-time ETW session against \
                the kernel process/file/network providers can be opened"
                .to_string(),
            is_elevated: true,
            amsi_etw_active: true,
            amsi_provider_active: false,
        }
    } else {
        WindowsTelemetryCapability {
            backend: WindowsBackendKind::WmiPoll,
            backend_reason: "process is not elevated; ETW real-time kernel provider sessions \
                require Administrator privileges — run the agent service elevated \
                (the default Windows service install already runs as SYSTEM) to enable it"
                .to_string(),
            is_elevated: false,
            amsi_etw_active: false,
            amsi_provider_active: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elevated_windows_selects_etw() {
        let cap = detect_capability_with(true, true);
        assert_eq!(cap.backend, WindowsBackendKind::EtwWindows);
        assert!(cap.is_elevated);
        assert!(cap.amsi_etw_active);
        assert!(!cap.amsi_provider_active);
        assert!(!cap.fully_degraded());
    }

    #[test]
    fn non_elevated_windows_falls_back_to_wmi_poll() {
        let cap = detect_capability_with(false, true);
        assert_eq!(cap.backend, WindowsBackendKind::WmiPoll);
        assert!(!cap.is_elevated);
        assert!(!cap.amsi_etw_active);
        assert!(cap.fully_degraded());
        assert!(cap.backend_reason.contains("Administrator"));
    }

    #[test]
    fn non_windows_always_falls_back() {
        let cap = detect_capability_with(true, false);
        assert_eq!(cap.backend, WindowsBackendKind::WmiPoll);
        assert!(cap.fully_degraded());
    }

    #[test]
    fn summary_mentions_backend_and_amsi() {
        let cap = detect_capability_with(true, true);
        let s = cap.summary();
        assert!(s.contains("EtwWindows"));
        assert!(s.contains("AMSI"));
    }

    #[test]
    fn amsi_provider_is_never_reported_active() {
        // Implementing a real AMSI *provider* requires a registered COM
        // DLL and is out of scope; pin this so a future change can't
        // silently claim it without updating docs too.
        assert!(!detect_capability_with(true, true).amsi_provider_active);
        assert!(!detect_capability_with(false, true).amsi_provider_active);
        assert!(!detect_capability_with(true, false).amsi_provider_active);
    }
}
