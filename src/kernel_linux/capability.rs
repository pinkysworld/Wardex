//! Runtime capability probing for Linux kernel telemetry backends.
//!
//! Decides, at startup, which backend actually gets used for process and
//! file telemetry, and records *why* — so the choice can be surfaced
//! honestly in `wardex doctor` and support bundles instead of a single
//! `has_ebpf: bool` that only meant "the kernel is new enough".

use serde::{Deserialize, Serialize};
use std::fs;

/// Effective Linux capability bit numbers we care about (linux/capability.h).
const CAP_NET_ADMIN: u32 = 12;
const CAP_SYS_ADMIN: u32 = 21;

/// Which concrete mechanism is producing telemetry for a given domain
/// (process lifecycle, or file activity).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelBackendKind {
    /// CN_PROC netlink process connector: real-time, kernel-pushed.
    NetlinkProcConnector,
    /// fanotify(7): real-time, kernel-pushed file events.
    Fanotify,
    /// inotify(7): real-time, kernel-pushed file events (fallback; no
    /// process/exec context, mark-per-watch rather than mark-per-mount).
    Inotify,
    /// Periodic /proc (and directory metadata) polling — the pre-existing
    /// collector. Used whenever a real event source can't be opened.
    ProcPoll,
    /// True in-kernel eBPF program. Reserved for a future backend; never
    /// selected today. See the `ebpf` cargo feature.
    Ebpf,
}

/// A full capability + backend-selection report for Linux kernel telemetry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelTelemetryCapability {
    /// Backend actively used (or that would be used) for process
    /// lifecycle events (exec/fork/exit/uid-change).
    pub process_backend: KernelBackendKind,
    /// Human-readable reason for that choice.
    pub process_backend_reason: String,
    /// Backend actively used (or that would be used) for file events.
    pub file_backend: KernelBackendKind,
    /// Human-readable reason for that choice.
    pub file_backend_reason: String,
    /// Whether the running process holds `CAP_NET_ADMIN` (required to open
    /// a `CN_PROC` netlink connector socket).
    pub has_cap_net_admin: bool,
    /// Whether the running process holds `CAP_SYS_ADMIN` (required for
    /// `fanotify_init(2)` in the general case).
    pub has_cap_sys_admin: bool,
    /// Whether the host kernel is new enough, and exposes the right
    /// interfaces, for eBPF to be *possible* in principle. This does not
    /// mean eBPF telemetry is active — see `ebpf_active`.
    pub ebpf_kernel_capable: bool,
    /// Whether a real eBPF telemetry backend is actually running. Always
    /// `false` today; kept as a distinct field so a future implementation
    /// can flip it on without an API shape change.
    pub ebpf_active: bool,
}

impl KernelTelemetryCapability {
    /// Short combined summary line, suitable for a single doctor row.
    pub fn summary(&self) -> String {
        format!(
            "process={:?} ({}); file={:?} ({}); eBPF: kernel-capable={} active={}",
            self.process_backend,
            self.process_backend_reason,
            self.file_backend,
            self.file_backend_reason,
            self.ebpf_kernel_capable,
            self.ebpf_active
        )
    }

    /// True when every telemetry domain is degraded to plain polling —
    /// i.e. no kernel-pushed events at all.
    pub fn fully_degraded(&self) -> bool {
        self.process_backend == KernelBackendKind::ProcPoll
            && self.file_backend == KernelBackendKind::ProcPoll
    }
}

/// Parse the effective capability bitmask (`CapEff`) out of
/// `/proc/self/status` and test whether `bit` is set. Returns `false`
/// (fail closed) on any parse error, matching how the rest of this
/// codebase treats unreadable /proc entries as "feature unavailable"
/// rather than propagating an error.
fn has_effective_capability(bit: u32) -> bool {
    let status = match fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(_) => return false,
    };
    for line in status.lines() {
        if let Some(hex) = line.strip_prefix("CapEff:") {
            let hex = hex.trim();
            if let Ok(mask) = u64::from_str_radix(hex, 16) {
                return (mask >> bit) & 1 == 1;
            }
        }
    }
    false
}

/// Kernel version string check shared with `collector_linux`, duplicated
/// narrowly here to keep this module self-contained and independently
/// testable.
fn kernel_at_least(version_str: &str, major: u32, minor: u32) -> bool {
    let token = version_str
        .split_whitespace()
        .find(|t| t.chars().next().is_some_and(|c| c.is_ascii_digit()));
    if let Some(ver) = token {
        let parts: Vec<u32> = ver
            .split(|c: char| !c.is_ascii_digit())
            .take(2)
            .filter_map(|s| s.parse().ok())
            .collect();
        if parts.len() >= 2 {
            return (parts[0], parts[1]) >= (major, minor);
        }
    }
    false
}

/// Run the full capability probe against the live host.
pub fn detect_capability() -> KernelTelemetryCapability {
    let has_cap_net_admin = has_effective_capability(CAP_NET_ADMIN);
    let has_cap_sys_admin = has_effective_capability(CAP_SYS_ADMIN);
    let kernel_version =
        fs::read_to_string("/proc/version").unwrap_or_else(|_| "Linux (unknown)".into());
    let ebpf_kernel_capable =
        std::path::Path::new("/sys/fs/bpf").exists() || kernel_at_least(&kernel_version, 4, 1);

    let (process_backend, process_backend_reason) = if has_cap_net_admin {
        (
            KernelBackendKind::NetlinkProcConnector,
            "CAP_NET_ADMIN is held; CN_PROC netlink connector can be opened".to_string(),
        )
    } else {
        (
            KernelBackendKind::ProcPoll,
            "CAP_NET_ADMIN is not held; run as root or grant \
             `setcap cap_net_admin+ep` to enable real-time process events"
                .to_string(),
        )
    };

    let (file_backend, file_backend_reason) =
        if has_cap_sys_admin && std::path::Path::new("/proc/sys/fs/fanotify").exists() {
            (
                KernelBackendKind::Fanotify,
                "CAP_SYS_ADMIN is held and /proc/sys/fs/fanotify exists; fanotify mark-mount \
             mode active"
                    .to_string(),
            )
        } else if std::path::Path::new("/proc/sys/fs/inotify").exists() {
            let reason = if has_cap_sys_admin {
                "fanotify interface not exposed by this kernel; using inotify".to_string()
            } else {
                "CAP_SYS_ADMIN is not held (required for fanotify_init); using inotify, which \
             needs no special privilege beyond normal file read access"
                    .to_string()
            };
            (KernelBackendKind::Inotify, reason)
        } else {
            (
                KernelBackendKind::ProcPoll,
                "neither fanotify nor inotify interfaces are exposed by this kernel".to_string(),
            )
        };

    KernelTelemetryCapability {
        process_backend,
        process_backend_reason,
        file_backend,
        file_backend_reason,
        has_cap_net_admin,
        has_cap_sys_admin,
        ebpf_kernel_capable,
        ebpf_active: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_at_least_parses_common_strings() {
        assert!(kernel_at_least(
            "Linux version 5.15.0-91-generic (gcc)",
            4,
            1
        ));
        assert!(kernel_at_least("Linux version 6.1.0-rpi", 5, 0));
        assert!(!kernel_at_least("Linux version 3.10.0-1160.el7", 4, 1));
    }

    #[test]
    fn detect_capability_is_internally_consistent() {
        // This runs against the real host (container may or may not grant
        // capabilities), so we only assert structural invariants, not a
        // specific outcome.
        let cap = detect_capability();
        assert!(!cap.ebpf_active, "eBPF backend is not implemented yet");
        match cap.process_backend {
            KernelBackendKind::NetlinkProcConnector => assert!(cap.has_cap_net_admin),
            KernelBackendKind::ProcPoll => assert!(!cap.has_cap_net_admin),
            other => panic!("unexpected process backend {other:?}"),
        }
        assert!(!cap.process_backend_reason.is_empty());
        assert!(!cap.file_backend_reason.is_empty());
    }

    #[test]
    fn summary_mentions_both_domains() {
        let cap = KernelTelemetryCapability {
            process_backend: KernelBackendKind::ProcPoll,
            process_backend_reason: "no CAP_NET_ADMIN".into(),
            file_backend: KernelBackendKind::Inotify,
            file_backend_reason: "no CAP_SYS_ADMIN".into(),
            has_cap_net_admin: false,
            has_cap_sys_admin: false,
            ebpf_kernel_capable: true,
            ebpf_active: false,
        };
        let s = cap.summary();
        assert!(s.contains("ProcPoll"));
        assert!(s.contains("Inotify"));
        assert!(!cap.fully_degraded());
    }

    #[test]
    fn fully_degraded_when_both_are_proc_poll() {
        let cap = KernelTelemetryCapability {
            process_backend: KernelBackendKind::ProcPoll,
            process_backend_reason: "x".into(),
            file_backend: KernelBackendKind::ProcPoll,
            file_backend_reason: "x".into(),
            has_cap_net_admin: false,
            has_cap_sys_admin: false,
            ebpf_kernel_capable: false,
            ebpf_active: false,
        };
        assert!(cap.fully_degraded());
    }
}
