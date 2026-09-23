//! Windows kernel-driven, event-based telemetry.
//!
//! This module adds a real-time ETW (Event Tracing for Windows) consumer
//! (`etw_consumer`, `#[cfg(windows)]`) for the kernel process, file, and
//! network manifest providers, plus best-effort DNS-Client, PowerShell
//! ScriptBlock logging, and Microsoft-Antimalware-Scan-Interface telemetry.
//! It replaces the "has_etw: bool" flag that used to sit next to a
//! WMI-only collector in `collector_windows.rs` with an honest report of
//! which backend is *actually* active and why — mirroring
//! `src/kernel_linux/`.
//!
//! The event-mapping logic (`mapping.rs`) is pure and platform-independent
//! on purpose: it is unit-tested on every CI host, including Linux, even
//! though the ETW consumer that feeds it can only build and run on
//! Windows. Capability detection (`capability.rs`) follows the same
//! pattern: the elevation check is `#[cfg(windows)]`, but the
//! backend-selection *decision* is a pure function taking the elevation
//! bool as a parameter, so it too is unit-tested everywhere.
//!
//! AMSI: implementing an actual AMSI *provider* requires a signed,
//! registered COM DLL (`IAntimalwareProvider`) — a system-wide
//! installation step far outside an EDR agent's normal privilege
//! boundary, and not something that can be verified in this environment.
//! Instead, this module consumes ETW telemetry from the
//! `Microsoft-Antimalware-Scan-Interface` provider, which reports scan
//! results from whichever real AMSI provider is registered (typically
//! Windows Defender). See `docs/runbooks/windows-agent.md`.

pub mod capability;
pub mod mapping;

#[cfg(windows)]
pub mod etw_consumer;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::thread::JoinHandle;

use crate::kernel_events::{EventSource, KernelEvent, KernelEventKind, KernelEventStream};

pub use capability::{WindowsBackendKind, WindowsTelemetryCapability, detect_capability};

/// Depth of the bounded channel the ETW callback thread feeds into the
/// consumer thread that pushes events onto the shared [`KernelEventStream`].
/// Sized generously for bursty exec storms while still bounding worst-case
/// memory use, matching `kernel_linux::CHANNEL_CAPACITY`.
const CHANNEL_CAPACITY: usize = 4_096;

/// A single normalized event plus the source provider that produced it.
pub(crate) struct RawEvent {
    pub(crate) source: EventSource,
    pub(crate) kind: KernelEventKind,
}

/// Counters exposed so operators/tests can see backpressure behavior.
#[derive(Debug, Default)]
pub struct WindowsTelemetryStats {
    pub process_events: AtomicU64,
    pub file_events: AtomicU64,
    pub network_events: AtomicU64,
    pub dns_events: AtomicU64,
    pub scriptblock_events: AtomicU64,
    pub amsi_events: AtomicU64,
    pub dropped_events: AtomicU64,
}

/// Seam for config wiring: a parallel change is adding `etw_enabled`,
/// `amsi_enabled`, `wmi_enabled`, and `ebpf_enabled` config keys. This
/// struct is what that config should populate and pass into [`spawn`];
/// until it is wired up, every flag defaults to enabled so behavior is
/// unchanged from "always try the best available backend".
#[derive(Debug, Clone, Copy)]
pub struct WindowsTelemetryOptions {
    /// Start the ETW consumer for process/file/network/DNS telemetry.
    pub etw: bool,
    /// Also subscribe to the `Microsoft-Antimalware-Scan-Interface` ETW
    /// provider (see the module docs for why this is not a full AMSI
    /// provider implementation).
    pub amsi_etw: bool,
    /// Also subscribe to PowerShell ScriptBlock logging (event ID 4104).
    pub powershell_scriptblock: bool,
}

impl Default for WindowsTelemetryOptions {
    fn default() -> Self {
        Self {
            etw: true,
            amsi_etw: true,
            powershell_scriptblock: true,
        }
    }
}

/// Handle to the running telemetry backend. Holding this alive keeps the
/// ETW session open; dropping it stops the trace (unlike
/// `kernel_linux::KernelTelemetryHandle`, whose backend threads are
/// daemon-style — `ferrisetw`'s `UserTrace` stops itself on `Drop`, so
/// callers must keep this handle for the life of the process).
pub struct WindowsTelemetryHandle {
    pub capability: WindowsTelemetryCapability,
    pub stats: Arc<WindowsTelemetryStats>,
    _consumer_thread: Option<JoinHandle<()>>,
    #[cfg(windows)]
    _etw_session: Option<etw_consumer::EtwSession>,
}

/// Detect capabilities and, when possible, start a real-time ETW consumer
/// feeding normalized [`KernelEvent`]s into `stream`. Never blocks the
/// caller long: the ETW session processes events on its own background
/// thread (matching `ferrisetw`'s `start_and_process` model), and a single
/// consumer thread here drains a bounded channel into `stream`.
///
/// On a non-elevated process, or on any platform other than Windows, this
/// starts no ETW session and returns a handle whose `capability` says so;
/// the caller (`collector_windows.rs` / `server_runtime.rs`) keeps using
/// the existing WMI/PowerShell polling collector in that case.
pub fn spawn(
    stream: KernelEventStream,
    hostname: String,
    agent_uid: Option<String>,
    options: WindowsTelemetryOptions,
) -> WindowsTelemetryHandle {
    // Referenced unconditionally so this parameter isn't flagged unused on
    // targets where the `#[cfg(windows)]` branch below (the only place
    // that reads its fields) doesn't compile.
    let _ = &options;
    let capability = detect_capability();
    let stats = Arc::new(WindowsTelemetryStats::default());

    let (tx, rx): (SyncSender<RawEvent>, Receiver<RawEvent>) = sync_channel(CHANNEL_CAPACITY);

    let consumer_thread = std::thread::spawn(move || {
        for raw in rx {
            let severity = crate::kernel_events::KernelEventSeverity::Info;
            let mitre = crate::kernel_events::suggest_mitre(&raw.kind);
            stream.push(KernelEvent {
                id: 0,
                timestamp_ms: now_ms(),
                source: raw.source,
                hostname: hostname.clone(),
                agent_uid: agent_uid.clone(),
                kind: raw.kind,
                severity,
                mitre_techniques: mitre,
            });
        }
    });

    #[cfg(windows)]
    let etw_session = if options.etw && capability.backend == WindowsBackendKind::EtwWindows {
        match etw_consumer::EtwSession::start(tx.clone(), Arc::clone(&stats), &options) {
            Ok(session) => {
                log::info!(
                    "kernel_windows: ETW consumer active for kernel process/file/network \
                     providers ({})",
                    capability.backend_reason
                );
                Some(session)
            }
            Err(e) => {
                log::warn!(
                    "kernel_windows: ETW session failed to start despite capability probe \
                     ({e}); falling back to WMI/PowerShell polling"
                );
                None
            }
        }
    } else {
        log::info!(
            "kernel_windows: ETW consumer inactive ({}); using WMI/PowerShell/reg.exe polling",
            capability.backend_reason
        );
        None
    };
    #[cfg(not(windows))]
    {
        log::info!(
            "kernel_windows: ETW consumer inactive ({}); using WMI/PowerShell/reg.exe polling",
            capability.backend_reason
        );
    }

    drop(tx);

    WindowsTelemetryHandle {
        capability,
        stats,
        _consumer_thread: Some(consumer_thread),
        #[cfg(windows)]
        _etw_session: etw_session,
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Forward an event onto the bounded channel, counting it either as
/// delivered or dropped-on-backpressure. Shared by every provider callback
/// in `etw_consumer.rs`.
pub(crate) fn send_or_drop(
    tx: &SyncSender<RawEvent>,
    stats: &WindowsTelemetryStats,
    source: EventSource,
    kind: KernelEventKind,
    counter: &AtomicU64,
) {
    counter.fetch_add(1, Ordering::Relaxed);
    if tx.try_send(RawEvent { source, kind }).is_err() {
        stats.dropped_events.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_on_non_windows_never_activates_etw() {
        let stream = KernelEventStream::new(16);
        let handle = spawn(
            stream,
            "test-host".into(),
            None,
            WindowsTelemetryOptions::default(),
        );
        // On the host these tests run on (Linux CI), capability detection
        // always reports WmiPoll; this pins that this function is safe to
        // call unconditionally from `server_runtime.rs` without a target
        // cfg guard around the call site itself.
        if !cfg!(windows) {
            assert!(handle.capability.fully_degraded());
        }
    }

    #[test]
    fn options_default_to_everything_enabled() {
        let opts = WindowsTelemetryOptions::default();
        assert!(opts.etw);
        assert!(opts.amsi_etw);
        assert!(opts.powershell_scriptblock);
    }
}
