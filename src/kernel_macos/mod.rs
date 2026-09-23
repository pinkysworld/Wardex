//! macOS kernel-driven, event-based telemetry via the Endpoint Security
//! Framework (ESF), feature-gated behind `macos-es` (off by default).
//!
//! Mirrors `kernel_windows`: `capability.rs` and `mapping.rs` are
//! unconditional and unit-tested on every host, while the real ESF client
//! (`es_consumer.rs`) only compiles under
//! `#[cfg(all(target_os = "macos", feature = "macos-es"))]` — it depends
//! on `endpoint-sec`, itself only pulled in as an optional,
//! `target_os = "macos"`-gated dependency, so nothing here affects the
//! default build on any platform, including macOS without the feature.
//!
//! ESF requires the `com.apple.developer.endpoint-security.client`
//! entitlement (from Apple, tied to a signed Team ID), the user's Full
//! Disk Access (TCC) approval, and root — none of which exist in this
//! development environment, so this has not been exercised end to end
//! against a live client. See `docs/runbooks/macos-agent.md`.

pub mod capability;
pub mod mapping;

#[cfg(all(target_os = "macos", feature = "macos-es"))]
pub mod es_consumer;

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::thread::JoinHandle;

use crate::kernel_events::{EventSource, KernelEvent, KernelEventKind, KernelEventStream};

pub use capability::{MacosBackendKind, MacosTelemetryCapability, detect_capability};

const CHANNEL_CAPACITY: usize = 4_096;

pub(crate) struct RawEvent {
    pub(crate) source: EventSource,
    pub(crate) kind: KernelEventKind,
}

#[derive(Debug, Default)]
pub struct MacosTelemetryStats {
    pub process_events: AtomicU64,
    pub file_events: AtomicU64,
    pub dropped_events: AtomicU64,
}

/// Seam for config wiring, matching `kernel_windows::WindowsTelemetryOptions`.
/// `etw_enabled`/`amsi_enabled`/`wmi_enabled`/`ebpf_enabled` config keys are
/// being added in a parallel branch; this struct is what a corresponding
/// macOS config option should populate. Defaults to enabled.
#[derive(Debug, Clone, Copy)]
pub struct MacosTelemetryOptions {
    pub es: bool,
}

impl Default for MacosTelemetryOptions {
    fn default() -> Self {
        Self { es: true }
    }
}

pub struct MacosTelemetryHandle {
    pub capability: MacosTelemetryCapability,
    pub stats: Arc<MacosTelemetryStats>,
    _consumer_thread: Option<JoinHandle<()>>,
    #[cfg(all(target_os = "macos", feature = "macos-es"))]
    _es_session: Option<es_consumer::EsSession>,
}

/// Detect capabilities and, when built with `macos-es` and running as root
/// on macOS, attempt to start a real Endpoint Security client. Falls back
/// to the existing `ps`/`lsof` polling collector — and says exactly why —
/// whenever any precondition isn't met, including when `es_new_client()`
/// itself rejects the attempt (not entitled, not permitted, not
/// privileged).
pub fn spawn(
    stream: KernelEventStream,
    hostname: String,
    agent_uid: Option<String>,
    options: MacosTelemetryOptions,
) -> MacosTelemetryHandle {
    // Referenced unconditionally so this parameter isn't flagged unused on
    // targets/builds where the `#[cfg(all(target_os = "macos", feature =
    // "macos-es"))]` branch below (the only place that reads it) doesn't
    // compile.
    let _ = &options;
    let capability = detect_capability();
    let stats = Arc::new(MacosTelemetryStats::default());

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

    #[cfg(all(target_os = "macos", feature = "macos-es"))]
    let (es_session, capability) = if options.es && capability.backend == MacosBackendKind::EsfMacos
    {
        match es_consumer::EsSession::start(tx.clone(), Arc::clone(&stats)) {
            Ok(session) => {
                log::info!(
                    "kernel_macos: Endpoint Security client active ({})",
                    capability.backend_reason
                );
                (Some(session), capability)
            }
            Err(e) => {
                log::warn!(
                    "kernel_macos: es_new_client() failed ({e:?}); falling back to ps/lsof \
                     polling. This means the entitlement, code signature, or TCC Full Disk \
                     Access approval is missing — see docs/runbooks/macos-agent.md."
                );
                let downgraded = MacosTelemetryCapability {
                    backend: MacosBackendKind::PollingMacos,
                    backend_reason: format!("es_new_client() failed: {e:?}"),
                    ..capability
                };
                (None, downgraded)
            }
        }
    } else {
        log::info!(
            "kernel_macos: Endpoint Security inactive ({}); using ps/lsof/mount polling",
            capability.backend_reason
        );
        (None, capability)
    };
    #[cfg(not(all(target_os = "macos", feature = "macos-es")))]
    {
        log::info!(
            "kernel_macos: Endpoint Security inactive ({}); using ps/lsof/mount polling",
            capability.backend_reason
        );
    }

    drop(tx);

    MacosTelemetryHandle {
        capability,
        stats,
        _consumer_thread: Some(consumer_thread),
        #[cfg(all(target_os = "macos", feature = "macos-es"))]
        _es_session: es_session,
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(all(target_os = "macos", feature = "macos-es"))]
pub(crate) fn send_or_drop(
    tx: &SyncSender<RawEvent>,
    stats: &MacosTelemetryStats,
    source: EventSource,
    kind: KernelEventKind,
    counter: &AtomicU64,
) {
    counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if tx.try_send(RawEvent { source, kind }).is_err() {
        stats
            .dropped_events
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_without_es_feature_never_activates_esf() {
        let stream = KernelEventStream::new(16);
        let handle = spawn(
            stream,
            "test-host".into(),
            None,
            MacosTelemetryOptions::default(),
        );
        if !(cfg!(target_os = "macos") && cfg!(feature = "macos-es")) {
            assert!(handle.capability.fully_degraded());
        }
    }

    #[test]
    fn options_default_to_enabled() {
        assert!(MacosTelemetryOptions::default().es);
    }
}
