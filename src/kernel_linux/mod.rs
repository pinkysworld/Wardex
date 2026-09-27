//! Linux kernel-driven, event-based telemetry backends.
//!
//! This module replaces the previous "eBPF" label on top of /proc polling
//! (see `src/collector_linux.rs`) with telemetry that is actually pushed by
//! the kernel:
//!
//!   * **Process lifecycle** — the netlink process connector (`CN_PROC`),
//!     which the kernel uses to broadcast fork/exec/exit/uid-change events.
//!     See [`netlink_proc`]. Requires `CAP_NET_ADMIN`.
//!   * **File activity** — `fanotify(7)`, falling back to `inotify(7)` when
//!     fanotify is unavailable (missing `CAP_SYS_ADMIN`, or an unsupported
//!     kernel). See [`fanotify_backend`] and [`inotify_backend`].
//!   * **eBPF** — not implemented. See the `ebpf` cargo feature and the
//!     [`KernelBackendKind::Ebpf`] variant for why, and what a real
//!     implementation would need.
//!
//! Every backend that touches raw syscalls does so through `nix`, which
//! keeps `unsafe` inside that dependency; this crate's
//! `#![deny]`-equivalent `unsafe_code = "forbid"` lint stays intact.
//!
//! Backends are selected at startup based on a runtime capability probe
//! ([`detect_capability`]) and degrade gracefully to the pre-existing
//! `/proc` polling collector when a privilege or kernel feature is missing,
//! logging the precise reason.

#![cfg(target_os = "linux")]

pub mod capability;
pub mod fanotify_backend;
pub mod inotify_backend;
pub mod netlink_proc;
pub mod procinfo;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::thread::JoinHandle;

use crate::kernel_events::{EventSource, KernelEvent, KernelEventKind, KernelEventStream};

pub use capability::{KernelBackendKind, KernelTelemetryCapability, detect_capability};

/// Depth of the bounded channel each backend thread feeds into the
/// consumer thread that pushes events onto the shared [`KernelEventStream`].
/// Sized generously for bursty exec storms (e.g. package installs) while
/// still bounding worst-case memory use.
const CHANNEL_CAPACITY: usize = 4_096;

/// A single normalized event plus the source backend that produced it,
/// used internally to route events from backend threads into the shared
/// stream.
pub(crate) struct RawEvent {
    pub(crate) source: EventSource,
    pub(crate) kind: KernelEventKind,
}

/// Counters exposed so operators/tests can see backpressure behavior.
#[derive(Debug, Default)]
pub struct KernelTelemetryStats {
    pub process_events: AtomicU64,
    pub file_events: AtomicU64,
    pub dropped_events: AtomicU64,
}

/// Handle to the running telemetry backends. Dropping it does not stop the
/// backend threads (they are daemon-style for the process lifetime, matching
/// the rest of the collector loop); it exists so callers can inspect the
/// capability report and live counters.
pub struct KernelTelemetryHandle {
    pub capability: KernelTelemetryCapability,
    pub stats: Arc<KernelTelemetryStats>,
    _threads: Vec<JoinHandle<()>>,
}

/// Detect capabilities and start whichever kernel telemetry backends are
/// available, feeding normalized [`KernelEvent`]s into `stream`.
///
/// This never blocks the caller: each backend runs on its own thread, and a
/// single consumer thread drains a bounded channel into `stream`, matching
/// the existing thread-per-collector model used elsewhere in the codebase
/// (see `server_runtime.rs`).
pub fn spawn(
    stream: KernelEventStream,
    hostname: String,
    agent_uid: Option<String>,
    watch_paths: Vec<String>,
) -> KernelTelemetryHandle {
    let capability = detect_capability();
    let stats = Arc::new(KernelTelemetryStats::default());
    let mut threads = Vec::new();

    let (tx, rx): (SyncSender<RawEvent>, Receiver<RawEvent>) = sync_channel(CHANNEL_CAPACITY);

    // Consumer: drains the channel into the shared stream. Runs regardless
    // of which producer backends started, and exits once every sender is
    // dropped (process shutdown).
    {
        let stream = stream.clone();
        let hostname = hostname.clone();
        let agent_uid = agent_uid.clone();
        threads.push(std::thread::spawn(move || {
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
        }));
    }

    match capability.process_backend {
        KernelBackendKind::NetlinkProcConnector => {
            let tx = tx.clone();
            let stats = Arc::clone(&stats);
            match netlink_proc::NetlinkProcListener::open() {
                Ok(listener) => {
                    threads.push(std::thread::spawn(move || {
                        netlink_proc::run(listener, tx, &stats);
                    }));
                    log::info!(
                        "kernel_linux: CN_PROC netlink process connector active ({})",
                        capability.process_backend_reason
                    );
                }
                Err(e) => {
                    log::warn!(
                        "kernel_linux: CN_PROC unavailable despite capability probe ({e}); \
                         process lifecycle events remain on /proc polling"
                    );
                }
            }
        }
        KernelBackendKind::ProcPoll => {
            log::info!(
                "kernel_linux: process lifecycle telemetry uses /proc polling ({})",
                capability.process_backend_reason
            );
        }
        KernelBackendKind::Fanotify | KernelBackendKind::Inotify | KernelBackendKind::Ebpf => {
            unreachable!("process backend selection never picks a file-only backend")
        }
    }

    match capability.file_backend {
        KernelBackendKind::Fanotify => {
            let tx = tx.clone();
            let stats = Arc::clone(&stats);
            let paths = watch_paths.clone();
            match fanotify_backend::FanotifyWatcher::open(&paths) {
                Ok(watcher) => {
                    threads.push(std::thread::spawn(move || {
                        fanotify_backend::run(watcher, tx, &stats);
                    }));
                    log::info!(
                        "kernel_linux: fanotify file telemetry active ({})",
                        capability.file_backend_reason
                    );
                }
                Err(e) => {
                    log::warn!(
                        "kernel_linux: fanotify unavailable despite capability probe ({e}); \
                         attempting inotify fallback"
                    );
                    spawn_inotify_fallback(&watch_paths, tx, Arc::clone(&stats), &mut threads);
                }
            }
        }
        KernelBackendKind::Inotify => {
            spawn_inotify_fallback(&watch_paths, tx.clone(), Arc::clone(&stats), &mut threads);
            log::info!(
                "kernel_linux: inotify file telemetry active ({})",
                capability.file_backend_reason
            );
        }
        KernelBackendKind::ProcPoll => {
            log::info!(
                "kernel_linux: file activity telemetry uses periodic /proc & directory \
                 snapshotting ({})",
                capability.file_backend_reason
            );
        }
        KernelBackendKind::NetlinkProcConnector | KernelBackendKind::Ebpf => {
            unreachable!("file backend selection never picks a process-only backend")
        }
    }

    drop(tx);

    KernelTelemetryHandle {
        capability,
        stats,
        _threads: threads,
    }
}

fn spawn_inotify_fallback(
    watch_paths: &[String],
    tx: SyncSender<RawEvent>,
    stats: Arc<KernelTelemetryStats>,
    threads: &mut Vec<JoinHandle<()>>,
) {
    match inotify_backend::InotifyWatcher::open(watch_paths) {
        Ok(watcher) => {
            threads.push(std::thread::spawn(move || {
                inotify_backend::run(watcher, tx, &stats);
            }));
        }
        Err(e) => {
            log::warn!("kernel_linux: inotify fallback also unavailable ({e})");
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn send_or_drop(
    tx: &SyncSender<RawEvent>,
    stats: &KernelTelemetryStats,
    source: EventSource,
    kind: KernelEventKind,
    counter: &AtomicU64,
) {
    counter.fetch_add(1, Ordering::Relaxed);
    if tx.try_send(RawEvent { source, kind }).is_err() {
        stats.dropped_events.fetch_add(1, Ordering::Relaxed);
    }
}
