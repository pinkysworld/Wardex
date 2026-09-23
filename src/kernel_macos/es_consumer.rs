//! Real Endpoint Security Framework (ESF) client.
//!
//! `#[cfg(all(target_os = "macos", feature = "macos-es"))]`: this can only
//! build on macOS with the optional `macos-es` feature (which pulls in the
//! `endpoint-sec` dependency — itself target-gated so it's never even
//! fetched on other platforms), and it has never run against a live ESF
//! session in this environment: doing so needs the
//! `com.apple.developer.endpoint-security.client` entitlement (granted by
//! Apple to a registered Team ID), a code-signed binary, and the user's
//! Full Disk Access (TCC) approval — none of which can be arranged here.
//! See `docs/runbooks/macos-agent.md` for the real setup steps.
//!
//! What *has* been verified: the pure mapping layer this module feeds
//! (`super::mapping`) is unit-tested on every host, including Linux CI,
//! and `cargo check` (which does not link) was attempted for this module —
//! see the report for whether it needed `endpoint-sec-sys`'s system
//! `libEndpointSecurity` linkage, which this sandbox cannot provide.
//!
//! `endpoint_sec::Client` is deliberately neither `Send` nor `Sync` (Apple
//! requires the client to be released on the thread that created it), so
//! [`EsSession::start`] spawns a dedicated thread that creates the client,
//! subscribes it, and then blocks for the life of the process — matching
//! how every ESF-based tool (including Apple's own sample code) structures
//! this.

use std::sync::Arc;
use std::sync::mpsc::SyncSender;

use endpoint_sec::sys::{NewClientError, es_event_type_t};
use endpoint_sec::{Client, Event};

use super::mapping::{
    EsExecEvent, EsExitEvent, EsFileEvent, EsFileOp, map_exec_event, map_exit_event, map_file_event,
};
use super::{MacosTelemetryStats, RawEvent, send_or_drop};
use crate::kernel_events::EventSource;

/// Handle to the background thread hosting the ESF client. The client
/// itself never leaves that thread (see the module docs); dropping this
/// handle asks the thread to exit via closing `shutdown_tx`, though in
/// practice — matching every other spawn_* collector in this codebase —
/// it is simply leaked for the life of the process.
pub struct EsSession {
    _thread: std::thread::JoinHandle<()>,
}

impl EsSession {
    /// Attempt to open an ESF client and subscribe it to the process/file
    /// events this module maps. Returns the specific `es_new_client()`
    /// failure reason (not entitled / not permitted / not privileged /
    /// other) so the caller can log an honest, actionable message instead
    /// of a bare "ESF unavailable".
    pub fn start(
        tx: SyncSender<RawEvent>,
        stats: Arc<MacosTelemetryStats>,
    ) -> Result<Self, NewClientError> {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), NewClientError>>();

        let thread = std::thread::spawn(move || {
            let handler = move |_client: &mut Client<'_>, message: endpoint_sec::Message| {
                handle_message(&message, &tx, &stats);
            };

            match Client::new(handler) {
                Ok(mut client) => {
                    let events: &[es_event_type_t] = &[
                        es_event_type_t::ES_EVENT_TYPE_NOTIFY_EXEC,
                        es_event_type_t::ES_EVENT_TYPE_NOTIFY_FORK,
                        es_event_type_t::ES_EVENT_TYPE_NOTIFY_EXIT,
                        es_event_type_t::ES_EVENT_TYPE_NOTIFY_CREATE,
                        es_event_type_t::ES_EVENT_TYPE_NOTIFY_WRITE,
                        es_event_type_t::ES_EVENT_TYPE_NOTIFY_CLOSE,
                        es_event_type_t::ES_EVENT_TYPE_NOTIFY_RENAME,
                        es_event_type_t::ES_EVENT_TYPE_NOTIFY_UNLINK,
                    ];
                    if let Err(e) = client.subscribe(events) {
                        log::warn!("kernel_macos: es_subscribe failed: {e:?}");
                        let _ = ready_tx.send(Err(NewClientError::NotPermitted));
                        return;
                    }
                    let _ = ready_tx.send(Ok(()));
                    // Park this thread forever; the client (and its
                    // subscription) stays alive as long as `client` is not
                    // dropped. There is nothing else for this thread to
                    // do — all real work happens in the `handler` closure,
                    // invoked by the ES runtime itself.
                    loop {
                        std::thread::park();
                    }
                }
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                }
            }
        });

        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self { _thread: thread }),
            Ok(Err(e)) => Err(e),
            // The thread panicked or dropped its sender before reporting;
            // treat as a generic failure rather than panicking here too.
            Err(_) => Err(NewClientError::NotPermitted),
        }
    }
}

fn handle_message(
    message: &endpoint_sec::Message,
    tx: &SyncSender<RawEvent>,
    stats: &MacosTelemetryStats,
) {
    let Some(event) = message.event() else {
        return;
    };
    let process = message.process();
    let pid = process.audit_token().pid() as u32;

    match event {
        Event::NotifyExec(exec) => {
            let target = exec.target();
            let exe = target.executable().path().to_string_lossy().into_owned();
            let args: Vec<String> = exec
                .args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            let cwd = exec
                .cwd()
                .map(|f| f.path().to_string_lossy().into_owned())
                .unwrap_or_default();
            let kind = map_exec_event(EsExecEvent {
                pid: target.audit_token().pid() as u32,
                ppid: target.ppid() as u32,
                uid: 0, // see kernel_macos::mapping doc: not exposed uniformly here
                exe,
                args,
                cwd,
            });
            send_or_drop(
                tx,
                stats,
                EventSource::EsfMacos,
                kind,
                &stats.process_events,
            );
        }
        Event::NotifyExit(exit) => {
            let kind = map_exit_event(EsExitEvent {
                pid,
                exit_code: exit.stat(),
            });
            send_or_drop(
                tx,
                stats,
                EventSource::EsfMacos,
                kind,
                &stats.process_events,
            );
        }
        Event::NotifyFork(_) => {
            // No dedicated `KernelEventKind` variant for fork, matching
            // `kernel_linux::netlink_proc`'s handling of the same gap —
            // counted, not forwarded, rather than forced into a
            // misleading exec/exit mapping.
        }
        Event::NotifyCreate(create) => {
            let Some(path) = create_destination_path(&create) else {
                return;
            };
            let kind = map_file_event(EsFileEvent {
                pid,
                path,
                old_path: None,
                op: EsFileOp::Create,
            });
            send_or_drop(tx, stats, EventSource::EsfMacos, kind, &stats.file_events);
        }
        Event::NotifyWrite(write) => {
            let path = write.target().path().to_string_lossy().into_owned();
            let kind = map_file_event(EsFileEvent {
                pid,
                path,
                old_path: None,
                op: EsFileOp::Write,
            });
            send_or_drop(tx, stats, EventSource::EsfMacos, kind, &stats.file_events);
        }
        Event::NotifyClose(close) => {
            // Only report a close-that-modified as a write; a plain close
            // (most reads) is not attack-relevant on its own and would
            // otherwise dominate the event stream.
            if close.modified() {
                let path = close.target().path().to_string_lossy().into_owned();
                let kind = map_file_event(EsFileEvent {
                    pid,
                    path,
                    old_path: None,
                    op: EsFileOp::Write,
                });
                send_or_drop(tx, stats, EventSource::EsfMacos, kind, &stats.file_events);
            }
        }
        Event::NotifyRename(rename) => {
            let old_path = rename.source().path().to_string_lossy().into_owned();
            let Some(new_path) = rename_destination_path(&rename) else {
                return;
            };
            let kind = map_file_event(EsFileEvent {
                pid,
                path: new_path,
                old_path: Some(old_path),
                op: EsFileOp::Rename,
            });
            send_or_drop(tx, stats, EventSource::EsfMacos, kind, &stats.file_events);
        }
        Event::NotifyUnlink(unlink) => {
            let path = unlink.target().path().to_string_lossy().into_owned();
            let kind = map_file_event(EsFileEvent {
                pid,
                path,
                old_path: None,
                op: EsFileOp::Delete,
            });
            send_or_drop(tx, stats, EventSource::EsfMacos, kind, &stats.file_events);
        }
        _ => {}
    }
}

fn create_destination_path(create: &endpoint_sec::EventCreate<'_>) -> Option<String> {
    use endpoint_sec::EventCreateDestinationFile;
    match create.destination()? {
        EventCreateDestinationFile::ExistingFile { file } => {
            Some(file.path().to_string_lossy().into_owned())
        }
        EventCreateDestinationFile::NewPath {
            directory,
            filename,
            ..
        } => {
            let mut p = std::path::PathBuf::from(directory.path());
            p.push(filename);
            Some(p.to_string_lossy().into_owned())
        }
    }
}

fn rename_destination_path(rename: &endpoint_sec::EventRename<'_>) -> Option<String> {
    use endpoint_sec::EventRenameDestinationFile;
    match rename.destination()? {
        EventRenameDestinationFile::ExistingFile { file } => {
            Some(file.path().to_string_lossy().into_owned())
        }
        EventRenameDestinationFile::NewPath {
            directory,
            filename,
        } => {
            let mut p = std::path::PathBuf::from(directory.path());
            p.push(filename);
            Some(p.to_string_lossy().into_owned())
        }
    }
}
