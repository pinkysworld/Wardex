//! Real-time ETW (Event Tracing for Windows) consumer.
//!
//! `#[cfg(windows)]`: this module can only build against a Windows target
//! (it depends on `ferrisetw`, which is itself only pulled in under
//! `[target.'cfg(windows)'.dependencies]` in `Cargo.toml`), and it has not
//! been exercised against a live ETW session in this environment — there
//! is no Windows host available here to test against. What has been
//! verified:
//!
//!   * `cargo check --target x86_64-pc-windows-gnu --all-targets` (see the
//!     repo's CONTRIBUTING/CI notes for the exact command used).
//!   * The pure mapping layer this module feeds (`super::mapping`) is
//!     unit-tested on every host, including Linux CI.
//!
//! What has **not** been verified, and should be checked against a live
//! capture before relying on this in production (e.g. with
//! `wevtutil gp <provider> /ge /gm`, or a WPR/xperf trace annotated with
//! field names):
//!
//!   * The exact numeric event IDs used below for `Microsoft-Windows-
//!     Kernel-Process` (ImageLoad), `Microsoft-Windows-Kernel-File`
//!     (create/write/delete/rename), and `Microsoft-Windows-Kernel-Network`
//!     (connect vs. accept) — these providers are manifest-based but
//!     Microsoft does not publish a single stable cross-build table of
//!     event ID → semantic meaning the way it does for the classic kernel
//!     logger providers, and community-documented IDs have shifted across
//!     Windows releases.
//!   * The exact property names for the AMSI ETW provider
//!     (`Microsoft-Antimalware-Scan-Interface`), which is not a MOF/
//!     manifest-published provider — the field names below come from
//!     public research into that provider's undocumented schema, not from
//!     a Microsoft manifest.
//!
//! Every callback here is defensive about that uncertainty: an event ID it
//! doesn't recognize, or a field that fails to parse, is silently skipped
//! rather than treated as an error — the same "degrade quietly, log the
//! reason once at startup" philosophy as `kernel_linux`.
//!
//! Providers subscribed (all via a single real-time `UserTrace` — none of
//! these require the singleton "NT Kernel Logger" session, so this
//! coexists with Sysmon, Defender, or other ETW consumers on the same
//! host):
//!   * `Microsoft-Windows-Kernel-Process` — process start/stop, image load.
//!   * `Microsoft-Windows-Kernel-File` — create/write/delete/rename.
//!   * `Microsoft-Windows-Kernel-Network` — TCP/UDP connect/accept.
//!   * `Microsoft-Windows-DNS-Client` — query completion.
//!   * `Microsoft-Windows-PowerShell` — ScriptBlock logging (event 4104),
//!     gated by [`super::WindowsTelemetryOptions::powershell_scriptblock`].
//!   * `Microsoft-Antimalware-Scan-Interface` — AMSI scan results (this is
//!     *not* an AMSI provider implementation; see the `kernel_windows`
//!     module docs), gated by
//!     [`super::WindowsTelemetryOptions::amsi_etw`].

use std::sync::Arc;
use std::sync::mpsc::SyncSender;

use ferrisetw::EventRecord;
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::UserTrace;

use super::mapping::{
    EtwAmsiScanEvent, EtwDnsEvent, EtwFileEvent, EtwFileOp, EtwImageLoadEvent, EtwNetworkEvent,
    EtwProcessEvent, EtwScriptBlockEvent, map_amsi_scan_event, map_dns_event, map_file_event,
    map_image_load_event, map_network_event, map_process_event, map_scriptblock_event,
};
use super::{RawEvent, WindowsTelemetryOptions, WindowsTelemetryStats, send_or_drop};
use crate::kernel_events::EventSource;

const KERNEL_PROCESS_GUID: &str = "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716";
const KERNEL_FILE_GUID: &str = "EDD08927-9CC4-4E65-B970-C2560FB5C289";
const KERNEL_NETWORK_GUID: &str = "7DD42A49-5329-4832-8DFD-43D979153A88";
const DNS_CLIENT_GUID: &str = "1C95126E-7EEA-49A9-A3FE-A378B03DDB4D";
const POWERSHELL_GUID: &str = "A0C1853B-5C40-4B15-8766-3CF1C58F985A";
const AMSI_GUID: &str = "2A576B87-09A7-520E-C21A-4942F0271D67";

/// Owns the running ETW session. `ferrisetw::trace::UserTrace` stops the
/// session on `Drop`, so this must be kept alive for as long as telemetry
/// should keep flowing — see `WindowsTelemetryHandle` in `mod.rs`.
pub struct EtwSession {
    _trace: UserTrace,
}

impl EtwSession {
    /// Build and start a real-time `UserTrace` covering every provider
    /// enabled by `options`. Returns an error (rather than panicking) if
    /// the trace session can't be opened — e.g. a race where privileges
    /// were revoked between the capability probe and this call, or another
    /// process already owns a same-named session.
    pub fn start(
        tx: SyncSender<RawEvent>,
        stats: Arc<WindowsTelemetryStats>,
        options: &WindowsTelemetryOptions,
    ) -> std::io::Result<Self> {
        let mut builder = UserTrace::new()
            .named("WardexKernelTelemetry".to_string())
            .enable(process_provider(tx.clone(), Arc::clone(&stats)))
            .enable(file_provider(tx.clone(), Arc::clone(&stats)))
            .enable(network_provider(tx.clone(), Arc::clone(&stats)))
            .enable(dns_provider(tx.clone(), Arc::clone(&stats)));

        if options.powershell_scriptblock {
            builder = builder.enable(powershell_provider(tx.clone(), Arc::clone(&stats)));
        }
        if options.amsi_etw {
            builder = builder.enable(amsi_provider(tx, stats));
        }

        let trace = builder.start_and_process().map_err(|e| {
            std::io::Error::other(format!("failed to start ETW UserTrace session: {e:?}"))
        })?;

        Ok(Self { _trace: trace })
    }
}

/// Best-effort helper: several providers carry `ProcessID` explicitly, but
/// when it's missing or fails to parse, `EventRecord`'s own header (the
/// process that logged the event) is usually the right fallback.
fn pid_or_header(parser: &Parser, record: &EventRecord, field: &str) -> u32 {
    parser.try_parse::<u32>(field).unwrap_or_else(|_| record.process_id())
}

fn process_provider(tx: SyncSender<RawEvent>, stats: Arc<WindowsTelemetryStats>) -> Provider {
    Provider::by_guid(KERNEL_PROCESS_GUID)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            let schema = match locator.event_schema(record) {
                Ok(s) => s,
                Err(_) => return,
            };
            let parser = Parser::create(record, &schema);
            let pid = pid_or_header(&parser, record, "ProcessID");

            match record.event_id() {
                // ProcessStart
                1 => {
                    let ppid: u32 = parser.try_parse("ParentProcessID").unwrap_or(0);
                    let image_name: String = parser
                        .try_parse("ImageName")
                        .or_else(|_| parser.try_parse::<String>("ImageFileName"))
                        .unwrap_or_default();
                    let command_line: String =
                        parser.try_parse("CommandLine").unwrap_or_default();
                    let kind = map_process_event(EtwProcessEvent {
                        pid,
                        ppid,
                        image_name,
                        command_line,
                        exit_code: None,
                    });
                    send_or_drop(
                        &tx,
                        &stats,
                        EventSource::EtwWindows,
                        kind,
                        &stats.process_events,
                    );
                }
                // ProcessStop
                2 => {
                    let exit_code: i32 = parser
                        .try_parse::<u32>("ExitCode")
                        .map(|v| v as i32)
                        .unwrap_or(0);
                    let kind = map_process_event(EtwProcessEvent {
                        pid,
                        ppid: 0,
                        image_name: String::new(),
                        command_line: String::new(),
                        exit_code: Some(exit_code),
                    });
                    send_or_drop(
                        &tx,
                        &stats,
                        EventSource::EtwWindows,
                        kind,
                        &stats.process_events,
                    );
                }
                // ImageLoad — event ID per community documentation, not a
                // published Microsoft manifest constant; see module docs.
                5 => {
                    let image_path: String = parser
                        .try_parse("FileName")
                        .or_else(|_| parser.try_parse::<String>("ImageName"))
                        .unwrap_or_default();
                    if !image_path.is_empty() {
                        let kind =
                            map_image_load_event(EtwImageLoadEvent { pid, image_path });
                        send_or_drop(
                            &tx,
                            &stats,
                            EventSource::EtwWindows,
                            kind,
                            &stats.process_events,
                        );
                    }
                }
                _ => {}
            }
        })
        .build()
}

fn file_provider(tx: SyncSender<RawEvent>, stats: Arc<WindowsTelemetryStats>) -> Provider {
    Provider::by_guid(KERNEL_FILE_GUID)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            let schema = match locator.event_schema(record) {
                Ok(s) => s,
                Err(_) => return,
            };
            let parser = Parser::create(record, &schema);
            let pid = record.process_id();
            let path: String = parser
                .try_parse("FileName")
                .or_else(|_| parser.try_parse::<String>("FilePath"))
                .unwrap_or_default();
            if path.is_empty() {
                return;
            }

            // Event IDs below are best-effort and should be verified
            // against a live capture — see module docs.
            let op = match record.event_id() {
                12 => Some(EtwFileOp::Create),
                17 => Some(EtwFileOp::Write),
                23 => Some(EtwFileOp::Delete),
                26 | 27 => Some(EtwFileOp::Rename),
                _ => None,
            };
            let Some(op) = op else { return };

            let old_path = if op == EtwFileOp::Rename {
                parser.try_parse::<String>("PreviousFileName").ok()
            } else {
                None
            };
            let bytes_written = if op == EtwFileOp::Write {
                parser.try_parse::<u32>("IoSize").map(u64::from).ok()
            } else {
                None
            };

            let kind = map_file_event(EtwFileEvent {
                pid,
                path,
                old_path,
                op,
                bytes_written,
            });
            send_or_drop(&tx, &stats, EventSource::EtwWindows, kind, &stats.file_events);
        })
        .build()
}

fn network_provider(tx: SyncSender<RawEvent>, stats: Arc<WindowsTelemetryStats>) -> Provider {
    Provider::by_guid(KERNEL_NETWORK_GUID)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            let schema = match locator.event_schema(record) {
                Ok(s) => s,
                Err(_) => return,
            };
            let parser = Parser::create(record, &schema);

            // Event IDs below are best-effort and should be verified
            // against a live capture — see module docs. TCP/UDP "connect"
            // and "accept" tasks are both present in this provider under
            // different numeric IDs per Windows release.
            let is_accept = match record.event_id() {
                12 => false, // connect
                15 => true,  // accept
                _ => return,
            };

            let pid = record.process_id();
            let src_addr: String = parser
                .try_parse("saddr")
                .or_else(|_| parser.try_parse::<String>("SourceAddress"))
                .unwrap_or_default();
            let dst_addr: String = parser
                .try_parse("daddr")
                .or_else(|_| parser.try_parse::<String>("DestAddress"))
                .unwrap_or_default();
            let src_port: u16 = parser
                .try_parse("sport")
                .or_else(|_| parser.try_parse::<u16>("SourcePort"))
                .unwrap_or(0);
            let dst_port: u16 = parser
                .try_parse("dport")
                .or_else(|_| parser.try_parse::<u16>("DestPort"))
                .unwrap_or(0);
            if src_addr.is_empty() && dst_addr.is_empty() {
                return;
            }

            let kind = map_network_event(EtwNetworkEvent {
                pid,
                src_addr,
                src_port,
                dst_addr,
                dst_port,
                protocol: "tcp".to_string(),
                is_accept,
            });
            send_or_drop(
                &tx,
                &stats,
                EventSource::EtwWindows,
                kind,
                &stats.network_events,
            );
        })
        .build()
}

fn dns_provider(tx: SyncSender<RawEvent>, stats: Arc<WindowsTelemetryStats>) -> Provider {
    Provider::by_guid(DNS_CLIENT_GUID)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            let schema = match locator.event_schema(record) {
                Ok(s) => s,
                Err(_) => return,
            };
            let parser = Parser::create(record, &schema);
            let query_name: String = match parser.try_parse("QueryName") {
                Ok(n) => n,
                Err(_) => return,
            };
            let query_type: String = parser
                .try_parse::<u32>("QueryType")
                .map(|t| t.to_string())
                .unwrap_or_default();
            let results: Vec<String> = parser
                .try_parse::<String>("QueryResults")
                .map(|s| {
                    s.split(';')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default();

            let kind = map_dns_event(EtwDnsEvent {
                pid: record.process_id(),
                query_name,
                query_type,
                results,
            });
            send_or_drop(&tx, &stats, EventSource::EtwWindows, kind, &stats.dns_events);
        })
        .build()
}

fn powershell_provider(tx: SyncSender<RawEvent>, stats: Arc<WindowsTelemetryStats>) -> Provider {
    Provider::by_guid(POWERSHELL_GUID)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            // ScriptBlock logging (Event ID 4104). Field names here match
            // the well-documented public Windows Event Log schema for that
            // event (independent of ETW vs. classic Event Log delivery).
            if record.event_id() != 4104 {
                return;
            }
            let schema = match locator.event_schema(record) {
                Ok(s) => s,
                Err(_) => return,
            };
            let parser = Parser::create(record, &schema);
            let script_text: String = match parser.try_parse("ScriptBlockText") {
                Ok(s) => s,
                Err(_) => return,
            };
            let script_block_id: String =
                parser.try_parse("ScriptBlockId").unwrap_or_default();
            let message_number: u32 = parser.try_parse("MessageNumber").unwrap_or(1);
            let message_total: u32 = parser.try_parse("MessageTotal").unwrap_or(1);

            let kind = map_scriptblock_event(EtwScriptBlockEvent {
                pid: record.process_id(),
                script_block_id,
                message_number,
                message_total,
                script_text,
            });
            send_or_drop(
                &tx,
                &stats,
                EventSource::EtwWindows,
                kind,
                &stats.scriptblock_events,
            );
        })
        .build()
}

fn amsi_provider(tx: SyncSender<RawEvent>, stats: Arc<WindowsTelemetryStats>) -> Provider {
    Provider::by_guid(AMSI_GUID)
        .add_callback(move |record: &EventRecord, locator: &SchemaLocator| {
            let schema = match locator.event_schema(record) {
                Ok(s) => s,
                Err(_) => return,
            };
            let parser = Parser::create(record, &schema);
            // Field names come from public research into this provider's
            // undocumented schema, not a Microsoft manifest — see module
            // docs. `Content`/`Content Name` are absent on plenty of scan
            // events (e.g. clean, non-buffer scans); skip rather than
            // guess when the essentials are missing.
            let app_name: String = parser
                .try_parse("App Name")
                .or_else(|_| parser.try_parse::<String>("AppName"))
                .unwrap_or_default();
            if app_name.is_empty() {
                return;
            }
            let content_name: String = parser
                .try_parse("Content Name")
                .or_else(|_| parser.try_parse::<String>("ContentName"))
                .unwrap_or_default();
            let content_preview: String = parser
                .try_parse("Content")
                .unwrap_or_default();
            let result_code: u32 = parser
                .try_parse("Scan Result")
                .or_else(|_| parser.try_parse::<u32>("ScanResult"))
                .unwrap_or(0);

            let kind = map_amsi_scan_event(EtwAmsiScanEvent {
                pid: record.process_id(),
                app_name,
                content_name,
                content_preview,
                result_code,
            });
            send_or_drop(&tx, &stats, EventSource::AmsiWindows, kind, &stats.amsi_events);
        })
        .build()
}
