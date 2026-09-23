//! Pure, platform-independent mapping from ETW-extracted field structs to
//! the normalized [`KernelEventKind`].
//!
//! Every function here takes plain data (no ETW types, no Windows API
//! calls) and returns a `KernelEventKind`, so the mapping logic — which is
//! the part most worth getting right and easiest to get wrong (field
//! names, units, which side is source/destination) — is exercised by unit
//! tests on every CI host, including Linux, independent of whether the
//! real ETW consumer in `etw_consumer.rs` (`#[cfg(windows)]`) can be built
//! or run there. `etw_consumer.rs` only has to parse ETW schema fields into
//! these structs and hand them to the functions below.

use crate::kernel_events::{AmsiResult, KernelEventKind, RegistryOp};

/// A decoded `Microsoft-Windows-Kernel-Process` process start/stop event
/// (event IDs 1 "start" / 2 "stop" in that provider's manifest).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtwProcessEvent {
    pub pid: u32,
    pub ppid: u32,
    pub image_name: String,
    pub command_line: String,
    pub exit_code: Option<i32>,
}

/// A decoded `Microsoft-Windows-Kernel-Process` image-load event (event ID
/// 5 "ImageLoad" in that provider's manifest).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtwImageLoadEvent {
    pub pid: u32,
    pub image_path: String,
}

/// File operation kind, decoded from a `Microsoft-Windows-Kernel-File`
/// event ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtwFileOp {
    Create,
    Write,
    Delete,
    Rename,
}

/// A decoded `Microsoft-Windows-Kernel-File` event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtwFileEvent {
    pub pid: u32,
    pub path: String,
    /// Populated only for `Rename` (the pre-rename path); `path` holds the
    /// post-rename path in that case.
    pub old_path: Option<String>,
    pub op: EtwFileOp,
    pub bytes_written: Option<u64>,
}

/// A decoded `Microsoft-Windows-Kernel-Network` TCP/UDP event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtwNetworkEvent {
    pub pid: u32,
    pub src_addr: String,
    pub src_port: u16,
    pub dst_addr: String,
    pub dst_port: u16,
    pub protocol: String,
    /// `true` for an inbound "accept" event, `false` for an outbound
    /// "connect" event.
    pub is_accept: bool,
}

/// A decoded `Microsoft-Windows-DNS-Client` query-completed event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtwDnsEvent {
    pub pid: u32,
    pub query_name: String,
    pub query_type: String,
    pub results: Vec<String>,
}

/// A decoded PowerShell ScriptBlock logging event (event ID 4104 from the
/// `Microsoft-Windows-PowerShell` provider).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtwScriptBlockEvent {
    pub pid: u32,
    pub script_block_id: String,
    pub message_number: u32,
    pub message_total: u32,
    pub script_text: String,
}

/// A decoded `Microsoft-Antimalware-Scan-Interface` scan event. This is
/// telemetry *about* AMSI scans performed by whichever real AMSI provider
/// is registered on the system (typically Windows Defender) — not a
/// provider implementation of our own. See `docs/runbooks/windows-agent.md`
/// for why implementing an actual AMSI provider is out of scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtwAmsiScanEvent {
    pub pid: u32,
    pub app_name: String,
    pub content_name: String,
    pub content_preview: String,
    /// Raw `AMSI_RESULT` value from the ETW payload.
    pub result_code: u32,
}

/// A decoded registry mutation event (`Microsoft-Windows-Kernel-Registry`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtwRegistryEvent {
    pub pid: u32,
    pub key_path: String,
    pub value_name: String,
    pub value_data: String,
    pub op: RegistryOp,
}

pub fn map_process_event(ev: EtwProcessEvent) -> KernelEventKind {
    match ev.exit_code {
        Some(code) => KernelEventKind::ProcessExit {
            pid: ev.pid,
            exit_code: code,
        },
        None => KernelEventKind::ProcessExec {
            pid: ev.pid,
            ppid: ev.ppid,
            // ETW's Kernel-Process provider does not carry a POSIX-style
            // uid; Windows has no equivalent primitive, so this is left at
            // 0 and callers should not treat it as meaningful the way the
            // Linux mapping's `uid` field is.
            uid: 0,
            exe: ev.image_name,
            args: split_command_line(&ev.command_line),
            cwd: String::new(),
            container_id: None,
        },
    }
}

pub fn map_image_load_event(ev: EtwImageLoadEvent) -> KernelEventKind {
    KernelEventKind::ModuleLoad {
        pid: ev.pid,
        path: ev.image_path,
        sha256: None,
    }
}

pub fn map_file_event(ev: EtwFileEvent) -> KernelEventKind {
    match ev.op {
        EtwFileOp::Create => KernelEventKind::FileOpen {
            pid: ev.pid,
            path: ev.path,
            flags: 0,
        },
        EtwFileOp::Write => KernelEventKind::FileWrite {
            pid: ev.pid,
            path: ev.path,
            bytes_written: ev.bytes_written.unwrap_or(0),
        },
        EtwFileOp::Delete => KernelEventKind::FileDelete {
            pid: ev.pid,
            path: ev.path,
        },
        EtwFileOp::Rename => KernelEventKind::FileRename {
            pid: ev.pid,
            old_path: ev.old_path.unwrap_or_default(),
            new_path: ev.path,
        },
    }
}

pub fn map_network_event(ev: EtwNetworkEvent) -> KernelEventKind {
    if ev.is_accept {
        KernelEventKind::NetworkAccept {
            pid: ev.pid,
            src_addr: ev.src_addr,
            src_port: ev.src_port,
            dst_addr: ev.dst_addr,
            dst_port: ev.dst_port,
            protocol: ev.protocol,
        }
    } else {
        KernelEventKind::NetworkConnect {
            pid: ev.pid,
            src_addr: ev.src_addr,
            src_port: ev.src_port,
            dst_addr: ev.dst_addr,
            dst_port: ev.dst_port,
            protocol: ev.protocol,
        }
    }
}

pub fn map_dns_event(ev: EtwDnsEvent) -> KernelEventKind {
    KernelEventKind::DnsQuery {
        pid: ev.pid,
        domain: ev.query_name,
        query_type: ev.query_type,
        response_addrs: ev.results,
    }
}

pub fn map_scriptblock_event(ev: EtwScriptBlockEvent) -> KernelEventKind {
    KernelEventKind::ScriptBlockExecution {
        pid: ev.pid,
        script_block_id: ev.script_block_id,
        message_number: ev.message_number,
        message_total: ev.message_total,
        script_text: ev.script_text,
    }
}

pub fn map_registry_event(ev: EtwRegistryEvent) -> KernelEventKind {
    KernelEventKind::RegistryMutate {
        pid: ev.pid,
        key: ev.key_path,
        value_name: ev.value_name,
        value_data: ev.value_data,
        operation: ev.op,
    }
}

/// `AMSI_RESULT` values, from `amsi.h`. Anything at or above
/// `AMSI_RESULT_DETECTED` (32768) is a detection; values are otherwise a
/// confidence score for "clean".
const AMSI_RESULT_CLEAN: u32 = 0;
const AMSI_RESULT_NOT_DETECTED: u32 = 1;
const AMSI_RESULT_BLOCKED_BY_ADMIN_START: u32 = 16384;
const AMSI_RESULT_BLOCKED_BY_ADMIN_END: u32 = 20479;
const AMSI_RESULT_DETECTED: u32 = 32768;

pub fn map_amsi_scan_event(ev: EtwAmsiScanEvent) -> KernelEventKind {
    let result = if ev.result_code >= AMSI_RESULT_DETECTED {
        AmsiResult::Detected
    } else if (AMSI_RESULT_BLOCKED_BY_ADMIN_START..=AMSI_RESULT_BLOCKED_BY_ADMIN_END)
        .contains(&ev.result_code)
    {
        AmsiResult::BlockedByAdmin
    } else if ev.result_code == AMSI_RESULT_NOT_DETECTED {
        AmsiResult::NotDetected
    } else {
        debug_assert!(
            ev.result_code == AMSI_RESULT_CLEAN || ev.result_code < AMSI_RESULT_NOT_DETECTED,
            "unrecognized AMSI_RESULT {}, treating as clean",
            ev.result_code
        );
        AmsiResult::Clean
    };
    KernelEventKind::AmsiScan {
        pid: ev.pid,
        app_name: ev.app_name,
        content_preview: ev.content_preview,
        result,
    }
}

/// Best-effort split of a Windows command line into argv-style tokens.
/// Windows has no single canonical quoting rule (each process parses its
/// own argv from the raw string via `CommandLineToArgvW`-like logic), so
/// this is intentionally simple: split on whitespace, respecting double
/// quotes. Good enough for MITRE keyword matching in
/// `kernel_events::suggest_mitre`; not a faithful `CommandLineToArgvW`
/// reimplementation.
fn split_command_line(cmd: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for c in cmd.chars() {
        match c {
            '"' => in_quotes = !in_quotes,
            c if c.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        args.push(current);
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_start_maps_to_exec() {
        let kind = map_process_event(EtwProcessEvent {
            pid: 100,
            ppid: 4,
            image_name: r"C:\Windows\System32\cmd.exe".into(),
            command_line: r#"cmd.exe /c "whoami""#.into(),
            exit_code: None,
        });
        match kind {
            KernelEventKind::ProcessExec {
                pid,
                ppid,
                exe,
                args,
                ..
            } => {
                assert_eq!(pid, 100);
                assert_eq!(ppid, 4);
                assert_eq!(exe, r"C:\Windows\System32\cmd.exe");
                assert_eq!(args, vec!["cmd.exe", "/c", "whoami"]);
            }
            other => panic!("expected ProcessExec, got {other:?}"),
        }
    }

    #[test]
    fn process_stop_maps_to_exit() {
        let kind = map_process_event(EtwProcessEvent {
            pid: 100,
            ppid: 4,
            image_name: "cmd.exe".into(),
            command_line: String::new(),
            exit_code: Some(1),
        });
        assert!(matches!(
            kind,
            KernelEventKind::ProcessExit {
                pid: 100,
                exit_code: 1
            }
        ));
    }

    #[test]
    fn image_load_maps_module_load() {
        let kind = map_image_load_event(EtwImageLoadEvent {
            pid: 200,
            image_path: r"C:\evil\payload.dll".into(),
        });
        assert!(matches!(kind, KernelEventKind::ModuleLoad { pid: 200, .. }));
    }

    #[test]
    fn file_create_maps_to_file_open() {
        let kind = map_file_event(EtwFileEvent {
            pid: 1,
            path: r"C:\Users\a\f.txt".into(),
            old_path: None,
            op: EtwFileOp::Create,
            bytes_written: None,
        });
        assert!(matches!(kind, KernelEventKind::FileOpen { pid: 1, .. }));
    }

    #[test]
    fn file_write_carries_byte_count() {
        let kind = map_file_event(EtwFileEvent {
            pid: 1,
            path: "f".into(),
            old_path: None,
            op: EtwFileOp::Write,
            bytes_written: Some(4096),
        });
        match kind {
            KernelEventKind::FileWrite { bytes_written, .. } => assert_eq!(bytes_written, 4096),
            other => panic!("expected FileWrite, got {other:?}"),
        }
    }

    #[test]
    fn file_rename_carries_both_paths() {
        let kind = map_file_event(EtwFileEvent {
            pid: 1,
            path: "new.txt".into(),
            old_path: Some("old.txt".into()),
            op: EtwFileOp::Rename,
            bytes_written: None,
        });
        match kind {
            KernelEventKind::FileRename {
                old_path, new_path, ..
            } => {
                assert_eq!(old_path, "old.txt");
                assert_eq!(new_path, "new.txt");
            }
            other => panic!("expected FileRename, got {other:?}"),
        }
    }

    #[test]
    fn network_connect_vs_accept() {
        let base = EtwNetworkEvent {
            pid: 1,
            src_addr: "10.0.0.1".into(),
            src_port: 1234,
            dst_addr: "10.0.0.2".into(),
            dst_port: 443,
            protocol: "tcp".into(),
            is_accept: false,
        };
        assert!(matches!(
            map_network_event(base.clone()),
            KernelEventKind::NetworkConnect { .. }
        ));
        let mut accept = base;
        accept.is_accept = true;
        assert!(matches!(
            map_network_event(accept),
            KernelEventKind::NetworkAccept { .. }
        ));
    }

    #[test]
    fn dns_event_carries_results() {
        let kind = map_dns_event(EtwDnsEvent {
            pid: 1,
            query_name: "example.com".into(),
            query_type: "A".into(),
            results: vec!["93.184.216.34".into()],
        });
        match kind {
            KernelEventKind::DnsQuery {
                domain,
                response_addrs,
                ..
            } => {
                assert_eq!(domain, "example.com");
                assert_eq!(response_addrs, vec!["93.184.216.34"]);
            }
            other => panic!("expected DnsQuery, got {other:?}"),
        }
    }

    #[test]
    fn scriptblock_event_maps_directly() {
        let kind = map_scriptblock_event(EtwScriptBlockEvent {
            pid: 1,
            script_block_id: "abc-123".into(),
            message_number: 1,
            message_total: 1,
            script_text: "Invoke-Mimikatz".into(),
        });
        assert!(matches!(kind, KernelEventKind::ScriptBlockExecution { .. }));
        let mitre = crate::kernel_events::suggest_mitre(&kind);
        assert!(mitre.iter().any(|t| t.technique_id == "T1059"));
    }

    #[test]
    fn amsi_clean_result() {
        let kind = map_amsi_scan_event(EtwAmsiScanEvent {
            pid: 1,
            app_name: "powershell.exe".into(),
            content_name: "".into(),
            content_preview: "Get-Process".into(),
            result_code: AMSI_RESULT_CLEAN,
        });
        assert!(matches!(
            kind,
            KernelEventKind::AmsiScan {
                result: AmsiResult::Clean,
                ..
            }
        ));
    }

    #[test]
    fn amsi_detected_result() {
        let kind = map_amsi_scan_event(EtwAmsiScanEvent {
            pid: 1,
            app_name: "powershell.exe".into(),
            content_name: "".into(),
            content_preview: "Invoke-Mimikatz".into(),
            result_code: 32768,
        });
        assert!(matches!(
            kind,
            KernelEventKind::AmsiScan {
                result: AmsiResult::Detected,
                ..
            }
        ));
    }

    #[test]
    fn amsi_blocked_by_admin_range() {
        let kind = map_amsi_scan_event(EtwAmsiScanEvent {
            pid: 1,
            app_name: "wscript.exe".into(),
            content_name: "".into(),
            content_preview: "".into(),
            result_code: 20000,
        });
        assert!(matches!(
            kind,
            KernelEventKind::AmsiScan {
                result: AmsiResult::BlockedByAdmin,
                ..
            }
        ));
    }

    #[test]
    fn registry_event_maps_operation() {
        let kind = map_registry_event(EtwRegistryEvent {
            pid: 1,
            key_path: r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run".into(),
            value_name: "evil".into(),
            value_data: r"C:\evil.exe".into(),
            op: RegistryOp::SetValue,
        });
        assert!(matches!(kind, KernelEventKind::RegistryMutate { .. }));
        let mitre = crate::kernel_events::suggest_mitre(&kind);
        assert!(mitre.iter().any(|t| t.technique_id == "T1547"));
    }

    #[test]
    fn split_command_line_respects_quotes() {
        assert_eq!(
            split_command_line(r#"powershell.exe -Command "Get-Process | Out-Null""#),
            vec!["powershell.exe", "-Command", "Get-Process | Out-Null"]
        );
    }

    #[test]
    fn split_command_line_empty() {
        assert!(split_command_line("").is_empty());
    }
}
