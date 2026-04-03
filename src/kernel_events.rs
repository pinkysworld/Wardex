//! Unified kernel-level event abstraction for cross-platform XDR monitoring.
//!
//! Provides a `KernelEvent` enum that normalises eBPF (Linux), Endpoint Security
//! Framework (macOS), and ETW (Windows) telemetry into a single stream consumable
//! by the detection, correlation, and UEBA engines.
#![allow(non_snake_case)]

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

// ── MITRE ATT&CK technique tags ─────────────────────────────────

/// Compact reference to a MITRE ATT&CK technique for inline tagging.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct MitreTechnique {
    pub tactic: String,
    pub technique_id: String,
    pub technique_name: String,
}

impl MitreTechnique {
    pub fn new(tactic: &str, id: &str, name: &str) -> Self {
        Self { tactic: tactic.into(), technique_id: id.into(), technique_name: name.into() }
    }
}

// Common technique constructors for reuse across collectors.
pub fn T1059_COMMAND_INTERPRETER() -> MitreTechnique {
    MitreTechnique::new("Execution", "T1059", "Command and Scripting Interpreter")
}
pub fn T1055_PROCESS_INJECTION() -> MitreTechnique {
    MitreTechnique::new("Defense Evasion", "T1055", "Process Injection")
}
pub fn T1071_APP_LAYER_PROTOCOL() -> MitreTechnique {
    MitreTechnique::new("Command and Control", "T1071", "Application Layer Protocol")
}
pub fn T1053_SCHEDULED_TASK() -> MitreTechnique {
    MitreTechnique::new("Persistence", "T1053", "Scheduled Task/Job")
}
pub fn T1547_BOOT_AUTOSTART() -> MitreTechnique {
    MitreTechnique::new("Persistence", "T1547", "Boot or Logon Autostart Execution")
}
pub fn T1543_CREATE_MODIFY_SERVICE() -> MitreTechnique {
    MitreTechnique::new("Persistence", "T1543", "Create or Modify System Process")
}
pub fn T1070_INDICATOR_REMOVAL() -> MitreTechnique {
    MitreTechnique::new("Defense Evasion", "T1070", "Indicator Removal")
}
pub fn T1027_OBFUSCATED_FILES() -> MitreTechnique {
    MitreTechnique::new("Defense Evasion", "T1027", "Obfuscated Files or Information")
}
pub fn T1082_SYSTEM_INFO_DISCOVERY() -> MitreTechnique {
    MitreTechnique::new("Discovery", "T1082", "System Information Discovery")
}
pub fn T1003_OS_CREDENTIAL_DUMPING() -> MitreTechnique {
    MitreTechnique::new("Credential Access", "T1003", "OS Credential Dumping")
}
pub fn T1021_REMOTE_SERVICES() -> MitreTechnique {
    MitreTechnique::new("Lateral Movement", "T1021", "Remote Services")
}
pub fn T1041_EXFIL_C2() -> MitreTechnique {
    MitreTechnique::new("Exfiltration", "T1041", "Exfiltration Over C2 Channel")
}
pub fn T1562_IMPAIR_DEFENSES() -> MitreTechnique {
    MitreTechnique::new("Defense Evasion", "T1562", "Impair Defenses")
}
pub fn T1112_MODIFY_REGISTRY() -> MitreTechnique {
    MitreTechnique::new("Defense Evasion", "T1112", "Modify Registry")
}
pub fn T1546_EVENT_TRIGGERED() -> MitreTechnique {
    MitreTechnique::new("Persistence", "T1546", "Event Triggered Execution")
}
pub fn T1569_SYSTEM_SERVICES() -> MitreTechnique {
    MitreTechnique::new("Execution", "T1569", "System Services")
}

// ── Kernel event types ──────────────────────────────────────────

/// Severity classification for kernel events.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum KernelEventSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Source platform that generated the event.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventSource {
    EbpfLinux,
    AuditdLinux,
    SelinuxLinux,
    EsfMacos,
    TccMacos,
    GatekeeperMacos,
    EtwWindows,
    AmsiWindows,
    SysmonWindows,
}

/// Unified kernel-level event abstraction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelEvent {
    /// Monotonic event ID within this agent's session.
    pub id: u64,
    /// UTC timestamp (epoch millis).
    pub timestamp_ms: u64,
    /// Which OS subsystem produced this event.
    pub source: EventSource,
    /// Hostname (for fleet correlation).
    pub hostname: String,
    /// Agent UID (for fleet correlation).
    pub agent_uid: Option<String>,
    /// The event payload.
    pub kind: KernelEventKind,
    /// Pre-computed severity for triage.
    pub severity: KernelEventSeverity,
    /// MITRE ATT&CK mappings relevant to this event.
    pub mitre_techniques: Vec<MitreTechnique>,
}

/// Discriminated union of all kernel event types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KernelEventKind {
    // ── Process lifecycle ────────────────────────────────────
    ProcessExec {
        pid: u32,
        ppid: u32,
        uid: u32,
        exe: String,
        args: Vec<String>,
        cwd: String,
        /// Container ID if running inside a container.
        container_id: Option<String>,
    },
    ProcessExit {
        pid: u32,
        exit_code: i32,
    },

    // ── File operations ──────────────────────────────────────
    FileOpen {
        pid: u32,
        path: String,
        flags: u32,
    },
    FileWrite {
        pid: u32,
        path: String,
        bytes_written: u64,
    },
    FileDelete {
        pid: u32,
        path: String,
    },
    FileRename {
        pid: u32,
        old_path: String,
        new_path: String,
    },
    FilePermissionChange {
        pid: u32,
        path: String,
        old_mode: u32,
        new_mode: u32,
    },

    // ── Network ──────────────────────────────────────────────
    NetworkConnect {
        pid: u32,
        src_addr: String,
        src_port: u16,
        dst_addr: String,
        dst_port: u16,
        protocol: String,
    },
    NetworkAccept {
        pid: u32,
        src_addr: String,
        src_port: u16,
        dst_addr: String,
        dst_port: u16,
        protocol: String,
    },
    DnsQuery {
        pid: u32,
        domain: String,
        query_type: String,
        response_addrs: Vec<String>,
    },

    // ── Registry (Windows) ───────────────────────────────────
    RegistryMutate {
        pid: u32,
        key: String,
        value_name: String,
        value_data: String,
        operation: RegistryOp,
    },

    // ── Module / driver loading ──────────────────────────────
    ModuleLoad {
        pid: u32,
        path: String,
        /// SHA-256 of the loaded module if available.
        sha256: Option<String>,
    },
    DriverLoad {
        driver_name: String,
        path: String,
        sha256: Option<String>,
        signed: bool,
    },

    // ── Named pipe (Windows C2 detection) ────────────────────
    NamedPipeCreate {
        pid: u32,
        pipe_name: String,
    },
    NamedPipeConnect {
        pid: u32,
        pipe_name: String,
    },

    // ── AMSI (Windows script scanning) ───────────────────────
    AmsiScan {
        pid: u32,
        app_name: String,
        content_preview: String,
        result: AmsiResult,
    },

    // ── WMI persistence (Windows) ────────────────────────────
    WmiPersistence {
        filter_name: String,
        consumer_name: String,
        query: String,
    },

    // ── macOS-specific ───────────────────────────────────────
    TccAccess {
        /// The service that was granted/denied access.
        service: String,
        /// Bundle identifier of the requesting app.
        client: String,
        allowed: bool,
    },
    GatekeeperVerdict {
        path: String,
        allowed: bool,
        reason: String,
    },
    SystemExtensionEvent {
        identifier: String,
        team_id: String,
        loaded: bool,
    },

    // ── SELinux / AppArmor ───────────────────────────────────
    SecurityDenial {
        /// Source context (SELinux scontext or AppArmor profile).
        source: String,
        target: String,
        permission: String,
        action: String,
    },

    // ── Container events (Linux) ─────────────────────────────
    ContainerEvent {
        container_id: String,
        runtime: String,
        event_type: ContainerEventType,
        image: Option<String>,
    },
}

/// Registry operation type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RegistryOp {
    Create,
    SetValue,
    DeleteKey,
    DeleteValue,
    Rename,
}

/// AMSI scan result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AmsiResult {
    Clean,
    NotDetected,
    Detected,
    BlockedByAdmin,
}

/// Container lifecycle event type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ContainerEventType {
    Start,
    Stop,
    Pause,
    Unpause,
    Die,
    OomKill,
}

// ── Kernel event stream ─────────────────────────────────────────

/// Thread-safe ring buffer for kernel events.
#[derive(Clone)]
pub struct KernelEventStream {
    inner: Arc<Mutex<KernelEventStreamInner>>,
}

struct KernelEventStreamInner {
    events: VecDeque<KernelEvent>,
    capacity: usize,
    next_id: u64,
}

impl KernelEventStream {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(KernelEventStreamInner {
                events: VecDeque::with_capacity(capacity),
                capacity,
                next_id: 1,
            })),
        }
    }

    /// Push a new event into the stream, assigning a sequential ID.
    pub fn push(&self, mut event: KernelEvent) {
        let mut inner = self.inner.lock().unwrap();
        event.id = inner.next_id;
        inner.next_id += 1;
        if inner.events.len() >= inner.capacity {
            inner.events.pop_front();
        }
        inner.events.push_back(event);
    }

    /// Return the most recent `limit` events, optionally filtered by kind.
    pub fn recent(&self, limit: usize, type_filter: Option<&[&str]>) -> Vec<KernelEvent> {
        let inner = self.inner.lock().unwrap();
        let iter = inner.events.iter().rev();
        let filtered: Vec<_> = if let Some(types) = type_filter {
            iter.filter(|e| {
                let kind_name = kernel_event_kind_name(&e.kind);
                types.iter().any(|t| kind_name.eq_ignore_ascii_case(t))
            })
            .take(limit)
            .cloned()
            .collect()
        } else {
            iter.take(limit).cloned().collect()
        };
        filtered.into_iter().rev().collect()
    }

    /// Total events ever pushed (including evicted ones).
    pub fn total_count(&self) -> u64 {
        let inner = self.inner.lock().unwrap();
        inner.next_id.saturating_sub(1)
    }

    /// Current buffered event count.
    pub fn buffered_count(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.events.len()
    }

    /// Return events with ID greater than `since_id`.
    pub fn since(&self, since_id: u64, limit: usize) -> Vec<KernelEvent> {
        let inner = self.inner.lock().unwrap();
        inner
            .events
            .iter()
            .filter(|e| e.id > since_id)
            .take(limit)
            .cloned()
            .collect()
    }
}

/// Helper: return a short string name for a `KernelEventKind` variant.
pub fn kernel_event_kind_name(kind: &KernelEventKind) -> &'static str {
    match kind {
        KernelEventKind::ProcessExec { .. } => "exec",
        KernelEventKind::ProcessExit { .. } => "exit",
        KernelEventKind::FileOpen { .. } => "file_open",
        KernelEventKind::FileWrite { .. } => "file_write",
        KernelEventKind::FileDelete { .. } => "file_delete",
        KernelEventKind::FileRename { .. } => "file_rename",
        KernelEventKind::FilePermissionChange { .. } => "file_chmod",
        KernelEventKind::NetworkConnect { .. } => "connect",
        KernelEventKind::NetworkAccept { .. } => "accept",
        KernelEventKind::DnsQuery { .. } => "dns",
        KernelEventKind::RegistryMutate { .. } => "registry",
        KernelEventKind::ModuleLoad { .. } => "module_load",
        KernelEventKind::DriverLoad { .. } => "driver_load",
        KernelEventKind::NamedPipeCreate { .. } => "pipe_create",
        KernelEventKind::NamedPipeConnect { .. } => "pipe_connect",
        KernelEventKind::AmsiScan { .. } => "amsi",
        KernelEventKind::WmiPersistence { .. } => "wmi",
        KernelEventKind::TccAccess { .. } => "tcc",
        KernelEventKind::GatekeeperVerdict { .. } => "gatekeeper",
        KernelEventKind::SystemExtensionEvent { .. } => "sysext",
        KernelEventKind::SecurityDenial { .. } => "denial",
        KernelEventKind::ContainerEvent { .. } => "container",
    }
}

/// Suggest MITRE techniques for a kernel event kind.
pub fn suggest_mitre(kind: &KernelEventKind) -> Vec<MitreTechnique> {
    match kind {
        KernelEventKind::ProcessExec { exe, args, .. } => {
            let mut v = vec![];
            let exe_lower = exe.to_lowercase();
            let args_str = args.join(" ").to_lowercase();
            if exe_lower.contains("powershell")
                || exe_lower.contains("cmd.exe")
                || exe_lower.contains("bash")
                || exe_lower.contains("python")
                || exe_lower.contains("wscript")
                || exe_lower.contains("cscript")
            {
                v.push(T1059_COMMAND_INTERPRETER());
            }
            if args_str.contains("-encodedcommand")
                || args_str.contains("-enc ")
                || args_str.contains("base64")
            {
                v.push(T1027_OBFUSCATED_FILES());
            }
            if exe_lower.contains("mimikatz")
                || exe_lower.contains("procdump")
                || (exe_lower.contains("rundll32") && args_str.contains("comsvcs"))
            {
                v.push(T1003_OS_CREDENTIAL_DUMPING());
            }
            v
        }
        KernelEventKind::NetworkConnect { dst_port, .. } => {
            let mut v = vec![T1071_APP_LAYER_PROTOCOL()];
            if *dst_port == 3389 || *dst_port == 22 || *dst_port == 5985 || *dst_port == 5986 {
                v.push(T1021_REMOTE_SERVICES());
            }
            v
        }
        KernelEventKind::RegistryMutate { key, .. } => {
            let mut v = vec![T1112_MODIFY_REGISTRY()];
            let k = key.to_lowercase();
            if k.contains("\\run\\") || k.contains("\\runonce\\") || k.contains("\\currentversion\\run") {
                v.push(T1547_BOOT_AUTOSTART());
            }
            v
        }
        KernelEventKind::NamedPipeCreate { pipe_name, .. }
        | KernelEventKind::NamedPipeConnect { pipe_name, .. } => {
            let p = pipe_name.to_lowercase();
            let mut v = vec![];
            // Known C2 framework named pipes
            if p.contains("msagent_") || p.contains("postex_") || p.contains("status_") {
                v.push(T1071_APP_LAYER_PROTOCOL());
            }
            v
        }
        KernelEventKind::AmsiScan { result, .. } => {
            if *result == AmsiResult::Detected || *result == AmsiResult::BlockedByAdmin {
                vec![T1059_COMMAND_INTERPRETER(), T1027_OBFUSCATED_FILES()]
            } else {
                vec![]
            }
        }
        KernelEventKind::WmiPersistence { .. } => {
            vec![T1546_EVENT_TRIGGERED()]
        }
        KernelEventKind::DriverLoad { signed, .. } => {
            if !signed {
                vec![T1562_IMPAIR_DEFENSES()]
            } else {
                vec![]
            }
        }
        KernelEventKind::ModuleLoad { .. } => vec![T1055_PROCESS_INJECTION()],
        KernelEventKind::SecurityDenial { .. } => vec![T1562_IMPAIR_DEFENSES()],
        KernelEventKind::ContainerEvent { event_type, .. } => {
            if *event_type == ContainerEventType::OomKill {
                vec![] // resource exhaustion, not necessarily attack
            } else {
                vec![]
            }
        }
        KernelEventKind::TccAccess { allowed, .. } => {
            if !allowed {
                vec![T1562_IMPAIR_DEFENSES()]
            } else {
                vec![T1082_SYSTEM_INFO_DISCOVERY()]
            }
        }
        KernelEventKind::GatekeeperVerdict { allowed, .. } => {
            if !*allowed {
                vec![T1562_IMPAIR_DEFENSES()]
            } else {
                vec![]
            }
        }
        _ => vec![],
    }
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_push_and_recent() {
        let stream = KernelEventStream::new(5);
        for i in 0..7 {
            stream.push(KernelEvent {
                id: 0,
                timestamp_ms: 1000 + i,
                source: EventSource::EbpfLinux,
                hostname: "test".into(),
                agent_uid: None,
                kind: KernelEventKind::ProcessExec {
                    pid: i as u32,
                    ppid: 1,
                    uid: 0,
                    exe: "/bin/ls".into(),
                    args: vec![],
                    cwd: "/".into(),
                    container_id: None,
                },
                severity: KernelEventSeverity::Info,
                mitre_techniques: vec![],
            });
        }
        assert_eq!(stream.buffered_count(), 5);
        assert_eq!(stream.total_count(), 7);
        let recent = stream.recent(3, None);
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].timestamp_ms, 1004);
    }

    #[test]
    fn stream_filter_by_type() {
        let stream = KernelEventStream::new(10);
        stream.push(KernelEvent {
            id: 0,
            timestamp_ms: 1,
            source: EventSource::EbpfLinux,
            hostname: "h".into(),
            agent_uid: None,
            kind: KernelEventKind::ProcessExec {
                pid: 1, ppid: 0, uid: 0,
                exe: "/bin/test".into(), args: vec![], cwd: "/".into(),
                container_id: None,
            },
            severity: KernelEventSeverity::Info,
            mitre_techniques: vec![],
        });
        stream.push(KernelEvent {
            id: 0,
            timestamp_ms: 2,
            source: EventSource::EbpfLinux,
            hostname: "h".into(),
            agent_uid: None,
            kind: KernelEventKind::DnsQuery {
                pid: 1, domain: "example.com".into(),
                query_type: "A".into(), response_addrs: vec![],
            },
            severity: KernelEventSeverity::Info,
            mitre_techniques: vec![],
        });
        let dns_only = stream.recent(10, Some(&["dns"]));
        assert_eq!(dns_only.len(), 1);
    }

    #[test]
    fn stream_since_filters_by_id() {
        let stream = KernelEventStream::new(10);
        for _ in 0..5 {
            stream.push(KernelEvent {
                id: 0,
                timestamp_ms: 1,
                source: EventSource::EbpfLinux,
                hostname: "h".into(),
                agent_uid: None,
                kind: KernelEventKind::ProcessExit { pid: 1, exit_code: 0 },
                severity: KernelEventSeverity::Info,
                mitre_techniques: vec![],
            });
        }
        let since_3 = stream.since(3, 100);
        assert_eq!(since_3.len(), 2);
    }

    #[test]
    fn suggest_mitre_exec_powershell() {
        let kind = KernelEventKind::ProcessExec {
            pid: 1, ppid: 0, uid: 0,
            exe: "C:\\Windows\\System32\\powershell.exe".into(),
            args: vec!["-EncodedCommand".into(), "abc".into()],
            cwd: "C:\\".into(),
            container_id: None,
        };
        let techs = suggest_mitre(&kind);
        assert!(techs.iter().any(|t| t.technique_id == "T1059"));
        assert!(techs.iter().any(|t| t.technique_id == "T1027"));
    }

    #[test]
    fn suggest_mitre_registry_run_key() {
        let kind = KernelEventKind::RegistryMutate {
            pid: 1,
            key: "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\evil".into(),
            value_name: "evil".into(),
            value_data: "C:\\evil.exe".into(),
            operation: RegistryOp::SetValue,
        };
        let techs = suggest_mitre(&kind);
        assert!(techs.iter().any(|t| t.technique_id == "T1547"));
    }

    #[test]
    fn suggest_mitre_named_pipe_c2() {
        let kind = KernelEventKind::NamedPipeCreate {
            pid: 1,
            pipe_name: "\\\\.\\pipe\\msagent_f7".into(),
        };
        let techs = suggest_mitre(&kind);
        assert!(techs.iter().any(|t| t.technique_id == "T1071"));
    }

    #[test]
    fn suggest_mitre_unsigned_driver() {
        let kind = KernelEventKind::DriverLoad {
            driver_name: "evil.sys".into(),
            path: "C:\\evil.sys".into(),
            sha256: None,
            signed: false,
        };
        let techs = suggest_mitre(&kind);
        assert!(techs.iter().any(|t| t.technique_id == "T1562"));
    }

    #[test]
    fn suggest_mitre_rdp_connect() {
        let kind = KernelEventKind::NetworkConnect {
            pid: 1,
            src_addr: "10.0.0.1".into(), src_port: 12345,
            dst_addr: "10.0.0.2".into(), dst_port: 3389,
            protocol: "tcp".into(),
        };
        let techs = suggest_mitre(&kind);
        assert!(techs.iter().any(|t| t.technique_id == "T1021"));
    }

    #[test]
    fn suggest_mitre_amsi_detected() {
        let kind = KernelEventKind::AmsiScan {
            pid: 1,
            app_name: "PowerShell".into(),
            content_preview: "Invoke-Mimikatz".into(),
            result: AmsiResult::Detected,
        };
        let techs = suggest_mitre(&kind);
        assert!(!techs.is_empty());
    }

    #[test]
    fn kernel_event_kind_name_coverage() {
        assert_eq!(kernel_event_kind_name(&KernelEventKind::ProcessExit { pid: 1, exit_code: 0 }), "exit");
        assert_eq!(kernel_event_kind_name(&KernelEventKind::DnsQuery {
            pid: 1, domain: "x".into(), query_type: "A".into(), response_addrs: vec![],
        }), "dns");
    }
}
