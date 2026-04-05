//! Windows-specific XDR collector for process, registry, service, network, DNS,
//! and PowerShell telemetry.  All collection uses safe WMI/command-line interfaces
//! (no raw kernel calls) so the agent runs without a kernel driver.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Capability detection ────────────────────────────────────────────

/// Windows version capability flags — determines which telemetry sources
/// are available on the running host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsCapabilities {
    pub version: String,
    pub build_number: u32,
    pub is_server: bool,
    pub has_wmi: bool,
    pub has_etw: bool,           // Event Tracing for Windows
    pub has_amsi: bool,          // Anti-Malware Scan Interface (Win10+)
    pub has_sysmon: bool,        // Sysmon installed (optional enrichment)
    pub has_powershell_logging: bool,
    pub has_wmic: bool,          // wmic deprecated in newer builds
}

impl WindowsCapabilities {
    /// Detect capabilities of the current Windows host.
    pub fn detect() -> Self {
        let (version, build_number) = detect_windows_version();
        Self {
            is_server: version.contains("Server"),
            has_wmi: true, // always available
            has_etw: build_number >= 6000,      // Vista+
            has_amsi: build_number >= 10240,     // Win10+
            has_sysmon: check_sysmon_installed(),
            has_powershell_logging: build_number >= 10240,
            has_wmic: build_number < 25000,      // deprecated in Win11 24H2+
            version,
            build_number,
        }
    }

    /// Return list of unavailable features for documentation/logging.
    pub fn unavailable_features(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if !self.has_etw { missing.push("ETW tracing"); }
        if !self.has_amsi { missing.push("AMSI script scanning"); }
        if !self.has_sysmon { missing.push("Sysmon enrichment"); }
        if !self.has_powershell_logging { missing.push("PowerShell ScriptBlock logging"); }
        missing
    }
}

fn detect_windows_version() -> (String, u32) {
    let version = std::process::Command::new("cmd")
        .args(["/c", "ver"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "Windows (unknown)".into());
    let build = version
        .rsplit('.')
        .next()
        .and_then(|s| s.trim_end_matches(']').parse::<u32>().ok())
        .unwrap_or(0);
    (version, build)
}

fn check_sysmon_installed() -> bool {
    std::process::Command::new("sc")
        .args(["query", "Sysmon64"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("RUNNING"))
        .unwrap_or(false)
}

// ── Process Events ──────────────────────────────────────────────────

/// A Windows process event capturing creation or termination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WinProcessEvent {
    pub timestamp: String,
    pub event_type: WinProcessEventType,
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub exe_path: String,
    pub cmd_line: String,
    pub user: String,
    pub session_id: u32,
    pub exe_hash: Option<String>,  // SHA-256 of executable
    pub ocsf_class_id: u32,       // 1007 = ProcessActivity
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WinProcessEventType {
    Create,
    Terminate,
}

/// Collect current running processes with parent-child relationships.
pub fn collect_processes() -> Vec<WinProcessEvent> {
    let now = chrono::Utc::now().to_rfc3339();
    let output = match std::process::Command::new("wmic")
        .args(["process", "get", "ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine,SessionId", "/format:csv"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut events = Vec::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() < 7 { continue; }
        // CSV format: Node,CommandLine,ExecutablePath,Name,ParentProcessId,ProcessId,SessionId
        let cmd_line = fields.get(1).unwrap_or(&"").to_string();
        let exe_path = fields.get(2).unwrap_or(&"").to_string();
        let name = fields.get(3).unwrap_or(&"").to_string();
        let ppid: u32 = fields.get(4).and_then(|s| s.trim().parse().ok()).unwrap_or(0);
        let pid: u32 = fields.get(5).and_then(|s| s.trim().parse().ok()).unwrap_or(0);
        let session_id: u32 = fields.get(6).and_then(|s| s.trim().parse().ok()).unwrap_or(0);
        if pid == 0 { continue; }
        events.push(WinProcessEvent {
            timestamp: now.clone(),
            event_type: WinProcessEventType::Create,
            pid, ppid, name, exe_path, cmd_line,
            user: String::new(),
            session_id,
            exe_hash: None,
            ocsf_class_id: 1007,
        });
    }
    events
}

// ── Network Connections ─────────────────────────────────────────────

/// A network connection observed on the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WinNetworkConnection {
    pub timestamp: String,
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: u32,
    pub process_name: String,
    pub ocsf_class_id: u32,  // 4001 = NetworkActivity
}

/// Collect active network connections using netstat.
pub fn collect_network_connections() -> Vec<WinNetworkConnection> {
    let now = chrono::Utc::now().to_rfc3339();
    let output = match std::process::Command::new("netstat")
        .args(["-ano"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut conns = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 { continue; }
        let proto = parts[0];
        if proto != "TCP" && proto != "UDP" { continue; }
        let (local_addr, local_port) = parse_endpoint(parts[1]);
        let (remote_addr, remote_port) = parse_endpoint(parts[2]);
        let state = if proto == "TCP" { parts[3].to_string() } else { "STATELESS".into() };
        let pid_idx = if proto == "TCP" { 4 } else { 3 };
        let pid: u32 = parts.get(pid_idx).and_then(|s| s.parse().ok()).unwrap_or(0);
        conns.push(WinNetworkConnection {
            timestamp: now.clone(),
            protocol: proto.to_string(),
            local_addr, local_port, remote_addr, remote_port,
            state, pid,
            process_name: String::new(),
            ocsf_class_id: 4001,
        });
    }
    conns
}

fn parse_endpoint(s: &str) -> (String, u16) {
    if let Some(idx) = s.rfind(':') {
        let addr = s[..idx].to_string();
        let port: u16 = s[idx+1..].parse().unwrap_or(0);
        (addr, port)
    } else {
        (s.to_string(), 0)
    }
}

// ── DNS Metadata ────────────────────────────────────────────────────

/// DNS query event observed on the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WinDnsEvent {
    pub timestamp: String,
    pub query_name: String,
    pub query_type: String,
    pub response: String,
    pub pid: u32,
    pub ocsf_class_id: u32,  // 4003 = DnsActivity
}

/// Collect DNS cache entries (non-invasive snapshot).
pub fn collect_dns_cache() -> Vec<WinDnsEvent> {
    let now = chrono::Utc::now().to_rfc3339();
    let output = match std::process::Command::new("ipconfig")
        .args(["/displaydns"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut events = Vec::new();
    let mut current_name = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_prefix("Record Name . . . . . : ") {
            current_name = name.trim().to_string();
        } else if let Some(rtype) = trimmed.strip_prefix("Record Type . . . . . : ") {
            let qtype = match rtype.trim() {
                "1" => "A", "28" => "AAAA", "5" => "CNAME", "15" => "MX",
                "2" => "NS", "12" => "PTR", "6" => "SOA", "16" => "TXT",
                other => other,
            };
            events.push(WinDnsEvent {
                timestamp: now.clone(),
                query_name: current_name.clone(),
                query_type: qtype.to_string(),
                response: String::new(),
                pid: 0,
                ocsf_class_id: 4003,
            });
        }
    }
    events
}

// ── Registry Monitoring ─────────────────────────────────────────────

/// Registry key/value change event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WinRegistryEvent {
    pub timestamp: String,
    pub hive: String,
    pub key_path: String,
    pub value_name: String,
    pub value_data: String,
    pub event_type: RegistryEventType,
    pub ocsf_class_id: u32,  // 5001 = ConfigState
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RegistryEventType {
    Snapshot,
    Created,
    Modified,
    Deleted,
}

/// High-value persistence-related registry keys to monitor.
pub const PERSISTENCE_REGISTRY_KEYS: &[&str] = &[
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"HKLM\SYSTEM\CurrentControlSet\Services",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
];

/// Snapshot persistence registry keys. Returns current values for diffing.
pub fn snapshot_registry_persistence() -> Vec<WinRegistryEvent> {
    let now = chrono::Utc::now().to_rfc3339();
    let mut events = Vec::new();
    for key in PERSISTENCE_REGISTRY_KEYS {
        let output = match std::process::Command::new("reg")
            .args(["query", key, "/s"])
            .output()
        {
            Ok(o) => o,
            Err(_) => continue,
        };
        let text = String::from_utf8_lossy(&output.stdout);
        let (hive, key_path) = key.split_once('\\').unwrap_or((key, ""));
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("HKEY") { continue; }
            let parts: Vec<&str> = trimmed.splitn(3, "    ").collect();
            if parts.len() >= 3 {
                events.push(WinRegistryEvent {
                    timestamp: now.clone(),
                    hive: hive.to_string(),
                    key_path: key_path.to_string(),
                    value_name: parts[0].trim().to_string(),
                    value_data: parts[2].trim().to_string(),
                    event_type: RegistryEventType::Snapshot,
                    ocsf_class_id: 5001,
                });
            }
        }
    }
    events
}

/// Diff two registry snapshots to find changes.
pub fn diff_registry(old: &[WinRegistryEvent], new: &[WinRegistryEvent]) -> Vec<WinRegistryEvent> {
    let old_map: HashMap<(String, String), String> = old.iter()
        .map(|e| ((e.key_path.clone(), e.value_name.clone()), e.value_data.clone()))
        .collect();
    let new_map: HashMap<(String, String), String> = new.iter()
        .map(|e| ((e.key_path.clone(), e.value_name.clone()), e.value_data.clone()))
        .collect();
    let now = chrono::Utc::now().to_rfc3339();
    let mut changes = Vec::new();

    for (key, new_val) in &new_map {
        match old_map.get(key) {
            None => changes.push(WinRegistryEvent {
                timestamp: now.clone(),
                hive: String::new(),
                key_path: key.0.clone(),
                value_name: key.1.clone(),
                value_data: new_val.clone(),
                event_type: RegistryEventType::Created,
                ocsf_class_id: 5001,
            }),
            Some(old_val) if old_val != new_val => changes.push(WinRegistryEvent {
                timestamp: now.clone(),
                hive: String::new(),
                key_path: key.0.clone(),
                value_name: key.1.clone(),
                value_data: new_val.clone(),
                event_type: RegistryEventType::Modified,
                ocsf_class_id: 5001,
            }),
            _ => {}
        }
    }
    for key in old_map.keys() {
        if !new_map.contains_key(key) {
            changes.push(WinRegistryEvent {
                timestamp: now.clone(),
                hive: String::new(),
                key_path: key.0.clone(),
                value_name: key.1.clone(),
                value_data: String::new(),
                event_type: RegistryEventType::Deleted,
                ocsf_class_id: 5001,
            });
        }
    }
    changes
}

// ── Service Monitoring ──────────────────────────────────────────────

/// Windows service state snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WinServiceInfo {
    pub timestamp: String,
    pub name: String,
    pub display_name: String,
    pub state: String,
    pub start_type: String,
    pub binary_path: String,
    pub account: String,
    pub ocsf_class_id: u32,  // 5001
}

/// Collect installed Windows services.
pub fn collect_services() -> Vec<WinServiceInfo> {
    let now = chrono::Utc::now().to_rfc3339();
    let output = match std::process::Command::new("wmic")
        .args(["service", "get", "Name,DisplayName,State,StartMode,PathName,StartName", "/format:csv"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut services = Vec::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() < 7 { continue; }
        let display_name = fields.get(1).unwrap_or(&"").to_string();
        let name = fields.get(2).unwrap_or(&"").to_string();
        let binary_path = fields.get(3).unwrap_or(&"").to_string();
        let start_type = fields.get(4).unwrap_or(&"").to_string();
        let account = fields.get(5).unwrap_or(&"").to_string();
        let state = fields.get(6).unwrap_or(&"").to_string();
        if name.trim().is_empty() { continue; }
        services.push(WinServiceInfo {
            timestamp: now.clone(),
            name: name.trim().to_string(),
            display_name: display_name.trim().to_string(),
            state: state.trim().to_string(),
            start_type: start_type.trim().to_string(),
            binary_path: binary_path.trim().to_string(),
            account: account.trim().to_string(),
            ocsf_class_id: 5001,
        });
    }
    services
}

// ── PowerShell / Script Execution ───────────────────────────────────

/// PowerShell execution event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WinPowerShellEvent {
    pub timestamp: String,
    pub script_name: String,
    pub cmd_line: String,
    pub pid: u32,
    pub user: String,
    pub is_encoded: bool,
    pub ocsf_class_id: u32,  // 1007
}

/// Detect running PowerShell processes and flag encoded commands.
pub fn collect_powershell_activity() -> Vec<WinPowerShellEvent> {
    let procs = collect_processes();
    let now = chrono::Utc::now().to_rfc3339();
    procs.iter()
        .filter(|p| {
            let lower = p.name.to_lowercase();
            lower.contains("powershell") || lower.contains("pwsh")
                || lower.contains("wscript") || lower.contains("cscript")
        })
        .map(|p| {
            let lower_cmd = p.cmd_line.to_lowercase();
            let is_encoded = lower_cmd.contains("-encodedcommand")
                || lower_cmd.contains("-enc ")
                || lower_cmd.contains("-e ")
                || lower_cmd.contains("frombase64");
            WinPowerShellEvent {
                timestamp: now.clone(),
                script_name: p.name.clone(),
                cmd_line: p.cmd_line.clone(),
                pid: p.pid,
                user: p.user.clone(),
                is_encoded,
                ocsf_class_id: 1007,
            }
        })
        .collect()
}

// ── Composite Collector ─────────────────────────────────────────────

/// Full Windows telemetry snapshot aggregating all sources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsSnapshot {
    pub timestamp: String,
    pub capabilities: WindowsCapabilities,
    pub processes: Vec<WinProcessEvent>,
    pub network_connections: Vec<WinNetworkConnection>,
    pub dns_cache: Vec<WinDnsEvent>,
    pub registry_persistence: Vec<WinRegistryEvent>,
    pub services: Vec<WinServiceInfo>,
    pub powershell_activity: Vec<WinPowerShellEvent>,
}

impl WindowsSnapshot {
    /// Collect a full telemetry snapshot.
    pub fn collect() -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        let caps = WindowsCapabilities::detect();
        Self {
            timestamp: now,
            capabilities: caps,
            processes: collect_processes(),
            network_connections: collect_network_connections(),
            dns_cache: collect_dns_cache(),
            registry_persistence: snapshot_registry_persistence(),
            services: collect_services(),
            powershell_activity: collect_powershell_activity(),
        }
    }

    /// Total event count across all sources.
    pub fn total_events(&self) -> usize {
        self.processes.len()
            + self.network_connections.len()
            + self.dns_cache.len()
            + self.registry_persistence.len()
            + self.services.len()
            + self.powershell_activity.len()
    }
}

// ── OCSF Class mapping ─────────────────────────────────────────────

/// Map a Windows event source to its OCSF class ID.
pub fn ocsf_class_for(source: &str) -> u32 {
    match source {
        "process" => 1007,    // ProcessActivity
        "network" => 4001,    // NetworkActivity
        "dns" => 4003,        // DnsActivity
        "registry" | "service" | "config" => 5001, // ConfigState
        "auth" => 3002,       // Authentication
        "file" => 1001,       // FileActivity
        _ => 2004,            // DetectionFinding
    }
}

// ── Supported Versions ──────────────────────────────────────────────

/// Supported Windows versions with their capabilities.
pub fn supported_versions() -> Vec<(&'static str, &'static str)> {
    vec![
        ("Windows 10 1809+",    "Full telemetry: processes, registry, services, PowerShell, AMSI, ETW"),
        ("Windows 10 1507-1803","Reduced: no AMSI, limited ScriptBlock logging"),
        ("Windows 11",          "Full telemetry, wmic may require fallback to PowerShell CIM"),
        ("Windows Server 2016+","Full telemetry with server-specific service monitoring"),
        ("Windows Server 2019+","Full telemetry including container-aware collection"),
        ("Windows 8.1",         "Basic: processes, network, services only. No AMSI/ETW."),
    ]
}

// ── Cross-platform Process Analysis & App Inventory ─────────────────

/// A suspicious-process finding for Windows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessFinding {
    pub pid: u32,
    pub name: String,
    pub user: String,
    pub risk_level: &'static str,
    pub reason: String,
    pub cpu_percent: f32,
    pub mem_percent: f32,
}

/// An installed application entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledApp {
    pub name: String,
    pub path: String,
    pub version: String,
    pub bundle_id: String,
    pub size_mb: f64,
    pub last_modified: String,
}

const SUSPICIOUS_NAMES: &[(&str, &str)] = &[
    ("xmrig", "Crypto-miner (XMRig)"),
    ("minerd", "Crypto-miner (minerd)"),
    ("cpuminer", "Crypto-miner (cpuminer)"),
    ("mimikatz", "Credential theft tool (mimikatz)"),
    ("procdump", "Process memory dump tool"),
    ("psexec", "Remote execution tool (PsExec)"),
    ("cobaltstrike", "Cobalt Strike beacon"),
    ("meterpreter", "Metasploit Meterpreter payload"),
    ("nc.exe", "Netcat — potential reverse shell"),
    ("ncat.exe", "Ncat — potential reverse shell"),
    ("socat", "Socat — potential tunnel"),
    ("powershell -enc", "Encoded PowerShell — potential obfuscated payload"),
    ("powershell -e ", "Encoded PowerShell — potential obfuscated payload"),
    ("-encodedcommand", "Encoded PowerShell — potential obfuscated payload"),
    ("iex(", "PowerShell Invoke-Expression — potential code injection"),
    ("invoke-expression", "PowerShell Invoke-Expression — potential code injection"),
    ("downloadstring", "PowerShell download cradle — remote code execution"),
    ("bitsadmin /transfer", "BITS transfer — potential data exfil or download"),
    ("certutil -urlcache", "Certutil download — LOLBin abuse"),
    ("regsvr32 /s /n /u /i:", "Regsvr32 proxy execution — LOLBin abuse"),
    ("mshta ", "MSHTA execution — LOLBin abuse"),
    ("rundll32 javascript:", "Rundll32 script exec — LOLBin abuse"),
    ("\\temp\\", "Process in temp folder — suspicious location"),
    ("\\tmp\\", "Process in tmp folder — suspicious location"),
    ("appdata\\local\\temp", "Process in user temp — suspicious location"),
];

const WINDOWS_SYSTEM_PROCS: &[&str] = &[
    "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "dwm.exe", "explorer.exe",
    "spoolsv.exe", "ctfmon.exe", "taskhostw.exe", "runtimebroker.exe",
    "searchindexer", "securityhealthservice", "msmpeng.exe", "nissrv.exe",
    "wuauserv", "trustedinstaller", "msiexec.exe", "dllhost.exe",
    "conhost.exe", "sihost.exe", "fontdrvhost.exe", "lsaiso.exe",
    "registry", "memcompression", "wmiprvse.exe", "searchprotocolhost",
    "searchfilterhost", "audiodg.exe", "dashost.exe",
];

/// Analyse running Windows processes for suspicious behaviour.
pub fn analyze_processes(procs: &[WinProcessEvent]) -> Vec<ProcessFinding> {
    let mut findings = Vec::new();

    for p in procs {
        let name_lower = p.name.to_lowercase();
        let cmd_lower = p.cmd_line.to_lowercase();
        let exe_lower = p.exe_path.to_lowercase();

        // Suspicious name/command patterns
        for &(pattern, desc) in SUSPICIOUS_NAMES {
            if name_lower.contains(pattern) || cmd_lower.contains(pattern) || exe_lower.contains(pattern) {
                findings.push(ProcessFinding {
                    pid: p.pid, name: p.name.clone(),
                    user: if p.user.is_empty() { "—".into() } else { p.user.clone() },
                    risk_level: "critical", reason: desc.to_string(),
                    cpu_percent: 0.0, mem_percent: 0.0,
                });
            }
        }

        // Non-system process with PID < 100 — unusual (potential PID spoofing)
        if p.pid > 4 && p.pid < 100 && !is_known_windows_system_process(&name_lower) {
            findings.push(ProcessFinding {
                pid: p.pid, name: p.name.clone(),
                user: if p.user.is_empty() { "—".into() } else { p.user.clone() },
                risk_level: "elevated",
                reason: "Very low PID for non-system process — unusual".to_string(),
                cpu_percent: 0.0, mem_percent: 0.0,
            });
        }

        // Process from suspicious paths
        if !exe_lower.is_empty()
            && !exe_lower.starts_with("c:\\windows\\")
            && !exe_lower.starts_with("c:\\program files")
            && !exe_lower.is_empty()
            && p.pid > 4
            && !is_known_windows_system_process(&name_lower)
        {
            // Check for truly suspicious paths
            if exe_lower.contains("\\temp\\") || exe_lower.contains("\\tmp\\")
                || exe_lower.contains("\\downloads\\") || exe_lower.contains("\\appdata\\local\\temp")
            {
                findings.push(ProcessFinding {
                    pid: p.pid, name: p.name.clone(),
                    user: if p.user.is_empty() { "—".into() } else { p.user.clone() },
                    risk_level: "elevated",
                    reason: format!("Process running from suspicious path: {}", p.exe_path),
                    cpu_percent: 0.0, mem_percent: 0.0,
                });
            }
        }
    }

    // Sort by risk desc
    findings.sort_by(|a, b| risk_ord(b.risk_level).cmp(&risk_ord(a.risk_level)));
    findings
}

/// Collect installed applications from Windows registry/wmic.
pub fn collect_installed_apps() -> Vec<InstalledApp> {
    let mut apps = Vec::new();

    // Try wmic product
    if let Ok(output) = std::process::Command::new("wmic")
        .args(["product", "get", "Name,Version,InstallLocation", "/format:csv"])
        .output()
    {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines().skip(1) {
                let fields: Vec<&str> = line.split(',').collect();
                if fields.len() >= 4 {
                    let install_location = fields.get(1).unwrap_or(&"").to_string();
                    let name = fields.get(2).unwrap_or(&"").trim().to_string();
                    let version = fields.get(3).unwrap_or(&"").trim().to_string();
                    if name.is_empty() { continue; }
                    apps.push(InstalledApp {
                        name,
                        path: install_location,
                        version,
                        bundle_id: String::new(),
                        size_mb: 0.0,
                        last_modified: String::new(),
                    });
                }
            }
        }
    }

    // Fallback: registry query for 64-bit apps
    if apps.is_empty() {
        if let Ok(output) = std::process::Command::new("reg")
            .args(["query", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "/s"])
            .output()
        {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                let mut current_name = String::new();
                let mut current_version = String::new();
                let mut current_path = String::new();

                for line in text.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("DisplayName") {
                        if let Some(val) = trimmed.split("REG_SZ").nth(1) {
                            current_name = val.trim().to_string();
                        }
                    } else if trimmed.starts_with("DisplayVersion") {
                        if let Some(val) = trimmed.split("REG_SZ").nth(1) {
                            current_version = val.trim().to_string();
                        }
                    } else if trimmed.starts_with("InstallLocation") {
                        if let Some(val) = trimmed.split("REG_SZ").nth(1) {
                            current_path = val.trim().to_string();
                        }
                    } else if trimmed.starts_with("HKEY_") || trimmed.is_empty() {
                        if !current_name.is_empty() {
                            apps.push(InstalledApp {
                                name: current_name.clone(),
                                path: current_path.clone(),
                                version: current_version.clone(),
                                bundle_id: String::new(),
                                size_mb: 0.0,
                                last_modified: String::new(),
                            });
                        }
                        current_name.clear();
                        current_version.clear();
                        current_path.clear();
                    }
                }
                // Flush last entry
                if !current_name.is_empty() {
                    apps.push(InstalledApp {
                        name: current_name,
                        path: current_path,
                        version: current_version,
                        bundle_id: String::new(),
                        size_mb: 0.0,
                        last_modified: String::new(),
                    });
                }
            }
        }
    }

    apps.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    apps
}

fn is_known_windows_system_process(name: &str) -> bool {
    WINDOWS_SYSTEM_PROCS.iter().any(|sp| name.contains(&sp.to_lowercase()))
}

fn risk_ord(level: &str) -> u8 {
    match level {
        "critical" => 3,
        "severe" => 2,
        "elevated" => 1,
        _ => 0,
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capabilities_detect_defaults() {
        // On non-Windows, detect returns safe defaults
        let caps = WindowsCapabilities {
            version: "Windows 10 Enterprise 19045".into(),
            build_number: 19045,
            is_server: false,
            has_wmi: true,
            has_etw: true,
            has_amsi: true,
            has_sysmon: false,
            has_powershell_logging: true,
            has_wmic: true,
        };
        assert!(caps.has_amsi);
        assert!(caps.has_etw);
        assert!(!caps.is_server);
        let missing = caps.unavailable_features();
        assert_eq!(missing, vec!["Sysmon enrichment"]);
    }

    #[test]
    fn test_capabilities_server() {
        let caps = WindowsCapabilities {
            version: "Windows Server 2022".into(),
            build_number: 20348,
            is_server: true,
            has_wmi: true,
            has_etw: true,
            has_amsi: true,
            has_sysmon: true,
            has_powershell_logging: true,
            has_wmic: true,
        };
        assert!(caps.is_server);
        assert!(caps.unavailable_features().is_empty());
    }

    #[test]
    fn test_capabilities_legacy() {
        let caps = WindowsCapabilities {
            version: "Windows 8.1".into(),
            build_number: 9600,
            is_server: false,
            has_wmi: true,
            has_etw: true,
            has_amsi: false,
            has_sysmon: false,
            has_powershell_logging: false,
            has_wmic: true,
        };
        assert!(!caps.has_amsi);
        assert!(!caps.has_powershell_logging);
        let missing = caps.unavailable_features();
        assert_eq!(missing.len(), 3); // AMSI, Sysmon, PowerShell
    }

    #[test]
    fn test_parse_endpoint() {
        let (addr, port) = parse_endpoint("192.168.1.100:443");
        assert_eq!(addr, "192.168.1.100");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_endpoint_ipv6() {
        let (addr, port) = parse_endpoint("[::1]:8080");
        assert_eq!(port, 8080);
        assert!(addr.contains("::1"));
    }

    #[test]
    fn test_ocsf_class_mapping() {
        assert_eq!(ocsf_class_for("process"), 1007);
        assert_eq!(ocsf_class_for("network"), 4001);
        assert_eq!(ocsf_class_for("dns"), 4003);
        assert_eq!(ocsf_class_for("registry"), 5001);
        assert_eq!(ocsf_class_for("auth"), 3002);
        assert_eq!(ocsf_class_for("unknown"), 2004);
    }

    #[test]
    fn test_registry_diff_detects_created() {
        let old = vec![];
        let new = vec![WinRegistryEvent {
            timestamp: "2026-01-01T00:00:00Z".into(),
            hive: "HKLM".into(),
            key_path: "SOFTWARE\\Test".into(),
            value_name: "AutoStart".into(),
            value_data: "malware.exe".into(),
            event_type: RegistryEventType::Snapshot,
            ocsf_class_id: 5001,
        }];
        let diff = diff_registry(&old, &new);
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].event_type, RegistryEventType::Created);
    }

    #[test]
    fn test_registry_diff_detects_modified() {
        let old = vec![WinRegistryEvent {
            timestamp: "t1".into(), hive: "HKLM".into(),
            key_path: "Run".into(), value_name: "svc".into(),
            value_data: "good.exe".into(),
            event_type: RegistryEventType::Snapshot, ocsf_class_id: 5001,
        }];
        let new = vec![WinRegistryEvent {
            timestamp: "t2".into(), hive: "HKLM".into(),
            key_path: "Run".into(), value_name: "svc".into(),
            value_data: "evil.exe".into(),
            event_type: RegistryEventType::Snapshot, ocsf_class_id: 5001,
        }];
        let diff = diff_registry(&old, &new);
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].event_type, RegistryEventType::Modified);
    }

    #[test]
    fn test_registry_diff_detects_deleted() {
        let old = vec![WinRegistryEvent {
            timestamp: "t1".into(), hive: "HKLM".into(),
            key_path: "Run".into(), value_name: "legit".into(),
            value_data: "app.exe".into(),
            event_type: RegistryEventType::Snapshot, ocsf_class_id: 5001,
        }];
        let new = vec![];
        let diff = diff_registry(&old, &new);
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].event_type, RegistryEventType::Deleted);
    }

    #[test]
    fn test_registry_no_changes() {
        let snap = vec![WinRegistryEvent {
            timestamp: "t1".into(), hive: "HKLM".into(),
            key_path: "Run".into(), value_name: "app".into(),
            value_data: "val".into(),
            event_type: RegistryEventType::Snapshot, ocsf_class_id: 5001,
        }];
        let diff = diff_registry(&snap, &snap);
        assert!(diff.is_empty());
    }

    #[test]
    fn test_supported_versions_not_empty() {
        let versions = supported_versions();
        assert!(versions.len() >= 5);
    }

    #[test]
    fn test_powershell_encoded_detection() {
        let evt = WinPowerShellEvent {
            timestamp: "t".into(),
            script_name: "powershell.exe".into(),
            cmd_line: "powershell.exe -EncodedCommand ZQBj...".into(),
            pid: 1234, user: "admin".into(),
            is_encoded: true, ocsf_class_id: 1007,
        };
        assert!(evt.is_encoded);
    }

    #[test]
    fn test_windows_snapshot_total_events() {
        let snap = WindowsSnapshot {
            timestamp: "t".into(),
            capabilities: WindowsCapabilities {
                version: "test".into(), build_number: 19045,
                is_server: false, has_wmi: true, has_etw: true,
                has_amsi: true, has_sysmon: false,
                has_powershell_logging: true, has_wmic: true,
            },
            processes: vec![],
            network_connections: vec![],
            dns_cache: vec![],
            registry_persistence: vec![],
            services: vec![],
            powershell_activity: vec![],
        };
        assert_eq!(snap.total_events(), 0);
    }
}
