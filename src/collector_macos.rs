//! macOS-specific XDR collector for process lifecycle, file activity,
//! network connections, mounted volumes, login events, and persistence
//! mechanism enumeration.  All collection uses user-space commands
//! (`ps`, `lsof`, `mount`, `last`, `csrutil`, `spctl`, `codesign`) —
//! no kernel extensions (kexts) are required.
//!
//! ## Entitlement Requirements
//!
//! | Entitlement / Permission       | Purpose                                    |
//! |-------------------------------|--------------------------------------------|
//! | Full Disk Access (TCC)        | Read LaunchDaemons, cron tabs, login items |
//! | Endpoint Security (ES)        | Real-time process/file events (optional)   |
//! | Network Extensions            | Packet-level inspection (optional)         |
//!
//! ## Capability Matrix
//!
//! | macOS Version   | Codename  | Notes                                      |
//! |----------------|-----------|--------------------------------------------|
//! | 12 Monterey    |           | Baseline: SIP, TCC, Gatekeeper available  |
//! | 13 Ventura     |           | Login Items API changes, Rapid Security    |
//! | 14 Sonoma      |           | Improved ES framework, stricter TCC        |
//! | 15 Sequoia     |           | Enhanced code-signing checks               |

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

// ── OCSF Class IDs ─────────────────────────────────────────────────

pub const OCSF_FILE_ACTIVITY: u32 = 1001;
pub const OCSF_PROCESS_ACTIVITY: u32 = 1007;
pub const OCSF_AUTH: u32 = 3002;
pub const OCSF_NETWORK_ACTIVITY: u32 = 4001;
pub const OCSF_CONFIG_STATE: u32 = 5001;
pub const OCSF_DEVICE_CONFIG: u32 = 5002;
pub const OCSF_DETECTION_FINDING: u32 = 2004;

/// Map a macOS event source to its OCSF class ID.
pub fn ocsf_class_for(source: &str) -> u32 {
    match source {
        "process" => OCSF_PROCESS_ACTIVITY,
        "file" => OCSF_FILE_ACTIVITY,
        "network" => OCSF_NETWORK_ACTIVITY,
        "auth" | "login" => OCSF_AUTH,
        "config" | "persistence" | "mount" => OCSF_CONFIG_STATE,
        "device" => OCSF_DEVICE_CONFIG,
        _ => OCSF_DETECTION_FINDING,
    }
}

// ── Capability Detection ────────────────────────────────────────────

/// macOS host capability flags — determines which telemetry sources
/// and security features are available on the running host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacosCapabilities {
    pub macos_version: String,
    pub build_number: String,
    pub sip_enabled: bool,
    pub tcc_status: TccStatus,
    pub gatekeeper_enabled: bool,
    pub code_signing_enforced: bool,
    pub detected_security_tools: Vec<String>,
    pub full_disk_access: bool,
}

/// TCC (Transparency, Consent, and Control) status summary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TccStatus {
    /// TCC is active and enforcing (normal state).
    Enforcing,
    /// TCC is present but status could not be determined.
    Unknown,
}

impl MacosCapabilities {
    /// Detect capabilities of the current macOS host.
    pub fn detect() -> Self {
        let (macos_version, build_number) = detect_macos_version();
        Self {
            sip_enabled: detect_sip_status(),
            tcc_status: TccStatus::Enforcing, // TCC is always enforcing on supported macOS
            gatekeeper_enabled: detect_gatekeeper_status(),
            code_signing_enforced: true, // always on macOS 12+
            detected_security_tools: detect_security_tools(),
            full_disk_access: check_full_disk_access(),
            macos_version,
            build_number,
        }
    }

    /// Return list of security concerns for documentation/logging.
    pub fn security_concerns(&self) -> Vec<&'static str> {
        let mut concerns = Vec::new();
        if !self.sip_enabled {
            concerns.push("SIP disabled — system integrity not protected");
        }
        if !self.gatekeeper_enabled {
            concerns.push("Gatekeeper disabled — unsigned apps can run");
        }
        if !self.full_disk_access {
            concerns.push("Full Disk Access not granted — limited telemetry");
        }
        if self.detected_security_tools.is_empty() {
            concerns.push("No third-party security tools detected");
        }
        concerns
    }

    /// Return list of unavailable features for documentation/logging.
    pub fn unavailable_features(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if !self.full_disk_access {
            missing.push("Full Disk Access (LaunchDaemons, cron enumeration)");
        }
        if !self.sip_enabled {
            missing.push("SIP protection guarantees");
        }
        missing
    }
}

fn detect_macos_version() -> (String, String) {
    let version = std::process::Command::new("sw_vers")
        .arg("-productVersion")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".into());
    let build = std::process::Command::new("sw_vers")
        .arg("-buildVersion")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".into());
    (version, build)
}

/// Parse SIP status from `csrutil status` output.
pub fn parse_sip_status(output: &str) -> bool {
    // Output: "System Integrity Protection status: enabled."
    // or "System Integrity Protection status: disabled."
    let lower = output.to_lowercase();
    lower.contains("enabled")
}

fn detect_sip_status() -> bool {
    std::process::Command::new("csrutil")
        .arg("status")
        .output()
        .map(|o| {
            let text = String::from_utf8_lossy(&o.stdout);
            parse_sip_status(&text)
        })
        .unwrap_or(true) // default to assuming SIP is on
}

fn detect_gatekeeper_status() -> bool {
    std::process::Command::new("spctl")
        .args(["--status"])
        .output()
        .map(|o| {
            let text = String::from_utf8_lossy(&o.stdout);
            text.contains("assessments enabled")
        })
        .unwrap_or(true)
}

fn detect_security_tools() -> Vec<String> {
    let mut tools = Vec::new();
    let known_agents: &[(&str, &str)] = &[
        ("com.crowdstrike.falcon", "CrowdStrike Falcon"),
        ("com.jamf.management", "Jamf Pro"),
        ("com.sentinelone.agent", "SentinelOne"),
        ("com.carbonblack.defense", "Carbon Black"),
        ("com.microsoft.wdav", "Microsoft Defender"),
        ("com.sophos.endpoint", "Sophos"),
        ("com.malwarebytes.agent", "Malwarebytes"),
        (
            "com.paloaltonetworks.GlobalProtect",
            "Palo Alto GlobalProtect",
        ),
    ];
    // Check LaunchDaemons and LaunchAgents for known security products
    let search_dirs = ["/Library/LaunchDaemons", "/Library/LaunchAgents"];
    for dir in &search_dirs {
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            for (pattern, label) in known_agents {
                if name.contains(pattern) && !tools.contains(&label.to_string()) {
                    tools.push(label.to_string());
                }
            }
        }
    }
    tools
}

fn check_full_disk_access() -> bool {
    // Heuristic: attempt to read a TCC-protected path.
    // If we can list /Library/Application Support/com.apple.TCC, we likely have FDA.
    Path::new("/Library/Application Support/com.apple.TCC/TCC.db").exists()
        && fs::metadata("/Library/Application Support/com.apple.TCC/TCC.db")
            .map(|m| m.len() > 0)
            .unwrap_or(false)
}

// ── Process Events ──────────────────────────────────────────────────

/// A macOS process event capturing lifecycle information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacosProcessEvent {
    pub timestamp: String,
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub user: String,
    pub group: String,
    pub cpu_percent: f32,
    pub mem_percent: f32,
    pub code_signed: CodeSignStatus,
    pub cmd_line: String,
    pub ocsf_class_id: u32,
}

/// Code signing verification status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CodeSignStatus {
    Valid,
    Invalid,
    NotSigned,
    Unknown,
}

/// Collect current running processes via `ps`.
pub fn collect_processes() -> Vec<MacosProcessEvent> {
    let now = chrono::Utc::now().to_rfc3339();
    // ps -axo pid,ppid,user,group,%cpu,%mem,comm
    let output = match std::process::Command::new("ps")
        .args(["-axo", "pid,ppid,user,group,%cpu,%mem,comm"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut events = Vec::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 7 {
            continue;
        }
        let pid: u32 = match fields[0].parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let ppid: u32 = fields[1].parse().unwrap_or(0);
        let user = fields[2].to_string();
        let group = fields[3].to_string();
        let cpu_percent: f32 = fields[4].parse().unwrap_or(0.0);
        let mem_percent: f32 = fields[5].parse().unwrap_or(0.0);
        let name = fields[6..].join(" ");
        events.push(MacosProcessEvent {
            timestamp: now.clone(),
            pid,
            ppid,
            name,
            user,
            group,
            cpu_percent,
            mem_percent,
            code_signed: CodeSignStatus::Unknown,
            cmd_line: String::new(),
            ocsf_class_id: OCSF_PROCESS_ACTIVITY,
        });
    }
    events
}

// ── File Events ─────────────────────────────────────────────────────

/// File activity in monitored macOS paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacosFileEvent {
    pub timestamp: String,
    pub path: String,
    pub operation: MacosFileOperation,
    pub size: u64,
    pub owner: String,
    pub ocsf_class_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MacosFileOperation {
    Read,
    Write,
    Create,
    Delete,
    Rename,
}

/// Paths of high interest for macOS XDR file monitoring.
pub const MONITORED_PATHS: &[&str] = &[
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons",
    "~/Library/LaunchAgents",
    "/tmp",
    "~/Downloads",
    "/usr/local/bin",
    "/private/var/tmp",
];

/// Snapshot recently modified files in monitored paths.
pub fn snapshot_recent_files(watch_paths: &[&str], since_secs: u64) -> Vec<MacosFileEvent> {
    let now = chrono::Utc::now().to_rfc3339();
    let cutoff = std::time::SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(since_secs))
        .unwrap_or(std::time::UNIX_EPOCH);
    let mut events = Vec::new();
    for base in watch_paths {
        // Expand ~ for home directory paths
        let expanded = if base.starts_with("~/") {
            if let Ok(home) = std::env::var("HOME") {
                format!("{}{}", home, &base[1..])
            } else {
                continue;
            }
        } else {
            base.to_string()
        };
        let entries = match fs::read_dir(&expanded) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            if !meta.is_file() {
                continue;
            }
            let modified = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
            if modified < cutoff {
                continue;
            }

            #[cfg(target_os = "macos")]
            let owner = {
                use std::os::unix::fs::MetadataExt;
                format!("uid:{}", meta.uid())
            };
            #[cfg(not(target_os = "macos"))]
            let owner = "unknown".to_string();

            events.push(MacosFileEvent {
                timestamp: now.clone(),
                path: entry.path().to_string_lossy().to_string(),
                operation: MacosFileOperation::Write,
                size: meta.len(),
                owner,
                ocsf_class_id: OCSF_FILE_ACTIVITY,
            });
        }
    }
    events
}

// ── Network Events ──────────────────────────────────────────────────

/// An active network connection observed on the macOS host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacosNetworkEvent {
    pub timestamp: String,
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: Option<u32>,
    pub process_name: String,
    pub ocsf_class_id: u32,
}

/// Collect active network connections using `lsof -i -nP`.
pub fn collect_network_connections() -> Vec<MacosNetworkEvent> {
    let now = chrono::Utc::now().to_rfc3339();
    let output = match std::process::Command::new("lsof")
        .args(["-i", "-nP", "-F", "pcnPtTn"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut conns = Vec::new();
    let mut current_pid: Option<u32> = None;
    let mut current_name = String::new();
    let mut current_proto = String::new();

    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let (tag, value) = (line.as_bytes()[0] as char, &line[1..]);
        match tag {
            'p' => current_pid = value.parse().ok(),
            'c' => current_name = value.to_string(),
            'P' => current_proto = value.to_uppercase(),
            'n' => {
                // Format: "host:port->remote_host:remote_port" or "host:port"
                if let Some((local, remote)) = value.split_once("->") {
                    let (la, lp) = parse_lsof_endpoint(local);
                    let (ra, rp) = parse_lsof_endpoint(remote);
                    conns.push(MacosNetworkEvent {
                        timestamp: now.clone(),
                        protocol: current_proto.clone(),
                        local_addr: la,
                        local_port: lp,
                        remote_addr: ra,
                        remote_port: rp,
                        state: String::new(),
                        pid: current_pid,
                        process_name: current_name.clone(),
                        ocsf_class_id: OCSF_NETWORK_ACTIVITY,
                    });
                } else if value.contains(':') {
                    let (la, lp) = parse_lsof_endpoint(value);
                    conns.push(MacosNetworkEvent {
                        timestamp: now.clone(),
                        protocol: current_proto.clone(),
                        local_addr: la,
                        local_port: lp,
                        remote_addr: String::new(),
                        remote_port: 0,
                        state: "LISTEN".into(),
                        pid: current_pid,
                        process_name: current_name.clone(),
                        ocsf_class_id: OCSF_NETWORK_ACTIVITY,
                    });
                }
            }
            _ => {}
        }
    }
    conns
}

fn parse_lsof_endpoint(s: &str) -> (String, u16) {
    // Handle IPv6 bracket notation [::1]:port or plain host:port
    if let Some(idx) = s.rfind(':') {
        let addr = &s[..idx];
        let port: u16 = s[idx + 1..].parse().unwrap_or(0);
        (
            addr.trim_matches(|c| c == '[' || c == ']').to_string(),
            port,
        )
    } else {
        (s.to_string(), 0)
    }
}

// ── Mount Events ────────────────────────────────────────────────────

/// A mounted volume or DMG on the macOS host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacosMountEvent {
    pub timestamp: String,
    pub device: String,
    pub mount_point: String,
    pub fs_type: String,
    pub options: Vec<String>,
    pub is_external: bool,
    pub is_dmg: bool,
    pub ocsf_class_id: u32,
}

/// Parse a single line from the `mount` command output.
pub fn parse_mount_line(line: &str) -> Option<MacosMountEvent> {
    // Format: "/dev/disk3s1 on /Volumes/USB (hfs, local, nodev, nosuid, read-only, ...)"
    let on_idx = line.find(" on ")?;
    let device = line[..on_idx].to_string();
    let rest = &line[on_idx + 4..];
    let paren_idx = rest.find(" (")?;
    let mount_point = rest[..paren_idx].to_string();
    let opts_str = rest[paren_idx + 2..].trim_end_matches(')');
    let options: Vec<String> = opts_str.split(", ").map(|s| s.trim().to_string()).collect();
    let fs_type = options.first().cloned().unwrap_or_default();
    let is_external = mount_point.starts_with("/Volumes/")
        && mount_point != "/Volumes/Macintosh HD"
        || device.contains("disk image");
    let is_dmg = device.contains("disk image") || mount_point.contains(".dmg");

    Some(MacosMountEvent {
        timestamp: String::new(), // filled by caller
        device,
        mount_point,
        fs_type,
        options,
        is_external,
        is_dmg,
        ocsf_class_id: OCSF_CONFIG_STATE,
    })
}

/// Collect mounted volumes via `mount` command.
pub fn collect_mounts() -> Vec<MacosMountEvent> {
    let now = chrono::Utc::now().to_rfc3339();
    let output = match std::process::Command::new("mount").output() {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .filter_map(|line| {
            let mut evt = parse_mount_line(line)?;
            evt.timestamp = now.clone();
            Some(evt)
        })
        .collect()
}

// ── Login Events ────────────────────────────────────────────────────

/// A login or session event from the macOS host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacosLoginEvent {
    pub timestamp: String,
    pub user: String,
    pub terminal: String,
    pub source: String,
    pub login_time: String,
    pub event_type: MacosLoginType,
    pub ocsf_class_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MacosLoginType {
    Login,
    Logout,
    Reboot,
    Shutdown,
}

/// Parse a single line from `last` command output.
pub fn parse_last_line(line: &str) -> Option<MacosLoginEvent> {
    // Format: "user  ttys000  192.168.1.1  Mon Jan  1 12:00   still logged in"
    //     or: "reboot  ~  Mon Jan  1 12:00"
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 3 {
        return None;
    }
    let user = fields[0].to_string();
    if user == "wtmp" || user.is_empty() {
        return None;
    }
    let event_type = match user.as_str() {
        "reboot" => MacosLoginType::Reboot,
        "shutdown" => MacosLoginType::Shutdown,
        _ => {
            if line.contains("logged in") {
                MacosLoginType::Login
            } else {
                MacosLoginType::Logout
            }
        }
    };
    let terminal = fields.get(1).unwrap_or(&"").to_string();
    let source = if fields.len() > 2
        && !fields[2].starts_with("Mon")
        && !fields[2].starts_with("Tue")
        && !fields[2].starts_with("Wed")
        && !fields[2].starts_with("Thu")
        && !fields[2].starts_with("Fri")
        && !fields[2].starts_with("Sat")
        && !fields[2].starts_with("Sun")
        && fields[2] != "~"
    {
        fields[2].to_string()
    } else {
        "console".to_string()
    };

    Some(MacosLoginEvent {
        timestamp: String::new(),
        user,
        terminal,
        source,
        login_time: fields[3..].join(" "),
        event_type,
        ocsf_class_id: OCSF_AUTH,
    })
}

/// Collect login events from `last` command.
pub fn collect_login_events() -> Vec<MacosLoginEvent> {
    let now = chrono::Utc::now().to_rfc3339();
    let output = match std::process::Command::new("last")
        .args(["-20"]) // last 20 entries
        .output()
    {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .filter_map(|line| {
            if line.trim().is_empty() {
                return None;
            }
            let mut evt = parse_last_line(line)?;
            evt.timestamp = now.clone();
            Some(evt)
        })
        .collect()
}

// ── Persistence Items ───────────────────────────────────────────────

/// A persistence mechanism found on the macOS host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacosPersistenceItem {
    pub timestamp: String,
    pub persistence_type: PersistenceType,
    pub path: String,
    pub label: String,
    pub program: String,
    pub enabled: bool,
    pub ocsf_class_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PersistenceType {
    LaunchAgent,
    LaunchDaemon,
    LoginItem,
    CronJob,
}

/// Classify a plist path as LaunchAgent or LaunchDaemon.
pub fn classify_persistence_path(path: &str) -> Option<PersistenceType> {
    if path.contains("LaunchAgents") {
        Some(PersistenceType::LaunchAgent)
    } else if path.contains("LaunchDaemons") {
        Some(PersistenceType::LaunchDaemon)
    } else {
        None
    }
}

/// Directories to scan for LaunchAgents / LaunchDaemons.
const PERSISTENCE_DIRS: &[(&str, PersistenceType)] = &[
    ("/Library/LaunchAgents", PersistenceType::LaunchAgent),
    ("/Library/LaunchDaemons", PersistenceType::LaunchDaemon),
    ("/System/Library/LaunchAgents", PersistenceType::LaunchAgent),
    (
        "/System/Library/LaunchDaemons",
        PersistenceType::LaunchDaemon,
    ),
];

/// Enumerate LaunchAgents, LaunchDaemons, and cron jobs.
pub fn collect_persistence_items() -> Vec<MacosPersistenceItem> {
    let now = chrono::Utc::now().to_rfc3339();
    let mut items = Vec::new();

    // Scan plist directories
    for (dir, ptype) in PERSISTENCE_DIRS {
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if !name.ends_with(".plist") {
                continue;
            }
            let label = name.trim_end_matches(".plist").to_string();
            // Try to extract Program/ProgramArguments from plist
            let program = extract_plist_program(&path.to_string_lossy());
            items.push(MacosPersistenceItem {
                timestamp: now.clone(),
                persistence_type: ptype.clone(),
                path: path.to_string_lossy().to_string(),
                label,
                program,
                enabled: true,
                ocsf_class_id: OCSF_CONFIG_STATE,
            });
        }
    }

    // Also scan user-level LaunchAgents
    if let Ok(home) = std::env::var("HOME") {
        let user_agents = format!("{}/Library/LaunchAgents", home);
        if let Ok(entries) = fs::read_dir(&user_agents) {
            for entry in entries.flatten() {
                let path = entry.path();
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                if !name.ends_with(".plist") {
                    continue;
                }
                let label = name.trim_end_matches(".plist").to_string();
                let program = extract_plist_program(&path.to_string_lossy());
                items.push(MacosPersistenceItem {
                    timestamp: now.clone(),
                    persistence_type: PersistenceType::LaunchAgent,
                    path: path.to_string_lossy().to_string(),
                    label,
                    program,
                    enabled: true,
                    ocsf_class_id: OCSF_CONFIG_STATE,
                });
            }
        }
    }

    // Cron jobs
    items.extend(collect_cron_jobs(&now));

    items
}

/// Attempt to extract the Program or ProgramArguments from a plist.
/// Uses a simple text-based approach (plists are often XML).
fn extract_plist_program(path: &str) -> String {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return String::new(),
    };
    // Look for <key>Program</key>\n<string>...</string>
    // or <key>ProgramArguments</key> followed by array of strings
    let mut found_program_key = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "<key>Program</key>" || trimmed == "<key>ProgramArguments</key>" {
            found_program_key = true;
            continue;
        }
        if found_program_key {
            if let Some(val) = trimmed.strip_prefix("<string>")
                && let Some(val) = val.strip_suffix("</string>")
            {
                return val.to_string();
            }
            // In the ProgramArguments array, the first <string> is the binary
            if trimmed == "<array>" {
                continue;
            }
            if trimmed.starts_with("<string>")
                && let Some(val) = trimmed.strip_prefix("<string>")
                && let Some(val) = val.strip_suffix("</string>")
            {
                return val.to_string();
            }
            // Stop looking if we hit another key or end of array
            if trimmed.starts_with("<key>") || trimmed == "</array>" || trimmed == "</dict>" {
                found_program_key = false;
            }
        }
    }
    String::new()
}

/// Collect cron jobs for the current user.
fn collect_cron_jobs(now: &str) -> Vec<MacosPersistenceItem> {
    let output = match std::process::Command::new("crontab").arg("-l").output() {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty() && !trimmed.starts_with('#')
        })
        .map(|line| {
            let parts: Vec<&str> = line.splitn(6, char::is_whitespace).collect();
            let program = parts.last().unwrap_or(&"").to_string();
            MacosPersistenceItem {
                timestamp: now.to_string(),
                persistence_type: PersistenceType::CronJob,
                path: "crontab".into(),
                label: program.clone(),
                program,
                enabled: true,
                ocsf_class_id: OCSF_CONFIG_STATE,
            }
        })
        .collect()
}

// ── Installed Applications ───────────────────────────────────────────

/// An installed application found in /Applications.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledApp {
    pub name: String,
    pub path: String,
    pub version: String,
    pub bundle_id: String,
    pub size_mb: f64,
    pub last_modified: String,
}

/// Enumerate installed macOS applications from /Applications (and ~/Applications).
pub fn collect_installed_apps() -> Vec<InstalledApp> {
    let mut apps = Vec::new();
    let dirs = [
        "/Applications".to_string(),
        format!("{}/Applications", std::env::var("HOME").unwrap_or_default()),
    ];
    for dir in &dirs {
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if !name.ends_with(".app") {
                continue;
            }
            let display_name = name.trim_end_matches(".app").to_string();
            let size_mb = dir_size_mb(&path);
            let last_modified = entry
                .metadata()
                .and_then(|m| m.modified())
                .map(|t| {
                    let dt: chrono::DateTime<chrono::Utc> = t.into();
                    dt.to_rfc3339()
                })
                .unwrap_or_default();

            // Read Info.plist for version and bundle ID
            let plist_path = path.join("Contents/Info.plist");
            let (version, bundle_id) = read_app_plist(&plist_path);

            apps.push(InstalledApp {
                name: display_name,
                path: path.to_string_lossy().to_string(),
                version,
                bundle_id,
                size_mb,
                last_modified,
            });
        }
    }
    apps.sort_by_key(|a| a.name.to_lowercase());
    apps
}

fn read_app_plist(path: &Path) -> (String, String) {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return (String::new(), String::new()),
    };
    let mut version = String::new();
    let mut bundle_id = String::new();
    let mut next_is_version = false;
    let mut next_is_bundle = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "<key>CFBundleShortVersionString</key>" {
            next_is_version = true;
            continue;
        }
        if trimmed == "<key>CFBundleIdentifier</key>" {
            next_is_bundle = true;
            continue;
        }
        if next_is_version {
            if let Some(val) = trimmed
                .strip_prefix("<string>")
                .and_then(|s| s.strip_suffix("</string>"))
            {
                version = val.to_string();
            }
            next_is_version = false;
        }
        if next_is_bundle {
            if let Some(val) = trimmed
                .strip_prefix("<string>")
                .and_then(|s| s.strip_suffix("</string>"))
            {
                bundle_id = val.to_string();
            }
            next_is_bundle = false;
        }
    }
    (version, bundle_id)
}

fn dir_size_mb(path: &Path) -> f64 {
    let mut total: u64 = 0;
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                if meta.is_file() {
                    total += meta.len();
                } else if meta.is_dir() {
                    // One level deep approximation to avoid long recursion
                    if let Ok(sub) = fs::read_dir(entry.path()) {
                        for se in sub.flatten() {
                            if let Ok(sm) = se.metadata()
                                && sm.is_file()
                            {
                                total += sm.len();
                            }
                        }
                    }
                }
            }
        }
    }
    total as f64 / (1024.0 * 1024.0)
}

// ── Process Behaviour Analysis ──────────────────────────────────────

/// Suspicious process finding from behavioural analysis.
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

/// Known-suspicious process name patterns.
const SUSPICIOUS_NAMES: &[(&str, &str)] = &[
    ("xmrig", "Crypto-miner (XMRig)"),
    ("minerd", "Crypto-miner (minerd)"),
    ("cpuminer", "Crypto-miner (cpuminer)"),
    ("kworker", "Potential rootkit masquerading as kernel worker"),
    (
        "kdevtmpfs",
        "Potential rootkit masquerading as kernel thread",
    ),
    (".hidden", "Hidden process (dotfile name)"),
    ("/tmp/", "Process running from /tmp — suspicious location"),
    (
        "/dev/shm",
        "Process running from shared memory — malware pattern",
    ),
    (
        "base64",
        "Base64 decode — potential obfuscated payload execution",
    ),
    ("curl|sh", "Pipe-to-shell — remote code execution pattern"),
    ("wget|sh", "Pipe-to-shell — remote code execution pattern"),
    (
        "python -c",
        "Inline Python execution — potential obfuscated payload",
    ),
    (
        "perl -e",
        "Inline Perl execution — potential obfuscated payload",
    ),
    (
        "ruby -e",
        "Inline Ruby execution — potential obfuscated payload",
    ),
];

fn process_basename(value: &str) -> &str {
    value.rsplit('/').next().unwrap_or(value)
}

fn contains_process_token(text: &str, token: &str) -> bool {
    text.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                '/' | '\\' | '|' | ';' | ':' | ',' | '(' | ')' | '[' | ']' | '=' | '"'
            )
    })
    .filter(|part| !part.is_empty())
    .any(|part| part == token)
}

fn is_relative_process_launch(name: &str, cmd: &str) -> bool {
    name.trim_start().starts_with("./") || cmd.trim_start().starts_with("./")
}

fn is_current_wardex_process(proc: &MacosProcessEvent) -> bool {
    proc.pid == std::process::id() && process_basename(&proc.name).eq_ignore_ascii_case("wardex")
}

fn looks_like_app_bundle_process(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("/applications/") && lower.contains(".app/contents/macos/")
}

/// Analyse running processes for suspicious behaviour.
pub fn analyze_processes(procs: &[MacosProcessEvent]) -> Vec<ProcessFinding> {
    let mut findings = Vec::new();

    for p in procs {
        let name_lower = p.name.to_lowercase();
        let cmd_lower = p.cmd_line.to_lowercase();
        let base_lower = process_basename(&name_lower);
        let is_self_wardex = is_current_wardex_process(p);

        if contains_process_token(&name_lower, "nc") || contains_process_token(&cmd_lower, "nc") {
            findings.push(ProcessFinding {
                pid: p.pid,
                name: p.name.clone(),
                user: p.user.clone(),
                risk_level: "critical",
                reason: "Netcat — potential reverse shell".to_string(),
                cpu_percent: p.cpu_percent,
                mem_percent: p.mem_percent,
            });
        }

        if contains_process_token(base_lower, "ncat")
            || contains_process_token(&name_lower, "ncat")
            || contains_process_token(&cmd_lower, "ncat")
        {
            findings.push(ProcessFinding {
                pid: p.pid,
                name: p.name.clone(),
                user: p.user.clone(),
                risk_level: "critical",
                reason: "Ncat — potential reverse shell".to_string(),
                cpu_percent: p.cpu_percent,
                mem_percent: p.mem_percent,
            });
        }

        if contains_process_token(base_lower, "socat")
            || contains_process_token(&name_lower, "socat")
            || contains_process_token(&cmd_lower, "socat")
        {
            findings.push(ProcessFinding {
                pid: p.pid,
                name: p.name.clone(),
                user: p.user.clone(),
                risk_level: "critical",
                reason: "Socat — potential reverse shell or tunnel".to_string(),
                cpu_percent: p.cpu_percent,
                mem_percent: p.mem_percent,
            });
        }

        if !is_self_wardex && is_relative_process_launch(&name_lower, &cmd_lower) {
            findings.push(ProcessFinding {
                pid: p.pid,
                name: p.name.clone(),
                user: p.user.clone(),
                risk_level: "elevated",
                reason: "Process launched from relative path — investigate execution context"
                    .to_string(),
                cpu_percent: p.cpu_percent,
                mem_percent: p.mem_percent,
            });
        }

        // Check against known-bad patterns
        for &(pattern, desc) in SUSPICIOUS_NAMES {
            if name_lower.contains(pattern) || cmd_lower.contains(pattern) {
                findings.push(ProcessFinding {
                    pid: p.pid,
                    name: p.name.clone(),
                    user: p.user.clone(),
                    risk_level: "critical",
                    reason: desc.to_string(),
                    cpu_percent: p.cpu_percent,
                    mem_percent: p.mem_percent,
                });
            }
        }

        // High CPU single process (>80% sustained)
        if p.cpu_percent > 80.0 && p.pid > 1 {
            findings.push(ProcessFinding {
                pid: p.pid,
                name: p.name.clone(),
                user: p.user.clone(),
                risk_level: "elevated",
                reason: format!(
                    "High CPU usage: {:.1}% — possible crypto-miner or resource abuse",
                    p.cpu_percent
                ),
                cpu_percent: p.cpu_percent,
                mem_percent: p.mem_percent,
            });
        }

        // High memory single process (>50%)
        if p.mem_percent > 50.0 && p.pid > 1 {
            findings.push(ProcessFinding {
                pid: p.pid,
                name: p.name.clone(),
                user: p.user.clone(),
                risk_level: "elevated",
                reason: format!(
                    "High memory usage: {:.1}% — possible memory-resident malware or DoS",
                    p.mem_percent
                ),
                cpu_percent: p.cpu_percent,
                mem_percent: p.mem_percent,
            });
        }

        // Root processes that aren't system daemons
        if p.user == "root"
            && p.ppid > 1
            && !is_known_system_process(base_lower)
            && !looks_like_app_bundle_process(&name_lower)
        {
            findings.push(ProcessFinding {
                pid: p.pid,
                name: p.name.clone(),
                user: p.user.clone(),
                risk_level: "severe",
                reason: "Non-system process running as root".to_string(),
                cpu_percent: p.cpu_percent,
                mem_percent: p.mem_percent,
            });
        }
    }

    // Deduplicate by pid (keep highest risk)
    findings.sort_by_key(|b| std::cmp::Reverse(risk_ord(b.risk_level)));
    let mut seen = std::collections::HashSet::new();
    findings.retain(|f| seen.insert(f.pid));
    findings
}

fn risk_ord(level: &str) -> u8 {
    match level {
        "critical" => 3,
        "severe" => 2,
        "elevated" => 1,
        _ => 0,
    }
}

fn is_known_system_process(name: &str) -> bool {
    const SYSTEM_PROCS: &[&str] = &[
        "launchd",
        "kernel_task",
        "mds",
        "mdworker",
        "opendirectoryd",
        "configd",
        "syslogd",
        "securityd",
        "distnoted",
        "login",
        "ps",
        "logd",
        "coreservicesd",
        "coreauthd",
        "WindowServer",
        "bluetoothd",
        "airportd",
        "wifid",
        "symptomsd",
        "trustd",
        "powerd",
        "diskarbitrationd",
        "fseventsd",
        "notifyd",
        "sandboxd",
        "cloudd",
        "networkserviceproxy",
        "loginwindow",
        "systemstats",
        "UserEventAgent",
        "cfprefsd",
        "apsd",
        "nsurlsessiond",
        "containermanagerd",
        "lsd",
        "ReportCrash",
        "mds_stores",
        "usermanagerd",
        "timed",
        "reversetemplated",
        "thermalmonitord",
        "sysmond",
        "biomed",
        "locationd",
        "coreduetd",
        "rapportd",
    ];
    SYSTEM_PROCS
        .iter()
        .any(|sp| name.contains(&sp.to_lowercase()))
}

// ── Composite Snapshot ──────────────────────────────────────────────

/// Full macOS telemetry snapshot aggregating all sources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacosSnapshot {
    pub timestamp: String,
    pub capabilities: MacosCapabilities,
    pub processes: Vec<MacosProcessEvent>,
    pub file_events: Vec<MacosFileEvent>,
    pub network_connections: Vec<MacosNetworkEvent>,
    pub mounts: Vec<MacosMountEvent>,
    pub login_events: Vec<MacosLoginEvent>,
    pub persistence_items: Vec<MacosPersistenceItem>,
}

impl MacosSnapshot {
    /// Collect a full telemetry snapshot.
    pub fn collect() -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        let caps = MacosCapabilities::detect();
        let watch_refs: Vec<&str> = MONITORED_PATHS.to_vec();

        Self {
            timestamp: now,
            capabilities: caps,
            processes: collect_processes(),
            file_events: snapshot_recent_files(&watch_refs, 300),
            network_connections: collect_network_connections(),
            mounts: collect_mounts(),
            login_events: collect_login_events(),
            persistence_items: collect_persistence_items(),
        }
    }

    /// Total event count across all sources.
    pub fn total_events(&self) -> usize {
        self.processes.len()
            + self.file_events.len()
            + self.network_connections.len()
            + self.mounts.len()
            + self.login_events.len()
            + self.persistence_items.len()
    }
}

// ── Supported Versions ──────────────────────────────────────────────

/// Supported macOS versions with their capabilities.
pub fn supported_versions() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "macOS 12 Monterey",
            "Baseline: SIP, TCC, Gatekeeper, ps/lsof/mount collection",
        ),
        (
            "macOS 13 Ventura",
            "Login Items API changes, Rapid Security Response updates",
        ),
        (
            "macOS 14 Sonoma",
            "Improved Endpoint Security framework, stricter TCC enforcement",
        ),
        (
            "macOS 15 Sequoia",
            "Enhanced code-signing verification, new privacy controls",
        ),
    ]
}

/// Entitlement requirements for full telemetry collection.
pub fn entitlement_requirements() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "Full Disk Access",
            "Required for reading LaunchDaemons, cron tabs, TCC.db",
        ),
        (
            "Endpoint Security",
            "Optional: real-time process/file event monitoring",
        ),
        (
            "Network Extensions",
            "Optional: packet-level network inspection",
        ),
        (
            "Accessibility",
            "Optional: UI event monitoring for screen lock detection",
        ),
        (
            "SystemExtensions",
            "Optional: load system extensions for deep monitoring",
        ),
    ]
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capabilities_construction() {
        let caps = MacosCapabilities {
            macos_version: "14.2.1".into(),
            build_number: "23C71".into(),
            sip_enabled: true,
            tcc_status: TccStatus::Enforcing,
            gatekeeper_enabled: true,
            code_signing_enforced: true,
            detected_security_tools: vec!["CrowdStrike Falcon".into()],
            full_disk_access: true,
        };
        assert!(caps.sip_enabled);
        assert!(caps.gatekeeper_enabled);
        assert!(caps.code_signing_enforced);
        assert_eq!(caps.tcc_status, TccStatus::Enforcing);
        assert_eq!(caps.detected_security_tools.len(), 1);
        assert!(caps.security_concerns().is_empty());
        assert!(caps.unavailable_features().is_empty());
    }

    #[test]
    fn test_capabilities_security_concerns() {
        let caps = MacosCapabilities {
            macos_version: "13.0".into(),
            build_number: "22A380".into(),
            sip_enabled: false,
            tcc_status: TccStatus::Enforcing,
            gatekeeper_enabled: false,
            code_signing_enforced: true,
            detected_security_tools: vec![],
            full_disk_access: false,
        };
        let concerns = caps.security_concerns();
        assert_eq!(concerns.len(), 4);
        assert!(concerns.contains(&"SIP disabled — system integrity not protected"));
        assert!(concerns.contains(&"Gatekeeper disabled — unsigned apps can run"));
        assert!(concerns.contains(&"Full Disk Access not granted — limited telemetry"));
        assert!(concerns.contains(&"No third-party security tools detected"));
    }

    #[test]
    fn test_sip_status_parsing() {
        assert!(parse_sip_status(
            "System Integrity Protection status: enabled."
        ));
        assert!(!parse_sip_status(
            "System Integrity Protection status: disabled."
        ));
        assert!(parse_sip_status(
            "System Integrity Protection status: enabled (Custom Configuration)."
        ));
        assert!(!parse_sip_status("unknown output"));
    }

    #[test]
    fn test_process_event_creation() {
        let evt = MacosProcessEvent {
            timestamp: "2026-01-15T10:00:00Z".into(),
            pid: 1234,
            ppid: 1,
            name: "Safari".into(),
            user: "michel".into(),
            group: "staff".into(),
            cpu_percent: 2.5,
            mem_percent: 1.8,
            code_signed: CodeSignStatus::Valid,
            cmd_line: "/Applications/Safari.app/Contents/MacOS/Safari".into(),
            ocsf_class_id: OCSF_PROCESS_ACTIVITY,
        };
        assert_eq!(evt.pid, 1234);
        assert_eq!(evt.ppid, 1);
        assert_eq!(evt.code_signed, CodeSignStatus::Valid);
        assert_eq!(evt.ocsf_class_id, 1007);
    }

    #[test]
    fn test_persistence_path_classification() {
        assert_eq!(
            classify_persistence_path("/Library/LaunchAgents/com.example.plist"),
            Some(PersistenceType::LaunchAgent)
        );
        assert_eq!(
            classify_persistence_path("/Library/LaunchDaemons/com.example.plist"),
            Some(PersistenceType::LaunchDaemon)
        );
        assert_eq!(
            classify_persistence_path("~/Library/LaunchAgents/com.example.plist"),
            Some(PersistenceType::LaunchAgent)
        );
        assert_eq!(classify_persistence_path("/usr/local/bin/tool"), None);
    }

    #[test]
    fn test_mount_line_parsing() {
        let line = "/dev/disk3s1 on /Volumes/USB (hfs, local, nodev, nosuid, read-only)";
        let evt = parse_mount_line(line).unwrap();
        assert_eq!(evt.device, "/dev/disk3s1");
        assert_eq!(evt.mount_point, "/Volumes/USB");
        assert_eq!(evt.fs_type, "hfs");
        assert!(evt.is_external);
        assert!(!evt.is_dmg);
    }

    #[test]
    fn test_mount_line_system_disk() {
        let line = "/dev/disk1s1 on / (apfs, sealed, local, read-only, journaled)";
        let evt = parse_mount_line(line).unwrap();
        assert_eq!(evt.device, "/dev/disk1s1");
        assert_eq!(evt.mount_point, "/");
        assert_eq!(evt.fs_type, "apfs");
        assert!(!evt.is_external);
    }

    #[test]
    fn test_login_event_parsing() {
        let line = "michel  ttys000                   Mon Mar 31 10:00   still logged in";
        let evt = parse_last_line(line).unwrap();
        assert_eq!(evt.user, "michel");
        assert_eq!(evt.terminal, "ttys000");
        assert_eq!(evt.event_type, MacosLoginType::Login);
    }

    #[test]
    fn test_login_event_reboot() {
        let line = "reboot  ~                         Mon Mar 31 09:00";
        let evt = parse_last_line(line).unwrap();
        assert_eq!(evt.user, "reboot");
        assert_eq!(evt.event_type, MacosLoginType::Reboot);
    }

    #[test]
    fn test_ocsf_class_mapping() {
        assert_eq!(ocsf_class_for("process"), 1007);
        assert_eq!(ocsf_class_for("file"), 1001);
        assert_eq!(ocsf_class_for("network"), 4001);
        assert_eq!(ocsf_class_for("login"), 3002);
        assert_eq!(ocsf_class_for("auth"), 3002);
        assert_eq!(ocsf_class_for("persistence"), 5001);
        assert_eq!(ocsf_class_for("mount"), 5001);
        assert_eq!(ocsf_class_for("device"), 5002);
        assert_eq!(ocsf_class_for("unknown"), 2004);
    }

    #[test]
    fn test_snapshot_total_events_empty() {
        let snap = MacosSnapshot {
            timestamp: "t".into(),
            capabilities: MacosCapabilities {
                macos_version: "14.0".into(),
                build_number: "23A344".into(),
                sip_enabled: true,
                tcc_status: TccStatus::Enforcing,
                gatekeeper_enabled: true,
                code_signing_enforced: true,
                detected_security_tools: vec![],
                full_disk_access: false,
            },
            processes: vec![],
            file_events: vec![],
            network_connections: vec![],
            mounts: vec![],
            login_events: vec![],
            persistence_items: vec![],
        };
        assert_eq!(snap.total_events(), 0);
    }

    #[test]
    fn test_version_capability_matrix() {
        let versions = supported_versions();
        assert_eq!(versions.len(), 4);
        assert!(versions[0].0.contains("Monterey"));
        assert!(versions[1].0.contains("Ventura"));
        assert!(versions[2].0.contains("Sonoma"));
        assert!(versions[3].0.contains("Sequoia"));
    }

    #[test]
    fn test_entitlement_requirements_listing() {
        let reqs = entitlement_requirements();
        assert!(reqs.len() >= 3);
        let labels: Vec<&str> = reqs.iter().map(|(l, _)| *l).collect();
        assert!(labels.contains(&"Full Disk Access"));
        assert!(labels.contains(&"Endpoint Security"));
        assert!(labels.contains(&"Network Extensions"));
    }

    #[test]
    fn test_parse_lsof_endpoint_ipv4() {
        let (addr, port) = parse_lsof_endpoint("192.168.1.100:443");
        assert_eq!(addr, "192.168.1.100");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_lsof_endpoint_ipv6() {
        let (addr, port) = parse_lsof_endpoint("[::1]:8080");
        assert_eq!(addr, "::1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn process_analysis_does_not_flag_onedrive_sync_service_as_netcat() {
        let procs = vec![MacosProcessEvent {
            timestamp: "t".into(),
            pid: 19927,
            ppid: 1,
            name: "/Applications/OneDrive.app/Contents/OneDrive Sync Service.app/Contents/MacOS/OneDrive Sync Service".into(),
            user: "michelpicker".into(),
            group: "staff".into(),
            cpu_percent: 0.0,
            mem_percent: 0.1,
            code_signed: CodeSignStatus::Valid,
            cmd_line: "/Applications/OneDrive.app/Contents/OneDrive Sync Service.app/Contents/MacOS/OneDrive Sync Service /silentConfig".into(),
            ocsf_class_id: OCSF_PROCESS_ACTIVITY,
        }];

        let findings = analyze_processes(&procs);
        assert!(findings.is_empty());
    }

    #[test]
    fn process_analysis_flags_relative_path_launch_as_elevated_not_critical() {
        let procs = vec![MacosProcessEvent {
            timestamp: "t".into(),
            pid: 27445,
            ppid: 73302,
            name: "./release/v0.41.3/wardex-macos-aarch64/wardex".into(),
            user: "michelpicker".into(),
            group: "staff".into(),
            cpu_percent: 0.0,
            mem_percent: 0.1,
            code_signed: CodeSignStatus::Unknown,
            cmd_line: "./release/v0.41.3/wardex-macos-aarch64/wardex".into(),
            ocsf_class_id: OCSF_PROCESS_ACTIVITY,
        }];

        let findings = analyze_processes(&procs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].risk_level, "elevated");
        assert!(findings[0].reason.contains("relative path"));
    }
}
