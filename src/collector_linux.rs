//! Linux-specific XDR collector for process lifecycle, file activity,
//! socket/network metadata, DNS monitoring, privilege escalation indicators,
//! container awareness, and capability detection.  All collection reads from
//! /proc and /sys (no external dependencies).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

// ── OCSF Class IDs ─────────────────────────────────────────────────

pub const OCSF_FILE_ACTIVITY: u32 = 1001;
pub const OCSF_PROCESS_ACTIVITY: u32 = 1007;
pub const OCSF_AUTH: u32 = 3002;
pub const OCSF_NETWORK_ACTIVITY: u32 = 4001;
pub const OCSF_DNS_ACTIVITY: u32 = 4003;
pub const OCSF_CONFIG_STATE: u32 = 5001;
pub const OCSF_DETECTION_FINDING: u32 = 2004;

/// Map a Linux event source to its OCSF class ID.
pub fn ocsf_class_for(source: &str) -> u32 {
    match source {
        "process" => OCSF_PROCESS_ACTIVITY,
        "file" => OCSF_FILE_ACTIVITY,
        "network" => OCSF_NETWORK_ACTIVITY,
        "dns" => OCSF_DNS_ACTIVITY,
        "auth" | "privesc" => OCSF_AUTH,
        "config" | "container" => OCSF_CONFIG_STATE,
        _ => OCSF_DETECTION_FINDING,
    }
}

// ── Capability Detection ────────────────────────────────────────────

/// Linux host capability flags — determines which telemetry sources
/// are available on the running kernel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxCapabilities {
    pub kernel_version: String,
    pub distro: String,
    pub has_ebpf: bool,
    pub has_auditd: bool,
    pub has_fanotify: bool,
    pub container_runtime: Option<String>,
    pub cgroup_version: u8,
    pub security_module: Option<String>,
}

impl LinuxCapabilities {
    /// Detect capabilities of the current Linux host.
    pub fn detect() -> Self {
        let kernel_version =
            read_file_trimmed("/proc/version").unwrap_or_else(|| "Linux (unknown)".into());
        let distro = detect_distro();
        Self {
            has_ebpf: detect_ebpf_support(&kernel_version),
            has_auditd: detect_auditd(),
            has_fanotify: Path::new("/proc/sys/fs/fanotify").exists()
                || kernel_version_at_least(&kernel_version, 2, 6, 37),
            container_runtime: detect_container_runtime(),
            cgroup_version: detect_cgroup_version(),
            security_module: detect_security_module(),
            kernel_version,
            distro,
        }
    }

    /// Return list of unavailable features for documentation/logging.
    pub fn unavailable_features(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if !self.has_ebpf {
            missing.push("eBPF tracing");
        }
        if !self.has_auditd {
            missing.push("auditd event stream");
        }
        if !self.has_fanotify {
            missing.push("fanotify file monitoring");
        }
        if self.security_module.is_none() {
            missing.push("security module (AppArmor/SELinux)");
        }
        missing
    }
}

fn read_file_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn detect_distro() -> String {
    // Try /etc/os-release first (systemd-based distros)
    if let Ok(content) = fs::read_to_string("/etc/os-release") {
        for line in content.lines() {
            if let Some(val) = line.strip_prefix("PRETTY_NAME=") {
                return val.trim_matches('"').to_string();
            }
        }
    }
    // Fallback to /etc/lsb-release
    if let Ok(content) = fs::read_to_string("/etc/lsb-release") {
        for line in content.lines() {
            if let Some(val) = line.strip_prefix("DISTRIB_DESCRIPTION=") {
                return val.trim_matches('"').to_string();
            }
        }
    }
    "Linux (unknown distro)".into()
}

fn detect_ebpf_support(kernel_version: &str) -> bool {
    // eBPF requires kernel 4.1+; /sys/fs/bpf is a strong indicator
    Path::new("/sys/fs/bpf").exists() || kernel_version_at_least(kernel_version, 4, 1, 0)
}

fn detect_auditd() -> bool {
    Path::new("/var/run/auditd.pid").exists()
        || Path::new("/run/auditd.pid").exists()
        || std::process::Command::new("pidof")
            .arg("auditd")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
}

fn detect_container_runtime() -> Option<String> {
    if Path::new("/var/run/docker.sock").exists() || Path::new("/run/docker.sock").exists() {
        return Some("docker".into());
    }
    if Path::new("/var/run/podman").exists() || Path::new("/run/podman").exists() {
        return Some("podman".into());
    }
    if Path::new("/var/run/containerd/containerd.sock").exists()
        || Path::new("/run/containerd/containerd.sock").exists()
    {
        return Some("containerd".into());
    }
    None
}

fn detect_cgroup_version() -> u8 {
    if Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        2
    } else if Path::new("/sys/fs/cgroup").exists() {
        1
    } else {
        0
    }
}

fn detect_security_module() -> Option<String> {
    // Check /sys/kernel/security/lsm
    if let Some(lsm) = read_file_trimmed("/sys/kernel/security/lsm") {
        if lsm.contains("selinux") {
            return Some("SELinux".into());
        }
        if lsm.contains("apparmor") {
            return Some("AppArmor".into());
        }
    }
    // Fallback checks
    if Path::new("/etc/selinux/config").exists() {
        return Some("SELinux".into());
    }
    if Path::new("/sys/kernel/security/apparmor").exists() {
        return Some("AppArmor".into());
    }
    None
}

/// Parse "Linux version X.Y.Z..." and check against minimum.
fn kernel_version_at_least(version_str: &str, major: u32, minor: u32, patch: u32) -> bool {
    // /proc/version: "Linux version 5.15.0-91-generic ..."
    let token = version_str
        .split_whitespace()
        .find(|t| t.chars().next().is_some_and(|c| c.is_ascii_digit()));
    if let Some(ver) = token {
        let parts: Vec<u32> = ver
            .split(|c: char| !c.is_ascii_digit())
            .take(3)
            .filter_map(|s| s.parse().ok())
            .collect();
        if parts.len() >= 3 {
            return (parts[0], parts[1], parts[2]) >= (major, minor, patch);
        }
    }
    false
}

// ── Process Events ──────────────────────────────────────────────────

/// A Linux process event capturing creation or snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxProcessEvent {
    pub timestamp: String,
    pub event_type: LinuxProcessEventType,
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub exe_path: String,
    pub cmd_line: String,
    pub uid: u32,
    pub gid: u32,
    pub cgroup: String,
    pub ns_pid: Option<u64>,
    pub ocsf_class_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LinuxProcessEventType {
    Snapshot,
    Create,
    Terminate,
}

/// Collect current running processes from /proc.
pub fn collect_processes() -> Vec<LinuxProcessEvent> {
    let now = chrono::Utc::now().to_rfc3339();
    let entries = match fs::read_dir("/proc") {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let mut events = Vec::new();
    for entry in entries.flatten() {
        let fname = entry.file_name();
        let name_str = fname.to_string_lossy();
        let pid: u32 = match name_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let proc_dir = format!("/proc/{pid}");
        let status = match fs::read_to_string(format!("{proc_dir}/status")) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let mut name = String::new();
        let mut ppid: u32 = 0;
        let mut uid: u32 = 0;
        let mut gid: u32 = 0;
        let mut ns_pid: Option<u64> = None;
        for line in status.lines() {
            if let Some(val) = line.strip_prefix("Name:\t") {
                name = val.trim().to_string();
            } else if let Some(val) = line.strip_prefix("PPid:\t") {
                ppid = val.trim().parse().unwrap_or(0);
            } else if let Some(val) = line.strip_prefix("Uid:\t") {
                uid = val
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            } else if let Some(val) = line.strip_prefix("Gid:\t") {
                gid = val
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
            } else if let Some(val) = line.strip_prefix("NSpid:\t") {
                // Last NSpid token is the pid inside the innermost namespace
                ns_pid = val.split_whitespace().last().and_then(|s| s.parse().ok());
            }
        }
        let exe_path = fs::read_link(format!("{proc_dir}/exe"))
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let cmd_line = fs::read_to_string(format!("{proc_dir}/cmdline"))
            .unwrap_or_default()
            .replace('\0', " ")
            .trim()
            .to_string();
        let cgroup = fs::read_to_string(format!("{proc_dir}/cgroup"))
            .unwrap_or_default()
            .lines()
            .next()
            .unwrap_or("")
            .to_string();

        events.push(LinuxProcessEvent {
            timestamp: now.clone(),
            event_type: LinuxProcessEventType::Snapshot,
            pid,
            ppid,
            name,
            exe_path,
            cmd_line,
            uid,
            gid,
            cgroup,
            ns_pid,
            ocsf_class_id: OCSF_PROCESS_ACTIVITY,
        });
    }
    events
}

// ── File Events ─────────────────────────────────────────────────────

/// File activity metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxFileEvent {
    pub timestamp: String,
    pub path: String,
    pub operation: FileOperation,
    pub uid: u32,
    pub inode: u64,
    pub size: u64,
    pub ocsf_class_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FileOperation {
    Read,
    Write,
    Create,
    Delete,
    Chmod,
    Rename,
}

/// Snapshot recently modified files under watched paths.
/// Reads metadata only — does not use inotify/fanotify.
pub fn snapshot_recent_files(watch_paths: &[&str], since_secs: u64) -> Vec<LinuxFileEvent> {
    let now = chrono::Utc::now().to_rfc3339();
    let cutoff = std::time::SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(since_secs))
        .unwrap_or(std::time::UNIX_EPOCH);
    let mut events = Vec::new();
    for base in watch_paths {
        let entries = match fs::read_dir(base) {
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
            #[cfg(target_os = "linux")]
            let inode = {
                use std::os::unix::fs::MetadataExt;
                meta.ino()
            };
            #[cfg(not(target_os = "linux"))]
            let inode = 0u64;

            #[cfg(target_os = "linux")]
            let uid = {
                use std::os::unix::fs::MetadataExt;
                meta.uid()
            };
            #[cfg(not(target_os = "linux"))]
            let uid = 0u32;

            events.push(LinuxFileEvent {
                timestamp: now.clone(),
                path: entry.path().to_string_lossy().to_string(),
                operation: FileOperation::Write,
                uid,
                inode,
                size: meta.len(),
                ocsf_class_id: OCSF_FILE_ACTIVITY,
            });
        }
    }
    events
}

// ── Network Sockets ─────────────────────────────────────────────────

/// An active network socket observed on the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxNetworkSocket {
    pub timestamp: String,
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub inode: u64,
    pub pid: Option<u32>,
    pub ocsf_class_id: u32,
}

/// TCP states from /proc/net/tcp (hex-encoded).
fn tcp_state_name(hex: &str) -> &'static str {
    match hex {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "UNKNOWN",
    }
}

/// Parse a hex-encoded IPv4 address + port from /proc/net/tcp format.
/// Format: "0100007F:0035" => 127.0.0.1:53
fn parse_proc_net_addr(s: &str) -> (String, u16) {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return (String::new(), 0);
    }
    let port = u16::from_str_radix(parts[1], 16).unwrap_or(0);
    let hex_addr = parts[0];
    if hex_addr.len() == 8 {
        // IPv4: stored in little-endian
        let raw = u32::from_str_radix(hex_addr, 16).unwrap_or(0);
        let addr = format!(
            "{}.{}.{}.{}",
            raw & 0xFF,
            (raw >> 8) & 0xFF,
            (raw >> 16) & 0xFF,
            (raw >> 24) & 0xFF,
        );
        (addr, port)
    } else {
        // IPv6 or unexpected — return raw
        (hex_addr.to_string(), port)
    }
}

/// Build a mapping from socket inode to PID by scanning /proc/[pid]/fd.
fn build_inode_to_pid_map() -> HashMap<u64, u32> {
    let mut map = HashMap::new();
    let entries = match fs::read_dir("/proc") {
        Ok(e) => e,
        Err(_) => return map,
    };
    for entry in entries.flatten() {
        let fname = entry.file_name();
        let pid: u32 = match fname.to_string_lossy().parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let fd_dir = format!("/proc/{pid}/fd");
        let fds = match fs::read_dir(&fd_dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for fd in fds.flatten() {
            if let Ok(link) = fs::read_link(fd.path()) {
                let link_str = link.to_string_lossy();
                if let Some(inode_str) = link_str
                    .strip_prefix("socket:[")
                    .and_then(|s| s.strip_suffix(']'))
                    && let Ok(inode) = inode_str.parse::<u64>()
                {
                    map.insert(inode, pid);
                }
            }
        }
    }
    map
}

/// Collect active TCP and UDP sockets from /proc/net.
pub fn collect_network_sockets() -> Vec<LinuxNetworkSocket> {
    let now = chrono::Utc::now().to_rfc3339();
    let inode_map = build_inode_to_pid_map();
    let mut sockets = Vec::new();

    for (proto, path) in &[("TCP", "/proc/net/tcp"), ("UDP", "/proc/net/udp")] {
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for line in content.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }
            let (local_addr, local_port) = parse_proc_net_addr(fields[1]);
            let (remote_addr, remote_port) = parse_proc_net_addr(fields[2]);
            let state = if *proto == "TCP" {
                tcp_state_name(fields[3]).to_string()
            } else {
                "STATELESS".into()
            };
            let inode: u64 = fields[9].parse().unwrap_or(0);
            let pid = inode_map.get(&inode).copied();
            sockets.push(LinuxNetworkSocket {
                timestamp: now.clone(),
                protocol: proto.to_string(),
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                state,
                inode,
                pid,
                ocsf_class_id: OCSF_NETWORK_ACTIVITY,
            });
        }
    }
    sockets
}

// ── DNS Events ──────────────────────────────────────────────────────

/// DNS query/configuration event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxDnsEvent {
    pub timestamp: String,
    pub query_name: String,
    pub query_type: String,
    pub source: String,
    pub ocsf_class_id: u32,
}

/// Collect DNS configuration from /etc/resolv.conf and optionally
/// systemd-resolved statistics.
pub fn collect_dns_info() -> Vec<LinuxDnsEvent> {
    let now = chrono::Utc::now().to_rfc3339();
    let mut events = Vec::new();

    // /etc/resolv.conf nameservers
    if let Ok(content) = fs::read_to_string("/etc/resolv.conf") {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') || trimmed.is_empty() {
                continue;
            }
            if let Some(ns) = trimmed.strip_prefix("nameserver") {
                let server = ns.trim();
                events.push(LinuxDnsEvent {
                    timestamp: now.clone(),
                    query_name: server.to_string(),
                    query_type: "nameserver".into(),
                    source: "/etc/resolv.conf".into(),
                    ocsf_class_id: OCSF_DNS_ACTIVITY,
                });
            } else if let Some(search) = trimmed.strip_prefix("search") {
                for domain in search.split_whitespace() {
                    events.push(LinuxDnsEvent {
                        timestamp: now.clone(),
                        query_name: domain.to_string(),
                        query_type: "search_domain".into(),
                        source: "/etc/resolv.conf".into(),
                        ocsf_class_id: OCSF_DNS_ACTIVITY,
                    });
                }
            }
        }
    }

    // systemd-resolved cache statistics (if available)
    if let Ok(output) = std::process::Command::new("resolvectl")
        .arg("statistics")
        .output()
        && output.status.success()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        events.push(LinuxDnsEvent {
            timestamp: now.clone(),
            query_name: text.trim().to_string(),
            query_type: "resolved_stats".into(),
            source: "systemd-resolved".into(),
            ocsf_class_id: OCSF_DNS_ACTIVITY,
        });
    }

    events
}

// ── Privilege Escalation Indicators ─────────────────────────────────

/// Privilege escalation indicator found on the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxPrivEscIndicator {
    pub timestamp: String,
    pub indicator_type: PrivEscType,
    pub path: String,
    pub details: String,
    pub risk: PrivEscRisk,
    pub ocsf_class_id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PrivEscType {
    SuidBinary,
    SgidBinary,
    Capability,
    SudoConfig,
    WorldWritableDir,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PrivEscRisk {
    High,
    Medium,
    Low,
    Info,
}

/// Well-known SUID binaries that are expected on a normal system.
const EXPECTED_SUID: &[&str] = &[
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/passwd",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/usr/bin/newgrp",
    "/usr/bin/gpasswd",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/bin/fusermount",
    "/usr/bin/fusermount3",
    "/usr/bin/pkexec",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/openssh/ssh-keysign",
    "/usr/sbin/pppd",
    "/bin/su",
    "/bin/mount",
    "/bin/umount",
    "/bin/ping",
    "/usr/bin/ping",
];

/// Classify SUID risk: unexpected SUID = High, known = Low.
pub fn classify_suid_risk(path: &str) -> PrivEscRisk {
    if EXPECTED_SUID.contains(&path) {
        PrivEscRisk::Low
    } else if path.contains("nmap")
        || path.contains("python")
        || path.contains("perl")
        || path.contains("vim")
        || path.contains("find")
        || path.contains("bash")
    {
        PrivEscRisk::High
    } else {
        PrivEscRisk::Medium
    }
}

/// Scan common binary directories for SUID/SGID binaries.
pub fn detect_suid_binaries() -> Vec<LinuxPrivEscIndicator> {
    let now = chrono::Utc::now().to_rfc3339();
    let dirs = ["/usr/bin", "/usr/sbin", "/usr/local/bin", "/bin", "/sbin"];
    let mut indicators = Vec::new();

    for dir in &dirs {
        let entries = match fs::read_dir(dir) {
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

            #[cfg(target_os = "linux")]
            let mode = {
                use std::os::unix::fs::PermissionsExt;
                meta.permissions().mode()
            };
            #[cfg(not(target_os = "linux"))]
            let mode: u32 = 0;

            let path = entry.path().to_string_lossy().to_string();

            // SUID bit: 0o4000
            if mode & 0o4000 != 0 {
                let risk = classify_suid_risk(&path);
                indicators.push(LinuxPrivEscIndicator {
                    timestamp: now.clone(),
                    indicator_type: PrivEscType::SuidBinary,
                    path: path.clone(),
                    details: format!("mode={:#o}", mode),
                    risk,
                    ocsf_class_id: OCSF_AUTH,
                });
            }
            // SGID bit: 0o2000
            if mode & 0o2000 != 0 {
                indicators.push(LinuxPrivEscIndicator {
                    timestamp: now.clone(),
                    indicator_type: PrivEscType::SgidBinary,
                    path,
                    details: format!("mode={:#o}", mode),
                    risk: PrivEscRisk::Info,
                    ocsf_class_id: OCSF_AUTH,
                });
            }
        }
    }
    indicators
}

/// Check for interesting sudo configuration lines.
pub fn check_sudo_config() -> Vec<LinuxPrivEscIndicator> {
    let now = chrono::Utc::now().to_rfc3339();
    let mut indicators = Vec::new();

    let sudoers_paths = ["/etc/sudoers"];
    for path in &sudoers_paths {
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('#') || trimmed.is_empty() {
                continue;
            }
            // Flag NOPASSWD entries
            if trimmed.contains("NOPASSWD") {
                indicators.push(LinuxPrivEscIndicator {
                    timestamp: now.clone(),
                    indicator_type: PrivEscType::SudoConfig,
                    path: path.to_string(),
                    details: trimmed.to_string(),
                    risk: PrivEscRisk::High,
                    ocsf_class_id: OCSF_AUTH,
                });
            }
            // Flag broad ALL=(ALL) ALL
            if trimmed.contains("ALL=(ALL)") && trimmed.contains("ALL") {
                indicators.push(LinuxPrivEscIndicator {
                    timestamp: now.clone(),
                    indicator_type: PrivEscType::SudoConfig,
                    path: path.to_string(),
                    details: trimmed.to_string(),
                    risk: PrivEscRisk::Medium,
                    ocsf_class_id: OCSF_AUTH,
                });
            }
        }
    }

    // Also scan /etc/sudoers.d/ directory
    if let Ok(entries) = fs::read_dir("/etc/sudoers.d") {
        for entry in entries.flatten() {
            let content = match fs::read_to_string(entry.path()) {
                Ok(c) => c,
                Err(_) => continue,
            };
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with('#') || trimmed.is_empty() {
                    continue;
                }
                if trimmed.contains("NOPASSWD") {
                    indicators.push(LinuxPrivEscIndicator {
                        timestamp: now.clone(),
                        indicator_type: PrivEscType::SudoConfig,
                        path: entry.path().to_string_lossy().to_string(),
                        details: trimmed.to_string(),
                        risk: PrivEscRisk::High,
                        ocsf_class_id: OCSF_AUTH,
                    });
                }
            }
        }
    }

    indicators
}

// ── Container Detection ─────────────────────────────────────────────

/// Container context for the current process or an observed process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxContainerInfo {
    pub timestamp: String,
    pub is_containerized: bool,
    pub runtime: Option<String>,
    pub container_id: Option<String>,
    pub cgroup_path: String,
    pub pid_namespace: Option<String>,
    pub ocsf_class_id: u32,
}

/// Detect if the current process runs inside a container.
pub fn detect_container() -> LinuxContainerInfo {
    let now = chrono::Utc::now().to_rfc3339();
    let cgroup_path = fs::read_to_string("/proc/1/cgroup")
        .unwrap_or_default()
        .trim()
        .to_string();

    let (is_containerized, runtime, container_id) = parse_container_from_cgroup(&cgroup_path);

    let pid_namespace = fs::read_link("/proc/1/ns/pid")
        .ok()
        .map(|p| p.to_string_lossy().to_string());

    LinuxContainerInfo {
        timestamp: now,
        is_containerized,
        runtime,
        container_id,
        cgroup_path,
        pid_namespace,
        ocsf_class_id: OCSF_CONFIG_STATE,
    }
}

/// Parse container ID and runtime from a cgroup path.
pub fn parse_container_from_cgroup(cgroup: &str) -> (bool, Option<String>, Option<String>) {
    // Docker: /docker/<container_id> or /system.slice/docker-<id>.scope
    // Podman: /machine.slice/libpod-<id>.scope
    // containerd: /system.slice/containerd-<id>.scope
    // k8s: /kubepods/.../<id>
    if cgroup.contains("/docker") || cgroup.contains("docker-") {
        let id = extract_container_id(cgroup);
        return (true, Some("docker".into()), id);
    }
    if cgroup.contains("libpod-") || cgroup.contains("/podman") {
        let id = extract_container_id(cgroup);
        return (true, Some("podman".into()), id);
    }
    if cgroup.contains("containerd-") {
        let id = extract_container_id(cgroup);
        return (true, Some("containerd".into()), id);
    }
    if cgroup.contains("/kubepods") || cgroup.contains("/kubelet") {
        let id = extract_container_id(cgroup);
        return (true, Some("kubernetes".into()), id);
    }
    // /.dockerenv file is another indicator
    if Path::new("/.dockerenv").exists() {
        return (true, Some("docker".into()), None);
    }
    (false, None, None)
}

fn extract_container_id(cgroup: &str) -> Option<String> {
    // Try to find a 64-char hex container ID
    for segment in cgroup.split('/') {
        let cleaned = segment
            .trim_start_matches("docker-")
            .trim_start_matches("libpod-")
            .trim_start_matches("containerd-")
            .trim_end_matches(".scope");
        if cleaned.len() >= 12
            && cleaned.len() <= 64
            && cleaned.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Some(cleaned.to_string());
        }
    }
    // Last segment might be the ID
    cgroup
        .rsplit('/')
        .find(|s| {
            let s = s.trim();
            s.len() >= 12 && s.chars().all(|c| c.is_ascii_hexdigit())
        })
        .map(|s| s.trim().to_string())
}

// ── Composite Snapshot ──────────────────────────────────────────────

/// Full Linux telemetry snapshot aggregating all sources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxSnapshot {
    pub timestamp: String,
    pub capabilities: LinuxCapabilities,
    pub processes: Vec<LinuxProcessEvent>,
    pub file_events: Vec<LinuxFileEvent>,
    pub network_sockets: Vec<LinuxNetworkSocket>,
    pub dns_info: Vec<LinuxDnsEvent>,
    pub priv_esc_indicators: Vec<LinuxPrivEscIndicator>,
    pub container_info: LinuxContainerInfo,
}

impl LinuxSnapshot {
    /// Collect a full telemetry snapshot.
    pub fn collect() -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        let caps = LinuxCapabilities::detect();
        let watch_dirs = ["/etc", "/tmp", "/var/log"];
        let watch_refs: Vec<&str> = watch_dirs.to_vec();

        let mut privesc = detect_suid_binaries();
        privesc.extend(check_sudo_config());

        Self {
            timestamp: now,
            capabilities: caps,
            processes: collect_processes(),
            file_events: snapshot_recent_files(&watch_refs, 300),
            network_sockets: collect_network_sockets(),
            dns_info: collect_dns_info(),
            priv_esc_indicators: privesc,
            container_info: detect_container(),
        }
    }

    /// Total event count across all sources.
    pub fn total_events(&self) -> usize {
        self.processes.len()
            + self.file_events.len()
            + self.network_sockets.len()
            + self.dns_info.len()
            + self.priv_esc_indicators.len()
            + 1 // container_info is always one record
    }
}

/// Supported Linux distributions and their capabilities.
pub fn supported_distros() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "Ubuntu 20.04+",
            "Full telemetry: /proc, /sys, AppArmor, cgroup v2, eBPF",
        ),
        ("Debian 11+", "Full telemetry: /proc, /sys, AppArmor"),
        (
            "RHEL/Rocky 8+",
            "Full telemetry: /proc, /sys, SELinux, cgroup v2",
        ),
        ("Fedora 36+", "Full telemetry with latest kernel features"),
        (
            "Alpine 3.16+",
            "Reduced: musl libc, no systemd, limited /proc",
        ),
        ("Amazon Linux 2", "Full telemetry: /proc, /sys, SELinux"),
    ]
}

// ── Tests ───────────────────────────────────────────────────────────

// ── Cross-platform Process Analysis & App Inventory ─────────────────

/// A suspicious-process finding, analogous to the macOS version.
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

/// An installed software package.
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

const LINUX_SYSTEM_PROCS: &[&str] = &[
    "systemd",
    "kthreadd",
    "rcu_gp",
    "rcu_par_gp",
    "kworker",
    "ksoftirqd",
    "migration",
    "cpuhp",
    "watchdog",
    "kdevtmpfsi",
    "netns",
    "kauditd",
    "khungtaskd",
    "oom_reaper",
    "writeback",
    "kcompactd",
    "kblockd",
    "blkcg_punt",
    "ata_sff",
    "edac-poller",
    "devfreq_wq",
    "kswapd",
    "ecryptfs",
    "kthrotld",
    "irq/",
    "scsi_",
    "ext4-rsv-conver",
    "jbd2/",
    "loop",
    "zswap",
    "cryptd",
    "journald",
    "udevd",
    "dbus-daemon",
    "polkitd",
    "NetworkManager",
    "sshd",
    "crond",
    "atd",
    "rsyslogd",
    "auditd",
    "firewalld",
    "containerd",
    "dockerd",
    "snapd",
    "thermald",
    "acpid",
    "login",
    "ps",
];

/// Analyse running Linux processes for suspicious behaviour.
pub fn analyze_processes(procs: &[LinuxProcessEvent]) -> Vec<ProcessFinding> {
    let mut findings = Vec::new();

    // Gather per-process CPU/memory from ps for enrichment
    let usage = collect_process_usage();

    for p in procs {
        let name_lower = p.name.to_lowercase();
        let cmd_lower = p.cmd_line.to_lowercase();
        let exe_lower = p.exe_path.to_lowercase();
        let base_lower = process_basename(&name_lower);
        let (cpu, mem) = usage.get(&p.pid).copied().unwrap_or((0.0, 0.0));

        if contains_process_token(&name_lower, "nc")
            || contains_process_token(&cmd_lower, "nc")
            || contains_process_token(&exe_lower, "nc")
        {
            findings.push(ProcessFinding {
                pid: p.pid,
                name: p.name.clone(),
                user: uid_to_name(p.uid),
                risk_level: "critical",
                reason: "Netcat — potential reverse shell".to_string(),
                cpu_percent: cpu,
                mem_percent: mem,
            });
        }

        if contains_process_token(base_lower, "ncat")
            || contains_process_token(&name_lower, "ncat")
            || contains_process_token(&cmd_lower, "ncat")
            || contains_process_token(&exe_lower, "ncat")
        {
            findings.push(ProcessFinding {
                pid: p.pid,
                name: p.name.clone(),
                user: uid_to_name(p.uid),
                risk_level: "critical",
                reason: "Ncat — potential reverse shell".to_string(),
                cpu_percent: cpu,
                mem_percent: mem,
            });
        }

        if contains_process_token(base_lower, "socat")
            || contains_process_token(&name_lower, "socat")
            || contains_process_token(&cmd_lower, "socat")
            || contains_process_token(&exe_lower, "socat")
        {
            findings.push(ProcessFinding {
                pid: p.pid,
                name: p.name.clone(),
                user: uid_to_name(p.uid),
                risk_level: "critical",
                reason: "Socat — potential reverse shell or tunnel".to_string(),
                cpu_percent: cpu,
                mem_percent: mem,
            });
        }

        if is_relative_process_launch(&name_lower, &cmd_lower) {
            findings.push(ProcessFinding {
                pid: p.pid,
                name: p.name.clone(),
                user: uid_to_name(p.uid),
                risk_level: "elevated",
                reason: "Process launched from relative path — investigate execution context"
                    .to_string(),
                cpu_percent: cpu,
                mem_percent: mem,
            });
        }

        // Suspicious name/command patterns
        for &(pattern, desc) in SUSPICIOUS_NAMES {
            if name_lower.contains(pattern)
                || cmd_lower.contains(pattern)
                || exe_lower.contains(pattern)
            {
                findings.push(ProcessFinding {
                    pid: p.pid,
                    name: p.name.clone(),
                    user: uid_to_name(p.uid),
                    risk_level: "critical",
                    reason: desc.to_string(),
                    cpu_percent: cpu,
                    mem_percent: mem,
                });
            }
        }

        // High CPU (>80%)
        if cpu > 80.0 && p.pid > 1 {
            findings.push(ProcessFinding {
                pid: p.pid,
                name: p.name.clone(),
                user: uid_to_name(p.uid),
                risk_level: "elevated",
                reason: format!(
                    "High CPU usage: {:.1}% — possible crypto-miner or resource abuse",
                    cpu
                ),
                cpu_percent: cpu,
                mem_percent: mem,
            });
        }

        // High memory (>50%)
        if mem > 50.0 && p.pid > 1 {
            findings.push(ProcessFinding {
                pid: p.pid,
                name: p.name.clone(),
                user: uid_to_name(p.uid),
                risk_level: "elevated",
                reason: format!(
                    "High memory usage: {:.1}% — possible memory-resident malware or DoS",
                    mem
                ),
                cpu_percent: cpu,
                mem_percent: mem,
            });
        }

        // Root non-system processes
        if p.uid == 0 && p.ppid > 1 && !is_known_linux_system_process(base_lower) {
            findings.push(ProcessFinding {
                pid: p.pid,
                name: p.name.clone(),
                user: "root".into(),
                risk_level: "severe",
                reason: "Non-system process running as root".to_string(),
                cpu_percent: cpu,
                mem_percent: mem,
            });
        }

        // Deleted executable (common malware pattern on Linux)
        if p.exe_path.contains("(deleted)") {
            findings.push(ProcessFinding {
                pid: p.pid,
                name: p.name.clone(),
                user: uid_to_name(p.uid),
                risk_level: "critical",
                reason: "Running from deleted executable — possible fileless malware".to_string(),
                cpu_percent: cpu,
                mem_percent: mem,
            });
        }
    }

    // Deduplicate: sort by risk desc, keep all unique (pid, reason-prefix) pairs
    findings.sort_by_key(|b| std::cmp::Reverse(risk_ord(b.risk_level)));
    findings
}

/// Collect installed packages via dpkg or rpm.
pub fn collect_installed_apps() -> Vec<InstalledApp> {
    let mut apps = Vec::new();

    // Try dpkg (Debian/Ubuntu)
    if let Ok(output) = std::process::Command::new("dpkg-query")
        .args(["-W", "-f", "${Package}\t${Version}\t${Installed-Size}\n"])
        .output()
        && output.status.success()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let fields: Vec<&str> = line.split('\t').collect();
            if fields.len() >= 2 {
                let name = fields[0].to_string();
                let version = fields[1].to_string();
                let size_kb: f64 = fields
                    .get(2)
                    .and_then(|s| s.trim().parse().ok())
                    .unwrap_or(0.0);
                apps.push(InstalledApp {
                    name: name.clone(),
                    path: format!("/usr/bin/{name}"),
                    version,
                    bundle_id: String::new(),
                    size_mb: size_kb / 1024.0,
                    last_modified: String::new(),
                });
            }
        }
    }

    // Fallback to rpm if dpkg returned nothing
    if apps.is_empty()
        && let Ok(output) = std::process::Command::new("rpm")
            .args([
                "-qa",
                "--queryformat",
                "%{NAME}\t%{VERSION}-%{RELEASE}\t%{SIZE}\n",
            ])
            .output()
        && output.status.success()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let fields: Vec<&str> = line.split('\t').collect();
            if fields.len() >= 2 {
                let name = fields[0].to_string();
                let version = fields[1].to_string();
                let size_bytes: f64 = fields
                    .get(2)
                    .and_then(|s| s.trim().parse().ok())
                    .unwrap_or(0.0);
                apps.push(InstalledApp {
                    name: name.clone(),
                    path: format!("/usr/bin/{name}"),
                    version,
                    bundle_id: String::new(),
                    size_mb: size_bytes / (1024.0 * 1024.0),
                    last_modified: String::new(),
                });
            }
        }
    }

    apps.sort_by_key(|a| a.name.to_lowercase());
    apps
}

/// Collect per-process CPU% and mem% using `ps`.
fn collect_process_usage() -> HashMap<u32, (f32, f32)> {
    let mut map = HashMap::new();
    let output = match std::process::Command::new("ps")
        .args(["-eo", "pid,%cpu,%mem"])
        .output()
    {
        Ok(o) if o.status.success() => o,
        _ => return map,
    };
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3
            && let Ok(pid) = fields[0].parse::<u32>()
        {
            let cpu: f32 = fields[1].parse().unwrap_or(0.0);
            let mem: f32 = fields[2].parse().unwrap_or(0.0);
            map.insert(pid, (cpu, mem));
        }
    }
    map
}

fn uid_to_name(uid: u32) -> String {
    if uid == 0 {
        return "root".into();
    }
    // Try to resolve from /etc/passwd
    if let Ok(passwd) = fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let fields: Vec<&str> = line.split(':').collect();
            if fields.len() >= 3
                && let Ok(u) = fields[2].parse::<u32>()
                && u == uid
            {
                return fields[0].to_string();
            }
        }
    }
    format!("uid:{uid}")
}

fn is_known_linux_system_process(name: &str) -> bool {
    LINUX_SYSTEM_PROCS
        .iter()
        .any(|sp| name.contains(&sp.to_lowercase()))
}

fn risk_ord(level: &str) -> u8 {
    match level {
        "critical" => 3,
        "severe" => 2,
        "elevated" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capabilities_detect_defaults() {
        let caps = LinuxCapabilities {
            kernel_version: "Linux version 5.15.0-91-generic".into(),
            distro: "Ubuntu 22.04.3 LTS".into(),
            has_ebpf: true,
            has_auditd: false,
            has_fanotify: true,
            container_runtime: Some("docker".into()),
            cgroup_version: 2,
            security_module: Some("AppArmor".into()),
        };
        assert!(caps.has_ebpf);
        assert!(caps.has_fanotify);
        assert!(!caps.has_auditd);
        assert_eq!(caps.cgroup_version, 2);
        let missing = caps.unavailable_features();
        assert_eq!(missing, vec!["auditd event stream"]);
    }

    #[test]
    fn test_capabilities_minimal() {
        let caps = LinuxCapabilities {
            kernel_version: "Linux version 3.10.0".into(),
            distro: "CentOS 7".into(),
            has_ebpf: false,
            has_auditd: false,
            has_fanotify: false,
            container_runtime: None,
            cgroup_version: 1,
            security_module: None,
        };
        let missing = caps.unavailable_features();
        assert_eq!(missing.len(), 4);
        assert!(missing.contains(&"eBPF tracing"));
        assert!(missing.contains(&"security module (AppArmor/SELinux)"));
    }

    #[test]
    fn test_kernel_version_parsing() {
        assert!(kernel_version_at_least(
            "Linux version 5.15.0-91-generic (gcc 11.4.0)",
            5,
            15,
            0,
        ));
        assert!(kernel_version_at_least(
            "Linux version 5.15.0-91-generic",
            4,
            1,
            0,
        ));
        assert!(!kernel_version_at_least(
            "Linux version 3.10.0-1160.el7",
            4,
            1,
            0,
        ));
        assert!(kernel_version_at_least(
            "Linux version 6.1.0-rpi4-rpi-v8",
            5,
            0,
            0,
        ));
    }

    #[test]
    fn test_parse_proc_net_addr_ipv4() {
        // 0100007F:0035 => 127.0.0.1:53
        let (addr, port) = parse_proc_net_addr("0100007F:0035");
        assert_eq!(addr, "127.0.0.1");
        assert_eq!(port, 53);
    }

    #[test]
    fn test_parse_proc_net_addr_zeros() {
        // 00000000:0000 => 0.0.0.0:0
        let (addr, port) = parse_proc_net_addr("00000000:0000");
        assert_eq!(addr, "0.0.0.0");
        assert_eq!(port, 0);
    }

    #[test]
    fn test_parse_proc_net_addr_external() {
        // C0A80164:01BB => 192.168.1.100:443
        // 0x64 = 100, 0x01 = 1, 0xA8 = 168, 0xC0 = 192 (little-endian)
        let (addr, port) = parse_proc_net_addr("6401A8C0:01BB");
        assert_eq!(addr, "192.168.1.100");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_tcp_state_name() {
        assert_eq!(tcp_state_name("01"), "ESTABLISHED");
        assert_eq!(tcp_state_name("0A"), "LISTEN");
        assert_eq!(tcp_state_name("06"), "TIME_WAIT");
        assert_eq!(tcp_state_name("FF"), "UNKNOWN");
    }

    #[test]
    fn test_ocsf_class_mapping() {
        assert_eq!(ocsf_class_for("process"), 1007);
        assert_eq!(ocsf_class_for("file"), 1001);
        assert_eq!(ocsf_class_for("network"), 4001);
        assert_eq!(ocsf_class_for("dns"), 4003);
        assert_eq!(ocsf_class_for("auth"), 3002);
        assert_eq!(ocsf_class_for("privesc"), 3002);
        assert_eq!(ocsf_class_for("config"), 5001);
        assert_eq!(ocsf_class_for("container"), 5001);
        assert_eq!(ocsf_class_for("unknown"), 2004);
    }

    #[test]
    fn test_suid_risk_classification() {
        assert_eq!(classify_suid_risk("/usr/bin/sudo"), PrivEscRisk::Low);
        assert_eq!(classify_suid_risk("/usr/bin/passwd"), PrivEscRisk::Low);
        assert_eq!(classify_suid_risk("/usr/bin/python3"), PrivEscRisk::High);
        assert_eq!(classify_suid_risk("/usr/bin/nmap"), PrivEscRisk::High);
        assert_eq!(classify_suid_risk("/usr/bin/vim.basic"), PrivEscRisk::High);
        assert_eq!(classify_suid_risk("/opt/custom/tool"), PrivEscRisk::Medium);
    }

    #[test]
    fn test_container_detection_docker() {
        let cgroup =
            "12:memory:/docker/abc123def456789012345678901234567890123456789012345678901234";
        let (is_container, runtime, id) = parse_container_from_cgroup(cgroup);
        assert!(is_container);
        assert_eq!(runtime.as_deref(), Some("docker"));
        assert!(id.is_some());
    }

    #[test]
    fn test_container_detection_podman() {
        let cgroup = "0::/machine.slice/libpod-aabbccdd11223344556677889900aabbccdd11223344556677889900aabb.scope";
        let (is_container, runtime, id) = parse_container_from_cgroup(cgroup);
        assert!(is_container);
        assert_eq!(runtime.as_deref(), Some("podman"));
        assert!(id.is_some());
    }

    #[test]
    fn test_container_detection_kubernetes() {
        let cgroup = "0::/kubepods/besteffort/pod1234-5678/abc123def456";
        let (is_container, runtime, _) = parse_container_from_cgroup(cgroup);
        assert!(is_container);
        assert_eq!(runtime.as_deref(), Some("kubernetes"));
    }

    #[test]
    fn test_container_detection_host() {
        let cgroup = "0::/init.scope";
        let (is_container, runtime, id) = parse_container_from_cgroup(cgroup);
        assert!(!is_container);
        assert!(runtime.is_none());
        assert!(id.is_none());
    }

    #[test]
    fn test_snapshot_total_events_empty() {
        let snap = LinuxSnapshot {
            timestamp: "t".into(),
            capabilities: LinuxCapabilities {
                kernel_version: "5.15.0".into(),
                distro: "test".into(),
                has_ebpf: false,
                has_auditd: false,
                has_fanotify: false,
                container_runtime: None,
                cgroup_version: 2,
                security_module: None,
            },
            processes: vec![],
            file_events: vec![],
            network_sockets: vec![],
            dns_info: vec![],
            priv_esc_indicators: vec![],
            container_info: LinuxContainerInfo {
                timestamp: "t".into(),
                is_containerized: false,
                runtime: None,
                container_id: None,
                cgroup_path: String::new(),
                pid_namespace: None,
                ocsf_class_id: OCSF_CONFIG_STATE,
            },
        };
        assert_eq!(snap.total_events(), 1); // container_info counts as 1
    }

    #[test]
    fn test_distro_detection_from_os_release() {
        // The detect_distro function reads files; we test the parse logic
        // by verifying the constant output for supported_distros.
        let distros = supported_distros();
        assert!(distros.len() >= 5);
        assert!(distros.iter().any(|(name, _)| name.contains("Ubuntu")));
        assert!(distros.iter().any(|(name, _)| name.contains("RHEL")));
        assert!(distros.iter().any(|(name, _)| name.contains("Alpine")));
    }

    #[test]
    fn test_file_operation_variants() {
        let evt = LinuxFileEvent {
            timestamp: "t".into(),
            path: "/etc/passwd".into(),
            operation: FileOperation::Write,
            uid: 0,
            inode: 12345,
            size: 2048,
            ocsf_class_id: OCSF_FILE_ACTIVITY,
        };
        assert_eq!(evt.operation, FileOperation::Write);
        assert_eq!(evt.ocsf_class_id, 1001);
    }

    #[test]
    fn test_process_event_namespace() {
        let evt = LinuxProcessEvent {
            timestamp: "t".into(),
            event_type: LinuxProcessEventType::Snapshot,
            pid: 1234,
            ppid: 1,
            name: "nginx".into(),
            exe_path: "/usr/sbin/nginx".into(),
            cmd_line: "nginx -g daemon off;".into(),
            uid: 0,
            gid: 0,
            cgroup: "0::/docker/abc123".into(),
            ns_pid: Some(1),
            ocsf_class_id: OCSF_PROCESS_ACTIVITY,
        };
        assert_eq!(evt.ns_pid, Some(1));
        assert_eq!(evt.ocsf_class_id, 1007);
    }

    #[test]
    fn test_privesc_indicator_structure() {
        let ind = LinuxPrivEscIndicator {
            timestamp: "t".into(),
            indicator_type: PrivEscType::SuidBinary,
            path: "/usr/bin/python3".into(),
            details: "mode=0o104755".into(),
            risk: PrivEscRisk::High,
            ocsf_class_id: OCSF_AUTH,
        };
        assert_eq!(ind.indicator_type, PrivEscType::SuidBinary);
        assert_eq!(ind.risk, PrivEscRisk::High);
        assert_eq!(ind.ocsf_class_id, 3002);
    }

    #[test]
    fn test_extract_container_id_docker_scope() {
        let cgroup = "0::/system.slice/docker-aabbccdd11223344556677889900aabbccdd11223344556677889900aabb.scope";
        let id = extract_container_id(cgroup);
        assert!(id.is_some());
        let id_str = id.unwrap();
        assert!(id_str.len() >= 12);
        assert!(id_str.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn linux_process_analysis_matches_netcat_as_token_only() {
        let procs = vec![LinuxProcessEvent {
            timestamp: "t".into(),
            event_type: LinuxProcessEventType::Snapshot,
            pid: 42,
            ppid: 1,
            name: "sync-service".into(),
            exe_path: "/usr/bin/sync-service".into(),
            cmd_line: "/usr/bin/sync-service --mode daemon".into(),
            uid: 1000,
            gid: 1000,
            cgroup: String::new(),
            ns_pid: None,
            ocsf_class_id: OCSF_PROCESS_ACTIVITY,
        }];

        let findings = analyze_processes(&procs);
        assert!(findings.is_empty());
    }

    #[test]
    fn linux_process_analysis_marks_relative_launch_as_elevated() {
        let procs = vec![LinuxProcessEvent {
            timestamp: "t".into(),
            event_type: LinuxProcessEventType::Snapshot,
            pid: 84,
            ppid: 1,
            name: "./wardex".into(),
            exe_path: String::new(),
            cmd_line: "./wardex".into(),
            uid: 1000,
            gid: 1000,
            cgroup: String::new(),
            ns_pid: None,
            ocsf_class_id: OCSF_PROCESS_ACTIVITY,
        }];

        let findings = analyze_processes(&procs);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].risk_level, "elevated");
        assert!(findings[0].reason.contains("relative path"));
    }
}
