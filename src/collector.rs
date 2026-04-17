//! Cross-platform host telemetry collector for live XDR monitoring.
//!
//! Provides real-time system metrics collection on Linux, macOS, and Windows,
//! file integrity monitoring via SHA-256 baselines, and a streaming monitor loop
//! that feeds samples into the anomaly detection pipeline.

use crate::config::{Config, MonitorScopeSettings};
use crate::detector::AnomalyDetector;
use crate::policy::{PolicyEngine, ThreatLevel};
use crate::telemetry::TelemetrySample;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ── Platform Detection ───────────────────────────────────────────────

/// Detected host platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostPlatform {
    Linux,
    MacOS,
    Windows,
    WindowsServer,
    Unknown,
}

impl fmt::Display for HostPlatform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Linux => write!(f, "Linux"),
            Self::MacOS => write!(f, "macOS"),
            Self::Windows => write!(f, "Windows"),
            Self::WindowsServer => write!(f, "Windows Server"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Basic host information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub platform: HostPlatform,
    pub hostname: String,
    pub os_version: String,
    pub arch: String,
}

/// Detect the current host platform at runtime.
pub fn detect_platform() -> HostInfo {
    let platform = detect_platform_kind();
    let hostname = get_hostname();
    let os_version = get_os_version();
    let arch = std::env::consts::ARCH.to_string();

    HostInfo {
        platform,
        hostname,
        os_version,
        arch,
    }
}

#[cfg(target_os = "linux")]
fn detect_platform_kind() -> HostPlatform {
    HostPlatform::Linux
}

#[cfg(target_os = "macos")]
fn detect_platform_kind() -> HostPlatform {
    HostPlatform::MacOS
}

#[cfg(target_os = "windows")]
fn detect_platform_kind() -> HostPlatform {
    // Detect Windows Server via `wmic os get caption`
    if let Ok(output) = std::process::Command::new("wmic")
        .args(["os", "get", "caption"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        if text.contains("Server") {
            return HostPlatform::WindowsServer;
        }
    }
    HostPlatform::Windows
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn detect_platform_kind() -> HostPlatform {
    HostPlatform::Unknown
}

fn get_hostname() -> String {
    #[cfg(unix)]
    {
        fs::read_to_string("/etc/hostname")
            .map(|s| s.trim().to_string())
            .or_else(|_| {
                std::process::Command::new("hostname")
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            })
            .unwrap_or_else(|_| "unknown".into())
    }
    #[cfg(windows)]
    {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".into())
    }
    #[cfg(not(any(unix, windows)))]
    {
        "unknown".into()
    }
}

fn get_os_version() -> String {
    #[cfg(target_os = "linux")]
    {
        fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|content| {
                content
                    .lines()
                    .find(|l| l.starts_with("PRETTY_NAME="))
                    .map(|l| {
                        l.trim_start_matches("PRETTY_NAME=")
                            .trim_matches('"')
                            .to_string()
                    })
            })
            .unwrap_or_else(|| "Linux".into())
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("sw_vers")
            .arg("-productVersion")
            .output()
            .map(|o| format!("macOS {}", String::from_utf8_lossy(&o.stdout).trim()))
            .unwrap_or_else(|_| "macOS".into())
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/c", "ver"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "Windows".into())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        "Unknown OS".into()
    }
}

// ── Metrics Collection ───────────────────────────────────────────────

/// Mutable state for delta-based metrics (CPU ticks, network bytes).
#[derive(Default)]
pub struct CollectorState {
    #[allow(dead_code)] // used on Linux only
    prev_cpu_idle: u64,
    #[allow(dead_code)] // used on Linux only
    prev_cpu_total: u64,
    prev_net_bytes: u64,
    prev_net_time: Option<Instant>,
}

/// Collect a single telemetry sample from the host OS.
pub fn collect_sample(
    state: &mut CollectorState,
    fim: Option<&FileIntegrityMonitor>,
) -> TelemetrySample {
    collect_sample_scoped(state, fim, None, &MonitorScopeSettings::default())
}

/// Collect a single telemetry sample while honoring monitoring scope toggles.
pub fn collect_sample_scoped(
    state: &mut CollectorState,
    fim: Option<&FileIntegrityMonitor>,
    persistence: Option<&FileIntegrityMonitor>,
    scope: &MonitorScopeSettings,
) -> TelemetrySample {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let file_integrity_drift = if scope.file_integrity {
        fim.map_or(0.0, |f| f.check())
    } else {
        0.0
    };
    let persistence_drift = if scope.service_persistence {
        persistence.map_or(0.0, |p| p.check())
    } else {
        0.0
    };

    TelemetrySample {
        timestamp_ms,
        cpu_load_pct: if scope.cpu_load {
            collect_cpu(state)
        } else {
            0.0
        },
        memory_load_pct: if scope.memory_pressure {
            collect_memory()
        } else {
            0.0
        },
        temperature_c: if scope.thermal_state {
            collect_temperature()
        } else {
            0.0
        },
        network_kbps: if scope.network_activity {
            collect_network(state)
        } else {
            0.0
        },
        auth_failures: if scope.auth_events {
            collect_auth_failures()
        } else {
            0
        },
        battery_pct: if scope.battery_state {
            collect_battery()
        } else {
            100.0
        },
        integrity_drift: file_integrity_drift.max(persistence_drift),
        process_count: if scope.process_activity {
            collect_process_count()
        } else {
            0
        },
        disk_pressure_pct: if scope.disk_pressure {
            collect_disk_pressure()
        } else {
            0.0
        },
    }
}

pub fn persistence_watch_paths(
    platform: HostPlatform,
    scope: &MonitorScopeSettings,
) -> Vec<String> {
    if !scope.service_persistence {
        return Vec::new();
    }

    let specific_selected = scope.launch_agents || scope.systemd_units || scope.scheduled_tasks;
    let mut paths = Vec::new();

    match platform {
        HostPlatform::Linux => {
            if scope.systemd_units || !specific_selected {
                paths.extend([
                    "/etc/systemd/system".to_string(),
                    "/run/systemd/system".to_string(),
                    "/usr/lib/systemd/system".to_string(),
                    "/lib/systemd/system".to_string(),
                ]);
            }
        }
        HostPlatform::MacOS => {
            if scope.launch_agents || !specific_selected {
                paths.extend([
                    "/Library/LaunchAgents".to_string(),
                    "/Library/LaunchDaemons".to_string(),
                ]);
                if let Ok(home) = std::env::var("HOME") {
                    paths.push(format!("{home}/Library/LaunchAgents"));
                }
            }
        }
        HostPlatform::Windows | HostPlatform::WindowsServer => {
            if scope.scheduled_tasks || !specific_selected {
                paths.push(r"C:\Windows\System32\Tasks".to_string());
            }
        }
        HostPlatform::Unknown => {}
    }

    paths
}

// ── CPU ──────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn collect_cpu(state: &mut CollectorState) -> f32 {
    // Read /proc/stat — first line: cpu user nice system idle ...
    let Ok(content) = fs::read_to_string("/proc/stat") else {
        return 0.0;
    };
    let Some(first) = content.lines().next() else {
        return 0.0;
    };
    let vals: Vec<u64> = first
        .split_whitespace()
        .skip(1) // skip "cpu"
        .filter_map(|v| v.parse().ok())
        .collect();
    if vals.len() < 4 {
        return 0.0;
    }
    let idle = vals[3];
    let total: u64 = vals.iter().sum();

    if state.prev_cpu_total == 0 {
        state.prev_cpu_idle = idle;
        state.prev_cpu_total = total;
        return 0.0;
    }

    let d_total = total.saturating_sub(state.prev_cpu_total);
    let d_idle = idle.saturating_sub(state.prev_cpu_idle);
    state.prev_cpu_idle = idle;
    state.prev_cpu_total = total;

    if d_total == 0 {
        return 0.0;
    }
    let usage = 100.0 * (1.0 - d_idle as f32 / d_total as f32);
    usage.clamp(0.0, 100.0)
}

#[cfg(target_os = "macos")]
fn collect_cpu(_state: &mut CollectorState) -> f32 {
    // Use `sysctl -n vm.loadavg` and scale load average to percentage
    // Alternatively use `top -l 1 -n 0` but that's slower
    let Ok(output) = std::process::Command::new("sysctl")
        .args(["-n", "hw.ncpu"])
        .output()
    else {
        return 0.0;
    };
    let ncpu: f32 = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .unwrap_or(1.0);

    let Ok(load_output) = std::process::Command::new("sysctl")
        .args(["-n", "vm.loadavg"])
        .output()
    else {
        return 0.0;
    };
    let load_str = String::from_utf8_lossy(&load_output.stdout);
    // Format: "{ 1.23 4.56 7.89 }" — parse first number (1-minute load average)
    let load1: f32 = load_str
        .trim()
        .trim_start_matches('{')
        .split_whitespace()
        .next()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0);

    let pct = (load1 / ncpu) * 100.0;
    pct.clamp(0.0, 100.0)
}

#[cfg(target_os = "windows")]
fn collect_cpu(_state: &mut CollectorState) -> f32 {
    let Ok(output) = std::process::Command::new("wmic")
        .args(["cpu", "get", "loadpercentage"])
        .output()
    else {
        return 0.0;
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|l| l.trim().parse::<f32>().ok())
        .next()
        .unwrap_or(0.0)
        .clamp(0.0, 100.0)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn collect_cpu(_state: &mut CollectorState) -> f32 {
    0.0
}

// ── Memory ───────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn collect_memory() -> f32 {
    let Ok(content) = fs::read_to_string("/proc/meminfo") else {
        return 0.0;
    };
    let mut total: u64 = 0;
    let mut available: u64 = 0;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            total = rest
                .split_whitespace()
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            available = rest
                .split_whitespace()
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
        }
    }
    if total == 0 {
        return 0.0;
    }
    let used_pct = 100.0 * (1.0 - available as f32 / total as f32);
    used_pct.clamp(0.0, 100.0)
}

#[cfg(target_os = "macos")]
fn collect_memory() -> f32 {
    // Use vm_stat to get page counts, sysctl for page size and total memory
    let page_size: u64 = std::process::Command::new("sysctl")
        .args(["-n", "hw.pagesize"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok())
        .unwrap_or(4096);

    let total_mem: u64 = std::process::Command::new("sysctl")
        .args(["-n", "hw.memsize"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok())
        .unwrap_or(0);

    let Ok(output) = std::process::Command::new("vm_stat").output() else {
        return 0.0;
    };
    let text = String::from_utf8_lossy(&output.stdout);

    let parse_pages = |prefix: &str| -> u64 {
        text.lines()
            .find(|l| l.starts_with(prefix))
            .and_then(|l| l.split(':').nth(1))
            .and_then(|v| v.trim().trim_end_matches('.').parse().ok())
            .unwrap_or(0)
    };

    let free = parse_pages("Pages free");
    let inactive = parse_pages("Pages inactive");
    let available_bytes = (free + inactive) * page_size;

    if total_mem == 0 {
        return 0.0;
    }
    let used_pct = 100.0 * (1.0 - available_bytes as f32 / total_mem as f32);
    used_pct.clamp(0.0, 100.0)
}

#[cfg(target_os = "windows")]
fn collect_memory() -> f32 {
    let Ok(output) = std::process::Command::new("wmic")
        .args([
            "OS",
            "get",
            "FreePhysicalMemory,TotalVisibleMemorySize",
            "/value",
        ])
        .output()
    else {
        return 0.0;
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut free: u64 = 0;
    let mut total: u64 = 0;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("FreePhysicalMemory=") {
            free = rest.trim().parse().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("TotalVisibleMemorySize=") {
            total = rest.trim().parse().unwrap_or(0);
        }
    }
    if total == 0 {
        return 0.0;
    }
    let used_pct = 100.0 * (1.0 - free as f32 / total as f32);
    used_pct.clamp(0.0, 100.0)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn collect_memory() -> f32 {
    0.0
}

// ── Temperature ──────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn collect_temperature() -> f32 {
    // Try thermal zone 0 first
    fs::read_to_string("/sys/class/thermal/thermal_zone0/temp")
        .ok()
        .and_then(|s| s.trim().parse::<f32>().ok())
        .map(|millideg| millideg / 1000.0)
        .unwrap_or(0.0)
}

#[cfg(target_os = "macos")]
fn collect_temperature() -> f32 {
    // Try powermetrics first (requires root but gives accurate CPU die temp)
    if let Ok(output) = std::process::Command::new("sudo")
        .args([
            "-n",
            "powermetrics",
            "--samplers",
            "smc",
            "-i",
            "1",
            "-n",
            "1",
        ])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if (line.contains("CPU die temperature") || line.contains("die temp"))
                && let Some(temp) = line
                    .split_whitespace()
                    .find_map(|w| w.trim_end_matches(" C").parse::<f32>().ok())
                && temp > 0.0
                && temp < 150.0
            {
                return temp;
            }
        }
    }
    // Fallback: sysctl thermal level (0-127 scale, approximate to celsius)
    if let Ok(output) = std::process::Command::new("sysctl")
        .args(["-n", "machdep.xcpm.cpu_thermal_level"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        if let Ok(level) = text.trim().parse::<f32>() {
            // Thermal level 0-127 maps roughly to 30-100°C range
            if level >= 0.0 {
                return 30.0 + (level / 127.0) * 70.0;
            }
        }
    }
    0.0
}

#[cfg(target_os = "windows")]
fn collect_temperature() -> f32 {
    // WMI thermal zone — requires admin, may not be available
    let Ok(output) = std::process::Command::new("wmic")
        .args([
            "/namespace:\\\\root\\wmi",
            "PATH",
            "MSAcpi_ThermalZoneTemperature",
            "get",
            "CurrentTemperature",
        ])
        .output()
    else {
        return 0.0;
    };
    // Value is in tenths of Kelvin
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|l| l.trim().parse::<f32>().ok())
        .next()
        .map(|tenths_k| tenths_k / 10.0 - 273.15)
        .unwrap_or(0.0)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn collect_temperature() -> f32 {
    0.0
}

// ── Network ──────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn collect_network(state: &mut CollectorState) -> f32 {
    let Ok(content) = fs::read_to_string("/proc/net/dev") else {
        return 0.0;
    };
    // Sum all interface bytes (skip lo)
    let mut total_bytes: u64 = 0;
    for line in content.lines().skip(2) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }
        let iface = parts[0].trim_end_matches(':');
        if iface == "lo" {
            continue;
        }
        let rx: u64 = parts[1].parse().unwrap_or(0);
        let tx: u64 = parts[9].parse().unwrap_or(0);
        total_bytes += rx + tx;
    }
    compute_network_kbps(state, total_bytes)
}

#[cfg(target_os = "macos")]
fn collect_network(state: &mut CollectorState) -> f32 {
    let Ok(output) = std::process::Command::new("netstat").args(["-ib"]).output() else {
        return 0.0;
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut total_bytes: u64 = 0;
    for line in text.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }
        let iface = parts[0];
        if iface.starts_with("lo") {
            continue;
        }
        // Only count <Link#N> rows — netstat -ib lists each interface
        // multiple times (once per address: Link, IPv4, IPv6, etc.)
        // with identical cumulative byte counters. Counting all rows
        // inflates the total by the number of addresses per interface.
        if !parts[2].starts_with("<Link") {
            continue;
        }
        // Columns: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
        if let (Some(ibytes), Some(obytes)) = (
            parts.get(6).and_then(|v| v.parse::<u64>().ok()),
            parts.get(9).and_then(|v| v.parse::<u64>().ok()),
        ) {
            total_bytes += ibytes + obytes;
        }
    }
    compute_network_kbps(state, total_bytes)
}

#[cfg(target_os = "windows")]
fn collect_network(state: &mut CollectorState) -> f32 {
    let Ok(output) = std::process::Command::new("netstat").args(["-e"]).output() else {
        return 0.0;
    };
    let text = String::from_utf8_lossy(&output.stdout);
    // Parse "Bytes" line: Bytes    <received>    <sent>
    let mut total_bytes: u64 = 0;
    for line in text.lines() {
        let lower = line.to_lowercase();
        if lower.contains("bytes") && !lower.contains("unicast") && !lower.contains("non-unicast") {
            let nums: Vec<u64> = line
                .split_whitespace()
                .filter_map(|v| v.parse().ok())
                .collect();
            if nums.len() >= 2 {
                total_bytes = nums[0] + nums[1];
            }
            break;
        }
    }
    compute_network_kbps(state, total_bytes)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn collect_network(_state: &mut CollectorState) -> f32 {
    0.0
}

fn compute_network_kbps(state: &mut CollectorState, total_bytes: u64) -> f32 {
    let now = Instant::now();
    let kbps = if let Some(prev_time) = state.prev_net_time {
        let elapsed = now.duration_since(prev_time).as_secs_f32();
        if elapsed > 0.0 && state.prev_net_bytes > 0 {
            let delta = total_bytes.saturating_sub(state.prev_net_bytes) as f32;
            (delta / 125.0) / elapsed // kbps (1 kbit = 1000 bits = 125 bytes)
        } else {
            0.0
        }
    } else {
        0.0
    };
    state.prev_net_bytes = total_bytes;
    state.prev_net_time = Some(now);
    kbps.max(0.0)
}

// ── Auth Failures ────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn collect_auth_failures() -> u32 {
    // Count recent authentication failures from /var/log/auth.log
    let path = if Path::new("/var/log/auth.log").exists() {
        "/var/log/auth.log"
    } else if Path::new("/var/log/secure").exists() {
        "/var/log/secure"
    } else {
        return 0;
    };

    let Ok(content) = fs::read_to_string(path) else {
        return 0;
    };
    // Count "authentication failure" occurrences in last 100 lines
    content
        .lines()
        .rev()
        .take(100)
        .filter(|l| {
            let lower = l.to_lowercase();
            lower.contains("authentication failure") || lower.contains("failed password")
        })
        .count() as u32
}

#[cfg(target_os = "macos")]
fn collect_auth_failures() -> u32 {
    // Check system log for auth failures via `log show`
    let Ok(output) = std::process::Command::new("log")
        .args([
            "show",
            "--predicate",
            "eventMessage CONTAINS 'authentication' AND eventMessage CONTAINS 'failure'",
            "--last",
            "5m",
            "--style",
            "compact",
        ])
        .output()
    else {
        return 0;
    };
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .filter(|l| !l.is_empty() && !l.starts_with("Filtering"))
        .count() as u32
}

#[cfg(target_os = "windows")]
fn collect_auth_failures() -> u32 {
    // Query Windows Security event log for Audit Failure events (Event ID 4625)
    let Ok(output) = std::process::Command::new("wevtutil")
        .args([
            "qe",
            "Security",
            "/q:*[System[(EventID=4625)]]",
            "/c:100",
            "/f:text",
        ])
        .output()
    else {
        return 0;
    };
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines().filter(|l| l.contains("Event[")).count() as u32
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn collect_auth_failures() -> u32 {
    0
}

// ── Battery ──────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn collect_battery() -> f32 {
    fs::read_to_string("/sys/class/power_supply/BAT0/capacity")
        .ok()
        .and_then(|s| s.trim().parse::<f32>().ok())
        .unwrap_or(100.0)
        .clamp(0.0, 100.0)
}

#[cfg(target_os = "macos")]
fn collect_battery() -> f32 {
    let Ok(output) = std::process::Command::new("pmset")
        .args(["-g", "batt"])
        .output()
    else {
        return 100.0;
    };
    let text = String::from_utf8_lossy(&output.stdout);
    // Parse "XX%" from the output
    text.lines()
        .find_map(|l| {
            l.split_whitespace()
                .find(|w| w.ends_with("%;") || w.ends_with('%'))
                .and_then(|w| {
                    w.trim_end_matches("%;")
                        .trim_end_matches('%')
                        .parse::<f32>()
                        .ok()
                })
        })
        .unwrap_or(100.0)
        .clamp(0.0, 100.0)
}

#[cfg(target_os = "windows")]
fn collect_battery() -> f32 {
    let Ok(output) = std::process::Command::new("wmic")
        .args(["path", "Win32_Battery", "get", "EstimatedChargeRemaining"])
        .output()
    else {
        return 100.0;
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|l| l.trim().parse::<f32>().ok())
        .next()
        .unwrap_or(100.0)
        .clamp(0.0, 100.0)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn collect_battery() -> f32 {
    100.0
}

// ── Process Count ────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn collect_process_count() -> u32 {
    fs::read_dir("/proc")
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.file_name()
                        .to_str()
                        .is_some_and(|s| s.chars().all(|c| c.is_ascii_digit()))
                })
                .count() as u32
        })
        .unwrap_or(0)
}

#[cfg(target_os = "macos")]
fn collect_process_count() -> u32 {
    std::process::Command::new("ps")
        .args(["-ax"])
        .output()
        .map(|o| {
            let text = String::from_utf8_lossy(&o.stdout);
            text.lines().count().saturating_sub(1) as u32 // subtract header
        })
        .unwrap_or(0)
}

#[cfg(target_os = "windows")]
fn collect_process_count() -> u32 {
    std::process::Command::new("wmic")
        .args(["process", "list", "brief"])
        .output()
        .map(|o| {
            let text = String::from_utf8_lossy(&o.stdout);
            text.lines()
                .filter(|l| !l.trim().is_empty())
                .count()
                .saturating_sub(1) as u32
        })
        .unwrap_or(0)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn collect_process_count() -> u32 {
    0
}

// ── Disk Pressure ────────────────────────────────────────────────────

#[cfg(unix)]
fn collect_disk_pressure() -> f32 {
    // Use df command as a portable approach for Unix
    let Ok(output) = std::process::Command::new("df").args(["-k", "/"]).output() else {
        return 0.0;
    };
    let text = String::from_utf8_lossy(&output.stdout);
    // Second line: filesystem 1K-blocks Used Available Use% Mounted
    text.lines()
        .nth(1)
        .and_then(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            // The "Use%" column is typically at index 4
            parts
                .iter()
                .find_map(|p| p.trim_end_matches('%').parse::<f32>().ok())
                .or_else(|| {
                    // Fallback: compute from blocks and available
                    let total: f32 = parts.get(1)?.parse().ok()?;
                    let available: f32 = parts.get(3)?.parse().ok()?;
                    if total > 0.0 {
                        Some(100.0 * (1.0 - available / total))
                    } else {
                        None
                    }
                })
        })
        .unwrap_or(0.0)
        .clamp(0.0, 100.0)
}

#[cfg(windows)]
fn collect_disk_pressure() -> f32 {
    let Ok(output) = std::process::Command::new("wmic")
        .args([
            "logicaldisk",
            "where",
            "DeviceID='C:'",
            "get",
            "Size,FreeSpace",
            "/value",
        ])
        .output()
    else {
        return 0.0;
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut free: u64 = 0;
    let mut total: u64 = 0;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("FreeSpace=") {
            free = rest.trim().parse().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("Size=") {
            total = rest.trim().parse().unwrap_or(0);
        }
    }
    if total == 0 {
        return 0.0;
    }
    let used_pct = 100.0 * (1.0 - free as f32 / total as f32);
    used_pct.clamp(0.0, 100.0)
}

#[cfg(not(any(unix, windows)))]
fn collect_disk_pressure() -> f32 {
    0.0
}

// ── File Integrity Monitor ───────────────────────────────────────────

const MAX_FIM_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10 MB

/// Monitors watched files/directories for integrity changes via SHA-256.
pub struct FileIntegrityMonitor {
    baselines: HashMap<PathBuf, String>,
}

impl FileIntegrityMonitor {
    /// Scan all watched paths and record SHA-256 baselines.
    pub fn new(watch_paths: &[String]) -> Self {
        let mut baselines = HashMap::new();
        for path_str in watch_paths {
            let path = Path::new(path_str);
            if path.is_file() {
                if let Some((p, hash)) = hash_file(path) {
                    baselines.insert(p, hash);
                }
            } else if path.is_dir() {
                collect_dir_hashes(path, &mut baselines);
            }
        }
        Self { baselines }
    }

    /// Check current hashes against baseline. Returns drift ratio 0.0–1.0.
    pub fn check(&self) -> f32 {
        if self.baselines.is_empty() {
            return 0.0;
        }
        let mut changed = 0u32;
        for (path, baseline_hash) in &self.baselines {
            match hash_file(path) {
                Some((_, current_hash)) => {
                    if current_hash != *baseline_hash {
                        changed += 1;
                    }
                }
                None => {
                    // File deleted or unreadable
                    changed += 1;
                }
            }
        }
        changed as f32 / self.baselines.len() as f32
    }

    pub fn file_count(&self) -> usize {
        self.baselines.len()
    }
}

fn hash_file(path: &Path) -> Option<(PathBuf, String)> {
    let metadata = fs::metadata(path).ok()?;
    if metadata.len() > MAX_FIM_FILE_SIZE {
        return None;
    }
    let data = fs::read(path).ok()?;
    let hash = hex::encode(Sha256::digest(&data));
    Some((path.to_path_buf(), hash))
}

fn collect_dir_hashes(dir: &Path, out: &mut HashMap<PathBuf, String>) {
    collect_dir_hashes_bounded(dir, out, 0);
}

fn collect_dir_hashes_bounded(dir: &Path, out: &mut HashMap<PathBuf, String>, depth: usize) {
    const MAX_DEPTH: usize = 32;
    if depth >= MAX_DEPTH {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        // Use symlink_metadata to avoid following symlinks into cycles
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.is_file() {
            if let Some((p, hash)) = hash_file(&path) {
                out.insert(p, hash);
            }
        } else if meta.is_dir() {
            collect_dir_hashes_bounded(&path, out, depth + 1);
        }
    }
}

// ── Alert Record ─────────────────────────────────────────────────────

/// An alert generated when the anomaly score exceeds the threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRecord {
    pub timestamp: String,
    pub hostname: String,
    pub platform: String,
    pub score: f32,
    pub confidence: f32,
    pub level: String,
    pub action: String,
    pub reasons: Vec<String>,
    pub sample: TelemetrySample,
    pub enforced: bool,
    #[serde(default)]
    pub mitre: Vec<crate::telemetry::MitreAttack>,
}

impl AlertRecord {
    /// Format as RFC 5424 syslog line.
    pub fn to_syslog(&self) -> String {
        let severity = match self.level.as_str() {
            "Critical" => 2,
            "Severe" => 3,
            "Elevated" => 4,
            _ => 6,
        };
        let pri = 8 * 10 + severity; // facility=security(10)
        format!(
            "<{pri}>1 {ts} {host} Wardex - - - score={score:.2} level={level} action={action} reasons=\"{reasons}\"",
            ts = self.timestamp,
            host = self.hostname,
            score = self.score,
            level = self.level,
            action = self.action,
            reasons = self.reasons.join("; "),
        )
    }

    /// Format as ArcSight CEF line.
    pub fn to_cef(&self) -> String {
        let severity = match self.level.as_str() {
            "Critical" => 10,
            "Severe" => 7,
            "Elevated" => 4,
            _ => 1,
        };
        format!(
            "CEF:0|Wardex|XDR|0.15.0|ANOMALY|{level}|{sev}|src={host} msg={reasons} cs1={score:.2} cs1Label=AnomalyScore cs2={action} cs2Label=ResponseAction",
            level = self.level,
            sev = severity,
            host = self.hostname,
            reasons = self.reasons.join("; "),
            score = self.score,
            action = self.action,
        )
    }
}

// ── Monitor Configuration ────────────────────────────────────────────

/// Runtime configuration for the monitor loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorConfig {
    pub interval_secs: u64,
    pub alert_threshold: f32,
    pub alert_log: String,
    pub webhook_url: Option<String>,
    pub watch_paths: Vec<String>,
    pub dry_run: bool,
    pub duration_secs: u64,
    pub syslog: bool,
    pub cef: bool,
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self {
            interval_secs: 5,
            alert_threshold: 3.5,
            alert_log: "var/alerts.jsonl".into(),
            webhook_url: None,
            watch_paths: Vec::new(),
            dry_run: false,
            duration_secs: 0,
            syslog: false,
            cef: false,
        }
    }
}

// ── Monitor Loop ─────────────────────────────────────────────────────

/// Run the live monitoring loop until interrupted or duration expires.
pub fn run_monitor(
    config: &Config,
    mon: &MonitorConfig,
    shutdown: Arc<AtomicBool>,
) -> MonitorSummary {
    let host = detect_platform();

    // Print startup banner
    log::info!("Wardex XDR Monitor");
    log::info!(
        "  Platform: {} ({} {})",
        host.platform,
        host.os_version,
        host.arch
    );
    log::info!("  Hostname: {}", host.hostname);
    log::info!("  Interval: {}s", mon.interval_secs);
    log::info!("  Threshold: {:.1}", mon.alert_threshold);
    log::info!(
        "  Webhook: {}",
        mon.webhook_url.as_deref().unwrap_or("disabled")
    );
    if mon.dry_run {
        log::info!("  Mode: DRY RUN (detection only, no enforcement)");
    }
    if !mon.watch_paths.is_empty() {
        log::info!("  Watch paths: {}", mon.watch_paths.join(", "));
    }
    log::info!("");

    // Initialize components
    let mut detector = AnomalyDetector::default();
    let policy = PolicyEngine;
    let mut collector_state = CollectorState::default();
    let fim = if !config.monitor.scope.file_integrity || mon.watch_paths.is_empty() {
        None
    } else {
        let f = FileIntegrityMonitor::new(&mon.watch_paths);
        log::info!("  File integrity: {} files baselined", f.file_count());
        log::info!("");
        Some(f)
    };
    let persistence = {
        let paths = persistence_watch_paths(host.platform, &config.monitor.scope);
        if paths.is_empty() {
            None
        } else {
            let monitor = FileIntegrityMonitor::new(&paths);
            log::info!(
                "  Persistence scope: {} files baselined",
                monitor.file_count()
            );
            Some(monitor)
        }
    };

    // Ensure alert log directory exists
    if let Some(parent) = Path::new(&mon.alert_log).parent() {
        let _ = fs::create_dir_all(parent);
    }

    let start = Instant::now();
    let mut summary = MonitorSummary::default();

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        if mon.duration_secs > 0 && start.elapsed().as_secs() >= mon.duration_secs {
            break;
        }

        // Collect and evaluate
        let sample = collect_sample_scoped(
            &mut collector_state,
            fim.as_ref(),
            persistence.as_ref(),
            &config.monitor.scope,
        );
        let signal = detector.evaluate(&sample);
        let decision = policy.evaluate(&signal, &sample);
        summary.samples += 1;

        // Format live line
        let level_str = format!("{:?}", decision.level);
        eprintln!(
            "  [{time}] cpu={cpu:.1}% mem={mem:.1}% net={net:.0}kbps procs={procs} disk={disk:.0}% score={score:.2} → {level}",
            time = chrono::Local::now().format("%H:%M:%S"),
            cpu = sample.cpu_load_pct,
            mem = sample.memory_load_pct,
            net = sample.network_kbps,
            procs = sample.process_count,
            disk = sample.disk_pressure_pct,
            score = signal.score,
            level = level_str,
        );

        // Alert if threshold exceeded
        if signal.score >= mon.alert_threshold {
            let mitre = crate::telemetry::map_alert_to_mitre(&signal.reasons);
            let alert = AlertRecord {
                timestamp: chrono::Utc::now().to_rfc3339(),
                hostname: host.hostname.clone(),
                platform: host.platform.to_string(),
                score: signal.score,
                confidence: signal.confidence,
                level: level_str.clone(),
                action: format!("{:?}", decision.action),
                reasons: signal.reasons.clone(),
                sample,
                enforced: !mon.dry_run && decision.level >= ThreatLevel::Severe,
                mitre,
            };

            summary.alerts += 1;
            if decision.level == ThreatLevel::Critical {
                summary.critical += 1;
            }

            // Append to alert log
            if let Ok(json) = serde_json::to_string(&alert)
                && let Ok(mut f) = fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&mon.alert_log)
                && let Err(e) = writeln!(f, "{json}")
            {
                eprintln!("[WARN] alert log write failed: {e}");
            }

            // Structured output
            if mon.syslog {
                println!("{}", alert.to_syslog());
            }
            if mon.cef {
                println!("{}", alert.to_cef());
            }

            // Webhook
            if let Some(ref url) = mon.webhook_url {
                send_webhook(url, &alert);
            }

            log::warn!(
                "  ** ALERT: score={:.2} level={} action={} **",
                alert.score,
                alert.level,
                alert.action,
            );
        }

        std::thread::sleep(Duration::from_secs(mon.interval_secs));
    }

    // Print summary
    let elapsed = start.elapsed();
    log::info!("");
    log::info!("Monitor stopped after {:.0}s", elapsed.as_secs_f32());
    log::info!(
        "  Samples: {} | Alerts: {} | Critical: {}",
        summary.samples,
        summary.alerts,
        summary.critical,
    );

    summary.duration_secs = elapsed.as_secs();
    summary
}

/// Summary of a monitoring session.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MonitorSummary {
    pub samples: u64,
    pub alerts: u64,
    pub critical: u64,
    pub duration_secs: u64,
}

// ── Webhook ──────────────────────────────────────────────────────────

fn send_webhook(url: &str, alert: &AlertRecord) {
    let body = match serde_json::to_string(alert) {
        Ok(b) => b,
        Err(e) => {
            log::error!("  webhook: failed to serialize alert: {e}");
            return;
        }
    };

    // Use ureq for HTTP POST
    match ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(5))
        .build()
        .post(url)
        .set("Content-Type", "application/json")
        .send_string(&body)
    {
        Ok(_) => log::info!("  webhook: alert sent to {url}"),
        Err(e) => log::error!("  webhook: failed to send to {url}: {e}"),
    }
}

// ── CLI Argument Parsing ─────────────────────────────────────────────

/// Parse monitor-related flags from CLI arguments.
pub fn parse_monitor_args(args: &mut dyn Iterator<Item = String>) -> MonitorConfig {
    let mut config = MonitorConfig::default();

    // Collect remaining args into a vec for pair-wise processing
    let remaining: Vec<String> = args.collect();
    let mut i = 0;
    while i < remaining.len() {
        match remaining[i].as_str() {
            "--interval" => {
                if let Some(v) = remaining.get(i + 1) {
                    config.interval_secs = v.parse().unwrap_or(5);
                    i += 1;
                }
            }
            "--threshold" => {
                if let Some(v) = remaining.get(i + 1) {
                    config.alert_threshold = v.parse().unwrap_or(3.5);
                    i += 1;
                }
            }
            "--alert-log" => {
                if let Some(v) = remaining.get(i + 1) {
                    config.alert_log = v.clone();
                    i += 1;
                }
            }
            "--webhook" => {
                if let Some(v) = remaining.get(i + 1) {
                    config.webhook_url = Some(v.clone());
                    i += 1;
                }
            }
            "--watch" => {
                if let Some(v) = remaining.get(i + 1) {
                    config.watch_paths = v.split(',').map(|s| s.trim().to_string()).collect();
                    i += 1;
                }
            }
            "--duration" => {
                if let Some(v) = remaining.get(i + 1) {
                    config.duration_secs = v.parse().unwrap_or(0);
                    i += 1;
                }
            }
            "--dry-run" => config.dry_run = true,
            "--syslog" => config.syslog = true,
            "--cef" => config.cef = true,
            _ => {}
        }
        i += 1;
    }

    config
}

// ── Real-Time File Watcher ────────────────────────────────────────────

use std::sync::Mutex;

/// Event from the real-time file watcher.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChangeEvent {
    pub timestamp_ms: u64,
    pub path: String,
    pub kind: FileChangeKind,
}

/// Kind of file change detected.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FileChangeKind {
    Created,
    Modified,
    Deleted,
    Renamed,
}

/// Real-time cross-platform file watcher using OS-native APIs
/// (inotify on Linux, FSEvents on macOS, ReadDirectoryChangesW on Windows).
pub struct RealtimeFileWatcher {
    events: Arc<Mutex<Vec<FileChangeEvent>>>,
    _watcher: Option<notify::RecommendedWatcher>,
}

impl fmt::Debug for RealtimeFileWatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self.events.lock().map(|e| e.len()).unwrap_or(0);
        f.debug_struct("RealtimeFileWatcher")
            .field("pending_events", &count)
            .finish()
    }
}

impl RealtimeFileWatcher {
    /// Start watching the given paths for file changes.
    pub fn new(watch_paths: &[String]) -> Self {
        use notify::{Event, EventKind, RecursiveMode, Watcher};

        let events: Arc<Mutex<Vec<FileChangeEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let events_tx = Arc::clone(&events);

        let watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                let kind = match event.kind {
                    EventKind::Create(_) => FileChangeKind::Created,
                    EventKind::Modify(_) => FileChangeKind::Modified,
                    EventKind::Remove(_) => FileChangeKind::Deleted,
                    _ => return,
                };
                let timestamp_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;

                for path in &event.paths {
                    let evt = FileChangeEvent {
                        timestamp_ms,
                        path: path.display().to_string(),
                        kind,
                    };
                    if let Ok(mut guard) = events_tx.lock() {
                        // Cap buffer at 10K events to prevent unbounded growth
                        if guard.len() < 10_000 {
                            guard.push(evt);
                        }
                    }
                }
            }
        });

        let watcher = match watcher {
            Ok(mut w) => {
                for path_str in watch_paths {
                    let p = Path::new(path_str);
                    if p.exists() {
                        let _ = w.watch(p, RecursiveMode::Recursive);
                    }
                }
                Some(w)
            }
            Err(_) => None,
        };

        Self {
            events,
            _watcher: watcher,
        }
    }

    /// Drain all pending events since last call.
    pub fn drain_events(&self) -> Vec<FileChangeEvent> {
        self.events
            .lock()
            .map(|mut guard| std::mem::take(&mut *guard))
            .unwrap_or_default()
    }

    /// Count pending events without draining.
    pub fn pending_count(&self) -> usize {
        self.events.lock().map(|g| g.len()).unwrap_or(0)
    }

    /// Compute file change velocity (events per second) over the given window.
    pub fn velocity(&self, window_ms: u64) -> f32 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let cutoff = now.saturating_sub(window_ms);

        let count = self
            .events
            .lock()
            .map(|guard| guard.iter().filter(|e| e.timestamp_ms >= cutoff).count())
            .unwrap_or(0);

        if window_ms == 0 {
            return count as f32;
        }
        (count as f32) / (window_ms as f32 / 1000.0)
    }
}

// ── DNS Snapshot Collector ───────────────────────────────────────────

/// A captured DNS query event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsEvent {
    pub timestamp_ms: u64,
    pub domain: String,
    pub record_type: String,
    pub source: String,
}

/// Collect recent DNS activity from OS-specific sources.
pub fn collect_dns_snapshot() -> Vec<DnsEvent> {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    collect_dns_platform(timestamp_ms)
}

#[cfg(target_os = "linux")]
fn collect_dns_platform(timestamp_ms: u64) -> Vec<DnsEvent> {
    // Try systemd-resolved cache via resolvectl
    if let Ok(output) = std::process::Command::new("resolvectl")
        .args(["statistics"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        if text.contains("Current Cache Size") {
            // resolvectl works — try query log from journal
            if let Ok(journal) = std::process::Command::new("journalctl")
                .args([
                    "-u",
                    "systemd-resolved",
                    "--since",
                    "1 min ago",
                    "--no-pager",
                    "-q",
                ])
                .output()
            {
                let jtext = String::from_utf8_lossy(&journal.stdout);
                return parse_resolved_journal(&jtext, timestamp_ms);
            }
        }
    }

    // Fallback: scan /var/log/syslog for DNS queries
    if let Ok(content) = fs::read_to_string("/var/log/syslog") {
        return content
            .lines()
            .rev()
            .take(500)
            .filter(|l| l.contains("query[") || l.contains("dnsmasq"))
            .filter_map(|l| parse_syslog_dns_line(l, timestamp_ms))
            .take(100)
            .collect();
    }
    Vec::new()
}

#[cfg(target_os = "linux")]
fn parse_resolved_journal(text: &str, timestamp_ms: u64) -> Vec<DnsEvent> {
    text.lines()
        .filter(|l| l.contains("Positive cache") || l.contains("Lookup"))
        .filter_map(|l| {
            // Extract domain from log line
            let domain = l
                .split_whitespace()
                .find(|w| w.contains('.') && !w.starts_with('/') && w.len() > 3)?;
            Some(DnsEvent {
                timestamp_ms,
                domain: domain.trim_end_matches(':').to_string(),
                record_type: "A".into(),
                source: "systemd-resolved".into(),
            })
        })
        .take(100)
        .collect()
}

#[cfg(target_os = "linux")]
fn parse_syslog_dns_line(line: &str, timestamp_ms: u64) -> Option<DnsEvent> {
    // Format: "... dnsmasq[xxx]: query[A] example.com from ..."
    if let Some(pos) = line.find("query[") {
        let rest = &line[pos + 6..];
        let rtype = rest.split(']').next().unwrap_or("A");
        let domain = rest.split(']').nth(1)?.split_whitespace().next()?;
        return Some(DnsEvent {
            timestamp_ms,
            domain: domain.to_string(),
            record_type: rtype.to_string(),
            source: "dnsmasq".into(),
        });
    }
    None
}

#[cfg(target_os = "macos")]
fn collect_dns_platform(timestamp_ms: u64) -> Vec<DnsEvent> {
    // Use log show to capture recent DNS resolution from mDNSResponder
    if let Ok(output) = std::process::Command::new("log")
        .args([
            "show",
            "--predicate",
            "subsystem == \"com.apple.dnssd\"",
            "--last",
            "1m",
            "--style",
            "compact",
            "--info",
        ])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        return text
            .lines()
            .filter(|l| l.contains("getaddrinfo") || l.contains("QueryRecord"))
            .filter_map(|l| {
                // Extract domain name from DNS log entry
                let words: Vec<&str> = l.split_whitespace().collect();
                let domain = words
                    .iter()
                    .find(|w| w.contains('.') && !w.starts_with('[') && w.len() > 3)?;
                Some(DnsEvent {
                    timestamp_ms,
                    domain: domain.trim_end_matches(',').to_string(),
                    record_type: "A".into(),
                    source: "mDNSResponder".into(),
                })
            })
            .take(100)
            .collect();
    }
    Vec::new()
}

#[cfg(target_os = "windows")]
fn collect_dns_platform(timestamp_ms: u64) -> Vec<DnsEvent> {
    let Ok(output) = std::process::Command::new("ipconfig")
        .args(["/displaydns"])
        .output()
    else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut events = Vec::new();
    let mut current_domain: Option<String> = None;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.ends_with('-') && trimmed.len() > 4 {
            // Section header: "    example.com"
            // Might appear as: "    Record Name . . . . : example.com"
        }
        if let Some(rest) = trimmed.strip_prefix("Record Name")
            && let Some(name) = rest.split(':').nth(1)
        {
            current_domain = Some(name.trim().to_string());
        }
        if let Some(rest) = trimmed.strip_prefix("Record Type")
            && let Some(ref domain) = current_domain
        {
            let rtype = rest
                .split(':')
                .nth(1)
                .map(|t| t.trim().to_string())
                .unwrap_or_else(|| "A".into());
            events.push(DnsEvent {
                timestamp_ms,
                domain: domain.clone(),
                record_type: rtype,
                source: "dns-cache".into(),
            });
            current_domain = None;
        }
    }
    events.into_iter().take(200).collect()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn collect_dns_platform(_timestamp_ms: u64) -> Vec<DnsEvent> {
    Vec::new()
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_platform_returns_known() {
        let host = detect_platform();
        assert_ne!(host.platform, HostPlatform::Unknown);
        assert!(!host.hostname.is_empty());
        assert!(!host.arch.is_empty());
    }

    #[test]
    fn collect_sample_returns_valid() {
        let mut state = CollectorState::default();
        let sample = collect_sample(&mut state, None);
        assert!(sample.cpu_load_pct >= 0.0 && sample.cpu_load_pct <= 100.0);
        assert!(sample.memory_load_pct >= 0.0 && sample.memory_load_pct <= 100.0);
        assert!(sample.battery_pct >= 0.0 && sample.battery_pct <= 100.0);
        assert!(sample.disk_pressure_pct >= 0.0 && sample.disk_pressure_pct <= 100.0);
        assert!(sample.timestamp_ms > 0);
    }

    #[test]
    fn collect_sample_second_read_gives_cpu() {
        let mut state = CollectorState::default();
        let _ = collect_sample(&mut state, None);
        std::thread::sleep(std::time::Duration::from_millis(200));
        let sample = collect_sample(&mut state, None);
        // Second read should produce a valid CPU value
        assert!(sample.cpu_load_pct >= 0.0 && sample.cpu_load_pct <= 100.0);
    }

    #[test]
    fn file_integrity_monitor_empty() {
        let fim = FileIntegrityMonitor::new(&[]);
        assert_eq!(fim.file_count(), 0);
        assert_eq!(fim.check(), 0.0);
    }

    #[test]
    fn file_integrity_monitor_detects_self() {
        let fim = FileIntegrityMonitor::new(&["Cargo.toml".into()]);
        assert_eq!(fim.file_count(), 1);
        assert_eq!(fim.check(), 0.0); // no change since baseline
    }

    #[test]
    fn persistence_watch_paths_require_master_toggle() {
        let scope = MonitorScopeSettings {
            service_persistence: false,
            systemd_units: true,
            ..MonitorScopeSettings::default()
        };
        assert!(persistence_watch_paths(HostPlatform::Linux, &scope).is_empty());
    }

    #[test]
    fn persistence_watch_paths_default_to_platform_recommendation() {
        let scope = MonitorScopeSettings {
            service_persistence: true,
            ..MonitorScopeSettings::default()
        };

        let linux_paths = persistence_watch_paths(HostPlatform::Linux, &scope);
        assert!(linux_paths.iter().any(|path| path.contains("systemd")));

        let mac_paths = persistence_watch_paths(HostPlatform::MacOS, &scope);
        assert!(mac_paths.iter().any(|path| path.contains("Launch")));

        let windows_paths = persistence_watch_paths(HostPlatform::Windows, &scope);
        assert!(windows_paths.iter().any(|path| path.contains("Tasks")));
    }

    #[test]
    fn collect_sample_scoped_can_disable_auth_events() {
        let mut state = CollectorState::default();
        let scope = MonitorScopeSettings {
            auth_events: false,
            ..MonitorScopeSettings::default()
        };
        let sample = collect_sample_scoped(&mut state, None, None, &scope);
        assert_eq!(sample.auth_failures, 0);
    }

    #[test]
    fn alert_record_syslog_format() {
        let alert = AlertRecord {
            timestamp: "2025-01-01T00:00:00Z".into(),
            hostname: "test-host".into(),
            platform: "Linux".into(),
            score: 4.5,
            confidence: 0.9,
            level: "Severe".into(),
            action: "Quarantine".into(),
            reasons: vec!["high CPU".into(), "auth spike".into()],
            sample: crate::telemetry::TelemetrySample {
                timestamp_ms: 0,
                cpu_load_pct: 95.0,
                memory_load_pct: 80.0,
                temperature_c: 70.0,
                network_kbps: 5000.0,
                auth_failures: 50,
                battery_pct: 100.0,
                integrity_drift: 0.0,
                process_count: 200,
                disk_pressure_pct: 45.0,
            },
            enforced: false,
            mitre: vec![],
        };
        let syslog = alert.to_syslog();
        assert!(syslog.contains("Wardex"));
        assert!(syslog.contains("score=4.50"));
        assert!(syslog.contains("level=Severe"));
    }

    #[test]
    fn alert_record_cef_format() {
        let alert = AlertRecord {
            timestamp: "2025-01-01T00:00:00Z".into(),
            hostname: "test-host".into(),
            platform: "Linux".into(),
            score: 6.0,
            confidence: 0.95,
            level: "Critical".into(),
            action: "RollbackAndEscalate".into(),
            reasons: vec!["integrity breach".into()],
            sample: crate::telemetry::TelemetrySample {
                timestamp_ms: 0,
                cpu_load_pct: 50.0,
                memory_load_pct: 50.0,
                temperature_c: 40.0,
                network_kbps: 100.0,
                auth_failures: 0,
                battery_pct: 100.0,
                integrity_drift: 0.5,
                process_count: 100,
                disk_pressure_pct: 30.0,
            },
            enforced: true,
            mitre: vec![],
        };
        let cef = alert.to_cef();
        assert!(cef.starts_with("CEF:0|Wardex"));
        assert!(cef.contains("cs1=6.00"));
    }

    #[test]
    fn parse_monitor_args_defaults() {
        let args: Vec<String> = vec![];
        let config = parse_monitor_args(&mut args.into_iter());
        assert_eq!(config.interval_secs, 5);
        assert!((config.alert_threshold - 3.5).abs() < 0.01);
        assert!(!config.dry_run);
        assert!(config.webhook_url.is_none());
    }

    #[test]
    fn parse_monitor_args_full() {
        let mut args = vec![
            "--interval",
            "2",
            "--threshold",
            "4.0",
            "--webhook",
            "https://example.com/hook",
            "--alert-log",
            "/tmp/alerts.jsonl",
            "--watch",
            "/etc,/usr/bin",
            "--duration",
            "60",
            "--dry-run",
            "--syslog",
            "--cef",
        ]
        .into_iter()
        .map(String::from);
        let config = parse_monitor_args(&mut args);
        assert_eq!(config.interval_secs, 2);
        assert!((config.alert_threshold - 4.0).abs() < 0.01);
        assert_eq!(
            config.webhook_url.as_deref(),
            Some("https://example.com/hook")
        );
        assert_eq!(config.alert_log, "/tmp/alerts.jsonl");
        assert_eq!(config.watch_paths, vec!["/etc", "/usr/bin"]);
        assert_eq!(config.duration_secs, 60);
        assert!(config.dry_run);
        assert!(config.syslog);
        assert!(config.cef);
    }

    #[test]
    fn monitor_config_default_serializes() {
        let config = MonitorConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: MonitorConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.interval_secs, 5);
    }

    #[test]
    fn host_platform_display() {
        assert_eq!(HostPlatform::Linux.to_string(), "Linux");
        assert_eq!(HostPlatform::MacOS.to_string(), "macOS");
        assert_eq!(HostPlatform::Windows.to_string(), "Windows");
        assert_eq!(HostPlatform::WindowsServer.to_string(), "Windows Server");
    }
}
