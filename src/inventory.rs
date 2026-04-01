use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInventory {
    pub collected_at: String,
    pub hardware: HardwareInfo,
    pub software: Vec<InstalledPackage>,
    pub services: Vec<ServiceInfo>,
    pub network: Vec<NetworkPort>,
    pub users: Vec<UserAccount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareInfo {
    pub cpu_model: String,
    pub cpu_cores: u32,
    pub total_ram_mb: u64,
    pub disks: Vec<DiskInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskInfo {
    pub name: String,
    pub size_gb: f64,
    pub mount_point: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledPackage {
    pub name: String,
    pub version: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub status: String,
    pub pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPort {
    pub protocol: String,
    pub port: u16,
    pub state: String,
    pub process: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserAccount {
    pub username: String,
    pub uid: Option<u32>,
    pub groups: Vec<String>,
    pub last_login: Option<String>,
}

/// Collect full system inventory for the current platform.
pub fn collect_inventory() -> SystemInventory {
    let platform = std::env::consts::OS;
    SystemInventory {
        collected_at: chrono::Utc::now().to_rfc3339(),
        hardware: collect_hardware(platform),
        software: collect_software(platform),
        services: collect_services(platform),
        network: collect_network_ports(platform),
        users: collect_users(platform),
    }
}

fn collect_hardware(platform: &str) -> HardwareInfo {
    let mut info = HardwareInfo {
        cpu_model: "Unknown".into(),
        cpu_cores: 0,
        total_ram_mb: 0,
        disks: Vec::new(),
    };

    match platform {
        "macos" => {
            if let Ok(out) = std::process::Command::new("sysctl")
                .args(["-n", "machdep.cpu.brand_string"])
                .output()
            {
                if out.status.success() {
                    info.cpu_model = String::from_utf8_lossy(&out.stdout).trim().to_string();
                }
            }
            if let Ok(out) = std::process::Command::new("sysctl")
                .args(["-n", "hw.ncpu"])
                .output()
            {
                if out.status.success() {
                    info.cpu_cores = String::from_utf8_lossy(&out.stdout)
                        .trim().parse().unwrap_or(0);
                }
            }
            if let Ok(out) = std::process::Command::new("sysctl")
                .args(["-n", "hw.memsize"])
                .output()
            {
                if out.status.success() {
                    let bytes: u64 = String::from_utf8_lossy(&out.stdout)
                        .trim().parse().unwrap_or(0);
                    info.total_ram_mb = bytes / (1024 * 1024);
                }
            }
        }
        "linux" => {
            if let Ok(content) = std::fs::read_to_string("/proc/cpuinfo") {
                if let Some(line) = content.lines().find(|l| l.starts_with("model name")) {
                    info.cpu_model = line.split(':').nth(1).unwrap_or("").trim().to_string();
                }
                info.cpu_cores = content.lines()
                    .filter(|l| l.starts_with("processor"))
                    .count() as u32;
            }
            if let Ok(content) = std::fs::read_to_string("/proc/meminfo") {
                if let Some(line) = content.lines().find(|l| l.starts_with("MemTotal")) {
                    let kb: u64 = line.split_whitespace().nth(1)
                        .and_then(|v| v.parse().ok()).unwrap_or(0);
                    info.total_ram_mb = kb / 1024;
                }
            }
        }
        "windows" => {
            if let Ok(out) = std::process::Command::new("wmic")
                .args(["cpu", "get", "Name", "/value"])
                .output()
            {
                if out.status.success() {
                    let text = String::from_utf8_lossy(&out.stdout);
                    if let Some(line) = text.lines().find(|l| l.starts_with("Name=")) {
                        info.cpu_model = line.trim_start_matches("Name=").trim().to_string();
                    }
                }
            }
            if let Ok(out) = std::process::Command::new("wmic")
                .args(["cpu", "get", "NumberOfLogicalProcessors", "/value"])
                .output()
            {
                if out.status.success() {
                    let text = String::from_utf8_lossy(&out.stdout);
                    if let Some(line) = text.lines().find(|l| l.starts_with("NumberOfLogicalProcessors=")) {
                        info.cpu_cores = line.split('=').nth(1)
                            .and_then(|v| v.trim().parse().ok()).unwrap_or(0);
                    }
                }
            }
        }
        _ => {}
    }
    info
}

fn collect_software(platform: &str) -> Vec<InstalledPackage> {
    let mut packages = Vec::new();
    match platform {
        "linux" => {
            // Try dpkg first, then rpm
            if let Ok(out) = std::process::Command::new("dpkg")
                .args(["-l"])
                .output()
            {
                if out.status.success() {
                    let text = String::from_utf8_lossy(&out.stdout);
                    for line in text.lines().skip(5).take(500) {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 3 && parts[0] == "ii" {
                            packages.push(InstalledPackage {
                                name: parts[1].to_string(),
                                version: parts[2].to_string(),
                                source: "dpkg".into(),
                            });
                        }
                    }
                }
            }
            if packages.is_empty() {
                if let Ok(out) = std::process::Command::new("rpm")
                    .args(["-qa", "--queryformat", "%{NAME} %{VERSION}\\n"])
                    .output()
                {
                    if out.status.success() {
                        let text = String::from_utf8_lossy(&out.stdout);
                        for line in text.lines().take(500) {
                            let parts: Vec<&str> = line.splitn(2, ' ').collect();
                            if parts.len() == 2 {
                                packages.push(InstalledPackage {
                                    name: parts[0].to_string(),
                                    version: parts[1].to_string(),
                                    source: "rpm".into(),
                                });
                            }
                        }
                    }
                }
            }
        }
        "macos" => {
            if let Ok(out) = std::process::Command::new("pkgutil")
                .args(["--pkgs"])
                .output()
            {
                if out.status.success() {
                    let text = String::from_utf8_lossy(&out.stdout);
                    for line in text.lines().take(500) {
                        let name = line.trim().to_string();
                        if !name.is_empty() {
                            packages.push(InstalledPackage {
                                name,
                                version: "installed".into(),
                                source: "pkgutil".into(),
                            });
                        }
                    }
                }
            }
        }
        "windows" => {
            if let Ok(out) = std::process::Command::new("wmic")
                .args(["product", "get", "Name,Version", "/format:csv"])
                .output()
            {
                if out.status.success() {
                    let text = String::from_utf8_lossy(&out.stdout);
                    for line in text.lines().skip(1).take(500) {
                        let parts: Vec<&str> = line.split(',').collect();
                        if parts.len() >= 3 {
                            packages.push(InstalledPackage {
                                name: parts[1].trim().to_string(),
                                version: parts[2].trim().to_string(),
                                source: "wmic".into(),
                            });
                        }
                    }
                }
            }
        }
        _ => {}
    }
    packages
}

fn collect_services(platform: &str) -> Vec<ServiceInfo> {
    let mut services = Vec::new();
    match platform {
        "linux" => {
            if let Ok(out) = std::process::Command::new("systemctl")
                .args(["list-units", "--type=service", "--no-pager", "--plain"])
                .output()
            {
                if out.status.success() {
                    let text = String::from_utf8_lossy(&out.stdout);
                    for line in text.lines().take(300) {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 4 && parts[0].ends_with(".service") {
                            services.push(ServiceInfo {
                                name: parts[0].to_string(),
                                status: parts[3].to_string(),
                                pid: None,
                            });
                        }
                    }
                }
            }
        }
        "macos" => {
            if let Ok(out) = std::process::Command::new("launchctl")
                .args(["list"])
                .output()
            {
                if out.status.success() {
                    let text = String::from_utf8_lossy(&out.stdout);
                    for line in text.lines().skip(1).take(300) {
                        let parts: Vec<&str> = line.split('\t').collect();
                        if parts.len() >= 3 {
                            let pid = parts[0].trim().parse().ok();
                            services.push(ServiceInfo {
                                name: parts[2].trim().to_string(),
                                status: if pid.is_some() { "running" } else { "stopped" }.into(),
                                pid,
                            });
                        }
                    }
                }
            }
        }
        "windows" => {
            if let Ok(out) = std::process::Command::new("sc")
                .args(["query", "state=", "all"])
                .output()
            {
                if out.status.success() {
                    let text = String::from_utf8_lossy(&out.stdout);
                    let mut name = String::new();
                    let mut status;
                    for line in text.lines() {
                        let trimmed = line.trim();
                        if trimmed.starts_with("SERVICE_NAME:") {
                            name = trimmed.trim_start_matches("SERVICE_NAME:").trim().to_string();
                        } else if trimmed.starts_with("STATE") {
                            status = trimmed.split_whitespace().last().unwrap_or("unknown").to_string();
                            if !name.is_empty() {
                                services.push(ServiceInfo {
                                    name: name.clone(),
                                    status: status.clone(),
                                    pid: None,
                                });
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    services
}

fn collect_network_ports(platform: &str) -> Vec<NetworkPort> {
    let mut ports = Vec::new();
    match platform {
        "linux" => {
            if let Ok(out) = std::process::Command::new("ss")
                .args(["-tlnp"])
                .output()
            {
                if out.status.success() {
                    let text = String::from_utf8_lossy(&out.stdout);
                    for line in text.lines().skip(1).take(200) {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 5 {
                            if let Some(port_str) = parts[3].rsplit(':').next() {
                                if let Ok(port) = port_str.parse() {
                                    ports.push(NetworkPort {
                                        protocol: "tcp".into(),
                                        port,
                                        state: parts[0].to_string(),
                                        process: parts.get(6).map(|s| s.to_string()),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        "macos" => {
            if let Ok(out) = std::process::Command::new("lsof")
                .args(["-iTCP", "-sTCP:LISTEN", "-P", "-n"])
                .output()
            {
                if out.status.success() {
                    let text = String::from_utf8_lossy(&out.stdout);
                    for line in text.lines().skip(1).take(200) {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 9 {
                            if let Some(port_str) = parts[8].rsplit(':').next() {
                                if let Ok(port) = port_str.parse() {
                                    ports.push(NetworkPort {
                                        protocol: "tcp".into(),
                                        port,
                                        state: "LISTEN".into(),
                                        process: Some(parts[0].to_string()),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        "windows" => {
            if let Ok(out) = std::process::Command::new("netstat")
                .args(["-ano"])
                .output()
            {
                if out.status.success() {
                    let text = String::from_utf8_lossy(&out.stdout);
                    for line in text.lines().take(200) {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 5 && parts[0] == "TCP" {
                            if let Some(port_str) = parts[1].rsplit(':').next() {
                                if let Ok(port) = port_str.parse() {
                                    ports.push(NetworkPort {
                                        protocol: "tcp".into(),
                                        port,
                                        state: parts[3].to_string(),
                                        process: parts.get(4).map(|s| s.to_string()),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    ports
}

fn collect_users(platform: &str) -> Vec<UserAccount> {
    let mut users = Vec::new();
    match platform {
        "linux" => {
            if let Ok(content) = std::fs::read_to_string("/etc/passwd") {
                for line in content.lines() {
                    let parts: Vec<&str> = line.split(':').collect();
                    if parts.len() >= 7 {
                        let uid: u32 = parts[2].parse().unwrap_or(0);
                        // Skip system accounts (uid < 1000) except root
                        if uid >= 1000 || uid == 0 {
                            users.push(UserAccount {
                                username: parts[0].to_string(),
                                uid: Some(uid),
                                groups: Vec::new(),
                                last_login: None,
                            });
                        }
                    }
                }
            }
        }
        "macos" => {
            if let Ok(out) = std::process::Command::new("dscl")
                .args([".", "list", "/Users"])
                .output()
            {
                if out.status.success() {
                    let text = String::from_utf8_lossy(&out.stdout);
                    for line in text.lines() {
                        let name = line.trim().to_string();
                        if !name.starts_with('_') && !name.is_empty() {
                            users.push(UserAccount {
                                username: name,
                                uid: None,
                                groups: Vec::new(),
                                last_login: None,
                            });
                        }
                    }
                }
            }
        }
        "windows" => {
            if let Ok(out) = std::process::Command::new("net")
                .args(["user"])
                .output()
            {
                if out.status.success() {
                    let text = String::from_utf8_lossy(&out.stdout);
                    // Skip header lines, parse user names
                    let mut in_list = false;
                    for line in text.lines() {
                        if line.starts_with("---") {
                            in_list = true;
                            continue;
                        }
                        if in_list && !line.starts_with("The command") {
                            for name in line.split_whitespace() {
                                users.push(UserAccount {
                                    username: name.to_string(),
                                    uid: None,
                                    groups: Vec::new(),
                                    last_login: None,
                                });
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    users
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_serialization() {
        let inv = SystemInventory {
            collected_at: "2025-01-01T00:00:00Z".into(),
            hardware: HardwareInfo {
                cpu_model: "Test CPU".into(),
                cpu_cores: 4,
                total_ram_mb: 8192,
                disks: vec![DiskInfo { name: "sda".into(), size_gb: 256.0, mount_point: "/".into() }],
            },
            software: vec![InstalledPackage { name: "vim".into(), version: "9.0".into(), source: "apt".into() }],
            services: vec![ServiceInfo { name: "sshd".into(), status: "running".into(), pid: Some(1234) }],
            network: vec![NetworkPort { protocol: "tcp".into(), port: 22, state: "LISTEN".into(), process: Some("sshd".into()) }],
            users: vec![UserAccount { username: "root".into(), uid: Some(0), groups: vec!["root".into()], last_login: None }],
        };
        let json = serde_json::to_string(&inv).unwrap();
        let parsed: SystemInventory = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.hardware.cpu_cores, 4);
        assert_eq!(parsed.software.len(), 1);
        assert_eq!(parsed.network[0].port, 22);
    }

    #[test]
    fn collect_inventory_runs_without_panic() {
        let inv = collect_inventory();
        assert!(!inv.collected_at.is_empty());
    }
}
