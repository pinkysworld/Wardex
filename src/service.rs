use std::path::Path;

/// Cross-platform service installation for Wardex (server or agent mode).
#[allow(dead_code)]
pub struct ServiceManager {
    service_name: String,
    display_name: String,
    binary_path: String,
    args: Vec<String>,
}

impl ServiceManager {
    pub fn new(mode: &str, extra_args: &[String]) -> Result<Self, String> {
        let binary = std::env::current_exe()
            .map_err(|e| format!("cannot determine current executable: {e}"))?
            .to_string_lossy()
            .to_string();

        let (service_name, display_name) = match mode {
            "server" => ("wardex-server", "Wardex XDR Server"),
            "agent" => ("wardex-agent", "Wardex XDR Agent"),
            _ => return Err(format!("unknown mode: {mode}")),
        };

        let mut args = vec![mode.to_string()];
        args.extend_from_slice(extra_args);

        Ok(Self {
            service_name: service_name.into(),
            display_name: display_name.into(),
            binary_path: binary,
            args,
        })
    }

    /// Install the service on the current platform.
    pub fn install(&self) -> Result<String, String> {
        #[cfg(target_os = "linux")]
        return self.install_systemd();

        #[cfg(target_os = "macos")]
        return self.install_launchd();

        #[cfg(target_os = "windows")]
        return self.install_windows_service();

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        Err("service installation not supported on this platform".into())
    }

    /// Uninstall the service on the current platform.
    pub fn uninstall(&self) -> Result<String, String> {
        #[cfg(target_os = "linux")]
        return self.uninstall_systemd();

        #[cfg(target_os = "macos")]
        return self.uninstall_launchd();

        #[cfg(target_os = "windows")]
        return self.uninstall_windows_service();

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        Err("service uninstallation not supported on this platform".into())
    }

    /// Get the service status.
    pub fn status(&self) -> Result<String, String> {
        #[cfg(target_os = "linux")]
        {
            run_command("systemctl", &["is-active", &self.service_name])
        }

        #[cfg(target_os = "macos")]
        {
            let label = format!("com.wardex.{}", self.service_name);
            run_command("launchctl", &["print", &format!("system/{label}")])
        }

        #[cfg(target_os = "windows")]
        {
            run_command("sc.exe", &["query", &self.service_name])
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        Err("not supported on this platform".into())
    }

    // ── Linux (systemd) ──────────────────────────────────────────────

    #[cfg(target_os = "linux")]
    fn install_systemd(&self) -> Result<String, String> {
        let args_str = self.args.join(" ");
        let unit = format!(
            "[Unit]\n\
            Description={display}\n\
            After=network.target\n\
            \n\
            [Service]\n\
            Type=simple\n\
            ExecStart={binary} {args}\n\
            Restart=on-failure\n\
            RestartSec=10\n\
            StandardOutput=journal\n\
            StandardError=journal\n\
            \n\
            [Install]\n\
            WantedBy=multi-user.target\n",
            display = self.display_name,
            binary = self.binary_path,
            args = args_str,
        );

        let unit_path = format!("/etc/systemd/system/{}.service", self.service_name);
        std::fs::write(&unit_path, &unit)
            .map_err(|e| format!("failed to write unit file: {e}"))?;

        run_command("systemctl", &["daemon-reload"])?;
        run_command("systemctl", &["enable", &self.service_name])?;
        run_command("systemctl", &["start", &self.service_name])?;

        Ok(format!("Installed and started {}", self.service_name))
    }

    #[cfg(target_os = "linux")]
    fn uninstall_systemd(&self) -> Result<String, String> {
        let _ = run_command("systemctl", &["stop", &self.service_name]);
        let _ = run_command("systemctl", &["disable", &self.service_name]);

        let unit_path = format!("/etc/systemd/system/{}.service", self.service_name);
        if Path::new(&unit_path).exists() {
            std::fs::remove_file(&unit_path)
                .map_err(|e| format!("failed to remove unit: {e}"))?;
        }
        let _ = run_command("systemctl", &["daemon-reload"]);

        Ok(format!("Uninstalled {}", self.service_name))
    }

    // ── macOS (launchd) ──────────────────────────────────────────────

    #[cfg(target_os = "macos")]
    fn install_launchd(&self) -> Result<String, String> {
        let label = format!("com.wardex.{}", self.service_name);
        let mut args_xml = format!("    <string>{}</string>\n", self.binary_path);
        for arg in &self.args {
            args_xml.push_str(&format!("    <string>{arg}</string>\n"));
        }

        let plist = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
{args}  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/var/log/{svc}.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/{svc}.err</string>
</dict>
</plist>"#,
            label = label,
            args = args_xml,
            svc = self.service_name,
        );

        let plist_path = format!("/Library/LaunchDaemons/{label}.plist");
        std::fs::write(&plist_path, &plist)
            .map_err(|e| format!("failed to write plist: {e}"))?;

        run_command("launchctl", &["load", &plist_path])?;

        Ok(format!("Installed and loaded {label}"))
    }

    #[cfg(target_os = "macos")]
    fn uninstall_launchd(&self) -> Result<String, String> {
        let label = format!("com.wardex.{}", self.service_name);
        let plist_path = format!("/Library/LaunchDaemons/{label}.plist");

        let _ = run_command("launchctl", &["unload", &plist_path]);

        if Path::new(&plist_path).exists() {
            std::fs::remove_file(&plist_path)
                .map_err(|e| format!("failed to remove plist: {e}"))?;
        }

        Ok(format!("Uninstalled {label}"))
    }

    // ── Windows (sc.exe) ─────────────────────────────────────────────

    #[cfg(target_os = "windows")]
    fn install_windows_service(&self) -> Result<String, String> {
        let binary_with_args = format!(
            "\"{}\" {}",
            self.binary_path,
            self.args.join(" ")
        );

        run_command(
            "sc.exe",
            &[
                "create",
                &self.service_name,
                &format!("binPath={}", binary_with_args),
                &format!("DisplayName={}", self.display_name),
                "start=auto",
            ],
        )?;

        run_command("sc.exe", &["start", &self.service_name])?;

        Ok(format!("Installed and started {}", self.service_name))
    }

    #[cfg(target_os = "windows")]
    fn uninstall_windows_service(&self) -> Result<String, String> {
        let _ = run_command("sc.exe", &["stop", &self.service_name]);
        run_command("sc.exe", &["delete", &self.service_name])?;

        Ok(format!("Uninstalled {}", self.service_name))
    }
}

/// Generate a systemd/launchd/sc-compatible service unit description for display.
pub fn describe_service(mode: &str) -> String {
    match mode {
        "server" => "Wardex XDR Server — central management and event correlation".into(),
        "agent" => "Wardex XDR Agent — endpoint telemetry collection and forwarding".into(),
        _ => "Unknown Wardex service mode".into(),
    }
}

fn run_command(cmd: &str, args: &[&str]) -> Result<String, String> {
    let output = std::process::Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("failed to run {cmd}: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if output.status.success() {
        Ok(stdout)
    } else {
        Err(format!("{cmd} failed: {stderr}"))
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_manager_creation() {
        let sm = ServiceManager::new("server", &[]).unwrap();
        assert_eq!(sm.service_name, "wardex-server");
        assert_eq!(sm.display_name, "Wardex XDR Server");
    }

    #[test]
    fn service_manager_agent_mode() {
        let args = vec!["--server".into(), "http://localhost:8080".into()];
        let sm = ServiceManager::new("agent", &args).unwrap();
        assert_eq!(sm.service_name, "wardex-agent");
        assert_eq!(sm.args, vec!["agent", "--server", "http://localhost:8080"]);
    }

    #[test]
    fn invalid_mode_rejected() {
        let result = ServiceManager::new("invalid", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn describe_server() {
        let desc = describe_service("server");
        assert!(desc.contains("central management"));
    }

    #[test]
    fn describe_agent() {
        let desc = describe_service("agent");
        assert!(desc.contains("endpoint telemetry"));
    }
}
