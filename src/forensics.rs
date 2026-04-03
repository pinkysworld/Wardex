use serde::Serialize;
use std::fs;
use std::path::Path;

use crate::runtime::RunResult;

use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use aes_gcm::aead::generic_array::GenericArray;
use rand::RngCore;

#[derive(Debug, Clone, Serialize)]
pub struct ForensicBundle {
    pub generated_at: String,
    pub total_samples: usize,
    pub alert_count: usize,
    pub critical_count: usize,
    pub average_score: f32,
    pub max_score: f32,
    pub audit_records: Vec<ForensicAuditEntry>,
    pub checkpoints: Vec<ForensicCheckpointEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ForensicAuditEntry {
    pub sequence: usize,
    pub category: String,
    pub summary: String,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ForensicCheckpointEntry {
    pub after_sequence: usize,
    pub cumulative_hash: String,
    pub signature: String,
}

impl ForensicBundle {
    pub fn from_run_result(result: &RunResult) -> Self {
        let audit_records = result
            .audit
            .records()
            .iter()
            .map(|r| ForensicAuditEntry {
                sequence: r.sequence,
                category: r.category.clone(),
                summary: r.summary.clone(),
                hash: r.current_hash.clone(),
            })
            .collect();

        let checkpoints = result
            .audit
            .checkpoints()
            .iter()
            .map(|cp| ForensicCheckpointEntry {
                after_sequence: cp.after_sequence,
                cumulative_hash: cp.cumulative_hash.clone(),
                signature: cp.signature.clone(),
            })
            .collect();

        Self {
            generated_at: chrono::Utc::now().to_rfc3339(),
            total_samples: result.summary.total_samples,
            alert_count: result.summary.alert_count,
            critical_count: result.summary.critical_count,
            average_score: result.summary.average_score,
            max_score: result.summary.max_score,
            audit_records,
            checkpoints,
        }
    }

    pub fn write_to_path(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create bundle directory: {e}"))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("failed to serialize forensic bundle: {e}"))?;
        fs::write(path, json).map_err(|e| format!("failed to write forensic bundle: {e}"))
    }

    /// Write the forensic bundle encrypted with AES-256-GCM.
    /// `key` must be exactly 32 bytes. The output file contains: 12-byte nonce ∥ ciphertext.
    pub fn write_encrypted(&self, path: &Path, key: &[u8; 32]) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create bundle directory: {e}"))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("failed to serialize forensic bundle: {e}"))?;

        let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = GenericArray::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, json.as_bytes())
            .map_err(|e| format!("AES-GCM encryption failed: {e}"))?;

        let mut output = Vec::with_capacity(12 + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);

        fs::write(path, output)
            .map_err(|e| format!("failed to write encrypted forensic bundle: {e}"))
    }

    /// Read and decrypt an AES-256-GCM encrypted forensic bundle.
    pub fn read_encrypted(path: &Path, key: &[u8; 32]) -> Result<String, String> {
        let data = fs::read(path)
            .map_err(|e| format!("failed to read encrypted bundle: {e}"))?;
        if data.len() < 12 {
            return Err("encrypted bundle too short".into());
        }
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
        let nonce = GenericArray::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("AES-GCM decryption failed: {e}"))?;

        String::from_utf8(plaintext)
            .map_err(|e| format!("decrypted bundle is not valid UTF-8: {e}"))
    }
}

// ── Evidence Collection Plans ────────────────────────────────────

/// Per-platform evidence artefact descriptor.
#[derive(Debug, Clone, Serialize)]
pub struct EvidenceArtifact {
    pub name: &'static str,
    pub path: &'static str,
    pub description: &'static str,
    pub volatile: bool,
}

/// Evidence collection plan with prioritised artefact list.
#[derive(Debug, Clone, Serialize)]
pub struct EvidenceCollectionPlan {
    pub platform: String,
    pub artifacts: Vec<EvidenceArtifact>,
}

impl EvidenceCollectionPlan {
    /// Build a collection plan for Linux hosts.
    pub fn linux() -> Self {
        Self {
            platform: "linux".into(),
            artifacts: vec![
                EvidenceArtifact { name: "process_list", path: "/proc", description: "Running processes and open fds", volatile: true },
                EvidenceArtifact { name: "network_connections", path: "/proc/net/tcp", description: "Active TCP connections", volatile: true },
                EvidenceArtifact { name: "network_connections6", path: "/proc/net/tcp6", description: "Active IPv6 TCP connections", volatile: true },
                EvidenceArtifact { name: "loaded_modules", path: "/proc/modules", description: "Loaded kernel modules", volatile: true },
                EvidenceArtifact { name: "mount_table", path: "/proc/mounts", description: "Mounted filesystems", volatile: true },
                EvidenceArtifact { name: "auth_log", path: "/var/log/auth.log", description: "Authentication log", volatile: false },
                EvidenceArtifact { name: "syslog", path: "/var/log/syslog", description: "System log", volatile: false },
                EvidenceArtifact { name: "journal", path: "/var/log/journal", description: "Systemd journal", volatile: false },
                EvidenceArtifact { name: "crontabs", path: "/var/spool/cron", description: "Scheduled tasks", volatile: false },
                EvidenceArtifact { name: "systemd_units", path: "/etc/systemd/system", description: "Custom systemd services", volatile: false },
                EvidenceArtifact { name: "passwd", path: "/etc/passwd", description: "User accounts", volatile: false },
                EvidenceArtifact { name: "shadow", path: "/etc/shadow", description: "Password hashes", volatile: false },
                EvidenceArtifact { name: "sudoers", path: "/etc/sudoers.d", description: "Sudo rules", volatile: false },
                EvidenceArtifact { name: "ssh_keys", path: "/home/*/.ssh", description: "SSH authorised keys", volatile: false },
                EvidenceArtifact { name: "bash_history", path: "/home/*/.bash_history", description: "Shell history", volatile: false },
                EvidenceArtifact { name: "tmp_files", path: "/tmp", description: "Temporary files", volatile: false },
                EvidenceArtifact { name: "audit_log", path: "/var/log/audit/audit.log", description: "Linux audit log", volatile: false },
                EvidenceArtifact { name: "dns_resolv", path: "/etc/resolv.conf", description: "DNS configuration", volatile: false },
                EvidenceArtifact { name: "hosts_file", path: "/etc/hosts", description: "Hosts file", volatile: false },
                EvidenceArtifact { name: "iptables_rules", path: "/etc/iptables", description: "Firewall rules", volatile: false },
            ],
        }
    }

    /// Build a collection plan for macOS hosts.
    pub fn macos() -> Self {
        Self {
            platform: "macos".into(),
            artifacts: vec![
                EvidenceArtifact { name: "process_list", path: "/dev/null", description: "Running processes (ps aux)", volatile: true },
                EvidenceArtifact { name: "network_connections", path: "/dev/null", description: "Active connections (netstat -an)", volatile: true },
                EvidenceArtifact { name: "unified_log", path: "/var/db/diagnostics", description: "macOS unified log", volatile: false },
                EvidenceArtifact { name: "install_log", path: "/var/log/install.log", description: "Install history", volatile: false },
                EvidenceArtifact { name: "launch_daemons", path: "/Library/LaunchDaemons", description: "System launch daemons", volatile: false },
                EvidenceArtifact { name: "launch_agents", path: "/Library/LaunchAgents", description: "System launch agents", volatile: false },
                EvidenceArtifact { name: "user_launch_agents", path: "~/Library/LaunchAgents", description: "User launch agents", volatile: false },
                EvidenceArtifact { name: "login_items", path: "~/Library/Application Support/com.apple.backgroundtaskmanagementagent", description: "Login items", volatile: false },
                EvidenceArtifact { name: "tcc_db", path: "/Library/Application Support/com.apple.TCC/TCC.db", description: "TCC permissions database", volatile: false },
                EvidenceArtifact { name: "keychain_db", path: "~/Library/Keychains", description: "User keychains", volatile: false },
                EvidenceArtifact { name: "safari_history", path: "~/Library/Safari/History.db", description: "Safari browsing history", volatile: false },
                EvidenceArtifact { name: "chrome_history", path: "~/Library/Application Support/Google/Chrome/Default/History", description: "Chrome history", volatile: false },
                EvidenceArtifact { name: "bash_history", path: "~/.bash_history", description: "Bash history", volatile: false },
                EvidenceArtifact { name: "zsh_history", path: "~/.zsh_history", description: "Zsh history", volatile: false },
                EvidenceArtifact { name: "profiles", path: "/var/db/ConfigurationProfiles", description: "MDM configuration profiles", volatile: false },
                EvidenceArtifact { name: "kernel_extensions", path: "/Library/Extensions", description: "Kernel extensions", volatile: false },
                EvidenceArtifact { name: "system_extensions", path: "/Library/SystemExtensions", description: "System extensions (ESF)", volatile: false },
                EvidenceArtifact { name: "quarantine_db", path: "~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2", description: "Quarantine events", volatile: false },
            ],
        }
    }

    /// Build a collection plan for Windows hosts.
    pub fn windows() -> Self {
        Self {
            platform: "windows".into(),
            artifacts: vec![
                EvidenceArtifact { name: "process_list", path: "NUL", description: "Running processes (tasklist /v)", volatile: true },
                EvidenceArtifact { name: "network_connections", path: "NUL", description: "Active connections (netstat -ano)", volatile: true },
                EvidenceArtifact { name: "security_evtx", path: r"C:\Windows\System32\winevt\Logs\Security.evtx", description: "Security event log", volatile: false },
                EvidenceArtifact { name: "system_evtx", path: r"C:\Windows\System32\winevt\Logs\System.evtx", description: "System event log", volatile: false },
                EvidenceArtifact { name: "powershell_evtx", path: r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx", description: "PowerShell log", volatile: false },
                EvidenceArtifact { name: "sysmon_evtx", path: r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx", description: "Sysmon log", volatile: false },
                EvidenceArtifact { name: "prefetch", path: r"C:\Windows\Prefetch", description: "Prefetch files", volatile: false },
                EvidenceArtifact { name: "amcache", path: r"C:\Windows\AppCompat\Programs\Amcache.hve", description: "AmCache hive", volatile: false },
                EvidenceArtifact { name: "shimcache", path: r"C:\Windows\System32\config\SYSTEM", description: "ShimCache in SYSTEM hive", volatile: false },
                EvidenceArtifact { name: "scheduled_tasks", path: r"C:\Windows\System32\Tasks", description: "Scheduled tasks", volatile: false },
                EvidenceArtifact { name: "startup_folder", path: r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup", description: "Startup folder", volatile: false },
                EvidenceArtifact { name: "registry_run", path: r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", description: "Registry run keys", volatile: false },
                EvidenceArtifact { name: "wmi_subscriptions", path: r"C:\Windows\System32\wbem\Repository", description: "WMI repository", volatile: false },
                EvidenceArtifact { name: "hosts_file", path: r"C:\Windows\System32\drivers\etc\hosts", description: "Hosts file", volatile: false },
                EvidenceArtifact { name: "ntuser_dat", path: r"C:\Users\*\NTUSER.DAT", description: "User registry hives", volatile: false },
                EvidenceArtifact { name: "recent_files", path: r"C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent", description: "Recently opened files", volatile: false },
                EvidenceArtifact { name: "powershell_history", path: r"C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt", description: "PS history", volatile: false },
            ],
        }
    }

    /// Filter to volatile-only artefacts (collect first for triage).
    pub fn volatile_only(&self) -> Vec<&EvidenceArtifact> {
        self.artifacts.iter().filter(|a| a.volatile).collect()
    }

    /// Filter to non-volatile artefacts.
    pub fn persistent_only(&self) -> Vec<&EvidenceArtifact> {
        self.artifacts.iter().filter(|a| !a.volatile).collect()
    }

    /// Total artefact count.
    pub fn count(&self) -> usize {
        self.artifacts.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{demo_samples, execute};

    #[test]
    fn bundle_captures_audit_records() {
        let result = execute(&demo_samples());
        let bundle = ForensicBundle::from_run_result(&result);

        assert_eq!(bundle.total_samples, 5);
        assert!(!bundle.audit_records.is_empty());
        assert!(bundle.max_score > 4.0);
    }

    #[test]
    fn bundle_serializes_to_json() {
        let result = execute(&demo_samples());
        let bundle = ForensicBundle::from_run_result(&result);
        let json = serde_json::to_string_pretty(&bundle).unwrap();

        assert!(json.contains("audit_records"));
        assert!(json.contains("checkpoints"));
        assert!(json.contains("generated_at"));
    }

    #[test]
    fn bundle_encrypt_decrypt_round_trip() {
        let result = execute(&demo_samples());
        let bundle = ForensicBundle::from_run_result(&result);
        let key: [u8; 32] = [0x42; 32];
        let dir = std::env::temp_dir().join("wardex_test_forensic_enc");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("bundle.enc");

        bundle.write_encrypted(&path, &key).unwrap();
        let decrypted = ForensicBundle::read_encrypted(&path, &key).unwrap();
        assert!(decrypted.contains("audit_records"));
        assert!(decrypted.contains("generated_at"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bundle_decrypt_wrong_key_fails() {
        let result = execute(&demo_samples());
        let bundle = ForensicBundle::from_run_result(&result);
        let key: [u8; 32] = [0x42; 32];
        let wrong_key: [u8; 32] = [0x99; 32];
        let dir = std::env::temp_dir().join("wardex_test_forensic_wrong_key");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("bundle.enc");

        bundle.write_encrypted(&path, &key).unwrap();
        assert!(ForensicBundle::read_encrypted(&path, &wrong_key).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn evidence_plan_linux_has_artifacts() {
        let plan = EvidenceCollectionPlan::linux();
        assert!(plan.count() > 10);
        assert!(plan.volatile_only().len() >= 2);
        assert!(plan.persistent_only().len() > 5);
    }

    #[test]
    fn evidence_plan_macos_has_tcc() {
        let plan = EvidenceCollectionPlan::macos();
        assert!(plan.artifacts.iter().any(|a| a.name == "tcc_db"));
    }

    #[test]
    fn evidence_plan_windows_has_evtx() {
        let plan = EvidenceCollectionPlan::windows();
        assert!(plan.artifacts.iter().any(|a| a.name == "security_evtx"));
        assert!(plan.artifacts.iter().any(|a| a.name == "prefetch"));
    }
}
