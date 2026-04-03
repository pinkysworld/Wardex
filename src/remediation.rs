//! Automated remediation engine with per-platform adapters.
//!
//! Provides a catalog of remediation actions, prerequisite checks,
//! rollback snapshots, and platform-specific execution paths.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Remediation actions ─────────────────────────────────────────

/// A remediation action that can be applied to a host.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum RemediationAction {
    /// Kill a malicious process.
    KillProcess { pid: u32, name: String },
    /// Quarantine a file (move to secure vault).
    QuarantineFile { path: String },
    /// Restore a file from a known-good copy.
    RestoreFile { path: String, source: String },
    /// Delete a persistence mechanism.
    RemovePersistence { mechanism: PersistenceMechanism },
    /// Revert a registry change (Windows).
    RevertRegistry { key: String, value_name: String, original_data: String },
    /// Block an IP at host firewall.
    BlockIp { addr: String },
    /// Disable a user account.
    DisableAccount { username: String },
    /// Revoke authentication tokens/sessions.
    RevokeTokens { username: String },
    /// Restart a service.
    RestartService { service_name: String },
    /// Apply a patch / update a package.
    PatchPackage { package: String, version: String },
    /// Reset file permissions.
    ResetPermissions { path: String, mode: String },
    /// Clear scheduled task.
    RemoveScheduledTask { task_name: String },
    /// Flush DNS cache.
    FlushDns,
    /// Custom remediation command.
    Custom { label: String, command: String, args: Vec<String> },
}

/// Persistence mechanisms across platforms.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PersistenceMechanism {
    /// Linux: systemd unit file.
    SystemdUnit { name: String },
    /// Linux: crontab entry.
    CronJob { user: String, pattern: String },
    /// Linux/macOS: rc.local or init script.
    InitScript { path: String },
    /// macOS: LaunchDaemon or LaunchAgent plist.
    LaunchItem { path: String, item_type: LaunchItemType },
    /// macOS: login item.
    LoginItem { name: String },
    /// Windows: Run/RunOnce registry key.
    RegistryRunKey { hive: String, value_name: String },
    /// Windows: scheduled task.
    ScheduledTask { name: String },
    /// Windows: WMI event subscription.
    WmiSubscription { name: String },
    /// Windows: service.
    WindowsService { name: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum LaunchItemType {
    Daemon,
    Agent,
}

// ── Platform adapters ───────────────────────────────────────────

/// Platform-specific remediation commands.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RemediationPlatform {
    Linux,
    MacOs,
    Windows,
}

/// Convert a remediation action to platform-specific commands.
pub fn platform_commands(
    action: &RemediationAction,
    platform: &RemediationPlatform,
) -> Vec<RemediationCommand> {
    match action {
        RemediationAction::KillProcess { pid, .. } => match platform {
            RemediationPlatform::Linux | RemediationPlatform::MacOs => {
                vec![RemediationCommand::new(
                    "kill",
                    vec!["-9".into(), pid.to_string()],
                    true,
                )]
            }
            RemediationPlatform::Windows => {
                vec![RemediationCommand::new(
                    "taskkill",
                    vec!["/PID".into(), pid.to_string(), "/F".into()],
                    true,
                )]
            }
        },
        RemediationAction::QuarantineFile { path } => {
            vec![RemediationCommand::new(
                "mv",
                vec![
                    path.clone(),
                    format!("/var/quarantine/{}", sanitize_filename(path)),
                ],
                true,
            )]
        }
        RemediationAction::BlockIp { addr } => match platform {
            RemediationPlatform::Linux => {
                vec![RemediationCommand::new(
                    "iptables",
                    vec![
                        "-A".into(),
                        "INPUT".into(),
                        "-s".into(),
                        addr.clone(),
                        "-j".into(),
                        "DROP".into(),
                    ],
                    true,
                )]
            }
            RemediationPlatform::MacOs => {
                vec![RemediationCommand::new(
                    "pfctl",
                    vec![
                        "-t".into(),
                        "blocked".into(),
                        "-T".into(),
                        "add".into(),
                        addr.clone(),
                    ],
                    true,
                )]
            }
            RemediationPlatform::Windows => {
                vec![RemediationCommand::new(
                    "netsh",
                    vec![
                        "advfirewall".into(),
                        "firewall".into(),
                        "add".into(),
                        "rule".into(),
                        format!("name=Block_{addr}"),
                        "dir=in".into(),
                        "action=block".into(),
                        format!("remoteip={addr}"),
                    ],
                    true,
                )]
            }
        },
        RemediationAction::DisableAccount { username } => match platform {
            RemediationPlatform::Linux => {
                vec![RemediationCommand::new(
                    "usermod",
                    vec!["-L".into(), username.clone()],
                    true,
                )]
            }
            RemediationPlatform::MacOs => {
                vec![RemediationCommand::new(
                    "dscl",
                    vec![
                        ".".into(),
                        "-create".into(),
                        format!("/Users/{username}"),
                        "AuthenticationAuthority".into(),
                        ";DisabledUser;".into(),
                    ],
                    true,
                )]
            }
            RemediationPlatform::Windows => {
                vec![RemediationCommand::new(
                    "net",
                    vec!["user".into(), username.clone(), "/active:no".into()],
                    true,
                )]
            }
        },
        RemediationAction::RemovePersistence { mechanism } => {
            persistence_removal_commands(mechanism, platform)
        }
        RemediationAction::FlushDns => match platform {
            RemediationPlatform::Linux => {
                vec![RemediationCommand::new(
                    "systemd-resolve",
                    vec!["--flush-caches".into()],
                    false,
                )]
            }
            RemediationPlatform::MacOs => {
                vec![RemediationCommand::new(
                    "dscacheutil",
                    vec!["-flushcache".into()],
                    false,
                )]
            }
            RemediationPlatform::Windows => {
                vec![RemediationCommand::new(
                    "ipconfig",
                    vec!["/flushdns".into()],
                    false,
                )]
            }
        },
        RemediationAction::RemoveScheduledTask { task_name } => match platform {
            RemediationPlatform::Linux => {
                vec![] // cron handled via RemovePersistence
            }
            RemediationPlatform::MacOs => {
                vec![] // launchd handled via RemovePersistence
            }
            RemediationPlatform::Windows => {
                vec![RemediationCommand::new(
                    "schtasks",
                    vec!["/Delete".into(), "/TN".into(), task_name.clone(), "/F".into()],
                    true,
                )]
            }
        },
        _ => vec![],
    }
}

fn persistence_removal_commands(
    mechanism: &PersistenceMechanism,
    platform: &RemediationPlatform,
) -> Vec<RemediationCommand> {
    match mechanism {
        PersistenceMechanism::SystemdUnit { name } => {
            if *platform == RemediationPlatform::Linux {
                vec![
                    RemediationCommand::new(
                        "systemctl",
                        vec!["stop".into(), name.clone()],
                        true,
                    ),
                    RemediationCommand::new(
                        "systemctl",
                        vec!["disable".into(), name.clone()],
                        true,
                    ),
                ]
            } else {
                vec![]
            }
        }
        PersistenceMechanism::LaunchItem { path, .. } => {
            if *platform == RemediationPlatform::MacOs {
                let label = path
                    .rsplit('/')
                    .next()
                    .unwrap_or(path)
                    .trim_end_matches(".plist");
                vec![
                    RemediationCommand::new(
                        "launchctl",
                        vec!["unload".into(), path.clone()],
                        true,
                    ),
                    RemediationCommand::new(
                        "mv",
                        vec![
                            path.clone(),
                            format!("/var/quarantine/{label}.plist"),
                        ],
                        true,
                    ),
                ]
            } else {
                vec![]
            }
        }
        PersistenceMechanism::RegistryRunKey { hive, value_name } => {
            if *platform == RemediationPlatform::Windows {
                vec![RemediationCommand::new(
                    "reg",
                    vec![
                        "delete".into(),
                        hive.clone(),
                        "/v".into(),
                        value_name.clone(),
                        "/f".into(),
                    ],
                    true,
                )]
            } else {
                vec![]
            }
        }
        PersistenceMechanism::CronJob { user, .. } => {
            if *platform == RemediationPlatform::Linux || *platform == RemediationPlatform::MacOs {
                // List cron for audit, actual removal needs manual crontab edit
                vec![RemediationCommand::new(
                    "crontab",
                    vec!["-l".into(), "-u".into(), user.clone()],
                    false,
                )]
            } else {
                vec![]
            }
        }
        PersistenceMechanism::ScheduledTask { name } | PersistenceMechanism::WmiSubscription { name } => {
            if *platform == RemediationPlatform::Windows {
                vec![RemediationCommand::new(
                    "schtasks",
                    vec!["/Delete".into(), "/TN".into(), name.clone(), "/F".into()],
                    true,
                )]
            } else {
                vec![]
            }
        }
        PersistenceMechanism::WindowsService { name } => {
            if *platform == RemediationPlatform::Windows {
                vec![
                    RemediationCommand::new("sc", vec!["stop".into(), name.clone()], true),
                    RemediationCommand::new("sc", vec!["delete".into(), name.clone()], true),
                ]
            } else {
                vec![]
            }
        }
        _ => vec![],
    }
}

/// A concrete command to execute on the target host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationCommand {
    pub program: String,
    pub args: Vec<String>,
    pub requires_elevation: bool,
}

impl RemediationCommand {
    pub fn new(program: &str, args: Vec<String>, requires_elevation: bool) -> Self {
        Self {
            program: program.into(),
            args,
            requires_elevation,
        }
    }
}

// ── Execution tracking ──────────────────────────────────────────

/// Snapshot taken before remediation for rollback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationSnapshot {
    pub snapshot_id: String,
    pub action: RemediationAction,
    pub platform: RemediationPlatform,
    pub hostname: String,
    /// Files backed up before modification.
    pub backed_up_files: Vec<String>,
    /// State values recorded before change.
    pub prior_state: HashMap<String, String>,
    pub taken_at: u64,
}

/// Outcome of a remediation attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationResult {
    pub action: RemediationAction,
    pub status: RemediationStatus,
    pub commands_run: Vec<RemediationCommand>,
    pub snapshot_id: Option<String>,
    pub output: Option<String>,
    pub error: Option<String>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RemediationStatus {
    Success,
    PartialSuccess,
    Failed,
    RolledBack,
    Skipped,
    PendingApproval,
}

// ── Engine ──────────────────────────────────────────────────────

/// Remediation engine tracking actions, snapshots, and results.
pub struct RemediationEngine {
    snapshots: Vec<RemediationSnapshot>,
    results: Vec<RemediationResult>,
    /// Actions requiring human approval before execution.
    approval_required: Vec<RemediationAction>,
    next_snapshot_id: u64,
}

impl Default for RemediationEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl RemediationEngine {
    pub fn new() -> Self {
        Self {
            snapshots: Vec::new(),
            results: Vec::new(),
            approval_required: vec![
                RemediationAction::DisableAccount {
                    username: String::new(),
                },
                RemediationAction::Custom {
                    label: String::new(),
                    command: String::new(),
                    args: vec![],
                },
            ],
            next_snapshot_id: 1,
        }
    }

    /// Check whether an action needs approval (matches by variant only).
    pub fn needs_approval(&self, action: &RemediationAction) -> bool {
        self.approval_required.iter().any(|a| {
            std::mem::discriminant(a) == std::mem::discriminant(action)
        })
    }

    /// Set which action types need approval.
    pub fn set_approval_required(&mut self, actions: Vec<RemediationAction>) {
        self.approval_required = actions;
    }

    /// Plan remediation: generate platform commands and prerequisite checks.
    pub fn plan(
        &self,
        action: &RemediationAction,
        platform: &RemediationPlatform,
    ) -> RemediationPlan {
        let commands = platform_commands(action, platform);
        let needs_approval = self.needs_approval(action);
        let prerequisites = prerequisite_checks(action, platform);

        RemediationPlan {
            action: action.clone(),
            platform: platform.clone(),
            commands,
            prerequisites,
            needs_approval,
        }
    }

    /// Record a snapshot for rollback.
    pub fn record_snapshot(
        &mut self,
        action: RemediationAction,
        platform: RemediationPlatform,
        hostname: &str,
        backed_up: Vec<String>,
        prior_state: HashMap<String, String>,
        now_ms: u64,
    ) -> String {
        let id = format!("snap-{}", self.next_snapshot_id);
        self.next_snapshot_id += 1;
        self.snapshots.push(RemediationSnapshot {
            snapshot_id: id.clone(),
            action,
            platform,
            hostname: hostname.into(),
            backed_up_files: backed_up,
            prior_state,
            taken_at: now_ms,
        });
        id
    }

    /// Record a remediation result.
    pub fn record_result(&mut self, result: RemediationResult) {
        self.results.push(result);
    }

    /// Get snapshot for potential rollback.
    pub fn get_snapshot(&self, id: &str) -> Option<&RemediationSnapshot> {
        self.snapshots.iter().find(|s| s.snapshot_id == id)
    }

    /// Recent remediation results.
    pub fn recent_results(&self, limit: usize) -> Vec<&RemediationResult> {
        let start = self.results.len().saturating_sub(limit);
        self.results[start..].iter().collect()
    }

    /// Stats: success / failure counts.
    pub fn stats(&self) -> RemediationStats {
        let mut stats = RemediationStats::default();
        for r in &self.results {
            match r.status {
                RemediationStatus::Success => stats.succeeded += 1,
                RemediationStatus::PartialSuccess => stats.partial += 1,
                RemediationStatus::Failed => stats.failed += 1,
                RemediationStatus::RolledBack => stats.rolled_back += 1,
                RemediationStatus::Skipped => stats.skipped += 1,
                RemediationStatus::PendingApproval => stats.pending += 1,
            }
        }
        stats
    }
}

/// A planned remediation before execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationPlan {
    pub action: RemediationAction,
    pub platform: RemediationPlatform,
    pub commands: Vec<RemediationCommand>,
    pub prerequisites: Vec<String>,
    pub needs_approval: bool,
}

/// Prerequisite checks for a remediation action.
fn prerequisite_checks(
    action: &RemediationAction,
    _platform: &RemediationPlatform,
) -> Vec<String> {
    match action {
        RemediationAction::KillProcess { pid, .. } => {
            vec![format!("Process {pid} exists and is running")]
        }
        RemediationAction::QuarantineFile { path } => {
            vec![
                format!("File {path} exists"),
                "Quarantine directory is writable".into(),
            ]
        }
        RemediationAction::BlockIp { addr } => {
            vec![format!("IP {addr} is not in allow-list")]
        }
        RemediationAction::DisableAccount { username } => {
            vec![
                format!("Account {username} exists"),
                format!("Account {username} is not a service account"),
            ]
        }
        _ => vec![],
    }
}

/// Remediation statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RemediationStats {
    pub succeeded: u64,
    pub partial: u64,
    pub failed: u64,
    pub rolled_back: u64,
    pub skipped: u64,
    pub pending: u64,
}

// ── Helpers ─────────────────────────────────────────────────────

fn sanitize_filename(path: &str) -> String {
    path.replace(['/', '\\'], "_")
        .trim_start_matches('_')
        .to_string()
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kill_process_linux() {
        let cmds = platform_commands(
            &RemediationAction::KillProcess {
                pid: 1234,
                name: "malware".into(),
            },
            &RemediationPlatform::Linux,
        );
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].program, "kill");
        assert!(cmds[0].args.contains(&"1234".to_string()));
    }

    #[test]
    fn kill_process_windows() {
        let cmds = platform_commands(
            &RemediationAction::KillProcess {
                pid: 5678,
                name: "malware.exe".into(),
            },
            &RemediationPlatform::Windows,
        );
        assert_eq!(cmds[0].program, "taskkill");
    }

    #[test]
    fn block_ip_per_platform() {
        let action = RemediationAction::BlockIp {
            addr: "10.0.0.99".into(),
        };
        let linux = platform_commands(&action, &RemediationPlatform::Linux);
        assert_eq!(linux[0].program, "iptables");

        let mac = platform_commands(&action, &RemediationPlatform::MacOs);
        assert_eq!(mac[0].program, "pfctl");

        let win = platform_commands(&action, &RemediationPlatform::Windows);
        assert_eq!(win[0].program, "netsh");
    }

    #[test]
    fn disable_account_macos() {
        let cmds = platform_commands(
            &RemediationAction::DisableAccount {
                username: "attacker".into(),
            },
            &RemediationPlatform::MacOs,
        );
        assert_eq!(cmds[0].program, "dscl");
    }

    #[test]
    fn remove_systemd_persistence() {
        let cmds = platform_commands(
            &RemediationAction::RemovePersistence {
                mechanism: PersistenceMechanism::SystemdUnit {
                    name: "evil.service".into(),
                },
            },
            &RemediationPlatform::Linux,
        );
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].program, "systemctl");
    }

    #[test]
    fn remove_launch_item_macos() {
        let cmds = platform_commands(
            &RemediationAction::RemovePersistence {
                mechanism: PersistenceMechanism::LaunchItem {
                    path: "/Library/LaunchDaemons/com.evil.plist".into(),
                    item_type: LaunchItemType::Daemon,
                },
            },
            &RemediationPlatform::MacOs,
        );
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0].program, "launchctl");
    }

    #[test]
    fn needs_approval_check() {
        let engine = RemediationEngine::new();
        assert!(engine.needs_approval(&RemediationAction::DisableAccount {
            username: "bob".into(),
        }));
        assert!(!engine.needs_approval(&RemediationAction::FlushDns));
    }

    #[test]
    fn plan_includes_prerequisites() {
        let engine = RemediationEngine::new();
        let plan = engine.plan(
            &RemediationAction::KillProcess {
                pid: 42,
                name: "evil".into(),
            },
            &RemediationPlatform::Linux,
        );
        assert!(!plan.prerequisites.is_empty());
        assert!(!plan.needs_approval);
    }

    #[test]
    fn snapshot_and_result_tracking() {
        let mut engine = RemediationEngine::new();
        let sid = engine.record_snapshot(
            RemediationAction::FlushDns,
            RemediationPlatform::Linux,
            "host1",
            vec![],
            HashMap::new(),
            1000,
        );
        assert!(engine.get_snapshot(&sid).is_some());

        engine.record_result(RemediationResult {
            action: RemediationAction::FlushDns,
            status: RemediationStatus::Success,
            commands_run: vec![],
            snapshot_id: Some(sid),
            output: None,
            error: None,
            duration_ms: 50,
        });
        let stats = engine.stats();
        assert_eq!(stats.succeeded, 1);
    }

    #[test]
    fn sanitize_filename_strips_slashes() {
        assert_eq!(sanitize_filename("/etc/passwd"), "etc_passwd");
        assert_eq!(sanitize_filename("C:\\Windows\\file.exe"), "C:_Windows_file.exe");
    }
}
