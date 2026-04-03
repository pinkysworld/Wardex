//! Live response module for interactive agent sessions.
//!
//! Provides a controlled command execution framework with per-platform
//! allowed-command whitelists, audit logging, session timeout, and
//! file retrieval capabilities.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Session management ──────────────────────────────────────────

/// Platform identifier for command whitelisting.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum LiveResponsePlatform {
    Linux,
    MacOs,
    Windows,
}

/// A live response session tied to a specific agent/host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveResponseSession {
    pub session_id: String,
    pub agent_id: String,
    pub hostname: String,
    pub platform: LiveResponsePlatform,
    pub operator: String,
    pub status: SessionStatus,
    pub started_at: u64,
    pub last_activity: u64,
    pub timeout_secs: u64,
    pub commands: Vec<CommandRecord>,
    pub retrieved_files: Vec<RetrievedFile>,
}

/// Session lifecycle status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionStatus {
    Active,
    TimedOut,
    ClosedByOperator,
    ClosedByPolicy,
    Error,
}

/// Record of a command executed in a live response session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandRecord {
    pub command_id: String,
    pub command: String,
    pub args: Vec<String>,
    pub status: CommandStatus,
    pub output: Option<String>,
    pub error: Option<String>,
    pub submitted_at: u64,
    pub completed_at: Option<u64>,
}

/// Command execution status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CommandStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Denied,
    TimedOut,
}

/// A file retrieved from a remote agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetrievedFile {
    pub remote_path: String,
    pub local_path: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub retrieved_at: u64,
}

// ── Command whitelists ──────────────────────────────────────────

/// Per-platform allowed commands for live response.
pub fn default_allowed_commands(platform: &LiveResponsePlatform) -> Vec<AllowedCommand> {
    match platform {
        LiveResponsePlatform::Linux => vec![
            AllowedCommand::new("ps", "List processes", &["-ef", "aux", "-eo"]),
            AllowedCommand::new("netstat", "Network connections", &["-tlnp", "-anp"]),
            AllowedCommand::new("ss", "Socket statistics", &["-tlnp", "-anp"]),
            AllowedCommand::new("ls", "List files", &["-la", "-lah", "-R"]),
            AllowedCommand::new("cat", "Read file contents", &[]),
            AllowedCommand::new("find", "Search files", &["-name", "-type", "-mtime"]),
            AllowedCommand::new("lsof", "Open files", &["-i", "-p"]),
            AllowedCommand::new("df", "Disk usage", &["-h"]),
            AllowedCommand::new("uptime", "System uptime", &[]),
            AllowedCommand::new("who", "Logged-in users", &[]),
            AllowedCommand::new("last", "Login history", &[]),
            AllowedCommand::new("journalctl", "System logs", &["--no-pager", "-n"]),
            AllowedCommand::new("sha256sum", "Hash file", &[]),
            AllowedCommand::new("md5sum", "Hash file (MD5)", &[]),
            AllowedCommand::new("stat", "File metadata", &[]),
            AllowedCommand::new("ip", "Network config", &["addr", "route", "link"]),
            AllowedCommand::new("systemctl", "Service status", &["status", "list-units"]),
        ],
        LiveResponsePlatform::MacOs => vec![
            AllowedCommand::new("ps", "List processes", &["-ef", "aux", "-eo"]),
            AllowedCommand::new("netstat", "Network connections", &["-an"]),
            AllowedCommand::new("lsof", "Open files", &["-i", "-p"]),
            AllowedCommand::new("ls", "List files", &["-la", "-lah"]),
            AllowedCommand::new("cat", "Read file contents", &[]),
            AllowedCommand::new("find", "Search files", &["-name", "-type", "-mtime"]),
            AllowedCommand::new("df", "Disk usage", &["-h"]),
            AllowedCommand::new("uptime", "System uptime", &[]),
            AllowedCommand::new("who", "Logged-in users", &[]),
            AllowedCommand::new("last", "Login history", &[]),
            AllowedCommand::new("log", "Unified log", &["show", "stream"]),
            AllowedCommand::new("shasum", "Hash file", &["-a", "256"]),
            AllowedCommand::new("stat", "File metadata", &[]),
            AllowedCommand::new("ifconfig", "Network config", &[]),
            AllowedCommand::new("launchctl", "Service status", &["list"]),
            AllowedCommand::new("csrutil", "SIP status", &["status"]),
            AllowedCommand::new("spctl", "Gatekeeper status", &["--status"]),
            AllowedCommand::new("codesign", "Signature check", &["-dvvv"]),
            AllowedCommand::new("profiles", "Config profiles", &["list"]),
            AllowedCommand::new("system_profiler", "System info", &["SPHardwareDataType"]),
        ],
        LiveResponsePlatform::Windows => vec![
            AllowedCommand::new("tasklist", "List processes", &["/v"]),
            AllowedCommand::new("netstat", "Network connections", &["-ano"]),
            AllowedCommand::new("dir", "List files", &["/a", "/s"]),
            AllowedCommand::new("type", "Read file contents", &[]),
            AllowedCommand::new("ipconfig", "Network config", &["/all"]),
            AllowedCommand::new("systeminfo", "System info", &[]),
            AllowedCommand::new("whoami", "Current user", &["/all"]),
            AllowedCommand::new("net", "Network info", &["session", "share", "user"]),
            AllowedCommand::new("sc", "Service control", &["query"]),
            AllowedCommand::new("wmic", "WMI queries", &["process", "service"]),
            AllowedCommand::new("certutil", "Hash file", &["-hashfile"]),
            AllowedCommand::new("schtasks", "Scheduled tasks", &["/query"]),
            AllowedCommand::new("reg", "Registry query", &["query"]),
            AllowedCommand::new("wevtutil", "Event logs", &["qe"]),
            AllowedCommand::new("Get-Process", "PS processes", &[]),
            AllowedCommand::new("Get-NetTCPConnection", "PS connections", &[]),
            AllowedCommand::new("Get-Service", "PS services", &[]),
        ],
    }
}

/// An allowed command and its description.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowedCommand {
    pub name: String,
    pub description: String,
    pub allowed_args: Vec<String>,
}

impl AllowedCommand {
    pub fn new(name: &str, desc: &str, args: &[&str]) -> Self {
        Self {
            name: name.into(),
            description: desc.into(),
            allowed_args: args.iter().map(|a| a.to_string()).collect(),
        }
    }
}

// ── Live response engine ────────────────────────────────────────

/// Engine managing live response sessions.
pub struct LiveResponseEngine {
    sessions: Vec<LiveResponseSession>,
    custom_allow_lists: HashMap<LiveResponsePlatform, Vec<AllowedCommand>>,
    default_timeout_secs: u64,
    next_session_id: u64,
    next_cmd_id: u64,
}

impl Default for LiveResponseEngine {
    fn default() -> Self {
        Self::new(1800) // 30 min default timeout
    }
}

impl LiveResponseEngine {
    pub fn new(default_timeout_secs: u64) -> Self {
        Self {
            sessions: Vec::new(),
            custom_allow_lists: HashMap::new(),
            default_timeout_secs,
            next_session_id: 1,
            next_cmd_id: 1,
        }
    }

    /// Override the allowed command list for a platform.
    pub fn set_allowed_commands(
        &mut self,
        platform: LiveResponsePlatform,
        commands: Vec<AllowedCommand>,
    ) {
        self.custom_allow_lists.insert(platform, commands);
    }

    /// Start a new live response session.
    pub fn open_session(
        &mut self,
        agent_id: &str,
        hostname: &str,
        platform: LiveResponsePlatform,
        operator: &str,
        now_ms: u64,
    ) -> String {
        let sid = format!("lr-{}", self.next_session_id);
        self.next_session_id += 1;

        self.sessions.push(LiveResponseSession {
            session_id: sid.clone(),
            agent_id: agent_id.into(),
            hostname: hostname.into(),
            platform,
            operator: operator.into(),
            status: SessionStatus::Active,
            started_at: now_ms,
            last_activity: now_ms,
            timeout_secs: self.default_timeout_secs,
            commands: Vec::new(),
            retrieved_files: Vec::new(),
        });

        sid
    }

    /// Submit a command to an active session. Returns Ok(command_id) or
    /// Err with denial reason.
    pub fn submit_command(
        &mut self,
        session_id: &str,
        command: &str,
        args: Vec<String>,
        now_ms: u64,
    ) -> Result<String, String> {
        let session = self
            .sessions
            .iter_mut()
            .find(|s| s.session_id == session_id)
            .ok_or_else(|| "Session not found".to_string())?;

        if session.status != SessionStatus::Active {
            return Err(format!("Session is {:?}", session.status));
        }

        // Check timeout
        let elapsed_secs = (now_ms.saturating_sub(session.last_activity)) / 1000;
        if elapsed_secs > session.timeout_secs {
            session.status = SessionStatus::TimedOut;
            return Err("Session timed out".to_string());
        }

        // Validate command is allowed
        let allowed = self
            .custom_allow_lists
            .get(&session.platform)
            .cloned()
            .unwrap_or_else(|| default_allowed_commands(&session.platform));

        if !allowed.iter().any(|a| a.name == command) {
            let cmd_id = format!("cmd-{}", self.next_cmd_id);
            self.next_cmd_id += 1;
            session.commands.push(CommandRecord {
                command_id: cmd_id.clone(),
                command: command.into(),
                args,
                status: CommandStatus::Denied,
                output: None,
                error: Some("Command not in allowlist".into()),
                submitted_at: now_ms,
                completed_at: Some(now_ms),
            });
            return Err(format!("Command '{command}' not in allowlist"));
        }

        let cmd_id = format!("cmd-{}", self.next_cmd_id);
        self.next_cmd_id += 1;

        session.commands.push(CommandRecord {
            command_id: cmd_id.clone(),
            command: command.into(),
            args,
            status: CommandStatus::Queued,
            output: None,
            error: None,
            submitted_at: now_ms,
            completed_at: None,
        });
        session.last_activity = now_ms;

        Ok(cmd_id)
    }

    /// Update a command's result (called when agent reports back).
    pub fn complete_command(
        &mut self,
        session_id: &str,
        command_id: &str,
        status: CommandStatus,
        output: Option<String>,
        error: Option<String>,
        now_ms: u64,
    ) -> bool {
        let session = match self.sessions.iter_mut().find(|s| s.session_id == session_id) {
            Some(s) => s,
            None => return false,
        };
        let cmd = match session
            .commands
            .iter_mut()
            .find(|c| c.command_id == command_id)
        {
            Some(c) => c,
            None => return false,
        };

        cmd.status = status;
        cmd.output = output;
        cmd.error = error;
        cmd.completed_at = Some(now_ms);
        session.last_activity = now_ms;
        true
    }

    /// Record a file retrieval from the agent.
    pub fn record_file_retrieval(
        &mut self,
        session_id: &str,
        remote_path: &str,
        local_path: &str,
        size_bytes: u64,
        sha256: &str,
        now_ms: u64,
    ) -> bool {
        let session = match self.sessions.iter_mut().find(|s| s.session_id == session_id) {
            Some(s) => s,
            None => return false,
        };

        session.retrieved_files.push(RetrievedFile {
            remote_path: remote_path.into(),
            local_path: local_path.into(),
            size_bytes,
            sha256: sha256.into(),
            retrieved_at: now_ms,
        });
        session.last_activity = now_ms;
        true
    }

    /// Close a session.
    pub fn close_session(&mut self, session_id: &str, reason: SessionStatus) -> bool {
        if let Some(s) = self.sessions.iter_mut().find(|s| s.session_id == session_id) {
            s.status = reason;
            true
        } else {
            false
        }
    }

    /// Check for timed-out sessions and mark them.
    pub fn check_timeouts(&mut self, now_ms: u64) -> Vec<String> {
        let mut timed_out = Vec::new();
        for s in &mut self.sessions {
            if s.status == SessionStatus::Active {
                let elapsed = (now_ms.saturating_sub(s.last_activity)) / 1000;
                if elapsed > s.timeout_secs {
                    s.status = SessionStatus::TimedOut;
                    timed_out.push(s.session_id.clone());
                }
            }
        }
        timed_out
    }

    /// Get a session by id.
    pub fn get_session(&self, session_id: &str) -> Option<&LiveResponseSession> {
        self.sessions.iter().find(|s| s.session_id == session_id)
    }

    /// List active sessions.
    pub fn active_sessions(&self) -> Vec<&LiveResponseSession> {
        self.sessions
            .iter()
            .filter(|s| s.status == SessionStatus::Active)
            .collect()
    }

    /// List all sessions.
    pub fn all_sessions(&self) -> &[LiveResponseSession] {
        &self.sessions
    }

    /// Audit log: all command records across all sessions.
    pub fn audit_log(&self) -> Vec<(&str, &CommandRecord)> {
        self.sessions
            .iter()
            .flat_map(|s| s.commands.iter().map(move |c| (s.session_id.as_str(), c)))
            .collect()
    }
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_and_run_command() {
        let mut engine = LiveResponseEngine::default();
        let sid = engine.open_session(
            "agent-1",
            "web-server",
            LiveResponsePlatform::Linux,
            "analyst@soc",
            1000,
        );
        let cmd_id = engine
            .submit_command(&sid, "ps", vec!["-ef".into()], 2000)
            .unwrap();
        assert!(engine
            .complete_command(
                &sid,
                &cmd_id,
                CommandStatus::Completed,
                Some("PID TTY ...".into()),
                None,
                3000,
            ));
        let session = engine.get_session(&sid).unwrap();
        assert_eq!(session.commands.len(), 1);
        assert_eq!(session.commands[0].status, CommandStatus::Completed);
    }

    #[test]
    fn denied_command_not_in_allowlist() {
        let mut engine = LiveResponseEngine::default();
        let sid = engine.open_session(
            "agent-1",
            "host",
            LiveResponsePlatform::Linux,
            "analyst",
            1000,
        );
        let result = engine.submit_command(&sid, "rm", vec!["-rf".into(), "/".into()], 2000);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not in allowlist"));
        // Denied command should still be in audit log
        let session = engine.get_session(&sid).unwrap();
        assert_eq!(session.commands[0].status, CommandStatus::Denied);
    }

    #[test]
    fn session_timeout() {
        let mut engine = LiveResponseEngine::new(60); // 60 sec timeout
        let sid = engine.open_session(
            "agent-1",
            "host",
            LiveResponsePlatform::MacOs,
            "analyst",
            1000,
        );
        // Try command 2 minutes later
        let result = engine.submit_command(&sid, "ps", vec![], 121_000);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("timed out"));
    }

    #[test]
    fn check_timeouts_marks_sessions() {
        let mut engine = LiveResponseEngine::new(30);
        let sid = engine.open_session(
            "agent-1",
            "host",
            LiveResponsePlatform::Windows,
            "analyst",
            1000,
        );
        let timed_out = engine.check_timeouts(50_000);
        assert_eq!(timed_out, vec![sid.clone()]);
        assert_eq!(
            engine.get_session(&sid).unwrap().status,
            SessionStatus::TimedOut
        );
    }

    #[test]
    fn file_retrieval_recorded() {
        let mut engine = LiveResponseEngine::default();
        let sid = engine.open_session(
            "agent-1",
            "host",
            LiveResponsePlatform::Linux,
            "analyst",
            1000,
        );
        assert!(engine.record_file_retrieval(
            &sid,
            "/etc/passwd",
            "/evidence/passwd",
            1024,
            "abc123",
            2000,
        ));
        let session = engine.get_session(&sid).unwrap();
        assert_eq!(session.retrieved_files.len(), 1);
        assert_eq!(session.retrieved_files[0].remote_path, "/etc/passwd");
    }

    #[test]
    fn close_session() {
        let mut engine = LiveResponseEngine::default();
        let sid = engine.open_session(
            "agent-1",
            "host",
            LiveResponsePlatform::Linux,
            "analyst",
            1000,
        );
        engine.close_session(&sid, SessionStatus::ClosedByOperator);
        assert_eq!(
            engine.get_session(&sid).unwrap().status,
            SessionStatus::ClosedByOperator
        );
        assert!(engine.active_sessions().is_empty());
    }

    #[test]
    fn audit_log_captures_all() {
        let mut engine = LiveResponseEngine::default();
        let sid = engine.open_session(
            "agent-1",
            "host",
            LiveResponsePlatform::Linux,
            "analyst",
            1000,
        );
        engine.submit_command(&sid, "ps", vec![], 2000).unwrap();
        engine.submit_command(&sid, "ls", vec!["-la".into()], 3000).unwrap();
        let _ = engine.submit_command(&sid, "rm", vec![], 4000); // denied
        assert_eq!(engine.audit_log().len(), 3);
    }

    #[test]
    fn macos_has_codesign() {
        let cmds = default_allowed_commands(&LiveResponsePlatform::MacOs);
        assert!(cmds.iter().any(|c| c.name == "codesign"));
    }

    #[test]
    fn windows_has_wevtutil() {
        let cmds = default_allowed_commands(&LiveResponsePlatform::Windows);
        assert!(cmds.iter().any(|c| c.name == "wevtutil"));
    }
}
