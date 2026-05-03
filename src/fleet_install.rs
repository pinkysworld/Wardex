use std::io::{ErrorKind, Write};
use std::process::{Command, Stdio};

use base64::Engine;
use serde::{Deserialize, Serialize};

const DEFAULT_INSTALL_TTL_SECS: u64 = 24 * 60 * 60;
const DEFAULT_SSH_PORT: u16 = 22;
const DEFAULT_WINRM_PORT: u16 = 5985;
const DEFAULT_WINRM_TLS_PORT: u16 = 5986;
const MAX_OUTPUT_EXCERPT_CHARS: usize = 4_000;

fn default_linux_platform() -> String {
    "linux".to_string()
}

fn default_windows_platform() -> String {
    "windows".to_string()
}

fn default_ssh_port() -> u16 {
    DEFAULT_SSH_PORT
}

fn default_accept_new_host_key() -> bool {
    true
}

fn default_use_sudo() -> bool {
    true
}

fn default_winrm_port() -> u16 {
    DEFAULT_WINRM_PORT
}

fn default_winrm_use_tls() -> bool {
    false
}

fn default_winrm_skip_cert_check() -> bool {
    false
}

fn normalized_platform_name(value: &str) -> &'static str {
    let value = value.trim().to_ascii_lowercase();
    if value.contains("darwin") || value.contains("mac") {
        "macos"
    } else if value.contains("win") {
        "windows"
    } else {
        "linux"
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshInstallRequest {
    pub hostname: String,
    pub address: String,
    #[serde(default = "default_linux_platform")]
    pub platform: String,
    pub manager_url: String,
    pub ssh_user: String,
    #[serde(default = "default_ssh_port")]
    pub ssh_port: u16,
    #[serde(default)]
    pub ssh_identity_file: Option<String>,
    #[serde(default = "default_accept_new_host_key")]
    pub ssh_accept_new_host_key: bool,
    #[serde(default = "default_use_sudo")]
    pub use_sudo: bool,
    #[serde(default)]
    pub ttl_secs: Option<u64>,
}

impl SshInstallRequest {
    pub fn normalized_platform(&self) -> &'static str {
        normalized_platform_name(&self.platform)
    }

    pub fn effective_ttl_secs(&self) -> u64 {
        self.ttl_secs.unwrap_or(DEFAULT_INSTALL_TTL_SECS).max(60)
    }

    pub fn validated_identity_file(&self) -> Option<String> {
        self.ssh_identity_file
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.hostname.trim().is_empty() {
            return Err("hostname is required".into());
        }
        if self.address.trim().is_empty() {
            return Err("address is required".into());
        }
        if self.manager_url.trim().is_empty() {
            return Err("manager_url is required".into());
        }
        if self.ssh_user.trim().is_empty() {
            return Err("ssh_user is required".into());
        }
        if self.ssh_port == 0 {
            return Err("ssh_port must be greater than zero".into());
        }
        if !matches!(self.normalized_platform(), "linux" | "macos") {
            return Err("remote SSH install currently supports Linux and macOS only".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WinRmInstallRequest {
    pub hostname: String,
    pub address: String,
    #[serde(default = "default_windows_platform")]
    pub platform: String,
    pub manager_url: String,
    pub winrm_username: String,
    pub winrm_password: String,
    #[serde(default = "default_winrm_port")]
    pub winrm_port: u16,
    #[serde(default = "default_winrm_use_tls")]
    pub winrm_use_tls: bool,
    #[serde(default = "default_winrm_skip_cert_check")]
    pub winrm_skip_cert_check: bool,
    #[serde(default)]
    pub ttl_secs: Option<u64>,
}

impl WinRmInstallRequest {
    pub fn normalized_platform(&self) -> &'static str {
        normalized_platform_name(&self.platform)
    }

    pub fn effective_ttl_secs(&self) -> u64 {
        self.ttl_secs.unwrap_or(DEFAULT_INSTALL_TTL_SECS).max(60)
    }

    pub fn effective_port(&self) -> u16 {
        if self.winrm_use_tls && self.winrm_port == DEFAULT_WINRM_PORT {
            DEFAULT_WINRM_TLS_PORT
        } else {
            self.winrm_port
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.hostname.trim().is_empty() {
            return Err("hostname is required".into());
        }
        if self.address.trim().is_empty() {
            return Err("address is required".into());
        }
        if self.manager_url.trim().is_empty() {
            return Err("manager_url is required".into());
        }
        if self.winrm_username.trim().is_empty() {
            return Err("winrm_username is required".into());
        }
        if self.winrm_password.is_empty() {
            return Err("winrm_password is required".into());
        }
        if self.effective_port() == 0 {
            return Err("winrm_port must be greater than zero".into());
        }
        if self.normalized_platform() != "windows" {
            return Err("remote WinRM install currently supports Windows only".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteInstallRecord {
    pub id: String,
    pub transport: String,
    pub hostname: String,
    pub address: String,
    pub platform: String,
    pub manager_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    pub ssh_user: String,
    pub ssh_port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_identity_file: Option<String>,
    pub ssh_accept_new_host_key: bool,
    pub use_sudo: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub winrm_username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub winrm_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub winrm_use_tls: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub winrm_skip_cert_check: Option<bool>,
    pub actor: String,
    pub status: String,
    pub started_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_heartbeat_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_excerpt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteInstallExecution {
    pub exit_code: Option<i32>,
    pub output_excerpt: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshCommandSpec {
    pub args: Vec<String>,
    pub script: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PowerShellCommandSpec {
    pub args: Vec<String>,
    pub script: String,
}

fn sh_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn toml_quote(value: &str) -> String {
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
    )
}

fn powershell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn install_artifact(platform: &str) -> (&'static str, &'static str) {
    match platform {
        "macos" => (
            "wardex-agent-macos-universal",
            "/usr/local/bin/wardex-agent",
        ),
        _ => ("wardex-agent-linux-amd64", "/usr/local/bin/wardex-agent"),
    }
}

fn sudo_prefix(request: &SshInstallRequest) -> &'static str {
    if request.use_sudo { "sudo -n " } else { "" }
}

fn combine_output(stdout: &[u8], stderr: &[u8]) -> Option<String> {
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(stdout),
        String::from_utf8_lossy(stderr)
    );
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(truncate_output(trimmed))
    }
}

fn truncate_output(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= MAX_OUTPUT_EXCERPT_CHARS {
        return text.to_string();
    }
    let head_len = MAX_OUTPUT_EXCERPT_CHARS / 2;
    let tail_len = MAX_OUTPUT_EXCERPT_CHARS - head_len;
    let head: String = chars[..head_len].iter().collect();
    let tail: String = chars[chars.len() - tail_len..].iter().collect();
    format!("{head}\n... output truncated ...\n{tail}")
}

pub fn build_remote_install_script(request: &SshInstallRequest, enrollment_token: &str) -> String {
    let platform = request.normalized_platform();
    let (artifact_name, install_path) = install_artifact(platform);
    let manager_url = request.manager_url.trim_end_matches('/');
    let download_url = format!("{manager_url}/api/updates/download/{artifact_name}");
    let sudo = sudo_prefix(request);

    if platform == "macos" {
        return format!(
            "set -eu\n\
curl -fsSL -o /tmp/wardex-agent {download_url}\n\
chmod +x /tmp/wardex-agent\n\
{sudo}install -m 755 /tmp/wardex-agent {install_path}\n\
{sudo}mkdir -p '/Library/Application Support/Wardex' /Library/Logs/Wardex\n\
cat <<'EOF' | {sudo}tee '/Library/Application Support/Wardex/agent.toml' >/dev/null\n\
[agent]\n\
server_url = {server_url}\n\
enrollment_token = {token}\n\
EOF\n\
cat <<'EOF' | {sudo}tee /Library/LaunchDaemons/com.wardex.agent.plist >/dev/null\n\
<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n\
<dict>\n\
  <key>Label</key>\n\
  <string>com.wardex.agent</string>\n\
  <key>ProgramArguments</key>\n\
  <array>\n\
    <string>{install_path_raw}</string>\n\
    <string>agent</string>\n\
  </array>\n\
  <key>EnvironmentVariables</key>\n\
  <dict>\n\
    <key>WARDEX_CONFIG_PATH</key>\n\
    <string>/Library/Application Support/Wardex/agent.toml</string>\n\
  </dict>\n\
  <key>RunAtLoad</key>\n\
  <true/>\n\
  <key>KeepAlive</key>\n\
  <true/>\n\
  <key>StandardOutPath</key>\n\
  <string>/Library/Logs/Wardex/agent.log</string>\n\
  <key>StandardErrorPath</key>\n\
  <string>/Library/Logs/Wardex/agent-error.log</string>\n\
</dict>\n\
</plist>\n\
EOF\n\
{sudo}launchctl unload /Library/LaunchDaemons/com.wardex.agent.plist >/dev/null 2>&1 || true\n\
{sudo}launchctl load /Library/LaunchDaemons/com.wardex.agent.plist\n",
            download_url = sh_quote(&download_url),
            sudo = sudo,
            install_path = sh_quote(install_path),
            install_path_raw = install_path,
            server_url = toml_quote(manager_url),
            token = toml_quote(enrollment_token),
        );
    }

    format!(
        "set -eu\n\
curl -fsSL -o /tmp/wardex-agent {download_url}\n\
chmod +x /tmp/wardex-agent\n\
{sudo}install -m 755 /tmp/wardex-agent {install_path}\n\
{sudo}mkdir -p /etc/wardex /var/lib/wardex\n\
cat <<'EOF' | {sudo}tee /etc/wardex/agent.toml >/dev/null\n\
[agent]\n\
server_url = {server_url}\n\
enrollment_token = {token}\n\
EOF\n\
cat <<'EOF' | {sudo}tee /etc/systemd/system/wardex-agent.service >/dev/null\n\
[Unit]\n\
Description=Wardex XDR Agent\n\
After=network.target auditd.service\n\
\n\
[Service]\n\
Type=simple\n\
Environment=WARDEX_CONFIG_PATH=/etc/wardex/agent.toml\n\
ExecStart={install_path_raw} agent\n\
Restart=always\n\
RestartSec=10\n\
User=root\n\
LimitNOFILE=65536\n\
\n\
[Install]\n\
WantedBy=multi-user.target\n\
EOF\n\
{sudo}systemctl daemon-reload\n\
{sudo}systemctl enable --now wardex-agent\n",
        download_url = sh_quote(&download_url),
        sudo = sudo,
        install_path = sh_quote(install_path),
        install_path_raw = install_path,
        server_url = toml_quote(manager_url),
        token = toml_quote(enrollment_token),
    )
}

pub fn build_ssh_command_spec(request: &SshInstallRequest, script: &str) -> SshCommandSpec {
    let mut args = vec![
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-o".to_string(),
        "ConnectTimeout=20".to_string(),
        "-o".to_string(),
        format!(
            "StrictHostKeyChecking={}",
            if request.ssh_accept_new_host_key {
                "accept-new"
            } else {
                "yes"
            }
        ),
        "-p".to_string(),
        request.ssh_port.to_string(),
    ];
    if let Some(identity_file) = request.validated_identity_file() {
        args.push("-i".to_string());
        args.push(identity_file);
    }
    args.push(format!(
        "{}@{}",
        request.ssh_user.trim(),
        request.address.trim()
    ));
    args.push("sh".to_string());
    args.push("-s".to_string());
    args.push("--".to_string());
    SshCommandSpec {
        args,
        script: script.to_string(),
    }
}

pub fn build_remote_windows_install_script(
    request: &WinRmInstallRequest,
    enrollment_token: &str,
) -> String {
    let manager_url = request.manager_url.trim_end_matches('/');
    let download_url = format!("{manager_url}/api/updates/download/wardex-agent-windows.exe");
    let install_path = r"C:\Program Files\Wardex\wardex-agent.exe";
    let config_path = r"C:\ProgramData\Wardex\agent.toml";
    let service_bin_path = format!(r#""{install_path}" agent --config "{config_path}""#);

    format!(
        "$ErrorActionPreference = 'Stop'\n\
$artifactPath = Join-Path $env:TEMP 'wardex-agent.exe'\n\
$installDir = 'C:\\Program Files\\Wardex'\n\
$configDir = 'C:\\ProgramData\\Wardex'\n\
$configPath = '{config_path}'\n\
Invoke-WebRequest -Uri {download_url} -OutFile $artifactPath\n\
New-Item -ItemType Directory -Force -Path $installDir, $configDir | Out-Null\n\
Copy-Item $artifactPath '{install_path}' -Force\n\
@'\n\
[agent]\n\
server_url = {server_url}\n\
enrollment_token = {token}\n\
'@ | Set-Content -Path $configPath -Encoding UTF8\n\
if (Get-Service -Name 'WardexAgent' -ErrorAction SilentlyContinue) {{\n\
  Stop-Service -Name 'WardexAgent' -Force -ErrorAction SilentlyContinue\n\
  sc.exe delete WardexAgent | Out-Null\n\
  Start-Sleep -Seconds 2\n\
}}\n\
New-Service -Name 'WardexAgent' -BinaryPathName {service_bin_path} -DisplayName 'Wardex XDR Agent' -StartupType Automatic\n\
Start-Service -Name 'WardexAgent'\n",
        config_path = config_path,
        download_url = powershell_quote(&download_url),
        install_path = install_path,
        server_url = toml_quote(manager_url),
        token = toml_quote(enrollment_token),
        service_bin_path = powershell_quote(&service_bin_path),
    )
}

pub fn build_winrm_command_spec(
    request: &WinRmInstallRequest,
    remote_script: &str,
) -> PowerShellCommandSpec {
    let scheme = if request.winrm_use_tls {
        "https"
    } else {
        "http"
    };
    let connection_uri = format!(
        "{scheme}://{}:{}/wsman",
        request.address.trim(),
        request.effective_port()
    );
    let remote_script_b64 = base64::engine::general_purpose::STANDARD.encode(remote_script);
    let session_option = if request.winrm_use_tls && request.winrm_skip_cert_check {
        "$invokeParams['SessionOption'] = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck\n"
    } else {
        ""
    };

    let script = format!(
        "$ErrorActionPreference = 'Stop'\n\
if (($IsLinux -or $IsMacOS) -and -not (Get-Module -ListAvailable -Name PSWSMan)) {{\n\
  throw 'transport unavailable: WinRM transport requires PowerShell WSMan support on the manager host. Install the PSWSMan module first.'\n\
}}\n\
$password = ConvertTo-SecureString {password} -AsPlainText -Force\n\
$credential = [System.Management.Automation.PSCredential]::new({username}, $password)\n\
$remoteScript = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String({remote_script_b64}))\n\
$invokeParams = @{{\n\
  ConnectionUri = {connection_uri}\n\
  Credential = $credential\n\
  Authentication = 'Negotiate'\n\
  ScriptBlock = [ScriptBlock]::Create($remoteScript)\n\
  ErrorAction = 'Stop'\n\
}}\n\
{session_option}Invoke-Command @invokeParams\n",
        password = powershell_quote(request.winrm_password.trim()),
        username = powershell_quote(request.winrm_username.trim()),
        remote_script_b64 = powershell_quote(&remote_script_b64),
        connection_uri = powershell_quote(&connection_uri),
        session_option = session_option,
    );

    PowerShellCommandSpec {
        args: vec![
            "-NoLogo".to_string(),
            "-NoProfile".to_string(),
            "-NonInteractive".to_string(),
            "-Command".to_string(),
            "-".to_string(),
        ],
        script,
    }
}

pub fn execute_ssh_install(
    request: &SshInstallRequest,
    enrollment_token: &str,
) -> Result<RemoteInstallExecution, String> {
    let script = build_remote_install_script(request, enrollment_token);
    let spec = build_ssh_command_spec(request, &script);
    let mut child = Command::new("ssh")
        .args(&spec.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to start ssh transport: {e}"))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "failed to open ssh stdin".to_string())?;
    stdin
        .write_all(spec.script.as_bytes())
        .map_err(|e| format!("failed to send install script over ssh: {e}"))?;
    drop(stdin);

    let output = child
        .wait_with_output()
        .map_err(|e| format!("failed to read ssh transport output: {e}"))?;
    let output_excerpt = combine_output(&output.stdout, &output.stderr);
    if output.status.success() {
        Ok(RemoteInstallExecution {
            exit_code: output.status.code(),
            output_excerpt,
        })
    } else {
        let suffix = output_excerpt
            .clone()
            .map(|text| format!(": {text}"))
            .unwrap_or_default();
        Err(format!(
            "ssh transport exited with code {}{suffix}",
            output
                .status
                .code()
                .map(|code| code.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        ))
    }
}

pub fn execute_winrm_install(
    request: &WinRmInstallRequest,
    enrollment_token: &str,
) -> Result<RemoteInstallExecution, String> {
    let remote_script = build_remote_windows_install_script(request, enrollment_token);
    let spec = build_winrm_command_spec(request, &remote_script);
    let mut child = Command::new("pwsh")
        .args(&spec.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            if e.kind() == ErrorKind::NotFound {
                "transport unavailable: pwsh is required on the manager host for WinRM remote install"
                    .to_string()
            } else {
                format!("failed to start WinRM transport: {e}")
            }
        })?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "failed to open pwsh stdin".to_string())?;
    stdin
        .write_all(spec.script.as_bytes())
        .map_err(|e| format!("failed to send WinRM script to pwsh: {e}"))?;
    drop(stdin);

    let output = child
        .wait_with_output()
        .map_err(|e| format!("failed to read WinRM transport output: {e}"))?;
    let output_excerpt = combine_output(&output.stdout, &output.stderr);
    if output.status.success() {
        Ok(RemoteInstallExecution {
            exit_code: output.status.code(),
            output_excerpt,
        })
    } else {
        let suffix = output_excerpt
            .clone()
            .map(|text| format!(": {text}"))
            .unwrap_or_default();
        Err(format!(
            "WinRM transport exited with code {}{suffix}",
            output
                .status
                .code()
                .map(|code| code.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request(platform: &str) -> SshInstallRequest {
        SshInstallRequest {
            hostname: "edge-02".to_string(),
            address: "10.0.4.12".to_string(),
            platform: platform.to_string(),
            manager_url: "https://manager.example.com:9090".to_string(),
            ssh_user: "root".to_string(),
            ssh_port: 2222,
            ssh_identity_file: Some("/tmp/wardex-test-key".to_string()),
            ssh_accept_new_host_key: true,
            use_sudo: true,
            ttl_secs: Some(3600),
        }
    }

    fn sample_winrm_request(platform: &str) -> WinRmInstallRequest {
        WinRmInstallRequest {
            hostname: "win-01".to_string(),
            address: "10.0.4.20".to_string(),
            platform: platform.to_string(),
            manager_url: "https://manager.example.com:9090".to_string(),
            winrm_username: "Administrator".to_string(),
            winrm_password: "Sup3rSecret!".to_string(),
            winrm_port: 5985,
            winrm_use_tls: false,
            winrm_skip_cert_check: false,
            ttl_secs: Some(3600),
        }
    }

    #[test]
    fn linux_script_uses_agent_service_and_config_path() {
        let script = build_remote_install_script(&sample_request("linux"), "token-123");
        assert!(script.contains("Environment=WARDEX_CONFIG_PATH=/etc/wardex/agent.toml"));
        assert!(script.contains("ExecStart=/usr/local/bin/wardex-agent agent"));
        assert!(script.contains("enrollment_token = \"token-123\""));
        assert!(!script.contains(" enroll --server "));
        assert!(!script.contains("--run --config"));
    }

    #[test]
    fn macos_script_uses_launchd_environment_variable() {
        let script = build_remote_install_script(&sample_request("macos"), "token-123");
        assert!(script.contains("<key>WARDEX_CONFIG_PATH</key>"));
        assert!(script.contains("<string>/usr/local/bin/wardex-agent</string>"));
        assert!(script.contains("<string>agent</string>"));
    }

    #[test]
    fn build_ssh_command_spec_includes_transport_options() {
        let request = sample_request("linux");
        let spec = build_ssh_command_spec(&request, "echo ok");
        assert!(spec.args.contains(&"BatchMode=yes".to_string()));
        assert!(spec.args.contains(&"ConnectTimeout=20".to_string()));
        assert!(
            spec.args
                .contains(&"StrictHostKeyChecking=accept-new".to_string())
        );
        assert!(spec.args.contains(&"-i".to_string()));
        assert!(spec.args.contains(&"/tmp/wardex-test-key".to_string()));
        assert!(spec.args.contains(&"root@10.0.4.12".to_string()));
    }

    #[test]
    fn validate_rejects_windows_remote_install() {
        let request = sample_request("windows");
        assert!(request.validate().is_err());
    }

    #[test]
    fn windows_script_uses_agent_config_and_service_args() {
        let script =
            build_remote_windows_install_script(&sample_winrm_request("windows"), "token-123");
        assert!(script.contains(r#"server_url = "https://manager.example.com:9090""#));
        assert!(script.contains(r#"enrollment_token = "token-123""#));
        assert!(script.contains(r#"agent --config "C:\ProgramData\Wardex\agent.toml""#));
        assert!(!script.contains(" enroll --server "));
        assert!(!script.contains("--run"));
    }

    #[test]
    fn build_winrm_command_spec_targets_wsman_uri() {
        let request = sample_winrm_request("windows");
        let spec = build_winrm_command_spec(&request, "Write-Host ok");
        assert_eq!(
            spec.args,
            vec!["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "-"]
        );
        assert!(spec.script.contains("PSWSMan"));
        assert!(spec.script.contains("http://10.0.4.20:5985/wsman"));
        assert!(spec.script.contains("FromBase64String"));
    }

    #[test]
    fn winrm_validate_rejects_non_windows_platform() {
        let request = sample_winrm_request("linux");
        assert!(request.validate().is_err());
    }
}
