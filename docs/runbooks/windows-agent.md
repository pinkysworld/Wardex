# Windows Agent Runbook

## Prerequisites

- Windows 8.1+ or Windows Server 2016+
- Administrator privileges for installation
- Network access to the Wardex server (default port 9090)
- .NET Framework 4.7.2+ (for WMI collection)

## Deployment

### 1. Download Agent Binary

```powershell
Invoke-WebRequest -Uri "https://<server>:9090/api/updates/download/wardex-agent-windows.exe" `
  -OutFile "$env:TEMP\wardex-agent.exe"
```

### 2. Enroll Agent

```powershell
.\wardex-agent.exe enroll `
  --server https://<server>:9090 `
  --token <enrollment-token> `
  --hostname $env:COMPUTERNAME `
  --platform windows
```

### 3. Install as Service

```powershell
sc.exe create WardexAgent `
  binPath= "C:\Program Files\Wardex\wardex-agent.exe --run" `
  start= auto `
  DisplayName= "Wardex XDR Agent"
sc.exe start WardexAgent
```

## Telemetry Sources

| Source | Data Collected | Configuration |
|--------|---------------|---------------|
| ETW (Event Tracing for Windows) | Process creation, network, DNS | Enabled by default |
| Sysmon (if installed) | Detailed process, file, registry | Install Sysmon with SE config |
| WMI | Service enumeration, OS info | Requires WMI service running |
| AMSI | Script/PowerShell content | Windows 10+ only |
| Windows Event Log | Security log, auth failures | Default audit policy sufficient |

### Sysmon Configuration

For enhanced visibility, install Sysmon with the Wardex-optimized config:

```powershell
sysmon64.exe -accepteula -i wardex-sysmon.xml
```

Key Sysmon event IDs monitored:
- **1**: Process creation (with hashes)
- **3**: Network connections
- **7**: Image loaded (DLL)
- **10**: Process access (LSASS detection)
- **11**: File creation
- **13**: Registry value set
- **22**: DNS query

## Registry Monitoring

The agent monitors these persistence-relevant registry paths:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\SYSTEM\CurrentControlSet\Services`
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`
- `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`

## Troubleshooting

### Agent Not Sending Telemetry

1. Check service status:
   ```powershell
   Get-Service WardexAgent
   ```
2. Check agent logs:
   ```powershell
   Get-Content "C:\ProgramData\Wardex\agent.log" -Tail 50
   ```
3. Verify network connectivity:
   ```powershell
   Test-NetConnection -ComputerName <server> -Port 9090
   ```

### High CPU Usage

1. Check collection interval (default 10s, increase if needed):
   ```powershell
   # Edit config
   notepad "C:\ProgramData\Wardex\config.toml"
   # Set: collection_interval_secs = 30
   ```
2. Disable expensive collectors:
   ```toml
   [collectors]
   etw_enabled = true
   wmi_enabled = false  # Disable if causing high CPU
   registry_scan_interval_secs = 300
   ```

### PowerShell Script Block Logging Conflicts

If AMSI integration conflicts with existing security tools:
```toml
[collectors]
amsi_enabled = false
powershell_script_block_logging = false
```

## Uninstallation

```powershell
sc.exe stop WardexAgent
sc.exe delete WardexAgent
Remove-Item -Recurse "C:\Program Files\Wardex"
Remove-Item -Recurse "C:\ProgramData\Wardex"
```
