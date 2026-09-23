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
| ETW (Event Tracing for Windows) | Real-time process start/stop, image load, file create/write/delete/rename, TCP/UDP connect/accept | Enabled by default, requires an elevated (Administrator) process — see below |
| PowerShell ScriptBlock logging (via ETW, event 4104) | Deobfuscated script text | Enabled by default alongside ETW |
| AMSI (via ETW, `Microsoft-Antimalware-Scan-Interface`) | Scan verdicts from whichever AMSI provider is installed (typically Defender) | Enabled by default alongside ETW; see "AMSI: what this agent does and does not do" below |
| Sysmon (if installed) | Detailed process, file, registry | Install Sysmon with SE config |
| WMI / PowerShell / `reg.exe` / `netstat` polling | Process/registry/service/network snapshots | Automatic fallback when ETW can't be started (see below); always available otherwise |
| Windows Event Log | Security log, auth failures | Default audit policy sufficient |

### Real-time ETW consumer

As of this change, the agent ships a real-time ETW consumer (`src/kernel_windows/`, built on the
[`ferrisetw`](https://crates.io/crates/ferrisetw) crate) that subscribes directly to the kernel
manifest providers below — this replaces the previous WMI-only "has_etw: bool" flag that never
actually opened an ETW session:

- `Microsoft-Windows-Kernel-Process` — process start/stop, image load
- `Microsoft-Windows-Kernel-File` — file create/write/delete/rename
- `Microsoft-Windows-Kernel-Network` — TCP/UDP connect/accept
- `Microsoft-Windows-DNS-Client` — query completion
- `Microsoft-Windows-PowerShell` — ScriptBlock logging (event ID 4104)
- `Microsoft-Antimalware-Scan-Interface` — AMSI scan verdicts (see below)

**This requires the agent process to be elevated (a member of `Administrators`).** The default
Windows service install (`sc.exe create ... start= auto`, running as `LocalSystem`) already
satisfies this. When the agent is *not* elevated — for example when run interactively as a
non-admin user for testing — it automatically falls back to the pre-existing WMI/PowerShell/
`reg.exe`/`netstat` polling collector in `collector_windows.rs`, and logs exactly why. Run
`wardex doctor` (or check the `windows_telemetry` block of `wardex doctor --json`) to see which
backend is active and the reason:

```powershell
wardex.exe doctor
# ...
#   [OK  ] ✓  Kernel telemetry (Windows ETW)
#          backend=EtwWindows (process token is elevated; a real-time ETW session against
#          the kernel process/file/network providers can be opened); elevated=true; AMSI ETW
#          consumer active=true; AMSI provider (COM DLL) implemented=false
```

Some of the numeric ETW event IDs used to distinguish, e.g., a file *write* from a file *delete*
within `Microsoft-Windows-Kernel-File`, are not published in a single stable Microsoft reference
and have shifted across Windows releases in community documentation. The consumer is defensive
about this — an unrecognized event ID, or a field that fails to parse, is silently skipped rather
than mis-classified — but if you rely on this in production, validate the exact IDs against a
live capture on your target Windows builds (e.g. `wevtutil gp Microsoft-Windows-Kernel-File
/ge /gm`) before trusting file-operation classification end to end. Process start/stop, network
connect, DNS, and PowerShell ScriptBlock logging use well-documented, stable event IDs and are
higher-confidence.

### AMSI: what this agent does and does not do

Implementing an actual **AMSI provider** — a registered `IAntimalwareProvider` COM DLL that every
AMSI-consuming process (PowerShell, WSH, Office macros, etc.) calls into on every scan — requires
a system-wide COM registration step, administrative rights well beyond a monitoring agent's normal
privilege boundary, and cannot be verified without a live, log-on-capable Windows host. **This
agent does not implement an AMSI provider.**

Instead, the ETW consumer above subscribes to the `Microsoft-Antimalware-Scan-Interface` ETW
provider, which reports scan results *from whichever real AMSI provider is already installed*
(normally Windows Defender). This gives visibility into AMSI verdicts (clean / detected / blocked
by admin) without installing anything — but it depends on a real AMSI provider being present and
Windows Defender (or another such provider) enabled; a host with all AMSI providers disabled
produces no AMSI ETW telemetry either way, same as before this change.

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

If AMSI integration conflicts with existing security tools, disable the AMSI backend (there is no separate
PowerShell-specific toggle; `amsi_enabled` covers script-content inspection):
```toml
[collectors]
amsi_enabled = false
```

## Uninstallation

```powershell
sc.exe stop WardexAgent
sc.exe delete WardexAgent
Remove-Item -Recurse "C:\Program Files\Wardex"
Remove-Item -Recurse "C:\ProgramData\Wardex"
```
