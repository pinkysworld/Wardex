# macOS Agent Runbook

## Prerequisites

- macOS 12 (Monterey) or later
- Administrator account
- Network access to SentinelEdge server (default port 9090)
- Full Disk Access (FDA) TCC approval for complete telemetry

## Deployment

### 1. Download Agent Binary

```bash
curl -o /tmp/sentineledge-agent \
  "https://<server>:9090/api/updates/download/sentineledge-agent-macos-universal"
chmod +x /tmp/sentineledge-agent
```

### 2. Code Signing Verification

The agent binary must be signed and notarized for Gatekeeper:

```bash
# Verify code signature
codesign -dvvv /tmp/sentineledge-agent
# Verify notarization
spctl --assess --type execute /tmp/sentineledge-agent
```

### 3. Enroll Agent

```bash
sudo /tmp/sentineledge-agent enroll \
  --server https://<server>:9090 \
  --token <enrollment-token> \
  --hostname $(hostname -s) \
  --platform macos
```

### 4. Install as LaunchDaemon

```bash
sudo cp /tmp/sentineledge-agent /usr/local/bin/
sudo mkdir -p /Library/Application\ Support/SentinelEdge

cat << 'EOF' | sudo tee /Library/LaunchDaemons/com.wardex.sentineledge-agent.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.wardex.sentineledge-agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/sentineledge-agent</string>
        <string>--run</string>
        <string>--config</string>
        <string>/Library/Application Support/SentinelEdge/config.toml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/Library/Logs/SentinelEdge/agent.log</string>
    <key>StandardErrorPath</key>
    <string>/Library/Logs/SentinelEdge/agent-error.log</string>
</dict>
</plist>
EOF

sudo launchctl load /Library/LaunchDaemons/com.wardex.sentineledge-agent.plist
```

## TCC (Transparency, Consent, and Control)

### Full Disk Access

The agent requires FDA for complete telemetry. Deploy via MDM profile or manually:

**Manual**: System Settings → Privacy & Security → Full Disk Access → Add `/usr/local/bin/sentineledge-agent`

**MDM (Configuration Profile)**:
```xml
<key>Services</key>
<dict>
    <key>SystemPolicyAllFiles</key>
    <array>
        <dict>
            <key>Identifier</key>
            <string>com.wardex.sentineledge-agent</string>
            <key>IdentifierType</key>
            <string>bundleID</string>
            <key>CodeRequirement</key>
            <string>identifier "com.wardex.sentineledge-agent" and anchor apple generic</string>
            <key>Allowed</key>
            <true/>
        </dict>
    </array>
</dict>
```

## Telemetry Sources

| Source | Data Collected | Requirements |
|--------|---------------|-------------|
| `ps` command | Process list with code signing | Always available |
| `lsof` / `netstat` | Network connections | Always available |
| `mount` | External storage mounts | Always available |
| `last` | Login history | Always available |
| LaunchAgent/Daemon plists | Persistence items | FDA recommended |
| Endpoint Security (ES) | Process, file, network events | System Extension + FDA |
| Unified Logging | System events | Always available |

## Persistence Monitoring

The agent monitors these persistence locations:

- `/Library/LaunchDaemons/` — System-wide daemons
- `/Library/LaunchAgents/` — System-wide agents
- `~/Library/LaunchAgents/` — Per-user agents
- `/Library/StartupItems/` — Legacy startup items
- Login Items (via `osascript`)
- Cron jobs (`/var/at/tabs/`, `/etc/crontab`)

## SIP (System Integrity Protection)

Check SIP status:
```bash
csrutil status
```

The agent operates with SIP enabled. If SIP is disabled, this is flagged as a security finding.

## Gatekeeper

```bash
# Check status
spctl --status
# Agent reports Gatekeeper-disabled as a risk indicator
```

## Version-Specific Notes

| macOS Version | Notes |
|--------------|-------|
| 12 (Monterey) | Full support. Endpoint Security framework available. |
| 13 (Ventura) | Lockdown Mode detection supported. |
| 14 (Sonoma) | Enhanced privacy controls. FDA approval critical. |
| 15 (Sequoia) | Latest supported. New security features auto-detected. |

## Troubleshooting

### Agent Not Running

```bash
# Check LaunchDaemon status
sudo launchctl list | grep sentineledge
# Try manual start
sudo launchctl kickstart system/com.wardex.sentineledge-agent
# View logs
log show --predicate 'processImagePath contains "sentineledge"' --last 1h
```

### TCC Permissions Missing

```bash
# Check current TCC database (requires FDA or SIP disabled)
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service, client FROM access WHERE client LIKE '%sentineledge%';"
```

### Network Monitoring Incomplete

If `lsof` returns partial results:
```bash
# Verify root execution
whoami  # should be root
# Check for SIP restrictions on lsof
ls -la $(which lsof)
```

## Uninstallation

```bash
sudo launchctl unload /Library/LaunchDaemons/com.wardex.sentineledge-agent.plist
sudo rm /Library/LaunchDaemons/com.wardex.sentineledge-agent.plist
sudo rm /usr/local/bin/sentineledge-agent
sudo rm -rf "/Library/Application Support/SentinelEdge"
sudo rm -rf /Library/Logs/SentinelEdge
```
