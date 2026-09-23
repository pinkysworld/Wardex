# macOS Agent Runbook

## Prerequisites

- macOS 12 (Monterey) or later
- Administrator account
- Network access to Wardex server (default port 9090)
- Full Disk Access (FDA) TCC approval for complete telemetry

## Deployment

### 1. Download Agent Binary

```bash
curl -o /tmp/wardex-agent \
  "https://<server>:9090/api/updates/download/wardex-agent-macos-universal"
chmod +x /tmp/wardex-agent
```

### 2. Code Signing Verification

The agent binary must be signed and notarized for Gatekeeper:

```bash
# Verify code signature
codesign --verify --strict --verbose=2 /tmp/wardex-agent
codesign -dvvv /tmp/wardex-agent
```

Confirm notarization from the release evidence or local `notarytool submit
--wait` output. `spctl --assess --type execute` is app-bundle oriented and is
not a reliable validation command for the standalone `wardex-agent` CLI.

### 3. Enroll Agent

```bash
sudo /tmp/wardex-agent enroll \
  --server https://<server>:9090 \
  --token <enrollment-token> \
  --hostname $(hostname -s) \
  --platform macos
```

### 4. Install as LaunchDaemon

```bash
sudo cp /tmp/wardex-agent /usr/local/bin/
sudo mkdir -p /Library/Application\ Support/Wardex

cat << 'EOF' | sudo tee /Library/LaunchDaemons/com.wardex.agent.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.wardex.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/wardex-agent</string>
        <string>--run</string>
        <string>--config</string>
        <string>/Library/Application Support/Wardex/config.toml</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/Library/Logs/Wardex/agent.log</string>
    <key>StandardErrorPath</key>
    <string>/Library/Logs/Wardex/agent-error.log</string>
</dict>
</plist>
EOF

sudo launchctl load /Library/LaunchDaemons/com.wardex.agent.plist
```

## TCC (Transparency, Consent, and Control)

### Full Disk Access

The agent requires FDA for complete telemetry. Deploy via MDM profile or manually:

**Manual**: System Settings → Privacy & Security → Full Disk Access → Add `/usr/local/bin/wardex-agent`

**MDM (Configuration Profile)**:
```xml
<key>Services</key>
<dict>
    <key>SystemPolicyAllFiles</key>
    <array>
        <dict>
            <key>Identifier</key>
            <string>com.wardex.agent</string>
            <key>IdentifierType</key>
            <string>bundleID</string>
            <key>CodeRequirement</key>
            <string>identifier "com.wardex.agent" and anchor apple generic</string>
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
| Endpoint Security (ESF) | Real-time process exec/fork/exit, file create/write/close/rename/unlink | Built with the `macos-es` cargo feature (off by default) + Apple entitlement + code signature + FDA + root — see below |
| Unified Logging | System events | Always available |

### Endpoint Security Framework (ESF): feature-gated, requires an Apple entitlement

The agent has real ESF client code (`src/kernel_macos/`, built on the
[`endpoint-sec`](https://crates.io/crates/endpoint-sec) crate), but it ships **disabled by
default** behind the `macos-es` cargo feature, and cannot function at all without steps only Apple
and your MDM can perform:

1. **Apple entitlement.** `es_new_client()` fails outright without the
   `com.apple.developer.endpoint-security.client` entitlement. Apple grants this only to
   registered Team IDs on request (via the [Developer Support
   form](https://developer.apple.com/contact/request/system-extension/)) — it is not something a
   build pipeline or this repository can self-provision. The entitlement must be baked into a
   signing profile and the binary re-signed with it.
2. **Code signature.** The entitled binary must be signed with that provisioning profile (and,
   in most real deployments, distributed as a signed system extension rather than a bare CLI
   binary — see Apple's *System Extensions and DriverKit* documentation).
3. **Full Disk Access (TCC).** Same requirement as the polling collector already documents above,
   deployed via the same manual or MDM steps.
4. **Root.** `es_new_client()` also requires the calling process to run as root (the LaunchDaemon
   install above already runs as root).

None of this can be arranged or exercised in an automated build/test environment — there is no
way to obtain Apple's entitlement, sign a binary with it, or grant TCC approval headlessly. To
build with it anyway once you do have all four:

```bash
cargo build --release --features macos-es
```

At runtime, `wardex doctor` reports which backend is actually active and, if ESF didn't come up,
exactly which precondition failed (missing feature, not root, or the specific `es_new_client()`
rejection — not entitled / not permitted / not privileged):

```bash
wardex doctor
# ...
#   [WARN] ⚠  Kernel telemetry (macOS Endpoint Security)
#          backend=PollingMacos (built without the `macos-es` cargo feature ...); ...
```

Whenever ESF isn't active — which is every default build, and any build where
`es_new_client()` is rejected — the agent transparently keeps using the `ps`/`lsof`/`mount`
polling collector documented in the rest of this runbook. The default build (without
`macos-es`) is completely unaffected by this code: the `endpoint-sec` dependency is both
optional and `target_os = "macos"`-gated in `Cargo.toml`, so it is never even fetched on other
platforms or without the feature.

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
sudo launchctl list | grep wardex
# Try manual start
sudo launchctl kickstart system/com.wardex.agent
# View logs
log show --predicate 'processImagePath contains "wardex"' --last 1h
```

### TCC Permissions Missing

```bash
# Check current TCC database (requires FDA or SIP disabled)
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
  "SELECT service, client FROM access WHERE client LIKE '%wardex%';"
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
sudo launchctl unload /Library/LaunchDaemons/com.wardex.agent.plist
sudo rm /Library/LaunchDaemons/com.wardex.agent.plist
sudo rm /usr/local/bin/wardex-agent
sudo rm -rf "/Library/Application Support/Wardex"
sudo rm -rf /Library/Logs/Wardex
```
