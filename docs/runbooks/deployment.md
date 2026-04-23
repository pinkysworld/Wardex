# Deployment &amp; Upgrade Runbook

## Overview

This runbook covers fresh installation, rolling upgrades via the atomic updater, and rollback procedures for Wardex XDR.

---

## 1. Fresh Installation

### Prerequisites

| Requirement | Minimum |
|-------------|---------|
| Rust toolchain | 1.82+ (edition 2024) |
| RAM | 512 MB |
| Disk | 200 MB |
| OS | Linux x86_64, macOS ARM64/x86_64, Windows x86_64 |

### Steps

```bash
# 1. Clone repository
git clone <repo-url> wardex && cd wardex

# 2. Build release binary
cargo build --release

# 3. Verify
./target/release/wardex --version

# 4. Create config directory
mkdir -p /etc/wardex
cp var/test-config.toml /etc/wardex/config.toml

# 5. Start server
./target/release/wardex serve --config /etc/wardex/config.toml
```

### Post-Install Verification

```bash
# Health check
curl -s http://localhost:8080/api/health | jq .

# Run self-test
cargo test -- --test-threads=1
```

---

## 2. Atomic Upgrade (v0.34.0+)

The `AtomicUpdater` performs a 5-step pipeline with automatic rollback on failure:

```
Download → Verify SHA-256 → Backup Current → Swap Binary → Validate
```

### Upgrade Steps

```bash
# 1. Prepare update bundle
#    Provide: new binary path, expected SHA-256 hash, version string

# 2. The updater performs:
#    [AUTO] Download/copy new binary to staging directory
#    [AUTO] Verify SHA-256 checksum matches expected hash
#    [AUTO] Backup current binary to staging/backup/
#    [AUTO] Atomic swap via rename (current → .old, new → current)
#    [AUTO] Validate swapped binary (file size > 0, exists)

# 3. On validation failure:
#    [AUTO] Automatic rollback: restore backup binary
#    [AUTO] State set to RolledBack with failure reason logged
```

### Manual Rollback

If the new version has issues after a successful upgrade:

```bash
# The AtomicUpdater keeps history of all updates
# Call rollback_to_previous() to restore the last known-good binary
# State transitions: Complete → RolledBack
```

### Update States

| State | Description |
|-------|-------------|
| `Idle` | No update in progress |
| `Downloading` | Copying new binary to staging |
| `Verifying` | Checking SHA-256 checksum |
| `BackingUp` | Creating backup of current binary |
| `Swapping` | Atomic rename of binaries |
| `Validating` | Post-swap integrity check |
| `Complete` | Upgrade successful |
| `RolledBack` | Reverted to previous version |
| `Failed(reason)` | Upgrade failed with error detail |

---

## 3. Fleet Enrollment

### Enroll a New Agent

```toml
# Agent config (/etc/wardex/agent.toml)
[agent]
server_url = "https://central.example.com:8443"
tenant_id = "tenant-acme"
device_id = "endpoint-042"
api_key = "<provisioned-key>"
heartbeat_interval_secs = 30
```

### Verify Enrollment

```bash
# Check fleet status on central server
curl -s http://localhost:8080/api/fleet | jq '.agents[] | select(.device_id == "endpoint-042")'
```

---

## 4. Configuration Reference

### Key Config Paths

| Path | Purpose |
|------|---------|
| `/etc/wardex/config.toml` | Server configuration |
| `/etc/wardex/agent.toml` | Agent configuration |
| `/var/lib/wardex/storage/` | Persistent storage (JSON) |
| `/var/lib/wardex/staging/` | Update staging directory |
| `/var/log/wardex/` | Application logs |

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WARDEX_CONFIG` | `/etc/wardex/config.toml` | Config file path |
| `WARDEX_PORT` | `8080` | HTTP listen port |
| `WARDEX_LOG_LEVEL` | `info` | Log verbosity |
| `WARDEX_STORAGE_DIR` | `./var/storage` | Storage backend directory |
