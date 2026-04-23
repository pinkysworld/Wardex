# Troubleshooting Runbook

## Quick Diagnostics

### 1. Service Won't Start

```bash
# Check binary exists and is executable
ls -la ./target/release/wardex

# Check port availability
lsof -i :8080

# Run with verbose logging
RUST_LOG=debug ./target/release/wardex serve 2>&1 | head -50

# Verify config syntax
cargo run -- validate-config --config /etc/wardex/config.toml
```

### 2. Agent Can't Connect to Server

| Check | Command |
|-------|---------|
| DNS resolution | `nslookup <server-host>` |
| Port reachable | `nc -zv <server-host> 8080` |
| TLS certificate | `openssl s_client -connect <server-host>:8443` |
| API key valid | `curl -H "Authorization: Bearer <key>" http://<server>:8080/api/health` |

### 3. High Memory Usage

```bash
# Check process memory
ps aux | grep wardex

# Check storage file sizes
du -sh /var/lib/wardex/storage/

# Trigger retention purge (reduces stored alerts)
curl -X POST http://localhost:8080/api/admin/purge-retention
```

### 4. Alerts Not Firing

```bash
# Verify detection mode
curl -s http://localhost:8080/api/config | jq '.detection_mode'

# Check policy is loaded
curl -s http://localhost:8080/api/policy/active | jq '.rules | length'

# Send test alert
curl -X POST http://localhost:8080/api/test-alert \
  -H "Content-Type: application/json" \
  -d '{"severity":"elevated","message":"test alert"}'
```

### 5. Notification Delivery Failures

| Channel | Common Issue | Fix |
|---------|-------------|-----|
| Slack | Invalid webhook URL | Verify URL starts with `https://hooks.slack.com/` |
| Teams | Connector disabled | Re-enable incoming webhook in Teams channel |
| PagerDuty | Wrong routing key | Verify Events API v2 integration key |
| Webhook | TLS errors | Check certificate chain, add CA bundle |
| Email | SMTP auth rejected | Verify credentials, check STARTTLS vs SSL |

### 6. Update / Rollback Issues

```bash
# Check current update state
curl -s http://localhost:8080/api/update/status | jq .

# SHA-256 mismatch → verify the hash
sha256sum /path/to/new-binary

# Manual rollback if API unavailable
cp /var/lib/wardex/staging/backup/wardex /usr/local/bin/wardex
```

---

## Common Error Messages

| Error | Cause | Resolution |
|-------|-------|------------|
| `address already in use` | Port 8080 occupied | Kill existing process or change port |
| `permission denied` | Insufficient privileges | Run with appropriate permissions |
| `tenant not found` | Unknown tenant ID in request | Register tenant via admin API |
| `checksum mismatch` | Corrupted update binary | Re-download and verify SHA-256 |
| `storage locked` | Concurrent write conflict | Retry; check for zombie processes |
| `certificate expired` | TLS cert past validity | Renew certificate |

---

## Log Analysis

```bash
# Tail last 100 log lines
tail -100 /var/log/wardex/server.log

# Filter for errors only
grep -i "error\|panic\|fatal" /var/log/wardex/server.log

# Count alerts by severity in last hour
grep "alert" /var/log/wardex/server.log | \
  grep "$(date -u +%Y-%m-%dT%H)" | \
  grep -oP '"level":"[^"]*"' | sort | uniq -c | sort -rn

# Check audit chain integrity
curl -s http://localhost:8080/api/audit/verify | jq .
```

---

## Escalation Path

1. **L1 — Operator**: Follow this runbook, check logs, restart if needed
2. **L2 — Engineer**: Review audit chain, check config diff, analyze core dumps
3. **L3 — Platform**: Code-level debugging, hotfix deployment
