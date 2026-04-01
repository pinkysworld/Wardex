# Disaster Recovery Plan

> T214 — Phase 27

## Scope

This document covers backup, restore, and failover procedures for a single
Wardex instance and its `var/` state directory.  Multi-node federation DR is
out of scope until Phase 30+.

## Critical State Inventory

| File / Directory | Contents | Loss Impact |
|-----------------|----------|-------------|
| `var/config.toml` | Runtime configuration | Medium — defaults are safe |
| `var/checkpoints/` | Detector snapshots | High — baseline lost |
| `var/cases.json` | Analyst case data | Critical — investigation continuity |
| `var/incidents.json` | Incident records | Critical |
| `var/reports/` | Generated reports | Medium — can regenerate |
| `var/spool/` | Encrypted telemetry backlog | High — undelivered events |
| `var/deployments.json` | Agent deployment state | Medium |
| `var/policy/` | Published policies | Medium — re-publishable |
| `var/keys/` | Post-quantum key material | Critical — must not leak |

## Backup Strategy

### Automated daily snapshot

```bash
#!/bin/bash
BACKUP_DIR="/opt/backups/wardex"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
tar czf "$BACKUP_DIR/wardex-state-$TIMESTAMP.tar.gz" \
    --exclude='var/spool/*' \
    var/
# Encrypt with age or GPG
age -r "$BACKUP_PUBKEY" \
    "$BACKUP_DIR/wardex-state-$TIMESTAMP.tar.gz" \
    > "$BACKUP_DIR/wardex-state-$TIMESTAMP.tar.gz.age"
rm "$BACKUP_DIR/wardex-state-$TIMESTAMP.tar.gz"
# Retain last 30 days
find "$BACKUP_DIR" -name '*.age' -mtime +30 -delete
```

### Key material backup

Key files under `var/keys/` must be backed up to an **offline** medium
(encrypted USB or HSM escrow).  They must **never** be included in networked
backups.

## Restore Procedure

1. Stop the Wardex process: `POST /api/shutdown` or `kill -TERM <pid>`.
2. Decrypt and extract the snapshot:
   ```bash
   age -d -i key.txt backup.tar.gz.age | tar xzf - -C /opt/wardex/
   ```
3. Start Wardex: `wardex serve --config var/config.toml`.
4. Verify via `GET /api/health` and `GET /api/status`.
5. If checkpoints are stale, trigger `POST /api/control/reset-baseline` and
   allow 10 minutes of learning.

## Recovery Time Objectives

| Scenario | RTO | RPO |
|----------|-----|-----|
| Config corruption | < 5 min | Last backup |
| Full disk loss | < 15 min | Daily backup (24 h) |
| Key compromise | < 30 min | Rotate + re-enroll agents |
| Binary corruption | < 10 min | Redeploy from CI artefact |

## DR Validation Tests

The test module `tests::disaster_recovery` validates:

1. **Checkpoint round-trip**: Save checkpoint → corrupt `var/` → restore →
   detector state matches.
2. **Config rebuild**: Delete `config.toml` → server starts with safe defaults
   and logs a warning.
3. **Spool replay**: Spool persists events across restart; replayed events
   appear in event store.
4. **Key rotation after restore**: Post-quantum keys rotate on first boot after
   restore if epoch is stale.

## Runbook Checklist

- [ ] Verify daily backup cron is active.
- [ ] Test restore to a staging instance monthly.
- [ ] Confirm key escrow is current after every `POST /api/quantum/rotate`.
- [ ] Review RTO/RPO with stakeholders quarterly.
