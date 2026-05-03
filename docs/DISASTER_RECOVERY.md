# Disaster Recovery Plan

> T214 — Phase 27

## Scope

This document covers backup, restore, and failover procedures for a Wardex
primary node, its `var/` state directory, and the shipped warm-standby
active/passive reference pattern, plus the config-backed external-standby or
leader-handoff posture surfaced in runtime readiness evidence. Fully automated
clustered control planes and federation-wide failover remain out of scope.

Use `GET /api/support/readiness-evidence`, `GET /api/system/health/dependencies`,
and `GET /api/backup/status` before and after a drill to confirm backup cadence,
latest restore artifacts, checkpoint coverage, cluster role, and recent failover
drill history from live runtime state.

Run `POST /api/control/failover-drill` after seeding a backup or control
checkpoint to record the latest automated failover drill result against the
current recovery artifacts and append it to the persisted drill history.

## Critical State Inventory

| File / Directory | Contents | Loss Impact |
|-----------------|----------|-------------|
| `var/config.toml` | Runtime configuration | Medium — defaults are safe |
| `var/checkpoints/` | Detector snapshots | High — baseline lost |
| `var/cases.json` | Analyst case data | Critical — investigation continuity |
| `var/incidents.json` | Incident records | Critical |
| `var/reports/` | Generated reports | Medium — can regenerate |
| `var/support.json` | Support-center state and persisted failover drill history | High — audit and recovery evidence continuity lost |
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
4. Verify via `GET /api/health`, `GET /api/status`, `GET /api/backup/status`,
   and `GET /api/system/health/dependencies`.
5. Run `POST /api/control/failover-drill` to validate durable storage and the
   currently restored backup/checkpoint artifacts.
6. Confirm `GET /api/support/readiness-evidence` reflects the expected backup,
   checkpoint, restore-ready posture, cluster role or leader-handoff state, and
   persisted recent failover drill history for the restored node.
7. If checkpoints are stale, trigger `POST /api/control/reset-baseline` and
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
- [ ] Run `POST /api/control/failover-drill` after staging restores and planned failover rehearsals.
- [ ] Review support/readiness evidence before and after every failover drill, including the cluster role and recent drill-history section.
- [ ] Confirm key escrow is current after every `POST /api/quantum/rotate`.
- [ ] Review RTO/RPO with stakeholders quarterly.

## Database Schema Migration

Wardex uses an embedded SQLite database stored under `var/`.  Schema changes
are applied automatically on startup.

### Verifying the schema version

```
GET /api/schema/version
```

Returns the current schema version number.  After upgrading the binary, confirm
the version has incremented to the expected value.

### Upgrade workflow

1. **Back up** `var/` before upgrading (see Backup Strategy above).
2. Stop the running instance.
3. Replace the binary with the new release.
4. Start the new binary — migrations run automatically on first boot.
5. Verify with `GET /api/health` and `GET /api/schema/version`.
6. If the upgrade fails, restore from backup and file an issue.

### Rollback

If a schema migration introduces a problem:

1. Stop the new binary.
2. Restore `var/` from the pre-upgrade backup.
3. Start the previous binary version.

> **Note:** Forward-only migrations are not reversible at the SQL level.
> Always back up before upgrading.
