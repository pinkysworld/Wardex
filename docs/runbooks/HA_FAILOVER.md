# HA Failover Runbook

**Audience**: Platform operators and SREs running Wardex in active/passive or
regional-active configurations.

**Prerequisites**: Familiarity with `docs/DEPLOYMENT_MODELS.md` and
`docs/DISASTER_RECOVERY.md`.

---

## 1. Architecture Reference

Wardex v1.0 supports **active/passive HA** backed by durable shared storage
or periodic backup replication.  A fully automated clustered control plane
(Raft leader election) is on the 1.1 roadmap; this runbook covers the
operationally sound pattern for 1.0.

```
                     ┌───────────────┐
                     │  Load Balancer│
                     │  / Reverse    │
                     │  Proxy        │
                     └──────┬────────┘
                  ┌─────────┴──────────┐
           Active │                    │ Standby (warm)
     ┌────────────▼──┐        ┌────────▼───────────┐
     │  Wardex Primary│        │  Wardex Standby    │
     │  (serving)     │        │  (idle / health    │
     │  var/ on NFS / │        │  check only)       │
     │  shared vol    │        │  same shared vol   │
     └────────────────┘        └────────────────────┘
```

### Key design constraints (v1.0)

- Only **one Wardex process should write** to `var/` (SQLite + spool) at a
  time. Concurrent writers on the same SQLite database will cause corruption.
- The ClickHouse event store is stateless from Wardex's perspective — multiple
  nodes can write to the same ClickHouse cluster simultaneously.
- Agent-facing endpoints (`POST /api/events`, heartbeat) are idempotent; a
  brief period of dual-write during failover is safe for these paths.

---

## 2. Pre-Failover Checklist

Run before any planned failover drill or unplanned failover:

1. **Verify backup currency**:
   ```bash
   curl -sSf http://PRIMARY:9077/api/backup/status \
     -H "Authorization: Bearer $ADMIN_TOKEN" | jq .last_backup_at
   ```
   Confirm `last_backup_at` is within your RPO window (default: 15 min).

2. **Check readiness evidence**:
   ```bash
   curl -sSf http://PRIMARY:9077/api/support/readiness-evidence \
     -H "Authorization: Bearer $ADMIN_TOKEN" | jq .overall_status
   ```
   Should return `"ready"` or `"degraded"` (not `"critical"`).

3. **Confirm standby is healthy** (serving health check only, not traffic):
   ```bash
   curl -sSf http://STANDBY:9077/api/health | jq .status
   ```
   Should return `"ok"`.

4. **Drain in-flight events** on the primary:
   ```bash
   curl -sSfX POST http://PRIMARY:9077/api/spool/flush \
     -H "Authorization: Bearer $ADMIN_TOKEN"
   ```

---

## 3. Planned Failover (maintenance window)

```bash
# 1. Stop primary
systemctl stop wardex          # or: kubectl scale deploy/wardex --replicas=0

# 2. Take a final backup (belt and suspenders)
wardex backup export --output /backup/pre-failover-$(date +%Y%m%d%H%M%S).tar.gz

# 3. If var/ is on local storage, rsync to standby
rsync -az --delete /var/wardex/ standby-host:/var/wardex/

# 4. Point load balancer / DNS to standby
# (update your LB config or flip the DNS A record)

# 5. Start standby as new primary
ssh standby-host systemctl start wardex

# 6. Verify
curl -sSf http://STANDBY:9077/api/health | jq .
```

Expected: health returns `"ok"` with `agents_connected` ≥ 0 within 30 seconds
of start (agents reconnect automatically using the configured server URL).

---

## 4. Unplanned Failover (primary failure)

```bash
# 1. Confirm primary is unreachable
curl --max-time 5 http://PRIMARY:9077/api/health || echo "primary down"

# 2. If var/ is on shared NFS / PVC — mount is already available on standby.
#    If local — restore the latest backup:
wardex backup restore \
  --input /backup/latest.tar.gz \
  --data-dir /var/wardex

# 3. Point load balancer to standby (same as planned failover step 4)

# 4. Start standby
ssh standby-host systemctl start wardex

# 5. Post-failover integrity check
curl -sSf http://STANDBY:9077/api/system/health/dependencies \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
```

### RPO / RTO targets (1.0 reference)

| Metric | Target | Notes |
|--------|--------|-------|
| RPO    | ≤ 15 min | Requires backup interval ≤ 15 min; configure in `[backup]` TOML section |
| RTO    | ≤ 30 min | Assumes shared storage or a recent backup within RPO; restore + start |

---

## 5. Agent Reconnection

Wardex agents retry failed connections with exponential backoff. After
failover:

- Agents reconnect automatically once the new primary responds on the same
  hostname/IP.
- If the server hostname changes, push an updated agent config via your
  provisioning tool before failover, or update the DNS name to point to the
  new host.
- Agent telemetry spooled during the outage is replayed automatically once
  connectivity is restored (`spool` directory on each agent).

---

## 6. Post-Failover Validation

```bash
# Health
curl -sSf http://NEW_PRIMARY:9077/api/health | jq .

# Agents reconnected
curl -sSf http://NEW_PRIMARY:9077/api/fleet/agents \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.[].status' | sort | uniq -c

# ClickHouse event ingest still flowing (if configured)
curl -sSf http://NEW_PRIMARY:9077/api/events?limit=5 \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq length
```

---

## 7. Failback (optional)

Once the original primary is repaired:

1. Stop the current active node (was standby).
2. Rsync `var/` back to the original primary (if on local storage).
3. Start original primary and redirect traffic back.
4. Confirm health as above.

Failback is optional — the standby can operate indefinitely as the new
primary.

---

## 8. Kubernetes / Helm Deployments

For Helm-managed deployments (`deploy/helm/wardex/`):

- Use `replicaCount: 1` with a `PodDisruptionBudget` (`minAvailable: 1`)
  backed by a `ReadWriteOnce` PVC and a cluster with topology spread.
- For multi-replica writes: use the ClickHouse backend for event storage
  and keep SQLite/state on a single leader pod (use a `StatefulSet` with
  `podManagementPolicy: Parallel` for rolling restart, not `Deployment`).
- Rolling upgrades: the Helm chart uses `RollingUpdate` by default.
  Wardex is safe to roll one pod at a time because idle standby pods serve
  only health probes.

See `docs/DEPLOYMENT_MODELS.md` for Helm configuration examples.

---

## Related Documents

- `docs/DISASTER_RECOVERY.md` — backup and restore procedures
- `docs/DEPLOYMENT_MODELS.md` — deployment topology reference
- `docs/PRODUCTION_HARDENING.md` — security hardening for production
- `docs/SLO_POLICY.md` — SLO definitions and error budgets
