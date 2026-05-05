# Upgrade Guide: 0.x → 1.0

This guide covers all breaking changes and migration steps required when
upgrading Wardex from any 0.x release to v1.0.0.

---

## Overview of Changes in v1.0

| Area | Change | Action required |
|------|--------|----------------|
| License | BUSL-1.1 → AGPL-3.0 + commercial dual-license | Review your use case; obtain commercial license if needed |
| Feature flags | `experimental-*` compile-time flags removed | Remove `--no-default-features --features experimental-*` from build scripts |
| API stability pledge | First stable API; breaking changes require v2.0 | Update CI to treat API changes as breaking |
| AGPL network-service clause | Using Wardex to provide a hosted service requires source disclosure | Ensure compliance or obtain commercial license |
| ClickHouse storage | Now the recommended event backend for production | Configure `[clickhouse]` section or continue using in-memory fallback |
| `LICENSE` file | Replaced with AGPL-3.0 full text + dual-license header | Update any legal acknowledgments in your docs |

---

## Step-by-Step Upgrade

### 1. Review your license obligations

If you run Wardex as an internal security tool with no external distribution
or SaaS offering, AGPL-3.0 permits this freely. If you distribute Wardex to
customers or run it as a hosted service, you need either:

- A commercial license (contact `support@wardex.dev`), **or**
- Compliance with AGPL-3.0's network-service copyleft requirement (publish
  your modifications).

### 2. Update build scripts

If you pinned features in build scripts, update them:

```bash
# Before (0.x):
cargo build --release --features experimental-ml,experimental-llm

# After (1.0) — all modules are unconditionally compiled:
cargo build --release
```

Remove any `--no-default-features --features experimental-*` flags. The
`tls` feature flag still exists for opt-in TLS in the `ureq` HTTP client.

### 3. Run the schema migration

Wardex applies SQLite migrations automatically on startup. No manual step is
needed for the SQLite database.

For ClickHouse, run the schema provisioning command if you are adding
ClickHouse for the first time:

```bash
wardex storage init-clickhouse --config /etc/wardex/wardex.toml
```

This creates the `wardex.events` table and the `alerts_per_hour` materialized
view (idempotent — safe to re-run).

### 4. Update your config file

No TOML keys were removed between 0.56.x and 1.0. The following **new**
optional sections are available:

```toml
# Add to enable ClickHouse event storage (recommended for production):
[clickhouse]
url = "http://clickhouse-host:8123"
database = "wardex"
username = "default"
password = ""
batch_size = 1000
flush_interval_secs = 5
retention_days = 90
```

### 5. Update SDK versions

If you use the TypeScript or Python SDKs, bump to 1.0.0:

```bash
# TypeScript
npm install @wardex/sdk@^1.0.0

# Python
pip install wardex==1.0.0
```

The SDK v1.0.0 packages add type annotations and cover ≥ 80 % of the
OpenAPI surface. See `docs/SDK_GUIDE.md` for the updated quick-start.

### 6. Review Helm values (Kubernetes deployments)

In `deploy/helm/wardex/values.yaml`, review:

- `networkPolicy.enabled` — now defaults to `true`; configure
  `networkPolicy.egressRules` if your cluster needs custom egress to
  ClickHouse or OIDC providers.
- `podDisruptionBudget.enabled` — already defaults to `true` since 0.56;
  confirm `minAvailable: 1` is correct for your replica count.
- `image.tag` — update to `"1.0.0"`.

### 7. Smoke test after upgrade

```bash
# Verify health
curl -sSf http://YOUR_SERVER:9077/api/health | jq .

# Run the release acceptance gate
make release-acceptance
```

---

## Breaking Changes by Version

### 0.56.x → 1.0.0

- **License change** (BUSL-1.1 → AGPL-3.0): Review obligations (see step 1).
- **`experimental-*` feature flags removed**: Update build scripts (see step 2).
- No HTTP API endpoints were removed. The full OpenAPI surface from 0.56.x
  is preserved in 1.0.0 and covered by the stability pledge.
- No TOML configuration keys were removed.
- No CLI commands or flags were removed.

---

## Rollback Procedure

If you need to roll back from 1.0.0 to 0.56.x:

1. Stop Wardex 1.0.0.
2. Restore the backup taken before the upgrade (see `docs/DISASTER_RECOVERY.md`).
3. Deploy the 0.56.x binary.
4. Start Wardex 0.56.x.

**Note**: If ClickHouse was newly provisioned in step 3 of the upgrade,
the ClickHouse schema is forward-only. Rolling back to 0.56.x is safe
because 0.56.x still reads the same schema. The reverse is also true:
1.0.0 schema is identical to 0.56.x for ClickHouse.

---

## Support

File upgrade issues at https://github.com/pinkysworld/Wardex/issues with the
`upgrade` label, or contact `support@wardex.dev` for production-critical
escalations.
