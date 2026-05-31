# Configuration Reference — Wardex

This document covers all configuration options for the Wardex XDR agent and server.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `WARDEX_PORT` | `8080` | HTTP server bind port |
| `WARDEX_HOST` | `127.0.0.1` | HTTP server bind address |
| `WARDEX_ENV` | `development` | Set to `production` to enable fail-closed production startup validation |
| `WARDEX_ADMIN_TOKEN` | generated in development | Admin API authentication token; required explicitly in production |
| `WARDEX_SPOOL_KEY` | derived development key | Persistent spool encryption key; required explicitly in production |
| `WARDEX_AGENT_TOKEN` | *(optional)* | Bootstrap bearer for enrollment and legacy shared-token agent auth; production agent routes also require the per-agent token returned at enrollment |
| `WARDEX_METRICS_TOKEN` | *(optional)* | Bearer token for `/api/metrics`; required in production unless `server.metrics_bearer_token` is set |
| `WARDEX_OPENAPI_PUBLIC` | config default | Required as explicit `true` or `false` in production so public API metadata exposure is intentional |
| `WARDEX_CORS_ORIGIN` | `http://localhost` | Allowed admin-console CORS origin; wildcard origins are rejected in production |
| `SENTINEL_CORS_ORIGIN` | — | Legacy alias for `WARDEX_CORS_ORIGIN`; prefer the Wardex variable in new deployments |
| `WARDEX_SESSION_KEY` | local key file | Optional explicit session sealing key. Production rejects legacy unsigned session payloads. |
| `WARDEX_UPDATE_SIGNING_KEY_BASE64` | — | Base64 Ed25519 update signing key used by the server when publishing agent releases; overrides `security.update_signing.signing_key_path` when set |
| `WARDEX_TLS_CERT` | — | Path to TLS certificate (PEM) |
| `WARDEX_TLS_KEY` | — | Path to TLS private key (PEM) |
| `WARDEX_DB_PATH` | `var/wardex.db` | SQLite database path |
| `RUST_LOG` | `info` | Log level filter (`debug`, `info`, `warn`, `error`) |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | — | OpenTelemetry collector endpoint |

### Production fail-closed baseline

When `WARDEX_ENV=production`, startup fails until the deployment states its trust posture explicitly:

- Set `WARDEX_ADMIN_TOKEN` and `WARDEX_SPOOL_KEY` to persistent high-entropy secrets.
- Protect metrics with `WARDEX_METRICS_TOKEN` or `server.metrics_bearer_token`.
- Set `WARDEX_OPENAPI_PUBLIC=true` or `WARDEX_OPENAPI_PUBLIC=false`; omit it only in development.
- Configure agent trust with `WARDEX_AGENT_TOKEN` for enrollment/bootstrap or `security.require_mtls_agents=true` with a trusted proxy allowlist.
- Use a specific `WARDEX_CORS_ORIGIN`; `*` is rejected in production.
- Do not rely on legacy unsigned session files. Production loads only sealed session state.

Agents receive a one-time per-agent token during enrollment. Store that token in the agent runtime config and send it with `X-Wardex-Agent-Id` and `X-Wardex-Agent-Token` on heartbeat, event, inventory, policy, log, and update requests. The shared `WARDEX_AGENT_TOKEN` remains useful for enrollment and development/legacy bootstrap, but production agent routes bind requests to the enrolled agent identity.

## Configuration File (`wardex.toml`)

The server reads `wardex.toml` from the working directory at startup (or from `--config <path>`).

### `[server]`

```toml
[server]
port = 8080
host = "127.0.0.1"
shutdown_timeout_secs = 30
# metrics_bearer_token = "s3cret"  # When set, /api/metrics requires this bearer token.
#                                  # Leave unset (default) to keep the endpoint public for Prometheus scrapers
#                                  # that run on a trusted network.
```

### `[security]`

```toml
[security]
token_ttl_secs = 86400        # Token lifetime (0 = no expiry)
rate_limit_per_min = 120       # API rate limit per client IP
brute_force_lockout = 5        # Lock IP after N failed auth attempts
require_mtls_agents = false    # When true, require verified agent mTLS identity
agent_ca_cert_path = ""        # Optional CA bundle used by the TLS terminator or listener
trusted_mtls_proxy_addrs = []  # Required in production when trusting mTLS identity headers

[security.update_signing]
require_signed_updates = true  # reject unsigned agent update releases
trusted_update_signers = []    # additional base64 Ed25519 public keys; bundled defaults remain trusted
signing_key_path = ""          # optional file containing a base64, hex, or raw 32-byte Ed25519 signing key
legacy_unsigned_grace_until = "" # optional temporary override for lab-only unsigned release acceptance
last_accepted_update_counter = 0 # optional agent-side replay counter seed
```

Agent update releases are signed at publish time when `WARDEX_UPDATE_SIGNING_KEY_BASE64` or
`security.update_signing.signing_key_path` is configured. Deployments verify the stored release binary against the
signature payload before assignment, downloads expose signature headers, and agents verify checksum, signer trust,
payload hash, replay counter, downgrade policy, and binary size before install. Production deployments should keep
`require_signed_updates = true`; unsigned update grace is now an explicit lab compatibility override instead of the
default.

### `[collection]`

```toml
[collection]
collection_interval_secs = 10  # How often to collect local telemetry
max_events_per_batch = 500     # Event batch size for SIEM forwarding
```

### `[siem]`

```toml
[siem]
enabled = false
url = ""
token = ""
format = "json"      # "json", "cef", or "leef"
batch_size = 100
```

### `[taxii]`

```toml
[taxii]
enabled = false
url = ""
collection = "default"
poll_interval_secs = 300
```

### `[detection]`

```toml
[detection]
profile = "balanced"           # "aggressive", "balanced", or "quiet"
anomaly_threshold = 0.75
slow_attack_window_secs = 3600
ransomware_canary_dirs = ["/tmp/canary"]
```

### `[updates]`

```toml
[updates]
auto_update = false
channel = "stable"             # "stable", "beta", or "nightly"
```

### `[remediation]`

```toml
[remediation]
allow_live_rollback = false    # default; reject any dry_run = false rollback with 403
execute_live_rollback_commands = false  # default; record accepted live rollback plans without running local commands
```

When `allow_live_rollback = false` (the default), `POST /api/remediation/change-reviews/:id/rollback` rejects any
request with `dry_run = false` and emits a `remediation.rollback.live_blocked … reason=allow_live_rollback_disabled`
audit-warn log. To enable live recovery, set the flag to `true` **and** require operators to confirm the target
by including `confirm_hostname` in the request body — the value must equal the change-review's `asset_id`
(case-insensitive). Mismatches are rejected with `400` and audit-logged as
`remediation.rollback.live_blocked … reason=hostname_confirmation_mismatch`. Accepted live rollbacks emit
`remediation.rollback.live`. When `execute_live_rollback_commands = false` (the default), those accepted live
requests still record the rollback proof and planned commands but do not execute OS commands. Setting
`execute_live_rollback_commands = true` allows local command execution for matching-platform rollbacks; the
response payload then includes per-command execution results. The Infrastructure console enforces the same
hostname-confirmation handshake via the "Live Rollback…" button. Focused regression coverage now exercises
matching-platform true execution for restore-file, kill-process, restart-service, block-ip, remove-persistence,
disable-account, and flush-dns adapters. Recommended operator posture is to keep
`execute_live_rollback_commands = false` outside controlled maintenance windows and only enable it after verifying
the typed-hostname confirmation flow plus the platform-specific command set on the target host.

## API Versioning

All API endpoints support both `/api/` and `/api/v1/` prefixes. For example:

```
GET /api/health        # current
GET /api/v1/health     # versioned (maps to same handler)
```

## Feature Flags

Feature flags can be queried via `GET /api/feature-flags` and toggled administratively. See [FEATURE_FLAGS.md](FEATURE_FLAGS.md) for the full list.
