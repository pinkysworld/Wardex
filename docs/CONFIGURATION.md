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
| `OTEL_EXPORTER_OTLP_ENDPOINT` | — | OpenTelemetry collector base URL (e.g. `http://otel-collector:4318`); used as the default when no endpoint has been saved via `POST /api/telemetry/otlp` |

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

Bind address and port are set via the `WARDEX_HOST` / `WARDEX_PORT` environment variables (see above), not in
`wardex.toml`.

```toml
[server]
rate_limit_read_per_minute = 360   # Max GET/read requests per minute per client IP (0 = unlimited)
rate_limit_write_per_minute = 60   # Max mutating requests per minute per client IP (0 = unlimited)
shutdown_timeout_secs = 30
openapi_public = true              # Whether /api/openapi.json stays public; must be set explicitly in production
# metrics_bearer_token = "s3cret"  # When set, /api/metrics requires this bearer token.
#                                  # Leave unset (default) to keep the endpoint public for Prometheus scrapers
#                                  # that run on a trusted network.
```

### `[security]`

```toml
[security]
token_ttl_secs = 86400        # Token lifetime (0 = no expiry)
require_mtls_agents = false    # When true, require verified agent mTLS identity
agent_ca_cert_path = ""        # Optional CA bundle used by the TLS terminator or listener
trusted_mtls_proxy_addrs = []  # Required in production when trusting mTLS identity headers
cors_allowed_origins = []      # Allowed admin-console CORS origins (empty = same-origin only)

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

### `[monitor]`

```toml
[monitor]
interval_secs = 5              # Legacy sampling cadence, still used as the collection interval fallback
alert_threshold = 3.5
alert_log = "var/alerts.jsonl"
dry_run = false
duration_secs = 0              # 0 = run indefinitely
syslog = false
cef = false
watch_paths = []
```

### `[collection]`

```toml
[collection]
collection_interval_secs = 10  # How often to collect local telemetry
max_events_per_batch = 500     # Event batch size for SIEM forwarding
```

`collection.collection_interval_secs` drives the agent's sampling loop. For backward compatibility with configs
written before `[collection]` existed, the agent only uses `collection_interval_secs` when it is explicitly set in
`wardex.toml`; otherwise it falls back to `monitor.interval_secs` (default `5`), so a config that sets only
`[monitor] interval_secs` keeps its cadence unchanged. If both are set and differ, `collection_interval_secs` wins
and the agent logs a one-time deprecation note.

### `[siem]`

```toml
[siem]
enabled = false
siem_type = "generic"    # "splunk", "elastic", "sentinel", "qradar", or "generic"
endpoint = ""            # SIEM endpoint URL (e.g. HEC endpoint for Splunk)
auth_token = ""
index = "wardex"
source_type = "wardex:xdr"
poll_interval_secs = 60
pull_enabled = false
batch_size = 50
verify_tls = true
```

### `[taxii]`

```toml
[taxii]
enabled = false
url = ""              # TAXII collection URL (e.g. https://taxii.example.com/api/collections/abc/objects/)
auth_token = ""
added_after = ""       # Optional RFC 3339 timestamp; only pull indicators newer than this
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

### `[collectors]`

Selects which platform collector backends are preferred, and the scan cadence for
each Windows telemetry source. `*_enabled = false` force-disables a backend even
when it is available; `*_enabled = true` (the default) prefers it but never
fabricates support — when the backend isn't compiled into this build or isn't
available on the running host, Wardex logs `"<name>_enabled=true but ... is not
available"` and falls back to the non-accelerated collection path instead of
silently doing nothing.

```toml
[collectors]
ebpf_enabled = true             # Linux eBPF tracing backend; not compiled into
                                 # this build yet, so enabling it only logs a
                                 # notice — kernel-event collection is tracked
                                 # separately (see kernel_events.rs).
ebpf_programs = ["execsnoop", "tcpconnect", "filelife"]
etw_enabled = true              # Windows Event Tracing for Windows
wmi_enabled = true              # Windows WMI/PowerShell collector paths
amsi_enabled = true             # Windows AMSI script-content inspection
registry_scan_interval_secs = 300
process_scan_interval_secs = 30
network_scan_interval_secs = 15
```

### `[container]`

Live Docker/Podman and in-cluster Kubernetes event sources (see
`src/container_runtime.rs`). Reachability is surfaced via `wardex doctor` and
`GET /api/platform`.

```toml
[container]
docker_enabled = false
docker_socket_path = "/var/run/docker.sock"  # or a Podman socket, e.g.
                                              # "/run/user/1000/podman/podman.sock"
docker_timeout_secs = 10
docker_backoff_secs = 1
docker_max_backoff_secs = 60
kubernetes_enabled = false
kubernetes_namespaces = []       # empty = all namespaces
```

Kubernetes support is best-effort: the in-cluster API server presents a TLS
certificate signed by the cluster's own CA, and this build's HTTP client does
not currently trust a custom root CA, so live Pod watching against a real
cluster will fail TLS verification. The watch-stream parsing and detection
mapping are implemented and unit-tested against fixtures so the feature can be
enabled as soon as a custom trust anchor is wired through.

### `[relay]`

```toml
[relay]
enabled = true
upstream = "https://central.example.com"
sync_interval_secs = 300
spool_max_bytes = 104857600  # 100 MB
```

### `[attestation]`

```toml
[attestation]
enabled = true
manifest_path = "/etc/wardex/manifest.json"
require_at_boot = true
periodic_check_minutes = 30
trust_store_path = "/etc/wardex/trust_store.json"
```

`trust_store_path` points at the local JSON trust store of accepted release
signer public keys (`attestation::TrustStore`). Verify a manifest against it
with `wardex attest-verify [manifest] [trust-store]`, which falls back to the
paths configured here when not given explicitly.
## Threat-Intel Enrichment, Ticketing, and OTLP Export

These integrations are configured at runtime through the admin API (not `wardex.toml`); every field takes a
literal value or a secret reference resolved through the same `SecretsResolver` the cloud collectors use
(`${ENV_VAR}`, `file:///path`, or `vault://mount/path#key`).

| Integration | Config endpoint | Action endpoint(s) | Notes |
|---|---|---|---|
| VirusTotal / AbuseIPDB enrichment | `GET`/`POST /api/integrations/enrichment` | `POST /api/enrich/lookup` (`{"kind": "ip_address\|file_hash\|domain\|url", "indicator": "..."}`) | VT public-API default is 4 req/min; AbuseIPDB defaults to 60 req/min. Results are cached with a per-provider TTL (default 1h). Both degrade to a typed error (never a panic) when disabled, misconfigured, or rate-limited. |
| Jira ticketing | `GET`/`POST /api/integrations/ticketing/jira` | `POST /api/tickets/sync`, `POST /api/tickets/pull` | Cloud (`email` + `api_token`) or Server (leave `email` empty, `api_token` used as a bearer PAT). Re-syncing an already-synced case adds a comment instead of creating a duplicate issue. |
| ServiceNow ticketing | `GET`/`POST /api/integrations/ticketing/servicenow` | `POST /api/tickets/sync`, `POST /api/tickets/pull` | Table API against `table` (default `incident`); basic auth (`username`/`password`) or `oauth_token`. Re-syncing patches the existing incident by `sys_id` instead of creating a new one. |
| OTLP/HTTP export | `GET`/`POST /api/telemetry/otlp` | `POST /api/telemetry/otlp/flush` | Exports batched OTLP/HTTP JSON to `{endpoint}/v1/traces`, `/v1/logs`, `/v1/metrics` with retry/backoff and a bounded, drop-counted queue. `OTEL_EXPORTER_OTLP_ENDPOINT` seeds the default endpoint. |

`POST /api/tickets/sync` is idempotent: syncing the same `(provider, object_kind, object_id)` again updates the
existing local record and the existing remote ticket (add-comment / patch) rather than creating a second one.
When no ticketing provider is enabled, it keeps the prior local-only bookkeeping behavior unchanged.

### SMTP email notifications

`notifications::SmtpConfig` now supports `use_tls` (STARTTLS on a plaintext port, typically 587), `implicit_tls`
(TLS from the first byte, typically port 465), `username`/`password` (AUTH PLAIN/LOGIN, negotiated from the
server's advertised `AUTH` capability), and an optional `ca_cert_pem` to trust an internal/private CA in addition
to the built-in Mozilla root store. Certificate verification is always on. Requesting TLS in a binary built
without the `tls` cargo feature fails delivery with a clear error instead of silently sending in plaintext.

### Okta identity collector

The Okta System Log collector (`collector_identity::OktaCollector`) now has a `poll()` method that performs the
HTTP fetch itself (matching the AWS/Azure/GCP collector shape), persists its `after` pagination cursor via the
same collector-checkpoint storage the other collectors use (so repeated polls advance through the log instead of
re-fetching the first page), and reads Okta's `X-Rate-Limit-Remaining`/`X-Rate-Limit-Reset` headers to report a
`retry_after_secs` hint instead of hammering the API when the org-wide rate limit is close to empty.

## API Versioning

All API endpoints support both `/api/` and `/api/v1/` prefixes. For example:

```
GET /api/health        # current
GET /api/v1/health     # versioned (maps to same handler)
```

## Feature Flags

Feature flags can be queried via `GET /api/feature-flags` and toggled administratively. See [FEATURE_FLAGS.md](FEATURE_FLAGS.md) for the full list.
