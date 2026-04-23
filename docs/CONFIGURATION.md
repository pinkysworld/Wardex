# Configuration Reference — Wardex

This document covers all configuration options for the Wardex XDR agent and server.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `WARDEX_PORT` | `8080` | HTTP server bind port |
| `WARDEX_HOST` | `127.0.0.1` | HTTP server bind address |
| `WARDEX_TOKEN` | *(required)* | Admin API authentication token |
| `WARDEX_AGENT_TOKEN` | *(optional)* | Enrollment token for XDR agents |
| `WARDEX_TLS_CERT` | — | Path to TLS certificate (PEM) |
| `WARDEX_TLS_KEY` | — | Path to TLS private key (PEM) |
| `WARDEX_DB_PATH` | `var/wardex.db` | SQLite database path |
| `RUST_LOG` | `info` | Log level filter (`debug`, `info`, `warn`, `error`) |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | — | OpenTelemetry collector endpoint |

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
```

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

## API Versioning

All API endpoints support both `/api/` and `/api/v1/` prefixes. For example:

```
GET /api/health        # current
GET /api/v1/health     # versioned (maps to same handler)
```

## Feature Flags

Feature flags can be queried via `GET /api/feature-flags` and toggled administratively. See [FEATURE_FLAGS.md](FEATURE_FLAGS.md) for the full list.
