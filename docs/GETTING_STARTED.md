# Getting Started

## Requirements

- Rust toolchain with `cargo`
- macOS, Linux, or Windows for local development
- a modern browser for the admin console

## Build

```bash
npm ci --prefix admin-console
cargo build --release
```

The Rust build embeds the admin console from `admin-console/dist`, so install the frontend dependencies first when building from a clean checkout.

## Run the demo

```bash
cargo run -- demo
```

This executes the built-in telemetry sequence and writes audit output to `var/demo.audit.log`.

## Analyze a telemetry trace

CSV:

```bash
cargo run -- analyze examples/credential_storm.csv
```

JSONL:

```bash
cargo run -- analyze examples/credential_storm.jsonl
```

Default audit output for `analyze` is `var/last-run.audit.log`.

## Generate a structured report

```bash
cargo run -- report examples/credential_storm.csv
```

Default output is `var/last-run.report.json`.

## Start the live control plane

```bash
cargo run
```

This starts the HTTP server on port `8080`, launches the embedded local monitor, and writes the admin token to `var/.wardex_token` unless you already set `WARDEX_ADMIN_TOKEN` yourself. Open `http://localhost:8080/admin/`, paste the token, and use the console to:

`http://localhost:8080/admin/` is the local backend-served console that comes from `cargo run`. If you launch the frontend with `cd admin-console && npm run dev`, the browser URL is `http://localhost:5173/admin/` while the Vite dev server proxies API traffic back to `127.0.0.1:8080`.

- inspect the Dashboard, Fleet & Agents, Threat Detection, Reports, and Settings surfaces
- work cases and alerts in the SOC Workbench
- manage hunts, rules, suppressions, and MITRE coverage in Detection Engineering
- review per-agent activity, deployment health, rollout targets, and rollback controls
- inspect diagnostics, dependency health, audit posture, and identity/provisioning configuration

## Evaluate Wardex in 15 minutes

This is the canonical evaluation path for Wardex. Seeded first-run proof data and exported artifacts are for evaluation only.

1. Start the control plane with `cargo run`.
2. Open `http://localhost:8080/admin/`.
3. Paste the token from `var/.wardex_token`.
4. Run the scripted proof path:

```bash
WARDEX_ADMIN_TOKEN="$(cat var/.wardex_token)" bash scripts/evaluate_to_value.sh
```

5. Review the exported artifacts in `output/evaluate-to-value/`.
6. Run `cargo run -- doctor` for the terminal report and `cargo run -- doctor --json` for machine-readable diagnostics.

The script proves readiness, evaluation-only first-run proof seeding, first alert visibility, response dry-run preview, evidence export, support bundle export, and deployment trust reporting through the same routes used by the admin console. The full guide lives in [`EVALUATE_WARDEX.md`](EVALUATE_WARDEX.md).

## Export the static status snapshot

```bash
cargo run -- status-json site/data/status.json
```

This refreshes the structured status payload consumed by the static site and offline views.

## Run tests

```bash
cargo test
```

The current release tracks 3635 Rust test functions, 328 admin-console tests, and 8 managed Playwright checks across 7 browser specs. Treat seeded demo data as evaluation-only when you validate the first-run operator journey.

## Frontend development (admin-console)

The admin console is a React SPA in `admin-console/`.

### Setup

```bash
cd admin-console
npm ci
```

### Development

Start the Rust backend first (the dev server proxies API calls to it):

```bash
# Terminal 1: backend
cargo run

# Terminal 2: frontend dev server
cd admin-console
npm run dev
```

The frontend dev server runs on `http://localhost:5173/admin/` and proxies all `/api` requests to `http://127.0.0.1:8080`. Use `:5173` only for frontend development; the embedded production-like local console from `cargo run` remains `http://localhost:8080/admin/`.

Paste the admin token from `var/.wardex_token` into the login form, or use the value you set in `WARDEX_ADMIN_TOKEN`.

### Testing

```bash
# Unit tests (Vitest)
npm test -- --run

# Lint + format check
npm run lint && npm run format:check

# E2E tests (requires running backend)
npx playwright install chromium
npx playwright test
```

### Environment variables

No special environment variables are required for frontend development. The proxy configuration in `vite.config.js` handles API routing automatically.

## Live validation helpers

- `python3 tests/live_test.py` exercises the live HTTP server paths.
- `python3 tests/verify_admin.py` validates key admin-console data surfaces.
- `tests/playwright/enterprise_console_smoke.spec.js` provides a reusable browser smoke flow for the enterprise console.
- `tests/playwright/live_release_smoke.spec.js` provides a focused release smoke for token login, sample alert injection, and live monitor verification.

## Release packages

Tagged releases are built by GitHub Actions for:

- Linux `x86_64-unknown-linux-musl`
- macOS `aarch64-apple-darwin`
- macOS `x86_64-apple-darwin`
- Windows `x86_64-pc-windows-msvc`

Native installation assets are also published for operators who do not want to unpack raw archives:

```bash
# Debian / Ubuntu (signed APT repository)
curl -fsSL https://pinkysworld.github.io/Wardex/apt/wardex-archive-key.asc \
  | gpg --dearmor \
  | sudo tee /usr/share/keyrings/wardex-archive-keyring.gpg > /dev/null
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/wardex-archive-keyring.gpg] https://pinkysworld.github.io/Wardex/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/wardex.list > /dev/null
sudo apt-get update
sudo apt-get install wardex

# RHEL / Fedora / Rocky
sudo rpm -i ./wardex-*.x86_64.rpm

# Homebrew
brew tap pinkysworld/wardex
brew install wardex
```

The Homebrew formula now builds Wardex from the tagged source archive, then installs the binary plus the bundled static site and example data under `share/wardex/`. The tap is published from the dedicated repository `pinkysworld/homebrew-wardex`.

If you prefer a manual Debian install, download the versioned `.deb` from the latest GitHub release page and run `sudo dpkg -i ./wardex_<version>_amd64.deb`.

## Telemetry format

The parser supports CSV (legacy 8-column and extended 10-column) and JSONL.

CSV header:

```text
timestamp_ms,cpu_load_pct,memory_load_pct,temperature_c,network_kbps,auth_failures,battery_pct,integrity_drift[,process_count,disk_pressure_pct]
```

JSONL line example:

```json
{"timestamp_ms":1000,"cpu_load_pct":18,"memory_load_pct":32,"temperature_c":41,"network_kbps":500,"auth_failures":0,"battery_pct":94,"integrity_drift":0.01,"process_count":42,"disk_pressure_pct":8}
```

## Production Configuration

### Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `WARDEX_ENV` | Set to `production` to enable fail-closed startup validation. | `development` |
| `WARDEX_ADMIN_TOKEN` | Override the auto-generated admin token. Required in production; use a 256-bit random hex string or stronger secret. | Auto-generated at startup |
| `WARDEX_SPOOL_KEY` | Persistent spool encryption key. Required in production so queued records survive restart and cannot fall back to derived development material. | Development fallback |
| `WARDEX_AGENT_TOKEN` | Bootstrap bearer for enrollment and legacy shared-token agent auth. Production agents also use the one-time per-agent token returned by enrollment. | unset |
| `WARDEX_METRICS_TOKEN` | Bearer token for `/api/metrics`, unless `server.metrics_bearer_token` is set in config. Required in production. | unset |
| `WARDEX_OPENAPI_PUBLIC` | Explicitly allow or deny public OpenAPI metadata in production (`true` or `false`). | Config default |
| `WARDEX_BIND` | Listen address and port. | `0.0.0.0:8080` |
| `WARDEX_CONFIG_PATH` | Explicit path to the runtime config file. Useful for packaged service installs. | Auto-discovered `var/wardex.toml` |
| `WARDEX_CORS_ORIGIN` | Allowed CORS origin for the admin console. Wildcards are rejected in production. | `http://localhost:8080` |
| `SENTINEL_CORS_ORIGIN` | Legacy alias for `WARDEX_CORS_ORIGIN`. Prefer the Wardex variable for new deployments. | unset |
| `WARDEX_LOG_LEVEL` | Log verbosity (`trace`, `debug`, `info`, `warn`, `error`). | `info` |
| `WARDEX_DATA_DIR` | Path to the data directory. | `var/` |

Production startup refuses insecure defaults when `WARDEX_ENV=production`. Before switching a deployment from evaluation to production, set the required secrets, choose the OpenAPI exposure posture, protect metrics, and define agent trust through `WARDEX_AGENT_TOKEN` or mTLS. Agent enrollment returns a per-agent token; keep it in the agent runtime config because heartbeat, event, inventory, policy, log, and update requests are bound to that enrolled identity in production.

### TLS configuration

To enable TLS for the HTTP listener, set the following in `var/config.toml`:

```toml
[tls]
cert_path = "/path/to/cert.pem"
key_path  = "/path/to/key.pem"
```

For mutual TLS (mTLS) agent authentication, add:

```toml
[security]
require_mtls_agents = true
agent_ca_cert_path = "/path/to/agent-ca.pem"
trusted_mtls_proxy_addrs = ["10.0.0.10"]
```

Wardex only trusts mTLS identity headers in production when the remote address matches `security.trusted_mtls_proxy_addrs`. Put the TLS-terminating reverse proxy or load balancer address in that allowlist, or terminate TLS directly in the Wardex listener when that deployment mode is available.

### Kubernetes / Helm secrets

When deploying via Helm, configure secrets in `values.yaml`:

```yaml
env:
  - name: WARDEX_ENV
    value: production
  - name: WARDEX_ADMIN_TOKEN
    valueFrom:
      secretKeyRef:
        name: wardex-secrets
        key: admin-token
  - name: WARDEX_SPOOL_KEY
    valueFrom:
      secretKeyRef:
        name: wardex-secrets
        key: spool-key
  - name: WARDEX_AGENT_TOKEN
    valueFrom:
      secretKeyRef:
        name: wardex-secrets
        key: agent-bootstrap-token
  - name: WARDEX_METRICS_TOKEN
    valueFrom:
      secretKeyRef:
        name: wardex-secrets
        key: metrics-token
  - name: WARDEX_OPENAPI_PUBLIC
    value: "false"

# Mount TLS certs from a Secret or cert-manager
extraVolumes:
  - name: tls-certs
    secret:
      secretName: wardex-tls

extraVolumeMounts:
  - name: tls-certs
    mountPath: /etc/wardex/tls
    readOnly: true
```

### Docker Compose secrets

Create a `.env` file (never committed to version control):

```env
WARDEX_ENV=production
WARDEX_ADMIN_TOKEN=your-256-bit-hex-token-here
WARDEX_SPOOL_KEY=your-persistent-spool-key-here
WARDEX_AGENT_TOKEN=your-agent-bootstrap-token-here
WARDEX_METRICS_TOKEN=your-metrics-token-here
WARDEX_OPENAPI_PUBLIC=false
WARDEX_CORS_ORIGIN=https://wardex.example.com
```

Reference it in `docker-compose.yml`:

```yaml
services:
  wardex:
    env_file: .env
```

## Demo Environment

A demo environment with sample data is available for evaluation and development:

```bash
# Start the server
cargo run

# In a separate terminal, seed sample data (alerts, events, agents)
bash demo/seed.sh
```

The seed script calls the Wardex API to populate alerts, events, and agent registrations
so you can explore the admin console and API without importing real data.

See `demo/docker-compose.yml` for a Docker-based demo setup.
