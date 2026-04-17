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

This starts the HTTP server on port `8080`, launches the embedded local monitor, and prints a one-time admin token to the terminal. Open `http://localhost:8080/admin/`, paste the token, and use the console to:

`http://localhost:8080/admin/` is the local backend-served console that comes from `cargo run`. If you launch the frontend with `cd admin-console && npm run dev`, the browser URL is `http://localhost:5173/admin/` while the Vite dev server proxies API traffic back to `127.0.0.1:8080`.

- inspect the Dashboard, Fleet & Agents, Threat Detection, Reports, and Settings surfaces
- work cases and alerts in the SOC Workbench
- manage hunts, rules, suppressions, and MITRE coverage in Detection Engineering
- review per-agent activity, deployment health, rollout targets, and rollback controls
- inspect diagnostics, dependency health, audit posture, and identity/provisioning configuration

## Export the static status snapshot

```bash
cargo run -- status-json site/data/status.json
```

This refreshes the structured status payload consumed by the static site and offline views.

## Run tests

```bash
cargo test
```

The current release passes 1345 automated tests (1161 lib + 184 integration) across unit and integration coverage, including API regression coverage for hunts, content lifecycle, suppressions, entity pivots, incident storyline, governance, and supportability.

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

Paste the admin token (printed by the backend or written to `var/.wardex_token`) into the login form.

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
| `WARDEX_ADMIN_TOKEN` | Override the auto-generated admin token. Set this in production to a 256-bit random hex string. | Auto-generated at startup |
| `WARDEX_BIND` | Listen address and port. | `0.0.0.0:8080` |
| `WARDEX_CONFIG_PATH` | Explicit path to the runtime config file. Useful for packaged service installs. | Auto-discovered `var/wardex.toml` |
| `SENTINEL_CORS_ORIGIN` | Allowed CORS origin(s) for the admin console. | `http://localhost:8080` |
| `WARDEX_LOG_LEVEL` | Log verbosity (`trace`, `debug`, `info`, `warn`, `error`). | `info` |
| `WARDEX_DATA_DIR` | Path to the data directory. | `var/` |

### TLS configuration

To enable TLS for the HTTP listener, set the following in `var/config.toml`:

```toml
[tls]
cert_path = "/path/to/cert.pem"
key_path  = "/path/to/key.pem"
```

For mutual TLS (mTLS) agent authentication, add:

```toml
[tls]
cert_path      = "/path/to/cert.pem"
key_path       = "/path/to/key.pem"
client_ca_path = "/path/to/ca.pem"
```

### Kubernetes / Helm secrets

When deploying via Helm, configure secrets in `values.yaml`:

```yaml
env:
  - name: WARDEX_ADMIN_TOKEN
    valueFrom:
      secretKeyRef:
        name: wardex-secrets
        key: admin-token

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
WARDEX_ADMIN_TOKEN=your-256-bit-hex-token-here
SENTINEL_CORS_ORIGIN=https://wardex.example.com
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
