# SDK Guide

Wardex ships auto-generated SDKs for Python and TypeScript.  Both are
derived from the OpenAPI specification at `docs/openapi.yaml`.

## Generating the SDKs

Run from the repository root:

```bash
bash sdk/generate.sh
```

This uses the OpenAPI Generator CLI to produce client libraries in
`sdk/python/` and `sdk/typescript/`. The generator script reads the release
version directly from `Cargo.toml`, so the SDK package versions stay aligned
with the Rust release version.

### Prerequisites

- Java 11+ (for OpenAPI Generator) or `npx @openapitools/openapi-generator-cli`
- `docs/openapi.yaml` must be up-to-date

### CI drift check

The CI pipeline regenerates the SDKs and fails if the committed SDK files drift from `docs/openapi.yaml`. Run the same validation locally before changing API shapes:

```bash
npm install -g @openapitools/openapi-generator-cli
bash sdk/generate.sh
git diff -- sdk/python sdk/typescript
```

## Python SDK

### Installation

```bash
pip install wardex-sdk
# Or install from source
cd sdk/python && pip install -e .
```

### Quick start

```python
from wardex_sdk import WardexClient

client = WardexClient(base_url="http://localhost:9077", api_key="...")

# List recent alerts
alerts = client.alerts.list(limit=50)
for alert in alerts:
    print(f"{alert.id}: {alert.level} — {alert.summary}")

# Query the LLM analyst
response = client.analyst.ask("What caused the spike in failed SSH logins?")
print(response.answer)

# Get fleet status
agents = client.fleet.list_agents()
for agent in agents:
    print(f"{agent.hostname}: {agent.status}")
```

### Configuration

```python
client = WardexClient(
    base_url="https://wardex.internal:9077",
    api_key="sk-...",
    timeout=30,
    verify_ssl=True,
)
```

## TypeScript SDK

### Installation

```bash
npm install @wardex/sdk
```

### Quick start

```typescript
import { WardexClient } from "@wardex/sdk";

const client = new WardexClient({
  baseUrl: "http://localhost:9077",
  apiKey: "...",
});

// List alerts
const alerts = await client.alerts.list({ limit: 50 });
alerts.forEach((a) => console.log(`${a.id}: ${a.level} — ${a.summary}`));

// Submit telemetry
await client.ingest.csv(csvPayload);
```

## API reference

The full API is documented at `docs/openapi.yaml`. Key areas include:

| Area              | Endpoints                              |
|-------------------|----------------------------------------|
| Alerts            | `/api/alerts`, `/api/alerts/{id}`      |
| Fleet             | `/api/fleet/*`, `/api/agents/*`        |
| Detection content | `/api/rules/*`, `/api/sigma/*`         |
| Hunt bundles      | `/api/hunts`, `/api/content/packs`     |
| Investigation     | `/api/cases/*`, `/api/incidents/*`     |
| Workbench         | `/api/workbench/overview`              |
| Analyst           | `/api/ask`, `/api/analyst/*`           |
| Compliance        | `/api/compliance/*`                    |
| Feature flags     | `/api/feature-flags/*`                 |
| Health            | `/api/healthz/*`, `/api/status-json`   |

Recent additions reflected in the generated SDKs include cookie-aware request credentials, admin session inspection/exchange helpers, collector lifecycle status access, remediation change-review read/write helpers, and signed remediation approval helpers. These updates align SDK consumers with the same HttpOnly-session, collector-ingestion, and approval-chain surfaces now used by the admin console.
