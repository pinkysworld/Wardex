# SDK Guide

Wardex ships auto-generated SDKs for Python and TypeScript.  Both are
derived from the OpenAPI specification at `docs/openapi.yaml`.

## Generating the SDKs

Run from the repository root:

```bash
cd sdk && bash generate.sh
```

This uses the OpenAPI Generator CLI to produce client libraries in
`sdk/python/` and `sdk/typescript/`.

### Prerequisites

- Java 11+ (for OpenAPI Generator) or `npx @openapitools/openapi-generator-cli`
- `docs/openapi.yaml` must be up-to-date

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

The full API is documented at `docs/openapi.yaml` (174 paths).  Key areas:

| Area              | Endpoints                              |
|-------------------|----------------------------------------|
| Alerts            | `/api/alerts`, `/api/alerts/{id}`      |
| Fleet             | `/api/fleet/*`, `/api/agents/*`        |
| Detection content | `/api/rules/*`, `/api/sigma/*`         |
| Investigation     | `/api/cases/*`, `/api/incidents/*`     |
| Analyst           | `/api/ask`, `/api/analyst/*`           |
| Compliance        | `/api/compliance/*`                    |
| Feature flags     | `/api/feature-flags/*`                 |
| Health            | `/api/healthz/*`, `/api/status-json`   |
