# @wardex/sdk

Typed TypeScript client for the Wardex private-cloud XDR / SIEM API.

## Install

```bash
npm install @wardex/sdk
```

## Quick start

```ts
import { WardexClient } from "@wardex/sdk";

const client = new WardexClient({
  baseUrl: "https://wardex.example.com",
  apiKey: process.env.WARDEX_TOKEN,
});

const health = await client.health();
console.log(health.status);
```

## Report workflows

```ts
import { WardexClient } from "@wardex/sdk";

const client = new WardexClient({
  baseUrl: "https://wardex.example.com",
  apiKey: process.env.WARDEX_TOKEN,
});

const templates = await client.reportTemplates({
  case_id: "42",
  incident_id: "7",
  investigation_id: "inv-7",
  source: "case",
  scope: "scoped",
});
console.log(templates.templates.map((template) => template.name));

const run = await client.createReportRun({
  name: "Control-plane Failover Drill History",
  kind: "control_plane_failover_history",
  scope: "control_plane",
  format: "json",
  audience: "audit",
  case_id: "42",
  incident_id: "7",
  investigation_id: "inv-7",
  source: "case",
});
console.log(run.run.preview.kind);

const schedule = await client.saveReportSchedule({
  name: "Weekly Control-plane Failover Drill History",
  kind: "control_plane_failover_history",
  scope: "control_plane",
  format: "json",
  cadence: "weekly",
  target: "audit@wardex.local",
});
console.log(schedule.schedule.target);
```

The report helpers expose the same template, persisted run, and delivery schedule flows used by the admin console, including the dedicated `control_plane_failover_history` evidence artifact.