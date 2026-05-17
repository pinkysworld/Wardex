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

### Release-proof helpers

The `v1.0.22` clients expose the same resilience/proof contracts used by the admin console and release gate, plus the workflow-continuity tranche, the CI-repair release helpers, and the refreshed documentation-release surfaces:

```python
client.alerts_page(limit=100)
client.events_page(cursor="100", limit=100, severity="high")
client.audit_log_page(cursor="50", limit=50)
client.workflow_preflight(workflow="release")
client.content_rule_preflight("rule-id", target_status="canary")
client.release_observability_gates()
client.release_provenance()
client.release_upgrade_rehearsal(target_version="1.0.22")
client.clean_release_cut()
client.container_release_parity()
client.release_verification_center()
client.self_hosted_deployment_wizard()
client.data_quality_dashboard()
client.performance_scale_baseline()
client.cluster_failover_execution()
client.secrets_rotation_operations()
client.operator_task_automation()
client.detection_validation_packs()
client.run_playbook("priority-lane-response", alert_id="alert-42")
client.resume_playbook("exec-42", feedback="approved for containment")
client.synthetic_console_monitor()
client.incident_timeline_replay()
client.detection_trust_score()
client.detection_trust_overview()
client.detection_trust_rules()
client.detection_trust_rule("rule-id")
client.detection_trust_tuning_drafts()
client.create_detection_trust_tuning_draft({"rule_id": "rule-id", "draft_type": "threshold_review"})
client.preview_detection_trust_tuning_draft("threshold_review-rule-id")
client.approve_detection_trust_tuning_draft("threshold_review-rule-id")
client.fleet_drift_compliance()
client.operator_work_queue()
client.retention_forecast()
client.adversarial_validation()
client.support_bundle_diff()
client.tenant_isolation_proof()
client.thread_detection_proof()
client.operational_snapshot_policy()
client.prune_operational_snapshots(dry_run=True, keep_latest_per_kind=25)
```

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

// Release-proof and cursor helpers
await client.alertsPage({ limit: 100 });
await client.eventsPage({ cursor: 100, limit: 100, severity: "high" });
await client.auditLogPage({ cursor: 50, limit: 50 });
await client.workflowPreflight({ workflow: "release" });
await client.contentRulePreflight("rule-id", { target_status: "canary" });
await client.releaseObservabilityGates();
await client.releaseProvenance();
await client.releaseUpgradeRehearsal({ targetVersion: "1.0.22" });
await client.cleanReleaseCut();
await client.containerReleaseParity();
await client.releaseVerificationCenter();
await client.selfHostedDeploymentWizard();
await client.dataQualityDashboard();
await client.performanceScaleBaseline();
await client.clusterFailoverExecution();
await client.secretsRotationOperations();
await client.operatorTaskAutomation();
await client.detectionValidationPacks();
await client.runPlaybook("priority-lane-response", "alert-42");
await client.resumePlaybookExecution("exec-42", "approved for containment");
await client.syntheticConsoleMonitor();
await client.incidentTimelineReplay();
await client.detectionTrustScore();
await client.detectionTrustOverview();
await client.detectionTrustRules();
await client.detectionTrustRule("rule-id");
await client.detectionTrustTuningDrafts();
await client.createDetectionTrustTuningDraft({ rule_id: "rule-id", draft_type: "threshold_review" });
await client.previewDetectionTrustTuningDraft("threshold_review-rule-id");
await client.approveDetectionTrustTuningDraft("threshold_review-rule-id");
await client.fleetDriftCompliance();
await client.operatorWorkQueue();
await client.retentionForecast();
await client.adversarialValidation();
await client.supportBundleDiff();
await client.tenantIsolationProof();
await client.threadDetectionProof();
await client.operationalSnapshotPolicy();
await client.pruneOperationalSnapshots({ dry_run: true, keep_latest_per_kind: 25 });
```

## API reference

The full API is documented at `docs/openapi.yaml`. Key areas include:

| Area              | Endpoints                              |
|-------------------|----------------------------------------|
| Alerts            | `/api/alerts`, `/api/alerts/{id}`, `/api/alerts/page` |
| Fleet             | `/api/fleet/*`, `/api/agents/*`        |
| Detection content | `/api/rules/*`, `/api/sigma/*`, `/api/content/rules/{id}/preflight` |
| Hunt bundles      | `/api/hunts`, `/api/content/packs`     |
| Investigation     | `/api/cases/*`, `/api/incidents/*`     |
| Workbench         | `/api/workbench/overview`              |
| Analyst           | `/api/ask`, `/api/analyst/*`           |
| Compliance        | `/api/compliance/*`                    |
| Feature flags     | `/api/feature-flags/*`                 |
| Health            | `/api/healthz/*`, `/api/status-json`, `/api/release/observability-gates`, `/api/workflows/preflight` |
| Production assurance | `/api/release/provenance`, `/api/release/upgrade-rehearsal`, `/api/monitoring/synthetic-console`, `/api/incidents/timeline-replay`, `/api/detection/trust-score`, `/api/fleet/drift-compliance`, `/api/operator/work-queue`, `/api/retention/forecast`, `/api/validation/adversarial`, `/api/support/bundle-diff` |
| Release verification | `/api/release/clean-cut`, `/api/containers/release-parity`, `/api/release/verification-center`, `/api/deployment/self-hosted-wizard`, `/api/data-quality/dashboard`, `/api/performance/scale-baseline`, `/api/cluster/failover-execution`, `/api/secrets/rotation-operations`, `/api/operator/task-automation`, `/api/detection/validation-packs` |

Recent additions reflected in the generated SDKs include cookie-aware request credentials, admin session inspection/exchange helpers, Command Center summary and per-lane access with explicit Python and TypeScript response models, collector lifecycle status access, remediation change-review read/write helpers, signed remediation approval helpers, rollback verification helpers, detection tuning profiles, normalized scoring, health probes, false-positive feedback, fleet remote install history/actions, process thread snapshots, backup listing/creation/status helpers, evidence collection plans, local host application/inventory inspection, cursor-page traversal, workflow/rule preflight proof, tenant isolation proof, thread-baseline proof, snapshot retention controls, release observability gates, production assurance helpers for provenance, rehearsal, synthetic monitoring, incident replay, detection trust, fleet drift, operator queues, retention forecast, adversarial validation, support bundle diffing, and release verification helpers for clean cuts, container parity, deployment wizard state, data quality, scale baselines, failover execution, secret rotation, task automation, and validation packs. These updates align SDK consumers with the same HttpOnly-session, command-center, collector-ingestion, approval-chain, recovery-proof, detection-tuning, fleet-install, backup, host-context, and release-proof surfaces now used by the admin console.
