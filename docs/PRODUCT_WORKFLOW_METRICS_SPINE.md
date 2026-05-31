# Wardex Product Workflow And Metrics Spine

Wardex already exposes most of the operator journeys it needs in product terms:
connector onboarding, first-run proof, case handoff, analyst assistant scope,
SOC workbench value summaries, and exportable evidence. What has been missing is
a single definition of what "first value", "ready", and "customer-ready" mean
across those surfaces.

This document fixes the product workflow decisions for the next tranche so
future UI and backend changes can measure value instead of just exposing more
status.

The machine-readable source of truth for this spine lives in
[`docs/product/workflow_metrics_spine.json`](product/workflow_metrics_spine.json).

## Product Decisions

1. Wardex measures workflow progress by proof-bearing states, not wizard
   completion alone.
2. Every canonical workflow needs:
   - a named first-value state,
   - explicit workflow states and events,
   - conversion and latency KPIs,
   - backend and frontend hooks that can be validated in-tree.
3. "Ready" in Wardex means an operator can continue with cited evidence,
   approval context, or exportable artifacts. It does not mean a screen merely
   rendered.
4. Shared workflow analytics should be introduced through one small taxonomy and
   event envelope before adding bespoke counters per feature.
5. Assistant scope parity is the first implementation priority because the UI
   already carries case, incident, investigation, and source context, and
   workflow metrics will be misleading until the backend treats that scope as
   canonical.

## Canonical Workflows

### 1. Connector Setup To Value

- **First value:** the connector has produced normalized Wardex evidence that is
  usable inside a case or hunt workflow.
- **Primary surfaces:** collector status, Command Center, SOC collector pivots.
- **Critical KPIs:** time to validate, time to first ingested event, time to
  first alert/case usage, freshness breach rate, recovery rate.

### 2. First-Run Protected Endpoint Journey

- **First value:** the operator reaches a protected workflow with live telemetry,
  a visible alert, and at least one dry-run proof path completed.
- **Primary surfaces:** Onboarding Wizard, Operator Launchpad, first-run proof
  API.
- **Critical KPIs:** auth-to-first-value time, wizard completion without value
  after 1h/24h, token-to-first-agent-online time, readiness-step drop-off.

### 3. Case Closure And Handoff Readiness

- **First value:** the case has enough evidence, approval continuity, rollback
  context, and ticket/export state for another analyst or customer-facing flow
  to continue without rework.
- **Primary surfaces:** SOC Workbench handoff packet, closure readiness checks,
  ticket sync, export links.
- **Critical KPIs:** readiness score over time, blocking-check frequency,
  handoff completeness, ticket-sync-before-close rate, reopen rate.

### 4. Scoped Analyst Copilot

- **First value:** the assistant returns a cited answer inside the intended
  case/incident/investigation/source scope and the analyst adopts a follow-up
  pivot, note, ticket draft, or handoff draft.
- **Primary surfaces:** Analyst Assistant workspace, scoped pivots, structured
  assistant output.
- **Critical KPIs:** scope mix, citation coverage, quality-gate fail rate,
  answer-to-pivot rate, answer-to-note/draft adoption rate.

### 5. Command Center And SOC Workbench Value Flow

- **First value:** a lane or workbench summary drives a concrete operator action
  such as triage, approval review, handoff, remediation, or release proof.
- **Primary surfaces:** Command Center, workbench overview, manager overview,
  launchpad pivots.
- **Critical KPIs:** lane click-through, drawer-to-action rate, time from lane
  open to first action, changed-since-last-visit counts, value share by lane.

### 6. Customer-Facing Value Reporting

- **First value:** Wardex emits a scoped report or evidence bundle that preserves
  execution context and can be reused during audit, customer handoff, or
  leadership review.
- **Primary surfaces:** report templates, report runs, report schedules,
  evidence bundle preview, Launchpad evidence pack.
- **Critical KPIs:** execution-context coverage, evidence freshness at export,
  rerun/reuse rate, case-close-to-pack time, report scope replay rate.

## Shared Analytics Envelope

The next implementation step should introduce one event envelope before broader
instrumentation:

```json
{
  "workflow": "connector_setup_to_value",
  "entity_id": "aws_cloudtrail",
  "state_from": "validated",
  "state_to": "ingesting",
  "event": "connector_first_event_ingested",
  "timestamp": "2026-05-28T12:00:00Z",
  "context": {
    "tenant_id": "optional",
    "case_id": "optional",
    "incident_id": "optional",
    "source": "optional"
  }
}
```

Required fields are:

- `workflow`
- `entity_id`
- `state_from`
- `state_to`
- `event`
- `timestamp`
- `context`

## Implementation Order

1. Assistant scope parity between frontend intent and backend request contract.
2. Shared workflow taxonomy plus persisted `WorkflowEvent` envelope.
3. First-run and connector first-value instrumentation.
4. Case closure/handoff readiness transition capture.
5. Command Center and reporting attribution for value outcomes.

## Guardrail

Run:

```bash
python3 scripts/check_product_workflow_metrics.py
```

The guardrail validates that:

- Wardex remains the canonical product name in the workflow spine.
- The six canonical workflows, first-value states, priorities, and shared event
  fields remain declared.
- Referenced API routes still exist in product/runtime docs or route catalogs.
- Backend and frontend hooks for the workflow spine still exist in the current
  codebase.

This is intentionally small and fast. It keeps product workflow work grounded in
the repo rather than drifting into deckware.
