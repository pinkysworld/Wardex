# wardex — Python SDK

Thin Python client for the **Wardex** private-cloud XDR / SIEM REST API.

## Install

```bash
pip install .          # from this directory
# or
pip install wardex     # once published to PyPI
```

## Quick start

```python
from wardex import WardexClient

client = WardexClient("https://wardex.example.com", token="your-api-token")

# Auth / session
print(client.auth_check())

# Fleet
agents = client.list_agents()
print(agents[0]["id"] if agents else "no agents")

# Ingest an agent event batch
client.ingest_event(
    {"hostname": "sensor-1", "level": "Elevated", "score": 2.1, "reasons": ["SDK sample"]},
    agent_id="sensor-1",
)
```

## Report workflows

```python
from wardex import WardexClient

client = WardexClient("https://wardex.example.com", token="your-api-token")

# Discover reusable templates for the active investigation context.
templates = client.report_templates(
    case_id="42",
    incident_id="7",
    investigation_id="inv-7",
    source="case",
    scope="scoped",
)
print([template["name"] for template in templates["templates"]])

# Create a dedicated failover-drill history artifact for auditors.
run = client.create_report_run(
    {
        "name": "Control-plane Failover Drill History",
        "kind": "control_plane_failover_history",
        "scope": "control_plane",
        "format": "json",
        "audience": "audit",
        "case_id": "42",
        "incident_id": "7",
        "investigation_id": "inv-7",
        "source": "case",
    }
)
print(run["run"]["preview"]["kind"])

# Schedule the same artifact for weekly delivery.
schedule = client.save_report_schedule(
    {
        "name": "Weekly Control-plane Failover Drill History",
        "kind": "control_plane_failover_history",
        "scope": "control_plane",
        "format": "json",
        "cadence": "weekly",
        "target": "audit@wardex.local",
    }
)
print(schedule["schedule"]["target"])
```

## API coverage

| Area | Methods |
|---|---|
| Authentication | `auth_check()`, `rotate_token()`, `session_info()`, `logout()`, `whoami()` |
| Status | `status()`, `health()`, `openapi_spec()` |
| Alerts | `list_alerts()`, `get_alert()` |
| Incidents | `list_incidents()`, `get_incident()`, `create_incident()`, `update_incident()` |
| Fleet | `list_agents()`, `get_agent()`, `get_agent_activity()`, `isolate_agent()` |
| Detection | `run_detection()`, `get_baseline()` |
| Telemetry | `ingest_event()`, `ingest_batch()` |
| Policy | `list_policies()`, `get_policy()`, `update_policy()` |
| Threat Intel | `add_ioc()`, `get_threat_intel_status()` |
| Response | `list_actions()`, `request_response_action()`, `approve_response_action()`, `execute_approved_actions()` |
| Reports | `generate_report()`, `list_reports()`, `report_templates()`, `save_report_template()`, `report_runs()`, `create_report_run()`, `report_schedules()`, `save_report_schedule()` |
| Config | `get_config()`, `update_config()` |
| Metrics | `metrics()` |

Notes:

- The server uses bearer tokens rather than username/password login, so `login()` now fails fast with guidance instead of calling a non-existent route.
- `ack_alert()` and `resolve_alert()` also fail fast with guidance because the current server exposes queue acknowledgement and event triage workflows instead of dedicated alert mutation routes.
- `ingest_event()` and `ingest_batch()` send the current event-batch envelope expected by `/api/events`.
- `generate_report()` maps to the currently exposed report endpoints: `full/latest/analysis` use `/api/report`, and `executive-summary` uses `/api/reports/executive-summary`.
- The report workflow helpers mirror the reusable template, persisted run, and schedule endpoints used by the admin console, including the `control_plane_failover_history` artifact kind for dedicated failover-drill evidence.
