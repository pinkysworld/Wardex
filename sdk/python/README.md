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

# Status
print(client.status())

# Alerts
alerts = client.list_alerts(limit=20)
for a in alerts:
    print(a["id"], a["level"])

# Ingest telemetry
client.ingest_event({"device_id": "sensor-1", "cpu": 42.0, "mem": 1024})
```

## API coverage

| Area | Methods |
|---|---|
| Authentication | `login()`, `logout()`, `whoami()` |
| Status | `status()`, `health()` |
| Alerts | `list_alerts()`, `get_alert()`, `ack_alert()`, `resolve_alert()` |
| Incidents | `list_incidents()`, `get_incident()`, `create_incident()`, `escalate()` |
| Fleet | `list_agents()`, `get_agent()`, `isolate_agent()`, `unisolate_agent()` |
| Detection | `run_detection()`, `get_baseline()` |
| Telemetry | `ingest_event()`, `ingest_batch()` |
| Policy | `list_policies()`, `get_policy()`, `update_policy()` |
| Threat Intel | `list_iocs()`, `add_ioc()`, `query_ioc()` |
| Response | `list_actions()`, `execute_action()` |
| Reports | `generate_report()`, `list_reports()` |
| Config | `get_config()`, `update_config()` |
| Metrics | `metrics()` |
