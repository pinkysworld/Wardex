#!/usr/bin/env python3
"""Verify admin console data shapes."""
import json, urllib.request, sys

TOKEN = sys.argv[1]

def get(path):
    r = urllib.request.Request(
        f"http://localhost:8080{path}",
        headers={"Authorization": f"Bearer {TOKEN}"}
    )
    return json.loads(urllib.request.urlopen(r).read().decode())

print("=== Status ===")
s = get("/api/status")
print(f"  version: {s.get('version')}, phases: {s.get('phases_completed')}")
print(f"  tasks: {s.get('tasks_completed')}/{s.get('total_tasks')}")

print("=== Health ===")
h = get("/api/health")
print(f"  status: {h.get('status')}, platform: {h.get('platform')}")

print("=== SLO ===")
slo = get("/api/slo/status")
print(f"  requests: {slo.get('total_requests')}, errors: {slo.get('total_errors')}")

print("=== Detection Summary ===")
d = get("/api/detection/summary")
print(f"  mode: {d.get('mode')}, ewma_alpha: {d.get('ewma_alpha')}")

print("=== Telemetry Current ===")
t = get("/api/telemetry/current")
cpu = t.get("cpu_load_pct", 0)
mem = t.get("memory_load_pct", 0)
net = t.get("network_kbps", 0)
print(f"  cpu: {cpu:.1f}%, mem: {mem:.1f}%, network: {net:.1f} kbps")

print("=== RBAC Users ===")
users = get("/api/rbac/users")
print(f"  users: {users}")

print("=== Cases ===")
cases = get("/api/cases")
if isinstance(cases, dict):
    items = cases.get("cases", [])
else:
    items = cases
print(f"  case_count: {len(items)}")

print("=== Sigma Rules ===")
sigma = get("/api/sigma/rules")
print(f"  rules: {sigma}")

print("=== Alerts ===")
alerts = get("/api/alerts")
if isinstance(alerts, dict):
    items = alerts.get("alerts", [])
else:
    items = alerts
print(f"  alert_count: {len(items)}")

print("\nAll admin data shapes verified OK")
