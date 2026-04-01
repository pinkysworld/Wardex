#!/usr/bin/env python3
"""Live server endpoint test - exercises all major Wardex API endpoints."""
import json
import urllib.request
import urllib.error
import sys

BASE = "http://localhost:8080"
TOKEN = sys.argv[1] if len(sys.argv) > 1 else ""
passed = 0
failed = 0
errors = []

def req(method, path, body=None, auth=True, expect=200):
    global passed, failed
    url = BASE + path
    headers = {}
    if auth and TOKEN:
        headers["Authorization"] = f"Bearer {TOKEN}"
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    else:
        data = None
    r = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        resp = urllib.request.urlopen(r)
        code = resp.status
        rbody = resp.read().decode()
    except urllib.error.HTTPError as e:
        code = e.code
        rbody = e.read().decode() if e.fp else ""
    status = "PASS" if code == expect else "FAIL"
    if status == "PASS":
        passed += 1
    else:
        failed += 1
        errors.append(f"  {method} {path}: expected {expect}, got {code}")
    print(f"  [{status}] {method} {path} -> {code} (expect {expect})")
    return code, rbody

print("=" * 60)
print("WARDEX LIVE ENDPOINT TEST")
print("=" * 60)

# ── Public endpoints ──
print("\n--- Public Endpoints ---")
req("GET", "/api/health", auth=False)
req("GET", "/api/openapi.json", auth=False)

# ── Auth required (should 401 without token) ──
print("\n--- Auth Enforcement ---")
req("GET", "/api/status", auth=False, expect=401)
req("GET", "/api/events", auth=False, expect=401)
req("GET", "/api/agents", auth=False, expect=401)

# ── Core status endpoints ──
print("\n--- Core Status ---")
req("GET", "/api/status")
req("GET", "/api/config/current")
req("GET", "/api/slo/status")
req("GET", "/api/checkpoints")
req("GET", "/api/correlation")
req("GET", "/api/host/info")

# ── Control endpoints ──
print("\n--- Control ---")
req("POST", "/api/control/mode", body={"mode": "frozen"})
req("POST", "/api/control/mode", body={"mode": "normal"})
req("POST", "/api/control/reset-baseline")
req("POST", "/api/control/checkpoint")
req("POST", "/api/control/run-demo")

# ── Events & Alerts ──
print("\n--- Events & Alerts ---")
req("GET", "/api/events")
req("GET", "/api/alerts")
req("GET", "/api/alerts/count")
req("GET", "/api/audit/log")
req("GET", "/api/events/summary")

# ── Agents ──
print("\n--- Agents ---")
req("GET", "/api/agents")

# ── Cases ──
print("\n--- Cases ---")
req("GET", "/api/cases")
_, body = req("POST", "/api/cases", body={"title": "Test Case", "description": "Live test"}, expect=201)
case_id = None
try:
    case_id = json.loads(body).get("id")
except:
    pass
if case_id:
    req("GET", f"/api/cases/{case_id}")

# ── RBAC ──
print("\n--- RBAC ---")
req("GET", "/api/rbac/users")
req("POST", "/api/rbac/users", body={"username": "testuser", "role": "viewer"}, expect=201)
req("DELETE", "/api/rbac/users/testuser")

# ── Sigma Rules ──
print("\n--- Sigma Rules ---")
req("GET", "/api/sigma/rules")
req("GET", "/api/sigma/stats")

# ── Feature Flags ──
print("\n--- Feature Flags ---")
req("GET", "/api/feature-flags")

# ── Threat Intel ──
print("\n--- Threat Intel ---")
req("GET", "/api/threat-intel/status")
req("POST", "/api/threat-intel/ioc", body={"value": "192.168.1.99", "ioc_type": "ip"})

# ── Process Tree ──
print("\n--- Process Tree ---")
req("GET", "/api/process-tree")

# ── Swarm ──
print("\n--- Swarm ---")
req("GET", "/api/swarm/posture")

# ── Side Channel ──
print("\n--- Side Channel ---")
req("GET", "/api/side-channel/status")

# ── TLS ──
print("\n--- TLS ---")
req("GET", "/api/tls/status")

# ── Detection ──
print("\n--- Detection ---")
req("GET", "/api/detection/summary")
req("GET", "/api/detection/weights")

# ── Telemetry ──
print("\n--- Telemetry ---")
req("GET", "/api/telemetry/current")
req("GET", "/api/telemetry/history")

# ── Fleet ──
print("\n--- Fleet ---")
req("GET", "/api/fleet/status")
req("GET", "/api/fleet/dashboard")
req("GET", "/api/fleet/inventory")

# ── Digital Twin ──
print("\n--- Digital Twin ---")
req("GET", "/api/digital-twin/status")

# ── Compliance ──
print("\n--- Compliance ---")
req("GET", "/api/compliance/status")

# ── Energy ──
print("\n--- Energy ---")
req("GET", "/api/energy/status")

# ── Monitor ──
print("\n--- Monitor ---")
req("GET", "/api/monitor/status")
req("GET", "/api/monitor/violations")

# ── Deception ──
print("\n--- Deception ---")
req("GET", "/api/deception/status")

# ── Drift ──
print("\n--- Drift ---")
req("GET", "/api/drift/status")

# ── Quantum ──
print("\n--- Quantum ---")
req("GET", "/api/quantum/key-status")

# ── Privacy ──
print("\n--- Privacy ---")
req("GET", "/api/privacy/budget")

# ── Fingerprint ──
print("\n--- Fingerprint ---")
req("GET", "/api/fingerprint/status")

# ── Research ──
print("\n--- Research ---")
req("GET", "/api/research-tracks")

# ── SIEM ──
print("\n--- SIEM ---")
req("GET", "/api/siem/status")

# ── Tenants ──
print("\n--- Tenants ---")
req("GET", "/api/tenants/count")

# ── Platform ──
print("\n--- Platform ---")
req("GET", "/api/platform")

# ── Reports ──
print("\n--- Reports ---")
req("GET", "/api/reports")
req("GET", "/api/reports/executive-summary")

# ── Incidents ──
print("\n--- Incidents ---")
req("GET", "/api/incidents")

# ── DLQ ──
print("\n--- Dead Letter Queue ---")
req("GET", "/api/dlq")
req("GET", "/api/dlq/stats")

# ── OCSF ──
print("\n--- OCSF ---")
req("GET", "/api/ocsf/schema", expect=503)  # 503 expected: no schema file loaded
req("GET", "/api/ocsf/schema/version")

# ── Causal Graph ──
print("\n--- Causal ---")
req("GET", "/api/causal/graph")

# ── Attestation ──
print("\n--- Attestation ---")
req("GET", "/api/attestation/status")

# ── Exports ──
print("\n--- Exports ---")
req("GET", "/api/export/tla")
req("GET", "/api/export/alloy")
req("GET", "/api/export/witnesses")

# ── Config management ──
print("\n--- Config Mgmt ---")
req("POST", "/api/config/reload", body={"path": "var/test-config.toml"})

# ── Endpoints listing ──
print("\n--- Endpoints ---")
req("GET", "/api/endpoints")

# ── Rollout ──
print("\n--- Rollout ---")
req("GET", "/api/rollout/config")

# ── Auth check ──
print("\n--- Auth ---")
req("GET", "/api/auth/check")

# ── Unknown endpoint (should 404) ──
print("\n--- Error Handling ---")
req("GET", "/api/nonexistent", expect=404)

# ── Static site ──
print("\n--- Static Site ---")
req("GET", "/", auth=False)
req("GET", "/admin.html", auth=False)

# ── Summary ──
print("\n" + "=" * 60)
print(f"RESULTS: {passed} passed, {failed} failed")
if errors:
    print("FAILURES:")
    for e in errors:
        print(e)
print("=" * 60)
sys.exit(1 if failed else 0)
