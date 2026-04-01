# Response Playbooks Runbook

## Overview

SentinelEdge provides automated and analyst-approved response actions through the Response Orchestrator. This runbook covers the response workflow, approval process, and standard playbooks.

## Response Workflow

```
Alert Detected → Sigma Rule Match → Response Action Queued
                                         ↓
                              [Tier Check: Auto / Approval]
                                    ↓              ↓
                              Auto-Execute    Pending Queue
                                    ↓              ↓
                              Audit Logged    Analyst Review
                                              ↓         ↓
                                          Approve     Deny
                                              ↓         ↓
                                          Execute    Log Denial
```

## Response Tiers

| Tier | Auto-Execute | Examples |
|------|-------------|----------|
| **Tier 1** (Low Risk) | Yes | Alert enrichment, log collection, IOC lookup |
| **Tier 2** (Medium Risk) | Configurable | Network isolation, process termination |
| **Tier 3** (High Risk) | No — Requires approval | Full quarantine, credential reset, firewall rule |

## API Endpoints

### View Pending Response Actions

```bash
curl -s http://localhost:9090/api/response/pending | jq
```

### Approve a Response Action

```bash
curl -X POST http://localhost:9090/api/response/approve \
  -H "Content-Type: application/json" \
  -d '{
    "request_id": "resp-001",
    "decision": "approved",
    "approver": "analyst@company.com",
    "reason": "Confirmed malicious activity on host web-03"
  }'
```

### Deny a Response Action

```bash
curl -X POST http://localhost:9090/api/response/approve \
  -H "Content-Type: application/json" \
  -d '{
    "request_id": "resp-001",
    "decision": "denied",
    "approver": "analyst@company.com",
    "reason": "False positive — legitimate admin activity"
  }'
```

### View Approval History

```bash
curl -s http://localhost:9090/api/response/approvals | jq
```

### View Audit Ledger

```bash
curl -s http://localhost:9090/api/response/audit | jq
```

## Standard Playbooks

### PB-001: Brute Force / Credential Storm

**Trigger**: Sigma rules SE-001 (Rapid Auth Failures), score ≥ 5.0

**Steps**:
1. Alert generated with MITRE T1110 (Brute Force)
2. Auto-action: Collect auth logs from target host
3. If >50 failures in 5 min: Queue network isolation (Tier 2)
4. Analyst reviews pending queue
5. If approved: Isolate host, create incident, notify SOC

**API Flow**:
```bash
# 1. Check alert queue
curl -s http://localhost:9090/api/queue/alerts | jq '.queue[] | select(.level == "critical")'

# 2. Create investigation case
curl -X POST http://localhost:9090/api/cases \
  -d '{"title": "Brute Force on web-03", "priority": "high", "event_ids": [42, 43, 44]}'

# 3. Build investigation graph
curl -X POST http://localhost:9090/api/investigation/graph \
  -d '{"event_ids": [42, 43, 44]}'

# 4. Approve isolation
curl -X POST http://localhost:9090/api/response/approve \
  -d '{"request_id": "resp-brute-001", "decision": "approved", "approver": "soc-lead", "reason": "Confirmed brute force"}'
```

### PB-002: Lateral Movement

**Trigger**: Sigma rules SE-014 (SSH Lateral Movement), cross-agent correlation

**Steps**:
1. Correlation engine detects same pattern across ≥2 agents
2. Auto-action: Enrich with process tree data
3. Queue containment for affected hosts (Tier 3)
4. Analyst reviews host timelines and investigation graph
5. If confirmed: Quarantine all affected hosts, escalate case

### PB-003: Ransomware Indicators

**Trigger**: Sigma rule SE-022 (Shadow Copy Deletion)

**Steps**:
1. Critical alert on shadow copy deletion
2. Immediate auto-action: Snapshot current state
3. Queue full network isolation (Tier 3)
4. Analyst reviews within 15 min SLA (critical)
5. If approved: Isolate, preserve evidence, create incident

### PB-004: Persistence Mechanism

**Trigger**: Sigma rules SE-011 (Scheduled Task), SE-018 (LaunchAgent), SE-017 (Cron)

**Steps**:
1. Alert on new persistence mechanism detected
2. Auto-action: Collect registry/file/plist snapshot
3. Compare against known-good baseline
4. If unknown: Queue for analyst review
5. Analyst decides: false positive → dismiss, or investigate → create case

### PB-005: Process Injection

**Trigger**: Sigma rule SE-024 (Process Injection)

**Steps**:
1. Alert with MITRE T1055 on suspicious process access
2. Auto-action: Capture process tree (parent chain)
3. Check if target process is sensitive (lsass, csrss, etc.)
4. If sensitive target: Queue isolation (Tier 3)
5. Full memory forensics recommended

## Case Management Workflow

### Creating a Case from Alerts

```bash
# 1. Search for related events
curl -X POST http://localhost:9090/api/events/search \
  -d '{"hostname": "web-03", "level": "critical", "limit": 20}'

# 2. Create case
curl -X POST http://localhost:9090/api/cases \
  -d '{
    "title": "Suspected compromise of web-03",
    "description": "Multiple critical alerts including brute force and lateral movement",
    "priority": "critical",
    "event_ids": [42, 43, 44, 45],
    "incident_ids": [7],
    "tags": ["brute-force", "lateral-movement"]
  }'

# 3. Assign analyst
curl -X POST http://localhost:9090/api/cases/1/update \
  -d '{"assignee": "analyst-alice"}'

# 4. Add investigation notes
curl -X POST http://localhost:9090/api/cases/1/comment \
  -d '{"author": "analyst-alice", "text": "Initial triage: confirmed suspicious login from external IP"}'

# 5. Attach evidence
curl -X POST http://localhost:9090/api/cases/1/evidence \
  -d '{"kind": "pcap", "reference_id": "pcap-2025-001", "description": "Network capture from web-03 eth0"}'

# 6. Escalate
curl -X POST http://localhost:9090/api/cases/1/update \
  -d '{"status": "escalated"}'
```

### Alert Queue SLA

| Priority | SLA | Auto-Escalation |
|----------|-----|----------------|
| Critical | 1 hour | After 1h, auto-escalate to SOC lead |
| Severe | 4 hours | After 4h, bump priority |
| Elevated | 24 hours | After 24h, add to daily review |
| Low | 72 hours | Weekly review batch |

Monitor SLA status:
```bash
curl -s http://localhost:9090/api/queue/stats | jq
# Returns: total, pending, acknowledged, sla_breached
```

## Escalation Matrix

| Condition | Action |
|-----------|--------|
| Score ≥ 8.0 | Auto-create incident, page on-call |
| Cross-agent correlation | Auto-escalate to Tier 3 |
| MITRE Tactic: Impact | Immediate SOC lead notification |
| SLA breach | Auto-assign to next available analyst |
| ≥3 critical alerts on same host in 1h | Auto-queue quarantine |
