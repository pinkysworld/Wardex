# Troubleshoot

Use this index for incident response, support triage, and runtime diagnostics.

## Primary Runbooks

1. [`runbooks/troubleshooting.md`](runbooks/troubleshooting.md) — common failures and diagnostics
2. [`runbooks/response-playbooks.md`](runbooks/response-playbooks.md) — response and remediation workflows
3. [`runbooks/spool-recovery.md`](runbooks/spool-recovery.md) — spool and persistence recovery

## Diagnostic Bundle

Capture and attach this minimum evidence set to operator escalations:

```bash
wardex doctor --json
curl -s http://127.0.0.1:9077/api/release/doctor
curl -s http://127.0.0.1:9077/api/support/bundle
```

## Escalation

If release/contract checks fail, include:

- `scripts/check_contract_parity.py` output
- `scripts/check_architecture_guardrails.py` output
- `scripts/check_product_workflow_metrics.py` output
