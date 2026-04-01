Phase 9: Response orchestration.

Read AGENTS.md and docs/EXECUTION_PLAN.md first.

Implement response orchestration with strict guardrails:
- isolate host
- kill process tree
- quarantine file
- block indicator submission interfaces
- disable or suspend account via pluggable identity adapters
- force re-auth/session revoke interfaces
- approval workflows
- dry-run mode
- rollback markers where possible
- immutable response audit trail
- blast-radius checks
- protected asset tagging (domain controllers, jump boxes, CI runners, etc.)

Deliverables:
- backend/response-orchestrator
- approval workflow model
- policy engine for response permissions
- response simulation mode
- docs/RUNBOOKS/response-playbooks.md

Acceptance criteria:
- destructive actions require explicit approval unless policy allows otherwise
- dry-run outputs are clear
- every action is audited
- protected assets cannot be remediated unsafely by default
- tests cover approval and policy edge cases
