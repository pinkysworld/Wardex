Phase 11: Production hardening, SRE, compliance.

Read AGENTS.md and docs/EXECUTION_PLAN.md first.

Harden the platform for production:
- HA deployment patterns
- backups and restore validation
- SLOs and error budgets
- metrics/logs/traces
- secret management
- staged rollouts
- signed updates/content
- SBOM generation
- vulnerability scanning
- tenant isolation tests
- chaos testing plan
- disaster recovery runbooks
- retention and deletion workflows
- regional deployment scaffolding
- compliance evidence checklist

Deliverables:
- infra IaC
- deployment runbooks
- observability dashboards
- backup/restore tests
- SBOM pipeline
- security scanning pipeline
- docs for SLOs, DR, and operations

Acceptance criteria:
- restore path tested
- observability is meaningful
- rollout/rollback documented and testable
- supply-chain artifacts exist
- production checklist is explicit and evidence-backed
