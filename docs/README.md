# Wardex Documentation

This folder tracks the current shipping product, not just the historical implementation journey.

Read it in this order:

1. [`GETTING_STARTED.md`](GETTING_STARTED.md) for local build, test, and control-plane startup.
2. [`ARCHITECTURE.md`](ARCHITECTURE.md) for the platform pipeline and major subsystems.
3. [`STATUS.md`](STATUS.md) for the current release posture, verification snapshot, and shipped enterprise capabilities.
4. [`DEPLOYMENT_MODELS.md`](DEPLOYMENT_MODELS.md) and [`PRODUCTION_HARDENING.md`](PRODUCTION_HARDENING.md) for deployment and operational readiness.
5. [`runbooks/README.md`](runbooks/README.md) for operator playbooks and integration guidance.
6. [`ROADMAP_XDR_PROFESSIONAL.md`](ROADMAP_XDR_PROFESSIONAL.md) for post-release priorities.

Reference material:

- [`openapi.yaml`](openapi.yaml) — HTTP API contract
- [`THREAT_MODEL.md`](THREAT_MODEL.md) — trust boundaries and abuse cases
- [`DISASTER_RECOVERY.md`](DISASTER_RECOVERY.md) — backup and restore planning
- [`SLO_POLICY.md`](SLO_POLICY.md) — service-level objectives and error budget guidance
- [`SCHEMA_LIFECYCLE.md`](SCHEMA_LIFECYCLE.md) — compatibility and schema evolution policy

Working rule:

- update docs when operator-visible behavior changes
- keep counts, versions, and release posture accurate
- treat the website, README, and docs as one release surface
