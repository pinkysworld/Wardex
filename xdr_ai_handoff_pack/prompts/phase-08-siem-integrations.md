Phase 8: SIEM integrations.

Read AGENTS.md and docs/EXECUTION_PLAN.md first.

Implement production-oriented SIEM integrations:
- generic syslog over TLS export
- generic webhook export
- generic JSON batch export
- Splunk CIM mapping/export
- Elastic ECS mapping/export
- Microsoft Sentinel ASIM-friendly export
- Google SecOps/UDM export
- QRadar integration scaffold
- bi-directional case/alert sync interfaces where practical
- parser conformance tests
- integration health checks and failure telemetry

Deliverables:
- backend/integrations/*
- mapping specs and fixtures
- export retry logic
- integration dashboards/health endpoints
- docs/RUNBOOKS/siem-integrations.md
- compatibility matrix by SIEM

Acceptance criteria:
- canonical events export correctly to supported formats
- parser tests catch mapping regressions
- failed exports are observable and retry safely
- integration docs include exact field mappings and limitations
