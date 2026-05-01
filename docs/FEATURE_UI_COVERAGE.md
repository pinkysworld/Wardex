# Wardex Feature-to-UI Coverage

This tracker exists to keep product claims, admin-console routing, and operator usability aligned.

Status legend:

- `Implemented`: shipped browser workflow is usable end-to-end for normal operators.
- `Ready`: routed UI exists and the workflow is structured enough for normal operator use.
- `Partial`: UI exists but key actions are buried, raw, or incomplete.
- `Missing`: backend capability exists without a meaningful browser workflow.

| Capability area | Primary UI surface | Status | Next closure target |
|---|---|---|---|
| Cross-product command and workflow federation | `Command Center`, `SOC Workbench`, `Settings`, `Threat Detection`, `Infrastructure`, `Analyst Assistant`, `Reports & Exports` | Ready | Keep the shipped action drawers, live release-gate route coverage, lane annotations, and focused lane-refresh contracts aligned as new workflows land |
| Detection engineering (rules, hunts, suppressions, packs) | `Threat Detection`, `Dashboard`, `Attack Graph` | Ready | Keep the URL-backed drilldowns, replay-corpus gate, and rule-panel handoffs covered as efficacy, ATT&CK gap, suppression-noise, and rollout workflows continue to evolve |
| SOC operations (queue, cases, timelines, approvals) | `SOC Workbench`, `Live Monitor` | Implemented | Keep the route-aware queue, case, investigation, and response pivots aligned as deeper escalation, approval, and playbook detail grows |
| Dashboard customization and shared views | `Dashboard` | Implemented | Keep the new priority-alert-aware report-center handoffs and persisted personal/shared layouts covered as the overview evolves |
| UEBA, NDR, graph analytics | `UEBA`, `NDR`, `Attack Graph` | Ready | Broaden regression coverage around the shipped entity/network playbooks, enriched explainability scoring, and stored-event campaign clustering, then keep tightening deeper evidence correlation and analyst narrative quality |
| Fleet, rollout, and release operations | `Fleet & Agents` | Ready | Keep the route-aware rollout history, recovery watchlists, and deployment-health actions aligned as fleet workflows deepen and live release telemetry expands |
| Vulnerability, exposure, drift, certificates, assets | `Infrastructure` | Ready | Keep the shipped malware verdict, guided remediation, signed approval-chain, rollback-proof verification, and recovery-history workflows covered while expanding live rollback execution |
| Security policy and advanced controls | `Security Policy` | Implemented | Structured policy composition, digital twin simulation, adversarial harness, deception deployment, and enforcement quarantine workflows are available in the browser console |
| Enterprise controls (RBAC, SSO, SCIM, settings) | `Settings`, login shell | Ready | Keep the new federated sign-in readiness center, launch validation, and SCIM handoff coverage aligned as broader IdP lifecycle validation evolves |
| Supportability, documentation, and contract verification | `Help & Docs` | Implemented | Keep the shipped parity diagnostics, embedded docs index/content, and operator API/GraphQL explorer aligned with future runtime and SDK releases |
| Reports, compliance, evidence, exports | `Reports & Exports`, `Security Policy` | Implemented | Structured compliance review, evidence bundle export, backend SIEM export formats, GDPR erase, PII scan, and privacy-budget checks are available in the browser console |
| Threat intelligence, enrichment, deception | `Threat Detection`, `Settings`, `Security Policy` | Implemented | Threat Detection now provides browse/filter/action workflows for indicator libraries, enrichment connectors, feed context, recent matches, and deception deployment |
| Long-retention history and search | `Settings` | Ready | Add cross-surface pivots from analyst workflows into the shipped ClickHouse-backed retained-event search and retention controls |
| Cloud, SaaS, and identity collectors | `Settings`, `Infrastructure`, `SOC Workbench` | Ready | Keep the routed collector-health lanes covered while regression-testing per-provider analytics, ingestion evidence, and cross-surface analyst pivots |
| AI assistant and RAG analyst workflows | `Analyst Assistant`, `SOC Workbench` | Implemented | Deepen retrieval quality, provider coverage, and analyst handoff workflows on top of the shipped case-aware assistant with citations and ticket-sync pivots |

## Release acceptance gate

Use `make release-acceptance` before release sign-off. The command builds the shipped admin console and Rust binary, validates published site links, starts a temporary local Wardex instance by default, and runs the live routed Playwright suite against `WARDEX_BASE_URL`. Set `WARDEX_RELEASE_ACCEPTANCE_MODE=external` to point the gate at an already running instance instead. See `docs/RELEASE_ACCEPTANCE.md` for the exact checklist and manual review criteria.

## Immediate execution order

1. Keep the explicit Command Center OpenAPI schemas, typed Python and TypeScript SDK models, per-lane SDK helpers, and release-gate coverage aligned as new command workflows land.
2. Keep the Python package exports and the TypeScript interfaces aligned whenever Command Center lane fields or metric keys change.
3. Continue broadening live Command Center smoke depth only when new routed workflows or operator actions actually ship.
