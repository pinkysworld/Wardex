# Wardex Feature-to-UI Coverage

This tracker exists to keep product claims, admin-console routing, and operator usability aligned.

Status legend:

- `Implemented`: shipped browser workflow is usable end-to-end for normal operators.
- `Ready`: routed UI exists and the workflow is structured enough for normal operator use.
- `Partial`: UI exists but key actions are buried, raw, or incomplete.
- `Missing`: backend capability exists without a meaningful browser workflow.

| Capability area | Primary UI surface | Status | Next closure target |
|---|---|---|---|
| Detection engineering (rules, hunts, suppressions, packs) | `Threat Detection`, `Dashboard`, `Attack Graph` | Partial | Broaden regression coverage and refine remaining long-tail lifecycle promotion flows around the new efficacy, ATT&CK gap, suppression-noise, and rollout drill-downs |
| SOC operations (queue, cases, timelines, approvals) | `SOC Workbench`, `Live Monitor` | Implemented | Expand browser regression coverage around the new route-aware queue, case, investigation, and response pivots |
| Dashboard customization and shared views | `Dashboard` | Implemented | Broaden browser regression coverage around persisted personal presets and shared analyst/admin layouts |
| UEBA, NDR, graph analytics | `UEBA`, `NDR`, `Attack Graph` | Partial | Deepen anomaly narratives, entity/network evidence correlation, and response-specific playbooks on top of the new cross-surface pivots |
| Fleet, rollout, and release operations | `Fleet & Agents` | Partial | Add stronger rollout history, recovery, and deployment-health actions |
| Vulnerability, exposure, drift, certificates, assets | `Infrastructure` | Partial | Finish guided remediation and configuration-review workflows |
| Security policy and advanced controls | `Security Policy` | Implemented | Structured policy composition, digital twin simulation, adversarial harness, deception deployment, and enforcement quarantine workflows are available in the browser console |
| Enterprise controls (RBAC, SSO, SCIM, settings) | `Settings`, login shell | Partial | Complete true end-to-end federated SSO redirect/callback exchange and broader lifecycle validation beyond the shipped provider discovery, sign-in shell, RBAC, SCIM, retention, and collector/secrets workflows |
| Supportability, documentation, and contract verification | `Help & Docs` | Implemented | Keep the shipped parity diagnostics, embedded docs index/content, and operator API/GraphQL explorer aligned with future runtime and SDK releases |
| Reports, compliance, evidence, exports | `Reports & Exports`, `Security Policy` | Implemented | Structured compliance review, evidence bundle export, backend SIEM export formats, GDPR erase, PII scan, and privacy-budget checks are available in the browser console |
| Threat intelligence, enrichment, deception | `Threat Detection`, `Settings`, `Security Policy` | Implemented | Threat Detection now provides browse/filter/action workflows for indicator libraries, enrichment connectors, feed context, recent matches, and deception deployment |
| Long-retention history and search | `Settings` | Ready | Add cross-surface pivots from analyst workflows into the shipped ClickHouse-backed retained-event search and retention controls |
| Cloud, SaaS, and identity collectors | `Settings`, `Infrastructure`, `SOC Workbench` | Partial | Extend the shipped AWS/Azure/GCP, secrets-manager, and case ticket-sync workflows to remaining SaaS and identity collectors plus deeper ingestion-health dashboards |
| AI assistant and RAG analyst workflows | `Analyst Assistant`, `SOC Workbench` | Implemented | Deepen retrieval quality, provider coverage, and analyst handoff workflows on top of the shipped case-aware assistant with citations and ticket-sync pivots |

## Release acceptance gate

Use `make release-acceptance` before release sign-off. The command builds the shipped admin console and Rust binary, validates published site links, and runs the live routed Playwright suite against `WARDEX_BASE_URL`. See `docs/RELEASE_ACCEPTANCE.md` for the exact checklist and manual review criteria.

## Immediate execution order

1. Complete end-to-end federated SSO redirect and callback validation beyond the shipped provider discovery and login shell.
2. Extend remaining SaaS and identity collector workflows beyond the shipped cloud, secrets-manager, and case ticket-sync surfaces.
3. Deepen the remaining UEBA, NDR, and infrastructure remediation workflows that are still marked `Partial`.
4. Broaden release-gate regression depth as new routed workflows ship.