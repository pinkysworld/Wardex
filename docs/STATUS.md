# Wardex Status

## Current release

- **Version:** `0.31.0`
- **Positioning:** private-cloud XDR and SIEM platform with enterprise detection engineering, analyst workflows, fleet operations, and governance controls
- **Source footprint:** 61 Rust source modules
- **API contract:** 117 documented OpenAPI paths
- **Verification:** 692 automated tests plus live admin-console smoke coverage

## Shipped in the current platform

### SOC operations

- Dashboard with analyst and manager overviews
- SOC Workbench with queue, cases, investigation pivots, storylines, and response approval flows
- Event search, incident timelines, process-tree inspection, and evidence package export

### Detection engineering

- Sigma and native managed rules
- Rule testing, promotion, rollback, suppressions, content packs, and MITRE coverage
- Saved hunts with thresholds, schedules, owners, history, and scheduled execution

### Fleet and release operations

- Cross-platform enrollment and heartbeat tracking
- Per-agent activity snapshots with version, deployment, inventory, and recent-event context
- Release publishing, rollout assignment, rollback, cancellation, and staged deployment controls

### Governance and enterprise controls

- RBAC, session TTL, token rotation, audit and retention controls
- IDP and SCIM configuration surfaces
- Change control entries, admin audit export, diagnostics bundle, and dependency health endpoints

### Integrations and evidence

- SIEM output, OCSF normalization, TAXII pull, and threat-intel enrichment
- Ticket sync, forensic evidence export, tamper-evident audit chain, and encrypted event buffering
- Deployment, disaster recovery, threat model, SLO, and runbook documentation

## Verification snapshot

The current release has been verified with:

- `cargo test` passing across unit and integration suites
- enterprise API regression coverage for hunts, content lifecycle, suppressions, storylines, governance, and supportability
- live browser smoke coverage of the admin console, including Detection Engineering, Fleet, SOC Workbench, Reports, Settings, and responsive navigation

## Current product posture

Wardex is now positioned as a professional XDR/SIEM control plane rather than an implementation diary. The runtime, admin console, release process, and website have been aligned around operator workflows, deployment readiness, and product documentation.

## Next release priorities

- durable analytics storage for historical search and long-horizon hunts
- stronger identity integration beyond configuration surfaces, including full enterprise SSO workflows
- HA/failover and backup/restore automation
- broader cloud and SaaS collectors
- deeper content engineering workflows such as canary promotion and richer pack distribution
