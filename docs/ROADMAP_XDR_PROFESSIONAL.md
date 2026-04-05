# Wardex XDR — Professional Roadmap

## Current release baseline

`v0.39.0` delivers the current enterprise control-plane slice:

- SOC Workbench for queue, cases, investigation, and response
- detection engineering with hunts, rule lifecycle, suppressions, and MITRE coverage
- fleet release operations with deployment, rollback, and activity snapshots
- enterprise governance surfaces for RBAC, identity provisioning, change control, audit, and diagnostics

## Next priorities

### Release-gating enterprise work

| Priority | Outcome | Status |
|---|---|---|
| Durable event storage | historical hunts, long-range investigations, and manager reporting at scale | Implemented |
| Enterprise identity completion | SSO flows, stronger group-to-role mapping, provisioning lifecycle validation | Next |
| HA and backup/restore automation | recovery-safe upgrades and resilient control-plane deployment | Implemented |
| Cloud and SaaS collectors | AWS, Azure, GCP, Entra/Okta, M365, and Workspace telemetry intake | Implemented |

### Detection and content maturity

| Priority | Outcome | Status |
|---|---|---|
| Canary promotion for content | safer rollout path for rules and hunts | Planned |
| Richer content packs | packaged detections by use case and environment | Planned |
| Saved-search productization | scheduled searches with better alert routing and reporting | Planned |
| Coverage analytics expansion | stronger ATT&CK and control-to-detection traceability | Planned |

### Scale and ecosystem

| Priority | Outcome | Status |
|---|---|---|
| Time-series/analytics backend | search and retention depth for enterprise scale | Planned |
| Additional collectors | broader cloud, identity, and SaaS visibility | Planned |
| SOAR-lite orchestration | guided, approval-aware automation beyond single response requests | Planned |
| Searchable docs site | richer operator-facing documentation delivery | Planned |

## Success criteria

| Metric | Current (`v0.39.0`) | Target |
|---|---|---|
| Automated tests | 991 | 1,000+ |
| OpenAPI paths | 160+ | maintained on every release |
| Release targets | Linux, macOS, Windows | maintained on every tagged release |
| Control-plane posture | single-node private-cloud | HA-ready enterprise deployment |
| Production hardening | 98% (58/59) | 100% |
| Detection content operations | hunts, rules, suppressions, packs | full canary/promote/distribute lifecycle |
