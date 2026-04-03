# Wardex — Feature Summary

Wardex is a self-hosted XDR and SIEM platform built in Rust for teams that want enterprise-grade detection, investigation, and fleet control without handing their control plane to a third-party cloud.

## Platform capabilities

- **Detection engineering**
  - Sigma and native detection content with Sigma-KernelEvent bridge
  - Saved hunts with thresholds, schedules, owners, and run history
  - Rule testing, promote/rollback lifecycle, suppressions, and content packs
  - MITRE ATT&CK coverage views and threat-summary dashboards
  - Named entity extraction from alert text (IP, domain, hash, MITRE technique, process)

- **SOC operations**
  - Alert queue with SLA awareness, acknowledgement, assignment, and escalation
  - Case management, incident tracking, investigation pivots, process-tree and timeline views
  - Incident storyline generation, evidence packages, and external ticket sync
  - Approval-gated response workflows with pending, approved, executed, denied, and expired states
  - Playbook condition DSL with numeric, string, CONTAINS, and AND/OR compound expressions

- **Threat hunting and analysis**
  - File integrity monitoring with baseline checksums, scan scheduling, and drift detection
  - Memory forensics: RWX region detection, process hollowing analysis, platform-specific collection plans
  - Fleet-wide attack campaign clustering using Jaccard similarity and connected-component analysis
  - Side-channel score fusion integrated into compound threat detector
  - UEBA geo-validation with GeoIP resolver and impossible-travel detection

- **Fleet and deployment**
  - Cross-platform agent enrollment, heartbeat tracking, health snapshots, and per-agent activity
  - Policy distribution, rollout groups, staged deployments, rollback, and cancellation
  - Release catalog management with update checks and deployment history
  - Device fingerprint EWMA drift tracking for impersonation detection

- **Enterprise controls**
  - RBAC with endpoint-level enforcement
  - Session TTL, token rotation, audit and retention controls
  - IDP and SCIM configuration surfaces
  - Change control, admin audit export, diagnostics, and dependency health
  - Digital twin calibration from real-world telemetry

- **Research and AI**
  - Federated learning with convergence loop and differential privacy
  - Deception engine with randomised canary deployment and attacker behavior profiling
  - Privacy-preserving forensics with 4 redaction levels and ZK proofs

- **Integrations and evidence**
  - Structured SIEM output, OCSF normalization, TAXII pull, and threat-intel enrichment
  - Compliance evidence, forensic exports, tamper-evident audit chain, and encrypted event spooling
  - Runbooks, OpenAPI contract, deployment models, disaster recovery guidance, and production hardening docs

## Product posture

- 75 Rust source modules
- 155+ API paths
- 832 automated tests
- GitHub Actions release packaging for Linux, macOS, and Windows

## Operator entry points

- `cargo run -- serve` for the live control plane
- `site/admin.html` for the browser console
- `docs/` for architecture, deployment, runbooks, and status
- GitHub Releases for packaged builds
