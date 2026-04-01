# Threat Model

## Objective
Identify the highest-risk threats to the XDR platform and establish initial controls, assumptions, and review areas.

## Assets to protect
- tenant telemetry
- tenant identities and roles
- enrollment credentials and device certificates
- policy bundles
- response action permissions
- alert, case, and audit data
- integration credentials for SIEM, identity, and cloud platforms
- software build and update pipeline artifacts

## Adversaries
1. External attacker targeting the SaaS control plane
2. Malicious insider with administrative access
3. Compromised tenant admin abusing legitimate privileges
4. Adversary on an endpoint attempting to disable or evade the agent
5. Supply-chain attacker targeting builds, packages, or update channels
6. Integration-layer attacker abusing outbound connectors or credentials

## High-level abuse cases
- forge or replay telemetry
- enroll rogue devices
- escalate privileges across tenants
- exfiltrate tenant telemetry from storage or APIs
- tamper with detections or suppress alerts
- trigger destructive response actions on protected assets
- poison event mappings or SIEM integrations
- replace a signed build or update artifact
- crash or starve ingestion services
- force excessive data retention or prevent deletion

## Trust boundaries
- endpoint to control plane
- endpoint to ingest gateway
- control plane to data plane
- service to service internal mesh
- analyst browser to backend APIs
- external integration adapters to third-party services

## Security objectives
- strong tenant isolation
- authenticated devices and services
- tamper-evident audit trails
- least privilege for users, services, and agents
- safe remediation with approvals and blast-radius controls
- secure software supply chain
- resilient ingest and replay handling
- controlled retention and deletion

## Initial mitigations
### Identity and access
- SSO-ready auth model
- RBAC first, ABAC hooks later
- MFA for privileged users
- service-account scoping
- time-bounded credentials where possible

### Transport and crypto
- mTLS for device and service channels
- per-tenant or scoped credentials where practical
- certificate rotation plan
- encrypted local spool on endpoints

### Agent safety
- signed updates
- watchdog and recovery hooks
- explicit uninstall protection strategy
- least-privilege collection model where practical
- capability detection and graceful degradation

### Backend safety
- tenant-aware authorization at every API boundary
- idempotency and replay protection on ingest
- dead-letter handling for malformed or suspicious input
- audit logging for admin and response actions
- secrets in managed secret stores

### Response safety
- approval workflows
- dry-run simulation
- protected asset tagging
- immutable response audit records
- rollback markers where feasible

### Supply chain
- SBOM generation
- provenance/attestation where possible
- dependency scanning
- release signing
- CI isolation review

## Security reviews required by phase
- Phase 1: authn/authz and tenant isolation
- Phase 2: ingest spoofing, replay, and schema validation
- Phase 3: agent enrollment, spool encryption, update safety
- Phase 4-6: OS-specific permissions and bypass/evasion review
- Phase 7: detection tampering and content integrity review
- Phase 8: integration credential handling and parser safety
- Phase 9: remediation abuse and blast-radius review
- Phase 11: backup/restore, DR, secrets, and operational resilience review

## Open questions
- how device identity issuance and revocation will work at scale
- how much tenant-configurable scripting, if any, will be allowed in response playbooks
- how to handle highly regulated data localization from day one
- how to support offline or semi-air-gapped update channels safely
