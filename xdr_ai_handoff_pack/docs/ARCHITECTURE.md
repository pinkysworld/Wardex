# Architecture Baseline

## Product intent
This platform is a production-grade XDR with SIEM integration. It collects endpoint and adjacent telemetry, normalizes it into a vendor-neutral event model, runs deterministic and behavioral detections, orchestrates guarded response actions, and interoperates with major SIEM platforms.

## Core architectural stance
- Use a shared Rust agent core for cross-platform consistency.
- Use OS-specific collectors instead of pretending telemetry parity exists across all operating systems.
- Normalize internally to an OCSF-aligned canonical event model.
- Keep transport OpenTelemetry-compatible where practical.
- Treat SIEM interoperability as a first-class product capability.
- Keep response actions auditable, policy-gated, and safe by default.

## High-level system components

### 1. Agent plane
The agent plane runs on endpoints and hosts.

Components:
- Rust agent core
- Windows collector
- Linux collector
- macOS collector
- later Unix compatibility collector
- local encrypted spool
- local policy cache
- health and diagnostics module
- upgrade and rollback hooks

Responsibilities:
- endpoint enrollment
- local policy application
- telemetry collection
- queueing and batching
- secure transport to ingest services
- degraded offline behavior

### 2. Ingest plane
The ingest plane authenticates, validates, and routes telemetry.

Components:
- gateway service
- schema validation layer
- replay and idempotency controls
- dead-letter handling
- rate limiting and tenant isolation checks

Responsibilities:
- receive telemetry over authenticated channels
- validate event envelopes
- apply tenant-aware routing
- persist raw events
- forward to normalization

### 3. Data plane
The data plane stores raw, normalized, and detection-ready data.

Components:
- raw immutable event store
- normalized event store
- searchable hot store
- long-term object storage
- graph store for entity relationships
- feature store for future anomaly and UEBA workflows

Responsibilities:
- durable storage
- query support
- replay support
- retention and deletion controls
- data residency support

### 4. Detection plane
The detection plane evaluates events and generates alerts.

Components:
- rule engine
- Sigma translation or compilation pipeline
- streaming correlation engine
- suppression and deduplication layer
- ATT&CK mapping metadata
- content test and replay harness

Responsibilities:
- deterministic detections
- behavioral chaining
- severity and confidence assignment
- alert enrichment
- replay-based validation

### 5. Response plane
The response plane performs guarded remediation.

Components:
- response orchestrator
- approval workflow engine
- dry-run simulation
- protected asset guardrails
- immutable response audit ledger
- adapters for identity, endpoint, and network actions

Responsibilities:
- isolate host
- kill process tree
- quarantine artifact
- revoke sessions or disable accounts
- submit indicators to enforcement systems
- ensure approvals and blast-radius checks

### 6. Integration plane
The integration plane connects the XDR to external systems.

Components:
- Splunk CIM export
- Elastic ECS export
- Sentinel ASIM-friendly export
- Google SecOps UDM export
- QRadar integration scaffold
- generic syslog/TLS export
- generic webhook and JSON export
- STIX/TAXII intelligence exchange later

Responsibilities:
- outbound export
- optional inbound alert or case sync
- field mapping maintenance
- parser conformance testing
- health monitoring and retry handling

### 7. Control plane
The control plane manages tenants, users, policies, and fleet state.

Components:
- tenant service
- identity/auth service
- RBAC and future ABAC hooks
- policy distribution service
- device enrollment service
- audit log service
- configuration APIs

Responsibilities:
- multi-tenancy
- user and role management
- certificate and enrollment lifecycle
- signed policy distribution
- fleet inventory and posture views

### 8. Analyst experience
The analyst console is the primary operational interface.

Components:
- alert queue
- case and incident management
- asset and user timelines
- process trees
- event search
- graph investigation view
- evidence export
- SIEM deep-links

Responsibilities:
- triage
- investigation
- collaboration
- case management
- controlled remediation approval

## Trust boundaries
1. Endpoint to control plane
2. Endpoint to ingest gateway
3. Internal service-to-service communication
4. Tenant-separated data access paths
5. External integration adapters
6. Analyst UI to backend APIs

Each trust boundary must enforce authentication, authorization, transport security, and auditable actions.

## Deployment model
Preferred initial deployment model:
- SaaS control plane
- regional ingest endpoints
- optional single-tenant deployment later
- optional relay/collector for constrained networks later

## Data model approach
The system should maintain three layers:
1. Raw immutable events
2. Canonical normalized events
3. Detection-ready and investigation-ready derived views

Do not collapse these layers early. Keeping them distinct improves replay, schema evolution, and forensic traceability.

## OS support tiers
### Tier 1
- Windows 10/11
- Windows Server 2019/2022/2025
- Ubuntu LTS
- Debian
- RHEL
- SUSE
- Amazon Linux
- macOS current minus two major versions

### Tier 2
- container hosts
- Kubernetes worker nodes
- VDI environments
- immutable Linux variants where collection is constrained

### Tier 3
- FreeBSD
- AIX
- Solaris/Illumos
- other niche Unix systems

Tier 3 should begin as reduced-fidelity compatibility collection, not full parity EDR.

## Security assumptions
- mTLS is required for agent and service channels.
- Secrets are not stored in source control.
- Policy bundles and agent updates should be signed.
- Sensitive actions require audit records.
- Destructive response actions require approval or explicit policy exception.

## Immediate architectural priorities
1. multi-tenant secure control plane
2. reliable ingest and normalization
3. shared agent core
4. Windows, Linux, and macOS collectors
5. deterministic detection engine
6. SIEM interoperability
7. response safety and auditability
8. production hardening and compliance

## Deferred architecture topics
- federated learning and privacy-preserving analytics
- advanced deception subsystems
- air-gapped deployment packaging
- global control-plane sharding
- fully autonomous remediation
