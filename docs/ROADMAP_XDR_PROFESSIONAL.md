# Wardex XDR — Professional Roadmap

> Living document — updated each phase.

## Vision

Evolve Wardex from a research-grade XDR prototype into a production-ready
platform that competes with commercial XDR/SIEM offerings while retaining its
unique research-driven capabilities (formal verification, causal detection,
post-quantum crypto, privacy-preserving analytics).

---

## Tier 1 — Differentiated Capabilities (Phase 28 – 30)

Features that no other open-source XDR offers.

| # | Feature | Phase | Status |
|---|---------|-------|--------|
| R1 | **Counterfactual Detection Simulator** — "what-if" analysis: replay historical telemetry against modified detection rules and compare outcomes. | 28 | Planned |
| R2 | **Causal Attack Storyline** — auto-generate a narrative from the causal graph linking root cause → lateral movement → exfiltration, with MITRE ATT&CK overlay. | 28 | Planned |
| R3 | **Drift Sentinel** — continuous statistical monitoring for concept drift in detector baselines with automatic re-calibration or freeze. | 28 | Planned |
| R4 | **Response Sandboxing** — execute remediation actions in a digital-twin simulation before applying to production agents. | 29 | Planned |
| R5 | **Adaptive Decoy Morphing** — deception engine that mutates decoy artefacts based on attacker TTP fingerprints. | 29 | Planned |
| R6 | **Privacy-Preserving Fleet Learning** — federated learning across agents using differential privacy to share detector improvements without exposing raw telemetry. | 30 | Planned |

---

## Tier 2 — SIEM Parity (Phase 30 – 33)

Bring Wardex up to feature parity with established SIEM platforms.

| # | Feature | Phase | Status |
|---|---------|-------|--------|
| S1 | **STIX/TAXII Integration** — ingest and publish threat intel via TAXII 2.1. | 30 | Planned |
| S2 | **Splunk HEC / ECS / ASIM / UDM Ingest** — accept events in Splunk HTTP Event Collector, Elastic Common Schema, Microsoft ASIM, and Google UDM formats. | 31 | Planned |
| S3 | **Log Source Wizard** — guided UI flow to configure new log sources (syslog, Windows Event Log, cloud audit). | 31 | Planned |
| S4 | **Scheduled Searches & Alerts** — cron-based saved searches with threshold-based alerting. | 32 | Planned |
| S5 | **Custom Dashboards** — drag-and-drop dashboard builder with chart widgets backed by the event API. | 32 | Planned |
| S6 | **SOAR-Lite Playbooks** — visual playbook editor for response orchestration, with conditional logic, approval gates, and webhook actions. | 33 | Planned |

---

## Tier 3 — Enterprise Scale (Phase 33 – 36)

Production hardening and enterprise-grade operations.

| # | Feature | Phase | Status |
|---|---------|-------|--------|
| E1 | **Time-Series Storage Backend** — pluggable storage for event data (embedded ClickHouse / DuckDB / Parquet). | 33 | Planned |
| E2 | **eBPF Agent** — kernel-level telemetry collection on Linux without polling overhead. | 34 | Planned |
| E3 | **Kubernetes Operator** — deploy Wardex as a K8s operator with CRDs for policies, agents, and tenants. | 34 | Planned |
| E4 | **Cloud Audit Collectors** — native collectors for AWS CloudTrail, Azure Activity Log, GCP Audit Logs. | 35 | Planned |
| E5 | **Multi-Region Federation** — cluster-aware deployment with cross-region posture synchronisation and data-sovereignty enforcement. | 35 | Planned |
| E6 | **Compliance Mapping** — automated mapping of detection coverage to NIST CSF, CIS Controls, ISO 27001, and PCI DSS. | 36 | Planned |

---

## Tier 4 — Community & Ecosystem (Ongoing)

| # | Feature | Status |
|---|---------|--------|
| C1 | **WASM Extension SDK** — community-authored detection and response plugins. | In progress (Phase 26 design) |
| C2 | **Sigma Rule Marketplace** — import/export Sigma rules with community sharing. | Planned |
| C3 | **Plugin Registry** — signed plugin distribution with version pinning. | Planned |
| C4 | **Documentation Site** — searchable docs site (mdBook or Docusaurus). | Planned |
| C5 | **OpenTelemetry Exporter** — export traces and metrics to OTEL collectors. | Planned |

---

## Milestone Map

```
Phase 27 ─── ✅ Production Docs & API Spec
Phase 28 ─── Counterfactual Detection, Causal Storyline, Drift Sentinel
Phase 29 ─── Response Sandboxing, Adaptive Decoys
Phase 30 ─── Privacy-Preserving Fleet Learning, STIX/TAXII
Phase 31 ─── Multi-format Ingest, Log Source Wizard
Phase 32 ─── Scheduled Searches, Custom Dashboards
Phase 33 ─── SOAR-Lite, Time-Series Storage
Phase 34 ─── eBPF Agent, Kubernetes Operator
Phase 35 ─── Cloud Collectors, Multi-Region Federation
Phase 36 ─── Compliance Mapping, GA Release
```

## Success Criteria

| Metric | Current (v0.27) | Target (v1.0) |
|--------|----------------|---------------|
| API endpoints | 149 | 200+ |
| Test count | 637+ | 1 000+ |
| Supported log formats | 1 (OCSF) | 6+ |
| Detection rules | Sigma | Sigma + YARA + custom |
| Max agents | 500 (tested) | 10 000 |
| p99 latency | < 50 ms | < 20 ms |
| Binary size | ~15 MB | < 20 MB |
