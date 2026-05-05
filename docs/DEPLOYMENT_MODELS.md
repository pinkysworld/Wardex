# Deployment Models

> T216 — Phase 27

## Overview

Wardex supports multiple deployment topologies ranging from a single-node
lab instance to a geo-distributed multi-tenant fleet.  This document describes
each model, its trade-offs, and configuration guidance.

---

## Model 1 — Single-Tenant Standalone

```
┌──────────────────┐
│  Wardex Server   │
│  (all-in-one)    │
│  + Admin UI      │
└────────┬─────────┘
         │ HTTP / mTLS
    ┌────┴────┐
    │ Agent 1 │ … N
    └─────────┘
```

**Use case**: Small lab, single-site OT/IoT deployment.

| Property | Value |
|----------|-------|
| Agents | 1 – 50 |
| HA | None (restart recovery) |
| State | Local `var/` directory |
| Auth | Single admin token |
| Config | `wardex serve --config var/config.toml` |

---

## Model 2 — Multi-Tenant

```
┌─────────────────────────┐
│  Wardex Server          │
│  MultiTenantManager     │
│  ├─ tenant-a (isolated) │
│  └─ tenant-b (isolated) │
└────────┬────────────────┘
         │
    Agents tagged with tenant_id
```

**Use case**: MSSP or shared-infrastructure deployment.

| Property | Value |
|----------|-------|
| Agents | 50 – 500 per tenant |
| Isolation | Tenant-scoped RBAC, event store, case store |
| Auth | Per-tenant admin tokens + RBAC users |
| Config | `[multi_tenant]` section in TOML |

### Configuration

```toml
[multi_tenant]
enabled = true
tenants = ["tenant-a", "tenant-b"]
```

Agents enroll with a `tenant_id` field in the enrollment payload.
All subsequent queries are scoped by tenant.

---

## Model 3 — Edge Relay

```
┌───────────┐       ┌───────────────┐
│ Edge Node │──WAN──│ Central Server│
│ (relay)   │       │ (aggregator)  │
└─────┬─────┘       └───────────────┘
      │ LAN
  Agents 1…N
```

**Use case**: Air-gapped or bandwidth-constrained sites.

| Property | Value |
|----------|-------|
| Edge node | Wardex in relay mode (`--relay`) |
| Spooling | Encrypted spool with store-and-forward |
| Connectivity | Periodic sync via `POST /api/events` batch |
| Offline operation | Full detection locally; alerts queued |

### Configuration

```toml
[relay]
enabled = true
upstream = "https://central.example.com"
sync_interval_secs = 300
spool_max_bytes = 104857600  # 100 MB
```

---

## Model 4 — Regional Federation

```
┌───────────┐    ┌───────────┐    ┌───────────┐
│ Region EU │    │ Region US │    │ Region AP │
│  Wardex   │◄──►│  Wardex   │◄──►│  Wardex   │
└───────────┘    └───────────┘    └───────────┘
       │ swarm protocol
       ▼
  Shared posture via /api/swarm/posture
```

**Use case**: Global enterprise with data-sovereignty requirements.

| Property | Value |
|----------|-------|
| Regions | 2 – 10 |
| Data residency | Events stay in-region |
| Cross-region | Posture scores + threat intel shared via swarm |
| Consistency | Eventual (crdt-like merge of posture vectors) |

---

## Choosing a Model

| Criterion | Standalone | Multi-Tenant | Edge Relay | Federation |
|-----------|-----------|-------------|-----------|-----------|
| Setup complexity | Low | Medium | Medium | High |
| Agent scale | ≤ 50 | ≤ 500/tenant | ≤ 100/relay | ≤ 10 000 |
| Data sovereignty | N/A | Shared infra | Per-site | Per-region |
| Offline capable | Yes | No | Yes | Partial |
| HA | Manual | Load-balancer | Relay failover | Cross-region |

## Hardware Guidelines

| Component | Standalone | Multi-Tenant | Relay |
|-----------|-----------|-------------|-------|
| CPU | 2 cores | 4 cores | 1 core |
| RAM | 512 MB | 2 GB | 256 MB |
| Disk | 1 GB | 10 GB | 500 MB |
| Network | 1 Mbps | 10 Mbps | 100 kbps |

## Sizing Guide

| Fleet Size | Recommended Model | CPU | RAM | Disk | Notes |
|-----------|-------------------|-----|-----|------|-------|
| 1 – 50 agents | Standalone | 2 vCPU | 2 GB | 20 GB | Good fit for labs, branch offices, and evaluation installs |
| 50 – 500 agents | Multi-Tenant or Edge Relay + Central | 4 – 8 vCPU | 8 GB | 100 GB | Keep backups and event retention outside the root filesystem |
| 500 – 5 000 agents | Regional Federation | 8 – 16 vCPU per region | 16 – 32 GB | 250+ GB | Separate operator traffic from ingest traffic and plan for external observability |

The primary scaling pressure is retained event volume rather than raw CPU. If you retain long histories, raise disk and backup budgets before you raise core count.

## High Availability Reference Pattern

Wardex v1.0 supports **active/passive HA** backed by durable shared storage
or periodic backup replication. A fully automated clustered control plane
(Raft leader election) is planned for v1.1; the current production pattern
is described below.

1. Place the HTTP/UI listener behind a load balancer or reverse proxy.
2. Keep `var/` on durable storage (NFS, cloud PVC, or equivalent) so the
   standby node can mount the same data on failover.
3. Mirror configuration, admin secrets, and TLS assets through your secret
   manager instead of node-local files.
4. Use a warm standby node running the same release version; apply
   backup/checkpoint artifacts automatically via `wardex backup restore`
   during unplanned failover.
5. Monitor backup currency via `/api/backup/status` and recovery posture
   via `/api/support/readiness-evidence` before every failover drill.
6. In federation mode, keep each region autonomous and share posture/intel
   across regions instead of forwarding all raw events cross-region.

For step-by-step failover procedures, RPO/RTO targets, and Kubernetes
specifics, see the **[HA Failover Runbook](runbooks/HA_FAILOVER.md)**.

For production planning, pair this document with `docs/DISASTER_RECOVERY.md`
and `docs/PRODUCTION_HARDENING.md` so sizing, backup cadence, and failover
drills are defined together.
