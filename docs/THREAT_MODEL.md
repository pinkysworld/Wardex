# Threat Model

> T217 — Phase 27  
> Promoted from xdr_ai_handoff_pack/docs/THREAT_MODEL.md

## 1. Assets

| Asset | Sensitivity | Location |
|-------|------------|----------|
| Telemetry data | High | Event store, spool |
| Detection baselines | High | Checkpoints, memory |
| Policy definitions | Medium | Policy store |
| Agent enrollment tokens | Critical | Memory, RBAC store |
| Post-quantum key material | Critical | var/keys/ |
| Case & incident data | High | Case store |
| Admin API token | Critical | Memory, printed at startup |
| Audit log | Medium | Audit store |

## 2. Adversary Profiles

| Adversary | Capability | Goal |
|-----------|-----------|------|
| **External attacker** | Network access, public exploits | Data exfiltration, ransomware |
| **Compromised agent** | Valid enrollment token, local code exec | Lateral movement, data poisoning |
| **Malicious insider** | Valid admin/analyst credentials | Policy tampering, evidence destruction |
| **Supply-chain attacker** | Compromised dependency or update binary | Persistent backdoor |
| **Sophisticated APT** | Timing side-channels, cryptanalysis | Long-term espionage |

## 3. Abuse Cases

### AC-1: Credential Storm
An attacker brute-forces the admin API token.

**Mitigations**:
- Rate limiter: 60 write requests/min, 360 read/min per IP.
- Token is 256-bit random, printed only at startup.
- Audit log records all auth failures.

### AC-2: Telemetry Poisoning
A compromised agent sends crafted telemetry to bias the detector baseline.

**Mitigations**:
- Baseline adaptation modes (Normal / Frozen / Decay).
- Statistical outlier rejection in detector.
- Device fingerprinting detects agent impersonation.
- Adversarial harness validates detector resilience.

### AC-3: Checkpoint Tampering
An attacker modifies checkpoint files to reset detection state.

**Mitigations**:
- CRC32 integrity check on checkpoint load.
- Checkpoints stored in `var/` with OS-level permissions.
- Planned: HMAC signing of checkpoint files (Phase 28+).

### AC-4: API Token Theft via Side-Channel
Timing analysis of auth comparison reveals token bytes.

**Mitigations**:
- Constant-time token comparison (ring / subtle).
- Side-channel detector monitors timing variance.

### AC-5: Supply-Chain Compromise
A malicious crate dependency exfiltrates data.

**Mitigations**:
- `cargo audit` in CI.
- Minimal dependency footprint (< 30 direct deps).
- Binary attestation via SHA-256 manifest.
- Update binary signature verification.

### AC-6: Response Action Abuse
An attacker with analyst credentials triggers destructive response actions.

**Mitigations**:
- Human-in-the-loop approval flow for all response actions.
- RBAC: only Admin role can approve destructive actions.
- Approval audit log is append-only.

### AC-7: Evidence Destruction
A malicious insider deletes cases or incident records.

**Mitigations**:
- RBAC: DELETE on sensitive paths requires Admin role.
- Audit log records all mutations with username.
- Planned: append-only evidence ledger (Phase 29+).

## 4. Trust Boundaries

```
┌─────────────────────────────────────────────────┐
│                  Wardex Server                   │
│  ┌─────────┐  ┌──────────────┐  ┌────────────┐ │
│  │ Admin UI│  │ Detection    │  │ Response   │ │
│  │ (SPA)   │  │ Engine       │  │ Orchestr.  │ │
│  └────┬────┘  └──────┬───────┘  └─────┬──────┘ │
│       │ auth          │                │ approval│
│  ┌────┴───────────────┴────────────────┴──────┐ │
│  │              HTTP API Layer                │ │
│  │  (rate limit, auth, RBAC, audit, CORS)     │ │
│  └────────────────────┬───────────────────────┘ │
└───────────────────────┼─────────────────────────┘
                        │ TLS / mTLS
            ┌───────────┴───────────┐
            │     XDR Agents        │
            │  (enrollment tokens)  │
            └───────────────────────┘
```

**Trust boundary 1**: Admin UI ↔ API — crossed via Bearer token.  
**Trust boundary 2**: API ↔ Agents — crossed via enrollment token.  
**Trust boundary 3**: Server ↔ Filesystem — OS-level permissions.

## 5. Security Objectives

| Objective | Requirement |
|-----------|-------------|
| Confidentiality | Telemetry encrypted at rest (spool) and in transit (TLS) |
| Integrity | Checkpoint CRC, event hash chain, audit tamper evidence |
| Availability | Rate limiting, graceful shutdown, spool store-and-forward |
| Non-repudiation | Audit log with timestamps, approval log for response actions |
| Least privilege | RBAC roles: Admin > Analyst > Viewer > ServiceAccount |

## 6. Mitigations by Category

### Identity & Access
- Random 256-bit admin token.
- RBAC with four roles.
- Per-tenant isolation in multi-tenant mode.
- Enrollment tokens for agents.

### Transport
- TLS listener support.
- CORS hardened: only configured origins.
- HSTS and X-Content-Type-Options headers.
- Rate limiting per IP per endpoint class.

### Agent Security
- Device fingerprinting.
- Heartbeat staleness detection (30 s → stale, 120 s → offline).
- Inventory verification.
- Update binary signature check.

### Backend Security
- Spool encryption (ChaCha20-Poly1305).
- Post-quantum key rotation (Kyber KEM).
- Checkpoint integrity (CRC32).
- Config deserialization with size limits.
- Request body size limit (10 MB).

### Response & Remediation
- Human-in-the-loop approval.
- Policy VM sandboxing.
- Enforcement quarantine with rollback.

### Supply Chain
- `cargo audit` and `cargo deny`.
- SHA-256 binary attestation.
- Reproducible builds target.

## 7. Open Questions

1. Should checkpoint files be HMAC-signed in addition to CRC?
2. Is mutual TLS (mTLS) required for agent ↔ server, or is enrollment-token
   auth sufficient for Phase 27?
3. Should the audit log support remote forwarding (syslog/CEF)?
4. What is the key escrow strategy for post-quantum keys?

## 8. Review Schedule

- **Per-phase**: Review threat model against new features.
- **Quarterly**: Full threat-model review with stakeholders.
- **Annually**: External penetration test.
