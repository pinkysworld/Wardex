# Production Hardening Checklist

> T218 — Phase 27  
> Derived from xdr_ai_handoff_pack/docs/production-hardening-review.md

## Overview

This checklist covers the controls required before Wardex is deployed in a
production environment.  Each item is scored as **Implemented**, **Partial**,
or **Not started**, with a priority of Critical / High / Medium.

---

## 1. Tenant Isolation

| # | Control | Priority | Status |
|---|---------|----------|--------|
| 1.1 | Event store scoped by `tenant_id` | Critical | Implemented |
| 1.2 | RBAC users bound to tenant | Critical | Implemented |
| 1.3 | Case store tenant-scoped | High | Implemented |
| 1.4 | Cross-tenant query prevention (API layer) | Critical | Implemented |
| 1.5 | Spool partitioned per tenant | Medium | Implemented |

## 2. Authentication & Authorisation

| # | Control | Priority | Status |
|---|---------|----------|--------|
| 2.1 | Admin token: 256-bit random | Critical | Implemented |
| 2.2 | Constant-time token comparison | Critical | Implemented |
| 2.3 | RBAC with four roles | Critical | Implemented |
| 2.4 | RBAC enforcement on all mutating paths | Critical | Implemented |
| 2.5 | Enrollment token per agent | High | Implemented |
| 2.6 | Token rotation mechanism | High | Implemented |
| 2.7 | Session expiry / token TTL | Medium | Implemented |

## 3. Transport Security

| # | Control | Priority | Status |
|---|---------|----------|--------|
| 3.1 | TLS listener support | Critical | Implemented |
| 3.2 | HSTS header | High | Implemented |
| 3.3 | CORS allowlist (no wildcard) | Critical | Implemented |
| 3.4 | X-Content-Type-Options: nosniff | High | Implemented |
| 3.5 | Mutual TLS (mTLS) for agents | Medium | Implemented |

## 4. Auditability

| # | Control | Priority | Status |
|---|---------|----------|--------|
| 4.1 | API audit log (last 1 000 entries) | Critical | Implemented |
| 4.2 | Audit log includes username (RBAC) | High | Implemented |
| 4.3 | Approval log for response actions | Critical | Implemented |
| 4.4 | Tamper-evident audit chain | High | Implemented |
| 4.5 | Remote log forwarding (syslog / CEF) | Medium | Implemented |

## 5. Schema & Versioning

| # | Control | Priority | Status |
|---|---------|----------|--------|
| 5.1 | OCSF event schema | High | Implemented |
| 5.2 | Schema version field on all persisted structs | High | Implemented |
| 5.3 | OpenAPI specification | High | Implemented (Phase 27) |
| 5.4 | Schema lifecycle documentation | Medium | Implemented (Phase 27) |

## 6. Rollback Safety

| # | Control | Priority | Status |
|---|---------|----------|--------|
| 6.1 | Checkpoint save/restore | Critical | Implemented |
| 6.2 | Checkpoint CRC integrity | High | Implemented |
| 6.3 | Agent update rollback | High | Implemented |
| 6.4 | Config hot-reload without restart | Medium | Implemented |
| 6.5 | Database migration rollback | Medium | Implemented |

## 7. Data Retention

| # | Control | Priority | Status |
|---|---------|----------|--------|
| 7.1 | Event store size limit | High | Implemented (10 000 events) |
| 7.2 | Alert ring buffer | High | Implemented (100 alerts) |
| 7.3 | Spool max size | High | Implemented (10 000 records) |
| 7.4 | Dead-letter queue with cap | High | Implemented (500 entries) |
| 7.5 | Configurable retention policies | Medium | Implemented |

## 8. Failure Handling

| # | Control | Priority | Status |
|---|---------|----------|--------|
| 8.1 | Agent heartbeat staleness detection | Critical | Implemented |
| 8.2 | Spool store-and-forward on network failure | High | Implemented |
| 8.3 | Graceful shutdown (`POST /api/shutdown`) | High | Implemented |
| 8.4 | Rate limiting (per IP, per endpoint class) | Critical | Implemented |
| 8.5 | Request body size limit (10 MB) | High | Implemented |
| 8.6 | Thread health monitoring | Medium | Implemented |

## 9. Test Realism

| # | Control | Priority | Status |
|---|---------|----------|--------|
| 9.1 | Adversarial harness with attack scenarios | High | Implemented |
| 9.2 | Integration tests with real HTTP | High | Implemented (114 tests) |
| 9.3 | Checkpoint round-trip tests | High | Implemented |
| 9.4 | Spool encryption round-trip | High | Implemented |
| 9.5 | Multi-tenant isolation tests | Medium | Implemented |
| 9.6 | Chaos / fault-injection tests | Medium | Implemented |

## 10. Packaging & Distribution

| # | Control | Priority | Status |
|---|---------|----------|--------|
| 10.1 | Single static binary | High | Implemented |
| 10.2 | SHA-256 binary attestation | High | Implemented |
| 10.3 | Container image (Dockerfile) | Medium | Implemented |
| 10.4 | systemd unit / launchd plist | Medium | Implemented |
| 10.5 | Package manager (deb/rpm/brew) | Low | Implemented |

## 11. Documentation

| # | Control | Priority | Status |
|---|---------|----------|--------|
| 11.1 | Getting Started guide | Critical | Implemented |
| 11.2 | OpenAPI spec | High | Implemented (Phase 27) |
| 11.3 | Threat model | High | Implemented (Phase 27) |
| 11.4 | Disaster recovery plan | High | Implemented (Phase 27) |
| 11.5 | SLO policy | High | Implemented (Phase 27) |
| 11.6 | Deployment models guide | Medium | Implemented (Phase 27) |

---

## Summary Scores

| Category | Score |
|----------|-------|
| Tenant Isolation | 5/5 |
| AuthN/AuthZ | 7/7 |
| Transport | 5/5 |
| Auditability | 5/5 |
| Schema | 4/4 |
| Rollback | 5/5 |
| Retention | 5/5 |
| Failure Handling | 6/6 |
| Test Realism | 6/6 |
| Packaging | 5/5 |
| Documentation | 6/6 |

**Overall**: 59/59 controls implemented (100%).

## Remediation Priorities

1. **Package publication verification** — keep release tags, source archive checksums, and Homebrew formula metadata in lockstep on every tag.
2. **Homebrew tap automation** — `.github/workflows/sync-homebrew-tap.yml` renders the tap formula against the tagged source archive and syncs it into `pinkysworld/homebrew-wardex` after a release is published. Configure a fine-grained PAT as `HOMEBREW_TAP_TOKEN` with contents write access to the tap repository before cutting releases.
3. **Cross-platform Homebrew validation** — `.github/workflows/validate-homebrew-formula.yml` should stay green on Apple Silicon macOS, Intel macOS, and x86_64 Linux before release cuts so the tap remains aligned with `homebrew/core` build and test expectations.
4. **APT repository publication** — `.github/workflows/pages.yml` now rebuilds `site/apt/` from the latest published `.deb` asset on Pages deploys and requires `APT_GPG_PRIVATE_KEY` to sign the published Debian repository metadata. Configure `APT_GPG_PRIVATE_KEY` and `APT_GPG_PASSPHRASE` before cutting releases so the public install path can stay on `signed-by=` rather than `trusted=yes`.
