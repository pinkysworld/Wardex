# Wardex Compliance Posture

This document states Wardex's current compliance posture and roadmap for
regulatory and certification frameworks.

## FIPS 140-2 / 140-3

**Status: Not targeted for v1.0.**

Wardex uses industry-standard cryptographic primitives (AES-GCM, SHA-2,
Ed25519, ChaCha20-Poly1305) via well-audited Rust crates (`aes-gcm`,
`sha2`, `ed25519-dalek`). These implementations are not currently validated
under NIST FIPS 140-2 or 140-3.

FIPS-validated cryptographic module support is planned for a future release.
Organisations with US federal or DoD procurement requirements should contact
the Wardex team to discuss timelines and requirements.

## Common Criteria (CC / ISO 15408)

**Status: Not targeted for v1.0.**

Common Criteria evaluation is a significant investment (typically EAL 2–4,
12–36 months, six-figure cost). It is not currently planned for any specific
release. Wardex will revisit CC evaluation when specific government or
critical-infrastructure procurement opportunities require it.

## SOC 2 Type II

**Status: Roadmap — targeting v1.2.**

Wardex Cloud and managed-service offerings will pursue SOC 2 Type II
certification. Self-hosted deployments are outside the audit boundary, but
the controls and evidence that Wardex provides (audit logs, RBAC, access
reviews, backup evidence) are designed to support operators in their own
SOC 2 programmes.

## ISO 27001

**Status: Informally aligned; not certified.**

The Wardex development and release process follows ISO 27001-aligned
practices (access control, change management, vulnerability management,
incident response) as described in `docs/PRODUCTION_HARDENING.md` and
`docs/SECURITY.md`. Formal certification is not currently sought.

## GDPR / Privacy

**Status: In progress — see DESIGN_PRIVACY below.**

Wardex stores security telemetry that may include personal data (usernames,
IP addresses, device identifiers). Operators are the data controllers.
Wardex provides:

- Per-tenant data isolation.
- Configurable event retention TTL (ClickHouse and SQLite).
- Audit-log export for compliance evidence.
- Privacy forensics module (`src/privacy.rs`) for PII detection and
  redaction in stored events.

A detailed data-retention and privacy guide will be published as
`docs/DATA_RETENTION_AND_PRIVACY.md` in v1.1.

## Supply Chain Security

Wardex follows supply-chain hardening practices described in
`docs/DESIGN_SUPPLY_CHAIN.md`:

- Release binaries are signed with `cosign` and SHA-256 checksummed.
- `cargo deny check` enforces the dependency licence allowlist and known
  vulnerability advisories on every CI run.
- Reproducible builds are documented in `docs/REPRODUCIBILITY.md`.
- SBOM generation (`cargo-sbom`) is planned for v1.1 releases.

## Contact

For compliance enquiries or to discuss specific regulatory requirements,
contact: **support@wardex.dev**
