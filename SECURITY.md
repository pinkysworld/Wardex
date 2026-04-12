# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.43.x  | Yes       |
| 0.42.x  | Security fixes only |
| < 0.42  | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in Wardex, please report it
responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to report

1. Email **security@wardex.dev** with a description of the vulnerability.
2. Include steps to reproduce, affected versions, and potential impact.
3. If possible, include a proof-of-concept or suggested fix.

### What to expect

- **Acknowledgement** within 48 hours of your report.
- **Triage and assessment** within 5 business days.
- **Fix timeline** communicated once the severity is assessed.
- **Credit** in the release notes (unless you prefer to remain anonymous).

### Severity Classification

We follow the CVSS v3.1 scoring model:

| Severity | CVSS Score | Response Target |
|----------|-----------|-----------------|
| Critical | 9.0–10.0  | Patch within 48 hours |
| High     | 7.0–8.9   | Patch within 7 days |
| Medium   | 4.0–6.9   | Patch in next release |
| Low      | 0.1–3.9   | Scheduled backlog |

### Scope

The following are in scope:

- Authentication and authorization bypass
- Remote code execution
- SQL injection or data exfiltration
- Cryptographic weaknesses (token generation, backup encryption, key management)
- Path traversal or file access beyond `var/`
- Denial of service via resource exhaustion (rate limiter bypass, memory, disk)
- Cross-site scripting (XSS) in the admin console

### Out of Scope

- Vulnerabilities in third-party dependencies (report upstream; we monitor via `cargo audit`)
- Issues requiring physical access to the host
- Social engineering attacks
- Denial of service via network flooding (infrastructure-level concern)

## Security Controls

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and
[docs/PRODUCTION_HARDENING.md](docs/PRODUCTION_HARDENING.md) for details on
implemented security controls.
