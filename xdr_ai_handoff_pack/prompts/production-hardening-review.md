Act as a principal engineer and security reviewer.

Review this repository for production readiness of an XDR platform with SIEM integration.

Check:
- tenant isolation
- authn/authz
- mTLS and secret handling
- auditability
- schema/versioning discipline
- rollback safety
- data retention/deletion
- agent failure handling
- integration failure handling
- test realism
- packaging and upgrade safety
- documentation sufficiency

Output:
- critical blockers
- high-risk issues
- medium-risk issues
- production-readiness score by subsystem
- exact remediation tasks
