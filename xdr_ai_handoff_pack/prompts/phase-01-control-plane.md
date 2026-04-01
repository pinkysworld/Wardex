Phase 1: Control plane and identity foundation.

Read AGENTS.md and docs/EXECUTION_PLAN.md first.

Implement the control plane foundations for the XDR platform:
- tenant model
- organizations/projects/environments
- users, roles, RBAC
- SSO-ready auth interfaces
- API tokens/service accounts
- device enrollment flow
- mTLS certificate enrollment design and scaffolding
- audit log service
- policy distribution API skeleton

Deliverables:
- backend/control-plane service
- backend/identity service
- database schema and migrations
- OpenAPI specs
- seed data for local development
- audit trail for admin actions
- docs/RUNBOOKS/local-control-plane.md
- ADR for RBAC vs ABAC decision

Acceptance criteria:
- tenant-aware APIs work locally
- authentication and authorization are enforced
- device enrollment flow can issue a mocked enrollment token
- audit logs record all admin mutations
- tests cover authz edge cases

Do not build full endpoint collection yet.
