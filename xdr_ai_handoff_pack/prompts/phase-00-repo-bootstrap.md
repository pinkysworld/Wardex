Phase 0: Repo bootstrap and architecture baseline.

Read AGENTS.md and docs/EXECUTION_PLAN.md first.

Create the initial repository structure for a production-grade XDR with SIEM integration. Do not implement full product logic yet. Focus on:
- repo layout
- build tooling
- linting
- test harnesses
- service skeletons
- Rust workspace for the agent
- backend service scaffolds
- UI scaffold
- docker-compose for local development
- docs/ARCHITECTURE.md
- docs/THREAT_MODEL.md
- at least 5 ADRs covering:
  1. language/runtime split
  2. canonical event model
  3. service boundaries
  4. auth strategy
  5. OS support tiers

Deliverables:
- runnable monorepo skeleton
- CI pipeline for build, lint, and tests
- minimal hello-world health endpoints for backend services
- minimal Rust agent core crate with interfaces only
- initial OpenAPI skeleton
- architecture and threat-model docs

Acceptance criteria:
- repo builds
- test jobs pass
- CI config exists
- docs are coherent
- phase summary lists deferred implementation work

Do not start telemetry collectors or SIEM integrations yet.
