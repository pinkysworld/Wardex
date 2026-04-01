Phase 3: Cross-platform agent core.

Read AGENTS.md and docs/EXECUTION_PLAN.md first.

Implement the shared Rust agent core:
- config management
- signed policy fetch contract
- local encrypted spool abstraction
- backpressure-aware sender
- health reporting
- plugin/collector interface
- local event queue
- upgrade interface
- watchdog/recovery hooks
- structured logging
- feature flags by OS and capability

Deliverables:
- Rust workspace with agent core crate
- collector trait/interface definitions
- local test harness and fixtures
- mocked control-plane enrollment
- spool encryption abstraction
- docs for agent lifecycle, policy lifecycle, and upgrade model

Acceptance criteria:
- agent core can start, enroll against a mocked endpoint, receive config, queue events, and send them
- offline mode is testable
- retry/backoff logic is covered by tests
- collector interfaces are stable and documented

Do not implement real OS telemetry yet.
