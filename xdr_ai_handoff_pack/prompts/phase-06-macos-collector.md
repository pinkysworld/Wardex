Phase 6: macOS collector.

Read AGENTS.md and docs/EXECUTION_PLAN.md first.

Implement the macOS collector based on current macOS-compatible security architecture:
- process lifecycle metadata
- file and execution visibility where available
- mount/login/session indicators
- network metadata where practical
- policy and permission checks
- packaging and entitlement documentation
- compatibility notes for current and previous major versions

Deliverables:
- agent/collectors/macos
- installer/uninstaller packaging scaffolding
- capability matrix by macOS version
- fixture corpus
- normalization mappings
- docs/RUNBOOKS/macos-agent.md

Acceptance criteria:
- collector integrates with agent core
- capability restrictions and entitlements are documented
- sample events normalize correctly
- test coverage exists for translation and failure modes
