Phase 4: Windows collector.

Read AGENTS.md and docs/EXECUTION_PLAN.md first.

Implement the first production-grade Windows collector package for Windows and Windows Server:
- process creation/termination
- parent-child relationships
- image/hash metadata
- network connection metadata
- DNS metadata
- selected persistence changes
- selected registry visibility
- service creation/change visibility
- PowerShell/script execution metadata where practical
- least-privilege and compatibility documentation

Deliverables:
- agent/collectors/windows
- Windows packaging/install/uninstall scripts
- event fixtures from Windows test hosts
- mapping from Windows-native telemetry to canonical schema
- capability flags per Windows version
- docs/RUNBOOKS/windows-agent.md

Acceptance criteria:
- collector events pass normalization tests
- supported Windows versions are documented
- service startup/shutdown works
- no unsupported kernel-level assumptions are hidden
- test harness includes realistic Windows event samples

Do not implement destructive response actions yet.
