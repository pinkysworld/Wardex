Phase 5: Linux collector.

Read AGENTS.md and docs/EXECUTION_PLAN.md first.

Implement the Linux collector with a layered design:
- preferred path: eBPF-based telemetry where practical
- fallback path: auditd / procfs / netlink / fanotify style metadata collection as appropriate
- process lifecycle
- file activity metadata
- socket/network metadata
- DNS metadata if available
- privilege escalation indicators
- container-aware metadata
- distro capability matrix

Deliverables:
- agent/collectors/linux
- distro packaging for at least Ubuntu and RHEL family
- capability detection logic
- canonical mappings
- fixture corpus from multiple distro types
- docs/RUNBOOKS/linux-agent.md
- ADR for Linux telemetry collection strategy

Acceptance criteria:
- collector works in testable local mode
- unsupported kernel/capability combinations degrade gracefully
- event mappings are documented
- packaging/install docs exist
- tests cover capability fallback behavior
