# XDR AI Handoff Pack

This package is a starter handoff for building a production-grade XDR platform with SIEM integration using an AI coding assistant such as Claude or Codex.

## What is included
- `AGENTS.md` repo guidance for the assistant
- `docs/EXECUTION_PLAN.md` phased build plan
- `docs/ARCHITECTURE.md` system architecture baseline
- `docs/THREAT_MODEL.md` initial threat model and trust boundaries
- `docs/ADR/` starter architecture decision records
- `prompts/` phase-by-phase execution prompts and review prompts

## Recommended usage
1. Create a new repository.
2. Copy all files from this pack into the repository root.
3. Ask your AI assistant to read `AGENTS.md` and `docs/EXECUTION_PLAN.md` first.
4. Run only one phase at a time from the `prompts/` directory.
5. Do not let the assistant skip phase acceptance criteria.

## Suggested first command to the assistant
Use `prompts/master-prompt.md` followed by `prompts/phase-00-repo-bootstrap.md`.

## Suggested starter monorepo layout

```text
/
  AGENTS.md
  README.md
  Makefile
  docker-compose.yml
  .github/workflows/
  docs/
    EXECUTION_PLAN.md
    ARCHITECTURE.md
    THREAT_MODEL.md
    ADR/
    RUNBOOKS/
    api/
    schemas/
  agent/
    core-rs/
    collectors/
      windows/
      linux/
      macos/
      unix-compat/
    packaging/
  backend/
    gateway/
    control-plane/
    identity/
    policy/
    event-normalizer/
    detection-engine/
    response-orchestrator/
    integrations/
      splunk/
      elastic/
      sentinel/
      secops/
      qradar/
      syslog/
      stix-taxii/
    case-management/
    graph-service/
  ui/
    analyst-console/
  infra/
    terraform/
    helm/
    local/
  test/
    integration/
    e2e/
    replay/
    fixtures/
```

## Notes
- This pack is intentionally conservative and engineering-heavy.
- It favors interoperability and safe response over unsupported marketing claims.
- It assumes Tier 1 coverage on Windows, Windows Server, macOS, and Linux before reduced-fidelity Unix collectors.
