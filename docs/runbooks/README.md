# Wardex Operational Runbooks

This directory contains operational runbooks for deploying, configuring, and operating Wardex XDR agents and the central server across all supported platforms.

## Contents

| Runbook | Description |
|---------|-------------|
| [windows-agent.md](windows-agent.md) | Windows agent deployment, ETW/Sysmon setup, troubleshooting |
| [linux-agent.md](linux-agent.md) | Linux agent deployment, auditd/eBPF setup, container integration |
| [macos-agent.md](macos-agent.md) | macOS agent deployment, TCC/SIP considerations, code signing |
| [siem-integrations.md](siem-integrations.md) | SIEM connector configuration for Splunk, Elastic, Sentinel, QRadar |
| [response-playbooks.md](response-playbooks.md) | Incident response playbooks and remediation approval workflows |
| [deployment.md](deployment.md) | Installation, atomic upgrades, rollback, fleet enrollment |
| [troubleshooting.md](troubleshooting.md) | Diagnostics, common failures, log analysis, escalation |
| [AGENT_ROLLBACK.md](AGENT_ROLLBACK.md) | Emergency rollback procedure for a bad agent release |
