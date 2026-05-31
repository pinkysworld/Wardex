# Operate Wardex

This guide is the operator-first index for daily Wardex usage in production and evaluation environments.

## Start Here

1. [`GETTING_STARTED.md`](GETTING_STARTED.md) — local bootstrapping and control-plane startup
2. [`EVALUATE_WARDEX.md`](EVALUATE_WARDEX.md) — the 15-minute evaluation-to-value path
3. [`CONFIGURATION.md`](CONFIGURATION.md) — runtime settings and hardening toggles
4. [`PRODUCTION_HARDENING.md`](PRODUCTION_HARDENING.md) — trust defaults, metrics, and operational guardrails
5. [`runbooks/command-center.md`](runbooks/command-center.md) — SOC and operator workflows

## Operational Commands

Validated command surfaces used in release acceptance:

```bash
wardex --version
wardex doctor
wardex doctor --json
curl -sSf http://127.0.0.1:9077/api/healthz/ready
curl -sSf http://127.0.0.1:9077/api/support/bundle
```

## Release-Readiness Diagnostics

`wardex doctor --json` includes installation layout hints, config path, service markers, known log locations, and support-bundle digest metadata. Use it in incident tickets and pre-release evidence collection.
