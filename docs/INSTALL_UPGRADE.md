# Install/Upgrade

Wardex supports source, package, Homebrew, and container installation paths.

## Installation Paths

1. [`runbooks/installation.md`](runbooks/installation.md) — canonical install commands for Homebrew, APT/RPM, Docker, Helm, and source
2. [`DEPLOYMENT_MODELS.md`](DEPLOYMENT_MODELS.md) — single-node, HA, and air-gapped deployment guidance
3. [`UPGRADE_0_56_TO_1_0.md`](UPGRADE_0_56_TO_1_0.md) — historical major upgrade reference

## Upgrade And Rollback Safety

Use these release gates before and after upgrading:

```bash
make release-acceptance
python3 scripts/check_release_trust_gates.py
python3 scripts/verify_release_artifacts.py release-assets
```

For rollback procedures, use:

- [`runbooks/AGENT_ROLLBACK.md`](runbooks/AGENT_ROLLBACK.md)
- [`DISASTER_RECOVERY.md`](DISASTER_RECOVERY.md)
