# Wardex Release Acceptance

This checklist gates release candidates against the shipped routed UI, structured operator workflows, and the live browser paths that replaced earlier ad hoc audits.

## Automated gate

Run the acceptance wrapper from the repository root:

```bash
make release-acceptance
```

The wrapper is implemented in `scripts/release_acceptance.sh` and runs these checks in order:

1. `admin-console` production build via `npm run build`.
2. Root `cargo build` so embedded assets and backend routes match the browser bundle.
3. Published marketing-site link validation across `site/*.html`.
4. Live admin reachability check against `WARDEX_BASE_URL`.
5. Routed browser release suite:
   - `tests/playwright/live_release_smoke.spec.js`
   - `tests/playwright/advanced_console_workflows.spec.js`
   - `tests/playwright/enterprise_console_smoke.spec.js`
   - `tests/playwright/assistant_ticketing_live.spec.js`
   - `tests/playwright/siem_settings_live.spec.js`
   - `tests/playwright/mobile_topbar_smoke.spec.js`

## Preconditions

- `admin-console/node_modules` must exist.
- A local or remote Wardex instance must already be running at `WARDEX_BASE_URL`.
- `WARDEX_ADMIN_TOKEN` must be set, or a token file must exist at `/tmp/wardex_smoke_token`.

Default values:

- `WARDEX_BASE_URL=http://127.0.0.1:8080`
- `WARDEX_ADMIN_TOKEN_FILE=/tmp/wardex_smoke_token`

## Manual release review

The automated gate does not replace operator review. Before cutting a release:

1. Review `docs/FEATURE_UI_COVERAGE.md` and confirm every shipped capability is either routed in the admin console or explicitly tracked as a remaining gap.
2. For every newly touched console flow, verify the primary surface is a structured workflow (cards, forms, tables, timelines, dialogs) rather than a raw JSON dead end.
3. Confirm `CHANGELOG.md`, `docs/STATUS.md`, `docs/ROADMAP_XDR_PROFESSIONAL.md`, and `docs/PROJECT_BACKLOG.md` describe the same shipped state and remaining gaps.
4. Keep screenshots or test logs for any UI-polish or routing changes that required visual review.

## Failure policy

- Any failed automated step blocks the release candidate.
- Any shipped feature that lacks a reachable routed surface must stay called out in `docs/FEATURE_UI_COVERAGE.md` and `docs/PROJECT_BACKLOG.md` before release sign-off.
- Any browser flow that regresses into a raw JSON-only fallback must be fixed or demoted from shipped claims before release sign-off.