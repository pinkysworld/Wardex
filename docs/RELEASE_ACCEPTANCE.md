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
3. API/OpenAPI/SDK contract parity via `python3 scripts/check_contract_parity.py`, including the report template, report run, and report schedule workflow across runtime routing, the live OpenAPI builder, `docs/openapi.yaml`, and both SDK clients.
4. Release-document consistency via `python3 scripts/validate_release_docs.py`, including `STATUS`, roadmap, feature UI coverage, and routed smoke mappings.
5. Published marketing-site link validation across `site/*.html`.
6. Managed mode only: start a temporary local Wardex instance on a loopback port with a cloned acceptance config that disables request throttling for the smoke run.
7. Live admin reachability check against `WARDEX_BASE_URL`.
8. Routed browser release suite:
   - `tests/playwright/live_release_smoke.spec.js`
   - `tests/playwright/advanced_console_workflows.spec.js`
   - `tests/playwright/enterprise_console_smoke.spec.js`
   - `tests/playwright/assistant_ticketing_live.spec.js`
   - `tests/playwright/siem_settings_live.spec.js`
   - `tests/playwright/mobile_topbar_smoke.spec.js`

## macOS release trust

Tagged macOS release jobs must Developer ID sign and notarize the `wardex`
binary before the `.tar.gz` archive is assembled. The release workflow fails
the macOS matrix jobs when the Apple signing credentials are missing, preventing
GitHub Releases from publishing unsigned binaries that macOS Gatekeeper blocks.

Required GitHub Actions secrets:

- `MACOS_DEVELOPER_ID_CERTIFICATE_BASE64` — base64-encoded Developer ID
  Application `.p12` certificate.
- `MACOS_DEVELOPER_ID_CERTIFICATE_PASSWORD` — password for that `.p12` file.
- `MACOS_NOTARY_APPLE_ID` — Apple ID used with `xcrun notarytool`.
- `MACOS_NOTARY_APP_PASSWORD` — app-specific password for notarization.
- `MACOS_NOTARY_TEAM_ID` — Apple Developer Team ID.

Optional secrets:

- `MACOS_CODESIGN_IDENTITY` — exact `codesign` identity name when the default
  `Developer ID Application` selector is ambiguous.
- `MACOS_KEYCHAIN_PASSWORD` — password for the temporary CI keychain.

Each macOS release asset must have matching `wardex-macos-*-gatekeeper.txt`
evidence in the GitHub Release. A local spot-check after extraction should pass:

```bash
codesign --verify --strict --verbose=2 wardex-macos-aarch64/wardex
codesign -dv --verbose=4 wardex-macos-aarch64/wardex
```

Apple notarization is confirmed by `xcrun notarytool submit --wait` returning
`Accepted`. `spctl --assess --type execute` is app-bundle oriented and reports
false negatives such as `does not seem to be an app` for standalone Wardex CLI
binaries.

Local archive builds use the same helper through `scripts/build_local_release.sh`
when these environment variables are present:

```bash
export WARDEX_MACOS_CERTIFICATE_BASE64="$(base64 -i DeveloperIDApplication.p12)"
export WARDEX_MACOS_CERTIFICATE_PASSWORD="<p12-password>"
export WARDEX_MACOS_NOTARY_APPLE_ID="<apple-id>"
export WARDEX_MACOS_NOTARY_PASSWORD="<app-specific-password>"
export WARDEX_MACOS_NOTARY_TEAM_ID="<team-id>"
export WARDEX_REQUIRE_MACOS_NOTARIZATION=1
bash scripts/build_local_release.sh
```

Without `WARDEX_REQUIRE_MACOS_NOTARIZATION=1`, local macOS archives may still be
created for development smoke testing, but they are not suitable for GitHub
release publication.

## GitHub CI preflight

The GitHub CI matrix also gates release branches with the Rust checks that are intentionally kept outside the browser-heavy acceptance wrapper:

```bash
cargo fmt -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
python3 scripts/check_panic_policy.py
```

The matrix runs Linux, macOS, and Windows without fail-fast cancellation so each platform reports its own failure context.

## Preconditions

- `admin-console/node_modules` must exist.
- Managed mode uses the local `var/wardex.toml` as its base config and starts its own temporary Wardex instance automatically.
- External mode still expects a local or remote Wardex instance to already be running at `WARDEX_BASE_URL`.
- `WARDEX_ADMIN_TOKEN` can be set explicitly; otherwise the wrapper uses `WARDEX_ADMIN_TOKEN_FILE` when it exists, and managed mode will generate a temporary token if neither is provided.

Default values:

- `WARDEX_RELEASE_ACCEPTANCE_MODE=managed`
- `WARDEX_BASE_URL=http://127.0.0.1:<auto-picked-port>` in managed mode, `http://127.0.0.1:8080` in external mode
- `WARDEX_ADMIN_TOKEN_FILE=/tmp/wardex_smoke_token`

To target an already running instance instead of letting the wrapper self-host one:

```bash
WARDEX_RELEASE_ACCEPTANCE_MODE=external \
WARDEX_BASE_URL=http://127.0.0.1:8080 \
bash scripts/release_acceptance.sh
```

## API Stability Pledge (v1.0+)

From v1.0, Wardex commits to a **12-month API stability guarantee**:

- No breaking changes to the public HTTP API, CLI interface, TOML
  configuration keys, or SDK method signatures within a major version series.
- Breaking changes require a major-version bump (1.x → 2.0) with deprecation
  notice in the prior minor release. See `docs/DEPRECATION_POLICY.md`.
- New endpoints, optional fields, and additive SDK methods may appear in any
  minor release.

Major-version release acceptance additionally requires:

1. `docs/UPGRADE_<prev>_TO_<major>.md` exists and covers all breaking changes.
2. `docs/DEPRECATION_POLICY.md` and `docs/COMPATIBILITY.md` are current.
3. No `deprecated: true` endpoints in `docs/openapi.yaml` without a
   documented removal target version.

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