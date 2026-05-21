# Contributing to Wardex

Thank you for your interest in contributing to Wardex.

## Development Setup

### Prerequisites

- **Rust** toolchain (MSRV: 1.88.0) — `rustup toolchain install stable`
- **Node.js** 22+ — for the admin console and TypeScript SDK. The package metadata requires at least 20.19.0 because current test dependencies such as jsdom and undici reject older 20.x releases.
- **Python** 3.9+ — for the Python SDK and live tests

### Build

```bash
cargo build --release
```

### Run tests

```bash
# Rust — unit + integration (1345+ tests)
cargo test

# Admin console — Vitest (26 tests)
cd admin-console && npm ci && npm test -- --run

# TypeScript SDK — Vitest (23 tests)
cd sdk/typescript && npm ci && npm test -- --run

# Python SDK — pytest
cd sdk/python && pip install -e . && pytest tests/ -v
```

### Code Quality

Before submitting a PR, ensure:

```bash
cargo fmt -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

The CI pipeline enforces these checks on every push and PR.

## How to Contribute

### Reporting Bugs

Open a GitHub issue with:
- Wardex version (`wardex --version`)
- OS and platform
- Steps to reproduce
- Expected vs. actual behaviour

### Security Issues

**Do not open public issues for security vulnerabilities.** See
[SECURITY.md](SECURITY.md) for the responsible disclosure process.

### Pull Requests

1. Fork the repository and create a feature branch from `main`.
2. Write tests for any new functionality.
3. Ensure all tests pass and linting is clean.
4. Keep commits focused — one logical change per commit.
5. Write a clear PR description explaining *what* and *why*.

### Code Style

- **Rust**: Follow `rustfmt` defaults. No `unsafe` code (enforced by `#[forbid(unsafe_code)]`).
- **TypeScript/JavaScript**: ESLint + Prettier (admin console and SDK).
- **Python**: Ruff for linting.

### Frontend Development

When changing the admin console (`admin-console/`):

1. Run the dev server: `cd admin-console && npm run dev`
2. The dev server proxies `/api` to `http://127.0.0.1:8080` — start the backend first with `cargo run`.
3. All new components should include a unit test in `src/__tests__/`.
4. Use the shared test utilities in `src/__tests__/test-utils.js` for mocking and render wrappers.
5. Add ARIA attributes to interactive elements (see existing patterns in `LiveMonitor.jsx` and `SearchPalette.jsx`).
6. Run `npm run lint && npm run format:check && npm test -- --run` before submitting.
7. For E2E tests, install Playwright once with `npx playwright install chromium`, then run `npm run e2e` (alias for `playwright test`).
8. Route components are lazy-loaded via `React.lazy()` in `App.jsx`.
9. State management uses React Context — see `hooks.jsx` for `useAuth`, `useRole`, `useTheme`, `useToast`, `useApi`.

### iCloud / cloud-synced workspaces

If your workspace lives under `~/Library/Mobile Documents/com~apple~CloudDocs/` (iCloud Drive), Vite's
file watchers and Playwright's `output/` paths can stall on metadata sync. Workarounds:

- Export `TMPDIR=/tmp/sentinel-edge-build` before running `npm run dev`, `npm run build`, or `npm run e2e`
  so build artefacts land on a non-synced filesystem.
- Disable iCloud "Optimize Mac Storage" for the project folder so Vite's lockfile reads are not paged out.
- Prefer cloning the repository to `~/src/` and symlinking it into iCloud if you need both worlds.

### Commit Messages

Use conventional commit format:

```
feat: add threat-hunting query aliases
fix: correct syslog severity mapping for elevated alerts
docs: add TLS configuration examples
test: add integration tests for LEEF export
```

### Panic Policy

Production code under `src/` should not introduce new `.unwrap()` or
`.expect(` calls. The CI job `panic-policy` counts these in non-test
regions of `src/` and fails any pull request that increases the count
above the baseline in `scripts/panic-baseline.txt`.

If a new call site is provably infallible:

1. Add a same-line `// SAFETY:` or `// INTENTIONAL:` comment that
   explains why the panic cannot fire (e.g. "non-empty checked above",
   "startup-only path, runtime exit on failure is acceptable").
2. Bump the integer in `scripts/panic-baseline.txt` by one in the same
   commit so reviewers see the policy override.

Run the guard locally with:

```bash
python3 scripts/check_panic_policy.py
```

## Testing Patterns

### Process-global atomics under parallel `cargo test`

`cargo test` runs tests inside a single binary in parallel by default. Any
counter or gauge stored in a `static AtomicU64` / `OnceLock<Mutex<…>>` —
`crate::state_lock::*`, `crate::server_auth::FAILED_AUTH_*`, the request
counters on `AppState`, etc. — is therefore **process-global**: every test in
the same binary observes the same value, and the order in which they run is
not deterministic.

That makes naïve assertions like

```rust
let before = STATE_LOCK_ACQUISITIONS.load(Ordering::Relaxed);
do_something();
let after = STATE_LOCK_ACQUISITIONS.load(Ordering::Relaxed);
assert_eq!(after, before + 1); // flaky — another test may have bumped it
```

flaky in practice. Use one of these patterns instead:

1. **Unique labels + `label_snapshot()` for exact equality.** When the metric
   supports a label dimension (e.g. `crate::state_lock::tracked_lock(state,
   "my_test/scenario_x")`), pick a label string that no other test will ever
   emit, then assert on the per-label snapshot. The label is the natural test
   isolation key, so equality is safe.

2. **`>= N` for aggregate counter deltas.** When the metric is unlabeled
   (`wardex_failed_auth_failures_total`, `wardex_state_lock_acquisitions_total`,
   …), snapshot the value before the action, take the delta, and assert
   `delta >= expected` rather than `delta == expected`. Other tests may
   concurrently bump the counter; they cannot reduce your delta.

3. **Per-binary integration tests for true equality assertions.** Each file
   under `tests/` builds its own integration binary with a fresh process and
   zeroed atomics. When a test must observe `active_lockouts == 1` or
   `failures_total == THRESHOLD` exactly, put it in its own `tests/<name>.rs`
   file. `tests/failed_auth_lockout.rs` is the canonical example.

For HTTP-level scenarios that depend on the request's source IP (failed-auth
lockouts, per-IP rate limiting), remember that `127.0.0.1` / `::1` are exempt
by design. Drive the process-global tracker directly via the
`#[doc(hidden)] pub` helpers in `src/server_auth.rs` (e.g.
`__test_failed_auth_record`) instead of trying to spoof the client IP at the
TCP layer.

## Project Structure

| Directory | Contents |
|-----------|----------|
| `src/` | Rust core — 116 modules |
| `admin-console/` | React admin UI (Vite + Vitest) |
| `sdk/python/` | Python SDK |
| `sdk/typescript/` | TypeScript SDK |
| `tests/` | Integration tests |
| `benches/` | Criterion benchmarks |
| `fuzz/` | Fuzz targets |
| `deploy/` | Helm, K8s, systemd, Homebrew |
| `docs/` | Architecture, design, runbooks |

## License

By contributing, you agree that your contributions will be licensed under the
[AGPL-3.0-only](LICENSE) license. Commercial licensing terms are documented in
[LICENSE.COMMERCIAL](LICENSE.COMMERCIAL).
