# Contributing to Wardex

Thank you for your interest in contributing to Wardex.

## Development Setup

### Prerequisites

- **Rust** toolchain (MSRV: 1.88.0) — `rustup toolchain install stable`
- **Node.js** 22+ — for the admin console
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
7. For E2E tests, install Playwright: `npx playwright install chromium` then `npx playwright test`.
8. Route components are lazy-loaded via `React.lazy()` in `App.jsx`.
9. State management uses React Context — see `hooks.jsx` for `useAuth`, `useRole`, `useTheme`, `useToast`, `useApi`.

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
[BSL 1.1](LICENSE) license (converts to Apache 2.0 on 2029-04-01).
