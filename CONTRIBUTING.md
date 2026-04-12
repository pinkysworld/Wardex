# Contributing to Wardex

Thank you for your interest in contributing to Wardex.

## Development Setup

### Prerequisites

- **Rust** toolchain (MSRV: 1.85.0) — `rustup toolchain install stable`
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

### Commit Messages

Use conventional commit format:

```
feat: add threat-hunting query aliases
fix: correct syslog severity mapping for elevated alerts
docs: add TLS configuration examples
test: add integration tests for LEEF export
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
