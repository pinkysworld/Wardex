#!/usr/bin/env python3
"""Validate documentation freshness signals without editing documentation."""

from __future__ import annotations

import pathlib
import re
import sys
import tomllib


ROOT = pathlib.Path(__file__).resolve().parents[1]
DOCS_ROOT = ROOT / "docs"
OPENAPI_DOC = DOCS_ROOT / "openapi.yaml"
STATUS_DOC = DOCS_ROOT / "STATUS.md"
README_DOC = ROOT / "README.md"
RELEASE_DOC = DOCS_ROOT / "RELEASE_ACCEPTANCE.md"
CONTRACT_PARITY = ROOT / "scripts" / "check_contract_parity.py"


def read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def cargo_version() -> str:
    with (ROOT / "Cargo.toml").open("rb") as handle:
        return tomllib.load(handle)["package"]["version"]


def required_contract_endpoints() -> set[str]:
    text = read(CONTRACT_PARITY)
    match = re.search(
        r"REQUIRED_RUNTIME_OPENAPI_ENDPOINTS\s*=\s*[\[{](.*?)[\]}]",
        text,
        flags=re.DOTALL,
    )
    if not match:
        raise RuntimeError("could not locate REQUIRED_RUNTIME_OPENAPI_ENDPOINTS")
    return {
        f"{method} {path}"
        for method, path in re.findall(
            r'\("(GET|POST|PUT|PATCH|DELETE)",\s*"(/api/[^"]+)"\)', match.group(1)
        )
    }


def openapi_operations(openapi_text: str) -> set[str]:
    operations: set[str] = set()
    current_path: str | None = None
    for raw_line in openapi_text.splitlines():
        if raw_line.startswith("  /") and raw_line.rstrip().endswith(":"):
            current_path = raw_line.strip().rstrip(":")
            continue
        method = raw_line.strip().rstrip(":")
        if current_path and method in {"get", "post", "put", "patch", "delete"}:
            operations.add(f"{method.upper()} {current_path}")
    return operations


def main() -> int:
    version = cargo_version()
    failures: list[str] = []

    openapi_text = read(OPENAPI_DOC)
    status_text = read(STATUS_DOC)
    readme_text = read(README_DOC)
    release_text = read(RELEASE_DOC)

    if f"version: {version}" not in openapi_text and f"version: '{version}'" not in openapi_text:
        failures.append(f"docs/openapi.yaml does not expose current Cargo version {version}")
    if f"`{version}`" not in status_text and f"v{version}" not in status_text:
        failures.append(f"docs/STATUS.md does not reference current Cargo version {version}")
    if "scripts/check_contract_parity.py" not in release_text:
        failures.append("docs/RELEASE_ACCEPTANCE.md does not mention the API contract parity gate")
    if "docs/openapi.yaml" not in readme_text and "OpenAPI" not in readme_text:
        failures.append("README.md does not point readers to API contract documentation")

    documented_ops = openapi_operations(openapi_text)
    missing_ops = sorted(required_contract_endpoints() - documented_ops)
    for operation in missing_ops:
        failures.append(f"docs/openapi.yaml is missing required operation {operation}")

    if failures:
        for failure in failures:
            print(f"docs-freshness: {failure}", file=sys.stderr)
        return 1

    print(f"docs-freshness: current version and {len(documented_ops)} OpenAPI operations are aligned")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())