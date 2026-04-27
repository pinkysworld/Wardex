#!/usr/bin/env python3
"""Fail release checks when API contract and SDK versions drift."""

from __future__ import annotations

import json
import pathlib
import re
import sys
import tomllib


ROOT = pathlib.Path(__file__).resolve().parents[1]
REQUIRED_RUNTIME_OPENAPI_ENDPOINTS = {
    ("GET", "/api/openapi.json"),
    ("POST", "/api/graphql"),
    ("GET", "/api/support/parity"),
    ("GET", "/api/support/readiness-evidence"),
    ("POST", "/api/support/first-run-proof"),
    ("GET", "/api/alerts"),
    ("GET", "/api/alerts/grouped"),
    ("GET", "/api/queue/alerts"),
    ("GET", "/api/fleet/dashboard"),
    ("POST", "/api/response/request"),
    ("GET", "/api/response/requests"),
    ("POST", "/api/response/approve"),
    ("POST", "/api/response/execute"),
    ("GET", "/api/response/approvals"),
    ("GET", "/api/ws/stats"),
}

REQUIRED_SDK_ENDPOINTS = {
    "/api/openapi.json",
    "/api/support/parity",
    "/api/support/readiness-evidence",
    "/api/support/first-run-proof",
    "/api/alerts",
    "/api/response/request",
    "/api/response/approve",
    "/api/response/execute",
    "/api/ws/stats",
}

MIN_OPENAPI_OPERATIONS = 80


def cargo_version() -> str:
    with (ROOT / "Cargo.toml").open("rb") as fh:
        return tomllib.load(fh)["package"]["version"]


def python_sdk_version() -> str:
    with (ROOT / "sdk/python/pyproject.toml").open("rb") as fh:
        return tomllib.load(fh)["project"]["version"]


def typescript_sdk_version() -> str:
    with (ROOT / "sdk/typescript/package.json").open() as fh:
        return json.load(fh)["version"]


def openapi_operations(source: str) -> set[tuple[str, str]]:
    return {
        (method.upper(), path)
        for path, method in re.findall(r'\.path\(\s*"([^"]+)",\s*"([^"]+)"', source)
    }


def main() -> int:
    version = cargo_version()
    failures: list[str] = []

    if python_sdk_version() != version:
        failures.append(f"Python SDK version {python_sdk_version()} != runtime {version}")
    if typescript_sdk_version() != version:
        failures.append(f"TypeScript SDK version {typescript_sdk_version()} != runtime {version}")

    endpoint_source = (ROOT / "src/server.rs").read_text(errors="ignore")
    openapi_source = (ROOT / "src/openapi.rs").read_text(errors="ignore")
    ts_sdk_source = (ROOT / "sdk/typescript/src/index.ts").read_text(errors="ignore")
    py_sdk_source = (ROOT / "sdk/python/wardex/client.py").read_text(errors="ignore")
    openapi_inventory = openapi_operations(openapi_source)

    for method, endpoint in sorted(REQUIRED_RUNTIME_OPENAPI_ENDPOINTS):
        if endpoint not in endpoint_source:
            failures.append(f"{method} {endpoint} missing from runtime endpoint catalog/auth routing")
        if (method, endpoint) not in openapi_inventory:
            failures.append(f"{method} {endpoint} missing from OpenAPI builder")

    for endpoint in sorted(REQUIRED_SDK_ENDPOINTS):
        if endpoint not in ts_sdk_source:
            failures.append(f"{endpoint} missing from TypeScript SDK client")
        if endpoint not in py_sdk_source:
            failures.append(f"{endpoint} missing from Python SDK client")

    if len(openapi_inventory) < MIN_OPENAPI_OPERATIONS:
        failures.append(
            f"OpenAPI operation inventory looks unexpectedly small ({len(openapi_inventory)} < {MIN_OPENAPI_OPERATIONS})"
        )

    operation_ids = re.findall(r'"(get|post|put|delete)[A-Z][A-Za-z0-9]+"', openapi_source)
    if len(operation_ids) < 50:
        failures.append("OpenAPI operation inventory looks unexpectedly small")

    if failures:
        for failure in failures:
            print(f"contract-parity: {failure}", file=sys.stderr)
        return 1
    print(
        f"contract-parity: runtime, OpenAPI ({len(openapi_inventory)} operations), GraphQL, and SDK versions aligned at {version}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
