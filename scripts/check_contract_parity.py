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
    ("GET", "/api/report-templates"),
    ("POST", "/api/report-templates"),
    ("GET", "/api/report-runs"),
    ("POST", "/api/report-runs"),
    ("GET", "/api/report-schedules"),
    ("POST", "/api/report-schedules"),
    ("GET", "/api/alerts"),
    ("GET", "/api/alerts/grouped"),
    ("GET", "/api/alerts/histogram"),
    ("GET", "/api/alerts/page"),
    ("GET", "/api/events/page"),
    ("GET", "/api/audit/log/page"),
    ("GET", "/api/queue/alerts"),
    ("GET", "/api/fleet/dashboard"),
    ("GET", "/api/operational/snapshots"),
    ("GET", "/api/operational/snapshots/verify"),
    ("GET", "/api/operational/snapshots/policy"),
    ("POST", "/api/operational/snapshots/prune"),
    ("GET", "/api/launchpad/evidence-pack"),
    ("GET", "/api/launchpad/release-diff"),
    ("GET", "/api/launchpad/demo-status"),
    ("POST", "/api/launchpad/demo-reset"),
    ("GET", "/api/release/doctor"),
    ("GET", "/api/release/observability-gates"),
    ("GET", "/api/release/provenance"),
    ("GET", "/api/release/upgrade-rehearsal"),
    ("GET", "/api/release/clean-cut"),
    ("GET", "/api/containers/release-parity"),
    ("GET", "/api/release/verification-center"),
    ("GET", "/api/deployment/self-hosted-wizard"),
    ("GET", "/api/data-quality/dashboard"),
    ("GET", "/api/performance/scale-baseline"),
    ("GET", "/api/cluster/failover-execution"),
    ("GET", "/api/secrets/rotation-operations"),
    ("GET", "/api/operator/task-automation"),
    ("GET", "/api/detection/validation-packs"),
    ("GET", "/api/monitoring/synthetic-console"),
    ("GET", "/api/incidents/timeline-replay"),
    ("GET", "/api/detection/trust-score"),
    ("GET", "/api/fleet/drift-compliance"),
    ("GET", "/api/operator/work-queue"),
    ("GET", "/api/retention/forecast"),
    ("GET", "/api/validation/adversarial"),
    ("GET", "/api/support/bundle-diff"),
    ("GET", "/api/workflows/preflight"),
    ("POST", "/api/content/rules/{id}/preflight"),
    ("GET", "/api/tenants/isolation-proof"),
    ("GET", "/api/processes/thread-proof"),
    ("GET", "/api/detection/recommendations"),
    ("GET", "/api/detection/readiness"),
    ("POST", "/api/response/request"),
    ("GET", "/api/response/requests"),
    ("POST", "/api/response/approve"),
    ("POST", "/api/response/execute"),
    ("GET", "/api/response/approvals"),
    ("GET", "/api/response/approval-overview"),
    ("GET", "/api/remediation/safety"),
    ("GET", "/api/support/bundle"),
    ("GET", "/api/ws/stats"),
    ("GET", "/api/ws/health"),
    ("GET", "/api/stream/readiness"),
    ("GET", "/api/stream/reliability-lab"),
    ("GET", "/api/sdk/contract-status"),
    ("POST", "/api/subscriptions"),
    ("GET", "/api/subscriptions/resume"),
}

REQUIRED_SDK_ENDPOINTS = {
    "/api/openapi.json",
    "/api/support/parity",
    "/api/support/readiness-evidence",
    "/api/support/first-run-proof",
    "/api/report-templates",
    "/api/report-runs",
    "/api/report-schedules",
    "/api/alerts",
    "/api/alerts/histogram",
    "/api/alerts/page",
    "/api/events/page",
    "/api/audit/log/page",
    "/api/operational/snapshots",
    "/api/operational/snapshots/verify",
    "/api/operational/snapshots/policy",
    "/api/operational/snapshots/prune",
    "/api/launchpad/evidence-pack",
    "/api/launchpad/release-diff",
    "/api/launchpad/demo-status",
    "/api/launchpad/demo-reset",
    "/api/release/doctor",
    "/api/release/observability-gates",
    "/api/release/provenance",
    "/api/release/upgrade-rehearsal",
    "/api/release/clean-cut",
    "/api/containers/release-parity",
    "/api/release/verification-center",
    "/api/deployment/self-hosted-wizard",
    "/api/data-quality/dashboard",
    "/api/performance/scale-baseline",
    "/api/cluster/failover-execution",
    "/api/secrets/rotation-operations",
    "/api/operator/task-automation",
    "/api/detection/validation-packs",
    "/api/monitoring/synthetic-console",
    "/api/incidents/timeline-replay",
    "/api/detection/trust-score",
    "/api/fleet/drift-compliance",
    "/api/operator/work-queue",
    "/api/retention/forecast",
    "/api/validation/adversarial",
    "/api/support/bundle-diff",
    "/api/workflows/preflight",
    "/api/content/rules/",
    "/preflight",
    "/api/tenants/isolation-proof",
    "/api/processes/thread-proof",
    "/api/detection/recommendations",
    "/api/detection/readiness",
    "/api/response/request",
    "/api/response/approve",
    "/api/response/execute",
    "/api/response/approval-overview",
    "/api/remediation/safety",
    "/api/support/bundle",
    "/api/ws/stats",
    "/api/ws/health",
    "/api/stream/readiness",
    "/api/stream/reliability-lab",
    "/api/sdk/contract-status",
    "/api/subscriptions",
    "/api/subscriptions/resume",
}

REQUIRED_AUTH_METADATA = {
    ("GET", "/api/health"): "public",
    ("GET", "/api/metrics"): "public",
    ("GET", "/api/openapi.json"): "public",
    ("GET", "/api/auth/sso/login"): "public",
    ("GET", "/api/auth/sso/callback"): "public",
    ("POST", "/api/auth/sso/callback"): "public",
    ("GET", "/api/agents/update"): "agent",
    ("POST", "/api/events"): "agent",
    ("GET", "/api/updates/download/{file_name}"): "agent",
    ("GET", "/api/updates/releases"): "authenticated",
    ("POST", "/api/updates/publish"): "authenticated",
    ("POST", "/api/updates/deploy"): "authenticated",
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


def openapi_yaml_operations(source: str) -> set[tuple[str, str]]:
    operations: set[tuple[str, str]] = set()
    current_path: str | None = None
    for line in source.splitlines():
        path_match = re.match(r"^  (/api/[^:]+):\s*$", line)
        if path_match:
            current_path = path_match.group(1)
            continue
        if re.match(r"^[^ ].*", line):
            current_path = None
            continue
        operation_match = re.match(r"^    (get|post|put|delete|patch):\s*$", line)
        if operation_match and current_path:
            operations.add((operation_match.group(1).upper(), current_path))
    return operations


def openapi_yaml_auth_metadata(source: str) -> dict[tuple[str, str], str]:
    metadata: dict[tuple[str, str], str] = {}
    current_path: str | None = None
    current_method: str | None = None
    for line in source.splitlines():
        path_match = re.match(r"^  (/api/[^:]+):\s*$", line)
        if path_match:
            current_path = path_match.group(1)
            current_method = None
            continue
        if re.match(r"^[^ ].*", line):
            current_path = None
            current_method = None
            continue
        operation_match = re.match(r"^    (get|post|put|delete|patch):\s*$", line)
        if operation_match and current_path:
            current_method = operation_match.group(1).upper()
            continue
        auth_match = re.match(r"^      x-wardex-auth:\s*([a-z_]+)\s*$", line)
        if auth_match and current_path and current_method:
            metadata[(current_method, current_path)] = auth_match.group(1)
    return metadata


def main() -> int:
    version = cargo_version()
    failures: list[str] = []

    if python_sdk_version() != version:
        failures.append(f"Python SDK version {python_sdk_version()} != runtime {version}")
    if typescript_sdk_version() != version:
        failures.append(f"TypeScript SDK version {typescript_sdk_version()} != runtime {version}")

    endpoint_source = (ROOT / "src/server.rs").read_text(errors="ignore")
    openapi_source = (ROOT / "src/openapi.rs").read_text(errors="ignore")
    docs_openapi_source = (ROOT / "docs/openapi.yaml").read_text(errors="ignore")
    ts_sdk_source = (ROOT / "sdk/typescript/src/index.ts").read_text(errors="ignore")
    py_sdk_source = (ROOT / "sdk/python/wardex/client.py").read_text(errors="ignore")
    openapi_inventory = openapi_operations(openapi_source)
    docs_openapi_inventory = openapi_yaml_operations(docs_openapi_source)
    docs_auth_metadata = openapi_yaml_auth_metadata(docs_openapi_source)

    for method, endpoint in sorted(REQUIRED_RUNTIME_OPENAPI_ENDPOINTS):
        if endpoint not in endpoint_source:
            failures.append(f"{method} {endpoint} missing from runtime endpoint catalog/auth routing")
        if (method, endpoint) not in openapi_inventory:
            failures.append(f"{method} {endpoint} missing from OpenAPI builder")
        if (method, endpoint) not in docs_openapi_inventory:
            failures.append(f"{method} {endpoint} missing from docs/openapi.yaml")

    for endpoint in sorted(REQUIRED_SDK_ENDPOINTS):
        if endpoint not in ts_sdk_source:
            failures.append(f"{endpoint} missing from TypeScript SDK client")
        if endpoint not in py_sdk_source:
            failures.append(f"{endpoint} missing from Python SDK client")

    if "x-wardex-auth" not in openapi_source:
        failures.append("OpenAPI builder missing x-wardex-auth operation metadata")
    for operation, expected_auth in sorted(REQUIRED_AUTH_METADATA.items()):
        if docs_auth_metadata.get(operation) != expected_auth:
            method, endpoint = operation
            actual = docs_auth_metadata.get(operation, "missing")
            failures.append(
                f"{method} {endpoint} docs/openapi.yaml x-wardex-auth {actual} != {expected_auth}"
            )

    if len(openapi_inventory) < MIN_OPENAPI_OPERATIONS:
        failures.append(
            f"OpenAPI operation inventory looks unexpectedly small ({len(openapi_inventory)} < {MIN_OPENAPI_OPERATIONS})"
        )
    if len(docs_openapi_inventory) < MIN_OPENAPI_OPERATIONS:
        failures.append(
            f"docs/openapi.yaml operation inventory looks unexpectedly small ({len(docs_openapi_inventory)} < {MIN_OPENAPI_OPERATIONS})"
        )

    operation_ids = re.findall(r'"(get|post|put|delete)[A-Z][A-Za-z0-9]+"', openapi_source)
    if len(operation_ids) < 50:
        failures.append("OpenAPI operation inventory looks unexpectedly small")

    if failures:
        for failure in failures:
            print(f"contract-parity: {failure}", file=sys.stderr)
        return 1
    print(
        f"contract-parity: runtime, OpenAPI builder ({len(openapi_inventory)} operations), docs/openapi.yaml ({len(docs_openapi_inventory)} operations), GraphQL, and SDK versions aligned at {version}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
