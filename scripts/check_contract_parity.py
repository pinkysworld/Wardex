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
    ("GET", "/api/detection/trust/overview"),
    ("GET", "/api/detection/trust/rules"),
    ("GET", "/api/detection/trust/rules/{id}"),
    ("GET", "/api/detection/trust/tuning-drafts"),
    ("POST", "/api/detection/trust/tuning-drafts"),
    ("POST", "/api/detection/trust/tuning-drafts/{id}/preview"),
    ("POST", "/api/detection/trust/tuning-drafts/{id}/approve"),
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
    ("GET", "/api/detection/tuning/feedback"),
    ("GET", "/api/detection/explain"),
    ("POST", "/api/response/request"),
    ("GET", "/api/response/requests"),
    ("GET", "/api/response/audit"),
    ("GET", "/api/response/execution-audit"),
    ("POST", "/api/response/approve"),
    ("POST", "/api/response/execute"),
    ("GET", "/api/response/approvals"),
    ("GET", "/api/response/approval-overview"),
    ("GET", "/api/remediation/safety"),
    ("GET", "/api/playbook/execution/{id}/recovery-actions"),
    ("GET", "/api/support/bundle"),
    ("GET", "/api/ws/stats"),
    ("GET", "/api/ws/health"),
    ("GET", "/api/stream/readiness"),
    ("GET", "/api/stream/reliability-lab"),
    ("GET", "/api/operator/workspaces"),
    ("POST", "/api/alerts/feedback"),
    ("GET", "/api/alerts/feedback/summary"),
    ("GET", "/api/alerts/evidence-chain"),
    ("POST", "/api/detection-lab/runs"),
    ("GET", "/api/detection-lab/status"),
    ("GET", "/api/detection-lab/history"),
    ("GET", "/api/detection-lab/report"),
    ("GET", "/api/response/safety"),
    ("POST", "/api/response/preview"),
    ("POST", "/api/response/verify"),
    ("GET", "/api/integrations/marketplace"),
    ("POST", "/api/integrations/validate"),
    ("GET", "/api/integrations/sample-event"),
    ("GET", "/api/operations/health"),
    ("GET", "/api/operations/health/snapshot"),
    ("GET", "/api/malware/explain"),
    ("GET", "/api/malware/scan-diff"),
    ("GET", "/api/sdk/contract-status"),
    ("GET", "/api/admin/rbac-coverage"),
    ("GET", "/api/rbac/coverage"),
    ("GET", "/api/search/performance-slo"),
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
    "/api/detection/trust/overview",
    "/api/detection/trust/rules",
    "/api/detection/trust/tuning-drafts",
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
    "/api/detection/tuning/feedback",
    "/api/detection/explain",
    "/api/response/request",
    "/api/response/audit",
    "/api/response/execution-audit",
    "/api/response/approve",
    "/api/response/execute",
    "/api/response/approval-overview",
    "/api/remediation/safety",
    "/api/playbook/execution/",
    "/recovery-actions",
    "/api/support/bundle",
    "/api/ws/stats",
    "/api/ws/health",
    "/api/stream/readiness",
    "/api/stream/reliability-lab",
    "/api/operator/workspaces",
    "/api/alerts/feedback",
    "/api/alerts/feedback/summary",
    "/api/alerts/evidence-chain",
    "/api/detection-lab/runs",
    "/api/detection-lab/status",
    "/api/detection-lab/history",
    "/api/detection-lab/report",
    "/api/response/safety",
    "/api/response/preview",
    "/api/response/verify",
    "/api/integrations/marketplace",
    "/api/integrations/validate",
    "/api/integrations/sample-event",
    "/api/operations/health",
    "/api/operations/health/snapshot",
    "/api/malware/explain",
    "/api/malware/scan-diff",
    "/api/sdk/contract-status",
    "/api/admin/rbac-coverage",
    "/api/search/performance-slo",
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


def openapi_yaml_operation_metadata(source: str) -> dict[tuple[str, str], dict[str, str | None]]:
    metadata: dict[tuple[str, str], dict[str, str | None]] = {}
    current_path: str | None = None
    current_method: str | None = None
    in_security_block = False
    for line in source.splitlines():
        path_match = re.match(r"^  (/api/[^:]+):\s*$", line)
        if path_match:
            current_path = path_match.group(1)
            current_method = None
            in_security_block = False
            continue
        if re.match(r"^[^ ].*", line):
            current_path = None
            current_method = None
            in_security_block = False
            continue
        operation_match = re.match(r"^    (get|post|put|delete|patch):\s*$", line)
        if operation_match and current_path:
            current_method = operation_match.group(1).upper()
            metadata[(current_method, current_path)] = {
                "operation_id": None,
                "auth": None,
            }
            in_security_block = False
            continue
        operation_id_match = re.match(r"^      operationId:\s*(\S+)\s*$", line)
        if operation_id_match and current_path and current_method:
            metadata[(current_method, current_path)]["operation_id"] = operation_id_match.group(1)
            continue
        auth_match = re.match(r"^      x-wardex-auth:\s*([a-z_]+)\s*$", line)
        if auth_match and current_path and current_method:
            metadata[(current_method, current_path)]["auth"] = auth_match.group(1)
            in_security_block = False
            continue
        if re.match(r"^      security:\s*$", line) and current_path and current_method:
            in_security_block = True
            continue
        if in_security_block and re.match(r"^      - \{\}\s*$", line):
            metadata[(current_method, current_path)]["auth"] = metadata[(current_method, current_path)][
                "auth"
            ] or "public"
            continue
        if in_security_block and re.match(r"^      - bearerAuth:\s*\[\]\s*$", line):
            metadata[(current_method, current_path)]["auth"] = metadata[(current_method, current_path)][
                "auth"
            ] or "authenticated"
            continue
        if in_security_block and re.match(r"^      [A-Za-z-]", line):
            in_security_block = False
    return metadata


def openapi_yaml_auth_metadata(source: str) -> dict[tuple[str, str], str]:
    return {
        operation: values["auth"]
        for operation, values in openapi_yaml_operation_metadata(source).items()
        if values["auth"]
    }


def openapi_yaml_deprecations(source: str) -> dict[tuple[str, str], dict[str, str]]:
    deprecations: dict[tuple[str, str], dict[str, str]] = {}
    current_path: str | None = None
    current_method: str | None = None
    current_fields: dict[str, str] | None = None

    def flush() -> None:
        if current_path and current_method and current_fields and current_fields.get("deprecated") == "true":
            deprecations[(current_method, current_path)] = dict(current_fields)

    for line in source.splitlines():
        path_match = re.match(r"^  (/api/[^:]+):\s*$", line)
        if path_match:
            flush()
            current_path = path_match.group(1)
            current_method = None
            current_fields = None
            continue
        if re.match(r"^[^ ].*", line):
            flush()
            current_path = None
            current_method = None
            current_fields = None
            continue
        operation_match = re.match(r"^    (get|post|put|delete|patch):\s*$", line)
        if operation_match and current_path:
            flush()
            current_method = operation_match.group(1).upper()
            current_fields = {}
            continue
        field_match = re.match(
            r"^      (deprecated|x-wardex-deprecated-since|x-wardex-sunset|x-wardex-replacement):\s*(.*?)\s*$",
            line,
        )
        if field_match and current_fields is not None:
            current_fields[field_match.group(1)] = field_match.group(2).strip().strip('"\'')

    flush()
    return deprecations


def main() -> int:
    version = cargo_version()
    failures: list[str] = []

    if python_sdk_version() != version:
        failures.append(f"Python SDK version {python_sdk_version()} != runtime {version}")
    if typescript_sdk_version() != version:
        failures.append(f"TypeScript SDK version {typescript_sdk_version()} != runtime {version}")

    endpoint_source = "\n".join(
        path.read_text(errors="ignore") for path in sorted((ROOT / "src").glob("server*.rs"))
    )
    openapi_source = "\n".join(
        path.read_text(errors="ignore") for path in sorted((ROOT / "src").glob("openapi*.rs"))
    )
    docs_openapi_source = (ROOT / "docs/openapi.yaml").read_text(errors="ignore")
    ts_sdk_source = (ROOT / "sdk/typescript/src/index.ts").read_text(errors="ignore")
    py_sdk_source = (ROOT / "sdk/python/wardex/client.py").read_text(errors="ignore")
    openapi_inventory = openapi_operations(openapi_source)
    docs_openapi_inventory = openapi_yaml_operations(docs_openapi_source)
    docs_operation_metadata = openapi_yaml_operation_metadata(docs_openapi_source)
    docs_auth_metadata = openapi_yaml_auth_metadata(docs_openapi_source)
    docs_deprecations = openapi_yaml_deprecations(docs_openapi_source)

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

    operation_id_index: dict[str, list[tuple[str, str]]] = {}
    for (method, endpoint), metadata in sorted(docs_operation_metadata.items()):
        operation_id = metadata["operation_id"]
        auth = metadata["auth"]
        if not operation_id:
            failures.append(f"{method} {endpoint} missing operationId in docs/openapi.yaml")
        else:
            operation_id_index.setdefault(operation_id, []).append((method, endpoint))
        if not auth:
            failures.append(f"{method} {endpoint} missing x-wardex-auth in docs/openapi.yaml")

    for operation_id, operations in sorted(operation_id_index.items()):
        if len(operations) > 1:
            rendered = ", ".join(f"{method} {path}" for method, path in operations)
            failures.append(
                f"duplicate operationId {operation_id} in docs/openapi.yaml for {rendered}"
            )

    for operation, expected_auth in sorted(REQUIRED_AUTH_METADATA.items()):
        if docs_auth_metadata.get(operation) != expected_auth:
            method, endpoint = operation
            actual = docs_auth_metadata.get(operation, "missing")
            failures.append(
                f"{method} {endpoint} docs/openapi.yaml x-wardex-auth {actual} != {expected_auth}"
            )

    for operation, fields in sorted(docs_deprecations.items()):
        missing = [
            name
            for name in (
                "x-wardex-deprecated-since",
                "x-wardex-sunset",
                "x-wardex-replacement",
            )
            if not fields.get(name)
        ]
        if missing:
            method, endpoint = operation
            failures.append(
                f"{method} {endpoint} deprecated in docs/openapi.yaml without {', '.join(missing)}"
            )

    if docs_deprecations and "Deprecation" not in endpoint_source:
        failures.append("runtime response wrapper missing Deprecation header support")
    if docs_deprecations and "Sunset" not in endpoint_source:
        failures.append("runtime response wrapper missing Sunset header support")

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
        f"contract-parity: runtime, OpenAPI builder ({len(openapi_inventory)} operations), docs/openapi.yaml ({len(docs_openapi_inventory)} operations), GraphQL, SDK versions, and {len(docs_deprecations)} active deprecation(s) aligned at {version}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
