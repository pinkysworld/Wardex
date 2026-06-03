#!/usr/bin/env python3
"""Validate Wardex API contract ownership and AppState architecture guardrails."""

from __future__ import annotations

import json
import pathlib
import re
import sys
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "docs/architecture/contract_state_spine.json"
OPENAPI_PATH = ROOT / "docs/openapi.yaml"
SERVER_PATH = ROOT / "src/server.rs"
ROUTING_PATH = ROOT / "src/server_routing.rs"
CI_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_WORKFLOW_PATH = ROOT / ".github" / "workflows" / "release.yml"


def load_manifest() -> dict[str, Any]:
    with MANIFEST_PATH.open() as fh:
        return json.load(fh)


def docs_openapi_paths(source: str) -> list[str]:
    return re.findall(r"^  (/api/[^:]+):\s*$", source, flags=re.MULTILINE)


def docs_openapi_auth_values(source: str) -> list[str]:
    return re.findall(r"^      x-wardex-auth:\s*([a-z_]+)\s*$", source, flags=re.MULTILINE)


def route_matches_prefix(path: str, prefix: str) -> bool:
    return path == prefix or path.startswith(f"{prefix}/")


def route_template_regex(path: str) -> re.Pattern[str]:
    parts = []
    for part in re.split(r"(\{[^}]+\})", path):
        if part.startswith("{") and part.endswith("}"):
            parts.append(r"[^/]+")
        else:
            parts.append(re.escape(part))
    return re.compile(rf"^{''.join(parts)}$")


def docs_path_matches(path: str, openapi_paths: set[str], openapi_templates: list[re.Pattern[str]]) -> bool:
    return path in openapi_paths or any(template.match(path) for template in openapi_templates)


def docs_prefix_matches(prefix: str, openapi_paths: set[str]) -> bool:
    normalized = prefix.rstrip("/")
    return any(
        path == normalized or path.startswith(prefix) or prefix.startswith(f"{path}/")
        for path in openapi_paths
    )


def runtime_api_paths(source: str) -> tuple[set[str], set[str]]:
    exact_paths = set(re.findall(r'\(Method::[A-Za-z]+,\s*"(/api/[^"]+)"\)', source))
    exact_paths.update(re.findall(r'url_path\s*==\s*"(/api/[^"]+)"', source))
    exact_paths.update(re.findall(r'path\s*==\s*"(/api/[^"]+)"', source))
    prefix_paths = set(re.findall(r'url_path\.starts_with\("(/api/[^"]+)"\)', source))
    prefix_paths.update(re.findall(r'path\.starts_with\("(/api/[^"]+)"\)', source))
    return exact_paths, prefix_paths


def owning_domains(path: str, domains: list[dict[str, Any]]) -> list[str]:
    owners: list[tuple[int, str]] = []
    for domain in domains:
        for prefix in domain.get("route_prefixes", []):
            if route_matches_prefix(path, prefix):
                owners.append((len(prefix), domain["id"]))
    if not owners:
        return []
    longest = max(length for length, _ in owners)
    return sorted(owner for length, owner in owners if length == longest)


def app_state_body(source: str) -> str:
    match = re.search(r"pub\(crate\) struct AppState \{(?P<body>.*?)\n\}", source, flags=re.S)
    return match.group("body") if match else ""


def app_state_has_field(body: str, field: str) -> bool:
    return bool(
        re.search(
            rf"^\s*(?:pub\(crate\)\s+)?{re.escape(field)}\s*:",
            body,
            flags=re.MULTILINE,
        )
    )


def routing_access_classes(source: str) -> set[str]:
    match = re.search(r"pub enum ApiRouteAccess \{(?P<body>.*?)\n\}", source, flags=re.S)
    if not match:
        return set()
    variants = re.findall(r"^\s*([A-Z][A-Za-z0-9_]*)\s*,?\s*$", match.group("body"), re.M)
    return {variant.lower() for variant in variants}


def required_test_snippets(manifest: dict[str, Any]) -> dict[str, str]:
    snippets: dict[str, str] = {}
    for entry in manifest.get("release_blocking_tests", []):
        name = entry.get("name")
        command = entry.get("command")
        if name and command:
            snippets[name] = command
    return snippets


def main() -> int:
    manifest = load_manifest()
    failures: list[str] = []

    if manifest.get("canonical_product_name") != "Wardex":
        failures.append("canonical_product_name must remain Wardex")

    domains = manifest.get("route_domains", [])
    if not domains:
        failures.append("manifest must define route_domains")

    domain_ids = [domain.get("id") for domain in domains]
    if len(domain_ids) != len(set(domain_ids)):
        failures.append("route domain ids must be unique")

    seen_prefixes: dict[str, str] = {}
    for domain in domains:
        domain_id = domain.get("id", "<missing>")
        if not domain.get("owner"):
            failures.append(f"{domain_id} missing owner")
        if not domain.get("route_prefixes"):
            failures.append(f"{domain_id} missing route_prefixes")
        if not domain.get("state_fields"):
            failures.append(f"{domain_id} missing state_fields")
        if not domain.get("target_lock"):
            failures.append(f"{domain_id} missing target_lock")
        for prefix in domain.get("route_prefixes", []):
            previous = seen_prefixes.setdefault(prefix, domain_id)
            if previous != domain_id:
                failures.append(f"route prefix {prefix} assigned to both {previous} and {domain_id}")

    routing_classes = routing_access_classes(ROUTING_PATH.read_text(errors="ignore"))
    manifest_classes = set(manifest.get("auth_classes", []))
    if routing_classes != manifest_classes:
        failures.append(
            f"auth class manifest {sorted(manifest_classes)} != runtime {sorted(routing_classes)}"
        )

    openapi_source = OPENAPI_PATH.read_text(errors="ignore")
    openapi_paths = docs_openapi_paths(openapi_source)
    openapi_path_set = set(openapi_paths)
    openapi_templates = [route_template_regex(path) for path in openapi_paths if "{" in path]
    for path in sorted(openapi_paths):
        owners = owning_domains(path, domains)
        if not owners:
            failures.append(f"{path} has no route domain owner in contract_state_spine.json")
        elif len(owners) > 1:
            failures.append(f"{path} has ambiguous route domain owners: {', '.join(owners)}")

    for auth_value in sorted(set(docs_openapi_auth_values(openapi_source))):
        if auth_value not in manifest_classes:
            failures.append(f"docs/openapi.yaml uses unknown x-wardex-auth value {auth_value}")

    server_source = SERVER_PATH.read_text(errors="ignore")
    state_body = app_state_body(server_source)
    if not state_body:
        failures.append("could not locate AppState body in src/server.rs")
    else:
        for domain in domains:
            for field in domain.get("state_fields", []):
                if not app_state_has_field(state_body, field):
                    failures.append(f"{domain['id']} state field {field} missing from AppState")

    runtime_route_source = "\n".join(
        path.read_text(errors="ignore") for path in sorted((ROOT / "src").glob("server*.rs"))
    )
    runtime_exact_paths, runtime_prefix_paths = runtime_api_paths(runtime_route_source)
    internal_routes = set(manifest.get("internal_runtime_routes", []))
    internal_prefixes = set(manifest.get("internal_runtime_route_prefixes", []))
    for path in sorted(runtime_exact_paths):
        if docs_path_matches(path, openapi_path_set, openapi_templates):
            continue
        if path in internal_routes:
            continue
        if any(path.startswith(prefix) for prefix in internal_prefixes):
            continue
        failures.append(f"{path} is a runtime API route but is not in OpenAPI or internal_runtime_routes")
    for path in sorted(internal_routes):
        if path not in runtime_exact_paths:
            failures.append(f"{path} is listed in internal_runtime_routes but no runtime route was found")
    for prefix in sorted(runtime_prefix_paths):
        if docs_prefix_matches(prefix, openapi_path_set):
            continue
        if prefix in internal_prefixes:
            continue
        failures.append(
            f"{prefix}* is a runtime API route prefix but is not in OpenAPI or internal_runtime_route_prefixes"
        )
    for prefix in sorted(internal_prefixes):
        if prefix not in runtime_prefix_paths:
            failures.append(
                f"{prefix} is listed in internal_runtime_route_prefixes but no runtime prefix route was found"
            )

    migration_order = manifest.get("state_decisions", {}).get("migration_order", [])
    if set(migration_order) != set(domain_ids):
        failures.append("state_decisions.migration_order must contain every route domain exactly once")

    ci_source = CI_WORKFLOW_PATH.read_text(errors="ignore")
    release_source = RELEASE_WORKFLOW_PATH.read_text(errors="ignore")
    for name, command in required_test_snippets(manifest).items():
        if command not in ci_source:
            failures.append(f"CI workflow does not run release-blocking test {name}: {command}")
        if command not in release_source:
            failures.append(f"release workflow does not run release-blocking test {name}: {command}")

    if failures:
        for failure in failures:
            print(f"architecture-guardrails: {failure}", file=sys.stderr)
        return 1

    print(
        "architecture-guardrails: "
        f"{len(openapi_paths)} OpenAPI paths mapped to {len(domains)} route domains; "
        f"{len(runtime_exact_paths)} runtime exact routes and {len(runtime_prefix_paths)} runtime prefixes checked; "
        f"{len(manifest_classes)} auth classes and AppState field anchors aligned"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
