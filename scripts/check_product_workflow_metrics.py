#!/usr/bin/env python3
"""Validate Wardex product workflow and metrics design guardrails."""

from __future__ import annotations

import json
import pathlib
import sys
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
DOC_PATH = ROOT / "docs" / "PRODUCT_WORKFLOW_METRICS_SPINE.md"
MANIFEST_PATH = ROOT / "docs" / "product" / "workflow_metrics_spine.json"
SEARCH_PATHS = [
    ROOT / "docs" / "openapi.yaml",
    ROOT / "src" / "server.rs",
    ROOT / "src" / "server_collectors.rs",
    ROOT / "src" / "openapi.rs",
]

EXPECTED_WORKFLOWS = [
    "connector_setup_to_value",
    "first_run_protected_endpoint_journey",
    "case_closure_and_handoff_readiness",
    "scoped_analyst_copilot",
    "command_center_and_soc_workbench_value_flow",
    "customer_facing_value_reporting",
]
EXPECTED_EVENT_FIELDS = {
    "workflow",
    "entity_id",
    "state_from",
    "state_to",
    "event",
    "timestamp",
    "context",
}
EXPECTED_PRIORITIES = [
    "assistant_scope_parity",
    "workflow_event_taxonomy",
    "first_value_instrumentation",
]


def load_manifest() -> dict[str, Any]:
    with MANIFEST_PATH.open(encoding="utf-8") as fh:
        return json.load(fh)


def read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def main() -> int:
    failures: list[str] = []

    if not DOC_PATH.is_file():
        print(f"product-workflow: missing {DOC_PATH.relative_to(ROOT)}", file=sys.stderr)
        return 2
    if not MANIFEST_PATH.is_file():
        print(f"product-workflow: missing {MANIFEST_PATH.relative_to(ROOT)}", file=sys.stderr)
        return 2

    manifest = load_manifest()
    doc = read(DOC_PATH)
    searchable_text = "\n".join(read(path) for path in SEARCH_PATHS if path.is_file())

    if manifest.get("canonical_product_name") != "Wardex":
        failures.append("canonical_product_name must remain Wardex")

    if "workflow_metrics_spine.json" not in doc:
        failures.append("docs/PRODUCT_WORKFLOW_METRICS_SPINE.md must reference the manifest path")

    required_fields = set(manifest.get("shared_event_schema", {}).get("required_fields", []))
    if required_fields != EXPECTED_EVENT_FIELDS:
        failures.append(
            "shared_event_schema.required_fields must match the canonical WorkflowEvent fields"
        )

    priorities = [item.get("id") for item in manifest.get("implementation_priorities", [])]
    if priorities != EXPECTED_PRIORITIES:
        failures.append(
            "implementation_priorities must preserve assistant_scope_parity, "
            "workflow_event_taxonomy, first_value_instrumentation in that order"
        )

    workflows = manifest.get("workflows", [])
    workflow_ids = [workflow.get("id") for workflow in workflows]
    if workflow_ids != EXPECTED_WORKFLOWS:
        failures.append("workflow ids must preserve the canonical Wardex workflow order")

    if len(set(workflow_ids)) != len(workflow_ids):
        failures.append("workflow ids must be unique")

    for workflow in workflows:
        workflow_id = workflow.get("id", "<missing>")
        label = workflow.get("label", workflow_id)
        if label not in doc:
            failures.append(f"{workflow_id} label {label!r} must appear in the design doc")

        states = workflow.get("states", [])
        events = workflow.get("events", [])
        metrics = workflow.get("metrics", [])
        api_paths = workflow.get("api_paths", [])
        backend_hooks = workflow.get("backend_hooks", [])
        frontend_hooks = workflow.get("frontend_hooks", [])

        if workflow.get("first_value_state") not in states:
            failures.append(f"{workflow_id} first_value_state must be present in states")
        if len(states) < 4:
            failures.append(f"{workflow_id} must declare at least four states")
        if len(states) != len(set(states)):
            failures.append(f"{workflow_id} states must be unique")
        if len(events) < 4:
            failures.append(f"{workflow_id} must declare at least four events")
        if len(events) != len(set(events)):
            failures.append(f"{workflow_id} events must be unique")
        if not metrics:
            failures.append(f"{workflow_id} must declare metrics")
        if len({metric.get('id') for metric in metrics}) != len(metrics):
            failures.append(f"{workflow_id} metric ids must be unique")
        if not api_paths:
            failures.append(f"{workflow_id} must declare api_paths")
        if not backend_hooks:
            failures.append(f"{workflow_id} must declare backend_hooks")
        if not frontend_hooks:
            failures.append(f"{workflow_id} must declare frontend_hooks")

        for api_path in api_paths:
            if api_path not in searchable_text:
                failures.append(
                    f"{workflow_id} api path {api_path} is not present in repo route/docs sources"
                )

        for hook_group, hooks in (("backend", backend_hooks), ("frontend", frontend_hooks)):
            for hook in hooks:
                hook_path = ROOT / hook.get("path", "")
                pattern = hook.get("pattern", "")
                if not hook_path.is_file():
                    failures.append(
                        f"{workflow_id} {hook_group} hook file missing: {hook_path.relative_to(ROOT)}"
                    )
                    continue
                source = read(hook_path)
                if pattern not in source:
                    failures.append(
                        f"{workflow_id} {hook_group} hook pattern {pattern!r} missing from {hook_path.relative_to(ROOT)}"
                    )

    if failures:
        for failure in failures:
            print(f"product-workflow: {failure}", file=sys.stderr)
        return 1

    print(
        "product-workflow: "
        f"{len(workflows)} workflows, {len(required_fields)} shared event fields, and "
        f"{len(priorities)} implementation priorities remain aligned with Wardex product surfaces"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
