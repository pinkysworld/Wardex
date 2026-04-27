#!/usr/bin/env python3
"""Validate release documentation stays aligned with shipped claims."""

from __future__ import annotations

import pathlib
import re
import sys
import tomllib


ROOT = pathlib.Path(__file__).resolve().parents[1]
STATUS_DOC = ROOT / "docs/STATUS.md"
ROADMAP_DOC = ROOT / "docs/ROADMAP_XDR_PROFESSIONAL.md"
FEATURE_COVERAGE_DOC = ROOT / "docs/FEATURE_UI_COVERAGE.md"
RELEASE_ACCEPTANCE_DOC = ROOT / "docs/RELEASE_ACCEPTANCE.md"
IMPLEMENTATION_PLAN_DOC = ROOT / "docs/IMPLEMENTATION_PLAN.md"
RELEASE_ACCEPTANCE_SCRIPT = ROOT / "scripts/release_acceptance.sh"
HELM_CHART = ROOT / "deploy/helm/wardex/Chart.yaml"
HELM_VALUES = ROOT / "deploy/helm/wardex/values.yaml"

VALID_FEATURE_STATUSES = {"Implemented", "Ready", "Partial", "Missing"}

CAPABILITY_SPEC_REQUIREMENTS = {
    "Detection engineering": {"advanced_console_workflows.spec.js"},
    "SOC operations": {"advanced_console_workflows.spec.js", "live_release_smoke.spec.js"},
    "Dashboard customization": {"live_release_smoke.spec.js"},
    "UEBA, NDR, graph analytics": {"advanced_console_workflows.spec.js"},
    "Fleet, rollout, and release operations": {
        "enterprise_console_smoke.spec.js",
        "live_release_smoke.spec.js",
    },
    "Vulnerability, exposure, drift, certificates, assets": {
        "advanced_console_workflows.spec.js"
    },
    "Security policy and advanced controls": {"advanced_console_workflows.spec.js"},
    "Enterprise controls": {"enterprise_console_smoke.spec.js", "siem_settings_live.spec.js"},
    "Supportability, documentation, and contract verification": {
        "live_release_smoke.spec.js",
        "assistant_ticketing_live.spec.js",
    },
    "Reports, compliance, evidence, exports": {
        "advanced_console_workflows.spec.js",
        "assistant_ticketing_live.spec.js",
    },
    "Threat intelligence, enrichment, deception": {"advanced_console_workflows.spec.js"},
    "Long-retention history and search": {"siem_settings_live.spec.js"},
    "Cloud, SaaS, and identity collectors": {"siem_settings_live.spec.js"},
    "AI assistant and RAG analyst workflows": {"assistant_ticketing_live.spec.js"},
}


def cargo_version() -> str:
    with (ROOT / "Cargo.toml").open("rb") as handle:
        return tomllib.load(handle)["package"]["version"]


def read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def yaml_scalar(text: str, key: str) -> str | None:
    match = re.search(rf"^{re.escape(key)}:\s*([^#\n]+)", text, flags=re.MULTILINE)
    if not match:
        return None
    return match.group(1).strip().strip("'\"")


def helm_image_tag() -> str | None:
    in_image = False
    for raw_line in read(HELM_VALUES).splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip())
        stripped = raw_line.strip()
        if indent == 0:
            in_image = stripped == "image:"
            continue
        if in_image and stripped.startswith("tag:"):
            return stripped.split(":", 1)[1].strip().strip("'\"")
    return None


def release_smoke_specs() -> set[str]:
    script = read(RELEASE_ACCEPTANCE_SCRIPT)
    return set(re.findall(r"tests/playwright/([A-Za-z0-9_.-]+\.spec\.js)", script))


def feature_rows() -> list[tuple[str, str]]:
    rows = []
    for line in read(FEATURE_COVERAGE_DOC).splitlines():
        if not line.startswith("|") or line.startswith("|---"):
            continue
        cells = [cell.strip().strip("`") for cell in line.strip("|").split("|")]
        if len(cells) < 3 or cells[0] == "Capability area":
            continue
        rows.append((cells[0], cells[2]))
    return rows


def required_specs_for(capability: str) -> set[str] | None:
    if capability in CAPABILITY_SPEC_REQUIREMENTS:
        return CAPABILITY_SPEC_REQUIREMENTS[capability]
    for label, specs in CAPABILITY_SPEC_REQUIREMENTS.items():
        if capability.startswith(label) or label.startswith(capability):
            return specs
    return None


def main() -> int:
    version = cargo_version()
    failures: list[str] = []

    status = read(STATUS_DOC)
    roadmap = read(ROADMAP_DOC)
    feature_coverage = read(FEATURE_COVERAGE_DOC)
    release_acceptance = read(RELEASE_ACCEPTANCE_DOC)
    implementation_plan = read(IMPLEMENTATION_PLAN_DOC)
    helm_chart = read(HELM_CHART)
    smoke_specs = release_smoke_specs()

    chart_version = yaml_scalar(helm_chart, "version")
    chart_app_version = yaml_scalar(helm_chart, "appVersion")
    values_image_tag = helm_image_tag()

    if f"`{version}`" not in status:
        failures.append(f"docs/STATUS.md does not mention current Cargo version `{version}`")
    if f"v{version}" not in roadmap:
        failures.append(f"docs/ROADMAP_XDR_PROFESSIONAL.md does not mention v{version}")
    if chart_version != version:
        failures.append(f"deploy/helm/wardex/Chart.yaml version {chart_version!r} != Cargo version `{version}`")
    if chart_app_version != version:
        failures.append(
            f"deploy/helm/wardex/Chart.yaml appVersion {chart_app_version!r} != Cargo version `{version}`"
        )
    if values_image_tag != version:
        failures.append(
            f"deploy/helm/wardex/values.yaml image.tag {values_image_tag!r} != Cargo version `{version}`"
        )
    if "Historical note" not in implementation_plan:
        failures.append("docs/IMPLEMENTATION_PLAN.md is not marked as a historical archive")
    if "Current release state and priorities live in" not in implementation_plan:
        failures.append("docs/IMPLEMENTATION_PLAN.md does not point readers to current status docs")
    stale_plan_claims = [
        "collectors (`collector_aws.rs`, `collector_azure.rs`, `collector_gcp.rs`) have event parsers but make no actual API calls",
    ]
    for claim in stale_plan_claims:
        if claim in implementation_plan and "implementation archive" not in implementation_plan[:500]:
            failures.append(
                "docs/IMPLEMENTATION_PLAN.md contains stale collector implementation claims without an archive warning"
            )
    if "validate_release_docs.py" not in release_acceptance:
        failures.append("docs/RELEASE_ACCEPTANCE.md does not document the release-doc validation step")
    if "Release acceptance gate" not in feature_coverage:
        failures.append("docs/FEATURE_UI_COVERAGE.md is missing its release acceptance section")

    for capability, status_value in feature_rows():
        if status_value not in VALID_FEATURE_STATUSES:
            failures.append(f"{capability} has invalid UI coverage status `{status_value}`")
            continue
        if status_value not in {"Implemented", "Ready"}:
            continue

        required_specs = required_specs_for(capability)
        if not required_specs:
            failures.append(f"{capability} has no release-smoke coverage mapping")
            continue
        if smoke_specs.isdisjoint(required_specs):
            expected = ", ".join(sorted(required_specs))
            failures.append(f"{capability} is {status_value} but release_acceptance.sh lacks {expected}")

    for spec in smoke_specs:
        if not (ROOT / "tests/playwright" / spec).is_file():
            failures.append(f"release_acceptance.sh references missing Playwright spec {spec}")

    if failures:
        for failure in failures:
            print(f"release-docs: {failure}", file=sys.stderr)
        return 1

    print(f"release-docs: status, roadmap, Helm chart, UI coverage, and release gate align for v{version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
