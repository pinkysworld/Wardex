#!/usr/bin/env python3
"""Validate release-facing facts across docs, site, and package metadata."""

from __future__ import annotations

import json
import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
FACTS_PATH = ROOT / "site" / "data" / "release_facts.json"

README = ROOT / "README.md"
GETTING_STARTED = ROOT / "docs" / "GETTING_STARTED.md"
STATUS = ROOT / "docs" / "STATUS.md"
RESOURCES = ROOT / "site" / "resources.html"
API_PAGE = ROOT / "site" / "api.html"
PRICING = ROOT / "site" / "pricing.html"
INDEX = ROOT / "site" / "index.html"
FEATURES = ROOT / "site" / "features.html"
ARCHITECTURE = ROOT / "site" / "architecture.html"
SUPPORT = ROOT / "site" / "support" / "index.html"
DONATE = ROOT / "site" / "donate.html"
INTEGRATIONS = ROOT / "site" / "integrations.html"
CHECKOUT = ROOT / "site" / "checkout.html"
CHANGELOG = ROOT / "site" / "changelog.html"
APP_JS = ROOT / "site" / "app.js"
RENDER_HOMEBREW = ROOT / "deploy" / "homebrew" / "render_formula.sh"
HOMEBREW_FORMULA = ROOT / "deploy" / "homebrew" / "wardex.rb"

STALE_CONTACT = "mip@gmx.biz"


def read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def load_facts() -> dict:
    return json.loads(read(FACTS_PATH))


def require_contains(failures: list[str], path: pathlib.Path, text: str, needle: str, label: str) -> None:
    if needle not in text:
        failures.append(f"{path.relative_to(ROOT)} missing {label}: {needle}")


def require_absent(failures: list[str], path: pathlib.Path, text: str, needle: str) -> None:
    if needle in text:
        failures.append(f"{path.relative_to(ROOT)} still contains stale value {needle!r}")


def main() -> int:
    facts = load_facts()
    version = facts["version"]
    counts = facts["counts"]
    support = facts["support"]
    license_spdx = facts["license"]["spdx"]
    hardening = facts["hardening"]["label"]
    total_checks = counts["total_automated_checks"]
    rust_tests = counts["rust_tests"]
    admin_tests = counts["admin_console_tests"]
    playwright_specs = counts["playwright_specs"]
    playwright_tests = counts["playwright_tests"]
    ops = counts["openapi_operations"]
    modules = counts["rust_modules"]

    failures: list[str] = []

    readme = read(README)
    require_contains(failures, README, readme, f"## Current Release: `v{version}`", "current release header")
    require_contains(failures, README, readme, support["page_url"], "canonical support page")
    require_contains(failures, README, readme, support["email"], "support email")

    getting_started = read(GETTING_STARTED)
    require_contains(
        failures,
        GETTING_STARTED,
        getting_started,
        f"The current release tracks {rust_tests} Rust test functions, {admin_tests} admin-console tests, and {playwright_tests} managed Playwright checks across {playwright_specs} browser specs.",
        "release test-count summary",
    )
    for channel in ("brew tap pinkysworld/wardex", "sudo apt-get install wardex", "sudo rpm -i ./wardex-*.x86_64.rpm"):
        require_contains(failures, GETTING_STARTED, getting_started, channel, "install channel")

    status = read(STATUS)
    require_contains(failures, STATUS, status, f"- **Version:** `{version}`", "version bullet")
    require_contains(failures, STATUS, status, f"- **Source footprint:** {modules} Rust source modules", "source-footprint bullet")
    require_contains(failures, STATUS, status, f"- **Production hardening:** {hardening}", "hardening bullet")
    require_contains(failures, STATUS, status, support["email"], "support email")
    require_contains(failures, STATUS, status, support["security_email"], "security email")

    app_js = read(APP_JS)
    for label, expected in (
        ("RELEASE_VERSION", version),
        ("MODULE_COUNT", str(modules)),
        ("API_COUNT", str(ops)),
        ("TEST_COUNT", str(total_checks)),
    ):
        require_contains(failures, APP_JS, app_js, f'const {label} = "{expected}";', label)
    require_contains(failures, APP_JS, app_js, 'file: "support/index.html"', "support route target")

    resources = read(RESOURCES)
    require_contains(failures, RESOURCES, resources, f"Track {ops} documented operations", "OpenAPI operation count")
    require_contains(failures, RESOURCES, resources, support["email"], "support email")

    api_page = read(API_PAGE)
    require_contains(failures, API_PAGE, api_page, f"{ops} documented operations", "API operation count")
    require_contains(failures, API_PAGE, api_page, support["email"], "API contact email")

    pricing = read(PRICING)
    require_contains(failures, PRICING, pricing, support["email"], "pricing support email")
    require_contains(failures, PRICING, pricing, f"<span id=\"license-version\">v{version}</span>", "pricing version")
    require_contains(failures, PRICING, pricing, "72h email", "starter SLA")
    require_contains(failures, PRICING, pricing, "24/7 support, signed SLA", "enterprise SLA")

    features = read(FEATURES)
    require_contains(failures, FEATURES, features, f"{ops} documented operations", "features OpenAPI operation count")
    require_contains(failures, FEATURES, features, support["email"], "features support email")

    architecture = read(ARCHITECTURE)
    require_contains(failures, ARCHITECTURE, architecture, support["email"], "architecture support email")

    support_page = read(SUPPORT)
    require_contains(failures, SUPPORT, support_page, support["email"], "support mailbox")
    require_contains(failures, SUPPORT, support_page, support["security_email"], "security mailbox")
    require_contains(failures, SUPPORT, support_page, "72h email", "starter SLA")
    require_contains(failures, SUPPORT, support_page, "24/7 enterprise coverage", "enterprise SLA")
    require_contains(failures, SUPPORT, support_page, support["security_advisory_url"], "security advisory link")

    donate = read(DONATE)
    require_contains(failures, DONATE, donate, "url=./support/", "canonical support redirect")

    for path in (INDEX, FEATURES, ARCHITECTURE, INTEGRATIONS, CHECKOUT, CHANGELOG, PRICING, SUPPORT, API_PAGE, RESOURCES, README):
        text = read(path)
        require_absent(failures, path, text, STALE_CONTACT)

    render_formula = read(RENDER_HOMEBREW)
    homebrew_formula = read(HOMEBREW_FORMULA)
    require_contains(failures, RENDER_HOMEBREW, render_formula, f'license "{license_spdx}"', "Homebrew render license")
    require_contains(failures, HOMEBREW_FORMULA, homebrew_formula, f'license "{license_spdx}"', "Homebrew formula license")
    require_absent(failures, RENDER_HOMEBREW, render_formula, "BUSL-1.1")
    require_absent(failures, HOMEBREW_FORMULA, homebrew_formula, "BUSL-1.1")

    if failures:
        for failure in failures:
            print(f"release-facts: {failure}", file=sys.stderr)
        return 1

    print(
        f"release-facts: docs, site, support, and package metadata align for v{version} with {ops} API operations and {total_checks} automated checks"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
