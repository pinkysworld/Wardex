#!/usr/bin/env python3
"""Generate the release-facts manifest used by docs, site, and packaging gates."""

from __future__ import annotations

import json
import pathlib
import re
import tomllib


ROOT = pathlib.Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "site" / "data" / "release_facts.json"

INSTALL_CHANNELS = [
    "source",
    "github-release-archives",
    "apt",
    "rpm",
    "homebrew",
    "container-image",
    "helm",
]


def load_cargo() -> dict:
    with (ROOT / "Cargo.toml").open("rb") as handle:
        return tomllib.load(handle)


def openapi_operation_count() -> int:
    source = (ROOT / "docs" / "openapi.yaml").read_text(encoding="utf-8")
    count = 0
    current_path: str | None = None
    for line in source.splitlines():
        if re.match(r"^  /api/[^:]+:\s*$", line):
            current_path = line.strip().rstrip(":")
            continue
        if current_path and re.match(r"^    (get|post|put|patch|delete|options|head):\s*$", line):
            count += 1
    return count


def rust_module_count() -> int:
    return len(list((ROOT / "src").glob("*.rs")))


def rust_test_count() -> int:
    count = 0
    for path in ROOT.rglob("*.rs"):
        source = path.read_text(encoding="utf-8", errors="ignore")
        count += len(re.findall(r"#\[(?:tokio::)?test\b", source))
    return count


def admin_console_test_count() -> int:
    count = 0
    for path in (ROOT / "admin-console" / "src").rglob("*.[jt]s*"):
        source = path.read_text(encoding="utf-8", errors="ignore")
        count += len(re.findall(r"\b(?:it|test)\s*\(", source))
    return count


def playwright_test_counts() -> tuple[int, int]:
    specs = 0
    tests = 0
    for path in (ROOT / "tests" / "playwright").rglob("*.spec.js"):
        specs += 1
        source = path.read_text(encoding="utf-8", errors="ignore")
        tests += len(re.findall(r"\btest\s*\(", source))
    return specs, tests


def main() -> int:
    cargo = load_cargo()
    rust_tests = rust_test_count()
    admin_tests = admin_console_test_count()
    playwright_specs, playwright_tests = playwright_test_counts()
    facts = {
        "product_name": "Wardex",
        "version": cargo["package"]["version"],
        "license": {
            "spdx": cargo["package"]["license"],
            "commercial_file": "LICENSE.COMMERCIAL",
        },
        "support": {
            "page_url": "https://minh.systems/Wardex/support/",
            "email": "support@wardex.dev",
            "security_email": "security@wardex.dev",
            "security_advisory_url": "https://github.com/pinkysworld/Wardex/security/advisories/new",
        },
        "hardening": {
            "production_controls": 59,
            "implemented_controls": 59,
            "label": "100% (59/59 controls implemented)",
        },
        "distribution": {
            "install_channels": INSTALL_CHANNELS,
            "homebrew_tap": "pinkysworld/wardex",
            "apt_repo": "https://pinkysworld.github.io/Wardex/apt",
            "ghcr_image": "ghcr.io/pinkysworld/wardex",
        },
        "counts": {
            "rust_modules": rust_module_count(),
            "openapi_operations": openapi_operation_count(),
            "rust_tests": rust_tests,
            "admin_console_tests": admin_tests,
            "playwright_specs": playwright_specs,
            "playwright_tests": playwright_tests,
            "total_automated_checks": rust_tests + admin_tests + playwright_tests,
        },
        "notes": {
            "evaluation_label": "Seeded demo data is for evaluation only.",
            "support_sla_summary": "Community guidance, 72h starter email, 24h team email, 8x5 business, 24/7 enterprise.",
        },
    }

    OUTPUT.write_text(json.dumps(facts, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"release-facts: wrote {OUTPUT.relative_to(ROOT)} for v{facts['version']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
