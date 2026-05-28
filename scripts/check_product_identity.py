#!/usr/bin/env python3
"""Validate SentinelEdge/Wardex product identity coherence across release surfaces."""

from __future__ import annotations

import pathlib
import sys
import tomllib


ROOT = pathlib.Path(__file__).resolve().parents[1]
CARGO_TOML = ROOT / "Cargo.toml"
README = ROOT / "README.md"
DOCS_README = ROOT / "docs/README.md"
RELEASE_ACCEPTANCE = ROOT / "docs/RELEASE_ACCEPTANCE.md"
APP = ROOT / "admin-console/src/App.jsx"


def read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8")


def load_identity() -> dict[str, str]:
    with CARGO_TOML.open("rb") as handle:
        cargo = tomllib.load(handle)
    metadata = cargo.get("package", {}).get("metadata", {}).get("product_identity", {})
    return {
        "product_name": str(metadata.get("product_name", "")).strip(),
        "runtime_name": str(metadata.get("runtime_name", "")).strip(),
        "admin_console_name": str(metadata.get("admin_console_name", "")).strip(),
        "repository": str(metadata.get("repository", "")).strip(),
    }


def main() -> int:
    identity = load_identity()
    failures: list[str] = []

    for key, value in identity.items():
        if not value:
            failures.append(
                f"Cargo.toml [package.metadata.product_identity] missing required `{key}`"
            )

    if failures:
        for failure in failures:
            print(f"product-identity: {failure}", file=sys.stderr)
        return 1

    readme = read(README)
    docs_readme = read(DOCS_README)
    release_acceptance = read(RELEASE_ACCEPTANCE)
    app = read(APP)

    product_name = identity["product_name"]
    runtime_name = identity["runtime_name"]
    admin_console_name = identity["admin_console_name"]
    repository = identity["repository"]

    required_checks = [
        (README, product_name, "top-level README product branding"),
        (README, runtime_name, "top-level README runtime branding"),
        (README, repository, "top-level README repository pointer"),
        (DOCS_README, product_name, "docs README product branding"),
        (DOCS_README, runtime_name, "docs README runtime branding"),
        (RELEASE_ACCEPTANCE, product_name, "release acceptance product branding"),
        (RELEASE_ACCEPTANCE, runtime_name, "release acceptance runtime branding"),
        (APP, admin_console_name, "admin console app title"),
    ]
    file_text = {
        README: readme,
        DOCS_README: docs_readme,
        RELEASE_ACCEPTANCE: release_acceptance,
        APP: app,
    }
    for path, needle, label in required_checks:
        if needle not in file_text[path]:
            failures.append(f"{path.relative_to(ROOT)} missing {label}: `{needle}`")

    if failures:
        for failure in failures:
            print(f"product-identity: {failure}", file=sys.stderr)
        return 1

    print(
        f"product-identity: metadata, docs, and admin console branding align for {product_name} ({runtime_name})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
