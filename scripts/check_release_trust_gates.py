#!/usr/bin/env python3
"""Validate that release trust gates remain wired into CI and release workflows."""

from __future__ import annotations

import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"

REQUIRED_CI_SNIPPETS = {
    "panic policy": "python3 scripts/check_panic_policy.py",
    "contract parity": "python3 scripts/check_contract_parity.py",
    "release docs": "python3 scripts/validate_release_docs.py",
    "docs freshness": "python3 scripts/validate_docs_freshness.py",
    "product identity": "python3 scripts/check_product_identity.py",
}

REQUIRED_RELEASE_SNIPPETS = {
    "release panic policy": "python3 scripts/check_panic_policy.py",
    "release contract parity": "python3 scripts/check_contract_parity.py",
    "release docs": "python3 scripts/validate_release_docs.py",
    "release docs freshness": "python3 scripts/validate_docs_freshness.py",
    "release product identity": "python3 scripts/check_product_identity.py",
    "release trust checker": "python3 scripts/check_release_trust_gates.py",
    "provenance attestation": "actions/attest-build-provenance@",
    "OIDC provenance permission": "id-token: write",
    "attestation permission": "attestations: write",
    "checksum verification": "sha256sum -c SHA256SUMS",
    "artifact verifier": "python3 scripts/verify_release_artifacts.py release-assets",
    "release notes extraction": "Extract release notes",
}

PINNED_RELEASE_ACTIONS = {
    "actions/attest-build-provenance",
    "softprops/action-gh-release",
    "actions/download-artifact",
}


def read(path: pathlib.Path) -> str:
    if not path.is_file():
        raise FileNotFoundError(path.relative_to(ROOT))
    return path.read_text(encoding="utf-8")


def pinned_action_refs(workflow: str) -> dict[str, list[str]]:
    refs: dict[str, list[str]] = {}
    for action, ref in re.findall(r"uses:\s*([^@\s]+)@([^\s#]+)", workflow):
        refs.setdefault(action, []).append(ref)
    return refs


def is_sha(ref: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{40,64}", ref))


def main() -> int:
    failures: list[str] = []
    try:
        ci = read(CI_WORKFLOW)
        release = read(RELEASE_WORKFLOW)
    except FileNotFoundError as error:
        print(f"release-trust: missing workflow {error}", file=sys.stderr)
        return 2

    for label, snippet in REQUIRED_CI_SNIPPETS.items():
        if snippet not in ci:
            failures.append(f"CI workflow is missing {label}: {snippet}")

    for label, snippet in REQUIRED_RELEASE_SNIPPETS.items():
        if snippet not in release:
            failures.append(f"release workflow is missing {label}: {snippet}")

    refs = pinned_action_refs(release)
    for action in sorted(PINNED_RELEASE_ACTIONS):
        action_refs = refs.get(action, [])
        if not action_refs:
            failures.append(f"release workflow is missing required action {action}")
            continue
        unpinned = [ref for ref in action_refs if not is_sha(ref)]
        if unpinned:
            failures.append(f"release workflow uses unpinned {action} ref(s): {', '.join(unpinned)}")

    if failures:
        for failure in failures:
            print(f"release-trust: {failure}", file=sys.stderr)
        return 1

    print(
        "release-trust: CI and release workflows retain panic, contract, docs, identity, provenance, checksum, and artifact gates"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
