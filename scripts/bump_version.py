#!/usr/bin/env python3
"""Bump or verify the Wardex version across every release-critical file.

`Cargo.toml` is the single source of truth. Every other version-bearing
file must agree with it, or releases drift (and CI jobs such as
`sdk-generation` fail late with an opaque `git diff` instead of a clear
message).

Usage:
    scripts/bump_version.py --check        # verify all files match Cargo.toml
    scripts/bump_version.py 1.0.24         # rewrite all files to 1.0.24

The `--check` mode is wired into CI (the `contract-parity` job) so a missed
location fails fast with a precise pointer to the offending file.
"""

from __future__ import annotations

import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
SEMVER = re.compile(r"^\d+\.\d+\.\d+$")
VER = r"\d+\.\d+\.\d+"

# Each entry: (relative path, regex with ONE capture group around the version,
# expected number of matches). When the count does not match, the location
# spec itself is stale and must be updated alongside the file.
LOCATIONS: list[tuple[str, str, int]] = [
    ("Cargo.toml", rf'(?m)^version = "({VER})"', 1),
    ("sdk/python/pyproject.toml", rf'(?m)^version = "({VER})"', 1),
    ("sdk/python/wardex/__init__.py", rf'__version__ = "({VER})"', 1),
    ("sdk/typescript/package.json", rf'"version": "({VER})"', 1),
    # package-lock.json carries the project version twice: the root object and
    # the packages[""] self-entry. Both are immediately preceded by the project
    # name, which the 80+ dependency version fields never are, so anchoring on
    # the name keeps the match precise.
    ("sdk/typescript/package-lock.json", rf'"name": "@wardex/sdk",\s*"version": "({VER})"', 2),
    ("deploy/helm/wardex/Chart.yaml", rf'(?m)^version: ({VER})\s*$', 1),
    ("deploy/helm/wardex/Chart.yaml", rf'(?m)^appVersion: "({VER})"', 1),
    ("deploy/helm/wardex/values.yaml", rf'(?m)^\s*tag: "({VER})"', 1),
    ("deploy/otlp.yaml", rf'service\.version: "({VER})"', 2),
    ("docs/openapi.yaml", rf'(?m)^  version: ({VER})\s*$', 1),
]


def cargo_version() -> str:
    with (ROOT / "Cargo.toml").open("rb") as handle:
        return tomllib.load(handle)["package"]["version"]


def found_versions(text: str, regex: str) -> list[str]:
    return re.compile(regex).findall(text)


def rewrite(text: str, regex: str, new: str, count: int) -> tuple[str, int]:
    pattern = re.compile(regex)

    def repl(match: re.Match[str]) -> str:
        whole = match.group(0)
        rel_start = match.start(1) - match.start(0)
        rel_end = match.end(1) - match.start(0)
        return whole[:rel_start] + new + whole[rel_end:]

    return pattern.subn(repl, text, count=count)


def check(expected: str) -> int:
    failures: list[str] = []
    total = 0
    for rel_path, regex, count in LOCATIONS:
        path = ROOT / rel_path
        if not path.is_file():
            failures.append(f"{rel_path}: file is missing")
            continue
        versions = found_versions(path.read_text(encoding="utf-8"), regex)
        if len(versions) != count:
            failures.append(
                f"{rel_path}: expected {count} version match(es) for /{regex}/, found {len(versions)} "
                "(update scripts/bump_version.py LOCATIONS)"
            )
            continue
        for value in versions:
            total += 1
            if value != expected:
                failures.append(f"{rel_path}: version {value!r} != Cargo.toml {expected!r}")

    if failures:
        for failure in failures:
            print(f"version-check: {failure}", file=sys.stderr)
        return 1
    print(f"version-check: all {total} release version fields aligned at {expected}")
    return 0


def bump(new: str) -> int:
    if not SEMVER.match(new):
        print(f"version-check: target version must look like X.Y.Z, got {new!r}", file=sys.stderr)
        return 1

    # Apply per (path, regex) so multiple specs on one file compose correctly.
    edited: dict[str, str] = {}
    failures: list[str] = []
    for rel_path, regex, count in LOCATIONS:
        path = ROOT / rel_path
        if not path.is_file():
            failures.append(f"{rel_path}: file is missing")
            continue
        text = edited.get(rel_path, path.read_text(encoding="utf-8"))
        new_text, n = rewrite(text, regex, new, count)
        if n != count:
            failures.append(
                f"{rel_path}: expected to rewrite {count} match(es) for /{regex}/, rewrote {n} "
                "(update scripts/bump_version.py LOCATIONS)"
            )
            continue
        edited[rel_path] = new_text

    if failures:
        for failure in failures:
            print(f"version-check: {failure}", file=sys.stderr)
        return 1

    for rel_path, text in edited.items():
        (ROOT / rel_path).write_text(text, encoding="utf-8")

    print(f"version-check: rewrote {len(edited)} files to {new}")
    print("Next steps:")
    print(f"  python3 scripts/changelog_reset_unreleased.py {new}")
    print("  python3 scripts/build_changelog.py CHANGELOG.md site/changelog.html")
    print("  cargo build   # refresh Cargo.lock")
    print("  python3 scripts/bump_version.py --check")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0] in {"-h", "--help"}:
        print(__doc__)
        return 0 if argv and argv[0] in {"-h", "--help"} else 1
    if argv[0] == "--check":
        return check(cargo_version())
    return bump(argv[0])


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
