#!/usr/bin/env python3
"""Verify release assets and SHA256SUMS before publishing."""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import re
import sys


EXPECTED_PATTERNS = [
    re.compile(r"wardex-linux-x86_64\.tar\.gz$"),
    re.compile(r"wardex-macos-aarch64\.tar\.gz$"),
    re.compile(r"wardex-macos-x86_64\.tar\.gz$"),
    re.compile(r"wardex-windows-x86_64\.zip$"),
    re.compile(r"wardex-macos-aarch64-gatekeeper\.txt$"),
    re.compile(r"wardex-macos-x86_64-gatekeeper\.txt$"),
    re.compile(r"wardex_[0-9]+\.[0-9]+\.[0-9]+_amd64\.deb$"),
    re.compile(r"wardex-[0-9]+\.[0-9]+\.[0-9]+-1\.x86_64\.rpm$"),
    re.compile(r"wardex-sbom\.cdx\.json$"),
]


def sha256(path: pathlib.Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def parse_sums(path: pathlib.Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line_no, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2 or not re.fullmatch(r"[0-9a-fA-F]{64}", parts[0]):
            raise ValueError(f"invalid checksum line {line_no}: {raw_line!r}")
        name = parts[1].lstrip("*").removeprefix("./")
        if not name or pathlib.PurePosixPath(name).is_absolute() or ".." in pathlib.PurePosixPath(name).parts:
            raise ValueError(f"unsafe checksum path on line {line_no}: {name!r}")
        entries[name] = parts[0].lower()
    return entries


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("asset_dir", type=pathlib.Path)
    parser.add_argument("--allow-missing-expected", action="store_true")
    args = parser.parse_args()

    asset_dir = args.asset_dir.resolve()
    sums_path = asset_dir / "SHA256SUMS"
    failures: list[str] = []

    if not asset_dir.is_dir():
        print(f"release-artifacts: missing asset directory {asset_dir}", file=sys.stderr)
        return 2
    if not sums_path.is_file():
        print(f"release-artifacts: missing {sums_path}", file=sys.stderr)
        return 2

    try:
        entries = parse_sums(sums_path)
    except ValueError as error:
        print(f"release-artifacts: {error}", file=sys.stderr)
        return 2

    assets = sorted(path for path in asset_dir.iterdir() if path.is_file() and path.name != "SHA256SUMS")
    asset_names = {path.name for path in assets}
    listed_names = set(entries)

    for path in assets:
        if path.stat().st_size == 0:
            failures.append(f"empty artifact: {path.name}")
        expected_digest = entries.get(path.name)
        if not expected_digest:
            failures.append(f"artifact missing from SHA256SUMS: {path.name}")
            continue
        actual_digest = sha256(path)
        if actual_digest != expected_digest:
            failures.append(f"checksum mismatch for {path.name}: expected {expected_digest}, got {actual_digest}")

    for listed_name in sorted(listed_names - asset_names):
        failures.append(f"SHA256SUMS references missing artifact: {listed_name}")

    if not args.allow_missing_expected:
        for pattern in EXPECTED_PATTERNS:
            if not any(pattern.fullmatch(name) for name in asset_names):
                failures.append(f"missing expected release artifact matching {pattern.pattern}")

    if failures:
        for failure in failures:
            print(f"release-artifacts: {failure}", file=sys.stderr)
        return 1

    print(f"release-artifacts: verified {len(assets)} asset(s) against SHA256SUMS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
