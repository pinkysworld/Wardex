#!/usr/bin/env python3
"""Convert the current `## [Unreleased]` heading into a versioned section.

Used after tagging a release so the changelog ships with both:
- a versioned section for the just-released tag, and
- a fresh `## [Unreleased]` placeholder for the next cycle.

Usage:
    scripts/changelog_reset_unreleased.py 0.55.0
    scripts/changelog_reset_unreleased.py --version 0.55.0 --date 2026-04-26
"""
from __future__ import annotations

import argparse
import datetime as _dt
import pathlib
import re
import sys


CHANGELOG_PATH = pathlib.Path(__file__).resolve().parent.parent / "CHANGELOG.md"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", nargs="?", help="Version that just shipped, e.g. 0.55.0")
    parser.add_argument("--version", dest="version_kw")
    parser.add_argument(
        "--date",
        default=_dt.date.today().isoformat(),
        help="Release date in YYYY-MM-DD (defaults to today, UTC)",
    )
    parser.add_argument(
        "--title",
        default="",
        help="Optional human title appended after the version, e.g. 'Per-Lane Command APIs'",
    )
    args = parser.parse_args()
    version = args.version or args.version_kw
    if not version:
        parser.error("a version (positional or --version) is required")

    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        parser.error(f"version must look like X.Y.Z, got {version!r}")

    text = CHANGELOG_PATH.read_text(encoding="utf-8")
    if f"## [{version}]" in text:
        print(f"changelog already contains a section for {version}; nothing to do",
              file=sys.stderr)
        return 0
    if "## [Unreleased]" not in text:
        parser.error("changelog is missing a `## [Unreleased]` heading")

    suffix = f" — {args.title}" if args.title else ""
    new_heading = f"## [Unreleased]\n\n## [{version}] — {args.date}{suffix}"
    updated = text.replace("## [Unreleased]", new_heading, 1)
    CHANGELOG_PATH.write_text(updated, encoding="utf-8")
    print(f"changelog reset: opened section {version} ({args.date}) and reseeded [Unreleased]")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
