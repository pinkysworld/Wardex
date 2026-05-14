#!/usr/bin/env python3
"""Detect accidental iCloud-style duplicate source files.

Fails when tracked or untracked files look like Finder/iCloud duplicate copies such as:
- "name 2.ext"
- "name (1).ext"

Build/cache directories are ignored.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

IGNORED_PREFIXES = (
    "target/",
    "admin-console/node_modules/",
    "admin-console/dist/",
    "sdk/typescript/node_modules/",
    "var/",
    ".venv/",
)

# Prefer source-like extensions so binary/media artifacts do not create noise.
SOURCE_EXTENSIONS = {
    ".rs",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".json",
    ".toml",
    ".yaml",
    ".yml",
    ".md",
    ".html",
    ".css",
    ".sh",
    ".py",
}

DUPLICATE_PATTERNS = (
    re.compile(r" \d+\.[^/]+$"),  # "file 2.js"
    re.compile(r" \(\d+\)(\.[^/]+)?$"),  # "file (1).js" or "file (1)"
)


def _read_null_delimited_git_paths(args: list[str]) -> list[str]:
    result = subprocess.run(
        args,
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [
        path
        for path in result.stdout.decode("utf-8", errors="replace").split("\0")
        if path
    ]


def list_workspace_files() -> list[str]:
    tracked = _read_null_delimited_git_paths(["git", "ls-files", "-z"])
    untracked = _read_null_delimited_git_paths(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"]
    )
    return sorted(set(tracked) | set(untracked))


def is_duplicate_copy(path: str) -> bool:
    if path.startswith(IGNORED_PREFIXES):
        return False
    filename = Path(path).name
    suffix = Path(path).suffix.lower()
    if suffix not in SOURCE_EXTENSIONS:
        return False
    return any(pattern.search(filename) for pattern in DUPLICATE_PATTERNS)


def main() -> int:
    offenders = sorted(path for path in list_workspace_files() if is_duplicate_copy(path))
    if not offenders:
        print("workspace-hygiene: no duplicate-like source copies found")
        return 0

    print("workspace-hygiene: found duplicate-like source files:", file=sys.stderr)
    for path in offenders:
        print(f"  - {path}", file=sys.stderr)
    print(
        "Remove or rename these files to avoid accidental drift from iCloud/Finder copies.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
