#!/usr/bin/env python3
"""
Nav-race guard: flag setSearchParams() calls inside a useEffect that aren't
protected by a `location.pathname` check.

Background: an effect that writes search params can fire after the user has
navigated to another route (the effect was scheduled before the navigation but
runs after). React Router resolves the write relative to the component's own
route, so it clobbers the new URL. We fixed this in ThreatDetection, then
extended the guard to Infrastructure and HelpDocs. This script keeps future
regressions out of CI.

Heuristic:
- Scan each .jsx/.tsx/.js/.ts file under admin-console/src/components.
- Locate every `useEffect(()` block.
- If a block contains `setSearchParams(`, require either:
    * `location.pathname` somewhere in the same block (the guard), OR
    * an explicit `// nav-race-ok` allowlist marker on the line before the call.

Exit 0 if clean, 1 with a report otherwise.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "admin-console" / "src" / "components"

USE_EFFECT_RE = re.compile(r"\buseEffect\s*\(")
SET_SEARCH_RE = re.compile(r"\bsetSearchParams\s*\(")
GUARD_RE = re.compile(r"location\.pathname|nav-race-ok")


def find_balanced_end(text: str, start: int) -> int:
    """Return index just past the matching ')' for a '(' at start (inclusive)."""
    depth = 0
    in_str: str | None = None
    i = start
    while i < len(text):
        ch = text[i]
        if in_str is not None:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
        else:
            if ch in ('"', "'", "`"):
                in_str = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return i + 1
        i += 1
    return len(text)


def scan_file(path: Path) -> list[tuple[int, str]]:
    text = path.read_text(encoding="utf-8")
    findings: list[tuple[int, str]] = []
    for match in USE_EFFECT_RE.finditer(text):
        open_paren = text.find("(", match.start())
        if open_paren == -1:
            continue
        end = find_balanced_end(text, open_paren)
        block = text[open_paren:end]
        if not SET_SEARCH_RE.search(block):
            continue
        if GUARD_RE.search(block):
            continue
        line_no = text.count("\n", 0, match.start()) + 1
        findings.append((line_no, "useEffect writes setSearchParams without pathname guard"))
    return findings


def main() -> int:
    if not TARGET.is_dir():
        print(f"target directory not found: {TARGET}", file=sys.stderr)
        return 2

    failures: list[str] = []
    for path in sorted(TARGET.rglob("*")):
        if path.suffix not in {".jsx", ".tsx", ".js", ".ts"}:
            continue
        for line_no, msg in scan_file(path):
            rel = path.relative_to(ROOT)
            failures.append(f"{rel}:{line_no}: {msg}")

    if failures:
        print("Nav-race guard: unguarded setSearchParams in useEffect detected.")
        print("Add a `location.pathname === '/<route>'` early return, or annotate")
        print("with `// nav-race-ok` on the line above if the write is genuinely safe.")
        print()
        for line in failures:
            print(line)
        return 1

    print(f"Nav-race guard: clean ({TARGET.relative_to(ROOT)}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
