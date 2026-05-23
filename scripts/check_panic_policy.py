#!/usr/bin/env python3
"""Panic-policy guard.

Counts `.unwrap()` and `.expect(` occurrences in production Rust files
under ``src/``, excluding regions that are unambiguously test-only
(``#[cfg(test)]`` attributes and ``mod tests {`` blocks at the top of
the file).

Compares the result against the committed baseline in
``scripts/panic-baseline.txt`` and exits non-zero if the count has
increased. To intentionally raise the baseline (e.g. when a new
``// SAFETY:``-annotated unwrap is required), update that file in the
same commit so reviewers can scrutinise the change.

Usage::

    python3 scripts/check_panic_policy.py
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src"
BASELINE_FILE = REPO_ROOT / "scripts" / "panic-baseline.txt"

PANIC_PATTERN = re.compile(r"\.(unwrap|expect)\s*\(")
TEST_ATTR = re.compile(r"#\[cfg\(test\)\]")
TEST_MOD = re.compile(r"^\s*mod\s+tests?\s*\{")


def count_in_file(path: Path) -> int:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    cutoff = len(lines)
    for idx, line in enumerate(lines):
        if TEST_ATTR.search(line) or TEST_MOD.search(line):
            cutoff = idx
            break
    total = 0
    for line in lines[:cutoff]:
        # Strip line comments to avoid counting `// .unwrap()` mentions.
        code = line.split("//", 1)[0]
        total += len(PANIC_PATTERN.findall(code))
    return total


def main() -> int:
    if not SRC_ROOT.is_dir():
        print(f"error: src/ not found at {SRC_ROOT}", file=sys.stderr)
        return 2

    counts_by_file: list[tuple[Path, int]] = []
    for path in sorted(SRC_ROOT.rglob("*.rs")):
        count = count_in_file(path)
        if count:
            counts_by_file.append((path, count))
    total = sum(count for _, count in counts_by_file)

    if not BASELINE_FILE.is_file():
        print(
            f"error: missing baseline file {BASELINE_FILE.relative_to(REPO_ROOT)}",
            file=sys.stderr,
        )
        return 2

    baseline_text = BASELINE_FILE.read_text(encoding="utf-8").strip()
    try:
        baseline = int(baseline_text)
    except ValueError:
        print(
            f"error: baseline file {BASELINE_FILE} must contain an integer, "
            f"got {baseline_text!r}",
            file=sys.stderr,
        )
        return 2

    print(f"panic-policy: {total} non-test unwrap/expect (baseline {baseline})")

    top_counts = sorted(counts_by_file, key=lambda item: (-item[1], str(item[0])))[:10]
    if top_counts:
        print("panic-policy: top production call sites by file")
        for path, count in top_counts:
            print(f"  {path.relative_to(REPO_ROOT)}: {count}")

    if total > baseline:
        print(
            "error: panic-policy regression detected.\n"
            f"  current: {total}\n"
            f"  baseline: {baseline}\n"
            "Either remove the new .unwrap()/.expect( in production code, or — "
            "if the call site is provably safe — update "
            "scripts/panic-baseline.txt in the same commit and add a "
            "// SAFETY: or // INTENTIONAL: comment explaining why the panic "
            "cannot fire.",
            file=sys.stderr,
        )
        return 1

    if total < baseline:
        print(
            "error: panic count is below baseline. Lower "
            "scripts/panic-baseline.txt in the same change so the release "
            "gate locks in the improvement.",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
