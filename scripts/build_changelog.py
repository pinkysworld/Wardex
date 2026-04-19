#!/usr/bin/env python3
"""
Build site/changelog.html from CHANGELOG.md.

Keeps the Pages build self-contained — no node/npm/pandoc dependency.
Produces a static HTML file matching the site's look and feel.

Usage:
    python3 scripts/build_changelog.py [CHANGELOG.md] [output.html]

Defaults:
    input  = CHANGELOG.md (repo root)
    output = site-build/changelog.html
"""

from __future__ import annotations

import html
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = REPO_ROOT / "CHANGELOG.md"
DEFAULT_OUTPUT = REPO_ROOT / "site-build" / "changelog.html"

VERSION_RE = re.compile(r"^## \[(?P<version>[^\]]+)\](?:\s*[—-]\s*(?P<title>.*))?$")
CATEGORY_RE = re.compile(r"^### (?P<category>.+)$")
BULLET_RE = re.compile(r"^-\s+(?P<text>.*)$")
BOLD_RE = re.compile(r"\*\*(.+?)\*\*")
INLINE_CODE_RE = re.compile(r"`([^`]+)`")
LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")


def inline(text: str) -> str:
    """Render inline markdown (bold, code, links) as HTML-safe output."""
    text = html.escape(text)
    # Links — must run before bold since link text may contain bold.
    text = LINK_RE.sub(
        lambda m: f'<a href="{html.escape(m.group(2), quote=True)}" '
        f'rel="noopener" target="_blank">{m.group(1)}</a>',
        text,
    )
    text = BOLD_RE.sub(r"<strong>\1</strong>", text)
    text = INLINE_CODE_RE.sub(r"<code>\1</code>", text)
    return text


def parse_changelog(source: str) -> list[dict]:
    """Parse keep-a-changelog style markdown into a list of release dicts."""
    releases: list[dict] = []
    current_release: dict | None = None
    current_category: dict | None = None

    for raw in source.splitlines():
        line = raw.rstrip()
        if not line:
            continue

        version_match = VERSION_RE.match(line)
        if version_match:
            current_release = {
                "version": version_match.group("version").strip(),
                "title": (version_match.group("title") or "").strip(),
                "categories": [],
            }
            current_category = None
            releases.append(current_release)
            continue

        category_match = CATEGORY_RE.match(line)
        if category_match and current_release is not None:
            current_category = {
                "name": category_match.group("category").strip(),
                "items": [],
            }
            current_release["categories"].append(current_category)
            continue

        bullet_match = BULLET_RE.match(line)
        if bullet_match and current_category is not None:
            current_category["items"].append(bullet_match.group("text").strip())
            continue

        # Free-form lines under a release (e.g. blurbs) are ignored for now.

    return releases


def render_html(releases: list[dict]) -> str:
    sections: list[str] = []
    nav_items: list[str] = []
    for release in releases:
        anchor = "v" + re.sub(r"[^A-Za-z0-9_.-]", "-", release["version"])
        version_label = html.escape(release["version"])
        title_label = inline(release["title"]) if release["title"] else ""
        nav_items.append(
            f'<li><a href="#{anchor}"><span class="chl-ver">v{version_label}</span>'
            f'<span class="chl-nav-title">{title_label}</span></a></li>'
        )

        category_html: list[str] = []
        for category in release["categories"]:
            items_html = "\n".join(
                f"        <li>{inline(item)}</li>" for item in category["items"]
            )
            category_html.append(
                f'      <div class="chl-category">\n'
                f'        <h3>{html.escape(category["name"])}</h3>\n'
                f"        <ul>\n{items_html}\n        </ul>\n"
                f"      </div>"
            )

        sections.append(
            f'    <article class="chl-release" id="{anchor}">\n'
            f'      <header class="chl-release-header">\n'
            f'        <span class="chl-version-tag">v{version_label}</span>\n'
            f"        <h2>{title_label or version_label}</h2>\n"
            f"      </header>\n"
            + ("\n".join(category_html) + "\n" if category_html else "")
            + "    </article>"
        )

    nav_html = "\n".join(f"      {item}" for item in nav_items)
    body = "\n".join(sections)

    return f"""<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Changelog &mdash; Wardex</title>
    <meta name="description" content="Release history for Wardex &mdash; private-cloud XDR built in Rust.">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&amp;family=JetBrains+Mono:wght@400;500&amp;display=swap" rel="stylesheet">
    <link rel="icon" href="favicon.svg" type="image/svg+xml">
    <link rel="stylesheet" href="styles.css?v=10">
    <script defer src="app.js?v=11"></script>
  </head>
  <body>
    <nav class="site-nav" id="site-nav">
      <div class="nav-inner">
        <a class="nav-brand" href="index.html">
          <span class="nav-logo">WX</span>
          <span class="nav-title">Wardex</span>
        </a>
        <button class="nav-toggle" id="nav-toggle" aria-label="Toggle navigation" aria-expanded="false">
          <span></span><span></span><span></span>
        </button>
        <div class="nav-links" id="nav-links">
          <a href="index.html" class="nav-link">Overview</a>
          <a href="features.html" class="nav-link">Features</a>
          <a href="architecture.html" class="nav-link">Architecture</a>
          <a href="resources.html" class="nav-link active">Resources</a>
          <a href="pricing.html" class="nav-link">Pricing</a>
          <a href="donate.html" class="nav-link">Support</a>
          <a href="https://github.com/pinkysworld/Wardex" class="nav-link nav-link-icon" target="_blank" rel="noopener" aria-label="GitHub">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/></svg>
          </a>
        </div>
      </div>
    </nav>

    <main class="main">
      <section class="section page-hero">
        <div class="container">
          <p class="label">Changelog</p>
          <h1>Release history</h1>
          <p class="page-hero-desc">
            Auto-generated from <a href="https://github.com/pinkysworld/Wardex/blob/main/CHANGELOG.md" target="_blank" rel="noopener">CHANGELOG.md</a> on every Pages build.
          </p>
        </div>
      </section>

      <section class="section">
        <div class="container chl-container">
          <aside class="chl-toc" aria-label="Release index">
            <h2>Releases</h2>
            <ul>
{nav_html}
            </ul>
          </aside>
          <div class="chl-body">
{body}
          </div>
        </div>
      </section>

      <footer class="site-footer">
        <div class="container">
          <div class="footer-bottom">
            <p>Wardex &middot; &copy; 2024&ndash;2026 &middot; <a href="../LICENSE" style="color:inherit;">BSL 1.1</a> &middot; <a href="https://github.com/pinkysworld/Wardex/releases" style="color: var(--nav-accent);" target="_blank" rel="noopener">GitHub Releases</a></p>
          </div>
        </div>
      </footer>
    </main>
  </body>
</html>
"""


def main(argv: list[str]) -> int:
    input_path = Path(argv[1]) if len(argv) > 1 else DEFAULT_INPUT
    output_path = Path(argv[2]) if len(argv) > 2 else DEFAULT_OUTPUT

    if not input_path.is_file():
        print(f"error: {input_path} not found", file=sys.stderr)
        return 1

    source = input_path.read_text(encoding="utf-8")
    releases = parse_changelog(source)
    if not releases:
        print("error: no release sections parsed from changelog", file=sys.stderr)
        return 1

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(render_html(releases), encoding="utf-8")
    print(f"wrote {output_path} ({len(releases)} releases)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
