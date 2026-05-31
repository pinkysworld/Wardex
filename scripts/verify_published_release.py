#!/usr/bin/env python3
"""Verify that the published Wardex release is visible across public channels."""

from __future__ import annotations

import argparse
import gzip
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


ROOT = pathlib.Path(__file__).resolve().parents[1]
VERIFY_ARTIFACTS = ROOT / "scripts" / "verify_release_artifacts.py"


def fetch_bytes(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json, application/json, text/plain;q=0.9",
            "User-Agent": "wardex-release-proof",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read()


def fetch_json(url: str) -> dict:
    return json.loads(fetch_bytes(url).decode("utf-8"))


def wait_for(description: str, timeout_secs: int, poll_secs: int, check):
    deadline = time.time() + timeout_secs
    last_error: str | None = None
    while time.time() < deadline:
        try:
            value = check()
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
        else:
            if value:
                return value
            last_error = f"{description} did not match yet"
        time.sleep(poll_secs)
    raise SystemExit(f"published-release: timed out waiting for {description}: {last_error}")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"published-release: {message}")


def download(url: str, dest: pathlib.Path) -> None:
    dest.write_bytes(fetch_bytes(url))


def verify_release_assets(repo: str, tag: str, timeout_secs: int, poll_secs: int) -> tuple[dict, pathlib.Path]:
    api_url = f"https://api.github.com/repos/{repo}/releases/tags/{tag}"

    release = wait_for(
        f"GitHub release {tag}",
        timeout_secs,
        poll_secs,
        lambda: fetch_json(api_url),
    )
    asset_dir = pathlib.Path(tempfile.mkdtemp(prefix="wardex-published-release-"))
    for asset in release.get("assets", []):
        name = asset.get("name")
        url = asset.get("browser_download_url")
        if not name or not url:
            continue
        download(url, asset_dir / name)

    subprocess.run(
        [sys.executable, str(VERIFY_ARTIFACTS), str(asset_dir)],
        check=True,
        cwd=ROOT,
    )
    return release, asset_dir


def verify_pages_release_facts(repo: str, version: str, timeout_secs: int, poll_secs: int) -> dict:
    expected_channels = {
        "source",
        "github-release-archives",
        "apt",
        "rpm",
        "homebrew",
        "container-image",
        "helm",
    }
    release_facts_url = f"https://pinkysworld.github.io/{repo.split('/')[-1]}/data/release_facts.json"

    def check():
        payload = fetch_json(release_facts_url)
        if payload.get("version") != version:
            return None
        channels = set(payload.get("distribution", {}).get("install_channels", []))
        if not expected_channels.issubset(channels):
            return None
        if payload.get("product_name") != "Wardex":
            return None
        return payload

    return wait_for("GitHub Pages release_facts.json", timeout_secs, poll_secs, check)


def verify_support_page(url: str, timeout_secs: int, poll_secs: int) -> None:
    def check():
        body = fetch_bytes(url).decode("utf-8", errors="replace")
        if "Wardex" not in body or "support@wardex.dev" not in body:
            return None
        return True

    wait_for(f"support page {url}", timeout_secs, poll_secs, check)


def verify_apt_repo(repo_name: str, version: str, timeout_secs: int, poll_secs: int) -> None:
    base_url = f"https://pinkysworld.github.io/{repo_name}/apt"
    key_url = f"{base_url}/wardex-archive-key.asc"
    release_url = f"{base_url}/dists/stable/Release"
    packages_url = f"{base_url}/dists/stable/main/binary-amd64/Packages.gz"

    wait_for("APT signing key", timeout_secs, poll_secs, lambda: b"BEGIN PGP PUBLIC KEY BLOCK" in fetch_bytes(key_url))

    def check_release():
        text = fetch_bytes(release_url).decode("utf-8", errors="replace")
        if "Origin: Wardex" not in text or "Suite: stable" not in text:
            return None
        return True

    wait_for("APT Release metadata", timeout_secs, poll_secs, check_release)

    def check_packages():
        text = gzip.decompress(fetch_bytes(packages_url)).decode("utf-8", errors="replace")
        if "Package: wardex" not in text:
            return None
        if f"Version: {version}" not in text:
            return None
        return True

    wait_for("APT Packages index", timeout_secs, poll_secs, check_packages)


def verify_homebrew_formula(repo: str, tag: str, version: str, timeout_secs: int, poll_secs: int) -> None:
    formula_url = "https://raw.githubusercontent.com/pinkysworld/homebrew-wardex/main/Formula/wardex.rb"
    source_url = f"https://github.com/{repo}/archive/refs/tags/{tag}.tar.gz"

    def check():
        text = fetch_bytes(formula_url).decode("utf-8", errors="replace")
        if 'class Wardex < Formula' not in text:
            return None
        if source_url not in text:
            return None
        if 'license "AGPL-3.0-only"' not in text:
            return None
        if version not in text and tag not in text:
            return None
        return True

    wait_for("Homebrew tap formula", timeout_secs, poll_secs, check)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default="pinkysworld/Wardex")
    parser.add_argument("--tag", required=True)
    parser.add_argument("--timeout-secs", type=int, default=900)
    parser.add_argument("--poll-secs", type=int, default=10)
    args = parser.parse_args()

    require(VERIFY_ARTIFACTS.is_file(), f"missing verifier script {VERIFY_ARTIFACTS}")

    version = args.tag.removeprefix("v")
    repo_name = args.repo.split("/")[-1]

    asset_dir: pathlib.Path | None = None
    try:
        release, asset_dir = verify_release_assets(args.repo, args.tag, args.timeout_secs, args.poll_secs)
        asset_names = {asset.get("name") for asset in release.get("assets", [])}
        require("SHA256SUMS" in asset_names, "GitHub release is missing SHA256SUMS")
        facts = verify_pages_release_facts(args.repo, version, args.timeout_secs, args.poll_secs)
        verify_apt_repo(repo_name, version, args.timeout_secs, args.poll_secs)
        verify_homebrew_formula(args.repo, args.tag, version, args.timeout_secs, args.poll_secs)
        verify_support_page(
            facts.get("support", {}).get("page_url", "https://minh.systems/Wardex/support/"),
            args.timeout_secs,
            args.poll_secs,
        )
    finally:
        if asset_dir and asset_dir.exists():
            shutil.rmtree(asset_dir, ignore_errors=True)

    print(
        "published-release: GitHub assets, checksums, Pages release facts, APT metadata, Homebrew tap, and support page reflect "
        f"{args.tag}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
