"""Live smoke tests for the Wardex Python SDK."""

from __future__ import annotations

import os

import pytest

from wardex import WardexClient


LIVE_BASE = os.environ.get("WDX_BASE_URL") or os.environ.get("WARDEX_LIVE_BASE_URL")
LIVE_API_KEY = os.environ.get("WDX_API_KEY") or os.environ.get("WARDEX_LIVE_API_KEY")

pytestmark = pytest.mark.skipif(not LIVE_BASE, reason="WDX_BASE_URL is not set")


def test_live_health_and_status() -> None:
    if not LIVE_API_KEY:
        pytest.skip("WDX_API_KEY is not set")

    client = WardexClient(LIVE_BASE, token=LIVE_API_KEY)

    status = client.status()
    assert isinstance(status["version"], str)
    assert "start" in status["cli_commands"]

    health = client.health()
    assert health["status"] == "ok"
    assert isinstance(health["version"], str)


def test_live_openapi_document() -> None:
    client = WardexClient(LIVE_BASE)

    spec = client.openapi_spec()

    assert spec["openapi"].startswith("3.")
    assert "/api/health" in spec["paths"]
    assert "/api/openapi.json" in spec["paths"]