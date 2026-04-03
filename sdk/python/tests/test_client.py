"""Tests for the Wardex Python SDK."""

import json
import pytest
import responses

from wardex import WardexClient, AuthenticationError, NotFoundError, RateLimitError, ServerError


BASE = "http://localhost:9077"


@responses.activate
def test_status():
    responses.add(responses.GET, f"{BASE}/api/status",
                  json={"status": "ok", "version": "0.35.0"})
    c = WardexClient(BASE, token="tok")
    data = c.status()
    assert data["status"] == "ok"


@responses.activate
def test_login_sets_token():
    responses.add(responses.POST, f"{BASE}/api/auth/login",
                  json={"token": "new-tok"})
    c = WardexClient(BASE)
    c.login("admin", "pass")
    assert c._token == "new-tok"


@responses.activate
def test_list_alerts():
    responses.add(responses.GET, f"{BASE}/api/alerts", json=[{"id": "a1"}])
    c = WardexClient(BASE, token="tok")
    alerts = c.list_alerts(limit=10)
    assert len(alerts) == 1


@responses.activate
def test_create_incident():
    responses.add(responses.POST, f"{BASE}/api/incidents",
                  json={"id": "inc-1", "title": "Test"})
    c = WardexClient(BASE, token="tok")
    inc = c.create_incident("Test", "high")
    assert inc["id"] == "inc-1"


@responses.activate
def test_ingest_event():
    responses.add(responses.POST, f"{BASE}/api/telemetry/ingest",
                  json={"accepted": True})
    c = WardexClient(BASE, token="tok")
    result = c.ingest_event({"device_id": "s1", "cpu": 42})
    assert result["accepted"] is True


@responses.activate
def test_auth_error():
    responses.add(responses.GET, f"{BASE}/api/status", status=401, body="denied")
    c = WardexClient(BASE, token="bad")
    with pytest.raises(AuthenticationError):
        c.status()


@responses.activate
def test_not_found():
    responses.add(responses.GET, f"{BASE}/api/alerts/xxx", status=404, body="nope")
    c = WardexClient(BASE, token="tok")
    with pytest.raises(NotFoundError):
        c.get_alert("xxx")


@responses.activate
def test_rate_limit():
    responses.add(responses.GET, f"{BASE}/api/alerts", status=429, body="slow")
    c = WardexClient(BASE, token="tok")
    with pytest.raises(RateLimitError):
        c.list_alerts()


@responses.activate
def test_server_error():
    responses.add(responses.GET, f"{BASE}/api/status", status=500, body="boom")
    c = WardexClient(BASE, token="tok")
    with pytest.raises(ServerError):
        c.status()


@responses.activate
def test_metrics_returns_text():
    responses.add(responses.GET, f"{BASE}/api/metrics",
                  body="# HELP wardex_up\nwardex_up 1\n",
                  content_type="text/plain")
    c = WardexClient(BASE, token="tok")
    text = c.metrics()
    assert "wardex_up" in text
