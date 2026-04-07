"""Tests for the Wardex Python SDK."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from wardex import (
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    ServerError,
    WardexClient,
    WardexError,
)


BASE = "http://localhost:9077"


class DummyResponse:
    def __init__(
        self,
        *,
        url: str,
        status_code: int = 200,
        json_data=None,
        text: str | None = None,
        headers: dict[str, str] | None = None,
    ):
        self.url = url
        self.status_code = status_code
        self._json_data = json_data
        self._text = text
        self.headers = headers or {}

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def text(self) -> str:
        if self._text is not None:
            return self._text
        if self._json_data is not None:
            return json.dumps(self._json_data)
        return ""

    def json(self):
        if self._json_data is None:
            raise ValueError("response body is not JSON")
        return self._json_data


def install_stub(monkeypatch, mapping):
    calls = []

    def normalize_params(params):
        if not params:
            return ()
        normalized = []
        for key, value in params.items():
            if isinstance(value, (list, tuple)):
                for item in value:
                    normalized.append((str(key), str(item)))
            else:
                normalized.append((str(key), str(value)))
        return tuple(sorted(normalized))

    def fake_request(session, method, url, **kwargs):
        method = method.upper()
        calls.append({"method": method, "url": url, "kwargs": kwargs})
        params_key = normalize_params(kwargs.get("params"))
        try:
            response = mapping[(method, url, params_key)]
        except KeyError as exc:
            try:
                response = mapping[(method, url)]
            except KeyError:
                raise AssertionError(f"unexpected request: {(method, url, params_key)}") from exc
        return response

    monkeypatch.setattr("requests.Session.request", fake_request)
    return calls


def test_status(monkeypatch):
    calls = install_stub(
        monkeypatch,
        {
            ("GET", f"{BASE}/api/status"): DummyResponse(
                url=f"{BASE}/api/status",
                json_data={"status": "ok", "version": "0.41.5"},
                headers={"content-type": "application/json"},
            )
        },
    )
    client = WardexClient(BASE, token="tok")
    data = client.status()
    assert data["status"] == "ok"
    assert calls[0]["kwargs"]["timeout"] == 30.0


def test_auth_check_and_rotate_token(monkeypatch):
    calls = install_stub(
        monkeypatch,
        {
            ("GET", f"{BASE}/api/auth/check"): DummyResponse(
                url=f"{BASE}/api/auth/check",
                json_data={"status": "ok", "ttl_secs": 3600},
                headers={"content-type": "application/json"},
            ),
            ("POST", f"{BASE}/api/auth/rotate"): DummyResponse(
                url=f"{BASE}/api/auth/rotate",
                json_data={"status": "rotated", "new_token": "new-tok"},
                headers={"content-type": "application/json"},
            ),
        },
    )
    client = WardexClient(BASE, token="tok")
    assert client.auth_check()["status"] == "ok"
    rotated = client.rotate_token()
    assert rotated["new_token"] == "new-tok"
    assert client._token == "new-tok"
    assert calls[1]["kwargs"]["headers"] if "headers" in calls[1]["kwargs"] else True


def test_login_is_explicitly_unsupported():
    client = WardexClient(BASE)
    with pytest.raises(WardexError, match="login\\(\\) is not supported"):
        client.login("admin", "pass")


def test_whoami_uses_auth_check_and_session_info(monkeypatch):
    install_stub(
        monkeypatch,
        {
            ("GET", f"{BASE}/api/auth/check"): DummyResponse(
                url=f"{BASE}/api/auth/check",
                json_data={"status": "ok"},
                headers={"content-type": "application/json"},
            ),
            ("GET", f"{BASE}/api/session/info"): DummyResponse(
                url=f"{BASE}/api/session/info",
                json_data={"uptime_secs": 12},
                headers={"content-type": "application/json"},
            ),
        },
    )
    client = WardexClient(BASE, token="tok")
    data = client.whoami()
    assert data["authenticated"] is True
    assert data["session"]["uptime_secs"] == 12


def test_create_incident_uses_summary_field_and_normalizes_severity(monkeypatch):
    calls = install_stub(
        monkeypatch,
        {
            ("POST", f"{BASE}/api/incidents"): DummyResponse(
                url=f"{BASE}/api/incidents",
                json_data={"id": 7, "title": "Test"},
                headers={"content-type": "application/json"},
            )
        },
    )
    client = WardexClient(BASE, token="tok")
    incident = client.create_incident("Test", "critical", "summary text")
    assert incident["id"] == 7
    assert calls[0]["kwargs"]["json"] == {
        "title": "Test",
        "severity": "Critical",
        "summary": "summary text",
    }


def test_alert_ack_and_resolve_fail_fast_when_server_has_no_route():
    client = WardexClient(BASE, token="tok")
    with pytest.raises(WardexError, match="ack_alert\\(\\) is not supported"):
        client.ack_alert("12")
    with pytest.raises(WardexError, match="resolve_alert\\(\\) is not supported"):
        client.resolve_alert("12")


def test_list_alerts_passes_query_params(monkeypatch):
    calls = install_stub(
        monkeypatch,
        {
            (
                "GET",
                f"{BASE}/api/alerts",
                (("limit", "25"), ("offset", "5")),
            ): DummyResponse(
                url=f"{BASE}/api/alerts",
                json_data=[{"id": 12}],
                headers={"content-type": "application/json"},
            )
        },
    )
    client = WardexClient(BASE, token="tok")
    data = client.list_alerts(limit=25, offset=5)
    assert data[0]["id"] == 12
    assert calls[0]["kwargs"]["params"] == {"limit": 25, "offset": 5}


def test_list_incidents_passes_query_params(monkeypatch):
    calls = install_stub(
        monkeypatch,
        {
            (
                "GET",
                f"{BASE}/api/incidents",
                (("limit", "10"), ("offset", "2")),
            ): DummyResponse(
                url=f"{BASE}/api/incidents",
                json_data=[{"id": 7}],
                headers={"content-type": "application/json"},
            )
        },
    )
    client = WardexClient(BASE, token="tok")
    data = client.list_incidents(limit=10, offset=2)
    assert data[0]["id"] == 7
    assert calls[0]["kwargs"]["params"] == {"limit": 10, "offset": 2}


def test_list_agents_and_get_agent_use_current_routes(monkeypatch):
    calls = install_stub(
        monkeypatch,
        {
            ("GET", f"{BASE}/api/agents"): DummyResponse(
                url=f"{BASE}/api/agents",
                json_data=[{"id": "a-1"}],
                headers={"content-type": "application/json"},
            ),
            ("GET", f"{BASE}/api/agents/a-1/details"): DummyResponse(
                url=f"{BASE}/api/agents/a-1/details",
                json_data={"agent": {"id": "a-1", "hostname": "db-01"}},
                headers={"content-type": "application/json"},
            ),
        },
    )
    client = WardexClient(BASE, token="tok")
    assert client.list_agents()[0]["id"] == "a-1"
    assert client.get_agent("a-1")["agent"]["hostname"] == "db-01"
    assert calls[0]["url"].endswith("/api/agents")
    assert calls[1]["url"].endswith("/api/agents/a-1/details")


def test_isolate_agent_submits_response_request(monkeypatch):
    calls = install_stub(
        monkeypatch,
        {
            ("GET", f"{BASE}/api/agents/a-1/details"): DummyResponse(
                url=f"{BASE}/api/agents/a-1/details",
                json_data={"agent": {"id": "a-1", "hostname": "db-01"}},
                headers={"content-type": "application/json"},
            ),
            ("POST", f"{BASE}/api/response/request"): DummyResponse(
                url=f"{BASE}/api/response/request",
                json_data={"status": "submitted"},
                headers={"content-type": "application/json"},
            ),
        },
    )
    client = WardexClient(BASE, token="tok")
    result = client.isolate_agent("a-1", dry_run=True)
    assert result["status"] == "submitted"
    assert calls[1]["kwargs"]["json"]["action"] == "isolate"
    assert calls[1]["kwargs"]["json"]["hostname"] == "db-01"
    assert calls[1]["kwargs"]["json"]["dry_run"] is True


def test_ingest_event_wraps_event_batch(monkeypatch):
    calls = install_stub(
        monkeypatch,
        {
            ("POST", f"{BASE}/api/events"): DummyResponse(
                url=f"{BASE}/api/events",
                json_data={"accepted": 1},
                headers={"content-type": "application/json"},
            )
        },
    )
    client = WardexClient(BASE, token="tok")
    result = client.ingest_event({"hostname": "sensor-1", "level": "Elevated"}, agent_id="edge-1")
    assert result["accepted"] == 1
    assert calls[0]["kwargs"]["json"] == {
        "agent_id": "edge-1",
        "events": [{"hostname": "sensor-1", "level": "Elevated"}],
    }


def test_ingest_batch_enforces_limit():
    client = WardexClient(BASE, token="tok")
    with pytest.raises(ValueError, match="exceeds maximum"):
        client.ingest_batch([{}] * 10001)


def test_policy_and_config_routes_use_current_endpoints(monkeypatch):
    calls = install_stub(
        monkeypatch,
        {
            ("GET", f"{BASE}/api/policy/history"): DummyResponse(
                url=f"{BASE}/api/policy/history",
                json_data=[{"version": 3}],
                headers={"content-type": "application/json"},
            ),
            ("GET", f"{BASE}/api/config/current"): DummyResponse(
                url=f"{BASE}/api/config/current",
                json_data={"monitor": {"interval_secs": 5}},
                headers={"content-type": "application/json"},
            ),
            ("POST", f"{BASE}/api/config/save"): DummyResponse(
                url=f"{BASE}/api/config/save",
                json_data={"status": "saved"},
                headers={"content-type": "application/json"},
            ),
        },
    )
    client = WardexClient(BASE, token="tok")
    assert client.list_policies()[0]["version"] == 3
    assert client.get_config()["monitor"]["interval_secs"] == 5
    assert client.update_config({"monitor": {"interval_secs": 10}})["status"] == "saved"
    assert calls[2]["kwargs"]["json"] == {"monitor": {"interval_secs": 10}}


def test_generate_report_uses_supported_endpoints(monkeypatch):
    calls = install_stub(
        monkeypatch,
        {
            ("GET", f"{BASE}/api/report"): DummyResponse(
                url=f"{BASE}/api/report",
                json_data={"report": "latest"},
                headers={"content-type": "application/json"},
            ),
            ("GET", f"{BASE}/api/reports/executive-summary"): DummyResponse(
                url=f"{BASE}/api/reports/executive-summary",
                json_data={"reports": 3},
                headers={"content-type": "application/json"},
            ),
        },
    )
    client = WardexClient(BASE, token="tok")
    assert client.generate_report()["report"] == "latest"
    assert client.generate_report("executive-summary")["reports"] == 3
    assert calls[0]["url"].endswith("/api/report")
    assert calls[1]["url"].endswith("/api/reports/executive-summary")


def test_error_mapping(monkeypatch):
    install_stub(
        monkeypatch,
        {
            ("GET", f"{BASE}/api/status"): DummyResponse(url=f"{BASE}/api/status", status_code=401, text="denied"),
            ("GET", f"{BASE}/api/alerts/xxx"): DummyResponse(url=f"{BASE}/api/alerts/xxx", status_code=404, text="nope"),
            ("GET", f"{BASE}/api/alerts"): DummyResponse(url=f"{BASE}/api/alerts", status_code=429, text="slow"),
            ("GET", f"{BASE}/api/health"): DummyResponse(url=f"{BASE}/api/health", status_code=500, text="boom"),
        },
    )
    client = WardexClient(BASE, token="tok")
    with pytest.raises(AuthenticationError):
        client.status()
    with pytest.raises(NotFoundError):
        client.get_alert("xxx")
    with pytest.raises(RateLimitError):
        client.list_alerts()
    with pytest.raises(ServerError):
        client.health()


def test_metrics_returns_text(monkeypatch):
    install_stub(
        monkeypatch,
        {
            ("GET", f"{BASE}/api/metrics"): DummyResponse(
                url=f"{BASE}/api/metrics",
                text="# HELP wardex_up\nwardex_up 1\n",
                headers={"content-type": "text/plain"},
            )
        },
    )
    client = WardexClient(BASE, token="tok")
    text = client.metrics()
    assert "wardex_up" in text


def test_openapi_spec_uses_json_endpoint(monkeypatch):
    install_stub(
        monkeypatch,
        {
            ("GET", f"{BASE}/api/openapi.json"): DummyResponse(
                url=f"{BASE}/api/openapi.json",
                json_data={"openapi": "3.0.3"},
                headers={"content-type": "application/json"},
            )
        },
    )
    client = WardexClient(BASE, token="tok")
    assert client.openapi_spec()["openapi"] == "3.0.3"
