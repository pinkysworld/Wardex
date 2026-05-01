"""Tests for the Wardex Python SDK."""

from __future__ import annotations

import json

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


def test_ws_stats(monkeypatch):
    calls = install_stub(
        monkeypatch,
        {
            ("GET", f"{BASE}/api/ws/stats"): DummyResponse(
                url=f"{BASE}/api/ws/stats",
                json_data={"native_websocket_supported": True, "connected_clients": 1},
                headers={"content-type": "application/json"},
            )
        },
    )
    client = WardexClient(BASE, token="tok")
    data = client.ws_stats()
    assert data["native_websocket_supported"] is True
    assert calls[0]["method"] == "GET"


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


def test_ack_and_resolve_alert_use_bulk_endpoints(monkeypatch):
    calls = install_stub(
        monkeypatch,
        {
            ("POST", f"{BASE}/api/alerts/bulk/acknowledge"): DummyResponse(
                url=f"{BASE}/api/alerts/bulk/acknowledge",
                json_data={"status": "ok", "acknowledged": 1},
                headers={"content-type": "application/json"},
            ),
            ("POST", f"{BASE}/api/alerts/bulk/resolve"): DummyResponse(
                url=f"{BASE}/api/alerts/bulk/resolve",
                json_data={"status": "ok", "resolved": 1},
                headers={"content-type": "application/json"},
            ),
            ("POST", f"{BASE}/api/alerts/bulk/close"): DummyResponse(
                url=f"{BASE}/api/alerts/bulk/close",
                json_data={"status": "ok", "closed": 2},
                headers={"content-type": "application/json"},
            ),
        },
    )
    client = WardexClient(BASE, token="tok")
    assert client.ack_alert("12")["acknowledged"] == 1
    assert calls[0]["kwargs"]["json"] == {"ids": ["12"]}
    assert client.resolve_alert("12")["resolved"] == 1
    assert calls[1]["kwargs"]["json"] == {"ids": ["12"]}
    assert client.close_alerts(["a", "b"])["closed"] == 2
    assert calls[2]["kwargs"]["json"] == {"ids": ["a", "b"]}


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


def test_fleet_install_and_process_thread_helpers_use_current_routes(monkeypatch):
    calls = install_stub(
        monkeypatch,
        {
            ("GET", f"{BASE}/api/fleet/installs"): DummyResponse(
                url=f"{BASE}/api/fleet/installs",
                json_data={"attempts": [], "total": 0},
                headers={"content-type": "application/json"},
            ),
            ("POST", f"{BASE}/api/fleet/install/ssh"): DummyResponse(
                url=f"{BASE}/api/fleet/install/ssh",
                json_data={"status": "awaiting_heartbeat"},
                headers={"content-type": "application/json"},
            ),
            ("POST", f"{BASE}/api/fleet/install/winrm"): DummyResponse(
                url=f"{BASE}/api/fleet/install/winrm",
                json_data={"status": "awaiting_heartbeat"},
                headers={"content-type": "application/json"},
            ),
            (
                "GET",
                f"{BASE}/api/processes/threads",
                (("pid", "4242"),),
            ): DummyResponse(
                url=f"{BASE}/api/processes/threads",
                json_data={"pid": 4242, "threads": []},
                headers={"content-type": "application/json"},
            ),
        },
    )
    client = WardexClient(BASE, token="tok")
    assert client.fleet_installs()["total"] == 0
    client.fleet_install_ssh({"hostname": "edge-1"})
    client.fleet_install_winrm({"hostname": "win-1"})
    assert client.process_threads(4242)["pid"] == 4242
    assert calls[1]["kwargs"]["json"] == {"hostname": "edge-1"}
    assert calls[2]["kwargs"]["json"] == {"hostname": "win-1"}
    assert calls[3]["kwargs"]["params"] == {"pid": 4242}


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
    client = WardexClient(BASE, token="tok", retries=0)
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


def test_backup_helpers_cover_listing_creation_status_and_crypto(monkeypatch):
    calls = install_stub(
        monkeypatch,
        {
            ("POST", f"{BASE}/api/backup/encrypt"): DummyResponse(
                url=f"{BASE}/api/backup/encrypt",
                json_data={"encrypted": "ciphertext"},
                headers={"content-type": "application/json"},
            ),
            ("POST", f"{BASE}/api/backup/decrypt"): DummyResponse(
                url=f"{BASE}/api/backup/decrypt",
                json_data={"data": "plaintext"},
                headers={"content-type": "application/json"},
            ),
            ("GET", f"{BASE}/api/backups"): DummyResponse(
                url=f"{BASE}/api/backups",
                json_data=[{"name": "wardex_backup_20260430_223500.db"}],
                headers={"content-type": "application/json"},
            ),
            ("POST", f"{BASE}/api/backups"): DummyResponse(
                url=f"{BASE}/api/backups",
                json_data={"name": "wardex_backup_20260501_101500.db"},
                headers={"content-type": "application/json"},
            ),
            ("GET", f"{BASE}/api/backup/status"): DummyResponse(
                url=f"{BASE}/api/backup/status",
                json_data={"enabled": True, "retention_count": 7},
                headers={"content-type": "application/json"},
            ),
        },
    )
    client = WardexClient(BASE, token="tok")
    assert client.backup_encrypt("plain", "pass")["encrypted"] == "ciphertext"
    assert client.backup_decrypt("cipher", "pass")["data"] == "plaintext"
    assert client.list_backups()[0]["name"].endswith(".db")
    assert client.create_backup()["name"].startswith("wardex_backup_")
    assert client.backup_status()["retention_count"] == 7
    assert calls[0]["kwargs"]["json"] == {"data": "plain", "passphrase": "pass"}
    assert calls[1]["kwargs"]["json"] == {"data": "cipher", "passphrase": "pass"}


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


def test_detection_helpers_cover_explain_feedback_profile_and_scoring(monkeypatch):
    calls = install_stub(
        monkeypatch,
        {
            ("GET", f"{BASE}/api/detection/replay-corpus"): DummyResponse(
                url=f"{BASE}/api/detection/replay-corpus",
                json_data={"precision": 0.98},
                headers={"content-type": "application/json"},
            ),
            ("POST", f"{BASE}/api/detection/replay-corpus"): DummyResponse(
                url=f"{BASE}/api/detection/replay-corpus",
                json_data={"accepted": True},
                headers={"content-type": "application/json"},
            ),
            (
                "GET",
                f"{BASE}/api/detection/explain",
                (("alert_id", "42"), ("event_id", "42")),
            ): DummyResponse(
                url=f"{BASE}/api/detection/explain",
                json_data={"alert_id": "42", "event_id": 42},
                headers={"content-type": "application/json"},
            ),
            (
                "GET",
                f"{BASE}/api/detection/feedback",
                (("event_id", "42"), ("limit", "25")),
            ): DummyResponse(
                url=f"{BASE}/api/detection/feedback",
                json_data={"items": [], "summary": {"total": 0}},
                headers={"content-type": "application/json"},
            ),
            ("POST", f"{BASE}/api/detection/feedback"): DummyResponse(
                url=f"{BASE}/api/detection/feedback",
                json_data={"id": 1},
                headers={"content-type": "application/json"},
            ),
            ("GET", f"{BASE}/api/detection/profile"): DummyResponse(
                url=f"{BASE}/api/detection/profile",
                json_data={"profile": "balanced"},
                headers={"content-type": "application/json"},
            ),
            ("PUT", f"{BASE}/api/detection/profile"): DummyResponse(
                url=f"{BASE}/api/detection/profile",
                json_data={"profile": "quiet", "applied": True},
                headers={"content-type": "application/json"},
            ),
            ("GET", f"{BASE}/api/detection/weights"): DummyResponse(
                url=f"{BASE}/api/detection/weights",
                json_data={"cpu": 1.0},
                headers={"content-type": "application/json"},
            ),
            ("POST", f"{BASE}/api/detection/weights"): DummyResponse(
                url=f"{BASE}/api/detection/weights",
                json_data={"status": "updated"},
                headers={"content-type": "application/json"},
            ),
            ("GET", f"{BASE}/api/detection/score/normalize"): DummyResponse(
                url=f"{BASE}/api/detection/score/normalize",
                json_data={"normalized": 95, "severity": "critical"},
                headers={"content-type": "application/json"},
            ),
        },
    )
    client = WardexClient(BASE, token="tok")
    assert client.detection_replay_corpus()["precision"] == 0.98
    assert client.evaluate_detection_replay_corpus({"source": "built_in"})["accepted"] is True
    assert client.detection_explain(event_id=42, alert_id="42")["event_id"] == 42
    assert client.detection_feedback(42, 25)["summary"]["total"] == 0
    assert client.record_detection_feedback({"verdict": "true_positive"})["id"] == 1
    assert client.detection_profile()["profile"] == "balanced"
    assert client.set_detection_profile("quiet")["applied"] is True
    assert client.detection_weights()["cpu"] == 1.0
    assert client.set_detection_weights({"cpu": 1.2})["status"] == "updated"
    assert client.normalize_score()["severity"] == "critical"
    assert calls[1]["kwargs"]["json"] == {"source": "built_in"}
    assert calls[6]["kwargs"]["json"] == {"profile": "quiet"}
    assert calls[8]["kwargs"]["json"] == {"cpu": 1.2}


def test_list_all_alerts_auto_paginates(monkeypatch):
    page1 = [{"id": i} for i in range(10)]
    page2 = [{"id": i} for i in range(10, 17)]
    install_stub(
        monkeypatch,
        {
            (
                "GET",
                f"{BASE}/api/alerts",
                (("limit", "10"), ("offset", "0")),
            ): DummyResponse(
                url=f"{BASE}/api/alerts",
                json_data=page1,
                headers={"content-type": "application/json"},
            ),
            (
                "GET",
                f"{BASE}/api/alerts",
                (("limit", "10"), ("offset", "10")),
            ): DummyResponse(
                url=f"{BASE}/api/alerts",
                json_data=page2,
                headers={"content-type": "application/json"},
            ),
        },
    )
    client = WardexClient(BASE, token="tok")
    all_alerts = list(client.list_all_alerts(page_size=10))
    assert len(all_alerts) == 17
    assert all_alerts[0]["id"] == 0
    assert all_alerts[-1]["id"] == 16


def test_escalate_posts_to_escalation_start(monkeypatch):
    calls = install_stub(
        monkeypatch,
        {
            ("POST", f"{BASE}/api/escalation/start"): DummyResponse(
                url=f"{BASE}/api/escalation/start",
                json_data={"escalation_id": "esc-001"},
                headers={"content-type": "application/json"},
            ),
        },
    )
    client = WardexClient(BASE, token="tok")
    result = client.escalate("alert-42", policy_id="urgent")
    assert result["escalation_id"] == "esc-001"
    assert calls[0]["kwargs"]["json"] == {"policy_id": "urgent", "alert_id": "alert-42"}


def test_retry_on_server_error(monkeypatch):
    attempt_count = {"n": 0}

    def fake_request(session, method, url, **kwargs):
        attempt_count["n"] += 1
        if attempt_count["n"] < 3:
            return DummyResponse(url=url, status_code=503, text="unavailable")
        return DummyResponse(
            url=url, json_data={"status": "ok"}, headers={"content-type": "application/json"}
        )

    monkeypatch.setattr("requests.Session.request", fake_request)
    client = WardexClient(BASE, token="tok", retries=3)
    result = client.status()
    assert result["status"] == "ok"
    assert attempt_count["n"] == 3


def test_retry_exhausted_raises(monkeypatch):
    def fake_request(session, method, url, **kwargs):
        return DummyResponse(url=url, status_code=500, text="boom")

    monkeypatch.setattr("requests.Session.request", fake_request)
    client = WardexClient(BASE, token="tok", retries=1)
    with pytest.raises(ServerError):
        client.status()
