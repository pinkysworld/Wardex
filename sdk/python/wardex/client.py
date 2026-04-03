"""Wardex REST API client."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urljoin

import requests

from wardex.exceptions import (
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    ServerError,
    WardexError,
)


class WardexClient:
    """Synchronous client for the Wardex REST API.

    Parameters
    ----------
    base_url : str
        Wardex server URL, e.g. ``"https://wardex.example.com"``.
    token : str | None
        Bearer token.  If omitted, call :meth:`login` first.
    timeout : float
        Default request timeout in seconds.
    verify : bool
        Whether to verify TLS certificates.
    """

    def __init__(
        self,
        base_url: str,
        token: str | None = None,
        timeout: float = 30.0,
        verify: bool = True,
    ):
        self._base = base_url.rstrip("/")
        self._token = token
        self._timeout = timeout
        self._session = requests.Session()
        self._session.verify = verify
        if token:
            self._session.headers["Authorization"] = f"Bearer {token}"

    # ── helpers ───────────────────────────────────────────────────────────

    def _url(self, path: str) -> str:
        return f"{self._base}{path}"

    def _raise_for_status(self, resp: requests.Response) -> None:
        if resp.ok:
            return
        body = resp.text
        code = resp.status_code
        if code in (401, 403):
            raise AuthenticationError(f"Auth error {code}", code, body)
        if code == 404:
            raise NotFoundError(f"Not found: {resp.url}", code, body)
        if code == 429:
            raise RateLimitError("Rate limit exceeded", code, body)
        if 500 <= code < 600:
            raise ServerError(f"Server error {code}", code, body)
        raise WardexError(f"HTTP {code}", code, body)

    def _get(self, path: str, **params: Any) -> Any:
        resp = self._session.get(self._url(path), params=params, timeout=self._timeout)
        self._raise_for_status(resp)
        if resp.headers.get("content-type", "").startswith("application/json"):
            return resp.json()
        return resp.text

    def _post(self, path: str, body: Any = None) -> Any:
        resp = self._session.post(self._url(path), json=body, timeout=self._timeout)
        self._raise_for_status(resp)
        if resp.headers.get("content-type", "").startswith("application/json"):
            return resp.json()
        return resp.text

    def _put(self, path: str, body: Any = None) -> Any:
        resp = self._session.put(self._url(path), json=body, timeout=self._timeout)
        self._raise_for_status(resp)
        if resp.headers.get("content-type", "").startswith("application/json"):
            return resp.json()
        return resp.text

    def _delete(self, path: str) -> Any:
        resp = self._session.delete(self._url(path), timeout=self._timeout)
        self._raise_for_status(resp)
        if resp.headers.get("content-type", "").startswith("application/json"):
            return resp.json()
        return resp.text

    # ── auth ──────────────────────────────────────────────────────────────

    def login(self, username: str, password: str) -> dict:
        data = self._post("/api/auth/login", {"username": username, "password": password})
        if isinstance(data, dict) and "token" in data:
            self._token = data["token"]
            self._session.headers["Authorization"] = f"Bearer {self._token}"
        return data

    def logout(self) -> Any:
        result = self._post("/api/auth/logout")
        self._token = None
        self._session.headers.pop("Authorization", None)
        return result

    def whoami(self) -> dict:
        return self._get("/api/auth/whoami")

    # ── status ────────────────────────────────────────────────────────────

    def status(self) -> dict:
        return self._get("/api/status")

    def health(self) -> dict:
        return self._get("/api/health")

    # ── alerts ────────────────────────────────────────────────────────────

    def list_alerts(self, limit: int = 50, offset: int = 0) -> list:
        return self._get("/api/alerts", limit=limit, offset=offset)

    def get_alert(self, alert_id: str) -> dict:
        return self._get(f"/api/alerts/{alert_id}")

    def ack_alert(self, alert_id: str) -> dict:
        return self._post(f"/api/alerts/{alert_id}/ack")

    def resolve_alert(self, alert_id: str) -> dict:
        return self._post(f"/api/alerts/{alert_id}/resolve")

    # ── incidents ─────────────────────────────────────────────────────────

    def list_incidents(self, limit: int = 50, offset: int = 0) -> list:
        return self._get("/api/incidents", limit=limit, offset=offset)

    def get_incident(self, incident_id: str) -> dict:
        return self._get(f"/api/incidents/{incident_id}")

    def create_incident(self, title: str, severity: str, description: str = "") -> dict:
        return self._post("/api/incidents", {
            "title": title,
            "severity": severity,
            "description": description,
        })

    def escalate(self, incident_id: str) -> dict:
        return self._post(f"/api/incidents/{incident_id}/escalate")

    # ── fleet ─────────────────────────────────────────────────────────────

    def list_agents(self) -> list:
        return self._get("/api/fleet/agents")

    def get_agent(self, agent_id: str) -> dict:
        return self._get(f"/api/fleet/agents/{agent_id}")

    def isolate_agent(self, agent_id: str) -> dict:
        return self._post(f"/api/fleet/agents/{agent_id}/isolate")

    def unisolate_agent(self, agent_id: str) -> dict:
        return self._post(f"/api/fleet/agents/{agent_id}/unisolate")

    # ── detection ─────────────────────────────────────────────────────────

    def run_detection(self) -> dict:
        return self._post("/api/detection/run")

    def get_baseline(self) -> dict:
        return self._get("/api/detection/baseline")

    # ── telemetry ─────────────────────────────────────────────────────────

    def ingest_event(self, event: dict) -> dict:
        return self._post("/api/telemetry/ingest", event)

    def ingest_batch(self, events: list[dict]) -> dict:
        return self._post("/api/telemetry/ingest/batch", events)

    # ── policy ────────────────────────────────────────────────────────────

    def list_policies(self) -> list:
        return self._get("/api/policies")

    def get_policy(self, policy_id: str) -> dict:
        return self._get(f"/api/policies/{policy_id}")

    def update_policy(self, policy_id: str, body: dict) -> dict:
        return self._put(f"/api/policies/{policy_id}", body)

    # ── threat intel ──────────────────────────────────────────────────────

    def list_iocs(self) -> list:
        return self._get("/api/threat-intel/iocs")

    def add_ioc(self, ioc: dict) -> dict:
        return self._post("/api/threat-intel/iocs", ioc)

    def query_ioc(self, value: str) -> dict:
        return self._get("/api/threat-intel/query", value=value)

    # ── response ──────────────────────────────────────────────────────────

    def list_actions(self) -> list:
        return self._get("/api/response/actions")

    def execute_action(self, action: dict) -> dict:
        return self._post("/api/response/execute", action)

    # ── reports ───────────────────────────────────────────────────────────

    def list_reports(self) -> list:
        return self._get("/api/reports")

    def generate_report(self, report_type: str = "full") -> dict:
        return self._post("/api/reports/generate", {"type": report_type})

    # ── config ────────────────────────────────────────────────────────────

    def get_config(self) -> dict:
        return self._get("/api/config")

    def update_config(self, config: dict) -> dict:
        return self._put("/api/config", config)

    # ── metrics ───────────────────────────────────────────────────────────

    def metrics(self) -> str:
        return self._get("/api/metrics")

    # ── openapi ───────────────────────────────────────────────────────────

    def openapi_spec(self) -> dict:
        return self._get("/api/openapi.json")
