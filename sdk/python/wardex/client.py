"""Wardex REST API client."""

from __future__ import annotations

from typing import Any

import requests

from wardex.exceptions import (
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    ServerError,
    WardexError,
)

MAX_BATCH_SIZE = 10_000
INCIDENT_SEVERITY_ALIASES = {
    "nominal": "Nominal",
    "low": "Low",
    "elevated": "Elevated",
    "medium": "Medium",
    "severe": "Severe",
    "high": "High",
    "critical": "Critical",
}


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

    Use as a context manager to ensure the underlying session is closed::

        with WardexClient("https://wardex.local", token="...") as wdx:
            wdx.status()
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

    # ── context manager ───────────────────────────────────────────────────

    def __enter__(self) -> WardexClient:
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> None:
        """Close the underlying HTTP session."""
        self._session.close()

    # ── helpers ───────────────────────────────────────────────────────────

    def _url(self, path: str) -> str:
        return f"{self._base}{path}"

    @staticmethod
    def _is_json(resp: requests.Response) -> bool:
        ct = resp.headers.get("content-type", "")
        return ct.split(";")[0].strip().lower() == "application/json"

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

    def _request(self, method: str, path: str, *, body: Any = None, **params: Any) -> Any:
        kwargs: dict[str, Any] = {"timeout": self._timeout}
        if params:
            kwargs["params"] = params
        if body is not None:
            kwargs["json"] = body
        resp = self._session.request(method, self._url(path), **kwargs)
        self._raise_for_status(resp)
        if self._is_json(resp):
            return resp.json()
        return resp.text

    def _get(self, path: str, **params: Any) -> Any:
        return self._request("GET", path, **params)

    def _post(self, path: str, body: Any = None) -> Any:
        return self._request("POST", path, body=body)

    def _put(self, path: str, body: Any = None) -> Any:
        return self._request("PUT", path, body=body)

    def _delete(self, path: str) -> Any:
        return self._request("DELETE", path)

    @staticmethod
    def _unsupported(name: str, guidance: str) -> WardexError:
        return WardexError(f"{name} is not supported by the current Wardex server API. {guidance}")

    # ── auth ──────────────────────────────────────────────────────────────

    def login(self, username: str, password: str) -> dict[str, Any]:
        raise self._unsupported(
            "login()",
            "Construct the client with an API token or call rotate_token() on an already authenticated session.",
        )

    def logout(self) -> Any:
        self._token = None
        self._session.headers.pop("Authorization", None)
        return {"status": "logged_out", "local_only": True}

    def whoami(self) -> dict[str, Any]:
        return {
            "authenticated": True,
            "auth": self.auth_check(),
            "session": self.session_info(),
        }

    def auth_check(self) -> dict[str, Any]:
        return self._get("/api/auth/check")

    def rotate_token(self) -> dict[str, Any]:
        data = self._post("/api/auth/rotate")
        if isinstance(data, dict):
            rotated = data.get("new_token")
            if rotated:
                self._token = rotated
                self._session.headers["Authorization"] = f"Bearer {rotated}"
        return data

    def session_info(self) -> dict[str, Any]:
        return self._get("/api/session/info")

    # ── status ────────────────────────────────────────────────────────────

    def status(self) -> dict[str, Any]:
        return self._get("/api/status")

    def health(self) -> dict[str, Any]:
        return self._get("/api/health")

    # ── alerts ────────────────────────────────────────────────────────────

    def list_alerts(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        return self._get("/api/alerts", limit=limit, offset=offset)

    def get_alert(self, alert_id: str) -> dict[str, Any]:
        return self._get(f"/api/alerts/{alert_id}")

    def ack_alert(self, alert_id: str) -> dict[str, Any]:
        raise self._unsupported(
            "ack_alert()",
            "Use the queue acknowledgement or event triage APIs; the current server does not expose a dedicated /api/alerts/{id}/ack route.",
        )

    def resolve_alert(self, alert_id: str) -> dict[str, Any]:
        raise self._unsupported(
            "resolve_alert()",
            "Use incident/case workflows or event triage; the current server does not expose a dedicated /api/alerts/{id}/resolve route.",
        )

    # ── incidents ─────────────────────────────────────────────────────────

    def list_incidents(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        return self._get("/api/incidents", limit=limit, offset=offset)

    def get_incident(self, incident_id: str) -> dict[str, Any]:
        return self._get(f"/api/incidents/{incident_id}")

    def create_incident(self, title: str, severity: str, description: str = "") -> dict[str, Any]:
        if not title or not title.strip():
            raise ValueError("title must not be empty")
        severity_key = severity.strip().lower()
        if severity_key not in INCIDENT_SEVERITY_ALIASES:
            allowed = "/".join(INCIDENT_SEVERITY_ALIASES.keys())
            raise ValueError(f"severity must be one of {allowed}, got '{severity}'")
        return self._post(
            "/api/incidents",
            {
                "title": title.strip(),
                "severity": INCIDENT_SEVERITY_ALIASES[severity_key],
                "summary": description,
            },
        )

    def escalate(self, incident_id: str) -> dict[str, Any]:
        raise self._unsupported(
            "escalate()",
            "Use create_incident(), update_incident(), or the escalation APIs directly if your deployment exposes them.",
        )

    def update_incident(
        self,
        incident_id: str,
        *,
        status: str | None = None,
        assignee: str | None = None,
        note: str | None = None,
        author: str | None = None,
    ) -> dict[str, Any]:
        body = {
            "status": status,
            "assignee": assignee,
            "note": note,
            "author": author,
        }
        return self._post(f"/api/incidents/{incident_id}/update", {k: v for k, v in body.items() if v is not None})

    # ── fleet ─────────────────────────────────────────────────────────────

    def list_agents(self) -> list[dict[str, Any]]:
        return self._get("/api/agents")

    def get_agent(self, agent_id: str) -> dict[str, Any]:
        return self._get(f"/api/agents/{agent_id}/details")

    def get_agent_activity(self, agent_id: str) -> dict[str, Any]:
        return self._get(f"/api/agents/{agent_id}/activity")

    def isolate_agent(
        self,
        agent_id: str,
        *,
        reason: str = "Requested from Wardex Python SDK",
        severity: str = "high",
        requested_by: str = "python-sdk",
        dry_run: bool = False,
    ) -> dict[str, Any]:
        agent = self.get_agent(agent_id)
        agent_meta = agent.get("agent", agent) if isinstance(agent, dict) else {}
        hostname = agent_meta.get("hostname")
        if not hostname:
            raise WardexError("Agent detail payload did not include a hostname for isolation")
        return self._post(
            "/api/response/request",
            {
                "action": "isolate",
                "hostname": hostname,
                "agent_uid": agent_id,
                "reason": reason,
                "severity": severity,
                "requested_by": requested_by,
                "dry_run": dry_run,
            },
        )

    def unisolate_agent(self, agent_id: str) -> dict[str, Any]:
        raise self._unsupported(
            "unisolate_agent()",
            "The current server exposes isolate as an approval-gated response action but does not expose a direct unisolate endpoint.",
        )

    # ── detection ─────────────────────────────────────────────────────────

    def run_detection(self) -> dict[str, Any]:
        return self._get("/api/detection/summary")

    def get_baseline(self) -> dict[str, Any]:
        return self._get("/api/report")

    # ── telemetry ─────────────────────────────────────────────────────────

    def ingest_event(self, event: dict[str, Any], *, agent_id: str = "python-sdk") -> dict[str, Any]:
        return self._post("/api/events", {"agent_id": agent_id, "events": [event]})

    def ingest_batch(self, events: list[dict[str, Any]], *, agent_id: str = "python-sdk") -> dict[str, Any]:
        if len(events) > MAX_BATCH_SIZE:
            raise ValueError(f"Batch size {len(events)} exceeds maximum of {MAX_BATCH_SIZE}")
        return self._post("/api/events", {"agent_id": agent_id, "events": events})

    # ── policy ────────────────────────────────────────────────────────────

    def list_policies(self) -> list[dict[str, Any]]:
        return self._get("/api/policy/history")

    def get_policy(self, policy_id: str) -> dict[str, Any]:
        if policy_id in {"current", "latest"}:
            return self._get("/api/policy/current")
        history = self.list_policies()
        for policy in history:
            version = str(policy.get("version", ""))
            if version == str(policy_id):
                return policy
        raise NotFoundError(f"Policy not found: {policy_id}", 404, "")

    def update_policy(self, policy_id: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._post("/api/policy/publish", body)

    # ── threat intel ──────────────────────────────────────────────────────

    def list_iocs(self) -> list[dict[str, Any]]:
        raise self._unsupported("list_iocs()", "Use get_threat_intel_status() or your own indicator store until list/query endpoints are exposed.")

    def add_ioc(self, ioc: dict[str, Any]) -> dict[str, Any]:
        return self._post("/api/threat-intel/ioc", ioc)

    def query_ioc(self, value: str) -> dict[str, Any]:
        raise self._unsupported("query_ioc()", "The current server exposes indicator submission and status, but not a dedicated IoC query endpoint.")

    def get_threat_intel_status(self) -> dict[str, Any]:
        return self._get("/api/threat-intel/status")

    # ── response ──────────────────────────────────────────────────────────

    def list_actions(self) -> list[dict[str, Any]]:
        return self._get("/api/response/requests")

    def execute_action(self, action: dict[str, Any]) -> dict[str, Any]:
        raise self._unsupported(
            "execute_action()",
            "Submit approval-gated actions with request_response_action(), then approve and execute them explicitly.",
        )

    def request_response_action(self, action: dict[str, Any]) -> dict[str, Any]:
        return self._post("/api/response/request", action)

    def approve_response_action(self, request_id: str, *, approve: bool = True, approver: str = "python-sdk", reason: str = "") -> dict[str, Any]:
        return self._post(
            "/api/response/approve",
            {
                "request_id": request_id,
                "decision": "approve" if approve else "deny",
                "approver": approver,
                "reason": reason,
            },
        )

    def execute_approved_actions(self, request_id: str | None = None) -> dict[str, Any]:
        body = {"request_id": request_id} if request_id else None
        return self._post("/api/response/execute", body)

    # ── reports ───────────────────────────────────────────────────────────

    def list_reports(self) -> list[dict[str, Any]]:
        return self._get("/api/reports")

    def generate_report(self, report_type: str = "full") -> dict[str, Any]:
        normalized = report_type.strip().lower()
        if normalized in {"full", "latest", "analysis"}:
            return self._get("/api/report")
        if normalized in {"executive", "executive-summary", "summary"}:
            return self._get("/api/reports/executive-summary")
        raise ValueError("report_type must be one of full/latest/analysis/executive-summary")

    # ── config ────────────────────────────────────────────────────────────

    def get_config(self) -> dict[str, Any]:
        return self._get("/api/config/current")

    def update_config(self, config: dict[str, Any]) -> dict[str, Any]:
        return self._post("/api/config/save", config)

    # ── metrics ───────────────────────────────────────────────────────────

    def metrics(self) -> str:
        return self._get("/api/metrics")

    # ── openapi ───────────────────────────────────────────────────────────

    def openapi_spec(self) -> dict[str, Any]:
        return self._get("/api/openapi.json")

    # ── vulnerability scanner ─────────────────────────────────────────

    def vulnerability_scan(self) -> dict[str, Any]:
        return self._get("/api/vulnerability/scan")

    def vulnerability_summary(self) -> dict[str, Any]:
        return self._get("/api/vulnerability/summary")

    # ── NDR engine ────────────────────────────────────────────────────

    def ndr_ingest(self, netflow: dict[str, Any]) -> dict[str, Any]:
        return self._post("/api/ndr/netflow", netflow)

    def ndr_report(self) -> dict[str, Any]:
        return self._get("/api/ndr/report")

    # ── container detection ───────────────────────────────────────────

    def container_event(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        return self._post("/api/container/event", event)

    def container_alerts(self) -> list[dict[str, Any]]:
        return self._get("/api/container/alerts")

    def container_stats(self) -> dict[str, Any]:
        return self._get("/api/container/stats")

    # ── certificate monitor ───────────────────────────────────────────

    def register_cert(self, cert: dict[str, Any]) -> dict[str, Any]:
        return self._post("/api/certs/register", cert)

    def cert_summary(self) -> dict[str, Any]:
        return self._get("/api/certs/summary")

    def cert_alerts(self) -> list[dict[str, Any]]:
        return self._get("/api/certs/alerts")

    # ── config drift detection ────────────────────────────────────────

    def config_drift_check(self, actual: dict[str, str]) -> dict[str, Any]:
        return self._post("/api/config-drift/check", actual)

    def config_drift_baselines(self) -> list[dict[str, Any]]:
        return self._get("/api/config-drift/baselines")

    # ── asset inventory ───────────────────────────────────────────────

    def assets(self) -> list[dict[str, Any]]:
        return self._get("/api/assets")

    def assets_summary(self) -> dict[str, Any]:
        return self._get("/api/assets/summary")

    def upsert_asset(self, asset: dict[str, Any]) -> dict[str, Any]:
        return self._post("/api/assets/upsert", asset)

    def search_assets(self, query: str) -> list[dict[str, Any]]:
        return self._get(f"/api/assets/search?q={query}")

    # ── detection efficacy ────────────────────────────────────────────

    def efficacy_triage(self, record: dict[str, Any]) -> dict[str, Any]:
        return self._post("/api/efficacy/triage", record)

    def efficacy_summary(self) -> dict[str, Any]:
        return self._get("/api/efficacy/summary")

    def efficacy_rule(self, rule_id: str) -> dict[str, Any]:
        return self._get(f"/api/efficacy/rule/{rule_id}")

    # ── investigation workflows ───────────────────────────────────────

    def investigation_workflows(self) -> list[dict[str, Any]]:
        return self._get("/api/investigations/workflows")

    def investigation_workflow(self, workflow_id: str) -> dict[str, Any]:
        return self._get(f"/api/investigations/workflows/{workflow_id}")

    def start_investigation(self, workflow_id: str, analyst: str, case_id: str | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {"workflow_id": workflow_id, "analyst": analyst}
        if case_id:
            payload["case_id"] = case_id
        return self._post("/api/investigations/start", payload)

    def active_investigations(self) -> list[dict[str, Any]]:
        return self._get("/api/investigations/active")

    def suggest_investigation(self, alert_reasons: list[str]) -> list[dict[str, Any]]:
        return self._post("/api/investigations/suggest", {"alert_reasons": alert_reasons})
