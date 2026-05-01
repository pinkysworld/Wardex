"""Wardex REST API client."""

from __future__ import annotations

import datetime
from email.utils import parsedate_to_datetime
import logging
import random
import time
from typing import Any, Generator

import requests
from urllib.parse import quote

from wardex.exceptions import (
    AuthenticationError,
    NotFoundError,
    RateLimitError,
    ServerError,
    WardexError,
)

MAX_BATCH_SIZE = 10_000
DEFAULT_RETRIES = 3
RETRY_BACKOFF_BASE = 0.5
RETRY_BACKOFF_MAX = 30.0

log = logging.getLogger(__name__)
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
        retries: int = DEFAULT_RETRIES,
    ):
        self._base = base_url.rstrip("/")
        self._token = token
        self._timeout = timeout
        self._retries = retries
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
        url = self._url(path)
        last_exc: Exception | None = None
        resp: requests.Response | None = None
        for attempt in range(self._retries + 1):
            try:
                resp = self._session.request(method, url, **kwargs)
            except requests.ConnectionError as exc:
                last_exc = exc
                if attempt < self._retries:
                    self._backoff(attempt)
                    continue
                raise
            if resp.status_code == 429 or resp.status_code >= 500:
                last_exc = None
                if attempt < self._retries:
                    retry_after = resp.headers.get("Retry-After")
                    if retry_after:
                        try:
                            delay = float(retry_after)
                        except ValueError:
                            try:
                                dt = parsedate_to_datetime(retry_after)
                                delay = max(0, (dt - datetime.datetime.now(datetime.timezone.utc)).total_seconds())
                            except Exception:
                                delay = self._backoff_delay(attempt)
                    else:
                        delay = self._backoff_delay(attempt)
                    log.warning(
                        "Retry %d/%d for %s %s (HTTP %d)",
                        attempt + 1, self._retries, method, path, resp.status_code,
                    )
                    time.sleep(delay)
                    continue
            self._raise_for_status(resp)
            if self._is_json(resp):
                return resp.json()
            return resp.text
        if last_exc is not None:
            raise last_exc
        if resp is not None:
            self._raise_for_status(resp)
        return None  # unreachable

    @staticmethod
    def _backoff_delay(attempt: int) -> float:
        delay = RETRY_BACKOFF_BASE * (2 ** attempt)
        delay = min(delay, RETRY_BACKOFF_MAX)
        return delay * (0.5 + random.random() * 0.5)

    def _backoff(self, attempt: int) -> None:
        delay = self._backoff_delay(attempt)
        log.warning("Retry %d/%d after %.1fs (connection error)", attempt + 1, self._retries, delay)
        time.sleep(delay)

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

    def ws_stats(self) -> dict[str, Any]:
        return self._get("/api/ws/stats")

    # ── alerts ────────────────────────────────────────────────────────────

    def list_alerts(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        return self._get("/api/alerts", limit=limit, offset=offset)

    def get_alert(self, alert_id: str) -> dict[str, Any]:
        return self._get(f"/api/alerts/{quote(alert_id, safe='')}")

    def ack_alert(self, alert_id: str) -> dict[str, Any]:
        """Acknowledge a single alert via the bulk acknowledge endpoint."""
        return self._post("/api/alerts/bulk/acknowledge", {"ids": [alert_id]})

    def ack_alerts(self, alert_ids: list[str]) -> dict[str, Any]:
        """Acknowledge multiple alerts in one request."""
        return self._post("/api/alerts/bulk/acknowledge", {"ids": alert_ids})

    def resolve_alert(self, alert_id: str) -> dict[str, Any]:
        """Resolve a single alert via the bulk resolve endpoint."""
        return self._post("/api/alerts/bulk/resolve", {"ids": [alert_id]})

    def resolve_alerts(self, alert_ids: list[str]) -> dict[str, Any]:
        """Resolve multiple alerts in one request."""
        return self._post("/api/alerts/bulk/resolve", {"ids": alert_ids})

    def close_alert(self, alert_id: str) -> dict[str, Any]:
        """Close a single alert via the bulk close endpoint."""
        return self._post("/api/alerts/bulk/close", {"ids": [alert_id]})

    def close_alerts(self, alert_ids: list[str]) -> dict[str, Any]:
        """Close multiple alerts in one request."""
        return self._post("/api/alerts/bulk/close", {"ids": alert_ids})

    def list_all_alerts(self, page_size: int = 50, max_pages: int = 10_000) -> Generator[dict[str, Any], None, None]:
        """Auto-paginating generator that yields every alert."""
        offset = 0
        for _ in range(max_pages):
            batch = self.list_alerts(limit=page_size, offset=offset)
            if not batch:
                return
            yield from batch
            if len(batch) < page_size:
                return
            offset += len(batch)

    # ── incidents ─────────────────────────────────────────────────────────

    def list_incidents(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        return self._get("/api/incidents", limit=limit, offset=offset)

    def get_incident(self, incident_id: str) -> dict[str, Any]:
        return self._get(f"/api/incidents/{quote(incident_id, safe='')}")

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

    def escalate(self, incident_id: str, *, policy_id: str = "default") -> dict[str, Any]:
        """Start an escalation for an incident/alert via the escalation engine."""
        return self._post("/api/escalation/start", {"policy_id": policy_id, "alert_id": incident_id})

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
        return self._post(f"/api/incidents/{quote(incident_id, safe='')}/update", {k: v for k, v in body.items() if v is not None})

    # ── fleet ─────────────────────────────────────────────────────────────

    def list_agents(self) -> list[dict[str, Any]]:
        return self._get("/api/agents")

    def get_agent(self, agent_id: str) -> dict[str, Any]:
        return self._get(f"/api/agents/{quote(agent_id, safe='')}/details")

    def get_agent_activity(self, agent_id: str) -> dict[str, Any]:
        return self._get(f"/api/agents/{quote(agent_id, safe='')}/activity")

    def fleet_installs(self) -> dict[str, Any]:
        return self._get("/api/fleet/installs")

    def fleet_install_ssh(self, request: dict[str, Any]) -> dict[str, Any]:
        return self._post("/api/fleet/install/ssh", request)

    def fleet_install_winrm(self, request: dict[str, Any]) -> dict[str, Any]:
        return self._post("/api/fleet/install/winrm", request)

    def process_threads(self, pid: int | str) -> dict[str, Any]:
        return self._get("/api/processes/threads", pid=pid)

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

    def detection_replay_corpus(self) -> dict[str, Any]:
        return self._get("/api/detection/replay-corpus")

    def evaluate_detection_replay_corpus(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._post("/api/detection/replay-corpus", payload)

    def detection_explain(
        self,
        *,
        event_id: int | None = None,
        alert_id: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if event_id is not None:
            params["event_id"] = event_id
        if alert_id:
            params["alert_id"] = alert_id
        return self._get("/api/detection/explain", **params)

    def detection_feedback(self, event_id: int | None = None, limit: int | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if event_id is not None:
            params["event_id"] = event_id
        if limit is not None:
            params["limit"] = limit
        return self._get("/api/detection/feedback", **params)

    def record_detection_feedback(self, feedback: dict[str, Any]) -> dict[str, Any]:
        return self._post("/api/detection/feedback", feedback)

    def detection_profile(self) -> dict[str, Any]:
        return self._get("/api/detection/profile")

    def set_detection_profile(self, profile: str | dict[str, Any]) -> dict[str, Any]:
        payload = profile if isinstance(profile, dict) else {"profile": profile}
        return self._put("/api/detection/profile", payload)

    def detection_weights(self) -> dict[str, Any]:
        return self._get("/api/detection/weights")

    def set_detection_weights(self, weights: dict[str, Any]) -> dict[str, Any]:
        return self._post("/api/detection/weights", weights)

    def normalize_score(self) -> dict[str, Any]:
        return self._get("/api/detection/score/normalize")

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

    def support_parity(self) -> dict[str, Any]:
        return self._get("/api/support/parity")

    def readiness_evidence(self) -> dict[str, Any]:
        return self._get("/api/support/readiness-evidence")

    def first_run_proof(self) -> dict[str, Any]:
        return self._post("/api/support/first-run-proof")

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
        return self._get("/api/assets/search", q=query)

    # ── detection efficacy ────────────────────────────────────────────

    def efficacy_triage(self, record: dict[str, Any]) -> dict[str, Any]:
        return self._post("/api/efficacy/triage", record)

    def efficacy_summary(self) -> dict[str, Any]:
        return self._get("/api/efficacy/summary")

    def efficacy_rule(self, rule_id: str) -> dict[str, Any]:
        return self._get(f"/api/efficacy/rule/{quote(rule_id, safe='')}")

    # ── investigation workflows ───────────────────────────────────────

    def investigation_workflows(self) -> list[dict[str, Any]]:
        return self._get("/api/investigations/workflows")

    def investigation_workflow(self, workflow_id: str) -> dict[str, Any]:
        return self._get(f"/api/investigations/workflows/{quote(workflow_id, safe='')}")

    def start_investigation(self, workflow_id: str, analyst: str, case_id: str | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {"workflow_id": workflow_id, "analyst": analyst}
        if case_id:
            payload["case_id"] = case_id
        return self._post("/api/investigations/start", payload)

    def active_investigations(self) -> list[dict[str, Any]]:
        return self._get("/api/investigations/active")

    def suggest_investigation(self, alert_reasons: list[str]) -> list[dict[str, Any]]:
        return self._post("/api/investigations/suggest", {"alert_reasons": alert_reasons})

    # ── malware detection / AV scanning ──────────────────────────────

    def scan_buffer(self, data: bytes, filename: str = "upload") -> dict[str, Any]:
        import base64
        payload = {"data": base64.b64encode(data).decode(), "filename": filename}
        return self._post("/api/scan/buffer", payload)

    def scan_hash(self, hash_value: str) -> dict[str, Any] | None:
        return self._post("/api/scan/hash", {"hash": hash_value})

    def malware_stats(self) -> dict[str, Any]:
        return self._get("/api/malware/stats")

    def malware_recent(self) -> list[dict[str, Any]]:
        return self._get("/api/malware/recent")

    def malware_import(self, data: str) -> dict[str, Any]:
        return self._post("/api/malware/signatures/import", data)

    def collectors_status(self) -> dict[str, Any]:
        return self._get("/api/collectors/status")

    def remediation_change_reviews(self) -> dict[str, Any]:
        return self._get("/api/remediation/change-reviews")

    def record_remediation_change_review(self, review: dict[str, Any]) -> dict[str, Any]:
        return self._post("/api/remediation/change-reviews", review)

    def approve_remediation_change_review(
        self,
        review_id: str,
        decision: str = "approve",
        comment: str | None = None,
        approver: str | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"decision": decision}
        if comment:
            payload["comment"] = comment
        if approver:
            payload["approver"] = approver
        return self._post(
            f"/api/remediation/change-reviews/{quote(review_id, safe='')}/approval",
            payload,
        )

    def execute_remediation_rollback(
        self,
        review_id: str,
        dry_run: bool = True,
        platform: str = "linux",
        confirm_hostname: str | None = None,
        **extra: Any,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"dry_run": dry_run, "platform": platform}
        if confirm_hostname:
            payload["confirm_hostname"] = confirm_hostname
        payload.update(extra)
        return self._post(
            f"/api/remediation/change-reviews/{quote(review_id, safe='')}/rollback",
            payload,
        )

    # ── threat hunting ───────────────────────────────────────────────

    def hunt(self, query: str) -> dict[str, Any]:
        return self._post("/api/hunt", {"query": query})

    # ── SIEM export ──────────────────────────────────────────────────

    def export_alerts(self, fmt: str = "json") -> str:
        return self._get("/api/export/alerts", format=fmt)

    # ── compliance ───────────────────────────────────────────────────

    def compliance_report(self, framework: str | None = None) -> Any:
        if framework:
            return self._get("/api/compliance/report", framework=framework)
        return self._get("/api/compliance/report")

    def compliance_summary(self) -> dict[str, Any]:
        return self._get("/api/compliance/summary")

    # ── playbook run ─────────────────────────────────────────────────

    def run_playbook(
        self,
        playbook_id: str,
        alert_id: str | None = None,
        variables: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"playbook_id": playbook_id}
        if alert_id:
            payload["alert_id"] = alert_id
        if variables:
            payload["variables"] = variables
        return self._post("/api/playbooks/run", payload)

    # ── alert deduplication ──────────────────────────────────────────

    def dedup_alerts(self) -> list[dict[str, Any]]:
        return self._get("/api/alerts/dedup")

    # ── API analytics ────────────────────────────────────────────────

    def api_analytics(self) -> dict[str, Any]:
        return self._get("/api/analytics")

    # ── OpenTelemetry traces ─────────────────────────────────────────

    def traces(self) -> dict[str, Any]:
        return self._get("/api/traces")

    # ── backup encryption ────────────────────────────────────────────

    def backup_encrypt(self, data: str, passphrase: str) -> dict[str, Any]:
        return self._post("/api/backup/encrypt", {"data": data, "passphrase": passphrase})

    def backup_decrypt(self, data: str, passphrase: str) -> dict[str, Any]:
        return self._post("/api/backup/decrypt", {"data": data, "passphrase": passphrase})

    def list_backups(self) -> list[dict[str, Any]]:
        return self._get("/api/backups")

    def create_backup(self) -> dict[str, Any]:
        return self._post("/api/backups")

    def backup_status(self) -> dict[str, Any]:
        return self._get("/api/backup/status")

    # ── detection rules ──────────────────────────────────────────────

    def detection_rules(self) -> dict[str, Any]:
        return self._get("/api/detection/rules")

    def add_detection_rule(
        self,
        name: str,
        pattern: str,
        rule_type: str = "yara",
        severity: str = "medium",
        description: str = "",
    ) -> dict[str, Any]:
        return self._post("/api/detection/rules", {
            "type": rule_type,
            "name": name,
            "pattern": pattern,
            "severity": severity,
            "description": description,
        })

    # ── UEBA ─────────────────────────────────────────────────────────

    def ueba_risky_entities(self) -> list[dict[str, Any]]:
        return self._get("/api/ueba/risky-entities")

    def ueba_anomalies(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._get("/api/ueba/anomalies", limit=limit)

    def ueba_peer_groups(self) -> list[dict[str, Any]]:
        return self._get("/api/ueba/peer-groups")

    def ueba_entity(self, entity_id: str) -> dict[str, Any]:
        return self._get(f"/api/ueba/entity/{quote(entity_id, safe='')}")

    def ueba_timeline(self, entity_id: str, hours: int = 24) -> list[dict[str, Any]]:
        return self._get(f"/api/ueba/timeline/{quote(entity_id, safe='')}", hours=hours)

    # ── NDR advanced ─────────────────────────────────────────────────

    def ndr_tls_anomalies(self) -> list[dict[str, Any]]:
        return self._get("/api/ndr/tls-anomalies")

    def ndr_dpi_anomalies(self) -> list[dict[str, Any]]:
        return self._get("/api/ndr/dpi-anomalies")

    def ndr_entropy_anomalies(self) -> list[dict[str, Any]]:
        return self._get("/api/ndr/entropy-anomalies")

    def ndr_self_signed_certs(self) -> list[dict[str, Any]]:
        return self._get("/api/ndr/self-signed-certs")

    def ndr_top_talkers(self, limit: int = 20) -> list[dict[str, Any]]:
        return self._get("/api/ndr/top-talkers", limit=limit)

    def ndr_protocol_distribution(self) -> dict[str, Any]:
        return self._get("/api/ndr/protocol-distribution")

    # ── email security ───────────────────────────────────────────────

    def email_analyze(self, headers: str) -> dict[str, Any]:
        return self._post("/api/email/analyze", {"headers": headers})

    def email_quarantine(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._get("/api/email/quarantine", limit=limit)

    def email_quarantine_release(self, message_id: str) -> dict[str, Any]:
        return self._post(f"/api/email/quarantine/{quote(message_id, safe='')}/release")

    def email_quarantine_delete(self, message_id: str) -> dict[str, Any]:
        return self._delete(f"/api/email/quarantine/{quote(message_id, safe='')}")

    def email_stats(self) -> dict[str, Any]:
        return self._get("/api/email/stats")

    def email_policies(self) -> list[dict[str, Any]]:
        return self._get("/api/email/policies")

    # ── campaigns / attack graph ─────────────────────────────────────

    def campaigns(self) -> dict[str, Any]:
        return self._get("/api/campaigns")
