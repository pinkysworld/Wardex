"""Tests for the Wardex Python SDK."""

from __future__ import annotations

import json

import pytest

from wardex import (
    AuthenticationError,
    CommandCenterLaneResponse,
    CommandCenterSummaryResponse,
    NotFoundError,
    RateLimitError,
    ServerError,
    WardexClient,
    WardexError,
)


BASE = "http://localhost:9077"


def test_command_center_types_are_exported():
    assert "generated_at" in CommandCenterSummaryResponse.__annotations__
    assert "metric_key" in CommandCenterLaneResponse.__annotations__


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


def test_failover_drill(monkeypatch):
    calls = install_stub(
        monkeypatch,
        {
            ("POST", f"{BASE}/api/control/failover-drill"): DummyResponse(
                url=f"{BASE}/api/control/failover-drill",
                json_data={
                    "digest": "failover-drill-digest",
                    "drill": {
                        "drill_type": "warm_standby_restore_dry_run",
                        "orchestration_scope": "standalone_reference",
                        "status": "passed",
                        "last_run_at": "2026-04-30T12:02:00Z",
                        "actor": "admin",
                        "summary": "Validated durable event storage with checkpoint artifacts for the documented warm-standby restore path.",
                        "artifact_source": "checkpoint",
                        "durable_storage_verified": True,
                        "backup_artifact_verified": False,
                        "checkpoint_artifact_verified": True,
                    },
                },
                headers={"content-type": "application/json"},
            )
        },
    )
    client = WardexClient(BASE, token="tok")
    data = client.failover_drill()
    assert data["drill"]["status"] == "passed"
    assert calls[0]["method"] == "POST"


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


def test_product_hardening_methods(monkeypatch):
    mapping = {
        ("GET", f"{BASE}/api/ws/health"): DummyResponse(url=f"{BASE}/api/ws/health", json_data={"status": "healthy"}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/stream/readiness"): DummyResponse(url=f"{BASE}/api/stream/readiness", json_data={"status": "ready"}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/stream/reliability-lab"): DummyResponse(url=f"{BASE}/api/stream/reliability-lab", json_data={"status": "pass"}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/operator/workspaces"): DummyResponse(url=f"{BASE}/api/operator/workspaces", json_data={"groups": []}, headers={"content-type": "application/json"}),
        ("POST", f"{BASE}/api/alerts/feedback"): DummyResponse(url=f"{BASE}/api/alerts/feedback", json_data={"status": "recorded"}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/alerts/feedback/summary"): DummyResponse(url=f"{BASE}/api/alerts/feedback/summary", json_data={"summary": {}}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/alerts/evidence-chain", (("alert_id", "7"),)): DummyResponse(url=f"{BASE}/api/alerts/evidence-chain", json_data={"alert_id": "7"}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/detection-lab/status"): DummyResponse(url=f"{BASE}/api/detection-lab/status", json_data={"status": "ready"}, headers={"content-type": "application/json"}),
        ("POST", f"{BASE}/api/detection-lab/runs"): DummyResponse(url=f"{BASE}/api/detection-lab/runs", json_data={"status": "completed"}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/detection-lab/history"): DummyResponse(url=f"{BASE}/api/detection-lab/history", json_data={"history": []}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/detection-lab/report"): DummyResponse(url=f"{BASE}/api/detection-lab/report", json_data={"report": {}}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/response/safety"): DummyResponse(url=f"{BASE}/api/response/safety", json_data={"status": "ready"}, headers={"content-type": "application/json"}),
        ("POST", f"{BASE}/api/response/preview"): DummyResponse(url=f"{BASE}/api/response/preview", json_data={"status": "preview_ready"}, headers={"content-type": "application/json"}),
        ("POST", f"{BASE}/api/response/verify"): DummyResponse(url=f"{BASE}/api/response/verify", json_data={"verified": True}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/integrations/marketplace"): DummyResponse(url=f"{BASE}/api/integrations/marketplace", json_data={"connectors": []}, headers={"content-type": "application/json"}),
        ("POST", f"{BASE}/api/integrations/validate"): DummyResponse(url=f"{BASE}/api/integrations/validate", json_data={"valid": True}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/integrations/sample-event", (("provider", "generic_syslog"),)): DummyResponse(url=f"{BASE}/api/integrations/sample-event", json_data={"provider": "generic_syslog"}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/operations/health"): DummyResponse(url=f"{BASE}/api/operations/health", json_data={"slo_cards": []}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/operations/health/snapshot"): DummyResponse(url=f"{BASE}/api/operations/health/snapshot", json_data={"snapshot": {}}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/malware/explain"): DummyResponse(url=f"{BASE}/api/malware/explain", json_data={"summary": {}}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/malware/scan-diff"): DummyResponse(url=f"{BASE}/api/malware/scan-diff", json_data={"comparison": {}}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/sdk/contract-status"): DummyResponse(url=f"{BASE}/api/sdk/contract-status", json_data={"status": "tracked"}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/operational/snapshots", (("kind", "stream_readiness"), ("limit", "3"))): DummyResponse(url=f"{BASE}/api/operational/snapshots", json_data={"snapshots": []}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/operational/snapshots/verify", (("digest", "abc"),)): DummyResponse(url=f"{BASE}/api/operational/snapshots/verify", json_data={"verified": True}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/release/doctor"): DummyResponse(url=f"{BASE}/api/release/doctor", json_data={"status": "ready"}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/release/provenance"): DummyResponse(url=f"{BASE}/api/release/provenance", json_data={"status": "ready"}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/release/upgrade-rehearsal", (("target_version", "1.0.13"),)): DummyResponse(url=f"{BASE}/api/release/upgrade-rehearsal", json_data={"status": "ready"}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/release/clean-cut"): DummyResponse(url=f"{BASE}/api/release/clean-cut", json_data={"status": "ready"}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/containers/release-parity"): DummyResponse(url=f"{BASE}/api/containers/release-parity", json_data={"status": "ready"}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/release/verification-center"): DummyResponse(url=f"{BASE}/api/release/verification-center", json_data={"status": "ready"}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/deployment/self-hosted-wizard"): DummyResponse(url=f"{BASE}/api/deployment/self-hosted-wizard", json_data={"status": "ready"}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/data-quality/dashboard"): DummyResponse(url=f"{BASE}/api/data-quality/dashboard", json_data={"status": "ready"}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/performance/scale-baseline"): DummyResponse(url=f"{BASE}/api/performance/scale-baseline", json_data={"status": "ready"}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/cluster/failover-execution"): DummyResponse(url=f"{BASE}/api/cluster/failover-execution", json_data={"status": "ready"}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/secrets/rotation-operations"): DummyResponse(url=f"{BASE}/api/secrets/rotation-operations", json_data={"status": "ready"}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/operator/task-automation"): DummyResponse(url=f"{BASE}/api/operator/task-automation", json_data={"status": "ready"}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/detection/validation-packs"): DummyResponse(url=f"{BASE}/api/detection/validation-packs", json_data={"status": "ready"}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/support/bundle"): DummyResponse(url=f"{BASE}/api/support/bundle", json_data={"status": "redacted"}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/launchpad/evidence-pack"): DummyResponse(url=f"{BASE}/api/launchpad/evidence-pack", json_data={"digest": "abc"}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/launchpad/release-diff"): DummyResponse(url=f"{BASE}/api/launchpad/release-diff", json_data={"status": "aligned"}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/launchpad/demo-status"): DummyResponse(url=f"{BASE}/api/launchpad/demo-status", json_data={"status": "available"}, headers={"content-type": "application/json"}),
        ("POST", f"{BASE}/api/launchpad/demo-reset"): DummyResponse(url=f"{BASE}/api/launchpad/demo-reset", json_data={"status": "reset_recorded"}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/alerts/histogram", (("bucket", "1h"), ("severity", "high"), ("window", "24h"))): DummyResponse(url=f"{BASE}/api/alerts/histogram", json_data={"total": 1}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/detection/recommendations", (("limit", "3"),)): DummyResponse(url=f"{BASE}/api/detection/recommendations", json_data={"recommendations": []}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/detection/readiness", (("limit", "5"),)): DummyResponse(url=f"{BASE}/api/detection/readiness", json_data={"rules": []}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/detection/trust/overview"): DummyResponse(url=f"{BASE}/api/detection/trust/overview", json_data={"draft_only_tuning": True}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/detection/trust/rules"): DummyResponse(url=f"{BASE}/api/detection/trust/rules", json_data={"rules": []}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/detection/trust/rules/rule-1"): DummyResponse(url=f"{BASE}/api/detection/trust/rules/rule-1", json_data={"found": True}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/detection/trust/tuning-drafts"): DummyResponse(url=f"{BASE}/api/detection/trust/tuning-drafts", json_data={"drafts": []}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/detection/tuning/feedback"): DummyResponse(url=f"{BASE}/api/detection/tuning/feedback", json_data={"items": []}, headers={"content-type": "application/json"}),
        ("POST", f"{BASE}/api/detection/trust/tuning-drafts"): DummyResponse(url=f"{BASE}/api/detection/trust/tuning-drafts", json_data={"created": True}, headers={"content-type": "application/json"}),
        ("POST", f"{BASE}/api/detection/trust/tuning-drafts/draft-1/preview"): DummyResponse(url=f"{BASE}/api/detection/trust/tuning-drafts/draft-1/preview", json_data={"auto_apply": False}, headers={"content-type": "application/json"}),
        ("POST", f"{BASE}/api/detection/trust/tuning-drafts/draft-1/approve"): DummyResponse(url=f"{BASE}/api/detection/trust/tuning-drafts/draft-1/approve", json_data={"applied": False}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/response/audit"): DummyResponse(url=f"{BASE}/api/response/audit", json_data={"count": 1}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/response/execution-audit?request_id=req-1&action_id=kill-process"): DummyResponse(url=f"{BASE}/api/response/execution-audit", json_data={"count": 1}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/admin/rbac-coverage"): DummyResponse(url=f"{BASE}/api/admin/rbac-coverage", json_data={"protected_routes": 1}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/search/performance-slo"): DummyResponse(url=f"{BASE}/api/search/performance-slo", json_data={"status": "ready"}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/response/approval-overview"): DummyResponse(url=f"{BASE}/api/response/approval-overview", json_data={"pending_count": 0}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/remediation/safety"): DummyResponse(url=f"{BASE}/api/remediation/safety", json_data={"status": "ready"}, headers={"content-type": "application/json"}),
        ("POST", f"{BASE}/api/playbooks/resume"): DummyResponse(url=f"{BASE}/api/playbooks/resume", json_data={"execution_id": "exec-1", "status": "succeeded"}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/playbook/execution/exec-1/recovery-actions"): DummyResponse(url=f"{BASE}/api/playbook/execution/exec-1/recovery-actions", json_data={"actions": []}, headers={"content-type": "application/json"}),
        ("POST", f"{BASE}/api/subscriptions"): DummyResponse(url=f"{BASE}/api/subscriptions", json_data={"subscription": {"subscription_id": "sub-1"}}, headers={"content-type": "application/json"}),
        ("GET", f"{BASE}/api/subscriptions/resume", (("cursor", "7"), ("limit", "2"), ("subscription_id", "sub-1"))): DummyResponse(url=f"{BASE}/api/subscriptions/resume", json_data={"events": []}, headers={"content-type": "application/json"}),
    }
    calls = install_stub(monkeypatch, mapping)
    client = WardexClient(BASE, token="tok")

    assert client.ws_health()["status"] == "healthy"
    assert client.stream_readiness()["status"] == "ready"
    assert client.stream_reliability_lab()["status"] == "pass"
    assert client.operator_workspaces()["groups"] == []
    assert client.alert_feedback({"state": "valid"})["status"] == "recorded"
    assert client.alert_feedback_summary()["summary"] == {}
    assert client.alert_evidence_chain(alert_id=7)["alert_id"] == "7"
    assert client.detection_lab_status()["status"] == "ready"
    assert client.detection_lab_run({"mode": "replay"})["status"] == "completed"
    assert client.detection_lab_history()["history"] == []
    assert client.detection_lab_report()["report"] == {}
    assert client.response_safety()["status"] == "ready"
    assert client.response_preview({"action": "block_ip"})["status"] == "preview_ready"
    assert client.response_verify({"action": "block_ip"})["verified"] is True
    assert client.integrations_marketplace()["connectors"] == []
    assert client.validate_integration({"provider": "generic_syslog"})["valid"] is True
    assert client.integration_sample_event("generic_syslog")["provider"] == "generic_syslog"
    assert client.operations_health()["slo_cards"] == []
    assert client.operations_health_snapshot()["snapshot"] == {}
    assert client.malware_explain()["summary"] == {}
    assert client.malware_scan_diff()["comparison"] == {}
    assert client.sdk_contract_status()["status"] == "tracked"
    assert client.operational_snapshots(kind="stream_readiness", limit=3)["snapshots"] == []
    assert client.verify_operational_snapshot(digest="abc")["verified"] is True
    assert client.release_doctor()["status"] == "ready"
    assert client.release_provenance()["status"] == "ready"
    assert client.release_upgrade_rehearsal(target_version="1.0.13")["status"] == "ready"
    assert client.clean_release_cut()["status"] == "ready"
    assert client.container_release_parity()["status"] == "ready"
    assert client.release_verification_center()["status"] == "ready"
    assert client.self_hosted_deployment_wizard()["status"] == "ready"
    assert client.data_quality_dashboard()["status"] == "ready"
    assert client.performance_scale_baseline()["status"] == "ready"
    assert client.cluster_failover_execution()["status"] == "ready"
    assert client.secrets_rotation_operations()["status"] == "ready"
    assert client.operator_task_automation()["status"] == "ready"
    assert client.detection_validation_packs()["status"] == "ready"
    assert client.support_bundle()["status"] == "redacted"
    assert client.launchpad_evidence_pack()["digest"] == "abc"
    assert client.launchpad_release_diff()["status"] == "aligned"
    assert client.launchpad_demo_status()["status"] == "available"
    assert client.launchpad_demo_reset()["status"] == "reset_recorded"
    assert client.alert_histogram(window="24h", bucket="1h", severity="high")["total"] == 1
    assert client.detection_recommendations(limit=3)["recommendations"] == []
    assert client.detection_readiness(limit=5)["rules"] == []
    assert client.detection_trust_overview()["draft_only_tuning"] is True
    assert client.detection_trust_rules()["rules"] == []
    assert client.detection_trust_rule("rule-1")["found"] is True
    assert client.detection_trust_tuning_drafts()["drafts"] == []
    assert client.detection_tuning_feedback()["items"] == []
    assert client.create_detection_trust_tuning_draft({"rule_id": "rule-1"})["created"] is True
    assert client.preview_detection_trust_tuning_draft("draft-1")["auto_apply"] is False
    assert client.approve_detection_trust_tuning_draft("draft-1")["applied"] is False
    assert client.response_audit()["count"] == 1
    assert client.response_execution_audit(request_id="req-1", action_id="kill-process")["count"] == 1
    assert client.rbac_coverage()["protected_routes"] == 1
    assert client.search_performance_slo()["status"] == "ready"
    assert client.response_approval_overview()["pending_count"] == 0
    assert client.remediation_safety()["status"] == "ready"
    assert client.resume_playbook("exec-1", feedback="approved")["status"] == "succeeded"
    assert client.playbook_execution_recovery_actions("exec-1")["actions"] == []
    assert client.create_subscription()["subscription"]["subscription_id"] == "sub-1"
    assert client.resume_subscription("sub-1", cursor=7, limit=2)["events"] == []
    assert calls[-1]["method"] == "GET"


def test_command_summary(monkeypatch):
    calls = install_stub(
        monkeypatch,
        {
            ("GET", f"{BASE}/api/command/summary"): DummyResponse(
                url=f"{BASE}/api/command/summary",
                json_data={
                    "generated_at": "2026-05-01T19:00:00Z",
                    "metrics": {"open_incidents": 3},
                    "lanes": {"connectors": {"readiness": {"collectors": []}}},
                },
                headers={"content-type": "application/json"},
            )
        },
    )
    client = WardexClient(BASE, token="tok")
    data = client.command_summary()
    assert data["metrics"]["open_incidents"] == 3
    assert calls[0]["method"] == "GET"


def test_command_lane(monkeypatch):
    calls = install_stub(
        monkeypatch,
        {
            ("GET", f"{BASE}/api/command/lanes/release"): DummyResponse(
                url=f"{BASE}/api/command/lanes/release",
                json_data={
                    "lane": "release",
                    "metric_key": "release_candidates",
                    "metric_value": 1,
                    "payload": {
                        "status": "ready",
                        "annotation": "Candidate metadata is available for rollout review, SBOM checks, and rollback planning.",
                        "next_step": "Review candidate notes, SBOM context, and rollout readiness before promotion.",
                    },
                },
                headers={"content-type": "application/json"},
            )
        },
    )
    client = WardexClient(BASE, token="tok")
    data = client.command_lane("release")
    assert data["lane"] == "release"
    assert data["metric_key"] == "release_candidates"
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


def test_report_listing_endpoints_include_execution_context_filters(monkeypatch):
    scoped_params = (
        ("case_id", "42"),
        ("incident_id", "7"),
        ("investigation_id", "inv-7"),
        ("scope", "scoped"),
        ("source", "case"),
    )
    calls = install_stub(
        monkeypatch,
        {
            ("GET", f"{BASE}/api/report-templates", scoped_params): DummyResponse(
                url=f"{BASE}/api/report-templates",
                json_data={"templates": [], "count": 0},
                headers={"content-type": "application/json"},
            ),
            ("GET", f"{BASE}/api/report-runs", scoped_params): DummyResponse(
                url=f"{BASE}/api/report-runs",
                json_data={"runs": [], "count": 0},
                headers={"content-type": "application/json"},
            ),
            ("GET", f"{BASE}/api/report-schedules", scoped_params): DummyResponse(
                url=f"{BASE}/api/report-schedules",
                json_data={"schedules": [], "count": 0},
                headers={"content-type": "application/json"},
            ),
        },
    )
    client = WardexClient(BASE, token="tok")
    assert client.report_templates(
        case_id="42",
        incident_id="7",
        investigation_id="inv-7",
        source="case",
        scope="scoped",
    )["count"] == 0
    assert client.report_runs(
        case_id="42",
        incident_id="7",
        investigation_id="inv-7",
        source="case",
        scope="scoped",
    )["count"] == 0
    assert client.report_schedules(
        case_id="42",
        incident_id="7",
        investigation_id="inv-7",
        source="case",
        scope="scoped",
    )["count"] == 0
    assert calls[0]["method"] == "GET"
    assert calls[1]["method"] == "GET"
    assert calls[2]["method"] == "GET"


def test_report_mutation_endpoints_post_failover_history_payloads(monkeypatch):
    calls = install_stub(
        monkeypatch,
        {
            ("POST", f"{BASE}/api/report-templates"): DummyResponse(
                url=f"{BASE}/api/report-templates",
                json_data={
                    "status": "saved",
                    "template": {
                        "id": "tpl-failover-drill-history",
                        "kind": "control_plane_failover_history",
                    },
                },
                headers={"content-type": "application/json"},
            ),
            ("POST", f"{BASE}/api/report-runs"): DummyResponse(
                url=f"{BASE}/api/report-runs",
                json_data={
                    "status": "created",
                    "run": {
                        "id": "run-1",
                        "kind": "control_plane_failover_history",
                        "preview": {"kind": "control_plane_failover_history"},
                    },
                },
                headers={"content-type": "application/json"},
            ),
            ("POST", f"{BASE}/api/report-schedules"): DummyResponse(
                url=f"{BASE}/api/report-schedules",
                json_data={
                    "status": "saved",
                    "schedule": {
                        "id": "sched-1",
                        "kind": "control_plane_failover_history",
                    },
                },
                headers={"content-type": "application/json"},
            ),
        },
    )
    client = WardexClient(BASE, token="tok")
    template = client.save_report_template(
        {
            "name": "Control-plane Failover Drill History",
            "kind": "control_plane_failover_history",
            "scope": "control_plane",
            "format": "json",
        }
    )
    run = client.create_report_run(
        {
            "name": "Control-plane Failover Drill History",
            "kind": "control_plane_failover_history",
            "scope": "control_plane",
            "format": "json",
            "case_id": "42",
            "incident_id": "7",
            "investigation_id": "inv-7",
            "source": "case",
        }
    )
    schedule = client.save_report_schedule(
        {
            "name": "Weekly Control-plane Failover Drill History",
            "kind": "control_plane_failover_history",
            "scope": "control_plane",
            "format": "json",
            "cadence": "weekly",
            "target": "audit@wardex.local",
        }
    )

    assert template["template"]["kind"] == "control_plane_failover_history"
    assert run["run"]["preview"]["kind"] == "control_plane_failover_history"
    assert schedule["schedule"]["kind"] == "control_plane_failover_history"
    assert calls[0]["kwargs"]["json"]["kind"] == "control_plane_failover_history"
    assert calls[1]["kwargs"]["json"]["investigation_id"] == "inv-7"
    assert calls[2]["kwargs"]["json"]["cadence"] == "weekly"


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
