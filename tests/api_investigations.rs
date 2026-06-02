mod common;
use common::*;

#[test]
fn queue_alerts_include_age_and_sla_fields() {
    let (port, token) = spawn_test_server();
    let (_agent_id, event_ids) = setup_agent_with_events(port, &token, "queue-host", 1);
    assert!(!event_ids.is_empty());

    let body: serde_json::Value = ureq::get(&format!("{}/api/queue/alerts", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("queue alerts")
        .into_json()
        .unwrap();

    assert!(body["count"].as_u64().unwrap() >= 1);
    let item = &body["queue"][0];
    assert!(item["event_id"].is_u64());
    assert!(item["age_secs"].is_u64());
    assert!(item["sla_breached"].is_boolean());
    assert!(item["severity"].is_string());
}

#[test]
fn case_detail_includes_linked_incidents_and_events() {
    let (port, token) = spawn_test_server();
    let (agent_id, event_ids) = setup_agent_with_events(port, &token, "case-host", 1);
    let event_id = event_ids[0];

    let incident: serde_json::Value = ureq::post(&format!("{}/api/incidents", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "title": "Case linked incident",
                "severity": "Critical",
                "event_ids": [event_id],
                "agent_ids": [agent_id],
                "summary": "linked incident for case detail"
            })
            .to_string(),
        )
        .expect("create incident")
        .into_json()
        .unwrap();
    let incident_id = incident["id"].as_u64().unwrap();

    let case: serde_json::Value = ureq::post(&format!("{}/api/cases", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "title": "Case with linked refs",
                "priority": "high",
                "description": "link incident and event",
                "incident_ids": [incident_id],
                "event_ids": [event_id],
                "tags": ["linked"]
            })
            .to_string(),
        )
        .expect("create case")
        .into_json()
        .unwrap();
    let case_id = case["id"].as_u64().unwrap();

    let detail: serde_json::Value = ureq::get(&format!("{}/api/cases/{}", base(port), case_id))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("case detail")
        .into_json()
        .unwrap();

    assert_eq!(detail["id"].as_u64().unwrap(), case_id);
    assert_eq!(detail["linked_incidents"].as_array().unwrap().len(), 1);
    assert_eq!(detail["linked_events"].as_array().unwrap().len(), 1);
    assert_eq!(
        detail["linked_incidents"][0]["id"].as_u64().unwrap(),
        incident_id
    );
    assert_eq!(detail["linked_events"][0]["id"].as_u64().unwrap(), event_id);
}

#[test]
fn timeline_endpoints_support_query_string_routing() {
    let (port, token) = spawn_test_server();
    let (agent_id, event_ids) = setup_agent_with_events(port, &token, "timeline-host", 2);
    assert_eq!(event_ids.len(), 2);

    let host_timeline: serde_json::Value = ureq::get(&format!(
        "{}/api/timeline/host?hostname=timeline-host",
        base(port)
    ))
    .set("Authorization", &auth_header(&token))
    .call()
    .expect("host timeline")
    .into_json()
    .unwrap();
    assert_eq!(host_timeline["host"].as_str().unwrap(), "timeline-host");
    assert_eq!(host_timeline["count"].as_u64().unwrap(), 2);

    let agent_timeline: serde_json::Value = ureq::get(&format!(
        "{}/api/timeline/agent?agent_id={}",
        base(port),
        agent_id
    ))
    .set("Authorization", &auth_header(&token))
    .call()
    .expect("agent timeline")
    .into_json()
    .unwrap();
    assert_eq!(agent_timeline["agent_id"].as_str().unwrap(), agent_id);
    assert_eq!(agent_timeline["count"].as_u64().unwrap(), 2);
}

#[test]
fn investigation_progress_endpoint_updates_active_snapshot() {
    let (port, token) = spawn_test_server();

    let started: serde_json::Value =
        ureq::post(&format!("{}/api/investigations/start", base(port)))
            .set("Authorization", &auth_header(&token))
            .send_json(serde_json::json!({
                "workflow_id": "credential-storm",
                "analyst": "analyst-1"
            }))
            .expect("start investigation")
            .into_json()
            .unwrap();

    let investigation_id = started["id"].as_str().expect("investigation id");
    assert!(investigation_id.starts_with("inv-"));
    assert_eq!(started["workflow_id"].as_str(), Some("credential-storm"));
    assert_eq!(started["status"].as_str(), Some("in-progress"));

    let updated: serde_json::Value =
        ureq::post(&format!("{}/api/investigations/progress", base(port)))
            .set("Authorization", &auth_header(&token))
            .send_json(serde_json::json!({
                "investigation_id": investigation_id,
                "step": 1,
                "completed": true,
                "note": "VPN telemetry reviewed",
                "finding": "Lockout pattern confirmed from single ASN"
            }))
            .expect("update investigation progress")
            .into_json()
            .unwrap();

    assert_eq!(updated["id"].as_str(), Some(investigation_id));
    assert_eq!(
        updated["notes"]["1"].as_str(),
        Some("VPN telemetry reviewed")
    );
    assert!(
        updated["completed_steps"]
            .as_array()
            .map(|items| items.iter().any(|value| value.as_u64() == Some(1)))
            .unwrap_or(false)
    );
    assert!(
        updated["findings"]
            .as_array()
            .map(|items| {
                items.iter().any(|value| {
                    value.as_str() == Some("Lockout pattern confirmed from single ASN")
                })
            })
            .unwrap_or(false)
    );
    assert!(updated["completion_percent"].as_u64().unwrap_or_default() > 0);
    assert_eq!(updated["next_step"]["order"].as_u64(), Some(2));

    let active: serde_json::Value = ureq::get(&format!("{}/api/investigations/active", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("active investigations")
        .into_json()
        .unwrap();

    let active_items = active.as_array().expect("active investigation array");
    let snapshot = active_items
        .iter()
        .find(|entry| entry["id"].as_str() == Some(investigation_id))
        .expect("active snapshot present");
    assert_eq!(
        snapshot["notes"]["1"].as_str(),
        Some("VPN telemetry reviewed")
    );
    assert_eq!(
        snapshot["workflow_name"].as_str(),
        Some("Investigate Credential Storm")
    );
}

#[test]
fn investigation_handoff_updates_linked_case_assignment_and_commentary() {
    let (port, token) = spawn_test_server();

    let case: serde_json::Value = ureq::post(&format!("{}/api/cases", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "title": "Identity escalation case",
            "priority": "high",
            "description": "Tracks credential storm investigation",
            "tags": ["identity", "handoff"]
        }))
        .expect("create case")
        .into_json()
        .unwrap();
    let case_id = case["id"].as_u64().expect("case id");

    let started: serde_json::Value =
        ureq::post(&format!("{}/api/investigations/start", base(port)))
            .set("Authorization", &auth_header(&token))
            .send_json(serde_json::json!({
                "workflow_id": "credential-storm",
                "analyst": "analyst-1",
                "case_id": case_id.to_string()
            }))
            .expect("start investigation")
            .into_json()
            .unwrap();

    let investigation_id = started["id"].as_str().expect("investigation id");
    let handed_off: serde_json::Value =
        ureq::post(&format!("{}/api/investigations/handoff", base(port)))
            .set("Authorization", &auth_header(&token))
            .send_json(serde_json::json!({
                "investigation_id": investigation_id,
                "to_analyst": "analyst-2",
                "summary": "Containment is in place but MFA bypass scope still needs confirmation.",
                "next_actions": [
                    "Confirm all targeted accounts were reset",
                    "Validate VPN source IP blocks"
                ],
                "questions": [
                    "Was any successful login followed by privilege escalation?"
                ],
                "case_id": case_id.to_string()
            }))
            .expect("handoff investigation")
            .into_json()
            .unwrap();

    assert_eq!(handed_off["status"].as_str(), Some("handoff-ready"));
    assert_eq!(handed_off["analyst"].as_str(), Some("analyst-2"));
    assert_eq!(
        handed_off["handoff"]["from_analyst"].as_str(),
        Some("analyst-1")
    );
    assert_eq!(
        handed_off["handoff"]["to_analyst"].as_str(),
        Some("analyst-2")
    );
    assert!(
        handed_off["handoff"]["next_actions"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .any(|value| value.as_str() == Some("Confirm all targeted accounts were reset"))
            })
            .unwrap_or(false)
    );

    let detail: serde_json::Value = ureq::get(&format!("{}/api/cases/{}", base(port), case_id))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("case detail")
        .into_json()
        .unwrap();

    assert_eq!(detail["assignee"].as_str(), Some("analyst-2"));
    let comments = detail["comments"].as_array().expect("case comments");
    assert!(comments.iter().any(|entry| {
        entry["text"]
            .as_str()
            .map(|text| {
                text.contains("Investigation handoff from analyst-1 to analyst-2")
                    && text.contains("Validate VPN source IP blocks")
            })
            .unwrap_or(false)
    }));
}

#[test]
fn case_handoff_packet_includes_linked_handoff_context() {
    let (port, token) = spawn_test_server();
    let (agent_id, event_ids) = setup_agent_with_events(port, &token, "handoff-packet-host", 2);
    assert_eq!(event_ids.len(), 2);

    let incident: serde_json::Value = ureq::post(&format!("{}/api/incidents", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "title": "Credential storm incident",
            "severity": "Critical",
            "event_ids": event_ids,
            "agent_ids": [agent_id],
            "summary": "Investigate suspicious auth activity on handoff-packet-host"
        }))
        .expect("create incident")
        .into_json()
        .unwrap();
    let incident_id = incident["id"].as_u64().expect("incident id");

    let case: serde_json::Value = ureq::post(&format!("{}/api/cases", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "title": "Identity escalation case",
            "priority": "high",
            "description": "Tracks credential storm investigation",
            "incident_ids": [incident_id],
            "event_ids": event_ids,
            "tags": ["identity", "handoff"]
        }))
        .expect("create case")
        .into_json()
        .unwrap();
    let case_id = case["id"].as_u64().expect("case id");

    ureq::post(&format!("{}/api/cases/{}/comment", base(port), case_id))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "author": "analyst-1",
            "text": "Escalation path validated and containment owner identified."
        }))
        .expect("add case comment");

    ureq::post(&format!("{}/api/cases/{}/evidence", base(port), case_id))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "kind": "query_result",
            "reference_id": "hunt-4242",
            "description": "Correlated VPN and Okta sign-in evidence"
        }))
        .expect("add case evidence");

    let started: serde_json::Value =
        ureq::post(&format!("{}/api/investigations/start", base(port)))
            .set("Authorization", &auth_header(&token))
            .send_json(serde_json::json!({
                "workflow_id": "credential-storm",
                "analyst": "analyst-1",
                "case_id": case_id.to_string()
            }))
            .expect("start investigation")
            .into_json()
            .unwrap();

    let investigation_id = started["id"].as_str().expect("investigation id");
    ureq::post(&format!("{}/api/investigations/handoff", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "investigation_id": investigation_id,
            "to_analyst": "analyst-2",
            "summary": "Containment is in place but MFA bypass scope still needs confirmation.",
            "next_actions": [
                "Confirm all targeted accounts were reset",
                "Validate VPN source IP blocks"
            ],
            "questions": [
                "Was any successful login followed by privilege escalation?"
            ],
            "case_id": case_id.to_string()
        }))
        .expect("handoff investigation");

    let packet: serde_json::Value = ureq::get(&format!(
        "{}/api/cases/{}/handoff-packet",
        base(port),
        case_id
    ))
    .set("Authorization", &auth_header(&token))
    .call()
    .expect("fetch handoff packet")
    .into_json()
    .unwrap();

    assert_eq!(
        packet["case"]["summary"].as_str(),
        Some("Containment is in place but MFA bypass scope still needs confirmation.")
    );
    assert_eq!(
        packet["linked_investigation"]["id"].as_str(),
        Some(investigation_id)
    );
    assert_eq!(
        packet["linked_investigation"]["status"].as_str(),
        Some("handoff-ready")
    );
    assert_eq!(
        packet["linked_investigation"]["analyst"].as_str(),
        Some("analyst-2")
    );
    assert_eq!(
        packet["next_actions"],
        serde_json::json!([
            "Confirm all targeted accounts were reset",
            "Validate VPN source IP blocks"
        ])
    );
    assert_eq!(
        packet["unresolved_questions"],
        serde_json::json!(["Was any successful login followed by privilege escalation?"])
    );
    assert_eq!(
        packet["checklist_state"]["evidence_items"].as_u64(),
        Some(1)
    );
    assert_eq!(packet["checklist_state"]["analyst_notes"].as_u64(), Some(2));
    assert_eq!(
        packet["checklist_state"]["linked_incidents"].as_u64(),
        Some(1)
    );
    assert_eq!(packet["checklist_state"]["linked_events"].as_u64(), Some(2));
    assert_eq!(packet["checklist_state"]["next_actions"].as_u64(), Some(2));
    assert_eq!(
        packet["checklist_state"]["unresolved_questions"].as_u64(),
        Some(1)
    );
    assert_eq!(
        packet["reopen_case_url"].as_str(),
        Some(format!("/soc?case={case_id}&drawer=case-workspace&casePanel=handoff#cases").as_str())
    );
}

#[test]
fn assistant_query_scope_accepts_case_incident_investigation_and_source() {
    let (port, token) = spawn_test_server();
    let (agent_id, event_ids) = setup_agent_with_events(port, &token, "assistant-scope-host", 2);

    let incident: serde_json::Value = ureq::post(&format!("{}/api/incidents", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "title": "Assistant scope incident",
            "severity": "Critical",
            "event_ids": event_ids,
            "agent_ids": [agent_id],
            "summary": "Scope parity incident"
        }))
        .expect("create assistant scope incident")
        .into_json()
        .unwrap();
    let incident_id = incident["id"].as_u64().expect("incident id");

    let case: serde_json::Value = ureq::post(&format!("{}/api/cases", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "title": "Assistant scope case",
            "priority": "high",
            "description": "Case linked to scoped incident",
            "incident_ids": [incident_id],
            "event_ids": event_ids,
            "tags": ["assistant", "scope"]
        }))
        .expect("create assistant scope case")
        .into_json()
        .unwrap();
    let case_id = case["id"].as_u64().expect("case id");

    let started: serde_json::Value =
        ureq::post(&format!("{}/api/investigations/start", base(port)))
            .set("Authorization", &auth_header(&token))
            .send_json(serde_json::json!({
                "workflow_id": "credential-storm",
                "analyst": "analyst-1",
                "case_id": case_id.to_string()
            }))
            .expect("start scoped investigation")
            .into_json()
            .unwrap();
    let investigation_id = started["id"].as_str().expect("investigation id");

    let response: serde_json::Value = ureq::post(&format!("{}/api/assistant/query", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "question": "Summarize the current investigation and cite the strongest evidence.",
            "case_id": case_id,
            "incident_id": incident_id,
            "investigation_id": investigation_id,
            "source": "case"
        }))
        .expect("assistant scoped query")
        .into_json()
        .unwrap();

    assert_eq!(response["mode"].as_str(), Some("retrieval-only"));
    assert_eq!(response["scope"]["case_id"].as_u64(), Some(case_id));
    assert_eq!(response["scope"]["incident_id"].as_u64(), Some(incident_id));
    assert_eq!(
        response["scope"]["investigation_id"].as_str(),
        Some(investigation_id)
    );
    assert_eq!(response["scope"]["source"].as_str(), Some("case"));
    assert_eq!(
        response["case_context"]["case"]["id"].as_u64(),
        Some(case_id)
    );
    assert!(
        response["citations"]
            .as_array()
            .map(|items| !items.is_empty())
            .unwrap_or(false)
    );
}

#[test]
fn assistant_query_rejects_conflicting_case_and_investigation_scope() {
    let (port, token) = spawn_test_server();

    let first_case: serde_json::Value = ureq::post(&format!("{}/api/cases", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "title": "Case A",
            "priority": "high",
            "description": "Linked to investigation",
            "tags": ["assistant", "scope"]
        }))
        .expect("create case A")
        .into_json()
        .unwrap();
    let first_case_id = first_case["id"].as_u64().expect("case A id");

    let second_case: serde_json::Value = ureq::post(&format!("{}/api/cases", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "title": "Case B",
            "priority": "medium",
            "description": "Conflicting scope case",
            "tags": ["assistant", "scope"]
        }))
        .expect("create case B")
        .into_json()
        .unwrap();
    let second_case_id = second_case["id"].as_u64().expect("case B id");

    let started: serde_json::Value =
        ureq::post(&format!("{}/api/investigations/start", base(port)))
            .set("Authorization", &auth_header(&token))
            .send_json(serde_json::json!({
                "workflow_id": "credential-storm",
                "analyst": "analyst-1",
                "case_id": first_case_id.to_string()
            }))
            .expect("start investigation with case A")
            .into_json()
            .unwrap();
    let investigation_id = started["id"].as_str().expect("investigation id");

    match ureq::post(&format!("{}/api/assistant/query", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "question": "Should we hand this off?",
            "case_id": second_case_id,
            "investigation_id": investigation_id
        })) {
        Err(ureq::Error::Status(400, response)) => {
            let body: serde_json::Value = response.into_json().expect("conflict response json");
            assert!(body["error"].as_str().is_some_and(|value| {
                value.contains("case scope conflicts with investigation scope")
            }));
        }
        Err(error) => panic!("expected assistant scope conflict, got {error}"),
        Ok(_) => panic!("assistant query unexpectedly accepted conflicting case scope"),
    }
}

#[test]
fn timeline_prefix_aliases_do_not_match_exact_routes() {
    let (port, token) = spawn_test_server();

    for path in [
        "/api/timeline/hostile?hostname=test-host",
        "/api/timeline/agentic?agent_id=test-agent",
    ] {
        match ureq::get(&format!("{}{}", base(port), path))
            .set("Authorization", &auth_header(&token))
            .call()
        {
            Err(ureq::Error::Status(404, _)) => {}
            other => panic!("expected 404 for {path}, got {other:?}"),
        }
    }
}

#[test]
fn agent_status_requires_auth() {
    let (port, token) = spawn_test_server();

    let token_resp = ureq::post(&format!("{}/api/agents/token", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "hostname": "auth-check-agent",
            "max_uses": 1
        }))
        .expect("create enrollment token");
    let enrollment_token = token_resp.into_json::<serde_json::Value>().unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();

    let enroll = ureq::post(&format!("{}/api/agents/enroll", base(port)))
        .set("Content-Type", "application/json")
        .send_string(&format!(
            r#"{{"enrollment_token":"{}","hostname":"auth-check-agent","platform":"linux","version":"1.0.0"}}"#,
            enrollment_token
        ))
        .expect("enroll agent for status auth test");
    let agent_id = enroll.into_json::<serde_json::Value>().unwrap()["agent_id"]
        .as_str()
        .unwrap()
        .to_string();

    match ureq::get(&format!("{}/api/agents/{}/status", base(port), agent_id)).call() {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401 for agent status without auth, got {other:?}"),
    }
}

#[test]
fn workbench_overview_surfaces_queue_cases_incidents_and_ready_actions() {
    let (port, token) = spawn_test_server();
    let (agent_id, event_ids) = setup_agent_with_events(port, &token, "workbench-host", 2);

    let case: serde_json::Value = ureq::post(&format!("{}/api/cases", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "title": "Workbench case",
                "priority": "critical",
                "description": "created for overview",
                "event_ids": [event_ids[0]],
                "tags": ["overview"]
            })
            .to_string(),
        )
        .expect("create workbench case")
        .into_json()
        .unwrap();
    assert!(case["id"].as_u64().unwrap() > 0);

    let incident: serde_json::Value = ureq::post(&format!("{}/api/incidents", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "title": "Workbench incident",
                "severity": "Critical",
                "event_ids": [event_ids[0]],
                "agent_ids": [agent_id],
                "summary": "created for workbench overview"
            })
            .to_string(),
        )
        .expect("create workbench incident")
        .into_json()
        .unwrap();
    assert!(incident["id"].as_u64().unwrap() > 0);

    let submitted: serde_json::Value = ureq::post(&format!("{}/api/response/request", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "action": "kill_process",
            "pid": 31337,
            "process_name": "payload.bin",
            "hostname": "workbench-host",
            "reason": "overview-ready response",
            "severity": "high",
            "requested_by": "integration-test",
        }))
        .expect("submit response request")
        .into_json()
        .unwrap();
    let request_id = submitted["request"]["id"].as_str().unwrap().to_string();
    let approver_token = create_rbac_user_token(port, &token, "workbench-approver", "admin");

    ureq::post(&format!("{}/api/response/approve", base(port)))
        .set("Authorization", &auth_header(&approver_token))
        .send_json(serde_json::json!({
            "request_id": request_id,
            "decision": "approved",
            "approver": "workbench-approver",
            "reason": "ready for overview",
        }))
        .expect("approve response request");

    let content_rule: serde_json::Value = ureq::post(&format!("{}/api/content/rules", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "title": "Workbench review rule",
            "description": "Used to validate SOC workbench review history.",
            "owner": "detections",
            "severity_mapping": "high",
            "pack_ids": ["identity-attacks"],
            "query": {
                "hostname": "workbench-host",
                "text": "test_reason",
                "limit": 100
            }
        }))
        .expect("create review rule")
        .into_json()
        .unwrap();
    let rule_id = content_rule["rule"]["metadata"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    ureq::post(&format!(
        "{}/api/content/rules/{}/test",
        base(port),
        rule_id
    ))
    .set("Authorization", &auth_header(&token))
    .call()
    .expect("test review rule");

    ureq::post(&format!("{}/api/detection/feedback", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "rule_id": rule_id,
            "analyst": "analyst-1",
            "verdict": "true_positive",
            "notes": "SOC handoff confirmed the replay noise is expected."
        }))
        .expect("record review feedback");

    let rules_catalog: serde_json::Value = ureq::get(&format!("{}/api/content/rules", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("content rules catalog")
        .into_json()
        .unwrap();
    for seed_rule_id in rules_catalog["rules"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| item["id"].as_str())
        .take(10)
    {
        ureq::post(&format!("{}/api/detection/feedback", base(port)))
            .set("Authorization", &auth_header(&token))
            .send_json(serde_json::json!({
                "rule_id": seed_rule_id,
                "analyst": "analyst-1",
                "verdict": "true_positive",
                "notes": "SOC handoff confirmed the replay noise is expected."
            }))
            .expect("seed review feedback");
    }

    let overview: serde_json::Value = ureq::get(&format!("{}/api/workbench/overview", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("workbench overview")
        .into_json()
        .unwrap();

    assert!(overview["queue"]["pending"].as_u64().unwrap() >= 2);
    assert!(overview["queue"]["items"][0]["age_secs"].is_u64());
    assert_eq!(overview["cases"]["total"].as_u64().unwrap(), 1);
    assert_eq!(overview["incidents"]["total"].as_u64().unwrap(), 1);
    assert_eq!(
        overview["response"]["ready_to_execute"].as_u64().unwrap(),
        1
    );
    assert!(overview["team_load"]["active_owners"].is_u64());
    assert!(overview["team_load"]["rebalance_hint"].is_string());
    assert!(overview["connector_impact"]["collectors_at_risk"].is_u64());
    assert!(overview["connector_impact"]["items"].is_array());
    let detection_review_item = overview["detection_review"]["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| {
            item["latest_feedback_verdict"].as_str() == Some("valid")
                && item["latest_feedback_notes"].as_str()
                    == Some("SOC handoff confirmed the replay noise is expected.")
        })
        .expect("review row with analyst history appears in workbench");
    assert!(detection_review_item["latest_replay_new_match_count"].is_u64());
    assert!(detection_review_item["latest_replay_cleared_match_count"].is_u64());
    assert!(!overview["urgent_items"].as_array().unwrap().is_empty());
}

#[test]
fn manager_overview_tracks_fleet_queue_and_deployment_health() {
    let (port, token) = spawn_test_server();
    let (agent_id, event_ids) = setup_agent_with_events(port, &token, "manager-host", 1);
    assert!(!event_ids.is_empty());

    ureq::post(&format!("{}/api/updates/publish", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "version": "9.9.9",
                "platform": "linux",
                "binary_base64": "aGVsbG8=",
                "release_notes": "manager overview release",
                "mandatory": true
            })
            .to_string(),
        )
        .expect("publish release");

    ureq::post(&format!("{}/api/updates/deploy", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "agent_id": agent_id,
                "version": "9.9.9",
                "platform": "linux",
                "rollout_group": "canary"
            })
            .to_string(),
        )
        .expect("deploy release");

    let overview: serde_json::Value = ureq::get(&format!("{}/api/manager/overview", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("manager overview")
        .into_json()
        .unwrap();

    assert_eq!(overview["fleet"]["total_agents"].as_u64().unwrap(), 1);
    assert_eq!(overview["fleet"]["online"].as_u64().unwrap(), 1);
    assert!(overview["queue"]["pending"].as_u64().unwrap() >= 1);
    assert!(
        overview["deployments"]["published_releases"]
            .as_u64()
            .unwrap()
            >= 1
    );
    assert!(overview["deployments"]["pending"].as_u64().unwrap() >= 1);
    assert!(overview["compliance"]["score"].is_number());
}

#[test]
fn agent_activity_snapshot_includes_deployment_and_event_analytics() {
    let (port, token) = spawn_test_server();
    let (agent_id, event_ids) = setup_agent_with_events(port, &token, "activity-host", 2);
    assert!(event_ids.len() >= 2);

    ureq::post(&format!("{}/api/updates/publish", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "version": "0.24.0",
                "platform": "linux",
                "binary_base64": "aGVsbG8=",
                "release_notes": "activity release",
                "mandatory": false
            })
            .to_string(),
        )
        .expect("publish release");

    ureq::post(&format!("{}/api/updates/deploy", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "agent_id": agent_id,
                "version": "0.24.0",
                "platform": "linux",
                "rollout_group": "ring-1"
            })
            .to_string(),
        )
        .expect("deploy release");

    ureq::post(&format!("{}/api/agents/{}/heartbeat", base(port), agent_id))
        .set("Content-Type", "application/json")
        .send_string(r#"{"version":"0.23.0","health":{"pending_alerts":3,"telemetry_queue_depth":1,"update_state":"downloading","update_target_version":"0.24.0"}}"#)
        .expect("heartbeat");

    let activity: serde_json::Value =
        ureq::get(&format!("{}/api/agents/{}/activity", base(port), agent_id))
            .set("Authorization", &auth_header(&token))
            .call()
            .expect("agent activity")
            .into_json()
            .unwrap();

    assert_eq!(activity["agent"]["id"].as_str().unwrap(), agent_id);
    assert_eq!(activity["computed_status"].as_str().unwrap(), "online");
    assert_eq!(
        activity["deployment"]["version"].as_str().unwrap(),
        "0.24.0"
    );
    assert_eq!(
        activity["deployment"]["rollout_group"].as_str().unwrap(),
        "ring-1"
    );
    assert_eq!(activity["health"]["pending_alerts"].as_u64().unwrap(), 3);
    assert!(activity["analytics"]["event_count"].as_u64().unwrap() >= 2);
    assert!(activity["timeline"].as_array().unwrap().len() >= 2);
}

#[test]
fn agents_summary_includes_freshness_versions_and_rollout_fields() {
    let (port, token) = spawn_test_server();
    let (agent_id, _event_ids) = setup_agent_with_events(port, &token, "summary-host", 1);

    ureq::post(&format!("{}/api/updates/publish", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "version": "1.2.3",
                "platform": "linux",
                "binary_base64": "aGVsbG8=",
                "release_notes": "summary release",
                "mandatory": false
            })
            .to_string(),
        )
        .expect("publish release");

    ureq::post(&format!("{}/api/updates/deploy", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "agent_id": agent_id,
                "version": "1.2.3",
                "platform": "linux",
                "rollout_group": "canary"
            })
            .to_string(),
        )
        .expect("deploy release");

    let agents: serde_json::Value = ureq::get(&format!("{}/api/agents", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("agent summary")
        .into_json()
        .unwrap();
    assert!(
        agents
            .as_array()
            .unwrap()
            .iter()
            .any(|agent| agent["id"] == serde_json::json!(LOCAL_CONSOLE_AGENT_ID))
    );
    let enrolled_agent = find_agent_by_id(&agents, &agent_id);
    assert_eq!(enrolled_agent["id"].as_str().unwrap(), agent_id);
    assert!(enrolled_agent["last_seen_age_secs"].is_u64());
    assert!(enrolled_agent["current_version"].is_string());
    assert_eq!(enrolled_agent["target_version"].as_str().unwrap(), "1.2.3");
    assert_eq!(enrolled_agent["rollout_group"].as_str().unwrap(), "canary");
    assert_eq!(
        enrolled_agent["deployment_status"].as_str().unwrap(),
        "assigned"
    );
    assert!(enrolled_agent["campaign_state"].as_str().is_some());
    assert!(enrolled_agent["campaign_progress"].is_object());
    assert_eq!(
        enrolled_agent["campaign_progress"]["prepared"].as_bool(),
        Some(true)
    );
}

#[test]
fn deployment_trust_report_endpoint_returns_customer_artifact_and_sections() {
    let (port, token) = spawn_test_server();
    let resp = ureq::get(&format!(
        "{}/api/release/deployment-trust-report",
        base(port)
    ))
    .set("Authorization", &auth_header(&token))
    .call()
    .expect("deployment trust report");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(body["customer_artifact"]["product_name"], "Wardex");
    assert_eq!(body["customer_artifact"]["runtime_name"], "Wardex");
    assert!(body["checks"].as_array().is_some());
    assert!(body["sections"]["verification_center"].is_object());
    assert!(body["sections"]["fleet_campaign"].is_object());
    assert!(body["evidence_freshness"].is_object());
    assert!(body["snapshot"].is_object());
}

#[test]
fn analyst_flow_links_queue_case_incident_and_response_actions() {
    let (port, token) = spawn_test_server();
    let (agent_id, event_ids) = setup_agent_with_events(port, &token, "analyst-flow-host", 1);
    let event_id = event_ids[0];

    let assign: serde_json::Value = ureq::post(&format!("{}/api/queue/assign", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "event_id": event_id,
            "assignee": "analyst-1"
        }))
        .expect("assign queue item")
        .into_json()
        .unwrap();
    assert_eq!(assign["event_id"].as_u64().unwrap_or(event_id), event_id);

    let case: serde_json::Value = ureq::post(&format!("{}/api/cases", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "title": "Analyst flow case",
                "priority": "high",
                "description": "created from queue",
                "event_ids": [event_id],
                "tags": ["analyst-flow"]
            })
            .to_string(),
        )
        .expect("create case")
        .into_json()
        .unwrap();
    let case_id = case["id"].as_u64().unwrap();

    let incident: serde_json::Value = ureq::post(&format!("{}/api/incidents", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(
            &serde_json::json!({
                "title": "Analyst flow incident",
                "severity": "Critical",
                "event_ids": [event_id],
                "agent_ids": [agent_id],
                "summary": "escalated from analyst flow"
            })
            .to_string(),
        )
        .expect("create incident")
        .into_json()
        .unwrap();
    let incident_id = incident["id"].as_u64().unwrap();

    ureq::post(&format!("{}/api/cases/{}/update", base(port), case_id))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "status": "investigating",
            "assignee": "analyst-1",
            "link_incident": incident_id
        }))
        .expect("update case");

    let submitted: serde_json::Value = ureq::post(&format!("{}/api/response/request", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "action": "kill_process",
            "pid": 9001,
            "process_name": "analyst-flow.bin",
            "hostname": "analyst-flow-host",
            "reason": "end-to-end analyst flow",
            "severity": "high",
            "requested_by": "integration-test",
        }))
        .expect("submit response request")
        .into_json()
        .unwrap();
    let request_id = submitted["request"]["id"].as_str().unwrap().to_string();
    let approver_token = create_rbac_user_token(port, &token, "analyst-flow-approver", "admin");

    ureq::post(&format!("{}/api/response/approve", base(port)))
        .set("Authorization", &auth_header(&approver_token))
        .send_json(serde_json::json!({
            "request_id": request_id,
            "decision": "approved",
            "approver": "analyst-flow-approver",
            "reason": "approved in analyst flow",
        }))
        .expect("approve response request");

    ureq::post(&format!("{}/api/response/execute", base(port)))
        .set("Authorization", &auth_header(&token))
        .send_json(serde_json::json!({
            "request_id": request_id
        }))
        .expect("execute response request");

    let detail: serde_json::Value = ureq::get(&format!("{}/api/cases/{}", base(port), case_id))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("case detail")
        .into_json()
        .unwrap();
    assert_eq!(detail["status"].as_str().unwrap(), "Investigating");
    assert_eq!(detail["linked_incidents"].as_array().unwrap().len(), 1);

    let requests: serde_json::Value = ureq::get(&format!("{}/api/response/requests", base(port)))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("response requests")
        .into_json()
        .unwrap();
    // PID 9001 on `analyst-flow-host` is not present on the test node, so the
    // node-local enforcer honestly reports failure rather than a fabricated
    // success. The flow itself (approve → execute → status transition) is
    // exercised end-to-end; "Failed" is the truthful terminal state.
    assert_eq!(
        requests["requests"][0]["status"].as_str().unwrap(),
        "Failed"
    );
}

// ── POST /api/events/bulk-triage ───────────────────────────────

#[test]
fn bulk_triage_updates_multiple_events() {
    let (port, token) = spawn_test_server();
    let (_agent_id, event_ids) = setup_agent_with_events(port, &token, "bulk-host", 3);
    assert!(event_ids.len() >= 3);

    let body = serde_json::json!({
        "event_ids": event_ids,
        "status": "investigating",
        "assignee": "analyst-1",
        "tags": ["bulk", "test"],
        "note": "bulk triage test",
        "author": "integration-test"
    });
    let resp = ureq::post(&format!("{}/api/events/bulk-triage", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(&body.to_string())
        .expect("bulk triage");
    assert_eq!(resp.status(), 200);
    let result: serde_json::Value = resp.into_json().unwrap();
    assert_eq!(result["updated"].as_u64().unwrap(), event_ids.len() as u64);
}

#[test]
fn bulk_triage_without_auth_returns_401() {
    let (port, _token) = spawn_test_server();
    let err = ureq::post(&format!("{}/api/events/bulk-triage", base(port)))
        .set("Content-Type", "application/json")
        .send_string(r#"{"event_ids":[1],"status":"acknowledged"}"#);
    match err {
        Err(ureq::Error::Status(401, _)) => {}
        other => panic!("expected 401, got {other:?}"),
    }
}

#[test]
fn bulk_triage_empty_ids_returns_400() {
    let (port, token) = spawn_test_server();
    let resp = ureq::post(&format!("{}/api/events/bulk-triage", base(port)))
        .set("Authorization", &auth_header(&token))
        .set("Content-Type", "application/json")
        .send_string(r#"{"event_ids":[],"status":"acknowledged"}"#);
    match resp {
        Err(ureq::Error::Status(400, _)) => {}
        other => panic!("expected 400, got {other:?}"),
    }
}
