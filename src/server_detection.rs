//! Detection explainability, replay corpus, and case handoff helpers.

use super::*;

fn detection_next_steps(level: &str, reasons: &[String]) -> Vec<String> {
    let mut steps = vec!["Validate the affected host, user, and process lineage.".to_string()];
    let joined = reasons.join(" ").to_ascii_lowercase();
    if joined.contains("credential") || joined.contains("brute") || joined.contains("login") {
        steps.push(
            "Review recent authentication activity and reset exposed credentials if confirmed."
                .to_string(),
        );
    }
    if joined.contains("lateral") || joined.contains("remote") || joined.contains("smb") {
        steps.push("Pivot into peer-host activity and isolate the source if lateral movement is confirmed.".to_string());
    }
    if joined.contains("ransom") || joined.contains("encrypt") {
        steps.push(
            "Quarantine the affected endpoint and inspect shadow-copy or mass-write activity."
                .to_string(),
        );
    }
    if severity_rank(level) >= 2 {
        steps.push("Escalate to containment or incident response if the activity cannot be explained quickly.".to_string());
    } else {
        steps.push("If the signal is benign, capture analyst feedback so similar noise can be suppressed safely.".to_string());
    }
    steps
}

fn risk_component(
    name: &str,
    score: f64,
    weight: f64,
    rationale: impl Into<String>,
) -> EntityRiskComponent {
    EntityRiskComponent {
        name: name.to_string(),
        score: score.clamp(0.0, 10.0),
        weight,
        rationale: rationale.into(),
    }
}

fn reason_contains_any(reasons: &[String], needles: &[&str]) -> bool {
    let joined = reasons.join(" ").to_ascii_lowercase();
    needles.iter().any(|needle| joined.contains(needle))
}

fn extract_reason_entity(reasons: &[String], prefixes: &[&str]) -> Option<String> {
    reasons
        .iter()
        .flat_map(|reason| reason.split(|c: char| c.is_whitespace() || matches!(c, ',' | ';')))
        .find_map(|token| {
            let trimmed = token.trim_matches(|c: char| {
                matches!(c, '"' | '\'' | '[' | ']' | '(' | ')' | ',' | ';')
            });
            let lower = trimmed.to_ascii_lowercase();
            prefixes.iter().find_map(|prefix| {
                lower
                    .strip_prefix(prefix)
                    .filter(|value| !value.trim().is_empty())
                    .map(|_| {
                        trimmed[prefix.len()..]
                            .trim_matches(|c: char| matches!(c, ':' | '=' | '"' | '\''))
                            .to_string()
                    })
            })
        })
        .filter(|value| !value.trim().is_empty())
}

fn detection_sequence_signals(event: &StoredEvent) -> Vec<String> {
    let mut signals = Vec::new();
    let reasons = &event.alert.reasons;
    if reason_contains_any(
        reasons,
        &["credential", "lsass", "password", "brute", "login"],
    ) {
        signals.push("Credential-access precursor observed in the detection reasons.".to_string());
    }
    if reason_contains_any(
        reasons,
        &["lateral", "remote", "smb", "rdp", "ssh", "winrm"],
    ) {
        signals.push("Lateral-movement or remote-service activity is present.".to_string());
    }
    if reason_contains_any(reasons, &["beacon", "c2", "command", "dns", "http"]) {
        signals.push("Command-and-control or beaconing context is present.".to_string());
    }
    if reason_contains_any(reasons, &["persist", "scheduled", "service", "autorun"]) {
        signals.push("Persistence behavior is part of the observed sequence.".to_string());
    }
    if reason_contains_any(reasons, &["ransom", "encrypt", "shadow", "mass_write"]) {
        signals.push("Impact-stage behavior appears in the same alert context.".to_string());
    }
    if event.correlated {
        signals.push(
            "Adjacent telemetry has already correlated this event with other activity.".to_string(),
        );
    }
    signals
}

fn detection_graph_context(event: &StoredEvent) -> Vec<String> {
    let mut context = vec![
        format!("host:{} reported the alert.", event.alert.hostname),
        format!("agent:{} supplied the telemetry.", event.agent_id),
    ];
    if !event.alert.action.trim().is_empty() {
        context.push(format!(
            "action:{} is the current behavior node.",
            event.alert.action
        ));
    }
    if let Some(destination) = extract_reason_entity(
        &event.alert.reasons,
        &[
            "dst=", "dst:", "dest=", "dest:", "domain=", "domain:", "ip=", "ip:",
        ],
    ) {
        context.push(format!(
            "network_destination:{} appears in the evidence.",
            destination
        ));
    }
    if !event.alert.mitre.is_empty() {
        context.push(format!(
            "{} MITRE technique(s) can seed a campaign graph pivot.",
            event.alert.mitre.len()
        ));
    }
    context
}

fn entity_recommended_pivots(kind: &str, id: &str) -> Vec<String> {
    match kind {
        "host" => vec![
            format!("Open host timeline for {id}."),
            "Compare this host against its platform peer group.".to_string(),
        ],
        "agent" => vec![
            format!("Check collector health and recent telemetry gaps for {id}."),
            "Pivot to correlated alerts from the same reporting agent.".to_string(),
        ],
        "process_or_action" => vec![
            format!("Search process lineage and command history for {id}."),
            "Look for the same action across peer hosts.".to_string(),
        ],
        "user" => vec![
            format!("Review authentication anomalies for {id}."),
            "Check recent privilege and lateral-movement activity for this identity.".to_string(),
        ],
        "network_destination" => vec![
            format!("Review DNS, proxy, and connection history for {id}."),
            "Check threat-intel sightings and related hosts for this destination.".to_string(),
        ],
        _ => vec!["Pivot into the case workspace with this entity selected.".to_string()],
    }
}

fn entity_score(
    kind: &str,
    id: String,
    base_score: f64,
    confidence: f64,
    peer_group: Option<String>,
    mut components: Vec<EntityRiskComponent>,
    sequence_signals: &[String],
    graph_context: &[String],
    rationale: Vec<String>,
) -> EntityRiskScore {
    if components.is_empty() {
        components.push(risk_component(
            "alert_score",
            base_score,
            1.0,
            "Risk inherits the alert score when no deeper entity evidence is available.",
        ));
    }
    EntityRiskScore {
        entity_kind: kind.to_string(),
        entity_id: id.clone(),
        score: base_score.clamp(0.0, 10.0),
        confidence: confidence.clamp(0.0, 1.0),
        rationale,
        peer_group,
        score_components: components,
        sequence_signals: sequence_signals.to_vec(),
        graph_context: graph_context.to_vec(),
        recommended_pivots: entity_recommended_pivots(kind, &id),
    }
}

fn build_entity_risk_scores(event: &StoredEvent) -> Vec<EntityRiskScore> {
    let sequence_signals = detection_sequence_signals(event);
    let graph_context = detection_graph_context(event);
    let sequence_bonus = (sequence_signals.len() as f64 * 0.35).min(1.4);
    let mitre_bonus = (event.alert.mitre.len() as f64 * 0.25).min(1.0);
    let correlation_bonus = if event.correlated { 0.8 } else { 0.0 };
    let host_score = event.alert.score as f64 + sequence_bonus + mitre_bonus + correlation_bonus;
    let peer_group = Some(format!("{} hosts", event.alert.platform));
    let mut scores = vec![entity_score(
        "host",
        event.alert.hostname.clone(),
        host_score,
        event.alert.confidence as f64,
        peer_group,
        vec![
            risk_component(
                "alert_score",
                event.alert.score as f64,
                0.55,
                format!("Detector score for this alert is {:.2}.", event.alert.score),
            ),
            risk_component(
                "sequence_context",
                sequence_bonus,
                0.2,
                format!("{} sequence signal(s) were derived from the alert reasons.", sequence_signals.len()),
            ),
            risk_component(
                "attack_mapping",
                mitre_bonus,
                0.15,
                format!("{} MITRE technique reference(s) are attached.", event.alert.mitre.len()),
            ),
            risk_component(
                "correlation",
                correlation_bonus,
                0.1,
                if event.correlated {
                    "The event is already correlated with adjacent telemetry."
                } else {
                    "No adjacent telemetry correlation has been recorded yet."
                },
            ),
        ],
        &sequence_signals,
        &graph_context,
        vec![
            format!("Alert severity is {}.", event.alert.level),
            format!("{} detection reason(s) attached to this host signal.", event.alert.reasons.len()),
            "Host risk blends direct detector score, sequence context, attack mapping, and correlation.".to_string(),
        ],
    )];
    if !event.agent_id.trim().is_empty() {
        scores.push(entity_score(
            "agent",
            event.agent_id.clone(),
            (event.alert.score as f64 * 0.9 + correlation_bonus).min(10.0),
            event.alert.confidence as f64,
            Some("reporting agents".to_string()),
            vec![
                risk_component(
                    "inherited_host_signal",
                    event.alert.score as f64 * 0.9,
                    0.75,
                    "Reporting-agent risk inherits most of the host alert score.",
                ),
                risk_component(
                    "correlation",
                    correlation_bonus,
                    0.25,
                    "Correlated agent telemetry increases confidence in the reporting source.",
                ),
            ],
            &sequence_signals,
            &graph_context,
            vec!["Entity score inherits the alert score for the reporting agent.".to_string()],
        ));
    }
    if !event.alert.action.trim().is_empty() {
        scores.push(entity_score(
            "process_or_action",
            event.alert.action.clone(),
            (event.alert.score as f64 * 0.8 + sequence_bonus).min(10.0),
            (event.alert.confidence as f64 * 0.95).min(1.0),
            Some("same-action executions".to_string()),
            vec![
                risk_component(
                    "action_frequency_proxy",
                    event.alert.score as f64 * 0.8,
                    0.65,
                    "Action-level risk is derived from the alert score and attached reasons.",
                ),
                risk_component(
                    "sequence_context",
                    sequence_bonus,
                    0.35,
                    "Multi-step attack context increases action-level priority.",
                ),
            ],
            &sequence_signals,
            &graph_context,
            vec![
                "Action-level risk is derived from the alert score and attached reasons."
                    .to_string(),
            ],
        ));
    }
    if let Some(user) = extract_reason_entity(
        &event.alert.reasons,
        &[
            "user=",
            "user:",
            "account=",
            "account:",
            "principal=",
            "principal:",
        ],
    )
    .or_else(|| {
        event
            .triage
            .assignee
            .as_deref()
            .filter(|assignee| !assignee.trim().is_empty() && *assignee != "unassigned")
            .map(str::to_string)
    }) {
        scores.push(entity_score(
            "user",
            user,
            (event.alert.score as f64 * 0.75 + sequence_bonus).min(10.0),
            (event.alert.confidence as f64 * 0.9).min(1.0),
            Some("identity peer group".to_string()),
            vec![
                risk_component(
                    "identity_signal",
                    event.alert.score as f64 * 0.75,
                    0.7,
                    "Identity risk is inferred from user/account evidence in the detection context.",
                ),
                risk_component(
                    "sequence_context",
                    sequence_bonus,
                    0.3,
                    "Credential, lateral movement, or C2 sequence evidence increases user risk.",
                ),
            ],
            &sequence_signals,
            &graph_context,
            vec!["User/entity scoring is inferred from identity tokens in the alert reasons or triage context.".to_string()],
        ));
    }
    if let Some(destination) = extract_reason_entity(
        &event.alert.reasons,
        &[
            "dst=", "dst:", "dest=", "dest:", "domain=", "domain:", "ip=", "ip:",
        ],
    ) {
        scores.push(entity_score(
            "network_destination",
            destination,
            (event.alert.score as f64 * 0.7 + if reason_contains_any(&event.alert.reasons, &["beacon", "c2", "dns", "http"]) { 1.0 } else { 0.0 }).min(10.0),
            (event.alert.confidence as f64 * 0.9).min(1.0),
            Some("network destinations".to_string()),
            vec![
                risk_component(
                    "destination_signal",
                    event.alert.score as f64 * 0.7,
                    0.65,
                    "Destination risk is inferred from network indicators attached to the alert.",
                ),
                risk_component(
                    "c2_context",
                    if reason_contains_any(&event.alert.reasons, &["beacon", "c2", "dns", "http"]) { 1.0 } else { 0.0 },
                    0.35,
                    "Beaconing, C2, DNS, or HTTP evidence increases destination priority.",
                ),
            ],
            &sequence_signals,
            &graph_context,
            vec!["Network destination scoring is inferred from destination tokens in the alert reasons.".to_string()],
        ));
    }
    scores
}

pub(super) fn build_detection_explainability(
    state: &AppState,
    event_id: Option<u64>,
    alert_id: Option<&str>,
) -> Option<DetectionExplainability> {
    let resolved_event_id =
        event_id.or_else(|| alert_id.and_then(|value| value.parse::<u64>().ok()))?;
    let event = state.event_store.get_event(resolved_event_id)?;
    let feedback = state.detection_feedback.for_event(event.id);
    let feedback_notes = feedback
        .iter()
        .map(|entry| {
            format!(
                "{} marked this as {}.",
                entry.analyst,
                entry.verdict.replace('_', " ")
            )
        })
        .collect::<Vec<_>>();
    let related_cases = state
        .case_store
        .list()
        .iter()
        .filter(|case| case.event_ids.contains(&event.id))
        .map(|case| format!("case-{}", case.id))
        .collect::<Vec<_>>();
    let mut evidence = vec![
        crate::detection_feedback::DetectionEvidence {
            kind: "score".to_string(),
            label: "Alert Score".to_string(),
            value: format!("{:.2}", event.alert.score),
            confidence: Some(event.alert.confidence),
            source: Some("detector".to_string()),
        },
        crate::detection_feedback::DetectionEvidence {
            kind: "host".to_string(),
            label: "Host".to_string(),
            value: event.alert.hostname.clone(),
            confidence: Some(event.alert.confidence),
            source: Some("telemetry".to_string()),
        },
    ];
    for reason in &event.alert.reasons {
        evidence.push(crate::detection_feedback::DetectionEvidence {
            kind: "reason".to_string(),
            label: "Detection Reason".to_string(),
            value: reason.clone(),
            confidence: Some(event.alert.confidence),
            source: Some("detector".to_string()),
        });
    }
    let evidence_chain = evidence
        .iter()
        .enumerate()
        .map(|(index, item)| {
            serde_json::json!({
                "timestamp": event.alert.timestamp,
                "sequence": index + 1,
                "signal_type": item.kind,
                "label": item.label,
                "value": item.value,
                "confidence_score": item.confidence.unwrap_or(event.alert.confidence),
                "source": item.source,
            })
        })
        .collect::<Vec<_>>();
    let matched_rules = active_rule_metadata(state)
        .iter()
        .filter(|rule| {
            let haystack = format!("{} {} {}", rule.id, rule.title, rule.description)
                .to_ascii_lowercase();
            event.alert.reasons.iter().any(|reason| {
                let normalized = reason.to_ascii_lowercase();
                normalized.contains(&rule.id.to_ascii_lowercase())
                    || normalized.contains(&rule.title.to_ascii_lowercase())
                    || rule.attack.iter().any(|attack| {
                        !attack.technique_id.is_empty()
                            && normalized.contains(&attack.technique_id.to_ascii_lowercase())
                    })
                    || haystack
                        .split_whitespace()
                        .take(4)
                        .any(|token| normalized.contains(token))
            })
        })
        .take(5)
        .map(|rule| {
            serde_json::json!({
                "rule_id": rule.id,
                "rule_name": rule.title,
                "lifecycle_stage": rule.lifecycle,
                "canary_pct": if matches!(rule.lifecycle, ContentLifecycle::Canary) { 25 } else { 100 },
                "owner": rule.owner,
            })
        })
        .collect::<Vec<_>>();
    let similar_past_alerts = state
        .event_store
        .all_events()
        .iter()
        .filter(|candidate| {
            candidate.id != event.id
                && (candidate.alert.hostname == event.alert.hostname
                    || candidate.alert.level == event.alert.level
                    || candidate.alert.reasons.iter().any(|reason| {
                        event.alert.reasons.iter().any(|current| current == reason)
                    }))
        })
        .rev()
        .take(5)
        .map(|candidate| {
            serde_json::json!({
                "event_id": candidate.id,
                "alert_id": candidate.id.to_string(),
                "timestamp": candidate.alert.timestamp,
                "hostname": candidate.alert.hostname,
                "severity": candidate.alert.level,
                "score": candidate.alert.score,
                "shared_reason": candidate.alert.reasons.iter().find(|reason| event.alert.reasons.iter().any(|current| current == *reason)),
            })
        })
        .collect::<Vec<_>>();

    let mut why_safe_or_noisy = Vec::new();
    if !feedback_notes.is_empty() {
        why_safe_or_noisy.extend(feedback_notes);
    } else if event.alert.score < 4.0 {
        why_safe_or_noisy.push(
            "This score sits near the low end of the queue, so analyst validation matters before escalating."
                .to_string(),
        );
    } else {
        why_safe_or_noisy.push(
            "No prior analyst feedback is recorded for this event, so treat the signal as unsuppressed."
                .to_string(),
        );
    }
    if related_cases.is_empty() {
        why_safe_or_noisy.push(
            "The alert is not currently linked to a case, which can indicate it is still early in triage."
                .to_string(),
        );
    }

    let mut why_fired = vec![format!(
        "The detector attached {} reason(s): {}.",
        event.alert.reasons.len(),
        event.alert.reasons.join(", ")
    )];
    why_fired.push(format!(
        "The alert scored {:.2} with {:.0}% confidence.",
        event.alert.score,
        event.alert.confidence as f64 * 100.0
    ));
    if event.correlated {
        why_fired.push(
            "The event is correlated with adjacent activity, which increases analyst confidence."
                .to_string(),
        );
    }
    if !event.alert.mitre.is_empty() {
        why_fired.push(format!(
            "Mapped MITRE ATT&CK context is present for {} technique reference(s).",
            event.alert.mitre.len()
        ));
    }

    Some(DetectionExplainability {
        event_id: Some(event.id),
        alert_id: Some(event.id.to_string()),
        severity: event.alert.level.clone(),
        title: format!("{} on {}", event.alert.action, event.alert.hostname),
        summary: vec![
            format!("{} alert from {}.", event.alert.level, event.agent_id),
            format!("Received at {}.", event.received_at),
        ],
        why_fired,
        why_safe_or_noisy,
        next_steps: detection_next_steps(&event.alert.level, &event.alert.reasons),
        evidence,
        entity_scores: build_entity_risk_scores(event),
        triage_status: Some(event.triage.status.clone()),
        related_cases,
        feedback,
        evidence_chain,
        matched_rules,
        similar_past_alerts,
    })
}

fn event_timestamp_ms(event: &StoredEvent) -> u64 {
    chrono::DateTime::parse_from_rfc3339(&event.alert.timestamp)
        .or_else(|_| chrono::DateTime::parse_from_rfc3339(&event.received_at))
        .map(|dt| dt.timestamp_millis().max(0) as u64)
        .unwrap_or(event.id.saturating_mul(1_000))
}

fn campaign_fleet_alert(event: &StoredEvent) -> crate::campaign::FleetAlert {
    crate::campaign::FleetAlert {
        alert_id: event.id.to_string(),
        hostname: event.alert.hostname.clone(),
        timestamp_ms: event_timestamp_ms(event),
        score: event.alert.score,
        level: event.alert.level.clone(),
        reasons: event.alert.reasons.clone(),
        mitre_techniques: event
            .alert
            .mitre
            .iter()
            .map(|attack| attack.technique_id.clone())
            .collect(),
    }
}

pub(super) fn build_campaign_correlation_view(events: &[StoredEvent]) -> serde_json::Value {
    let fleet_alerts = events.iter().map(campaign_fleet_alert).collect::<Vec<_>>();
    let mut detector = crate::campaign::CampaignDetector::default();
    let report = detector.detect(&fleet_alerts);
    let campaign_count = report.campaigns.len();
    let temporal_chain_count = report.temporal_chains.len();
    let temporal_chain_alerts = report
        .temporal_chains
        .iter()
        .map(|chain| chain.alert_count)
        .sum::<usize>();
    let event_by_alert_id = events
        .iter()
        .map(|event| (event.id.to_string(), event))
        .collect::<HashMap<_, _>>();
    let mut nodes: HashMap<String, serde_json::Value> = HashMap::new();
    let mut edges = Vec::new();
    let mut sequence_summaries = Vec::new();

    for campaign in &report.campaigns {
        let campaign_events = campaign
            .alert_ids
            .iter()
            .filter_map(|id| event_by_alert_id.get(id).copied())
            .collect::<Vec<_>>();
        let sequence_signals = campaign_events
            .iter()
            .flat_map(|event| detection_sequence_signals(event))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let graph_context = campaign_events
            .iter()
            .flat_map(|event| detection_graph_context(event))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let recommended_pivots = vec![
            format!("Open SOC campaigns for {}.", campaign.campaign_id),
            "Seed a hunt from the shared reasons and affected hosts.".to_string(),
            "Review entity risk for the highest-score host in the campaign.".to_string(),
        ];

        for host in &campaign.hosts {
            let host_events = campaign_events
                .iter()
                .filter(|event| event.alert.hostname.eq_ignore_ascii_case(host))
                .collect::<Vec<_>>();
            let risk_score = host_events
                .iter()
                .map(|event| event.alert.score)
                .fold(campaign.max_score, f32::max)
                * 10.0;
            nodes.insert(
                host.clone(),
                serde_json::json!({
                    "id": host,
                    "label": host,
                    "type": "host",
                    "risk_score": risk_score.min(100.0),
                    "campaign_id": campaign.campaign_id,
                    "campaign_severity": campaign.severity,
                    "sequence_signals": sequence_signals.clone(),
                }),
            );
        }

        let mut sorted_hosts = campaign.hosts.clone();
        sorted_hosts.sort();
        for pair in sorted_hosts.windows(2) {
            edges.push(serde_json::json!({
                "source": pair[0],
                "target": pair[1],
                "type": if reason_contains_any(&campaign.shared_reasons, &["lateral", "remote", "smb", "rdp", "ssh", "winrm"]) {
                    "lateral_movement"
                } else if reason_contains_any(&campaign.shared_reasons, &["credential", "login", "brute", "lsass"]) {
                    "privilege_escalation"
                } else {
                    "execution"
                },
                "weight": campaign.alert_count.min(4),
                "campaign_id": campaign.campaign_id,
                "shared_reasons": campaign.shared_reasons.clone(),
            }));
        }

        sequence_summaries.push(serde_json::json!({
            "campaign_id": campaign.campaign_id,
            "name": campaign.name,
            "severity": campaign.severity,
            "host_count": campaign.hosts.len(),
            "alert_count": campaign.alert_count,
            "max_score": campaign.max_score,
            "avg_score": campaign.avg_score,
            "shared_techniques": campaign.shared_techniques.clone(),
            "shared_reasons": campaign.shared_reasons.clone(),
            "sequence_signals": sequence_signals.clone(),
            "graph_context": graph_context.into_iter().take(8).collect::<Vec<_>>(),
            "recommended_pivots": recommended_pivots,
        }));
    }

    serde_json::json!({
        "campaigns": report.campaigns,
        "temporal_chains": report.temporal_chains,
        "summary": {
            "campaign_count": campaign_count,
            "temporal_chain_count": temporal_chain_count,
            "temporal_chain_alerts": temporal_chain_alerts,
            "total_alerts": report.total_alerts,
            "unclustered_alerts": report.unclustered_alerts,
            "fleet_coverage": report.fleet_coverage,
        },
        "sequence_summaries": sequence_summaries,
        "graph": {
            "nodes": nodes.into_values().collect::<Vec<_>>(),
            "edges": edges,
        },
    })
}

fn replay_sample(
    timestamp_ms: u64,
    cpu_load_pct: f32,
    memory_load_pct: f32,
    network_kbps: f32,
    auth_failures: u32,
    integrity_drift: f32,
    process_count: u32,
    disk_pressure_pct: f32,
) -> crate::telemetry::TelemetrySample {
    crate::telemetry::TelemetrySample {
        timestamp_ms,
        cpu_load_pct,
        memory_load_pct,
        temperature_c: 38.0 + (cpu_load_pct / 20.0).min(20.0),
        network_kbps,
        auth_failures,
        battery_pct: 86.0,
        integrity_drift,
        process_count,
        disk_pressure_pct,
    }
}

fn normalize_replay_dimension_token(value: &str) -> String {
    let mut normalized = String::new();
    let mut last_was_separator = true;
    for ch in value.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch.to_ascii_lowercase());
            last_was_separator = false;
        } else if !last_was_separator {
            normalized.push('_');
            last_was_separator = true;
        }
    }
    normalized.trim_matches('_').to_string()
}

fn normalize_replay_platform(value: Option<&str>) -> String {
    let normalized = normalize_replay_dimension_token(value.unwrap_or_default());
    if normalized.is_empty() {
        return "unspecified".to_string();
    }
    if normalized.contains("windows") || normalized == "win" {
        return "windows".to_string();
    }
    if normalized.contains("linux") {
        return "linux".to_string();
    }
    if normalized.contains("darwin") || normalized.contains("macos") || normalized == "mac" {
        return "macos".to_string();
    }
    if normalized.contains("android") {
        return "android".to_string();
    }
    if normalized.contains("ios") {
        return "ios".to_string();
    }
    normalized
}

fn infer_replay_signal_type(
    hint: &str,
    sample: &crate::telemetry::TelemetrySample,
    expected_malicious: bool,
) -> String {
    let joined = hint.to_ascii_lowercase();
    if joined.contains("credential")
        || joined.contains("identity")
        || joined.contains("login")
        || joined.contains("auth")
        || sample.auth_failures >= 8
    {
        return "identity".to_string();
    }
    if joined.contains("lateral")
        || joined.contains("remote")
        || joined.contains("smb")
        || joined.contains("rdp")
        || joined.contains("ssh")
    {
        return "lateral_movement".to_string();
    }
    if joined.contains("beacon")
        || joined.contains("c2")
        || joined.contains("dns")
        || joined.contains("http")
        || joined.contains("network")
        || sample.network_kbps >= 5_000.0
    {
        return "network".to_string();
    }
    if joined.contains("ransom")
        || joined.contains("encrypt")
        || joined.contains("shadow")
        || joined.contains("impact")
        || sample.disk_pressure_pct >= 75.0
    {
        return "impact".to_string();
    }
    if joined.contains("admin") || joined.contains("maintenance") {
        return "admin_activity".to_string();
    }
    if joined.contains("developer")
        || joined.contains("tooling")
        || joined.contains("build")
        || joined.contains("compile")
    {
        return "developer_tooling".to_string();
    }
    if sample.integrity_drift >= 0.2 {
        return "integrity".to_string();
    }
    if expected_malicious {
        "behavioral_attack".to_string()
    } else {
        "baseline_activity".to_string()
    }
}

fn normalize_replay_signal_type(
    value: Option<&str>,
    hint: &str,
    sample: &crate::telemetry::TelemetrySample,
    expected_malicious: bool,
) -> String {
    let normalized = normalize_replay_dimension_token(value.unwrap_or_default());
    if normalized.is_empty() {
        infer_replay_signal_type(hint, sample, expected_malicious)
    } else {
        normalized
    }
}

#[derive(Debug, Clone)]
pub(super) struct ReplayCorpusEntry {
    id: String,
    label: String,
    sample: crate::telemetry::TelemetrySample,
    expected_malicious: bool,
    platform: String,
    signal_type: String,
}

#[derive(Debug, Clone)]
struct ReplayCorpusEvaluation {
    id: String,
    label: String,
    platform: String,
    signal_type: String,
    expected_malicious: bool,
    predicted_malicious: bool,
    score: f32,
    confidence: f32,
    top_contributions: Vec<(String, f32)>,
}

#[derive(Debug, serde::Deserialize)]
struct ReplayCorpusPackRequest {
    name: Option<String>,
    source: Option<String>,
    limit: Option<usize>,
    threshold: Option<f32>,
    samples: Option<Vec<ReplayCorpusPackSample>>,
}

#[derive(Debug, serde::Deserialize)]
struct ReplayCorpusPackSample {
    id: Option<String>,
    label: Option<String>,
    expected: String,
    platform: Option<String>,
    signal_type: Option<String>,
    sample: crate::telemetry::TelemetrySample,
}

fn replay_corpus_samples() -> Vec<ReplayCorpusEntry> {
    vec![
        ReplayCorpusEntry {
            id: "benign_admin".to_string(),
            label: "Benign admin activity".to_string(),
            sample: replay_sample(1, 28.0, 42.0, 900.0, 1, 0.02, 58, 22.0),
            expected_malicious: false,
            platform: "linux".to_string(),
            signal_type: "admin_activity".to_string(),
        },
        ReplayCorpusEntry {
            id: "developer_tooling".to_string(),
            label: "Developer tooling".to_string(),
            sample: replay_sample(2, 46.0, 58.0, 1400.0, 0, 0.03, 96, 34.0),
            expected_malicious: false,
            platform: "macos".to_string(),
            signal_type: "developer_tooling".to_string(),
        },
        ReplayCorpusEntry {
            id: "identity_abuse".to_string(),
            label: "Identity abuse".to_string(),
            sample: replay_sample(3, 72.0, 70.0, 4200.0, 18, 0.16, 132, 44.0),
            expected_malicious: true,
            platform: "windows".to_string(),
            signal_type: "identity".to_string(),
        },
        ReplayCorpusEntry {
            id: "ransomware".to_string(),
            label: "Ransomware".to_string(),
            sample: replay_sample(4, 88.0, 82.0, 5200.0, 3, 0.38, 190, 92.0),
            expected_malicious: true,
            platform: "windows".to_string(),
            signal_type: "impact".to_string(),
        },
        ReplayCorpusEntry {
            id: "beaconing".to_string(),
            label: "Beaconing and C2".to_string(),
            sample: replay_sample(5, 64.0, 66.0, 8800.0, 4, 0.13, 118, 45.0),
            expected_malicious: true,
            platform: "linux".to_string(),
            signal_type: "network".to_string(),
        },
        ReplayCorpusEntry {
            id: "lateral_movement".to_string(),
            label: "Lateral movement".to_string(),
            sample: replay_sample(6, 78.0, 72.0, 6500.0, 10, 0.19, 160, 52.0),
            expected_malicious: true,
            platform: "linux".to_string(),
            signal_type: "lateral_movement".to_string(),
        },
    ]
}

fn replay_metric_status(precision: f32, recall: f32, false_positive_rate: f32) -> &'static str {
    if precision >= 0.7 && recall >= 0.7 && false_positive_rate <= 0.35 {
        "ready"
    } else if precision >= 0.5 && recall >= 0.5 {
        "watch"
    } else {
        "needs_tuning"
    }
}

fn replay_false_positive_rate(false_positives: usize, true_negatives: usize) -> f32 {
    if false_positives + true_negatives > 0 {
        false_positives as f32 / (false_positives + true_negatives) as f32
    } else {
        0.0
    }
}

fn evaluate_replay_corpus(
    corpus: &[ReplayCorpusEntry],
    threshold: f32,
) -> (
    crate::benchmark::BenchmarkResult,
    Vec<ReplayCorpusEvaluation>,
) {
    let mut detector = AnomalyDetector::default();
    let mut harness = crate::benchmark::BenchmarkHarness::new();
    let mut evaluations = Vec::new();

    for entry in corpus {
        let signal = detector.evaluate(&entry.sample);
        let predicted_malicious = signal.score >= threshold;
        harness.record(predicted_malicious, entry.expected_malicious);
        harness.record_contributions(&signal.contributions);
        evaluations.push(ReplayCorpusEvaluation {
            id: entry.id.clone(),
            label: entry.label.clone(),
            platform: entry.platform.clone(),
            signal_type: entry.signal_type.clone(),
            expected_malicious: entry.expected_malicious,
            predicted_malicious,
            score: signal.score,
            confidence: signal.confidence,
            top_contributions: signal
                .contributions
                .iter()
                .map(|(name, value)| ((*name).to_string(), *value))
                .collect(),
        });
    }

    (harness.result(), evaluations)
}

fn build_replay_dimension_deltas<F>(
    evaluations: &[ReplayCorpusEvaluation],
    overall: &crate::benchmark::BenchmarkResult,
    overall_false_positive_rate: f32,
    key_fn: F,
) -> Vec<serde_json::Value>
where
    F: Fn(&ReplayCorpusEvaluation) -> &str,
{
    let mut grouped = std::collections::BTreeMap::<String, Vec<&ReplayCorpusEvaluation>>::new();
    for evaluation in evaluations {
        grouped
            .entry(key_fn(evaluation).to_string())
            .or_default()
            .push(evaluation);
    }

    grouped
        .into_iter()
        .map(|(group, items)| {
            let mut harness = crate::benchmark::BenchmarkHarness::new();
            let benign_samples = items.iter().filter(|item| !item.expected_malicious).count();
            let malicious_samples = items.len() - benign_samples;
            let passed_samples = items
                .iter()
                .filter(|item| item.predicted_malicious == item.expected_malicious)
                .count();
            for item in &items {
                harness.record(item.predicted_malicious, item.expected_malicious);
            }
            let result = harness.result();
            let false_positive_rate =
                replay_false_positive_rate(result.false_positives, result.true_negatives);
            let precision_delta = result.precision - overall.precision;
            let recall_delta = result.recall - overall.recall;
            let accuracy_delta = result.accuracy - overall.accuracy;
            let false_positive_delta = false_positive_rate - overall_false_positive_rate;
            serde_json::json!({
                "group": group,
                "sample_count": items.len(),
                "malicious_samples": malicious_samples,
                "benign_samples": benign_samples,
                "passed_samples": passed_samples,
                "precision": result.precision,
                "recall": result.recall,
                "accuracy": result.accuracy,
                "false_positive_rate": false_positive_rate,
                "delta": {
                    "precision": precision_delta,
                    "recall": recall_delta,
                    "accuracy": accuracy_delta,
                    "false_positive_rate": false_positive_delta,
                },
                "needs_attention": items.len() > 1
                    && (precision_delta < -0.05
                        || recall_delta < -0.05
                        || false_positive_delta > 0.05),
                "examples": items
                    .iter()
                    .take(3)
                    .map(|item| {
                        serde_json::json!({
                            "id": item.id,
                            "label": item.label,
                            "expected": if item.expected_malicious { "malicious" } else { "benign" },
                            "predicted": if item.predicted_malicious { "malicious" } else { "benign" },
                            "score": item.score,
                        })
                    })
                    .collect::<Vec<_>>(),
            })
        })
        .collect()
}

pub(super) fn build_replay_corpus_evaluation_for(
    corpus_kind: &str,
    pack_name: &str,
    corpus: &[ReplayCorpusEntry],
    threshold: f32,
) -> serde_json::Value {
    let (result, evaluations) = evaluate_replay_corpus(corpus, threshold);
    let false_positive_rate =
        replay_false_positive_rate(result.false_positives, result.true_negatives);
    let category_results = evaluations
        .iter()
        .map(|evaluation| {
            serde_json::json!({
                "id": evaluation.id,
                "label": evaluation.label,
                "platform": evaluation.platform,
                "signal_type": evaluation.signal_type,
                "expected": if evaluation.expected_malicious { "malicious" } else { "benign" },
                "predicted": if evaluation.predicted_malicious { "malicious" } else { "benign" },
                "score": evaluation.score,
                "confidence": evaluation.confidence,
                "passed": evaluation.predicted_malicious == evaluation.expected_malicious,
                "top_contributions": evaluation
                    .top_contributions
                    .iter()
                    .take(4)
                    .map(|(name, value)| serde_json::json!({ "name": name, "value": value }))
                    .collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "corpus_kind": corpus_kind,
        "pack_name": pack_name,
        "threshold": threshold,
        "status": replay_metric_status(result.precision, result.recall, false_positive_rate),
        "summary": {
            "total_samples": result.true_positives + result.false_positives + result.true_negatives + result.false_negatives,
            "precision": result.precision,
            "recall": result.recall,
            "f1": result.f1,
            "accuracy": result.accuracy,
            "false_positive_rate": false_positive_rate,
            "true_positives": result.true_positives,
            "false_positives": result.false_positives,
            "true_negatives": result.true_negatives,
            "false_negatives": result.false_negatives,
        },
        "acceptance_targets": {
            "precision_min": 0.7,
            "recall_min": 0.7,
            "false_positive_rate_max": 0.35,
            "operator_goal": "Use replay-corpus drift before promoting detector/rule changes into broad rollout.",
        },
        "categories": category_results,
        "platform_deltas": build_replay_dimension_deltas(
            &evaluations,
            &result,
            false_positive_rate,
            |evaluation| &evaluation.platform,
        ),
        "signal_type_deltas": build_replay_dimension_deltas(
            &evaluations,
            &result,
            false_positive_rate,
            |evaluation| &evaluation.signal_type,
        ),
        "signal_contributions": result.signal_contributions,
    })
}

pub(super) fn build_replay_corpus_evaluation() -> serde_json::Value {
    let corpus = replay_corpus_samples();
    build_replay_corpus_evaluation_for("builtin", "Wardex built-in replay corpus", &corpus, 2.0)
}

pub(super) fn retained_event_replay_entries(
    events: &[StoredEvent],
    limit: usize,
    threshold: f32,
) -> Vec<ReplayCorpusEntry> {
    events
        .iter()
        .rev()
        .take(limit.min(256))
        .map(|event| ReplayCorpusEntry {
            id: format!("event-{}", event.id),
            label: format!(
                "{} on {}",
                if event.alert.action.trim().is_empty() {
                    event.alert.level.as_str()
                } else {
                    event.alert.action.as_str()
                },
                event.alert.hostname
            ),
            sample: event.alert.sample,
            expected_malicious: event.alert.score >= threshold,
            platform: normalize_replay_platform(Some(&event.alert.platform)),
            signal_type: normalize_replay_signal_type(
                None,
                &format!("{} {}", event.alert.action, event.alert.reasons.join(" ")),
                &event.alert.sample,
                event.alert.score >= threshold,
            ),
        })
        .collect()
}

fn replay_pack_threshold(value: Option<f32>) -> Result<f32, String> {
    let threshold = value.unwrap_or(2.0);
    if !threshold.is_finite() || threshold <= 0.0 {
        return Err("threshold must be a positive finite number".to_string());
    }
    Ok(threshold)
}

fn parse_custom_replay_samples(
    samples: Vec<ReplayCorpusPackSample>,
) -> Result<Vec<ReplayCorpusEntry>, String> {
    if samples.is_empty() {
        return Err("samples must not be empty".to_string());
    }
    if samples.len() > 256 {
        return Err("samples must contain at most 256 entries".to_string());
    }
    samples
        .into_iter()
        .enumerate()
        .map(|(idx, item)| {
            let expected = item.expected.trim().to_ascii_lowercase();
            let expected_malicious = match expected.as_str() {
                "malicious" | "attack" | "true_positive" | "tp" => true,
                "benign" | "clean" | "false_positive" | "fp" => false,
                _ => {
                    return Err(format!(
                        "samples[{idx}].expected must be benign or malicious"
                    ));
                }
            };
            let id = item.id.unwrap_or_else(|| format!("sample-{}", idx + 1));
            let label = item.label.unwrap_or_else(|| format!("Sample {}", idx + 1));
            let hint = format!("{id} {label}");
            Ok(ReplayCorpusEntry {
                id,
                label,
                sample: item.sample,
                expected_malicious,
                platform: normalize_replay_platform(item.platform.as_deref()),
                signal_type: normalize_replay_signal_type(
                    item.signal_type.as_deref(),
                    &hint,
                    &item.sample,
                    expected_malicious,
                ),
            })
        })
        .collect()
}

pub(super) fn parse_replay_corpus_pack(
    raw: &str,
) -> Result<(String, String, f32, Option<usize>, Vec<ReplayCorpusEntry>), String> {
    let request: ReplayCorpusPackRequest =
        serde_json::from_str(raw).map_err(|e| format!("invalid JSON: {e}"))?;
    let threshold = replay_pack_threshold(request.threshold)?;
    let source = request
        .source
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "custom".to_string());
    if source != "custom" && source != "retained_events" {
        return Err("source must be custom or retained_events".to_string());
    }
    if matches!(request.limit, Some(0)) {
        return Err("limit must be greater than zero".to_string());
    }
    let pack_name = request
        .name
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            if source == "retained_events" {
                "Retained-event replay corpus".to_string()
            } else {
                "Custom replay corpus".to_string()
            }
        });
    let entries = if source == "retained_events" {
        Vec::new()
    } else {
        parse_custom_replay_samples(request.samples.unwrap_or_default())?
    };
    Ok((source, pack_name, threshold, request.limit, entries))
}

pub(super) fn build_manager_queue_digest(state: &mut AppState) -> ManagerQueueDigest {
    state.agent_registry.refresh_staleness();
    let top_queue_items = state
        .alert_queue
        .pending()
        .into_iter()
        .map(|item| queue_alert_summary(item, &state.event_store))
        .take(6)
        .collect::<Vec<_>>();
    let queue = ManagerQueueOverview {
        pending: state
            .alert_queue
            .all()
            .iter()
            .filter(|item| !item.acknowledged)
            .count(),
        acknowledged: state
            .alert_queue
            .all()
            .iter()
            .filter(|item| item.acknowledged)
            .count(),
        assigned: state
            .alert_queue
            .all()
            .iter()
            .filter(|item| item.assignee.is_some())
            .count(),
        sla_breached: top_queue_items
            .iter()
            .filter(|item| item.sla_breached)
            .count(),
        critical_pending: state
            .alert_queue
            .all()
            .iter()
            .filter(|item| !item.acknowledged && severity_rank(&item.level) >= 3)
            .count(),
    };
    let stale_cases = state
        .case_store
        .list()
        .iter()
        .filter(|case| {
            !matches!(case.status, CaseStatus::Resolved | CaseStatus::Closed)
                && age_secs_since(&case.updated_at).unwrap_or_default() > 24 * 60 * 60
        })
        .count();
    let degraded_collectors = state
        .agent_registry
        .list()
        .iter()
        .filter(|agent| {
            let (status, _) =
                computed_agent_status(agent, state.agent_registry.heartbeat_interval());
            matches!(status.as_str(), "stale" | "offline")
        })
        .count();
    let requests = state.response_orchestrator.all_requests();
    let pending_dry_run_approvals = requests
        .iter()
        .filter(|request| request.dry_run && request.status == ApprovalStatus::Pending)
        .count();
    let ready_to_execute = requests
        .iter()
        .filter(|request| request.status == ApprovalStatus::Approved && !request.dry_run)
        .count();
    let recent_suppressions = state
        .enterprise
        .suppressions()
        .iter()
        .rev()
        .take(5)
        .map(|suppression| {
            serde_json::json!({
                "id": suppression.id,
                "name": suppression.name,
                "created_at": suppression.created_at,
                "active": suppression.is_active(),
                "justification": suppression.justification,
            })
        })
        .collect::<Vec<_>>();
    let analytics = state.event_store.analytics();
    let noisy_reasons = analytics
        .top_reasons
        .iter()
        .map(|reason| format!("{} ({})", reason.reason, reason.count))
        .collect::<Vec<_>>();
    let mut changes_since_last_shift = Vec::new();
    if queue.sla_breached > 0 {
        changes_since_last_shift.push(format!(
            "{} queue item(s) are now past SLA.",
            queue.sla_breached
        ));
    }
    if degraded_collectors > 0 {
        changes_since_last_shift.push(format!(
            "{degraded_collectors} collector(s) are stale or offline."
        ));
    }
    if stale_cases > 0 {
        changes_since_last_shift.push(format!(
            "{stale_cases} case(s) have been open without recent analyst updates."
        ));
    }
    if pending_dry_run_approvals > 0 {
        changes_since_last_shift.push(format!(
            "{pending_dry_run_approvals} dry-run response request(s) still need approval."
        ));
    }
    if changes_since_last_shift.is_empty() {
        changes_since_last_shift.push(
            "No material queue, collector, or approval drift was detected since the last manager check."
                .to_string(),
        );
    }
    let urgent_items = top_queue_items
        .iter()
        .take(3)
        .map(|item| UrgentItem {
            kind: "queue".to_string(),
            severity: if item.sla_breached {
                "Critical".to_string()
            } else {
                item.severity.clone()
            },
            title: format!("Queue item #{} on {}", item.event_id, item.hostname),
            subtitle: item.reasons.join(", "),
            reference_id: item.event_id.to_string(),
        })
        .collect::<Vec<_>>();

    ManagerQueueDigest {
        generated_at: chrono::Utc::now().to_rfc3339(),
        queue,
        stale_cases,
        degraded_collectors,
        pending_dry_run_approvals,
        ready_to_execute,
        recent_suppressions,
        noisy_reasons,
        changes_since_last_shift,
        top_queue_items,
        urgent_items,
    }
}

pub(super) fn case_linked_incidents(
    case: &crate::analyst::Case,
    incident_store: &IncidentStore,
) -> Vec<serde_json::Value> {
    case.incident_ids
        .iter()
        .filter_map(|id| incident_store.get(*id))
        .map(|incident| {
            serde_json::json!({
                "id": incident.id,
                "title": incident.title,
                "severity": incident.severity,
                "status": format!("{:?}", incident.status),
                "updated_at": incident.updated_at,
            })
        })
        .collect()
}

pub(super) fn case_linked_events(
    case: &crate::analyst::Case,
    event_store: &EventStore,
) -> Vec<serde_json::Value> {
    case.event_ids
        .iter()
        .filter_map(|id| event_store.get_event(*id))
        .map(|event| {
            serde_json::json!({
                "id": event.id,
                "agent_id": event.agent_id,
                "hostname": event.alert.hostname,
                "level": event.alert.level,
                "score": event.alert.score,
                "received_at": event.received_at,
                "reasons": event.alert.reasons,
            })
        })
        .collect()
}

fn case_closure_readiness_json(
    case: &crate::analyst::Case,
    handoff: Option<&crate::investigation::InvestigationHandoff>,
    linked_events: &[serde_json::Value],
    related_response_requests: &[&crate::response::ResponseRequest],
    related_response_audit: &[&crate::response::ResponseAuditEntry],
    related_ticket_syncs: &[crate::enterprise::TicketSyncRecord],
) -> serde_json::Value {
    let evidence_complete = !case.evidence.is_empty() || !linked_events.is_empty();
    let questions_closed = handoff
        .map(|entry| entry.questions.is_empty())
        .unwrap_or(false);
    let approval_state = related_response_requests
        .iter()
        .all(|request| !matches!(request.status, ApprovalStatus::Pending));
    let execution_result =
        related_response_requests.is_empty() || !related_response_audit.is_empty();
    let rollback_path = related_response_audit
        .iter()
        .any(|entry| !entry.reversal_path.trim().is_empty());
    let ticket_synced = !related_ticket_syncs.is_empty();
    let exportable = evidence_complete && case.comments.len() + linked_events.len() > 0;
    let checks = vec![
        (
            "evidence",
            evidence_complete,
            "Evidence or linked events attached",
        ),
        (
            "questions",
            questions_closed,
            "Open handoff questions closed",
        ),
        ("approvals", approval_state, "No pending response approvals"),
        (
            "execution",
            execution_result,
            "Execution result recorded or not required",
        ),
        (
            "rollback",
            rollback_path || related_response_requests.is_empty(),
            "Rollback path recorded",
        ),
        ("ticket", ticket_synced, "External ticket sync recorded"),
        ("export", exportable, "Handoff packet exportable"),
    ];
    let passed = checks.iter().filter(|(_, ok, _)| *ok).count();
    serde_json::json!({
        "status": if passed == checks.len() { "ready" } else { "review_required" },
        "score": ((passed as f64 / checks.len() as f64) * 100.0).round() as u64,
        "passed": passed,
        "total": checks.len(),
        "checks": checks.into_iter().map(|(id, ok, detail)| serde_json::json!({
            "id": id,
            "status": if ok { "pass" } else { "review" },
            "detail": detail,
        })).collect::<Vec<_>>(),
    })
}

pub(super) fn case_handoff_packet_json(
    case: &crate::analyst::Case,
    incident_store: &IncidentStore,
    event_store: &EventStore,
    workflow_store: &crate::investigation::WorkflowStore,
    response_requests: &[crate::response::ResponseRequest],
    response_audit: &[crate::response::ResponseAuditEntry],
    ticket_syncs: &[crate::enterprise::TicketSyncRecord],
) -> serde_json::Value {
    let linked_incidents = case_linked_incidents(case, incident_store);
    let linked_events = case_linked_events(case, event_store);
    let related_hosts = linked_events
        .iter()
        .filter_map(|event| event.get("hostname").and_then(serde_json::Value::as_str))
        .map(|host| host.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    let linked_investigation = workflow_store
        .active_snapshots()
        .into_iter()
        .find(|snapshot| snapshot.case_id.as_deref() == Some(&case.id.to_string()));
    let handoff = linked_investigation
        .as_ref()
        .and_then(|snapshot| snapshot.handoff.clone());

    let related_response_requests = response_requests
        .iter()
        .filter(|request| {
            !related_hosts.is_empty()
                && related_hosts.contains(&request.target.hostname.to_ascii_lowercase())
        })
        .collect::<Vec<_>>();
    let related_response_audit = response_audit
        .iter()
        .filter(|entry| {
            !related_hosts.is_empty()
                && related_hosts.contains(&entry.target_hostname.to_ascii_lowercase())
        })
        .collect::<Vec<_>>();
    let related_ticket_syncs = ticket_syncs
        .iter()
        .filter(|sync| {
            sync.object_kind.eq_ignore_ascii_case("case") && sync.object_id == case.id.to_string()
        })
        .cloned()
        .collect::<Vec<_>>();

    let mut response_by_status = HashMap::new();
    for request in &related_response_requests {
        *response_by_status
            .entry(format!("{:?}", request.status))
            .or_insert(0usize) += 1;
    }

    let mut timeline = vec![serde_json::json!({
        "timestamp": case.created_at,
        "kind": "case_created",
        "summary": format!("Case #{} created", case.id),
        "detail": case.title,
    })];
    timeline.extend(case.comments.iter().map(|comment| {
        serde_json::json!({
            "timestamp": comment.timestamp,
            "kind": "case_note",
            "summary": format!("Note from {}", comment.author),
            "detail": comment.text,
        })
    }));
    timeline.extend(case.evidence.iter().map(|evidence| {
        serde_json::json!({
            "timestamp": evidence.added_at,
            "kind": "evidence",
            "summary": evidence.description,
            "detail": format!("{} · {}", evidence.kind, evidence.reference_id),
        })
    }));
    timeline.extend(linked_incidents.iter().map(|incident| {
        serde_json::json!({
            "timestamp": incident.get("updated_at").cloned().unwrap_or(serde_json::Value::Null),
            "kind": "incident",
            "summary": format!("Incident #{}", incident["id"].as_u64().unwrap_or_default()),
            "detail": incident["title"].as_str().unwrap_or("Linked incident"),
        })
    }));
    timeline.extend(linked_events.iter().map(|event| {
        serde_json::json!({
            "timestamp": event.get("received_at").cloned().unwrap_or(serde_json::Value::Null),
            "kind": "event",
            "summary": format!("Event #{}", event["id"].as_u64().unwrap_or_default()),
            "detail": event["reasons"]
                .as_array()
                .map(|items| items.iter().filter_map(serde_json::Value::as_str).collect::<Vec<_>>().join(", "))
                .unwrap_or_default(),
        })
    }));
    if let Some(handoff) = &handoff {
        timeline.push(serde_json::json!({
            "timestamp": handoff.updated_at,
            "kind": "investigation_handoff",
            "summary": format!("Handoff from {} to {}", handoff.from_analyst, handoff.to_analyst),
            "detail": handoff.summary,
        }));
    }
    timeline.extend(related_response_audit.iter().map(|entry| {
        serde_json::json!({
            "timestamp": entry.timestamp,
            "kind": "response_action",
            "summary": entry.action,
            "detail": format!("{:?} on {}", entry.status, entry.target_hostname),
        })
    }));
    timeline.extend(related_ticket_syncs.iter().map(|sync| {
        serde_json::json!({
            "timestamp": sync.synced_at,
            "kind": "ticket_sync",
            "summary": format!("{} {}", sync.provider, sync.external_key),
            "detail": sync.summary,
        })
    }));
    timeline.sort_by(|left, right| {
        right["timestamp"]
            .as_str()
            .unwrap_or("")
            .cmp(left["timestamp"].as_str().unwrap_or(""))
    });

    let latest_ticket_sync = related_ticket_syncs
        .iter()
        .max_by(|left, right| left.synced_at.cmp(&right.synced_at))
        .cloned();
    let closure_readiness = case_closure_readiness_json(
        case,
        handoff.as_ref(),
        &linked_events,
        &related_response_requests,
        &related_response_audit,
        &related_ticket_syncs,
    );

    serde_json::json!({
        "case": {
            "id": case.id,
            "title": case.title,
            "status": format!("{:?}", case.status),
            "priority": format!("{:?}", case.priority),
            "assignee": case.assignee,
            "created_at": case.created_at,
            "updated_at": case.updated_at,
            "summary": if let Some(handoff) = &handoff {
                handoff.summary.clone()
            } else if !case.description.trim().is_empty() {
                case.description.clone()
            } else {
                format!("Case #{} is ready for shift handoff packaging.", case.id)
            },
        },
        "linked_investigation": linked_investigation.as_ref().map(|snapshot| serde_json::json!({
            "id": snapshot.id,
            "workflow_name": snapshot.workflow_name,
            "status": snapshot.status,
            "analyst": snapshot.analyst,
            "completion_percent": snapshot.completion_percent,
        })),
        "timeline": timeline,
        "evidence_links": case.evidence.iter().map(|evidence| serde_json::json!({
            "kind": evidence.kind,
            "reference_id": evidence.reference_id,
            "description": evidence.description,
            "added_at": evidence.added_at,
        })).collect::<Vec<_>>(),
        "unresolved_questions": handoff.as_ref().map(|entry| entry.questions.clone()).unwrap_or_default(),
        "next_actions": handoff.as_ref().map(|entry| entry.next_actions.clone()).unwrap_or_default(),
        "response_status": {
            "related_host_count": related_hosts.len(),
            "pending": response_by_status.get("Pending").copied().unwrap_or_default(),
            "approved": response_by_status.get("Approved").copied().unwrap_or_default(),
            "executed": response_by_status.get("Executed").copied().unwrap_or_default(),
            "recent_actions": related_response_audit.iter().take(5).map(|entry| serde_json::json!({
                "request_id": entry.request_id,
                "action": entry.action,
                "status": format!("{:?}", entry.status),
                "timestamp": entry.timestamp,
                "target_hostname": entry.target_hostname,
            })).collect::<Vec<_>>(),
        },
        "checklist_state": {
            "evidence_items": case.evidence.len(),
            "analyst_notes": case.comments.len(),
            "linked_incidents": case.incident_ids.len(),
            "linked_events": case.event_ids.len(),
            "mitre_techniques": case.mitre_techniques.len(),
            "next_actions": handoff.as_ref().map(|entry| entry.next_actions.len()).unwrap_or_default(),
            "unresolved_questions": handoff.as_ref().map(|entry| entry.questions.len()).unwrap_or_default(),
            "ticket_syncs": related_ticket_syncs.len(),
        },
        "closure_readiness": closure_readiness,
        "ticket_sync_result": latest_ticket_sync.as_ref().map(|sync| serde_json::json!({
            "provider": sync.provider,
            "external_key": sync.external_key,
            "status": sync.status,
            "queue_or_project": sync.queue_or_project,
            "summary": sync.summary,
            "synced_by": sync.synced_by,
            "synced_at": sync.synced_at,
        })),
        "reopen_case_url": format!("/soc?case={}&drawer=case-workspace&casePanel=handoff#cases", case.id),
    })
}
