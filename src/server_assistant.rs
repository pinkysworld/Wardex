//! Assistant request/response shaping and retrieval helpers.

use super::*;

#[derive(Debug, Clone, serde::Deserialize)]
pub(super) struct AssistantQueryRequest {
    pub(super) question: String,
    #[serde(default)]
    pub(super) case_id: Option<u64>,
    #[serde(default)]
    pub(super) incident_id: Option<u64>,
    #[serde(default)]
    pub(super) investigation_id: Option<String>,
    #[serde(default)]
    pub(super) source: Option<String>,
    #[serde(default)]
    pub(super) conversation_id: Option<String>,
    #[serde(default)]
    pub(super) context_filter: Option<crate::llm_analyst::ContextFilter>,
    #[serde(default)]
    pub(super) limit: Option<usize>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct AssistantCaseContext {
    pub(super) case: crate::analyst::Case,
    pub(super) linked_events: Vec<crate::llm_analyst::ContextEvent>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct AssistantScopeContext {
    pub(super) case_id: Option<u64>,
    pub(super) incident_id: Option<u64>,
    pub(super) investigation_id: Option<String>,
    pub(super) source: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct AssistantStatusResponse {
    enabled: bool,
    provider: String,
    model: String,
    has_api_key: bool,
    active_conversations: usize,
    endpoint: String,
    mode: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct AssistantQueryResponse {
    pub(super) answer: String,
    pub(super) structured: AssistantStructuredOutput,
    pub(super) citations: Vec<crate::llm_analyst::Citation>,
    pub(super) confidence: f32,
    pub(super) model_used: String,
    pub(super) tokens_used: crate::llm_analyst::TokenUsage,
    pub(super) response_time_ms: u64,
    pub(super) conversation_id: String,
    pub(super) mode: String,
    pub(super) scope: AssistantScopeContext,
    pub(super) case_context: Option<AssistantCaseContext>,
    pub(super) context_events: Vec<crate::llm_analyst::ContextEvent>,
    pub(super) warnings: Vec<String>,
    pub(super) quality_gates: Vec<AssistantQualityGate>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct AssistantStructuredOutput {
    summary: String,
    strongest_evidence: Vec<String>,
    open_questions: Vec<String>,
    recommended_pivots: Vec<String>,
    draft_hunt: Option<String>,
    draft_ticket: Option<String>,
    draft_handoff: Option<String>,
    not_ready_reason: Option<String>,
    approval_state: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(super) struct AssistantQualityGate {
    id: String,
    status: String,
    detail: String,
}

const ASSISTANT_STOP_WORDS: &[&str] = &[
    "a", "an", "and", "are", "case", "does", "for", "from", "have", "how", "into", "need", "show",
    "that", "the", "this", "what", "when", "where", "with", "why",
];

fn assistant_provider_from_env(value: &str) -> crate::llm_analyst::LlmProvider {
    match value.trim().to_ascii_lowercase().as_str() {
        "azure" | "azure-openai" | "azure_openai" => crate::llm_analyst::LlmProvider::AzureOpenAi,
        "anthropic" => crate::llm_analyst::LlmProvider::Anthropic,
        "ollama" => crate::llm_analyst::LlmProvider::Ollama,
        "custom" => crate::llm_analyst::LlmProvider::Custom,
        _ => crate::llm_analyst::LlmProvider::OpenAi,
    }
}

pub(super) fn load_llm_analyst_from_env() -> crate::llm_analyst::LlmAnalyst {
    let mut config = crate::llm_analyst::LlmConfig::default();

    if let Ok(value) = std::env::var("WARDEX_ASSISTANT_PROVIDER") {
        config.provider = assistant_provider_from_env(&value);
    }
    if let Ok(value) = std::env::var("WARDEX_ASSISTANT_ENDPOINT")
        && !value.trim().is_empty()
    {
        config.api_endpoint = value;
    }
    if let Ok(value) = std::env::var("WARDEX_ASSISTANT_API_KEY") {
        config.api_key = value;
    }
    if let Ok(value) = std::env::var("WARDEX_ASSISTANT_MODEL")
        && !value.trim().is_empty()
    {
        config.model = value;
    }
    if let Ok(value) = std::env::var("WARDEX_ASSISTANT_SYSTEM_PROMPT")
        && !value.trim().is_empty()
    {
        config.system_prompt = Some(value);
    }
    if let Ok(value) = std::env::var("WARDEX_ASSISTANT_MAX_CONTEXT_EVENTS")
        && let Ok(parsed) = value.parse::<usize>()
        && parsed > 0
    {
        config.max_context_events = parsed.min(50);
    }

    config.enabled = std::env::var("WARDEX_ASSISTANT_ENABLED")
        .ok()
        .and_then(|value| parse_bool_query(&value))
        .unwrap_or(!config.api_key.is_empty());

    crate::llm_analyst::LlmAnalyst::new(config)
}

pub(super) fn assistant_mode(status: &crate::llm_analyst::LlmStatus) -> String {
    if status.enabled && status.has_api_key {
        "llm".to_string()
    } else {
        "retrieval-only".to_string()
    }
}

pub(super) fn assistant_status_response(
    status: &crate::llm_analyst::LlmStatus,
) -> AssistantStatusResponse {
    AssistantStatusResponse {
        enabled: status.enabled,
        provider: status.provider.clone(),
        model: status.model.clone(),
        has_api_key: status.has_api_key,
        active_conversations: status.active_conversations,
        endpoint: status.endpoint.clone(),
        mode: assistant_mode(status),
    }
}

fn assistant_level_rank(level: &str) -> u8 {
    match level.trim().to_ascii_lowercase().as_str() {
        "critical" => 5,
        "severe" | "high" => 4,
        "elevated" | "medium" => 3,
        "warning" | "low" => 2,
        _ => 1,
    }
}

pub(super) fn assistant_normalize_optional(value: Option<String>) -> Option<String> {
    value.and_then(|entry| {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn assistant_event_summary(event: &StoredEvent) -> String {
    let reasons = if event.alert.reasons.is_empty() {
        event.alert.action.clone()
    } else {
        event.alert.reasons.join("; ")
    };
    format!(
        "{} on {} (score {:.1}, action {})",
        reasons, event.alert.hostname, event.alert.score, event.alert.action
    )
}

fn assistant_context_event(
    event: &StoredEvent,
    relevance: f32,
) -> crate::llm_analyst::ContextEvent {
    crate::llm_analyst::ContextEvent {
        id: event.id.to_string(),
        event_type: if event.alert.score >= 5.0 {
            "alert".to_string()
        } else {
            "event".to_string()
        },
        summary: assistant_event_summary(event),
        severity: event.alert.level.clone(),
        timestamp: event.alert.timestamp.clone(),
        device: Some(event.alert.hostname.clone()),
        raw_data: None,
        relevance,
    }
}

fn assistant_matches_filter(
    event: &StoredEvent,
    filter: Option<&crate::llm_analyst::ContextFilter>,
) -> bool {
    let Some(filter) = filter else {
        return true;
    };

    if let Some(hours) = filter.time_range_hours
        && let Ok(timestamp) = chrono::DateTime::parse_from_rfc3339(&event.alert.timestamp)
    {
        let threshold = chrono::Utc::now() - chrono::Duration::hours(hours.min(24 * 365) as i64);
        if timestamp.with_timezone(&chrono::Utc) < threshold {
            return false;
        }
    }

    if let Some(severity) = filter.severity_min.as_deref()
        && assistant_level_rank(&event.alert.level) < assistant_level_rank(severity)
    {
        return false;
    }

    if let Some(device_filter) = filter.device_filter.as_deref() {
        let needle = device_filter.to_ascii_lowercase();
        if !event.alert.hostname.to_ascii_lowercase().contains(&needle)
            && !event.agent_id.to_ascii_lowercase().contains(&needle)
        {
            return false;
        }
    }

    if let Some(alert_types) = filter.alert_types.as_ref()
        && !alert_types.is_empty()
    {
        let haystack = format!(
            "{} {}",
            event.alert.action.to_ascii_lowercase(),
            event.alert.reasons.join(" ").to_ascii_lowercase()
        );
        if !alert_types
            .iter()
            .map(|value| value.trim().to_ascii_lowercase())
            .any(|needle| !needle.is_empty() && haystack.contains(&needle))
        {
            return false;
        }
    }

    true
}

fn assistant_terms(question: &str, case: Option<&crate::analyst::Case>) -> Vec<String> {
    let mut terms = BTreeSet::new();
    let mut push_terms = |value: &str| {
        for term in value
            .split(|ch: char| !ch.is_ascii_alphanumeric())
            .map(|entry| entry.trim().to_ascii_lowercase())
            .filter(|entry| entry.len() >= 3 && !ASSISTANT_STOP_WORDS.contains(&entry.as_str()))
        {
            terms.insert(term);
        }
    };

    push_terms(question);
    if let Some(case) = case {
        push_terms(&case.title);
        push_terms(&case.description);
        for tag in &case.tags {
            push_terms(tag);
        }
        for technique in &case.mitre_techniques {
            push_terms(technique);
        }
    }

    terms.into_iter().collect()
}

pub(super) fn assistant_linked_events_by_ids(
    event_ids: &[u64],
    event_store: &EventStore,
    limit: usize,
) -> Vec<crate::llm_analyst::ContextEvent> {
    let mut linked: Vec<_> = event_ids
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(|id| event_store.get_event(id))
        .map(|event| {
            assistant_context_event(event, (0.3 + (event.alert.score / 15.0)).clamp(0.4, 0.99))
        })
        .collect();
    linked.sort_by(|left, right| {
        right
            .relevance
            .partial_cmp(&left.relevance)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| right.timestamp.cmp(&left.timestamp))
    });
    linked.truncate(limit);
    linked
}

pub(super) fn assistant_context_events(
    event_store: &EventStore,
    request: &AssistantQueryRequest,
    case: Option<&crate::analyst::Case>,
    linked_events: &[crate::llm_analyst::ContextEvent],
    scope_event_ids: Option<&HashSet<u64>>,
) -> Vec<crate::llm_analyst::ContextEvent> {
    let limit = request.limit.unwrap_or(8).clamp(1, 20);
    let linked_ids: HashSet<u64> = linked_events
        .iter()
        .filter_map(|event| event.id.parse::<u64>().ok())
        .collect();
    let terms = assistant_terms(&request.question, case);
    let mut context = linked_events
        .iter()
        .take(limit)
        .cloned()
        .collect::<Vec<_>>();
    if context.len() >= limit {
        return context;
    }

    let mut candidates: Vec<_> = event_store
        .all_events()
        .iter()
        .filter(|event| !linked_ids.contains(&event.id))
        .filter(|event| scope_event_ids.is_none_or(|ids| ids.contains(&event.id)))
        .filter(|event| assistant_matches_filter(event, request.context_filter.as_ref()))
        .filter_map(|event| {
            let haystack = format!(
                "{} {} {} {} {} {}",
                event.agent_id,
                event.alert.hostname,
                event.alert.level,
                event.alert.action,
                event.alert.reasons.join(" "),
                event.triage.tags.join(" ")
            )
            .to_ascii_lowercase();
            let match_count = terms
                .iter()
                .filter(|term| haystack.contains(term.as_str()))
                .count();
            if !terms.is_empty() && match_count == 0 {
                return None;
            }

            let relevance = if terms.is_empty() {
                (event.alert.score / 10.0).clamp(0.1, 0.85)
            } else {
                ((match_count as f32 * 0.2) + (event.alert.score / 10.0)).clamp(0.1, 1.0)
            };

            Some(assistant_context_event(event, relevance))
        })
        .collect();
    candidates.sort_by(|left, right| {
        right
            .relevance
            .partial_cmp(&left.relevance)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| right.timestamp.cmp(&left.timestamp))
    });
    candidates.truncate(limit.saturating_sub(context.len()));
    context.extend(candidates);
    context
}

fn assistant_fallback_answer(
    case_context: Option<&AssistantCaseContext>,
    context_events: &[crate::llm_analyst::ContextEvent],
) -> String {
    let mut sections = Vec::new();

    if let Some(context) = case_context {
        let mut summary = format!(
            "Case #{} {} is currently {:?} with {:?} priority",
            context.case.id, context.case.title, context.case.status, context.case.priority
        );
        if let Some(assignee) = context.case.assignee.as_deref() {
            summary.push_str(&format!(", assigned to {assignee}."));
        } else {
            summary.push('.');
        }
        sections.push(summary);

        if !context.case.tags.is_empty() {
            sections.push(format!("Tags: {}.", context.case.tags.join(", ")));
        }
        if let Some(comment) = context.case.comments.last() {
            sections.push(format!(
                "Latest analyst note from {}: {}.",
                comment.author, comment.text
            ));
        }
    }

    if let Some(primary) = context_events.first() {
        sections.push(format!(
            "Primary supporting evidence is {} {} on {} at {}. {}.",
            primary.event_type,
            primary.id,
            primary.device.as_deref().unwrap_or("unknown host"),
            primary.timestamp,
            primary.summary
        ));
    } else {
        sections.push("No retained events matched the current assistant scope.".to_string());
    }

    if context_events.len() > 1 {
        sections.push(format!(
            "{} additional cited event(s) reinforce this context.",
            context_events.len().saturating_sub(1)
        ));
    }

    let mut answer = sections.join("\n\n");
    answer.push_str("\n\nRecommended next steps:\n");
    if case_context.is_some() {
        answer.push_str("- Review linked case comments and evidence before handoff.\n");
    }
    if let Some(primary) = context_events.first() {
        answer.push_str(&format!(
            "- Pivot on cited source {} and host {} in the SOC workbench.\n",
            primary.id,
            primary.device.as_deref().unwrap_or("unknown host")
        ));
    }
    answer
        .push_str("- Use the citations below when escalating or syncing to an external ticket.\n");
    answer
}

pub(super) fn assistant_structured_output(
    answer: &str,
    case_context: Option<&AssistantCaseContext>,
    context_events: &[crate::llm_analyst::ContextEvent],
    citations: &[crate::llm_analyst::Citation],
    confidence: f32,
) -> AssistantStructuredOutput {
    let summary = answer
        .lines()
        .find(|line| !line.trim().is_empty())
        .map_or_else(
            || "No assistant summary was produced.".to_string(),
            |line| line.trim().trim_start_matches(['-', '*', ' ']).to_string(),
        );
    let strongest_evidence = citations
        .iter()
        .take(3)
        .map(|citation| {
            format!(
                "{} {}: {}",
                citation.source_type, citation.source_id, citation.summary
            )
        })
        .collect::<Vec<_>>();
    let mut open_questions = Vec::new();
    if citations.is_empty() {
        open_questions
            .push("Which retained event or case artifact should anchor this answer?".to_string());
    }
    if confidence < 0.5 {
        open_questions
            .push("Is there additional evidence that can raise answer confidence?".to_string());
    }
    if let Some(context) = case_context
        && context
            .case
            .assignee
            .as_deref()
            .unwrap_or("")
            .trim()
            .is_empty()
    {
        open_questions.push("Who owns the next investigation step for this case?".to_string());
    }
    let recommended_pivots = context_events
        .iter()
        .take(3)
        .map(|event| {
            format!(
                "Pivot on {} {} in SOC Workbench",
                event.event_type, event.id
            )
        })
        .collect::<Vec<_>>();
    let draft_hunt = context_events.first().map(|event| {
        format!(
            "Search for related {} activity on {} around {}",
            event.event_type,
            event.device.as_deref().unwrap_or("the affected host"),
            event.timestamp
        )
    });
    let draft_ticket = case_context.map(|context| {
        format!(
            "Case #{} {}: {} cited evidence item(s), {} open question(s).",
            context.case.id,
            context.case.title,
            citations.len(),
            open_questions.len()
        )
    });
    let draft_handoff = case_context.map(|context| {
        format!(
            "Handoff case #{} with {} linked event(s), latest summary: {}",
            context.case.id,
            context.linked_events.len(),
            summary
        )
    });
    AssistantStructuredOutput {
        summary,
        strongest_evidence,
        open_questions,
        recommended_pivots,
        draft_hunt,
        draft_ticket,
        draft_handoff,
        not_ready_reason: if citations.is_empty() || confidence < 0.5 {
            Some("Answer needs stronger cited evidence before response execution.".to_string())
        } else {
            None
        },
        approval_state: "assistant_suggestion_only_no_execution".to_string(),
    }
}

pub(super) fn assistant_response_from_fallback(
    request: &AssistantQueryRequest,
    scope: AssistantScopeContext,
    case_context: Option<AssistantCaseContext>,
    context_events: Vec<crate::llm_analyst::ContextEvent>,
    warnings: Vec<String>,
    response_time_ms: u64,
) -> AssistantQueryResponse {
    let citations = context_events
        .iter()
        .take(5)
        .map(|event| crate::llm_analyst::Citation {
            source_type: event.event_type.clone(),
            source_id: event.id.clone(),
            summary: event.summary.clone(),
            relevance_score: event.relevance,
        })
        .collect::<Vec<_>>();
    let confidence = if citations.is_empty() {
        0.2
    } else {
        (0.35 + (citations.len() as f32 * 0.1)).min(0.85)
    };

    let quality_gates = assistant_quality_gates(&citations, confidence, "retrieval-only");

    let answer = assistant_fallback_answer(case_context.as_ref(), &context_events);
    let structured = assistant_structured_output(
        &answer,
        case_context.as_ref(),
        &context_events,
        &citations,
        confidence,
    );

    AssistantQueryResponse {
        answer,
        structured,
        citations,
        confidence,
        model_used: "retrieval-only".to_string(),
        tokens_used: crate::llm_analyst::TokenUsage {
            prompt_tokens: 0,
            completion_tokens: 0,
            total_tokens: 0,
        },
        response_time_ms,
        conversation_id: request.conversation_id.clone().unwrap_or_else(|| {
            format!(
                "local-{}",
                chrono::Utc::now().timestamp_millis().unsigned_abs()
            )
        }),
        mode: "retrieval-only".to_string(),
        scope,
        case_context,
        context_events,
        warnings,
        quality_gates,
    }
}

pub(super) fn assistant_quality_gates(
    citations: &[crate::llm_analyst::Citation],
    confidence: f32,
    mode: &str,
) -> Vec<AssistantQualityGate> {
    vec![
        AssistantQualityGate {
            id: "citation_required".into(),
            status: if citations.is_empty() {
                "review".into()
            } else {
                "pass".into()
            },
            detail: if citations.is_empty() {
                "answer has no cited source evidence".into()
            } else {
                format!("{} cited source(s) attached", citations.len())
            },
        },
        AssistantQualityGate {
            id: "confidence_floor".into(),
            status: if confidence >= 0.5 {
                "pass".into()
            } else {
                "review".into()
            },
            detail: format!("{:.0}% answer confidence", confidence * 100.0),
        },
        AssistantQualityGate {
            id: "execution_boundary".into(),
            status: "pass".into(),
            detail: format!("{mode} mode cannot execute response actions"),
        },
    ]
}
