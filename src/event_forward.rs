use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::collector::AlertRecord;

/// An event batch received from an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventBatch {
    pub agent_id: String,
    pub events: Vec<AlertRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EventNote {
    pub author: String,
    pub note: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventTriage {
    pub status: String,
    pub assignee: Option<String>,
    pub tags: Vec<String>,
    pub notes: Vec<EventNote>,
    pub acknowledged_at: Option<String>,
    pub resolved_at: Option<String>,
    pub last_updated_at: String,
}

impl Default for EventTriage {
    fn default() -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            status: "new".to_string(),
            assignee: None,
            tags: Vec::new(),
            notes: Vec::new(),
            acknowledged_at: None,
            resolved_at: None,
            last_updated_at: now,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EventTriageUpdate {
    pub status: Option<String>,
    pub assignee: Option<String>,
    pub tags: Option<Vec<String>>,
    pub note: Option<String>,
    pub author: Option<String>,
}

/// A stored event with server-side metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEvent {
    pub id: u64,
    pub agent_id: String,
    pub received_at: String,
    pub alert: AlertRecord,
    pub correlated: bool,
    #[serde(default)]
    pub triage: EventTriage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EventStoreSnapshot {
    events: Vec<StoredEvent>,
    next_id: u64,
}

/// Server-side event store that receives, stores, and correlates events from multiple agents.
pub struct EventStore {
    events: Vec<StoredEvent>,
    next_id: u64,
    max_events: usize,
    store_path: Option<String>,
    /// Correlation windows: group events by (reason, time_window) across agents
    correlation_window_secs: i64,
}

impl EventStore {
    pub fn new(max_events: usize) -> Self {
        Self::new_with_path(max_events, None)
    }

    pub fn with_persistence(max_events: usize, path: impl Into<String>) -> Self {
        Self::new_with_path(max_events, Some(path.into()))
    }

    fn new_with_path(max_events: usize, store_path: Option<String>) -> Self {
        let mut store = Self {
            events: Vec::new(),
            next_id: 1,
            max_events,
            store_path,
            correlation_window_secs: 60,
        };
        store.load();
        store.trim_to_limit();
        store
    }

    fn load(&mut self) {
        let Some(path) = self.store_path.as_deref() else {
            return;
        };
        let Ok(raw) = fs::read_to_string(path) else {
            return;
        };
        let Ok(snapshot) = serde_json::from_str::<EventStoreSnapshot>(&raw) else {
            return;
        };
        self.events = snapshot.events;
        self.next_id = snapshot
            .next_id
            .max(self.events.iter().map(|event| event.id).max().unwrap_or(0) + 1);
    }

    fn persist(&self) {
        let Some(path) = self.store_path.as_deref() else {
            return;
        };
        let snapshot = EventStoreSnapshot {
            events: self.events.clone(),
            next_id: self.next_id,
        };
        if let Ok(json) = serde_json::to_string_pretty(&snapshot) {
            let path_ref = Path::new(path);
            if let Some(parent) = path_ref.parent() {
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::write(path_ref, json);
        }
    }

    fn trim_to_limit(&mut self) {
        if self.events.len() > self.max_events {
            let excess = self.events.len() - self.max_events;
            self.events.drain(0..excess);
        }
    }

    fn normalize_status(status: &str) -> Option<String> {
        match status.trim().to_ascii_lowercase().as_str() {
            "new" => Some("new".to_string()),
            "acknowledged" => Some("acknowledged".to_string()),
            "investigating" => Some("investigating".to_string()),
            "contained" => Some("contained".to_string()),
            "resolved" => Some("resolved".to_string()),
            _ => None,
        }
    }

    pub fn update_triage(&mut self, event_id: u64, update: EventTriageUpdate) -> Result<StoredEvent, String> {
        let event = self
            .events
            .iter_mut()
            .find(|event| event.id == event_id)
            .ok_or_else(|| "event not found".to_string())?;

        let now = chrono::Utc::now().to_rfc3339();
        if let Some(status) = update.status {
            let normalized = Self::normalize_status(&status)
                .ok_or_else(|| format!("invalid triage status: {status}"))?;
            event.triage.status = normalized.clone();
            if matches!(normalized.as_str(), "acknowledged" | "investigating" | "contained" | "resolved")
                && event.triage.acknowledged_at.is_none()
            {
                event.triage.acknowledged_at = Some(now.clone());
            }
            if normalized == "resolved" {
                event.triage.resolved_at = Some(now.clone());
            } else {
                event.triage.resolved_at = None;
            }
        }
        if let Some(assignee) = update.assignee {
            let trimmed = assignee.trim();
            event.triage.assignee = (!trimmed.is_empty()).then_some(trimmed.to_string());
        }
        if let Some(tags) = update.tags {
            event.triage.tags = tags
                .into_iter()
                .map(|tag| tag.trim().to_ascii_lowercase())
                .filter(|tag| !tag.is_empty())
                .collect();
            event.triage.tags.sort();
            event.triage.tags.dedup();
        }
        if let Some(note) = update.note {
            let trimmed = note.trim();
            if !trimmed.is_empty() {
                event.triage.notes.push(EventNote {
                    author: update.author.unwrap_or_else(|| "analyst".to_string()),
                    note: trimmed.to_string(),
                    created_at: now.clone(),
                });
            }
        }
        event.triage.last_updated_at = now;
        let updated = event.clone();
        self.persist();
        Ok(updated)
    }

    pub fn triage_summary(&self) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for event in &self.events {
            *counts.entry(event.triage.status.clone()).or_insert(0) += 1;
        }
        counts
    }

    /// Bulk update triage on multiple events at once.
    pub fn bulk_update_triage(&mut self, event_ids: &[u64], update: &EventTriageUpdate) -> BulkTriageResult {
        let now = chrono::Utc::now().to_rfc3339();
        let mut updated = 0u64;
        let mut failed = Vec::new();

        for &event_id in event_ids {
            let event = match self.events.iter_mut().find(|e| e.id == event_id) {
                Some(e) => e,
                None => {
                    failed.push((event_id, "event not found".to_string()));
                    continue;
                }
            };
            if let Some(ref status) = update.status {
                match Self::normalize_status(status) {
                    Some(normalized) => {
                        event.triage.status = normalized.clone();
                        if matches!(normalized.as_str(), "acknowledged" | "investigating" | "contained" | "resolved")
                            && event.triage.acknowledged_at.is_none()
                        {
                            event.triage.acknowledged_at = Some(now.clone());
                        }
                        if normalized == "resolved" {
                            event.triage.resolved_at = Some(now.clone());
                        } else {
                            event.triage.resolved_at = None;
                        }
                    }
                    None => {
                        failed.push((event_id, format!("invalid triage status: {status}")));
                        continue;
                    }
                }
            }
            if let Some(ref assignee) = update.assignee {
                let trimmed = assignee.trim();
                event.triage.assignee = (!trimmed.is_empty()).then_some(trimmed.to_string());
            }
            if let Some(ref tags) = update.tags {
                event.triage.tags = tags.iter()
                    .map(|t| t.trim().to_ascii_lowercase())
                    .filter(|t| !t.is_empty())
                    .collect();
                event.triage.tags.sort();
                event.triage.tags.dedup();
            }
            if let Some(ref note) = update.note {
                let trimmed = note.trim();
                if !trimmed.is_empty() {
                    event.triage.notes.push(EventNote {
                        author: update.author.clone().unwrap_or_else(|| "analyst".to_string()),
                        note: trimmed.to_string(),
                        created_at: now.clone(),
                    });
                }
            }
            event.triage.last_updated_at = now.clone();
            updated += 1;
        }
        self.persist();
        BulkTriageResult { updated, failed }
    }

    pub fn has_persistence(&self) -> bool {
        self.store_path.is_some()
    }

    pub fn storage_path(&self) -> Option<&str> {
        self.store_path.as_deref()
    }

    /// Return the N most recent events.
    pub fn recent_events(&self, n: usize) -> Vec<StoredEvent> {
        let start = self.events.len().saturating_sub(n);
        self.events[start..].to_vec()
    }

    /// Get event by ID.
    pub fn get_event(&self, id: u64) -> Option<&StoredEvent> {
        self.events.iter().find(|e| e.id == id)
    }

    /// Ingest a batch of events from an agent.
    pub fn ingest(&mut self, batch: &EventBatch) -> IngestResult {
        let received_at = chrono::Utc::now().to_rfc3339();
        let mut ingested = 0;

        for alert in &batch.events {
            let event = StoredEvent {
                id: self.next_id,
                agent_id: batch.agent_id.clone(),
                received_at: received_at.clone(),
                alert: alert.clone(),
                correlated: false,
                triage: EventTriage::default(),
            };
            self.next_id += 1;
            self.events.push(event);
            ingested += 1;
        }

        self.trim_to_limit();

        let correlations = self.correlate();
        self.persist();

        IngestResult {
            ingested,
            total: self.events.len(),
            correlations,
        }
    }

    /// Cross-agent correlation: detect the same anomaly pattern across multiple agents
    /// within a time window (potential lateral movement or coordinated attack).
    fn correlate(&mut self) -> Vec<CorrelationMatch> {
        let mut matches = Vec::new();
        let window = self.correlation_window_secs;

        let mut by_reason: HashMap<String, Vec<usize>> = HashMap::new();
        for (idx, event) in self.events.iter().enumerate() {
            if event.correlated {
                continue;
            }
            let primary_reason = event.alert.reasons.first().cloned().unwrap_or_default();
            if !primary_reason.is_empty() {
                by_reason.entry(primary_reason).or_default().push(idx);
            }
        }

        for (reason, indices) in &by_reason {
            if indices.len() < 2 {
                continue;
            }

            let mut agent_groups: HashMap<String, Vec<usize>> = HashMap::new();
            for &idx in indices {
                let event = &self.events[idx];
                agent_groups.entry(event.agent_id.clone()).or_default().push(idx);
            }

            if agent_groups.len() < 2 {
                continue;
            }

            let timestamps: Vec<(usize, i64)> = indices
                .iter()
                .filter_map(|&idx| {
                    chrono::DateTime::parse_from_rfc3339(&self.events[idx].received_at)
                        .ok()
                        .map(|dt| (idx, dt.timestamp()))
                })
                .collect();

            if timestamps.len() < 2 {
                continue;
            }

            let min_ts = timestamps.iter().map(|t| t.1).min().unwrap();
            let max_ts = timestamps.iter().map(|t| t.1).max().unwrap();

            if max_ts - min_ts <= window {
                let correlated_agents: Vec<String> = agent_groups.keys().cloned().collect();
                let event_ids: Vec<u64> = indices.iter().map(|&idx| self.events[idx].id).collect();

                matches.push(CorrelationMatch {
                    reason: reason.clone(),
                    agents: correlated_agents,
                    event_ids: event_ids.clone(),
                    severity: "high".into(),
                    description: format!(
                        "Cross-agent correlation: '{}' detected on {} agents within {}s window",
                        reason,
                        agent_groups.len(),
                        window,
                    ),
                });

                for &idx in indices {
                    self.events[idx].correlated = true;
                    // Escalate score for cross-agent correlation
                    let score = &mut self.events[idx].alert.score;
                    *score = (*score + 1.5).min(10.0);
                    // Re-evaluate severity level based on boosted score
                    let new_level = if *score >= 8.0 {
                        "Critical"
                    } else if *score >= 6.0 {
                        "Severe"
                    } else if *score >= 4.0 {
                        "Elevated"
                    } else {
                        "Nominal"
                    };
                    self.events[idx].alert.level = new_level.to_string();
                }
            }
        }

        matches
    }

    /// Get a reference to all stored events.
    pub fn all_events(&self) -> &[StoredEvent] {
        &self.events
    }

    /// Get all stored events, optionally filtered by agent_id.
    pub fn list(&self, agent_id: Option<&str>, limit: usize) -> Vec<&StoredEvent> {
        let iter = self.events.iter().rev();
        match agent_id {
            Some(id) => iter.filter(|event| event.agent_id == id).take(limit).collect(),
            None => iter.take(limit).collect(),
        }
    }

    /// Get correlation matches from the most recent correlation pass.
    pub fn recent_correlations(&self) -> Vec<CorrelationMatch> {
        let mut by_reason: HashMap<String, Vec<&StoredEvent>> = HashMap::new();
        for event in &self.events {
            if event.correlated {
                let reason = event.alert.reasons.first().cloned().unwrap_or_default();
                by_reason.entry(reason).or_default().push(event);
            }
        }

        let mut matches = Vec::new();
        for (reason, events) in &by_reason {
            let mut agents: Vec<String> = events.iter().map(|event| event.agent_id.clone()).collect();
            agents.sort();
            agents.dedup();
            if agents.len() >= 2 {
                matches.push(CorrelationMatch {
                    reason: reason.clone(),
                    agents,
                    event_ids: events.iter().map(|event| event.id).collect(),
                    severity: "high".into(),
                    description: format!("Cross-agent pattern: '{}'", reason),
                });
            }
        }
        matches
    }

    pub fn total_events(&self) -> usize {
        self.events.len()
    }

    pub fn analytics(&self) -> EventAnalytics {
        let total_events = self.events.len();
        let correlated_events = self.events.iter().filter(|event| event.correlated).count();

        let mut severity_counts: HashMap<String, usize> = HashMap::new();
        let mut triage_counts: HashMap<String, usize> = HashMap::new();
        let mut reason_counts: HashMap<String, usize> = HashMap::new();
        let mut per_agent: HashMap<String, Vec<&StoredEvent>> = HashMap::new();

        for event in &self.events {
            let level = event.alert.level.to_ascii_lowercase();
            *severity_counts.entry(level).or_insert(0) += 1;
            *triage_counts.entry(event.triage.status.clone()).or_insert(0) += 1;

            for reason in &event.alert.reasons {
                *reason_counts.entry(reason.clone()).or_insert(0) += 1;
            }

            per_agent.entry(event.agent_id.clone()).or_default().push(event);
        }

        let mut top_reasons: Vec<TopReason> = reason_counts
            .into_iter()
            .map(|(reason, count)| TopReason { reason, count })
            .collect();
        top_reasons.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.reason.cmp(&b.reason)));
        top_reasons.truncate(5);

        let mut hot_agents: Vec<AgentRiskSummary> = per_agent
            .into_iter()
            .map(|(agent_id, events)| {
                let event_count = events.len();
                let correlated_count = events.iter().filter(|event| event.correlated).count();
                let critical_count = events
                    .iter()
                    .filter(|event| severity_rank(&event.alert.level) >= 3)
                    .count();
                let average_score = if event_count > 0 {
                    events.iter().map(|event| event.alert.score).sum::<f32>() / event_count as f32
                } else {
                    0.0
                };
                let max_score = events
                    .iter()
                    .map(|event| event.alert.score)
                    .fold(0.0f32, f32::max);
                let max_rank = events
                    .iter()
                    .map(|event| severity_rank(&event.alert.level))
                    .max()
                    .unwrap_or(0);

                AgentRiskSummary {
                    agent_id,
                    event_count,
                    correlated_count,
                    critical_count,
                    max_score,
                    average_score,
                    highest_level: severity_label(max_rank).to_string(),
                    risk: risk_label(max_rank, average_score, correlated_count).to_string(),
                }
            })
            .collect();
        hot_agents.sort_by(|a, b| {
            severity_rank(&b.risk)
                .cmp(&severity_rank(&a.risk))
                .then_with(|| b.correlated_count.cmp(&a.correlated_count))
                .then_with(|| b.max_score.total_cmp(&a.max_score))
        });
        hot_agents.truncate(5);

        EventAnalytics {
            total_events,
            correlated_events,
            correlation_rate: if total_events > 0 {
                correlated_events as f32 / total_events as f32
            } else {
                0.0
            },
            severity_counts,
            triage_counts,
            top_reasons,
            hot_agents,
        }
    }

    pub fn clear(&mut self) {
        self.events.clear();
        self.next_id = 1;
        self.persist();
    }

    /// Return the total number of stored events.
    pub fn count(&self) -> usize {
        self.events.len()
    }

    /// Trim events to at most `max` entries, removing oldest first.
    /// Returns the number of events removed.
    pub fn apply_retention(&mut self, max: usize) -> usize {
        if self.events.len() <= max {
            return 0;
        }
        let trim = self.events.len() - max;
        self.events.drain(..trim);
        self.persist();
        trim
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestResult {
    pub ingested: usize,
    pub total: usize,
    pub correlations: Vec<CorrelationMatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkTriageResult {
    pub updated: u64,
    pub failed: Vec<(u64, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationMatch {
    pub reason: String,
    pub agents: Vec<String>,
    pub event_ids: Vec<u64>,
    pub severity: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopReason {
    pub reason: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRiskSummary {
    pub agent_id: String,
    pub event_count: usize,
    pub correlated_count: usize,
    pub critical_count: usize,
    pub max_score: f32,
    pub average_score: f32,
    pub highest_level: String,
    pub risk: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventAnalytics {
    pub total_events: usize,
    pub correlated_events: usize,
    pub correlation_rate: f32,
    pub severity_counts: HashMap<String, usize>,
    pub triage_counts: HashMap<String, usize>,
    pub top_reasons: Vec<TopReason>,
    pub hot_agents: Vec<AgentRiskSummary>,
}

fn severity_rank(level: &str) -> u8 {
    match level.to_ascii_lowercase().as_str() {
        "critical" => 3,
        "severe" => 2,
        "elevated" => 1,
        _ => 0,
    }
}

fn severity_label(rank: u8) -> &'static str {
    match rank {
        3 => "Critical",
        2 => "Severe",
        1 => "Elevated",
        _ => "Nominal",
    }
}

fn risk_label(max_rank: u8, average_score: f32, correlated_count: usize) -> &'static str {
    if max_rank >= 3 || correlated_count >= 2 {
        "Critical"
    } else if max_rank >= 2 || average_score >= 6.0 {
        "Severe"
    } else if max_rank >= 1 || average_score >= 4.0 {
        "Elevated"
    } else {
        "Nominal"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::TelemetrySample;

    fn make_alert(reasons: &[&str]) -> AlertRecord {
        AlertRecord {
            timestamp: chrono::Utc::now().to_rfc3339(),
            hostname: "test".into(),
            platform: "linux".into(),
            score: 5.0,
            confidence: 0.9,
            level: "critical".into(),
            action: "isolate".into(),
            reasons: reasons.iter().map(|reason| reason.to_string()).collect(),
            sample: TelemetrySample {
                timestamp_ms: 0,
                cpu_load_pct: 0.0,
                memory_load_pct: 0.0,
                temperature_c: 0.0,
                network_kbps: 0.0,
                auth_failures: 0,
                battery_pct: 100.0,
                integrity_drift: 0.0,
                process_count: 0,
                disk_pressure_pct: 0.0,
            },
            enforced: false,
            mitre: vec![],
        }
    }

    #[test]
    fn ingest_stores_events() {
        let mut store = EventStore::new(100);
        let batch = EventBatch {
            agent_id: "agent-1".into(),
            events: vec![make_alert(&["high_cpu"])],
        };
        let result = store.ingest(&batch);
        assert_eq!(result.ingested, 1);
        assert_eq!(result.total, 1);
    }

    #[test]
    fn cross_agent_correlation() {
        let mut store = EventStore::new(100);

        let batch1 = EventBatch {
            agent_id: "agent-1".into(),
            events: vec![make_alert(&["high_cpu"])],
        };
        store.ingest(&batch1);

        let batch2 = EventBatch {
            agent_id: "agent-2".into(),
            events: vec![make_alert(&["high_cpu"])],
        };
        let result = store.ingest(&batch2);

        assert!(!result.correlations.is_empty());
        assert_eq!(result.correlations[0].agents.len(), 2);
    }

    #[test]
    fn max_events_trimming() {
        let mut store = EventStore::new(5);
        for i in 0..10 {
            let batch = EventBatch {
                agent_id: format!("agent-{}", i % 3),
                events: vec![make_alert(&["test"])],
            };
            store.ingest(&batch);
        }
        assert!(store.total_events() <= 5);
    }

    #[test]
    fn list_filters_by_agent() {
        let mut store = EventStore::new(100);
        let batch1 = EventBatch {
            agent_id: "agent-1".into(),
            events: vec![make_alert(&["x"]), make_alert(&["y"])],
        };
        let batch2 = EventBatch {
            agent_id: "agent-2".into(),
            events: vec![make_alert(&["z"])],
        };
        store.ingest(&batch1);
        store.ingest(&batch2);

        assert_eq!(store.list(Some("agent-1"), 10).len(), 2);
        assert_eq!(store.list(Some("agent-2"), 10).len(), 1);
        assert_eq!(store.list(None, 10).len(), 3);
    }

    #[test]
    fn triage_updates_status_and_notes() {
        let mut store = EventStore::new(100);
        store.ingest(&EventBatch {
            agent_id: "agent-1".into(),
            events: vec![make_alert(&["high_cpu"])],
        });

        let updated = store
            .update_triage(
                1,
                EventTriageUpdate {
                    status: Some("investigating".into()),
                    assignee: Some("alice".into()),
                    tags: Some(vec!["cpu".into(), "urgent".into()]),
                    note: Some("Escalated to SOC".into()),
                    author: Some("ops".into()),
                },
            )
            .expect("update triage");

        assert_eq!(updated.triage.status, "investigating");
        assert_eq!(updated.triage.assignee.as_deref(), Some("alice"));
        assert_eq!(updated.triage.notes.len(), 1);
        assert!(updated.triage.acknowledged_at.is_some());
    }

    #[test]
    fn triage_rejects_unknown_status() {
        let mut store = EventStore::new(100);
        store.ingest(&EventBatch {
            agent_id: "agent-1".into(),
            events: vec![make_alert(&["high_cpu"])],
        });

        let err = store
            .update_triage(
                1,
                EventTriageUpdate {
                    status: Some("queued".into()),
                    ..EventTriageUpdate::default()
                },
            )
            .expect_err("unknown triage status should fail");

        assert!(err.contains("invalid triage status"));
    }

    #[test]
    fn analytics_summarizes_reasons_and_hot_agents() {
        let mut store = EventStore::new(100);
        store.ingest(&EventBatch {
            agent_id: "agent-1".into(),
            events: vec![make_alert(&["high_cpu"]), make_alert(&["high_cpu"])],
        });
        store.ingest(&EventBatch {
            agent_id: "agent-2".into(),
            events: vec![make_alert(&["high_cpu"]), make_alert(&["auth_spike"])],
        });

        let analytics = store.analytics();
        assert_eq!(analytics.total_events, 4);
        assert!(!analytics.top_reasons.is_empty());
        assert_eq!(analytics.top_reasons[0].reason, "high_cpu");
        assert!(analytics.hot_agents.iter().any(|agent| agent.agent_id == "agent-1"));
        assert_eq!(analytics.triage_counts.get("new").copied().unwrap_or(0), 4);
    }
}