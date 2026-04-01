use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::collector::AlertRecord;

/// An event batch received from an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventBatch {
    pub agent_id: String,
    pub events: Vec<AlertRecord>,
}

/// A stored event with server-side metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEvent {
    pub id: u64,
    pub agent_id: String,
    pub received_at: String,
    pub alert: AlertRecord,
    pub correlated: bool,
}

/// Server-side event store that receives, stores, and correlates events from multiple agents.
pub struct EventStore {
    events: Vec<StoredEvent>,
    next_id: u64,
    max_events: usize,
    /// Correlation windows: group events by (reason, time_window) across agents
    correlation_window_secs: i64,
}

impl EventStore {
    pub fn new(max_events: usize) -> Self {
        Self {
            events: Vec::new(),
            next_id: 1,
            max_events,
            correlation_window_secs: 60,
        }
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
            };
            self.next_id += 1;
            self.events.push(event);
            ingested += 1;
        }

        // Trim oldest if over limit
        while self.events.len() > self.max_events {
            self.events.remove(0);
        }

        // Run cross-agent correlation
        let correlations = self.correlate();

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

        // Group uncorrelated events by primary reason
        let mut by_reason: HashMap<String, Vec<usize>> = HashMap::new();
        for (idx, event) in self.events.iter().enumerate() {
            if event.correlated {
                continue;
            }
            let primary_reason = event
                .alert
                .reasons
                .first()
                .cloned()
                .unwrap_or_default();
            if !primary_reason.is_empty() {
                by_reason
                    .entry(primary_reason)
                    .or_default()
                    .push(idx);
            }
        }

        // For each reason group, find events from different agents within the time window
        for (reason, indices) in &by_reason {
            if indices.len() < 2 {
                continue;
            }

            let mut agent_groups: HashMap<String, Vec<usize>> = HashMap::new();
            for &idx in indices {
                let event = &self.events[idx];
                agent_groups
                    .entry(event.agent_id.clone())
                    .or_default()
                    .push(idx);
            }

            // Need events from at least 2 different agents
            if agent_groups.len() < 2 {
                continue;
            }

            // Check time proximity
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
                let event_ids: Vec<u64> = indices
                    .iter()
                    .map(|&idx| self.events[idx].id)
                    .collect();

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

                // Mark events as correlated
                for &idx in indices {
                    self.events[idx].correlated = true;
                }
            }
        }

        matches
    }

    /// Get all stored events, optionally filtered by agent_id.
    pub fn list(&self, agent_id: Option<&str>, limit: usize) -> Vec<&StoredEvent> {
        let iter = self.events.iter().rev();
        match agent_id {
            Some(id) => iter.filter(|e| e.agent_id == id).take(limit).collect(),
            None => iter.take(limit).collect(),
        }
    }

    /// Get correlation matches from the most recent correlation pass.
    pub fn recent_correlations(&self) -> Vec<CorrelationMatch> {
        // Re-run correlation on current data without modifying state
        let mut by_reason: HashMap<String, Vec<&StoredEvent>> = HashMap::new();
        for event in &self.events {
            if event.correlated {
                let reason = event.alert.reasons.first().cloned().unwrap_or_default();
                by_reason.entry(reason).or_default().push(event);
            }
        }

        let mut matches = Vec::new();
        for (reason, events) in &by_reason {
            let mut agents: Vec<String> = events.iter().map(|e| e.agent_id.clone()).collect();
            agents.sort();
            agents.dedup();
            if agents.len() >= 2 {
                matches.push(CorrelationMatch {
                    reason: reason.clone(),
                    agents,
                    event_ids: events.iter().map(|e| e.id).collect(),
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
        let mut reason_counts: HashMap<String, usize> = HashMap::new();
        let mut per_agent: HashMap<String, Vec<&StoredEvent>> = HashMap::new();

        for event in &self.events {
            let level = event.alert.level.to_ascii_lowercase();
            *severity_counts.entry(level).or_insert(0) += 1;

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
            top_reasons,
            hot_agents,
        }
    }

    pub fn clear(&mut self) {
        self.events.clear();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestResult {
    pub ingested: usize,
    pub total: usize,
    pub correlations: Vec<CorrelationMatch>,
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
    } else if max_rank >= 2 || average_score >= 3.0 {
        "Severe"
    } else if max_rank >= 1 || average_score >= 1.5 {
        "Elevated"
    } else {
        "Nominal"
    }
}

// ── Tests ────────────────────────────────────────────────────────────

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
            reasons: reasons.iter().map(|s| s.to_string()).collect(),
            sample: TelemetrySample {
                timestamp_ms: 0, cpu_load_pct: 0.0, memory_load_pct: 0.0,
                temperature_c: 0.0, network_kbps: 0.0, auth_failures: 0,
                battery_pct: 100.0, integrity_drift: 0.0,
                process_count: 0, disk_pressure_pct: 0.0,
            },
            enforced: false,
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

        // Agent 1 reports high_cpu
        let batch1 = EventBatch {
            agent_id: "agent-1".into(),
            events: vec![make_alert(&["high_cpu"])],
        };
        store.ingest(&batch1);

        // Agent 2 reports same reason within window
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
    }
}
