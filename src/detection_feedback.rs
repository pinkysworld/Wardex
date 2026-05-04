use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DetectionEvidence {
    pub kind: String,
    pub label: String,
    pub value: String,
    #[serde(default)]
    pub confidence: Option<f32>,
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionFeedback {
    pub id: u64,
    #[serde(default)]
    pub event_id: Option<u64>,
    #[serde(default)]
    pub alert_id: Option<String>,
    #[serde(default)]
    pub rule_id: Option<String>,
    pub analyst: String,
    pub verdict: String,
    #[serde(default)]
    pub reason_pattern: Option<String>,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub evidence: Vec<DetectionEvidence>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DetectionFeedbackSummary {
    pub total: usize,
    pub by_verdict: HashMap<String, usize>,
    pub analysts: usize,
}

pub struct DetectionFeedbackStore {
    entries: Vec<DetectionFeedback>,
    next_id: u64,
    store_path: String,
}

impl DetectionFeedbackStore {
    pub fn new(store_path: &str) -> Self {
        let safe_path = if let Some(parent) = Path::new(store_path).parent() {
            let _ = std::fs::create_dir_all(parent);
            match parent.canonicalize() {
                Ok(canon) => canon
                    .join(Path::new(store_path).file_name().unwrap_or_default())
                    .to_string_lossy()
                    .to_string(),
                Err(_) => store_path.to_string(),
            }
        } else {
            store_path.to_string()
        };
        let mut store = Self {
            entries: Vec::new(),
            next_id: 1,
            store_path: safe_path,
        };
        store.load();
        store
    }

    fn load(&mut self) {
        let path = Path::new(&self.store_path);
        if path.exists()
            && let Ok(content) = std::fs::read_to_string(path)
            && let Ok(entries) = serde_json::from_str::<Vec<DetectionFeedback>>(&content)
        {
            self.next_id = entries
                .iter()
                .map(|entry| entry.id)
                .max()
                .unwrap_or(0)
                .saturating_add(1);
            self.entries = entries;
        }
    }

    fn persist(&self) {
        let path = Path::new(&self.store_path);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(&self.entries) {
            let tmp = format!("{}.tmp", self.store_path);
            if std::fs::write(&tmp, &json).is_ok()
                && let Err(error) = std::fs::rename(&tmp, path)
            {
                eprintln!("[WARN] detection feedback persist rename failed: {error}");
            }
        }
    }

    pub fn record(
        &mut self,
        event_id: Option<u64>,
        alert_id: Option<String>,
        rule_id: Option<String>,
        analyst: String,
        verdict: String,
        reason_pattern: Option<String>,
        notes: String,
        evidence: Vec<DetectionEvidence>,
    ) -> DetectionFeedback {
        let entry = DetectionFeedback {
            id: self.next_id,
            event_id,
            alert_id,
            rule_id,
            analyst,
            verdict,
            reason_pattern,
            notes,
            evidence,
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        self.next_id += 1;
        self.entries.push(entry.clone());
        self.persist();
        entry
    }

    pub fn list(&self) -> &[DetectionFeedback] {
        &self.entries
    }

    pub fn list_recent(&self, limit: usize) -> Vec<DetectionFeedback> {
        self.entries.iter().rev().take(limit).cloned().collect()
    }

    pub fn for_event(&self, event_id: u64) -> Vec<DetectionFeedback> {
        self.entries
            .iter()
            .filter(|entry| entry.event_id == Some(event_id))
            .cloned()
            .collect()
    }

    pub fn for_rule(&self, rule_id: &str) -> Vec<DetectionFeedback> {
        self.entries
            .iter()
            .filter(|entry| entry.rule_id.as_deref() == Some(rule_id))
            .cloned()
            .collect()
    }

    pub fn summary(&self) -> DetectionFeedbackSummary {
        let mut by_verdict = HashMap::new();
        let mut analysts = std::collections::HashSet::new();
        for entry in &self.entries {
            *by_verdict.entry(entry.verdict.clone()).or_insert(0) += 1;
            analysts.insert(entry.analyst.clone());
        }
        DetectionFeedbackSummary {
            total: self.entries.len(),
            by_verdict,
            analysts: analysts.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store_path(name: &str) -> String {
        format!(
            "/tmp/wardex_detection_feedback_{}_{}.json",
            name,
            std::process::id()
        )
    }

    #[test]
    fn feedback_store_records_and_filters_entries() {
        let path = temp_store_path("record");
        let _ = std::fs::remove_file(&path);
        let mut store = DetectionFeedbackStore::new(&path);
        let entry = store.record(
            Some(42),
            Some("42".to_string()),
            Some("rule-1".to_string()),
            "analyst-1".to_string(),
            "true_positive".to_string(),
            Some("credential dump".to_string()),
            "confirmed by analyst".to_string(),
            vec![DetectionEvidence {
                kind: "reason".to_string(),
                label: "Rule".to_string(),
                value: "credential dump".to_string(),
                confidence: Some(0.9),
                source: Some("detector".to_string()),
            }],
        );
        assert_eq!(entry.id, 1);
        assert_eq!(store.list().len(), 1);
        assert_eq!(store.for_event(42).len(), 1);
        assert_eq!(store.for_rule("rule-1").len(), 1);

        let summary = store.summary();
        assert_eq!(summary.total, 1);
        assert_eq!(summary.by_verdict.get("true_positive"), Some(&1));

        let _ = std::fs::remove_file(&path);
    }
}
