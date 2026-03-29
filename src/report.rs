use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::runtime::{RunResult, RunSummary};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonSampleEntry {
    pub index: usize,
    pub timestamp_ms: u64,
    pub score: f32,
    pub confidence: f32,
    pub suspicious_axes: usize,
    pub level: String,
    pub action: String,
    pub isolation_pct: u8,
    pub reasons: Vec<String>,
    pub rationale: String,
    /// Per-signal attribution (T080). Each entry is (signal_name, contribution).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub contributions: Vec<(String, f32)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonSummary {
    pub total_samples: usize,
    pub alert_count: usize,
    pub critical_count: usize,
    pub average_score: f32,
    pub max_score: f32,
}

impl From<&RunSummary> for JsonSummary {
    fn from(s: &RunSummary) -> Self {
        Self {
            total_samples: s.total_samples,
            alert_count: s.alert_count,
            critical_count: s.critical_count,
            average_score: s.average_score,
            max_score: s.max_score,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonReport {
    pub generated_at: String,
    pub summary: JsonSummary,
    pub samples: Vec<JsonSampleEntry>,
}

impl JsonReport {
    pub fn from_run_result(result: &RunResult) -> Self {
        let samples = result
            .reports
            .iter()
            .map(|r| JsonSampleEntry {
                index: r.index,
                timestamp_ms: r.sample.timestamp_ms,
                score: r.signal.score,
                confidence: r.signal.confidence,
                suspicious_axes: r.signal.suspicious_axes,
                level: r.decision.level.as_str().to_string(),
                action: r.decision.action.as_str().to_string(),
                isolation_pct: r.decision.isolation_pct,
                reasons: r.signal.reasons.clone(),
                rationale: r.decision.rationale.clone(),
                contributions: r
                    .signal
                    .contributions
                    .iter()
                    .map(|(name, val)| (name.to_string(), *val))
                    .collect(),
            })
            .collect();

        Self {
            generated_at: chrono::Utc::now().to_rfc3339(),
            summary: JsonSummary::from(&result.summary),
            samples,
        }
    }

    pub fn write_to_path(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create report directory: {e}"))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("failed to serialize report: {e}"))?;
        fs::write(path, json).map_err(|e| format!("failed to write report: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::JsonReport;
    use crate::runtime::{demo_samples, execute};

    #[test]
    fn from_run_result_produces_report() {
        let result = execute(&demo_samples());
        let report = JsonReport::from_run_result(&result);

        assert_eq!(report.summary.total_samples, 5);
        assert_eq!(report.samples.len(), 5);
        assert!(report.summary.max_score > 4.0);
    }

    #[test]
    fn report_serializes_to_json() {
        let result = execute(&demo_samples());
        let report = JsonReport::from_run_result(&result);
        let json = serde_json::to_string_pretty(&report).unwrap();

        assert!(json.contains("total_samples"));
        assert!(json.contains("generated_at"));
    }
}
