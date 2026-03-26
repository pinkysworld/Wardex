use serde::Serialize;
use std::fs;
use std::path::Path;

use crate::runtime::RunResult;

#[derive(Debug, Clone, Serialize)]
pub struct ForensicBundle {
    pub generated_at: String,
    pub total_samples: usize,
    pub alert_count: usize,
    pub critical_count: usize,
    pub average_score: f32,
    pub max_score: f32,
    pub audit_records: Vec<ForensicAuditEntry>,
    pub checkpoints: Vec<ForensicCheckpointEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ForensicAuditEntry {
    pub sequence: usize,
    pub category: String,
    pub summary: String,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ForensicCheckpointEntry {
    pub after_sequence: usize,
    pub cumulative_hash: String,
    pub signature: String,
}

impl ForensicBundle {
    pub fn from_run_result(result: &RunResult) -> Self {
        let audit_records = result
            .audit
            .records()
            .iter()
            .map(|r| ForensicAuditEntry {
                sequence: r.sequence,
                category: r.category.clone(),
                summary: r.summary.clone(),
                hash: r.current_hash.clone(),
            })
            .collect();

        let checkpoints = result
            .audit
            .checkpoints()
            .iter()
            .map(|cp| ForensicCheckpointEntry {
                after_sequence: cp.after_sequence,
                cumulative_hash: cp.cumulative_hash.clone(),
                signature: cp.signature.clone(),
            })
            .collect();

        Self {
            generated_at: chrono::Utc::now().to_rfc3339(),
            total_samples: result.summary.total_samples,
            alert_count: result.summary.alert_count,
            critical_count: result.summary.critical_count,
            average_score: result.summary.average_score,
            max_score: result.summary.max_score,
            audit_records,
            checkpoints,
        }
    }

    pub fn write_to_path(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create bundle directory: {e}"))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("failed to serialize forensic bundle: {e}"))?;
        fs::write(path, json).map_err(|e| format!("failed to write forensic bundle: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::ForensicBundle;
    use crate::runtime::{demo_samples, execute};

    #[test]
    fn bundle_captures_audit_records() {
        let result = execute(&demo_samples());
        let bundle = ForensicBundle::from_run_result(&result);

        assert_eq!(bundle.total_samples, 5);
        assert!(!bundle.audit_records.is_empty());
        assert!(bundle.max_score > 4.0);
    }

    #[test]
    fn bundle_serializes_to_json() {
        let result = execute(&demo_samples());
        let bundle = ForensicBundle::from_run_result(&result);
        let json = serde_json::to_string_pretty(&bundle).unwrap();

        assert!(json.contains("audit_records"));
        assert!(json.contains("checkpoints"));
        assert!(json.contains("generated_at"));
    }
}
