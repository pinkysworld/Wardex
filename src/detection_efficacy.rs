//! Detection efficacy tracking.
//!
//! Tracks true positive rate, false positive rate, mean time to triage,
//! and per-rule detection quality metrics over time — providing a
//! closed-loop feedback dashboard for detection engineering.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Efficacy metrics ────────────────────────────────────────────

/// Outcome of an alert after investigation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AlertOutcome {
    TruePositive,
    FalsePositive,
    Benign,
    Inconclusive,
    Pending,
}

/// A triage record linking an alert to its outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageRecord {
    pub alert_id: String,
    pub rule_id: String,
    pub rule_name: String,
    pub severity: String,
    pub outcome: AlertOutcome,
    pub triaged_by: String,
    pub created_at_ms: u64,
    pub triaged_at_ms: u64,
    pub triage_duration_ms: u64,
    pub agent_id: Option<String>,
}

/// Per-rule detection efficacy metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleEfficacy {
    pub rule_id: String,
    pub rule_name: String,
    pub total_alerts: usize,
    pub true_positives: usize,
    pub false_positives: usize,
    pub benign: usize,
    pub inconclusive: usize,
    pub pending: usize,
    pub tp_rate: f32,
    pub fp_rate: f32,
    pub precision: f32,
    pub mean_triage_secs: f32,
    pub trend: EfficacyTrend,
}

/// Whether detection quality is improving, stable, or degrading.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EfficacyTrend {
    Improving,
    Stable,
    Degrading,
    InsufficientData,
}

/// Fleet-wide detection efficacy summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EfficacySummary {
    pub total_alerts_triaged: usize,
    pub overall_tp_rate: f32,
    pub overall_fp_rate: f32,
    pub overall_precision: f32,
    pub mean_triage_secs: f32,
    pub rules_tracked: usize,
    pub worst_rules: Vec<RuleEfficacy>,
    pub best_rules: Vec<RuleEfficacy>,
    pub by_severity: HashMap<String, SeverityEfficacy>,
}

/// Per-severity efficacy breakdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityEfficacy {
    pub total: usize,
    pub tp_rate: f32,
    pub fp_rate: f32,
    pub mean_triage_secs: f32,
}

// ── Tracker ─────────────────────────────────────────────────────

/// Detection efficacy tracker.
pub struct EfficacyTracker {
    records: Vec<TriageRecord>,
    max_records: usize,
}

impl Default for EfficacyTracker {
    fn default() -> Self {
        Self::new(100_000)
    }
}

impl EfficacyTracker {
    pub fn new(max_records: usize) -> Self {
        Self {
            records: Vec::new(),
            max_records,
        }
    }

    /// Record a triage outcome.
    pub fn record(&mut self, record: TriageRecord) {
        self.records.push(record);
        // Evict oldest if over limit
        if self.records.len() > self.max_records {
            self.records.drain(0..self.records.len() - self.max_records);
        }
    }

    /// Total triage records.
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    /// Compute per-rule efficacy.
    pub fn per_rule_efficacy(&self) -> Vec<RuleEfficacy> {
        let mut by_rule: HashMap<String, Vec<&TriageRecord>> = HashMap::new();
        for rec in &self.records {
            by_rule.entry(rec.rule_id.clone()).or_default().push(rec);
        }

        by_rule.into_iter().map(|(rule_id, records)| {
            let rule_name = records.first().map(|r| r.rule_name.clone()).unwrap_or_default();
            let total = records.len();
            let tp = records.iter().filter(|r| r.outcome == AlertOutcome::TruePositive).count();
            let fp = records.iter().filter(|r| r.outcome == AlertOutcome::FalsePositive).count();
            let benign = records.iter().filter(|r| r.outcome == AlertOutcome::Benign).count();
            let inconclusive = records.iter().filter(|r| r.outcome == AlertOutcome::Inconclusive).count();
            let pending = records.iter().filter(|r| r.outcome == AlertOutcome::Pending).count();

            let resolved = tp + fp + benign;
            let tp_rate = if resolved > 0 { tp as f32 / resolved as f32 } else { 0.0 };
            let fp_rate = if resolved > 0 { fp as f32 / resolved as f32 } else { 0.0 };
            let precision = if tp + fp > 0 { tp as f32 / (tp + fp) as f32 } else { 0.0 };

            let triage_times: Vec<f32> = records.iter()
                .filter(|r| r.outcome != AlertOutcome::Pending)
                .map(|r| r.triage_duration_ms as f32 / 1000.0)
                .collect();
            let mean_triage = if triage_times.is_empty() { 0.0 }
                else { triage_times.iter().sum::<f32>() / triage_times.len() as f32 };

            // Simple trend: compare first half vs second half FP rates
            let trend = if records.len() < 10 {
                EfficacyTrend::InsufficientData
            } else {
                let mid = records.len() / 2;
                let first_half_fp = records[..mid].iter().filter(|r| r.outcome == AlertOutcome::FalsePositive).count() as f32 / mid as f32;
                let second_half_fp = records[mid..].iter().filter(|r| r.outcome == AlertOutcome::FalsePositive).count() as f32 / (records.len() - mid) as f32;
                if second_half_fp < first_half_fp - 0.05 {
                    EfficacyTrend::Improving
                } else if second_half_fp > first_half_fp + 0.05 {
                    EfficacyTrend::Degrading
                } else {
                    EfficacyTrend::Stable
                }
            };

            RuleEfficacy {
                rule_id,
                rule_name,
                total_alerts: total,
                true_positives: tp,
                false_positives: fp,
                benign,
                inconclusive,
                pending,
                tp_rate: (tp_rate * 1000.0).round() / 1000.0,
                fp_rate: (fp_rate * 1000.0).round() / 1000.0,
                precision: (precision * 1000.0).round() / 1000.0,
                mean_triage_secs: (mean_triage * 10.0).round() / 10.0,
                trend,
            }
        }).collect()
    }

    /// Fleet-wide efficacy summary.
    pub fn summary(&self) -> EfficacySummary {
        let rules = self.per_rule_efficacy();
        let triaged: Vec<&TriageRecord> = self.records.iter()
            .filter(|r| r.outcome != AlertOutcome::Pending)
            .collect();

        let total = triaged.len();
        let tp = triaged.iter().filter(|r| r.outcome == AlertOutcome::TruePositive).count();
        let fp = triaged.iter().filter(|r| r.outcome == AlertOutcome::FalsePositive).count();
        let resolved = tp + fp + triaged.iter().filter(|r| r.outcome == AlertOutcome::Benign).count();

        let overall_tp = if resolved > 0 { tp as f32 / resolved as f32 } else { 0.0 };
        let overall_fp = if resolved > 0 { fp as f32 / resolved as f32 } else { 0.0 };
        let precision = if tp + fp > 0 { tp as f32 / (tp + fp) as f32 } else { 0.0 };

        let triage_times: Vec<f32> = triaged.iter()
            .map(|r| r.triage_duration_ms as f32 / 1000.0)
            .collect();
        let mean_triage = if triage_times.is_empty() { 0.0 }
            else { triage_times.iter().sum::<f32>() / triage_times.len() as f32 };

        // By severity
        let mut by_severity: HashMap<String, Vec<&TriageRecord>> = HashMap::new();
        for rec in &triaged {
            by_severity.entry(rec.severity.clone()).or_default().push(rec);
        }
        let sev_map: HashMap<String, SeverityEfficacy> = by_severity.into_iter().map(|(sev, recs)| {
            let s_total = recs.len();
            let s_tp = recs.iter().filter(|r| r.outcome == AlertOutcome::TruePositive).count();
            let s_fp = recs.iter().filter(|r| r.outcome == AlertOutcome::FalsePositive).count();
            let s_resolved = s_tp + s_fp + recs.iter().filter(|r| r.outcome == AlertOutcome::Benign).count();
            let s_triage: Vec<f32> = recs.iter().map(|r| r.triage_duration_ms as f32 / 1000.0).collect();
            let s_mean = if s_triage.is_empty() { 0.0 } else { s_triage.iter().sum::<f32>() / s_triage.len() as f32 };
            (sev, SeverityEfficacy {
                total: s_total,
                tp_rate: if s_resolved > 0 { s_tp as f32 / s_resolved as f32 } else { 0.0 },
                fp_rate: if s_resolved > 0 { s_fp as f32 / s_resolved as f32 } else { 0.0 },
                mean_triage_secs: (s_mean * 10.0).round() / 10.0,
            })
        }).collect();

        let mut worst: Vec<RuleEfficacy> = rules.iter()
            .filter(|r| r.total_alerts >= 5)
            .cloned()
            .collect();
        worst.sort_by(|a, b| b.fp_rate.total_cmp(&a.fp_rate));
        worst.truncate(5);

        let mut best: Vec<RuleEfficacy> = rules.iter()
            .filter(|r| r.total_alerts >= 5)
            .cloned()
            .collect();
        best.sort_by(|a, b| b.precision.total_cmp(&a.precision));
        best.truncate(5);

        EfficacySummary {
            total_alerts_triaged: total,
            overall_tp_rate: (overall_tp * 1000.0).round() / 1000.0,
            overall_fp_rate: (overall_fp * 1000.0).round() / 1000.0,
            overall_precision: (precision * 1000.0).round() / 1000.0,
            mean_triage_secs: (mean_triage * 10.0).round() / 10.0,
            rules_tracked: rules.len(),
            worst_rules: worst,
            best_rules: best,
            by_severity: sev_map,
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(rule: &str, outcome: AlertOutcome) -> TriageRecord {
        TriageRecord {
            alert_id: format!("alert-{rule}"),
            rule_id: rule.into(),
            rule_name: format!("Rule {rule}"),
            severity: "High".into(),
            outcome,
            triaged_by: "analyst".into(),
            created_at_ms: 1000,
            triaged_at_ms: 5000,
            triage_duration_ms: 4000,
            agent_id: None,
        }
    }

    #[test]
    fn tracks_outcomes() {
        let mut tracker = EfficacyTracker::default();
        tracker.record(make_record("R1", AlertOutcome::TruePositive));
        tracker.record(make_record("R1", AlertOutcome::TruePositive));
        tracker.record(make_record("R1", AlertOutcome::FalsePositive));
        let rules = tracker.per_rule_efficacy();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].true_positives, 2);
        assert_eq!(rules[0].false_positives, 1);
    }

    #[test]
    fn summary_computes() {
        let mut tracker = EfficacyTracker::default();
        for _ in 0..8 {
            tracker.record(make_record("R1", AlertOutcome::TruePositive));
        }
        for _ in 0..2 {
            tracker.record(make_record("R1", AlertOutcome::FalsePositive));
        }
        let summary = tracker.summary();
        assert!(summary.overall_tp_rate > 0.7);
        assert!(summary.overall_fp_rate < 0.3);
    }
}
