use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::runtime::{RunResult, RunSummary};
use crate::incident::{Incident, IncidentStore};
use crate::event_forward::EventStore;
use crate::telemetry::MitreAttack;

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
     .replace('\'', "&#x27;")
}

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

    pub fn to_html(&self) -> String {
        let mut html = String::from(r#"<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Wardex Report</title>
<style>
body{font-family:-apple-system,sans-serif;background:#0f172a;color:#e2e8f0;margin:2rem;}
h1{color:#60a5fa;}table{border-collapse:collapse;width:100%;margin:1rem 0;}
th,td{border:1px solid #334155;padding:8px;text-align:left;}
th{background:#1e293b;color:#93c5fd;}
.critical{color:#ef4444;font-weight:bold;}.severe{color:#f97316;}.elevated{color:#eab308;}
.card{background:#1e293b;border-radius:8px;padding:1rem;margin:0.5rem;display:inline-block;min-width:150px;}
.card h3{margin:0;color:#94a3b8;font-size:0.8rem;}.card p{margin:0.3rem 0 0;font-size:1.5rem;color:#60a5fa;}
</style></head><body>
"#);
        html.push_str(&format!("<h1>Wardex Security Report</h1><p>Generated: {}</p>", self.generated_at));
        html.push_str("<div>");
        html.push_str(&format!("<div class='card'><h3>Total Samples</h3><p>{}</p></div>", self.summary.total_samples));
        html.push_str(&format!("<div class='card'><h3>Alerts</h3><p>{}</p></div>", self.summary.alert_count));
        html.push_str(&format!("<div class='card'><h3>Critical</h3><p class='critical'>{}</p></div>", self.summary.critical_count));
        html.push_str(&format!("<div class='card'><h3>Max Score</h3><p>{:.2}</p></div>", self.summary.max_score));
        html.push_str("</div>");

        if !self.samples.is_empty() {
            html.push_str("<h2>Alert Details</h2><table><tr><th>#</th><th>Score</th><th>Level</th><th>Action</th><th>Reasons</th></tr>");
            for s in &self.samples {
                let class = match s.level.as_str() {
                    "Critical" => "critical",
                    "Severe" => "severe",
                    _ => "elevated",
                };
                html.push_str(&format!(
                    "<tr><td>{}</td><td>{:.2}</td><td class='{}'>{}</td><td>{}</td><td>{}</td></tr>",
                    s.index, s.score, class, html_escape(&s.level), html_escape(&s.action), html_escape(&s.reasons.join(", "))
                ));
            }
            html.push_str("</table>");
        }
        html.push_str("</body></html>");
        html
    }
}

// ── Report Store ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredReport {
    pub id: u64,
    pub report: JsonReport,
    pub generated_at: String,
    pub report_type: String,
}

pub struct ReportStore {
    reports: Vec<StoredReport>,
    next_id: u64,
    store_path: String,
}

impl ReportStore {
    pub fn new(store_path: &str) -> Self {
        let mut store = ReportStore {
            reports: Vec::new(),
            next_id: 1,
            store_path: store_path.to_string(),
        };
        store.load();
        store
    }

    fn load(&mut self) {
        let path = Path::new(&self.store_path);
        if path.exists() {
            if let Ok(content) = fs::read_to_string(path) {
                if let Ok(reports) = serde_json::from_str::<Vec<StoredReport>>(&content) {
                    self.next_id = reports.iter().map(|r| r.id).max().unwrap_or(0) + 1;
                    self.reports = reports;
                }
            }
        }
    }

    fn persist(&self) {
        let path = Path::new(&self.store_path);
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(&self.reports) {
            let _ = fs::write(path, json);
        }
    }

    pub fn store(&mut self, report: JsonReport, report_type: &str) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let stored = StoredReport {
            id,
            generated_at: report.generated_at.clone(),
            report,
            report_type: report_type.to_string(),
        };
        self.reports.push(stored);
        // Keep last 100 reports
        while self.reports.len() > 100 {
            self.reports.remove(0);
        }
        self.persist();
        id
    }

    pub fn list(&self) -> Vec<serde_json::Value> {
        self.reports.iter().map(|r| {
            serde_json::json!({
                "id": r.id,
                "generated_at": r.generated_at,
                "report_type": r.report_type,
                "total_samples": r.report.summary.total_samples,
                "alert_count": r.report.summary.alert_count,
                "critical_count": r.report.summary.critical_count,
            })
        }).collect()
    }

    pub fn get(&self, id: u64) -> Option<&StoredReport> {
        self.reports.iter().find(|r| r.id == id)
    }

    pub fn delete(&mut self, id: u64) -> bool {
        let before = self.reports.len();
        self.reports.retain(|r| r.id != id);
        if self.reports.len() < before {
            self.persist();
            true
        } else {
            false
        }
    }

    pub fn executive_summary(&self, incident_store: &IncidentStore) -> serde_json::Value {
        let total_reports = self.reports.len();
        let total_events: usize = self.reports.iter().map(|r| r.report.summary.total_samples).sum();
        let total_alerts: usize = self.reports.iter().map(|r| r.report.summary.alert_count).sum();
        let total_critical: usize = self.reports.iter().map(|r| r.report.summary.critical_count).sum();
        let max_score = self.reports.iter().map(|r| r.report.summary.max_score).fold(0.0f32, f32::max);
        let avg_score: Option<f32> = if total_events > 0 {
            let weighted_sum: f32 = self.reports.iter()
                .map(|r| r.report.summary.average_score * r.report.summary.total_samples as f32)
                .sum();
            Some(weighted_sum / total_events as f32)
        } else {
            None
        };

        let incidents = incident_store.list();
        let open_incidents = incidents.iter().filter(|i| {
            matches!(i.status, crate::incident::IncidentStatus::Open | crate::incident::IncidentStatus::Investigating)
        }).count();

        let mut technique_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for inc in incidents {
            for tech in &inc.mitre_techniques {
                *technique_counts.entry(format!("{} - {}", tech.technique_id, tech.technique_name)).or_insert(0) += 1;
            }
        }
        let mut top_techniques: Vec<_> = technique_counts.into_iter().collect();
        top_techniques.sort_by(|a, b| b.1.cmp(&a.1));
        top_techniques.truncate(5);

        // Aggregate detection reasons across all report samples
        let mut reason_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for stored in &self.reports {
            for sample in &stored.report.samples {
                for reason in &sample.reasons {
                    *reason_counts.entry(reason.clone()).or_insert(0) += 1;
                }
            }
        }
        let mut top_reasons: Vec<_> = reason_counts.into_iter().collect();
        top_reasons.sort_by(|a, b| b.1.cmp(&a.1));
        top_reasons.truncate(10);

        serde_json::json!({
            "total_reports": total_reports,
            "total_events": total_events,
            "total_alerts": total_alerts,
            "critical_alerts": total_critical,
            "avg_score": avg_score,
            "max_score": max_score,
            "incidents_total": incidents.len(),
            "incidents_open": open_incidents,
            "top_mitre_techniques": top_techniques,
            "top_reasons": top_reasons,
            "period": {
                "total_reports": total_reports,
                "first_report": self.reports.first().map(|r| &r.generated_at),
                "last_report": self.reports.last().map(|r| &r.generated_at),
            },
        })
    }
}

// ── Incident Report ─────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub timestamp: String,
    pub event_type: String,
    pub description: String,
    pub agent_id: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentReport {
    pub incident: Incident,
    pub timeline: Vec<TimelineEntry>,
    pub affected_agents: Vec<String>,
    pub mitre_coverage: Vec<MitreAttack>,
    pub recommendations: Vec<String>,
}

impl IncidentReport {
    pub fn generate(incident: &Incident, event_store: &EventStore) -> Self {
        let mut timeline = Vec::new();
        let mut affected_agents = incident.agent_ids.clone();

        // Build timeline from event IDs
        for &event_id in &incident.event_ids {
            if let Some(event) = event_store.get_event(event_id) {
                timeline.push(TimelineEntry {
                    timestamp: event.received_at.clone(),
                    event_type: event.alert.level.clone(),
                    description: event.alert.reasons.join(", "),
                    agent_id: event.agent_id.clone(),
                    severity: event.alert.level.clone(),
                });
                if !affected_agents.contains(&event.agent_id) {
                    affected_agents.push(event.agent_id.clone());
                }
            }
        }
        timeline.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        // Recommendations based on MITRE techniques
        let mut recommendations = Vec::new();
        for tech in &incident.mitre_techniques {
            let rec = match tech.technique_id.as_str() {
                "T1110" => "Enforce multi-factor authentication and account lockout policies.",
                "T1496" => "Audit CPU/GPU usage and block unauthorized mining software.",
                "T1565" => "Enable file integrity monitoring and verify backup routines.",
                "T1071" => "Inspect encrypted traffic at network boundaries and block C2 addresses.",
                "T1055" => "Deploy process injection detection and restrict process memory access.",
                "T1059" => "Limit script execution policies and audit command-line activity.",
                "T1041" => "Monitor outbound data volumes and inspect traffic to uncommon destinations.",
                "T1053" => "Audit scheduled tasks/cron jobs and restrict creation to authorized accounts.",
                _ => "Investigate this technique and review related activity logs.",
            };
            recommendations.push(format!("{} ({}): {}", tech.technique_name, tech.technique_id, rec));
        }
        if recommendations.is_empty() {
            recommendations.push("Review correlated events and identify potential lateral movement.".into());
        }

        IncidentReport {
            incident: incident.clone(),
            timeline,
            affected_agents,
            mitre_coverage: incident.mitre_techniques.clone(),
            recommendations,
        }
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
