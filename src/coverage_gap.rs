//! ATT&CK coverage gap analysis.
//!
//! Identifies techniques in the MITRE ATT&CK matrix that have zero
//! detection mappings, and generates remediation recommendations.

use serde::{Deserialize, Serialize};

use crate::mitre_coverage::{CoverageConfidence, MitreCoverageTracker};

/// A gap in ATT&CK coverage — a technique with no detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageGap {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub priority: GapPriority,
    pub recommendation: String,
    pub suggested_sources: Vec<String>,
}

/// Priority level for uncovered techniques.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum GapPriority {
    Critical,
    High,
    Medium,
    Low,
}

/// Full gap analysis report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GapAnalysisReport {
    pub total_techniques: usize,
    pub covered: usize,
    pub uncovered: usize,
    pub coverage_pct: f32,
    pub gaps: Vec<CoverageGap>,
    pub by_tactic: Vec<TacticGapSummary>,
    pub top_recommendations: Vec<String>,
    pub generated_at: String,
}

/// Gap summary per tactic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TacticGapSummary {
    pub tactic: String,
    pub total: usize,
    pub covered: usize,
    pub uncovered: usize,
    pub pct: f32,
    pub gap_ids: Vec<String>,
}

// ── High-value techniques by prevalence ──────────────────────────────

/// Techniques commonly used in real-world attacks (higher priority when uncovered).
const HIGH_VALUE_TECHNIQUES: &[&str] = &[
    "T1059", "T1053", "T1547", "T1078", "T1110", "T1003", "T1021", "T1071",
    "T1486", "T1190", "T1566", "T1055", "T1036", "T1027", "T1562", "T1070",
    "T1569", "T1560", "T1105", "T1573",
];

/// Generate a complete gap analysis from the coverage tracker.
pub fn analyze_gaps(tracker: &MitreCoverageTracker) -> GapAnalysisReport {
    let summary = tracker.summary();
    let heatmap = tracker.heatmap();

    let mut gaps = Vec::new();
    let mut by_tactic: std::collections::HashMap<String, Vec<CoverageGap>> =
        std::collections::HashMap::new();

    for cell in &heatmap {
        if !cell.covered {
            let priority = if HIGH_VALUE_TECHNIQUES.contains(&cell.technique_id.as_str()) {
                GapPriority::Critical
            } else {
                match cell.tactic.as_str() {
                    "initial-access" | "execution" | "credential-access" => GapPriority::High,
                    "persistence" | "privilege-escalation" | "lateral-movement" => {
                        GapPriority::Medium
                    }
                    _ => GapPriority::Low,
                }
            };

            let recommendation = generate_recommendation(&cell.technique_id, &cell.technique_name);
            let suggested_sources = suggest_detection_sources(&cell.technique_id, &cell.tactic);

            let gap = CoverageGap {
                technique_id: cell.technique_id.clone(),
                technique_name: cell.technique_name.clone(),
                tactic: cell.tactic.clone(),
                priority,
                recommendation,
                suggested_sources,
            };

            by_tactic
                .entry(cell.tactic.clone())
                .or_default()
                .push(gap.clone());
            gaps.push(gap);
        }
    }

    // Sort gaps by priority
    gaps.sort_by_key(|g| match g.priority {
        GapPriority::Critical => 0,
        GapPriority::High => 1,
        GapPriority::Medium => 2,
        GapPriority::Low => 3,
    });

    let tactic_summaries: Vec<TacticGapSummary> = summary
        .by_tactic
        .iter()
        .map(|tc| {
            let gap_ids = by_tactic
                .get(&tc.tactic)
                .map(|gs| gs.iter().map(|g| g.technique_id.clone()).collect())
                .unwrap_or_default();
            TacticGapSummary {
                tactic: tc.tactic.clone(),
                total: tc.total,
                covered: tc.covered,
                uncovered: tc.total - tc.covered,
                pct: tc.pct,
                gap_ids,
            }
        })
        .collect();

    let top_recommendations: Vec<String> = gaps
        .iter()
        .filter(|g| matches!(g.priority, GapPriority::Critical | GapPriority::High))
        .take(5)
        .map(|g| format!("[{}] {}: {}", g.technique_id, g.technique_name, g.recommendation))
        .collect();

    GapAnalysisReport {
        total_techniques: summary.total_techniques,
        covered: summary.covered_techniques,
        uncovered: summary.total_techniques - summary.covered_techniques,
        coverage_pct: summary.coverage_pct,
        gaps,
        by_tactic: tactic_summaries,
        top_recommendations,
        generated_at: chrono::Utc::now().to_rfc3339(),
    }
}

fn generate_recommendation(technique_id: &str, technique_name: &str) -> String {
    match technique_id {
        "T1059" => "Add Sigma rules for command-line interpreter usage (PowerShell, bash, cmd)".into(),
        "T1053" => "Monitor scheduled task creation and modification events".into(),
        "T1547" => "Track autostart registry keys and startup folder modifications".into(),
        "T1078" => "Implement UEBA baseline for valid account usage patterns".into(),
        "T1110" => "Enable auth failure rate monitoring with adaptive thresholds".into(),
        "T1003" => "Add YARA rules for credential dumping tool signatures".into(),
        "T1021" => "Monitor lateral movement via SSH/RDP/SMB connections".into(),
        "T1071" => "Deploy NDR rules for anomalous application-layer protocol usage".into(),
        "T1486" => "Enable ransomware detection (file velocity + canary files)".into(),
        "T1190" => "Monitor web-facing service logs for exploitation signatures".into(),
        "T1566" => "Integrate email gateway IoC feeds for phishing detection".into(),
        "T1055" => "Add process injection detection (hollowing, DLL injection)".into(),
        "T1036" => "Detect process name masquerading and path anomalies".into(),
        "T1027" => "Scan for obfuscated scripts and encoded payloads".into(),
        "T1562" => "Monitor security tool processes and configuration changes".into(),
        "T1070" => "Track log clearing and indicator removal activities".into(),
        _ => format!("Create detection rule for {technique_name} ({technique_id})"),
    }
}

fn suggest_detection_sources(technique_id: &str, tactic: &str) -> Vec<String> {
    let mut sources = Vec::new();
    match tactic {
        "initial-access" => {
            sources.push("WAF / reverse proxy logs".into());
            sources.push("Email gateway integration".into());
        }
        "execution" | "persistence" => {
            sources.push("Sigma rule".into());
            sources.push("Process monitoring".into());
            sources.push("FIM baseline".into());
        }
        "credential-access" => {
            sources.push("UEBA baseline".into());
            sources.push("Auth log correlation".into());
            sources.push("YARA rule".into());
        }
        "lateral-movement" => {
            sources.push("NDR engine".into());
            sources.push("Lateral movement detector".into());
        }
        "exfiltration" | "command-and-control" => {
            sources.push("NDR engine".into());
            sources.push("Beacon detector".into());
            sources.push("DNS log analysis".into());
        }
        _ => {
            sources.push("Sigma rule".into());
        }
    }
    sources
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyze_gaps_returns_report() {
        let tracker = MitreCoverageTracker::new();
        let report = analyze_gaps(&tracker);
        assert!(report.total_techniques > 0);
        // With builtin mappings some techniques should be covered
        assert!(report.covered > 0);
        assert!(!report.generated_at.is_empty());
    }

    #[test]
    fn gaps_are_sorted_by_priority() {
        let tracker = MitreCoverageTracker::new();
        let report = analyze_gaps(&tracker);
        if report.gaps.len() >= 2 {
            let priorities: Vec<u8> = report
                .gaps
                .iter()
                .map(|g| match g.priority {
                    GapPriority::Critical => 0,
                    GapPriority::High => 1,
                    GapPriority::Medium => 2,
                    GapPriority::Low => 3,
                })
                .collect();
            for w in priorities.windows(2) {
                assert!(w[0] <= w[1], "gaps should be sorted by priority");
            }
        }
    }

    #[test]
    fn tactic_summaries_present() {
        let tracker = MitreCoverageTracker::new();
        let report = analyze_gaps(&tracker);
        assert!(!report.by_tactic.is_empty());
    }
}
