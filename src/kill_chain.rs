//! Cyber kill chain reconstruction and MITRE ATT&CK phase mapping.
//!
//! Groups correlated security events into Lockheed Martin Cyber Kill Chain
//! stages, assigns confidence scores per stage, and produces a narrative
//! timeline suitable for incident investigation.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Kill chain phases ───────────────────────────────────────────

/// Lockheed Martin Cyber Kill Chain phases.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum KillChainPhase {
    Reconnaissance,
    Weaponization,
    Delivery,
    Exploitation,
    Installation,
    CommandAndControl,
    ActionsOnObjectives,
}

impl KillChainPhase {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Reconnaissance => "Reconnaissance",
            Self::Weaponization => "Weaponization",
            Self::Delivery => "Delivery",
            Self::Exploitation => "Exploitation",
            Self::Installation => "Installation",
            Self::CommandAndControl => "Command & Control",
            Self::ActionsOnObjectives => "Actions on Objectives",
        }
    }

    pub fn index(&self) -> usize {
        match self {
            Self::Reconnaissance => 0,
            Self::Weaponization => 1,
            Self::Delivery => 2,
            Self::Exploitation => 3,
            Self::Installation => 4,
            Self::CommandAndControl => 5,
            Self::ActionsOnObjectives => 6,
        }
    }

    pub fn all() -> &'static [KillChainPhase] {
        &[
            Self::Reconnaissance,
            Self::Weaponization,
            Self::Delivery,
            Self::Exploitation,
            Self::Installation,
            Self::CommandAndControl,
            Self::ActionsOnObjectives,
        ]
    }
}

// ── Event input ─────────────────────────────────────────────────

/// Minimal event representation consumed by the kill chain analyser.
/// Can be constructed from `StoredEvent`, `KernelEvent`, or alert records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainEvent {
    pub event_id: String,
    pub timestamp_ms: u64,
    pub hostname: String,
    pub agent_uid: Option<String>,
    /// Alert reasons or descriptions.
    pub reasons: Vec<String>,
    /// MITRE technique IDs already mapped (e.g. from `map_alert_to_mitre`).
    pub mitre_technique_ids: Vec<String>,
    /// Anomaly score (0–10).
    pub score: f32,
    /// Process name or path if available.
    pub process: Option<String>,
    /// Network destination if relevant.
    pub dst_addr: Option<String>,
    /// File path if relevant.
    pub file_path: Option<String>,
}

// ── Kill chain output ───────────────────────────────────────────

/// A reconstructed kill chain for an incident.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChain {
    /// Incident ID this chain belongs to.
    pub incident_id: String,
    /// Stages observed, ordered by phase.
    pub stages: Vec<KillChainStage>,
    /// Overall confidence (0–1) based on evidence coverage.
    pub overall_confidence: f32,
    /// Furthest phase reached.
    pub furthest_phase: KillChainPhase,
    /// Total events mapped across all stages.
    pub total_events: usize,
}

/// A single stage in the kill chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillChainStage {
    pub phase: KillChainPhase,
    /// Events attributed to this stage.
    pub events: Vec<KillChainEvent>,
    /// Confidence that this stage actually occurred (0–1).
    pub confidence: f32,
    /// Earliest event timestamp in this stage.
    pub first_seen_ms: u64,
    /// Latest event timestamp.
    pub last_seen_ms: u64,
    /// MITRE techniques observed in this stage.
    pub techniques: Vec<String>,
}

// ── MITRE → Kill Chain mapping ──────────────────────────────────

/// Map a MITRE ATT&CK technique ID to its most likely kill chain phase.
fn technique_to_phase(technique_id: &str) -> KillChainPhase {
    match technique_id {
        // Reconnaissance
        "T1595" | "T1592" | "T1589" | "T1590" | "T1591" | "T1596" | "T1593" | "T1594"
        | "T1082" | "T1016" | "T1018" | "T1049" | "T1033" | "T1007" | "T1069" | "T1087"
        | "T1135" | "T1046" => KillChainPhase::Reconnaissance,

        // Delivery
        "T1566" | "T1091" | "T1195" | "T1189" => KillChainPhase::Delivery,

        // Exploitation
        "T1203" | "T1068" | "T1211" | "T1212" | "T1110" | "T1190" | "T1133" => {
            KillChainPhase::Exploitation
        }

        // Installation / Persistence
        "T1053" | "T1547" | "T1543" | "T1546" | "T1136" | "T1098" | "T1078" | "T1556"
        | "T1112" | "T1055" | "T1574" => KillChainPhase::Installation,

        // C2
        "T1071" | "T1573" | "T1095" | "T1572" | "T1090" | "T1105" | "T1132" | "T1001"
        | "T1568" | "T1219" => KillChainPhase::CommandAndControl,

        // Actions on Objectives
        "T1041" | "T1048" | "T1567" | "T1029" | "T1565" | "T1496" | "T1486" | "T1491"
        | "T1485" | "T1499" | "T1498" | "T1561" => KillChainPhase::ActionsOnObjectives,

        // Defense Evasion / Execution — maps to Exploitation/Installation
        "T1059" | "T1569" | "T1106" => KillChainPhase::Exploitation,
        "T1070" | "T1027" | "T1562" | "T1036" | "T1140" | "T1480" | "T1202" | "T1218" => {
            KillChainPhase::Installation
        }

        // Lateral Movement — maps to Actions on Objectives
        "T1021" | "T1570" | "T1534" | "T1080" => KillChainPhase::ActionsOnObjectives,

        // Credential Access
        "T1003" | "T1558" | "T1552" | "T1539" | "T1528" | "T1649" => {
            KillChainPhase::Exploitation
        }

        // Default: treat as exploitation for unknown techniques
        _ => KillChainPhase::Exploitation,
    }
}

/// Map alert reason strings (as used in existing codebase) to kill chain phases.
fn reason_to_phase(reason: &str) -> Option<KillChainPhase> {
    let r = reason.to_lowercase();
    if r.contains("scan") || r.contains("enum") || r.contains("discover") || r.contains("recon") {
        Some(KillChainPhase::Reconnaissance)
    } else if r.contains("phish") || r.contains("deliver") || r.contains("dropper") {
        Some(KillChainPhase::Delivery)
    } else if r.contains("exploit") || r.contains("brute") || r.contains("credential")
        || r.contains("auth fail")
    {
        Some(KillChainPhase::Exploitation)
    } else if r.contains("persist") || r.contains("install") || r.contains("launch_agent")
        || r.contains("systemd") || r.contains("registry")
    {
        Some(KillChainPhase::Installation)
    } else if r.contains("c2") || r.contains("beacon") || r.contains("callback")
        || r.contains("command and control")
    {
        Some(KillChainPhase::CommandAndControl)
    } else if r.contains("exfil") || r.contains("data_transfer") || r.contains("encrypt")
        || r.contains("ransom") || r.contains("lateral")
    {
        Some(KillChainPhase::ActionsOnObjectives)
    } else if r.contains("network") {
        Some(KillChainPhase::CommandAndControl)
    } else {
        None
    }
}

// ── Kill chain analyser ─────────────────────────────────────────

/// Reconstructs a cyber kill chain from a set of correlated events.
pub struct KillChainAnalyzer;

impl KillChainAnalyzer {
    pub fn new() -> Self {
        Self
    }

    /// Reconstruct kill chain stages from events associated with an incident.
    pub fn reconstruct(&self, incident_id: &str, events: &[KillChainEvent]) -> KillChain {
        let mut stage_map: HashMap<KillChainPhase, Vec<KillChainEvent>> = HashMap::new();
        let mut technique_map: HashMap<KillChainPhase, Vec<String>> = HashMap::new();

        for event in events {
            let mut assigned = false;

            // Primary: use MITRE technique IDs
            for tid in &event.mitre_technique_ids {
                let phase = technique_to_phase(tid);
                stage_map.entry(phase).or_default().push(event.clone());
                technique_map
                    .entry(phase)
                    .or_default()
                    .push(tid.clone());
                assigned = true;
            }

            // Fallback: use reason strings
            if !assigned {
                for reason in &event.reasons {
                    if let Some(phase) = reason_to_phase(reason) {
                        stage_map.entry(phase).or_default().push(event.clone());
                        assigned = true;
                        break;
                    }
                }
            }

            // Last resort: high-score events with network indicators → C2
            if !assigned && event.score > 5.0 && event.dst_addr.is_some() {
                stage_map
                    .entry(KillChainPhase::CommandAndControl)
                    .or_default()
                    .push(event.clone());
            }
        }

        // Build stages ordered by phase
        let mut stages = Vec::new();
        let mut furthest = KillChainPhase::Reconnaissance;

        for phase in KillChainPhase::all() {
            if let Some(phase_events) = stage_map.get(phase) {
                if phase_events.is_empty() {
                    continue;
                }
                let first_seen = phase_events
                    .iter()
                    .map(|e| e.timestamp_ms)
                    .min()
                    .unwrap_or(0);
                let last_seen = phase_events
                    .iter()
                    .map(|e| e.timestamp_ms)
                    .max()
                    .unwrap_or(0);

                let mut techs: Vec<String> = technique_map
                    .get(phase)
                    .cloned()
                    .unwrap_or_default();
                techs.sort();
                techs.dedup();

                // Confidence: based on evidence count and score magnitude
                let avg_score: f32 = phase_events.iter().map(|e| e.score).sum::<f32>()
                    / phase_events.len() as f32;
                let evidence_factor =
                    (phase_events.len() as f32 / 3.0).min(1.0); // 3+ events → full
                let score_factor = (avg_score / 5.0).min(1.0);
                let technique_factor = if techs.is_empty() { 0.3 } else { 0.7 };
                let confidence =
                    (evidence_factor * 0.4 + score_factor * 0.3 + technique_factor * 0.3)
                        .min(1.0);

                stages.push(KillChainStage {
                    phase: *phase,
                    events: phase_events.clone(),
                    confidence,
                    first_seen_ms: first_seen,
                    last_seen_ms: last_seen,
                    techniques: techs,
                });
                furthest = *phase;
            }
        }

        let total_events = events.len();
        let overall_confidence = if stages.is_empty() {
            0.0
        } else {
            let sum: f32 = stages.iter().map(|s| s.confidence).sum();
            let phase_coverage = stages.len() as f32 / 7.0;
            (sum / stages.len() as f32 * 0.6 + phase_coverage * 0.4).min(1.0)
        };

        KillChain {
            incident_id: incident_id.to_string(),
            stages,
            overall_confidence,
            furthest_phase: furthest,
            total_events,
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(id: &str, ts: u64, techniques: &[&str], reasons: &[&str], score: f32) -> KillChainEvent {
        KillChainEvent {
            event_id: id.into(),
            timestamp_ms: ts,
            hostname: "host1".into(),
            agent_uid: None,
            reasons: reasons.iter().map(|s| s.to_string()).collect(),
            mitre_technique_ids: techniques.iter().map(|s| s.to_string()).collect(),
            score,
            process: None,
            dst_addr: None,
            file_path: None,
        }
    }

    #[test]
    fn reconstruction_maps_techniques_to_phases() {
        let events = vec![
            make_event("e1", 1000, &["T1046"], &[], 3.0),       // Recon
            make_event("e2", 2000, &["T1566"], &[], 4.0),       // Delivery
            make_event("e3", 3000, &["T1203"], &[], 6.0),       // Exploitation
            make_event("e4", 4000, &["T1053"], &[], 5.0),       // Installation
            make_event("e5", 5000, &["T1071"], &[], 7.0),       // C2
            make_event("e6", 6000, &["T1041"], &[], 8.0),       // Actions
        ];
        let chain = KillChainAnalyzer::new().reconstruct("inc-1", &events);
        assert_eq!(chain.stages.len(), 6);
        assert_eq!(chain.furthest_phase, KillChainPhase::ActionsOnObjectives);
        assert!(chain.overall_confidence > 0.5);
        assert_eq!(chain.total_events, 6);
    }

    #[test]
    fn reconstruction_uses_reason_fallback() {
        let events = vec![
            make_event("e1", 1000, &[], &["port scan detected"], 4.0),
            make_event("e2", 2000, &[], &["brute force auth failures"], 6.0),
            make_event("e3", 3000, &[], &["persistence via launch_agent"], 5.0),
        ];
        let chain = KillChainAnalyzer::new().reconstruct("inc-2", &events);
        assert!(chain.stages.len() >= 3);
        let phases: Vec<_> = chain.stages.iter().map(|s| s.phase).collect();
        assert!(phases.contains(&KillChainPhase::Reconnaissance));
        assert!(phases.contains(&KillChainPhase::Exploitation));
        assert!(phases.contains(&KillChainPhase::Installation));
    }

    #[test]
    fn empty_events_produce_empty_chain() {
        let chain = KillChainAnalyzer::new().reconstruct("inc-3", &[]);
        assert!(chain.stages.is_empty());
        assert_eq!(chain.overall_confidence, 0.0);
        assert_eq!(chain.total_events, 0);
    }

    #[test]
    fn confidence_increases_with_evidence() {
        let few = vec![make_event("e1", 1000, &["T1071"], &[], 3.0)];
        let chain_few = KillChainAnalyzer::new().reconstruct("inc-4", &few);

        let many = vec![
            make_event("e1", 1000, &["T1071"], &[], 7.0),
            make_event("e2", 2000, &["T1071"], &[], 8.0),
            make_event("e3", 3000, &["T1071"], &[], 9.0),
            make_event("e4", 4000, &["T1041"], &[], 8.0),
        ];
        let chain_many = KillChainAnalyzer::new().reconstruct("inc-5", &many);
        assert!(chain_many.overall_confidence >= chain_few.overall_confidence);
    }

    #[test]
    fn high_score_network_events_fallback_to_c2() {
        let events = vec![KillChainEvent {
            event_id: "e1".into(),
            timestamp_ms: 1000,
            hostname: "h1".into(),
            agent_uid: None,
            reasons: vec![],
            mitre_technique_ids: vec![],
            score: 8.0,
            process: None,
            dst_addr: Some("10.10.10.10".into()),
            file_path: None,
        }];
        let chain = KillChainAnalyzer::new().reconstruct("inc-6", &events);
        assert!(chain.stages.iter().any(|s| s.phase == KillChainPhase::CommandAndControl));
    }

    #[test]
    fn technique_to_phase_coverage() {
        assert_eq!(technique_to_phase("T1595"), KillChainPhase::Reconnaissance);
        assert_eq!(technique_to_phase("T1566"), KillChainPhase::Delivery);
        assert_eq!(technique_to_phase("T1203"), KillChainPhase::Exploitation);
        assert_eq!(technique_to_phase("T1053"), KillChainPhase::Installation);
        assert_eq!(technique_to_phase("T1071"), KillChainPhase::CommandAndControl);
        assert_eq!(technique_to_phase("T1041"), KillChainPhase::ActionsOnObjectives);
        assert_eq!(technique_to_phase("T1021"), KillChainPhase::ActionsOnObjectives);
    }

    #[test]
    fn stages_ordered_by_phase() {
        let events = vec![
            make_event("e1", 5000, &["T1041"], &[], 5.0), // Actions (last)
            make_event("e2", 1000, &["T1046"], &[], 3.0), // Recon (first)
        ];
        let chain = KillChainAnalyzer::new().reconstruct("inc-7", &events);
        assert!(chain.stages[0].phase.index() < chain.stages[1].phase.index());
    }

    #[test]
    fn phase_labels() {
        assert_eq!(KillChainPhase::Reconnaissance.label(), "Reconnaissance");
        assert_eq!(KillChainPhase::CommandAndControl.label(), "Command & Control");
        assert_eq!(KillChainPhase::ActionsOnObjectives.label(), "Actions on Objectives");
    }
}
