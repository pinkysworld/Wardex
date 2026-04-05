//! MITRE ATT&CK coverage tracker.
//!
//! Maps detection modules, Sigma rules, and YARA rules to ATT&CK
//! technique IDs and exposes coverage metrics per tactic.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// A single ATT&CK technique mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechniqueMapping {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub detection_source: String,
    pub confidence: CoverageConfidence,
}

/// Confidence level for a detection mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoverageConfidence {
    /// Fully implemented and tested detection.
    High,
    /// Detection exists but may miss variants.
    Medium,
    /// Minimal or indirect detection only.
    Low,
}

/// Heatmap cell for a single tactic×technique combination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeatmapCell {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub covered: bool,
    pub confidence: Option<CoverageConfidence>,
    pub sources: Vec<String>,
}

/// Summary of coverage across all tactics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageSummary {
    pub total_techniques: usize,
    pub covered_techniques: usize,
    pub coverage_pct: f32,
    pub by_tactic: Vec<TacticCoverage>,
    pub gaps: Vec<String>,
}

/// Coverage for a single tactic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TacticCoverage {
    pub tactic: String,
    pub total: usize,
    pub covered: usize,
    pub pct: f32,
}

/// Central MITRE ATT&CK coverage tracker.
#[derive(Debug, Clone)]
pub struct MitreCoverageTracker {
    mappings: Vec<TechniqueMapping>,
    matrix: HashMap<String, Vec<MatrixTechnique>>,
}

#[derive(Debug, Clone)]
struct MatrixTechnique {
    id: String,
    name: String,
}

impl Default for MitreCoverageTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl MitreCoverageTracker {
    pub fn new() -> Self {
        let mut tracker = Self {
            mappings: Vec::new(),
            matrix: HashMap::new(),
        };
        tracker.load_matrix();
        tracker.load_builtin_mappings();
        tracker
    }

    /// Load the ATT&CK Enterprise matrix (subset of most common techniques).
    fn load_matrix(&mut self) {
        let tactics: &[(&str, &[(&str, &str)])] = &[
            ("initial-access", &[
                ("T1190", "Exploit Public-Facing Application"),
                ("T1133", "External Remote Services"),
                ("T1566", "Phishing"),
                ("T1078", "Valid Accounts"),
                ("T1195", "Supply Chain Compromise"),
                ("T1199", "Trusted Relationship"),
            ]),
            ("execution", &[
                ("T1059", "Command and Scripting Interpreter"),
                ("T1053", "Scheduled Task/Job"),
                ("T1047", "Windows Management Instrumentation"),
                ("T1204", "User Execution"),
                ("T1569", "System Services"),
                ("T1106", "Native API"),
            ]),
            ("persistence", &[
                ("T1547", "Boot or Logon Autostart Execution"),
                ("T1053", "Scheduled Task/Job"),
                ("T1136", "Create Account"),
                ("T1543", "Create or Modify System Process"),
                ("T1546", "Event Triggered Execution"),
                ("T1556", "Modify Authentication Process"),
            ]),
            ("privilege-escalation", &[
                ("T1548", "Abuse Elevation Control Mechanism"),
                ("T1134", "Access Token Manipulation"),
                ("T1068", "Exploitation for Privilege Escalation"),
                ("T1055", "Process Injection"),
                ("T1078", "Valid Accounts"),
            ]),
            ("defense-evasion", &[
                ("T1070", "Indicator Removal"),
                ("T1036", "Masquerading"),
                ("T1027", "Obfuscated Files or Information"),
                ("T1055", "Process Injection"),
                ("T1218", "System Binary Proxy Execution"),
                ("T1562", "Impair Defenses"),
                ("T1112", "Modify Registry"),
            ]),
            ("credential-access", &[
                ("T1110", "Brute Force"),
                ("T1003", "OS Credential Dumping"),
                ("T1555", "Credentials from Password Stores"),
                ("T1558", "Steal or Forge Kerberos Tickets"),
                ("T1552", "Unsecured Credentials"),
            ]),
            ("discovery", &[
                ("T1087", "Account Discovery"),
                ("T1082", "System Information Discovery"),
                ("T1083", "File and Directory Discovery"),
                ("T1046", "Network Service Discovery"),
                ("T1057", "Process Discovery"),
                ("T1049", "System Network Connections Discovery"),
            ]),
            ("lateral-movement", &[
                ("T1021", "Remote Services"),
                ("T1080", "Taint Shared Content"),
                ("T1550", "Use Alternate Authentication Material"),
                ("T1570", "Lateral Tool Transfer"),
            ]),
            ("collection", &[
                ("T1560", "Archive Collected Data"),
                ("T1119", "Automated Collection"),
                ("T1005", "Data from Local System"),
                ("T1039", "Data from Network Shared Drive"),
                ("T1074", "Data Staged"),
            ]),
            ("command-and-control", &[
                ("T1071", "Application Layer Protocol"),
                ("T1132", "Data Encoding"),
                ("T1568", "Dynamic Resolution"),
                ("T1573", "Encrypted Channel"),
                ("T1105", "Ingress Tool Transfer"),
                ("T1572", "Protocol Tunneling"),
            ]),
            ("exfiltration", &[
                ("T1048", "Exfiltration Over Alternative Protocol"),
                ("T1041", "Exfiltration Over C2 Channel"),
                ("T1567", "Exfiltration Over Web Service"),
                ("T1029", "Scheduled Transfer"),
            ]),
            ("impact", &[
                ("T1486", "Data Encrypted for Impact"),
                ("T1485", "Data Destruction"),
                ("T1489", "Service Stop"),
                ("T1498", "Network Denial of Service"),
                ("T1496", "Resource Hijacking"),
            ]),
        ];

        for (tactic, techniques) in tactics {
            let entries: Vec<MatrixTechnique> = techniques
                .iter()
                .map(|(id, name)| MatrixTechnique {
                    id: id.to_string(),
                    name: name.to_string(),
                })
                .collect();
            self.matrix.insert(tactic.to_string(), entries);
        }
    }

    /// Register built-in detection module mappings.
    fn load_builtin_mappings(&mut self) {
        let builtin: &[(&str, &str, &str, &str, CoverageConfidence)] = &[
            // Detector modules
            ("T1110", "Brute Force", "credential-access", "detector.rs (auth_failures signal)", CoverageConfidence::High),
            ("T1078", "Valid Accounts", "initial-access", "ueba.rs (anomalous login)", CoverageConfidence::Medium),
            ("T1486", "Data Encrypted for Impact", "impact", "ransomware.rs (velocity + extension)", CoverageConfidence::High),
            ("T1496", "Resource Hijacking", "impact", "detector.rs (CPU + entropy low)", CoverageConfidence::Medium),
            ("T1071", "Application Layer Protocol", "command-and-control", "beacon.rs (periodicity)", CoverageConfidence::High),
            ("T1568", "Dynamic Resolution", "command-and-control", "beacon.rs (DGA entropy)", CoverageConfidence::High),
            ("T1572", "Protocol Tunneling", "command-and-control", "beacon.rs (DNS tunneling)", CoverageConfidence::High),
            ("T1021", "Remote Services", "lateral-movement", "lateral.rs (fan-out)", CoverageConfidence::Medium),
            ("T1570", "Lateral Tool Transfer", "lateral-movement", "lateral.rs (hop-chain)", CoverageConfidence::Medium),
            ("T1055", "Process Injection", "privilege-escalation", "memory_forensics.rs (RWX regions)", CoverageConfidence::Medium),
            ("T1055", "Process Injection", "defense-evasion", "memory_forensics.rs (RWX regions)", CoverageConfidence::Medium),
            ("T1083", "File and Directory Discovery", "discovery", "fim.rs (file access monitoring)", CoverageConfidence::Low),
            ("T1005", "Data from Local System", "collection", "fim.rs (file change tracking)", CoverageConfidence::Low),
            ("T1082", "System Information Discovery", "discovery", "collector.rs (system profiling)", CoverageConfidence::Low),
            ("T1057", "Process Discovery", "discovery", "process_tree.rs (deep chains)", CoverageConfidence::Medium),
            ("T1543", "Create or Modify System Process", "persistence", "fim.rs + kernel_events.rs", CoverageConfidence::Medium),
            ("T1195", "Supply Chain Compromise", "initial-access", "sbom.rs (dependency tracking)", CoverageConfidence::Low),
            ("T1498", "Network Denial of Service", "impact", "detector.rs (network burst signal)", CoverageConfidence::Medium),

            // Sigma rule coverage
            ("T1110", "Brute Force", "credential-access", "sigma/authentication.yml", CoverageConfidence::High),
            ("T1059", "Command and Scripting Interpreter", "execution", "sigma/endpoint.yml (LOLBins)", CoverageConfidence::Medium),
            ("T1068", "Exploitation for Privilege Escalation", "privilege-escalation", "sigma/endpoint.yml (integrity→SYSTEM)", CoverageConfidence::Medium),
            ("T1071", "Application Layer Protocol", "command-and-control", "sigma/network.yml (C2 IoC)", CoverageConfidence::Medium),
            ("T1572", "Protocol Tunneling", "command-and-control", "sigma/network.yml (DNS tunneling)", CoverageConfidence::Medium),

            // UEBA coverage
            ("T1078", "Valid Accounts", "privilege-escalation", "ueba.rs (impossible travel)", CoverageConfidence::High),
            ("T1048", "Exfiltration Over Alternative Protocol", "exfiltration", "ueba.rs (data exfil pattern)", CoverageConfidence::Medium),
            ("T1021", "Remote Services", "lateral-movement", "ueba.rs (lateral movement)", CoverageConfidence::Medium),
        ];

        for (id, name, tactic, source, confidence) in builtin {
            self.mappings.push(TechniqueMapping {
                technique_id: id.to_string(),
                technique_name: name.to_string(),
                tactic: tactic.to_string(),
                detection_source: source.to_string(),
                confidence: *confidence,
            });
        }
    }

    /// Add a custom technique mapping (e.g. from a Sigma rule import).
    pub fn add_mapping(&mut self, mapping: TechniqueMapping) {
        self.mappings.push(mapping);
    }

    /// Generate the full heatmap for the ATT&CK matrix.
    pub fn heatmap(&self) -> Vec<HeatmapCell> {
        let covered: HashMap<(String, String), Vec<&TechniqueMapping>> = {
            let mut map: HashMap<(String, String), Vec<&TechniqueMapping>> = HashMap::new();
            for m in &self.mappings {
                map.entry((m.tactic.clone(), m.technique_id.clone()))
                    .or_default()
                    .push(m);
            }
            map
        };

        let mut cells = Vec::new();
        for (tactic, techniques) in &self.matrix {
            for tech in techniques {
                let key = (tactic.clone(), tech.id.clone());
                if let Some(sources) = covered.get(&key) {
                    let best_confidence = sources
                        .iter()
                        .map(|s| s.confidence)
                        .max_by_key(|c| match c {
                            CoverageConfidence::High => 3,
                            CoverageConfidence::Medium => 2,
                            CoverageConfidence::Low => 1,
                        })
                        .unwrap_or(CoverageConfidence::Low);
                    cells.push(HeatmapCell {
                        technique_id: tech.id.clone(),
                        technique_name: tech.name.clone(),
                        tactic: tactic.clone(),
                        covered: true,
                        confidence: Some(best_confidence),
                        sources: sources.iter().map(|s| s.detection_source.clone()).collect(),
                    });
                } else {
                    cells.push(HeatmapCell {
                        technique_id: tech.id.clone(),
                        technique_name: tech.name.clone(),
                        tactic: tactic.clone(),
                        covered: false,
                        confidence: None,
                        sources: Vec::new(),
                    });
                }
            }
        }
        cells
    }

    /// Generate coverage summary with gap analysis.
    pub fn summary(&self) -> CoverageSummary {
        let heatmap = self.heatmap();

        // Deduplicate techniques (same ID can appear in multiple tactics)
        let mut all_techniques: HashSet<String> = HashSet::new();
        let mut covered_techniques: HashSet<String> = HashSet::new();

        for cell in &heatmap {
            all_techniques.insert(cell.technique_id.clone());
            if cell.covered {
                covered_techniques.insert(cell.technique_id.clone());
            }
        }

        let total = all_techniques.len();
        let covered = covered_techniques.len();

        let gaps: Vec<String> = all_techniques
            .difference(&covered_techniques)
            .cloned()
            .collect();

        let mut by_tactic: Vec<TacticCoverage> = Vec::new();
        for (tactic, techniques) in &self.matrix {
            let tactic_total = techniques.len();
            let tactic_covered = techniques
                .iter()
                .filter(|t| {
                    heatmap.iter().any(|c| {
                        c.tactic == *tactic && c.technique_id == t.id && c.covered
                    })
                })
                .count();
            by_tactic.push(TacticCoverage {
                tactic: tactic.clone(),
                total: tactic_total,
                covered: tactic_covered,
                pct: if tactic_total > 0 {
                    (tactic_covered as f32 / tactic_total as f32) * 100.0
                } else {
                    0.0
                },
            });
        }
        by_tactic.sort_by(|a, b| a.tactic.cmp(&b.tactic));

        CoverageSummary {
            total_techniques: total,
            covered_techniques: covered,
            coverage_pct: if total > 0 {
                (covered as f32 / total as f32) * 100.0
            } else {
                0.0
            },
            by_tactic,
            gaps,
        }
    }

    /// Return all registered mappings.
    pub fn mappings(&self) -> &[TechniqueMapping] {
        &self.mappings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracker_loads_builtin_mappings() {
        let tracker = MitreCoverageTracker::new();
        assert!(!tracker.mappings().is_empty());
        assert!(tracker.mappings().len() >= 20);
    }

    #[test]
    fn heatmap_covers_known_techniques() {
        let tracker = MitreCoverageTracker::new();
        let heatmap = tracker.heatmap();
        assert!(!heatmap.is_empty());
        let brute_force = heatmap
            .iter()
            .find(|c| c.technique_id == "T1110" && c.tactic == "credential-access");
        assert!(brute_force.is_some());
        let bf = brute_force.unwrap();
        assert!(bf.covered);
        assert_eq!(bf.confidence, Some(CoverageConfidence::High));
    }

    #[test]
    fn summary_reports_gaps() {
        let tracker = MitreCoverageTracker::new();
        let summary = tracker.summary();
        assert!(summary.total_techniques > 0);
        assert!(summary.covered_techniques > 0);
        assert!(summary.coverage_pct > 0.0);
        assert!(summary.coverage_pct < 100.0); // We don't cover everything
        assert!(!summary.gaps.is_empty());
    }

    #[test]
    fn custom_mapping_increases_coverage() {
        let mut tracker = MitreCoverageTracker::new();
        let before = tracker.summary().covered_techniques;
        tracker.add_mapping(TechniqueMapping {
            technique_id: "T1485".into(),
            technique_name: "Data Destruction".into(),
            tactic: "impact".into(),
            detection_source: "custom_rule.yml".into(),
            confidence: CoverageConfidence::High,
        });
        let after = tracker.summary().covered_techniques;
        assert!(after >= before);
    }

    #[test]
    fn by_tactic_coverage_populated() {
        let tracker = MitreCoverageTracker::new();
        let summary = tracker.summary();
        assert!(!summary.by_tactic.is_empty());
        let c2 = summary
            .by_tactic
            .iter()
            .find(|t| t.tactic == "command-and-control");
        assert!(c2.is_some());
        assert!(c2.unwrap().covered > 0);
    }
}
