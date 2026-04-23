//! Guided investigation workflows.
//!
//! Provides step-by-step analyst guidance for common investigation
//! scenarios with pre-built pivots, recommended actions, and
//! checklists.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A step in an investigation workflow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationStep {
    pub order: usize,
    pub title: String,
    pub description: String,
    pub api_pivot: Option<String>,
    pub recommended_actions: Vec<String>,
    pub evidence_to_collect: Vec<String>,
    pub auto_queries: Vec<AutoQuery>,
}

/// A pre-built query to run as part of a step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoQuery {
    pub name: String,
    pub endpoint: String,
    pub description: String,
}

/// A complete investigation workflow template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationWorkflow {
    pub id: String,
    pub name: String,
    pub description: String,
    pub trigger_conditions: Vec<String>,
    pub severity: String,
    pub mitre_techniques: Vec<String>,
    pub estimated_minutes: u32,
    pub steps: Vec<InvestigationStep>,
    pub completion_criteria: Vec<String>,
}

/// Investigation progress tracker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationProgress {
    pub id: String,
    pub workflow_id: String,
    pub case_id: Option<String>,
    pub analyst: String,
    pub started_at: String,
    pub updated_at: String,
    pub completed_steps: Vec<usize>,
    pub notes: HashMap<usize, String>,
    pub status: String,
    pub findings: Vec<String>,
    pub handoff: Option<InvestigationHandoff>,
}

/// Structured analyst handoff attached to an active investigation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationHandoff {
    pub from_analyst: String,
    pub to_analyst: String,
    pub summary: String,
    pub next_actions: Vec<String>,
    pub questions: Vec<String>,
    pub updated_at: String,
}

/// Investigation progress enriched with workflow metadata for UI consumption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvestigationSnapshot {
    pub id: String,
    pub workflow_id: String,
    pub workflow_name: String,
    pub workflow_description: String,
    pub workflow_severity: String,
    pub mitre_techniques: Vec<String>,
    pub estimated_minutes: u32,
    pub case_id: Option<String>,
    pub analyst: String,
    pub started_at: String,
    pub updated_at: String,
    pub completed_steps: Vec<usize>,
    pub notes: HashMap<usize, String>,
    pub status: String,
    pub findings: Vec<String>,
    pub handoff: Option<InvestigationHandoff>,
    pub total_steps: usize,
    pub completion_percent: u8,
    pub next_step: Option<InvestigationStep>,
    pub steps: Vec<InvestigationStep>,
    pub completion_criteria: Vec<String>,
}

/// Investigation workflow store.
pub struct WorkflowStore {
    workflows: Vec<InvestigationWorkflow>,
    progress: Vec<InvestigationProgress>,
    next_progress_id: u64,
}

impl Default for WorkflowStore {
    fn default() -> Self {
        Self::new()
    }
}

impl WorkflowStore {
    pub fn new() -> Self {
        Self {
            workflows: builtin_workflows(),
            progress: Vec::new(),
            next_progress_id: 1,
        }
    }

    pub fn list_workflows(&self) -> &[InvestigationWorkflow] {
        &self.workflows
    }

    pub fn get_workflow(&self, id: &str) -> Option<&InvestigationWorkflow> {
        self.workflows.iter().find(|w| w.id == id)
    }

    pub fn start_investigation(
        &mut self,
        workflow_id: &str,
        analyst: &str,
        case_id: Option<String>,
    ) -> Option<InvestigationProgress> {
        if self.workflows.iter().any(|w| w.id == workflow_id) {
            let now = chrono::Utc::now().to_rfc3339();
            let progress = InvestigationProgress {
                id: format!("inv-{}", self.next_progress_id),
                workflow_id: workflow_id.to_string(),
                case_id,
                analyst: analyst.to_string(),
                started_at: now.clone(),
                updated_at: now,
                completed_steps: Vec::new(),
                notes: HashMap::new(),
                status: "in-progress".into(),
                findings: Vec::new(),
                handoff: None,
            };
            self.next_progress_id += 1;
            self.progress.push(progress.clone());
            Some(progress)
        } else {
            None
        }
    }

    pub fn complete_step(
        &mut self,
        workflow_id: &str,
        analyst: &str,
        step: usize,
        note: Option<String>,
    ) {
        if let Some(p) = self.progress.iter_mut().find(|p| {
            p.workflow_id == workflow_id && p.analyst == analyst && p.status == "in-progress"
        }) {
            if !p.completed_steps.contains(&step) {
                p.completed_steps.push(step);
                p.completed_steps.sort_unstable();
            }
            if let Some(n) = note {
                p.notes.insert(step, n);
            }
            p.updated_at = chrono::Utc::now().to_rfc3339();
        }
    }

    pub fn active_investigations(&self) -> Vec<&InvestigationProgress> {
        self.progress
            .iter()
            .filter(|p| is_active_status(&p.status))
            .collect()
    }

    pub fn active_snapshots(&self) -> Vec<InvestigationSnapshot> {
        self.progress
            .iter()
            .filter(|progress| is_active_status(&progress.status))
            .filter_map(|progress| self.snapshot_for_progress(progress))
            .collect()
    }

    pub fn get_snapshot(&self, investigation_id: &str) -> Option<InvestigationSnapshot> {
        self.progress
            .iter()
            .find(|progress| progress.id == investigation_id)
            .and_then(|progress| self.snapshot_for_progress(progress))
    }

    pub fn update_investigation(
        &mut self,
        investigation_id: &str,
        step: Option<usize>,
        completed: Option<bool>,
        note: Option<String>,
        status: Option<String>,
        finding: Option<String>,
    ) -> Option<InvestigationSnapshot> {
        let progress_index = self
            .progress
            .iter()
            .position(|progress| progress.id == investigation_id)?;
        let workflow_id = self.progress[progress_index].workflow_id.clone();
        let valid_steps = self
            .get_workflow(&workflow_id)?
            .steps
            .iter()
            .map(|entry| entry.order)
            .collect::<Vec<_>>();
        let status_provided = status.is_some();

        {
            let progress = &mut self.progress[progress_index];
            if let Some(step_order) = step {
                if !valid_steps.contains(&step_order) {
                    return None;
                }

                if let Some(is_completed) = completed {
                    if is_completed {
                        if !progress.completed_steps.contains(&step_order) {
                            progress.completed_steps.push(step_order);
                        }
                        progress.completed_steps.sort_unstable();
                    } else {
                        progress.completed_steps.retain(|entry| *entry != step_order);
                    }
                }

                if let Some(step_note) = note {
                    let trimmed = step_note.trim().to_string();
                    if trimmed.is_empty() {
                        progress.notes.remove(&step_order);
                    } else {
                        progress.notes.insert(step_order, trimmed);
                    }
                }
            }

            if let Some(status_value) = status
                && !status_value.trim().is_empty()
            {
                progress.status = status_value.trim().to_string();
            }

            if let Some(finding_text) = finding {
                let trimmed = finding_text.trim().to_string();
                if !trimmed.is_empty()
                    && !progress
                        .findings
                        .iter()
                        .any(|entry| entry.eq_ignore_ascii_case(&trimmed))
                {
                    progress.findings.push(trimmed);
                }
            }

            if !status_provided {
                let all_completed = !valid_steps.is_empty()
                    && valid_steps
                        .iter()
                        .all(|step_order| progress.completed_steps.contains(step_order));
                progress.status = if all_completed {
                    "completed".into()
                } else {
                    "in-progress".into()
                };
            }

            progress.updated_at = chrono::Utc::now().to_rfc3339();
        }

        self.get_snapshot(investigation_id)
    }

    pub fn record_handoff(
        &mut self,
        investigation_id: &str,
        to_analyst: String,
        summary: String,
        next_actions: Vec<String>,
        questions: Vec<String>,
    ) -> Option<InvestigationSnapshot> {
        let progress = self
            .progress
            .iter_mut()
            .find(|progress| progress.id == investigation_id)?;
        let now = chrono::Utc::now().to_rfc3339();
        let from_analyst = progress.analyst.clone();
        let next_owner = to_analyst.trim().to_string();
        progress.handoff = Some(InvestigationHandoff {
            from_analyst,
            to_analyst: next_owner.clone(),
            summary: summary.trim().to_string(),
            next_actions,
            questions,
            updated_at: now.clone(),
        });
        progress.analyst = next_owner;
        progress.status = "handoff-ready".into();
        progress.updated_at = now;
        self.get_snapshot(investigation_id)
    }

    pub fn workflow_count(&self) -> usize {
        self.workflows.len()
    }

    /// Suggest a workflow based on alert type.
    pub fn suggest_for_alert(&self, alert_reasons: &[String]) -> Vec<&InvestigationWorkflow> {
        let reasons_lower: Vec<String> = alert_reasons.iter().map(|r| r.to_lowercase()).collect();
        self.workflows
            .iter()
            .filter(|w| {
                w.trigger_conditions.iter().any(|tc| {
                    let tc_lower = tc.to_lowercase();
                    reasons_lower
                        .iter()
                        .any(|r| r.contains(&tc_lower) || tc_lower.contains(r.as_str()))
                })
            })
            .collect()
    }

    fn snapshot_for_progress(
        &self,
        progress: &InvestigationProgress,
    ) -> Option<InvestigationSnapshot> {
        let workflow = self.get_workflow(&progress.workflow_id)?;
        let total_steps = workflow.steps.len();
        let completed_count = progress.completed_steps.len().min(total_steps);
        let completion_percent = if total_steps == 0 {
            0
        } else {
            ((completed_count * 100) / total_steps) as u8
        };
        let next_step = workflow
            .steps
            .iter()
            .find(|step| !progress.completed_steps.contains(&step.order))
            .cloned();

        Some(InvestigationSnapshot {
            id: progress.id.clone(),
            workflow_id: progress.workflow_id.clone(),
            workflow_name: workflow.name.clone(),
            workflow_description: workflow.description.clone(),
            workflow_severity: workflow.severity.clone(),
            mitre_techniques: workflow.mitre_techniques.clone(),
            estimated_minutes: workflow.estimated_minutes,
            case_id: progress.case_id.clone(),
            analyst: progress.analyst.clone(),
            started_at: progress.started_at.clone(),
            updated_at: progress.updated_at.clone(),
            completed_steps: progress.completed_steps.clone(),
            notes: progress.notes.clone(),
            status: progress.status.clone(),
            findings: progress.findings.clone(),
            handoff: progress.handoff.clone(),
            total_steps,
            completion_percent,
            next_step,
            steps: workflow.steps.clone(),
            completion_criteria: workflow.completion_criteria.clone(),
        })
    }
}

fn is_active_status(status: &str) -> bool {
    !matches!(status, "completed" | "closed" | "resolved")
}

fn builtin_workflows() -> Vec<InvestigationWorkflow> {
    vec![
        InvestigationWorkflow {
            id: "credential-storm".into(),
            name: "Investigate Credential Storm".into(),
            description: "Step-by-step investigation for brute-force or credential stuffing attacks".into(),
            trigger_conditions: vec!["auth_failure".into(), "credential".into(), "brute_force".into(), "login".into()],
            severity: "High".into(),
            mitre_techniques: vec!["T1110".into(), "T1110.001".into(), "T1110.003".into()],
            estimated_minutes: 30,
            steps: vec![
                InvestigationStep {
                    order: 1,
                    title: "Identify affected accounts".into(),
                    description: "Query UEBA for entities with high auth failure rates".into(),
                    api_pivot: Some("/api/ueba/risky".into()),
                    recommended_actions: vec!["List top entities by auth failure count".into()],
                    evidence_to_collect: vec!["Affected usernames".into(), "Source IPs".into()],
                    auto_queries: vec![AutoQuery { name: "Risky entities".into(), endpoint: "/api/ueba/risky".into(), description: "Get entities with anomalous auth patterns".into() }],
                },
                InvestigationStep {
                    order: 2,
                    title: "Determine attack scope".into(),
                    description: "Check if the attack is targeted (single account) or broad (many accounts)".into(),
                    api_pivot: Some("/api/events?severity=critical".into()),
                    recommended_actions: vec!["Count unique target accounts".into(), "Map source IP geolocation".into()],
                    evidence_to_collect: vec!["Attack window".into(), "Number of targets".into()],
                    auto_queries: vec![],
                },
                InvestigationStep {
                    order: 3,
                    title: "Check for successful compromise".into(),
                    description: "Look for auth successes following failures — indicates credential was guessed".into(),
                    api_pivot: Some("/api/events?reason=auth".into()),
                    recommended_actions: vec!["Search for auth success events from attack IPs".into()],
                    evidence_to_collect: vec!["Compromised accounts".into()],
                    auto_queries: vec![AutoQuery { name: "Lateral movement".into(), endpoint: "/api/lateral/analyze".into(), description: "Check for cross-host movement after compromise".into() }],
                },
                InvestigationStep {
                    order: 4,
                    title: "Contain and respond".into(),
                    description: "Block source IPs, reset compromised credentials, notify account owners".into(),
                    api_pivot: Some("/api/response/request".into()),
                    recommended_actions: vec!["Block attacking IPs at firewall".into(), "Force password reset".into(), "Enable MFA for affected accounts".into()],
                    evidence_to_collect: vec!["Response actions taken".into()],
                    auto_queries: vec![],
                },
            ],
            completion_criteria: vec![
                "All compromised accounts identified".into(),
                "Source IPs blocked".into(),
                "Passwords reset for compromised accounts".into(),
                "Incident report filed".into(),
            ],
        },
        InvestigationWorkflow {
            id: "ransomware-triage".into(),
            name: "Triage Ransomware Alert".into(),
            description: "Rapid triage of a potential ransomware infection".into(),
            trigger_conditions: vec!["ransomware".into(), "encryption".into(), "file_velocity".into(), "canary".into()],
            severity: "Critical".into(),
            mitre_techniques: vec!["T1486".into(), "T1490".into()],
            estimated_minutes: 15,
            steps: vec![
                InvestigationStep {
                    order: 1,
                    title: "Assess scope immediately".into(),
                    description: "Determine how many hosts show ransomware signals".into(),
                    api_pivot: Some("/api/alerts?severity=critical".into()),
                    recommended_actions: vec!["Check file change velocity across fleet".into()],
                    evidence_to_collect: vec!["Affected host count".into(), "File extensions changed".into()],
                    auto_queries: vec![],
                },
                InvestigationStep {
                    order: 2,
                    title: "Isolate affected hosts".into(),
                    description: "Network-isolate compromised hosts to stop lateral spread".into(),
                    api_pivot: Some("/api/response/request".into()),
                    recommended_actions: vec!["Issue isolate command for all affected hosts".into(), "Block C2 IPs at perimeter".into()],
                    evidence_to_collect: vec!["Isolation confirmation".into()],
                    auto_queries: vec![AutoQuery { name: "Beacon analysis".into(), endpoint: "/api/beacon/analyze".into(), description: "Identify C2 callbacks".into() }],
                },
                InvestigationStep {
                    order: 3,
                    title: "Identify initial access vector".into(),
                    description: "Trace back to patient zero and initial compromise method".into(),
                    api_pivot: Some("/api/killchain/reconstruct".into()),
                    recommended_actions: vec!["Review process trees on first-affected host".into(), "Check email gateway logs".into()],
                    evidence_to_collect: vec!["Initial access vector".into(), "Patient zero hostname".into()],
                    auto_queries: vec![AutoQuery { name: "Kill chain".into(), endpoint: "/api/killchain/reconstruct".into(), description: "Reconstruct attack timeline".into() }],
                },
                InvestigationStep {
                    order: 4,
                    title: "Preserve evidence and recover".into(),
                    description: "Collect forensic images, start recovery from backups".into(),
                    api_pivot: Some("/api/evidence/plan/linux".into()),
                    recommended_actions: vec!["Capture forensic images".into(), "Verify backup integrity".into(), "Begin restoration".into()],
                    evidence_to_collect: vec!["Forensic images".into(), "Backup status".into()],
                    auto_queries: vec![],
                },
            ],
            completion_criteria: vec![
                "All affected hosts isolated".into(),
                "Initial access vector identified".into(),
                "Forensic evidence preserved".into(),
                "Recovery initiated from clean backups".into(),
            ],
        },
        InvestigationWorkflow {
            id: "lateral-movement".into(),
            name: "Investigate Lateral Movement".into(),
            description: "Trace and contain cross-host lateral movement".into(),
            trigger_conditions: vec!["lateral".into(), "ssh".into(), "rdp".into(), "smb".into(), "pass_the_hash".into()],
            severity: "High".into(),
            mitre_techniques: vec!["T1021".into(), "T1550".into(), "T1076".into()],
            estimated_minutes: 45,
            steps: vec![
                InvestigationStep {
                    order: 1,
                    title: "Map movement paths".into(),
                    description: "Identify all hosts in the lateral chain".into(),
                    api_pivot: Some("/api/lateral/analyze".into()),
                    recommended_actions: vec!["Export full lateral movement graph".into()],
                    evidence_to_collect: vec!["Hop list".into(), "Credentials used".into()],
                    auto_queries: vec![AutoQuery { name: "Lateral paths".into(), endpoint: "/api/lateral/analyze".into(), description: "Full lateral movement analysis".into() }],
                },
                InvestigationStep {
                    order: 2,
                    title: "Check credential reuse".into(),
                    description: "Determine if a single credential was used across multiple hosts".into(),
                    api_pivot: Some("/api/ueba/risky".into()),
                    recommended_actions: vec!["Identify shared credentials".into(), "Check service account usage".into()],
                    evidence_to_collect: vec!["Reused credentials".into()],
                    auto_queries: vec![],
                },
                InvestigationStep {
                    order: 3,
                    title: "Contain spread".into(),
                    description: "Segment network and rotate compromised credentials".into(),
                    api_pivot: Some("/api/response/request".into()),
                    recommended_actions: vec!["Segment affected network zone".into(), "Rotate all compromised credentials".into(), "Review privilege escalation events".into()],
                    evidence_to_collect: vec!["Containment actions".into()],
                    auto_queries: vec![],
                },
            ],
            completion_criteria: vec![
                "All hop hosts identified and contained".into(),
                "Compromised credentials rotated".into(),
                "Network segmentation verified".into(),
            ],
        },
        InvestigationWorkflow {
            id: "c2-beacon".into(),
            name: "Investigate C2 Beacon".into(),
            description: "Investigate and block command-and-control communication".into(),
            trigger_conditions: vec!["beacon".into(), "c2".into(), "callback".into(), "dga".into(), "dns_tunnel".into()],
            severity: "Critical".into(),
            mitre_techniques: vec!["T1071".into(), "T1568".into(), "T1573".into()],
            estimated_minutes: 30,
            steps: vec![
                InvestigationStep {
                    order: 1,
                    title: "Confirm C2 activity".into(),
                    description: "Review beacon analysis to confirm regular callback pattern".into(),
                    api_pivot: Some("/api/beacon/analyze".into()),
                    recommended_actions: vec!["Verify beacon interval and jitter".into(), "Check destination reputation".into()],
                    evidence_to_collect: vec!["C2 IP/domain".into(), "Beacon interval".into(), "Affected host".into()],
                    auto_queries: vec![AutoQuery { name: "Beacon scan".into(), endpoint: "/api/beacon/analyze".into(), description: "Full beacon analysis".into() }],
                },
                InvestigationStep {
                    order: 2,
                    title: "Identify implant".into(),
                    description: "Find the process responsible for C2 communication".into(),
                    api_pivot: Some("/api/processes/analysis".into()),
                    recommended_actions: vec!["Correlate beacon times with process activity".into(), "Check for persistence mechanisms".into()],
                    evidence_to_collect: vec!["Implant process name/path".into(), "Persistence method".into()],
                    auto_queries: vec![AutoQuery { name: "Process analysis".into(), endpoint: "/api/processes/analysis".into(), description: "Suspicious process detection".into() }],
                },
                InvestigationStep {
                    order: 3,
                    title: "Block and eradicate".into(),
                    description: "Block C2 infrastructure and remove implant".into(),
                    api_pivot: Some("/api/response/request".into()),
                    recommended_actions: vec!["Block C2 domains/IPs at DNS and firewall".into(), "Kill implant process".into(), "Remove persistence".into(), "Scan for additional implants".into()],
                    evidence_to_collect: vec!["Blocked indicators".into(), "Eradication confirmation".into()],
                    auto_queries: vec![],
                },
            ],
            completion_criteria: vec![
                "C2 infrastructure blocked".into(),
                "Implant process terminated".into(),
                "Persistence removed".into(),
                "No further beacon activity detected".into(),
            ],
        },
        InvestigationWorkflow {
            id: "container-escape".into(),
            name: "Investigate Container Escape".into(),
            description: "Investigate and contain a container breakout attempt".into(),
            trigger_conditions: vec!["container_escape".into(), "namespace_escape".into(), "privileged".into(), "container".into()],
            severity: "Critical".into(),
            mitre_techniques: vec!["T1611".into()],
            estimated_minutes: 20,
            steps: vec![
                InvestigationStep {
                    order: 1,
                    title: "Identify escape method".into(),
                    description: "Determine how the container escaped (CVE, misconfiguration, privileged mode)".into(),
                    api_pivot: Some("/api/container/alerts".into()),
                    recommended_actions: vec!["Check container capabilities".into(), "Review volume mounts".into()],
                    evidence_to_collect: vec!["Container ID".into(), "Escape vector".into(), "Image name".into()],
                    auto_queries: vec![AutoQuery { name: "Container alerts".into(), endpoint: "/api/container/alerts".into(), description: "Container security alerts".into() }],
                },
                InvestigationStep {
                    order: 2,
                    title: "Assess host compromise".into(),
                    description: "Determine if the host kernel/filesystem was accessed".into(),
                    api_pivot: Some("/api/processes/live".into()),
                    recommended_actions: vec!["Review host processes for anomalies".into(), "Check FIM for host filesystem changes".into()],
                    evidence_to_collect: vec!["Host-level indicators".into()],
                    auto_queries: vec![],
                },
                InvestigationStep {
                    order: 3,
                    title: "Contain and remediate".into(),
                    description: "Kill container, patch vulnerability, harden runtime".into(),
                    api_pivot: Some("/api/response/request".into()),
                    recommended_actions: vec!["Stop affected container".into(), "Update container runtime".into(), "Apply seccomp/AppArmor profiles".into(), "Restrict capabilities".into()],
                    evidence_to_collect: vec!["Remediation actions".into()],
                    auto_queries: vec![],
                },
            ],
            completion_criteria: vec![
                "Escape method identified".into(),
                "Affected container terminated".into(),
                "Runtime vulnerability patched".into(),
                "Host integrity verified".into(),
            ],
        },
    ]
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_workflows_load() {
        let store = WorkflowStore::new();
        assert!(store.workflow_count() >= 5);
    }

    #[test]
    fn suggest_for_credential_alert() {
        let store = WorkflowStore::new();
        let suggestions = store.suggest_for_alert(&["high auth_failure rate".to_string()]);
        assert!(!suggestions.is_empty());
        assert!(suggestions.iter().any(|w| w.id == "credential-storm"));
    }

    #[test]
    fn start_and_track_investigation() {
        let mut store = WorkflowStore::new();
        let progress = store.start_investigation("credential-storm", "analyst-1", None);
        assert!(progress.is_some());
        assert_eq!(progress.as_ref().map(|entry| entry.id.as_str()), Some("inv-1"));
        store.complete_step(
            "credential-storm",
            "analyst-1",
            1,
            Some("Found 3 targets".into()),
        );
        let active = store.active_investigations();
        assert_eq!(active.len(), 1);
        assert!(active[0].completed_steps.contains(&1));
        assert!(active[0].updated_at >= active[0].started_at);
    }

    #[test]
    fn snapshot_includes_progress_and_workflow_metadata() {
        let mut store = WorkflowStore::new();
        let progress = store
            .start_investigation("credential-storm", "analyst-1", Some("42".into()))
            .expect("investigation started");

        let snapshot = store
            .update_investigation(
                &progress.id,
                Some(1),
                Some(true),
                Some("Scoped three targeted accounts".into()),
                None,
                Some("Targeting stayed inside finance admins".into()),
            )
            .expect("snapshot after progress update");

        assert_eq!(snapshot.id, progress.id);
        assert_eq!(snapshot.workflow_id, "credential-storm");
        assert_eq!(snapshot.workflow_name, "Investigate Credential Storm");
        assert_eq!(snapshot.case_id.as_deref(), Some("42"));
        assert_eq!(snapshot.completion_percent, 25);
        assert!(snapshot.completed_steps.contains(&1));
        assert_eq!(snapshot.notes.get(&1).map(String::as_str), Some("Scoped three targeted accounts"));
        assert!(snapshot
            .findings
            .iter()
            .any(|finding| finding.contains("finance admins")));
        assert_eq!(snapshot.total_steps, 4);
        assert!(snapshot.next_step.is_some());
    }

    #[test]
    fn record_handoff_updates_active_investigation_owner() {
        let mut store = WorkflowStore::new();
        let progress = store
            .start_investigation("credential-storm", "analyst-1", Some("99".into()))
            .expect("investigation started");

        let snapshot = store
            .record_handoff(
                &progress.id,
                "analyst-2".into(),
                "Awaiting identity team validation on two suspicious sign-ins".into(),
                vec!["Confirm MFA coverage".into(), "Review VPN geolocation anomalies".into()],
                vec!["Did any of the targets reuse a service credential?".into()],
            )
            .expect("handoff snapshot");

        assert_eq!(snapshot.analyst, "analyst-2");
        assert_eq!(snapshot.status, "handoff-ready");
        assert!(snapshot.handoff.is_some());
        let handoff = snapshot.handoff.expect("handoff attached");
        assert_eq!(handoff.from_analyst, "analyst-1");
        assert_eq!(handoff.to_analyst, "analyst-2");
        assert_eq!(handoff.next_actions.len(), 2);
    }
}
