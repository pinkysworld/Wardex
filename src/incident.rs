use crate::event_forward::StoredEvent;
use crate::telemetry::MitreAttack;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IncidentStatus {
    Open,
    Investigating,
    Contained,
    Resolved,
    FalsePositive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventNote {
    pub author: String,
    pub timestamp: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Incident {
    pub id: u64,
    pub title: String,
    pub severity: String,
    pub status: IncidentStatus,
    pub created_at: String,
    pub updated_at: String,
    pub event_ids: Vec<u64>,
    pub agent_ids: Vec<String>,
    pub mitre_techniques: Vec<MitreAttack>,
    pub summary: String,
    pub assignee: Option<String>,
    pub notes: Vec<EventNote>,
}

pub struct IncidentStore {
    pub incidents: Vec<Incident>,
    next_id: u64,
    store_path: String,
}

impl IncidentStore {
    pub fn new(store_path: &str) -> Self {
        // Canonicalize parent directory to prevent path-traversal
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
        let mut store = IncidentStore {
            incidents: Vec::new(),
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
            && let Ok(incidents) = serde_json::from_str::<Vec<Incident>>(&content)
        {
            self.next_id = incidents
                .iter()
                .map(|i| i.id)
                .max()
                .unwrap_or(0)
                .saturating_add(1);
            self.incidents = incidents;
        }
    }

    fn persist(&self) {
        let path = Path::new(&self.store_path);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(&self.incidents) {
            let tmp = format!("{}.tmp", self.store_path);
            if std::fs::write(&tmp, &json).is_ok()
                && let Err(e) = std::fs::rename(&tmp, path)
            {
                eprintln!("[WARN] incident persist rename failed: {e}");
            }
        }
    }

    pub fn create(
        &mut self,
        title: String,
        severity: String,
        event_ids: Vec<u64>,
        agent_ids: Vec<String>,
        mitre: Vec<MitreAttack>,
        summary: String,
    ) -> &Incident {
        let now = chrono::Utc::now().to_rfc3339();
        let incident = Incident {
            id: self.next_id,
            title,
            severity,
            status: IncidentStatus::Open,
            created_at: now.clone(),
            updated_at: now,
            event_ids,
            agent_ids,
            mitre_techniques: mitre,
            summary,
            assignee: None,
            notes: Vec::new(),
        };
        self.next_id += 1;
        self.incidents.push(incident);
        self.persist();
        self.incidents.last().unwrap()
    }

    pub fn get(&self, id: u64) -> Option<&Incident> {
        self.incidents.iter().find(|i| i.id == id)
    }

    pub fn update_status(&mut self, id: u64, status: IncidentStatus) -> Result<(), String> {
        let now = chrono::Utc::now().to_rfc3339();
        match self.incidents.iter_mut().find(|i| i.id == id) {
            Some(inc) => {
                inc.status = status;
                inc.updated_at = now;
                self.persist();
                Ok(())
            }
            None => Err("incident not found".into()),
        }
    }

    pub fn update(
        &mut self,
        id: u64,
        assignee: Option<String>,
        note: Option<EventNote>,
        status: Option<IncidentStatus>,
    ) -> Result<(), String> {
        let now = chrono::Utc::now().to_rfc3339();
        match self.incidents.iter_mut().find(|i| i.id == id) {
            Some(inc) => {
                if let Some(a) = assignee {
                    inc.assignee = Some(a);
                }
                if let Some(n) = note {
                    inc.notes.push(n);
                }
                if let Some(s) = status {
                    inc.status = s;
                }
                inc.updated_at = now;
                self.persist();
                Ok(())
            }
            None => Err("incident not found".into()),
        }
    }

    pub fn list(&self) -> &[Incident] {
        &self.incidents
    }

    pub fn list_filtered(&self, status: Option<&str>, severity: Option<&str>) -> Vec<&Incident> {
        self.incidents
            .iter()
            .filter(|i| {
                if let Some(s) = status {
                    let status_str = match &i.status {
                        IncidentStatus::Open => "open",
                        IncidentStatus::Investigating => "investigating",
                        IncidentStatus::Contained => "contained",
                        IncidentStatus::Resolved => "resolved",
                        IncidentStatus::FalsePositive => "false_positive",
                    };
                    if status_str != s {
                        return false;
                    }
                }
                if let Some(sev) = severity
                    && i.severity != sev
                {
                    return false;
                }
                true
            })
            .collect()
    }

    /// Auto-cluster events into incidents based on MITRE technique + time window.
    pub fn auto_cluster(&mut self, events: &[StoredEvent]) -> Vec<u64> {
        let mut new_incident_ids = Vec::new();
        if events.is_empty() {
            return new_incident_ids;
        }

        // Group by MITRE technique within 5-minute windows
        let mut technique_groups: std::collections::HashMap<String, Vec<&StoredEvent>> =
            std::collections::HashMap::new();
        for event in events {
            for mitre in &event.alert.mitre {
                technique_groups
                    .entry(mitre.technique_id.clone())
                    .or_default()
                    .push(event);
            }
        }

        for (technique_id, group) in &technique_groups {
            if group.len() < 2 {
                continue;
            }
            // Check if events are within 5-minute window
            let timestamps: Vec<_> = group
                .iter()
                .filter_map(|e| chrono::DateTime::parse_from_rfc3339(&e.received_at).ok())
                .collect();
            if timestamps.len() < 2 {
                continue;
            }
            let (Some(min_ts), Some(max_ts)) = (timestamps.iter().min(), timestamps.iter().max())
            else {
                continue;
            };
            let span = max_ts.signed_duration_since(*min_ts);
            if span.num_seconds() > 300 {
                continue;
            }

            // Check if these events already belong to an open incident
            let event_ids: Vec<u64> = group.iter().map(|e| e.id).collect();
            let already_covered = self.incidents.iter().any(|inc| {
                matches!(
                    inc.status,
                    IncidentStatus::Open | IncidentStatus::Investigating
                ) && event_ids.iter().any(|eid| inc.event_ids.contains(eid))
            });
            if already_covered {
                // Merge new event_ids into the FIRST matching open/investigating incident
                if let Some(inc) = self.incidents.iter_mut().find(|inc| {
                    matches!(
                        inc.status,
                        IncidentStatus::Open | IncidentStatus::Investigating
                    ) && event_ids.iter().any(|eid| inc.event_ids.contains(eid))
                }) {
                    for eid in &event_ids {
                        if !inc.event_ids.contains(eid) {
                            inc.event_ids.push(*eid);
                        }
                    }
                    inc.updated_at = chrono::Utc::now().to_rfc3339();
                }
                continue;
            }

            let agent_ids: Vec<String> = group
                .iter()
                .map(|e| e.agent_id.clone())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();

            let mitre_tech: Vec<MitreAttack> = group
                .iter()
                .flat_map(|e| e.alert.mitre.clone())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();

            let severity = group
                .iter()
                .map(|e| e.alert.level.as_str())
                .max_by_key(|l| match *l {
                    "Critical" => 4,
                    "Severe" => 3,
                    "Elevated" => 2,
                    _ => 1,
                })
                .unwrap_or("Elevated")
                .to_string();

            let title = format!("{} cluster across {} agents", technique_id, agent_ids.len());
            let summary = format!(
                "Auto-detected cluster of {} events matching technique {} within {:.0}s window",
                event_ids.len(),
                technique_id,
                span.num_seconds()
            );

            let inc = self.create(title, severity, event_ids, agent_ids, mitre_tech, summary);
            new_incident_ids.push(inc.id);
        }

        // Also cluster same-agent severe+ events within 2-minute window
        let mut agent_severe: std::collections::HashMap<&str, Vec<&StoredEvent>> =
            std::collections::HashMap::new();
        for event in events {
            if matches!(event.alert.level.as_str(), "Critical" | "Severe") {
                agent_severe.entry(&event.agent_id).or_default().push(event);
            }
        }
        for (agent_id, group) in &agent_severe {
            if group.len() < 2 {
                continue;
            }
            let timestamps: Vec<_> = group
                .iter()
                .filter_map(|e| chrono::DateTime::parse_from_rfc3339(&e.received_at).ok())
                .collect();
            if timestamps.len() < 2 {
                continue;
            }
            let (Some(min_ts), Some(max_ts)) = (timestamps.iter().min(), timestamps.iter().max())
            else {
                continue;
            };
            if max_ts.signed_duration_since(*min_ts).num_seconds() > 120 {
                continue;
            }
            let event_ids: Vec<u64> = group.iter().map(|e| e.id).collect();
            let already_covered = self.incidents.iter().any(|inc| {
                matches!(
                    inc.status,
                    IncidentStatus::Open | IncidentStatus::Investigating
                ) && event_ids.iter().any(|eid| inc.event_ids.contains(eid))
            });
            if already_covered {
                // Merge new event_ids into the FIRST matching open/investigating incident
                if let Some(inc) = self.incidents.iter_mut().find(|inc| {
                    matches!(
                        inc.status,
                        IncidentStatus::Open | IncidentStatus::Investigating
                    ) && event_ids.iter().any(|eid| inc.event_ids.contains(eid))
                }) {
                    for eid in &event_ids {
                        if !inc.event_ids.contains(eid) {
                            inc.event_ids.push(*eid);
                        }
                    }
                    inc.updated_at = chrono::Utc::now().to_rfc3339();
                }
                continue;
            }
            let mitre: Vec<MitreAttack> =
                group.iter().flat_map(|e| e.alert.mitre.clone()).collect();
            let title = format!("Severe event burst on {}", agent_id);
            let summary = format!(
                "{} severe+ events on agent {} within 2-minute window",
                event_ids.len(),
                agent_id
            );
            let inc = self.create(
                title,
                "Severe".into(),
                event_ids,
                vec![agent_id.to_string()],
                mitre,
                summary,
            );
            new_incident_ids.push(inc.id);
        }

        self.persist();
        new_incident_ids
    }
}

// Need Hash for MitreAttack dedup
impl std::hash::Hash for MitreAttack {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.technique_id.hash(state);
        self.tactic.hash(state);
    }
}
impl Eq for MitreAttack {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::AlertRecord;
    use crate::telemetry::TelemetrySample;

    fn make_event(
        id: u64,
        agent: &str,
        level: &str,
        mitre_id: &str,
        timestamp: &str,
    ) -> StoredEvent {
        StoredEvent {
            id,
            agent_id: agent.to_string(),
            received_at: timestamp.to_string(),
            alert: AlertRecord {
                timestamp: timestamp.to_string(),
                hostname: agent.to_string(),
                platform: "linux".to_string(),
                score: 5.0,
                confidence: 0.9,
                level: level.to_string(),
                action: "alert".to_string(),
                reasons: vec!["test".to_string()],
                sample: TelemetrySample {
                    timestamp_ms: 0,
                    cpu_load_pct: 0.0,
                    memory_load_pct: 0.0,
                    temperature_c: 0.0,
                    network_kbps: 0.0,
                    auth_failures: 0,
                    battery_pct: 100.0,
                    integrity_drift: 0.0,
                    process_count: 0,
                    disk_pressure_pct: 0.0,
                },
                enforced: false,
                mitre: vec![MitreAttack {
                    tactic: "Test".into(),
                    technique_id: mitre_id.into(),
                    technique_name: "Test Technique".into(),
                }],
                narrative: None,
            },
            correlated: false,
            triage: crate::event_forward::EventTriage::default(),
        }
    }

    #[test]
    fn create_and_update_incident() {
        let dir = std::env::temp_dir().join("wardex_test_incidents");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("incidents.json");
        let mut store = IncidentStore::new(path.to_str().unwrap());

        let inc = store.create(
            "Test incident".into(),
            "Critical".into(),
            vec![1, 2],
            vec!["agent-1".into()],
            vec![],
            "Test summary".into(),
        );
        assert_eq!(inc.id, 1);
        assert_eq!(inc.status, IncidentStatus::Open);

        store
            .update_status(1, IncidentStatus::Investigating)
            .unwrap();
        assert_eq!(store.get(1).unwrap().status, IncidentStatus::Investigating);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn auto_cluster_by_mitre_technique() {
        let dir = std::env::temp_dir().join("wardex_test_cluster");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("cluster.json");
        let mut store = IncidentStore::new(path.to_str().unwrap());

        let events = vec![
            make_event(1, "agent-1", "Severe", "T1110", "2025-01-01T00:00:00Z"),
            make_event(2, "agent-2", "Critical", "T1110", "2025-01-01T00:02:00Z"),
            make_event(3, "agent-1", "Elevated", "T1110", "2025-01-01T00:03:00Z"),
        ];

        let new_ids = store.auto_cluster(&events);
        assert!(!new_ids.is_empty());
        let inc = store.get(new_ids[0]).unwrap();
        assert!(inc.event_ids.contains(&1));
        assert!(inc.event_ids.contains(&2));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn auto_cluster_same_agent_severe_burst() {
        let dir = std::env::temp_dir().join("wardex_test_burst");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("burst.json");
        let mut store = IncidentStore::new(path.to_str().unwrap());

        let events = vec![
            make_event(10, "agent-x", "Severe", "T9999", "2025-01-01T00:00:00Z"),
            make_event(11, "agent-x", "Critical", "T8888", "2025-01-01T00:01:00Z"),
        ];

        let new_ids = store.auto_cluster(&events);
        assert!(!new_ids.is_empty());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn auto_cluster_merges_into_first_matching_incident() {
        let dir = std::env::temp_dir().join("wardex_test_multi_merge");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("multi_merge.json");
        let mut store = IncidentStore::new(path.to_str().unwrap());

        // Create two open incidents sharing event_id 1
        store.create(
            "Inc A".into(),
            "Severe".into(),
            vec![1, 2],
            vec!["agent-1".into()],
            vec![],
            "A".into(),
        );
        store.create(
            "Inc B".into(),
            "Severe".into(),
            vec![1, 3],
            vec!["agent-2".into()],
            vec![],
            "B".into(),
        );

        // Now auto-cluster events that overlap with event_id 1
        let events = vec![
            make_event(1, "agent-1", "Severe", "T1110", "2025-01-01T00:00:00Z"),
            make_event(4, "agent-3", "Critical", "T1110", "2025-01-01T00:01:00Z"),
        ];
        store.auto_cluster(&events);

        // Only the FIRST matching incident should receive event_id 4
        // (merging into all would cause duplicate events across incidents)
        let inc_a = store.get(1).unwrap();
        let inc_b = store.get(2).unwrap();
        assert!(inc_a.event_ids.contains(&4), "Inc A should have event 4");
        assert!(
            !inc_b.event_ids.contains(&4),
            "Inc B should NOT have event 4 (single-merge)"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn list_filtered_by_status() {
        let dir = std::env::temp_dir().join("wardex_test_filter");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("filter.json");
        let mut store = IncidentStore::new(path.to_str().unwrap());

        store.create(
            "Inc 1".into(),
            "Critical".into(),
            vec![],
            vec![],
            vec![],
            "".into(),
        );
        store.create(
            "Inc 2".into(),
            "Elevated".into(),
            vec![],
            vec![],
            vec![],
            "".into(),
        );
        store.update_status(1, IncidentStatus::Resolved).unwrap();

        let open = store.list_filtered(Some("open"), None);
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].id, 2);

        let _ = std::fs::remove_file(&path);
    }
}
