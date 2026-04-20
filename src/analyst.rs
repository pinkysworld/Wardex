use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

// ── Case Management ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CaseStatus {
    New,
    Triaging,
    Investigating,
    Escalated,
    Resolved,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CasePriority {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseComment {
    pub author: String,
    pub timestamp: String,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRef {
    pub kind: String,
    pub reference_id: String,
    pub description: String,
    pub added_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Case {
    pub id: u64,
    pub title: String,
    pub description: String,
    pub status: CaseStatus,
    pub priority: CasePriority,
    pub assignee: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub incident_ids: Vec<u64>,
    pub event_ids: Vec<u64>,
    pub tags: Vec<String>,
    pub comments: Vec<CaseComment>,
    pub evidence: Vec<EvidenceRef>,
    pub mitre_techniques: Vec<String>,
}

pub struct CaseStore {
    cases: Vec<Case>,
    next_id: u64,
    store_path: String,
}

impl CaseStore {
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
        let mut store = CaseStore {
            cases: Vec::new(),
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
            && let Ok(cases) = serde_json::from_str::<Vec<Case>>(&content)
        {
            self.next_id = cases
                .iter()
                .map(|c| c.id)
                .max()
                .unwrap_or(0)
                .saturating_add(1);
            self.cases = cases;
        }
    }

    fn persist(&self) {
        let path = Path::new(&self.store_path);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(&self.cases) {
            let tmp = format!("{}.tmp", self.store_path);
            if std::fs::write(&tmp, &json).is_ok()
                && let Err(e) = std::fs::rename(&tmp, path)
            {
                eprintln!("[WARN] case persist rename failed: {e}");
            }
        }
    }

    pub fn create(
        &mut self,
        title: String,
        description: String,
        priority: CasePriority,
        incident_ids: Vec<u64>,
        event_ids: Vec<u64>,
        tags: Vec<String>,
    ) -> &Case {
        let now = chrono::Utc::now().to_rfc3339();
        let case = Case {
            id: self.next_id,
            title,
            description,
            status: CaseStatus::New,
            priority,
            assignee: None,
            created_at: now.clone(),
            updated_at: now,
            incident_ids,
            event_ids,
            tags,
            comments: Vec::new(),
            evidence: Vec::new(),
            mitre_techniques: Vec::new(),
        };
        self.next_id += 1;
        self.cases.push(case);
        self.persist();
        // SAFETY: we just pushed, so last() is always Some
        self.cases.last().expect("cases: just pushed")
    }

    pub fn get(&self, id: u64) -> Option<&Case> {
        self.cases.iter().find(|c| c.id == id)
    }

    pub fn list(&self) -> &[Case] {
        &self.cases
    }

    pub fn update_status(&mut self, id: u64, status: CaseStatus) -> bool {
        if let Some(c) = self.cases.iter_mut().find(|c| c.id == id) {
            c.status = status;
            c.updated_at = chrono::Utc::now().to_rfc3339();
            self.persist();
            true
        } else {
            false
        }
    }

    pub fn assign(&mut self, id: u64, assignee: String) -> bool {
        if let Some(c) = self.cases.iter_mut().find(|c| c.id == id) {
            c.assignee = Some(assignee);
            c.updated_at = chrono::Utc::now().to_rfc3339();
            self.persist();
            true
        } else {
            false
        }
    }

    pub fn add_comment(&mut self, id: u64, author: String, text: String) -> bool {
        if let Some(c) = self.cases.iter_mut().find(|c| c.id == id) {
            c.comments.push(CaseComment {
                author,
                timestamp: chrono::Utc::now().to_rfc3339(),
                text,
            });
            c.updated_at = chrono::Utc::now().to_rfc3339();
            self.persist();
            true
        } else {
            false
        }
    }

    pub fn add_evidence(
        &mut self,
        id: u64,
        kind: String,
        reference_id: String,
        description: String,
    ) -> bool {
        if let Some(c) = self.cases.iter_mut().find(|c| c.id == id) {
            c.evidence.push(EvidenceRef {
                kind,
                reference_id,
                description,
                added_at: chrono::Utc::now().to_rfc3339(),
            });
            c.updated_at = chrono::Utc::now().to_rfc3339();
            self.persist();
            true
        } else {
            false
        }
    }

    pub fn link_incident(&mut self, case_id: u64, incident_id: u64) -> bool {
        if let Some(c) = self.cases.iter_mut().find(|c| c.id == case_id) {
            if !c.incident_ids.contains(&incident_id) {
                c.incident_ids.push(incident_id);
                c.updated_at = chrono::Utc::now().to_rfc3339();
                self.persist();
            }
            true
        } else {
            false
        }
    }

    pub fn list_filtered(
        &self,
        status: Option<&str>,
        priority: Option<&str>,
        assignee: Option<&str>,
    ) -> Vec<&Case> {
        self.cases
            .iter()
            .filter(|c| {
                if let Some(s) = status {
                    let cs = format!("{:?}", c.status);
                    if !cs.eq_ignore_ascii_case(s) {
                        return false;
                    }
                }
                if let Some(p) = priority {
                    let cp = format!("{:?}", c.priority);
                    if !cp.eq_ignore_ascii_case(p) {
                        return false;
                    }
                }
                if let Some(a) = assignee {
                    match &c.assignee {
                        Some(ca) if ca == a => {}
                        _ => return false,
                    }
                }
                true
            })
            .collect()
    }

    pub fn stats(&self) -> HashMap<String, usize> {
        let mut m = HashMap::new();
        for c in &self.cases {
            *m.entry(format!("{:?}", c.status)).or_insert(0) += 1;
        }
        m.insert("total".into(), self.cases.len());
        m
    }
}

// ── Alert Queue ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedAlert {
    pub event_id: u64,
    pub score: f64,
    pub level: String,
    pub hostname: String,
    pub timestamp: String,
    pub assignee: Option<String>,
    pub sla_deadline: Option<String>,
    pub acknowledged: bool,
}

pub struct AlertQueue {
    items: Vec<QueuedAlert>,
}

impl Default for AlertQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl AlertQueue {
    pub fn new() -> Self {
        AlertQueue { items: Vec::new() }
    }

    pub fn enqueue(
        &mut self,
        event_id: u64,
        score: f64,
        level: String,
        hostname: String,
        timestamp: String,
    ) {
        let normalized_level = level.trim().to_ascii_lowercase();
        let sla_hours: i64 = match normalized_level.as_str() {
            "critical" => 1,
            "severe" => 4,
            "elevated" => 24,
            _ => 72,
        };
        let deadline = chrono::Utc::now() + chrono::Duration::hours(sla_hours);
        self.items.push(QueuedAlert {
            event_id,
            score,
            level: normalized_level,
            hostname,
            timestamp,
            assignee: None,
            sla_deadline: Some(deadline.to_rfc3339()),
            acknowledged: false,
        });
        self.items.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }

    pub fn acknowledge(&mut self, event_id: u64) -> bool {
        if let Some(item) = self.items.iter_mut().find(|i| i.event_id == event_id) {
            item.acknowledged = true;
            true
        } else {
            false
        }
    }

    pub fn assign(&mut self, event_id: u64, assignee: String) -> bool {
        if let Some(item) = self.items.iter_mut().find(|i| i.event_id == event_id) {
            item.assignee = Some(assignee);
            true
        } else {
            false
        }
    }

    pub fn pending(&self) -> Vec<&QueuedAlert> {
        self.items.iter().filter(|i| !i.acknowledged).collect()
    }

    pub fn all(&self) -> &[QueuedAlert] {
        &self.items
    }

    pub fn by_assignee(&self, assignee: &str) -> Vec<&QueuedAlert> {
        self.items
            .iter()
            .filter(|i| i.assignee.as_deref() == Some(assignee))
            .collect()
    }

    pub fn dismiss(&mut self, event_id: u64) -> bool {
        let before = self.items.len();
        self.items.retain(|i| i.event_id != event_id);
        self.items.len() < before
    }

    pub fn stats(&self) -> serde_json::Value {
        let total = self.items.len();
        let pending = self.items.iter().filter(|i| !i.acknowledged).count();
        let assigned = self.items.iter().filter(|i| i.assignee.is_some()).count();
        let breached = self
            .items
            .iter()
            .filter(|i| {
                if let Some(ref deadline) = i.sla_deadline {
                    let now = chrono::Utc::now();
                    if let Ok(dl) = chrono::DateTime::parse_from_rfc3339(deadline) {
                        !i.acknowledged && now > dl
                    } else {
                        false
                    }
                } else {
                    false
                }
            })
            .count();
        serde_json::json!({
            "total": total,
            "pending": pending,
            "unacknowledged": pending,
            "acknowledged": total - pending,
            "assigned": assigned,
            "sla_breached": breached,
        })
    }
}

// ── Event Search ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchQuery {
    pub text: Option<String>,
    pub hostname: Option<String>,
    pub level: Option<String>,
    pub agent_id: Option<String>,
    pub from_ts: Option<String>,
    pub to_ts: Option<String>,
    pub limit: Option<usize>,
}

pub fn search_events<'a>(
    events: &'a [crate::event_forward::StoredEvent],
    query: &SearchQuery,
) -> Vec<&'a crate::event_forward::StoredEvent> {
    let limit = query.limit.unwrap_or(100).min(1000);
    events
        .iter()
        .filter(|e| {
            if let Some(ref h) = query.hostname
                && !e.alert.hostname.contains(h.as_str())
            {
                return false;
            }
            if let Some(ref l) = query.level
                && !e.alert.level.eq_ignore_ascii_case(l)
            {
                return false;
            }
            if let Some(ref a) = query.agent_id
                && e.agent_id != *a
            {
                return false;
            }
            if let Some(ref from) = query.from_ts
                && e.alert.timestamp < *from
            {
                return false;
            }
            if let Some(ref to) = query.to_ts
                && e.alert.timestamp > *to
            {
                return false;
            }
            if let Some(ref text) = query.text {
                let t = text.to_lowercase();
                let in_reasons = e
                    .alert
                    .reasons
                    .iter()
                    .any(|r| r.to_lowercase().contains(&t));
                let in_host = e.alert.hostname.to_lowercase().contains(&t);
                let in_action = e.alert.action.to_lowercase().contains(&t);
                if !in_reasons && !in_host && !in_action {
                    return false;
                }
            }
            true
        })
        .take(limit)
        .collect()
}

// ── Timeline ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct TimelineEntry {
    pub timestamp: String,
    pub event_id: u64,
    pub event_type: String,
    pub severity: String,
    pub description: String,
    pub agent_id: String,
}

pub fn build_host_timeline(
    events: &[crate::event_forward::StoredEvent],
    hostname: &str,
) -> Vec<TimelineEntry> {
    let mut entries: Vec<TimelineEntry> = events
        .iter()
        .filter(|e| e.alert.hostname.eq_ignore_ascii_case(hostname))
        .map(|e| TimelineEntry {
            timestamp: e.alert.timestamp.clone(),
            event_id: e.id,
            event_type: if e.alert.score >= 5.0 {
                "critical_alert".into()
            } else if e.alert.score >= 3.0 {
                "alert".into()
            } else {
                "observation".into()
            },
            severity: e.alert.level.clone(),
            description: e.alert.reasons.join("; "),
            agent_id: e.agent_id.clone(),
        })
        .collect();
    entries.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    entries
}

pub fn build_agent_timeline(
    events: &[crate::event_forward::StoredEvent],
    agent_id: &str,
) -> Vec<TimelineEntry> {
    let mut entries: Vec<TimelineEntry> = events
        .iter()
        .filter(|e| e.agent_id == agent_id)
        .map(|e| TimelineEntry {
            timestamp: e.alert.timestamp.clone(),
            event_id: e.id,
            event_type: if e.alert.score >= 5.0 {
                "critical_alert".into()
            } else if e.alert.score >= 3.0 {
                "alert".into()
            } else {
                "observation".into()
            },
            severity: e.alert.level.clone(),
            description: e.alert.reasons.join("; "),
            agent_id: e.agent_id.clone(),
        })
        .collect();
    entries.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    entries
}

// ── Investigation Graph ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct GraphNode {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct GraphEdge {
    pub source: String,
    pub target: String,
    pub relation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct InvestigationGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

pub fn build_investigation_graph(
    events: &[crate::event_forward::StoredEvent],
    event_ids: &[u64],
) -> InvestigationGraph {
    let mut nodes: Vec<GraphNode> = Vec::new();
    let mut edges: Vec<GraphEdge> = Vec::new();
    let mut host_set: HashMap<String, bool> = HashMap::new();
    let mut agent_set: HashMap<String, bool> = HashMap::new();
    let mut technique_set: HashMap<String, bool> = HashMap::new();

    for e in events.iter().filter(|e| event_ids.contains(&e.id)) {
        let event_node = format!("event-{}", e.id);
        nodes.push(GraphNode {
            id: event_node.clone(),
            kind: "event".into(),
            label: format!("Event #{} (score: {:.1})", e.id, e.alert.score),
            metadata: serde_json::json!({
                "score": e.alert.score,
                "level": e.alert.level,
                "timestamp": e.alert.timestamp,
            }),
        });

        // Host node
        if !host_set.contains_key(&e.alert.hostname) {
            host_set.insert(e.alert.hostname.clone(), true);
            nodes.push(GraphNode {
                id: format!("host-{}", e.alert.hostname),
                kind: "host".into(),
                label: e.alert.hostname.clone(),
                metadata: serde_json::json!({"platform": e.alert.platform}),
            });
        }
        edges.push(GraphEdge {
            source: event_node.clone(),
            target: format!("host-{}", e.alert.hostname),
            relation: "observed_on".into(),
        });

        // Agent node
        if !agent_set.contains_key(&e.agent_id) {
            agent_set.insert(e.agent_id.clone(), true);
            nodes.push(GraphNode {
                id: format!("agent-{}", e.agent_id),
                kind: "agent".into(),
                label: format!("Agent {}", e.agent_id),
                metadata: serde_json::json!({}),
            });
        }
        edges.push(GraphEdge {
            source: event_node.clone(),
            target: format!("agent-{}", e.agent_id),
            relation: "reported_by".into(),
        });

        // MITRE technique nodes
        for m in &e.alert.mitre {
            let tid = &m.technique_id;
            if !technique_set.contains_key(tid) {
                technique_set.insert(tid.clone(), true);
                nodes.push(GraphNode {
                    id: format!("technique-{}", tid),
                    kind: "technique".into(),
                    label: format!("{} ({})", m.technique_name, tid),
                    metadata: serde_json::json!({"tactic": m.tactic}),
                });
            }
            edges.push(GraphEdge {
                source: event_node.clone(),
                target: format!("technique-{}", tid),
                relation: "uses_technique".into(),
            });
        }
    }

    InvestigationGraph { nodes, edges }
}

// ── Remediation Approval ───────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ApprovalDecision {
    Approved,
    Denied,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemediationApproval {
    pub request_id: String,
    pub decision: ApprovalDecision,
    pub approver: String,
    pub reason: String,
    pub decided_at: String,
}

pub struct ApprovalLog {
    entries: Vec<RemediationApproval>,
}

impl Default for ApprovalLog {
    fn default() -> Self {
        Self::new()
    }
}

impl ApprovalLog {
    pub fn new() -> Self {
        ApprovalLog {
            entries: Vec::new(),
        }
    }

    pub fn record(
        &mut self,
        request_id: String,
        decision: ApprovalDecision,
        approver: String,
        reason: String,
    ) {
        self.entries.push(RemediationApproval {
            request_id,
            decision,
            approver,
            reason,
            decided_at: chrono::Utc::now().to_rfc3339(),
        });
    }

    pub fn recent(&self, limit: usize) -> &[RemediationApproval] {
        let start = self.entries.len().saturating_sub(limit);
        &self.entries[start..]
    }

    pub fn list(&self) -> &[RemediationApproval] {
        &self.entries
    }

    pub fn for_request(&self, request_id: &str) -> Option<&RemediationApproval> {
        self.entries
            .iter()
            .rev()
            .find(|e| e.request_id == request_id)
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::AlertRecord;
    use crate::event_forward::StoredEvent;
    use crate::telemetry::{MitreAttack, TelemetrySample};

    fn make_sample() -> TelemetrySample {
        TelemetrySample {
            timestamp_ms: 0,
            cpu_load_pct: 50.0,
            memory_load_pct: 60.0,
            temperature_c: 45.0,
            network_kbps: 200.0,
            auth_failures: 0,
            battery_pct: 100.0,
            integrity_drift: 0.0,
            process_count: 50,
            disk_pressure_pct: 10.0,
        }
    }

    fn make_alert(score: f64, hostname: &str, level: &str) -> AlertRecord {
        AlertRecord {
            timestamp: "2025-01-01T00:00:00Z".into(),
            hostname: hostname.into(),
            platform: "linux".into(),
            score: score as f32,
            confidence: 0.9_f32,
            reasons: vec!["test reason".into()],
            action: "alert".into(),
            level: level.into(),
            enforced: false,
            mitre: vec![MitreAttack {
                technique_id: "T1059".into(),
                technique_name: "Command Execution".into(),
                tactic: "Execution".into(),
            }],
            sample: make_sample(),
            narrative: None,
        }
    }

    fn make_stored_event(id: u64, agent: &str, hostname: &str, score: f64) -> StoredEvent {
        StoredEvent {
            id,
            agent_id: agent.into(),
            received_at: "2025-01-01T00:00:00Z".into(),
            alert: make_alert(
                score,
                hostname,
                if score >= 5.0 { "critical" } else { "elevated" },
            ),
            correlated: false,
            triage: Default::default(),
        }
    }

    // Case Store tests

    #[test]
    fn case_create_and_get() {
        let mut store = CaseStore::new("/tmp/wardex_test_cases.json");
        store.cases.clear();
        store.next_id = 1;
        let case = store.create(
            "Test Case".into(),
            "Description".into(),
            CasePriority::High,
            vec![1],
            vec![10, 20],
            vec!["malware".into()],
        );
        assert_eq!(case.id, 1);
        assert_eq!(case.status, CaseStatus::New);
        assert!(store.get(1).is_some());
        assert!(store.get(99).is_none());
    }

    #[test]
    fn case_update_status() {
        let mut store = CaseStore::new("/tmp/wardex_test_cases2.json");
        store.cases.clear();
        store.next_id = 1;
        store.create(
            "C1".into(),
            "D1".into(),
            CasePriority::Medium,
            vec![],
            vec![],
            vec![],
        );
        assert!(store.update_status(1, CaseStatus::Investigating));
        assert_eq!(store.get(1).unwrap().status, CaseStatus::Investigating);
        assert!(!store.update_status(99, CaseStatus::Closed));
    }

    #[test]
    fn case_assign_and_comment() {
        let mut store = CaseStore::new("/tmp/wardex_test_cases3.json");
        store.cases.clear();
        store.next_id = 1;
        store.create(
            "C1".into(),
            "D1".into(),
            CasePriority::Low,
            vec![],
            vec![],
            vec![],
        );
        assert!(store.assign(1, "analyst1".into()));
        assert_eq!(store.get(1).unwrap().assignee, Some("analyst1".into()));
        assert!(store.add_comment(1, "analyst1".into(), "Initial triage".into()));
        assert_eq!(store.get(1).unwrap().comments.len(), 1);
    }

    #[test]
    fn case_add_evidence() {
        let mut store = CaseStore::new("/tmp/wardex_test_cases4.json");
        store.cases.clear();
        store.next_id = 1;
        store.create(
            "C1".into(),
            "D1".into(),
            CasePriority::Critical,
            vec![],
            vec![],
            vec![],
        );
        assert!(store.add_evidence(
            1,
            "pcap".into(),
            "pcap-001".into(),
            "Network capture".into()
        ));
        assert_eq!(store.get(1).unwrap().evidence.len(), 1);
    }

    #[test]
    fn case_link_incident() {
        let mut store = CaseStore::new("/tmp/wardex_test_cases5.json");
        store.cases.clear();
        store.next_id = 1;
        store.create(
            "C1".into(),
            "D1".into(),
            CasePriority::High,
            vec![],
            vec![],
            vec![],
        );
        assert!(store.link_incident(1, 42));
        assert!(store.get(1).unwrap().incident_ids.contains(&42));
        // Idempotent
        store.link_incident(1, 42);
        assert_eq!(store.get(1).unwrap().incident_ids.len(), 1);
    }

    #[test]
    fn case_list_filtered() {
        let mut store = CaseStore::new("/tmp/wardex_test_cases6.json");
        store.cases.clear();
        store.next_id = 1;
        store.create(
            "C1".into(),
            "D1".into(),
            CasePriority::High,
            vec![],
            vec![],
            vec![],
        );
        store.create(
            "C2".into(),
            "D2".into(),
            CasePriority::Low,
            vec![],
            vec![],
            vec![],
        );
        store.update_status(1, CaseStatus::Investigating);
        let investigating = store.list_filtered(Some("Investigating"), None, None);
        assert_eq!(investigating.len(), 1);
        let high = store.list_filtered(None, Some("High"), None);
        assert_eq!(high.len(), 1);
    }

    #[test]
    fn case_stats() {
        let mut store = CaseStore::new("/tmp/wardex_test_cases7.json");
        store.cases.clear();
        store.next_id = 1;
        store.create(
            "C1".into(),
            "D1".into(),
            CasePriority::High,
            vec![],
            vec![],
            vec![],
        );
        store.create(
            "C2".into(),
            "D2".into(),
            CasePriority::Low,
            vec![],
            vec![],
            vec![],
        );
        let stats = store.stats();
        assert_eq!(stats["total"], 2);
    }

    // Alert Queue tests

    #[test]
    fn alert_queue_priority_sort() {
        let mut q = AlertQueue::new();
        q.enqueue(
            1,
            3.0,
            "elevated".into(),
            "host-a".into(),
            "2025-01-01T00:00:00Z".into(),
        );
        q.enqueue(
            2,
            8.5,
            "critical".into(),
            "host-b".into(),
            "2025-01-01T00:01:00Z".into(),
        );
        q.enqueue(
            3,
            5.0,
            "severe".into(),
            "host-c".into(),
            "2025-01-01T00:02:00Z".into(),
        );
        let pending = q.pending();
        assert_eq!(pending[0].event_id, 2); // highest score first
        assert_eq!(pending[1].event_id, 3);
        assert_eq!(pending[2].event_id, 1);
    }

    #[test]
    fn alert_queue_acknowledge() {
        let mut q = AlertQueue::new();
        q.enqueue(1, 5.0, "severe".into(), "h".into(), "t".into());
        assert_eq!(q.pending().len(), 1);
        assert!(q.acknowledge(1));
        assert_eq!(q.pending().len(), 0);
    }

    #[test]
    fn alert_queue_assign_and_filter() {
        let mut q = AlertQueue::new();
        q.enqueue(1, 5.0, "severe".into(), "h".into(), "t".into());
        q.enqueue(2, 3.0, "elevated".into(), "h".into(), "t".into());
        q.assign(1, "alice".into());
        assert_eq!(q.by_assignee("alice").len(), 1);
        assert_eq!(q.by_assignee("bob").len(), 0);
    }

    #[test]
    fn alert_queue_dismiss() {
        let mut q = AlertQueue::new();
        q.enqueue(1, 5.0, "severe".into(), "h".into(), "t".into());
        assert!(q.dismiss(1));
        assert!(!q.dismiss(1)); // already gone
    }

    #[test]
    fn alert_queue_stats() {
        let mut q = AlertQueue::new();
        q.enqueue(1, 5.0, "severe".into(), "h".into(), "t".into());
        q.enqueue(2, 3.0, "elevated".into(), "h".into(), "t".into());
        q.acknowledge(1);
        let stats = q.stats();
        assert_eq!(stats["total"], 2);
        assert_eq!(stats["pending"], 1);
        assert_eq!(stats["acknowledged"], 1);
    }

    // Event Search tests

    #[test]
    fn search_by_hostname() {
        let events = vec![
            make_stored_event(1, "a1", "web-01", 4.0),
            make_stored_event(2, "a1", "db-01", 3.0),
        ];
        let q = SearchQuery {
            text: None,
            hostname: Some("web".into()),
            level: None,
            agent_id: None,
            from_ts: None,
            to_ts: None,
            limit: None,
        };
        let results = search_events(&events, &q);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, 1);
    }

    #[test]
    fn search_by_level() {
        let events = vec![
            make_stored_event(1, "a1", "h1", 6.0),
            make_stored_event(2, "a1", "h2", 2.0),
        ];
        let q = SearchQuery {
            text: None,
            hostname: None,
            level: Some("critical".into()),
            agent_id: None,
            from_ts: None,
            to_ts: None,
            limit: None,
        };
        let results = search_events(&events, &q);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn search_by_text() {
        let events = vec![make_stored_event(1, "a1", "h1", 4.0)];
        let q = SearchQuery {
            text: Some("test reason".into()),
            hostname: None,
            level: None,
            agent_id: None,
            from_ts: None,
            to_ts: None,
            limit: None,
        };
        let results = search_events(&events, &q);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn search_limit() {
        let events: Vec<StoredEvent> = (1..=50)
            .map(|i| make_stored_event(i, "a1", "h1", 3.0))
            .collect();
        let q = SearchQuery {
            text: None,
            hostname: None,
            level: None,
            agent_id: None,
            from_ts: None,
            to_ts: None,
            limit: Some(5),
        };
        let results = search_events(&events, &q);
        assert_eq!(results.len(), 5);
    }

    // Timeline tests

    #[test]
    fn host_timeline() {
        let events = vec![
            make_stored_event(1, "a1", "web-01", 6.0),
            make_stored_event(2, "a2", "web-01", 3.0),
            make_stored_event(3, "a1", "db-01", 4.0),
        ];
        let tl = build_host_timeline(&events, "web-01");
        assert_eq!(tl.len(), 2);
    }

    #[test]
    fn agent_timeline() {
        let events = vec![
            make_stored_event(1, "agent-1", "h1", 4.0),
            make_stored_event(2, "agent-2", "h2", 3.0),
            make_stored_event(3, "agent-1", "h3", 5.0),
        ];
        let tl = build_agent_timeline(&events, "agent-1");
        assert_eq!(tl.len(), 2);
    }

    // Investigation Graph tests

    #[test]
    fn investigation_graph_basic() {
        let events = vec![
            make_stored_event(1, "a1", "web-01", 6.0),
            make_stored_event(2, "a1", "web-01", 3.0),
            make_stored_event(3, "a2", "db-01", 4.0),
        ];
        let graph = build_investigation_graph(&events, &[1, 2, 3]);
        // Nodes: 3 events + 2 hosts + 2 agents + 1 technique
        assert!(graph.nodes.len() >= 7);
        assert!(!graph.edges.is_empty());
        // Check node kinds
        assert!(graph.nodes.iter().any(|n| n.kind == "event"));
        assert!(graph.nodes.iter().any(|n| n.kind == "host"));
        assert!(graph.nodes.iter().any(|n| n.kind == "technique"));
    }

    #[test]
    fn investigation_graph_subset() {
        let events = vec![
            make_stored_event(1, "a1", "h1", 4.0),
            make_stored_event(2, "a1", "h2", 3.0),
        ];
        let graph = build_investigation_graph(&events, &[1]);
        let event_nodes: Vec<_> = graph.nodes.iter().filter(|n| n.kind == "event").collect();
        assert_eq!(event_nodes.len(), 1);
    }

    // Approval tests

    #[test]
    fn approval_log_record_and_query() {
        let mut log = ApprovalLog::new();
        log.record(
            "req-1".into(),
            ApprovalDecision::Approved,
            "admin".into(),
            "Verified threat".into(),
        );
        log.record(
            "req-2".into(),
            ApprovalDecision::Denied,
            "admin".into(),
            "False positive".into(),
        );
        assert_eq!(log.recent(10).len(), 2);
        let r1 = log.for_request("req-1").unwrap();
        assert_eq!(r1.decision, ApprovalDecision::Approved);
        let r2 = log.for_request("req-2").unwrap();
        assert_eq!(r2.decision, ApprovalDecision::Denied);
        assert!(log.for_request("req-99").is_none());
    }
}
