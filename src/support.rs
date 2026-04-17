use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportTemplateRecord {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub scope: String,
    pub format: String,
    pub last_run_at: Option<String>,
    pub next_run_at: Option<String>,
    pub status: String,
    pub audience: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportRunRecord {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub scope: String,
    pub format: String,
    pub last_run_at: Option<String>,
    pub next_run_at: Option<String>,
    pub status: String,
    pub audience: String,
    pub summary: String,
    pub size_bytes: u64,
    pub preview: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportScheduleRecord {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub scope: String,
    pub format: String,
    pub last_run_at: Option<String>,
    pub next_run_at: Option<String>,
    pub status: String,
    pub cadence: String,
    pub target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboxItem {
    pub id: String,
    pub kind: String,
    pub title: String,
    pub severity: String,
    pub path: String,
    pub created_at: String,
    pub acknowledged: bool,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SupportSnapshot {
    templates: Vec<ReportTemplateRecord>,
    runs: Vec<ReportRunRecord>,
    schedules: Vec<ReportScheduleRecord>,
    inbox: Vec<InboxItem>,
    next_sequence: u64,
}

impl Default for SupportSnapshot {
    fn default() -> Self {
        Self {
            templates: default_templates(),
            runs: Vec::new(),
            schedules: Vec::new(),
            inbox: Vec::new(),
            next_sequence: 1,
        }
    }
}

fn default_templates() -> Vec<ReportTemplateRecord> {
    vec![
        ReportTemplateRecord {
            id: "tpl-executive-status".to_string(),
            name: "Executive Status".to_string(),
            kind: "executive_status".to_string(),
            scope: "global".to_string(),
            format: "json".to_string(),
            last_run_at: None,
            next_run_at: None,
            status: "ready".to_string(),
            audience: "executive".to_string(),
            description:
                "Leadership-ready overview of queue pressure, incidents, and fleet posture."
                    .to_string(),
        },
        ReportTemplateRecord {
            id: "tpl-audit-export".to_string(),
            name: "Audit Export".to_string(),
            kind: "audit_export".to_string(),
            scope: "audit".to_string(),
            format: "json".to_string(),
            last_run_at: None,
            next_run_at: None,
            status: "ready".to_string(),
            audience: "security".to_string(),
            description: "Operational audit evidence for investigations and reviews.".to_string(),
        },
        ReportTemplateRecord {
            id: "tpl-incident-package".to_string(),
            name: "Incident Package".to_string(),
            kind: "incident_package".to_string(),
            scope: "incidents".to_string(),
            format: "json".to_string(),
            last_run_at: None,
            next_run_at: None,
            status: "ready".to_string(),
            audience: "analyst".to_string(),
            description: "Case-oriented bundle with queue, incident, and response context."
                .to_string(),
        },
        ReportTemplateRecord {
            id: "tpl-compliance-snapshot".to_string(),
            name: "Compliance Snapshot".to_string(),
            kind: "compliance_snapshot".to_string(),
            scope: "compliance".to_string(),
            format: "json".to_string(),
            last_run_at: None,
            next_run_at: None,
            status: "ready".to_string(),
            audience: "audit".to_string(),
            description: "Current compliance and control health posture.".to_string(),
        },
        ReportTemplateRecord {
            id: "tpl-formal-verification".to_string(),
            name: "Formal Verification Bundle".to_string(),
            kind: "formal_verification_bundle".to_string(),
            scope: "verification".to_string(),
            format: "json".to_string(),
            last_run_at: None,
            next_run_at: None,
            status: "ready".to_string(),
            audience: "engineering".to_string(),
            description: "Artifacts and metadata for formal verification exports.".to_string(),
        },
    ]
}

pub struct SupportStore {
    snapshot: SupportSnapshot,
    store_path: String,
}

impl SupportStore {
    pub fn new(store_path: &str) -> Self {
        let safe_path = if let Some(parent) = Path::new(store_path).parent() {
            let _ = fs::create_dir_all(parent);
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
        let mut store = Self {
            snapshot: SupportSnapshot::default(),
            store_path: safe_path,
        };
        store.load();
        if store.snapshot.templates.is_empty() {
            store.snapshot.templates = default_templates();
            store.persist();
        }
        store
    }

    fn load(&mut self) {
        let path = Path::new(&self.store_path);
        if path.exists()
            && let Ok(content) = fs::read_to_string(path)
            && let Ok(snapshot) = serde_json::from_str::<SupportSnapshot>(&content)
        {
            self.snapshot = snapshot;
        }
    }

    fn persist(&self) {
        let path = Path::new(&self.store_path);
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(&self.snapshot) {
            let tmp = format!("{}.tmp", self.store_path);
            if fs::write(&tmp, json).is_ok() {
                let _ = fs::rename(&tmp, path);
            }
        }
    }

    fn next_id(&mut self, prefix: &str) -> String {
        let id = format!("{prefix}-{}", self.snapshot.next_sequence);
        self.snapshot.next_sequence += 1;
        id
    }

    pub fn report_templates(&self) -> &[ReportTemplateRecord] {
        &self.snapshot.templates
    }

    pub fn report_runs(&self) -> &[ReportRunRecord] {
        &self.snapshot.runs
    }

    pub fn report_schedules(&self) -> &[ReportScheduleRecord] {
        &self.snapshot.schedules
    }

    pub fn inbox_items(&self) -> &[InboxItem] {
        &self.snapshot.inbox
    }

    pub fn upsert_report_template(
        &mut self,
        id: Option<&str>,
        name: String,
        kind: String,
        scope: String,
        format: String,
        status: String,
        audience: String,
        description: String,
    ) -> ReportTemplateRecord {
        if let Some(existing_id) = id
            && let Some(template) = self
                .snapshot
                .templates
                .iter_mut()
                .find(|template| template.id == existing_id)
        {
            template.name = name;
            template.kind = kind;
            template.scope = scope;
            template.format = format;
            template.status = status;
            template.audience = audience;
            template.description = description;
            let updated = template.clone();
            self.persist();
            return updated;
        }

        let created = ReportTemplateRecord {
            id: id.unwrap_or(&self.next_id("tpl")).to_string(),
            name,
            kind,
            scope,
            format,
            last_run_at: None,
            next_run_at: None,
            status,
            audience,
            description,
        };
        self.snapshot.templates.push(created.clone());
        self.persist();
        created
    }

    pub fn add_report_run(
        &mut self,
        name: String,
        kind: String,
        scope: String,
        format: String,
        audience: String,
        status: String,
        summary: String,
        size_bytes: u64,
        preview: serde_json::Value,
    ) -> ReportRunRecord {
        let now = now_rfc3339();
        let created = ReportRunRecord {
            id: self.next_id("run"),
            name: name.clone(),
            kind: kind.clone(),
            scope: scope.clone(),
            format: format.clone(),
            last_run_at: Some(now.clone()),
            next_run_at: None,
            status: status.clone(),
            audience: audience.clone(),
            summary,
            size_bytes,
            preview,
        };
        self.snapshot.runs.insert(0, created.clone());
        self.snapshot.runs.truncate(100);
        if let Some(template) = self
            .snapshot
            .templates
            .iter_mut()
            .find(|template| template.kind == kind && template.scope == scope)
        {
            template.last_run_at = Some(now);
            template.format = format;
            template.status = status;
            template.audience = audience;
            template.name = name;
        }
        self.persist();
        created
    }

    pub fn upsert_report_schedule(
        &mut self,
        id: Option<&str>,
        name: String,
        kind: String,
        scope: String,
        format: String,
        cadence: String,
        target: String,
        next_run_at: Option<String>,
        status: String,
    ) -> ReportScheduleRecord {
        if let Some(existing_id) = id
            && let Some(schedule) = self
                .snapshot
                .schedules
                .iter_mut()
                .find(|schedule| schedule.id == existing_id)
        {
            schedule.name = name;
            schedule.kind = kind;
            schedule.scope = scope;
            schedule.format = format;
            schedule.cadence = cadence;
            schedule.target = target;
            schedule.next_run_at = next_run_at;
            schedule.status = status;
            let updated = schedule.clone();
            self.persist();
            return updated;
        }

        let created = ReportScheduleRecord {
            id: id.unwrap_or(&self.next_id("sched")).to_string(),
            name,
            kind,
            scope,
            format,
            last_run_at: None,
            next_run_at,
            status,
            cadence,
            target,
        };
        self.snapshot.schedules.insert(0, created.clone());
        self.persist();
        created
    }

    pub fn sync_inbox(&mut self, live_items: Vec<InboxItem>) -> Vec<InboxItem> {
        let previous = self.snapshot.inbox.clone();
        let merged = live_items
            .into_iter()
            .map(|mut item| {
                if let Some(existing) = previous.iter().find(|existing| existing.id == item.id) {
                    item.acknowledged = existing.acknowledged;
                    if item.created_at.is_empty() {
                        item.created_at = existing.created_at.clone();
                    }
                }
                item
            })
            .collect::<Vec<_>>();
        self.snapshot.inbox = merged.clone();
        self.persist();
        merged
    }

    pub fn acknowledge_inbox(&mut self, id: &str) -> Option<InboxItem> {
        let item = self.snapshot.inbox.iter_mut().find(|item| item.id == id)?;
        item.acknowledged = true;
        let updated = item.clone();
        self.persist();
        Some(updated)
    }
}
