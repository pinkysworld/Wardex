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
    #[serde(default)]
    pub execution_context: Option<ReportExecutionContext>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportExecutionContext {
    pub case_id: Option<String>,
    pub incident_id: Option<String>,
    pub investigation_id: Option<String>,
    pub source: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReportExecutionScopeFilter {
    #[default]
    All,
    Scoped,
    Unscoped,
}

#[derive(Debug, Clone, Default)]
pub struct ReportExecutionContextFilter {
    pub case_id: Option<String>,
    pub incident_id: Option<String>,
    pub investigation_id: Option<String>,
    pub source: Option<String>,
    pub scope: ReportExecutionScopeFilter,
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
    #[serde(default)]
    pub execution_context: Option<ReportExecutionContext>,
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
    #[serde(default)]
    pub execution_context: Option<ReportExecutionContext>,
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
            execution_context: None,
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
            execution_context: None,
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
            execution_context: None,
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
            execution_context: None,
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
            execution_context: None,
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

    pub fn report_templates_filtered(
        &self,
        filter: &ReportExecutionContextFilter,
    ) -> Vec<ReportTemplateRecord> {
        self.snapshot
            .templates
            .iter()
            .filter(|template| execution_context_matches(template.execution_context.as_ref(), filter))
            .cloned()
            .collect()
    }

    pub fn report_runs(&self) -> &[ReportRunRecord] {
        &self.snapshot.runs
    }

    pub fn report_runs_filtered(
        &self,
        filter: &ReportExecutionContextFilter,
    ) -> Vec<ReportRunRecord> {
        self.snapshot
            .runs
            .iter()
            .filter(|run| execution_context_matches(run.execution_context.as_ref(), filter))
            .cloned()
            .collect()
    }

    pub fn report_schedules(&self) -> &[ReportScheduleRecord] {
        &self.snapshot.schedules
    }

    pub fn report_schedules_filtered(
        &self,
        filter: &ReportExecutionContextFilter,
    ) -> Vec<ReportScheduleRecord> {
        self.snapshot
            .schedules
            .iter()
            .filter(|schedule| execution_context_matches(schedule.execution_context.as_ref(), filter))
            .cloned()
            .collect()
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
        execution_context: Option<ReportExecutionContext>,
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
            template.execution_context = execution_context;
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
            execution_context,
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
        execution_context: Option<ReportExecutionContext>,
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
            execution_context,
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
        execution_context: Option<ReportExecutionContext>,
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
            schedule.execution_context = execution_context;
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
            execution_context,
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

fn execution_context_matches(
    context: Option<&ReportExecutionContext>,
    filter: &ReportExecutionContextFilter,
) -> bool {
    match filter.scope {
        ReportExecutionScopeFilter::Unscoped => return context.is_none(),
        ReportExecutionScopeFilter::Scoped if context.is_none() => return false,
        ReportExecutionScopeFilter::All | ReportExecutionScopeFilter::Scoped => {}
    }

    let requires_context_match = filter.case_id.is_some()
        || filter.incident_id.is_some()
        || filter.investigation_id.is_some()
        || filter.source.is_some();
    if !requires_context_match {
        return true;
    }

    let Some(context) = context else {
        return false;
    };

    fn field_matches(actual: Option<&String>, expected: Option<&String>) -> bool {
        match expected {
            Some(expected_value) => actual.is_some_and(|actual_value| actual_value == expected_value),
            None => true,
        }
    }

    field_matches(context.case_id.as_ref(), filter.case_id.as_ref())
        && field_matches(context.incident_id.as_ref(), filter.incident_id.as_ref())
        && field_matches(
            context.investigation_id.as_ref(),
            filter.investigation_id.as_ref(),
        )
        && field_matches(context.source.as_ref(), filter.source.as_ref())
}

#[cfg(test)]
mod tests {
    use super::{
        ReportExecutionContext, ReportExecutionContextFilter, ReportExecutionScopeFilter,
        SupportStore,
    };

    fn temp_store_path(label: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_nanos();
        std::env::temp_dir()
            .join(format!("sentineledge-support-{label}-{nanos}.json"))
            .to_string_lossy()
            .to_string()
    }

    #[test]
    fn report_runs_and_schedules_preserve_execution_context() {
        let path = temp_store_path("context");
        let mut store = SupportStore::new(&path);
        let execution_context = ReportExecutionContext {
            case_id: Some("42".to_string()),
            incident_id: Some("7".to_string()),
            investigation_id: Some("inv-7".to_string()),
            source: Some("case".to_string()),
        };

        let run = store.add_report_run(
            "Scoped report".to_string(),
            "incident_package".to_string(),
            "incidents".to_string(),
            "json".to_string(),
            "analyst".to_string(),
            "completed".to_string(),
            "Scoped summary".to_string(),
            128,
            serde_json::json!({"ok": true}),
            Some(execution_context.clone()),
        );
        let schedule = store.upsert_report_schedule(
            None,
            "Scoped schedule".to_string(),
            "incident_package".to_string(),
            "incidents".to_string(),
            "json".to_string(),
            "weekly".to_string(),
            "ops@wardex.local".to_string(),
            Some("2026-04-30T08:00:00Z".to_string()),
            "active".to_string(),
            Some(execution_context.clone()),
        );

        assert_eq!(
            run.execution_context
                .as_ref()
                .and_then(|context| context.case_id.as_deref()),
            Some("42")
        );
        assert_eq!(
            schedule
                .execution_context
                .as_ref()
                .and_then(|context| context.investigation_id.as_deref()),
            Some("inv-7")
        );

        let reloaded = SupportStore::new(&path);
        assert_eq!(
            reloaded.report_runs()[0]
                .execution_context
                .as_ref()
                .and_then(|context| context.incident_id.as_deref()),
            Some("7")
        );
        assert_eq!(
            reloaded.report_schedules()[0]
                .execution_context
                .as_ref()
                .and_then(|context| context.source.as_deref()),
            Some("case")
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn report_runs_and_schedules_filter_by_execution_context() {
        let path = temp_store_path("filters");
        let mut store = SupportStore::new(&path);
        let scoped_context = ReportExecutionContext {
            case_id: Some("42".to_string()),
            incident_id: Some("7".to_string()),
            investigation_id: Some("inv-7".to_string()),
            source: Some("case".to_string()),
        };

        store.add_report_run(
            "Scoped report".to_string(),
            "incident_package".to_string(),
            "incidents".to_string(),
            "json".to_string(),
            "analyst".to_string(),
            "completed".to_string(),
            "Scoped summary".to_string(),
            128,
            serde_json::json!({"ok": true}),
            Some(scoped_context.clone()),
        );
        store.add_report_run(
            "Global report".to_string(),
            "executive_status".to_string(),
            "global".to_string(),
            "json".to_string(),
            "executive".to_string(),
            "completed".to_string(),
            "Global summary".to_string(),
            64,
            serde_json::json!({"ok": true}),
            None,
        );
        store.upsert_report_schedule(
            None,
            "Scoped schedule".to_string(),
            "incident_package".to_string(),
            "incidents".to_string(),
            "json".to_string(),
            "weekly".to_string(),
            "analysts@wardex.local".to_string(),
            Some("2026-04-24T08:00:00Z".to_string()),
            "active".to_string(),
            Some(scoped_context.clone()),
        );
        store.upsert_report_schedule(
            None,
            "Global schedule".to_string(),
            "executive_status".to_string(),
            "global".to_string(),
            "json".to_string(),
            "weekly".to_string(),
            "exec@wardex.local".to_string(),
            Some("2026-04-24T08:00:00Z".to_string()),
            "active".to_string(),
            None,
        );

        let scoped_filter = ReportExecutionContextFilter {
            case_id: Some("42".to_string()),
            incident_id: Some("7".to_string()),
            investigation_id: Some("inv-7".to_string()),
            source: Some("case".to_string()),
            scope: ReportExecutionScopeFilter::Scoped,
        };
        let unscoped_filter = ReportExecutionContextFilter {
            scope: ReportExecutionScopeFilter::Unscoped,
            ..ReportExecutionContextFilter::default()
        };

        assert_eq!(store.report_runs_filtered(&scoped_filter).len(), 1);
        assert_eq!(store.report_schedules_filtered(&scoped_filter).len(), 1);
        assert_eq!(store.report_runs_filtered(&unscoped_filter).len(), 1);
        assert_eq!(store.report_schedules_filtered(&unscoped_filter).len(), 1);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn report_templates_preserve_and_filter_execution_context() {
        let path = temp_store_path("template-filters");
        let mut store = SupportStore::new(&path);
        let scoped_context = ReportExecutionContext {
            case_id: Some("42".to_string()),
            incident_id: Some("7".to_string()),
            investigation_id: Some("inv-7".to_string()),
            source: Some("case".to_string()),
        };

        let scoped_template = store.upsert_report_template(
            None,
            "Scoped incident package".to_string(),
            "incident_package".to_string(),
            "incidents".to_string(),
            "json".to_string(),
            "ready".to_string(),
            "analyst".to_string(),
            "Scoped preset".to_string(),
            Some(scoped_context.clone()),
        );

        assert_eq!(
            scoped_template
                .execution_context
                .as_ref()
                .and_then(|context| context.case_id.as_deref()),
            Some("42")
        );

        let reloaded = SupportStore::new(&path);
        let filtered = reloaded.report_templates_filtered(&ReportExecutionContextFilter {
            case_id: Some("42".to_string()),
            incident_id: Some("7".to_string()),
            investigation_id: Some("inv-7".to_string()),
            source: Some("case".to_string()),
            scope: ReportExecutionScopeFilter::Scoped,
        });
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "Scoped incident package");

        let unscoped = reloaded.report_templates_filtered(&ReportExecutionContextFilter {
            scope: ReportExecutionScopeFilter::Unscoped,
            ..ReportExecutionContextFilter::default()
        });
        assert!(unscoped.iter().any(|template| template.id == "tpl-executive-status"));

        let _ = std::fs::remove_file(path);
    }
}
