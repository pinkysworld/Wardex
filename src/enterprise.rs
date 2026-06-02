use crate::analyst::{Case, SearchQuery};
use crate::audit::sha256_hex;
use crate::collector::AlertRecord;
use crate::detection_feedback::DetectionFeedbackStore;
use crate::event_forward::StoredEvent;
use crate::incident::Incident;
use crate::ocsf;
use crate::rbac::User;
use crate::response::{ApprovalStatus, ResponseAction, ResponseAuditEntry, ResponseRequest};
use crate::sigma::{AttackMapping, RuleStatus, SigmaEngine, SigmaRule, builtin_rules};
use crate::telemetry::MitreAttack;
use crate::threat_intel::{IoC, IoCType};
use chrono::{Datelike, Timelike};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

#[path = "enterprise_store.rs"]
mod enterprise_store;

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn millis_to_rfc3339(value: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(value as i64)
        .unwrap_or_else(chrono::Utc::now)
        .to_rfc3339()
}

fn playbook_status_label(status: &crate::playbook::ExecutionStatus) -> &'static str {
    match status {
        crate::playbook::ExecutionStatus::Pending => "pending",
        crate::playbook::ExecutionStatus::Running => "running",
        crate::playbook::ExecutionStatus::Succeeded => "succeeded",
        crate::playbook::ExecutionStatus::Failed => "failed",
        crate::playbook::ExecutionStatus::TimedOut => "timed_out",
        crate::playbook::ExecutionStatus::Skipped => "skipped",
        crate::playbook::ExecutionStatus::AwaitingApproval => "awaiting_approval",
        crate::playbook::ExecutionStatus::Cancelled => "cancelled",
    }
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack
        .to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

fn parse_time(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

fn cron_field_matches(value: u32, expr: &str) -> bool {
    let token = expr.trim();
    if token == "*" {
        return true;
    }
    token.parse::<u32>() == Ok(value)
}

fn cron_is_due(expr: &str, now: chrono::DateTime<chrono::Utc>, last_run_at: Option<&str>) -> bool {
    let parts: Vec<&str> = expr.split_whitespace().collect();
    if parts.len() != 5 {
        return false;
    }

    let minute = now.minute();
    let hour = now.hour();
    let day = now.day();
    let month = now.month();
    let weekday = now.weekday().num_days_from_sunday();

    let matches_now = cron_field_matches(minute, parts[0])
        && cron_field_matches(hour, parts[1])
        && cron_field_matches(day, parts[2])
        && cron_field_matches(month, parts[3])
        && cron_field_matches(weekday, parts[4]);
    if !matches_now {
        return false;
    }

    let Some(last_run_at) = last_run_at else {
        return true;
    };
    let Some(last_run) = parse_time(last_run_at) else {
        return true;
    };

    // Prevent repeated trigger in the same minute while scheduler loop runs each second.
    !(last_run.year() == now.year()
        && last_run.month() == now.month()
        && last_run.day() == now.day()
        && last_run.hour() == now.hour()
        && last_run.minute() == now.minute())
}

fn severity_rank(severity: &str) -> u8 {
    match severity.trim().to_ascii_lowercase().as_str() {
        "critical" => 5,
        "severe" => 4,
        "high" => 4,
        "elevated" => 3,
        "medium" => 3,
        "low" => 2,
        "info" | "informational" => 1,
        _ => 0,
    }
}

const IDENTITY_ROLES: [&str; 3] = ["admin", "analyst", "viewer"];
const SCIM_PROVISIONING_MODES: [&str; 2] = ["manual", "automatic"];
const ANALYTICS_HISTORY_LIMIT: usize = 250;

fn normalize_optional_text(value: Option<String>) -> Option<String> {
    value.and_then(|entry| {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn normalize_identity_role(role: &str) -> Result<String, String> {
    let normalized = role.trim().to_ascii_lowercase();
    if IDENTITY_ROLES.contains(&normalized.as_str()) {
        Ok(normalized)
    } else {
        Err(format!(
            "invalid role '{role}'; expected one of {}",
            IDENTITY_ROLES.join(", ")
        ))
    }
}

fn normalize_group_role_mappings(
    mappings: HashMap<String, String>,
) -> Result<HashMap<String, String>, String> {
    let mut normalized = HashMap::new();
    for (group, role) in mappings {
        let group_name = group.trim();
        if group_name.is_empty() {
            return Err("group role mappings cannot contain empty group names".into());
        }
        let normalized_role = normalize_identity_role(&role)?;
        normalized.insert(group_name.to_string(), normalized_role);
    }
    Ok(normalized)
}

fn normalize_string_list(values: Vec<String>) -> Vec<String> {
    let mut normalized = Vec::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        let candidate = trimmed.to_string();
        if !normalized.contains(&candidate) {
            normalized.push(candidate);
        }
    }
    normalized
}

fn validation_issue(level: &str, field: &str, message: &str) -> IdentityConfigIssue {
    IdentityConfigIssue {
        level: level.to_string(),
        field: field.to_string(),
        message: message.to_string(),
    }
}

fn validation_status(enabled: bool, issues: &[IdentityConfigIssue]) -> String {
    if !enabled {
        return "disabled".to_string();
    }
    if issues.iter().any(|issue| issue.level == "error") {
        return "error".to_string();
    }
    if issues.iter().any(|issue| issue.level == "warning") {
        return "warning".to_string();
    }
    "ready".to_string()
}

fn attack_name(attack: &MitreAttack) -> String {
    if attack.technique_name.is_empty() {
        attack.technique_id.clone()
    } else {
        format!("{} ({})", attack.technique_name, attack.technique_id)
    }
}

fn mitre_from_attack_mapping(attack: &AttackMapping) -> MitreAttack {
    MitreAttack {
        tactic: attack.tactic.clone(),
        technique_id: attack.technique_id.clone(),
        technique_name: attack.technique_name.clone(),
    }
}

fn response_action_label(action: &ResponseAction) -> String {
    match action {
        ResponseAction::Alert => "Alert".to_string(),
        ResponseAction::Isolate => "Isolate host".to_string(),
        ResponseAction::Throttle { rate_limit_kbps } => {
            format!("Throttle to {rate_limit_kbps} kbps")
        }
        ResponseAction::KillProcess { pid, process_name } => {
            format!("Kill process {process_name} (PID {pid})")
        }
        ResponseAction::QuarantineFile { path } => format!("Quarantine file {path}"),
        ResponseAction::BlockIp { ip } => format!("Block IP {ip}"),
        ResponseAction::DisableAccount { username } => format!("Disable account {username}"),
        ResponseAction::RollbackConfig { config_name } => format!("Rollback config {config_name}"),
        ResponseAction::Custom { name, .. } => format!("Custom action {name}"),
    }
}

fn response_status_label(status: &ApprovalStatus) -> String {
    format!("{status:?}")
}

fn default_pack_saved_searches(id: &str) -> Vec<String> {
    match id {
        "identity-attacks" => vec![
            "failed logins by user".to_string(),
            "password spray by source".to_string(),
            "mfa bypass follow-up".to_string(),
        ],
        "lateral-movement" => vec![
            "shared admin tools by host".to_string(),
            "remote service creation".to_string(),
        ],
        "cloud-audit" => vec![
            "new admin role grants".to_string(),
            "cross-region console activity".to_string(),
        ],
        "insider-risk" => vec![
            "bulk access to sensitive files".to_string(),
            "archive and transfer staging".to_string(),
        ],
        "ransomware" => vec![
            "encryption velocity by host".to_string(),
            "shadow copy tampering".to_string(),
        ],
        "admin-abuse" => vec![
            "unexpected privileged shell".to_string(),
            "service persistence changes".to_string(),
        ],
        _ => Vec::new(),
    }
}

fn default_pack_workflows(id: &str) -> Vec<String> {
    match id {
        "identity-attacks" => vec!["credential-storm".to_string()],
        "lateral-movement" => vec!["lateral-movement".to_string()],
        "cloud-audit" => vec!["container-escape".to_string()],
        "insider-risk" => vec!["credential-storm".to_string()],
        "ransomware" => vec!["ransomware-triage".to_string()],
        "admin-abuse" => vec!["lateral-movement".to_string()],
        _ => Vec::new(),
    }
}

fn default_pack_target_group(id: &str) -> Option<String> {
    match id {
        "identity-attacks" | "lateral-movement" | "ransomware" => Some("soc-analysts".to_string()),
        "admin-abuse" => Some("soc-admins".to_string()),
        "cloud-audit" => Some("cloud-responders".to_string()),
        "insider-risk" => Some("insider-risk-reviewers".to_string()),
        _ => None,
    }
}

fn default_pack_rollout_notes(id: &str) -> Option<String> {
    match id {
        "identity-attacks" => {
            Some("Keep identity hunts in canary until group mappings and SCIM sync validate cleanly.".to_string())
        }
        "lateral-movement" => {
            Some("Promote only after shared-host hunts show stable match rates across managed endpoints.".to_string())
        }
        "cloud-audit" => {
            Some("Route escalations to cloud responders before enabling automatic account containment.".to_string())
        }
        "insider-risk" => {
            Some("Pair with analyst review workflows to reduce false positives before broad rollout.".to_string())
        }
        "ransomware" => {
            Some("Use canary promotion with containment approval gates before activating enterprise-wide.".to_string())
        }
        "admin-abuse" => {
            Some("Map this pack to privileged admin groups so approval paths follow enterprise identity ownership.".to_string())
        }
        _ => None,
    }
}

fn default_pack_list() -> Vec<ContentPack> {
    vec![
        ContentPack::new(
            "identity-attacks",
            "Identity Attacks",
            "Credential abuse, brute force, and Kerberos misuse.",
        ),
        ContentPack::new(
            "lateral-movement",
            "Lateral Movement",
            "Remote execution, propagation, and cross-host movement.",
        ),
        ContentPack::new(
            "cloud-audit",
            "Cloud Audit",
            "Cloud control plane and SaaS audit detections.",
        ),
        ContentPack::new(
            "insider-risk",
            "Insider Risk",
            "Sensitive data access, exfiltration, and policy bypass.",
        ),
        ContentPack::new(
            "ransomware",
            "Ransomware",
            "Mass encryption, backup tampering, and impact patterns.",
        ),
        ContentPack::new(
            "admin-abuse",
            "Admin Abuse",
            "Suspicious admin tooling, persistence, and privileged misuse.",
        ),
    ]
}

fn default_builtin_lifecycle(status: &RuleStatus) -> ContentLifecycle {
    match status {
        RuleStatus::Experimental => ContentLifecycle::Draft,
        RuleStatus::Test => ContentLifecycle::Test,
        RuleStatus::Stable => ContentLifecycle::Active,
        RuleStatus::Deprecated => ContentLifecycle::Deprecated,
    }
}

fn default_pack_ids_for_rule(rule: &SigmaRule) -> Vec<String> {
    let title = rule.title.to_ascii_lowercase();
    let tags = rule.tags.join(" ").to_ascii_lowercase();
    let mut packs = Vec::new();
    if title.contains("credential")
        || title.contains("kerberoast")
        || title.contains("brute")
        || tags.contains("credential")
        || tags.contains("authentication")
    {
        packs.push("identity-attacks".to_string());
    }
    if title.contains("remote")
        || title.contains("lateral")
        || title.contains("psexec")
        || title.contains("wmi")
        || tags.contains("lateral")
    {
        packs.push("lateral-movement".to_string());
    }
    if title.contains("ransom")
        || title.contains("encrypt")
        || title.contains("shadow")
        || tags.contains("impact")
    {
        packs.push("ransomware".to_string());
    }
    if title.contains("powershell")
        || title.contains("admin")
        || title.contains("service")
        || title.contains("task")
        || title.contains("registry")
        || tags.contains("privilege")
    {
        packs.push("admin-abuse".to_string());
    }
    if title.contains("dns")
        || title.contains("exfil")
        || title.contains("archive")
        || title.contains("data")
    {
        packs.push("insider-risk".to_string());
    }
    if title.contains("aws")
        || title.contains("azure")
        || title.contains("gcp")
        || title.contains("cloud")
    {
        packs.push("cloud-audit".to_string());
    }
    packs.sort();
    packs.dedup();
    packs
}

fn search_query_matches_event(event: &StoredEvent, query: &SearchQuery) -> bool {
    if let Some(hostname) = &query.hostname
        && !contains_ci(&event.alert.hostname, hostname)
    {
        return false;
    }
    if let Some(level) = &query.level
        && !event.alert.level.eq_ignore_ascii_case(level)
    {
        return false;
    }
    if let Some(agent_id) = &query.agent_id
        && event.agent_id != *agent_id
    {
        return false;
    }
    if let Some(from_ts) = &query.from_ts
        && event.alert.timestamp < *from_ts
    {
        return false;
    }
    if let Some(to_ts) = &query.to_ts
        && event.alert.timestamp > *to_ts
    {
        return false;
    }
    if let Some(text) = &query.text {
        let in_reasons = event
            .alert
            .reasons
            .iter()
            .any(|reason| contains_ci(reason, text));
        let in_host = contains_ci(&event.alert.hostname, text);
        let in_action = contains_ci(&event.alert.action, text);
        let in_mitre = event.alert.mitre.iter().any(|attack| {
            contains_ci(&attack.technique_id, text) || contains_ci(&attack.technique_name, text)
        });
        if !in_reasons && !in_host && !in_action && !in_mitre {
            return false;
        }
    }
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContentLifecycle {
    Draft,
    Test,
    Canary,
    Active,
    Deprecated,
    RolledBack,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContentKind {
    Sigma,
    Native,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleChange {
    pub changed_at: String,
    pub changed_by: String,
    pub from: ContentLifecycle,
    pub to: ContentLifecycle,
    pub reason: String,
}

/// Result of the canary auto-promotion evaluation for a single rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryPromotionResult {
    pub rule_id: String,
    pub rule_name: String,
    pub action: CanaryAction,
    pub reason: String,
}

/// Action taken (or not) during canary auto-promotion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CanaryAction {
    Promoted,
    RolledBack,
    NoChange,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedRuleMetadata {
    pub id: String,
    pub title: String,
    pub description: String,
    pub owner: String,
    pub kind: ContentKind,
    pub builtin: bool,
    pub enabled: bool,
    pub lifecycle: ContentLifecycle,
    pub previous_lifecycle: Option<ContentLifecycle>,
    pub version: u32,
    pub pack_ids: Vec<String>,
    pub attack: Vec<MitreAttack>,
    pub false_positive_review: Option<String>,
    pub last_test_at: Option<String>,
    pub last_test_match_count: usize,
    pub last_promotion_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub lifecycle_history: Vec<LifecycleChange>,
}

impl ManagedRuleMetadata {
    fn builtin_from_sigma(rule: &SigmaRule) -> Self {
        let created_at = now_rfc3339();
        Self {
            id: rule.id.clone(),
            title: rule.title.clone(),
            description: rule.description.clone(),
            owner: "system".to_string(),
            kind: ContentKind::Sigma,
            builtin: true,
            enabled: rule.enabled,
            lifecycle: default_builtin_lifecycle(&rule.status),
            previous_lifecycle: None,
            version: 1,
            pack_ids: default_pack_ids_for_rule(rule),
            attack: rule.attack.iter().map(mitre_from_attack_mapping).collect(),
            false_positive_review: rule.falsepositives.first().cloned(),
            last_test_at: None,
            last_test_match_count: 0,
            last_promotion_at: None,
            created_at: created_at.clone(),
            updated_at: created_at,
            lifecycle_history: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeContentRule {
    pub metadata: ManagedRuleMetadata,
    pub query: SearchQuery,
    pub severity_mapping: String,
    pub rationale: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentPack {
    pub id: String,
    pub name: String,
    pub description: String,
    pub use_case: String,
    pub enabled: bool,
    pub rule_ids: Vec<String>,
    #[serde(default)]
    pub saved_searches: Vec<String>,
    #[serde(default)]
    pub recommended_workflows: Vec<String>,
    pub target_group: Option<String>,
    pub rollout_notes: Option<String>,
    pub updated_at: String,
}

impl ContentPack {
    pub fn new(id: &str, name: &str, description: &str) -> Self {
        Self {
            id: id.to_string(),
            name: name.to_string(),
            description: description.to_string(),
            use_case: id.to_string(),
            enabled: true,
            rule_ids: Vec::new(),
            saved_searches: default_pack_saved_searches(id),
            recommended_workflows: default_pack_workflows(id),
            target_group: default_pack_target_group(id),
            rollout_notes: default_pack_rollout_notes(id),
            updated_at: now_rfc3339(),
        }
    }
}

fn default_hunt_lifecycle() -> ContentLifecycle {
    ContentLifecycle::Draft
}

fn default_canary_percentage() -> u8 {
    100
}

fn default_hunt_hypothesis() -> String {
    String::new()
}

fn default_hunt_expected_outcome() -> HuntExpectedOutcome {
    HuntExpectedOutcome::Explore
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HuntExpectedOutcome {
    Confirm,
    Refute,
    Explore,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedHunt {
    pub id: String,
    pub name: String,
    pub owner: String,
    pub enabled: bool,
    pub severity: String,
    pub threshold: usize,
    pub suppression_window_secs: u64,
    pub schedule_interval_secs: Option<u64>,
    pub schedule_cron: Option<String>,
    pub last_run_at: Option<String>,
    pub next_run_at: Option<String>,
    pub query: SearchQuery,
    #[serde(default = "default_hunt_hypothesis")]
    pub hypothesis: String,
    #[serde(default = "default_hunt_expected_outcome")]
    pub expected_outcome: HuntExpectedOutcome,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default = "default_hunt_lifecycle")]
    pub lifecycle: ContentLifecycle,
    #[serde(default = "default_canary_percentage")]
    pub canary_percentage: u8,
    pub pack_id: Option<String>,
    #[serde(default)]
    pub recommended_workflows: Vec<String>,
    pub target_group: Option<String>,
    /// Automated response actions triggered when threshold is exceeded.
    #[serde(default)]
    pub response_actions: Vec<HuntResponseAction>,
    /// Tags for categorisation and filtering.
    #[serde(default)]
    pub tags: Vec<String>,
    /// MITRE ATT&CK technique IDs associated with this hunt.
    #[serde(default)]
    pub mitre_techniques: Vec<String>,
}

/// Automated response action that fires when a hunt threshold is exceeded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum HuntResponseAction {
    /// Send a notification via configured channels.
    Notify { channel: String, min_level: String },
    /// Create an incident automatically.
    CreateIncident {
        severity: String,
        title_template: String,
    },
    /// Suppress the matching rule for a duration.
    AutoSuppress {
        duration_secs: u64,
        justification: String,
    },
    /// Isolate the affected agent from the network.
    IsolateAgent,
}

/// Result of evaluating response actions after a hunt run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseActionResult {
    pub action: String,
    pub executed: bool,
    pub detail: String,
}

fn hunt_severity_rank(level: &str) -> u8 {
    match level.trim().to_ascii_lowercase().as_str() {
        "info" | "low" => 1,
        "medium" | "elevated" => 2,
        "high" | "severe" => 3,
        "critical" => 4,
        _ => 1,
    }
}

impl SavedHunt {
    /// Evaluate response actions for a completed hunt run.
    pub fn evaluate_responses(&self, run: &HuntRun) -> Vec<ResponseActionResult> {
        if !run.threshold_exceeded || self.response_actions.is_empty() {
            return vec![];
        }
        self.response_actions.iter().map(|action| {
            match action {
                HuntResponseAction::Notify { channel, min_level } => {
                    let executed = hunt_severity_rank(&run.severity) >= hunt_severity_rank(min_level);
                    ResponseActionResult {
                        action: "notify".into(),
                        executed,
                        detail: if executed {
                            format!("Notify channel '{}' (min_level={}): {} matches", channel, min_level, run.match_count)
                        } else {
                            format!(
                                "Skipped notify channel '{}' because run severity '{}' is below min_level '{}'",
                                channel, run.severity, min_level
                            )
                        },
                    }
                }
                HuntResponseAction::CreateIncident { severity, title_template } => {
                    let title = title_template
                        .replace("{hunt_name}", &self.name)
                        .replace("{match_count}", &run.match_count.to_string());
                    ResponseActionResult {
                        action: "create_incident".into(),
                        executed: true,
                        detail: format!("Create {severity} incident: {title}"),
                    }
                }
                HuntResponseAction::AutoSuppress { duration_secs, justification } => ResponseActionResult {
                    action: "auto_suppress".into(),
                    executed: true,
                    detail: format!("Suppress for {duration_secs}s: {justification}"),
                },
                HuntResponseAction::IsolateAgent => ResponseActionResult {
                    action: "isolate_agent".into(),
                    executed: true,
                    detail: format!("Isolate agents from {} matching events", run.match_count),
                },
            }
        }).collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntRun {
    pub id: String,
    pub hunt_id: String,
    pub run_at: String,
    pub match_count: usize,
    pub suppressed_count: usize,
    pub threshold_exceeded: bool,
    pub severity: String,
    pub case_id: Option<u64>,
    pub time_from: Option<String>,
    pub time_to: Option<String>,
    pub yield_rate: f32,
    #[serde(default)]
    pub matched_event_ids: Vec<u64>,
    #[serde(default)]
    pub matched_agent_ids: Vec<String>,
    pub sample_event_ids: Vec<u64>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleTestResult {
    pub id: String,
    pub rule_id: String,
    pub tested_at: String,
    pub match_count: usize,
    pub suppressed_count: usize,
    pub sample_event_ids: Vec<u64>,
    pub new_match_ids: Vec<u64>,
    pub cleared_match_ids: Vec<u64>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertSuppressionAuditEntry {
    pub timestamp: String,
    pub actor: String,
    pub action: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertSuppression {
    pub id: String,
    pub name: String,
    pub rule_id: Option<String>,
    pub hunt_id: Option<String>,
    pub hostname: Option<String>,
    pub agent_id: Option<String>,
    pub severity: Option<String>,
    pub text: Option<String>,
    pub expires_at: Option<String>,
    pub justification: String,
    pub created_by: String,
    pub created_at: String,
    pub active: bool,
    pub audit: Vec<AlertSuppressionAuditEntry>,
}

impl AlertSuppression {
    pub fn is_active(&self) -> bool {
        if !self.active {
            return false;
        }
        match &self.expires_at {
            Some(expires_at) => parse_time(expires_at)
                .map(|ts| ts > chrono::Utc::now())
                .unwrap_or(true),
            None => true,
        }
    }

    pub fn matches_event(
        &self,
        event: &StoredEvent,
        rule_id: Option<&str>,
        hunt_id: Option<&str>,
    ) -> bool {
        if !self.is_active() {
            return false;
        }
        if let Some(expected) = &self.rule_id
            && Some(expected.as_str()) != rule_id
        {
            return false;
        }
        if let Some(expected) = &self.hunt_id
            && Some(expected.as_str()) != hunt_id
        {
            return false;
        }
        if let Some(hostname) = &self.hostname
            && !contains_ci(&event.alert.hostname, hostname)
        {
            return false;
        }
        if let Some(agent_id) = &self.agent_id
            && event.agent_id != *agent_id
        {
            return false;
        }
        if let Some(severity) = &self.severity
            && !event.alert.level.eq_ignore_ascii_case(severity)
        {
            return false;
        }
        if let Some(text) = &self.text {
            let reasons = event.alert.reasons.join(" ");
            if !contains_ci(&event.alert.hostname, text)
                && !contains_ci(&event.alert.action, text)
                && !contains_ci(&reasons, text)
            {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentConnector {
    pub id: String,
    pub kind: String,
    pub display_name: String,
    pub endpoint: Option<String>,
    pub auth_mode: Option<String>,
    pub enabled: bool,
    pub status: String,
    pub timeout_secs: u64,
    pub last_sync_at: Option<String>,
    pub last_error: Option<String>,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketSyncRecord {
    pub id: String,
    pub provider: String,
    pub object_kind: String,
    pub object_id: String,
    pub status: String,
    pub external_key: String,
    pub queue_or_project: Option<String>,
    pub summary: String,
    pub synced_by: String,
    pub synced_at: String,
    pub sync_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityProviderConfig {
    pub id: String,
    pub kind: String,
    pub display_name: String,
    pub issuer_url: Option<String>,
    pub sso_url: Option<String>,
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    pub entity_id: Option<String>,
    pub enabled: bool,
    pub status: String,
    pub group_role_mappings: HashMap<String, String>,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimConfig {
    pub enabled: bool,
    pub base_url: Option<String>,
    pub bearer_token: Option<String>,
    pub provisioning_mode: String,
    pub default_role: String,
    pub group_role_mappings: HashMap<String, String>,
    pub status: String,
    pub updated_at: Option<String>,
    pub last_sync_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IdentityConfigIssue {
    pub level: String,
    pub field: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct IdentityConfigValidation {
    pub status: String,
    pub issues: Vec<IdentityConfigIssue>,
    pub mapping_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct IdentityProviderSummary {
    #[serde(flatten)]
    pub provider: IdentityProviderConfig,
    pub validation: IdentityConfigValidation,
}

impl Default for ScimConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: None,
            bearer_token: None,
            provisioning_mode: "manual".to_string(),
            default_role: "viewer".to_string(),
            group_role_mappings: HashMap::new(),
            status: "disabled".to_string(),
            updated_at: None,
            last_sync_at: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeControlEntry {
    pub id: String,
    pub category: String,
    pub target: String,
    pub summary: String,
    pub requested_by: String,
    pub status: String,
    pub created_at: String,
    pub executed_at: Option<String>,
    pub payload_hash: Option<String>,
    pub reference_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OperationalMetrics {
    pub search_queries_total: u64,
    pub hunt_runs_total: u64,
    pub response_exec_total: u64,
    pub ticket_sync_total: u64,
    pub last_search_latency_ms: u64,
    pub last_hunt_latency_ms: u64,
    pub last_response_latency_ms: u64,
    pub last_ticket_sync_latency_ms: u64,
    pub last_search_at: Option<String>,
    pub last_hunt_at: Option<String>,
    pub last_response_at: Option<String>,
    pub last_ticket_sync_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaybookAnalyticsRecord {
    pub execution_id: String,
    pub playbook_id: String,
    pub alert_id: Option<String>,
    pub executed_by: String,
    pub status: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub duration_ms: Option<u64>,
    pub step_count: usize,
    pub error: Option<String>,
    pub recorded_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolloutAnalyticsRecord {
    pub id: String,
    pub action: String,
    pub version: String,
    pub platform: Option<String>,
    pub agent_id: Option<String>,
    pub rollout_group: Option<String>,
    pub status: String,
    pub requested_by: String,
    pub notes: Option<String>,
    pub recorded_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct EnterpriseSnapshot {
    builtin_rules: Vec<ManagedRuleMetadata>,
    native_rules: Vec<NativeContentRule>,
    packs: Vec<ContentPack>,
    hunts: Vec<SavedHunt>,
    hunt_runs: Vec<HuntRun>,
    rule_tests: Vec<RuleTestResult>,
    suppressions: Vec<AlertSuppression>,
    connectors: Vec<EnrichmentConnector>,
    ticket_syncs: Vec<TicketSyncRecord>,
    idp_providers: Vec<IdentityProviderConfig>,
    scim: ScimConfig,
    change_control: Vec<ChangeControlEntry>,
    metrics: OperationalMetrics,
    #[serde(default)]
    playbook_history: Vec<PlaybookAnalyticsRecord>,
    #[serde(default)]
    rollout_history: Vec<RolloutAnalyticsRecord>,
    next_counter: u64,
}

pub struct EnterpriseStore {
    snapshot: EnterpriseSnapshot,
    store_path: String,
}

fn lifecycle_slug(lifecycle: &ContentLifecycle) -> &'static str {
    match lifecycle {
        ContentLifecycle::Draft => "draft",
        ContentLifecycle::Test => "test",
        ContentLifecycle::Canary => "canary",
        ContentLifecycle::Active => "active",
        ContentLifecycle::Deprecated => "deprecated",
        ContentLifecycle::RolledBack => "rolled_back",
    }
}

fn validate_idp_provider_config(provider: &IdentityProviderConfig) -> IdentityConfigValidation {
    let mut issues = Vec::new();
    if provider.display_name.trim().is_empty() {
        issues.push(validation_issue(
            "error",
            "display_name",
            "Display name is required.",
        ));
    }

    match provider.kind.trim().to_ascii_lowercase().as_str() {
        "oidc" => {
            if provider.enabled
                && provider
                    .issuer_url
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .is_empty()
            {
                issues.push(validation_issue(
                    "error",
                    "issuer_url",
                    "Enabled OIDC providers require an issuer URL.",
                ));
            }
            if provider.enabled
                && provider
                    .client_id
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .is_empty()
            {
                issues.push(validation_issue(
                    "error",
                    "client_id",
                    "Enabled OIDC providers require a client ID.",
                ));
            }
            if provider.enabled
                && provider
                    .client_secret
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .is_empty()
            {
                issues.push(validation_issue(
                    "error",
                    "client_secret",
                    "Enabled OIDC providers require a client secret.",
                ));
            }
            if provider.enabled
                && provider
                    .redirect_uri
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .is_empty()
            {
                issues.push(validation_issue(
                    "error",
                    "redirect_uri",
                    "Enabled OIDC providers require a redirect URI.",
                ));
            }
        }
        "saml" => {
            if provider.enabled && provider.sso_url.as_deref().unwrap_or("").trim().is_empty() {
                issues.push(validation_issue(
                    "error",
                    "sso_url",
                    "Enabled SAML providers require an SSO URL.",
                ));
            }
            if provider.enabled
                && provider
                    .entity_id
                    .as_deref()
                    .unwrap_or("")
                    .trim()
                    .is_empty()
            {
                issues.push(validation_issue(
                    "error",
                    "entity_id",
                    "Enabled SAML providers require an entity ID.",
                ));
            }
        }
        _ => issues.push(validation_issue(
            "error",
            "kind",
            "Provider kind must be OIDC or SAML.",
        )),
    }

    if provider.enabled && provider.group_role_mappings.is_empty() {
        issues.push(validation_issue(
            "warning",
            "group_role_mappings",
            "No group-to-role mappings configured; users may fall back to viewer access.",
        ));
    }

    IdentityConfigValidation {
        status: validation_status(provider.enabled, &issues),
        mapping_count: provider.group_role_mappings.len(),
        issues,
    }
}

fn validate_scim_config(config: &ScimConfig) -> IdentityConfigValidation {
    let mut issues = Vec::new();
    if config.enabled && config.base_url.as_deref().unwrap_or("").trim().is_empty() {
        issues.push(validation_issue(
            "error",
            "base_url",
            "Enabled SCIM provisioning requires a base URL.",
        ));
    }
    if config.enabled
        && config
            .bearer_token
            .as_deref()
            .unwrap_or("")
            .trim()
            .is_empty()
    {
        issues.push(validation_issue(
            "error",
            "bearer_token",
            "Enabled SCIM provisioning requires a bearer token.",
        ));
    }
    if !SCIM_PROVISIONING_MODES.contains(&config.provisioning_mode.as_str()) {
        issues.push(validation_issue(
            "error",
            "provisioning_mode",
            "Provisioning mode must be manual or automatic.",
        ));
    }
    if !IDENTITY_ROLES.contains(&config.default_role.as_str()) {
        issues.push(validation_issue(
            "error",
            "default_role",
            "Default role must be admin, analyst, or viewer.",
        ));
    }
    if config.enabled && config.group_role_mappings.is_empty() {
        issues.push(validation_issue(
            "warning",
            "group_role_mappings",
            "No group-to-role mappings configured; all provisioned users receive the default role.",
        ));
    }
    if config.enabled && config.default_role == "admin" {
        issues.push(validation_issue(
            "warning",
            "default_role",
            "Default role is admin; review whether all newly provisioned users should be privileged.",
        ));
    }

    IdentityConfigValidation {
        status: validation_status(config.enabled, &issues),
        mapping_count: config.group_role_mappings.len(),
        issues,
    }
}

pub fn build_rule_review_history(
    store: &EnterpriseStore,
    feedback_store: &DetectionFeedbackStore,
    rule_id: &str,
) -> serde_json::Value {
    let mut recent_replays: Vec<&RuleTestResult> = store
        .rule_tests()
        .iter()
        .filter(|result| result.rule_id == rule_id)
        .collect();
    recent_replays.sort_by(|left, right| right.tested_at.cmp(&left.tested_at));
    let recent_replays: Vec<serde_json::Value> = recent_replays
        .into_iter()
        .take(3)
        .map(|result| {
            serde_json::json!({
                "tested_at": result.tested_at,
                "match_count": result.match_count,
                "suppressed_count": result.suppressed_count,
                "new_match_count": result.new_match_ids.len(),
                "cleared_match_count": result.cleared_match_ids.len(),
                "summary": result.summary,
            })
        })
        .collect();
    let latest_replay = recent_replays
        .first()
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    let mut feedback = feedback_store.for_rule(rule_id);
    feedback.sort_by(|left, right| right.created_at.cmp(&left.created_at));
    let mut by_verdict = HashMap::new();
    for entry in &feedback {
        *by_verdict.entry(entry.verdict.clone()).or_insert(0usize) += 1;
    }
    let recent_feedback: Vec<serde_json::Value> = feedback
        .iter()
        .take(3)
        .map(|entry| {
            serde_json::json!({
                "id": entry.id,
                "analyst": entry.analyst,
                "verdict": entry.verdict,
                "notes": entry.notes,
                "created_at": entry.created_at,
            })
        })
        .collect();
    let latest_feedback = feedback.first();

    serde_json::json!({
        "latest_replay": latest_replay,
        "recent_replays": recent_replays,
        "analyst_feedback": {
            "total": feedback.len(),
            "by_verdict": by_verdict,
            "latest_verdict": latest_feedback.map(|entry| entry.verdict.clone()),
            "latest_analyst": latest_feedback.map(|entry| entry.analyst.clone()),
            "latest_notes": latest_feedback
                .map(|entry| entry.notes.clone())
                .filter(|notes| !notes.trim().is_empty()),
            "latest_at": latest_feedback.map(|entry| entry.created_at.clone()),
            "recent": recent_feedback,
        }
    })
}

pub fn build_content_rules_view(
    store: &EnterpriseStore,
    feedback_store: &DetectionFeedbackStore,
) -> Vec<serde_json::Value> {
    let mut items = Vec::new();
    for rule in store.builtin_rules() {
        let review_history = build_rule_review_history(store, feedback_store, &rule.id);
        items.push(serde_json::json!({
            "id": rule.id,
            "title": rule.title,
            "description": rule.description,
            "kind": "sigma",
            "builtin": true,
            "owner": rule.owner,
            "enabled": rule.enabled,
            "lifecycle": rule.lifecycle,
            "version": rule.version,
            "pack_ids": rule.pack_ids,
            "attack": rule.attack,
            "last_test_at": rule.last_test_at,
            "last_test_match_count": rule.last_test_match_count,
            "last_promotion_at": rule.last_promotion_at,
            "false_positive_review": rule.false_positive_review,
            "review_history": review_history,
        }));
    }
    for rule in store.native_rules() {
        let review_history = build_rule_review_history(store, feedback_store, &rule.metadata.id);
        items.push(serde_json::json!({
            "id": rule.metadata.id,
            "title": rule.metadata.title,
            "description": rule.metadata.description,
            "kind": "native",
            "builtin": false,
            "owner": rule.metadata.owner,
            "enabled": rule.metadata.enabled,
            "lifecycle": rule.metadata.lifecycle,
            "version": rule.metadata.version,
            "pack_ids": rule.metadata.pack_ids,
            "attack": rule.metadata.attack,
            "severity_mapping": rule.severity_mapping,
            "query": rule.query,
            "last_test_at": rule.metadata.last_test_at,
            "last_test_match_count": rule.metadata.last_test_match_count,
            "last_promotion_at": rule.metadata.last_promotion_at,
            "false_positive_review": rule.metadata.false_positive_review,
            "review_history": review_history,
        }));
    }
    items.sort_by(|a, b| {
        let a_builtin = a["builtin"].as_bool().unwrap_or(false);
        let b_builtin = b["builtin"].as_bool().unwrap_or(false);
        b_builtin.cmp(&a_builtin).then_with(|| {
            a["id"]
                .as_str()
                .unwrap_or_default()
                .cmp(b["id"].as_str().unwrap_or_default())
        })
    });
    items
}

pub fn build_mitre_coverage(store: &EnterpriseStore, incidents: &[Incident]) -> serde_json::Value {
    let mut technique_map: HashMap<String, serde_json::Value> = HashMap::new();
    for rule in store.builtin_rules() {
        for attack in &rule.attack {
            let entry = technique_map
                .entry(attack.technique_id.clone())
                .or_insert_with(|| {
                    serde_json::json!({
                        "technique_id": attack.technique_id,
                        "technique_name": attack.technique_name,
                        "tactic": attack.tactic,
                        "enabled_rules": 0usize,
                        "disabled_rules": 0usize,
                        "packs": Vec::<String>::new(),
                        "incident_count": 0usize,
                        "enabled": false,
                    })
                });
            if matches!(
                rule.lifecycle,
                ContentLifecycle::Active | ContentLifecycle::Canary | ContentLifecycle::Test
            ) && rule.enabled
            {
                entry["enabled_rules"] =
                    serde_json::json!(entry["enabled_rules"].as_u64().unwrap_or(0) + 1);
                entry["enabled"] = serde_json::json!(true);
            } else {
                entry["disabled_rules"] =
                    serde_json::json!(entry["disabled_rules"].as_u64().unwrap_or(0) + 1);
            }
            let mut packs = entry["packs"].as_array().cloned().unwrap_or_default();
            for pack_id in &rule.pack_ids {
                if !packs
                    .iter()
                    .any(|value| value.as_str() == Some(pack_id.as_str()))
                {
                    packs.push(serde_json::json!(pack_id));
                }
            }
            entry["packs"] = serde_json::Value::Array(packs);
        }
    }
    for rule in store.native_rules() {
        for attack in &rule.metadata.attack {
            let entry = technique_map
                .entry(attack.technique_id.clone())
                .or_insert_with(|| {
                    serde_json::json!({
                        "technique_id": attack.technique_id,
                        "technique_name": attack.technique_name,
                        "tactic": attack.tactic,
                        "enabled_rules": 0usize,
                        "disabled_rules": 0usize,
                        "packs": Vec::<String>::new(),
                        "incident_count": 0usize,
                        "enabled": false,
                    })
                });
            if matches!(
                rule.metadata.lifecycle,
                ContentLifecycle::Active | ContentLifecycle::Canary | ContentLifecycle::Test
            ) && rule.metadata.enabled
            {
                entry["enabled_rules"] =
                    serde_json::json!(entry["enabled_rules"].as_u64().unwrap_or(0) + 1);
                entry["enabled"] = serde_json::json!(true);
            } else {
                entry["disabled_rules"] =
                    serde_json::json!(entry["disabled_rules"].as_u64().unwrap_or(0) + 1);
            }
        }
    }
    for incident in incidents {
        for attack in &incident.mitre_techniques {
            let entry = technique_map
                .entry(attack.technique_id.clone())
                .or_insert_with(|| {
                    serde_json::json!({
                        "technique_id": attack.technique_id,
                        "technique_name": attack.technique_name,
                        "tactic": attack.tactic,
                        "enabled_rules": 0usize,
                        "disabled_rules": 0usize,
                        "packs": Vec::<String>::new(),
                        "incident_count": 0usize,
                        "enabled": false,
                    })
                });
            entry["incident_count"] =
                serde_json::json!(entry["incident_count"].as_u64().unwrap_or(0) + 1);
        }
    }

    let mut techniques: Vec<serde_json::Value> = technique_map.into_values().collect();
    techniques.sort_by(|a, b| {
        b["incident_count"]
            .as_u64()
            .unwrap_or(0)
            .cmp(&a["incident_count"].as_u64().unwrap_or(0))
            .then_with(|| {
                a["technique_id"]
                    .as_str()
                    .unwrap_or("")
                    .cmp(b["technique_id"].as_str().unwrap_or(""))
            })
    });

    let coverage_gap: Vec<serde_json::Value> = techniques
        .iter()
        .filter(|technique| technique["enabled"].as_bool() != Some(true))
        .map(|technique| {
            serde_json::json!({
                "technique_id": technique["technique_id"],
                "technique_name": technique["technique_name"],
                "reason": if technique["disabled_rules"].as_u64().unwrap_or(0) > 0 { "disabled_only" } else { "not_covered" },
            })
        })
        .collect();

    serde_json::json!({
        "techniques": techniques,
        "packs": store.packs(),
        "coverage_gap": coverage_gap,
    })
}

pub fn build_entity_profile(
    kind: &str,
    id: &str,
    events: &[StoredEvent],
    incidents: &[Incident],
    cases: &[Case],
    iocs: &[IoC],
    response_requests: &[ResponseRequest],
    users: &[User],
    connectors: &[EnrichmentConnector],
    ticket_syncs: &[TicketSyncRecord],
) -> serde_json::Value {
    let normalized = kind.trim().to_ascii_lowercase();
    let mut related_event_ids = Vec::new();
    let mut related_incidents = Vec::new();
    let mut related_cases = Vec::new();
    let mut references = Vec::new();
    let mut last_seen: Option<String> = None;

    for event in events {
        let matched = match normalized.as_str() {
            "host" => event.alert.hostname.eq_ignore_ascii_case(id),
            "process" => event
                .alert
                .reasons
                .iter()
                .any(|reason| contains_ci(reason, id)),
            "ip" | "domain" | "hash" => event
                .alert
                .reasons
                .iter()
                .any(|reason| contains_ci(reason, id)),
            "user" | "account" => event
                .triage
                .assignee
                .as_deref()
                .map(|assignee| assignee.eq_ignore_ascii_case(id))
                .unwrap_or(false),
            _ => false,
        };
        if matched {
            related_event_ids.push(event.id);
            references.push(serde_json::json!({
                "kind": "event",
                "id": event.id,
                "timestamp": event.received_at,
                "summary": event.alert.reasons.join(", "),
            }));
            if last_seen
                .as_deref()
                .map(|ts| ts < event.received_at.as_str())
                .unwrap_or(true)
            {
                last_seen = Some(event.received_at.clone());
            }
        }
    }

    for incident in incidents {
        let matched = match normalized.as_str() {
            "host" => incident
                .event_ids
                .iter()
                .any(|event_id| related_event_ids.contains(event_id)),
            "user" | "account" => incident
                .assignee
                .as_deref()
                .map(|assignee| assignee.eq_ignore_ascii_case(id))
                .unwrap_or(false),
            _ => incident
                .summary
                .to_ascii_lowercase()
                .contains(&id.to_ascii_lowercase()),
        };
        if matched {
            related_incidents.push(incident.id);
        }
    }

    for case in cases {
        let matched = match normalized.as_str() {
            "host" => case
                .event_ids
                .iter()
                .any(|event_id| related_event_ids.contains(event_id)),
            "user" | "account" => case
                .assignee
                .as_deref()
                .map(|assignee| assignee.eq_ignore_ascii_case(id))
                .unwrap_or(false),
            _ => {
                case.title
                    .to_ascii_lowercase()
                    .contains(&id.to_ascii_lowercase())
                    || case
                        .description
                        .to_ascii_lowercase()
                        .contains(&id.to_ascii_lowercase())
            }
        };
        if matched {
            related_cases.push(case.id);
        }
    }

    if matches!(normalized.as_str(), "ip" | "domain" | "hash" | "process") {
        for ioc in iocs {
            let ioc_kind = match ioc.ioc_type {
                IoCType::IpAddress => "ip",
                IoCType::Domain => "domain",
                IoCType::FileHash => "hash",
                IoCType::ProcessName => "process",
                _ => "",
            };
            if ioc_kind == normalized && ioc.value.eq_ignore_ascii_case(id) {
                references.push(serde_json::json!({
                    "kind": "threat_intel",
                    "value": ioc.value,
                    "severity": ioc.severity,
                    "source": ioc.source,
                }));
                last_seen = Some(ioc.last_seen.clone());
            }
        }
    }

    if matches!(normalized.as_str(), "process" | "host" | "user" | "account") {
        for request in response_requests {
            let matched = match normalized.as_str() {
                "process" => response_action_label(&request.action)
                    .to_ascii_lowercase()
                    .contains(&id.to_ascii_lowercase()),
                "host" => request.target.hostname.eq_ignore_ascii_case(id),
                "user" | "account" => {
                    request.requested_by.eq_ignore_ascii_case(id)
                        || request
                            .approvals
                            .iter()
                            .any(|approval| approval.approver.eq_ignore_ascii_case(id))
                }
                _ => false,
            };
            if matched {
                references.push(serde_json::json!({
                    "kind": "response",
                    "id": request.id,
                    "status": response_status_label(&request.status),
                    "summary": response_action_label(&request.action),
                }));
            }
        }
    }

    if matches!(normalized.as_str(), "user" | "account") {
        for user in users {
            if user.username.eq_ignore_ascii_case(id) {
                references.push(serde_json::json!({
                    "kind": "rbac_user",
                    "username": user.username,
                    "role": format!("{:?}", user.role),
                    "enabled": user.enabled,
                }));
            }
        }
    }

    let enrichments: Vec<serde_json::Value> = connectors
        .iter()
        .filter(|connector| connector.enabled)
        .map(|connector| {
            serde_json::json!({
                "source": connector.kind,
                "status": connector.status,
                "summary": format!("{} enrichment available", connector.display_name),
            })
        })
        .collect();

    let synced_tickets: Vec<serde_json::Value> = ticket_syncs
        .iter()
        .filter(|sync| match normalized.as_str() {
            "host" => sync
                .summary
                .to_ascii_lowercase()
                .contains(&id.to_ascii_lowercase()),
            "user" | "account" => sync.synced_by.eq_ignore_ascii_case(id),
            _ => sync
                .summary
                .to_ascii_lowercase()
                .contains(&id.to_ascii_lowercase()),
        })
        .map(|sync| {
            serde_json::json!({
                "provider": sync.provider,
                "external_key": sync.external_key,
                "status": sync.status,
                "synced_at": sync.synced_at,
            })
        })
        .collect();

    let risk = if !related_incidents.is_empty() {
        "high"
    } else if !related_event_ids.is_empty() || !references.is_empty() {
        "medium"
    } else {
        "low"
    };

    serde_json::json!({
        "kind": normalized,
        "id": id,
        "label": id,
        "risk": risk,
        "last_seen": last_seen,
        "related_event_count": related_event_ids.len(),
        "related_incident_count": related_incidents.len(),
        "related_case_count": related_cases.len(),
        "related_event_ids": related_event_ids,
        "related_incidents": related_incidents,
        "related_cases": related_cases,
        "references": references,
        "enrichments": enrichments,
        "ticket_syncs": synced_tickets,
    })
}

pub fn build_entity_timeline(
    kind: &str,
    id: &str,
    events: &[StoredEvent],
    incidents: &[Incident],
    cases: &[Case],
    response_audit: &[ResponseAuditEntry],
    ticket_syncs: &[TicketSyncRecord],
) -> Vec<serde_json::Value> {
    let normalized = kind.trim().to_ascii_lowercase();
    let mut items = Vec::new();

    for event in events {
        let matched = match normalized.as_str() {
            "host" => event.alert.hostname.eq_ignore_ascii_case(id),
            "user" | "account" => event
                .triage
                .assignee
                .as_deref()
                .map(|assignee| assignee.eq_ignore_ascii_case(id))
                .unwrap_or(false),
            _ => event
                .alert
                .reasons
                .iter()
                .any(|reason| contains_ci(reason, id)),
        };
        if matched {
            items.push(serde_json::json!({
                "timestamp": event.received_at,
                "kind": "event",
                "summary": format!("Event #{} · {}", event.id, event.alert.reasons.join(", ")),
                "severity": event.alert.level,
            }));
        }
    }

    for incident in incidents {
        let matched = match normalized.as_str() {
            "host" => incident
                .summary
                .to_ascii_lowercase()
                .contains(&id.to_ascii_lowercase()),
            "user" | "account" => incident
                .assignee
                .as_deref()
                .map(|assignee| assignee.eq_ignore_ascii_case(id))
                .unwrap_or(false),
            _ => incident
                .summary
                .to_ascii_lowercase()
                .contains(&id.to_ascii_lowercase()),
        };
        if matched {
            items.push(serde_json::json!({
                "timestamp": incident.updated_at,
                "kind": "incident",
                "summary": format!("Incident #{} · {}", incident.id, incident.title),
                "severity": incident.severity,
            }));
        }
    }

    for case in cases {
        let matched = match normalized.as_str() {
            "user" | "account" => case
                .assignee
                .as_deref()
                .map(|assignee| assignee.eq_ignore_ascii_case(id))
                .unwrap_or(false),
            _ => case
                .title
                .to_ascii_lowercase()
                .contains(&id.to_ascii_lowercase()),
        };
        if matched {
            items.push(serde_json::json!({
                "timestamp": case.updated_at,
                "kind": "case",
                "summary": format!("Case #{} · {}", case.id, case.title),
                "severity": format!("{:?}", case.priority),
            }));
        }
    }

    for audit in response_audit {
        let matched = match normalized.as_str() {
            "host" => audit.target_hostname.eq_ignore_ascii_case(id),
            "user" | "account" => audit
                .approvals
                .iter()
                .any(|approval| approval.approver.eq_ignore_ascii_case(id)),
            _ => audit
                .action
                .to_ascii_lowercase()
                .contains(&id.to_ascii_lowercase()),
        };
        if matched {
            items.push(serde_json::json!({
                "timestamp": audit.timestamp,
                "kind": "response_audit",
                "summary": audit.action,
                "severity": format!("{:?}", audit.status),
            }));
        }
    }

    for sync in ticket_syncs {
        let matched = match normalized.as_str() {
            "user" | "account" => sync.synced_by.eq_ignore_ascii_case(id),
            _ => sync
                .summary
                .to_ascii_lowercase()
                .contains(&id.to_ascii_lowercase()),
        };
        if matched {
            items.push(serde_json::json!({
                "timestamp": sync.synced_at,
                "kind": "ticket_sync",
                "summary": format!("{} {}", sync.provider, sync.external_key),
                "severity": sync.status,
            }));
        }
    }

    items.sort_by(|a, b| {
        b["timestamp"]
            .as_str()
            .unwrap_or("")
            .cmp(a["timestamp"].as_str().unwrap_or(""))
    });
    items
}

pub fn build_incident_storyline(
    incident: &Incident,
    related_events: &[StoredEvent],
    cases: &[Case],
    response_requests: &[ResponseRequest],
    response_audit: &[ResponseAuditEntry],
    ticket_syncs: &[TicketSyncRecord],
) -> serde_json::Value {
    let mut hosts = HashSet::new();
    let mut reasons = HashSet::new();
    let mut techniques = Vec::new();
    let mut timeline = Vec::new();
    for event in related_events {
        hosts.insert(event.alert.hostname.clone());
        for reason in &event.alert.reasons {
            reasons.insert(reason.clone());
        }
        for attack in &event.alert.mitre {
            techniques.push(serde_json::json!({
                "technique_id": attack.technique_id,
                "technique_name": attack.technique_name,
                "tactic": attack.tactic,
            }));
        }
        timeline.push(serde_json::json!({
            "timestamp": event.received_at,
            "stage": if severity_rank(&event.alert.level) >= 4 { "impact" } else { "detection" },
            "summary": format!("{} on {}", event.alert.reasons.join(", "), event.alert.hostname),
            "event_id": event.id,
            "severity": event.alert.level,
        }));
    }
    let linked_cases: Vec<serde_json::Value> = cases
        .iter()
        .filter(|case| case.incident_ids.contains(&incident.id))
        .map(|case| {
            serde_json::json!({
                "id": case.id,
                "title": case.title,
                "status": format!("{:?}", case.status),
                "assignee": case.assignee,
            })
        })
        .collect();
    let response_actions: Vec<serde_json::Value> = response_requests
        .iter()
        .filter(|request| hosts.contains(&request.target.hostname))
        .map(|request| {
            serde_json::json!({
                "id": request.id,
                "status": response_status_label(&request.status),
                "action": response_action_label(&request.action),
                "requested_by": request.requested_by,
            })
        })
        .collect();
    let approval_history: Vec<serde_json::Value> = response_audit
        .iter()
        .filter(|entry| {
            hosts.contains(&entry.target_hostname)
        })
        .map(|entry| serde_json::json!({
            "recorded_at": entry.timestamp,
            "status": entry.status,
            "action": entry.action,
            "approvers": entry.approvals.iter().map(|approval| approval.approver.clone()).collect::<Vec<_>>(),
        }))
        .collect();
    let synced_tickets: Vec<serde_json::Value> = ticket_syncs
        .iter()
        .filter(|sync| sync.object_kind == "incident" && sync.object_id == incident.id.to_string())
        .map(|sync| {
            serde_json::json!({
                "provider": sync.provider,
                "external_key": sync.external_key,
                "status": sync.status,
                "synced_at": sync.synced_at,
            })
        })
        .collect();

    timeline.sort_by(|a, b| {
        a["timestamp"]
            .as_str()
            .unwrap_or("")
            .cmp(b["timestamp"].as_str().unwrap_or(""))
    });

    let narrative = format!(
        "Incident '{}' tracks {} event(s) across {} agent(s) and {} host(s). Primary findings: {}. ATT&CK coverage: {}.",
        incident.title,
        related_events.len(),
        incident.agent_ids.len(),
        hosts.len(),
        reasons.into_iter().take(5).collect::<Vec<_>>().join(", "),
        incident
            .mitre_techniques
            .iter()
            .map(attack_name)
            .collect::<Vec<_>>()
            .join(", ")
    );

    serde_json::json!({
        "incident_id": incident.id,
        "narrative": narrative,
        "timeline": timeline,
        "entities": {
            "hosts": hosts.into_iter().collect::<Vec<_>>(),
            "agents": incident.agent_ids,
            "techniques": techniques,
        },
        "linked_cases": linked_cases,
        "response_actions": response_actions,
        "approval_history": approval_history,
        "ticket_syncs": synced_tickets,
        "recommendations": [
            "Validate containment status against impacted hosts and active deployment channels.",
            "Review linked cases and analyst comments for escalation or false-positive notes.",
            "Confirm response approvals and execution results before closing the incident."
        ],
        "evidence_package": {
            "incident_summary": incident.summary,
            "case_count": linked_cases.len(),
            "response_count": response_actions.len(),
            "ticket_count": synced_tickets.len(),
            "attachment_refs": linked_cases.iter().map(|case| format!("case:{}", case["id"].as_u64().unwrap_or(0))).collect::<Vec<_>>(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::AlertRecord;
    use crate::telemetry::TelemetrySample;

    fn store_test_path(name: &str) -> String {
        format!(
            "/tmp/{}_{}.json",
            name,
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        )
    }

    fn sample_event(id: u64, hostname: &str, level: &str, reasons: &[&str]) -> StoredEvent {
        StoredEvent {
            id,
            agent_id: "agent-1".to_string(),
            received_at: "2025-01-01T00:00:00Z".to_string(),
            alert: AlertRecord {
                timestamp: "2025-01-01T00:00:00Z".to_string(),
                hostname: hostname.to_string(),
                platform: "linux".to_string(),
                score: 0.9,
                confidence: 0.95,
                level: level.to_string(),
                action: "alert".to_string(),
                reasons: reasons.iter().map(|reason| reason.to_string()).collect(),
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
                    tactic: "Credential Access (TA0006)".to_string(),
                    technique_id: "T1110".to_string(),
                    technique_name: "Brute Force".to_string(),
                }],
                narrative: None,
            },
            correlated: false,
            triage: Default::default(),
        }
    }

    #[test]
    fn builtin_rules_bootstrap_and_hunt_run() {
        let path = store_test_path("wardex_enterprise_test");
        let mut store = EnterpriseStore::new(&path);
        assert!(!store.builtin_rules().is_empty());
        let hunt = store.create_or_update_hunt(
            None,
            "Credential Sweep".to_string(),
            "analyst".to_string(),
            "high".to_string(),
            1,
            0,
            None,
            None,
            SearchQuery {
                text: Some("credential".to_string()),
                hostname: None,
                level: None,
                agent_id: None,
                from_ts: None,
                to_ts: None,
                limit: Some(100),
            },
            "Credential abuse likely present on exposed hosts".to_string(),
            HuntExpectedOutcome::Confirm,
            ContentLifecycle::Canary,
            15,
            Some("identity-attacks".to_string()),
            vec!["credential-storm".to_string()],
            Some("soc-analysts".to_string()),
        );
        let run = store
            .run_hunt(
                &hunt.id,
                &[sample_event(
                    1,
                    "web-01",
                    "Critical",
                    &["credential_access"],
                )],
                None,
                None,
            )
            .expect("hunt run");
        assert_eq!(run.match_count, 1);
    }

    #[test]
    fn playbook_and_rollout_history_persist_round_trip() {
        let path = store_test_path("wardex_enterprise_history_test");
        {
            let mut store = EnterpriseStore::new(&path);
            let execution = crate::playbook::PlaybookExecution {
                execution_id: "exec-42".to_string(),
                playbook_id: "credential-storm".to_string(),
                alert_id: Some("alert-7".to_string()),
                executed_by: "analyst-1".to_string(),
                status: crate::playbook::ExecutionStatus::Succeeded,
                started_at: 1_700_000_000_000,
                finished_at: Some(1_700_000_000_450),
                step_results: vec![crate::playbook::StepResult {
                    step_id: "step-1".to_string(),
                    status: crate::playbook::ExecutionStatus::Succeeded,
                    started_at: 1_700_000_000_000,
                    finished_at: Some(1_700_000_000_450),
                    output: Some("ok".to_string()),
                    error: None,
                }],
                variables: HashMap::new(),
                error: None,
            };
            let playbook_record = store.record_playbook_execution(&execution);
            assert_eq!(playbook_record.status, "succeeded");
            assert_eq!(playbook_record.duration_ms, Some(450));

            let rollout_record = store.record_rollout_event(
                "deploy",
                "1.2.3",
                Some("linux".to_string()),
                Some("agent-7".to_string()),
                Some("canary".to_string()),
                "assigned",
                "analyst-1",
                Some("Canary rollout".to_string()),
            );
            assert_eq!(rollout_record.action, "deploy");
            assert_eq!(rollout_record.version, "1.2.3");
        }

        let store = EnterpriseStore::new(&path);
        assert_eq!(store.playbook_history().len(), 1);
        assert_eq!(store.playbook_history()[0].execution_id, "exec-42");
        assert_eq!(store.playbook_history()[0].status, "succeeded");
        assert_eq!(store.rollout_history().len(), 1);
        assert_eq!(store.rollout_history()[0].action, "deploy");
        assert_eq!(
            store.rollout_history()[0].agent_id.as_deref(),
            Some("agent-7")
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn content_rule_lifecycle_changes_record_rollout_history() {
        let path = store_test_path("wardex_enterprise_content_rollout_test");
        let mut store = EnterpriseStore::new(&path);
        let rule = store.create_or_update_native_rule(
            None,
            "Suspicious PowerShell".to_string(),
            "Detects suspicious PowerShell execution.".to_string(),
            "secops".to_string(),
            "high".to_string(),
            Some("Replay evidence is stable".to_string()),
            vec!["identity-attacks".to_string()],
            vec![MitreAttack {
                tactic: "Credential Access (TA0006)".to_string(),
                technique_id: "T1110".to_string(),
                technique_name: "Brute Force".to_string(),
            }],
            SearchQuery {
                text: Some("powershell".to_string()),
                hostname: None,
                level: None,
                agent_id: None,
                from_ts: None,
                to_ts: None,
                limit: Some(100),
            },
        );

        let promoted = store
            .promote_rule(
                &rule.metadata.id,
                ContentLifecycle::Canary,
                "analyst-1",
                "Replay corpus passed for canary rollout",
            )
            .expect("promote rule");
        assert_eq!(promoted.lifecycle, ContentLifecycle::Canary);

        let rolled_back = store
            .rollback_rule(&rule.metadata.id, "analyst-2")
            .expect("rollback rule");
        assert_eq!(rolled_back.lifecycle, ContentLifecycle::Draft);

        assert_eq!(store.rollout_history().len(), 2);
        assert_eq!(store.rollout_history()[0].action, "content-promote");
        assert_eq!(
            store.rollout_history()[0].agent_id.as_deref(),
            Some(rule.metadata.id.as_str())
        );
        assert_eq!(
            store.rollout_history()[0].rollout_group.as_deref(),
            Some("canary")
        );
        assert!(
            store.rollout_history()[0]
                .notes
                .as_deref()
                .unwrap_or_default()
                .contains("Replay corpus passed for canary rollout")
        );
        assert_eq!(store.rollout_history()[1].action, "content-rollback");
        assert_eq!(
            store.rollout_history()[1].rollout_group.as_deref(),
            Some("draft")
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn response_action_evaluate() {
        let hunt = SavedHunt {
            id: "hunt-001".into(),
            name: "Cred scan".into(),
            owner: "analyst".into(),
            enabled: true,
            severity: "high".into(),
            threshold: 5,
            suppression_window_secs: 3600,
            schedule_interval_secs: Some(300),
            schedule_cron: None,
            last_run_at: None,
            next_run_at: None,
            query: SearchQuery {
                text: None,
                hostname: None,
                level: None,
                agent_id: None,
                from_ts: None,
                to_ts: None,
                limit: None,
            },
            hypothesis: "Credential scan should find repeated auth failures".into(),
            expected_outcome: HuntExpectedOutcome::Confirm,
            created_at: now_rfc3339(),
            updated_at: now_rfc3339(),
            lifecycle: ContentLifecycle::Canary,
            canary_percentage: 20,
            pack_id: Some("identity-attacks".into()),
            recommended_workflows: vec!["credential-storm".into()],
            target_group: Some("soc-analysts".into()),
            response_actions: vec![
                HuntResponseAction::Notify {
                    channel: "ops-slack".into(),
                    min_level: "Severe".into(),
                },
                HuntResponseAction::CreateIncident {
                    severity: "Critical".into(),
                    title_template: "{hunt_name}: {match_count} hits".into(),
                },
            ],
            tags: vec!["credential".into()],
            mitre_techniques: vec!["T1110".into()],
        };

        let run = HuntRun {
            id: "run-1".into(),
            hunt_id: "hunt-001".into(),
            run_at: now_rfc3339(),
            match_count: 10,
            suppressed_count: 0,
            threshold_exceeded: true,
            severity: "high".into(),
            case_id: None,
            time_from: None,
            time_to: None,
            yield_rate: 1.0,
            matched_event_ids: vec![1, 2, 3],
            matched_agent_ids: vec!["agent-1".into()],
            sample_event_ids: vec![1, 2, 3],
            summary: "10 matches".into(),
        };

        let results = hunt.evaluate_responses(&run);
        assert_eq!(results.len(), 2);
        assert!(results[0].executed);
        assert!(results[0].detail.contains("ops-slack"));
        assert!(results[1].detail.contains("Cred scan: 10 hits"));
    }

    #[test]
    fn response_action_skipped_below_threshold() {
        let hunt = SavedHunt {
            id: "hunt-002".into(),
            name: "test".into(),
            owner: "a".into(),
            enabled: true,
            severity: "low".into(),
            threshold: 5,
            suppression_window_secs: 0,
            schedule_interval_secs: None,
            schedule_cron: None,
            last_run_at: None,
            next_run_at: None,
            query: SearchQuery {
                text: None,
                hostname: None,
                level: None,
                agent_id: None,
                from_ts: None,
                to_ts: None,
                limit: None,
            },
            hypothesis: String::new(),
            expected_outcome: HuntExpectedOutcome::Explore,
            created_at: now_rfc3339(),
            updated_at: now_rfc3339(),
            lifecycle: ContentLifecycle::Draft,
            canary_percentage: 100,
            pack_id: None,
            recommended_workflows: vec![],
            target_group: None,
            response_actions: vec![HuntResponseAction::IsolateAgent],
            tags: vec![],
            mitre_techniques: vec![],
        };

        let run = HuntRun {
            id: "run-2".into(),
            hunt_id: "hunt-002".into(),
            run_at: now_rfc3339(),
            match_count: 2,
            suppressed_count: 0,
            threshold_exceeded: false,
            severity: "low".into(),
            case_id: None,
            time_from: None,
            time_to: None,
            yield_rate: 1.0,
            matched_event_ids: vec![],
            matched_agent_ids: vec![],
            sample_event_ids: vec![],
            summary: "".into(),
        };

        let results = hunt.evaluate_responses(&run);
        assert!(results.is_empty(), "no actions should fire below threshold");
    }

    #[test]
    fn response_action_notify_respects_min_level() {
        let hunt = SavedHunt {
            id: "hunt-003".into(),
            name: "notify-gate".into(),
            owner: "a".into(),
            enabled: true,
            severity: "medium".into(),
            threshold: 1,
            suppression_window_secs: 0,
            schedule_interval_secs: None,
            schedule_cron: None,
            last_run_at: None,
            next_run_at: None,
            query: SearchQuery {
                text: None,
                hostname: None,
                level: None,
                agent_id: None,
                from_ts: None,
                to_ts: None,
                limit: None,
            },
            hypothesis: String::new(),
            expected_outcome: HuntExpectedOutcome::Explore,
            created_at: now_rfc3339(),
            updated_at: now_rfc3339(),
            lifecycle: ContentLifecycle::Test,
            canary_percentage: 100,
            pack_id: None,
            recommended_workflows: vec![],
            target_group: None,
            response_actions: vec![HuntResponseAction::Notify {
                channel: "pagerduty".into(),
                min_level: "critical".into(),
            }],
            tags: vec![],
            mitre_techniques: vec![],
        };

        let run = HuntRun {
            id: "run-3".into(),
            hunt_id: "hunt-003".into(),
            run_at: now_rfc3339(),
            match_count: 3,
            suppressed_count: 0,
            threshold_exceeded: true,
            severity: "medium".into(),
            case_id: None,
            time_from: None,
            time_to: None,
            yield_rate: 1.0,
            matched_event_ids: vec![1],
            matched_agent_ids: vec!["agent-1".into()],
            sample_event_ids: vec![1],
            summary: "".into(),
        };

        let results = hunt.evaluate_responses(&run);
        assert_eq!(results.len(), 1);
        assert!(!results[0].executed);
        assert!(results[0].detail.contains("below min_level"));
    }

    #[test]
    fn identity_provider_configs_are_normalized_and_validated() {
        let path = store_test_path("wardex_identity_provider_test");
        let mut store = EnterpriseStore::new(&path);

        let mut mappings = HashMap::new();
        mappings.insert(" Engineers ".to_string(), " ANALYST ".to_string());

        let provider = store
            .create_or_update_idp_provider(
                None,
                "OIDC".to_string(),
                " Corporate SSO ".to_string(),
                Some(" https://issuer.example.com ".to_string()),
                None,
                Some(" wardex-admin ".to_string()),
                Some(" super-secret ".to_string()),
                Some(" https://wardex.example.com/api/auth/sso/callback ".to_string()),
                None,
                true,
                mappings,
            )
            .expect("provider should be created");

        assert_eq!(provider.kind, "oidc");
        assert_eq!(provider.display_name, "Corporate SSO");
        assert_eq!(
            provider.issuer_url.as_deref(),
            Some("https://issuer.example.com")
        );
        assert_eq!(provider.client_id.as_deref(), Some("wardex-admin"));
        assert_eq!(
            provider.redirect_uri.as_deref(),
            Some("https://wardex.example.com/api/auth/sso/callback")
        );
        assert_eq!(
            provider
                .group_role_mappings
                .get("Engineers")
                .map(String::as_str),
            Some("analyst")
        );

        let summary = store
            .idp_provider_summaries()
            .into_iter()
            .find(|summary| summary.provider.id == provider.id)
            .expect("provider summary should exist");
        assert_eq!(summary.validation.status, "ready");
        assert_eq!(summary.validation.mapping_count, 1);
        assert!(summary.validation.issues.is_empty());
    }

    #[test]
    fn scim_validation_flags_risky_defaults_and_rejects_invalid_roles() {
        let path = store_test_path("wardex_scim_validation_test");
        let mut store = EnterpriseStore::new(&path);

        let err = store
            .update_scim(
                false,
                None,
                None,
                "manual".to_string(),
                "owner".to_string(),
                HashMap::new(),
            )
            .expect_err("invalid default roles should be rejected");
        assert!(err.contains("invalid role 'owner'"));

        let config = store
            .update_scim(
                true,
                Some(" https://scim.example.com ".to_string()),
                Some(" super-secret-token ".to_string()),
                "AUTOMATIC".to_string(),
                " Admin ".to_string(),
                HashMap::new(),
            )
            .expect("valid scim config should be stored");

        assert_eq!(config.base_url.as_deref(), Some("https://scim.example.com"));
        assert_eq!(config.bearer_token.as_deref(), Some("super-secret-token"));
        assert_eq!(config.provisioning_mode, "automatic");
        assert_eq!(config.default_role, "admin");

        let validation = store.scim_validation();
        assert_eq!(validation.status, "warning");
        assert_eq!(validation.mapping_count, 0);
        assert!(
            validation
                .issues
                .iter()
                .any(|issue| issue.field == "group_role_mappings" && issue.level == "warning")
        );
        assert!(
            validation
                .issues
                .iter()
                .any(|issue| issue.field == "default_role" && issue.level == "warning")
        );
    }
}
