use crate::analyst::{Case, SearchQuery};
use crate::audit::sha256_hex;
use crate::collector::AlertRecord;
use crate::event_forward::StoredEvent;
use crate::incident::Incident;
use crate::ocsf;
use crate::rbac::User;
use crate::response::{ApprovalStatus, ResponseAction, ResponseAuditEntry, ResponseRequest};
use crate::sigma::{builtin_rules, AttackMapping, RuleStatus, SigmaEngine, SigmaRule};
use crate::telemetry::MitreAttack;
use crate::threat_intel::{IoC, IoCType};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_ascii_lowercase().contains(&needle.to_ascii_lowercase())
}

fn parse_time(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc))
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
        ResponseAction::Throttle { rate_limit_kbps } => format!("Throttle to {rate_limit_kbps} kbps"),
        ResponseAction::KillProcess { pid, process_name } => format!("Kill process {process_name} (PID {pid})"),
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

fn default_pack_list() -> Vec<ContentPack> {
    vec![
        ContentPack::new("identity-attacks", "Identity Attacks", "Credential abuse, brute force, and Kerberos misuse."),
        ContentPack::new("lateral-movement", "Lateral Movement", "Remote execution, propagation, and cross-host movement."),
        ContentPack::new("cloud-audit", "Cloud Audit", "Cloud control plane and SaaS audit detections."),
        ContentPack::new("insider-risk", "Insider Risk", "Sensitive data access, exfiltration, and policy bypass."),
        ContentPack::new("ransomware", "Ransomware", "Mass encryption, backup tampering, and impact patterns."),
        ContentPack::new("admin-abuse", "Admin Abuse", "Suspicious admin tooling, persistence, and privileged misuse."),
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
    if let Some(hostname) = &query.hostname {
        if !contains_ci(&event.alert.hostname, hostname) {
            return false;
        }
    }
    if let Some(level) = &query.level {
        if !event.alert.level.eq_ignore_ascii_case(level) {
            return false;
        }
    }
    if let Some(agent_id) = &query.agent_id {
        if event.agent_id != *agent_id {
            return false;
        }
    }
    if let Some(from_ts) = &query.from_ts {
        if event.alert.timestamp < *from_ts {
            return false;
        }
    }
    if let Some(to_ts) = &query.to_ts {
        if event.alert.timestamp > *to_ts {
            return false;
        }
    }
    if let Some(text) = &query.text {
        let in_reasons = event
            .alert
            .reasons
            .iter()
            .any(|reason| contains_ci(reason, text));
        let in_host = contains_ci(&event.alert.hostname, text);
        let in_action = contains_ci(&event.alert.action, text);
        let in_mitre = event
            .alert
            .mitre
            .iter()
            .any(|attack| contains_ci(&attack.technique_id, text) || contains_ci(&attack.technique_name, text));
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
            updated_at: now_rfc3339(),
        }
    }
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
    pub last_run_at: Option<String>,
    pub next_run_at: Option<String>,
    pub query: SearchQuery,
    pub created_at: String,
    pub updated_at: String,
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
        if let Some(expected) = &self.rule_id {
            if Some(expected.as_str()) != rule_id {
                return false;
            }
        }
        if let Some(expected) = &self.hunt_id {
            if Some(expected.as_str()) != hunt_id {
                return false;
            }
        }
        if let Some(hostname) = &self.hostname {
            if !contains_ci(&event.alert.hostname, hostname) {
                return false;
            }
        }
        if let Some(agent_id) = &self.agent_id {
            if event.agent_id != *agent_id {
                return false;
            }
        }
        if let Some(severity) = &self.severity {
            if !event.alert.level.eq_ignore_ascii_case(severity) {
                return false;
            }
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
    next_counter: u64,
}

pub struct EnterpriseStore {
    snapshot: EnterpriseSnapshot,
    store_path: String,
}

impl EnterpriseStore {
    pub fn new(store_path: &str) -> Self {
        let mut store = Self {
            snapshot: EnterpriseSnapshot {
                packs: default_pack_list(),
                scim: ScimConfig::default(),
                ..EnterpriseSnapshot::default()
            },
            store_path: store_path.to_string(),
        };
        store.load();
        store.ensure_default_connectors();
        store.bootstrap_builtin_sigma();
        store.persist();
        store
    }

    fn load(&mut self) {
        let path = Path::new(&self.store_path);
        if !path.exists() {
            return;
        }
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Ok(snapshot) = serde_json::from_str::<EnterpriseSnapshot>(&content) {
                self.snapshot = snapshot;
            }
        }
    }

    fn persist(&self) {
        let path = Path::new(&self.store_path);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(&self.snapshot) {
            let _ = std::fs::write(path, json);
        }
    }

    fn next_id(&mut self, prefix: &str) -> String {
        self.snapshot.next_counter += 1;
        format!("{prefix}-{:06}", self.snapshot.next_counter)
    }

    fn ensure_default_connectors(&mut self) {
        let defaults = [
            ("asset-inventory", "asset_inventory", "Asset Inventory"),
            ("vuln-scanner", "vulnerability_scanner", "Vulnerability Scanner"),
            ("identity-directory", "identity_directory", "Identity Directory"),
            ("geoip", "geoip", "GeoIP"),
            ("whois", "whois", "WHOIS"),
            ("threat-reputation", "threat_reputation", "Threat Reputation"),
            ("aws-cloudtrail", "aws_cloudtrail", "AWS CloudTrail"),
            ("azure-activity", "azure_activity", "Azure Activity Log"),
            ("gcp-audit", "gcp_audit", "GCP Audit Logs"),
            ("okta", "okta", "Okta"),
            ("entra", "entra_id", "Microsoft Entra ID"),
            ("m365", "microsoft_365", "Microsoft 365"),
            ("gworkspace", "google_workspace", "Google Workspace"),
        ];
        for (id, kind, display) in defaults {
            if self.snapshot.connectors.iter().any(|c| c.id == id) {
                continue;
            }
            self.snapshot.connectors.push(EnrichmentConnector {
                id: id.to_string(),
                kind: kind.to_string(),
                display_name: display.to_string(),
                endpoint: None,
                auth_mode: None,
                enabled: matches!(kind, "asset_inventory" | "threat_reputation" | "geoip" | "whois"),
                status: if matches!(kind, "asset_inventory" | "threat_reputation" | "geoip" | "whois") {
                    "ready".to_string()
                } else {
                    "disabled".to_string()
                },
                timeout_secs: 10,
                last_sync_at: None,
                last_error: None,
                metadata: HashMap::new(),
            });
        }
    }

    pub fn bootstrap_builtin_sigma(&mut self) {
        let rules = builtin_rules();
        let mut changed = false;
        for rule in &rules {
            if self.snapshot.builtin_rules.iter().any(|meta| meta.id == rule.id) {
                continue;
            }
            self.snapshot
                .builtin_rules
                .push(ManagedRuleMetadata::builtin_from_sigma(rule));
            changed = true;
        }
        if self.snapshot.packs.is_empty() {
            self.snapshot.packs = default_pack_list();
            changed = true;
        }
        for pack in &mut self.snapshot.packs {
            pack.rule_ids.clear();
        }
        for meta in &self.snapshot.builtin_rules {
            for pack_id in &meta.pack_ids {
                if let Some(pack) = self.snapshot.packs.iter_mut().find(|pack| pack.id == *pack_id) {
                    if !pack.rule_ids.contains(&meta.id) {
                        pack.rule_ids.push(meta.id.clone());
                    }
                    pack.updated_at = now_rfc3339();
                }
            }
        }
        for rule in &self.snapshot.native_rules {
            for pack_id in &rule.metadata.pack_ids {
                if let Some(pack) = self.snapshot.packs.iter_mut().find(|pack| pack.id == *pack_id) {
                    if !pack.rule_ids.contains(&rule.metadata.id) {
                        pack.rule_ids.push(rule.metadata.id.clone());
                    }
                    pack.updated_at = now_rfc3339();
                }
            }
        }
        if changed {
            self.persist();
        }
    }

    pub fn effective_sigma_rules(&self) -> Vec<SigmaRule> {
        let mut rules = builtin_rules();
        for rule in &mut rules {
            if let Some(meta) = self.snapshot.builtin_rules.iter().find(|meta| meta.id == rule.id) {
                rule.enabled = meta.enabled
                    && matches!(
                        meta.lifecycle,
                        ContentLifecycle::Active | ContentLifecycle::Canary | ContentLifecycle::Test
                    );
                rule.status = match meta.lifecycle {
                    ContentLifecycle::Draft => RuleStatus::Experimental,
                    ContentLifecycle::Test => RuleStatus::Test,
                    ContentLifecycle::Canary | ContentLifecycle::Active => RuleStatus::Stable,
                    ContentLifecycle::Deprecated | ContentLifecycle::RolledBack => RuleStatus::Deprecated,
                };
            }
        }
        rules
    }

    pub fn builtin_rules(&self) -> &[ManagedRuleMetadata] {
        &self.snapshot.builtin_rules
    }

    pub fn native_rules(&self) -> &[NativeContentRule] {
        &self.snapshot.native_rules
    }

    pub fn packs(&self) -> &[ContentPack] {
        &self.snapshot.packs
    }

    pub fn hunts(&self) -> &[SavedHunt] {
        &self.snapshot.hunts
    }

    pub fn hunt_runs(&self, hunt_id: &str) -> Vec<&HuntRun> {
        self.snapshot
            .hunt_runs
            .iter()
            .filter(|run| run.hunt_id == hunt_id)
            .collect()
    }

    pub fn suppressions(&self) -> &[AlertSuppression] {
        &self.snapshot.suppressions
    }

    pub fn connectors(&self) -> &[EnrichmentConnector] {
        &self.snapshot.connectors
    }

    pub fn ticket_syncs(&self) -> &[TicketSyncRecord] {
        &self.snapshot.ticket_syncs
    }

    pub fn idp_providers(&self) -> &[IdentityProviderConfig] {
        &self.snapshot.idp_providers
    }

    pub fn scim(&self) -> &ScimConfig {
        &self.snapshot.scim
    }

    pub fn change_control(&self) -> &[ChangeControlEntry] {
        &self.snapshot.change_control
    }

    pub fn metrics(&self) -> &OperationalMetrics {
        &self.snapshot.metrics
    }

    pub fn record_change(
        &mut self,
        category: &str,
        target: &str,
        summary: &str,
        requested_by: &str,
        reference_id: Option<String>,
        payload: Option<&str>,
    ) -> ChangeControlEntry {
        let entry = ChangeControlEntry {
            id: self.next_id("chg"),
            category: category.to_string(),
            target: target.to_string(),
            summary: summary.to_string(),
            requested_by: requested_by.to_string(),
            status: "approved".to_string(),
            created_at: now_rfc3339(),
            executed_at: Some(now_rfc3339()),
            payload_hash: payload.map(|value| sha256_hex(value.as_bytes())),
            reference_id,
        };
        self.snapshot.change_control.push(entry.clone());
        self.persist();
        entry
    }

    pub fn record_search_metrics(&mut self, latency_ms: u64) {
        self.snapshot.metrics.search_queries_total += 1;
        self.snapshot.metrics.last_search_latency_ms = latency_ms;
        self.snapshot.metrics.last_search_at = Some(now_rfc3339());
        self.persist();
    }

    pub fn record_hunt_metrics(&mut self, latency_ms: u64) {
        self.snapshot.metrics.hunt_runs_total += 1;
        self.snapshot.metrics.last_hunt_latency_ms = latency_ms;
        self.snapshot.metrics.last_hunt_at = Some(now_rfc3339());
        self.persist();
    }

    pub fn record_response_metrics(&mut self, latency_ms: u64) {
        self.snapshot.metrics.response_exec_total += 1;
        self.snapshot.metrics.last_response_latency_ms = latency_ms;
        self.snapshot.metrics.last_response_at = Some(now_rfc3339());
        self.persist();
    }

    pub fn record_ticket_sync_metrics(&mut self, latency_ms: u64) {
        self.snapshot.metrics.ticket_sync_total += 1;
        self.snapshot.metrics.last_ticket_sync_latency_ms = latency_ms;
        self.snapshot.metrics.last_ticket_sync_at = Some(now_rfc3339());
        self.persist();
    }

    pub fn active_suppression_count(&self) -> usize {
        self.snapshot
            .suppressions
            .iter()
            .filter(|suppression| suppression.is_active())
            .count()
    }

    pub fn event_is_suppressed(
        &self,
        event: &StoredEvent,
        rule_id: Option<&str>,
        hunt_id: Option<&str>,
    ) -> bool {
        self.snapshot
            .suppressions
            .iter()
            .any(|suppression| suppression.matches_event(event, rule_id, hunt_id))
    }

    pub fn apply_active_native_rules(&self, alert: &mut AlertRecord, agent_id: &str) -> usize {
        let pseudo_event = StoredEvent {
            id: 0,
            agent_id: agent_id.to_string(),
            received_at: alert.timestamp.clone(),
            alert: alert.clone(),
            correlated: false,
            triage: Default::default(),
        };
        let mut matched = 0usize;
        for rule in &self.snapshot.native_rules {
            if !rule.metadata.enabled
                || !matches!(
                    rule.metadata.lifecycle,
                    ContentLifecycle::Active | ContentLifecycle::Canary | ContentLifecycle::Test
                )
            {
                continue;
            }
            if !search_query_matches_event(&pseudo_event, &rule.query) {
                continue;
            }
            matched += 1;
            let reason = format!("native_rule:{}", rule.metadata.id);
            if !alert.reasons.iter().any(|existing| existing == &reason) {
                alert.reasons.push(reason);
            }
            for attack in &rule.metadata.attack {
                if !alert
                    .mitre
                    .iter()
                    .any(|existing| existing.technique_id == attack.technique_id)
                {
                    alert.mitre.push(attack.clone());
                }
            }
        }
        matched
    }

    pub fn create_or_update_hunt(
        &mut self,
        id: Option<&str>,
        name: String,
        owner: String,
        severity: String,
        threshold: usize,
        suppression_window_secs: u64,
        schedule_interval_secs: Option<u64>,
        query: SearchQuery,
    ) -> SavedHunt {
        if let Some(existing_id) = id {
            if let Some(index) = self.snapshot.hunts.iter().position(|hunt| hunt.id == existing_id) {
                let updated = {
                    let hunt = &mut self.snapshot.hunts[index];
                    hunt.name = name;
                    hunt.owner = owner;
                    hunt.severity = severity;
                    hunt.threshold = threshold;
                    hunt.suppression_window_secs = suppression_window_secs;
                    hunt.schedule_interval_secs = schedule_interval_secs;
                    hunt.query = query;
                    hunt.updated_at = now_rfc3339();
                    hunt.clone()
                };
                self.persist();
                return updated;
            }
        }
        let created_at = now_rfc3339();
        let hunt = SavedHunt {
            id: self.next_id("hunt"),
            name,
            owner,
            enabled: true,
            severity,
            threshold,
            suppression_window_secs,
            schedule_interval_secs,
            last_run_at: None,
            next_run_at: schedule_interval_secs.map(|secs| {
                (chrono::Utc::now() + chrono::Duration::seconds(secs as i64)).to_rfc3339()
            }),
            query,
            created_at: created_at.clone(),
            updated_at: created_at,
        };
        self.snapshot.hunts.push(hunt.clone());
        self.persist();
        hunt
    }

    pub fn due_hunt_ids(&self) -> Vec<String> {
        let now = chrono::Utc::now();
        self.snapshot
            .hunts
            .iter()
            .filter(|hunt| hunt.enabled && hunt.schedule_interval_secs.is_some())
            .filter(|hunt| {
                hunt.next_run_at
                    .as_deref()
                    .and_then(parse_time)
                    .map(|next| next <= now)
                    .unwrap_or(false)
            })
            .map(|hunt| hunt.id.clone())
            .collect()
    }

    pub fn run_hunt(&mut self, hunt_id: &str, events: &[StoredEvent]) -> Result<HuntRun, String> {
        let hunt_index = self
            .snapshot
            .hunts
            .iter()
            .position(|hunt| hunt.id == hunt_id)
            .ok_or_else(|| "hunt not found".to_string())?;

        let hunt = self.snapshot.hunts[hunt_index].clone();
        let matches: Vec<&StoredEvent> = events
            .iter()
            .filter(|event| search_query_matches_event(event, &hunt.query))
            .collect();
        let suppressed_matches: Vec<&StoredEvent> = matches
            .iter()
            .copied()
            .filter(|event| self.event_is_suppressed(event, None, Some(hunt_id)))
            .collect();
        let visible_matches: Vec<&StoredEvent> = matches
            .into_iter()
            .filter(|event| !self.event_is_suppressed(event, None, Some(hunt_id)))
            .collect();
        let run = HuntRun {
            id: self.next_id("hrun"),
            hunt_id: hunt.id.clone(),
            run_at: now_rfc3339(),
            match_count: visible_matches.len(),
            suppressed_count: suppressed_matches.len(),
            threshold_exceeded: visible_matches.len() >= hunt.threshold,
            severity: hunt.severity.clone(),
            sample_event_ids: visible_matches.iter().take(10).map(|event| event.id).collect(),
            summary: format!(
                "{} matched {} event(s){}",
                hunt.name,
                visible_matches.len(),
                if suppressed_matches.is_empty() {
                    String::new()
                } else {
                    format!(" ({} suppressed)", suppressed_matches.len())
                }
            ),
        };
        self.snapshot.hunt_runs.push(run.clone());
        if let Some(hunt_mut) = self.snapshot.hunts.get_mut(hunt_index) {
            hunt_mut.last_run_at = Some(run.run_at.clone());
            hunt_mut.next_run_at = hunt_mut.schedule_interval_secs.map(|secs| {
                (chrono::Utc::now() + chrono::Duration::seconds(secs as i64)).to_rfc3339()
            });
            hunt_mut.updated_at = now_rfc3339();
        }
        self.persist();
        Ok(run)
    }

    pub fn create_or_update_native_rule(
        &mut self,
        id: Option<&str>,
        title: String,
        description: String,
        owner: String,
        severity_mapping: String,
        rationale: Option<String>,
        pack_ids: Vec<String>,
        attack: Vec<MitreAttack>,
        query: SearchQuery,
    ) -> NativeContentRule {
        if let Some(existing_id) = id {
            if let Some(index) = self
                .snapshot
                .native_rules
                .iter()
                .position(|rule| rule.metadata.id == existing_id)
            {
                let updated = {
                    let rule = &mut self.snapshot.native_rules[index];
                    rule.metadata.title = title;
                    rule.metadata.description = description;
                    rule.metadata.owner = owner;
                    rule.metadata.pack_ids = pack_ids;
                    rule.metadata.attack = attack;
                    rule.metadata.updated_at = now_rfc3339();
                    rule.severity_mapping = severity_mapping;
                    rule.rationale = rationale;
                    rule.query = query;
                    rule.clone()
                };
                self.bootstrap_builtin_sigma();
                self.persist();
                return updated;
            }
        }
        let created_at = now_rfc3339();
        let rule = NativeContentRule {
            metadata: ManagedRuleMetadata {
                id: self.next_id("nat"),
                title,
                description,
                owner,
                kind: ContentKind::Native,
                builtin: false,
                enabled: true,
                lifecycle: ContentLifecycle::Draft,
                previous_lifecycle: None,
                version: 1,
                pack_ids,
                attack,
                false_positive_review: None,
                last_test_at: None,
                last_test_match_count: 0,
                last_promotion_at: None,
                created_at: created_at.clone(),
                updated_at: created_at,
                lifecycle_history: Vec::new(),
            },
            query,
            severity_mapping,
            rationale,
        };
        self.snapshot.native_rules.push(rule.clone());
        self.bootstrap_builtin_sigma();
        self.persist();
        rule
    }

    pub fn update_builtin_metadata(
        &mut self,
        id: &str,
        owner: Option<String>,
        enabled: Option<bool>,
        pack_ids: Option<Vec<String>>,
        false_positive_review: Option<String>,
    ) -> Result<ManagedRuleMetadata, String> {
        let rule = self
            .snapshot
            .builtin_rules
            .iter_mut()
            .find(|rule| rule.id == id)
            .ok_or_else(|| "content rule not found".to_string())?;
        if let Some(owner) = owner {
            rule.owner = owner;
        }
        if let Some(enabled) = enabled {
            rule.enabled = enabled;
        }
        if let Some(pack_ids) = pack_ids {
            rule.pack_ids = pack_ids;
        }
        if let Some(review) = false_positive_review {
            rule.false_positive_review = Some(review);
        }
        rule.updated_at = now_rfc3339();
        let updated = rule.clone();
        self.bootstrap_builtin_sigma();
        self.persist();
        Ok(updated)
    }

    pub fn find_rule_metadata(&self, id: &str) -> Option<ManagedRuleMetadata> {
        self.snapshot
            .builtin_rules
            .iter()
            .find(|rule| rule.id == id)
            .cloned()
            .or_else(|| self.snapshot.native_rules.iter().find(|rule| rule.metadata.id == id).map(|rule| rule.metadata.clone()))
    }

    pub fn promote_rule(
        &mut self,
        rule_id: &str,
        target: ContentLifecycle,
        actor: &str,
        reason: &str,
    ) -> Result<ManagedRuleMetadata, String> {
        if let Some(rule) = self.snapshot.builtin_rules.iter_mut().find(|rule| rule.id == rule_id) {
            let previous = rule.lifecycle.clone();
            rule.previous_lifecycle = Some(previous.clone());
            rule.lifecycle = target.clone();
            rule.version += 1;
            rule.last_promotion_at = Some(now_rfc3339());
            rule.updated_at = now_rfc3339();
            rule.lifecycle_history.push(LifecycleChange {
                changed_at: now_rfc3339(),
                changed_by: actor.to_string(),
                from: previous,
                to: target,
                reason: reason.to_string(),
            });
            let updated = rule.clone();
            self.persist();
            return Ok(updated);
        }
        if let Some(rule) = self.snapshot.native_rules.iter_mut().find(|rule| rule.metadata.id == rule_id) {
            let previous = rule.metadata.lifecycle.clone();
            rule.metadata.previous_lifecycle = Some(previous.clone());
            rule.metadata.lifecycle = target.clone();
            rule.metadata.version += 1;
            rule.metadata.last_promotion_at = Some(now_rfc3339());
            rule.metadata.updated_at = now_rfc3339();
            rule.metadata.lifecycle_history.push(LifecycleChange {
                changed_at: now_rfc3339(),
                changed_by: actor.to_string(),
                from: previous,
                to: target,
                reason: reason.to_string(),
            });
            let updated = rule.metadata.clone();
            self.persist();
            return Ok(updated);
        }
        Err("content rule not found".to_string())
    }

    pub fn rollback_rule(&mut self, rule_id: &str, actor: &str) -> Result<ManagedRuleMetadata, String> {
        if let Some(rule) = self.snapshot.builtin_rules.iter_mut().find(|rule| rule.id == rule_id) {
            let target = rule.previous_lifecycle.clone().unwrap_or(ContentLifecycle::Test);
            let current = rule.lifecycle.clone();
            rule.lifecycle = target.clone();
            rule.previous_lifecycle = Some(current.clone());
            rule.updated_at = now_rfc3339();
            rule.lifecycle_history.push(LifecycleChange {
                changed_at: now_rfc3339(),
                changed_by: actor.to_string(),
                from: current,
                to: target,
                reason: "rollback".to_string(),
            });
            let updated = rule.clone();
            self.persist();
            return Ok(updated);
        }
        if let Some(rule) = self.snapshot.native_rules.iter_mut().find(|rule| rule.metadata.id == rule_id) {
            let target = rule
                .metadata
                .previous_lifecycle
                .clone()
                .unwrap_or(ContentLifecycle::Draft);
            let current = rule.metadata.lifecycle.clone();
            rule.metadata.lifecycle = target.clone();
            rule.metadata.previous_lifecycle = Some(current.clone());
            rule.metadata.updated_at = now_rfc3339();
            rule.metadata.lifecycle_history.push(LifecycleChange {
                changed_at: now_rfc3339(),
                changed_by: actor.to_string(),
                from: current,
                to: target,
                reason: "rollback".to_string(),
            });
            let updated = rule.metadata.clone();
            self.persist();
            return Ok(updated);
        }
        Err("content rule not found".to_string())
    }

    pub fn test_rule(&mut self, rule_id: &str, events: &[StoredEvent]) -> Result<RuleTestResult, String> {
        let previous = self
            .snapshot
            .rule_tests
            .iter()
            .filter(|result| result.rule_id == rule_id)
            .max_by(|a, b| a.tested_at.cmp(&b.tested_at))
            .cloned();

        let (match_ids, suppressed_ids) = if self.snapshot.builtin_rules.iter().any(|rule| rule.id == rule_id) {
            let rules = builtin_rules();
            let sigma_rule = rules
                .into_iter()
                .find(|rule| rule.id == rule_id)
                .ok_or_else(|| "builtin sigma rule not found".to_string())?;
            let mut engine = SigmaEngine::new();
            engine.add_rule(sigma_rule);
            let mut match_ids = Vec::new();
            let mut suppressed_ids = Vec::new();
            for event in events {
                let ocsf_event = ocsf::alert_to_ocsf(&event.alert);
                let matched = engine.evaluate(&ocsf_event, 0);
                if matched.is_empty() {
                    continue;
                }
                if self.event_is_suppressed(event, Some(rule_id), None) {
                    suppressed_ids.push(event.id);
                } else {
                    match_ids.push(event.id);
                }
            }
            (match_ids, suppressed_ids)
        } else {
            let rule = self
                .snapshot
                .native_rules
                .iter()
                .find(|rule| rule.metadata.id == rule_id)
                .cloned()
                .ok_or_else(|| "content rule not found".to_string())?;
            let mut match_ids = Vec::new();
            let mut suppressed_ids = Vec::new();
            for event in events {
                if !search_query_matches_event(event, &rule.query) {
                    continue;
                }
                if self.event_is_suppressed(event, Some(rule_id), None) {
                    suppressed_ids.push(event.id);
                } else {
                    match_ids.push(event.id);
                }
            }
            (match_ids, suppressed_ids)
        };

        let previous_ids: HashSet<u64> = previous
            .as_ref()
            .map(|result| result.sample_event_ids.iter().copied().collect())
            .unwrap_or_default();
        let current_ids: HashSet<u64> = match_ids.iter().copied().collect();
        let new_match_ids: Vec<u64> = current_ids.difference(&previous_ids).copied().collect();
        let cleared_match_ids: Vec<u64> = previous_ids.difference(&current_ids).copied().collect();

        let result = RuleTestResult {
            id: self.next_id("rtest"),
            rule_id: rule_id.to_string(),
            tested_at: now_rfc3339(),
            match_count: match_ids.len(),
            suppressed_count: suppressed_ids.len(),
            sample_event_ids: match_ids.iter().copied().take(25).collect(),
            new_match_ids,
            cleared_match_ids,
            summary: format!(
                "Rule {} matched {} event(s){}",
                rule_id,
                match_ids.len(),
                if suppressed_ids.is_empty() {
                    String::new()
                } else {
                    format!(" ({} suppressed)", suppressed_ids.len())
                }
            ),
        };
        self.snapshot.rule_tests.push(result.clone());
        if let Some(rule) = self.snapshot.builtin_rules.iter_mut().find(|rule| rule.id == rule_id) {
            rule.last_test_at = Some(result.tested_at.clone());
            rule.last_test_match_count = result.match_count;
        }
        if let Some(rule) = self.snapshot.native_rules.iter_mut().find(|rule| rule.metadata.id == rule_id) {
            rule.metadata.last_test_at = Some(result.tested_at.clone());
            rule.metadata.last_test_match_count = result.match_count;
        }
        self.persist();
        Ok(result)
    }

    pub fn create_or_update_pack(
        &mut self,
        id: Option<&str>,
        name: String,
        description: String,
        enabled: bool,
        rule_ids: Vec<String>,
    ) -> ContentPack {
        if let Some(id) = id {
            if let Some(index) = self.snapshot.packs.iter().position(|pack| pack.id == id) {
                let pack_id = self.snapshot.packs[index].id.clone();
                let updated = {
                    let pack = &mut self.snapshot.packs[index];
                    pack.name = name;
                    pack.description = description;
                    pack.enabled = enabled;
                    pack.rule_ids = rule_ids.clone();
                    pack.updated_at = now_rfc3339();
                    pack.clone()
                };
                for rule in &mut self.snapshot.builtin_rules {
                    if rule_ids.contains(&rule.id) && !rule.pack_ids.contains(&pack_id) {
                        rule.pack_ids.push(pack_id.clone());
                    }
                }
                for rule in &mut self.snapshot.native_rules {
                    if rule_ids.contains(&rule.metadata.id) && !rule.metadata.pack_ids.contains(&pack_id) {
                        rule.metadata.pack_ids.push(pack_id.clone());
                    }
                }
                self.persist();
                return updated;
            }
        }
        let pack = ContentPack {
            id: id.unwrap_or(&self.next_id("pack")).to_string(),
            name,
            description,
            use_case: "custom".to_string(),
            enabled,
            rule_ids,
            updated_at: now_rfc3339(),
        };
        self.snapshot.packs.push(pack.clone());
        self.persist();
        pack
    }

    pub fn create_or_update_suppression(
        &mut self,
        id: Option<&str>,
        name: String,
        rule_id: Option<String>,
        hunt_id: Option<String>,
        hostname: Option<String>,
        agent_id: Option<String>,
        severity: Option<String>,
        text: Option<String>,
        expires_at: Option<String>,
        justification: String,
        actor: String,
        active: bool,
    ) -> AlertSuppression {
        if let Some(existing_id) = id {
            if let Some(index) = self
                .snapshot
                .suppressions
                .iter()
                .position(|suppression| suppression.id == existing_id)
            {
                let updated = {
                    let suppression = &mut self.snapshot.suppressions[index];
                    suppression.name = name;
                    suppression.rule_id = rule_id;
                    suppression.hunt_id = hunt_id;
                    suppression.hostname = hostname;
                    suppression.agent_id = agent_id;
                    suppression.severity = severity;
                    suppression.text = text;
                    suppression.expires_at = expires_at;
                    suppression.justification = justification.clone();
                    suppression.active = active;
                    suppression.audit.push(AlertSuppressionAuditEntry {
                        timestamp: now_rfc3339(),
                        actor,
                        action: if active { "updated" } else { "disabled" }.to_string(),
                        reason: justification,
                    });
                    suppression.clone()
                };
                self.persist();
                return updated;
            }
        }
        let suppression = AlertSuppression {
            id: self.next_id("supp"),
            name,
            rule_id,
            hunt_id,
            hostname,
            agent_id,
            severity,
            text,
            expires_at,
            justification: justification.clone(),
            created_by: actor.clone(),
            created_at: now_rfc3339(),
            active,
            audit: vec![AlertSuppressionAuditEntry {
                timestamp: now_rfc3339(),
                actor,
                action: "created".to_string(),
                reason: justification,
            }],
        };
        self.snapshot.suppressions.push(suppression.clone());
        self.persist();
        suppression
    }

    pub fn create_or_update_connector(
        &mut self,
        id: Option<&str>,
        kind: String,
        display_name: String,
        endpoint: Option<String>,
        auth_mode: Option<String>,
        enabled: bool,
        timeout_secs: u64,
        metadata: HashMap<String, String>,
    ) -> EnrichmentConnector {
        if let Some(id) = id {
            if let Some(index) = self.snapshot.connectors.iter().position(|connector| connector.id == id) {
                let updated = {
                    let connector = &mut self.snapshot.connectors[index];
                    connector.kind = kind;
                    connector.display_name = display_name;
                    connector.endpoint = endpoint;
                    connector.auth_mode = auth_mode;
                    connector.enabled = enabled;
                    connector.timeout_secs = timeout_secs;
                    connector.metadata = metadata;
                    connector.status = if enabled { "ready".to_string() } else { "disabled".to_string() };
                    connector.last_error = None;
                    connector.clone()
                };
                self.persist();
                return updated;
            }
        }
        let connector = EnrichmentConnector {
            id: self.next_id("conn"),
            kind,
            display_name,
            endpoint,
            auth_mode,
            enabled,
            status: if enabled { "ready".to_string() } else { "disabled".to_string() },
            timeout_secs,
            last_sync_at: None,
            last_error: None,
            metadata,
        };
        self.snapshot.connectors.push(connector.clone());
        self.persist();
        connector
    }

    pub fn sync_ticket(
        &mut self,
        provider: String,
        object_kind: String,
        object_id: String,
        queue_or_project: Option<String>,
        summary: String,
        synced_by: String,
    ) -> TicketSyncRecord {
        if let Some(index) = self
            .snapshot
            .ticket_syncs
            .iter()
            .position(|sync| sync.provider == provider && sync.object_kind == object_kind && sync.object_id == object_id)
        {
            let updated = {
                let existing = &mut self.snapshot.ticket_syncs[index];
                existing.sync_count += 1;
                existing.synced_at = now_rfc3339();
                existing.summary = summary;
                existing.status = "updated".to_string();
                existing.clone()
            };
            self.persist();
            return updated;
        }
        let external_key = format!(
            "{}-{}-{}",
            provider.to_ascii_uppercase(),
            object_kind.to_ascii_uppercase(),
            object_id
        );
        let record = TicketSyncRecord {
            id: self.next_id("ticket"),
            provider,
            object_kind,
            object_id,
            status: "created".to_string(),
            external_key,
            queue_or_project,
            summary,
            synced_by,
            synced_at: now_rfc3339(),
            sync_count: 1,
        };
        self.snapshot.ticket_syncs.push(record.clone());
        self.persist();
        record
    }

    pub fn create_or_update_idp_provider(
        &mut self,
        id: Option<&str>,
        kind: String,
        display_name: String,
        issuer_url: Option<String>,
        sso_url: Option<String>,
        client_id: Option<String>,
        entity_id: Option<String>,
        enabled: bool,
        group_role_mappings: HashMap<String, String>,
    ) -> IdentityProviderConfig {
        if let Some(id) = id {
            if let Some(index) = self.snapshot.idp_providers.iter().position(|provider| provider.id == id) {
                let updated = {
                    let provider = &mut self.snapshot.idp_providers[index];
                    provider.kind = kind;
                    provider.display_name = display_name;
                    provider.issuer_url = issuer_url;
                    provider.sso_url = sso_url;
                    provider.client_id = client_id;
                    provider.entity_id = entity_id;
                    provider.enabled = enabled;
                    provider.group_role_mappings = group_role_mappings;
                    provider.status = if enabled { "configured".to_string() } else { "disabled".to_string() };
                    provider.updated_at = now_rfc3339();
                    provider.clone()
                };
                self.persist();
                return updated;
            }
        }
        let provider = IdentityProviderConfig {
            id: self.next_id("idp"),
            kind,
            display_name,
            issuer_url,
            sso_url,
            client_id,
            entity_id,
            enabled,
            status: if enabled { "configured".to_string() } else { "disabled".to_string() },
            group_role_mappings,
            updated_at: now_rfc3339(),
        };
        self.snapshot.idp_providers.push(provider.clone());
        self.persist();
        provider
    }

    pub fn update_scim(
        &mut self,
        enabled: bool,
        base_url: Option<String>,
        bearer_token: Option<String>,
        provisioning_mode: String,
        default_role: String,
        group_role_mappings: HashMap<String, String>,
    ) -> ScimConfig {
        self.snapshot.scim.enabled = enabled;
        self.snapshot.scim.base_url = base_url;
        self.snapshot.scim.bearer_token = bearer_token;
        self.snapshot.scim.provisioning_mode = provisioning_mode;
        self.snapshot.scim.default_role = default_role;
        self.snapshot.scim.group_role_mappings = group_role_mappings;
        self.snapshot.scim.status = if enabled {
            "configured".to_string()
        } else {
            "disabled".to_string()
        };
        self.snapshot.scim.updated_at = Some(now_rfc3339());
        self.persist();
        self.snapshot.scim.clone()
    }
}

pub fn build_content_rules_view(store: &EnterpriseStore) -> Vec<serde_json::Value> {
    let mut items = Vec::new();
    for rule in store.builtin_rules() {
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
        }));
    }
    for rule in store.native_rules() {
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

pub fn build_mitre_coverage(
    store: &EnterpriseStore,
    incidents: &[Incident],
) -> serde_json::Value {
    let mut technique_map: HashMap<String, serde_json::Value> = HashMap::new();
    for rule in store.builtin_rules() {
        for attack in &rule.attack {
            let entry = technique_map.entry(attack.technique_id.clone()).or_insert_with(|| {
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
            if matches!(rule.lifecycle, ContentLifecycle::Active | ContentLifecycle::Canary | ContentLifecycle::Test)
                && rule.enabled
            {
                entry["enabled_rules"] = serde_json::json!(entry["enabled_rules"].as_u64().unwrap_or(0) + 1);
                entry["enabled"] = serde_json::json!(true);
            } else {
                entry["disabled_rules"] = serde_json::json!(entry["disabled_rules"].as_u64().unwrap_or(0) + 1);
            }
            let mut packs = entry["packs"].as_array().cloned().unwrap_or_default();
            for pack_id in &rule.pack_ids {
                if !packs.iter().any(|value| value.as_str() == Some(pack_id.as_str())) {
                    packs.push(serde_json::json!(pack_id));
                }
            }
            entry["packs"] = serde_json::Value::Array(packs);
        }
    }
    for rule in store.native_rules() {
        for attack in &rule.metadata.attack {
            let entry = technique_map.entry(attack.technique_id.clone()).or_insert_with(|| {
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
            if matches!(rule.metadata.lifecycle, ContentLifecycle::Active | ContentLifecycle::Canary | ContentLifecycle::Test)
                && rule.metadata.enabled
            {
                entry["enabled_rules"] = serde_json::json!(entry["enabled_rules"].as_u64().unwrap_or(0) + 1);
                entry["enabled"] = serde_json::json!(true);
            } else {
                entry["disabled_rules"] = serde_json::json!(entry["disabled_rules"].as_u64().unwrap_or(0) + 1);
            }
        }
    }
    for incident in incidents {
        for attack in &incident.mitre_techniques {
            let entry = technique_map.entry(attack.technique_id.clone()).or_insert_with(|| {
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
            entry["incident_count"] = serde_json::json!(entry["incident_count"].as_u64().unwrap_or(0) + 1);
        }
    }

    let mut techniques: Vec<serde_json::Value> = technique_map.into_values().collect();
    techniques.sort_by(|a, b| {
        b["incident_count"]
            .as_u64()
            .unwrap_or(0)
            .cmp(&a["incident_count"].as_u64().unwrap_or(0))
            .then_with(|| a["technique_id"].as_str().unwrap_or("").cmp(b["technique_id"].as_str().unwrap_or("")))
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
            "process" => event.alert.reasons.iter().any(|reason| contains_ci(reason, id)),
            "ip" | "domain" | "hash" => event.alert.reasons.iter().any(|reason| contains_ci(reason, id)),
            "user" | "account" => event.triage.assignee.as_deref().map(|assignee| assignee.eq_ignore_ascii_case(id)).unwrap_or(false),
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
            if last_seen.as_deref().map(|ts| ts < event.received_at.as_str()).unwrap_or(true) {
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
            "host" => case.event_ids.iter().any(|event_id| related_event_ids.contains(event_id)),
            "user" | "account" => case
                .assignee
                .as_deref()
                .map(|assignee| assignee.eq_ignore_ascii_case(id))
                .unwrap_or(false),
            _ => case
                .title
                .to_ascii_lowercase()
                .contains(&id.to_ascii_lowercase())
                || case
                    .description
                    .to_ascii_lowercase()
                    .contains(&id.to_ascii_lowercase()),
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
                "process" => response_action_label(&request.action).to_ascii_lowercase().contains(&id.to_ascii_lowercase()),
                "host" => request.target.hostname.eq_ignore_ascii_case(id),
                "user" | "account" => request.requested_by.eq_ignore_ascii_case(id)
                    || request.approvals.iter().any(|approval| approval.approver.eq_ignore_ascii_case(id)),
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
        .map(|connector| serde_json::json!({
            "source": connector.kind,
            "status": connector.status,
            "summary": format!("{} enrichment available", connector.display_name),
        }))
        .collect();

    let synced_tickets: Vec<serde_json::Value> = ticket_syncs
        .iter()
        .filter(|sync| match normalized.as_str() {
            "host" => sync.summary.to_ascii_lowercase().contains(&id.to_ascii_lowercase()),
            "user" | "account" => sync.synced_by.eq_ignore_ascii_case(id),
            _ => sync.summary.to_ascii_lowercase().contains(&id.to_ascii_lowercase()),
        })
        .map(|sync| serde_json::json!({
            "provider": sync.provider,
            "external_key": sync.external_key,
            "status": sync.status,
            "synced_at": sync.synced_at,
        }))
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
            _ => event.alert.reasons.iter().any(|reason| contains_ci(reason, id)),
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
            "host" => incident.summary.to_ascii_lowercase().contains(&id.to_ascii_lowercase()),
            "user" | "account" => incident
                .assignee
                .as_deref()
                .map(|assignee| assignee.eq_ignore_ascii_case(id))
                .unwrap_or(false),
            _ => incident.summary.to_ascii_lowercase().contains(&id.to_ascii_lowercase()),
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
            _ => case.title.to_ascii_lowercase().contains(&id.to_ascii_lowercase()),
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
            _ => audit.action.to_ascii_lowercase().contains(&id.to_ascii_lowercase()),
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
            _ => sync.summary.to_ascii_lowercase().contains(&id.to_ascii_lowercase()),
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

    items.sort_by(|a, b| b["timestamp"].as_str().unwrap_or("").cmp(a["timestamp"].as_str().unwrap_or("")));
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
        .map(|case| serde_json::json!({
            "id": case.id,
            "title": case.title,
            "status": format!("{:?}", case.status),
            "assignee": case.assignee,
        }))
        .collect();
    let response_actions: Vec<serde_json::Value> = response_requests
        .iter()
        .filter(|request| {
            hosts.contains(&request.target.hostname)
        })
        .map(|request| serde_json::json!({
            "id": request.id,
            "status": response_status_label(&request.status),
            "action": response_action_label(&request.action),
            "requested_by": request.requested_by,
        }))
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
        .map(|sync| serde_json::json!({
            "provider": sync.provider,
            "external_key": sync.external_key,
            "status": sync.status,
            "synced_at": sync.synced_at,
        }))
        .collect();

    timeline.sort_by(|a, b| a["timestamp"].as_str().unwrap_or("").cmp(b["timestamp"].as_str().unwrap_or("")));

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
            },
            correlated: false,
            triage: Default::default(),
        }
    }

    #[test]
    fn builtin_rules_bootstrap_and_hunt_run() {
        let path = format!("/tmp/wardex_enterprise_test_{}.json", chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default());
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
            SearchQuery {
                text: Some("credential".to_string()),
                hostname: None,
                level: None,
                agent_id: None,
                from_ts: None,
                to_ts: None,
                limit: Some(100),
            },
        );
        let run = store
            .run_hunt(&hunt.id, &[sample_event(1, "web-01", "Critical", &["credential_access"])])
            .expect("hunt run");
        assert_eq!(run.match_count, 1);
    }
}
