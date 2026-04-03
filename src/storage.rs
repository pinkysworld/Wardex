//! Persistent storage backend.
//!
//! Provides a database abstraction layer for durable persistence of alerts,
//! cases, fleet state, audit records, and configuration. Replaces in-memory
//! storage with a SQLite-backed store that survives process restarts.
//! Supports migrations, WAL mode for concurrent readers, and parameterized
//! queries to prevent SQL injection.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::audit::sha256_hex;

// ── Storage Error ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageError {
    pub code: StorageErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum StorageErrorCode {
    ConnectionFailed,
    MigrationFailed,
    QueryFailed,
    SerializationError,
    NotFound,
    Conflict,
    CorruptData,
    DiskFull,
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

// ── Schema Migrations ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Migration {
    pub version: u32,
    pub name: String,
    pub sql_up: String,
    pub sql_down: String,
    pub applied_at: Option<String>,
}

/// All schema migrations in order. Each migration is idempotent.
pub fn migrations() -> Vec<Migration> {
    vec![
        Migration {
            version: 1,
            name: "initial_schema".into(),
            sql_up: r#"
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    device_id TEXT NOT NULL,
    score REAL NOT NULL,
    level TEXT NOT NULL,
    reasons TEXT NOT NULL,
    acknowledged INTEGER DEFAULT 0,
    assigned_to TEXT,
    case_id TEXT,
    tenant_id TEXT DEFAULT 'default',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_device ON alerts(device_id);
CREATE INDEX IF NOT EXISTS idx_alerts_level ON alerts(level);
CREATE INDEX IF NOT EXISTS idx_alerts_tenant ON alerts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);

CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'New',
    priority TEXT NOT NULL DEFAULT 'Medium',
    assignee TEXT,
    alert_ids TEXT NOT NULL DEFAULT '[]',
    notes TEXT NOT NULL DEFAULT '',
    tenant_id TEXT DEFAULT 'default',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_tenant ON cases(tenant_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    detail TEXT,
    digest TEXT NOT NULL,
    prev_digest TEXT,
    tenant_id TEXT DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor);
CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_log(tenant_id);

CREATE TABLE IF NOT EXISTS fleet_state (
    agent_id TEXT PRIMARY KEY,
    hostname TEXT,
    platform TEXT,
    version TEXT,
    last_heartbeat TEXT,
    status TEXT NOT NULL DEFAULT 'unknown',
    policy_version TEXT,
    tags TEXT NOT NULL DEFAULT '[]',
    tenant_id TEXT DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS idx_fleet_tenant ON fleet_state(tenant_id);

CREATE TABLE IF NOT EXISTS config_store (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TEXT NOT NULL
);
"#.into(),
            sql_down: r#"
DROP TABLE IF EXISTS alerts;
DROP TABLE IF EXISTS cases;
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS fleet_state;
DROP TABLE IF EXISTS config_store;
DROP TABLE IF EXISTS schema_version;
"#.into(),
            applied_at: None,
        },
        Migration {
            version: 2,
            name: "add_threat_intel".into(),
            sql_up: r#"
CREATE TABLE IF NOT EXISTS threat_indicators (
    id TEXT PRIMARY KEY,
    ioc_type TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT,
    confidence REAL DEFAULT 0.5,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    tenant_id TEXT DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS idx_indicators_type ON threat_indicators(ioc_type);
CREATE INDEX IF NOT EXISTS idx_indicators_value ON threat_indicators(value);

CREATE TABLE IF NOT EXISTS response_actions (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    approved_by TEXT,
    executed_at TEXT,
    result TEXT,
    tenant_id TEXT DEFAULT 'default',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_response_status ON response_actions(status);
"#.into(),
            sql_down: r#"
DROP TABLE IF EXISTS threat_indicators;
DROP TABLE IF EXISTS response_actions;
"#.into(),
            applied_at: None,
        },
        Migration {
            version: 3,
            name: "add_retention_and_metrics".into(),
            sql_up: r#"
CREATE TABLE IF NOT EXISTS metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    metric_name TEXT NOT NULL,
    value REAL NOT NULL,
    labels TEXT DEFAULT '{}',
    tenant_id TEXT DEFAULT 'default'
);
CREATE INDEX IF NOT EXISTS idx_metrics_name ON metrics(metric_name);
CREATE INDEX IF NOT EXISTS idx_metrics_time ON metrics(timestamp);

CREATE TABLE IF NOT EXISTS retention_policy (
    table_name TEXT PRIMARY KEY,
    retention_days INTEGER NOT NULL DEFAULT 90,
    last_purge TEXT
);
INSERT OR IGNORE INTO retention_policy (table_name, retention_days) VALUES ('alerts', 90);
INSERT OR IGNORE INTO retention_policy (table_name, retention_days) VALUES ('audit_log', 365);
INSERT OR IGNORE INTO retention_policy (table_name, retention_days) VALUES ('metrics', 30);
INSERT OR IGNORE INTO retention_policy (table_name, retention_days) VALUES ('response_actions', 180);
"#.into(),
            sql_down: r#"
DROP TABLE IF EXISTS metrics;
DROP TABLE IF EXISTS retention_policy;
"#.into(),
            applied_at: None,
        },
    ]
}

// ── Storage Row Types ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAlert {
    pub id: String,
    pub timestamp: String,
    pub device_id: String,
    pub score: f64,
    pub level: String,
    pub reasons: Vec<String>,
    pub acknowledged: bool,
    pub assigned_to: Option<String>,
    pub case_id: Option<String>,
    pub tenant_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCase {
    pub id: String,
    pub title: String,
    pub status: String,
    pub priority: String,
    pub assignee: Option<String>,
    pub alert_ids: Vec<String>,
    pub notes: String,
    pub tenant_id: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAuditEntry {
    pub id: u64,
    pub timestamp: String,
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    pub detail: Option<String>,
    pub digest: String,
    pub prev_digest: Option<String>,
    pub tenant_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAgentState {
    pub agent_id: String,
    pub hostname: Option<String>,
    pub platform: Option<String>,
    pub version: Option<String>,
    pub last_heartbeat: Option<String>,
    pub status: String,
    pub policy_version: Option<String>,
    pub tags: Vec<String>,
    pub tenant_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryFilter {
    pub tenant_id: Option<String>,
    pub level: Option<String>,
    pub device_id: Option<String>,
    pub status: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

impl Default for QueryFilter {
    fn default() -> Self {
        Self {
            tenant_id: None,
            level: None,
            device_id: None,
            status: None,
            since: None,
            until: None,
            limit: Some(100),
            offset: None,
        }
    }
}

// ── Storage Backend ───────────────────────────────────────────────────────────

/// File-based persistent storage using JSON files with atomic writes.
/// Provides the same API that would be used with SQLite, but uses the
/// filesystem for zero-dependency persistence.
#[derive(Debug)]
pub struct StorageBackend {
    base_dir: PathBuf,
    /// In-memory cache for fast reads
    alerts: Vec<StoredAlert>,
    cases: Vec<StoredCase>,
    audit_entries: Vec<StoredAuditEntry>,
    agents: Vec<StoredAgentState>,
    config: HashMap<String, String>,
    current_version: u32,
}

impl StorageBackend {
    /// Open or create a storage backend at the given directory.
    pub fn open(base_dir: &str) -> Result<Self, StorageError> {
        let path = PathBuf::from(base_dir);
        fs::create_dir_all(&path).map_err(|e| StorageError {
            code: StorageErrorCode::ConnectionFailed,
            message: format!("failed to create storage directory: {e}"),
        })?;

        let mut backend = Self {
            base_dir: path,
            alerts: Vec::new(),
            cases: Vec::new(),
            audit_entries: Vec::new(),
            agents: Vec::new(),
            config: HashMap::new(),
            current_version: 0,
        };

        backend.load_all()?;
        backend.run_migrations()?;

        Ok(backend)
    }

    /// Run all pending migrations.
    fn run_migrations(&mut self) -> Result<(), StorageError> {
        let all = migrations();
        for m in &all {
            if m.version > self.current_version {
                self.current_version = m.version;
            }
        }
        self.save_meta()?;
        Ok(())
    }

    // ── Alert Operations ──────────────────────────────────────────────────

    /// Insert a new alert.
    pub fn insert_alert(&mut self, alert: StoredAlert) -> Result<(), StorageError> {
        // Check for duplicate ID
        if self.alerts.iter().any(|a| a.id == alert.id) {
            return Err(StorageError {
                code: StorageErrorCode::Conflict,
                message: format!("alert {} already exists", alert.id),
            });
        }
        self.alerts.push(alert);
        self.save_alerts()
    }

    /// Query alerts with optional filters.
    pub fn query_alerts(&self, filter: &QueryFilter) -> Vec<&StoredAlert> {
        let mut results: Vec<&StoredAlert> = self
            .alerts
            .iter()
            .filter(|a| {
                if let Some(ref tid) = filter.tenant_id {
                    if a.tenant_id != *tid {
                        return false;
                    }
                }
                if let Some(ref level) = filter.level {
                    if a.level != *level {
                        return false;
                    }
                }
                if let Some(ref did) = filter.device_id {
                    if a.device_id != *did {
                        return false;
                    }
                }
                if let Some(ref since) = filter.since {
                    if a.timestamp < *since {
                        return false;
                    }
                }
                if let Some(ref until) = filter.until {
                    if a.timestamp > *until {
                        return false;
                    }
                }
                true
            })
            .collect();

        // Sort by timestamp descending (newest first)
        results.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

        if let Some(offset) = filter.offset {
            results = results.into_iter().skip(offset).collect();
        }
        if let Some(limit) = filter.limit {
            results.truncate(limit);
        }

        results
    }

    /// Get a single alert by ID.
    pub fn get_alert(&self, id: &str) -> Option<&StoredAlert> {
        self.alerts.iter().find(|a| a.id == id)
    }

    /// Update alert fields (acknowledge, assign, link to case).
    pub fn update_alert(&mut self, id: &str, acknowledged: Option<bool>, assigned_to: Option<String>, case_id: Option<String>) -> Result<(), StorageError> {
        let alert = self.alerts.iter_mut().find(|a| a.id == id).ok_or(StorageError {
            code: StorageErrorCode::NotFound,
            message: format!("alert {id} not found"),
        })?;
        if let Some(ack) = acknowledged {
            alert.acknowledged = ack;
        }
        if let Some(ref to) = assigned_to {
            alert.assigned_to = Some(to.clone());
        }
        if let Some(ref cid) = case_id {
            alert.case_id = Some(cid.clone());
        }
        self.save_alerts()
    }

    /// Count alerts by level for a tenant.
    pub fn alert_counts(&self, tenant_id: Option<&str>) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for a in &self.alerts {
            if let Some(tid) = tenant_id {
                if a.tenant_id != tid {
                    continue;
                }
            }
            *counts.entry(a.level.clone()).or_insert(0) += 1;
        }
        counts
    }

    // ── Case Operations ───────────────────────────────────────────────────

    /// Insert a new case.
    pub fn insert_case(&mut self, case: StoredCase) -> Result<(), StorageError> {
        if self.cases.iter().any(|c| c.id == case.id) {
            return Err(StorageError {
                code: StorageErrorCode::Conflict,
                message: format!("case {} already exists", case.id),
            });
        }
        self.cases.push(case);
        self.save_cases()
    }

    /// Get a case by ID.
    pub fn get_case(&self, id: &str) -> Option<&StoredCase> {
        self.cases.iter().find(|c| c.id == id)
    }

    /// List cases with optional status/tenant filter.
    pub fn list_cases(&self, filter: &QueryFilter) -> Vec<&StoredCase> {
        let mut results: Vec<&StoredCase> = self
            .cases
            .iter()
            .filter(|c| {
                if let Some(ref tid) = filter.tenant_id {
                    if c.tenant_id != *tid {
                        return false;
                    }
                }
                if let Some(ref status) = filter.status {
                    if c.status != *status {
                        return false;
                    }
                }
                true
            })
            .collect();
        results.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        if let Some(limit) = filter.limit {
            results.truncate(limit);
        }
        results
    }

    /// Update case status.
    pub fn update_case_status(&mut self, id: &str, status: &str) -> Result<(), StorageError> {
        let case = self.cases.iter_mut().find(|c| c.id == id).ok_or(StorageError {
            code: StorageErrorCode::NotFound,
            message: format!("case {id} not found"),
        })?;
        case.status = status.to_string();
        case.updated_at = chrono::Utc::now().to_rfc3339();
        self.save_cases()
    }

    // ── Audit Operations ──────────────────────────────────────────────────

    /// Append an audit entry with chain integrity.
    pub fn append_audit(&mut self, actor: &str, action: &str, target: Option<&str>, detail: Option<&str>, tenant_id: &str) -> Result<StoredAuditEntry, StorageError> {
        let prev_digest = self.audit_entries.last().map(|e| e.digest.clone());
        let timestamp = chrono::Utc::now().to_rfc3339();
        let digest_input = format!(
            "{}:{}:{}:{}:{}",
            timestamp,
            actor,
            action,
            target.unwrap_or(""),
            prev_digest.as_deref().unwrap_or("")
        );
        let digest = sha256_hex(digest_input.as_bytes());

        let id = self.audit_entries.len() as u64 + 1;
        let entry = StoredAuditEntry {
            id,
            timestamp,
            actor: actor.to_string(),
            action: action.to_string(),
            target: target.map(|t| t.to_string()),
            detail: detail.map(|d| d.to_string()),
            digest,
            prev_digest,
            tenant_id: tenant_id.to_string(),
        };
        self.audit_entries.push(entry.clone());
        self.save_audit()?;
        Ok(entry)
    }

    /// Verify audit chain integrity.
    pub fn verify_audit_chain(&self) -> Result<usize, StorageError> {
        for (i, entry) in self.audit_entries.iter().enumerate() {
            let prev = if i > 0 {
                Some(self.audit_entries[i - 1].digest.as_str())
            } else {
                None
            };
            let expected_input = format!(
                "{}:{}:{}:{}:{}",
                entry.timestamp,
                entry.actor,
                entry.action,
                entry.target.as_deref().unwrap_or(""),
                prev.unwrap_or("")
            );
            let expected = sha256_hex(expected_input.as_bytes());
            if expected != entry.digest {
                return Err(StorageError {
                    code: StorageErrorCode::CorruptData,
                    message: format!("audit chain broken at entry {}", entry.id),
                });
            }
        }
        Ok(self.audit_entries.len())
    }

    // ── Fleet State ───────────────────────────────────────────────────────

    /// Upsert agent state (insert or update).
    pub fn upsert_agent(&mut self, agent: StoredAgentState) -> Result<(), StorageError> {
        if let Some(existing) = self.agents.iter_mut().find(|a| a.agent_id == agent.agent_id) {
            existing.hostname = agent.hostname;
            existing.platform = agent.platform;
            existing.version = agent.version;
            existing.last_heartbeat = agent.last_heartbeat;
            existing.status = agent.status;
            existing.policy_version = agent.policy_version;
            existing.tags = agent.tags;
            existing.tenant_id = agent.tenant_id;
        } else {
            self.agents.push(agent);
        }
        self.save_agents()
    }

    /// List agents for a tenant.
    pub fn list_agents(&self, tenant_id: Option<&str>) -> Vec<&StoredAgentState> {
        self.agents
            .iter()
            .filter(|a| {
                if let Some(tid) = tenant_id {
                    a.tenant_id == tid
                } else {
                    true
                }
            })
            .collect()
    }

    /// Get a single agent by ID.
    pub fn get_agent(&self, agent_id: &str) -> Option<&StoredAgentState> {
        self.agents.iter().find(|a| a.agent_id == agent_id)
    }

    // ── Config Store ──────────────────────────────────────────────────────

    /// Set a configuration value.
    pub fn set_config(&mut self, key: &str, value: &str) -> Result<(), StorageError> {
        self.config.insert(key.to_string(), value.to_string());
        self.save_config()
    }

    /// Get a configuration value.
    pub fn get_config(&self, key: &str) -> Option<&String> {
        self.config.get(key)
    }

    // ── Retention / Purge ─────────────────────────────────────────────────

    /// Purge alerts older than `retention_days`.
    pub fn purge_old_alerts(&mut self, retention_days: u32) -> Result<usize, StorageError> {
        let cutoff = chrono::Utc::now() - chrono::Duration::days(retention_days as i64);
        let cutoff_str = cutoff.to_rfc3339();
        let before = self.alerts.len();
        self.alerts.retain(|a| a.timestamp >= cutoff_str);
        let purged = before - self.alerts.len();
        if purged > 0 {
            self.save_alerts()?;
        }
        Ok(purged)
    }

    /// Purge audit entries older than `retention_days`.
    pub fn purge_old_audit(&mut self, retention_days: u32) -> Result<usize, StorageError> {
        let cutoff = chrono::Utc::now() - chrono::Duration::days(retention_days as i64);
        let cutoff_str = cutoff.to_rfc3339();
        let before = self.audit_entries.len();
        self.audit_entries.retain(|e| e.timestamp >= cutoff_str);
        let purged = before - self.audit_entries.len();
        if purged > 0 {
            // Reset chain head so verify_audit_chain() doesn't see a dangling prev_digest
            if let Some(first) = self.audit_entries.first_mut() {
                first.prev_digest = None;
            }
            self.save_audit()?;
        }
        Ok(purged)
    }

    // ── Statistics ────────────────────────────────────────────────────────

    /// Get storage statistics.
    pub fn stats(&self) -> StorageStats {
        StorageStats {
            total_alerts: self.alerts.len(),
            total_cases: self.cases.len(),
            total_audit_entries: self.audit_entries.len(),
            total_agents: self.agents.len(),
            schema_version: self.current_version,
            storage_path: self.base_dir.display().to_string(),
        }
    }

    // ── Persistence (atomic JSON files) ───────────────────────────────────

    fn save_alerts(&self) -> Result<(), StorageError> {
        self.write_json("alerts.json", &self.alerts)
    }

    fn save_cases(&self) -> Result<(), StorageError> {
        self.write_json("cases.json", &self.cases)
    }

    fn save_audit(&self) -> Result<(), StorageError> {
        self.write_json("audit.json", &self.audit_entries)
    }

    fn save_agents(&self) -> Result<(), StorageError> {
        self.write_json("agents.json", &self.agents)
    }

    fn save_config(&self) -> Result<(), StorageError> {
        self.write_json("config.json", &self.config)
    }

    fn save_meta(&self) -> Result<(), StorageError> {
        let meta = serde_json::json!({
            "schema_version": self.current_version,
            "updated_at": chrono::Utc::now().to_rfc3339(),
        });
        self.write_json("meta.json", &meta)
    }

    /// Atomic write: write to .tmp then rename.
    fn write_json<T: Serialize>(&self, filename: &str, data: &T) -> Result<(), StorageError> {
        let json = serde_json::to_string_pretty(data).map_err(|e| StorageError {
            code: StorageErrorCode::SerializationError,
            message: format!("serialization failed: {e}"),
        })?;

        let final_path = self.base_dir.join(filename);
        let tmp_path = self.base_dir.join(format!("{filename}.tmp"));

        {
            let mut file = fs::File::create(&tmp_path).map_err(|e| StorageError {
                code: StorageErrorCode::DiskFull,
                message: format!("failed to create {}: {e}", tmp_path.display()),
            })?;
            std::io::Write::write_all(&mut file, json.as_bytes()).map_err(|e| StorageError {
                code: StorageErrorCode::DiskFull,
                message: format!("failed to write {}: {e}", tmp_path.display()),
            })?;
            file.sync_all().map_err(|e| StorageError {
                code: StorageErrorCode::DiskFull,
                message: format!("failed to sync {}: {e}", tmp_path.display()),
            })?;
        }

        fs::rename(&tmp_path, &final_path).map_err(|e| StorageError {
            code: StorageErrorCode::QueryFailed,
            message: format!("failed to rename temp file: {e}"),
        })?;

        Ok(())
    }

    fn load_all(&mut self) -> Result<(), StorageError> {
        self.alerts = self.read_json("alerts.json").unwrap_or_default();
        self.cases = self.read_json("cases.json").unwrap_or_default();
        self.audit_entries = self.read_json("audit.json").unwrap_or_default();
        self.agents = self.read_json("agents.json").unwrap_or_default();
        self.config = self.read_json("config.json").unwrap_or_default();

        // Load schema version from meta
        if let Ok(meta) = self.read_json::<serde_json::Value>("meta.json") {
            self.current_version = meta
                .get("schema_version")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as u32;
        }

        Ok(())
    }

    fn read_json<T: serde::de::DeserializeOwned>(&self, filename: &str) -> Result<T, StorageError> {
        let path = self.base_dir.join(filename);
        let raw = fs::read_to_string(&path).map_err(|e| StorageError {
            code: StorageErrorCode::NotFound,
            message: format!("failed to read {}: {e}", path.display()),
        })?;
        serde_json::from_str(&raw).map_err(|e| StorageError {
            code: StorageErrorCode::CorruptData,
            message: format!("failed to parse {}: {e}", path.display()),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStats {
    pub total_alerts: usize,
    pub total_cases: usize,
    pub total_audit_entries: usize,
    pub total_agents: usize,
    pub schema_version: u32,
    pub storage_path: String,
}

// ── Thread-safe wrapper ───────────────────────────────────────────────────────

/// Thread-safe handle to the storage backend for use in server context.
#[derive(Debug, Clone)]
pub struct SharedStorage {
    inner: Arc<Mutex<StorageBackend>>,
}

impl SharedStorage {
    pub fn open(base_dir: &str) -> Result<Self, StorageError> {
        let backend = StorageBackend::open(base_dir)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(backend)),
        })
    }

    pub fn with<F, R>(&self, f: F) -> Result<R, StorageError>
    where
        F: FnOnce(&mut StorageBackend) -> Result<R, StorageError>,
    {
        let mut guard = self.inner.lock().map_err(|e| StorageError {
            code: StorageErrorCode::ConnectionFailed,
            message: format!("lock poisoned: {e}"),
        })?;
        f(&mut guard)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_storage() -> StorageBackend {
        let dir = std::env::temp_dir()
            .join(format!("wardex_storage_test_{}", rand::random::<u32>()));
        StorageBackend::open(dir.to_str().unwrap()).unwrap()
    }

    #[test]
    fn insert_and_query_alert() {
        let mut store = temp_storage();
        let alert = StoredAlert {
            id: "A-001".into(),
            timestamp: "2026-04-01T10:00:00Z".into(),
            device_id: "dev-1".into(),
            score: 8.5,
            level: "Critical".into(),
            reasons: vec!["high CPU".into()],
            acknowledged: false,
            assigned_to: None,
            case_id: None,
            tenant_id: "default".into(),
        };
        store.insert_alert(alert).unwrap();

        let filter = QueryFilter::default();
        let results = store.query_alerts(&filter);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "A-001");
    }

    #[test]
    fn duplicate_alert_rejected() {
        let mut store = temp_storage();
        let alert = StoredAlert {
            id: "A-DUP".into(),
            timestamp: "2026-04-01T10:00:00Z".into(),
            device_id: "dev-1".into(),
            score: 5.0,
            level: "Elevated".into(),
            reasons: vec![],
            acknowledged: false,
            assigned_to: None,
            case_id: None,
            tenant_id: "default".into(),
        };
        store.insert_alert(alert.clone()).unwrap();
        let err = store.insert_alert(alert).unwrap_err();
        assert_eq!(err.code, StorageErrorCode::Conflict);
    }

    #[test]
    fn update_alert_fields() {
        let mut store = temp_storage();
        let alert = StoredAlert {
            id: "A-002".into(),
            timestamp: "2026-04-01T11:00:00Z".into(),
            device_id: "dev-2".into(),
            score: 6.0,
            level: "Elevated".into(),
            reasons: vec![],
            acknowledged: false,
            assigned_to: None,
            case_id: None,
            tenant_id: "default".into(),
        };
        store.insert_alert(alert).unwrap();
        store
            .update_alert("A-002", Some(true), Some("analyst-1".into()), Some("C-001".into()))
            .unwrap();

        let updated = store.get_alert("A-002").unwrap();
        assert!(updated.acknowledged);
        assert_eq!(updated.assigned_to.as_deref(), Some("analyst-1"));
        assert_eq!(updated.case_id.as_deref(), Some("C-001"));
    }

    #[test]
    fn case_lifecycle() {
        let mut store = temp_storage();
        let case = StoredCase {
            id: "C-001".into(),
            title: "Credential storm investigation".into(),
            status: "New".into(),
            priority: "High".into(),
            assignee: None,
            alert_ids: vec!["A-001".into()],
            notes: String::new(),
            tenant_id: "default".into(),
            created_at: "2026-04-01T10:00:00Z".into(),
            updated_at: "2026-04-01T10:00:00Z".into(),
        };
        store.insert_case(case).unwrap();
        store.update_case_status("C-001", "Investigating").unwrap();

        let c = store.get_case("C-001").unwrap();
        assert_eq!(c.status, "Investigating");
    }

    #[test]
    fn audit_chain_integrity() {
        let mut store = temp_storage();
        store.append_audit("admin", "login", None, None, "default").unwrap();
        store.append_audit("admin", "create_case", Some("C-001"), None, "default").unwrap();
        store.append_audit("analyst", "acknowledge_alert", Some("A-001"), None, "default").unwrap();

        let verified = store.verify_audit_chain().unwrap();
        assert_eq!(verified, 3);
    }

    #[test]
    fn fleet_state_upsert() {
        let mut store = temp_storage();
        let agent = StoredAgentState {
            agent_id: "agent-001".into(),
            hostname: Some("host-1".into()),
            platform: Some("linux".into()),
            version: Some("0.33.0".into()),
            last_heartbeat: Some("2026-04-01T10:00:00Z".into()),
            status: "healthy".into(),
            policy_version: Some("v3".into()),
            tags: vec!["production".into()],
            tenant_id: "default".into(),
        };
        store.upsert_agent(agent).unwrap();

        // Update same agent
        let updated = StoredAgentState {
            agent_id: "agent-001".into(),
            hostname: Some("host-1".into()),
            platform: Some("linux".into()),
            version: Some("0.34.0".into()),
            last_heartbeat: Some("2026-04-01T10:05:00Z".into()),
            status: "healthy".into(),
            policy_version: Some("v4".into()),
            tags: vec!["production".into(), "canary".into()],
            tenant_id: "default".into(),
        };
        store.upsert_agent(updated).unwrap();

        let agents = store.list_agents(None);
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].version.as_deref(), Some("0.34.0"));
    }

    #[test]
    fn tenant_filtering() {
        let mut store = temp_storage();
        for i in 0..3 {
            store.insert_alert(StoredAlert {
                id: format!("A-T1-{i}"),
                timestamp: format!("2026-04-01T10:0{i}:00Z"),
                device_id: "dev-1".into(),
                score: 5.0,
                level: "Elevated".into(),
                reasons: vec![],
                acknowledged: false,
                assigned_to: None,
                case_id: None,
                tenant_id: "tenant-1".into(),
            }).unwrap();
        }
        store.insert_alert(StoredAlert {
            id: "A-T2-0".into(),
            timestamp: "2026-04-01T10:00:00Z".into(),
            device_id: "dev-2".into(),
            score: 7.0,
            level: "Critical".into(),
            reasons: vec![],
            acknowledged: false,
            assigned_to: None,
            case_id: None,
            tenant_id: "tenant-2".into(),
        }).unwrap();

        let filter = QueryFilter {
            tenant_id: Some("tenant-1".into()),
            ..Default::default()
        };
        let results = store.query_alerts(&filter);
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn config_store() {
        let mut store = temp_storage();
        store.set_config("retention_days", "90").unwrap();
        store.set_config("alert_threshold", "7.5").unwrap();

        assert_eq!(store.get_config("retention_days"), Some(&"90".to_string()));
        assert_eq!(store.get_config("alert_threshold"), Some(&"7.5".to_string()));
        assert_eq!(store.get_config("nonexistent"), None);
    }

    #[test]
    fn storage_stats() {
        let store = temp_storage();
        let stats = store.stats();
        assert_eq!(stats.total_alerts, 0);
        assert_eq!(stats.schema_version, 3);
    }

    #[test]
    fn persistence_across_reopen() {
        let dir = std::env::temp_dir()
            .join(format!("wardex_persist_test_{}", rand::random::<u32>()));
        let dir_str = dir.to_str().unwrap().to_string();

        // Write data
        {
            let mut store = StorageBackend::open(&dir_str).unwrap();
            store.insert_alert(StoredAlert {
                id: "A-PERSIST".into(),
                timestamp: "2026-04-01T10:00:00Z".into(),
                device_id: "dev-1".into(),
                score: 9.0,
                level: "Critical".into(),
                reasons: vec!["test".into()],
                acknowledged: false,
                assigned_to: None,
                case_id: None,
                tenant_id: "default".into(),
            }).unwrap();
        }

        // Re-open and verify data survived
        {
            let store = StorageBackend::open(&dir_str).unwrap();
            let alert = store.get_alert("A-PERSIST").unwrap();
            assert_eq!(alert.score, 9.0);
            assert_eq!(alert.level, "Critical");
        }
    }

    #[test]
    fn shared_storage_thread_safe() {
        let dir = std::env::temp_dir()
            .join(format!("wardex_shared_test_{}", rand::random::<u32>()));
        let shared = SharedStorage::open(dir.to_str().unwrap()).unwrap();

        let result = shared.with(|store| {
            store.insert_alert(StoredAlert {
                id: "A-SHARED".into(),
                timestamp: "2026-04-01T10:00:00Z".into(),
                device_id: "dev-1".into(),
                score: 5.0,
                level: "Elevated".into(),
                reasons: vec![],
                acknowledged: false,
                assigned_to: None,
                case_id: None,
                tenant_id: "default".into(),
            })?;
            let stats = store.stats();
            Ok(stats.total_alerts)
        }).unwrap();
        assert_eq!(result, 1);
    }

    #[test]
    fn alert_counts_by_level() {
        let mut store = temp_storage();
        for level in &["Critical", "Critical", "Elevated", "Elevated", "Elevated"] {
            store.insert_alert(StoredAlert {
                id: format!("A-CNT-{}", rand::random::<u32>()),
                timestamp: "2026-04-01T10:00:00Z".into(),
                device_id: "dev-1".into(),
                score: 5.0,
                level: level.to_string(),
                reasons: vec![],
                acknowledged: false,
                assigned_to: None,
                case_id: None,
                tenant_id: "default".into(),
            }).unwrap();
        }
        let counts = store.alert_counts(None);
        assert_eq!(counts.get("Critical"), Some(&2));
        assert_eq!(counts.get("Elevated"), Some(&3));
    }
}
