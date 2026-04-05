//! Persistent storage backend.
//!
//! Provides a database abstraction layer for durable persistence of alerts,
//! cases, fleet state, audit records, and configuration. Uses a SQLite-backed
//! store that survives process restarts.
//! Supports migrations, WAL mode for concurrent readers, and parameterized
//! queries to prevent SQL injection.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection};

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

/// SQLite-backed persistent storage with WAL mode for concurrent reads.
/// Provides the same API as the previous JSON file-based implementation
/// but with proper ACID guarantees and indexed queries.
pub struct StorageBackend {
    conn: Connection,
    base_dir: PathBuf,
    current_version: u32,
}

impl std::fmt::Debug for StorageBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageBackend")
            .field("base_dir", &self.base_dir)
            .field("current_version", &self.current_version)
            .finish()
    }
}

impl StorageBackend {
    /// Open or create a storage backend at the given directory.
    pub fn open(base_dir: &str) -> Result<Self, StorageError> {
        let path = PathBuf::from(base_dir);
        fs::create_dir_all(&path).map_err(|e| StorageError {
            code: StorageErrorCode::ConnectionFailed,
            message: format!("failed to create storage directory: {e}"),
        })?;

        let db_path = path.join("wardex.db");
        let conn = Connection::open(&db_path).map_err(|e| StorageError {
            code: StorageErrorCode::ConnectionFailed,
            message: format!("failed to open SQLite database: {e}"),
        })?;

        // Enable WAL mode for concurrent readers
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;")
            .map_err(|e| StorageError {
                code: StorageErrorCode::ConnectionFailed,
                message: format!("failed to set PRAGMA: {e}"),
            })?;

        let mut backend = Self {
            conn,
            base_dir: path,
            current_version: 0,
        };

        backend.load_current_version();
        backend.run_migrations()?;

        Ok(backend)
    }

    fn load_current_version(&mut self) {
        // Attempt to load current schema version
        let version: u32 = self.conn
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);
        self.current_version = version;
    }

    /// Expose the underlying connection for ad-hoc queries (e.g. retention policy lookups).
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Return the current schema version number.
    pub fn schema_version(&self) -> u32 {
        self.current_version
    }

    /// Return migration history as JSON-serializable records.
    pub fn schema_info(&self) -> Vec<Migration> {
        let all = migrations();
        let mut result = Vec::new();
        let mut stmt = self.conn
            .prepare("SELECT version, name, applied_at FROM schema_version ORDER BY version")
            .ok();
        if let Some(ref mut s) = stmt {
            let rows = s.query_map([], |row| {
                Ok((row.get::<_, u32>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?))
            });
            if let Ok(rows) = rows {
                for row in rows.flatten() {
                    result.push(Migration {
                        version: row.0,
                        name: row.1,
                        sql_up: String::new(),
                        sql_down: String::new(),
                        applied_at: Some(row.2),
                    });
                }
            }
        }
        // Add unapplied migrations
        let applied_max = result.last().map(|m| m.version).unwrap_or(0);
        for m in &all {
            if m.version > applied_max {
                result.push(Migration {
                    version: m.version,
                    name: m.name.clone(),
                    sql_up: String::new(),
                    sql_down: String::new(),
                    applied_at: None,
                });
            }
        }
        result
    }

    /// Run all pending migrations.
    fn run_migrations(&mut self) -> Result<(), StorageError> {
        let all = migrations();
        for m in &all {
            if m.version > self.current_version {
                self.conn.execute_batch(&m.sql_up).map_err(|e| StorageError {
                    code: StorageErrorCode::MigrationFailed,
                    message: format!("migration v{} '{}' failed: {e}", m.version, m.name),
                })?;
                let now = chrono::Utc::now().to_rfc3339();
                self.conn.execute(
                    "INSERT OR REPLACE INTO schema_version (version, name, applied_at) VALUES (?1, ?2, ?3)",
                    params![m.version, m.name, now],
                ).map_err(|e| StorageError {
                    code: StorageErrorCode::MigrationFailed,
                    message: format!("failed to record migration v{}: {e}", m.version),
                })?;
                self.current_version = m.version;
            }
        }
        Ok(())
    }

    /// Rollback the most recent migration, executing its `sql_down`.
    /// Returns the version that was rolled back, or None if already at v0.
    pub fn rollback_migration(&mut self) -> Result<Option<u32>, StorageError> {
        if self.current_version == 0 {
            return Ok(None);
        }
        let all = migrations();
        let target = all.iter().find(|m| m.version == self.current_version);
        let Some(m) = target else {
            return Err(StorageError {
                code: StorageErrorCode::MigrationFailed,
                message: format!("no migration found for version {}", self.current_version),
            });
        };
        let rolled_back = m.version;
        self.conn.execute_batch(&m.sql_down).map_err(|e| StorageError {
            code: StorageErrorCode::MigrationFailed,
            message: format!("rollback v{} '{}' failed: {e}", m.version, m.name),
        })?;
        self.conn.execute(
            "DELETE FROM schema_version WHERE version = ?1",
            params![m.version],
        ).map_err(|e| StorageError {
            code: StorageErrorCode::MigrationFailed,
            message: format!("failed to remove migration record v{}: {e}", m.version),
        })?;
        self.current_version = m.version - 1;
        Ok(Some(rolled_back))
    }

    // ── Alert Operations ──────────────────────────────────────────────────

    /// Insert a new alert.
    pub fn insert_alert(&mut self, alert: StoredAlert) -> Result<(), StorageError> {
        let reasons_json = serde_json::to_string(&alert.reasons).unwrap_or_default();
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO alerts (id, timestamp, device_id, score, level, reasons, acknowledged, assigned_to, case_id, tenant_id, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                alert.id, alert.timestamp, alert.device_id, alert.score,
                alert.level, reasons_json, alert.acknowledged as i32,
                alert.assigned_to, alert.case_id, alert.tenant_id, now
            ],
        ).map(|_| ()).map_err(|e| {
            if let rusqlite::Error::SqliteFailure(ref err, _) = e
                && (err.extended_code == 1555 || err.extended_code == 2067) {
                    return StorageError {
                        code: StorageErrorCode::Conflict,
                        message: format!("alert {} already exists", alert.id),
                    };
                }
            StorageError {
                code: StorageErrorCode::QueryFailed,
                message: format!("insert alert failed: {e}"),
            }
        })
    }

    /// Query alerts with optional filters.
    pub fn query_alerts(&self, filter: &QueryFilter) -> Vec<StoredAlert> {
        let mut sql = String::from("SELECT id, timestamp, device_id, score, level, reasons, acknowledged, assigned_to, case_id, tenant_id FROM alerts WHERE 1=1");
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        let mut idx = 1;

        if let Some(ref tid) = filter.tenant_id {
            sql.push_str(&format!(" AND tenant_id = ?{idx}"));
            param_values.push(Box::new(tid.clone()));
            idx += 1;
        }
        if let Some(ref level) = filter.level {
            sql.push_str(&format!(" AND level = ?{idx}"));
            param_values.push(Box::new(level.clone()));
            idx += 1;
        }
        if let Some(ref did) = filter.device_id {
            sql.push_str(&format!(" AND device_id = ?{idx}"));
            param_values.push(Box::new(did.clone()));
            idx += 1;
        }
        if let Some(ref since) = filter.since {
            sql.push_str(&format!(" AND timestamp >= ?{idx}"));
            param_values.push(Box::new(since.clone()));
            idx += 1;
        }
        if let Some(ref until) = filter.until {
            sql.push_str(&format!(" AND timestamp <= ?{idx}"));
            param_values.push(Box::new(until.clone()));
            idx += 1;
        }

        sql.push_str(" ORDER BY timestamp DESC");

        if let Some(limit) = filter.limit {
            sql.push_str(&format!(" LIMIT {limit}"));
        }
        if let Some(offset) = filter.offset {
            sql.push_str(&format!(" OFFSET {offset}"));
        }

        let _ = idx; // suppress unused warning

        let params_ref: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|p| p.as_ref()).collect();

        let mut stmt = match self.conn.prepare(&sql) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map(params_ref.as_slice(), |row| {
            let reasons_str: String = row.get(5)?;
            let reasons: Vec<String> = serde_json::from_str(&reasons_str).unwrap_or_default();
            let ack: i32 = row.get(6)?;
            Ok(StoredAlert {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                device_id: row.get(2)?,
                score: row.get(3)?,
                level: row.get(4)?,
                reasons,
                acknowledged: ack != 0,
                assigned_to: row.get(7)?,
                case_id: row.get(8)?,
                tenant_id: row.get(9)?,
            })
        });

        match rows {
            Ok(mapped) => mapped.filter_map(|r| r.ok()).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Get a single alert by ID.
    pub fn get_alert(&self, id: &str) -> Option<StoredAlert> {
        self.conn.query_row(
            "SELECT id, timestamp, device_id, score, level, reasons, acknowledged, assigned_to, case_id, tenant_id FROM alerts WHERE id = ?1",
            params![id],
            |row| {
                let reasons_str: String = row.get(5)?;
                let reasons: Vec<String> = serde_json::from_str(&reasons_str).unwrap_or_default();
                let ack: i32 = row.get(6)?;
                Ok(StoredAlert {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    device_id: row.get(2)?,
                    score: row.get(3)?,
                    level: row.get(4)?,
                    reasons,
                    acknowledged: ack != 0,
                    assigned_to: row.get(7)?,
                    case_id: row.get(8)?,
                    tenant_id: row.get(9)?,
                })
            },
        ).ok()
    }

    /// Update alert fields (acknowledge, assign, link to case).
    pub fn update_alert(&mut self, id: &str, acknowledged: Option<bool>, assigned_to: Option<String>, case_id: Option<String>) -> Result<(), StorageError> {
        // Verify the alert exists
        if self.get_alert(id).is_none() {
            return Err(StorageError {
                code: StorageErrorCode::NotFound,
                message: format!("alert {id} not found"),
            });
        }
        if let Some(ack) = acknowledged {
            self.conn.execute("UPDATE alerts SET acknowledged = ?1 WHERE id = ?2", params![ack as i32, id])
                .map_err(|e| StorageError { code: StorageErrorCode::QueryFailed, message: format!("update failed: {e}") })?;
        }
        if let Some(ref to) = assigned_to {
            self.conn.execute("UPDATE alerts SET assigned_to = ?1 WHERE id = ?2", params![to, id])
                .map_err(|e| StorageError { code: StorageErrorCode::QueryFailed, message: format!("update failed: {e}") })?;
        }
        if let Some(ref cid) = case_id {
            self.conn.execute("UPDATE alerts SET case_id = ?1 WHERE id = ?2", params![cid, id])
                .map_err(|e| StorageError { code: StorageErrorCode::QueryFailed, message: format!("update failed: {e}") })?;
        }
        Ok(())
    }

    /// Count alerts by level for a tenant.
    pub fn alert_counts(&self, tenant_id: Option<&str>) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        let tid_owned = tenant_id.map(|s| s.to_string());
        let (sql, param): (&str, Vec<Box<dyn rusqlite::types::ToSql>>) = match &tid_owned {
            Some(tid) => ("SELECT level, COUNT(*) FROM alerts WHERE tenant_id = ?1 GROUP BY level", vec![Box::new(tid.clone()) as Box<dyn rusqlite::types::ToSql>]),
            None => ("SELECT level, COUNT(*) FROM alerts GROUP BY level", vec![]),
        };
        let params_ref: Vec<&dyn rusqlite::types::ToSql> = param.iter().map(|p| p.as_ref()).collect();

        if let Ok(mut stmt) = self.conn.prepare(sql) {
            let _ = stmt.query_map(params_ref.as_slice(), |row| {
                let level: String = row.get(0)?;
                let count: usize = row.get(1)?;
                Ok((level, count))
            }).map(|rows| {
                for r in rows.flatten() {
                    counts.insert(r.0, r.1);
                }
            });
        }
        counts
    }

    // ── Case Operations ───────────────────────────────────────────────────

    /// Insert a new case.
    pub fn insert_case(&mut self, case: StoredCase) -> Result<(), StorageError> {
        let alert_ids_json = serde_json::to_string(&case.alert_ids).unwrap_or_default();
        self.conn.execute(
            "INSERT INTO cases (id, title, status, priority, assignee, alert_ids, notes, tenant_id, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                case.id, case.title, case.status, case.priority,
                case.assignee, alert_ids_json, case.notes,
                case.tenant_id, case.created_at, case.updated_at
            ],
        ).map(|_| ()).map_err(|e| {
            if let rusqlite::Error::SqliteFailure(ref err, _) = e
                && (err.extended_code == 1555 || err.extended_code == 2067) {
                    return StorageError {
                        code: StorageErrorCode::Conflict,
                        message: format!("case {} already exists", case.id),
                    };
                }
            StorageError {
                code: StorageErrorCode::QueryFailed,
                message: format!("insert case failed: {e}"),
            }
        })
    }

    /// Get a case by ID.
    pub fn get_case(&self, id: &str) -> Option<StoredCase> {
        self.conn.query_row(
            "SELECT id, title, status, priority, assignee, alert_ids, notes, tenant_id, created_at, updated_at FROM cases WHERE id = ?1",
            params![id],
            |row| {
                let alert_ids_str: String = row.get(5)?;
                let alert_ids: Vec<String> = serde_json::from_str(&alert_ids_str).unwrap_or_default();
                Ok(StoredCase {
                    id: row.get(0)?,
                    title: row.get(1)?,
                    status: row.get(2)?,
                    priority: row.get(3)?,
                    assignee: row.get(4)?,
                    alert_ids,
                    notes: row.get(6)?,
                    tenant_id: row.get(7)?,
                    created_at: row.get(8)?,
                    updated_at: row.get(9)?,
                })
            },
        ).ok()
    }

    /// List cases with optional status/tenant filter.
    pub fn list_cases(&self, filter: &QueryFilter) -> Vec<StoredCase> {
        let mut sql = String::from("SELECT id, title, status, priority, assignee, alert_ids, notes, tenant_id, created_at, updated_at FROM cases WHERE 1=1");
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        let mut idx = 1;

        if let Some(ref tid) = filter.tenant_id {
            sql.push_str(&format!(" AND tenant_id = ?{idx}"));
            param_values.push(Box::new(tid.clone()));
            idx += 1;
        }
        if let Some(ref status) = filter.status {
            sql.push_str(&format!(" AND status = ?{idx}"));
            param_values.push(Box::new(status.clone()));
            idx += 1;
        }

        sql.push_str(" ORDER BY updated_at DESC");

        if let Some(limit) = filter.limit {
            sql.push_str(&format!(" LIMIT {limit}"));
        }

        let _ = idx;

        let params_ref: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|p| p.as_ref()).collect();

        let mut stmt = match self.conn.prepare(&sql) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt.query_map(params_ref.as_slice(), |row| {
            let alert_ids_str: String = row.get(5)?;
            let alert_ids: Vec<String> = serde_json::from_str(&alert_ids_str).unwrap_or_default();
            Ok(StoredCase {
                id: row.get(0)?,
                title: row.get(1)?,
                status: row.get(2)?,
                priority: row.get(3)?,
                assignee: row.get(4)?,
                alert_ids,
                notes: row.get(6)?,
                tenant_id: row.get(7)?,
                created_at: row.get(8)?,
                updated_at: row.get(9)?,
            })
        });

        match rows {
            Ok(mapped) => mapped.filter_map(|r| r.ok()).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Update case status.
    pub fn update_case_status(&mut self, id: &str, status: &str) -> Result<(), StorageError> {
        let now = chrono::Utc::now().to_rfc3339();
        let changed = self.conn.execute(
            "UPDATE cases SET status = ?1, updated_at = ?2 WHERE id = ?3",
            params![status, now, id],
        ).map_err(|e| StorageError {
            code: StorageErrorCode::QueryFailed,
            message: format!("update case failed: {e}"),
        })?;
        if changed == 0 {
            return Err(StorageError {
                code: StorageErrorCode::NotFound,
                message: format!("case {id} not found"),
            });
        }
        Ok(())
    }

    // ── Audit Operations ──────────────────────────────────────────────────

    /// Append an audit entry with chain integrity.
    pub fn append_audit(&mut self, actor: &str, action: &str, target: Option<&str>, detail: Option<&str>, tenant_id: &str) -> Result<StoredAuditEntry, StorageError> {
        // Get the previous digest from the last entry
        let prev_digest: Option<String> = self.conn.query_row(
            "SELECT digest FROM audit_log ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get(0),
        ).ok();

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

        self.conn.execute(
            "INSERT INTO audit_log (timestamp, actor, action, target, detail, digest, prev_digest, tenant_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![timestamp, actor, action, target, detail, digest, prev_digest, tenant_id],
        ).map_err(|e| StorageError {
            code: StorageErrorCode::QueryFailed,
            message: format!("append audit failed: {e}"),
        })?;

        let id = self.conn.last_insert_rowid() as u64;

        Ok(StoredAuditEntry {
            id,
            timestamp,
            actor: actor.to_string(),
            action: action.to_string(),
            target: target.map(|t| t.to_string()),
            detail: detail.map(|d| d.to_string()),
            digest,
            prev_digest,
            tenant_id: tenant_id.to_string(),
        })
    }

    /// Verify audit chain integrity.
    pub fn verify_audit_chain(&self) -> Result<usize, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp, actor, action, target, digest, prev_digest FROM audit_log ORDER BY id ASC"
        ).map_err(|e| StorageError {
            code: StorageErrorCode::QueryFailed,
            message: format!("audit query failed: {e}"),
        })?;

        let entries: Vec<(u64, String, String, String, Option<String>, String, Option<String>)> = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)? as u64,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                ))
            })
            .map_err(|e| StorageError {
                code: StorageErrorCode::QueryFailed,
                message: format!("audit query failed: {e}"),
            })?
            .filter_map(|r| r.ok())
            .collect();

        let mut prev_expected: Option<String> = None;
        for (id, timestamp, actor, action, target, digest, _prev_digest) in &entries {
            let expected_input = format!(
                "{}:{}:{}:{}:{}",
                timestamp,
                actor,
                action,
                target.as_deref().unwrap_or(""),
                prev_expected.as_deref().unwrap_or("")
            );
            let expected = sha256_hex(expected_input.as_bytes());
            if expected != *digest {
                return Err(StorageError {
                    code: StorageErrorCode::CorruptData,
                    message: format!("audit chain broken at entry {}", id),
                });
            }
            prev_expected = Some(digest.clone());
        }

        Ok(entries.len())
    }

    // ── Fleet State ───────────────────────────────────────────────────────

    /// Upsert agent state (insert or update).
    pub fn upsert_agent(&mut self, agent: StoredAgentState) -> Result<(), StorageError> {
        let tags_json = serde_json::to_string(&agent.tags).unwrap_or_default();
        self.conn.execute(
            "INSERT OR REPLACE INTO fleet_state (agent_id, hostname, platform, version, last_heartbeat, status, policy_version, tags, tenant_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                agent.agent_id, agent.hostname, agent.platform, agent.version,
                agent.last_heartbeat, agent.status, agent.policy_version,
                tags_json, agent.tenant_id
            ],
        ).map_err(|e| StorageError {
            code: StorageErrorCode::QueryFailed,
            message: format!("upsert agent failed: {e}"),
        })?;
        Ok(())
    }

    /// List agents for a tenant.
    pub fn list_agents(&self, tenant_id: Option<&str>) -> Vec<StoredAgentState> {
        let (sql, param_values): (&str, Vec<Box<dyn rusqlite::types::ToSql>>) = if let Some(tid) = tenant_id {
            (
                "SELECT agent_id, hostname, platform, version, last_heartbeat, status, policy_version, tags, tenant_id FROM fleet_state WHERE tenant_id = ?1",
                vec![Box::new(tid.to_string()) as Box<dyn rusqlite::types::ToSql>],
            )
        } else {
            (
                "SELECT agent_id, hostname, platform, version, last_heartbeat, status, policy_version, tags, tenant_id FROM fleet_state",
                vec![],
            )
        };

        let params_ref: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|p| p.as_ref()).collect();

        let mut stmt = match self.conn.prepare(sql) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let rows = stmt.query_map(params_ref.as_slice(), |row| {
            let tags_str: String = row.get(7)?;
            let tags: Vec<String> = serde_json::from_str(&tags_str).unwrap_or_default();
            Ok(StoredAgentState {
                agent_id: row.get(0)?,
                hostname: row.get(1)?,
                platform: row.get(2)?,
                version: row.get(3)?,
                last_heartbeat: row.get(4)?,
                status: row.get(5)?,
                policy_version: row.get(6)?,
                tags,
                tenant_id: row.get(8)?,
            })
        });

        match rows {
            Ok(mapped) => mapped.filter_map(|r| r.ok()).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Get a single agent by ID.
    pub fn get_agent(&self, agent_id: &str) -> Option<StoredAgentState> {
        self.conn.query_row(
            "SELECT agent_id, hostname, platform, version, last_heartbeat, status, policy_version, tags, tenant_id FROM fleet_state WHERE agent_id = ?1",
            params![agent_id],
            |row| {
                let tags_str: String = row.get(7)?;
                let tags: Vec<String> = serde_json::from_str(&tags_str).unwrap_or_default();
                Ok(StoredAgentState {
                    agent_id: row.get(0)?,
                    hostname: row.get(1)?,
                    platform: row.get(2)?,
                    version: row.get(3)?,
                    last_heartbeat: row.get(4)?,
                    status: row.get(5)?,
                    policy_version: row.get(6)?,
                    tags,
                    tenant_id: row.get(8)?,
                })
            },
        ).ok()
    }

    // ── Config Store ──────────────────────────────────────────────────────

    /// Set a configuration value.
    pub fn set_config(&mut self, key: &str, value: &str) -> Result<(), StorageError> {
        let now = chrono::Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT OR REPLACE INTO config_store (key, value, updated_at) VALUES (?1, ?2, ?3)",
            params![key, value, now],
        ).map_err(|e| StorageError {
            code: StorageErrorCode::QueryFailed,
            message: format!("set config failed: {e}"),
        })?;
        Ok(())
    }

    /// Get a configuration value.
    pub fn get_config(&self, key: &str) -> Option<String> {
        self.conn.query_row(
            "SELECT value FROM config_store WHERE key = ?1",
            params![key],
            |row| row.get(0),
        ).ok()
    }

    // ── Retention / Purge ─────────────────────────────────────────────────

    /// Purge alerts older than `retention_days`.
    pub fn purge_old_alerts(&mut self, retention_days: u32) -> Result<usize, StorageError> {
        let cutoff = chrono::Utc::now() - chrono::Duration::days(retention_days as i64);
        let cutoff_str = cutoff.to_rfc3339();
        let purged = self.conn.execute(
            "DELETE FROM alerts WHERE timestamp < ?1",
            params![cutoff_str],
        ).map_err(|e| StorageError {
            code: StorageErrorCode::QueryFailed,
            message: format!("purge alerts failed: {e}"),
        })?;
        Ok(purged)
    }

    /// Purge audit entries older than `retention_days` and recompute chain.
    pub fn purge_old_audit(&mut self, retention_days: u32) -> Result<usize, StorageError> {
        let cutoff = chrono::Utc::now() - chrono::Duration::days(retention_days as i64);
        let cutoff_str = cutoff.to_rfc3339();
        let purged = self.conn.execute(
            "DELETE FROM audit_log WHERE timestamp < ?1",
            params![cutoff_str],
        ).map_err(|e| StorageError {
            code: StorageErrorCode::QueryFailed,
            message: format!("purge audit failed: {e}"),
        })?;

        if purged > 0 {
            // Recompute chain for remaining entries
            let mut stmt = self.conn.prepare(
                "SELECT id, timestamp, actor, action, target FROM audit_log ORDER BY id ASC"
            ).map_err(|e| StorageError {
                code: StorageErrorCode::QueryFailed,
                message: format!("audit rechain query failed: {e}"),
            })?;

            let entries: Vec<(i64, String, String, String, Option<String>)> = stmt
                .query_map([], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))
                })
                .map_err(|e| StorageError {
                    code: StorageErrorCode::QueryFailed,
                    message: format!("audit rechain failed: {e}"),
                })?
                .filter_map(|r| r.ok())
                .collect();

            let mut prev_digest: Option<String> = None;
            for (id, timestamp, actor, action, target) in &entries {
                let digest_input = format!(
                    "{}:{}:{}:{}:{}",
                    timestamp, actor, action,
                    target.as_deref().unwrap_or(""),
                    prev_digest.as_deref().unwrap_or("")
                );
                let digest = sha256_hex(digest_input.as_bytes());
                self.conn.execute(
                    "UPDATE audit_log SET digest = ?1, prev_digest = ?2 WHERE id = ?3",
                    params![digest, prev_digest, id],
                ).map_err(|e| StorageError {
                    code: StorageErrorCode::QueryFailed,
                    message: format!("audit rechain update failed: {e}"),
                })?;
                prev_digest = Some(digest);
            }
        }

        Ok(purged)
    }

    /// Purge metrics older than `retention_days`.
    pub fn purge_old_metrics(&mut self, retention_days: u32) -> Result<usize, StorageError> {
        let cutoff = chrono::Utc::now() - chrono::Duration::days(retention_days as i64);
        let cutoff_str = cutoff.to_rfc3339();
        let purged = self.conn.execute(
            "DELETE FROM metrics WHERE timestamp < ?1",
            params![cutoff_str],
        ).map_err(|e| StorageError {
            code: StorageErrorCode::QueryFailed,
            message: format!("purge metrics failed: {e}"),
        })?;
        Ok(purged)
    }

    /// Purge response actions older than `retention_days`.
    pub fn purge_old_response_actions(&mut self, retention_days: u32) -> Result<usize, StorageError> {
        let cutoff = chrono::Utc::now() - chrono::Duration::days(retention_days as i64);
        let cutoff_str = cutoff.to_rfc3339();
        let purged = self.conn.execute(
            "DELETE FROM response_actions WHERE created_at < ?1",
            params![cutoff_str],
        ).map_err(|e| StorageError {
            code: StorageErrorCode::QueryFailed,
            message: format!("purge response_actions failed: {e}"),
        })?;
        Ok(purged)
    }

    // ── Statistics ────────────────────────────────────────────────────────

    fn count_table(&self, table: &str) -> usize {
        // table names are hardcoded constants, not user input
        let sql = format!("SELECT COUNT(*) FROM {table}");
        self.conn.query_row(&sql, [], |row| row.get::<_, usize>(0)).unwrap_or(0)
    }

    /// Get storage statistics.
    pub fn stats(&self) -> StorageStats {
        StorageStats {
            total_alerts: self.count_table("alerts"),
            total_cases: self.count_table("cases"),
            total_audit_entries: self.count_table("audit_log"),
            total_agents: self.count_table("fleet_state"),
            schema_version: self.current_version,
            storage_path: self.base_dir.display().to_string(),
        }
    }

    /// GDPR right-to-forget: purge all records associated with a given entity
    /// (device ID / agent ID) across all tables. Returns total rows deleted.
    pub fn purge_entity(&mut self, entity_id: &str) -> Result<usize, StorageError> {
        let tables_columns: &[(&str, &str)] = &[
            ("alerts", "device_id"),
            ("cases", "assignee"),
            ("audit_log", "actor"),
            ("fleet_state", "agent_id"),
            ("threat_indicators", "source"),
            ("response_actions", "target"),
            ("metrics", "labels"),
        ];

        let mut total = 0usize;
        for &(table, column) in tables_columns {
            // Use LIKE for the metrics labels column (JSON text), exact match for others
            let sql = if column == "labels" {
                format!("DELETE FROM {table} WHERE {column} LIKE ?1")
            } else {
                format!("DELETE FROM {table} WHERE {column} = ?1")
            };
            let param = if column == "labels" {
                format!("%{entity_id}%")
            } else {
                entity_id.to_string()
            };
            let deleted = self.conn.execute(&sql, params![param]).unwrap_or(0);
            total += deleted;
        }

        // Record the deletion in the audit log
        self.append_audit(
            "system:gdpr",
            "entity-forget",
            Some(entity_id),
            Some(&format!("purged {total} records for GDPR right-to-forget")),
            "default",
        )?;

        Ok(total)
    }

    /// Create a full database backup using SQLite's VACUUM INTO.
    pub fn backup(&self, dest_path: &str) -> Result<(), StorageError> {
        self.conn
            .execute_batch(&format!("VACUUM INTO '{}'", dest_path.replace('\'', "''")))
            .map_err(|e| StorageError {
                code: StorageErrorCode::QueryFailed,
                message: format!("backup failed: {e}"),
            })
    }

    /// Compact the database by running VACUUM and WAL checkpoint.
    /// Returns the size in bytes before and after compaction.
    pub fn compact(&self) -> Result<(u64, u64), StorageError> {
        let db_path = self.base_dir.join("wardex.db");
        let wal_path = self.base_dir.join("wardex.db-wal");

        let size_before = std::fs::metadata(&db_path).map(|m| m.len()).unwrap_or(0)
            + std::fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0);

        // Force WAL checkpoint
        self.conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(|e| StorageError {
                code: StorageErrorCode::QueryFailed,
                message: format!("WAL checkpoint failed: {e}"),
            })?;

        // VACUUM to reclaim space
        self.conn.execute_batch("VACUUM;").map_err(|e| StorageError {
            code: StorageErrorCode::QueryFailed,
            message: format!("vacuum failed: {e}"),
        })?;

        let size_after = std::fs::metadata(&db_path).map(|m| m.len()).unwrap_or(0)
            + std::fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0);

        Ok((size_before, size_after))
    }

    /// Purge all data from all tables but keep the schema intact.
    /// Returns total rows deleted across all tables.
    pub fn reset_all_data(&mut self) -> Result<usize, StorageError> {
        let tables = [
            "alerts", "cases", "audit_log", "fleet_state",
            "threat_indicators", "response_actions", "metrics", "config_store",
        ];
        let mut total = 0usize;
        for table in &tables {
            let deleted = self.conn.execute(&format!("DELETE FROM {table}"), [])
                .unwrap_or(0);
            total += deleted;
        }
        // Re-initialize with a clean audit entry
        self.append_audit(
            "system",
            "database-reset",
            None,
            Some(&format!("purged {total} records across all tables")),
            "default",
        )?;
        Ok(total)
    }

    /// Return database file sizes for diagnostics.
    pub fn db_file_sizes(&self) -> DbFileSizes {
        let db_path = self.base_dir.join("wardex.db");
        let wal_path = self.base_dir.join("wardex.db-wal");
        let shm_path = self.base_dir.join("wardex.db-shm");
        DbFileSizes {
            db_bytes: std::fs::metadata(&db_path).map(|m| m.len()).unwrap_or(0),
            wal_bytes: std::fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0),
            shm_bytes: std::fs::metadata(&shm_path).map(|m| m.len()).unwrap_or(0),
        }
    }

    /// Clean up legacy flat-file data from var/ directory.
    /// Returns the list of files that were removed.
    pub fn cleanup_legacy_files(var_dir: &str) -> Vec<String> {
        let legacy_files = [
            "agents.json", "alerts.jsonl", "cases.json", "events.json",
            "incidents.json", "demo.audit.log", "last-run.audit.log",
            "last-run.report.json", "enterprise.json", "deployments.json",
            "test-config.toml",
        ];
        let var_path = std::path::Path::new(var_dir);
        let mut removed = Vec::new();
        for f in &legacy_files {
            let path = var_path.join(f);
            if path.exists() && std::fs::remove_file(&path).is_ok() {
                removed.push(f.to_string());
            }
            // Also remove .bak versions
            let bak_path = var_path.join(format!("{f}.bak"));
            if bak_path.exists() && std::fs::remove_file(&bak_path).is_ok() {
                removed.push(format!("{f}.bak"));
            }
        }
        removed
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbFileSizes {
    pub db_bytes: u64,
    pub wal_bytes: u64,
    pub shm_bytes: u64,
}

impl DbFileSizes {
    pub fn total(&self) -> u64 {
        self.db_bytes + self.wal_bytes + self.shm_bytes
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

        assert_eq!(store.get_config("retention_days"), Some("90".to_string()));
        assert_eq!(store.get_config("alert_threshold"), Some("7.5".to_string()));
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

    #[test]
    fn audit_chain_survives_purge() {
        let mut store = temp_storage();

        // Insert 5 audit entries with proper chaining
        store.append_audit("system", "old_action_0", None, None, "default").unwrap();
        store.append_audit("system", "old_action_1", None, None, "default").unwrap();
        store.append_audit("system", "old_action_2", None, None, "default").unwrap();
        store.append_audit("admin", "recent_1", None, None, "default").unwrap();
        store.append_audit("admin", "recent_2", None, None, "default").unwrap();

        // Verify chain before purge
        let before = store.verify_audit_chain();
        assert!(before.is_ok(), "chain should be valid before purge: {:?}", before);

        // Backdate the first 3 entries so they fall outside retention
        let old_ts = "2020-01-01T00:00:00+00:00";
        store.conn.execute(
            "UPDATE audit_log SET timestamp = ?1 WHERE id <= 3",
            params![old_ts],
        ).unwrap();

        // Purge entries older than 1 day (should remove old_ts entries)
        let purged = store.purge_old_audit(1).unwrap();
        assert!(purged >= 3, "should purge at least 3 old entries, got {}", purged);

        // Verify chain survives purge (rechain should rebuild)
        let after = store.verify_audit_chain();
        assert!(after.is_ok(), "chain should be valid after purge: {:?}", after);
    }
}
