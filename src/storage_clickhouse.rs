// ClickHouse event storage adapter for high-volume time-series telemetry.
//
// Provides a storage trait and ClickHouse implementation for event
// ingest, querying, aggregation, and retention management.
// SQLite remains the backend for config, cases, audit, and fleet state.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// ── Storage trait ───────────────────────────────────────────────

/// Backend-agnostic event store trait.
pub trait EventStore: Send + Sync {
    fn insert_events(&self, events: &[StoredEvent]) -> Result<usize, String>;
    fn query_events(&self, filter: &EventFilter) -> Result<Vec<StoredEvent>, String>;
    fn count_events(&self, filter: &EventFilter) -> Result<u64, String>;
    fn aggregate(&self, query: &AggregationQuery) -> Result<AggregationResult, String>;
    fn purge_before(&self, timestamp: &DateTime<Utc>) -> Result<u64, String>;
}

// ── Event model ─────────────────────────────────────────────────

/// A normalized event stored in the time-series backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEvent {
    pub timestamp: DateTime<Utc>,
    pub tenant_id: String,
    pub event_class: u16,
    pub severity: u8,
    pub device_id: String,
    pub user_name: String,
    pub process_name: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub raw_json: String,
}

// ── Filter / query types ────────────────────────────────────────

/// Filter criteria for event queries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventFilter {
    pub tenant_id: Option<String>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub severity_min: Option<u8>,
    pub event_class: Option<u16>,
    pub device_id: Option<String>,
    pub user_name: Option<String>,
    pub src_ip: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

fn urlencoded(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            b' ' => out.push_str("%20"),
            _ => out.push_str(&format!("%{:02X}", byte)),
        }
    }
    out
}

fn sql_string_literal(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "''"))
}

fn matches_filter(event: &StoredEvent, filter: &EventFilter) -> bool {
    if let Some(ref tenant_id) = filter.tenant_id
        && event.tenant_id != *tenant_id
    {
        return false;
    }
    if let Some(ref from) = filter.from
        && event.timestamp < *from
    {
        return false;
    }
    if let Some(ref to) = filter.to
        && event.timestamp > *to
    {
        return false;
    }
    if let Some(severity_min) = filter.severity_min
        && event.severity < severity_min
    {
        return false;
    }
    if let Some(event_class) = filter.event_class
        && event.event_class != event_class
    {
        return false;
    }
    if let Some(ref device_id) = filter.device_id
        && event.device_id != *device_id
    {
        return false;
    }
    if let Some(ref user_name) = filter.user_name
        && event.user_name != *user_name
    {
        return false;
    }
    if let Some(ref src_ip) = filter.src_ip
        && event.src_ip != *src_ip
    {
        return false;
    }
    true
}

fn apply_offset_limit(mut events: Vec<StoredEvent>, filter: &EventFilter) -> Vec<StoredEvent> {
    events.sort_by(|left, right| right.timestamp.cmp(&left.timestamp));
    let offset = filter.offset.unwrap_or(0) as usize;
    let limit = filter.limit.unwrap_or(100) as usize;
    events.into_iter().skip(offset).take(limit).collect()
}

fn grouped_value(event: &StoredEvent, field: &str) -> String {
    match field {
        "tenant_id" => event.tenant_id.clone(),
        "severity" => event.severity.to_string(),
        "device_id" => event.device_id.clone(),
        "user_name" => event.user_name.clone(),
        "event_class" => event.event_class.to_string(),
        _ => "other".into(),
    }
}

fn aggregate_events(events: &[StoredEvent], query: &AggregationQuery) -> AggregationResult {
    match &query.metric {
        AggregationMetric::Count => {
            let mut groups: HashMap<String, u64> = HashMap::new();
            for event in events {
                *groups
                    .entry(grouped_value(event, &query.group_by))
                    .or_insert(0) += 1;
            }
            let mut buckets: Vec<AggBucket> = groups
                .into_iter()
                .map(|(key, count)| AggBucket { key, count })
                .collect();
            buckets.sort_by_key(|bucket| std::cmp::Reverse(bucket.count));
            AggregationResult {
                total: events.len() as u64,
                buckets,
            }
        }
        AggregationMetric::CountDistinct(field) => {
            let mut groups: HashMap<String, HashSet<String>> = HashMap::new();
            for event in events {
                let distinct_value = grouped_value(event, field);
                groups
                    .entry(grouped_value(event, &query.group_by))
                    .or_default()
                    .insert(distinct_value);
            }
            let mut buckets: Vec<AggBucket> = groups
                .into_iter()
                .map(|(key, values)| AggBucket {
                    key,
                    count: values.len() as u64,
                })
                .collect();
            buckets.sort_by_key(|bucket| std::cmp::Reverse(bucket.count));
            let total = buckets.iter().map(|bucket| bucket.count).sum();
            AggregationResult { buckets, total }
        }
    }
}

/// Aggregation query specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationQuery {
    pub group_by: String,
    pub metric: AggregationMetric,
    pub filter: EventFilter,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AggregationMetric {
    Count,
    CountDistinct(String),
}

/// Result of an aggregation query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregationResult {
    pub buckets: Vec<AggBucket>,
    pub total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggBucket {
    pub key: String,
    pub count: u64,
}

// ── ClickHouse configuration ────────────────────────────────────

/// Configuration for the ClickHouse event storage backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClickHouseConfig {
    pub url: String,
    pub database: String,
    pub username: String,
    pub password: String,
    pub batch_size: usize,
    pub flush_interval_secs: u64,
    pub retention_days: u32,
}

impl Default for ClickHouseConfig {
    fn default() -> Self {
        Self {
            url: "http://localhost:8123".into(),
            database: "wardex".into(),
            username: "default".into(),
            password: String::new(),
            batch_size: 1000,
            flush_interval_secs: 5,
            retention_days: 90,
        }
    }
}

// ── ClickHouse storage implementation ───────────────────────────

/// ClickHouse-backed event store.
///
/// Holds config and an in-memory buffer for batch inserts.
/// In production, flushes are sent via HTTP to the ClickHouse server.
pub struct ClickHouseStorage {
    config: ClickHouseConfig,
    buffer: std::sync::Mutex<Vec<StoredEvent>>,
    total_inserted: std::sync::atomic::AtomicU64,
}

impl ClickHouseStorage {
    pub fn new(config: ClickHouseConfig) -> Self {
        Self {
            config,
            buffer: std::sync::Mutex::new(Vec::new()),
            total_inserted: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn config(&self) -> &ClickHouseConfig {
        &self.config
    }

    fn is_memory_mode(&self) -> bool {
        self.config.url.starts_with("memory://")
    }

    fn filter_clause(&self, filter: &EventFilter) -> String {
        let mut conditions = Vec::new();
        if let Some(ref tenant_id) = filter.tenant_id {
            conditions.push(format!("tenant_id = {}", sql_string_literal(tenant_id)));
        }
        if let Some(ref from) = filter.from {
            conditions.push(format!(
                "timestamp >= parseDateTime64BestEffort({})",
                sql_string_literal(&from.to_rfc3339())
            ));
        }
        if let Some(ref to) = filter.to {
            conditions.push(format!(
                "timestamp <= parseDateTime64BestEffort({})",
                sql_string_literal(&to.to_rfc3339())
            ));
        }
        if let Some(severity_min) = filter.severity_min {
            conditions.push(format!("severity >= {severity_min}"));
        }
        if let Some(event_class) = filter.event_class {
            conditions.push(format!("event_class = {event_class}"));
        }
        if let Some(ref device_id) = filter.device_id {
            conditions.push(format!("device_id = {}", sql_string_literal(device_id)));
        }
        if let Some(ref user_name) = filter.user_name {
            conditions.push(format!("user_name = {}", sql_string_literal(user_name)));
        }
        if let Some(ref src_ip) = filter.src_ip {
            conditions.push(format!("src_ip = {}", sql_string_literal(src_ip)));
        }
        if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        }
    }

    fn apply_auth_headers(&self, request: ureq::Request) -> ureq::Request {
        let request = request.set("X-ClickHouse-User", &self.config.username);
        if self.config.password.is_empty() {
            request
        } else {
            request.set("X-ClickHouse-Key", &self.config.password)
        }
    }

    fn execute_query(&self, query: &str, body: Option<&str>) -> Result<String, String> {
        if self.is_memory_mode() {
            return Ok(String::new());
        }
        let endpoint = format!(
            "{}?query={}",
            self.config.url.trim_end_matches('/'),
            urlencoded(query)
        );
        let request = self.apply_auth_headers(ureq::post(&endpoint));
        let response = match body {
            Some(payload) => request.send_string(payload),
            None => request.call(),
        }
        .map_err(|error| format!("ClickHouse request failed: {error}"))?;
        response
            .into_string()
            .map_err(|error| format!("ClickHouse response read failed: {error}"))
    }

    fn buffered_events_matching(&self, filter: &EventFilter) -> Result<Vec<StoredEvent>, String> {
        let buffer = self.buffer.lock().map_err(|error| error.to_string())?;
        Ok(buffer
            .iter()
            .filter(|event| matches_filter(event, filter))
            .cloned()
            .collect())
    }

    fn insert_body(events: &[StoredEvent]) -> Result<String, String> {
        let mut lines = Vec::with_capacity(events.len());
        for event in events {
            let row = serde_json::json!({
                "timestamp": event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
                "tenant_id": event.tenant_id,
                "event_class": event.event_class,
                "severity": event.severity,
                "device_id": event.device_id,
                "user_name": event.user_name,
                "process_name": event.process_name,
                "src_ip": event.src_ip,
                "dst_ip": event.dst_ip,
                "raw_json": event.raw_json,
            });
            lines.push(
                serde_json::to_string(&row)
                    .map_err(|error| format!("ClickHouse insert serialization failed: {error}"))?,
            );
        }
        Ok(lines.join("\n"))
    }

    fn remote_select_events(
        &self,
        filter: &EventFilter,
        fetch_limit: u32,
    ) -> Result<Vec<StoredEvent>, String> {
        #[derive(Deserialize)]
        struct QueryRow {
            timestamp: String,
            tenant_id: String,
            event_class: u16,
            severity: u8,
            device_id: String,
            user_name: String,
            process_name: String,
            src_ip: String,
            dst_ip: String,
            raw_json: String,
        }

        if self.is_memory_mode() {
            return Ok(Vec::new());
        }

        let query = format!(
            "SELECT formatDateTime(timestamp, '%Y-%m-%dT%H:%i:%S.%fZ') AS timestamp, tenant_id, event_class, severity, device_id, user_name, process_name, src_ip, dst_ip, raw_json FROM {}.events {} ORDER BY timestamp DESC LIMIT {} FORMAT JSONEachRow",
            self.config.database,
            self.filter_clause(filter),
            fetch_limit.max(1),
        );
        let body = self.execute_query(&query, None)?;
        body.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                let row: QueryRow = serde_json::from_str(line)
                    .map_err(|error| format!("ClickHouse row parse failed: {error}"))?;
                let timestamp = chrono::DateTime::parse_from_rfc3339(&row.timestamp)
                    .map(|value| value.with_timezone(&Utc))
                    .or_else(|_| {
                        chrono::NaiveDateTime::parse_from_str(
                            &row.timestamp,
                            "%Y-%m-%d %H:%M:%S%.f",
                        )
                        .map(|value| value.and_utc())
                    })
                    .map_err(|error| format!("ClickHouse timestamp parse failed: {error}"))?;
                Ok(StoredEvent {
                    timestamp,
                    tenant_id: row.tenant_id,
                    event_class: row.event_class,
                    severity: row.severity,
                    device_id: row.device_id,
                    user_name: row.user_name,
                    process_name: row.process_name,
                    src_ip: row.src_ip,
                    dst_ip: row.dst_ip,
                    raw_json: row.raw_json,
                })
            })
            .collect()
    }

    pub fn ensure_schema(&self) -> Result<(), String> {
        if self.is_memory_mode() {
            return Ok(());
        }
        self.execute_query(
            &format!("CREATE DATABASE IF NOT EXISTS {}", self.config.database),
            None,
        )?;
        self.execute_query(&self.create_table_sql(), None)?;
        self.execute_query(&self.alerts_per_hour_mv_sql(), None)?;
        Ok(())
    }

    /// Returns the DDL for creating the events table.
    pub fn create_table_sql(&self) -> String {
        format!(
            r#"CREATE TABLE IF NOT EXISTS {db}.events (
    timestamp DateTime64(3),
    tenant_id String,
    event_class UInt16,
    severity UInt8,
    device_id String,
    user_name String,
    process_name String,
    src_ip String,
    dst_ip String,
    raw_json String
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, timestamp, event_class)
TTL timestamp + INTERVAL {days} DAY"#,
            db = self.config.database,
            days = self.config.retention_days,
        )
    }

    /// DDL for the pre-aggregated alerts-per-hour materialized view.
    pub fn alerts_per_hour_mv_sql(&self) -> String {
        format!(
            r#"CREATE MATERIALIZED VIEW IF NOT EXISTS {db}.alerts_per_hour
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (tenant_id, hour, severity)
AS SELECT
    tenant_id,
    toStartOfHour(timestamp) AS hour,
    severity,
    count() AS cnt
FROM {db}.events
GROUP BY tenant_id, hour, severity"#,
            db = self.config.database,
        )
    }

    /// Number of events currently buffered.
    pub fn buffer_len(&self) -> usize {
        self.buffer.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Total events inserted since start.
    pub fn total_inserted(&self) -> u64 {
        self.total_inserted
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Flush the current buffer to ClickHouse via the HTTP API.
    pub fn flush(&self) -> Result<usize, String> {
        let snapshot = {
            let buf = self.buffer.lock().map_err(|error| error.to_string())?;
            buf.clone()
        };
        let count = snapshot.len();
        if count == 0 {
            return Ok(0);
        }
        if !self.is_memory_mode() {
            let body = Self::insert_body(&snapshot)?;
            self.execute_query(
                &format!(
                    "INSERT INTO {}.events FORMAT JSONEachRow",
                    self.config.database
                ),
                Some(&body),
            )?;
        }
        let mut buf = self.buffer.lock().map_err(|error| error.to_string())?;
        let drain = count.min(buf.len());
        buf.drain(0..drain);
        self.total_inserted.fetch_add(
            drain as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        Ok(drain)
    }
}

impl EventStore for ClickHouseStorage {
    fn insert_events(&self, events: &[StoredEvent]) -> Result<usize, String> {
        let mut buf = self.buffer.lock().map_err(|e| e.to_string())?;
        buf.extend_from_slice(events);
        let should_flush = buf.len() >= self.config.batch_size;
        let count = events.len();
        drop(buf);
        if should_flush {
            self.flush()?;
        }
        Ok(count)
    }

    fn query_events(&self, filter: &EventFilter) -> Result<Vec<StoredEvent>, String> {
        let mut results = self.buffered_events_matching(filter)?;
        if !self.is_memory_mode() {
            let fetch_limit = filter
                .offset
                .unwrap_or(0)
                .saturating_add(filter.limit.unwrap_or(100))
                .saturating_add(results.len() as u32)
                .max(100);
            match self.remote_select_events(filter, fetch_limit) {
                Ok(mut remote) => results.append(&mut remote),
                Err(error) => {
                    log::warn!("[CLICKHOUSE] query fallback to buffer-only results: {error}");
                }
            }
        }
        Ok(apply_offset_limit(results, filter))
    }

    fn count_events(&self, filter: &EventFilter) -> Result<u64, String> {
        let buffered = self.buffered_events_matching(filter)?;
        if self.is_memory_mode() {
            return Ok(buffered.len() as u64);
        }

        #[derive(Deserialize)]
        struct CountRow {
            count: u64,
        }

        let query = format!(
            "SELECT count() AS count FROM {}.events {} FORMAT JSONEachRow",
            self.config.database,
            self.filter_clause(filter),
        );
        let body = self.execute_query(&query, None)?;
        let count = body
            .lines()
            .find(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str::<CountRow>(line))
            .transpose()
            .map_err(|error| format!("ClickHouse count parse failed: {error}"))?
            .map(|row| row.count)
            .unwrap_or(0);
        Ok(count + buffered.len() as u64)
    }

    fn aggregate(&self, query: &AggregationQuery) -> Result<AggregationResult, String> {
        let events = self.query_events(&EventFilter {
            limit: Some(50_000),
            offset: Some(0),
            ..query.filter.clone()
        })?;
        Ok(aggregate_events(&events, query))
    }

    fn purge_before(&self, timestamp: &DateTime<Utc>) -> Result<u64, String> {
        let buffered_purged = {
            let mut buf = self.buffer.lock().map_err(|error| error.to_string())?;
            let before = buf.len();
            buf.retain(|event| event.timestamp >= *timestamp);
            (before - buf.len()) as u64
        };
        if self.is_memory_mode() {
            return Ok(buffered_purged);
        }

        #[derive(Deserialize)]
        struct CountRow {
            count: u64,
        }

        let count_query = format!(
            "SELECT count() AS count FROM {}.events WHERE timestamp < parseDateTime64BestEffort({}) FORMAT JSONEachRow",
            self.config.database,
            sql_string_literal(&timestamp.to_rfc3339()),
        );
        let count_body = self.execute_query(&count_query, None)?;
        let persisted = count_body
            .lines()
            .find(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str::<CountRow>(line))
            .transpose()
            .map_err(|error| format!("ClickHouse purge count parse failed: {error}"))?
            .map(|row| row.count)
            .unwrap_or(0);
        self.execute_query(
            &format!(
                "ALTER TABLE {}.events DELETE WHERE timestamp < parseDateTime64BestEffort({})",
                self.config.database,
                sql_string_literal(&timestamp.to_rfc3339()),
            ),
            None,
        )?;
        Ok(persisted + buffered_purged)
    }
}

// ── In-memory fallback ──────────────────────────────────────────

/// Simple in-memory event store used when ClickHouse is not configured.
pub struct InMemoryEventStore {
    events: std::sync::Mutex<Vec<StoredEvent>>,
}

impl Default for InMemoryEventStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryEventStore {
    pub fn new() -> Self {
        Self {
            events: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl EventStore for InMemoryEventStore {
    fn insert_events(&self, events: &[StoredEvent]) -> Result<usize, String> {
        let mut store = self.events.lock().map_err(|e| e.to_string())?;
        store.extend_from_slice(events);
        Ok(events.len())
    }
    fn query_events(&self, filter: &EventFilter) -> Result<Vec<StoredEvent>, String> {
        let store = self.events.lock().map_err(|e| e.to_string())?;
        let filtered: Vec<StoredEvent> = store
            .iter()
            .filter(|event| matches_filter(event, filter))
            .cloned()
            .collect();
        Ok(apply_offset_limit(filtered, filter))
    }
    fn count_events(&self, filter: &EventFilter) -> Result<u64, String> {
        let store = self.events.lock().map_err(|e| e.to_string())?;
        let count = store
            .iter()
            .filter(|event| matches_filter(event, filter))
            .count();
        Ok(count as u64)
    }
    fn aggregate(&self, query: &AggregationQuery) -> Result<AggregationResult, String> {
        let events = self.query_events(&EventFilter {
            limit: Some(50_000),
            offset: Some(0),
            ..query.filter.clone()
        })?;
        Ok(aggregate_events(&events, query))
    }
    fn purge_before(&self, timestamp: &DateTime<Utc>) -> Result<u64, String> {
        let mut store = self.events.lock().map_err(|e| e.to_string())?;
        let before = store.len();
        store.retain(|e| e.timestamp >= *timestamp);
        Ok((before - store.len()) as u64)
    }
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_clickhouse_config(batch_size: usize) -> ClickHouseConfig {
        ClickHouseConfig {
            url: "memory://clickhouse".into(),
            batch_size,
            ..Default::default()
        }
    }

    fn sample_event(ts: &str, severity: u8, device: &str) -> StoredEvent {
        StoredEvent {
            timestamp: ts.parse::<DateTime<Utc>>().unwrap(),
            tenant_id: "t1".into(),
            event_class: 1001,
            severity,
            device_id: device.into(),
            user_name: "testuser".into(),
            process_name: "sshd".into(),
            src_ip: "10.0.0.1".into(),
            dst_ip: "10.0.0.2".into(),
            raw_json: "{}".into(),
        }
    }

    #[test]
    fn clickhouse_config_defaults() {
        let cfg = ClickHouseConfig::default();
        assert_eq!(cfg.url, "http://localhost:8123");
        assert_eq!(cfg.database, "wardex");
        assert_eq!(cfg.batch_size, 1000);
        assert_eq!(cfg.retention_days, 90);
    }

    #[test]
    fn create_table_sql_contains_ttl() {
        let store = ClickHouseStorage::new(ClickHouseConfig::default());
        let sql = store.create_table_sql();
        assert!(sql.contains("MergeTree"));
        assert!(sql.contains("TTL timestamp + INTERVAL 90 DAY"));
        assert!(sql.contains("PARTITION BY toYYYYMM(timestamp)"));
    }

    #[test]
    fn materialized_view_sql() {
        let store = ClickHouseStorage::new(ClickHouseConfig::default());
        let sql = store.alerts_per_hour_mv_sql();
        assert!(sql.contains("MATERIALIZED VIEW"));
        assert!(sql.contains("SummingMergeTree"));
    }

    #[test]
    fn insert_and_query_events() {
        let store = ClickHouseStorage::new(test_clickhouse_config(10000));
        let events = vec![
            sample_event("2026-04-05T10:00:00Z", 3, "dev1"),
            sample_event("2026-04-05T11:00:00Z", 5, "dev2"),
            sample_event("2026-04-05T12:00:00Z", 1, "dev1"),
        ];
        let inserted = store.insert_events(&events).unwrap();
        assert_eq!(inserted, 3);
        assert_eq!(store.buffer_len(), 3);

        let all = store.query_events(&EventFilter::default()).unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn query_with_filter() {
        let store = ClickHouseStorage::new(test_clickhouse_config(10000));
        store
            .insert_events(&[
                sample_event("2026-04-05T10:00:00Z", 3, "dev1"),
                sample_event("2026-04-05T11:00:00Z", 5, "dev2"),
                sample_event("2026-04-05T12:00:00Z", 1, "dev1"),
            ])
            .unwrap();

        let filter = EventFilter {
            device_id: Some("dev1".into()),
            ..Default::default()
        };
        let results = store.query_events(&filter).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn count_events() {
        let store = ClickHouseStorage::new(test_clickhouse_config(10000));
        store
            .insert_events(&[
                sample_event("2026-04-05T10:00:00Z", 3, "dev1"),
                sample_event("2026-04-05T11:00:00Z", 5, "dev2"),
            ])
            .unwrap();
        let count = store.count_events(&EventFilter::default()).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn aggregate_by_device() {
        let store = ClickHouseStorage::new(test_clickhouse_config(10000));
        store
            .insert_events(&[
                sample_event("2026-04-05T10:00:00Z", 3, "dev1"),
                sample_event("2026-04-05T11:00:00Z", 5, "dev2"),
                sample_event("2026-04-05T12:00:00Z", 1, "dev1"),
            ])
            .unwrap();
        let result = store
            .aggregate(&AggregationQuery {
                group_by: "device_id".into(),
                metric: AggregationMetric::Count,
                filter: EventFilter::default(),
            })
            .unwrap();
        assert_eq!(result.total, 3);
        assert_eq!(result.buckets.len(), 2);
        assert_eq!(result.buckets[0].key, "dev1"); // sorted by count desc
        assert_eq!(result.buckets[0].count, 2);
    }

    #[test]
    fn flush_clears_buffer() {
        let store = ClickHouseStorage::new(test_clickhouse_config(10000));
        store
            .insert_events(&[sample_event("2026-04-05T10:00:00Z", 3, "dev1")])
            .unwrap();
        assert_eq!(store.buffer_len(), 1);
        let flushed = store.flush().unwrap();
        assert_eq!(flushed, 1);
        assert_eq!(store.buffer_len(), 0);
        assert_eq!(store.total_inserted(), 1);
    }

    #[test]
    fn auto_flush_on_batch_size() {
        let store = ClickHouseStorage::new(test_clickhouse_config(2));
        store
            .insert_events(&[
                sample_event("2026-04-05T10:00:00Z", 3, "dev1"),
                sample_event("2026-04-05T11:00:00Z", 5, "dev2"),
            ])
            .unwrap();
        // Buffer should have been flushed (batch_size = 2)
        assert_eq!(store.buffer_len(), 0);
        assert_eq!(store.total_inserted(), 2);
    }

    #[test]
    fn purge_old_events() {
        let store = ClickHouseStorage::new(test_clickhouse_config(10000));
        store
            .insert_events(&[
                sample_event("2026-04-01T10:00:00Z", 3, "dev1"),
                sample_event("2026-04-05T11:00:00Z", 5, "dev2"),
            ])
            .unwrap();
        let cutoff = "2026-04-03T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let purged = store.purge_before(&cutoff).unwrap();
        assert_eq!(purged, 1);
        assert_eq!(store.buffer_len(), 1);
    }

    #[test]
    fn in_memory_store_basic() {
        let store = InMemoryEventStore::new();
        store
            .insert_events(&[sample_event("2026-04-05T10:00:00Z", 3, "dev1")])
            .unwrap();
        let count = store.count_events(&EventFilter::default()).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn pagination_works() {
        let store = ClickHouseStorage::new(test_clickhouse_config(10000));
        store
            .insert_events(&[
                sample_event("2026-04-05T10:00:00Z", 1, "a"),
                sample_event("2026-04-05T11:00:00Z", 2, "b"),
                sample_event("2026-04-05T12:00:00Z", 3, "c"),
                sample_event("2026-04-05T13:00:00Z", 4, "d"),
            ])
            .unwrap();
        let page = store
            .query_events(&EventFilter {
                limit: Some(2),
                offset: Some(1),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].device_id, "c");
        assert_eq!(page[1].device_id, "b");
    }
}
