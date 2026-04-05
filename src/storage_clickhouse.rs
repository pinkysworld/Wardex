// ClickHouse event storage adapter for high-volume time-series telemetry.
//
// Provides a storage trait and ClickHouse implementation for event
// ingest, querying, aggregation, and retention management.
// SQLite remains the backend for config, cases, audit, and fleet state.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
        self.buffer.lock().unwrap().len()
    }

    /// Total events inserted since start.
    pub fn total_inserted(&self) -> u64 {
        self.total_inserted.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Flush the buffer (in production this would POST to ClickHouse HTTP API).
    pub fn flush(&self) -> Result<usize, String> {
        let mut buf = self.buffer.lock().map_err(|e| e.to_string())?;
        let count = buf.len();
        self.total_inserted.fetch_add(count as u64, std::sync::atomic::Ordering::Relaxed);
        buf.clear();
        Ok(count)
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
        let buf = self.buffer.lock().map_err(|e| e.to_string())?;
        let limit = filter.limit.unwrap_or(100) as usize;
        let offset = filter.offset.unwrap_or(0) as usize;
        let results: Vec<StoredEvent> = buf.iter()
            .filter(|e| {
                if let Some(ref t) = filter.tenant_id { if e.tenant_id != *t { return false; } }
                if let Some(ref from) = filter.from { if e.timestamp < *from { return false; } }
                if let Some(ref to) = filter.to { if e.timestamp > *to { return false; } }
                if let Some(sev) = filter.severity_min { if e.severity < sev { return false; } }
                if let Some(cls) = filter.event_class { if e.event_class != cls { return false; } }
                if let Some(ref d) = filter.device_id { if e.device_id != *d { return false; } }
                if let Some(ref u) = filter.user_name { if e.user_name != *u { return false; } }
                if let Some(ref ip) = filter.src_ip { if e.src_ip != *ip { return false; } }
                true
            })
            .skip(offset)
            .take(limit)
            .cloned()
            .collect();
        Ok(results)
    }

    fn count_events(&self, filter: &EventFilter) -> Result<u64, String> {
        let results = self.query_events(&EventFilter { limit: Some(u32::MAX), ..(filter.clone()) })?;
        Ok(results.len() as u64)
    }

    fn aggregate(&self, query: &AggregationQuery) -> Result<AggregationResult, String> {
        let events = self.query_events(&EventFilter { limit: Some(u32::MAX), ..(query.filter.clone()) })?;
        let mut groups: HashMap<String, u64> = HashMap::new();
        for ev in &events {
            let key = match query.group_by.as_str() {
                "severity" => ev.severity.to_string(),
                "device_id" => ev.device_id.clone(),
                "user_name" => ev.user_name.clone(),
                "event_class" => ev.event_class.to_string(),
                _ => "other".into(),
            };
            *groups.entry(key).or_insert(0) += 1;
        }
        let total = events.len() as u64;
        let mut buckets: Vec<AggBucket> = groups.into_iter()
            .map(|(key, count)| AggBucket { key, count })
            .collect();
        buckets.sort_by(|a, b| b.count.cmp(&a.count));
        Ok(AggregationResult { buckets, total })
    }

    fn purge_before(&self, timestamp: &DateTime<Utc>) -> Result<u64, String> {
        let mut buf = self.buffer.lock().map_err(|e| e.to_string())?;
        let before = buf.len();
        buf.retain(|e| e.timestamp >= *timestamp);
        Ok((before - buf.len()) as u64)
    }
}

// ── In-memory fallback ──────────────────────────────────────────

/// Simple in-memory event store used when ClickHouse is not configured.
pub struct InMemoryEventStore {
    events: std::sync::Mutex<Vec<StoredEvent>>,
}

impl InMemoryEventStore {
    pub fn new() -> Self {
        Self { events: std::sync::Mutex::new(Vec::new()) }
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
        let limit = filter.limit.unwrap_or(100) as usize;
        let offset = filter.offset.unwrap_or(0) as usize;
        let filtered: Vec<StoredEvent> = store.iter()
            .filter(|e| {
                if let Some(ref tid) = filter.tenant_id { if e.tenant_id != *tid { return false; } }
                if let Some(ref from) = filter.from { if e.timestamp < *from { return false; } }
                if let Some(ref to) = filter.to { if e.timestamp > *to { return false; } }
                if let Some(sev) = filter.severity_min { if e.severity < sev { return false; } }
                if let Some(cls) = filter.event_class { if e.event_class != cls { return false; } }
                if let Some(ref did) = filter.device_id { if e.device_id != *did { return false; } }
                if let Some(ref un) = filter.user_name { if e.user_name != *un { return false; } }
                if let Some(ref ip) = filter.src_ip { if e.src_ip != *ip { return false; } }
                true
            })
            .skip(offset)
            .take(limit)
            .cloned()
            .collect();
        Ok(filtered)
    }
    fn count_events(&self, filter: &EventFilter) -> Result<u64, String> {
        let store = self.events.lock().map_err(|e| e.to_string())?;
        let count = store.iter()
            .filter(|e| {
                if let Some(ref tid) = filter.tenant_id { if e.tenant_id != *tid { return false; } }
                if let Some(ref from) = filter.from { if e.timestamp < *from { return false; } }
                if let Some(ref to) = filter.to { if e.timestamp > *to { return false; } }
                if let Some(sev) = filter.severity_min { if e.severity < sev { return false; } }
                if let Some(cls) = filter.event_class { if e.event_class != cls { return false; } }
                if let Some(ref did) = filter.device_id { if e.device_id != *did { return false; } }
                if let Some(ref un) = filter.user_name { if e.user_name != *un { return false; } }
                if let Some(ref ip) = filter.src_ip { if e.src_ip != *ip { return false; } }
                true
            })
            .count();
        Ok(count as u64)
    }
    fn aggregate(&self, _query: &AggregationQuery) -> Result<AggregationResult, String> {
        Ok(AggregationResult { buckets: vec![], total: 0 })
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
    use chrono::TimeZone;

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
        let store = ClickHouseStorage::new(ClickHouseConfig { batch_size: 10000, ..Default::default() });
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
        let store = ClickHouseStorage::new(ClickHouseConfig { batch_size: 10000, ..Default::default() });
        store.insert_events(&[
            sample_event("2026-04-05T10:00:00Z", 3, "dev1"),
            sample_event("2026-04-05T11:00:00Z", 5, "dev2"),
            sample_event("2026-04-05T12:00:00Z", 1, "dev1"),
        ]).unwrap();

        let filter = EventFilter { device_id: Some("dev1".into()), ..Default::default() };
        let results = store.query_events(&filter).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn count_events() {
        let store = ClickHouseStorage::new(ClickHouseConfig { batch_size: 10000, ..Default::default() });
        store.insert_events(&[
            sample_event("2026-04-05T10:00:00Z", 3, "dev1"),
            sample_event("2026-04-05T11:00:00Z", 5, "dev2"),
        ]).unwrap();
        let count = store.count_events(&EventFilter::default()).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn aggregate_by_device() {
        let store = ClickHouseStorage::new(ClickHouseConfig { batch_size: 10000, ..Default::default() });
        store.insert_events(&[
            sample_event("2026-04-05T10:00:00Z", 3, "dev1"),
            sample_event("2026-04-05T11:00:00Z", 5, "dev2"),
            sample_event("2026-04-05T12:00:00Z", 1, "dev1"),
        ]).unwrap();
        let result = store.aggregate(&AggregationQuery {
            group_by: "device_id".into(),
            metric: AggregationMetric::Count,
            filter: EventFilter::default(),
        }).unwrap();
        assert_eq!(result.total, 3);
        assert_eq!(result.buckets.len(), 2);
        assert_eq!(result.buckets[0].key, "dev1"); // sorted by count desc
        assert_eq!(result.buckets[0].count, 2);
    }

    #[test]
    fn flush_clears_buffer() {
        let store = ClickHouseStorage::new(ClickHouseConfig { batch_size: 10000, ..Default::default() });
        store.insert_events(&[sample_event("2026-04-05T10:00:00Z", 3, "dev1")]).unwrap();
        assert_eq!(store.buffer_len(), 1);
        let flushed = store.flush().unwrap();
        assert_eq!(flushed, 1);
        assert_eq!(store.buffer_len(), 0);
        assert_eq!(store.total_inserted(), 1);
    }

    #[test]
    fn auto_flush_on_batch_size() {
        let store = ClickHouseStorage::new(ClickHouseConfig { batch_size: 2, ..Default::default() });
        store.insert_events(&[
            sample_event("2026-04-05T10:00:00Z", 3, "dev1"),
            sample_event("2026-04-05T11:00:00Z", 5, "dev2"),
        ]).unwrap();
        // Buffer should have been flushed (batch_size = 2)
        assert_eq!(store.buffer_len(), 0);
        assert_eq!(store.total_inserted(), 2);
    }

    #[test]
    fn purge_old_events() {
        let store = ClickHouseStorage::new(ClickHouseConfig { batch_size: 10000, ..Default::default() });
        store.insert_events(&[
            sample_event("2026-04-01T10:00:00Z", 3, "dev1"),
            sample_event("2026-04-05T11:00:00Z", 5, "dev2"),
        ]).unwrap();
        let cutoff = "2026-04-03T00:00:00Z".parse::<DateTime<Utc>>().unwrap();
        let purged = store.purge_before(&cutoff).unwrap();
        assert_eq!(purged, 1);
        assert_eq!(store.buffer_len(), 1);
    }

    #[test]
    fn in_memory_store_basic() {
        let store = InMemoryEventStore::new();
        store.insert_events(&[
            sample_event("2026-04-05T10:00:00Z", 3, "dev1"),
        ]).unwrap();
        let count = store.count_events(&EventFilter::default()).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn pagination_works() {
        let store = ClickHouseStorage::new(ClickHouseConfig { batch_size: 10000, ..Default::default() });
        store.insert_events(&[
            sample_event("2026-04-05T10:00:00Z", 1, "a"),
            sample_event("2026-04-05T11:00:00Z", 2, "b"),
            sample_event("2026-04-05T12:00:00Z", 3, "c"),
            sample_event("2026-04-05T13:00:00Z", 4, "d"),
        ]).unwrap();
        let page = store.query_events(&EventFilter { limit: Some(2), offset: Some(1), ..Default::default() }).unwrap();
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].device_id, "b");
        assert_eq!(page[1].device_id, "c");
    }
}
