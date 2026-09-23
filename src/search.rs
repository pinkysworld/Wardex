// ── Full-Text Event Search (Tantivy) ─────────────────────────────────────────
//
// Real, disk-backed full-text search over security events, powered by
// Tantivy. This module is split into three layers:
//
//   1. `SearchIndex`   — a single Tantivy index (schema, writer, reader) with
//      a small, stable, string-keyed ingestion API (`index_event`), so
//      callers never need to know about Tantivy types.
//   2. A hunt-query DSL compiler (`compile_predicate`) that turns the
//      existing KQL-like `HuntPredicate` tree into native Tantivy queries
//      (`BooleanQuery` / `RegexQuery` / `RangeQuery`), so filtering runs
//      inside the index rather than by scanning every event in Rust.
//   3. `PersistentEventStore` — a disk-backed, mmap'd instance of
//      `SearchIndex` under the Wardex `var/` directory, with retention
//      deletion, schema-version-aware rebuild-on-corruption, and periodic
//      commits that never block search requests.
//
// ── Schema ────────────────────────────────────────────────────────────────
//
//   field             tantivy type              purpose
//   ----------------  ------------------------  --------------------------
//   timestamp         DATE  (FAST)               range filters + sort
//   timestamp_kw      STORED (text)              display (original case)
//   timestamp_lc      STRING                     `timestamp:` match (lowercased)
//   device_id         STORED (text)              display (original case)
//   device_id_lc      STRING                     exact/substring match (lowercased)
//   event_class       STORED (text)              display (original case)
//   event_class_lc    STRING                     exact/substring match (lowercased)
//   process_name      STORED (text)              display (original case)
//   process_name_lc   STRING                     exact/substring match (lowercased)
//   src_ip            STORED (text)               display (original case)
//   src_ip_lc         STRING                     exact/substring match (lowercased)
//   dst_ip            STORED (text)               display (original case)
//   dst_ip_lc         STRING                     exact/substring match (lowercased)
//   user_name         STORED (text)               display (original case)
//   user_name_lc      STRING                     exact/substring match (lowercased)
//   command_line      TEXT   (STORED)            tokenized full-text search
//   command_line_lc   STRING                     substring/wildcard match (lowercased)
//   raw_text          TEXT   (STORED)            tokenized full-text search
//   raw_text_lc       STRING                     substring/wildcard match (lowercased)
//
// Every field used for `field:pattern`/free-text matching is untokenized
// (one raw token per document) *and* lowercased at index time (its `_lc`
// companion), with the query pattern lowercased the same way before being
// compiled to a regex (see `glob_to_regex`) — this reproduces the
// substring/wildcard semantics of the original hand-rolled scanner exactly,
// without relying on inline regex flags: Tantivy's regex engine
// (`tantivy-fst`, built on a restricted `regex-automata` syntax subset)
// rejects the `(?i)` case-insensitive flag with a parse error, so case
// folding has to happen on the data instead. The un-suffixed fields keep the
// original-case value purely for display (`SearchHit`/aggregation output).
//
// ── DSL → Tantivy mapping ────────────────────────────────────────────────
//
//   HuntPredicate::FieldMatch { field, pattern } → RegexQuery on the `_lc`
//     STRING field for `field` (glob `*` and bare substrings both compile to
//     a regex; see `glob_to_regex`). An unknown field name matches every
//     document for pattern `"*"` and no documents otherwise, matching the
//     legacy scanner's behaviour for empty field values.
//   HuntPredicate::FreeText(text)   → BooleanQuery (Should) of RegexQuery
//     over every free-text field (device_id_lc, process_name_lc,
//     command_line_lc, src_ip_lc, dst_ip_lc, user_name_lc, raw_text_lc).
//   HuntPredicate::And/Or/Not       → BooleanQuery (Must/Should/MustNot).
//   SearchQuery.from/to             → RangeQuery on the `timestamp` fast
//     field, ANDed with the free-text query.
//
// ── Fallback to the linear scanner ───────────────────────────────────────
//
// Every predicate the DSL currently produces compiles to a native Tantivy
// query — there is no fallback needed for filtering. Tantivy has no generic
// group-by/aggregation collector for arbitrary stored string fields, though,
// so `hunt_aggregate` uses Tantivy only to *narrow* the candidate set (via
// the compiled filter query, ordered by recency and capped at
// `AGG_SCAN_LIMIT` documents), then reuses the original linear evaluator
// (`field_value`/`evaluate_predicate`, retained below) to group/bucket that
// bounded candidate set. This keeps aggregation semantics identical to the
// pre-Tantivy implementation while letting the index do the expensive part
// (locating matching documents) instead of scanning the whole corpus.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tantivy::collector::{Count, TopDocs};
use tantivy::directory::MmapDirectory;
use tantivy::query::{AllQuery, BooleanQuery, EmptyQuery, Occur, Query, RangeQuery, RegexQuery};
use tantivy::schema::{FAST, Field, STORED, STRING, Schema, TEXT, TantivyDocument, Value};
use tantivy::{Index, IndexReader, IndexWriter, ReloadPolicy, Term};

/// Bumped whenever the on-disk schema changes shape. A mismatch (or a
/// missing/corrupt metadata sidecar) triggers an automatic rebuild of the
/// on-disk index rather than a hard failure.
pub const SEARCH_SCHEMA_VERSION: u32 = 2;

/// Sidecar metadata file name written next to the Tantivy index directory.
/// Doctor/status tooling reads this file directly instead of opening the
/// live index (which could race with the running server's writer lock).
const META_FILE: &str = "wardex_search_meta.json";

/// Upper bound on how many (recency-ordered) matching documents
/// `hunt_aggregate` will pull out of the index before bucketing in memory.
/// Aggregations over corpora at or under this size are exact; beyond it,
/// only the most recent `AGG_SCAN_LIMIT` matches are considered (documented
/// limitation, matching common practice in similar hunting tools).
const AGG_SCAN_LIMIT: usize = 50_000;

// ── Search Query ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchQuery {
    pub query: String,
    #[serde(default)]
    pub fields: Vec<String>,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
    #[serde(default)]
    pub sort_by: Option<String>,
    #[serde(default)]
    pub sort_desc: bool,
}

fn default_limit() -> usize {
    50
}

// ── Search Result ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    pub total: u64,
    pub hits: Vec<SearchHit>,
    pub took_ms: f64,
    pub query: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    pub score: f32,
    pub timestamp: String,
    pub device_id: String,
    pub event_class: String,
    pub process_name: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub snippet: String,
}

// ── Search Index ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexStats {
    pub total_documents: u64,
    pub index_size_bytes: u64,
    pub last_commit: Option<DateTime<Utc>>,
    pub pending_docs: u64,
    pub schema_version: u32,
    /// True the first time stats were read after this process rebuilt the
    /// on-disk index because of corruption or a schema-version mismatch.
    pub rebuilt: bool,
}

/// Handles to every field in the search schema, resolved once at open time.
#[derive(Debug, Clone)]
struct SearchFields {
    timestamp: Field,
    timestamp_kw: Field,
    timestamp_lc: Field,
    device_id: Field,
    device_id_lc: Field,
    event_class: Field,
    event_class_lc: Field,
    process_name: Field,
    process_name_lc: Field,
    command_line: Field,
    command_line_lc: Field,
    src_ip: Field,
    src_ip_lc: Field,
    dst_ip: Field,
    dst_ip_lc: Field,
    user_name: Field,
    user_name_lc: Field,
    raw_text: Field,
    raw_text_lc: Field,
}

fn build_schema() -> (Schema, SearchFields) {
    let mut b = Schema::builder();
    let timestamp = b.add_date_field("timestamp", FAST);
    // Display copies keep the original-case text, stored only (not
    // indexed): matching always goes through the lowercased `_lc` companion
    // below, since Tantivy's regex engine has no case-insensitive flag.
    let timestamp_kw = b.add_text_field("timestamp_kw", STORED);
    let timestamp_lc = b.add_text_field("timestamp_lc", STRING);
    let device_id = b.add_text_field("device_id", STORED);
    let device_id_lc = b.add_text_field("device_id_lc", STRING);
    let event_class = b.add_text_field("event_class", STORED);
    let event_class_lc = b.add_text_field("event_class_lc", STRING);
    let process_name = b.add_text_field("process_name", STORED);
    let process_name_lc = b.add_text_field("process_name_lc", STRING);
    let command_line = b.add_text_field("command_line", TEXT | STORED);
    let command_line_lc = b.add_text_field("command_line_lc", STRING);
    let src_ip = b.add_text_field("src_ip", STORED);
    let src_ip_lc = b.add_text_field("src_ip_lc", STRING);
    let dst_ip = b.add_text_field("dst_ip", STORED);
    let dst_ip_lc = b.add_text_field("dst_ip_lc", STRING);
    let user_name = b.add_text_field("user_name", STORED);
    let user_name_lc = b.add_text_field("user_name_lc", STRING);
    let raw_text = b.add_text_field("raw_text", TEXT | STORED);
    let raw_text_lc = b.add_text_field("raw_text_lc", STRING);
    let schema = b.build();
    let fields = SearchFields {
        timestamp,
        timestamp_kw,
        timestamp_lc,
        device_id,
        device_id_lc,
        event_class,
        event_class_lc,
        process_name,
        process_name_lc,
        command_line,
        command_line_lc,
        src_ip,
        src_ip_lc,
        dst_ip,
        dst_ip_lc,
        user_name,
        user_name_lc,
        raw_text,
        raw_text_lc,
    };
    (schema, fields)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IndexMetaFile {
    schema_version: u32,
    #[serde(default)]
    doc_count: u64,
    #[serde(default)]
    index_size_bytes: u64,
    #[serde(default)]
    last_commit: Option<DateTime<Utc>>,
}

#[derive(Debug, Default)]
struct StatsInner {
    last_commit: Option<DateTime<Utc>>,
    pending_docs: u64,
}

/// A Tantivy-backed search index. Depending on how it was opened this is
/// either an ephemeral in-RAM index (used for one-shot rebuild-from-events
/// calls and tests) or a persistent, mmap'd, on-disk index (used by
/// [`PersistentEventStore`]).
pub struct SearchIndex {
    #[allow(dead_code)]
    schema: Schema,
    fields: SearchFields,
    writer: Mutex<IndexWriter>,
    reader: IndexReader,
    disk_path: Option<PathBuf>,
    stats: Mutex<StatsInner>,
    rebuilt: AtomicBool,
    doc_count: AtomicU64,
}

impl std::fmt::Debug for SearchIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SearchIndex")
            .field("disk_path", &self.disk_path)
            .field("doc_count", &self.doc_count.load(Ordering::Relaxed))
            .finish()
    }
}

/// Minimum memory budget Tantivy's writer will accept per indexing thread.
const MIN_WRITER_MEMORY_BYTES: usize = 15_000_000;

fn open_index_at(dir: &Path, schema: &Schema) -> tantivy::Result<Index> {
    let mmap_dir = MmapDirectory::open(dir)?;
    Index::open_or_create(mmap_dir, schema.clone())
}

fn reset_dir(dir: &Path) -> Result<(), String> {
    if dir.exists() {
        std::fs::remove_dir_all(dir)
            .map_err(|e| format!("failed to reset search index directory {dir:?}: {e}"))?;
    }
    std::fs::create_dir_all(dir)
        .map_err(|e| format!("failed to create search index directory {dir:?}: {e}"))
}

fn read_meta(path: &Path) -> Option<IndexMetaFile> {
    let data = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

fn write_meta(path: &Path, meta: &IndexMetaFile) -> Result<(), String> {
    let data = serde_json::to_string_pretty(meta)
        .map_err(|e| format!("failed to serialize search index metadata: {e}"))?;
    std::fs::write(path, data)
        .map_err(|e| format!("failed to write search index metadata to {path:?}: {e}"))
}

fn dir_size_bytes(dir: &Path) -> u64 {
    let mut total = 0u64;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata()
                && meta.is_file()
            {
                total += meta.len();
            }
        }
    }
    total
}

impl SearchIndex {
    /// Open (or create) a persistent, mmap'd, on-disk search index at
    /// `path`, using the default writer memory budget. `path` is always
    /// treated as real on-disk state — including under `/tmp/` — so a
    /// deployment whose data directory happens to live under `/tmp`
    /// (containers, CI) still gets a durable index rather than silently
    /// losing it on restart. Callers that explicitly want a throwaway,
    /// never-persisted index (tests, fuzzing, one-shot benchmarks) should
    /// call [`SearchIndex::in_memory`] instead.
    pub fn new(path: &str) -> Result<Self, String> {
        Self::open_on_disk(Path::new(path), default_memory_budget() * 1024 * 1024)
            .map(|(idx, _rebuilt)| idx)
    }

    /// Create a throwaway in-memory index. Never touches disk, and is never
    /// shared across calls — each call gets its own fresh, empty index.
    /// Use this explicitly for tests, fuzzing, and one-shot benchmarks;
    /// production code should use [`SearchIndex::new`] or
    /// [`PersistentEventStore`].
    pub fn in_memory() -> Result<Self, String> {
        let (schema, fields) = build_schema();
        let index = Index::create_in_ram(schema.clone());
        let writer = index
            .writer_with_num_threads::<TantivyDocument>(1, MIN_WRITER_MEMORY_BYTES)
            .map_err(|e| format!("failed to create search index writer: {e}"))?;
        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::Manual)
            .try_into()
            .map_err(|e| format!("failed to create search index reader: {e}"))?;
        Ok(Self {
            schema,
            fields,
            writer: Mutex::new(writer),
            reader,
            disk_path: None,
            stats: Mutex::new(StatsInner::default()),
            rebuilt: AtomicBool::new(false),
            doc_count: AtomicU64::new(0),
        })
    }

    /// Open (or create) a persistent, mmap'd index at `dir`.
    ///
    /// Returns `(index, rebuilt)` where `rebuilt` is `true` if the on-disk
    /// index was wiped and recreated empty because it failed to open or its
    /// schema version didn't match [`SEARCH_SCHEMA_VERSION`] — callers
    /// should follow up with a rebuild-from-source-of-truth pass in that
    /// case (see [`PersistentEventStore::open`]).
    pub fn open_on_disk(dir: &Path, memory_budget_bytes: usize) -> Result<(Self, bool), String> {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("failed to create search index directory {dir:?}: {e}"))?;
        let (schema, fields) = build_schema();
        let meta_path = dir.join(META_FILE);

        let mut rebuilt = false;
        let index = match open_index_at(dir, &schema) {
            Ok(idx) => match read_meta(&meta_path) {
                Some(meta) if meta.schema_version == SEARCH_SCHEMA_VERSION => idx,
                _ => {
                    log::warn!(
                        "search index at {dir:?} is missing schema metadata or is a stale \
                         version; rebuilding empty index (schema_version={SEARCH_SCHEMA_VERSION})"
                    );
                    reset_dir(dir)?;
                    rebuilt = true;
                    open_index_at(dir, &schema)
                        .map_err(|e| format!("failed to recreate search index at {dir:?}: {e}"))?
                }
            },
            Err(e) => {
                log::warn!(
                    "search index at {dir:?} failed to open ({e}); it may be corrupt. \
                     Rebuilding an empty index."
                );
                reset_dir(dir)?;
                rebuilt = true;
                open_index_at(dir, &schema)
                    .map_err(|e| format!("failed to recreate search index at {dir:?}: {e}"))?
            }
        };

        let memory_budget = memory_budget_bytes.max(MIN_WRITER_MEMORY_BYTES);
        let writer = index
            .writer_with_num_threads::<TantivyDocument>(1, memory_budget)
            .map_err(|e| format!("failed to create search index writer at {dir:?}: {e}"))?;
        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::Manual)
            .try_into()
            .map_err(|e| format!("failed to create search index reader at {dir:?}: {e}"))?;

        let doc_count = reader.searcher().num_docs();
        write_meta(
            &meta_path,
            &IndexMetaFile {
                schema_version: SEARCH_SCHEMA_VERSION,
                doc_count,
                index_size_bytes: dir_size_bytes(dir),
                last_commit: None,
            },
        )?;

        Ok((
            Self {
                schema,
                fields,
                writer: Mutex::new(writer),
                reader,
                disk_path: Some(dir.to_path_buf()),
                stats: Mutex::new(StatsInner::default()),
                rebuilt: AtomicBool::new(rebuilt),
                doc_count: AtomicU64::new(doc_count),
            },
            rebuilt,
        ))
    }

    fn build_document(&self, fields: &HashMap<String, String>) -> TantivyDocument {
        let mut doc = TantivyDocument::default();
        let f = &self.fields;
        let get = |k: &str| fields.get(k).cloned().unwrap_or_default();

        let ts_raw = get("timestamp");
        let ts = parse_timestamp(&ts_raw).unwrap_or_else(Utc::now);
        doc.add_date(
            f.timestamp,
            tantivy::DateTime::from_timestamp_nanos(ts.timestamp_nanos_opt().unwrap_or_default()),
        );
        let ts_display = if ts_raw.is_empty() {
            ts.to_rfc3339()
        } else {
            ts_raw
        };
        doc.add_text(f.timestamp_lc, ts_display.to_lowercase());
        doc.add_text(f.timestamp_kw, ts_display);

        let mut add_pair = |disp: Field, lc: Field, value: String| {
            doc.add_text(lc, value.to_lowercase());
            doc.add_text(disp, value);
        };
        add_pair(f.device_id, f.device_id_lc, get("device_id"));
        add_pair(f.event_class, f.event_class_lc, get("event_class"));
        add_pair(f.process_name, f.process_name_lc, get("process_name"));
        add_pair(f.command_line, f.command_line_lc, get("command_line"));
        add_pair(f.src_ip, f.src_ip_lc, get("src_ip"));
        add_pair(f.dst_ip, f.dst_ip_lc, get("dst_ip"));
        add_pair(f.user_name, f.user_name_lc, get("user_name"));
        add_pair(f.raw_text, f.raw_text_lc, get("raw_text"));
        doc
    }

    pub fn index_event(&self, fields: HashMap<String, String>) -> Result<(), String> {
        let doc = self.build_document(&fields);
        let writer = self
            .writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        writer
            .add_document(doc)
            .map_err(|e| format!("failed to index event: {e}"))?;
        let mut stats = self
            .stats
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        stats.pending_docs += 1;
        Ok(())
    }

    /// Commit buffered writes and reload the reader so they become visible
    /// to `search`/`hunt` immediately. This is the only operation that
    /// blocks on the writer lock; ordinary reads never do.
    pub fn commit(&self) -> Result<u64, String> {
        {
            let mut writer = self
                .writer
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            writer
                .commit()
                .map_err(|e| format!("failed to commit search index: {e}"))?;
        }
        self.reader
            .reload()
            .map_err(|e| format!("failed to reload search index reader: {e}"))?;

        let total_documents = self.reader.searcher().num_docs();
        self.doc_count.store(total_documents, Ordering::Relaxed);
        let now = Utc::now();
        let index_size_bytes = match &self.disk_path {
            Some(dir) => dir_size_bytes(dir),
            None => total_documents * 512, // rough estimate for in-RAM indices
        };
        {
            let mut stats = self
                .stats
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            stats.last_commit = Some(now);
            stats.pending_docs = 0;
        }
        if let Some(dir) = &self.disk_path {
            let _ = write_meta(
                &dir.join(META_FILE),
                &IndexMetaFile {
                    schema_version: SEARCH_SCHEMA_VERSION,
                    doc_count: total_documents,
                    index_size_bytes,
                    last_commit: Some(now),
                },
            );
        }
        Ok(total_documents)
    }

    fn hit_from_doc(&self, doc: &TantivyDocument) -> SearchHit {
        let f = &self.fields;
        let get = |field: Field| -> String {
            doc.get_first(field)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string()
        };
        let raw_text = get(f.raw_text);
        let process_name = get(f.process_name);
        let command_line = get(f.command_line);
        let src_ip = get(f.src_ip);
        let snippet = if !raw_text.is_empty() {
            raw_text.chars().take(200).collect()
        } else {
            format!("{process_name} {command_line} {src_ip}")
        };
        SearchHit {
            score: 1.0,
            timestamp: get(f.timestamp_kw),
            device_id: get(f.device_id),
            event_class: get(f.event_class),
            process_name,
            src_ip,
            dst_ip: get(f.dst_ip),
            snippet,
        }
    }

    fn linear_doc_from(&self, doc: &TantivyDocument) -> LinearDoc {
        let f = &self.fields;
        let get = |field: Field| -> String {
            doc.get_first(field)
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string()
        };
        LinearDoc {
            timestamp: get(f.timestamp_kw),
            device_id: get(f.device_id),
            event_class: get(f.event_class),
            process_name: get(f.process_name),
            command_line: get(f.command_line),
            src_ip: get(f.src_ip),
            dst_ip: get(f.dst_ip),
            user_name: get(f.user_name),
            raw_text: get(f.raw_text),
        }
    }

    fn count_query(&self, query: &dyn Query) -> Result<u64, String> {
        self.reader
            .searcher()
            .search(query, &Count)
            .map(|c| c as u64)
            .map_err(|e| format!("search failed: {e}"))
    }

    /// Run `query`, returning the exact total match count and a page of
    /// hits ordered by timestamp (most-recent-first unless `sort_desc` is
    /// false).
    fn run_query(
        &self,
        query: &dyn Query,
        limit: usize,
        offset: usize,
        sort_desc: bool,
    ) -> Result<(u64, Vec<SearchHit>), String> {
        let searcher = self.reader.searcher();
        let total = self.count_query(query)?;
        let fetch_n = offset.saturating_add(limit.max(1)).min(200_000);
        let order = if sort_desc {
            tantivy::Order::Desc
        } else {
            tantivy::Order::Asc
        };
        let top = searcher
            .search(
                query,
                &TopDocs::with_limit(fetch_n)
                    .order_by_fast_field::<tantivy::DateTime>("timestamp", order),
            )
            .map_err(|e| format!("search failed: {e}"))?;
        let mut hits = Vec::new();
        for (_, addr) in top.into_iter().skip(offset).take(limit) {
            let doc: TantivyDocument = searcher
                .doc(addr)
                .map_err(|e| format!("failed to fetch document: {e}"))?;
            hits.push(self.hit_from_doc(&doc));
        }
        Ok((total, hits))
    }

    /// Fetch up to `limit` of the most recent documents matching `query`,
    /// for use by the aggregation fallback path.
    fn fetch_recent(&self, query: &dyn Query, limit: usize) -> Result<Vec<LinearDoc>, String> {
        let searcher = self.reader.searcher();
        let top = searcher
            .search(
                query,
                &TopDocs::with_limit(limit)
                    .order_by_fast_field::<tantivy::DateTime>("timestamp", tantivy::Order::Desc),
            )
            .map_err(|e| format!("search failed: {e}"))?;
        let mut out = Vec::with_capacity(top.len());
        for (_, addr) in top {
            let doc: TantivyDocument = searcher
                .doc(addr)
                .map_err(|e| format!("failed to fetch document: {e}"))?;
            out.push(self.linear_doc_from(&doc));
        }
        Ok(out)
    }

    /// Free-text search, compiled to a Tantivy query. `query.from`/`query.to`
    /// (RFC 3339 timestamps) are compiled to a `RangeQuery` on the fast
    /// `timestamp` field and ANDed with the free-text clause.
    pub fn search(&self, query: &SearchQuery) -> Result<SearchResult, String> {
        let start = std::time::Instant::now();
        let text_query = compile_free_text(&query.query, &self.fields)?;
        let combined =
            self.apply_time_range(text_query, query.from.as_deref(), query.to.as_deref())?;
        let sort_desc = query.sort_by.as_deref() != Some("timestamp") || query.sort_desc;
        let (total, hits) =
            self.run_query(combined.as_ref(), query.limit, query.offset, sort_desc)?;
        Ok(SearchResult {
            total,
            hits,
            took_ms: start.elapsed().as_secs_f64() * 1000.0,
            query: query.query.clone(),
        })
    }

    fn apply_time_range(
        &self,
        base: Box<dyn Query>,
        from: Option<&str>,
        to: Option<&str>,
    ) -> Result<Box<dyn Query>, String> {
        if from.is_none() && to.is_none() {
            return Ok(base);
        }
        let lower = match from.and_then(parse_timestamp) {
            Some(dt) => std::ops::Bound::Included(Term::from_field_date(
                self.fields.timestamp,
                tantivy::DateTime::from_timestamp_nanos(
                    dt.timestamp_nanos_opt().unwrap_or_default(),
                ),
            )),
            None => std::ops::Bound::Unbounded,
        };
        let upper = match to.and_then(parse_timestamp) {
            Some(dt) => std::ops::Bound::Included(Term::from_field_date(
                self.fields.timestamp,
                tantivy::DateTime::from_timestamp_nanos(
                    dt.timestamp_nanos_opt().unwrap_or_default(),
                ),
            )),
            None => std::ops::Bound::Unbounded,
        };
        let range = RangeQuery::new(lower, upper);
        Ok(Box::new(BooleanQuery::new(vec![
            (Occur::Must, base),
            (Occur::Must, Box::new(range)),
        ])))
    }

    /// Execute a hunt query using KQL-like syntax, compiled to Tantivy.
    /// Supports: field:value, field="exact", AND, OR, NOT, parentheses.
    /// Example: `process_name:mimikatz AND src_ip:10.0.0.*`
    pub fn hunt(&self, hunt_query: &str) -> Result<SearchResult, String> {
        let start = std::time::Instant::now();
        let predicate = parse_hunt_query(hunt_query)?;
        let compiled = compile_predicate(&predicate, &self.fields)?;
        let (total, hits) = self.run_query(compiled.as_ref(), 100, 0, true)?;
        Ok(SearchResult {
            total,
            hits,
            took_ms: start.elapsed().as_secs_f64() * 1000.0,
            query: hunt_query.into(),
        })
    }

    pub fn stats(&self) -> IndexStats {
        let stats = self
            .stats
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let index_size_bytes = match &self.disk_path {
            Some(dir) => dir_size_bytes(dir),
            None => self.doc_count.load(Ordering::Relaxed) * 512,
        };
        IndexStats {
            total_documents: self.doc_count.load(Ordering::Relaxed),
            index_size_bytes,
            last_commit: stats.last_commit,
            pending_docs: stats.pending_docs,
            schema_version: SEARCH_SCHEMA_VERSION,
            rebuilt: self.rebuilt.swap(false, Ordering::Relaxed),
        }
    }

    pub fn clear(&self) -> Result<(), String> {
        {
            let writer = self
                .writer
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            writer
                .delete_all_documents()
                .map_err(|e| format!("failed to clear search index: {e}"))?;
        }
        self.commit()?;
        Ok(())
    }

    /// Delete every document whose timestamp is strictly before `cutoff`.
    /// Returns the number of documents that matched (and were deleted).
    pub fn delete_before(&self, cutoff: DateTime<Utc>) -> Result<u64, String> {
        let term = Term::from_field_date(
            self.fields.timestamp,
            tantivy::DateTime::from_timestamp_nanos(
                cutoff.timestamp_nanos_opt().unwrap_or_default(),
            ),
        );
        let range: Box<dyn Query> = Box::new(RangeQuery::new(
            std::ops::Bound::Unbounded,
            std::ops::Bound::Excluded(term),
        ));
        let matched = self.count_query(range.as_ref())?;
        if matched == 0 {
            return Ok(0);
        }
        {
            let writer = self
                .writer
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            writer
                .delete_query(range)
                .map_err(|e| format!("failed to apply retention delete: {e}"))?;
        }
        self.commit()?;
        Ok(matched)
    }
}

// ── Hunt Query DSL Parser ────────────────────────────────────────────────────

/// Parsed hunt predicate tree.
#[derive(Debug, Clone)]
pub enum HuntPredicate {
    /// field:value (wildcard * supported)
    FieldMatch {
        field: String,
        pattern: String,
    },
    /// Full-text search
    FreeText(String),
    And(Box<HuntPredicate>, Box<HuntPredicate>),
    Or(Box<HuntPredicate>, Box<HuntPredicate>),
    Not(Box<HuntPredicate>),
}

/// Parse a KQL-like hunt query string into a predicate tree.
pub fn parse_hunt_query(input: &str) -> Result<HuntPredicate, String> {
    let tokens = tokenize_hunt(input)?;
    if tokens.is_empty() {
        return Err("empty query".into());
    }
    let (pred, rest) = parse_or(&tokens)?;
    if !rest.is_empty() {
        return Err(format!("unexpected tokens after query: {rest:?}"));
    }
    Ok(pred)
}

#[derive(Debug, Clone, PartialEq)]
enum HuntToken {
    Word(String),
    FieldValue(String, String),
    And,
    Or,
    Not,
    LParen,
    RParen,
}

fn tokenize_hunt(input: &str) -> Result<Vec<HuntToken>, String> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();

    while let Some(&c) = chars.peek() {
        if c.is_whitespace() {
            chars.next();
            continue;
        }
        if c == '(' {
            tokens.push(HuntToken::LParen);
            chars.next();
        } else if c == ')' {
            tokens.push(HuntToken::RParen);
            chars.next();
        } else if c == '"' {
            chars.next();
            let mut s = String::new();
            while let Some(&ch) = chars.peek() {
                if ch == '"' {
                    chars.next();
                    break;
                }
                s.push(ch);
                chars.next();
            }
            tokens.push(HuntToken::Word(s));
        } else {
            let mut word = String::new();
            while let Some(&ch) = chars.peek() {
                if ch.is_whitespace() || ch == '(' || ch == ')' {
                    break;
                }
                word.push(ch);
                chars.next();
            }
            match word.to_uppercase().as_str() {
                "AND" => tokens.push(HuntToken::And),
                "OR" => tokens.push(HuntToken::Or),
                "NOT" => tokens.push(HuntToken::Not),
                _ => {
                    if let Some((field, value)) = word.split_once(':') {
                        let value = value.trim_matches('"').trim_matches('\'');
                        tokens.push(HuntToken::FieldValue(field.to_string(), value.to_string()));
                    } else {
                        tokens.push(HuntToken::Word(word));
                    }
                }
            }
        }
    }
    Ok(tokens)
}

fn parse_or(tokens: &[HuntToken]) -> Result<(HuntPredicate, &[HuntToken]), String> {
    let (mut left, mut rest) = parse_and(tokens)?;
    while !rest.is_empty() && rest[0] == HuntToken::Or {
        let (right, r) = parse_and(&rest[1..])?;
        left = HuntPredicate::Or(Box::new(left), Box::new(right));
        rest = r;
    }
    Ok((left, rest))
}

fn parse_and(tokens: &[HuntToken]) -> Result<(HuntPredicate, &[HuntToken]), String> {
    let (mut left, mut rest) = parse_unary(tokens)?;
    while !rest.is_empty()
        && (rest[0] == HuntToken::And
            || matches!(
                rest[0],
                HuntToken::Word(_)
                    | HuntToken::FieldValue(_, _)
                    | HuntToken::Not
                    | HuntToken::LParen
            ))
    {
        if rest[0] == HuntToken::And {
            let (right, r) = parse_unary(&rest[1..])?;
            left = HuntPredicate::And(Box::new(left), Box::new(right));
            rest = r;
        } else {
            // Implicit AND
            let (right, r) = parse_unary(rest)?;
            left = HuntPredicate::And(Box::new(left), Box::new(right));
            rest = r;
        }
    }
    Ok((left, rest))
}

fn parse_unary(tokens: &[HuntToken]) -> Result<(HuntPredicate, &[HuntToken]), String> {
    if tokens.is_empty() {
        return Err("unexpected end of query".into());
    }
    if tokens[0] == HuntToken::Not {
        let (inner, rest) = parse_unary(&tokens[1..])?;
        return Ok((HuntPredicate::Not(Box::new(inner)), rest));
    }
    parse_primary(tokens)
}

fn parse_primary(tokens: &[HuntToken]) -> Result<(HuntPredicate, &[HuntToken]), String> {
    if tokens.is_empty() {
        return Err("unexpected end of query".into());
    }
    match &tokens[0] {
        HuntToken::LParen => {
            let (inner, rest) = parse_or(&tokens[1..])?;
            if rest.is_empty() || rest[0] != HuntToken::RParen {
                return Err("missing closing parenthesis".into());
            }
            Ok((inner, &rest[1..]))
        }
        HuntToken::FieldValue(field, value) => Ok((
            HuntPredicate::FieldMatch {
                field: field.clone(),
                pattern: value.clone(),
            },
            &tokens[1..],
        )),
        HuntToken::Word(w) => Ok((HuntPredicate::FreeText(w.clone()), &tokens[1..])),
        other => Err(format!("unexpected token: {other:?}")),
    }
}

// ── Glob/substring pattern → regex compilation ──────────────────────────────
//
// Mirrors the semantics of the original hand-rolled `wildcard_match`: a
// pattern with no `*` is a case-insensitive substring match; a pattern with
// `*` is anchored at either end unless that end is itself a `*`.

fn regex_escape_char(c: char, out: &mut String) {
    if matches!(
        c,
        '.' | '^' | '$' | '|' | '(' | ')' | '[' | ']' | '{' | '}' | '*' | '+' | '?' | '\\'
    ) {
        out.push('\\');
    }
    out.push(c);
}

fn regex_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        regex_escape_char(c, &mut out);
    }
    out
}

/// Compile a glob/substring DSL pattern into a Tantivy `RegexQuery` pattern.
///
/// Two things make this different from writing an ordinary Rust regex:
///
/// - Tantivy's regex engine (`tantivy-fst`, an automaton built for FST
///   intersection) matches a pattern against a whole term at once — it has
///   no "search anywhere in the string" mode — so this never emits `^`/`$`
///   anchors; a pattern like `10\.0\..*` already only matches terms that
///   *start* with `10.0.` because matching starts at position 0 and must
///   consume the entire term. Anchors aren't just redundant here, they're
///   actively rejected (`Error::NoEmpty`, "empty match operators are not
///   allowed") since `^`/`$` are zero-width assertions this engine doesn't
///   support at all.
/// - It also rejects the `(?i)` inline case-insensitive flag, so case
///   folding happens by lowercasing the pattern here and matching it
///   against the pre-lowercased `_lc` companion fields (see the module
///   docs) instead of via a regex flag.
fn glob_to_regex(pattern: &str) -> String {
    let pattern = pattern.to_lowercase();
    if !pattern.contains('*') {
        return format!(".*{}.*", regex_escape(&pattern));
    }
    let mut body = String::new();
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '*' {
            while chars.peek() == Some(&'*') {
                chars.next();
            }
            body.push_str(".*");
        } else {
            regex_escape_char(c, &mut body);
        }
    }
    body
}

/// Resolve a DSL field alias to the schema field used for substring/wildcard
/// matching (the untokenized, lowercased `_lc` copy of that field).
fn kw_field(alias: &str, f: &SearchFields) -> Option<Field> {
    match alias {
        "timestamp" => Some(f.timestamp_lc),
        "device_id" | "device" => Some(f.device_id_lc),
        "event_class" | "class" => Some(f.event_class_lc),
        "process_name" | "process" => Some(f.process_name_lc),
        "command_line" | "cmd" => Some(f.command_line_lc),
        "src_ip" | "src" => Some(f.src_ip_lc),
        "dst_ip" | "dst" => Some(f.dst_ip_lc),
        "user_name" | "user" => Some(f.user_name_lc),
        "raw_text" | "raw" => Some(f.raw_text_lc),
        _ => None,
    }
}

/// The set of fields a bare free-text term is matched against — mirrors the
/// original `evaluate_predicate`'s `FreeText` handling exactly (device_id,
/// process_name, command_line, src_ip, dst_ip, user_name, raw_text; note
/// `event_class` is intentionally excluded, matching legacy behaviour).
fn free_text_fields(f: &SearchFields) -> [Field; 7] {
    [
        f.device_id_lc,
        f.process_name_lc,
        f.command_line_lc,
        f.src_ip_lc,
        f.dst_ip_lc,
        f.user_name_lc,
        f.raw_text_lc,
    ]
}

fn compile_field_match(
    field: &str,
    pattern: &str,
    f: &SearchFields,
) -> Result<Box<dyn Query>, String> {
    match kw_field(field, f) {
        Some(fld) => {
            let regex = glob_to_regex(pattern);
            let q = RegexQuery::from_pattern(&regex, fld)
                .map_err(|e| format!("invalid pattern {pattern:?}: {e}"))?;
            Ok(Box::new(q))
        }
        None => {
            if pattern == "*" {
                Ok(Box::new(AllQuery))
            } else {
                Ok(Box::new(EmptyQuery))
            }
        }
    }
}

fn compile_free_text(text: &str, f: &SearchFields) -> Result<Box<dyn Query>, String> {
    if text.is_empty() {
        return Ok(Box::new(AllQuery));
    }
    let regex = glob_to_regex(text);
    let mut clauses: Vec<(Occur, Box<dyn Query>)> = Vec::new();
    for fld in free_text_fields(f) {
        let q = RegexQuery::from_pattern(&regex, fld)
            .map_err(|e| format!("invalid query {text:?}: {e}"))?;
        clauses.push((Occur::Should, Box::new(q)));
    }
    Ok(Box::new(BooleanQuery::new(clauses)))
}

/// Compile a parsed hunt predicate tree into a native Tantivy query. Every
/// variant of [`HuntPredicate`] has a direct Tantivy equivalent today (see
/// the module-level docs for the full mapping and the documented
/// aggregation-only fallback).
fn compile_predicate(pred: &HuntPredicate, f: &SearchFields) -> Result<Box<dyn Query>, String> {
    match pred {
        HuntPredicate::FieldMatch { field, pattern } => compile_field_match(field, pattern, f),
        HuntPredicate::FreeText(text) => compile_free_text(text, f),
        HuntPredicate::And(a, b) => Ok(Box::new(BooleanQuery::new(vec![
            (Occur::Must, compile_predicate(a, f)?),
            (Occur::Must, compile_predicate(b, f)?),
        ]))),
        HuntPredicate::Or(a, b) => Ok(Box::new(BooleanQuery::new(vec![
            (Occur::Should, compile_predicate(a, f)?),
            (Occur::Should, compile_predicate(b, f)?),
        ]))),
        HuntPredicate::Not(inner) => Ok(Box::new(BooleanQuery::new(vec![
            (Occur::Must, Box::new(AllQuery)),
            (Occur::MustNot, compile_predicate(inner, f)?),
        ]))),
    }
}

fn parse_timestamp(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .ok()
}

// ── Linear evaluator (aggregation fallback) ─────────────────────────────────
//
// Tantivy has no generic group-by/min/max/distinct collector over arbitrary
// stored string fields, so `hunt_aggregate` narrows the corpus with a
// compiled Tantivy query (see above) and then buckets the bounded result
// set with this linear evaluator — the same logic the whole engine used to
// run over every document, now only run over the documents that already
// matched the filter.

#[derive(Debug, Clone)]
struct LinearDoc {
    timestamp: String,
    device_id: String,
    event_class: String,
    process_name: String,
    command_line: String,
    src_ip: String,
    dst_ip: String,
    user_name: String,
    raw_text: String,
}

fn field_value(doc: &LinearDoc, field: &str) -> String {
    match field {
        "timestamp" => doc.timestamp.clone(),
        "device_id" | "device" => doc.device_id.clone(),
        "event_class" | "class" => doc.event_class.clone(),
        "process_name" | "process" => doc.process_name.clone(),
        "command_line" | "cmd" => doc.command_line.clone(),
        "src_ip" | "src" => doc.src_ip.clone(),
        "dst_ip" | "dst" => doc.dst_ip.clone(),
        "user_name" | "user" => doc.user_name.clone(),
        "raw_text" | "raw" => doc.raw_text.clone(),
        _ => String::new(),
    }
}

// ── Persistent Event Store ───────────────────────────────────────────────────
//
// Disk-backed, mmap'd Tantivy event store with retention deletion and
// rebuild-from-source-of-truth for recovery.

/// Configuration for the persistent event store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventStoreConfig {
    #[serde(default = "default_index_path")]
    pub index_path: String,
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
    #[serde(default = "default_commit_interval")]
    pub commit_interval_secs: u64,
    #[serde(default = "default_memory_budget")]
    pub memory_budget_mb: usize,
    #[serde(default)]
    pub compress_old_segments: bool,
}

fn default_index_path() -> String {
    "var/search_index".into()
}
fn default_retention_days() -> u32 {
    90
}
fn default_commit_interval() -> u64 {
    30
}
fn default_memory_budget() -> usize {
    64
}

impl Default for EventStoreConfig {
    fn default() -> Self {
        Self {
            index_path: default_index_path(),
            retention_days: default_retention_days(),
            commit_interval_secs: default_commit_interval(),
            memory_budget_mb: default_memory_budget(),
            compress_old_segments: false,
        }
    }
}

/// Persistent event store backed by Tantivy for durable full-text search.
///
/// Concurrency: there is a single writer (guarded internally by a mutex in
/// [`SearchIndex`]); reads never take that lock and are served from a
/// shared, explicitly-reloaded reader. Commits are triggered either
/// explicitly (`commit`) or opportunistically by `maybe_commit`, which
/// callers should invoke after ingest — it is a no-op unless
/// `commit_interval_secs` has elapsed or enough documents are pending, so it
/// never blocks a request handler on a full commit unless one is actually
/// due.
pub struct PersistentEventStore {
    config: EventStoreConfig,
    index: SearchIndex,
    ingest_count: Arc<AtomicU64>,
    last_commit_at: Arc<Mutex<std::time::Instant>>,
    pending_since_commit: Arc<AtomicU64>,
}

impl std::fmt::Debug for PersistentEventStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PersistentEventStore")
            .field("config", &self.config)
            .finish()
    }
}

impl PersistentEventStore {
    /// Create or open a persistent event store. `seed_events` is only used
    /// to repopulate the index if it had to be rebuilt from scratch because
    /// it was missing, corrupt, or at an old schema version — a healthy
    /// reopen trusts the data already on disk and does not re-index
    /// anything.
    pub fn open(
        config: EventStoreConfig,
        seed_events: &[HashMap<String, String>],
    ) -> Result<Self, String> {
        let memory_budget_bytes = config.memory_budget_mb.max(16) * 1024 * 1024;
        let (index, rebuilt) =
            SearchIndex::open_on_disk(Path::new(&config.index_path), memory_budget_bytes)?;
        let store = Self {
            config,
            index,
            ingest_count: Arc::new(AtomicU64::new(0)),
            last_commit_at: Arc::new(Mutex::new(std::time::Instant::now())),
            pending_since_commit: Arc::new(AtomicU64::new(0)),
        };
        if rebuilt && !seed_events.is_empty() {
            log::info!(
                "search index rebuild triggered: reindexing {} events from source of truth",
                seed_events.len()
            );
            store.rebuild_from(seed_events)?;
        }
        Ok(store)
    }

    /// Ingest a batch of events into the store. Does not commit — call
    /// `maybe_commit` (or `commit`) afterwards to make them searchable.
    pub fn ingest(&self, events: &[HashMap<String, String>]) -> Result<usize, String> {
        let mut count = 0;
        for event in events {
            self.index.index_event(event.clone())?;
            count += 1;
        }
        self.ingest_count.fetch_add(count as u64, Ordering::Relaxed);
        self.pending_since_commit
            .fetch_add(count as u64, Ordering::Relaxed);
        Ok(count)
    }

    /// Commit pending writes to disk unconditionally.
    pub fn commit(&self) -> Result<u64, String> {
        let total = self.index.commit()?;
        self.pending_since_commit.store(0, Ordering::Relaxed);
        *self
            .last_commit_at
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = std::time::Instant::now();
        Ok(total)
    }

    /// Commit only if `commit_interval_secs` has elapsed since the last
    /// commit, or a large batch is pending. Safe (and cheap) to call after
    /// every ingest from a request handler.
    pub fn maybe_commit(&self) -> Result<Option<u64>, String> {
        const MAX_PENDING_BEFORE_FORCED_COMMIT: u64 = 5_000;
        let due = {
            let last = *self
                .last_commit_at
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            last.elapsed().as_secs() >= self.config.commit_interval_secs
        };
        let pending = self.pending_since_commit.load(Ordering::Relaxed);
        if pending == 0 {
            return Ok(None);
        }
        if due || pending >= MAX_PENDING_BEFORE_FORCED_COMMIT {
            Ok(Some(self.commit()?))
        } else {
            Ok(None)
        }
    }

    /// Search events in the store.
    pub fn search(&self, query: &SearchQuery) -> Result<SearchResult, String> {
        self.index.search(query)
    }

    /// Hunt with KQL-like syntax.
    pub fn hunt(&self, query: &str) -> Result<SearchResult, String> {
        self.index.hunt(query)
    }

    /// Hunt with optional pipe aggregation.
    pub fn hunt_aggregate(&self, query: &str) -> Result<HuntAggregationResult, String> {
        self.index.hunt_aggregate(query)
    }

    /// Apply the configured (day-based) retention policy, removing events
    /// older than `retention_days`. Returns the number of documents
    /// deleted.
    pub fn apply_retention(&self) -> Result<u64, String> {
        let cutoff = Utc::now() - Duration::days(i64::from(self.config.retention_days));
        self.index.delete_before(cutoff)
    }

    /// Delete every event older than an externally supplied cutoff — used
    /// to keep the index in sync when the primary event store is trimmed by
    /// record count rather than age.
    pub fn delete_before(&self, cutoff: DateTime<Utc>) -> Result<u64, String> {
        self.index.delete_before(cutoff)
    }

    /// Rebuild the entire index from a fresh source-of-truth snapshot
    /// (e.g. the SQLite-backed event store). Clears the index, re-indexes
    /// every supplied event, and commits.
    pub fn rebuild_from(&self, events: &[HashMap<String, String>]) -> Result<u64, String> {
        self.index.clear()?;
        for event in events {
            self.index.index_event(event.clone())?;
        }
        self.commit()
    }

    /// Get store statistics.
    pub fn stats(&self) -> EventStoreStats {
        let idx_stats = self.index.stats();
        EventStoreStats {
            total_events: idx_stats.total_documents,
            index_size_bytes: idx_stats.index_size_bytes,
            ingest_count: self.ingest_count.load(Ordering::Relaxed),
            last_commit: idx_stats.last_commit,
            retention_days: self.config.retention_days,
            index_path: self.config.index_path.clone(),
            pending_docs: idx_stats.pending_docs,
            schema_version: idx_stats.schema_version,
            rebuilt: idx_stats.rebuilt,
        }
    }
}

/// Statistics for the persistent event store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventStoreStats {
    pub total_events: u64,
    pub index_size_bytes: u64,
    pub ingest_count: u64,
    pub last_commit: Option<DateTime<Utc>>,
    pub retention_days: u32,
    pub index_path: String,
    pub pending_docs: u64,
    pub schema_version: u32,
    pub rebuilt: bool,
}

/// Read the on-disk metadata sidecar for a search index without opening the
/// (possibly locked-by-the-running-server) Tantivy index itself. Used by
/// `wardex doctor` / status tooling.
pub fn read_index_meta(index_path: &str) -> Option<EventStoreStats> {
    let dir = Path::new(index_path);
    let meta = read_meta(&dir.join(META_FILE))?;
    Some(EventStoreStats {
        total_events: meta.doc_count,
        index_size_bytes: meta.index_size_bytes,
        ingest_count: meta.doc_count,
        last_commit: meta.last_commit,
        retention_days: default_retention_days(),
        index_path: index_path.to_string(),
        pending_docs: 0,
        schema_version: meta.schema_version,
        rebuilt: false,
    })
}

// ── Hunt Aggregation DSL ─────────────────────────────────────────────────────

/// Aggregation functions supported in the hunt DSL via pipe operator.
/// Example: `process_name:mimikatz | count by device_id`
/// Example: `severity:critical | count_distinct user_name`
/// Example: `src_ip:10.* | top 5 dst_ip`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HuntAggregation {
    Count { group_by: Option<String> },
    CountDistinct { field: String },
    Top { n: usize, field: String },
    Min { field: String },
    Max { field: String },
    Values { field: String },
}

/// Result of a hunt aggregation query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntAggregationResult {
    pub query: String,
    pub aggregation: String,
    pub total_matching: u64,
    pub buckets: Vec<HuntAggBucket>,
    pub scalar: Option<String>,
    pub took_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HuntAggBucket {
    pub key: String,
    pub count: u64,
}

/// Parse a pipe-separated aggregation from a hunt query.
/// Returns (filter_part, aggregation) if a pipe is found.
fn parse_hunt_pipe(input: &str) -> Result<(String, Option<HuntAggregation>), String> {
    if let Some(idx) = input.find('|') {
        let filter = input[..idx].trim().to_string();
        let agg_part = input[idx + 1..].trim();
        if agg_part.is_empty() {
            return Err("missing aggregation after pipe".into());
        }
        let tokens: Vec<String> = agg_part.split_whitespace().map(str::to_lowercase).collect();

        let agg = match tokens.first().map(String::as_str) {
            Some("count") => {
                if tokens.len() >= 3 && tokens[1] == "by" {
                    Some(HuntAggregation::Count {
                        group_by: Some(tokens[2].clone()),
                    })
                } else if tokens.len() == 1 {
                    Some(HuntAggregation::Count { group_by: None })
                } else {
                    return Err("count only supports `count` or `count by <field>`".into());
                }
            }
            Some("count_distinct") => match tokens.get(1) {
                Some(field) => Some(HuntAggregation::CountDistinct {
                    field: field.clone(),
                }),
                None => return Err("count_distinct requires a field".into()),
            },
            Some("top") => {
                if tokens.len() >= 3 {
                    let n = tokens[1]
                        .parse::<usize>()
                        .map_err(|_| "top requires a numeric limit".to_string())?;
                    Some(HuntAggregation::Top {
                        n,
                        field: tokens[2].clone(),
                    })
                } else {
                    return Err("top requires `top <n> <field>`".into());
                }
            }
            Some("min") => match tokens.get(1) {
                Some(field) => Some(HuntAggregation::Min {
                    field: field.clone(),
                }),
                None => return Err("min requires a field".into()),
            },
            Some("max") => match tokens.get(1) {
                Some(field) => Some(HuntAggregation::Max {
                    field: field.clone(),
                }),
                None => return Err("max requires a field".into()),
            },
            Some("values") => match tokens.get(1) {
                Some(field) => Some(HuntAggregation::Values {
                    field: field.clone(),
                }),
                None => return Err("values requires a field".into()),
            },
            Some(_) => return Err(format!("unsupported aggregation: {agg_part}")),
            None => return Err("missing aggregation after pipe".into()),
        };
        Ok((filter, agg))
    } else {
        Ok((input.to_string(), None))
    }
}

impl SearchIndex {
    /// Execute a hunt query with optional pipe aggregation.
    /// Supports: `process_name:mimikatz | count by device_id`
    ///
    /// The filter half of the query is compiled to a native Tantivy query
    /// and used to narrow the corpus (see the module docs); the
    /// aggregation itself runs over that bounded candidate set using the
    /// linear evaluator, since Tantivy has no generic group-by collector
    /// for arbitrary stored string fields.
    pub fn hunt_aggregate(&self, input: &str) -> Result<HuntAggregationResult, String> {
        let start = std::time::Instant::now();
        let (filter_part, aggregation) = parse_hunt_pipe(input)?;

        let compiled: Box<dyn Query> = if filter_part.is_empty() || filter_part == "*" {
            Box::new(AllQuery)
        } else {
            let predicate = parse_hunt_query(&filter_part)?;
            compile_predicate(&predicate, &self.fields)?
        };

        let total_matching = self.count_query(compiled.as_ref())?;
        let matching = self.fetch_recent(compiled.as_ref(), AGG_SCAN_LIMIT)?;

        let agg = match aggregation {
            Some(ref a) => a.clone(),
            None => HuntAggregation::Count { group_by: None },
        };

        let (buckets, scalar) = match &agg {
            HuntAggregation::Count { group_by: None } => (vec![], Some(total_matching.to_string())),
            HuntAggregation::Count {
                group_by: Some(field),
            } => {
                let mut groups: HashMap<String, u64> = HashMap::new();
                for doc in &matching {
                    let key = field_value(doc, field);
                    *groups
                        .entry(if key.is_empty() {
                            "(empty)".into()
                        } else {
                            key
                        })
                        .or_insert(0) += 1;
                }
                let mut buckets: Vec<HuntAggBucket> = groups
                    .into_iter()
                    .map(|(key, count)| HuntAggBucket { key, count })
                    .collect();
                buckets.sort_by_key(|b| std::cmp::Reverse(b.count));
                (buckets, None)
            }
            HuntAggregation::CountDistinct { field } => {
                let unique: std::collections::HashSet<String> = matching
                    .iter()
                    .map(|d| field_value(d, field))
                    .filter(|v| !v.is_empty())
                    .collect();
                (vec![], Some(unique.len().to_string()))
            }
            HuntAggregation::Top { n, field } => {
                let mut groups: HashMap<String, u64> = HashMap::new();
                for doc in &matching {
                    let key = field_value(doc, field);
                    if !key.is_empty() {
                        *groups.entry(key).or_insert(0) += 1;
                    }
                }
                let mut buckets: Vec<HuntAggBucket> = groups
                    .into_iter()
                    .map(|(key, count)| HuntAggBucket { key, count })
                    .collect();
                buckets.sort_by_key(|b| std::cmp::Reverse(b.count));
                buckets.truncate(*n);
                (buckets, None)
            }
            HuntAggregation::Min { field } => {
                let val = matching
                    .iter()
                    .map(|d| field_value(d, field))
                    .filter(|v| !v.is_empty())
                    .min();
                (vec![], val)
            }
            HuntAggregation::Max { field } => {
                let val = matching
                    .iter()
                    .map(|d| field_value(d, field))
                    .filter(|v| !v.is_empty())
                    .max();
                (vec![], val)
            }
            HuntAggregation::Values { field } => {
                let unique: std::collections::HashSet<String> = matching
                    .iter()
                    .map(|d| field_value(d, field))
                    .filter(|v| !v.is_empty())
                    .collect();
                let buckets: Vec<HuntAggBucket> = unique
                    .into_iter()
                    .map(|key| HuntAggBucket { key, count: 1 })
                    .collect();
                (buckets, None)
            }
        };

        let agg_desc = match &agg {
            HuntAggregation::Count { group_by: Some(f) } => format!("count by {f}"),
            HuntAggregation::Count { group_by: None } => "count".into(),
            HuntAggregation::CountDistinct { field } => format!("count_distinct {field}"),
            HuntAggregation::Top { n, field } => format!("top {n} {field}"),
            HuntAggregation::Min { field } => format!("min {field}"),
            HuntAggregation::Max { field } => format!("max {field}"),
            HuntAggregation::Values { field } => format!("values {field}"),
        };

        Ok(HuntAggregationResult {
            query: input.into(),
            aggregation: agg_desc,
            total_matching,
            buckets,
            scalar,
            took_ms: start.elapsed().as_secs_f64() * 1000.0,
        })
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_index() -> SearchIndex {
        let idx = SearchIndex::in_memory().unwrap();
        let mut fields = HashMap::new();
        fields.insert("timestamp".into(), "2026-04-05T12:00:00Z".into());
        fields.insert("device_id".into(), "srv-01".into());
        fields.insert("process_name".into(), "mimikatz.exe".into());
        fields.insert(
            "command_line".into(),
            "mimikatz.exe sekurlsa::logonpasswords".into(),
        );
        fields.insert("src_ip".into(), "10.0.0.5".into());
        fields.insert("dst_ip".into(), "10.0.0.1".into());
        fields.insert("user_name".into(), "admin".into());
        fields.insert(
            "raw_text".into(),
            "Credential dumping detected: mimikatz".into(),
        );
        idx.index_event(fields).unwrap();

        let mut fields2 = HashMap::new();
        fields2.insert("timestamp".into(), "2026-04-05T12:05:00Z".into());
        fields2.insert("process_name".into(), "svchost.exe".into());
        fields2.insert("raw_text".into(), "Normal system process activity".into());
        fields2.insert("src_ip".into(), "192.168.1.1".into());
        idx.index_event(fields2).unwrap();
        idx.commit().unwrap();
        idx
    }

    fn q(query: &str) -> SearchQuery {
        SearchQuery {
            query: query.into(),
            fields: vec![],
            from: None,
            to: None,
            limit: 10,
            offset: 0,
            sort_by: None,
            sort_desc: false,
        }
    }

    #[test]
    fn test_search_basic() {
        let idx = make_index();
        let r = idx.search(&q("mimikatz")).unwrap();
        assert_eq!(r.total, 1);
        assert_eq!(r.hits[0].process_name, "mimikatz.exe");
    }

    #[test]
    fn test_search_ip() {
        let idx = make_index();
        let r = idx.search(&q("10.0.0.5")).unwrap();
        assert_eq!(r.total, 1);
    }

    #[test]
    fn test_search_no_results() {
        let idx = make_index();
        let r = idx.search(&q("nonexistent_process")).unwrap();
        assert_eq!(r.total, 0);
    }

    #[test]
    fn test_search_pagination() {
        let idx = make_index();
        let mut query = q("");
        query.limit = 1;
        let r = idx.search(&query).unwrap();
        // empty string matches everything (AllQuery)
        assert!(r.total >= 1);
        assert_eq!(r.hits.len(), 1);
    }

    #[test]
    fn test_search_offset() {
        let idx = make_index();
        let mut query = q("");
        query.limit = 1;
        query.offset = 1;
        let r = idx.search(&query).unwrap();
        assert_eq!(r.total, 2);
        assert_eq!(r.hits.len(), 1);
    }

    #[test]
    fn test_stats() {
        let idx = make_index();
        let s = idx.stats();
        assert_eq!(s.total_documents, 2);
        assert!(s.last_commit.is_some());
        assert_eq!(s.schema_version, SEARCH_SCHEMA_VERSION);
    }

    #[test]
    fn test_clear() {
        let idx = make_index();
        idx.clear().unwrap();
        let s = idx.stats();
        assert_eq!(s.total_documents, 0);
    }

    #[test]
    fn test_case_insensitive_search() {
        let idx = make_index();
        let r = idx.search(&q("MIMIKATZ")).unwrap();
        assert_eq!(r.total, 1);
    }

    #[test]
    fn test_hunt_field_match() {
        let idx = make_index();
        let r = idx.hunt("process_name:mimikatz").unwrap();
        assert_eq!(r.total, 1);
    }

    #[test]
    fn test_hunt_wildcard() {
        let idx = make_index();
        let r = idx.hunt("src_ip:10.0.*").unwrap();
        assert_eq!(r.total, 1);
    }

    #[test]
    fn test_hunt_and() {
        let idx = make_index();
        let r = idx.hunt("process:mimikatz AND src:10.0.0.5").unwrap();
        assert_eq!(r.total, 1);
    }

    #[test]
    fn test_hunt_or() {
        let idx = make_index();
        let r = idx.hunt("process:mimikatz OR process:svchost").unwrap();
        assert_eq!(r.total, 2);
    }

    #[test]
    fn test_hunt_not() {
        let idx = make_index();
        let r = idx.hunt("NOT process:svchost").unwrap();
        assert_eq!(r.total, 1);
        assert_eq!(r.hits[0].process_name, "mimikatz.exe");
    }

    #[test]
    fn test_hunt_free_text() {
        let idx = make_index();
        let r = idx.hunt("credential").unwrap();
        assert_eq!(r.total, 1);
    }

    #[test]
    fn test_hunt_implicit_and() {
        let idx = make_index();
        let r = idx.hunt("process:mimikatz user:admin").unwrap();
        assert_eq!(r.total, 1);
    }

    #[test]
    fn test_hunt_unknown_field() {
        let idx = make_index();
        assert_eq!(idx.hunt("bogus_field:*").unwrap().total, 2);
        assert_eq!(idx.hunt("bogus_field:anything").unwrap().total, 0);
    }

    // `glob_to_regex` itself is exercised end-to-end (compiled into a real
    // Tantivy `RegexQuery` and executed against the index) by
    // `test_hunt_wildcard`, `test_hunt_field_match`, `test_case_insensitive_search`
    // and friends above, rather than by a standalone unit test against a
    // hand-rolled regex simulator — the actual matching engine is
    // `tantivy-fst`, and a from-scratch reimplementation of it here would
    // risk diverging from its real (restricted) syntax semantics instead of
    // catching a mismatch.

    #[test]
    fn test_hunt_aggregate_count() {
        let idx = make_index();
        let r = idx.hunt_aggregate("* | count").unwrap();
        assert_eq!(r.total_matching, 2);
        assert_eq!(r.scalar.as_deref(), Some("2"));
    }

    #[test]
    fn test_hunt_aggregate_count_by() {
        let idx = make_index();
        let r = idx.hunt_aggregate("* | count by device_id").unwrap();
        assert_eq!(r.total_matching, 2);
        assert!(!r.buckets.is_empty());
    }

    #[test]
    fn test_hunt_aggregate_count_distinct() {
        let idx = make_index();
        let r = idx
            .hunt_aggregate("* | count_distinct process_name")
            .unwrap();
        assert_eq!(r.scalar.as_deref(), Some("2"));
    }

    #[test]
    fn test_hunt_aggregate_top() {
        let idx = make_index();
        let r = idx.hunt_aggregate("* | top 5 src_ip").unwrap();
        assert!(r.buckets.len() <= 5);
    }

    #[test]
    fn test_hunt_pipe_with_filter() {
        let idx = make_index();
        let r = idx
            .hunt_aggregate("process:mimikatz | count by src_ip")
            .unwrap();
        assert_eq!(r.total_matching, 1);
        assert_eq!(r.buckets.len(), 1);
    }

    #[test]
    fn test_hunt_aggregate_rejects_unknown_pipe() {
        let idx = make_index();
        let err = idx.hunt_aggregate("* | nonsense").unwrap_err();
        assert!(err.contains("unsupported aggregation"));
    }

    #[test]
    fn test_hunt_aggregate_rejects_incomplete_pipe() {
        let idx = make_index();
        let err = idx.hunt_aggregate("* | count by").unwrap_err();
        assert!(err.contains("count only supports"));
    }

    #[test]
    fn test_persistent_store_ingest_search_commit() {
        let dir = std::env::temp_dir().join(format!("wardex_search_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config = EventStoreConfig {
            index_path: dir.to_string_lossy().to_string(),
            ..Default::default()
        };
        let store = PersistentEventStore::open(config, &[]).unwrap();
        let mut fields = HashMap::new();
        fields.insert("timestamp".into(), Utc::now().to_rfc3339());
        fields.insert("process_name".into(), "lsass.exe".into());
        fields.insert("raw_text".into(), "process dump detected".into());
        store.ingest(&[fields]).unwrap();
        store.commit().unwrap();

        let r = store.hunt("process:lsass").unwrap();
        assert_eq!(r.total, 1);

        let stats = store.stats();
        assert_eq!(stats.total_events, 1);
        assert!(stats.last_commit.is_some());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_persistent_store_retention_deletes_old_events() {
        let dir =
            std::env::temp_dir().join(format!("wardex_search_retention_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config = EventStoreConfig {
            index_path: dir.to_string_lossy().to_string(),
            retention_days: 1,
            ..Default::default()
        };
        let store = PersistentEventStore::open(config, &[]).unwrap();

        let mut old = HashMap::new();
        old.insert(
            "timestamp".into(),
            (Utc::now() - Duration::days(5)).to_rfc3339(),
        );
        old.insert("process_name".into(), "old.exe".into());
        let mut recent = HashMap::new();
        recent.insert("timestamp".into(), Utc::now().to_rfc3339());
        recent.insert("process_name".into(), "recent.exe".into());
        store.ingest(&[old, recent]).unwrap();
        store.commit().unwrap();
        assert_eq!(store.stats().total_events, 2);

        let deleted = store.apply_retention().unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(store.stats().total_events, 1);
        let r = store.hunt("process:recent").unwrap();
        assert_eq!(r.total, 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_persistent_store_rebuild() {
        let dir =
            std::env::temp_dir().join(format!("wardex_search_rebuild_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config = EventStoreConfig {
            index_path: dir.to_string_lossy().to_string(),
            ..Default::default()
        };
        let store = PersistentEventStore::open(config.clone(), &[]).unwrap();
        let mut fields = HashMap::new();
        fields.insert("process_name".into(), "stale.exe".into());
        store.ingest(&[fields]).unwrap();
        store.commit().unwrap();
        assert_eq!(store.stats().total_events, 1);

        let mut fresh = HashMap::new();
        fresh.insert("process_name".into(), "fresh.exe".into());
        let total = store.rebuild_from(&[fresh]).unwrap();
        assert_eq!(total, 1);
        assert_eq!(store.hunt("process:stale").unwrap().total, 0);
        assert_eq!(store.hunt("process:fresh").unwrap().total, 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_schema_version_mismatch_triggers_rebuild() {
        let dir = std::env::temp_dir().join(format!("wardex_search_schema_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Simulate a stale metadata file from a previous schema version.
        std::fs::write(
            dir.join(META_FILE),
            r#"{"schema_version":0,"doc_count":0,"index_size_bytes":0,"last_commit":null}"#,
        )
        .unwrap();
        let config = EventStoreConfig {
            index_path: dir.to_string_lossy().to_string(),
            ..Default::default()
        };
        let mut seed = HashMap::new();
        seed.insert("process_name".into(), "seeded.exe".into());
        let store = PersistentEventStore::open(config, &[seed]).unwrap();
        // The stale-version index should have been rebuilt and the seed
        // event reindexed.
        assert_eq!(store.hunt("process:seeded").unwrap().total, 1);
        assert_eq!(store.stats().schema_version, SEARCH_SCHEMA_VERSION);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_corrupt_index_triggers_rebuild() {
        let dir =
            std::env::temp_dir().join(format!("wardex_search_corrupt_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("meta.json"), b"not valid tantivy metadata").unwrap();
        let config = EventStoreConfig {
            index_path: dir.to_string_lossy().to_string(),
            ..Default::default()
        };
        let mut seed = HashMap::new();
        seed.insert("process_name".into(), "healed.exe".into());
        let store = PersistentEventStore::open(config, &[seed]).unwrap();
        assert_eq!(store.hunt("process:healed").unwrap().total, 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_concurrency_smoke() {
        let dir =
            std::env::temp_dir().join(format!("wardex_search_concurrency_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config = EventStoreConfig {
            index_path: dir.to_string_lossy().to_string(),
            ..Default::default()
        };
        let store = Arc::new(PersistentEventStore::open(config, &[]).unwrap());

        let mut handles = Vec::new();
        for t in 0..4 {
            let store = Arc::clone(&store);
            handles.push(std::thread::spawn(move || {
                for i in 0..25 {
                    let mut fields = HashMap::new();
                    fields.insert("timestamp".into(), Utc::now().to_rfc3339());
                    fields.insert("process_name".into(), format!("proc-{t}-{i}"));
                    store.ingest(&[fields]).unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        store.commit().unwrap();
        assert_eq!(store.stats().total_events, 100);
        let r = store.hunt("process:proc-2-*").unwrap();
        assert_eq!(r.total, 25);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_read_index_meta_from_sidecar() {
        let dir = std::env::temp_dir().join(format!("wardex_search_meta_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config = EventStoreConfig {
            index_path: dir.to_string_lossy().to_string(),
            ..Default::default()
        };
        let store = PersistentEventStore::open(config, &[]).unwrap();
        let mut fields = HashMap::new();
        fields.insert("process_name".into(), "meta-test.exe".into());
        store.ingest(&[fields]).unwrap();
        store.commit().unwrap();

        let meta = read_index_meta(&dir.to_string_lossy()).expect("meta sidecar should exist");
        assert_eq!(meta.total_events, 1);
        assert_eq!(meta.schema_version, SEARCH_SCHEMA_VERSION);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
