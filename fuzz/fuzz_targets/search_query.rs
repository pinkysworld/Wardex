#![no_main]
use libfuzzer_sys::fuzz_target;
use wardex::search::SearchQuery;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // `in_memory()` always creates a throwaway, never-persisted index
        // (see `SearchIndex::in_memory`), so this never touches disk.
        let idx = wardex::search::SearchIndex::in_memory().ok();
        if let Some(idx) = idx {
            let query = SearchQuery {
                query: s.to_string(),
                fields: vec![],
                from: None,
                to: None,
                limit: 10,
                offset: 0,
                sort_by: None,
                sort_desc: false,
            };
            // Free-text search compiles `s` into a regex-based Tantivy
            // query (see `glob_to_regex`/`compile_free_text`); this
            // exercises that compiler against arbitrary, possibly
            // regex-metacharacter-heavy input.
            let _ = idx.search(&query);
            // The hunt DSL parser + Tantivy predicate compiler
            // (`parse_hunt_query` / `compile_predicate`).
            let _ = idx.hunt(s);
            // The pipe-aggregation parser sits in front of the same
            // predicate compiler and has its own token grammar.
            let _ = idx.hunt_aggregate(s);
            let _ = idx.hunt_aggregate(&format!("{s} | count"));
            let _ = idx.hunt_aggregate(&format!("{s} | count by device_id"));
        }
    }
});
