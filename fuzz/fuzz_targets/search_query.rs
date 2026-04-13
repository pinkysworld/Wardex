#![no_main]
use libfuzzer_sys::fuzz_target;
use wardex::search::SearchQuery;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let idx = wardex::search::SearchIndex::new("/tmp/fuzz_search").ok();
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
            let _ = idx.search(&query);
            let _ = idx.hunt(s);
        }
    }
});
