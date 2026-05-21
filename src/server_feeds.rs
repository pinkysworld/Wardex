//! Threat-feed ingestion route handlers.
//!
//! Extracted from `server.rs` as part of the incremental decomposition of the
//! monolithic dispatch chain. The route-matching cascade in `server.rs`
//! pre-parses the feed id from dynamic paths and passes it in, so each
//! handler is a small, testable unit.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::response::Response;

use crate::server::{AppState, read_body_limited};
use crate::server_response::{error_json, json_response};

/// `GET /api/feeds` — list every configured feed source.
pub(crate) fn handle_feeds_list(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let s = crate::state_lock::tracked_lock(state, "server_feeds/handle_feeds_list");
    let body = serde_json::to_string(s.feed_engine.sources()).unwrap_or_default();
    json_response(&body, 200)
}

/// `POST /api/feeds` — register a new feed source.
pub(crate) fn handle_feeds_create(body: &[u8], state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let body_str = match read_body_limited(body, 16384) {
        Ok(value) => value,
        Err(error) => return error_json(&error, 400),
    };
    match serde_json::from_str::<crate::feed_ingestion::FeedSource>(&body_str) {
        Ok(src) => {
            let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
            let id = s.feed_engine.add_source(src);
            json_response(&format!(r#"{{"id":"{id}"}}"#), 201)
        }
        Err(error) => error_json(&format!("invalid feed source: {error}"), 400),
    }
}

/// `DELETE /api/feeds/{id}` — remove a feed source.
pub(crate) fn handle_feeds_delete(feed_id: &str, state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    if s.feed_engine.remove_source(feed_id) {
        json_response(r#"{"deleted":true}"#, 204)
    } else {
        error_json("feed source not found", 404)
    }
}

/// `POST /api/feeds/{id}/poll` — ingest a caller-supplied payload through the
/// feed's protocol parser.
pub(crate) fn handle_feeds_poll(
    feed_id: &str,
    body: &[u8],
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    let body_str = match read_body_limited(body, 10 * 1024 * 1024) {
        Ok(value) => value,
        Err(error) => return error_json(&error, 400),
    };
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    let AppState {
        ref mut feed_engine,
        ref mut threat_intel,
        ref mut malware_hash_db,
        ref mut yara_engine,
        ..
    } = *s;
    match feed_engine.poll_feed(
        feed_id,
        &body_str,
        threat_intel,
        malware_hash_db,
        yara_engine,
    ) {
        Ok(result) => {
            let body = serde_json::to_string(&result).unwrap_or_default();
            json_response(&body, 200)
        }
        Err(error) => error_json(&error, 400),
    }
}

/// `POST /api/feeds/{id}/fetch` — live HTTPS fetch from the feed URL, then
/// ingest. Network I/O happens off the state lock; only the ingest step holds
/// the lock.
pub(crate) fn handle_feeds_fetch(feed_id: &str, state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let source = {
        let s = state.lock().unwrap_or_else(|e| e.into_inner());
        s.feed_engine
            .sources()
            .iter()
            .find(|src| src.id == feed_id)
            .cloned()
    };
    match source {
        None => error_json("feed source not found", 404),
        Some(source) if !source.enabled => error_json("feed source is disabled", 400),
        Some(source) => match crate::feed_ingestion::fetch_feed_data(&source) {
            Ok(data) => {
                let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                let AppState {
                    ref mut feed_engine,
                    ref mut threat_intel,
                    ref mut malware_hash_db,
                    ref mut yara_engine,
                    ..
                } = *s;
                match feed_engine.poll_feed(
                    feed_id,
                    &data,
                    threat_intel,
                    malware_hash_db,
                    yara_engine,
                ) {
                    Ok(result) => {
                        json_response(&serde_json::to_string(&result).unwrap_or_default(), 200)
                    }
                    Err(error) => error_json(&error, 400),
                }
            }
            Err(error) => {
                let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
                s.feed_engine.record_feed_failure(feed_id, &error);
                error_json(&error, 502)
            }
        },
    }
}

/// `GET /api/feeds/stats` — aggregate ingestion statistics.
pub(crate) fn handle_feeds_stats(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let s = state.lock().unwrap_or_else(|e| e.into_inner());
    let body = serde_json::to_string(&s.feed_engine.stats()).unwrap_or_default();
    json_response(&body, 200)
}

/// `POST /api/feeds/hot-reload/hashes` — hot-reload the malware-hash database
/// from a JSON payload without restarting the server.
pub(crate) fn handle_feeds_hot_reload_hashes(
    body: &[u8],
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    let body_str = match read_body_limited(body, 10 * 1024 * 1024) {
        Ok(value) => value,
        Err(error) => return error_json(&error, 400),
    };
    let mut s = state.lock().unwrap_or_else(|e| e.into_inner());
    let AppState {
        ref mut feed_engine,
        ref mut malware_hash_db,
        ..
    } = *s;
    match feed_engine.hot_reload_hashes(&body_str, malware_hash_db) {
        Ok(count) => json_response(&format!(r#"{{"imported":{count}}}"#), 200),
        Err(error) => error_json(&error, 400),
    }
}
