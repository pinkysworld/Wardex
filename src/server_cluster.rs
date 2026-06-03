//! HA cluster RPC handlers and the Raft driver loop.
//!
//! Extracted from `server.rs` as part of the incremental decomposition of the
//! monolithic dispatch chain. Contains:
//!
//! - The four `/api/cluster/*` RPC handlers (`vote`, `append`, `snapshot`,
//!   `health`).
//! - The background driver loop (`spawn_cluster_runtime_loop`) that sends
//!   heartbeats / append RPCs to peers when leader, and starts elections
//!   when follower / candidate timeouts fire.
//! - The two peer-RPC helpers (`cluster_peer_url`,
//!   `cluster_peer_auth_header`) that were only used by the loop.
//!
//! `cluster_request_authorized` stays in `server.rs` because the dispatch
//! gate uses it directly before delegating to the handlers here.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::response::Response;

use crate::server::{AppState, read_body_limited};
use crate::server_response::{error_json, json_response};

/// Build the `Authorization: Bearer …` header that this node uses when
/// calling peer RPCs. Falls back to the main API token if no dedicated
/// cluster token is configured.
fn cluster_peer_auth_header(state: &AppState) -> String {
    let token = state
        .config
        .cluster
        .auth_token
        .clone()
        .unwrap_or_else(|| state.token.clone());
    format!("Bearer {token}")
}

/// Build a full peer URL from a configured peer address and a path. Bare
/// host:port addresses get a scheme prepended: `https://` when
/// `require_tls` is on, otherwise `http://` (back-compat). Explicit schemes
/// in the address are preserved.
fn cluster_peer_url(addr: &str, path: &str, require_tls: bool) -> String {
    let trimmed = addr.trim().trim_end_matches('/');
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        format!("{trimmed}{path}")
    } else if require_tls {
        format!("https://{trimmed}{path}")
    } else {
        format!("http://{trimmed}{path}")
    }
}

/// `POST /api/cluster/vote` — handle a Raft vote request from a peer.
pub(crate) fn handle_cluster_vote(body: &[u8], state: &Arc<Mutex<AppState>>) -> Response<Body> {
    match read_body_limited(body, 64 * 1024) {
        Ok(raw) => match serde_json::from_str::<crate::cluster::VoteRequest>(&raw) {
            Ok(request) => {
                let response = {
                    let s = crate::state_lock::tracked_lock(
                        state,
                        "server_cluster/handle_cluster_vote",
                    );
                    s.cluster.handle_vote_request(&request)
                };
                match serde_json::to_string(&response) {
                    Ok(json) => json_response(&json, 200),
                    Err(e) => error_json(&format!("serialization error: {e}"), 500),
                }
            }
            Err(e) => error_json(&format!("invalid JSON: {e}"), 400),
        },
        Err(e) => error_json(&e, 400),
    }
}

/// `POST /api/cluster/append` — handle a Raft append-entries / heartbeat
/// from the current leader.
pub(crate) fn handle_cluster_append(body: &[u8], state: &Arc<Mutex<AppState>>) -> Response<Body> {
    match read_body_limited(body, 512 * 1024) {
        Ok(raw) => match serde_json::from_str::<crate::cluster::AppendRequest>(&raw) {
            Ok(request) => {
                let response = {
                    let s = state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    s.cluster.handle_append(&request)
                };
                match serde_json::to_string(&response) {
                    Ok(json) => json_response(&json, 200),
                    Err(e) => error_json(&format!("serialization error: {e}"), 500),
                }
            }
            Err(e) => error_json(&format!("invalid JSON: {e}"), 400),
        },
        Err(e) => error_json(&e, 400),
    }
}

/// `POST /api/cluster/snapshot` — install a Raft log snapshot from the
/// current leader (used for follower catch-up after log compaction).
pub(crate) fn handle_cluster_snapshot(body: &[u8], state: &Arc<Mutex<AppState>>) -> Response<Body> {
    match read_body_limited(body, 512 * 1024) {
        Ok(raw) => match serde_json::from_str::<crate::cluster::InstallSnapshotRequest>(&raw) {
            Ok(request) => {
                let response = {
                    let s = state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    s.cluster.handle_install_snapshot(&request)
                };
                match serde_json::to_string(&response) {
                    Ok(json) => json_response(&json, 200),
                    Err(e) => error_json(&format!("serialization error: {e}"), 500),
                }
            }
            Err(e) => error_json(&format!("invalid JSON: {e}"), 400),
        },
        Err(e) => error_json(&e, 400),
    }
}

/// `GET /api/cluster/health` — local cluster health snapshot (role, term,
/// leader, peer reachability, commit index, uptime).
pub(crate) fn handle_cluster_health(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let health = {
        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        s.cluster.health()
    };
    match serde_json::to_string(&health) {
        Ok(json) => json_response(&json, 200),
        Err(e) => error_json(&format!("serialization error: {e}"), 500),
    }
}

/// Returns true if the peer address will speak plaintext HTTP (either an
/// explicit `http://` scheme or a bare host:port when `require_tls` is off).
fn peer_uses_plaintext(addr: &str, require_tls: bool) -> bool {
    let trimmed = addr.trim().trim_end_matches('/');
    if trimmed.starts_with("https://") {
        return false;
    }
    if trimmed.starts_with("http://") {
        return true;
    }
    !require_tls
}

/// Log a warning if any peer would receive plaintext RPCs. Called once at
/// driver-loop startup so operators see the gap on every restart.
fn warn_if_plaintext_peers(config: &crate::cluster::ClusterConfig) {
    if config.require_tls {
        return;
    }
    let plaintext: Vec<&str> = config
        .peers
        .iter()
        .filter(|p| peer_uses_plaintext(&p.addr, config.require_tls))
        .map(|p| p.addr.as_str())
        .collect();
    if !plaintext.is_empty() {
        log::warn!(
            "[cluster] {} peer(s) will receive RPCs over plaintext HTTP — bearer token will travel unencrypted on the wire. Set cluster.require_tls=true (and use https:// peer URLs) for production.",
            plaintext.len()
        );
    }
}

/// Background driver loop. Snapshots cluster state under the AppState lock
/// at the start of each tick, then issues peer RPCs without holding the
/// lock so a slow peer cannot stall the rest of the server.
pub(crate) fn spawn_cluster_runtime_loop(state: &Arc<Mutex<AppState>>) {
    let state = Arc::clone(state);
    std::thread::spawn(move || {
        // Emit the plaintext-peer warning once at startup so it is visible
        // in the boot log rather than buried in per-tick output.
        {
            let s = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            warn_if_plaintext_peers(&s.config.cluster);
        }

        loop {
            let (shutdown, cluster, config, auth_header) = {
                let s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                (
                    s.shutdown.load(Ordering::Relaxed),
                    s.cluster.clone(),
                    s.config.cluster.clone(),
                    cluster_peer_auth_header(&s),
                )
            };

            if shutdown {
                break;
            }

            if config.peers.is_empty() {
                std::thread::sleep(std::time::Duration::from_millis(200));
                continue;
            }

            if cluster.is_leader() {
                for peer in &config.peers {
                    let request = match cluster.prepare_append(&peer.node_id) {
                        Some(request) => request,
                        None => continue,
                    };
                    let url =
                        cluster_peer_url(&peer.addr, "/api/cluster/append", config.require_tls);
                    let response = ureq::post(&url)
                        .set("Authorization", &auth_header)
                        .send_string(
                            &serde_json::to_string(&request).unwrap_or_else(|_| "{}".to_string()),
                        );

                    match response {
                        Ok(response) => {
                            match response.into_json::<crate::cluster::AppendResponse>() {
                                Ok(append_response) => {
                                    cluster.handle_append_response(&peer.node_id, &append_response)
                                }
                                Err(_) => cluster.mark_peer_unreachable(&peer.node_id),
                            }
                        }
                        Err(_) => cluster.mark_peer_unreachable(&peer.node_id),
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(
                    config.heartbeat_interval_ms.max(25),
                ));
                continue;
            }

            if cluster.should_start_election() {
                let request = cluster.start_election();
                let mut votes = 1usize;
                let majority = config.peers.len().div_ceil(2) + 1;

                for peer in &config.peers {
                    let url = cluster_peer_url(&peer.addr, "/api/cluster/vote", config.require_tls);
                    match ureq::post(&url)
                        .set("Authorization", &auth_header)
                        .send_string(
                            &serde_json::to_string(&request).unwrap_or_else(|_| "{}".to_string()),
                        ) {
                        Ok(response) => {
                            match response.into_json::<crate::cluster::VoteResponse>() {
                                Ok(vote_response) => {
                                    if vote_response.vote_granted {
                                        votes += 1;
                                    }
                                }
                                Err(_) => cluster.mark_peer_unreachable(&peer.node_id),
                            }
                        }
                        Err(_) => cluster.mark_peer_unreachable(&peer.node_id),
                    }
                }

                if votes >= majority {
                    cluster.become_leader();
                }
            }

            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cluster_peer_url_keeps_explicit_scheme() {
        assert_eq!(
            cluster_peer_url("http://peer-a:9078", "/api/cluster/vote", false),
            "http://peer-a:9078/api/cluster/vote",
        );
        assert_eq!(
            cluster_peer_url("https://peer-b:9078", "/api/cluster/vote", true),
            "https://peer-b:9078/api/cluster/vote",
        );
    }

    #[test]
    fn cluster_peer_url_defaults_to_http_without_require_tls() {
        assert_eq!(
            cluster_peer_url("peer-c:9078", "/api/cluster/append", false),
            "http://peer-c:9078/api/cluster/append",
        );
    }

    #[test]
    fn cluster_peer_url_defaults_to_https_when_require_tls() {
        assert_eq!(
            cluster_peer_url("peer-d:9078", "/api/cluster/append", true),
            "https://peer-d:9078/api/cluster/append",
        );
    }

    #[test]
    fn peer_uses_plaintext_classifies_schemes() {
        // explicit https is never plaintext
        assert!(!peer_uses_plaintext("https://peer", false));
        assert!(!peer_uses_plaintext("https://peer", true));
        // explicit http is always plaintext
        assert!(peer_uses_plaintext("http://peer", false));
        assert!(peer_uses_plaintext("http://peer", true));
        // bare host:port follows the require_tls default
        assert!(peer_uses_plaintext("peer:9078", false));
        assert!(!peer_uses_plaintext("peer:9078", true));
    }
}
