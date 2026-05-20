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

/// Build a full peer URL from a configured peer address and a path. If the
/// address has no scheme, default to `http://` (operators can opt in to
/// `https://` by configuring the peer address with the scheme explicitly).
fn cluster_peer_url(addr: &str, path: &str) -> String {
    let trimmed = addr.trim().trim_end_matches('/');
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        format!("{trimmed}{path}")
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
                    let s = state.lock().unwrap_or_else(|e| e.into_inner());
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
                    let s = state.lock().unwrap_or_else(|e| e.into_inner());
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
                    let s = state.lock().unwrap_or_else(|e| e.into_inner());
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
        let s = state.lock().unwrap_or_else(|e| e.into_inner());
        s.cluster.health()
    };
    match serde_json::to_string(&health) {
        Ok(json) => json_response(&json, 200),
        Err(e) => error_json(&format!("serialization error: {e}"), 500),
    }
}

/// Background driver loop. Snapshots cluster state under the AppState lock
/// at the start of each tick, then issues peer RPCs without holding the
/// lock so a slow peer cannot stall the rest of the server.
pub(crate) fn spawn_cluster_runtime_loop(state: &Arc<Mutex<AppState>>) {
    let state = Arc::clone(state);
    std::thread::spawn(move || {
        loop {
            let (shutdown, cluster, config, auth_header) = {
                let s = state.lock().unwrap_or_else(|e| e.into_inner());
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
                    let url = cluster_peer_url(&peer.addr, "/api/cluster/append");
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
                    let url = cluster_peer_url(&peer.addr, "/api/cluster/vote");
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
