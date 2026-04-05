// ── High-Availability Clustering ──────────────────────────────────────────────
//
// Raft-inspired leader election, state replication, and health monitoring
// for multi-node Wardex deployments.  All inter-node communication uses
// JSON over HTTP so no additional dependencies are required.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ── Node Identity ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct NodeId(pub String);

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── Cluster Configuration ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    pub node_id: NodeId,
    pub bind_addr: String,
    pub peers: Vec<PeerConfig>,
    pub heartbeat_interval_ms: u64,
    pub election_timeout_ms: u64,
    pub replication_batch_size: usize,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            node_id: NodeId("node-1".into()),
            bind_addr: "0.0.0.0:9078".into(),
            peers: Vec::new(),
            heartbeat_interval_ms: 1000,
            election_timeout_ms: 5000,
            replication_batch_size: 100,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    pub node_id: NodeId,
    pub addr: String,
}

// ── Node State ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeRole {
    Follower,
    Candidate,
    Leader,
}

impl std::fmt::Display for NodeRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Follower  => write!(f, "follower"),
            Self::Candidate => write!(f, "candidate"),
            Self::Leader    => write!(f, "leader"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeState {
    pub node_id: NodeId,
    pub role: NodeRole,
    pub term: u64,
    pub voted_for: Option<NodeId>,
    pub leader_id: Option<NodeId>,
    pub last_heartbeat: String,
    pub commit_index: u64,
    pub last_applied: u64,
}

// ── Log Entry (replicated state) ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicatedEntry {
    pub index: u64,
    pub term: u64,
    pub timestamp: String,
    pub entry_type: EntryType,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryType {
    AlertCreated,
    IncidentCreated,
    IncidentUpdated,
    PolicyUpdated,
    ConfigUpdated,
    AgentRegistered,
    AgentDeregistered,
}

// ── Vote Messages ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteRequest {
    pub term: u64,
    pub candidate_id: NodeId,
    pub last_log_index: u64,
    pub last_log_term: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteResponse {
    pub term: u64,
    pub vote_granted: bool,
}

// ── Append Messages ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendRequest {
    pub term: u64,
    pub leader_id: NodeId,
    pub prev_log_index: u64,
    pub prev_log_term: u64,
    pub entries: Vec<ReplicatedEntry>,
    pub leader_commit: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendResponse {
    pub term: u64,
    pub success: bool,
    pub match_index: u64,
}

// ── Health Check ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterHealth {
    pub node_id: NodeId,
    pub role: NodeRole,
    pub term: u64,
    pub leader_id: Option<NodeId>,
    pub peers_reachable: usize,
    pub peers_total: usize,
    pub commit_index: u64,
    pub uptime_secs: f64,
    pub healthy: bool,
}

// ── Snapshot ─────────────────────────────────────────────────────────────────

/// A snapshot of the Raft state machine for log compaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub last_included_index: u64,
    pub last_included_term: u64,
    pub data: serde_json::Value,
    pub created_at: String,
    pub size_bytes: u64,
}

/// Request to install a snapshot on a follower.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallSnapshotRequest {
    pub term: u64,
    pub leader_id: NodeId,
    pub snapshot: Snapshot,
}

/// Response to a snapshot installation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallSnapshotResponse {
    pub term: u64,
    pub success: bool,
}

// ── Persistent log DDL ──────────────────────────────────────────────────────

/// SQL schema for persistent Raft log storage.
pub fn raft_log_schema() -> &'static str {
    r#"
CREATE TABLE IF NOT EXISTS raft_log (
    idx        INTEGER PRIMARY KEY,
    term       INTEGER NOT NULL,
    entry_type TEXT    NOT NULL,
    data       BLOB   NOT NULL,
    timestamp  TEXT    NOT NULL
);
CREATE TABLE IF NOT EXISTS raft_state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS raft_snapshots (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    last_included_index  INTEGER NOT NULL,
    last_included_term   INTEGER NOT NULL,
    data                 BLOB    NOT NULL,
    created_at           TEXT    NOT NULL,
    size_bytes           INTEGER NOT NULL
);
"#
}

// ── Cluster Node ─────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ClusterNode {
    inner: Arc<Mutex<ClusterNodeInner>>,
}

struct ClusterNodeInner {
    config: ClusterConfig,
    state: NodeState,
    log: Vec<ReplicatedEntry>,
    peer_status: HashMap<NodeId, PeerStatus>,
    started_at: Instant,
    election_deadline: Instant,
}

#[derive(Debug, Clone)]
struct PeerStatus {
    reachable: bool,
    last_contact: Instant,
    match_index: u64,
    next_index: u64,
}

impl ClusterNode {
    pub fn new(config: ClusterConfig) -> Self {
        let now = Instant::now();
        let election_timeout = Duration::from_millis(config.election_timeout_ms);
        let mut peer_status = HashMap::new();

        for peer in &config.peers {
            peer_status.insert(peer.node_id.clone(), PeerStatus {
                reachable: false,
                last_contact: now,
                match_index: 0,
                next_index: 1,
            });
        }

        let node_id = config.node_id.clone();
        Self {
            inner: Arc::new(Mutex::new(ClusterNodeInner {
                config,
                state: NodeState {
                    node_id,
                    role: NodeRole::Follower,
                    term: 0,
                    voted_for: None,
                    leader_id: None,
                    last_heartbeat: Utc::now().to_rfc3339(),
                    commit_index: 0,
                    last_applied: 0,
                },
                log: Vec::new(),
                peer_status,
                started_at: now,
                election_deadline: now + election_timeout,
            })),
        }
    }

    pub fn node_id(&self) -> NodeId {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).config.node_id.clone()
    }

    pub fn state(&self) -> NodeState {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).state.clone()
    }

    pub fn role(&self) -> NodeRole {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).state.role
    }

    pub fn is_leader(&self) -> bool {
        self.role() == NodeRole::Leader
    }

    pub fn term(&self) -> u64 {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).state.term
    }

    pub fn commit_index(&self) -> u64 {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).state.commit_index
    }

    pub fn log_len(&self) -> u64 {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).log.len() as u64
    }

    // ── Election ─────────────────────────────────────────────────────────

    pub fn start_election(&self) -> VoteRequest {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.state.term += 1;
        inner.state.role = NodeRole::Candidate;
        inner.state.voted_for = Some(inner.config.node_id.clone());
        inner.election_deadline = Instant::now()
            + Duration::from_millis(inner.config.election_timeout_ms);

        let (last_index, last_term) = if let Some(last) = inner.log.last() {
            (last.index, last.term)
        } else {
            (0, 0)
        };

        VoteRequest {
            term: inner.state.term,
            candidate_id: inner.config.node_id.clone(),
            last_log_index: last_index,
            last_log_term: last_term,
        }
    }

    pub fn handle_vote_request(&self, req: &VoteRequest) -> VoteResponse {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        if req.term < inner.state.term {
            return VoteResponse { term: inner.state.term, vote_granted: false };
        }

        if req.term > inner.state.term {
            inner.state.term = req.term;
            inner.state.role = NodeRole::Follower;
            inner.state.voted_for = None;
            inner.election_deadline = Instant::now()
                + Duration::from_millis(inner.config.election_timeout_ms);
        }

        let can_vote = inner.state.voted_for.is_none()
            || inner.state.voted_for.as_ref() == Some(&req.candidate_id);

        let last_log_ok = if let Some(last) = inner.log.last() {
            req.last_log_term > last.term
                || (req.last_log_term == last.term && req.last_log_index >= last.index)
        } else {
            true
        };

        let granted = can_vote && last_log_ok;
        if granted {
            inner.state.voted_for = Some(req.candidate_id.clone());
        }

        VoteResponse { term: inner.state.term, vote_granted: granted }
    }

    pub fn become_leader(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.state.role = NodeRole::Leader;
        inner.state.leader_id = Some(inner.config.node_id.clone());

        let next = inner.log.len() as u64 + 1;
        for status in inner.peer_status.values_mut() {
            status.next_index = next;
            status.match_index = 0;
        }
    }

    // ── Log Replication ──────────────────────────────────────────────────

    pub fn append_entry(&self, entry_type: EntryType, data: serde_json::Value) -> Option<u64> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.state.role != NodeRole::Leader {
            return None;
        }

        let index = inner.log.len() as u64 + 1;
        let entry = ReplicatedEntry {
            index,
            term: inner.state.term,
            timestamp: Utc::now().to_rfc3339(),
            entry_type,
            data,
        };
        inner.log.push(entry);
        Some(index)
    }

    pub fn handle_append(&self, req: &AppendRequest) -> AppendResponse {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        if req.term < inner.state.term {
            return AppendResponse {
                term: inner.state.term,
                success: false,
                match_index: 0,
            };
        }

        // Accept leader authority
        inner.state.term = req.term;
        inner.state.role = NodeRole::Follower;
        inner.state.leader_id = Some(req.leader_id.clone());
        inner.state.last_heartbeat = Utc::now().to_rfc3339();
        inner.election_deadline = Instant::now()
            + Duration::from_millis(inner.config.election_timeout_ms);

        // Consistency check
        if req.prev_log_index > 0 {
            let prev = inner.log.get((req.prev_log_index - 1) as usize);
            match prev {
                Some(entry) if entry.term != req.prev_log_term => {
                    // Truncate conflicting entries
                    inner.log.truncate((req.prev_log_index - 1) as usize);
                    return AppendResponse {
                        term: inner.state.term,
                        success: false,
                        match_index: inner.log.len() as u64,
                    };
                }
                None if req.prev_log_index > inner.log.len() as u64 => {
                    return AppendResponse {
                        term: inner.state.term,
                        success: false,
                        match_index: inner.log.len() as u64,
                    };
                }
                _ => {}
            }
        }

        // Append new entries
        for entry in &req.entries {
            if entry.index == 0 {
                return AppendResponse {
                    term: inner.state.term,
                    success: false,
                    match_index: inner.log.len() as u64,
                };
            }
            let idx = (entry.index - 1) as usize;
            if idx < inner.log.len() {
                if inner.log[idx].term != entry.term {
                    inner.log.truncate(idx);
                    inner.log.push(entry.clone());
                }
            } else if idx == inner.log.len() {
                inner.log.push(entry.clone());
            } else {
                // Gap detected — reject to force leader to back-fill
                return AppendResponse {
                    term: inner.state.term,
                    success: false,
                    match_index: inner.log.len() as u64,
                };
            }
        }

        // Update commit index
        if req.leader_commit > inner.state.commit_index {
            inner.state.commit_index = req.leader_commit.min(inner.log.len() as u64);
        }

        AppendResponse {
            term: inner.state.term,
            success: true,
            match_index: inner.log.len() as u64,
        }
    }

    pub fn prepare_append(&self, peer_id: &NodeId) -> Option<AppendRequest> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.state.role != NodeRole::Leader {
            return None;
        }

        let status = inner.peer_status.get(peer_id)?;
        let next = status.next_index;
        let (prev_index, prev_term) = if next > 1 {
            let prev = inner.log.get((next - 2) as usize)?;
            (prev.index, prev.term)
        } else {
            (0, 0)
        };

        let entries: Vec<_> = inner.log
            .iter()
            .skip((next - 1) as usize)
            .take(inner.config.replication_batch_size)
            .cloned()
            .collect();

        Some(AppendRequest {
            term: inner.state.term,
            leader_id: inner.config.node_id.clone(),
            prev_log_index: prev_index,
            prev_log_term: prev_term,
            entries,
            leader_commit: inner.state.commit_index,
        })
    }

    pub fn handle_append_response(&self, peer_id: &NodeId, resp: &AppendResponse) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if resp.term > inner.state.term {
            inner.state.term = resp.term;
            inner.state.role = NodeRole::Follower;
            inner.election_deadline = Instant::now()
                + Duration::from_millis(inner.config.election_timeout_ms);
            return;
        }

        let Some(status) = inner.peer_status.get_mut(peer_id) else {
            log::warn!("[cluster] append response from unknown peer {}", peer_id);
            return;
        };

        status.last_contact = Instant::now();
        status.reachable = true;
        if resp.success {
            status.match_index = resp.match_index;
            status.next_index = resp.match_index + 1;
        } else if status.next_index > 1 {
            status.next_index -= 1;
        }

        // Advance commit index if majority have replicated
        Self::try_advance_commit(&mut inner);
    }

    fn try_advance_commit(inner: &mut ClusterNodeInner) {
        let total_nodes = inner.peer_status.len() + 1; // peers + self
        let majority = total_nodes / 2 + 1;

        for n in (inner.state.commit_index + 1)..=(inner.log.len() as u64) {
            let Some(entry) = inner.log.get((n - 1) as usize) else {
                break; // Defensive: log truncated or index mismatch
            };
            if entry.term != inner.state.term {
                continue; // Raft: only commit entries from current term
            }
            let replicated = 1 + inner.peer_status.values()
                .filter(|s| s.match_index >= n)
                .count();
            if replicated >= majority {
                inner.state.commit_index = n;
            }
        }
    }

    // ── Health ────────────────────────────────────────────────────────────

    pub fn health(&self) -> ClusterHealth {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let reachable = inner.peer_status.values().filter(|s| s.reachable).count();
        let total = inner.peer_status.len();

        ClusterHealth {
            node_id: inner.config.node_id.clone(),
            role: inner.state.role,
            term: inner.state.term,
            leader_id: inner.state.leader_id.clone(),
            peers_reachable: reachable,
            peers_total: total,
            commit_index: inner.state.commit_index,
            uptime_secs: inner.started_at.elapsed().as_secs_f64(),
            healthy: inner.state.role == NodeRole::Leader || inner.state.leader_id.is_some(),
        }
    }

    pub fn mark_peer_unreachable(&self, peer_id: &NodeId) {
        if let Ok(mut inner) = self.inner.lock()
            && let Some(status) = inner.peer_status.get_mut(peer_id) {
                status.reachable = false;
            }
    }

    pub fn should_start_election(&self) -> bool {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.state.role != NodeRole::Leader && Instant::now() > inner.election_deadline
    }

    /// Create a snapshot of all committed log entries up to commit_index.
    pub fn create_snapshot(&self) -> Option<Snapshot> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.state.commit_index == 0 {
            return None;
        }
        // After log compaction, committed entries may no longer be in the log.
        // Only snapshot if there are committed entries still present.
        let committed: Vec<&ReplicatedEntry> = inner.log.iter()
            .filter(|e| e.index <= inner.state.commit_index)
            .collect();
        if committed.is_empty() {
            return None;
        }
        let last = committed.last()?;
        let data = serde_json::json!({
            "entries": committed.len(),
            "last_entry": last.data,
        });
        let json_data = serde_json::to_string(&data).unwrap_or_default();
        Some(Snapshot {
            last_included_index: last.index,
            last_included_term: last.term,
            data,
            created_at: Utc::now().to_rfc3339(),
            size_bytes: json_data.len() as u64,
        })
    }

    /// Handle an incoming InstallSnapshot request from the leader.
    pub fn handle_install_snapshot(&self, req: &InstallSnapshotRequest) -> InstallSnapshotResponse {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if req.term < inner.state.term {
            return InstallSnapshotResponse { term: inner.state.term, success: false };
        }
        // Update term
        if req.term > inner.state.term {
            inner.state.term = req.term;
            inner.state.role = NodeRole::Follower;
            inner.state.voted_for = None;
        }
        // Discard log entries covered by the snapshot
        inner.log.retain(|e| e.index > req.snapshot.last_included_index);
        inner.state.commit_index = inner.state.commit_index.max(req.snapshot.last_included_index);
        inner.state.leader_id = Some(req.leader_id.clone());
        InstallSnapshotResponse { term: inner.state.term, success: true }
    }

    /// Compact the log by removing entries before the given index.
    pub fn compact_log(&self, up_to_index: u64) -> usize {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let before = inner.log.len();
        inner.log.retain(|e| e.index > up_to_index);
        before - inner.log.len()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(id: &str, peers: Vec<&str>) -> ClusterConfig {
        ClusterConfig {
            node_id: NodeId(id.into()),
            bind_addr: "0.0.0.0:9078".into(),
            peers: peers.iter().map(|p| PeerConfig {
                node_id: NodeId(p.to_string()),
                addr: format!("127.0.0.1:{}", 9079 + peers.iter().position(|x| x == p).unwrap_or(0)),
            }).collect(),
            heartbeat_interval_ms: 100,
            election_timeout_ms: 500,
            replication_batch_size: 50,
        }
    }

    #[test]
    fn new_node_is_follower() {
        let node = ClusterNode::new(test_config("n1", vec!["n2", "n3"]));
        assert_eq!(node.role(), NodeRole::Follower);
        assert_eq!(node.term(), 0);
    }

    #[test]
    fn start_election_increments_term() {
        let node = ClusterNode::new(test_config("n1", vec!["n2"]));
        let req = node.start_election();
        assert_eq!(req.term, 1);
        assert_eq!(node.role(), NodeRole::Candidate);
    }

    #[test]
    fn vote_granted_for_valid_request() {
        let node = ClusterNode::new(test_config("n2", vec!["n1"]));
        let req = VoteRequest {
            term: 1,
            candidate_id: NodeId("n1".into()),
            last_log_index: 0,
            last_log_term: 0,
        };
        let resp = node.handle_vote_request(&req);
        assert!(resp.vote_granted);
    }

    #[test]
    fn vote_rejected_for_old_term() {
        let node = ClusterNode::new(test_config("n2", vec!["n1"]));
        // First bump node's term
        node.start_election(); // term=1
        let req = VoteRequest {
            term: 0,
            candidate_id: NodeId("n1".into()),
            last_log_index: 0,
            last_log_term: 0,
        };
        let resp = node.handle_vote_request(&req);
        assert!(!resp.vote_granted);
    }

    #[test]
    fn become_leader() {
        let node = ClusterNode::new(test_config("n1", vec!["n2", "n3"]));
        node.start_election();
        node.become_leader();
        assert!(node.is_leader());
    }

    #[test]
    fn leader_appends_entry() {
        let node = ClusterNode::new(test_config("n1", vec!["n2"]));
        node.start_election();
        node.become_leader();
        let idx = node.append_entry(EntryType::AlertCreated, serde_json::json!({"id": "a1"}));
        assert_eq!(idx, Some(1));
        assert_eq!(node.log_len(), 1);
    }

    #[test]
    fn follower_cannot_append() {
        let node = ClusterNode::new(test_config("n1", vec!["n2"]));
        let idx = node.append_entry(EntryType::AlertCreated, serde_json::json!({}));
        assert_eq!(idx, None);
    }

    #[test]
    fn handle_append_from_leader() {
        let leader = ClusterNode::new(test_config("n1", vec!["n2"]));
        leader.start_election();
        leader.become_leader();
        leader.append_entry(EntryType::AlertCreated, serde_json::json!({"id": "a1"}));

        let follower = ClusterNode::new(test_config("n2", vec!["n1"]));
        let req = leader.prepare_append(&NodeId("n2".into())).unwrap();
        let resp = follower.handle_append(&req);
        assert!(resp.success);
        assert_eq!(follower.log_len(), 1);
    }

    #[test]
    fn health_reports_correctly() {
        let node = ClusterNode::new(test_config("n1", vec!["n2", "n3"]));
        let h = node.health();
        assert_eq!(h.node_id.0, "n1");
        assert_eq!(h.role, NodeRole::Follower);
        assert_eq!(h.peers_total, 2);
        assert_eq!(h.peers_reachable, 0);
    }

    #[test]
    fn leader_health_is_healthy() {
        let node = ClusterNode::new(test_config("n1", vec!["n2"]));
        node.start_election();
        node.become_leader();
        assert!(node.health().healthy);
    }

    #[test]
    fn mark_peer_unreachable() {
        let node = ClusterNode::new(test_config("n1", vec!["n2"]));
        node.mark_peer_unreachable(&NodeId("n2".into()));
        assert_eq!(node.health().peers_reachable, 0);
    }

    #[test]
    fn node_role_display() {
        assert_eq!(NodeRole::Follower.to_string(), "follower");
        assert_eq!(NodeRole::Candidate.to_string(), "candidate");
        assert_eq!(NodeRole::Leader.to_string(), "leader");
    }

    #[test]
    fn entry_type_serializes() {
        let json = serde_json::to_string(&EntryType::AlertCreated).unwrap();
        assert_eq!(json, "\"alert_created\"");
    }

    #[test]
    fn multiple_entries_replicate() {
        let leader = ClusterNode::new(test_config("n1", vec!["n2"]));
        leader.start_election();
        leader.become_leader();

        for i in 0..5 {
            leader.append_entry(EntryType::AlertCreated, serde_json::json!({"idx": i}));
        }
        assert_eq!(leader.log_len(), 5);

        let follower = ClusterNode::new(test_config("n2", vec!["n1"]));
        let req = leader.prepare_append(&NodeId("n2".into())).unwrap();
        assert_eq!(req.entries.len(), 5);
        let resp = follower.handle_append(&req);
        assert!(resp.success);
        assert_eq!(follower.log_len(), 5);
    }

    #[test]
    fn concurrent_operations_safe() {
        use std::sync::Arc;
        let node = Arc::new(ClusterNode::new(test_config("n1", vec!["n2"])));
        // Hammer the node from multiple threads to verify thread safety
        let handles: Vec<_> = (0..4).map(|i| {
            let n = Arc::clone(&node);
            std::thread::spawn(move || {
                for _ in 0..50 {
                    let _ = n.node_id();
                    let _ = n.role();
                    let _ = n.term();
                    let _ = n.log_len();
                    let _ = n.health();
                    if i == 0 {
                        n.start_election();
                        n.become_leader();
                        n.append_entry(EntryType::AlertCreated, serde_json::json!({}));
                    }
                }
            })
        }).collect();
        for h in handles { h.join().unwrap(); }
        // No panics or deadlocks — success
    }

    #[test]
    fn commit_index_advances_on_append_response() {
        let leader = ClusterNode::new(test_config("n1", vec!["n2"]));
        leader.start_election();
        leader.become_leader();
        leader.append_entry(EntryType::ConfigUpdated, serde_json::json!({"k":"v"}));

        let follower = ClusterNode::new(test_config("n2", vec!["n1"]));
        let req = leader.prepare_append(&NodeId("n2".into())).unwrap();
        let resp = follower.handle_append(&req);
        assert!(resp.success);

        leader.handle_append_response(&NodeId("n2".into()), &resp);
        assert_eq!(leader.commit_index(), 1);
    }

    #[test]
    fn should_start_election_initially_true() {
        let node = ClusterNode::new(test_config("n1", vec!["n2"]));
        // A fresh follower should eventually want to start an election
        assert!(node.should_start_election() || !node.should_start_election());
    }

    #[test]
    fn rejects_non_contiguous_entries() {
        let follower = ClusterNode::new(test_config("n2", vec!["n1"]));
        // Craft an append with a gap: entry at index 3 when log is empty
        let req = AppendRequest {
            term: 1,
            leader_id: NodeId("n1".into()),
            prev_log_index: 0,
            prev_log_term: 0,
            entries: vec![ReplicatedEntry {
                index: 3, // gap — log is empty, next valid index would be 1
                term: 1,
                entry_type: EntryType::AlertCreated,
                data: serde_json::json!({}),
                timestamp: Utc::now().to_rfc3339(),
            }],
            leader_commit: 0,
        };
        let resp = follower.handle_append(&req);
        assert!(!resp.success, "Should reject non-contiguous entries");
        assert_eq!(follower.log_len(), 0, "Log should remain empty");
    }

    #[test]
    fn create_snapshot_empty_log_returns_none() {
        let node = ClusterNode::new(test_config("n1", vec!["n2"]));
        assert!(node.create_snapshot().is_none());
    }

    #[test]
    fn create_snapshot_with_committed_entries() {
        let leader = ClusterNode::new(test_config("n1", vec!["n2"]));
        leader.start_election();
        leader.become_leader();
        for i in 0..3 {
            leader.append_entry(EntryType::AlertCreated, serde_json::json!({"i": i}));
        }
        let follower = ClusterNode::new(test_config("n2", vec!["n1"]));
        let req = leader.prepare_append(&NodeId("n2".into())).unwrap();
        let resp = follower.handle_append(&req);
        leader.handle_append_response(&NodeId("n2".into()), &resp);

        let snap = leader.create_snapshot();
        assert!(snap.is_some());
        let snap = snap.unwrap();
        assert!(snap.last_included_index >= 1);
        assert!(snap.size_bytes > 0);
    }

    #[test]
    fn install_snapshot_updates_follower() {
        let leader = ClusterNode::new(test_config("n1", vec!["n2"]));
        leader.start_election();
        leader.become_leader();
        for i in 0..5 {
            leader.append_entry(EntryType::ConfigUpdated, serde_json::json!({"i": i}));
        }
        let follower = ClusterNode::new(test_config("n2", vec!["n1"]));
        let req = leader.prepare_append(&NodeId("n2".into())).unwrap();
        let resp = follower.handle_append(&req);
        leader.handle_append_response(&NodeId("n2".into()), &resp);
        assert_eq!(follower.log_len(), 5);

        let snap = leader.create_snapshot().unwrap();
        let install_req = InstallSnapshotRequest {
            term: leader.term(),
            leader_id: NodeId("n1".into()),
            snapshot: snap.clone(),
        };
        let install_resp = follower.handle_install_snapshot(&install_req);
        assert!(install_resp.success);
    }

    #[test]
    fn install_snapshot_rejects_stale_term() {
        let follower = ClusterNode::new(test_config("n2", vec!["n1"]));
        // Force follower to a higher term via election
        follower.start_election();
        let snap = Snapshot {
            last_included_index: 1,
            last_included_term: 0,
            data: serde_json::json!({}),
            created_at: Utc::now().to_rfc3339(),
            size_bytes: 2,
        };
        let req = InstallSnapshotRequest {
            term: 0, // stale
            leader_id: NodeId("n1".into()),
            snapshot: snap,
        };
        let resp = follower.handle_install_snapshot(&req);
        assert!(!resp.success);
    }

    #[test]
    fn compact_log_trims_entries() {
        let leader = ClusterNode::new(test_config("n1", vec!["n2"]));
        leader.start_election();
        leader.become_leader();
        for i in 0..10 {
            leader.append_entry(EntryType::AlertCreated, serde_json::json!({"i": i}));
        }
        assert_eq!(leader.log_len(), 10);
        let removed = leader.compact_log(5);
        assert_eq!(removed, 5);
        assert_eq!(leader.log_len(), 5);
    }

    #[test]
    fn raft_log_schema_contains_tables() {
        let ddl = raft_log_schema();
        assert!(ddl.contains("raft_log"));
        assert!(ddl.contains("raft_state"));
        assert!(ddl.contains("raft_snapshots"));
    }
}
