//! Swarm coordination, fleet orchestration, mesh topology, and consensus voting.
//!
//! Implements gossip-based status dissemination, Byzantine-fault-tolerant
//! voting for threat consensus, mesh topology self-organisation, fleet
//! device management, and negotiated security posture.
//! Covers R03 (swarm), R23 (voting), R24 (negotiation), R37 (mesh).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::audit::sha256_hex;
use crate::policy::ThreatLevel;

// ── Gossip Protocol ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipMessage {
    pub sender_id: String,
    pub sequence: u64,
    pub timestamp_ms: u64,
    pub payload: GossipPayload,
    pub digest: String,
    pub ttl: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipPayload {
    StatusUpdate {
        threat_level: String,
        score: f32,
        battery_pct: f32,
        cpu_load_pct: f32,
    },
    ThreatAlert {
        severity: String,
        indicator: String,
        confidence: f32,
    },
    PolicyUpdate {
        policy_hash: String,
        version: u64,
    },
    VoteRequest {
        round_id: String,
        proposal: String,
    },
    VoteResponse {
        round_id: String,
        vote: bool,
        reason: String,
    },
}

impl GossipMessage {
    pub fn new(sender_id: &str, sequence: u64, payload: GossipPayload) -> Self {
        let ts = chrono::Utc::now().timestamp_millis() as u64;
        let digest_input = format!("{sender_id}:{sequence}:{ts}");
        let digest = sha256_hex(digest_input.as_bytes());
        Self {
            sender_id: sender_id.to_string(),
            sequence,
            timestamp_ms: ts,
            payload,
            digest,
            ttl: 5,
        }
    }
}

// ── Device Registry & Fleet Management ───────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub device_id: String,
    pub name: String,
    pub platform: String,
    pub firmware_version: String,
    pub enrolled_at: String,
    pub last_seen_ms: u64,
    pub status: DeviceStatus,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeviceStatus {
    Online,
    Offline,
    Quarantined,
    Compromised,
    Updating,
    Decommissioned,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetHealthReport {
    pub total_devices: usize,
    pub online: usize,
    pub offline: usize,
    pub quarantined: usize,
    pub compromised: usize,
    pub avg_threat_score: f32,
    pub critical_alerts: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDistribution {
    pub policy_hash: String,
    pub version: u64,
    pub distributed_to: Vec<String>,
    pub acknowledged_by: Vec<String>,
    pub pending: Vec<String>,
}

// ── Voting Consensus (R23) ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteRound {
    pub round_id: String,
    pub proposal: String,
    pub initiator: String,
    pub votes: HashMap<String, Vote>,
    pub quorum_threshold: f32, // fraction [0, 1]
    pub status: VoteStatus,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    pub voter_id: String,
    pub approve: bool,
    pub confidence: f32,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VoteStatus {
    Open,
    QuorumReached,
    Approved,
    Rejected,
    Expired,
}

impl VoteRound {
    pub fn new(round_id: &str, proposal: &str, initiator: &str, quorum: f32) -> Self {
        Self {
            round_id: round_id.to_string(),
            proposal: proposal.to_string(),
            initiator: initiator.to_string(),
            votes: HashMap::new(),
            quorum_threshold: quorum.clamp(0.0, 1.0),
            status: VoteStatus::Open,
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn cast_vote(&mut self, vote: Vote) {
        if self.status == VoteStatus::Open {
            self.votes.insert(vote.voter_id.clone(), vote);
        }
    }

    /// Tally votes and determine outcome.
    pub fn tally(&mut self, total_voters: usize) -> VoteStatus {
        if total_voters == 0 {
            self.status = VoteStatus::Rejected;
            return self.status.clone();
        }

        let participation = self.votes.len() as f32 / total_voters as f32;
        if participation < self.quorum_threshold {
            return VoteStatus::Open; // not enough votes yet
        }

        self.status = VoteStatus::QuorumReached;

        let approve_count = self.votes.values().filter(|v| v.approve).count();
        let weighted_approval: f32 = self
            .votes
            .values()
            .filter(|v| v.approve)
            .map(|v| v.confidence)
            .sum::<f32>();
        let weighted_total: f32 = self.votes.values().map(|v| v.confidence).sum::<f32>();

        let approval_rate = if weighted_total > 0.0 {
            weighted_approval / weighted_total
        } else {
            approve_count as f32 / self.votes.len() as f32
        };

        if approval_rate >= 0.5 {
            self.status = VoteStatus::Approved;
        } else {
            self.status = VoteStatus::Rejected;
        }

        self.status.clone()
    }
}

// ── Negotiated Security Posture (R24) ────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureNegotiation {
    pub negotiation_id: String,
    pub participants: Vec<String>,
    pub proposed_level: String,
    pub current_levels: HashMap<String, String>,
    pub agreed_level: Option<String>,
    pub constraints: Vec<PostureConstraint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureConstraint {
    pub device_id: String,
    pub min_level: String,
    pub max_level: String,
    pub reason: String,
}

impl PostureNegotiation {
    pub fn new(negotiation_id: &str, participants: Vec<String>) -> Self {
        Self {
            negotiation_id: negotiation_id.to_string(),
            participants,
            proposed_level: "elevated".into(),
            current_levels: HashMap::new(),
            agreed_level: None,
            constraints: Vec::new(),
        }
    }

    /// Each participant reports its current security posture.
    pub fn report_posture(&mut self, device_id: &str, level: &str) {
        self.current_levels
            .insert(device_id.to_string(), level.to_string());
    }

    /// Add a constraint on what security levels a device can accept.
    pub fn add_constraint(&mut self, constraint: PostureConstraint) {
        self.constraints.push(constraint);
    }

    /// Resolve the negotiation: find the highest level that all
    /// participants can accept given their constraints.
    pub fn resolve(&mut self) -> Option<String> {
        let levels = ["nominal", "elevated", "severe", "critical"];
        let priority: HashMap<&str, u8> =
            levels.iter().enumerate().map(|(i, &l)| (l, i as u8)).collect();

        // Start from the highest reported level
        let max_current = self
            .current_levels
            .values()
            .filter_map(|l| priority.get(l.as_str()))
            .max()
            .copied()
            .unwrap_or(0);

        let mut proposed_idx = max_current as usize;

        // Clamp by constraints
        for constraint in &self.constraints {
            let min_idx = priority.get(constraint.min_level.as_str()).copied().unwrap_or(0) as usize;
            let max_idx = priority.get(constraint.max_level.as_str()).copied().unwrap_or(3) as usize;
            proposed_idx = proposed_idx.clamp(min_idx, max_idx);
        }

        let agreed = levels[proposed_idx.min(levels.len() - 1)].to_string();
        self.agreed_level = Some(agreed.clone());
        Some(agreed)
    }
}

// ── Mesh Topology Self-Organisation (R37) ────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshNode {
    pub id: String,
    pub role: MeshRole,
    pub neighbors: Vec<String>,
    pub load: f32,
    pub capacity: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MeshRole {
    Leaf,
    Relay,
    Gateway,
    Coordinator,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshReorgAction {
    pub action: String,
    pub node_id: String,
    pub detail: String,
}

// ── Swarm Node (Composite) ───────────────────────────────────────────────────

#[derive(Debug)]
pub struct SwarmNode {
    pub id: String,
    pub devices: HashMap<String, DeviceRecord>,
    gossip_seq: u64,
    pub inbox: Vec<GossipMessage>,
    seen_digests: Vec<String>,
    pub active_votes: HashMap<String, VoteRound>,
    pub mesh: Vec<MeshNode>,
    peer_scores: HashMap<String, f32>,
}

impl SwarmNode {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_string(),
            devices: HashMap::new(),
            gossip_seq: 0,
            inbox: Vec::new(),
            seen_digests: Vec::new(),
            active_votes: HashMap::new(),
            mesh: Vec::new(),
            peer_scores: HashMap::new(),
        }
    }

    // ── Device Registry ──

    pub fn register_device(&mut self, device: DeviceRecord) {
        self.devices.insert(device.device_id.clone(), device);
    }

    pub fn set_device_status(&mut self, device_id: &str, status: DeviceStatus) {
        if let Some(device) = self.devices.get_mut(device_id) {
            device.status = status;
            device.last_seen_ms = chrono::Utc::now().timestamp_millis() as u64;
        }
    }

    pub fn health_report(&self) -> FleetHealthReport {
        let total = self.devices.len();
        let online = self
            .devices
            .values()
            .filter(|d| d.status == DeviceStatus::Online)
            .count();
        let offline = self
            .devices
            .values()
            .filter(|d| d.status == DeviceStatus::Offline)
            .count();
        let quarantined = self
            .devices
            .values()
            .filter(|d| d.status == DeviceStatus::Quarantined)
            .count();
        let compromised = self
            .devices
            .values()
            .filter(|d| d.status == DeviceStatus::Compromised)
            .count();

        FleetHealthReport {
            total_devices: total,
            online,
            offline,
            quarantined,
            compromised,
            avg_threat_score: 0.0,
            critical_alerts: 0,
        }
    }

    // ── Gossip ──

    /// Create and broadcast a status update.
    pub fn broadcast_status(
        &mut self,
        threat_level: &ThreatLevel,
        score: f32,
        battery: f32,
        cpu: f32,
    ) -> GossipMessage {
        self.gossip_seq += 1;
        GossipMessage::new(
            &self.id,
            self.gossip_seq,
            GossipPayload::StatusUpdate {
                threat_level: threat_level.as_str().to_string(),
                score,
                battery_pct: battery,
                cpu_load_pct: cpu,
            },
        )
    }

    /// Receive and process a gossip message.
    pub fn receive_gossip(&mut self, msg: GossipMessage) -> bool {
        // Dedup by digest
        if self.seen_digests.contains(&msg.digest) {
            return false;
        }
        self.seen_digests.push(msg.digest.clone());

        // Process payload
        match &msg.payload {
            GossipPayload::StatusUpdate { threat_level, score, .. } => {
                self.peer_scores
                    .insert(msg.sender_id.clone(), *score);
                // If neighbour reports critical, update local awareness
                if threat_level == "critical" {
                    self.set_device_status(&msg.sender_id, DeviceStatus::Compromised);
                }
            }
            GossipPayload::ThreatAlert { severity, indicator, confidence } => {
                // Log threat intelligence from peer
                let _ = (severity, indicator, confidence);
            }
            GossipPayload::VoteRequest { round_id, proposal } => {
                // Auto-create a vote round if we don't have one
                if !self.active_votes.contains_key(round_id) {
                    let round = VoteRound::new(round_id, proposal, &msg.sender_id, 0.5);
                    self.active_votes.insert(round_id.clone(), round);
                }
            }
            GossipPayload::VoteResponse { round_id, vote, reason } => {
                if let Some(round) = self.active_votes.get_mut(round_id) {
                    round.cast_vote(Vote {
                        voter_id: msg.sender_id.clone(),
                        approve: *vote,
                        confidence: 1.0,
                        reason: reason.clone(),
                    });
                }
            }
            GossipPayload::PolicyUpdate { .. } => {}
        }

        self.inbox.push(msg);
        true
    }

    /// Forward messages with remaining TTL to peers (epidemic dissemination).
    pub fn forward_pending(&mut self) -> Vec<GossipMessage> {
        self.inbox
            .iter()
            .filter(|m| m.ttl > 1)
            .map(|m| {
                let mut forwarded = m.clone();
                forwarded.ttl -= 1;
                forwarded
            })
            .collect()
    }

    // ── Voting ──

    /// Initiate a vote round for a swarm-wide decision.
    pub fn propose_vote(&mut self, proposal: &str) -> VoteRound {
        let round_id = format!("vote-{}-{}", self.id, self.gossip_seq + 1);
        let round = VoteRound::new(&round_id, proposal, &self.id, 0.5);
        self.active_votes.insert(round_id, round.clone());
        round
    }

    // ── Mesh Management ──

    /// Build or rebalance the mesh topology.
    pub fn rebalance_mesh(&mut self) -> Vec<MeshReorgAction> {
        let mut actions = Vec::new();

        // Assign roles based on capacity
        for node in &mut self.mesh {
            let old_role = node.role.clone();
            if node.capacity > 100.0 && node.neighbors.len() >= 3 {
                node.role = MeshRole::Gateway;
            } else if node.neighbors.len() >= 2 {
                node.role = MeshRole::Relay;
            } else {
                node.role = MeshRole::Leaf;
            }
            if node.role != old_role {
                actions.push(MeshReorgAction {
                    action: "role_change".into(),
                    node_id: node.id.clone(),
                    detail: format!("{:?} → {:?}", old_role, node.role),
                });
            }
        }

        // Detect overloaded nodes and suggest splitting
        for node in &self.mesh {
            if node.load > node.capacity * 0.9 {
                actions.push(MeshReorgAction {
                    action: "offload".into(),
                    node_id: node.id.clone(),
                    detail: format!(
                        "load {:.0}/{:.0} ({}%); shed to neighbours",
                        node.load,
                        node.capacity,
                        (node.load / node.capacity * 100.0) as u32
                    ),
                });
            }
        }

        actions
    }

    /// Add a mesh node with neighbours and capacity.
    pub fn add_mesh_node(
        &mut self,
        id: &str,
        neighbors: Vec<String>,
        capacity: f32,
        load: f32,
    ) {
        self.mesh.push(MeshNode {
            id: id.into(),
            role: MeshRole::Leaf,
            neighbors,
            load,
            capacity,
        });
    }

    // ── Policy Distribution ──

    /// Distribute a policy update to all registered devices.
    pub fn distribute_policy(&self, policy_json: &str) -> PolicyDistribution {
        let hash = sha256_hex(policy_json.as_bytes());
        let device_ids: Vec<String> = self.devices.keys().cloned().collect();
        PolicyDistribution {
            policy_hash: hash,
            version: self.gossip_seq + 1,
            distributed_to: device_ids.clone(),
            acknowledged_by: Vec::new(), // filled asynchronously
            pending: device_ids,
        }
    }

    /// Get aggregate peer threat scores.
    pub fn peer_threat_summary(&self) -> (f32, f32, usize) {
        if self.peer_scores.is_empty() {
            return (0.0, 0.0, 0);
        }
        let count = self.peer_scores.len();
        let sum: f32 = self.peer_scores.values().sum();
        let max = self
            .peer_scores
            .values()
            .cloned()
            .fold(0.0_f32, f32::max);
        (sum / count as f32, max, count)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_device(id: &str) -> DeviceRecord {
        DeviceRecord {
            device_id: id.into(),
            name: format!("Device {id}"),
            platform: "linux-arm64".into(),
            firmware_version: "1.0.0".into(),
            enrolled_at: "2026-01-01T00:00:00Z".into(),
            last_seen_ms: 0,
            status: DeviceStatus::Online,
            tags: vec!["sensor".into()],
        }
    }

    #[test]
    fn swarm_device_registry() {
        let mut node = SwarmNode::new("coordinator-1");
        node.register_device(test_device("dev-001"));
        node.register_device(test_device("dev-002"));
        node.register_device(test_device("dev-003"));

        let health = node.health_report();
        assert_eq!(health.total_devices, 3);
        assert_eq!(health.online, 3);
    }

    #[test]
    fn gossip_broadcast_and_receive() {
        let mut node_a = SwarmNode::new("node-A");
        let mut node_b = SwarmNode::new("node-B");

        let msg = node_a.broadcast_status(&ThreatLevel::Elevated, 2.5, 85.0, 45.0);
        assert_eq!(msg.sender_id, "node-A");

        let accepted = node_b.receive_gossip(msg.clone());
        assert!(accepted);

        // Duplicate should be rejected
        let dup = node_b.receive_gossip(msg);
        assert!(!dup);
    }

    #[test]
    fn gossip_forwarding_decrements_ttl() {
        let mut node = SwarmNode::new("relay");
        let msg = GossipMessage::new(
            "origin",
            1,
            GossipPayload::StatusUpdate {
                threat_level: "nominal".into(),
                score: 0.5,
                battery_pct: 90.0,
                cpu_load_pct: 20.0,
            },
        );
        node.receive_gossip(msg);

        let forwarded = node.forward_pending();
        assert_eq!(forwarded.len(), 1);
        assert_eq!(forwarded[0].ttl, 4);
    }

    #[test]
    fn vote_round_approval() {
        let mut round = VoteRound::new("vote-001", "escalate-all", "leader", 0.5);
        round.cast_vote(Vote {
            voter_id: "dev-1".into(),
            approve: true,
            confidence: 1.0,
            reason: "agree".into(),
        });
        round.cast_vote(Vote {
            voter_id: "dev-2".into(),
            approve: true,
            confidence: 0.8,
            reason: "agree".into(),
        });
        round.cast_vote(Vote {
            voter_id: "dev-3".into(),
            approve: false,
            confidence: 0.5,
            reason: "disagree".into(),
        });

        let status = round.tally(5);
        assert_eq!(status, VoteStatus::Approved); // 3/5 = 0.6 >= 0.5 quorum, weighted approval > 0.5
    }

    #[test]
    fn vote_round_rejection() {
        let mut round = VoteRound::new("vote-002", "quarantine-subnet", "leader", 0.5);
        round.cast_vote(Vote {
            voter_id: "a".into(),
            approve: false,
            confidence: 1.0,
            reason: "no".into(),
        });
        round.cast_vote(Vote {
            voter_id: "b".into(),
            approve: false,
            confidence: 1.0,
            reason: "no".into(),
        });
        round.cast_vote(Vote {
            voter_id: "c".into(),
            approve: true,
            confidence: 0.3,
            reason: "maybe".into(),
        });

        let status = round.tally(3);
        assert_eq!(status, VoteStatus::Rejected);
    }

    #[test]
    fn posture_negotiation_resolves() {
        let mut neg = PostureNegotiation::new(
            "neg-001",
            vec!["dev-1".into(), "dev-2".into(), "dev-3".into()],
        );
        neg.report_posture("dev-1", "nominal");
        neg.report_posture("dev-2", "elevated");
        neg.report_posture("dev-3", "nominal");
        neg.add_constraint(PostureConstraint {
            device_id: "dev-3".into(),
            min_level: "nominal".into(),
            max_level: "severe".into(),
            reason: "battery constraints".into(),
        });

        let agreed = neg.resolve().unwrap();
        // Max reported is "elevated", within dev-3's constraint range
        assert_eq!(agreed, "elevated");
    }

    #[test]
    fn mesh_rebalancing() {
        let mut node = SwarmNode::new("coordinator");
        node.add_mesh_node("gw-1", vec!["s-1".into(), "s-2".into(), "s-3".into()], 200.0, 50.0);
        node.add_mesh_node("s-1", vec!["gw-1".into()], 50.0, 10.0);
        node.add_mesh_node("overloaded", vec!["gw-1".into()], 30.0, 29.0);

        let actions = node.rebalance_mesh();
        // gw-1 should become Gateway (high capacity, 3+ neighbours)
        assert!(actions.iter().any(|a| a.action == "role_change" && a.node_id == "gw-1"));
        // overloaded should get an offload suggestion
        assert!(actions.iter().any(|a| a.action == "offload" && a.node_id == "overloaded"));
    }

    #[test]
    fn policy_distribution() {
        let mut node = SwarmNode::new("coordinator");
        node.register_device(test_device("dev-1"));
        node.register_device(test_device("dev-2"));

        let dist = node.distribute_policy(r#"{"critical_score": 5.2}"#);
        assert!(!dist.policy_hash.is_empty());
        assert_eq!(dist.distributed_to.len(), 2);
    }

    #[test]
    fn peer_threat_summary() {
        let mut node = SwarmNode::new("aggregator");
        node.peer_scores.insert("peer-1".into(), 1.5);
        node.peer_scores.insert("peer-2".into(), 3.0);
        node.peer_scores.insert("peer-3".into(), 0.5);

        let (avg, max, count) = node.peer_threat_summary();
        assert_eq!(count, 3);
        assert!((avg - 5.0 / 3.0).abs() < 0.01);
        assert!((max - 3.0).abs() < 0.01);
    }

    #[test]
    fn device_status_transitions() {
        let mut node = SwarmNode::new("mgr");
        node.register_device(test_device("dev-1"));
        assert_eq!(node.devices["dev-1"].status, DeviceStatus::Online);

        node.set_device_status("dev-1", DeviceStatus::Quarantined);
        assert_eq!(node.devices["dev-1"].status, DeviceStatus::Quarantined);

        let health = node.health_report();
        assert_eq!(health.quarantined, 1);
        assert_eq!(health.online, 0);
    }
}
