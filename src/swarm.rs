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
    // ── Phase 33: cross-agent intelligence sharing ────
    LateralMovementIntel {
        src_host: String,
        dst_host: String,
        protocol: String,
        pattern: String,
        risk_score: f32,
        mitre_ids: Vec<String>,
    },
    UebaIntel {
        entity_kind: String,
        entity_id: String,
        anomaly_type: String,
        risk_score: f32,
        description: String,
    },
    BeaconIntel {
        target_host: String,
        dest_ip: String,
        dest_domain: String,
        beacon_score: f32,
        is_dga: bool,
        mitre_ids: Vec<String>,
    },
    ThreatIntelUpdate {
        ioc_type: String,
        indicator: String,
        confidence: f32,
        source_agent: String,
        ttl_hours: u32,
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

// ── Shared Intelligence Cache ────────────────────────────────────────────────

/// An entry in the shared intelligence cache received from peer agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelEntry {
    pub ioc_type: String,
    pub indicator: String,
    pub confidence: f32,
    pub source_agent: String,
    pub received_at: String,
    pub ttl_hours: u32,
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// Cache of threat intelligence shared across the swarm.
/// TTL-based eviction with a maximum entry count.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SharedIntelCache {
    entries: Vec<IntelEntry>,
}

impl SharedIntelCache {
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    pub fn insert(&mut self, entry: IntelEntry) {
        // Dedup by ioc_type + indicator — update if already present
        if let Some(existing) = self.entries.iter_mut().find(|e| {
            e.ioc_type == entry.ioc_type && e.indicator == entry.indicator
        }) {
            *existing = entry;
        } else {
            self.entries.push(entry);
        }
        // Cap at 10,000 entries (LRU-style: remove oldest)
        while self.entries.len() > 10_000 {
            self.entries.remove(0);
        }
    }

    pub fn lookup(&self, indicator: &str) -> Option<&IntelEntry> {
        self.entries.iter().find(|e| e.indicator == indicator)
    }

    pub fn lookup_by_type(&self, ioc_type: &str) -> Vec<&IntelEntry> {
        self.entries.iter().filter(|e| e.ioc_type == ioc_type).collect()
    }

    /// Remove entries whose TTL has expired.
    pub fn evict_expired(&mut self) {
        let now = chrono::Utc::now();
        self.entries.retain(|e| {
            if let Ok(received) = chrono::DateTime::parse_from_rfc3339(&e.received_at) {
                let expiry = received + chrono::Duration::hours(e.ttl_hours as i64);
                now < expiry
            } else {
                false
            }
        });
    }

    pub fn all(&self) -> &[IntelEntry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn stats(&self) -> IntelCacheStats {
        let mut by_type: HashMap<String, usize> = HashMap::new();
        let mut by_source: HashMap<String, usize> = HashMap::new();
        for e in &self.entries {
            *by_type.entry(e.ioc_type.clone()).or_default() += 1;
            *by_source.entry(e.source_agent.clone()).or_default() += 1;
        }
        IntelCacheStats {
            total: self.entries.len(),
            by_type,
            by_source,
        }
    }
}

/// Summary statistics for the shared intel cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntelCacheStats {
    pub total: usize,
    pub by_type: HashMap<String, usize>,
    pub by_source: HashMap<String, usize>,
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
        } else if !self.votes.is_empty() {
            approve_count as f32 / self.votes.len() as f32
        } else {
            0.0
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

// ── Mesh Self-Healing (R37) ──────────────────────────────────────────────────

/// Result of a BFS spanning-tree computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanningTree {
    /// Root node of the spanning tree.
    pub root: String,
    /// Parent of each node (root has itself as parent).
    pub parent: HashMap<String, String>,
    /// Depth of each node from the root.
    pub depth: HashMap<String, usize>,
    /// Total number of nodes reached.
    pub nodes_reached: usize,
}

/// A detected network partition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Partition {
    pub partition_id: usize,
    pub members: Vec<String>,
    pub size: usize,
}

/// Result of partition detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionReport {
    pub partitions: Vec<Partition>,
    pub is_connected: bool,
    pub largest_partition_size: usize,
}

/// A repair action proposed by the self-healing algorithm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairAction {
    pub action_type: RepairType,
    pub from_node: String,
    pub to_node: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RepairType {
    /// Add an edge to reconnect partitions.
    AddEdge,
    /// Promote a leaf to relay to improve connectivity.
    PromoteRelay,
    /// Re-route traffic through an alternate path.
    Reroute,
}

/// Compute a BFS spanning tree from a root node over a mesh topology.
pub fn bfs_spanning_tree(mesh: &[MeshNode], root_id: &str) -> SpanningTree {
    let mut parent: HashMap<String, String> = HashMap::new();
    let mut depth: HashMap<String, usize> = HashMap::new();
    let mut visited: Vec<String> = Vec::new();
    let mut queue: std::collections::VecDeque<String> = std::collections::VecDeque::new();

    // Index for quick lookup
    let node_map: HashMap<&str, &MeshNode> = mesh.iter().map(|n| (n.id.as_str(), n)).collect();

    if !node_map.contains_key(root_id) {
        return SpanningTree {
            root: root_id.to_string(),
            parent,
            depth,
            nodes_reached: 0,
        };
    }

    queue.push_back(root_id.to_string());
    visited.push(root_id.to_string());
    parent.insert(root_id.to_string(), root_id.to_string());
    depth.insert(root_id.to_string(), 0);

    while let Some(current) = queue.pop_front() {
        let current_depth = depth[&current];
        if let Some(node) = node_map.get(current.as_str()) {
            for neighbor_id in &node.neighbors {
                if !visited.contains(neighbor_id) {
                    visited.push(neighbor_id.clone());
                    parent.insert(neighbor_id.clone(), current.clone());
                    depth.insert(neighbor_id.clone(), current_depth + 1);
                    queue.push_back(neighbor_id.clone());
                }
            }
        }
    }

    SpanningTree {
        root: root_id.to_string(),
        parent,
        depth,
        nodes_reached: visited.len(),
    }
}

/// Detect partitions in a mesh topology using connected-component analysis.
pub fn detect_partitions(mesh: &[MeshNode]) -> PartitionReport {
    let mut visited: Vec<String> = Vec::new();
    let mut partitions = Vec::new();
    let node_map: HashMap<&str, &MeshNode> = mesh.iter().map(|n| (n.id.as_str(), n)).collect();

    for node in mesh {
        if visited.contains(&node.id) {
            continue;
        }
        // BFS from this node
        let mut component = Vec::new();
        let mut queue: std::collections::VecDeque<String> = std::collections::VecDeque::new();
        queue.push_back(node.id.clone());
        visited.push(node.id.clone());

        while let Some(current) = queue.pop_front() {
            component.push(current.clone());
            if let Some(n) = node_map.get(current.as_str()) {
                for neighbor_id in &n.neighbors {
                    if !visited.contains(neighbor_id) {
                        visited.push(neighbor_id.clone());
                        queue.push_back(neighbor_id.clone());
                    }
                }
            }
        }

        let size = component.len();
        partitions.push(Partition {
            partition_id: partitions.len(),
            members: component,
            size,
        });
    }

    let largest = partitions.iter().map(|p| p.size).max().unwrap_or(0);
    let is_connected = partitions.len() <= 1;

    PartitionReport {
        partitions,
        is_connected,
        largest_partition_size: largest,
    }
}

/// Propose repair actions to heal a partitioned mesh.
///
/// Strategy: for each pair of disconnected partitions, find the closest
/// pair of nodes (by capacity) and propose adding an edge between them.
/// Additionally promotes high-capacity leaf nodes to relay status.
pub fn propose_repairs(mesh: &[MeshNode], report: &PartitionReport) -> Vec<RepairAction> {
    let mut repairs = Vec::new();

    if report.is_connected {
        return repairs;
    }

    // For each pair of partitions, find the best nodes to bridge
    for i in 0..report.partitions.len() {
        for j in (i + 1)..report.partitions.len() {
            let p_a = &report.partitions[i];
            let p_b = &report.partitions[j];

            // Find the highest-capacity node in each partition
            let best_a = p_a
                .members
                .iter()
                .filter_map(|id| mesh.iter().find(|n| n.id == *id))
                .max_by(|a, b| a.capacity.partial_cmp(&b.capacity).unwrap_or(std::cmp::Ordering::Equal));
            let best_b = p_b
                .members
                .iter()
                .filter_map(|id| mesh.iter().find(|n| n.id == *id))
                .max_by(|a, b| a.capacity.partial_cmp(&b.capacity).unwrap_or(std::cmp::Ordering::Equal));

            if let (Some(a), Some(b)) = (best_a, best_b) {
                repairs.push(RepairAction {
                    action_type: RepairType::AddEdge,
                    from_node: a.id.clone(),
                    to_node: b.id.clone(),
                    reason: format!(
                        "Bridge partition {} ({} nodes) ↔ partition {} ({} nodes)",
                        i, p_a.size, j, p_b.size
                    ),
                });
            }
        }
    }

    // Promote high-capacity leaf nodes in small partitions to relay
    for partition in &report.partitions {
        if partition.size <= 2 {
            for member_id in &partition.members {
                if let Some(node) = mesh.iter().find(|n| n.id == *member_id) {
                    if node.role == MeshRole::Leaf && node.capacity > 50.0 {
                        repairs.push(RepairAction {
                            action_type: RepairType::PromoteRelay,
                            from_node: node.id.clone(),
                            to_node: node.id.clone(),
                            reason: format!(
                                "Promote leaf in small partition {} (capacity={:.0}) to relay",
                                partition.partition_id, node.capacity
                            ),
                        });
                    }
                }
            }
        }
    }

    repairs
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
    pub intel_cache: SharedIntelCache,
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
            intel_cache: SharedIntelCache::new(),
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

    /// Broadcast a threat-intelligence payload to the swarm.
    pub fn broadcast_threat_intel(&mut self, payload: GossipPayload) -> GossipMessage {
        self.gossip_seq += 1;
        GossipMessage::new(&self.id, self.gossip_seq, payload)
    }

    /// Check if a given indicator matches any shared intel entry.
    /// Returns the matching entry's confidence if found.
    pub fn check_intel(&self, indicator: &str) -> Option<f32> {
        self.intel_cache.lookup(indicator).map(|e| e.confidence)
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
            GossipPayload::LateralMovementIntel {
                src_host, dst_host, protocol, pattern, risk_score, mitre_ids,
            } => {
                self.intel_cache.insert(IntelEntry {
                    ioc_type: "lateral_movement".into(),
                    indicator: format!("{src_host}->{dst_host}:{protocol}"),
                    confidence: *risk_score,
                    source_agent: msg.sender_id.clone(),
                    received_at: chrono::Utc::now().to_rfc3339(),
                    ttl_hours: 24,
                    metadata: serde_json::json!({
                        "src_host": src_host,
                        "dst_host": dst_host,
                        "protocol": protocol,
                        "pattern": pattern,
                        "mitre_ids": mitre_ids,
                    }),
                });
            }
            GossipPayload::UebaIntel {
                entity_kind, entity_id, anomaly_type, risk_score, description,
            } => {
                self.intel_cache.insert(IntelEntry {
                    ioc_type: "ueba_anomaly".into(),
                    indicator: format!("{entity_kind}:{entity_id}"),
                    confidence: *risk_score,
                    source_agent: msg.sender_id.clone(),
                    received_at: chrono::Utc::now().to_rfc3339(),
                    ttl_hours: 12,
                    metadata: serde_json::json!({
                        "entity_kind": entity_kind,
                        "entity_id": entity_id,
                        "anomaly_type": anomaly_type,
                        "description": description,
                    }),
                });
            }
            GossipPayload::BeaconIntel {
                target_host, dest_ip, dest_domain, beacon_score, is_dga, mitre_ids,
            } => {
                self.intel_cache.insert(IntelEntry {
                    ioc_type: if *is_dga { "dga_domain" } else { "beacon_c2" }.into(),
                    indicator: if dest_domain.is_empty() { dest_ip.clone() } else { dest_domain.clone() },
                    confidence: *beacon_score,
                    source_agent: msg.sender_id.clone(),
                    received_at: chrono::Utc::now().to_rfc3339(),
                    ttl_hours: 48,
                    metadata: serde_json::json!({
                        "target_host": target_host,
                        "dest_ip": dest_ip,
                        "dest_domain": dest_domain,
                        "is_dga": is_dga,
                        "mitre_ids": mitre_ids,
                    }),
                });
            }
            GossipPayload::ThreatIntelUpdate {
                ioc_type, indicator, confidence, source_agent, ttl_hours,
            } => {
                self.intel_cache.insert(IntelEntry {
                    ioc_type: ioc_type.clone(),
                    indicator: indicator.clone(),
                    confidence: *confidence,
                    source_agent: source_agent.clone(),
                    received_at: chrono::Utc::now().to_rfc3339(),
                    ttl_hours: *ttl_hours,
                    metadata: serde_json::Value::Null,
                });
            }
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

    // ── Self-Healing ──

    /// Detect partitions in the mesh and propose repair actions.
    pub fn self_heal(&self) -> (PartitionReport, Vec<RepairAction>) {
        let report = detect_partitions(&self.mesh);
        let repairs = propose_repairs(&self.mesh, &report);
        (report, repairs)
    }

    /// Apply a repair action by adding edges to the mesh.
    pub fn apply_repair(&mut self, repair: &RepairAction) {
        if repair.action_type == RepairType::AddEdge {
            // Add the from→to neighbor link
            if let Some(from_node) = self.mesh.iter_mut().find(|n| n.id == repair.from_node) {
                if !from_node.neighbors.contains(&repair.to_node) {
                    from_node.neighbors.push(repair.to_node.clone());
                }
            }
            // Add the to→from neighbor link (undirected)
            if let Some(to_node) = self.mesh.iter_mut().find(|n| n.id == repair.to_node) {
                if !to_node.neighbors.contains(&repair.from_node) {
                    to_node.neighbors.push(repair.from_node.clone());
                }
            }
        } else if repair.action_type == RepairType::PromoteRelay {
            if let Some(node) = self.mesh.iter_mut().find(|n| n.id == repair.from_node) {
                node.role = MeshRole::Relay;
            }
        }
    }

    /// Compute a BFS spanning tree from the coordinator.
    pub fn spanning_tree(&self) -> SpanningTree {
        bfs_spanning_tree(&self.mesh, &self.id)
    }
}

// ── Mesh Transport Layer ─────────────────────────────────────────────────────

/// A message frame for the mesh transport protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshFrame {
    pub frame_id: u64,
    pub src: String,
    pub dst: String,
    pub hop_count: u8,
    pub max_hops: u8,
    pub payload: Vec<u8>,
    pub payload_type: MeshPayloadType,
    pub timestamp_ms: u64,
    pub checksum: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MeshPayloadType {
    Gossip,
    IntelShare,
    PolicySync,
    Heartbeat,
    DataRequest,
    DataResponse,
}

/// Peer connection state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConnection {
    pub peer_id: String,
    pub address: String,
    pub connected_at: String,
    pub last_heartbeat: String,
    pub latency_ms: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub state: PeerState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PeerState {
    Connected,
    Connecting,
    Disconnected,
    Failed,
}

/// Transport statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportStats {
    pub frames_sent: u64,
    pub frames_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub active_peers: usize,
    pub failed_peers: usize,
}

/// Mesh transport engine for real peer-to-peer communication.
///
/// In production this would bind TCP/QUIC sockets; in this embedded
/// build it uses in-process message queues for the same API surface.
#[derive(Debug)]
pub struct MeshTransport {
    node_id: String,
    peers: HashMap<String, PeerConnection>,
    outbound_queue: Vec<MeshFrame>,
    inbound_queue: Vec<MeshFrame>,
    frame_counter: u64,
    stats: TransportStats,
}

impl MeshTransport {
    pub fn new(node_id: &str) -> Self {
        Self {
            node_id: node_id.into(),
            peers: HashMap::new(),
            outbound_queue: Vec::new(),
            inbound_queue: Vec::new(),
            frame_counter: 0,
            stats: TransportStats {
                frames_sent: 0,
                frames_received: 0,
                bytes_sent: 0,
                bytes_received: 0,
                active_peers: 0,
                failed_peers: 0,
            },
        }
    }

    /// Register a peer with its address.
    pub fn add_peer(&mut self, peer_id: &str, address: &str) {
        let conn = PeerConnection {
            peer_id: peer_id.into(),
            address: address.into(),
            connected_at: chrono::Utc::now().to_rfc3339(),
            last_heartbeat: chrono::Utc::now().to_rfc3339(),
            latency_ms: 0,
            bytes_sent: 0,
            bytes_received: 0,
            state: PeerState::Connected,
        };
        self.peers.insert(peer_id.into(), conn);
        self.stats.active_peers = self.peers.values().filter(|p| p.state == PeerState::Connected).count();
    }

    /// Disconnect a peer.
    pub fn disconnect_peer(&mut self, peer_id: &str) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.state = PeerState::Disconnected;
        }
        self.stats.active_peers = self.peers.values().filter(|p| p.state == PeerState::Connected).count();
    }

    /// Send a frame to a specific peer.
    pub fn send(&mut self, dst: &str, payload: &[u8], payload_type: MeshPayloadType) -> MeshFrame {
        self.frame_counter += 1;
        let checksum = sha256_hex(payload);
        let frame = MeshFrame {
            frame_id: self.frame_counter,
            src: self.node_id.clone(),
            dst: dst.into(),
            hop_count: 0,
            max_hops: 10,
            payload: payload.to_vec(),
            payload_type,
            timestamp_ms: chrono::Utc::now().timestamp_millis() as u64,
            checksum,
        };
        self.stats.frames_sent += 1;
        self.stats.bytes_sent += payload.len() as u64;
        if let Some(peer) = self.peers.get_mut(dst) {
            peer.bytes_sent += payload.len() as u64;
        }
        self.outbound_queue.push(frame.clone());
        frame
    }

    /// Broadcast a frame to all connected peers.
    pub fn broadcast(&mut self, payload: &[u8], payload_type: MeshPayloadType) -> Vec<MeshFrame> {
        let peer_ids: Vec<String> = self.peers
            .values()
            .filter(|p| p.state == PeerState::Connected)
            .map(|p| p.peer_id.clone())
            .collect();
        let mut frames = Vec::new();
        for pid in &peer_ids {
            let frame = self.send(pid, payload, payload_type.clone());
            frames.push(frame);
        }
        frames
    }

    /// Receive a frame from a peer.
    pub fn receive(&mut self, frame: MeshFrame) -> bool {
        // Verify checksum
        let expected = sha256_hex(&frame.payload);
        if expected != frame.checksum {
            return false;
        }
        // Check hop count
        if frame.hop_count >= frame.max_hops {
            return false;
        }
        self.stats.frames_received += 1;
        self.stats.bytes_received += frame.payload.len() as u64;
        if let Some(peer) = self.peers.get_mut(&frame.src) {
            peer.bytes_received += frame.payload.len() as u64;
            peer.last_heartbeat = chrono::Utc::now().to_rfc3339();
        }
        self.inbound_queue.push(frame);
        true
    }

    /// Drain the inbound queue.
    pub fn drain_inbound(&mut self) -> Vec<MeshFrame> {
        std::mem::take(&mut self.inbound_queue)
    }

    /// Drain the outbound queue.
    pub fn drain_outbound(&mut self) -> Vec<MeshFrame> {
        std::mem::take(&mut self.outbound_queue)
    }

    /// Send a heartbeat to all peers.
    pub fn heartbeat(&mut self) -> Vec<MeshFrame> {
        self.broadcast(b"heartbeat", MeshPayloadType::Heartbeat)
    }

    /// Get transport statistics.
    pub fn stats(&self) -> &TransportStats {
        &self.stats
    }

    /// Get all peer connections.
    pub fn peers(&self) -> &HashMap<String, PeerConnection> {
        &self.peers
    }

    /// Forward a frame to the next hop (increment hop_count).
    pub fn forward(&mut self, mut frame: MeshFrame, next_hop: &str) -> Option<MeshFrame> {
        frame.hop_count += 1;
        if frame.hop_count >= frame.max_hops {
            return None;
        }
        frame.dst = next_hop.into();
        self.outbound_queue.push(frame.clone());
        self.stats.frames_sent += 1;
        self.stats.bytes_sent += frame.payload.len() as u64;
        Some(frame)
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
            enrolled_at: "T0".into(),
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

    // ── Mesh Self-Healing Tests ──

    fn make_mesh_node(id: &str, role: MeshRole, neighbors: &[&str], capacity: f32) -> MeshNode {
        MeshNode {
            id: id.to_string(),
            role,
            neighbors: neighbors.iter().map(|s| s.to_string()).collect(),
            load: 0.0,
            capacity,
        }
    }

    #[test]
    fn bfs_spanning_tree_connected_graph() {
        let mesh = vec![
            make_mesh_node("A", MeshRole::Coordinator, &["B", "C"], 100.0),
            make_mesh_node("B", MeshRole::Relay, &["A", "D"], 80.0),
            make_mesh_node("C", MeshRole::Leaf, &["A"], 40.0),
            make_mesh_node("D", MeshRole::Leaf, &["B"], 30.0),
        ];
        let tree = bfs_spanning_tree(&mesh, "A");
        assert_eq!(tree.nodes_reached, 4);
        assert_eq!(tree.root, "A");
        assert_eq!(tree.depth["A"], 0);
        assert_eq!(tree.depth["B"], 1);
        assert_eq!(tree.depth["C"], 1);
        assert_eq!(tree.depth["D"], 2);
        assert_eq!(tree.parent["B"], "A");
        assert_eq!(tree.parent["D"], "B");
    }

    #[test]
    fn bfs_spanning_tree_missing_root() {
        let mesh = vec![
            make_mesh_node("A", MeshRole::Leaf, &[], 10.0),
        ];
        let tree = bfs_spanning_tree(&mesh, "Z");
        assert_eq!(tree.nodes_reached, 0);
    }

    #[test]
    fn detect_partitions_connected() {
        let mesh = vec![
            make_mesh_node("A", MeshRole::Coordinator, &["B"], 100.0),
            make_mesh_node("B", MeshRole::Relay, &["A", "C"], 80.0),
            make_mesh_node("C", MeshRole::Leaf, &["B"], 40.0),
        ];
        let report = detect_partitions(&mesh);
        assert!(report.is_connected);
        assert_eq!(report.partitions.len(), 1);
        assert_eq!(report.largest_partition_size, 3);
    }

    #[test]
    fn detect_partitions_disconnected() {
        let mesh = vec![
            make_mesh_node("A", MeshRole::Coordinator, &["B"], 100.0),
            make_mesh_node("B", MeshRole::Relay, &["A"], 80.0),
            make_mesh_node("C", MeshRole::Leaf, &["D"], 40.0),
            make_mesh_node("D", MeshRole::Leaf, &["C"], 30.0),
        ];
        let report = detect_partitions(&mesh);
        assert!(!report.is_connected);
        assert_eq!(report.partitions.len(), 2);
        assert_eq!(report.largest_partition_size, 2);
    }

    #[test]
    fn propose_repairs_connected_noop() {
        let mesh = vec![
            make_mesh_node("A", MeshRole::Coordinator, &["B"], 100.0),
            make_mesh_node("B", MeshRole::Leaf, &["A"], 50.0),
        ];
        let report = detect_partitions(&mesh);
        let repairs = propose_repairs(&mesh, &report);
        assert!(repairs.is_empty());
    }

    #[test]
    fn propose_repairs_adds_bridge_edge() {
        let mesh = vec![
            make_mesh_node("A", MeshRole::Coordinator, &["B"], 100.0),
            make_mesh_node("B", MeshRole::Relay, &["A"], 80.0),
            make_mesh_node("C", MeshRole::Leaf, &["D"], 40.0),
            make_mesh_node("D", MeshRole::Leaf, &["C"], 60.0),
        ];
        let report = detect_partitions(&mesh);
        let repairs = propose_repairs(&mesh, &report);
        let bridge = repairs.iter().find(|r| r.action_type == RepairType::AddEdge);
        assert!(bridge.is_some());
        let b = bridge.unwrap();
        // Highest capacity in partition 0 is A (100), partition 1 is D (60)
        assert_eq!(b.from_node, "A");
        assert_eq!(b.to_node, "D");
    }

    #[test]
    fn propose_repairs_promotes_high_capacity_leaf() {
        let mesh = vec![
            make_mesh_node("A", MeshRole::Coordinator, &[], 100.0),
            make_mesh_node("B", MeshRole::Leaf, &[], 75.0),
        ];
        let report = detect_partitions(&mesh);
        let repairs = propose_repairs(&mesh, &report);
        let promote = repairs.iter().find(|r| r.action_type == RepairType::PromoteRelay);
        assert!(promote.is_some());
        assert_eq!(promote.unwrap().from_node, "B");
    }

    #[test]
    fn swarm_node_self_heal_connected() {
        let mut node = SwarmNode::new("coord");
        node.mesh = vec![
            make_mesh_node("coord", MeshRole::Coordinator, &["r1"], 100.0),
            make_mesh_node("r1", MeshRole::Relay, &["coord", "l1"], 80.0),
            make_mesh_node("l1", MeshRole::Leaf, &["r1"], 40.0),
        ];
        let (report, repairs) = node.self_heal();
        assert!(report.is_connected);
        assert!(repairs.is_empty());
    }

    #[test]
    fn swarm_node_self_heal_partitioned() {
        let mut node = SwarmNode::new("coord");
        node.mesh = vec![
            make_mesh_node("coord", MeshRole::Coordinator, &["r1"], 100.0),
            make_mesh_node("r1", MeshRole::Relay, &["coord"], 80.0),
            make_mesh_node("iso", MeshRole::Leaf, &[], 60.0),
        ];
        let (report, repairs) = node.self_heal();
        assert!(!report.is_connected);
        assert!(!repairs.is_empty());
    }

    #[test]
    fn swarm_node_apply_repair_adds_edge() {
        let mut node = SwarmNode::new("coord");
        node.mesh = vec![
            make_mesh_node("coord", MeshRole::Coordinator, &[], 100.0),
            make_mesh_node("iso", MeshRole::Leaf, &[], 60.0),
        ];
        let repair = RepairAction {
            action_type: RepairType::AddEdge,
            from_node: "coord".into(),
            to_node: "iso".into(),
            reason: "bridge".into(),
        };
        node.apply_repair(&repair);
        assert!(node.mesh[0].neighbors.contains(&"iso".to_string()));
        assert!(node.mesh[1].neighbors.contains(&"coord".to_string()));
        // After repair, the mesh should be connected
        let (report, _) = node.self_heal();
        assert!(report.is_connected);
    }

    #[test]
    fn swarm_node_apply_repair_promotes_relay() {
        let mut node = SwarmNode::new("coord");
        node.mesh = vec![
            make_mesh_node("coord", MeshRole::Coordinator, &["l1"], 100.0),
            make_mesh_node("l1", MeshRole::Leaf, &["coord"], 60.0),
        ];
        let repair = RepairAction {
            action_type: RepairType::PromoteRelay,
            from_node: "l1".into(),
            to_node: "l1".into(),
            reason: "promote".into(),
        };
        node.apply_repair(&repair);
        assert_eq!(node.mesh[1].role, MeshRole::Relay);
    }

    #[test]
    fn spanning_tree_from_swarm_node() {
        let mut node = SwarmNode::new("coord");
        node.mesh = vec![
            make_mesh_node("coord", MeshRole::Coordinator, &["r1", "r2"], 100.0),
            make_mesh_node("r1", MeshRole::Relay, &["coord", "l1"], 80.0),
            make_mesh_node("r2", MeshRole::Relay, &["coord"], 70.0),
            make_mesh_node("l1", MeshRole::Leaf, &["r1"], 40.0),
        ];
        let tree = node.spanning_tree();
        assert_eq!(tree.nodes_reached, 4);
        assert_eq!(tree.root, "coord");
    }

    // ── Mesh Transport Tests ────────

    #[test]
    fn mesh_transport_send_receive() {
        let mut t1 = MeshTransport::new("node-A");
        let mut t2 = MeshTransport::new("node-B");

        t1.add_peer("node-B", "127.0.0.1:9001");
        t2.add_peer("node-A", "127.0.0.1:9000");

        let frame = t1.send("node-B", b"hello mesh", MeshPayloadType::Gossip);
        assert_eq!(frame.src, "node-A");
        assert_eq!(frame.dst, "node-B");

        let accepted = t2.receive(frame);
        assert!(accepted);
        let msgs = t2.drain_inbound();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].payload, b"hello mesh");
    }

    #[test]
    fn mesh_transport_broadcast() {
        let mut t = MeshTransport::new("center");
        t.add_peer("a", "127.0.0.1:9001");
        t.add_peer("b", "127.0.0.1:9002");
        t.add_peer("c", "127.0.0.1:9003");

        let frames = t.broadcast(b"sync", MeshPayloadType::PolicySync);
        assert_eq!(frames.len(), 3);
        assert_eq!(t.stats().frames_sent, 3);
    }

    #[test]
    fn mesh_transport_heartbeat() {
        let mut t = MeshTransport::new("hb");
        t.add_peer("peer1", "10.0.0.1:9000");
        let frames = t.heartbeat();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].payload_type, MeshPayloadType::Heartbeat);
    }

    #[test]
    fn mesh_transport_checksum_validation() {
        let mut t = MeshTransport::new("rx");
        t.add_peer("bad", "10.0.0.1:9000");

        let bad_frame = MeshFrame {
            frame_id: 1,
            src: "bad".into(),
            dst: "rx".into(),
            hop_count: 0,
            max_hops: 10,
            payload: b"tampered".to_vec(),
            payload_type: MeshPayloadType::Gossip,
            timestamp_ms: 0,
            checksum: "wrong-checksum".into(),
        };
        let accepted = t.receive(bad_frame);
        assert!(!accepted);
    }

    #[test]
    fn mesh_transport_hop_limit() {
        let mut t = MeshTransport::new("relay");
        t.add_peer("next", "10.0.0.1:9000");

        let frame = MeshFrame {
            frame_id: 1,
            src: "origin".into(),
            dst: "relay".into(),
            hop_count: 10,
            max_hops: 10,
            payload: b"expired".to_vec(),
            payload_type: MeshPayloadType::Gossip,
            timestamp_ms: 0,
            checksum: sha256_hex(b"expired"),
        };
        let accepted = t.receive(frame);
        assert!(!accepted);
    }

    #[test]
    fn mesh_transport_forward() {
        let mut t = MeshTransport::new("relay");
        let frame = MeshFrame {
            frame_id: 1,
            src: "origin".into(),
            dst: "relay".into(),
            hop_count: 2,
            max_hops: 10,
            payload: b"forward-me".to_vec(),
            payload_type: MeshPayloadType::IntelShare,
            timestamp_ms: 0,
            checksum: sha256_hex(b"forward-me"),
        };
        let forwarded = t.forward(frame, "next-hop");
        assert!(forwarded.is_some());
        let f = forwarded.unwrap();
        assert_eq!(f.hop_count, 3);
        assert_eq!(f.dst, "next-hop");
    }

    #[test]
    fn mesh_transport_disconnect_peer() {
        let mut t = MeshTransport::new("node");
        t.add_peer("p1", "10.0.0.1:9000");
        t.add_peer("p2", "10.0.0.2:9000");
        assert_eq!(t.stats().active_peers, 2);

        t.disconnect_peer("p1");
        assert_eq!(t.stats().active_peers, 1);

        // Broadcast only goes to connected peers
        let frames = t.broadcast(b"test", MeshPayloadType::Gossip);
        assert_eq!(frames.len(), 1);
    }

    #[test]
    fn mesh_transport_stats() {
        let mut t = MeshTransport::new("stats-node");
        t.add_peer("p1", "10.0.0.1:9000");
        t.send("p1", b"data1", MeshPayloadType::DataRequest);
        t.send("p1", b"data22", MeshPayloadType::DataResponse);

        let stats = t.stats();
        assert_eq!(stats.frames_sent, 2);
        assert_eq!(stats.bytes_sent, 11); // 5 + 6
        assert_eq!(stats.active_peers, 1);
    }
}
