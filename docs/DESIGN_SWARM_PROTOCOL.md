# Swarm Coordination Protocol Sketch

Design document for cross-device coordination, covering R03 (swarm intelligence), R08 (privacy-preserving coordinated response), R15 (threat intelligence sharing), and R23 (verifiable swarm defense).

## Goals

1. Let devices share partial threat signals without exposing raw telemetry.
2. Aggregate low-confidence evidence across a fleet to detect distributed attacks.
3. Coordinate collective defensive actions (quarantine, isolation) without a central controller.
4. Prove that aggregation and voting were performed honestly.

## Non-goals (for the initial protocol)

- Real-time sub-millisecond coordination (edge devices tolerate seconds-scale latency).
- Full Byzantine fault tolerance against >1/3 compromised nodes.
- Cross-vendor interoperability (initial protocol targets SentinelEdge-to-SentinelEdge).

## Architecture overview

```
┌─────────┐     ┌─────────┐     ┌─────────┐
│ Node A  │────▶│  Swarm  │◀────│ Node C  │
│ Detector│     │  Relay  │     │ Detector│
└────┬────┘     └────┬────┘     └────┬────┘
     │               │               │
     ▼               ▼               ▼
  Local           Aggregate       Local
  Score           + Vote          Score
```

### Components

| Component | Responsibility | Module |
|-----------|---------------|--------|
| **ThreatDigest** | Compact summary of local anomaly state (no raw telemetry) | `swarm::digest` |
| **SwarmRelay** | Gossip-based message relay using UDP multicast or mDNS | `swarm::relay` |
| **AggregationEngine** | Combine digests from multiple nodes into a fleet-level signal | `swarm::aggregation` |
| **VoteCoordinator** | Threshold-based voting on collective defensive actions | `swarm::vote` |
| **ProvenanceChain** | Signed provenance for shared threat indicators | `swarm::provenance` |

## Data structures

### ThreatDigest

A privacy-preserving summary that a node broadcasts to the swarm. Contains no raw telemetry values.

```rust
/// Compact threat summary — no raw sample data.
pub struct ThreatDigest {
    /// Node identity (public key hash).
    pub node_id: [u8; 32],
    /// Monotonic sequence number for replay protection.
    pub seq: u64,
    /// Timestamp of the digest window (epoch ms).
    pub window_end_ms: u64,
    /// Number of samples in the window.
    pub sample_count: u32,
    /// Maximum anomaly score observed in the window.
    pub max_score: f32,
    /// Number of alerts (non-nominal decisions) in the window.
    pub alert_count: u32,
    /// Bitfield indicating which signal dimensions contributed.
    /// Bits 0-7: cpu, mem, temp, net, auth, drift, procs, disk.
    pub suspicious_dims: u8,
    /// SHA-256 of the serialized digest for integrity.
    pub digest_hash: [u8; 32],
    /// Ed25519 signature by the node's private key.
    pub signature: [u8; 64],
}
```

### SwarmVote

A signed vote on whether to trigger a collective defensive action.

```rust
pub enum VoteDecision {
    Observe,
    CollectiveThrottle,
    CollectiveQuarantine,
    CollectiveIsolate,
}

pub struct SwarmVote {
    /// Which collective action is being proposed.
    pub proposal_id: [u8; 32],
    /// The voter's node identity.
    pub node_id: [u8; 32],
    /// Vote decision.
    pub decision: VoteDecision,
    /// Justification: the voter's max observed score.
    pub evidence_score: f32,
    /// Ed25519 signature.
    pub signature: [u8; 64],
}
```

### SharedIndicator

A threat indicator shared across the fleet with signed provenance.

```rust
pub struct SharedIndicator {
    /// What kind of threat pattern was observed.
    pub indicator_type: IndicatorType,
    /// Compact pattern description (no raw data).
    pub pattern_hash: [u8; 32],
    /// Confidence score (0.0–1.0).
    pub confidence: f32,
    /// Originating node.
    pub source_node: [u8; 32],
    /// Chain of custody: list of (node_id, timestamp, signature).
    pub provenance: Vec<ProvenanceEntry>,
}

pub enum IndicatorType {
    AuthStorm,
    IntegrityDrift,
    ResourceExhaustion,
    NetworkAnomaly,
    Custom(u16),
}
```

## Protocol phases

### Phase 1 — Digest gossip

1. Each node computes a `ThreatDigest` at the end of every detection window (e.g., every 60 seconds or every N samples).
2. The digest is signed with the node's Ed25519 private key.
3. The digest is broadcast to local-network peers via UDP multicast.
4. Receiving nodes verify the signature and sequence number (reject replays).
5. Each node maintains a bounded map of recent digests from peers (`HashMap<NodeId, VecDeque<ThreatDigest>>`).

### Phase 2 — Fleet-level aggregation

1. Each node independently aggregates received digests.
2. Aggregation logic:
   - `fleet_alert_ratio = sum(peer.alert_count) / sum(peer.sample_count)`
   - `fleet_max_score = max(peer.max_score for all peers)`
   - `correlated_dims = bitwise OR of all peer.suspicious_dims`
   - Alarm if `fleet_alert_ratio > threshold` OR `correlated_dims` has ≥3 bits set across multiple nodes.
3. No central aggregator — every node computes independently and may reach the same conclusion.

### Phase 3 — Collective action voting

1. When a node's aggregation triggers a fleet-level alarm, it proposes a collective action by broadcasting a `SwarmVote`.
2. Other nodes receive the proposal and cast their own votes based on their local + aggregated view.
3. A collective action is triggered when ≥ `ceil(N * 2/3)` nodes vote for the same action (simple threshold, not BFT).
4. Nodes that voted "observe" still respect the majority decision to prevent split-brain.
5. The vote tally and all signatures are recorded in each node's local audit log.

### Phase 4 — Indicator sharing

1. When a node detects a specific attack pattern (e.g., credential storm), it creates a `SharedIndicator`.
2. The indicator is broadcast with the node's signature as the first provenance entry.
3. Relaying nodes add their own provenance entry before forwarding.
4. Receiving nodes verify the full provenance chain before incorporating the indicator into local detection.

## Security considerations

| Threat | Mitigation |
|--------|-----------|
| Digest forgery | Ed25519 signature verification; reject unsigned digests |
| Replay attacks | Monotonic sequence numbers per node; bounded time window |
| Sybil attacks | Node registration with initial key exchange in a trusted setup phase |
| Majority manipulation | 2/3 threshold for collective action; nodes log dissenting votes for audit |
| Information leakage | Digests contain only aggregate statistics, no raw telemetry |
| Network partitions | Nodes fall back to local-only detection when peer count drops below minimum |

## Energy considerations

- Digest computation: negligible (one SHA-256 + one Ed25519 sign per window).
- Gossip overhead: one UDP packet per window per peer (~256 bytes).
- Voting: infrequent — only when fleet-level alarm triggers.
- Memory: bounded digest map (e.g., 50 peers × 10 windows = 500 entries).

## Integration with existing runtime

The swarm layer would sit alongside the existing pipeline:

```
telemetry → detector → policy → actions
                │                  │
                ▼                  ▼
           replay buffer     audit log
                │
                ▼
         ThreatDigest ──▶ SwarmRelay ──▶ peers
                              │
                              ▼
                     AggregationEngine
                              │
                              ▼
                      VoteCoordinator
                              │
                              ▼
                    Collective action
```

The swarm layer does not modify the core detection pipeline — it adds a parallel coordination path.

## Implementation phases

1. **v0.1** — `ThreatDigest` struct, signature, and local-only aggregation (no networking).
2. **v0.2** — UDP multicast gossip with signature verification and replay rejection.
3. **v0.3** — Fleet-level aggregation with configurable thresholds.
4. **v0.4** — Collective action voting with 2/3 threshold.
5. **v0.5** — SharedIndicator provenance chain.
6. **v0.6** — ZK proof of honest aggregation (Halo2 circuit for vote tally integrity).
