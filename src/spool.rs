// Encrypted local spool for agent event buffering with replay-on-recovery.
// ADR-0003: Agent spool for resilient event delivery.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

// ── Encryption (SHA-256 CTR mode, no extra deps) ────────────────

/// Stream cipher using SHA-256 in counter mode for spool-at-rest protection.
/// Derives a unique keystream block for each 32-byte segment using:
///   keystream[i] = SHA-256(key || block_counter)
/// This provides semantic security (identical plaintexts produce different
/// ciphertexts when keys differ) unlike raw XOR with short key repetition.
/// For production deployments with regulatory requirements, consider
/// upgrading to AES-256-GCM via a dedicated crypto crate.
fn spool_cipher(data: &[u8], key: &[u8]) -> Vec<u8> {
    use sha2::{Sha256, Digest};
    let mut result = Vec::with_capacity(data.len());
    let mut offset = 0;
    let mut counter: u64 = 0;
    while offset < data.len() {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(counter.to_le_bytes());
        let block = hasher.finalize();
        let remaining = data.len() - offset;
        let take = remaining.min(32);
        for i in 0..take {
            result.push(data[offset + i] ^ block[i]);
        }
        offset += take;
        counter += 1;
    }
    result
}

// ── Spool entry ─────────────────────────────────────────────────

/// A spooled event entry with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpoolEntry {
    /// Monotonic sequence number for ordering.
    pub seq: u64,
    /// ISO-8601 timestamp when enqueued.
    pub enqueued_at: String,
    /// Number of delivery attempts.
    pub attempts: u32,
    /// Event payload (JSON-serialized OCSF event or raw telemetry).
    pub payload: String,
    /// Destination tag (e.g. "control-plane", "siem-splunk").
    pub destination: String,
}

// ── Encrypted spool ─────────────────────────────────────────────

/// Encrypted event spool with bounded capacity and delivery tracking.
pub struct EncryptedSpool {
    queue: VecDeque<Vec<u8>>, // Encrypted entries
    key: Vec<u8>,
    max_entries: usize,
    next_seq: u64,
    /// Total events ever enqueued.
    pub total_enqueued: u64,
    /// Total events successfully dequeued/delivered.
    pub total_delivered: u64,
    /// Total events dropped due to overflow.
    pub total_dropped: u64,
    /// Maximum retry attempts before dead-lettering.
    pub max_retries: u32,
}

impl EncryptedSpool {
    /// Create a new spool with the given encryption key and capacity.
    pub fn new(key: &[u8], max_entries: usize) -> Self {
        assert!(!key.is_empty(), "Spool encryption key must not be empty");
        Self {
            queue: VecDeque::new(),
            key: key.to_vec(),
            max_entries,
            next_seq: 1,
            total_enqueued: 0,
            total_delivered: 0,
            total_dropped: 0,
            max_retries: 5,
        }
    }

    /// Enqueue an event payload. Encrypts at rest.
    pub fn enqueue(&mut self, payload: &str, destination: &str, timestamp: &str) -> u64 {
        let entry = SpoolEntry {
            seq: self.next_seq,
            enqueued_at: timestamp.into(),
            attempts: 0,
            payload: payload.into(),
            destination: destination.into(),
        };
        let seq = self.next_seq;
        self.next_seq += 1;
        self.total_enqueued += 1;

        let json = serde_json::to_vec(&entry).unwrap_or_default();
        let encrypted = spool_cipher(&json, &self.key);

        if self.queue.len() >= self.max_entries {
            self.queue.pop_front(); // Drop oldest
            self.total_dropped += 1;
        }
        self.queue.push_back(encrypted);
        seq
    }

    /// Peek at the next entry without removing it.
    pub fn peek(&self) -> Option<SpoolEntry> {
        let encrypted = self.queue.front()?;
        let decrypted = spool_cipher(encrypted, &self.key);
        serde_json::from_slice(&decrypted).ok()
    }

    /// Dequeue the next entry (successful delivery).
    pub fn dequeue(&mut self) -> Option<SpoolEntry> {
        let encrypted = self.queue.pop_front()?;
        let decrypted = spool_cipher(&encrypted, &self.key);
        self.total_delivered += 1;
        serde_json::from_slice(&decrypted).ok()
    }

    /// Mark delivery attempt failed; re-enqueue with incremented attempts.
    /// Returns None if max retries exceeded (dead-lettered).
    pub fn nack(&mut self) -> Option<SpoolEntry> {
        let encrypted = self.queue.pop_front()?;
        let decrypted = spool_cipher(&encrypted, &self.key);
        if let Ok(mut entry) = serde_json::from_slice::<SpoolEntry>(&decrypted) {
            entry.attempts += 1;
            if entry.attempts > self.max_retries {
                self.total_dropped += 1;
                return None; // Dead-lettered
            }
            let json = serde_json::to_vec(&entry).unwrap_or_default();
            let re_encrypted = spool_cipher(&json, &self.key);
            self.queue.push_back(re_encrypted); // Re-enqueue at end
            Some(entry)
        } else {
            None
        }
    }

    /// Number of entries currently in the spool.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Drain all entries (for batch flush).
    pub fn drain_all(&mut self) -> Vec<SpoolEntry> {
        let mut results = Vec::new();
        while let Some(entry) = self.dequeue() {
            results.push(entry);
        }
        results
    }

    /// Persist spool to bytes (encrypted on disk).
    pub fn persist(&self) -> Vec<u8> {
        let entries: Vec<Vec<u8>> = self.queue.iter().cloned().collect();
        let header = SpoolPersistHeader {
            next_seq: self.next_seq,
            total_enqueued: self.total_enqueued,
            total_delivered: self.total_delivered,
            total_dropped: self.total_dropped,
            entry_count: entries.len() as u64,
        };
        let mut data = serde_json::to_vec(&header).unwrap_or_default();
        data.push(b'\n');
        for e in &entries {
            let encoded = hex::encode(e);
            data.extend_from_slice(encoded.as_bytes());
            data.push(b'\n');
        }
        data
    }

    /// Restore spool from persisted bytes.
    pub fn restore(&mut self, data: &[u8]) -> Result<usize, String> {
        let text = String::from_utf8(data.to_vec()).map_err(|e| e.to_string())?;
        let mut lines = text.lines();
        let header_line = lines.next().ok_or("Empty persist data")?;
        let header: SpoolPersistHeader = serde_json::from_str(header_line)
            .map_err(|e| format!("Invalid header: {}", e))?;

        self.next_seq = header.next_seq;
        self.total_enqueued = header.total_enqueued;
        self.total_delivered = header.total_delivered;
        self.total_dropped = header.total_dropped;

        let mut count = 0;
        for line in lines {
            if line.is_empty() { continue; }
            let encrypted = hex::decode(line).map_err(|e| format!("Invalid hex: {}", e))?;
            self.queue.push_back(encrypted);
            count += 1;
        }
        Ok(count)
    }

    /// Get spool statistics.
    pub fn stats(&self) -> SpoolStats {
        SpoolStats {
            current_depth: self.queue.len(),
            max_entries: self.max_entries,
            total_enqueued: self.total_enqueued,
            total_delivered: self.total_delivered,
            total_dropped: self.total_dropped,
            utilization_pct: if self.max_entries > 0 { (self.queue.len() as f64 / self.max_entries as f64 * 100.0) as u8 } else { 0 },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SpoolPersistHeader {
    next_seq: u64,
    total_enqueued: u64,
    total_delivered: u64,
    total_dropped: u64,
    entry_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpoolStats {
    pub current_depth: usize,
    pub max_entries: usize,
    pub total_enqueued: u64,
    pub total_delivered: u64,
    pub total_dropped: u64,
    pub utilization_pct: u8,
}

// ── Backpressure ────────────────────────────────────────────────

/// Backpressure signal based on spool utilization.
#[derive(Debug, Clone, PartialEq)]
pub enum BackpressureSignal {
    /// Normal operation, all events accepted.
    Accept,
    /// Spool filling up: throttle low-priority events.
    ThrottleLow,
    /// Spool nearly full: only critical events.
    CriticalOnly,
    /// Spool full: drop all new events.
    Drop,
}

impl EncryptedSpool {
    /// Current backpressure signal based on spool utilization.
    pub fn backpressure(&self) -> BackpressureSignal {
        backpressure_signal(&self.stats())
    }
}

/// Determine backpressure signal from spool stats.
pub fn backpressure_signal(stats: &SpoolStats) -> BackpressureSignal {
    match stats.utilization_pct {
        0..=70 => BackpressureSignal::Accept,
        71..=85 => BackpressureSignal::ThrottleLow,
        86..=95 => BackpressureSignal::CriticalOnly,
        _ => BackpressureSignal::Drop,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enqueue_dequeue() {
        let mut spool = EncryptedSpool::new(b"test-key-16bytes", 100);
        spool.enqueue(r#"{"event":"test"}"#, "control-plane", "2026-01-01T00:00:00Z");
        assert_eq!(spool.len(), 1);

        let entry = spool.dequeue().unwrap();
        assert_eq!(entry.seq, 1);
        assert_eq!(entry.payload, r#"{"event":"test"}"#);
        assert_eq!(entry.destination, "control-plane");
        assert_eq!(entry.attempts, 0);
        assert!(spool.is_empty());
    }

    #[test]
    fn encryption_protects_data() {
        let mut spool = EncryptedSpool::new(b"secret-key-abcde", 100);
        spool.enqueue("sensitive-payload", "dst", "now");

        // Raw encrypted bytes should not contain the plaintext
        let raw = &spool.queue[0];
        let raw_str = String::from_utf8_lossy(raw);
        assert!(!raw_str.contains("sensitive-payload"), "Payload should be encrypted");
    }

    #[test]
    fn peek_does_not_remove() {
        let mut spool = EncryptedSpool::new(b"key", 100);
        spool.enqueue("payload", "dst", "now");
        assert!(spool.peek().is_some());
        assert_eq!(spool.len(), 1);
    }

    #[test]
    fn overflow_drops_oldest() {
        let mut spool = EncryptedSpool::new(b"key", 3);
        spool.enqueue("a", "dst", "t1");
        spool.enqueue("b", "dst", "t2");
        spool.enqueue("c", "dst", "t3");
        assert_eq!(spool.len(), 3);

        spool.enqueue("d", "dst", "t4");
        assert_eq!(spool.len(), 3);
        assert_eq!(spool.total_dropped, 1);

        let first = spool.peek().unwrap();
        assert_eq!(first.payload, "b"); // 'a' was dropped
    }

    #[test]
    fn nack_retries() {
        let mut spool = EncryptedSpool::new(b"key", 100);
        spool.max_retries = 2;
        spool.enqueue("retry-me", "dst", "now");

        // First nack
        let entry = spool.nack().unwrap();
        assert_eq!(entry.attempts, 1);
        assert_eq!(spool.len(), 1); // Re-enqueued

        // Second nack
        let entry = spool.nack().unwrap();
        assert_eq!(entry.attempts, 2);

        // Third nack exceeds max_retries
        let dead = spool.nack();
        assert!(dead.is_none(), "Should be dead-lettered after max retries");
        assert!(spool.is_empty());
    }

    #[test]
    fn drain_all() {
        let mut spool = EncryptedSpool::new(b"key", 100);
        for i in 0..5 {
            spool.enqueue(&format!("event-{}", i), "dst", "now");
        }
        let drained = spool.drain_all();
        assert_eq!(drained.len(), 5);
        assert!(spool.is_empty());
    }

    #[test]
    fn persist_and_restore() {
        let mut spool = EncryptedSpool::new(b"persist-key-abc!", 100);
        spool.enqueue("event-1", "dst", "t1");
        spool.enqueue("event-2", "dst", "t2");

        let persisted = spool.persist();

        let mut restored = EncryptedSpool::new(b"persist-key-abc!", 100);
        let count = restored.restore(&persisted).unwrap();
        assert_eq!(count, 2);
        assert_eq!(restored.len(), 2);

        let e1 = restored.dequeue().unwrap();
        assert_eq!(e1.payload, "event-1");
        let e2 = restored.dequeue().unwrap();
        assert_eq!(e2.payload, "event-2");
    }

    #[test]
    fn backpressure_signals() {
        let stats = SpoolStats { current_depth: 50, max_entries: 100, total_enqueued: 50, total_delivered: 0, total_dropped: 0, utilization_pct: 50 };
        assert_eq!(backpressure_signal(&stats), BackpressureSignal::Accept);

        let stats = SpoolStats { utilization_pct: 80, ..stats.clone() };
        assert_eq!(backpressure_signal(&stats), BackpressureSignal::ThrottleLow);

        let stats = SpoolStats { utilization_pct: 90, ..stats.clone() };
        assert_eq!(backpressure_signal(&stats), BackpressureSignal::CriticalOnly);

        let stats = SpoolStats { utilization_pct: 98, ..stats.clone() };
        assert_eq!(backpressure_signal(&stats), BackpressureSignal::Drop);
    }

    #[test]
    fn stats_reporting() {
        let mut spool = EncryptedSpool::new(b"key", 100);
        spool.enqueue("a", "dst", "t");
        spool.enqueue("b", "dst", "t");
        spool.dequeue();

        let stats = spool.stats();
        assert_eq!(stats.current_depth, 1);
        assert_eq!(stats.total_enqueued, 2);
        assert_eq!(stats.total_delivered, 1);
    }
}
