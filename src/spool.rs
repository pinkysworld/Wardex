// Encrypted local spool for agent event buffering with replay-on-recovery.
// ADR-0003: Agent spool for resilient event delivery.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

// ── Encryption (SHA-256 CTR mode, no extra deps) ────────────────

/// Stream cipher using SHA-256 in counter mode for spool-at-rest protection.
/// Derives a unique keystream block for each 32-byte segment using:
///   keystream[i] = SHA-256(key || nonce || block_counter)
/// A 16-byte random nonce is prepended to the ciphertext so that identical
/// plaintexts produce different ciphertexts even with the same key.
/// For production deployments with regulatory requirements, consider
/// upgrading to AES-256-GCM via a dedicated crypto crate.
fn spool_cipher_core(data: &[u8], key: &[u8], nonce: &[u8; 16]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut result = Vec::with_capacity(data.len());
    let mut offset = 0;
    let mut counter: u128 = 0;
    while offset < data.len() {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(nonce);
        hasher.update(counter.to_le_bytes());
        let block = hasher.finalize();
        let remaining = data.len() - offset;
        let take = remaining.min(32);
        for i in 0..take {
            result.push(data[offset + i] ^ block[i]);
        }
        offset += take;
        counter = counter.wrapping_add(1);
    }
    result
}

/// Encrypt: generate a random nonce, prepend it, then XOR with keystream.
fn spool_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    use rand::Rng;
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill(&mut nonce);
    let mut result = nonce.to_vec();
    result.extend(spool_cipher_core(data, key, &nonce));
    result
}

/// Decrypt: strip the 16-byte nonce prefix, then XOR with keystream.
fn spool_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    // Structurally tie the length check to the nonce extraction so a future
    // refactor cannot split them and reintroduce a panic path.
    let Ok(nonce_bytes) = <[u8; 16]>::try_from(data.get(..16).unwrap_or(&[])) else {
        return Vec::new();
    };
    spool_cipher_core(&data[16..], key, &nonce_bytes)
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
    /// Tenant identifier for multi-tenant isolation.
    #[serde(default)]
    pub tenant_id: Option<String>,
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
    ///
    /// # Panics
    /// Panics if `key` is empty. Prefer `try_new` for fallible construction.
    pub fn new(key: &[u8], max_entries: usize) -> Self {
        match Self::try_new(key, max_entries) {
            Ok(spool) => spool,
            Err(message) => panic!("{message}"),
        }
    }

    /// Fallible constructor — returns Err if the key is empty.
    pub fn try_new(key: &[u8], max_entries: usize) -> Result<Self, String> {
        if key.is_empty() {
            return Err("Spool encryption key must not be empty".into());
        }
        Ok(Self {
            queue: VecDeque::new(),
            key: key.to_vec(),
            max_entries,
            next_seq: 1,
            total_enqueued: 0,
            total_delivered: 0,
            total_dropped: 0,
            max_retries: 5,
        })
    }

    /// Enqueue an event payload. Encrypts at rest.
    pub fn enqueue(&mut self, payload: &str, destination: &str, timestamp: &str) -> u64 {
        self.enqueue_with_tenant(payload, destination, timestamp, None)
    }

    /// Enqueue an event payload with tenant isolation. Encrypts at rest.
    pub fn enqueue_with_tenant(
        &mut self,
        payload: &str,
        destination: &str,
        timestamp: &str,
        tenant_id: Option<&str>,
    ) -> u64 {
        let entry = SpoolEntry {
            seq: self.next_seq,
            enqueued_at: timestamp.into(),
            attempts: 0,
            payload: payload.into(),
            destination: destination.into(),
            tenant_id: tenant_id.map(|s| s.to_string()),
        };
        let seq = self.next_seq;
        self.next_seq += 1;
        self.total_enqueued += 1;

        let json = serde_json::to_vec(&entry).unwrap_or_default();
        let encrypted = spool_encrypt(&json, &self.key);

        if self.queue.len() >= self.max_entries {
            self.queue.pop_front(); // Drop oldest
            self.total_dropped += 1;
        }
        self.queue.push_back(encrypted);
        seq
    }

    /// List entries for a specific tenant (decrypts all to filter).
    pub fn entries_for_tenant(&self, tenant_id: &str) -> Vec<SpoolEntry> {
        self.queue
            .iter()
            .filter_map(|encrypted| {
                let decrypted = spool_decrypt(encrypted, &self.key);
                serde_json::from_slice::<SpoolEntry>(&decrypted).ok()
            })
            .filter(|e| e.tenant_id.as_deref() == Some(tenant_id))
            .collect()
    }

    /// Count entries by tenant.
    pub fn tenant_counts(&self) -> std::collections::HashMap<String, usize> {
        let mut counts = std::collections::HashMap::new();
        for encrypted in &self.queue {
            let decrypted = spool_decrypt(encrypted, &self.key);
            if let Ok(entry) = serde_json::from_slice::<SpoolEntry>(&decrypted) {
                let key = entry.tenant_id.unwrap_or_else(|| "default".to_string());
                *counts.entry(key).or_insert(0) += 1;
            }
        }
        counts
    }

    /// Peek at the next entry without removing it.
    pub fn peek(&self) -> Option<SpoolEntry> {
        let encrypted = self.queue.front()?;
        let decrypted = spool_decrypt(encrypted, &self.key);
        serde_json::from_slice(&decrypted).ok()
    }

    /// Peek at the next entry for a specific tenant.
    pub fn peek_for_tenant(&self, tenant_id: &str) -> Option<SpoolEntry> {
        for encrypted in &self.queue {
            let decrypted = spool_decrypt(encrypted, &self.key);
            if let Ok(entry) = serde_json::from_slice::<SpoolEntry>(&decrypted)
                && entry.tenant_id.as_deref() == Some(tenant_id)
            {
                return Some(entry);
            }
        }
        None
    }

    /// Dequeue the next entry (successful delivery).
    pub fn dequeue(&mut self) -> Option<SpoolEntry> {
        let encrypted = self.queue.pop_front()?;
        let decrypted = spool_decrypt(&encrypted, &self.key);
        self.total_delivered += 1;
        serde_json::from_slice(&decrypted).ok()
    }

    /// Dequeue the next entry belonging to a specific tenant.
    pub fn dequeue_for_tenant(&mut self, tenant_id: &str) -> Option<SpoolEntry> {
        let pos = self.queue.iter().position(|encrypted| {
            let decrypted = spool_decrypt(encrypted, &self.key);
            serde_json::from_slice::<SpoolEntry>(&decrypted)
                .map(|e| e.tenant_id.as_deref() == Some(tenant_id))
                .unwrap_or(false)
        })?;
        let encrypted = self.queue.remove(pos)?;
        let decrypted = spool_decrypt(&encrypted, &self.key);
        self.total_delivered += 1;
        serde_json::from_slice(&decrypted).ok()
    }

    /// Mark delivery attempt failed; re-enqueue with incremented attempts.
    /// Returns None if max retries exceeded (dead-lettered).
    /// Accepts the previously dequeued entry that failed delivery.
    pub fn nack(&mut self, mut entry: SpoolEntry) -> Option<SpoolEntry> {
        entry.attempts += 1;
        if entry.attempts > self.max_retries {
            self.total_dropped += 1;
            return None; // Dead-lettered
        }
        let json = serde_json::to_vec(&entry).unwrap_or_default();
        let re_encrypted = spool_encrypt(&json, &self.key);
        self.queue.push_back(re_encrypted); // Re-enqueue at end
        Some(entry)
    }

    /// Number of entries currently in the spool.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Number of entries for a specific tenant.
    pub fn len_for_tenant(&self, tenant_id: &str) -> usize {
        self.entries_for_tenant(tenant_id).len()
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

    /// Drain entries for a specific tenant only.
    pub fn drain_for_tenant(&mut self, tenant_id: &str) -> Vec<SpoolEntry> {
        let mut results = Vec::new();
        let mut remaining = VecDeque::new();
        while let Some(encrypted) = self.queue.pop_front() {
            let decrypted = spool_decrypt(&encrypted, &self.key);
            if let Ok(entry) = serde_json::from_slice::<SpoolEntry>(&decrypted) {
                if entry.tenant_id.as_deref() == Some(tenant_id) {
                    self.total_delivered += 1;
                    results.push(entry);
                } else {
                    remaining.push_back(encrypted);
                }
            }
        }
        self.queue = remaining;
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
        let header: SpoolPersistHeader =
            serde_json::from_str(header_line).map_err(|e| format!("Invalid header: {}", e))?;

        // Parse all entries FIRST before updating state
        let mut temp_queue = std::collections::VecDeque::new();
        let mut count = 0;
        for line in lines {
            if line.is_empty() {
                continue;
            }
            let encrypted = hex::decode(line).map_err(|e| format!("Invalid hex: {}", e))?;
            temp_queue.push_back(encrypted);
            count += 1;
        }
        if count != header.entry_count as usize {
            return Err(format!(
                "Entry count mismatch: expected {}, got {}",
                header.entry_count, count
            ));
        }

        // NOW update state after all entries are validated
        self.next_seq = header.next_seq;
        self.total_enqueued = header.total_enqueued;
        self.total_delivered = header.total_delivered;
        self.total_dropped = header.total_dropped;
        self.queue = temp_queue;

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
            utilization_pct: if self.max_entries > 0 {
                (self.queue.len() as f64 / self.max_entries as f64 * 100.0) as u8
            } else {
                0
            },
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
        spool.enqueue(
            r#"{"event":"test"}"#,
            "control-plane",
            "2026-01-01T00:00:00Z",
        );
        assert_eq!(spool.len(), 1);

        let entry = spool.dequeue().unwrap();
        assert_eq!(entry.seq, 1);
        assert_eq!(entry.payload, r#"{"event":"test"}"#);
        assert_eq!(entry.destination, "control-plane");
        assert_eq!(entry.attempts, 0);
        assert!(spool.is_empty());
    }

    #[test]
    fn try_new_rejects_empty_key() {
        assert!(EncryptedSpool::try_new(b"", 100).is_err());
    }

    #[test]
    fn encryption_protects_data() {
        let mut spool = EncryptedSpool::new(b"secret-key-abcde", 100);
        spool.enqueue("sensitive-payload", "dst", "now");

        // Raw encrypted bytes should not contain the plaintext
        let raw = &spool.queue[0];
        let raw_str = String::from_utf8_lossy(raw);
        assert!(
            !raw_str.contains("sensitive-payload"),
            "Payload should be encrypted"
        );
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

        // Dequeue, then nack (simulates failed delivery)
        let entry = spool.dequeue().unwrap();
        let entry = spool.nack(entry).unwrap();
        assert_eq!(entry.attempts, 1);
        assert_eq!(spool.len(), 1); // Re-enqueued

        // Second failed delivery
        let entry = spool.dequeue().unwrap();
        let entry = spool.nack(entry).unwrap();
        assert_eq!(entry.attempts, 2);

        // Third nack exceeds max_retries
        let entry = spool.dequeue().unwrap();
        let dead = spool.nack(entry);
        assert!(dead.is_none(), "Should be dead-lettered after max retries");
        assert!(spool.is_empty());
    }

    #[test]
    fn nack_retries_correct_entry_with_multiple() {
        let mut spool = EncryptedSpool::new(b"key", 100);
        spool.max_retries = 3;
        spool.enqueue("event-a", "dst", "now");
        spool.enqueue("event-b", "dst", "now");
        spool.enqueue("event-c", "dst", "now");

        // Dequeue event-a, simulate failed delivery
        let entry_a = spool.dequeue().unwrap();
        assert_eq!(entry_a.payload, "event-a");

        // Nack event-a — it should be re-enqueued at the end
        let retried = spool.nack(entry_a).unwrap();
        assert_eq!(retried.payload, "event-a");
        assert_eq!(retried.attempts, 1);

        // Queue should now be: [event-b, event-c, event-a(retry)]
        assert_eq!(spool.len(), 3);

        // Dequeue should give event-b next, not event-a
        let entry_b = spool.dequeue().unwrap();
        assert_eq!(entry_b.payload, "event-b");
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
        let stats = SpoolStats {
            current_depth: 50,
            max_entries: 100,
            total_enqueued: 50,
            total_delivered: 0,
            total_dropped: 0,
            utilization_pct: 50,
        };
        assert_eq!(backpressure_signal(&stats), BackpressureSignal::Accept);

        let stats = SpoolStats {
            utilization_pct: 80,
            ..stats.clone()
        };
        assert_eq!(backpressure_signal(&stats), BackpressureSignal::ThrottleLow);

        let stats = SpoolStats {
            utilization_pct: 90,
            ..stats.clone()
        };
        assert_eq!(
            backpressure_signal(&stats),
            BackpressureSignal::CriticalOnly
        );

        let stats = SpoolStats {
            utilization_pct: 98,
            ..stats.clone()
        };
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

    #[test]
    fn tenant_aware_enqueue_and_filter() {
        let mut spool = EncryptedSpool::new(b"tenant-test-key!", 100);
        spool.enqueue_with_tenant("event-a", "dst", "t1", Some("tenant-1"));
        spool.enqueue_with_tenant("event-b", "dst", "t2", Some("tenant-2"));
        spool.enqueue_with_tenant("event-c", "dst", "t3", Some("tenant-1"));
        spool.enqueue("event-d", "dst", "t4"); // no tenant

        let t1 = spool.entries_for_tenant("tenant-1");
        assert_eq!(t1.len(), 2);
        assert_eq!(t1[0].payload, "event-a");
        assert_eq!(t1[1].payload, "event-c");

        let t2 = spool.entries_for_tenant("tenant-2");
        assert_eq!(t2.len(), 1);

        let counts = spool.tenant_counts();
        assert_eq!(counts["tenant-1"], 2);
        assert_eq!(counts["tenant-2"], 1);
        assert_eq!(counts["default"], 1);
    }

    #[test]
    fn tenant_id_preserved_in_persist_restore() {
        let mut spool = EncryptedSpool::new(b"persist-tenant!!", 100);
        spool.enqueue_with_tenant("ev1", "dst", "t", Some("acme-corp"));
        let persisted = spool.persist();

        let mut restored = EncryptedSpool::new(b"persist-tenant!!", 100);
        restored.restore(&persisted).unwrap();
        let entry = restored.dequeue().unwrap();
        assert_eq!(entry.tenant_id.as_deref(), Some("acme-corp"));
    }

    #[test]
    fn tenant_isolation_dequeue() {
        let mut spool = EncryptedSpool::new(b"tenant-isolate!!", 100);
        spool.enqueue_with_tenant("ev1", "dst", "t1", Some("alpha"));
        spool.enqueue_with_tenant("ev2", "dst", "t2", Some("beta"));
        spool.enqueue_with_tenant("ev3", "dst", "t3", Some("alpha"));

        // Dequeue only alpha's entries
        let e1 = spool.dequeue_for_tenant("alpha").unwrap();
        assert_eq!(e1.payload, "ev1");
        let e2 = spool.dequeue_for_tenant("alpha").unwrap();
        assert_eq!(e2.payload, "ev3");
        assert!(spool.dequeue_for_tenant("alpha").is_none());

        // Beta's entry should still be available
        assert_eq!(spool.len(), 1);
        let e3 = spool.dequeue_for_tenant("beta").unwrap();
        assert_eq!(e3.payload, "ev2");
    }

    #[test]
    fn tenant_isolation_peek() {
        let mut spool = EncryptedSpool::new(b"tenant-peek!!!!!", 100);
        spool.enqueue_with_tenant("ev1", "dst", "t1", Some("alpha"));
        spool.enqueue_with_tenant("ev2", "dst", "t2", Some("beta"));

        let peeked = spool.peek_for_tenant("beta").unwrap();
        assert_eq!(peeked.payload, "ev2");
        // Peek doesn't consume
        assert_eq!(spool.len(), 2);
    }

    #[test]
    fn tenant_isolation_drain() {
        let mut spool = EncryptedSpool::new(b"tenant-drain!!!!", 100);
        spool.enqueue_with_tenant("ev1", "dst", "t1", Some("alpha"));
        spool.enqueue_with_tenant("ev2", "dst", "t2", Some("beta"));
        spool.enqueue_with_tenant("ev3", "dst", "t3", Some("alpha"));

        let drained = spool.drain_for_tenant("alpha");
        assert_eq!(drained.len(), 2);
        assert_eq!(spool.len(), 1);
        let remaining = spool.dequeue().unwrap();
        assert_eq!(remaining.tenant_id.as_deref(), Some("beta"));
    }

    #[test]
    fn tenant_len() {
        let mut spool = EncryptedSpool::new(b"tenant-len!!!!!!", 100);
        spool.enqueue_with_tenant("ev1", "dst", "t1", Some("alpha"));
        spool.enqueue_with_tenant("ev2", "dst", "t2", Some("beta"));
        spool.enqueue_with_tenant("ev3", "dst", "t3", Some("alpha"));

        assert_eq!(spool.len_for_tenant("alpha"), 2);
        assert_eq!(spool.len_for_tenant("beta"), 1);
        assert_eq!(spool.len_for_tenant("gamma"), 0);
    }
}
