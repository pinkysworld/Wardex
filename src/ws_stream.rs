// ── WebSocket Event Stream ────────────────────────────────────────────────────
//
// Lightweight WebSocket implementation for real-time event streaming at
// /ws/events.  Uses RFC 6455 handshake over the existing tiny_http server.
// No external websocket crate — we implement the framing protocol directly.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ── WebSocket Constants ──────────────────────────────────────────────────────

const WS_MAGIC: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const OPCODE_TEXT: u8 = 0x01;
const OPCODE_CLOSE: u8 = 0x08;
const _OPCODE_PING: u8 = 0x09;
const OPCODE_PONG: u8 = 0x0A;

/// Maximum allowed WebSocket frame payload (1 MiB).
const MAX_FRAME_PAYLOAD: usize = 1024 * 1024;

// ── Event types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WsEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub timestamp: String,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WsSubscription {
    pub channels: Vec<String>,
}

// ── Frame encoding / decoding ────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct WsFrame {
    pub fin: bool,
    pub opcode: u8,
    pub payload: Vec<u8>,
}

impl WsFrame {
    pub fn text(msg: &str) -> Self {
        Self {
            fin: true,
            opcode: OPCODE_TEXT,
            payload: msg.as_bytes().to_vec(),
        }
    }

    pub fn close() -> Self {
        Self {
            fin: true,
            opcode: OPCODE_CLOSE,
            payload: vec![],
        }
    }

    pub fn pong(payload: Vec<u8>) -> Self {
        Self {
            fin: true,
            opcode: OPCODE_PONG,
            payload,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let first = if self.fin { 0x80 } else { 0 } | self.opcode;
        buf.push(first);

        let len = self.payload.len();
        if len < 126 {
            buf.push(len as u8);
        } else if len < 65536 {
            buf.push(126);
            buf.push((len >> 8) as u8);
            buf.push((len & 0xFF) as u8);
        } else {
            buf.push(127);
            for i in (0..8).rev() {
                buf.push(((len >> (i * 8)) & 0xFF) as u8);
            }
        }

        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        Self::decode_inner(data, false)
    }

    /// Decode a frame from a client, enforcing RFC 6455 masking requirement.
    /// Client-to-server frames MUST be masked; unmasked frames are rejected.
    pub fn decode_client(data: &[u8]) -> Option<(Self, usize)> {
        Self::decode_inner(data, true)
    }

    fn decode_inner(data: &[u8], require_mask: bool) -> Option<(Self, usize)> {
        if data.len() < 2 {
            return None;
        }

        let fin = (data[0] & 0x80) != 0;
        let opcode = data[0] & 0x0F;
        let masked = (data[1] & 0x80) != 0;

        // RFC 6455 §5.1: client frames MUST be masked
        if require_mask && !masked {
            return None;
        }

        let mut payload_len = (data[1] & 0x7F) as usize;
        let mut offset = 2;

        if payload_len == 126 {
            if data.len() < 4 {
                return None;
            }
            payload_len = ((data[2] as usize) << 8) | (data[3] as usize);
            offset = 4;
        } else if payload_len == 127 {
            if data.len() < 10 {
                return None;
            }
            payload_len = 0;
            for i in 0..8 {
                payload_len = match payload_len.checked_shl(8) {
                    Some(shifted) => shifted | (data[2 + i] as usize),
                    None => return None, // overflow — reject frame
                };
            }
            offset = 10;
        }

        if payload_len > MAX_FRAME_PAYLOAD {
            return None; // reject oversized frames
        }

        let mask_key = if masked {
            if data.len() < offset + 4 {
                return None;
            }
            let key = [
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ];
            offset += 4;
            Some(key)
        } else {
            None
        };

        if data.len() < offset + payload_len {
            return None;
        }

        let mut payload = data[offset..offset + payload_len].to_vec();
        if let Some(mask) = mask_key {
            for i in 0..payload.len() {
                payload[i] ^= mask[i % 4];
            }
        }

        let total = offset + payload_len;
        Some((
            Self {
                fin,
                opcode,
                payload,
            },
            total,
        ))
    }
}

// ── Handshake ────────────────────────────────────────────────────────────────

pub fn compute_accept_key(client_key: &str) -> String {
    // RFC 6455 §4.2.2 requires SHA-1.  We implement a minimal SHA-1 here
    // so we stay compatible with every standard WebSocket client without
    // adding a new crate dependency.
    let mut input = Vec::with_capacity(client_key.len() + WS_MAGIC.len());
    input.extend_from_slice(client_key.as_bytes());
    input.extend_from_slice(WS_MAGIC.as_bytes());
    let hash = sha1_digest(&input);
    base64_encode(&hash)
}

/// Minimal SHA-1 (RFC 3174) — used only for the WebSocket accept key.
#[allow(clippy::needless_range_loop)]
fn sha1_digest(msg: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    // Pre-processing: pad message
    let ml = msg.len() as u64 * 8;
    let mut data = msg.to_vec();
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0x00);
    }
    data.extend_from_slice(&ml.to_be_bytes());

    for chunk in data.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, bytes) in chunk.chunks_exact(4).enumerate().take(16) {
            w[i] = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

fn base64_encode(input: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

pub fn build_handshake_response(accept_key: &str) -> String {
    format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\
         \r\n",
        accept_key
    )
}

pub fn parse_ws_key(headers: &str) -> Option<String> {
    for line in headers.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("sec-websocket-key:") {
            return Some(line.split(':').nth(1)?.trim().to_string());
        }
    }
    None
}

// ── Event Bus ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct EventBus {
    inner: Arc<Mutex<EventBusInner>>,
}

#[derive(Debug)]
struct EventBusInner {
    events: VecDeque<WsEvent>,
    max_buffer: usize,
    sequence: u64,
    subscribers: Vec<Subscriber>,
    next_subscriber_id: u64,
}

#[derive(Debug)]
struct Subscriber {
    id: u64,
    channels: Vec<String>,
    queue: VecDeque<WsEvent>,
}

impl EventBus {
    pub fn new(max_buffer: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(EventBusInner {
                events: VecDeque::new(),
                max_buffer,
                sequence: 0,
                subscribers: Vec::new(),
                next_subscriber_id: 1,
            })),
        }
    }

    pub fn publish(&self, event: WsEvent) {
        if let Ok(mut bus) = self.inner.lock() {
            let max_buf = bus.max_buffer;
            // Fan out to subscribers
            for sub in &mut bus.subscribers {
                if sub.channels.is_empty() || sub.channels.contains(&event.event_type) {
                    sub.queue.push_back(event.clone());
                    // Limit per-subscriber queue
                    while sub.queue.len() > max_buf {
                        sub.queue.pop_front();
                    }
                }
            }
            // Store in ring buffer
            bus.events.push_back(event);
            while bus.events.len() > max_buf {
                bus.events.pop_front();
            }
            bus.sequence += 1;
        }
    }

    pub fn subscribe(&self, channels: Vec<String>) -> u64 {
        if let Ok(mut bus) = self.inner.lock() {
            let id = bus.next_subscriber_id;
            bus.next_subscriber_id += 1;
            bus.subscribers.push(Subscriber {
                id,
                channels,
                queue: VecDeque::new(),
            });
            id
        } else {
            0
        }
    }

    pub fn unsubscribe(&self, id: u64) {
        if let Ok(mut bus) = self.inner.lock() {
            bus.subscribers.retain(|s| s.id != id);
        }
    }

    pub fn drain(&self, subscriber_id: u64) -> Vec<WsEvent> {
        if let Ok(mut bus) = self.inner.lock()
            && let Some(sub) = bus.subscribers.iter_mut().find(|s| s.id == subscriber_id)
        {
            return sub.queue.drain(..).collect();
        }
        vec![]
    }

    pub fn recent(&self, count: usize) -> Vec<WsEvent> {
        if let Ok(bus) = self.inner.lock() {
            bus.events.iter().rev().take(count).cloned().collect()
        } else {
            vec![]
        }
    }

    pub fn subscriber_count(&self) -> usize {
        self.inner.lock().map(|b| b.subscribers.len()).unwrap_or(0)
    }

    pub fn event_count(&self) -> u64 {
        self.inner.lock().map(|b| b.sequence).unwrap_or(0)
    }
}

// ── Helper: emit common events ───────────────────────────────────────────────

pub fn alert_event(level: &str, device_id: &str, reasons: &[String]) -> WsEvent {
    WsEvent {
        event_type: "alert".into(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        data: serde_json::json!({
            "level": level,
            "device_id": device_id,
            "reasons": reasons,
        }),
    }
}

pub fn incident_event(id: &str, title: &str, severity: &str) -> WsEvent {
    WsEvent {
        event_type: "incident".into(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        data: serde_json::json!({
            "id": id,
            "title": title,
            "severity": severity,
        }),
    }
}

pub fn agent_event(agent_id: &str, action: &str) -> WsEvent {
    WsEvent {
        event_type: "agent".into(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        data: serde_json::json!({
            "agent_id": agent_id,
            "action": action,
        }),
    }
}

pub fn heartbeat_event() -> WsEvent {
    WsEvent {
        event_type: "heartbeat".into(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        data: serde_json::json!({}),
    }
}

// ── WsConnection (manages one connected client) ─────────────────────────────

pub struct WsConnection {
    pub subscriber_id: u64,
    pub connected_at: Instant,
    pub last_ping: Instant,
    pub frames_sent: u64,
    pub frames_received: u64,
}

impl WsConnection {
    pub fn new(subscriber_id: u64) -> Self {
        Self {
            subscriber_id,
            connected_at: Instant::now(),
            last_ping: Instant::now(),
            frames_sent: 0,
            frames_received: 0,
        }
    }

    pub fn record_sent(&mut self) {
        self.frames_sent += 1;
    }
    pub fn record_received(&mut self) {
        self.frames_received += 1;
    }

    pub fn uptime_secs(&self) -> f64 {
        self.connected_at.elapsed().as_secs_f64()
    }

    pub fn since_last_ping(&self) -> Duration {
        self.last_ping.elapsed()
    }
}

// ── AlertBroadcaster (pushes alerts to all connected WS clients) ────────────

/// Manages broadcasting alert events to all subscribed WebSocket clients.
pub struct AlertBroadcaster {
    bus: EventBus,
    connections: Vec<WsConnection>,
}

impl Default for AlertBroadcaster {
    fn default() -> Self { Self::new() }
}

impl AlertBroadcaster {
    pub fn new() -> Self {
        Self {
            bus: EventBus::new(5000),
            connections: Vec::new(),
        }
    }

    /// Register a new WebSocket client. Returns the subscriber ID.
    pub fn connect(&mut self) -> u64 {
        let id = self.bus.subscribe(vec!["alerts".into(), "events".into()]);
        self.connections.push(WsConnection::new(id));
        id
    }

    /// Disconnect a client by subscriber ID.
    pub fn disconnect(&mut self, subscriber_id: u64) {
        self.bus.unsubscribe(subscriber_id);
        self.connections.retain(|c| c.subscriber_id != subscriber_id);
    }

    /// Broadcast an alert to all connected clients.
    pub fn broadcast_alert(&mut self, alert: serde_json::Value) {
        let event = WsEvent {
            event_type: "alert".into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            data: alert,
        };
        self.bus.publish(event);
    }

    /// Broadcast a generic event to all connected clients.
    pub fn broadcast_event(&mut self, event_type: &str, data: serde_json::Value) {
        let event = WsEvent {
            event_type: event_type.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            data,
        };
        self.bus.publish(event);
    }

    /// Drain pending events for a specific subscriber.
    pub fn drain_for(&mut self, subscriber_id: u64) -> Vec<WsEvent> {
        self.bus.drain(subscriber_id)
    }

    /// Get the number of connected clients.
    pub fn client_count(&self) -> usize {
        self.connections.len()
    }

    /// Get connection stats.
    pub fn stats(&self) -> serde_json::Value {
        serde_json::json!({
            "connected_clients": self.connections.len(),
            "total_events": self.bus.event_count(),
            "subscribers": self.bus.subscriber_count(),
            "connections": self.connections.iter().map(|c| serde_json::json!({
                "subscriber_id": c.subscriber_id,
                "uptime_secs": c.uptime_secs(),
                "frames_sent": c.frames_sent,
                "frames_received": c.frames_received,
            })).collect::<Vec<_>>(),
        })
    }

    /// Remove idle connections (no ping for > timeout).
    pub fn sweep_idle(&mut self, timeout: Duration) -> usize {
        let stale: Vec<u64> = self.connections.iter()
            .filter(|c| c.since_last_ping() > timeout)
            .map(|c| c.subscriber_id)
            .collect();
        let count = stale.len();
        for id in stale {
            self.disconnect(id);
        }
        count
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_encode_decode_roundtrip() {
        let frame = WsFrame::text("Hello, WebSocket!");
        let encoded = frame.encode();
        let (decoded, consumed) = WsFrame::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert!(decoded.fin);
        assert_eq!(decoded.opcode, OPCODE_TEXT);
        assert_eq!(
            std::str::from_utf8(&decoded.payload).unwrap(),
            "Hello, WebSocket!"
        );
    }

    #[test]
    fn frame_close() {
        let frame = WsFrame::close();
        let encoded = frame.encode();
        let (decoded, _) = WsFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.opcode, OPCODE_CLOSE);
        assert!(decoded.payload.is_empty());
    }

    #[test]
    fn frame_medium_payload() {
        let payload = "x".repeat(300);
        let frame = WsFrame::text(&payload);
        let encoded = frame.encode();
        assert!(encoded.len() > 300);
        let (decoded, _) = WsFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.payload.len(), 300);
    }

    #[test]
    fn frame_large_payload() {
        let payload = "y".repeat(70000);
        let frame = WsFrame::text(&payload);
        let encoded = frame.encode();
        let (decoded, _) = WsFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.payload.len(), 70000);
    }

    #[test]
    fn frame_decode_incomplete_returns_none() {
        assert!(WsFrame::decode(&[0x81]).is_none());
        assert!(WsFrame::decode(&[]).is_none());
    }

    #[test]
    fn base64_encode_works() {
        assert_eq!(base64_encode(b"Hello"), "SGVsbG8=");
        assert_eq!(base64_encode(b"Hi"), "SGk=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
    }

    #[test]
    fn compute_accept_key_rfc6455_vector() {
        // RFC 6455 §4.2.2 test vector
        let key = compute_accept_key("dGhlIHNhbXBsZSBub25jZQ==");
        assert_eq!(key, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn build_handshake_response_format() {
        let resp = build_handshake_response("test-key");
        assert!(resp.starts_with("HTTP/1.1 101"));
        assert!(resp.contains("Upgrade: websocket"));
        assert!(resp.contains("Sec-WebSocket-Accept: test-key"));
    }

    #[test]
    fn parse_ws_key_finds_key() {
        let headers = "GET /ws HTTP/1.1\r\nHost: localhost\r\nSec-WebSocket-Key: abc123\r\n";
        assert_eq!(parse_ws_key(headers), Some("abc123".into()));
    }

    #[test]
    fn parse_ws_key_missing_returns_none() {
        let headers = "GET /ws HTTP/1.1\r\nHost: localhost\r\n";
        assert!(parse_ws_key(headers).is_none());
    }

    #[test]
    fn event_bus_publish_and_drain() {
        let bus = EventBus::new(100);
        let id = bus.subscribe(vec![]);
        bus.publish(alert_event("critical", "dev-1", &["test".into()]));
        bus.publish(alert_event("elevated", "dev-2", &["test2".into()]));
        let events = bus.drain(id);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, "alert");
    }

    #[test]
    fn event_bus_filtered_subscription() {
        let bus = EventBus::new(100);
        let id = bus.subscribe(vec!["incident".into()]);
        bus.publish(alert_event("critical", "dev-1", &[]));
        bus.publish(incident_event("inc-1", "Test", "high"));
        let events = bus.drain(id);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "incident");
    }

    #[test]
    fn event_bus_unsubscribe() {
        let bus = EventBus::new(100);
        let id = bus.subscribe(vec![]);
        assert_eq!(bus.subscriber_count(), 1);
        bus.unsubscribe(id);
        assert_eq!(bus.subscriber_count(), 0);
    }

    #[test]
    fn event_bus_recent() {
        let bus = EventBus::new(100);
        for i in 0..5 {
            bus.publish(alert_event("elevated", &format!("dev-{}", i), &[]));
        }
        let recent = bus.recent(3);
        assert_eq!(recent.len(), 3);
    }

    #[test]
    fn event_bus_ring_buffer_limit() {
        let bus = EventBus::new(3);
        for i in 0..10 {
            bus.publish(alert_event("nominal", &format!("dev-{}", i), &[]));
        }
        let recent = bus.recent(100);
        assert_eq!(recent.len(), 3);
    }

    #[test]
    fn event_bus_thread_safe() {
        let bus = EventBus::new(1000);
        let bus2 = bus.clone();
        let id = bus.subscribe(vec![]);
        let h = std::thread::spawn(move || {
            for i in 0..50 {
                bus2.publish(alert_event("elevated", &format!("t-{}", i), &[]));
            }
        });
        for i in 0..50 {
            bus.publish(alert_event("critical", &format!("m-{}", i), &[]));
        }
        h.join().unwrap();
        let events = bus.drain(id);
        assert_eq!(events.len(), 100);
    }

    #[test]
    fn ws_connection_tracking() {
        let mut conn = WsConnection::new(42);
        assert_eq!(conn.subscriber_id, 42);
        assert_eq!(conn.frames_sent, 0);
        conn.record_sent();
        conn.record_received();
        assert_eq!(conn.frames_sent, 1);
        assert_eq!(conn.frames_received, 1);
        assert!(conn.uptime_secs() < 1.0);
    }

    #[test]
    fn frame_decode_rejects_oversized() {
        // Craft a frame header claiming a payload > MAX_FRAME_PAYLOAD
        let mut data = vec![0x81u8, 127]; // text, 8-byte length
        let huge: u64 = (MAX_FRAME_PAYLOAD as u64) + 1;
        data.extend_from_slice(&huge.to_be_bytes());
        assert!(WsFrame::decode(&data).is_none());
    }

    #[test]
    fn helper_events_serialize() {
        let a = alert_event("critical", "dev-1", &["breach".into()]);
        let json = serde_json::to_string(&a).unwrap();
        assert!(json.contains("\"type\":\"alert\""));

        let i = incident_event("inc-1", "Breach", "critical");
        let json = serde_json::to_string(&i).unwrap();
        assert!(json.contains("\"type\":\"incident\""));

        let ag = agent_event("agent-1", "enrolled");
        let json = serde_json::to_string(&ag).unwrap();
        assert!(json.contains("\"type\":\"agent\""));

        let hb = heartbeat_event();
        let json = serde_json::to_string(&hb).unwrap();
        assert!(json.contains("\"type\":\"heartbeat\""));
    }
}
