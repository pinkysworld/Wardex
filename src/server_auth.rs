//! Token parsing, constant-time comparison, and per-IP failed-auth rate
//! limiting helpers.
//!
//! Extracted from `server.rs` as part of the incremental decomposition
//! started in v1.0.23 (alongside `server_ml.rs`, `server_feeds.rs`,
//! `server_cluster.rs`, `server_response.rs`). Everything in this module is
//! self-contained (no `AppState` access) so it can live behind a process-global
//! `OnceLock` and be exercised in unit tests without spinning a server.

use axum::body::Body;
use axum::http::HeaderMap;
use axum::response::Response;

/// Parses an `Authorization: Bearer <token>` header, returning the token.
///
/// The scheme match is case-insensitive (some legacy clients send `BEARER`);
/// the token is trimmed of surrounding whitespace.
pub(crate) fn bearer_token(headers: &HeaderMap) -> Option<String> {
    if let Some(val) = headers.get("authorization")
        && let Ok(s) = val.to_str()
        && let Some((scheme, token)) = s.split_once(char::is_whitespace)
        && scheme.eq_ignore_ascii_case("bearer")
    {
        let trimmed = token.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    None
}

/// Constant-time byte comparison of two tokens. Returns `false` when either
/// side is missing or the lengths differ — but never short-circuits on the
/// first differing byte, so attackers cannot infer prefix matches by timing.
pub(crate) fn secure_token_eq(provided: Option<&str>, expected: &str) -> bool {
    let Some(provided) = provided else {
        return false;
    };
    let a = provided.as_bytes();
    let b = expected.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ── Failed-auth backoff tracker ─────────────────────────────────────────────
//
// The generic per-route rate limiter doesn't distinguish successful from
// failed auth, so a brute-force attempt against `/api/auth/*` or the agent /
// cluster bearer-token paths gets the full read-quota of attempts per minute.
// This tracker layers an exponential backoff on *failed* auth specifically:
//   - 5 consecutive failures from the same IP within 5 minutes → 30 s lockout
//   - Lockout doubles on every subsequent burst (cap 1 h)
//   - A success resets the counter
//   - Loopback addresses (127.0.0.1 / ::1 / unknown) are exempt so local
//     tooling and cluster peers aren't penalized
//
// Stored as a process-global so we can add it without rewiring AppState
// constructors. Bounded in size by a periodic sweep.

pub(crate) struct FailedAuthState {
    pub(crate) fails: u32,
    pub(crate) first_fail_at: u64,
    pub(crate) locked_until: u64,
    pub(crate) lockout_secs: u64,
}

pub(crate) struct FailedAuthTracker {
    pub(crate) entries: std::collections::HashMap<String, FailedAuthState>,
    pub(crate) last_sweep: u64,
}

pub(crate) const FAILED_AUTH_THRESHOLD: u32 = 5;
pub(crate) const FAILED_AUTH_WINDOW_SECS: u64 = 300;
pub(crate) const FAILED_AUTH_INITIAL_LOCKOUT_SECS: u64 = 30;
pub(crate) const FAILED_AUTH_MAX_LOCKOUT_SECS: u64 = 3600;
pub(crate) const FAILED_AUTH_MAX_ENTRIES: usize = 1024;

impl FailedAuthTracker {
    pub(crate) fn new() -> Self {
        Self {
            entries: std::collections::HashMap::new(),
            last_sweep: 0,
        }
    }

    pub(crate) fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    pub(crate) fn is_exempt(ip: &str) -> bool {
        ip.is_empty()
            || ip == "unknown"
            || ip.starts_with("127.")
            || ip == "::1"
            || ip.starts_with("[::1]")
    }

    pub(crate) fn sweep(&mut self, now: u64) {
        if now.saturating_sub(self.last_sweep) < 60 {
            return;
        }
        self.last_sweep = now;
        self.entries.retain(|_, s| {
            now < s.locked_until || now.saturating_sub(s.first_fail_at) < FAILED_AUTH_WINDOW_SECS
        });
        if self.entries.len() > FAILED_AUTH_MAX_ENTRIES {
            self.entries.clear();
        }
    }

    /// Returns Some(remaining_secs) if the IP is currently locked out.
    pub(crate) fn locked_remaining(&mut self, ip: &str) -> Option<u64> {
        if Self::is_exempt(ip) {
            return None;
        }
        let now = Self::now_secs();
        self.sweep(now);
        let s = self.entries.get(ip)?;
        if now < s.locked_until {
            Some(s.locked_until - now)
        } else {
            None
        }
    }

    pub(crate) fn record_failure(&mut self, ip: &str) -> Option<u64> {
        if Self::is_exempt(ip) {
            return None;
        }
        let now = Self::now_secs();
        self.sweep(now);
        let entry = self
            .entries
            .entry(ip.to_string())
            .or_insert(FailedAuthState {
                fails: 0,
                first_fail_at: now,
                locked_until: 0,
                lockout_secs: FAILED_AUTH_INITIAL_LOCKOUT_SECS,
            });
        if now.saturating_sub(entry.first_fail_at) > FAILED_AUTH_WINDOW_SECS {
            entry.fails = 0;
            entry.first_fail_at = now;
        }
        entry.fails = entry.fails.saturating_add(1);
        if entry.fails >= FAILED_AUTH_THRESHOLD {
            entry.locked_until = now + entry.lockout_secs;
            let triggered = entry.lockout_secs;
            entry.lockout_secs =
                (entry.lockout_secs.saturating_mul(2)).min(FAILED_AUTH_MAX_LOCKOUT_SECS);
            entry.fails = 0;
            entry.first_fail_at = now;
            Some(triggered)
        } else {
            None
        }
    }

    pub(crate) fn record_success(&mut self, ip: &str) {
        if Self::is_exempt(ip) {
            return;
        }
        self.entries.remove(ip);
    }
}

fn failed_auth_tracker() -> &'static std::sync::Mutex<FailedAuthTracker> {
    static TRACKER: std::sync::OnceLock<std::sync::Mutex<FailedAuthTracker>> =
        std::sync::OnceLock::new();
    TRACKER.get_or_init(|| std::sync::Mutex::new(FailedAuthTracker::new()))
}

/// Returns Some(retry_after_secs) if the IP is locked out.
pub(crate) fn failed_auth_locked(ip: &str) -> Option<u64> {
    failed_auth_tracker()
        .lock()
        .ok()
        .and_then(|mut g| g.locked_remaining(ip))
}

/// Records a failed auth attempt. Returns Some(lockout_secs) if this attempt
/// triggered a fresh lockout (callers can audit-log the event).
pub(crate) fn failed_auth_record(ip: &str) -> Option<u64> {
    failed_auth_tracker()
        .lock()
        .ok()
        .and_then(|mut g| g.record_failure(ip))
}

pub(crate) fn failed_auth_clear(ip: &str) {
    if let Ok(mut g) = failed_auth_tracker().lock() {
        g.record_success(ip);
    }
}

/// Returns the 429 response carrying the retry-after, used when the IP is
/// already locked out from prior failed auth attempts.
pub(crate) fn failed_auth_locked_response(retry_after_secs: u64) -> Response<Body> {
    let body = format!(
        "{{\"error\":\"too many failed authentication attempts\",\"retry_after_secs\":{retry_after_secs},\"status\":429}}"
    );
    Response::builder()
        .status(429)
        .header("content-type", "application/json")
        .header("retry-after", retry_after_secs.to_string())
        .body(Body::from(body))
        .unwrap_or_else(|_| Response::new(Body::from("rate limited")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn hdr(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("authorization", HeaderValue::from_str(value).unwrap());
        h
    }

    #[test]
    fn bearer_token_rejects_empty_token_after_scheme() {
        // "Bearer " with nothing after is not a valid token.
        assert_eq!(bearer_token(&hdr("Bearer ")), None);
        // Whitespace-only payload also rejected.
        assert_eq!(bearer_token(&hdr("Bearer    ")), None);
    }

    #[test]
    fn bearer_token_returns_none_for_non_bearer_schemes() {
        assert_eq!(bearer_token(&hdr("Basic dXNlcjpwYXNz")), None);
        assert_eq!(bearer_token(&hdr("Digest nonce=abc")), None);
    }

    #[test]
    fn bearer_token_returns_none_when_header_missing() {
        let headers = HeaderMap::new();
        assert_eq!(bearer_token(&headers), None);
    }

    #[test]
    fn bearer_token_trims_surrounding_whitespace() {
        assert_eq!(
            bearer_token(&hdr("Bearer   tok-42  ")).as_deref(),
            Some("tok-42")
        );
    }

    #[test]
    fn secure_token_eq_rejects_length_mismatch_without_panic() {
        // The early length check must not panic on differing-length inputs.
        assert!(!secure_token_eq(Some("short"), "much-longer-token"));
        assert!(!secure_token_eq(Some("much-longer-token"), "short"));
    }

    #[test]
    fn secure_token_eq_handles_empty_expected() {
        assert!(secure_token_eq(Some(""), ""));
        assert!(!secure_token_eq(Some("x"), ""));
    }

    #[test]
    fn failed_auth_tracker_exempts_unknown_and_ipv6_loopback() {
        let mut t = FailedAuthTracker::new();
        for _ in 0..(FAILED_AUTH_THRESHOLD + 2) {
            assert!(t.record_failure("unknown").is_none());
            assert!(t.record_failure("::1").is_none());
            assert!(t.record_failure("[::1]").is_none());
            assert!(t.record_failure("").is_none());
        }
        assert!(t.locked_remaining("unknown").is_none());
        assert!(t.locked_remaining("::1").is_none());
        assert!(t.locked_remaining("[::1]").is_none());
        assert!(t.locked_remaining("").is_none());
    }

    #[test]
    fn failed_auth_tracker_lockout_caps_at_max() {
        let mut t = FailedAuthTracker::new();
        // Force the lockout to grow until it hits the cap. Each lockout cycle
        // requires THRESHOLD failures; we cap iteration so the test stays fast.
        for _ in 0..40 {
            for _ in 0..FAILED_AUTH_THRESHOLD {
                t.record_failure("9.9.9.9");
            }
        }
        let stored = t
            .entries
            .get("9.9.9.9")
            .expect("entry exists after lockouts");
        assert_eq!(stored.lockout_secs, FAILED_AUTH_MAX_LOCKOUT_SECS);
    }

    #[test]
    fn failed_auth_tracker_sweep_drops_idle_entries() {
        let mut t = FailedAuthTracker::new();
        // Inject a stale entry that is past the window and not locked.
        t.entries.insert(
            "8.8.8.8".to_string(),
            FailedAuthState {
                fails: 1,
                first_fail_at: 0,
                locked_until: 0,
                lockout_secs: FAILED_AUTH_INITIAL_LOCKOUT_SECS,
            },
        );
        // last_sweep = 0 so the >=60s gate trivially passes.
        t.sweep(FAILED_AUTH_WINDOW_SECS + 120);
        assert!(!t.entries.contains_key("8.8.8.8"));
    }

    #[test]
    fn failed_auth_tracker_sweep_keeps_locked_entries() {
        let mut t = FailedAuthTracker::new();
        let now = FailedAuthTracker::now_secs();
        t.entries.insert(
            "8.8.4.4".to_string(),
            FailedAuthState {
                fails: 0,
                first_fail_at: 0,
                locked_until: now + 300,
                lockout_secs: FAILED_AUTH_INITIAL_LOCKOUT_SECS,
            },
        );
        t.sweep(now);
        assert!(t.entries.contains_key("8.8.4.4"));
    }

    #[test]
    fn failed_auth_tracker_sweep_clears_when_entry_cap_exceeded() {
        let mut t = FailedAuthTracker::new();
        // Insert MAX_ENTRIES + 1 stale entries that would otherwise be retained.
        let now = FailedAuthTracker::now_secs();
        for i in 0..(FAILED_AUTH_MAX_ENTRIES + 1) {
            t.entries.insert(
                format!("10.0.{}.{}", i / 256, i % 256),
                FailedAuthState {
                    fails: 1,
                    first_fail_at: now,
                    locked_until: now + 600,
                    lockout_secs: FAILED_AUTH_INITIAL_LOCKOUT_SECS,
                },
            );
        }
        // Force the sweep to run (last_sweep=0).
        t.sweep(now);
        assert!(t.entries.is_empty(), "sweep should clear when over cap");
    }

    #[test]
    fn failed_auth_locked_response_carries_retry_after_header() {
        let resp = failed_auth_locked_response(42);
        assert_eq!(resp.status(), 429);
        assert_eq!(
            resp.headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok()),
            Some("42")
        );
        assert_eq!(
            resp.headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
    }
}
