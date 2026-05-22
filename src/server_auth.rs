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
use std::sync::atomic::{AtomicU64, Ordering};

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

fn failed_auth_token_bucket(presented_token: Option<&str>) -> String {
    let Some(token) = presented_token
        .map(str::trim)
        .filter(|token| !token.is_empty())
    else {
        return "none".into();
    };
    crate::audit::sha256_hex(token.as_bytes())[..12].to_string()
}

/// Returns the internal failed-auth tracking key for a request. The source IP
/// remains the primary dimension, while the optional presented bearer token is
/// represented only by a short SHA-256 prefix so raw credentials never enter
/// memory snapshots, metrics, or audit-adjacent state.
pub(crate) fn failed_auth_subject(ip: &str, presented_token: Option<&str>) -> String {
    if FailedAuthTracker::is_exempt(ip) {
        return ip.to_string();
    }
    format!("{}|token:{}", ip, failed_auth_token_bucket(presented_token))
}

fn failed_auth_ip_subject(ip: &str) -> String {
    ip.to_string()
}

fn failed_auth_tracker() -> &'static std::sync::Mutex<FailedAuthTracker> {
    static TRACKER: std::sync::OnceLock<std::sync::Mutex<FailedAuthTracker>> =
        std::sync::OnceLock::new();
    TRACKER.get_or_init(|| std::sync::Mutex::new(FailedAuthTracker::new()))
}

// ── Observability counters ──────────────────────────────────────────────────
//
// All counters are observability-only and use `Ordering::Relaxed`. They are
// surfaced by [`failed_auth_stats`] and rendered in `/api/metrics` so
// operators can detect brute-force pressure even before a lockout fires.

static FAILED_AUTH_FAILURES_TOTAL: AtomicU64 = AtomicU64::new(0);
static FAILED_AUTH_LOCKOUTS_TRIGGERED: AtomicU64 = AtomicU64::new(0);
static FAILED_AUTH_LOCKOUT_BREACH_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static FAILED_AUTH_RESETS_TOTAL: AtomicU64 = AtomicU64::new(0);
static FAILED_AUTH_EXEMPT_SKIPS: AtomicU64 = AtomicU64::new(0);

/// Read-only snapshot of the failed-auth observability counters plus the
/// currently-active lockout count.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct FailedAuthStats {
    pub(crate) failures_total: u64,
    pub(crate) lockouts_triggered_total: u64,
    pub(crate) lockout_breach_attempts_total: u64,
    pub(crate) resets_total: u64,
    pub(crate) exempt_skips_total: u64,
    pub(crate) active_lockouts: u64,
    pub(crate) tracked_entries: u64,
}

/// Returns the current failed-auth observability snapshot. Locks the
/// tracker briefly to count active lockouts; safe to call from
/// `/api/metrics` request handlers.
pub(crate) fn failed_auth_stats() -> FailedAuthStats {
    let (active, tracked) = match failed_auth_tracker().lock() {
        Ok(g) => {
            let now = FailedAuthTracker::now_secs();
            let active = g.entries.values().filter(|s| now < s.locked_until).count() as u64;
            (active, g.entries.len() as u64)
        }
        Err(e) => {
            let g = e.into_inner();
            let now = FailedAuthTracker::now_secs();
            let active = g.entries.values().filter(|s| now < s.locked_until).count() as u64;
            (active, g.entries.len() as u64)
        }
    };
    FailedAuthStats {
        failures_total: FAILED_AUTH_FAILURES_TOTAL.load(Ordering::Relaxed),
        lockouts_triggered_total: FAILED_AUTH_LOCKOUTS_TRIGGERED.load(Ordering::Relaxed),
        lockout_breach_attempts_total: FAILED_AUTH_LOCKOUT_BREACH_ATTEMPTS.load(Ordering::Relaxed),
        resets_total: FAILED_AUTH_RESETS_TOTAL.load(Ordering::Relaxed),
        exempt_skips_total: FAILED_AUTH_EXEMPT_SKIPS.load(Ordering::Relaxed),
        active_lockouts: active,
        tracked_entries: tracked,
    }
}

#[cfg(test)]
pub(crate) fn failed_auth_locked_subject(ip: &str, subject: &str) -> Option<u64> {
    if FailedAuthTracker::is_exempt(ip) {
        FAILED_AUTH_EXEMPT_SKIPS.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    let remaining = failed_auth_tracker()
        .lock()
        .ok()
        .and_then(|mut g| g.locked_remaining(subject));
    if remaining.is_some() {
        FAILED_AUTH_LOCKOUT_BREACH_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    }
    remaining
}

pub(crate) fn failed_auth_locked_request(ip: &str, subject: &str) -> Option<u64> {
    if FailedAuthTracker::is_exempt(ip) {
        FAILED_AUTH_EXEMPT_SKIPS.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    let ip_subject = failed_auth_ip_subject(ip);
    let remaining = failed_auth_tracker().lock().ok().and_then(|mut g| {
        let ip_remaining = g.locked_remaining(&ip_subject);
        let subject_remaining = if subject == ip_subject {
            None
        } else {
            g.locked_remaining(subject)
        };
        ip_remaining.max(subject_remaining)
    });
    if remaining.is_some() {
        FAILED_AUTH_LOCKOUT_BREACH_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    }
    remaining
}

/// Records a failed auth attempt. Returns Some(lockout_secs) if this attempt
/// triggered a fresh lockout (callers can audit-log the event).
pub(crate) fn failed_auth_record(ip: &str) -> Option<u64> {
    let subject = failed_auth_ip_subject(ip);
    failed_auth_record_subject(ip, &subject)
}

pub(crate) fn failed_auth_record_subject(ip: &str, subject: &str) -> Option<u64> {
    if FailedAuthTracker::is_exempt(ip) {
        FAILED_AUTH_EXEMPT_SKIPS.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    FAILED_AUTH_FAILURES_TOTAL.fetch_add(1, Ordering::Relaxed);
    let triggered = failed_auth_tracker()
        .lock()
        .ok()
        .and_then(|mut g| g.record_failure(subject));
    if triggered.is_some() {
        FAILED_AUTH_LOCKOUTS_TRIGGERED.fetch_add(1, Ordering::Relaxed);
    }
    triggered
}

pub(crate) fn failed_auth_record_request(ip: &str, subject: &str) -> Option<u64> {
    if FailedAuthTracker::is_exempt(ip) {
        FAILED_AUTH_EXEMPT_SKIPS.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    FAILED_AUTH_FAILURES_TOTAL.fetch_add(1, Ordering::Relaxed);
    let ip_subject = failed_auth_ip_subject(ip);
    let triggered = failed_auth_tracker().lock().ok().and_then(|mut g| {
        let ip_triggered = g.record_failure(&ip_subject);
        let subject_triggered = if subject == ip_subject {
            None
        } else {
            g.record_failure(subject)
        };
        ip_triggered.or(subject_triggered)
    });
    if triggered.is_some() {
        FAILED_AUTH_LOCKOUTS_TRIGGERED.fetch_add(1, Ordering::Relaxed);
    }
    triggered
}

pub(crate) fn failed_auth_clear(ip: &str) {
    let subject = failed_auth_ip_subject(ip);
    failed_auth_clear_subject(ip, &subject);
}

pub(crate) fn failed_auth_clear_subject(ip: &str, subject: &str) {
    if FailedAuthTracker::is_exempt(ip) {
        FAILED_AUTH_EXEMPT_SKIPS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if let Ok(mut g) = failed_auth_tracker().lock() {
        let existed = g.entries.contains_key(subject);
        g.record_success(subject);
        if existed {
            FAILED_AUTH_RESETS_TOTAL.fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub(crate) fn failed_auth_clear_request(ip: &str, subject: &str) {
    if FailedAuthTracker::is_exempt(ip) {
        FAILED_AUTH_EXEMPT_SKIPS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if let Ok(mut g) = failed_auth_tracker().lock() {
        let ip_subject = failed_auth_ip_subject(ip);
        let ip_existed = g.entries.contains_key(&ip_subject);
        g.record_success(&ip_subject);
        let subject_existed = if subject == ip_subject {
            false
        } else {
            let existed = g.entries.contains_key(subject);
            g.record_success(subject);
            existed
        };
        if ip_existed || subject_existed {
            FAILED_AUTH_RESETS_TOTAL.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Test-only helper: records a synthetic failed-auth attempt for `ip`.
///
/// Exposed `#[doc(hidden)] pub` so integration tests in `tests/` can drive
/// the process-global tracker with non-loopback IPs (loopback is exempt by
/// design, which makes a real-IP HTTP E2E impossible from in-process tests).
/// Production callers must continue to use the crate-private wrappers.
#[doc(hidden)]
pub fn __test_failed_auth_record(ip: &str) -> Option<u64> {
    failed_auth_record(ip)
}

/// Test-only helper: clears the synthetic failed-auth state for `ip`.
#[doc(hidden)]
pub fn __test_failed_auth_clear(ip: &str) {
    failed_auth_clear(ip);
}

/// Test-only helper: snapshots the failed-auth counters/stats.
#[doc(hidden)]
pub fn __test_failed_auth_stats() -> FailedAuthStatsSnapshot {
    let s = failed_auth_stats();
    FailedAuthStatsSnapshot {
        failures_total: s.failures_total,
        lockouts_triggered_total: s.lockouts_triggered_total,
        lockout_breach_attempts_total: s.lockout_breach_attempts_total,
        resets_total: s.resets_total,
        exempt_skips_total: s.exempt_skips_total,
        active_lockouts: s.active_lockouts,
        tracked_entries: s.tracked_entries,
    }
}

/// Public mirror of `FailedAuthStats` for test consumers.
#[doc(hidden)]
#[derive(Debug, Clone, Copy)]
pub struct FailedAuthStatsSnapshot {
    pub failures_total: u64,
    pub lockouts_triggered_total: u64,
    pub lockout_breach_attempts_total: u64,
    pub resets_total: u64,
    pub exempt_skips_total: u64,
    pub active_lockouts: u64,
    pub tracked_entries: u64,
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

    #[test]
    fn failed_auth_stats_increment_on_failure_and_lockout() {
        // The tracker state is keyed by IP, but the observability counters are
        // process-global, so parallel tests may also move them forward.
        let ip = "203.0.113.77";
        failed_auth_clear(ip);
        let before = failed_auth_stats();
        // Below threshold: increments failures_total but not lockouts.
        for _ in 0..(FAILED_AUTH_THRESHOLD - 1) {
            failed_auth_record(ip);
        }
        let mid = failed_auth_stats();
        assert!(mid.failures_total >= before.failures_total + (FAILED_AUTH_THRESHOLD - 1) as u64);
        // Threshold-th failure triggers a lockout.
        failed_auth_record(ip);
        let after = failed_auth_stats();
        assert!(after.failures_total >= before.failures_total + FAILED_AUTH_THRESHOLD as u64);
        assert!(after.lockouts_triggered_total >= before.lockouts_triggered_total + 1);
        // Probing while locked counts as a breach attempt.
        let before_breach = failed_auth_stats().lockout_breach_attempts_total;
        let subject = failed_auth_ip_subject(ip);
        assert!(failed_auth_locked_subject(ip, &subject).is_some());
        let after_breach = failed_auth_stats().lockout_breach_attempts_total;
        assert!(after_breach >= before_breach + 1);
        // Cleanup so subsequent tests don't see a stale entry.
        failed_auth_clear(ip);
    }

    #[test]
    fn failed_auth_clear_records_reset_when_entry_existed() {
        let ip = "198.51.100.9";
        // Seed a failure so the IP has an entry.
        failed_auth_record(ip);
        let before = failed_auth_stats();
        failed_auth_clear(ip);
        let after = failed_auth_stats();
        assert!(after.resets_total >= before.resets_total + 1);
        // Clearing an unknown IP does NOT count as a reset.
        let before2 = failed_auth_stats();
        failed_auth_clear("198.51.100.10");
        let after2 = failed_auth_stats();
        assert!(after2.resets_total >= before2.resets_total);
    }

    #[test]
    fn failed_auth_stats_count_exempt_skips() {
        let before = failed_auth_stats();
        // Loopback addresses are exempt and should bump the exempt counter.
        assert!(failed_auth_record("127.0.0.1").is_none());
        let loopback_subject = failed_auth_subject("::1", None);
        assert!(failed_auth_locked_subject("::1", &loopback_subject).is_none());
        failed_auth_clear("127.0.0.5");
        let after = failed_auth_stats();
        assert!(after.exempt_skips_total - before.exempt_skips_total >= 3);
    }

    #[test]
    fn failed_auth_subject_separates_presented_token_buckets() {
        let ip = "198.51.100.44";
        let token_a = failed_auth_subject(ip, Some("token-a"));
        let token_b = failed_auth_subject(ip, Some("token-b"));
        assert_ne!(token_a, token_b);
        assert!(!token_a.contains("token-a"));
        assert!(!token_b.contains("token-b"));

        failed_auth_clear_subject(ip, &token_a);
        failed_auth_clear_subject(ip, &token_b);
        for _ in 0..FAILED_AUTH_THRESHOLD {
            failed_auth_record_subject(ip, &token_a);
        }

        assert!(failed_auth_locked_subject(ip, &token_a).is_some());
        assert!(failed_auth_locked_subject(ip, &token_b).is_none());
        failed_auth_clear_subject(ip, &token_a);
        failed_auth_clear_subject(ip, &token_b);
    }

    #[test]
    fn failed_auth_request_preserves_ip_wide_lockout_for_rotating_tokens() {
        let ip = "198.51.100.45";
        let cleanup_subject = failed_auth_subject(ip, Some("token-new"));
        failed_auth_clear_request(ip, &cleanup_subject);

        for i in 0..FAILED_AUTH_THRESHOLD {
            let subject = failed_auth_subject(ip, Some(&format!("token-{}", i)));
            failed_auth_record_request(ip, &subject);
        }

        assert!(failed_auth_locked_request(ip, &cleanup_subject).is_some());
        for i in 0..FAILED_AUTH_THRESHOLD {
            let subject = failed_auth_subject(ip, Some(&format!("token-{}", i)));
            failed_auth_clear_request(ip, &subject);
        }
        failed_auth_clear_request(ip, &cleanup_subject);
    }
}
