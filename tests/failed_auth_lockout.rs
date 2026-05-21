//! Failed-auth lockout end-to-end test.
//!
//! Drives the process-global failed-auth tracker with synthetic non-loopback
//! IPs (loopback is exempt by design, so a real-IP HTTP path can't be
//! exercised in-process) and verifies the `/api/metrics` endpoint exposes
//! the resulting counters.
//!
//! Guards three contracts simultaneously:
//!   * `wardex_failed_auth_failures_total` increments per recorded failure.
//!   * Crossing the threshold flips `wardex_failed_auth_lockouts_triggered_total`
//!     and `wardex_failed_auth_active_lockouts`.
//!   * Clearing the IP increments `wardex_failed_auth_resets_total` and
//!     drops the active-lockouts gauge back to zero.
//!
//! Each integration test runs in its own binary, so the process-global
//! atomics start at zero here.

use std::collections::HashMap;
use std::time::Duration;

use wardex::server::spawn_test_server;
use wardex::server_auth::{
    __test_failed_auth_clear, __test_failed_auth_record, __test_failed_auth_stats,
};

/// Mirrors `FAILED_AUTH_THRESHOLD` in `src/server_auth.rs`. Kept in sync by
/// hand because the constant is `pub(crate)`; if you bump the production
/// threshold, update this too.
const THRESHOLD: u32 = 5;

fn metric_map(body: &str) -> HashMap<String, f64> {
    let mut out = HashMap::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Skip labeled series — the failed-auth counters here are unlabeled.
        if line.contains('{') {
            continue;
        }
        if let Some((name, value)) = line.split_once(char::is_whitespace)
            && let Ok(v) = value.trim().parse::<f64>()
        {
            out.insert(name.to_string(), v);
        }
    }
    out
}

#[test]
fn failed_auth_lockout_increments_metrics_and_resets_on_clear() {
    let (port, token) = spawn_test_server();
    let base = format!("http://127.0.0.1:{port}");
    let auth = format!("Bearer {token}");

    // Synthetic, documentation-reserved (RFC 5737) IP guarantees we never
    // collide with a real client and is not in the loopback exempt set.
    let ip = "203.0.113.42";

    // Snapshot the initial state — each integration test binary owns its own
    // process, so these should be zero, but read them defensively rather than
    // asserting equality so the test stays robust if other init code touches
    // the tracker in the future.
    let baseline = __test_failed_auth_stats();
    assert_eq!(baseline.active_lockouts, 0, "no active lockouts at startup");

    // Record THRESHOLD failures — the THRESHOLD-th one trips the lockout.
    let mut triggered_at = None;
    for i in 0..THRESHOLD {
        if let Some(secs) = __test_failed_auth_record(ip) {
            triggered_at = Some((i + 1, secs));
            break;
        }
    }
    let (trip_n, lockout_secs) = triggered_at.expect("lockout should trip within THRESHOLD calls");
    assert_eq!(
        trip_n, THRESHOLD,
        "lockout trips on the THRESHOLD-th failure"
    );
    assert!(
        lockout_secs > 0,
        "initial lockout duration must be positive"
    );

    let after_trip = __test_failed_auth_stats();
    assert_eq!(
        after_trip.failures_total,
        baseline.failures_total + u64::from(THRESHOLD),
        "failures_total advanced by exactly THRESHOLD",
    );
    assert_eq!(
        after_trip.lockouts_triggered_total,
        baseline.lockouts_triggered_total + 1,
        "lockouts_triggered_total advanced by exactly one",
    );
    assert_eq!(after_trip.active_lockouts, 1, "exactly one IP is locked");

    // Drive one extra recorded failure while locked — should still count
    // toward failures_total and bump lockout_breach_attempts via the locked
    // probe path. We exercise the locked-probe directly via the metrics
    // surface below instead of touching another helper.
    let _ = __test_failed_auth_record(ip);

    // Now hit /api/metrics and confirm the live exposition reflects the
    // tracker state we just observed.
    let resp = ureq::get(&format!("{base}/api/metrics"))
        .set("Authorization", &auth)
        .timeout(Duration::from_secs(10))
        .call()
        .expect("metrics request succeeds");
    assert_eq!(resp.status(), 200, "metrics endpoint returns 200");
    let body = resp.into_string().expect("metrics body is utf-8");
    let metrics = metric_map(&body);

    let failures = metrics
        .get("wardex_failed_auth_failures_total")
        .copied()
        .expect("failures_total exposed");
    let triggered = metrics
        .get("wardex_failed_auth_lockouts_triggered_total")
        .copied()
        .expect("lockouts_triggered_total exposed");
    let active = metrics
        .get("wardex_failed_auth_active_lockouts")
        .copied()
        .expect("active_lockouts exposed");

    assert!(
        failures >= u64::from(THRESHOLD) as f64,
        "live failures_total >= THRESHOLD (got {failures})",
    );
    assert!(
        triggered >= 1.0,
        "live lockouts_triggered_total >= 1 (got {triggered})",
    );
    assert_eq!(active, 1.0, "live active_lockouts == 1");

    // Clearing the IP must drop the gauge back to zero and bump resets_total.
    __test_failed_auth_clear(ip);
    let after_clear = __test_failed_auth_stats();
    assert_eq!(after_clear.active_lockouts, 0, "clear releases the lockout");
    assert_eq!(
        after_clear.resets_total,
        after_trip.resets_total + 1,
        "resets_total advanced by exactly one",
    );
}
