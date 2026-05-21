//! Concurrent backend smoke test.
//!
//! Spawns the in-process test server and fires N parallel requests across a
//! mix of read-only and authenticated routes. Verifies:
//!   * every request succeeds (status code < 500),
//!   * no panic / poisoned lock surfaces,
//!   * `/api/metrics` is parseable after the storm and exposes the new
//!     `wardex_state_lock_*` and `wardex_failed_auth_*` series.
//!
//! Acts as a guard against accidental lock-ordering or lifetime regressions
//! introduced by future `state.lock()` migrations.

use std::sync::{Arc, atomic::AtomicUsize, atomic::Ordering};
use std::thread;
use std::time::Duration;

use wardex::server::spawn_test_server;

const WORKERS: usize = 16;
const ITERATIONS_PER_WORKER: usize = 12;

fn base(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

fn auth_header(token: &str) -> String {
    format!("Bearer {token}")
}

#[test]
fn concurrent_mixed_route_smoke_keeps_server_healthy() {
    let (port, token) = spawn_test_server();
    let token = Arc::new(token);
    let base_url = Arc::new(base(port));
    let errors = Arc::new(AtomicUsize::new(0));
    let server_errors = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::with_capacity(WORKERS);
    for worker in 0..WORKERS {
        let token = token.clone();
        let base_url = base_url.clone();
        let errors = errors.clone();
        let server_errors = server_errors.clone();
        handles.push(thread::spawn(move || {
            // Rotate across a mix of routes so the parallel calls actually
            // contend on the shared AppState mutex rather than serializing on
            // a single handler's locks.
            let routes = ["/api/status", "/api/health", "/api/metrics", "/api/version"];
            for i in 0..ITERATIONS_PER_WORKER {
                let route = routes[(worker + i) % routes.len()];
                let url = format!("{}{}", base_url, route);
                let result = ureq::get(&url)
                    .set("Authorization", &auth_header(&token))
                    .timeout(Duration::from_secs(10))
                    .call();
                match result {
                    Ok(resp) => {
                        let code = resp.status();
                        if code >= 500 {
                            server_errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(ureq::Error::Status(code, _)) => {
                        if code >= 500 {
                            server_errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(_) => {
                        errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }
    for h in handles {
        h.join().expect("worker panicked");
    }

    let transport_errors = errors.load(Ordering::Relaxed);
    let five_xx = server_errors.load(Ordering::Relaxed);
    assert_eq!(
        transport_errors, 0,
        "expected no transport errors under concurrent load"
    );
    assert_eq!(
        five_xx, 0,
        "expected no 5xx responses under concurrent load"
    );

    // Pull /metrics and ensure the new state-lock and failed-auth series are
    // visible (sanity check that load actually exercised tracked_lock paths).
    let metrics = ureq::get(&format!("{}/api/metrics", base_url))
        .set("Authorization", &auth_header(&token))
        .call()
        .expect("metrics fetch")
        .into_string()
        .expect("metrics body");

    for needle in [
        "wardex_state_lock_acquisitions_total ",
        "wardex_state_lock_poisoned_total ",
        "wardex_failed_auth_failures_total ",
        "wardex_failed_auth_active_lockouts ",
    ] {
        assert!(
            metrics.contains(needle),
            "expected /api/metrics to expose `{}` after concurrent smoke; got:\n{}",
            needle,
            metrics.lines().take(40).collect::<Vec<_>>().join("\n")
        );
    }

    // Poisoned counter must stay at 0 (no panics inside locked sections).
    let poisoned_line = metrics
        .lines()
        .find(|l| l.starts_with("wardex_state_lock_poisoned_total "))
        .expect("poisoned line present");
    let value: u64 = poisoned_line
        .rsplit(' ')
        .next()
        .and_then(|v| v.parse().ok())
        .expect("parsable poisoned counter");
    assert_eq!(
        value, 0,
        "no handler should have poisoned the AppState mutex during concurrent smoke"
    );
}
