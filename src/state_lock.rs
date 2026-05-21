//! Lock-acquisition instrumentation for the global `AppState` mutex (and any
//! other hot `std::sync::Mutex`).
//!
//! The bulk of the axum handler in `server.rs` calls `state.lock()` hundreds
//! of times per request flow. Operators have no visibility into how long
//! those acquisitions actually take — a slow handler could be CPU-bound, I/O
//! bound, or spinning on the global lock, and the existing
//! `wardex_http_request_duration_ms` histogram cannot tell us which.
//!
//! This module exposes:
//!
//!   * [`tracked_lock`] — drop-in replacement for `mutex.lock()` that records
//!     the wait latency into atomic counters before returning the guard.
//!   * [`LockStatsSnapshot`] / [`snapshot`] — a cheap read-only view that the
//!     `/metrics` and `/api/health/diagnostics` endpoints can surface.
//!   * [`SLOW_LOCK_WAIT_THRESHOLD_MS`] — the bound above which an acquisition
//!     is logged as a slow wait (currently 25 ms; tunable here only).
//!
//! Counters use `Ordering::Relaxed` because they are observability-only.
//! Migration is opt-in: a callsite uses `tracked_lock(&state, "label")`
//! instead of `state.lock()`. Existing `state.lock()` callers continue to
//! work unchanged.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::Instant;

/// Acquisitions taking longer than this are counted as "slow waits" and
/// reported separately in the snapshot.
pub(crate) const SLOW_LOCK_WAIT_THRESHOLD_MS: u64 = 25;

static LOCK_ACQUISITIONS: AtomicU64 = AtomicU64::new(0);
static LOCK_WAIT_NS_TOTAL: AtomicU64 = AtomicU64::new(0);
static LOCK_SLOW_WAITS: AtomicU64 = AtomicU64::new(0);
static LOCK_MAX_WAIT_NS: AtomicU64 = AtomicU64::new(0);
static LOCK_POISONED: AtomicU64 = AtomicU64::new(0);

/// Read-only snapshot of the lock-instrumentation counters. Returned by
/// [`snapshot`]; safe to render into Prometheus text or JSON diagnostics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct LockStatsSnapshot {
    pub(crate) acquisitions: u64,
    pub(crate) wait_ns_total: u64,
    pub(crate) slow_waits: u64,
    pub(crate) max_wait_ns: u64,
    pub(crate) poisoned: u64,
}

impl LockStatsSnapshot {
    /// Convenience: returns the mean acquisition latency in milliseconds, or
    /// 0.0 when no acquisitions have been recorded yet.
    pub(crate) fn mean_wait_ms(&self) -> f64 {
        if self.acquisitions == 0 {
            0.0
        } else {
            (self.wait_ns_total as f64) / (self.acquisitions as f64) / 1_000_000.0
        }
    }
}

/// Returns the current snapshot of lock-acquisition counters.
pub(crate) fn snapshot() -> LockStatsSnapshot {
    LockStatsSnapshot {
        acquisitions: LOCK_ACQUISITIONS.load(Ordering::Relaxed),
        wait_ns_total: LOCK_WAIT_NS_TOTAL.load(Ordering::Relaxed),
        slow_waits: LOCK_SLOW_WAITS.load(Ordering::Relaxed),
        max_wait_ns: LOCK_MAX_WAIT_NS.load(Ordering::Relaxed),
        poisoned: LOCK_POISONED.load(Ordering::Relaxed),
    }
}

/// Acquires the given mutex, measures the wait latency, and records the
/// observation into the global counters before returning the guard.
///
/// On poisoned mutexes the inner data is recovered via `into_inner()` so the
/// instrumentation matches the existing `unwrap_or_else(|e| e.into_inner())`
/// pattern used throughout `server.rs`.
///
/// The `label` argument is reserved for a future label-aware metric — it is
/// accepted now so call sites don't need to change again later. The compiler
/// can dead-code-eliminate the argument until that ships.
pub(crate) fn tracked_lock<'a, T>(mutex: &'a Mutex<T>, _label: &'static str) -> MutexGuard<'a, T> {
    let started = Instant::now();
    let guard = match mutex.lock() {
        Ok(g) => g,
        Err(poisoned) => {
            LOCK_POISONED.fetch_add(1, Ordering::Relaxed);
            poisoned.into_inner()
        }
    };
    let waited = started.elapsed();
    let waited_ns = waited.as_nanos().min(u64::MAX as u128) as u64;
    LOCK_ACQUISITIONS.fetch_add(1, Ordering::Relaxed);
    LOCK_WAIT_NS_TOTAL.fetch_add(waited_ns, Ordering::Relaxed);
    if waited.as_millis() as u64 >= SLOW_LOCK_WAIT_THRESHOLD_MS {
        LOCK_SLOW_WAITS.fetch_add(1, Ordering::Relaxed);
    }
    // Lock-free max update via compare-and-swap retry loop.
    let mut current = LOCK_MAX_WAIT_NS.load(Ordering::Relaxed);
    while waited_ns > current {
        match LOCK_MAX_WAIT_NS.compare_exchange_weak(
            current,
            waited_ns,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(observed) => current = observed,
        }
    }
    guard
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    // Each test grabs a private baseline of the global counters and asserts
    // on the *delta* so concurrent test execution cannot cause spurious
    // failures.
    fn delta(before: LockStatsSnapshot, after: LockStatsSnapshot) -> LockStatsSnapshot {
        LockStatsSnapshot {
            acquisitions: after.acquisitions - before.acquisitions,
            wait_ns_total: after.wait_ns_total.saturating_sub(before.wait_ns_total),
            slow_waits: after.slow_waits - before.slow_waits,
            max_wait_ns: after.max_wait_ns,
            poisoned: after.poisoned - before.poisoned,
        }
    }

    #[test]
    fn tracked_lock_records_acquisition() {
        let m = Mutex::new(0_u32);
        let before = snapshot();
        {
            let mut g = tracked_lock(&m, "test/basic");
            *g += 1;
        }
        let after = snapshot();
        let d = delta(before, after);
        assert_eq!(d.acquisitions, 1);
        assert_eq!(d.poisoned, 0);
    }

    #[test]
    fn tracked_lock_recovers_from_poisoned_mutex() {
        let m = Arc::new(Mutex::new(42_u32));
        let m2 = m.clone();
        let _ = thread::spawn(move || {
            let _g = m2.lock().unwrap();
            panic!("intentional panic to poison the mutex");
        })
        .join();
        assert!(m.is_poisoned());

        let before = snapshot();
        let g = tracked_lock(&m, "test/poison");
        assert_eq!(*g, 42, "poisoned mutex must still expose inner value");
        let after = snapshot();
        let d = delta(before, after);
        assert_eq!(d.acquisitions, 1);
        assert_eq!(d.poisoned, 1);
    }

    #[test]
    fn snapshot_mean_wait_ms_is_zero_for_empty_snapshot() {
        let empty = LockStatsSnapshot::default();
        assert_eq!(empty.mean_wait_ms(), 0.0);
    }

    #[test]
    fn snapshot_mean_wait_ms_computes_average() {
        let s = LockStatsSnapshot {
            acquisitions: 4,
            // 8 ms total over 4 acquisitions → 2 ms mean.
            wait_ns_total: 8_000_000,
            slow_waits: 0,
            max_wait_ns: 4_000_000,
            poisoned: 0,
        };
        assert!((s.mean_wait_ms() - 2.0).abs() < 1e-9);
    }

    #[test]
    fn tracked_lock_counts_slow_wait_when_contended() {
        // Hold the lock for slightly longer than the slow threshold, then race
        // a second acquisition against it. The second call must be classed as
        // a slow wait.
        let m = Arc::new(Mutex::new(0_u32));
        let m2 = m.clone();
        let before = snapshot();

        let holder = {
            let m = m.clone();
            thread::spawn(move || {
                let _g = m.lock().unwrap();
                thread::sleep(Duration::from_millis(SLOW_LOCK_WAIT_THRESHOLD_MS + 15));
            })
        };

        // Give the holder a moment to actually grab the lock.
        thread::sleep(Duration::from_millis(5));

        let waiter = thread::spawn(move || {
            let _g = tracked_lock(&m2, "test/slow");
        });

        holder.join().unwrap();
        waiter.join().unwrap();

        let after = snapshot();
        let d = delta(before, after);
        assert!(d.acquisitions >= 1);
        assert!(
            d.slow_waits >= 1,
            "expected at least one slow wait, got {:?}",
            d
        );
    }
}
