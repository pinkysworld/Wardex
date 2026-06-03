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

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Instant;

/// Acquisitions taking longer than this are counted as "slow waits" and
/// reported separately in the snapshot.
pub(crate) const SLOW_LOCK_WAIT_THRESHOLD_MS: u64 = 25;

/// Hard cap on the number of distinct labels tracked in the per-label
/// registry. Prevents an accidentally-dynamic label (e.g. one built from a
/// user-controlled string) from unbounded growth. Once the cap is hit, new
/// labels still record into the global aggregate counters but are not added
/// to the per-label map.
pub(crate) const MAX_TRACKED_LABELS: usize = 128;

static LOCK_ACQUISITIONS: AtomicU64 = AtomicU64::new(0);
static LOCK_WAIT_NS_TOTAL: AtomicU64 = AtomicU64::new(0);
static LOCK_SLOW_WAITS: AtomicU64 = AtomicU64::new(0);
static LOCK_MAX_WAIT_NS: AtomicU64 = AtomicU64::new(0);
static LOCK_POISONED: AtomicU64 = AtomicU64::new(0);
static LOCK_LABELS_DROPPED: AtomicU64 = AtomicU64::new(0);

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

/// Per-label counters mirrored alongside the global aggregates so operators
/// can attribute contention to a specific callsite.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct LabelStats {
    pub(crate) acquisitions: u64,
    pub(crate) wait_ns_total: u64,
    pub(crate) slow_waits: u64,
    pub(crate) max_wait_ns: u64,
}

impl LabelStats {
    pub(crate) fn mean_wait_ms(&self) -> f64 {
        if self.acquisitions == 0 {
            0.0
        } else {
            (self.wait_ns_total as f64) / (self.acquisitions as f64) / 1_000_000.0
        }
    }
}

fn label_registry() -> &'static Mutex<HashMap<&'static str, LabelStats>> {
    static REG: OnceLock<Mutex<HashMap<&'static str, LabelStats>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Returns a sorted snapshot of every label that has ever acquired a lock
/// through [`tracked_lock`]. Sorted by label so Prometheus output is stable.
pub(crate) fn label_snapshot() -> Vec<(&'static str, LabelStats)> {
    let g = match label_registry().lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };
    let mut out: Vec<(&'static str, LabelStats)> = g.iter().map(|(k, v)| (*k, *v)).collect();
    out.sort_by_key(|(k, _)| *k);
    out
}

/// Number of per-label observations dropped because the label registry was
/// already saturated. Aggregate lock counters are still recorded for these
/// observations; only the dynamic label dimension is omitted.
pub(crate) fn label_drop_snapshot() -> u64 {
    LOCK_LABELS_DROPPED.load(Ordering::Relaxed)
}

fn record_label_sample(label: &'static str, waited_ns: u64, slow: bool) {
    let Ok(mut reg) = label_registry().lock() else {
        return;
    };
    if !reg.contains_key(label) && reg.len() >= MAX_TRACKED_LABELS {
        // Registry is saturated; aggregate counters already recorded the
        // observation so we just skip the per-label update.
        LOCK_LABELS_DROPPED.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let entry = reg.entry(label).or_default();
    entry.acquisitions = entry.acquisitions.saturating_add(1);
    entry.wait_ns_total = entry.wait_ns_total.saturating_add(waited_ns);
    if slow {
        entry.slow_waits = entry.slow_waits.saturating_add(1);
    }
    if waited_ns > entry.max_wait_ns {
        entry.max_wait_ns = waited_ns;
    }
}

#[allow(dead_code)]
#[cfg(test)]
pub(crate) fn reset_for_tests() {
    if let Ok(mut reg) = label_registry().lock() {
        reg.clear();
    }
}

/// Acquires the given mutex, measures the wait latency, and records the
/// observation into the global counters before returning the guard.
///
/// On poisoned mutexes the inner data is recovered via `into_inner()` so the
/// instrumentation matches the existing `unwrap_or_else(|e| e.into_inner())`
/// pattern used throughout `server.rs`.
///
/// The `label` argument is used both for the per-label metric registry and
/// for future log/diagnostic correlation. Labels must be `'static` so the
/// registry can store them without allocation; pass a string literal.
pub(crate) fn tracked_lock<'a, T>(mutex: &'a Mutex<T>, label: &'static str) -> MutexGuard<'a, T> {
    let started = Instant::now();
    let guard = match mutex.lock() {
        Ok(g) => g,
        Err(poisoned) => {
            LOCK_POISONED.fetch_add(1, Ordering::Relaxed);
            poisoned.into_inner()
        }
    };
    let waited = started.elapsed();
    let waited_ns = waited.as_nanos().min(u128::from(u64::MAX)) as u64;
    let slow = waited.as_millis() as u64 >= SLOW_LOCK_WAIT_THRESHOLD_MS;
    LOCK_ACQUISITIONS.fetch_add(1, Ordering::Relaxed);
    LOCK_WAIT_NS_TOTAL.fetch_add(waited_ns, Ordering::Relaxed);
    if slow {
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
    record_label_sample(label, waited_ns, slow);
    guard
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
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
        // Counters are process-global and other parallel tests increment
        // them too; assert that *our* call is reflected (>= 1) rather than
        // exact equality.
        assert!(d.acquisitions >= 1);
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
        assert!(d.acquisitions >= 1);
        assert!(d.poisoned >= 1);
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
            "expected at least one slow wait, got {d:?}"
        );
    }

    #[test]
    fn tracked_lock_records_fanout_contention_by_label() {
        let label = "test/contention_fanout";
        let m = Arc::new(Mutex::new(0_u32));
        let waiters = 6_u32;
        let ready = Arc::new(Barrier::new(waiters as usize + 1));
        let before = snapshot();
        let before_label = label_snapshot()
            .into_iter()
            .find(|(k, _)| *k == label)
            .map(|(_, stats)| stats)
            .unwrap_or_default();
        let guard = m.lock().unwrap();
        let handles = (0..waiters)
            .map(|_| {
                let m = Arc::clone(&m);
                let ready = Arc::clone(&ready);
                thread::spawn(move || {
                    ready.wait();
                    let mut g = tracked_lock(&m, label);
                    *g += 1;
                })
            })
            .collect::<Vec<_>>();

        ready.wait();
        thread::sleep(Duration::from_millis(SLOW_LOCK_WAIT_THRESHOLD_MS + 10));
        drop(guard);

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(*m.lock().unwrap(), waiters);
        let d = delta(before, snapshot());
        assert!(d.acquisitions >= u64::from(waiters));
        assert!(d.slow_waits >= u64::from(waiters));
        let after_label = label_snapshot()
            .into_iter()
            .find(|(k, _)| *k == label)
            .map(|(_, stats)| stats)
            .expect("contention label should be present");
        assert!(after_label.acquisitions >= before_label.acquisitions + u64::from(waiters));
        assert!(after_label.slow_waits >= before_label.slow_waits + u64::from(waiters));
    }

    #[test]
    fn tracked_lock_records_per_label_counters() {
        // Use a unique label so concurrent test cases cannot perturb the
        // per-label counter; the registry is a process-global.
        let label = "test/per_label_records";
        let m = Mutex::new(0_u32);
        let before_acq = label_snapshot()
            .into_iter()
            .find(|(k, _)| *k == label)
            .map_or(0, |(_, v)| v.acquisitions);
        for _ in 0..3 {
            let _g = tracked_lock(&m, label);
        }
        let entry = label_snapshot()
            .into_iter()
            .find(|(k, _)| *k == label)
            .expect("label registry should contain the test label");
        assert_eq!(entry.1.acquisitions, before_acq + 3);
    }

    #[test]
    fn label_snapshot_is_sorted_for_deterministic_emission() {
        let m = Mutex::new(0_u32);
        {
            let _g = tracked_lock(&m, "test/zzz_label_sort");
        }
        {
            let _g = tracked_lock(&m, "test/aaa_label_sort");
        }
        let snap = label_snapshot();
        let keys: Vec<&'static str> = snap.iter().map(|(k, _)| *k).collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(keys, sorted, "label_snapshot must be sorted");
    }
}
