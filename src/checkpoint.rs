use std::collections::VecDeque;

use crate::baseline::PersistedBaseline;
use crate::detector::AnomalyDetector;

#[derive(Debug, Clone)]
pub struct CheckpointEntry {
    pub baseline: PersistedBaseline,
    pub timestamp_ms: u64,
}

pub struct CheckpointStore {
    capacity: usize,
    entries: VecDeque<CheckpointEntry>,
}

impl CheckpointStore {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: VecDeque::with_capacity(capacity),
        }
    }

    pub fn capture(&mut self, detector: &AnomalyDetector) {
        if let Some(snapshot) = detector.snapshot() {
            self.push_snapshot(snapshot);
        }
    }

    /// Push a pre-extracted baseline snapshot into the checkpoint store.
    pub fn push_snapshot(&mut self, baseline: PersistedBaseline) {
        if self.capacity == 0 {
            return;
        }
        if self.entries.len() == self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back(CheckpointEntry {
            baseline,
            timestamp_ms: chrono::Utc::now().timestamp_millis() as u64,
        });
    }

    pub fn latest(&self) -> Option<&CheckpointEntry> {
        self.entries.back()
    }

    pub fn entries(&self) -> &VecDeque<CheckpointEntry> {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Restore the detector to the most recent checkpoint.
    /// Returns `true` if a checkpoint was applied, `false` if no checkpoints exist.
    pub fn restore_latest(&self, detector: &mut AnomalyDetector) -> bool {
        if let Some(entry) = self.latest() {
            detector.restore_baseline(&entry.baseline);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CheckpointStore;
    use crate::detector::AnomalyDetector;
    use crate::telemetry::TelemetrySample;

    fn sample() -> TelemetrySample {
        TelemetrySample {
            timestamp_ms: 1,
            cpu_load_pct: 20.0,
            memory_load_pct: 30.0,
            temperature_c: 38.0,
            network_kbps: 500.0,
            auth_failures: 0,
            battery_pct: 90.0,
            integrity_drift: 0.01,
            process_count: 40,
            disk_pressure_pct: 10.0,
        }
    }

    #[test]
    fn capture_stores_snapshot() {
        let mut detector = AnomalyDetector::default();
        detector.evaluate(&sample());

        let mut store = CheckpointStore::new(5);
        store.capture(&detector);

        assert_eq!(store.len(), 1);
        assert!(store.latest().is_some());
    }

    #[test]
    fn capacity_bounds_entries() {
        let mut detector = AnomalyDetector::default();
        detector.evaluate(&sample());

        let mut store = CheckpointStore::new(2);
        store.capture(&detector);
        store.capture(&detector);
        store.capture(&detector);

        assert_eq!(store.len(), 2);
    }

    #[test]
    fn restore_latest_applies_baseline() {
        let mut detector = AnomalyDetector::default();
        detector.evaluate(&sample());

        let mut store = CheckpointStore::new(5);
        store.capture(&detector);

        // Reset and verify restore brings it back
        detector.reset_baseline();
        assert!(store.restore_latest(&mut detector));
        assert!(detector.snapshot().is_some());
    }

    #[test]
    fn restore_latest_returns_false_when_empty() {
        let store = CheckpointStore::new(5);
        let mut detector = AnomalyDetector::default();
        assert!(!store.restore_latest(&mut detector));
    }
}
