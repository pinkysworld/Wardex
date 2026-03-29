use std::collections::VecDeque;

use crate::actions::{ActionResult, DeviceController, DeviceStateSnapshot};
use crate::baseline::PersistedBaseline;
use crate::detector::AnomalyDetector;

#[derive(Debug, Clone)]
pub struct CheckpointEntry {
    pub baseline: PersistedBaseline,
    pub device_state: DeviceStateSnapshot,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone)]
pub struct RestoreOutcome {
    pub baseline_restored: bool,
    pub device_state: DeviceStateSnapshot,
    pub action_results: Vec<ActionResult>,
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
            self.push_snapshot(snapshot, DeviceStateSnapshot::default());
        }
    }

    /// Push a pre-extracted baseline snapshot into the checkpoint store.
    pub fn push_snapshot(&mut self, baseline: PersistedBaseline, device_state: DeviceStateSnapshot) {
        if self.capacity == 0 {
            return;
        }
        if self.entries.len() == self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back(CheckpointEntry {
            baseline,
            device_state,
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

    pub fn restore_latest_with_device(
        &self,
        detector: &mut AnomalyDetector,
        device: &mut DeviceController,
    ) -> Option<RestoreOutcome> {
        let entry = self.latest()?;
        detector.restore_baseline(&entry.baseline);
        let action_results = device.restore_snapshot(&entry.device_state);
        Some(RestoreOutcome {
            baseline_restored: true,
            device_state: entry.device_state.clone(),
            action_results,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::CheckpointStore;
    use crate::actions::{DeviceController, DeviceStateSnapshot};
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
    fn capture_defaults_device_state() {
        let mut detector = AnomalyDetector::default();
        detector.evaluate(&sample());

        let mut store = CheckpointStore::new(5);
        store.capture(&detector);

        let entry = store.latest().unwrap();
        assert_eq!(entry.device_state, DeviceStateSnapshot::default());
    }

    #[test]
    fn restore_latest_with_device_restores_snapshot() {
        let mut detector = AnomalyDetector::default();
        detector.evaluate(&sample());

        let mut store = CheckpointStore::new(5);
        store.push_snapshot(
            detector.snapshot().unwrap(),
            DeviceStateSnapshot {
                isolation_pct: 85,
                service_quarantined: true,
                network_isolated: false,
                last_action: "quarantine".into(),
            },
        );

        detector.reset_baseline();
        let mut device = DeviceController::default();
        let restored = store.restore_latest_with_device(&mut detector, &mut device).unwrap();

        assert!(restored.baseline_restored);
        assert_eq!(restored.device_state.isolation_pct, 85);
        assert_eq!(device.snapshot(), restored.device_state);
        assert!(!restored.action_results.is_empty());
    }

    #[test]
    fn restore_latest_returns_false_when_empty() {
        let store = CheckpointStore::new(5);
        let mut detector = AnomalyDetector::default();
        assert!(!store.restore_latest(&mut detector));
    }
}
