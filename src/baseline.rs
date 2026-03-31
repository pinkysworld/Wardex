use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedBaseline {
    pub cpu_load_pct: f32,
    pub memory_load_pct: f32,
    pub temperature_c: f32,
    pub network_kbps: f32,
    pub auth_failures: f32,
    pub battery_pct: f32,
    pub integrity_drift: f32,
    pub process_count: f32,
    pub disk_pressure_pct: f32,
    pub observed_samples: usize,
}

impl PersistedBaseline {
    pub fn save_to_path(&self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("failed to create directory: {e}"))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("failed to serialize baseline: {e}"))?;
        fs::write(path, json).map_err(|e| format!("failed to write baseline: {e}"))
    }

    pub fn load_from_path(path: &Path) -> Result<Self, String> {
        let raw = fs::read_to_string(path).map_err(|e| format!("failed to read baseline: {e}"))?;
        serde_json::from_str(&raw).map_err(|e| format!("failed to parse baseline: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::PersistedBaseline;

    #[test]
    fn round_trip_json() {
        let baseline = PersistedBaseline {
            cpu_load_pct: 25.0,
            memory_load_pct: 40.0,
            temperature_c: 38.0,
            network_kbps: 600.0,
            auth_failures: 1.0,
            battery_pct: 88.0,
            integrity_drift: 0.02,
            process_count: 42.0,
            disk_pressure_pct: 15.0,
            observed_samples: 10,
        };

        let json = serde_json::to_string(&baseline).unwrap();
        let parsed: PersistedBaseline = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.cpu_load_pct, 25.0);
        assert_eq!(parsed.observed_samples, 10);
    }

    #[test]
    fn save_and_load() {
        let dir = std::env::temp_dir().join("wardex_test_baseline");
        let path = dir.join("baseline.json");

        let baseline = PersistedBaseline {
            cpu_load_pct: 15.0,
            memory_load_pct: 30.0,
            temperature_c: 36.0,
            network_kbps: 400.0,
            auth_failures: 0.0,
            battery_pct: 95.0,
            integrity_drift: 0.01,
            process_count: 35.0,
            disk_pressure_pct: 10.0,
            observed_samples: 5,
        };

        baseline.save_to_path(&path).unwrap();
        let loaded = PersistedBaseline::load_from_path(&path).unwrap();

        assert_eq!(loaded.battery_pct, 95.0);
        assert_eq!(loaded.observed_samples, 5);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
