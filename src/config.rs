use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorSettings {
    pub warmup_samples: usize,
    pub smoothing: f32,
    pub learn_threshold: f32,
}

impl Default for DetectorSettings {
    fn default() -> Self {
        Self {
            warmup_samples: 4,
            smoothing: 0.22,
            learn_threshold: 1.35,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySettings {
    pub critical_score: f32,
    pub severe_score: f32,
    pub elevated_score: f32,
    pub critical_integrity_drift: f32,
    pub low_battery_threshold: f32,
}

impl Default for PolicySettings {
    fn default() -> Self {
        Self {
            critical_score: 5.2,
            severe_score: 3.0,
            elevated_score: 1.4,
            critical_integrity_drift: 0.45,
            low_battery_threshold: 20.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputSettings {
    pub audit_path: String,
    pub report_path: String,
    pub checkpoint_interval: usize,
}

impl Default for OutputSettings {
    fn default() -> Self {
        Self {
            audit_path: "var/last-run.audit.log".into(),
            report_path: "var/last-run.report.json".into(),
            checkpoint_interval: 5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub detector: DetectorSettings,
    pub policy: PolicySettings,
    pub output: OutputSettings,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            detector: DetectorSettings::default(),
            policy: PolicySettings::default(),
            output: OutputSettings::default(),
        }
    }
}

impl Config {
    pub fn write_default_toml(path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create directory: {e}"))?;
        }
        let config = Self::default();
        let toml_str =
            toml::to_string_pretty(&config).map_err(|e| format!("failed to serialize: {e}"))?;
        fs::write(path, toml_str).map_err(|e| format!("failed to write config: {e}"))
    }

    pub fn load_from_path(path: &Path) -> Result<Self, String> {
        let raw = fs::read_to_string(path).map_err(|e| format!("failed to read config: {e}"))?;

        match path.extension().and_then(|e| e.to_str()) {
            Some("json") => {
                serde_json::from_str(&raw).map_err(|e| format!("invalid JSON config: {e}"))
            }
            _ => toml::from_str(&raw).map_err(|e| format!("invalid TOML config: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn default_round_trip_toml() {
        let config = Config::default();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.detector.warmup_samples, 4);
        assert!((parsed.detector.smoothing - 0.22).abs() < 0.001);
    }

    #[test]
    fn default_round_trip_json() {
        let config = Config::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: Config = serde_json::from_str(&json).unwrap();
        assert!((parsed.policy.critical_score - 5.2).abs() < 0.001);
    }

    #[test]
    fn write_and_load() {
        let dir = std::env::temp_dir().join("sentineledge_test_config");
        let path = dir.join("config.toml");

        Config::write_default_toml(&path).unwrap();
        let loaded = Config::load_from_path(&path).unwrap();
        assert_eq!(loaded.output.checkpoint_interval, 5);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
