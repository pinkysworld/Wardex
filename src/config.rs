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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    pub detector: DetectorSettings,
    pub policy: PolicySettings,
    pub output: OutputSettings,
}

impl Config {
    pub fn write_default_toml(path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("failed to create directory: {e}"))?;
        }
        let config = Self::default();
        let toml_str =
            toml::to_string_pretty(&config).map_err(|e| format!("failed to serialize: {e}"))?;
        fs::write(path, toml_str).map_err(|e| format!("failed to write config: {e}"))
    }

    pub fn load_from_path(path: &Path) -> Result<Self, String> {
        let raw = fs::read_to_string(path).map_err(|e| format!("failed to read config: {e}"))?;

        let config: Self = match path.extension().and_then(|e| e.to_str()) {
            Some("json") => {
                serde_json::from_str(&raw).map_err(|e| format!("invalid JSON config: {e}"))?
            }
            _ => toml::from_str(&raw).map_err(|e| format!("invalid TOML config: {e}"))?,
        };
        config.validate()?;
        Ok(config)
    }

    /// Validate invariants: threshold ordering, non-negative values, ranges.
    pub fn validate(&self) -> Result<(), String> {
        let d = &self.detector;
        if d.warmup_samples == 0 {
            return Err("detector.warmup_samples must be >= 1".into());
        }
        if !(0.0..=1.0).contains(&d.smoothing) {
            return Err(format!(
                "detector.smoothing must be in [0.0, 1.0], got {}",
                d.smoothing
            ));
        }
        if d.learn_threshold < 0.0 {
            return Err(format!(
                "detector.learn_threshold must be >= 0.0, got {}",
                d.learn_threshold
            ));
        }

        let p = &self.policy;
        if p.critical_score <= p.severe_score {
            return Err(format!(
                "policy.critical_score ({}) must be > severe_score ({})",
                p.critical_score, p.severe_score
            ));
        }
        if p.severe_score <= p.elevated_score {
            return Err(format!(
                "policy.severe_score ({}) must be > elevated_score ({})",
                p.severe_score, p.elevated_score
            ));
        }
        if p.elevated_score < 0.0 {
            return Err(format!(
                "policy.elevated_score must be >= 0.0, got {}",
                p.elevated_score
            ));
        }
        if p.critical_integrity_drift < 0.0 || p.critical_integrity_drift > 1.0 {
            return Err(format!(
                "policy.critical_integrity_drift must be in [0.0, 1.0], got {}",
                p.critical_integrity_drift
            ));
        }
        if p.low_battery_threshold < 0.0 || p.low_battery_threshold > 100.0 {
            return Err(format!(
                "policy.low_battery_threshold must be in [0.0, 100.0], got {}",
                p.low_battery_threshold
            ));
        }

        let o = &self.output;
        if o.checkpoint_interval == 0 {
            return Err("output.checkpoint_interval must be >= 1".into());
        }

        Ok(())
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

    #[test]
    fn default_config_validates() {
        Config::default().validate().unwrap();
    }

    #[test]
    fn rejects_inverted_thresholds() {
        let mut config = Config::default();
        config.policy.critical_score = 2.0;
        config.policy.severe_score = 3.0;
        let err = config.validate().unwrap_err();
        assert!(err.contains("critical_score"), "error: {err}");
    }

    #[test]
    fn rejects_zero_warmup() {
        let mut config = Config::default();
        config.detector.warmup_samples = 0;
        let err = config.validate().unwrap_err();
        assert!(err.contains("warmup_samples"), "error: {err}");
    }

    #[test]
    fn rejects_smoothing_out_of_range() {
        let mut config = Config::default();
        config.detector.smoothing = 1.5;
        let err = config.validate().unwrap_err();
        assert!(err.contains("smoothing"), "error: {err}");
    }

    #[test]
    fn rejects_zero_checkpoint_interval() {
        let mut config = Config::default();
        config.output.checkpoint_interval = 0;
        let err = config.validate().unwrap_err();
        assert!(err.contains("checkpoint_interval"), "error: {err}");
    }
}
