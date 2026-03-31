use crate::siem::SiemConfig;

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
pub struct MonitorSettings {
    pub interval_secs: u64,
    pub alert_threshold: f32,
    pub alert_log: String,
    pub dry_run: bool,
    pub duration_secs: u64,
    pub webhook_url: Option<String>,
    pub syslog: bool,
    pub cef: bool,
    pub watch_paths: Vec<String>,
}

impl Default for MonitorSettings {
    fn default() -> Self {
        Self {
            interval_secs: 5,
            alert_threshold: 3.5,
            alert_log: "var/alerts.jsonl".into(),
            dry_run: false,
            duration_secs: 0,
            webhook_url: None,
            syslog: false,
            cef: false,
            watch_paths: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    pub detector: DetectorSettings,
    pub policy: PolicySettings,
    pub output: OutputSettings,
    #[serde(default)]
    pub monitor: MonitorSettings,
    #[serde(default)]
    pub siem: SiemConfig,
    #[serde(default)]
    pub agent: AgentSettings,
}

/// Agent-mode settings (for `wardex agent`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSettings {
    /// Server URL to connect to.
    pub server_url: String,
    /// Enrollment token for initial registration.
    pub enrollment_token: String,
    /// Enable auto-update checking.
    #[serde(default = "default_auto_update")]
    pub auto_update: bool,
    /// Update check interval in seconds.
    #[serde(default = "default_update_interval")]
    pub update_check_interval_secs: u64,
}

fn default_auto_update() -> bool {
    true
}
fn default_update_interval() -> u64 {
    300
}

impl Default for AgentSettings {
    fn default() -> Self {
        Self {
            server_url: "http://localhost:8080".into(),
            enrollment_token: String::new(),
            auto_update: true,
            update_check_interval_secs: 300,
        }
    }
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

// ── Hot-Reload Support ───────────────────────────────────────────────

/// Result of a hot-reload operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotReloadResult {
    pub success: bool,
    pub applied_fields: Vec<String>,
    pub previous_values: std::collections::HashMap<String, String>,
    pub error: Option<String>,
}

/// A partial config update for hot-reloading.
/// Only fields that are `Some` will be applied.
/// Accepts both flat fields (legacy) and nested objects.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConfigPatch {
    // Flat fields (legacy / backward compat)
    #[serde(default)]
    pub warmup_samples: Option<usize>,
    #[serde(default)]
    pub smoothing: Option<f32>,
    #[serde(default)]
    pub learn_threshold: Option<f32>,
    #[serde(default)]
    pub critical_score: Option<f32>,
    #[serde(default)]
    pub severe_score: Option<f32>,
    #[serde(default)]
    pub elevated_score: Option<f32>,
    #[serde(default)]
    pub critical_integrity_drift: Option<f32>,
    #[serde(default)]
    pub low_battery_threshold: Option<f32>,

    // Nested objects (from admin console settings panel)
    #[serde(default)]
    pub detector: Option<DetectorSettings>,
    #[serde(default)]
    pub policy: Option<PolicySettings>,
    #[serde(default)]
    pub monitor: Option<MonitorSettings>,
}

impl ConfigPatch {
    /// Apply this patch to a Config, validate the result, and return
    /// the list of changed fields with their previous values.
    pub fn apply(&self, config: &mut Config) -> HotReloadResult {
        let mut applied = Vec::new();
        let mut previous = std::collections::HashMap::new();

        // Snapshot the original config for rollback on validation failure
        let original = config.clone();

        if let Some(v) = self.warmup_samples {
            previous.insert("warmup_samples".into(), config.detector.warmup_samples.to_string());
            config.detector.warmup_samples = v;
            applied.push("warmup_samples".into());
        }
        if let Some(v) = self.smoothing {
            previous.insert("smoothing".into(), config.detector.smoothing.to_string());
            config.detector.smoothing = v;
            applied.push("smoothing".into());
        }
        if let Some(v) = self.learn_threshold {
            previous.insert("learn_threshold".into(), config.detector.learn_threshold.to_string());
            config.detector.learn_threshold = v;
            applied.push("learn_threshold".into());
        }
        if let Some(v) = self.critical_score {
            previous.insert("critical_score".into(), config.policy.critical_score.to_string());
            config.policy.critical_score = v;
            applied.push("critical_score".into());
        }
        if let Some(v) = self.severe_score {
            previous.insert("severe_score".into(), config.policy.severe_score.to_string());
            config.policy.severe_score = v;
            applied.push("severe_score".into());
        }
        if let Some(v) = self.elevated_score {
            previous.insert("elevated_score".into(), config.policy.elevated_score.to_string());
            config.policy.elevated_score = v;
            applied.push("elevated_score".into());
        }
        if let Some(v) = self.critical_integrity_drift {
            previous.insert("critical_integrity_drift".into(), config.policy.critical_integrity_drift.to_string());
            config.policy.critical_integrity_drift = v;
            applied.push("critical_integrity_drift".into());
        }
        if let Some(v) = self.low_battery_threshold {
            previous.insert("low_battery_threshold".into(), config.policy.low_battery_threshold.to_string());
            config.policy.low_battery_threshold = v;
            applied.push("low_battery_threshold".into());
        }

        // Nested objects (from admin console settings panel)
        if let Some(ref d) = self.detector {
            previous.insert("detector".into(), format!("{:?}", config.detector));
            config.detector = d.clone();
            applied.push("detector".into());
        }
        if let Some(ref p) = self.policy {
            previous.insert("policy".into(), format!("{:?}", config.policy));
            config.policy = p.clone();
            applied.push("policy".into());
        }
        if let Some(ref m) = self.monitor {
            previous.insert("monitor".into(), format!("{:?}", config.monitor));
            config.monitor = m.clone();
            applied.push("monitor".into());
        }

        // Validate the patched config
        if let Err(e) = config.validate() {
            // Rollback
            *config = original;
            return HotReloadResult {
                success: false,
                applied_fields: Vec::new(),
                previous_values: std::collections::HashMap::new(),
                error: Some(e),
            };
        }

        HotReloadResult {
            success: true,
            applied_fields: applied,
            previous_values: previous,
            error: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, ConfigPatch};

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
        let dir = std::env::temp_dir().join("wardex_test_config");
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

    #[test]
    fn hot_reload_applies_partial_patch() {
        let mut config = Config::default();
        let patch = ConfigPatch {
            smoothing: Some(0.35),
            critical_score: Some(6.0),
            ..Default::default()
        };
        let result = patch.apply(&mut config);
        assert!(result.success);
        assert_eq!(result.applied_fields.len(), 2);
        assert!((config.detector.smoothing - 0.35).abs() < 0.001);
        assert!((config.policy.critical_score - 6.0).abs() < 0.001);
        // Previous values recorded
        assert!(result.previous_values.contains_key("smoothing"));
    }

    #[test]
    fn hot_reload_rolls_back_on_invalid() {
        let mut config = Config::default();
        let original_critical = config.policy.critical_score;
        // Set critical_score below severe_score (invalid)
        let patch = ConfigPatch {
            critical_score: Some(1.0),
            ..Default::default()
        };
        let result = patch.apply(&mut config);
        assert!(!result.success);
        assert!(result.error.is_some());
        // Config should be rolled back
        assert!((config.policy.critical_score - original_critical).abs() < 0.001);
    }

    #[test]
    fn hot_reload_empty_patch_is_noop() {
        let mut config = Config::default();
        let patch = ConfigPatch::default();
        let result = patch.apply(&mut config);
        assert!(result.success);
        assert!(result.applied_fields.is_empty());
    }
}
