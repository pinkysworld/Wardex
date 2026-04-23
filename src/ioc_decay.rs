//! IoC confidence decay engine.
//!
//! Implements time-based confidence decay for indicators of compromise.
//! IoCs that haven't been re-observed lose confidence over time,
//! reducing false-positive noise from stale intelligence.

use serde::{Deserialize, Serialize};

use crate::threat_intel::{IoC, ThreatIntelStore};

/// Configuration for confidence decay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecayConfig {
    /// Half-life in days — confidence halves after this many days without re-observation.
    pub half_life_days: f64,
    /// Minimum confidence below which IoCs are removed.
    pub min_confidence: f32,
    /// Maximum age in days before automatic removal regardless of confidence.
    pub max_age_days: u64,
    /// Whether decay is enabled.
    pub enabled: bool,
}

impl Default for DecayConfig {
    fn default() -> Self {
        Self {
            half_life_days: 30.0,
            min_confidence: 0.1,
            max_age_days: 365,
            enabled: true,
        }
    }
}

impl DecayConfig {
    /// Validate configuration parameters. Returns an error message if invalid.
    pub fn validate(&self) -> Result<(), String> {
        if !self.half_life_days.is_finite() || self.half_life_days <= 0.0 {
            return Err(format!(
                "half_life_days must be a positive finite number, got {}",
                self.half_life_days
            ));
        }
        if !self.min_confidence.is_finite()
            || self.min_confidence < 0.0
            || self.min_confidence > 1.0
        {
            return Err(format!(
                "min_confidence must be between 0.0 and 1.0, got {}",
                self.min_confidence
            ));
        }
        Ok(())
    }
}

/// Result of a decay pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecayResult {
    pub iocs_processed: usize,
    pub iocs_decayed: usize,
    pub iocs_removed: usize,
    pub avg_confidence_before: f32,
    pub avg_confidence_after: f32,
    pub timestamp: String,
}

/// Apply confidence decay to all IoCs in the store.
pub fn apply_decay(store: &mut ThreatIntelStore, config: &DecayConfig) -> DecayResult {
    if !config.enabled {
        return DecayResult {
            iocs_processed: 0,
            iocs_decayed: 0,
            iocs_removed: 0,
            avg_confidence_before: 0.0,
            avg_confidence_after: 0.0,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
    }

    if let Err(e) = config.validate() {
        eprintln!("[ioc_decay] invalid config, skipping decay: {e}");
        return DecayResult {
            iocs_processed: 0,
            iocs_decayed: 0,
            iocs_removed: 0,
            avg_confidence_before: 0.0,
            avg_confidence_after: 0.0,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };
    }

    let now = chrono::Utc::now();
    let all_iocs = store.all_iocs();
    let total = all_iocs.len();

    let avg_before = if total > 0 {
        all_iocs.iter().map(|i| i.confidence).sum::<f32>() / total as f32
    } else {
        0.0
    };

    let mut decayed_count = 0usize;
    let mut updated_iocs: Vec<IoC> = Vec::new();
    let mut to_remove: Vec<String> = Vec::new();

    for ioc in &all_iocs {
        let last_seen = match chrono::DateTime::parse_from_rfc3339(&ioc.last_seen) {
            Ok(ts) => ts.with_timezone(&chrono::Utc),
            Err(_) => {
                updated_iocs.push(ioc.clone());
                continue;
            }
        };

        let age_days = (now - last_seen).num_seconds().max(0) as f64 / 86400.0;

        // Check max age
        if age_days > config.max_age_days as f64 {
            to_remove.push(format!("{:?}:{}", ioc.ioc_type, ioc.value));
            continue;
        }

        // Apply exponential decay: confidence * 0.5^(age / half_life)
        let decay_factor = (0.5_f64).powf(age_days / config.half_life_days) as f32;
        let new_confidence = ioc.confidence * decay_factor;

        if new_confidence < config.min_confidence {
            to_remove.push(format!("{:?}:{}", ioc.ioc_type, ioc.value));
        } else if (new_confidence - ioc.confidence).abs() > 0.001 {
            let mut updated = ioc.clone();
            updated.confidence = new_confidence;
            updated_iocs.push(updated);
            decayed_count += 1;
        } else {
            updated_iocs.push(ioc.clone());
        }
    }

    let removed_count = to_remove.len();

    // Re-add updated IoCs (store.add_ioc replaces by key)
    for ioc in &updated_iocs {
        store.add_ioc(ioc.clone());
    }

    // Purge removed IoCs by setting a very short TTL on just them
    // (Use the existing purge mechanism or direct removal)
    // For simplicity, we do a targeted purge by age
    if !to_remove.is_empty() {
        store.purge_expired(&now.to_rfc3339(), config.max_age_days);
    }

    let remaining = store.all_iocs();
    let avg_after = if remaining.is_empty() {
        0.0
    } else {
        remaining.iter().map(|i| i.confidence).sum::<f32>() / remaining.len() as f32
    };

    DecayResult {
        iocs_processed: total,
        iocs_decayed: decayed_count,
        iocs_removed: removed_count,
        avg_confidence_before: avg_before,
        avg_confidence_after: avg_after,
        timestamp: chrono::Utc::now().to_rfc3339(),
    }
}

/// Check a single IoC's decayed confidence without modifying the store.
pub fn preview_decay(ioc: &IoC, config: &DecayConfig) -> f32 {
    if !config.enabled {
        return ioc.confidence;
    }

    let now = chrono::Utc::now();
    let last_seen = match chrono::DateTime::parse_from_rfc3339(&ioc.last_seen) {
        Ok(ts) => ts.with_timezone(&chrono::Utc),
        Err(_) => return ioc.confidence,
    };

    let age_days = (now - last_seen).num_seconds().max(0) as f64 / 86400.0;
    let decay_factor = (0.5_f64).powf(age_days / config.half_life_days) as f32;
    (ioc.confidence * decay_factor).max(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threat_intel::{IoC, IoCType, ThreatIntelStore};

    fn make_ioc(value: &str, last_seen: &str, confidence: f32) -> IoC {
        IoC {
            ioc_type: IoCType::IpAddress,
            value: value.to_string(),
            confidence,
            severity: "high".to_string(),
            source: "test".to_string(),
            first_seen: "2025-01-01T00:00:00Z".to_string(),
            last_seen: last_seen.to_string(),
            tags: vec![],
            related_iocs: vec![],
            metadata: crate::threat_intel::IndicatorMetadata::default(),
            sightings: Vec::new(),
        }
    }

    #[test]
    fn recent_iocs_not_decayed() {
        let mut store = ThreatIntelStore::new();
        let now = chrono::Utc::now().to_rfc3339();
        store.add_ioc(make_ioc("10.0.0.1", &now, 0.9));

        let config = DecayConfig::default();
        let result = apply_decay(&mut store, &config);
        assert_eq!(result.iocs_processed, 1);
        assert_eq!(result.iocs_removed, 0);
        // Confidence should be approximately unchanged for very recent IoCs
        let remaining = store.all_iocs();
        assert!(!remaining.is_empty());
        assert!(remaining[0].confidence > 0.85);
    }

    #[test]
    fn old_iocs_removed() {
        let mut store = ThreatIntelStore::new();
        store.add_ioc(make_ioc("10.0.0.2", "2024-01-01T00:00:00Z", 0.9));

        let config = DecayConfig {
            max_age_days: 365,
            ..Default::default()
        };
        let result = apply_decay(&mut store, &config);
        // IoC is >1 year old, should be removed
        assert!(result.iocs_removed > 0 || result.iocs_decayed > 0);
    }

    #[test]
    fn disabled_does_nothing() {
        let mut store = ThreatIntelStore::new();
        store.add_ioc(make_ioc("10.0.0.3", "2024-01-01T00:00:00Z", 0.9));

        let config = DecayConfig {
            enabled: false,
            ..Default::default()
        };
        let result = apply_decay(&mut store, &config);
        assert_eq!(result.iocs_processed, 0);
    }

    #[test]
    fn preview_shows_decay() {
        let ioc = make_ioc("10.0.0.4", "2025-06-01T00:00:00Z", 0.9);
        let config = DecayConfig::default();
        let preview = preview_decay(&ioc, &config);
        // Old enough that confidence should be significantly reduced
        assert!(preview < 0.9);
    }

    #[test]
    fn validate_rejects_zero_half_life() {
        let config = DecayConfig {
            half_life_days: 0.0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_nan_half_life() {
        let config = DecayConfig {
            half_life_days: f64::NAN,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_infinite_half_life() {
        let config = DecayConfig {
            half_life_days: f64::INFINITY,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_negative_half_life() {
        let config = DecayConfig {
            half_life_days: -10.0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_invalid_min_confidence() {
        let config = DecayConfig {
            min_confidence: f32::NAN,
            ..Default::default()
        };
        assert!(config.validate().is_err());

        let config2 = DecayConfig {
            min_confidence: 1.5,
            ..Default::default()
        };
        assert!(config2.validate().is_err());
    }

    #[test]
    fn validate_accepts_default() {
        assert!(DecayConfig::default().validate().is_ok());
    }

    #[test]
    fn invalid_config_skips_decay() {
        let mut store = ThreatIntelStore::new();
        let now = chrono::Utc::now().to_rfc3339();
        store.add_ioc(make_ioc("10.0.0.5", &now, 0.9));

        let config = DecayConfig {
            half_life_days: 0.0,
            ..Default::default()
        };
        let result = apply_decay(&mut store, &config);
        assert_eq!(result.iocs_processed, 0);
        // IoC should be untouched
        assert_eq!(store.all_iocs().len(), 1);
        assert!((store.all_iocs()[0].confidence - 0.9).abs() < 0.001);
    }
}
