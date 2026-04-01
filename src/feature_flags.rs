// Runtime feature flag system with canary/gradual rollout support.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

/// A runtime feature flag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureFlag {
    pub name: String,
    pub description: String,
    pub enabled: bool,
    /// Rollout percentage (0-100). Evaluated by hashing the context key.
    pub rollout_pct: u8,
    /// Optional: only applies to these OS types. Empty = all.
    #[serde(default)]
    pub os_filter: Vec<String>,
    /// Kill switch: if true, flag is forcibly disabled regardless of other settings.
    pub kill_switch: bool,
}

/// Feature flag registry for runtime toggles.
pub struct FeatureFlagRegistry {
    flags: Mutex<HashMap<String, FeatureFlag>>,
}

impl FeatureFlagRegistry {
    pub fn new() -> Self {
        Self { flags: Mutex::new(HashMap::new()) }
    }

    pub fn register(&self, flag: FeatureFlag) {
        self.flags.lock().unwrap().insert(flag.name.clone(), flag);
    }

    pub fn set_enabled(&self, name: &str, enabled: bool) -> bool {
        if let Some(f) = self.flags.lock().unwrap().get_mut(name) {
            f.enabled = enabled;
            true
        } else {
            false
        }
    }

    pub fn set_kill_switch(&self, name: &str, killed: bool) -> bool {
        if let Some(f) = self.flags.lock().unwrap().get_mut(name) {
            f.kill_switch = killed;
            true
        } else {
            false
        }
    }

    pub fn set_rollout_pct(&self, name: &str, pct: u8) -> bool {
        if let Some(f) = self.flags.lock().unwrap().get_mut(name) {
            f.rollout_pct = pct.min(100);
            true
        } else {
            false
        }
    }

    /// Check if a feature is active for a given context key (e.g. agent_uid or hostname).
    pub fn is_enabled(&self, name: &str, context_key: &str) -> bool {
        let flags = self.flags.lock().unwrap();
        let Some(flag) = flags.get(name) else { return false };
        if flag.kill_switch { return false; }
        if !flag.enabled { return false; }

        // OS filter check
        if !flag.os_filter.is_empty() {
            let current_os = std::env::consts::OS;
            if !flag.os_filter.iter().any(|o| o.eq_ignore_ascii_case(current_os)) {
                return false;
            }
        }

        // Rollout percentage: deterministic hash of context_key
        if flag.rollout_pct < 100 {
            let hash = simple_hash(context_key);
            let bucket = (hash % 100) as u8;
            return bucket < flag.rollout_pct;
        }

        true
    }

    /// Check if enabled without rollout gating (admin/testing).
    pub fn is_globally_enabled(&self, name: &str) -> bool {
        let flags = self.flags.lock().unwrap();
        flags.get(name).map_or(false, |f| f.enabled && !f.kill_switch)
    }

    pub fn list_flags(&self) -> Vec<FeatureFlag> {
        self.flags.lock().unwrap().values().cloned().collect()
    }

    pub fn all_flags(&self) -> Vec<FeatureFlag> {
        self.list_flags()
    }

    pub fn get_flag(&self, name: &str) -> Option<FeatureFlag> {
        self.flags.lock().unwrap().get(name).cloned()
    }
}

impl Default for FeatureFlagRegistry {
    fn default() -> Self { Self::new() }
}

fn simple_hash(s: &str) -> u64 {
    let mut h: u64 = 5381;
    for b in s.bytes() {
        h = h.wrapping_mul(33).wrapping_add(b as u64);
    }
    h
}

/// Register built-in feature flags for SentinelEdge.
pub fn register_defaults(registry: &FeatureFlagRegistry) {
    let defaults = vec![
        FeatureFlag { name: "sigma_engine".into(), description: "Sigma rule-based detection engine".into(), enabled: true, rollout_pct: 100, os_filter: vec![], kill_switch: false },
        FeatureFlag { name: "ocsf_normalization".into(), description: "OCSF canonical event normalization".into(), enabled: true, rollout_pct: 100, os_filter: vec![], kill_switch: false },
        FeatureFlag { name: "response_orchestration".into(), description: "Approval-gated response actions".into(), enabled: true, rollout_pct: 100, os_filter: vec![], kill_switch: false },
        FeatureFlag { name: "process_tree".into(), description: "Process tree tracking and lineage".into(), enabled: true, rollout_pct: 100, os_filter: vec![], kill_switch: false },
        FeatureFlag { name: "encrypted_spool".into(), description: "Encrypted local event spool".into(), enabled: true, rollout_pct: 100, os_filter: vec![], kill_switch: false },
        FeatureFlag { name: "sentinel_asim_export".into(), description: "Microsoft Sentinel ASIM export format".into(), enabled: false, rollout_pct: 100, os_filter: vec![], kill_switch: false },
        FeatureFlag { name: "google_udm_export".into(), description: "Google SecOps UDM export format".into(), enabled: false, rollout_pct: 100, os_filter: vec![], kill_switch: false },
        FeatureFlag { name: "digital_twin_advanced".into(), description: "Advanced digital twin simulations".into(), enabled: true, rollout_pct: 50, os_filter: vec![], kill_switch: false },
        FeatureFlag { name: "causal_storyline".into(), description: "Causal storyline generation for incidents".into(), enabled: true, rollout_pct: 100, os_filter: vec![], kill_switch: false },
        FeatureFlag { name: "deception_morphing".into(), description: "Dynamic decoy endpoint morphing".into(), enabled: false, rollout_pct: 25, os_filter: vec![], kill_switch: false },
    ];
    for f in defaults {
        registry.register(f);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_check() {
        let reg = FeatureFlagRegistry::new();
        reg.register(FeatureFlag {
            name: "test_flag".into(), description: "test".into(),
            enabled: true, rollout_pct: 100, os_filter: vec![], kill_switch: false,
        });
        assert!(reg.is_enabled("test_flag", "any-key"));
        assert!(!reg.is_enabled("nonexistent", "any-key"));
    }

    #[test]
    fn kill_switch_overrides() {
        let reg = FeatureFlagRegistry::new();
        reg.register(FeatureFlag {
            name: "killable".into(), description: "".into(),
            enabled: true, rollout_pct: 100, os_filter: vec![], kill_switch: false,
        });
        assert!(reg.is_enabled("killable", "k"));
        reg.set_kill_switch("killable", true);
        assert!(!reg.is_enabled("killable", "k"));
    }

    #[test]
    fn rollout_percentage() {
        let reg = FeatureFlagRegistry::new();
        reg.register(FeatureFlag {
            name: "canary".into(), description: "".into(),
            enabled: true, rollout_pct: 50, os_filter: vec![], kill_switch: false,
        });
        // With 50% rollout, roughly half of random keys should pass
        let mut enabled_count = 0;
        for i in 0..100 {
            if reg.is_enabled("canary", &format!("agent-{}", i)) {
                enabled_count += 1;
            }
        }
        // Should be roughly 50 +/- 20
        assert!(enabled_count > 20 && enabled_count < 80, "Got {} enabled out of 100", enabled_count);
    }

    #[test]
    fn zero_rollout_blocks_all() {
        let reg = FeatureFlagRegistry::new();
        reg.register(FeatureFlag {
            name: "blocked".into(), description: "".into(),
            enabled: true, rollout_pct: 0, os_filter: vec![], kill_switch: false,
        });
        for i in 0..50 {
            assert!(!reg.is_enabled("blocked", &format!("k{}", i)));
        }
    }

    #[test]
    fn disabled_flag() {
        let reg = FeatureFlagRegistry::new();
        reg.register(FeatureFlag {
            name: "off".into(), description: "".into(),
            enabled: false, rollout_pct: 100, os_filter: vec![], kill_switch: false,
        });
        assert!(!reg.is_enabled("off", "any"));
    }

    #[test]
    fn toggle_enabled() {
        let reg = FeatureFlagRegistry::new();
        reg.register(FeatureFlag {
            name: "toggle".into(), description: "".into(),
            enabled: false, rollout_pct: 100, os_filter: vec![], kill_switch: false,
        });
        assert!(!reg.is_globally_enabled("toggle"));
        reg.set_enabled("toggle", true);
        assert!(reg.is_globally_enabled("toggle"));
    }

    #[test]
    fn list_and_get() {
        let reg = FeatureFlagRegistry::new();
        register_defaults(&reg);
        let flags = reg.list_flags();
        assert!(flags.len() >= 10);
        assert!(reg.get_flag("sigma_engine").is_some());
    }

    #[test]
    fn defaults_registered() {
        let reg = FeatureFlagRegistry::new();
        register_defaults(&reg);
        assert!(reg.is_globally_enabled("sigma_engine"));
        assert!(reg.is_globally_enabled("ocsf_normalization"));
        assert!(!reg.is_globally_enabled("sentinel_asim_export")); // off by default
    }
}
