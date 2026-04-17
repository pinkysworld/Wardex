//! Agent lifecycle management.
//!
//! Tracks hardware/agent lifecycle states (active, stale, archived,
//! decommissioned) with automatic aging based on heartbeat intervals.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Lifecycle state for an enrolled agent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AgentLifecycle {
    Active,
    Stale,
    Offline,
    Archived,
    Decommissioned,
}

/// Lifecycle configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleConfig {
    /// Seconds without heartbeat before marking as Stale.
    pub stale_after_secs: u64,
    /// Seconds without heartbeat before marking as Offline.
    pub offline_after_secs: u64,
    /// Days without heartbeat before auto-archiving.
    pub archive_after_days: u64,
    /// Whether auto-archiving is enabled.
    pub auto_archive: bool,
}

impl Default for LifecycleConfig {
    fn default() -> Self {
        Self {
            stale_after_secs: 300,    // 5 minutes
            offline_after_secs: 3600, // 1 hour
            archive_after_days: 30,
            auto_archive: true,
        }
    }
}

/// Agent lifecycle entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentLifecycleEntry {
    pub agent_id: String,
    pub hostname: String,
    pub state: AgentLifecycle,
    pub last_heartbeat: String,
    pub state_changed_at: String,
    pub notes: Option<String>,
}

/// Result of a lifecycle sweep.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleSweepResult {
    pub total_agents: usize,
    pub active: usize,
    pub stale: usize,
    pub offline: usize,
    pub archived: usize,
    pub decommissioned: usize,
    pub transitions: Vec<LifecycleTransition>,
    pub timestamp: String,
}

/// A state transition that occurred during a sweep.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleTransition {
    pub agent_id: String,
    pub from: AgentLifecycle,
    pub to: AgentLifecycle,
    pub reason: String,
}

/// Agent lifecycle manager.
#[derive(Debug)]
pub struct LifecycleManager {
    entries: HashMap<String, AgentLifecycleEntry>,
    config: LifecycleConfig,
    transitions: Vec<LifecycleTransition>,
}

impl Default for LifecycleManager {
    fn default() -> Self {
        Self::new(LifecycleConfig::default())
    }
}

impl LifecycleManager {
    pub fn new(config: LifecycleConfig) -> Self {
        Self {
            entries: HashMap::new(),
            config,
            transitions: Vec::new(),
        }
    }

    /// Register or update an agent's heartbeat.
    pub fn heartbeat(&mut self, agent_id: &str, hostname: &str) {
        let now = chrono::Utc::now().to_rfc3339();
        let entry =
            self.entries
                .entry(agent_id.to_string())
                .or_insert_with(|| AgentLifecycleEntry {
                    agent_id: agent_id.to_string(),
                    hostname: hostname.to_string(),
                    state: AgentLifecycle::Active,
                    last_heartbeat: now.clone(),
                    state_changed_at: now.clone(),
                    notes: None,
                });

        entry.last_heartbeat = now.clone();
        entry.hostname = hostname.to_string();

        // Reactivate if was stale/offline
        if matches!(entry.state, AgentLifecycle::Stale | AgentLifecycle::Offline) {
            let old_state = entry.state.clone();
            entry.state = AgentLifecycle::Active;
            entry.state_changed_at = now;
            self.transitions.push(LifecycleTransition {
                agent_id: agent_id.to_string(),
                from: old_state,
                to: AgentLifecycle::Active,
                reason: "heartbeat received".into(),
            });
        }
    }

    /// Manually set an agent's lifecycle state.
    pub fn set_state(&mut self, agent_id: &str, state: AgentLifecycle, reason: &str) -> bool {
        if let Some(entry) = self.entries.get_mut(agent_id) {
            let old_state = entry.state.clone();
            entry.state = state.clone();
            entry.state_changed_at = chrono::Utc::now().to_rfc3339();
            entry.notes = Some(reason.to_string());
            self.transitions.push(LifecycleTransition {
                agent_id: agent_id.to_string(),
                from: old_state,
                to: state,
                reason: reason.to_string(),
            });
            true
        } else {
            false
        }
    }

    /// Run a lifecycle sweep — check all agents and transition stale/offline/archived.
    pub fn sweep(&mut self) -> LifecycleSweepResult {
        let now = chrono::Utc::now();
        let mut transitions = Vec::new();

        for entry in self.entries.values_mut() {
            if matches!(
                entry.state,
                AgentLifecycle::Archived | AgentLifecycle::Decommissioned
            ) {
                continue;
            }

            let last = match chrono::DateTime::parse_from_rfc3339(&entry.last_heartbeat) {
                Ok(ts) => ts.with_timezone(&chrono::Utc),
                Err(_) => continue,
            };

            let elapsed_secs = (now - last).num_seconds().unsigned_abs();
            let elapsed_days = elapsed_secs / 86400;

            let new_state =
                if self.config.auto_archive && elapsed_days >= self.config.archive_after_days {
                    AgentLifecycle::Archived
                } else if elapsed_secs >= self.config.offline_after_secs {
                    AgentLifecycle::Offline
                } else if elapsed_secs >= self.config.stale_after_secs {
                    AgentLifecycle::Stale
                } else {
                    AgentLifecycle::Active
                };

            if new_state != entry.state {
                transitions.push(LifecycleTransition {
                    agent_id: entry.agent_id.clone(),
                    from: entry.state.clone(),
                    to: new_state.clone(),
                    reason: format!("auto-sweep: {elapsed_secs}s since last heartbeat"),
                });
                entry.state = new_state;
                entry.state_changed_at = now.to_rfc3339();
            }
        }

        self.transitions.extend(transitions.clone());

        let mut active = 0;
        let mut stale = 0;
        let mut offline = 0;
        let mut archived = 0;
        let mut decommissioned = 0;

        for entry in self.entries.values() {
            match entry.state {
                AgentLifecycle::Active => active += 1,
                AgentLifecycle::Stale => stale += 1,
                AgentLifecycle::Offline => offline += 1,
                AgentLifecycle::Archived => archived += 1,
                AgentLifecycle::Decommissioned => decommissioned += 1,
            }
        }

        LifecycleSweepResult {
            total_agents: self.entries.len(),
            active,
            stale,
            offline,
            archived,
            decommissioned,
            transitions,
            timestamp: now.to_rfc3339(),
        }
    }

    /// Get all lifecycle entries.
    pub fn all_entries(&self) -> Vec<&AgentLifecycleEntry> {
        self.entries.values().collect()
    }

    /// Get entry for a specific agent.
    pub fn get_entry(&self, agent_id: &str) -> Option<&AgentLifecycleEntry> {
        self.entries.get(agent_id)
    }

    /// Get recent transitions.
    pub fn recent_transitions(&self, limit: usize) -> &[LifecycleTransition] {
        let start = if self.transitions.len() > limit {
            self.transitions.len() - limit
        } else {
            0
        };
        &self.transitions[start..]
    }

    /// Get config.
    pub fn config(&self) -> &LifecycleConfig {
        &self.config
    }

    /// Update config.
    pub fn set_config(&mut self, config: LifecycleConfig) {
        self.config = config;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heartbeat_creates_active_entry() {
        let mut mgr = LifecycleManager::default();
        mgr.heartbeat("agent-1", "host1");
        let entry = mgr.get_entry("agent-1").unwrap();
        assert_eq!(entry.state, AgentLifecycle::Active);
    }

    #[test]
    fn manual_decommission() {
        let mut mgr = LifecycleManager::default();
        mgr.heartbeat("agent-2", "host2");
        assert!(mgr.set_state(
            "agent-2",
            AgentLifecycle::Decommissioned,
            "Hardware retired"
        ));
        assert_eq!(
            mgr.get_entry("agent-2").unwrap().state,
            AgentLifecycle::Decommissioned
        );
    }

    #[test]
    fn sweep_detects_stale() {
        let mut mgr = LifecycleManager::new(LifecycleConfig {
            stale_after_secs: 0, // Immediately stale
            offline_after_secs: 1,
            archive_after_days: 30,
            auto_archive: true,
        });
        mgr.heartbeat("agent-3", "host3");

        // Small sleep to ensure elapsed > 0
        std::thread::sleep(std::time::Duration::from_millis(10));

        let result = mgr.sweep();
        // Should transition to at least Stale or Offline
        assert!(result.stale > 0 || result.offline > 0);
    }

    #[test]
    fn heartbeat_reactivates() {
        let mut mgr = LifecycleManager::default();
        mgr.heartbeat("agent-4", "host4");
        mgr.set_state("agent-4", AgentLifecycle::Stale, "test");
        assert_eq!(
            mgr.get_entry("agent-4").unwrap().state,
            AgentLifecycle::Stale
        );

        mgr.heartbeat("agent-4", "host4");
        assert_eq!(
            mgr.get_entry("agent-4").unwrap().state,
            AgentLifecycle::Active
        );
    }
}
