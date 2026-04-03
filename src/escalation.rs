//! Escalation and notification engine.
//!
//! SLA-driven auto-escalation chains, multi-channel notifications,
//! on-call rotation, and acknowledgement tracking.

use serde::{Deserialize, Serialize};

// ── Escalation policy ───────────────────────────────────────────

/// An escalation policy defining the chain of contacts and SLA deadlines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationPolicy {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub levels: Vec<EscalationLevel>,
    /// Minimum alert severity to activate this policy.
    pub min_severity: f32,
    /// alert reason patterns (case-insensitive substring match).
    pub reason_patterns: Vec<String>,
}

/// A single level in the escalation chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationLevel {
    /// Level number (1 = first responder, 2 = manager, etc.).
    pub level: u32,
    /// Contacts at this level.
    pub contacts: Vec<Contact>,
    /// Seconds to wait for acknowledgement before escalating to next level.
    pub sla_secs: u64,
    /// Notification channels to use at this level.
    pub channels: Vec<EscalationChannel>,
}

/// A contact (person or group) for notifications.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub name: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub slack_id: Option<String>,
    pub role: String,
    pub on_call: bool,
}

/// Supported notification channels.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EscalationChannel {
    Email,
    Slack,
    PagerDuty,
    MsTeams,
    Webhook { url: String },
    Sms,
    Syslog,
}

// ── Escalation state ────────────────────────────────────────────

/// Active escalation for an alert/incident.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationState {
    pub escalation_id: String,
    pub policy_id: String,
    pub alert_id: String,
    pub current_level: u32,
    pub status: EscalationStatus,
    pub started_at: u64,
    pub last_escalated_at: u64,
    pub acknowledged_by: Option<String>,
    pub acknowledged_at: Option<u64>,
    pub notifications: Vec<NotificationRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EscalationStatus {
    Active,
    Acknowledged,
    Resolved,
    Expired,
}

/// Record of a sent notification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationRecord {
    pub channel: EscalationChannel,
    pub recipient: String,
    pub level: u32,
    pub sent_at: u64,
    pub delivered: bool,
    pub message_summary: String,
}

// ── On-call rotation ────────────────────────────────────────────

/// A simple weekly on-call rotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnCallSchedule {
    pub id: String,
    pub name: String,
    pub members: Vec<Contact>,
    /// Rotation period in hours (e.g. 168 for weekly).
    pub rotation_hours: u64,
    /// Epoch ms when the rotation started (first member on-call).
    pub start_epoch_ms: u64,
}

impl OnCallSchedule {
    /// Determine who is on-call at a given timestamp.
    pub fn on_call_at(&self, now_ms: u64) -> Option<&Contact> {
        if self.members.is_empty() || self.rotation_hours == 0 {
            return None;
        }
        let elapsed_ms = now_ms.saturating_sub(self.start_epoch_ms);
        let rotation_ms = self.rotation_hours * 3_600_000;
        let idx = ((elapsed_ms / rotation_ms) as usize) % self.members.len();
        Some(&self.members[idx])
    }
}

// ── Engine ──────────────────────────────────────────────────────

/// Escalation engine managing policies, active escalations, and schedules.
pub struct EscalationEngine {
    policies: Vec<EscalationPolicy>,
    active: Vec<EscalationState>,
    schedules: Vec<OnCallSchedule>,
    next_esc_id: u64,
}

impl Default for EscalationEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl EscalationEngine {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
            active: Vec::new(),
            schedules: Vec::new(),
            next_esc_id: 1,
        }
    }

    /// Register an escalation policy.
    pub fn add_policy(&mut self, policy: EscalationPolicy) {
        self.policies.retain(|p| p.id != policy.id);
        self.policies.push(policy);
    }

    /// Remove a policy.
    pub fn remove_policy(&mut self, id: &str) -> bool {
        let before = self.policies.len();
        self.policies.retain(|p| p.id != id);
        self.policies.len() < before
    }

    /// List policies.
    pub fn list_policies(&self) -> &[EscalationPolicy] {
        &self.policies
    }

    /// Register an on-call schedule.
    pub fn add_schedule(&mut self, schedule: OnCallSchedule) {
        self.schedules.retain(|s| s.id != schedule.id);
        self.schedules.push(schedule);
    }

    /// Get current on-call for a schedule.
    pub fn current_on_call(&self, schedule_id: &str, now_ms: u64) -> Option<&Contact> {
        self.schedules
            .iter()
            .find(|s| s.id == schedule_id)
            .and_then(|s| s.on_call_at(now_ms))
    }

    /// Find matching policies for an alert.
    pub fn matching_policies(&self, severity: f32, reason: &str) -> Vec<&EscalationPolicy> {
        self.policies
            .iter()
            .filter(|p| {
                if !p.enabled || severity < p.min_severity {
                    return false;
                }
                p.reason_patterns.is_empty()
                    || p.reason_patterns
                        .iter()
                        .any(|pat| reason.to_lowercase().contains(&pat.to_lowercase()))
            })
            .collect()
    }

    /// Start an escalation for an alert.
    pub fn start_escalation(
        &mut self,
        policy_id: &str,
        alert_id: &str,
        now_ms: u64,
    ) -> Option<String> {
        let policy = self.policies.iter().find(|p| p.id == policy_id)?;
        if !policy.enabled || policy.levels.is_empty() {
            return None;
        }

        let esc_id = format!("esc-{}", self.next_esc_id);
        self.next_esc_id += 1;

        // Generate initial notifications for level 1
        let level = &policy.levels[0];
        let notifications: Vec<NotificationRecord> = level
            .contacts
            .iter()
            .flat_map(|c| {
                level.channels.iter().map(move |ch| NotificationRecord {
                    channel: ch.clone(),
                    recipient: c.name.clone(),
                    level: level.level,
                    sent_at: now_ms,
                    delivered: true, // Assume success (real impl would track delivery)
                    message_summary: format!("Alert {alert_id} requires attention"),
                })
            })
            .collect();

        self.active.push(EscalationState {
            escalation_id: esc_id.clone(),
            policy_id: policy_id.into(),
            alert_id: alert_id.into(),
            current_level: 1,
            status: EscalationStatus::Active,
            started_at: now_ms,
            last_escalated_at: now_ms,
            acknowledged_by: None,
            acknowledged_at: None,
            notifications,
        });

        Some(esc_id)
    }

    /// Acknowledge an escalation (stops further escalation).
    pub fn acknowledge(
        &mut self,
        escalation_id: &str,
        by: &str,
        now_ms: u64,
    ) -> bool {
        if let Some(esc) = self.active.iter_mut().find(|e| e.escalation_id == escalation_id) {
            if esc.status != EscalationStatus::Active {
                return false;
            }
            esc.status = EscalationStatus::Acknowledged;
            esc.acknowledged_by = Some(by.into());
            esc.acknowledged_at = Some(now_ms);
            true
        } else {
            false
        }
    }

    /// Resolve an escalation.
    pub fn resolve(&mut self, escalation_id: &str) -> bool {
        if let Some(esc) = self.active.iter_mut().find(|e| e.escalation_id == escalation_id) {
            esc.status = EscalationStatus::Resolved;
            true
        } else {
            false
        }
    }

    /// Check SLA deadlines and auto-escalate where needed.
    /// Returns list of escalation IDs that were escalated.
    pub fn check_sla(&mut self, now_ms: u64) -> Vec<String> {
        let mut escalated = Vec::new();

        // Collect policy data needed for escalation
        let policy_levels: Vec<(String, Vec<EscalationLevel>)> = self
            .policies
            .iter()
            .map(|p| (p.id.clone(), p.levels.clone()))
            .collect();

        for esc in &mut self.active {
            if esc.status != EscalationStatus::Active {
                continue;
            }

            // Find this escalation's policy levels
            let levels = match policy_levels.iter().find(|(id, _)| *id == esc.policy_id) {
                Some((_, levels)) => levels,
                None => continue,
            };

            if levels.is_empty() {
                continue;
            }

            let current_idx = match levels
                .iter()
                .position(|l| l.level == esc.current_level)
            {
                Some(idx) => idx,
                None => {
                    esc.status = EscalationStatus::Expired;
                    continue;
                }
            };

            let current = &levels[current_idx];
            let elapsed_secs = (now_ms.saturating_sub(esc.last_escalated_at)) / 1000;

            if elapsed_secs >= current.sla_secs {
                // Try to escalate to next level
                if current_idx + 1 < levels.len() {
                    let next = &levels[current_idx + 1];
                    esc.current_level = next.level;
                    esc.last_escalated_at = now_ms;

                    // Generate notifications for the new level
                    for contact in &next.contacts {
                        for ch in &next.channels {
                            esc.notifications.push(NotificationRecord {
                                channel: ch.clone(),
                                recipient: contact.name.clone(),
                                level: next.level,
                                sent_at: now_ms,
                                delivered: true,
                                message_summary: format!(
                                    "ESCALATED (L{}): Alert {} unacknowledged",
                                    next.level, esc.alert_id
                                ),
                            });
                        }
                    }
                    escalated.push(esc.escalation_id.clone());
                } else {
                    // No more levels — mark as expired
                    esc.status = EscalationStatus::Expired;
                }
            }
        }

        escalated
    }

    /// Get an escalation by id.
    pub fn get_escalation(&self, id: &str) -> Option<&EscalationState> {
        self.active.iter().find(|e| e.escalation_id == id)
    }

    /// List active (unresolved) escalations.
    pub fn active_escalations(&self) -> Vec<&EscalationState> {
        self.active
            .iter()
            .filter(|e| e.status == EscalationStatus::Active)
            .collect()
    }

    /// All escalation records.
    pub fn all_escalations(&self) -> &[EscalationState] {
        &self.active
    }

    /// Total notification count.
    pub fn total_notifications(&self) -> usize {
        self.active.iter().map(|e| e.notifications.len()).sum()
    }
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_policy() -> EscalationPolicy {
        EscalationPolicy {
            id: "pol-1".into(),
            name: "Critical Alert".into(),
            enabled: true,
            levels: vec![
                EscalationLevel {
                    level: 1,
                    contacts: vec![Contact {
                        name: "Analyst Alice".into(),
                        email: Some("alice@example.com".into()),
                        phone: None,
                        slack_id: Some("U123".into()),
                        role: "SOC Analyst".into(),
                        on_call: true,
                    }],
                    sla_secs: 300,
                    channels: vec![EscalationChannel::Slack],
                },
                EscalationLevel {
                    level: 2,
                    contacts: vec![Contact {
                        name: "Manager Bob".into(),
                        email: Some("bob@example.com".into()),
                        phone: Some("+1234567890".into()),
                        slack_id: None,
                        role: "SOC Manager".into(),
                        on_call: false,
                    }],
                    sla_secs: 600,
                    channels: vec![EscalationChannel::Email, EscalationChannel::PagerDuty],
                },
            ],
            min_severity: 70.0,
            reason_patterns: vec!["lateral".into(), "ransomware".into()],
        }
    }

    #[test]
    fn matching_policies_filter() {
        let mut engine = EscalationEngine::new();
        engine.add_policy(sample_policy());

        let m = engine.matching_policies(80.0, "lateral movement detected");
        assert_eq!(m.len(), 1);

        let m = engine.matching_policies(50.0, "lateral movement");
        assert!(m.is_empty()); // below severity

        let m = engine.matching_policies(80.0, "normal event");
        assert!(m.is_empty()); // no reason match
    }

    #[test]
    fn start_and_acknowledge() {
        let mut engine = EscalationEngine::new();
        engine.add_policy(sample_policy());

        let eid = engine
            .start_escalation("pol-1", "alert-999", 1000)
            .unwrap();
        assert_eq!(engine.active_escalations().len(), 1);

        assert!(engine.acknowledge(&eid, "alice", 5000));
        let esc = engine.get_escalation(&eid).unwrap();
        assert_eq!(esc.status, EscalationStatus::Acknowledged);
        assert_eq!(esc.acknowledged_by.as_deref(), Some("alice"));
    }

    #[test]
    fn sla_auto_escalation() {
        let mut engine = EscalationEngine::new();
        engine.add_policy(sample_policy());

        let eid = engine
            .start_escalation("pol-1", "alert-1", 0)
            .unwrap();

        // After 301 seconds → should escalate to level 2
        let escalated = engine.check_sla(301_000);
        assert_eq!(escalated, vec![eid.clone()]);
        assert_eq!(engine.get_escalation(&eid).unwrap().current_level, 2);
    }

    #[test]
    fn sla_expires_after_all_levels() {
        let mut engine = EscalationEngine::new();
        engine.add_policy(sample_policy());

        let eid = engine
            .start_escalation("pol-1", "alert-1", 0)
            .unwrap();

        // Escalate level 1 → 2
        engine.check_sla(301_000);
        // Escalate level 2 → expired (no level 3)
        engine.check_sla(901_000 + 301_000);

        assert_eq!(
            engine.get_escalation(&eid).unwrap().status,
            EscalationStatus::Expired
        );
    }

    #[test]
    fn on_call_rotation() {
        let schedule = OnCallSchedule {
            id: "soc".into(),
            name: "SOC Rotation".into(),
            members: vec![
                Contact {
                    name: "Alice".into(),
                    email: None,
                    phone: None,
                    slack_id: None,
                    role: "Analyst".into(),
                    on_call: true,
                },
                Contact {
                    name: "Bob".into(),
                    email: None,
                    phone: None,
                    slack_id: None,
                    role: "Analyst".into(),
                    on_call: true,
                },
            ],
            rotation_hours: 168, // weekly
            start_epoch_ms: 0,
        };

        assert_eq!(schedule.on_call_at(0).unwrap().name, "Alice");
        // One week later
        assert_eq!(
            schedule.on_call_at(168 * 3_600_000).unwrap().name,
            "Bob"
        );
        // Two weeks later → back to Alice
        assert_eq!(
            schedule.on_call_at(2 * 168 * 3_600_000).unwrap().name,
            "Alice"
        );
    }

    #[test]
    fn resolve_escalation() {
        let mut engine = EscalationEngine::new();
        engine.add_policy(sample_policy());

        let eid = engine
            .start_escalation("pol-1", "alert-1", 1000)
            .unwrap();
        assert!(engine.resolve(&eid));
        assert_eq!(
            engine.get_escalation(&eid).unwrap().status,
            EscalationStatus::Resolved
        );
        assert!(engine.active_escalations().is_empty());
    }

    #[test]
    fn notification_count() {
        let mut engine = EscalationEngine::new();
        engine.add_policy(sample_policy());

        engine.start_escalation("pol-1", "alert-1", 0);
        // Level 1: 1 contact × 1 channel = 1 notification
        assert_eq!(engine.total_notifications(), 1);

        // Escalate to level 2: 1 contact × 2 channels = 2 more
        engine.check_sla(301_000);
        assert_eq!(engine.total_notifications(), 3);
    }

    #[test]
    fn disabled_policy_not_matched() {
        let mut engine = EscalationEngine::new();
        let mut p = sample_policy();
        p.enabled = false;
        engine.add_policy(p);

        assert!(engine.matching_policies(90.0, "ransomware").is_empty());
    }

    #[test]
    fn schedule_engine_integration() {
        let mut engine = EscalationEngine::new();
        engine.add_schedule(OnCallSchedule {
            id: "soc".into(),
            name: "SOC".into(),
            members: vec![Contact {
                name: "Charlie".into(),
                email: None,
                phone: None,
                slack_id: None,
                role: "Analyst".into(),
                on_call: true,
            }],
            rotation_hours: 168,
            start_epoch_ms: 0,
        });

        let oc = engine.current_on_call("soc", 100_000).unwrap();
        assert_eq!(oc.name, "Charlie");
    }
}
