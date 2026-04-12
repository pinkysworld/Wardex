//! Threat-level classification and response-action mapping for anomaly signals.

use serde::{Deserialize, Serialize};

use crate::detector::AnomalySignal;
use crate::telemetry::TelemetrySample;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ThreatLevel {
    Nominal,
    Elevated,
    Severe,
    Critical,
}

impl ThreatLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Nominal => "nominal",
            Self::Elevated => "elevated",
            Self::Severe => "severe",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResponseAction {
    Observe,
    RateLimit,
    Quarantine,
    RollbackAndEscalate,
}

impl ResponseAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::RateLimit => "rate-limit",
            Self::Quarantine => "quarantine",
            Self::RollbackAndEscalate => "rollback-and-escalate",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PolicyDecision {
    pub level: ThreatLevel,
    pub action: ResponseAction,
    pub isolation_pct: u8,
    pub rationale: String,
}

#[derive(Debug, Default)]
pub struct PolicyEngine;

impl PolicyEngine {
    pub fn evaluate(&self, signal: &AnomalySignal, sample: &TelemetrySample) -> PolicyDecision {
        let mut notes = vec![format!(
            "score {:.2} with {:.0}% confidence",
            signal.score,
            signal.confidence * 100.0
        )];

        let mut level = if sample.integrity_drift >= 0.45 || signal.score >= 5.2 {
            ThreatLevel::Critical
        } else if signal.score >= 3.0 {
            ThreatLevel::Severe
        } else if signal.score >= 1.4 {
            ThreatLevel::Elevated
        } else {
            ThreatLevel::Nominal
        };

        let mut action = match level {
            ThreatLevel::Nominal => ResponseAction::Observe,
            ThreatLevel::Elevated => ResponseAction::RateLimit,
            ThreatLevel::Severe => ResponseAction::Quarantine,
            ThreatLevel::Critical => ResponseAction::RollbackAndEscalate,
        };

        let mut isolation_pct = match action {
            ResponseAction::Observe => 0,
            ResponseAction::RateLimit => 30,
            ResponseAction::Quarantine => 75,
            ResponseAction::RollbackAndEscalate => 100,
        };

        if sample.battery_pct < 20.0 {
            match action {
                ResponseAction::Quarantine => {
                    action = ResponseAction::RateLimit;
                    level = ThreatLevel::Elevated.max(level);
                    isolation_pct = 45;
                    notes
                        .push("battery under 20%, softening quarantine to preserve runtime".into());
                }
                ResponseAction::RollbackAndEscalate if sample.integrity_drift < 0.45 => {
                    action = ResponseAction::Quarantine;
                    level = ThreatLevel::Severe;
                    isolation_pct = 85;
                    notes.push(
                        "battery under 20%, deferring rollback but keeping aggressive isolation"
                            .into(),
                    );
                }
                _ => {}
            }
        }

        if sample.integrity_drift >= 0.45 {
            notes.push("integrity drift crossed the critical threshold".into());
        }

        PolicyDecision {
            level,
            action,
            isolation_pct,
            rationale: notes.join("; "),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PolicyEngine, ResponseAction, ThreatLevel};
    use crate::detector::AnomalySignal;
    use crate::telemetry::TelemetrySample;

    #[test]
    fn low_battery_softens_quarantine() {
        let engine = PolicyEngine;
        let decision = engine.evaluate(
            &AnomalySignal {
                score: 3.4,
                confidence: 1.0,
                suspicious_axes: 3,
                reasons: vec!["network burst".into()],
                contributions: Vec::new(),
                triage: None,
            },
            &TelemetrySample {
                timestamp_ms: 1,
                cpu_load_pct: 70.0,
                memory_load_pct: 65.0,
                temperature_c: 50.0,
                network_kbps: 5000.0,
                auth_failures: 6,
                battery_pct: 14.0,
                integrity_drift: 0.18,
                process_count: 0,
                disk_pressure_pct: 0.0,
            },
        );

        assert_eq!(decision.level, ThreatLevel::Severe);
        assert_eq!(decision.action, ResponseAction::RateLimit);
    }

    #[test]
    fn integrity_drift_forces_critical() {
        let engine = PolicyEngine;
        let decision = engine.evaluate(
            &AnomalySignal {
                score: 1.0,
                confidence: 0.8,
                suspicious_axes: 1,
                reasons: vec!["integrity drift".into()],
                contributions: Vec::new(),
                triage: None,
            },
            &TelemetrySample {
                timestamp_ms: 1,
                cpu_load_pct: 30.0,
                memory_load_pct: 30.0,
                temperature_c: 38.0,
                network_kbps: 800.0,
                auth_failures: 0,
                battery_pct: 80.0,
                integrity_drift: 0.52,
                process_count: 0,
                disk_pressure_pct: 0.0,
            },
        );

        assert_eq!(decision.level, ThreatLevel::Critical);
    }
}

// ─── Policy composition algebra (R39 / T076) ───

/// A composable policy rule that maps signal+sample to an optional decision.
/// Returning `None` means the rule abstains (no opinion).
pub type PolicyRule = Box<dyn Fn(&AnomalySignal, &TelemetrySample) -> Option<PolicyDecision>>;

/// Composition operators for combining two policy decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompositionOp {
    /// Take the more severe of two decisions.
    MaxSeverity,
    /// Take the less severe of two decisions.
    MinSeverity,
    /// Left policy wins on conflict; right is only used if left abstains.
    LeftPriority,
    /// Right policy wins on conflict; left is only used if right abstains.
    RightPriority,
}

/// A conflict between two policy decisions.
#[derive(Debug, Clone)]
pub struct PolicyConflict {
    pub left_level: ThreatLevel,
    pub left_action: ResponseAction,
    pub right_level: ThreatLevel,
    pub right_action: ResponseAction,
    pub resolution: String,
}

/// Compose two optional policy decisions using the given operator.
pub fn compose_decisions(
    left: Option<PolicyDecision>,
    right: Option<PolicyDecision>,
    op: CompositionOp,
) -> (Option<PolicyDecision>, Option<PolicyConflict>) {
    match (left, right) {
        (None, None) => (None, None),
        (Some(l), None) => (Some(l), None),
        (None, Some(r)) => (Some(r), None),
        (Some(l), Some(r)) => {
            let conflict = if l.level != r.level || l.action != r.action {
                Some(PolicyConflict {
                    left_level: l.level,
                    left_action: l.action,
                    right_level: r.level,
                    right_action: r.action,
                    resolution: format!("{:?}", op),
                })
            } else {
                None
            };

            let chosen = match op {
                CompositionOp::MaxSeverity => {
                    if l.level >= r.level {
                        l
                    } else {
                        r
                    }
                }
                CompositionOp::MinSeverity => {
                    if l.level <= r.level {
                        l
                    } else {
                        r
                    }
                }
                CompositionOp::LeftPriority => l,
                CompositionOp::RightPriority => r,
            };

            (Some(chosen), conflict)
        }
    }
}

/// A composite policy that chains multiple rules with a composition operator.
pub struct CompositePolicy {
    rules: Vec<(&'static str, PolicyRule)>,
    op: CompositionOp,
}

impl CompositePolicy {
    pub fn new(op: CompositionOp) -> Self {
        Self {
            rules: Vec::new(),
            op,
        }
    }

    pub fn add_rule(&mut self, name: &'static str, rule: PolicyRule) {
        self.rules.push((name, rule));
    }

    /// Evaluate all rules and compose their decisions, recording any conflicts.
    pub fn evaluate(
        &self,
        signal: &AnomalySignal,
        sample: &TelemetrySample,
    ) -> (Option<PolicyDecision>, Vec<PolicyConflict>) {
        let mut combined: Option<PolicyDecision> = None;
        let mut conflicts = Vec::new();

        for (_name, rule) in &self.rules {
            let decision = rule(signal, sample);
            let (merged, conflict) = compose_decisions(combined, decision, self.op);
            if let Some(c) = conflict {
                conflicts.push(c);
            }
            combined = merged;
        }

        (combined, conflicts)
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

#[cfg(test)]
mod composition_tests {
    use super::*;
    use crate::detector::AnomalySignal;
    use crate::telemetry::TelemetrySample;

    fn dummy_signal(score: f32) -> AnomalySignal {
        AnomalySignal {
            score,
            confidence: 1.0,
            suspicious_axes: 1,
            reasons: vec!["test".into()],
            contributions: Vec::new(),
            triage: None,
        }
    }

    fn dummy_sample() -> TelemetrySample {
        TelemetrySample {
            timestamp_ms: 1,
            cpu_load_pct: 50.0,
            memory_load_pct: 50.0,
            temperature_c: 40.0,
            network_kbps: 500.0,
            auth_failures: 0,
            battery_pct: 80.0,
            integrity_drift: 0.01,
            process_count: 50,
            disk_pressure_pct: 10.0,
        }
    }

    #[test]
    fn max_severity_picks_higher() {
        let low = PolicyDecision {
            level: ThreatLevel::Elevated,
            action: ResponseAction::RateLimit,
            isolation_pct: 30,
            rationale: "low".into(),
        };
        let high = PolicyDecision {
            level: ThreatLevel::Critical,
            action: ResponseAction::RollbackAndEscalate,
            isolation_pct: 100,
            rationale: "high".into(),
        };
        let (result, conflict) =
            compose_decisions(Some(low), Some(high), CompositionOp::MaxSeverity);
        assert_eq!(result.unwrap().level, ThreatLevel::Critical);
        assert!(conflict.is_some());
    }

    #[test]
    fn min_severity_picks_lower() {
        let low = PolicyDecision {
            level: ThreatLevel::Elevated,
            action: ResponseAction::RateLimit,
            isolation_pct: 30,
            rationale: "low".into(),
        };
        let high = PolicyDecision {
            level: ThreatLevel::Severe,
            action: ResponseAction::Quarantine,
            isolation_pct: 75,
            rationale: "high".into(),
        };
        let (result, _) = compose_decisions(Some(low), Some(high), CompositionOp::MinSeverity);
        assert_eq!(result.unwrap().level, ThreatLevel::Elevated);
    }

    #[test]
    fn left_priority_wins() {
        let left = PolicyDecision {
            level: ThreatLevel::Nominal,
            action: ResponseAction::Observe,
            isolation_pct: 0,
            rationale: "left".into(),
        };
        let right = PolicyDecision {
            level: ThreatLevel::Critical,
            action: ResponseAction::RollbackAndEscalate,
            isolation_pct: 100,
            rationale: "right".into(),
        };
        let (result, _) = compose_decisions(Some(left), Some(right), CompositionOp::LeftPriority);
        assert_eq!(result.unwrap().level, ThreatLevel::Nominal);
    }

    #[test]
    fn no_conflict_when_agreeing() {
        let a = PolicyDecision {
            level: ThreatLevel::Severe,
            action: ResponseAction::Quarantine,
            isolation_pct: 75,
            rationale: "a".into(),
        };
        let b = PolicyDecision {
            level: ThreatLevel::Severe,
            action: ResponseAction::Quarantine,
            isolation_pct: 75,
            rationale: "b".into(),
        };
        let (_, conflict) = compose_decisions(Some(a), Some(b), CompositionOp::MaxSeverity);
        assert!(conflict.is_none());
    }

    #[test]
    fn composite_policy_chains_rules() {
        let mut cp = CompositePolicy::new(CompositionOp::MaxSeverity);
        cp.add_rule(
            "always_elevated",
            Box::new(|_sig, _sam| {
                Some(PolicyDecision {
                    level: ThreatLevel::Elevated,
                    action: ResponseAction::RateLimit,
                    isolation_pct: 30,
                    rationale: "rule1".into(),
                })
            }),
        );
        cp.add_rule(
            "high_score_critical",
            Box::new(|sig, _sam| {
                if sig.score > 5.0 {
                    Some(PolicyDecision {
                        level: ThreatLevel::Critical,
                        action: ResponseAction::RollbackAndEscalate,
                        isolation_pct: 100,
                        rationale: "rule2".into(),
                    })
                } else {
                    None
                }
            }),
        );

        assert_eq!(cp.rule_count(), 2);

        // Low score: only first rule fires
        let (decision, conflicts) = cp.evaluate(&dummy_signal(2.0), &dummy_sample());
        assert_eq!(decision.unwrap().level, ThreatLevel::Elevated);
        assert!(conflicts.is_empty());

        // High score: both fire, max wins
        let (decision, conflicts) = cp.evaluate(&dummy_signal(6.0), &dummy_sample());
        assert_eq!(decision.unwrap().level, ThreatLevel::Critical);
        assert_eq!(conflicts.len(), 1);
    }

    #[test]
    fn abstain_passes_through() {
        let (result, _) = compose_decisions(
            None,
            Some(PolicyDecision {
                level: ThreatLevel::Severe,
                action: ResponseAction::Quarantine,
                isolation_pct: 75,
                rationale: "only".into(),
            }),
            CompositionOp::MaxSeverity,
        );
        assert_eq!(result.unwrap().level, ThreatLevel::Severe);

        let (result, _) = compose_decisions(None, None, CompositionOp::MaxSeverity);
        assert!(result.is_none());
    }
}
