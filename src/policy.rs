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
