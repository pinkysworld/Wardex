use serde::{Deserialize, Serialize};

use crate::policy::{PolicyDecision, ResponseAction};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionResult {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceStateSnapshot {
    pub isolation_pct: u8,
    pub service_quarantined: bool,
    pub network_isolated: bool,
    pub last_action: String,
}

pub trait DeviceAction {
    fn execute(&self, decision: &PolicyDecision) -> ActionResult;
    fn restore(&self, snapshot: &DeviceStateSnapshot) -> ActionResult;
    fn name(&self) -> &str;
}

pub struct ThrottleAdapter;

impl DeviceAction for ThrottleAdapter {
    fn execute(&self, decision: &PolicyDecision) -> ActionResult {
        ActionResult {
            success: true,
            message: format!(
                "throttle applied at {}% isolation ({})",
                decision.isolation_pct,
                decision.action.as_str()
            ),
        }
    }

    fn restore(&self, snapshot: &DeviceStateSnapshot) -> ActionResult {
        ActionResult {
            success: true,
            message: format!("throttle restored to {}% isolation", snapshot.isolation_pct),
        }
    }

    fn name(&self) -> &str {
        "throttle"
    }
}

pub struct QuarantineAdapter;

impl DeviceAction for QuarantineAdapter {
    fn execute(&self, decision: &PolicyDecision) -> ActionResult {
        ActionResult {
            success: true,
            message: format!(
                "quarantine enforced at {}% isolation ({})",
                decision.isolation_pct,
                decision.action.as_str()
            ),
        }
    }

    fn restore(&self, snapshot: &DeviceStateSnapshot) -> ActionResult {
        ActionResult {
            success: true,
            message: format!(
                "quarantine restored at {}% isolation",
                snapshot.isolation_pct
            ),
        }
    }

    fn name(&self) -> &str {
        "quarantine"
    }
}

pub struct IsolateAdapter;

impl DeviceAction for IsolateAdapter {
    fn execute(&self, decision: &PolicyDecision) -> ActionResult {
        ActionResult {
            success: true,
            message: format!(
                "network isolation at {}% ({})",
                decision.isolation_pct,
                decision.action.as_str()
            ),
        }
    }

    fn restore(&self, snapshot: &DeviceStateSnapshot) -> ActionResult {
        ActionResult {
            success: true,
            message: format!("network isolation restored at {}%", snapshot.isolation_pct),
        }
    }

    fn name(&self) -> &str {
        "isolate"
    }
}

pub struct LoggingAdapter;

impl DeviceAction for LoggingAdapter {
    fn execute(&self, decision: &PolicyDecision) -> ActionResult {
        ActionResult {
            success: true,
            message: format!(
                "logged: level={} action={} isolation={}%",
                decision.level.as_str(),
                decision.action.as_str(),
                decision.isolation_pct
            ),
        }
    }

    fn restore(&self, snapshot: &DeviceStateSnapshot) -> ActionResult {
        ActionResult {
            success: true,
            message: format!(
                "logged restore: isolation={}%, quarantined={}, network_isolated={}, last_action={}",
                snapshot.isolation_pct,
                snapshot.service_quarantined,
                snapshot.network_isolated,
                snapshot.last_action
            ),
        }
    }

    fn name(&self) -> &str {
        "logging"
    }
}

pub struct RestoreAdapter;

impl DeviceAction for RestoreAdapter {
    fn execute(&self, decision: &PolicyDecision) -> ActionResult {
        ActionResult {
            success: true,
            message: format!(
                "restore adapter observed live action={} isolation={}%; use restore() for rollback",
                decision.action.as_str(),
                decision.isolation_pct
            ),
        }
    }

    fn restore(&self, _snapshot: &DeviceStateSnapshot) -> ActionResult {
        ActionResult {
            success: true,
            message: "device state restored to nominal".into(),
        }
    }

    fn name(&self) -> &str {
        "restore"
    }
}

pub struct CompositeAdapter {
    adapters: Vec<Box<dyn DeviceAction>>,
}

impl CompositeAdapter {
    pub fn new(adapters: Vec<Box<dyn DeviceAction>>) -> Self {
        Self { adapters }
    }

    pub fn execute_all(&self, decision: &PolicyDecision) -> Vec<ActionResult> {
        self.adapters
            .iter()
            .map(|adapter| adapter.execute(decision))
            .collect()
    }

    pub fn restore_all(&self, snapshot: &DeviceStateSnapshot) -> Vec<ActionResult> {
        self.adapters
            .iter()
            .map(|adapter| adapter.restore(snapshot))
            .collect()
    }
}

pub struct DeviceController {
    logger: LoggingAdapter,
    throttle: ThrottleAdapter,
    quarantine: QuarantineAdapter,
    isolate: IsolateAdapter,
    restore: RestoreAdapter,
    state: DeviceStateSnapshot,
}

impl Default for DeviceController {
    fn default() -> Self {
        Self {
            logger: LoggingAdapter,
            throttle: ThrottleAdapter,
            quarantine: QuarantineAdapter,
            isolate: IsolateAdapter,
            restore: RestoreAdapter,
            state: DeviceStateSnapshot::default(),
        }
    }
}

impl DeviceController {
    pub fn snapshot(&self) -> DeviceStateSnapshot {
        self.state.clone()
    }

    pub fn apply_decision(&mut self, decision: &PolicyDecision) -> Vec<ActionResult> {
        let mut results = vec![self.logger.execute(decision)];
        self.state = state_for_decision(decision);

        match decision.action {
            ResponseAction::Observe => {
                results.push(self.restore.restore(&self.state));
            }
            ResponseAction::RateLimit => {
                results.push(self.throttle.execute(decision));
            }
            ResponseAction::Quarantine => {
                results.push(self.quarantine.execute(decision));
            }
            ResponseAction::RollbackAndEscalate => {
                results.push(self.isolate.execute(decision));
            }
        }

        results
    }

    pub fn restore_snapshot(&mut self, snapshot: &DeviceStateSnapshot) -> Vec<ActionResult> {
        let mut results = Vec::new();

        if snapshot.network_isolated {
            results.push(self.isolate.restore(snapshot));
        } else if snapshot.service_quarantined {
            results.push(self.quarantine.restore(snapshot));
        } else if snapshot.isolation_pct > 0 {
            results.push(self.throttle.restore(snapshot));
        } else {
            results.push(self.restore.restore(snapshot));
        }

        results.push(self.logger.restore(snapshot));
        self.state = snapshot.clone();
        results
    }
}

fn state_for_decision(decision: &PolicyDecision) -> DeviceStateSnapshot {
    match decision.action {
        ResponseAction::Observe => DeviceStateSnapshot {
            isolation_pct: 0,
            service_quarantined: false,
            network_isolated: false,
            last_action: decision.action.as_str().into(),
        },
        ResponseAction::RateLimit => DeviceStateSnapshot {
            isolation_pct: decision.isolation_pct,
            service_quarantined: false,
            network_isolated: false,
            last_action: decision.action.as_str().into(),
        },
        ResponseAction::Quarantine => DeviceStateSnapshot {
            isolation_pct: decision.isolation_pct,
            service_quarantined: true,
            network_isolated: false,
            last_action: decision.action.as_str().into(),
        },
        ResponseAction::RollbackAndEscalate => DeviceStateSnapshot {
            isolation_pct: decision.isolation_pct,
            service_quarantined: true,
            network_isolated: true,
            last_action: decision.action.as_str().into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{PolicyDecision, ResponseAction, ThreatLevel};

    fn test_decision() -> PolicyDecision {
        PolicyDecision {
            level: ThreatLevel::Severe,
            action: ResponseAction::Quarantine,
            isolation_pct: 75,
            rationale: "test scenario".into(),
        }
    }

    #[test]
    fn throttle_adapter_succeeds() {
        let adapter = ThrottleAdapter;
        let result = adapter.execute(&test_decision());
        assert!(result.success);
        assert!(result.message.contains("75%"));
    }

    #[test]
    fn quarantine_adapter_succeeds() {
        let adapter = QuarantineAdapter;
        let result = adapter.execute(&test_decision());
        assert!(result.success);
        assert!(result.message.contains("quarantine"));
    }

    #[test]
    fn isolate_adapter_succeeds() {
        let adapter = IsolateAdapter;
        let result = adapter.execute(&test_decision());
        assert!(result.success);
        assert!(result.message.contains("isolation"));
    }

    #[test]
    fn logging_adapter_succeeds() {
        let adapter = LoggingAdapter;
        let result = adapter.execute(&test_decision());
        assert!(result.success);
        assert!(result.message.contains("severe"));
    }

    #[test]
    fn composite_chains_adapters() {
        let composite = CompositeAdapter::new(vec![
            Box::new(LoggingAdapter),
            Box::new(ThrottleAdapter),
            Box::new(QuarantineAdapter),
        ]);
        let results = composite.execute_all(&test_decision());
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| r.success));
    }

    #[test]
    fn controller_tracks_quarantine_state() {
        let mut controller = DeviceController::default();
        let results = controller.apply_decision(&test_decision());

        assert_eq!(results.len(), 2);
        assert!(controller.snapshot().service_quarantined);
        assert_eq!(controller.snapshot().isolation_pct, 75);
    }

    #[test]
    fn controller_restores_nominal_state() {
        let mut controller = DeviceController::default();
        controller.apply_decision(&test_decision());

        let target = DeviceStateSnapshot::default();
        let results = controller.restore_snapshot(&target);

        assert_eq!(results.len(), 2);
        assert_eq!(controller.snapshot(), target);
        assert!(results[0].message.contains("nominal"));
    }

    #[test]
    fn controller_restores_isolated_state() {
        let mut controller = DeviceController::default();
        let target = DeviceStateSnapshot {
            isolation_pct: 100,
            service_quarantined: true,
            network_isolated: true,
            last_action: "rollback-and-escalate".into(),
        };

        let results = controller.restore_snapshot(&target);

        assert_eq!(controller.snapshot(), target);
        assert!(results[0].message.contains("restored"));
    }
}
