use crate::policy::PolicyDecision;

#[derive(Debug, Clone)]
pub struct ActionResult {
    pub success: bool,
    pub message: String,
}

pub trait DeviceAction {
    fn execute(&self, decision: &PolicyDecision) -> ActionResult;
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

    fn name(&self) -> &str {
        "logging"
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
}
