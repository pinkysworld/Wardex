use crate::policy::{ResponseAction, ThreatLevel};

#[derive(Debug, Clone)]
pub enum TransitionTrigger {
    ScoreThreshold { score: f32 },
    IntegrityDrift { drift: f32 },
    BatteryDegradation { battery_pct: f32 },
}

#[derive(Debug, Clone)]
pub struct Transition {
    pub from: ThreatLevel,
    pub to: ThreatLevel,
    pub action: ResponseAction,
    pub trigger: TransitionTrigger,
}

pub struct PolicyStateMachine {
    state: ThreatLevel,
    trace: Vec<Transition>,
}

impl PolicyStateMachine {
    pub fn new() -> Self {
        Self {
            state: ThreatLevel::Nominal,
            trace: Vec::new(),
        }
    }

    pub fn state(&self) -> ThreatLevel {
        self.state
    }

    pub fn step(
        &mut self,
        level: ThreatLevel,
        action: ResponseAction,
        trigger: TransitionTrigger,
    ) {
        let transition = Transition {
            from: self.state,
            to: level,
            action,
            trigger,
        };
        self.state = level;
        self.trace.push(transition);
    }

    pub fn trace(&self) -> &[Transition] {
        &self.trace
    }

    pub fn is_legal(from: ThreatLevel, to: ThreatLevel) -> bool {
        if to >= from {
            return true;
        }
        // De-escalation is only legal one level at a time
        match (from, to) {
            (ThreatLevel::Critical, ThreatLevel::Severe) => true,
            (ThreatLevel::Severe, ThreatLevel::Elevated) => true,
            (ThreatLevel::Elevated, ThreatLevel::Nominal) => true,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PolicyStateMachine, TransitionTrigger};
    use crate::policy::{ResponseAction, ThreatLevel};

    #[test]
    fn initial_state_is_nominal() {
        let sm = PolicyStateMachine::new();
        assert_eq!(sm.state(), ThreatLevel::Nominal);
    }

    #[test]
    fn step_records_transition() {
        let mut sm = PolicyStateMachine::new();
        sm.step(
            ThreatLevel::Critical,
            ResponseAction::RollbackAndEscalate,
            TransitionTrigger::ScoreThreshold { score: 8.0 },
        );

        assert_eq!(sm.state(), ThreatLevel::Critical);
        assert_eq!(sm.trace().len(), 1);
        assert_eq!(sm.trace()[0].from, ThreatLevel::Nominal);
        assert_eq!(sm.trace()[0].to, ThreatLevel::Critical);
    }

    #[test]
    fn escalation_is_always_legal() {
        assert!(PolicyStateMachine::is_legal(
            ThreatLevel::Nominal,
            ThreatLevel::Critical
        ));
        assert!(PolicyStateMachine::is_legal(
            ThreatLevel::Elevated,
            ThreatLevel::Severe
        ));
    }

    #[test]
    fn single_step_deescalation_is_legal() {
        assert!(PolicyStateMachine::is_legal(
            ThreatLevel::Critical,
            ThreatLevel::Severe
        ));
        assert!(PolicyStateMachine::is_legal(
            ThreatLevel::Severe,
            ThreatLevel::Elevated
        ));
        assert!(PolicyStateMachine::is_legal(
            ThreatLevel::Elevated,
            ThreatLevel::Nominal
        ));
    }

    #[test]
    fn multi_step_deescalation_is_illegal() {
        assert!(!PolicyStateMachine::is_legal(
            ThreatLevel::Critical,
            ThreatLevel::Nominal
        ));
        assert!(!PolicyStateMachine::is_legal(
            ThreatLevel::Severe,
            ThreatLevel::Nominal
        ));
        assert!(!PolicyStateMachine::is_legal(
            ThreatLevel::Critical,
            ThreatLevel::Elevated
        ));
    }
}
