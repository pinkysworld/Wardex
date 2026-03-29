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

impl Default for PolicyStateMachine {
    fn default() -> Self {
        Self {
            state: ThreatLevel::Nominal,
            trace: Vec::new(),
        }
    }
}

impl PolicyStateMachine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn state(&self) -> ThreatLevel {
        self.state
    }

    pub fn step(&mut self, level: ThreatLevel, action: ResponseAction, trigger: TransitionTrigger) {
        if !Self::is_legal(self.state, level) {
            // Clamp illegal de-escalations: stay at current level.
            return;
        }
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
        matches!(
            (from, to),
            (ThreatLevel::Critical, ThreatLevel::Severe)
                | (ThreatLevel::Severe, ThreatLevel::Elevated)
                | (ThreatLevel::Elevated, ThreatLevel::Nominal)
        )
    }

    /// Export the state machine definition and recorded trace as a TLA+ module.
    pub fn export_tla(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        let _ = writeln!(out, "---- MODULE PolicyStateMachine ----");
        let _ = writeln!(out, "EXTENDS Naturals, Sequences");
        let _ = writeln!(out);
        let _ = writeln!(out, "CONSTANTS Nominal, Elevated, Severe, Critical");
        let _ = writeln!(out);
        let _ = writeln!(out, "States == {{Nominal, Elevated, Severe, Critical}}");
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "Actions == {{\"observe\", \"rate-limit\", \"quarantine\", \"rollback-and-escalate\"}}"
        );
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "(* Escalation is always legal; de-escalation only one step at a time *)"
        );
        let _ = writeln!(out, "LegalTransition(from, to) ==");
        let _ = writeln!(out, "    \\/ to >= from");
        let _ = writeln!(out, "    \\/ (from = Critical /\\ to = Severe)");
        let _ = writeln!(out, "    \\/ (from = Severe /\\ to = Elevated)");
        let _ = writeln!(out, "    \\/ (from = Elevated /\\ to = Nominal)");
        let _ = writeln!(out);
        let _ = writeln!(out, "VARIABLE state");
        let _ = writeln!(out);
        let _ = writeln!(out, "Init == state = Nominal");
        let _ = writeln!(out);
        let _ = writeln!(out, "Step(nextState) ==");
        let _ = writeln!(out, "    /\\ LegalTransition(state, nextState)");
        let _ = writeln!(out, "    /\\ state' = nextState");
        let _ = writeln!(out);
        let _ = writeln!(out, "Next == \\E s \\in States : Step(s)");
        let _ = writeln!(out);
        let _ = writeln!(out, "Spec == Init /\\ [][Next]_state");
        let _ = writeln!(out);
        let _ = writeln!(out, "(* Safety: no multi-step de-escalation *)");
        let _ = writeln!(
            out,
            "NoSkipDeescalation == [][LegalTransition(state, state')]_state"
        );
        let _ = writeln!(out);

        // Recorded trace as a witness sequence
        if !self.trace.is_empty() {
            let _ = writeln!(out, "(* Recorded trace witness *)");
            let _ = write!(out, "Trace == <<");
            for (i, t) in self.trace.iter().enumerate() {
                if i > 0 {
                    let _ = write!(out, ", ");
                }
                let _ = write!(
                    out,
                    "[from |-> {}, to |-> {}, action |-> \"{}\"]",
                    tla_state(t.from),
                    tla_state(t.to),
                    t.action.as_str()
                );
            }
            let _ = writeln!(out, ">>");
            let _ = writeln!(out);
        }

        let _ = writeln!(out, "====");
        out
    }

    /// Export the state machine definition and recorded trace as an Alloy module.
    pub fn export_alloy(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        let _ = writeln!(out, "module PolicyStateMachine");
        let _ = writeln!(out);
        let _ = writeln!(out, "open util/ordering[State]");
        let _ = writeln!(out);
        let _ = writeln!(out, "abstract sig ThreatLevel {{}}");
        let _ = writeln!(
            out,
            "one sig Nominal, Elevated, Severe, Critical extends ThreatLevel {{}}"
        );
        let _ = writeln!(out);
        let _ = writeln!(out, "abstract sig Action {{}}");
        let _ = writeln!(
            out,
            "one sig Observe, RateLimit, Quarantine, RollbackAndEscalate extends Action {{}}"
        );
        let _ = writeln!(out);
        let _ = writeln!(out, "sig State {{");
        let _ = writeln!(out, "    level: one ThreatLevel,");
        let _ = writeln!(out, "    action: lone Action");
        let _ = writeln!(out, "}}");
        let _ = writeln!(out);
        let _ = writeln!(out, "fun rank[t: ThreatLevel]: Int {{");
        let _ = writeln!(out, "    t = Nominal => 0");
        let _ = writeln!(out, "    else t = Elevated => 1");
        let _ = writeln!(out, "    else t = Severe => 2");
        let _ = writeln!(out, "    else 3");
        let _ = writeln!(out, "}}");
        let _ = writeln!(out);
        let _ = writeln!(out, "pred legalTransition[from, to: ThreatLevel] {{");
        let _ = writeln!(out, "    rank[to] >= rank[from]");
        let _ = writeln!(out, "    or (from = Critical and to = Severe)");
        let _ = writeln!(out, "    or (from = Severe and to = Elevated)");
        let _ = writeln!(out, "    or (from = Elevated and to = Nominal)");
        let _ = writeln!(out, "}}");
        let _ = writeln!(out);
        let _ = writeln!(out, "fact init {{");
        let _ = writeln!(out, "    first.level = Nominal");
        let _ = writeln!(out, "    no first.action");
        let _ = writeln!(out, "}}");
        let _ = writeln!(out);
        let _ = writeln!(out, "fact transitions {{");
        let _ = writeln!(out, "    all s: State - last |");
        let _ = writeln!(out, "        let s' = s.next |");
        let _ = writeln!(out, "            legalTransition[s.level, s'.level]");
        let _ = writeln!(out, "}}");
        let _ = writeln!(out);
        let _ = writeln!(out, "assert noSkipDeescalation {{");
        let _ = writeln!(out, "    all s: State - last |");
        let _ = writeln!(out, "        let s' = s.next |");
        let _ = writeln!(out, "            legalTransition[s.level, s'.level]");
        let _ = writeln!(out, "}}");
        let _ = writeln!(out);

        // Recorded trace as a fact
        if !self.trace.is_empty() {
            let _ = writeln!(out, "// Recorded trace witness");
            let _ = writeln!(out, "fact traceWitness {{");
            let _ = writeln!(out, "    #State = add[#Transition, 1]");
            for (i, t) in self.trace.iter().enumerate() {
                let _ = writeln!(
                    out,
                    "    (first{}).level = {}",
                    ".next".repeat(i),
                    alloy_state(t.from),
                );
                let _ = writeln!(
                    out,
                    "    (first{}).level = {}",
                    ".next".repeat(i + 1),
                    alloy_state(t.to),
                );
                let _ = writeln!(
                    out,
                    "    (first{}).action = {}",
                    ".next".repeat(i + 1),
                    alloy_action(t.action),
                );
            }
            let _ = writeln!(out, "}}");
            let _ = writeln!(out);
        }

        let _ = writeln!(
            out,
            "check noSkipDeescalation for {} State",
            std::cmp::max(4, self.trace.len() + 1)
        );
        out
    }
}

fn tla_state(level: ThreatLevel) -> &'static str {
    match level {
        ThreatLevel::Nominal => "Nominal",
        ThreatLevel::Elevated => "Elevated",
        ThreatLevel::Severe => "Severe",
        ThreatLevel::Critical => "Critical",
    }
}

fn alloy_state(level: ThreatLevel) -> &'static str {
    match level {
        ThreatLevel::Nominal => "Nominal",
        ThreatLevel::Elevated => "Elevated",
        ThreatLevel::Severe => "Severe",
        ThreatLevel::Critical => "Critical",
    }
}

fn alloy_action(action: ResponseAction) -> &'static str {
    match action {
        ResponseAction::Observe => "Observe",
        ResponseAction::RateLimit => "RateLimit",
        ResponseAction::Quarantine => "Quarantine",
        ResponseAction::RollbackAndEscalate => "RollbackAndEscalate",
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

    #[test]
    fn step_rejects_illegal_transition() {
        let mut sm = PolicyStateMachine::new();
        // Escalate to Critical
        sm.step(
            ThreatLevel::Critical,
            ResponseAction::RollbackAndEscalate,
            TransitionTrigger::ScoreThreshold { score: 8.0 },
        );
        assert_eq!(sm.state(), ThreatLevel::Critical);

        // Attempt illegal jump: Critical → Nominal (skip Severe and Elevated)
        sm.step(
            ThreatLevel::Nominal,
            ResponseAction::Observe,
            TransitionTrigger::ScoreThreshold { score: 0.1 },
        );
        // State should remain Critical (illegal transition was rejected)
        assert_eq!(sm.state(), ThreatLevel::Critical);
        // Only the initial escalation should be in the trace
        assert_eq!(sm.trace().len(), 1);
    }

    #[test]
    fn export_tla_contains_module_and_spec() {
        let sm = PolicyStateMachine::new();
        let tla = sm.export_tla();
        assert!(tla.contains("MODULE PolicyStateMachine"));
        assert!(tla.contains("LegalTransition(from, to)"));
        assert!(tla.contains("Init == state = Nominal"));
        assert!(tla.contains("Spec == Init /\\ [][Next]_state"));
        assert!(tla.contains("NoSkipDeescalation"));
        assert!(tla.contains("===="));
        // No trace for empty machine
        assert!(!tla.contains("Trace =="));
    }

    #[test]
    fn export_tla_includes_trace_witness() {
        let mut sm = PolicyStateMachine::new();
        sm.step(
            ThreatLevel::Elevated,
            ResponseAction::RateLimit,
            TransitionTrigger::ScoreThreshold { score: 2.0 },
        );
        sm.step(
            ThreatLevel::Critical,
            ResponseAction::RollbackAndEscalate,
            TransitionTrigger::IntegrityDrift { drift: 0.5 },
        );
        let tla = sm.export_tla();
        assert!(tla.contains("Trace == <<"));
        assert!(tla.contains("from |-> Nominal"));
        assert!(tla.contains("to |-> Elevated"));
        assert!(tla.contains("to |-> Critical"));
        assert!(tla.contains("\"rate-limit\""));
        assert!(tla.contains("\"rollback-and-escalate\""));
    }

    #[test]
    fn export_alloy_contains_module_and_check() {
        let sm = PolicyStateMachine::new();
        let alloy = sm.export_alloy();
        assert!(alloy.contains("module PolicyStateMachine"));
        assert!(alloy.contains("abstract sig ThreatLevel"));
        assert!(alloy.contains("one sig Nominal, Elevated, Severe, Critical"));
        assert!(alloy.contains("pred legalTransition"));
        assert!(alloy.contains("assert noSkipDeescalation"));
        assert!(alloy.contains("check noSkipDeescalation"));
        // No trace for empty machine
        assert!(!alloy.contains("traceWitness"));
    }

    #[test]
    fn export_alloy_includes_trace_witness() {
        let mut sm = PolicyStateMachine::new();
        sm.step(
            ThreatLevel::Severe,
            ResponseAction::Quarantine,
            TransitionTrigger::ScoreThreshold { score: 4.0 },
        );
        let alloy = sm.export_alloy();
        assert!(alloy.contains("traceWitness"));
        assert!(alloy.contains("Nominal"));
        assert!(alloy.contains("Severe"));
        assert!(alloy.contains("Quarantine"));
    }
}
