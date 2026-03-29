//! Temporal-logic runtime monitor (T083 / R29 / T074).
//!
//! Implements a lightweight property checking engine for SentinelTL
//! properties as described in DESIGN_TEMPORAL_LOGIC.md. Supports
//! safety properties ("always P") and bounded liveness
//! ("within N samples P").

/// A single runtime event fed to the monitor.
#[derive(Debug, Clone)]
pub enum MonitorEvent {
    Sample { score: f32, battery_pct: f32 },
    Alert { severity: String },
    Action { kind: String, battery_pct: f32 },
    Transition { from: String, to: String },
}

/// The stream type a property listens on.
#[derive(Debug, Clone, PartialEq)]
pub enum Stream {
    Sample,
    Alert,
    Action,
    Transition,
}

/// An obligation the property requires after trigger.
#[derive(Debug)]
pub enum Obligation {
    /// P must hold on every subsequent event (safety).
    Always(Box<dyn Predicate>),
    /// P must hold on at least one of the next N events (bounded liveness).
    Within(usize, Box<dyn Predicate>),
}

/// A named temporal property.
pub struct Property {
    pub name: String,
    stream: Stream,
    guard: Option<Box<dyn Predicate>>,
    obligation: Obligation,
}

/// Trait for predicates evaluated against monitor events.
pub trait Predicate: std::fmt::Debug + Send {
    fn check(&self, event: &MonitorEvent) -> bool;
}

// ─── Built-in predicates ────────────────────────────────────────────

/// Score bounded: `score <= limit`.
#[derive(Debug)]
pub struct ScoreBounded {
    pub limit: f32,
}

impl Predicate for ScoreBounded {
    fn check(&self, event: &MonitorEvent) -> bool {
        match event {
            MonitorEvent::Sample { score, .. } => *score <= self.limit,
            _ => true,
        }
    }
}

/// Severity equals a specific value.
#[derive(Debug)]
pub struct SeverityEquals {
    pub value: String,
}

impl Predicate for SeverityEquals {
    fn check(&self, event: &MonitorEvent) -> bool {
        match event {
            MonitorEvent::Alert { severity } => *severity == self.value,
            _ => false,
        }
    }
}

/// Action kind is not a specific value.
#[derive(Debug)]
pub struct ActionKindNot {
    pub value: String,
}

impl Predicate for ActionKindNot {
    fn check(&self, event: &MonitorEvent) -> bool {
        match event {
            MonitorEvent::Action { kind, .. } => *kind != self.value,
            _ => false,
        }
    }
}

/// Battery above threshold.
#[derive(Debug)]
pub struct BatteryAbove {
    pub threshold: f32,
}

impl Predicate for BatteryAbove {
    fn check(&self, event: &MonitorEvent) -> bool {
        match event {
            MonitorEvent::Sample { battery_pct, .. } => *battery_pct >= self.threshold,
            MonitorEvent::Action { battery_pct, .. } => *battery_pct >= self.threshold,
            _ => true,
        }
    }
}

/// Transition target is not a specific state.
#[derive(Debug)]
pub struct TransitionToNot {
    pub state: String,
}

impl Predicate for TransitionToNot {
    fn check(&self, event: &MonitorEvent) -> bool {
        match event {
            MonitorEvent::Transition { to, .. } => *to != self.state,
            _ => true,
        }
    }
}

/// Always true — used as a guard that matches every event on the stream.
#[derive(Debug)]
pub struct AlwaysTrue;

impl Predicate for AlwaysTrue {
    fn check(&self, _event: &MonitorEvent) -> bool {
        true
    }
}

// ─── Monitor state machine ──────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PropertyStatus {
    /// Property has not yet been triggered by a matching guard event.
    Idle,
    /// Tracking a bounded-liveness countdown.
    Tracking { remaining: usize },
    /// The obligation was met.
    Satisfied,
    /// The obligation was violated.
    Violated,
}

struct PropertyState {
    status: PropertyStatus,
}

/// A violation record.
#[derive(Debug, Clone)]
pub struct Violation {
    pub property_name: String,
    pub event_index: usize,
}

/// The runtime monitor that tracks a set of temporal properties.
#[derive(Default)]
pub struct Monitor {
    properties: Vec<Property>,
    states: Vec<PropertyState>,
    event_count: usize,
    violations: Vec<Violation>,
}

impl Monitor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a property to be monitored.
    pub fn add_property(&mut self, property: Property) {
        self.states.push(PropertyState {
            status: PropertyStatus::Idle,
        });
        self.properties.push(property);
    }

    /// Feed an event and check all properties.
    pub fn step(&mut self, event: &MonitorEvent) {
        self.event_count += 1;

        for (i, prop) in self.properties.iter().enumerate() {
            let state = &mut self.states[i];

            // Only process events on the matching stream.
            if !matches_stream(&prop.stream, event) {
                // But still count down bounded-liveness trackers.
                if let PropertyStatus::Tracking { remaining } = &mut state.status {
                    if *remaining == 0 {
                        state.status = PropertyStatus::Violated;
                        self.violations.push(Violation {
                            property_name: prop.name.clone(),
                            event_index: self.event_count,
                        });
                    } else {
                        *remaining -= 1;
                    }
                }
                continue;
            }

            match state.status {
                PropertyStatus::Idle => {
                    // Check guard
                    let guard_matches = match &prop.guard {
                        Some(g) => g.check(event),
                        None => true,
                    };

                    if guard_matches {
                        match &prop.obligation {
                            Obligation::Always(pred) => {
                                if pred.check(event) {
                                    state.status = PropertyStatus::Satisfied;
                                } else {
                                    state.status = PropertyStatus::Violated;
                                    self.violations.push(Violation {
                                        property_name: prop.name.clone(),
                                        event_index: self.event_count,
                                    });
                                }
                            }
                            Obligation::Within(n, pred) => {
                                if pred.check(event) {
                                    state.status = PropertyStatus::Satisfied;
                                } else if *n == 0 {
                                    state.status = PropertyStatus::Violated;
                                    self.violations.push(Violation {
                                        property_name: prop.name.clone(),
                                        event_index: self.event_count,
                                    });
                                } else {
                                    state.status = PropertyStatus::Tracking { remaining: *n - 1 };
                                }
                            }
                        }
                    }
                }
                PropertyStatus::Tracking { remaining } => match &prop.obligation {
                    Obligation::Within(_, pred) => {
                        if pred.check(event) {
                            state.status = PropertyStatus::Satisfied;
                        } else if remaining == 0 {
                            state.status = PropertyStatus::Violated;
                            self.violations.push(Violation {
                                property_name: prop.name.clone(),
                                event_index: self.event_count,
                            });
                        } else {
                            state.status = PropertyStatus::Tracking {
                                remaining: remaining - 1,
                            };
                        }
                    }
                    Obligation::Always(pred) => {
                        if !pred.check(event) {
                            state.status = PropertyStatus::Violated;
                            self.violations.push(Violation {
                                property_name: prop.name.clone(),
                                event_index: self.event_count,
                            });
                        }
                    }
                },
                PropertyStatus::Satisfied => {
                    // For safety properties, keep checking.
                    if let Obligation::Always(pred) = &prop.obligation
                        && !pred.check(event)
                    {
                        state.status = PropertyStatus::Violated;
                        self.violations.push(Violation {
                            property_name: prop.name.clone(),
                            event_index: self.event_count,
                        });
                    }
                }
                PropertyStatus::Violated => {
                    // Terminal — do nothing.
                }
            }
        }
    }

    /// Get the status of each property by name.
    pub fn statuses(&self) -> Vec<(&str, PropertyStatus)> {
        self.properties
            .iter()
            .zip(self.states.iter())
            .map(|(p, s)| (p.name.as_str(), s.status))
            .collect()
    }

    /// All violations accumulated so far.
    pub fn violations(&self) -> &[Violation] {
        &self.violations
    }

    pub fn event_count(&self) -> usize {
        self.event_count
    }
}

fn matches_stream(stream: &Stream, event: &MonitorEvent) -> bool {
    matches!(
        (stream, event),
        (Stream::Sample, MonitorEvent::Sample { .. })
            | (Stream::Alert, MonitorEvent::Alert { .. })
            | (Stream::Action, MonitorEvent::Action { .. })
            | (Stream::Transition, MonitorEvent::Transition { .. })
    )
}

// ─── Convenience constructors for the design-doc examples ───────────

impl Property {
    /// `property score_bounded { on sample => always score <= limit }`
    pub fn score_bounded(limit: f32) -> Self {
        Self {
            name: "score_bounded".into(),
            stream: Stream::Sample,
            guard: None,
            obligation: Obligation::Always(Box::new(ScoreBounded { limit })),
        }
    }

    /// `property critical_response { on alert where severity == "critical"
    ///     => within N samples action.kind != "none" }`
    pub fn critical_response(within: usize) -> Self {
        Self {
            name: "critical_response".into(),
            stream: Stream::Alert,
            guard: Some(Box::new(SeverityEquals {
                value: "critical".into(),
            })),
            obligation: Obligation::Within(
                within,
                Box::new(ActionKindNot {
                    value: "none".into(),
                }),
            ),
        }
    }

    /// `property no_skip_escalation { on transition where from == "normal"
    ///     => always to != "critical" }`
    pub fn no_skip_escalation() -> Self {
        Self {
            name: "no_skip_escalation".into(),
            stream: Stream::Transition,
            guard: Some(Box::new(AlwaysTrue)),
            obligation: Obligation::Always(Box::new(TransitionToNot {
                state: "critical".into(),
            })),
        }
    }
}

/// Create a monitor pre-loaded with sensible default safety properties.
///
/// Properties included:
/// - `score_bounded(10.0)`: score should never exceed 10.0 (sanity bound)
/// - `no_skip_escalation`: transitions should not jump from normal straight to critical
pub fn default_safety_monitor() -> Monitor {
    let mut mon = Monitor::new();
    mon.add_property(Property::score_bounded(10.0));
    mon.add_property(Property::no_skip_escalation());
    mon
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_bounded_satisfied() {
        let mut mon = Monitor::new();
        mon.add_property(Property::score_bounded(1.0));

        mon.step(&MonitorEvent::Sample {
            score: 0.3,
            battery_pct: 90.0,
        });
        mon.step(&MonitorEvent::Sample {
            score: 0.8,
            battery_pct: 85.0,
        });

        assert!(mon.violations().is_empty());
        let statuses = mon.statuses();
        assert_eq!(statuses[0].1, PropertyStatus::Satisfied);
    }

    #[test]
    fn score_bounded_violated() {
        let mut mon = Monitor::new();
        mon.add_property(Property::score_bounded(1.0));

        mon.step(&MonitorEvent::Sample {
            score: 0.5,
            battery_pct: 90.0,
        });
        mon.step(&MonitorEvent::Sample {
            score: 1.5,
            battery_pct: 80.0,
        });

        assert_eq!(mon.violations().len(), 1);
        assert_eq!(mon.violations()[0].property_name, "score_bounded");
        assert_eq!(mon.statuses()[0].1, PropertyStatus::Violated);
    }

    #[test]
    fn critical_response_satisfied_within_window() {
        let mut mon = Monitor::new();
        mon.add_property(Property::critical_response(3));

        // Trigger: critical alert
        mon.step(&MonitorEvent::Alert {
            severity: "critical".into(),
        });
        // Non-matching stream events don't count down
        mon.step(&MonitorEvent::Sample {
            score: 0.5,
            battery_pct: 90.0,
        });
        // Matching response action
        mon.step(&MonitorEvent::Action {
            kind: "quarantine".into(),
            battery_pct: 80.0,
        });

        assert!(mon.violations().is_empty());
    }

    #[test]
    fn critical_response_violated_timeout() {
        let mut mon = Monitor::new();
        mon.add_property(Property::critical_response(2));

        mon.step(&MonitorEvent::Alert {
            severity: "critical".into(),
        });
        // Two non-matching events on different streams — countdown continues
        mon.step(&MonitorEvent::Sample {
            score: 0.5,
            battery_pct: 90.0,
        });
        mon.step(&MonitorEvent::Sample {
            score: 0.6,
            battery_pct: 89.0,
        });
        // Countdown should have expired
        mon.step(&MonitorEvent::Sample {
            score: 0.7,
            battery_pct: 88.0,
        });

        assert_eq!(mon.violations().len(), 1);
        assert_eq!(mon.violations()[0].property_name, "critical_response");
    }

    #[test]
    fn non_critical_alert_does_not_trigger() {
        let mut mon = Monitor::new();
        mon.add_property(Property::critical_response(2));

        mon.step(&MonitorEvent::Alert {
            severity: "elevated".into(),
        });

        assert!(mon.violations().is_empty());
        assert_eq!(mon.statuses()[0].1, PropertyStatus::Idle);
    }

    #[test]
    fn no_skip_escalation_violated() {
        let mut mon = Monitor::new();
        mon.add_property(Property::no_skip_escalation());

        mon.step(&MonitorEvent::Transition {
            from: "normal".into(),
            to: "critical".into(),
        });

        assert_eq!(mon.violations().len(), 1);
        assert_eq!(mon.violations()[0].property_name, "no_skip_escalation");
    }

    #[test]
    fn no_skip_escalation_satisfied() {
        let mut mon = Monitor::new();
        mon.add_property(Property::no_skip_escalation());

        mon.step(&MonitorEvent::Transition {
            from: "normal".into(),
            to: "elevated".into(),
        });

        assert!(mon.violations().is_empty());
        assert_eq!(mon.statuses()[0].1, PropertyStatus::Satisfied);
    }

    #[test]
    fn multiple_properties_tracked_independently() {
        let mut mon = Monitor::new();
        mon.add_property(Property::score_bounded(1.0));
        mon.add_property(Property::no_skip_escalation());

        mon.step(&MonitorEvent::Sample {
            score: 0.5,
            battery_pct: 90.0,
        });
        mon.step(&MonitorEvent::Transition {
            from: "normal".into(),
            to: "elevated".into(),
        });

        let statuses = mon.statuses();
        assert_eq!(statuses[0].1, PropertyStatus::Satisfied); // score bounded
        assert_eq!(statuses[1].1, PropertyStatus::Satisfied); // no skip
        assert!(mon.violations().is_empty());
    }
}
