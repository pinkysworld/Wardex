//! Digital twin simulation engine.
//!
//! Provides device-state modelling, simulation execution, what-if
//! analysis, and fleet-scale scenario replay.
//! Covers R31 (digital twin simulation).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Device State Model ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DeviceState {
    Normal,
    Degraded,
    UnderAttack,
    Quarantined,
    Offline,
    Recovering,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwinSnapshot {
    pub device_id: String,
    pub state: DeviceState,
    pub cpu_load: f64,
    pub memory_used_mb: f64,
    pub network_tx_kbps: f64,
    pub network_rx_kbps: f64,
    pub open_connections: u32,
    pub processes: u32,
    pub threat_score: f64,
    pub uptime_secs: u64,
    pub custom: HashMap<String, f64>,
}

impl TwinSnapshot {
    pub fn new(device_id: &str) -> Self {
        Self {
            device_id: device_id.to_string(),
            state: DeviceState::Normal,
            cpu_load: 0.0,
            memory_used_mb: 0.0,
            network_tx_kbps: 0.0,
            network_rx_kbps: 0.0,
            open_connections: 0,
            processes: 0,
            threat_score: 0.0,
            uptime_secs: 0,
            custom: HashMap::new(),
        }
    }
}

// ── Simulation Events ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SimEvent {
    CpuSpike { target: String, load: f64 },
    MemoryExhaust { target: String, mb: f64 },
    NetworkFlood { target: String, kbps: f64 },
    MalwareInject { target: String, score: f64 },
    ProcessSpawn { target: String, count: u32 },
    ConnectionBurst { target: String, count: u32 },
    StateChange { target: String, new_state: DeviceState },
    CustomMetric { target: String, key: String, value: f64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimStep {
    pub tick: u64,
    pub events: Vec<SimEvent>,
}

// ── Simulation Engine ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimResult {
    pub ticks_simulated: u64,
    pub final_states: HashMap<String, TwinSnapshot>,
    pub alerts_generated: Vec<SimAlert>,
    pub state_transitions: Vec<StateTransition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimAlert {
    pub tick: u64,
    pub device_id: String,
    pub alert_type: String,
    pub message: String,
    pub severity: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransition {
    pub tick: u64,
    pub device_id: String,
    pub from: DeviceState,
    pub to: DeviceState,
    pub reason: String,
}

#[derive(Debug)]
pub struct DigitalTwinEngine {
    devices: HashMap<String, TwinSnapshot>,
    alert_thresholds: AlertThresholds,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertThresholds {
    pub cpu_critical: f64,
    pub memory_critical_mb: f64,
    pub threat_score_high: f64,
    pub connection_burst: u32,
    pub process_burst: u32,
}

impl Default for AlertThresholds {
    fn default() -> Self {
        Self {
            cpu_critical: 90.0,
            memory_critical_mb: 1500.0,
            threat_score_high: 7.0,
            connection_burst: 100,
            process_burst: 50,
        }
    }
}

impl Default for DigitalTwinEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DigitalTwinEngine {
    pub fn new() -> Self {
        Self {
            devices: HashMap::new(),
            alert_thresholds: AlertThresholds::default(),
        }
    }

    pub fn with_thresholds(thresholds: AlertThresholds) -> Self {
        Self {
            devices: HashMap::new(),
            alert_thresholds: thresholds,
        }
    }

    /// Register a device twin with its initial snapshot.
    pub fn register(&mut self, snapshot: TwinSnapshot) {
        self.devices.insert(snapshot.device_id.clone(), snapshot);
    }

    /// Run a simulation scenario defined as a list of timed steps.
    pub fn simulate(&mut self, scenario: &[SimStep]) -> SimResult {
        let mut alerts = Vec::new();
        let mut transitions = Vec::new();
        let mut max_tick = 0u64;

        for step in scenario {
            max_tick = max_tick.max(step.tick);
            for event in &step.events {
                let (device_id, new_alerts, new_transitions) =
                    self.apply_event(step.tick, event);
                if let Some(id) = device_id {
                    if let Some(dev) = self.devices.get_mut(&id) {
                        dev.uptime_secs = step.tick;
                    }
                }
                alerts.extend(new_alerts);
                transitions.extend(new_transitions);
            }
        }

        SimResult {
            ticks_simulated: max_tick,
            final_states: self.devices.clone(),
            alerts_generated: alerts,
            state_transitions: transitions,
        }
    }

    fn apply_event(
        &mut self,
        tick: u64,
        event: &SimEvent,
    ) -> (Option<String>, Vec<SimAlert>, Vec<StateTransition>) {
        let mut alerts = Vec::new();
        let mut transitions = Vec::new();

        match event {
            SimEvent::CpuSpike { target, load } => {
                if let Some(dev) = self.devices.get_mut(target) {
                    dev.cpu_load = *load;
                    if *load > self.alert_thresholds.cpu_critical {
                        alerts.push(SimAlert {
                            tick,
                            device_id: target.clone(),
                            alert_type: "cpu_critical".into(),
                            message: format!("CPU at {load:.1}%"),
                            severity: load / 10.0,
                        });
                        if dev.state == DeviceState::Normal {
                            transitions.push(StateTransition {
                                tick,
                                device_id: target.clone(),
                                from: DeviceState::Normal,
                                to: DeviceState::Degraded,
                                reason: "CPU overload".into(),
                            });
                            dev.state = DeviceState::Degraded;
                        }
                    }
                }
                return (Some(target.clone()), alerts, transitions);
            }
            SimEvent::MemoryExhaust { target, mb } => {
                if let Some(dev) = self.devices.get_mut(target) {
                    dev.memory_used_mb = *mb;
                    if *mb > self.alert_thresholds.memory_critical_mb {
                        alerts.push(SimAlert {
                            tick,
                            device_id: target.clone(),
                            alert_type: "memory_critical".into(),
                            message: format!("Memory at {mb:.0} MB"),
                            severity: 8.0,
                        });
                    }
                }
                return (Some(target.clone()), alerts, transitions);
            }
            SimEvent::NetworkFlood { target, kbps } => {
                if let Some(dev) = self.devices.get_mut(target) {
                    dev.network_rx_kbps = *kbps;
                }
                return (Some(target.clone()), alerts, transitions);
            }
            SimEvent::MalwareInject { target, score } => {
                if let Some(dev) = self.devices.get_mut(target) {
                    dev.threat_score = *score;
                    if *score > self.alert_thresholds.threat_score_high {
                        let prev = dev.state.clone();
                        dev.state = DeviceState::UnderAttack;
                        transitions.push(StateTransition {
                            tick,
                            device_id: target.clone(),
                            from: prev,
                            to: DeviceState::UnderAttack,
                            reason: format!("Threat score {score:.1}"),
                        });
                        alerts.push(SimAlert {
                            tick,
                            device_id: target.clone(),
                            alert_type: "malware".into(),
                            message: format!("Malware detected, score {score:.1}"),
                            severity: *score,
                        });
                    }
                }
                return (Some(target.clone()), alerts, transitions);
            }
            SimEvent::ProcessSpawn { target, count } => {
                if let Some(dev) = self.devices.get_mut(target) {
                    dev.processes += count;
                    if dev.processes > self.alert_thresholds.process_burst {
                        alerts.push(SimAlert {
                            tick,
                            device_id: target.clone(),
                            alert_type: "process_burst".into(),
                            message: format!("{} processes", dev.processes),
                            severity: 6.0,
                        });
                    }
                }
                return (Some(target.clone()), alerts, transitions);
            }
            SimEvent::ConnectionBurst { target, count } => {
                if let Some(dev) = self.devices.get_mut(target) {
                    dev.open_connections += count;
                    if dev.open_connections > self.alert_thresholds.connection_burst {
                        alerts.push(SimAlert {
                            tick,
                            device_id: target.clone(),
                            alert_type: "connection_burst".into(),
                            message: format!("{} connections", dev.open_connections),
                            severity: 7.0,
                        });
                    }
                }
                return (Some(target.clone()), alerts, transitions);
            }
            SimEvent::StateChange { target, new_state } => {
                if let Some(dev) = self.devices.get_mut(target) {
                    let prev = dev.state.clone();
                    dev.state = new_state.clone();
                    transitions.push(StateTransition {
                        tick,
                        device_id: target.clone(),
                        from: prev,
                        to: new_state.clone(),
                        reason: "manual state change".into(),
                    });
                }
                return (Some(target.clone()), alerts, transitions);
            }
            SimEvent::CustomMetric { target, key, value } => {
                if let Some(dev) = self.devices.get_mut(target) {
                    dev.custom.insert(key.clone(), *value);
                }
                return (Some(target.clone()), alerts, transitions);
            }
        }
    }

    /// What-if analysis: clone current state, run a hypothetical scenario,
    /// return the result without modifying the engine.
    pub fn what_if(&self, scenario: &[SimStep]) -> SimResult {
        let mut clone = DigitalTwinEngine {
            devices: self.devices.clone(),
            alert_thresholds: self.alert_thresholds.clone(),
        };
        clone.simulate(scenario)
    }

    pub fn snapshot(&self, device_id: &str) -> Option<&TwinSnapshot> {
        self.devices.get(device_id)
    }

    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    pub fn all_snapshots(&self) -> &HashMap<String, TwinSnapshot> {
        &self.devices
    }

    /// Calibrate a digital twin from real-world telemetry data.
    /// Adjusts the twin's snapshot to match observed values and returns
    /// a report of how much each parameter drifted.
    pub fn calibrate_from_real(
        &mut self,
        device_id: &str,
        real: &TwinSnapshot,
    ) -> Option<CalibrationReport> {
        let twin = self.devices.get_mut(device_id)?;
        let diffs = vec![
            ("cpu_load".into(), (twin.cpu_load - real.cpu_load).abs()),
            ("memory_used_mb".into(), (twin.memory_used_mb - real.memory_used_mb).abs()),
            ("network_tx_kbps".into(), (twin.network_tx_kbps - real.network_tx_kbps).abs()),
            ("network_rx_kbps".into(), (twin.network_rx_kbps - real.network_rx_kbps).abs()),
            ("threat_score".into(), (twin.threat_score - real.threat_score).abs()),
        ];
        let max_drift = diffs.iter().map(|(_, d)| *d).fold(0.0_f64, f64::max);

        // Apply calibration: snap twin to real values
        twin.cpu_load = real.cpu_load;
        twin.memory_used_mb = real.memory_used_mb;
        twin.network_tx_kbps = real.network_tx_kbps;
        twin.network_rx_kbps = real.network_rx_kbps;
        twin.open_connections = real.open_connections;
        twin.processes = real.processes;
        twin.threat_score = real.threat_score;
        twin.state = real.state.clone();

        Some(CalibrationReport {
            device_id: device_id.to_string(),
            parameter_drifts: diffs,
            max_drift,
            calibrated: true,
        })
    }
}

/// Calibration report showing twin-vs-real drift.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationReport {
    pub device_id: String,
    pub parameter_drifts: Vec<(String, f64)>,
    pub max_drift: f64,
    pub calibrated: bool,
}

// ── Fleet-Scale Simulation ───────────────────────────────────────────────────

/// Run a fleet-scale scenario propagating an attack across multiple devices.
pub fn fleet_attack_simulation(
    engine: &mut DigitalTwinEngine,
    attacker_device: &str,
    neighbours: &[String],
    propagation_probability: f64,
) -> SimResult {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    let mut steps = Vec::new();

    // Tick 1: initial infection
    steps.push(SimStep {
        tick: 1,
        events: vec![SimEvent::MalwareInject {
            target: attacker_device.to_string(),
            score: 9.5,
        }],
    });

    // Ticks 2..N: probabilistic lateral movement
    for (i, neighbour) in neighbours.iter().enumerate() {
        if rng.r#gen::<f64>() < propagation_probability {
            steps.push(SimStep {
                tick: (i + 2) as u64,
                events: vec![SimEvent::MalwareInject {
                    target: neighbour.clone(),
                    score: 7.0 + rng.r#gen::<f64>() * 2.0,
                }],
            });
        }
    }

    engine.simulate(&steps)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_engine() -> DigitalTwinEngine {
        let mut engine = DigitalTwinEngine::new();
        engine.register(TwinSnapshot::new("dev-A"));
        engine.register(TwinSnapshot::new("dev-B"));
        engine
    }

    #[test]
    fn register_and_snapshot() {
        let engine = setup_engine();
        assert_eq!(engine.device_count(), 2);
        assert!(engine.snapshot("dev-A").is_some());
    }

    #[test]
    fn cpu_spike_alert_and_transition() {
        let mut engine = setup_engine();
        let scenario = vec![SimStep {
            tick: 1,
            events: vec![SimEvent::CpuSpike {
                target: "dev-A".into(),
                load: 95.0,
            }],
        }];
        let result = engine.simulate(&scenario);
        assert_eq!(result.alerts_generated.len(), 1);
        assert_eq!(result.state_transitions.len(), 1);
        assert_eq!(
            engine.snapshot("dev-A").unwrap().state,
            DeviceState::Degraded
        );
    }

    #[test]
    fn malware_inject_changes_state() {
        let mut engine = setup_engine();
        let scenario = vec![SimStep {
            tick: 1,
            events: vec![SimEvent::MalwareInject {
                target: "dev-B".into(),
                score: 9.0,
            }],
        }];
        let result = engine.simulate(&scenario);
        assert_eq!(
            result.final_states["dev-B"].state,
            DeviceState::UnderAttack
        );
        assert!(result.alerts_generated.iter().any(|a| a.alert_type == "malware"));
    }

    #[test]
    fn what_if_does_not_modify_engine() {
        let engine = setup_engine();
        let scenario = vec![SimStep {
            tick: 1,
            events: vec![SimEvent::CpuSpike {
                target: "dev-A".into(),
                load: 99.0,
            }],
        }];
        let result = engine.what_if(&scenario);
        assert!(!result.alerts_generated.is_empty());
        // Original engine should be unchanged
        assert_eq!(
            engine.snapshot("dev-A").unwrap().state,
            DeviceState::Normal
        );
    }

    #[test]
    fn multi_step_scenario() {
        let mut engine = setup_engine();
        let scenario = vec![
            SimStep {
                tick: 1,
                events: vec![SimEvent::CpuSpike {
                    target: "dev-A".into(),
                    load: 50.0,
                }],
            },
            SimStep {
                tick: 2,
                events: vec![
                    SimEvent::CpuSpike {
                        target: "dev-A".into(),
                        load: 95.0,
                    },
                    SimEvent::ProcessSpawn {
                        target: "dev-A".into(),
                        count: 60,
                    },
                ],
            },
        ];
        let result = engine.simulate(&scenario);
        assert_eq!(result.ticks_simulated, 2);
        assert!(result.alerts_generated.len() >= 2);
    }

    #[test]
    fn custom_metric_injection() {
        let mut engine = setup_engine();
        let scenario = vec![SimStep {
            tick: 1,
            events: vec![SimEvent::CustomMetric {
                target: "dev-A".into(),
                key: "battery_pct".into(),
                value: 15.0,
            }],
        }];
        engine.simulate(&scenario);
        let snap = engine.snapshot("dev-A").unwrap();
        assert_eq!(snap.custom["battery_pct"], 15.0);
    }

    #[test]
    fn fleet_attack_propagation() {
        let mut engine = DigitalTwinEngine::new();
        for i in 0..5 {
            engine.register(TwinSnapshot::new(&format!("node-{i}")));
        }
        let neighbours: Vec<String> = (1..5).map(|i| format!("node-{i}")).collect();
        let result = fleet_attack_simulation(&mut engine, "node-0", &neighbours, 1.0);
        // With probability 1.0, all neighbours should be attacked
        assert!(result.alerts_generated.len() >= 4);
    }

    #[test]
    fn connection_burst_alert() {
        let mut engine = setup_engine();
        let scenario = vec![SimStep {
            tick: 1,
            events: vec![SimEvent::ConnectionBurst {
                target: "dev-A".into(),
                count: 150,
            }],
        }];
        let result = engine.simulate(&scenario);
        assert!(result.alerts_generated.iter().any(|a| a.alert_type == "connection_burst"));
    }

    #[test]
    fn calibrate_twin_from_real() {
        let mut engine = setup_engine();
        let mut real = TwinSnapshot::new("dev-A");
        real.cpu_load = 42.0;
        real.memory_used_mb = 512.0;
        real.threat_score = 2.5;

        let report = engine.calibrate_from_real("dev-A", &real).unwrap();
        assert!(report.calibrated);
        assert!((engine.snapshot("dev-A").unwrap().cpu_load - 42.0).abs() < 0.01);
        assert!((engine.snapshot("dev-A").unwrap().memory_used_mb - 512.0).abs() < 0.01);
    }
}
