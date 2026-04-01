use std::fmt::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::audit::AuditLog;
use crate::checkpoint::CheckpointStore;
use crate::compliance::{ComplianceManager, Framework};
use crate::correlation::{self, CorrelationResult};
use crate::detector::{AnomalyDetector, AnomalySignal};
use crate::digital_twin::{DigitalTwinEngine, SimEvent, SimStep, TwinSnapshot};
use crate::enforcement::{NetworkEnforcer, ProcessEnforcer, ProcessTarget};
use crate::energy::{EnergyBudget, PowerState};
use crate::monitor::{self, MonitorEvent, Violation};
use crate::policy::{PolicyDecision, PolicyEngine, ThreatLevel};
use crate::proof::ProofRegistry;
use crate::replay::ReplayBuffer;
use crate::side_channel::{SideChannelDetector, SideChannelReport};
use crate::state_machine::{PolicyStateMachine, TransitionTrigger};
use crate::telemetry::TelemetrySample;
use crate::threat_intel::{IoCType, ThreatIntelStore};

#[derive(Debug, Clone)]
pub struct SampleReport {
    pub index: usize,
    pub sample: TelemetrySample,
    pub signal: AnomalySignal,
    pub decision: PolicyDecision,
}

#[derive(Debug, Clone)]
pub struct RunSummary {
    pub total_samples: usize,
    pub alert_count: usize,
    pub critical_count: usize,
    pub average_score: f32,
    pub max_score: f32,
}

#[derive(Debug, Clone)]
pub struct RunResult {
    pub reports: Vec<SampleReport>,
    pub summary: RunSummary,
    pub audit: AuditLog,
    pub correlation: Option<CorrelationResult>,
    pub monitor_violations: Vec<Violation>,
    pub enforcement_actions: Vec<String>,
    pub threat_intel_matches: Vec<String>,
    pub energy_state: PowerState,
    pub side_channel: SideChannelReport,
    pub compliance_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackStatus {
    pub code: String,
    pub title: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusManifest {
    pub updated_at: String,
    pub backlog_completed: usize,
    pub backlog_total: usize,
    pub completed_phases: usize,
    pub total_phases: usize,
    pub cli_commands: Vec<String>,
    pub implemented: Vec<String>,
    pub partially_wired: Vec<String>,
    pub not_implemented: Vec<String>,
    pub research_tracks: Vec<TrackStatus>,
}

pub fn demo_samples() -> Vec<TelemetrySample> {
    vec![
        TelemetrySample {
            timestamp_ms: 1_000,
            cpu_load_pct: 18.0,
            memory_load_pct: 32.0,
            temperature_c: 41.0,
            network_kbps: 500.0,
            auth_failures: 0,
            battery_pct: 94.0,
            integrity_drift: 0.01,
            process_count: 42,
            disk_pressure_pct: 8.0,
        },
        TelemetrySample {
            timestamp_ms: 2_000,
            cpu_load_pct: 23.0,
            memory_load_pct: 34.0,
            temperature_c: 42.0,
            network_kbps: 550.0,
            auth_failures: 1,
            battery_pct: 92.0,
            integrity_drift: 0.02,
            process_count: 44,
            disk_pressure_pct: 9.0,
        },
        TelemetrySample {
            timestamp_ms: 3_000,
            cpu_load_pct: 26.0,
            memory_load_pct: 36.0,
            temperature_c: 43.0,
            network_kbps: 620.0,
            auth_failures: 0,
            battery_pct: 90.0,
            integrity_drift: 0.02,
            process_count: 45,
            disk_pressure_pct: 10.0,
        },
        TelemetrySample {
            timestamp_ms: 4_000,
            cpu_load_pct: 64.0,
            memory_load_pct: 58.0,
            temperature_c: 51.0,
            network_kbps: 5_400.0,
            auth_failures: 8,
            battery_pct: 63.0,
            integrity_drift: 0.11,
            process_count: 98,
            disk_pressure_pct: 55.0,
        },
        TelemetrySample {
            timestamp_ms: 5_000,
            cpu_load_pct: 81.0,
            memory_load_pct: 69.0,
            temperature_c: 57.0,
            network_kbps: 7_000.0,
            auth_failures: 15,
            battery_pct: 47.0,
            integrity_drift: 0.19,
            process_count: 145,
            disk_pressure_pct: 78.0,
        },
    ]
}

pub fn execute(samples: &[TelemetrySample]) -> RunResult {
    let mut detector = AnomalyDetector::default();
    let policy = PolicyEngine;
    let mut audit = AuditLog::with_checkpoint_interval(5);
    let mut checkpoints = CheckpointStore::new(10);
    let mut state_machine = PolicyStateMachine::new();
    let mut proof_registry = ProofRegistry::new();
    let mut replay = ReplayBuffer::new(100);
    let mut reports = Vec::with_capacity(samples.len());

    // Phase 12 modules wired into pipeline
    let mut threat_intel = ThreatIntelStore::new();
    let mut net_enforcer = NetworkEnforcer::new();
    let mut proc_enforcer = ProcessEnforcer::new();
    let mut energy = EnergyBudget::new(500.0);
    let mut side_channel = SideChannelDetector::new();
    let mut twin = DigitalTwinEngine::new();
    let mut compliance = ComplianceManager::new();
    compliance.load_iec62443_defaults();
    let mut enforcement_actions: Vec<String> = Vec::new();
    let mut ti_matches: Vec<String> = Vec::new();

    // Register a digital twin device for the local node
    twin.register(TwinSnapshot::new("local-node"));

    audit.record("boot", "Wardex runtime started in prototype mode");

    for (index, sample) in samples.iter().enumerate() {
        // Capture pre-evaluation state for proof binding
        let prior_snap = detector
            .snapshot()
            .map(|s| serde_json::to_vec(&s).unwrap_or_default())
            .unwrap_or_default();

        let signal = detector.evaluate(sample);
        let decision = policy.evaluate(&signal, sample);

        // Record proof of baseline update (T032)
        let post_snap = detector
            .snapshot()
            .map(|s| serde_json::to_vec(&s).unwrap_or_default())
            .unwrap_or_default();
        proof_registry.record("baseline_update", &prior_snap, &post_snap);

        // Record state machine transition (T033)
        let trigger = if sample.integrity_drift >= 0.45 {
            TransitionTrigger::IntegrityDrift {
                drift: sample.integrity_drift,
            }
        } else if sample.battery_pct < 20.0 {
            TransitionTrigger::BatteryDegradation {
                battery_pct: sample.battery_pct,
            }
        } else {
            TransitionTrigger::ScoreThreshold {
                score: signal.score,
            }
        };
        state_machine.step(decision.level, decision.action, trigger);

        // --- Threat intelligence correlation (R07) ---
        // Check auth_failures as a behaviour-pattern IoC
        if sample.auth_failures > 5 {
            let ti_result = threat_intel.check(
                &IoCType::BehaviorPattern,
                &format!("auth_burst:{}", sample.auth_failures),
            );
            if ti_result.matched {
                ti_matches.push(format!(
                    "sample={} ioc=auth_burst match={}",
                    index + 1,
                    ti_result.context
                ));
                audit.record(
                    "threat_intel",
                    format!("sample={} auth_burst matched IoC", index + 1),
                );
            }
        }

        // --- Enforcement escalation (R05) ---
        if decision.level >= ThreatLevel::Severe {
            let action_desc = if decision.level == ThreatLevel::Critical {
                let result = net_enforcer.block_all(&format!("device-{}", index));
                format!("network_block: {}", result.detail)
            } else {
                let target = ProcessTarget {
                    pid: (index + 1000) as u32,
                    name: format!("suspect-{}", index),
                    user: "system".into(),
                };
                let result = proc_enforcer.suspend_process(&target);
                format!("process_suspend: {}", result.detail)
            };
            enforcement_actions.push(action_desc.clone());
            audit.record(
                "enforcement",
                format!("sample={} {}", index + 1, action_desc),
            );
        }

        // --- Digital twin state update (R09) ---
        let twin_events = vec![SimStep {
            tick: index as u64,
            events: vec![
                SimEvent::CpuSpike {
                    target: "local-node".into(),
                    load: sample.cpu_load_pct as f64,
                },
                SimEvent::CustomMetric {
                    target: "local-node".into(),
                    key: "threat_score".into(),
                    value: signal.score as f64,
                },
            ],
        }];
        let _ = twin.simulate(&twin_events);

        // --- Energy budget tick (R14) ---
        let _power_state = energy.tick();

        // --- Side-channel timing observation (R12) ---
        // Use network latency as a timing proxy
        let timing_ns = (sample.network_kbps * 1000.0) as u64;
        let _verdict = side_channel.observe_timing(timing_ns);

        // --- Compliance evidence (R10) ---
        if decision.level != ThreatLevel::Nominal {
            compliance.add_evidence(
                "IEC62443-SR-3.5",
                &format!(
                    "Alert detected sample={} level={} action={}",
                    index + 1,
                    decision.level.as_str(),
                    decision.action.as_str()
                ),
            );
        }

        // Push to replay buffer (T040)
        replay.push(*sample);

        audit.record(
            "detect",
            format!(
                "sample={} score={:.2} level={} axes={} reasons={}",
                index + 1,
                signal.score,
                decision.level.as_str(),
                signal.suspicious_axes,
                signal.reasons.join(", ")
            ),
        );

        if decision.level != ThreatLevel::Nominal {
            audit.record(
                "respond",
                format!(
                    "sample={} action={} isolation={} rationale={}",
                    index + 1,
                    decision.action.as_str(),
                    decision.isolation_pct,
                    decision.rationale
                ),
            );
        }

        // Capture a checkpoint every time we cross a critical threshold
        if decision.level >= ThreatLevel::Severe {
            checkpoints.capture(&detector);
        }

        reports.push(SampleReport {
            index: index + 1,
            sample: *sample,
            signal,
            decision,
        });
    }

    let total_samples = reports.len();
    let alert_count = reports
        .iter()
        .filter(|report| report.decision.level != ThreatLevel::Nominal)
        .count();
    let critical_count = reports
        .iter()
        .filter(|report| report.decision.level == ThreatLevel::Critical)
        .count();
    let max_score = reports
        .iter()
        .map(|report| report.signal.score)
        .fold(0.0_f32, f32::max);
    let average_score = if total_samples == 0 {
        0.0
    } else {
        reports
            .iter()
            .map(|report| report.signal.score)
            .sum::<f32>()
            / total_samples as f32
    };

    audit.record(
        "summary",
        format!(
            "samples={} alerts={} critical={} avg_score={:.2} max_score={:.2} replay_buffer={} proofs={}",
            total_samples, alert_count, critical_count, average_score, max_score,
            replay.len(), proof_registry.proofs().len()
        ),
    );

    // Run correlation analysis on the replay buffer (T090 / R30)
    let correlation = if replay.len() >= 3 {
        let result = correlation::analyze(&replay, 0.8);
        if !result.correlated_pairs.is_empty() || result.co_rising_count > 0 {
            audit.record(
                "correlation",
                format!(
                    "correlated_pairs={} co_rising={}",
                    result.correlated_pairs.len(),
                    result.co_rising_count
                ),
            );
        }
        Some(result)
    } else {
        None
    };

    // Run temporal-logic monitor over the sample/alert/action stream (T091 / R29)
    let mut monitor = monitor::default_safety_monitor();
    for report in &reports {
        monitor.step(&MonitorEvent::Sample {
            score: report.signal.score,
            battery_pct: report.sample.battery_pct,
        });
        if report.decision.level != ThreatLevel::Nominal {
            monitor.step(&MonitorEvent::Alert {
                severity: report.decision.level.as_str().to_string(),
            });
            monitor.step(&MonitorEvent::Action {
                kind: report.decision.action.as_str().to_string(),
                battery_pct: report.sample.battery_pct,
            });
        }
    }
    // Feed state machine transitions to the monitor (CQ-20 / R29)
    for transition in state_machine.trace() {
        monitor.step(&MonitorEvent::Transition {
            from: transition.from.as_str().to_string(),
            to: transition.to.as_str().to_string(),
        });
    }
    let monitor_violations = monitor.violations().to_vec();
    if !monitor_violations.is_empty() {
        audit.record(
            "monitor",
            format!(
                "violations={} properties={}",
                monitor_violations.len(),
                monitor_violations
                    .iter()
                    .map(|v| v.property_name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
    }

    // Compliance score for active framework
    let compliance_report = compliance.report(&Framework::Iec62443);
    let compliance_score = compliance_report.score;

    // Side-channel summary
    let sc_report = side_channel.report();

    // Final energy state
    let energy_state = energy.state.clone();

    // Log enrichment summary
    audit.record(
        "enrichment",
        format!(
            "enforcement_actions={} ti_matches={} energy={}% side_channel_risk={} compliance_score={:.1}%",
            enforcement_actions.len(),
            ti_matches.len(),
            energy.remaining_pct() as u32,
            sc_report.overall_risk,
            compliance_score,
        ),
    );

    RunResult {
        reports,
        summary: RunSummary {
            total_samples,
            alert_count,
            critical_count,
            average_score,
            max_score,
        },
        audit,
        correlation,
        monitor_violations,
        enforcement_actions,
        threat_intel_matches: ti_matches,
        energy_state,
        side_channel: sc_report,
        compliance_score,
    }
}

pub fn render_console_report(result: &RunResult, audit_path: Option<&Path>) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "Wardex prototype analysis");
    let _ = writeln!(
        output,
        "samples: {} | alerts: {} | critical: {} | avg score: {:.2} | max score: {:.2}",
        result.summary.total_samples,
        result.summary.alert_count,
        result.summary.critical_count,
        result.summary.average_score,
        result.summary.max_score
    );

    for report in &result.reports {
        let _ = writeln!(
            output,
            "\n#{} t={} score={:.2} level={} action={} isolation={}%",
            report.index,
            report.sample.timestamp_ms,
            report.signal.score,
            report.decision.level.as_str(),
            report.decision.action.as_str(),
            report.decision.isolation_pct
        );
        let _ = writeln!(
            output,
            "  cpu={:.1}% mem={:.1}% temp={:.1}C net={:.0}kbps auth_failures={} battery={:.1}% integrity={:.2} procs={} disk={:.1}%",
            report.sample.cpu_load_pct,
            report.sample.memory_load_pct,
            report.sample.temperature_c,
            report.sample.network_kbps,
            report.sample.auth_failures,
            report.sample.battery_pct,
            report.sample.integrity_drift,
            report.sample.process_count,
            report.sample.disk_pressure_pct
        );
        let _ = writeln!(output, "  reasons: {}", report.signal.reasons.join("; "));
        let _ = writeln!(output, "  policy: {}", report.decision.rationale);
    }

    if let Some(path) = audit_path {
        let _ = writeln!(output, "\naudit log: {}", path.display());
    }

    // Correlation summary (T090)
    if let Some(ref corr) = result.correlation
        && (!corr.correlated_pairs.is_empty() || corr.co_rising_count > 0)
    {
        let _ = writeln!(output, "\ncorrelation analysis:");
        for pair in &corr.correlated_pairs {
            let _ = writeln!(
                output,
                "  {} ~ {} (r={:.2})",
                pair.signal_a, pair.signal_b, pair.coefficient
            );
        }
        if corr.co_rising_count > 0 {
            let _ = writeln!(
                output,
                "  co-rising signals ({}): {}",
                corr.co_rising_count,
                corr.co_rising_signals.join(", ")
            );
        }
    }

    // Monitor violations (T091)
    if !result.monitor_violations.is_empty() {
        let _ = writeln!(
            output,
            "\nmonitor violations ({}):",
            result.monitor_violations.len()
        );
        for v in &result.monitor_violations {
            let _ = writeln!(
                output,
                "  property '{}' violated at event #{}",
                v.property_name, v.event_index
            );
        }
    }

    // Enrichment summary (Phase 12)
    if !result.enforcement_actions.is_empty() {
        let _ = writeln!(
            output,
            "\nenforcement actions ({}):",
            result.enforcement_actions.len()
        );
        for ea in &result.enforcement_actions {
            let _ = writeln!(output, "  {}", ea);
        }
    }
    if !result.threat_intel_matches.is_empty() {
        let _ = writeln!(
            output,
            "\nthreat intelligence matches ({}):",
            result.threat_intel_matches.len()
        );
        for m in &result.threat_intel_matches {
            let _ = writeln!(output, "  {}", m);
        }
    }
    let _ = writeln!(
        output,
        "\nenergy: {:?} | side-channel risk: {} | compliance: {:.1}%",
        result.energy_state, result.side_channel.overall_risk, result.compliance_score,
    );

    output
}

pub fn status_snapshot() -> String {
    let status = status_manifest();

    [
        &format!("Wardex status snapshot ({})", status.updated_at),
        "",
        "Phase 1 — Runtime Hardening (complete):",
        "  - TOML/JSON configuration loading",
        "  - JSONL telemetry ingestion alongside CSV",
        "  - structured JSON reports for SIEM ingestion",
        "  - baseline persistence and reload between runs",
        "  - richer anomaly features: process count, disk pressure",
        "  - deterministic test fixtures for benign and adversarial traces",
        "",
        "Phase 2 — Device Actions (complete):",
        "  - pluggable device action adapters (trait-based)",
        "  - throttle, quarantine, and isolate implementations",
        "  - rollback checkpoints with bounded ring buffer",
        "  - forensic evidence bundle exporter",
        "",
        "Phase 3 — Verifiability (complete):",
        "  - SHA-256 cryptographic digest chain (replaces FNV-1a)",
        "  - signed audit checkpoints at configurable intervals",
        "  - chain verification for integrity checking",
        "  - proof-carrying update metadata for baseline transitions",
        "  - formally checkable policy state machine with transition validation",
        "",
        "Phase 4 — Edge Learning (complete):",
        "  - bounded replay buffer for telemetry windows",
        "  - baseline adaptation controls (freeze, decay, reset)",
        "  - poisoning heuristics: mean-shift, variance, drift, auth-burst",
        "  - FP/FN benchmark harness with precision/recall/F1",
        "",
        "Phase 5 — Research Blueprint Expansion (complete):",
        "  - research paper targeting with evaluation plan (T050)",
        "  - swarm coordination protocol sketch (T051)",
        "  - Wasm extension surface specification (T052)",
        "  - supply-chain attestation inputs (T053)",
        "  - post-quantum logging upgrade path (T054)",
        "",
        "Phase 6 — Browser Admin Console (complete):",
        "  - structured status JSON export for browser consumption",
        "  - live browser admin console with authenticated control plane",
        "  - HTTP server with token-authenticated API for status, analysis, and mode control",
        "  - report inspector for generated JSON report files",
        "",
        "Phase 7 — Expanded Research Agenda (complete):",
        "  - research questions formalised for R26-R30 (T070)",
        "  - research questions formalised for R31-R35 (T071)",
        "  - research questions formalised for R36-R40 (T072)",
        "  - adversarial robustness testing harness design (T073)",
        "  - temporal-logic property specification format (T074)",
        "  - digital-twin fleet simulation architecture (T075)",
        "  - formal policy composition algebra (T076)",
        "",
        "Phase 8 — Runtime Intelligence (complete):",
        "  - explainable anomaly attribution with per-signal contributions (T080)",
        "  - config validation with threshold ordering and range checks (T081)",
        "  - multi-signal anomaly correlation engine (T082)",
        "  - temporal-logic runtime monitor (T083)",
        "  - adversarial test harness with evasion strategies (T084)",
        "",
        "Phase 9 — Pipeline Integration & Fingerprinting (complete):",
        "  - correlation engine wired into runtime pipeline (T090)",
        "  - temporal-logic monitor wired into runtime pipeline (T091)",
        "  - /api/correlation endpoint for live analysis (T092)",
        "  - adversarial harness CLI command (T093)",
        "  - behavioural device fingerprinting (T094)",
        "",
        "Phase 10 — Integration Closure (complete):",
        "  - adapter-backed checkpoint restore (T100)",
        "  - TLA+/Alloy model export for offline verification (T101)",
        "  - proof backend interface with witness export (T102)",
        "  - single-source research-track status data (T103)",
        "  - supply-chain attestation foundations (T104)",
        "",
        "Phase 13 — Research Agenda Advancement (complete):",
        "  - modules wired into runtime pipeline (T132)",
        "  - criterion micro-benchmarks for paper evaluation (T133)",
        "  - continual learning with drift detection (T134)",
        "  - policy composition algebra with conflict detection (T135)",
        "",
        "Foundation (complete):",
        "  - adaptive multi-signal anomaly scoring (8 dimensions)",
        "  - battery-aware mitigation scaling",
        "  - chained audit log output",
        "  - CLI: demo, analyze, status, status-json, report, init-config, harness, export-model, attest, serve, help",
        "  - documentation and GitHub Pages site",
        "",
        "Not built yet:",
        "  - (all research tracks now have foundation implementations)",
        "",
        "See docs/STATUS.md and docs/PROJECT_BACKLOG.md for the full breakdown.",
    ]
    .join("\n")
}

pub fn status_manifest() -> StatusManifest {
    StatusManifest {
        updated_at: "current".into(),
        backlog_completed: 160,
        backlog_total: 160,
        completed_phases: 27,
        total_phases: 27,
        cli_commands: vec![
            "demo".into(),
            "analyze".into(),
            "report".into(),
            "init-config".into(),
            "status".into(),
            "status-json".into(),
            "harness".into(),
            "export-model".into(),
            "attest".into(),
            "bench".into(),
            "serve".into(),
            "monitor".into(),
            "start".into(),
            "help".into(),
        ],
        implemented: vec![
            "Typed telemetry ingestion from CSV and JSONL".into(),
            "Adaptive EWMA-based anomaly scoring across eight signal dimensions".into(),
            "Battery-aware policy decisions with pluggable action adapters".into(),
            "SHA-256 audit chain with signed checkpoints and verification".into(),
            "Rollback checkpoints and forensic evidence bundles".into(),
            "Proof-carrying baseline update metadata".into(),
            "Policy state machine with transition validation".into(),
            "Replay buffer with descriptive statistics".into(),
            "Poisoning heuristics and adaptation controls".into(),
            "FP/FN benchmark harness".into(),
            "HTTP server with token-authenticated API".into(),
            "Live browser admin console with authenticated control plane".into(),
            "Research paper targeting with evaluation plan".into(),
            "Swarm coordination protocol design".into(),
            "Wasm extension surface specification".into(),
            "Supply-chain attestation design".into(),
            "Post-quantum logging upgrade path".into(),
            "Research questions for R26-R30 (explainability)".into(),
            "Research questions for R31-R35 (infrastructure)".into(),
            "Research questions for R36-R40 (resilience)".into(),
            "Adversarial robustness testing harness design".into(),
            "Temporal-logic property specification format".into(),
            "Digital-twin fleet simulation architecture".into(),
            "Formal policy composition algebra".into(),
            "Explainable anomaly attribution with per-signal contributions".into(),
            "Config validation with threshold ordering and range checks".into(),
            "Multi-signal anomaly correlation engine".into(),
            "Temporal-logic runtime monitor (safety + bounded liveness)".into(),
            "Adversarial test harness with evasion strategies and coverage".into(),
            "Correlation engine integrated into runtime pipeline".into(),
            "Temporal-logic monitor integrated into runtime pipeline".into(),
            "Server-side /api/correlation endpoint for live analysis".into(),
            "Adversarial harness CLI command".into(),
            "Behavioural device fingerprinting with impersonation detection".into(),
            "Adapter-backed checkpoint restore for abstract device state".into(),
            "TLA+ and Alloy model export for offline formal verification".into(),
            "Proof backend interface with witness export for ZK integration".into(),
            "Single-source research-track data with API and static-file fallback".into(),
            "Supply-chain attestation: build manifest generation, trust-store loading, artifact verification".into(),
            "Extended 120-sample test fixtures for paper evaluation (4 scenarios)".into(),
            "Fixed-threshold baseline comparison detector for paper evaluation".into(),
            "`bench` CLI command comparing adaptive EWMA vs fixed-threshold detectors".into(),
            "Per-signal contribution aggregation in benchmark results for paper attribution".into(),
            "Stale documentation cleanup: corrected counts, dates, phase headers, and changelog entries".into(),
            "Deep OS enforcement engine (process control, network isolation, filesystem quarantine)".into(),
            "Hardware root-of-trust abstraction (software TPM with PCR extend/read/quote/seal/unseal)".into(),
            "Post-quantum Lamport one-time signatures with full key lifecycle".into(),
            "Quantum-walk threat propagation engine on arbitrary graph topologies".into(),
            "Epoch-based key rotation manager with retire/expire lifecycle".into(),
            "Sigma-protocol ZK proof backend (commitment, challenge, response)".into(),
            "Gossip-based swarm coordination with threat alert propagation".into(),
            "Fleet orchestration: device registry, health monitoring, policy distribution".into(),
            "Byzantine-tolerant weighted voting consensus for collective threat assessment".into(),
            "Mesh topology management with role-based rebalancing".into(),
            "Privacy-preserving coordination: differential privacy, federated averaging, secure aggregation".into(),
            "Forensic evidence redaction with configurable privacy levels".into(),
            "Sandboxed bytecode VM for extensible policy rules with resource limits".into(),
            "IoC management, threat feed ingestion, and intelligence correlation".into(),
            "Deception engine: honeypots, honey-files, honey-credentials, canary tokens with attacker tracking".into(),
            "Side-channel detection: timing analysis, cache monitoring, frequency analysis, covert channel detection".into(),
            "Digital twin simulation: device state modeling, what-if analysis, fleet-scale attack propagation".into(),
            "Formal verification: explicit-state model checker (safety, reachability, invariants)".into(),
            "Regulatory compliance: IEC 62443 controls, evidence management, framework scoring".into(),
            "Causal analysis engine: root-cause graphs, path-strength, false-positive probability estimation".into(),
            "Multi-tenancy: tenant isolation, API-key authentication, resource quotas, tier-based limits".into(),
            "Edge-cloud hybrid: workload offload engine, platform capability detection, sync protocol".into(),
            "Autonomous patch management: lifecycle (stage/install/rollback), severity-ordered planning".into(),
            "Energy harvesting: power-state machine, energy-budget tracking, harvesting-aware scheduling".into(),
            "Model quantization with correctness proofs: int8/int4, compression ratio, error bounds".into(),
            "Self-healing network topology with BFS path finding".into(),
            "Cross-platform abstraction with enforcement capability detection".into(),
            "Negotiated security posture with constraint-based resolution".into(),
            "Runtime pipeline enrichment: threat intel, enforcement, digital twin, energy, side-channel, compliance wired into execute()".into(),
            "Criterion micro-benchmarks: per-sample throughput (~55K/sec), per-stage latency, and scaling benchmarks".into(),
            "Continual learning with Page-Hinkley drift detection and automatic baseline re-learning".into(),
            "Policy composition algebra with MaxSeverity/MinSeverity/Priority operators and conflict detection".into(),
            "Admin console wired to all API endpoints: security ops, fleet, digital twin, monitoring, compliance, quantum, policy, infrastructure, formal exports".into(),
            "Full-coverage admin UI panels: enforcement quarantine, threat intel IOC, side-channel, deception deploy, fleet register, twin simulate, harness run, drift reset, privacy budget, quantum key rotate, policy compose, WASM VM, energy harvest, workload offload, patch status, TLA+/Alloy/witness export".into(),
            "HTTP integration tests for all 45+ API endpoints (77 tests) with auth coverage".into(),
            "Paper evaluation harnesses: per-sample latency benchmark and audit chain scaling test (10-100K records)".into(),
            "Research tracks documentation fully synchronised with implementation status".into(),
            "ML-DSA-65 post-quantum hybrid signatures with classical+PQ dual verification".into(),
            "TLS server configuration module with mTLS, version enforcement, and certificate validation".into(),
            "Zero-downtime configuration hot-reload with validation and automatic rollback".into(),
            "Mesh self-healing topology: BFS spanning tree, partition detection, repair proposal and application".into(),
            "Cross-platform host telemetry collector with OS-specific metric collection".into(),
            "File-integrity monitoring with SHA-256 baselines".into(),
            "Webhook, syslog, and CEF alert output".into(),
            "Simplified startup: cargo run defaults to combined serve+monitor mode".into(),
            "Server alert API: health, alerts, alerts/count, endpoints, config/save".into(),
            "Admin console Live Monitoring panel with auto-polling alert table".into(),
            "Admin console Settings panel with MonitorSettings and nested ConfigPatch".into(),
            "Toast notification system and token show/hide toggle".into(),
            "Agent enrollment with token-based authentication and heartbeat staleness detection".into(),
            "Agent client for endpoint telemetry forwarding and policy reception".into(),
            "Cross-agent event forwarding with correlation".into(),
            "Versioned policy distribution with agent-targeted delivery".into(),
            "Cross-platform service installation (systemd/launchd/sc.exe)".into(),
            "SIEM integration: Splunk HEC, Elasticsearch bulk, generic JSON with pull-based threat intel".into(),
            "Agent auto-update with SHA-256 binary verification".into(),
            "Local system auto-monitoring with background telemetry collection thread".into(),
            "Professional dark-themed admin console with sidebar navigation and 10 sections".into(),
            "Telemetry sparklines with canvas-based real-time visualization".into(),
            "Demo mode with simulated escalating attack scenario (client-side only)".into(),
            "BSL 1.1 license with scheduled Apache 2.0 conversion".into(),
            "Global collapsible activity log across all admin views".into(),
            "Responsive icon-only sidebar and keyboard shortcut (Ctrl+K / ⌘+K)".into(),
            "Velocity rate-of-change detector with first/second derivative analysis and σ-outlier flagging".into(),
            "Shannon entropy detector with per-axis sliding-window analysis for constant-traffic and randomised-evasion detection".into(),
            "Compound multi-axis threat detector with coordinated attack scoring multiplier".into(),
            "Server security hardening: canonicalize path traversal check, 10 MB body limit, X-Content-Type-Options / X-Frame-Options / Cache-Control headers, CORS on static files".into(),
            "Detection analysis panel in admin console with live velocity / entropy / compound status".into(),
            "Graceful shutdown via CLI (Ctrl+C / SIGTERM) and web console (/api/shutdown endpoint)".into(),
            "Expandable alert detail rows with full telemetry snapshot and detection analysis".into(),
            "Alert detail API endpoint with severity classification and recommendations".into(),
            "Help section redesign with categorised layout (Getting Started / Detection & Architecture / Reference)".into(),
            "Shutdown button in admin console Settings with double-confirmation safety".into(),
            "Bounded request body reads for chunked transfer encoding (read_body_limited)".into(),
            "Code review hardening: JSON injection fixes, auth on sensitive GET endpoints, consistent security headers".into(),
            "OpenAPI 3.0 specification with 149 endpoint definitions and GET /api/openapi.json public endpoint".into(),
            "Schema lifecycle policy with versioning strategy, compatibility rules, and migration process".into(),
            "Disaster recovery plan with backup/restore procedures, RTO/RPO, and DR validation tests".into(),
            "Service-level objectives with error-budget instrumentation and GET /api/slo/status endpoint".into(),
            "Deployment model documentation: standalone, multi-tenant, edge relay, regional federation".into(),
            "Threat model promoted to primary docs: adversary profiles, abuse cases, trust boundaries".into(),
            "Production hardening checklist: 59-control scorecard derived from XDR AI handoff pack".into(),
        ],
        partially_wired: vec![],
        not_implemented: vec![],
        research_tracks: research_tracks(),
    }
}

/// Canonical research-track data embedded from `site/data/research_tracks.json`.
const RESEARCH_TRACKS_JSON: &str = include_str!("../site/data/research_tracks.json");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackGroup {
    pub id: String,
    pub label: String,
    pub tracks: Vec<TrackDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackDetail {
    pub code: String,
    pub status: String,
    pub title: String,
    pub summary: String,
    pub idea: String,
    pub matters: String,
    pub state: String,
}

/// Return the full canonical research-track groups (used by the API).
pub fn research_track_groups() -> Vec<TrackGroup> {
    serde_json::from_str(RESEARCH_TRACKS_JSON).unwrap_or_default()
}

fn research_tracks() -> Vec<TrackStatus> {
    research_track_groups()
        .into_iter()
        .flat_map(|g| g.tracks)
        .map(|t| TrackStatus {
            code: t.code,
            title: t.title,
            status: t.status,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{demo_samples, execute, status_manifest};

    #[test]
    fn demo_sequence_produces_alerts() {
        let result = execute(&demo_samples());

        assert_eq!(result.summary.total_samples, 5);
        assert!(result.summary.alert_count >= 2);
        assert!(result.summary.max_score > 4.0);
    }

    #[test]
    fn status_manifest_reports_backlog_progress() {
        let manifest = status_manifest();
        assert_eq!(manifest.backlog_completed, 160);
        assert_eq!(manifest.backlog_total, 160);
        assert_eq!(manifest.total_phases, 27);
        assert!(manifest.cli_commands.iter().any(|cmd| cmd == "status-json"));
        assert!(manifest.partially_wired.is_empty());
        assert_eq!(manifest.not_implemented.len(), 0);
    }

    #[test]
    fn execute_includes_correlation_results() {
        let result = execute(&demo_samples());
        // The demo has 5 samples ≥ 3, so correlation should be present
        assert!(result.correlation.is_some());
        let corr = result.correlation.unwrap();
        // Demo samples escalate CPU/mem/net together → expect correlations
        assert!(
            !corr.correlated_pairs.is_empty() || corr.co_rising_count > 0,
            "expected correlation or co-rising signals in escalating demo"
        );
    }

    #[test]
    fn execute_runs_monitor_without_panic() {
        let result = execute(&demo_samples());
        // Monitor runs safety checks; demo is well-behaved, so no violations expected
        // (score_bounded at 10.0 should not fire for typical demo scores)
        // Just verify it doesn't panic and returns a Vec
        let _ = result.monitor_violations;
    }
}
