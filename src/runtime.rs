use std::fmt::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::audit::AuditLog;
use crate::checkpoint::CheckpointStore;
use crate::detector::{AnomalyDetector, AnomalySignal};
use crate::policy::{PolicyDecision, PolicyEngine, ThreatLevel};
use crate::proof::ProofRegistry;
use crate::replay::ReplayBuffer;
use crate::state_machine::{PolicyStateMachine, TransitionTrigger};
use crate::telemetry::TelemetrySample;

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

    audit.record("boot", "SentinelEdge runtime started in prototype mode");

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
    }
}

pub fn render_console_report(result: &RunResult, audit_path: Option<&Path>) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "SentinelEdge prototype analysis");
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

    output
}

pub fn status_snapshot() -> String {
    let status = status_manifest();

    [
        &format!("SentinelEdge status snapshot ({})", status.updated_at),
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
        "Foundation (complete):",
        "  - adaptive multi-signal anomaly scoring (8 dimensions)",
        "  - battery-aware mitigation scaling",
        "  - chained audit log output",
        "  - CLI: demo, analyze, status, report, init-config, serve",
        "  - documentation and GitHub Pages site",
        "",
        "Not built yet:",
        "  - continual learning and privacy-preserving updates",
        "  - zero-knowledge proofs and formal verification",
        "  - swarm coordination and post-quantum cryptography",
        "",
        "See docs/STATUS.md and docs/PROJECT_BACKLOG.md for the full breakdown.",
    ]
    .join("\n")
}

pub fn status_manifest() -> StatusManifest {
    StatusManifest {
        updated_at: "2026-03-12".into(),
        backlog_completed: 41,
        backlog_total: 41,
        completed_phases: 8,
        total_phases: 8,
        cli_commands: vec![
            "demo".into(),
            "analyze".into(),
            "report".into(),
            "init-config".into(),
            "status".into(),
            "status-json".into(),
            "serve".into(),
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
        ],
        partially_wired: vec![
            "Checkpoint restore semantics without real device-state restoration".into(),
            "ZK proof placeholder in proof metadata".into(),
            "TLA+/Alloy export path for the state machine".into(),
        ],
        not_implemented: vec![
            "Continual learning and privacy-preserving updates".into(),
            "Zero-knowledge proofs and formal verification export".into(),
            "Swarm coordination and cross-device protocols".into(),
            "Post-quantum signatures and hardware roots of trust".into(),
            "Explainability, adversarial robustness, temporal-logic monitoring".into(),
            "Digital twin simulation, deception, multi-tenancy, side-channel detection".into(),
            "Edge-cloud offload, mesh self-organisation, device fingerprinting".into(),
            "Policy composition, privacy-preserving forensics".into(),
        ],
    }
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
        assert_eq!(manifest.backlog_completed, 41);
        assert_eq!(manifest.backlog_total, 41);
        assert!(manifest.cli_commands.iter().any(|cmd| cmd == "status-json"));
    }
}
