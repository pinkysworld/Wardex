use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tiny_http::{Header, Method, Request, Response, Server};

use crate::actions::DeviceController;
use crate::checkpoint::CheckpointStore;
use crate::compliance::{ComplianceManager, CausalGraph};
use crate::correlation;
use crate::detector::{AdaptationMode, AnomalyDetector, DriftDetector};
use crate::digital_twin::DigitalTwinEngine;
use crate::edge_cloud::{PlatformCapabilities, PatchManager};
use crate::enforcement::EnforcementEngine;
use crate::energy::EnergyBudget;
use crate::fingerprint::DeviceFingerprint;
use crate::monitor::Monitor;
use crate::multi_tenant::MultiTenantManager;
use crate::privacy::PrivacyAccountant;
use crate::proof::{DigestBackend, ProofRegistry};
use crate::quantum::KeyRotationManager;
use crate::replay::ReplayBuffer;
use crate::report::JsonReport;
use crate::runtime;
use crate::side_channel::SideChannelDetector;
use crate::state_machine::PolicyStateMachine;
use crate::swarm::{DeviceRecord, DeviceStatus, SwarmNode};
use crate::telemetry::TelemetrySample;
use crate::threat_intel::{DeceptionEngine, ThreatIntelStore};
use crate::wasm_engine::PolicyVm;

struct AppState {
    detector: AnomalyDetector,
    checkpoints: CheckpointStore,
    device: DeviceController,
    replay: ReplayBuffer,
    proofs: ProofRegistry,
    last_report: Option<JsonReport>,
    token: String,
    swarm: SwarmNode,
    enforcement: EnforcementEngine,
    threat_intel: ThreatIntelStore,
    digital_twin: DigitalTwinEngine,
    compliance: ComplianceManager,
    multi_tenant: MultiTenantManager,
    energy: EnergyBudget,
    side_channel: SideChannelDetector,
    key_rotation: KeyRotationManager,
    privacy: PrivacyAccountant,
    policy_vm: PolicyVm,
    fingerprint: Option<DeviceFingerprint>,
    monitor: Monitor,
    drift: DriftDetector,
    deception: DeceptionEngine,
    patches: PatchManager,
    causal: CausalGraph,
}

pub fn run_server(port: u16, site_dir: &Path) -> Result<(), String> {
    let addr = format!("0.0.0.0:{port}");
    let server = Server::http(&addr).map_err(|e| format!("failed to start server: {e}"))?;

    let token = generate_token();
    println!("SentinelEdge admin console");
    println!("  Listening on http://localhost:{port}");
    println!("  Site directory: {}", site_dir.display());
    println!("  Auth token: {token}");
    println!("  Press Ctrl+C to stop");

    let state = Arc::new(Mutex::new(AppState {
        detector: AnomalyDetector::default(),
        checkpoints: CheckpointStore::new(10),
        device: DeviceController::default(),
        replay: ReplayBuffer::new(200),
        proofs: ProofRegistry::new(),
        last_report: None,
        token: token.clone(),
        swarm: SwarmNode::new("gateway-0"),
        enforcement: EnforcementEngine::new(),
        threat_intel: ThreatIntelStore::new(),
        digital_twin: DigitalTwinEngine::new(),
        compliance: ComplianceManager::new(),
        multi_tenant: MultiTenantManager::new(),
        energy: EnergyBudget::new(500.0),
        side_channel: SideChannelDetector::new(),
        key_rotation: KeyRotationManager::new(3600),
        privacy: PrivacyAccountant::new(10.0),
        policy_vm: PolicyVm::default(),
        fingerprint: None,
        monitor: Monitor::new(),
        drift: DriftDetector::new(0.005, 50.0),
        deception: DeceptionEngine::new(),
        patches: PatchManager::new(),
        causal: CausalGraph::new(),
    }));

    let site_dir = site_dir.to_path_buf();

    serve_loop(&server, &state, &site_dir);

    Ok(())
}

/// Spawn a test server on a random port. Returns `(port, token)`.
/// The server runs in a background thread.
#[doc(hidden)]
pub fn spawn_test_server() -> (u16, String) {
    let server = Server::http("127.0.0.1:0").expect("bind test server");
    let port = server.server_addr().to_ip().expect("ip addr").port();
    let token = generate_token();
    let state = Arc::new(Mutex::new(AppState {
        detector: AnomalyDetector::default(),
        checkpoints: CheckpointStore::new(10),
        device: DeviceController::default(),
        replay: ReplayBuffer::new(200),
        proofs: ProofRegistry::new(),
        last_report: None,
        token: token.clone(),
        swarm: SwarmNode::new("test-node-0"),
        enforcement: EnforcementEngine::new(),
        threat_intel: ThreatIntelStore::new(),
        digital_twin: DigitalTwinEngine::new(),
        compliance: ComplianceManager::new(),
        multi_tenant: MultiTenantManager::new(),
        energy: EnergyBudget::new(500.0),
        side_channel: SideChannelDetector::new(),
        key_rotation: KeyRotationManager::new(3600),
        privacy: PrivacyAccountant::new(10.0),
        policy_vm: PolicyVm::default(),
        fingerprint: None,
        monitor: Monitor::new(),
        drift: DriftDetector::new(0.005, 50.0),
        deception: DeceptionEngine::new(),
        patches: PatchManager::new(),
        causal: CausalGraph::new(),
    }));
    let site_dir = PathBuf::from("site");
    std::thread::spawn(move || {
        serve_loop(&server, &state, &site_dir);
    });
    (port, token)
}

fn serve_loop(server: &Server, state: &Arc<Mutex<AppState>>, site_dir: &Path) {
    for request in server.incoming_requests() {
        let url = request.url().to_string();

        if url.starts_with("/api/") {
            handle_api(request, state, site_dir);
        } else {
            serve_static(request, site_dir);
        }
    }
}

fn generate_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.r#gen()).collect();
    hex::encode(bytes)
}

fn json_response(body: &str, status: u16) -> Response<std::io::Cursor<Vec<u8>>> {
    let data = body.as_bytes().to_vec();
    let len = data.len();
    Response::new(
        tiny_http::StatusCode(status),
        vec![
            Header::from_bytes(b"Content-Type", b"application/json").unwrap(),
            Header::from_bytes(b"Access-Control-Allow-Origin", b"http://localhost").unwrap(),
            Header::from_bytes(b"Vary", b"Origin").unwrap(),
        ],
        std::io::Cursor::new(data),
        Some(len),
        None,
    )
}

fn error_json(message: &str, status: u16) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = format!(r#"{{"error":"{}"}}"#, message.replace('"', "\\\""));
    json_response(&body, status)
}

fn text_response(body: &str, status: u16) -> Response<std::io::Cursor<Vec<u8>>> {
    let data = body.as_bytes().to_vec();
    let len = data.len();
    Response::new(
        tiny_http::StatusCode(status),
        vec![
            Header::from_bytes(b"Content-Type", b"text/plain; charset=utf-8").unwrap(),
            Header::from_bytes(b"Access-Control-Allow-Origin", b"http://localhost").unwrap(),
            Header::from_bytes(b"Vary", b"Origin").unwrap(),
        ],
        std::io::Cursor::new(data),
        Some(len),
        None,
    )
}

fn check_auth(request: &Request, state: &Arc<Mutex<AppState>>) -> bool {
    let state = state.lock().unwrap();
    for header in request.headers() {
        if header
            .field
            .as_str()
            .as_str()
            .eq_ignore_ascii_case("authorization")
        {
            let val = header.value.as_str();
            if let Some(token) = val.strip_prefix("Bearer ") {
                return token.trim() == state.token;
            }
        }
    }
    false
}

fn handle_api(mut request: Request, state: &Arc<Mutex<AppState>>, _site_dir: &Path) {
    let url = request.url().to_string();
    let method = request.method().clone();

    // Check auth for mutating endpoints before consuming the request body
    let needs_auth = matches!(
        (&method, url.as_str()),
        (Method::Get, "/api/auth/check")
            | (Method::Post, "/api/analyze")
            | (Method::Post, "/api/control/mode")
            | (Method::Post, "/api/control/reset-baseline")
            | (Method::Post, "/api/control/run-demo")
            | (Method::Post, "/api/control/checkpoint")
            | (Method::Post, "/api/control/restore-checkpoint")
            | (Method::Post, "/api/fleet/register")
            | (Method::Post, "/api/enforcement/quarantine")
            | (Method::Post, "/api/threat-intel/ioc")
            | (Method::Post, "/api/digital-twin/simulate")
            | (Method::Post, "/api/energy/consume")
            | (Method::Post, "/api/quantum/rotate")
            | (Method::Post, "/api/policy-vm/execute")
            | (Method::Post, "/api/harness/run")
            | (Method::Post, "/api/deception/deploy")
            | (Method::Post, "/api/policy/compose")
            | (Method::Post, "/api/drift/reset")
            | (Method::Post, "/api/offload/decide")
            | (Method::Post, "/api/energy/harvest")
    );

    if needs_auth && !check_auth(&request, state) {
        let _ = request.respond(error_json("unauthorized", 401));
        return;
    }

    let response = match (method, url.as_str()) {
        (Method::Get, "/api/auth/check") => json_response(r#"{"status":"ok"}"#, 200),
        (Method::Get, "/api/status") => {
            let manifest = runtime::status_manifest();
            match serde_json::to_string_pretty(&manifest) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/report") => {
            let s = state.lock().unwrap();
            if let Some(ref report) = s.last_report {
                match serde_json::to_string_pretty(report) {
                    Ok(json) => json_response(&json, 200),
                    Err(e) => error_json(&format!("serialization error: {e}"), 500),
                }
            } else {
                drop(s);
                let result = runtime::execute(&runtime::demo_samples());
                let report = JsonReport::from_run_result(&result);
                match serde_json::to_string_pretty(&report) {
                    Ok(json) => {
                        state.lock().unwrap().last_report = Some(report);
                        json_response(&json, 200)
                    }
                    Err(e) => error_json(&format!("serialization error: {e}"), 500),
                }
            }
        }
        (Method::Post, "/api/analyze") => handle_analyze(&mut request, state),
        (Method::Post, "/api/control/mode") => handle_mode(&mut request, state),
        (Method::Post, "/api/control/reset-baseline") => {
            let mut s = state.lock().unwrap();
            s.detector.reset_baseline();
            json_response(r#"{"status":"baseline reset"}"#, 200)
        }
        (Method::Post, "/api/control/checkpoint") => {
            let mut s = state.lock().unwrap();
            if let Some(snapshot) = s.detector.snapshot() {
                let device_state = s.device.snapshot();
                s.checkpoints.push_snapshot(snapshot, device_state);
            }
            let count = s.checkpoints.len();
            json_response(
                &format!(r#"{{"status":"checkpoint saved","total":{count}}}"#),
                200,
            )
        }
        (Method::Post, "/api/control/restore-checkpoint") => {
            let mut s = state.lock().unwrap();
            let restored = s.checkpoints.latest().cloned().map(|entry| {
                s.detector.restore_baseline(&entry.baseline);
                let action_results = s.device.restore_snapshot(&entry.device_state);
                serde_json::json!({
                    "status": "checkpoint restored",
                    "baseline_restored": true,
                    "device_state": entry.device_state,
                    "actions": action_results,
                })
            });
            if let Some(body) = restored {
                json_response(&body.to_string(), 200)
            } else {
                error_json("no checkpoints available", 404)
            }
        }
        (Method::Get, "/api/checkpoints") => {
            let s = state.lock().unwrap();
            let info = serde_json::json!({
                "count": s.checkpoints.len(),
                "timestamps": s.checkpoints.entries().iter()
                    .map(|e| e.timestamp_ms)
                    .collect::<Vec<_>>(),
                "device_states": s.checkpoints.entries().iter()
                    .map(|e| e.device_state.clone())
                    .collect::<Vec<_>>(),
            });
            json_response(&info.to_string(), 200)
        }
        (Method::Get, "/api/correlation") => {
            let s = state.lock().unwrap();
            let result = correlation::analyze(&s.replay, 0.8);
            match serde_json::to_string_pretty(&result) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/export/tla") => {
            let sm = PolicyStateMachine::new();
            text_response(&sm.export_tla(), 200)
        }
        (Method::Get, "/api/export/alloy") => {
            let sm = PolicyStateMachine::new();
            text_response(&sm.export_alloy(), 200)
        }
        (Method::Get, "/api/export/witnesses") => {
            let s = state.lock().unwrap();
            let json = s.proofs.export_witnesses_json(&DigestBackend);
            json_response(&json, 200)
        }
        (Method::Get, "/api/research-tracks") => {
            let groups = runtime::research_track_groups();
            match serde_json::to_string_pretty(&groups) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/attestation/status") => {
            let summary = crate::attestation::VerificationResult {
                passed: false,
                checks: vec![crate::attestation::CheckResult {
                    name: "attestation_loaded".into(),
                    passed: false,
                    detail: "no manifest loaded; use the attest CLI to generate one".into(),
                }],
            };
            match serde_json::to_string_pretty(&summary) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Post, "/api/control/run-demo") => {
            let demo = runtime::demo_samples();
            let result = runtime::execute(&demo);
            let report = JsonReport::from_run_result(&result);
            match serde_json::to_string_pretty(&report) {
                Ok(json) => {
                    let mut s = state.lock().unwrap();
                    for (sample, report) in demo.iter().zip(result.reports.iter()) {
                        let pre = s
                            .detector
                            .snapshot()
                            .map(|snap| serde_json::to_vec(&snap).unwrap_or_default())
                            .unwrap_or_default();
                        s.detector.evaluate(sample);
                        let post = s
                            .detector
                            .snapshot()
                            .map(|snap| serde_json::to_vec(&snap).unwrap_or_default())
                            .unwrap_or_default();
                        s.proofs.record("baseline_update", &pre, &post);
                        s.device.apply_decision(&report.decision);
                        s.replay.push(*sample);
                    }
                    s.last_report = Some(report);
                    drop(s);
                    json_response(&json, 200)
                }
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }

        // ── Fleet / Swarm ─────────────────────────────────────────
        (Method::Get, "/api/fleet/status") => {
            let s = state.lock().unwrap();
            let report = s.swarm.health_report();
            match serde_json::to_string_pretty(&report) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Post, "/api/fleet/register") => {
            handle_fleet_register(&mut request, state)
        }

        // ── Enforcement ───────────────────────────────────────────
        (Method::Get, "/api/enforcement/status") => {
            let s = state.lock().unwrap();
            let tpm_status = s.enforcement.tpm.status();
            let info = serde_json::json!({
                "process_enforcer": "active",
                "network_enforcer": "active",
                "filesystem_enforcer": "active",
                "tpm": tpm_status,
                "topology_nodes": s.enforcement.topology.nodes.len(),
                "history_len": s.enforcement.history().len(),
            });
            json_response(&info.to_string(), 200)
        }
        (Method::Post, "/api/enforcement/quarantine") => {
            handle_enforcement_quarantine(&mut request, state)
        }

        // ── Threat Intelligence ───────────────────────────────────
        (Method::Get, "/api/threat-intel/status") => {
            let s = state.lock().unwrap();
            let info = serde_json::json!({
                "ioc_count": s.threat_intel.ioc_count(),
            });
            json_response(&info.to_string(), 200)
        }
        (Method::Post, "/api/threat-intel/ioc") => {
            handle_threat_intel_ioc(&mut request, state)
        }

        // ── Digital Twin ──────────────────────────────────────────
        (Method::Get, "/api/digital-twin/status") => {
            let s = state.lock().unwrap();
            let info = serde_json::json!({
                "twin_count": s.digital_twin.device_count(),
            });
            json_response(&info.to_string(), 200)
        }
        (Method::Post, "/api/digital-twin/simulate") => {
            handle_digital_twin_simulate(&mut request, state)
        }

        // ── Compliance ────────────────────────────────────────────
        (Method::Get, "/api/compliance/status") => {
            let s = state.lock().unwrap();
            let report = s.compliance.report(&crate::compliance::Framework::Iec62443);
            match serde_json::to_string_pretty(&report) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }

        // ── Energy ────────────────────────────────────────────────
        (Method::Get, "/api/energy/status") => {
            let s = state.lock().unwrap();
            let info = serde_json::json!({
                "remaining_pct": s.energy.remaining_pct(),
                "capacity_mwh": s.energy.capacity_mwh,
                "current_mwh": s.energy.current_mwh,
                "power_state": format!("{:?}", s.energy.state),
            });
            json_response(&info.to_string(), 200)
        }
        (Method::Post, "/api/energy/consume") => {
            handle_energy_consume(&mut request, state)
        }

        // ── Multi-tenancy ─────────────────────────────────────────
        (Method::Get, "/api/tenants/count") => {
            let s = state.lock().unwrap();
            let info = serde_json::json!({
                "tenant_count": s.multi_tenant.tenant_count(),
            });
            json_response(&info.to_string(), 200)
        }

        // ── Platform ──────────────────────────────────────────────
        (Method::Get, "/api/platform") => {
            let caps = PlatformCapabilities::detect_current();
            let info = serde_json::json!({
                "platform": format!("{:?}", caps.platform),
                "has_tpm": caps.has_tpm,
                "has_seccomp": caps.has_seccomp,
                "has_ebpf": caps.has_ebpf,
                "has_firewall": caps.has_firewall,
                "max_threads": caps.max_threads,
            });
            json_response(&info.to_string(), 200)
        }

        // ── Side-Channel Detection ────────────────────────────────
        (Method::Get, "/api/side-channel/status") => {
            let s = state.lock().unwrap();
            let report = s.side_channel.report();
            let info = serde_json::json!({
                "timing_anomalies": report.timing_anomalies,
                "cache_alerts": report.cache_alerts,
                "covert_channels": report.covert_channels,
                "overall_risk": report.overall_risk,
            });
            json_response(&info.to_string(), 200)
        }

        // ── Quantum / Post-Quantum ────────────────────────────────
        (Method::Get, "/api/quantum/key-status") => {
            let s = state.lock().unwrap();
            let info = serde_json::json!({
                "current_epoch": s.key_rotation.current_epoch(),
                "total_epochs": s.key_rotation.epochs().len(),
            });
            json_response(&info.to_string(), 200)
        }
        (Method::Post, "/api/quantum/rotate") => {
            let mut s = state.lock().unwrap();
            s.key_rotation.rotate();
            let info = serde_json::json!({
                "status": "rotated",
                "new_epoch": s.key_rotation.current_epoch(),
            });
            json_response(&info.to_string(), 200)
        }

        // ── Privacy ───────────────────────────────────────────────
        (Method::Get, "/api/privacy/budget") => {
            let s = state.lock().unwrap();
            let info = serde_json::json!({
                "budget_remaining": s.privacy.budget_remaining(),
                "is_exhausted": s.privacy.is_exhausted(),
            });
            json_response(&info.to_string(), 200)
        }

        // ── Policy VM ─────────────────────────────────────────────
        (Method::Post, "/api/policy-vm/execute") => {
            handle_policy_vm_execute(&mut request, state)
        }

        // ── Fingerprint ───────────────────────────────────────────
        (Method::Get, "/api/fingerprint/status") => {
            let s = state.lock().unwrap();
            let info = serde_json::json!({
                "trained": s.fingerprint.is_some(),
                "replay_samples": s.replay.len(),
            });
            json_response(&info.to_string(), 200)
        }

        // ── Adversarial Harness ───────────────────────────────────
        (Method::Post, "/api/harness/run") => {
            let config = crate::harness::HarnessConfig::default();
            let result = crate::harness::run(&config);
            let info = serde_json::json!({
                "evasion_rate": result.evasion_rate,
                "coverage_ratio": result.coverage.coverage_ratio(),
                "total_count": result.total_count,
                "evasion_count": result.evasion_count,
            });
            json_response(&info.to_string(), 200)
        }

        // ── Temporal-Logic Monitor ────────────────────────────────
        (Method::Get, "/api/monitor/status") => {
            let s = state.lock().unwrap();
            let statuses: Vec<_> = s.monitor.statuses().iter().map(|(name, status)| {
                serde_json::json!({ "name": name, "status": format!("{:?}", status) })
            }).collect();
            let info = serde_json::json!({
                "properties": statuses,
                "violation_count": s.monitor.violations().len(),
            });
            json_response(&info.to_string(), 200)
        }
        (Method::Get, "/api/monitor/violations") => {
            let s = state.lock().unwrap();
            let violations: Vec<_> = s.monitor.violations().iter().map(|v| {
                serde_json::json!({
                    "property": v.property_name,
                    "event_index": v.event_index,
                })
            }).collect();
            json_response(&serde_json::json!({ "violations": violations }).to_string(), 200)
        }

        // ── Deception Engine ──────────────────────────────────────
        (Method::Get, "/api/deception/status") => {
            let s = state.lock().unwrap();
            let report = s.deception.report();
            let info = serde_json::json!({
                "total_decoys": report.total_decoys,
                "active_decoys": report.active_decoys,
                "total_interactions": report.total_interactions,
                "attacker_profiles": report.attacker_profiles,
            });
            json_response(&info.to_string(), 200)
        }
        (Method::Post, "/api/deception/deploy") => {
            handle_deception_deploy(&mut request, state)
        }

        // ── Policy Composition ────────────────────────────────────
        (Method::Post, "/api/policy/compose") => {
            handle_policy_compose(&mut request, state)
        }

        // ── Drift Detection ───────────────────────────────────────
        (Method::Get, "/api/drift/status") => {
            let s = state.lock().unwrap();
            let info = serde_json::json!({
                "sample_count": s.drift.sample_count(),
            });
            json_response(&info.to_string(), 200)
        }
        (Method::Post, "/api/drift/reset") => {
            let mut s = state.lock().unwrap();
            s.drift.reset();
            json_response(r#"{"status":"drift detector reset"}"#, 200)
        }

        // ── Causal Analysis ───────────────────────────────────────
        (Method::Get, "/api/causal/graph") => {
            let s = state.lock().unwrap();
            let info = serde_json::json!({
                "node_count": s.causal.node_count(),
                "edge_count": s.causal.edge_count(),
            });
            json_response(&info.to_string(), 200)
        }

        // ── Patch Management ──────────────────────────────────────
        (Method::Get, "/api/patches") => {
            let s = state.lock().unwrap();
            let plan = s.patches.plan();
            let info = serde_json::json!({
                "total_patches": s.patches.patch_count(),
                "installed": s.patches.installed_count(),
                "patches_in_plan": plan.patches.len(),
                "estimated_downtime_secs": plan.estimated_downtime_secs,
            });
            json_response(&info.to_string(), 200)
        }

        // ── Workload Offload ──────────────────────────────────────
        (Method::Post, "/api/offload/decide") => {
            let caps = PlatformCapabilities::detect_current();
            let edge_cap = crate::edge_cloud::EdgeCapacity {
                cpu_available: 60.0,
                memory_available_mb: 512,
                bandwidth_kbps: 1000,
                latency_to_cloud_ms: 50,
            };
            let workloads = vec![
                crate::edge_cloud::Workload { id: "w1".into(), name: "detection".into(), cpu_cost: 20.0, memory_mb: 64, latency_sensitive: true, data_size_kb: 100, tier: crate::edge_cloud::ProcessingTier::EdgePreferred },
                crate::edge_cloud::Workload { id: "w2".into(), name: "reporting".into(), cpu_cost: 10.0, memory_mb: 32, latency_sensitive: false, data_size_kb: 200, tier: crate::edge_cloud::ProcessingTier::CloudPreferred },
            ];
            let decisions = crate::edge_cloud::decide_offload(&workloads, &edge_cap);
            let info: Vec<_> = decisions.iter().map(|d| serde_json::json!({
                "workload": d.workload_id,
                "run_on": d.run_on,
                "reason": d.reason,
                "estimated_latency_ms": d.estimated_latency_ms,
            })).collect();
            json_response(&serde_json::json!({ "decisions": info, "platform": format!("{:?}", caps.platform) }).to_string(), 200)
        }

        // ── Swarm Posture ─────────────────────────────────────────
        (Method::Get, "/api/swarm/posture") => {
            let info = serde_json::json!({
                "current_posture": "standard",
                "negotiation_available": true,
            });
            json_response(&info.to_string(), 200)
        }

        // ── Energy Harvesting ─────────────────────────────────────
        (Method::Post, "/api/energy/harvest") => {
            let mut s = state.lock().unwrap();
            let recharged = s.energy.capacity_mwh * 0.05;
            s.energy.current_mwh = (s.energy.current_mwh + recharged).min(s.energy.capacity_mwh);
            let info = serde_json::json!({
                "status": "harvested",
                "recharged_mwh": recharged,
                "remaining_pct": s.energy.remaining_pct(),
            });
            json_response(&info.to_string(), 200)
        }
        (Method::Options, _) => {
            let data: Vec<u8> = Vec::new();
            Response::new(
                tiny_http::StatusCode(204),
                vec![
                    Header::from_bytes(b"Access-Control-Allow-Origin", b"http://localhost")
                        .unwrap(),
                    Header::from_bytes(b"Vary", b"Origin").unwrap(),
                    Header::from_bytes(b"Access-Control-Allow-Methods", b"GET, POST, OPTIONS")
                        .unwrap(),
                    Header::from_bytes(
                        b"Access-Control-Allow-Headers",
                        b"Content-Type, Authorization",
                    )
                    .unwrap(),
                ],
                std::io::Cursor::new(data),
                Some(0),
                None,
            )
        }
        _ => error_json("not found", 404),
    };

    let _ = request.respond(response);
}

fn handle_analyze(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut body = String::new();
    if std::io::Read::read_to_string(request.as_reader(), &mut body).is_err() {
        return error_json("failed to read request body", 400);
    }

    // Detect format: if the content-type says CSV or the body looks like CSV, parse as CSV
    let is_csv = request.headers().iter().any(|h| {
        h.field.as_str().to_ascii_lowercase() == "content-type" && h.value.as_str().contains("csv")
    }) || (!body.trim_start().starts_with('{') && body.contains(','));

    let samples: Result<Vec<TelemetrySample>, String> = if is_csv {
        // CSV: skip known header rows, parse each data line
        use crate::telemetry::{CSV_HEADER, CSV_HEADER_LEGACY};
        body.lines()
            .enumerate()
            .filter(|(_, l)| !l.trim().is_empty())
            .filter(|(_, l)| {
                let trimmed = l.trim();
                trimmed != CSV_HEADER && trimmed != CSV_HEADER_LEGACY
            })
            .map(|(line_num, line)| {
                TelemetrySample::parse_line(line, line_num + 1).map_err(|e| format!("{e}"))
            })
            .collect()
    } else if body.trim_start().starts_with('{') {
        // JSONL — enumerate before filtering so line numbers match the original input
        body.lines()
            .enumerate()
            .filter(|(_, l)| !l.trim().is_empty())
            .map(|(i, line)| serde_json::from_str(line).map_err(|e| format!("line {}: {e}", i + 1)))
            .collect()
    } else {
        Err("Unsupported format. POST body must be JSONL or CSV.".into())
    };

    match samples {
        Ok(samples) if !samples.is_empty() => {
            let result = runtime::execute(&samples);
            let report = JsonReport::from_run_result(&result);
            let json = match serde_json::to_string_pretty(&report) {
                Ok(j) => j,
                Err(e) => return error_json(&format!("serialization error: {e}"), 500),
            };
            let mut s = state.lock().unwrap();
            // Update the live detector baseline with the analyzed samples
            for (sample, report) in samples.iter().zip(result.reports.iter()) {
                let pre = s
                    .detector
                    .snapshot()
                    .and_then(|snap| {
                        serde_json::to_vec(&snap)
                            .map_err(|e| eprintln!("proof pre-snapshot serialization error: {e}"))
                            .ok()
                    })
                    .unwrap_or_default();
                s.detector.evaluate(sample);
                let post = s
                    .detector
                    .snapshot()
                    .and_then(|snap| {
                        serde_json::to_vec(&snap)
                            .map_err(|e| eprintln!("proof post-snapshot serialization error: {e}"))
                            .ok()
                    })
                    .unwrap_or_default();
                s.proofs.record("baseline_update", &pre, &post);
                s.device.apply_decision(&report.decision);
                s.replay.push(*sample);
            }
            s.last_report = Some(report);
            drop(s);
            json_response(&json, 200)
        }
        Ok(_) => error_json("no samples in request body", 400),
        Err(e) => error_json(&e, 400),
    }
}

fn handle_mode(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut body = String::new();
    if std::io::Read::read_to_string(request.as_reader(), &mut body).is_err() {
        return error_json("failed to read request body", 400);
    }

    #[derive(serde::Deserialize)]
    struct ModeRequest {
        mode: String,
        #[serde(default)]
        decay_rate: Option<f32>,
    }

    let mode_req: ModeRequest = match serde_json::from_str(&body) {
        Ok(m) => m,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };

    let mode = match mode_req.mode.as_str() {
        "normal" => AdaptationMode::Normal,
        "frozen" => AdaptationMode::Frozen,
        "decay" => {
            let rate = mode_req.decay_rate.unwrap_or(0.05);
            if !rate.is_finite() || !(0.0..=1.0).contains(&rate) {
                return error_json("decay_rate must be a finite value in 0.0..=1.0", 400);
            }
            AdaptationMode::Decay(rate)
        }
        other => return error_json(&format!("unknown mode: {other}"), 400),
    };

    let mut s = state.lock().unwrap();
    s.detector.set_adaptation(mode);
    json_response(
        &format!(r#"{{"status":"mode set to {}"}}"#, mode_req.mode),
        200,
    )
}

fn handle_fleet_register(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut body = String::new();
    if std::io::Read::read_to_string(request.as_reader(), &mut body).is_err() {
        return error_json("failed to read request body", 400);
    }
    #[derive(serde::Deserialize)]
    struct Reg {
        device_id: String,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        platform: Option<String>,
    }
    let req: Reg = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    let record = DeviceRecord {
        device_id: req.device_id.clone(),
        name: req.name.unwrap_or_else(|| req.device_id.clone()),
        platform: req.platform.unwrap_or_else(|| "unknown".into()),
        firmware_version: "0.0.0".into(),
        enrolled_at: chrono::Utc::now().to_rfc3339(),
        last_seen_ms: chrono::Utc::now().timestamp_millis() as u64,
        status: DeviceStatus::Online,
        tags: Vec::new(),
    };
    let mut s = state.lock().unwrap();
    s.swarm.register_device(record);
    json_response(
        &format!(r#"{{"status":"registered","device":"{}"}}"#, req.device_id),
        200,
    )
}

fn handle_enforcement_quarantine(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut body = String::new();
    if std::io::Read::read_to_string(request.as_reader(), &mut body).is_err() {
        return error_json("failed to read request body", 400);
    }
    #[derive(serde::Deserialize)]
    struct QuarantineReq {
        target: String,
    }
    let req: QuarantineReq = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    let mut s = state.lock().unwrap();
    let results = s
        .enforcement
        .enforce(&crate::enforcement::EnforcementLevel::Quarantine, &req.target);
    let info = serde_json::json!({
        "target": req.target,
        "actions": results.len(),
        "results": results.iter().map(|r| serde_json::json!({
            "action": r.action,
            "success": r.success,
            "detail": r.detail,
        })).collect::<Vec<_>>(),
    });
    json_response(&info.to_string(), 200)
}

fn handle_threat_intel_ioc(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut body = String::new();
    if std::io::Read::read_to_string(request.as_reader(), &mut body).is_err() {
        return error_json("failed to read request body", 400);
    }
    #[derive(serde::Deserialize)]
    struct IocReq {
        value: String,
        ioc_type: String,
        #[serde(default = "default_confidence")]
        confidence: f32,
    }
    fn default_confidence() -> f32 {
        0.8
    }
    let req: IocReq = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };

    let ioc_type = match req.ioc_type.as_str() {
        "ip" => crate::threat_intel::IoCType::IpAddress,
        "domain" => crate::threat_intel::IoCType::Domain,
        "hash" => crate::threat_intel::IoCType::FileHash,
        "process" => crate::threat_intel::IoCType::ProcessName,
        _ => crate::threat_intel::IoCType::BehaviorPattern,
    };

    let now = chrono::Utc::now().to_rfc3339();
    let mut s = state.lock().unwrap();
    s.threat_intel.add_ioc(crate::threat_intel::IoC {
        ioc_type,
        value: req.value.clone(),
        confidence: req.confidence,
        severity: "medium".into(),
        source: "api".into(),
        first_seen: now.clone(),
        last_seen: now,
        tags: Vec::new(),
        related_iocs: Vec::new(),
    });
    json_response(
        &format!(r#"{{"status":"added","value":"{}"}}"#, req.value),
        200,
    )
}

fn handle_digital_twin_simulate(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut body = String::new();
    if std::io::Read::read_to_string(request.as_reader(), &mut body).is_err() {
        return error_json("failed to read request body", 400);
    }
    #[derive(serde::Deserialize)]
    struct SimReq {
        device_id: String,
        event_type: String,
    }
    let req: SimReq = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };

    let event = match req.event_type.as_str() {
        "cpu_spike" => crate::digital_twin::SimEvent::CpuSpike {
            target: req.device_id.clone(),
            load: 95.0,
        },
        "memory_exhaust" => crate::digital_twin::SimEvent::MemoryExhaust {
            target: req.device_id.clone(),
            mb: 1800.0,
        },
        "network_flood" => crate::digital_twin::SimEvent::NetworkFlood {
            target: req.device_id.clone(),
            kbps: 10_000.0,
        },
        "malware_inject" => crate::digital_twin::SimEvent::MalwareInject {
            target: req.device_id.clone(),
            score: 9.0,
        },
        _ => crate::digital_twin::SimEvent::CpuSpike {
            target: req.device_id.clone(),
            load: 80.0,
        },
    };

    let step = crate::digital_twin::SimStep {
        tick: 1,
        events: vec![event],
    };

    let mut s = state.lock().unwrap();
    let result = s.digital_twin.simulate(&[step]);
    let info = serde_json::json!({
        "device_id": req.device_id,
        "ticks_simulated": result.ticks_simulated,
        "alerts": result.alerts_generated.len(),
        "transitions": result.state_transitions.len(),
    });
    json_response(&info.to_string(), 200)
}

fn handle_energy_consume(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut body = String::new();
    if std::io::Read::read_to_string(request.as_reader(), &mut body).is_err() {
        return error_json("failed to read request body", 400);
    }
    #[derive(serde::Deserialize)]
    struct ConsumeReq {
        drain_rate_mw: f64,
    }
    let req: ConsumeReq = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    let mut s = state.lock().unwrap();
    s.energy.drain_rate_mw = req.drain_rate_mw;
    let new_state = s.energy.tick();
    let info = serde_json::json!({
        "remaining_pct": s.energy.remaining_pct(),
        "power_state": format!("{new_state:?}"),
    });
    json_response(&info.to_string(), 200)
}

fn handle_policy_vm_execute(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut body = String::new();
    if std::io::Read::read_to_string(request.as_reader(), &mut body).is_err() {
        return error_json("failed to read request body", 400);
    }
    #[derive(serde::Deserialize)]
    struct VmReq {
        #[serde(default)]
        env: std::collections::HashMap<String, f64>,
    }
    let req: VmReq = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    let s = state.lock().unwrap();
    // Build a simple program that loads env values and computes a risk composite
    let program = crate::wasm_engine::PolicyProgram::new("api-eval", vec![
        crate::wasm_engine::Opcode::LoadVar("score".into()),
        crate::wasm_engine::Opcode::LoadVar("battery".into()),
        crate::wasm_engine::Opcode::Mul,
        crate::wasm_engine::Opcode::StoreResult("risk_composite".into()),
        crate::wasm_engine::Opcode::Halt,
    ]);
    let result = s.policy_vm.execute(&program, &req.env);
    let info = serde_json::json!({
        "success": result.success,
        "outputs": result.outputs,
        "steps_executed": result.steps_executed,
        "error": result.error,
    });
    json_response(&info.to_string(), 200)
}

fn handle_deception_deploy(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut body = String::new();
    if std::io::Read::read_to_string(request.as_reader(), &mut body).is_err() {
        return error_json("failed to read request body", 400);
    }
    #[derive(serde::Deserialize)]
    struct DeployReq {
        decoy_type: String,
        name: String,
        #[serde(default)]
        description: Option<String>,
    }
    let req: DeployReq = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    let decoy_type = match req.decoy_type.as_str() {
        "honeypot" => crate::threat_intel::DecoyType::Honeypot,
        "honeyfile" => crate::threat_intel::DecoyType::HoneyFile,
        "honeycredential" => crate::threat_intel::DecoyType::HoneyCredential,
        "honeyservice" => crate::threat_intel::DecoyType::HoneyService,
        "canary" => crate::threat_intel::DecoyType::Canary,
        _ => crate::threat_intel::DecoyType::Honeypot,
    };
    let mut s = state.lock().unwrap();
    let id = s.deception.deploy(
        decoy_type,
        &req.name,
        req.description.as_deref().unwrap_or("Deployed via API"),
    );
    json_response(
        &serde_json::json!({ "status": "deployed", "decoy_id": id }).to_string(),
        200,
    )
}

fn handle_policy_compose(
    request: &mut Request,
    _state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut body = String::new();
    if std::io::Read::read_to_string(request.as_reader(), &mut body).is_err() {
        return error_json("failed to read request body", 400);
    }
    #[derive(serde::Deserialize)]
    struct ComposeReq {
        operator: String,
        score_a: f32,
        battery_a: f32,
        score_b: f32,
        battery_b: f32,
    }
    let req: ComposeReq = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    let op = match req.operator.as_str() {
        "max" => crate::policy::CompositionOp::MaxSeverity,
        "min" => crate::policy::CompositionOp::MinSeverity,
        "left" => crate::policy::CompositionOp::LeftPriority,
        "right" => crate::policy::CompositionOp::RightPriority,
        _ => return error_json("unknown operator: use max, min, left, or right", 400),
    };
    let engine = crate::policy::PolicyEngine;
    let signal_a = crate::detector::AnomalySignal {
        score: req.score_a, confidence: 0.9, suspicious_axes: 0,
        reasons: vec!["composed-a".into()], contributions: Vec::new(),
    };
    let sample_a = TelemetrySample {
        timestamp_ms: 0, cpu_load_pct: 0.0, memory_load_pct: 0.0,
        temperature_c: 0.0, network_kbps: 0.0, auth_failures: 0,
        battery_pct: req.battery_a, integrity_drift: 0.0,
        process_count: 0, disk_pressure_pct: 0.0,
    };
    let decision_a = engine.evaluate(&signal_a, &sample_a);
    let signal_b = crate::detector::AnomalySignal {
        score: req.score_b, confidence: 0.9, suspicious_axes: 0,
        reasons: vec!["composed-b".into()], contributions: Vec::new(),
    };
    let sample_b = TelemetrySample {
        timestamp_ms: 0, cpu_load_pct: 0.0, memory_load_pct: 0.0,
        temperature_c: 0.0, network_kbps: 0.0, auth_failures: 0,
        battery_pct: req.battery_b, integrity_drift: 0.0,
        process_count: 0, disk_pressure_pct: 0.0,
    };
    let decision_b = engine.evaluate(&signal_b, &sample_b);
    let (result, conflict) = crate::policy::compose_decisions(Some(decision_a), Some(decision_b), op);
    let info = serde_json::json!({
        "result": result.as_ref().map(|d| serde_json::json!({
            "level": format!("{:?}", d.level),
            "action": format!("{:?}", d.action),
        })),
        "conflict": conflict.as_ref().map(|c| serde_json::json!({
            "left_level": format!("{:?}", c.left_level),
            "right_level": format!("{:?}", c.right_level),
            "resolution": c.resolution,
        })),
    });
    json_response(&info.to_string(), 200)
}

fn serve_static(request: Request, site_dir: &Path) {
    let url = request.url();
    let relative = if url == "/" { "/index.html" } else { url };

    // Prevent path traversal
    let clean = relative.trim_start_matches('/');
    let requested = PathBuf::from(clean);
    if requested
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        let _ = request.respond(error_json("forbidden", 403));
        return;
    }

    let file_path = site_dir.join(clean);

    if file_path.is_file() {
        let content_type = match file_path.extension().and_then(|e| e.to_str()) {
            Some("html") => "text/html; charset=utf-8",
            Some("js") => "application/javascript; charset=utf-8",
            Some("css") => "text/css; charset=utf-8",
            Some("json") => "application/json",
            Some("csv") => "text/csv",
            Some("svg") => "image/svg+xml",
            Some("png") => "image/png",
            _ => "application/octet-stream",
        };

        match fs::read(&file_path) {
            Ok(data) => {
                let len = data.len();
                let response = Response::new(
                    tiny_http::StatusCode(200),
                    vec![Header::from_bytes(b"Content-Type", content_type.as_bytes()).unwrap()],
                    std::io::Cursor::new(data),
                    Some(len),
                    None,
                );
                let _ = request.respond(response);
            }
            Err(_) => {
                let _ = request.respond(error_json("read error", 500));
            }
        }
    } else {
        let _ = request.respond(error_json("not found", 404));
    }
}
