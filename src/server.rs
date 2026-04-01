use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tiny_http::{Header, Method, Request, Response, Server};

use crate::actions::DeviceController;
use crate::auto_update::UpdateManager;
use crate::checkpoint::CheckpointStore;
use crate::compliance::{ComplianceManager, CausalGraph};
use crate::collector::{AlertRecord, CollectorState, FileIntegrityMonitor, HostInfo, HostPlatform, detect_platform};
use crate::config::Config;
use crate::correlation;
use crate::detector::{AdaptationMode, AnomalyDetector, CompoundThreatDetector, DriftDetector, EntropyDetector, VelocityDetector};
use crate::digital_twin::DigitalTwinEngine;
use crate::edge_cloud::{PlatformCapabilities, PatchManager};
use crate::enforcement::EnforcementEngine;
use crate::energy::EnergyBudget;
use crate::enrollment::AgentRegistry;
use crate::event_forward::EventStore;
use crate::fingerprint::DeviceFingerprint;
use crate::monitor::Monitor;
use crate::multi_tenant::MultiTenantManager;
use crate::policy_dist::PolicyStore;
use crate::privacy::PrivacyAccountant;
use crate::proof::{DigestBackend, ProofRegistry};
use crate::quantum::KeyRotationManager;
use crate::replay::ReplayBuffer;
use crate::report::JsonReport;
use crate::runtime;
use crate::side_channel::SideChannelDetector;
use crate::siem::SiemConnector;
use crate::state_machine::PolicyStateMachine;
use crate::swarm::{DeviceRecord, DeviceStatus, SwarmNode};
use crate::telemetry::TelemetrySample;
use crate::threat_intel::{DeceptionEngine, ThreatIntelStore};
use crate::tls::ListenerMode;
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
    listener_mode: ListenerMode,
    config: Config,
    alerts: Vec<AlertRecord>,
    server_start: std::time::Instant,
    // XDR fleet management
    agent_registry: AgentRegistry,
    event_store: EventStore,
    policy_store: PolicyStore,
    update_manager: UpdateManager,
    siem_connector: SiemConnector,
    // Local host telemetry (ring buffer, last 300 samples)
    local_telemetry: Vec<TelemetrySample>,
    local_host_info: HostInfo,
    // Phase 21: advanced detectors
    velocity: VelocityDetector,
    entropy: EntropyDetector,
    compound: CompoundThreatDetector,
    // Phase 22: shutdown support
    shutdown: Arc<AtomicBool>,
}

pub fn run_server(port: u16, site_dir: &Path, shutdown: Arc<AtomicBool>) -> Result<(), String> {
    let addr = format!("0.0.0.0:{port}");
    let server = Server::http(&addr).map_err(|e| format!("failed to start server: {e}"))?;

    let token = generate_token();
    println!("Wardex admin console");
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
        listener_mode: ListenerMode::Plain { port },
        config: Config::default(),
        alerts: Vec::new(),
        server_start: std::time::Instant::now(),
        agent_registry: AgentRegistry::new("var/agents.json"),
        event_store: EventStore::new(10_000),
        policy_store: PolicyStore::new(),
        update_manager: UpdateManager::new("var/updates"),
        siem_connector: SiemConnector::new(crate::siem::SiemConfig::default()),
        local_telemetry: Vec::new(),
        local_host_info: detect_platform(),
        velocity: VelocityDetector::new(60, 2.5),
        entropy: EntropyDetector::new(60, 8),
        compound: CompoundThreatDetector::default(),
        shutdown: shutdown.clone(),
    }));

    // ── Spawn local host monitoring thread ──────────────────────────
    {
        let monitor_state = Arc::clone(&state);
        std::thread::spawn(move || {
            let mut cs = CollectorState::default();
            let mut consecutive_elevated: u32 = 0;
            let mut file_watch_cache: Vec<String> = Vec::new();
            let mut file_monitor: Option<FileIntegrityMonitor> = None;
            let mut persistence_watch_cache: Vec<String> = Vec::new();
            let mut persistence_monitor: Option<FileIntegrityMonitor> = None;
            const CONFIRM_SAMPLES: u32 = 2; // require N consecutive elevated before alerting
            loop {
                let (scope, watch_paths, host_platform) = {
                    let s = monitor_state.lock().unwrap();
                    (
                        s.config.monitor.scope.clone(),
                        s.config.monitor.watch_paths.clone(),
                        s.local_host_info.platform,
                    )
                };

                if scope.file_integrity {
                    if watch_paths != file_watch_cache {
                        file_monitor = if watch_paths.is_empty() {
                            None
                        } else {
                            Some(FileIntegrityMonitor::new(&watch_paths))
                        };
                        file_watch_cache = watch_paths.clone();
                    }
                } else {
                    file_monitor = None;
                    file_watch_cache.clear();
                }

                let persistence_paths = crate::collector::persistence_watch_paths(host_platform, &scope);
                if persistence_paths != persistence_watch_cache {
                    persistence_monitor = if persistence_paths.is_empty() {
                        None
                    } else {
                        Some(FileIntegrityMonitor::new(&persistence_paths))
                    };
                    persistence_watch_cache = persistence_paths;
                }

                let sample = crate::collector::collect_sample_scoped(
                    &mut cs,
                    file_monitor.as_ref(),
                    persistence_monitor.as_ref(),
                    &scope,
                );
                {
                    let mut s = monitor_state.lock().unwrap();
                    if s.local_telemetry.len() >= 300 {
                        s.local_telemetry.remove(0);
                    }
                    s.local_telemetry.push(sample);
                    let mut signal = s.detector.evaluate(&sample);

                    // Phase 21: velocity / entropy / compound enrichment
                    let vel_report = s.velocity.update(&sample);
                    let ent_report = s.entropy.update(&sample);
                    signal.score += vel_report.score_boost + ent_report.score_boost;
                    let mut extra_reasons: Vec<String> = Vec::new();
                    for ax in &vel_report.anomalous_axes {
                        extra_reasons.push(format!("velocity-spike:{ax}"));
                    }
                    for ax in &ent_report.anomalous_axes {
                        extra_reasons.push(format!("entropy-anomaly:{ax}"));
                    }
                    let cmp_report = s.compound.evaluate(&signal);
                    if cmp_report.is_compound_attack {
                        signal.score = cmp_report.compound_score;
                        extra_reasons.push(format!(
                            "compound-threat({:.0}%)",
                            cmp_report.concurrent_fraction * 100.0
                        ));
                    }
                    signal.reasons.extend(extra_reasons);

                    let crit = s.config.policy.critical_score;
                    let sev = s.config.policy.severe_score;
                    let elev = s.config.policy.elevated_score;
                    if signal.score >= elev {
                        consecutive_elevated += 1;
                        // Critical/Severe bypass confirmation — alert immediately
                        // Elevated requires consecutive confirmation to suppress noise
                        let confirmed = signal.score >= sev || consecutive_elevated >= CONFIRM_SAMPLES;
                        if confirmed {
                            let level = if signal.score >= crit { "Critical" }
                                else if signal.score >= sev { "Severe" }
                                else { "Elevated" };
                            let host = s.local_host_info.clone();
                            let alert = AlertRecord {
                                timestamp: chrono::Utc::now().to_rfc3339(),
                                hostname: host.hostname,
                                platform: host.platform.to_string(),
                                score: signal.score,
                                confidence: signal.confidence,
                                level: level.to_string(),
                                action: "monitor".to_string(),
                                reasons: signal.reasons,
                                sample,
                                enforced: false,
                            };
                            if s.alerts.len() >= 10_000 {
                                s.alerts.remove(0);
                            }
                            s.alerts.push(alert);
                        }
                    } else {
                        consecutive_elevated = 0;
                    }
                    let interval = s.config.monitor.interval_secs.max(1);
                    drop(s);
                    std::thread::sleep(std::time::Duration::from_secs(interval));
                }
            }
        });
    }

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
        listener_mode: ListenerMode::Plain { port },
        config: Config::default(),
        alerts: Vec::new(),
        server_start: std::time::Instant::now(),
        agent_registry: AgentRegistry::new(&format!("/tmp/wardex_test_{port}/agents.json")),
        event_store: EventStore::new(1000),
        policy_store: PolicyStore::new(),
        update_manager: UpdateManager::new(&format!("/tmp/wardex_test_{port}/updates")),
        siem_connector: SiemConnector::new(crate::siem::SiemConfig::default()),
        local_telemetry: Vec::new(),
        local_host_info: detect_platform(),
        velocity: VelocityDetector::new(60, 2.5),
        entropy: EntropyDetector::new(60, 8),
        compound: CompoundThreatDetector::default(),
        shutdown: Arc::new(AtomicBool::new(false)),
    }));
    let site_dir = PathBuf::from("site");
    std::thread::spawn(move || {
        serve_loop(&server, &state, &site_dir);
    });
    (port, token)
}

fn serve_loop(server: &Server, state: &Arc<Mutex<AppState>>, site_dir: &Path) {
    loop {
        match server.recv_timeout(std::time::Duration::from_millis(500)) {
            Ok(Some(request)) => {
                let url = request.url().to_string();
                if url.starts_with("/api/") {
                    handle_api(request, state, site_dir, server);
                } else {
                    serve_static(request, site_dir);
                }
            }
            Ok(None) => {} // timeout, check shutdown
            Err(_) => break,
        }
        let s = state.lock().unwrap();
        if s.shutdown.load(Ordering::Relaxed) {
            drop(s);
            eprintln!("Server shutting down…");
            break;
        }
    }
}

fn generate_token() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.r#gen()).collect();
    hex::encode(bytes)
}

fn cors_origin() -> String {
    std::env::var("SENTINEL_CORS_ORIGIN").unwrap_or_else(|_| "*".into())
}

fn json_response(body: &str, status: u16) -> Response<std::io::Cursor<Vec<u8>>> {
    let origin = cors_origin();
    let data = body.as_bytes().to_vec();
    let len = data.len();
    Response::new(
        tiny_http::StatusCode(status),
        vec![
            Header::from_bytes(b"Content-Type", b"application/json").unwrap(),
            Header::from_bytes(b"Access-Control-Allow-Origin", origin.as_bytes()).unwrap(),
            Header::from_bytes(b"Vary", b"Origin").unwrap(),
            Header::from_bytes(b"X-Content-Type-Options", b"nosniff").unwrap(),
            Header::from_bytes(b"X-Frame-Options", b"DENY").unwrap(),
            Header::from_bytes(b"Cache-Control", b"no-store").unwrap(),
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
    let origin = cors_origin();
    let data = body.as_bytes().to_vec();
    let len = data.len();
    Response::new(
        tiny_http::StatusCode(status),
        vec![
            Header::from_bytes(b"Content-Type", b"text/plain; charset=utf-8").unwrap(),
            Header::from_bytes(b"Access-Control-Allow-Origin", origin.as_bytes()).unwrap(),
            Header::from_bytes(b"Vary", b"Origin").unwrap(),
            Header::from_bytes(b"X-Content-Type-Options", b"nosniff").unwrap(),
            Header::from_bytes(b"X-Frame-Options", b"DENY").unwrap(),
            Header::from_bytes(b"Cache-Control", b"no-store").unwrap(),
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

fn host_platform_key(platform: HostPlatform) -> &'static str {
    match platform {
        HostPlatform::Linux => "linux",
        HostPlatform::MacOS => "macos",
        HostPlatform::Windows | HostPlatform::WindowsServer => "windows",
        HostPlatform::Unknown => "unknown",
    }
}

fn monitoring_option(
    id: &str,
    label: &str,
    description: &str,
    selected: bool,
    supported: bool,
    recommended: bool,
    mode: &str,
    reason: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "label": label,
        "description": description,
        "selected": selected,
        "supported": supported,
        "recommended": recommended,
        "mode": mode,
        "reason": reason,
    })
}

fn monitoring_guidance(platform: HostPlatform) -> Vec<&'static str> {
    match platform {
        HostPlatform::Linux => vec![
            "Linux hosts benefit most from auth-failure monitoring and systemd-unit persistence checks because both map directly to common intrusion paths.",
            "Battery coverage depends on power-supply telemetry such as BAT0; server-class systems often report no battery data.",
        ],
        HostPlatform::MacOS => vec![
            "macOS hosts should prioritize LaunchAgents and LaunchDaemons because they are common persistence locations for userland malware.",
            "Thermal telemetry is limited on macOS in the current pure-Rust collector path, so CPU and process signals remain the stronger indicators.",
        ],
        HostPlatform::Windows | HostPlatform::WindowsServer => vec![
            "Windows hosts should prioritize Security-log failures and scheduled-task persistence because both are frequently abused during compromise and re-entry.",
            "Battery and thermal coverage depends on WMI support and may be absent on desktop or virtualized systems.",
        ],
        HostPlatform::Unknown => vec![
            "This host platform could not be classified cleanly, so Wardex recommends sticking to portable telemetry and file-integrity checks.",
            "Platform-specific persistence checks remain unavailable until the runtime can map standard service locations for this OS.",
        ],
    }
}

fn monitoring_options_payload(host: &HostInfo, config: &Config) -> serde_json::Value {
    let platform_key = host_platform_key(host.platform);
    let caps = PlatformCapabilities::detect_current();
    let scope = &config.monitor.scope;
    let persistence_paths = crate::collector::persistence_watch_paths(host.platform, scope);

    let core = vec![
        monitoring_option(
            "cpu_load",
            "CPU load",
            "Monitors sustained or sudden CPU pressure to catch miners, brute-force spikes, and runaway workloads.",
            scope.cpu_load,
            true,
            true,
            "always_on",
            Some("Core telemetry is always collected in the current release."),
        ),
        monitoring_option(
            "memory_pressure",
            "Memory pressure",
            "Tracks RAM consumption trends to surface exhaustion, injection, and staging behavior.",
            scope.memory_pressure,
            true,
            true,
            "always_on",
            Some("Core telemetry is always collected in the current release."),
        ),
        monitoring_option(
            "network_activity",
            "Network activity",
            "Flags bursts or sustained traffic shifts associated with exfiltration, C2, or floods.",
            scope.network_activity,
            true,
            true,
            "always_on",
            Some("Core telemetry is always collected in the current release."),
        ),
        monitoring_option(
            "disk_pressure",
            "Disk pressure",
            "Watches disk utilization changes that can indicate ransomware, log stuffing, or resource starvation.",
            scope.disk_pressure,
            true,
            true,
            "always_on",
            Some("Core telemetry is always collected in the current release."),
        ),
        monitoring_option(
            "process_activity",
            "Process activity",
            "Uses process-count anomalies to highlight fork storms, lateral tooling, and persistence bursts.",
            scope.process_activity,
            true,
            true,
            "always_on",
            Some("Core telemetry is always collected in the current release."),
        ),
    ];

    let security = vec![
        monitoring_option(
            "auth_events",
            "Authentication events",
            "Tracks failed-logon spikes to detect brute-force and credential-stuffing behavior.",
            scope.auth_events,
            true,
            true,
            "configurable",
            Some("Disable only if the host cannot expose auth logs or Security-event access is intentionally restricted."),
        ),
        monitoring_option(
            "file_integrity",
            "File integrity",
            "Hashes configured paths and alerts on unexpected changes. This is the scope item that directly changes collector behavior now.",
            scope.file_integrity,
            true,
            true,
            "configurable",
            None,
        ),
        monitoring_option(
            "service_persistence",
            "Service persistence",
            "Covers startup services and persistence footholds using OS-specific baseline paths.",
            scope.service_persistence,
            platform_key != "unknown",
            true,
            "configurable",
            Some(if platform_key == "unknown" {
                "Runtime could not determine standard persistence locations for this host."
            } else {
                "Enable this together with the host-specific source below; if no source is selected, Wardex uses the recommended source for the current OS."
            }),
        ),
    ];

    let host_specific = vec![
        monitoring_option(
            "thermal_state",
            "Thermal state",
            "Adds device-heat context to CPU and workload anomalies.",
            scope.thermal_state,
            true,
            platform_key != "unknown",
            "always_on",
            Some("Collected as part of the current host telemetry pipeline."),
        ),
        monitoring_option(
            "battery_state",
            "Battery state",
            "Useful on mobile or battery-backed devices where power drain can be part of the attack path.",
            scope.battery_state,
            true,
            matches!(host.platform, HostPlatform::MacOS | HostPlatform::Windows | HostPlatform::WindowsServer),
            "always_on",
            Some("Collected when the host exposes battery data."),
        ),
        monitoring_option(
            "launch_agents",
            "Launch agents",
            "macOS persistence points such as LaunchAgents and LaunchDaemons.",
            scope.launch_agents,
            platform_key == "macos",
            platform_key == "macos",
            "configurable",
            Some(if platform_key == "macos" {
                "Recommended on macOS because LaunchAgents and LaunchDaemons are baselined directly when service persistence is enabled."
            } else {
                "macOS-specific monitoring point."
            }),
        ),
        monitoring_option(
            "systemd_units",
            "systemd units",
            "Linux startup services and unit-file persistence.",
            scope.systemd_units,
            platform_key == "linux",
            platform_key == "linux",
            "configurable",
            Some(if platform_key == "linux" {
                "Recommended on Linux because systemd unit paths are baselined directly when service persistence is enabled."
            } else {
                "Linux-specific monitoring point."
            }),
        ),
        monitoring_option(
            "scheduled_tasks",
            "Scheduled tasks",
            "Windows task-scheduler persistence and delayed execution.",
            scope.scheduled_tasks,
            platform_key == "windows",
            platform_key == "windows",
            "configurable",
            Some(if platform_key == "windows" {
                "Recommended on Windows because Task Scheduler definitions are baselined directly when service persistence is enabled."
            } else {
                "Windows-specific monitoring point."
            }),
        ),
    ];

    let selected_now = vec![
        (scope.cpu_load, "CPU load"),
        (scope.memory_pressure, "Memory pressure"),
        (scope.network_activity, "Network activity"),
        (scope.disk_pressure, "Disk pressure"),
        (scope.process_activity, "Process activity"),
        (scope.auth_events, "Authentication events"),
        (scope.thermal_state, "Thermal state"),
        (scope.battery_state, "Battery state"),
        (scope.file_integrity, "File integrity"),
        (scope.service_persistence, "Service persistence"),
        (scope.launch_agents, "Launch agents"),
        (scope.systemd_units, "systemd units"),
        (scope.scheduled_tasks, "Scheduled tasks"),
    ]
    .into_iter()
    .filter_map(|(enabled, label)| enabled.then_some(label))
    .collect::<Vec<_>>();

    serde_json::json!({
        "host": {
            "platform": host.platform.to_string(),
            "platform_key": platform_key,
            "hostname": host.hostname,
            "os_version": host.os_version,
            "arch": host.arch,
            "has_tpm": caps.has_tpm,
            "has_seccomp": caps.has_seccomp,
            "has_ebpf": caps.has_ebpf,
            "has_firewall": caps.has_firewall,
            "process_control": caps.process_control,
        },
        "summary": {
            "selected_now": selected_now,
            "watch_path_count": config.monitor.watch_paths.len(),
            "persistence_path_count": persistence_paths.len(),
            "platform_guidance": monitoring_guidance(host.platform),
            "notes": [
                "Core telemetry remains always-on unless a scope toggle explicitly gates that collector.",
                "Auth-event collection and persistence baselines now follow the selected monitoring scope in addition to file-integrity paths."
            ]
        },
        "groups": [
            {
                "id": "core_system",
                "label": "Core System",
                "description": "Signals already collected on every sample.",
                "options": core,
            },
            {
                "id": "security_signals",
                "label": "Security Signals",
                "description": "Signals tied to attack behavior and integrity checks.",
                "options": security,
            },
            {
                "id": "host_specific",
                "label": "Host-Specific",
                "description": "OS-aware recommendations and planned collectors for this platform.",
                "options": host_specific,
            }
        ]
    })
}

fn handle_api(mut request: Request, state: &Arc<Mutex<AppState>>, _site_dir: &Path, server: &Server) {
    let url = request.url().to_string();
    let method = request.method().clone();

    // ── Request body size limit (10 MB) ──
    const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;
    if let Some(len) = request.body_length() {
        if len > MAX_BODY_SIZE {
            let _ = request.respond(error_json("request body too large", 413));
            return;
        }
    }
    // Body limit enforced in read_body_limited()

    // Check auth for mutating endpoints before consuming the request body
    // XDR agent endpoints that do NOT require admin auth (agents use enrollment tokens)
    let is_agent_endpoint = url.starts_with("/api/agents/enroll")
        || url.starts_with("/api/agents/update")
        || (url.contains("/heartbeat") && url.starts_with("/api/agents/"))
        || url.starts_with("/api/events")
        || url.starts_with("/api/policy/current")
        || url.starts_with("/api/updates/download/");

    let needs_auth = !is_agent_endpoint && matches!(
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
            | (Method::Post, "/api/config/reload")
            | (Method::Post, "/api/config/save")
            | (Method::Post, "/api/agents/token")
            | (Method::Post, "/api/policy/publish")
            | (Method::Post, "/api/updates/publish")
            | (Method::Post, "/api/shutdown")
            | (Method::Post, "/api/mesh/heal")
            | (Method::Delete, "/api/alerts")
    ) || (!is_agent_endpoint && (
        (method == Method::Get && url == "/api/fleet/dashboard")
        || (method == Method::Get && url == "/api/siem/status")
        || (method == Method::Get && url == "/api/agents")
        || (method == Method::Get && url == "/api/telemetry/current")
        || (method == Method::Get && url == "/api/telemetry/history")
        || (method == Method::Get && url == "/api/host/info")
        || (method == Method::Get && url == "/api/config/current")
        || (method == Method::Get && url == "/api/checkpoints")
        || (method == Method::Get && url == "/api/correlation")
        || (method == Method::Get && url == "/api/alerts")
        || (method == Method::Get && url == "/api/alerts/count")
        || (method == Method::Get && url.starts_with("/api/alerts/") && url != "/api/alerts/count")
        || (method == Method::Get && url == "/api/report")
        || (method == Method::Get && url == "/api/threads/status")
        || (method == Method::Get && url == "/api/detection/summary")
        || (method == Method::Get && url == "/api/monitoring/options")
        || (method == Method::Get && url == "/api/endpoints")
        || (method == Method::Get && url == "/api/status")
        || (method == Method::Delete && url.starts_with("/api/agents/"))
    ));

    if needs_auth && !check_auth(&request, state) {
        let _ = request.respond(error_json("unauthorized", 401));
        return;
    }

    let response = match (method.clone(), url.as_str()) {
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
            } else if !s.alerts.is_empty() {
                // Generate a live report from monitoring alerts
                let alerts = &s.alerts;
                let total = alerts.len();
                let critical = alerts.iter().filter(|a| a.level == "Critical").count();
                let avg_score = if total > 0 { alerts.iter().map(|a| a.score).sum::<f32>() / total as f32 } else { 0.0 };
                let max_score = alerts.iter().map(|a| a.score).fold(0.0f32, f32::max);
                let samples: Vec<serde_json::Value> = alerts.iter().enumerate().map(|(i, a)| {
                    serde_json::json!({
                        "index": i,
                        "timestamp_ms": chrono::DateTime::parse_from_rfc3339(&a.timestamp).map(|dt| dt.timestamp_millis() as u64).unwrap_or(0),
                        "score": a.score,
                        "confidence": a.confidence,
                        "suspicious_axes": a.reasons.len(),
                        "level": a.level,
                        "action": a.action,
                        "isolation_pct": 0,
                        "reasons": a.reasons,
                        "rationale": format!("{} alert from live monitor", a.level),
                        "contributions": []
                    })
                }).collect();
                let report = serde_json::json!({
                    "generated_at": chrono::Utc::now().to_rfc3339(),
                    "summary": {
                        "total_samples": total,
                        "alert_count": total,
                        "critical_count": critical,
                        "average_score": avg_score,
                        "max_score": max_score,
                    },
                    "samples": samples,
                });
                json_response(&report.to_string(), 200)
            } else {
                json_response(r#"{"generated_at":"","summary":{"total_samples":0,"alert_count":0,"critical_count":0,"average_score":0.0,"max_score":0.0},"samples":[]}"#, 200)
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

        // ── TLS Status ───────────────────────────────────────────
        (Method::Get, "/api/tls/status") => {
            let s = state.lock().unwrap();
            let info = serde_json::json!({
                "tls_enabled": s.listener_mode.is_tls(),
                "scheme": s.listener_mode.scheme(),
                "port": s.listener_mode.port(),
            });
            json_response(&info.to_string(), 200)
        }

        // ── Mesh Health / Self-Healing ────────────────────────────
        (Method::Get, "/api/mesh/health") => {
            let s = state.lock().unwrap();
            let (report, repairs) = s.swarm.self_heal();
            let info = serde_json::json!({
                "is_connected": report.is_connected,
                "partition_count": report.partitions.len(),
                "largest_partition_size": report.largest_partition_size,
                "partitions": report.partitions,
                "proposed_repairs": repairs,
            });
            json_response(&info.to_string(), 200)
        }
        (Method::Post, "/api/mesh/heal") => {
            let mut s = state.lock().unwrap();
            let (report, repairs) = s.swarm.self_heal();
            let applied = repairs.len();
            for repair in &repairs {
                s.swarm.apply_repair(repair);
            }
            let (post_report, _) = s.swarm.self_heal();
            let info = serde_json::json!({
                "repairs_applied": applied,
                "was_connected": report.is_connected,
                "now_connected": post_report.is_connected,
                "partitions_before": report.partitions.len(),
                "partitions_after": post_report.partitions.len(),
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

        // ── Config Hot-Reload ─────────────────────────────────────
        (Method::Get, "/api/config/current") => {
            let s = state.lock().unwrap();
            match serde_json::to_string_pretty(&s.config) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Post, "/api/config/reload") => {
            handle_config_reload(&mut request, state)
        }
        (Method::Post, "/api/config/save") => {
            let s = state.lock().unwrap();
            let config_path = std::path::Path::new("var/wardex.toml");
            match toml::to_string_pretty(&s.config) {
                Ok(toml_str) => {
                    if let Some(parent) = config_path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    match std::fs::write(config_path, &toml_str) {
                        Ok(()) => json_response(
                            &format!(r#"{{"status":"saved","path":"{}"}}"#, config_path.display()),
                            200,
                        ),
                        Err(e) => error_json(&format!("failed to write config: {e}"), 500),
                    }
                }
                Err(e) => error_json(&format!("failed to serialize config: {e}"), 500),
            }
        }

        // ── Health & Alerts ──────────────────────────────────────────
        (Method::Get, "/api/health") => {
            let s = state.lock().unwrap();
            let host = crate::collector::detect_platform();
            let uptime = s.server_start.elapsed().as_secs();
            let body = serde_json::json!({
                "status": "ok",
                "version": env!("CARGO_PKG_VERSION"),
                "uptime_secs": uptime,
                "platform": host.platform.to_string(),
                "hostname": host.hostname,
                "os_version": host.os_version,
            });
            json_response(&body.to_string(), 200)
        }
        (Method::Get, "/api/alerts") => {
            let s = state.lock().unwrap();
            let recent: Vec<_> = s.alerts.iter().enumerate().rev().take(100)
                .map(|(i, a)| {
                    let mut obj = serde_json::to_value(a).unwrap_or_default();
                    if let Some(map) = obj.as_object_mut() {
                        map.insert("_index".to_string(), serde_json::json!(i));
                    }
                    obj
                })
                .collect();
            match serde_json::to_string(&recent) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/alerts/count") => {
            let s = state.lock().unwrap();
            let total = s.alerts.len();
            let critical = s.alerts.iter().filter(|a| a.level == "Critical").count();
            let severe = s.alerts.iter().filter(|a| a.level == "Severe").count();
            let elevated = s.alerts.iter().filter(|a| a.level == "Elevated").count();
            let body = serde_json::json!({
                "total": total,
                "critical": critical,
                "severe": severe,
                "elevated": elevated,
            });
            json_response(&body.to_string(), 200)
        }
        (Method::Delete, "/api/alerts") => {
            let mut s = state.lock().unwrap();
            let cleared = s.alerts.len();
            s.alerts.clear();
            json_response(
                &format!(r#"{{"status":"cleared","count":{cleared}}}"#),
                200,
            )
        }
        // ── Local Telemetry ──────────────────────────────────────
        (Method::Get, "/api/telemetry/current") => {
            let s = state.lock().unwrap();
            if let Some(sample) = s.local_telemetry.last() {
                match serde_json::to_string(sample) {
                    Ok(json) => json_response(&json, 200),
                    Err(e) => error_json(&format!("serialization error: {e}"), 500),
                }
            } else {
                json_response(r#"{"message":"no telemetry collected yet"}"#, 200)
            }
        }
        (Method::Get, "/api/telemetry/history") => {
            let s = state.lock().unwrap();
            let samples: Vec<_> = s.local_telemetry.iter().rev().take(120).collect();
            match serde_json::to_string(&samples) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }
        (Method::Get, "/api/host/info") => {
            let s = state.lock().unwrap();
            let host = &s.local_host_info;
            let uptime = s.server_start.elapsed().as_secs();
            let cpu_cores = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1);
            let capabilities = PlatformCapabilities::detect_current();
            let body = serde_json::json!({
                "hostname": host.hostname,
                "platform": host.platform.to_string(),
                "os_version": host.os_version,
                "arch": host.arch,
                "cpu_cores": cpu_cores,
                "uptime_secs": uptime,
                "version": env!("CARGO_PKG_VERSION"),
                "local_monitoring": true,
                "telemetry_samples": s.local_telemetry.len(),
                "has_tpm": capabilities.has_tpm,
                "has_seccomp": capabilities.has_seccomp,
                "has_ebpf": capabilities.has_ebpf,
                "has_firewall": capabilities.has_firewall,
            });
            json_response(&body.to_string(), 200)
        }
        (Method::Get, "/api/threads/status") => {
            let s = state.lock().unwrap();
            let uptime = s.server_start.elapsed().as_secs();
            let body = serde_json::json!({
                "monitoring_thread": "active",
                "sample_count": s.local_telemetry.len(),
                "collection_rate_hz": 0.2,
                "uptime_secs": uptime,
                "alert_count": s.alerts.len(),
            });
            json_response(&body.to_string(), 200)
        }
        (Method::Get, "/api/monitoring/options") => {
            let s = state.lock().unwrap();
            let body = monitoring_options_payload(&s.local_host_info, &s.config);
            json_response(&body.to_string(), 200)
        }
        (Method::Get, "/api/endpoints") => {
            let endpoints = serde_json::json!([
                {"method": "GET", "path": "/api/health", "auth": false, "description": "Server health, version, uptime, platform"},
                {"method": "GET", "path": "/api/host/info", "auth": true, "description": "Detailed host info + monitoring status"},
                {"method": "GET", "path": "/api/telemetry/current", "auth": true, "description": "Latest local telemetry sample"},
                {"method": "GET", "path": "/api/telemetry/history", "auth": true, "description": "Last 120 local telemetry samples"},
                {"method": "GET", "path": "/api/checkpoints", "auth": true, "description": "Saved checkpoint metadata"},
                {"method": "GET", "path": "/api/correlation", "auth": true, "description": "Replay-buffer correlation analysis"},
                {"method": "GET", "path": "/api/alerts", "auth": true, "description": "Last 100 alerts"},
                {"method": "GET", "path": "/api/alerts/count", "auth": true, "description": "Alert count by severity"},
                {"method": "DELETE", "path": "/api/alerts", "auth": true, "description": "Clear all alerts"},
                {"method": "GET", "path": "/api/status", "auth": true, "description": "Project status manifest"},
                {"method": "GET", "path": "/api/report", "auth": true, "description": "Latest analysis report"},
                {"method": "POST", "path": "/api/analyze", "auth": true, "description": "Analyze CSV/JSONL telemetry"},
                {"method": "GET", "path": "/api/config/current", "auth": true, "description": "Current configuration"},
                {"method": "GET", "path": "/api/monitoring/options", "auth": true, "description": "OS-aware monitoring points and recommendations"},
                {"method": "POST", "path": "/api/config/reload", "auth": true, "description": "Hot-reload config patch"},
                {"method": "POST", "path": "/api/config/save", "auth": true, "description": "Persist config to disk"},
                {"method": "GET", "path": "/api/endpoints", "auth": true, "description": "This endpoint listing"},
                {"method": "GET", "path": "/api/threads/status", "auth": true, "description": "Background thread status and collection stats"},
                {"method": "GET", "path": "/api/detection/summary", "auth": true, "description": "Velocity, entropy, compound detector state"},
            ]);
            json_response(&endpoints.to_string(), 200)
        }

        // ── XDR Agent Management ──────────────────────────────────
        (Method::Post, "/api/agents/enroll") => {
            handle_agent_enroll(&mut request, state)
        }
        (Method::Post, "/api/agents/token") => {
            handle_agent_create_token(&mut request, state)
        }
        (Method::Get, "/api/agents") => {
            let s = state.lock().unwrap();
            let agents = s.agent_registry.list();
            match serde_json::to_string(&agents) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }

        // ── XDR Events ────────────────────────────────────────────
        (Method::Post, "/api/events") => {
            handle_event_ingest(&mut request, state)
        }
        (Method::Get, "/api/events") => {
            let s = state.lock().unwrap();
            let events = s.event_store.list(None, 200);
            match serde_json::to_string(&events) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }

        // ── XDR Policy Distribution ──────────────────────────────
        (Method::Get, "/api/policy/current") => {
            let s = state.lock().unwrap();
            match s.policy_store.current() {
                Some(policy) => match serde_json::to_string(policy) {
                    Ok(json) => json_response(&json, 200),
                    Err(e) => error_json(&format!("serialization error: {e}"), 500),
                },
                None => json_response(r#"{"version":0,"message":"no policy published"}"#, 200),
            }
        }
        (Method::Post, "/api/policy/publish") => {
            handle_policy_publish(&mut request, state)
        }

        // ── XDR Update Distribution ──────────────────────────────
        (Method::Post, "/api/updates/publish") => {
            handle_update_publish(&mut request, state)
        }

        // ── Detection Analysis ─────────────────────────────────
        (Method::Get, "/api/detection/summary") => {
            let s = state.lock().unwrap();
            let vel_state = &s.velocity;
            let ent_state = &s.entropy;
            let cmp_state = &s.compound;
            let body = serde_json::json!({
                "velocity": {
                    "window_size": vel_state.window_len(),
                    "sigma": vel_state.sigma(),
                },
                "entropy": {
                    "window_size": ent_state.window_len(),
                    "bins": ent_state.bins(),
                },
                "compound": {
                    "min_concurrent_fraction": cmp_state.min_concurrent_fraction,
                    "per_axis_threshold": cmp_state.per_axis_threshold,
                },
            });
            json_response(&body.to_string(), 200)
        }

        // ── SIEM Status ──────────────────────────────────────────
        (Method::Get, "/api/siem/status") => {
            let s = state.lock().unwrap();
            let status = s.siem_connector.status();
            match serde_json::to_string(&status) {
                Ok(json) => json_response(&json, 200),
                Err(e) => error_json(&format!("serialization error: {e}"), 500),
            }
        }

        // ── Fleet Dashboard ──────────────────────────────────────
        (Method::Get, "/api/fleet/dashboard") => {
            let s = state.lock().unwrap();
            let agents = s.agent_registry.list();
            let counts = s.agent_registry.counts();
            let total_events = s.event_store.total_events();
            let correlations = s.event_store.recent_correlations();
            let policy_version = s.policy_store.current_version();
            let siem_status = s.siem_connector.status();
            let releases = s.update_manager.list_releases();
            let info = serde_json::json!({
                "fleet": {
                    "total_agents": agents.len(),
                    "status_counts": counts,
                },
                "events": {
                    "total": total_events,
                    "recent_correlations": correlations.len(),
                    "correlations": correlations,
                },
                "policy": {
                    "current_version": policy_version,
                },
                "updates": {
                    "available_releases": releases.len(),
                },
                "siem": {
                    "enabled": siem_status.enabled,
                    "pending": siem_status.pending_events,
                    "total_pushed": siem_status.total_pushed,
                    "total_pulled": siem_status.total_pulled,
                },
            });
            json_response(&info.to_string(), 200)
        }

        (Method::Post, "/api/shutdown") => {
            let s = state.lock().unwrap();
            s.shutdown.store(true, Ordering::SeqCst);
            drop(s);
            server.unblock();
            json_response(r#"{"status":"shutting_down"}"#, 200)
        }

        (Method::Options, _) => {
            let data: Vec<u8> = Vec::new();
            Response::new(
                tiny_http::StatusCode(204),
                vec![
                    Header::from_bytes(b"Access-Control-Allow-Origin", cors_origin().as_bytes())
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
        _ => {
            // Dynamic routes with path parameters
            if method == Method::Get && (url == "/api/agents/update" || url.starts_with("/api/agents/update?")) {
                // GET /api/agents/update?current_version=xxx&platform=yyy
                handle_agent_update_check(&mut request, state)
            } else if method == Method::Post && url.ends_with("/heartbeat") && url.starts_with("/api/agents/") {
                // POST /api/agents/{id}/heartbeat
                let agent_id = url.strip_prefix("/api/agents/")
                    .and_then(|rest| rest.strip_suffix("/heartbeat"))
                    .unwrap_or("");
                handle_agent_heartbeat(&mut request, state, agent_id)
            } else if method == Method::Get && url.starts_with("/api/agents/") && url.ends_with("/status") {
                // GET /api/agents/{id}/status
                let agent_id = url.strip_prefix("/api/agents/")
                    .and_then(|rest| rest.strip_suffix("/status"))
                    .unwrap_or("");
                let s = state.lock().unwrap();
                match s.agent_registry.get(agent_id) {
                    Some(agent) => match serde_json::to_string(agent) {
                        Ok(json) => json_response(&json, 200),
                        Err(e) => error_json(&format!("serialization error: {e}"), 500),
                    },
                    None => error_json("agent not found", 404),
                }
            } else if method == Method::Delete && url.starts_with("/api/agents/") {
                // DELETE /api/agents/{id}
                let agent_id = url.strip_prefix("/api/agents/").unwrap_or("");
                let mut s = state.lock().unwrap();
                match s.agent_registry.deregister(agent_id) {
                    Ok(()) => {
                        let body = serde_json::json!({"status": "deregistered", "agent_id": agent_id});
                        json_response(&body.to_string(), 200)
                    }
                    Err(e) => error_json(&e, 404),
                }
            } else if method == Method::Get && url.starts_with("/api/updates/download/") {
                // GET /api/updates/download/{file_name}
                let file_name = url.strip_prefix("/api/updates/download/").unwrap_or("");
                let s = state.lock().unwrap();
                match s.update_manager.get_release_binary(file_name) {
                    Ok(data) => {
                        let len = data.len();
                        Response::new(
                            tiny_http::StatusCode(200),
                            vec![
                                Header::from_bytes(b"Content-Type", b"application/octet-stream").unwrap(),
                                Header::from_bytes(b"Access-Control-Allow-Origin", cors_origin().as_bytes()).unwrap(),
                            ],
                            std::io::Cursor::new(data),
                            Some(len),
                            None,
                        )
                    }
                    Err(e) => error_json(&e, 404),
                }
            } else if method == Method::Get && url.starts_with("/api/events?") {
                // GET /api/events?agent_id=xxx&limit=100
                let query = url.strip_prefix("/api/events?").unwrap_or("");
                let mut agent_id_filter: Option<String> = None;
                let mut limit = 200usize;
                for param in query.split('&') {
                    if let Some(val) = param.strip_prefix("agent_id=") {
                        agent_id_filter = Some(val.to_string());
                    } else if let Some(val) = param.strip_prefix("limit=") {
                        limit = val.parse().unwrap_or(200);
                    }
                }
                let s = state.lock().unwrap();
                let events = s.event_store.list(agent_id_filter.as_deref(), limit);
                match serde_json::to_string(&events) {
                    Ok(json) => json_response(&json, 200),
                    Err(e) => error_json(&format!("serialization error: {e}"), 500),
                }
            } else if method == Method::Get && url.starts_with("/api/alerts/") && url != "/api/alerts/count" {
                // GET /api/alerts/{index} — detailed alert view
                let idx_str = url.strip_prefix("/api/alerts/").unwrap_or("");
                match idx_str.parse::<usize>() {
                    Ok(idx) => {
                        let s = state.lock().unwrap();
                        if idx < s.alerts.len() {
                            let alert = &s.alerts[idx];
                            let detail = serde_json::json!({
                                "index": idx,
                                "timestamp": alert.timestamp,
                                "hostname": alert.hostname,
                                "platform": alert.platform,
                                "score": alert.score,
                                "confidence": alert.confidence,
                                "level": alert.level,
                                "action": alert.action,
                                "reasons": alert.reasons,
                                "enforced": alert.enforced,
                                "sample": {
                                    "timestamp_ms": alert.sample.timestamp_ms,
                                    "cpu_load_pct": alert.sample.cpu_load_pct,
                                    "memory_load_pct": alert.sample.memory_load_pct,
                                    "temperature_c": alert.sample.temperature_c,
                                    "network_kbps": alert.sample.network_kbps,
                                    "auth_failures": alert.sample.auth_failures,
                                    "battery_pct": alert.sample.battery_pct,
                                    "integrity_drift": alert.sample.integrity_drift,
                                    "process_count": alert.sample.process_count,
                                    "disk_pressure_pct": alert.sample.disk_pressure_pct,
                                },
                                "analysis": {
                                    "severity_class": if alert.score >= 5.2 { "critical" }
                                        else if alert.score >= 3.0 { "severe" }
                                        else { "elevated" },
                                    "multi_axis": alert.reasons.len() > 1,
                                    "axis_count": alert.reasons.len(),
                                    "recommendation": if alert.score >= 5.2 {
                                        "Immediate isolation recommended. Investigate all flagged axes and correlate with SIEM events."
                                    } else if alert.score >= 3.0 {
                                        "Elevated investigation priority. Review flagged telemetry and check for lateral movement."
                                    } else {
                                        "Monitor closely. Consider tightening thresholds if pattern persists."
                                    },
                                },
                            });
                            json_response(&detail.to_string(), 200)
                        } else {
                            error_json("alert index out of range", 404)
                        }
                    }
                    Err(_) => error_json("invalid alert index", 400),
                }
            } else {
                error_json("not found", 404)
            }
        }
    };

    let _ = request.respond(response);
}

/// Read the request body with a size limit to prevent OOM from chunked requests.
fn read_body_limited(request: &mut Request, limit: usize) -> Result<String, String> {
    let mut buf = Vec::new();
    let mut reader = std::io::Read::take(request.as_reader(), limit as u64 + 1);
    match std::io::Read::read_to_end(&mut reader, &mut buf) {
        Ok(n) if n > limit => Err("request body too large".to_string()),
        Ok(_) => String::from_utf8(buf).map_err(|_| "invalid UTF-8 in request body".to_string()),
        Err(e) => Err(format!("failed to read request body: {e}")),
    }
}

fn handle_analyze(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };

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
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };

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
    let body = serde_json::json!({"status": format!("mode set to {}", mode_req.mode)});
    json_response(&body.to_string(), 200)
}

fn handle_fleet_register(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
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
    let body = serde_json::json!({"status": "registered", "device": req.device_id});
    json_response(&body.to_string(), 200)
}

fn handle_enforcement_quarantine(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
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
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
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
    let body = serde_json::json!({"status": "added", "value": req.value});
    json_response(&body.to_string(), 200)
}

fn handle_digital_twin_simulate(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
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
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
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
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
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
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
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
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
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

fn handle_config_reload(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    let patch: crate::config::ConfigPatch = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    let mut s = state.lock().unwrap();
    let result = patch.apply(&mut s.config);
    match serde_json::to_string_pretty(&result) {
        Ok(json) => {
            let status = if result.success { 200 } else { 400 };
            json_response(&json, status)
        }
        Err(e) => error_json(&format!("serialization error: {e}"), 500),
    }
}

// ── XDR Handler Functions ────────────────────────────────────────────

fn handle_agent_enroll(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    let req: crate::enrollment::EnrollRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    let mut s = state.lock().unwrap();
    match s.agent_registry.enroll(&req) {
        Ok(resp) => match serde_json::to_string(&resp) {
            Ok(json) => json_response(&json, 200),
            Err(e) => error_json(&format!("serialization error: {e}"), 500),
        },
        Err(e) => error_json(&e, 403),
    }
}

fn handle_agent_create_token(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    #[derive(serde::Deserialize)]
    struct TokenReq {
        #[serde(default = "default_max_uses")]
        max_uses: u32,
    }
    fn default_max_uses() -> u32 {
        10
    }
    let req: TokenReq = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(_) => TokenReq { max_uses: 10 },
    };
    let mut s = state.lock().unwrap();
    let token = s.agent_registry.create_token(req.max_uses);
    match serde_json::to_string(&token) {
        Ok(json) => json_response(&json, 200),
        Err(e) => error_json(&format!("serialization error: {e}"), 500),
    }
}

fn handle_agent_heartbeat(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
    agent_id: &str,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    #[derive(serde::Deserialize)]
    struct HeartbeatReq {
        #[serde(default)]
        version: String,
    }
    let req: HeartbeatReq = serde_json::from_str(&body).unwrap_or(HeartbeatReq {
        version: env!("CARGO_PKG_VERSION").to_string(),
    });
    let mut s = state.lock().unwrap();
    match s.agent_registry.heartbeat(agent_id, &req.version) {
        Ok(()) => json_response(
            &format!(r#"{{"status":"ok","interval_secs":{}}}"#, s.agent_registry.heartbeat_interval()),
            200,
        ),
        Err(e) => error_json(&e, 404),
    }
}

fn handle_agent_update_check(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    // Agent sends GET /api/agents/update?agent_id=xxx&current_version=yyy
    let url = request.url().to_string();
    let query = url.split('?').nth(1).unwrap_or("");
    let mut current_version = String::new();
    let mut platform = String::from("universal");
    for param in query.split('&') {
        if let Some(val) = param.strip_prefix("current_version=") {
            current_version = val.to_string();
        } else if let Some(val) = param.strip_prefix("platform=") {
            platform = val.to_string();
        }
    }
    if current_version.is_empty() {
        current_version = env!("CARGO_PKG_VERSION").to_string();
    }
    let s = state.lock().unwrap();
    let resp = s.update_manager.check_update(&current_version, &platform);
    match serde_json::to_string(&resp) {
        Ok(json) => json_response(&json, 200),
        Err(e) => error_json(&format!("serialization error: {e}"), 500),
    }
}

fn handle_event_ingest(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    let batch: crate::event_forward::EventBatch = match serde_json::from_str(&body) {
        Ok(b) => b,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    let mut s = state.lock().unwrap();
    let result = s.event_store.ingest(&batch);

    // Also forward to SIEM if enabled
    for alert in &batch.events {
        s.siem_connector.queue_alert(alert);
    }

    match serde_json::to_string(&result) {
        Ok(json) => json_response(&json, 200),
        Err(e) => error_json(&format!("serialization error: {e}"), 500),
    }
}

fn handle_policy_publish(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    let policy: crate::policy_dist::Policy = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    let mut s = state.lock().unwrap();
    s.policy_store.publish(policy);
    let version = s.policy_store.current_version();
    json_response(
        &format!(r#"{{"status":"published","version":{version}}}"#),
        200,
    )
}

fn handle_update_publish(
    request: &mut Request,
    state: &Arc<Mutex<AppState>>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = match read_body_limited(request, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    #[derive(serde::Deserialize)]
    struct PublishReq {
        version: String,
        platform: String,
        #[serde(default)]
        binary_base64: String,
        #[serde(default)]
        release_notes: String,
        #[serde(default)]
        mandatory: bool,
    }
    let req: PublishReq = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };

    let binary = match base64_decode(&req.binary_base64) {
        Ok(b) => b,
        Err(e) => return error_json(&format!("invalid base64: {e}"), 400),
    };

    let mut s = state.lock().unwrap();
    match s.update_manager.publish_release(
        &req.version,
        &req.platform,
        &binary,
        &req.release_notes,
        req.mandatory,
    ) {
        Ok(release) => match serde_json::to_string(&release) {
            Ok(json) => json_response(&json, 200),
            Err(e) => error_json(&format!("serialization error: {e}"), 500),
        },
        Err(e) => error_json(&e, 500),
    }
}

/// Simple base64 decoder (no external dependency needed).
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    if input.is_empty() {
        return Ok(Vec::new());
    }
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let input = input.as_bytes();
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    for &b in input {
        if b == b'=' || b == b'\n' || b == b'\r' || b == b' ' {
            continue;
        }
        let val = TABLE.iter().position(|&c| c == b)
            .ok_or_else(|| format!("invalid base64 character: {}", b as char))? as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

fn serve_static(request: Request, site_dir: &Path) {
    let url = request.url();
    let relative = if url == "/" { "/index.html" } else { url };

    // Prevent path traversal via components
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

    // Canonicalize to prevent symlink-based path traversal
    let canon_site = match site_dir.canonicalize() {
        Ok(p) => p,
        Err(_) => { let _ = request.respond(error_json("server error", 500)); return; }
    };
    if let Ok(canon_file) = file_path.canonicalize() {
        if !canon_file.starts_with(&canon_site) {
            let _ = request.respond(error_json("forbidden", 403));
            return;
        }
    }

    if file_path.is_file() {
        let content_type = match file_path.extension().and_then(|e| e.to_str()) {
            Some("html") => "text/html; charset=utf-8",
            Some("js") => "application/javascript; charset=utf-8",
            Some("css") => "text/css; charset=utf-8",
            Some("json") => "application/json",
            Some("csv") => "text/csv",
            Some("svg") => "image/svg+xml",
            Some("png") => "image/png",
            Some("ico") => "image/x-icon",
            Some("woff2") => "font/woff2",
            _ => "application/octet-stream",
        };

        match fs::read(&file_path) {
            Ok(data) => {
                let len = data.len();
                let origin = cors_origin();
                let response = Response::new(
                    tiny_http::StatusCode(200),
                    vec![
                        Header::from_bytes(b"Content-Type", content_type.as_bytes()).unwrap(),
                        Header::from_bytes(b"Access-Control-Allow-Origin", origin.as_bytes()).unwrap(),
                        Header::from_bytes(b"X-Content-Type-Options", b"nosniff").unwrap(),
                        Header::from_bytes(b"X-Frame-Options", b"DENY").unwrap(),
                        Header::from_bytes(b"Cache-Control", b"no-store").unwrap(),
                    ],
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
