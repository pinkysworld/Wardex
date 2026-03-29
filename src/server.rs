use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tiny_http::{Header, Method, Request, Response, Server};

use crate::actions::DeviceController;
use crate::checkpoint::CheckpointStore;
use crate::correlation;
use crate::detector::{AdaptationMode, AnomalyDetector};
use crate::proof::{DigestBackend, ProofRegistry};
use crate::replay::ReplayBuffer;
use crate::report::JsonReport;
use crate::runtime;
use crate::state_machine::PolicyStateMachine;
use crate::telemetry::TelemetrySample;

struct AppState {
    detector: AnomalyDetector,
    checkpoints: CheckpointStore,
    device: DeviceController,
    replay: ReplayBuffer,
    proofs: ProofRegistry,
    last_report: Option<JsonReport>,
    token: String,
}

pub fn run_server(port: u16, site_dir: &Path) -> Result<(), String> {
    let addr = format!("0.0.0.0:{port}");
    let server =
        Server::http(&addr).map_err(|e| format!("failed to start server: {e}"))?;

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
    let response = Response::new(
        tiny_http::StatusCode(status),
        vec![
            Header::from_bytes(b"Content-Type", b"application/json").unwrap(),
            Header::from_bytes(b"Access-Control-Allow-Origin", b"http://localhost").unwrap(),
            Header::from_bytes(b"Vary", b"Origin").unwrap(),
        ],
        std::io::Cursor::new(data),
        Some(len),
        None,
    );
    response
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
        if header.field.as_str() == "Authorization" || header.field.as_str() == "authorization" {
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
        (Method::Post, "/api/analyze")
            | (Method::Post, "/api/control/mode")
            | (Method::Post, "/api/control/reset-baseline")
            | (Method::Post, "/api/control/run-demo")
            | (Method::Post, "/api/control/checkpoint")
            | (Method::Post, "/api/control/restore-checkpoint")
    );

    if needs_auth && !check_auth(&request, state) {
        let _ = request.respond(error_json("unauthorized", 401));
        return;
    }

    let response = match (method, url.as_str()) {
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
        (Method::Post, "/api/analyze") => {
            handle_analyze(&mut request, state)
        }
        (Method::Post, "/api/control/mode") => {
            handle_mode(&mut request, state)
        }
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
                        let pre = s.detector.snapshot()
                            .map(|snap| serde_json::to_vec(&snap).unwrap_or_default())
                            .unwrap_or_default();
                        s.detector.evaluate(sample);
                        let post = s.detector.snapshot()
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
        (Method::Options, _) => {
            let data: Vec<u8> = Vec::new();
            Response::new(
                tiny_http::StatusCode(204),
                vec![
                    Header::from_bytes(b"Access-Control-Allow-Origin", b"http://localhost").unwrap(),
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

fn handle_analyze(request: &mut Request, state: &Arc<Mutex<AppState>>) -> Response<std::io::Cursor<Vec<u8>>> {
    let mut body = String::new();
    if std::io::Read::read_to_string(request.as_reader(), &mut body).is_err() {
        return error_json("failed to read request body", 400);
    }

    // Detect format: if the content-type says CSV or the body looks like CSV, parse as CSV
    let is_csv = request.headers().iter().any(|h| {
        h.field.as_str().to_ascii_lowercase() == "content-type"
            && h.value.as_str().contains("csv")
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
                TelemetrySample::parse_line(line, line_num + 1)
                    .map_err(|e| format!("{e}"))
            })
            .collect()
    } else if body.trim_start().starts_with('{') {
        // JSONL — enumerate before filtering so line numbers match the original input
        body.lines()
            .enumerate()
            .filter(|(_, l)| !l.trim().is_empty())
            .map(|(i, line)| {
                serde_json::from_str(line)
                    .map_err(|e| format!("line {}: {e}", i + 1))
            })
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
                let pre = s.detector.snapshot()
                    .map(|snap| serde_json::to_vec(&snap).unwrap_or_default())
                    .unwrap_or_default();
                s.detector.evaluate(sample);
                let post = s.detector.snapshot()
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
        Ok(_) => error_json("no samples in request body", 400),
        Err(e) => error_json(&e, 400),
    }
}

fn handle_mode(request: &mut Request, state: &Arc<Mutex<AppState>>) -> Response<std::io::Cursor<Vec<u8>>> {
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
                    vec![Header::from_bytes(
                        b"Content-Type",
                        content_type.as_bytes(),
                    )
                    .unwrap()],
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
