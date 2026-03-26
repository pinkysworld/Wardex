use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tiny_http::{Header, Method, Request, Response, Server};

use crate::detector::{AdaptationMode, AnomalyDetector};
use crate::report::JsonReport;
use crate::runtime;
use crate::telemetry::TelemetrySample;

struct AppState {
    detector: AnomalyDetector,
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
        last_report: None,
        token: token.clone(),
    }));

    let site_dir = site_dir.to_path_buf();

    for request in server.incoming_requests() {
        let url = request.url().to_string();

        if url.starts_with("/api/") {
            handle_api(request, &state, &site_dir);
        } else {
            serve_static(request, &site_dir);
        }
    }

    Ok(())
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
            Header::from_bytes(b"Access-Control-Allow-Origin", b"*").unwrap(),
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
                let json = serde_json::to_string_pretty(&report).unwrap_or_default();
                state.lock().unwrap().last_report = Some(report);
                json_response(&json, 200)
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
        (Method::Post, "/api/control/run-demo") => {
            let result = runtime::execute(&runtime::demo_samples());
            let report = JsonReport::from_run_result(&result);
            let json = serde_json::to_string_pretty(&report).unwrap_or_default();
            state.lock().unwrap().last_report = Some(
                serde_json::from_str(&json).unwrap(),
            );
            json_response(&json, 200)
        }
        (Method::Options, _) => {
            let data: Vec<u8> = Vec::new();
            Response::new(
                tiny_http::StatusCode(204),
                vec![
                    Header::from_bytes(b"Access-Control-Allow-Origin", b"*").unwrap(),
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

    // Try JSONL first, then CSV lines
    let samples: Result<Vec<TelemetrySample>, String> = if body.trim_start().starts_with('{') {
        body.lines()
            .filter(|l| !l.trim().is_empty())
            .enumerate()
            .map(|(i, line)| {
                serde_json::from_str(line)
                    .map_err(|e| format!("line {}: {e}", i + 1))
            })
            .collect()
    } else {
        Err("POST body must be JSONL format (one JSON object per line)".into())
    };

    match samples {
        Ok(samples) if !samples.is_empty() => {
            let result = runtime::execute(&samples);
            let report = JsonReport::from_run_result(&result);
            let json = serde_json::to_string_pretty(&report).unwrap_or_default();
            state.lock().unwrap().last_report = Some(
                serde_json::from_str(&json).unwrap(),
            );
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
        "decay" => AdaptationMode::Decay(mode_req.decay_rate.unwrap_or(0.05)),
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
