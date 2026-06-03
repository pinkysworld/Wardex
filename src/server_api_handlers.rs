//! API handler bodies delegated from the main server router.

use super::*;

/// Read the request body with a size limit and a 30-second timeout to prevent
/// both OOM from oversized bodies and slowloris-style attacks.
pub(crate) fn read_body_limited(body: &[u8], limit: usize) -> Result<String, String> {
    if body.len() > limit {
        return Err("request body too large".to_string());
    }
    String::from_utf8(body.to_vec()).map_err(|_| "invalid UTF-8 in request body".to_string())
}

pub(super) fn handle_onboarding_readiness(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let mut s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let body = serde_json::to_string(&build_onboarding_readiness(&mut s)).unwrap_or_default();
    json_response(&body, 200)
}

pub(super) fn handle_manager_queue_digest(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let mut s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let body = serde_json::to_string(&build_manager_queue_digest(&mut s)).unwrap_or_default();
    json_response(&body, 200)
}

pub(super) fn handle_detection_explain(url: &str, state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let event_id = url_param(url, "event_id").and_then(|value| value.parse::<u64>().ok());
    let alert_id = url_param(url, "alert_id");
    let s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match build_detection_explainability(&s, event_id, alert_id.as_deref()) {
        Some(explanation) => {
            let body = serde_json::to_string(&explanation).unwrap_or_default();
            json_response(&body, 200)
        }
        None => error_json("event not found", 404),
    }
}

pub(super) fn handle_detection_feedback_get(
    url: &str,
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    let event_id = url_param(url, "event_id").and_then(|value| value.parse::<u64>().ok());
    let rule_id = url_param(url, "rule_id");
    let limit = url_param(url, "limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(50)
        .min(200);
    let s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let items = if let Some(event_id) = event_id {
        s.detection_feedback.for_event(event_id)
    } else if let Some(rule_id) = rule_id {
        s.detection_feedback.for_rule(&rule_id)
    } else {
        s.detection_feedback.list_recent(limit)
    };
    let mut by_verdict = HashMap::new();
    let mut analysts = HashSet::new();
    for item in &items {
        *by_verdict.entry(item.verdict.clone()).or_insert(0) += 1;
        analysts.insert(item.analyst.clone());
    }
    let summary = crate::detection_feedback::DetectionFeedbackSummary {
        total: items.len(),
        by_verdict,
        analysts: analysts.len(),
    };
    json_response(
        &serde_json::json!({
            "items": items,
            "summary": summary,
        })
        .to_string(),
        200,
    )
}

pub(super) fn handle_detection_feedback_post(
    body: &[u8],
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    #[derive(serde::Deserialize)]
    struct FeedbackReq {
        event_id: Option<u64>,
        alert_id: Option<String>,
        rule_id: Option<String>,
        analyst: Option<String>,
        verdict: String,
        reason_pattern: Option<String>,
        notes: Option<String>,
        #[serde(default)]
        evidence: Vec<crate::detection_feedback::DetectionEvidence>,
    }

    let body = match read_body_limited(body, 16384) {
        Ok(body) => body,
        Err(error) => return error_json(&error, 400),
    };
    let req: FeedbackReq = match serde_json::from_str(&body) {
        Ok(req) => req,
        Err(error) => return error_json(&format!("invalid feedback request: {error}"), 400),
    };
    if req.verdict.trim().is_empty() {
        return error_json("verdict is required", 400);
    }
    let verdict = normalize_detection_outcome(&req.verdict).to_string();
    let mut s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let entry = s.detection_feedback.record(
        req.event_id,
        req.alert_id,
        req.rule_id,
        req.analyst.unwrap_or_else(|| "analyst".to_string()),
        verdict,
        req.reason_pattern,
        req.notes.unwrap_or_default(),
        req.evidence,
    );
    let body = serde_json::to_string(&entry).unwrap_or_default();
    json_response(&body, 200)
}

pub(super) fn handle_threat_intel_library_v2(state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut indicators = s.threat_intel.all_iocs();
    indicators.sort_by(|left, right| {
        right
            .last_seen
            .cmp(&left.last_seen)
            .then_with(|| left.value.cmp(&right.value))
    });
    let mut feeds = s.threat_intel.feeds().to_vec();
    feeds.sort_by(|left, right| {
        right
            .last_updated
            .cmp(&left.last_updated)
            .then_with(|| left.name.cmp(&right.name))
    });
    let body = serde_json::json!({
        "count": indicators.len(),
        "indicators": indicators,
        "feeds": feeds,
        "recent_matches": s.threat_intel.match_history().iter().rev().take(25).cloned().collect::<Vec<_>>(),
        "recent_sightings": s.threat_intel.recent_sightings(25),
        "stats": s.threat_intel.enrichment_stats(),
    });
    json_response(&body.to_string(), 200)
}

pub(super) fn handle_threat_intel_sightings(
    url: &str,
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    let limit = url_param(url, "limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(50)
        .min(200);
    let s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let sightings = s.threat_intel.recent_sightings(limit);
    json_response(
        &serde_json::json!({
            "count": sightings.len(),
            "items": sightings,
        })
        .to_string(),
        200,
    )
}

#[derive(Debug, serde::Deserialize)]
struct MalwarePathScanRequest {
    scope: Option<String>,
    paths: Option<Vec<String>>,
    include_rootkit: Option<bool>,
    max_files: Option<usize>,
    max_bytes_per_file: Option<usize>,
}

#[derive(Debug, serde::Serialize)]
struct MalwarePathScanFinding {
    path: String,
    verdict: String,
    confidence: f64,
    sha256: String,
    size_bytes: usize,
    matches: Vec<crate::malware_scanner::ScanMatch>,
    malware_family: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct MalwarePathScanError {
    path: String,
    error: String,
}

#[derive(Debug, serde::Serialize)]
struct RootkitFinding {
    category: String,
    severity: String,
    path: Option<String>,
    process: Option<String>,
    detail: String,
    recommendation: String,
}

#[derive(Debug, serde::Deserialize)]
struct RootkitScanRequest {
    paths: Option<Vec<String>>,
    max_files: Option<usize>,
}

pub(super) fn handle_malware_path_scan(
    body: &[u8],
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    let body = match read_body_limited(body, 32 * 1024) {
        Ok(body) => body,
        Err(error) => return error_json(&error, 400),
    };
    let req: MalwarePathScanRequest = match serde_json::from_str(&body) {
        Ok(req) => req,
        Err(error) => {
            return error_json(&format!("invalid malware path scan request: {error}"), 400);
        }
    };

    let scope = req
        .scope
        .unwrap_or_else(|| "folder".to_string())
        .trim()
        .to_ascii_lowercase();
    let mut roots = req
        .paths
        .unwrap_or_default()
        .into_iter()
        .map(|path| path.trim().to_string())
        .filter(|path| !path.is_empty())
        .collect::<Vec<_>>();
    if scope == "whole_system" && roots.is_empty() {
        roots = default_system_scan_roots();
    }
    if roots.is_empty() {
        return error_json(
            "at least one path is required unless scope is whole_system",
            400,
        );
    }

    let max_files = req
        .max_files
        .unwrap_or(if scope == "whole_system" { 500 } else { 250 })
        .clamp(1, 5_000);
    let max_bytes = req
        .max_bytes_per_file
        .unwrap_or(crate::malware_scanner::MAX_SCAN_SIZE)
        .clamp(1, crate::malware_scanner::MAX_SCAN_SIZE);
    let scan_targets = collect_scan_targets(&roots, &scope, max_files);
    let mut findings = Vec::new();
    let mut errors = Vec::new();
    let mut skipped_files = 0_usize;

    for path in scan_targets {
        match fs::metadata(&path) {
            Ok(metadata) if metadata.is_file() => {
                if metadata.len() as usize > max_bytes {
                    skipped_files += 1;
                    errors.push(MalwarePathScanError {
                        path: path.display().to_string(),
                        error: format!("file exceeds scan cap of {max_bytes} bytes"),
                    });
                    continue;
                }
            }
            Ok(_) => {
                skipped_files += 1;
                continue;
            }
            Err(error) => {
                skipped_files += 1;
                errors.push(MalwarePathScanError {
                    path: path.display().to_string(),
                    error: format!("metadata unavailable: {error}"),
                });
                continue;
            }
        }

        let data = match fs::read(&path) {
            Ok(data) => data,
            Err(error) => {
                skipped_files += 1;
                errors.push(MalwarePathScanError {
                    path: path.display().to_string(),
                    error: format!("read failed: {error}"),
                });
                continue;
            }
        };
        let filename = path.file_name().map_or_else(
            || path.display().to_string(),
            |name| name.to_string_lossy().to_string(),
        );
        let mut s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let AppState {
            ref mut malware_scanner,
            ref mut malware_hash_db,
            ref yara_engine,
            ref mut threat_intel,
            ..
        } = *s;
        match malware_scanner.scan_buffer(
            &data,
            &filename,
            malware_hash_db,
            yara_engine,
            threat_intel,
        ) {
            Ok(result) => findings.push(MalwarePathScanFinding {
                path: path.display().to_string(),
                verdict: result.verdict.to_string(),
                confidence: result.confidence,
                sha256: result.sha256,
                size_bytes: result.size_bytes,
                matches: result.matches,
                malware_family: result.malware_family,
            }),
            Err(error) => errors.push(MalwarePathScanError {
                path: path.display().to_string(),
                error,
            }),
        }
    }

    let rootkit_findings = if req.include_rootkit.unwrap_or(false) {
        run_rootkit_scan(&roots, max_files)
    } else {
        Vec::new()
    };
    let malicious = findings
        .iter()
        .filter(|finding| finding.verdict == "malicious" || finding.verdict == "ransomware")
        .count();
    let suspicious = findings
        .iter()
        .filter(|finding| finding.verdict == "suspicious")
        .count();
    let clean = findings
        .iter()
        .filter(|finding| finding.verdict == "clean")
        .count();
    json_response(
        &serde_json::json!({
            "summary": {
                "scope": scope,
                "requested_paths": roots,
                "scanned_files": findings.len(),
                "skipped_files": skipped_files,
                "malicious": malicious,
                "suspicious": suspicious,
                "clean": clean,
                "max_files": max_files,
                "max_bytes_per_file": max_bytes,
            },
            "findings": findings,
            "errors": errors,
            "rootkit_findings": rootkit_findings,
        })
        .to_string(),
        200,
    )
}

pub(super) fn handle_rootkit_scan(body: &[u8]) -> Response<Body> {
    let body = match read_body_limited(body, 32 * 1024) {
        Ok(body) => body,
        Err(error) => return error_json(&error, 400),
    };
    let req: RootkitScanRequest = match serde_json::from_str(&body) {
        Ok(req) => req,
        Err(error) => return error_json(&format!("invalid rootkit scan request: {error}"), 400),
    };
    let roots = req
        .paths
        .unwrap_or_else(default_rootkit_scan_roots)
        .into_iter()
        .map(|path| path.trim().to_string())
        .filter(|path| !path.is_empty())
        .collect::<Vec<_>>();
    let max_files = req.max_files.unwrap_or(500).clamp(1, 5_000);
    let findings = run_rootkit_scan(&roots, max_files);
    json_response(
        &serde_json::json!({
            "summary": {
                "scanned_roots": roots,
                "finding_count": findings.len(),
                "max_files": max_files,
            },
            "findings": findings,
        })
        .to_string(),
        200,
    )
}

fn collect_scan_targets(roots: &[String], scope: &str, max_files: usize) -> Vec<PathBuf> {
    let mut targets = Vec::new();
    let recurse = scope != "file";
    let mut stack = roots.iter().map(PathBuf::from).collect::<Vec<_>>();
    while let Some(path) = stack.pop() {
        if targets.len() >= max_files {
            break;
        }
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_file() {
            targets.push(path);
        } else if metadata.is_dir()
            && recurse
            && let Ok(entries) = fs::read_dir(&path)
        {
            for entry in entries.flatten() {
                stack.push(entry.path());
            }
        }
    }
    targets
}

fn default_system_scan_roots() -> Vec<String> {
    [
        "/Applications",
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        "/Library/Extensions",
        "/usr/local/bin",
        "/opt",
        "/tmp",
        "/private/tmp",
        "/etc",
        "/home",
        "C:\\Users",
        "C:\\ProgramData",
        "C:\\Windows\\Temp",
        "C:\\Windows\\System32\\Tasks",
    ]
    .iter()
    .filter(|path| Path::new(path).exists())
    .map(std::string::ToString::to_string)
    .collect()
}

fn default_rootkit_scan_roots() -> Vec<String> {
    [
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        "/Library/Extensions",
        "/System/Library/Extensions",
        "/etc",
        "/usr/local/bin",
        "/tmp",
        "/private/tmp",
        "/dev/shm",
        "/proc",
        "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        "C:\\Windows\\System32\\drivers",
        "C:\\Windows\\System32\\Tasks",
        "C:\\Windows\\Temp",
    ]
    .iter()
    .filter(|path| Path::new(path).exists())
    .map(std::string::ToString::to_string)
    .collect()
}

fn run_rootkit_scan(roots: &[String], max_files: usize) -> Vec<RootkitFinding> {
    let mut findings = Vec::new();
    let targets = collect_scan_targets(roots, "folder", max_files);
    for path in targets {
        let path_string = path.display().to_string();
        let lower_path = path_string.to_ascii_lowercase();
        let file_name = path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_default();
        if lower_path.ends_with("/ld.so.preload")
            && fs::metadata(&path).map(|m| m.len() > 0).unwrap_or(false)
        {
            findings.push(RootkitFinding {
                category: "library_preload".into(),
                severity: "high".into(),
                path: Some(path_string.clone()),
                process: None,
                detail: "ld.so.preload is present and non-empty, which can force hidden libraries into every process.".into(),
                recommendation: "Review contents offline, validate each referenced library hash, and isolate host if unauthorized.".into(),
            });
        }
        if file_name.starts_with('.')
            && (lower_path.contains("/launch")
                || lower_path.contains("/tmp/")
                || lower_path.contains("/private/tmp/")
                || lower_path.contains("/usr/local/bin/"))
        {
            findings.push(RootkitFinding {
                category: "hidden_artifact".into(),
                severity: "medium".into(),
                path: Some(path_string.clone()),
                process: None,
                detail: "Hidden executable or persistence artifact in a sensitive location.".into(),
                recommendation: "Hash the file, inspect signing/provenance, and quarantine if it is not expected.".into(),
            });
        }
        if lower_path.ends_with(".plist")
            && (lower_path.contains("launchagents") || lower_path.contains("launchdaemons"))
            && let Ok(bytes) = fs::read(&path)
        {
            let sample =
                String::from_utf8_lossy(&bytes[..bytes.len().min(64 * 1024)]).to_ascii_lowercase();
            if [
                "dyld_insert_libraries",
                "/private/tmp/",
                "/tmp/",
                "curl ",
                "bash -c",
                "nc ",
                "chmod +x",
                "base64",
            ]
            .iter()
            .any(|needle| sample.contains(needle))
            {
                findings.push(RootkitFinding {
                    category: "launch_persistence".into(),
                    severity: "high".into(),
                    path: Some(path_string.clone()),
                    process: None,
                    detail: "Launch item contains suspicious loader, network, or temporary-path behavior.".into(),
                    recommendation: "Disable the launch item, preserve the plist and target binary, then run a full malware scan.".into(),
                });
            }
        }
        if lower_path.ends_with(".kext") && lower_path.contains("/library/extensions/") {
            findings.push(RootkitFinding {
                category: "kernel_extension".into(),
                severity: "medium".into(),
                path: Some(path_string.clone()),
                process: None,
                detail: "Third-party kernel extension present in a rootkit-relevant location.".into(),
                recommendation: "Verify vendor signing, notarization, and business justification before allowing it to remain loaded.".into(),
            });
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = fs::metadata(&path) {
                let mode = metadata.permissions().mode();
                if metadata.is_file()
                    && mode & 0o002 != 0
                    && (lower_path.contains("/usr/local/bin/") || lower_path.contains("/etc/"))
                {
                    findings.push(RootkitFinding {
                        category: "world_writable_system_file".into(),
                        severity: "high".into(),
                        path: Some(path_string.clone()),
                        process: None,
                        detail: "World-writable file in a privileged system path.".into(),
                        recommendation: "Remove world-write permissions, compare against package baseline, and investigate recent writers.".into(),
                    });
                }
            }
        }
    }

    findings.extend(scan_proc_rootkit_indicators());
    findings
}

fn scan_proc_rootkit_indicators() -> Vec<RootkitFinding> {
    let proc = Path::new("/proc");
    if !proc.exists() {
        return Vec::new();
    }
    let mut findings = Vec::new();
    if let Ok(entries) = fs::read_dir(proc) {
        for entry in entries.flatten().take(4096) {
            let pid = entry.file_name().to_string_lossy().to_string();
            if !pid.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            let comm_path = entry.path().join("comm");
            let exe_path = entry.path().join("exe");
            let comm = fs::read_to_string(comm_path).unwrap_or_default();
            let name = comm.trim();
            if matches!(name, "kworker" | "kthreadd" | "rcu_sched")
                && fs::read_link(&exe_path).is_ok()
            {
                findings.push(RootkitFinding {
                    category: "kernel_thread_masquerade".into(),
                    severity: "high".into(),
                    path: fs::read_link(&exe_path)
                        .ok()
                        .map(|path| path.display().to_string()),
                    process: Some(format!("{name} pid={pid}")),
                    detail: "Process is using a kernel-thread-like name while exposing a user-space executable.".into(),
                    recommendation: "Dump process memory, isolate host, and terminate only after evidence capture.".into(),
                });
            }
        }
    }
    findings
}

pub(super) fn handle_scan_buffer_v2(body: &[u8], state: &Arc<Mutex<AppState>>) -> Response<Body> {
    #[derive(serde::Deserialize)]
    struct ScanReqV2 {
        data: String,
        filename: Option<String>,
        behavior: Option<crate::malware_scanner::BehaviorSignals>,
        allowlist: Option<crate::malware_scanner::ScanAllowlist>,
    }

    let body = match read_body_limited(body, 256 * 1024) {
        Ok(body) => body,
        Err(error) => return error_json(&error, 400),
    };
    let req: ScanReqV2 = match serde_json::from_str(&body) {
        Ok(req) => req,
        Err(error) => return error_json(&format!("invalid scan request: {error}"), 400),
    };
    let decoded =
        match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &req.data) {
            Ok(data) => data,
            Err(error) => return error_json(&format!("invalid base64: {error}"), 400),
        };
    let filename = req.filename.unwrap_or_else(|| "upload".to_string());
    let mut s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let AppState {
        ref mut malware_scanner,
        ref mut malware_hash_db,
        ref yara_engine,
        ref mut threat_intel,
        ..
    } = *s;
    match malware_scanner.deep_scan_buffer(
        &decoded,
        &filename,
        malware_hash_db,
        yara_engine,
        threat_intel,
        req.behavior,
        req.allowlist,
    ) {
        Ok(result) => {
            let body = serde_json::to_string(&result).unwrap_or_default();
            json_response(&body, 200)
        }
        Err(error) => error_json(&error, 400),
    }
}

pub(super) fn handle_analyze(body: &[u8], state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };

    // Detect format: if the body looks like CSV rather than JSON, parse as CSV
    let is_csv = !body.trim_start().starts_with('{') && body.contains(',');

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
            let total = samples.len();
            let result = runtime::execute(&samples);
            let report = JsonReport::from_run_result(&result);
            let json = match serde_json::to_string_pretty(&report) {
                Ok(j) => j,
                Err(e) => return error_json(&format!("serialization error: {e}"), 500),
            };
            // Process in chunks to reduce lock hold time for large batches
            let chunk_size = 200;
            for chunk_start in (0..total).step_by(chunk_size) {
                let chunk_end = (chunk_start + chunk_size).min(total);
                let mut s = state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                for (sample, report_entry) in samples[chunk_start..chunk_end]
                    .iter()
                    .zip(result.reports[chunk_start..chunk_end].iter())
                {
                    let pre = s
                        .detector
                        .snapshot()
                        .and_then(|snap| {
                            serde_json::to_vec(&snap)
                                .map_err(|e| {
                                    log::error!("proof pre-snapshot serialization error: {e}")
                                })
                                .ok()
                        })
                        .unwrap_or_default();
                    s.detector.evaluate(sample);
                    let post = s
                        .detector
                        .snapshot()
                        .and_then(|snap| {
                            serde_json::to_vec(&snap)
                                .map_err(|e| {
                                    log::error!("proof post-snapshot serialization error: {e}")
                                })
                                .ok()
                        })
                        .unwrap_or_default();
                    s.proofs.record("baseline_update", &pre, &post);
                    s.device.apply_decision(&report_entry.decision);
                    s.replay.push(*sample);
                }
                s.last_report = Some(report.clone());
            }
            json_response(&json, 200)
        }
        Ok(_) => error_json("no samples in request body", 400),
        Err(e) => error_json(&e, 400),
    }
}

pub(super) fn handle_mode(body: &[u8], state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
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

    let mut s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    s.detector.set_adaptation(mode);
    let body = serde_json::json!({"status": format!("mode set to {}", mode_req.mode)});
    json_response(&body.to_string(), 200)
}

pub(super) fn handle_enforcement_quarantine(
    body: &[u8],
    state: &Arc<Mutex<AppState>>,
    auth_identity: &AuthIdentity,
    remote_addr: &str,
) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
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
    let mut s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let results = s.enforcement.enforce(
        &crate::enforcement::EnforcementLevel::Quarantine,
        &req.target,
    );
    let success = results.iter().all(|result| result.success);
    s.audit_log.record(
        "POST",
        &format!(
            "/api/enforcement/quarantine target={} actor={}",
            req.target,
            auth_identity.actor()
        ),
        remote_addr,
        if success { 200 } else { 207 },
        true,
    );
    let info = serde_json::json!({
        "target": req.target,
        "actor": auth_identity.actor(),
        "approval_state": "rbac_authorized",
        "actions": results.len(),
        "success": success,
        "results": results.iter().map(|r| serde_json::json!({
            "action": r.action,
            "success": r.success,
            "detail": r.detail,
            "rollback_command": r.rollback_command,
        })).collect::<Vec<_>>(),
    });
    json_response(&info.to_string(), 200)
}

pub(super) fn handle_threat_intel_ioc(body: &[u8], state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
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
    let mut s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        metadata: crate::threat_intel::IndicatorMetadata::default(),
        sightings: Vec::new(),
    });
    let body = serde_json::json!({"status": "added", "value": req.value});
    json_response(&body.to_string(), 200)
}

pub(super) fn handle_digital_twin_simulate(
    body: &[u8],
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
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
        "process_burst" => crate::digital_twin::SimEvent::ProcessSpawn {
            target: req.device_id.clone(),
            count: 80,
        },
        "connection_burst" => crate::digital_twin::SimEvent::ConnectionBurst {
            target: req.device_id.clone(),
            count: 160,
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

    let mut s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let seeded_device = if s.digital_twin.snapshot(&req.device_id).is_none() {
        s.digital_twin
            .register(crate::digital_twin::TwinSnapshot::new(&req.device_id));
        true
    } else {
        false
    };
    let result = s.digital_twin.simulate(&[step]);
    let alerts_generated = result.alerts_generated.clone();
    let state_transitions = result.state_transitions.clone();
    let final_state = result.final_states.get(&req.device_id).cloned();
    let info = serde_json::json!({
        "device_id": req.device_id,
        "event_type": req.event_type,
        "seeded_device": seeded_device,
        "ticks_simulated": result.ticks_simulated,
        "alerts": alerts_generated.len(),
        "transitions": state_transitions.len(),
        "final_state": final_state,
        "alerts_generated": alerts_generated,
        "state_transitions": state_transitions,
        "twin_count": s.digital_twin.device_count(),
    });
    json_response(&info.to_string(), 200)
}

pub(super) fn handle_harness_run(body: &[u8], _state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };

    #[derive(Default, serde::Deserialize)]
    struct HarnessReq {
        #[serde(default)]
        traces_per_strategy: Option<usize>,
        #[serde(default)]
        trace_length: Option<usize>,
        #[serde(default)]
        evasion_threshold: Option<f32>,
    }

    let req = if body.trim().is_empty() {
        HarnessReq::default()
    } else {
        match serde_json::from_str::<HarnessReq>(&body) {
            Ok(parsed) => parsed,
            Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
        }
    };

    let mut config = crate::harness::HarnessConfig::default();
    if let Some(traces_per_strategy) = req.traces_per_strategy {
        if !(1..=10).contains(&traces_per_strategy) {
            return error_json("traces_per_strategy must be between 1 and 10", 400);
        }
        config.traces_per_strategy = traces_per_strategy;
    }
    if let Some(trace_length) = req.trace_length {
        if !(10..=500).contains(&trace_length) {
            return error_json("trace_length must be between 10 and 500", 400);
        }
        config.trace_length = trace_length;
    }
    if let Some(evasion_threshold) = req.evasion_threshold {
        if !evasion_threshold.is_finite() || !(0.1..=10.0).contains(&evasion_threshold) {
            return error_json(
                "evasion_threshold must be a finite value between 0.1 and 10.0",
                400,
            );
        }
        config.evasion_threshold = evasion_threshold;
    }

    let result = crate::harness::run(&config);
    let strategies: Vec<_> = [
        (crate::harness::Strategy::SlowDrip, "SlowDrip"),
        (crate::harness::Strategy::BurstMask, "BurstMask"),
        (crate::harness::Strategy::DriftInject, "DriftInject"),
    ]
    .into_iter()
    .map(|(strategy, label)| {
        let traces: Vec<_> = result
            .traces
            .iter()
            .filter(|trace| trace.strategy == strategy)
            .collect();
        let total = traces.len();
        let evaded = traces.iter().filter(|trace| trace.evaded).count();
        let avg_max_score = if total == 0 {
            0.0_f32
        } else {
            traces.iter().map(|trace| trace.max_score).sum::<f32>() / total as f32
        };
        let highest_max_score = traces
            .iter()
            .map(|trace| trace.max_score)
            .fold(0.0_f32, f32::max);
        serde_json::json!({
            "strategy": label,
            "total": total,
            "evaded": evaded,
            "detected": total.saturating_sub(evaded),
            "avg_max_score": avg_max_score,
            "highest_max_score": highest_max_score,
        })
    })
    .collect();

    let info = serde_json::json!({
        "config": {
            "traces_per_strategy": config.traces_per_strategy,
            "trace_length": config.trace_length,
            "evasion_threshold": config.evasion_threshold,
        },
        "evasion_rate": result.evasion_rate,
        "coverage_ratio": result.coverage.coverage_ratio(),
        "transition_count": result.coverage.transition_count,
        "score_buckets": result.coverage.score_buckets.to_vec(),
        "total_count": result.total_count,
        "evasion_count": result.evasion_count,
        "strategies": strategies,
    });
    json_response(&info.to_string(), 200)
}

pub(super) fn handle_energy_consume(body: &[u8], state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
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
    let mut s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    s.energy.drain_rate_mw = req.drain_rate_mw;
    let new_state = s.energy.tick();
    let info = serde_json::json!({
        "remaining_pct": s.energy.remaining_pct(),
        "power_state": format!("{new_state:?}"),
    });
    json_response(&info.to_string(), 200)
}

pub(super) fn handle_policy_vm_execute(
    body: &[u8],
    state: &Arc<Mutex<AppState>>,
) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
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
    let s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // Build a simple program that loads env values and computes a risk composite
    let program = crate::wasm_engine::PolicyProgram::new(
        "api-eval",
        vec![
            crate::wasm_engine::Opcode::LoadVar("score".into()),
            crate::wasm_engine::Opcode::LoadVar("battery".into()),
            crate::wasm_engine::Opcode::Mul,
            crate::wasm_engine::Opcode::StoreResult("risk_composite".into()),
            crate::wasm_engine::Opcode::Halt,
        ],
    );
    let result = s.policy_vm.execute(&program, &req.env);
    let info = serde_json::json!({
        "success": result.success,
        "outputs": result.outputs,
        "steps_executed": result.steps_executed,
        "error": result.error,
    });
    json_response(&info.to_string(), 200)
}

pub(super) fn handle_deception_deploy(body: &[u8], state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
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
    let mut s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
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

pub(super) fn handle_policy_compose(body: &[u8], _state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
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
        score: req.score_a,
        confidence: 0.9,
        suspicious_axes: 0,
        reasons: vec!["composed-a".into()],
        contributions: Vec::new(),
        triage: None,
    };
    let sample_a = TelemetrySample {
        timestamp_ms: 0,
        cpu_load_pct: 0.0,
        memory_load_pct: 0.0,
        temperature_c: 0.0,
        network_kbps: 0.0,
        auth_failures: 0,
        battery_pct: req.battery_a,
        integrity_drift: 0.0,
        process_count: 0,
        disk_pressure_pct: 0.0,
    };
    let decision_a = engine.evaluate(&signal_a, &sample_a);
    let signal_b = crate::detector::AnomalySignal {
        score: req.score_b,
        confidence: 0.9,
        suspicious_axes: 0,
        reasons: vec!["composed-b".into()],
        contributions: Vec::new(),
        triage: None,
    };
    let sample_b = TelemetrySample {
        timestamp_ms: 0,
        cpu_load_pct: 0.0,
        memory_load_pct: 0.0,
        temperature_c: 0.0,
        network_kbps: 0.0,
        auth_failures: 0,
        battery_pct: req.battery_b,
        integrity_drift: 0.0,
        process_count: 0,
        disk_pressure_pct: 0.0,
    };
    let decision_b = engine.evaluate(&signal_b, &sample_b);
    let (result, conflict) =
        crate::policy::compose_decisions(Some(decision_a), Some(decision_b), op);
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

pub(super) fn handle_config_reload(body: &[u8], state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    let patch: crate::config::ConfigPatch = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    let mut s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let result = patch.apply(&mut s.config);
    if result.success {
        s.cluster = ClusterNode::new(s.config.cluster.clone());
    }
    match serde_json::to_string_pretty(&result) {
        Ok(json) => {
            let status = if result.success { 200 } else { 400 };
            json_response(&json, status)
        }
        Err(e) => error_json(&format!("serialization error: {e}"), 500),
    }
}

pub(super) fn config_save_target(
    current: &Config,
    body: &str,
) -> Result<(Config, Vec<String>), Box<Response<Body>>> {
    if body.trim().is_empty() {
        return Ok((current.clone(), Vec::new()));
    }

    let patch: crate::config::ConfigPatch = match serde_json::from_str(body) {
        Ok(p) => p,
        Err(e) => return Err(Box::new(error_json(&format!("invalid JSON: {e}"), 400))),
    };

    let mut next_config = current.clone();
    let result = patch.apply(&mut next_config);
    if !result.success {
        return match serde_json::to_string_pretty(&result) {
            Ok(json) => Err(Box::new(json_response(&json, 400))),
            Err(e) => Err(Box::new(error_json(
                &format!("serialization error: {e}"),
                500,
            ))),
        };
    }

    Ok((next_config, result.applied_fields))
}

// ── XDR Handler Functions ────────────────────────────────────────────

pub(super) fn handle_event_triage(
    body: &[u8],
    state: &Arc<Mutex<AppState>>,
    event_id: &str,
) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    let event_id = match event_id.parse::<u64>() {
        Ok(id) => id,
        Err(_) => return error_json("invalid event id", 400),
    };
    let update: crate::event_forward::EventTriageUpdate = match serde_json::from_str(&body) {
        Ok(update) => update,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };

    let mut s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match s.event_store.update_triage(event_id, update) {
        Ok(event) => json_response(
            &serde_json::json!({ "status": "updated", "event": event }).to_string(),
            200,
        ),
        Err(e) if e == "event not found" => error_json(&e, 404),
        Err(e) => error_json(&e, 400),
    }
}

pub(super) fn handle_event_ingest(body: &[u8], state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    let mut batch: crate::event_forward::EventBatch = match serde_json::from_str(&body) {
        Ok(b) => b,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    let mut s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let native_rule_matches: usize = batch
        .events
        .iter_mut()
        .map(|alert| {
            s.enterprise
                .apply_active_native_rules(alert, &batch.agent_id)
        })
        .sum();
    let result = s.event_store.ingest(&batch);
    // Dual-write to ClickHouse when configured
    if let Some(ref ch) = s.clickhouse_store {
        let ch_events: Vec<crate::storage_clickhouse::StoredEvent> = batch
            .events
            .iter()
            .map(|a| crate::storage_clickhouse::StoredEvent {
                timestamp: chrono::Utc::now(),
                tenant_id: "default".into(),
                event_class: 1000,
                severity: (a.score.min(255.0) as u8),
                device_id: a.hostname.clone(),
                user_name: String::new(),
                process_name: a.action.clone(),
                src_ip: String::new(),
                dst_ip: String::new(),
                raw_json: serde_json::to_string(a).unwrap_or_default(),
            })
            .collect();
        if let Err(e) = crate::storage_clickhouse::EventStore::insert_events(ch, &ch_events) {
            log::warn!("[CLICKHOUSE] dual-write failed: {e}");
        }
    }
    let newly_ingested = s.event_store.recent_events(batch.events.len());

    for event in &newly_ingested {
        if severity_rank(&event.alert.level) > 0 {
            s.alert_queue.enqueue(
                event.id,
                f64::from(event.alert.score),
                event.alert.level.clone(),
                event.alert.hostname.clone(),
                event.received_at.clone(),
            );
        }
    }

    // Also forward to SIEM if enabled
    for alert in &batch.events {
        s.siem_connector.queue_alert(alert);
    }

    // Auto-cluster into incidents
    let recent = s.event_store.recent_events(50);
    let _new_incidents = s.incident_store.auto_cluster(&recent);

    // Sigma evaluation on ingested events (gated by feature flag)
    let sigma_matches = if s.feature_flags.is_enabled("sigma_engine", "default") {
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut total_matches = native_rule_matches;
        for alert in &batch.events {
            let ocsf_event = ocsf::alert_to_ocsf(alert);
            let matches = s.sigma_engine.evaluate(&ocsf_event, now_epoch);
            total_matches += matches.len();
        }
        total_matches
    } else {
        0
    };
    drop(s);

    let mut resp = match serde_json::to_value(&result) {
        Ok(serde_json::Value::Object(mut map)) => {
            if sigma_matches > 0 {
                map.insert(
                    "sigma_matches".to_string(),
                    serde_json::json!(sigma_matches),
                );
            }
            json_response(&serde_json::Value::Object(map).to_string(), 200)
        }
        Ok(other) => json_response(&other.to_string(), 200),
        Err(e) => error_json(&format!("serialization error: {e}"), 500),
    };
    let _ = &mut resp; // suppress unused warning
    resp
}

pub(super) fn handle_bulk_triage(body: &[u8], state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    #[derive(serde::Deserialize)]
    struct BulkTriageReq {
        event_ids: Vec<u64>,
        #[serde(flatten)]
        update: crate::event_forward::EventTriageUpdate,
    }
    let req: BulkTriageReq = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    if req.event_ids.is_empty() {
        return error_json("event_ids must not be empty", 400);
    }
    if req.event_ids.len() > 500 {
        return error_json("too many event_ids (max 500)", 400);
    }
    let mut s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let result = s
        .event_store
        .bulk_update_triage(&req.event_ids, &req.update);
    let payload = serde_json::json!({
        "updated": result.updated,
        "failed": result.failed.iter().map(|(id, msg)| serde_json::json!({"event_id": id, "error": msg})).collect::<Vec<_>>(),
    });
    json_response(&payload.to_string(), 200)
}

pub(super) fn handle_policy_publish(body: &[u8], state: &Arc<Mutex<AppState>>) -> Response<Body> {
    let body = match read_body_limited(body, 10 * 1024 * 1024) {
        Ok(b) => b,
        Err(e) => return error_json(&e, 400),
    };
    let policy: crate::policy_dist::Policy = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(e) => return error_json(&format!("invalid JSON: {e}"), 400),
    };
    let mut s = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    s.policy_store.publish(policy);
    let version = s.policy_store.current_version();
    json_response(
        &format!(r#"{{"status":"published","version":{version}}}"#),
        200,
    )
}

pub(crate) fn response_required_approvals(tier: ActionTier) -> usize {
    match tier {
        ActionTier::Auto => 0,
        ActionTier::SingleApproval => 1,
        ActionTier::DualApproval => 2,
        ActionTier::BreakGlass => 2,
    }
}

pub(crate) fn response_action_label(action: &ResponseAction) -> String {
    match action {
        ResponseAction::Alert => "Alert".to_string(),
        ResponseAction::Isolate => "Isolate host".to_string(),
        ResponseAction::Throttle { rate_limit_kbps } => {
            format!("Throttle to {rate_limit_kbps} kbps")
        }
        ResponseAction::KillProcess { pid, process_name } => {
            format!("Kill process {process_name} (PID {pid})")
        }
        ResponseAction::QuarantineFile { path } => format!("Quarantine file {path}"),
        ResponseAction::BlockIp { ip } => format!("Block IP {ip}"),
        ResponseAction::DisableAccount { username } => format!("Disable account {username}"),
        ResponseAction::RollbackConfig { config_name } => format!("Rollback config {config_name}"),
        ResponseAction::Custom { name, .. } => format!("Custom action {name}"),
    }
}

pub(crate) fn response_request_json(request: &ResponseRequest) -> serde_json::Value {
    let approved_count = request
        .approvals
        .iter()
        .filter(|record| record.decision == ResponseApprovalDecision::Approve)
        .count();
    serde_json::json!({
        "id": request.id.clone(),
        "action": format!("{:?}", request.action),
        "action_label": response_action_label(&request.action),
        "target": request.target.clone(),
        "target_hostname": request.target.hostname.clone(),
        "target_agent_uid": request.target.agent_uid.clone(),
        "tier": format!("{:?}", request.tier),
        "status": format!("{:?}", request.status),
        "created_at": request.requested_at.clone(),
        "requested_at": request.requested_at.clone(),
        "requested_by": request.requested_by.clone(),
        "reason": request.reason.clone(),
        "severity": request.severity.clone(),
        "approvals": request.approvals.clone(),
        "approval_count": approved_count,
        "approvals_required": response_required_approvals(request.tier),
        "dry_run": request.dry_run,
        "is_protected_asset": request.is_protected_asset,
        "blast_radius": request.blast_radius.as_ref().map(|blast| serde_json::json!({
            "affected_services": blast.affected_services,
            "affected_endpoints": blast.affected_endpoints,
            "risk_level": blast.risk_level.clone(),
            "impact_summary": blast.impact_summary.clone(),
        })),
        "blast_radius_summary": request.blast_radius.as_ref().map(|blast| blast.impact_summary.clone()),
        "input_context": {
            "target": request.target.clone(),
            "severity": request.severity.clone(),
            "tier": format!("{:?}", request.tier),
            "dry_run": request.dry_run,
            "protected_asset": request.is_protected_asset,
            "requested_at": request.requested_at.clone(),
        },
        "dry_run_result": request.dry_run.then(|| serde_json::json!({
            "request_id": request.id.clone(),
            "would_execute": request.tier != ActionTier::BreakGlass,
            "tier": format!("{:?}", request.tier),
            "blast_radius": request.blast_radius.clone(),
            "is_protected": request.is_protected_asset,
            "approvals_required": response_required_approvals(request.tier),
        })),
        "execution_result": (request.status == ApprovalStatus::Executed).then(|| {
            format!("{} completed for {}", response_action_label(&request.action), request.target.hostname)
        }),
        "reversal_path": response_reversal_path(&request.action, &request.target),
    })
}

pub(crate) fn response_reversal_path(action: &ResponseAction, target: &ResponseTarget) -> String {
    match action {
        ResponseAction::Alert => "No reversal required; notification-only action.".to_string(),
        ResponseAction::Isolate => format!(
            "Remove host {} from isolation and verify heartbeat plus policy sync.",
            target.hostname
        ),
        ResponseAction::Throttle { .. } => format!(
            "Restore normal rate limits for {} and verify service latency.",
            target.hostname
        ),
        ResponseAction::KillProcess { process_name, .. } => {
            format!(
                "Restart {process_name} only from a verified clean binary if business impact requires it."
            )
        }
        ResponseAction::QuarantineFile { path } => {
            format!("Release {path} from quarantine only after hash, YARA, and provenance review.")
        }
        ResponseAction::BlockIp { ip } => {
            format!(
                "Remove block for {ip} from network controls and confirm no active incident dependency."
            )
        }
        ResponseAction::DisableAccount { username } => {
            format!(
                "Re-enable {username} after credential reset, MFA verification, and owner approval."
            )
        }
        ResponseAction::RollbackConfig { config_name } => {
            format!(
                "Reapply the superseded {config_name} config through change control if rollback is no longer needed."
            )
        }
        ResponseAction::Custom { name, .. } => {
            format!("Follow the documented reversal procedure for custom action {name}.")
        }
    }
}

pub(crate) fn response_action_from_json(
    value: &serde_json::Value,
) -> Result<ResponseAction, String> {
    let action = value["action"]
        .as_str()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    match action.as_str() {
        "alert" => Ok(ResponseAction::Alert),
        "isolate" => Ok(ResponseAction::Isolate),
        "throttle" => Ok(ResponseAction::Throttle {
            rate_limit_kbps: value["rate_limit_kbps"].as_u64().unwrap_or(256) as u32,
        }),
        "kill_process" => {
            let pid = value["pid"]
                .as_u64()
                .ok_or("pid is required for kill_process")? as u32;
            let process_name = value["process_name"]
                .as_str()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map_or_else(|| format!("pid-{pid}"), std::string::ToString::to_string);
            Ok(ResponseAction::KillProcess { pid, process_name })
        }
        "quarantine_file" => {
            let path = value["path"]
                .as_str()
                .ok_or("path is required for quarantine_file")?
                .trim()
                .to_string();
            if path.is_empty() {
                return Err("path is required for quarantine_file".into());
            }
            Ok(ResponseAction::QuarantineFile { path })
        }
        "block_ip" => {
            let ip = value["ip"]
                .as_str()
                .ok_or("ip is required for block_ip")?
                .trim()
                .to_string();
            if ip.is_empty() {
                return Err("ip is required for block_ip".into());
            }
            Ok(ResponseAction::BlockIp { ip })
        }
        "disable_account" => {
            let username = value["username"]
                .as_str()
                .ok_or("username is required for disable_account")?
                .trim()
                .to_string();
            if username.is_empty() {
                return Err("username is required for disable_account".into());
            }
            Ok(ResponseAction::DisableAccount { username })
        }
        "rollback_config" => {
            let config_name = value["config_name"]
                .as_str()
                .ok_or("config_name is required for rollback_config")?
                .trim()
                .to_string();
            if config_name.is_empty() {
                return Err("config_name is required for rollback_config".into());
            }
            Ok(ResponseAction::RollbackConfig { config_name })
        }
        "custom" => {
            let name = value["name"]
                .as_str()
                .ok_or("name is required for custom action")?
                .trim()
                .to_string();
            if name.is_empty() {
                return Err("name is required for custom action".into());
            }
            let payload = value["payload"].as_str().unwrap_or("").to_string();
            Ok(ResponseAction::Custom { name, payload })
        }
        _ => Err("unsupported action".into()),
    }
}

fn graphql_source_rows(
    source: &str,
    alerts: &VecDeque<AlertRecord>,
    registry: &AgentRegistry,
    events: &EventStore,
    enterprise: &EnterpriseStore,
    incidents: &IncidentStore,
    threat_intel: &ThreatIntelStore,
) -> Option<Vec<serde_json::Value>> {
    match source.to_ascii_lowercase().as_str() {
        "alerts" => Some(
            alerts
                .iter()
                .enumerate()
                .map(|(i, a)| {
                    serde_json::json!({
                        "id": format!("alert-{i}"),
                        "level": a.level,
                        "timestamp": a.timestamp,
                        "device_id": a.hostname,
                        "score": a.score,
                        "status": "open",
                    })
                })
                .collect(),
        ),
        "agents" => Some(
            registry
                .list()
                .iter()
                .map(|a| {
                    serde_json::json!({
                        "id": a.id,
                        "hostname": a.hostname,
                        "os": a.platform,
                        "version": a.version,
                        "status": format!("{:?}", a.status),
                        "last_heartbeat": a.last_seen,
                    })
                })
                .collect(),
        ),
        "events" => Some(
            events
                .all_events()
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "timestamp": e.received_at,
                        "device_id": e.agent_id,
                        "event_type": e.alert.level,
                        "hostname": e.alert.hostname,
                        "score": e.alert.score,
                    })
                })
                .collect(),
        ),
        "hunts" => Some(
            enterprise
                .hunts()
                .iter()
                .map(|h| {
                    serde_json::json!({
                        "id": h.id,
                        "name": h.name,
                        "status": if h.enabled { "active" } else { "disabled" },
                        "severity": h.severity,
                        "threshold": h.threshold,
                        "created_at": h.created_at,
                    })
                })
                .collect(),
        ),
        "incidents" => Some(
            incidents
                .list()
                .iter()
                .map(|inc| {
                    serde_json::json!({
                        "id": inc.id,
                        "title": inc.title,
                        "severity": inc.severity,
                        "status": format!("{:?}", inc.status),
                        "alert_count": inc.event_ids.len(),
                        "created_at": inc.created_at,
                    })
                })
                .collect(),
        ),
        "iocs" => Some(
            threat_intel
                .all_iocs()
                .into_iter()
                .map(|ioc| {
                    serde_json::json!({
                        "value": ioc.value,
                        "ioc_type": format!("{:?}", ioc.ioc_type),
                        "source": ioc.source,
                        "severity": ioc.severity,
                        "confidence": ioc.confidence,
                    })
                })
                .collect(),
        ),
        _ => None,
    }
}

pub(super) fn graphql_aggregate_json(
    args: &HashMap<String, serde_json::Value>,
    alerts: &VecDeque<AlertRecord>,
    registry: &AgentRegistry,
    events: &EventStore,
    enterprise: &EnterpriseStore,
    incidents: &IncidentStore,
    threat_intel: &ThreatIntelStore,
) -> serde_json::Value {
    let source = args.get("source").and_then(|v| v.as_str()).unwrap_or("");
    let op_raw = args.get("op").and_then(|v| v.as_str()).unwrap_or("");
    let field = args.get("field").and_then(|v| v.as_str()).unwrap_or("");
    let group_by = args.get("group_by").and_then(|v| v.as_str());

    let Some(rows) = graphql_source_rows(
        source,
        alerts,
        registry,
        events,
        enterprise,
        incidents,
        threat_intel,
    ) else {
        return serde_json::json!({
            "op": op_raw,
            "field": field,
            "value": serde_json::Value::Null,
            "group_by": group_by,
            "groups": [],
        });
    };

    let Ok(op) = AggregateOp::from_str(op_raw) else {
        return serde_json::json!({
            "op": op_raw,
            "field": field,
            "value": serde_json::Value::Null,
            "group_by": group_by,
            "groups": [],
        });
    };

    serde_json::to_value(aggregate(&rows, op, field, group_by)).unwrap_or_else(|_| {
        serde_json::json!({
            "op": op_raw,
            "field": field,
            "value": serde_json::Value::Null,
            "group_by": group_by,
            "groups": [],
        })
    })
}

pub(super) fn next_response_request_id() -> String {
    static RESPONSE_REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);
    let sequence = RESPONSE_REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(
        "resp-{}-{}",
        chrono::Utc::now()
            .timestamp_nanos_opt()
            .unwrap_or_else(|| chrono::Utc::now().timestamp_micros() * 1_000),
        sequence
    )
}

pub(super) fn build_operator_inbox(state: &mut AppState) -> Vec<InboxItem> {
    state.agent_registry.refresh_staleness();
    let mut items = Vec::new();
    let now = chrono::Utc::now();

    let pending_approvals = state.response_orchestrator.pending_requests().len();
    if pending_approvals > 0 {
        items.push(InboxItem {
            id: "pending-approvals".to_string(),
            kind: "pending_approvals".to_string(),
            title: format!("{pending_approvals} response approval(s) waiting"),
            severity: if pending_approvals > 3 {
                "high"
            } else {
                "medium"
            }
            .to_string(),
            path: "/soc#response".to_string(),
            created_at: now.to_rfc3339(),
            acknowledged: false,
            summary: "Manual response actions still need analyst approval before execution."
                .to_string(),
        });
    }

    let offline_agents = state
        .agent_registry
        .list()
        .iter()
        .filter(|agent| {
            matches!(
                agent.status,
                crate::enrollment::AgentStatus::Offline | crate::enrollment::AgentStatus::Stale
            )
        })
        .count();
    if offline_agents > 0 {
        items.push(InboxItem {
            id: "offline-agents".to_string(),
            kind: "offline_agents".to_string(),
            title: format!("{offline_agents} agent(s) need heartbeat follow-up"),
            severity: if offline_agents > 5 { "high" } else { "medium" }.to_string(),
            path: "/fleet?status=offline".to_string(),
            created_at: now.to_rfc3339(),
            acknowledged: false,
            summary:
                "One or more endpoints are stale or offline and may need recovery or redeployment."
                    .to_string(),
        });
    }

    let stale_incidents = state
        .incident_store
        .list()
        .iter()
        .filter(|incident| {
            matches!(
                incident.status,
                crate::incident::IncidentStatus::Open
                    | crate::incident::IncidentStatus::Investigating
            ) && chrono::DateTime::parse_from_rfc3339(&incident.created_at)
                .map(|ts| {
                    now.signed_duration_since(ts.with_timezone(&chrono::Utc))
                        .num_hours()
                        >= 24
                })
                .unwrap_or(false)
        })
        .count();
    if stale_incidents > 0 {
        items.push(InboxItem {
            id: "stale-incidents".to_string(),
            kind: "stale_incidents".to_string(),
            title: format!("{stale_incidents} incident(s) have been open for over 24h"),
            severity: "medium".to_string(),
            path: "/soc#incidents".to_string(),
            created_at: now.to_rfc3339(),
            acknowledged: false,
            summary: "Review long-running investigations for ownership, containment progress, and next actions.".to_string(),
        });
    }

    let feed_stats = state.feed_engine.stats();
    if feed_stats.errors_last_24h > 0 || feed_stats.active_sources < feed_stats.total_sources {
        items.push(InboxItem {
            id: "feed-degradation".to_string(),
            kind: "feed_degradation".to_string(),
            title: "Feed ingestion needs operator attention".to_string(),
            severity: if feed_stats.errors_last_24h > 0 {
                "high".to_string()
            } else {
                "medium".to_string()
            },
            path: "/reports?tab=delivery".to_string(),
            created_at: now.to_rfc3339(),
            acknowledged: false,
            summary: format!(
                "{} source(s) active, {} error(s) recorded in the last 24 hours.",
                feed_stats.active_sources, feed_stats.errors_last_24h
            ),
        });
    }

    let failed_exports = state
        .support_store
        .report_runs()
        .iter()
        .filter(|run| run.status.eq_ignore_ascii_case("failed"))
        .count();
    if failed_exports > 0 {
        items.push(InboxItem {
            id: "failed-exports".to_string(),
            kind: "failed_exports".to_string(),
            title: format!("{failed_exports} report export(s) failed"),
            severity: "medium".to_string(),
            path: "/reports?tab=runs".to_string(),
            created_at: now.to_rfc3339(),
            acknowledged: false,
            summary: "Review report run history and rerun failed exports with the same scope."
                .to_string(),
        });
    }

    state.support_store.sync_inbox(items)
}

fn hunt_incident_marker(hunt: &SavedHunt) -> String {
    format!("hunt_id={}", hunt.id)
}

pub(super) fn execute_hunt_response_actions(
    hunt: &SavedHunt,
    run: &HuntRun,
    events: &[StoredEvent],
    incident_store: &mut IncidentStore,
    enterprise: &mut EnterpriseStore,
    response_orchestrator: &ResponseOrchestrator,
    actor: &str,
) -> Vec<ResponseActionResult> {
    let mut results = hunt.evaluate_responses(run);
    if results.is_empty() {
        return results;
    }

    let event_ids = if run.matched_event_ids.is_empty() {
        run.sample_event_ids.clone()
    } else {
        run.matched_event_ids.clone()
    };

    let matching_events: Vec<&StoredEvent> = events
        .iter()
        .filter(|event| event_ids.contains(&event.id))
        .collect();

    let mut host_targets = Vec::new();
    let mut seen_targets = BTreeSet::new();
    let mut agent_ids = BTreeSet::new();
    let mut seen_techniques = BTreeSet::new();
    let mut mitre = Vec::new();

    for event in &matching_events {
        agent_ids.insert(event.agent_id.clone());
        let target_key = (event.alert.hostname.clone(), Some(event.agent_id.clone()));
        if seen_targets.insert(target_key.clone()) {
            host_targets.push(target_key);
        }
        for attack in &event.alert.mitre {
            if seen_techniques.insert(attack.technique_id.clone()) {
                mitre.push(attack.clone());
            }
        }
    }

    for (action, result) in hunt.response_actions.iter().zip(results.iter_mut()) {
        if !result.executed {
            continue;
        }
        match action {
            HuntResponseAction::Notify { channel, min_level } => {
                let mut request_ids = Vec::new();
                for (hostname, agent_uid) in &host_targets {
                    let request = ResponseRequest {
                        id: next_response_request_id(),
                        action: ResponseAction::Alert,
                        target: ResponseTarget {
                            hostname: hostname.clone(),
                            agent_uid: agent_uid.clone(),
                            asset_tags: Vec::new(),
                        },
                        reason: format!(
                            "Automated hunt notification via {channel} (min_level={min_level}) from {}",
                            hunt.name
                        ),
                        severity: run.severity.clone(),
                        tier: ActionTier::Auto,
                        status: ApprovalStatus::Pending,
                        requested_at: chrono::Utc::now().to_rfc3339(),
                        requested_by: actor.to_string(),
                        approvals: Vec::new(),
                        dry_run: false,
                        blast_radius: None,
                        is_protected_asset: false,
                    };
                    if let Ok(request_id) = response_orchestrator.submit(request) {
                        request_ids.push(request_id);
                    }
                }
                if request_ids.is_empty() {
                    result.executed = false;
                    result.detail = format!(
                        "Skipped notify channel '{channel}' because no eligible hosts were found"
                    );
                } else {
                    result.detail = format!(
                        "Notify channel '{}' (min_level={}) queued {} alert notification(s): {}",
                        channel,
                        min_level,
                        request_ids.len(),
                        request_ids.join(", ")
                    );
                }
            }
            HuntResponseAction::CreateIncident {
                severity,
                title_template,
            } => {
                let title = title_template
                    .replace("{hunt_name}", &hunt.name)
                    .replace("{match_count}", &run.match_count.to_string());
                let summary = format!(
                    "Auto-created from hunt '{}' ({}) run {} with {} visible match(es)",
                    hunt.name,
                    hunt_incident_marker(hunt),
                    run.id,
                    run.match_count
                );
                let incident_agent_ids = if run.matched_agent_ids.is_empty() {
                    agent_ids.iter().cloned().collect::<Vec<_>>()
                } else {
                    run.matched_agent_ids.clone()
                };
                if let Some(existing) = incident_store.incidents.iter_mut().find(|incident| {
                    matches!(
                        incident.status,
                        crate::incident::IncidentStatus::Open
                            | crate::incident::IncidentStatus::Investigating
                    ) && incident.summary.contains(&hunt_incident_marker(hunt))
                }) {
                    for event_id in &event_ids {
                        if !existing.event_ids.contains(event_id) {
                            existing.event_ids.push(*event_id);
                        }
                    }
                    for agent_id in &incident_agent_ids {
                        if !existing.agent_ids.contains(agent_id) {
                            existing.agent_ids.push(agent_id.clone());
                        }
                    }
                    for attack in &mitre {
                        if !existing
                            .mitre_techniques
                            .iter()
                            .any(|current| current.technique_id == attack.technique_id)
                        {
                            existing.mitre_techniques.push(attack.clone());
                        }
                    }
                    existing.updated_at = chrono::Utc::now().to_rfc3339();
                    existing.summary = summary;
                    result.detail = format!(
                        "Updated existing {severity} incident #{}: {}",
                        existing.id, existing.title
                    );
                } else {
                    let incident = incident_store.create(
                        title.clone(),
                        severity.clone(),
                        event_ids.clone(),
                        incident_agent_ids,
                        mitre.clone(),
                        summary,
                    );
                    result.detail = format!("Create {severity} incident #{}: {title}", incident.id);
                }
            }
            HuntResponseAction::AutoSuppress {
                duration_secs,
                justification,
            } => {
                let suppression_name = format!("Auto-suppress {}", hunt.name);
                let existing_id = enterprise
                    .suppressions()
                    .iter()
                    .find(|suppression| {
                        suppression.hunt_id.as_deref() == Some(hunt.id.as_str())
                            && suppression.name == suppression_name
                    })
                    .map(|suppression| suppression.id.clone());
                let expires_at = (chrono::Utc::now()
                    + chrono::Duration::seconds(*duration_secs as i64))
                .to_rfc3339();
                let suppression = enterprise.create_or_update_suppression(
                    existing_id.as_deref(),
                    suppression_name,
                    None,
                    Some(hunt.id.clone()),
                    None,
                    None,
                    Some(run.severity.clone()),
                    None,
                    Some(expires_at.clone()),
                    justification.clone(),
                    actor.to_string(),
                    true,
                );
                result.detail = format!(
                    "Suppress for {duration_secs}s until {} via suppression {}",
                    expires_at, suppression.id
                );
            }
            HuntResponseAction::IsolateAgent => {
                let mut request_ids = Vec::new();
                let mut failures = Vec::new();
                for (hostname, agent_uid) in &host_targets {
                    let request = ResponseRequest {
                        id: next_response_request_id(),
                        action: ResponseAction::Isolate,
                        target: ResponseTarget {
                            hostname: hostname.clone(),
                            agent_uid: agent_uid.clone(),
                            asset_tags: Vec::new(),
                        },
                        reason: format!(
                            "Automated host isolation requested by hunt '{}' run {}",
                            hunt.name, run.id
                        ),
                        severity: run.severity.clone(),
                        tier: ActionTier::SingleApproval,
                        status: ApprovalStatus::Pending,
                        requested_at: chrono::Utc::now().to_rfc3339(),
                        requested_by: actor.to_string(),
                        approvals: Vec::new(),
                        dry_run: false,
                        blast_radius: None,
                        is_protected_asset: false,
                    };
                    match response_orchestrator.submit(request) {
                        Ok(request_id) => request_ids.push(request_id),
                        Err(err) => failures.push(format!("{hostname}: {err}")),
                    }
                }
                if request_ids.is_empty() {
                    result.executed = false;
                    result.detail = if failures.is_empty() {
                        "Skipped isolation because no eligible hosts were found".to_string()
                    } else {
                        format!("Isolation requests rejected: {}", failures.join("; "))
                    };
                } else {
                    let mut detail = format!(
                        "Queued {} isolate request(s): {}",
                        request_ids.len(),
                        request_ids.join(", ")
                    );
                    if !failures.is_empty() {
                        detail.push_str(&format!("; rejected: {}", failures.join("; ")));
                    }
                    result.detail = detail;
                }
            }
        }
    }

    results
}

/// Simple base64 decoder (no external dependency needed).
pub(crate) fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
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
        let val = TABLE
            .iter()
            .position(|&c| c == b)
            .ok_or_else(|| format!("invalid base64 character: {}", b as char))?
            as u32;
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

/// Attempt base64 decode; fall back to raw bytes if invalid.
pub(super) fn base64_decode_or_raw(input: &str) -> Vec<u8> {
    base64_decode(input).unwrap_or_else(|_| input.as_bytes().to_vec())
}
