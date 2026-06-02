//! Local process detail and thread inspection helpers.
//!
//! Extracted from `server.rs` as part of the post-v1.0.28 hardening sweep.
//! The route dispatcher remains in `server.rs`; this child module keeps the
//! process evidence builders together while preserving the previous private
//! helper access semantics.

#[allow(unused_imports)]
use super::*;

fn process_basename(value: &str) -> &str {
    value
        .rsplit(['/', '\\'])
        .next()
        .filter(|segment| !segment.is_empty())
        .unwrap_or(value)
}

#[cfg(not(target_os = "windows"))]
fn run_command_text(command: &str, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(command)
        .args(args)
        .output()
        .ok()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(target_os = "macos")]
fn process_lsof_path(pid: u32, descriptor: &str) -> Option<String> {
    let pid_arg = pid.to_string();
    let output = run_command_text("lsof", &["-a", "-p", &pid_arg, "-d", descriptor, "-Fn"])?;
    output
        .lines()
        .find_map(|line| line.strip_prefix('n').map(|value| value.trim().to_string()))
        .filter(|value| !value.is_empty())
}

#[cfg(not(target_os = "windows"))]
fn parse_network_activity_lines(lines: &str) -> Vec<serde_json::Value> {
    lines
        .lines()
        .skip(1)
        .filter_map(|line| {
            let protocol = if line.contains(" TCP ") {
                "TCP"
            } else if line.contains(" UDP ") {
                "UDP"
            } else {
                return None;
            };
            let (_, rest) = line.split_once(&format!(" {protocol} "))?;
            let trimmed = rest.trim();
            let (endpoint, state) = match trimmed.rsplit_once(" (") {
                Some((endpoint, state)) => (
                    endpoint.trim(),
                    Some(state.trim_end_matches(')').trim().to_string()),
                ),
                None => (trimmed, None),
            };
            Some(serde_json::json!({
                "protocol": protocol,
                "endpoint": endpoint,
                "state": state,
            }))
        })
        .collect()
}

#[cfg(target_os = "macos")]
fn code_signature_summary(exe_path: &str) -> serde_json::Value {
    #[cfg(target_os = "macos")]
    {
        let Some(output) = run_command_text("codesign", &["-dv", "--verbose=4", exe_path]) else {
            return serde_json::json!({
                "status": "unknown",
            });
        };
        let identifier = output
            .lines()
            .find_map(|line| line.strip_prefix("Identifier=").map(str::trim))
            .unwrap_or("");
        let team = output
            .lines()
            .find_map(|line| line.strip_prefix("TeamIdentifier=").map(str::trim))
            .unwrap_or("");
        let authority: Vec<String> = output
            .lines()
            .filter_map(|line| {
                line.strip_prefix("Authority=")
                    .map(|s| s.trim().to_string())
            })
            .collect();
        serde_json::json!({
            "status": if authority.is_empty() { "unsigned_or_unknown" } else { "signed" },
            "identifier": if identifier.is_empty() { serde_json::Value::Null } else { serde_json::json!(identifier) },
            "team_identifier": if team.is_empty() { serde_json::Value::Null } else { serde_json::json!(team) },
            "authority": authority,
        })
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = exe_path;
        serde_json::json!({
            "status": "unavailable",
        })
    }
}

#[cfg(not(target_os = "windows"))]
fn process_recommendations(
    findings: &[serde_json::Value],
    network: &[serde_json::Value],
    is_self: bool,
) -> Vec<String> {
    let mut items = Vec::new();
    if is_self {
        items.push(
            "Wardex is monitoring its own process; suppress self-findings before escalating."
                .to_string(),
        );
    }
    if findings.iter().any(|finding| {
        finding["reason"]
            .as_str()
            .unwrap_or("")
            .to_ascii_lowercase()
            .contains("reverse shell")
    }) {
        items.push(
            "Review the full command line, network peers, and parent process before considering kill or host isolation."
                .to_string(),
        );
    }
    if network
        .iter()
        .any(|entry| entry["state"].as_str() == Some("LISTEN"))
    {
        items.push(
            "Validate whether the process should be listening locally or remotely; unexpected listeners are good containment candidates."
                .to_string(),
        );
    }
    if findings.is_empty() {
        items.push(
            "No high-confidence behavioural findings matched this process at inspection time."
                .to_string(),
        );
    }
    items
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn thread_state_label(state: &str) -> &'static str {
    match state.chars().next().unwrap_or('?') {
        'R' => "running",
        'S' => "sleeping",
        'I' => "idle",
        'D' | 'U' => "blocked",
        'T' => "stopped",
        'Z' => "zombie",
        _ => "unknown",
    }
}

#[cfg(any(target_os = "macos", test))]
fn parse_macos_process_threads_output(output: &str, pid: u32) -> Vec<serde_json::Value> {
    let lines: Vec<&str> = output
        .lines()
        .map(str::trim_end)
        .filter(|line| !line.trim().is_empty())
        .collect();
    if lines.len() < 3 {
        return Vec::new();
    }

    lines
        .into_iter()
        .skip(2)
        .enumerate()
        .filter_map(|(index, line)| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 6 {
                return None;
            }
            let row_pid = fields[0].parse::<u32>().ok()?;
            if row_pid != pid {
                return None;
            }
            let cpu_percent = fields[1].parse::<f64>().unwrap_or(0.0);
            let state = fields[2].to_string();
            let priority = fields[3].to_string();
            let system_time = fields[4].to_string();
            let user_time = fields[5].to_string();
            Some(serde_json::json!({
                "thread_id": (index + 1) as u32,
                "os_thread_id": serde_json::Value::Null,
                "identifier_type": "row_slot",
                "state": state,
                "state_label": thread_state_label(&state),
                "priority": priority,
                "cpu_percent": (cpu_percent * 10.0).round() / 10.0,
                "system_time": system_time,
                "user_time": user_time,
                "wait_reason": serde_json::Value::Null,
            }))
        })
        .collect()
}

#[allow(dead_code)]
#[cfg(any(target_os = "linux", test))]
fn parse_linux_process_threads_output(output: &str) -> Vec<serde_json::Value> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 6 {
                return None;
            }
            let thread_id = fields[0].parse::<u32>().ok()?;
            let state = fields[1].to_string();
            let cpu_time = fields[2].to_string();
            let cpu_percent = fields[3].parse::<f64>().unwrap_or(0.0);
            let priority = fields[4].to_string();
            let wait_reason = match fields[5] {
                "-" | "?" => None,
                value => Some(value.to_string()),
            };
            let command = if fields.len() > 6 {
                Some(fields[6..].join(" "))
            } else {
                None
            };
            Some(serde_json::json!({
                "thread_id": thread_id,
                "os_thread_id": thread_id,
                "identifier_type": "tid",
                "state": state,
                "state_label": thread_state_label(&state),
                "priority": priority,
                "cpu_percent": (cpu_percent * 10.0).round() / 10.0,
                "cpu_time": cpu_time,
                "wait_reason": wait_reason,
                "command": command,
            }))
        })
        .collect()
}

fn thread_evidence(thread: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "thread_id": thread["thread_id"].clone(),
        "os_thread_id": thread["os_thread_id"].clone(),
        "state": thread["state"].clone(),
        "state_label": thread["state_label"].clone(),
        "priority": thread["priority"].clone(),
        "cpu_percent": thread["cpu_percent"].clone(),
        "wait_reason": thread["wait_reason"].clone(),
    })
}

fn push_thread_anomaly(
    anomalies: &mut Vec<serde_json::Value>,
    score: &mut u32,
    kind: &str,
    severity: &str,
    weight: u32,
    detail: String,
    evidence: serde_json::Value,
) {
    *score = score.saturating_add(weight);
    anomalies.push(serde_json::json!({
        "kind": kind,
        "severity": severity,
        "detail": detail,
        "evidence": evidence,
    }));
}

fn suspicious_wait_reason(reason: &str) -> bool {
    let normalized = reason.trim().to_ascii_lowercase();
    [
        "ptrace",
        "task_for_pid",
        "mach_vm",
        "process_vm",
        "bpf",
        "uprobe",
        "kprobe",
        "ftrace",
        "inject",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

fn thread_anomaly_level(score: u32) -> &'static str {
    if score >= 75 {
        "critical"
    } else if score >= 45 {
        "high"
    } else if score >= 20 {
        "elevated"
    } else {
        "nominal"
    }
}

fn build_thread_anomaly_summary(
    identifier_type: &str,
    message: Option<&str>,
    threads: &[serde_json::Value],
    hot_threads: &[serde_json::Value],
    blocked_threads: &[serde_json::Value],
    thread_count: usize,
    hot_thread_count: usize,
    blocked_count: usize,
    top_cpu_percent: f64,
    wait_reason_count: usize,
) -> (Vec<serde_json::Value>, u32, Vec<String>) {
    let mut anomalies = Vec::new();
    let mut score = 0_u32;
    let mut recommendations = Vec::new();
    let mut add_recommendation = |value: &str| {
        if !recommendations.iter().any(|item| item == value) {
            recommendations.push(value.to_string());
        }
    };

    if identifier_type == "unsupported" || message.is_some() {
        push_thread_anomaly(
            &mut anomalies,
            &mut score,
            "collection_gap",
            "info",
            0,
            message
                .unwrap_or("Per-thread collection returned no rows for this platform.")
                .to_string(),
            serde_json::json!({ "identifier_type": identifier_type }),
        );
        add_recommendation(
            "Collect a live Linux or macOS thread snapshot before ruling out thread-level anomalies.",
        );
    }

    if thread_count >= 128 {
        push_thread_anomaly(
            &mut anomalies,
            &mut score,
            "thread_fanout",
            "high",
            28,
            format!(
                "Process exposes {thread_count} threads, which is unusually broad for live triage."
            ),
            serde_json::json!({ "thread_count": thread_count }),
        );
        add_recommendation(
            "Compare thread fan-out against the process baseline and loaded modules.",
        );
    } else if thread_count >= 64 {
        push_thread_anomaly(
            &mut anomalies,
            &mut score,
            "thread_fanout",
            "medium",
            14,
            format!(
                "Process exposes {thread_count} threads; watch for worker-pool burst behavior."
            ),
            serde_json::json!({ "thread_count": thread_count }),
        );
        add_recommendation("Review whether the thread count matches expected workload scale.");
    }

    if let Some(top_thread) = hot_threads.first() {
        if top_cpu_percent >= 25.0 {
            push_thread_anomaly(
                &mut anomalies,
                &mut score,
                "hot_thread",
                "high",
                30,
                format!(
                    "Thread CPU peaked at {:.1}% during collection.",
                    top_cpu_percent
                ),
                thread_evidence(top_thread),
            );
            add_recommendation(
                "Profile the hottest thread before terminating the process or approving response automation.",
            );
        } else if hot_thread_count >= 3 && top_cpu_percent >= 10.0 {
            push_thread_anomaly(
                &mut anomalies,
                &mut score,
                "cpu_concentration",
                "medium",
                16,
                format!(
                    "{hot_thread_count} threads exceeded 5% CPU with a {:.1}% peak.",
                    top_cpu_percent
                ),
                serde_json::json!({
                    "hot_thread_count": hot_thread_count,
                    "top_cpu_percent": (top_cpu_percent * 10.0).round() / 10.0,
                    "top_thread": thread_evidence(top_thread),
                }),
            );
            add_recommendation(
                "Check whether hot workers line up with expected process activity or injected execution.",
            );
        }
    }

    if thread_count > 0 && blocked_count >= 3 {
        let blocked_ratio = blocked_count as f64 / thread_count as f64;
        if blocked_ratio >= 0.5 {
            push_thread_anomaly(
                &mut anomalies,
                &mut score,
                "blocked_concentration",
                "high",
                26,
                format!("{blocked_count}/{thread_count} threads are blocked or stopped."),
                serde_json::json!({
                    "blocked_count": blocked_count,
                    "thread_count": thread_count,
                    "blocked_threads": blocked_threads.iter().take(3).map(thread_evidence).collect::<Vec<_>>(),
                }),
            );
            add_recommendation(
                "Inspect blocked wait channels before deciding whether the process is hung or deliberately suspended.",
            );
        } else if blocked_ratio >= 0.25 {
            push_thread_anomaly(
                &mut anomalies,
                &mut score,
                "blocked_concentration",
                "medium",
                14,
                format!("{blocked_count}/{thread_count} threads are blocked or stopped."),
                serde_json::json!({
                    "blocked_count": blocked_count,
                    "thread_count": thread_count,
                    "blocked_threads": blocked_threads.iter().take(3).map(thread_evidence).collect::<Vec<_>>(),
                }),
            );
            add_recommendation(
                "Correlate blocked workers with file, socket, or credential activity in the timeline.",
            );
        }
    }

    let stopped_threads = threads
        .iter()
        .filter(|thread| {
            matches!(
                thread["state_label"].as_str(),
                Some("stopped") | Some("zombie")
            )
        })
        .take(3)
        .cloned()
        .collect::<Vec<_>>();
    if !stopped_threads.is_empty() {
        push_thread_anomaly(
            &mut anomalies,
            &mut score,
            "suspended_thread",
            "medium",
            15,
            format!(
                "{} stopped or zombie thread state{} observed.",
                stopped_threads.len(),
                if stopped_threads.len() == 1 {
                    " was"
                } else {
                    "s were"
                }
            ),
            serde_json::json!({
                "threads": stopped_threads.iter().map(thread_evidence).collect::<Vec<_>>(),
            }),
        );
        add_recommendation(
            "Validate whether stopped thread state came from debugging, suspension, or abnormal termination.",
        );
    }

    let suspicious_waits = threads
        .iter()
        .filter_map(|thread| {
            let reason = thread["wait_reason"].as_str()?.trim();
            if reason.is_empty() || !suspicious_wait_reason(reason) {
                return None;
            }
            Some(serde_json::json!({
                "thread_id": thread["thread_id"].clone(),
                "wait_reason": reason,
                "state_label": thread["state_label"].clone(),
                "cpu_percent": thread["cpu_percent"].clone(),
            }))
        })
        .take(4)
        .collect::<Vec<_>>();
    if !suspicious_waits.is_empty() {
        push_thread_anomaly(
            &mut anomalies,
            &mut score,
            "suspicious_wait_reason",
            "high",
            32,
            format!(
                "{} thread wait reason{} matched injection, tracing, or kernel instrumentation terms.",
                suspicious_waits.len(),
                if suspicious_waits.len() == 1 { "" } else { "s" }
            ),
            serde_json::json!({ "wait_reasons": suspicious_waits }),
        );
        add_recommendation(
            "Treat suspicious wait channels as process evidence and pivot to module, handle, and parent lineage review.",
        );
    } else if wait_reason_count > 0 {
        add_recommendation(
            "Use exposed wait reasons to separate normal waiting from stuck or externally controlled workers.",
        );
    }

    if anomalies.is_empty() {
        add_recommendation(
            "No thread-level anomaly is visible in the current snapshot; keep this as baseline evidence.",
        );
    }

    (anomalies, score.min(100), recommendations)
}

fn build_process_threads_response(
    pid: u32,
    hostname: &str,
    platform: &str,
    identifier_type: &str,
    note: Option<&str>,
    threads: Vec<serde_json::Value>,
    message: Option<&str>,
) -> serde_json::Value {
    let mut hot_threads = threads.clone();
    hot_threads.sort_by(|left, right| {
        right["cpu_percent"]
            .as_f64()
            .unwrap_or(0.0)
            .partial_cmp(&left["cpu_percent"].as_f64().unwrap_or(0.0))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    hot_threads.truncate(3);
    let blocked_threads = threads
        .iter()
        .filter(|thread| {
            matches!(
                thread["state_label"].as_str(),
                Some("blocked") | Some("stopped")
            )
        })
        .take(4)
        .cloned()
        .collect::<Vec<_>>();
    let wait_reason_count = threads
        .iter()
        .filter(|thread| {
            thread["wait_reason"]
                .as_str()
                .map(|value| !value.trim().is_empty())
                .unwrap_or(false)
        })
        .count();
    let running_count = threads
        .iter()
        .filter(|thread| thread["state_label"].as_str() == Some("running"))
        .count();
    let sleeping_count = threads
        .iter()
        .filter(|thread| {
            matches!(
                thread["state_label"].as_str(),
                Some("sleeping") | Some("idle")
            )
        })
        .count();
    let blocked_count = threads
        .iter()
        .filter(|thread| {
            matches!(
                thread["state_label"].as_str(),
                Some("blocked") | Some("stopped")
            )
        })
        .count();
    let hot_thread_count = threads
        .iter()
        .filter(|thread| thread["cpu_percent"].as_f64().unwrap_or(0.0) >= 5.0)
        .count();
    let top_cpu_percent = threads
        .iter()
        .filter_map(|thread| thread["cpu_percent"].as_f64())
        .fold(0.0_f64, f64::max);
    let rounded_top_cpu_percent = (top_cpu_percent * 10.0).round() / 10.0;
    let (thread_anomalies, anomaly_score, recommendations) = build_thread_anomaly_summary(
        identifier_type,
        message,
        &threads,
        &hot_threads,
        &blocked_threads,
        threads.len(),
        hot_thread_count,
        blocked_count,
        rounded_top_cpu_percent,
        wait_reason_count,
    );
    let anomaly_level = thread_anomaly_level(anomaly_score);
    let observed_thread_count = threads.len();
    let expected_max_threads = if identifier_type == "unsupported" {
        0
    } else {
        64
    };
    let expected_hot_threads = if identifier_type == "unsupported" {
        0
    } else {
        2
    };
    let fanout_deviation = observed_thread_count.saturating_sub(expected_max_threads);
    let hot_thread_deviation = hot_thread_count.saturating_sub(expected_hot_threads);
    let baseline_status = if identifier_type == "unsupported" || message.is_some() {
        "collection_gap"
    } else if anomaly_score >= 45 || fanout_deviation > 0 || hot_thread_deviation > 0 {
        "deviated"
    } else {
        "within_baseline"
    };

    serde_json::json!({
        "pid": pid,
        "hostname": hostname,
        "platform": platform,
        "collection_source": match (platform, identifier_type) {
            ("macos", "row_slot") => "ps -M -p <pid>",
            ("linux", "tid") => "ps -L -p <pid>",
            ("windows", _) => "windows-thread-collector",
            _ => "process-thread-collector",
        },
        "identifier_type": identifier_type,
        "note": note,
        "message": message,
        "thread_count": threads.len(),
        "running_count": running_count,
        "sleeping_count": sleeping_count,
        "blocked_count": blocked_count,
        "hot_thread_count": hot_thread_count,
        "top_cpu_percent": rounded_top_cpu_percent,
        "wait_reason_count": wait_reason_count,
        "thread_anomaly_count": thread_anomalies.len(),
        "thread_anomaly_score": anomaly_score,
        "thread_anomaly_level": anomaly_level,
        "thread_baseline": {
            "status": baseline_status,
            "expected_thread_count": { "min": if identifier_type == "unsupported" { 0 } else { 1 }, "max": expected_max_threads },
            "expected_hot_threads_max": expected_hot_threads,
            "thread_count_deviation": fanout_deviation,
            "hot_thread_deviation": hot_thread_deviation,
            "confidence": if identifier_type == "unsupported" || message.is_some() { "low" } else if wait_reason_count > 0 { "high" } else { "medium" },
            "evidence": {
                "running_count": running_count,
                "sleeping_count": sleeping_count,
                "blocked_count": blocked_count,
                "wait_reason_count": wait_reason_count,
                "top_cpu_percent": rounded_top_cpu_percent,
            },
        },
        "thread_anomalies": thread_anomalies,
        "anomaly_score": anomaly_score,
        "anomaly_level": anomaly_level,
        "recommendations": recommendations,
        "hot_threads": hot_threads,
        "blocked_threads": blocked_threads,
        "threads": threads,
    })
}

pub(crate) fn process_threads_json(pid: u32, hostname: &str) -> Option<serde_json::Value> {
    #[cfg(target_os = "macos")]
    {
        let pid_arg = pid.to_string();
        let output = run_command_text("ps", &["-M", "-p", &pid_arg])?;
        let threads = parse_macos_process_threads_output(&output, pid);
        if output.lines().count() < 2 {
            return None;
        }
        Some(build_process_threads_response(
            pid,
            hostname,
            "macos",
            "row_slot",
            Some(
                "macOS exposes real per-thread rows here, but the default CLI surface does not provide stable thread IDs. Thread numbers are collection-time row slots.",
            ),
            threads,
            None,
        ))
    }
    #[cfg(target_os = "linux")]
    {
        let pid_arg = pid.to_string();
        let output = run_command_text(
            "ps",
            &[
                "-L",
                "-p",
                &pid_arg,
                "-o",
                "lwp=,state=,time=,%cpu=,pri=,wchan=,comm=",
            ],
        )?;
        let threads = parse_linux_process_threads_output(&output);
        if threads.is_empty() {
            return None;
        }
        Some(build_process_threads_response(
            pid,
            hostname,
            "linux",
            "tid",
            Some(
                "Linux thread IDs are native task IDs from the local task table; wait_reason reflects the current wait channel when the kernel exposes one.",
            ),
            threads,
            None,
        ))
    }
    #[cfg(target_os = "windows")]
    {
        Some(build_process_threads_response(
            pid,
            hostname,
            "windows",
            "unsupported",
            None,
            Vec::new(),
            Some("Per-process OS-thread collection is not implemented on Windows yet."),
        ))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Some(build_process_threads_response(
            pid,
            hostname,
            std::env::consts::OS,
            "unsupported",
            None,
            Vec::new(),
            Some("Per-process OS-thread collection is not supported on this platform."),
        ))
    }
}

#[cfg(target_os = "macos")]
fn collect_process_snapshot_macos(pid: u32) -> Option<crate::collector_macos::MacosProcessEvent> {
    let pid_arg = pid.to_string();
    let line = run_command_text(
        "ps",
        &[
            "-p",
            &pid_arg,
            "-o",
            "pid=,ppid=,user=,group=,%cpu=,%mem=,comm=",
        ],
    )?;
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 7 {
        return None;
    }
    Some(crate::collector_macos::MacosProcessEvent {
        timestamp: chrono::Utc::now().to_rfc3339(),
        pid: fields[0].parse().ok()?,
        ppid: fields[1].parse().unwrap_or(0),
        user: fields[2].to_string(),
        group: fields[3].to_string(),
        cpu_percent: fields[4].parse().unwrap_or(0.0),
        mem_percent: fields[5].parse().unwrap_or(0.0),
        name: fields[6..].join(" "),
        code_signed: crate::collector_macos::CodeSignStatus::Unknown,
        cmd_line: String::new(),
        ocsf_class_id: crate::collector_macos::OCSF_PROCESS_ACTIVITY,
    })
}

pub(crate) fn process_detail_json(pid: u32, hostname: &str) -> Option<serde_json::Value> {
    #[cfg(target_os = "macos")]
    {
        let processes = crate::collector_macos::collect_processes();
        let process = processes
            .iter()
            .find(|proc| proc.pid == pid)
            .cloned()
            .or_else(|| collect_process_snapshot_macos(pid))?;
        let findings: Vec<serde_json::Value> =
            crate::collector_macos::analyze_processes(&processes)
                .into_iter()
                .filter(|finding| finding.pid == pid)
                .map(|finding| {
                    serde_json::json!({
                        "pid": finding.pid,
                        "name": finding.name,
                        "user": finding.user,
                        "risk_level": finding.risk_level,
                        "reason": finding.reason,
                        "cpu_percent": finding.cpu_percent,
                        "mem_percent": finding.mem_percent,
                    })
                })
                .collect();
        let pid_arg = pid.to_string();
        let cmd_line =
            run_command_text("ps", &["-p", &pid_arg, "-o", "command="]).unwrap_or_else(|| {
                if process.cmd_line.is_empty() {
                    process.name.clone()
                } else {
                    process.cmd_line.clone()
                }
            });
        let start_time = run_command_text("ps", &["-p", &pid_arg, "-o", "lstart="]);
        let elapsed = run_command_text("ps", &["-p", &pid_arg, "-o", "etime="]);
        let exe_path = process_lsof_path(pid, "txt");
        let cwd = process_lsof_path(pid, "cwd");
        let network = run_command_text("lsof", &["-nP", "-a", "-p", &pid_arg, "-i"])
            .map(|output| parse_network_activity_lines(&output))
            .unwrap_or_default();
        let display_name = process_basename(&process.name).to_string();
        let is_self = pid == std::process::id() && display_name.eq_ignore_ascii_case("wardex");
        let risk_level = findings
            .first()
            .and_then(|finding| finding["risk_level"].as_str())
            .unwrap_or("nominal");
        let signature = exe_path
            .as_deref()
            .map(code_signature_summary)
            .unwrap_or_else(|| serde_json::json!({"status": "unknown"}));

        Some(serde_json::json!({
            "pid": process.pid,
            "ppid": process.ppid,
            "name": process.name,
            "display_name": display_name,
            "user": process.user,
            "group": process.group,
            "cpu_percent": process.cpu_percent,
            "mem_percent": process.mem_percent,
            "hostname": hostname,
            "platform": "macos",
            "cmd_line": cmd_line,
            "exe_path": exe_path,
            "cwd": cwd,
            "start_time": start_time,
            "elapsed": elapsed,
            "risk_level": risk_level,
            "findings": findings,
            "network_activity": network,
            "code_signature": signature,
            "analysis": {
                "self_process": is_self,
                "listener_count": network.iter().filter(|entry| entry["state"].as_str() == Some("LISTEN")).count(),
                "recommendations": process_recommendations(&findings, &network, is_self),
            },
        }))
    }
    #[cfg(target_os = "linux")]
    {
        let processes = crate::collector_linux::collect_processes();
        let process = processes.iter().find(|proc| proc.pid == pid)?;
        let findings: Vec<serde_json::Value> =
            crate::collector_linux::analyze_processes(&processes)
                .into_iter()
                .filter(|finding| finding.pid == pid)
                .map(|finding| {
                    serde_json::json!({
                        "pid": finding.pid,
                        "name": finding.name,
                        "user": finding.user,
                        "risk_level": finding.risk_level,
                        "reason": finding.reason,
                        "cpu_percent": finding.cpu_percent,
                        "mem_percent": finding.mem_percent,
                    })
                })
                .collect();
        let pid_arg = pid.to_string();
        let network = run_command_text("lsof", &["-nP", "-a", "-p", &pid_arg, "-i"])
            .map(|output| parse_network_activity_lines(&output))
            .unwrap_or_default();
        Some(serde_json::json!({
            "pid": process.pid,
            "ppid": process.ppid,
            "name": process.name,
            "display_name": process_basename(&process.name),
            "user": if process.uid == 0 { "root".to_string() } else { format!("uid:{}", process.uid) },
            "group": format!("gid:{}", process.gid),
            "cpu_percent": findings.first().and_then(|finding| finding["cpu_percent"].as_f64()).unwrap_or(0.0),
            "mem_percent": findings.first().and_then(|finding| finding["mem_percent"].as_f64()).unwrap_or(0.0),
            "hostname": hostname,
            "platform": "linux",
            "cmd_line": process.cmd_line,
            "exe_path": process.exe_path,
            "cwd": std::fs::read_link(format!("/proc/{pid}/cwd")).ok().map(|path| path.display().to_string()),
            "start_time": serde_json::Value::Null,
            "elapsed": serde_json::Value::Null,
            "risk_level": findings.first().and_then(|finding| finding["risk_level"].as_str()).unwrap_or("nominal"),
            "findings": findings,
            "network_activity": network,
            "code_signature": serde_json::json!({"status": "unavailable"}),
            "analysis": {
                "self_process": false,
                "listener_count": network.iter().filter(|entry| entry["state"].as_str() == Some("LISTEN")).count(),
                "recommendations": process_recommendations(&findings, &network, false),
            },
        }))
    }
    #[cfg(target_os = "windows")]
    {
        let _ = (pid, hostname);
        None
    }
}

#[cfg(test)]
mod process_thread_parsing_tests {
    use super::*;

    fn sample_alert() -> AlertRecord {
        AlertRecord {
            timestamp: "2026-04-27T10:00:00Z".to_string(),
            hostname: "edge-1".to_string(),
            platform: "linux".to_string(),
            score: 8.4,
            confidence: 0.93,
            level: "Critical".to_string(),
            action: "monitor".to_string(),
            reasons: vec![
                "Suspicious python3 execution from /usr/bin/python3 with outbound network activity"
                    .to_string(),
            ],
            sample: crate::telemetry::TelemetrySample {
                timestamp_ms: 1,
                cpu_load_pct: 75.0,
                memory_load_pct: 61.0,
                temperature_c: 0.0,
                network_kbps: 220.0,
                auth_failures: 0,
                battery_pct: 100.0,
                integrity_drift: 0.0,
                process_count: 123,
                disk_pressure_pct: 10.0,
            },
            enforced: false,
            mitre: vec![],
            narrative: None,
        }
    }

    #[test]
    fn parses_macos_process_thread_rows() {
        let output = concat!(
            "USER           PID   TT   %CPU STAT PRI     STIME     UTIME COMMAND\n",
            "michelpicker  1788   ??    3.1 S    47T   8:53.17  44:02.77 /Applications/Visual Studio Code.app/Contents/MacOS/Code Helper\n",
            "              1788         0.0 S    37T   0:00.00   0:00.00 \n",
            "              1788         1.4 S    47T   5:46.80  23:35.52 \n",
            "              1788         0.0 R    54R   0:00.24   0:00.16 \n"
        );

        let threads = parse_macos_process_threads_output(output, 1788);

        assert_eq!(threads.len(), 3);
        assert_eq!(threads[0]["thread_id"].as_u64(), Some(1));
        assert_eq!(threads[1]["cpu_percent"].as_f64(), Some(1.4));
        assert_eq!(threads[2]["state_label"].as_str(), Some("running"));
        assert!(threads[0]["wait_reason"].is_null());
    }

    #[test]
    fn parses_linux_process_thread_rows() {
        let output = concat!(
            "4242 R 00:00:01 12.5 40 - python3\n",
            "4243 S 00:00:00 0.0 20 futex_wait_queue_me python3\n"
        );

        let threads = parse_linux_process_threads_output(output);

        assert_eq!(threads.len(), 2);
        assert_eq!(threads[0]["thread_id"].as_u64(), Some(4242));
        assert_eq!(threads[0]["state_label"].as_str(), Some("running"));
        assert_eq!(threads[1]["cpu_time"].as_str(), Some("00:00:00"));
        assert_eq!(
            threads[1]["wait_reason"].as_str(),
            Some("futex_wait_queue_me")
        );
    }

    #[test]
    fn process_thread_response_adds_anomaly_summary() {
        let threads = vec![
            serde_json::json!({
                "thread_id": 4242,
                "os_thread_id": 4242,
                "identifier_type": "tid",
                "state": "R",
                "state_label": "running",
                "priority": "40",
                "cpu_percent": 34.2,
                "cpu_time": "00:00:03",
                "wait_reason": serde_json::Value::Null,
                "command": "python3",
            }),
            serde_json::json!({
                "thread_id": 4243,
                "os_thread_id": 4243,
                "identifier_type": "tid",
                "state": "D",
                "state_label": "blocked",
                "priority": "20",
                "cpu_percent": 0.1,
                "cpu_time": "00:00:00",
                "wait_reason": "ptrace_stop",
                "command": "python3",
            }),
        ];

        let payload = build_process_threads_response(
            4242,
            "edge-1",
            "linux",
            "tid",
            Some("linux test snapshot"),
            threads,
            None,
        );

        let anomalies = payload["thread_anomalies"].as_array().unwrap();
        assert!(anomalies.iter().any(|item| item["kind"] == "hot_thread"));
        assert!(
            anomalies
                .iter()
                .any(|item| item["kind"] == "suspicious_wait_reason")
        );
        assert_eq!(payload["thread_anomaly_level"].as_str(), Some("high"));
        assert!(payload["thread_anomaly_score"].as_u64().unwrap() >= 45);
        assert!(payload["recommendations"].as_array().unwrap().len() >= 2);
    }

    #[test]
    fn alert_json_value_adds_entities_and_resolved_process() {
        let alert = sample_alert();
        let catalog = vec![AlertProcessPivot {
            pid: 4242,
            ppid: Some(321),
            name: "/usr/bin/python3".to_string(),
            display_name: "python3".to_string(),
            user: Some("analyst".to_string()),
            group: Some("staff".to_string()),
            cpu_percent: Some(12.5),
            mem_percent: Some(2.4),
            hostname: "edge-1".to_string(),
            platform: "linux".to_string(),
            cmd_line: Some("/usr/bin/python3 suspicious.py".to_string()),
            exe_path: Some("/usr/bin/python3".to_string()),
        }];

        let payload = alert_json_value(&alert, 7, "edge-1", &catalog);

        assert_eq!(payload["id"].as_u64(), Some(7));
        assert_eq!(payload["process_resolution"].as_str(), Some("unique"));
        assert_eq!(payload["process"]["pid"].as_u64(), Some(4242));
        assert!(
            payload["process_names"]
                .as_array()
                .unwrap_or(&vec![])
                .iter()
                .filter_map(|value| value.as_str())
                .any(|name| name.contains("python"))
        );
        assert!(
            payload["entities"]
                .as_array()
                .unwrap_or(&vec![])
                .iter()
                .any(|entity| entity["entity_type"].as_str() == Some("ProcessName"))
        );
    }

    #[test]
    fn alert_json_value_resolves_remote_host_processes_via_combined_catalog() {
        let mut alert = sample_alert();
        alert.hostname = "edge-7".to_string();
        let combined_catalog = vec![
            AlertProcessPivot {
                pid: 1111,
                ppid: Some(1),
                name: "bash".to_string(),
                display_name: "bash".to_string(),
                user: None,
                group: None,
                cpu_percent: None,
                mem_percent: None,
                hostname: "console-host".to_string(),
                platform: "linux".to_string(),
                cmd_line: None,
                exe_path: None,
            },
            AlertProcessPivot {
                pid: 9090,
                ppid: Some(1),
                name: "/usr/bin/python3".to_string(),
                display_name: "python3".to_string(),
                user: Some("svc".to_string()),
                group: None,
                cpu_percent: None,
                mem_percent: None,
                hostname: "edge-7".to_string(),
                platform: "remote".to_string(),
                cmd_line: Some("/usr/bin/python3 worker.py".to_string()),
                exe_path: Some("/usr/bin/python3".to_string()),
            },
        ];

        let payload = alert_json_value(&alert, 0, "console-host", &combined_catalog);

        assert_eq!(payload["process_resolution"].as_str(), Some("unique"));
        assert_eq!(payload["process"]["pid"].as_u64(), Some(9090));
        assert_eq!(payload["process"]["hostname"].as_str(), Some("edge-7"));
    }

    #[test]
    fn alert_json_value_falls_back_to_remote_host_when_no_pivots_match() {
        let mut alert = sample_alert();
        alert.hostname = "edge-9".to_string();
        // Catalog has no entries for edge-9, only for the local console host.
        let catalog = vec![AlertProcessPivot {
            pid: 1111,
            ppid: Some(1),
            name: "bash".to_string(),
            display_name: "bash".to_string(),
            user: None,
            group: None,
            cpu_percent: None,
            mem_percent: None,
            hostname: "console-host".to_string(),
            platform: "linux".to_string(),
            cmd_line: None,
            exe_path: None,
        }];

        let payload = alert_json_value(&alert, 0, "console-host", &catalog);

        assert_eq!(payload["process_resolution"].as_str(), Some("remote_host"));
        assert!(payload.get("process_candidates").is_none());
        assert!(payload.get("process").is_none());
    }
}
