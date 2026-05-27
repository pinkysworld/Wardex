//! Alert ↔ process pivot helpers.
//!
//! Extracted from `server.rs` as part of the incremental decomposition of the
//! monolithic module. Covers the `AlertProcessPivot` data shape plus the helper
//! functions that build a per-host process catalog (live local + remote tree)
//! and resolve alerts against it for the alerts JSON payloads.

use std::collections::HashSet;

#[allow(unused_imports)]
use crate::server::*;

#[derive(Debug, Clone, serde::Serialize, PartialEq)]
pub(crate) struct AlertProcessPivot {
    pub(crate) pid: u32,
    pub(crate) ppid: Option<u32>,
    pub(crate) name: String,
    pub(crate) display_name: String,
    pub(crate) user: Option<String>,
    pub(crate) group: Option<String>,
    pub(crate) cpu_percent: Option<f32>,
    pub(crate) mem_percent: Option<f32>,
    pub(crate) hostname: String,
    pub(crate) platform: String,
    pub(crate) cmd_line: Option<String>,
    pub(crate) exe_path: Option<String>,
}

pub(crate) fn normalized_process_token(value: &str) -> String {
    let token = value
        .split_whitespace()
        .next()
        .unwrap_or(value)
        .trim_matches('"');
    let base = token
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(token)
        .trim_end_matches(':');
    base.trim_end_matches(".exe").to_ascii_lowercase()
}

pub(crate) fn host_matches_local(alert_hostname: &str, local_hostname: &str) -> bool {
    if alert_hostname.eq_ignore_ascii_case(local_hostname) {
        return true;
    }
    let alert_short = alert_hostname.split('.').next().unwrap_or(alert_hostname);
    let local_short = local_hostname.split('.').next().unwrap_or(local_hostname);
    alert_short.eq_ignore_ascii_case(local_short)
}

pub(crate) fn extract_alert_process_names(
    entities: &[crate::entity_extract::ExtractedEntity],
) -> Vec<String> {
    let mut seen = HashSet::new();
    entities
        .iter()
        .filter(|entity| {
            matches!(
                entity.entity_type,
                crate::entity_extract::EntityType::ProcessName
            )
        })
        .filter_map(|entity| {
            let normalized = normalized_process_token(&entity.value);
            if normalized.is_empty() || !seen.insert(normalized.clone()) {
                None
            } else {
                Some(normalized)
            }
        })
        .collect()
}

pub(crate) fn alert_process_matches_name(process: &AlertProcessPivot, process_name: &str) -> bool {
    let target = normalized_process_token(process_name);
    if target.is_empty() {
        return false;
    }
    [
        process.display_name.as_str(),
        process.name.as_str(),
        process.exe_path.as_deref().unwrap_or(""),
        process.cmd_line.as_deref().unwrap_or(""),
    ]
    .iter()
    .map(|value| normalized_process_token(value))
    .any(|candidate| !candidate.is_empty() && candidate == target)
}

pub(crate) fn resolve_alert_process_pivots(
    process_names: &[String],
    catalog: &[AlertProcessPivot],
    alert_hostname: &str,
) -> Vec<AlertProcessPivot> {
    let mut matched = catalog
        .iter()
        .filter(|process| host_matches_local(&process.hostname, alert_hostname))
        .filter(|process| {
            process_names
                .iter()
                .any(|process_name| alert_process_matches_name(process, process_name))
        })
        .cloned()
        .collect::<Vec<_>>();
    matched.sort_by(|left, right| {
        right
            .cpu_percent
            .unwrap_or(0.0)
            .partial_cmp(&left.cpu_percent.unwrap_or(0.0))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                right
                    .mem_percent
                    .unwrap_or(0.0)
                    .partial_cmp(&left.mem_percent.unwrap_or(0.0))
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| left.display_name.cmp(&right.display_name))
    });
    matched.dedup_by_key(|process| process.pid);
    matched.truncate(4);
    matched
}

/// Strip directory components from a process path; mirrors the helper in
/// `collector_linux` / `collector_macos`.
fn process_basename(value: &str) -> &str {
    value
        .rsplit(['/', '\\'])
        .next()
        .filter(|segment| !segment.is_empty())
        .unwrap_or(value)
}

#[cfg(target_os = "macos")]
pub(crate) fn live_alert_process_catalog(local_hostname: &str) -> Vec<AlertProcessPivot> {
    crate::collector_macos::collect_processes()
        .into_iter()
        .map(|process| {
            let name = process.name;
            let display_name = process_basename(&name).to_string();
            let exe_path = if name.contains('/') {
                Some(name.clone())
            } else {
                None
            };
            AlertProcessPivot {
                pid: process.pid,
                ppid: Some(process.ppid),
                name,
                display_name,
                user: Some(process.user),
                group: Some(process.group),
                cpu_percent: Some(process.cpu_percent),
                mem_percent: Some(process.mem_percent),
                hostname: local_hostname.to_string(),
                platform: "macos".to_string(),
                cmd_line: None,
                exe_path,
            }
        })
        .collect()
}

#[cfg(target_os = "linux")]
pub(crate) fn live_alert_process_catalog(local_hostname: &str) -> Vec<AlertProcessPivot> {
    crate::collector_linux::collect_processes()
        .into_iter()
        .map(|process| {
            let display_name = process_basename(&process.name).to_string();
            AlertProcessPivot {
                pid: process.pid,
                ppid: Some(process.ppid),
                name: process.name,
                display_name,
                user: Some(if process.uid == 0 {
                    "root".to_string()
                } else {
                    format!("uid:{}", process.uid)
                }),
                group: Some(format!("gid:{}", process.gid)),
                cpu_percent: None,
                mem_percent: None,
                hostname: local_hostname.to_string(),
                platform: "linux".to_string(),
                cmd_line: (!process.cmd_line.is_empty()).then_some(process.cmd_line),
                exe_path: (!process.exe_path.is_empty()).then_some(process.exe_path),
            }
        })
        .collect()
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub(crate) fn live_alert_process_catalog(_local_hostname: &str) -> Vec<AlertProcessPivot> {
    Vec::new()
}

/// Build alert process pivots for processes tracked from remote hosts via the
/// central process tree. Local-host nodes are skipped — they are already covered
/// by `live_alert_process_catalog`. Returns up to 256 alive remote nodes.
pub(crate) fn remote_alert_process_catalog(
    process_tree: &crate::process_tree::ProcessTree,
    local_hostname: &str,
) -> Vec<AlertProcessPivot> {
    process_tree
        .alive_processes()
        .into_iter()
        .filter(|node| !host_matches_local(&node.hostname, local_hostname))
        .take(256)
        .map(|node| {
            let display_name = process_basename(&node.name).to_string();
            AlertProcessPivot {
                pid: node.pid,
                ppid: Some(node.ppid),
                name: node.name.clone(),
                display_name,
                user: node.user.clone(),
                group: None,
                cpu_percent: None,
                mem_percent: None,
                hostname: node.hostname.clone(),
                platform: "remote".to_string(),
                cmd_line: node.cmd_line.clone(),
                exe_path: node.exe_path.clone(),
            }
        })
        .collect()
}

/// Combine the local-host live process catalog with remote process-tree pivots
/// so alerts originating on any tracked host can be resolved to a process.
pub(crate) fn assemble_alert_process_catalog(
    local_hostname: &str,
    process_tree: &crate::process_tree::ProcessTree,
) -> Vec<AlertProcessPivot> {
    let mut catalog = live_alert_process_catalog(local_hostname);
    catalog.extend(remote_alert_process_catalog(process_tree, local_hostname));
    catalog
}

pub(crate) fn alert_process_resolution(
    alert_hostname: &str,
    local_hostname: &str,
    process_names: &[String],
    process_candidates: &[AlertProcessPivot],
) -> &'static str {
    if process_names.is_empty() {
        "none"
    } else if process_candidates.len() == 1 {
        "unique"
    } else if process_candidates.len() > 1 {
        "multiple"
    } else if !host_matches_local(alert_hostname, local_hostname) {
        "remote_host"
    } else {
        "unresolved"
    }
}
