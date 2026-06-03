//! Evidence-freshness and operational-snapshot persistence helpers.
//!
//! Extracted from `server.rs` as part of the incremental decomposition of the
//! monolithic module. This module owns:
//!
//! * **Evidence freshness envelopes** (`evidence_freshness`,
//!   `with_evidence_freshness`, `payload_evidence_freshness`,
//!   `evidence_freshness_check`) — the schema-versioned metadata that release,
//!   container, observability, synthetic-console, and similar readiness
//!   builders attach to their payloads.
//! * **Operational-snapshot storage** (`persist_operational_snapshot`,
//!   `list_operational_snapshots`, `verify_operational_snapshot`,
//!   `snapshot_entry_from_path`, `safe_snapshot_lookup_path`,
//!   `payload_with_snapshot`, `build_snapshot_policy_payload`,
//!   `prune_operational_snapshots`) — durable JSON envelopes under
//!   `<storage_root>/operational_snapshots/<kind>/<file>.json`.
//!
//! Plus the shared support helpers (`operational_snapshot_kind`,
//! `storage_root_path`, `short_digest`, `evidence_request_id`,
//! `evidence_environment_id`) and the `EVIDENCE_FRESHNESS_WINDOW_SECS` window.

use std::fs;
use std::path::{Path, PathBuf};

#[allow(unused_imports)]
use crate::server::*;

pub(crate) const EVIDENCE_FRESHNESS_WINDOW_SECS: i64 = 6 * 60 * 60;

pub(crate) fn operational_snapshot_kind(kind: &str) -> String {
    kind.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>()
}

pub(crate) fn storage_root_path(storage: &crate::storage::SharedStorage) -> Option<PathBuf> {
    storage
        .with(|store| Ok(store.stats().storage_path))
        .ok()
        .map(PathBuf::from)
}

pub(crate) fn short_digest(value: &str, width: usize) -> String {
    value.chars().take(width).collect()
}

pub(crate) fn evidence_request_id() -> String {
    crate::structured_log::generate_request_id()
        .unwrap_or_else(|_| format!("req-fallback-{}", chrono::Utc::now().timestamp_micros()))
}

pub(crate) fn evidence_environment_id(state: &AppState) -> String {
    let source = format!(
        "{}:{}:{}",
        state.local_host_info.hostname,
        state.config_path.display(),
        env!("CARGO_PKG_VERSION")
    );
    short_digest(&crate::audit::sha256_hex(source.as_bytes()), 16)
}

pub(crate) fn evidence_freshness(
    state: &AppState,
    kind: &str,
    mode: &str,
    source: &str,
    status: &str,
    stale_reason: Option<&str>,
    critical: bool,
    artifacts: serde_json::Value,
) -> serde_json::Value {
    let collected_at = chrono::Utc::now();
    let expires_at = collected_at + chrono::Duration::seconds(EVIDENCE_FRESHNESS_WINDOW_SECS);
    let artifact_digest = crate::audit::sha256_hex(
        serde_json::json!({
            "kind": kind,
            "mode": mode,
            "source": source,
            "runtime_version": env!("CARGO_PKG_VERSION"),
            "artifacts": artifacts,
        })
        .to_string()
        .as_bytes(),
    );
    serde_json::json!({
        "schema": "wardex.evidence_freshness.v1",
        "kind": kind,
        "mode": mode,
        "source": source,
        "status": status,
        "critical": critical,
        "environment_id": evidence_environment_id(state),
        "run_id": format!("{kind}-{}", short_digest(&artifact_digest, 12)),
        "request_id": evidence_request_id(),
        "collected_at": collected_at.to_rfc3339(),
        "expires_at": expires_at.to_rfc3339(),
        "fresh_for_secs": EVIDENCE_FRESHNESS_WINDOW_SECS,
        "artifact_digest": artifact_digest,
        "stale_reason": stale_reason,
    })
}

pub(crate) fn with_evidence_freshness(
    mut payload: serde_json::Value,
    evidence: serde_json::Value,
) -> serde_json::Value {
    if let Some(map) = payload.as_object_mut() {
        map.insert("evidence_freshness".to_string(), evidence);
        payload
    } else {
        serde_json::json!({
            "payload": payload,
            "evidence_freshness": evidence,
        })
    }
}

pub(crate) fn payload_evidence_freshness(payload: &serde_json::Value) -> Option<serde_json::Value> {
    payload.get("evidence_freshness").cloned()
}

pub(crate) fn evidence_freshness_check(
    id: &str,
    label: &str,
    payload: &serde_json::Value,
    critical: bool,
) -> serde_json::Value {
    let evidence = payload.get("evidence_freshness");
    let status = evidence
        .and_then(|value| value.get("status"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");
    let mode = evidence
        .and_then(|value| value.get("mode"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("missing");
    let source = evidence
        .and_then(|value| value.get("source"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unreported");
    let stale_reason = evidence
        .and_then(|value| value.get("stale_reason"))
        .and_then(serde_json::Value::as_str);
    let check_status = if status == "fresh" {
        "pass"
    } else if critical {
        "fail"
    } else {
        "warn"
    };
    serde_json::json!({
        "id": id,
        "status": check_status,
        "detail": if let Some(reason) = stale_reason {
            format!("{label} evidence is {status} from {mode} ({source}): {reason}.")
        } else {
            format!("{label} evidence is {status} from {mode} ({source}).")
        },
        "evidence_status": status,
        "evidence_mode": mode,
        "critical": critical,
    })
}

pub(crate) fn snapshot_entry_from_path(
    root: &Path,
    path: &Path,
    include_payload: bool,
) -> Option<serde_json::Value> {
    let bytes = fs::read(path).ok()?;
    let envelope: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let payload = envelope.get("payload");
    let digest = envelope.get("digest").and_then(serde_json::Value::as_str)?;
    let computed_digest =
        payload.map(|payload| crate::audit::sha256_hex(payload.to_string().as_bytes()));
    let verified = computed_digest.as_deref() == Some(digest);
    let relative = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    let storage_key = format!("operational_snapshots/{relative}");
    let mut entry = serde_json::json!({
        "kind": envelope.get("kind").and_then(serde_json::Value::as_str).unwrap_or("unknown"),
        "digest": digest,
        "generated_at": envelope.get("generated_at").cloned().unwrap_or(serde_json::Value::Null),
        "storage_key": storage_key,
        "size_bytes": bytes.len(),
        "verified": verified,
        "evidence_freshness": envelope.get("evidence_freshness").cloned().unwrap_or(serde_json::Value::Null),
    });
    if include_payload && let Some(map) = entry.as_object_mut() {
        map.insert(
            "payload".to_string(),
            payload.cloned().unwrap_or(serde_json::Value::Null),
        );
    }
    Some(entry)
}

pub(crate) fn list_operational_snapshots(
    storage: &crate::storage::SharedStorage,
    kind_filter: Option<&str>,
    limit: usize,
) -> serde_json::Value {
    let generated_at = chrono::Utc::now().to_rfc3339();
    let Some(storage_path) = storage_root_path(storage) else {
        return serde_json::json!({
            "generated_at": generated_at,
            "status": "unavailable",
            "snapshots": [],
            "count": 0,
            "error": "storage_unavailable",
        });
    };
    let root = storage_path.join("operational_snapshots");
    let requested_kind = kind_filter
        .map(operational_snapshot_kind)
        .filter(|value| !value.is_empty());
    let limit = limit.clamp(1, 500);
    let mut candidates = Vec::new();
    if let Ok(kind_dirs) = fs::read_dir(&root) {
        for kind_dir in kind_dirs.flatten() {
            let Ok(file_type) = kind_dir.file_type() else {
                continue;
            };
            if !file_type.is_dir() {
                continue;
            }
            let kind_name = kind_dir.file_name().to_string_lossy().to_string();
            if let Some(ref requested_kind) = requested_kind
                && requested_kind != &kind_name
            {
                continue;
            }
            if let Ok(files) = fs::read_dir(kind_dir.path()) {
                for file in files.flatten() {
                    let Ok(file_type) = file.file_type() else {
                        continue;
                    };
                    if file_type.is_file()
                        && file.path().extension().and_then(|value| value.to_str()) == Some("json")
                    {
                        let modified = file
                            .metadata()
                            .ok()
                            .and_then(|metadata| metadata.modified().ok());
                        candidates.push((modified, file.path()));
                    }
                }
            }
        }
    }
    candidates.sort_by(|(left_modified, left_path), (right_modified, right_path)| {
        right_modified
            .cmp(left_modified)
            .then_with(|| right_path.cmp(left_path))
    });
    let mut snapshots = candidates
        .into_iter()
        .take(limit)
        .filter_map(|(_, path)| snapshot_entry_from_path(&root, &path, false))
        .collect::<Vec<_>>();
    snapshots.sort_by(|left, right| {
        right
            .get("generated_at")
            .and_then(serde_json::Value::as_str)
            .cmp(&left.get("generated_at").and_then(serde_json::Value::as_str))
    });
    let verified_count = snapshots
        .iter()
        .filter(|entry| {
            entry
                .get("verified")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
        })
        .count();
    serde_json::json!({
        "generated_at": generated_at,
        "status": if snapshots.is_empty() { "empty" } else { "indexed" },
        "storage_root": "operational_snapshots",
        "kind_filter": requested_kind,
        "count": snapshots.len(),
        "verified_count": verified_count,
        "snapshots": snapshots,
    })
}

pub(crate) fn safe_snapshot_lookup_path(root: &Path, storage_key: &str) -> Option<PathBuf> {
    let key = storage_key
        .strip_prefix("operational_snapshots/")
        .unwrap_or(storage_key)
        .trim();
    if key.is_empty()
        || key.starts_with('/')
        || key.contains("..")
        || key.contains('\\')
        || key.split('/').any(|part| part.is_empty() || part == ".")
    {
        return None;
    }
    Some(root.join(key))
}

pub(crate) fn verify_operational_snapshot(
    storage: &crate::storage::SharedStorage,
    storage_key: Option<&str>,
    digest: Option<&str>,
) -> serde_json::Value {
    let generated_at = chrono::Utc::now().to_rfc3339();
    let Some(storage_path) = storage_root_path(storage) else {
        return serde_json::json!({
            "generated_at": generated_at,
            "status": "unavailable",
            "verified": false,
            "error": "storage_unavailable",
        });
    };
    let root = storage_path.join("operational_snapshots");
    let entry = if let Some(storage_key) = storage_key {
        safe_snapshot_lookup_path(&root, storage_key)
            .and_then(|path| snapshot_entry_from_path(&root, &path, true))
    } else if let Some(digest) = digest {
        list_operational_snapshots(storage, None, 500)
            .get("snapshots")
            .and_then(serde_json::Value::as_array)
            .and_then(|items| {
                items
                    .iter()
                    .find(|entry| {
                        entry.get("digest").and_then(serde_json::Value::as_str) == Some(digest)
                    })
                    .and_then(|entry| {
                        let storage_key = entry.get("storage_key")?.as_str()?;
                        safe_snapshot_lookup_path(&root, storage_key)
                            .and_then(|path| snapshot_entry_from_path(&root, &path, true))
                    })
            })
    } else {
        None
    };
    match entry {
        Some(entry) => serde_json::json!({
            "generated_at": generated_at,
            "status": if entry.get("verified").and_then(serde_json::Value::as_bool).unwrap_or(false) { "verified" } else { "digest_mismatch" },
            "verified": entry.get("verified").and_then(serde_json::Value::as_bool).unwrap_or(false),
            "snapshot": entry,
        }),
        None => serde_json::json!({
            "generated_at": generated_at,
            "status": "not_found",
            "verified": false,
            "error": "snapshot_not_found",
        }),
    }
}

pub(crate) fn persist_operational_snapshot(
    storage: &crate::storage::SharedStorage,
    kind: &str,
    payload: &serde_json::Value,
) -> serde_json::Value {
    let digest = crate::audit::sha256_hex(payload.to_string().as_bytes());
    let generated_at = chrono::Utc::now().to_rfc3339();
    let Some(storage_path) = storage_root_path(storage) else {
        return serde_json::json!({
            "persisted": false,
            "digest": digest,
            "error": "storage_unavailable",
        });
    };
    let safe_kind = operational_snapshot_kind(kind);
    let dir = storage_path.join("operational_snapshots").join(&safe_kind);
    if let Err(err) = fs::create_dir_all(&dir) {
        return serde_json::json!({
            "persisted": false,
            "digest": digest,
            "error": format!("snapshot_dir_failed: {err}"),
        });
    }
    let short_digest = digest.chars().take(12).collect::<String>();
    let file_name = format!(
        "{}-{short_digest}.json",
        chrono::Utc::now().timestamp_millis()
    );
    let storage_key = format!("operational_snapshots/{safe_kind}/{file_name}");
    let path = dir.join(&file_name);
    let envelope = serde_json::json!({
        "kind": safe_kind,
        "digest": digest,
        "generated_at": generated_at,
        "evidence_freshness": payload_evidence_freshness(payload),
        "payload": payload,
    });
    match serde_json::to_vec_pretty(&envelope)
        .ok()
        .and_then(|bytes| fs::write(&path, bytes).ok())
    {
        Some(_) => serde_json::json!({
            "persisted": true,
            "digest": envelope["digest"].clone(),
            "generated_at": generated_at,
            "storage_key": storage_key,
        }),
        None => serde_json::json!({
            "persisted": false,
            "digest": envelope["digest"].clone(),
            "error": "snapshot_write_failed",
        }),
    }
}

pub(crate) fn payload_with_snapshot(
    mut payload: serde_json::Value,
    snapshot: serde_json::Value,
) -> serde_json::Value {
    if let Some(map) = payload.as_object_mut() {
        map.insert("snapshot".to_string(), snapshot);
        payload
    } else {
        serde_json::json!({ "generated": payload, "snapshot": snapshot })
    }
}

pub(crate) fn build_snapshot_policy_payload(
    storage: &crate::storage::SharedStorage,
) -> serde_json::Value {
    let snapshots = list_operational_snapshots(storage, None, 500);
    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "status": "configured",
        "keep_latest_per_kind": 25,
        "max_prune_batch": 500,
        "redaction_policy": {
            "sensitive_key_matchers": ["token", "secret", "password", "credential", "authorization", "cookie", "private_key", "api_key"],
            "support_bundle_redacts_before_snapshot": true,
        },
        "snapshot_index": snapshots,
    })
}

pub(crate) fn prune_operational_snapshots(
    storage: &crate::storage::SharedStorage,
    keep_latest: usize,
    dry_run: bool,
) -> serde_json::Value {
    let generated_at = chrono::Utc::now().to_rfc3339();
    let Some(storage_path) = storage_root_path(storage) else {
        return serde_json::json!({
            "generated_at": generated_at,
            "status": "unavailable",
            "dry_run": dry_run,
            "pruned": [],
            "error": "storage_unavailable",
        });
    };
    let root = storage_path.join("operational_snapshots");
    let keep_latest = keep_latest.clamp(1, 500);
    let mut candidates = Vec::new();
    if let Ok(kind_dirs) = fs::read_dir(&root) {
        for kind_dir in kind_dirs.flatten() {
            let Ok(file_type) = kind_dir.file_type() else {
                continue;
            };
            if !file_type.is_dir() {
                continue;
            }
            let kind = kind_dir.file_name().to_string_lossy().to_string();
            let mut files = fs::read_dir(kind_dir.path())
                .ok()
                .into_iter()
                .flat_map(std::iter::Iterator::flatten)
                .filter(|entry| {
                    entry.path().extension().and_then(|value| value.to_str()) == Some("json")
                })
                .collect::<Vec<_>>();
            files.sort_by_key(|entry| std::cmp::Reverse(entry.file_name()));
            for file in files.into_iter().skip(keep_latest) {
                let file_path = file.path();
                let relative = file_path
                    .strip_prefix(&root)
                    .unwrap_or(&file_path)
                    .to_string_lossy()
                    .replace('\\', "/");
                let storage_key = format!("operational_snapshots/{relative}");
                let removed = dry_run || fs::remove_file(&file_path).is_ok();
                candidates.push(serde_json::json!({
                    "kind": kind,
                    "storage_key": storage_key,
                    "removed": removed && !dry_run,
                    "dry_run": dry_run,
                }));
            }
        }
    }
    serde_json::json!({
        "generated_at": generated_at,
        "status": if dry_run { "preview" } else { "applied" },
        "dry_run": dry_run,
        "keep_latest_per_kind": keep_latest,
        "candidate_count": candidates.len(),
        "pruned": candidates,
    })
}
