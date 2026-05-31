//! Control-plane posture and failover-drill helpers.
//!
//! Extracted from `server.rs` as part of the incremental decomposition of the
//! monolithic module. Covers the backup-record scanning helpers, the
//! `BackupStatusSnapshot` / `ControlPlanePostureSnapshot` aggregates, the
//! cluster snapshot used by `/api/cluster/*` endpoints, and the failover-drill
//! evaluation logic that backs `crate::support::FailoverDrillRecord`.

use std::fs;
use std::path::Path;

#[allow(unused_imports)]
use crate::server::*;
use crate::support::FailoverDrillRecord;

pub(crate) fn backup_file_record(path: &Path) -> Result<crate::backup::BackupRecord, String> {
    let metadata =
        fs::metadata(path).map_err(|e| format!("failed to read backup metadata: {e}"))?;
    let contents = fs::read(path).map_err(|e| format!("failed to read backup file: {e}"))?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "invalid backup file name".to_string())?
        .to_string();
    let modified = metadata.modified().unwrap_or(std::time::UNIX_EPOCH);
    let timestamp = chrono::DateTime::<chrono::Utc>::from(modified).to_rfc3339();

    Ok(crate::backup::BackupRecord {
        name,
        timestamp,
        size_bytes: metadata.len(),
        checksum: crate::audit::sha256_hex(&contents),
        verified: true,
    })
}

pub(crate) fn is_runtime_backup_file(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }

    match path.file_name().and_then(|value| value.to_str()) {
        Some(file_name) => file_name.starts_with("wardex_backup_") && file_name.ends_with(".db"),
        None => false,
    }
}

pub(crate) fn backup_records_in_dir(backup_path: &Path) -> Vec<crate::backup::BackupRecord> {
    let mut records = fs::read_dir(backup_path)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(Result::ok))
        .map(|entry| entry.path())
        .filter(|path| is_runtime_backup_file(path))
        .filter_map(|path| backup_file_record(&path).ok())
        .collect::<Vec<_>>();
    records.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    records
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct BackupStatusSnapshot {
    pub(crate) enabled: bool,
    pub(crate) retention_count: u32,
    pub(crate) path: String,
    pub(crate) schedule_cron: String,
    pub(crate) observed_backups: usize,
    pub(crate) latest_backup_at: Option<String>,
}

impl BackupStatusSnapshot {
    pub(crate) fn gather() -> Self {
        let config = crate::backup::BackupConfig::default();
        let backup_path = Path::new(&config.path);
        let records = backup_records_in_dir(backup_path);

        Self {
            enabled: config.enabled,
            retention_count: config.retention_count,
            path: config.path,
            schedule_cron: config.schedule_cron,
            observed_backups: records.len(),
            latest_backup_at: records.first().map(|record| record.timestamp.clone()),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ControlPlaneClusterSnapshot {
    pub(crate) node_id: String,
    pub(crate) role: String,
    pub(crate) leader_id: Option<String>,
    pub(crate) peers_total: usize,
    pub(crate) peers_reachable: usize,
    pub(crate) commit_index: u64,
    pub(crate) healthy: bool,
    pub(crate) primary_region: String,
    pub(crate) replica_regions: Vec<String>,
    pub(crate) replica_lag_entries: u64,
    pub(crate) replication_health: String,
    pub(crate) replicas: Vec<ControlPlaneReplicaSnapshot>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ControlPlaneReplicaSnapshot {
    pub(crate) node_id: String,
    pub(crate) addr: String,
    pub(crate) replica_region: String,
    pub(crate) reachable: bool,
    pub(crate) match_index: u64,
    pub(crate) lag_entries: u64,
}

pub(crate) fn control_plane_cluster_snapshot(
    state: &AppState,
) -> Option<ControlPlaneClusterSnapshot> {
    let health = state.cluster.health();
    if health.peers_total == 0 {
        return None;
    }

    let replication = state.cluster.replication_state();

    Some(ControlPlaneClusterSnapshot {
        node_id: health.node_id.to_string(),
        role: health.role.to_string(),
        leader_id: health.leader_id.map(|leader_id| leader_id.to_string()),
        peers_total: health.peers_total,
        peers_reachable: health.peers_reachable,
        commit_index: health.commit_index,
        healthy: health.healthy,
        primary_region: replication.primary_region,
        replica_regions: replication.replica_regions,
        replica_lag_entries: replication.max_lag_entries,
        replication_health: replication.replication_health,
        replicas: replication
            .replicas
            .into_iter()
            .map(|replica| ControlPlaneReplicaSnapshot {
                node_id: replica.node_id.to_string(),
                addr: replica.addr,
                replica_region: replica.replica_region,
                reachable: replica.reachable,
                match_index: replica.match_index,
                lag_entries: replica.lag_entries,
            })
            .collect(),
    })
}

pub(crate) fn control_plane_failover_history_preview(state: &AppState) -> serde_json::Value {
    let backup_status = BackupStatusSnapshot::gather();
    let control_plane = ControlPlanePostureSnapshot::gather(state, &backup_status);
    let drills = control_plane.failover_drill_history.clone();
    let passed = drills
        .iter()
        .filter(|drill| drill.status == "passed")
        .count();
    let failed = drills
        .iter()
        .filter(|drill| drill.status == "failed")
        .count();

    serde_json::json!({
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "kind": "control_plane_failover_history",
        "topology": control_plane.topology,
        "orchestration_scope": control_plane.orchestration_scope,
        "ha_mode": control_plane.ha_mode,
        "documented_failover": control_plane.documented_failover,
        "recovery_status": control_plane.recovery_status,
        "cluster": control_plane.cluster,
        "latest_drill": control_plane.failover_drill,
        "drill_count": drills.len(),
        "passed_count": passed,
        "failed_count": failed,
        "history": drills,
    })
}

pub(crate) fn failover_drill_orchestration_scope(topology: &str) -> String {
    if topology == "standalone" {
        "standalone_reference".to_string()
    } else {
        "non_standalone_orchestrated".to_string()
    }
}

pub(crate) fn failover_drill_type(topology: &str) -> &'static str {
    if topology == "standalone" {
        "warm_standby_restore_dry_run"
    } else {
        "leader_handoff_restore_dry_run"
    }
}

pub(crate) fn control_plane_ha_mode(cluster: Option<&ControlPlaneClusterSnapshot>) -> &'static str {
    match cluster.map(|cluster| cluster.role.as_str()) {
        None => "active_passive_reference",
        Some("leader") => "leader_handoff_primary",
        Some("follower") => "external_standby",
        Some("candidate") => "leader_election",
        Some(_) => "non_standalone_orchestrated",
    }
}

pub(crate) fn control_plane_recovery_status(
    cluster: Option<&ControlPlaneClusterSnapshot>,
    durable_storage: bool,
    restore_ready: bool,
) -> String {
    if !durable_storage || !restore_ready {
        return "review".to_string();
    }

    match cluster {
        None => "ready_for_documented_failover".to_string(),
        Some(cluster) if !cluster.healthy => "review".to_string(),
        Some(cluster) if cluster.role == "leader" => "ready_for_leader_handoff".to_string(),
        Some(cluster) if cluster.role == "follower" => "ready_as_external_standby".to_string(),
        Some(_) => "leader_election_in_progress".to_string(),
    }
}

pub(crate) fn control_plane_documented_failover(
    cluster: Option<&ControlPlaneClusterSnapshot>,
) -> &'static str {
    if cluster.is_some() {
        "leader_handoff_or_external_standby_restore"
    } else {
        "warm_standby_restore"
    }
}

pub(crate) fn failover_drill_summary(
    durable_storage_verified: bool,
    backup_artifact_verified: bool,
    checkpoint_artifact_verified: bool,
) -> String {
    match (
        durable_storage_verified,
        backup_artifact_verified,
        checkpoint_artifact_verified,
    ) {
        (true, true, true) => "Validated durable event storage with both backup and checkpoint artifacts for the documented failover path.".to_string(),
        (true, true, false) => "Validated durable event storage with backup artifacts for the documented failover path.".to_string(),
        (true, false, true) => "Validated durable event storage with checkpoint artifacts for the documented failover path.".to_string(),
        (false, false, false) => "Failover drill failed because durable event storage is disabled and no backup or checkpoint artifacts were available.".to_string(),
        (false, _, _) => "Failover drill failed because durable event storage is disabled.".to_string(),
        (true, false, false) => "Failover drill failed because no backup or checkpoint artifacts were available for recovery validation.".to_string(),
    }
}

impl FailoverDrillRecord {
    pub(crate) fn not_run(topology: &str) -> Self {
        Self {
            drill_type: failover_drill_type(topology).to_string(),
            orchestration_scope: failover_drill_orchestration_scope(topology),
            status: "not_run".to_string(),
            last_run_at: None,
            actor: None,
            summary: "No automated failover drill has been recorded yet.".to_string(),
            artifact_source: "none".to_string(),
            durable_storage_verified: false,
            backup_artifact_verified: false,
            checkpoint_artifact_verified: false,
        }
    }

    pub(crate) fn evaluate(state: &AppState, backup: &BackupStatusSnapshot, actor: &str) -> Self {
        let topology = if control_plane_cluster_snapshot(state).is_some() {
            "clustered"
        } else {
            "standalone"
        };
        let durable_storage_verified = state.event_store.has_persistence();
        let backup_artifact_verified = backup.observed_backups > 0;
        let checkpoint_artifact_verified = !state.checkpoints.is_empty();
        let artifact_source = match (backup_artifact_verified, checkpoint_artifact_verified) {
            (true, true) => "backup_and_checkpoint",
            (true, false) => "backup",
            (false, true) => "checkpoint",
            (false, false) => "none",
        };

        Self {
            drill_type: failover_drill_type(topology).to_string(),
            orchestration_scope: failover_drill_orchestration_scope(topology),
            status: if durable_storage_verified
                && (backup_artifact_verified || checkpoint_artifact_verified)
            {
                "passed".to_string()
            } else {
                "failed".to_string()
            },
            last_run_at: Some(chrono::Utc::now().to_rfc3339()),
            actor: Some(actor.to_string()),
            summary: failover_drill_summary(
                durable_storage_verified,
                backup_artifact_verified,
                checkpoint_artifact_verified,
            ),
            artifact_source: artifact_source.to_string(),
            durable_storage_verified,
            backup_artifact_verified,
            checkpoint_artifact_verified,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ControlPlanePostureSnapshot {
    pub(crate) topology: String,
    pub(crate) orchestration_scope: String,
    pub(crate) ha_mode: String,
    pub(crate) leader: bool,
    pub(crate) durable_storage: bool,
    pub(crate) event_store_path: String,
    pub(crate) backup_schedule_cron: String,
    pub(crate) observed_backups: usize,
    pub(crate) latest_backup_at: Option<String>,
    pub(crate) checkpoint_count: usize,
    pub(crate) latest_checkpoint_at: Option<String>,
    pub(crate) restore_ready: bool,
    pub(crate) recovery_status: String,
    pub(crate) documented_failover: String,
    pub(crate) recovery_targets: Vec<RecoveryTargetEntry>,
    pub(crate) cluster: Option<ControlPlaneClusterSnapshot>,
    pub(crate) failover_drill: FailoverDrillRecord,
    pub(crate) failover_drill_history: Vec<FailoverDrillRecord>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct RecoveryTargetEntry {
    pub(crate) scenario: String,
    pub(crate) rto: String,
    pub(crate) rpo: String,
}

impl ControlPlanePostureSnapshot {
    pub(crate) fn gather(state: &AppState, backup: &BackupStatusSnapshot) -> Self {
        let checkpoint_count = state.checkpoints.len();
        let latest_checkpoint_at = state.checkpoints.latest().map(|entry| {
            chrono::DateTime::<chrono::Utc>::from(
                std::time::UNIX_EPOCH + std::time::Duration::from_millis(entry.timestamp_ms),
            )
            .to_rfc3339()
        });
        let durable_storage = state.event_store.has_persistence();
        let restore_ready = backup.observed_backups > 0 || checkpoint_count > 0;
        let cluster = control_plane_cluster_snapshot(state);
        let topology = if cluster.is_some() {
            "clustered".to_string()
        } else {
            "standalone".to_string()
        };
        let orchestration_scope = failover_drill_orchestration_scope(&topology);
        let mut failover_drill_history = state.support_store.failover_drills().to_vec();
        if failover_drill_history.is_empty()
            && let Some(drill) = state.last_failover_drill.clone()
        {
            failover_drill_history.push(drill);
        }
        let failover_drill = state
            .support_store
            .latest_failover_drill()
            .or_else(|| state.last_failover_drill.clone())
            .unwrap_or_else(|| FailoverDrillRecord::not_run(&topology));
        let recovery_targets = vec![
            RecoveryTargetEntry {
                scenario: "Config corruption".to_string(),
                rto: "< 5 min".to_string(),
                rpo: "Last backup".to_string(),
            },
            RecoveryTargetEntry {
                scenario: "Full disk loss".to_string(),
                rto: "< 15 min".to_string(),
                rpo: "Daily backup (24 h)".to_string(),
            },
            RecoveryTargetEntry {
                scenario: "Key compromise".to_string(),
                rto: "< 30 min".to_string(),
                rpo: "Rotate + re-enroll agents".to_string(),
            },
            RecoveryTargetEntry {
                scenario: "Binary corruption".to_string(),
                rto: "< 10 min".to_string(),
                rpo: "Redeploy from CI artefact".to_string(),
            },
        ];

        Self {
            topology,
            orchestration_scope,
            ha_mode: control_plane_ha_mode(cluster.as_ref()).to_string(),
            leader: cluster
                .as_ref()
                .map(|cluster| cluster.role == "leader")
                .unwrap_or(true),
            durable_storage,
            event_store_path: state
                .event_store
                .storage_path()
                .unwrap_or("memory")
                .to_string(),
            backup_schedule_cron: backup.schedule_cron.clone(),
            observed_backups: backup.observed_backups,
            latest_backup_at: backup.latest_backup_at.clone(),
            checkpoint_count,
            latest_checkpoint_at,
            restore_ready,
            recovery_status: control_plane_recovery_status(
                cluster.as_ref(),
                durable_storage,
                restore_ready,
            ),
            documented_failover: control_plane_documented_failover(cluster.as_ref()).to_string(),
            recovery_targets,
            cluster,
            failover_drill,
            failover_drill_history,
        }
    }

    pub(crate) fn ha_mode_payload(&self) -> serde_json::Value {
        let status = match self.cluster.as_ref() {
            Some(cluster) if self.durable_storage && self.restore_ready && cluster.healthy => {
                "ready_for_orchestrated_failover"
            }
            None if self.durable_storage && self.restore_ready => "ready_for_active_passive",
            _ => "review",
        };
        serde_json::json!({
            "mode": self.ha_mode,
            "topology": self.topology,
            "orchestration_scope": self.orchestration_scope,
            "status": status,
            "leader": self.leader,
            "recovery_status": self.recovery_status,
            "documented_failover": self.documented_failover,
            "observed_backups": self.observed_backups,
            "latest_backup_at": self.latest_backup_at,
            "checkpoint_count": self.checkpoint_count,
            "latest_checkpoint_at": self.latest_checkpoint_at,
            "restore_ready": self.restore_ready,
            "cluster": self.cluster,
            "failover_drill_history_count": self.failover_drill_history.len(),
            "failover_drill": self.failover_drill.clone(),
        })
    }
}
