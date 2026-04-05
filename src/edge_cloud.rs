//! Edge-cloud hybrid offload, cross-platform abstraction, patch management,
//! and long-term evolution strategies.
//!
//! Covers R22 (cross-platform), R25 (long-term evolution),
//! R32 (autonomous patch management), R36 (edge-cloud hybrid).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Workload Offload (R36) ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProcessingTier {
    EdgeOnly,
    EdgePreferred,
    CloudPreferred,
    CloudOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workload {
    pub id: String,
    pub name: String,
    pub cpu_cost: f64,
    pub memory_mb: u64,
    pub latency_sensitive: bool,
    pub data_size_kb: u64,
    pub tier: ProcessingTier,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeCapacity {
    pub cpu_available: f64,
    pub memory_available_mb: u64,
    pub bandwidth_kbps: u64,
    pub latency_to_cloud_ms: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OffloadDecision {
    pub workload_id: String,
    pub run_on: String,
    pub reason: String,
    pub estimated_latency_ms: u32,
}

/// Decide where to run workloads based on edge capacity and requirements.
pub fn decide_offload(
    workloads: &[Workload],
    edge: &EdgeCapacity,
) -> Vec<OffloadDecision> {
    let mut remaining_cpu = edge.cpu_available;
    let mut remaining_mem = edge.memory_available_mb;
    let mut decisions = Vec::new();

    for w in workloads {
        let decision = match w.tier {
            ProcessingTier::EdgeOnly => {
                remaining_cpu = (remaining_cpu - w.cpu_cost).max(0.0);
                remaining_mem = remaining_mem.saturating_sub(w.memory_mb);
                OffloadDecision {
                    workload_id: w.id.clone(),
                    run_on: "edge".into(),
                    reason: "forced edge-only".into(),
                    estimated_latency_ms: 1,
                }
            },
            ProcessingTier::CloudOnly => OffloadDecision {
                workload_id: w.id.clone(),
                run_on: "cloud".into(),
                reason: "forced cloud-only".into(),
                estimated_latency_ms: edge.latency_to_cloud_ms,
            },
            ProcessingTier::EdgePreferred | ProcessingTier::CloudPreferred => {
                let fits_edge = w.cpu_cost <= remaining_cpu
                    && w.memory_mb <= remaining_mem;
                let prefer_edge = matches!(w.tier, ProcessingTier::EdgePreferred)
                    || w.latency_sensitive;

                if fits_edge && prefer_edge {
                    remaining_cpu -= w.cpu_cost;
                    remaining_mem -= w.memory_mb;
                    OffloadDecision {
                        workload_id: w.id.clone(),
                        run_on: "edge".into(),
                        reason: "fits edge capacity".into(),
                        estimated_latency_ms: 1,
                    }
                } else if fits_edge && !prefer_edge {
                    // Cloud preferred but edge has capacity — use cloud anyway
                    OffloadDecision {
                        workload_id: w.id.clone(),
                        run_on: "cloud".into(),
                        reason: "cloud preferred despite edge capacity".into(),
                        estimated_latency_ms: edge.latency_to_cloud_ms,
                    }
                } else {
                    // Doesn't fit edge → cloud
                    OffloadDecision {
                        workload_id: w.id.clone(),
                        run_on: "cloud".into(),
                        reason: "insufficient edge capacity".into(),
                        estimated_latency_ms: edge.latency_to_cloud_ms,
                    }
                }
            }
        };
        decisions.push(decision);
    }
    decisions
}

// ── Cross-Platform Abstraction (R22) ─────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Platform {
    LinuxX86,
    LinuxArm,
    MacOsArm,
    MacOsX86,
    WindowsX86,
    FreeBsd,
    Rtos,
    Wasm,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformCapabilities {
    pub platform: Platform,
    pub has_tpm: bool,
    pub has_seccomp: bool,
    pub has_ebpf: bool,
    pub has_firewall: bool,
    pub max_threads: u32,
    pub process_control: bool,
}

impl PlatformCapabilities {
    pub fn detect_current() -> Self {
        #[cfg(target_os = "linux")]
        {
            Self {
                platform: if cfg!(target_arch = "aarch64") {
                    Platform::LinuxArm
                } else {
                    Platform::LinuxX86
                },
                has_tpm: true,
                has_seccomp: true,
                has_ebpf: true,
                has_firewall: true,
                max_threads: 256,
                process_control: true,
            }
        }
        #[cfg(target_os = "macos")]
        {
            Self {
                platform: if cfg!(target_arch = "aarch64") {
                    Platform::MacOsArm
                } else {
                    Platform::MacOsX86
                },
                has_tpm: false,
                has_seccomp: false,
                has_ebpf: false,
                has_firewall: true,
                max_threads: 256,
                process_control: true,
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Self {
                platform: Platform::FreeBsd,
                has_tpm: false,
                has_seccomp: false,
                has_ebpf: false,
                has_firewall: false,
                max_threads: 64,
                process_control: false,
            }
        }
    }

    /// Check if a given enforcement action is possible on this platform.
    pub fn can_enforce(&self, action: &str) -> bool {
        match action {
            "process_kill" | "process_suspend" => self.process_control,
            "firewall_block" | "rate_limit" => self.has_firewall,
            "seccomp_sandbox" => self.has_seccomp,
            "ebpf_probe" => self.has_ebpf,
            "tpm_attest" => self.has_tpm,
            _ => false,
        }
    }
}

// ── Patch Management (R32) ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PatchStatus {
    Available,
    Downloading,
    Staged,
    Installing,
    Installed,
    Failed,
    RolledBack,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Patch {
    pub id: String,
    pub version: String,
    pub severity: String,
    pub cve_ids: Vec<String>,
    pub description: String,
    pub status: PatchStatus,
    pub staged_at: Option<String>,
    pub installed_at: Option<String>,
    pub rollback_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchPlan {
    pub patches: Vec<String>,
    pub order: Vec<usize>,
    pub estimated_downtime_secs: u64,
    pub rollback_plan: Vec<String>,
}

#[derive(Debug)]
pub struct PatchManager {
    patches: HashMap<String, Patch>,
    installed_history: Vec<(String, String)>, // (patch_id, timestamp)
}

impl Default for PatchManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PatchManager {
    pub fn new() -> Self {
        Self {
            patches: HashMap::new(),
            installed_history: Vec::new(),
        }
    }

    /// Register an available patch.
    pub fn register_patch(&mut self, patch: Patch) {
        self.patches.insert(patch.id.clone(), patch);
    }

    /// Stage a patch for installation.
    pub fn stage(&mut self, patch_id: &str) -> Result<(), String> {
        let patch = self
            .patches
            .get_mut(patch_id)
            .ok_or_else(|| "patch not found".to_string())?;
        if patch.status != PatchStatus::Available && patch.status != PatchStatus::Failed {
            return Err(format!("patch {} not in stageable state", patch_id));
        }
        patch.status = PatchStatus::Staged;
        patch.staged_at = Some(chrono::Utc::now().to_rfc3339());
        Ok(())
    }

    /// Install a staged patch.
    pub fn install(&mut self, patch_id: &str) -> Result<(), String> {
        let patch = self
            .patches
            .get_mut(patch_id)
            .ok_or_else(|| "patch not found".to_string())?;
        if patch.status != PatchStatus::Staged {
            return Err(format!("patch {} not staged", patch_id));
        }
        patch.status = PatchStatus::Installed;
        let ts = chrono::Utc::now().to_rfc3339();
        patch.installed_at = Some(ts.clone());
        self.installed_history.push((patch_id.to_string(), ts));
        Ok(())
    }

    /// Roll back a patch.
    pub fn rollback(&mut self, patch_id: &str) -> Result<(), String> {
        let patch = self
            .patches
            .get_mut(patch_id)
            .ok_or_else(|| "patch not found".to_string())?;
        if !patch.rollback_available {
            return Err("rollback not available".to_string());
        }
        if patch.status != PatchStatus::Installed {
            return Err("patch not installed".to_string());
        }
        patch.status = PatchStatus::RolledBack;
        Ok(())
    }

    /// Create a patch plan: install patches ordered by severity.
    pub fn plan(&self) -> PatchPlan {
        let mut staged: Vec<&Patch> = self
            .patches
            .values()
            .filter(|p| p.status == PatchStatus::Staged || p.status == PatchStatus::Available)
            .collect();
        // Critical first
        staged.sort_by(|a, b| {
            let sev_ord = |s: &str| -> u8 {
                match s {
                    "critical" => 0,
                    "high" => 1,
                    "medium" => 2,
                    _ => 3,
                }
            };
            sev_ord(&a.severity).cmp(&sev_ord(&b.severity))
        });

        let patches: Vec<String> = staged.iter().map(|p| p.id.clone()).collect();
        let order: Vec<usize> = (0..patches.len()).collect();
        let downtime = staged.len() as u64 * 30; // 30s per patch estimate
        let rollback = patches.clone();

        PatchPlan {
            patches,
            order,
            estimated_downtime_secs: downtime,
            rollback_plan: rollback,
        }
    }

    pub fn patch_count(&self) -> usize {
        self.patches.len()
    }

    pub fn installed_count(&self) -> usize {
        self.patches.values().filter(|p| p.status == PatchStatus::Installed).count()
    }
}

// ── Sync Protocol (R36) ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncMessage {
    pub message_id: String,
    pub from_node: String,
    pub to_node: String,
    pub payload_type: String,
    pub payload_hash: String,
    pub payload_size_bytes: u64,
    pub timestamp: String,
    pub sequence: u64,
}

/// Bidirectional sync state tracker between edge and cloud.
#[derive(Debug)]
pub struct SyncTracker {
    local_seq: u64,
    remote_seq: u64,
    pending: Vec<SyncMessage>,
    acked: Vec<String>,
}

impl Default for SyncTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl SyncTracker {
    pub fn new() -> Self {
        Self {
            local_seq: 0,
            remote_seq: 0,
            pending: Vec::new(),
            acked: Vec::new(),
        }
    }

    /// Queue a message for syncing.
    pub fn enqueue(&mut self, from: &str, to: &str, payload_type: &str, size: u64) -> String {
        self.local_seq += 1;
        let msg_id = format!("{from}-{}-{}", self.local_seq, payload_type);
        self.pending.push(SyncMessage {
            message_id: msg_id.clone(),
            from_node: from.to_string(),
            to_node: to.to_string(),
            payload_type: payload_type.to_string(),
            payload_hash: String::new(),
            payload_size_bytes: size,
            timestamp: chrono::Utc::now().to_rfc3339(),
            sequence: self.local_seq,
        });
        msg_id
    }

    /// Acknowledge receipt of a message.
    pub fn acknowledge(&mut self, msg_id: &str) -> bool {
        if let Some(pos) = self.pending.iter().position(|m| m.message_id == msg_id) {
            let msg = self.pending.remove(pos);
            self.remote_seq = self.remote_seq.max(msg.sequence);
            self.acked.push(msg_id.to_string());
            true
        } else {
            false
        }
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub fn local_sequence(&self) -> u64 {
        self.local_seq
    }

    pub fn is_synced(&self) -> bool {
        self.pending.is_empty()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offload_edge_preferred() {
        let workloads = vec![Workload {
            id: "w1".into(),
            name: "anomaly-detect".into(),
            cpu_cost: 20.0,
            memory_mb: 64,
            latency_sensitive: true,
            data_size_kb: 100,
            tier: ProcessingTier::EdgePreferred,
        }];
        let edge = EdgeCapacity {
            cpu_available: 80.0,
            memory_available_mb: 512,
            bandwidth_kbps: 1000,
            latency_to_cloud_ms: 50,
        };
        let decisions = decide_offload(&workloads, &edge);
        assert_eq!(decisions[0].run_on, "edge");
    }

    #[test]
    fn offload_cloud_when_edge_full() {
        let workloads = vec![Workload {
            id: "w2".into(),
            name: "deep-analysis".into(),
            cpu_cost: 200.0,
            memory_mb: 2048,
            latency_sensitive: false,
            data_size_kb: 500,
            tier: ProcessingTier::EdgePreferred,
        }];
        let edge = EdgeCapacity {
            cpu_available: 10.0,
            memory_available_mb: 64,
            bandwidth_kbps: 1000,
            latency_to_cloud_ms: 50,
        };
        let decisions = decide_offload(&workloads, &edge);
        assert_eq!(decisions[0].run_on, "cloud");
    }

    #[test]
    fn platform_capabilities() {
        let caps = PlatformCapabilities::detect_current();
        assert!(caps.can_enforce("process_kill"));
    }

    #[test]
    fn patch_lifecycle() {
        let mut pm = PatchManager::new();
        pm.register_patch(Patch {
            id: "CVE-0000-0001".into(),
            version: "1.0.1".into(),
            severity: "critical".into(),
            cve_ids: vec!["CVE-0000-0001".into()],
            description: "Buffer overflow fix".into(),
            status: PatchStatus::Available,
            staged_at: None,
            installed_at: None,
            rollback_available: true,
        });

        assert!(pm.stage("CVE-0000-0001").is_ok());
        assert!(pm.install("CVE-0000-0001").is_ok());
        assert_eq!(pm.installed_count(), 1);
        assert!(pm.rollback("CVE-0000-0001").is_ok());
    }

    #[test]
    fn patch_plan_orders_by_severity() {
        let mut pm = PatchManager::new();
        pm.register_patch(Patch {
            id: "low-1".into(),
            version: "1.0".into(),
            severity: "low".into(),
            cve_ids: vec![],
            description: "minor fix".into(),
            status: PatchStatus::Available,
            staged_at: None,
            installed_at: None,
            rollback_available: false,
        });
        pm.register_patch(Patch {
            id: "crit-1".into(),
            version: "1.0".into(),
            severity: "critical".into(),
            cve_ids: vec![],
            description: "critical fix".into(),
            status: PatchStatus::Available,
            staged_at: None,
            installed_at: None,
            rollback_available: true,
        });

        let plan = pm.plan();
        assert_eq!(plan.patches[0], "crit-1");
    }

    #[test]
    fn sync_tracker_enqueue_and_ack() {
        let mut st = SyncTracker::new();
        let id = st.enqueue("edge-1", "cloud", "telemetry", 1024);
        assert_eq!(st.pending_count(), 1);
        assert!(!st.is_synced());

        assert!(st.acknowledge(&id));
        assert!(st.is_synced());
    }

    #[test]
    fn sync_tracker_sequence() {
        let mut st = SyncTracker::new();
        st.enqueue("e", "c", "t1", 100);
        st.enqueue("e", "c", "t2", 200);
        assert_eq!(st.local_sequence(), 2);
    }

    #[test]
    fn cloud_only_workload() {
        let workloads = vec![Workload {
            id: "w3".into(),
            name: "model-train".into(),
            cpu_cost: 0.0,
            memory_mb: 0,
            latency_sensitive: false,
            data_size_kb: 0,
            tier: ProcessingTier::CloudOnly,
        }];
        let edge = EdgeCapacity {
            cpu_available: 100.0,
            memory_available_mb: 1024,
            bandwidth_kbps: 10000,
            latency_to_cloud_ms: 20,
        };
        let decisions = decide_offload(&workloads, &edge);
        assert_eq!(decisions[0].run_on, "cloud");
    }
}
