//! Ransomware detection engine.
//!
//! Monitors file-activity velocity, extension entropy, and canary files
//! to detect ransomware behavior. Integrates with the real-time file
//! watcher and file integrity monitor for multi-signal detection.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::collector::{FileChangeEvent, FileChangeKind};

// ── Configuration ───────────────────────────────────────────────────

/// Ransomware detector configuration.
#[derive(Debug, Clone)]
pub struct RansomwareConfig {
    /// File changes per second threshold to trigger velocity alert.
    pub velocity_threshold: f32,
    /// Minimum number of extension changes to trigger entropy alert.
    pub extension_change_threshold: usize,
    /// Sliding window size (ms) for velocity calculation.
    pub window_ms: u64,
    /// Score threshold to classify as ransomware (0.0–10.0).
    pub alert_threshold: f32,
    /// Weight for velocity signal.
    pub velocity_weight: f32,
    /// Weight for extension entropy signal.
    pub extension_weight: f32,
    /// Weight for canary file signal.
    pub canary_weight: f32,
    /// Weight for FIM drift signal.
    pub fim_weight: f32,
}

impl Default for RansomwareConfig {
    fn default() -> Self {
        Self {
            velocity_threshold: 50.0,   // 50+ file changes/sec is suspicious
            extension_change_threshold: 10, // 10+ extension changes in window
            window_ms: 30_000,          // 30-second sliding window
            alert_threshold: 5.0,
            velocity_weight: 2.5,
            extension_weight: 3.0,
            canary_weight: 4.0,
            fim_weight: 1.5,
        }
    }
}

// ── Canary File ─────────────────────────────────────────────────────

/// A sentinel file placed in a monitored directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryFile {
    pub path: String,
    pub hash: String,
    pub created_at_ms: u64,
}

// ── Detection Result ────────────────────────────────────────────────

/// Result of a ransomware detection evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RansomwareSignal {
    /// Combined ransomware risk score (0.0–10.0).
    pub score: f32,
    /// Whether the score exceeds the alert threshold.
    pub alert: bool,
    /// File change velocity (events/sec) in the current window.
    pub velocity: f32,
    /// Number of file extension changes detected.
    pub extension_changes: usize,
    /// Number of canary files that were tampered with.
    pub canaries_triggered: usize,
    /// Total canary files being monitored.
    pub canaries_total: usize,
    /// Current FIM integrity drift ratio.
    pub fim_drift: f32,
    /// Breakdown of which signals contributed to the score.
    pub contributions: Vec<RansomwareContribution>,
    /// MITRE ATT&CK technique IDs.
    pub mitre_techniques: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RansomwareContribution {
    pub signal: String,
    pub raw_value: f32,
    pub weighted: f32,
}

// ── Extension Tracker ───────────────────────────────────────────────

/// Tracks file extension changes to detect mass-rename patterns.
#[derive(Debug)]
struct ExtensionTracker {
    /// Recent extension change events with timestamps.
    changes: VecDeque<(u64, String, String)>, // (timestamp, old_ext, new_ext)
    /// Known ransomware extensions for boosted scoring.
    known_ransom_extensions: Vec<String>,
}

impl ExtensionTracker {
    fn new() -> Self {
        Self {
            changes: VecDeque::new(),
            known_ransom_extensions: vec![
                ".encrypted".into(), ".locked".into(), ".crypto".into(),
                ".crypt".into(), ".enc".into(), ".ransom".into(),
                ".pay".into(), ".locky".into(), ".wncry".into(),
                ".cerber".into(), ".zepto".into(), ".zzzzz".into(),
                ".micro".into(), ".aaa".into(),
            ],
        }
    }

    fn record_change(&mut self, path: &str, kind: FileChangeKind, window_ms: u64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Prune old entries
        let cutoff = now.saturating_sub(window_ms);
        while self.changes.front().is_some_and(|(ts, _, _)| *ts < cutoff) {
            self.changes.pop_front();
        }

        if kind == FileChangeKind::Created || kind == FileChangeKind::Renamed {
            let ext = Path::new(path)
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| format!(".{e}"))
                .unwrap_or_default();

            if !ext.is_empty() {
                self.changes.push_back((now, path.to_string(), ext));
            }
        }
    }

    fn extension_change_count(&self) -> usize {
        self.changes.len()
    }

    fn has_known_ransom_extension(&self) -> bool {
        self.changes.iter().any(|(_, _, ext)| {
            self.known_ransom_extensions.iter().any(|r| ext.eq_ignore_ascii_case(r))
        })
    }

    /// Compute entropy of extension distribution (higher = more suspicious).
    fn extension_entropy(&self) -> f32 {
        if self.changes.is_empty() {
            return 0.0;
        }
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for (_, _, ext) in &self.changes {
            *counts.entry(ext.as_str()).or_insert(0) += 1;
        }
        let total = self.changes.len() as f32;
        // Low entropy (all same extension) is MORE suspicious for ransomware
        let mut entropy = 0.0f32;
        for &count in counts.values() {
            let p = count as f32 / total;
            if p > 0.0 {
                entropy -= p * p.log2();
            }
        }
        // Invert: low entropy (uniform extension) = high suspicion
        // Use threshold of 2.0 to catch mixed-extension ransomware (e.g. .encrypted + .locked)
        if entropy < 2.0 && total > 5.0 {
            return (2.0 - entropy) / 2.0 * (total / 10.0).min(1.0);
        }
        0.0
    }
}

// ── Ransomware Detector ─────────────────────────────────────────────

/// Multi-signal ransomware detection engine.
pub struct RansomwareDetector {
    config: RansomwareConfig,
    canaries: Vec<CanaryFile>,
    extension_tracker: ExtensionTracker,
    /// Rolling event buffer for velocity computation.
    event_timestamps: VecDeque<u64>,
}

impl std::fmt::Debug for RansomwareDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RansomwareDetector")
            .field("canaries", &self.canaries.len())
            .field("pending_events", &self.event_timestamps.len())
            .finish()
    }
}

impl Default for RansomwareDetector {
    fn default() -> Self {
        Self::new(RansomwareConfig::default())
    }
}

impl RansomwareDetector {
    pub fn new(config: RansomwareConfig) -> Self {
        Self {
            config,
            canaries: Vec::new(),
            extension_tracker: ExtensionTracker::new(),
            event_timestamps: VecDeque::new(),
        }
    }

    /// Deploy canary files in the given directories.
    /// Returns the number of canary files successfully created.
    pub fn deploy_canaries(&mut self, directories: &[&str]) -> usize {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let mut deployed = 0;

        for dir in directories {
            let dir_path = Path::new(dir);
            if !dir_path.is_dir() {
                continue;
            }

            let canary_name = format!(".wardex_canary_{:x}.dat", now.wrapping_add(deployed as u64));
            let canary_path = dir_path.join(&canary_name);

            // Content is random-looking but deterministic for hash verification
            let content = format!(
                "WARDEX-CANARY-v1\ntimestamp={now}\npath={}\nintegrity=sentinel\n",
                canary_path.display()
            );
            let hash = hex::encode(Sha256::digest(content.as_bytes()));

            if std::fs::write(&canary_path, &content).is_ok() {
                self.canaries.push(CanaryFile {
                    path: canary_path.display().to_string(),
                    hash,
                    created_at_ms: now,
                });
                deployed += 1;
            }
        }
        deployed
    }

    /// Check all canary files for tampering.
    fn check_canaries(&self) -> (usize, usize) {
        let total = self.canaries.len();
        let mut triggered = 0;
        for canary in &self.canaries {
            let path = Path::new(&canary.path);
            match std::fs::read(path) {
                Ok(data) => {
                    let current_hash = hex::encode(Sha256::digest(&data));
                    if current_hash != canary.hash {
                        triggered += 1;
                    }
                }
                Err(_) => {
                    // File deleted — canary triggered
                    triggered += 1;
                }
            }
        }
        (triggered, total)
    }

    /// Ingest file change events from the real-time watcher.
    pub fn ingest_events(&mut self, events: &[FileChangeEvent]) {
        let cutoff = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let window_start = cutoff.saturating_sub(self.config.window_ms);

        // Prune old timestamps
        while self.event_timestamps.front().is_some_and(|ts| *ts < window_start) {
            self.event_timestamps.pop_front();
        }

        for event in events {
            self.event_timestamps.push_back(event.timestamp_ms);
            self.extension_tracker.record_change(&event.path, event.kind, self.config.window_ms);
        }
    }

    /// Compute current file change velocity (events/sec).
    fn velocity(&self) -> f32 {
        if self.event_timestamps.is_empty() || self.config.window_ms == 0 {
            return 0.0;
        }
        let count = self.event_timestamps.len() as f32;
        count / (self.config.window_ms as f32 / 1000.0)
    }

    /// Evaluate all ransomware signals and produce a combined score.
    pub fn evaluate(&mut self, fim_drift: f32) -> RansomwareSignal {
        let velocity = self.velocity();
        let ext_changes = self.extension_tracker.extension_change_count();
        let (canaries_triggered, canaries_total) = self.check_canaries();
        let ext_entropy = self.extension_tracker.extension_entropy();
        let has_known_ext = self.extension_tracker.has_known_ransom_extension();

        let mut contributions = Vec::new();
        let mut total_score = 0.0f32;

        // 1. Velocity signal
        let velocity_ratio = (velocity / self.config.velocity_threshold).min(3.0);
        let velocity_score = velocity_ratio * self.config.velocity_weight;
        if velocity_score > 0.1 {
            contributions.push(RansomwareContribution {
                signal: "file_velocity".into(),
                raw_value: velocity,
                weighted: velocity_score,
            });
        }
        total_score += velocity_score;

        // 2. Extension change signal
        let ext_ratio = (ext_changes as f32 / self.config.extension_change_threshold as f32).min(3.0);
        let mut ext_score = ext_ratio * self.config.extension_weight;
        // Boost if known ransomware extensions detected
        if has_known_ext {
            ext_score *= 2.0;
        }
        // Boost for low-entropy extension changes (uniform target extension)
        ext_score += ext_entropy * self.config.extension_weight;
        if ext_score > 0.1 {
            contributions.push(RansomwareContribution {
                signal: "extension_changes".into(),
                raw_value: ext_changes as f32,
                weighted: ext_score,
            });
        }
        total_score += ext_score;

        // 3. Canary signal (strongest indicator)
        if canaries_total > 0 {
            let canary_ratio = canaries_triggered as f32 / canaries_total as f32;
            let canary_score = canary_ratio * self.config.canary_weight * 2.5;
            if canary_score > 0.0 {
                contributions.push(RansomwareContribution {
                    signal: "canary_triggered".into(),
                    raw_value: canaries_triggered as f32,
                    weighted: canary_score,
                });
            }
            total_score += canary_score;
        }

        // 4. FIM drift signal
        let fim_score = fim_drift * self.config.fim_weight * 10.0;
        if fim_score > 0.1 {
            contributions.push(RansomwareContribution {
                signal: "fim_drift".into(),
                raw_value: fim_drift,
                weighted: fim_score,
            });
        }
        total_score += fim_score;

        let score = total_score.min(10.0);
        let alert = score >= self.config.alert_threshold;

        let mut mitre = Vec::new();
        if alert {
            mitre.push("T1486".into()); // Data Encrypted for Impact
            mitre.push("T1490".into()); // Inhibit System Recovery
            if has_known_ext {
                mitre.push("T1036.008".into()); // Masquerading: File Extension
            }
        }

        RansomwareSignal {
            score,
            alert,
            velocity,
            extension_changes: ext_changes,
            canaries_triggered,
            canaries_total,
            fim_drift,
            contributions,
            mitre_techniques: mitre,
        }
    }

    /// Get current number of deployed canaries.
    pub fn canary_count(&self) -> usize {
        self.canaries.len()
    }

    /// Get the configuration.
    pub fn config(&self) -> &RansomwareConfig {
        &self.config
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    #[test]
    fn no_events_no_alert() {
        let mut det = RansomwareDetector::default();
        let signal = det.evaluate(0.0);
        assert!(!signal.alert);
        assert_eq!(signal.score, 0.0);
    }

    #[test]
    fn high_velocity_triggers_score() {
        let mut det = RansomwareDetector::default();
        let ts = now_ms();
        // Simulate 200 rapid file changes
        let events: Vec<FileChangeEvent> = (0..200)
            .map(|i| FileChangeEvent {
                timestamp_ms: ts,
                path: format!("/tmp/file_{i}.encrypted"),
                kind: FileChangeKind::Created,
            })
            .collect();
        det.ingest_events(&events);
        let signal = det.evaluate(0.0);
        assert!(signal.velocity > 0.0);
        assert!(signal.score > 0.0);
    }

    #[test]
    fn known_extension_boosts_score() {
        let mut det = RansomwareDetector::default();
        let ts = now_ms();
        let events: Vec<FileChangeEvent> = (0..20)
            .map(|i| FileChangeEvent {
                timestamp_ms: ts,
                path: format!("/tmp/doc_{i}.encrypted"),
                kind: FileChangeKind::Created,
            })
            .collect();
        det.ingest_events(&events);
        let with_ransom = det.evaluate(0.0);

        let mut det2 = RansomwareDetector::default();
        let events2: Vec<FileChangeEvent> = (0..20)
            .map(|i| FileChangeEvent {
                timestamp_ms: ts,
                path: format!("/tmp/doc_{i}.txt"),
                kind: FileChangeKind::Created,
            })
            .collect();
        det2.ingest_events(&events2);
        let without_ransom = det2.evaluate(0.0);

        assert!(with_ransom.score > without_ransom.score);
    }

    #[test]
    fn canary_deployment() {
        let tmp = std::env::temp_dir().join(format!("wardex_canary_test_{}", rand::random::<u32>()));
        std::fs::create_dir_all(&tmp).unwrap();
        let dir_str = tmp.to_str().unwrap();

        let mut det = RansomwareDetector::default();
        let deployed = det.deploy_canaries(&[dir_str]);
        assert!(deployed >= 1);
        assert_eq!(det.canary_count(), deployed);

        // Canary not triggered initially
        let signal = det.evaluate(0.0);
        assert_eq!(signal.canaries_triggered, 0);

        // Tamper with canary
        let canary_path = &det.canaries[0].path;
        std::fs::write(canary_path, "TAMPERED").unwrap();

        let signal = det.evaluate(0.0);
        assert_eq!(signal.canaries_triggered, 1);
        assert!(signal.score > 0.0);

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn fim_drift_contributes_to_score() {
        let mut det = RansomwareDetector::default();
        let signal = det.evaluate(0.5); // 50% FIM drift
        assert!(signal.score > 0.0);
        assert!(signal.contributions.iter().any(|c| c.signal == "fim_drift"));
    }

    #[test]
    fn combined_signals_amplify() {
        let mut det = RansomwareDetector::default();
        let ts = now_ms();

        // High velocity + known extension + FIM drift
        let events: Vec<FileChangeEvent> = (0..100)
            .map(|i| FileChangeEvent {
                timestamp_ms: ts,
                path: format!("/tmp/victim_{i}.encrypted"),
                kind: FileChangeKind::Created,
            })
            .collect();
        det.ingest_events(&events);
        let signal = det.evaluate(0.3);

        // Should have high combined score
        assert!(signal.score > 3.0);
        assert!(signal.contributions.len() >= 2);
    }
}
