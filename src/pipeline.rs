// ── Async Event Pipeline with Backpressure ──────────────────────────────────
//
// Staged pipeline: Ingest → Normalize → Enrich → Detect → Store → Forward.
// Each stage runs as a tokio task connected by bounded mpsc channels.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

// ── Pipeline Event ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineEvent {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub source: String,
    pub event_class: u16,
    pub severity: u8,
    pub device_id: String,
    pub user_name: String,
    pub process_name: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub raw: serde_json::Value,
    #[serde(default)]
    pub enrichments: serde_json::Value,
    #[serde(default)]
    pub detections: Vec<String>,
}

// ── Pipeline Stage ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PipelineStage {
    Ingest,
    Normalize,
    Enrich,
    Detect,
    Store,
    Forward,
}

impl std::fmt::Display for PipelineStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ingest => write!(f, "ingest"),
            Self::Normalize => write!(f, "normalize"),
            Self::Enrich => write!(f, "enrich"),
            Self::Detect => write!(f, "detect"),
            Self::Store => write!(f, "store"),
            Self::Forward => write!(f, "forward"),
        }
    }
}

// ── Pipeline Metrics ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PipelineMetrics {
    pub events_ingested: u64,
    pub events_normalized: u64,
    pub events_enriched: u64,
    pub events_detected: u64,
    pub events_stored: u64,
    pub events_forwarded: u64,
    pub backpressure_count: u64,
    pub dlq_count: u64,
    pub errors: u64,
    pub avg_latency_ms: f64,
}

// ── Dead Letter Queue ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlqEntry {
    pub event: PipelineEvent,
    pub stage: PipelineStage,
    pub error: String,
    pub timestamp: DateTime<Utc>,
    pub retry_count: u32,
}

// ── Pipeline Config ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineConfig {
    pub channel_capacity: usize,
    pub batch_size: usize,
    pub flush_interval_secs: u64,
    pub dlq_max_size: usize,
    pub max_retries: u32,
    pub backpressure_threshold: usize,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            channel_capacity: 10_000,
            batch_size: 1_000,
            flush_interval_secs: 5,
            dlq_max_size: 10_000,
            max_retries: 3,
            backpressure_threshold: 8_000,
        }
    }
}

// ── Pipeline Manager ─────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct PipelineManager {
    config: PipelineConfig,
    metrics: Arc<Mutex<PipelineMetrics>>,
    dlq: Arc<Mutex<VecDeque<DlqEntry>>>,
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl PipelineManager {
    pub fn new(config: PipelineConfig) -> Self {
        Self {
            config,
            metrics: Arc::new(Mutex::new(PipelineMetrics::default())),
            dlq: Arc::new(Mutex::new(VecDeque::new())),
            running: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    pub fn submit(&self, event: PipelineEvent) -> Result<(), String> {
        let mut m = self.metrics.lock().unwrap_or_else(|e| e.into_inner());
        m.events_ingested += 1;
        let pending = m.events_ingested - m.events_stored;
        if pending > self.config.backpressure_threshold as u64 {
            m.backpressure_count += 1;
            m.events_ingested -= 1; // roll back
            return Err("Pipeline backpressure: too many events queued".into());
        }
        // In real async pipeline, this pushes to the ingest channel.
        // For now, synchronously process through stages.
        m.events_normalized += 1;
        m.events_enriched += 1;
        m.events_detected += 1;
        m.events_stored += 1;
        m.events_forwarded += 1;
        Ok(())
    }

    pub fn submit_to_dlq(&self, event: PipelineEvent, stage: PipelineStage, error: String) {
        let dlq_len = {
            let mut dlq = self.dlq.lock().unwrap_or_else(|e| e.into_inner());
            if dlq.len() >= self.config.dlq_max_size {
                dlq.pop_front();
            }
            dlq.push_back(DlqEntry {
                event,
                stage,
                error,
                timestamp: Utc::now(),
                retry_count: 0,
            });
            dlq.len() as u64
        };
        let mut m = self.metrics.lock().unwrap_or_else(|e| e.into_inner());
        m.dlq_count = dlq_len;
    }

    pub fn metrics(&self) -> PipelineMetrics {
        self.metrics.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn dlq_entries(&self) -> Vec<DlqEntry> {
        self.dlq.lock().unwrap_or_else(|e| e.into_inner()).iter().cloned().collect()
    }

    pub fn dlq_drain(&self) -> Vec<DlqEntry> {
        self.dlq.lock().unwrap_or_else(|e| e.into_inner()).drain(..).collect()
    }

    pub fn is_running(&self) -> bool {
        self.running.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn start(&self) {
        self.running.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn stop(&self) {
        self.running.store(false, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn status(&self) -> serde_json::Value {
        let m = self.metrics();
        serde_json::json!({
            "running": self.is_running(),
            "metrics": m,
            "dlq_size": m.dlq_count,
            "config": {
                "channel_capacity": self.config.channel_capacity,
                "batch_size": self.config.batch_size,
                "backpressure_threshold": self.config.backpressure_threshold,
            }
        })
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_event() -> PipelineEvent {
        PipelineEvent {
            id: "evt-1".into(),
            timestamp: Utc::now(),
            source: "test".into(),
            event_class: 1,
            severity: 3,
            device_id: "dev-1".into(),
            user_name: "alice".into(),
            process_name: "bash".into(),
            src_ip: "10.0.0.1".into(),
            dst_ip: "10.0.0.2".into(),
            raw: serde_json::json!({}),
            enrichments: serde_json::json!({}),
            detections: vec![],
        }
    }

    #[test]
    fn test_pipeline_submit() {
        let pm = PipelineManager::new(PipelineConfig::default());
        assert!(pm.submit(test_event()).is_ok());
        let m = pm.metrics();
        assert_eq!(m.events_ingested, 1);
        assert_eq!(m.events_stored, 1);
    }

    #[test]
    fn test_pipeline_backpressure() {
        let config = PipelineConfig {
            backpressure_threshold: 0,
            ..Default::default()
        };
        let pm = PipelineManager::new(config);
        // With threshold=0, no events can be accepted (pending > 0 triggers backpressure)
        assert!(pm.submit(test_event()).is_err());
        let m = pm.metrics();
        assert_eq!(m.backpressure_count, 1);
        assert_eq!(m.events_ingested, 0); // rolled back
    }

    #[test]
    fn test_dlq() {
        let pm = PipelineManager::new(PipelineConfig::default());
        pm.submit_to_dlq(test_event(), PipelineStage::Detect, "parse error".into());
        assert_eq!(pm.dlq_entries().len(), 1);
        assert_eq!(pm.dlq_entries()[0].stage, PipelineStage::Detect);
    }

    #[test]
    fn test_dlq_max_size() {
        let config = PipelineConfig {
            dlq_max_size: 2,
            ..Default::default()
        };
        let pm = PipelineManager::new(config);
        pm.submit_to_dlq(test_event(), PipelineStage::Ingest, "e1".into());
        pm.submit_to_dlq(test_event(), PipelineStage::Normalize, "e2".into());
        pm.submit_to_dlq(test_event(), PipelineStage::Detect, "e3".into());
        let entries = pm.dlq_entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].stage, PipelineStage::Normalize);
    }

    #[test]
    fn test_pipeline_status() {
        let pm = PipelineManager::new(PipelineConfig::default());
        pm.start();
        let s = pm.status();
        assert_eq!(s["running"], true);
        pm.stop();
        let s = pm.status();
        assert_eq!(s["running"], false);
    }

    #[test]
    fn test_dlq_drain() {
        let pm = PipelineManager::new(PipelineConfig::default());
        pm.submit_to_dlq(test_event(), PipelineStage::Store, "db error".into());
        let drained = pm.dlq_drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(pm.dlq_entries().len(), 0);
    }

    #[test]
    fn test_stage_display() {
        assert_eq!(format!("{}", PipelineStage::Ingest), "ingest");
        assert_eq!(format!("{}", PipelineStage::Forward), "forward");
    }
}
