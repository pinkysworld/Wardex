// ── Data Archival ─────────────────────────────────────────────────────────────
//
// Aged-out telemetry, alerts, and incidents are compressed and archived to
// local disk (or an S3-compatible remote via pre-signed URLs).  Columnar
// export uses a compact JSONL+gzip format; an optional CSV exporter is
// provided for compliance workflows.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::{Arc, Mutex};

// ── Configuration ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivalConfig {
    pub archive_dir: String,
    pub retention_days: u32,
    pub compress: bool,
    pub max_file_size_mb: u64,
    pub remote: Option<RemoteConfig>,
}

impl Default for ArchivalConfig {
    fn default() -> Self {
        Self {
            archive_dir: "var/archive".into(),
            retention_days: 365,
            compress: true,
            max_file_size_mb: 256,
            remote: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteConfig {
    pub endpoint: String,
    pub bucket: String,
    pub prefix: String,
    pub region: String,
}

// ── Archive Record ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveRecord {
    pub timestamp: String,
    pub record_type: RecordType,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecordType {
    Alert,
    Incident,
    Telemetry,
    AuditLog,
}

impl std::fmt::Display for RecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Alert     => write!(f, "alert"),
            Self::Incident  => write!(f, "incident"),
            Self::Telemetry => write!(f, "telemetry"),
            Self::AuditLog  => write!(f, "audit_log"),
        }
    }
}

// ── Archive Manifest ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveManifest {
    pub created: String,
    pub record_type: RecordType,
    pub record_count: usize,
    pub date_range_start: String,
    pub date_range_end: String,
    pub compressed: bool,
    pub size_bytes: u64,
    pub checksum_sha256: String,
    pub filename: String,
}

// ── ArchivalEngine ───────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct ArchivalEngine {
    config: ArchivalConfig,
    manifests: Arc<Mutex<Vec<ArchiveManifest>>>,
}

impl ArchivalEngine {
    pub fn new(config: ArchivalConfig) -> Self {
        Self {
            config,
            manifests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Maximum records per single archive call to bound memory usage.
    const MAX_RECORDS_PER_ARCHIVE: usize = 100_000;

    pub fn archive_records(
        &self,
        record_type: RecordType,
        records: &[ArchiveRecord],
    ) -> Result<ArchiveManifest, String> {
        if records.is_empty() {
            return Err("No records to archive".into());
        }
        if records.len() > Self::MAX_RECORDS_PER_ARCHIVE {
            return Err(format!(
                "Too many records ({}) — max {} per call",
                records.len(),
                Self::MAX_RECORDS_PER_ARCHIVE
            ));
        }

        let dir = Path::new(&self.config.archive_dir);
        std::fs::create_dir_all(dir).map_err(|e| format!("mkdir: {}", e))?;

        let now = Utc::now();
        let filename = format!(
            "{}-{}.jsonl{}",
            record_type,
            now.format("%Y%m%dT%H%M%SZ"),
            if self.config.compress { ".gz" } else { "" }
        );
        let path = dir.join(&filename);

        // Build JSONL content
        let mut jsonl = Vec::new();
        for rec in records {
            let line = serde_json::to_string(rec).map_err(|e| e.to_string())?;
            jsonl.extend_from_slice(line.as_bytes());
            jsonl.push(b'\n');
        }

        let final_data = if self.config.compress {
            compress_gzip(&jsonl)?
        } else {
            jsonl.clone()
        };

        std::fs::write(&path, &final_data).map_err(|e| format!("write: {}", e))?;

        // Compute SHA-256
        let checksum = sha256_hex(&final_data);

        // Date range
        let timestamps: Vec<&str> = records.iter().map(|r| r.timestamp.as_str()).collect();
        let start = timestamps.iter().min().unwrap_or(&"").to_string();
        let end = timestamps.iter().max().unwrap_or(&"").to_string();

        let manifest = ArchiveManifest {
            created: now.to_rfc3339(),
            record_type,
            record_count: records.len(),
            date_range_start: start,
            date_range_end: end,
            compressed: self.config.compress,
            size_bytes: final_data.len() as u64,
            checksum_sha256: checksum,
            filename: filename.clone(),
        };

        // Store manifest
        if let Ok(mut m) = self.manifests.lock() {
            m.push(manifest.clone());
        }

        // Write manifest sidecar
        let manifest_path = dir.join(format!("{}.manifest.json", filename));
        if let Ok(json) = serde_json::to_string_pretty(&manifest) {
            let _ = std::fs::write(manifest_path, json);
        }

        Ok(manifest)
    }

    pub fn list_archives(&self) -> Vec<ArchiveManifest> {
        self.manifests.lock().map(|m| m.clone()).unwrap_or_default()
    }

    pub fn export_csv(
        &self,
        record_type: RecordType,
        records: &[ArchiveRecord],
    ) -> Result<String, String> {
        if records.is_empty() {
            return Err("No records to export".into());
        }

        let dir = Path::new(&self.config.archive_dir);
        std::fs::create_dir_all(dir).map_err(|e| format!("mkdir: {}", e))?;

        let now = Utc::now();
        let filename = format!(
            "{}-{}.csv",
            record_type,
            now.format("%Y%m%dT%H%M%SZ")
        );
        let path = dir.join(&filename);

        // Collect all unique keys from data fields
        let mut keys: Vec<String> = Vec::new();
        for rec in records {
            if let serde_json::Value::Object(map) = &rec.data {
                for k in map.keys() {
                    if !keys.contains(k) {
                        keys.push(k.clone());
                    }
                }
            }
        }
        keys.sort();

        let mut csv = String::new();
        // Header
        csv.push_str("timestamp,record_type");
        for k in &keys {
            csv.push(',');
            csv.push_str(k);
        }
        csv.push('\n');

        // Rows
        for rec in records {
            csv.push_str(&csv_escape(&rec.timestamp));
            csv.push(',');
            csv.push_str(&rec.record_type.to_string());
            for k in &keys {
                csv.push(',');
                if let serde_json::Value::Object(map) = &rec.data {
                    if let Some(v) = map.get(k) {
                        csv.push_str(&csv_escape(&value_to_csv(v)));
                    }
                }
            }
            csv.push('\n');
        }

        std::fs::write(&path, &csv).map_err(|e| format!("write: {}", e))?;
        Ok(filename)
    }

    pub fn prune_old_archives(&self, before: &str) -> Result<usize, String> {
        let cutoff = before.to_string();
        let mut removed = 0;

        if let Ok(mut manifests) = self.manifests.lock() {
            let dir = Path::new(&self.config.archive_dir);
            manifests.retain(|m| {
                if m.date_range_end < cutoff {
                    let _ = std::fs::remove_file(dir.join(&m.filename));
                    let _ = std::fs::remove_file(dir.join(format!("{}.manifest.json", &m.filename)));
                    removed += 1;
                    false
                } else {
                    true
                }
            });
        }

        Ok(removed)
    }

    pub fn archive_dir(&self) -> &str {
        &self.config.archive_dir
    }

    pub fn total_archive_size(&self) -> u64 {
        self.manifests
            .lock()
            .map(|m| m.iter().map(|a| a.size_bytes).sum())
            .unwrap_or(0)
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(data);
    hex::encode(hash)
}

fn compress_gzip(data: &[u8]) -> Result<Vec<u8>, String> {
    // Simple DEFLATE-style compression stub.
    // In production, use flate2 crate.  For now, store raw with gzip header.
    let mut out = Vec::new();
    // gzip header
    out.extend_from_slice(&[0x1f, 0x8b, 0x08, 0x00]); // magic + method
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // mtime
    out.extend_from_slice(&[0x00, 0xFF]); // xfl + OS

    // Store blocks (uncompressed DEFLATE blocks)
    let mut offset = 0;
    for chunk in data.chunks(65535) {
        offset += chunk.len();
        let len = chunk.len() as u16;
        let is_last = offset >= data.len();
        out.push(if is_last { 0x01 } else { 0x00 }); // BFINAL
        out.push((len & 0xFF) as u8);
        out.push((len >> 8) as u8);
        let nlen = !len;
        out.push((nlen & 0xFF) as u8);
        out.push((nlen >> 8) as u8);
        out.extend_from_slice(chunk);
    }

    // CRC32 and size
    let crc = crc32_simple(data);
    out.extend_from_slice(&crc.to_le_bytes());
    let size = data.len() as u32;
    out.extend_from_slice(&size.to_le_bytes());

    Ok(out)
}

fn crc32_simple(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

fn csv_escape(s: &str) -> String {
    // Guard against CSV formula injection (DDE attacks)
    let s = if s.starts_with('=') || s.starts_with('+') || s.starts_with('-')
        || s.starts_with('@') || s.starts_with('\t') || s.starts_with('\r')
    {
        format!("'{}", s)
    } else {
        s.to_string()
    };
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\""  , s.replace('"', "\"\""))
    } else {
        s
    }
}

fn value_to_csv(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("wardex-archive-test-{}", rand::random::<u32>()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample_records(n: usize) -> Vec<ArchiveRecord> {
        (0..n)
            .map(|i| ArchiveRecord {
                timestamp: format!("2025-01-{:02}T00:00:00Z", (i % 28) + 1),
                record_type: RecordType::Alert,
                data: serde_json::json!({
                    "id": format!("alert-{}", i),
                    "level": "elevated",
                    "device_id": format!("dev-{}", i),
                }),
            })
            .collect()
    }

    #[test]
    fn archive_creates_file_and_manifest() {
        let dir = temp_dir();
        let config = ArchivalConfig {
            archive_dir: dir.to_string_lossy().into(),
            compress: false,
            ..Default::default()
        };
        let engine = ArchivalEngine::new(config);
        let records = sample_records(5);
        let manifest = engine.archive_records(RecordType::Alert, &records).unwrap();
        assert_eq!(manifest.record_count, 5);
        assert!(manifest.size_bytes > 0);
        assert!(!manifest.checksum_sha256.is_empty());
        assert!(dir.join(&manifest.filename).exists());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn archive_compressed() {
        let dir = temp_dir();
        let config = ArchivalConfig {
            archive_dir: dir.to_string_lossy().into(),
            compress: true,
            ..Default::default()
        };
        let engine = ArchivalEngine::new(config);
        let records = sample_records(10);
        let manifest = engine.archive_records(RecordType::Telemetry, &records).unwrap();
        assert!(manifest.compressed);
        assert!(manifest.filename.ends_with(".gz"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn archive_empty_records_error() {
        let engine = ArchivalEngine::new(ArchivalConfig::default());
        let result = engine.archive_records(RecordType::Alert, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn export_csv_creates_file() {
        let dir = temp_dir();
        let config = ArchivalConfig {
            archive_dir: dir.to_string_lossy().into(),
            ..Default::default()
        };
        let engine = ArchivalEngine::new(config);
        let records = sample_records(3);
        let filename = engine.export_csv(RecordType::Alert, &records).unwrap();
        assert!(filename.ends_with(".csv"));
        let content = fs::read_to_string(dir.join(&filename)).unwrap();
        assert!(content.starts_with("timestamp,record_type"));
        assert_eq!(content.lines().count(), 4); // header + 3 rows
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn list_archives_tracks_manifests() {
        let dir = temp_dir();
        let config = ArchivalConfig {
            archive_dir: dir.to_string_lossy().into(),
            compress: false,
            ..Default::default()
        };
        let engine = ArchivalEngine::new(config);
        engine.archive_records(RecordType::Alert, &sample_records(2)).unwrap();
        engine.archive_records(RecordType::Incident, &[ArchiveRecord {
            timestamp: "2025-06-01T00:00:00Z".into(),
            record_type: RecordType::Incident,
            data: serde_json::json!({"id": "inc-1"}),
        }]).unwrap();
        assert_eq!(engine.list_archives().len(), 2);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn total_archive_size() {
        let dir = temp_dir();
        let config = ArchivalConfig {
            archive_dir: dir.to_string_lossy().into(),
            compress: false,
            ..Default::default()
        };
        let engine = ArchivalEngine::new(config);
        engine.archive_records(RecordType::Alert, &sample_records(5)).unwrap();
        assert!(engine.total_archive_size() > 0);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn sha256_hex_correct() {
        let hash = sha256_hex(b"hello");
        assert_eq!(hash, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    #[test]
    fn csv_escape_handles_special_chars() {
        assert_eq!(csv_escape("hello"), "hello");
        assert_eq!(csv_escape("hello,world"), "\"hello,world\"");
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn record_type_display() {
        assert_eq!(RecordType::Alert.to_string(), "alert");
        assert_eq!(RecordType::AuditLog.to_string(), "audit_log");
    }

    #[test]
    fn crc32_known_value() {
        // CRC32 of empty string
        let crc = crc32_simple(b"");
        assert_eq!(crc, 0x00000000);
        // CRC32 of "123456789" is well-known
        let crc = crc32_simple(b"123456789");
        assert_eq!(crc, 0xCBF43926);
    }
}
