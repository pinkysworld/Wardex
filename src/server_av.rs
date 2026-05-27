//! Local open-source AV signature loading helpers.
//!
//! Extracted from `server.rs` as part of the incremental decomposition of the
//! monolithic module. Discovers ClamAV-format hash signature files (`.hdb`,
//! `.hsb`, `.hashes`, `.txt`) under a fixed set of operator-controlled preset
//! directories, exposes the discovery state as a JSON payload for the admin
//! console, and loads matching signatures into the `MalwareHashDb`.
//!
//! The directories and supported extensions are deliberately hard-coded and
//! gated behind an explicit operator action — no automatic download or remote
//! fetch happens here.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[allow(unused_imports)]
use crate::server::*;

const LOCAL_AV_SIGNATURE_PRESET_DIRS: &[&str] = &[
    "rules/clamav",
    "rules/malware_hashes",
    "var/signatures/clamav",
    "/var/lib/clamav",
    "/usr/local/share/clamav",
    "/opt/homebrew/share/clamav",
];

const LOCAL_AV_SIGNATURE_EXTENSIONS: &[&str] = &["hdb", "hsb", "hashes", "txt"];

pub(crate) fn local_av_signature_files() -> Vec<PathBuf> {
    let mut files = Vec::new();
    for dir in LOCAL_AV_SIGNATURE_PRESET_DIRS {
        let path = Path::new(dir);
        let Ok(entries) = fs::read_dir(path) else {
            continue;
        };
        for entry in entries.flatten() {
            let file_path = entry.path();
            let ext = file_path
                .extension()
                .and_then(|value| value.to_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if LOCAL_AV_SIGNATURE_EXTENSIONS.contains(&ext.as_str()) {
                files.push(file_path);
            }
        }
    }
    files.sort();
    files
}

pub(crate) fn local_av_signature_presets_json() -> serde_json::Value {
    let files = local_av_signature_files();
    let directories: Vec<_> = LOCAL_AV_SIGNATURE_PRESET_DIRS
        .iter()
        .map(|dir| {
            let path = Path::new(dir);
            let detected_files = files
                .iter()
                .filter(|file| file.parent().is_some_and(|parent| parent == path))
                .map(|file| file.display().to_string())
                .collect::<Vec<_>>();
            serde_json::json!({
                "path": dir,
                "exists": path.exists(),
                "detected_files": detected_files,
            })
        })
        .collect();
    serde_json::json!({
        "preset": "local_open_source_av",
        "formats": ["clamav_hdb_md5", "clamav_hsb_sha256", "plain_hash_lines"],
        "operator_decision_required": true,
        "auto_download": false,
        "directories": directories,
    })
}

pub(crate) fn load_local_open_source_av_signatures(state: &Arc<Mutex<AppState>>) -> usize {
    let mut imported = 0usize;
    for file_path in local_av_signature_files() {
        let Ok(content) = fs::read_to_string(&file_path) else {
            continue;
        };
        let mut s = crate::state_lock::tracked_lock(state, "server/load_local_av_signatures");
        match s
            .malware_hash_db
            .load_clamav_hash_signatures(&content, Some(&format!("local:{}", file_path.display())))
        {
            Ok(count) => imported += count,
            Err(error) => tracing::warn!(
                "failed to load local malware signatures {}: {error}",
                file_path.display()
            ),
        }
    }
    imported
}
