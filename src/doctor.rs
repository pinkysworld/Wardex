//! `wardex doctor` — preflight/health report for operators.
//!
//! Prints a redactable diagnostic bundle: config file status, runtime paths,
//! data-dir disk space, rule pack counts, and dependency versions. Designed
//! to be pasted into support tickets.

use std::path::{Path, PathBuf};

use crate::config::{self, Config};

/// One row of the doctor report.
#[derive(Debug)]
pub struct Check {
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    Warn,
    Fail,
    Info,
}

impl Status {
    fn glyph(self) -> &'static str {
        match self {
            Status::Ok => "✓",
            Status::Warn => "!",
            Status::Fail => "✗",
            Status::Info => "·",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Status::Ok => "OK",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
            Status::Info => "INFO",
        }
    }
}

/// Run all checks and return a list of results.
pub fn run() -> Vec<Check> {
    vec![
        check_version(),
        check_rustc_info(),
        check_install_layout(),
        check_config(),
        check_data_dir(),
        check_site_dir(),
        check_rules_dir(),
        check_var_dir(),
        check_logs_location(),
        check_service_layout(),
        check_support_bundle_digest(),
        check_redaction_policy(),
    ]
}

/// Format the report as a plain-text block suitable for terminals or paste-in.
pub fn format_report(checks: &[Check]) -> String {
    let mut out = String::new();
    out.push_str("Wardex doctor — diagnostic report\n");
    out.push_str("══════════════════════════════════\n\n");
    for c in checks {
        out.push_str(&format!(
            "  [{:4}] {}  {}\n         {}\n\n",
            c.status.label(),
            c.status.glyph(),
            c.name,
            c.detail.replace('\n', "\n         "),
        ));
    }
    let failures = checks.iter().filter(|c| c.status == Status::Fail).count();
    let warnings = checks.iter().filter(|c| c.status == Status::Warn).count();
    out.push_str(&format!(
        "Summary: {} checks · {} warnings · {} failures\n",
        checks.len(),
        warnings,
        failures,
    ));
    out
}

/// Render machine-readable doctor output used by release/support tooling.
pub fn format_report_json(checks: &[Check]) -> String {
    let failures = checks.iter().filter(|c| c.status == Status::Fail).count();
    let warnings = checks.iter().filter(|c| c.status == Status::Warn).count();
    let config_path = config::runtime_config_path();
    let layout = install_layout();
    let logs = log_paths();
    let support_digest = latest_support_bundle_digest();
    let payload = serde_json::json!({
        "schema": "wardex.doctor.v1",
        "version": env!("CARGO_PKG_VERSION"),
        "runtime": {
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "family": std::env::consts::FAMILY,
        },
        "installation": layout,
        "summary": {
            "checks": checks.len(),
            "warnings": warnings,
            "failures": failures,
            "status": if failures > 0 { "fail" } else if warnings > 0 { "warn" } else { "ok" },
        },
        "config": {
            "path": config_path.display().to_string(),
            "exists": config_path.exists(),
        },
        "service_health": service_health_summary(),
        "logs": {
            "locations": logs,
        },
        "support_bundle": {
            "latest_digest": support_digest,
        },
        "redaction": {
            "summary": "support bundle snapshots redact secrets and sensitive headers before persistence",
            "sensitive_keys": ["authorization", "api_key", "x-api-key", "cookie", "set-cookie", "token", "secret"],
        },
        "checks": checks
            .iter()
            .map(|check| {
                serde_json::json!({
                    "name": check.name,
                    "status": check.status.label().to_ascii_lowercase(),
                    "detail": check.detail,
                })
            })
            .collect::<Vec<_>>(),
    });
    serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string())
}

fn check_version() -> Check {
    Check {
        name: "Wardex build",
        status: Status::Info,
        detail: format!(
            "version {} · target {}",
            env!("CARGO_PKG_VERSION"),
            std::env::consts::OS,
        ),
    }
}

fn check_rustc_info() -> Check {
    Check {
        name: "Runtime",
        status: Status::Info,
        detail: format!(
            "os={} arch={} family={}",
            std::env::consts::OS,
            std::env::consts::ARCH,
            std::env::consts::FAMILY,
        ),
    }
}

fn check_install_layout() -> Check {
    let layout = install_layout();
    Check {
        name: "Installation layout",
        status: Status::Info,
        detail: format!(
            "{} ({})",
            layout
                .get("type")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown"),
            layout
                .get("root")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unreported")
        ),
    }
}

fn check_config() -> Check {
    let path = config::runtime_config_path();
    if !path.exists() {
        return Check {
            name: "Config file",
            status: Status::Warn,
            detail: format!(
                "{} does not exist (defaults will be used). Run `wardex init-config` to write one.",
                path.display()
            ),
        };
    }
    match Config::load_from_path(&path) {
        Ok(_) => Check {
            name: "Config file",
            status: Status::Ok,
            detail: format!("parsed {} successfully", path.display()),
        },
        Err(e) => Check {
            name: "Config file",
            status: Status::Fail,
            detail: format!("{}: {e}", path.display()),
        },
    }
}

fn check_data_dir() -> Check {
    let path = PathBuf::from("var");
    describe_dir("Data directory (var/)", &path, false)
}

fn check_site_dir() -> Check {
    let path = PathBuf::from("site");
    describe_dir("Site assets (site/)", &path, true)
}

fn check_rules_dir() -> Check {
    let path = PathBuf::from("rules");
    if !path.is_dir() {
        return Check {
            name: "Rule packs (rules/)",
            status: Status::Warn,
            detail: "directory not found — built-in rules may be unavailable".to_string(),
        };
    }
    let yara = count_files(&path.join("yara"), "json");
    let sigma = count_files(&path.join("sigma"), "yml");
    Check {
        name: "Rule packs (rules/)",
        status: if yara + sigma > 0 {
            Status::Ok
        } else {
            Status::Warn
        },
        detail: format!("{yara} YARA JSON packs · {sigma} Sigma YAML files"),
    }
}

fn check_var_dir() -> Check {
    let alerts = PathBuf::from("var/alerts.jsonl");
    let crash = PathBuf::from("var/crash.log");
    let mut parts = Vec::new();
    if let Ok(meta) = std::fs::metadata(&alerts) {
        parts.push(format!("alerts.jsonl = {} bytes", meta.len()));
    }
    if let Ok(meta) = std::fs::metadata(&crash)
        && meta.len() > 0
    {
        return Check {
            name: "Crash log",
            status: Status::Warn,
            detail: format!(
                "var/crash.log contains {} bytes — review for recent panics",
                meta.len()
            ),
        };
    }
    Check {
        name: "Runtime artifacts",
        status: Status::Info,
        detail: if parts.is_empty() {
            "no alerts or crash log on disk yet".to_string()
        } else {
            parts.join(" · ")
        },
    }
}

fn check_logs_location() -> Check {
    let locations = log_paths();
    let existing = locations
        .iter()
        .filter_map(serde_json::Value::as_object)
        .filter(|entry| {
            entry
                .get("exists")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
        })
        .count();
    Check {
        name: "Logs location",
        status: if existing > 0 {
            Status::Ok
        } else {
            Status::Warn
        },
        detail: if existing > 0 {
            format!("{existing} configured log path(s) currently exist")
        } else {
            "no known log path exists yet; first runtime start usually creates logs".to_string()
        },
    }
}

fn check_service_layout() -> Check {
    let summary = service_health_summary();
    let status = summary
        .get("status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("info");
    let detail = summary
        .get("detail")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("service metadata unavailable")
        .to_string();
    Check {
        name: "Service health",
        status: match status {
            "ok" => Status::Ok,
            "warn" => Status::Warn,
            "fail" => Status::Fail,
            _ => Status::Info,
        },
        detail,
    }
}

fn check_support_bundle_digest() -> Check {
    let digest = latest_support_bundle_digest();
    Check {
        name: "Support bundle digest",
        status: if digest.is_some() {
            Status::Ok
        } else {
            Status::Warn
        },
        detail: digest.unwrap_or_else(|| {
            "no support bundle digest found yet (generate /api/support/bundle once)".to_string()
        }),
    }
}

fn check_redaction_policy() -> Check {
    Check {
        name: "Redaction summary",
        status: Status::Info,
        detail:
            "Support snapshots redact authorization, cookie, API key, token, and secret fields."
                .to_string(),
    }
}

fn describe_dir(name: &'static str, path: &Path, required: bool) -> Check {
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_dir() => Check {
            name,
            status: Status::Ok,
            detail: format!("{} is present", path.display()),
        },
        Ok(_) => Check {
            name,
            status: Status::Fail,
            detail: format!("{} exists but is not a directory", path.display()),
        },
        Err(_) => Check {
            name,
            status: if required { Status::Fail } else { Status::Warn },
            detail: format!("{} not found", path.display()),
        },
    }
}

fn count_files(dir: &Path, ext: &str) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some(ext))
        .count()
}

fn install_layout() -> serde_json::Value {
    let root = config::runtime_root_dir();
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("wardex"));
    let exe_str = exe.to_string_lossy();
    let root_str = root.to_string_lossy();
    let is_container = Path::new("/.dockerenv").exists()
        || std::env::var("container")
            .map(|value| !value.is_empty())
            .unwrap_or(false);
    let layout = if is_container {
        "container"
    } else if exe_str.contains("/Cellar/wardex/")
        || exe_str.contains("/homebrew/")
        || root_str.contains("Homebrew")
    {
        "homebrew"
    } else if exe_str.starts_with("/usr/bin/")
        || exe_str.starts_with("/usr/local/bin/")
        || exe_str.starts_with("/opt/wardex/")
    {
        "package"
    } else if root.join("Cargo.toml").exists() {
        "source"
    } else {
        "unknown"
    };
    serde_json::json!({
        "type": layout,
        "root": root.display().to_string(),
        "binary": exe.display().to_string(),
        "config_path": config::runtime_config_path().display().to_string(),
    })
}

fn service_health_summary() -> serde_json::Value {
    let mut signals = Vec::new();
    let mut status = "info";

    if Path::new("/etc/systemd/system/wardex.service").exists()
        || Path::new("/lib/systemd/system/wardex.service").exists()
    {
        signals.push("systemd unit installed");
        status = "ok";
    }
    if Path::new("/Library/LaunchDaemons/dev.wardex.agent.plist").exists() {
        signals.push("launchd plist installed");
        status = "ok";
    }
    if Path::new("var/wardex.pid").exists() {
        signals.push("runtime pid file present");
        status = "ok";
    }

    let detail = if signals.is_empty() {
        "no service unit markers detected; source/dev mode is likely active"
    } else {
        "service layout markers found"
    };
    serde_json::json!({
        "status": status,
        "detail": detail,
        "signals": signals,
    })
}

fn log_paths() -> Vec<serde_json::Value> {
    let candidates = [
        "var/crash.log",
        "var/server.log",
        "var/wardex.log",
        "/var/log/wardex/server.log",
        "/usr/local/var/log/wardex/server.log",
        "/opt/homebrew/var/log/wardex/server.log",
    ];
    candidates
        .iter()
        .map(|path| {
            let p = Path::new(path);
            serde_json::json!({
                "path": path,
                "exists": p.exists(),
            })
        })
        .collect()
}

fn latest_support_bundle_digest() -> Option<String> {
    let support_store = Path::new("var/support.json");
    if support_store.exists()
        && let Ok(bytes) = std::fs::read(support_store)
    {
        return Some(crate::audit::sha256_hex(&bytes));
    }

    let root = Path::new("var/operational_snapshots/support_bundle");
    let entries = std::fs::read_dir(root).ok()?;
    let mut candidates = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let modified = entry.metadata().ok().and_then(|meta| meta.modified().ok());
        candidates.push((modified, path));
    }
    candidates.sort_by(|(left_modified, left_path), (right_modified, right_path)| {
        right_modified
            .cmp(left_modified)
            .then_with(|| right_path.cmp(left_path))
    });
    let latest = candidates.into_iter().next()?.1;
    let json = serde_json::from_slice::<serde_json::Value>(&std::fs::read(latest).ok()?).ok()?;
    json.get("digest")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_returns_checks() {
        let checks = run();
        assert!(
            !checks.is_empty(),
            "doctor should return at least one check"
        );
        // version check should always be Info
        assert!(checks.iter().any(|c| c.name == "Wardex build"));
    }

    #[test]
    fn format_report_is_non_empty() {
        let report = format_report(&run());
        assert!(report.contains("Wardex doctor"));
        assert!(report.contains("Summary:"));
    }

    #[test]
    fn format_report_json_has_schema_and_summary() {
        let report = format_report_json(&run());
        let payload =
            serde_json::from_str::<serde_json::Value>(&report).expect("doctor json should parse");
        assert_eq!(
            payload.get("schema").and_then(serde_json::Value::as_str),
            Some("wardex.doctor.v1")
        );
        assert!(
            payload.get("summary").is_some(),
            "summary should be present"
        );
    }

    #[test]
    fn status_glyphs_are_stable() {
        assert_eq!(Status::Ok.glyph(), "✓");
        assert_eq!(Status::Fail.label(), "FAIL");
    }
}
