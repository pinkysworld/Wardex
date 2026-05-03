//! Wardex application entry point: CLI parsing, runtime setup, and subcommand dispatch.

use std::env;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use wardex::agent_client;
use wardex::attestation::BuildManifest;
use wardex::benchmark::{BenchmarkResult, run_benchmark};
use wardex::collector;
use wardex::config::Config;
use wardex::detector::AnomalyDetector;
use wardex::fixed_threshold::{FixedThresholdDetector, run_fixed_benchmark};
use wardex::harness::{self, HarnessConfig};
use wardex::report::JsonReport;
use wardex::runtime;
use wardex::server;
use wardex::service::ServiceManager;
use wardex::state_machine::PolicyStateMachine;
use wardex::telemetry::TelemetrySample;

fn main() {
    env_logger::init();

    // Global panic hook: log panics to stderr and attempt to flush critical state.
    // Prevents unhandled panics from poisoning shared mutexes without logging.
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|l| format!(" at {}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_default();
        let payload = if let Some(s) = info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "unknown panic".to_string()
        };
        eprintln!("[PANIC]{location}: {payload}");
        // Attempt to flush stderr and write a crash marker for recovery on restart
        let _ = std::io::Write::flush(&mut std::io::stderr());
        let crash_info = format!(
            "{{\"panic\":\"{}\",\"location\":\"{}\",\"timestamp\":\"{}\"}}\n",
            payload.replace('"', "\\\""),
            location.trim(),
            chrono::Utc::now().to_rfc3339(),
        );
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("var/crash.log")
            .and_then(|mut f| std::io::Write::write_all(&mut f, crash_info.as_bytes()));
    }));

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("fatal: failed to create tokio runtime: {err}");
            process::exit(1);
        }
    };
    if let Err(error) = rt.block_on(run()) {
        eprintln!("error: {error}");
        process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "start".into());

    match command.as_str() {
        "start" => {
            // Combined mode: HTTP server + live monitor (the "just works" default)
            let mut port = 8080u16;
            let mut monitor_args = Vec::new();

            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--port" => {
                        let value = args
                            .next()
                            .ok_or_else(|| "`start --port` requires a value".to_string())?;
                        port = value
                            .parse::<u16>()
                            .map_err(|_| "invalid port number".to_string())?;
                    }
                    _ => monitor_args.push(arg),
                }
            }

            let config = load_or_create_config();
            let mon = collector::parse_monitor_args(&mut monitor_args.into_iter());
            let site_dir = resolve_site_dir(&PathBuf::from("site"))?;

            let shutdown = Arc::new(AtomicBool::new(false));

            // Spawn server in background task
            let site_dir_clone = site_dir.clone();
            let shutdown_clone = shutdown.clone();
            let server_config = config.clone();
            tokio::task::spawn(async move {
                if let Err(e) =
                    server::run_server(port, &site_dir_clone, shutdown_clone, server_config).await
                {
                    eprintln!("server error: {e}");
                }
            });

            eprintln!("Admin console: http://localhost:{port}/admin/");
            eprintln!();

            // Register Ctrl+C
            let shutdown_sig = shutdown.clone();
            let _ = register_ctrlc(shutdown_sig);

            // Run monitor in blocking task
            tokio::task::spawn_blocking(move || {
                collector::run_monitor(&config, &mon, shutdown);
            })
            .await
            .map_err(|e| format!("monitor task failed: {e}"))?;
        }
        "monitor" => {
            // CLI-only monitor (no web server) — for headless/embedded use
            let config = load_or_create_config();
            let mon = collector::parse_monitor_args(&mut args);

            let shutdown = Arc::new(AtomicBool::new(false));
            let shutdown_sig = shutdown.clone();
            let _ = register_ctrlc(shutdown_sig);

            collector::run_monitor(&config, &mon, shutdown);
        }
        "demo" => {
            let audit_path = args
                .next()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("var/demo.audit.log"));

            if args.next().is_some() {
                return Err("too many arguments for `demo`".into());
            }

            let result = runtime::execute(&runtime::demo_samples());
            result
                .audit
                .write_to_path(&audit_path)
                .map_err(|error| format!("failed to write audit log: {error}"))?;
            print!(
                "{}",
                runtime::render_console_report(&result, Some(&audit_path))
            );
        }
        "analyze" => {
            let input_path = args
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| "missing telemetry path for `analyze`".to_string())?;
            let audit_path = args
                .next()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("var/last-run.audit.log"));

            if args.next().is_some() {
                return Err("too many arguments for `analyze`".into());
            }

            let samples =
                TelemetrySample::parse_auto(&input_path).map_err(|error| error.to_string())?;
            let result = runtime::execute(&samples);
            result
                .audit
                .write_to_path(&audit_path)
                .map_err(|error| format!("failed to write audit log: {error}"))?;
            print!(
                "{}",
                runtime::render_console_report(&result, Some(&audit_path))
            );
        }
        "report" => {
            let input_path = args
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| "missing telemetry path for `report`".to_string())?;
            let report_path = args
                .next()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("var/last-run.report.json"));

            if args.next().is_some() {
                return Err("too many arguments for `report`".into());
            }

            let samples =
                TelemetrySample::parse_auto(&input_path).map_err(|error| error.to_string())?;
            let result = runtime::execute(&samples);
            let json_report = JsonReport::from_run_result(&result);
            json_report.write_to_path(&report_path)?;
            println!("JSON report written to {}", report_path.display());
        }
        "init-config" => {
            let config_path = args
                .next()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("wardex.toml"));

            if args.next().is_some() {
                return Err("too many arguments for `init-config`".into());
            }

            Config::write_default_toml(&config_path)?;
            println!("Default config written to {}", config_path.display());
        }
        "status" => {
            if args.next().is_some() {
                return Err("`status` does not accept extra arguments".into());
            }
            println!("{}", runtime::status_snapshot());
        }
        "doctor" => {
            if args.next().is_some() {
                return Err("`doctor` does not accept extra arguments".into());
            }
            let checks = wardex::doctor::run();
            print!("{}", wardex::doctor::format_report(&checks));
            let failures = checks
                .iter()
                .filter(|c| c.status == wardex::doctor::Status::Fail)
                .count();
            if failures > 0 {
                process::exit(1);
            }
        }
        "status-json" => {
            let output_path = args.next().map(PathBuf::from);

            if args.next().is_some() {
                return Err("too many arguments for `status-json`".into());
            }

            let manifest = runtime::status_manifest();
            let json = serde_json::to_string_pretty(&manifest)
                .map_err(|error| format!("failed to serialize status JSON: {error}"))?;

            if let Some(path) = output_path {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|error| format!("failed to create status directory: {error}"))?;
                }
                std::fs::write(&path, json)
                    .map_err(|error| format!("failed to write status JSON: {error}"))?;
                println!("Status JSON written to {}", path.display());
            } else {
                println!("{json}");
            }
        }
        "help" | "--help" | "-h" => print_usage(),
        "version" | "--version" | "-V" => {
            println!("wardex {}", env!("CARGO_PKG_VERSION"));
        }
        "harness" => {
            if args.next().is_some() {
                return Err("`harness` does not accept extra arguments".into());
            }

            let config = HarnessConfig::default();
            let result = harness::run(&config);

            println!("Wardex adversarial harness");
            println!(
                "  strategies: SlowDrip, BurstMask, DriftInject ({} traces each)",
                config.traces_per_strategy
            );
            println!(
                "  trace length: {} samples, evasion threshold: {:.1}",
                config.trace_length, config.evasion_threshold
            );
            println!();
            println!(
                "  total traces: {} | evasions: {} | evasion rate: {:.1}%",
                result.total_count,
                result.evasion_count,
                result.evasion_rate * 100.0
            );
            println!(
                "  coverage: {:.0}% of score buckets exercised",
                result.coverage.coverage_ratio() * 100.0
            );
            println!();

            for trace in &result.traces {
                println!(
                    "  {:?} max_score={:.2} evaded={}",
                    trace.strategy, trace.max_score, trace.evaded
                );
            }
        }
        "export-model" => {
            let format = args.next().unwrap_or_else(|| "tla".to_string());
            let output_path = args.next().map(PathBuf::from);

            if args.next().is_some() {
                return Err("too many arguments for `export-model`".into());
            }

            let sm = PolicyStateMachine::new();
            let content = match format.as_str() {
                "tla" => sm.export_tla(),
                "alloy" => sm.export_alloy(),
                other => {
                    return Err(format!(
                        "unknown format `{other}`, expected `tla` or `alloy`"
                    ));
                }
            };

            if let Some(path) = output_path {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| format!("failed to create directory: {e}"))?;
                }
                std::fs::write(&path, &content)
                    .map_err(|e| format!("failed to write model: {e}"))?;
                println!("{} model written to {}", format, path.display());
            } else {
                print!("{content}");
            }
        }
        "attest" => {
            let binary_path = args
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| "missing binary path for `attest`".to_string())?;
            let output_path = args
                .next()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("var/manifest.json"));

            let artifact_paths: Vec<PathBuf> = args.map(PathBuf::from).collect();
            let artifact_refs: Vec<&Path> = artifact_paths.iter().map(|p| p.as_path()).collect();

            let manifest = BuildManifest::generate(&binary_path, &artifact_refs)?;
            manifest.write_to_path(&output_path)?;
            println!(
                "Build manifest written to {} ({} artifact{})",
                output_path.display(),
                manifest.artifact_hashes.len(),
                if manifest.artifact_hashes.len() == 1 {
                    ""
                } else {
                    "s"
                }
            );
        }
        "bench" => {
            let benign_path = args
                .next()
                .unwrap_or_else(|| "examples/benign_extended.csv".to_string());
            let attack_path = args
                .next()
                .ok_or_else(|| "missing attack CSV path for `bench`".to_string())?;
            let threshold: f32 = args
                .next()
                .map(|t| {
                    t.parse::<f32>()
                        .map_err(|_| "invalid threshold".to_string())
                })
                .transpose()?
                .unwrap_or(2.0);

            if args.next().is_some() {
                return Err("too many arguments for `bench`".into());
            }

            run_bench(&benign_path, &attack_path, threshold)?;
        }
        "serve" => {
            let port: u16 = args
                .next()
                .map(|p| p.parse().map_err(|_| "invalid port number".to_string()))
                .transpose()?
                .unwrap_or(8080);

            let site_dir = args
                .next()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("site"));
            let site_dir = resolve_site_dir(&site_dir)?;

            if args.next().is_some() {
                return Err("too many arguments for `serve`".into());
            }

            let config = load_or_create_config();
            let shutdown = Arc::new(AtomicBool::new(false));
            let shutdown_sig = shutdown.clone();
            let _ = register_ctrlc(shutdown_sig);

            server::run_server(port, &site_dir, shutdown, config).await?;
        }
        "server" => {
            // XDR server mode — central management + event correlation
            let config = load_or_create_config();
            let port: u16 = args
                .next()
                .map(|p| p.parse().map_err(|_| "invalid port number".to_string()))
                .transpose()?
                .unwrap_or(8080);
            let site_dir = resolve_site_dir(&PathBuf::from("site"))?;
            let shutdown = Arc::new(AtomicBool::new(false));

            // Start SIEM poller if enabled
            let siem_shutdown = shutdown.clone();
            let _siem_handle = wardex::siem::start_siem_poller(config.siem.clone(), siem_shutdown);

            let shutdown_sig = shutdown.clone();
            let _ = register_ctrlc(shutdown_sig);

            eprintln!("Wardex XDR Server v{}", env!("CARGO_PKG_VERSION"));
            server::run_server(port, &site_dir, shutdown, config).await?;
        }
        "agent" => {
            // XDR agent mode — enroll with server and run local monitoring
            let raw_agent_args: Vec<String> = args.collect();
            if let Some(config_path) = find_agent_config_override(&raw_agent_args)? {
                wardex::config::set_runtime_config_override(config_path)?;
            }
            let config = load_or_create_config();

            // Parse agent-specific args
            let mut server_url = config.agent.server_url.clone();
            let mut token = config.agent.enrollment_token.clone();
            let mut remaining_args = Vec::new();
            let mut args = raw_agent_args.into_iter();

            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--config" => {
                        let _ = args.next().ok_or("--config requires a path")?;
                    }
                    "--server" => {
                        server_url = args.next().ok_or("--server requires a URL")?;
                    }
                    "--token" => {
                        token = args.next().ok_or("--token requires a value")?;
                    }
                    "install" => {
                        let extra: Vec<String> = args.collect();
                        let sm = ServiceManager::new("agent", &extra)?;
                        let msg = sm.install()?;
                        println!("{msg}");
                        return Ok(());
                    }
                    "uninstall" => {
                        let sm = ServiceManager::new("agent", &[])?;
                        let msg = sm.uninstall()?;
                        println!("{msg}");
                        return Ok(());
                    }
                    "status" => {
                        let sm = ServiceManager::new("agent", &[])?;
                        match sm.status() {
                            Ok(s) => println!("{s}"),
                            Err(e) => println!("Service not installed or error: {e}"),
                        }
                        return Ok(());
                    }
                    other => remaining_args.push(other.to_string()),
                }
            }

            let has_persisted_agent_id = config
                .agent
                .agent_id
                .as_deref()
                .map(str::trim)
                .is_some_and(|value| !value.is_empty());

            if token.is_empty() && !has_persisted_agent_id {
                return Err("enrollment token required: use --token <TOKEN> or set agent.enrollment_token in config".into());
            }

            let mon = collector::MonitorConfig::default();
            let shutdown = Arc::new(AtomicBool::new(false));
            let shutdown_sig = shutdown.clone();
            let _ = register_ctrlc(shutdown_sig);

            agent_client::run_agent(&server_url, &token, &config, &mon, shutdown)?;
        }
        other => {
            return Err(format!(
                "unknown command `{other}`. run `cargo run -- help` for usage"
            ));
        }
    }

    Ok(())
}

fn find_agent_config_override(args: &[String]) -> Result<Option<PathBuf>, String> {
    let mut index = 0;
    while index < args.len() {
        if args[index] == "--config" {
            let value = args
                .get(index + 1)
                .ok_or_else(|| "--config requires a path".to_string())?;
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err("--config requires a path".into());
            }
            return Ok(Some(PathBuf::from(trimmed)));
        }
        index += 1;
    }
    Ok(None)
}

fn resolve_site_dir(site_dir: &Path) -> Result<PathBuf, String> {
    if site_dir.is_absolute() {
        return if site_dir.is_dir() {
            Ok(site_dir.to_path_buf())
        } else {
            Err(format!(
                "site directory does not exist: {}",
                site_dir.display()
            ))
        };
    }

    let mut candidates = Vec::new();

    if let Ok(current_dir) = env::current_dir() {
        candidates.push(current_dir.join(site_dir));
    }

    if let Ok(exe_path) = env::current_exe()
        && let Some(exe_dir) = exe_path.parent()
    {
        candidates.push(exe_dir.join(site_dir));
        candidates.push(exe_dir.join("..").join(site_dir));
        candidates.push(exe_dir.join("..").join("..").join(site_dir));
    }

    for candidate in candidates {
        if candidate.is_dir() {
            return candidate
                .canonicalize()
                .map_err(|e| format!("failed to canonicalize site directory: {e}"));
        }
    }

    Err(format!(
        "site directory `{}` not found from current directory or binary location",
        site_dir.display()
    ))
}

fn print_usage() {
    println!("Wardex — Cross-platform XDR platform");
    println!();
    println!("Quick start (no args needed):");
    println!("  cargo run                          Start server + live monitor with defaults");
    println!();
    println!("XDR Commands:");
    println!("  server  [port]                     Start XDR central server");
    println!("  agent   --server <url> --token <t>  Start XDR agent (connects to server)");
    println!("  agent   install [flags]            Install agent as OS service");
    println!("  agent   uninstall                  Uninstall agent OS service");
    println!("  agent   status                     Check agent service status");
    println!();
    println!("Standalone Commands:");
    println!("  start   [--port <port>] [flags]    Server + monitor (same as no args)");
    println!("  monitor [flags]                    CLI-only monitor (no web server)");
    println!("  serve   [port] [site_dir]          Web server only (no monitor)");
    println!("  demo    [audit_path]               Run demo telemetry analysis");
    println!("  analyze <csv|jsonl> [audit_path]   Analyze telemetry file");
    println!("  report  <csv|jsonl> [report_path]  Generate JSON report");
    println!("  init-config [config_path]          Write default config file");
    println!("  status                             Print project status");
    println!("  status-json [output_path]          Export status as JSON");
    println!("  doctor                             Run preflight diagnostics");
    println!("  harness                            Run adversarial harness");
    println!("  export-model <tla|alloy> [path]    Export formal model");
    println!("  attest <binary> [manifest] [...]   Generate build manifest");
    println!("  bench <benign> <attack> [thresh]   Benchmark detectors");
    println!("  version                            Print Wardex version and exit");
    println!("  help                               Show this message");
    println!();
    println!("Monitor flags (for start/monitor):");
    println!("  --interval <secs>     Collection interval (default: 5)");
    println!("  --threshold <score>   Alert threshold (default: 3.5)");
    println!("  --alert-log <path>    Alert output file (default: var/alerts.jsonl)");
    println!("  --webhook <url>       POST alerts to webhook URL");
    println!("  --watch <paths>       File integrity paths (comma-separated)");
    println!("  --duration <secs>     Auto-stop after N seconds (0 = unlimited)");
    println!("  --dry-run             Detect only, no enforcement");
    println!("  --syslog              Output alerts as RFC 5424 syslog");
    println!("  --cef                 Output alerts as ArcSight CEF");
    println!();
    println!("Configuration:");
    println!("  All settings can be changed via the admin console at");
    println!("  http://localhost:8080/admin/ (Settings panel).");
    println!("  Config is stored in var/wardex.toml and persists across restarts.");
}

fn load_or_create_config() -> Config {
    let config_path = wardex::config::runtime_config_path();
    if config_path.exists() {
        match Config::load_from_path(&config_path) {
            Ok(c) => return c,
            Err(e) => eprintln!(
                "warning: failed to load {}: {e}, using defaults",
                config_path.display()
            ),
        }
    } else {
        // Create default config on first run
        if let Err(e) = Config::write_default_toml(&config_path) {
            eprintln!("warning: failed to write default config: {e}");
        } else {
            eprintln!("Created default config: {}", config_path.display());
        }
    }
    Config::default()
}

fn register_ctrlc(shutdown: Arc<AtomicBool>) -> Result<(), String> {
    ctrlc::set_handler(move || {
        eprintln!("\nShutting down gracefully…");
        shutdown.store(true, Ordering::SeqCst);
    })
    .map_err(|e| format!("failed to register Ctrl+C handler: {e}"))
}

fn run_bench(benign_path: &str, attack_path: &str, threshold: f32) -> Result<(), String> {
    let benign_samples =
        TelemetrySample::parse_auto(Path::new(benign_path)).map_err(|e| e.to_string())?;
    let attack_samples =
        TelemetrySample::parse_auto(Path::new(attack_path)).map_err(|e| e.to_string())?;

    let mut labeled: Vec<(TelemetrySample, bool)> = Vec::new();
    for s in &benign_samples {
        labeled.push((*s, false));
    }
    for s in &attack_samples {
        labeled.push((*s, true));
    }

    let total = labeled.len();

    // Adaptive EWMA detector
    let mut adaptive = AnomalyDetector::default();
    let start_adaptive = std::time::Instant::now();
    let ewma_result = run_benchmark(&mut adaptive, &labeled, threshold);
    let elapsed_adaptive = start_adaptive.elapsed();

    // Fixed-threshold detector
    let fixed = FixedThresholdDetector::default();
    let start_fixed = std::time::Instant::now();
    let fixed_result = run_fixed_benchmark(&fixed, &labeled, threshold);
    let elapsed_fixed = start_fixed.elapsed();

    println!("Wardex benchmark comparison");
    println!(
        "  benign: {} ({} samples)",
        benign_path,
        benign_samples.len()
    );
    println!(
        "  attack: {} ({} samples)",
        attack_path,
        attack_samples.len()
    );
    println!("  threshold: {threshold:.1}");
    println!("  total samples: {total}");
    println!();

    fn print_row(label: &str, r: &BenchmarkResult, elapsed: std::time::Duration, total: usize) {
        let throughput = total as f64 / elapsed.as_secs_f64();
        println!(
            "  {label:<16} P={:.3}  R={:.3}  F1={:.3}  Acc={:.3}  TP={:<4} FP={:<4} FN={:<4} TN={:<4}  {:.0} samples/s",
            r.precision,
            r.recall,
            r.f1,
            r.accuracy,
            r.true_positives,
            r.false_positives,
            r.false_negatives,
            r.true_negatives,
            throughput,
        );
    }

    print_row("Adaptive EWMA", &ewma_result, elapsed_adaptive, total);
    print_row("Fixed Thresh.", &fixed_result, elapsed_fixed, total);

    if !ewma_result.signal_contributions.is_empty() || !fixed_result.signal_contributions.is_empty()
    {
        println!();
        println!("  Per-signal average contributions:");
        let all_signals: Vec<&str> = {
            let mut s: Vec<&str> = ewma_result
                .signal_contributions
                .iter()
                .map(|(n, _)| n.as_str())
                .chain(
                    fixed_result
                        .signal_contributions
                        .iter()
                        .map(|(n, _)| n.as_str()),
                )
                .collect();
            s.sort();
            s.dedup();
            s
        };
        for signal in &all_signals {
            let ewma_val = ewma_result
                .signal_contributions
                .iter()
                .find(|(n, _)| n == signal)
                .map(|(_, v)| *v)
                .unwrap_or(0.0);
            let fixed_val = fixed_result
                .signal_contributions
                .iter()
                .find(|(n, _)| n == signal)
                .map(|(_, v)| *v)
                .unwrap_or(0.0);
            println!("    {signal:<22} EWMA={ewma_val:.4}  Fixed={fixed_val:.4}");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::find_agent_config_override;
    use std::path::PathBuf;

    #[test]
    fn finds_agent_config_override_in_argument_list() {
        let args = vec![
            "--server".to_string(),
            "https://manager.example.com:9090".to_string(),
            "--config".to_string(),
            "/tmp/wardex-agent.toml".to_string(),
        ];

        let path = find_agent_config_override(&args).unwrap();
        assert_eq!(path, Some(PathBuf::from("/tmp/wardex-agent.toml")));
    }

    #[test]
    fn rejects_missing_agent_config_override_value() {
        let args = vec!["--config".to_string()];
        let error = find_agent_config_override(&args).unwrap_err();
        assert!(error.contains("requires a path"));
    }
}
