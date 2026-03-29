use std::env;
use std::path::{Path, PathBuf};
use std::process;

use sentineledge::attestation::BuildManifest;
use sentineledge::benchmark::{BenchmarkResult, run_benchmark};
use sentineledge::config::Config;
use sentineledge::detector::AnomalyDetector;
use sentineledge::fixed_threshold::{FixedThresholdDetector, run_fixed_benchmark};
use sentineledge::harness::{self, HarnessConfig};
use sentineledge::report::JsonReport;
use sentineledge::runtime;
use sentineledge::server;
use sentineledge::state_machine::PolicyStateMachine;
use sentineledge::telemetry::TelemetrySample;

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        print_usage();
        return Ok(());
    };

    match command.as_str() {
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
                .unwrap_or_else(|| PathBuf::from("sentineledge.toml"));

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
        "harness" => {
            if args.next().is_some() {
                return Err("`harness` does not accept extra arguments".into());
            }

            let config = HarnessConfig::default();
            let result = harness::run(&config);

            println!("SentinelEdge adversarial harness");
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

            if args.next().is_some() {
                return Err("too many arguments for `serve`".into());
            }

            server::run_server(port, &site_dir)?;
        }
        other => {
            return Err(format!(
                "unknown command `{other}`. run `cargo run -- help` for usage"
            ));
        }
    }

    Ok(())
}

fn print_usage() {
    println!("SentinelEdge prototype");
    println!();
    println!("Usage:");
    println!("  cargo run -- demo [audit_path]");
    println!("  cargo run -- analyze <csv_or_jsonl_path> [audit_path]");
    println!("  cargo run -- report <csv_or_jsonl_path> [report_path]");
    println!("  cargo run -- init-config [config_path]");
    println!("  cargo run -- status");
    println!("  cargo run -- status-json [output_path]");
    println!("  cargo run -- harness");
    println!("  cargo run -- export-model <tla|alloy> [output_path]");
    println!("  cargo run -- attest <binary_path> [manifest_path] [artifact...]");
    println!("  cargo run -- bench <benign_csv> <attack_csv> [threshold]");
    println!("  cargo run -- serve [port] [site_dir]");
    println!("  cargo run -- help");
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

    println!("SentinelEdge benchmark comparison");
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
