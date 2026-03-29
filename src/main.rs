use std::env;
use std::path::PathBuf;
use std::process;

use sentineledge::config::Config;
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
                other => return Err(format!("unknown format `{other}`, expected `tla` or `alloy`")),
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
    println!("  cargo run -- serve [port] [site_dir]");
    println!("  cargo run -- help");
}
