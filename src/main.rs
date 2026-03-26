use std::env;
use std::path::PathBuf;
use std::process;

use sentineledge::config::Config;
use sentineledge::report::JsonReport;
use sentineledge::runtime;
use sentineledge::server;
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
    println!("  cargo run -- serve [port] [site_dir]");
    println!("  cargo run -- help");
}
