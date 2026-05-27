use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(tarpaulin)");

    let admin_dir = PathBuf::from("admin-console");
    let src_dir = admin_dir.join("src");
    let dist_index = admin_dir.join("dist").join("index.html");

    println!("cargo:rerun-if-changed=build.rs");
    emit_rerun_for_file(admin_dir.join("index.html"));
    emit_rerun_for_file(admin_dir.join("package.json"));
    emit_rerun_for_file(admin_dir.join("package-lock.json"));
    emit_rerun_for_file(admin_dir.join("vite.config.js"));
    emit_rerun_for_dir(&src_dir);

    match admin_build_skip_reason(&admin_dir) {
        Some(reason) => {
            if env_flag("WARDEX_SKIP_ADMIN_BUILD") {
                ensure_placeholder_admin_dist(&dist_index);
                println!(
                    "cargo:warning=embedded admin console build skipped by WARDEX_SKIP_ADMIN_BUILD: {reason}; using placeholder dist/index.html"
                );
            } else {
                panic!(
                    "embedded admin console cannot be built: {reason}. \
                     Install Node.js and run `npm ci --prefix admin-console`, \
                     or set WARDEX_SKIP_ADMIN_BUILD=1 to ship a placeholder UI."
                );
            }
        }
        None => run_admin_build(&admin_dir),
    }

    if !dist_index.is_file() {
        panic!(
            "admin console build did not produce {}",
            dist_index.display()
        );
    }
}

fn emit_rerun_for_file(path: PathBuf) {
    if path.exists() {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

fn emit_rerun_for_dir(dir: &Path) {
    if !dir.exists() {
        return;
    }
    let entries = fs::read_dir(dir).unwrap_or_else(|e| {
        panic!(
            "failed to read admin console source directory {}: {e}",
            dir.display()
        )
    });
    for entry in entries {
        let entry = entry.unwrap_or_else(|e| panic!("failed to read admin console entry: {e}"));
        let path = entry.path();
        if path.is_dir() {
            emit_rerun_for_dir(&path);
        } else {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}

fn run_admin_build(admin_dir: &Path) {
    let npm = npm_command();
    let status = Command::new(&npm)
        .arg("run")
        .arg("build")
        .current_dir(admin_dir)
        .status()
        .unwrap_or_else(|e| {
            panic!(
                "failed to run `{}` for embedded admin console build in {}: {e}. run `npm ci --prefix admin-console` before cargo build when building from a clean checkout",
                npm.to_string_lossy(),
                admin_dir.display()
            )
        });
    if !status.success() {
        panic!(
            "embedded admin console build failed in {} with status {}. run `npm ci --prefix admin-console` before cargo build when building from a clean checkout",
            admin_dir.display(),
            status
        );
    }
}

fn admin_build_skip_reason(admin_dir: &Path) -> Option<String> {
    if env_flag("WARDEX_SKIP_ADMIN_BUILD") {
        return Some("WARDEX_SKIP_ADMIN_BUILD is set".to_string());
    }
    let npm = npm_command();
    match Command::new(&npm).arg("--version").status() {
        Ok(status) if status.success() => {}
        Ok(status) => {
            return Some(format!(
                "{} --version exited with status {}",
                npm.to_string_lossy(),
                status
            ));
        }
        Err(err) => {
            return Some(format!("{} is unavailable: {err}", npm.to_string_lossy()));
        }
    }
    if !admin_dir.join("node_modules").is_dir() {
        if !admin_dir.join("package-lock.json").is_file() {
            return Some(
                "admin-console/node_modules and admin-console/package-lock.json are both missing"
                    .to_string(),
            );
        }
        println!(
            "cargo:warning=admin-console/node_modules missing; running `npm ci` to install dependencies"
        );
        let status = Command::new(&npm)
            .arg("ci")
            .current_dir(admin_dir)
            .status();
        match status {
            Ok(s) if s.success() => {}
            Ok(s) => {
                return Some(format!(
                    "`npm ci` for admin console exited with status {s}"
                ));
            }
            Err(err) => {
                return Some(format!("failed to run `npm ci` for admin console: {err}"));
            }
        }
    }
    None
}

fn ensure_placeholder_admin_dist(dist_index: &Path) {
    if dist_index.is_file() {
        return;
    }
    if let Some(parent) = dist_index.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|e| {
            panic!(
                "failed to create placeholder admin console directory {}: {e}",
                parent.display()
            )
        });
    }
    fs::write(
        dist_index,
        concat!(
            "<!doctype html>\n",
            "<html lang=\"en\">\n",
            "  <head><meta charset=\"utf-8\"><title>Wardex Admin Console</title></head>\n",
            "  <body>\n",
            "    <main>Embedded admin console assets were not built for this checkout.</main>\n",
            "  </body>\n",
            "</html>\n"
        ),
    )
    .unwrap_or_else(|e| {
        panic!(
            "failed to write placeholder admin console dist asset {}: {e}",
            dist_index.display()
        )
    });
}

fn env_flag(key: &str) -> bool {
    env::var(key)
        .ok()
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn npm_command() -> OsString {
    if cfg!(windows) {
        OsString::from("npm.cmd")
    } else if let Ok(explicit) = env::var("NPM") {
        OsString::from(explicit)
    } else {
        OsString::from("npm")
    }
}
