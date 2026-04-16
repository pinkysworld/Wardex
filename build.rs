use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let admin_dir = PathBuf::from("admin-console");
    let src_dir = admin_dir.join("src");

    println!("cargo:rerun-if-changed=build.rs");
    emit_rerun_for_file(admin_dir.join("index.html"));
    emit_rerun_for_file(admin_dir.join("package.json"));
    emit_rerun_for_file(admin_dir.join("package-lock.json"));
    emit_rerun_for_file(admin_dir.join("vite.config.js"));
    emit_rerun_for_dir(&src_dir);

    run_admin_build(&admin_dir);

    let dist_index = admin_dir.join("dist").join("index.html");
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

fn npm_command() -> OsString {
    if cfg!(windows) {
        OsString::from("npm.cmd")
    } else if let Ok(explicit) = env::var("NPM") {
        OsString::from(explicit)
    } else {
        OsString::from("npm")
    }
}
