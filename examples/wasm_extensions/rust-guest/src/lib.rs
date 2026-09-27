//! Example Wardex WebAssembly extension, written in Rust and compiled to
//! `wasm32-unknown-unknown`. Implements the `wardex_v1` host ABI (see
//! `docs/WASM_ABI.md` in the main Wardex repository).
//!
//! This crate is intentionally minimal and does not pull in `serde_json`
//! or any allocator crate: it uses `std` (available on
//! `wasm32-unknown-unknown`) with a trivial bump allocator for `alloc`,
//! and a hand-rolled scan for the two JSON fields it cares about rather
//! than a full JSON parser. A real extension is free to vendor
//! `serde`/`serde_json` instead — this is a "smallest working example",
//! not a template you must copy verbatim.
//!
//! Build:
//! ```sh
//! cargo build --target wasm32-unknown-unknown --release
//! ```
//! The output is at
//! `target/wasm32-unknown-unknown/release/wardex_example_extension.wasm`.

use std::cell::Cell;

// ── Host imports (module "wardex_v1") ───────────────────────────────────
// Only these five names, from only this module, are permitted — anything
// else causes the host to reject the module before it ever runs.
#[link(wasm_import_module = "wardex_v1")]
extern "C" {
    fn log(ptr: i32, len: i32);
    fn emit_alert(ptr: i32, len: i32) -> i32;
    #[allow(dead_code)]
    fn kv_get(key_ptr: i32, key_len: i32, val_ptr: i32, val_max_len: i32) -> i32;
    #[allow(dead_code)]
    fn kv_set(key_ptr: i32, key_len: i32, val_ptr: i32, val_len: i32) -> i32;
    #[allow(dead_code)]
    fn now_unix_ms() -> i64;
}

fn host_log(msg: &str) {
    unsafe { log(msg.as_ptr() as i32, msg.len() as i32) }
}

fn host_emit_alert(json: &str) {
    unsafe {
        emit_alert(json.as_ptr() as i32, json.len() as i32);
    }
}

// ── Trivial bump allocator backing the `alloc` export ───────────────────
//
// The host calls `alloc(size)` once per invocation (to get a buffer to
// write the event JSON into) before calling `on_event`. Since the whole
// instance is discarded after each invocation, a bump allocator that
// never frees is sufficient and keeps this example free of any crate
// dependency.
const HEAP_SIZE: usize = 64 * 1024; // 64 KiB scratch space
static mut HEAP: [u8; HEAP_SIZE] = [0; HEAP_SIZE];
thread_local! {
    static HEAP_OFFSET: Cell<usize> = const { Cell::new(0) };
}

#[no_mangle]
pub extern "C" fn alloc(size: i32) -> i32 {
    let size = size.max(0) as usize;
    HEAP_OFFSET.with(|off| {
        let start = off.get();
        if start + size > HEAP_SIZE {
            return -1;
        }
        off.set(start + size);
        // SAFETY: `start..start+size` was just reserved above and is
        // within `HEAP`'s bounds; this module is single-threaded (wasm32
        // has no threads here) so there is no concurrent access.
        (unsafe { HEAP.as_ptr().add(start) }) as i32
    })
}

#[no_mangle]
pub extern "C" fn wardex_abi_version() -> i32 {
    1
}

#[no_mangle]
pub extern "C" fn init() -> i32 {
    host_log("office_child_process extension initialized");
    0
}

/// Extracts a top-level string field's value from a flat JSON object
/// without a general-purpose parser. Good enough for Wardex's own event
/// encoding (flat, no nested objects in the fields this extension reads);
/// a real extension with more complex needs should vendor a JSON crate.
fn extract_string_field<'a>(json: &'a str, field: &str) -> Option<&'a str> {
    let needle = format!("\"{field}\"");
    let start = json.find(&needle)? + needle.len();
    let rest = &json[start..];
    let colon = rest.find(':')?;
    let after_colon = rest[colon + 1..].trim_start();
    let quoted = after_colon.strip_prefix('"')?;
    let end = quoted.find('"')?;
    Some(&quoted[..end])
}

#[no_mangle]
pub extern "C" fn on_event(ptr: i32, len: i32) -> i32 {
    let bytes = unsafe { std::slice::from_raw_parts(ptr as *const u8, len.max(0) as usize) };
    let Ok(event_json) = std::str::from_utf8(bytes) else {
        return -1;
    };

    let process_name = extract_string_field(event_json, "process_name").unwrap_or("");
    let parent_name = extract_string_field(event_json, "parent_process_name").unwrap_or("");

    let office_apps = ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"];
    let shells = ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe"];

    let parent_is_office = office_apps.iter().any(|a| parent_name.eq_ignore_ascii_case(a));
    let child_is_shell = shells.iter().any(|s| process_name.eq_ignore_ascii_case(s));

    if parent_is_office && child_is_shell {
        host_log("office application spawned a shell — raising alert");
        // Field values are inlined directly rather than JSON-escaped
        // generically, since process names from this event source are
        // already known not to contain quote characters; a production
        // extension handling untrusted strings should escape properly.
        let alert = format!(
            "{{\"severity\":\"high\",\"title\":\"Office application spawned a shell\",\
              \"mitre_technique\":\"T1566\",\"fields\":{{\"process_name\":\"{process_name}\",\
              \"parent_process_name\":\"{parent_name}\"}}}}"
        );
        host_emit_alert(&alert);
    }

    0
}
