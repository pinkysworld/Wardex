#![no_main]
//! Fuzzes WebAssembly extension module loading (parsing, validation, and
//! import/export ABI checks) in `wardex::wasm_runtime`. Never executes a
//! loaded module — only `load_bytes` is exercised — so this target is
//! purely about the loader never panicking on attacker-controlled bytes.

use libfuzzer_sys::fuzz_target;
use wardex::wasm_runtime::{WasmExtensionManager, WasmRuntimeSettings};

fuzz_target!(|data: &[u8]| {
    let settings = WasmRuntimeSettings {
        enabled: true,
        ..Default::default()
    };
    let manager = WasmExtensionManager::new(settings);
    let _ = manager.load_bytes("fuzz", data);
});
