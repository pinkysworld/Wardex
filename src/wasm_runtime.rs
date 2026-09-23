//! Real WebAssembly extension runtime — `wardex_v1` host ABI, backed by
//! `wasmi` (a pure-Rust, deterministic WebAssembly *interpreter*: no JIT,
//! no `unsafe` in the embedder API surface, and fuel metering built in).
//!
//! ## Why `wasmi` and not `wasmtime`
//!
//! Wardex is a security product embedding *third-party, untrusted* code.
//! `wasmtime` compiles guest modules to native machine code with a JIT
//! (Cranelift), which:
//!   - executes attacker-influenced bytes as native instructions, widening
//!     the exploitable surface if the JIT itself has a bug (JIT bugs are a
//!     recurring CVE category across every mainstream JIT);
//!   - pulls in a large dependency graph (Cranelift, `mmap`-based code
//!     generation, platform-specific unwinding) that is hard to audit and
//!     meaningfully increases binary size;
//!   - needs W^X memory and executable-page allocation, which is extra
//!     attack surface this crate would rather not carry given
//!     `#![forbid(unsafe_code)]` at the crate level (wasmtime's own use of
//!     `unsafe` is not something we inherit responsibility for auditing,
//!     but it does mean "no JIT bugs" is not a property we can claim).
//!
//! `wasmi` interprets validated bytecode directly, has deterministic fuel
//! accounting for every instruction (a natural fit for "wall-clock budget"
//! enforcement without timers or threads), and is small enough that
//! reviewing its host-facing API surface is tractable. The interpreter is
//! slower per-instruction than a JIT, which is an acceptable trade for a
//! detection/response extension point that runs short, bounded snippets of
//! logic per event rather than hot inner loops. See `docs/WASM_ABI.md` for
//! the full ABI contract and `docs/WASM_TUTORIAL.md` for a walkthrough.
//!
//! License note: `wasmi` and its `wasmi_core`/`wasmi_ir`/`wasmi_collections`
//! crates are Apache-2.0; `wat`/`wast`/`wasmparser`/`wasm-encoder` (pulled
//! in transitively, and directly as a dev-dependency for tests) are
//! Apache-2.0 WITH LLVM-exception. Both are already in `deny.toml`'s
//! `licenses.allow` list, so no policy change was needed.
//!
//! ## Legacy VM
//!
//! [`crate::wasm_engine`] is a small stack-based bytecode VM predating this
//! module and is *not* WebAssembly. It remains available (see its module
//! docs) for the one existing caller (`/api/policy-vm/execute`) but new
//! extensions should target this module instead.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use wasmi::{
    Caller, Config as WasmiConfig, Engine, Extern, Linker, Module, ResourceLimiter, Store,
    StoreLimits, StoreLimitsBuilder,
};

/// Host ABI module name that guest imports must target.
pub const ABI_MODULE: &str = "wardex_v1";
/// Host ABI version. Guests declare their expected version via the
/// `wardex_abi_version` export; a mismatch is a load-time rejection.
pub const ABI_VERSION: i32 = 1;
/// Host functions that guests are allowed to import from [`ABI_MODULE`].
pub const ALLOWED_IMPORTS: &[&str] = &["log", "emit_alert", "kv_get", "kv_set", "now_unix_ms"];
/// Guest exports required of every loaded module.
pub const REQUIRED_EXPORTS: &[&str] = &["wardex_abi_version", "init", "alloc", "on_event"];

// ── Config ───────────────────────────────────────────────────────────────

/// Configuration for the WebAssembly extension runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WasmRuntimeSettings {
    /// Whether the runtime loads and executes extensions at all.
    pub enabled: bool,
    /// Directory scanned for `*.wasm` extension modules at startup/reload.
    pub extensions_dir: String,
    /// Fuel budget per invocation (covers `init` + one `on_event` call).
    /// `wasmi` charges fuel per interpreted instruction/block, so this is
    /// the CPU-bound proxy for a wall-clock timeout: exhausting it raises
    /// a deterministic trap rather than running unbounded.
    pub fuel_limit: u64,
    /// Maximum linear memory size, in 64 KiB Wasm pages, an extension may
    /// grow to. Enforced by a [`wasmi::ResourceLimiter`].
    pub max_memory_pages: u32,
    /// Documented budget in milliseconds that `fuel_limit` is calibrated
    /// against. Not itself enforced by a timer — see the module docs on
    /// why fuel is used as the enforcement mechanism instead.
    pub timeout_ms: u64,
    /// Maximum size, in bytes, of a `.wasm` module file that will be
    /// loaded (rejected before parsing/validation if larger).
    pub max_module_bytes: usize,
    /// Maximum number of key/value entries an extension may hold in its
    /// scoped state store.
    pub max_kv_entries: usize,
    /// Maximum size, in bytes, of a single key/value entry's value.
    pub max_kv_value_bytes: usize,
    /// Require an Ed25519 signature (checked against
    /// `trusted_upload_signers`) on every module uploaded through the API,
    /// in addition to the content-hash the caller supplies.
    pub require_signed_uploads: bool,
    /// Base64-encoded Ed25519 public keys trusted to sign uploaded
    /// extension modules.
    pub trusted_upload_signers: Vec<String>,
}

impl Default for WasmRuntimeSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            extensions_dir: "var/wasm_extensions".to_string(),
            fuel_limit: 5_000_000,
            max_memory_pages: 16, // 1 MiB
            timeout_ms: 50,
            max_module_bytes: 2 * 1024 * 1024,
            max_kv_entries: 64,
            max_kv_value_bytes: 4096,
            require_signed_uploads: false,
            trusted_upload_signers: Vec::new(),
        }
    }
}

// ── Host-visible outputs ─────────────────────────────────────────────────

/// A detection/alert emitted by a guest via the `emit_alert` host call.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EmittedAlert {
    /// One of "critical" | "high" | "medium" | "low" | "info" (free-form;
    /// callers should validate against their own severity enum).
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub mitre_technique: Option<String>,
    #[serde(default)]
    pub fields: serde_json::Map<String, serde_json::Value>,
}

/// Per-extension execution metrics, surfaced via `doctor`/`/api/status`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExtensionMetrics {
    pub invocations: u64,
    pub fuel_used_total: u64,
    pub traps: u64,
    pub errors: u64,
    pub alerts_emitted: u64,
    pub last_error: Option<String>,
    pub last_invocation_ms: Option<u64>,
}

// ── Loaded extension ─────────────────────────────────────────────────────

struct WasmExtension {
    name: String,
    sha256: String,
    module: Module,
    /// Extension-scoped key/value state. Persists across invocations of
    /// this extension but is never shared with other extensions — this is
    /// the isolation boundary tests exercise.
    kv: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    metrics: Mutex<ExtensionMetrics>,
}

/// Guest memory + host-callback state for a single invocation.
struct HostState {
    extension_name: String,
    alerts: Vec<EmittedAlert>,
    kv: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    max_kv_entries: usize,
    max_kv_value_bytes: usize,
    limits: StoreLimits,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Bound on any single guest->host byte read, independent of extension
/// memory limits, so a malformed `len` argument cannot force an
/// unbounded host-side allocation.
const MAX_HOST_READ_BYTES: usize = 256 * 1024;

fn read_guest_bytes(caller: &mut Caller<'_, HostState>, ptr: i32, len: i32) -> Vec<u8> {
    if ptr < 0 || len < 0 {
        return Vec::new();
    }
    let len = (len as usize).min(MAX_HOST_READ_BYTES);
    let memory = match caller.get_export("memory") {
        Some(Extern::Memory(m)) => m,
        _ => return Vec::new(),
    };
    let mut buf = vec![0u8; len];
    if memory.read(&caller, ptr as usize, &mut buf).is_err() {
        return Vec::new();
    }
    buf
}

fn host_log(mut caller: Caller<'_, HostState>, ptr: i32, len: i32) {
    let bytes = read_guest_bytes(&mut caller, ptr, len);
    let message = String::from_utf8_lossy(&bytes);
    let name = caller.data().extension_name.clone();
    log::info!(target: "wasm_extension", "[{name}] {message}");
}

#[derive(Debug, Deserialize)]
struct RawAlert {
    #[serde(default)]
    severity: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    mitre_technique: Option<String>,
    #[serde(default)]
    fields: Option<serde_json::Map<String, serde_json::Value>>,
}

fn host_emit_alert(mut caller: Caller<'_, HostState>, ptr: i32, len: i32) -> i32 {
    let bytes = read_guest_bytes(&mut caller, ptr, len);
    match serde_json::from_slice::<RawAlert>(&bytes) {
        Ok(raw) => {
            caller.data_mut().alerts.push(EmittedAlert {
                severity: raw.severity,
                title: raw.title,
                mitre_technique: raw.mitre_technique,
                fields: raw.fields.unwrap_or_default(),
            });
            0
        }
        Err(_) => -1,
    }
}

fn host_kv_get(mut caller: Caller<'_, HostState>, key_ptr: i32, key_len: i32, val_ptr: i32, val_max_len: i32) -> i32 {
    let key_bytes = read_guest_bytes(&mut caller, key_ptr, key_len);
    let key = String::from_utf8_lossy(&key_bytes).to_string();
    let kv = caller.data().kv.clone();
    let value = lock(&kv).get(&key).cloned();
    let Some(value) = value else {
        return -1;
    };
    if val_max_len < 0 || value.len() > val_max_len as usize {
        return -2;
    }
    let memory = match caller.get_export("memory") {
        Some(Extern::Memory(m)) => m,
        _ => return -3,
    };
    if val_ptr < 0 || memory.write(&mut caller, val_ptr as usize, &value).is_err() {
        return -3;
    }
    value.len() as i32
}

fn host_kv_set(mut caller: Caller<'_, HostState>, key_ptr: i32, key_len: i32, val_ptr: i32, val_len: i32) -> i32 {
    let key_bytes = read_guest_bytes(&mut caller, key_ptr, key_len);
    let key = String::from_utf8_lossy(&key_bytes).to_string();
    let value = read_guest_bytes(&mut caller, val_ptr, val_len);
    let (max_entries, max_val_bytes) = {
        let s = caller.data();
        (s.max_kv_entries, s.max_kv_value_bytes)
    };
    if value.len() > max_val_bytes {
        return -2;
    }
    let kv = caller.data().kv.clone();
    let mut guard = lock(&kv);
    if !guard.contains_key(&key) && guard.len() >= max_entries {
        return -1;
    }
    guard.insert(key, value);
    0
}

fn host_now_unix_ms(_caller: Caller<'_, HostState>) -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

// ── Manager ──────────────────────────────────────────────────────────────

/// Loads, sandboxes, and runs `.wasm` extensions against pipeline events.
pub struct WasmExtensionManager {
    engine: Engine,
    config: WasmRuntimeSettings,
    extensions: Mutex<HashMap<String, Arc<WasmExtension>>>,
}

/// Result of a load attempt, returned to API callers and `doctor`.
#[derive(Debug, Clone, Serialize)]
pub struct LoadOutcome {
    pub name: String,
    pub sha256: String,
}

impl WasmExtensionManager {
    pub fn new(config: WasmRuntimeSettings) -> Self {
        let mut wasmi_config = WasmiConfig::default();
        wasmi_config.consume_fuel(true);
        let engine = Engine::new(&wasmi_config);
        Self {
            engine,
            config,
            extensions: Mutex::new(HashMap::new()),
        }
    }

    pub fn config(&self) -> &WasmRuntimeSettings {
        &self.config
    }

    /// Scans `extensions_dir` for `*.wasm` files and loads each one. Files
    /// that fail validation are skipped (logged) rather than aborting the
    /// whole load, so one bad extension cannot block the rest.
    pub fn load_dir(&self) -> Result<Vec<LoadOutcome>, String> {
        let mut loaded = Vec::new();
        if !self.config.enabled {
            return Ok(loaded);
        }
        let dir = Path::new(&self.config.extensions_dir);
        if !dir.exists() {
            return Ok(loaded);
        }
        let entries = std::fs::read_dir(dir).map_err(|e| format!("read {}: {e}", dir.display()))?;
        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("wasm") {
                continue;
            }
            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("extension")
                .to_string();
            let bytes = match std::fs::read(&path) {
                Ok(b) => b,
                Err(e) => {
                    log::warn!("wasm_runtime: could not read {}: {e}", path.display());
                    continue;
                }
            };
            match self.load_bytes(&name, &bytes) {
                Ok(outcome) => loaded.push(outcome),
                Err(e) => log::warn!("wasm_runtime: rejected extension '{name}': {e}"),
            }
        }
        Ok(loaded)
    }

    /// Validates and registers a module from raw bytes under `name`,
    /// replacing any prior extension with the same name. Fresh state (the
    /// extension's key/value store) is created, so replacing an extension
    /// starts it with a clean slate.
    pub fn load_bytes(&self, name: &str, bytes: &[u8]) -> Result<LoadOutcome, String> {
        if !self.config.enabled {
            return Err("wasm runtime is disabled".to_string());
        }
        if bytes.len() > self.config.max_module_bytes {
            return Err(format!(
                "module is {} bytes, exceeds max_module_bytes ({})",
                bytes.len(),
                self.config.max_module_bytes
            ));
        }
        let module = Module::new(&self.engine, bytes).map_err(|e| format!("invalid module: {e}"))?;

        for import in module.imports() {
            if import.module() != ABI_MODULE || !ALLOWED_IMPORTS.contains(&import.name()) {
                return Err(format!(
                    "forbidden import '{}::{}': only {ABI_MODULE}::{{{}}} is permitted",
                    import.module(),
                    import.name(),
                    ALLOWED_IMPORTS.join(", "),
                ));
            }
        }

        let export_names: Vec<&str> = module.exports().map(|e| e.name()).collect();
        for required in REQUIRED_EXPORTS {
            if !export_names.contains(required) {
                return Err(format!("module is missing required export '{required}'"));
            }
        }

        let sha256 = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(bytes))
        };

        let extension = Arc::new(WasmExtension {
            name: name.to_string(),
            sha256: sha256.clone(),
            module,
            kv: Arc::new(Mutex::new(HashMap::new())),
            metrics: Mutex::new(ExtensionMetrics::default()),
        });
        lock(&self.extensions).insert(name.to_string(), extension);
        Ok(LoadOutcome {
            name: name.to_string(),
            sha256,
        })
    }

    pub fn remove(&self, name: &str) -> bool {
        lock(&self.extensions).remove(name).is_some()
    }

    pub fn list(&self) -> Vec<LoadOutcome> {
        lock(&self.extensions)
            .values()
            .map(|e| LoadOutcome {
                name: e.name.clone(),
                sha256: e.sha256.clone(),
            })
            .collect()
    }

    pub fn metrics(&self) -> HashMap<String, ExtensionMetrics> {
        lock(&self.extensions)
            .iter()
            .map(|(name, ext)| (name.clone(), lock(&ext.metrics).clone()))
            .collect()
    }

    /// Runs every loaded extension against `event`, returning
    /// `(extension_name, alert)` pairs for every alert emitted. An
    /// individual extension's failure (trap, error, ABI mismatch) is
    /// recorded in its metrics and does not affect other extensions or
    /// the caller (this call never fails).
    pub fn run_on_event(&self, event: &serde_json::Value) -> Vec<(String, EmittedAlert)> {
        if !self.config.enabled {
            return Vec::new();
        }
        let event_bytes = serde_json::to_vec(event).unwrap_or_default();
        let names: Vec<String> = lock(&self.extensions).keys().cloned().collect();
        let mut out = Vec::new();
        for name in names {
            let extension = lock(&self.extensions).get(&name).cloned();
            let Some(extension) = extension else { continue };
            match self.invoke(&extension, &event_bytes) {
                Ok(alerts) => {
                    for alert in alerts {
                        out.push((name.clone(), alert));
                    }
                }
                Err(e) => log::warn!("wasm_runtime: extension '{name}' failed: {e}"),
            }
        }
        out
    }

    fn invoke(&self, extension: &Arc<WasmExtension>, event_bytes: &[u8]) -> Result<Vec<EmittedAlert>, String> {
        let start = Instant::now();
        let limits = StoreLimitsBuilder::new()
            .memory_size(self.config.max_memory_pages as usize * 65536)
            .memories(1)
            .tables(4)
            .instances(1)
            .trap_on_grow_failure(true)
            .build();
        let host_state = HostState {
            extension_name: extension.name.clone(),
            alerts: Vec::new(),
            kv: extension.kv.clone(),
            max_kv_entries: self.config.max_kv_entries,
            max_kv_value_bytes: self.config.max_kv_value_bytes,
            limits,
        };
        let mut store = Store::new(&self.engine, host_state);
        store.limiter(|state: &mut HostState| &mut state.limits as &mut dyn ResourceLimiter);
        store
            .set_fuel(self.config.fuel_limit)
            .map_err(|e| e.to_string())?;

        let mut linker = Linker::new(&self.engine);
        linker
            .func_wrap(ABI_MODULE, "log", host_log)
            .map_err(|e| e.to_string())?;
        linker
            .func_wrap(ABI_MODULE, "emit_alert", host_emit_alert)
            .map_err(|e| e.to_string())?;
        linker
            .func_wrap(ABI_MODULE, "kv_get", host_kv_get)
            .map_err(|e| e.to_string())?;
        linker
            .func_wrap(ABI_MODULE, "kv_set", host_kv_set)
            .map_err(|e| e.to_string())?;
        linker
            .func_wrap(ABI_MODULE, "now_unix_ms", host_now_unix_ms)
            .map_err(|e| e.to_string())?;

        let result = self.run_instance(&mut store, &mut linker, extension, event_bytes);

        let fuel_remaining = store.get_fuel().unwrap_or(0);
        let fuel_used = self.config.fuel_limit.saturating_sub(fuel_remaining);
        let elapsed_ms = start.elapsed().as_millis() as u64;

        let mut metrics = lock(&extension.metrics);
        metrics.invocations += 1;
        metrics.fuel_used_total += fuel_used;
        metrics.last_invocation_ms = Some(elapsed_ms);

        match result {
            Ok((code, alerts)) => {
                metrics.alerts_emitted += alerts.len() as u64;
                if code != 0 {
                    metrics.errors += 1;
                    metrics.last_error = Some(format!("on_event returned non-zero status {code}"));
                }
                Ok(alerts)
            }
            Err(e) => {
                let is_trap = e.contains("trap") || e.contains("fuel") || e.contains("out of bounds");
                if is_trap {
                    metrics.traps += 1;
                } else {
                    metrics.errors += 1;
                }
                metrics.last_error = Some(e.clone());
                Err(e)
            }
        }
    }

    fn run_instance(
        &self,
        store: &mut Store<HostState>,
        linker: &mut Linker<HostState>,
        extension: &Arc<WasmExtension>,
        event_bytes: &[u8],
    ) -> Result<(i32, Vec<EmittedAlert>), String> {
        let instance = linker
            .instantiate_and_start(&mut *store, &extension.module)
            .map_err(|e| format!("instantiate: {e}"))?;

        let abi_version_fn = instance
            .get_typed_func::<(), i32>(&*store, "wardex_abi_version")
            .map_err(|e| format!("missing wardex_abi_version export: {e}"))?;
        let version = abi_version_fn
            .call(&mut *store, ())
            .map_err(|e| format!("wardex_abi_version trapped: {e}"))?;
        if version != ABI_VERSION {
            return Err(format!(
                "ABI version mismatch: extension declares {version}, host supports {ABI_VERSION}"
            ));
        }

        let init_fn = instance
            .get_typed_func::<(), i32>(&*store, "init")
            .map_err(|e| format!("missing init export: {e}"))?;
        init_fn
            .call(&mut *store, ())
            .map_err(|e| format!("init trapped: {e}"))?;

        let memory = instance
            .get_memory(&*store, "memory")
            .ok_or_else(|| "module does not export linear memory".to_string())?;

        let alloc_fn = instance
            .get_typed_func::<i32, i32>(&*store, "alloc")
            .map_err(|e| format!("missing alloc export: {e}"))?;
        let len = i32::try_from(event_bytes.len()).map_err(|_| "event too large".to_string())?;
        let ptr = alloc_fn
            .call(&mut *store, len)
            .map_err(|e| format!("alloc trapped: {e}"))?;
        if ptr < 0 {
            return Err("guest alloc returned a negative pointer".to_string());
        }
        memory
            .write(&mut *store, ptr as usize, event_bytes)
            .map_err(|e| format!("writing event into guest memory: {e}"))?;

        let on_event_fn = instance
            .get_typed_func::<(i32, i32), i32>(&*store, "on_event")
            .map_err(|e| format!("missing on_event export: {e}"))?;
        let code = on_event_fn
            .call(&mut *store, (ptr, len))
            .map_err(|e| format!("on_event trapped: {e}"))?;

        let alerts = std::mem::take(&mut store.data_mut().alerts);
        Ok((code, alerts))
    }
}

// ── Upload signing (hash pinning + optional Ed25519 signature) ──────────

/// Verifies an uploaded module's content hash and, if
/// `require_signed_uploads` is set (or a signature is supplied), its
/// Ed25519 signature against `trusted_upload_signers`. Mirrors the
/// signing pattern used for agent update artifacts in
/// [`crate::auto_update`].
pub fn verify_upload(
    bytes: &[u8],
    expected_sha256: &str,
    signature_b64: Option<&str>,
    signer_pubkey_b64: Option<&str>,
    settings: &WasmRuntimeSettings,
) -> Result<String, String> {
    use base64::Engine as _;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use sha2::{Digest, Sha256};

    let actual_sha256 = hex::encode(Sha256::digest(bytes));
    if !expected_sha256.is_empty() && !actual_sha256.eq_ignore_ascii_case(expected_sha256) {
        return Err(format!(
            "sha256 mismatch: expected {expected_sha256}, computed {actual_sha256}"
        ));
    }

    if !settings.require_signed_uploads {
        return Ok(actual_sha256);
    }

    let signature_b64 = signature_b64.ok_or("missing required upload signature")?;
    let signer_pubkey_b64 = signer_pubkey_b64.ok_or("missing required upload signer public key")?;

    if !settings
        .trusted_upload_signers
        .iter()
        .any(|trusted| trusted == signer_pubkey_b64)
    {
        return Err("untrusted upload signer".to_string());
    }

    let b64 = base64::engine::general_purpose::STANDARD;
    let pk_bytes = b64
        .decode(signer_pubkey_b64)
        .map_err(|e| format!("decode signer public key: {e}"))?;
    let pk_arr: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| "signer public key must be 32 bytes".to_string())?;
    let verifying_key = VerifyingKey::from_bytes(&pk_arr).map_err(|e| format!("invalid signer key: {e}"))?;

    let sig_bytes = b64
        .decode(signature_b64)
        .map_err(|e| format!("decode signature: {e}"))?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "signature must be 64 bytes".to_string())?;
    let signature = Signature::from_bytes(&sig_arr);

    verifying_key
        .verify(bytes, &signature)
        .map_err(|e| format!("signature verification failed: {e}"))?;

    Ok(actual_sha256)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wat_module(source: &str) -> Vec<u8> {
        wat::parse_str(source).expect("valid WAT fixture")
    }

    /// A minimal, ABI-compliant extension: `init` and `on_event` both
    /// succeed without doing anything. Used as a scaffold other tests
    /// build on with string replacement.
    const HAPPY_PATH_WAT: &str = r#"
        (module
          (import "wardex_v1" "emit_alert" (func $emit_alert (param i32 i32) (result i32)))
          (memory (export "memory") 2)
          (global $heap_ptr (mut i32) (i32.const 1024))
          (data (i32.const 0) "{\"severity\":\"high\",\"title\":\"guest detection\",\"mitre_technique\":\"T1059\",\"fields\":{}}")

          (func (export "wardex_abi_version") (result i32) (i32.const 1))
          (func (export "init") (result i32) (i32.const 0))
          (func (export "alloc") (param $size i32) (result i32)
            (local $ptr i32)
            (local.set $ptr (global.get $heap_ptr))
            (global.set $heap_ptr (i32.add (global.get $heap_ptr) (local.get $size)))
            (local.get $ptr))
          (func (export "on_event") (param $ptr i32) (param $len i32) (result i32)
            (call $emit_alert (i32.const 0) (i32.const 83))
            drop
            (i32.const 0)))
    "#;

    fn manager(cfg: WasmRuntimeSettings) -> WasmExtensionManager {
        WasmExtensionManager::new(cfg)
    }

    fn enabled_config() -> WasmRuntimeSettings {
        WasmRuntimeSettings {
            enabled: true,
            ..Default::default()
        }
    }

    #[test]
    fn happy_path_emits_alert() {
        let mgr = manager(enabled_config());
        let bytes = wat_module(HAPPY_PATH_WAT);
        mgr.load_bytes("happy", &bytes).expect("loads");
        let event = serde_json::json!({"event_class": 1, "process_name": "cmd.exe"});
        let alerts = mgr.run_on_event(&event);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].0, "happy");
        assert_eq!(alerts[0].1.severity, "high");
        assert_eq!(alerts[0].1.mitre_technique.as_deref(), Some("T1059"));
        let metrics = mgr.metrics();
        let m = &metrics["happy"];
        assert_eq!(m.invocations, 1);
        assert_eq!(m.alerts_emitted, 1);
        assert_eq!(m.traps, 0);
        assert!(m.fuel_used_total > 0);
    }

    #[test]
    fn fuel_exhaustion_traps() {
        // Busy-loops forever; must exhaust fuel rather than hang the host.
        const BUSY_LOOP_WAT: &str = r#"
            (module
              (memory (export "memory") 2)
              (func (export "wardex_abi_version") (result i32) (i32.const 1))
              (func (export "init") (result i32) (i32.const 0))
              (func (export "alloc") (param $size i32) (result i32) (i32.const 1024))
              (func (export "on_event") (param $ptr i32) (param $len i32) (result i32)
                (loop $forever
                  (br $forever))
                (i32.const 0)))
        "#;
        let mut cfg = enabled_config();
        cfg.fuel_limit = 10_000;
        let mgr = manager(cfg);
        let bytes = wat_module(BUSY_LOOP_WAT);
        mgr.load_bytes("looper", &bytes).expect("loads (no forbidden imports)");
        let alerts = mgr.run_on_event(&serde_json::json!({}));
        assert!(alerts.is_empty());
        let metrics = mgr.metrics();
        let m = &metrics["looper"];
        assert_eq!(m.invocations, 1);
        assert_eq!(m.traps, 1);
        assert!(m.last_error.as_deref().unwrap_or("").to_lowercase().contains("fuel"));
    }

    #[test]
    fn memory_limit_is_enforced() {
        // Tries to grow memory far past the configured cap.
        const GROW_WAT: &str = r#"
            (module
              (memory (export "memory") 1)
              (func (export "wardex_abi_version") (result i32) (i32.const 1))
              (func (export "init") (result i32) (i32.const 0))
              (func (export "alloc") (param $size i32) (result i32) (i32.const 1024))
              (func (export "on_event") (param $ptr i32) (param $len i32) (result i32)
                (memory.grow (i32.const 10000))
                drop
                (i32.const 0)))
        "#;
        let mut cfg = enabled_config();
        cfg.max_memory_pages = 2; // 128 KiB cap; the guest asks for far more.
        let mgr = manager(cfg);
        let bytes = wat_module(GROW_WAT);
        mgr.load_bytes("grower", &bytes).expect("loads");
        let alerts = mgr.run_on_event(&serde_json::json!({}));
        assert!(alerts.is_empty());
        let metrics = mgr.metrics();
        let m = &metrics["grower"];
        // trap_on_grow_failure(true) turns the failed grow into a trap.
        assert_eq!(m.traps, 1);
    }

    #[test]
    fn forbidden_import_is_rejected_at_load() {
        const BAD_IMPORT_WAT: &str = r#"
            (module
              (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
              (memory (export "memory") 1)
              (func (export "wardex_abi_version") (result i32) (i32.const 1))
              (func (export "init") (result i32) (i32.const 0))
              (func (export "alloc") (param $size i32) (result i32) (i32.const 1024))
              (func (export "on_event") (param $ptr i32) (param $len i32) (result i32) (i32.const 0)))
        "#;
        let mgr = manager(enabled_config());
        let bytes = wat_module(BAD_IMPORT_WAT);
        let err = mgr.load_bytes("bad", &bytes).unwrap_err();
        assert!(err.contains("forbidden import"), "unexpected error: {err}");
        assert!(mgr.list().is_empty());
    }

    #[test]
    fn malformed_module_is_rejected() {
        let mgr = manager(enabled_config());
        let err = mgr.load_bytes("garbage", b"not a wasm module").unwrap_err();
        assert!(err.contains("invalid module"), "unexpected error: {err}");
    }

    #[test]
    fn module_size_limit_is_enforced() {
        let mut cfg = enabled_config();
        cfg.max_module_bytes = 8;
        let mgr = manager(cfg);
        let bytes = wat_module(HAPPY_PATH_WAT);
        assert!(bytes.len() > 8);
        let err = mgr.load_bytes("toobig", &bytes).unwrap_err();
        assert!(err.contains("max_module_bytes"), "unexpected error: {err}");
    }

    #[test]
    fn missing_required_export_is_rejected() {
        const NO_ON_EVENT_WAT: &str = r#"
            (module
              (memory (export "memory") 1)
              (func (export "wardex_abi_version") (result i32) (i32.const 1))
              (func (export "init") (result i32) (i32.const 0))
              (func (export "alloc") (param $size i32) (result i32) (i32.const 1024)))
        "#;
        let mgr = manager(enabled_config());
        let bytes = wat_module(NO_ON_EVENT_WAT);
        let err = mgr.load_bytes("incomplete", &bytes).unwrap_err();
        assert!(err.contains("missing required export"), "unexpected error: {err}");
    }

    #[test]
    fn abi_version_mismatch_is_rejected_at_run() {
        const WRONG_VERSION_WAT: &str = r#"
            (module
              (memory (export "memory") 1)
              (func (export "wardex_abi_version") (result i32) (i32.const 99))
              (func (export "init") (result i32) (i32.const 0))
              (func (export "alloc") (param $size i32) (result i32) (i32.const 1024))
              (func (export "on_event") (param $ptr i32) (param $len i32) (result i32) (i32.const 0)))
        "#;
        let mgr = manager(enabled_config());
        let bytes = wat_module(WRONG_VERSION_WAT);
        mgr.load_bytes("wrongver", &bytes).expect("loads (validation is structural, not semantic)");
        let alerts = mgr.run_on_event(&serde_json::json!({}));
        assert!(alerts.is_empty());
        let metrics = mgr.metrics();
        let m = &metrics["wrongver"];
        assert_eq!(m.errors, 1);
        assert!(m.last_error.as_deref().unwrap_or("").contains("ABI version mismatch"));
    }

    #[test]
    fn state_is_isolated_between_extensions() {
        const KV_ROUNDTRIP_WAT: &str = r#"
            (module
              (import "wardex_v1" "kv_set" (func $kv_set (param i32 i32 i32 i32) (result i32)))
              (import "wardex_v1" "kv_get" (func $kv_get (param i32 i32 i32 i32) (result i32)))
              (import "wardex_v1" "emit_alert" (func $emit_alert (param i32 i32) (result i32)))
              (memory (export "memory") 2)
              ;; key "k" at offset 0 (1 byte); alert JSON template at offset 16;
              ;; read buffer at offset 128.
              (data (i32.const 0) "k")
              (data (i32.const 16) "{\"severity\":\"low\",\"title\":\"seen-before\",\"fields\":{}}")

              (func (export "wardex_abi_version") (result i32) (i32.const 1))
              (func (export "init") (result i32) (i32.const 0))
              (func (export "alloc") (param $size i32) (result i32) (i32.const 512))
              (func (export "on_event") (param $ptr i32) (param $len i32) (result i32)
                (local $got i32)
                (local.set $got (call $kv_get (i32.const 0) (i32.const 1) (i32.const 128) (i32.const 16)))
                (if (i32.eq (local.get $got) (i32.const -1))
                  (then
                    ;; first time seen: remember it, stay quiet.
                    (drop (call $kv_set (i32.const 0) (i32.const 1) (i32.const 200) (i32.const 1))))
                  (else
                    ;; seen before (state persisted): raise an alert.
                    (drop (call $emit_alert (i32.const 16) (i32.const 52)))))
                (i32.const 0)))
        "#;
        let mgr = manager(enabled_config());
        let bytes = wat_module(KV_ROUNDTRIP_WAT);
        mgr.load_bytes("a", &bytes).expect("loads");
        mgr.load_bytes("b", &bytes).expect("loads");

        // First event: neither extension has state yet, so no alerts.
        let alerts = mgr.run_on_event(&serde_json::json!({}));
        assert!(alerts.is_empty());

        // Second event: each extension now has *its own* persisted key
        // and should independently alert — if state leaked between them,
        // it wouldn't change this particular assertion, so we also check
        // that extension "b" alerting doesn't depend on "a" ever having
        // run (simulated by only running "a" for the first event above,
        // both saw the same call though — the real isolation check is
        // that each has exactly one alert here, from its own state).
        let alerts = mgr.run_on_event(&serde_json::json!({}));
        let names: Vec<&str> = alerts.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"a"));
        assert!(names.contains(&"b"));
        assert_eq!(alerts.len(), 2);
    }

    #[test]
    fn verify_upload_checks_hash() {
        let settings = WasmRuntimeSettings::default();
        let bytes = wat_module(HAPPY_PATH_WAT);
        let good_sha = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(&bytes))
        };
        assert!(verify_upload(&bytes, &good_sha, None, None, &settings).is_ok());
        assert!(verify_upload(&bytes, "deadbeef", None, None, &settings).is_err());
    }

    #[test]
    fn verify_upload_requires_trusted_signature_when_configured() {
        use base64::Engine as _;
        use ed25519_dalek::{Signer, SigningKey};

        let bytes = wat_module(HAPPY_PATH_WAT);
        let sha = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(&bytes))
        };
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let signature = signing_key.sign(&bytes);
        let b64 = base64::engine::general_purpose::STANDARD;
        let sig_b64 = b64.encode(signature.to_bytes());
        let pk_b64 = b64.encode(signing_key.verifying_key().to_bytes());

        let mut settings = WasmRuntimeSettings {
            require_signed_uploads: true,
            ..Default::default()
        };
        // No trusted signer configured yet: must fail even with a valid signature.
        assert!(verify_upload(&bytes, &sha, Some(&sig_b64), Some(&pk_b64), &settings).is_err());

        settings.trusted_upload_signers.push(pk_b64.clone());
        assert!(verify_upload(&bytes, &sha, Some(&sig_b64), Some(&pk_b64), &settings).is_ok());

        // Missing signature entirely, once required, is rejected.
        assert!(verify_upload(&bytes, &sha, None, None, &settings).is_err());
    }

    #[test]
    fn disabled_runtime_loads_nothing_and_runs_nothing() {
        let mgr = manager(WasmRuntimeSettings::default()); // enabled: false
        let bytes = wat_module(HAPPY_PATH_WAT);
        assert!(mgr.load_bytes("x", &bytes).is_err());
        assert!(mgr.run_on_event(&serde_json::json!({})).is_empty());
    }
}
