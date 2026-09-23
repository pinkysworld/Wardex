# Wardex WebAssembly Extension ABI — `wardex_v1`

This document is the contract between the Wardex host runtime
(`src/wasm_runtime.rs`) and guest `.wasm` extension modules. It supersedes
the old bytecode-VM sketch previously described in `docs/WASM_TUTORIAL.md`;
extensions today are **real WebAssembly**, executed by [`wasmi`][wasmi], a
pure-Rust, deterministic interpreter (see "Runtime choice" below).

## Versioning

The ABI is versioned by name (`wardex_v1`) and by an explicit
`wardex_abi_version` export the guest must provide. The host currently
implements version `1`. A module whose `wardex_abi_version()` return value
does not match the host's supported version is rejected at run time (the
module still *loads* — the version check is semantic, run on first
invocation — but every invocation fails and is recorded in that
extension's `errors` metric).

## Sandbox model

Every extension runs in its own `wasmi` `Store`/`Instance`, freshly
instantiated for each event:

- **CPU bound**: fuel metering (`Config::consume_fuel(true)`) charges every
  interpreted instruction/block. Each invocation gets a fresh fuel budget
  (`wasm_runtime.fuel_limit`, config default `5_000_000`); exhausting it
  raises a deterministic trap. This is how a "wall-clock timeout" is
  enforced — without threads, without preemption, and without relying on
  the guest cooperating.
- **Memory bound**: a `wasmi::ResourceLimiter` (`StoreLimits`) caps linear
  memory growth at `wasm_runtime.max_memory_pages` 64 KiB pages (config
  default 16 pages = 1 MiB). A grow past the cap traps rather than
  silently failing.
- **Table bound**: the same `ResourceLimiter` caps every table at
  `wasm_runtime.max_table_elements` elements (config default 4096) —
  `wasmi` otherwise leaves table size unbounded, so a module declaring
  (or growing) a table with hundreds of millions of elements would cost
  the host hundreds of MB per invocation. Exceeding it fails
  instantiation or traps on `table.grow`, the same as the memory limit.
- **Host-call cost bound**: reading guest memory in a host call (`log`,
  `emit_alert`, `kv_get`/`kv_set` key and value arguments) charges extra
  fuel proportional to the bytes copied, on top of `wasmi`'s own
  per-instruction accounting — those bytes are host-side `memcpy`/JSON-
  parse work the guest's own interpreted instruction count would not
  otherwise reflect. `emit_alert` is additionally capped per invocation
  at `wasm_runtime.max_alerts_per_invocation` alerts (default 32) and
  `wasm_runtime.max_alert_bytes_per_invocation` total payload bytes
  (default 1 MiB); calls past either cap are rejected (see the return
  codes below) rather than growing the alert list without bound.
- **No ambient authority**: extensions get **no WASI**, no filesystem, no
  network, no clock beyond the explicit `now_unix_ms` host call. The only
  imports permitted are the five functions under the `wardex_v1` module
  listed below — anything else is rejected when the module is loaded,
  before it ever runs.
- **Module size bound**: `wasm_runtime.max_module_bytes` (default 2 MiB)
  is checked before parsing.
- **Load-time validation**: `wasmi::Module::new` validates the module
  (type-checks every function body) before it is accepted; malformed or
  invalid bytecode is rejected with no code ever executed.
- **State isolation**: each extension gets its own key/value store (see
  below), keyed by extension name at the host, never shared across
  extensions.

## Guest exports (required)

| Export | Signature | Purpose |
|---|---|---|
| `wardex_abi_version` | `() -> i32` | Must return `1`. Checked on every invocation before `init`/`on_event` run. |
| `init` | `() -> i32` | Called once per invocation, before `on_event`. Non-zero is recorded as an error but does not stop `on_event` from being attempted in the current implementation's ordering (init runs to completion or traps first). |
| `alloc` | `(size: i32) -> i32` | Bump-allocate `size` bytes in the guest's own linear memory and return the offset. The host calls this to obtain a buffer, then writes the current event's JSON encoding into it before calling `on_event`. |
| `on_event` | `(ptr: i32, len: i32) -> i32` | The event handler. `ptr`/`len` describe the UTF-8 JSON event bytes the host wrote via `alloc`. Return `0` for success; any other value is recorded as a (non-trapping) error in the extension's metrics. |

The module must also export its linear memory as `memory` (the default
for `wasm32-unknown-unknown` `cdylib` builds — nothing special to do).

`dealloc` is not required; the host discards the instance (and its
memory) after each invocation, so guest-side memory is not reused across
events. Persistent extension state goes through `kv_set`/`kv_get`
instead (see below), not guest linear memory.

## Host imports (module `wardex_v1`)

All of these are the *only* imports a module may declare; any other
import (including anything from `wasi_snapshot_preview1` or any other
module namespace) is rejected at load time.

### `log(ptr: i32, len: i32)`

Logs a UTF-8 string (from the guest's memory, `ptr`/`len`) at `info`
level, tagged with the extension's name, via the host's `log` crate
target `wasm_extension`. Reads are clamped to 256 KiB regardless of the
`len` argument.

### `emit_alert(ptr: i32, len: i32) -> i32`

Reads a JSON object from the guest's memory (`ptr`/`len`) and, if it
parses, records it as a detection. Returns `0` on success, `-1` if the
bytes are not valid JSON for the expected shape, `-2` if the invocation
has already emitted `wasm_runtime.max_alerts_per_invocation` alerts, or
`-3` if accepting this payload would exceed
`wasm_runtime.max_alert_bytes_per_invocation` total bytes for the
invocation.

JSON shape:

```json
{
  "severity": "high",
  "title": "Suspicious child process of Office app",
  "mitre_technique": "T1059",
  "fields": { "process_name": "cmd.exe", "parent": "winword.exe" }
}
```

All fields except `fields` are optional strings; `fields` is an optional
free-form object merged into the alert for downstream consumers. `severity`
is not validated against a fixed enum by the ABI layer — callers of
`WasmExtensionManager::run_on_event` are expected to map it onto their own
severity scale.

### `kv_get(key_ptr: i32, key_len: i32, val_ptr: i32, val_max_len: i32) -> i32`

Looks up `key` (UTF-8 bytes at `key_ptr`/`key_len`) in this extension's
key/value store. On a hit, writes the value into the guest's memory at
`val_ptr` (if it fits within `val_max_len`) and returns its length. On a
miss, returns `-1`. If the value doesn't fit in `val_max_len`, returns
`-2` without writing anything. Returns `-3` on a memory-access failure.
Returns `-4` if `key` exceeds `wasm_runtime.max_kv_key_bytes`.

### `kv_set(key_ptr: i32, key_len: i32, val_ptr: i32, val_len: i32) -> i32`

Stores `value` (bytes at `val_ptr`/`val_len`) under `key`. Returns `0` on
success. Returns `-1` if the store is at `wasm_runtime.max_kv_entries`
and `key` is not already present (bounded state — no unbounded growth).
Returns `-2` if `value` exceeds `wasm_runtime.max_kv_value_bytes`. Returns
`-4` if `key` exceeds `wasm_runtime.max_kv_key_bytes` — only values were
size-capped before; an unbounded key is the same risk.

The key/value store is:
- **Scoped per extension.** Extension `a` can never read or overwrite
  extension `b`'s entries — each `WasmExtension` owns its own map.
- **Persistent across invocations of the same extension** for as long as
  the host process runs (it lives in the `WasmExtensionManager`, not in
  guest memory, which is discarded every invocation). It is *not*
  persisted to disk; a restart clears it. Extensions that need durable
  state should emit it as alert `fields` and let a downstream store
  persist it.

### `now_unix_ms() -> i64`

Returns the host's wall-clock time in milliseconds since the Unix epoch.
This is the only source of "current time" available to a guest — there is
no `clock_time_get` WASI import.

## Runtime choice: `wasmi` vs `wasmtime`

Wardex chose [`wasmi`][wasmi] (a pure-Rust WebAssembly *interpreter*, no
JIT) over `wasmtime` (a JIT compiler built on Cranelift) for this
extension point:

- **Threat model fit.** Extensions are, by construction, untrusted
  third-party code. `wasmtime` compiles guest bytecode to native
  instructions ahead of running it; a bug in the JIT's code generation is
  a route to executing attacker-influenced native code, a recurring CVE
  category for every mainstream JIT (V8, JavaScriptCore, Cranelift
  included). An interpreter has no such step: it only ever reads
  validated bytecode and dispatches through a fixed set of Rust match
  arms.
- **Determinism.** `wasmi`'s fuel metering charges a fixed cost per
  interpreted unit of work, independent of the host CPU's branch
  predictor, cache state, or JIT warm-up. The same module with the same
  fuel budget behaves identically run to run — useful for a detection
  extension whose behavior should be auditable and reproducible.
- **Attack surface and binary size.** `wasmtime` pulls in Cranelift, its
  own unwinding/signal-handling machinery for guarding against traps in
  JIT-compiled code, and platform-specific executable-memory management.
  `wasmi` is a much smaller dependency graph with a narrower job
  (interpret validated bytecode), which is easier to reason about
  alongside this crate's `#![forbid(unsafe_code)]` policy for its own
  code — the embedder API `wasmi` exposes to `src/wasm_runtime.rs`
  required no `unsafe` on our side.
- **Cost we accept.** Interpretation is slower per instruction than JIT
  execution. This extension point runs short, bounded snippets of
  detection logic once per event, not hot inner loops processing bulk
  data — the fuel-metered CPU budget (`fuel_limit`, `timeout_ms` as its
  documented calibration target) is deliberately small, so raw
  interpreter throughput is not the bottleneck it would be for, say, a
  general-purpose plugin runtime executing large user programs.

### License

`wasmi` and its `wasmi_core`/`wasmi_ir`/`wasmi_collections` crates are
Apache-2.0. The Bytecode Alliance crates it (and our `wat` dev-dependency)
pull in transitively — `wasmparser`, `wast`, `wasm-encoder` — are
Apache-2.0 WITH LLVM-exception. Both license identifiers were already
present in `deny.toml`'s `[licenses].allow` list before this change, so no
policy update was required; `cargo deny check` (when the tool is
available) covers this dependency subtree like any other.

## Legacy bytecode VM

`src/wasm_engine.rs` (`PolicyVm` / `Opcode` / `VirtualMachine`) is a small
stack-based bytecode interpreter that predates this module and was never
actually WebAssembly, despite the historical name association in this
codebase's docs. It remains in place, unchanged, for its one existing
caller (`POST /api/policy-vm/execute`) and is not deprecated by this
change, but new extension work should target the `wardex_v1` ABI in this
document instead. See the module-level doc comment on `wasm_engine` for
detail on what it does and does not provide (notably: it has no memory
model, no host callbacks, and nothing resembling WebAssembly bytecode).

## Configuration

`wasm_runtime` in `wardex.toml` (see `WasmRuntimeSettings` in
`src/wasm_runtime.rs` for exact field docs and defaults):

```toml
[wasm_runtime]
enabled = false
extensions_dir = "var/wasm_extensions"
fuel_limit = 5000000
max_memory_pages = 16
timeout_ms = 50
max_module_bytes = 2097152
max_kv_entries = 64
max_kv_value_bytes = 4096
max_kv_key_bytes = 256
max_table_elements = 4096
max_alerts_per_invocation = 32
max_alert_bytes_per_invocation = 1048576
require_signed_uploads = false
trusted_upload_signers = []
```

## Loading extensions

- **Directory load** (at server startup, and whenever `load_dir()` is
  called again): every `*.wasm` file in `extensions_dir` is loaded, named
  after its file stem. A file that fails validation is logged and
  skipped; it does not prevent the rest of the directory from loading.
- **API upload**: `POST /api/wasm-extensions/upload` with a JSON body
  `{"name", "wasm_base64", "sha256", "signature"?, "signer_pubkey"?}`.
  The host always checks the supplied `sha256` against the actual content
  hash (hash pinning). If `wasm_runtime.require_signed_uploads` is set,
  it additionally requires an Ed25519 `signature` over the raw module
  bytes from a `signer_pubkey` present in `trusted_upload_signers` — the
  same signing shape used for agent update artifacts in
  `src/auto_update.rs`, reused here rather than inventing a second
  pattern. Independently of `require_signed_uploads`, a `signature` that
  *is* supplied is always verified: an invalid signature, or one from a
  `signer_pubkey` not in `trusted_upload_signers`, is rejected even when
  signing is not mandatory. Only an upload with no `signature` field at
  all skips verification when `require_signed_uploads` is off.
- `GET /api/wasm-extensions` lists loaded extensions with their SHA-256
  and per-extension metrics (invocations, fuel used, traps, errors,
  alerts emitted).
- `DELETE /api/wasm-extensions/{name}` unloads an extension.
- `POST /api/wasm-extensions/run` runs every loaded extension against a
  supplied sample event (`{"event": {...}}`) and returns any alerts —
  useful for testing an extension without waiting for live traffic.

[wasmi]: https://github.com/wasmi-labs/wasmi
