# WASM Extension Tutorial

Build detection logic as sandboxed, real WebAssembly modules that run
inside the Wardex runtime, using the `wardex_v1` host ABI. The full ABI
contract lives in [`docs/WASM_ABI.md`](WASM_ABI.md) — this document is a
walkthrough of building, loading, and testing an extension.

Wardex executes extensions with [`wasmi`][wasmi], a pure-Rust WebAssembly
*interpreter* (no JIT). See `docs/WASM_ABI.md` for why, and for the
sandbox limits (fuel, memory, module size) that apply to every extension.

> **Prerequisites:** a running Wardex instance with `wasm_runtime.enabled
> = true` in `wardex.toml`. To build the Rust example below you also need
> the `wasm32-unknown-unknown` Rust target (`rustup target add
> wasm32-unknown-unknown`). If you only want to try the WAT example, you
> need `wat2wasm` from the [WABT toolkit][wabt] (or `wasm-tools`).

---

## 1. Enable the runtime

```toml
# wardex.toml
[wasm_runtime]
enabled = true
extensions_dir = "var/wasm_extensions"
fuel_limit = 5000000
max_memory_pages = 16
max_module_bytes = 2097152
max_kv_entries = 64
max_kv_value_bytes = 4096
```

See `WasmRuntimeSettings` in `src/wasm_runtime.rs` for every field and its
default.

## 2. The fastest path: a WAT extension

WebAssembly Text format (`.wat`) needs no Rust toolchain at all. A
complete, runnable example lives at
[`examples/wasm_extensions/auth_spike.wat`](../examples/wasm_extensions/auth_spike.wat):
it tracks a counter in the extension's key/value state and raises a
`T1110` (brute force) alert once the counter passes 3.

```bash
wat2wasm examples/wasm_extensions/auth_spike.wat -o auth_spike.wasm
mkdir -p var/wasm_extensions
cp auth_spike.wasm var/wasm_extensions/
wardex reload   # or restart the server; it scans extensions_dir at startup
```

Every extension must implement four exports and may import up to five
host functions — see [`docs/WASM_ABI.md`](WASM_ABI.md) for the exact
signatures. The short version:

| You export | You get to call |
|---|---|
| `wardex_abi_version() -> i32` (must return `1`) | `log(ptr, len)` |
| `init() -> i32` | `emit_alert(ptr, len) -> i32` |
| `alloc(size: i32) -> i32` | `kv_get(key_ptr, key_len, val_ptr, val_max_len) -> i32` |
| `on_event(ptr: i32, len: i32) -> i32` | `kv_set(key_ptr, key_len, val_ptr, val_len) -> i32` |
| | `now_unix_ms() -> i64` |

`on_event`'s `ptr`/`len` point at the current event, JSON-encoded, that
the host wrote into your module's own memory (via your `alloc` export) —
you never need to import anything to *read* the event, only to act on it.

## 3. The Rust path

A complete Cargo project is at
[`examples/wasm_extensions/rust-guest/`](../examples/wasm_extensions/rust-guest/).
It is **not** part of Wardex's own crate or build — it's a standalone
project you copy out and build independently:

```bash
cd examples/wasm_extensions/rust-guest
cargo build --target wasm32-unknown-unknown --release
cp target/wasm32-unknown-unknown/release/wardex_example_extension.wasm \
   /path/to/wardex/var/wasm_extensions/office_child_process.wasm
```

The guest crate's `src/lib.rs` implements the same four exports by hand
(no `std`, a tiny bump allocator, and manual `extern "C"` host imports) —
read it alongside `docs/WASM_ABI.md` for the exact contract each export
and import needs to honor. The example inspects the event's
`process_name` and `parent_process_name` fields (Wardex's event JSON) and
raises an alert when an Office application spawns a shell.

## 4. Verify it loaded and test it

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:3000/api/wasm-extensions | jq .
```

```json
{
  "enabled": true,
  "extensions_dir": "var/wasm_extensions",
  "extensions": [
    {
      "name": "auth_spike",
      "sha256": "…",
      "metrics": {
        "invocations": 0,
        "fuel_used_total": 0,
        "traps": 0,
        "errors": 0,
        "alerts_emitted": 0,
        "last_error": null,
        "last_invocation_ms": null
      }
    }
  ]
}
```

Run every loaded extension against a synthetic event without waiting for
live traffic:

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -d '{"event": {"process_name": "cmd.exe", "parent_process_name": "winword.exe"}}' \
  http://localhost:3000/api/wasm-extensions/run | jq .
```

`wardex doctor` also reports whether the runtime is enabled and how many
`.wasm` modules are present in `extensions_dir`.

## 5. Upload via the API instead of the filesystem

```bash
WASM_B64=$(base64 -w0 auth_spike.wasm)
SHA256=$(sha256sum auth_spike.wasm | cut -d' ' -f1)
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"name\":\"auth_spike\",\"wasm_base64\":\"$WASM_B64\",\"sha256\":\"$SHA256\"}" \
  http://localhost:3000/api/wasm-extensions/upload
```

If `wasm_runtime.require_signed_uploads = true`, also supply `signature`
(base64 Ed25519 signature over the raw module bytes) and `signer_pubkey`
(base64 public key), with `signer_pubkey` present in
`wasm_runtime.trusted_upload_signers`. This mirrors the signing pattern
used for agent update artifacts (`src/auto_update.rs`).

Remove an extension:

```bash
curl -s -X DELETE -H "Authorization: Bearer $TOKEN" \
  http://localhost:3000/api/wasm-extensions/auth_spike
```

## Resource limits

| Resource | Config key | Default |
|---|---|---|
| CPU (fuel, enforces the wall-clock budget) | `wasm_runtime.fuel_limit` | 5,000,000 per invocation |
| Memory | `wasm_runtime.max_memory_pages` | 16 pages (1 MiB) |
| Module size | `wasm_runtime.max_module_bytes` | 2 MiB |
| Extension state entries | `wasm_runtime.max_kv_entries` | 64 |
| Extension state entry size | `wasm_runtime.max_kv_value_bytes` | 4 KiB |

Exceeding fuel or the memory cap raises a trap; the extension's
`traps` metric increments and the event pipeline continues unaffected —
one extension's failure never blocks another extension or the rest of
the pipeline.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Extension rejected at load with "forbidden import" | Module imports something other than the five `wardex_v1` functions (commonly WASI) | Remove the import; extensions have no filesystem/network access by design |
| Extension rejected at load with "missing required export" | One of `wardex_abi_version`/`init`/`alloc`/`on_event` is missing | Add the missing export — see `docs/WASM_ABI.md` |
| `errors` metric increases, `last_error` says "ABI version mismatch" | `wardex_abi_version()` returns something other than `1` | Return `1` (the only version the host currently supports) |
| `traps` metric increases, `last_error` mentions fuel | The extension is doing too much work per event, or looping | Raise `wasm_runtime.fuel_limit`, or optimize the extension |
| `traps` metric increases, no fuel mention | Memory grow past `max_memory_pages`, or an out-of-bounds access | Raise `max_memory_pages`, or check the extension's memory arithmetic |
| Alerts never appear | `emit_alert`'s JSON doesn't parse, or the extension never calls it | Check the JSON shape in `docs/WASM_ABI.md`; use `log` to debug |

[wasmi]: https://github.com/wasmi-labs/wasmi
[wabt]: https://github.com/WebAssembly/wabt
