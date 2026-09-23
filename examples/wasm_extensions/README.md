# Example Wardex WebAssembly extensions

Two runnable examples of the `wardex_v1` host ABI (see
`../../docs/WASM_ABI.md` and `../../docs/WASM_TUTORIAL.md`):

- `auth_spike.wat` — WebAssembly Text format, no toolchain beyond
  `wat2wasm` (from [WABT](https://github.com/WebAssembly/wabt)) needed.
  Demonstrates `kv_get`/`kv_set` (bounded, per-extension state) and
  `emit_alert`.
- `rust-guest/` — a standalone Rust crate (**not** part of the main
  Wardex crate/build) targeting `wasm32-unknown-unknown`. Demonstrates
  `log` and `emit_alert`, and inspecting the event JSON the host writes
  into the guest's memory.

Neither is built by `cargo build`/`cargo test` at the repository root;
build them separately as shown below, then drop the resulting `.wasm`
file into your Wardex instance's `wasm_runtime.extensions_dir` (or
upload it via `POST /api/wasm-extensions/upload`).

```sh
# WAT example
wat2wasm auth_spike.wat -o auth_spike.wasm

# Rust example
cd rust-guest
cargo build --target wasm32-unknown-unknown --release
# output: target/wasm32-unknown-unknown/release/wardex_example_extension.wasm
```
