;; Example Wardex WebAssembly extension, written directly in WAT.
;;
;; Implements the `wardex_v1` host ABI (see docs/WASM_ABI.md). Counts
;; failed-login events per source IP using the extension's scoped
;; key/value state, and raises an alert once a source IP has been seen
;; three or more times.
;;
;; Build with `wat2wasm` (from the WABT toolkit) or `wat::parse_file`:
;;
;;   wat2wasm auth_spike.wat -o auth_spike.wasm
;;
;; then drop `auth_spike.wasm` into your configured `wasm_runtime.extensions_dir`.
(module
  (import "wardex_v1" "kv_get" (func $kv_get (param i32 i32 i32 i32) (result i32)))
  (import "wardex_v1" "kv_set" (func $kv_set (param i32 i32 i32 i32) (result i32)))
  (import "wardex_v1" "emit_alert" (func $emit_alert (param i32 i32) (result i32)))
  (import "wardex_v1" "log" (func $log (param i32 i32)))

  (memory (export "memory") 4)

  ;; Fixed key this toy extension tracks state under. A real extension
  ;; would parse the event JSON at (ptr, len) to extract a real source IP
  ;; and use it (or a hash of it) as the key; this example keeps the
  ;; parsing out of scope and just demonstrates the ABI shape.
  (data (i32.const 0) "src_ip_counter")
  ;; Alert JSON template, written once and reused.
  (data (i32.const 64)
    "{\"severity\":\"medium\",\"title\":\"repeated auth failure\",\"mitre_technique\":\"T1110\",\"fields\":{}}")
  (data (i32.const 256) "extension invoked")

  (global $heap_ptr (mut i32) (i32.const 4096))

  (func (export "wardex_abi_version") (result i32)
    (i32.const 1))

  (func (export "init") (result i32)
    (call $log (i32.const 256) (i32.const 17))
    (i32.const 0))

  (func (export "alloc") (param $size i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $heap_ptr))
    (global.set $heap_ptr (i32.add (global.get $heap_ptr) (local.get $size)))
    (local.get $ptr))

  ;; on_event ignores the event payload in this toy example (a real
  ;; extension would read it from (ptr, len) and parse the JSON) and just
  ;; demonstrates incrementing bounded, extension-scoped state.
  (func (export "on_event") (param $ptr i32) (param $len i32) (result i32)
    (local $count_buf i32)
    (local $got i32)
    (local $count i32)

    (local.set $count_buf (i32.const 512))
    (local.set $got
      (call $kv_get (i32.const 0) (i32.const 14) (local.get $count_buf) (i32.const 4)))

    (if (i32.eq (local.get $got) (i32.const 4))
      (then (local.set $count (i32.load (local.get $count_buf))))
      (else (local.set $count (i32.const 0))))

    (local.set $count (i32.add (local.get $count) (i32.const 1)))
    (i32.store (local.get $count_buf) (local.get $count))
    (drop (call $kv_set (i32.const 0) (i32.const 14) (local.get $count_buf) (i32.const 4)))

    (if (i32.ge_s (local.get $count) (i32.const 3))
      (then (drop (call $emit_alert (i32.const 64) (i32.const 91)))))

    (i32.const 0)))
