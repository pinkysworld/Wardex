#![no_main]
use libfuzzer_sys::fuzz_target;
use wardex::yara_engine::YaraEngine;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // JSON rule loading must never panic on arbitrary input.
        let mut engine = YaraEngine::new();
        let _ = engine.load_rules_json(s);

        // The `.yar` compiler must also never panic — on a malformed or
        // adversarial rule file it should return a `CompileError`, never
        // crash or hang. If it does compile, run the resulting rules
        // against a couple of small buffers to also fuzz the matcher
        // (hex-token backtracking and regex evaluation in particular).
        let mut yar_engine = YaraEngine::new();
        if let Ok((_, _)) = yar_engine.load_rules_yar(s) {
            let _ = yar_engine.scan(data);
            let _ = yar_engine.scan(b"MZ\x00\x00PE\x00\x00 sample buffer for fuzzing UPX! eval($_POST");
        }
    }
});
