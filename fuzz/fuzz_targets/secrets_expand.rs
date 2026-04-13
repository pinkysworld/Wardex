#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let resolver = wardex::secrets::SecretsResolver::new(wardex::secrets::SecretsConfig::default());
        let _ = resolver.expand_string(s);
    }
});
