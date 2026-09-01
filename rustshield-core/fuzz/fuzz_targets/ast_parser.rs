#![no_main]
use libfuzzer_sys::fuzz_target;
use rustshield_domain::SourceFile;
use rustshield_infrastructure::NativeAstEngine;

fuzz_target!(|data: &[u8]| {
    if let Ok(code_str) = std::str::from_utf8(data) {
        if let Ok(source_file) = SourceFile::new("fuzz_target.rs", code_str, "rust") {
            // Garante que o parser nativo é resistente a buffer overflows e pânicos
            let _ = NativeAstEngine::scan_source_file(&source_file);
        }
    }
});
