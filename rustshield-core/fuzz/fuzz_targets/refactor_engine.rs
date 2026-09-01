#![no_main]
use libfuzzer_sys::fuzz_target;
use rustshield_application::{RefactorEngine, RefactorTargetMode};
use rustshield_domain::SourceFile;
use rustshield_infrastructure::NativeAstEngine;

fuzz_target!(|data: &[u8]| {
    if let Ok(code_str) = std::str::from_utf8(data) {
        let modes = [
            RefactorTargetMode::InPlace,
            RefactorTargetMode::Rust,
            RefactorTargetMode::Go,
        ];

        for mode in modes {
            if let Ok(source_file) = SourceFile::new("fuzz_refactor.rs", code_str, "rust") {
                let vulns = NativeAstEngine::scan_source_file(&source_file);
                let result = RefactorEngine::refactor(&source_file, mode, &vulns);
                
                // Validações de integridade do resultado da refatoração
                assert!(!result.refactored_code.is_empty() || code_str.is_empty());
                assert!(result.remediation_score_delta >= 0.0);
            }
        }
    }
});
