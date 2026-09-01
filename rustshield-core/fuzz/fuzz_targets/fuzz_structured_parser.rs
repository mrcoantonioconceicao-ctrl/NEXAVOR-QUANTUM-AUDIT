#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rustshield_domain::SourceFile;
use rustshield_infrastructure::NativeAstEngine;

#[derive(Arbitrary, Debug)]
pub struct FuzzCodeInput {
    pub file_path: String,
    pub language: String,
    pub raw_snippet: String,
    pub is_binary_payload: bool,
}

fuzz_target!(|input: FuzzCodeInput| {
    // Validação estruturada gerada pelo arbitrary
    if let Ok(source_file) = SourceFile::new(
        if input.file_path.is_empty() { "default.rs" } else { &input.file_path },
        &input.raw_snippet,
        if input.language.is_empty() { "rust" } else { &input.language },
    ) {
        let vulnerabilities = NativeAstEngine::scan_source_file(&source_file);
        for vuln in &vulnerabilities {
            assert!(!vuln.id.is_empty());
            assert!(vuln.cvss_score >= 0.0 && vuln.cvss_score <= 10.0);
        }
    }
});
