#![no_main]
use libfuzzer_sys::fuzz_target;
use rustshield_domain::SourceFile;
use rustshield_infrastructure::{ast::AstParser, NativeAstEngine};

fuzz_target!(|data: &[u8]| {
    // 1. Fuzzing direto com buffer bruto, verificando ausência de crashes ou out-of-bounds
    let _ = AstParser::parse_raw_buffer(data, "fuzz_raw_input.rs", "rust");

    // 2. Fuzzing em linguagens suportadas com tratamento de erro Result<T, E>
    if let Ok(code_str) = std::str::from_utf8(data) {
        let languages = ["rust", "python", "javascript", "typescript", "cpp", "go", "unknown"];
        
        for lang in languages {
            if let Ok(source_file) = SourceFile::new("fuzz_target_input.src", code_str, lang) {
                // Executa análise estática AST segura
                if let Ok(vulnerabilities) = NativeAstEngine::scan_source_file_safe(&source_file) {
                    for vuln in &vulnerabilities {
                        assert!(!vuln.id.is_empty(), "O ID da vulnerabilidade não pode ser vazio");
                        assert!(vuln.cvss_score >= 0.0 && vuln.cvss_score <= 10.0, "Score CVSS fora dos limites [0.0, 10.0]");
                    }
                }
            }
        }
    }
});
