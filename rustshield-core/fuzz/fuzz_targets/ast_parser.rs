#![no_main]
use libfuzzer_sys::fuzz_target;
use rustshield_domain::SourceFile;
use rustshield_infrastructure::NativeAstEngine;

fuzz_target!(|data: &[u8]| {
    // 1. Fuzzing direto com bytes arbitrários e potenciais sequências inválidas UTF-8
    if let Ok(code_str) = std::str::from_utf8(data) {
        let languages = ["rust", "python", "javascript", "typescript", "cpp", "go", "unknown"];
        
        for lang in languages {
            if let Ok(source_file) = SourceFile::new("fuzz_target_input.src", code_str, lang) {
                // Executa análise estática AST garantindo ausência de pânicos, loops infinitos ou out-of-bounds
                let vulnerabilities = NativeAstEngine::scan_source_file(&source_file);
                
                // Valida que nenhuma vulnerabilidade gerada contém ponteiros nulos ou estados inválidos
                for vuln in &vulnerabilities {
                    assert!(!vuln.id.is_empty(), "O ID da vulnerabilidade não pode ser vazio");
                    assert!(vuln.cvss_score >= 0.0 && vuln.cvss_score <= 10.0, "Score CVSS fora dos limites [0.0, 10.0]");
                }
            }
        }
    }
});
