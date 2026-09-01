use rustshield_domain::{SourceFile, Vulnerability};

pub struct NativeAstEngine;

impl NativeAstEngine {
    /// Executa análise sintática estática em um arquivo de código-fonte
    pub fn scan_source_file(file: &SourceFile) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        let content = &file.content;
        let path = &file.path;
        let lang = file.language.to_lowercase();

        let lines: Vec<&str> = content.lines().collect();

        for (idx, line) in lines.iter().enumerate() {
            let line_num = idx + 1;
            let line_trimmed = line.trim();

            // Ignorar comentários
            if line_trimmed.starts_with("//") || line_trimmed.starts_with('#') || line_trimmed.starts_with("/*") {
                continue;
            }

            // 1. Detecção de Injeção e Execução Dinâmica de Código (OWASP A03 / NIST SP 800-218)
            if (lang.contains("python") || lang.contains("javascript") || lang.contains("typescript"))
                && (line_trimmed.contains("eval(") || line_trimmed.contains("exec("))
            {
                if let Ok(v) = Vulnerability::new(
                    &format!("AST-SEC-A03-{line_num}"),
                    9.4,
                    "Execução Dinâmica de Código Insegura (eval / exec)",
                    "Uso de eval() ou exec() permite injeção arbitrária de código remoto (RCE) e quebra de sandbox.",
                    path,
                    "OWASP A03:2021-Injection",
                ) {
                    vulns.push(
                        v.with_line(line_num)
                            .with_cwe("CWE-95")
                            .with_remediation("Substituir eval() por parsers seguros e estruturados (ex: serde_json / JSON.parse)"),
                    );
                }
            }

            // 2. Detecção de Comandos de Sistema Inseguros (Command Injection)
            if (line_trimmed.contains("os.system(") || line_trimmed.contains("child_process.exec("))
                && !line_trimmed.contains("execFile")
            {
                if let Ok(v) = Vulnerability::new(
                    &format!("AST-SEC-CMD-{line_num}"),
                    8.8,
                    "Potencial Injeção de Comando no Sistema Operacional",
                    "Execução direta de shell string sem sanitização de argumentos e sem array defensivo.",
                    path,
                    "OWASP A03:2021-Injection",
                ) {
                    vulns.push(
                        v.with_line(line_num)
                            .with_cwe("CWE-78")
                            .with_remediation("Utilizar subprocess.run([arg1, arg2]) ou Command::new com argumentos isolados"),
                    );
                }
            }

            // 3. Detecção de Blocos Unsafe e Corrupção de Memória (Rust / C++)
            if lang.contains("rust") && line_trimmed.contains("unsafe {") {
                if let Ok(v) = Vulnerability::new(
                    &format!("AST-SEC-MEM-{line_num}"),
                    7.2,
                    "Bloco `unsafe` Não Auditado sem Comentário // SAFETY:",
                    "Blocos inseguros contornam as garantias de Memory Safety do compilador do Rust.",
                    path,
                    "OWASP A06:2021-Vulnerable and Outdated Components",
                ) {
                    vulns.push(
                        v.with_line(line_num)
                            .with_cwe("CWE-119")
                            .with_remediation("Encapsular em abstrações RAII seguras e documentar invariantes com // SAFETY:"),
                    );
                }
            }

            // 4. Detecção de Pânicos e Unwrap Inseguro em Produção (Rust)
            if lang.contains("rust") && (line_trimmed.contains(".unwrap()") || line_trimmed.contains("panic!(")) {
                if let Ok(v) = Vulnerability::new(
                    &format!("AST-SEC-PANIC-{line_num}"),
                    5.3,
                    "Chamada Insegura a .unwrap() / panic! em Caminho Crítico",
                    "Pânico explícito causa negação de serviço (DoS) por encerramento abrupto do processo de thread.",
                    path,
                    "OWASP A04:2021-Insecure Design",
                ) {
                    vulns.push(
                        v.with_line(line_num)
                            .with_cwe("CWE-754")
                            .with_remediation("Substituir unwrap() por propagação de erro idiomática via operador `?` e Result<T, E>"),
                    );
                }
            }

            // 5. Detecção de Geradores de Números Pseudo-Aleatórios Inseguros (Cryptographic Weakness)
            if line_trimmed.contains("Math.random()") || line_trimmed.contains("rand::random()") {
                if let Ok(v) = Vulnerability::new(
                    &format!("AST-SEC-RAND-{line_num}"),
                    6.5,
                    "Gerador Aleatório Não Criptográfico em Contexto de Segurança",
                    "Uso de PRNG fraco previsível em operações que exigem aleatoriedade criptograficamente segura.",
                    path,
                    "OWASP A02:2021-Cryptographic Failures",
                ) {
                    vulns.push(
                        v.with_line(line_num)
                            .with_cwe("CWE-330")
                            .with_remediation("Utilizar CSPRNG como ring::rand::SystemRandom ou crypto.getRandomValues()"),
                    );
                }
            }
        }

        vulns
    }
}
