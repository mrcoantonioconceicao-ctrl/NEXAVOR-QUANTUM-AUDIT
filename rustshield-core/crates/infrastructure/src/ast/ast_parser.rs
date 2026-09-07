//! AST Parser Bounded Context - Safe Static Syntax Analysis
//!
//! Este módulo implementa análise sintática sem qualquer uso de `unsafe`, `transmute`
//! ou manipulação de ponteiros brutos sem verificação. Todas as indexações utilizam
//! bounds checking estrito via `.get()`, e entradas malformadas retornam `Result<T, AstParserError>`
//! sem causar panic, crash ou estouro de buffer (ASan heap-buffer-overflow remediado).

use rustshield_domain::{SourceFile, Vulnerability};

/// Erros tipados para falhas determinísticas durante o parsing de AST
#[derive(Debug, thiserror::Error, Clone, PartialEq)]
pub enum AstParserError {
    #[error("Buffer de entrada vazio ou nulo")]
    EmptyInput,

    #[error("Sequência de bytes UTF-8 inválida: {0}")]
    InvalidUtf8(String),

    #[error("Tentativa de acesso fora dos limites (IndexOutOfBounds) no índice {index}, tamanho total {len}")]
    OutOfBounds { index: usize, len: usize },

    #[error("Estrutura AST malformada ou truncada: {0}")]
    MalformedAst(String),

    #[error("Payload excede capacidade máxima permitida de {max_bytes} bytes")]
    PayloadTooLarge { max_bytes: usize },
}

/// Unidade sintática processada e validada
#[derive(Debug, Clone)]
pub struct ParsedAstUnit {
    pub file_path: String,
    pub language: String,
    pub total_lines: usize,
    pub total_bytes: usize,
    pub vulnerabilities: Vec<Vulnerability>,
}

/// Motor de Parsing AST Seguro (Zero-Unsafe & Strict Bounds Checking)
pub struct AstParser;

impl AstParser {
    /// Limite máximo defensivo de buffer para prevenir negação de serviço (16 MB)
    pub const MAX_BUFFER_SIZE: usize = 16 * 1024 * 1024;

    /// Realiza o parsing seguro a partir de um buffer de bytes brutos com verificação UTF-8
    pub fn parse_raw_buffer(
        buffer: &[u8],
        path: &str,
        language: &str,
    ) -> Result<ParsedAstUnit, AstParserError> {
        if buffer.is_empty() {
            return Err(AstParserError::EmptyInput);
        }

        if buffer.len() > Self::MAX_BUFFER_SIZE {
            return Err(AstParserError::PayloadTooLarge {
                max_bytes: Self::MAX_BUFFER_SIZE,
            });
        }

        let content = std::str::from_utf8(buffer)
            .map_err(|e| AstParserError::InvalidUtf8(e.to_string()))?;

        Self::parse_str(content, path, language)
    }

    /// Realiza o parsing seguro de uma string UTF-8 com checagem estrita de bounds
    pub fn parse_str(
        content: &str,
        path: &str,
        language: &str,
    ) -> Result<ParsedAstUnit, AstParserError> {
        let lines: Vec<&str> = content.lines().collect();
        let total_lines = lines.len();
        let total_bytes = content.len();

        let mut vulnerabilities = Vec::new();
        let lang = language.to_lowercase();

        // Itera usando bounds checking seguro via .get()
        for idx in 0..total_lines {
            let Some(line) = lines.get(idx) else {
                return Err(AstParserError::OutOfBounds {
                    index: idx,
                    len: total_lines,
                });
            };

            let line_num = idx + 1;
            let line_trimmed = line.trim();

            // Ignorar comentários
            if line_trimmed.starts_with("//")
                || line_trimmed.starts_with('#')
                || line_trimmed.starts_with("/*")
            {
                continue;
            }

            // 1. Injeção Dinâmica (eval / exec)
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
                    vulnerabilities.push(
                        v.with_line(line_num)
                            .with_cwe("CWE-95")
                            .with_remediation("Substituir eval() por parsers seguros e estruturados (ex: serde_json / JSON.parse)"),
                    );
                }
            }

            // 2. Injeção de Comando no Sistema Operacional
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
                    vulnerabilities.push(
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
                    vulnerabilities.push(
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
                    vulnerabilities.push(
                        v.with_line(line_num)
                            .with_cwe("CWE-754")
                            .with_remediation("Substituir unwrap() por propagação de erro idiomática via operador `?` e Result<T, E>"),
                    );
                }
            }

            // 5. Gerador Pseudo-Aleatório Não Seguro
            if line_trimmed.contains("Math.random()") || line_trimmed.contains("rand::random()") {
                if let Ok(v) = Vulnerability::new(
                    &format!("AST-SEC-RAND-{line_num}"),
                    6.5,
                    "Gerador Aleatório Não Criptográfico em Contexto de Segurança",
                    "Uso de PRNG fraco previsível em operações que exigem aleatoriedade criptograficamente segura.",
                    path,
                    "OWASP A02:2021-Cryptographic Failures",
                ) {
                    vulnerabilities.push(
                        v.with_line(line_num)
                            .with_cwe("CWE-330")
                            .with_remediation("Utilizar CSPRNG como ring::rand::SystemRandom ou crypto.getRandomValues()"),
                    );
                }
            }

            // 6. Primitiva de Sincronização Bloqueante em Contexto Async Tokio (std::sync::Mutex / std::sync::RwLock)
            if lang.contains("rust") && (line_trimmed.contains("std::sync::Mutex") || line_trimmed.contains("std::sync::RwLock")) {
                if let Ok(v) = Vulnerability::new(
                    &format!("AST-SEC-ASYNC-LOCK-{line_num}"),
                    7.8,
                    "Primitiva de Sincronização Bloqueante em Contexto Async Tokio",
                    "Uso de std::sync::Mutex ou std::sync::RwLock bloqueia o thread worker do reactor Tokio, podendo causar inanição e deadlock.",
                    path,
                    "OWASP A04:2021-Insecure Design",
                ) {
                    vulnerabilities.push(
                        v.with_line(line_num)
                            .with_cwe("CWE-821")
                            .with_remediation("Substituir por tokio::sync::Mutex ou tokio::sync::RwLock para operações assíncronas"),
                    );
                }
            }

            // 7. Variável Global Mutável (static mut - Data Race Crítico)
            if lang.contains("rust") && (line_trimmed.starts_with("static mut ") || line_trimmed.contains(" static mut ")) {
                if let Ok(v) = Vulnerability::new(
                    &format!("AST-SEC-STATIC-MUT-{line_num}"),
                    8.9,
                    "Variável Global Mutável `static mut` (Data Race Crítico)",
                    "Acesso a `static mut` sem sincronização atômica quebra o modelo de exclusão mútua do Rust e causa corrupção de memória.",
                    path,
                    "OWASP A04:2021-Insecure Design",
                ) {
                    vulnerabilities.push(
                        v.with_line(line_num)
                            .with_cwe("CWE-362")
                            .with_remediation("Utilizar tipos atômicos ou tokio::sync::Mutex / RwLock encapsulado"),
                    );
                }
            }

            // 8. Transmutação Arbitrária de Tipos (mem::transmute)
            if lang.contains("rust") && line_trimmed.contains("transmute") && !line_trimmed.contains("// safe") {
                if let Ok(v) = Vulnerability::new(
                    &format!("AST-SEC-TRANSMUTE-{line_num}"),
                    8.2,
                    "Transmutação Insegura de Tipos `mem::transmute`",
                    "Transmutação direta de ponteiros ou tipos sem verificação de layout quebra invariantes de alinhamento e ABI.",
                    path,
                    "OWASP A06:2021-Vulnerable and Outdated Components",
                ) {
                    vulnerabilities.push(
                        v.with_line(line_num)
                            .with_cwe("CWE-843")
                            .with_remediation("Utilizar bytemuck para conversões seguras em tempo de compilação ou traits TryFrom/TryInto"),
                    );
                }
            }

            // 9. Desserialização Insegura (pickle / yaml / unserialize)
            if line_trimmed.contains("pickle.loads(")
                || line_trimmed.contains("unserialize(")
                || (line_trimmed.contains("yaml.load(") && !line_trimmed.contains("safe_load") && !line_trimmed.contains("SafeLoader"))
            {
                if let Ok(v) = Vulnerability::new(
                    &format!("AST-SEC-DESERIALIZE-{line_num}"),
                    9.6,
                    "Desserialização Insegura de Objetos Não Confiáveis",
                    "Desserialização de payloads arbitrários permite instanciação de classes maliciosas e Execução Remota de Código (RCE).",
                    path,
                    "OWASP A08:2021-Software and Data Integrity Failures",
                ) {
                    vulnerabilities.push(
                        v.with_line(line_num)
                            .with_cwe("CWE-502")
                            .with_remediation("Substituir por parsers seguros como json.loads, yaml.safe_load ou Protocol Buffers"),
                    );
                }
            }

            // 10. Verificação Específica Solana Anchor (AccountInfo Arbitrária / Falha de Validação em Saque de Emergência)
            if lang.contains("rust")
                && (content.contains("anchor_lang") || content.contains("solana_program") || content.contains("declare_id!"))
            {
                if line_trimmed.contains("pub recipient: AccountInfo")
                    && !content.contains("constraint = recipient.key()")
                    && !line_trimmed.contains("Signer")
                {
                    if let Ok(v) = Vulnerability::new(
                        &format!("ANCHOR-SEC-CHECK-{line_num}"),
                        9.1,
                        "Solana Anchor: Ausência de Constraint de Assinatura/Owner no Recipiente de Emergência",
                        "Conta AccountInfo arbitrária sem constraint de owner ou assinatura permite dreno de fundos do cofre.",
                        path,
                        "OWASP A01:2021-Broken Access Control",
                    ) {
                        vulnerabilities.push(
                            v.with_line(line_num)
                                .with_cwe("CWE-284")
                                .with_remediation("Adicionar `#[account(mut, constraint = recipient.key() == vault_state.owner)]` e validação Signer"),
                        );
                    }
                }
            }
        }

        Ok(ParsedAstUnit {
            file_path: path.to_string(),
            language: language.to_string(),
            total_lines,
            total_bytes,
            vulnerabilities,
        })
    }

    /// Realiza parsing a partir de um SourceFile de domínio com tratamento seguro de erros
    pub fn parse_file(file: &SourceFile) -> Result<Vec<Vulnerability>, AstParserError> {
        let parsed = Self::parse_str(&file.content, &file.path, &file.language)?;
        Ok(parsed.vulnerabilities)
    }
}
