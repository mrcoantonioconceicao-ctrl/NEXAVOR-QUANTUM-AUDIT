use rustshield_domain::{SourceFile, Vulnerability};
use crate::ast::ast_parser::{AstParser, AstParserError, ParsedAstUnit};

pub struct NativeAstEngine;

impl NativeAstEngine {
    /// Executa análise sintática estática segura em um arquivo de código-fonte, retornando Result<T, E>
    pub fn scan_source_file_safe(file: &SourceFile) -> Result<Vec<Vulnerability>, AstParserError> {
        AstParser::parse_file(file)
    }

    /// Executa análise sintática a partir de buffer de bytes com bounds-checking estrito
    pub fn parse_raw_buffer(
        buffer: &[u8],
        path: &str,
        language: &str,
    ) -> Result<ParsedAstUnit, AstParserError> {
        AstParser::parse_raw_buffer(buffer, path, language)
    }

    /// Wrapper determinístico compatível com a interface original, garantindo ausência de pânicos
    pub fn scan_source_file(file: &SourceFile) -> Vec<Vulnerability> {
        Self::scan_source_file_safe(file).unwrap_or_default()
    }
}
