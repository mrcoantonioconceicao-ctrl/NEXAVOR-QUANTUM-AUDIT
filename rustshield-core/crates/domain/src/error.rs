use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum DomainError {
    #[error("Identificador de vulnerabilidade inválido: '{0}'. Deve iniciar com prefixos padrão como 'CVE-', 'GHSA-' ou 'RUSTSEC-'.")]
    InvalidVulnerabilityId(String),

    #[error("Score CVSS fora do intervalo válido (0.0 a 10.0): {0}")]
    InvalidCvssScore(String),

    #[error("Caminho de arquivo inválido ou inseguro (tentativa de path traversal): '{0}'")]
    InsecureFilePath(String),

    #[error("Nome de repositório inválido: '{0}'")]
    InvalidRepositoryName(String),

    #[error("Versão semântica de dependência inválida: '{0}'")]
    InvalidSemanticVersion(String),

    #[error("Erro de validação de integridade criptográfica: {0}")]
    IntegrityValidationFailed(String),

    #[error("Entidade de domínio em estado inconsistente: {0}")]
    InconsistentState(String),
}
