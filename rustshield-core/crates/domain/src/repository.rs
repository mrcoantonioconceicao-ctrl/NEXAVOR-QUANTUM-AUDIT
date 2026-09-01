use serde::{Deserialize, Serialize};
use crate::error::DomainError;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceFile {
    pub path: String,
    pub content: String,
    pub language: String,
    pub size_bytes: usize,
    pub sha256_hash: String,
}

impl SourceFile {
    pub fn new(path: &str, content: &str, lang: &str) -> Result<Self, DomainError> {
        let clean_path = path.trim().replace('\\', "/");
        if clean_path.contains("..") || clean_path.starts_with('/') {
            return Err(DomainError::InsecureFilePath(clean_path));
        }

        Ok(Self {
            path: clean_path,
            content: content.to_string(),
            language: lang.trim().to_string(),
            size_bytes: content.len(),
            sha256_hash: String::new(), // Will be populated in infra
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Repository {
    pub name: String,
    pub url: String,
    pub branch: String,
    pub default_branch: String,
    pub language: String,
    pub total_files: usize,
    pub total_lines: usize,
    pub commit_sha: String,
}

impl Repository {
    pub fn new(name: &str, url: &str, branch: &str, primary_lang: &str) -> Result<Self, DomainError> {
        if name.trim().is_empty() {
            return Err(DomainError::InvalidRepositoryName("Nome do repositório não pode ser vazio".to_string()));
        }

        Ok(Self {
            name: name.trim().to_string(),
            url: url.trim().to_string(),
            branch: branch.trim().to_string(),
            default_branch: branch.trim().to_string(),
            language: primary_lang.trim().to_string(),
            total_files: 0,
            total_lines: 0,
            commit_sha: "HEAD".to_string(),
        })
    }
}
