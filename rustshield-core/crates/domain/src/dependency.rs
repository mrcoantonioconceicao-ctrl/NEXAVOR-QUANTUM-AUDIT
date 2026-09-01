use serde::{Deserialize, Serialize};
use crate::error::DomainError;
use crate::vulnerability::Vulnerability;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Cargo,
    Npm,
    Pip,
    GoMod,
    Maven,
    Other(String),
}

impl Ecosystem {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "cargo" | "crates.io" => Self::Cargo,
            "npm" | "pnpm" | "yarn" => Self::Npm,
            "pip" | "pypi" => Self::Pip,
            "gomod" | "go" => Self::GoMod,
            "maven" => Self::Maven,
            other => Self::Other(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Cargo => "cargo",
            Self::Npm => "npm",
            Self::Pip => "pip",
            Self::GoMod => "gomod",
            Self::Maven => "maven",
            Self::Other(s) => s.as_str(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub ecosystem: Ecosystem,
    pub license: Option<String>,
    pub direct: bool,
    pub purl: String,
    pub vulnerabilities: Vec<Vulnerability>,
}

impl Dependency {
    pub fn new(name: &str, version: &str, ecosystem: Ecosystem) -> Result<Self, DomainError> {
        let trimmed_name = name.trim();
        let trimmed_ver = version.trim();

        if trimmed_name.is_empty() {
            return Err(DomainError::InconsistentState("Nome da dependência não pode ser vazio".to_string()));
        }
        if trimmed_ver.is_empty() {
            return Err(DomainError::InvalidSemanticVersion("Versão da dependência não pode ser vazia".to_string()));
        }

        let purl = format!("pkg:{}/{}@{}", ecosystem.as_str(), trimmed_name, trimmed_ver);

        Ok(Self {
            name: trimmed_name.to_string(),
            version: trimmed_ver.to_string(),
            ecosystem,
            license: None,
            direct: true,
            purl,
            vulnerabilities: Vec::new(),
        })
    }

    pub fn with_license(mut self, license: &str) -> Self {
        self.license = Some(license.trim().to_string());
        self
    }

    pub fn add_vulnerability(&mut self, vuln: Vulnerability) {
        self.vulnerabilities.push(vuln);
    }
}
