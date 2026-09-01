use serde::{Deserialize, Serialize};
use crate::dependency::Dependency;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SbomMetadata {
    pub timestamp: String,
    pub tool_name: String,
    pub tool_version: String,
    pub authors: Vec<String>,
    pub component_name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CycloneDxComponent {
    #[serde(rename = "type")]
    pub component_type: String,
    pub name: String,
    pub version: String,
    pub purl: String,
    pub licenses: Vec<String>,
    pub hashes: Vec<SbomHash>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SbomHash {
    pub alg: String,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CycloneDxBom {
    #[serde(rename = "bomFormat")]
    pub bom_format: String,
    #[serde(rename = "specVersion")]
    pub spec_version: String,
    #[serde(rename = "serialNumber")]
    pub serial_number: String,
    pub version: u32,
    pub metadata: SbomMetadata,
    pub components: Vec<CycloneDxComponent>,
}

impl CycloneDxBom {
    pub fn from_dependencies(component_name: &str, deps: &[Dependency]) -> Self {
        let components = deps
            .iter()
            .map(|d| CycloneDxComponent {
                component_type: "library".to_string(),
                name: d.name.clone(),
                version: d.version.clone(),
                purl: d.purl.clone(),
                licenses: d.license.clone().into_iter().collect(),
                hashes: vec![SbomHash {
                    alg: "SHA-256".to_string(),
                    content: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
                }],
            })
            .collect();

        Self {
            bom_format: "CycloneDX".to_string(),
            spec_version: "1.5".to_string(),
            serial_number: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
            version: 1,
            metadata: SbomMetadata {
                timestamp: chrono::Utc::now().to_rfc3339(),
                tool_name: "RustShield Secure Core".to_string(),
                tool_version: "2.0.0".to_string(),
                authors: vec!["RustShield DevSecOps Team".to_string()],
                component_name: component_name.to_string(),
            },
            components,
        }
    }
}
