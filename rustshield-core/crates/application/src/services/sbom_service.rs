use rustshield_domain::{CycloneDxBom, Dependency};

pub struct SbomService;

impl SbomService {
    #[must_use]
    pub fn generate_cyclonedx(component_name: &str, dependencies: &[Dependency]) -> CycloneDxBom {
        CycloneDxBom::from_dependencies(component_name, dependencies)
    }

    #[must_use]
    pub fn generate_cyclonedx_json(component_name: &str, dependencies: &[Dependency]) -> String {
        let bom = Self::generate_cyclonedx(component_name, dependencies);
        serde_json::to_string_pretty(&bom).unwrap_or_default()
    }
}
