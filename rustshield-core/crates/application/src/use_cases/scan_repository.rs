use anyhow::Result;
use rustshield_domain::{AuditReport, Dependency, Repository, SourceFile};
use crate::services::auditor_service::AuditorService;

pub struct ScanRepositoryUseCase {
    auditor_service: AuditorService,
}

impl Default for ScanRepositoryUseCase {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanRepositoryUseCase {
    #[must_use]
    pub fn new() -> Self {
        Self {
            auditor_service: AuditorService::new(),
        }
    }

    pub async fn execute(
        &self,
        repo: Repository,
        files: Vec<SourceFile>,
        deps: Vec<Dependency>,
    ) -> Result<AuditReport> {
        self.auditor_service.audit_repository(repo, files, deps).await
    }
}
