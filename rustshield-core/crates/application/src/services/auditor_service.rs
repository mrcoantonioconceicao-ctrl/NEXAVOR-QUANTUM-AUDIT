use anyhow::Result;
use rustshield_domain::{AuditReport, Dependency, FairRiskEvaluation, Repository, SourceFile, Vulnerability};
use rustshield_infrastructure::{NativeAstEngine, OsvClient, TamperProofLedger};

pub struct AuditorService {
    osv_client: OsvClient,
}

impl Default for AuditorService {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditorService {
    #[must_use]
    pub fn new() -> Self {
        Self {
            osv_client: OsvClient::new(),
        }
    }

    /// Executa a auditoria completa de segurança em um repositório e arquivos-fonte
    pub async fn audit_repository(
        &self,
        repository: Repository,
        files: Vec<SourceFile>,
        dependencies: Vec<Dependency>,
    ) -> Result<AuditReport> {
        let start_time = std::time::Instant::now();
        let mut all_vulnerabilities: Vec<Vulnerability> = Vec::new();

        let mut total_lines = 0;
        for file in &files {
            total_lines += file.content.lines().count();
            let mut ast_vulns = NativeAstEngine::scan_source_file(file);
            all_vulnerabilities.append(&mut ast_vulns);
        }

        // Consulta assíncrona ao OSV.dev para dependências
        if !dependencies.is_empty() {
            match self.osv_client.query_batch_vulnerabilities(&dependencies).await {
                Ok(mut dep_vulns) => all_vulnerabilities.append(&mut dep_vulns),
                Err(e) => tracing::warn!("Falha ao consultar OSV.dev: {e}"),
            }
        }

        let score = AuditReport::calculate_score(&all_vulnerabilities);
        let fair_risk = FairRiskEvaluation::calculate(
            500_000.0,
            25.0,
            (all_vulnerabilities.len() as f64) * 0.1,
            15_000.0,
            88.0,
        );

        let report_id = format!("AUDIT-{}", uuid::Uuid::new_v4());
        let timestamp = chrono::Utc::now().to_rfc3339();

        let report_payload = format!(
            "{}:{}:{}:{}",
            report_id, repository.name, score, all_vulnerabilities.len()
        );
        let tamper_proof_hash = TamperProofLedger::compute_sha256(report_payload.as_bytes());

        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        Ok(AuditReport {
            id: report_id,
            timestamp,
            repository,
            score,
            vulnerabilities: all_vulnerabilities,
            dependencies,
            fair_risk,
            total_files_scanned: files.len(),
            total_lines_scanned: total_lines,
            execution_time_ms,
            tamper_proof_hash,
            previous_hash: None,
        })
    }
}
