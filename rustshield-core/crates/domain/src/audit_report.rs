use serde::{Deserialize, Serialize};
use crate::dependency::Dependency;
use crate::repository::Repository;
use crate::risk_score::FairRiskEvaluation;
use crate::vulnerability::Vulnerability;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditReport {
    pub id: String,
    pub timestamp: String,
    pub repository: Repository,
    pub score: u32, // 0..100
    pub vulnerabilities: Vec<Vulnerability>,
    pub dependencies: Vec<Dependency>,
    pub fair_risk: FairRiskEvaluation,
    pub total_files_scanned: usize,
    pub total_lines_scanned: usize,
    pub execution_time_ms: u64,
    pub tamper_proof_hash: String,
    pub previous_hash: Option<String>,
}

impl AuditReport {
    #[must_use]
    pub fn calculate_score(vulns: &[Vulnerability]) -> u32 {
        let mut deduction = 0;
        for v in vulns {
            match v.severity {
                crate::vulnerability::Severity::Critical => deduction += 25,
                crate::vulnerability::Severity::High => deduction += 12,
                crate::vulnerability::Severity::Medium => deduction += 5,
                crate::vulnerability::Severity::Low => deduction += 2,
            }
        }
        100u32.saturating_sub(deduction)
    }
}
