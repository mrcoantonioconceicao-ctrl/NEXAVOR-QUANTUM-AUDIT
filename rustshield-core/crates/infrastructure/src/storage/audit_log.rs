use anyhow::Result;
use rustshield_domain::AuditReport;
use serde::{Deserialize, Serialize};
use std::sync::RwLock;
use crate::crypto::hasher::TamperProofLedger;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerBlock {
    pub index: usize,
    pub timestamp: String,
    pub report_id: String,
    pub repository: String,
    pub score: u32,
    pub vuln_count: usize,
    pub previous_hash: String,
    pub current_hash: String,
}

pub struct AppendOnlyLedger {
    blocks: RwLock<Vec<LedgerBlock>>,
}

impl Default for AppendOnlyLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl AppendOnlyLedger {
    #[must_use]
    pub fn new() -> Self {
        // Genesis block
        let genesis = LedgerBlock {
            index: 0,
            timestamp: chrono::Utc::now().to_rfc3339(),
            report_id: "GENESIS".to_string(),
            repository: "ROOT_INIT".to_string(),
            score: 100,
            vuln_count: 0,
            previous_hash: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            current_hash: "8f48937b42004d8058dd5a898b9f1d07c0800c0175b9f71c4c114f6b15b13511".to_string(),
        };

        Self {
            blocks: RwLock::new(vec![genesis]),
        }
    }

    pub fn append_report(&self, report: &AuditReport) -> Result<LedgerBlock> {
        let mut blocks = self.blocks.write().map_err(|_| anyhow::anyhow!("Falha ao adquirir lock de escrita no ledger"))?;
        let prev_block = blocks.last().ok_or_else(|| anyhow::anyhow!("Ledger corrompido: sem bloco anterior"))?;
        let prev_hash = prev_block.current_hash.clone();
        let index = blocks.len();

        let payload = format!(
            "{}:{}:{}:{}:{}:{}",
            index, report.id, report.repository.name, report.score, report.vulnerabilities.len(), report.timestamp
        );

        let current_hash = TamperProofLedger::compute_chained_hash(&prev_hash, payload.as_bytes());

        let new_block = LedgerBlock {
            index,
            timestamp: report.timestamp.clone(),
            report_id: report.id.clone(),
            repository: report.repository.name.clone(),
            score: report.score,
            vuln_count: report.vulnerabilities.len(),
            previous_hash: prev_hash,
            current_hash,
        };

        blocks.push(new_block.clone());
        Ok(new_block)
    }

    pub fn get_all_blocks(&self) -> Vec<LedgerBlock> {
        self.blocks.read().map(|b| b.clone()).unwrap_or_default()
    }

    pub fn verify_integrity(&self) -> bool {
        let blocks = match self.blocks.read() {
            Ok(b) => b,
            Err(_) => return false,
        };

        if blocks.is_empty() {
            return false;
        }

        for i in 1..blocks.len() {
            let prev = &blocks[i - 1];
            let curr = &blocks[i];

            if curr.previous_hash != prev.current_hash {
                return false;
            }

            let payload = format!(
                "{}:{}:{}:{}:{}:{}",
                curr.index, curr.report_id, curr.repository, curr.score, curr.vuln_count, curr.timestamp
            );
            let expected_hash = TamperProofLedger::compute_chained_hash(&prev.current_hash, payload.as_bytes());

            if !TamperProofLedger::constant_time_eq(curr.current_hash.as_bytes(), expected_hash.as_bytes()) {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustshield_domain::{FairRiskEvaluation, Repository};

    #[test]
    fn test_ledger_append_and_verify() {
        let ledger = AppendOnlyLedger::new();
        let report = AuditReport {
            id: "RPT-001".to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            repository: Repository::new("test-repo", "http://github.com", "main", "Rust").unwrap(),
            score: 95,
            vulnerabilities: vec![],
            dependencies: vec![],
            fair_risk: FairRiskEvaluation::calculate(100_000.0, 10.0, 0.2, 5000.0, 90.0),
            total_files_scanned: 10,
            total_lines_scanned: 500,
            execution_time_ms: 120,
            tamper_proof_hash: "hash".to_string(),
            previous_hash: None,
        };

        let block = ledger.append_report(&report);
        assert!(block.is_ok());
        assert!(ledger.verify_integrity());
    }
}
