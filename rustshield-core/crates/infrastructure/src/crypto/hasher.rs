use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub struct TamperProofLedger;

impl TamperProofLedger {
    #[must_use]
    pub fn compute_sha256(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    #[must_use]
    pub fn compute_chained_hash(prev_hash: &str, current_payload: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(prev_hash.as_bytes());
        hasher.update(current_payload);
        hex::encode(hasher.finalize())
    }

    /// Verificação de igualdade em tempo constante (Constant-Time Comparison)
    /// Essencial para prevenir ataques de temporização (Timing Attacks) em tokens e hashes de segurança.
    #[must_use]
    pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        a.ct_eq(b).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_hashing() {
        let hash = TamperProofLedger::compute_sha256(b"rustshield-secure-payload");
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_constant_time_comparison() {
        let token_a = b"secret_token_123456789";
        let token_b = b"secret_token_123456789";
        let token_c = b"secret_token_999999999";

        assert!(TamperProofLedger::constant_time_eq(token_a, token_b));
        assert!(!TamperProofLedger::constant_time_eq(token_a, token_c));
    }
}
