use rustshield_domain::FairRiskEvaluation;

/// Custom error type for calculation failures.
/// Requires 'thiserror' crate dependency in your `Cargo.toml`:
/// `[dependencies]`
/// `thiserror = "1.0"`
#[derive(Debug, thiserror::Error)]
pub enum CalculateRiskError {
    #[error("Asset value must be a non-negative number and not NaN or infinite.")]
    InvalidAssetValue,
    #[error("Exposure factor must be a number between 0.0 and 1.0 (inclusive), and not NaN or infinite.")]
    InvalidExposureFactor,
    #[error("Annualized Rate of Occurrence (ARO) must be a non-negative number and not NaN or infinite.")]
    InvalidARO,
    #[error("Security cost must be a non-negative number and not NaN or infinite.")]
    InvalidSecurityCost,
    #[error("Mitigation percent must be a number between 0.0 and 1.0 (inclusive), and not NaN or infinite.")]
    InvalidMitigationPercent,
}

pub struct CalculateRiskUseCase;

impl CalculateRiskUseCase {
    #[must_use]
    pub fn execute(
        asset_value_usd: f64,
        exposure_factor_percent: f64,
        aro: f64,
        security_cost_usd: f64,
        mitigation_percent: f64,
    ) -> Result<FairRiskEvaluation, CalculateRiskError> {
        // Input validation for f64 parameters to prevent incorrect calculations or panics
        if asset_value_usd.is_nan() || asset_value_usd.is_infinite() || asset_value_usd < 0.0 {
            return Err(CalculateRiskError::InvalidAssetValue);
        }
        // Exposure factor is typically a percentage, so between 0.0 and 1.0
        if exposure_factor_percent.is_nan() || exposure_factor_percent.is_infinite() || exposure_factor_percent < 0.0 || exposure_factor_percent > 1.0 {
            return Err(CalculateRiskError::InvalidExposureFactor);
        }
        if aro.is_nan() || aro.is_infinite() || aro < 0.0 {
            return Err(CalculateRiskError::InvalidARO);
        }
        if security_cost_usd.is_nan() || security_cost_usd.is_infinite() || security_cost_usd < 0.0 {
            return Err(CalculateRiskError::InvalidSecurityCost);
        }
        // Mitigation percent is typically a percentage, so between 0.0 and 1.0
        if mitigation_percent.is_nan() || mitigation_percent.is_infinite() || mitigation_percent < 0.0 || mitigation_percent > 1.0 {
            return Err(CalculateRiskError::InvalidMitigationPercent);
        }

        // All inputs are valid, proceed with calculation
        Ok(FairRiskEvaluation::calculate(
            asset_value_usd,
            exposure_factor_percent,
            aro,
            security_cost_usd,
            mitigation_percent,
        ))
    }
}
