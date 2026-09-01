use rustshield_domain::FairRiskEvaluation;

pub struct CalculateRiskUseCase;

impl CalculateRiskUseCase {
    #[must_use]
    pub fn execute(
        asset_value_usd: f64,
        exposure_factor_percent: f64,
        aro: f64,
        security_cost_usd: f64,
        mitigation_percent: f64,
    ) -> FairRiskEvaluation {
        FairRiskEvaluation::calculate(
            asset_value_usd,
            exposure_factor_percent,
            aro,
            security_cost_usd,
            mitigation_percent,
        )
    }
}
