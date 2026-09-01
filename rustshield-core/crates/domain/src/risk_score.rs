use serde::{Deserialize, Serialize};

/// Quantificação Financeira de Risco Cibernético baseada no Modelo FAIR (Factor Analysis of Information Risk)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FairRiskEvaluation {
    pub asset_value_usd: f64,
    pub exposure_factor_percent: f64,
    pub single_loss_expectancy_usd: f64, // SLE = Asset Value * Exposure Factor
    pub annualized_rate_of_occurrence: f64, // ARO (probabilidade anualizada)
    pub annualized_loss_expectancy_usd: f64, // ALE = SLE * ARO
    pub post_mitigation_loss_usd: f64,
    pub security_investment_cost_usd: f64,
    pub return_on_security_investment_percent: f64, // ROSI = (ALE_saved - Cost) / Cost * 100
    pub risk_reduction_percentage: f64,
}

impl FairRiskEvaluation {
    #[must_use]
    pub fn calculate(
        asset_value_usd: f64,
        exposure_factor_percent: f64,
        aro: f64,
        security_cost_usd: f64,
        mitigation_effectiveness_percent: f64,
    ) -> Self {
        let ef = (exposure_factor_percent.clamp(0.0, 100.0)) / 100.0;
        let sle = asset_value_usd * ef;
        let initial_ale = sle * aro;

        let effectiveness = (mitigation_effectiveness_percent.clamp(0.0, 100.0)) / 100.0;
        let post_mitigation_ale = initial_ale * (1.0 - effectiveness);
        let ale_saved = initial_ale - post_mitigation_ale;

        let rosi = if security_cost_usd > 0.0 {
            ((ale_saved - security_cost_usd) / security_cost_usd) * 100.0
        } else {
            0.0
        };

        Self {
            asset_value_usd,
            exposure_factor_percent,
            single_loss_expectancy_usd: sle,
            annualized_rate_of_occurrence: aro,
            annualized_loss_expectancy_usd: initial_ale,
            post_mitigation_loss_usd: post_mitigation_ale,
            security_investment_cost_usd: security_cost_usd,
            return_on_security_investment_percent: rosi,
            risk_reduction_percentage: mitigation_effectiveness_percent,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fair_calculation() {
        let eval = FairRiskEvaluation::calculate(1_000_000.0, 30.0, 0.5, 25_000.0, 85.0);
        assert_eq!(eval.single_loss_expectancy_usd, 300_000.0);
        assert_eq!(eval.annualized_loss_expectancy_usd, 150_000.0);
        assert_eq!(eval.post_mitigation_loss_usd, 22_500.0);
        // Saved = 127,500. ROSI = (127,500 - 25,000)/25,000 * 100 = 410%
        assert_eq!(eval.return_on_security_investment_percent, 410.0);
    }
}
