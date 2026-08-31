/**
 * Bounded Context: GRC (Governance, Risk & Compliance)
 * Modelo FAIR (Factor Analysis of Information Risk) para quantificação financeira de risco cibernético.
 */

export interface FAIRMetrics {
  assetValueUsd: number;
  singleLossExpectancy: number; // SLE = Asset Value * Exposure Factor
  annualizedRateOfOccurrence: number; // ARO = Probabilidade de ataque por ano
  annualLossExpectancy: number; // ALE = SLE * ARO
  securityInvestmentCostUsd: number;
  riskMitigationFactorPercent: number; // Ex: 0.85 (85% de redução do risco)
  returnOnSecurityInvestment: number; // ROSI = ((ALE_before - ALE_after) - Cost) / Cost * 100
  mitigatedAnnualLossExpectancy: number; // ALE_after
}

export interface SecuritySLA {
  id: string;
  name: string;
  criticalResolutionTimeHours: number;
  highResolutionTimeHours: number;
  mediumResolutionTimeHours: number;
  complianceTargetPercent: number;
  currentComplianceStatus: 'COMPLIANT' | 'WARNING' | 'BREACHED';
}

export class GRCService {
  public static calculateFAIR(
    assetValueUsd: number,
    exposureFactorPercent: number,
    aro: number,
    securityCostUsd: number,
    mitigationPercent: number
  ): FAIRMetrics {
    const ef = Math.max(0, Math.min(1, exposureFactorPercent / 100));
    const mit = Math.max(0, Math.min(1, mitigationPercent / 100));

    const sle = assetValueUsd * ef;
    const aleBefore = sle * aro;
    const aleAfter = aleBefore * (1 - mit);
    const riskMitigatedValue = aleBefore - aleAfter;

    const rosi = securityCostUsd > 0
      ? ((riskMitigatedValue - securityCostUsd) / securityCostUsd) * 100
      : 0;

    return {
      assetValueUsd,
      singleLossExpectancy: Math.round(sle),
      annualizedRateOfOccurrence: Number(aro.toFixed(2)),
      annualLossExpectancy: Math.round(aleBefore),
      securityInvestmentCostUsd: securityCostUsd,
      riskMitigationFactorPercent: Math.round(mit * 100),
      mitigatedAnnualLossExpectancy: Math.round(aleAfter),
      returnOnSecurityInvestment: Number(rosi.toFixed(1)),
    };
  }

  public static evaluateSLA(criticalCount: number, highCount: number): SecuritySLA {
    let status: 'COMPLIANT' | 'WARNING' | 'BREACHED' = 'COMPLIANT';
    if (criticalCount > 0) {
      status = 'BREACHED';
    } else if (highCount > 2) {
      status = 'WARNING';
    }

    return {
      id: 'SLA-NEXAVOR-PQC-01',
      name: 'NEXAVOR Quantum Security SLA (ISO 27001 / NIST SP 800-218)',
      criticalResolutionTimeHours: 24,
      highResolutionTimeHours: 72,
      mediumResolutionTimeHours: 168,
      complianceTargetPercent: 99.5,
      currentComplianceStatus: status,
    };
  }
}
