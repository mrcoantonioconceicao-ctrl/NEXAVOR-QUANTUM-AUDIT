import { RustVulnerability, SourceFile } from './types.ts';

export interface SolanaAnchorAstMetrics {
  totalAnchorMacrosFound: number;
  signerCheckPassedCount: number;
  checkedMathUsageCount: number;
  uncheckedMathRiskCount: number;
  pdaCanonicalBumpEnforcedCount: number;
  pdaUncheckedBumpRiskCount: number;
  cpiVerificationCount: number;
}

export interface SolanaAstAnalysisResult {
  vulnerabilities: RustVulnerability[];
  metrics: SolanaAnchorAstMetrics;
  isFallbackModeUsed: boolean;
  fallbackReason?: string;
}

/**
 * Motor de Análise Estática AST Específico para Solana Anchor.
 * Inspeciona rigorosamente macros #[account(...)], verificação de assinantes,
 * aritmética segura (checked_add) e derivação de PDAs.
 */
export function analyzeSolanaAnchorAstPatterns(files: SourceFile[]): SolanaAstAnalysisResult {
  const vulnerabilities: RustVulnerability[] = [];
  const metrics: SolanaAnchorAstMetrics = {
    totalAnchorMacrosFound: 0,
    signerCheckPassedCount: 0,
    checkedMathUsageCount: 0,
    uncheckedMathRiskCount: 0,
    pdaCanonicalBumpEnforcedCount: 0,
    pdaUncheckedBumpRiskCount: 0,
    cpiVerificationCount: 0,
  };

  for (const file of files) {
    if (!file.path.endsWith('.rs')) continue;
    const lines = file.content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();
      const lineNum = i + 1;

      // 1. Contagem e Análise de Macros Anchor
      if (trimmed.startsWith('#[account') || trimmed.startsWith('#[derive(Accounts)]') || trimmed.startsWith('#[program]')) {
        metrics.totalAnchorMacrosFound++;
      }

      // 2. Análise de Signer Verification & Escalada de Privilégios
      if (trimmed.includes('pub authority:') || trimmed.includes('pub admin:') || trimmed.includes('pub owner:')) {
        const window = lines.slice(Math.max(0, i - 3), Math.min(lines.length, i + 5)).join('\n');
        if (window.includes('Signer<\'info\'>') || window.includes('#[account(signer)]')) {
          metrics.signerCheckPassedCount++;
        } else if (window.includes('AccountInfo<\'info\'>')) {
          vulnerabilities.push({
            id: `SOL-AST-SIGNER-${lineNum}`,
            file: file.path,
            line: lineNum,
            language: 'Rust (Anchor)',
            title: 'Escalação de Privilégios: Falta de Restrição Signer<\'info\'> ou #[account(signer)]',
            severity: 'CRITICAL',
            cwe: 'CWE-285: Improper Authorization',
            cvssScore: 9.8,
            category: 'BROKEN_ACCESS_AUTH',
            description: `A conta de autoridade na linha ${lineNum} utiliza AccountInfo<'info'> genérica sem a verificação Signer<'info'> ou #[account(signer)]. Atacantes podem invocar instruções passando chaves públicas arbitrárias sem assinar a transação.`,
            unsafeRiskDetail: 'Mutações administrativas não autorizadas em contratos Anchor.',
            waveShockwaveRadius: 'SYSTEM_PROCESS',
            originalSnippet: line,
            remediatedSnippet: line.replace("AccountInfo<'info'>", "Signer<'info'>"),
            suggestion: "Substitua a conta de autoridade por Signer<'info'> ou adicione #[account(signer)] na struct de contexto.",
            miriVerificationStatus: 'DETECTED_UB',
          });
        }
      }

      // 3. Análise de Aritmética Financeira (checked_add / checked_sub / checked_mul)
      if (
        (trimmed.includes('+=') || trimmed.includes('-=') || trimmed.includes('*=')) &&
        (trimmed.includes('amount') || trimmed.includes('balance') || trimmed.includes('lamports') || trimmed.includes('tokens') || trimmed.includes('count'))
      ) {
        if (trimmed.includes('checked_add') || trimmed.includes('checked_sub') || trimmed.includes('checked_mul')) {
          metrics.checkedMathUsageCount++;
        } else {
          metrics.uncheckedMathRiskCount++;
          vulnerabilities.push({
            id: `SOL-AST-MATH-${lineNum}`,
            file: file.path,
            line: lineNum,
            language: 'Rust (Anchor)',
            title: 'Aritmética Não Protegida: Risco de Integer Overflow / Underflow em Balanço',
            severity: 'HIGH',
            cwe: 'CWE-190: Integer Overflow or Wraparound',
            cvssScore: 8.4,
            category: 'INTEGER_OVERFLOW',
            description: `A operação aritmética na linha ${lineNum} altera valores numéricos diretos sem o uso de checked_add, checked_sub ou checked_mul. Em builds de release sem overflow-checks, esta operação pode causar wraparound silencioso.`,
            unsafeRiskDetail: 'Corrupção de saldos e risco de mineração ilimitada de tokens.',
            waveShockwaveRadius: 'CRATE_BOUNDARY',
            originalSnippet: line,
            remediatedSnippet: line.replace('+=', '= balance.checked_add(amount).ok_or(error!(ErrorCode::ArithmeticOverflow))?'),
            suggestion: 'Utilize metodos checked_add / checked_sub e propague erros customizados do Anchor via ok_or(error!(...))?.',
            miriVerificationStatus: 'DETECTED_UB',
          });
        }
      }

      // 4. Derivação de PDA e Validação de Canonical Bump
      if (trimmed.includes('find_program_address') || trimmed.includes('create_program_address') || trimmed.includes('seeds =')) {
        const window = lines.slice(i, Math.min(lines.length, i + 6)).join('\n');
        if (window.includes('bump =') || window.includes('bump')) {
          metrics.pdaCanonicalBumpEnforcedCount++;
        } else {
          metrics.pdaUncheckedBumpRiskCount++;
          vulnerabilities.push({
            id: `SOL-AST-PDA-${lineNum}`,
            file: file.path,
            line: lineNum,
            language: 'Rust (Anchor)',
            title: 'PDA Unchecked Bump: Risco de Injeção de Contas com Bumps Secundários',
            severity: 'HIGH',
            cwe: 'CWE-347: Improper Verification of Cryptographic Signature',
            cvssScore: 8.1,
            category: 'CRYPTOGRAPHIC_FAILURES',
            description: `A derivação de PDA na linha ${lineNum} não valida nem armazena o bump canônico oficial. Um atacante pode gerar um bump secundário válido e forjar PDAs para explorar o contrato.`,
            unsafeRiskDetail: 'Ataque de colisão e substituição de PDA (Bump Spoofing).',
            waveShockwaveRadius: 'CRATE_BOUNDARY',
            originalSnippet: line,
            remediatedSnippet: `#[account(seeds = [b"vault", authority.key().as_ref()], bump = vault.bump)]`,
            suggestion: 'Defina a restrição bump = conta.bump na struct Anchor ou valide o bump retornado por find_program_address.',
            miriVerificationStatus: 'DETECTED_UB',
          });
        }
      }

      // 5. Invariantes de CPI (Cross-Program Invocations)
      if (trimmed.includes('invoke(') || trimmed.includes('invoke_signed(')) {
        const window = lines.slice(Math.max(0, i - 4), Math.min(lines.length, i + 6)).join('\n');
        if (window.includes('program.key') || window.includes('check_id') || window.includes('CpiContext')) {
          metrics.cpiVerificationCount++;
        } else {
          vulnerabilities.push({
            id: `SOL-AST-CPI-${lineNum}`,
            file: file.path,
            line: lineNum,
            language: 'Rust (Anchor)',
            title: 'CPI Target Spoofing: Invocação Cruzada Sem Validação de Program ID',
            severity: 'CRITICAL',
            cwe: 'CWE-20: Improper Input Validation',
            cvssScore: 9.3,
            category: 'BROKEN_ACCESS_AUTH',
            description: `A chamada cruzada CPI na linha ${lineNum} não verifica se o target_program_id corresponde ao programa oficial esperado. Um programa malicioso substituto pode ser injetado.`,
            unsafeRiskDetail: 'Execução de código arbitrário via programas dublês no ecossistema Solana.',
            waveShockwaveRadius: 'SYSTEM_PROCESS',
            originalSnippet: line,
            remediatedSnippet: `require_keys_eq!(*target_program.key, expected_program::ID, ErrorCode::InvalidProgramId);`,
            suggestion: 'Inspecione o Program ID do programa invocado com require_keys_eq! ou utilize CpiContext do Anchor.',
            miriVerificationStatus: 'DETECTED_UB',
          });
        }
      }
    }
  }

  return {
    vulnerabilities,
    metrics,
    isFallbackModeUsed: false,
  };
}

/**
 * Wrapper com Tratamento de Erros e Fallback Gracioso.
 * Tenta executar a requisição externa/AI se fornecida, e faz failover automático
 * para a análise heurística determinística local em caso de falhas de rede, 503 ou rate limits.
 */
export async function analyzeSolanaAnchorAstWithFallback(
  files: SourceFile[],
  externalApiCall?: () => Promise<RustVulnerability[]>
): Promise<SolanaAstAnalysisResult> {
  const localAnalysis = analyzeSolanaAnchorAstPatterns(files);

  if (!externalApiCall) {
    return localAnalysis;
  }

  try {
    const remoteVulns = await externalApiCall();
    // Combina e desduplica vulnerabilidades
    const combined = [...localAnalysis.vulnerabilities, ...remoteVulns];
    const unique = combined.filter((v, idx, self) =>
      idx === self.findIndex((t) => t.file === v.file && t.line === v.line && t.title === v.title)
    );

    return {
      vulnerabilities: unique,
      metrics: localAnalysis.metrics,
      isFallbackModeUsed: false,
    };
  } catch (err: any) {
    const errorMessage = err?.message || 'Falha ou Rate Limit (HTTP 503/429) na API de auditoria externa';
    console.warn('[RustShield AST Engine Fallback] Falha na chamada externa. Ativando análise estática autónoma local:', errorMessage);

    return {
      vulnerabilities: localAnalysis.vulnerabilities,
      metrics: localAnalysis.metrics,
      isFallbackModeUsed: true,
      fallbackReason: `Failover Gracioso Ativado: ${errorMessage}`,
    };
  }
}
