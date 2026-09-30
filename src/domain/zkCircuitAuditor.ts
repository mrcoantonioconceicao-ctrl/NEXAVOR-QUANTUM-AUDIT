import { RustVulnerability, SourceFile } from './types.ts';

export interface ZkCircuitRule {
  ruleId: string;
  title: string;
  category: 'UNCONSTRAINED_VARIABLE' | 'MISSING_RANGE_CHECK' | 'UNSAFE_NULLIFIER_HASH' | 'PUBLIC_INPUT_UNDERCONSTRAINED' | 'PRIVATE_WITNESS_LEAK';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  cwe: string;
  description: string;
  validate: (line: string, idx: number, allLines: string[], fileContent: string) => RustVulnerability | null;
}

export const ZK_CIRCUIT_CHECKLIST: ZkCircuitRule[] = [
  // 1. Unconstrained Circuit Variable (Halo2 / Bellman / Arkworks)
  {
    ruleId: 'ZK-CHK-001',
    title: 'Variável de Circuito Sem Restrição (Unconstrained Variable / Soundness Leak)',
    category: 'UNCONSTRAINED_VARIABLE',
    severity: 'CRITICAL',
    cwe: 'CWE-697',
    description: 'Alocação de variável testemunha no circuito ZK sem invocação de restrição (enforce / constrain_equal). Prova pode ser forjada.',
    validate: (line, idx, allLines) => {
      const trimmed = line.trim();
      if (
        (trimmed.includes('cs.alloc(') || trimmed.includes('region.assign_advice') || trimmed.includes('alloc_input(')) &&
        !allLines.slice(idx, idx + 10).join('\n').includes('enforce') &&
        !allLines.slice(idx, idx + 10).join('\n').includes('constrain') &&
        !allLines.slice(idx, idx + 10).join('\n').includes('assert_equal')
      ) {
        return {
          id: `ZK-UNCONSTRAINED-${idx + 1}`,
          file: '',
          line: idx + 1,
          language: 'Rust (Halo2 / ZK)',
          title: 'Vulnerabilidade de Solidez ZK: Variável de Circuito Sem Restrição (Unconstrained Variable)',
          severity: 'CRITICAL',
          cwe: 'CWE-697',
          cvssScore: 9.8,
          category: 'CRYPTOGRAPHIC_FAILURES',
          description: 'A variável alocada no circuito não possui polinômio de restrição associado. O provador (prover) pode atribuir qualquer valor arbitrário e gerar uma prova ZK sintaticamente válida.',
          unsafeRiskDetail: 'Quebra de solidez (Soundness Leak) no sistema de prova Zero-Knowledge.',
          waveShockwaveRadius: 'SYSTEM_PROCESS',
          originalSnippet: line,
          remediatedSnippet: `${line}\nregion.constrain_equal(assigned_var.cell(), target_cell)?;`,
          suggestion: 'Imponha a restrição de igualdade ou porta polinomial imediatamente após a alocação do valor de conselho (advice).',
          miriVerificationStatus: 'DETECTED_UB',
        };
      }
      return null;
    },
  },

  // 2. Missing Range Check on Field Elements
  {
    ruleId: 'ZK-CHK-002',
    title: 'Ausência de Range Check em Elementos de Campo Numérico (Field Overflow)',
    category: 'MISSING_RANGE_CHECK',
    severity: 'HIGH',
    cwe: 'CWE-190',
    description: 'Operações em corpos finitos (Fr/Fq) sem verificação de limites (Range Check) em tabelas de busca (Lookup Tables).',
    validate: (line, idx, allLines) => {
      const trimmed = line.trim();
      if (
        (trimmed.includes('as u64') || trimmed.includes('to_scalar()') || trimmed.includes('Fp::from(')) &&
        (trimmed.includes('amount') || trimmed.includes('balance') || trimmed.includes('value')) &&
        !allLines.slice(Math.max(0, idx - 5), idx + 8).join('\n').includes('range_check') &&
        !allLines.slice(Math.max(0, idx - 5), idx + 8).join('\n').includes('lookup')
      ) {
        return {
          id: `ZK-RANGE-${idx + 1}`,
          file: '',
          line: idx + 1,
          language: 'Rust (Halo2 / Zcash)',
          title: 'Risco de Wraparound de Corpo Finito: Falta de Range Check em Valor de Transação ZK',
          severity: 'HIGH',
          cwe: 'CWE-190',
          cvssScore: 8.6,
          category: 'INTEGER_OVERFLOW',
          description: 'Conversão para elemento de corpo finito sem restrição de bits (Range Check). Valores superiores à ordem do corpo podem causar wraparound silencioso.',
          unsafeRiskDetail: 'Geração de provas com saldos ZK inflacionados por mod p.',
          waveShockwaveRadius: 'CRATE_BOUNDARY',
          originalSnippet: line,
          remediatedSnippet: `lookup_config.range_check(layouter, advice_cell, 64)?; // Restrição de 64 bits\n${line}`,
          suggestion: 'Configure uma tabela de lookup ou gate de decomposição em bits para restringir o escalar ao limite numérico (ex: 64 bits).',
          miriVerificationStatus: 'DETECTED_UB',
        };
      }
      return null;
    },
  },

  // 3. Unsafe Nullifier Hash Generation (Privacy Drain)
  {
    ruleId: 'ZK-CHK-003',
    title: 'Nullifier Hash Inseguro ou Sem Domínio de Separação (Replay Risk)',
    category: 'UNSAFE_NULLIFIER_HASH',
    severity: 'CRITICAL',
    cwe: 'CWE-327',
    description: 'Derivação de Nullifier em circuito ZK usando função de hash não resistente a colisões ou sem domain separator.',
    validate: (line, idx, allLines) => {
      const trimmed = line.trim();
      if (
        (trimmed.includes('nullifier') || trimmed.includes('nf_commit')) &&
        (trimmed.includes('Sha256') || trimmed.includes('Keccak') || trimmed.includes('Sha3'))
      ) {
        return {
          id: `ZK-NULLIFIER-${idx + 1}`,
          file: '',
          line: idx + 1,
          language: 'Rust (Zcash / Halo2)',
          title: 'Quebra de Privacidade & Replay: Nullifier Hash Gerado com Algoritmo Inadequado para ZK',
          severity: 'CRITICAL',
          cwe: 'CWE-327',
          cvssScore: 9.1,
          category: 'CRYPTOGRAPHIC_FAILURES',
          description: 'Uso de hashes tradicionais (SHA-256/Keccak) para geração de Nullifiers ZK. Hashes algébricos amigáveis a circuitos (Poseidon, Sinsemilla, Pedersen) com Domain Separator devem ser utilizados.',
          unsafeRiskDetail: 'Ataques de gasto duplo (Double Spending) e rastreabilidade de privacidade.',
          waveShockwaveRadius: 'SYSTEM_PROCESS',
          originalSnippet: line,
          remediatedSnippet: line.replace('Sha256::digest', 'poseidon::Hash::digest_with_domain(DOMAIN_NULLIFIER, &seeds)'),
          suggestion: 'Utilize Poseidon, Sinsemilla ou Pedersen Hashes amigáveis a ZK com Domain Separator para derivar Nullifiers.',
          miriVerificationStatus: 'DETECTED_UB',
        };
      }
      return null;
    },
  },

  // 4. Private Witness Leak in Telemetry
  {
    ruleId: 'ZK-CHK-004',
    title: 'Vazamento de Testemunha Privada em Logs (Private Witness Exposure)',
    category: 'PRIVATE_WITNESS_LEAK',
    severity: 'HIGH',
    cwe: 'CWE-532',
    description: 'Impressão ou log de escalares contendo segredos ZK (spending keys, witness, randomness) em texto claro.',
    cweScore: 7.8,
    validate: (line, idx) => {
      const trimmed = line.trim();
      if (
        (trimmed.includes('println!') || trimmed.includes('msg!') || trimmed.includes('log::info!') || trimmed.includes('tracing::debug!')) &&
        (trimmed.includes('witness') || trimmed.includes('sk_usr') || trimmed.includes('spending_key') || trimmed.includes('randomness'))
      ) {
        return {
          id: `ZK-WITNESS-LEAK-${idx + 1}`,
          file: '',
          line: idx + 1,
          language: 'Rust (ZK / Privacy)',
          title: 'Vazamento de Segredo Privado: Impressão de Testemunha ZK em Logs de Diagnóstico',
          severity: 'HIGH',
          cwe: 'CWE-532',
          cvssScore: 7.8,
          category: 'SENSITIVE_DATA_EXPOSURE',
          description: 'Sua aplicação imprime variáveis de testemunha privada (witness/spending keys) no console ou log de auditoria, comprometendo o anônimato.',
          unsafeRiskDetail: 'Exposição irrecuperável de chaves privadas em logs de servidor.',
          waveShockwaveRadius: 'CRATE_BOUNDARY',
          originalSnippet: line,
          remediatedSnippet: '// Log de segredos privados removido para conformidade ZK e LGPD',
          suggestion: 'Elimine logs de diagnóstico contendo testemunhas privadas ou criptografe o payload.',
          miriVerificationStatus: 'DETECTED_UB',
        };
      }
      return null;
    },
  },
];

export function analyzeZkCircuitPrimitives(files: SourceFile[]): RustVulnerability[] {
  const vulnerabilities: RustVulnerability[] = [];

  for (const file of files) {
    if (!file.path.endsWith('.rs')) continue;
    const lines = file.content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const rule of ZK_CIRCUIT_CHECKLIST) {
        const vuln = rule.validate(line, i, lines, file.content);
        if (vuln) {
          vuln.file = file.path;
          vulnerabilities.push(vuln);
        }
      }
    }
  }

  return vulnerabilities;
}
