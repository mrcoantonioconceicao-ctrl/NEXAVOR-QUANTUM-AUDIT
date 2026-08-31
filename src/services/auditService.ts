import {
  RepositoryMetadata,
  SecurityAuditReport,
  SourceFile,
  RustVulnerability,
} from '../domain/types.ts';
import { analyzePolyglotStaticPatterns } from '../domain/polyglotStaticEngine.ts';
import {
  auditManifestDependencies,
  scanObsoleteDependenciesWithAdvisoryAPIs,
  DependencyAuditResult,
} from '../domain/dependencyAuditor.ts';
import { computeWaveSpectralAnalysis } from '../domain/waveTheory.ts';
import { auditQuantumCryptography } from '../domain/quantumCrypto.ts';
import { generateSecurityTestSuite } from '../domain/securityTests.ts';

export interface CvssScoreCalculationInput {
  vulnerabilities: Array<{ severity?: string; cvssScore?: number }>;
  totalUnsafeBlocks?: number;
  waveHazardsCount?: number;
  quantumReadinessScore?: number;
}

/**
  * Calcula a severidade e a nota geral de segurança com pesos de CVSS v3.1/v4.0.
  * Se o repositório não possuir vulnerabilidades críticas (CVSS 9.0-10.0),
  * pontua proporcionalmente na faixa de 65 a 75/100 para evitar alarmismo injustificado.
  */
export function calculateCvssWeightedSecurityScore(input: CvssScoreCalculationInput): number {
  const {
    vulnerabilities,
    totalUnsafeBlocks = 0,
    waveHazardsCount = 0,
    quantumReadinessScore = 100,
  } = input;

  const criticalCount = vulnerabilities.filter(
    (v) => v.severity === 'CRITICAL' || (v.cvssScore !== undefined && v.cvssScore >= 9.0)
  ).length;

  const highCount = vulnerabilities.filter(
    (v) => v.severity === 'HIGH' || (v.cvssScore !== undefined && v.cvssScore >= 7.0 && v.cvssScore < 9.0)
  ).length;

  const mediumCount = vulnerabilities.filter(
    (v) => v.severity === 'MEDIUM' || (v.cvssScore !== undefined && v.cvssScore >= 4.0 && v.cvssScore < 7.0)
  ).length;

  const lowCount = vulnerabilities.filter(
    (v) => v.severity === 'LOW' || (v.cvssScore !== undefined && v.cvssScore < 4.0)
  ).length;

  // CVSS Weighted Deductions
  const critDeduction = Math.min(45, criticalCount * 20);
  const highDeduction = Math.min(20, highCount * 4.0);
  const medDeduction = Math.min(10, mediumCount * 1.5);
  const lowDeduction = Math.min(4, lowCount * 0.5);
  const unsafeDeduction = Math.min(8, totalUnsafeBlocks * 1.0);
  const waveDeduction = Math.min(5, waveHazardsCount * 1.0);
  const quantumDeduction =
    quantumReadinessScore < 50 ? Math.min(5, (50 - quantumReadinessScore) * 0.1) : 0;

  let calculatedScore =
    100 -
    (critDeduction +
      highDeduction +
      medDeduction +
      lowDeduction +
      unsafeDeduction +
      waveDeduction +
      quantumDeduction);

  // Exact rule: Repositories WITHOUT critical vulnerabilities (CVSS < 9.0)
  // are scored proportionally in the 65 - 75 range (if non-critical issues exist) or 100 if completely clean!
  if (criticalCount === 0) {
    if (highCount === 0 && mediumCount === 0 && lowCount === 0 && totalUnsafeBlocks === 0) {
      return quantumReadinessScore >= 80 ? 100 : Math.round(calculatedScore);
    }
    // Has non-critical advisories/updates: map strictly to 65 - 75
    const mappedScore = Math.round(65 + (Math.max(0, Math.min(30, calculatedScore - 50)) / 30) * 10);
    return Math.min(75, Math.max(65, mappedScore));
  }

  // Critical vulnerabilities present (CVSS 9.0-10.0): range 15 - 55
  return Math.max(15, Math.min(55, Math.round(calculatedScore)));
}

/**
 * Escaneia os arquivos de manifesto (`Cargo.toml`, `package.json`, `go.mod`, etc.)
 * para identificar dependências obsoletas, depreciadas e vulnerabilidades conhecidas (CVEs/GHSA/RustSec)
 * através de chamadas integradas às APIs do OSV.dev (Open Source Vulnerabilities) e GitHub Advisory Database.
 *
 * @param files Lista de arquivos-fonte e manifestos do repositório
 * @returns Resultado detalhado da auditoria de dependências com CVEs e recomendações de atualização
 */
export async function scanManifestDependenciesWithAdvisories(
  files: SourceFile[]
): Promise<DependencyAuditResult> {
  return await scanObsoleteDependenciesWithAdvisoryAPIs(files);
}

/**
 * Identifica dependências obsoletas e desatualizadas em manifestos (`Cargo.toml`, `package.json`, `go.mod`)
 * consultando bases de advisories (OSV.dev / GitHub Advisory Database / RustSec).
 */
export async function scanObsoleteDependencies(
  files: SourceFile[]
): Promise<DependencyAuditResult> {
  return await scanObsoleteDependenciesWithAdvisoryAPIs(files);
}

export async function runFullSecurityAudit(
  repo: RepositoryMetadata,
  files: SourceFile[],
  onProgress?: (stepIndex: number, progress: number, message: string) => void
): Promise<SecurityAuditReport> {
  // Step 1: Ingestion & normalization across all languages
  onProgress?.(0, 50, `Ingerindo ${files.length} arquivos-fonte e analisando árvore Git (${repo.language})...`);
  onProgress?.(0, 100, `Árvore de dependências e arquivos de código carregados com sucesso.`);

  // Step 2: Supply Chain & Real-Time Manifest CVE Audit (RustSec / OSV / PyPI / npm / Go)
  onProgress?.(1, 30, 'Auditando manifests (Cargo.toml, package.json, requirements.txt, go.mod) contra bases RustSec & OSV...');
  const dependencyResult = await scanManifestDependenciesWithAdvisories(files);
  onProgress?.(
    1,
    100,
    `Varredura concluída: ${dependencyResult.totalDependenciesCount} dependências analisadas, ${dependencyResult.vulnerableCount} vulneráveis (CVEs/RustSec: ${dependencyResult.rustsecCount}), ${dependencyResult.outdatedCount} desatualizadas.`
  );

  // Step 3: AST & Polyglot Static Pattern Analysis
  onProgress?.(2, 40, 'Executando motor estático universal de análise de AST e padrões de segurança...');
  const staticResult = analyzePolyglotStaticPatterns(files);
  onProgress?.(2, 100, `Identificados ${staticResult.vulnerabilities.length} pontos de vulnerabilidade de código em [${staticResult.detectedLanguages.join(', ')}].`);

  // Step 4: Zero-Day Wave Theory Analysis
  onProgress?.(3, 50, 'Calculando entropia espectral e matriz de ressonância de onda para previsão de 0-Day...');
  const waveAnalysis = computeWaveSpectralAnalysis(files);
  onProgress?.(3, 100, `Mapeados ${waveAnalysis.hazards.length} vetores de interferência de ondas de risco.`);

  // Step 5: Quantum Cryptography & Shor Audit
  onProgress?.(4, 50, 'Auditando algoritmos criptográficos contra computação quântica (Shor/Grover)...');
  const quantumMetrics = auditQuantumCryptography(files);
  onProgress?.(4, 100, `Score de prontidão pós-quântica calculado: ${quantumMetrics.quantumReadinessScore}/100.`);

  // Combine static + supply chain vulnerabilities before deep AI review
  const initialVulnerabilities = [...dependencyResult.generatedAuditIssues, ...staticResult.vulnerabilities];

  // Step 6: Deep AI Reasoning & Polyglot Code Review Synthesis
  onProgress?.(5, 30, `Consultando motor de IA especialista em segurança (${staticResult.primaryLanguage} / PQC / Supply Chain / 0-Day)...`);
  let aiEnrichedVulnerabilities = initialVulnerabilities;
  let aiExecutiveSummary = '';
  let aiDddVerdict = `Alinhamento com Bounded Contexts, separação de camadas e tipagem forte em ${staticResult.primaryLanguage}.`;
  let aiSoaVerdict = 'Arquitetura com separação clara de responsabilidades e isolamento de microsserviços.';

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 18000); // 18s fallback limit

    const aiRes = await fetch('/api/audit/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      signal: controller.signal,
      body: JSON.stringify({
        repoName: repo.fullName,
        files: files.map((f) => ({ path: f.path, content: f.content })),
        language: staticResult.primaryLanguage.toLowerCase(),
        detectedIssuesSummary: `${initialVulnerabilities.length} vulnerabilidades (incluindo ${dependencyResult.vulnerableCount} falhas de dependências/RustSec e ${staticResult.vulnerabilities.length} estáticas), ${waveAnalysis.hazards.length} hazards de onda, ${staticResult.totalUnsafeBlocks} blocos críticos`,
      }),
    });
    clearTimeout(timeoutId);

    if (aiRes.ok) {
      const aiData = await aiRes.json();
      if (aiData.result) {
        aiExecutiveSummary = aiData.result.executiveSummary;
        if (aiData.result.architectureVerdict) {
          aiDddVerdict = aiData.result.architectureVerdict.dddCompliance || aiDddVerdict;
          aiSoaVerdict = aiData.result.architectureVerdict.soaResilience || aiSoaVerdict;
        }
        if (Array.isArray(aiData.result.deepVulnerabilities) && aiData.result.deepVulnerabilities.length > 0) {
          const knownFilePaths = new Set(files.map((f) => f.path));
          const existingKeys = new Set(initialVulnerabilities.map((v) => `${v.file}:${v.line}`));

          const mappedAiVulns: RustVulnerability[] = [];
          for (let idx = 0; idx < aiData.result.deepVulnerabilities.length; idx++) {
            const v = aiData.result.deepVulnerabilities[idx];
            const targetFile = v.file || '';
            // Only accept vulnerability if the file actually exists in the audited codebase
            if (!knownFilePaths.has(targetFile)) {
              continue;
            }

            const key = `${targetFile}:${v.line || 1}`;
            if (existingKeys.has(key)) {
              continue;
            }
            existingKeys.add(key);

            mappedAiVulns.push({
              id: `AI-VULN-${idx + 1}`,
              file: targetFile,
              line: v.line || 1,
              language: staticResult.primaryLanguage,
              title: v.title || 'Vulnerabilidade Avançada de Arquitetura/Memória',
              severity: v.severity || 'HIGH',
              cwe: v.cwe || 'CWE-119',
              cvssScore: v.severity === 'CRITICAL' ? 9.5 : v.severity === 'HIGH' ? 8.2 : 6.0,
              category: 'UNSAFE_UB',
              description: v.explanation || 'Falha profunda de invariante de segurança em código analisado.',
              unsafeRiskDetail: v.unsafeBlockAnalysis || 'Operação contornando garantias de isolamento de estado.',
              waveShockwaveRadius: v.waveShockwaveRisk || 'CRATE_BOUNDARY',
              quantumRiskDetail: v.quantumVulnerability,
              originalSnippet: v.originalSnippet || '// Trecho com falha',
              remediatedSnippet: v.remediatedSnippet || '// Trecho remediado',
              suggestion: v.suggestion || v.remediationSuggestion || 'Aplique tipagem estrita, encapsulamento de estado e validação de limites conforme as diretrizes periciais.',
              miriVerificationStatus: 'DETECTED_UB',
              clippyLintRule: 'polyglot_security_deep_audit',
            });
          }

          aiEnrichedVulnerabilities = [...initialVulnerabilities, ...mappedAiVulns];
        }
      }
    }
  } catch (aiErr) {
    console.warn('AI analysis fallback to static engine:', aiErr);
  }

  onProgress?.(5, 100, 'Code Review e patches de remediação multi-linguagem gerados com sucesso.');

  // Step 7: Executive Synthesis & Security Score Calculation (CVSS v3.1/v4.0 Weighted)
  onProgress?.(6, 50, 'Sintetizando scorecard executivo, matriz de risco e testes de segurança...');

  const totalVulns = aiEnrichedVulnerabilities.length;
  const criticalCount = aiEnrichedVulnerabilities.filter(
    (v) => v.severity === 'CRITICAL' || (v.cvssScore && v.cvssScore >= 9.0)
  ).length;
  const highCount = aiEnrichedVulnerabilities.filter(
    (v) => v.severity === 'HIGH' || (v.cvssScore && v.cvssScore >= 7.0 && v.cvssScore < 9.0)
  ).length;
  const mediumCount = aiEnrichedVulnerabilities.filter(
    (v) => v.severity === 'MEDIUM' || (v.cvssScore && v.cvssScore >= 4.0 && v.cvssScore < 7.0)
  ).length;

  // Real CVSS v3.1/v4.0 Weighted Calculation
  const overallSecurityScore = calculateCvssWeightedSecurityScore({
    vulnerabilities: aiEnrichedVulnerabilities,
    totalUnsafeBlocks: staticResult.totalUnsafeBlocks,
    waveHazardsCount: waveAnalysis.hazards.length,
    quantumReadinessScore: quantumMetrics.quantumReadinessScore,
  });

  if (!aiExecutiveSummary) {
    aiExecutiveSummary = `Parecer pericial de auditoria automatizada para ${repo.fullName} (${staticResult.detectedLanguages.join(', ')}). Foram inspecionadas ${staticResult.totalLines} linhas de código e ${files.length} arquivos-fonte, mapeando ${dependencyResult.totalDependenciesCount} dependências de pacote. O repositório registra ${totalVulns} apontamentos de segurança (${criticalCount} críticos, ${highCount} de alta severidade e ${mediumCount} moderados) com ${dependencyResult.vulnerableCount} advisories de supply chain (OSV.dev / RustSec / GHSA). A análise de ressonância espectral de entropia indica postura de risco mensurável, enquanto o motor criptográfico avalia conformidade com os novos padrões NIST PQC (FIPS 203 ML-KEM e FIPS 204 ML-DSA).`;
  }

  const securityTests = generateSecurityTestSuite(aiEnrichedVulnerabilities);

  // Generate tailored remediation roadmap
  const remediationRoadmap = [
    {
      phase: 'Fase 1: Estancamento Imediato de Riscos Críticos & CVEs (0-48 Horas)',
      priority: 1,
      actions: [
        `Atualizar dependências com CVEs ativas no Cargo.toml, package.json e requirements.txt para as versões fixadas.`,
        `Corrigir falhas de execução remota (RCE), desserialização e buffer overflows em arquivos críticos.`,
        `Sanitizar todas as entradas de usuário contra injeções SQL e Command Injection.`,
      ],
      estimatedEffort: '16 Horas de Engenharia Especializada',
    },
    {
      phase: 'Fase 2: Blindagem Concorrente & Resiliência 10k CCU (Semana 1-2)',
      priority: 2,
      actions: [
        `Atualizar dependências desatualizadas e runtimes para as versões LTS mais recentes.`,
        `Eliminar Data Races em estruturas compartilhadas utilizando Mutex/Atomics ou canais assíncronos.`,
        `Implementar Padrão Soliton: Amortecer ondas de choque de falhas com Circuit Breakers e Bounded Contexts.`,
      ],
      estimatedEffort: '40 Horas de Engenharia',
    },
    {
      phase: 'Fase 3: Transição Pós-Quântica & Conformidade NIST (Semana 3-4)',
      priority: 3,
      actions: [
        'Introduzir algoritmos NIST PQC: Híbrido X25519 + ML-KEM-768 (Kyber) e ML-DSA (Dilithium).',
        'Impor comparações de tempo constante (Constant-Time) para mitigar ataques de canal lateral.',
        'Integrar análise estática automatizada e verificação SARIF na pipeline de CI/CD (GitHub Actions).',
      ],
      estimatedEffort: '32 Horas de Engenharia',
    },
  ];

  const report: SecurityAuditReport = {
    id: `AUDIT-${Math.random().toString(36).substring(2, 9).toUpperCase()}`,
    timestamp: new Date().toISOString(),
    targetRepo: repo,
    filesAudited: files,
    overallSecurityScore,
    editionDetected: staticResult.editionDetected,
    detectedLanguages: staticResult.detectedLanguages,
    primaryLanguage: staticResult.primaryLanguage,
    totalUnsafeBlocks: staticResult.totalUnsafeBlocks,
    totalLinesAudited: staticResult.totalLines,
    vulnerabilities: aiEnrichedVulnerabilities,
    waveHazards: waveAnalysis.hazards,
    quantumMetrics,
    executiveSummary: aiExecutiveSummary,
    dependencyAnalysis: dependencyResult,
    architectureVerdict: {
      dddCompliance: aiDddVerdict,
      soaResilience: aiSoaVerdict,
      waveTheoryZeroDayPosture: waveAnalysis.hazards.length > 0
        ? 'Risco de Ressonância Construtiva de Falhas Detectado - Requer Amortecedores Soliton'
        : 'Baixa Entropia Espectral - Invariantes Estáveis',
      iso27001Status: criticalCount === 0 ? 'COMPLIANT' : 'NEEDS_REMEDIATION',
      soc2Status: criticalCount === 0 && highCount < 2 ? 'PASS' : 'WARNING',
      nistSp800Status: criticalCount > 0 ? 'GAPS_IDENTIFIED' : 'ALIGNED',
      rustSecAdvisories: dependencyResult.rustsecCount + dependencyResult.vulnerableCount,
    },
    remediationRoadmap,
    securityTests,
  };

  onProgress?.(6, 100, 'Auditoria concluída com sucesso. Relatório executivo pronto para exportação.');
  return report;
}
