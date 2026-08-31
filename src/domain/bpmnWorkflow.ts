import { BpmnStep } from './types.ts';

export const REFACTOR_BPMN_WORKFLOW_STEPS: BpmnStep[] = [
  {
    id: 'bpmn-step-1-audit',
    name: '1. Ingestão & Auditoria de Ativos',
    role: 'SOA_INGESTION',
    status: 'PENDING',
    description: 'Resolução da árvore de código-fonte, mapeamento de dependências e parsing da AST.',
    progressPercent: 0,
    details: [],
  },
  {
    id: 'bpmn-step-2-vuln-detect',
    name: '2. Detecção de Vulnerabilidades (OWASP & PQC)',
    role: 'AST_ANALYSIS',
    status: 'PENDING',
    description: 'Mapeamento determinístico de falhas de memória, injeções, chamadas dinâmicas e primitivas quânticas obsoletas.',
    progressPercent: 0,
    details: [],
  },
  {
    id: 'bpmn-step-3-sla-eval',
    name: '3. Avaliação de SLA & Governança GRC',
    role: 'SUPPLY_CHAIN_CVE',
    status: 'PENDING',
    description: 'Cálculo de métricas FAIR (ALE/ROSI) e verificação do SLA de segurança (ISO 27001 / NIST SP 800-218).',
    progressPercent: 0,
    details: [],
  },
  {
    id: 'bpmn-step-4-decision-gateway',
    name: '4. Decision Gateway: In-Place vs. Polyglot Migration',
    role: 'CODE_REVIEW',
    status: 'PENDING',
    description: 'Gateway BPMN: Avalia se o target deve ser Hardening In-Place (mesma linguagem) ou Migração Polyglot (Rust/Go).',
    progressPercent: 0,
    details: [],
  },
  {
    id: 'bpmn-step-5-ast-rag-refactor',
    name: '5. Refatoração AST + RAG (Gemini AI Engine)',
    role: 'AST_ANALYSIS',
    status: 'PENDING',
    description: 'Execução da refatoração guiada por normas RAG (NIST SP 800-218, PCI-DSS v4.0, FIPS 203/204/205).',
    progressPercent: 0,
    details: [],
  },
  {
    id: 'bpmn-step-6-ledger-signing',
    name: '6. Assinatura PQC em Ledger Inviolável',
    role: 'QUANTUM_CRYPTO',
    status: 'PENDING',
    description: 'Geração de carimbo criptográfico com assinatura ML-DSA-65 e hash SHA-256 no audit trail do RustShield.',
    progressPercent: 0,
    details: [],
  },
  {
    id: 'bpmn-step-7-github-pr-ci',
    name: '7. Notificação de Gate CI/CD & GitHub PR',
    role: 'EXECUTIVE_SYNTHESIS',
    status: 'PENDING',
    description: 'Cometimento do código refatorado em nova branch isolada e abertura automatizada de Pull Request com relatório.',
    progressPercent: 0,
    details: [],
  },
];

export const INITIAL_BPMN_STEPS: BpmnStep[] = [
  {
    id: 'step-1-ingest',
    name: '1. SOA Gateway & Ingestão Git',
    role: 'SOA_INGESTION',
    status: 'PENDING',
    description: 'Resolução de árvore Git, validação de integridade e extração dos manifestos e código-fonte.',
    progressPercent: 0,
    details: [],
  },
  {
    id: 'step-2-supply-chain',
    name: '2. Supply Chain & CVEs em Tempo Real',
    role: 'SUPPLY_CHAIN_CVE',
    status: 'PENDING',
    description: 'Auditoria de Cargo.toml, package.json, requirements.txt, go.mod com consulta à base RustSec e OSV/NVD.',
    progressPercent: 0,
    details: [],
  },
  {
    id: 'step-3-ast',
    name: '3. Análise Estática de AST & Memory Safety',
    role: 'AST_ANALYSIS',
    status: 'PENDING',
    description: 'Auditoria de padrões inseguros, blocos `unsafe`, injeções SQL/Command, UAF e falhas de concorrência.',
    progressPercent: 0,
    details: [],
  },
  {
    id: 'step-4-wave',
    name: '4. Teoria das Ondas & Previsão de 0-Day',
    role: 'WAVE_ZERO_DAY',
    status: 'PENDING',
    description: 'Cálculo de entropia espectral, ressonância construtiva de hazards e amortecedores Soliton.',
    progressPercent: 0,
    details: [],
  },
  {
    id: 'step-5-pqc',
    name: '5. Criptografia Pós-Quântica (NIST PQC)',
    role: 'QUANTUM_CRYPTO',
    status: 'PENDING',
    description: 'Avaliação de resistência contra Shor/Grover, conformidade NIST FIPS 203/204 e ataques de temporização.',
    progressPercent: 0,
    details: [],
  },
  {
    id: 'step-6-review',
    name: '6. Code Review Especializado & Patches',
    role: 'CODE_REVIEW',
    status: 'PENDING',
    description: 'Geração de patches idiomáticos (Antes vs Depois), barreiras RAII e mitigação de vulnerabilidades.',
    progressPercent: 0,
    details: [],
  },
  {
    id: 'step-7-synthesis',
    name: '7. Síntese Executiva & Relatórios SARIF/PDF',
    role: 'EXECUTIVE_SYNTHESIS',
    status: 'PENDING',
    description: 'Consolidação de métricas CVSS 4.0, NIST SP 800-218, ISO 27001 e geração do relatório executivo.',
    progressPercent: 0,
    details: [],
  },
];

export function advanceBpmnStep(
  steps: BpmnStep[],
  activeStepIndex: number,
  progress: number,
  detailMessage?: string
): BpmnStep[] {
  return steps.map((step, idx) => {
    if (idx < activeStepIndex) {
      return { ...step, status: 'COMPLETED', progressPercent: 100 };
    }
    if (idx === activeStepIndex) {
      const details = detailMessage
        ? [...(step.details || []), `[${new Date().toLocaleTimeString()}] ${detailMessage}`]
        : step.details;
      return {
        ...step,
        status: progress >= 100 ? 'COMPLETED' : 'RUNNING',
        progressPercent: Math.min(100, progress),
        timestamp: new Date().toISOString(),
        details,
      };
    }
    return { ...step, status: 'PENDING', progressPercent: 0 };
  });
}
