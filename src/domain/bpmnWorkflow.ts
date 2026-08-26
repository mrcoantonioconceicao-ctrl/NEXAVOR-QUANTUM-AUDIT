import { BpmnStep } from './types.ts';

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
