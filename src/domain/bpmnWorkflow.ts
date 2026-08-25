import { BpmnStep } from './types.ts';

export const INITIAL_BPMN_STEPS: BpmnStep[] = [
  {
    id: 'step-1-ingest',
    name: '1. SOA Gateway & GitHub Ingestion',
    role: 'SOA_INGESTION',
    status: 'PENDING',
    description: 'Resolução de árvore Git, validação de payload e extração de crates (.rs, Cargo.toml, Cargo.lock).',
    progressPercent: 0,
    details: [],
  },
  {
    id: 'step-2-ast',
    name: '2. AST & Unsafe Pattern Analysis',
    role: 'AST_ANALYSIS',
    status: 'PENDING',
    description: 'Auditoria de padrões legados, `unsafe` blocks, `std::mem::uninitialized`, aliasing e alinhamento.',
    progressPercent: 0,
    details: [],
  },
  {
    id: 'step-3-wave',
    name: '3. Zero-Day Wave Theory & Spectral Modeling',
    role: 'WAVE_ZERO_DAY',
    status: 'PENDING',
    description: 'Cálculo de entropia espectral, ressonância construtiva de hazards e amortecedores Soliton.',
    progressPercent: 0,
    details: [],
  },
  {
    id: 'step-4-pqc',
    name: '4. Post-Quantum Cryptography & Shor Audit',
    role: 'QUANTUM_CRYPTO',
    status: 'PENDING',
    description: 'Avaliação de resistência contra algoritmos de Shor e Grover, compliance NIST PQC e Timing Attacks.',
    progressPercent: 0,
    details: [],
  },
  {
    id: 'step-5-review',
    name: '5. DDD Code Review & Miri Remediations',
    role: 'CODE_REVIEW',
    status: 'PENDING',
    description: 'Geração de patches idiomáticos Rust 2021/2024, mitigação de Use-After-Free e RAII barriers.',
    progressPercent: 0,
    details: [],
  },
  {
    id: 'step-6-synthesis',
    name: '6. Executive PDF Report & SARIF Synthesis',
    role: 'EXECUTIVE_SYNTHESIS',
    status: 'PENDING',
    description: 'Consolidação de métricas CVSS 4.0, NIST SP 800-218, ISO 27001 e geração do relatório C-Level.',
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
