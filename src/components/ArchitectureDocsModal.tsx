import React from 'react';
import { Layers, Cpu, GitBranch, Terminal, Award, Code2 } from 'lucide-react';

export const ArchitectureDocsModal: React.FC = () => {
  return (
    <div className="space-y-6 max-w-7xl mx-auto px-4 sm:px-6 py-6 font-sans text-zinc-300">
      {/* Header Banner */}
      <div className="rounded border border-zinc-800 bg-zinc-900/40 p-5 space-y-2">
        <div className="flex items-center gap-2">
          <Award className="h-4 w-4 text-emerald-400" />
          <span className="text-[10px] font-mono font-bold text-emerald-400 uppercase tracking-widest">
            ARQUITETURA ENTERPRISE // POLYGLOT ALL-LANGUAGES, DDD, SOA, BPMN, PQC & 10K CCU
          </span>
        </div>
        <h2 className="text-xl font-bold text-white font-mono uppercase">
          Especificação Arquitetural de 15 Anos de Engenharia de Cibersegurança
        </h2>
        <p className="text-xs text-zinc-400 max-w-3xl leading-relaxed">
          Fundamentado em análise estática poliglota, protocolos criptográficos de computação quântica (MIT Science), dimensionamento para 10.000 clientes simultâneos e modelagem matemática de perturbação de ondas para prevenção antecipada de vulnerabilidades Zero-Day.
        </p>
      </div>

      {/* Polyglot Engine Matrix Card */}
      <div className="rounded border border-zinc-800 bg-zinc-900/50 p-5 border-l-2 border-l-emerald-400 space-y-3">
        <div className="flex items-center gap-2 text-emerald-400">
          <Code2 className="h-4 w-4" />
          <h3 className="text-sm font-bold font-mono uppercase tracking-wider">
            Matriz de Cobertura Multi-Linguagem (Universal Polyglot Engine)
          </h3>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 pt-1 text-xs font-mono">
          <div className="p-3 rounded bg-zinc-950 border border-zinc-800 space-y-1">
            <div className="text-emerald-400 font-bold">Rust (2015 - 2024)</div>
            <p className="text-zinc-400 text-[11px]">
              Blocos unsafe, UB em std::mem::uninitialized, aliasing mutável, static mut, Send/Sync, Tokio async deadlocks e panics em Drop.
            </p>
          </div>
          <div className="p-3 rounded bg-zinc-950 border border-zinc-800 space-y-1">
            <div className="text-emerald-400 font-bold">Python (3.8 - 3.12)</div>
            <p className="text-zinc-400 text-[11px]">
              Desserialização RCE (pickle/cPickle), os.system, PyYAML sem SafeLoader, SQLi em f-strings, hashes fracos MD5/DES e FastAPI misconfig.
            </p>
          </div>
          <div className="p-3 rounded bg-zinc-950 border border-zinc-800 space-y-1">
            <div className="text-emerald-400 font-bold">TypeScript / Node.js</div>
            <p className="text-zinc-400 text-[11px]">
              Prototype Pollution, bypass de JWT com jwt.decode, Buffer.allocUnsafe (vazamento de heap), child_process.exec e ReDoS.
            </p>
          </div>
          <div className="p-3 rounded bg-zinc-950 border border-zinc-800 space-y-1">
            <div className="text-emerald-400 font-bold">Go (Golang 1.20+)</div>
            <p className="text-zinc-400 text-[11px]">
              Data Races em maps sob 10k CCU, vazamento de goroutines, unsafe.Pointer sem alinhamento de GC e SQLi com fmt.Sprintf.
            </p>
          </div>
          <div className="p-3 rounded bg-zinc-950 border border-zinc-800 space-y-1">
            <div className="text-emerald-400 font-bold">C / C++ (C11 - C++23)</div>
            <p className="text-zinc-400 text-[11px]">
              Buffer Overflow (strcpy/sprintf), Format String (printf(var)), Use-After-Free (UAF), Double Free e vazamento de memória.
            </p>
          </div>
          <div className="p-3 rounded bg-zinc-950 border border-zinc-800 space-y-1">
            <div className="text-emerald-400 font-bold">Solidity / Web3</div>
            <p className="text-zinc-400 text-[11px]">
              Ataques de Reentrância (SWC-107), autenticação fraca via tx.origin (SWC-115), overflow/underflow e manipulação de oráculos.
            </p>
          </div>
        </div>
      </div>

      {/* 4 Architectural Pillars Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Pillar 1: DDD (Domain-Driven Design) */}
        <div className="rounded border border-zinc-800 bg-zinc-900/50 p-5 border-l-2 border-l-emerald-500 space-y-3">
          <div className="flex items-center gap-2 text-emerald-400">
            <Layers className="h-4 w-4" />
            <h3 className="text-sm font-bold font-mono uppercase tracking-wider">1. Domain-Driven Design (DDD)</h3>
          </div>
          <p className="text-xs text-zinc-400 leading-relaxed">
            O auditor estrutura a análise em Bounded Contexts estritamente isolados:
          </p>
          <ul className="space-y-2 text-xs text-zinc-400 list-disc list-inside font-mono">
            <li>
              <strong className="text-zinc-200">Bounded Context de Invariantes de Memória & RCE:</strong> Garantia estática de memória, limites de buffers e ausência de desserialização insegura.
            </li>
            <li>
              <strong className="text-zinc-200">Bounded Context de Concorrência & 10k CCU:</strong> Isolamento de tarefas assíncronas com cooperação estrita e barreira semântica contra data races.
            </li>
            <li>
              <strong className="text-zinc-200">Bounded Context Criptográfico Pós-Quântico:</strong> Abstração agnóstica de primitivas para rotação a quente de algoritmos clássicos para ML-KEM e ML-DSA.
            </li>
          </ul>
        </div>

        {/* Pillar 2: SOA & Hexagonal Architecture */}
        <div className="rounded border border-zinc-800 bg-zinc-900/50 p-5 border-l-2 border-l-blue-500 space-y-3">
          <div className="flex items-center gap-2 text-blue-400">
            <Terminal className="h-4 w-4" />
            <h3 className="text-sm font-bold font-mono uppercase tracking-wider">2. SOA & Hexagonal Architecture</h3>
          </div>
          <p className="text-xs text-zinc-400 leading-relaxed">
            O backend Express + motor de análise segue o padrão Hexagonal (Ports & Adapters):
          </p>
          <ul className="space-y-2 text-xs text-zinc-400 list-disc list-inside font-mono">
            <li>
              <strong className="text-zinc-200">Porta de Ingestão Git:</strong> Adaptador multi-linguagem para GitHub REST API com resolução inteligente de branches, download direto de arquivos reais e zero dados mockados no pipeline de análise.
            </li>
            <li>
              <strong className="text-zinc-200">Porta de Raciocínio Semântico:</strong> Comunicação com Gemini do lado do servidor via `@google/genai` sem exposição de credenciais no cliente.
            </li>
            <li>
              <strong className="text-zinc-200">Porta de Exportação SARIF/PDF:</strong> Geração de relatórios executivos para C-Levels e integração com pipelines de CI/CD.
            </li>
          </ul>
        </div>

        {/* Pillar 3: BPMN 2.0 State Machine */}
        <div className="rounded border border-zinc-800 bg-zinc-900/50 p-5 border-l-2 border-l-purple-500 space-y-3">
          <div className="flex items-center gap-2 text-purple-400">
            <GitBranch className="h-4 w-4" />
            <h3 className="text-sm font-bold font-mono uppercase tracking-wider">3. BPMN 2.0 State Machine</h3>
          </div>
          <p className="text-xs text-zinc-400 leading-relaxed">
            O fluxo de auditoria segue uma máquina de estados finita com transições auditáveis:
          </p>
          <div className="p-3 rounded bg-zinc-950 border border-zinc-800 text-[11px] font-mono text-zinc-400 space-y-1">
            <div><span className="text-emerald-400">[Start]</span> ➔ Polyglot Ingestion & Tree Resolver</div>
            <div>➔ <span className="text-purple-400">[Gateway: Polyglot AST Scanner]</span> ➔ AST & Unsafe Pattern Scanner</div>
            <div>➔ Wave Theory Spectral Modeling ➔ Quantum Crypto Shor Audit</div>
            <div>➔ Code Review & Patch Generation ➔ <span className="text-emerald-400">[End]</span> Executive PDF Synthesis</div>
          </div>
        </div>

        {/* Pillar 4: MIT Quantum Info & Zero-Day Wave Theory */}
        <div className="rounded border border-zinc-800 bg-zinc-900/50 p-5 border-l-2 border-l-amber-500 space-y-3">
          <div className="flex items-center gap-2 text-amber-400">
            <Cpu className="h-4 w-4" />
            <h3 className="text-sm font-bold font-mono uppercase tracking-wider">4. PQC (MIT Lab) & Teoria das Ondas</h3>
          </div>
          <p className="text-xs text-zinc-400 leading-relaxed">
            Fundamentos de Física Matemática aplicados à cibersegurança de qualquer linguagem:
          </p>
          <ul className="space-y-2 text-xs text-zinc-400 list-disc list-inside font-mono">
            <li>
              <strong className="text-zinc-200">Teoria das Ondas para Zero-Days:</strong> Como 0-days são anomalias desconhecidas, calculamos a interferência construtiva de perturbações de estado no grafo de dependências.
            </li>
            <li>
              <strong className="text-zinc-200">Amortecedores Soliton:</strong> Injeção de guardas monádicas que impedem a dispersão da onda de choque através das bordas dos microsserviços.
            </li>
            <li>
              <strong className="text-zinc-200">Resistência Quântica NIST FIPS 203/204:</strong> Migração de chaves clássicas quebráveis por Shor para ML-KEM e ML-DSA.
            </li>
          </ul>
        </div>
      </div>
    </div>
  );
};
