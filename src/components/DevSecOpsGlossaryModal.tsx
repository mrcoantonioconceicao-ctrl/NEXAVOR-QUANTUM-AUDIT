import React, { useState, useMemo } from 'react';
import { BookOpen, Search, X, Shield, Cpu, Layers, Radio, Lock, Zap, CheckCircle2 } from 'lucide-react';

interface GlossaryTerm {
  term: string;
  category: 'Métricas & Score' | 'Memória & AST' | 'Criptografia & PQC' | 'Supply Chain' | 'DevSecOps';
  simpleDefinition: string;
  technicalDetails: string;
  practicalImpact: string;
  recommendation: string;
}

const GLOSSARY_TERMS: GlossaryTerm[] = [
  {
    term: 'Score de Segurança Executivo',
    category: 'Métricas & Score',
    simpleDefinition: 'Nota consolidada de 0 a 100 que resume a postura geral de integridade e resiliência do repositório.',
    technicalDetails: 'Algoritmo ponderado baseado em CVSS v3.1, contagem de blocos unsafe, dependências vulneráveis (RUSTSEC/CVE) e conformidade ISO/SOC2.',
    practicalImpact: 'Scores abaixo de 70 indicam alto risco de incidentes em produção e reprovação em auditorias formais.',
    recommendation: 'Priorize a resolução de itens "Bloqueadores" para elevar o score rapidamente.',
  },
  {
    term: 'Status de Prontidão (Production Readiness)',
    category: 'Métricas & Score',
    simpleDefinition: 'Avaliação semafórica em linguagem natural que informa se o código está pronto para deploy ou se precisa de correções.',
    technicalDetails: 'Combina ausência de vulnerabilidades CRITICAL, índice de segurança de memória >= 80 e ausência de CVEs conhecidas.',
    practicalImpact: 'Evita deploys prematuros que podem causar quedas de serviço, vazamento de dados ou falhas de conformidade.',
    recommendation: 'Não realize deploy em produção se o status estiver como "Riscos Críticos Detectados".',
  },
  {
    term: 'CVSS (Common Vulnerability Scoring System)',
    category: 'Métricas & Score',
    simpleDefinition: 'Padrão internacional de 0.0 a 10.0 para mensurar a gravidade intrínseca de uma vulnerabilidade.',
    technicalDetails: 'Considera vetor de ataque (rede, local), complexidade, privilégios requeridos e impacto em confidencialidade, integridade e disponibilidade.',
    practicalImpact: 'Notas 9.0 a 10.0 (CRITICAL) permitem exploração remota grave sem autenticação.',
    recommendation: 'Corrija vulnerabilidades CVSS >= 7.0 (High/Critical) imediatamente.',
  },
  {
    term: 'Complexidade Ciclomática',
    category: 'Memória & AST',
    simpleDefinition: 'Mede quantos caminhos alternativos e ramificações condicionais (if, match, loops) existem em uma função.',
    technicalDetails: 'Calculada a partir do grafo de fluxo de controle (CFG) da Árvore Sintática Abstrata (AST) do compilador.',
    practicalImpact: 'Funções com complexidade maior que 15 são difíceis de testar completamente, gerando "pontos cegos" de segurança.',
    recommendation: 'Refatore funções complexas dividindo-as em submódulos menores ou aplicando Early Return.',
  },
  {
    term: 'Segurança de Memória (Memory Safety)',
    category: 'Memória & AST',
    simpleDefinition: 'Garantia de que o programa nunca acessará memória inválida, corrompida ou já desalocada.',
    technicalDetails: 'Em Rust, é garantida pelo borrow checker (posse e tempo de vida). Em blocos unsafe, essa garantia é desativada.',
    practicalImpact: 'Falhas de memória respondem por ~70% de todas as falhas de segurança graves (Microsoft/Chromium CVE studies).',
    recommendation: 'Substitua blocos unsafe e ponteiros brutos por tipos seguros da biblioteca padrão ou smart pointers (Arc, Mutex).',
  },
  {
    term: 'Blocos Unsafe e Ponteiros Brutos (*const T, *mut T)',
    category: 'Memória & AST',
    simpleDefinition: 'Trechos de código onde o desenvolvedor assume a responsabilidade manual por checagens de ponteiro e limites.',
    technicalDetails: 'Permitem desreferenciação direta de endereços de memória, conversão bruta (transmute) e chamadas FFI C.',
    practicalImpact: 'Um único ponteiro inválido pode causar Buffer Overflow, Use-After-Free ou Kernel Panic.',
    recommendation: 'Encapsule qualquer necessidade de baixo nível atrás de APIs seguras e execute o teste MIRI.',
  },
  {
    term: 'Resistência Quântica (PQC - Post-Quantum Cryptography)',
    category: 'Criptografia & PQC',
    simpleDefinition: 'Capacidade dos algoritmos criptográficos resistirem a ataques futuros executados por computadores quânticos.',
    technicalDetails: 'Criptografia assimétrica tradicional (RSA, ECC) é quebrada pelo Algoritmo de Shor. PQC utiliza reticulados (ML-KEM, Kyber, Dilithium).',
    practicalImpact: 'Ataques "Store Now, Decrypt Later" já capturam tráfego criptografado hoje para decifrá-lo quando computadores quânticos estiverem operacionais.',
    recommendation: 'Migre chaves assimétricas para padrões NIST FIPS 203/204 (ML-KEM e ML-DSA).',
  },
  {
    term: 'Algoritmo de Shor',
    category: 'Criptografia & PQC',
    simpleDefinition: 'Algoritmo quântico que fatora números inteiros e calcula logaritmos discretos em tempo polinomial rápido.',
    technicalDetails: 'Quebra matematicamente chaves RSA (2048/4096) e curvas elípticas (Ed25519, secp256k1).',
    practicalImpact: 'Torna obsoleta a assinatura digital e troca de chaves convencional em um horizonte de 5 a 10 anos.',
    recommendation: 'Utilize esquemas híbridos clássico + quântico na camada de transporte TLS.',
  },
  {
    term: 'Supply Chain & RUSTSEC Advisories',
    category: 'Supply Chain',
    simpleDefinition: 'Auditoria de bibliotecas de terceiros (crates / dependências) listadas no Cargo.lock.',
    technicalDetails: 'Cruzamento com o banco de dados oficial RustSec Advisory e CVEs do National Vulnerability Database (NVD).',
    practicalImpact: 'Mesmo que seu código seja perfeito, uma biblioteca externa com backdoor ou RCE compromete o sistema inteiro.',
    recommendation: 'Atualize as versões das crates no Cargo.toml conforme sugerido na ferramenta.',
  },
  {
    term: 'Teoria de Ondas e Ressonância Zero-Day',
    category: 'DevSecOps',
    simpleDefinition: 'Modelo preditivo que analisa a densidade de alterações e acoplamento de código para antecipar falhas antes de virarem incidentes.',
    technicalDetails: 'Mapeia variações de entropia espectral e efeitos cascata na fronteira de módulos.',
    practicalImpact: 'Identifica trechos de código instáveis onde futuros bugs de dia zero têm maior probabilidade estatística de surgir.',
    recommendation: 'Diminua o acoplamento entre módulos e aumente a cobertura de testes nas zonas de alta entropia.',
  },
  {
    term: 'MIRI (Rust Undefined Behavior Detector)',
    category: 'Memória & AST',
    simpleDefinition: 'Ferramenta de interpretação do compilador Rust que detecta comportamentos indefinidos em tempo de execução.',
    technicalDetails: 'Monitora violações de Stacked Borrows / Tree Borrows, vazamentos de memória e acessos fora dos limites.',
    practicalImpact: 'Detecta bugs silenciosos que passam desapercebidos em testes normais mas causam falhas aleatórias em produção.',
    recommendation: 'Rode "cargo miri test" regularmente no seu pipeline de integração contínua (CI).',
  },
];

interface DevSecOpsGlossaryModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const DevSecOpsGlossaryModal: React.FC<DevSecOpsGlossaryModalProps> = ({
  isOpen,
  onClose,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('TODAS');

  const categories = ['TODAS', 'Métricas & Score', 'Memória & AST', 'Criptografia & PQC', 'Supply Chain', 'DevSecOps'];

  const filteredTerms = useMemo(() => {
    return GLOSSARY_TERMS.filter((item) => {
      const matchCategory = selectedCategory === 'TODAS' || item.category === selectedCategory;
      const matchSearch =
        searchTerm.trim() === '' ||
        item.term.toLowerCase().includes(searchTerm.toLowerCase()) ||
        item.simpleDefinition.toLowerCase().includes(searchTerm.toLowerCase()) ||
        item.technicalDetails.toLowerCase().includes(searchTerm.toLowerCase());
      return matchCategory && matchSearch;
    });
  }, [searchTerm, selectedCategory]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="bg-zinc-900 border border-zinc-700 rounded-xl max-w-3xl w-full max-h-[85vh] flex flex-col shadow-2xl overflow-hidden font-sans">
        {/* Header */}
        <div className="px-6 py-4 border-b border-zinc-800 flex items-center justify-between bg-zinc-950/60">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-emerald-950/60 border border-emerald-500/30 text-emerald-400">
              <BookOpen className="h-5 w-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white font-mono flex items-center gap-2">
                <span>Glossário DevSecOps & Engenharia</span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-zinc-800 text-zinc-400 font-normal">
                  {filteredTerms.length} termos
                </span>
              </h3>
              <p className="text-xs text-zinc-400">
                Guia contextual em linguagem natural e direta para desenvolvedores e engenheiros.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-zinc-400 hover:text-white p-1 rounded-lg hover:bg-zinc-800 transition-colors cursor-pointer"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Search & Category Filter */}
        <div className="p-4 border-b border-zinc-800 bg-zinc-900/80 space-y-3">
          <div className="relative">
            <Search className="h-4 w-4 absolute left-3 top-1/2 -translate-y-1/2 text-zinc-400" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Buscar termo, métrica ou conceito (ex: PQC, Unsafe, CVSS, Complexidade)..."
              className="w-full pl-9 pr-4 py-2 bg-zinc-950 border border-zinc-800 focus:border-emerald-500 rounded-lg text-xs text-zinc-200 outline-none font-mono"
            />
          </div>

          <div className="flex items-center gap-1.5 flex-wrap overflow-x-auto pb-1 text-xs">
            {categories.map((cat) => (
              <button
                key={cat}
                onClick={() => setSelectedCategory(cat)}
                className={`px-2.5 py-1 rounded-md text-[11px] font-mono font-medium transition-colors cursor-pointer ${
                  selectedCategory === cat
                    ? 'bg-emerald-600 text-white shadow-xs'
                    : 'bg-zinc-800/80 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200'
                }`}
              >
                {cat}
              </button>
            ))}
          </div>
        </div>

        {/* Content List */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4 divide-y divide-zinc-800/70">
          {filteredTerms.length === 0 ? (
            <div className="text-center py-12 text-zinc-500 font-mono text-xs">
              Nenhum termo encontrado para a busca "{searchTerm}".
            </div>
          ) : (
            filteredTerms.map((term, idx) => (
              <div key={idx} className={`space-y-2.5 ${idx > 0 ? 'pt-4' : ''}`}>
                <div className="flex items-start sm:items-center justify-between gap-2 flex-wrap">
                  <h4 className="text-sm font-bold text-white font-mono flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-emerald-400" />
                    <span>{term.term}</span>
                  </h4>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-800 text-zinc-300 border border-zinc-700">
                    {term.category}
                  </span>
                </div>

                {/* Direct Simple Definition */}
                <div className="text-xs text-zinc-300 leading-relaxed bg-zinc-950/60 p-3 rounded-lg border border-zinc-800/80">
                  <span className="font-bold text-emerald-400 font-mono uppercase text-[10px] block mb-1">
                    O que significa na prática:
                  </span>
                  {term.simpleDefinition}
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[11px]">
                  <div className="p-2.5 rounded bg-zinc-950/40 border border-zinc-800/60">
                    <span className="font-bold text-zinc-400 font-mono uppercase text-[10px] block mb-0.5">
                      Detalhe Técnico:
                    </span>
                    <span className="text-zinc-400 leading-relaxed">{term.technicalDetails}</span>
                  </div>
                  <div className="p-2.5 rounded bg-amber-950/20 border border-amber-900/30">
                    <span className="font-bold text-amber-400 font-mono uppercase text-[10px] block mb-0.5">
                      Impacto Prático no Projeto:
                    </span>
                    <span className="text-amber-200/90 leading-relaxed">{term.practicalImpact}</span>
                  </div>
                </div>

                <div className="text-[11px] text-zinc-400 flex items-start gap-1.5 pt-1">
                  <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0 mt-0.5" />
                  <span>
                    <strong className="text-zinc-300 font-mono uppercase text-[10px]">Recomendação:</strong> {term.recommendation}
                  </span>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-zinc-800 bg-zinc-950 flex items-center justify-between text-xs text-zinc-500 font-mono">
          <span>RustShield Quantum DevSecOps Knowledge Base</span>
          <button
            onClick={onClose}
            className="px-3 py-1 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 rounded font-medium transition-colors cursor-pointer"
          >
            Fechar
          </button>
        </div>
      </div>
    </div>
  );
};
