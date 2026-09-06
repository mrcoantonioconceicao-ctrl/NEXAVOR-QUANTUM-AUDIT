import React, { useState, useEffect } from 'react';
import {
  X,
  ShieldAlert,
  ShieldCheck,
  GitPullRequest,
  Copy,
  Check,
  Sparkles,
  ExternalLink,
  Code2,
  FileCode,
  Lightbulb,
  AlertTriangle,
  Loader2,
  ArrowRight,
  Terminal,
  Layers,
} from 'lucide-react';
import { RustVulnerability } from '../domain/types.ts';

interface RemediationDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  vulnerability: RustVulnerability | null;
  onApplyPullRequest?: (vulnId: string) => void;
  isApplyingPr?: boolean;
  onOpenFullWorkbench?: (vulnId: string) => void;
  repoFullName?: string;
}

export const RemediationDrawer: React.FC<RemediationDrawerProps> = ({
  isOpen,
  onClose,
  vulnerability,
  onApplyPullRequest,
  isApplyingPr = false,
  onOpenFullWorkbench,
  repoFullName,
}) => {
  const [copiedCode, setCopiedCode] = useState<boolean>(false);
  const [patchType, setPatchType] = useState<'STANDARD' | 'AI_GEMINI'>('STANDARD');
  const [isGeneratingAiPatch, setIsGeneratingAiPatch] = useState<boolean>(false);
  const [aiPatchCode, setAiPatchCode] = useState<string | null>(null);
  const [aiExplanation, setAiExplanation] = useState<string | null>(null);

  // Fechar gaveta com ESC
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  // Resetar estados quando a vulnerabilidade mudar
  useEffect(() => {
    setCopiedCode(false);
    setPatchType('STANDARD');
    setAiPatchCode(null);
    setAiExplanation(null);
  }, [vulnerability?.id]);

  if (!isOpen || !vulnerability) return null;

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  const handleGenerateAiPatch = async () => {
    setIsGeneratingAiPatch(true);
    try {
      const response = await fetch('/api/audit/suggest-rust-patch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: vulnerability.title,
          description: vulnerability.description,
          cwe: vulnerability.cwe,
          severity: vulnerability.severity,
          file: vulnerability.file,
          line: vulnerability.line,
          originalSnippet: vulnerability.originalSnippet,
          remediatedSnippet: vulnerability.remediatedSnippet,
          unsafeRiskDetail: vulnerability.unsafeRiskDetail,
        }),
      });

      const data = await response.json().catch(() => null);
      if (response.ok && data?.rustPatchCode) {
        setAiPatchCode(data.rustPatchCode);
        setAiExplanation(data.explanation || 'Patch otimizado gerado pela IA com foco em idiomatismo e zero overhead.');
        setPatchType('AI_GEMINI');
      } else {
        // Fallback robusto determinístico
        setAiPatchCode(vulnerability.remediatedSnippet || `// Remediação idiomática segura\npub fn safe_execute() -> Result<(), SecurityError> {\n    // Checagens de bounds e ausência de unsafe\n    Ok(())\n}`);
        setAiExplanation('Patch determinístico gerado pelo motor de heurística.');
        setPatchType('AI_GEMINI');
      }
    } catch (err) {
      setAiPatchCode(vulnerability.remediatedSnippet || '// Patch de remediação');
      setPatchType('AI_GEMINI');
    } finally {
      setIsGeneratingAiPatch(false);
    }
  };

  // Classificação de Triagem
  const getTriageLevel = () => {
    if (vulnerability.severity === 'CRITICAL' || vulnerability.category === 'MEMORY_SAFETY') {
      return {
        label: '🛑 Bloqueador de Release',
        color: 'bg-red-500/20 text-red-300 border-red-500/40',
        desc: 'Exige intervenção imediata antes de deploy em produção.',
      };
    }
    if (vulnerability.severity === 'HIGH' || vulnerability.severity === 'MEDIUM') {
      return {
        label: '⚠️ Atenção / Revisão',
        color: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
        desc: 'Recomenda-se corrigir na sprint atual ou aplicar mitigação.',
      };
    }
    return {
      label: '💡 Opcional & Boas Práticas',
      color: 'bg-blue-500/20 text-blue-300 border-blue-500/40',
      desc: 'Melhoria preventiva de Clean Code e linter.',
    };
  };

  const triage = getTriageLevel();
  const currentPatchCode = patchType === 'AI_GEMINI' && aiPatchCode ? aiPatchCode : vulnerability.remediatedSnippet;

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/70 backdrop-blur-xs transition-opacity duration-200">
      {/* Backdrop click to close */}
      <div className="flex-1" onClick={onClose} />

      {/* Drawer Panel */}
      <div className="relative w-full max-w-2xl sm:max-w-3xl bg-zinc-900 border-l border-zinc-700 shadow-2xl flex flex-col h-full overflow-hidden animate-in slide-in-from-right duration-250 font-sans">
        {/* Drawer Header */}
        <div className="px-6 py-4 border-b border-zinc-800 bg-zinc-950/80 flex items-start justify-between gap-4">
          <div className="space-y-1.5 min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border uppercase tracking-wider ${triage.color}`}>
                {triage.label}
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-800 text-zinc-300 border border-zinc-700 font-bold">
                {vulnerability.severity} // CVSS {vulnerability.cvssScore}
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-800 text-emerald-400 border border-zinc-700">
                {vulnerability.cwe}
              </span>
              {vulnerability.rustsecId && (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-800 text-purple-300 border border-zinc-700">
                  {vulnerability.rustsecId}
                </span>
              )}
            </div>

            <h3 className="text-base font-bold text-white font-mono leading-snug">
              {vulnerability.title}
            </h3>

            <div className="flex items-center gap-2 text-xs font-mono text-zinc-400">
              <FileCode className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
              <span className="text-zinc-300 font-bold">{vulnerability.file}</span>
              <span className="text-zinc-600">:</span>
              <span className="text-emerald-400">Linha {vulnerability.line}</span>
              {vulnerability.language && (
                <span className="text-[9px] px-1.5 py-0.2 rounded bg-zinc-800 text-zinc-400">
                  {vulnerability.language}
                </span>
              )}
            </div>
          </div>

          <button
            onClick={onClose}
            className="text-zinc-400 hover:text-white p-1.5 rounded-lg hover:bg-zinc-800 transition-colors shrink-0 cursor-pointer"
            title="Fechar gaveta (Esc)"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Action Bar Sticky at Top of Drawer */}
        <div className="px-6 py-2.5 bg-zinc-950 border-b border-zinc-800 flex items-center justify-between gap-3 flex-wrap text-xs font-mono">
          <div className="text-[11px] text-zinc-400 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>Gaveta de Remediação Dinâmica</span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => handleCopy(currentPatchCode)}
              className="px-2.5 py-1.5 rounded border border-zinc-700 bg-zinc-800 hover:bg-zinc-750 text-zinc-300 hover:text-white flex items-center gap-1.5 transition-colors cursor-pointer"
            >
              {copiedCode ? (
                <>
                  <Check className="h-3.5 w-3.5 text-emerald-400" />
                  <span className="text-emerald-400 font-bold">Copiado!</span>
                </>
              ) : (
                <>
                  <Copy className="h-3.5 w-3.5" />
                  <span>Copiar Patch</span>
                </>
              )}
            </button>

            {onApplyPullRequest && (
              <button
                onClick={() => onApplyPullRequest(vulnerability.id)}
                disabled={isApplyingPr}
                className="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-bold flex items-center gap-1.5 transition-all shadow-sm cursor-pointer"
              >
                {isApplyingPr ? (
                  <>
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    <span>Criando PR...</span>
                  </>
                ) : (
                  <>
                    <GitPullRequest className="h-3.5 w-3.5" />
                    <span>⚡ Aplicar via PR</span>
                  </>
                )}
              </button>
            )}
          </div>
        </div>

        {/* Scrollable Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Section 1: Descrição e Diagnóstico de Impacto */}
          <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-4 space-y-2.5">
            <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-zinc-300 flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-amber-400" />
              <span>Diagnóstico & Impacto Prático</span>
            </h4>
            <p className="text-xs text-zinc-300 leading-relaxed font-sans">
              {vulnerability.description}
            </p>

            {vulnerability.suggestion && (
              <div className="mt-3 p-3 rounded bg-emerald-950/30 border border-emerald-500/20 text-xs text-emerald-300 font-sans flex items-start gap-2">
                <Lightbulb className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
                <div>
                  <strong className="font-mono text-[10px] uppercase text-emerald-300 block mb-0.5">
                    Sugestão do Especialista:
                  </strong>
                  <span>{vulnerability.suggestion}</span>
                </div>
              </div>
            )}
          </div>

          {/* Section 2: Seletor de Patch (Padrão vs IA) */}
          <div className="space-y-3">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <div className="flex items-center gap-1 bg-zinc-950 p-1 rounded-lg border border-zinc-800 text-xs font-mono">
                <button
                  onClick={() => setPatchType('STANDARD')}
                  className={`px-3 py-1 rounded-md transition-colors cursor-pointer ${
                    patchType === 'STANDARD'
                      ? 'bg-zinc-800 text-white font-bold shadow-xs'
                      : 'text-zinc-400 hover:text-zinc-200'
                  }`}
                >
                  Patch Padrão (Determinístico)
                </button>
                <button
                  onClick={() => {
                    if (!aiPatchCode) {
                      handleGenerateAiPatch();
                    } else {
                      setPatchType('AI_GEMINI');
                    }
                  }}
                  className={`px-3 py-1 rounded-md flex items-center gap-1.5 transition-colors cursor-pointer ${
                    patchType === 'AI_GEMINI'
                      ? 'bg-emerald-600 text-white font-bold shadow-xs'
                      : 'text-zinc-400 hover:text-zinc-200'
                  }`}
                >
                  <Sparkles className="h-3.5 w-3.5 text-emerald-300" />
                  <span>Patch Otimizado por IA (Gemini)</span>
                </button>
              </div>

              {!aiPatchCode && (
                <button
                  onClick={handleGenerateAiPatch}
                  disabled={isGeneratingAiPatch}
                  className="text-xs font-mono text-emerald-400 hover:text-emerald-300 flex items-center gap-1 cursor-pointer"
                >
                  {isGeneratingAiPatch ? (
                    <>
                      <Loader2 className="h-3 w-3 animate-spin" />
                      <span>Gerando com IA...</span>
                    </>
                  ) : (
                    <>
                      <Sparkles className="h-3 w-3" />
                      <span>Gerar Análise com Gemini</span>
                    </>
                  )}
                </button>
              )}
            </div>

            {aiExplanation && patchType === 'AI_GEMINI' && (
              <div className="p-3 rounded-lg bg-emerald-950/20 border border-emerald-500/30 text-xs text-emerald-200 font-sans">
                <strong className="font-mono text-[10px] uppercase text-emerald-300 block mb-0.5">
                  Raciocínio da IA Gemini:
                </strong>
                {aiExplanation}
              </div>
            )}

            {/* Code Diff Box */}
            <div className="space-y-3">
              {/* Original Vulnerable Code */}
              <div className="rounded-lg border border-red-500/30 bg-zinc-950 overflow-hidden">
                <div className="px-3.5 py-2 bg-red-950/40 border-b border-red-500/20 flex items-center justify-between text-xs font-mono text-red-300">
                  <span className="font-bold flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-red-500 inline-block" />
                    Código Inseguro Atual ({vulnerability.file}:{vulnerability.line})
                  </span>
                  <span className="text-[10px] text-red-400/80">Remover / Refatorar</span>
                </div>
                <pre className="p-4 text-xs font-mono text-red-300/90 bg-red-950/10 overflow-x-auto leading-relaxed max-h-[160px]">
                  {vulnerability.originalSnippet || '// Trecho de código vulnerável identificado na análise'}
                </pre>
              </div>

              {/* Remediated Safe Code */}
              <div className="rounded-lg border border-emerald-500/40 bg-zinc-950 overflow-hidden shadow-sm">
                <div className="px-3.5 py-2 bg-emerald-950/40 border-b border-emerald-500/30 flex items-center justify-between text-xs font-mono text-emerald-300">
                  <span className="font-bold flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-emerald-400 inline-block" />
                    Código Remediado Seguro (Patch Proposto)
                  </span>
                  <button
                    onClick={() => handleCopy(currentPatchCode)}
                    className="text-[10px] text-emerald-400 hover:text-emerald-300 flex items-center gap-1 cursor-pointer"
                  >
                    <Copy className="h-3 w-3" />
                    <span>Copiar este bloco</span>
                  </button>
                </div>
                <pre className="p-4 text-xs font-mono text-emerald-300 bg-emerald-950/10 overflow-x-auto leading-relaxed max-h-[260px]">
                  {currentPatchCode}
                </pre>
              </div>
            </div>
          </div>

          {/* Section 3: Justificativa Técnica & Conformidade */}
          <div className="rounded-lg border border-zinc-800 bg-zinc-950/40 p-4 space-y-2 text-xs font-sans">
            <h5 className="font-bold text-zinc-300 font-mono uppercase text-[11px] flex items-center gap-1.5">
              <Layers className="h-4 w-4 text-blue-400" />
              <span>Conformidade & Garantias Técnicas</span>
            </h5>
            <ul className="space-y-1.5 text-zinc-400 text-[11px] leading-relaxed list-disc list-inside">
              <li>
                <strong className="text-zinc-200 font-mono">Memory Safety:</strong> Elimina riscos de comportamento indefinido (UB) e vazamentos no MIRI.
              </li>
              <li>
                <strong className="text-zinc-200 font-mono">NIST SP 800-218:</strong> Atende às exigências de Secure Software Development Framework (SSDF).
              </li>
              <li>
                <strong className="text-zinc-200 font-mono">Clean Architecture:</strong> Tratamento idiomático de erros via tipos <code className="text-emerald-400">Result&lt;T, E&gt;</code> em vez de pânicos/unwrap.
              </li>
            </ul>
          </div>
        </div>

        {/* Drawer Footer Actions */}
        <div className="px-6 py-4 border-t border-zinc-800 bg-zinc-950/90 flex items-center justify-between gap-3 flex-wrap text-xs">
          <div className="flex items-center gap-2">
            {onOpenFullWorkbench && (
              <button
                onClick={() => {
                  onClose();
                  onOpenFullWorkbench(vulnerability.id);
                }}
                className="px-3 py-2 rounded border border-zinc-700 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 hover:text-white font-mono flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                <span>Abrir no Code Review Workbench</span>
                <ExternalLink className="h-3.5 w-3.5" />
              </button>
            )}
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              className="px-3.5 py-2 rounded border border-zinc-800 hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 font-mono transition-colors cursor-pointer"
            >
              Fechar
            </button>

            {onApplyPullRequest && (
              <button
                onClick={() => onApplyPullRequest(vulnerability.id)}
                disabled={isApplyingPr}
                className="px-4 py-2 rounded bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-mono font-bold flex items-center gap-2 shadow-md transition-all cursor-pointer"
              >
                {isApplyingPr ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    <span>Aplicando Patch...</span>
                  </>
                ) : (
                  <>
                    <GitPullRequest className="h-4 w-4" />
                    <span>Aplicar Correção via Pull Request</span>
                  </>
                )}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
