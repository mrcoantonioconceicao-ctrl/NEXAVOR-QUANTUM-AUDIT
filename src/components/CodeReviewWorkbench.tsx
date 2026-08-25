import React, { useState } from 'react';
import {
  Code2,
  Check,
  Copy,
  ShieldCheck,
  AlertTriangle,
  Layers,
  Terminal,
  Lightbulb,
} from 'lucide-react';
import { SecurityAuditReport } from '../domain/types.ts';

interface CodeReviewWorkbenchProps {
  report: SecurityAuditReport;
  selectedVulnId?: string | null;
}

export const CodeReviewWorkbench: React.FC<CodeReviewWorkbenchProps> = ({
  report,
  selectedVulnId: initialVulnId,
}) => {
  const [selectedVulnId, setSelectedVulnId] = useState<string>(
    initialVulnId || report.vulnerabilities[0]?.id || ''
  );
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const selectedVuln =
    report.vulnerabilities.find((v) => v.id === selectedVulnId) ||
    report.vulnerabilities[0];

  const handleCopyCode = (code: string, id: string) => {
    navigator.clipboard.writeText(code);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto px-4 sm:px-6 py-6 text-zinc-300">
      {/* Header Banner */}
      <div className="rounded border border-zinc-800 bg-zinc-900/40 p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Code2 className="h-4 w-4 text-emerald-400" />
            <span className="text-[10px] font-mono font-bold uppercase tracking-widest text-emerald-400">
              CODE REVIEW PERICIAL & REMEDIAÇÃO UNIVERSAL
            </span>
          </div>
          <h2 className="text-lg font-bold text-white font-mono uppercase">
            Bancada de Revisão de Código & Patches Multi-Linguagem
          </h2>
          <p className="text-xs text-zinc-400">
            Comparação side-by-side entre o código legado vulnerável e o patch de segurança corrigido com tipagem estrita, sanitização e garantias de isolamento de estado.
          </p>
        </div>
      </div>

      {/* Main Workbench: Left List & Right Diff Viewer */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Vulnerability Sidebar */}
        <div className="lg:col-span-4 rounded border border-zinc-800 bg-zinc-950 p-4 space-y-2">
          <div className="text-[10px] font-bold text-zinc-500 px-2 py-1 font-mono uppercase tracking-widest">
            Vulnerabilidades ({report.vulnerabilities.length})
          </div>

          <div className="space-y-1.5 max-h-[640px] overflow-y-auto pr-1">
            {report.vulnerabilities.map((vuln) => {
              const isSelected = selectedVuln?.id === vuln.id;
              return (
                <button
                  key={vuln.id}
                  onClick={() => setSelectedVulnId(vuln.id)}
                  className={`w-full text-left p-3 rounded border transition-all text-xs space-y-1 ${
                    isSelected
                      ? 'border-zinc-700 bg-zinc-900 text-white shadow-xs'
                      : 'border-zinc-800/80 bg-zinc-950/80 text-zinc-400 hover:border-zinc-700 hover:text-zinc-200'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-1.5">
                      <span
                        className={`text-[9px] font-bold px-1.5 py-0.5 rounded font-mono uppercase tracking-wider ${
                          vuln.severity === 'CRITICAL'
                            ? 'bg-red-500/10 text-red-400 border border-red-500/20'
                            : vuln.severity === 'HIGH'
                            ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                            : 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20'
                        }`}
                      >
                        {vuln.severity}
                      </span>
                      {vuln.language && (
                        <span className="text-[9px] px-1 py-0.5 rounded bg-zinc-800 text-emerald-400 font-mono">
                          {vuln.language}
                        </span>
                      )}
                    </div>
                    <span className="text-[10px] font-mono text-zinc-500 truncate">
                      {vuln.file.split('/').pop()}:{vuln.line}
                    </span>
                  </div>
                  <div className="font-semibold text-zinc-200 line-clamp-1 font-mono">{vuln.title}</div>
                  <div className="text-[11px] text-zinc-500 font-mono">{vuln.cwe}</div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Diff & Remediation Details */}
        <div className="lg:col-span-8 space-y-4">
          {selectedVuln ? (
            <div className="rounded border border-zinc-800 bg-zinc-900/40 p-5 space-y-5">
              {/* Header Info */}
              <div className="space-y-2 border-b border-zinc-800/80 pb-4">
                <div className="flex flex-wrap items-center gap-2">
                  <span
                    className={`text-[9px] font-bold px-1.5 py-0.5 rounded font-mono uppercase tracking-wider ${
                      selectedVuln.severity === 'CRITICAL'
                        ? 'bg-red-500/10 text-red-400 border border-red-500/20'
                        : selectedVuln.severity === 'HIGH'
                        ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                        : 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20'
                    }`}
                  >
                    {selectedVuln.severity} // CVSS {selectedVuln.cvssScore}
                  </span>
                  {selectedVuln.language && (
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-800 text-emerald-400 border border-zinc-700 font-bold">
                      {selectedVuln.language}
                    </span>
                  )}
                  <span className="text-xs font-mono text-emerald-400 font-semibold">
                    {selectedVuln.cwe}
                  </span>
                  <span className="text-xs font-mono text-zinc-500">
                    Arquivo: {selectedVuln.file} (Linha {selectedVuln.line})
                  </span>
                </div>
                <h3 className="text-sm font-bold text-white font-mono">{selectedVuln.title}</h3>
                <p className="text-xs text-zinc-400 leading-relaxed font-sans">
                  {selectedVuln.description}
                </p>

                {/* Explicit Portuguese Remediation Suggestion Card */}
                {selectedVuln.suggestion && (
                  <div className="p-3.5 rounded bg-emerald-950/20 border border-emerald-500/30 text-xs text-emerald-300 font-sans flex items-start gap-2.5 shadow-xs">
                    <Lightbulb className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-mono font-bold uppercase tracking-wider text-[11px] text-emerald-400 block mb-0.5">
                        Sugestão Pericial de Remediação:
                      </span>
                      <span className="text-emerald-200/90 leading-relaxed">
                        {selectedVuln.suggestion}
                      </span>
                    </div>
                  </div>
                )}

                <div className="p-3 rounded bg-zinc-950 border border-zinc-800 text-xs text-zinc-400 font-mono">
                  <span className="font-bold text-zinc-200">Análise Pericial de Risco: </span>
                  {selectedVuln.unsafeRiskDetail}
                </div>
              </div>

              {/* Side-by-side or Stacked Diff Code View */}
              <div className="space-y-4">
                {/* Legacy Snippet */}
                <div className="rounded border border-red-500/30 bg-zinc-950 overflow-hidden">
                  <div className="flex items-center justify-between px-3 py-1.5 bg-red-500/10 border-b border-red-500/20 text-xs font-mono text-red-400">
                    <div className="flex items-center gap-1.5">
                      <AlertTriangle className="h-3.5 w-3.5" />
                      <span className="text-[10px] uppercase font-bold tracking-wider">
                        Código Vulnerável Identificado ({selectedVuln.language || 'Legacy'})
                      </span>
                    </div>
                  </div>
                  <pre className="p-3 text-xs font-mono text-red-200 overflow-x-auto bg-zinc-950 leading-relaxed">
                    {selectedVuln.originalSnippet}
                  </pre>
                </div>

                {/* Remediated Snippet */}
                <div className="rounded border border-emerald-500/30 bg-zinc-950 overflow-hidden shadow-xs">
                  <div className="flex items-center justify-between px-3 py-1.5 bg-emerald-500/10 border-b border-emerald-500/20 text-xs font-mono text-emerald-400">
                    <div className="flex items-center gap-1.5">
                      <ShieldCheck className="h-3.5 w-3.5" />
                      <span className="text-[10px] uppercase font-bold tracking-wider">
                        Patch Remediado Conforme ({selectedVuln.language || 'Production'})
                      </span>
                    </div>
                    <button
                      onClick={() => handleCopyCode(selectedVuln.remediatedSnippet, selectedVuln.id)}
                      className="flex items-center gap-1 px-2.5 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-[10px] font-mono uppercase tracking-wider transition-colors"
                    >
                      {copiedId === selectedVuln.id ? (
                        <>
                          <Check className="h-3 w-3 text-emerald-400" />
                          <span>Copiado!</span>
                        </>
                      ) : (
                        <>
                          <Copy className="h-3 w-3" />
                          <span>Copiar Patch</span>
                        </>
                      )}
                    </button>
                  </div>
                  <pre className="p-3 text-xs font-mono text-emerald-300 overflow-x-auto bg-zinc-950 leading-relaxed">
                    {selectedVuln.remediatedSnippet}
                  </pre>
                </div>
              </div>

              {/* Verification & Risk Radius */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
                <div className="p-3 rounded bg-zinc-950 border border-zinc-800 flex items-start gap-2">
                  <Terminal className="h-4 w-4 text-emerald-400 shrink-0 mt-0.5" />
                  <div>
                    <div className="text-zinc-500 text-[10px] uppercase tracking-wider">Status de Validação Formal</div>
                    <div className="text-emerald-400 font-bold text-xs mt-0.5">
                      {selectedVuln.miriVerificationStatus === 'DETECTED_UB'
                        ? 'Falha Crítica Mitigada pelo Patch'
                        : 'Verificação Formal Validada'}
                    </div>
                  </div>
                </div>

                <div className="p-3 rounded bg-zinc-950 border border-zinc-800 flex items-start gap-2">
                  <Layers className="h-4 w-4 text-purple-400 shrink-0 mt-0.5" />
                  <div>
                    <div className="text-zinc-500 text-[10px] uppercase tracking-wider">Raio de Impacto de Onda</div>
                    <div className="text-purple-300 font-bold text-xs mt-0.5">{selectedVuln.waveShockwaveRadius}</div>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="p-12 text-center text-zinc-500 font-mono text-xs">
              Selecione uma vulnerabilidade para visualizar a análise detalhada e o patch.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
