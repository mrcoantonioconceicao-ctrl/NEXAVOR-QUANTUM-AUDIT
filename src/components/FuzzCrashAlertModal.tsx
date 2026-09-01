import React, { useState } from 'react';
import {
  AlertOctagon,
  X,
  Terminal,
  ShieldAlert,
  Copy,
  Check,
  ExternalLink,
  Wrench,
  FlaskConical,
  CheckCircle2,
  GitBranch,
  GitCommit,
  Clock,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { FuzzCrashAlert } from '../domain/types.ts';

interface FuzzCrashAlertModalProps {
  isOpen: boolean;
  alert: FuzzCrashAlert | null;
  onClose: () => void;
  onNavigateToTests?: () => void;
  onNavigateToRefactor?: () => void;
  onResolveAlert?: (alertId: string) => void;
}

export const FuzzCrashAlertModal: React.FC<FuzzCrashAlertModalProps> = ({
  isOpen,
  alert,
  onClose,
  onNavigateToTests,
  onNavigateToRefactor,
  onResolveAlert,
}) => {
  const [copiedLog, setCopiedLog] = useState<boolean>(false);
  const [isLogExpanded, setIsLogExpanded] = useState<boolean>(true);

  if (!isOpen || !alert) return null;

  const handleCopyLog = () => {
    navigator.clipboard.writeText(alert.rawErrorLog);
    setCopiedLog(true);
    setTimeout(() => setCopiedLog(false), 3000);
  };

  const handleResolve = () => {
    if (onResolveAlert) {
      onResolveAlert(alert.id);
    }
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 overflow-y-auto animate-fadeIn">
      <div className="relative w-full max-w-3xl rounded-xl border border-red-500/50 bg-zinc-900 shadow-2xl shadow-red-950/60 overflow-hidden text-zinc-200 my-8">
        {/* Header with Critical Glow */}
        <div className="flex items-center justify-between border-b border-red-900/60 bg-red-950/40 px-6 py-4">
          <div className="flex items-center space-x-3 min-w-0">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-red-500/20 border border-red-500/40 text-red-400 animate-pulse">
              <AlertOctagon className="h-6 w-6" />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="rounded bg-red-500/20 px-2 py-0.5 text-[10px] font-mono font-bold uppercase tracking-wider text-red-300 border border-red-500/40">
                  {alert.severity} // CI/CD Webhook
                </span>
                <span className="rounded bg-zinc-800 px-2 py-0.5 text-[10px] font-mono text-zinc-400">
                  Target: {alert.target}
                </span>
              </div>
              <h2 className="text-base sm:text-lg font-mono font-bold text-white tracking-wide truncate">
                Falha de Memory Safety detectada por Cargo-Fuzz
              </h2>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-zinc-400 hover:bg-zinc-800 hover:text-white transition-colors"
            aria-label="Fechar modal"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 space-y-6 max-h-[75vh] overflow-y-auto font-sans">
          {/* Metadata Cards Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
            <div className="rounded-lg border border-zinc-800 bg-zinc-950/70 p-3">
              <div className="flex items-center gap-1.5 text-zinc-400 mb-1 text-[11px]">
                <ShieldAlert className="h-3.5 w-3.5 text-red-400" />
                <span>Classificação</span>
              </div>
              <div className="font-bold text-red-300 truncate">{alert.issueType}</div>
            </div>

            <div className="rounded-lg border border-zinc-800 bg-zinc-950/70 p-3">
              <div className="flex items-center gap-1.5 text-zinc-400 mb-1 text-[11px]">
                <GitBranch className="h-3.5 w-3.5 text-emerald-400" />
                <span>Branch / PR</span>
              </div>
              <div className="font-bold text-zinc-200 truncate">
                {alert.branch} {alert.prNumber ? `(PR #${alert.prNumber})` : ''}
              </div>
            </div>

            <div className="rounded-lg border border-zinc-800 bg-zinc-950/70 p-3">
              <div className="flex items-center gap-1.5 text-zinc-400 mb-1 text-[11px]">
                <GitCommit className="h-3.5 w-3.5 text-blue-400" />
                <span>Commit SHA</span>
              </div>
              <div className="font-bold text-zinc-300 font-mono truncate">
                {alert.commitSha || 'N/A'}
              </div>
            </div>

            <div className="rounded-lg border border-zinc-800 bg-zinc-950/70 p-3">
              <div className="flex items-center gap-1.5 text-zinc-400 mb-1 text-[11px]">
                <Clock className="h-3.5 w-3.5 text-amber-400" />
                <span>Horário</span>
              </div>
              <div className="font-bold text-zinc-300 truncate">
                {new Date(alert.timestamp).toLocaleTimeString()}
              </div>
            </div>
          </div>

          {/* Remediation Advice Box */}
          <div className="rounded-lg border border-emerald-500/30 bg-emerald-950/20 p-4">
            <div className="flex items-center gap-2 text-emerald-400 text-xs font-mono font-bold uppercase tracking-wide mb-1.5">
              <CheckCircle2 className="h-4 w-4" />
              <span>Diretriz de Remediação Pericial (RustShield)</span>
            </div>
            <p className="text-xs text-zinc-300 leading-relaxed font-sans">
              {alert.remediationAdvice}
            </p>
          </div>

          {/* Crash Input Payload Preview if available */}
          {alert.crashInputPreview && (
            <div className="rounded-lg border border-zinc-800 bg-zinc-950/90 p-4">
              <div className="text-[11px] font-mono font-bold uppercase tracking-wide text-zinc-400 mb-2">
                Payload de Entrada Maliciosa Mutada (Crash Corpus)
              </div>
              <div className="rounded bg-black/60 p-2.5 font-mono text-[11px] text-amber-300 break-all border border-zinc-900">
                {alert.crashInputPreview}
              </div>
            </div>
          )}

          {/* LibFuzzer & AddressSanitizer Terminal Stack Trace */}
          <div className="rounded-lg border border-red-900/50 bg-black/90 overflow-hidden">
            <div className="flex items-center justify-between border-b border-zinc-800/80 bg-zinc-950 px-4 py-2.5">
              <div className="flex items-center gap-2 font-mono text-xs text-zinc-300">
                <Terminal className="h-4 w-4 text-red-400" />
                <span>LibFuzzer & AddressSanitizer Execution Trace</span>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={handleCopyLog}
                  className="flex items-center gap-1.5 rounded bg-zinc-800/80 px-2.5 py-1 text-[10px] font-mono text-zinc-300 hover:bg-zinc-700 transition-colors"
                >
                  {copiedLog ? (
                    <>
                      <Check className="h-3 w-3 text-emerald-400" />
                      <span>Copiado!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="h-3 w-3" />
                      <span>Copiar Log</span>
                    </>
                  )}
                </button>
                <button
                  onClick={() => setIsLogExpanded(!isLogExpanded)}
                  className="rounded p-1 text-zinc-400 hover:bg-zinc-800 transition-colors"
                >
                  {isLogExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                </button>
              </div>
            </div>

            {isLogExpanded && (
              <pre className="p-4 text-xs font-mono text-red-300 overflow-x-auto whitespace-pre-wrap leading-relaxed max-h-56 select-text">
                {alert.rawErrorLog}
              </pre>
            )}
          </div>
        </div>

        {/* Modal Action Buttons Footer */}
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 border-t border-zinc-800 bg-zinc-950 px-6 py-4 font-mono text-xs">
          <div className="text-zinc-500 text-[11px] truncate w-full sm:w-auto">
            Webhook ID: {alert.id}
          </div>

          <div className="flex items-center gap-2.5 w-full sm:w-auto justify-end">
            {onNavigateToTests && (
              <button
                onClick={() => {
                  onNavigateToTests();
                  onClose();
                }}
                className="flex items-center gap-1.5 rounded border border-zinc-700 bg-zinc-800 px-3 py-2 text-zinc-200 hover:bg-zinc-700 transition-colors"
              >
                <FlaskConical className="h-3.5 w-3.5 text-purple-400" />
                <span>Ver na Suíte de Testes</span>
              </button>
            )}

            {onNavigateToRefactor && (
              <button
                onClick={() => {
                  onNavigateToRefactor();
                  onClose();
                }}
                className="flex items-center gap-1.5 rounded border border-emerald-500/50 bg-emerald-950/60 px-3 py-2 text-emerald-300 hover:bg-emerald-900/60 transition-colors"
              >
                <Wrench className="h-3.5 w-3.5" />
                <span>Refatorar AST & Hardening</span>
              </button>
            )}

            <button
              onClick={handleResolve}
              className="flex items-center gap-1.5 rounded bg-red-600 px-3.5 py-2 font-bold text-white hover:bg-red-500 transition-colors shadow-md shadow-red-950"
            >
              <CheckCircle2 className="h-3.5 w-3.5" />
              <span>Marcar como Ciente</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
