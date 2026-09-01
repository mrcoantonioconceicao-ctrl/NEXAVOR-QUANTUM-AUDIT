import React from 'react';
import { AlertOctagon, ArrowRight, X, ShieldAlert, Terminal, Eye } from 'lucide-react';
import { FuzzCrashAlert } from '../domain/types.ts';

interface FuzzCrashBannerProps {
  alert: FuzzCrashAlert | null;
  onOpenDetails: () => void;
  onDismiss: () => void;
}

export const FuzzCrashBanner: React.FC<FuzzCrashBannerProps> = ({
  alert,
  onOpenDetails,
  onDismiss,
}) => {
  if (!alert) return null;

  return (
    <div className="relative z-40 w-full border-b border-red-500/60 bg-gradient-to-r from-red-950 via-zinc-950 to-red-950 text-white px-4 py-2.5 shadow-lg shadow-red-950/40">
      <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3 text-xs font-mono">
        <div className="flex items-center gap-3 min-w-0">
          <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-red-600/30 border border-red-500/50 text-red-400 animate-pulse">
            <AlertOctagon className="h-4 w-4" />
          </div>
          <div className="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-2 min-w-0">
            <span className="font-bold text-red-300 uppercase tracking-wider whitespace-nowrap">
              🚨 CI/CD Fuzzing Alert:
            </span>
            <span className="text-zinc-200 truncate">
              Crash / Memory Safety em <code className="bg-red-950/80 px-1 py-0.5 rounded border border-red-800/60 text-red-200">{alert.target}</code> ({alert.issueType})
            </span>
            {alert.commitSha && (
              <span className="text-zinc-400 text-[11px] hidden md:inline">
                • Commit [{alert.commitSha.substring(0, 7)}]
              </span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0 self-end sm:self-auto">
          <button
            onClick={onOpenDetails}
            className="flex items-center gap-1.5 rounded bg-red-600 px-3 py-1 text-[11px] font-bold text-white hover:bg-red-500 transition-colors shadow-xs"
          >
            <Eye className="h-3 w-3" />
            <span>Inspecionar Crash</span>
            <ArrowRight className="h-3 w-3" />
          </button>

          <button
            onClick={onDismiss}
            className="rounded p-1 text-zinc-400 hover:bg-zinc-800 hover:text-white transition-colors"
            title="Ocultar aviso"
            aria-label="Ocultar aviso"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  );
};
