import React, { useState, useMemo } from 'react';
import {
  GitCompare,
  History,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  TrendingDown,
  TrendingUp,
  ArrowRight,
  Code2,
  Calendar,
  Sparkles,
  FileCode,
  FileDown,
  Trash2,
  PlusCircle,
  Activity,
  Layers,
  Lightbulb,
} from 'lucide-react';
import { SecurityAuditReport } from '../domain/types.ts';
import {
  AuditSessionSnapshot,
  getAuditHistory,
  saveAuditSession,
  deleteAuditSession,
  compareAuditReports,
  generateSyntheticBaselineSession,
} from '../services/auditHistoryService.ts';

interface AuditDiffComparatorProps {
  currentReport: SecurityAuditReport;
  onNavigateToCodeReview?: (vulnId: string) => void;
  onNavigateToWaves?: () => void;
  onSelectHistoricalReport?: (report: SecurityAuditReport) => void;
}

type FilterType = 'all' | 'new_only' | 'fixed_only' | 'persisting' | 'waves';

export const AuditDiffComparator: React.FC<AuditDiffComparatorProps> = ({
  currentReport,
  onNavigateToCodeReview,
  onNavigateToWaves,
  onSelectHistoricalReport,
}) => {
  const [filter, setFilter] = useState<FilterType>('all');
  const [selectedBaselineId, setSelectedBaselineId] = useState<string | 'synthetic' | null>(null);
  const [historyRefreshKey, setHistoryRefreshKey] = useState<number>(0);
  const [copiedNotification, setCopiedNotification] = useState<boolean>(false);

  // Load history snapshots for this repo
  const historyList = useMemo(() => {
    // trigger memo on historyRefreshKey
    void historyRefreshKey;
    const allHistory = getAuditHistory(currentReport.targetRepo?.fullName);
    return allHistory.filter((h) => h.id !== currentReport.id);
  }, [currentReport, historyRefreshKey]);

  // Determine baseline report
  const baselineReport: SecurityAuditReport = useMemo(() => {
    if (selectedBaselineId && selectedBaselineId !== 'synthetic') {
      const found = historyList.find((h) => h.id === selectedBaselineId);
      if (found?.report) return found.report;
    }

    if (historyList.length > 0 && selectedBaselineId !== 'synthetic') {
      return historyList[0].report;
    }

    // Default to synthetic baseline simulation if no previous scans exist
    return generateSyntheticBaselineSession(currentReport);
  }, [currentReport, historyList, selectedBaselineId]);

  // Compute full diff comparison
  const diffResult = useMemo(() => {
    return compareAuditReports(currentReport, baselineReport);
  }, [currentReport, baselineReport]);

  const handleSimulatePriorRelease = () => {
    const synthetic = generateSyntheticBaselineSession(currentReport);
    saveAuditSession(synthetic);
    setSelectedBaselineId(synthetic.id);
    setHistoryRefreshKey((prev) => prev + 1);
  };

  const handleDeleteSession = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    deleteAuditSession(id);
    setHistoryRefreshKey((prev) => prev + 1);
    if (selectedBaselineId === id) {
      setSelectedBaselineId(null);
    }
  };

  const handleExportDiffReport = () => {
    const summary = {
      repository: currentReport.targetRepo.fullName,
      generatedAt: new Date().toISOString(),
      currentSession: {
        id: currentReport.id,
        timestamp: currentReport.timestamp,
        score: currentReport.overallSecurityScore,
        vulnerabilitiesCount: currentReport.vulnerabilities.length,
      },
      baselineSession: {
        id: baselineReport.id,
        timestamp: baselineReport.timestamp,
        score: baselineReport.overallSecurityScore,
        vulnerabilitiesCount: baselineReport.vulnerabilities.length,
      },
      diffSummary: {
        scoreDelta: diffResult.scoreDelta,
        verdict: diffResult.verdict,
        newVulnerabilitiesCount: diffResult.newVulnerabilities.length,
        fixedVulnerabilitiesCount: diffResult.fixedVulnerabilities.length,
        persistingVulnerabilitiesCount: diffResult.persistingVulnerabilities.length,
      },
      newVulnerabilities: diffResult.newVulnerabilities.map((v) => ({
        id: v.id,
        title: v.title,
        severity: v.severity,
        cwe: v.cwe,
        file: v.file,
        line: v.line,
        explanation: v.description,
      })),
      fixedVulnerabilities: diffResult.fixedVulnerabilities.map((v) => ({
        id: v.id,
        title: v.title,
        severity: v.severity,
        file: v.file,
      })),
    };

    const blob = new Blob([JSON.stringify(summary, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `qaudit-diff-report-${currentReport.targetRepo.name}-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    setCopiedNotification(true);
    setTimeout(() => setCopiedNotification(false), 3000);
  };

  const isSyntheticBaseline = baselineReport.id.startsWith('baseline-sim-');

  return (
    <div className="space-y-6 max-w-7xl mx-auto px-4 sm:px-6 py-6 text-zinc-300">
      {/* Top Header Card */}
      <div className="rounded border border-zinc-800 bg-zinc-900/40 p-5 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-800 text-blue-400 border border-zinc-700 font-bold uppercase tracking-wider flex items-center gap-1">
              <GitCompare className="h-3 w-3" />
              Comparador de Regressões
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-900 text-zinc-400 border border-zinc-800">
              {currentReport.targetRepo.fullName}
            </span>
            {isSyntheticBaseline && (
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 font-bold">
                Baseline Simulada (v1.2.0)
              </span>
            )}
          </div>
          <h2 className="text-lg font-bold text-white font-mono flex items-center gap-2">
            <span>Análise Comparativa com Auditoria Anterior</span>
          </h2>
          <p className="text-xs text-zinc-400">
            Identifica regressões, novas vulnerabilidades inseridas em commits recentes e validação de falhas corrigidas.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <button
            onClick={handleSimulatePriorRelease}
            className="flex items-center gap-1.5 rounded border border-zinc-700 bg-zinc-800/90 px-3 py-1.5 text-xs font-mono text-zinc-200 hover:bg-zinc-700 hover:text-white transition-colors"
            title="Injetar e simular scan da versão/release anterior para testar regressões"
          >
            <Sparkles className="h-3.5 w-3.5 text-amber-400" />
            <span>Simular Release Anterior</span>
          </button>

          <button
            onClick={handleExportDiffReport}
            className="flex items-center gap-1.5 rounded bg-zinc-800 border border-zinc-700 px-3 py-1.5 text-xs font-mono font-bold text-emerald-400 hover:bg-zinc-700 transition-colors"
            title="Exportar relatório JSON com o diff detalhado"
          >
            <FileDown className="h-3.5 w-3.5" />
            <span>Exportar Diff</span>
          </button>
        </div>
      </div>

      {/* Baseline Selection Strip */}
      <div className="rounded border border-zinc-800 bg-zinc-900/60 p-3.5 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs font-mono">
        <div className="flex items-center gap-2 min-w-0">
          <History className="h-4 w-4 text-zinc-400 shrink-0" />
          <span className="text-zinc-400 shrink-0">Sessão Baseline Comparada:</span>
          <select
            value={selectedBaselineId || (historyList[0]?.id ?? 'synthetic')}
            onChange={(e) => setSelectedBaselineId(e.target.value)}
            className="rounded border border-zinc-700 bg-zinc-950 px-2.5 py-1 text-xs text-zinc-200 focus:border-emerald-500 focus:outline-none truncate max-w-md"
          >
            {historyList.map((h) => (
              <option key={h.id} value={h.id}>
                {new Date(h.timestamp).toLocaleString('pt-BR')} — Score: {h.score}/100 ({h.vulnerabilitiesCount.total} vulns) [{h.commitOrBranch}]
              </option>
            ))}
            {historyList.length === 0 && (
              <option value="synthetic">
                Release Baseline v1.2.0 (Simulada) — Score: {baselineReport.overallSecurityScore}/100
              </option>
            )}
          </select>
        </div>

        <div className="flex items-center gap-2 text-[11px] text-zinc-400 shrink-0">
          <span>Scan Atual:</span>
          <span className="text-emerald-400 font-bold">
            {new Date(currentReport.timestamp).toLocaleTimeString('pt-BR')} (Score: {currentReport.overallSecurityScore}/100)
          </span>
        </div>
      </div>

      {/* Regression Verdict Banner */}
      <div
        className={`rounded-md border p-4.5 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 ${
          diffResult.verdict === 'CRITICAL_REGRESSION'
            ? 'bg-rose-950/20 border-rose-500/40 text-rose-300'
            : diffResult.verdict === 'REGRESSION'
            ? 'bg-amber-950/20 border-amber-500/40 text-amber-300'
            : diffResult.verdict === 'IMPROVED'
            ? 'bg-emerald-950/20 border-emerald-500/40 text-emerald-300'
            : 'bg-zinc-900/60 border-zinc-800 text-zinc-300'
        }`}
      >
        <div className="flex items-center gap-3">
          <div className="p-2 rounded bg-zinc-950/60 shrink-0">
            {diffResult.verdict === 'CRITICAL_REGRESSION' || diffResult.verdict === 'REGRESSION' ? (
              <ShieldAlert className="h-6 w-6 text-rose-400 animate-pulse" />
            ) : diffResult.verdict === 'IMPROVED' ? (
              <ShieldCheck className="h-6 w-6 text-emerald-400" />
            ) : (
              <CheckCircle2 className="h-6 w-6 text-blue-400" />
            )}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono uppercase font-bold tracking-widest px-2 py-0.5 rounded bg-zinc-950/80 border border-current">
                {diffResult.verdict === 'CRITICAL_REGRESSION'
                  ? 'ALERTA DE REGRESSÃO CRÍTICA'
                  : diffResult.verdict === 'REGRESSION'
                  ? 'REGRESSÃO DE SEGURANÇA DETECTADA'
                  : diffResult.verdict === 'IMPROVED'
                  ? 'POSTURA DE SEGURANÇA MELHORADA'
                  : 'SITUAÇÃO ESTÁVEL'}
              </span>
            </div>
            <p className="text-xs mt-1 font-sans leading-relaxed text-zinc-200">
              {diffResult.verdictMessage}
            </p>
          </div>
        </div>

        {diffResult.newVulnerabilities.length > 0 && (
          <button
            onClick={() => setFilter('new_only')}
            className="shrink-0 rounded bg-rose-500/20 border border-rose-500/40 hover:bg-rose-500/30 text-rose-300 px-3 py-1.5 text-xs font-mono font-bold flex items-center gap-1.5 transition-colors"
          >
            <span>Ver {diffResult.newVulnerabilities.length} Novas Regressões</span>
            <ArrowRight className="h-3.5 w-3.5" />
          </button>
        )}
      </div>

      {/* 4 Delta Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        {/* Score Delta */}
        <div className="rounded border border-zinc-800 bg-zinc-900/50 p-4">
          <span className="text-[10px] uppercase font-bold tracking-widest text-zinc-500 font-mono">
            Variação de Score (Δ)
          </span>
          <div className="mt-2 flex items-baseline gap-2">
            <span
              className={`text-2xl font-mono font-bold ${
                diffResult.scoreDelta > 0
                  ? 'text-emerald-400'
                  : diffResult.scoreDelta < 0
                  ? 'text-rose-400'
                  : 'text-zinc-400'
              }`}
            >
              {diffResult.scoreDelta > 0 ? `+${diffResult.scoreDelta}` : diffResult.scoreDelta} pts
            </span>
            <span className="text-xs text-zinc-500 font-mono">
              ({baselineReport.overallSecurityScore} → {currentReport.overallSecurityScore})
            </span>
          </div>
          <div className="flex items-center gap-1 text-[11px] mt-1 font-mono">
            {diffResult.scoreDelta >= 0 ? (
              <span className="text-emerald-400 flex items-center gap-1">
                <TrendingUp className="h-3.5 w-3.5" /> Evolução positiva
              </span>
            ) : (
              <span className="text-rose-400 flex items-center gap-1">
                <TrendingDown className="h-3.5 w-3.5" /> Queda na segurança
              </span>
            )}
          </div>
        </div>

        {/* New Vulnerabilities (Regression) */}
        <div className="rounded border border-zinc-800 bg-zinc-900/50 p-4 border-l-2 border-l-rose-500">
          <span className="text-[10px] uppercase font-bold tracking-widest text-zinc-500 font-mono">
            Novas Vulnerabilidades
          </span>
          <div className="mt-2 flex items-baseline gap-2">
            <span className={`text-2xl font-mono font-bold ${diffResult.newVulnerabilities.length > 0 ? 'text-rose-400' : 'text-zinc-400'}`}>
              +{diffResult.newVulnerabilities.length}
            </span>
            <span className="text-xs text-zinc-500 font-mono">introduzidas</span>
          </div>
          <p className="text-[11px] text-zinc-400 mt-1 truncate">
            {diffResult.newVulnerabilities.length > 0 ? 'Requerem correção imediata' : 'Nenhuma nova brecha'}
          </p>
        </div>

        {/* Fixed Vulnerabilities */}
        <div className="rounded border border-zinc-800 bg-zinc-900/50 p-4 border-l-2 border-l-emerald-500">
          <span className="text-[10px] uppercase font-bold tracking-widest text-zinc-500 font-mono">
            Falhas Corrigidas
          </span>
          <div className="mt-2 flex items-baseline gap-2">
            <span className={`text-2xl font-mono font-bold ${diffResult.fixedVulnerabilities.length > 0 ? 'text-emerald-400' : 'text-zinc-400'}`}>
              {diffResult.fixedVulnerabilities.length}
            </span>
            <span className="text-xs text-zinc-500 font-mono">resolvidas</span>
          </div>
          <p className="text-[11px] text-zinc-400 mt-1 truncate">
            {diffResult.fixedVulnerabilities.length > 0 ? 'Eliminadas no código atual' : 'Sem remediações novas'}
          </p>
        </div>

        {/* Persisting Vulnerabilities */}
        <div className="rounded border border-zinc-800 bg-zinc-900/50 p-4 border-l-2 border-l-amber-500">
          <span className="text-[10px] uppercase font-bold tracking-widest text-zinc-500 font-mono">
            Falhas Persistentes
          </span>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-mono font-bold text-amber-400">
              {diffResult.persistingVulnerabilities.length}
            </span>
            <span className="text-xs text-zinc-500 font-mono">pendentes</span>
          </div>
          <p className="text-[11px] text-zinc-400 mt-1 truncate">
            Presentes em ambas as versões
          </p>
        </div>
      </div>

      {/* Interactive Tabs / Filter Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-zinc-800 pb-3">
        <div className="flex flex-wrap items-center gap-1.5">
          <button
            onClick={() => setFilter('all')}
            className={`rounded-md px-3 py-1.5 text-xs font-mono font-semibold transition-colors ${
              filter === 'all'
                ? 'bg-zinc-800 text-white border border-zinc-700'
                : 'text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200'
            }`}
          >
            Todas as Alterações ({diffResult.allDiffItems.length})
          </button>

          <button
            onClick={() => setFilter('new_only')}
            className={`rounded-md px-3 py-1.5 text-xs font-mono font-semibold transition-colors flex items-center gap-1.5 ${
              filter === 'new_only'
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                : 'text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200'
            }`}
          >
            <span className="h-2 w-2 rounded-full bg-rose-500 animate-pulse" />
            <span>Novas Regressões ({diffResult.newVulnerabilities.length})</span>
          </button>

          <button
            onClick={() => setFilter('fixed_only')}
            className={`rounded-md px-3 py-1.5 text-xs font-mono font-semibold transition-colors ${
              filter === 'fixed_only'
                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                : 'text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200'
            }`}
          >
            Corrigidas ({diffResult.fixedVulnerabilities.length})
          </button>

          <button
            onClick={() => setFilter('persisting')}
            className={`rounded-md px-3 py-1.5 text-xs font-mono font-semibold transition-colors ${
              filter === 'persisting'
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                : 'text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200'
            }`}
          >
            Persistentes ({diffResult.persistingVulnerabilities.length})
          </button>

          <button
            onClick={() => setFilter('waves')}
            className={`rounded-md px-3 py-1.5 text-xs font-mono font-semibold transition-colors flex items-center gap-1 ${
              filter === 'waves'
                ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/40'
                : 'text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200'
            }`}
          >
            <Activity className="h-3.5 w-3.5" />
            <span>Vetores Zero-Day ({diffResult.waveHazardDelta.newHazards.length + diffResult.waveHazardDelta.persistingHazards.length})</span>
          </button>
        </div>
      </div>

      {/* Vulnerabilities Diff List */}
      {filter !== 'waves' && (
        <div className="space-y-3">
          {diffResult.allDiffItems
            .filter((item) => {
              if (filter === 'new_only') return item.status === 'NEW';
              if (filter === 'fixed_only') return item.status === 'FIXED';
              if (filter === 'persisting') return item.status === 'PERSISTING';
              return true;
            })
            .map((item, idx) => {
              const vuln = item.vulnerability;
              const isNew = item.status === 'NEW';
              const isFixed = item.status === 'FIXED';

              return (
                <div
                  key={`${vuln.id}-${idx}`}
                  className={`rounded-lg border p-4 transition-all ${
                    isNew
                      ? 'border-rose-500/50 bg-rose-950/15 shadow-sm'
                      : isFixed
                      ? 'border-emerald-500/40 bg-emerald-950/10'
                      : 'border-zinc-800 bg-zinc-900/40'
                  }`}
                >
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 mb-2">
                    <div className="flex flex-wrap items-center gap-2">
                      {/* Status Tag */}
                      {isNew && (
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500 text-zinc-950 font-bold uppercase tracking-wider animate-pulse flex items-center gap-1">
                          <AlertTriangle className="h-3 w-3" />
                          NOVA REGRESSÃO (Scan Atual)
                        </span>
                      )}
                      {isFixed && (
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 font-bold uppercase tracking-wider flex items-center gap-1">
                          <CheckCircle2 className="h-3 w-3" />
                          CORRIGIDA / REMEDIADA
                        </span>
                      )}
                      {!isNew && !isFixed && (
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-800 text-zinc-400 border border-zinc-700 font-bold uppercase tracking-wider">
                          PERSISTENTE
                        </span>
                      )}

                      {/* Severity Pill */}
                      <span
                        className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase ${
                          vuln.severity === 'CRITICAL'
                            ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                            : vuln.severity === 'HIGH'
                            ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30'
                            : vuln.severity === 'MEDIUM'
                            ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                            : 'bg-zinc-800 text-zinc-300'
                        }`}
                      >
                        {vuln.severity} (CVSS {vuln.cvssScore})
                      </span>

                      {/* File Path & Line */}
                      <span className="text-xs font-mono text-zinc-300 flex items-center gap-1">
                        <FileCode className="h-3.5 w-3.5 text-zinc-500" />
                        <span>{vuln.file}:{vuln.line}</span>
                      </span>

                      {vuln.cwe && (
                        <span className="text-[10px] font-mono text-zinc-500">
                          {vuln.cwe}
                        </span>
                      )}
                    </div>

                    {/* Action button */}
                    {onNavigateToCodeReview && !isFixed && (
                      <button
                        onClick={() => onNavigateToCodeReview(vuln.id)}
                        className="self-start md:self-auto text-xs font-mono text-emerald-400 hover:text-emerald-300 flex items-center gap-1 underline underline-offset-4"
                      >
                        <span>Abrir no Workbench</span>
                        <ArrowRight className="h-3 w-3" />
                      </button>
                    )}
                  </div>

                  <h3 className="text-sm font-bold text-zinc-100 font-mono mb-1">
                    {vuln.title}
                  </h3>

                  <p className="text-xs text-zinc-400 leading-relaxed mb-3">
                    {vuln.description}
                  </p>

                  {/* Sugestão em Português */}
                  {vuln.suggestion && (
                    <div className="flex items-start gap-2 mb-3 text-[11px] font-sans text-emerald-300 bg-emerald-950/30 border border-emerald-500/25 px-2.5 py-1.5 rounded">
                      <Lightbulb className="h-3.5 w-3.5 shrink-0 text-emerald-400 mt-0.5" />
                      <div>
                        <strong className="font-mono text-[10px] uppercase tracking-wider text-emerald-400 block">
                          Sugestão de Remediação:
                        </strong>
                        <span className="text-emerald-200/90">{vuln.suggestion}</span>
                      </div>
                    </div>
                  )}

                  {/* Code Snippet Box */}
                  <div className="rounded border border-zinc-800 bg-zinc-950 p-2.5 font-mono text-xs overflow-x-auto">
                    <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1 flex items-center justify-between">
                      <span>Snippet Auditado:</span>
                      <span className="text-zinc-600">{vuln.file}</span>
                    </div>
                    <pre className="text-rose-300/90 text-xs">
                      {vuln.originalSnippet || '// Trecho de código analisado'}
                    </pre>
                  </div>
                </div>
              );
            })}

          {diffResult.allDiffItems.length === 0 && (
            <div className="p-12 text-center text-zinc-500 font-mono text-xs border border-dashed border-zinc-800 rounded">
              Nenhuma alteração de vulnerabilidade encontrada para o filtro selecionado.
            </div>
          )}
        </div>
      )}

      {/* Wave Hazards Diff View */}
      {filter === 'waves' && (
        <div className="space-y-4">
          <div className="rounded-md border border-indigo-500/30 bg-indigo-950/20 p-4 text-xs font-mono">
            <div className="flex items-center justify-between mb-2">
              <span className="text-indigo-300 font-bold uppercase tracking-wider flex items-center gap-1.5">
                <Activity className="h-4 w-4" />
                Variação Espectral Zero-Day (Teoria das Ondas)
              </span>
              {onNavigateToWaves && (
                <button
                  onClick={onNavigateToWaves}
                  className="text-emerald-400 hover:underline flex items-center gap-1 text-[11px]"
                >
                  <span>Abrir Visualizador 3D</span>
                  <ArrowRight className="h-3 w-3" />
                </button>
              )}
            </div>
            <p className="text-zinc-400 leading-relaxed font-sans">
              Compara os vetores de choque e a entropia harmônica entre as versões de código. Novos vetores indicam pontos de interferência construtiva adicionados no último commit.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
            {diffResult.waveHazardDelta.newHazards.map((hazard) => (
              <div
                key={hazard.id}
                className="rounded border border-rose-500/40 bg-rose-950/15 p-4 space-y-2"
              >
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500 text-zinc-950 font-bold uppercase">
                    NOVO VETOR DE CHOQUE
                  </span>
                  <span className="text-xs font-mono text-zinc-400">
                    Entropia: {(hazard.spectralEntropy * 100).toFixed(0)}%
                  </span>
                </div>
                <div className="text-xs font-bold text-white font-mono">{hazard.moduleName}</div>
                <p className="text-[11px] text-zinc-400">{hazard.theoreticalZeroDaySurface}</p>
                <div className="text-[10px] font-mono text-emerald-400 bg-zinc-950/80 p-2 rounded border border-zinc-800">
                  <span className="text-zinc-500">Amortecedor Soliton:</span> {hazard.solitonDampenerRemediation}
                </div>
              </div>
            ))}

            {diffResult.waveHazardDelta.persistingHazards.map((hazard) => (
              <div
                key={hazard.id}
                className="rounded border border-zinc-800 bg-zinc-900/40 p-4 space-y-2"
              >
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-800 text-zinc-400 uppercase">
                    VETOR PERSISTENTE
                  </span>
                  <span className="text-xs font-mono text-zinc-400">
                    {hazard.harmonicFrequency}
                  </span>
                </div>
                <div className="text-xs font-bold text-white font-mono">{hazard.moduleName}</div>
                <p className="text-[11px] text-zinc-400">{hazard.theoreticalZeroDaySurface}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Historical Audit Sessions Timeline Strip */}
      <div className="mt-8 rounded-lg border border-zinc-800 bg-zinc-900/30 p-5">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <History className="h-4 w-4 text-emerald-400" />
            <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-white">
              Histórico de Sessões ({historyList.length + 1} Registradas)
            </h3>
          </div>
          <span className="text-[10px] text-zinc-500 font-mono">
            Armazenamento Local Criptografado
          </span>
        </div>

        <div className="divide-y divide-zinc-800/80">
          {/* Current Scan */}
          <div className="py-2.5 flex items-center justify-between text-xs font-mono bg-zinc-900/60 px-3 rounded">
            <div className="flex items-center gap-3">
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-white font-bold">Scan Atual (Ativo)</span>
              <span className="text-zinc-500">
                {new Date(currentReport.timestamp).toLocaleString('pt-BR')}
              </span>
            </div>
            <div className="flex items-center gap-4">
              <span className="text-emerald-400 font-bold">
                Score: {currentReport.overallSecurityScore}/100
              </span>
              <span className="text-zinc-400">
                {currentReport.vulnerabilities.length} vulnerabilidades
              </span>
            </div>
          </div>

          {/* Historical Scans */}
          {historyList.map((item) => (
            <div
              key={item.id}
              onClick={() => setSelectedBaselineId(item.id)}
              className={`py-2.5 flex items-center justify-between text-xs font-mono px-3 transition-colors cursor-pointer hover:bg-zinc-850 ${
                selectedBaselineId === item.id ? 'bg-zinc-800/80 border-l-2 border-l-blue-500' : ''
              }`}
            >
              <div className="flex items-center gap-3">
                <Calendar className="h-3.5 w-3.5 text-zinc-500" />
                <span className="text-zinc-300">
                  {new Date(item.timestamp).toLocaleString('pt-BR')}
                </span>
                <span className="text-[10px] text-zinc-500 px-1.5 py-0.5 rounded bg-zinc-950">
                  {item.commitOrBranch}
                </span>
              </div>
              <div className="flex items-center gap-4">
                <span className="text-zinc-300 font-semibold">
                  Score: {item.score}/100
                </span>
                <span className="text-zinc-400">
                  {item.vulnerabilitiesCount.total} vulns
                </span>
                <button
                  onClick={(e) => handleDeleteSession(item.id, e)}
                  className="text-zinc-600 hover:text-rose-400 p-1 transition-colors"
                  title="Remover sessão do histórico"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {copiedNotification && (
        <div className="fixed bottom-6 right-6 z-50 rounded border border-emerald-500/50 bg-zinc-900 px-4 py-2.5 text-xs font-mono text-emerald-400 shadow-xl">
          Relatório de Regressão Diff exportado com sucesso!
        </div>
      )}
    </div>
  );
};
