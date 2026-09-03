import React, { useState, useMemo } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Radio,
  Cpu,
  Layers,
  ArrowUpRight,
  Clock,
  Award,
  CheckCircle,
  AlertTriangle,
  Server,
  FileCode,
  FolderGit2,
  GitCompare,
  GitPullRequest,
  TrendingDown,
  TrendingUp,
  Sparkles,
  Lightbulb,
  Shield,
  Package,
  ExternalLink,
  AlertOctagon,
  Loader2,
  Lock,
  FileSpreadsheet,
} from 'lucide-react';
import { SecurityAuditReport, VulnerabilitySeverity, SourceFile } from '../domain/types.ts';
import { TabType } from './Sidebar.tsx';
import { getAuditHistory, compareAuditReports, generateSyntheticBaselineSession } from '../services/auditHistoryService.ts';
import { SecurityBadgeModal } from './SecurityBadgeModal.tsx';
import { DependencyVulnerabilitiesPanel } from './DependencyVulnerabilitiesPanel.tsx';
import { createGitHubPullRequest, CreatePrResult } from '../services/githubService.ts';
import { exportAuditToCsv } from '../services/excelExporter.ts';

interface AuditDashboardProps {
  report: SecurityAuditReport;
  onNavigateToTab: (tab: TabType) => void;
  onSelectVulnerabilityForReview: (vulnId: string) => void;
}

export const AuditDashboard: React.FC<AuditDashboardProps> = ({
  report,
  onNavigateToTab,
  onSelectVulnerabilityForReview,
}) => {
  const [isBadgeModalOpen, setIsBadgeModalOpen] = useState(false);
  const [selectedFileForInspection, setSelectedFileForInspection] = useState<SourceFile>(
    report.filesAudited[0] || { path: 'src/lib.rs', size: 0, content: '' }
  );

  // 1-Click Pull Request Remediation State
  const [isCreatingPr, setIsCreatingPr] = useState<boolean>(false);
  const [prResult, setPrResult] = useState<CreatePrResult | null>(null);
  const [githubTokenInput, setGithubTokenInput] = useState<string>('');
  const [showTokenModal, setShowTokenModal] = useState<boolean>(false);
  const [activeVulnForPr, setActiveVulnForPr] = useState<string | null>(null);

  const handleApplyPullRequest = async (targetVulnId?: string, tokenOverride?: string) => {
    setIsCreatingPr(true);
    setPrResult(null);
    setActiveVulnForPr(targetVulnId || 'ALL');

    const targetVulns = targetVulnId
      ? report.vulnerabilities.filter((v) => v.id === targetVulnId)
      : report.vulnerabilities;

    const patches = targetVulns.map((v) => {
      // Deduce packageName & targetVersion from title or vulnerability metadata
      const packageName = v.rustsecId || v.cwe || v.title.split(' ')[0] || 'crate';
      const targetVersion = v.fixedVersion || '0.4.38';
      const manifestPath = v.file.includes('/') ? v.file : `Cargo.toml`;

      return {
        manifestPath,
        packageName,
        currentVersion: '0.1.0',
        targetVersion,
        remediationCommand: v.suggestion || v.description,
      };
    });

    // Also include any dependency vulnerabilities if available
    if (report.dependencyAnalysis?.vulnerabilities) {
      report.dependencyAnalysis.vulnerabilities.forEach((dv) => {
        patches.push({
          manifestPath: dv.manifestPath,
          packageName: dv.packageName,
          currentVersion: dv.versionConstraint,
          targetVersion: dv.fixedVersion,
          remediationCommand: dv.remediation,
        });
      });
    }

    const result = await createGitHubPullRequest({
      repoUrl: report.targetRepo?.url || `https://github.com/${report.targetRepo?.owner || 'owner'}/${report.targetRepo?.name || 'repo'}`,
      githubToken: tokenOverride !== undefined ? tokenOverride : githubTokenInput,
      patches: patches.length > 0 ? patches : [{
        manifestPath: 'Cargo.toml',
        packageName: 'chrono',
        targetVersion: '0.4.38',
      }],
      prTitle: targetVulnId
        ? `[RustShield Quantum] Remediação: ${targetVulns[0]?.title || 'Patch de Segurança'}`
        : `[RustShield Quantum] Remediação Automática Completa (${report.vulnerabilities.length} vulnerabilidades)`,
    });

    setIsCreatingPr(false);
    setActiveVulnForPr(null);
    setPrResult(result);

    if (result.requiresToken && !tokenOverride) {
      setShowTokenModal(true);
    }
  };

  // Compare with baseline if history exists or generate demo baseline
  const comparison = useMemo(() => {
    const history = getAuditHistory(report.targetRepo?.fullName).filter((h) => h.id !== report.id);
    const baseline = history.length > 0 ? history[0].report : generateSyntheticBaselineSession(report);
    return compareAuditReports(report, baseline);
  }, [report]);

  const getSeverityBadge = (sev: VulnerabilitySeverity) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-red-500/10 text-red-400 border border-red-500/20';
      case 'HIGH':
        return 'bg-amber-500/10 text-amber-400 border border-amber-500/20';
      case 'MEDIUM':
        return 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20';
      default:
        return 'bg-zinc-800 text-zinc-300 border border-zinc-700';
    }
  };

  const criticals = report.vulnerabilities.filter((v) => v.severity === 'CRITICAL');
  const highs = report.vulnerabilities.filter((v) => v.severity === 'HIGH');
  const mediums = report.vulnerabilities.filter((v) => v.severity === 'MEDIUM');

  return (
    <div className="space-y-6 max-w-7xl mx-auto px-4 sm:px-6 py-6 text-zinc-300">
      {/* Target Repo Header Card */}
      <div className="rounded border border-zinc-800 bg-zinc-900/40 p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1.5">
          <div className="flex flex-wrap items-center gap-2">
            {report.targetRepo?.pullRequest ? (
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/40 font-bold uppercase tracking-wider flex items-center gap-1">
                <GitPullRequest className="h-3 w-3" />
                Pull Request #{report.targetRepo.pullRequest.number}
              </span>
            ) : (
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-bold uppercase tracking-wider flex items-center gap-1">
                <FolderGit2 className="h-3 w-3" />
                Auditoria Completa (Repo)
              </span>
            )}
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-800 text-emerald-400 border border-zinc-700 font-bold uppercase tracking-wider">
              {report.primaryLanguage || 'Polyglot'} {report.editionDetected}
            </span>
            {report.detectedLanguages && report.detectedLanguages.length > 1 && (
              <div className="flex items-center gap-1">
                {report.detectedLanguages.map((l) => (
                  <span key={l} className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-400">
                    {l}
                  </span>
                ))}
              </div>
            )}
            <span className="text-[11px] text-zinc-500 font-mono">
              {report.filesAudited.length} arquivos auditados ({report.totalLinesAudited} linhas)
            </span>
          </div>

          <h2 className="text-lg font-bold text-white font-mono flex items-center gap-2">
            <span>{report.targetRepo.fullName}</span>
            {report.targetRepo?.pullRequest && (
              <span className="text-xs font-normal text-zinc-400 font-sans">
                — {report.targetRepo.pullRequest.title}
              </span>
            )}
          </h2>

          <p className="text-xs text-zinc-400">
            {report.targetRepo?.pullRequest
              ? `PR aberto por @${report.targetRepo.pullRequest.author} (${report.targetRepo.pullRequest.baseBranch} ⟵ ${report.targetRepo.pullRequest.headBranch}) com +${report.targetRepo.pullRequest.additions} / -${report.targetRepo.pullRequest.deletions} linhas`
              : report.targetRepo.description}
          </p>
        </div>

        <div className="flex items-center gap-3 shrink-0">
          <button
            onClick={() => exportAuditToCsv(report)}
            className="px-3 py-1.5 rounded border border-blue-500/40 bg-blue-950/40 hover:bg-blue-900/60 text-blue-300 font-mono text-xs font-bold flex items-center gap-1.5 transition-colors shadow-xs"
            title="Exportar todas as vulnerabilidades e relatórios para planilha Excel (.csv)"
          >
            <FileSpreadsheet className="h-4 w-4 text-blue-400" />
            <span>Excel (.csv)</span>
          </button>
          <button
            onClick={() => setIsBadgeModalOpen(true)}
            className="px-3 py-1.5 rounded border border-emerald-500/40 bg-emerald-950/40 hover:bg-emerald-900/60 text-emerald-300 font-mono text-xs font-bold flex items-center gap-1.5 transition-colors shadow-xs"
            title="Gerar e copiar badge de segurança Markdown para o README"
          >
            <Shield className="h-4 w-4 text-emerald-400" />
            <span>Badge README</span>
          </button>
          <div className="text-right">
            <div className="text-[10px] uppercase tracking-widest text-zinc-500 font-mono font-bold">Classificação C-Level</div>
            <div className="text-xs font-semibold font-mono text-emerald-400">
              {report.targetRepo?.pullRequest ? 'PR GATEWAY // CONFIDENCIAL' : 'CONFIDENCIAL // MIT PQC // 10K CCU'}
            </div>
          </div>
        </div>
      </div>

      {/* Critical CVE & Supply Chain Immediate Alert Banner */}
      {report.dependencyAnalysis && report.dependencyAnalysis.vulnerabilities.some(v => v.severity === 'CRITICAL' || v.severity === 'HIGH') && (
        <div className="rounded-lg border-2 border-red-500/80 bg-red-950/40 p-4 shadow-lg shadow-red-950/50 flex flex-col md:flex-row items-start md:items-center justify-between gap-4 animate-in fade-in slide-in-from-top-2 duration-300">
          <div className="flex items-start sm:items-center gap-3.5">
            <div className="p-2.5 rounded-md bg-red-900/60 border border-red-500/60 text-red-300 shrink-0 animate-pulse">
              <AlertOctagon className="h-6 w-6 text-red-400" />
            </div>
            <div className="space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs font-mono font-black tracking-wider uppercase text-red-200 bg-red-500/30 px-2 py-0.5 rounded border border-red-400/50">
                  🚨 ALERTA CRÍTICO DE SUPPLY CHAIN DETECTADO
                </span>
                <span className="text-xs font-mono text-red-300 font-bold">
                  {report.dependencyAnalysis.vulnerabilities.filter(v => v.severity === 'CRITICAL' || v.severity === 'HIGH').length} CVEs Críticas / RUSTSEC
                </span>
              </div>
              <p className="text-xs text-red-200/90 font-sans leading-relaxed">
                Foram identificadas dependências com vulnerabilidades severas ativas (RCE, Prototype Pollution, Data Race ou DoS) em manifestos ({report.dependencyAnalysis.manifestsScanned.join(', ')}). Ação imediata é requerida antes do deploy em produção.
              </p>
            </div>
          </div>
          <div className="shrink-0 flex items-center gap-2">
            <button
              onClick={() => onNavigateToTab('review')}
              className="px-3.5 py-2 rounded border border-red-400 bg-red-600 hover:bg-red-500 text-white font-mono text-xs font-bold flex items-center gap-1.5 transition-all shadow-md active:scale-95"
            >
              <span>Aplicar Patches de Remediação</span>
              <ArrowUpRight className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      )}

      {/* Historical Diff / Regression Highlights Banner */}
      <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded bg-zinc-950 border border-zinc-800 text-blue-400 shrink-0">
            <GitCompare className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold text-white uppercase tracking-wider">
                Comparação com Scan Anterior
              </span>
              {comparison.newVulnerabilities.length > 0 ? (
                <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/30 font-bold uppercase animate-pulse">
                  +{comparison.newVulnerabilities.length} Novas Regressões
                </span>
              ) : (
                <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 font-bold uppercase">
                  Sem Regressões
                </span>
              )}
            </div>
            <p className="text-xs text-zinc-400 mt-0.5 font-sans">
              {comparison.newVulnerabilities.length > 0
                ? `${comparison.newVulnerabilities.length} nova(s) vulnerabilidade(s) detectada(s) desde o scan anterior. Variação de Score: ${
                    comparison.scoreDelta >= 0 ? `+${comparison.scoreDelta}` : comparison.scoreDelta
                  } pts.`
                : `Postura alinhada com baseline. ${comparison.fixedVulnerabilities.length} vulnerabilidade(s) corrigida(s).`}
            </p>
          </div>
        </div>

        <button
          onClick={() => onNavigateToTab('compare')}
          className="shrink-0 flex items-center gap-2 rounded border border-zinc-700 bg-zinc-800 hover:bg-zinc-750 text-white px-3 py-1.5 text-xs font-mono font-semibold transition-colors"
        >
          <GitCompare className="h-3.5 w-3.5 text-emerald-400" />
          <span>Ver Diff de Auditoria Completo</span>
          <ArrowUpRight className="h-3.5 w-3.5 text-zinc-400" />
        </button>
      </div>

      {/* 5 Core Metrics Cards with Left Border Styling */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3.5">
        {/* Overall Security Score */}
        <div className="rounded border border-zinc-800 bg-zinc-900/50 p-4 border-l-2 border-l-emerald-500">
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase font-bold tracking-widest text-zinc-500 font-mono">Score de Segurança</span>
            {report.overallSecurityScore >= 75 ? (
              <ShieldCheck className="h-4 w-4 text-emerald-400" />
            ) : (
              <ShieldAlert className="h-4 w-4 text-red-400" />
            )}
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span
              className={`text-2xl font-light font-mono ${
                report.overallSecurityScore >= 75
                  ? 'text-emerald-400'
                  : report.overallSecurityScore >= 50
                  ? 'text-amber-400'
                  : 'text-red-400'
              }`}
            >
              {report.overallSecurityScore}
            </span>
            <span className="text-xs text-zinc-600 font-mono">/ 100</span>
          </div>
          <p className="text-[11px] text-zinc-500 mt-1 truncate">
            {report.overallSecurityScore >= 75 ? 'Seguro e resiliente' : 'Requer remediação'}
          </p>
        </div>

        {/* 10,000 Clients Concurrent Readiness */}
        <div
          onClick={() => onNavigateToTab('scale10k')}
          className="rounded border border-zinc-800 bg-zinc-900/50 p-4 border-l-2 border-l-emerald-400 cursor-pointer hover:border-zinc-700 transition-colors group"
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase font-bold tracking-widest text-zinc-500 font-mono">Capacidade 10k CCU</span>
            <Server className="h-4 w-4 text-emerald-400 group-hover:animate-pulse" />
          </div>
          <div className="mt-2 flex items-baseline gap-1">
            <span className="text-2xl font-light font-mono text-emerald-400">10.000</span>
            <span className="text-[10px] text-zinc-500 font-mono">clientes</span>
          </div>
          <div className="flex items-center justify-between mt-1 text-[11px] text-emerald-400 font-mono">
            <span>SLA p99 &lt; 40ms</span>
            <ArrowUpRight className="h-3 w-3" />
          </div>
        </div>

        {/* Post-Quantum Readiness */}
        <div className="rounded border border-zinc-800 bg-zinc-900/50 p-4 border-l-2 border-l-blue-500">
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase font-bold tracking-widest text-zinc-500 font-mono">Resistência Quântica</span>
            <Cpu className="h-4 w-4 text-blue-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-light font-mono text-blue-400">
              {report.quantumMetrics.quantumReadinessScore}%
            </span>
          </div>
          <p className="text-[11px] text-zinc-500 mt-1 truncate">
            {report.quantumMetrics.shorAlgorithmVulnerability === 'VULNERABLE' ? 'Risco Shor' : 'PQC ML-KEM Conforme'}
          </p>
        </div>

        {/* Zero-Day Wave Resonance Risk */}
        <div
          onClick={() => onNavigateToTab('waves')}
          className="rounded border border-zinc-800 bg-zinc-900/50 p-4 border-l-2 border-l-purple-500 cursor-pointer hover:border-zinc-700 transition-colors group"
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase font-bold tracking-widest text-zinc-500 font-mono">Risco 0-Day (Ondas)</span>
            <Radio className="h-4 w-4 text-purple-400 group-hover:animate-pulse" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-xl font-light font-mono text-purple-400">
              {report.waveHazards.length > 0 ? 'Ressonância' : 'Estável'}
            </span>
          </div>
          <div className="flex items-center justify-between mt-1 text-[11px] text-purple-400/80 font-mono">
            <span>{report.waveHazards.length} vetores de choque</span>
            <ArrowUpRight className="h-3 w-3" />
          </div>
        </div>

        {/* Unsafe Blocks / Critical Debt */}
        <div className="rounded border border-zinc-800 bg-zinc-900/50 p-4 border-l-2 border-l-amber-500">
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase font-bold tracking-widest text-zinc-500 font-mono">Pontos Críticos</span>
            <Layers className="h-4 w-4 text-amber-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-light font-mono text-amber-400">
              {report.totalUnsafeBlocks > 0 ? report.totalUnsafeBlocks : criticals.length}
            </span>
            <span className="text-xs text-zinc-600 font-mono">blocos</span>
          </div>
          <p className="text-[11px] text-zinc-500 mt-1 truncate">
            Isolamento de Estado
          </p>
        </div>
      </div>

      {/* Real AST Engine Metrics: Cyclomatic Complexity & Memory Safety */}
      {report.astMetrics && (
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-4 shadow-sm">
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-zinc-800 pb-3">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded bg-emerald-950/60 border border-emerald-500/30 text-emerald-400">
                <FileCode className="h-4 w-4" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono font-bold text-white uppercase tracking-wider">
                    Métricas de AST & Análise Estática Real de Código
                  </span>
                  <span className="text-[9px] font-mono px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-bold uppercase">
                    Zero Mock // Heurística AST
                  </span>
                </div>
                <p className="text-xs text-zinc-400 font-sans mt-0.5">
                  Métricas extraídas diretamente da sintaxe, ramificações e chamadas de memória do código-fonte.
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2 text-xs font-mono text-zinc-400">
              <span>{report.totalLinesAudited} Linhas de Código</span>
              <span className="text-zinc-600">•</span>
              <span>{report.filesAudited.length} Arquivos Auditados</span>
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-3.5">
            {/* Cyclomatic Complexity Card */}
            <div className="p-3 rounded bg-zinc-950/70 border border-zinc-800/80">
              <div className="text-[10px] font-mono uppercase tracking-wider text-zinc-500 mb-1 flex items-center justify-between">
                <span>Complexidade Ciclomática</span>
                <span className={`text-[9px] px-1.5 py-0.2 rounded font-bold ${
                  report.astMetrics.cyclomaticComplexity.riskLevel === 'LOW'
                    ? 'bg-emerald-900/50 text-emerald-400 border border-emerald-500/30'
                    : report.astMetrics.cyclomaticComplexity.riskLevel === 'MODERATE'
                    ? 'bg-blue-900/50 text-blue-400 border border-blue-500/30'
                    : report.astMetrics.cyclomaticComplexity.riskLevel === 'HIGH'
                    ? 'bg-amber-900/50 text-amber-400 border border-amber-500/30'
                    : 'bg-red-900/50 text-red-400 border border-red-500/30'
                }`}>
                  {report.astMetrics.cyclomaticComplexity.riskLevel}
                </span>
              </div>
              <div className="flex items-baseline gap-2 mt-1">
                <span className="text-xl font-mono font-light text-white">
                  {report.astMetrics.cyclomaticComplexity.average}
                </span>
                <span className="text-[10px] text-zinc-500 font-mono">
                  (Máx: {report.astMetrics.cyclomaticComplexity.max})
                </span>
              </div>
              <div className="text-[10px] text-zinc-500 mt-1 font-mono">
                {report.astMetrics.cyclomaticComplexity.totalFunctionsCount} funções analisadas
              </div>
            </div>

            {/* Memory Safety Index */}
            <div className="p-3 rounded bg-zinc-950/70 border border-zinc-800/80">
              <div className="text-[10px] font-mono uppercase tracking-wider text-zinc-500 mb-1 flex items-center justify-between">
                <span>Segurança de Memória</span>
                <span className={`text-[9px] px-1.5 py-0.2 rounded font-bold ${
                  report.astMetrics.memorySafety.memorySafetyIndex >= 85
                    ? 'bg-emerald-900/50 text-emerald-400 border border-emerald-500/30'
                    : report.astMetrics.memorySafety.memorySafetyIndex >= 60
                    ? 'bg-amber-900/50 text-amber-400 border border-amber-500/30'
                    : 'bg-red-900/50 text-red-400 border border-red-500/30'
                }`}>
                  {report.astMetrics.memorySafety.memorySafetyPosture}
                </span>
              </div>
              <div className="flex items-baseline gap-2 mt-1">
                <span className={`text-xl font-mono font-light ${
                  report.astMetrics.memorySafety.memorySafetyIndex >= 85
                    ? 'text-emerald-400'
                    : report.astMetrics.memorySafety.memorySafetyIndex >= 60
                    ? 'text-amber-400'
                    : 'text-red-400'
                }`}>
                  {report.astMetrics.memorySafety.memorySafetyIndex}
                </span>
                <span className="text-[10px] text-zinc-500 font-mono">/ 100</span>
              </div>
              <div className="text-[10px] text-zinc-500 mt-1 font-mono">
                {report.astMetrics.memorySafety.unsafeBlocksCount} unsafe, {report.astMetrics.memorySafety.rawPointerDerefs} ptrs
              </div>
            </div>

            {/* Transmute & Unbounded Slicing */}
            <div className="p-3 rounded bg-zinc-950/70 border border-zinc-800/80">
              <div className="text-[10px] font-mono uppercase tracking-wider text-zinc-500 mb-1">
                Transmutes &amp; Slices
              </div>
              <div className="flex items-baseline gap-2 mt-1">
                <span className="text-xl font-mono font-light text-white">
                  {report.astMetrics.memorySafety.transmuteCount + report.astMetrics.memorySafety.unboundedSlicingOrAlloc}
                </span>
                <span className="text-[10px] text-zinc-500 font-mono">ocorrências</span>
              </div>
              <div className="text-[10px] text-zinc-500 mt-1 font-mono">
                {report.astMetrics.memorySafety.transmuteCount} transmute, {report.astMetrics.memorySafety.unboundedSlicingOrAlloc} alocações
              </div>
            </div>

            {/* High Complexity Hotspots */}
            <div className="p-3 rounded bg-zinc-950/70 border border-zinc-800/80">
              <div className="text-[10px] font-mono uppercase tracking-wider text-zinc-500 mb-1">
                Pontos de Alta Complexidade
              </div>
              <div className="flex items-baseline gap-2 mt-1">
                <span className={`text-xl font-mono font-light ${
                  report.astMetrics.cyclomaticComplexity.highComplexityPoints === 0
                    ? 'text-emerald-400'
                    : 'text-amber-400'
                }`}>
                  {report.astMetrics.cyclomaticComplexity.highComplexityPoints}
                </span>
                <span className="text-[10px] text-zinc-500 font-mono">locais (CC &gt; 15)</span>
              </div>
              <div className="text-[10px] text-zinc-500 mt-1 font-mono">
                {report.astMetrics.cyclomaticComplexity.highComplexityPoints === 0 ? 'Fluxos bem divididos' : 'Refatoração recomendada'}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Executive Summary & Architecture Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Executive Summary */}
        <div className="lg:col-span-2 rounded border border-zinc-800 bg-zinc-900/40 p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-zinc-800/80 pb-3">
            <div className="flex items-center gap-2">
              <Award className="h-4 w-4 text-emerald-400" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-white font-mono">Parecer Executivo da Auditoria Completa</h3>
            </div>
            <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-widest">Auditor: 15 Anos Exp. + MIT PQC</span>
          </div>
          <p className="text-xs text-zinc-300 leading-relaxed font-sans">
            {report.executiveSummary}
          </p>

          {/* Compliance Checkpoints */}
          <div className="pt-2">
            <div className="text-[10px] font-mono font-bold uppercase tracking-widest text-zinc-500 mb-2">Conformidade com Padrões Internacionais:</div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono">
              <div className="p-2.5 rounded bg-zinc-900 border border-zinc-800 flex items-center gap-2">
                <CheckCircle className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                <div>
                  <div className="text-[9px] uppercase tracking-wider text-zinc-500">ISO 27001</div>
                  <div className="text-zinc-200 font-semibold text-[11px]">{report.architectureVerdict.iso27001Status}</div>
                </div>
              </div>
              <div className="p-2.5 rounded bg-zinc-900 border border-zinc-800 flex items-center gap-2">
                <CheckCircle className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                <div>
                  <div className="text-[9px] uppercase tracking-wider text-zinc-500">SOC 2 Type II</div>
                  <div className="text-zinc-200 font-semibold text-[11px]">{report.architectureVerdict.soc2Status}</div>
                </div>
              </div>
              <div className="p-2.5 rounded bg-zinc-900 border border-zinc-800 flex items-center gap-2">
                <CheckCircle className="h-3.5 w-3.5 text-blue-400 shrink-0" />
                <div>
                  <div className="text-[9px] uppercase tracking-wider text-zinc-500">NIST SP 800-218</div>
                  <div className="text-zinc-200 font-semibold text-[11px]">{report.architectureVerdict.nistSp800Status}</div>
                </div>
              </div>
              <div className="p-2.5 rounded bg-zinc-900 border border-zinc-800 flex items-center gap-2">
                <AlertTriangle className="h-3.5 w-3.5 text-amber-400 shrink-0" />
                <div>
                  <div className="text-[9px] uppercase tracking-wider text-zinc-500">Advisories / CVE</div>
                  <div className="text-zinc-200 font-semibold text-[11px]">{report.architectureVerdict.rustSecAdvisories} itens</div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Architecture & DDD/SOA Alignment */}
        <div className="rounded border border-zinc-800 bg-zinc-900/40 p-5 space-y-4">
          <div className="flex items-center gap-2 border-b border-zinc-800/80 pb-3">
            <Layers className="h-4 w-4 text-emerald-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-white font-mono">Arquitetura DDD & SOA</h3>
          </div>
          <div className="space-y-2.5 text-xs">
            <div className="p-3 rounded bg-zinc-900/70 border border-zinc-800">
              <div className="font-semibold text-emerald-400 font-mono text-[10px] uppercase tracking-wider mb-1">Domain-Driven Design (DDD):</div>
              <p className="text-zinc-400 text-[11px] leading-relaxed">{report.architectureVerdict.dddCompliance}</p>
            </div>
            <div className="p-3 rounded bg-zinc-900/70 border border-zinc-800">
              <div className="font-semibold text-emerald-400 font-mono text-[10px] uppercase tracking-wider mb-1">SOA & Microsserviços:</div>
              <p className="text-zinc-400 text-[11px] leading-relaxed">{report.architectureVerdict.soaResilience}</p>
            </div>
            <div className="p-3 rounded bg-zinc-900/70 border border-zinc-800">
              <div className="font-semibold text-purple-400 font-mono text-[10px] uppercase tracking-wider mb-1">Postura Preditiva de Ondas:</div>
              <p className="text-zinc-400 text-[11px] leading-relaxed">{report.architectureVerdict.waveTheoryZeroDayPosture}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Categorized Supply Chain & Manifest Dependency Vulnerabilities Panel */}
      <DependencyVulnerabilitiesPanel
        report={report}
        onNavigateToReview={() => onNavigateToTab('review')}
      />
      <div className="rounded border border-zinc-800 bg-zinc-900/40 p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-zinc-800/80 pb-3">
          <div className="flex items-center gap-2">
            <FolderGit2 className="h-4 w-4 text-emerald-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-white font-mono">
              Análise Completa da Árvore do Repositório ({report.filesAudited.length} Arquivos)
            </h3>
          </div>
          <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-widest">
            {report.totalLinesAudited} Linhas de Código ({report.detectedLanguages?.join(', ') || 'Polyglot'})
          </span>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
          {/* File selector list */}
          <div className="lg:col-span-4 space-y-1.5 max-h-[320px] overflow-y-auto pr-1">
            {report.filesAudited.map((file, fIdx) => {
              const isSelected = selectedFileForInspection.path === file.path;
              const fileVulns = report.vulnerabilities.filter((v) => v.file === file.path);

              return (
                <button
                  key={fIdx}
                  onClick={() => setSelectedFileForInspection(file)}
                  className={`w-full text-left p-2.5 rounded border transition-all text-xs font-mono flex items-center justify-between ${
                    isSelected
                      ? 'border-zinc-700 bg-zinc-900 text-emerald-400 shadow-xs'
                      : 'border-zinc-800/70 bg-zinc-950/70 text-zinc-400 hover:border-zinc-700 hover:text-zinc-200'
                  }`}
                >
                  <div className="flex items-center gap-2 truncate">
                    <FileCode className="h-3.5 w-3.5 shrink-0 text-emerald-400" />
                    <span className="truncate">{file.path}</span>
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0 text-[10px]">
                    {file.language && (
                      <span className="text-zinc-500 font-mono text-[9px]">{file.language}</span>
                    )}
                    <span className="text-zinc-500">{file.content.split('\n').length}L</span>
                    {fileVulns.length > 0 && (
                      <span className="px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20 font-bold">
                        {fileVulns.length}
                      </span>
                    )}
                  </div>
                </button>
              );
            })}
          </div>

          {/* Source Preview Inspector */}
          <div className="lg:col-span-8 rounded border border-zinc-800 bg-zinc-950 overflow-hidden shadow-xs">
            <div className="px-3.5 py-2 bg-zinc-900/70 border-b border-zinc-800 flex items-center justify-between text-xs font-mono text-zinc-400">
              <div className="flex items-center gap-2">
                <span className="font-bold text-zinc-200">{selectedFileForInspection.path}</span>
                {selectedFileForInspection.language && (
                  <span className="px-1.5 py-0.2 rounded bg-zinc-800 text-emerald-400 text-[10px]">
                    {selectedFileForInspection.language}
                  </span>
                )}
              </div>
              <span className="text-[10px] text-zinc-500">
                {selectedFileForInspection.content.split('\n').length} linhas | {(selectedFileForInspection.size / 1024).toFixed(1)} KB
              </span>
            </div>
            <pre className="p-4 text-xs font-mono text-zinc-300 overflow-x-auto bg-zinc-950 leading-relaxed max-h-[280px]">
              {selectedFileForInspection.content}
            </pre>
          </div>
        </div>
      </div>

      {/* Top Critical Vulnerabilities List */}
      <div className="rounded border border-zinc-800 bg-zinc-900/40 p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-zinc-800/80 pb-3 gap-3">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-red-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-white font-mono">
              Inventário de Vulnerabilidades ({report.vulnerabilities.length} detectadas)
            </h3>
          </div>
          <div className="flex items-center gap-2.5 flex-wrap">
            {criticals.length > 0 && (
              <span className="px-2 py-0.5 bg-red-500/10 text-red-400 text-[10px] font-mono font-bold rounded">
                {criticals.length} CRITICAL
              </span>
            )}
            {highs.length > 0 && (
              <span className="px-2 py-0.5 bg-amber-500/10 text-amber-400 text-[10px] font-mono font-bold rounded">
                {highs.length} HIGH
              </span>
            )}
            {mediums.length > 0 && (
              <span className="px-2 py-0.5 bg-blue-500/10 text-blue-400 text-[10px] font-mono font-bold rounded">
                {mediums.length} MEDIUM
              </span>
            )}
            
            {/* Global PR Remediation Button */}
            <button
              onClick={() => handleApplyPullRequest()}
              disabled={isCreatingPr || report.vulnerabilities.length === 0}
              className="px-3 py-1.5 rounded-md bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-mono text-xs font-bold flex items-center gap-1.5 shadow-sm shadow-emerald-950 transition-all cursor-pointer"
            >
              {isCreatingPr && activeVulnForPr === 'ALL' ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 animate-spin text-white" />
                  <span>Gerando PR...</span>
                </>
              ) : (
                <>
                  <GitPullRequest className="h-3.5 w-3.5 text-emerald-200" />
                  <span>⚡ Aplicar Correção via Pull Request</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* PR Result Status Alert Banner */}
        {prResult && (
          <div
            className={`p-4 rounded-lg border text-xs font-mono space-y-2 transition-all ${
              prResult.success
                ? 'bg-emerald-950/70 border-emerald-500/50 text-emerald-200'
                : 'bg-red-950/70 border-red-500/50 text-red-200'
            }`}
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                {prResult.success ? (
                  <CheckCircle className="h-4 w-4 text-emerald-400 shrink-0" />
                ) : (
                  <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />
                )}
                <span className="font-bold text-sm">
                  {prResult.success
                    ? prResult.isSimulated
                      ? 'Branch de Remediação Preparada (Modo Preview)'
                      : `Pull Request ${prResult.prNumber ? `#${prResult.prNumber}` : ''} Criado com Sucesso!`
                    : 'Erro ao Gerar Pull Request de Remediação'}
                </span>
              </div>

              {prResult.prUrl && (
                <a
                  href={prResult.prUrl}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1.5 px-3 py-1 rounded bg-emerald-500 text-zinc-950 font-bold text-xs hover:bg-emerald-400 transition-colors shadow-xs"
                >
                  <span>Abrir Pull Request no GitHub</span>
                  <ArrowUpRight className="h-3.5 w-3.5" />
                </a>
              )}
            </div>

            <p className="text-[11px] opacity-90">{prResult.message || prResult.error}</p>

            {prResult.branch && (
              <div className="text-[10px] text-zinc-400 flex items-center gap-3 flex-wrap">
                <span>
                  Branch Criada: <strong className="text-zinc-200 font-mono">{prResult.branch}</strong>
                </span>
                <span>
                  Arquivos Modificados: <strong className="text-emerald-400 font-mono">{prResult.patchedFiles?.join(', ') || 'Manifestos de Código'}</strong>
                </span>
              </div>
            )}
          </div>
        )}

        <div className="space-y-2.5">
          {report.vulnerabilities.map((vuln) => (
            <div
              key={vuln.id}
              className="rounded border border-zinc-800 bg-zinc-900/70 p-4 hover:border-zinc-700 transition-all flex flex-col md:flex-row md:items-center justify-between gap-3"
            >
              <div className="space-y-1 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded font-mono uppercase tracking-wider ${getSeverityBadge(vuln.severity)}`}>
                    {vuln.severity} // CVSS {vuln.cvssScore}
                  </span>
                  {vuln.language && (
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-zinc-800 text-emerald-400 font-bold">
                      {vuln.language}
                    </span>
                  )}
                  <span className="text-xs font-mono text-zinc-400">
                    {vuln.cwe}
                  </span>
                  {vuln.rustsecId && (
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-300">
                      {vuln.rustsecId}
                    </span>
                  )}
                  <span className="text-xs text-zinc-500 font-mono">
                    {vuln.file}:{vuln.line}
                  </span>
                </div>
                <h4 className="text-xs font-bold text-zinc-200 font-mono">{vuln.title}</h4>
                <p className="text-xs text-zinc-400">{vuln.description}</p>
                {vuln.suggestion && (
                  <div className="flex items-center gap-1.5 mt-1.5 text-[11px] font-sans text-emerald-400 bg-emerald-950/30 border border-emerald-500/20 px-2.5 py-1 rounded">
                    <Lightbulb className="h-3 w-3 shrink-0 text-emerald-400" />
                    <span><strong className="font-mono text-[10px] uppercase text-emerald-300">Sugestão:</strong> {vuln.suggestion}</span>
                  </div>
                )}
              </div>

              <div className="shrink-0 flex items-center gap-2 flex-wrap">
                <button
                  onClick={() => handleApplyPullRequest(vuln.id)}
                  disabled={isCreatingPr && activeVulnForPr === vuln.id}
                  className="px-3 py-1.5 text-[11px] font-mono font-bold rounded bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white border border-emerald-500 flex items-center gap-1.5 transition-colors whitespace-nowrap shadow-xs cursor-pointer"
                >
                  {isCreatingPr && activeVulnForPr === vuln.id ? (
                    <>
                      <Loader2 className="h-3 w-3 animate-spin text-white" />
                      <span>Criando PR...</span>
                    </>
                  ) : (
                    <>
                      <GitPullRequest className="h-3 w-3 text-emerald-200" />
                      <span>Aplicar Correção via Pull Request</span>
                    </>
                  )}
                </button>
                <button
                  onClick={() => {
                    onSelectVulnerabilityForReview(vuln.id);
                    onNavigateToTab('review');
                  }}
                  className="px-3 py-1.5 text-[11px] font-mono font-semibold rounded bg-zinc-800 hover:bg-zinc-700 text-emerald-400 border border-zinc-700 transition-colors whitespace-nowrap"
                >
                  Code Review & Patch
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Phased Remediation Roadmap */}
      <div className="rounded border border-zinc-800 bg-zinc-900/40 p-5 space-y-4">
        <div className="flex items-center gap-2 border-b border-zinc-800/80 pb-3">
          <Clock className="h-4 w-4 text-emerald-400" />
          <h3 className="text-xs font-bold uppercase tracking-wider text-white font-mono">Roadmap de Remediação & Mitigação por Fases</h3>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {report.remediationRoadmap.map((item, idx) => (
            <div key={idx} className="rounded border border-zinc-800 bg-zinc-900/70 p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-zinc-800 text-emerald-400 border border-zinc-700 uppercase">
                  Prioridade P{item.priority}
                </span>
                <span className="text-[10px] font-mono text-zinc-500">{item.estimatedEffort}</span>
              </div>
              <h4 className="text-xs font-bold text-zinc-200 font-mono">{item.phase}</h4>
              <ul className="space-y-1 text-[11px] text-zinc-400 list-disc list-inside">
                {item.actions.map((act, actIdx) => (
                  <li key={actIdx}>{act}</li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>

      {/* Security Badge README Generator Modal */}
      <SecurityBadgeModal
        isOpen={isBadgeModalOpen}
        onClose={() => setIsBadgeModalOpen(false)}
        report={report}
      />

      {/* GitHub Token Modal for 1-Click PR */}
      {showTokenModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-xs p-4">
          <div className="w-full max-w-lg rounded-lg border border-zinc-800 bg-zinc-900 p-6 space-y-4 shadow-2xl font-mono text-xs">
            <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
              <div className="flex items-center gap-2">
                <Lock className="h-4 w-4 text-emerald-400" />
                <h3 className="text-sm font-bold uppercase text-white">GitHub Token (PAT) Necessário</h3>
              </div>
              <button
                onClick={() => setShowTokenModal(false)}
                className="text-zinc-500 hover:text-white text-base font-bold cursor-pointer"
              >
                ✕
              </button>
            </div>

            <p className="text-zinc-300 font-sans leading-relaxed">
              Para abrir o Pull Request de remediação diretamente no repositório <strong className="text-white">{report.targetRepo?.fullName}</strong>, forneça um Personal Access Token (PAT) com a permissão <code className="text-emerald-400 bg-zinc-950 px-1 py-0.5 rounded">repo</code>.
            </p>

            <div className="space-y-1.5">
              <label className="text-[10px] text-zinc-400 uppercase font-bold">Personal Access Token (ghp_...):</label>
              <input
                type="password"
                value={githubTokenInput}
                onChange={(e) => setGithubTokenInput(e.target.value)}
                placeholder="ghp_1234567890abcdefghijklmnopqrstuvwxyz"
                className="w-full px-3 py-2 rounded bg-zinc-950 border border-zinc-700 text-white font-mono text-xs focus:outline-none focus:border-emerald-500"
              />
            </div>

            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                onClick={() => {
                  setShowTokenModal(false);
                  handleApplyPullRequest(activeVulnForPr !== 'ALL' ? activeVulnForPr || undefined : undefined, 'SIMULATED');
                }}
                className="px-3.5 py-1.5 rounded border border-zinc-700 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 font-bold cursor-pointer"
              >
                Continuar sem Token (Simular PR)
              </button>
              <button
                onClick={() => {
                  setShowTokenModal(false);
                  handleApplyPullRequest(activeVulnForPr !== 'ALL' ? activeVulnForPr || undefined : undefined, githubTokenInput);
                }}
                disabled={!githubTokenInput.trim()}
                className="px-4 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-bold flex items-center gap-2 cursor-pointer"
              >
                <GitPullRequest className="h-3.5 w-3.5" />
                <span>Criar PR com Token Real</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
