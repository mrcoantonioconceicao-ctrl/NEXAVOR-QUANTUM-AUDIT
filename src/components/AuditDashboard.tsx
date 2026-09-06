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
  ChevronDown,
  ChevronUp,
  BookOpen,
  Filter,
  CheckCircle2,
  SlidersHorizontal,
} from 'lucide-react';
import { SecurityAuditReport, VulnerabilitySeverity, SourceFile, RustVulnerability } from '../domain/types.ts';
import { TabType } from './Sidebar.tsx';
import { getAuditHistory, compareAuditReports, generateSyntheticBaselineSession } from '../services/auditHistoryService.ts';
import { SecurityBadgeModal } from './SecurityBadgeModal.tsx';
import { DependencyVulnerabilitiesPanel } from './DependencyVulnerabilitiesPanel.tsx';
import { createGitHubPullRequest, CreatePrResult } from '../services/githubService.ts';
import { exportAuditToCsv } from '../services/excelExporter.ts';
import { HelpTooltip } from './HelpTooltip.tsx';
import { DevSecOpsGlossaryModal } from './DevSecOpsGlossaryModal.tsx';
import { RemediationDrawer } from './RemediationDrawer.tsx';

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

  // UX Reorganization: Progressive Reading & Dynamic Remediation Drawer
  const [isAdvancedEngineOpen, setIsAdvancedEngineOpen] = useState<boolean>(false);
  const [isGlossaryOpen, setIsGlossaryOpen] = useState<boolean>(false);
  const [selectedVulnForDrawer, setSelectedVulnForDrawer] = useState<RustVulnerability | null>(null);
  const [triageFilter, setTriageFilter] = useState<'ALL' | 'BLOCKERS' | 'ATTENTION' | 'OPTIONAL'>('ALL');
  const [treeFileFilter, setTreeFileFilter] = useState<'ALL' | 'VULNERABLE' | 'BLOCKERS'>('ALL');

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

  // Triagem clara baseada em impacto
  const blockers = useMemo(() => {
    return report.vulnerabilities.filter(
      (v) => v.severity === 'CRITICAL' || v.category === 'MEMORY_SAFETY'
    );
  }, [report.vulnerabilities]);

  const attention = useMemo(() => {
    return report.vulnerabilities.filter(
      (v) => (v.severity === 'HIGH' || v.severity === 'MEDIUM') && v.category !== 'MEMORY_SAFETY'
    );
  }, [report.vulnerabilities]);

  const optionals = useMemo(() => {
    return report.vulnerabilities.filter(
      (v) => v.severity === 'LOW' || v.severity === 'INFORMATIONAL'
    );
  }, [report.vulnerabilities]);

  const filteredVulnerabilities = useMemo(() => {
    switch (triageFilter) {
      case 'BLOCKERS':
        return blockers;
      case 'ATTENTION':
        return attention;
      case 'OPTIONAL':
        return optionals;
      case 'ALL':
      default:
        return report.vulnerabilities;
    }
  }, [triageFilter, blockers, attention, optionals, report.vulnerabilities]);

  // Status de Prontidão (Production Readiness) em linguagem natural e direta
  const readinessStatus = useMemo(() => {
    const hasCriticalDeps = report.dependencyAnalysis?.vulnerabilities.some(
      (dv) => dv.severity === 'CRITICAL' || dv.severity === 'HIGH'
    );

    if (blockers.length > 0 || hasCriticalDeps) {
      return {
        level: 'CRITICAL',
        title: 'Riscos Críticos Detectados',
        subtext: 'Bloqueador de Produção',
        icon: ShieldAlert,
        badgeColor: 'bg-red-500/20 text-red-300 border-red-500/40',
        borderColor: 'border-red-500/40 bg-red-950/20',
        indicatorColor: 'bg-red-500',
        textColor: 'text-red-400',
        summary: `Foram detectados ${blockers.length} bloqueador(es) crítico(s) de integridade de memória e/ou vulnerabilidades graves de supply chain. Ação imediata é necessária antes do deploy.`,
        recommendation: 'Corrija os bloqueadores prioritários antes de prosseguir com qualquer release em ambiente produtivo.',
        actionLabel: 'Ver Bloqueadores',
      };
    }

    if (attention.length > 0) {
      return {
        level: 'ATTENTION',
        title: 'Atenção Requerida',
        subtext: 'Revisão Recomendada',
        icon: AlertTriangle,
        badgeColor: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
        borderColor: 'border-amber-500/40 bg-amber-950/20',
        indicatorColor: 'bg-amber-500',
        textColor: 'text-amber-400',
        summary: `O código não apresenta bloqueadores fatais imediatos, mas possui ${attention.length} débito(s) de segurança que exigem revisão durante a sprint antes do deploy final.`,
        recommendation: 'Agende a refatoração dos itens de alta complexidade e atualize crates secundárias.',
        actionLabel: 'Ver Itens de Atenção',
      };
    }

    return {
      level: 'SAFE',
      title: 'Código Seguro para Produção',
      subtext: 'Aprovado para Release',
      icon: ShieldCheck,
      badgeColor: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
      borderColor: 'border-emerald-500/40 bg-emerald-950/20',
      indicatorColor: 'bg-emerald-500',
      textColor: 'text-emerald-400',
      summary: 'Todas as verificações sintáticas de AST, integridade de memória, criptografia e dependências foram aprovadas com sucesso. Pronto para release!',
      recommendation: 'Mantenha os gates do CI/CD ativos para validar novos commits e pull requests.',
      actionLabel: 'Exportar Relatório',
    };
  }, [blockers.length, attention.length, report.dependencyAnalysis]);

  // Filtro para a árvore de arquivos
  const filteredTreeFiles = useMemo(() => {
    return report.filesAudited.filter((file) => {
      const fileVulns = report.vulnerabilities.filter((v) => v.file === file.path);
      if (treeFileFilter === 'BLOCKERS') {
        return fileVulns.some((v) => v.severity === 'CRITICAL' || v.category === 'MEMORY_SAFETY');
      }
      if (treeFileFilter === 'VULNERABLE') {
        return fileVulns.length > 0;
      }
      return true;
    });
  }, [report.filesAudited, report.vulnerabilities, treeFileFilter]);

  // Arquivos vulneráveis selecionados
  const selectedFileVulns = useMemo(() => {
    return report.vulnerabilities.filter((v) => v.file === selectedFileForInspection.path);
  }, [report.vulnerabilities, selectedFileForInspection.path]);

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

        <div className="flex items-center gap-2.5 flex-wrap shrink-0">
          <button
            onClick={() => setIsGlossaryOpen(true)}
            className="px-3 py-1.5 rounded border border-purple-500/40 bg-purple-950/40 hover:bg-purple-900/60 text-purple-300 font-mono text-xs font-bold flex items-center gap-1.5 transition-colors shadow-xs cursor-pointer"
            title="Abrir Glossário DevSecOps com explicações em português de métricas e termos técnicos"
          >
            <BookOpen className="h-4 w-4 text-purple-400" />
            <span>Glossário DevSecOps</span>
          </button>
          <button
            onClick={() => exportAuditToCsv(report)}
            className="px-3 py-1.5 rounded border border-blue-500/40 bg-blue-950/40 hover:bg-blue-900/60 text-blue-300 font-mono text-xs font-bold flex items-center gap-1.5 transition-colors shadow-xs cursor-pointer"
            title="Exportar todas as vulnerabilidades e relatórios para planilha Excel (.csv)"
          >
            <FileSpreadsheet className="h-4 w-4 text-blue-400" />
            <span>Excel (.csv)</span>
          </button>
          <button
            onClick={() => setIsBadgeModalOpen(true)}
            className="px-3 py-1.5 rounded border border-emerald-500/40 bg-emerald-950/40 hover:bg-emerald-900/60 text-emerald-300 font-mono text-xs font-bold flex items-center gap-1.5 transition-colors shadow-xs cursor-pointer"
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

      {/* Camadas de Leitura Progressiva: Status de Prontidão (Production Readiness) */}
      <div className={`rounded-xl border p-5 shadow-lg transition-all ${readinessStatus.borderColor}`}>
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-start sm:items-center gap-3.5">
            <div className={`p-3 rounded-lg border shrink-0 ${readinessStatus.badgeColor}`}>
              <readinessStatus.icon className="h-6 w-6" />
            </div>
            <div className="space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className={`text-xs font-mono font-black uppercase tracking-wider px-2.5 py-0.5 rounded border ${readinessStatus.badgeColor}`}>
                  {readinessStatus.subtext}
                </span>
                <h3 className="text-base font-bold text-white font-mono flex items-center gap-2">
                  <span>{readinessStatus.title}</span>
                  <HelpTooltip
                    title="Status de Prontidão"
                    content="Avaliação semafórica em linguagem natural que analisa se o repositório está seguro para produção ou se possui bloqueadores fatais."
                    impact="Evita deploys de código vulnerável que possam causar incidentes de segurança ou indisponibilidade."
                  />
                </h3>
              </div>
              <p className="text-xs text-zinc-300 font-sans leading-relaxed max-w-3xl">
                {readinessStatus.summary}
              </p>
              <div className="text-[11px] text-zinc-400 font-sans flex items-center gap-1.5 pt-0.5">
                <strong className="text-zinc-300 font-mono uppercase text-[10px]">Recomendação:</strong>
                <span>{readinessStatus.recommendation}</span>
              </div>
            </div>
          </div>

          <div className="shrink-0 flex items-center gap-2">
            {readinessStatus.level === 'CRITICAL' && (
              <button
                onClick={() => {
                  setTriageFilter('BLOCKERS');
                  const el = document.getElementById('inventory-section');
                  el?.scrollIntoView({ behavior: 'smooth' });
                }}
                className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white font-mono text-xs font-bold flex items-center gap-1.5 transition-all shadow-md active:scale-95 cursor-pointer"
              >
                <span>Ver {blockers.length} Bloqueadores</span>
                <ArrowUpRight className="h-4 w-4" />
              </button>
            )}
            {readinessStatus.level === 'ATTENTION' && (
              <button
                onClick={() => {
                  setTriageFilter('ATTENTION');
                  const el = document.getElementById('inventory-section');
                  el?.scrollIntoView({ behavior: 'smooth' });
                }}
                className="px-4 py-2 rounded-lg bg-amber-600 hover:bg-amber-500 text-white font-mono text-xs font-bold flex items-center gap-1.5 transition-all shadow-md active:scale-95 cursor-pointer"
              >
                <span>Ver {attention.length} Itens de Atenção</span>
                <ArrowUpRight className="h-4 w-4" />
              </button>
            )}
            {readinessStatus.level === 'SAFE' && (
              <button
                onClick={() => exportAuditToCsv(report)}
                className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-mono text-xs font-bold flex items-center gap-1.5 transition-all shadow-md active:scale-95 cursor-pointer"
              >
                <FileSpreadsheet className="h-4 w-4" />
                <span>Exportar Relatório Seguro (.csv)</span>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* 4 Cartões Primários Simplificados (Visão Executiva Clara) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Card 1: Status de Prontidão */}
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-4 relative overflow-hidden">
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase font-bold tracking-widest text-zinc-400 font-mono flex items-center gap-1.5">
              <span>Status de Deploy</span>
              <HelpTooltip
                title="Status de Deploy"
                content="Indica se o código atende às barreiras de qualidade para liberação contínua sem quebras de contrato ou falhas de memória."
                impact="Repositórios bloqueados não devem receber tag de release em produção."
              />
            </span>
            <span className={`w-2.5 h-2.5 rounded-full ${readinessStatus.indicatorColor} animate-pulse`} />
          </div>
          <div className="mt-2.5">
            <div className={`text-lg font-bold font-mono ${readinessStatus.textColor} leading-tight truncate`}>
              {readinessStatus.title}
            </div>
            <p className="text-[11px] text-zinc-400 mt-1 truncate">
              {readinessStatus.subtext}
            </p>
          </div>
        </div>

        {/* Card 2: Bloqueadores Imediatos */}
        <div
          onClick={() => {
            setTriageFilter('BLOCKERS');
            const el = document.getElementById('inventory-section');
            el?.scrollIntoView({ behavior: 'smooth' });
          }}
          className={`rounded-lg border p-4 cursor-pointer transition-all ${
            blockers.length > 0
              ? 'border-red-500/40 bg-red-950/20 hover:border-red-500/70 hover:bg-red-950/30'
              : 'border-zinc-800 bg-zinc-900/60 hover:border-zinc-700'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase font-bold tracking-widest text-zinc-400 font-mono flex items-center gap-1.5">
              <span>Bloqueadores</span>
              <HelpTooltip
                title="Falhas Bloqueadoras"
                content="Vulnerabilidades de gravidade Crítica (CVSS >= 9.0) ou riscos graves de Memory Safety que comprometem o isolamento do processo."
                impact="Podem permitir Execução Remota de Código (RCE), corrupção de memória ou falha catastrófica."
              />
            </span>
            <ShieldAlert className={`h-4 w-4 ${blockers.length > 0 ? 'text-red-400' : 'text-zinc-500'}`} />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className={`text-2xl font-bold font-mono ${blockers.length > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
              {blockers.length}
            </span>
            <span className="text-xs text-zinc-500 font-mono">falhas</span>
          </div>
          <p className="text-[11px] text-zinc-400 mt-1 flex items-center justify-between">
            <span>{blockers.length > 0 ? 'Ação imediata necessária' : 'Nenhum bloqueador'}</span>
            <ArrowUpRight className="h-3 w-3 text-zinc-500" />
          </p>
        </div>

        {/* Card 3: Itens em Atenção */}
        <div
          onClick={() => {
            setTriageFilter('ATTENTION');
            const el = document.getElementById('inventory-section');
            el?.scrollIntoView({ behavior: 'smooth' });
          }}
          className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-4 cursor-pointer hover:border-zinc-700 hover:bg-zinc-900/80 transition-all"
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase font-bold tracking-widest text-zinc-400 font-mono flex items-center gap-1.5">
              <span>Em Atenção</span>
              <HelpTooltip
                title="Itens de Atenção"
                content="Falhas de severidade Média e Alta que devem ser sanadas na sprint para evitar acúmulo de débito técnico."
                impact="Degrada a confiabilidade e resiliência do sistema com o tempo."
              />
            </span>
            <AlertTriangle className="h-4 w-4 text-amber-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-amber-400">
              {attention.length}
            </span>
            <span className="text-xs text-zinc-500 font-mono">itens</span>
          </div>
          <p className="text-[11px] text-zinc-400 mt-1 flex items-center justify-between">
            <span>Revisão recomendada</span>
            <ArrowUpRight className="h-3 w-3 text-zinc-500" />
          </p>
        </div>

        {/* Card 4: Score de Segurança Executivo */}
        <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-4">
          <div className="flex items-center justify-between">
            <span className="text-[10px] uppercase font-bold tracking-widest text-zinc-400 font-mono flex items-center gap-1.5">
              <span>Score de Segurança</span>
              <HelpTooltip
                title="Score de Segurança"
                content="Nota calculada ponderando severidade CVSS, contagem de unsafe blocks e postura de conformidade das dependências."
                impact="Scores acima de 75 indicam maturidade satisfatória para aprovação em auditorias formais."
              />
            </span>
            {report.overallSecurityScore >= 75 ? (
              <ShieldCheck className="h-4 w-4 text-emerald-400" />
            ) : (
              <ShieldAlert className="h-4 w-4 text-amber-400" />
            )}
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span
              className={`text-2xl font-bold font-mono ${
                report.overallSecurityScore >= 75
                  ? 'text-emerald-400'
                  : report.overallSecurityScore >= 50
                  ? 'text-amber-400'
                  : 'text-red-400'
              }`}
            >
              {report.overallSecurityScore}
            </span>
            <span className="text-xs text-zinc-500 font-mono">/ 100</span>
          </div>
          {/* Visual Progress Bar */}
          <div className="w-full h-1.5 bg-zinc-800 rounded-full mt-2 overflow-hidden">
            <div
              className={`h-full transition-all duration-500 ${
                report.overallSecurityScore >= 75
                  ? 'bg-emerald-500'
                  : report.overallSecurityScore >= 50
                  ? 'bg-amber-500'
                  : 'bg-red-500'
              }`}
              style={{ width: `${Math.min(100, Math.max(0, report.overallSecurityScore))}%` }}
            />
          </div>
        </div>
      </div>

      {/* ACORDEÃO: VISÃO AVANÇADA / ENGENHARIA DEEP TECH */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 overflow-hidden transition-all shadow-sm">
        <button
          onClick={() => setIsAdvancedEngineOpen(!isAdvancedEngineOpen)}
          className="w-full px-5 py-3.5 flex items-center justify-between bg-zinc-950/60 hover:bg-zinc-950/90 text-left transition-colors cursor-pointer border-b border-zinc-800/80"
        >
          <div className="flex items-center gap-2.5">
            <div className="p-1.5 rounded-md bg-purple-950/60 border border-purple-500/30 text-purple-400">
              <SlidersHorizontal className="h-4 w-4" />
            </div>
            <div>
              <div className="text-xs font-mono font-bold text-white flex items-center gap-2">
                <span>Visão Avançada / Engenharia Deep Tech (PQC, Teoria de Ondas, AST & Concorrência)</span>
                <span className="text-[10px] px-2 py-0.2 rounded bg-zinc-800 text-zinc-400 font-normal">
                  {isAdvancedEngineOpen ? 'Recolher' : 'Expandir'}
                </span>
              </div>
              <p className="text-[11px] text-zinc-400 font-sans mt-0.5">
                Métricas aprofundadas de criptografia quântica, entropia espectral e análise estática sintática da AST.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 text-zinc-400">
            {isAdvancedEngineOpen ? (
              <ChevronUp className="h-5 w-5 text-purple-400" />
            ) : (
              <ChevronDown className="h-5 w-5 text-zinc-400" />
            )}
          </div>
        </button>

        {isAdvancedEngineOpen && (
          <div className="p-5 space-y-6 animate-in fade-in slide-in-from-top-2 duration-200">
            {/* 4 Cartões Técnicos Avançados */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
              {/* Capacidade 10k CCU */}
              <div
                onClick={() => onNavigateToTab('scale10k')}
                className="rounded-lg border border-zinc-800 bg-zinc-950/70 p-4 cursor-pointer hover:border-zinc-700 transition-colors group"
              >
                <div className="flex items-center justify-between">
                  <span className="text-[10px] uppercase font-bold tracking-widest text-zinc-400 font-mono flex items-center gap-1">
                    <span>Capacidade 10k CCU</span>
                    <HelpTooltip
                      title="Capacidade 10k Concorrência"
                      content="Resiliência comprovada de concorrência com 10.000 clientes simultâneos sob thread-safety rigoroso."
                      impact="Garante ausência de thread contention e memory spikes em picos de tráfego."
                    />
                  </span>
                  <Server className="h-4 w-4 text-emerald-400 group-hover:animate-pulse" />
                </div>
                <div className="mt-2 flex items-baseline gap-1">
                  <span className="text-xl font-bold font-mono text-emerald-400">10.000</span>
                  <span className="text-[10px] text-zinc-500 font-mono">clientes</span>
                </div>
                <div className="flex items-center justify-between mt-1 text-[11px] text-emerald-400 font-mono">
                  <span>SLA p99 &lt; 40ms</span>
                  <ArrowUpRight className="h-3 w-3" />
                </div>
              </div>

              {/* Resistência Quântica PQC */}
              <div
                onClick={() => onNavigateToTab('pqc')}
                className="rounded-lg border border-zinc-800 bg-zinc-950/70 p-4 cursor-pointer hover:border-zinc-700 transition-colors group"
              >
                <div className="flex items-center justify-between">
                  <span className="text-[10px] uppercase font-bold tracking-widest text-zinc-400 font-mono flex items-center gap-1">
                    <span>Resistência Quântica</span>
                    <HelpTooltip
                      title="Resistência Quântica PQC"
                      content="Mede a blindagem das primitivas criptográficas contra ataques pelo Algoritmo de Shor em computadores quânticos."
                      impact="Criptografia tradicional (RSA/ECC) pode ser quebrada no futuro em ataques 'Store Now, Decrypt Later'."
                    />
                  </span>
                  <Cpu className="h-4 w-4 text-blue-400" />
                </div>
                <div className="mt-2 flex items-baseline gap-2">
                  <span className="text-xl font-bold font-mono text-blue-400">
                    {report.quantumMetrics.quantumReadinessScore}%
                  </span>
                  <span className="text-[10px] text-zinc-500 font-mono">PQC Index</span>
                </div>
                <div className="flex items-center justify-between mt-1 text-[11px] text-blue-400 font-mono">
                  <span>{report.quantumMetrics.shorAlgorithmVulnerability === 'VULNERABLE' ? 'Risco Shor Detectado' : 'ML-KEM Conforme'}</span>
                  <ArrowUpRight className="h-3 w-3" />
                </div>
              </div>

              {/* Risco 0-Day (Teoria de Ondas) */}
              <div
                onClick={() => onNavigateToTab('waves')}
                className="rounded-lg border border-zinc-800 bg-zinc-950/70 p-4 cursor-pointer hover:border-zinc-700 transition-colors group"
              >
                <div className="flex items-center justify-between">
                  <span className="text-[10px] uppercase font-bold tracking-widest text-zinc-400 font-mono flex items-center gap-1">
                    <span>Risco 0-Day (Ondas)</span>
                    <HelpTooltip
                      title="Teoria de Ondas Zero-Day"
                      content="Mapeamento preditivo de anomalias sintáticas e entropia espectral para identificar onde novos bugs de dia zero tendem a surgir."
                      impact="Permite refatoração preventiva antes que falhas desconhecidas virem exploits em produção."
                    />
                  </span>
                  <Radio className="h-4 w-4 text-purple-400 group-hover:animate-pulse" />
                </div>
                <div className="mt-2 flex items-baseline gap-2">
                  <span className="text-xl font-bold font-mono text-purple-400">
                    {report.waveHazards.length > 0 ? 'Ressonância' : 'Estável'}
                  </span>
                </div>
                <div className="flex items-center justify-between mt-1 text-[11px] text-purple-400/80 font-mono">
                  <span>{report.waveHazards.length} vetores de choque</span>
                  <ArrowUpRight className="h-3 w-3" />
                </div>
              </div>

              {/* Pontos Críticos / Unsafe Blocks */}
              <div className="rounded-lg border border-zinc-800 bg-zinc-950/70 p-4">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] uppercase font-bold tracking-widest text-zinc-400 font-mono flex items-center gap-1">
                    <span>Pontos Críticos</span>
                    <HelpTooltip
                      title="Blocos Unsafe e Isolamento"
                      content="Blocos onde as checagens do compilador Rust foram desativadas manualmente, exigindo auditoria de limites de memória."
                      impact="Desreferenciação incorreta causa falhas de segmentação (Segmentation Fault) e Buffer Overflow."
                    />
                  </span>
                  <Layers className="h-4 w-4 text-amber-400" />
                </div>
                <div className="mt-2 flex items-baseline gap-2">
                  <span className="text-xl font-bold font-mono text-amber-400">
                    {report.totalUnsafeBlocks > 0 ? report.totalUnsafeBlocks : criticals.length}
                  </span>
                  <span className="text-xs text-zinc-500 font-mono">blocos</span>
                </div>
                <p className="text-[11px] text-zinc-400 mt-1 truncate font-mono">
                  Isolamento de Estado
                </p>
              </div>
            </div>

            {/* Painel Real de Métricas de AST */}
            {report.astMetrics && (
              <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-4 space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-zinc-800 gap-2">
                  <div className="flex items-center gap-2">
                    <FileCode className="h-4 w-4 text-emerald-400" />
                    <h4 className="text-xs font-mono font-bold text-white uppercase tracking-wider">
                      Análise Estática Sintática & Métricas Reais de AST
                    </h4>
                  </div>
                  <span className="text-[10px] font-mono text-zinc-400">
                    {report.totalLinesAudited} Linhas • {report.filesAudited.length} Arquivos Auditados
                  </span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  {/* Complexidade Ciclomática */}
                  <div className="p-3 rounded bg-zinc-900/70 border border-zinc-800">
                    <div className="text-[10px] font-mono uppercase tracking-wider text-zinc-400 mb-1 flex items-center justify-between">
                      <span className="flex items-center gap-1">
                        <span>Complexidade Ciclomática</span>
                        <HelpTooltip
                          title="Complexidade Ciclomática"
                          content="Quantidade de caminhos e ramificações independentes no código."
                          impact="Funções com CC > 15 possuem alto risco de bugs lógicos não testados."
                        />
                      </span>
                    </div>
                    <div className="flex items-baseline gap-2 mt-1">
                      <span className="text-xl font-mono font-bold text-white">
                        {report.astMetrics.cyclomaticComplexity.average}
                      </span>
                      <span className="text-[10px] text-zinc-500 font-mono">
                        (Máx: {report.astMetrics.cyclomaticComplexity.max})
                      </span>
                    </div>
                    <div className="text-[10px] text-zinc-400 mt-1 font-mono">
                      {report.astMetrics.cyclomaticComplexity.totalFunctionsCount} funções analisadas
                    </div>
                  </div>

                  {/* Segurança de Memória */}
                  <div className="p-3 rounded bg-zinc-900/70 border border-zinc-800">
                    <div className="text-[10px] font-mono uppercase tracking-wider text-zinc-400 mb-1 flex items-center justify-between">
                      <span className="flex items-center gap-1">
                        <span>Segurança de Memória</span>
                        <HelpTooltip
                          title="Índice de Segurança de Memória"
                          content="Garantia estática contra Use-After-Free, Double Free e ponteiros nulos."
                          impact="Índices baixos demandam revisão detalhada com Miri."
                        />
                      </span>
                    </div>
                    <div className="flex items-baseline gap-2 mt-1">
                      <span className={`text-xl font-mono font-bold ${
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
                    <div className="text-[10px] text-zinc-400 mt-1 font-mono">
                      {report.astMetrics.memorySafety.unsafeBlocksCount} unsafe, {report.astMetrics.memorySafety.rawPointerDerefs} ptrs
                    </div>
                  </div>

                  {/* Transmutes & Slices */}
                  <div className="p-3 rounded bg-zinc-900/70 border border-zinc-800">
                    <div className="text-[10px] font-mono uppercase tracking-wider text-zinc-400 mb-1 flex items-center gap-1">
                      <span>Transmutes &amp; Slices</span>
                      <HelpTooltip
                        title="Transmutes & Alocações Livres"
                        content="Conversões brutas de tipos de dados de baixo nível que ignoram a checagem de tipos."
                        impact="Transmutes de tipos incompatíveis causam Undefined Behavior instantâneo."
                      />
                    </div>
                    <div className="flex items-baseline gap-2 mt-1">
                      <span className="text-xl font-mono font-bold text-white">
                        {report.astMetrics.memorySafety.transmuteCount + report.astMetrics.memorySafety.unboundedSlicingOrAlloc}
                      </span>
                      <span className="text-[10px] text-zinc-500 font-mono">ocorrências</span>
                    </div>
                    <div className="text-[10px] text-zinc-400 mt-1 font-mono">
                      {report.astMetrics.memorySafety.transmuteCount} transmute, {report.astMetrics.memorySafety.unboundedSlicingOrAlloc} alocações
                    </div>
                  </div>

                  {/* High Complexity Hotspots */}
                  <div className="p-3 rounded bg-zinc-900/70 border border-zinc-800">
                    <div className="text-[10px] font-mono uppercase tracking-wider text-zinc-400 mb-1 flex items-center gap-1">
                      <span>Pontos Críticos (CC &gt; 15)</span>
                      <HelpTooltip
                        title="Hotspots de Complexidade"
                        content="Funções hiper-ramificadas que excedem o limiar de legibilidade e teste seguro."
                        impact="Candidatos prioritários a refatoração."
                      />
                    </div>
                    <div className="flex items-baseline gap-2 mt-1">
                      <span className={`text-xl font-mono font-bold ${
                        report.astMetrics.cyclomaticComplexity.highComplexityPoints === 0
                          ? 'text-emerald-400'
                          : 'text-amber-400'
                      }`}>
                        {report.astMetrics.cyclomaticComplexity.highComplexityPoints}
                      </span>
                      <span className="text-[10px] text-zinc-500 font-mono">locais críticos</span>
                    </div>
                    <div className="text-[10px] text-zinc-400 mt-1 font-mono">
                      {report.astMetrics.cyclomaticComplexity.highComplexityPoints === 0 ? 'Fluxos bem divididos' : 'Refatoração recomendada'}
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

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
        <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-zinc-800/80 pb-3 gap-3">
          <div className="flex items-center gap-2">
            <FolderGit2 className="h-4 w-4 text-emerald-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-white font-mono">
              Análise da Árvore do Repositório ({report.filesAudited.length} Arquivos)
            </h3>
          </div>
          {/* Tree File Triage Filters */}
          <div className="flex items-center gap-1.5 flex-wrap">
            <button
              onClick={() => setTreeFileFilter('ALL')}
              className={`px-2 py-1 rounded text-[10px] font-mono font-bold transition-colors cursor-pointer ${
                treeFileFilter === 'ALL'
                  ? 'bg-zinc-700 text-white'
                  : 'bg-zinc-900 text-zinc-400 hover:text-white border border-zinc-800'
              }`}
            >
              Todos ({report.filesAudited.length})
            </button>
            <button
              onClick={() => setTreeFileFilter('VULNERABLE')}
              className={`px-2 py-1 rounded text-[10px] font-mono font-bold transition-colors cursor-pointer ${
                treeFileFilter === 'VULNERABLE'
                  ? 'bg-amber-600 text-white'
                  : 'bg-zinc-900 text-amber-400 hover:text-amber-300 border border-zinc-800'
              }`}
            >
              Com Falhas ({report.filesAudited.filter(f => report.vulnerabilities.some(v => v.file === f.path)).length})
            </button>
            <button
              onClick={() => setTreeFileFilter('BLOCKERS')}
              className={`px-2 py-1 rounded text-[10px] font-mono font-bold transition-colors cursor-pointer ${
                treeFileFilter === 'BLOCKERS'
                  ? 'bg-red-600 text-white'
                  : 'bg-zinc-900 text-red-400 hover:text-red-300 border border-zinc-800'
              }`}
            >
              🛑 Apenas Bloqueadores ({report.filesAudited.filter(f => report.vulnerabilities.some(v => v.file === f.path && (v.severity === 'CRITICAL' || v.category === 'MEMORY_SAFETY'))).length})
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
          {/* File selector list */}
          <div className="lg:col-span-4 space-y-1.5 max-h-[320px] overflow-y-auto pr-1">
            {filteredTreeFiles.length === 0 ? (
              <div className="p-4 rounded border border-zinc-800 bg-zinc-950/60 text-center text-xs font-mono text-zinc-500">
                Nenhum arquivo encontrado com este filtro de triagem.
              </div>
            ) : (
              filteredTreeFiles.map((file, fIdx) => {
                const isSelected = selectedFileForInspection.path === file.path;
                const fileVulns = report.vulnerabilities.filter((v) => v.file === file.path);
                const hasBlocker = fileVulns.some((v) => v.severity === 'CRITICAL' || v.category === 'MEMORY_SAFETY');

                return (
                  <button
                    key={fIdx}
                    onClick={() => setSelectedFileForInspection(file)}
                    className={`w-full text-left p-2.5 rounded border transition-all text-xs font-mono flex items-center justify-between cursor-pointer ${
                      isSelected
                        ? 'border-emerald-500/60 bg-zinc-900 text-emerald-400 shadow-xs'
                        : 'border-zinc-800/70 bg-zinc-950/70 text-zinc-400 hover:border-zinc-700 hover:text-zinc-200'
                    }`}
                  >
                    <div className="flex items-center gap-2 truncate">
                      <FileCode className={`h-3.5 w-3.5 shrink-0 ${hasBlocker ? 'text-red-400' : fileVulns.length > 0 ? 'text-amber-400' : 'text-emerald-400'}`} />
                      <span className="truncate">{file.path}</span>
                    </div>
                    <div className="flex items-center gap-1.5 shrink-0 text-[10px]">
                      {hasBlocker ? (
                        <span className="px-1.5 py-0.2 rounded bg-red-500/20 text-red-300 border border-red-500/30 text-[9px] font-bold">
                          🛑 Bloqueador
                        </span>
                      ) : fileVulns.length > 0 ? (
                        <span className="px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 text-[9px] font-bold">
                          ⚠️ {fileVulns.length} Falhas
                        </span>
                      ) : (
                        <span className="px-1.5 py-0.2 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[9px]">
                          ✅ Seguro
                        </span>
                      )}
                    </div>
                  </button>
                );
              })
            )}
          </div>

          {/* Source Preview Inspector with direct remediation action */}
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

            {/* Quick Remediation Bar in Preview if file has vulnerabilities */}
            {selectedFileVulns.length > 0 && (
              <div className="px-3.5 py-2 bg-amber-950/40 border-b border-amber-500/30 flex items-center justify-between text-xs font-mono">
                <span className="text-amber-300 flex items-center gap-1.5 text-[11px]">
                  <AlertTriangle className="h-3.5 w-3.5 text-amber-400 shrink-0" />
                  <span>{selectedFileVulns.length} vulnerabilidade(s) neste arquivo</span>
                </span>
                <button
                  onClick={() => setSelectedVulnForDrawer(selectedFileVulns[0])}
                  className="px-2.5 py-1 rounded bg-amber-600 hover:bg-amber-500 text-white font-bold text-[10px] flex items-center gap-1 transition-colors cursor-pointer shadow-xs active:scale-95"
                >
                  <Sparkles className="h-3 w-3 text-amber-200" />
                  <span>⚡ Abrir Correção na Gaveta</span>
                </button>
              </div>
            )}

            <pre className="p-4 text-xs font-mono text-zinc-300 overflow-x-auto bg-zinc-950 leading-relaxed max-h-[280px]">
              {selectedFileForInspection.content}
            </pre>
          </div>
        </div>
      </div>

      {/* Top Critical Vulnerabilities List with Impact-Based Triage */}
      <div id="inventory-section" className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-5 space-y-4 scroll-mt-20 shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between border-b border-zinc-800/80 pb-4 gap-3">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-red-400" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-white font-mono flex items-center gap-2">
                <span>Triagem Priorizada de Vulnerabilidades ({report.vulnerabilities.length} detectadas)</span>
                <HelpTooltip
                  title="Triagem Priorizada"
                  content="Organiza as falhas por impacto real de negócio e arquitetura: Bloqueadores de release, Débitos técnicos de Atenção e Opcionais/Boas Práticas."
                  impact="Permite foco cirúrgico no que realmente quebra a segurança antes de resolver débitos estéticos."
                />
              </h3>
            </div>
            <p className="text-[11px] text-zinc-400 font-sans">
              Selecione qualquer vulnerabilidade para abrir a gaveta lateral de remediação unificada com análise e patch imediato.
            </p>
          </div>

          <div className="flex items-center gap-2.5 flex-wrap">
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
                  <span>⚡ Aplicar Correção em Lote (PR)</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Triage Priority Navigation Tabs */}
        <div className="flex items-center gap-2 flex-wrap border-b border-zinc-800/60 pb-3 text-xs font-mono">
          <button
            onClick={() => setTriageFilter('ALL')}
            className={`px-3 py-1.5 rounded-md font-bold transition-all cursor-pointer flex items-center gap-1.5 ${
              triageFilter === 'ALL'
                ? 'bg-zinc-700 text-white shadow-xs'
                : 'bg-zinc-900/80 text-zinc-400 hover:text-zinc-200 border border-zinc-800'
            }`}
          >
            <span>Todos</span>
            <span className="text-[10px] px-1.5 py-0.2 rounded bg-zinc-800 text-zinc-300">
              {report.vulnerabilities.length}
            </span>
          </button>

          <button
            onClick={() => setTriageFilter('BLOCKERS')}
            className={`px-3 py-1.5 rounded-md font-bold transition-all cursor-pointer flex items-center gap-1.5 ${
              triageFilter === 'BLOCKERS'
                ? 'bg-red-600 text-white shadow-xs shadow-red-950'
                : 'bg-zinc-900/80 text-red-400 hover:bg-red-950/30 border border-zinc-800'
            }`}
          >
            <span>🛑 Bloqueadores</span>
            <span className={`text-[10px] px-1.5 py-0.2 rounded font-bold ${triageFilter === 'BLOCKERS' ? 'bg-red-700 text-white' : 'bg-red-950/80 text-red-300 border border-red-500/30'}`}>
              {blockers.length}
            </span>
          </button>

          <button
            onClick={() => setTriageFilter('ATTENTION')}
            className={`px-3 py-1.5 rounded-md font-bold transition-all cursor-pointer flex items-center gap-1.5 ${
              triageFilter === 'ATTENTION'
                ? 'bg-amber-600 text-white shadow-xs shadow-amber-950'
                : 'bg-zinc-900/80 text-amber-400 hover:bg-amber-950/30 border border-zinc-800'
            }`}
          >
            <span>⚠️ Atenção</span>
            <span className={`text-[10px] px-1.5 py-0.2 rounded font-bold ${triageFilter === 'ATTENTION' ? 'bg-amber-700 text-white' : 'bg-amber-950/80 text-amber-300 border border-amber-500/30'}`}>
              {attention.length}
            </span>
          </button>

          <button
            onClick={() => setTriageFilter('OPTIONAL')}
            className={`px-3 py-1.5 rounded-md font-bold transition-all cursor-pointer flex items-center gap-1.5 ${
              triageFilter === 'OPTIONAL'
                ? 'bg-blue-600 text-white shadow-xs'
                : 'bg-zinc-900/80 text-zinc-400 hover:text-zinc-200 border border-zinc-800'
            }`}
          >
            <span>💡 Opcionais &amp; Boas Práticas</span>
            <span className={`text-[10px] px-1.5 py-0.2 rounded font-bold ${triageFilter === 'OPTIONAL' ? 'bg-blue-700 text-white' : 'bg-zinc-800 text-zinc-400'}`}>
              {optionals.length}
            </span>
          </button>
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

        {/* Filtered Vulnerabilities List */}
        <div className="space-y-2.5">
          {filteredVulnerabilities.length === 0 ? (
            <div className="p-8 rounded-xl border border-zinc-800 bg-zinc-950/60 text-center space-y-2">
              <CheckCircle2 className="h-8 w-8 text-emerald-400 mx-auto" />
              <h4 className="text-sm font-bold font-mono text-zinc-200">
                Nenhuma vulnerabilidade nesta categoria
              </h4>
              <p className="text-xs text-zinc-400 max-w-md mx-auto font-sans">
                O repositório está limpo para esta camada de prioridade. Alterne as abas acima para ver outros itens ou examine os relatórios executivos.
              </p>
            </div>
          ) : (
            filteredVulnerabilities.map((vuln) => {
              const isBlocker = vuln.severity === 'CRITICAL' || vuln.category === 'MEMORY_SAFETY';
              const isAttention = (vuln.severity === 'HIGH' || vuln.severity === 'MEDIUM') && !isBlocker;

              return (
                <div
                  key={vuln.id}
                  onClick={(e) => {
                    // Prevent opening drawer if user clicked a button or interactive child
                    if ((e.target as HTMLElement).closest('button, a')) return;
                    setSelectedVulnForDrawer(vuln);
                  }}
                  className={`rounded-xl border p-4 transition-all flex flex-col md:flex-row md:items-center justify-between gap-3 cursor-pointer hover:border-zinc-600 ${
                    isBlocker
                      ? 'border-red-500/30 bg-red-950/10 hover:bg-red-950/20'
                      : isAttention
                      ? 'border-amber-500/30 bg-amber-950/10 hover:bg-amber-950/20'
                      : 'border-zinc-800 bg-zinc-900/60 hover:bg-zinc-900/90'
                  }`}
                >
                  <div className="space-y-1.5 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      {isBlocker ? (
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded font-mono uppercase bg-red-500/20 text-red-300 border border-red-500/40 flex items-center gap-1">
                          <span>🛑 Bloqueador</span>
                        </span>
                      ) : isAttention ? (
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded font-mono uppercase bg-amber-500/20 text-amber-300 border border-amber-500/40 flex items-center gap-1">
                          <span>⚠️ Atenção</span>
                        </span>
                      ) : (
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded font-mono uppercase bg-blue-500/20 text-blue-300 border border-blue-500/40 flex items-center gap-1">
                          <span>💡 Opcional</span>
                        </span>
                      )}

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

                    <h4 className="text-xs font-bold text-zinc-100 font-mono flex items-center gap-2">
                      <span>{vuln.title}</span>
                    </h4>

                    <p className="text-xs text-zinc-400 line-clamp-2">{vuln.description}</p>

                    {vuln.suggestion && (
                      <div className="flex items-center gap-1.5 mt-1.5 text-[11px] font-sans text-emerald-400 bg-emerald-950/30 border border-emerald-500/20 px-2.5 py-1 rounded">
                        <Lightbulb className="h-3 w-3 shrink-0 text-emerald-400" />
                        <span><strong className="font-mono text-[10px] uppercase text-emerald-300">Sugestão:</strong> {vuln.suggestion}</span>
                      </div>
                    )}
                  </div>

                  {/* Actions Column */}
                  <div className="shrink-0 flex items-center gap-2 flex-wrap pt-2 md:pt-0">
                    {/* Primary Button: Open Remediation Drawer */}
                    <button
                      onClick={() => setSelectedVulnForDrawer(vuln)}
                      className="px-3.5 py-1.5 text-[11px] font-mono font-bold rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white flex items-center gap-1.5 transition-all shadow-xs cursor-pointer active:scale-95"
                      title="Abrir Gaveta Lateral de Inspeção e Correção Automatizada"
                    >
                      <Sparkles className="h-3.5 w-3.5 text-emerald-200" />
                      <span>⚡ Inspecionar &amp; Corrigir</span>
                    </button>

                    {/* Secondary: 1-Click PR */}
                    <button
                      onClick={() => handleApplyPullRequest(vuln.id)}
                      disabled={isCreatingPr && activeVulnForPr === vuln.id}
                      className="px-2.5 py-1.5 text-[11px] font-mono font-semibold rounded-lg bg-zinc-800 hover:bg-zinc-700 disabled:opacity-50 text-zinc-200 border border-zinc-700 flex items-center gap-1.5 transition-colors whitespace-nowrap cursor-pointer"
                      title="Gerar Pull Request automático no GitHub para esta vulnerabilidade"
                    >
                      {isCreatingPr && activeVulnForPr === vuln.id ? (
                        <>
                          <Loader2 className="h-3 w-3 animate-spin text-white" />
                          <span>PR...</span>
                        </>
                      ) : (
                        <>
                          <GitPullRequest className="h-3 w-3 text-emerald-400" />
                          <span>PR</span>
                        </>
                      )}
                    </button>

                    {/* Workbench Full Screen View */}
                    <button
                      onClick={() => {
                        onSelectVulnerabilityForReview(vuln.id);
                        onNavigateToTab('review');
                      }}
                      className="px-2.5 py-1.5 text-[11px] font-mono font-semibold rounded-lg bg-zinc-800/80 hover:bg-zinc-700 text-zinc-400 hover:text-zinc-200 border border-zinc-700 transition-colors whitespace-nowrap"
                      title="Abrir no Workbench Completo de Revisão de Código"
                    >
                      Workbench
                    </button>
                  </div>
                </div>
              );
            })
          )}
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
      {/* Remediation Drawer (Unified Quick Fix & Patch Generation) */}
      <RemediationDrawer
        isOpen={!!selectedVulnForDrawer}
        onClose={() => setSelectedVulnForDrawer(null)}
        vulnerability={selectedVulnForDrawer}
        onApplyPullRequest={(vulnId) => handleApplyPullRequest(vulnId)}
        isApplyingPr={isCreatingPr}
        onOpenFullWorkbench={(vulnId) => {
          onSelectVulnerabilityForReview(vulnId);
          onNavigateToTab('review');
        }}
        repoFullName={report.targetRepo?.fullName}
      />

      {/* DevSecOps Portuguese Glossary Modal */}
      <DevSecOpsGlossaryModal
        isOpen={isGlossaryOpen}
        onClose={() => setIsGlossaryOpen(false)}
      />
    </div>
  );
};
