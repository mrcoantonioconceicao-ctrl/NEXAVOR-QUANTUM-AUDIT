import React, { useState, useMemo } from 'react';
import {
  Package,
  AlertOctagon,
  AlertTriangle,
  CheckCircle,
  ExternalLink,
  Search,
  Copy,
  Check,
  Filter,
  Layers,
  ArrowUpRight,
  Clock,
  ShieldCheck,
  Sparkles,
  GitPullRequest,
  Loader2,
  Lock,
  ShieldAlert,
} from 'lucide-react';
import { SecurityAuditReport, VulnerabilitySeverity } from '../domain/types.ts';
import { createGitHubPullRequest, CreatePrResult } from '../services/githubService.ts';
import { getStoredGitHubToken, setStoredGitHubToken } from '../services/tokenStorage.ts';

interface DependencyVulnerabilitiesPanelProps {
  report: SecurityAuditReport;
  onNavigateToReview?: () => void;
}

export const DependencyVulnerabilitiesPanel: React.FC<DependencyVulnerabilitiesPanelProps> = ({
  report,
  onNavigateToReview,
}) => {
  const depAnalysis = report.dependencyAnalysis;
  const [severityFilter, setSeverityFilter] = useState<'ALL' | VulnerabilitySeverity>('ALL');
  const [ecosystemFilter, setEcosystemFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [showOutdatedTable, setShowOutdatedTable] = useState<boolean>(true);

  // 1-Click Pull Request Remediation State
  const [isCreatingPr, setIsCreatingPr] = useState<boolean>(false);
  const [prResult, setPrResult] = useState<CreatePrResult | null>(null);
  const [githubTokenInput, setGithubTokenInput] = useState<string>(() => getStoredGitHubToken());
  const [showTokenModal, setShowTokenModal] = useState<boolean>(false);

  const handleCopyCommand = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleTriggerAutoPr = async (tokenOverride?: string) => {
    if (!depAnalysis) return;

    setIsCreatingPr(true);
    setPrResult(null);

    const patches = [
      ...depAnalysis.vulnerabilities.map((v) => ({
        manifestPath: v.manifestPath,
        packageName: v.packageName,
        currentVersion: v.versionConstraint,
        targetVersion: v.fixedVersion,
        remediationCommand: v.remediation,
      })),
      ...depAnalysis.outdated.map((o) => ({
        manifestPath: o.manifestPath,
        packageName: o.packageName,
        currentVersion: o.currentVersion,
        targetVersion: o.latestVersion,
        remediationCommand: o.remediationCommand,
      })),
    ];

    // Deduplicate patches by manifestPath + packageName
    const uniquePatchesMap = new Map<string, (typeof patches)[0]>();
    patches.forEach((p) => {
      const key = `${p.manifestPath}::${p.packageName}`;
      if (!uniquePatchesMap.has(key)) {
        uniquePatchesMap.set(key, p);
      }
    });

    const uniquePatches = Array.from(uniquePatchesMap.values());

    const effectiveToken = (tokenOverride !== undefined ? tokenOverride : (githubTokenInput || getStoredGitHubToken())).trim();

    const targetUrl = report.targetRepo.url || 
      (report.targetRepo.fullName ? `https://github.com/${report.targetRepo.fullName}` : `https://github.com/${report.targetRepo.owner}/${report.targetRepo.name}`);

    const result = await createGitHubPullRequest({
      repoUrl: targetUrl,
      githubToken: effectiveToken,
      patches: uniquePatches,
    });

    setIsCreatingPr(false);
    setPrResult(result);

    if (result.requiresToken && !tokenOverride) {
      setShowTokenModal(true);
    }
  };

  const ecosystemsAvailable = useMemo(() => {
    if (!depAnalysis) return [];
    const ecoSet = new Set<string>();
    depAnalysis.vulnerabilities.forEach((v) => {
      if (v.ecosystem) ecoSet.add(v.ecosystem);
    });
    depAnalysis.outdated.forEach((o) => {
      if (o.ecosystem) ecoSet.add(o.ecosystem);
    });
    return Array.from(ecoSet);
  }, [depAnalysis]);

  const filteredVulnerabilities = useMemo(() => {
    if (!depAnalysis) return [];
    return depAnalysis.vulnerabilities.filter((v) => {
      const matchesSeverity = severityFilter === 'ALL' || v.severity === severityFilter;
      const matchesEcosystem = ecosystemFilter === 'ALL' || v.ecosystem.toLowerCase().includes(ecosystemFilter.toLowerCase());
      const q = searchQuery.toLowerCase().trim();
      const matchesSearch =
        !q ||
        v.packageName.toLowerCase().includes(q) ||
        v.advisoryId.toLowerCase().includes(q) ||
        (v.cve && v.cve.toLowerCase().includes(q)) ||
        v.title.toLowerCase().includes(q) ||
        v.manifestPath.toLowerCase().includes(q);

      return matchesSeverity && matchesEcosystem && matchesSearch;
    });
  }, [depAnalysis, severityFilter, ecosystemFilter, searchQuery]);

  const filteredOutdated = useMemo(() => {
    if (!depAnalysis) return [];
    return depAnalysis.outdated.filter((o) => {
      const matchesEcosystem = ecosystemFilter === 'ALL' || o.ecosystem.toLowerCase().includes(ecosystemFilter.toLowerCase());
      const q = searchQuery.toLowerCase().trim();
      const matchesSearch =
        !q ||
        o.packageName.toLowerCase().includes(q) ||
        o.manifestPath.toLowerCase().includes(q);

      return matchesEcosystem && matchesSearch;
    });
  }, [depAnalysis, ecosystemFilter, searchQuery]);

  if (!depAnalysis) {
    return null;
  }

  const criticalCount = depAnalysis.vulnerabilities.filter((v) => v.severity === 'CRITICAL').length;
  const highCount = depAnalysis.vulnerabilities.filter((v) => v.severity === 'HIGH').length;
  const mediumCount = depAnalysis.vulnerabilities.filter((v) => v.severity === 'MEDIUM' || v.severity === 'LOW').length;

  const maxCvss = depAnalysis.vulnerabilities.reduce((max, v) => Math.max(max, v.cvssScore || 0), 0);

  const getCvssBadge = (score: number, sev: VulnerabilitySeverity) => {
    if (score >= 9.0 || sev === 'CRITICAL') {
      return {
        bg: 'bg-red-500/20 border-red-500/50 text-red-300',
        bar: 'bg-red-500',
        label: 'CRÍTICO (CVSS 4.0)',
      };
    }
    if (score >= 7.0 || sev === 'HIGH') {
      return {
        bg: 'bg-amber-500/20 border-amber-500/50 text-amber-300',
        bar: 'bg-amber-500',
        label: 'ALTO RISCO',
      };
    }
    if (score >= 4.0 || sev === 'MEDIUM') {
      return {
        bg: 'bg-yellow-500/20 border-yellow-500/50 text-yellow-300',
        bar: 'bg-yellow-500',
        label: 'MÉDIO',
      };
    }
    return {
      bg: 'bg-blue-500/20 border-blue-500/50 text-blue-300',
      bar: 'bg-blue-500',
      label: 'BAIXO',
    };
  };

  const getEcosystemBadge = (ecosystem: string) => {
    const ecoLower = ecosystem.toLowerCase();
    if (ecoLower.includes('rust') || ecoLower.includes('cargo') || ecoLower.includes('crates')) {
      return 'bg-amber-950/60 text-amber-300 border-amber-500/40';
    }
    if (ecoLower.includes('node') || ecoLower.includes('npm') || ecoLower.includes('type')) {
      return 'bg-emerald-950/60 text-emerald-300 border-emerald-500/40';
    }
    if (ecoLower.includes('go')) {
      return 'bg-cyan-950/60 text-cyan-300 border-cyan-500/40';
    }
    if (ecoLower.includes('python') || ecoLower.includes('pypi')) {
      return 'bg-blue-950/60 text-blue-300 border-blue-500/40';
    }
    return 'bg-zinc-800 text-zinc-300 border-zinc-700';
  };

  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-5 space-y-5">
      {/* Header with Title and Summary Stats */}
      <div className="flex flex-col md:flex-row md:items-center justify-between border-b border-zinc-800/80 pb-4 gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
              <Package className="h-5 w-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold uppercase tracking-wider text-white font-mono flex items-center gap-2">
                <span>Vulnerabilidades de Dependências & Supply Chain (CVE / OSV)</span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800/80 font-normal">
                  OSV.dev & RustSec Live
                </span>
              </h3>
              <p className="text-xs text-zinc-400 font-sans">
                Auditoria contínua de manifestos com pontuação CVSS, severidade e referências diretas de remediação.
              </p>
            </div>
          </div>
        </div>

        {/* Quick KPI Badges */}
        <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
          <div className="px-3 py-1.5 rounded-md bg-zinc-950 border border-zinc-800 flex items-center gap-2">
            <span className="text-zinc-500 text-[10px] uppercase">Manifestos:</span>
            <span className="text-zinc-200 font-bold">{depAnalysis.manifestsScanned.length}</span>
          </div>

          <div className="px-3 py-1.5 rounded-md bg-zinc-950 border border-zinc-800 flex items-center gap-2">
            <span className="text-zinc-500 text-[10px] uppercase">Total Deps:</span>
            <span className="text-emerald-400 font-bold">{depAnalysis.totalDependenciesCount}</span>
          </div>

          <div
            className={`px-3 py-1.5 rounded-md border flex items-center gap-2 ${
              depAnalysis.vulnerableCount > 0
                ? 'bg-red-500/15 text-red-400 border-red-500/40 font-bold animate-pulse'
                : 'bg-emerald-500/15 text-emerald-400 border-emerald-500/40 font-bold'
            }`}
          >
            <AlertOctagon className="h-3.5 w-3.5" />
            <span>{depAnalysis.vulnerableCount} Vulnerabilidades Ativas</span>
          </div>

          {maxCvss > 0 && (
            <div className="px-3 py-1.5 rounded-md bg-rose-950/50 border border-rose-500/40 text-rose-300 font-bold flex items-center gap-1.5">
              <span className="text-[10px] text-rose-400 uppercase">Max CVSS:</span>
              <span>{maxCvss.toFixed(1)} / 10.0</span>
            </div>
          )}

          {/* 1-Click PR Remediation Button */}
          <button
            onClick={() => handleTriggerAutoPr()}
            disabled={isCreatingPr || (depAnalysis.vulnerableCount === 0 && depAnalysis.outdated.length === 0)}
            className="px-3.5 py-1.5 rounded-md bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-bold flex items-center gap-2 shadow-sm shadow-emerald-950 transition-all cursor-pointer"
          >
            {isCreatingPr ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin text-white" />
                <span>Gerando Branch & PR...</span>
              </>
            ) : (
              <>
                <GitPullRequest className="h-4 w-4 text-emerald-200" />
                <span>⚡ Aplicar Correção em 1-Clique (GitHub PR)</span>
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
            <div className="text-[10px] text-zinc-400 flex items-center gap-3">
              <span>
                Branch Criada: <strong className="text-zinc-200 font-mono">{prResult.branch}</strong>
              </span>
              <span>
                Manifestos Corrigidos: <strong className="text-emerald-400 font-mono">{prResult.patchedFiles?.join(', ') || 'Todos'}</strong>
              </span>
            </div>
          )}
        </div>
      )}

      {/* Manifests Scanned Pills */}
      <div className="flex flex-wrap items-center gap-2 text-xs font-mono bg-zinc-950/70 p-3 rounded border border-zinc-800/80">
        <span className="text-zinc-400 text-[11px] font-semibold flex items-center gap-1.5">
          <Layers className="h-3.5 w-3.5 text-zinc-500" />
          <span>Arquivos de Manifesto Inspecionados:</span>
        </span>
        {depAnalysis.manifestsScanned.map((manifest) => (
          <span
            key={manifest}
            className="px-2.5 py-1 rounded bg-zinc-900 border border-zinc-700/80 text-emerald-300 font-bold text-[11px] shadow-sm"
          >
            {manifest}
          </span>
        ))}
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-3 pt-1">
        {/* Search */}
        <div className="relative flex-1">
          <Search className="h-4 w-4 absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Buscar por pacote, CVE (ex: CVE-2024-3444, RUSTSEC), manifesto..."
            className="w-full pl-9 pr-3 py-1.5 rounded-md bg-zinc-950 border border-zinc-800 text-xs font-mono text-zinc-200 placeholder:text-zinc-600 focus:outline-none focus:border-emerald-500 transition-colors"
          />
        </div>

        {/* Severity Filters */}
        <div className="flex flex-wrap items-center gap-1.5 font-mono text-[11px]">
          <span className="text-zinc-500 mr-1 text-[10px] uppercase flex items-center gap-1">
            <Filter className="h-3 w-3" />
            <span>Severidade:</span>
          </span>
          <button
            onClick={() => setSeverityFilter('ALL')}
            className={`px-2.5 py-1 rounded border transition-all ${
              severityFilter === 'ALL'
                ? 'bg-zinc-800 text-white border-zinc-600 font-bold'
                : 'bg-zinc-950 text-zinc-400 border-zinc-800 hover:text-zinc-200'
            }`}
          >
            Todos ({depAnalysis.vulnerabilities.length})
          </button>
          {criticalCount > 0 && (
            <button
              onClick={() => setSeverityFilter('CRITICAL')}
              className={`px-2.5 py-1 rounded border transition-all ${
                severityFilter === 'CRITICAL'
                  ? 'bg-red-600 text-white border-red-500 font-bold shadow-sm shadow-red-950'
                  : 'bg-red-950/30 text-red-400 border-red-500/30 hover:bg-red-950/60'
              }`}
            >
              Crítico ({criticalCount})
            </button>
          )}
          {highCount > 0 && (
            <button
              onClick={() => setSeverityFilter('HIGH')}
              className={`px-2.5 py-1 rounded border transition-all ${
                severityFilter === 'HIGH'
                  ? 'bg-amber-600 text-white border-amber-500 font-bold shadow-sm shadow-amber-950'
                  : 'bg-amber-950/30 text-amber-400 border-amber-500/30 hover:bg-amber-950/60'
              }`}
            >
              Alto ({highCount})
            </button>
          )}
          {mediumCount > 0 && (
            <button
              onClick={() => setSeverityFilter('MEDIUM')}
              className={`px-2.5 py-1 rounded border transition-all ${
                severityFilter === 'MEDIUM'
                  ? 'bg-yellow-600 text-white border-yellow-500 font-bold'
                  : 'bg-yellow-950/30 text-yellow-400 border-yellow-500/30 hover:bg-yellow-950/60'
              }`}
            >
              Médio/Baixo ({mediumCount})
            </button>
          )}
        </div>

        {/* Ecosystem Filter Dropdown / Buttons */}
        {ecosystemsAvailable.length > 1 && (
          <div className="flex items-center gap-1.5 font-mono text-[11px]">
            <span className="text-zinc-500 text-[10px] uppercase">Ecosistema:</span>
            <select
              value={ecosystemFilter}
              onChange={(e) => setEcosystemFilter(e.target.value)}
              className="bg-zinc-950 border border-zinc-800 text-zinc-300 text-xs rounded px-2.5 py-1 focus:outline-none focus:border-emerald-500"
            >
              <option value="ALL">Todos os Ecosistemas</option>
              {ecosystemsAvailable.map((eco) => (
                <option key={eco} value={eco}>
                  {eco}
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {/* Main Categorized Vulnerabilities Table */}
      {filteredVulnerabilities.length > 0 ? (
        <div className="overflow-x-auto rounded-lg border border-zinc-800 bg-zinc-950 shadow-inner">
          <table className="w-full text-left font-mono text-xs">
            <thead>
              <tr className="border-b border-zinc-800 bg-zinc-900/80 text-[10px] uppercase tracking-wider text-zinc-400">
                <th className="py-3 px-3.5">Ecosistema & Manifesto</th>
                <th className="py-3 px-3.5">Pacote & Versão</th>
                <th className="py-3 px-3.5">Advisory / CVE</th>
                <th className="py-3 px-3.5">Risco (CVSS 4.0)</th>
                <th className="py-3 px-3.5">Descrição do Impacto</th>
                <th className="py-3 px-3.5">Versão Corrigida</th>
                <th className="py-3 px-3.5 text-right">Referências & Remediação</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800/60">
              {filteredVulnerabilities.map((vuln, idx) => {
                const cvssMeta = getCvssBadge(vuln.cvssScore, vuln.severity);
                const ecoBadgeClass = getEcosystemBadge(vuln.ecosystem);
                const isCopied = copiedId === `cmd-${idx}`;

                return (
                  <tr key={idx} className="hover:bg-zinc-900/50 transition-colors group">
                    {/* Ecosystem & Manifest */}
                    <td className="py-3 px-3.5 align-top">
                      <div className="flex flex-col gap-1">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold border inline-block w-fit ${ecoBadgeClass}`}
                        >
                          {vuln.ecosystem}
                        </span>
                        <span className="text-[11px] text-zinc-400 font-sans break-all">
                          {vuln.manifestPath}
                        </span>
                      </div>
                    </td>

                    {/* Package & Affected Version */}
                    <td className="py-3 px-3.5 align-top">
                      <div className="flex flex-col gap-0.5">
                        <span className="font-bold text-white text-sm tracking-tight">{vuln.packageName}</span>
                        <span className="text-[11px] text-red-400 font-mono">
                          Afetado: {vuln.versionConstraint}
                        </span>
                      </div>
                    </td>

                    {/* Advisory & CVE */}
                    <td className="py-3 px-3.5 align-top">
                      <div className="flex flex-col gap-1">
                        <span className="px-2 py-0.5 rounded bg-zinc-900 border border-zinc-700 text-zinc-200 text-[11px] font-bold w-fit">
                          {vuln.advisoryId}
                        </span>
                        {vuln.cve && vuln.cve !== vuln.advisoryId && (
                          <span className="text-[10px] text-zinc-400 font-mono font-semibold">
                            {vuln.cve}
                          </span>
                        )}
                      </div>
                    </td>

                    {/* Risk Level & CVSS Score */}
                    <td className="py-3 px-3.5 align-top">
                      <div className="flex flex-col gap-1.5 w-32">
                        <div className="flex items-center justify-between text-[11px] font-bold">
                          <span className={`px-1.5 py-0.5 rounded border text-[10px] ${cvssMeta.bg}`}>
                            {vuln.severity}
                          </span>
                          <span className="text-white font-mono">{vuln.cvssScore.toFixed(1)}/10</span>
                        </div>
                        <div className="w-full bg-zinc-800 rounded-full h-1.5 overflow-hidden">
                          <div
                            className={`h-full rounded-full ${cvssMeta.bar}`}
                            style={{ width: `${Math.min(100, (vuln.cvssScore / 10) * 100)}%` }}
                          />
                        </div>
                      </div>
                    </td>

                    {/* Description & Impact */}
                    <td className="py-3 px-3.5 align-top max-w-xs">
                      <div className="space-y-1">
                        <div className="text-zinc-200 font-sans text-xs font-semibold leading-snug">
                          {vuln.title}
                        </div>
                        <div className="text-zinc-400 font-sans text-[11px] leading-relaxed line-clamp-2">
                          {vuln.description}
                        </div>
                      </div>
                    </td>

                    {/* Fixed Version */}
                    <td className="py-3 px-3.5 align-top">
                      <div className="flex flex-col gap-1">
                        <span className="px-2 py-0.5 rounded bg-emerald-950/70 border border-emerald-500/40 text-emerald-300 font-bold text-xs w-fit">
                          {vuln.fixedVersion}
                        </span>
                        <span className="text-[10px] text-zinc-500">Versão Segura</span>
                      </div>
                    </td>

                    {/* Reference Links & Action */}
                    <td className="py-3 px-3.5 align-top text-right">
                      <div className="flex flex-col items-end gap-1.5">
                        {vuln.advisoryUrl && (
                          <a
                            href={vuln.advisoryUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-zinc-900 hover:bg-zinc-800 border border-zinc-700 text-emerald-400 hover:text-emerald-300 text-[11px] font-bold transition-colors shadow-sm"
                            title="Ver advisory oficial no OSV.dev / GitHub Advisory"
                          >
                            <span>Advisory Oficial</span>
                            <ExternalLink className="h-3 w-3" />
                          </a>
                        )}

                        <button
                          onClick={() => handleCopyCommand(vuln.remediation, `cmd-${idx}`)}
                          className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-zinc-950 hover:bg-zinc-900 border border-zinc-800 text-zinc-400 hover:text-zinc-200 text-[10px] transition-colors"
                          title="Copiar comando de remediação"
                        >
                          {isCopied ? (
                            <>
                              <Check className="h-3 w-3 text-emerald-400" />
                              <span className="text-emerald-400 font-bold">Copiado!</span>
                            </>
                          ) : (
                            <>
                              <Copy className="h-3 w-3" />
                              <span>Copiar Fix</span>
                            </>
                          )}
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-950/20 p-6 text-center space-y-2">
          <div className="inline-flex p-3 rounded-full bg-emerald-500/20 text-emerald-400 mb-1">
            <ShieldCheck className="h-8 w-8" />
          </div>
          <h4 className="text-sm font-bold text-white font-mono">
            {searchQuery || severityFilter !== 'ALL' || ecosystemFilter !== 'ALL'
              ? 'Nenhuma vulnerabilidade encontrada com os filtros selecionados.'
              : 'Nenhuma CVE crítica ou vulnerabilidade conhecida encontrada nas dependências!'}
          </h4>
          <p className="text-xs text-zinc-400 max-w-md mx-auto font-sans">
            Todos os pacotes declarados nos manifestos ({depAnalysis.manifestsScanned.join(', ')}) estão em conformidade com as bases de segurança do OSV.dev e RustSec.
          </p>
        </div>
      )}

      {/* Outdated Dependencies Collapsible Section */}
      {depAnalysis.outdated.length > 0 && (
        <div className="rounded-lg border border-zinc-800 bg-zinc-950/80 p-4 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Clock className="h-4 w-4 text-amber-400" />
              <h4 className="text-xs font-bold uppercase tracking-wider text-amber-300 font-mono">
                Dependências Desatualizadas & Defasagem de Ciclo de Vida ({filteredOutdated.length})
              </h4>
            </div>
            <button
              onClick={() => setShowOutdatedTable(!showOutdatedTable)}
              className="text-[11px] font-mono text-zinc-400 hover:text-white underline"
            >
              {showOutdatedTable ? 'Ocultar Tabela' : 'Expandir Tabela'}
            </button>
          </div>

          {showOutdatedTable && (
            <div className="overflow-x-auto rounded border border-zinc-800/80 bg-zinc-900/40">
              <table className="w-full text-left font-mono text-xs">
                <thead>
                  <tr className="border-b border-zinc-800 text-[10px] uppercase text-zinc-500 bg-zinc-900/80">
                    <th className="py-2.5 px-3">Ecosistema & Arquivo</th>
                    <th className="py-2.5 px-3">Pacote</th>
                    <th className="py-2.5 px-3">Versão Atual</th>
                    <th className="py-2.5 px-3">Versão Recomendada</th>
                    <th className="py-2.5 px-3">Status</th>
                    <th className="py-2.5 px-3 text-right">Comando de Atualização</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/50">
                  {filteredOutdated.map((item, idx) => (
                    <tr key={idx} className="hover:bg-zinc-800/40 transition-colors">
                      <td className="py-2.5 px-3 text-zinc-400 text-[11px]">
                        <span className="px-1.5 py-0.5 rounded bg-zinc-900 text-zinc-300 border border-zinc-800 text-[9px] mr-1.5">
                          {item.ecosystem}
                        </span>
                        {item.manifestPath}
                      </td>
                      <td className="py-2.5 px-3 font-bold text-zinc-200">{item.packageName}</td>
                      <td className="py-2.5 px-3 text-amber-400 font-bold">{item.currentVersion}</td>
                      <td className="py-2.5 px-3 text-emerald-400 font-bold">{item.latestVersion}</td>
                      <td className="py-2.5 px-3">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${
                            item.isMajorBehind
                              ? 'bg-red-500/15 text-red-300 border-red-500/30'
                              : 'bg-amber-500/15 text-amber-300 border-amber-500/30'
                          }`}
                        >
                          {item.isMajorBehind ? 'MAJOR OUTDATED' : item.status}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          <code className="text-[10px] text-zinc-300 bg-zinc-950 px-2 py-0.5 rounded border border-zinc-800 select-all">
                            {item.remediationCommand}
                          </code>
                          <button
                            onClick={() => handleCopyCommand(item.remediationCommand, `out-${idx}`)}
                            className="p-1 rounded bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 text-zinc-400 hover:text-zinc-200"
                            title="Copiar comando"
                          >
                            {copiedId === `out-${idx}` ? (
                              <Check className="h-3 w-3 text-emerald-400" />
                            ) : (
                              <Copy className="h-3 w-3" />
                            )}
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

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
                className="text-zinc-500 hover:text-white text-base font-bold"
              >
                ✕
              </button>
            </div>

            <p className="text-zinc-300 font-sans leading-relaxed">
              Para abrir um Pull Request diretamente no repositório <strong className="text-white">{report.targetRepo.fullName}</strong>, forneça um Personal Access Token (PAT) com a permissão <code className="text-emerald-400 bg-zinc-950 px-1 py-0.5 rounded">repo</code>.
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
                  handleTriggerAutoPr('SIMULATED');
                }}
                className="px-3.5 py-1.5 rounded border border-zinc-700 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 font-bold"
              >
                Continuar sem Token (Simular PR)
              </button>
              <button
                onClick={() => {
                  setShowTokenModal(false);
                  const clean = githubTokenInput.trim();
                  if (clean) setStoredGitHubToken(clean);
                  handleTriggerAutoPr(clean);
                }}
                disabled={!githubTokenInput.trim()}
                className="px-4 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-bold flex items-center gap-2"
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
