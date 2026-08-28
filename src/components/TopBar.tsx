import React from 'react';
import { Menu, Play, FileDown, Code2, Shield, Key } from 'lucide-react';
import { TabType } from './Sidebar.tsx';

interface TopBarProps {
  activeTab: TabType;
  onOpenMobileMenu: () => void;
  onNewAudit: () => void;
  onExportPdf: () => void;
  onExportSarif: () => void;
  onOpenTokenModal: () => void;
  hasToken: boolean;
  isAuditing: boolean;
  hasReport: boolean;
}

const TAB_TITLES: Record<TabType, { title: string; subtitle: string }> = {
  dashboard: { title: 'Dashboard Executivo', subtitle: 'Métricas e Postura de Segurança' },
  compliance: { title: 'Governança & Conformidade GRC', subtitle: 'SOC 2, ISO 27001, NIST SP 800-218, FAIR & SBOM' },
  pqc: { title: 'Hub Criptográfico Pós-Quântico', subtitle: 'NIST FIPS 203/204/205, Shor & Algoritmos de Reticulados' },
  cicd: { title: 'Pipeline Studio Multi-Cloud', subtitle: 'GitHub Actions, GitLab CI, Azure DevOps & Webhooks' },
  auditTrail: { title: 'Trilha Imutável SIEM & RBAC', subtitle: 'Livro-Razão Criptográfico e Log Stream CEF' },
  compare: { title: 'Comparador de Regressões (Diff)', subtitle: 'Detecção de Novas Vulnerabilidades vs Scan Anterior' },
  scale10k: { title: 'Cluster 10k RPS', subtitle: 'Arquitetura e Resiliência' },
  waves: { title: 'Teoria das Ondas', subtitle: 'Análise Espectral Soliton & Zero-Days' },
  bpmn: { title: 'BPMN Pipeline', subtitle: 'Fluxo Formal de Auditoria' },
  review: { title: 'Code Review Workbench', subtitle: 'Remediação e Diff Estático' },
  astRefactor: { title: 'Refatoração Legada (AST + IA)', subtitle: 'Ponte Determinística AST + Raciocínio Gemini IA' },
  tests: { title: 'Testes de Segurança', subtitle: 'Suíte Miri e Validação Dinâmica' },
  architecture: { title: 'Arquitetura & DDD', subtitle: 'Bounded Contexts e SOA' },
  webhooks: { title: 'Webhooks & CI/CD', subtitle: 'Gatilhos Automáticos e Auditoria em Tempo Real' },
};


export const TopBar: React.FC<TopBarProps> = ({
  activeTab,
  onOpenMobileMenu,
  onNewAudit,
  onExportPdf,
  onExportSarif,
  onOpenTokenModal,
  hasToken,
  isAuditing,
  hasReport,
}) => {
  const currentTabInfo = TAB_TITLES[activeTab] || { title: 'Auditoria', subtitle: 'Visão Geral' };

  return (
    <header className="sticky top-0 z-30 flex h-14 w-full items-center justify-between border-b border-zinc-800 bg-zinc-900/90 px-4 sm:px-6 backdrop-blur-md text-zinc-300">
      {/* Left: Mobile Drawer Trigger + Active View Breadcrumb */}
      <div className="flex items-center space-x-3 min-w-0">
        <button
          onClick={onOpenMobileMenu}
          className="flex h-9 w-9 items-center justify-center rounded-md border border-zinc-800 bg-zinc-950 text-zinc-300 hover:bg-zinc-800 hover:text-white lg:hidden"
          aria-label="Abrir menu lateral de navegação"
        >
          <Menu className="h-5 w-5" />
        </button>

        <div className="flex items-center space-x-2 min-w-0">
          <Shield className="h-4 w-4 text-emerald-400 shrink-0 hidden sm:inline" />
          <div className="flex flex-col min-w-0">
            <div className="flex items-center gap-2">
              <h1 className="text-xs sm:text-sm font-bold font-mono text-white uppercase tracking-wide truncate">
                {currentTabInfo.title}
              </h1>
            </div>
            <span className="text-[10px] text-zinc-400 font-sans hidden sm:block truncate">
              {currentTabInfo.subtitle}
            </span>
          </div>
        </div>
      </div>

      {/* Right: Quick Action Controls */}
      <div className="flex items-center space-x-2 shrink-0">
        {/* Token GitHub Button */}
        <button
          onClick={onOpenTokenModal}
          className={`flex items-center gap-1.5 rounded border px-2.5 sm:px-3 py-1.5 text-[11px] font-mono font-bold uppercase tracking-wider transition-all whitespace-nowrap shrink-0 ${
            hasToken
              ? 'border-emerald-500/50 bg-emerald-950/40 text-emerald-300 hover:bg-emerald-900/60'
              : 'border-amber-500/60 bg-amber-950/40 text-amber-300 hover:bg-amber-900/60 animate-pulse'
          }`}
          title="Configurar Personal Access Token (PAT) do GitHub para criar Pull Requests"
        >
          <Key className="h-3.5 w-3.5" />
          <span>{hasToken ? 'Token PAT Active' : '🔑 Colar Token PAT'}</span>
        </button>

        <button
          onClick={onNewAudit}
          disabled={isAuditing}
          className="flex items-center gap-1.5 rounded border border-zinc-700 bg-zinc-800/80 px-2.5 sm:px-3 py-1.5 text-[11px] font-mono font-bold uppercase tracking-wider text-zinc-200 hover:bg-zinc-700 hover:text-white transition-colors disabled:opacity-50 whitespace-nowrap shrink-0"
        >
          <Play className="h-3 w-3 text-emerald-400" />
          <span className="hidden sm:inline">Nova</span> Auditoria
        </button>

        {hasReport && (
          <>
            <button
              onClick={onExportSarif}
              className="hidden md:flex items-center gap-1.5 rounded border border-zinc-700 bg-zinc-850 px-2.5 sm:px-3 py-1.5 text-[11px] font-mono font-bold uppercase tracking-wider text-zinc-200 hover:bg-zinc-700 transition-colors whitespace-nowrap shrink-0"
              title="Exportar formato OASIS SARIF v2.1.0"
            >
              <Code2 className="h-3.5 w-3.5 text-blue-400" />
              <span>SARIF</span>
            </button>

            <button
              onClick={onExportPdf}
              className="flex items-center gap-1.5 rounded bg-emerald-500 px-3 py-1.5 text-[11px] font-mono font-bold uppercase tracking-wider text-zinc-950 hover:bg-emerald-400 transition-colors shadow-xs whitespace-nowrap shrink-0"
              title="Exportar Relatório PDF Executivo"
            >
              <FileDown className="h-3.5 w-3.5" />
              <span>PDF</span>
            </button>
          </>
        )}
      </div>
    </header>
  );
};

