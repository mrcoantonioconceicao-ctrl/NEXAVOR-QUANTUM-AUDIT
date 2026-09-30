import React from 'react';
import {
  LayoutDashboard,
  Code2,
  Wand2,
  Key,
  ShieldCheck,
  ChevronLeft,
  ChevronRight,
  Play,
  FileDown,
  Globe,
  Radio,
  X,
  Workflow,
  Lock,
  Flame,
  GitCompare,
  Activity,
  Layers,
  Webhook,
  Terminal,
} from 'lucide-react';
import { TabType } from './Sidebar.tsx';
import { SecurityAuditReport } from '../domain/types.ts';

interface NavigationSidebarProps {
  activeTab: TabType;
  onTabChange: (tab: TabType) => void;
  isCollapsed: boolean;
  onToggleCollapse: () => void;
  isMobileOpen: boolean;
  onCloseMobile: () => void;
  onNewAudit: () => void;
  onExportPdf: () => void;
  onExportSarif: () => void;
  unresolvedFuzzAlertCount?: number;
  isAuditing: boolean;
  report: SecurityAuditReport | null;
}

export const NavigationSidebar: React.FC<NavigationSidebarProps> = ({
  activeTab,
  onTabChange,
  isCollapsed,
  onToggleCollapse,
  isMobileOpen,
  onCloseMobile,
  onNewAudit,
  onExportPdf,
  onExportSarif,
  unresolvedFuzzAlertCount = 0,
  isAuditing,
  report,
}) => {
  const vulnTotal = report?.vulnerabilities?.length || 0;
  const criticalCount = report?.vulnerabilities?.filter((v) => v.severity === 'CRITICAL').length || 0;
  const targetRepo = report?.targetRepo;
  const primaryLang = report?.primaryLanguage || targetRepo?.language || 'Solana / Rust';

  const mainNavItems: Array<{
    id: TabType;
    label: string;
    description: string;
    icon: React.ElementType;
    badge?: string;
    badgeColor?: string;
  }> = [
    {
      id: 'dashboard',
      label: 'Dashboard Executivo',
      description: 'Métricas & Scorecard CVSS',
      icon: LayoutDashboard,
      badge: vulnTotal > 0 ? `${vulnTotal}` : 'OK',
      badgeColor: criticalCount > 0 ? 'bg-rose-500/20 text-rose-400 border-rose-500/30' : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
    },
    {
      id: 'review',
      label: 'Auditoria AST & Solana',
      description: 'Invariantes Anchor, PDAs & Reentrância',
      icon: Code2,
      badge: 'Solana / Anchor',
      badgeColor: 'bg-purple-500/20 text-purple-300 border-purple-500/40',
    },
    {
      id: 'astRefactor',
      label: 'Estúdio de Refatoração',
      description: 'Hardening In-Place & Smart Contracts',
      icon: Wand2,
      badge: 'AST Core',
      badgeColor: 'bg-indigo-500/20 text-indigo-300 border-indigo-500/40',
    },
    {
      id: 'pqc',
      label: 'Criptografia Pós-Quântica & ZK',
      description: 'NIST PQC ML-KEM & ZK Circuits',
      icon: Key,
      badge: 'PQC / ZK',
      badgeColor: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
    },
    {
      id: 'compliance',
      label: 'Relatórios Executivos',
      description: 'SOC2, ISO 27001, LGPD & Badges SVG',
      icon: ShieldCheck,
      badge: 'C-Level',
      badgeColor: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    },
  ];

  const secondaryNavItems: Array<{
    id: TabType;
    label: string;
    icon: React.ElementType;
  }> = [
    { id: 'threatIntel', label: 'Threat Intel (Gemini 3.5)', icon: Globe },
    { id: 'fuzzing', label: `Cargo-Fuzz & ASan ${unresolvedFuzzAlertCount > 0 ? `(${unresolvedFuzzAlertCount})` : ''}`, icon: Flame },
    { id: 'cicd', label: 'Pipeline Studio Multi-Cloud', icon: Workflow },
    { id: 'auditTrail', label: 'Trilha Imutável SIEM', icon: Lock },
    { id: 'compare', label: 'Comparador de Regressões (Diff)', icon: GitCompare },
    { id: 'waves', label: 'Densidade de Risco & Espectro', icon: Activity },
    { id: 'architecture', label: 'Arquitetura & Bounded Contexts', icon: Layers },
    { id: 'tests', label: 'Suíte Miri & Sanitizers', icon: Terminal },
    { id: 'webhooks', label: 'Repositórios & Webhooks', icon: Webhook },
  ];

  const handleSelectTab = (tab: TabType) => {
    onTabChange(tab);
    onCloseMobile();
  };

  return (
    <>
      {/* Overlay para Dispositivos Móveis */}
      {isMobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/80 backdrop-blur-sm lg:hidden transition-opacity"
          onClick={onCloseMobile}
          aria-hidden="true"
        />
      )}

      {/* NavigationSidebar Fixa & Persistente */}
      <aside
        className={`fixed top-0 bottom-0 left-0 z-50 flex flex-col border-r border-zinc-800/90 bg-zinc-950 text-zinc-300 transition-all duration-300 ease-in-out ${
          isMobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        } ${isCollapsed ? 'w-20' : 'w-72 lg:w-68'}`}
      >
        {/* Cabeçalho de Branding */}
        <div className="flex h-16 items-center justify-between border-b border-zinc-800/80 px-4 shrink-0">
          <div className="flex items-center space-x-3 overflow-hidden">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-emerald-500 text-zinc-950 font-bold font-mono text-lg shadow-md shadow-emerald-950">
              🛡️
            </div>
            {!isCollapsed && (
              <div className="flex flex-col min-w-0">
                <span className="text-xs font-bold tracking-wider text-white uppercase font-mono truncate">
                  RustShield
                </span>
                <span className="text-[10px] text-emerald-400 font-mono tracking-tight truncate">
                  Quantum Engine v2.5
                </span>
              </div>
            )}
          </div>

          <button
            onClick={onCloseMobile}
            className="rounded-md p-1.5 text-zinc-400 hover:bg-zinc-800 hover:text-white lg:hidden"
            aria-label="Fechar navegação"
          >
            <X className="h-5 w-5" />
          </button>

          <button
            onClick={onToggleCollapse}
            className="hidden lg:flex h-7 w-7 items-center justify-center rounded border border-zinc-800 bg-zinc-900 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100 transition-colors"
            title={isCollapsed ? 'Expandir Menu' : 'Recolher Menu'}
          >
            {isCollapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
          </button>
        </div>

        {/* Status do Repositório Alvo */}
        {!isCollapsed && targetRepo && (
          <div className="mx-3 mt-3 rounded-md border border-zinc-800 bg-zinc-900/80 p-2.5 font-mono text-xs shrink-0">
            <div className="flex items-center justify-between text-[10px] text-zinc-400 uppercase tracking-wider mb-1">
              <span className="flex items-center gap-1.5 text-emerald-400 font-bold">
                <Radio className="h-3 w-3 animate-pulse" />
                Alvo Ativo
              </span>
              <span className="text-zinc-300">{primaryLang}</span>
            </div>
            <div className="truncate text-xs font-bold text-zinc-100" title={targetRepo.fullName || 'Repositório'}>
              {targetRepo.fullName || targetRepo.name}
            </div>
            <div className="mt-1 flex items-center justify-between text-[10px] text-zinc-400">
              <span>Score de Segurança:</span>
              <span className={`font-bold ${report?.overallSecurityScore && report.overallSecurityScore < 70 ? 'text-rose-400' : 'text-emerald-400'}`}>
                {report?.overallSecurityScore ?? 100}/100
              </span>
            </div>
          </div>
        )}

        {/* Módulos Principais */}
        <div className="flex-1 overflow-y-auto px-2 py-3 space-y-1">
          {!isCollapsed && (
            <div className="px-3 pb-1 text-[10px] font-mono font-bold uppercase tracking-widest text-emerald-400/90">
              Módulos Principais
            </div>
          )}

          {mainNavItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;

            return (
              <button
                key={item.id}
                onClick={() => handleSelectTab(item.id)}
                title={isCollapsed ? item.label : undefined}
                className={`group flex w-full items-center rounded-lg px-2.5 py-2.5 text-xs font-medium transition-all ${
                  isActive
                    ? 'bg-emerald-500/15 text-white font-semibold shadow-xs border border-emerald-500/40'
                    : 'text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200'
                } ${isCollapsed ? 'justify-center' : 'justify-between'}`}
              >
                <div className="flex items-center space-x-3 min-w-0">
                  <div
                    className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-md transition-colors ${
                      isActive ? 'bg-emerald-500 text-zinc-950 font-bold' : 'text-zinc-400 group-hover:text-white'
                    }`}
                  >
                    <Icon className="h-4 w-4" />
                  </div>

                  {!isCollapsed && (
                    <div className="flex flex-col text-left truncate min-w-0">
                      <span className="truncate text-xs font-mono font-bold">{item.label}</span>
                      <span className="text-[10px] text-zinc-400 truncate leading-tight font-sans">
                        {item.description}
                      </span>
                    </div>
                  )}
                </div>

                {!isCollapsed && item.badge && (
                  <span
                    className={`ml-1.5 shrink-0 rounded border px-1.5 py-0.5 text-[9px] font-mono font-bold ${
                      item.badgeColor || 'bg-zinc-800 text-zinc-300 border-zinc-700'
                    }`}
                  >
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}

          {/* Seção Secundária */}
          {!isCollapsed && (
            <div className="pt-4 px-3 pb-1 text-[10px] font-mono font-bold uppercase tracking-widest text-zinc-500">
              Módulos Complementares
            </div>
          )}

          {secondaryNavItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;

            return (
              <button
                key={item.id}
                onClick={() => handleSelectTab(item.id)}
                title={isCollapsed ? item.label : undefined}
                className={`group flex w-full items-center rounded-md px-2.5 py-1.5 text-xs font-mono transition-all ${
                  isActive
                    ? 'bg-zinc-800 text-emerald-400 font-bold border border-zinc-700'
                    : 'text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200'
                } ${isCollapsed ? 'justify-center' : 'justify-start space-x-2.5'}`}
              >
                <Icon className="h-3.5 w-3.5 shrink-0" />
                {!isCollapsed && <span className="truncate">{item.label}</span>}
              </button>
            );
          })}
        </div>

        {/* Rodapé de Ações Frequentes */}
        <div className="border-t border-zinc-800 p-2.5 space-y-1.5 bg-zinc-950 shrink-0">
          <button
            onClick={() => {
              onNewAudit();
              onCloseMobile();
            }}
            disabled={isAuditing}
            className={`flex w-full items-center gap-2 rounded-md border border-emerald-500/40 bg-emerald-950/40 px-3 py-2 text-xs font-mono font-bold uppercase tracking-wider text-emerald-300 hover:bg-emerald-900/60 transition-colors disabled:opacity-50 ${
              isCollapsed ? 'justify-center px-0' : 'justify-start'
            }`}
            title="Nova Auditoria"
          >
            <Play className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
            {!isCollapsed && <span className="truncate">Nova Auditoria</span>}
          </button>

          {report && (
            <div className={`flex gap-1.5 ${isCollapsed ? 'flex-col' : 'flex-row'}`}>
              <button
                onClick={() => {
                  onExportSarif();
                  onCloseMobile();
                }}
                className="flex flex-1 items-center justify-center gap-1 rounded border border-zinc-800 bg-zinc-900 px-2 py-1.5 text-[10px] font-mono text-zinc-300 hover:bg-zinc-800 hover:text-white"
                title="Exportar SARIF"
              >
                {!isCollapsed && <span>SARIF</span>}
              </button>

              <button
                onClick={() => {
                  onExportPdf();
                  onCloseMobile();
                }}
                className="flex flex-1 items-center justify-center gap-1 rounded bg-emerald-500 px-2 py-1.5 text-[10px] font-mono font-bold text-zinc-950 hover:bg-emerald-400"
                title="Exportar PDF"
              >
                <FileDown className="h-3 w-3 shrink-0" />
                {!isCollapsed && <span>PDF</span>}
              </button>
            </div>
          )}
        </div>
      </aside>
    </>
  );
};
