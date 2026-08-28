import React from 'react';
import {
  LayoutDashboard,
  GitCompare,
  Server,
  Activity,
  GitBranch,
  FileCode2,
  Terminal,
  Layers,
  ChevronLeft,
  ChevronRight,
  Play,
  FileDown,
  Code2,
  ShieldAlert,
  X,
  Radio,
  Webhook,
  Wand2,
  ShieldCheck,
  Cpu,
  Lock,
  Workflow,
} from 'lucide-react';
import { SecurityAuditReport } from '../domain/types.ts';

export type TabType =
  | 'dashboard'
  | 'compliance'
  | 'pqc'
  | 'cicd'
  | 'auditTrail'
  | 'compare'
  | 'scale10k'
  | 'waves'
  | 'bpmn'
  | 'review'
  | 'astRefactor'
  | 'tests'
  | 'architecture'
  | 'webhooks';


interface SidebarProps {
  activeTab: TabType;
  onTabChange: (tab: TabType) => void;
  isCollapsed: boolean;
  onToggleCollapse: () => void;
  isMobileOpen: boolean;
  onCloseMobile: () => void;
  onNewAudit: () => void;
  onExportPdf: () => void;
  onExportSarif: () => void;
  isAuditing: boolean;
  report: SecurityAuditReport | null;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onTabChange,
  isCollapsed,
  onToggleCollapse,
  isMobileOpen,
  onCloseMobile,
  onNewAudit,
  onExportPdf,
  onExportSarif,
  isAuditing,
  report,
}) => {
  const vulnTotal = report?.vulnerabilities?.length || 0;
  const criticalCount = report?.vulnerabilities?.filter((v) => v.severity === 'CRITICAL').length || 0;
  const targetRepo = report?.targetRepo;
  const primaryLang = report?.primaryLanguage || targetRepo?.language || 'Polyglot';
  const testCount = report?.securityTests?.length || 0;

  const navItems = [
    {
      id: 'dashboard' as TabType,
      label: 'Dashboard',
      description: 'Visão Geral & Métricas',
      icon: LayoutDashboard,
      badge: vulnTotal > 0 ? `${vulnTotal}` : undefined,
      badgeColor: criticalCount > 0 ? 'bg-rose-500/20 text-rose-400 border-rose-500/30' : 'bg-zinc-800 text-zinc-400',
    },
    {
      id: 'compliance' as TabType,
      label: 'Conformidade & GRC',
      description: 'SOC2, ISO, FAIR & SBOM',
      icon: ShieldCheck,
      badge: 'Enterprise',
      badgeColor: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
    },
    {
      id: 'pqc' as TabType,
      label: 'Post-Quantum (PQC)',
      description: 'FIPS 203/204 & Shor',
      icon: Cpu,
      badge: 'PQC',
      badgeColor: 'bg-indigo-500/20 text-indigo-400 border-indigo-500/30',
    },
    {
      id: 'cicd' as TabType,
      label: 'Multi-Cloud CI/CD',
      description: 'Pipeline Studio & Gate',
      icon: Workflow,
      badge: 'CI/CD',
      badgeColor: 'bg-teal-500/20 text-teal-400 border-teal-500/30',
    },
    {
      id: 'auditTrail' as TabType,
      label: 'Trilha SIEM & RBAC',
      description: 'Ledger Forense Imutável',
      icon: Lock,
      badge: 'SIEM',
      badgeColor: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    },
    {
      id: 'review' as TabType,
      label: 'Code Review',
      description: 'Remediação & Diff Rust',
      icon: FileCode2,
      badge: vulnTotal > 0 ? `${vulnTotal}` : undefined,
      badgeColor: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
    },
    {
      id: 'astRefactor' as TabType,
      label: 'Refatoração AST',
      description: 'Análise AST + Gemini IA',
      icon: Wand2,
      badge: 'AST + IA',
      badgeColor: 'bg-purple-500/20 text-purple-300 border-purple-500/40',
    },
    {
      id: 'compare' as TabType,
      label: 'Diff & Histórico',
      description: 'Comparador de Regressões',
      icon: GitCompare,
      badge: 'Diff',
      badgeColor: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    },
    {
      id: 'scale10k' as TabType,
      label: 'Cluster 10k',
      description: 'Arquitetura de Alta Escala',
      icon: Server,
      badge: '10k RPS',
      badgeColor: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
    },
    {
      id: 'waves' as TabType,
      label: 'Teoria das Ondas',
      description: 'Análise Espectral Soliton',
      icon: Activity,
      badge: 'Zero-Day',
      badgeColor: 'bg-indigo-500/20 text-indigo-400 border-indigo-500/30',
    },
    {
      id: 'bpmn' as TabType,
      label: 'BPMN Pipeline',
      description: 'Fluxo Formal de Auditoria',
      icon: GitBranch,
    },
    {
      id: 'tests' as TabType,
      label: 'Testes de Segurança',
      description: 'Suíte Miri & Sanitizers',
      icon: Terminal,
      badge: testCount > 0 ? `${testCount}` : undefined,
      badgeColor: 'bg-zinc-800 text-zinc-300',
    },
    {
      id: 'architecture' as TabType,
      label: 'Arquitetura & DDD',
      description: 'Modelagem de Domínio & SOA',
      icon: Layers,
    },
    {
      id: 'webhooks' as TabType,
      label: 'Webhooks & CI/CD',
      description: 'Gatilhos Automáticos GitHub',
      icon: Webhook,
      badge: 'Realtime',
      badgeColor: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
    },
  ];


  const handleSelectTab = (tab: TabType) => {
    onTabChange(tab);
    onCloseMobile();
  };

  return (
    <>
      {/* Mobile Backdrop Overlay */}
      {isMobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/70 backdrop-blur-sm lg:hidden transition-opacity"
          onClick={onCloseMobile}
          aria-hidden="true"
        />
      )}

      {/* Sidebar Container */}
      <aside
        className={`fixed top-0 bottom-0 left-0 z-50 flex flex-col border-r border-zinc-800 bg-zinc-950 text-zinc-300 transition-all duration-300 ease-in-out lg:static ${
          isMobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        } ${isCollapsed ? 'lg:w-18' : 'w-72 lg:w-64'}`}
      >
        {/* Sidebar Header / Brand */}
        <div className="flex h-15 items-center justify-between border-b border-zinc-800/80 px-4">
          <div className="flex items-center space-x-3 overflow-hidden">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-emerald-500 text-zinc-950 font-bold font-mono text-base shadow-sm">
              Ω
            </div>
            {!isCollapsed && (
              <div className="flex flex-col min-w-0 transition-opacity">
                <span className="text-xs font-bold tracking-wider text-white uppercase font-mono truncate">
                  Q-Audit
                </span>
                <span className="text-[10px] text-emerald-400 font-mono tracking-tight truncate">
                  Production Engine
                </span>
              </div>
            )}
          </div>

          {/* Close button for Mobile Drawer */}
          <button
            onClick={onCloseMobile}
            className="rounded-md p-1.5 text-zinc-400 hover:bg-zinc-800 hover:text-white lg:hidden"
            aria-label="Fechar menu lateral"
          >
            <X className="h-5 w-5" />
          </button>

          {/* Collapse/Expand Toggle on Desktop */}
          <button
            onClick={onToggleCollapse}
            className="hidden lg:flex h-7 w-7 items-center justify-center rounded border border-zinc-800 bg-zinc-900 text-zinc-400 hover:bg-zinc-800 hover:text-zinc-100 transition-colors"
            title={isCollapsed ? 'Expandir barra lateral' : 'Recolher barra lateral'}
          >
            {isCollapsed ? (
              <ChevronRight className="h-3.5 w-3.5" />
            ) : (
              <ChevronLeft className="h-3.5 w-3.5" />
            )}
          </button>
        </div>

        {/* Target Repository Status Pill (if loaded and not collapsed) */}
        {!isCollapsed && targetRepo && (
          <div className="mx-3 mt-3 rounded-md border border-zinc-800/90 bg-zinc-900/60 p-2.5 font-mono text-xs">
            <div className="flex items-center justify-between text-[10px] text-zinc-400 uppercase tracking-wider mb-1">
              <span className="flex items-center gap-1">
                <Radio className="h-2.5 w-2.5 text-emerald-400 animate-pulse" />
                Alvo Ativo
              </span>
              <span className="text-emerald-400 font-bold">{primaryLang}</span>
            </div>
            <div className="truncate text-xs font-bold text-zinc-200" title={targetRepo.fullName || 'Repositório'}>
              {targetRepo.fullName || targetRepo.name}
            </div>
            {criticalCount > 0 ? (
              <div className="mt-1.5 flex items-center gap-1.5 text-[10px] text-rose-400 font-medium">
                <ShieldAlert className="h-3 w-3 shrink-0" />
                <span>{criticalCount} vulnerabilidades críticas</span>
              </div>
            ) : (
              <div className="mt-1.5 text-[10px] text-emerald-400">
                Score Geral: {report?.overallSecurityScore ?? 100}/100
              </div>
            )}
          </div>
        )}

        {/* Navigation Items List */}
        <div className="flex-1 overflow-y-auto px-2 py-3 space-y-1">
          {!isCollapsed && (
            <div className="px-3 pb-1 text-[10px] font-mono font-bold uppercase tracking-widest text-zinc-400">
              Módulos de Análise
            </div>
          )}

          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;

            return (
              <button
                key={item.id}
                onClick={() => handleSelectTab(item.id)}
                title={isCollapsed ? item.label : undefined}
                className={`group flex w-full items-center rounded-lg px-2.5 py-2 text-xs font-medium transition-all ${
                  isActive
                    ? 'bg-zinc-800/90 text-white font-semibold shadow-xs border border-zinc-700/60'
                    : 'text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200'
                } ${isCollapsed ? 'justify-center' : 'justify-between'}`}
              >
                <div className="flex items-center space-x-2.5 min-w-0">
                  <div
                    className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-md transition-colors ${
                      isActive
                        ? 'bg-emerald-500/20 text-emerald-400'
                        : 'text-zinc-400 group-hover:text-zinc-200'
                    }`}
                  >
                    <Icon className="h-4 w-4" />
                  </div>

                  {!isCollapsed && (
                    <div className="flex flex-col text-left truncate min-w-0">
                      <span className="truncate text-xs font-mono">{item.label}</span>
                      <span className="text-[10px] text-zinc-400 truncate leading-tight font-sans">
                        {item.description}
                      </span>
                    </div>
                  )}
                </div>

                {!isCollapsed && item.badge && (
                  <span
                    className={`ml-2 shrink-0 rounded border px-1.5 py-0.5 text-[9px] font-mono font-bold ${
                      item.badgeColor || 'bg-zinc-800 text-zinc-300 border-zinc-700'
                    }`}
                  >
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Sidebar Footer Actions */}
        <div className="border-t border-zinc-800/80 p-2.5 space-y-1.5 bg-zinc-950">
          <button
            onClick={() => {
              onNewAudit();
              onCloseMobile();
            }}
            disabled={isAuditing}
            className={`flex w-full items-center gap-2 rounded-md border border-zinc-800 bg-zinc-900 px-3 py-2 text-xs font-mono font-bold uppercase tracking-wider text-zinc-200 hover:bg-zinc-800 hover:text-white transition-colors disabled:opacity-50 ${
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
                className={`flex flex-1 items-center justify-center gap-1.5 rounded-md border border-zinc-800 bg-zinc-900 px-2 py-1.5 text-[11px] font-mono text-zinc-300 hover:bg-zinc-850 hover:text-white transition-colors`}
                title="Exportar SARIF v2.1.0"
              >
                <Code2 className="h-3.5 w-3.5 text-blue-400 shrink-0" />
                {!isCollapsed && <span>SARIF</span>}
              </button>

              <button
                onClick={() => {
                  onExportPdf();
                  onCloseMobile();
                }}
                className={`flex flex-1 items-center justify-center gap-1.5 rounded-md bg-emerald-500 px-2 py-1.5 text-[11px] font-mono font-bold text-zinc-950 hover:bg-emerald-400 transition-colors shadow-xs`}
                title="Exportar PDF Executivo"
              >
                <FileDown className="h-3.5 w-3.5 shrink-0" />
                {!isCollapsed && <span>PDF</span>}
              </button>
            </div>
          )}

          {/* Engine Status indicator */}
          {!isCollapsed && (
            <div className="pt-2 flex items-center justify-between text-[9px] font-mono text-zinc-400 uppercase tracking-widest px-1">
              <span>MIT QUANTUM LABS</span>
              <span className="text-emerald-400">v1.85 PROD</span>
            </div>
          )}
        </div>
      </aside>
    </>
  );
};
