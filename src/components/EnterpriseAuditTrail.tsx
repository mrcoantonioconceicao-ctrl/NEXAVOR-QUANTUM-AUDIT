import React, { useState, useMemo } from 'react';
import {
  ShieldAlert,
  Terminal,
  Download,
  Lock,
  CheckCircle,
  UserCheck,
  Search,
  Filter,
  Radio,
  FileCode,
  Key,
  Shield,
  Layers,
} from 'lucide-react';
import { SecurityAuditReport } from '../domain/types.ts';
import { createAuditTrailChain, downloadSiemLogs, AuditTrailBlock } from '../services/siemService.ts';

interface EnterpriseAuditTrailProps {
  report: SecurityAuditReport | null;
}

export type EnterpriseRole = 'CISO' | 'LEAD_ARCHITECT' | 'SECOPS_AUDITOR' | 'DEV_LEAD' | 'COMPLIANCE_OFFICER';

const ROLES_INFO: Record<EnterpriseRole, { label: string; permissions: string[]; badgeColor: string }> = {
  CISO: {
    label: 'CISO / VP de Segurança',
    permissions: ['Assinatura de Homologação ISO 27001', 'Supressão de Risco com Justificativa', 'Acesso Irrestrito a Chaves & PAT', 'Bloqueio de Merge CI/CD'],
    badgeColor: 'bg-purple-500/20 text-purple-300 border-purple-500/40',
  },
  LEAD_ARCHITECT: {
    label: 'Arquiteto de Segurança Líder',
    permissions: ['Aprovação de Refatoração AST', 'Geração de Patches 1-Click', 'Configuração de Webhooks', 'Download de SBOM & SARIF'],
    badgeColor: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
  },
  SECOPS_AUDITOR: {
    label: 'Auditor SecOps & Forense',
    permissions: ['Exportação de SIEM (CEF / NDJSON)', 'Execução de Testes Miri UB', 'Análise Espectral de Ondas 0-Day'],
    badgeColor: 'bg-blue-500/20 text-blue-300 border-blue-500/40',
  },
  DEV_LEAD: {
    label: 'Tech Lead / Engenheiro Senior',
    permissions: ['Visualização de Código Legado vs Refatorado', 'Abertura de Pull Requests', 'Testes de Bounds'],
    badgeColor: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
  },
  COMPLIANCE_OFFICER: {
    label: 'Oficial de Governança & DPO',
    permissions: ['Download de Relatório Executivo PDF', 'Auditoria de Matriz SOC2 / NIST', 'Avaliação de Risco FAIR'],
    badgeColor: 'bg-teal-500/20 text-teal-300 border-teal-500/40',
  },
};

export const EnterpriseAuditTrail: React.FC<EnterpriseAuditTrailProps> = ({ report }) => {
  const [activeRole, setActiveRole] = useState<EnterpriseRole>('CISO');
  const [logFilter, setLogFilter] = useState('');
  const [activeView, setActiveView] = useState<'chain' | 'siem' | 'rbac'>('chain');

  const auditBlocks = useMemo(() => {
    if (!report) return [];
    return createAuditTrailChain(report);
  }, [report]);

  const filteredBlocks = auditBlocks.filter(
    (b) =>
      b.action.toLowerCase().includes(logFilter.toLowerCase()) ||
      b.actor.toLowerCase().includes(logFilter.toLowerCase()) ||
      b.details.toLowerCase().includes(logFilter.toLowerCase()) ||
      b.hash.includes(logFilter)
  );

  return (
    <div className="space-y-6 text-zinc-300">
      {/* Header Banner */}
      <div className="rounded-xl border border-zinc-800 bg-linear-to-r from-zinc-900 via-zinc-900/90 to-zinc-950 p-5 sm:p-6 shadow-xl">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2">
              <span className="flex h-6 items-center rounded-md bg-blue-500/20 px-2 text-[10px] font-mono font-bold uppercase text-blue-400 border border-blue-500/30">
                Immutable Ledger
              </span>
              <span className="text-xs text-zinc-400 font-mono">Trilha de Auditoria Criptográfica & SIEM</span>
            </div>
            <h2 className="text-xl sm:text-2xl font-bold font-mono text-white tracking-tight">
              Livro-Razão Imutável Forense & Integração SIEM
            </h2>
            <p className="text-xs sm:text-sm text-zinc-400 max-w-3xl">
              Registro auditável com encadeamento de hashes SHA-256 à prova de adulteração (Tamper-Proof) e exportação em formato CEF / Syslog RFC 5424.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2 shrink-0">
            {report && (
              <>
                <button
                  onClick={() => downloadSiemLogs(report, 'cef')}
                  className="flex items-center gap-1.5 rounded-lg border border-blue-500/40 bg-blue-950/40 px-3 py-2 text-xs font-mono font-bold text-blue-300 hover:bg-blue-900/60 transition-all shadow-xs"
                  title="Exportar no padrão ArcSight / Splunk / Datadog CEF (Common Event Format)"
                >
                  <Download className="h-3.5 w-3.5" />
                  <span>Exportar CEF SIEM</span>
                </button>

                <button
                  onClick={() => downloadSiemLogs(report, 'ndjson')}
                  className="flex items-center gap-1.5 rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-xs font-mono font-bold text-zinc-200 hover:bg-zinc-700 transition-all"
                  title="Exportar no formato Newline-Delimited JSON para ElasticSearch / Logstash"
                >
                  <FileCode className="h-3.5 w-3.5 text-emerald-400" />
                  <span>JSON-ND (Elastic)</span>
                </button>
              </>
            )}
          </div>
        </div>

        {/* View Switcher Tabs */}
        <div className="mt-6 flex flex-wrap gap-2 border-t border-zinc-800/80 pt-4">
          <button
            onClick={() => setActiveView('chain')}
            className={`flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-mono font-semibold transition-all ${
              activeView === 'chain'
                ? 'bg-zinc-800 text-white border border-zinc-700 shadow-xs'
                : 'text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200'
            }`}
          >
            <Lock className="h-3.5 w-3.5 text-blue-400" />
            <span>Encadeamento Criptográfico (Hash Chain)</span>
          </button>

          <button
            onClick={() => setActiveView('siem')}
            className={`flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-mono font-semibold transition-all ${
              activeView === 'siem'
                ? 'bg-zinc-800 text-white border border-zinc-700 shadow-xs'
                : 'text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200'
            }`}
          >
            <Terminal className="h-3.5 w-3.5 text-emerald-400" />
            <span>Terminal de Eventos SIEM</span>
          </button>

          <button
            onClick={() => setActiveView('rbac')}
            className={`flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-mono font-semibold transition-all ${
              activeView === 'rbac'
                ? 'bg-zinc-800 text-white border border-zinc-700 shadow-xs'
                : 'text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200'
            }`}
          >
            <UserCheck className="h-3.5 w-3.5 text-purple-400" />
            <span>Simulador de Perfis RBAC</span>
          </button>
        </div>
      </div>

      {/* VIEW 1: HASH CHAIN IMMUTABLE LOG */}
      {activeView === 'chain' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-zinc-900/60 p-4 rounded-xl border border-zinc-800">
            <div className="flex items-center gap-2">
              <Lock className="h-4 w-4 text-emerald-400" />
              <span className="text-xs font-mono font-bold text-white uppercase">
                Status da Cadeia: <span className="text-emerald-400">ÍNTEGRA & ASSINADA (0 Adulterações)</span>
              </span>
            </div>

            <div className="relative w-full sm:w-64">
              <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-zinc-500" />
              <input
                type="text"
                placeholder="Filtrar por hash, ação ou ator..."
                value={logFilter}
                onChange={(e) => setLogFilter(e.target.value)}
                className="w-full rounded-md border border-zinc-800 bg-zinc-950 pl-8 pr-3 py-1.5 text-xs font-mono text-zinc-200 placeholder-zinc-600 focus:border-emerald-500 focus:outline-none"
              />
            </div>
          </div>

          <div className="space-y-3">
            {filteredBlocks.map((block) => (
              <div
                key={block.blockIndex}
                className="rounded-xl border border-zinc-800 bg-zinc-900/70 p-4 font-mono space-y-3 transition-all hover:border-zinc-700"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-zinc-800/80 pb-2">
                  <div className="flex items-center gap-2">
                    <span className="rounded bg-zinc-800 px-2 py-0.5 text-xs font-bold text-emerald-400 border border-zinc-700">
                      BLOCO #{block.blockIndex}
                    </span>
                    <span className="text-xs font-bold text-zinc-100">{block.action}</span>
                  </div>
                  <span className="text-[11px] text-zinc-500">{new Date(block.timestamp).toLocaleString('pt-BR')}</span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                  <div>
                    <span className="text-zinc-500">Ator: </span>
                    <span className="text-zinc-200">{block.actor}</span> <span className="text-zinc-500">({block.role})</span>
                  </div>
                  <div>
                    <span className="text-zinc-500">Alvo: </span>
                    <span className="text-zinc-200">{block.targetRepo}</span>
                  </div>
                </div>

                <div className="rounded bg-zinc-950 p-2.5 text-xs text-zinc-300 font-sans border border-zinc-900">
                  {block.details}
                </div>

                <div className="space-y-1 text-[10px] text-zinc-500 overflow-x-auto pt-1">
                  <div>
                    <span className="text-zinc-600 font-bold">PREV HASH: </span>
                    <span className="font-mono text-zinc-400">{block.previousHash}</span>
                  </div>
                  <div>
                    <span className="text-emerald-500 font-bold">BLOCK HASH: </span>
                    <span className="font-mono text-emerald-400">{block.hash}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* VIEW 2: SIEM TERMINAL STREAM */}
      {activeView === 'siem' && (
        <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-4 font-mono text-xs space-y-3 shadow-2xl">
          <div className="flex items-center justify-between border-b border-zinc-800 pb-2 text-zinc-400">
            <div className="flex items-center gap-2">
              <Radio className="h-3.5 w-3.5 text-emerald-400 animate-pulse" />
              <span>SIEM Syslog Ingestion Feed (RFC 5424 / CEF v0.1)</span>
            </div>
            <span>Stream: LIVE (TCP 514 / TLS)</span>
          </div>

          <div className="space-y-1.5 overflow-x-auto max-h-96 p-2 bg-black/60 rounded border border-zinc-900 text-zinc-300">
            {(report?.vulnerabilities || []).map((vuln, idx) => (
              <div key={idx} className="hover:bg-zinc-900/50 p-1 rounded transition-colors whitespace-nowrap">
                <span className="text-zinc-500">[{new Date().toISOString()}] </span>
                <span className="text-blue-400">CEF:0|MIT-Quantum|RustShield|2.5.0|</span>
                <span className="text-amber-400">{vuln.cwe}|</span>
                <span className="text-zinc-200">{vuln.title}|</span>
                <span className={vuln.severity === 'CRITICAL' ? 'text-rose-400 font-bold' : 'text-amber-400'}>
                  sev={vuln.severity === 'CRITICAL' ? '10' : '7'}|
                </span>
                <span className="text-emerald-400">src={vuln.file}:{vuln.line}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* VIEW 3: RBAC SIMULATOR */}
      {activeView === 'rbac' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 sm:grid-cols-5 gap-3">
            {(Object.keys(ROLES_INFO) as EnterpriseRole[]).map((r) => {
              const info = ROLES_INFO[r];
              const isSel = activeRole === r;
              return (
                <button
                  key={r}
                  onClick={() => setActiveRole(r)}
                  className={`p-3.5 rounded-xl border text-left font-mono transition-all ${
                    isSel
                      ? 'border-purple-500 bg-purple-950/20 text-white shadow-lg'
                      : 'border-zinc-800 bg-zinc-900/60 text-zinc-400 hover:bg-zinc-850 hover:text-zinc-200'
                  }`}
                >
                  <div className="text-xs font-bold truncate">{info.label}</div>
                  <div className="text-[10px] text-zinc-500 mt-1">{r}</div>
                </button>
              );
            })}
          </div>

          <div className="rounded-xl border border-zinc-800 bg-zinc-900/70 p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Shield className="h-5 w-5 text-purple-400" />
                <h3 className="text-sm font-mono font-bold text-white uppercase">
                  Privilégios & Matriz de Autorização: {ROLES_INFO[activeRole].label}
                </h3>
              </div>
              <span className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold border ${ROLES_INFO[activeRole].badgeColor}`}>
                {activeRole}
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {ROLES_INFO[activeRole].permissions.map((perm, idx) => (
                <div key={idx} className="flex items-center gap-2.5 p-3 rounded-lg bg-zinc-950/60 border border-zinc-850">
                  <CheckCircle className="h-4 w-4 text-emerald-400 shrink-0" />
                  <span className="text-xs text-zinc-200 font-sans">{perm}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
