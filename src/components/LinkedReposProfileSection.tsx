import React, { useState, useEffect } from 'react';
import {
  GitBranch,
  Link,
  Plus,
  RefreshCw,
  CheckCircle2,
  AlertCircle,
  Copy,
  Check,
  Play,
  Trash2,
  Shield,
  Zap,
  ExternalLink,
  Info,
  Clock,
  Code2,
  Key,
  Sliders,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { LinkedRepository, LinkedReposService } from '../services/linkedReposService.ts';

interface LinkedReposProfileSectionProps {
  currentRepoUrl?: string;
  onSelectRepoForAudit?: (repoUrl: string) => void;
  showNotification: (msg: string) => void;
}

export const LinkedReposProfileSection: React.FC<LinkedReposProfileSectionProps> = ({
  currentRepoUrl,
  onSelectRepoForAudit,
  showNotification,
}) => {
  const [linkedRepos, setLinkedRepos] = useState<LinkedRepository[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [isLinking, setIsSaving] = useState<boolean>(false);
  const [showSetupGuide, setShowSetupGuide] = useState<boolean>(false);

  // New Repo Form state
  const [inputUrl, setInputUrl] = useState<string>(currentRepoUrl || '');
  const [targetBranch, setTargetBranch] = useState<string>('main');
  const [autoReaudit, setAutoReaudit] = useState<boolean>(true);

  // Copied states
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Simulation running states
  const [simulatingId, setSimulatingId] = useState<string | null>(null);

  useEffect(() => {
    loadLinkedRepos();

    // Listen to real-time SSE stream for live updates when auto-reaudits trigger!
    let eventSource: EventSource | null = null;
    try {
      eventSource = new EventSource('/api/webhooks/stream');

      eventSource.addEventListener('linked_repo_added', () => {
        loadLinkedRepos();
      });

      eventSource.addEventListener('linked_repo_updated', () => {
        loadLinkedRepos();
      });

      eventSource.addEventListener('linked_repo_deleted', () => {
        loadLinkedRepos();
      });

      eventSource.addEventListener('linked_repo_reaudited', (e: any) => {
        try {
          const data = JSON.parse(e.data);
          if (data?.repo) {
            setLinkedRepos((prev) =>
              prev.map((r) => (r.id === data.repo.id ? data.repo : r))
            );
            showNotification(
              `🔄 Re-auditoria automática concluída para '${data.repo.repoFullName}' (Score: ${data.score}/100)`
            );
          }
        } catch {
          loadLinkedRepos();
        }
      });
    } catch (err) {
      console.warn('SSE stream listener fallback:', err);
    }

    return () => {
      if (eventSource) eventSource.close();
    };
  }, []);

  const loadLinkedRepos = async () => {
    setLoading(true);
    try {
      const data = await LinkedReposService.getLinkedRepos();
      setLinkedRepos(data);
    } catch (err) {
      console.error('Error loading linked repositories:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleLinkRepository = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputUrl.trim()) {
      showNotification('Por favor, informe a URL ou nome do repositório GitHub.');
      return;
    }

    setIsSaving(true);
    try {
      const newRepo = await LinkedReposService.linkRepository({
        repoUrl: inputUrl,
        targetBranch,
        autoReauditOnPush: autoReaudit,
      });

      showNotification(`Repositório '${newRepo.repoFullName}' vinculado ao perfil com sucesso!`);
      setInputUrl('');
      loadLinkedRepos();
    } catch (err: any) {
      showNotification(`Erro: ${err?.message || 'Falha ao vincular repositório.'}`);
    } finally {
      setIsSaving(false);
    }
  };

  const handleUnlink = async (id: string, repoName: string) => {
    if (!window.confirm(`Deseja desvincular o repositório '${repoName}' do seu perfil de auditoria?`)) {
      return;
    }

    try {
      await LinkedReposService.unlinkRepository(id);
      showNotification(`Repositório '${repoName}' desvinculado.`);
      setLinkedRepos((prev) => prev.filter((r) => r.id !== id));
    } catch (err: any) {
      showNotification(`Erro ao desvincular: ${err?.message}`);
    }
  };

  const handleToggleAutoAudit = async (repo: LinkedRepository) => {
    try {
      const updated = await LinkedReposService.updateLinkedRepo(repo.id, {
        autoReauditOnPush: !repo.autoReauditOnPush,
      });
      showNotification(
        `Re-auditoria automática na branch '${repo.targetBranch}' ${
          updated.autoReauditOnPush ? 'ativada' : 'pausada'
        }.`
      );
      setLinkedRepos((prev) => prev.map((r) => (r.id === repo.id ? updated : r)));
    } catch (err: any) {
      showNotification(`Erro ao atualizar: ${err?.message}`);
    }
  };

  const handleSimulatePush = async (repo: LinkedRepository) => {
    setSimulatingId(repo.id);
    try {
      showNotification(`Simulando git push origin ${repo.targetBranch} em '${repo.repoFullName}'...`);
      const result = await LinkedReposService.simulatePushToMain(
        repo.repoUrl,
        `feat(sec): auto re-audit push trigger on ${repo.targetBranch} branch`,
        'mrcoantonioconceicao-ctrl'
      );

      if (result.success) {
        showNotification(
          `⚡ Re-auditoria automática executada! Score calculado: ${result.delivery?.vulnSummary?.score || 100}/100`
        );
        loadLinkedRepos();
      }
    } catch (err: any) {
      showNotification(`Erro no teste: ${err?.message}`);
    } finally {
      setSimulatingId(null);
    }
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    showNotification('Copiado para a área de transferência!');
    setTimeout(() => setCopiedId(null), 2000);
  };

  const baseUrl = typeof window !== 'undefined' ? window.location.origin : 'https://qaudit.ai';

  return (
    <div className="space-y-6">
      {/* Hero Header */}
      <div className="relative overflow-hidden rounded-xl bg-gradient-to-r from-zinc-900 via-emerald-950/30 to-zinc-900 border border-emerald-500/20 p-6 shadow-2xl">
        <div className="absolute top-0 right-0 -mt-8 -mr-8 w-64 h-64 rounded-full bg-emerald-500/5 blur-3xl pointer-events-none" />
        
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 relative z-10">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2">
              <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                <Zap className="h-3 w-3 animate-pulse text-emerald-400" /> Auto-Re-Audit Pipeline
              </span>
              <span className="text-xs font-mono text-zinc-400">CI/CD Continuous Governance</span>
            </div>
            <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
              <Link className="h-5 w-5 text-emerald-400" />
              Repositórios GitHub Vinculados ao Perfil
            </h2>
            <p className="text-sm text-zinc-400 max-w-2xl leading-relaxed">
              Vincule seus repositórios GitHub ao seu perfil de auditoria. Qualquer envio de código (<code className="text-emerald-300 font-mono text-xs">git push</code>) para a branch principal (<code className="text-emerald-300 font-mono text-xs">main</code>) dispara automaticamente uma re-auditoria pericial em tempo real.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={loadLinkedRepos}
              className="inline-flex items-center gap-2 px-3 py-2 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs font-mono font-medium transition border border-zinc-700"
              title="Atualizar lista de repositórios"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin text-emerald-400' : ''}`} />
              Sincronizar
            </button>
            <button
              onClick={() => setShowSetupGuide(!showSetupGuide)}
              className="inline-flex items-center gap-2 px-3 py-2 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-300 text-xs font-mono font-medium transition border border-emerald-500/30"
            >
              <Info className="h-3.5 w-3.5" />
              Guia Webhook GitHub {showSetupGuide ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
            </button>
          </div>
        </div>

        {/* Expandable Setup Guide */}
        {showSetupGuide && (
          <div className="mt-6 pt-6 border-t border-zinc-800/80 grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono text-zinc-300">
            <div className="p-3.5 rounded-lg bg-zinc-950/70 border border-zinc-800 space-y-1">
              <div className="text-emerald-400 font-bold flex items-center gap-1.5">
                <span className="flex items-center justify-center h-4 w-4 rounded-full bg-emerald-500 text-zinc-950 font-sans text-[10px] font-bold">1</span>
                Vincule o Repositório
              </div>
              <p className="text-zinc-400 text-[11px]">
                Adicione a URL do repositório no formulário abaixo e defina a branch alvo (ex: <code className="text-emerald-300">main</code>).
              </p>
            </div>
            <div className="p-3.5 rounded-lg bg-zinc-950/70 border border-zinc-800 space-y-1">
              <div className="text-emerald-400 font-bold flex items-center gap-1.5">
                <span className="flex items-center justify-center h-4 w-4 rounded-full bg-emerald-500 text-zinc-950 font-sans text-[10px] font-bold">2</span>
                Configure o Webhook
              </div>
              <p className="text-zinc-400 text-[11px]">
                No GitHub (<code className="text-emerald-300">Settings -&gt; Webhooks</code>), cole o Payload URL e Secret fornecidos.
              </p>
            </div>
            <div className="p-3.5 rounded-lg bg-zinc-950/70 border border-zinc-800 space-y-1">
              <div className="text-emerald-400 font-bold flex items-center gap-1.5">
                <span className="flex items-center justify-center h-4 w-4 rounded-full bg-emerald-500 text-zinc-950 font-sans text-[10px] font-bold">3</span>
                Push para a Branch Main
              </div>
              <p className="text-zinc-400 text-[11px]">
                A cada novo commit enviado para a branch <code className="text-emerald-300">main</code>, o Q-Audit executa re-auditoria em tempo real.
              </p>
            </div>
          </div>
        )}
      </div>

      {/* Linking Form */}
      <div className="rounded-xl bg-zinc-900/90 border border-zinc-800 p-5 shadow-lg">
        <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider mb-3 flex items-center gap-2">
          <Plus className="h-4 w-4 text-emerald-400" />
          Vincular Novo Repositório ao Perfil
        </h3>

        <form onSubmit={handleLinkRepository} className="grid grid-cols-1 md:grid-cols-12 gap-3">
          <div className="md:col-span-6 relative">
            <input
              type="text"
              value={inputUrl}
              onChange={(e) => setInputUrl(e.target.value)}
              placeholder="Ex: mrcoantonioconceicao-ctrl/Atolada-anchor ou URL completa"
              className="w-full bg-zinc-950 border border-zinc-700/80 rounded-lg px-3.5 py-2.5 text-xs text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-emerald-500 font-mono transition"
            />
          </div>

          <div className="md:col-span-3 flex items-center gap-2">
            <span className="text-xs text-zinc-400 font-mono flex items-center gap-1">
              <GitBranch className="h-3.5 w-3.5 text-emerald-400" /> Branch:
            </span>
            <select
              value={targetBranch}
              onChange={(e) => setTargetBranch(e.target.value)}
              className="flex-1 bg-zinc-950 border border-zinc-700/80 rounded-lg px-2.5 py-2 text-xs text-emerald-400 font-mono focus:outline-none focus:border-emerald-500"
            >
              <option value="main">main (padrão)</option>
              <option value="master">master</option>
              <option value="develop">develop</option>
              <option value="dev">dev</option>
            </select>
          </div>

          <div className="md:col-span-3 flex items-center gap-2">
            <button
              type="submit"
              disabled={isLinking || !inputUrl.trim()}
              className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-zinc-950 font-bold text-xs font-mono transition shadow-lg shadow-emerald-500/10 cursor-pointer"
            >
              {isLinking ? (
                <>
                  <RefreshCw className="h-3.5 w-3.5 animate-spin" /> Vinculando...
                </>
              ) : (
                <>
                  <Link className="h-3.5 w-3.5" /> Vincular Repositório
                </>
              )}
            </button>
          </div>
        </form>
      </div>

      {/* Linked Repositories List */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-zinc-200 font-mono uppercase tracking-wider flex items-center gap-2">
            <Shield className="h-4 w-4 text-emerald-400" />
            Repositórios Ativos ({linkedRepos.length})
          </h3>
          <span className="text-xs font-mono text-zinc-400">
            {linkedRepos.filter((r) => r.autoReauditOnPush).length} com Re-Auditoria Automática Ativa na <code className="text-emerald-400">main</code>
          </span>
        </div>

        {linkedRepos.length === 0 ? (
          <div className="rounded-xl bg-zinc-900/50 border border-dashed border-zinc-800 p-8 text-center space-y-3">
            <Link className="h-8 w-8 text-zinc-600 mx-auto" />
            <div className="space-y-1">
              <h4 className="text-sm font-semibold text-zinc-300">Nenhum repositório vinculado ao perfil ainda</h4>
              <p className="text-xs text-zinc-500 max-w-md mx-auto">
                Insira a URL do seu projeto do GitHub acima para habilitar auditorias automáticas contínuas a cada push na branch principal.
              </p>
            </div>
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-4">
            {linkedRepos.map((repo) => {
              const fullPayloadUrl = `${baseUrl}${repo.webhookUrl}`;

              return (
                <div
                  key={repo.id}
                  className="rounded-xl bg-zinc-900/90 border border-zinc-800 hover:border-emerald-500/40 p-5 transition shadow-lg space-y-4"
                >
                  {/* Card Top Row */}
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-3 border-b border-zinc-800/80">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono text-sm font-bold text-white flex items-center gap-1.5">
                          <Code2 className="h-4 w-4 text-emerald-400" />
                          {repo.repoFullName}
                        </span>

                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                          <GitBranch className="h-3 w-3" /> branch: {repo.targetBranch}
                        </span>

                        {repo.autoReauditOnPush ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                            <Zap className="h-3 w-3 text-emerald-400 animate-pulse" /> Auto-Audit ON
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-amber-500/10 text-amber-300 border border-amber-500/20">
                            Pausado
                          </span>
                        )}
                      </div>

                      <a
                        href={repo.repoUrl}
                        target="_blank"
                        rel="noreferrer"
                        className="text-xs text-zinc-400 hover:text-emerald-400 font-mono inline-flex items-center gap-1 transition"
                      >
                        {repo.repoUrl} <ExternalLink className="h-3 w-3" />
                      </a>
                    </div>

                    {/* Stats Badges */}
                    <div className="flex items-center gap-3">
                      <div className="px-3 py-1.5 rounded-lg bg-zinc-950 border border-zinc-800 text-right">
                        <div className="text-[10px] text-zinc-500 font-mono uppercase">Última Nota</div>
                        <div className="text-xs font-mono font-bold text-emerald-400">
                          {repo.lastAuditScore !== undefined ? `${repo.lastAuditScore}/100` : 'Pendente'}
                        </div>
                      </div>

                      <div className="px-3 py-1.5 rounded-lg bg-zinc-950 border border-zinc-800 text-right">
                        <div className="text-[10px] text-zinc-500 font-mono uppercase">Re-Auditorias</div>
                        <div className="text-xs font-mono font-bold text-zinc-200">
                          {repo.totalReaudits} executadas
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Card Middle Row - Latest Commit & Webhook info */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                    <div className="p-3 rounded-lg bg-zinc-950/80 border border-zinc-800/80 space-y-1">
                      <span className="text-[10px] text-zinc-500 uppercase flex items-center gap-1">
                        <Clock className="h-3 w-3 text-emerald-400" /> Último Push Auditado na Main
                      </span>
                      <p className="text-zinc-200 font-medium truncate">
                        {repo.lastCommitMessage || 'Aguardando primeiro push...'}
                      </p>
                      <div className="flex items-center justify-between text-[11px] text-zinc-400 pt-0.5">
                        <span>SHA: <code className="text-emerald-400">{repo.lastCommitSha || 'main'}</code></span>
                        <span>por @{repo.lastCommitAuthor || 'sec-bot'}</span>
                      </div>
                    </div>

                    <div className="p-3 rounded-lg bg-zinc-950/80 border border-zinc-800/80 space-y-1">
                      <span className="text-[10px] text-zinc-500 uppercase flex items-center justify-between">
                        <span className="flex items-center gap-1"><Key className="h-3 w-3 text-emerald-400" /> Endpoint Webhook do GitHub</span>
                        <button
                          onClick={() => copyToClipboard(fullPayloadUrl, repo.id)}
                          className="text-emerald-400 hover:underline flex items-center gap-0.5 text-[10px]"
                        >
                          {copiedId === repo.id ? <Check className="h-2.5 w-2.5 text-emerald-400" /> : <Copy className="h-2.5 w-2.5" />}
                          {copiedId === repo.id ? 'Copiado!' : 'Copiar URL'}
                        </button>
                      </span>
                      <div className="bg-zinc-900 px-2 py-1 rounded text-[11px] text-zinc-300 truncate border border-zinc-800">
                        {fullPayloadUrl}
                      </div>
                      <div className="text-[10px] text-zinc-500 truncate">
                        Secret: <code className="text-zinc-400">{repo.secret}</code>
                      </div>
                    </div>
                  </div>

                  {/* Card Bottom Row - Actions */}
                  <div className="flex flex-wrap items-center justify-between gap-2 pt-2">
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => handleSimulatePush(repo)}
                        disabled={simulatingId === repo.id}
                        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 text-xs font-mono font-medium transition cursor-pointer"
                        title="Simular um push na branch main para testar o gatilho automático de re-auditoria"
                      >
                        <Play className={`h-3 w-3 ${simulatingId === repo.id ? 'animate-spin text-emerald-400' : 'text-emerald-400'}`} />
                        {simulatingId === repo.id ? 'Executando Re-Auditoria...' : 'Simular Push na Main'}
                      </button>

                      <button
                        onClick={() => handleToggleAutoAudit(repo)}
                        className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-mono transition border ${
                          repo.autoReauditOnPush
                            ? 'bg-zinc-800 hover:bg-zinc-700 text-zinc-300 border-zinc-700'
                            : 'bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border-emerald-500/40'
                        }`}
                      >
                        <Sliders className="h-3 w-3" />
                        {repo.autoReauditOnPush ? 'Pausar Re-Auditoria' : 'Ativar Re-Auditoria'}
                      </button>

                      {onSelectRepoForAudit && (
                        <button
                          onClick={() => onSelectRepoForAudit(repo.repoUrl)}
                          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs font-mono transition border border-zinc-700"
                        >
                          <Shield className="h-3 w-3 text-emerald-400" />
                          Auditar Agora na UI
                        </button>
                      )}
                    </div>

                    <button
                      onClick={() => handleUnlink(repo.id, repo.repoFullName)}
                      className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 text-xs font-mono transition cursor-pointer"
                      title="Desvincular repositório do perfil"
                    >
                      <Trash2 className="h-3 w-3" />
                      Desvincular
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};
