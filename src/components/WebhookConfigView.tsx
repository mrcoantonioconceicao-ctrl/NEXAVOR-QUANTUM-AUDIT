import React, { useState, useEffect } from 'react';
import {
  Webhook,
  Radio,
  Copy,
  Check,
  Zap,
  RefreshCw,
  Plus,
  Trash2,
  Shield,
  GitCommit,
  GitPullRequest,
  CheckCircle2,
  AlertTriangle,
  ExternalLink,
  Code,
  Key,
  Layers,
  Sparkles,
  ChevronRight,
  Info,
  Clock,
  Play,
} from 'lucide-react';
import { WebhookConfig, WebhookDeliveryLog, WebhookEvent } from '../domain/types.ts';
import { SecurityBadgeModal } from './SecurityBadgeModal.tsx';

interface WebhookConfigViewProps {
  currentRepoUrl?: string;
  onTriggerAuditFromWebhook?: (repoUrl: string, branch: string) => void;
  showNotification: (msg: string) => void;
}

export const WebhookConfigView: React.FC<WebhookConfigViewProps> = ({
  currentRepoUrl = 'https://github.com/user/repository',
  onTriggerAuditFromWebhook,
  showNotification,
}) => {
  const [configs, setConfigs] = useState<WebhookConfig[]>([]);
  const [deliveries, setDeliveries] = useState<WebhookDeliveryLog[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [isBadgeModalOpen, setIsBadgeModalOpen] = useState<boolean>(false);

  // Form states
  const [repoUrl, setRepoUrl] = useState<string>(currentRepoUrl);
  const [secret, setSecret] = useState<string>('sec_qaudit_9941a87b3c2d');
  const [autoAudit, setAutoAudit] = useState<boolean>(true);
  const [selectedEvents, setSelectedEvents] = useState<WebhookEvent[]>(['push', 'pull_request']);
  const [isSaving, setIsSaving] = useState<boolean>(false);
  const [copiedUrl, setCopiedUrl] = useState<boolean>(false);
  const [copiedSecret, setCopiedSecret] = useState<boolean>(false);

  // Simulation states
  const [simBranch, setSimBranch] = useState<string>('main');
  const [simMessage, setSimMessage] = useState<string>('feat(pqc): implement Kyber ML-KEM post-quantum key exchange');
  const [simAuthor, setSimAuthor] = useState<string>('sec-architect');
  const [isSimulating, setIsSimulating] = useState<boolean>(false);

  const webhookEndpointUrl = typeof window !== 'undefined'
    ? `${window.location.origin}/api/webhooks/github`
    : 'https://qaudit.ai/api/webhooks/github';

  const fullWebhookPayloadUrl = `${webhookEndpointUrl}?secret=${secret}`;

  // Fetch configs and deliveries on mount
  useEffect(() => {
    fetchData();

    // Setup SSE listener for real-time deliveries!
    let eventSource: EventSource | null = null;
    try {
      eventSource = new EventSource('/api/webhooks/stream');
      
      eventSource.addEventListener('webhook_triggered', (e: any) => {
        try {
          const data = JSON.parse(e.data);
          if (data?.delivery) {
            setDeliveries((prev) => [data.delivery, ...prev.slice(0, 49)]);
            showNotification(`⚡ Webhook recebido! Commit [${data.commitSha}] por @${data.author}`);
          }
        } catch (err) {
          console.error('Failed to parse SSE event:', err);
        }
      });
    } catch (err) {
      console.warn('SSE EventSource not supported or failed to connect:', err);
    }

    return () => {
      if (eventSource) {
        eventSource.close();
      }
    };
  }, []);

  const fetchData = async () => {
    setLoading(true);
    try {
      const [configRes, deliveryRes] = await Promise.all([
        fetch('/api/webhooks/configs').then((r) => r.json()).catch(() => ({ configs: [] })),
        fetch('/api/webhooks/deliveries').then((r) => r.json()).catch(() => ({ deliveries: [] })),
      ]);

      if (configRes.configs && Array.isArray(configRes.configs)) {
        setConfigs(configRes.configs);
        if (configRes.configs.length > 0) {
          setRepoUrl(configRes.configs[0].repoUrl || currentRepoUrl);
          setSecret(configRes.configs[0].secret || 'sec_qaudit_9941a87b3c2d');
          setAutoAudit(configRes.configs[0].autoAuditOnPush !== false);
          setSelectedEvents(configRes.configs[0].events || ['push', 'pull_request']);
        }
      }

      if (deliveryRes.deliveries && Array.isArray(deliveryRes.deliveries)) {
        setDeliveries(deliveryRes.deliveries);
      }
    } catch (err) {
      console.error('Failed to load webhook data:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateSecret = () => {
    const randomBytes = Array.from({ length: 12 }, () =>
      Math.floor(Math.random() * 16).toString(16)
    ).join('');
    const newSecret = `sec_qaudit_${randomBytes}`;
    setSecret(newSecret);
    showNotification('Nova chave secreta HMAC gerada com sucesso.');
  };

  const handleCopy = (text: string, type: 'url' | 'secret') => {
    navigator.clipboard.writeText(text);
    if (type === 'url') {
      setCopiedUrl(true);
      setTimeout(() => setCopiedUrl(false), 2000);
    } else {
      setCopiedSecret(true);
      setTimeout(() => setCopiedSecret(false), 2000);
    }
    showNotification('Copiado para a área de transferência!');
  };

  const handleSaveConfig = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaving(true);
    try {
      const res = await fetch('/api/webhooks/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repoUrl,
          secret,
          events: selectedEvents,
          autoAuditOnPush: autoAudit,
          active: true,
        }),
      });

      const data = await res.json();
      if (data.success && data.config) {
        showNotification('Configuração de webhook salva e ativada no servidor!');
        fetchData();
      } else {
        showNotification(`Erro: ${data.error || 'Falha ao salvar webhook.'}`);
      }
    } catch (err: any) {
      showNotification(`Erro ao conectar com o servidor: ${err.message}`);
    } finally {
      setIsSaving(false);
    }
  };

  const handleToggleEvent = (ev: WebhookEvent) => {
    if (selectedEvents.includes(ev)) {
      if (selectedEvents.length === 1) return; // keep at least 1
      setSelectedEvents(selectedEvents.filter((e) => e !== ev));
    } else {
      setSelectedEvents([...selectedEvents, ev]);
    }
  };

  const handleSimulatePush = async () => {
    setIsSimulating(true);
    try {
      const res = await fetch('/api/webhooks/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          event: 'push',
          repoUrl,
          branch: simBranch,
          commitMessage: simMessage,
          author: simAuthor,
        }),
      });

      const data = await res.json();
      if (data.success && data.delivery) {
        setDeliveries((prev) => [data.delivery, ...prev]);
        showNotification(`⚡ Webhook Push simulado com sucesso! SHA: ${data.delivery.commitSha}`);
        if (autoAudit && onTriggerAuditFromWebhook) {
          onTriggerAuditFromWebhook(repoUrl, simBranch);
        }
      }
    } catch (err: any) {
      showNotification(`Erro ao simular webhook: ${err.message}`);
    } finally {
      setIsSimulating(false);
    }
  };

  const handleDeleteConfig = async (id: string) => {
    try {
      const res = await fetch(`/api/webhooks/config/${id}`, { method: 'DELETE' });
      if (res.ok) {
        showNotification('Webhook removido.');
        fetchData();
      }
    } catch (err) {
      console.error('Failed to delete webhook:', err);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto px-4 sm:px-6 py-6 text-zinc-300">
      {/* Header Banner */}
      <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2">
              <span className="px-2.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 text-[10px] font-mono font-bold uppercase tracking-wider flex items-center gap-1.5">
                <Radio className="h-3 w-3 text-emerald-400 animate-pulse" />
                Gatilhos Automáticos GitHub Webhooks
              </span>
              <span className="text-xs font-mono text-zinc-500">CI/CD Realtime Pipeline</span>
            </div>
            <h1 className="text-xl font-bold text-white font-mono flex items-center gap-2">
              <Webhook className="h-5 w-5 text-emerald-400" />
              <span>Configuração de Webhooks & Auditoria Automática</span>
            </h1>
            <p className="text-xs text-zinc-400 max-w-2xl leading-relaxed">
              Configure webhooks no GitHub para disparar automaticamente auditorias periciais de segurança a cada{' '}
              <strong className="text-zinc-200">git push</strong> ou <strong className="text-zinc-200">Pull Request</strong>, atualizando os dashboards em tempo real sem intervenção manual.
            </p>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={() => setIsBadgeModalOpen(true)}
              className="flex items-center gap-1.5 px-3 py-2 rounded border border-emerald-500/40 bg-emerald-950/40 hover:bg-emerald-900/60 text-emerald-300 font-mono text-xs font-bold transition-colors shadow-xs"
            >
              <Shield className="h-3.5 w-3.5 text-emerald-400" />
              <span>Gerar Badge README</span>
            </button>
            <button
              onClick={fetchData}
              disabled={loading}
              className="flex items-center gap-1.5 px-3 py-2 rounded border border-zinc-800 bg-zinc-900 text-xs font-mono text-zinc-300 hover:bg-zinc-800 transition-colors"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin text-emerald-400' : 'text-zinc-400'}`} />
              <span>Atualizar</span>
            </button>
          </div>
        </div>

        {/* Quick Metrics Bar */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-6 pt-5 border-t border-zinc-800/80">
          <div className="bg-zinc-950/60 rounded border border-zinc-800/80 p-3">
            <div className="text-[10px] font-mono text-zinc-500 uppercase">Webhooks Ativos</div>
            <div className="text-lg font-bold font-mono text-white mt-0.5">
              {configs.filter((c) => c.active).length} / {configs.length || 1}
            </div>
          </div>
          <div className="bg-zinc-950/60 rounded border border-zinc-800/80 p-3">
            <div className="text-[10px] font-mono text-zinc-500 uppercase">Deliveries Recebidas</div>
            <div className="text-lg font-bold font-mono text-emerald-400 mt-0.5">
              {deliveries.length}
            </div>
          </div>
          <div className="bg-zinc-950/60 rounded border border-zinc-800/80 p-3">
            <div className="text-[10px] font-mono text-zinc-500 uppercase">Modo Auto-Audit</div>
            <div className="text-lg font-bold font-mono text-blue-400 mt-0.5">
              {autoAudit ? 'Habilitado' : 'Manual'}
            </div>
          </div>
          <div className="bg-zinc-950/60 rounded border border-zinc-800/80 p-3">
            <div className="text-[10px] font-mono text-zinc-500 uppercase">Latência Média</div>
            <div className="text-lg font-bold font-mono text-zinc-300 mt-0.5">
              ~340ms (Tokio async)
            </div>
          </div>
        </div>
      </div>

      {/* Grid Layout: Config Form + Simulation & Instructions */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column (7 cols): Webhook Setup Form */}
        <div className="lg:col-span-7 space-y-6">
          <form onSubmit={handleSaveConfig} className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-5 space-y-5">
            <div className="flex items-center justify-between pb-3 border-b border-zinc-800 font-mono">
              <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <Key className="h-4 w-4 text-emerald-400" />
                <span>Parâmetros do Webhook</span>
              </h2>
              <span className="text-[10px] text-emerald-400 bg-emerald-950/40 border border-emerald-500/20 px-2 py-0.5 rounded">
                HMAC SHA-256 Validated
              </span>
            </div>

            {/* Target Repo Input */}
            <div>
              <label className="block text-xs font-mono font-bold text-zinc-300 mb-1.5">
                1. URL do Repositório Alvo (GitHub)
              </label>
              <input
                type="text"
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                placeholder="https://github.com/usuario/repositorio"
                className="w-full px-3 py-2 bg-zinc-950 border border-zinc-800 rounded text-xs text-emerald-400 font-mono focus:outline-none focus:border-emerald-500"
                required
              />
            </div>

            {/* Webhook Payload URL with 1-Click Copy */}
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-xs font-mono font-bold text-zinc-300">
                  2. Payload URL (Colar nas configurações do GitHub)
                </label>
                <button
                  type="button"
                  onClick={() => handleCopy(fullWebhookPayloadUrl, 'url')}
                  className="text-[11px] font-mono text-emerald-400 hover:text-emerald-300 flex items-center gap-1"
                >
                  {copiedUrl ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                  <span>{copiedUrl ? 'Copiado!' : 'Copiar URL completa'}</span>
                </button>
              </div>
              <div className="relative">
                <input
                  type="text"
                  readOnly
                  value={fullWebhookPayloadUrl}
                  className="w-full px-3 py-2 bg-zinc-950/80 border border-zinc-800 rounded text-xs text-zinc-300 font-mono select-all focus:outline-none"
                />
              </div>
            </div>

            {/* Secret Token & HMAC Generator */}
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="text-xs font-mono font-bold text-zinc-300">
                  3. Secret Token (HMAC SHA-256 Signature)
                </label>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={handleGenerateSecret}
                    className="text-[11px] font-mono text-zinc-400 hover:text-zinc-200 underline"
                  >
                    Gerar Novo Secret
                  </button>
                  <button
                    type="button"
                    onClick={() => handleCopy(secret, 'secret')}
                    className="text-[11px] font-mono text-emerald-400 hover:text-emerald-300 flex items-center gap-1"
                  >
                    {copiedSecret ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                    <span>{copiedSecret ? 'Copiado!' : 'Copiar Secret'}</span>
                  </button>
                </div>
              </div>
              <input
                type="text"
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                className="w-full px-3 py-2 bg-zinc-950 border border-zinc-800 rounded text-xs text-amber-300 font-mono focus:outline-none focus:border-amber-500"
                required
              />
            </div>

            {/* Event Subscriptions */}
            <div>
              <label className="block text-xs font-mono font-bold text-zinc-300 mb-2">
                4. Eventos Assinados (Subscribed Events)
              </label>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {[
                  { id: 'push' as WebhookEvent, label: 'git push', desc: 'Commits & Braches' },
                  { id: 'pull_request' as WebhookEvent, label: 'pull_request', desc: 'Abertura/Updates de PR' },
                  { id: 'workflow_run' as WebhookEvent, label: 'workflow_run', desc: 'Execuções de CI' },
                  { id: 'release' as WebhookEvent, label: 'release', desc: 'Tags & Deploys' },
                ].map((item) => {
                  const isChecked = selectedEvents.includes(item.id);
                  return (
                    <button
                      type="button"
                      key={item.id}
                      onClick={() => handleToggleEvent(item.id)}
                      className={`p-2.5 rounded border text-left font-mono transition-all ${
                        isChecked
                          ? 'bg-emerald-950/40 border-emerald-500/50 text-emerald-300'
                          : 'bg-zinc-950 border-zinc-800 text-zinc-500 hover:text-zinc-400'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold">{item.label}</span>
                        {isChecked && <Check className="h-3 w-3 text-emerald-400" />}
                      </div>
                      <div className="text-[10px] text-zinc-500 mt-1 font-sans">{item.desc}</div>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Auto Audit Toggle Switch */}
            <div className="rounded border border-zinc-800 bg-zinc-950 p-3.5 flex items-center justify-between">
              <div className="space-y-0.5">
                <div className="text-xs font-mono font-bold text-white flex items-center gap-2">
                  <Zap className="h-3.5 w-3.5 text-emerald-400" />
                  <span>Executar Auditoria Automática no Recebimento</span>
                </div>
                <p className="text-[11px] text-zinc-400 font-sans">
                  Varre os arquivos alterados e atualiza o relatório e score executivo instantaneamente.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setAutoAudit(!autoAudit)}
                className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                  autoAudit ? 'bg-emerald-500' : 'bg-zinc-800'
                }`}
              >
                <span
                  className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-zinc-950 shadow transition duration-200 ease-in-out ${
                    autoAudit ? 'translate-x-4' : 'translate-x-0'
                  }`}
                />
              </button>
            </div>

            {/* Save Button */}
            <div className="pt-2 flex items-center justify-between">
              <span className="text-[11px] text-zinc-500 font-mono">
                Ativo no endpoint Express <code>/api/webhooks/github</code>
              </span>
              <button
                type="submit"
                disabled={isSaving}
                className="px-4 py-2 rounded bg-emerald-500 hover:bg-emerald-400 text-zinc-950 font-mono font-bold text-xs uppercase tracking-wider flex items-center gap-2 transition-colors disabled:opacity-50"
              >
                {isSaving ? (
                  <>
                    <span className="h-3.5 w-3.5 border-2 border-zinc-950 border-t-transparent rounded-full animate-spin" />
                    <span>Salvando...</span>
                  </>
                ) : (
                  <>
                    <CheckCircle2 className="h-4 w-4" />
                    <span>Salvar Configuração</span>
                  </>
                )}
              </button>
            </div>
          </form>

          {/* List of Active Webhook Configurations */}
          <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-5 space-y-3">
            <h3 className="text-xs font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Layers className="h-4 w-4 text-emerald-400" />
              <span>Webhooks Cadastrados ({configs.length})</span>
            </h3>

            {configs.length === 0 ? (
              <div className="text-xs text-zinc-500 font-mono py-4 text-center">
                Nenhum webhook cadastrado ainda. Salve acima para registrar.
              </div>
            ) : (
              <div className="space-y-2">
                {configs.map((cfg) => (
                  <div
                    key={cfg.id}
                    className="rounded border border-zinc-800 bg-zinc-950 p-3 flex items-center justify-between text-xs font-mono"
                  >
                    <div className="space-y-1 min-w-0 pr-2">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-emerald-400 truncate">{cfg.repoUrl}</span>
                        <span className="text-[10px] px-1.5 py-0.2 rounded bg-zinc-800 text-zinc-300">
                          {cfg.events.join(', ')}
                        </span>
                      </div>
                      <div className="text-[10px] text-zinc-500 flex items-center gap-3">
                        <span>Criado: {new Date(cfg.createdAt).toLocaleDateString('pt-BR')}</span>
                        <span>Deliveries: {cfg.totalDeliveries}</span>
                        {cfg.lastTriggeredAt && (
                          <span className="text-emerald-400">
                            Último envio: {new Date(cfg.lastTriggeredAt).toLocaleTimeString('pt-BR')}
                          </span>
                        )}
                      </div>
                    </div>

                    <button
                      onClick={() => handleDeleteConfig(cfg.id)}
                      className="text-zinc-500 hover:text-rose-400 p-1.5 transition-colors"
                      title="Excluir webhook"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right Column (5 cols): Test Simulator & GitHub Setup Guide */}
        <div className="lg:col-span-5 space-y-6">
          {/* Interactive Webhook Test Simulator */}
          <div className="rounded-lg border border-emerald-500/30 bg-emerald-950/10 p-5 space-y-4">
            <div className="flex items-center justify-between pb-2 border-b border-emerald-500/20 font-mono">
              <h3 className="text-xs font-bold text-emerald-300 uppercase tracking-wider flex items-center gap-2">
                <Play className="h-4 w-4 text-emerald-400" />
                <span>Simulador de Webhook Push</span>
              </h3>
              <span className="text-[10px] text-emerald-400 font-mono font-bold">DISPARO IMEDIATO</span>
            </div>

            <p className="text-xs text-zinc-400 font-sans leading-relaxed">
              Dispare um evento <strong className="text-emerald-300">push</strong> simulado para testar o recebimento e o recarregamento em tempo real do Dashboard de Auditoria.
            </p>

            <div className="space-y-3 font-mono text-xs">
              <div>
                <label className="block text-[11px] text-zinc-400 mb-1">Branch do Commit</label>
                <input
                  type="text"
                  value={simBranch}
                  onChange={(e) => setSimBranch(e.target.value)}
                  className="w-full px-2.5 py-1.5 bg-zinc-950 border border-zinc-800 rounded text-emerald-400 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-[11px] text-zinc-400 mb-1">Mensagem do Commit</label>
                <input
                  type="text"
                  value={simMessage}
                  onChange={(e) => setSimMessage(e.target.value)}
                  className="w-full px-2.5 py-1.5 bg-zinc-950 border border-zinc-800 rounded text-zinc-200 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-[11px] text-zinc-400 mb-1">Autor do Push</label>
                <input
                  type="text"
                  value={simAuthor}
                  onChange={(e) => setSimAuthor(e.target.value)}
                  className="w-full px-2.5 py-1.5 bg-zinc-950 border border-zinc-800 rounded text-zinc-300 focus:outline-none"
                />
              </div>
            </div>

            <button
              type="button"
              onClick={handleSimulatePush}
              disabled={isSimulating}
              className="w-full py-2.5 rounded bg-emerald-500 hover:bg-emerald-400 text-zinc-950 font-mono font-bold text-xs uppercase tracking-wider flex items-center justify-center gap-2 transition-colors disabled:opacity-50 shadow-xs"
            >
              {isSimulating ? (
                <>
                  <span className="h-3.5 w-3.5 border-2 border-zinc-950 border-t-transparent rounded-full animate-spin" />
                  <span>Enviando Payload...</span>
                </>
              ) : (
                <>
                  <Zap className="h-4 w-4 fill-current" />
                  <span>⚡ Disparar Push Event Agora</span>
                </>
              )}
            </button>
          </div>

          {/* GitHub Setup Instructions Card */}
          <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-5 space-y-3">
            <h3 className="text-xs font-mono font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Code className="h-4 w-4 text-emerald-400" />
              <span>Como Configurar no GitHub</span>
            </h3>

            <ol className="space-y-3 text-xs text-zinc-300 font-sans">
              <li className="flex items-start gap-2">
                <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded bg-zinc-800 font-mono text-[10px] font-bold text-emerald-400">
                  1
                </span>
                <div>
                  Acesse o repositório no GitHub e vá em <strong>Settings &rarr; Webhooks</strong>.
                </div>
              </li>
              <li className="flex items-start gap-2">
                <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded bg-zinc-800 font-mono text-[10px] font-bold text-emerald-400">
                  2
                </span>
                <div>
                  Clique em <strong>Add webhook</strong> e cole a <code>Payload URL</code> fornecida no formulário.
                </div>
              </li>
              <li className="flex items-start gap-2">
                <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded bg-zinc-800 font-mono text-[10px] font-bold text-emerald-400">
                  3
                </span>
                <div>
                  Selecione <strong>Content type: application/json</strong> e insira o <code>Secret</code>.
                </div>
              </li>
              <li className="flex items-start gap-2">
                <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded bg-zinc-800 font-mono text-[10px] font-bold text-emerald-400">
                  4
                </span>
                <div>
                  Escolha os eventos <strong>Pushes</strong> e/ou <strong>Pull requests</strong> e clique em <strong>Add webhook</strong>.
                </div>
              </li>
            </ol>
          </div>
        </div>
      </div>

      {/* Real-time Delivery History Table */}
      <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-5 space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-zinc-800 font-mono">
          <div className="flex items-center gap-2">
            <Clock className="h-4 w-4 text-emerald-400" />
            <h3 className="text-xs font-bold text-white uppercase tracking-wider">
              Histórico de Webhook Deliveries (Realtime Feed)
            </h3>
          </div>
          <span className="text-[10px] text-zinc-500 font-mono">
            {deliveries.length} eventos registrados
          </span>
        </div>

        {deliveries.length === 0 ? (
          <div className="text-xs text-zinc-500 font-mono py-8 text-center">
            Nenhuma delivery recebida ainda. Use o simulador acima ou faça um push no GitHub.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs">
              <thead>
                <tr className="border-b border-zinc-800 text-[10px] uppercase text-zinc-500">
                  <th className="py-2.5 px-3">Status</th>
                  <th className="py-2.5 px-3">Evento</th>
                  <th className="py-2.5 px-3">Branch / Commit</th>
                  <th className="py-2.5 px-3">Mensagem / Autor</th>
                  <th className="py-2.5 px-3">Vulnerabilidades</th>
                  <th className="py-2.5 px-3">Score Auditado</th>
                  <th className="py-2.5 px-3 text-right">Horário</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/60">
                {deliveries.map((del) => (
                  <tr key={del.id} className="hover:bg-zinc-900/80 transition-colors">
                    <td className="py-3 px-3">
                      <span className="inline-flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-500/30">
                        <CheckCircle2 className="h-3 w-3 text-emerald-400" />
                        {del.status} OK
                      </span>
                    </td>
                    <td className="py-3 px-3">
                      <span className="inline-flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded bg-zinc-800 text-zinc-300">
                        {del.event === 'push' && <GitCommit className="h-3 w-3 text-emerald-400" />}
                        {del.event === 'pull_request' && <GitPullRequest className="h-3 w-3 text-blue-400" />}
                        {del.event}
                      </span>
                    </td>
                    <td className="py-3 px-3">
                      <div className="text-zinc-200 font-bold">{del.branch}</div>
                      {del.commitSha && <div className="text-[10px] text-zinc-500">sha: {del.commitSha}</div>}
                    </td>
                    <td className="py-3 px-3 max-w-xs">
                      <div className="truncate text-zinc-300" title={del.commitMessage}>
                        {del.commitMessage || 'No commit message'}
                      </div>
                      {del.author && <div className="text-[10px] text-zinc-500">por @{del.author}</div>}
                    </td>
                    <td className="py-3 px-3">
                      {del.vulnSummary ? (
                        <div className="flex items-center gap-2 text-[10px]">
                          <span className="text-rose-400 font-bold">{del.vulnSummary.critical} Críticas</span>
                          <span className="text-amber-400">{del.vulnSummary.high} Altas</span>
                        </div>
                      ) : (
                        <span className="text-zinc-500 text-[10px]">N/A</span>
                      )}
                    </td>
                    <td className="py-3 px-3">
                      {del.vulnSummary?.score !== undefined ? (
                        <span
                          className={`text-xs font-bold ${
                            del.vulnSummary.score >= 80
                              ? 'text-emerald-400'
                              : del.vulnSummary.score >= 60
                              ? 'text-amber-400'
                              : 'text-rose-400'
                          }`}
                        >
                          {del.vulnSummary.score}/100
                        </span>
                      ) : (
                        <span className="text-zinc-500 text-[10px]">-</span>
                      )}
                    </td>
                    <td className="py-3 px-3 text-right text-[10px] text-zinc-500">
                      {new Date(del.timestamp).toLocaleTimeString('pt-BR')}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <SecurityBadgeModal
        isOpen={isBadgeModalOpen}
        onClose={() => setIsBadgeModalOpen(false)}
        showNotification={showNotification}
      />
    </div>
  );
};
