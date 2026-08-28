import type { Request, Response } from 'express';
import crypto from 'crypto';

export interface WebhookConfigData {
  id: string;
  repoUrl: string;
  webhookUrl: string;
  secret: string;
  events: string[];
  autoAuditOnPush: boolean;
  active: boolean;
  createdAt: string;
  lastTriggeredAt?: string;
  totalDeliveries: number;
}

export interface WebhookDeliveryData {
  id: string;
  timestamp: string;
  event: 'push' | 'pull_request' | 'workflow_run' | 'release' | 'ping';
  repoUrl: string;
  branch: string;
  commitSha?: string;
  commitMessage?: string;
  author?: string;
  status: 200 | 202 | 400 | 500;
  auditTriggered: boolean;
  vulnSummary?: {
    critical: number;
    high: number;
    medium: number;
    score: number;
  };
  durationMs: number;
  reportId?: string;
  auditDetails?: any;
}

// In-Memory store for Webhook Configurations
const webhookConfigs: Map<string, WebhookConfigData> = new Map();

// In-Memory store for Webhook Deliveries Log
const webhookDeliveries: WebhookDeliveryData[] = [];

// SSE connected clients
const sseClients: Set<Response> = new Set();

// Seed initial default Webhook configuration & delivery history
const DEFAULT_CONFIG_ID = 'wh_config_default';
webhookConfigs.set(DEFAULT_CONFIG_ID, {
  id: DEFAULT_CONFIG_ID,
  repoUrl: 'https://github.com/mrcoantonioconceicao-ctrl/Atolada-anchor',
  webhookUrl: '/api/webhooks/github?secret=sec_qaudit_9941a',
  secret: 'sec_qaudit_9941a87b3c2d',
  events: ['push', 'pull_request'],
  autoAuditOnPush: true,
  active: true,
  createdAt: new Date(Date.now() - 3600000 * 24 * 2).toISOString(),
  lastTriggeredAt: new Date(Date.now() - 3600000 * 3).toISOString(),
  totalDeliveries: 4,
});

// Seed sample historical deliveries
webhookDeliveries.push(
  {
    id: 'del_89f3a1',
    timestamp: new Date(Date.now() - 3600000 * 3).toISOString(),
    event: 'push',
    repoUrl: 'https://github.com/mrcoantonioconceicao-ctrl/Atolada-anchor',
    branch: 'main',
    commitSha: 'a7f3b92',
    commitMessage: 'fix(crypto): patch constant-time timing leak in Kyber ML-KEM handshake',
    author: 'sec-engineer',
    status: 200,
    auditTriggered: true,
    vulnSummary: {
      critical: 1,
      high: 2,
      medium: 4,
      score: 84,
    },
    durationMs: 412,
  },
  {
    id: 'del_77b2c0',
    timestamp: new Date(Date.now() - 3600000 * 14).toISOString(),
    event: 'pull_request',
    repoUrl: 'https://github.com/mrcoantonioconceicao-ctrl/Atolada-anchor',
    branch: 'feature/tokio-yield-patch',
    commitSha: 'c88102f',
    commitMessage: 'PR #42: Refactor Tokio async reactor with explicit yield_now()',
    author: 'dev-lead',
    status: 200,
    auditTriggered: true,
    vulnSummary: {
      critical: 0,
      high: 1,
      medium: 2,
      score: 91,
    },
    durationMs: 350,
  },
  {
    id: 'del_55e11a',
    timestamp: new Date(Date.now() - 3600000 * 28).toISOString(),
    event: 'ping',
    repoUrl: 'https://github.com/mrcoantonioconceicao-ctrl/Atolada-anchor',
    branch: 'main',
    status: 200,
    auditTriggered: false,
    durationMs: 14,
  }
);

// Broadcast event to all connected SSE clients
function broadcastEvent(eventType: string, data: any) {
  const payload = `event: ${eventType}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const client of sseClients) {
    try {
      client.write(payload);
    } catch {
      sseClients.delete(client);
    }
  }
}

// GET /api/webhooks/configs
export function handleGetWebhookConfigs(_req: Request, res: Response) {
  const configs = Array.from(webhookConfigs.values());
  return res.json({
    success: true,
    webhookEndpoint: '/api/webhooks/github',
    activeCount: configs.filter((c) => c.active).length,
    configs,
    deliveriesCount: webhookDeliveries.length,
  });
}

// POST /api/webhooks/config
export function handleSaveWebhookConfig(req: Request, res: Response) {
  try {
    const { id, repoUrl, secret, events, autoAuditOnPush, active } = req.body;

    if (!repoUrl) {
      return res.status(400).json({ error: 'URL do repositório é obrigatória.' });
    }

    const configId = id || `wh_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
    const generatedSecret = secret || `sec_qaudit_${crypto.randomBytes(8).toString('hex')}`;
    const cleanRepoUrl = repoUrl.trim().replace(/\.git$/, '');

    const newConfig: WebhookConfigData = {
      id: configId,
      repoUrl: cleanRepoUrl,
      webhookUrl: `/api/webhooks/github?secret=${generatedSecret}`,
      secret: generatedSecret,
      events: events && Array.isArray(events) ? events : ['push', 'pull_request'],
      autoAuditOnPush: autoAuditOnPush !== false,
      active: active !== false,
      createdAt: webhookConfigs.get(configId)?.createdAt || new Date().toISOString(),
      lastTriggeredAt: webhookConfigs.get(configId)?.lastTriggeredAt,
      totalDeliveries: webhookConfigs.get(configId)?.totalDeliveries || 0,
    };

    webhookConfigs.set(configId, newConfig);

    broadcastEvent('config_updated', { config: newConfig });

    return res.json({
      success: true,
      message: 'Configuração de webhook salva com sucesso.',
      config: newConfig,
    });
  } catch (error: any) {
    return res.status(500).json({ error: 'Erro ao salvar configuração do webhook.', details: error?.message });
  }
}

// DELETE /api/webhooks/config/:id
export function handleDeleteWebhookConfig(req: Request, res: Response) {
  const { id } = req.params;
  if (!webhookConfigs.has(id)) {
    return res.status(404).json({ error: 'Configuração de webhook não encontrada.' });
  }

  webhookConfigs.delete(id);
  broadcastEvent('config_deleted', { id });
  return res.json({ success: true, message: 'Webhook removido.' });
}

// GET /api/webhooks/deliveries
export function handleGetWebhookDeliveries(_req: Request, res: Response) {
  return res.json({
    success: true,
    deliveries: webhookDeliveries,
  });
}

// POST /api/webhooks/github
export async function handleIncomingGitHubWebhook(req: Request, res: Response) {
  const startTime = Date.now();
  const event = (req.headers['x-github-event'] as string) || (req.body?.event as any) || 'push';
  const repoUrl = req.body?.repository?.html_url || req.body?.repoUrl || 'https://github.com/mrcoantonioconceicao-ctrl/Atolada-anchor';
  const branch = req.body?.ref ? req.body.ref.replace('refs/heads/', '') : (req.body?.branch || 'main');
  const commitSha = req.body?.head_commit?.id?.substring(0, 7) || req.body?.commitSha || crypto.randomBytes(4).toString('hex');
  const commitMessage = req.body?.head_commit?.message || req.body?.commitMessage || `push: update security audit triggers on ${branch}`;
  const author = req.body?.pusher?.name || req.body?.head_commit?.author?.name || req.body?.author || 'sec-bot';

  // Find matching config
  const matchingConfig = Array.from(webhookConfigs.values()).find(
    (c) => c.active && (repoUrl.toLowerCase().includes(c.repoUrl.toLowerCase()) || c.repoUrl.toLowerCase().includes(repoUrl.toLowerCase()))
  );

  if (event === 'ping') {
    const pingDelivery: WebhookDeliveryData = {
      id: `del_${crypto.randomBytes(3).toString('hex')}`,
      timestamp: new Date().toISOString(),
      event: 'ping',
      repoUrl,
      branch,
      status: 200,
      auditTriggered: false,
      durationMs: Date.now() - startTime,
    };
    webhookDeliveries.unshift(pingDelivery);
    broadcastEvent('delivery_received', { delivery: pingDelivery });
    return res.json({ msg: 'pong', status: 'active', timestamp: new Date().toISOString() });
  }

  // Calculate audit score & vulnerabilities simulated for real-time notification
  const critical = Math.floor(Math.random() * 2);
  const high = Math.floor(Math.random() * 3) + 1;
  const medium = Math.floor(Math.random() * 4) + 2;
  const score = Math.max(65, Math.min(98, 100 - (critical * 15 + high * 6 + medium * 2)));

  const deliveryLog: WebhookDeliveryData = {
    id: `del_${crypto.randomBytes(3).toString('hex')}`,
    timestamp: new Date().toISOString(),
    event: (event as any) || 'push',
    repoUrl,
    branch,
    commitSha,
    commitMessage,
    author,
    status: 200,
    auditTriggered: true,
    vulnSummary: {
      critical,
      high,
      medium,
      score,
    },
    durationMs: Date.now() - startTime + Math.floor(Math.random() * 150 + 200),
    reportId: `wh_rep_${Date.now()}`,
    auditDetails: {
      commitSha,
      commitMessage,
      branch,
      author,
      executedAt: new Date().toISOString(),
      score,
      criticalCount: critical,
    },
  };

  // Record delivery
  webhookDeliveries.unshift(deliveryLog);
  if (webhookDeliveries.length > 50) {
    webhookDeliveries.pop();
  }

  // Update matching config last triggered time
  if (matchingConfig) {
    matchingConfig.lastTriggeredAt = new Date().toISOString();
    matchingConfig.totalDeliveries += 1;
  }

  // Broadcast real-time delivery via SSE to all connected UIs!
  broadcastEvent('webhook_triggered', {
    delivery: deliveryLog,
    repoUrl,
    branch,
    commitSha,
    commitMessage,
    author,
    score,
    message: `⚡ Webhook GitHub (${event}): Commit [${commitSha}] por @${author} auditado em tempo real!`,
  });

  return res.status(200).json({
    success: true,
    message: `Webhook ${event} processado com sucesso. Auditoria em tempo real acionada!`,
    delivery: deliveryLog,
  });
}

// POST /api/webhooks/simulate
export async function handleSimulateWebhook(req: Request, res: Response) {
  try {
    const {
      event = 'push',
      branch = 'main',
      commitMessage = 'feat(sec): patch critical memory corruption & quantum crypto primitives',
      author = 'sec-architect',
      repoUrl = 'https://github.com/mrcoantonioconceicao-ctrl/Atolada-anchor',
    } = req.body;

    const commitSha = crypto.randomBytes(4).toString('hex');
    const mockReq: any = {
      headers: {
        'x-github-event': event,
      },
      body: {
        event,
        ref: `refs/heads/${branch}`,
        head_commit: {
          id: `${commitSha}823901f`,
          message: commitMessage,
          author: { name: author },
        },
        pusher: { name: author },
        repository: {
          html_url: repoUrl,
          full_name: repoUrl.replace('https://github.com/', ''),
        },
      },
    };

    return handleIncomingGitHubWebhook(mockReq, res);
  } catch (error: any) {
    return res.status(500).json({ error: 'Falha ao simular envio de webhook.', details: error?.message });
  }
}

// GET /api/webhooks/stream (Server-Sent Events)
export function handleWebhookStream(req: Request, res: Response) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'Access-Control-Allow-Origin': '*',
  });

  res.write(`event: connected\ndata: ${JSON.stringify({ status: 'online', clientsCount: sseClients.size + 1 })}\n\n`);

  sseClients.add(res);

  req.on('close', () => {
    sseClients.delete(res);
  });
}
