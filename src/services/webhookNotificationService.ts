/**
 * Serviço de Notificação em Tempo Real (Webhooks, Slack, Microsoft Teams e Discord)
 */

export interface WebhookConfig {
  id: string;
  name: string;
  url: string;
  platform: 'SLACK' | 'TEAMS' | 'DISCORD' | 'GENERIC_JSON';
  enabled: boolean;
  triggerOnCritical: boolean;
  triggerOnHigh: boolean;
  triggerOnComplianceFailure: boolean;
  createdAt: string;
}

export interface WebhookDispatchLog {
  id: string;
  webhookName: string;
  timestamp: string;
  status: 'SUCCESS' | 'FAILED';
  statusCode: number;
  message: string;
}

const STORAGE_KEY_WEBHOOKS = 'rustshield_webhook_configs_v1';
const STORAGE_KEY_LOGS = 'rustshield_webhook_logs_v1';

export class WebhookNotificationService {
  /**
   * Obtém as configurações de Webhook salvas
   */
  public static getConfigs(): WebhookConfig[] {
    try {
      const data = localStorage.getItem(STORAGE_KEY_WEBHOOKS);
      if (data) {
        return JSON.parse(data);
      }
    } catch (e) {
      console.error('Erro ao ler webhooks do localStorage:', e);
    }
    return [
      {
        id: 'wh_default_slack',
        name: 'Canal SecOps Slack (Exemplo)',
        url: 'https://hooks.slack.com/services/T000/B000/XXXXX',
        platform: 'SLACK',
        enabled: true,
        triggerOnCritical: true,
        triggerOnHigh: true,
        triggerOnComplianceFailure: true,
        createdAt: new Date().toISOString(),
      },
    ];
  }

  /**
   * Salva configurações de Webhook
   */
  public static saveConfigs(configs: WebhookConfig[]): void {
    try {
      localStorage.setItem(STORAGE_KEY_WEBHOOKS, JSON.stringify(configs));
    } catch (e) {
      console.error('Erro ao salvar webhooks no localStorage:', e);
    }
  }

  /**
   * Obtém os logs de envio
   */
  public static getDispatchLogs(): WebhookDispatchLog[] {
    try {
      const data = localStorage.getItem(STORAGE_KEY_LOGS);
      if (data) {
        return JSON.parse(data);
      }
    } catch (e) {
      console.error('Erro ao ler logs de webhook:', e);
    }
    return [];
  }

  /**
   * Registra um log de envio
   */
  private static addLog(log: WebhookDispatchLog): void {
    const logs = this.getDispatchLogs();
    logs.unshift(log);
    if (logs.length > 50) logs.pop();
    try {
      localStorage.setItem(STORAGE_KEY_LOGS, JSON.stringify(logs));
    } catch (e) {
      console.error('Erro ao salvar log de webhook:', e);
    }
  }

  /**
   * Envia um disparo de teste para o Webhook especificado
   */
  public static async sendTestNotification(config: WebhookConfig): Promise<{ success: boolean; message: string }> {
    const payload = this.formatPayload(config.platform, {
      title: '🚨 Teste de Conexão de Webhook - RustShield Quantum',
      repoName: 'NEXAVOR-QUANTUM-AUDIT',
      criticalCount: 2,
      highCount: 5,
      score: 88,
      detailsUrl: 'https://ai.studio/build',
    });

    try {
      if (config.url.includes('example') || config.url.includes('XXXXX')) {
        // Simulação bem sucedida para URL demonstrativa
        const log: WebhookDispatchLog = {
          id: `log_${Date.now()}`,
          webhookName: config.name,
          timestamp: new Date().toISOString(),
          status: 'SUCCESS',
          statusCode: 200,
          message: 'Disparo de teste simulado com sucesso (URL Demonstrativa)',
        };
        this.addLog(log);
        return { success: true, message: 'Disparo de teste simulado com sucesso!' };
      }

      const res = await fetch(config.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const isSuccess = res.ok;
      const log: WebhookDispatchLog = {
        id: `log_${Date.now()}`,
        webhookName: config.name,
        timestamp: new Date().toISOString(),
        status: isSuccess ? 'SUCCESS' : 'FAILED',
        statusCode: res.status,
        message: isSuccess ? 'Alerta entregue com sucesso' : `Erro HTTP ${res.status}`,
      };
      this.addLog(log);

      return {
        success: isSuccess,
        message: isSuccess ? 'Disparo realizado com sucesso!' : `Falha no envio (HTTP ${res.status})`,
      };
    } catch (err: any) {
      const log: WebhookDispatchLog = {
        id: `log_${Date.now()}`,
        webhookName: config.name,
        timestamp: new Date().toISOString(),
        status: 'FAILED',
        statusCode: 0,
        message: err?.message || 'Erro de rede ao conectar no Webhook',
      };
      this.addLog(log);

      return {
        success: false,
        message: `Erro ao disparar Webhook: ${err?.message || 'Erro de rede'}`,
      };
    }
  }

  /**
   * Notifica automaticamente webhooks configurados sobre vulnerabilidades detectadas
   */
  public static async notifyAuditAlert(data: {
    repoName: string;
    criticalCount: number;
    highCount: number;
    score: number;
  }): Promise<void> {
    const configs = this.getConfigs().filter((c) => c.enabled);
    if (configs.length === 0) return;

    for (const config of configs) {
      const shouldTrigger =
        (config.triggerOnCritical && data.criticalCount > 0) ||
        (config.triggerOnHigh && data.highCount > 0) ||
        (config.triggerOnComplianceFailure && data.score < 70);

      if (!shouldTrigger) continue;

      const payload = this.formatPayload(config.platform, {
        title: `🚨 Alerta de Segurança DevSecOps: ${data.repoName}`,
        repoName: data.repoName,
        criticalCount: data.criticalCount,
        highCount: data.highCount,
        score: data.score,
        detailsUrl: window.location.href,
      });

      try {
        if (!config.url.includes('example') && !config.url.includes('XXXXX')) {
          await fetch(config.url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
          });
        }
        this.addLog({
          id: `log_${Date.now()}`,
          webhookName: config.name,
          timestamp: new Date().toISOString(),
          status: 'SUCCESS',
          statusCode: 200,
          message: `Notificação enviada: ${data.criticalCount} críticas, ${data.highCount} altas. Score: ${data.score}%`,
        });
      } catch (err: any) {
        this.addLog({
          id: `log_${Date.now()}`,
          webhookName: config.name,
          timestamp: new Date().toISOString(),
          status: 'FAILED',
          statusCode: 0,
          message: `Falha ao notificar: ${err?.message || 'Erro de rede'}`,
        });
      }
    }
  }

  /**
   * Formata a carga útil (payload) de acordo com a plataforma alvo
   */
  private static formatPayload(
    platform: WebhookConfig['platform'],
    params: {
      title: string;
      repoName: string;
      criticalCount: number;
      highCount: number;
      score: number;
      detailsUrl: string;
    }
  ) {
    if (platform === 'SLACK') {
      return {
        text: `${params.title}\n*Repositório:* ${params.repoName}\n*Vulnerabilidades Críticas:* ${params.criticalCount}\n*Vulnerabilidades Altas:* ${params.highCount}\n*Score de Segurança:* ${params.score}%`,
        attachments: [
          {
            color: params.criticalCount > 0 ? '#E11D48' : '#D97706',
            fields: [
              { title: 'Status', value: params.score >= 80 ? 'Seguro' : 'Risco Elevado', short: true },
              { title: 'Ação Recomendada', value: 'Executar Autofix IA no Cockpit RustShield', short: true },
            ],
          },
        ],
      };
    }

    if (platform === 'TEAMS') {
      return {
        '@type': 'MessageCard',
        '@context': 'http://schema.org/extensions',
        themeColor: params.criticalCount > 0 ? 'E11D48' : 'D97706',
        summary: params.title,
        sections: [
          {
            activityTitle: params.title,
            activitySubtitle: `Repositório: ${params.repoName}`,
            facts: [
              { name: 'Falhas Críticas', value: `${params.criticalCount}` },
              { name: 'Falhas Altas', value: `${params.highCount}` },
              { name: 'Score Geral', value: `${params.score}%` },
            ],
            markdown: true,
          },
        ],
      };
    }

    if (platform === 'DISCORD') {
      return {
        content: `**${params.title}**`,
        embeds: [
          {
            title: `Resultado da Auditoria - ${params.repoName}`,
            color: params.criticalCount > 0 ? 14752840 : 14251782,
            fields: [
              { name: 'Críticas', value: `${params.criticalCount}`, inline: true },
              { name: 'Altas', value: `${params.highCount}`, inline: true },
              { name: 'Score de Segurança', value: `${params.score}%`, inline: true },
            ],
          },
        ],
      };
    }

    // GENERIC_JSON
    return {
      event: 'SECURITY_AUDIT_ALERT',
      timestamp: new Date().toISOString(),
      repository: params.repoName,
      metrics: {
        criticalVulnerabilities: params.criticalCount,
        highVulnerabilities: params.highCount,
        overallSecurityScore: params.score,
      },
    };
  }
}
