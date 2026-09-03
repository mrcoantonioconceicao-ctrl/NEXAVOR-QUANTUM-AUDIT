/**
 * Bounded Context: knowledgeGraph
 * Serviço de Orquestração RAG Híbrido (HybridRAGService)
 * Realiza a consulta paralela entre o Banco Vetorial (pgvector / Qdrant) e o Banco de Grafos (Neo4j / FalkorDB),
 * executando o Reranking ponderado, a fusão de contexto semântico-relacional e a preparação do Prompt para o Gemini AI Engine.
 * 
 * Inclui Monitor de Latência em tempo real para rastrear o tempo de resposta das consultas paralelas
 * e avaliar a eficiência da fusão de contexto.
 */

import {
  HybridRAGQueryRequest,
  HybridRAGQueryResult,
  VectorChunk,
  GraphSubgraphResult,
  FusedContextItem,
} from './types.ts';
import { HybridRAGFusionService } from './HybridRAGFusionService.ts';

export interface LatencyMetricRecord {
  id: string;
  timestamp: string;
  querySnippet: string;
  vectorRetrievalMs: number;
  graphRetrievalMs: number;
  fusionMs: number;
  totalMs: number;
  vectorCount: number;
  graphNodesCount: number;
  efficiencyRating: 'EXCELLENT' | 'GOOD' | 'MODERATE' | 'SLOW';
}

export type NotificationCallback = (message: string) => void;

export class HybridRAGService {
  private latencyHistory: LatencyMetricRecord[] = [];
  private globalNotificationHandler: NotificationCallback | null = null;

  /**
   * Registra um handler global de notificação (ex: showNotification do React)
   */
  public registerNotificationHandler(handler: NotificationCallback): void {
    this.globalNotificationHandler = handler;
  }

  /**
   * Executa a busca paralela em dois canais (Vector RAG + GraphRAG),
   * monitora a latência de cada etapa, exibe os tempos no console e notifica via showNotification.
   */
  public async executeHybridQuery(
    request: HybridRAGQueryRequest,
    customNotificationHandler?: NotificationCallback
  ): Promise<HybridRAGQueryResult> {
    const startTime = performance.now();

    // Execução da busca fusionada paralela
    const result = await HybridRAGFusionService.executeHybridQuery(request);

    const endTime = performance.now();
    const measuredTotalMs = Math.round(endTime - startTime);

    // Garantir que a latência total capturada pelo monitor seja precisa
    if (result.metrics) {
      result.metrics.totalMs = measuredTotalMs || result.metrics.totalMs;
    }

    // Registrar e Notificar a latência medida
    this.logAndTrackLatency(result, customNotificationHandler);

    return result;
  }

  /**
   * Rastreia a latência da consulta, gera classificação de eficiência, exibe logs formatados no console
   * e chama o handler de notificação (showNotification)
   */
  public logAndTrackLatency(
    result: HybridRAGQueryResult,
    customNotificationHandler?: NotificationCallback
  ): LatencyMetricRecord {
    const { metrics, query } = result;
    const { vectorRetrievalMs, graphRetrievalMs, fusionMs, totalMs, vectorCount, graphNodesCount } = metrics;

    // Calcular Rating de Eficiência
    let efficiencyRating: 'EXCELLENT' | 'GOOD' | 'MODERATE' | 'SLOW' = 'EXCELLENT';
    if (totalMs > 300) {
      efficiencyRating = 'SLOW';
    } else if (totalMs > 150) {
      efficiencyRating = 'MODERATE';
    } else if (totalMs > 50) {
      efficiencyRating = 'GOOD';
    }

    const record: LatencyMetricRecord = {
      id: `rag_lat_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      timestamp: new Date().toISOString(),
      querySnippet: query.length > 50 ? query.substring(0, 50) + '...' : query,
      vectorRetrievalMs,
      graphRetrievalMs,
      fusionMs,
      totalMs,
      vectorCount,
      graphNodesCount,
      efficiencyRating,
    };

    // Armazenar no histórico em memória (últimos 50 registros)
    this.latencyHistory.unshift(record);
    if (this.latencyHistory.length > 50) {
      this.latencyHistory.pop();
    }

    // === CONSOLE LOGGING FORMATADO ===
    console.group(`⚡ [HybridRAG Latency Monitor] Consulta: "${record.querySnippet}"`);
    console.log(`⏱️  Tempo Total: ${totalMs} ms (Rating: ${efficiencyRating})`);
    console.log(`🔍 Vector RAG (pgvector): ${vectorRetrievalMs} ms (${vectorCount} trechos)`);
    console.log(`🕸️  GraphRAG (Neo4j): ${graphRetrievalMs} ms (${graphNodesCount} nós)`);
    console.log(`🧬 Reranking & Fusão: ${fusionMs} ms`);
    console.table([
      {
        Etapa: '1. Vector Retrieval',
        'Tempo (ms)': vectorRetrievalMs,
        'Participação (%)': `${Math.round((vectorRetrievalMs / Math.max(1, totalMs)) * 100)}%`,
      },
      {
        Etapa: '2. Graph Traversal',
        'Tempo (ms)': graphRetrievalMs,
        'Participação (%)': `${Math.round((graphRetrievalMs / Math.max(1, totalMs)) * 100)}%`,
      },
      {
        Etapa: '3. Context Fusion & Reranking',
        'Tempo (ms)': fusionMs,
        'Participação (%)': `${Math.round((fusionMs / Math.max(1, totalMs)) * 100)}%`,
      },
      {
        Etapa: 'TOTAL',
        'Tempo (ms)': totalMs,
        'Participação (%)': '100%',
      },
    ]);
    console.groupEnd();

    // === EMISSÃO DE NOTIFICAÇÃO ===
    const notifyText = `⚡ [RAG Latency] Total: ${totalMs}ms | Vector: ${vectorRetrievalMs}ms | Graph: ${graphRetrievalMs}ms | Fusão: ${fusionMs}ms (${efficiencyRating})`;

    if (customNotificationHandler) {
      customNotificationHandler(notifyText);
    } else if (this.globalNotificationHandler) {
      this.globalNotificationHandler(notifyText);
    }

    return record;
  }

  /**
   * Retorna o histórico recente de logs de latência
   */
  public getLatencyHistory(): LatencyMetricRecord[] {
    return [...this.latencyHistory];
  }

  /**
   * Calcula as métricas médias de latência acumuladas
   */
  public getAverageMetrics() {
    if (this.latencyHistory.length === 0) {
      return {
        avgVectorMs: 0,
        avgGraphMs: 0,
        avgFusionMs: 0,
        avgTotalMs: 0,
        totalQueriesExecuted: 0,
      };
    }

    const total = this.latencyHistory.length;
    const sumVector = this.latencyHistory.reduce((acc, curr) => acc + curr.vectorRetrievalMs, 0);
    const sumGraph = this.latencyHistory.reduce((acc, curr) => acc + curr.graphRetrievalMs, 0);
    const sumFusion = this.latencyHistory.reduce((acc, curr) => acc + curr.fusionMs, 0);
    const sumTotal = this.latencyHistory.reduce((acc, curr) => acc + curr.totalMs, 0);

    return {
      avgVectorMs: Math.round(sumVector / total),
      avgGraphMs: Math.round(sumGraph / total),
      avgFusionMs: Math.round(sumFusion / total),
      avgTotalMs: Math.round(sumTotal / total),
      totalQueriesExecuted: total,
    };
  }

  /**
   * Limpa o histórico de latência
   */
  public clearLatencyHistory(): void {
    this.latencyHistory = [];
  }

  /**
   * Executa a busca vetorial isolada em especificações e advisories de segurança
   */
  public async performVectorSearch(query: string, topK: number = 5): Promise<VectorChunk[]> {
    const res = await this.executeHybridQuery({ query, topK, vectorWeight: 1.0, graphWeight: 0.0 });
    return res.vectorResults;
  }

  /**
   * Executa a travessia isolada no Grafo de Conhecimento do Neo4j
   */
  public async performGraphTraversal(targetFileOrFunction: string): Promise<GraphSubgraphResult> {
    const res = await this.executeHybridQuery({
      query: `Impact analysis for ${targetFileOrFunction}`,
      targetFileOrFunction,
      vectorWeight: 0.0,
      graphWeight: 1.0,
    });
    return res.graphResult;
  }

  /**
   * Constrói o Prompt Enriquecido consolidador para consumo pelo Gemini Engine
   */
  public buildGeminiContextPrompt(
    userQuery: string,
    fusedItems: FusedContextItem[],
    cypherQuery: string
  ): string {
    const itemsText = fusedItems
      .map(
        (item, index) =>
          `[Contexto #${index + 1} | Origem: ${item.sourceType} | Score Reranked: ${item.rerankedScore}]\n` +
          `Título: ${item.title}\n` +
          `Conteúdo: ${item.content}\n`
      )
      .join('\n---\n');

    return `
SYSTEM INSTRUCTION: NEXAVOR QUANTUM AUDIT - GEMINI HYBRID RAG ORCHESTRATOR
Você é o auditor principal de segurança DevSecOps do sistema NEXAVOR-QUANTUM-AUDIT.
Sua tarefa é analisar o código e a infraestrutura a partir das evidências combinadas recuperadas via Vector RAG (pgvector) e GraphRAG (Neo4j).

=== PERGUNTA DA AUDITORIA ===
"${userQuery}"

=== CONTEXTO HÍBRIDO FUSIONADO (SEMÂNTICA + GRAFO RELACIONAL) ===
${itemsText}

=== CONSULTA CYPHER EXECUTADA NO NEO4J ===
${cypherQuery}

=== DIRECTIVAS DE RESPOSTA ===
1. Responda em Português com linguagem técnica e direta.
2. Identifique de forma explícita o impacto no Grafo de Conhecimento (arquivos, funções e dependências vulneráveis) e correlacione com a norma técnica (FIPS 204 / NIST SP 800-218 / PCI-DSS v4.0).
3. Apresente o código refatorado in-place com tratamentos seguros (ex: checked_add, checked_sub) e isolamento pós-quântico.
`.trim();
  }
}

export const hybridRagService = new HybridRAGService();

