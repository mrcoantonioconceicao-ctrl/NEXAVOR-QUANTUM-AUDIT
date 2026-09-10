/**
 * Service: HybridRAGService
 * Serviço de orquestração RAG Híbrido (Vector RAG Qdrant/pgvector + GraphRAG Neo4j)
 * com suporte a Circuit Breaker de 3 estados (CLOSED, OPEN, HALF_OPEN),
 * timeout estrito de 1500ms no Neo4j e Exponential Backoff com Jitter
 * no fallback vetorial para evitar sobrecarga/avalanche no cluster Qdrant.
 */

import { HybridRAGFusionService } from '../domain/knowledgeGraph/HybridRAGFusionService.ts';
import {
  HybridRAGQueryRequest,
  HybridRAGQueryResult,
  GraphSubgraphResult,
} from '../domain/knowledgeGraph/types.ts';

export type CircuitState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export interface CircuitBreakerBackoffConfig {
  /** Número de falhas consecutivas antes de desarmar para OPEN (padrão: 3) */
  failureThreshold: number;
  /** Delay base do backoff exponencial em ms (padrão: 150ms) */
  baseBackoffMs: number;
  /** Multiplicador da escala exponencial (padrão: 2.0) */
  backoffMultiplier: number;
  /** Teto máximo de delay de backoff em ms (padrão: 3000ms) */
  maxBackoffMs: number;
  /** Fator de variação pseudo-aleatória (jitter) para mitigar thundering herd (padrão: 0.2 = ±20%) */
  jitterFactor: number;
  /** Janela de resfriamento em ms antes de testar recuperação em HALF_OPEN (padrão: 12000ms = 12s) */
  resetTimeoutMs: number;
  /** Timeout rígido para operações de grafo no Neo4j (padrão: 1500ms) */
  neo4jTimeoutMs: number;
}

export interface HybridRagCircuitTelemetry {
  state: CircuitState;
  consecutiveFailures: number;
  lastFailureTimestamp: number | null;
  lastSuccessTimestamp: number | null;
  currentEstimatedBackoffMs: number;
  totalFallbackCalls: number;
  totalThrottledDelayMs: number;
  lastBackoffAppliedMs: number;
  graphContextAvailable: boolean;
}

export class HybridRAGService {
  private static config: CircuitBreakerBackoffConfig = {
    failureThreshold: 3,
    baseBackoffMs: 150,
    backoffMultiplier: 2.0,
    maxBackoffMs: 3000,
    jitterFactor: 0.2,
    resetTimeoutMs: 12000,
    neo4jTimeoutMs: 1500,
  };

  private static state: CircuitState = 'CLOSED';
  private static consecutiveFailures: number = 0;
  private static lastFailureTimestamp: number | null = null;
  private static lastSuccessTimestamp: number | null = null;
  private static totalFallbackCalls: number = 0;
  private static totalThrottledDelayMs: number = 0;
  private static lastBackoffAppliedMs: number = 0;

  /**
   * Helper utilitário para aguardar com Promise
   */
  private static sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Configura dinamicamente os parâmetros do Circuit Breaker e Exponential Backoff
   */
  public static configure(newConfig: Partial<CircuitBreakerBackoffConfig>): void {
    this.config = { ...this.config, ...newConfig };
  }

  /**
   * Calcula o delay de Exponential Backoff com Full Jitter
   * Fórmula: min(maxBackoffMs, baseBackoffMs * (multiplier ^ (failures - 1))) * (1 ± jitter)
   */
  public static calculateExponentialBackoff(failureCount: number): number {
    if (failureCount <= 0) return 0;

    const exponent = Math.max(0, failureCount - 1);
    const rawDelay = Math.min(
      this.config.maxBackoffMs,
      this.config.baseBackoffMs * Math.pow(this.config.backoffMultiplier, exponent)
    );

    // Jitter pseudo-aleatório simétrico entre [-jitterFactor, +jitterFactor]
    const jitterMultiplier = 1 + (Math.random() * 2 - 1) * this.config.jitterFactor;
    const finalDelay = Math.max(0, Math.round(rawDelay * jitterMultiplier));

    return Math.min(this.config.maxBackoffMs, finalDelay);
  }

  /**
   * Obtém a telemetria atual do Circuit Breaker e do mecanismo de backoff
   */
  public static getTelemetry(): HybridRagCircuitTelemetry {
    return {
      state: this.state,
      consecutiveFailures: this.consecutiveFailures,
      lastFailureTimestamp: this.lastFailureTimestamp,
      lastSuccessTimestamp: this.lastSuccessTimestamp,
      currentEstimatedBackoffMs: this.calculateExponentialBackoff(this.consecutiveFailures),
      totalFallbackCalls: this.totalFallbackCalls,
      totalThrottledDelayMs: this.totalThrottledDelayMs,
      lastBackoffAppliedMs: this.lastBackoffAppliedMs,
      graphContextAvailable: this.state === 'CLOSED',
    };
  }

  /**
   * Redefine manualmente o estado do Circuit Breaker para CLOSED
   */
  public static resetCircuitBreaker(): void {
    const previousState = this.state;
    this.state = 'CLOSED';
    this.consecutiveFailures = 0;
    this.lastFailureTimestamp = null;
    this.lastBackoffAppliedMs = 0;
    console.log(
      `🔄 [HybridRAG Circuit Breaker] Reset manual executado. Estado alterado de ${previousState} para CLOSED.`
    );
  }

  /**
   * Executa a busca híbrida (Vetor + Grafo Neo4j) com resiliência:
   * 1. Monitora o estado do Circuit Breaker (CLOSED / OPEN / HALF_OPEN).
   * 2. Se o Neo4j estiver em OPEN (falhas recorrentes), bypassa a chamada do grafo
   *    para não esperar o timeout inútil de 1500ms e aplica EXPONENTIAL BACKOFF com Jitter
   *    antes de chamar o Qdrant/pgvector, evitando a sobrecarga por efeito manada (thundering herd).
   * 3. Se o Neo4j falhar ou ultrapassar 1500ms, incrementa a contagem de falhas,
   *    calcula o backoff proporcional e chaveia suavemente para 'graphContextAvailable: false'.
   */
  public static async executeHybridQuery(request: HybridRAGQueryRequest): Promise<HybridRAGQueryResult> {
    const now = Date.now();

    // 1. Verificação de transição para HALF_OPEN após período de resfriamento
    if (this.state === 'OPEN' && this.lastFailureTimestamp) {
      const elapsedSinceFailure = now - this.lastFailureTimestamp;
      if (elapsedSinceFailure >= this.config.resetTimeoutMs) {
        this.state = 'HALF_OPEN';
        console.info(
          `🟡 [HybridRAG Circuit Breaker] Cooldown de ${elapsedSinceFailure}ms decorrido. Transicionando para HALF_OPEN para sondagem de recuperação do Neo4j.`
        );
      }
    }

    // 2. Se o Circuit Breaker estiver OPEN, aciona diretamente o Fallback com Exponential Backoff
    if (this.state === 'OPEN') {
      return this.executeVectorFallbackWithBackoff(request, 'CIRCUIT_BREAKER_OPEN_BYPASS');
    }

    // 3. Tentativa de consulta no Neo4j com timeout estrito de 1500ms
    let neo4jFailed = false;
    let failureReason = '';

    try {
      // Criação de promise de timeout estrito
      const neo4jTimeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(
          () => reject(new Error(`NEO4J_TIMEOUT_EXCEEDED (>${this.config.neo4jTimeoutMs}ms)`)),
          this.config.neo4jTimeoutMs
        );
      });

      // Execução da query via FusionService
      const queryPromise = HybridRAGFusionService.executeHybridQuery(request);

      const result = await Promise.race([queryPromise, neo4jTimeoutPromise]);

      // Se o FusionService já detectou circuit breaker internamente
      if (!result.graphContextAvailable || result.circuitBreakerTriggered) {
        neo4jFailed = true;
        failureReason = 'Internal FusionService flagged graph unavailable';
      } else {
        // Sucesso comprovado no Neo4j
        if (this.state === 'HALF_OPEN' || this.consecutiveFailures > 0) {
          console.info(
            `🟢 [HybridRAG Circuit Breaker] Neo4j respondeu com sucesso! Recuperação confirmada. Circuit Breaker redefinido para CLOSED.`
          );
        }
        this.state = 'CLOSED';
        this.consecutiveFailures = 0;
        this.lastSuccessTimestamp = Date.now();
        this.lastBackoffAppliedMs = 0;

        return {
          ...result,
          circuitBreakerState: 'CLOSED',
          backoffAppliedMs: 0,
          consecutiveFailures: 0,
        };
      }
    } catch (err: any) {
      neo4jFailed = true;
      failureReason = err?.message || String(err);
    }

    // 4. Se o Neo4j falhou ou expirou os 1500ms, aplica a lógica de falha recorrente e backoff
    if (neo4jFailed) {
      this.consecutiveFailures++;
      this.lastFailureTimestamp = Date.now();

      if (this.consecutiveFailures >= this.config.failureThreshold) {
        this.state = 'OPEN';
        console.warn(
          `🔴 [HybridRAG Circuit Breaker] Limiar atingido (${this.consecutiveFailures} falhas consecutivas). Circuit Breaker DESARMADO para estado OPEN.`
        );
      }

      return this.executeVectorFallbackWithBackoff(request, failureReason);
    }

    // Fallback defensivo padrão
    return HybridRAGFusionService.executeHybridQuery(request);
  }

  /**
   * Executa a rota de fallback para o contexto vetorial puro aplicando Exponential Backoff
   * para proteger o Qdrant contra picos repentinos de concorrência.
   */
  private static async executeVectorFallbackWithBackoff(
    request: HybridRAGQueryRequest,
    reason: string
  ): Promise<HybridRAGQueryResult> {
    this.totalFallbackCalls++;

    // Cálculo do backoff com base no número de falhas consecutivas
    const backoffMs = this.calculateExponentialBackoff(this.consecutiveFailures);
    this.lastBackoffAppliedMs = backoffMs;
    this.totalThrottledDelayMs += backoffMs;

    console.warn(
      `⏱️ [HybridRAG Backoff] Falha do Neo4j registrada (${reason}). ` +
      `Falhas consecutivas: ${this.consecutiveFailures} | Estado: ${this.state}. ` +
      `Aplicando Exponential Backoff de ${backoffMs}ms no acesso ao Qdrant para amortecer a carga no banco vetorial.`
    );

    // Amortecimento / Pacing temporal antes de requisitar o contexto vetorial
    if (backoffMs > 0) {
      await this.sleep(backoffMs);
    }

    // Requisição ao contexto vetorial puro (peso 1.0 para vetor, 0.0 para grafo)
    const vectorOnlyRequest: HybridRAGQueryRequest = {
      ...request,
      vectorWeight: 1.0,
      graphWeight: 0.0,
    };

    const vectorResult = await HybridRAGFusionService.executeHybridQuery(vectorOnlyRequest);

    // Subgrafo vazio de fallback com metadados do Circuit Breaker
    const emptySubgraph: GraphSubgraphResult = {
      nodes: [],
      relationships: [],
      cypherMatchQuery: `// [CIRCUIT BREAKER: ${this.state}] Neo4j indisponível (${reason}). Backoff aplicado: ${backoffMs}ms.`,
      relevanceScore: 0.0,
      relationshipPathSummary: [
        `[CIRCUIT BREAKER - ${this.state}] Grafo Neo4j indisponível (${this.consecutiveFailures} falha(s)).`,
        `[EXPONENTIAL BACKOFF] Amortecimento de ${backoffMs}ms aplicado para proteger o cluster Qdrant contra picos de tráfego.`,
      ],
    };

    return {
      ...vectorResult,
      graphResult: emptySubgraph,
      graphContextAvailable: false,
      circuitBreakerTriggered: true,
      circuitBreakerState: this.state,
      backoffAppliedMs: backoffMs,
      consecutiveFailures: this.consecutiveFailures,
      aiDiagnosticRationale:
        `[CIRCUIT BREAKER ATIVADO - MODO DEGRADAÇÃO GRACIOSA] ` +
        `O Grafo de Conhecimento Neo4j falhou ou excedeu o timeout de ${this.config.neo4jTimeoutMs}ms (${reason}). ` +
        `Para proteger o banco vetorial Qdrant contra avalanche de requisições, foi aplicado um Exponential Backoff de ${backoffMs}ms com ${this.consecutiveFailures} falha(s) consecutiva(s). ` +
        `O Gemini utilizará exclusivamente o contexto normativo vetorial (Qdrant/pgvector) com ${vectorResult.vectorResults.length} chunks recuperados.`,
    };
  }
}

// Instância singleton para uso orientado a objetos e compatibilidade universal
export const hybridRagServiceClient = HybridRAGService;

export { HybridRAGFusionService };

