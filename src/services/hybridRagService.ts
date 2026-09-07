/**
 * Service: HybridRAGService
 * Serviço de orquestração RAG Híbrido (Vector RAG + GraphRAG Neo4j)
 * com suporte a Circuit Breaker e Graceful Degradation (Timeout 1500ms).
 */

import { HybridRAGFusionService } from '../domain/knowledgeGraph/HybridRAGFusionService.ts';
import { HybridRAGQueryRequest, HybridRAGQueryResult } from '../domain/knowledgeGraph/types.ts';

export class HybridRAGService {
  /**
   * Executa a busca híbrida (Vetor + Grafo Neo4j).
   * Se o tempo de resposta do Neo4j exceder 1500ms ou ocorrer erro de conexão,
   * dispara o Circuit Breaker, registra o evento no log e altera automaticamente
   * para o contexto vetorial puro (Qdrant/pgvector) retornando 'graphContextAvailable: false'.
   */
  public static async executeHybridQuery(request: HybridRAGQueryRequest): Promise<HybridRAGQueryResult> {
    return HybridRAGFusionService.executeHybridQuery(request);
  }
}

export { HybridRAGFusionService };
