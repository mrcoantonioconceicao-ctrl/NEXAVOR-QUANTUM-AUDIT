/**
 * Servidor MCP (Model Context Protocol) - NEXAVOR Quantum Audit
 * Expõe ferramentas do motor pericial de AST, Refatoração In-Place / Polyglot
 * e Cálculo FAIR de Risco Financeiro para IDEs (VSCode/Cursor) e assistentes de IA.
 */

import { AstRefactorEngine } from '../domain/astRefactorEngine.ts';
import { GRCService } from '../domain/grc.ts';
import { GraphSyncService } from '../domain/knowledgeGraph/GraphSyncService.ts';
import { HybridRAGFusionService } from '../domain/knowledgeGraph/HybridRAGFusionService.ts';

export interface MCPToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, any>;
    required?: string[];
  };
}

export interface MCPRequest {
  jsonrpc: '2.0';
  id: string | number;
  method: string;
  params?: {
    name?: string;
    arguments?: Record<string, any>;
  };
}

export interface MCPResponse {
  jsonrpc: '2.0';
  id: string | number;
  result?: any;
  error?: {
    code: number;
    message: string;
    data?: any;
  };
}

export const MCP_TOOLS: MCPToolDefinition[] = [
  {
    name: 'analyze_ast',
    description: 'Executa análise sintática determinística e identificação de violações AST no código-fonte.',
    inputSchema: {
      type: 'object',
      properties: {
        code: { type: 'string', description: 'Código-fonte a ser analisado.' },
        language: { type: 'string', description: 'Linguagem de programação (ex: Python, TypeScript, Rust, C++).' },
        filePath: { type: 'string', description: 'Caminho do arquivo (ex: src/service.ts).' },
      },
      required: ['code'],
    },
  },
  {
    name: 'refactor_code',
    description: 'Executa refatoração In-Place (Mesma Linguagem - Hardening) ou Migração Polyglot (Rust ou Go).',
    inputSchema: {
      type: 'object',
      properties: {
        code: { type: 'string', description: 'Código-fonte original a ser refatorado/migrado.' },
        language: { type: 'string', description: 'Linguagem do código de origem.' },
        target_mode: {
          type: 'string',
          enum: ['IN_PLACE', 'REFRACTOR_IN_PLACE', 'MIGRATE_RUST', 'RUST', 'MIGRATE_GO', 'GO'],
          description: 'Modo de refatoração: IN_PLACE (mesma linguagem) ou RUST / GO (migração polyglot).',
        },
        filePath: { type: 'string', description: 'Caminho do arquivo original.' },
      },
      required: ['code', 'target_mode'],
    },
  },
  {
    name: 'calculate_fair',
    description: 'Calcula métricas financeiras de risco de segurança segundo o modelo FAIR (ALE, SLE, ARO e ROSI).',
    inputSchema: {
      type: 'object',
      properties: {
        assetValueUsd: { type: 'number', description: 'Valor estimado do ativo cibernético em USD.' },
        exposureFactorPercent: { type: 'number', description: 'Fator de exposição % (0 a 100).' },
        aro: { type: 'number', description: 'Taxa Anual de Ocorrência (ARO - Annualized Rate of Occurrence).' },
        securityCostUsd: { type: 'number', description: 'Custo do investimento em controles de segurança em USD.' },
        mitigationPercent: { type: 'number', description: 'Percentual de mitigação de risco % (ex: 85 para 85%).' },
      },
      required: ['assetValueUsd', 'exposureFactorPercent', 'aro', 'securityCostUsd', 'mitigationPercent'],
    },
  },
  {
    name: 'query_impact_graph',
    description: 'Navega no Grafo de Conhecimento (GraphRAG) e retorna a árvore de impacto multi-hop de vulnerabilidades e não-conformidades de um arquivo/função.',
    inputSchema: {
      type: 'object',
      properties: {
        targetId: { type: 'string', description: 'ID ou nome do arquivo/função (ex: "programs/solana_sandbox_counter/src/lib.rs" ou "increment()").' },
        maxDepth: { type: 'number', description: 'Profundidade máxima de navegação no grafo (1 a 5).' },
      },
      required: ['targetId'],
    },
  },
  {
    name: 'hybrid_rag_query',
    description: 'Executa consulta RAG Híbrida combinando busca vetorial semântica (NIST/FIPS/PCI-DSS) e navegação em Grafo de Conhecimento (GraphRAG) com Reranking.',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Pergunta ou requisição de auditoria semântica/relacional.' },
        targetFileOrFunction: { type: 'string', description: 'Arquivo ou função para focar a análise de impacto em grafo.' },
        vectorWeight: { type: 'number', description: 'Peso da busca vetorial (0.0 a 1.0).' },
        graphWeight: { type: 'number', description: 'Peso da navegação em grafo (0.0 a 1.0).' },
      },
      required: ['query'],
    },
  },
];

export class MCPServer {
  public static async handleRequest(req: MCPRequest): Promise<MCPResponse> {
    const { id, method, params } = req;

    if (method === 'tools/list') {
      return {
        jsonrpc: '2.0',
        id,
        result: {
          tools: MCP_TOOLS,
        },
      };
    }

    if (method === 'tools/call') {
      const toolName = params?.name;
      const args = params?.arguments || {};

      try {
        if (toolName === 'analyze_ast') {
          const { code, language, filePath = 'snippet.code' } = args;
          const report = AstRefactorEngine.analyzeFile(filePath, code || '', language);
          return {
            jsonrpc: '2.0',
            id,
            result: {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(report, null, 2),
                },
              ],
            },
          };
        }

        if (toolName === 'refactor_code') {
          const { code = '', language = 'Autodetect', target_mode = 'IN_PLACE', filePath = 'module.src' } = args;
          const modeUpper = String(target_mode).toUpperCase();
          const isInPlace = modeUpper === 'IN_PLACE' || modeUpper === 'REFRACTOR_IN_PLACE';
          const targetLang = isInPlace
            ? language
            : modeUpper.includes('GO')
            ? 'Go'
            : 'Rust';

          const astReport = AstRefactorEngine.analyzeFile(filePath, code, language);
          
          return {
            jsonrpc: '2.0',
            id,
            result: {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(
                    {
                      targetMode: isInPlace ? 'IN_PLACE' : targetLang === 'Go' ? 'MIGRATE_GO' : 'MIGRATE_RUST',
                      targetLanguage: targetLang,
                      originalLanguage: language,
                      filePath,
                      violationsDetected: astReport.violations.length,
                      astViolations: astReport.violations,
                      instruction: isInPlace
                        ? `Refatoração In-Place na mesma linguagem (${language}). Mantenha a extensão original, aplique verificações de tempo constante, elimine OWASP/PQC vulnerabilidades e adicione tratamento de erros nativo.`
                        : `Migração Polyglot para ${targetLang}. Converta para ${targetLang} idiomaticamente com tipagem estrita e ausência de pânicos.`,
                    },
                    null,
                    2
                  ),
                },
              ],
            },
          };
        }

        if (toolName === 'calculate_fair') {
          const { assetValueUsd, exposureFactorPercent, aro, securityCostUsd, mitigationPercent } = args;
          const metrics = GRCService.calculateFAIR(
            Number(assetValueUsd || 0),
            Number(exposureFactorPercent || 0),
            Number(aro || 0),
            Number(securityCostUsd || 0),
            Number(mitigationPercent || 0)
          );
          return {
            jsonrpc: '2.0',
            id,
            result: {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(metrics, null, 2),
                },
              ],
            },
          };
        }

        if (toolName === 'query_impact_graph') {
          const { targetId = 'lib.rs', maxDepth = 3 } = args;
          const impactTree = GraphSyncService.queryImpactTree(targetId, Number(maxDepth));
          return {
            jsonrpc: '2.0',
            id,
            result: {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(impactTree, null, 2),
                },
              ],
            },
          };
        }

        if (toolName === 'hybrid_rag_query') {
          const { query = '', targetFileOrFunction, vectorWeight, graphWeight } = args;
          const ragResult = await HybridRAGFusionService.executeHybridQuery({
            query,
            targetFileOrFunction,
            vectorWeight: vectorWeight !== undefined ? Number(vectorWeight) : 0.5,
            graphWeight: graphWeight !== undefined ? Number(graphWeight) : 0.5,
          });
          return {
            jsonrpc: '2.0',
            id,
            result: {
              content: [
                {
                  type: 'text',
                  text: JSON.stringify(ragResult, null, 2),
                },
              ],
            },
          };
        }

        return {
          jsonrpc: '2.0',
          id,
          error: {
            code: -32601,
            message: `Ferramenta MCP desconhecida: ${toolName}`,
          },
        };
      } catch (err: any) {
        return {
          jsonrpc: '2.0',
          id,
          error: {
            code: -32603,
            message: `Erro ao executar ferramenta MCP ${toolName}: ${err?.message || String(err)}`,
          },
        };
      }
    }

    return {
      jsonrpc: '2.0',
      id,
      error: {
        code: -32601,
        message: `Método MCP não suportado: ${method}`,
      },
    };
  }
}
