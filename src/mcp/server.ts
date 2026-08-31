/**
 * Servidor MCP (Model Context Protocol) - NEXAVOR Quantum Audit
 * Expõe ferramentas do motor pericial de AST, Refatoração In-Place / Polyglot
 * e Cálculo FAIR de Risco Financeiro para IDEs (VSCode/Cursor) e assistentes de IA.
 */

import { AstRefactorEngine } from '../domain/astRefactorEngine.ts';
import { GRCService } from '../domain/grc.ts';

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
];

export class MCPServer {
  public static handleRequest(req: MCPRequest): MCPResponse {
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
